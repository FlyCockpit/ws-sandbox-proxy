//! Preview tunnels: one pinned `tunnel` client
//! process per sandbox, run by this daemon OUTSIDE the guest. It dials the
//! tunnel server outbound and forwards visitor streams only to the declared
//! ports of the sandbox's pinned guest address, both taken from the
//! sandbox's RECORDED network plan (never from the server frame or the
//! guest).
//!
//! - The per-tunnel token lives only in memory, in the client's environment
//!   and in the client's state directory under `$XDG_RUNTIME_DIR` (tmpfs):
//!   never on persistent disk, never in argv, never in logs.
//! - The binary is re-hashed before every start and must match the
//!   configured SHA-256.
//! - A client never outlives its sandbox's network: the runtime's teardown
//!   hook stops and reaps it before the bridge (and its subnet) is released.
//! - Clients do not survive the daemon: a graceful stop kills them, a
//!   service restart kills the unit's cgroup, and a fresh daemon kills every
//!   process whose argv names a state directory under this node's base
//!   (found in `/proc`, not through files a race could remove) before the
//!   runtime starts any cleanup.
//!   The control plane re-applies (with a rotated token) after the next
//!   registration.

use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sandbox_protocol::{
    TunnelApplyV11, TunnelCapabilityV11, TunnelClearV11, TunnelErrorV11, TunnelStateV11,
    TunnelStatusV11,
};
use sandbox_runtime::SandboxRuntime;

/// Exit codes of the pinned client (`tunnel` README "Supervised daemon").
const EXIT_GONE: i32 = 3;
const EXIT_REPLACED: i32 = 4;
/// Unexpected exits restarted before the host reports `client_failed`.
const MAX_RESTARTS: u32 = 5;
const POLL_INTERVAL: Duration = Duration::from_secs(2);
const IPC_TIMEOUT: Duration = Duration::from_secs(2);
const STOP_GRACE: Duration = Duration::from_secs(3);
const LOG_FILE: &str = "client.log";
const STATE_SUBDIR: &str = "client";

/// The node's `[tunnel]` section, validated.
#[derive(Debug, Clone)]
pub(crate) struct TunnelSettings {
    pub client: PathBuf,
    pub client_sha256: String,
    pub max_tunnels: u32,
    pub allow_for_others: bool,
}

impl TunnelSettings {
    pub(crate) fn capability(&self) -> TunnelCapabilityV11 {
        TunnelCapabilityV11 {
            client_sha256: self.client_sha256.clone(),
            max_tunnels: self.max_tunnels,
            allow_for_others: self.allow_for_others,
        }
    }
}

/// SHA-256 of a file, lowercase hex.
pub(crate) fn file_sha256(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        context.update(&buffer[..read]);
    }
    Ok(context
        .finish()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// `true` when `path` is an absolute regular file matching `sha256`.
pub(crate) fn verify_client(path: &Path, sha256: &str) -> bool {
    path.is_absolute()
        && std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_file())
        && file_sha256(path).is_ok_and(|actual| actual == sha256)
}

struct Entry {
    generation: u64,
    server: String,
    token: zeroize::Zeroizing<String>,
    ports: Vec<u16>,
    target: std::net::Ipv4Addr,
    child: Option<Child>,
    restarts: u32,
    restart_at: Option<Instant>,
    /// Last state reported for this generation.
    reported: Option<(TunnelStateV11, Option<TunnelErrorV11>, Option<String>)>,
    /// Terminal for this generation: no restart until a new apply.
    terminal: bool,
}

static INSTALLED: std::sync::OnceLock<Arc<TunnelManager>> = std::sync::OnceLock::new();

/// What this host's lease journal says about a sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LeaseHere {
    /// No lease row at all: the sandbox is not (or no longer) on this host.
    Unknown,
    /// A row exists but allows no work now (expired, deadline passed,
    /// clock or journal unsound).
    Lapsed,
    /// A live lease; `own`: the node's owner owns the sandbox.
    Live { own: bool },
}

/// The lease journal lookup the manager consults.
pub(crate) type Holder = Arc<dyn Fn(&str) -> LeaseHere + Send + Sync>;

/// This node's identity among the tunnel clients of one user: a digest of
/// the daemon's state directory, so two daemons of one user never sweep
/// each other's clients and a restarted daemon finds its own whatever its
/// environment.
fn node_key(state_dir: &Path) -> String {
    // Canonical: `/data/./wssp` and `/data/wssp` are one node.
    let state_dir = std::fs::canonicalize(state_dir).unwrap_or_else(|_| state_dir.to_path_buf());
    let digest = ring::digest::digest(
        &ring::digest::SHA256,
        state_dir.as_os_str().as_encoded_bytes(),
    );
    digest.as_ref()[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// This node's client base: `$XDG_RUNTIME_DIR/wssp/tunnels/<node key>`.
fn node_base(runtime_dir: &Path, key: &str) -> PathBuf {
    runtime_dir.join("wssp").join("tunnels").join(key)
}

/// Start the node's manager once per process and hook it into every network
/// teardown. A daemon without `[tunnel]` (or whose client does not verify)
/// installs nothing and never advertises the capability.
pub(crate) fn install(
    settings: Option<TunnelSettings>,
    runtime: Arc<dyn SandboxRuntime>,
    state_dir: &Path,
    holder: Holder,
) {
    if INSTALLED.get().is_some() {
        return;
    }
    let Some(manager) = TunnelManager::start(settings, runtime, state_dir, holder) else {
        return;
    };
    if INSTALLED.set(manager.clone()).is_ok() {
        let hook = manager.clone();
        sandbox_runtime::set_network_teardown_hook(Arc::new(move |sandbox_id: &str| {
            hook.stop(sandbox_id);
            Ok(())
        }));
        let created = manager.clone();
        sandbox_runtime::set_network_created_hook(Arc::new(move |sandbox_id: &str| {
            created.network_created(sandbox_id);
        }));
        let removed = manager.clone();
        sandbox_runtime::set_network_removed_hook(Arc::new(move |sandbox_id: &str| {
            removed.network_removed(sandbox_id);
        }));
        tracing::info!(
            client_sha256 = %manager.settings.client_sha256,
            max_tunnels = manager.settings.max_tunnels,
            "preview tunnels available"
        );
    }
}

/// The installed manager, if any.
pub(crate) fn installed() -> Option<&'static Arc<TunnelManager>> {
    INSTALLED.get()
}

/// Runs and supervises the tunnel clients of this node.
pub(crate) struct TunnelManager {
    settings: TunnelSettings,
    runtime: Arc<dyn SandboxRuntime>,
    holder: Holder,
    base: PathBuf,
    entries: Mutex<HashMap<String, Entry>>,
    /// Highest generation applied or cleared per sandbox (guarded by the
    /// entries lock): an apply at or below it is stale, even after a clear
    /// or a teardown removed the entry. Dropped when the sandbox's network
    /// and recorded plan are gone.
    floors: Mutex<HashMap<String, u64>>,
    /// Sandboxes whose network a teardown has started on: no client starts
    /// for them until the runtime creates a new bridge (lock order: entries,
    /// then retired).
    retired: Mutex<std::collections::HashSet<String>>,
    events: Mutex<VecDeque<TunnelStatusV11>>,
    /// Relay frames, handled on the manager's own thread: the relay loop
    /// never waits for a client to start or stop.
    commands: Mutex<VecDeque<Cmd>>,
    wake: std::sync::Condvar,
    /// Daemon shutdown began (set under the entries lock): no client starts.
    shutdown: std::sync::atomic::AtomicBool,
}

enum Cmd {
    Apply(TunnelApplyV11),
    Clear(TunnelClearV11),
    ReportAll,
}

impl Cmd {
    /// The sandbox and generation an apply or clear is for.
    fn fence(&self) -> Option<(&str, u64)> {
        match self {
            Cmd::Apply(apply) => Some((&apply.sandbox_id, apply.generation)),
            Cmd::Clear(clear) => Some((&clear.sandbox_id, clear.generation)),
            Cmd::ReportAll => None,
        }
    }
}

/// Most queued frames; beyond it a new apply is turned into a clear of its
/// generation (refused, and the older client stops). The queue keeps at
/// most one apply and one clear per sandbox.
const MAX_QUEUED: usize = 4096;

impl TunnelManager {
    /// The manager when `[tunnel]` is configured, the binary verifies and a
    /// private runtime directory exists; `None` (capability off) otherwise.
    pub(crate) fn start(
        settings: Option<TunnelSettings>,
        runtime: Arc<dyn SandboxRuntime>,
        state_dir: &Path,
        holder: Holder,
    ) -> Option<Arc<Self>> {
        let settings = settings?;
        if !verify_client(&settings.client, &settings.client_sha256) {
            tracing::warn!(
                client = %settings.client.display(),
                "tunnel client missing or its SHA-256 differs from [tunnel] client_sha256; preview tunnels are off"
            );
            return None;
        }
        // Canonical, so every client's `--state-dir` is the plain absolute
        // path the startup sweep recognises.
        let Some(runtime_dir) =
            std::env::var_os("XDG_RUNTIME_DIR").and_then(|dir| std::fs::canonicalize(dir).ok())
        else {
            tracing::warn!(
                "XDG_RUNTIME_DIR is not set; preview tunnels are off (tokens stay off persistent disk)"
            );
            return None;
        };
        let base = node_base(&runtime_dir, &node_key(state_dir));
        if let Err(error) = prepare_base(&runtime_dir, &base) {
            tracing::warn!(%error, "cannot prepare the tunnel state directory; preview tunnels are off");
            return None;
        }
        let manager = Arc::new(Self::with_base(settings, runtime, holder, base));
        let monitor = Arc::downgrade(&manager);
        std::thread::Builder::new()
            .name("wssp-tunnels".into())
            .spawn(move || {
                while let Some(manager) = monitor.upgrade() {
                    manager.poll();
                    manager.idle(POLL_INTERVAL);
                }
            })
            .ok()?;
        Some(manager)
    }

    fn with_base(
        settings: TunnelSettings,
        runtime: Arc<dyn SandboxRuntime>,
        holder: Holder,
        base: PathBuf,
    ) -> Self {
        Self {
            settings,
            runtime,
            holder,
            base,
            entries: Mutex::new(HashMap::new()),
            floors: Mutex::new(HashMap::new()),
            retired: Mutex::new(std::collections::HashSet::new()),
            events: Mutex::new(VecDeque::new()),
            commands: Mutex::new(VecDeque::new()),
            wake: std::sync::Condvar::new(),
            shutdown: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub(crate) fn capability(&self) -> TunnelCapabilityV11 {
        self.settings.capability()
    }

    fn dir(&self, sandbox_id: &str) -> PathBuf {
        self.base.join(sandbox_id)
    }

    fn push(&self, status: TunnelStatusV11) {
        let mut events = self.events.lock().unwrap_or_else(|e| e.into_inner());
        if events.len() >= 1024 {
            events.pop_front();
        }
        events.push_back(status);
    }

    /// Status frames to send (oldest first).
    pub(crate) fn drain_events(&self) -> Vec<TunnelStatusV11> {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
            .collect()
    }

    /// After a new registration: report every current generation again so
    /// the control plane can tell a live client from a lost one. Queued:
    /// the relay loop never waits for the entries lock.
    pub(crate) fn report_all(&self) {
        self.enqueue(Cmd::ReportAll);
    }

    fn report_all_now(&self) {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        for (sandbox_id, entry) in entries.iter() {
            let (state, error, tunnel_id) =
                entry
                    .reported
                    .clone()
                    .unwrap_or((TunnelStateV11::Connecting, None, None));
            self.push(TunnelStatusV11 {
                sandbox_id: sandbox_id.clone(),
                generation: entry.generation,
                state,
                error,
                tunnel_id,
            });
        }
    }

    /// Node owner consent, enforced here too: only a sandbox this host holds
    /// a live lease for (clock-checked), another user's only with
    /// `allow_for_others`. Checked at apply and on every supervision pass.
    fn consent(&self, sandbox_id: &str) -> bool {
        match (self.holder)(sandbox_id) {
            LeaseHere::Live { own } => own || self.settings.allow_for_others,
            LeaseHere::Unknown | LeaseHere::Lapsed => false,
        }
    }

    fn refuse(&self, sandbox_id: &str, generation: u64) {
        self.push(TunnelStatusV11 {
            sandbox_id: sandbox_id.to_string(),
            generation,
            state: TunnelStateV11::Error,
            error: Some(TunnelErrorV11::Refused),
            tunnel_id: None,
        });
    }

    fn enqueue(&self, command: Cmd) {
        let mut commands = self.commands.lock().unwrap_or_else(|e| e.into_inner());
        // Coalesce by generation, so the newest intent survives and no
        // fence is lost: a clear supersedes every queued frame of its
        // sandbox at or below its generation (clear wins a tie); an apply
        // is dropped when a queued frame of its sandbox is at or above it
        // (that frame fences it anyway) and supersedes older applies.
        let mut command = command;
        match command.fence() {
            Some((sandbox_id, generation)) => {
                let is_clear = matches!(command, Cmd::Clear(_));
                let superseded = commands.iter().any(|queued| {
                    queued.fence().is_some_and(|(id, queued_generation)| {
                        id == sandbox_id
                            && queued_generation >= generation
                            && (!is_clear || matches!(queued, Cmd::Clear(_)))
                    })
                });
                if superseded {
                    return;
                }
                commands.retain(|queued| {
                    !queued.fence().is_some_and(|(id, queued_generation)| {
                        id == sandbox_id
                            && (if is_clear {
                                queued_generation <= generation
                            } else {
                                matches!(queued, Cmd::Apply(_))
                            })
                    })
                });
            }
            None => commands.retain(|queued| !matches!(queued, Cmd::ReportAll)),
        }
        if commands.len() >= MAX_QUEUED
            && let Cmd::Apply(apply) = &command
        {
            tracing::warn!(sandbox = %apply.sandbox_id, generation = apply.generation, "tunnel apply refused: too many queued frames");
            self.refuse(&apply.sandbox_id, apply.generation);
            // Still fences: the older client stops and the floor moves.
            command = Cmd::Clear(TunnelClearV11 {
                sandbox_id: apply.sandbox_id.clone(),
                generation: apply.generation,
            });
        }
        commands.push_back(command);
        self.wake.notify_all();
    }

    /// Wait up to `timeout` for a queued frame.
    fn idle(&self, timeout: Duration) {
        let commands = self.commands.lock().unwrap_or_else(|e| e.into_inner());
        if commands.is_empty() {
            let _ = self.wake.wait_timeout(commands, timeout);
        }
    }

    /// `tunnel.apply`: queued; the manager's thread starts the client.
    pub(crate) fn apply(&self, apply: TunnelApplyV11) {
        self.enqueue(Cmd::Apply(apply));
    }

    /// `tunnel.clear`: queued; the manager's thread stops the client.
    pub(crate) fn clear(&self, clear: &TunnelClearV11) {
        self.enqueue(Cmd::Clear(clear.clone()));
    }

    fn run_commands(&self) {
        loop {
            let next = self
                .commands
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .pop_front();
            match next {
                Some(Cmd::Apply(apply)) => self.apply_now(apply),
                Some(Cmd::Clear(clear)) => self.clear_now(&clear),
                Some(Cmd::ReportAll) => self.report_all_now(),
                None => return,
            }
        }
    }

    /// Start (or replace) the sandbox's client.
    fn apply_now(&self, apply: TunnelApplyV11) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        {
            let mut floors = self.floors.lock().unwrap_or_else(|e| e.into_inner());
            let floor = floors.entry(apply.sandbox_id.clone()).or_insert(0);
            if *floor >= apply.generation {
                // Stale or repeated (also after a clear or a teardown): the
                // newest generation stands.
                return;
            }
            *floor = apply.generation;
        }
        let retired = self
            .retired
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&apply.sandbox_id);
        let target = if retired || self.shutdown.load(std::sync::atomic::Ordering::SeqCst) {
            None
        } else {
            self.runtime.tunnel_target(&apply.sandbox_id)
        };
        let consent = self.consent(&apply.sandbox_id);
        let refusal = match &target {
            None => Some("no current recorded tunnel plan"),
            Some(_) if !consent => {
                Some("the sandbox is not held here or the node owner does not allow it")
            }
            Some((_, declared)) if !apply.ports.iter().all(|port| declared.contains(port)) => {
                Some("undeclared ports")
            }
            // Ended clients (gone, replaced, failed) hold no slot; a
            // replacement is free only when it replaces a live one.
            Some(_)
                if !entries
                    .get(&apply.sandbox_id)
                    .is_some_and(|entry| !entry.terminal)
                    && entries.values().filter(|entry| !entry.terminal).count()
                        >= self.settings.max_tunnels as usize =>
            {
                Some("node tunnel limit")
            }
            Some(_) => None,
        };
        if let Some(reason) = refusal {
            // A refused generation supersedes the older one: its client stops.
            if let Some(mut old) = entries.remove(&apply.sandbox_id) {
                stop_child(&mut old.child);
            }
            let _ = std::fs::remove_dir_all(self.dir(&apply.sandbox_id));
            drop(entries);
            tracing::warn!(sandbox = %apply.sandbox_id, generation = apply.generation, retired, reason, "tunnel apply refused");
            self.refuse(&apply.sandbox_id, apply.generation);
            return;
        }
        let Some((target, _)) = target else {
            return;
        };
        if let Some(mut old) = entries.remove(&apply.sandbox_id) {
            stop_child(&mut old.child);
        }
        let dir = self.dir(&apply.sandbox_id);
        let _ = std::fs::remove_dir_all(&dir);
        let mut entry = Entry {
            generation: apply.generation,
            server: apply.server,
            token: zeroize::Zeroizing::new(apply.token),
            ports: apply.ports,
            target,
            child: None,
            restarts: 0,
            restart_at: None,
            reported: None,
            terminal: false,
        };
        tracing::info!(sandbox = %apply.sandbox_id, generation = entry.generation, ports = ?entry.ports, "tunnel client starting");
        if let Err(error) = self.spawn(&apply.sandbox_id, &mut entry) {
            tracing::warn!(sandbox = %apply.sandbox_id, %error, "tunnel client did not start");
            entry.terminal = true;
            self.report(
                &apply.sandbox_id,
                &mut entry,
                TunnelStateV11::Error,
                Some(TunnelErrorV11::Refused),
                None,
            );
            entries.insert(apply.sandbox_id, entry);
            return;
        }
        self.report(
            &apply.sandbox_id,
            &mut entry,
            TunnelStateV11::Connecting,
            None,
            None,
        );
        entries.insert(apply.sandbox_id, entry);
    }

    /// Stop the client of any generation up to this one.
    fn clear_now(&self, clear: &TunnelClearV11) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        {
            // Recorded whatever the runtime or the lease journal says right
            // now; dropped only at a confirmed `network_removed`.
            let mut floors = self.floors.lock().unwrap_or_else(|e| e.into_inner());
            let floor = floors.entry(clear.sandbox_id.clone()).or_insert(0);
            if *floor > clear.generation {
                return;
            }
            // Every apply up to this generation is now stale.
            *floor = clear.generation;
        }
        // Reaped under the lock: a teardown hook waiting for it cannot
        // release the network while this client still runs.
        if let Some(mut entry) = entries.remove(&clear.sandbox_id) {
            stop_child(&mut entry.child);
            tracing::info!(sandbox = %clear.sandbox_id, generation = entry.generation, "tunnel client stopped");
        }
        let _ = std::fs::remove_dir_all(self.dir(&clear.sandbox_id));
        drop(entries);
        self.push(TunnelStatusV11 {
            sandbox_id: clear.sandbox_id.clone(),
            generation: clear.generation,
            state: TunnelStateV11::Stopped,
            error: None,
            tunnel_id: None,
        });
    }

    /// Stop and reap the sandbox's client (the network teardown hook).
    /// Teardown: no client may start for this sandbox until a new bridge
    /// exists ([`Self::network_created`]); the current one is reaped.
    pub(crate) fn stop(&self, sandbox_id: &str) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        self.retired
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(sandbox_id.to_string());
        // Reaped under the lock, like clear and replace: nothing observes
        // the entry gone while its client still runs.
        if let Some(mut entry) = entries.remove(sandbox_id) {
            stop_child(&mut entry.child);
            tracing::info!(sandbox = %sandbox_id, generation = entry.generation, "tunnel client stopped before network teardown");
            // The control plane re-applies if the sandbox still runs.
            self.push(TunnelStatusV11 {
                sandbox_id: sandbox_id.to_string(),
                generation: entry.generation,
                state: TunnelStateV11::Stopped,
                error: None,
                tunnel_id: None,
            });
        }
        let _ = std::fs::remove_dir_all(self.dir(sandbox_id));
    }

    /// A runtime tunnel-port change (`tunnel.ports`) is durably pending and
    /// its ACL write comes next: a client forwarding any port outside
    /// `allowed` stops now (reaped under the lock; its visitor connections
    /// close with it). The server re-applies with the new port set.
    pub(crate) fn restrict(&self, sandbox_id: &str, allowed: &[u16]) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let outside = entries
            .get(sandbox_id)
            .is_some_and(|entry| !entry.ports.iter().all(|port| allowed.contains(port)));
        if !outside {
            return;
        }
        if let Some(mut entry) = entries.remove(sandbox_id) {
            stop_child(&mut entry.child);
            tracing::info!(sandbox = %sandbox_id, generation = entry.generation, ports = ?entry.ports, "tunnel client stopped: its ports are no longer all declared");
            self.push(TunnelStatusV11 {
                sandbox_id: sandbox_id.to_string(),
                generation: entry.generation,
                state: TunnelStateV11::Stopped,
                error: None,
                tunnel_id: None,
            });
        }
        let _ = std::fs::remove_dir_all(self.dir(sandbox_id));
    }

    /// A bridge exists for the sandbox again: lift the teardown fence.
    pub(crate) fn network_created(&self, sandbox_id: &str) {
        let _entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        self.retired
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(sandbox_id);
    }

    /// The sandbox's network AND its recorded plan are confirmed gone, so
    /// no apply can name a target: drop the teardown fence and the
    /// generation floor (both stay bounded by the sandboxes with networks).
    pub(crate) fn network_removed(&self, sandbox_id: &str) {
        let _entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        self.retired
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(sandbox_id);
        self.floors
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(sandbox_id);
    }

    /// Daemon shutdown: every client stops.
    pub(crate) fn stop_all(&self) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        // Latched under the lock: no queued or later apply starts a client.
        self.shutdown
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.commands
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        let mut children = Vec::new();
        for (sandbox_id, mut entry) in entries.drain() {
            children.extend(entry.child.take());
            let _ = std::fs::remove_dir_all(self.dir(&sandbox_id));
        }
        // One shared grace for all clients, not one per client.
        stop_children(children);
    }

    fn report(
        &self,
        sandbox_id: &str,
        entry: &mut Entry,
        state: TunnelStateV11,
        error: Option<TunnelErrorV11>,
        tunnel_id: Option<String>,
    ) {
        let next = (state, error, tunnel_id.clone());
        if entry.reported.as_ref() == Some(&next) {
            return;
        }
        entry.reported = Some(next);
        self.push(TunnelStatusV11 {
            sandbox_id: sandbox_id.to_string(),
            generation: entry.generation,
            state,
            error,
            tunnel_id,
        });
    }

    fn spawn(&self, sandbox_id: &str, entry: &mut Entry) -> anyhow::Result<()> {
        // Re-hashed before every start: a swapped binary never runs.
        anyhow::ensure!(
            verify_client(&self.settings.client, &self.settings.client_sha256),
            "the tunnel client no longer matches its pinned SHA-256"
        );
        // Re-checked before every start (restarts too): the recorded plan
        // must still declare every port, at the same target.
        anyhow::ensure!(
            self.runtime
                .tunnel_target(sandbox_id)
                .is_some_and(|(target, declared)| target == entry.target
                    && entry.ports.iter().all(|port| declared.contains(port))),
            "the recorded tunnel plan no longer declares the client's ports"
        );
        let dir = self.dir(sandbox_id);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .or_else(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    Ok(())
                } else {
                    Err(error)
                }
            })?;
        private_dir(&dir)?;
        let log = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(dir.join(LOG_FILE))?;
        let state_dir = dir.join(STATE_SUBDIR);
        let child = Command::new(&self.settings.client)
            .arg("--state-dir")
            .arg(&state_dir)
            .arg("daemon")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("TUNNEL_TOKEN", entry.token.as_str())
            .env("TUNNEL_SERVER", &entry.server)
            .env("TUNNEL_TARGET_HOST", entry.target.to_string())
            .env("RUST_LOG", "info")
            .current_dir(&dir)
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .process_group(0)
            .spawn()?;
        // Owned at once; a crashed daemon's successor finds it by its argv.
        entry.child = Some(child);
        Ok(())
    }

    /// One supervision pass: queued frames first, then reap exits, restart
    /// crashes, expose ports and read client status. Client IPC runs
    /// without the entries lock (a teardown stop never waits for it).
    pub(crate) fn poll(&self) {
        self.run_commands();
        let mut probes: Vec<(String, u64, PathBuf, Vec<u16>)> = Vec::new();
        {
            let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            let ids: Vec<String> = entries.keys().cloned().collect();
            for sandbox_id in ids {
                let Some(entry) = entries.get_mut(&sandbox_id) else {
                    continue;
                };
                if entry.terminal {
                    continue;
                }
                // The lease lapsed (or was never this host's): the client
                // stops at once and is not restarted.
                if !self.consent(&sandbox_id) {
                    stop_child(&mut entry.child);
                    entry.terminal = true;
                    entry.restart_at = None;
                    let _ = std::fs::remove_dir_all(self.dir(&sandbox_id));
                    tracing::info!(sandbox = %sandbox_id, generation = entry.generation, "tunnel client stopped: the sandbox's lease here ended");
                    self.report(&sandbox_id, entry, TunnelStateV11::Stopped, None, None);
                    continue;
                }
                let exited = match entry.child.as_mut().map(Child::try_wait) {
                    Some(Ok(Some(status))) => Some(status.code()),
                    Some(Ok(None)) => None,
                    Some(Err(_)) => Some(None),
                    None => None,
                };
                if let Some(code) = exited {
                    entry.child = None;
                    self.exited(&sandbox_id, entry, code);
                    continue;
                }
                if entry.child.is_none() {
                    if entry.restart_at.is_some_and(|at| Instant::now() >= at)
                        && !self.shutdown.load(std::sync::atomic::Ordering::SeqCst)
                    {
                        entry.restart_at = None;
                        if let Err(error) = self.spawn(&sandbox_id, entry) {
                            entry.terminal = true;
                            tracing::warn!(sandbox = %sandbox_id, %error, "tunnel client restart failed");
                            self.report(
                                &sandbox_id,
                                entry,
                                TunnelStateV11::Error,
                                Some(TunnelErrorV11::ClientFailed),
                                None,
                            );
                        }
                    }
                    continue;
                }
                let socket = self.dir(&sandbox_id).join(STATE_SUBDIR).join("daemon.sock");
                probes.push((sandbox_id, entry.generation, socket, entry.ports.clone()));
            }
        }
        for (sandbox_id, generation, socket, ports) in probes {
            // Queued frames (a clear, above all) never wait behind probes.
            if !self
                .commands
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty()
            {
                break;
            }
            // Reconciled on every pass against a fresh status (only a
            // `status` reply counts): a requested port the client does not
            // list (never exposed, or its declaration failed later) is
            // exposed again; the tunnel is `connected` only when the client
            // is and every requested port is.
            let status = ipc(&socket, &serde_json::json!({"type": "status"}))
                .ok()
                .as_ref()
                .and_then(status_of)
                .cloned();
            if status
                .as_ref()
                .is_some_and(|status| !lists_ports(status, &ports))
            {
                let _ = ipc(
                    &socket,
                    &serde_json::json!({"type": "expose", "ports": ports}),
                );
            }
            let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            // Stopped or replaced meanwhile: this probe is stale.
            let Some(entry) = entries
                .get_mut(&sandbox_id)
                .filter(|entry| entry.generation == generation && entry.child.is_some())
            else {
                continue;
            };
            let Some(status) = status else {
                continue;
            };
            let tunnel_id = status["tunnel_id"]
                .as_str()
                .filter(|id| id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric()))
                .map(str::to_string);
            let all_connected = connected_ports(&status, &ports);
            match status["state"].as_str() {
                Some("connected") if all_connected => {
                    // A client that connects has recovered: its restart
                    // budget starts again.
                    entry.restarts = 0;
                    self.report(
                        &sandbox_id,
                        entry,
                        TunnelStateV11::Connected,
                        None,
                        tunnel_id,
                    );
                }
                Some("connected" | "connecting") => self.report(
                    &sandbox_id,
                    entry,
                    TunnelStateV11::Connecting,
                    None,
                    tunnel_id,
                ),
                _ => {}
            }
        }
    }

    /// A client process ended: map its exit code (README "Supervised daemon").
    fn exited(&self, sandbox_id: &str, entry: &mut Entry, code: Option<i32>) {
        match code {
            Some(EXIT_GONE) => {
                entry.terminal = true;
                tracing::info!(sandbox = %sandbox_id, generation = entry.generation, "tunnel gone (deleted, expired or token refused)");
                self.report(
                    sandbox_id,
                    entry,
                    TunnelStateV11::Error,
                    Some(TunnelErrorV11::TunnelGone),
                    None,
                );
            }
            Some(EXIT_REPLACED) => {
                entry.terminal = true;
                tracing::info!(sandbox = %sandbox_id, generation = entry.generation, "tunnel client replaced");
                self.report(
                    sandbox_id,
                    entry,
                    TunnelStateV11::Error,
                    Some(TunnelErrorV11::Replaced),
                    None,
                );
            }
            _ if entry.restarts >= MAX_RESTARTS => {
                entry.terminal = true;
                tracing::warn!(sandbox = %sandbox_id, generation = entry.generation, "tunnel client keeps failing; not restarting");
                self.report(
                    sandbox_id,
                    entry,
                    TunnelStateV11::Error,
                    Some(TunnelErrorV11::ClientFailed),
                    None,
                );
            }
            _ => {
                entry.restarts += 1;
                entry.restart_at =
                    Some(Instant::now() + Duration::from_secs(2u64.pow(entry.restarts.min(5))));
                tracing::warn!(sandbox = %sandbox_id, generation = entry.generation, ?code, restarts = entry.restarts, "tunnel client exited; restarting");
                self.report(sandbox_id, entry, TunnelStateV11::Connecting, None, None);
            }
        }
    }
}

/// `tmpfs` / `ramfs` magic numbers (statfs(2)).
const TMPFS_MAGIC: u64 = 0x0102_1994;
const RAMFS_MAGIC: u64 = 0x8584_58f6;

/// A directory (never a symlink) owned by this user, mode 0700.
fn private_dir(dir: &Path) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.file_type().is_dir() || meta.uid() != nix::unistd::geteuid().as_raw() {
        return Err(std::io::Error::other(format!(
            "`{}` is not a directory owned by this user",
            dir.display()
        )));
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

fn memory_backed(path: &Path) -> std::io::Result<()> {
    let fs = rustix::fs::statfs(path).map_err(std::io::Error::from)?;
    let kind = u64::try_from(fs.f_type).unwrap_or(0);
    if kind != TMPFS_MAGIC && kind != RAMFS_MAGIC {
        return Err(std::io::Error::other(
            "the tunnel state directory is not on tmpfs; tunnel tokens must not reach persistent disk",
        ));
    }
    Ok(())
}

fn prepare_base(runtime_dir: &Path, base: &Path) -> std::io::Result<()> {
    // Tokens live in the clients' state directories: memory-backed only.
    memory_backed(runtime_dir)?;
    let meta = std::fs::metadata(runtime_dir)?;
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(std::io::Error::other(
            "XDG_RUNTIME_DIR is accessible to other users",
        ));
    }
    // Each level created (or found) as a real directory of ours: no
    // symlink may redirect the state directories elsewhere.
    let relative = base
        .strip_prefix(runtime_dir)
        .map_err(|_| std::io::Error::other("the tunnel base is outside XDG_RUNTIME_DIR"))?;
    let mut dir = runtime_dir.to_path_buf();
    for component in relative.components() {
        dir.push(component);
        match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        private_dir(&dir)?;
    }
    // The effective directory itself (a mount below the runtime dir counts).
    memory_backed(base)
}

/// Before the runtime starts any cleanup, every client an earlier daemon
/// of this node left running is killed and the node's directory emptied —
/// whether or not tunnels are configured now, whichever client binary ran
/// and whatever `XDG_RUNTIME_DIR` is now. Clients are found by scanning
/// `/proc` for this user's processes whose own arguments are
/// `--state-dir …/wssp/tunnels/<node key>/<sandbox>/client … daemon`, so a
/// client whose directory a race already removed is still found. A client
/// that survives SIGKILL fails the daemon's start (its network must not be
/// released under it).
pub(crate) fn sweep_leftovers(state_dir: &Path) -> anyhow::Result<()> {
    let key = node_key(state_dir);
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .and_then(|dir| std::fs::canonicalize(dir).ok())
        .map(|dir| node_base(&dir, &key));
    sweep_leftovers_of(&key, base.as_deref())
}

fn sweep_leftovers_of(key: &str, base: Option<&Path>) -> anyhow::Result<()> {
    let uid = nix::unistd::geteuid().as_raw();
    let mut killed = Vec::new();
    if let Ok(procs) = std::fs::read_dir("/proc") {
        for proc_entry in procs.flatten() {
            let Some(pid) = proc_entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<i32>().ok())
                .filter(|pid| *pid > 1 && *pid != std::process::id().cast_signed())
            else {
                continue;
            };
            // The process's own effective uid: the real client makes itself
            // non-dumpable, which leaves its `/proc/<pid>` owned by root.
            if effective_uid(pid) != Some(uid) {
                continue;
            }
            let cmdline = std::fs::read(proc_entry.path().join("cmdline")).unwrap_or_default();
            if runs_client_of(&cmdline, key) {
                // Its own process group (spawned as a group leader) too.
                let target = nix::unistd::Pid::from_raw(pid);
                let _ = nix::sys::signal::killpg(target, nix::sys::signal::Signal::SIGKILL);
                let _ = nix::sys::signal::kill(target, nix::sys::signal::Signal::SIGKILL);
                killed.push(pid);
            }
        }
    }
    // Not our children (no wait): bounded until the kernel drops them.
    let deadline = Instant::now() + STOP_GRACE;
    for pid in &killed {
        while process_alive(*pid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    if let Some(pid) = killed.iter().find(|pid| process_alive(**pid)) {
        anyhow::bail!("an earlier preview-tunnel client (pid {pid}) survived SIGKILL");
    }
    if let Some(base) = base
        && let Ok(read) = std::fs::read_dir(base)
    {
        for entry in read.flatten() {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
    Ok(())
}

/// The effective uid of `pid` (`Uid:` line of `/proc/<pid>/status`).
fn effective_uid(pid: i32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// Alive and not yet a zombie.
fn process_alive(pid: i32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        stat.rsplit_once(") ")
            .is_none_or(|(_, rest)| !rest.starts_with('Z'))
    })
}

/// `cmdline` (NUL-separated argv) is a tunnel client of the node `key`:
/// an absolute `--state-dir …/wssp/tunnels/<key>/<sandbox>/client` (no `.`
/// or `..` segment anywhere), run as `daemon`.
fn runs_client_of(cmdline: &[u8], key: &str) -> bool {
    let args: Vec<&[u8]> = cmdline.split(|b| *b == 0).collect();
    let owned = |state: &[u8]| {
        let segments: Vec<&[u8]> = state.split(|b| *b == b'/').collect();
        let n = segments.len();
        n >= 6
            && segments[0].is_empty()
            && segments[1..]
                .iter()
                .all(|segment| !segment.is_empty() && *segment != b"." && *segment != b"..")
            && segments[n - 5] == b"wssp"
            && segments[n - 4] == b"tunnels"
            && segments[n - 3] == key.as_bytes()
            && segments[n - 1] == STATE_SUBDIR.as_bytes()
    };
    args.windows(2)
        .any(|pair| pair[0] == b"--state-dir" && owned(pair[1]))
        && args.contains(&b"daemon".as_slice())
}

/// The `status` object of a client reply, only when the reply is a status.
fn status_of(response: &serde_json::Value) -> Option<&serde_json::Value> {
    (response["type"] == "status").then(|| &response["status"])
}

/// Every port in `ports` is listed and declared (`connected: true`).
fn connected_ports(status: &serde_json::Value, ports: &[u16]) -> bool {
    let connected: Vec<u64> = status["ports"]
        .as_array()
        .map(|listed| {
            listed
                .iter()
                .filter(|port| port["connected"] == true)
                .filter_map(|port| port["port"].as_u64())
                .collect()
        })
        .unwrap_or_default();
    ports
        .iter()
        .all(|port| connected.contains(&u64::from(*port)))
}

/// The status lists every port in `ports`.
fn lists_ports(status: &serde_json::Value, ports: &[u16]) -> bool {
    let listed: Vec<u64> = status["ports"]
        .as_array()
        .map(|ports| {
            ports
                .iter()
                .filter_map(|port| port["port"].as_u64())
                .collect()
        })
        .unwrap_or_default();
    ports.iter().all(|port| listed.contains(&u64::from(*port)))
}

/// SIGTERM, a short grace, then SIGKILL; always reaped before returning.
fn stop_child(child: &mut Option<Child>) {
    stop_children(child.take().into_iter().collect());
}

/// Stop clients together: SIGTERM to each client's process group (it was
/// spawned as the group leader, so anything it forked goes too), one shared
/// grace, then SIGKILL to the groups; every client is reaped before
/// returning.
fn stop_children(mut children: Vec<Child>) {
    let signal_all = |children: &[Child], signal: nix::sys::signal::Signal| {
        for child in children {
            if let Ok(pid) = i32::try_from(child.id()) {
                let pid = nix::unistd::Pid::from_raw(pid);
                let _ = nix::sys::signal::killpg(pid, signal);
                let _ = nix::sys::signal::kill(pid, signal);
            }
        }
    };
    signal_all(&children, nix::sys::signal::Signal::SIGTERM);
    let deadline = Instant::now() + STOP_GRACE;
    while Instant::now() < deadline {
        children.retain_mut(|child| !matches!(child.try_wait(), Ok(Some(_))));
        if children.is_empty() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    signal_all(&children, nix::sys::signal::Signal::SIGKILL);
    for child in &mut children {
        let _ = child.wait();
    }
}

/// One newline-delimited JSON request/response on the client's socket.
fn ipc(socket: &Path, request: &serde_json::Value) -> std::io::Result<serde_json::Value> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(IPC_TIMEOUT))?;
    stream.set_write_timeout(Some(IPC_TIMEOUT))?;
    let mut line = serde_json::to_vec(request)?;
    line.push(b'\n');
    stream.write_all(&line)?;
    let mut reader = BufReader::new(stream.take(64 * 1024));
    let mut response = String::new();
    reader.read_line(&mut response)?;
    serde_json::from_str(&response).map_err(std::io::Error::other)
}

#[cfg(test)]
#[path = "tunnel_tests.rs"]
mod tests;
