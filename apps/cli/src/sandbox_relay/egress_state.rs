//! Node egress state of the node daemon (see docs/guide/hosts.md#egress-guard).
//!
//! - [`NodeEgress`]: the live consent (`allow_open_egress_for_others`), the
//!   node `EgressSettings` from the node config, the hello owner, and the
//!   guard probe the runtime's start fence also uses. Dispatch workers read
//!   it for the §1.5 early admission and the settings captured at
//!   materialization.
//! - [`GuardMonitor`]: a process-scoped thread that asks the guard for a
//!   fresh `status` every tick, drops stale answers with the
//!   `(instance_id, generation)` fence, (re)pushes the deployment blocklist
//!   (E6, `egress.blocklist` from the server) to every new guard instance
//!   and on change — never before the server's list is known, so a lost
//!   daemon state file cannot clear the guard's list — and keeps
//!   the latest `guard_ok` verdict (the shared lease rule) for the
//!   `host.egress-state` heartbeat. It never blocks the relay loop.
//!
//! The heartbeat is a lease renewal, not an admission input: every create
//! and cold reconnect still makes its own fresh guard call, and the runtime
//! start fence stays authoritative.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use sandbox_protocol::HostEgressStateV11;
use sandbox_runtime::egress::{EgressAdmission, EgressSettings};
use sandbox_runtime::guard::probe::{GuardProbe, GuardStatus, GuardUnhealthy, evaluate_guard};
use sandbox_runtime::guard::status::GenerationFence;
use sandbox_runtime::{RuntimeError, SandboxRuntime};

/// `host.egress-state` period while connected (§2.5): the server's lease is
/// 15 s, so three heartbeats fit in one lease.
pub(super) const EGRESS_STATE_INTERVAL: Duration = Duration::from_secs(5);
/// Guard poll period of the monitor (the same one-second schedule as the
/// host policy reload, §3 "Live reload").
pub(super) const GUARD_POLL_INTERVAL: Duration = Duration::from_secs(1);
/// An observation older than this is reported as unreachable: a monitor
/// stuck on a hung guard socket never renews the server lease.
const OBSERVATION_MAX_AGE: Duration = Duration::from_secs(4);
const SAFE_INTEGER_MAX: u64 = 9_007_199_254_740_991;
/// The server's last `egress.blocklist`, in the daemon state directory.
pub(super) const DEPLOYMENT_BLOCKLIST_FILE: &str = "egress-deployment-blocklist.json";

/// The deployment blocklist the daemon relays to the guard (§2.0.4), as the
/// server's `egress.blocklist` delivered it (E6). The server sends
/// `configured:false` explicitly when it has no list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct DeploymentList {
    pub configured: bool,
    pub entries: Vec<String>,
}

#[derive(Debug, Clone)]
struct Observation {
    at: Instant,
    status: Option<GuardStatus>,
    verdict: Result<(), GuardUnhealthy>,
}

#[derive(Debug, Default)]
struct PushState {
    /// Desired list, and whether it changed since the last successful push.
    /// `None` is UNKNOWN: nothing is pushed, so the guard keeps enforcing
    /// its own last-good deployment list (and reports the source as not yet
    /// confirmed, which refuses new sandboxes). It becomes `Some` only from
    /// the server: the list persisted in the daemon state directory by an
    /// earlier run, or a valid `egress.blocklist` frame. A missing,
    /// unreadable or corrupt persisted list stays unknown; it is never
    /// read as `configured:false`, which would CLEAR the guard's list.
    desired: Option<DeploymentList>,
    dirty: bool,
    /// The server's list is invalid and this daemon has no earlier list from
    /// it: refuse new sandboxes rather than run with an empty list (M13).
    refused: bool,
    /// Guard instance that holds our last successful push.
    pushed_instance: Option<String>,
    fence: GenerationFence,
}

#[derive(Debug)]
pub(super) struct NodeEgress {
    probe: Option<Arc<dyn GuardProbe>>,
    host_owner_id: Mutex<String>,
    allow_open_for_others: AtomicBool,
    /// Live `allow_guest_sudo_for_others` (default on).
    allow_guest_sudo_for_others: AtomicBool,
    settings: Mutex<EgressSettings>,
    push: Mutex<PushState>,
    observation: Mutex<Option<Observation>>,
    /// Where the server's last `egress.blocklist` is kept (daemon state dir).
    deployment_path: Option<std::path::PathBuf>,
    /// Bumped when a tick pushed the deployment list or the guard verdict
    /// turned healthy: the relay loop then sends `host.egress-state` at once
    /// instead of at the next 5 s renewal.
    progress: AtomicU64,
    /// Wakes the guard monitor before its next poll (a new deployment list
    /// is pushed at once, not on the next tick).
    wake: Mutex<bool>,
    wake_cv: Condvar,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|err| err.into_inner())
}

/// What one `host.egress-state` reports, without the per-session fence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct EgressReport {
    pub allow_open_for_others: bool,
    pub allow_guest_sudo_for_others: bool,
    pub guard_ok: bool,
    pub guard_reason: Option<String>,
    pub guard_instance_id: Option<String>,
    pub guard_generation: Option<u64>,
}

impl EgressReport {
    /// "Changed" means anything but the generation, which advances on every
    /// guard resync and is carried by the periodic heartbeat anyway.
    pub fn same_state(&self, other: &Self) -> bool {
        self.allow_open_for_others == other.allow_open_for_others
            && self.allow_guest_sudo_for_others == other.allow_guest_sudo_for_others
            && self.guard_ok == other.guard_ok
            && self.guard_reason == other.guard_reason
            && self.guard_instance_id == other.guard_instance_id
    }

    pub fn message(&self, connection_epoch: u32, sequence: u64) -> HostEgressStateV11 {
        let state = HostEgressStateV11 {
            connection_epoch,
            sequence,
            allow_open_for_others: self.allow_open_for_others,
            allow_guest_sudo_for_others: self.allow_guest_sudo_for_others,
            guard_ok: self.guard_ok,
            guard_reason: self.guard_reason.clone(),
            guard_instance_id: self.guard_instance_id.clone(),
            guard_generation: self.guard_generation,
        };
        if state.is_valid() {
            return state;
        }
        // Never send a malformed lease: report "not ok" with nothing else.
        HostEgressStateV11 {
            guard_ok: false,
            guard_reason: Some(GuardUnhealthy::NotOk.as_str().into()),
            guard_instance_id: None,
            guard_generation: None,
            ..state
        }
    }
}

impl NodeEgress {
    pub fn new(probe: Option<Arc<dyn GuardProbe>>, config: &crate::config::Config) -> Self {
        Self {
            probe,
            host_owner_id: Mutex::new(String::new()),
            allow_open_for_others: AtomicBool::new(config.open_egress_for_others()),
            allow_guest_sudo_for_others: AtomicBool::new(config.guest_sudo_for_others()),
            settings: Mutex::new(config.egress_settings()),
            push: Mutex::new(PushState {
                dirty: true,
                ..PushState::default()
            }),
            deployment_path: None,
            observation: Mutex::new(None),
            progress: AtomicU64::new(0),
            wake: Mutex::new(false),
            wake_cv: Condvar::new(),
        }
    }

    /// Changes whenever the relay should report at once (see `progress`).
    pub fn progress(&self) -> u64 {
        self.progress.load(Ordering::Acquire)
    }

    /// Wake the guard monitor now.
    pub fn wake(&self) {
        *lock(&self.wake) = true;
        self.wake_cv.notify_all();
    }

    /// The monitor's sleep: until `timeout` passes or `wake` is called.
    fn wait_wake(&self, timeout: Duration) {
        let guard = lock(&self.wake);
        let (mut woken, _) = self
            .wake_cv
            .wait_timeout_while(guard, timeout, |woken| !*woken)
            .unwrap_or_else(|err| err.into_inner());
        *woken = false;
    }

    /// The hello owner (`hello.ok`): sandboxes of this owner are "own".
    pub fn set_host_owner(&self, host_owner_id: &str) {
        *lock(&self.host_owner_id) = host_owner_id.to_string();
    }

    /// The desired deployment list and whether the monitor was woken
    /// (clearing the wake), for tests.
    #[cfg(test)]
    pub(super) fn deployment_and_wake(&self) -> (Option<DeploymentList>, bool) {
        let desired = lock(&self.push).desired.clone();
        let woken = std::mem::take(&mut *lock(&self.wake));
        (desired, woken)
    }

    /// Live host policy reload (§3): consent applies to the next create or
    /// cold reconnect; settings to sandboxes materialized afterwards.
    pub fn apply_policy(
        &self,
        allow_open_for_others: bool,
        allow_guest_sudo_for_others: bool,
        settings: EgressSettings,
    ) {
        self.allow_open_for_others
            .store(allow_open_for_others, Ordering::Release);
        self.allow_guest_sudo_for_others
            .store(allow_guest_sudo_for_others, Ordering::Release);
        *lock(&self.settings) = settings;
    }

    /// Guest sudo consent backstop (OD-2): the node owner's own sandboxes
    /// always; another owner's only while `allow_guest_sudo_for_others` is
    /// on. Checked on every create and cold reconnect that carries
    /// `guestSudo`, never on allocation recovery.
    pub fn guest_sudo_permitted(&self, sandbox_owner_id: &str) -> bool {
        let own = {
            let host = lock(&self.host_owner_id);
            !host.is_empty() && *host == sandbox_owner_id
        };
        own || self.allow_guest_sudo_for_others.load(Ordering::Acquire)
    }

    pub fn allow_open_for_others(&self) -> bool {
        self.allow_open_for_others.load(Ordering::Acquire)
    }

    /// The node settings without the guard's domain blocklist (hello-time
    /// resolver probe for `egressOpen`).
    pub fn node_settings(&self) -> EgressSettings {
        lock(&self.settings).clone()
    }

    /// Replace the deployment list; the monitor is woken to push it at once
    /// (and pushes it again to every new guard instance).
    pub fn set_deployment(&self, list: DeploymentList) {
        let changed = {
            let mut push = lock(&self.push);
            let changed = push.desired.as_ref() != Some(&list);
            if changed {
                push.desired = Some(list);
                push.dirty = true;
            }
            changed
        };
        if changed {
            self.wake();
        }
    }

    /// Keep the server's last list in `path` (daemon state directory) and
    /// start from it: a valid persisted list becomes the desired one.
    pub fn with_deployment_store(mut self, path: std::path::PathBuf) -> Self {
        match std::fs::read(&path) {
            Ok(bytes) => {
                match serde_json::from_slice::<sandbox_protocol::EgressBlocklistV11>(&bytes) {
                    Ok(list)
                        if list.is_valid()
                            && !list.invalid
                            && blocklist_digest(&list.entries) == list.digest =>
                    {
                        self.set_deployment(DeploymentList {
                            configured: list.configured,
                            entries: list.entries,
                        });
                    }
                    _ => tracing::warn!(
                        path = %path.display(),
                        "ignoring an unreadable persisted deployment egress blocklist; the guard keeps its last list until the server sends one"
                    ),
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => tracing::warn!(
                path = %path.display(),
                error = %err,
                "cannot read the persisted deployment egress blocklist"
            ),
        }
        self.deployment_path = Some(path);
        self
    }

    /// The server's `egress.blocklist` (E6). The frame is shape-checked by
    /// the protocol decoder; here its digest must match its entries or the
    /// frame is ignored and the last list stays (never an empty one). The
    /// guard remains the authoritative parser of the entries.
    pub fn receive_blocklist(&self, list: &sandbox_protocol::EgressBlocklistV11) -> bool {
        if !list.is_valid() || blocklist_digest(&list.entries) != list.digest {
            tracing::warn!(
                "ignoring a deployment egress blocklist whose digest does not match; the last list stays"
            );
            return false;
        }
        if list.invalid {
            let mut push = lock(&self.push);
            if push.desired.is_some() {
                tracing::warn!(
                    "the server's deployment egress blocklist is invalid; keeping the last list it sent"
                );
            } else {
                push.refused = true;
                tracing::warn!(
                    "the server's deployment egress blocklist is invalid and this node has no earlier list; new sandboxes cannot start here until it is fixed"
                );
            }
            return true;
        }
        tracing::info!(
            configured = list.configured,
            entries = list.entries.len(),
            digest = %list.digest,
            "received the deployment egress blocklist"
        );
        if let Some(path) = &self.deployment_path
            && let Err(err) = persist_blocklist(path, list)
        {
            tracing::warn!(
                path = %path.display(),
                error = %format!("{err:#}"),
                "cannot persist the deployment egress blocklist; a restart starts from the previous one"
            );
        }
        self.set_deployment(DeploymentList {
            configured: list.configured,
            entries: list.entries.clone(),
        });
        lock(&self.push).refused = false;
        true
    }

    /// The server's list is invalid and no earlier one exists (M13).
    fn deployment_refused(&self) -> bool {
        lock(&self.push).refused
    }

    /// §1.5: `open_egress_permitted = own sandbox || node consent` from the
    /// dispatch owner, the hello owner and the live policy; `guard_ok` from
    /// one fresh guard call (never the heartbeat's cached verdict).
    pub fn admission(
        &self,
        sandbox_owner_id: &str,
        runtime: &dyn SandboxRuntime,
    ) -> EgressAdmission {
        let own = {
            let host_owner = lock(&self.host_owner_id);
            !host_owner.is_empty() && *host_owner == sandbox_owner_id
        };
        EgressAdmission {
            open_egress_permitted: own || self.allow_open_for_others(),
            guard_ok: !self.deployment_refused() && runtime.egress_guard_check().is_ok(),
        }
    }

    /// The settings a create is materialized with (§2.1): this node's config
    /// plus the guard-validated domain blocklist of both sources. A guard
    /// that cannot answer refuses the create (it is not admissible anyway).
    pub fn create_settings(&self) -> Result<EgressSettings, RuntimeError> {
        let mut settings = self.node_settings();
        if let Some(probe) = &self.probe {
            settings.domain_blocklist = probe.domain_blocklist().map_err(|err| {
                sandbox_runtime::EgressRefusal::GuardUnavailable.error(format!(
                    "the network guard did not return its blocklist: {}",
                    err.message
                ))
            })?;
        }
        settings.validate()?;
        Ok(settings)
    }

    /// One monitor tick: fresh status, fence, deployment (re)push on a new
    /// guard instance or a changed list, lease-rule verdict.
    pub fn tick(&self) {
        let Some(probe) = &self.probe else {
            self.observe(None, Err(GuardUnhealthy::Unreachable));
            return;
        };
        let status = match probe.status() {
            Ok(status) => status,
            Err(_) => {
                self.observe(None, Err(GuardUnhealthy::Unreachable));
                return;
            }
        };
        let push_list = {
            let mut push = lock(&self.push);
            if !push.fence.observe(&status) {
                // An answer older than one already seen from this instance.
                return;
            }
            let new_instance = push.pushed_instance.as_deref() != Some(&status.instance_id);
            // Unknown: never push (no clear without the server's word).
            push.desired.clone().filter(|_| new_instance || push.dirty)
        };
        let status = match push_list {
            None => status,
            Some(list) => match probe.push_deployment(list.configured, list.entries.clone()) {
                Ok(_) => {
                    {
                        let mut push = lock(&self.push);
                        push.pushed_instance = Some(status.instance_id.clone());
                        if push.desired.as_ref() == Some(&list) {
                            push.dirty = false;
                        }
                    }
                    tracing::info!(
                        guard_instance = %status.instance_id,
                        configured = list.configured,
                        "pushed the deployment blocklist to the egress guard"
                    );
                    self.progress.fetch_add(1, Ordering::AcqRel);
                    // The answer read before the push predates it.
                    match probe.status() {
                        Ok(fresh) => {
                            if !lock(&self.push).fence.observe(&fresh) {
                                return;
                            }
                            fresh
                        }
                        Err(_) => {
                            self.observe(None, Err(GuardUnhealthy::Unreachable));
                            return;
                        }
                    }
                }
                Err(err) => {
                    tracing::warn!(
                        guard_instance = %status.instance_id,
                        reason = %err.message,
                        "the egress guard refused the deployment blocklist push; retrying"
                    );
                    status
                }
            },
        };
        let verdict = probe
            .expectations()
            .map_err(|_| GuardUnhealthy::Unreachable)
            .and_then(|expect| evaluate_guard(&status, &expect))
            .and_then(|()| {
                if self.deployment_refused() {
                    Err(GuardUnhealthy::DeploymentSource)
                } else {
                    Ok(())
                }
            });
        self.observe(Some(status), verdict);
    }

    fn observe(&self, status: Option<GuardStatus>, verdict: Result<(), GuardUnhealthy>) {
        let mut slot = lock(&self.observation);
        let before = slot.as_ref().map(|o| o.verdict);
        if verdict.is_ok() && before != Some(Ok(())) {
            self.progress.fetch_add(1, Ordering::AcqRel);
        }
        if before != Some(verdict) {
            match verdict {
                Ok(()) => tracing::info!("egress guard healthy; this node accepts new sandboxes"),
                Err(reason) => {
                    let hint = matches!(
                        reason,
                        GuardUnhealthy::Unreachable | GuardUnhealthy::Outdated
                    )
                    .then(crate::guard_report::install_command);
                    tracing::warn!(
                        reason = reason.as_str(),
                        install = hint.as_deref().unwrap_or(""),
                        "egress guard not healthy; new sandboxes cannot start on this node (running ones keep running)"
                    );
                }
            }
        }
        *slot = Some(Observation {
            at: Instant::now(),
            status,
            verdict,
        });
    }

    /// The current report (§2.5): `guard_ok` exactly when the latest fresh
    /// observation passes the lease rule and names a valid instance and
    /// generation ≥ 1.
    pub fn report(&self) -> EgressReport {
        let observation = lock(&self.observation).clone();
        let (status, verdict) = match observation {
            Some(o) if o.at.elapsed() <= OBSERVATION_MAX_AGE => (o.status, o.verdict),
            _ => (None, Err(GuardUnhealthy::Unreachable)),
        };
        let identity = status.as_ref().and_then(|status| {
            (sandbox_protocol::valid_egress_guard_instance_id(&status.instance_id)
                && (1..=SAFE_INTEGER_MAX).contains(&status.generation))
            .then(|| (status.instance_id.clone(), status.generation))
        });
        let verdict = match (verdict, &identity) {
            (Ok(()), None) => Err(GuardUnhealthy::NotOk),
            (verdict, _) => verdict,
        };
        EgressReport {
            allow_open_for_others: self.allow_open_for_others(),
            allow_guest_sudo_for_others: self.allow_guest_sudo_for_others.load(Ordering::Acquire),
            guard_ok: verdict.is_ok(),
            guard_reason: verdict.err().map(|reason| reason.as_str().to_string()),
            guard_instance_id: identity.as_ref().map(|(id, _)| id.clone()),
            guard_generation: identity.map(|(_, generation)| generation),
        }
    }
}

/// `sha256:<hex>` of `JSON.stringify(entries)`, the `egress.blocklist`
/// digest the server computes (shared fixture
/// `crates/sandbox-protocol/fixtures/egress_blocklist_cases.json`).
pub(super) fn blocklist_digest(entries: &[String]) -> String {
    let text = sandbox_protocol::egress_blocklist_digest_input(entries);
    format!("sha256:{}", super::journal::sha256_hex(text.as_bytes()))
}

fn persist_blocklist(
    path: &std::path::Path,
    list: &sandbox_protocol::EgressBlocklistV11,
) -> anyhow::Result<()> {
    use anyhow::Context as _;
    let dir = path.parent().context("blocklist path has no parent")?;
    // Not a journal record: its failure never latches the journal.
    super::journal::persist_bytes(
        &super::journal::IoLatch::default(),
        dir,
        path,
        &serde_json::to_vec(list)?,
    )
}

/// Process-scoped guard poller; stops and joins on drop.
pub(super) struct GuardMonitor {
    stop: Arc<AtomicBool>,
    node: Arc<NodeEgress>,
    handle: Option<JoinHandle<()>>,
}

impl GuardMonitor {
    pub fn start(node: Arc<NodeEgress>, interval: Duration) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let log_dispatch = tracing::dispatcher::get_default(|dispatch| dispatch.clone());
        let handle = {
            let stop = stop.clone();
            let node = node.clone();
            std::thread::Builder::new()
                .name("wssp-guard-monitor".into())
                .spawn(move || {
                    let _log = tracing::dispatcher::set_default(&log_dispatch);
                    while !stop.load(Ordering::Acquire) {
                        node.tick();
                        if !stop.load(Ordering::Acquire) {
                            node.wait_wake(interval);
                        }
                    }
                })
                .ok()
        };
        if handle.is_none() {
            tracing::warn!("egress guard monitor could not start; this node reports no guard");
        }
        Self { stop, node, handle }
    }
}

impl Drop for GuardMonitor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.node.wake();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
#[path = "egress_state_tests.rs"]
mod tests;
