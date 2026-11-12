//! Daemon credential service: routes the credential frames,
//! fetches operation specs, runs the install-before-READY launch sequence
//! (residue recover → residue scrub → inject), the stop/kill/expiry
//! teardown ([`teardown`]), uploads capture envelopes, sends the credential
//! census and re-requests env after a daemon restart.
//!
//! Env values live only in memory ([`InstalledEnv`]). Nothing here logs a
//! value, a bundle, a guest path or a frame body: failures carry a fixed,
//! non-secret class only.
//!
//! Waits never hold a lock: a request registers a per-key channel, queues
//! its frame, and waits on the channel with a deadline and a cancellation
//! probe (`still_wanted`).

use sandbox_protocol::{
    BundleRequestReason, CREDENTIAL_BUNDLE_MAX_BYTES, CREDENTIAL_CHUNK_RAW_BYTES,
    CaptureAckOutcome, CaptureAckReason, CaptureKind, CredentialBundleRequestV11,
    CredentialCapabilitiesV11, CredentialCaptureAckV11, CredentialCaptureBeginV11,
    CredentialCaptureChunkV11, CredentialCensusV11, CredentialDelivery,
    CredentialQuarantineDiscardedV11, CredentialScrubbedV11, CredentialSpecRefV11,
    CredentialSpecRequestV11, CredentialSpecV11, DaemonControlMessage, ServerControlMessage,
    SpecLeaseAction, SpecLeaseV11, SpecResidueAction, encode_chunk_data,
};
use sandbox_runtime::{CredentialGuest, SandboxRuntime};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, mpsc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::journal::{BindingPhase, BindingPurpose, BindingRecord};
use super::ops::{InstalledEnv, capture_binding, install_bundle, scrub_paths};
use super::outbox::OutboxEntry;
use super::proxy::{Authority, InstallValues, LeaseRevocations, ProxyHub, ProxySettings};
use super::slot::{CredSandbox, SlotUser};
use super::store::{CaptureContext, CredentialStore};
use super::transfer::{BundleReceiver, ReceivedBundle, SpecAssembler};

#[path = "checkpoint.rs"]
mod checkpoint;
#[path = "teardown.rs"]
mod teardown;
pub use checkpoint::{CHECKPOINT_TICK, CheckpointOutcome, CheckpointTarget, CheckpointTimer};

#[path = "live.rs"]
mod live;
pub use live::FreeFailure;
pub use teardown::{
    EXPIRY_CREDENTIAL_PHASE, FreeCapture, TEARDOWN_CREDENTIAL_BUDGET, TeardownPath,
    TeardownRequest, TeardownVerdict,
};

/// `credential.spec.chunk` stream for one operation.
pub const SPEC_WAIT: Duration = Duration::from_secs(60);
/// No bundle within 60 s fails the install (INSTALLING → RELEASED).
pub const BUNDLE_WAIT: Duration = Duration::from_secs(60);
/// A capture outcome (recovery) is awaited at most this long.
pub const ACK_WAIT: Duration = Duration::from_secs(30);
/// After a daemon restart, `command.run` waits this long for env.
pub const ENV_WAIT: Duration = Duration::from_secs(10);
/// Credential frames precede the operation result on the socket.
const FLUSH_WAIT: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(100);
/// Env restore after a daemon restart retries a transient failure (busy,
/// vault unavailable, internal, timeout) with exponential backoff between
/// these bounds; it ends only on success or an authoritative refusal.
#[cfg(not(test))]
const RESTORE_RETRY_MIN: Duration = Duration::from_secs(1);
#[cfg(test)]
const RESTORE_RETRY_MIN: Duration = Duration::from_millis(10);
#[cfg(not(test))]
const RESTORE_RETRY_MAX: Duration = Duration::from_secs(60);
#[cfg(test)]
const RESTORE_RETRY_MAX: Duration = Duration::from_millis(80);
/// `credential.bundle.refused` codes that settle a restore for good: the
/// lease is not ACTIVE on this host (`not_authorized`, `stale`) or has no
/// value (`needs_login`). Every other code (`busy`, `unavailable`,
/// `internal`, `residue_pending`, …) is transient.
const RESTORE_AUTHORITATIVE_REFUSALS: [&str; 3] = ["not_authorized", "stale", "needs_login"];
const DRAIN_BATCH: usize = 64;

/// Why a bundle request failed, kept apart for the restore's retry rule.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BundleFailure {
    /// `credential.bundle.refused` with the server's non-secret code.
    Refused(String),
    /// No answer within the wait, or the socket went away.
    Timeout,
    /// A malformed request, frame sequence or bundle.
    Invalid,
    /// No longer wanted.
    Cancelled,
}

/// The result of one restore attempt.
enum RestoreStep {
    /// Pending ended: env installed, or settled without it.
    Settled,
    /// Transient: still pending, retried after a backoff.
    Retry,
    /// No longer wanted: stop the loop, the binding stays pending.
    Cancelled,
}

/// Why a launch could not complete. Fixed, non-secret classes only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchFailure {
    /// The spec could not be fetched or verified (before any guest effect).
    SpecInvalid,
    /// A residue recovery capture did not resolve (no scrub ran).
    Recovery,
    /// A residue scrub was not verified (injection never started).
    Scrub,
    /// A bundle was refused, timed out or failed to install.
    Install,
    /// The operation is no longer wanted (cancelled, superseded, revoked).
    Cancelled,
}

impl LaunchFailure {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SpecInvalid => "credential spec invalid",
            Self::Recovery => "credential recovery failed",
            Self::Scrub => "credential residue scrub not verified",
            Self::Install => "credential install failed",
            Self::Cancelled => "credential launch cancelled",
        }
    }
}

impl std::fmt::Display for LaunchFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Env is still being re-requested after a daemon restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvPending;

/// The sandbox a launch installs into.
#[derive(Debug, Clone)]
pub struct LaunchTarget {
    pub operation_id: String,
    pub guest: CredentialGuest,
    /// Digest of the operation spec (journaled per binding).
    pub spec_digest: String,
}

#[derive(Debug, Default)]
struct Frames {
    queue: VecDeque<DaemonControlMessage>,
    pushed: u64,
    drained: u64,
}

#[derive(Debug, Default)]
struct SandboxEnv {
    /// Installed env per lease, memory only.
    leases: BTreeMap<String, InstalledEnv>,
    /// Bindings whose env a daemon restart still has to re-request.
    pending: BTreeSet<String>,
}

#[derive(Default)]
struct RestoreWork {
    running: bool,
    /// Epoch of a completed census that arrived while a worker was running.
    kick: Option<u64>,
}

struct Inner {
    store: CredentialStore,
    host_id: String,
    host_owner: Mutex<Option<String>>,
    frames: Mutex<Frames>,
    flushed: Condvar,
    waiters: Mutex<HashMap<String, HashMap<u64, mpsc::Sender<ServerControlMessage>>>>,
    next_waiter: AtomicU64,
    /// Invalidates session-owned uploads and restores on disconnect / census.
    session_epoch: AtomicU64,
    env: Mutex<HashMap<String, SandboxEnv>>,
    env_cv: Condvar,
    census: Mutex<VecDeque<CredentialCensusV11>>,
    /// Set by `begin_census`, cleared by the ack of the last page.
    census_running: AtomicBool,
    /// One env-restore loop at a time; a later census only kicks it.
    /// Running and kick share a lock so worker exit cannot lose a new census.
    restore_work: Mutex<RestoreWork>,
    /// Per-sandbox guest slot and teardown progress.
    sandboxes: Mutex<HashMap<String, Arc<teardown::Coord>>>,
    /// Checkpoint schedule, last sealed digests and revoked leases.
    checkpoints: Mutex<checkpoint::Checkpoints>,
    /// Proxy mode: present only when the runtime gives sandboxes a
    /// bridge gateway; the `proxy` capability follows it.
    proxy: Mutex<Option<Arc<ProxyHub>>>,
    /// Lease revocations, shared with the proxy hub: an install, restore or
    /// env insert lands only under an [`Authority`] taken before its bundle
    /// wait and not revoked since.
    revocations: Arc<LeaseRevocations>,
}

#[derive(Clone)]
pub struct CredentialService {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for CredentialService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialService").finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn random_id(prefix: &str) -> String {
    let mut bytes = [0u8; 12];
    if ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes).is_err() {
        // Uniqueness, not secrecy: fall back to the clock.
        bytes[..8].copy_from_slice(&now_ms().to_le_bytes());
    }
    format!("{prefix}{}", super::seal::hex(&bytes))
}

/// Removes the waiter registration when the wait ends on any path.
struct Waiter<'a> {
    service: &'a CredentialService,
    key: String,
    token: u64,
    rx: mpsc::Receiver<ServerControlMessage>,
}

impl Drop for Waiter<'_> {
    fn drop(&mut self) {
        let mut waiters = lock(&self.service.inner.waiters);
        if let Some(entries) = waiters.get_mut(&self.key) {
            entries.remove(&self.token);
            if entries.is_empty() {
                waiters.remove(&self.key);
            }
        }
    }
}

impl Waiter<'_> {
    /// Next frame for this key, or `None` at the deadline / cancellation.
    fn next(
        &self,
        deadline: Instant,
        still_wanted: &dyn Fn() -> bool,
    ) -> Result<ServerControlMessage, LaunchFailure> {
        loop {
            if !still_wanted() {
                return Err(LaunchFailure::Cancelled);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(LaunchFailure::Install);
            }
            match self.rx.recv_timeout(left.min(POLL)) {
                Ok(frame) => return Ok(frame),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => return Err(LaunchFailure::Install),
            }
        }
    }
}

impl CredentialService {
    /// Opens `<state>/credentials`. Bindings that were ACTIVE with env when
    /// the daemon stopped are marked env-pending until their restore.
    pub fn start(state_dir: &Path, host_id: &str) -> anyhow::Result<Self> {
        let store = CredentialStore::open(state_dir)?;
        let mut env: HashMap<String, SandboxEnv> = HashMap::new();
        for b in store.journal().state().bindings.values() {
            if b.phase == BindingPhase::Active && restorable(b) {
                env.entry(b.sandbox_id.clone())
                    .or_default()
                    .pending
                    .insert(b.binding_id.clone());
            }
        }
        Ok(Self {
            inner: Arc::new(Inner {
                store,
                host_id: host_id.to_owned(),
                host_owner: Mutex::new(None),
                frames: Mutex::new(Frames::default()),
                flushed: Condvar::new(),
                waiters: Mutex::new(HashMap::new()),
                next_waiter: AtomicU64::new(0),
                session_epoch: AtomicU64::new(0),
                env: Mutex::new(env),
                env_cv: Condvar::new(),
                census: Mutex::new(VecDeque::new()),
                census_running: AtomicBool::new(false),
                restore_work: Mutex::default(),
                sandboxes: Mutex::new(HashMap::new()),
                checkpoints: Mutex::default(),
                proxy: Mutex::new(None),
                revocations: Arc::default(),
            }),
        })
    }

    pub fn store(&self) -> &CredentialStore {
        &self.inner.store
    }

    /// Hello capability: files and env delivery, sealed return, chunked spec
    /// transfer and periodic checkpoints; proxy delivery once
    /// [`Self::enable_proxy`] ran (the runtime has per-sandbox gateways).
    pub fn capabilities(&self) -> CredentialCapabilitiesV11 {
        CredentialCapabilitiesV11 {
            files: true,
            env: true,
            proxy: self.proxy_hub().is_some(),
            sealed_return: true,
            checkpoint: true,
            spec_transfer: true,
            max_bundle_bytes: CREDENTIAL_BUNDLE_MAX_BYTES as u64,
            return_key_epoch: self.inner.store.current_key_epoch(),
        }
    }

    /// Turns proxy delivery on. Journaled ACTIVE proxied bindings get
    /// their handles back at once as pending (503) until the `proxy` restore
    /// bundle arrives after the census.
    pub fn enable_proxy(&self, settings: ProxySettings) {
        let hub = Arc::new(ProxyHub::with_revocations(
            settings,
            self.inner.revocations.clone(),
        ));
        let journaled: Vec<BindingRecord> = self
            .inner
            .store
            .journal()
            .state()
            .bindings
            .values()
            .filter(|b| b.phase == BindingPhase::Active && !b.proxy_handles.is_empty())
            .cloned()
            .collect();
        for binding in journaled {
            let Some(lease) = binding.spec.as_ref() else {
                continue;
            };
            if hub
                .install(
                    &binding.sandbox_id,
                    lease,
                    &binding.binding_id,
                    &binding.proxy_handles,
                    None,
                )
                .is_err()
            {
                tracing::warn!("journaled credential proxy handles could not be registered");
            }
        }
        *lock(&self.inner.proxy) = Some(hub);
    }

    /// The proxy port a create must open on its gateway ACL: set
    /// only when proxy delivery runs here and the spec holds a proxied lease.
    pub fn launch_proxy_port(&self, spec: &sandbox_protocol::CredentialSpecV11) -> Option<u16> {
        if !spec
            .leases
            .iter()
            .any(|lease| lease.delivery == sandbox_protocol::CredentialDelivery::Proxy)
        {
            return None;
        }
        self.proxy_hub().map(|hub| hub.port())
    }

    pub fn proxy_hub(&self) -> Option<Arc<ProxyHub>> {
        lock(&self.inner.proxy).clone()
    }

    /// Moves a proxied lease's values from its bundle into the proxy and
    /// returns the guest env (base URLs and placeholders only). `restore`
    /// reuses the journaled handles; otherwise fresh handles are journaled
    /// before the guest can see them. Refused when the lease was revoked
    /// after `authority` was taken. The values are wiped on every path.
    fn install_proxied(
        &self,
        authority: &Authority,
        sandbox_id: &str,
        lease: &SpecLeaseV11,
        binding_id: &str,
        values: InstalledEnv,
        restore: bool,
    ) -> Result<InstalledEnv, LaunchFailure> {
        let hub = self.proxy_hub().ok_or(LaunchFailure::Install)?;
        let handles = if restore {
            self.inner
                .store
                .journal()
                .binding(binding_id)
                .map(|b| b.proxy_handles.clone())
                .filter(|h| h.len() == lease.proxy.len())
                .ok_or(LaunchFailure::Install)?
        } else {
            let handles =
                super::proxy::new_handles(lease.proxy.len()).ok_or(LaunchFailure::Install)?;
            self.inner
                .store
                .journal()
                .set_proxy_handles(binding_id, handles.clone())
                .map_err(|_| LaunchFailure::Install)?;
            handles
        };
        let mode = if restore {
            InstallValues::Restore(&values.values)
        } else {
            InstallValues::Fresh(&values.values)
        };
        let guest = hub
            .install_authorized(authority, sandbox_id, lease, binding_id, &handles, mode)
            .map_err(|e| {
                tracing::warn!(reason = e.as_str(), "credential proxy install refused");
                LaunchFailure::Install
            })?;
        drop(values);
        Ok(InstalledEnv {
            values: guest
                .into_iter()
                .map(|(name, value)| (name, super::SecretBytes::copy_from(value.as_bytes())))
                .collect(),
        })
    }

    pub fn on_registered(&self, host_owner_id: &str) {
        *lock(&self.inner.host_owner) = Some(host_owner_id.to_owned());
    }

    fn host_owner(&self) -> Option<String> {
        lock(&self.inner.host_owner).clone()
    }

    // --- frame queue -------------------------------------------------------------

    fn push(&self, message: DaemonControlMessage) -> u64 {
        let mut frames = lock(&self.inner.frames);
        frames.queue.push_back(message);
        frames.pushed += 1;
        frames.pushed
    }

    /// Frames for the connect loop to send now, in order.
    pub fn drain(&self) -> Vec<DaemonControlMessage> {
        let mut frames = lock(&self.inner.frames);
        let n = frames.queue.len().min(DRAIN_BATCH);
        let out: Vec<_> = frames.queue.drain(..n).collect();
        frames.drained += out.len() as u64;
        drop(frames);
        self.inner.flushed.notify_all();
        out
    }

    /// Waits until every frame queued up to `seq` was handed to the socket,
    /// so a result published afterwards follows them on the wire.
    fn flush(&self, seq: u64, still_wanted: &dyn Fn() -> bool) -> Result<(), LaunchFailure> {
        let deadline = Instant::now() + FLUSH_WAIT;
        let mut frames = lock(&self.inner.frames);
        while frames.drained < seq {
            if !still_wanted() {
                return Err(LaunchFailure::Cancelled);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(LaunchFailure::Install);
            }
            frames = self
                .inner
                .flushed
                .wait_timeout(frames, left.min(POLL))
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
        Ok(())
    }

    fn wait_for(&self, key: String) -> Waiter<'_> {
        let (tx, rx) = mpsc::channel();
        let token = self.inner.next_waiter.fetch_add(1, Ordering::Relaxed);
        lock(&self.inner.waiters)
            .entry(key.clone())
            .or_default()
            .insert(token, tx);
        Waiter {
            service: self,
            key,
            token,
            rx,
        }
    }

    fn deliver(&self, key: &str, frame: ServerControlMessage) {
        if let Some(entries) = lock(&self.inner.waiters).get(key) {
            for tx in entries.values() {
                let _ = tx.send(frame.clone());
            }
        }
    }

    /// Routes one server → daemon credential frame.
    pub fn handle_server(&self, frame: ServerControlMessage) {
        match frame {
            ServerControlMessage::CredentialReturnKey(ref key) => {
                match self.inner.store.install_return_key(key) {
                    Ok(ack) => {
                        self.push(DaemonControlMessage::CredentialReturnKeyAck(ack));
                        // Key acceptance: a complete census follows the ack.
                        self.begin_census();
                    }
                    Err(_) => tracing::warn!("credential return key refused"),
                }
            }
            ServerControlMessage::CredentialSpecChunk(ref c) => {
                let key = format!("spec:{}", c.operation_id);
                self.deliver(&key, frame);
            }
            ServerControlMessage::CredentialSpecRefused(ref r) => {
                let key = format!("spec:{}", r.operation_id);
                self.deliver(&key, frame);
            }
            ServerControlMessage::CredentialBundleBegin(ref b) => {
                let key = format!("bundle:{}", b.request_id);
                self.deliver(&key, frame);
            }
            ServerControlMessage::CredentialBundleChunk(ref c) => {
                let key = format!("bundle:{}", c.request_id);
                self.deliver(&key, frame);
            }
            ServerControlMessage::CredentialBundleRefused(ref r) => {
                let key = format!("bundle:{}", r.request_id);
                self.deliver(&key, frame);
            }
            ServerControlMessage::CredentialCaptureAck(ref ack) => {
                if self.inner.store.apply_capture_ack(ack).is_err() {
                    tracing::warn!("credential capture ack could not be applied");
                }
                let key = format!("ack:{}", ack.capture_id);
                self.deliver(&key, frame);
            }
            ServerControlMessage::CredentialQuarantineDiscard(ref discard) => {
                match self.inner.store.discard_quarantined(&discard.capture_ids) {
                    Ok(done) if !done.is_empty() => {
                        self.push(DaemonControlMessage::CredentialQuarantineDiscarded(
                            CredentialQuarantineDiscardedV11 { capture_ids: done },
                        ));
                    }
                    Ok(_) => {}
                    Err(_) => tracing::warn!("credential quarantine discard failed"),
                }
            }
            ServerControlMessage::CredentialRevoke(ref revoke) => {
                self.revoke_lease(&revoke.lease_id);
            }
            ServerControlMessage::CredentialCensusAck(ref ack) => self.on_census_ack(ack.page),
            _ => {}
        }
    }

    // --- census -----------------------------------------------------------------

    /// After `reconcile.complete` (and after every accepted return key): the
    /// complete census, one page at a time on the previous page's ack.
    pub fn begin_census(&self) {
        self.inner.session_epoch.fetch_add(1, Ordering::SeqCst);
        let pages = match self.inner.store.census() {
            Ok(pages) => pages,
            Err(_) => {
                tracing::warn!("credential census exceeds its bounds");
                return;
            }
        };
        let mut queue = lock(&self.inner.census);
        queue.clear();
        queue.extend(pages);
        let first = queue.front().cloned();
        drop(queue);
        if let Some(first) = first {
            self.inner.census_running.store(true, Ordering::SeqCst);
            self.push(DaemonControlMessage::CredentialCensus(first));
        }
    }

    /// Ends detached retry work as soon as its relay session ends.
    pub fn on_disconnect(&self) {
        self.inner.session_epoch.fetch_add(1, Ordering::SeqCst);
    }

    fn on_census_ack(&self, page: u32) {
        let mut queue = lock(&self.inner.census);
        if queue.front().map(|p| p.page) != Some(page) {
            return;
        }
        let acked = queue.pop_front();
        let next = queue.front().cloned();
        drop(queue);
        if let Some(next) = next {
            self.push(DaemonControlMessage::CredentialCensus(next));
        } else if acked.is_some_and(|p| p.complete)
            && self.inner.census_running.swap(false, Ordering::SeqCst)
        {
            // The server settled this host: upload what the census listed,
            // then re-request env for ACTIVE leases (daemon restart).
            let service = self.clone();
            let epoch = self.inner.session_epoch.load(Ordering::SeqCst);
            let _ = std::thread::Builder::new()
                .name("wssp-credential-census".into())
                .spawn(move || {
                    let still_wanted =
                        || service.inner.session_epoch.load(Ordering::SeqCst) == epoch;
                    service.upload_pending(&still_wanted);
                    service.restore_env(epoch);
                });
        }
    }

    // --- spec ---------------------------------------------------------------------

    /// `credential.spec.request` → verified spec. Runs before any VM effect;
    /// any failure is `credential_spec_invalid`.
    pub fn fetch_spec(
        &self,
        operation_id: &str,
        reference: &CredentialSpecRefV11,
        still_wanted: &dyn Fn() -> bool,
    ) -> Result<CredentialSpecV11, LaunchFailure> {
        let mut assembler =
            SpecAssembler::new(operation_id, reference).map_err(|_| LaunchFailure::SpecInvalid)?;
        let waiter = self.wait_for(format!("spec:{operation_id}"));
        self.push(DaemonControlMessage::CredentialSpecRequest(
            CredentialSpecRequestV11 {
                operation_id: operation_id.to_owned(),
                digest: reference.digest.clone(),
            },
        ));
        let deadline = Instant::now() + SPEC_WAIT;
        while !assembler.is_complete() {
            match waiter.next(deadline, still_wanted) {
                Ok(ServerControlMessage::CredentialSpecChunk(chunk)) => assembler
                    .push(chunk.seq, &chunk.data)
                    .map_err(|_| LaunchFailure::SpecInvalid)?,
                Ok(_) => return Err(LaunchFailure::SpecInvalid),
                Err(LaunchFailure::Cancelled) => return Err(LaunchFailure::Cancelled),
                Err(_) => return Err(LaunchFailure::SpecInvalid),
            }
        }
        assembler.finish().map_err(|_| LaunchFailure::SpecInvalid)
    }

    // --- launch (create / cold reconnect) -----------------------------------

    /// After readiness, before READY: residue `recover` entries (pack → seal
    /// → upload → outcome → scrub → `scrubbed`), then residue `scrub`
    /// entries (scrub → verify → `scrubbed`), then per lease `bundle.request`
    /// → install intent → restore → env in memory → `installed`. Returns
    /// once every frame is on the wire ahead of the operation result.
    pub fn launch(
        &self,
        runtime: &dyn SandboxRuntime,
        target: &LaunchTarget,
        spec: &CredentialSpecV11,
        still_wanted: &dyn Fn() -> bool,
    ) -> Result<(), LaunchFailure> {
        // The install holds the sandbox's guest slot: an expiry or stop that
        // must preempt it cancels the helper through this permit.
        let coord = self.coord(&target.guest.sandbox_id);
        let permit = Arc::new(sandbox_runtime::RuntimePermit::with_timeout(
            SPEC_WAIT + BUNDLE_WAIT * 8 + ACK_WAIT * 16,
        ));
        let slot = coord.slot.acquire(
            SlotUser::Install,
            super::slot::ATTACH_FREE_SLOT_WAIT,
            &permit,
        );
        let result = match slot {
            Ok(_guard) => {
                let runtime = runtime.with_cancellation(permit.clone());
                let wanted = || still_wanted() && !permit.is_cancelled();
                self.launch_inner(runtime.as_ref(), target, spec, &wanted)
            }
            Err(super::slot::SlotError::Revoked) => Err(LaunchFailure::Cancelled),
            Err(_) => Err(LaunchFailure::Install),
        };
        if result.is_err() {
            self.forget_sandbox_env(&target.guest.sandbox_id);
        }
        result
    }

    fn launch_inner(
        &self,
        runtime: &dyn SandboxRuntime,
        target: &LaunchTarget,
        spec: &CredentialSpecV11,
        still_wanted: &dyn Fn() -> bool,
    ) -> Result<(), LaunchFailure> {
        let sandbox_id = target.guest.sandbox_id.as_str();
        if spec.sandbox_id != sandbox_id
            || self.host_owner().as_deref() != Some(spec.host_owner_id.as_str())
        {
            return Err(LaunchFailure::SpecInvalid);
        }
        let mut last = 0;
        // 1. Recover residue the RECOVERING lease's RECOVER binding supersedes.
        for residue in spec
            .residue
            .iter()
            .filter(|r| r.action == SpecResidueAction::Recover)
        {
            let lease = spec
                .leases
                .iter()
                .find(|l| l.lease_id == residue.lease_id && l.action == SpecLeaseAction::Recover)
                .ok_or(LaunchFailure::SpecInvalid)?;
            let recover_binding = lease.binding_id.clone().ok_or(LaunchFailure::SpecInvalid)?;
            self.record(target, lease, &recover_binding, BindingPurpose::Recover)?;
            let ctx = CaptureContext {
                host_owner_id: spec.host_owner_id.clone(),
                host_id: self.inner.host_id.clone(),
                sandbox_owner_id: spec.sandbox_owner_id.clone(),
                sandbox_id: sandbox_id.to_owned(),
                lease_id: lease.lease_id.clone(),
                binding_id: recover_binding.clone(),
                instance_id: lease.instance_id.clone(),
                credential_id: lease.credential_id.clone(),
                capture_id: random_id("cap"),
                kind: CaptureKind::Recovery,
                residue_id: residue.residue_id.clone(),
            };
            let entry = capture_binding(
                &self.inner.store,
                runtime,
                &target.guest,
                lease,
                &ctx,
                now_ms(),
            )
            .map_err(|_| LaunchFailure::Recovery)?;
            let ack = self
                .upload(&entry, still_wanted)
                .map_err(|e| match e {
                    LaunchFailure::Cancelled => e,
                    _ => LaunchFailure::Recovery,
                })?
                .ok_or(LaunchFailure::Recovery)?;
            if !recovery_permits_scrub(&ack) {
                return Err(LaunchFailure::Recovery);
            }
            let verified = scrub_paths(runtime, &target.guest, residue.paths.clone())
                .map_err(|_| LaunchFailure::Scrub)?;
            last = self.push(DaemonControlMessage::CredentialScrubbed(
                CredentialScrubbedV11 {
                    sandbox_id: sandbox_id.to_owned(),
                    binding_ids: vec![residue.binding_id.clone()],
                    verified_absent: verified,
                },
            ));
            if !verified {
                return Err(LaunchFailure::Scrub);
            }
            let _ = self
                .inner
                .store
                .journal()
                .mark_scrubbed(std::slice::from_ref(&residue.binding_id));
        }
        // 2. Scrub every other uncleared residue row; injection waits on it.
        for residue in spec
            .residue
            .iter()
            .filter(|r| r.action == SpecResidueAction::Scrub)
        {
            if !still_wanted() {
                return Err(LaunchFailure::Cancelled);
            }
            let verified = scrub_paths(runtime, &target.guest, residue.paths.clone())
                .map_err(|_| LaunchFailure::Scrub)?;
            last = self.push(DaemonControlMessage::CredentialScrubbed(
                CredentialScrubbedV11 {
                    sandbox_id: sandbox_id.to_owned(),
                    binding_ids: vec![residue.binding_id.clone()],
                    verified_absent: verified,
                },
            ));
            if !verified {
                return Err(LaunchFailure::Scrub);
            }
            let mut journal = self.inner.store.journal();
            if journal.binding(&residue.binding_id).is_some() {
                let _ = journal.mark_scrubbed(std::slice::from_ref(&residue.binding_id));
            }
        }
        // 3. Inject (fresh and recovered leases), one bundle each.
        for lease in spec
            .leases
            .iter()
            .filter(|l| matches!(l.action, SpecLeaseAction::Inject | SpecLeaseAction::Recover))
        {
            let request_id = random_id("req");
            // Taken before the bundle wait: a revocation from here on
            // fences this install (proxy handles and env alike).
            let authority = self.inner.revocations.authority(&lease.lease_id);
            let received = self.request_bundle(
                CredentialBundleRequestV11 {
                    request_id: request_id.clone(),
                    sandbox_id: sandbox_id.to_owned(),
                    lease_id: lease.lease_id.clone(),
                    operation_id: Some(target.operation_id.clone()),
                    binding_id: None,
                    reason: BundleRequestReason::Install,
                },
                lease,
                false,
                still_wanted,
            )?;
            self.record(target, lease, &received.binding_id, BindingPurpose::Install)?;
            let binding_id = received.binding_id.clone();
            let (installed, env) = install_bundle(
                &self.inner.store,
                runtime,
                &target.guest,
                lease,
                &request_id,
                &received,
            )
            .map_err(|_| LaunchFailure::Install)?;
            drop(received);
            // Proxy mode: the values go to the host proxy, never the guest.
            let env = if lease.delivery == CredentialDelivery::Proxy {
                self.install_proxied(&authority, sandbox_id, lease, &binding_id, env, false)?
            } else {
                env
            };
            if lease.action == SpecLeaseAction::Recover
                && let Some(old) = &lease.binding_id
            {
                // The grant closed the RECOVER binding; its files were scrubbed.
                let _ = self.inner.store.journal().forget_binding(old);
            }
            last = self.push(DaemonControlMessage::CredentialInstalled(installed));
            // A revocation that raced the install wins: no env lands after it.
            let landed = self.inner.revocations.while_valid(&authority, || {
                lock(&self.inner.env)
                    .entry(sandbox_id.to_owned())
                    .or_default()
                    .leases
                    .insert(lease.lease_id.clone(), env);
            });
            if landed.is_none() {
                tracing::debug!("credential env not kept: the lease was revoked meanwhile");
            }
        }
        self.flush(last, still_wanted)
    }

    fn record(
        &self,
        target: &LaunchTarget,
        lease: &SpecLeaseV11,
        binding_id: &str,
        purpose: BindingPurpose,
    ) -> Result<(), LaunchFailure> {
        self.inner
            .store
            .journal()
            .record_binding(BindingRecord {
                binding_id: binding_id.to_owned(),
                lease_id: lease.lease_id.clone(),
                sandbox_id: target.guest.sandbox_id.clone(),
                credential_id: lease.credential_id.clone(),
                instance_id: lease.instance_id.clone(),
                spec_digest: target.spec_digest.clone(),
                copy_back: lease.copy_back,
                exclusive: lease.exclusive,
                purpose,
                install_intent: None,
                installed_seq: None,
                phase: match purpose {
                    BindingPurpose::Recover => BindingPhase::Stopped,
                    _ => BindingPhase::Installing,
                },
                teardown: None,
                scrubbed_verified: false,
                spec: Some(lease.clone()),
                proxy_handles: Vec::new(),
            })
            .map_err(|_| match purpose {
                BindingPurpose::Recover => LaunchFailure::Recovery,
                _ => LaunchFailure::Install,
            })
    }

    /// One bundle request and its stream. `restore` bundles carry env only.
    fn request_bundle(
        &self,
        request: CredentialBundleRequestV11,
        lease: &SpecLeaseV11,
        restore: bool,
        still_wanted: &dyn Fn() -> bool,
    ) -> Result<ReceivedBundle, LaunchFailure> {
        self.fetch_bundle(request, lease, restore, still_wanted)
            .map_err(|failure| match failure {
                BundleFailure::Cancelled => LaunchFailure::Cancelled,
                _ => LaunchFailure::Install,
            })
    }

    /// [`Self::request_bundle`] keeping the failure class: a restore retries
    /// a transient one and settles only on an authoritative refusal.
    fn fetch_bundle(
        &self,
        request: CredentialBundleRequestV11,
        lease: &SpecLeaseV11,
        restore: bool,
        still_wanted: &dyn Fn() -> bool,
    ) -> Result<ReceivedBundle, BundleFailure> {
        if !request.is_valid() {
            return Err(BundleFailure::Invalid);
        }
        if !still_wanted() {
            return Err(BundleFailure::Cancelled);
        }
        let waiter = self.wait_for(format!("bundle:{}", request.request_id));
        self.push(DaemonControlMessage::CredentialBundleRequest(request));
        let deadline = Instant::now() + BUNDLE_WAIT;
        let next = |deadline| {
            waiter
                .next(deadline, still_wanted)
                .map_err(|failure| match failure {
                    LaunchFailure::Cancelled => BundleFailure::Cancelled,
                    // The deadline passed or the socket went away.
                    _ => BundleFailure::Timeout,
                })
        };
        let (mut receiver, chunk_count) = match next(deadline)? {
            ServerControlMessage::CredentialBundleBegin(begin) => {
                let count = begin.chunk_count;
                (
                    BundleReceiver::new(begin).map_err(|_| BundleFailure::Invalid)?,
                    count,
                )
            }
            ServerControlMessage::CredentialBundleRefused(refused) => {
                return Err(BundleFailure::Refused(refused.code));
            }
            _ => return Err(BundleFailure::Invalid),
        };
        for expected in 0..chunk_count {
            match next(deadline)? {
                ServerControlMessage::CredentialBundleChunk(chunk) if chunk.seq == expected => {
                    receiver
                        .push(chunk.seq, &chunk.data)
                        .map_err(|_| BundleFailure::Invalid)?;
                }
                _ => return Err(BundleFailure::Invalid),
            }
        }
        receiver
            .finish(lease, restore)
            .map_err(|_| BundleFailure::Invalid)
    }

    /// `credential.capture.begin` + chunks of the self-verified envelope, then
    /// the outcome (`None` when none arrived within the wait).
    fn upload(
        &self,
        entry: &OutboxEntry,
        still_wanted: &dyn Fn() -> bool,
    ) -> Result<Option<CredentialCaptureAckV11>, LaunchFailure> {
        self.upload_within(entry, ACK_WAIT, still_wanted)
    }

    /// [`Self::upload`] with an explicit outcome wait (a teardown charges it
    /// to its own budget).
    fn upload_within(
        &self,
        entry: &OutboxEntry,
        ack_wait: Duration,
        still_wanted: &dyn Fn() -> bool,
    ) -> Result<Option<CredentialCaptureAckV11>, LaunchFailure> {
        let envelope = self
            .inner
            .store
            .outbox()
            .read(&entry.capture_id)
            .map_err(|_| LaunchFailure::Install)?;
        let chunks: Vec<String> = envelope
            .bytes
            .chunks(CREDENTIAL_CHUNK_RAW_BYTES)
            .map(encode_chunk_data)
            .collect();
        let begin = CredentialCaptureBeginV11 {
            capture_id: entry.capture_id.clone(),
            lease_id: entry.lease_id.clone(),
            binding_id: entry.binding_id.clone(),
            kid_r: entry.kid_r.clone(),
            kind: entry.kind,
            envelope_digest: envelope.digest_hex(),
            envelope_len: envelope.bytes.len() as u64,
            chunk_count: chunks.len() as u32,
        };
        drop(envelope);
        if !begin.is_valid() {
            return Err(LaunchFailure::Install);
        }
        if !still_wanted() {
            return Err(LaunchFailure::Cancelled);
        }
        let waiter = self.wait_for(format!("ack:{}", entry.capture_id));
        let mut batch = Vec::with_capacity(chunks.len() + 1);
        batch.push(DaemonControlMessage::CredentialCaptureBegin(begin));
        for (seq, data) in chunks.into_iter().enumerate() {
            batch.push(DaemonControlMessage::CredentialCaptureChunk(
                CredentialCaptureChunkV11 {
                    capture_id: entry.capture_id.clone(),
                    seq: seq as u32,
                    data,
                },
            ));
        }
        // A capture begin and its entire chunk stream are one queue transition.
        // The server has one current capture receiver per connection.
        {
            let mut frames = lock(&self.inner.frames);
            frames.pushed += batch.len() as u64;
            frames.queue.extend(batch);
        }
        match waiter.next(Instant::now() + ack_wait, still_wanted) {
            Ok(ServerControlMessage::CredentialCaptureAck(ack)) => Ok(Some(ack)),
            Ok(_) => Ok(None),
            Err(LaunchFailure::Cancelled) => Err(LaunchFailure::Cancelled),
            Err(_) => Ok(None),
        }
    }

    /// After a complete census: every unresolved envelope is uploaded
    /// (idempotent server-side by `(captureId, envelopeDigest)`).
    pub fn upload_pending(&self, still_wanted: &dyn Fn() -> bool) {
        let pending: Vec<OutboxEntry> = self
            .inner
            .store
            .outbox()
            .pending()
            .filter(|e| !e.rejected_held)
            .cloned()
            .collect();
        for entry in pending {
            if self.upload(&entry, still_wanted).is_err() {
                return;
            }
        }
    }

    // --- env ------------------------------------------------------------------------

    /// Daemon restart: `bundle.request{restore_env}` for every ACTIVE
    /// binding with env, after the census. The binding stays env-pending
    /// (commands wait, then `credential_env_pending`) until the restore
    /// succeeds or is settled for good: an authoritative refusal, a
    /// revocation, the binding no longer ACTIVE here, or a bundle that fails
    /// validation. A transient failure (busy, vault unavailable, internal,
    /// timeout) is retried with exponential backoff. One loop runs at a time;
    /// a census while it waits out a backoff makes it retry at once.
    fn restore_env(&self, epoch: u64) {
        let still_wanted = || self.inner.session_epoch.load(Ordering::SeqCst) == epoch;
        {
            let mut work = lock(&self.inner.restore_work);
            if !still_wanted() {
                return;
            }
            if work.running {
                work.kick = Some(epoch);
                return;
            }
            work.running = true;
        }
        let mut backoff = RESTORE_RETRY_MIN;
        loop {
            if !still_wanted() {
                break;
            }
            {
                let mut work = lock(&self.inner.restore_work);
                if work.kick == Some(epoch) {
                    work.kick = None;
                }
            }
            let mut retry = false;
            for binding in self.restore_candidates() {
                match self.restore_one(&binding, &still_wanted) {
                    RestoreStep::Settled => {}
                    RestoreStep::Retry => retry = true,
                    RestoreStep::Cancelled => {
                        retry = false;
                        break;
                    }
                }
            }
            if !retry || !self.wait_restore_backoff(backoff, &still_wanted) {
                break;
            }
            backoff = (backoff * 2).min(RESTORE_RETRY_MAX);
        }
        let kick = {
            let mut work = lock(&self.inner.restore_work);
            work.running = false;
            work.kick.take()
        };
        // A completed newer census may have found this worker still exiting.
        // Restart with that census's epoch, never the old cancellation probe.
        if let Some(epoch) = kick
            && !self.restore_candidates().is_empty()
        {
            self.restore_env(epoch);
        }
    }

    /// Env-pending bindings to (re-)request. A pending binding that is no
    /// longer ACTIVE with env here (torn down, recovery required) is settled
    /// without env: nothing will restore it.
    fn restore_candidates(&self) -> Vec<BindingRecord> {
        let journal = self.inner.store.journal();
        let bindings = &journal.state().bindings;
        let mut envs = lock(&self.inner.env);
        let mut todo = Vec::new();
        let mut settled = false;
        for entry in envs.values_mut() {
            entry.pending.retain(|binding_id| {
                match bindings
                    .get(binding_id)
                    .filter(|b| b.phase == BindingPhase::Active && restorable(b))
                {
                    Some(binding) => {
                        todo.push(binding.clone());
                        true
                    }
                    None => {
                        settled = true;
                        false
                    }
                }
            });
        }
        drop(envs);
        if settled {
            self.inner.env_cv.notify_all();
        }
        todo
    }

    /// Sleeps `backoff` (polling `still_wanted` and the census kick); false
    /// when the restore is no longer wanted.
    fn wait_restore_backoff(&self, backoff: Duration, still_wanted: &dyn Fn() -> bool) -> bool {
        let deadline = Instant::now() + backoff;
        loop {
            if !still_wanted() {
                return false;
            }
            if lock(&self.inner.restore_work).kick.is_some() {
                return true;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return true;
            }
            std::thread::sleep(left.min(POLL));
        }
    }

    /// One restore attempt for one env-pending binding.
    fn restore_one(&self, binding: &BindingRecord, still_wanted: &dyn Fn() -> bool) -> RestoreStep {
        let Some(lease) = binding.spec.as_ref() else {
            return RestoreStep::Settled;
        };
        // Taken before the bundle wait: a revocation during it wins.
        let authority = self.inner.revocations.authority(&binding.lease_id);
        if !self.inner.revocations.is_valid(&authority) {
            self.finish_restore(binding, &authority, None);
            return RestoreStep::Settled;
        }
        let received = self.fetch_bundle(
            CredentialBundleRequestV11 {
                request_id: random_id("req"),
                sandbox_id: binding.sandbox_id.clone(),
                lease_id: binding.lease_id.clone(),
                operation_id: None,
                binding_id: Some(binding.binding_id.clone()),
                reason: if lease.delivery == CredentialDelivery::Proxy {
                    BundleRequestReason::Proxy
                } else {
                    BundleRequestReason::RestoreEnv
                },
            },
            lease,
            true,
            still_wanted,
        );
        if !still_wanted() {
            return RestoreStep::Cancelled;
        }
        let received = match received {
            Ok(received) => Some(received),
            Err(BundleFailure::Cancelled) => return RestoreStep::Cancelled,
            Err(BundleFailure::Timeout) => {
                tracing::warn!("credential env restore timed out; retrying");
                return RestoreStep::Retry;
            }
            Err(BundleFailure::Refused(code))
                if !RESTORE_AUTHORITATIVE_REFUSALS.contains(&code.as_str()) =>
            {
                tracing::warn!(code = %code, "credential env restore refused transiently; retrying");
                return RestoreStep::Retry;
            }
            Err(BundleFailure::Refused(_) | BundleFailure::Invalid) => None,
        };
        let env = received.and_then(|received| {
            let view = received.view().ok()?;
            Some(InstalledEnv {
                values: view
                    .env
                    .iter()
                    .map(|e| (e.name.to_owned(), super::SecretBytes::copy_from(e.value)))
                    .collect(),
            })
        });
        let env = match env {
            Some(env) if lease.delivery == CredentialDelivery::Proxy => self
                .install_proxied(
                    &authority,
                    &binding.sandbox_id,
                    lease,
                    &binding.binding_id,
                    env,
                    true,
                )
                .ok(),
            other => other,
        };
        if env.is_none() && lease.delivery == CredentialDelivery::Proxy {
            // Refused: the pending handles answer 403 from now on.
            if let Some(hub) = self.proxy_hub() {
                hub.revoke_lease(&binding.lease_id);
            }
        }
        if env.is_none() {
            tracing::warn!("credential env restore refused");
        }
        self.finish_restore(binding, &authority, env);
        RestoreStep::Settled
    }

    /// Ends the binding's pending restore. The env lands only while the
    /// lease is not revoked (a revocation during the bundle wait wins).
    fn finish_restore(
        &self,
        binding: &BindingRecord,
        authority: &Authority,
        env: Option<InstalledEnv>,
    ) {
        let finish = |env: Option<InstalledEnv>| {
            let mut envs = lock(&self.inner.env);
            let entry = envs.entry(binding.sandbox_id.clone()).or_default();
            entry.pending.remove(&binding.binding_id);
            if let Some(env) = env {
                entry.leases.insert(binding.lease_id.clone(), env);
            }
        };
        let mut env = Some(env);
        let landed = self
            .inner
            .revocations
            .while_valid(authority, || finish(env.take().flatten()));
        if landed.is_none() {
            finish(None);
        }
        self.inner.env_cv.notify_all();
    }

    /// Credential env for a command in `sandbox_id`. While a daemon restart
    /// is still re-requesting it, waits up to `wait`, then `EnvPending`
    /// (retryable `credential_env_pending`).
    pub fn env_for(
        &self,
        sandbox_id: &str,
        wait: Duration,
    ) -> Result<Vec<(String, String)>, EnvPending> {
        let deadline = Instant::now() + wait;
        let mut envs = lock(&self.inner.env);
        loop {
            let pending = envs
                .get(sandbox_id)
                .is_some_and(|entry| !entry.pending.is_empty());
            if !pending {
                break;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(EnvPending);
            }
            envs = self
                .inner
                .env_cv
                .wait_timeout(envs, left)
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
        Ok(envs
            .get(sandbox_id)
            .map(|entry| {
                entry
                    .leases
                    .values()
                    .flat_map(|env| env.values.iter())
                    .filter_map(|(name, value)| {
                        std::str::from_utf8(value.expose())
                            .ok()
                            .map(|v| (name.clone(), v.to_owned()))
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    /// `credential.revoke`: the lease's env is dropped (zeroized) at once,
    /// and its proxy handles are removed (values wiped, bound guest
    /// connections closed).
    pub fn revoke_lease(&self, lease_id: &str) {
        // Tombstone first: an install, restore or env insert racing this
        // revocation is refused from here on.
        self.inner.revocations.revoke(lease_id);
        self.forget_checkpoints_of_lease(lease_id);
        if let Some(hub) = self.proxy_hub() {
            hub.revoke_lease(lease_id);
        }
        let mut envs = lock(&self.inner.env);
        for entry in envs.values_mut() {
            entry.leases.remove(lease_id);
        }
    }

    pub fn forget_sandbox_env(&self, sandbox_id: &str) {
        if let Some(hub) = self.proxy_hub() {
            hub.remove_sandbox(sandbox_id);
        }
        lock(&self.inner.env).remove(sandbox_id);
        self.inner.env_cv.notify_all();
    }

    // --- template capture --------------------------------------------------

    /// A template capture of the sandbox must be refused: a credential
    /// teardown attempt is open, a binding is being installed or torn down,
    /// or an install / checkpoint / teardown holds the guest slot. Login
    /// files are in motion, so no scrub list can be trusted yet.
    pub fn capture_refused(&self, sandbox_id: &str) -> bool {
        let busy_slot = lock(&self.inner.sandboxes)
            .get(sandbox_id)
            .is_some_and(|coord| coord.slot.holder().is_some());
        if busy_slot {
            return true;
        }
        let journal = self.inner.store.journal();
        journal
            .teardown_attempt(sandbox_id)
            .is_some_and(|a| a.state == super::journal::AttemptState::Open)
            || journal
                .bindings_of(sandbox_id)
                .any(|b| matches!(b.phase, BindingPhase::Installing | BindingPhase::Teardown))
    }

    /// The template capture's login scrub list (home-relative): every path
    /// of the capture spec's residue entries unioned with every path this
    /// host's journal records for a binding of the sandbox. Never filtered;
    /// the runtime fails the capture on any invalid entry.
    pub fn capture_scrub_paths(
        &self,
        sandbox_id: &str,
        spec: Option<&CredentialSpecV11>,
    ) -> Vec<String> {
        let mut paths: BTreeSet<String> = spec
            .map(|s| {
                s.residue
                    .iter()
                    .flat_map(|r| r.paths.iter().cloned())
                    .collect()
            })
            .unwrap_or_default();
        let journal = self.inner.store.journal();
        for binding in journal.bindings_of(sandbox_id) {
            if let Some(lease) = binding.spec.as_ref() {
                paths.extend(super::ops::included_paths(lease));
            }
        }
        paths.into_iter().collect()
    }

    /// The sandbox's guest slot (created on first use).
    pub fn slot(&self, sandbox_id: &str) -> Arc<teardown::Coord> {
        self.coord(sandbox_id)
    }

    fn coord(&self, sandbox_id: &str) -> Arc<teardown::Coord> {
        lock(&self.inner.sandboxes)
            .entry(sandbox_id.to_owned())
            .or_default()
            .clone()
    }
}

/// A binding whose env (not files) or proxy values a daemon restart can
/// re-request (`restore_env` / `proxy`).
fn restorable(binding: &BindingRecord) -> bool {
    binding.spec.as_ref().is_some_and(|s| !s.env.is_empty())
}

/// RECOVERING → INSTALLING: COMMITTED, UNCHANGED or an
/// authorized DISCARDED permit scrubbing the recovered residue; DEFERRED and
/// REJECTED never do.
fn recovery_permits_scrub(ack: &CredentialCaptureAckV11) -> bool {
    match ack.outcome {
        CaptureAckOutcome::Committed | CaptureAckOutcome::Unchanged => true,
        CaptureAckOutcome::Discarded => ack.reason.is_some_and(CaptureAckReason::is_discard),
        CaptureAckOutcome::Deferred | CaptureAckOutcome::Rejected => false,
    }
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
