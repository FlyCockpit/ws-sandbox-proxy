//! Fixed, bounded workers keep Incus waits off the socket reader.
//! Ownership/lock order:
//! - journal mutex persists intent/result/deletion, released before authority or IO;
//! - authority owns per-sandbox generations and operation completion/spawn permits;
//! - authority → runtime permit (local spawn only) or authority → exec active map;
//! - a runtime permit never reacquires authority. Incus waits hold none of these;
//! - FakeRuntime permit → short state lock; its simulated waits hold neither;
//! - completion channels own finished values until the reader publishes them.
//!
//! Commands, lifecycle, ordinary file/process work and guest signals each use
//! bounded per-sandbox FIFO queues and fixed pools, scheduled round-robin.
//! Lifecycle and ordinary work have one active job per sandbox; commands allow
//! several. Ordinary admission is at most four queued per sandbox within
//! sixteen; slow signal helpers have their own two workers. The control
//! coordinator only records intent and in-memory bookkeeping, never guest IO.
//! Stop/kill revoke permits at admission and have a reserved worker, but cannot
//! overtake an earlier lifecycle job for the same sandbox. Scheduling locks
//! are released before the lock order above.
//! Terminal state alone is not synchronization: journal writers and confirmation
//! deletion compare/mutate under the same mutex, and missing intent cannot be recreated.
use super::authority::{AuthorityReject, HostAuthority};
use super::journal::HostJournal;
use super::output::{Frame, OutputWindow};
#[cfg(test)]
use crate::sandbox_relay::test_support::FixtureRuntime;
use sandbox_protocol::results::{LiveConsistency, ResultBody};
use sandbox_protocol::{
    DispatchKindClass, OperationDispatch, OperationState, SandboxErrorCode, classify_dispatch_kind,
    unsupported_dispatch_error,
};
use sandbox_runtime::{
    CreateSandboxRequest, EffectError, GuestIdentity, KillSandboxRequest, ListDirRequest,
    MkdirRequest, MovePathRequest, ProbeSandboxRequest, ProcessSignal, ReadFileRequest,
    ReconnectSandboxRequest, RemovePathRequest, RunCommandRequest, SandboxRuntime,
    SignalProcessRequest, StatPathRequest, StopSandboxRequest, WriteFileRequest,
};
use serde_json::json;

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct HostFilePage {
    #[serde(flatten)]
    result: ResultBody,
    continuation: Option<sandbox_runtime::DirectoryContinuation>,
}

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex, mpsc};
type OutputKey = (String, u64, u64);
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const QUEUE_CAP: usize = 16;
/// A completion held for its output drain publishes this long before the
/// sandbox lease deadline, so lease expiry never fences a finished result.
const LEASE_MARGIN: Duration = Duration::from_secs(2);
/// Ordinary file/process work (4b.3): a fixed pool, one active job per
/// sandbox, per-sandbox FIFO admission of at most four queued jobs within the
/// host-wide sixteen. One sandbox's flood can never fill every slot.
const ORDINARY_WORKERS: usize = 4;
const ORDINARY_QUEUED_PER_SANDBOX: usize = 4;
/// Slow guest-signal helpers (finite 10 s deadline each) get their own small
/// pool and queue, so they never wait behind, or occupy, ordinary workers.
const SIGNAL_WORKERS: usize = 2;
const SIGNAL_QUEUED_PER_SANDBOX: usize = 4;
const SIGNAL_QUEUE_CAP: usize = 8;
// Resumes have their own two-slot bound; all sixteen wire positions stay available.
const RESUME_CAP: usize = 2;
#[derive(Debug, Clone)]
pub struct DispatchError {
    /// Typed wire reason: a capacity reason with `host_capacity`, an egress
    /// refusal reason with `unsupported_capability`.
    pub reason: Option<sandbox_protocol::ProtocolErrorReason>,
    /// Open code: a journaled `Other` from a newer daemon replays verbatim.
    pub code: sandbox_protocol::WireErrorCode,
    pub message: String,
}
impl DispatchError {
    /// A locally raised error as a runtime error. Local errors always carry a
    /// catalog code; an `Other` (only ever replayed from the journal) maps to
    /// `internal`.
    pub fn into_runtime(self) -> sandbox_runtime::RuntimeError {
        let code = self.code.known().unwrap_or(SandboxErrorCode::Internal);
        sandbox_runtime::RuntimeError::new(code, self.message)
    }
}
#[derive(Debug)]
pub struct FinishedOp {
    pub operation_id: String,
    pub sandbox_id: String,
    pub generation: u64,
    pub attempt: u64,
    pub state: OperationState,
    pub payload: Option<serde_json::Value>,
    pub error: Option<DispatchError>,
    pub download: Option<sandbox_runtime::FileContent>,
    /// True only for the exec supervisor's interim observation. Producer
    /// completion is tracked by this flag, never by persisted payload fields:
    /// a journal persistence failure blanks the payload, and mistaking that
    /// finished producer for an interim observation would pin its output
    /// window open forever.
    pub interim: bool,
    /// The attempt's ownership, only on a worker's final completion. Every
    /// observation (interim, stdin failure, refusal) carries `None`.
    pub owner: Option<super::authority::OwnershipToken>,
    /// Host facts of a `vm_not_running` readiness failure (path, Incus
    /// status, time since last seen Running) for the operator log only. The
    /// error message is reduced to its code; these never reach the wire.
    pub readiness_detail: Option<sandbox_runtime::NotRunningDetail>,
}
/// Tests compare and keep completions; a copy never carries ownership.
#[cfg(test)]
impl Clone for FinishedOp {
    fn clone(&self) -> Self {
        Self {
            operation_id: self.operation_id.clone(),
            sandbox_id: self.sandbox_id.clone(),
            generation: self.generation,
            attempt: self.attempt,
            state: self.state,
            payload: self.payload.clone(),
            error: self.error.clone(),
            download: self.download.clone(),
            interim: self.interim,
            owner: None,
            readiness_detail: self.readiness_detail.clone(),
        }
    }
}
/// Raw dispatch errors exist only before runtime issue or in read-only branches.
/// Mutation failures retain their typed evidence all the way to finish_dispatch.
#[derive(Debug)]
enum DispatchFailure {
    SessionClosed(DispatchError),
    Rejected(DispatchError),
    Effect(EffectError),
    ImageMissing(serde_json::Value),
    /// Keep pre-runtime diagnostics (including imageMissing) under uncertainty.
    AllocationUnknown(Box<DispatchFailure>),
}
impl From<DispatchError> for DispatchFailure {
    fn from(error: DispatchError) -> Self {
        Self::Rejected(error)
    }
}
impl From<AuthorityReject> for DispatchFailure {
    fn from(error: AuthorityReject) -> Self {
        let detail = DispatchError {
            reason: None,
            code: error.code.into(),
            message: error.message,
        };
        if error.session_closed {
            Self::SessionClosed(detail)
        } else {
            Self::Rejected(detail)
        }
    }
}
impl From<EffectError> for DispatchFailure {
    fn from(error: EffectError) -> Self {
        Self::Effect(error)
    }
}
type DispatchValue = (
    Option<serde_json::Value>,
    Option<sandbox_runtime::FileContent>,
    Option<OperationState>,
);
#[derive(Debug)]
enum DispatchSuccess {
    Effect(sandbox_runtime::Completed<DispatchValue>),
    ReadOnly(DispatchValue),
}
impl DispatchSuccess {
    fn into_value(self) -> DispatchValue {
        match self {
            Self::Effect(proof) => proof.into_value(),
            Self::ReadOnly(value) => value,
        }
    }
}

#[derive(Clone)]
struct TrackedCommand {
    sandbox_id: String,
    process_id: String,
    description: sandbox_runtime::CommandDescription,
    output: sandbox_runtime::CommandOutput,
}
type TrackedCommands = Arc<Mutex<HashMap<OutputKey, TrackedCommand>>>;
struct DispatchJob {
    /// Taken before queuing; a job dropped unqueued releases it.
    owner: Option<super::authority::OwnershipToken>,
    first_allocation_attempt: bool,
    tracked: TrackedCommands,
    resumed: bool,
    output: Option<sandbox_runtime::CommandOutput>,
    dispatch: OperationDispatch,
    instance_name: String,
    upload: Option<sandbox_runtime::FileContent>,
}
/// A fixed per-sandbox limit keeps the host flag simple while reserving slots
/// for other sandboxes. Clamp it when the operator chooses a smaller host cap.
const COMMANDS_PER_SANDBOX: usize = 8;
#[derive(Clone, Copy)]
struct CommandLimits {
    host: usize,
    per_sandbox: usize,
}
impl CommandLimits {
    fn new(host: u32) -> Self {
        let host = host.clamp(1, 256) as usize;
        Self {
            host,
            per_sandbox: COMMANDS_PER_SANDBOX.min(host),
        }
    }
}
#[derive(Default)]
struct CommandState {
    queues: HashMap<String, VecDeque<DispatchJob>>,
    turns: VecDeque<String>,
    active: HashMap<String, usize>,
    queued: usize,
    reservations: HashMap<String, usize>,
    urgent_queued: usize,
    resumed_queued: usize,
    ordinary_active: usize,
    /// The single reserved urgent lifecycle worker holds a job. While it does,
    /// free ordinary lifecycle workers also take wire stop/kill heads, so
    /// parallel teardowns of different sandboxes do not serialize behind it.
    urgent_running: bool,
    creator_active: HashMap<String, usize>,
    reserved_creators: HashMap<String, usize>,
    closed: bool,
}
/// This mutex only protects scheduling; it is released before journal,
/// authority, runtime admission or IO. One turn admits one FIFO queue head.
struct CommandQueue {
    state: Mutex<CommandState>,
    ready: Condvar,
    limits: CommandLimits,
    reserved_urgent: bool,
    creator_active_cap: usize,
    /// Non-urgent queued jobs, host-wide.
    total_cap: usize,
    /// Queued (not yet active) jobs per sandbox subqueue.
    queued_per_sandbox: usize,
}
/// RAII admission owned by a staged upload, then transferred to its job.
/// Dropping pending transfer state on failure/cancel/disconnect releases once.
pub(super) struct UploadReservation {
    queue: Arc<CommandQueue>,
    sandbox: String,
    creator: String,
    held: bool,
}
fn release_upload_reservation(state: &mut CommandState, sandbox: &str, creator: &str) {
    if let Some(count) = state.reserved_creators.get_mut(creator) {
        *count -= 1;
        if *count == 0 {
            state.reserved_creators.remove(creator);
        }
    }
    if let Some(count) = state.reservations.get_mut(sandbox) {
        *count -= 1;
        if *count == 0 {
            state.reservations.remove(sandbox);
        }
    }
}
impl Drop for UploadReservation {
    fn drop(&mut self) {
        if self.held {
            let mut state = self.queue.state.lock().unwrap_or_else(|e| e.into_inner());
            release_upload_reservation(&mut state, &self.sandbox, &self.creator);
        }
    }
}
impl UploadReservation {
    pub(super) fn creator(&self) -> &str {
        &self.creator
    }
    #[cfg(test)]
    pub(super) fn for_test(sandbox: &str, creator: &str) -> Self {
        Arc::new(CommandQueue::fair(4, 4, 16))
            .reserve(sandbox, creator)
            .unwrap()
    }
}
impl CommandQueue {
    fn new(limits: CommandLimits) -> Self {
        Self {
            state: Mutex::new(CommandState::default()),
            ready: Condvar::new(),
            limits,
            reserved_urgent: false,
            // Always preserve an arrival slot, including before a second
            // creator appears. Capacity one has no parallel fairness promise.
            creator_active_cap: limits.host.saturating_sub(1).max(1),
            total_cap: QUEUE_CAP,
            queued_per_sandbox: usize::MAX,
        }
    }
    /// A fair pool: `workers` active jobs host-wide, one per sandbox, and
    /// bounded per-sandbox FIFO admission within `total_cap`.
    fn fair(workers: usize, queued_per_sandbox: usize, total_cap: usize) -> Self {
        Self {
            total_cap,
            queued_per_sandbox,
            creator_active_cap: usize::MAX,
            ..Self::new(CommandLimits {
                host: workers,
                per_sandbox: 1,
            })
        }
    }
    fn lifecycle(host: usize) -> Self {
        Self {
            reserved_urgent: true,
            creator_active_cap: usize::MAX,
            ..Self::new(CommandLimits {
                host,
                per_sandbox: 1,
            })
        }
    }
    fn creator_queued(&self, state: &CommandState, creator: &str) -> usize {
        state
            .queues
            .values()
            .flat_map(|q| q.iter())
            .filter(|job| {
                job.dispatch.sandbox_owner_id == creator
                    && !job.resumed
                    && !matches!(job.dispatch.kind.as_str(), "sandbox.stop" | "sandbox.kill")
            })
            .count()
            + state.reserved_creators.get(creator).copied().unwrap_or(0)
    }
    fn reserve(
        self: &Arc<Self>,
        sandbox: &str,
        creator: &str,
    ) -> anyhow::Result<UploadReservation> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let reserved: usize = state.reservations.values().sum();
        let local = state.reservations.get(sandbox).copied().unwrap_or(0);
        if state.closed
            || state.queued + reserved >= self.total_cap
            || self.creator_queued(&state, creator) >= self.total_cap.saturating_sub(1).max(1)
            || state.queues.get(sandbox).map_or(0, VecDeque::len) + local >= self.queued_per_sandbox
        {
            anyhow::bail!("host work queue full or closed");
        }
        *state.reservations.entry(sandbox.to_owned()).or_default() += 1;
        *state
            .reserved_creators
            .entry(creator.to_owned())
            .or_default() += 1;
        Ok(UploadReservation {
            queue: self.clone(),
            sandbox: sandbox.to_owned(),
            creator: creator.to_owned(),
            held: true,
        })
    }
    fn submit(&self, job: DispatchJob) -> anyhow::Result<()> {
        self.submit_reserved(job, None)
    }
    fn submit_reserved(
        &self,
        job: DispatchJob,
        mut reservation: Option<UploadReservation>,
    ) -> anyhow::Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let reserved = reservation.as_ref().is_some_and(|r| {
            std::ptr::eq(self, r.queue.as_ref())
                && r.sandbox == job.dispatch.sandbox_id
                && r.creator == job.dispatch.sandbox_owner_id
                && r.held
        });
        if reservation.is_some() && !reserved {
            anyhow::bail!("invalid upload reservation");
        }
        // Move the reservation into the queue atomically. It already owns
        // admission; later ordinary work cannot steal it during streaming.
        if let Some(r) = reservation.as_mut() {
            release_upload_reservation(&mut state, &r.sandbox, &r.creator);
            r.held = false;
        }
        let urgent = self.reserved_urgent
            && matches!(job.dispatch.kind.as_str(), "sandbox.stop" | "sandbox.kill");
        let queued = if urgent {
            state.urgent_queued - state.resumed_queued
        } else {
            state.queued - state.urgent_queued
        };
        // Counted under the scheduler lock before enqueue; empty subqueues
        // are retired on dequeue, so a subqueue's length is its admission.
        let sandbox_queued = state
            .queues
            .get(&job.dispatch.sandbox_id)
            .map_or(0, VecDeque::len);
        if state.closed
            || (!reserved && queued + state.reservations.values().sum::<usize>() >= self.total_cap)
            || (!reserved
                && !urgent
                && sandbox_queued
                    + state
                        .reservations
                        .get(&job.dispatch.sandbox_id)
                        .copied()
                        .unwrap_or(0)
                    >= self.queued_per_sandbox)
            || (!reserved
                && !job.resumed
                && !matches!(job.dispatch.kind.as_str(), "sandbox.stop" | "sandbox.kill")
                && self.creator_queued(&state, &job.dispatch.sandbox_owner_id)
                    >= self.total_cap.saturating_sub(1).max(1))
            || (job.resumed && state.urgent_queued >= RESUME_CAP)
        {
            anyhow::bail!("host work queue full or closed");
        }
        if urgent {
            state.urgent_queued += 1;
            state.resumed_queued += usize::from(job.resumed);
        }
        let sandbox = job.dispatch.sandbox_id.clone();
        if !state.queues.contains_key(&sandbox) {
            state.turns.push_back(sandbox.clone());
        }
        state.queues.entry(sandbox).or_default().push_back(job);
        state.queued += 1;
        self.ready.notify_all();
        Ok(())
    }
    // Only an explicit closed-and-drained decision may terminate a worker.
    #[deny(clippy::question_mark_used)]
    fn next(self: &Arc<Self>) -> Option<(DispatchJob, CommandSlot)> {
        self.next_for(None)
    }
    // Lifecycle workers share the same FIFO heads and active keys. The reserved
    // urgent worker bypasses the ordinary host budget, never the per-key gate.
    // Only that single worker passes Some(true); commands pass None.
    #[deny(clippy::question_mark_used)]
    fn next_for(self: &Arc<Self>, urgent: Option<bool>) -> Option<(DispatchJob, CommandSlot)> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            // At most host workers call next, each retaining its slot through
            // completion publication. Check the host limit here as well so the
            // scheduler's bounds are explicit and independently testable.
            if urgent == Some(true) || state.ordinary_active < self.limits.host {
                let wire_waiting = urgent == Some(true)
                    && state.queues.iter().any(|(id, q)| {
                        state.active.get(id).copied().unwrap_or(0) < self.limits.per_sandbox
                            && q.iter().any(|j| {
                                !j.resumed
                                    && matches!(
                                        j.dispatch.kind.as_str(),
                                        "sandbox.stop" | "sandbox.kill"
                                    )
                            })
                    });
                for _ in 0..state.turns.len() {
                    let Some(sandbox) = state.turns.pop_front() else {
                        // The mutex and initial turn count make this unreachable:
                        // each iteration removes at most one turn. If that ever
                        // changes, stop scanning and reach the wait/close logic
                        // below rather than silently terminating this worker.
                        break;
                    };
                    let is_urgent = |job: &DispatchJob| {
                        matches!(job.dispatch.kind.as_str(), "sandbox.stop" | "sandbox.kill")
                    };
                    // Ordinary lifecycle workers take ordinary heads, and a
                    // wire stop/kill head only while the reserved worker is
                    // already busy: the reserved worker stays the guaranteed
                    // teardown lane (a lone cleanup never consumes ordinary
                    // capacity), and spare ordinary workers absorb parallel
                    // teardowns. Resumed retries stay on the reserved lane.
                    let urgent_running = state.urgent_running;
                    let matches_lane = urgent.is_none_or(|urgent| {
                        let queue = state.queues.get(&sandbox);
                        if urgent {
                            queue.is_some_and(|q| q.iter().any(is_urgent))
                        } else {
                            queue
                                .and_then(VecDeque::front)
                                .is_some_and(|j| !is_urgent(j) || (urgent_running && !j.resumed))
                        }
                    });
                    let resume_only = state
                        .queues
                        .get(&sandbox)
                        .is_some_and(|q| !q.iter().any(|j| !j.resumed && is_urgent(j)));
                    let creator_full = urgent != Some(true)
                        && state
                            .queues
                            .get(&sandbox)
                            .and_then(VecDeque::front)
                            .is_some_and(|job| {
                                state
                                    .creator_active
                                    .get(&job.dispatch.sandbox_owner_id)
                                    .copied()
                                    .unwrap_or(0)
                                    >= self.creator_active_cap
                            });
                    if creator_full
                        || (wire_waiting && resume_only)
                        || !matches_lane
                        || state.active.get(&sandbox).copied().unwrap_or(0)
                            >= self.limits.per_sandbox
                    {
                        state.turns.push_back(sandbox);
                        continue;
                    }
                    let job = state.queues.get_mut(&sandbox).and_then(VecDeque::pop_front);
                    if state.queues.get(&sandbox).is_some_and(|q| !q.is_empty()) {
                        state.turns.push_back(sandbox.clone());
                    } else {
                        state.queues.remove(&sandbox);
                    }
                    if let Some(job) = job {
                        state.queued -= 1;
                        if self.reserved_urgent
                            && matches!(job.dispatch.kind.as_str(), "sandbox.stop" | "sandbox.kill")
                        {
                            state.urgent_queued -= 1;
                            state.resumed_queued -= usize::from(job.resumed);
                        }
                        *state.active.entry(sandbox.clone()).or_default() += 1;
                        if urgent == Some(true) {
                            state.urgent_running = true;
                            // Ordinary workers that skipped a teardown head
                            // while this lane was idle may now take it.
                            self.ready.notify_all();
                        } else {
                            state.ordinary_active += 1;
                            *state
                                .creator_active
                                .entry(job.dispatch.sandbox_owner_id.clone())
                                .or_default() += 1;
                        }
                        let creator = job.dispatch.sandbox_owner_id.clone();
                        return Some((
                            job,
                            CommandSlot {
                                queue: self.clone(),
                                sandbox,
                                creator,
                                urgent: urgent == Some(true),
                            },
                        ));
                    }
                }
            }
            if state.closed && state.queued == 0 {
                return None;
            }
            state = self.ready.wait(state).unwrap_or_else(|e| e.into_inner());
        }
    }
    fn close(&self) {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).closed = true;
        self.ready.notify_all();
    }
}
/// Release capacity even if a worker exits early. Never held across other locks.
struct CommandSlot {
    queue: Arc<CommandQueue>,
    sandbox: String,
    creator: String,
    urgent: bool,
}
impl Drop for CommandSlot {
    fn drop(&mut self) {
        let mut state = self.queue.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(active) = state.active.get_mut(&self.sandbox) {
            *active -= 1;
            if *active == 0 {
                state.active.remove(&self.sandbox);
            }
        }
        if self.urgent {
            state.urgent_running = false;
        } else {
            state.ordinary_active -= 1;
            if let Some(active) = state.creator_active.get_mut(&self.creator) {
                *active -= 1;
                if *active == 0 {
                    state.creator_active.remove(&self.creator);
                }
            }
        }
        self.queue.ready.notify_all();
    }
}
enum JobReceiver {
    Commands(Arc<CommandQueue>),
    Lifecycle(Arc<CommandQueue>, bool),
}
impl JobReceiver {
    fn recv(&self) -> Option<(DispatchJob, Option<CommandSlot>)> {
        match self {
            Self::Commands(queue) => queue.next().map(|(job, slot)| (job, Some(slot))),
            Self::Lifecycle(queue, urgent) => queue
                .next_for(Some(*urgent))
                .map(|(job, slot)| (job, Some(slot))),
        }
    }
}
type Control = Box<dyn FnOnce() + Send>;
struct PendingStart {
    sandbox_id: String,
    process_id: String,
    output: sandbox_runtime::CommandOutput,
    /// Publish the bound birth again: it may have died with a dropped relay
    /// transport, and the adopting session must learn it (live R2-1).
    republish: bool,
}
pub struct RelaySupervisor {
    runtime: Arc<dyn SandboxRuntime>,
    journal: Arc<HostJournal>,
    finished_tx: mpsc::SyncSender<FinishedOp>,
    tracked: TrackedCommands,
    outputs: Mutex<HashMap<OutputKey, OutputWindow>>,
    /// 10.5 command attempts awaiting one best-effort `process.started`:
    /// (sandbox, process identity, output sink). Bounded by output slots.
    starts: Mutex<HashMap<OutputKey, PendingStart>>,
    output_turn: std::sync::atomic::AtomicUsize,
    /// Output chunk size negotiated by the current connection's `hello.ok`
    /// (D3b); 8 KiB until a server answers with a larger ceiling.
    output_chunk_bytes: std::sync::atomic::AtomicUsize,
    pending: Arc<Mutex<Vec<(FinishedOp, Instant)>>>,
    /// Fair ordinary file/process pool (4b.3).
    ordinary: Arc<CommandQueue>,
    /// Finite guest-signal pool, separate from ordinary work and control.
    signals: Arc<CommandQueue>,
    /// Reserved bookkeeping lane: SIGKILL only requests the cancel owner.
    kills: Arc<CommandQueue>,
    commands: Arc<CommandQueue>,
    output_capacity: usize,
    lifecycle: Arc<CommandQueue>,
    control: Option<mpsc::SyncSender<Control>>,
    observations: Option<mpsc::SyncSender<Control>>,
    storage_observations: Option<mpsc::SyncSender<Control>>,
    finished_rx: mpsc::Receiver<FinishedOp>,
    // One single-result mailbox per accepted observation; completed results
    // count toward the same bound as queued/running observations.
    /// Each mailbox is tagged with the session epoch it was enqueued in
    /// (minor 7): a refusal from an older session is dropped, never published
    /// on a newer one (persisted refusals reach the server as receipts).
    #[allow(clippy::type_complexity)]
    refusals: Mutex<Vec<(Option<u64>, mpsc::Receiver<(String, FinishedOp)>)>>,
    workers: Vec<JoinHandle<()>>,
    authority: HostAuthority,
    /// Process-scoped image cache, installed once at connect startup.
    images: Arc<std::sync::OnceLock<super::images::ImageService>>,
    /// Process-scoped credential service (CLI logins), installed at startup.
    credentials: Arc<std::sync::OnceLock<super::credentials::service::CredentialService>>,
    /// Process-scoped disk offload service (needs the image cache).
    offload: OffloadSlot,
    /// Process-scoped node egress state (consent, settings, guard),
    /// installed once at connect startup.
    egress: EgressSlot,
    /// Wall-clock start of this daemon run (ms): results written since then
    /// are this run's to deliver before a quiesce or shutdown ends it.
    started_ms: u64,
}
type EgressSlot = Arc<std::sync::OnceLock<Arc<super::egress_state::NodeEgress>>>;
type OffloadSlot = Arc<std::sync::OnceLock<super::offload::OffloadService>>;
impl RelaySupervisor {
    /// Install the disk offload service.
    pub fn install_offload(&self, offload: super::offload::OffloadService) {
        let _ = self.offload.set(offload);
    }
    pub fn offload(&self) -> Option<&super::offload::OffloadService> {
        self.offload.get()
    }
    /// Install the image cache used by create fetches and captures.
    pub fn install_images(&self, images: super::images::ImageService) {
        let _ = self.images.set(images);
    }
    pub fn images(&self) -> Option<&super::images::ImageService> {
        self.images.get()
    }
    /// Size output frames for the accepted hello answer. Before hello,
    /// resetting the ceiling uses the protocol minimum.
    pub fn set_output_chunk_bytes(&self, answer: Option<u32>) {
        self.output_chunk_bytes.store(
            sandbox_protocol::negotiated_output_chunk_bytes(
                sandbox_protocol::SANDBOX_OUTPUT_CHUNK_OFFER_BYTES,
                answer,
            ),
            std::sync::atomic::Ordering::Relaxed,
        );
    }
    /// The output chunk size new frames use (D3b).
    pub fn output_chunk_bytes(&self) -> usize {
        self.output_chunk_bytes
            .load(std::sync::atomic::Ordering::Relaxed)
    }
    /// Install the credential service used by create/reconnect installs.
    pub fn install_credentials(&self, credentials: super::credentials::service::CredentialService) {
        let _ = self.credentials.set(credentials);
    }
    pub fn credentials(&self) -> Option<&super::credentials::service::CredentialService> {
        self.credentials.get()
    }
    /// Install the node egress state used by create / reconnect admission.
    pub(super) fn install_egress(&self, egress: Arc<super::egress_state::NodeEgress>) {
        let _ = self.egress.set(egress);
    }
    pub(super) fn egress(&self) -> Option<&Arc<super::egress_state::NodeEgress>> {
        self.egress.get()
    }
    pub fn start(
        runtime: Arc<dyn SandboxRuntime>,
        journal: Arc<HostJournal>,
        authority: HostAuthority,
        #[cfg(target_os = "linux")] exec: Option<sandbox_runtime::ExecSupervisor>,
    ) -> Self {
        Self::start_with_command_limit(
            runtime,
            journal,
            authority,
            #[cfg(target_os = "linux")]
            exec,
            16,
        )
    }
    pub fn start_with_command_limit(
        runtime: Arc<dyn SandboxRuntime>,
        journal: Arc<HostJournal>,
        authority: HostAuthority,
        #[cfg(target_os = "linux")] exec: Option<sandbox_runtime::ExecSupervisor>,
        max_concurrent_commands: u32,
    ) -> Self {
        Self::start_with_limits(
            runtime,
            journal,
            authority,
            #[cfg(target_os = "linux")]
            exec,
            CommandLimits::new(max_concurrent_commands),
        )
    }
    fn start_with_limits(
        runtime: Arc<dyn SandboxRuntime>,
        journal: Arc<HostJournal>,
        authority: HostAuthority,
        #[cfg(target_os = "linux")] exec: Option<sandbox_runtime::ExecSupervisor>,
        limits: CommandLimits,
    ) -> Self {
        let (finished_tx, finished_rx) = mpsc::sync_channel(QUEUE_CAP);
        let mut workers = Vec::new();
        // Workers log through the starting thread's subscriber: the global
        // one in production, a scoped capture in tests (E-21).
        let log_dispatch = tracing::dispatcher::get_default(|dispatch| dispatch.clone());
        let commands = Arc::new(CommandQueue::new(limits));
        let tracked = TrackedCommands::default();
        let mut receivers = Vec::new();
        let lifecycle = Arc::new(CommandQueue::lifecycle(limits.host));
        let images: Arc<std::sync::OnceLock<super::images::ImageService>> = Arc::default();
        let credentials: Arc<std::sync::OnceLock<super::credentials::service::CredentialService>> =
            Arc::default();
        let egress: EgressSlot = Arc::default();
        let offload: OffloadSlot = Arc::default();
        // Restored lineages bind from the journaled
        // lease records, before any dispatch or autonomous bind runs.
        for (sandbox_id, base) in journal.restore_bases() {
            runtime.bind_restore_base(&sandbox_id, &base);
        }
        let ordinary = Arc::new(CommandQueue::fair(
            ORDINARY_WORKERS,
            ORDINARY_QUEUED_PER_SANDBOX,
            QUEUE_CAP,
        ));
        let signals = Arc::new(CommandQueue::fair(
            SIGNAL_WORKERS,
            SIGNAL_QUEUED_PER_SANDBOX,
            SIGNAL_QUEUE_CAP,
        ));
        let kills = Arc::new(CommandQueue::fair(1, 4, QUEUE_CAP));
        receivers.push(JobReceiver::Commands(kills.clone()));
        receivers.extend((0..ORDINARY_WORKERS).map(|_| JobReceiver::Commands(ordinary.clone())));
        receivers.extend((0..SIGNAL_WORKERS).map(|_| JobReceiver::Commands(signals.clone())));
        receivers.extend((0..limits.host).map(|_| JobReceiver::Commands(commands.clone())));
        receivers
            .extend((0..limits.host).map(|_| JobReceiver::Lifecycle(lifecycle.clone(), false)));
        receivers.push(JobReceiver::Lifecycle(lifecycle.clone(), true));
        for rx in receivers {
            let runtime = runtime.clone();
            let journal = journal.clone();
            let authority = authority.clone();
            let finished_tx = finished_tx.clone();
            #[cfg(target_os = "linux")]
            let exec = exec.clone();
            let log_dispatch = log_dispatch.clone();
            let images = images.clone();
            let credentials = credentials.clone();
            let egress = egress.clone();
            let offload = offload.clone();
            workers.push(thread::spawn(move || {
                let _log = tracing::dispatcher::set_default(&log_dispatch);
                while let Some((mut job, _slot)) = rx.recv() {
                    // This worker owns the attempt until the iteration ends,
                    // on every path (result, deferral, early exit).
                    // The job's ownership token moves into this worker; it
                    // is released when the iteration ends unless it moves on
                    // with the final completion (review rounds 1-3).
                    let owner = job.owner.take();
                    job.first_allocation_attempt = journal.first_allocation_attempt(&job.dispatch);
                    let d = &job.dispatch;
                    let started = Instant::now();
                    log_operation_started(d);
                    let lease_work = journal.lease_work(d);
                    // The journal's effective lease: for an observational
                    // reconnect this is the healthy current lease, not the
                    // overtaken queued lease the ACK echoes.
                    let mut effective_lease: Option<sandbox_protocol::HostLease> = None;
                    // D1: the build gate decides from the journaled record
                    // before any lease, Effect or runtime call.
                    let build = super::build::gate(
                        &journal,
                        images.get().is_some_and(|images| images.builds_enabled()),
                        d,
                    );
                    let defaults = match &build {
                        Err(error) => Err(error.clone()),
                        Ok(build) if d.kind == "command.run" => journal
                            .execution_env(&d.sandbox_id, d.generation, d.private_config.as_ref())
                            .map_err(|_| DispatchError { reason: None,
                                code: SandboxErrorCode::ProtocolError.into(),
                                message: "private command configuration refused".into(),
                            })
                            .and_then(|env| {
                                credential_command_env(credentials.get(), &d.sandbox_id, env)
                            })
                            .and_then(|env| {
                                command_request(
                                    d,
                                    job.instance_name.clone(),
                                    &env,
                                    build.root.as_ref(),
                                )
                                .map(|_| env)
                            }),
                        // B9: start/ready commands see the same environment
                        // as the sandbox's commands.
                        Ok(_) if d.startup.is_some()
                            && matches!(d.kind.as_str(), "sandbox.create" | "sandbox.reconnect") => journal
                            .execution_env(&d.sandbox_id, d.generation, d.private_config.as_ref())
                            .map_err(|_| DispatchError { reason: None,
                                code: SandboxErrorCode::ProtocolError.into(),
                                message: "private startup configuration refused".into(),
                            }),
                        Ok(_) => Ok(Vec::new()),
                    };
                    let (build, readiness) = build
                        .map(|proof| (proof.root, proof.readiness))
                        .unwrap_or_default();
                    let (defaults, config_error) = match defaults {
                        Ok(env) => (env, None),
                        Err(error) => (Vec::new(), Some(error)),
                    };
                    // Held from the passed gate until Effect is durable (or
                    // refused): a detach waits for it (review #2).
                    let mut admission = None;
                    // A kill or reconnect preempts the
                    // sandbox's unfinished disk offload and, before any lease
                    // or Effect record, waits for an in-flight publish. The
                    // hold keeps a new publish out until this iteration ends.
                    let (_offload_hold, preempted) = match (d.kind.as_str(), offload.get()) {
                        ("sandbox.reconnect" | "sandbox.kill", Some(offload)) => match offload
                            .preempt(&d.sandbox_id, &|| {
                                !journal.cancel_blocks(&d.operation_id, d.generation)
                                    && authority.owned(&d.operation_id, d.generation, d.attempt)
                            }) {
                            Ok(hold) => (Some(hold), Ok(())),
                            Err(error) => (
                                None,
                                Err(DispatchError {
                                    reason: None,
                                    code: error.code.into(),
                                    message: error.message.into(),
                                }),
                            ),
                        },
                        _ => (None, Ok(())),
                    };
                    // A planned image fetch runs in the Intent phase, before
                    // the effect gate, any lease or Effect record (P10): it
                    // continues while the create is still wanted.
                    let fetched = preempted.and_then(|()| match (d.kind.as_str(), images.get()) {
                        // A restore fetches its stored disk
                        // here too, paced by `offload_fetch_mbps`; a cached
                        // cold reconnect proves its retained root first.
                        ("sandbox.reconnect", _) if d.restore.is_some() || d.expect_disk.is_some() => {
                            restore_intent(runtime.as_ref(), images.get(), offload.get(), d, &job.instance_name, &|| {
                                !journal.cancel_blocks(&d.operation_id, d.generation)
                                    && authority.owned(&d.operation_id, d.generation, d.attempt)
                            })
                        }
                        ("sandbox.create", Some(images)) if d.image.is_some() => images
                            .ensure_image(d, &|| {
                                !journal.cancel_blocks(&d.operation_id, d.generation)
                                    && authority.owned(&d.operation_id, d.generation, d.attempt)
                            })
                            .map_err(|error| DispatchError {
                                reason: error.reason,
                                code: error.code.into(),
                                message: error.message.into(),
                            }),
                        ("sandbox.create", None) if d.image.is_some() => Err(DispatchError {
                            reason: None,
                            code: SandboxErrorCode::UnsupportedCapability.into(),
                            message: "image cache disabled".into(),
                        }),
                        _ => Ok(()),
                    });
                    // CLI logins (§6.1): the operation's credential spec is
                    // fetched and verified before any VM effect; a failure
                    // touches no guest (`credential_spec_invalid`).
                    let still_wanted = || {
                        !journal.cancel_blocks(&d.operation_id, d.generation)
                            && authority.owned(&d.operation_id, d.generation, d.attempt)
                    };
                    let mut teardown: Option<super::credentials::service::TeardownVerdict> = None;
                    let (fetched, credential_spec) = match fetched {
                        Ok(()) => match fetch_credential_spec(credentials.get(), d, &still_wanted) {
                            Ok(spec) => (Ok(()), spec),
                            Err(error) => (Err(error), None),
                        },
                        Err(error) => (Err(error), None),
                    };
                    // CLI logins (§9): a create whose spec holds a proxied
                    // login records the gateway proxy allow in its ACL plan.
                    let credential_proxy_port = match (credential_spec.as_ref(), credentials.get()) {
                        // A restore is a new VM's ACL plan.
                        (Some(spec), Some(service))
                            if d.kind == "sandbox.create" || d.restore.is_some() =>
                        {
                            service.launch_proxy_port(spec)
                        }
                        _ => None,
                    };
                    // CLI logins (§7.6): a template capture also scrubs every
                    // login path the spec and this host's journal name.
                    let capture_credentials = match (d.kind.as_str(), credentials.get()) {
                        ("sandbox.capture", Some(service)) => {
                            service.capture_scrub_paths(&d.sandbox_id, credential_spec.as_ref())
                        }
                        _ => Vec::new(),
                    };
                    let result = if let Some(error) = config_error {
                        Err(DispatchFailure::Rejected(error))
                    } else if let Err(error) = fetched {
                        Err(DispatchFailure::Rejected(error))
                    } else if let Some(error) = capture_credential_refusal(credentials.get(), d) {
                        Err(DispatchFailure::Rejected(error))
                    } else if let Err(error) = authority
                        // M4: carried (unadopted) work waits here, before the
                        // stream/cancel checks re-run and before any lease or
                        // Effect record, until it is adopted or revoked.
                        .wait_effect_admission(&d.operation_id, d.generation, d.attempt)
                        .and_then(|token| {
                            admission = Some(token);
                            authority
                                .accept_stream(&d.operation_id, d.generation, d.attempt)
                                .map(|_| ())
                        })
                    {
                        if error.session_closed {
                            Err(DispatchFailure::from(error))
                        } else {
                            Err(DispatchFailure::Rejected(DispatchError { reason: None,
                                code: SandboxErrorCode::Cancelled.into(),
                                message: "cancelled before effect".into(),
                            }))
                        }
                    } else if journal.cancel_blocks(&d.operation_id, d.generation) {
                        Err(DispatchFailure::Rejected(DispatchError { reason: None,
                            code: SandboxErrorCode::Cancelled.into(),
                            message: "cancelled before effect".into(),
                        }))
                    } else if let Some(refusal) = matches!(
                        d.kind.as_str(),
                        "sandbox.create" | "sandbox.reconnect" | "sandbox.lease.renew"
                    )
                    .then(|| journal.accept_lease(d))
                    .and_then(|accepted| match accepted {
                        Ok(lease) => {
                            effective_lease = Some(lease);
                            // The journaled restore
                            // base binds every later bind of this sandbox,
                            // and a restore drops this host's stale offload
                            // journal entry.
                            if let Some(base) = journal.restore_base(&d.sandbox_id) {
                                runtime.bind_restore_base(&d.sandbox_id, &base);
                            }
                            if d.restore.is_some()
                                && let Some(offload) = offload.get()
                            {
                                offload.forget_on_restore(&d.sandbox_id);
                            }
                            None
                        }
                        Err(error) => Some(error),
                    }) {
                        if journal.io_failed() {
                            Err(DispatchFailure::Effect(
                                sandbox_runtime::RuntimeError::new(
                                    SandboxErrorCode::UnknownOutcome,
                                    "lease persistence failed",
                                )
                                .into(),
                            ))
                        } else if refusal
                            .downcast_ref::<super::journal::LeaseCeilingExceeded>()
                            .is_some()
                        {
                            // Before any effect: the host's local ceiling
                            // refused this lease. A typed policy refusal, not
                            // a state conflict.
                            Err(DispatchFailure::Rejected(DispatchError { reason: None,
                                code: SandboxErrorCode::LeaseExceedsPolicy.into(),
                                message: "lease exceeds the host lease ceiling".into(),
                            }))
                        } else {
                            Err(DispatchFailure::Rejected(DispatchError { reason: None,
                                code: SandboxErrorCode::StateConflict.into(),
                                message: "lease was not durably accepted".into(),
                            }))
                        }
                    } else if journal.record_effect(&d.operation_id).is_err() {
                        Err(DispatchFailure::Effect(
                            sandbox_runtime::RuntimeError::new(
                                SandboxErrorCode::UnknownOutcome,
                                "receipt persistence failed",
                            )
                            .into(),
                        ))
                    } else {
                        // Effect is durable: the transition is over.
                        drop(admission.take());
                        // Debug-build wire-test hold: a create in Effect,
                        // before any runtime call (release builds: no-op).
                        if d.kind == "sandbox.create" {
                            crate::state::test_barrier("create_effect");
                        }
                        // CLI logins (§10.3, §10.4): capture by default
                        // before the VM stops or is destroyed.
                        teardown = credential_teardown(
                            credentials.get(),
                            runtime.as_ref(),
                            &journal,
                            d,
                            &still_wanted,
                        );
                        if let Some(refusal) = teardown.as_ref().and_then(teardown_refusal) {
                            Err(refusal)
                        } else if matches!(d.kind.as_str(), "credential.attach" | "credential.free") {
                            run_credential_live(
                                credentials.get(),
                                runtime.as_ref(),
                                &journal,
                                d,
                                credential_spec.as_ref(),
                                &still_wanted,
                            )
                        } else {
                        #[cfg(target_os = "linux")]
                        {
                            if d.kind == "sandbox.capture" {
                                run_capture(&runtime, &job, &authority, images.get(), &capture_credentials)
                            } else if d.kind == "command.run"
                                && let Some(exec) = &exec
                            {
                                run_supervised(
                                    exec,
                                    &job,
                                    &authority,
                                    &journal,
                                    &finished_tx,
                                    &defaults,
                                    build.as_ref(),
                                )
                            } else {
                                run_job(
                                    &runtime,
                                    &job,
                                    &authority,
                                    effective_lease.as_ref(),
                                    &defaults,
                                    Launch {
                                        build: build.as_ref(),
                                        readiness,
                                        egress: egress.get().map(|egress| egress.as_ref()),
                                        credential_proxy_port,
                                    },
                                )
                            }
                        }
                        #[cfg(not(target_os = "linux"))]
                        {
                            if d.kind == "sandbox.capture" {
                                run_capture(&runtime, &job, &authority, images.get(), &capture_credentials)
                            } else {
                                run_job(
                                    &runtime,
                                    &job,
                                    &authority,
                                    effective_lease.as_ref(),
                                    &defaults,
                                    Launch {
                                        build: build.as_ref(),
                                        readiness,
                                        egress: egress.get().map(|egress| egress.as_ref()),
                                        credential_proxy_port,
                                    },
                                )
                            }
                        }
                        }
                    };
                    // A restore's imported disk image
                    // never outlives its attempt, also when the attempt was
                    // refused after the fetch and before init.
                    delete_restore_image(runtime.as_ref(), d);
                    // CLI logins (§10.4): credentials are installed after
                    // readiness and before the create/reconnect reports READY.
                    let mut installed = Vec::new();
                    let launch_failure = match (&result, credential_spec.as_ref(), credentials.get()) {
                        (Ok(_), Some(spec), Some(service))
                            if matches!(d.kind.as_str(), "sandbox.create" | "sandbox.reconnect") =>
                        {
                            service
                            .launch(
                                runtime.as_ref(),
                                &super::credentials::service::LaunchTarget {
                                    operation_id: d.operation_id.clone(),
                                    guest: credential_guest(d),
                                    spec_digest: d
                                        .credential_spec
                                        .as_ref()
                                        .map(|r| r.digest.clone())
                                        .unwrap_or_default(),
                                },
                                spec,
                                &still_wanted,
                            )
                            .map(|reports| installed = reports)
                            .err()
                            .map(|failure| credential_launch_failure(runtime.as_ref(), &job, failure))
                        }
                        _ => None,
                    };
                    drop(admission);
                    drop(lease_work);
                    let credential_refusal = matches!(&result, Err(DispatchFailure::Rejected(e))
                        if e.code == SandboxErrorCode::CredentialCaptureFailed);
                    if (job.resumed
                        && !credential_refusal
                        && matches!(&result, Err(DispatchFailure::Rejected(_))))
                        || (matches!(d.kind.as_str(), "sandbox.stop" | "sandbox.kill")
                            && matches!(&result, Err(DispatchFailure::SessionClosed(_))))
                    {
                        // Recovery owns a durable teardown obligation. A wire
                        // teardown also survives session closure before issue.
                        // Keep Intent/UNKNOWN for the next session; fresh
                        // validation/capacity/authority refusals still fail.
                        if journal.defer_teardown(&d.operation_id).is_err() {
                            tracing::warn!(operation_id = %d.operation_id,
                                "teardown recovery deferral could not be persisted; keeping pending");
                        }
                        continue;
                    }
                    let result = classify_allocation_refusal(runtime.as_ref(), d, job.first_allocation_attempt, result);
                    let result = match launch_failure {
                        Some(failure) => Err(failure),
                        None => result,
                    };
                    let mut finished = finish_dispatch(d, result, started);
                    // A confirmed kill removed the root: a `stored` offload
                    // entry for it would never be released otherwise. Only
                    // enqueued: the alias IO never delays this receipt.
                    if d.kind == "sandbox.kill"
                        && finished.state == OperationState::Succeeded
                        && let Some(offload) = offload.get()
                    {
                        offload.forget_on_kill(&d.sandbox_id);
                    }
                    // CLI logins: the stop/kill receipt carries the teardown
                    // outcomes; a stopped/destroyed VM settles its bindings.
                    if let (Some(super::credentials::service::TeardownVerdict::Proceed(outcomes)), Some(service)) =
                        (teardown.as_ref(), credentials.get())
                        && finished.state == OperationState::Succeeded
                    {
                        service.settle_teardown(&d.sandbox_id, d.kind == "sandbox.kill");
                        if !outcomes.is_empty()
                            && let Some(fields) = finished
                                .payload
                                .get_or_insert_with(|| json!({}))
                                .as_object_mut()
                        {
                            fields.insert("credentialOutcomes".into(), json!(outcomes));
                        }
                    }
                    // CLI logins: the READY receipt repeats every `installed`
                    // report, so a frame lost with its socket cannot turn a
                    // replayed create/reconnect into an install failure.
                    if finished.state == OperationState::Succeeded
                        && !installed.is_empty()
                        && let Some(fields) = finished
                            .payload
                            .get_or_insert_with(|| json!({}))
                            .as_object_mut()
                    {
                        fields.insert("credentialInstalled".into(), json!(installed));
                    }
                    // M7: a READY-based create ACKs readyAt + timeout, not the
                    // provisional backstop it was dispatched with.
                    if d.kind == "sandbox.create"
                        && finished.state == OperationState::Succeeded
                        && d.lease.as_ref().is_some_and(|l| l.from_ready_ms.is_some())
                    {
                        match journal.settle_ready_lease(d) {
                            Ok(Some(settled)) => {
                                if let Some(fields) = finished
                                    .payload
                                    .get_or_insert_with(|| json!({}))
                                    .as_object_mut()
                                {
                                    fields.insert("lease".into(), json!(settled));
                                }
                            }
                            Ok(None) => {}
                            Err(_) => {
                                tracing::warn!(operation_id = %d.operation_id,
                                    "READY lease could not be settled; the provisional backstop stays");
                            }
                        }
                    }
                    if let Some(output) = &job.output {
                        let output_bytes = output.close();
                        let payload = finished.payload.get_or_insert_with(|| json!({}));
                        if let Some(fields) = payload.as_object_mut() {
                            fields.insert("outputBytes".into(), json!(output_bytes));
                        }
                    }
                    if d.kind == "command.run" {
                        job.tracked.lock().unwrap_or_else(|e| e.into_inner()).remove(&(d.operation_id.clone(), d.generation, d.attempt));
                    }
                    let finished = settle_carry_expired(&journal, d, finished);
                    let mut finished = persist_finished(&journal, finished);
                    // Publication now owns the attempt until it is published.
                    finished.owner = owner;
                    if finished_tx.send(finished).is_err() {
                        break;
                    }
                }
            }));
        }
        let (observation_tx, observation_rx) = mpsc::sync_channel::<Control>(QUEUE_CAP);
        // Image inventory and live probes must never block cancel/stdin/control IO.
        workers.push(thread::spawn(move || {
            while let Ok(work) = observation_rx.recv() {
                work();
            }
        }));
        // Storage health must progress even while inventory waits on DNS policy IO.
        let (storage_tx, storage_rx) = mpsc::sync_channel::<Control>(1);
        workers.push(thread::spawn(move || {
            while let Ok(work) = storage_rx.recv() {
                work();
            }
        }));
        let (control_tx, control_rx) = mpsc::sync_channel::<Control>(QUEUE_CAP);
        // Keep the directory lock alive until even detached control work has stopped.
        let control_journal = journal.clone();
        workers.push(thread::spawn(move || {
            let _journal = control_journal;
            while let Ok(work) = control_rx.recv() {
                work();
            }
        }));
        Self {
            runtime,
            journal,
            finished_tx,
            tracked,
            outputs: Mutex::new(HashMap::new()),
            starts: Mutex::new(HashMap::new()),
            output_turn: std::sync::atomic::AtomicUsize::new(0),
            output_chunk_bytes: std::sync::atomic::AtomicUsize::new(
                sandbox_protocol::SANDBOX_OUTPUT_CHUNK_MIN_BYTES,
            ),
            pending: Arc::new(Mutex::new(Vec::new())),
            lifecycle,
            ordinary,
            signals,
            kills,
            commands,
            // Running + queued commands, including windows awaiting output ACKs.
            output_capacity: limits.host + QUEUE_CAP,
            control: Some(control_tx),
            observations: Some(observation_tx),
            storage_observations: Some(storage_tx),
            finished_rx,
            refusals: Mutex::new(Vec::new()),
            workers,
            authority,
            images,
            credentials,
            offload,
            egress,
            started_ms: wall_ms(),
        }
    }
    /// Existence reads for admission refusals stay on the bounded observation
    /// lane, so a slow daemon cannot block socket control traffic.
    pub(super) fn refuse_before_runtime(&self, d: &OperationDispatch, error: DispatchError) {
        let first = self.journal.first_allocation_attempt(d);
        let runtime = self.runtime.clone();
        let journal = self.journal.clone();
        let tx = self.finished_tx.clone();
        let pending = self.pending.clone();
        let dispatch = d.clone();
        let queued_error = error.clone();
        if self
            .observe(move || {
                let result = classify_allocation_refusal(
                    runtime.as_ref(),
                    &dispatch,
                    first,
                    Err(DispatchFailure::Rejected(queued_error)),
                );
                let finished = finish_dispatch(&dispatch, result, Instant::now());
                if let Err(
                    mpsc::TrySendError::Full(finished) | mpsc::TrySendError::Disconnected(finished),
                ) = tx.try_send(persist_finished(&journal, finished))
                {
                    pending
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push((finished, Instant::now()));
                }
            })
            .is_err()
        {
            // Queue saturation supplies no absence proof. Persist uncertainty
            // on the regular completion path without fallible submission.
            let error = DispatchFailure::Rejected(error);
            let error = if matches!(d.kind.as_str(), "sandbox.create" | "sandbox.reconnect") {
                DispatchFailure::AllocationUnknown(Box::new(error))
            } else {
                error
            };
            let finished = finish_dispatch(d, Err(error), Instant::now());
            self.pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((persist_finished(&self.journal, finished), Instant::now()));
        }
    }

    /// Unadmitted refusals have no local completion permit. Keep their exact
    /// dispatch identity and publish through the existing server-fenced result
    /// protocol, without completing/revoking somebody else's local authority.
    pub(super) fn refuse_unadmitted(
        &self,
        d: &OperationDispatch,
        first: bool,
        persist: bool,
        error: DispatchError,
    ) -> Option<FinishedOp> {
        let mut slots = self.refusals.lock().unwrap_or_else(|e| e.into_inner());
        if slots.len() < QUEUE_CAP {
            let runtime = self.runtime.clone();
            let journal = self.journal.clone();
            let dispatch = d.clone();
            let queued_error = error.clone();
            let (tx, rx) = mpsc::sync_channel(1);
            if self
                .observe(move || {
                    let result = classify_allocation_refusal(
                        runtime.as_ref(),
                        &dispatch,
                        first,
                        Err(DispatchFailure::Rejected(queued_error)),
                    );
                    let mut finished = finish_dispatch(&dispatch, result, Instant::now());
                    if persist {
                        finished = persist_finished(&journal, finished);
                    }
                    // This mailbox receives exactly one result. A slow socket
                    // cannot block the observation worker or consume more slots.
                    let _ = tx.try_send((dispatch.kind, finished));
                })
                .is_ok()
            {
                slots.push((self.authority.session_epoch(), rx));
                return None;
            }
        }
        // Full/closed observation lane or result slots: answer on the reader
        // through send_finished without any runtime IO or fallible submission.
        let mut finished = finish_dispatch(
            d,
            Err(DispatchFailure::AllocationUnknown(Box::new(
                DispatchFailure::Rejected(error),
            ))),
            Instant::now(),
        );
        if persist {
            finished = persist_finished(&self.journal, finished);
        }
        Some(finished)
    }

    pub(super) fn poll_refusals(&self) -> Vec<(String, FinishedOp)> {
        let mut ready = Vec::new();
        let current = self.authority.session_epoch();
        self.refusals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(epoch, rx)| match rx.try_recv() {
                Ok(result) => {
                    if *epoch == current {
                        ready.push(result);
                    }
                    false
                }
                Err(mpsc::TryRecvError::Empty) => true,
                Err(mpsc::TryRecvError::Disconnected) => false,
            });
        ready
    }

    /// The process-scoped completion channel, for results produced outside
    /// the worker pools (stdin failures): they drain with every other result.
    pub(super) fn finished_sender(&self) -> mpsc::SyncSender<FinishedOp> {
        self.finished_tx.clone()
    }

    /// Sandboxes with queued or active lifecycle work.
    pub(super) fn lifecycle_busy(&self) -> std::collections::HashSet<String> {
        let state = self
            .lifecycle
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        state
            .active
            .keys()
            .chain(
                state
                    .queues
                    .iter()
                    .filter(|(_, queue)| !queue.is_empty())
                    .map(|(id, _)| id),
            )
            .cloned()
            .collect()
    }

    /// WP7: counts the `command.run` work a quiesce must still drain (the
    /// quiesce worker waits for it). Independent of this supervisor's
    /// lifetime. A command is drained only once the server confirmed its
    /// result: a process that exited is not enough, its tail output and its
    /// result frame may still be waiting to publish (live finding: a result
    /// that only reached the server as the next daemon's bare receipt lost
    /// its stdout). Counted:
    /// - queued and running attempts, and every accepted attempt someone
    ///   still owns (a finished one waiting behind its output drain or for
    ///   publication), whichever is larger;
    /// - terminal `command.run` results written since this call (this daemon
    ///   run) that the server has not confirmed yet.
    pub(super) fn quiesce_outstanding(&self) -> Box<dyn Fn() -> usize + Send> {
        let commands = self.commands.clone();
        let authority = self.authority.clone();
        let journal = self.journal.clone();
        let since_ms = self.started_ms;
        Box::new(move || {
            let running = {
                let state = commands.state.lock().unwrap_or_else(|e| e.into_inner());
                state.queued + state.active.values().sum::<usize>()
            };
            let owned = authority
                .pending_of_kind("command.run")
                .iter()
                .filter(|id| {
                    authority
                        .pending(id)
                        .is_some_and(|work| !work.owners.is_empty())
                })
                .count();
            running.max(owned) + journal.unconfirmed_results_since("command.run", since_ms)
        })
    }

    /// fu-a: the shutdown flush still has something to deliver: a finished
    /// completion waiting to publish (behind its output drain or the step-end
    /// barrier), or a `command.run` result written this run that the server
    /// has not confirmed. Running work does not count.
    pub(super) fn shutdown_flush_pending(&self) -> bool {
        !self
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
            || self
                .journal
                .unconfirmed_results_since("command.run", self.started_ms)
                > 0
    }

    /// After a revoke-all exit, wait (bounded) for revoked jobs to drain out
    /// of every pool, as the per-session teardown's join used to.
    pub(super) fn quiesce(&self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        let pools = [
            &self.ordinary,
            &self.signals,
            &self.kills,
            &self.commands,
            &self.lifecycle,
        ];
        while Instant::now() < deadline {
            let busy = pools.iter().any(|pool| {
                let state = pool.state.lock().unwrap_or_else(|e| e.into_inner());
                state.queued > 0 || !state.active.is_empty()
            });
            if !busy {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    pub(super) fn reserve_upload(&self, sandbox: &str) -> anyhow::Result<UploadReservation> {
        let creator = self
            .journal
            .sandbox_owner(sandbox)
            .ok_or_else(|| anyhow::anyhow!("missing verified workload binding"))?;
        self.ordinary.reserve(sandbox, &creator)
    }
    pub(super) fn submit_upload(
        &self,
        dispatch: OperationDispatch,
        instance_name: String,
        upload: sandbox_runtime::FileContent,
        reservation: UploadReservation,
    ) -> anyhow::Result<()> {
        let owner = self.authority.take_ownership(
            &dispatch.operation_id,
            dispatch.generation,
            dispatch.attempt,
        );
        self.ordinary.submit_reserved(
            DispatchJob {
                owner,
                first_allocation_attempt: false,
                tracked: self.tracked.clone(),
                resumed: false,
                output: None,
                dispatch,
                instance_name,
                upload: Some(upload),
            },
            Some(reservation),
        )
    }
    pub fn submit(
        &self,
        dispatch: OperationDispatch,
        instance_name: String,
        upload: Option<sandbox_runtime::FileContent>,
    ) -> anyhow::Result<()> {
        // Submission follows verified Intent admission. Never let a supplied
        // owner split one creator's scheduling/staging quotas across identities.
        if self.journal.sandbox_owner(&dispatch.sandbox_id).as_deref()
            != Some(dispatch.sandbox_owner_id.as_str())
        {
            anyhow::bail!("workload binding changed");
        }
        let output = (dispatch.kind == "command.run").then(|| {
            let output = sandbox_runtime::CommandOutput::default();
            match &dispatch.process_id {
                Some(process_id) => output.with_start_sink(start_sink(
                    self.journal.clone(),
                    &dispatch,
                    process_id.clone(),
                )),
                None => output,
            }
        });
        let key = (
            dispatch.operation_id.clone(),
            dispatch.generation,
            dispatch.attempt,
        );
        let mut outputs = self.outputs.lock().unwrap_or_else(|e| e.into_inner());
        if output.is_some() && (outputs.len() >= self.output_capacity || outputs.contains_key(&key))
        {
            anyhow::bail!("output slots full");
        }
        let is_command = dispatch.kind == "command.run";
        let process_id = dispatch.process_id.clone().filter(|_| is_command);
        let sandbox_id = dispatch.sandbox_id.clone();
        let is_lifecycle = is_lifecycle_kind(&dispatch.kind)
            || matches!(
                dispatch.kind.as_str(),
                "sandbox.lease.renew" | "sandbox.probe" | "sandbox.capture"
            );
        if let (Some(process_id), Some(output)) = (&process_id, &output) {
            // Description only; the worker's build gate still decides the run.
            let build = super::build::gate(
                &self.journal,
                self.images().is_some_and(|images| images.builds_enabled()),
                &dispatch,
            )
            .map_err(DispatchError::into_runtime)?
            .root;
            let request = command_request(&dispatch, instance_name.clone(), &[], build.as_ref())
                .map_err(DispatchError::into_runtime)?;
            let description = sandbox_runtime::CommandDescription::from_request(&request)
                .ok_or_else(|| {
                    sandbox_runtime::RuntimeError::new(
                        SandboxErrorCode::ProtocolError,
                        "invalid command description",
                    )
                })?;
            self.tracked
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(
                    key.clone(),
                    TrackedCommand {
                        sandbox_id: sandbox_id.clone(),
                        process_id: process_id.clone(),
                        description,
                        output: output.clone(),
                    },
                );
        }
        let job = DispatchJob {
            owner: self.authority.take_ownership(&key.0, key.1, key.2),
            first_allocation_attempt: false,
            tracked: self.tracked.clone(),
            resumed: false,
            output: output.clone(),
            dispatch,
            instance_name,
            upload,
        };
        let result = if is_command {
            self.commands.submit(job)
        } else if is_lifecycle {
            self.lifecycle.submit(job)
        } else if job.dispatch.kind == "process.signal" {
            if job
                .dispatch
                .signal
                .as_deref()
                .and_then(|name| ProcessSignal::parse(name).ok())
                .is_some_and(ProcessSignal::is_kill)
            {
                self.kills.submit(job)
            } else {
                self.signals.submit(job)
            }
        } else {
            self.ordinary.submit(job)
        };
        if result.is_err() {
            self.tracked
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&key);
        }
        if result.is_ok()
            && let Some(output) = output
        {
            if let Some(process_id) = process_id {
                self.starts
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(
                        key.clone(),
                        PendingStart {
                            republish: false,
                            sandbox_id,
                            process_id,
                            output: output.clone(),
                        },
                    );
            }
            outputs.insert(key, OutputWindow::new(output));
        }
        result
    }

    /// Resume durable, unresolved teardown authority after receipt inventory.
    /// Inventory alone cannot delete a stopped, half-created VM. Never replay
    /// a teardown superseded by a newer receipt, lease, or confirmed cleanup.
    pub fn resume_teardowns(
        &self,
        journal: &HostJournal,
        binding: &super::journal::TransportBindingV11,
    ) -> anyhow::Result<()> {
        let mut receipts = journal.matching(binding)?;
        // Each completed retry cycle persists a fresh write time. Oldest
        // obligations go first when more sandboxes need recovery than fit in
        // the bounded cleanup queue; persistent failures cannot monopolize it.
        receipts.sort_by_key(|receipt| receipt.written_at_unix_ms);
        let cleanups = journal.cleanup_generations(binding)?;
        let busy = self.lifecycle_busy();
        let available = RESUME_CAP.saturating_sub(
            self.lifecycle
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .urgent_queued,
        );
        let mut admitted = 0;
        for receipt in &receipts {
            if admitted >= available {
                break;
            }
            if receipt.digest_pruned
                || receipt.phase == super::journal::ReceiptPhase::Result
                || !matches!(receipt.kind.as_str(), "sandbox.kill" | "sandbox.stop")
                || busy.contains(&receipt.sandbox_id)
                || receipts.iter().any(|newer| {
                    newer.sandbox_id == receipt.sandbox_id && newer.generation > receipt.generation
                })
                || journal
                    .lease(&receipt.sandbox_id)
                    .is_some_and(|lease| lease.generation > receipt.generation)
                || cleanups
                    .get(&receipt.sandbox_id)
                    .is_some_and(|generation| *generation >= receipt.generation)
            {
                continue;
            }
            let dispatch: OperationDispatch =
                serde_json::from_value(json!({"sandboxOwnerId":receipt.sandbox_owner_id,
                    "operationId": receipt.operation_id, "sandboxId": receipt.sandbox_id,
                    "generation": receipt.generation, "attempt": receipt.attempt,
                    "kind": receipt.kind, "idempotencyKey": receipt.idempotency_key,
                    "allocation": receipt.allocation,
                    "incusFingerprint": receipt.template_fingerprint,
                }))?;
            // A worker can finish with UNKNOWN (for example when result
            // persistence fails). The reader retains its authority entry for
            // a later upgrade, but no queued/active worker owns it anymore.
            // Retire that idle entry before re-arming the durable attempt.
            // A crash in Effect without a result is already uncertain. Make
            // that durable before requeuing so every later result writer uses
            // the journal's UNKNOWN-versus-refusal arbitration.
            if receipt.phase == super::journal::ReceiptPhase::Effect
                && receipt.state != OperationState::UnknownOutcome
            {
                journal.record_reconciled_result(
                    &receipt.operation_id,
                    OperationState::UnknownOutcome,
                    None,
                    Some(SandboxErrorCode::UnknownOutcome.into()),
                    None,
                )?;
            }
            self.authority.complete(&receipt.operation_id);
            if !self.authority.resume_teardown(receipt).unwrap_or(false) {
                continue;
            }
            self.lifecycle.submit(DispatchJob {
                owner: self.authority.take_ownership(
                    &receipt.operation_id,
                    receipt.generation,
                    receipt.attempt,
                ),
                first_allocation_attempt: false,
                tracked: TrackedCommands::default(),
                resumed: true,
                output: None,
                dispatch,
                instance_name: sandbox_runtime::default_incus_instance_name(&receipt.sandbox_id),
                upload: None,
            })?;
            admitted += 1;
        }
        Ok(())
    }
    pub fn control(&self, work: impl FnOnce() + Send + 'static) -> anyhow::Result<()> {
        self.control
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("control closed"))?
            .try_send(Box::new(work))
            .map_err(|_| anyhow::anyhow!("host control queue full or closed"))
    }
    pub fn observe_storage(&self, work: impl FnOnce() + Send + 'static) -> anyhow::Result<()> {
        self.storage_observations
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("storage observations closed"))?
            .try_send(Box::new(work))
            .map_err(|_| anyhow::anyhow!("storage observation queue full or closed"))
    }
    /// The storage observation queue, for the session's host reports
    /// (`host_reports`), which also run during reconciliation.
    pub(super) fn storage_observer(&self) -> Option<mpsc::SyncSender<Control>> {
        self.storage_observations.clone()
    }
    pub fn observe(&self, work: impl FnOnce() + Send + 'static) -> anyhow::Result<()> {
        self.observations
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("observations closed"))?
            .try_send(Box::new(work))
            .map_err(|_| anyhow::anyhow!("host observation queue full or closed"))
    }
    /// Best-effort, bounded, idempotent start observations (4a): at most one
    /// per accepted 10.5 command attempt, host clock only, no nonce, no ACK.
    /// Losing one is an availability uncertainty; final results repeat it.
    pub fn poll_started(&self) -> Vec<sandbox_protocol::results::ProcessStarted> {
        // Never hold the output lock while taking `starts` (submit nests them
        // the other way). An entry without a live output window is dropped.
        let live: std::collections::HashSet<OutputKey> = self
            .outputs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .cloned()
            .collect();
        let mut starts = self.starts.lock().unwrap_or_else(|e| e.into_inner());
        let mut ready = Vec::new();
        starts.retain(|key, pending| {
            if !live.contains(key) {
                return false;
            }
            if self
                .authority
                .accept_completion(&key.0, key.1, key.2)
                .is_err()
            {
                // Carried and not yet adopted: keep it for the adopting
                // session. Gone (revoked, superseded): drop it.
                return self
                    .authority
                    .pending(&key.0)
                    .is_some_and(|work| work.generation == key.1 && work.attempt == key.2);
            }
            let birth = if std::mem::take(&mut pending.republish) {
                pending.output.start()
            } else {
                pending.output.take_unpublished_start()
            };
            let Some(birth) = birth else {
                return true;
            };
            if let Some(frame) = started_frame(
                &key.0,
                key.1,
                key.2,
                &pending.sandbox_id,
                &pending.process_id,
                &birth,
            ) {
                ready.push(frame);
            }
            // Kept while the command's window lives: an adoption republishes.
            true
        });
        ready
    }

    /// After adoption: publish this command's start evidence again (the
    /// first publication may have died with the transport). The server binds
    /// an identical birth idempotently. Evidence not yet bound is published
    /// as soon as it arrives, as always.
    pub(super) fn republish_started(&self, operation_id: &str, generation: u64, attempt: u64) {
        if let Some(pending) = self
            .starts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(&(operation_id.to_string(), generation, attempt))
        {
            pending.republish = true;
        }
    }
    pub fn poll_output(&self) -> anyhow::Result<Vec<Frame>> {
        let mut outputs = self.outputs.lock().unwrap_or_else(|e| e.into_inner());
        if outputs.is_empty() {
            return Ok(Vec::new());
        }
        let start = self
            .output_turn
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % outputs.len();
        let keys: Vec<_> = outputs.keys().cloned().collect();
        for index in 0..keys.len() {
            let key = &keys[(start + index) % keys.len()];
            if self
                .authority
                .accept_completion(&key.0, key.1, key.2)
                .is_err()
            {
                continue;
            }
            if let Some(window) = outputs.get_mut(key) {
                window.set_chunk_bytes(
                    self.output_chunk_bytes
                        .load(std::sync::atomic::Ordering::Relaxed),
                );
                let ready = window.poll(&key.0, key.1, key.2, Instant::now())?;
                // At most four writes per socket turn, including retransmits.
                if !ready.is_empty() {
                    return Ok(ready);
                }
            }
        }
        Ok(Vec::new())
    }

    /// An output window is still registered for this exact attempt. While it
    /// is, completion publication belongs to the drain/grace owner in
    /// `poll_finished` — never to a terminal-receipt shortcut.
    pub fn output_open(&self, operation_id: &str, generation: u64, attempt: u64) -> bool {
        self.outputs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&(operation_id.into(), generation, attempt))
    }

    pub fn ack_output(
        &self,
        operation: String,
        generation: u64,
        attempt: u64,
        sequence: u64,
        offset: u64,
    ) {
        if let Some(window) = self
            .outputs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(&(operation, generation, attempt))
        {
            window.ack(sequence, offset, Instant::now());
        }
    }
    /// Completions returned by `poll_finished` that could not be published
    /// (the socket failed mid-batch) go back, tokens and all, ahead of new
    /// ones. Their output windows are already closed, so they are ready.
    pub(super) fn requeue_finished(&self, items: Vec<FinishedOp>) {
        if items.is_empty() {
            return;
        }
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let mut requeued: Vec<_> = items.into_iter().map(|item| (item, now)).collect();
        requeued.append(&mut pending);
        *pending = requeued;
    }
    /// Completions ready to publish. A finished command's result seals its
    /// output on the server, so it is held while its retained output drains:
    /// for as long as ACKs keep advancing (see [`OutputWindow::drain_settled`]),
    /// never past [`super::output::DRAIN_MAX`] nor the sandbox's lease
    /// deadline. Then whatever is still retained becomes a gap.
    pub fn poll_finished(&self) -> Vec<FinishedOp> {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let mut outputs = self.outputs.lock().unwrap_or_else(|e| e.into_inner());
        // Draining completions are bounded by output slots; they must not
        // hold the completion queue shut for unrelated work.
        let draining = pending
            .iter()
            .filter(|(done, _)| {
                outputs.contains_key(&(done.operation_id.clone(), done.generation, done.attempt))
            })
            .count();
        let capacity = QUEUE_CAP.saturating_sub(pending.len() - draining);
        pending.extend(
            self.finished_rx
                .try_iter()
                .take(capacity)
                .map(|f| (f, Instant::now())),
        );
        let now = Instant::now();
        let mut ready = Vec::new();
        let mut i = 0;
        while i < pending.len() {
            let (done, since) = &pending[i];
            let key = (done.operation_id.clone(), done.generation, done.attempt);
            if outputs.contains_key(&key) && done.interim {
                ready.push(pending.remove(i).0);
                continue;
            }
            let settled = outputs.get(&key).is_none_or(|window| {
                window.drain_settled(*since, *since + super::output::DRAIN_MAX, now)
                    || self.lease_ends_soon(&done.sandbox_id)
            });
            if settled {
                outputs.remove(&key);
                ready.push(pending.remove(i).0);
            } else {
                i += 1;
            }
        }
        ready
    }
    /// `poll_finished` behind an instant server that stores and ACKs all
    /// retained output, for tests that do not exercise the output wire.
    #[cfg(test)]
    pub(super) fn poll_finished_consumed(&self) -> Vec<FinishedOp> {
        {
            let now = Instant::now();
            let mut outputs = self.outputs.lock().unwrap_or_else(|e| e.into_inner());
            for ((operation, generation, attempt), window) in outputs.iter_mut() {
                while let Ok(frames) = window.poll(operation, *generation, *attempt, now) {
                    let Some(last) = frames.last() else { break };
                    let end = last.metadata.offset.unwrap_or(0) + last.body_len() as u64;
                    window.ack(last.metadata.sequence, end, now);
                }
            }
        }
        self.poll_finished()
    }
    /// The sandbox's journaled lease ends within [`LEASE_MARGIN`] (or already
    /// expired) by the lease clock expiry uses: a held completion publishes
    /// before expiry can fence it. An unreadable clock publishes at once.
    fn lease_ends_soon(&self, sandbox_id: &str) -> bool {
        self.journal.lease_ends_within(sandbox_id, LEASE_MARGIN)
    }
    fn shutdown_workers(&mut self) {
        self.authority.shutdown();
        self.ordinary.close();
        self.signals.close();
        self.kills.close();
        self.commands.close();
        self.lifecycle.close();
        self.control.take();
        self.observations.take();
        self.storage_observations.take();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !self.workers.is_empty() && Instant::now() < deadline {
            // Drain bounded completions so workers can finish during shutdown.
            for _ in self.finished_rx.try_iter() {}
            let mut index = 0;
            while index < self.workers.len() {
                if self.workers[index].is_finished() {
                    let _ = self.workers.swap_remove(index).join();
                } else {
                    index += 1;
                }
            }
            if !self.workers.is_empty() {
                thread::sleep(Duration::from_millis(10));
            }
        }
        // Remaining workers retain journal lock and revoked authority until they exit.
    }
}
impl Drop for RelaySupervisor {
    fn drop(&mut self) {
        self.shutdown_workers();
    }
}
/// THE pre-runtime allocation boundary: create requires absence; reconnect
/// requires not running. Both require journal-proven first-attempt evidence.
/// A refused create cannot release against VM-only absence on missing storage.
pub(super) fn pinned_refusal_state(
    runtime: &dyn SandboxRuntime,
    kind: sandbox_runtime::AllocationKind,
    first: bool,
    id: &str,
    allocation: Option<&sandbox_protocol::capacity_v11::PinnedAllocationV11>,
) -> OperationState {
    let Some(a) = allocation else {
        return OperationState::UnknownOutcome;
    };
    let root = super::journal::storage::allocation_root(a);
    let proven = match kind {
        sandbox_runtime::AllocationKind::Create => runtime
            .prove_root_absent(&root, &sandbox_runtime::default_incus_instance_name(id))
            .is_ok(),
        sandbox_runtime::AllocationKind::Reconnect => {
            runtime.observe_storage_pool(&root.pool).is_ok()
        }
    };
    if !proven {
        return OperationState::UnknownOutcome;
    }
    sandbox_runtime::allocation_refusal_for_runtime(runtime, kind, first, id)
}

fn classify_allocation_refusal(
    runtime: &dyn SandboxRuntime,
    dispatch: &OperationDispatch,
    first_attempt: bool,
    result: Result<DispatchSuccess, DispatchFailure>,
) -> Result<DispatchSuccess, DispatchFailure> {
    let allocation = sandbox_runtime::AllocationKind::from_dispatch(dispatch);
    let refused = matches!(
        &result,
        Err(DispatchFailure::Rejected(_)
            | DispatchFailure::SessionClosed(_)
            | DispatchFailure::ImageMissing(_))
    );
    if let Some(kind) = allocation.filter(|_| refused) {
        let state = pinned_refusal_state(
            runtime,
            kind,
            first_attempt,
            &dispatch.sandbox_id,
            dispatch.allocation.as_ref(),
        );
        if state == OperationState::UnknownOutcome {
            return result.map_err(|error| DispatchFailure::AllocationUnknown(Box::new(error)));
        }
    }
    result
}

/// `sandbox.capture` (after the Effect record): copy, scrub and publish on
/// the runtime, journal the result as an origin-pinned managed image and,
/// in S3 mode, upload it in the background. The receipt carries the image facts.
fn run_capture(
    runtime: &Arc<dyn SandboxRuntime>,
    job: &DispatchJob,
    authority: &HostAuthority,
    images: Option<&super::images::ImageService>,
    credential_scrub_paths: &[String],
) -> Result<DispatchSuccess, DispatchFailure> {
    let d = &job.dispatch;
    let Some(images) = images else {
        return Err(DispatchError {
            reason: None,
            code: SandboxErrorCode::UnsupportedCapability.into(),
            message: "image cache disabled".into(),
        }
        .into());
    };
    let capture = d.capture.as_ref().ok_or_else(|| DispatchError {
        reason: None,
        code: SandboxErrorCode::ProtocolError.into(),
        message: "capture body missing".into(),
    })?;
    authority
        .accept_stream(&d.operation_id, d.generation, d.attempt)
        .map_err(DispatchFailure::from)?;
    // A STOPPED capture copies the root without a freeze or snapshot, under
    // the host's confirmed stop (B1). Never on the server's word alone: the
    // runtime must positively see the instance not running.
    if capture.stopped && !matches!(runtime.sandbox_may_be_running(&d.sandbox_id), Ok(false)) {
        tracing::warn!(
            operation_id = %d.operation_id,
            sandbox_id = %d.sandbox_id,
            reason = "stopped_capture_instance_may_be_running",
            "host refused stopped capture"
        );
        return Err(DispatchError {
            reason: None,
            code: SandboxErrorCode::CaptureFailed.into(),
            message: "sandbox is not stopped".into(),
        }
        .into());
    }
    let request = sandbox_runtime::CaptureRequest {
        sandbox_id: d.sandbox_id.clone(),
        operation_id: d.operation_id.clone(),
        stopped: capture.stopped,
        guest_home: d.guest_home.clone().unwrap_or_else(|| "/home/user".into()),
        extra_scrub_paths: capture.scrub_paths.clone(),
        credential_scrub_paths: credential_scrub_paths.to_vec(),
    };
    let outcome = runtime
        .capture_template(&request, &|phase| images.capture_progress(d, phase))
        .map_err(|error| capture_failure(d, &error))?;
    images
        .captured(d, &outcome.fingerprint, outcome.size_bytes, capture.upload)
        .map_err(|error| {
            tracing::warn!(
                operation_id = %d.operation_id,
                sandbox_id = %d.sandbox_id,
                code = ?error.code,
                error = %error.message,
                "captured image was not cached"
            );
            DispatchError {
                reason: None,
                code: if error.code == SandboxErrorCode::ImageCacheFull {
                    SandboxErrorCode::ImageCacheFull.into()
                } else {
                    SandboxErrorCode::CaptureFailed.into()
                },
                message: "captured image does not fit the image cache".into(),
            }
        })?;
    Ok(DispatchSuccess::ReadOnly((
        Some(json!({
            "fingerprint": outcome.fingerprint,
            "sizeBytes": outcome.size_bytes,
            "architecture": outcome.architecture,
            "symlinkedPaths": outcome.symlinked_paths,
        })),
        None,
        None,
    )))
}

/// A failed runtime capture as its dispatch error. The wire keeps the fixed
/// message; the host log keeps the runtime's cause (Incus and scrub-helper
/// text, never a credential) so a failed capture is diagnosable on the host.
fn capture_failure(d: &OperationDispatch, error: &sandbox_runtime::RuntimeError) -> DispatchError {
    tracing::warn!(
        operation_id = %d.operation_id,
        sandbox_id = %d.sandbox_id,
        code = ?error.code,
        error = %error.message,
        "template capture failed"
    );
    DispatchError {
        reason: None,
        code: if error.message.starts_with("capture_freeze_failed") {
            SandboxErrorCode::CaptureFreezeFailed.into()
        } else if error.code == SandboxErrorCode::Cancelled {
            SandboxErrorCode::Cancelled.into()
        } else {
            SandboxErrorCode::CaptureFailed.into()
        },
        message: "template capture failed".into(),
    }
}

/// Per-job launch inputs beside the dispatch: the journaled build binding
/// (D1), the node egress state, and the CLI-logins proxy port when this
/// create's credential spec carries a proxied login.
#[derive(Clone, Copy, Default)]
struct Launch<'a> {
    build: Option<&'a super::build::BuildBinding>,
    /// The create's readiness, from the same gate proof.
    readiness: sandbox_runtime::ReadinessMode,
    egress: Option<&'a super::egress_state::NodeEgress>,
    credential_proxy_port: Option<u16>,
}

fn run_job(
    runtime: &Arc<dyn SandboxRuntime>,
    job: &DispatchJob,
    authority: &HostAuthority,
    effective_lease: Option<&sandbox_protocol::HostLease>,
    defaults: &[(String, String)],
    launch: Launch<'_>,
) -> Result<DispatchSuccess, DispatchFailure> {
    let d = &job.dispatch;
    authority
        .accept_stream(&d.operation_id, d.generation, d.attempt)
        .map_err(DispatchFailure::from)?;
    let permit = authority
        .register_runtime(&d.operation_id, d.generation, d.attempt)
        .map_err(DispatchFailure::from)?;
    let runtime = runtime.with_cancellation(permit.clone());
    if let Some(bytes) = &job.upload {
        let response = runtime.write_file(&WriteFileRequest {
            template_fingerprint: d.incus_fingerprint.clone().unwrap_or_default(),
            sandbox_id: d.sandbox_id.clone(),
            instance_name: job.instance_name.clone(),
            operation_id: d.operation_id.clone(),
            generation: d.generation,
            attempt: d.attempt,
            idempotency_key: d.idempotency_key.clone(),
            path: d.path.clone().unwrap_or_default(),
            bytes: bytes.clone(),
            guest: guest_from_dispatch(d),
        })?;
        Ok(DispatchSuccess::Effect(response.map(|response| {
            (
                Some(json!({"path": response.path, "size": response.bytes_written})),
                None,
                None,
            )
        })))
    } else {
        if d.kind == "sandbox.stop" {
            graceful_wire_stop(runtime.as_ref(), job, &permit);
        }
        let mut delay = Duration::from_millis(100);
        let mut uncertain = false;
        let mut attempts = 0;
        loop {
            attempts += 1;
            let mut result =
                execute_dispatch(runtime.as_ref(), job, effective_lease, defaults, launch);
            if matches!(
                &result,
                Err(DispatchFailure::Effect(EffectError::Unknown(_)))
            ) {
                uncertain = true;
            }
            if uncertain {
                // A later pre-issue refusal cannot erase the earlier attempt's
                // uncertainty. Only positive completion can settle teardown.
                result = result.map_err(|error| match error {
                    DispatchFailure::Effect(error) => DispatchFailure::Effect(error.after_issue()),
                    other => other,
                });
            }
            if !matches!(d.kind.as_str(), "sandbox.kill" | "sandbox.stop")
                || !matches!(
                    &result,
                    Err(DispatchFailure::Effect(EffectError::Unknown(_)))
                )
                || permit.is_cancelled()
                || attempts >= 3
            {
                return result;
            }
            // Keep the journal in Effect until positive teardown evidence.
            // Yield the reserved cleanup worker after three tries; heartbeat
            // recovery resumes idle UNKNOWN work so other sandboxes progress.
            // Disconnect/shutdown/newer authority interrupts the backoff.
            tracing::warn!(operation_id = %d.operation_id, sandbox_id = %d.sandbox_id,
                kind = %d.kind, "sandbox teardown outcome unknown; retrying");
            if permit.wait_for(delay).is_err() {
                return result;
            }
            delay = (delay * 2).min(Duration::from_secs(5));
        }
    }
}
/// E1-B-03: a wire `sandbox.stop` (a user or build stop, or a system stop
/// the server sends) asks the guest to shut down first, so writes still in
/// its page cache reach the disk, bounded exactly like the expiry's graceful
/// attempt (`GRACEFUL_STOP_TIMEOUT` in the guest, `GRACEFUL_STOP_BUDGET` in
/// all). It runs after the credential teardown (capture and durable scrub),
/// once per dispatch (never per teardown retry). Its outcome is advisory:
/// the forced stop always follows as the completion proof and only observes
/// a VM that already stopped. A child of the dispatch permit, so a relay
/// disconnect, cancellation or newer authority still preempts it at once.
/// `sandbox.kill` never waits for the guest.
fn graceful_wire_stop(
    runtime: &dyn SandboxRuntime,
    job: &DispatchJob,
    permit: &Arc<sandbox_runtime::RuntimePermit>,
) {
    let d = &job.dispatch;
    let runtime = runtime.with_cancellation(Arc::new(sandbox_runtime::RuntimePermit::child(
        permit.clone(),
        super::expiry::GRACEFUL_STOP_BUDGET,
    )));
    let stopped = runtime
        .stop_sandbox_graceful(
            &StopSandboxRequest {
                template_fingerprint: d.incus_fingerprint.clone().unwrap_or_default(),
                sandbox_id: d.sandbox_id.clone(),
                instance_name: job.instance_name.clone(),
                operation_id: d.operation_id.clone(),
                idempotency_key: d.idempotency_key.clone(),
            },
            super::expiry::GRACEFUL_STOP_TIMEOUT,
        )
        .is_ok();
    if !stopped {
        tracing::info!(operation_id = %d.operation_id, "graceful stop did not complete; forcing");
    }
}

struct DispatchRequest<'a> {
    generation: u64,
    kind: &'a str,
    operation_id: &'a str,
    sandbox_id: &'a str,
    instance_name: &'a str,
    idempotency_key: &'a str,
    template_digest: Option<&'a str>,
    incus_fingerprint: Option<&'a str>,
    guest: GuestIdentity,
    architecture: Option<&'a str>,
    path: Option<&'a str>,
    dest_path: Option<&'a str>,
    recursive: bool,
    max_depth: Option<u32>,
    pid: Option<u32>,
    signal: Option<&'a str>,
}

/// A plain guest-user command. Build fields are refused here (fail closed):
/// only [`command_request`] with a gate-issued binding runs a root step.
#[cfg(test)]
pub(super) fn run_command_request_from_dispatch(
    dispatch: &OperationDispatch,
    instance_name: String,
    defaults: &[(String, String)],
) -> Result<RunCommandRequest, DispatchError> {
    command_request(dispatch, instance_name, defaults, None)
}

/// The runtime request for a `command.run`. `runAs`/`buildCopy` (D1) need the
/// [`super::build::BuildBinding`] the build gate issues for a journaled build
/// record; without it they are a protocol error, never a guest-user run.
pub(super) fn command_request(
    dispatch: &OperationDispatch,
    instance_name: String,
    defaults: &[(String, String)],
    build: Option<&super::build::BuildBinding>,
) -> Result<RunCommandRequest, DispatchError> {
    let build_step = match (&dispatch.run_as, &dispatch.build_copy, build) {
        (None, None, _) => None,
        (_, _, None) => {
            return Err(DispatchError {
                reason: None,
                code: SandboxErrorCode::ProtocolError.into(),
                message: "root steps run only in build sandboxes".into(),
            });
        }
        (Some(sandbox_protocol::RunAsV11::Root), None, Some(_)) => {
            Some(sandbox_runtime::BuildStep::Root)
        }
        (None, Some(copy), Some(_)) => Some(sandbox_runtime::BuildStep::Copy(copy.clone())),
        (Some(_), Some(_), Some(_)) => {
            return Err(DispatchError {
                reason: None,
                code: SandboxErrorCode::ProtocolError.into(),
                message: "build copy implies root".into(),
            });
        }
    };
    if let Some(sandbox_runtime::BuildStep::Copy(copy)) = &build_step {
        // The fixed helper takes no workload argv, script or environment;
        // template defaults never reach it either.
        if dispatch.argv.is_some()
            || dispatch.script.is_some()
            || dispatch.env.as_ref().is_some_and(|env| !env.is_empty())
            || !copy.is_valid()
        {
            return Err(DispatchError {
                reason: None,
                code: SandboxErrorCode::ProtocolError.into(),
                message: "invalid build copy".into(),
            });
        }
        let fingerprint = dispatch
            .incus_fingerprint
            .as_deref()
            .filter(|value| sandbox_runtime::is_incus_fingerprint(value))
            .ok_or_else(|| DispatchError {
                reason: None,
                code: SandboxErrorCode::ProtocolError.into(),
                message: "command.run requires a canonical template fingerprint".into(),
            })?;
        sandbox_protocol::validate_command_timeout(dispatch.timeout_ms).map_err(
            |(code, message)| DispatchError {
                reason: None,
                code: code.into(),
                message,
            },
        )?;
        return Ok(RunCommandRequest {
            template_fingerprint: fingerprint.to_string(),
            generation: dispatch.generation,
            attempt: dispatch.attempt,
            sandbox_id: dispatch.sandbox_id.clone(),
            instance_name,
            operation_id: dispatch.operation_id.clone(),
            idempotency_key: dispatch.idempotency_key.clone(),
            argv: Vec::new(),
            script: None,
            cwd: dispatch.cwd.clone(),
            timeout_ms: dispatch.timeout_ms,
            env: Vec::new(),
            stdin: None,
            guest: guest_from_dispatch(dispatch),
            build_step,
        });
    }
    let fingerprint = dispatch
        .incus_fingerprint
        .as_deref()
        .filter(|value| sandbox_runtime::is_incus_fingerprint(value))
        .ok_or_else(|| DispatchError {
            reason: None,
            code: SandboxErrorCode::ProtocolError.into(),
            message: "command.run requires a canonical template fingerprint".into(),
        })?;
    let guest = guest_from_dispatch(dispatch);
    // Validate each source before merging: duplicate/malformed overrides must
    // not be hidden by collecting into a map. Commands take precedence.
    sandbox_protocol::validate_env(defaults)
        .and_then(|()| sandbox_protocol::validate_env(dispatch.env.as_deref().unwrap_or_default()))
        .map_err(|(code, _)| DispatchError {
            reason: None,
            code: code.into(),
            message: "invalid command environment".into(),
        })?;
    let mut union: std::collections::BTreeMap<_, _> = defaults.iter().cloned().collect();
    union.extend(dispatch.env.iter().flatten().cloned());
    let env: Vec<_> = union.into_iter().collect();
    let spec = sandbox_protocol::CommandRunSpec {
        argv: dispatch.argv.as_deref(),
        script: dispatch.script.as_deref(),
        cwd: dispatch.cwd.as_deref(),
        env: Some(&env),
    };
    sandbox_protocol::validate_command_timeout(dispatch.timeout_ms).map_err(
        |(code, message)| DispatchError {
            reason: None,
            code: code.into(),
            message,
        },
    )?;
    sandbox_protocol::validate_command_run_spec(&spec).map_err(|(code, message)| {
        DispatchError {
            reason: None,
            code: code.into(),
            message,
        }
    })?;
    Ok(RunCommandRequest {
        template_fingerprint: fingerprint.to_string(),
        generation: dispatch.generation,
        attempt: dispatch.attempt,
        sandbox_id: dispatch.sandbox_id.clone(),
        instance_name,
        operation_id: dispatch.operation_id.clone(),
        idempotency_key: dispatch.idempotency_key.clone(),
        argv: dispatch.argv.clone().unwrap_or_default(),
        script: dispatch.script.clone(),
        cwd: dispatch.cwd.clone(),
        timeout_ms: dispatch.timeout_ms,
        env,
        stdin: None,
        guest,
        build_step,
    })
}

/// The Intent-phase step of a restore or a cached
/// cold reconnect, before any lease or Effect record.
/// - `restore`: fetch, validate and import the stored disk (staging only,
///   never a cache entry), paced by `offload_fetch_mbps`;
/// - `expectDisk`: the retained root must be the one stored as that offload
///   (journaled seq and fingerprint, unchanged `last_used_at`); otherwise
///   `disk_stale`, refused without starting.
pub(super) fn restore_intent(
    runtime: &dyn SandboxRuntime,
    images: Option<&super::images::ImageService>,
    offload: Option<&super::offload::OffloadService>,
    d: &OperationDispatch,
    instance_name: &str,
    still_wanted: &dyn Fn() -> bool,
) -> Result<(), DispatchError> {
    let (Some(images), Some(offload)) = (images, offload) else {
        return Err(DispatchError {
            reason: None,
            code: SandboxErrorCode::UnsupportedCapability.into(),
            message: "disk offload disabled".into(),
        });
    };
    if let Some(expect) = &d.expect_disk {
        return expect_disk_holds(runtime, offload, &d.sandbox_id, instance_name, expect)
            .then_some(())
            .ok_or_else(|| DispatchError {
                reason: None,
                code: DISK_STALE_CODE.into(),
                message: DISK_STALE.into(),
            });
    }
    let limit = offload.fetch_limit();
    let pace = |bytes: u64| {
        limit
            .as_deref()
            .is_none_or(|limit| limit.pace(bytes, &|| !still_wanted()))
    };
    images
        .ensure_restore_image(d, &pace, still_wanted)
        .map_err(|error| DispatchError {
            reason: error.reason,
            code: error.code.into(),
            message: error.message.into(),
        })
}

/// The cached cold reconnect refusal: the server then
/// evicts or discards the cached copy and restores from the stored one.
pub(super) const DISK_STALE: &str = "disk_stale";
/// The wire code of that refusal (host error messages never reach the wire;
/// `finish_bound` strips them). The server keeps the sandbox STOPPED and its
/// next start evicts or discards the cached copy, then restores.
pub(super) const DISK_STALE_CODE: SandboxErrorCode = SandboxErrorCode::DiskStale;

/// Whether this host's retained root is exactly the stored offload `expect`.
pub(super) fn expect_disk_holds(
    runtime: &dyn SandboxRuntime,
    offload: &super::offload::OffloadService,
    sandbox_id: &str,
    instance_name: &str,
    expect: &sandbox_protocol::DispatchExpectDiskV11,
) -> bool {
    let Some(entry) = offload.entry(sandbox_id) else {
        return false;
    };
    entry.phase == super::offload::OffloadPhase::Stored
        && entry.seq == expect.seq
        && entry.fingerprint().as_deref() == Some(expect.fingerprint.as_str())
        && entry.last_used_at.is_some()
        && runtime
            .instance_last_used(instance_name)
            .is_ok_and(|now| now == entry.last_used_at)
}

/// Drop the restore's imported disk image right after
/// init. It is this sandbox's own stored disk (no other lineage launches
/// from it) and the instance keeps its own root volume; it was never a cache
/// entry, so nothing else references it.
fn delete_restore_image(runtime: &dyn SandboxRuntime, d: &OperationDispatch) {
    let Some(restore) = d.restore.as_ref() else {
        return;
    };
    // The image is deleted right after init and again when the attempt
    // ends: the second delete of an image already gone is not a failure
    // (Incus does not report a missing image as `NotFound`).
    if let Err(error) = runtime.delete_image(&restore.fingerprint)
        && error.code != SandboxErrorCode::NotFound
        && !runtime
            .list_image_fingerprints()
            .is_ok_and(|images| !images.contains(&restore.fingerprint))
    {
        tracing::warn!(operation_id = %d.operation_id, code = ?error.code,
            "restore disk image delete failed");
    }
}

/// The restore's launch request. The template tag stays the
/// dispatch's template; the launch image is `restore.fingerprint`.
fn restore_launch(d: &OperationDispatch) -> Option<sandbox_runtime::RestoreLaunch> {
    d.restore
        .as_ref()
        .map(|restore| sandbox_runtime::RestoreLaunch {
            fingerprint: restore.fingerprint.clone(),
            cloud_init_instance_id: restore.cloud_init_instance_id.clone(),
        })
}

/// The guest account credential files belong to (the dispatch's guest).
fn credential_guest(dispatch: &OperationDispatch) -> sandbox_runtime::CredentialGuest {
    let guest = guest_from_dispatch(dispatch);
    sandbox_runtime::CredentialGuest {
        sandbox_id: dispatch.sandbox_id.clone(),
        uid: guest.guest_uid,
        gid: guest.guest_gid,
        home: guest.guest_home,
    }
}

/// `credentialSpec` on a create/reconnect (or a template capture's login
/// scrub list, §7.6): fetched and verified before any VM effect. A daemon
/// without the credential service refuses it; a capture spec for another
/// sandbox, or one that carries leases, is invalid.
fn fetch_credential_spec(
    credentials: Option<&super::credentials::service::CredentialService>,
    d: &OperationDispatch,
    still_wanted: &dyn Fn() -> bool,
) -> Result<Option<sandbox_protocol::CredentialSpecV11>, DispatchError> {
    let Some(reference) = d.credential_spec.as_ref() else {
        return Ok(None);
    };
    if !matches!(
        d.kind.as_str(),
        "sandbox.create"
            | "sandbox.reconnect"
            | "sandbox.capture"
            | "credential.attach"
            | "credential.free"
    ) {
        return Ok(None);
    }
    let Some(service) = credentials else {
        return Err(DispatchError {
            reason: None,
            code: SandboxErrorCode::UnsupportedCapability.into(),
            message: "credentials disabled".into(),
        });
    };
    let spec = service
        .fetch_spec(&d.operation_id, reference, still_wanted)
        .map_err(|failure| DispatchError {
            reason: None,
            code: if failure == super::credentials::service::LaunchFailure::Cancelled {
                SandboxErrorCode::Cancelled.into()
            } else {
                SandboxErrorCode::CredentialSpecInvalid.into()
            },
            message: failure.as_str().into(),
        })?;
    if d.kind == "sandbox.capture" && (spec.sandbox_id != d.sandbox_id || !spec.leases.is_empty()) {
        return Err(DispatchError {
            reason: None,
            code: SandboxErrorCode::CredentialSpecInvalid.into(),
            message: super::credentials::service::LaunchFailure::SpecInvalid
                .as_str()
                .into(),
        });
    }
    Ok(Some(spec))
}

/// `sandbox.capture` while login files are in motion on this host (an open
/// teardown attempt, a binding installing or tearing down, a held guest
/// slot): refused before any effect. The server
/// refuses the same window first (`credential.capture_in_progress`); this
/// closes the race with work the host started after acceptance.
fn capture_credential_refusal(
    credentials: Option<&super::credentials::service::CredentialService>,
    d: &OperationDispatch,
) -> Option<DispatchError> {
    (d.kind == "sandbox.capture" && credentials.is_some_and(|s| s.capture_refused(&d.sandbox_id)))
        .then(|| DispatchError {
            reason: None,
            code: SandboxErrorCode::StateConflict.into(),
            message: "credential work in flight".into(),
        })
}

/// A credential launch failed after the VM became ready (§7.1, §10.4).
/// Create: an uncertain outcome with `credential_install_failed`, so the
/// server's provisioning-failure destroy removes the VM. Cold reconnect: the
/// VM is stopped first without scrub (residue stays recoverable); a proven
/// stop makes the reconnect a definite FAILED (sandbox STOPPED).
fn credential_launch_failure(
    runtime: &dyn SandboxRuntime,
    job: &DispatchJob,
    failure: super::credentials::service::LaunchFailure,
) -> DispatchFailure {
    let d = &job.dispatch;
    tracing::warn!(operation_id = %d.operation_id, reason = failure.as_str(),
        "credential launch failed");
    let code = SandboxErrorCode::CredentialInstallFailed;
    // A restore is a new VM; it fails like a create.
    if d.kind == "sandbox.reconnect" && d.restore.is_none() {
        let stopped = runtime.stop_sandbox(&StopSandboxRequest {
            template_fingerprint: d.incus_fingerprint.clone().unwrap_or_default(),
            sandbox_id: d.sandbox_id.clone(),
            instance_name: job.instance_name.clone(),
            operation_id: d.operation_id.clone(),
            idempotency_key: d.idempotency_key.clone(),
        });
        if stopped.is_ok() {
            return DispatchFailure::Rejected(DispatchError {
                reason: None,
                code: code.into(),
                message: failure.as_str().into(),
            });
        }
    }
    DispatchFailure::Effect(sandbox_runtime::RuntimeError::new(code, failure.as_str()).into())
}

/// Stop/kill credential phase (§10.3, §10.4): `None` when the kind or the
/// daemon has no credentials. Runs after Effect is durable and before the
/// runtime stops or destroys the VM. A user stop/kill whose capture fails
/// is refused only after the abort and the host lease-row re-bind are
/// durable; a system stop/kill always proceeds.
fn credential_teardown(
    credentials: Option<&super::credentials::service::CredentialService>,
    runtime: &dyn SandboxRuntime,
    journal: &HostJournal,
    d: &OperationDispatch,
    still_wanted: &dyn Fn() -> bool,
) -> Option<super::credentials::service::TeardownVerdict> {
    use super::credentials::service::{TEARDOWN_CREDENTIAL_BUDGET, TeardownPath, TeardownRequest};
    let path = match d.kind.as_str() {
        "sandbox.stop" => TeardownPath::Stop,
        "sandbox.kill" => TeardownPath::Kill,
        _ => return None,
    };
    let service = credentials?;
    let system = d.credential_teardown == Some(sandbox_protocol::CredentialTeardownOrigin::System);
    // The spec (when sent) is verified before any guest effect; a failure is
    // a pre-check failure, never a skipped capture.
    let mut spec_unverified = false;
    let spec = d.credential_spec.as_ref().and_then(|reference| {
        service
            .fetch_spec(&d.operation_id, reference, still_wanted)
            .inspect_err(|_| spec_unverified = true)
            .ok()
    });
    let guest = recorded_credential_guest(journal, d);
    let request = TeardownRequest {
        operation_id: d.operation_id.clone(),
        guest,
        sandbox_owner_id: d.sandbox_owner_id.clone(),
        host_owner_id: None,
        path,
        system,
        skip: d.credential_capture == Some(sandbox_protocol::CredentialCaptureMode::Skip),
        spec_unverified,
        generation: d.generation,
        budget: TEARDOWN_CREDENTIAL_BUDGET,
    };
    let sandbox_id = d.sandbox_id.clone();
    Some(service.teardown(
        runtime,
        &request,
        spec.as_ref(),
        still_wanted,
        &|generation| {
            journal
                .rebind_after_refused_teardown(&sandbox_id, generation)
                .map(|_| ())
        },
    ))
}

/// The lease record's declared guest identity, else the dispatch's.
fn recorded_credential_guest(
    journal: &HostJournal,
    d: &OperationDispatch,
) -> sandbox_runtime::CredentialGuest {
    journal
        .lease(&d.sandbox_id)
        .and_then(|row| row.guest)
        .map(|g| sandbox_runtime::CredentialGuest {
            sandbox_id: d.sandbox_id.clone(),
            uid: g.guest_uid,
            gid: g.guest_gid,
            home: g.guest_home,
        })
        .unwrap_or_else(|| credential_guest(d))
}

/// `credential.attach` / `credential.free` (§10.4), after Effect is durable.
/// The spec was fetched and verified before any guest effect. Attach reports
/// `attached`; free reports its binding's `credentialOutcomes`.
fn run_credential_live(
    credentials: Option<&super::credentials::service::CredentialService>,
    runtime: &dyn SandboxRuntime,
    journal: &HostJournal,
    d: &OperationDispatch,
    spec: Option<&sandbox_protocol::CredentialSpecV11>,
    still_wanted: &dyn Fn() -> bool,
) -> Result<DispatchSuccess, DispatchFailure> {
    use super::credentials::service::{FreeFailure, LaunchFailure, LaunchTarget};
    let Some(service) = credentials else {
        return Err(DispatchError {
            reason: None,
            code: SandboxErrorCode::UnsupportedCapability.into(),
            message: "credentials disabled".into(),
        }
        .into());
    };
    let Some(spec) = spec else {
        return Err(DispatchError {
            reason: None,
            code: SandboxErrorCode::CredentialSpecInvalid.into(),
            message: "credential spec missing".into(),
        }
        .into());
    };
    let guest = recorded_credential_guest(journal, d);
    if d.kind == "credential.attach" {
        let target = LaunchTarget {
            operation_id: d.operation_id.clone(),
            guest,
            spec_digest: d
                .credential_spec
                .as_ref()
                .map(|r| r.digest.clone())
                .unwrap_or_default(),
        };
        let installed = service
            .attach(runtime, &target, spec, still_wanted)
            .map_err(|failure| DispatchError {
                reason: None,
                code: match failure {
                    LaunchFailure::Cancelled => SandboxErrorCode::Cancelled.into(),
                    LaunchFailure::SpecInvalid => SandboxErrorCode::CredentialSpecInvalid.into(),
                    _ => SandboxErrorCode::CredentialInstallFailed.into(),
                },
                message: failure.as_str().into(),
            })?;
        // The receipt repeats the `installed` reports (see the launch).
        return Ok(DispatchSuccess::ReadOnly((
            Some(json!({ "state": "attached", "credentialInstalled": installed })),
            None,
            None,
        )));
    }
    let outcomes = service
        .free(
            runtime,
            &guest,
            &d.sandbox_owner_id,
            &d.operation_id,
            spec,
            still_wanted,
        )
        .map_err(|failure| DispatchError {
            reason: None,
            code: match failure {
                FreeFailure::Busy => SandboxErrorCode::StateConflict.into(),
                FreeFailure::Cancelled => SandboxErrorCode::Cancelled.into(),
                FreeFailure::SpecInvalid => SandboxErrorCode::CredentialSpecInvalid.into(),
            },
            message: failure.as_str().into(),
        })?;
    Ok(DispatchSuccess::ReadOnly((
        Some(json!({ "state": "freed", "credentialOutcomes": outcomes })),
        None,
        None,
    )))
}

/// The dispatch failure a teardown verdict turns into, if any.
fn teardown_refusal(
    verdict: &super::credentials::service::TeardownVerdict,
) -> Option<DispatchFailure> {
    use super::credentials::service::TeardownVerdict as V;
    match verdict {
        V::NoCredentials | V::Proceed(_) => None,
        V::Refused(_) => Some(DispatchFailure::Rejected(DispatchError {
            reason: None,
            code: SandboxErrorCode::CredentialCaptureFailed.into(),
            message: "credential capture failed".into(),
        })),
        V::Cancelled => Some(DispatchFailure::Rejected(DispatchError {
            reason: None,
            code: SandboxErrorCode::Cancelled.into(),
            message: "credential teardown cancelled".into(),
        })),
        V::Uncertain => Some(DispatchFailure::Effect(
            sandbox_runtime::RuntimeError::new(
                SandboxErrorCode::UnknownOutcome,
                "credential teardown outcome unknown",
            )
            .into(),
        )),
    }
}

/// `command.run` env: private defaults plus the sandbox's installed
/// credential env (memory only; command env still wins later). After a
/// daemon restart the env may still be re-requested: wait ≤ 10 s, then the
/// retryable `credential_env_pending`.
fn credential_command_env(
    credentials: Option<&super::credentials::service::CredentialService>,
    sandbox_id: &str,
    mut env: Vec<(String, String)>,
) -> Result<Vec<(String, String)>, DispatchError> {
    let Some(service) = credentials else {
        return Ok(env);
    };
    let extra = service
        .env_for(sandbox_id, super::credentials::service::ENV_WAIT)
        .map_err(|_| DispatchError {
            reason: None,
            code: SandboxErrorCode::CredentialEnvPending.into(),
            message: "credential env pending".into(),
        })?;
    for (name, value) in extra {
        if !env.iter().any(|(existing, _)| *existing == name) {
            env.push((name, value));
        }
    }
    Ok(env)
}

pub(super) fn guest_from_dispatch(dispatch: &OperationDispatch) -> GuestIdentity {
    GuestIdentity {
        guest_uid: dispatch.guest_uid.unwrap_or(1000),
        guest_gid: dispatch.guest_gid.unwrap_or(1000),
        guest_home: dispatch
            .guest_home
            .clone()
            .unwrap_or_else(|| "/home/user".to_string()),
        guest_shell: dispatch
            .guest_shell
            .clone()
            .unwrap_or_else(|| "/bin/bash".to_string()),
    }
}

fn dispatch_request(job: &DispatchJob) -> DispatchRequest<'_> {
    let dispatch = &job.dispatch;
    DispatchRequest {
        generation: dispatch.generation,
        kind: &dispatch.kind,
        operation_id: &dispatch.operation_id,
        sandbox_id: &dispatch.sandbox_id,
        instance_name: &job.instance_name,
        idempotency_key: &dispatch.idempotency_key,
        template_digest: dispatch.template_digest.as_deref(),
        incus_fingerprint: dispatch.incus_fingerprint.as_deref(),
        guest: guest_from_dispatch(dispatch),
        architecture: dispatch.architecture.as_deref(),
        path: dispatch.path.as_deref(),
        dest_path: dispatch.dest_path.as_deref(),
        recursive: dispatch.recursive.unwrap_or(false),
        max_depth: dispatch.max_depth,
        pid: dispatch.pid,
        signal: dispatch.signal.as_deref(),
    }
}

// Frames were already validated against strict 1.0 at ingress.
// Reuse the sized wire boundary; stored-record defaults never admit a fresh launch.
pub(super) fn runtime_launch_size(
    dispatch: &OperationDispatch,
) -> Result<sandbox_protocol::VmSize, DispatchError> {
    if let Some(a) = &dispatch.allocation {
        if dispatch.cpu_count.is_some_and(|v| v != a.cpu_count)
            || dispatch.memory_mi_b.is_some_and(|v| v != a.memory_mi_b)
        {
            return Err(DispatchError {
                reason: None,
                code: SandboxErrorCode::VmSizeMismatch.into(),
                message: "VM allocation differs".into(),
            });
        }
        return sandbox_protocol::VmSize::new(a.cpu_count, a.memory_mi_b).map_err(|_| {
            DispatchError {
                reason: None,
                code: SandboxErrorCode::ProtocolError.into(),
                message: "invalid VM size".into(),
            }
        });
    }
    sandbox_protocol::dispatch_vm_size(dispatch, sandbox_protocol::SANDBOX_RELAY_PROTOCOL_VERSION)
        .ok()
        .flatten()
        .ok_or_else(|| DispatchError {
            reason: None,
            code: SandboxErrorCode::ProtocolError.into(),
            message: "invalid VM size".into(),
        })
}

fn required_lease(d: &OperationDispatch) -> Result<sandbox_protocol::HostLease, DispatchError> {
    let lease = d.lease.clone().ok_or_else(|| DispatchError {
        reason: None,
        code: SandboxErrorCode::StateConflict.into(),
        message: "missing lease".into(),
    })?;
    lease.validate_now().map_err(|message| DispatchError {
        reason: None,
        code: SandboxErrorCode::StateConflict.into(),
        message: message.into(),
    })?;
    Ok(lease)
}

/// Run one launch dispatch end to end on `runtime` (B9 startup tests).
#[cfg(test)]
pub(super) fn execute_launch_for_test(
    runtime: &dyn SandboxRuntime,
    dispatch: OperationDispatch,
    defaults: &[(String, String)],
) -> FinishedOp {
    let job = DispatchJob {
        owner: None,
        first_allocation_attempt: true,
        tracked: TrackedCommands::default(),
        resumed: false,
        output: None,
        instance_name: sandbox_runtime::default_incus_instance_name(&dispatch.sandbox_id),
        upload: None,
        dispatch,
    };
    let result = execute_dispatch(runtime, &job, None, defaults, Launch::default());
    let d = &job.dispatch;
    finish_bound(
        &d.operation_id,
        &d.sandbox_id,
        d.generation,
        d.attempt,
        result,
    )
}

/// B9: after a launch booted the VM, run the revision's start/ready commands
/// before READY. A failure keeps the launch's effect uncertain (the VM
/// exists) with the typed startup code, so the server queues its cleanup.
fn with_startup<T>(
    runtime: &dyn SandboxRuntime,
    job: &DispatchJob,
    env: &[(String, String)],
    proof: sandbox_runtime::Completed<T>,
) -> sandbox_runtime::EffectOutcome<T> {
    match &job.dispatch.startup {
        None => Ok(proof),
        Some(startup) => proof.observe(|| {
            super::startup::run(runtime, &job.dispatch, &job.instance_name, env, startup)
        }),
    }
}

/// The daemon's early create / cold-reconnect inputs (see
/// docs/guide/network.md#refusal-reasons): `open_egress_permitted` from the dispatch
/// owner, the hello owner and the live consent, and `guard_ok` from one
/// fresh guard check, never cached across the decision. Without node egress
/// state (fixtures that never installed one) open egress is not permitted,
/// the fail-closed answer. The runtime start fence remains authoritative.
fn early_egress_admission(
    runtime: &dyn SandboxRuntime,
    job: &DispatchJob,
    egress: Option<&super::egress_state::NodeEgress>,
) -> sandbox_runtime::egress::EgressAdmission {
    match egress {
        Some(egress) => egress.admission(&job.dispatch.sandbox_owner_id, runtime),
        None => sandbox_runtime::egress::EgressAdmission {
            open_egress_permitted: false,
            guard_ok: runtime.egress_guard_check().is_ok(),
        },
    }
}

/// Guest sudo consent backstop (OD-2, S5): a create or cold reconnect that
/// carries `guestSudo` for another owner's sandbox is refused before any
/// runtime call while this node's `allow_guest_sudo_for_others` is off.
/// Fixtures without node state fail closed. Allocation recovery never comes
/// here (consent applies to the next create or cold reconnect).
fn guest_sudo_admission(
    d: &OperationDispatch,
    egress: Option<&super::egress_state::NodeEgress>,
) -> Result<(), DispatchError> {
    if d.guest_sudo != Some(true)
        || egress.is_some_and(|node| node.guest_sudo_permitted(&d.sandbox_owner_id))
    {
        return Ok(());
    }
    Err(DispatchError {
        reason: Some(sandbox_protocol::EgressRefusalReason::GuestSudoNotPermitted.into()),
        code: SandboxErrorCode::UnsupportedCapability.into(),
        message: "this node's owner does not allow guest sudo for other users' sandboxes".into(),
    })
}

/// The runtime's guest sudo step for a create. The journal already bound
/// these flags into the lease record (`guest_sudo` fixed; it equals the
/// dispatch's on every accepted create). The hygiene audit runs only on a
/// workload create whose guest cannot reach root: never on a build VM (D1
/// runs root steps by design; U2), never when `guestRoot` is set (the
/// audit proves nothing there).
fn create_guest_privilege(d: &OperationDispatch) -> sandbox_runtime::GuestPrivilege {
    let sudo = d.guest_sudo == Some(true);
    sandbox_runtime::GuestPrivilege {
        sudo,
        audit: !sudo && d.guest_root.is_none() && d.build.is_none(),
    }
}

/// Node settings captured at materialization (§2.1): the node config plus
/// the guard's validated domain blocklist. Fixtures without node egress
/// state use the documented defaults.
fn create_egress_settings(
    egress: Option<&super::egress_state::NodeEgress>,
) -> Result<sandbox_runtime::egress::EgressSettings, DispatchFailure> {
    match egress {
        Some(egress) => egress.create_settings().map_err(|err| {
            DispatchFailure::from(DispatchError {
                reason: err.wire_reason(),
                code: err.code.into(),
                message: err.message,
            })
        }),
        None => Ok(sandbox_runtime::egress::EgressSettings::default()),
    }
}

/// The create result: the sandbox state, plus the grants the node's domain
/// blocklist denied (`egressDeniedGrants`, bounded by the runtime) when any,
/// and the guest's observed group-signal support (`guestGroupSignals`).
/// P2 (Ubuntu 26.04): a guest user that may linger keeps a user manager, and
/// so possibly a command's processes, alive outside the command's scope.
/// Running-VM retirement then keeps UNKNOWN receipts until the VM stops (it
/// fails safe), so this is an operator warning, never a refusal: the guest
/// could enable linger after readiness anyway, and refusing would fail every
/// create on a stock image. The fix is the template's deny rule.
/// Readiness tolerated guest restarts (an Ubuntu 26.04 first boot reboots
/// once): one operator-visible line, never a failure.
fn note_readiness_restarts(sandbox_id: &str, restarts: u32) {
    if restarts > 0 {
        tracing::info!(sandbox_id = %sandbox_id, n = restarts, "readiness restart tolerated");
    }
}

fn warn_guest_linger(sandbox_id: &str, linger: Option<sandbox_runtime::GuestLinger>) {
    if let Some(
        linger @ (sandbox_runtime::GuestLinger::Allowed | sandbox_runtime::GuestLinger::Enabled),
    ) = linger
    {
        tracing::warn!(
            sandbox_id = %sandbox_id,
            linger = linger.as_str(),
            "guest user can enable systemd linger: UNKNOWN commands may not retire while the VM \
             runs; deny self-linger in the template (docs/operations/templates.md#deny-self-linger)"
        );
    }
}

fn create_result_json(response: &sandbox_runtime::CreateSandboxResponse) -> serde_json::Value {
    warn_guest_linger(&response.sandbox.sandbox_id, response.guest_linger);
    note_readiness_restarts(&response.sandbox.sandbox_id, response.readiness_restarts);
    let mut result = ready_result_json(response.sandbox.state, response.guest_group_signals);
    if !response.egress_denied_grants.is_empty() {
        result["egressDeniedGrants"] = serde_json::Value::Array(
            response
                .egress_denied_grants
                .iter()
                .cloned()
                .map(serde_json::Value::String)
                .collect(),
        );
    }
    result
}

/// A create or reconnect result: the state, plus `guestGroupSignals` when
/// the runtime observed whether the guest delivers TERM/INT/HUP (absent:
/// unobserved; the server keeps listing them, checked at call time).
fn ready_result_json(
    state: sandbox_protocol::SandboxLifecycleState,
    guest_group_signals: Option<bool>,
) -> serde_json::Value {
    let mut result = json!({ "state": state });
    if let Some(supported) = guest_group_signals {
        result["guestGroupSignals"] = serde_json::Value::Bool(supported);
    }
    result
}

fn execute_dispatch(
    runtime: &dyn SandboxRuntime,
    job: &DispatchJob,
    effective_lease: Option<&sandbox_protocol::HostLease>,
    defaults: &[(String, String)],
    launch: Launch<'_>,
) -> Result<DispatchSuccess, DispatchFailure> {
    let request = dispatch_request(job);
    if let Some(err) = reject_unsupported_dispatch(request.kind) {
        return Err(err.into());
    }
    match request.kind {
        "sandbox.lease.renew" => Ok(DispatchSuccess::ReadOnly((Some(json!({})), None, None))),
        "sandbox.create" => {
            // Fresh creates verify the exact artifact independently of the
            // hello census. Original-disk reconnect never consults this cache.
            if let (Some(revision), Some(epoch), Some(artifact)) = (
                job.dispatch.template_revision_id.as_deref(),
                job.dispatch.verification_connection_epoch,
                request.incus_fingerprint,
            ) {
                match runtime.resolve_image_ref(artifact) {
                    Ok(image)
                        if image.fingerprint == artifact
                            && Some(image.architecture.as_str()) == request.architecture => {}
                    Ok(_) => {
                        return Err(DispatchError {
                            reason: None,
                            code: SandboxErrorCode::StateConflict.into(),
                            message: "exact image architecture mismatch".into(),
                        }
                        .into());
                    }
                    Err(error) if error.code == SandboxErrorCode::NotFound => {
                        return Err(DispatchFailure::ImageMissing(json!({ "imageMissing": {
                            "templateRevisionId": revision, "artifact": artifact,
                            "architecture": request.architecture, "connectionEpoch": epoch,
                        } })));
                    }
                    Err(error) => {
                        return Err(DispatchError {
                            reason: None,
                            code: error.code.into(),
                            message: "exact image verification failed".into(),
                        }
                        .into());
                    }
                }
            }
            guest_sudo_admission(&job.dispatch, launch.egress)?;
            let request = CreateSandboxRequest {
                // B12: a build VM's allowlist resolver reports refused names.
                // A build create is marked by its dispatch's build binding;
                // the gate grants a `BuildBinding` only to root steps, never
                // to the create itself.
                refused_dns_hints: job.dispatch.build.is_some(),
                first_attempt: job.first_allocation_attempt,
                vm_size: runtime_launch_size(&job.dispatch)?,
                lease: required_lease(&job.dispatch)?,
                sandbox_id: request.sandbox_id.to_string(),
                instance_name: request.instance_name.to_string(),
                idempotency_key: request.idempotency_key.to_string(),
                template_digest: request.template_digest.unwrap_or("").to_string(),
                incus_fingerprint: request.incus_fingerprint.map(str::to_string),
                guest: request.guest.clone(),
                architecture: request.architecture.map(str::to_string),
                egress_policy: job.dispatch.egress_policy.clone(),
                egress_policy_hash: job.dispatch.egress_policy_hash.clone(),
                egress_settings: sandbox_runtime::egress::EgressSettings {
                    credential_proxy_port: launch.credential_proxy_port,
                    tunnel_ports: job.dispatch.tunnel_ports.clone(),
                    tunnel_revision: job.dispatch.tunnel_ports_revision.unwrap_or(0),
                    ..create_egress_settings(launch.egress)?
                },
                egress_admission: early_egress_admission(runtime, job, launch.egress),
                guest_privilege: create_guest_privilege(&job.dispatch),
                readiness: launch.readiness,
                restore: None,
            };
            let proof = if let Some(a) = &job.dispatch.allocation {
                runtime.create_sandbox_on_storage(
                    &request,
                    &super::journal::storage::allocation_root(a),
                )
            } else {
                return Err(DispatchError {
                    reason: None,
                    code: SandboxErrorCode::ProtocolError.into(),
                    message: "missing pinned allocation".into(),
                }
                .into());
            }?;
            let proof = with_startup(runtime, job, defaults, proof)?;
            Ok(DispatchSuccess::Effect(proof.map(|response| {
                (Some(create_result_json(&response)), None, None)
            })))
        }
        "sandbox.kill" => {
            let request = KillSandboxRequest {
                template_fingerprint: request.incus_fingerprint.unwrap_or_default().to_string(),
                sandbox_id: request.sandbox_id.to_string(),
                instance_name: request.instance_name.to_string(),
                operation_id: request.operation_id.to_string(),
                idempotency_key: request.idempotency_key.to_string(),
            };
            let proof = if let Some(a) = &job.dispatch.allocation {
                runtime
                    .kill_sandbox_on_storage(&request, &super::journal::storage::allocation_root(a))
            } else {
                return Err(DispatchError {
                    reason: None,
                    code: SandboxErrorCode::ProtocolError.into(),
                    message: "missing pinned allocation".into(),
                }
                .into());
            }?;
            Ok(DispatchSuccess::Effect(proof.map(|response| {
                (Some(json!({ "state": response.sandbox.state })), None, None)
            })))
        }
        // A restore reconnect boots a NEW root from the
        // stored disk through the create path (create proofs, U3); its
        // result is this reconnect's result.
        "sandbox.reconnect" if job.dispatch.restore.is_some() => {
            guest_sudo_admission(&job.dispatch, launch.egress)?;
            let template = request
                .template_digest
                .or(request.incus_fingerprint)
                .unwrap_or("")
                .to_string();
            let create = CreateSandboxRequest {
                refused_dns_hints: false,
                first_attempt: job.first_allocation_attempt,
                vm_size: runtime_launch_size(&job.dispatch)?,
                lease: match effective_lease {
                    Some(lease) => lease.clone(),
                    None => required_lease(&job.dispatch)?,
                },
                sandbox_id: request.sandbox_id.to_string(),
                instance_name: request.instance_name.to_string(),
                idempotency_key: request.idempotency_key.to_string(),
                incus_fingerprint: Some(template.clone()),
                template_digest: template,
                guest: request.guest.clone(),
                architecture: request.architecture.map(str::to_string),
                egress_policy: job.dispatch.egress_policy.clone(),
                egress_policy_hash: job.dispatch.egress_policy_hash.clone(),
                egress_settings: sandbox_runtime::egress::EgressSettings {
                    credential_proxy_port: launch.credential_proxy_port,
                    tunnel_ports: job.dispatch.tunnel_ports.clone(),
                    tunnel_revision: job.dispatch.tunnel_ports_revision.unwrap_or(0),
                    ..create_egress_settings(launch.egress)?
                },
                egress_admission: early_egress_admission(runtime, job, launch.egress),
                guest_privilege: create_guest_privilege(&job.dispatch),
                readiness: sandbox_runtime::ReadinessMode::Standard,
                restore: restore_launch(&job.dispatch),
            };
            let Some(a) = &job.dispatch.allocation else {
                return Err(DispatchError {
                    reason: None,
                    code: SandboxErrorCode::ProtocolError.into(),
                    message: "missing pinned allocation".into(),
                }
                .into());
            };
            let proof = runtime
                .create_sandbox_on_storage(&create, &super::journal::storage::allocation_root(a));
            // The disk image is needed only by `incus init` (S6): delete it
            // whatever the outcome; a retry fetches it again.
            delete_restore_image(runtime, &job.dispatch);
            let proof = with_startup(runtime, job, defaults, proof?)?;
            Ok(DispatchSuccess::Effect(proof.map(|response| {
                let mut result = create_result_json(&response);
                if let Some(fields) = result.as_object_mut() {
                    fields.remove("egressDeniedGrants");
                }
                (Some(result), None, None)
            })))
        }
        "sandbox.reconnect" => {
            // The runtime validates the effective lease the journal observed;
            // the queued lease may already be past its own deadline. The ACK
            // still echoes the queued lease (`finish_bound`).
            let lease = match effective_lease {
                Some(lease) => {
                    lease.validate_now().map_err(|message| DispatchError {
                        reason: None,
                        code: SandboxErrorCode::StateConflict.into(),
                        message: message.into(),
                    })?;
                    lease.clone()
                }
                None => required_lease(&job.dispatch)?,
            };
            guest_sudo_admission(&job.dispatch, launch.egress)?;
            let request = ReconnectSandboxRequest {
                vm_size: runtime_launch_size(&job.dispatch)?,
                lease,
                template_fingerprint: request.incus_fingerprint.unwrap_or_default().to_string(),
                architecture: request.architecture.map(str::to_string),
                guest: request.guest.clone(),
                sandbox_id: request.sandbox_id.to_string(),
                instance_name: request.instance_name.to_string(),
                operation_id: request.operation_id.to_string(),
                idempotency_key: request.idempotency_key.to_string(),
                egress_policy: job.dispatch.egress_policy.clone(),
                egress_policy_hash: job.dispatch.egress_policy_hash.clone(),
                egress_admission: early_egress_admission(runtime, job, launch.egress),
                guest_sudo: job.dispatch.guest_sudo == Some(true),
            };
            let proof = if let Some(a) = &job.dispatch.allocation {
                runtime.reconnect_sandbox_on_storage(
                    &request,
                    &super::journal::storage::allocation_root(a),
                )
            } else {
                return Err(DispatchError {
                    reason: None,
                    code: SandboxErrorCode::ProtocolError.into(),
                    message: "missing pinned allocation".into(),
                }
                .into());
            }?;
            let proof = with_startup(runtime, job, defaults, proof)?;
            Ok(DispatchSuccess::Effect(proof.map(|response| {
                warn_guest_linger(&response.sandbox.sandbox_id, response.guest_linger);
                note_readiness_restarts(&response.sandbox.sandbox_id, response.readiness_restarts);
                (
                    Some(ready_result_json(
                        response.sandbox.state,
                        response.guest_group_signals,
                    )),
                    None,
                    None,
                )
            })))
        }
        "sandbox.stop" => {
            let proof = runtime.stop_sandbox(&StopSandboxRequest {
                template_fingerprint: request.incus_fingerprint.unwrap_or_default().to_string(),
                sandbox_id: request.sandbox_id.to_string(),
                instance_name: request.instance_name.to_string(),
                operation_id: request.operation_id.to_string(),
                idempotency_key: request.idempotency_key.to_string(),
            })?;
            Ok(DispatchSuccess::Effect(proof.map(|response| {
                (Some(json!({ "state": response.sandbox.state })), None, None)
            })))
        }
        "sandbox.probe" => {
            let response = runtime
                .probe_sandbox(&ProbeSandboxRequest {
                    template_fingerprint: request.incus_fingerprint.unwrap_or_default().to_string(),
                    architecture: request.architecture.map(str::to_string),
                    sandbox_id: request.sandbox_id.to_string(),
                    instance_name: request.instance_name.to_string(),
                    operation_id: request.operation_id.to_string(),
                    idempotency_key: request.idempotency_key.to_string(),
                    guest: request.guest.clone(),
                })
                .map_err(|err| DispatchError {
                    reason: None,
                    code: err.code.into(),
                    message: err.message,
                })?;
            Ok(DispatchSuccess::ReadOnly((
                Some(json!({ "liveProbeState": response.state })),
                None,
                None,
            )))
        }
        "command.run" => {
            let command = command_request(
                &job.dispatch,
                job.instance_name.clone(),
                defaults,
                launch.build,
            )?;
            let response = runtime.run_command_stream(
                &command,
                job.output.as_ref().ok_or_else(|| DispatchError {
                    reason: None,
                    code: SandboxErrorCode::Internal.into(),
                    message: "missing output sink".into(),
                })?,
            )?;
            Ok(DispatchSuccess::Effect(response.map(|response| {
                (
                    command_observation_for(&job.dispatch, &response),
                    None,
                    Some(response.command.state),
                )
            })))
        }
        "file.get" => {
            let path = request.path.ok_or_else(|| DispatchError {
                reason: None,
                code: SandboxErrorCode::ProtocolError.into(),
                message: "file.get requires path".to_string(),
            })?;
            let response = runtime
                .read_file(&ReadFileRequest {
                    sandbox_owner_id: job.dispatch.sandbox_owner_id.clone(),
                    template_fingerprint: request.incus_fingerprint.unwrap_or_default().to_string(),
                    guest: request.guest.clone(),
                    sandbox_id: request.sandbox_id.to_string(),
                    instance_name: request.instance_name.to_string(),
                    operation_id: request.operation_id.to_string(),
                    idempotency_key: request.idempotency_key.to_string(),
                    path: path.to_string(),
                })
                .map_err(runtime_err)?;
            Ok(DispatchSuccess::ReadOnly((
                Some(json!({
                    "path": response.path,
                    "size": response.bytes.len(),
                    "sha256": response.bytes.digest(),
                })),
                Some(response.bytes),
                None,
            )))
        }
        "file.list" => {
            let path = require_path(&request, "file.list")?;
            let response = runtime
                .list_dir(&ListDirRequest {
                    template_fingerprint: request.incus_fingerprint.unwrap_or_default().to_string(),
                    guest: request.guest.clone(),
                    sandbox_id: request.sandbox_id.to_string(),
                    instance_name: request.instance_name.to_string(),
                    operation_id: request.operation_id.to_string(),
                    idempotency_key: request.idempotency_key.to_string(),
                    path: path.to_string(),
                    depth: request.max_depth.unwrap_or(1).min(8),
                    limit: job.dispatch.limit.unwrap_or(100),
                    generation: request.generation,
                    continuation: job.dispatch.continuation.as_ref().map(|c| {
                        sandbox_runtime::DirectoryContinuation {
                            last_key: c.last_key.clone(),
                            root: c.root.clone(),
                            depth: c.depth,
                            limit: c.limit,
                            generation: u64::from(c.generation),
                            kind: sandbox_runtime::DirectoryKind::ListDir,
                        }
                    }),
                })
                .map_err(runtime_err)?;
            Ok(DispatchSuccess::ReadOnly((
                Some(
                    serde_json::to_value(HostFilePage {
                        result: ResultBody::List {
                            path: response.path,
                            depth: response.depth,
                            items: response.items,
                            next_cursor: response
                                .continuation
                                .as_ref()
                                .map(|_| job.dispatch.operation_id.clone()),
                            consistency: LiveConsistency::Live,
                        },
                        continuation: response.continuation,
                    })
                    .map_err(|_| DispatchError {
                        reason: None,
                        code: SandboxErrorCode::ProtocolError.into(),
                        message: "invalid list response".into(),
                    })?,
                ),
                None,
                None,
            )))
        }
        "file.stat" => {
            let path = require_path(&request, "file.stat")?;
            let response = runtime
                .stat_path(&StatPathRequest {
                    template_fingerprint: request.incus_fingerprint.unwrap_or_default().to_string(),
                    guest: request.guest.clone(),
                    sandbox_id: request.sandbox_id.to_string(),
                    instance_name: request.instance_name.to_string(),
                    operation_id: request.operation_id.to_string(),
                    idempotency_key: request.idempotency_key.to_string(),
                    path: path.to_string(),
                })
                .map_err(runtime_err)?;
            Ok(DispatchSuccess::ReadOnly((
                Some(
                    serde_json::to_value(ResultBody::Stat { entry: response }).map_err(|_| {
                        DispatchError {
                            reason: None,
                            code: SandboxErrorCode::ProtocolError.into(),
                            message: "invalid stat response".into(),
                        }
                    })?,
                ),
                None,
                None,
            )))
        }
        "file.mkdir" => {
            let path = require_path(&request, "file.mkdir")?;
            let proof = runtime.mkdir(&MkdirRequest {
                template_fingerprint: request.incus_fingerprint.unwrap_or_default().to_string(),
                guest: request.guest.clone(),
                sandbox_id: request.sandbox_id.to_string(),
                instance_name: request.instance_name.to_string(),
                operation_id: request.operation_id.to_string(),
                idempotency_key: request.idempotency_key.to_string(),
                path: path.to_string(),
            })?;
            serialize_completed_effect(proof, |response| {
                encode_mutation_result(ResultBody::Mkdir {
                    created: response.created,
                })
            })
            .map(DispatchSuccess::Effect)
        }
        "file.remove" => {
            let path = require_path(&request, "file.remove")?;
            let proof = runtime.remove_path(&RemovePathRequest {
                template_fingerprint: request.incus_fingerprint.unwrap_or_default().to_string(),
                guest: request.guest.clone(),
                sandbox_id: request.sandbox_id.to_string(),
                instance_name: request.instance_name.to_string(),
                operation_id: request.operation_id.to_string(),
                idempotency_key: request.idempotency_key.to_string(),
                path: path.to_string(),
                recursive: request.recursive,
            })?;
            serialize_completed_effect(proof, |_| {
                encode_mutation_result(ResultBody::Remove { removed: true })
            })
            .map(DispatchSuccess::Effect)
        }
        "file.move" => {
            let from = require_path(&request, "file.move")?;
            let to = request.dest_path.ok_or_else(|| DispatchError {
                reason: None,
                code: SandboxErrorCode::ProtocolError.into(),
                message: "file.move requires destPath".to_string(),
            })?;
            let proof = runtime.move_path(&MovePathRequest {
                template_fingerprint: request.incus_fingerprint.unwrap_or_default().to_string(),
                guest: request.guest.clone(),
                sandbox_id: request.sandbox_id.to_string(),
                instance_name: request.instance_name.to_string(),
                operation_id: request.operation_id.to_string(),
                idempotency_key: request.idempotency_key.to_string(),
                from: from.to_string(),
                to: to.to_string(),
            })?;
            serialize_completed_effect(proof, |entry| {
                encode_mutation_result(ResultBody::Rename {
                    entry: entry.clone(),
                })
            })
            .map(DispatchSuccess::Effect)
        }
        "process.list" => {
            let result = tracked_process_page(job)?;
            Ok(DispatchSuccess::ReadOnly((Some(result), None, None)))
        }
        "process.signal" => {
            let pid = request.pid.ok_or_else(|| DispatchError {
                reason: None,
                code: SandboxErrorCode::ProtocolError.into(),
                message: "process.signal requires pid".to_string(),
            })?;
            // A naked PID never authorizes an effect (4b). Session ingress
            // already refuses a signal without its tracked target; this
            // destructure keeps the invariant local to the effect.
            let (Some(process), Some(target_operation_id)) =
                (&job.dispatch.process, &job.dispatch.target_operation_id)
            else {
                return Err(DispatchError {
                    reason: None,
                    code: SandboxErrorCode::UnsupportedCapability.into(),
                    message: "process signal requires a full tracked target".to_string(),
                }
                .into());
            };
            let signal =
                ProcessSignal::parse(request.signal.unwrap_or_default()).map_err(runtime_err)?;
            let target = sandbox_runtime::SignalTarget {
                target_operation_id: target_operation_id.clone(),
                generation: u64::from(process.generation),
                attempt: u64::from(process.attempt),
                pid: process.pid,
            };
            let proof = runtime.signal_process(&SignalProcessRequest {
                template_fingerprint: request.incus_fingerprint.unwrap_or_default().to_string(),
                guest: request.guest.clone(),
                sandbox_id: request.sandbox_id.to_string(),
                instance_name: request.instance_name.to_string(),
                operation_id: request.operation_id.to_string(),
                idempotency_key: request.idempotency_key.to_string(),
                pid,
                signal,
                target: Some(target),
            })?;
            Ok(DispatchSuccess::Effect(proof.map(|outcome| {
                (
                    signal_result(process, target_operation_id, signal, outcome),
                    None,
                    None,
                )
            })))
        }

        other => Err(DispatchError {
            reason: None,
            code: SandboxErrorCode::ProtocolError.into(),
            message: format!("unsupported dispatch kind {other}"),
        }
        .into()),
    }
}

#[cfg(test)]
thread_local! {
    static FAIL_MUTATION_ENCODING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

// Shared encoder seam exercises failures at the actual post-effect call sites.
// Fault injection is thread-local and absent from production builds.
fn encode_mutation_result(
    value: impl serde::Serialize,
) -> Result<serde_json::Value, serde_json::Error> {
    #[cfg(test)]
    if FAIL_MUTATION_ENCODING.get() {
        return Err(serde_json::Error::io(std::io::Error::other(
            "injected serializer failure",
        )));
    }
    serde_json::to_value(value)
}

// Serialization happens after the guest mutation. A failed observation cannot
// turn positive effect evidence into a pre-issue rejection.
fn serialize_completed_effect<T>(
    proof: sandbox_runtime::Completed<T>,
    encode_result: impl FnOnce(&T) -> Result<serde_json::Value, serde_json::Error>,
) -> Result<sandbox_runtime::Completed<DispatchValue>, DispatchFailure> {
    let value = encode_result(&proof).map_err(|_| {
        EffectError::from(sandbox_runtime::RuntimeError::new(
            SandboxErrorCode::ProtocolError,
            "invalid mutation response",
        ))
    })?;
    Ok(proof.map(|_| (Some(value), None, None)))
}

pub fn reject_unsupported_dispatch(kind: &str) -> Option<DispatchError> {
    match classify_dispatch_kind(kind) {
        DispatchKindClass::UnsupportedCapability => {
            let (code, message) = unsupported_dispatch_error(kind);
            Some(DispatchError {
                reason: None,
                code: code.into(),
                message,
            })
        }
        DispatchKindClass::Unknown => Some(DispatchError {
            reason: None,
            code: SandboxErrorCode::ProtocolError.into(),
            message: format!("unsupported dispatch kind {kind}"),
        }),
        DispatchKindClass::Allowed | DispatchKindClass::Control => None,
    }
}

fn require_path<'a>(request: &DispatchRequest<'a>, kind: &str) -> Result<&'a str, DispatchError> {
    request.path.ok_or_else(|| DispatchError {
        reason: None,
        code: SandboxErrorCode::ProtocolError.into(),
        message: format!("{kind} requires path"),
    })
}

fn tracked_process_page(job: &DispatchJob) -> Result<serde_json::Value, DispatchError> {
    let invalid = || DispatchError {
        reason: None,
        code: SandboxErrorCode::ProtocolError.into(),
        message: "invalid process page".into(),
    };
    let limit = job.dispatch.limit.unwrap_or(100);
    if !(1..=100).contains(&limit) {
        return Err(invalid());
    }
    let after: Option<(String, String)> = job
        .dispatch
        .continuation
        .as_ref()
        .map(|c| serde_json::from_str(&c.last_key))
        .transpose()
        .map_err(|_| invalid())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let observed_at = sandbox_protocol::results::format_timestamp_ms(now);
    let mut items = Vec::new();
    let mut more;
    {
        let tracked = job.tracked.lock().unwrap_or_else(|e| e.into_inner());
        // Admission bounds the map. Select/limit small identity records first;
        // descriptions are borrowed for byte sizing and cloned only if retained.
        let mut candidates: Vec<_> = tracked
            .iter()
            .filter_map(|(key, command)| {
                if command.sandbox_id != job.dispatch.sandbox_id || key.1 != job.dispatch.generation
                {
                    return None;
                }
                let birth = command.output.start()?;
                let started_at =
                    sandbox_protocol::results::format_timestamp_ms(birth.started_at_ms);
                if after
                    .as_ref()
                    .is_some_and(|a| (&started_at, &command.process_id) <= (&a.0, &a.1))
                {
                    return None;
                }
                Some((key, command, birth, started_at))
            })
            .collect();
        candidates.sort_by(|a, b| (&a.3, &a.1.process_id).cmp(&(&b.3, &b.1.process_id)));
        more = candidates.len() > limit;
        let mut bytes = 512;
        for (key, command, birth, started_at) in candidates.into_iter().take(limit) {
            let process = process_ref(
                &command.sandbox_id,
                key.1,
                key.2,
                &command.process_id,
                &birth,
            )
            .ok_or_else(invalid)?;
            #[derive(serde::Serialize)]
            #[serde(rename_all = "camelCase")]
            struct Preview<'a> {
                process: &'a sandbox_protocol::results::ProcessRef,
                operation_id: &'a str,
                kind: &'a str,
                cmd: &'a str,
                args: &'a [String],
                args_truncated: bool,
                cwd: &'a str,
                started_at: &'a str,
                observed_at: &'a str,
            }
            let preview = Preview {
                process: &process,
                operation_id: &key.0,
                kind: "command",
                cmd: &command.description.cmd,
                args: &command.description.args,
                args_truncated: command.description.args_truncated,
                cwd: &command.description.cwd,
                started_at: &started_at,
                observed_at: &observed_at,
            };
            let size = serde_json::to_vec(&preview).map_err(|_| invalid())?.len() + 1;
            if bytes + size
                > sandbox_runtime::HOST_RESULT_MAX_BYTES
                    - sandbox_runtime::HOST_RESULT_WRAPPER_BYTES
            {
                more = true;
                break;
            }
            bytes += size;
            let info = sandbox_protocol::results::ProcessInfo {
                process,
                operation_id: key.0.clone(),
                kind: sandbox_protocol::results::CommandKind::Command,
                cmd: command.description.cmd.clone(),
                args: command.description.args.clone(),
                args_truncated: command.description.args_truncated,
                cwd: command.description.cwd.clone(),
                started_at,
                observed_at: observed_at.clone(),
            };
            if !info.validate() {
                return Err(invalid());
            }
            items.push(info);
        }
    }
    if more && items.is_empty() {
        return Err(DispatchError {
            reason: None,
            code: SandboxErrorCode::RequestTooLarge.into(),
            message: "process entry too large".into(),
        });
    }
    let cursor = if more {
        items.last().map(|last|json!({"lastKey":json!([last.started_at,last.process.process_id]).to_string(),"root":"/","depth":1,"limit":limit,"generation":job.dispatch.generation,"kind":"LIST_PROCESSES"}))
    } else {
        None
    };
    Ok(
        json!({"type":"process.list","items":items,"consistency":"live","nextCursor":cursor.as_ref().map(|_|&job.dispatch.operation_id),"continuation":cursor}),
    )
}

pub fn command_result_json(response: &sandbox_runtime::RunCommandResponse) -> serde_json::Value {
    json!({ "exitCode": response.command.exit_code, "pid": response.command.guest_pid })
}

fn process_ref(
    sandbox_id: &str,
    generation: u64,
    attempt: u64,
    process_id: &str,
    birth: &sandbox_runtime::CommandBirth,
) -> Option<sandbox_protocol::results::ProcessRef> {
    let process = sandbox_protocol::results::ProcessRef {
        sandbox_id: sandbox_id.to_string(),
        generation: u32::try_from(generation).ok()?,
        process_id: process_id.to_string(),
        attempt: u32::try_from(attempt).ok()?,
        pid: birth.pid,
    };
    process.validate().then_some(process)
}

fn started_frame(
    operation_id: &str,
    generation: u64,
    attempt: u64,
    sandbox_id: &str,
    process_id: &str,
    birth: &sandbox_runtime::CommandBirth,
) -> Option<sandbox_protocol::results::ProcessStarted> {
    let process = process_ref(sandbox_id, generation, attempt, process_id, birth)?;
    let observed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(birth.started_at_ms, |d| {
            u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
        });
    sandbox_protocol::results::ProcessStarted::observed(
        operation_id,
        &process,
        &birth.boot_id,
        birth.start_ticks,
        birth.started_at_ms,
        observed,
    )
}

/// Final command results repeat the bound identity. Session ingress
/// refuses a command without one, so there is no unbound body.
pub fn command_result_for(
    dispatch: &OperationDispatch,
    response: &sandbox_runtime::RunCommandResponse,
) -> Option<serde_json::Value> {
    let process_id = dispatch.process_id.as_ref()?;
    let birth = response.command.birth.as_ref()?;
    let process = process_ref(
        &dispatch.sandbox_id,
        dispatch.generation,
        dispatch.attempt,
        process_id,
        birth,
    )?;
    typed_result_value(sandbox_protocol::results::ResultBody::Command {
        process,
        started_at: sandbox_protocol::results::format_timestamp_ms(birth.started_at_ms),
        exit_code: response.command.exit_code,
    })
}

// Durable 10.5 receipts retain the start frame as private metadata. The
// standalone frame still passes through the sole negotiated wire encoder.
fn command_observation_for(
    dispatch: &OperationDispatch,
    response: &sandbox_runtime::RunCommandResponse,
) -> Option<serde_json::Value> {
    let mut result = command_result_for(dispatch, response)?;
    let birth = started_frame_value(
        &dispatch.operation_id,
        dispatch.generation,
        dispatch.attempt,
        &dispatch.sandbox_id,
        dispatch.process_id.as_deref()?,
        response.command.birth.as_ref()?,
    )?;
    result.as_object_mut()?.insert("birth".into(), birth);
    Some(result)
}

/// The journaled form of a start frame, through the sole negotiated wire
/// encoder (the same bytes a receipt's `birth` and `ext.commandStart` hold).
fn started_frame_value(
    operation_id: &str,
    generation: u64,
    attempt: u64,
    sandbox_id: &str,
    process_id: &str,
    birth: &sandbox_runtime::CommandBirth,
) -> Option<serde_json::Value> {
    let started = started_frame(
        operation_id,
        generation,
        attempt,
        sandbox_id,
        process_id,
        birth,
    )?;
    let encoded =
        sandbox_protocol::WireCodes::negotiated(sandbox_protocol::SANDBOX_RELAY_PROTOCOL_VERSION)
            .encode(&sandbox_protocol::DaemonControlMessage::from(started), None)
            .ok()?;
    serde_json::from_str(&encoded.text).ok()
}

fn typed_result_value(body: sandbox_protocol::results::ResultBody) -> Option<serde_json::Value> {
    serde_json::to_value(&body).ok()
}
fn signal_result(
    process: &sandbox_protocol::results::ProcessRef,
    target_operation_id: &str,
    signal: ProcessSignal,
    outcome: sandbox_runtime::SignalOutcome,
) -> Option<serde_json::Value> {
    use sandbox_protocol::results::{ProcessSignal as WireSignal, ResultBody, SignalDelivery};
    // SIGKILL is cancellation intent, never group-delivery evidence. The
    // server canonicalizes it to cancel; the host emits no signal result body.
    if outcome == sandbox_runtime::SignalOutcome::CancelRequested {
        return None;
    }
    let signal = match signal {
        ProcessSignal::Sigterm => WireSignal::SIGTERM,
        ProcessSignal::Sigint => WireSignal::SIGINT,
        ProcessSignal::Sighup => WireSignal::SIGHUP,
        ProcessSignal::Sigkill => WireSignal::SIGKILL,
    };
    typed_result_value(ResultBody::Signal {
        process: process.clone(),
        target_operation_id: target_operation_id.to_owned(),
        signal,
        accepted: true,
        delivery: SignalDelivery::ProcessGroup,
    })
}

fn wrap_typed_result(
    dispatch: &OperationDispatch,
    finished: &mut FinishedOp,
    failure: Option<sandbox_protocol::results::Failure>,
) {
    let mut raw = finished.payload.take().unwrap_or(serde_json::Value::Null);
    let birth = raw.as_object_mut().and_then(|o| o.remove("birth"));
    let continuation = raw.as_object_mut().and_then(|o| o.remove("continuation"));
    let payload = if dispatch.kind == "command.run" {
        if raw.get("type").and_then(serde_json::Value::as_str) == Some("command") {
            raw
        } else {
            serde_json::Value::Null
        }
    } else if finished.state == OperationState::Succeeded {
        raw
    } else {
        serde_json::Value::Null
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let wrapped = json!({"version":1,"observedAt":sandbox_protocol::results::format_timestamp_ms(now),
        "payload":payload,"continuation":continuation,"birth":birth,"failure":failure});
    finished.payload = Some(wrapped);
}

pub fn runtime_err(err: sandbox_runtime::RuntimeError) -> DispatchError {
    DispatchError {
        reason: err.wire_reason(),
        code: err.code.into(),
        message: err.code.as_str().to_owned(),
    }
}

fn finish_dispatch(
    dispatch: &OperationDispatch,
    result: Result<DispatchSuccess, DispatchFailure>,
    started: Instant,
) -> FinishedOp {
    // Refused before any host effect: a precondition, capacity or admission
    // answer, not a runtime failure (HR-R6).
    let not_issued = matches!(
        &result,
        Err(DispatchFailure::Rejected(_))
            | Err(DispatchFailure::SessionClosed(_))
            | Err(DispatchFailure::ImageMissing(_))
            | Err(DispatchFailure::Effect(
                sandbox_runtime::EffectError::NotIssued(_)
            ))
    );
    // Interim/unknown command observations repeat the bound identity too. An
    // unstarted observation must also clear finish_bound's unbound PID body.
    let identity = match &result {
        Err(DispatchFailure::Effect(error)) if dispatch.process_id.is_some() => Some(
            error
                .command()
                .and_then(|response| command_observation_for(dispatch, response)),
        ),
        _ => None,
    };
    let failure = match &result {
        Err(DispatchFailure::Effect(error)) => error.failure(),
        _ => None,
    };
    let mut finished = finish_bound(
        &dispatch.operation_id,
        &dispatch.sandbox_id,
        dispatch.generation,
        dispatch.attempt,
        result,
    );
    if let Some(payload) = identity {
        finished.payload = payload;
    }
    // A versioned command succeeds only with its bound birth: 1.0 has no
    // command payload without one, and the server can never apply such a
    // success. Work that ran but left no identity evidence is uncertain.
    if dispatch.kind == "command.run"
        && dispatch.process_id.is_some()
        && finished.state == OperationState::Succeeded
        && finished.payload.is_none()
    {
        finished.state = OperationState::UnknownOutcome;
        finished.error = Some(DispatchError {
            reason: None,
            code: SandboxErrorCode::UnknownOutcome.into(),
            message: SandboxErrorCode::UnknownOutcome.as_str().to_owned(),
        });
    }
    if finished.state == OperationState::Succeeded
        && matches!(
            dispatch.kind.as_str(),
            "sandbox.create" | "sandbox.reconnect" | "sandbox.lease.renew"
        )
        && let Some(fields) = finished
            .payload
            .get_or_insert_with(|| json!({}))
            .as_object_mut()
    {
        fields.insert("lease".into(), json!(dispatch.lease));
    }
    if dispatch.result_version == Some(1) {
        use sandbox_protocol::results::{Failure, FailureEffect, FailureResource};
        let failure = failure.or_else(|| {
            finished.error.as_ref().map(|_| Failure {
                reason: None,
                resource: match dispatch.kind.as_str() {
                    "command.run" => FailureResource::Command,
                    "process.signal" | "process.list" => FailureResource::Process,
                    _ => FailureResource::Filesystem,
                },
                effect: if not_issued {
                    FailureEffect::None
                } else {
                    FailureEffect::Unknown
                },
            })
        });
        wrap_typed_result(dispatch, &mut finished, failure);
    }
    log_operation_finished(&dispatch.kind, &finished, not_issued, started.elapsed());
    finished
}

/// E-21: one line when a host worker starts an operation. Identifiers only:
/// request content (argv, script, env, stdin, cwd, guest paths, file bytes)
/// and credentials never reach the log.
fn log_operation_started(dispatch: &OperationDispatch) {
    tracing::info!(
        operation_id = %dispatch.operation_id,
        sandbox_id = %dispatch.sandbox_id,
        kind = %dispatch.kind,
        generation = dispatch.generation,
        attempt = dispatch.attempt,
        "host operation started"
    );
}

/// Lifecycle severity remains distinct, but every automatic diagnostic uses
/// only the typed code. Raw runtime reasons may contain workload values.
fn is_lifecycle_kind(kind: &str) -> bool {
    matches!(
        kind,
        "sandbox.create"
            | "sandbox.reconnect"
            | "sandbox.stop"
            | "sandbox.kill"
            // CLI logins (§10.1 P3-8): attach/free run in the per-sandbox
            // lifecycle queue, never concurrently with a stop.
            | "credential.attach"
            | "credential.free"
    )
}

/// E-21 / E-11 / HR-R6: one line per finished host operation with its kind,
/// ids, outcome, error code and duration. Success is INFO. A refusal before
/// any effect is WARN (expected preconditions, capacity, cancellation). A
/// definite lifecycle failure after issue is ERROR; any other failure or
/// uncertain outcome is WARN.
fn log_operation_finished(
    kind: &str,
    finished: &FinishedOp,
    not_issued: bool,
    elapsed: std::time::Duration,
) {
    let duration_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
    let outcome = match finished.state {
        OperationState::Succeeded => "succeeded",
        OperationState::Failed if not_issued => "refused",
        OperationState::Failed => "failed",
        OperationState::Cancelled => "cancelled",
        OperationState::UnknownOutcome => "unknown",
        _ => "other",
    };
    let Some(error) = &finished.error else {
        tracing::info!(
            operation_id = %finished.operation_id,
            sandbox_id = %finished.sandbox_id,
            kind,
            attempt = finished.attempt,
            outcome,
            duration_ms,
            "host operation finished"
        );
        return;
    };
    let lifecycle = is_lifecycle_kind(kind);
    // The failed readiness check: a constant label, never guest text.
    let readiness = error
        .reason
        .and_then(sandbox_protocol::ProtocolErrorReason::readiness)
        .map_or("", sandbox_protocol::ReadinessFailureReason::as_str);
    let detail = readiness_log_detail(finished);
    match finished.state {
        OperationState::Succeeded | OperationState::Cancelled => tracing::info!(
            operation_id = %finished.operation_id,
            sandbox_id = %finished.sandbox_id,
            kind,
            attempt = finished.attempt,
            outcome,
            code = %error.code,
            duration_ms,
            "host operation finished"
        ),
        OperationState::Failed if lifecycle && !not_issued => tracing::error!(
            operation_id = %finished.operation_id,
            sandbox_id = %finished.sandbox_id,
            kind,
            attempt = finished.attempt,
            outcome,
            code = %error.code,
            readiness,
            detail = %detail,
            duration_ms,
            "sandbox lifecycle operation failed: {}",
            error.code.as_str()
        ),
        _ if lifecycle => tracing::warn!(
            operation_id = %finished.operation_id,
            sandbox_id = %finished.sandbox_id,
            kind,
            attempt = finished.attempt,
            outcome,
            code = %error.code,
            readiness,
            detail = %detail,
            duration_ms,
            "sandbox lifecycle operation did not succeed: {}",
            error.code.as_str()
        ),
        _ => tracing::warn!(
            operation_id = %finished.operation_id,
            sandbox_id = %finished.sandbox_id,
            kind,
            attempt = finished.attempt,
            outcome,
            code = %error.code,
            duration_ms,
            "host operation did not succeed"
        ),
    }
}

/// The `detail` of a lifecycle failure line: the typed host facts of a
/// `vm_not_running` readiness failure (path, Incus status, time since last
/// seen Running), never message or guest text. Empty otherwise.
fn readiness_log_detail(finished: &FinishedOp) -> String {
    finished
        .readiness_detail
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_default()
}

pub(super) fn finish_effect(
    operation_id: &str,
    sandbox_id: &str,
    generation: u64,
    attempt: u64,
    outcome: sandbox_runtime::EffectOutcome<DispatchValue>,
) -> FinishedOp {
    finish_bound(
        operation_id,
        sandbox_id,
        generation,
        attempt,
        outcome
            .map(DispatchSuccess::Effect)
            .map_err(DispatchFailure::Effect),
    )
}

fn finish_bound(
    operation_id: &str,
    sandbox_id: &str,
    generation: u64,
    attempt: u64,
    result: Result<DispatchSuccess, DispatchFailure>,
) -> FinishedOp {
    let mut readiness_detail = None;
    let (state, payload, download, error) = match result {
        Ok(success) => {
            let (payload, download, terminal) = success.into_value();
            (
                terminal.unwrap_or(OperationState::Succeeded),
                payload,
                download,
                None,
            )
        }
        Err(DispatchFailure::AllocationUnknown(error)) => {
            let mut finished =
                finish_bound(operation_id, sandbox_id, generation, attempt, Err(*error));
            finished.state = OperationState::UnknownOutcome;
            return finished;
        }
        Err(DispatchFailure::ImageMissing(payload)) => (
            OperationState::Failed,
            Some(payload),
            None,
            Some(DispatchError {
                reason: None,
                code: SandboxErrorCode::NotFound.into(),
                message: "exact image missing".into(),
            }),
        ),
        Err(DispatchFailure::Rejected(error) | DispatchFailure::SessionClosed(error)) => {
            (OperationState::Failed, None, None, Some(error))
        }
        Err(DispatchFailure::Effect(error)) => {
            let state = error.state();
            let payload = error.command().map(command_result_json);
            // Outcome certainty and diagnostic cause are independent. In particular,
            // GuestUnavailable must survive the durable UNKNOWN receipt so the
            // server can commit readiness-failure cleanup.
            let error = error.into_error();
            // Typed host facts, carried apart from the message (which is
            // reduced to its code below).
            readiness_detail = error.not_running_detail().cloned();
            let detail = runtime_err(error);
            (state, payload, None, Some(detail))
        }
    };
    // Runtime/validation diagnostics can contain env, stdin, stderr or nested
    // parser sources. Strip them before journal receipt creation AND logging.
    let error = error.map(|error| DispatchError {
        reason: error.reason.filter(|reason| reason.fits_wire(&error.code)),
        message: error.code.as_str().to_owned(),
        code: error.code,
    });
    FinishedOp {
        operation_id: operation_id.into(),
        sandbox_id: sandbox_id.into(),
        generation,
        attempt,
        state,
        payload,
        error,
        download,
        interim: false,
        readiness_detail,
        owner: None,
    }
}

#[cfg(target_os = "linux")]
fn run_supervised(
    supervisor: &sandbox_runtime::ExecSupervisor,
    job: &DispatchJob,
    authority: &HostAuthority,
    journal: &HostJournal,
    finished_tx: &mpsc::SyncSender<FinishedOp>,
    defaults: &[(String, String)],
    build: Option<&super::build::BuildBinding>,
) -> Result<DispatchSuccess, DispatchFailure> {
    let permit = authority
        .register_runtime(
            &job.dispatch.operation_id,
            job.dispatch.generation,
            job.dispatch.attempt,
        )
        .map_err(|err| DispatchError {
            reason: None,
            code: err.code.into(),
            message: err.message,
        })?;
    let supervisor = supervisor.with_cancellation(permit);
    let supervisor = if let Some(output) = &job.output {
        supervisor.with_output(output.clone())
    } else {
        supervisor
    };
    let request = command_request(&job.dispatch, job.instance_name.clone(), defaults, build)?;
    let bound = supervisor.bind(&request).map_err(|err| DispatchError {
        reason: None,
        code: err.code.into(),
        message: err.message,
    })?;
    let response = supervisor.run_with_updates(
        &bound,
        &request,
        || {
            authority
                .accept_stream(&request.operation_id, request.generation, request.attempt)
                .map_err(|err| sandbox_runtime::RuntimeError::new(err.code, err.message))?;
            authority
                .register_exec(&request.operation_id, request.generation, request.attempt)
                .map_err(|err| sandbox_runtime::RuntimeError::new(err.code, err.message))
        },
        |response| {
            let mut observation = FinishedOp {
                operation_id: request.operation_id.clone(),
                sandbox_id: request.sandbox_id.clone(),
                generation: request.generation,
                attempt: request.attempt,
                state: OperationState::UnknownOutcome,
                payload: command_observation_for(&job.dispatch, &response),
                error: Some(DispatchError {
                    reason: None,
                    code: SandboxErrorCode::UnknownOutcome.into(),
                    message: "termination not yet proven".into(),
                }),
                download: None,
                interim: true,
                readiness_detail: None,
                owner: None,
            };
            wrap_typed_result(&job.dispatch, &mut observation, None);
            finished_tx
                .send(persist_finished(journal, observation))
                .is_ok()
        },
    )?;
    Ok(DispatchSuccess::Effect(response.map(|response| {
        (
            command_observation_for(&job.dispatch, &response),
            None,
            Some(response.command.state),
        )
    })))
}

#[cfg(all(test, unix))]
mod tests {
    /// A failed capture keeps the fixed wire message but logs the runtime's
    /// cause on the host (prod 26.04 capture: the log said only
    /// `capture_failed`).
    #[test]
    fn a_failed_capture_logs_the_runtime_cause() {
        let d: super::OperationDispatch = serde_json::from_value(serde_json::json!({
            "sandboxOwnerId":"owner", "operationId":"cap-op", "sandboxId":"sbx",
            "kind":"sandbox.capture", "generation":2, "attempt":1,
            "idempotencyKey":"cap-op", "bodyHash":"a".repeat(64), "incusName":"wssp-sbx-sbx",
            "capture": {"scrubPaths": [], "stopped": true, "upload": false}}))
        .unwrap();
        let cause = sandbox_runtime::RuntimeError::new(
            sandbox_protocol::SandboxErrorCode::Internal,
            "incus scrub failed: guest operation failed (1 scrub error(s), first: read_only_fs at /etc/machine-id)",
        );
        let (error, logs) = crate::logging::with_subscriber(
            crate::cli::LogFormat::Text,
            tracing_subscriber::EnvFilter::new("info"),
            || super::capture_failure(&d, &cause),
        );
        let logs = String::from_utf8(logs).unwrap();
        assert!(logs.contains("template capture failed"), "{logs}");
        assert!(logs.contains("cap-op"), "{logs}");
        assert!(logs.contains("read_only_fs at /etc/machine-id"), "{logs}");
        assert_eq!(error.message, "template capture failed");
        assert_eq!(
            error.code.known(),
            Some(sandbox_protocol::SandboxErrorCode::CaptureFailed)
        );
    }

    #[test]
    fn create_result_reports_denied_grants_only_when_present() {
        let mut response = sandbox_runtime::CreateSandboxResponse {
            sandbox: sandbox_runtime::SandboxRecord {
                sandbox_id: "s".into(),
                generation: 1,
                state: sandbox_protocol::SandboxLifecycleState::Ready,
                idempotency_key: "k".into(),
            },
            egress_denied_grants: Vec::new(),
            guest_group_signals: None,
            guest_linger: None,
            readiness_restarts: 0,
        };
        assert_eq!(create_result_json(&response), json!({ "state": "ready" }));
        response.egress_denied_grants = vec!["api.bad.example".into()];
        assert_eq!(
            create_result_json(&response),
            json!({ "state": "ready", "egressDeniedGrants": ["api.bad.example"] })
        );
    }

    /// Group-signal support is reported only when observed (create and
    /// reconnect share the shape); a 6.8 guest reports `false`.
    #[test]
    fn ready_results_report_observed_group_signal_support_only() {
        use sandbox_protocol::SandboxLifecycleState::Ready;
        assert_eq!(ready_result_json(Ready, None), json!({ "state": "ready" }));
        for supported in [true, false] {
            assert_eq!(
                ready_result_json(Ready, Some(supported)),
                json!({ "state": "ready", "guestGroupSignals": supported })
            );
        }
    }

    #[test]
    fn guest_sudo_consent_refuses_a_foreign_sudo_launch_before_any_runtime_call() {
        let node =
            super::super::egress_state::NodeEgress::new(None, &crate::config::Config::default());
        node.set_host_owner("owner");
        let mut foreign = dispatch("sudo", "sandbox.create", 1);
        foreign.sandbox_owner_id = "someone-else".into();
        foreign.guest_sudo = Some(true);
        foreign.guest_root = Some(true);
        // Default consent: allowed.
        assert!(guest_sudo_admission(&foreign, Some(&node)).is_ok());
        node.apply_policy(false, false, Default::default());
        let refused = guest_sudo_admission(&foreign, Some(&node)).unwrap_err();
        assert_eq!(
            refused.reason,
            Some(sandbox_protocol::EgressRefusalReason::GuestSudoNotPermitted.into())
        );
        assert_eq!(
            refused.code,
            sandbox_protocol::WireErrorCode::from(SandboxErrorCode::UnsupportedCapability)
        );
        // Own sandboxes always; no sudo needs no consent.
        let mut own = foreign.clone();
        own.sandbox_owner_id = "owner".into();
        assert!(guest_sudo_admission(&own, Some(&node)).is_ok());
        let mut plain = foreign.clone();
        plain.guest_sudo = None;
        assert!(guest_sudo_admission(&plain, Some(&node)).is_ok());
        // Without node state: fail closed.
        assert!(guest_sudo_admission(&own, None).is_err());
    }

    #[test]
    fn the_create_audit_runs_only_for_a_rootless_workload_create() {
        let mut d = dispatch("c", "sandbox.create", 1);
        assert_eq!(
            create_guest_privilege(&d),
            sandbox_runtime::GuestPrivilege {
                sudo: false,
                audit: true
            }
        );
        d.guest_root = Some(true);
        assert!(!create_guest_privilege(&d).audit, "tainted revision");
        d.guest_sudo = Some(true);
        assert_eq!(
            create_guest_privilege(&d),
            sandbox_runtime::GuestPrivilege {
                sudo: true,
                audit: false
            }
        );
        let mut build = dispatch("b", "sandbox.create", 1);
        build.build = Some(sandbox_protocol::DispatchBuildV11 {
            build_id: "b".repeat(24),
            bootstrap: false,
        });
        assert!(
            !create_guest_privilege(&build).audit,
            "U2: never in build VMs"
        );
    }

    #[test]
    fn egress_refusals_survive_diagnostic_sanitization() {
        use sandbox_protocol::EgressRefusalReason;
        for reason in [
            EgressRefusalReason::OpenEgressNotPermitted,
            EgressRefusalReason::EgressGuardUnavailable,
        ] {
            let d = dispatch("egress", "sandbox.create", 1);
            let refused = DispatchFailure::Rejected(DispatchError {
                reason: Some(reason.into()),
                code: SandboxErrorCode::UnsupportedCapability.into(),
                message: "private diagnostic".into(),
            });
            let finished = finish_dispatch(&d, Err(refused), Instant::now());
            let error = finished.error.unwrap();
            assert_eq!(error.reason, Some(reason.into()));
            assert_eq!(error.message, "unsupported_capability");
        }
        // A reason never travels with a code it does not belong to.
        let finished = finish_bound(
            "bad",
            "sbx",
            1,
            1,
            Err(DispatchFailure::Rejected(DispatchError {
                reason: Some(EgressRefusalReason::EgressGuardUnavailable.into()),
                code: SandboxErrorCode::HostCapacity.into(),
                message: "private".into(),
            })),
        );
        assert_eq!(finished.error.unwrap().reason, None);
    }

    #[test]
    fn capacity_reason_survives_diagnostic_sanitization_and_uncertainty() {
        use sandbox_protocol::capacity_v11::CapacityReason;
        for reason in [
            CapacityReason::Ram,
            CapacityReason::Vcpu,
            CapacityReason::Disk,
            CapacityReason::Storage,
            CapacityReason::Ceiling,
        ] {
            for uncertain in [false, true] {
                let d = dispatch("capacity", "sandbox.create", 1);
                let refused = DispatchFailure::Rejected(DispatchError {
                    reason: Some(reason.into()),
                    code: SandboxErrorCode::HostCapacity.into(),
                    message: "private diagnostic".into(),
                });
                let failure = if uncertain {
                    DispatchFailure::AllocationUnknown(Box::new(refused))
                } else {
                    refused
                };
                let finished = finish_dispatch(&d, Err(failure), Instant::now());
                assert_eq!(
                    finished.state,
                    if uncertain {
                        OperationState::UnknownOutcome
                    } else {
                        OperationState::Failed
                    }
                );
                let error = finished.error.unwrap();
                assert_eq!(error.reason, Some(reason.into()));
                assert_eq!(error.message, "host_capacity");
            }
        }
        let finished = finish_bound(
            "bad",
            "sbx",
            1,
            1,
            Err(DispatchFailure::Rejected(DispatchError {
                reason: Some(CapacityReason::Disk.into()),
                code: SandboxErrorCode::Timeout.into(),
                message: "private".into(),
            })),
        );
        assert_eq!(finished.error.unwrap().reason, None);
    }

    use super::*;
    use crate::sandbox_relay::journal::{
        CrashPoint, Decision, TransportBindingV11, intent_from_dispatch,
    };
    use sandbox_runtime::FakeRuntime;

    #[test]
    fn refusal_submission_failures_answer_unknown_without_runtime_io() {
        for closed in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let binding = TransportBindingV11 {
                server: "wss://example".into(),
                host_owner_id: "owner".into(),
                host_id: "host".into(),
            };
            let journal = Arc::new(
                crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap(),
            );
            let fake = FakeRuntime::new()
                .with_inventory_hook(|_| panic!("fallback must not observe runtime"));
            fake.fixture_root().unwrap();
            let mut relay = RelaySupervisor::start(
                Arc::new(fake),
                journal.clone(),
                HostAuthority::default(),
                #[cfg(target_os = "linux")]
                None,
            );
            let (entered_tx, entered_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            relay
                .observe(move || {
                    entered_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                })
                .unwrap();
            entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            if closed {
                relay.observations.take();
            } else {
                for _ in 0..QUEUE_CAP {
                    relay.observe(|| {}).unwrap();
                }
            }
            for persist in [false, true] {
                let d = dispatch(
                    if persist { "persisted" } else { "unadmitted" },
                    "sandbox.create",
                    1,
                );
                if persist {
                    journal
                        .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &d))
                        .unwrap();
                }
                let result = relay.refuse_unadmitted(
                    &d,
                    true,
                    persist,
                    DispatchError {
                        reason: None,
                        code: SandboxErrorCode::HostCapacity.into(),
                        message: "refused".into(),
                    },
                );
                // Submission failure must bypass runtime IO and result queuing.
                assert!(
                    result.is_some(),
                    "submission failure must answer synchronously"
                );
                assert_eq!(result.unwrap().state, OperationState::UnknownOutcome);
                if persist {
                    assert_eq!(
                        journal.lookup(&d.operation_id).unwrap().state,
                        OperationState::UnknownOutcome
                    );
                }
            }
            // The admitted fallback also survives simultaneous observation
            // and completion saturation and stays on its authority-aware drain.
            for n in 0..QUEUE_CAP {
                let d = dispatch(&format!("completion-{n}"), "sandbox.create", 1);
                relay
                    .finished_tx
                    .try_send(finish_dispatch(
                        &d,
                        Err(DispatchFailure::Rejected(DispatchError {
                            reason: None,
                            code: SandboxErrorCode::HostCapacity.into(),
                            message: "full".into(),
                        })),
                        Instant::now(),
                    ))
                    .unwrap();
            }
            let d = dispatch("admitted", "sandbox.reconnect", 1);
            journal
                .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &d))
                .unwrap();
            relay.refuse_before_runtime(
                &d,
                DispatchError {
                    reason: None,
                    code: SandboxErrorCode::HostCapacity.into(),
                    message: "refused".into(),
                },
            );
            assert_eq!(
                done(&relay, "admitted").state,
                OperationState::UnknownOutcome
            );
            release_tx.send(()).unwrap();
        }
    }

    #[test]
    fn create_first_attempt_evidence_excludes_prior_issue_and_retained_lease() {
        for history in ["fresh", "effect", "lease", "other-receipt", "missing"] {
            let dir = tempfile::tempdir().unwrap();
            let binding = TransportBindingV11 {
                server: "wss://create.test".into(),
                host_owner_id: "owner".into(),
                host_id: "host".into(),
            };
            let journal =
                crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap();
            let d = dispatch("create", "sandbox.create", 1);
            if history != "missing" {
                journal
                    .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &d))
                    .unwrap();
            }
            match history {
                "effect" => journal.record_effect("create").unwrap(),
                "lease" => {
                    journal.accept_lease(&d).unwrap();
                }
                "other-receipt" => {
                    let mut other = d.clone();
                    other.operation_id = "prior".into();
                    other.idempotency_key = "prior".into();
                    journal
                        .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &other))
                        .unwrap();
                    journal.record_effect("prior").unwrap();
                }
                _ => {}
            }
            assert_eq!(
                journal.first_allocation_attempt(&d),
                history == "fresh",
                "{history}"
            );
            drop(journal);
            let journal =
                crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap();
            assert_eq!(
                journal.first_allocation_attempt(&d),
                history == "fresh",
                "reopen: {history}"
            );
        }
    }

    // The cross product exercises the production classifier/finisher without
    // fsync or worker startup per row. The integration test below reaches it
    // through every actual refusal kind. Prior Effect and lease histories are
    // distinct journal inputs in create_first_attempt_evidence_excludes_prior_issue_and_retained_lease
    // and reconnect_first_attempt_evidence_rejects_ambiguous_generation_history.
    #[test]
    fn create_refusals_require_first_attempt_and_confirmed_absence() {
        for refusal in [
            "image-missing",
            "image-architecture",
            "image-error",
            "cancel",
            "journal-cancel",
            "session-closed",
            "lease",
            "runtime-preflight",
        ] {
            for history in ["first", "retry"] {
                for observation in ["absent", "present", "error"] {
                    let mut fake = FakeRuntime::new();
                    fake.fixture_root().unwrap();
                    if observation == "present" {
                        seed(&fake);
                    }
                    if observation == "error" {
                        fake = fake.with_inventory_hook(|stage| {
                            assert_eq!(stage, "exists");
                            Err(RuntimeError::new(
                                SandboxErrorCode::Internal,
                                "daemon unavailable",
                            ))
                        });
                    }
                    let mut d = dispatch("create", "sandbox.create", 1);
                    d.attempt = if history == "retry" { 2 } else { 1 };
                    let code = match refusal {
                        "image-missing" => SandboxErrorCode::NotFound,
                        "image-architecture" | "lease" => SandboxErrorCode::StateConflict,
                        "image-error" | "runtime-preflight" => SandboxErrorCode::ProtocolError,
                        _ => SandboxErrorCode::Cancelled,
                    };
                    let error = DispatchError {
                        reason: None,
                        code: code.into(),
                        message: refusal.into(),
                    };
                    let failure = match refusal {
                        "image-missing" => {
                            DispatchFailure::ImageMissing(json!({"imageMissing": {}}))
                        }
                        "session-closed" => DispatchFailure::SessionClosed(error),
                        "runtime-preflight" => {
                            let mut request = CreateSandboxRequest::for_test("sbx", "create");
                            request.first_attempt = history == "first";
                            request.guest.guest_uid = 0;
                            DispatchFailure::Effect(fake.create_fixture(&request).unwrap_err())
                        }
                        _ => DispatchFailure::Rejected(error),
                    };
                    let result =
                        classify_allocation_refusal(&fake, &d, history == "first", Err(failure));
                    let finished = finish_dispatch(&d, result, Instant::now());
                    let expected = if history == "first" && observation == "absent" {
                        OperationState::Failed
                    } else {
                        OperationState::UnknownOutcome
                    };
                    assert_eq!(
                        finished.state, expected,
                        "{refusal}, {history}, {observation}"
                    );
                    assert_eq!(finished.error.unwrap().code, code);
                    assert_eq!(finished.payload.is_some(), refusal == "image-missing");
                }
            }
        }
    }

    #[test]
    fn admission_refusal_uses_journal_evidence_even_at_attempt_one() {
        let dir = tempfile::tempdir().unwrap();
        let binding = TransportBindingV11 {
            server: "wss://refusal.test".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        };
        let journal = Arc::new(
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap(),
        );
        let fake = FakeRuntime::new();
        fake.fixture_root().unwrap();
        let authority = HostAuthority::default();
        let relay = RelaySupervisor::start(
            Arc::new(fake),
            journal.clone(),
            authority.clone(),
            #[cfg(target_os = "linux")]
            None,
        );
        // An absent VM does not erase a prior issue recorded for this sandbox.
        let prior = dispatch("prior", "sandbox.create", 1);
        journal
            .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &prior))
            .unwrap();
        journal.record_effect("prior").unwrap();
        let d = dispatch("admission", "sandbox.create", 1);
        journal
            .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &d))
            .unwrap();
        assert_eq!(d.attempt, 1);
        assert!(!journal.first_allocation_attempt(&d));
        relay.refuse_before_runtime(
            &d,
            DispatchError {
                reason: None,
                code: SandboxErrorCode::StateConflict.into(),
                message: "live capacity full".into(),
            },
        );
        assert_eq!(
            done(&relay, "admission").state,
            OperationState::UnknownOutcome
        );
        assert_eq!(
            journal.lookup("admission").unwrap().state,
            OperationState::UnknownOutcome
        );
        // Pin the dequeue sampling too, separately from admission sampling.
        let mut worker = dispatch("worker", "sandbox.create", 1);
        worker.lease.as_mut().unwrap().deadline_unix_ms = 1;
        journal
            .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &worker))
            .unwrap();
        authority
            .accept_dispatch("worker", "sbx", "sandbox.create", 1, 1)
            .unwrap();
        relay.submit(worker, "wssp-sbx-sbx".into(), None).unwrap();
        assert_eq!(done(&relay, "worker").state, OperationState::UnknownOutcome);
        assert_eq!(
            journal.lookup("worker").unwrap().state,
            OperationState::UnknownOutcome
        );
    }

    #[test]
    fn reconnect_pre_runtime_refusals_require_first_attempt_and_not_running() {
        use sandbox_runtime::StopSandboxRequest;
        for refusal in ["cancel", "session-closed", "lease"] {
            for history in ["first", "retry", "ambiguous"] {
                for observation in ["absent", "stopped", "running", "error"] {
                    let mut fake = FakeRuntime::new();
                    fake.fixture_root().unwrap();
                    if matches!(observation, "stopped" | "running") {
                        seed(&fake);
                        if observation == "stopped" {
                            fake.stop_sandbox(&StopSandboxRequest {
                                template_fingerprint: CreateSandboxRequest::for_test("sbx", "seed")
                                    .template_digest
                                    .clone(),
                                sandbox_id: "sbx".into(),
                                instance_name: "wssp-sbx-sbx".into(),
                                operation_id: "stop".into(),
                                idempotency_key: "stop".into(),
                            })
                            .unwrap();
                        }
                    }
                    if observation == "error" {
                        fake = fake.with_inventory_hook(|stage| {
                            assert_eq!(stage, "running");
                            Err(RuntimeError::new(
                                SandboxErrorCode::Internal,
                                "daemon unavailable",
                            ))
                        });
                    }
                    let mut d = dispatch("reconnect", "sandbox.reconnect", 3);
                    d.attempt = if history == "retry" { 2 } else { 1 };
                    let error = DispatchError {
                        reason: None,
                        code: if refusal == "lease" {
                            SandboxErrorCode::StateConflict.into()
                        } else {
                            SandboxErrorCode::Cancelled.into()
                        },
                        message: refusal.into(),
                    };
                    let failure = if refusal == "session-closed" {
                        DispatchFailure::SessionClosed(error)
                    } else {
                        DispatchFailure::Rejected(error)
                    };
                    let result =
                        classify_allocation_refusal(&fake, &d, history == "first", Err(failure));
                    let finished = finish_dispatch(&d, result, Instant::now());
                    assert_eq!(
                        finished.state,
                        if history == "first" && matches!(observation, "absent" | "stopped") {
                            OperationState::Failed
                        } else {
                            OperationState::UnknownOutcome
                        },
                        "{refusal}, {history}, {observation}"
                    );
                }
            }
        }
    }

    #[test]
    fn reconnect_worker_and_admission_refusals_use_journal_first_attempt() {
        for admission in [false, true] {
            for history in ["first", "retry", "ambiguous"] {
                let dir = tempfile::tempdir().unwrap();
                let binding = TransportBindingV11 {
                    server: "wss://refusal.test".into(),
                    host_owner_id: "owner".into(),
                    host_id: "host".into(),
                };
                let journal = Arc::new(
                    crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap(),
                );
                // An older create and lease do not make a cold reconnect a retry.
                let prior = dispatch("prior", "sandbox.create", 1);
                journal
                    .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &prior))
                    .unwrap();
                journal.accept_fixture_lease(&prior).unwrap();
                let mut d = dispatch("reconnect", "sandbox.reconnect", 3);
                d.attempt = if history == "retry" { 2 } else { 1 };
                // Worker refusal: expired incoming lease, before runtime execution.
                d.lease.as_mut().unwrap().deadline_unix_ms = 1;
                journal
                    .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &d))
                    .unwrap();
                if history == "ambiguous" {
                    journal.record_effect("reconnect").unwrap();
                }
                assert_eq!(journal.first_allocation_attempt(&d), history == "first");
                let authority = HostAuthority::default();
                authority
                    .accept_dispatch("reconnect", "sbx", "sandbox.reconnect", 3, d.attempt)
                    .unwrap();
                let relay = RelaySupervisor::start(
                    Arc::new({
                        let fake = FakeRuntime::new();
                        fake.fixture_root().unwrap();
                        fake
                    }),
                    journal.clone(),
                    authority,
                    #[cfg(target_os = "linux")]
                    None,
                );
                if admission {
                    relay.refuse_before_runtime(
                        &d,
                        DispatchError {
                            reason: None,
                            code: SandboxErrorCode::StateConflict.into(),
                            message: "capacity full".into(),
                        },
                    );
                } else {
                    relay.submit(d, "wssp-sbx-sbx".into(), None).unwrap();
                }
                let expected = if history == "first" {
                    OperationState::Failed
                } else {
                    OperationState::UnknownOutcome
                };
                assert_eq!(
                    done(&relay, "reconnect").state,
                    expected,
                    "admission={admission}, {history}"
                );
                assert_eq!(journal.lookup("reconnect").unwrap().state, expected);
            }
        }
    }

    #[test]
    fn create_refusal_kinds_reach_shared_classifier() {
        for refusal in [
            "image-missing",
            "image-architecture",
            "image-error",
            "cancel",
            "journal-cancel",
            "session-closed",
            "lease",
            "runtime-preflight",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let binding = TransportBindingV11 {
                server: "wss://create.test".into(),
                host_owner_id: "owner".into(),
                host_id: "host".into(),
            };
            let journal = Arc::new(
                crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap(),
            );
            let fake = FakeRuntime::new();
            fake.fixture_root().unwrap();
            let mut d = dispatch("create", "sandbox.create", 1);
            let code = match refusal {
                "image-missing" | "image-architecture" | "image-error" => {
                    d.template_revision_id = Some("revision".into());
                    d.verification_connection_epoch = Some(7);
                    let artifact = if refusal == "image-error" {
                        "invalid image".into()
                    } else {
                        format!("sha256:{}", "f".repeat(64))
                    };
                    if refusal == "image-architecture" {
                        fake.register_image("test-image", &artifact, "aarch64");
                    }
                    d.template_digest = Some(artifact.clone());
                    d.incus_fingerprint = Some(artifact);
                    match refusal {
                        "image-missing" => SandboxErrorCode::NotFound,
                        "image-architecture" => SandboxErrorCode::StateConflict,
                        _ => SandboxErrorCode::ProtocolError,
                    }
                }
                "lease" => {
                    d.lease.as_mut().unwrap().deadline_unix_ms = 1;
                    SandboxErrorCode::StateConflict
                }
                "runtime-preflight" => {
                    d.guest_uid = Some(0);
                    SandboxErrorCode::ProtocolError
                }
                "session-closed" => SandboxErrorCode::Cancelled,
                _ => SandboxErrorCode::Cancelled,
            };
            let mut receipt = intent_from_dispatch(&journal, &binding, &d);
            // Legacy stored cancellations still pass through the
            // journal guard, even though new wire cancels forbid create.
            receipt.cancel_requested = refusal == "journal-cancel";
            journal.record_fixture_intent(&receipt).unwrap();
            assert!(journal.first_allocation_attempt(&d));
            let authority = HostAuthority::default();
            authority
                .accept_dispatch("create", "sbx", "sandbox.create", 1, 1)
                .unwrap();
            if refusal == "cancel" {
                // Supersession is the create cancellation path (wire
                // cancellation of lifecycle operations is forbidden).
                authority
                    .accept_dispatch("newer", "sbx", "sandbox.stop", 2, 1)
                    .unwrap();
            } else if refusal == "session-closed" {
                authority.shutdown();
            }
            let relay = RelaySupervisor::start(
                Arc::new(fake.clone()),
                journal.clone(),
                authority,
                #[cfg(target_os = "linux")]
                None,
            );
            relay.submit(d, "wssp-sbx-sbx".into(), None).unwrap();
            let finished = done(&relay, "create");
            let expected = OperationState::Failed;
            assert_eq!(finished.state, expected, "{refusal}");
            assert_eq!(finished.error.unwrap().code, code, "{refusal}");
            assert_eq!(journal.lookup("create").unwrap().state, expected);
            assert_eq!(finished.payload.is_some(), refusal == "image-missing");
            assert!(!fake.sandbox_exists("sbx").unwrap());
        }
    }

    #[test]
    fn real_unsupported_allocation_workers_cannot_prove_no_live_vm() {
        for kind in ["sandbox.create", "sandbox.reconnect"] {
            for attempt in [1, 2] {
                let dir = tempfile::tempdir().unwrap();
                let binding = TransportBindingV11 {
                    server: "wss://example".into(),
                    host_owner_id: "owner".into(),
                    host_id: "host".into(),
                };
                let journal = Arc::new(
                    crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap(),
                );
                let mut d = dispatch("unsupported", kind, 1);
                d.attempt = attempt;
                let authority = HostAuthority::default();
                let relay = RelaySupervisor::start(
                    Arc::new(sandbox_runtime::UnsupportedRuntime),
                    journal.clone(),
                    authority.clone(),
                    #[cfg(target_os = "linux")]
                    None,
                );
                admit(&relay, &journal, &binding, &authority, d);
                let finished = done(&relay, "unsupported");
                assert_eq!(
                    finished.error.unwrap().code,
                    SandboxErrorCode::HostRuntimeUnsupported
                );
                assert_eq!(
                    finished.state,
                    OperationState::UnknownOutcome,
                    "{kind}, attempt={attempt}"
                );
                assert_eq!(
                    journal.lookup("unsupported").unwrap().state,
                    OperationState::UnknownOutcome
                );
            }
        }
    }

    #[test]
    fn sandbox_command_environment_union_is_validated_and_redacted() {
        let mut d = dispatch("union", "command.run", 1);
        d.env = Some(vec![
            ("APP".into(), "command-private".into()),
            ("ONLY".into(), "command-only".into()),
        ]);
        let defaults = vec![
            ("APP".into(), "default-private".into()),
            ("KEEP".into(), "retained-private".into()),
        ];
        let request =
            run_command_request_from_dispatch(&d, "wssp-sbx-sbx".into(), &defaults).unwrap();
        assert_eq!(
            request.env,
            vec![
                ("APP".into(), "command-private".into()),
                ("KEEP".into(), "retained-private".into()),
                ("ONLY".into(), "command-only".into())
            ]
        );
        for private in ["command-private", "retained-private", "default-private"] {
            assert!(!format!("{request:?}").contains(private));
        }
        let defaults: Vec<_> = (0..64).map(|i| (format!("K{i}"), "value".into())).collect();
        let error =
            run_command_request_from_dispatch(&d, "wssp-sbx-sbx".into(), &defaults).unwrap_err();
        assert!(!error.message.contains("private"));
        d.env = Some(vec![
            ("APP".into(), "one".into()),
            ("APP".into(), "two".into()),
        ]);
        assert!(run_command_request_from_dispatch(&d, "wssp-sbx-sbx".into(), &[]).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn retained_defaults_reach_both_command_paths_without_argv_or_proc_values() {
        for supervised in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            let binary = root.join("incus");
            crate::sandbox_relay::test_support::install_executable(
                &binary,
                r#"#!/bin/sh
root=$(dirname "$0")
[ "$1" = "--project" ] && shift 2
case "$1" in
 version) exit 0 ;;
 profile) echo '[{"name":"default","devices":{"root":{"type":"disk","path":"/","pool":"default"},"eth0":{"type":"nic","network":"incusbr0"}}}]'; exit 0 ;;
 query) echo '{"type":"sync","metadata":{"status":"Running","status_code":103,"type":"virtual-machine","config":{"user.flycockpit.sandbox_id":"sbx","user.flycockpit.template_digest":"sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789","volatile.base_image":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"}}}'; exit 0 ;;
 exec)
   while [ "$1" != "--" ]; do shift; done; shift
   case "$1" in
     /bin/sh) exec "$@" ;;
     *) exec /usr/bin/python3 "$root/transport.py" "$@" ;;
   esac ;;
esac
exit 1
"#,
                0o700,
            );
            std::fs::write(
                root.join("transport.py"),
                include_str!("../../../../crates/sandbox-runtime/fixtures/env-transport.py")
                    .replace(
                        "HOME='/home/user'",
                        &format!(
                            "HOME={}",
                            serde_json::to_string(&root.to_string_lossy()).unwrap()
                        ),
                    ),
            )
            .unwrap();
            std::fs::write(root.join("transport-mode"), "pass").unwrap();
            let runtime = IncusKvmRuntime::new(IncusConfig {
                binary: binary.to_string_lossy().into_owned(),
                project: "default".into(),
            })
            .unwrap();
            let exec = runtime.exec_supervisor();
            let binding = TransportBindingV11 {
                server: "wss://example".into(),
                host_owner_id: "owner".into(),
                host_id: "host".into(),
            };
            let journal = Arc::new(
                crate::sandbox_relay::test_support::open_journal(root.join("journal"), &binding)
                    .unwrap(),
            );
            let key = sandbox_protocol::JournalKeyInstall {
                connection_epoch: 1,
                key_version: 1,
                key_id: "d".repeat(32),
                key_hex: "ab".repeat(32),
                server: binding.server.clone(),
                host_owner_id: binding.host_owner_id.clone(),
                host_id: binding.host_id.clone(),
            };
            journal.install_key(&key, &binding, 1).unwrap();
            let config = sandbox_protocol::PrivateConfigInstall {
                sandbox_owner_id: "owner".into(),
                refusal_token: Some("install-token".into()),
                connection_epoch: 1,
                server: binding.server.clone(),
                host_owner_id: binding.host_owner_id.clone(),
                host_id: binding.host_id.clone(),
                sandbox_id: "sbx".into(),
                generation: 1,
                config: sandbox_protocol::PrivateConfigRef {
                    config_id: "config".into(),
                    binding_scheme: "hmac-sha256-v1".into(),
                    binding_key_id: key.key_id.clone(),
                    binding_mac: "c".repeat(64),
                },
                env: vec![
                    ("APP".into(), "default-private".into()),
                    ("KEEP".into(), "retained-private".into()),
                ],
            };
            journal.install_config(&config, &binding, 1).unwrap();
            let authority = HostAuthority::default();
            let relay = RelaySupervisor::start(
                Arc::new(runtime),
                journal.clone(),
                authority.clone(),
                supervised.then_some(exec),
            );
            let mut command = dispatch("command", "command.run", 1);
            command.guest_home = Some(root.to_string_lossy().into_owned());
            command.private_config = Some(config.config.clone());
            command.digest_scheme = Some("hmac-sha256-v1".into());
            command.digest_key_id = Some(key.key_id.clone());
            command.env = Some(vec![
                ("APP".into(), "command-private".into()),
                ("HOME".into(), "ignored-private".into()),
            ]);
            command.argv = Some(vec!["/usr/bin/python3".into(), "-I".into(), "-c".into(), "import os,sys,json; open(sys.argv[1],'w').write(json.dumps({k:os.environ.get(k) for k in ['APP','KEEP','HOME']}))".into(), root.join("target-env").to_string_lossy().into_owned()]);
            journal
                .record_fixture_intent(&journal.prepare_dispatch(&binding, &command).unwrap())
                .unwrap();
            authority
                .accept_dispatch("command", "sbx", "command.run", 1, 1)
                .unwrap();
            relay.submit(command, "wssp-sbx-sbx".into(), None).unwrap();
            let (result, frames) = done_with_output(&relay, "command");
            let stderr: Vec<u8> = frames
                .iter()
                .flat_map(|frame| frame.body().to_vec())
                .collect();
            assert_eq!(
                result.state,
                OperationState::Succeeded,
                "{supervised}: {result:?}: {}",
                String::from_utf8_lossy(&stderr)
            );
            let target: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(root.join("target-env")).unwrap())
                    .unwrap();
            assert_eq!(
                target,
                json!({"APP":"command-private", "KEEP":"retained-private", "HOME": root.to_string_lossy()})
            );
            for path in ["actual-proc", "actual-argv"] {
                let bytes = std::fs::read(root.join(path)).unwrap();
                for value in [
                    b"retained-private".as_slice(),
                    b"command-private",
                    b"default-private",
                    b"ignored-private",
                ] {
                    assert!(!bytes.windows(value.len()).any(|b| b == value));
                }
            }
            let receipt = serde_json::to_string(&journal.lookup("command").unwrap()).unwrap();
            assert!(!receipt.contains("retained-private"));
            assert!(!receipt.contains("command-private"));

            // Each source fits individually, but the union exceeds 64 names.
            // The effect persistence trap must remain untouched in BOTH paths.
            let mut oversize = dispatch("oversize-union", "command.run", 1);
            oversize.private_config = Some(config.config.clone());
            oversize.digest_scheme = Some("hmac-sha256-v1".into());
            oversize.digest_key_id = Some(key.key_id.clone());
            oversize.env = Some((0..64).map(|i| (format!("K{i}"), "value".into())).collect());
            journal
                .record_fixture_intent(&journal.prepare_dispatch(&binding, &oversize).unwrap())
                .unwrap();
            authority
                .accept_dispatch("oversize-union", "sbx", "command.run", 1, 1)
                .unwrap();
            journal.inject_crash(CrashPoint::AfterEffect);
            relay.submit(oversize, "wssp-sbx-sbx".into(), None).unwrap();
            let refused = done(&relay, "oversize-union");
            assert_eq!(
                refused.state,
                OperationState::Failed,
                "{supervised}: {refused:?}"
            );
            assert_eq!(
                refused.error.unwrap().code,
                SandboxErrorCode::RequestTooLarge
            );
        }
    }

    #[test]
    fn large_command_output_never_enters_control_json() {
        let response = sandbox_runtime::RunCommandResponse {
            command: sandbox_runtime::CommandRecord {
                operation_id: "large".into(),
                idempotency_key: "large".into(),
                state: OperationState::Succeeded,
                exit_code: Some(0),
                guest_pid: None,
                birth: None,
                chunks: vec![sandbox_runtime::CommandStreamChunk {
                    stream: sandbox_runtime::CommandStream::Stdout,
                    sequence: 0,
                    bytes: vec![b'x'; 2 * 1024 * 1024],
                    final_chunk: true,
                }],
            },
        };
        let result = command_result_json(&response);
        assert!(
            result.to_string().len() < 128,
            "command control contains output bytes"
        );
        assert_eq!(result, json!({"exitCode":0,"pid":null}));
    }

    #[test]
    fn c15_command_builder_rejects_missing_identity_and_preserves_script_and_guest() {
        let mut d = dispatch("script", "command.run", 1);
        d.argv = None;
        d.script = Some("printf '世界  '\n".into());
        d.guest_uid = Some(1234);
        d.guest_gid = Some(2345);
        d.guest_home = Some("/home/declared".into());
        let request = run_command_request_from_dispatch(&d, "wssp-sbx-sbx".into(), &[]).unwrap();
        assert_eq!(request.script, d.script);
        assert_eq!(
            request.template_fingerprint,
            d.incus_fingerprint.clone().unwrap()
        );
        assert_eq!(request.guest.guest_uid, 1234);
        assert_eq!(request.guest.guest_gid, 2345);
        assert_eq!(request.guest.guest_home, "/home/declared");
        for invalid in [None, Some(String::new()), Some("alias".into())] {
            d.incus_fingerprint = invalid;
            let error =
                run_command_request_from_dispatch(&d, "wssp-sbx-sbx".into(), &[]).unwrap_err();
            assert_eq!(error.code, SandboxErrorCode::ProtocolError);
        }
    }

    #[test]
    fn crash_after_write_before_result_never_repeats_and_control_continues() {
        let _staging = crate::sandbox_relay::test_support::staging_quota();
        let dir = tempfile::tempdir().expect("dir");
        let binding = TransportBindingV11 {
            server: "wss://example".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        };
        let journal = Arc::new(
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding)
                .expect("journal"),
        );
        let fake = FakeRuntime::new();
        fake.fixture_root().unwrap();
        fake.create_fixture(&CreateSandboxRequest::for_test("sbx", "create"))
            .expect("create");
        let runtime: Arc<dyn SandboxRuntime> = Arc::new(fake);
        let authority = HostAuthority::default();
        let relay = RelaySupervisor::start(
            runtime.clone(),
            journal.clone(),
            authority.clone(),
            #[cfg(target_os = "linux")]
            None,
        );
        let dispatch: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner", "operationId":"write", "sandboxId":"sbx", "generation":1, "attempt":1, "kind":"file.put", "idempotencyKey":"write","bodyHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "path":"/file"})).expect("dispatch");
        let receipt = intent_from_dispatch(&journal, &binding, &dispatch);
        journal.record_fixture_intent(&receipt).expect("intent");
        journal.inject_crash(CrashPoint::BeforeResult);
        authority
            .accept_dispatch("write", "sbx", "file.put", 1, 1)
            .expect("admit");
        relay
            .submit(
                dispatch,
                "wssp-sbx-sbx".into(),
                Some(sandbox_runtime::FileContent::from_bytes(b"once").unwrap()),
            )
            .expect("submit");
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(done) = relay.poll_finished().pop() {
                assert_eq!(done.state, OperationState::UnknownOutcome);
                break;
            }
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            runtime
                .read_file(&ReadFileRequest {
                    sandbox_owner_id: "owner".into(),
                    template_fingerprint: sandbox_runtime::CreateSandboxRequest::for_test(
                        "sbx", "key"
                    )
                    .template_digest,
                    guest: Default::default(),
                    sandbox_id: "sbx".into(),
                    instance_name: "wssp-sbx-sbx".into(),
                    operation_id: "read".into(),
                    idempotency_key: "read".into(),
                    path: "/file".into()
                })
                .expect("external effect happened")
                .bytes
                .read_chunk(0, sandbox_runtime::FILE_CHUNK_BYTES)
                .unwrap(),
            b"once"
        );
        drop(relay);
        drop(journal);
        let journal = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding)
            .expect("restart");
        assert!(matches!(
            journal.record_fixture_intent(&receipt).expect("duplicate"),
            Decision::Unknown(_)
        ));
    }

    fn drain_fixture() -> (
        tempfile::TempDir,
        Arc<HostJournal>,
        HostAuthority,
        RelaySupervisor,
    ) {
        drain_fixture_with_clock(None)
    }

    fn drain_fixture_with_clock(
        clock: Option<Arc<dyn crate::sandbox_relay::clock::ClockSource>>,
    ) -> (
        tempfile::TempDir,
        Arc<HostJournal>,
        HostAuthority,
        RelaySupervisor,
    ) {
        let dir = tempfile::tempdir().expect("dir");
        let binding = TransportBindingV11 {
            server: "wss://example".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        };
        let mut journal = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding)
            .expect("journal");
        if let Some(clock) = clock {
            journal.clock = Arc::new(crate::sandbox_relay::clock::LeaseClock::new(clock));
        }
        let journal = Arc::new(journal);
        let fake = FakeRuntime::new();
        fake.fixture_root().unwrap();
        let authority = HostAuthority::default();
        let relay = RelaySupervisor::start(
            Arc::new(fake),
            journal.clone(),
            authority.clone(),
            #[cfg(target_os = "linux")]
            None,
        );
        (dir, journal, authority, relay)
    }

    fn finished_command(id: &str) -> FinishedOp {
        FinishedOp {
            operation_id: id.into(),
            sandbox_id: "sbx".into(),
            generation: 1,
            attempt: 1,
            state: OperationState::Succeeded,
            payload: None,
            error: None,
            download: None,
            interim: false,
            readiness_detail: None,
            owner: None,
        }
    }

    /// D3a: a command's final retained output (here the full 1 MiB head and
    /// tail of a 4 MiB stream) reaches a server that ACKs slower than the old
    /// fixed 1 s grace allowed, and the result publishes only after it.
    #[test]
    fn slow_acking_server_receives_the_complete_tail_before_the_result() {
        let (_dir, _journal, authority, relay) = drain_fixture();
        authority
            .accept_dispatch("cmd", "sbx", "command.run", 1, 1)
            .expect("admit");
        let output = sandbox_runtime::CommandOutput::default();
        let total = 4 * 1024 * 1024;
        for n in 0..total / 8192 {
            let mut chunk = vec![0u8; 8192];
            chunk[..8].copy_from_slice(&(n as u64).to_be_bytes());
            output.push(sandbox_runtime::CommandStream::Stdout, &chunk);
        }
        let retained = output.retained();
        assert_eq!(retained, 1024 * 1024);
        relay
            .outputs
            .lock()
            .unwrap()
            .insert(("cmd".into(), 1, 1), OutputWindow::new(output.clone()));
        relay
            .finished_sender()
            .send(finished_command("cmd"))
            .expect("finish");
        // The server ingests one chunk per 12 ms: ~1.5 s for the whole tail.
        let mut unacked: VecDeque<Frame> = VecDeque::new();
        let mut stored: std::collections::BTreeMap<u64, (u64, usize)> = Default::default();
        let started = Instant::now();
        let result = loop {
            assert!(started.elapsed() < Duration::from_secs(20), "drain hung");
            for frame in relay.poll_output().expect("encode") {
                if !stored.contains_key(&frame.metadata.sequence)
                    && !unacked
                        .iter()
                        .any(|f| f.metadata.sequence == frame.metadata.sequence)
                {
                    unacked.push_back(frame);
                }
            }
            let done = relay.poll_finished();
            if let Some(done) = done.into_iter().next() {
                break done;
            }
            if let Some(frame) = unacked.pop_front() {
                thread::sleep(Duration::from_millis(12));
                let offset = frame.metadata.offset.expect("offset");
                stored.insert(frame.metadata.sequence, (offset, frame.body_len()));
                relay.ack_output(
                    "cmd".into(),
                    1,
                    1,
                    frame.metadata.sequence,
                    offset + frame.body_len() as u64,
                );
            } else {
                thread::sleep(Duration::from_millis(1));
            }
        };
        assert_eq!(result.operation_id, "cmd");
        assert!(
            started.elapsed() > Duration::from_secs(1),
            "the drain outlived the old grace"
        );
        let bytes: usize = stored.values().map(|(_, len)| len).sum();
        assert_eq!(bytes, retained, "tail lost before the result");
        let (last_offset, last_len) = stored.values().next_back().copied().unwrap();
        assert_eq!(last_offset + last_len as u64, total as u64);
        assert!(!relay.output_open("cmd", 1, 1));
    }

    /// D3a: with no ACK progress the completion still publishes, after
    /// `DRAIN_IDLE`, with the unsent output left as a gap.
    #[test]
    fn stalled_drain_publishes_after_the_idle_bound() {
        let (_dir, _journal, _authority, relay) = drain_fixture();
        let output = sandbox_runtime::CommandOutput::default();
        output.push(sandbox_runtime::CommandStream::Stdout, b"never acked");
        relay
            .outputs
            .lock()
            .unwrap()
            .insert(("cmd".into(), 1, 1), OutputWindow::new(output));
        relay
            .finished_sender()
            .send(finished_command("cmd"))
            .expect("finish");
        let started = Instant::now();
        loop {
            if let Some(done) = relay.poll_finished().pop() {
                assert_eq!(done.operation_id, "cmd");
                break;
            }
            assert!(started.elapsed() < super::super::output::DRAIN_IDLE + Duration::from_secs(5));
            thread::sleep(Duration::from_millis(20));
        }
        assert!(started.elapsed() >= super::super::output::DRAIN_IDLE);
        assert!(!relay.output_open("cmd", 1, 1));
    }

    /// D3a: a completion held for its output never outlives the sandbox
    /// lease: within `LEASE_MARGIN` of the journaled deadline it publishes.
    #[test]
    fn held_completion_publishes_before_the_lease_deadline() {
        let (_dir, journal, authority, relay) = drain_fixture();
        let now_ms = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();
        let create: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner", "operationId":"create", "sandboxId":"sbx", "generation":1, "attempt":1, "kind":"sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(), "idempotencyKey":"create","bodyHash":"a".repeat(64), "lease":{"revision":1,"deadlineUnixMs":now_ms + 6_000,"action":"destroy","expiryPolicy":"retry-force-60s"}})).expect("dispatch");
        let binding = TransportBindingV11 {
            server: "wss://example".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        };
        journal
            .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &create))
            .expect("intent");
        journal.accept_fixture_lease(&create).expect("lease");
        assert!(journal.lease("sbx").is_some());
        authority
            .accept_dispatch("cmd", "sbx", "command.run", 1, 1)
            .expect("admit");
        let output = sandbox_runtime::CommandOutput::default();
        output.push(sandbox_runtime::CommandStream::Stdout, b"never acked");
        relay
            .outputs
            .lock()
            .unwrap()
            .insert(("cmd".into(), 1, 1), OutputWindow::new(output));
        relay
            .finished_sender()
            .send(finished_command("cmd"))
            .expect("finish");
        let started = Instant::now();
        // Released 2 s (`LEASE_MARGIN`) before the deadline by wall clock:
        // later than the old 1 s grace, before `DRAIN_IDLE`. Measured on the
        // wall clock so slow fixture setup cannot skew it.
        let wall_ms = || {
            u64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis(),
            )
            .unwrap()
        };
        let deadline_ms = now_ms + 6_000;
        loop {
            if relay.poll_finished().pop().is_some() {
                break;
            }
            assert!(wall_ms() < deadline_ms, "held past the lease");
            thread::sleep(Duration::from_millis(20));
        }
        let released = wall_ms();
        assert!(
            released + 50 >= deadline_ms - 2_000 && released < deadline_ms,
            "released {} ms before the deadline",
            deadline_ms.saturating_sub(released)
        );
        assert!(started.elapsed() < super::super::output::DRAIN_IDLE);
    }

    /// A lease clock source whose wall clock can roll back and whose reads
    /// can fail; monotonic milliseconds advance only when the test says so.
    #[derive(Debug, Default)]
    struct RollbackClock {
        wall: std::sync::atomic::AtomicU64,
        mono: std::sync::atomic::AtomicU64,
        fail: std::sync::atomic::AtomicBool,
    }
    impl crate::sandbox_relay::clock::ClockSource for RollbackClock {
        fn sample(&self) -> anyhow::Result<(u64, u64)> {
            use std::sync::atomic::Ordering::SeqCst;
            if self.fail.load(SeqCst) {
                anyhow::bail!("clock unavailable");
            }
            Ok((self.wall.load(SeqCst), self.mono.load(SeqCst)))
        }
    }

    /// A command of `sbx` finished with output that is never ACKed, under a
    /// destroy lease ending at `deadline_ms` (by the journal's lease clock).
    fn hold_completion_under_lease(
        journal: &HostJournal,
        authority: &HostAuthority,
        relay: &RelaySupervisor,
        deadline_ms: u64,
    ) {
        let create: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner", "operationId":"create", "sandboxId":"sbx", "generation":1, "attempt":1, "kind":"sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(), "idempotencyKey":"create","bodyHash":"a".repeat(64), "lease":{"revision":1,"deadlineUnixMs":deadline_ms,"action":"destroy","expiryPolicy":"retry-force-60s"}})).expect("dispatch");
        let binding = TransportBindingV11 {
            server: "wss://example".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        };
        journal
            .record_fixture_intent(&intent_from_dispatch(journal, &binding, &create))
            .expect("intent");
        journal.accept_fixture_lease(&create).expect("lease");
        authority
            .accept_dispatch("cmd", "sbx", "command.run", 1, 1)
            .expect("admit");
        let output = sandbox_runtime::CommandOutput::default();
        output.push(sandbox_runtime::CommandStream::Stdout, b"never acked");
        relay
            .outputs
            .lock()
            .unwrap()
            .insert(("cmd".into(), 1, 1), OutputWindow::new(output));
        relay
            .finished_sender()
            .send(finished_command("cmd"))
            .expect("finish");
    }

    /// D3a: the lease margin is measured on the rollback-resistant lease
    /// clock that expiry uses. The system wall clock here is a day behind the
    /// lease clock (a backward adjustment): the completion still publishes
    /// 2 s (`LEASE_MARGIN`) before the deadline by the lease clock, not when
    /// the rolled-back wall clock would reach it.
    #[test]
    fn held_completion_publishes_by_the_lease_clock_after_a_wall_clock_rollback() {
        use std::sync::atomic::Ordering::SeqCst;
        let real_ms = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();
        let lease_now = real_ms + 86_400_000;
        let clock = Arc::new(RollbackClock::default());
        clock.wall.store(lease_now, SeqCst);
        let (_dir, journal, authority, relay) = drain_fixture_with_clock(Some(clock.clone()));
        let deadline_ms = lease_now + 6_000;
        hold_completion_under_lease(&journal, &authority, &relay, deadline_ms);
        // The wall clock rolls back a day; 3 s pass on the monotonic clock.
        clock.wall.store(real_ms, SeqCst);
        clock.mono.store(3_000, SeqCst);
        assert!(relay.poll_finished().is_empty(), "3 s before the deadline");
        // 1 999 ms before the deadline by the lease clock: inside the margin.
        clock.mono.store(4_001, SeqCst);
        let ready = relay.poll_finished();
        assert_eq!(ready.len(), 1, "held inside the lease margin");
        assert_eq!(ready[0].operation_id, "cmd");
        assert!(!relay.output_open("cmd", 1, 1));
    }

    /// D3a: when the lease clock cannot be read, a held completion publishes
    /// at once rather than waiting for its output drain.
    #[test]
    fn held_completion_publishes_at_once_when_the_lease_clock_fails() {
        use std::sync::atomic::Ordering::SeqCst;
        let lease_now = 4_000_000_000_000;
        let clock = Arc::new(RollbackClock::default());
        clock.wall.store(lease_now, SeqCst);
        let (_dir, journal, authority, relay) = drain_fixture_with_clock(Some(clock.clone()));
        hold_completion_under_lease(&journal, &authority, &relay, lease_now + 600_000);
        assert!(
            relay.poll_finished().is_empty(),
            "held while the lease is far off"
        );
        clock.fail.store(true, SeqCst);
        let ready = relay.poll_finished();
        assert_eq!(ready.len(), 1, "held with an unreadable lease clock");
        assert_eq!(ready[0].operation_id, "cmd");
    }

    /// D3a: completions held for their output drain do not close the
    /// completion queue to unrelated work.
    #[test]
    fn draining_completions_do_not_block_unrelated_completions() {
        let (_dir, _journal, _authority, relay) = drain_fixture();
        for n in 0..QUEUE_CAP {
            let id = format!("cmd{n}");
            let output = sandbox_runtime::CommandOutput::default();
            output.push(sandbox_runtime::CommandStream::Stdout, b"unacked");
            relay
                .outputs
                .lock()
                .unwrap()
                .insert((id.clone(), 1, 1), OutputWindow::new(output));
            relay
                .finished_sender()
                .send(finished_command(&id))
                .expect("finish");
            assert!(relay.poll_finished().is_empty());
        }
        let mut other = finished_command("file");
        other.state = OperationState::Succeeded;
        relay.finished_sender().send(other).expect("finish");
        let ready = relay.poll_finished();
        assert_eq!(
            ready
                .iter()
                .map(|d| d.operation_id.as_str())
                .collect::<Vec<_>>(),
            vec!["file"]
        );
        assert_eq!(relay.pending.lock().unwrap().len(), QUEUE_CAP);
    }

    /// C25: when result persistence fails, `persist_finished` blanks the
    /// payload. The finished producer must still be recognized as finished:
    /// its output window is released after the bounded drain/grace instead of
    /// leaking a command slot until reconnect.
    #[test]
    fn failed_result_persistence_releases_the_output_window() {
        let dir = tempfile::tempdir().expect("dir");
        let binding = TransportBindingV11 {
            server: "wss://example".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        };
        let journal = Arc::new(
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding)
                .expect("journal"),
        );
        let fake = FakeRuntime::new();
        fake.fixture_root().unwrap();
        fake.create_fixture(&CreateSandboxRequest::for_test("sbx", "create"))
            .expect("create");
        let runtime: Arc<dyn SandboxRuntime> = Arc::new(fake);
        let authority = HostAuthority::default();
        let relay = RelaySupervisor::start(
            runtime,
            journal.clone(),
            authority.clone(),
            #[cfg(target_os = "linux")]
            None,
        );
        let dispatch: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner", "operationId":"cmd", "sandboxId":"sbx", "generation":1, "attempt":1, "kind":"command.run", "argv":["true"], "idempotencyKey":"cmd","bodyHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})).expect("dispatch");
        journal
            .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &dispatch))
            .expect("intent");
        journal.inject_crash(CrashPoint::BeforeResult);
        authority
            .accept_dispatch("cmd", "sbx", "command.run", 1, 1)
            .expect("admit");
        relay
            .submit(dispatch, "wssp-sbx-sbx".into(), None)
            .expect("submit");
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let done = relay.poll_finished();
            if let Some(done) = done.iter().find(|d| d.operation_id == "cmd") {
                assert_eq!(done.state, OperationState::UnknownOutcome);
                assert!(!done.interim);
                break;
            }
            assert!(Instant::now() < deadline, "finished op never published");
            thread::sleep(Duration::from_millis(5));
        }
        let window_deadline = Instant::now() + Duration::from_secs(3);
        while relay.output_open("cmd", 1, 1) {
            relay.poll_finished();
            assert!(
                Instant::now() < window_deadline,
                "output window leaked after persistence failure"
            );
            thread::sleep(Duration::from_millis(5));
        }
        // A freed slot admits fresh command work immediately.
        let mut next: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner", "operationId":"cmd-2", "sandboxId":"sbx", "generation":1, "attempt":1, "kind":"command.run", "argv":["true"], "idempotencyKey":"cmd-2","bodyHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})).expect("dispatch");
        next.operation_id = "cmd-2".into();
        journal
            .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &next))
            .expect("intent");
        authority
            .accept_dispatch("cmd-2", "sbx", "command.run", 1, 1)
            .expect("admit");
        relay
            .submit(next, "wssp-sbx-sbx".into(), None)
            .expect("slot released");
    }

    #[test]
    fn c14_blocked_observations_do_not_block_control_and_are_bounded() {
        let dir = tempfile::tempdir().expect("dir");
        let binding = TransportBindingV11 {
            server: "wss://example".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        };
        let journal = Arc::new(
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding)
                .expect("journal"),
        );
        let relay = RelaySupervisor::start(
            Arc::new({
                let fake = FakeRuntime::new();
                fake.fixture_root().unwrap();
                fake
            }),
            journal,
            HostAuthority::default(),
            #[cfg(target_os = "linux")]
            None,
        );
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        relay
            .observe(move || {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            })
            .unwrap();
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        for _ in 0..QUEUE_CAP {
            relay.observe(|| {}).unwrap();
        }
        assert!(relay.observe(|| {}).is_err());
        let (control_tx, control_rx) = mpsc::channel();
        relay
            .control(move || {
                control_tx.send(()).unwrap();
            })
            .unwrap();
        let (storage_tx, storage_rx) = mpsc::channel();
        relay
            .observe_storage(move || storage_tx.send(()).unwrap())
            .unwrap();
        let storage_progressed = storage_rx.recv_timeout(Duration::from_secs(1));
        let progressed = control_rx.recv_timeout(Duration::from_secs(1));
        release_tx.send(()).unwrap();
        progressed.expect("cancel/stdin lane progresses during host inventory IO");
        storage_progressed.expect("storage health progresses during host inventory IO");
    }

    #[test]
    fn control_queue_capacity_is_bounded() {
        let _staging = crate::sandbox_relay::test_support::staging_quota();
        let dir = tempfile::tempdir().expect("dir");
        let binding = TransportBindingV11 {
            server: "wss://example".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        };
        let journal = Arc::new(
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding)
                .expect("journal"),
        );
        let runtime: Arc<dyn SandboxRuntime> = Arc::new({
            let fake = FakeRuntime::new();
            fake.fixture_root().unwrap();
            fake
        });
        let authority = HostAuthority::default();
        let relay = RelaySupervisor::start(
            runtime.clone(),
            journal.clone(),
            authority.clone(),
            #[cfg(target_os = "linux")]
            None,
        );
        let dispatch: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner", "operationId":"create", "sandboxId":"sbx", "generation":1, "attempt":1, "kind":"sandbox.create", "cpuCount": 1, "memoryMiB": 1024, "lease": sandbox_protocol::HostLease::for_test(), "idempotencyKey":"create","bodyHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})).expect("dispatch");
        journal
            .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &dispatch))
            .expect("intent");
        authority
            .accept_dispatch("create", "sbx", "sandbox.create", 1, 1)
            .expect("admit");
        relay
            .submit(dispatch, "wssp-sbx-sbx".into(), None)
            .expect("submit");
        let (tx, rx) = mpsc::channel();
        relay
            .control(move || {
                tx.send(()).expect("control");
            })
            .expect("enqueue");
        rx.recv_timeout(Duration::from_secs(1))
            .expect("control progresses independently");
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        relay
            .control(move || {
                entered_tx.send(()).expect("entered");
                release_rx.recv().expect("release");
            })
            .expect("block control");
        entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("entered");
        for _ in 0..QUEUE_CAP {
            relay.control(|| {}).expect("bounded slots");
        }
        assert!(relay.control(|| {}).is_err());
        release_tx.send(()).expect("release");
        drop(relay);
    }
    use sandbox_runtime::*;
    use std::sync::Mutex;
    include!("command_pool_tests.rs");
    include!("lifecycle_pool_tests.rs");
    include!("ordinary_pool_tests.rs");
    include!("output_chunk_tests.rs");

    type CommandHook = Arc<
        dyn Fn(&RunCommandRequest, &Arc<RuntimePermit>) -> Result<(), RuntimeError> + Send + Sync,
    >;
    #[derive(Clone)]
    struct GatedRuntime {
        inner: Arc<dyn SandboxRuntime>,
        kind: &'static str,
        entered: mpsc::SyncSender<()>,
        release: Arc<Mutex<mpsc::Receiver<()>>>,
        cancelled: mpsc::Sender<()>,
        timeout: bool,
        permit: Option<Arc<RuntimePermit>>,
        command_hook: Option<CommandHook>,
    }
    impl GatedRuntime {
        fn pause(&self, kind: &str) -> Result<(), RuntimeError> {
            if kind == self.kind {
                self.entered.send(()).unwrap();
                let release = self.release.lock().unwrap();
                if kind == "sandbox.create" {
                    // Model the production readiness wait: the VM exists,
                    // but admission revocation interrupts its boot polling.
                    loop {
                        if let Some(permit) = &self.permit {
                            permit.wait_for(Duration::ZERO)?;
                        }
                        match release.recv_timeout(Duration::from_millis(10)) {
                            Ok(()) => break,
                            Err(mpsc::RecvTimeoutError::Timeout) => continue,
                            Err(error) => panic!("boot gate disconnected: {error}"),
                        }
                    }
                } else {
                    release.recv_timeout(Duration::from_secs(5)).unwrap();
                }
                if self.timeout {
                    return Err(RuntimeError::new(
                        SandboxErrorCode::Timeout,
                        "effect performed then timeout",
                    ));
                }
                if self.permit.as_ref().is_some_and(|p| p.is_cancelled()) {
                    return Err(RuntimeError::new(
                        SandboxErrorCode::UnknownOutcome,
                        "preempted",
                    ));
                }
            }
            Ok(())
        }
    }
    impl SandboxRuntime for GatedRuntime {
        fn egress_guard_check(&self) -> Result<(), sandbox_runtime::RuntimeError> {
            self.inner.egress_guard_check()
        }
        fn initialize_storage_pool(
            &self,
            name: &str,
            expected: Option<&sandbox_runtime::StoragePoolIdentity>,
        ) -> Result<sandbox_runtime::StoragePoolIdentity, RuntimeError> {
            self.inner.initialize_storage_pool(name, expected)
        }
        fn observe_storage_pool(
            &self,
            pool: &sandbox_runtime::StoragePoolIdentity,
        ) -> Result<sandbox_runtime::StoragePoolObservation, RuntimeError> {
            self.inner.observe_storage_pool(pool)
        }
        fn storage_root_census(
            &self,
            pool: &sandbox_runtime::StoragePoolIdentity,
        ) -> Result<sandbox_runtime::StorageRootCensus, RuntimeError> {
            self.inner.storage_root_census(pool)
        }
        fn prove_root_absent(
            &self,
            root: &sandbox_runtime::RootDisk,
            name: &str,
        ) -> Result<sandbox_runtime::RootAbsenceProof, RuntimeError> {
            self.inner.prove_root_absent(root, name)
        }
        fn with_cancellation(&self, permit: Arc<RuntimePermit>) -> Box<dyn SandboxRuntime> {
            Box::new(Self {
                inner: Arc::from(self.inner.with_cancellation(permit.clone())),
                permit: Some(permit),
                ..self.clone()
            })
        }
        fn query_sandbox(
            &self,
            id: &str,
            key: Option<&str>,
            template_fingerprint: Option<&str>,
        ) -> Result<Option<sandbox_protocol::SandboxLifecycleState>, RuntimeError> {
            self.inner.query_sandbox(id, key, template_fingerprint)
        }
        fn create_sandbox_on_storage(
            &self,
            r: &CreateSandboxRequest,
            root: &sandbox_runtime::RootDisk,
        ) -> sandbox_runtime::EffectOutcome<CreateSandboxResponse> {
            let result = self.inner.create_sandbox_on_storage(r, root)?;
            self.pause("sandbox.create")?;
            Ok(result)
        }
        fn write_file(
            &self,
            r: &WriteFileRequest,
        ) -> sandbox_runtime::EffectOutcome<WriteFileResponse> {
            let result = self.inner.write_file(r)?;
            self.pause("file.put")?;
            Ok(result)
        }
        fn run_command(
            &self,
            r: &RunCommandRequest,
        ) -> sandbox_runtime::EffectOutcome<RunCommandResponse> {
            if let Some(hook) = &self.command_hook {
                hook(r, self.permit.as_ref().expect("scoped command permit"))?;
            } else {
                self.pause("command.run")?;
            }
            self.inner.run_command(r)
        }
        fn cancel_operation(&self, id: &str) -> sandbox_runtime::EffectOutcome<()> {
            let proof = self.inner.cancel_operation(id)?;
            self.cancelled.send(()).unwrap();
            Ok(proof)
        }
        fn kill_sandbox_on_storage(
            &self,
            request: &KillSandboxRequest,
            root: &sandbox_runtime::RootDisk,
        ) -> sandbox_runtime::EffectOutcome<KillSandboxResponse> {
            self.inner.kill_sandbox_on_storage(request, root)
        }
        fn read_file(&self, request: &ReadFileRequest) -> Result<ReadFileResponse, RuntimeError> {
            self.inner.read_file(request)
        }
        fn reconnect_sandbox_on_storage(
            &self,
            request: &ReconnectSandboxRequest,
            root: &sandbox_runtime::RootDisk,
        ) -> sandbox_runtime::EffectOutcome<ReconnectSandboxResponse> {
            self.inner.reconnect_sandbox_on_storage(request, root)
        }
        fn stop_sandbox(
            &self,
            request: &StopSandboxRequest,
        ) -> sandbox_runtime::EffectOutcome<StopSandboxResponse> {
            self.inner.stop_sandbox(request)
        }
        fn list_dir(&self, request: &ListDirRequest) -> Result<ListDirResponse, RuntimeError> {
            self.inner.list_dir(request)
        }
        fn stat_path(&self, request: &StatPathRequest) -> Result<EntryInfo, RuntimeError> {
            self.inner.stat_path(request)
        }
        fn mkdir(&self, request: &MkdirRequest) -> sandbox_runtime::EffectOutcome<MkdirResponse> {
            self.inner.mkdir(request)
        }
        fn remove_path(
            &self,
            request: &RemovePathRequest,
        ) -> sandbox_runtime::EffectOutcome<RemovePathResponse> {
            self.inner.remove_path(request)
        }
        fn move_path(
            &self,
            request: &MovePathRequest,
        ) -> sandbox_runtime::EffectOutcome<EntryInfo> {
            self.inner.move_path(request)
        }
        fn list_processes(
            &self,
            request: &ListProcessesRequest,
        ) -> Result<ListProcessesResponse, RuntimeError> {
            self.inner.list_processes(request)
        }
        fn signal_process(
            &self,
            request: &SignalProcessRequest,
        ) -> sandbox_runtime::EffectOutcome<sandbox_runtime::SignalOutcome> {
            self.inner.signal_process(request)
        }
        fn write_stdin(&self, request: &WriteStdinRequest) -> sandbox_runtime::EffectOutcome<()> {
            self.inner.write_stdin(request)
        }
        fn create_snapshot(
            &self,
            request: &SnapshotRequest,
        ) -> sandbox_runtime::EffectOutcome<SnapshotResponse> {
            self.inner.create_snapshot(request)
        }
        fn restore_snapshot(
            &self,
            request: &SnapshotRequest,
        ) -> sandbox_runtime::EffectOutcome<SnapshotResponse> {
            self.inner.restore_snapshot(request)
        }
        fn fork_sandbox(
            &self,
            request: &ForkSandboxRequest,
        ) -> sandbox_runtime::EffectOutcome<ForkSandboxResponse> {
            self.inner.fork_sandbox(request)
        }
        fn probe_sandbox(
            &self,
            request: &ProbeSandboxRequest,
        ) -> Result<sandbox_runtime::ProbeSandboxResponse, RuntimeError> {
            self.inner.probe_sandbox(request)
        }
    }
    fn dispatch(id: &str, kind: &str, generation: u64) -> OperationDispatch {
        const FP: &str = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let mut value = json!({"sandboxOwnerId":"owner", "operationId":id, "sandboxId":"sbx", "generation":generation, "attempt":1,
            "kind":kind, "lease": sandbox_protocol::HostLease { revision: generation, ..sandbox_protocol::HostLease::for_test() }, "idempotencyKey":id, "bodyHash":"a".repeat(64), "path":"/file", "argv":["true"],
            "templateDigest":FP, "incusFingerprint":FP,"architecture":"x86_64"});
        if matches!(kind, "sandbox.create" | "sandbox.reconnect") {
            value["cpuCount"] = json!(1);
            value["memoryMiB"] = json!(1024);
        }
        if matches!(
            kind,
            "sandbox.create" | "sandbox.reconnect" | "sandbox.stop" | "sandbox.kill"
        ) {
            value["allocation"] =
                serde_json::to_value(crate::sandbox_relay::test_support::allocation()).unwrap();
        }
        if sandbox_protocol::KEY_FREE_CLEANUP_KINDS.contains(&kind) {
            let fields = value.as_object_mut().unwrap();
            fields.remove("path");
            fields.remove("argv");
        }
        crate::sandbox_relay::test_support::current_fixture_dispatch(
            &serde_json::from_value(value).unwrap(),
        )
    }
    fn seed(fake: &FakeRuntime) {
        fake.create_fixture(&CreateSandboxRequest::for_test("sbx", "seed"))
            .unwrap();
    }
    fn admit(
        relay: &RelaySupervisor,
        journal: &HostJournal,
        binding: &TransportBindingV11,
        authority: &HostAuthority,
        d: OperationDispatch,
    ) {
        journal
            .record_fixture_intent(&intent_from_dispatch(journal, binding, &d))
            .unwrap();
        authority
            .accept_dispatch(
                &d.operation_id,
                &d.sandbox_id,
                &d.kind,
                d.generation,
                d.attempt,
            )
            .unwrap();
        let bytes = (d.kind == "file.put")
            .then(|| sandbox_runtime::FileContent::from_bytes(b"payload").unwrap());
        let instance_name = sandbox_runtime::default_incus_instance_name(&d.sandbox_id);
        relay.submit(d, instance_name, bytes).unwrap();
    }
    fn done(relay: &RelaySupervisor, id: &str) -> FinishedOp {
        done_with_output(relay, id).0
    }
    fn done_with_output(relay: &RelaySupervisor, id: &str) -> (FinishedOp, Vec<Frame>) {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut output = Vec::new();
        loop {
            for frame in relay.poll_output().expect("encode output") {
                relay.ack_output(
                    frame.metadata.operation_id.clone(),
                    frame.metadata.generation,
                    frame.metadata.attempt,
                    frame.metadata.sequence,
                    frame.metadata.offset.unwrap() + frame.body_len() as u64,
                );
                output.push(frame);
            }
            if let Some(result) = relay
                .poll_finished()
                .into_iter()
                .find(|r| r.operation_id == id)
            {
                return (result, output);
            }
            assert!(Instant::now() < deadline, "no completion for {id}");
            thread::sleep(Duration::from_millis(2));
        }
    }
    fn relay_fixture() -> (
        tempfile::TempDir,
        TransportBindingV11,
        Arc<HostJournal>,
        FakeRuntime,
        HostAuthority,
        RelaySupervisor,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let binding = TransportBindingV11 {
            server: "wss://example".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        };
        let journal = Arc::new(
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap(),
        );
        let fake = FakeRuntime::new();
        fake.fixture_root().unwrap();
        seed(&fake);
        let authority = HostAuthority::default();
        let relay = RelaySupervisor::start(
            Arc::new(fake.clone()),
            journal.clone(),
            authority.clone(),
            #[cfg(target_os = "linux")]
            None,
        );
        (dir, binding, journal, fake, authority, relay)
    }

    /// P10 (M4): work still queued (Intent) when the relay transport drops
    /// never starts an effect while detached; adoption releases it.
    #[test]
    fn m4_carried_intent_command_waits_at_the_effect_gate_until_adopted() {
        let (_dir, binding, journal, _fake, authority, relay) = relay_fixture();
        authority.attach(1);
        let d = dispatch("cmd", "command.run", 1);
        journal
            .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &d))
            .unwrap();
        authority
            .accept_dispatch("cmd", "sbx", "command.run", 1, 1)
            .unwrap();
        // Queued behind a busy pool when the transport drops: owned, Intent.
        std::mem::forget(authority.take_ownership("cmd", 1, 1).unwrap());
        authority.detach(Instant::now());
        relay
            .submit(d, sandbox_runtime::default_incus_instance_name("sbx"), None)
            .unwrap();
        thread::sleep(Duration::from_millis(400));
        assert!(
            relay.poll_finished().is_empty(),
            "nothing ran while detached"
        );
        assert_eq!(
            journal.lookup("cmd").unwrap().phase,
            super::super::journal::ReceiptPhase::Intent,
            "no Effect is recorded while detached"
        );
        authority.attach(2);
        thread::sleep(Duration::from_millis(100));
        assert_eq!(
            journal.lookup("cmd").unwrap().phase,
            super::super::journal::ReceiptPhase::Intent,
            "attach alone does not adopt"
        );
        assert!(authority.adopt("cmd", 1, 1, 2));
        assert_eq!(done(&relay, "cmd").state, OperationState::Succeeded);
    }

    /// Round 2 #1: a command that finished just before the drop, with output
    /// not yet published, stays owned by the publication path: it is carried,
    /// keeps its output window, and publishes every byte after adoption.
    #[test]
    fn finished_command_with_unpublished_output_is_carried_and_drains_after_adoption() {
        let (_dir, binding, journal, _fake, authority, relay) = relay_fixture();
        authority.attach(1);
        admit(
            &relay,
            &journal,
            &binding,
            &authority,
            dispatch("cmd", "command.run", 1),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while journal.lookup("cmd").unwrap().phase != super::super::journal::ReceiptPhase::Result {
            assert!(Instant::now() < deadline, "command never finished");
            thread::sleep(Duration::from_millis(5));
        }
        // The worker's iteration has ended; nothing was published yet.
        thread::sleep(Duration::from_millis(100));
        assert!(authority.owned("cmd", 1, 1), "publication still owns it");
        assert_eq!(
            authority.detach(Instant::now()),
            1,
            "carried, not forgotten"
        );
        assert!(relay.output_open("cmd", 1, 1));
        authority.attach(2);
        assert!(authority.adopt("cmd", 1, 1, 2));
        let (finished, output) = done_with_output(&relay, "cmd");
        assert_eq!(finished.state, OperationState::Succeeded);
        let published: u64 = output.iter().map(|f| f.body_len() as u64).sum();
        assert!(published > 0, "retained output is published after adoption");
        assert_eq!(
            finished
                .payload
                .as_ref()
                .and_then(|p| p["outputBytes"].as_u64()),
            Some(published),
            "every byte"
        );
    }

    /// P10/P9: a refused (revoked) carried Intent job is refused as a session
    /// closure before any effect; its persisted refusal is the late receipt.
    #[test]
    fn m4_revoked_carried_intent_work_never_issues() {
        let (_dir, binding, journal, fake, authority, relay) = relay_fixture();
        authority.attach(1);
        let d = dispatch("create", "sandbox.create", 3);
        let mut d = d;
        d.sandbox_id = "fresh".into();
        journal
            .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &d))
            .unwrap();
        authority
            .accept_dispatch("create", "fresh", "sandbox.create", 3, 1)
            .unwrap();
        std::mem::forget(authority.take_ownership("create", 3, 1).unwrap());
        authority.detach(Instant::now());
        relay
            .submit(
                d,
                sandbox_runtime::default_incus_instance_name("fresh"),
                None,
            )
            .unwrap();
        thread::sleep(Duration::from_millis(300));
        assert!(authority.revoke_carried("create").is_some());
        let finished = done(&relay, "create");
        assert_ne!(finished.state, OperationState::Succeeded);
        assert!(fake.query_sandbox("fresh", None, None).unwrap().is_none());
        let receipt = journal.lookup("create").unwrap();
        assert_eq!(receipt.phase, super::super::journal::ReceiptPhase::Result);
        assert!(authority.take_late("create", 3, 1), "owed a late receipt");
    }

    /// N1 (MUST-DO 1): a cancel accepted while an Intent command waits at
    /// the gate is honoured after adoption: the stream/cancel checks re-run
    /// after the wake, so no effect is issued.
    #[test]
    fn n1_cancel_while_waiting_at_the_gate_prevents_the_effect() {
        let (_dir, binding, journal, _fake, authority, relay) = relay_fixture();
        authority.attach(1);
        let d = dispatch("cmd", "command.run", 1);
        journal
            .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &d))
            .unwrap();
        authority
            .accept_dispatch("cmd", "sbx", "command.run", 1, 1)
            .unwrap();
        // Queued behind a busy pool when the transport drops: owned, Intent.
        std::mem::forget(authority.take_ownership("cmd", 1, 1).unwrap());
        authority.detach(Instant::now());
        relay
            .submit(d, sandbox_runtime::default_incus_instance_name("sbx"), None)
            .unwrap();
        thread::sleep(Duration::from_millis(300));
        // The cancel arrives while the job is parked at the gate.
        assert!(
            journal
                .request_cancel(&authority, "cmd", 1, 1)
                .unwrap()
                .is_ok()
        );
        authority.attach(2);
        assert!(authority.adopt("cmd", 1, 1, 2));
        let finished = done(&relay, "cmd");
        // `true` would have succeeded had the effect been issued.
        assert_eq!(
            finished.error.as_ref().map(|e| e.code.clone()),
            Some(SandboxErrorCode::Cancelled.into())
        );
        assert_ne!(finished.state, OperationState::Succeeded);
    }

    /// WP0: a versioned command that completed without its bound birth has
    /// no 1.0 payload. It is never reported SUCCEEDED (an unappliable
    /// receipt); the outcome is uncertain, with an unknown effect.
    #[test]
    fn versioned_command_success_without_birth_is_uncertain() {
        let mut d = dispatch("cmd-unborn", "command.run", 1);
        d.process_id = Some("proc-unborn".into());
        d.result_version = Some(1);
        let finished = finish_dispatch(
            &d,
            Ok(DispatchSuccess::ReadOnly((
                None,
                None,
                Some(OperationState::Succeeded),
            ))),
            Instant::now(),
        );
        assert_eq!(finished.state, OperationState::UnknownOutcome);
        assert_eq!(
            finished.error.as_ref().map(|e| e.code.clone()),
            Some(SandboxErrorCode::UnknownOutcome.into())
        );
        let result = finished.payload.unwrap();
        assert_eq!(result["payload"], json!(null));
        assert_eq!(result["failure"]["effect"], "unknown");
        assert_eq!(result["failure"]["resource"], "command");
    }

    /// WP3 (D2/D3): only a proven stop of a carry-expired command becomes
    /// FAILED `host_disconnect_expired`; a typed result stays a valid
    /// journal receipt across a reload. A wire cancel stays CANCELLED and a
    /// natural ending keeps its code.
    #[test]
    fn carry_expired_proven_stop_settles_host_disconnect_expired() {
        let (dir, binding, journal, _fake, _authority, relay) = relay_fixture();
        let finished = |d: &OperationDispatch, state| {
            let mut op = FinishedOp {
                operation_id: d.operation_id.clone(),
                sandbox_id: d.sandbox_id.clone(),
                generation: d.generation,
                attempt: d.attempt,
                state,
                payload: Some(json!({"exitCode": null, "pid": null})),
                error: None,
                download: None,
                interim: false,
                readiness_detail: None,
                owner: None,
            };
            if d.result_version == Some(1) {
                op.payload = None;
                wrap_typed_result(d, &mut op, None);
            }
            op
        };
        for (id, typed, reason, state, expected) in [
            (
                "carry",
                false,
                true,
                OperationState::Cancelled,
                OperationState::Failed,
            ),
            (
                "typed",
                true,
                true,
                OperationState::Cancelled,
                OperationState::Failed,
            ),
            (
                "wire",
                false,
                false,
                OperationState::Cancelled,
                OperationState::Cancelled,
            ),
            (
                "raced",
                false,
                true,
                OperationState::Succeeded,
                OperationState::Succeeded,
            ),
            (
                "unproven",
                false,
                true,
                OperationState::UnknownOutcome,
                OperationState::UnknownOutcome,
            ),
        ] {
            let mut d = dispatch(id, "command.run", 1);
            if typed {
                d.result_version = Some(1);
            }
            journal
                .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &d))
                .unwrap();
            journal
                .record_cancel_for(
                    id,
                    1,
                    1,
                    reason.then_some(super::super::journal::CancelReason::CarryExpired),
                )
                .unwrap();
            let settled = settle_carry_expired(&journal, &d, finished(&d, state));
            assert_eq!(settled.state, expected, "{id}");
            let carry_code = settled
                .error
                .as_ref()
                .is_some_and(|e| e.code.is(SandboxErrorCode::HostDisconnectExpired));
            assert_eq!(carry_code, expected == OperationState::Failed, "{id}");
            if typed {
                assert_eq!(
                    settled.payload.as_ref().unwrap()["failure"],
                    json!({"resource": "command", "effect": "partial"})
                );
            }
            if state != OperationState::UnknownOutcome {
                let persisted = persist_finished(&journal, settled);
                assert_eq!(persisted.state, expected, "{id}");
            }
        }
        drop(relay);
        drop(journal);
        let reopened =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap();
        let typed = reopened.lookup("typed").expect("typed receipt reloads");
        assert_eq!(typed.state, OperationState::Failed);
        assert!(
            typed
                .error_code
                .as_ref()
                .is_some_and(|code| code.is(SandboxErrorCode::HostDisconnectExpired))
        );
    }

    #[test]
    fn every_b3_typed_payload_round_trips_through_b1_result_body() {
        use sandbox_protocol::results::ResultBody;
        let mut d = dispatch("cmd", "command.run", 1);
        d.process_id = Some("proc".into());
        let birth = sandbox_runtime::CommandBirth {
            pid: 4242,
            boot_id: "00000000-0000-4000-8000-000000000000".into(),
            start_ticks: 1,
            started_at_ms: 1000,
        };
        let process = process_ref(&d.sandbox_id, 1, 1, "proc", &birth).unwrap();
        for signal in [
            ProcessSignal::Sigterm,
            ProcessSignal::Sigint,
            ProcessSignal::Sighup,
        ] {
            let value = signal_result(
                &process,
                "cmd",
                signal,
                sandbox_runtime::SignalOutcome::ProcessGroup,
            )
            .unwrap();
            let parsed: ResultBody = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(serde_json::to_value(parsed).unwrap(), value);
        }
        assert!(
            signal_result(
                &process,
                "cmd",
                ProcessSignal::Sigkill,
                sandbox_runtime::SignalOutcome::CancelRequested
            )
            .is_none()
        );
        for exit_code in [None, Some(0), Some(143)] {
            let response = sandbox_runtime::RunCommandResponse {
                command: sandbox_runtime::CommandRecord {
                    operation_id: "cmd".into(),
                    idempotency_key: "cmd".into(),
                    state: OperationState::Succeeded,
                    exit_code,
                    guest_pid: Some(4242),
                    birth: Some(birth.clone()),
                    chunks: Vec::new(),
                },
            };
            let value = command_result_for(&d, &response).unwrap();
            let parsed: ResultBody = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(serde_json::to_value(parsed).unwrap(), value);
            let mut unstarted = response;
            unstarted.command.birth = None;
            assert!(command_result_for(&d, &unstarted).is_none());
        }
    }

    #[test]
    fn start_observation_is_published_once_and_final_results_repeat_identity() {
        let _staging = crate::sandbox_relay::test_support::staging_quota();
        let (_dir, binding, journal, _fake, authority, relay) = relay_fixture();
        let mut started_dispatch = dispatch("cmd-105", "command.run", 1);
        started_dispatch.process_id = Some("proc-1".into());
        started_dispatch.result_version = Some(1);
        admit(&relay, &journal, &binding, &authority, started_dispatch);
        let deadline = Instant::now() + Duration::from_secs(5);
        let started = loop {
            if let Some(started) = relay.poll_started().into_iter().next() {
                break started;
            }
            assert!(Instant::now() < deadline, "no start observation");
            thread::sleep(Duration::from_millis(2));
        };
        assert!(started.validate());
        assert_eq!(
            (
                started.operation_id.as_str(),
                started.process_id.as_str(),
                started.sandbox_id.as_str()
            ),
            ("cmd-105", "proc-1", "sbx")
        );
        let wire = sandbox_protocol::WireCodes::negotiated("1.0")
            .encode(
                &sandbox_protocol::DaemonControlMessage::from(started.clone()),
                None,
            )
            .unwrap()
            .text;
        assert!(!wire.contains("WSSP") && !wire.contains("nonce"), "{wire}");
        assert!(relay.poll_started().is_empty(), "published at most once");
        let result = done(&relay, "cmd-105");
        let payload = result.payload.unwrap()["payload"].clone();
        let parsed: sandbox_protocol::results::ResultBody =
            serde_json::from_value(payload.clone()).unwrap();
        assert!(matches!(
            parsed,
            sandbox_protocol::results::ResultBody::Command { .. }
        ));
        assert_eq!(serde_json::to_value(parsed).unwrap(), payload);
        assert_eq!(payload["process"]["processId"], "proc-1");
        assert_eq!(payload["process"]["pid"], started.pid);
        assert_eq!(payload["startedAt"], started.started_at);
    }

    #[test]
    fn rich_command_receipt_retains_encoded_birth_and_strict_payload() {
        let _staging = crate::sandbox_relay::test_support::staging_quota();
        let (_dir, binding, journal, _fake, authority, relay) = relay_fixture();
        let mut d = dispatch("cmd-rich", "command.run", 1);
        d.process_id = Some("proc-rich".into());
        d.result_version = Some(1);
        admit(&relay, &journal, &binding, &authority, d);
        let result = done(&relay, "cmd-rich");
        assert_eq!(result.state, OperationState::Succeeded);
        let value = result.payload.unwrap();
        let typed: sandbox_protocol::results::host::HostOperationResult =
            serde_json::from_value(value.clone()).unwrap();
        assert!(typed.validate(sandbox_protocol::results::ResultKind::RunCommand, "sbx", 1));
        assert_eq!(typed.birth.as_ref().unwrap().process_id, "proc-rich");
        assert!(typed.output_bytes.is_some());
        assert!(value["payload"].get("outputBytes").is_none());
        assert!(value["payload"].get("birth").is_none());
        assert_eq!(journal.lookup("cmd-rich").unwrap().result, Some(value));
    }

    #[test]
    fn absent_cleanup_execution_matches_server_result_fixtures() {
        let _staging = crate::sandbox_relay::test_support::staging_quota();
        let cases: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../../../../crates/sandbox-protocol/fixtures/control_absent_cleanup_results.json"
        ))
        .unwrap();
        for case in cases {
            let dir = tempfile::tempdir().unwrap();
            let binding = TransportBindingV11 {
                server: "wss://example".into(),
                host_owner_id: "owner".into(),
                host_id: "host".into(),
            };
            let journal = Arc::new(
                crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap(),
            );
            let fake = FakeRuntime::new();
            fake.fixture_root().unwrap();
            let authority = HostAuthority::default();
            let relay = RelaySupervisor::start(
                Arc::new(fake.clone()),
                journal.clone(),
                authority.clone(),
                #[cfg(target_os = "linux")]
                None,
            );
            let kind = case["kind"].as_str().unwrap();
            admit(
                &relay,
                &journal,
                &binding,
                &authority,
                dispatch("op", kind, 1),
            );
            let result = done(&relay, "op");
            assert!(result.error.is_none());
            let frame = sandbox_protocol::DaemonControlMessage::OperationResult {
                id: "result-op".into(),
                operation_id: result.operation_id,
                sandbox_id: result.sandbox_id,
                generation: result.generation,
                attempt: result.attempt,
                state: result.state,
                result: result.payload.clone(),
                error: None,
            };
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(
                    &sandbox_protocol::WireCodes::negotiated("1.0")
                        .encode(&frame, None)
                        .unwrap()
                        .text
                )
                .unwrap(),
                case["frame"]
            );
            assert_eq!(journal.lookup("op").unwrap().result, result.payload);
            assert_eq!(fake.query_sandbox("sbx", None, None).unwrap(), None);
        }
    }

    #[test]
    fn real_cancel_and_teardown_execute_while_ordinary_runtime_is_inside_io() {
        let _staging = crate::sandbox_relay::test_support::staging_quota();
        for (kind, teardown) in [
            ("command.run", "sandbox.stop"),
            ("sandbox.create", "sandbox.stop"),
            ("sandbox.create", "sandbox.kill"),
            ("file.put", "sandbox.stop"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let binding = TransportBindingV11 {
                server: "wss://example".into(),
                host_owner_id: "owner".into(),
                host_id: "host".into(),
            };
            let journal = Arc::new(
                crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap(),
            );
            let fake = FakeRuntime::with_command_delay(Duration::from_millis(1200));
            fake.fixture_root().unwrap();
            if kind != "sandbox.create" {
                seed(&fake);
            }
            let (entered_tx, entered_rx) = mpsc::sync_channel(1);
            let (release_tx, release_rx) = mpsc::channel();
            let (cancel_tx, cancel_rx) = mpsc::channel();
            let runtime: Arc<dyn SandboxRuntime> = Arc::new(GatedRuntime {
                inner: Arc::new(fake),
                kind,
                entered: entered_tx,
                release: Arc::new(Mutex::new(release_rx)),
                cancelled: cancel_tx,
                timeout: false,
                permit: None,
                command_hook: None,
            });
            let authority = HostAuthority::default();
            let relay = RelaySupervisor::start(
                runtime.clone(),
                journal.clone(),
                authority.clone(),
                #[cfg(target_os = "linux")]
                None,
            );
            admit(
                &relay,
                &journal,
                &binding,
                &authority,
                dispatch("slow", kind, 1),
            );
            entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            if kind == "command.run" {
                authority.accept_cancel("slow", 1, 1).unwrap();
                journal.record_cancel("slow", 1, 1).unwrap();
                let control_runtime = runtime.clone();
                relay
                    .control(move || {
                        control_runtime.cancel_operation("slow").unwrap();
                    })
                    .unwrap();
                cancel_rx
                    .recv_timeout(Duration::from_millis(250))
                    .expect("real runtime cancel blocked by ordinary IO");
            }
            // Stop (and expiry uses this same kind) must finish before the ordinary IO barrier is released.
            admit(
                &relay,
                &journal,
                &binding,
                &authority,
                dispatch("stop", teardown, 2),
            );
            assert_eq!(done(&relay, "stop").state, OperationState::Succeeded);
            assert_eq!(
                runtime.query_sandbox("sbx", None, None).unwrap(),
                if teardown == "sandbox.kill" {
                    None
                } else {
                    Some(sandbox_protocol::SandboxLifecycleState::Stopped)
                }
            );
            if kind != "sandbox.create" {
                release_tx.send(()).unwrap();
                assert_eq!(done(&relay, "slow").state, OperationState::UnknownOutcome);
            } else {
                assert_eq!(
                    journal.lookup("slow").unwrap().state,
                    OperationState::UnknownOutcome
                );
            }
        }
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn effect_then_timeout_stays_unknown_and_lifecycle_inventory_resolves() {
        let _staging = crate::sandbox_relay::test_support::staging_quota();
        for kind in ["sandbox.create", "file.put"] {
            for found in [true, false] {
                let dir = tempfile::tempdir().unwrap();
                let binding = TransportBindingV11 {
                    server: "wss://example".into(),
                    host_owner_id: "owner".into(),
                    host_id: "host".into(),
                };
                let journal = Arc::new(
                    crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap(),
                );
                let fake = FakeRuntime::new();
                fake.fixture_root().unwrap();
                if kind == "file.put" {
                    seed(&fake);
                }
                let (entered, entered_rx) = mpsc::sync_channel(1);
                let (release_tx, release) = mpsc::channel();
                let (cancelled, _) = mpsc::channel();
                let runtime: Arc<dyn SandboxRuntime> = Arc::new(GatedRuntime {
                    inner: Arc::new(fake),
                    kind,
                    entered,
                    release: Arc::new(Mutex::new(release)),
                    cancelled,
                    timeout: true,
                    permit: None,
                    command_hook: None,
                });
                let authority = HostAuthority::default();
                let relay = RelaySupervisor::start(
                    runtime.clone(),
                    journal.clone(),
                    authority.clone(),
                    #[cfg(target_os = "linux")]
                    None,
                );
                admit(
                    &relay,
                    &journal,
                    &binding,
                    &authority,
                    dispatch("effect", kind, 1),
                );
                entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                release_tx.send(()).unwrap();
                assert_eq!(done(&relay, "effect").state, OperationState::UnknownOutcome);
                assert_eq!(
                    journal.lookup("effect").unwrap().phase,
                    super::super::journal::ReceiptPhase::Effect
                );
                drop(relay);
                drop(journal);
                if !found {
                    runtime
                        .kill_fixture(&KillSandboxRequest {
                            template_fingerprint: sandbox_runtime::CreateSandboxRequest::for_test(
                                "sbx", "key",
                            )
                            .template_digest,
                            sandbox_id: "sbx".into(),
                            instance_name: "wssp-sbx-sbx".into(),
                            operation_id: "kill".into(),
                            idempotency_key: "kill".into(),
                        })
                        .unwrap();
                }
                let journal =
                    crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap();
                let resolved = super::super::reconcile::resolve_receipt(
                    &journal,
                    runtime.as_ref(),
                    journal.lookup("effect").unwrap(),
                )
                .unwrap();
                assert_eq!(
                    resolved.state,
                    if kind == "file.put" {
                        OperationState::UnknownOutcome
                    } else if found {
                        OperationState::Succeeded
                    } else {
                        OperationState::UnknownOutcome
                    }
                );
            }
        }
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn both_command_consumers_retain_unknown_raw_output_and_spawn_proofs() {
        for supervised in [false, true] {
            for mode in [
                "missing_exit",
                "no_pid",
                "spawn_failure",
                "overlap_exit",
                "overlap_setup",
            ] {
                let dir = tempfile::tempdir().unwrap();
                let shim = dir.path().join("incus");
                crate::sandbox_relay::test_support::install_executable(
                    &shim,
                    r#"#!/bin/sh
root=$(dirname "$0")
[ "$1" = "--project" ] && shift 2
case "$1" in
 version) exit 0 ;;
 profile) echo '[{"name":"default","devices":{"root":{"type":"disk","path":"/","pool":"default"},"eth0":{"type":"nic","network":"incusbr0"}}}]'; exit 0 ;;
 query) echo '{"type":"sync","metadata":{"status":"Running","status_code":103,"type":"virtual-machine","config":{"user.flycockpit.sandbox_id":"sbx","user.flycockpit.template_digest":"sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789","volatile.base_image":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"}}}'; exit 0 ;;
 exec)
   while [ "$1" != "--" ]; do shift; done
   shift
   # Simulate the guest scope; preserve the inner helper/command argv.
   if [ "${1:-}" = /usr/bin/systemd-run ]; then
     [ "${2:-}" = --scope ] && [ "${3:-}" = --quiet ] && [ "${4:-}" = --collect ] &&
       [ "${5:-}" = --no-ask-password ] && [ "${6:-}" = --description=wssp-command ] &&
       [ "${7:-}" = --property=OOMPolicy=continue ] && [ "${8:-}" = --expand-environment=no ] &&
       [ "${10:-}" = --slice=wssp.slice ] && [ "${11:-}" = -- ] || exit 1
     case "${9:-}" in --unit=wssp-cmd-*.scope) ;; *) exit 1 ;; esac
     shift 11
   fi
   # The launcher: python3 -I -S -c <helper> <unit> <uid> <gid> <command...>.
   if [ "${2:-}" = -I ] && [ "${3:-}" = -S ] && [ "${4:-}" = -c ]; then shift 8; fi
   script=$5
   rest=${script#*WSSP_EXIT }
   nonce=${rest%% *}
   mode=$(cat "$root/mode")
   case "$mode" in
     no_pid) printf 'partial-no-pid' ;;
     overlap_exit) printf 'WSSP_PID %s 4242\nWSSP_EXIT %s 37\n' "$nonce" "$nonce" ;;
     overlap_setup) printf 'WSSP_PID %s 4242\nWSSP_SETUP_FAILED %s 37\n' "$nonce" "$nonce" ;;
     *) printf 'WSSP_PID %s 4242\npartial' "$nonce" ;;
   esac > "$root/raw"
   printf 'stdout-before-loss'
   cat "$root/raw" >&2
   exit 0 ;;
esac
exit 1
"#,
                    0o700,
                );
                std::fs::write(dir.path().join("mode"), mode).unwrap();
                let runtime = IncusKvmRuntime::new(IncusConfig {
                    binary: shim.to_string_lossy().into_owned(),
                    project: "default".into(),
                })
                .unwrap();
                let exec = supervised.then(|| runtime.exec_supervisor());
                if mode == "spawn_failure" {
                    std::fs::remove_file(&shim).unwrap();
                }
                let binding = TransportBindingV11 {
                    server: "wss://example".into(),
                    host_owner_id: "owner".into(),
                    host_id: "host".into(),
                };
                let journal = Arc::new(
                    crate::sandbox_relay::test_support::open_journal(
                        dir.path().join("journal"),
                        &binding,
                    )
                    .unwrap(),
                );
                let authority = HostAuthority::default();
                let relay = RelaySupervisor::start(
                    Arc::new(runtime),
                    journal.clone(),
                    authority.clone(),
                    exec,
                );
                admit(
                    &relay,
                    &journal,
                    &binding,
                    &authority,
                    dispatch("command", "command.run", 1),
                );
                let (finished, output) = done_with_output(&relay, "command");
                if mode == "spawn_failure" {
                    assert_eq!(finished.state, OperationState::Failed);
                    assert_eq!(
                        finished.error.unwrap().code,
                        SandboxErrorCode::HostEffectNotIssued
                    );
                } else {
                    assert_eq!(
                        finished.state,
                        OperationState::UnknownOutcome,
                        "exec={supervised}, {mode}"
                    );
                    let payload = finished.payload.unwrap();
                    assert!(payload.get("stdout").is_none());
                    let stdout: Vec<_> = output
                        .iter()
                        .filter(|f| f.metadata.flags.as_ref().unwrap().stdout == Some(true))
                        .flat_map(|f| f.body().to_vec())
                        .collect();
                    assert_eq!(stdout, b"stdout-before-loss");
                    let stderr: Vec<_> = output
                        .iter()
                        .filter(|f| f.metadata.flags.as_ref().unwrap().stderr == Some(true))
                        .flat_map(|f| f.body().to_vec())
                        .collect();
                    let raw = std::fs::read(dir.path().join("raw")).unwrap();
                    // Live output strips a valid private PID banner; terminal certainty still uses raw evidence.
                    let expected_stderr = if mode == "no_pid" {
                        raw.as_slice()
                    } else {
                        &raw[raw.iter().position(|b| *b == b'\n').unwrap() + 1..]
                    };
                    assert_eq!(stderr, expected_stderr, "all user stderr survives {mode}");
                    assert_eq!(payload["outputBytes"], stdout.len() + stderr.len());
                }
                drop(relay);
                drop(journal);
                let journal = crate::sandbox_relay::test_support::open_journal(
                    dir.path().join("journal"),
                    &binding,
                )
                .unwrap();
                assert_eq!(
                    journal.lookup("command").unwrap().phase,
                    if mode == "spawn_failure" {
                        super::super::journal::ReceiptPhase::Result
                    } else {
                        super::super::journal::ReceiptPhase::Effect
                    }
                );
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn env_frame_refusal_retains_uncertain_effect_receipt_until_evidence() {
        for supervised in [false, true] {
            for mode in ["refuse", "late"] {
                let dir = tempfile::tempdir().unwrap();
                let root = dir.path();
                let shim = root.join("incus");
                crate::sandbox_relay::test_support::install_executable(
                    &shim,
                    r#"#!/bin/sh
root=$(dirname "$0")
[ "$1" = "--project" ] && shift 2
case "$1" in
 version) exit 0 ;;
 profile) echo '[{"name":"default","devices":{"root":{"type":"disk","path":"/","pool":"default"},"eth0":{"type":"nic","network":"incusbr0"}}}]'; exit 0 ;;
 query) echo '{"type":"sync","metadata":{"status":"Running","status_code":103,"type":"virtual-machine","config":{"user.flycockpit.sandbox_id":"sbx","user.flycockpit.template_digest":"sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789","volatile.base_image":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"}}}'; exit 0 ;;
 exec)
   while [ "$1" != "--" ]; do shift; done
   shift
   case "$1" in
     /bin/sh) exec "$@" ;;
     *) exec /usr/bin/python3 "$root/transport.py" "$@" ;;
   esac ;;
esac
exit 1
"#,
                    0o700,
                );
                std::fs::write(
                    root.join("transport.py"),
                    include_str!("../../../../crates/sandbox-runtime/fixtures/env-transport.py"),
                )
                .unwrap();
                std::fs::write(root.join("transport-mode"), mode).unwrap();
                let payload = br#"{"HOME":"invalid-stored-default"}"#;
                let mut frame = b"WSSPENV\0\x01".to_vec();
                frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
                frame.extend_from_slice(payload);
                std::fs::write(root.join("invalid-frame"), frame).unwrap();
                let runtime = IncusKvmRuntime::new(IncusConfig {
                    binary: shim.to_string_lossy().into_owned(),
                    project: "default".into(),
                })
                .unwrap();
                let exec = runtime.exec_supervisor();
                let binding = TransportBindingV11 {
                    server: "wss://example".into(),
                    host_owner_id: "owner".into(),
                    host_id: "host".into(),
                };
                let journal = Arc::new(
                    crate::sandbox_relay::test_support::open_journal(
                        root.join("journal"),
                        &binding,
                    )
                    .unwrap(),
                );
                let authority = HostAuthority::default();
                let relay = RelaySupervisor::start(
                    Arc::new(runtime),
                    journal.clone(),
                    authority.clone(),
                    supervised.then(|| exec.clone()),
                );
                let mut command = dispatch("command", "command.run", 1);
                command.env = Some(vec![("APP".into(), "private-env-canary".into())]);
                command.argv = Some(vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    format!("printf ran > '{}'", root.join("target-ran").display()),
                ]);
                if mode == "late" {
                    // Generic direct-run also has its original user pipe only
                    // when stdin was queued before admission.
                    exec.write_stdin(&WriteStdinRequest {
                        operation_id: "command".into(),
                        generation: 1,
                        attempt: 1,
                        bytes: vec![255; 1024 * 1024],
                        eof: true,
                    })
                    .unwrap();
                }
                admit(&relay, &journal, &binding, &authority, command);
                if mode == "late" {
                    let deadline = Instant::now() + Duration::from_secs(5);
                    while !root.join("proof-finished").exists() {
                        assert!(Instant::now() < deadline);
                        thread::sleep(Duration::from_millis(2));
                    }
                    std::fs::write(root.join("close-stdin"), "").unwrap();
                }
                let result = done(&relay, "command");
                assert!(!root.join("target-ran").exists());
                if mode == "late" {
                    assert_eq!(result.state, OperationState::UnknownOutcome);
                    assert_eq!(result.error.unwrap().code, SandboxErrorCode::UnknownOutcome);
                    // An unresolved effect remains journaled/charged; no failed
                    // result or implicit retry can release its sandbox slot.
                    assert_eq!(
                        journal.lookup("command").unwrap().phase,
                        super::super::journal::ReceiptPhase::Effect
                    );
                } else {
                    assert_eq!(result.state, OperationState::Failed);
                    assert_eq!(
                        result.error.unwrap().code,
                        SandboxErrorCode::HostEffectNotIssued
                    );
                    assert_eq!(
                        journal.lookup("command").unwrap().phase,
                        super::super::journal::ReceiptPhase::Result
                    );
                }
            }
        }
    }

    /// E-21 redaction: every dispatched operation logs a start and a finish
    /// line (kind, operation id, outcome, duration) through the real worker
    /// path, and no request content reaches the log: not argv, script, env
    /// names or values, cwd, guest paths, file bytes, credentials, or a
    /// non-lifecycle error message (which names the guest path). Both the
    /// text and JSON production formats are checked.
    #[test]
    fn operation_logs_carry_ids_and_outcomes_but_no_request_content() {
        const FP: &str = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        const SECRETS: [&str; 9] = [
            "ARGV-SECRET-7d1",
            "SCRIPT-SECRET-4c2",
            "ENV_NAME_SECRET_9a",
            "ENV-VALUE-SECRET-3e",
            "wssp_host_",
            "/home/user/cwd-secret-5b",
            "/home/user/put-secret-8f.txt",
            "/home/user/missing-secret-2d",
            "FILE-BYTES-SECRET-6a",
        ];
        for format in [crate::cli::LogFormat::Text, crate::cli::LogFormat::Json] {
            let (states, captured) = crate::logging::with_subscriber(
                format,
                tracing_subscriber::EnvFilter::new("trace"),
                || {
                    let _staging = crate::sandbox_relay::test_support::staging_quota();
                    let dir = tempfile::tempdir().unwrap();
                    let binding = TransportBindingV11 {
                        server: "wss://example".into(),
                        host_owner_id: "owner".into(),
                        host_id: "host".into(),
                    };
                    let journal = Arc::new(
                        crate::sandbox_relay::test_support::open_journal(dir.path(), &binding)
                            .unwrap(),
                    );
                    let fake = FakeRuntime::new();
                    fake.fixture_root().unwrap();
                    seed(&fake);
                    let runtime: Arc<dyn SandboxRuntime> = Arc::new(fake);
                    let authority = HostAuthority::default();
                    let relay = RelaySupervisor::start(
                        runtime,
                        journal.clone(),
                        authority.clone(),
                        #[cfg(target_os = "linux")]
                        None,
                    );
                    let token = format!("wssp_host_{}", "Z".repeat(43));
                    let ops = [
                        json!({"operationId":"op-run", "kind":"command.run",
                            "argv":["echo", SECRETS[0]],
                            "env":[[SECRETS[2], SECRETS[3]], ["TOKEN", token]],
                            "cwd": SECRETS[5]}),
                        json!({"operationId":"op-script", "kind":"command.run",
                            "script": format!("echo {}", SECRETS[1])}),
                        json!({"operationId":"op-put", "kind":"file.put", "path": SECRETS[6],
                            "fileSize": SECRETS[8].len()}),
                        json!({"operationId":"op-get", "kind":"file.get", "path": SECRETS[7]}),
                    ];
                    let mut states = Vec::new();
                    for op in ops {
                        let mut value = json!({"sandboxOwnerId":"owner", "sandboxId":"sbx", "generation":1, "attempt":1,
                            "idempotencyKey":"k", "bodyHash":"a".repeat(64),
                            "templateDigest":FP, "incusFingerprint":FP, "architecture":"x86_64"});
                        for (key, field) in op.as_object().unwrap() {
                            value[key] = field.clone();
                        }
                        value["idempotencyKey"] = value["operationId"].clone();
                        let d: OperationDispatch = serde_json::from_value(value).unwrap();
                        journal
                            .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &d))
                            .unwrap();
                        authority
                            .accept_dispatch(&d.operation_id, "sbx", &d.kind, 1, 1)
                            .unwrap();
                        let id = d.operation_id.clone();
                        let upload = (d.kind == "file.put").then(|| {
                            sandbox_runtime::FileContent::from_bytes(SECRETS[8].as_bytes()).unwrap()
                        });
                        relay.submit(d, "wssp-sbx-sbx".into(), upload).unwrap();
                        states.push((id.clone(), done(&relay, &id).state));
                    }
                    drop(relay);
                    states
                },
            );
            let text = String::from_utf8_lossy(&captured).to_string();
            assert_eq!(
                states,
                vec![
                    ("op-run".to_string(), OperationState::Succeeded),
                    ("op-script".to_string(), OperationState::Succeeded),
                    ("op-put".to_string(), OperationState::Succeeded),
                    ("op-get".to_string(), OperationState::Failed),
                ],
                "{text}"
            );
            for id in ["op-run", "op-script", "op-put", "op-get"] {
                let lines: Vec<&str> = text.lines().filter(|l| l.contains(id)).collect();
                assert!(
                    lines.iter().any(|l| l.contains("host operation started")),
                    "{id} start: {text}"
                );
                assert!(
                    lines.iter().any(|l| l.contains("duration_ms")
                        && l.contains("outcome")
                        && l.contains("kind")),
                    "{id} finish: {text}"
                );
            }
            // Exact code token: the host log keeps the precise internal code
            // (B2-K-1); only peer frames are respelled for their session.
            let code = match format {
                crate::cli::LogFormat::Text => "code=fs_not_found",
                crate::cli::LogFormat::Json => "\"code\":\"fs_not_found\"",
            };
            assert!(
                text.lines().any(|l| l.contains("op-get")
                    && l.contains("WARN")
                    && l.split([' ', ',', '{', '}']).any(|token| token == code)),
                "a non-lifecycle failure is a WARN with its exact code: {text}"
            );
            for secret in SECRETS {
                assert!(
                    !text.contains(secret),
                    "{secret} leaked into the log:\n{text}"
                );
            }
            assert!(
                !text.contains("[REDACTED]"),
                "nothing needed redaction: {text}"
            );
        }
    }

    /// HR-R6: a lifecycle refusal before any effect is a WARN, not an ERROR;
    /// a definite lifecycle failure after issue stays an ERROR. Both keep
    /// the constant typed runtime code (E-11).
    #[test]
    fn lifecycle_refusals_are_warnings_and_issued_failures_are_errors() {
        let finished = |code| FinishedOp {
            operation_id: "op-life".into(),
            sandbox_id: "sbx".into(),
            generation: 1,
            attempt: 1,
            state: OperationState::Failed,
            payload: None,
            error: Some(DispatchError {
                reason: None,
                code,
                message: "host is at its live sandbox limit".into(),
            }),
            download: None,
            interim: false,
            readiness_detail: None,
            owner: None,
        };
        for (not_issued, level, other) in [(true, "WARN", "ERROR"), (false, "ERROR", "WARN")] {
            let ((), captured) = crate::logging::with_subscriber(
                crate::cli::LogFormat::Text,
                tracing_subscriber::EnvFilter::new("trace"),
                || {
                    log_operation_finished(
                        "sandbox.create",
                        &finished(SandboxErrorCode::HostCapacity.into()),
                        not_issued,
                        Duration::from_millis(7),
                    )
                },
            );
            let text = String::from_utf8_lossy(&captured).to_string();
            assert!(text.contains(level), "{text}");
            assert!(!text.contains(other), "{text}");
            assert!(text.contains("host_capacity"), "{text}");
            assert!(text.contains("duration_ms=7"), "{text}");
            let outcome = if not_issued {
                "outcome=\"refused\""
            } else {
                "outcome=\"failed\""
            };
            assert!(text.contains(outcome), "{text}");
        }
    }

    #[test]
    fn sensitive_runtime_stdin_errors_are_constant_before_receipts_and_logs() {
        const SENTINEL: &str = "synthetic-env-stdin-supervisor-3a";
        const ENCODED: &str = "c3ludGhldGljLWVudi1zdGRpbi1zdXBlcnZpc29yLTNh";
        let detail = format!("{SENTINEL} {ENCODED}");
        let mapped = runtime_err(RuntimeError::new(
            SandboxErrorCode::GuestOperationFailed,
            &detail,
        ));
        assert_eq!(mapped.message, "guest_operation_failed");
        for rejected in [true, false] {
            let result = if rejected {
                Err(DispatchFailure::Rejected(DispatchError {
                    reason: None,
                    code: SandboxErrorCode::GuestOperationFailed.into(),
                    message: detail.clone(),
                }))
            } else {
                Err(DispatchFailure::Effect(EffectError::from(
                    RuntimeError::new(SandboxErrorCode::GuestOperationFailed, &detail),
                )))
            };
            let finished = finish_bound("op", "sbx", 1, 1, result);
            assert_eq!(
                finished.state,
                if rejected {
                    OperationState::Failed
                } else {
                    OperationState::UnknownOutcome
                }
            );
            assert_eq!(finished.error.unwrap().message, "guest_operation_failed");
        }
        let dir = tempfile::tempdir().unwrap();
        let binding = TransportBindingV11 {
            server: "wss://example".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        };
        let journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap();
        let d = dispatch("op", "command.run", 1);
        journal
            .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &d))
            .unwrap();
        let raw = FinishedOp {
            operation_id: "op".into(),
            sandbox_id: "sbx".into(),
            generation: 1,
            attempt: 1,
            state: OperationState::Failed,
            payload: None,
            error: Some(DispatchError {
                reason: None,
                code: SandboxErrorCode::GuestOperationFailed.into(),
                message: detail.clone(),
            }),
            download: None,
            interim: false,
            readiness_detail: None,
            owner: None,
        };
        // Exercise the public stdin/result arbitration boundary with an unsanitized
        // producer, not just the ordinary worker completion path.
        let persisted = persist_finished(&journal, raw.clone());
        assert_eq!(persisted.error.unwrap().message, "guest_operation_failed");
        let receipt = serde_json::to_string(&journal.lookup("op").unwrap()).unwrap();
        assert!(!receipt.contains(SENTINEL));
        assert!(!receipt.contains(ENCODED));
        for format in [crate::cli::LogFormat::Text, crate::cli::LogFormat::Json] {
            let (_, captured) = crate::logging::with_subscriber(
                format,
                tracing_subscriber::EnvFilter::new("trace"),
                || {
                    // A raw producer bypass still cannot reach automatic lifecycle logs.
                    log_operation_finished("sandbox.create", &raw, false, Duration::from_millis(1));
                },
            );
            let text = String::from_utf8_lossy(&captured);
            assert!(text.contains("guest_operation_failed"));
            assert!(!text.contains(SENTINEL));
            assert!(!text.contains(ENCODED));
        }
    }

    /// A `vm_not_running` readiness failure keeps its typed host facts (path,
    /// Incus status, time since last seen Running) through `finish_bound` to
    /// the lifecycle log line, while the message stays reduced to its code
    /// and nothing of it reaches the line.
    #[test]
    fn a_vm_not_running_failure_logs_its_host_facts_and_never_its_message() {
        const SENTINEL: &str = "synthetic-readiness-message-u2604";
        let detail = sandbox_runtime::NotRunningDetail::new(
            "validate_pass",
            Some(("Er ror\n<x>", 112)),
            Some(Duration::from_millis(40)),
        );
        let error = RuntimeError::new(SandboxErrorCode::GuestUnavailable, SENTINEL)
            .with_not_running_detail(Some(detail));
        let finished = finish_bound(
            "op-vm",
            "sbx",
            1,
            1,
            Err(DispatchFailure::Effect(EffectError::from(error))),
        );
        assert_eq!(
            finished.error.as_ref().unwrap().message,
            "guest_unavailable"
        );
        let expected =
            "readiness path validate_pass, observed status Errorx/112, last seen Running 40 ms ago";
        assert_eq!(readiness_log_detail(&finished), expected);
        for format in [crate::cli::LogFormat::Text, crate::cli::LogFormat::Json] {
            let ((), captured) = crate::logging::with_subscriber(
                format,
                tracing_subscriber::EnvFilter::new("trace"),
                || {
                    log_operation_finished(
                        "sandbox.create",
                        &finished,
                        false,
                        Duration::from_millis(1),
                    )
                },
            );
            let text = String::from_utf8_lossy(&captured).to_string();
            assert!(text.contains(expected), "{text}");
            assert!(!text.contains(SENTINEL), "{text}");
            assert!(!text.contains("<x>"), "{text}");
        }

        // Any other failure carries no detail.
        let finished = finish_bound(
            "op-other",
            "sbx",
            1,
            1,
            Err(DispatchFailure::Effect(EffectError::from(
                RuntimeError::new(SandboxErrorCode::GuestUnavailable, SENTINEL),
            ))),
        );
        assert_eq!(readiness_log_detail(&finished), "");
    }

    /// A template capture is refused before any
    /// effect while login files are in motion on this host; other kinds
    /// and a daemon without the credential service never are.
    #[test]
    fn a_capture_is_refused_while_credential_work_is_in_flight() {
        let dir = tempfile::tempdir().unwrap();
        let service =
            super::super::credentials::service::CredentialService::start(dir.path(), "host-1")
                .unwrap();
        let capture = dispatch("cap", "sandbox.capture", 1);
        assert!(capture_credential_refusal(Some(&service), &capture).is_none());
        service
            .store()
            .journal()
            .open_or_join_teardown(&capture.sandbox_id, "op-stop")
            .unwrap();
        let refused = capture_credential_refusal(Some(&service), &capture).expect("refused");
        assert_eq!(refused.code, SandboxErrorCode::StateConflict);
        assert!(capture_credential_refusal(None, &capture).is_none());
        let stop = dispatch("stop", "sandbox.stop", 2);
        assert!(capture_credential_refusal(Some(&service), &stop).is_none());
    }
}

/// All result producers arbitrate under the journal mutex. In particular stdin
/// failure and the command worker publish the same durable winning outcome.
/// WP3 (D2): a command the expiry service stopped at `max_carry`
/// (`ext.cancelReason = carry_expired`) whose stop is proven (CANCELLED)
/// settles FAILED `host_disconnect_expired`. Without proof it stays UNKNOWN,
/// and a natural ending that raced the stop (an exit, `timeout`) keeps its
/// own code (D3).
fn settle_carry_expired(
    journal: &HostJournal,
    d: &OperationDispatch,
    mut finished: FinishedOp,
) -> FinishedOp {
    use super::journal::CancelReason;
    use sandbox_protocol::results::{FailureEffect, FailureResource};
    if d.kind != "command.run" || finished.state != OperationState::Cancelled {
        return finished;
    }
    let carry_expired = journal.lookup(&d.operation_id).is_some_and(|receipt| {
        receipt.generation == d.generation
            && receipt.attempt == d.attempt
            && receipt.cancel_requested
            && CancelReason::of(&receipt) == Some(CancelReason::CarryExpired)
    });
    if !carry_expired {
        return finished;
    }
    finished.state = OperationState::Failed;
    finished.error = Some(DispatchError {
        reason: None,
        code: SandboxErrorCode::HostDisconnectExpired.into(),
        message: SandboxErrorCode::HostDisconnectExpired.as_str().into(),
    });
    if d.result_version == Some(1)
        && let Some(fields) = finished
            .payload
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
    {
        // The command ran and was stopped by the host.
        fields.insert(
            "failure".into(),
            json!({
                "resource": FailureResource::Command,
                "effect": FailureEffect::Partial,
            }),
        );
    }
    tracing::warn!(
        operation_id = %d.operation_id,
        sandbox_id = %d.sandbox_id,
        "carried command stopped at the carry cap (host_disconnect_expired)"
    );
    finished
}

fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Decision 2: journal the start (`ext.commandStart`) when the runtime binds
/// it, on the command's own wait loop. A failed write latches the journal
/// (like every writer); the command keeps running.
fn start_sink(
    journal: Arc<HostJournal>,
    dispatch: &OperationDispatch,
    process_id: String,
) -> impl Fn(&sandbox_runtime::CommandStart) + Send + Sync + 'static {
    let operation_id = dispatch.operation_id.clone();
    let sandbox_id = dispatch.sandbox_id.clone();
    let (generation, attempt) = (dispatch.generation, dispatch.attempt);
    move |start| {
        let Some(frame) = started_frame_value(
            &operation_id,
            generation,
            attempt,
            &sandbox_id,
            &process_id,
            &start.birth,
        ) else {
            return;
        };
        if journal
            .record_command_start(
                &operation_id,
                (generation, attempt),
                frame,
                start.uid,
                start.budget_ms,
                start.qemu,
            )
            .is_err()
        {
            tracing::warn!("command start journal write failed; the journal is latched");
        }
    }
}

pub fn persist_finished(journal: &HostJournal, mut finished: FinishedOp) -> FinishedOp {
    if let Some(error) = &mut finished.error {
        error.message = error.code.as_str().to_owned();
    }
    // An interim command observation (a cancel, revoked permit or
    // deadline stop not yet proven) makes the command due for `kill-cancel`.
    let ext = if finished.interim && finished.state == OperationState::UnknownOutcome {
        vec![(
            super::journal::COMMAND_STOP_UNPROVEN_EXT,
            serde_json::Value::Bool(true),
        )]
    } else {
        Vec::new()
    };
    match journal.record_attempt_result_ext(
        &finished.operation_id,
        (finished.generation, finished.attempt),
        finished.state,
        finished.payload.clone(),
        (
            finished.error.as_ref().map(|e| e.code.clone()),
            finished.error.as_ref().map(|e| e.message.clone()),
            finished.error.as_ref().and_then(|e| e.reason),
        ),
        &ext,
    ) {
        // The receipt moved on to a later attempt: this completion is stale.
        // Its authority is gone too, so it never publishes (fu-a).
        Ok(None) => tracing::debug!(
            operation_id = %finished.operation_id,
            generation = finished.generation,
            attempt = finished.attempt,
            "stale attempt result not journaled: the receipt belongs to a later attempt"
        ),
        Ok(Some(receipt)) => {
            // U1: a finished lifecycle dispatch is a host event for the
            // sandbox: its parked host-proof retirements are due now (a stop,
            // kill or cold reconnect changed or ended the QEMU process).
            if receipt.is_terminal()
                && matches!(
                    receipt.kind.as_str(),
                    "sandbox.stop"
                        | "sandbox.kill"
                        | "sandbox.reconnect"
                        | "sandbox.create"
                        | "sandbox.probe"
                )
            {
                journal.rearm_parked(&receipt.sandbox_id);
            }
            let reason = receipt.error_reason();
            finished.state = receipt.state;
            finished.payload = receipt.result;
            finished.error = receipt.error_code.map(|code| DispatchError {
                reason,
                message: code.as_str().to_owned(),
                code,
            });
        }
        Err(_) => {
            finished.state = OperationState::UnknownOutcome;
            finished.payload = None;
            finished.error = Some(DispatchError {
                reason: None,
                code: SandboxErrorCode::UnknownOutcome.into(),
                message: "result persistence failed".into(),
            });
        }
    }
    finished
}

#[cfg(all(test, unix))]
mod lease_tests {
    use super::*;
    use crate::sandbox_relay::journal::{CrashPoint, TransportBindingV11, intent_from_dispatch};
    #[test]
    fn create_boot_and_ack_require_durable_lease_and_result() {
        for (fault, expired) in [
            (None, false),
            (Some(CrashPoint::BeforeLease), false),
            (Some(CrashPoint::BeforeResult), false),
            (None, true),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let binding = TransportBindingV11 {
                server: "wss://lease.test".into(),
                host_owner_id: "owner".into(),
                host_id: "host".into(),
            };
            let journal = Arc::new(
                crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap(),
            );
            let runtime = Arc::new({
                let fake = sandbox_runtime::FakeRuntime::new();
                fake.fixture_root().unwrap();
                fake
            });
            runtime.fixture_root().unwrap();
            let authority = HostAuthority::default();
            let dispatch: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner",  "operationId": "create", "sandboxId": "sbx", "kind": "sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(), "cpuCount": 1, "memoryMiB": 1024, "idempotencyKey": "create", "generation": 1, "attempt": 1, "bodyHash": "a".repeat(64), "lease": sandbox_protocol::HostLease::for_test(), "architecture": "x86_64", "templateDigest": CreateSandboxRequest::for_test("sbx", "create").template_digest, "incusFingerprint": CreateSandboxRequest::for_test("sbx", "create").incus_fingerprint })).unwrap();
            let mut dispatch =
                crate::sandbox_relay::test_support::current_fixture_dispatch(&dispatch);
            if expired {
                dispatch.lease.as_mut().unwrap().deadline_unix_ms = 1;
            }
            journal
                .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &dispatch))
                .unwrap();
            if let Some(fault) = fault {
                journal.inject_crash(fault);
            }
            authority
                .accept_dispatch("create", "sbx", "sandbox.create", 1, 1)
                .unwrap();
            let relay = RelaySupervisor::start(
                runtime.clone(),
                journal.clone(),
                authority,
                #[cfg(target_os = "linux")]
                None,
            );
            relay
                .submit(dispatch.clone(), "wssp-sbx-sbx".into(), None)
                .unwrap();
            let until = Instant::now() + Duration::from_secs(3);
            let done = loop {
                if let Some(done) = relay.poll_finished().pop() {
                    break done;
                }
                assert!(Instant::now() < until);
                thread::sleep(Duration::from_millis(2));
            };
            if fault == Some(CrashPoint::BeforeLease) || expired {
                assert!(
                    runtime.sandbox_inventory().unwrap().is_empty(),
                    "no boot before durable lease"
                );
                assert_ne!(done.state, OperationState::Succeeded);
            } else {
                assert!(
                    journal.lease("sbx").is_some(),
                    "successful boot requires a durable lease"
                );
                assert_eq!(journal.lease("sbx").unwrap().lease, dispatch.lease.unwrap());
                assert_eq!(runtime.sandbox_inventory().unwrap().len(), 1);
                assert_eq!(
                    done.state,
                    if fault.is_none() {
                        OperationState::Succeeded
                    } else {
                        OperationState::UnknownOutcome
                    }
                );
                if fault.is_none() {
                    assert!(done.payload.unwrap().get("lease").is_some());
                }
            }
        }
    }

    /// E1-B-03: a wire stop asks the guest to shut down first (so its page
    /// cache reaches the disk), then the forced stop always runs as the
    /// completion proof — also when the guest ignores the request. A kill
    /// never waits for the guest.
    #[test]
    fn wire_stop_is_graceful_first_then_forced_and_kill_never_waits() {
        for ignores in [false, true] {
            let stages = Arc::new(Mutex::new(Vec::<String>::new()));
            let fake = {
                let stages = stages.clone();
                sandbox_runtime::FakeRuntime::new()
                    .with_graceful_stop()
                    .with_lifecycle_hook(move |stage| {
                        stages.lock().unwrap().push(stage.to_owned());
                        if ignores && stage == "stop_graceful" {
                            return Err(sandbox_runtime::RuntimeError::new(
                                SandboxErrorCode::Timeout,
                                "guest ignored the shutdown",
                            ));
                        }
                        Ok(())
                    })
            };
            fake.fixture_root().unwrap();
            let runtime: Arc<dyn SandboxRuntime> = Arc::new(fake);
            runtime
                .create_fixture(&sandbox_runtime::CreateSandboxRequest::for_test(
                    "sbx", "create",
                ))
                .unwrap();
            let job = |kind: &str| {
                DispatchJob {
                owner: None,
                first_allocation_attempt: false,
                tracked: TrackedCommands::default(),
                resumed: false,
                output: None,
                dispatch: serde_json::from_value(json!({"sandboxOwnerId":"owner",
                    "operationId": kind, "sandboxId": "sbx", "kind": kind,
                    "allocation": crate::sandbox_relay::test_support::allocation(),
                    "generation": 1, "attempt": 1, "idempotencyKey": kind, "bodyHash": "b".repeat(64),
                    "incusFingerprint": sandbox_runtime::CreateSandboxRequest::for_test("sbx", "key").incus_fingerprint,
                }))
                .unwrap(),
                instance_name: "wssp-sbx-sbx".into(),
                upload: None,
            }
            };
            let authority = HostAuthority::default();
            authority
                .accept_dispatch("sandbox.stop", "sbx", "sandbox.stop", 1, 1)
                .unwrap();
            stages.lock().unwrap().clear();
            let result = run_job(
                &runtime,
                &job("sandbox.stop"),
                &authority,
                None,
                &[],
                Launch::default(),
            );
            assert!(result.is_ok(), "ignores={ignores}: {result:?}");
            assert_eq!(
                *stages.lock().unwrap(),
                ["stop_graceful", "stop"],
                "ignores={ignores}"
            );
            authority
                .accept_dispatch("sandbox.kill", "sbx", "sandbox.kill", 1, 1)
                .unwrap();
            stages.lock().unwrap().clear();
            let result = run_job(
                &runtime,
                &job("sandbox.kill"),
                &authority,
                None,
                &[],
                Launch::default(),
            );
            assert!(result.is_ok(), "{result:?}");
            assert!(
                !stages.lock().unwrap().iter().any(|s| s == "stop_graceful"),
                "{:?}",
                stages.lock().unwrap()
            );
        }
    }

    /// An observational warm reconnect runs runtime work with the effective
    /// lease the journal observed — the healthy renewal — because the runtime
    /// revalidates the lease against its own wall clock and the queued lease
    /// may already be past its deadline. The queued lease alone must fail.
    #[test]
    fn observational_reconnect_runs_with_the_effective_lease() {
        let runtime: Arc<dyn SandboxRuntime> = Arc::new({
            let fake = sandbox_runtime::FakeRuntime::new();
            fake.fixture_root().unwrap();
            fake
        });
        runtime
            .create_fixture(&sandbox_runtime::CreateSandboxRequest::for_test(
                "sbx", "create",
            ))
            .unwrap();
        let expired_dispatch = |operation: &str| -> OperationDispatch {
            serde_json::from_value(json!({"sandboxOwnerId":"owner",
                "operationId": operation, "sandboxId": "sbx", "kind": "sandbox.reconnect", "allocation": crate::sandbox_relay::test_support::allocation(), "cpuCount": 1, "memoryMiB": 1024,
                "generation": 1, "attempt": 1, "idempotencyKey": operation, "bodyHash": "b".repeat(64),
                "incusFingerprint": sandbox_runtime::CreateSandboxRequest::for_test("sbx", "key").incus_fingerprint,
                "architecture": "x86_64",
                "lease": {"revision": 1, "deadlineUnixMs": 1_000, "action": "stop", "expiryPolicy": "retry-force-60s"}
            }))
            .unwrap()
        };
        for effective in [true, false] {
            let authority = HostAuthority::default();
            authority
                .accept_dispatch("reconnect", "sbx", "sandbox.reconnect", 1, 1)
                .unwrap();
            let dispatch = expired_dispatch("reconnect");
            let job = DispatchJob {
                owner: None,
                first_allocation_attempt: false,
                tracked: TrackedCommands::default(),
                resumed: false,
                output: None,
                dispatch: dispatch.clone(),
                instance_name: "wssp-sbx-sbx".into(),
                upload: None,
            };
            let observed = effective.then(|| sandbox_protocol::HostLease {
                revision: 2,
                ..sandbox_protocol::HostLease::for_test()
            });
            let result = run_job(
                &runtime,
                &job,
                &authority,
                observed.as_ref(),
                &[],
                Launch::default(),
            );
            if effective {
                assert!(
                    result.is_ok(),
                    "the effective renewal validates at runtime: {result:?}"
                );
            } else {
                assert!(result.is_err(), "the queued lease is past its own deadline");
            }
        }
        // B1: an effective lease past 24h, and the far-future "no lease timer"
        // deadline, are structurally valid for a warm reconnect.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        for deadline in [
            now + 25 * 3_600_000,
            sandbox_protocol::LEASE_UNLIMITED_DEADLINE_MS,
        ] {
            let authority = HostAuthority::default();
            authority
                .accept_dispatch("reconnect", "sbx", "sandbox.reconnect", 1, 1)
                .unwrap();
            let job = DispatchJob {
                owner: None,
                first_allocation_attempt: false,
                tracked: TrackedCommands::default(),
                resumed: false,
                output: None,
                dispatch: expired_dispatch("reconnect"),
                instance_name: "wssp-sbx-sbx".into(),
                upload: None,
            };
            let observed = sandbox_protocol::HostLease {
                revision: 2,
                deadline_unix_ms: deadline,
                ..sandbox_protocol::HostLease::for_test()
            };
            let result = run_job(
                &runtime,
                &job,
                &authority,
                Some(&observed),
                &[],
                Launch::default(),
            );
            assert!(result.is_ok(), "{deadline}: {result:?}");
        }
    }

    /// A lease past the host's local ceiling is refused before any effect
    /// with the typed `lease_exceeds_policy` code, never `state_conflict`.
    #[test]
    fn ceiling_refusal_maps_to_lease_exceeds_policy_before_any_effect() {
        let dir = tempfile::tempdir().unwrap();
        let binding = TransportBindingV11 {
            server: "wss://lease.test".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        };
        let journal = Arc::new(
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap(),
        );
        // `HostLease::for_test` ends four hours out; the host allows one.
        journal.set_lease_ceiling(Some(3_600_000));
        let runtime = Arc::new({
            let fake = sandbox_runtime::FakeRuntime::new();
            fake.fixture_root().unwrap();
            fake
        });
        let authority = HostAuthority::default();
        let dispatch: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner",  "operationId": "create", "sandboxId": "sbx", "kind": "sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(), "cpuCount": 1, "memoryMiB": 1024, "idempotencyKey": "create", "generation": 1, "attempt": 1, "bodyHash": "a".repeat(64), "lease": sandbox_protocol::HostLease::for_test(), "architecture": "x86_64", "templateDigest": CreateSandboxRequest::for_test("sbx", "create").template_digest, "incusFingerprint": CreateSandboxRequest::for_test("sbx", "create").incus_fingerprint })).unwrap();
        let dispatch = crate::sandbox_relay::test_support::current_fixture_dispatch(&dispatch);
        journal
            .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &dispatch))
            .unwrap();
        authority
            .accept_dispatch("create", "sbx", "sandbox.create", 1, 1)
            .unwrap();
        let relay = RelaySupervisor::start(
            runtime.clone(),
            journal.clone(),
            authority,
            #[cfg(target_os = "linux")]
            None,
        );
        relay.submit(dispatch, "wssp-sbx-sbx".into(), None).unwrap();
        let until = Instant::now() + Duration::from_secs(3);
        let done = loop {
            if let Some(done) = relay.poll_finished().pop() {
                break done;
            }
            assert!(Instant::now() < until);
            thread::sleep(Duration::from_millis(2));
        };
        assert_eq!(done.state, OperationState::Failed);
        assert_eq!(
            done.error.map(|e| e.code),
            Some(SandboxErrorCode::LeaseExceedsPolicy.into())
        );
        assert!(runtime.sandbox_inventory().unwrap().is_empty(), "no boot");
        assert!(journal.lease("sbx").is_none(), "nothing stored");
    }

    /// B1: dispatched create/renew leases past 24h, and the far-future
    /// deadline, pass the structural check; one millisecond more is refused.
    #[test]
    fn required_lease_accepts_25h_and_the_unlimited_deadline() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let renew = |deadline: u64| -> OperationDispatch {
            serde_json::from_value(json!({"sandboxOwnerId":"owner",
                "operationId": "renew", "sandboxId": "sbx", "kind": "sandbox.lease.renew",
                "generation": 1, "attempt": 1, "idempotencyKey": "renew", "bodyHash": "b".repeat(64),
                "lease": {"revision": 2, "deadlineUnixMs": deadline, "action": "stop", "expiryPolicy": "retry-force-60s"}
            }))
            .unwrap()
        };
        assert!(required_lease(&renew(now + 25 * 3_600_000)).is_ok());
        assert!(required_lease(&renew(sandbox_protocol::LEASE_UNLIMITED_DEADLINE_MS)).is_ok());
        let refused =
            required_lease(&renew(sandbox_protocol::LEASE_UNLIMITED_DEADLINE_MS + 1)).unwrap_err();
        assert_eq!(refused.code, SandboxErrorCode::StateConflict);
    }
}

#[cfg(test)]
mod revision_image_tests {
    use super::*;
    use sandbox_runtime::FakeRuntime;

    fn job(artifact: &str) -> DispatchJob {
        let request = CreateSandboxRequest::for_test("revision-image", "create");
        DispatchJob { owner: None,
            first_allocation_attempt: false,
            tracked: TrackedCommands::default(),
            resumed: false,
            output: None,
            instance_name: request.instance_name,
            upload: None,
            dispatch: serde_json::from_value(json!({"sandboxOwnerId":"owner",
                "operationId": "create", "sandboxId": "revision-image", "idempotencyKey": "create",
                "kind": "sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(), "cpuCount": 1, "memoryMiB": 1024, "generation": 1, "attempt": 1,
                "templateRevisionId": "revision", "verificationConnectionEpoch": 7,
                "templateDigest": artifact, "incusFingerprint": artifact,
                "architecture": "x86_64", "lease": request.lease,
                "egressPolicy": request.egress_policy, "egressPolicyHash": request.egress_policy_hash,
            })).unwrap(),
        }
    }

    #[test]
    fn fresh_create_missing_exact_image_reports_only_its_revision_artifact_epoch_before_effect() {
        let fake = FakeRuntime::new();
        fake.fixture_root().unwrap();
        let artifact = format!("sha256:{}", "f".repeat(64));
        let job = job(&artifact);
        let result = execute_dispatch(&fake, &job, None, &[], Launch::default());
        let finished = finish_bound("create", "revision-image", 1, 1, result);
        assert_eq!(finished.state, OperationState::Failed);
        assert_eq!(finished.error.unwrap().code, SandboxErrorCode::NotFound);
        assert_eq!(
            finished.payload,
            Some(json!({ "imageMissing": {
                "templateRevisionId": "revision", "artifact": artifact,
                "architecture": "x86_64", "connectionEpoch": 7,
            }}))
        );
        assert_eq!(
            fake.query_sandbox("revision-image", None, None).unwrap(),
            None
        );
    }

    // PG supplies actual server dispatches through a test-only file bridge.
    // Normal Rust runs cover the same real adapter/daemon verdicts independently.
    #[cfg(target_os = "linux")]
    #[test]
    fn incus_exact_image_missing_pipeline() {
        use crate::sandbox_relay::{
            connect::availability_status, test_support::image_lookup_runtime,
        };
        let bridge = std::env::var_os("WSSP_TEST_IMAGE_DISPATCH").map(std::path::PathBuf::from);
        let mut results = Vec::new();
        for mode in ["json", "cli", "denied", "unknown"] {
            let (dir, runtime) = image_lookup_runtime(mode);
            let artifact = format!("sha256:{}", "a".repeat(64));
            let mut job = job(&artifact);
            if let Some(path) = &bridge {
                let dispatches: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
                job.dispatch =
                    serde_json::from_value(dispatches.get(mode).unwrap().clone()).unwrap();
                job.instance_name = format!("wssp-sbx-{}", job.dispatch.sandbox_id);
            }
            let binding = sandbox_protocol::AvailabilityBinding {
                revision_id: job.dispatch.template_revision_id.clone().unwrap(),
                artifact: job.dispatch.incus_fingerprint.clone().unwrap(),
                architecture: job.dispatch.architecture.clone().unwrap(),
                manifest_hash: "b".repeat(64),
            };
            let availability = availability_status(&runtime, &binding);
            let result = execute_dispatch(&runtime, &job, None, &[], Launch::default());
            let finished = finish_bound(
                &job.dispatch.operation_id,
                &job.dispatch.sandbox_id,
                job.dispatch.generation,
                job.dispatch.attempt,
                result,
            );
            let missing = matches!(mode, "json" | "cli");
            assert_eq!(
                availability,
                if missing {
                    sandbox_protocol::AvailabilityStatus::Missing
                } else {
                    sandbox_protocol::AvailabilityStatus::Rejected
                }
            );
            assert_eq!(finished.state, OperationState::Failed);
            assert_eq!(finished.payload.is_some(), missing);
            assert_eq!(
                finished.error.as_ref().unwrap().code,
                match mode {
                    "json" | "cli" => SandboxErrorCode::NotFound,
                    "denied" => SandboxErrorCode::AccessDenied,
                    _ => SandboxErrorCode::Internal,
                }
            );
            let calls = std::fs::read_to_string(dir.path().join("calls")).unwrap();
            assert!(!calls.lines().any(|line| {
                line.split_whitespace()
                    .any(|word| matches!(word, "init" | "start" | "exec"))
            }));
            let mut frame = json!({ "type": "operation.result", "id": format!("result-{mode}"),
                "operationId": finished.operation_id, "sandboxId": finished.sandbox_id,
                "generation": finished.generation, "attempt": finished.attempt, "state": finished.state });
            if let Some(error) = finished.error {
                frame["error"] = json!({ "code": error.code, "message": error.message });
            }
            if let Some(result) = finished.payload {
                frame["result"] = result;
            }
            results.push(json!({ "mode": mode, "availability": availability, "frame": frame }));
        }
        if let Some(path) = bridge {
            std::fs::write(
                path.with_extension("results.json"),
                serde_json::to_vec(&results).unwrap(),
            )
            .unwrap();
        }
    }

    #[test]
    fn typed_process_pages_select_started_owned_commands_before_cloning_descriptions() {
        let tracked = TrackedCommands::default();
        for index in 0..7 {
            let output = sandbox_runtime::CommandOutput::default();
            if index != 4 {
                output.bind_start(&sandbox_runtime::CommandBirth {
                    pid: 100 + index,
                    boot_id: "12345678-1234-4234-8234-123456789abc".into(),
                    start_ticks: 1,
                    started_at_ms: 1_793_059_200_000 + u64::from(index),
                });
            }
            tracked.lock().unwrap().insert(
                (
                    format!("command-{index}"),
                    if index == 6 { 2 } else { 1 },
                    1,
                ),
                TrackedCommand {
                    sandbox_id: if index == 5 { "foreign" } else { "sbx" }.into(),
                    process_id: format!("process-{index}"),
                    description: sandbox_runtime::CommandDescription {
                        cmd: "run".into(),
                        args: vec!["a".repeat(500); 7],
                        args_truncated: false,
                        cwd: format!("/{}", "d".repeat(3500)),
                    },
                    output,
                },
            );
        }
        let mut job=DispatchJob { owner: None,first_allocation_attempt:false,tracked,resumed:false,output:None,instance_name:"wssp-sbx-sbx".into(),upload:None,dispatch:serde_json::from_value(json!({"sandboxOwnerId":"owner", "operationId":"list","sandboxId":"sbx","idempotencyKey":"list","kind":"process.list","generation":1,"attempt":1,"resultVersion":1,"limit":100})).unwrap()};
        let fake = FakeRuntime::new();
        fake.fixture_root().unwrap();
        let done = finish_dispatch(
            &job.dispatch,
            execute_dispatch(&fake, &job, None, &[], Launch::default()),
            Instant::now(),
        );
        let encoded = done.payload.unwrap();
        assert!(encoded.to_string().len() <= 24576);
        let page: sandbox_protocol::results::host::HostOperationResult =
            serde_json::from_value(encoded).unwrap();
        assert!(page.validate(
            sandbox_protocol::results::ResultKind::ListProcesses,
            "sbx",
            1
        ));
        let Some(sandbox_protocol::results::ResultBody::Processes { items, .. }) = &page.payload
        else {
            panic!("process page")
        };
        assert!(!items.is_empty() && items.len() < 4);
        assert!(items.iter().all(|p| p.operation_id != "command-4"
            && p.operation_id != "command-5"
            && p.operation_id != "command-6"));
        let last = items.last().unwrap();
        assert_eq!(
            page.continuation.as_ref().unwrap().last_key,
            json!([last.started_at, last.process.process_id]).to_string()
        );
        job.dispatch.continuation = page.continuation;
        let done = finish_dispatch(
            &job.dispatch,
            execute_dispatch(&fake, &job, None, &[], Launch::default()),
            Instant::now(),
        );
        let page: sandbox_protocol::results::host::HostOperationResult =
            serde_json::from_value(done.payload.unwrap()).unwrap();
        assert!(page.continuation.is_none());
        let Some(sandbox_protocol::results::ResultBody::Processes { items, .. }) = page.payload
        else {
            panic!("process page")
        };
        assert_eq!(items.len(), 1);
    }

    #[test]
    fn post_effect_serialization_failure_is_unknown() {
        struct EncodingFailure;
        impl Drop for EncodingFailure {
            fn drop(&mut self) {
                FAIL_MUTATION_ENCODING.set(false);
            }
        }
        for kind in ["file.mkdir", "file.remove", "file.move"] {
            let fake = FakeRuntime::new();
            fake.fixture_root().unwrap();
            fake.create_fixture(&CreateSandboxRequest::for_test("sbx", "seed"))
                .unwrap();
            fake.mkdir(&MkdirRequest {
                template_fingerprint: String::new(),
                guest: Default::default(),
                sandbox_id: "sbx".into(),
                instance_name: "wssp-sbx-sbx".into(),
                operation_id: "seed-dir".into(),
                idempotency_key: "seed-dir".into(),
                path: "/source".into(),
            })
            .unwrap();
            let dispatch: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner",
                    "operationId":"mutation", "sandboxId":"sbx", "idempotencyKey":"mutation",
                    "kind":kind, "generation":1, "attempt":1, "resultVersion":1,
                    "path": if kind == "file.mkdir" { "/created" } else { "/source" }, "destPath":"/moved", "recursive":true,
                })).unwrap();
            let job = DispatchJob {
                owner: None,
                first_allocation_attempt: false,
                tracked: TrackedCommands::default(),
                resumed: false,
                output: None,
                instance_name: "wssp-sbx-sbx".into(),
                upload: None,
                dispatch: dispatch.clone(),
            };
            let guard = EncodingFailure;
            FAIL_MUTATION_ENCODING.set(true);
            let result = execute_dispatch(&fake, &job, None, &[], Launch::default());
            assert!(
                matches!(
                    &result,
                    Err(DispatchFailure::Effect(EffectError::Unknown(_)))
                ),
                "{kind}: {result:?}"
            );
            let finished = finish_dispatch(&dispatch, result, Instant::now());
            assert_eq!(finished.state, OperationState::UnknownOutcome, "{kind}");
            assert_eq!(
                finished.payload.as_ref().unwrap()["failure"]["effect"],
                "unknown"
            );
            drop(guard);
        }
    }

    #[test]
    fn typed_metadata_producers_share_the_receipt_codec() {
        let fake = FakeRuntime::new();
        fake.fixture_root().unwrap();
        fake.create_fixture(&CreateSandboxRequest::for_test("sbx", "seed"))
            .unwrap();
        let run = |id: &str, kind: &str, path: &str, dest: Option<&str>| {
            let d:OperationDispatch=serde_json::from_value(json!({"sandboxOwnerId":"owner", "operationId":id,"sandboxId":"sbx","idempotencyKey":id,"kind":kind,"generation":1,"attempt":1,"resultVersion":1,"path":path,"destPath":dest,"maxDepth":1,"limit":1})).unwrap();
            let job = DispatchJob {
                owner: None,
                first_allocation_attempt: false,
                tracked: TrackedCommands::default(),
                resumed: false,
                output: None,
                instance_name: "wssp-sbx-sbx".into(),
                upload: None,
                dispatch: d.clone(),
            };
            let done = finish_dispatch(
                &d,
                execute_dispatch(&fake, &job, None, &[], Launch::default()),
                Instant::now(),
            );
            let body: sandbox_protocol::results::host::HostOperationResult =
                serde_json::from_value(done.payload.unwrap()).unwrap();
            assert!(body.validate(
                sandbox_protocol::results::host::kind_from_dispatch(kind).unwrap(),
                "sbx",
                1
            ));
            (done.state, body)
        };
        let (_, created) = run("mkdir-a", "file.mkdir", "/dir/a", None);
        assert_eq!(
            serde_json::to_value(created.payload).unwrap(),
            json!({"type":"file.mkdir","created":true})
        );
        let escaped_path = format!("/{}", vec!["\u{1}".repeat(255); 16].join("/"));
        assert_eq!(escaped_path.len(), 4096);
        let (escaped_state, escaped) = run("mkdir-escaped", "file.mkdir", &escaped_path, None);
        assert_eq!(escaped_state, OperationState::Succeeded);
        assert_eq!(
            serde_json::to_value(escaped.payload).unwrap(),
            json!({"type":"file.mkdir","created":true})
        );
        let (_, existing) = run("mkdir-existing", "file.mkdir", "/dir/a", None);
        assert_eq!(
            serde_json::to_value(existing.payload).unwrap(),
            json!({"type":"file.mkdir","created":false})
        );
        run("mkdir-b", "file.mkdir", "/dir/b", None);
        let (_, page) = run("list", "file.list", "/dir", None);
        assert_eq!(page.continuation.unwrap().last_key, "a");
        let (_, stat) = run("stat", "file.stat", "/dir/a", None);
        assert!(matches!(
            stat.payload,
            Some(sandbox_protocol::results::ResultBody::Stat { .. })
        ));
        let (_, moved) = run("move", "file.move", "/dir/a", Some("/dir/c"));
        assert!(matches!(
            moved.payload,
            Some(sandbox_protocol::results::ResultBody::Rename { .. })
        ));
        let (_, removed) = run("remove", "file.remove", "/dir/c", None);
        assert!(matches!(
            removed.payload,
            Some(sandbox_protocol::results::ResultBody::Remove { removed: true })
        ));
        let (state, failed) = run("missing", "file.stat", "/missing", None);
        assert_eq!(state, OperationState::Failed);
        assert_eq!(
            failed.failure.unwrap().effect,
            sandbox_protocol::results::FailureEffect::None
        );
    }

    #[test]
    fn fresh_create_uses_the_exact_cached_artifact_after_an_alias_moves() {
        let fake = FakeRuntime::new();
        fake.fixture_root().unwrap();
        let first = format!("sha256:{}", "f".repeat(64));
        let second = format!("sha256:{}", "e".repeat(64));
        fake.register_image("base", &first, "x86_64");
        fake.register_image("base", &second, "aarch64");
        let job = job(&first);
        assert!(execute_dispatch(&fake, &job, None, &[], Launch::default()).is_ok());
    }
}

#[cfg(test)]
mod restore_dispatch_tests {
    //! Restore frames and recovery on the FakeRuntime.
    use super::*;
    use sandbox_runtime::FakeRuntime;

    fn restore_job(disk: &str, first: bool) -> DispatchJob {
        let request = CreateSandboxRequest::for_test("restored", "restore");
        DispatchJob {
            owner: None,
            first_allocation_attempt: first,
            tracked: TrackedCommands::default(),
            resumed: false,
            output: None,
            instance_name: request.instance_name,
            upload: None,
            dispatch: serde_json::from_value(json!({"sandboxOwnerId":"owner",
                "operationId": "restore", "sandboxId": "restored", "idempotencyKey": "restore",
                "kind": "sandbox.reconnect", "allocation": crate::sandbox_relay::test_support::allocation(),
                "cpuCount": 1, "memoryMiB": 1024, "generation": 4, "attempt": 1,
                "templateDigest": request.template_digest, "incusFingerprint": request.incus_fingerprint,
                "architecture": "x86_64", "lease": request.lease,
                "image": {"fingerprint": disk, "sizeBytes": 4096, "format": "unified", "source": "fetch"},
                "restore": {"offloadId": "off-1", "seq": 1, "fingerprint": disk,
                    "cloudInitInstanceId": "iid-restored"},
                "launchMode": "new_root",
            }))
            .unwrap(),
        }
    }

    #[test]
    fn a_restore_frame_boots_a_new_root_from_the_disk_with_the_template_tag() {
        let fake = FakeRuntime::new();
        fake.fixture_root().unwrap();
        let disk = fake.seed_image_bytes(b"stored disk of restored", "x86_64", false);
        let job = restore_job(&disk, true);
        assert_eq!(
            sandbox_runtime::AllocationKind::from_dispatch(&job.dispatch),
            Some(sandbox_runtime::AllocationKind::Create)
        );
        let result = execute_dispatch(&fake, &job, None, &[], Launch::default());
        let finished = finish_bound("restore", "restored", 4, 1, result);
        assert_eq!(finished.state, OperationState::Succeeded, "{finished:?}");
        // launch = restore.fingerprint; the template binding is unchanged.
        assert_eq!(
            fake.restore_base("restored").as_deref(),
            Some(disk.as_str())
        );
        fake.stop_sandbox(&StopSandboxRequest {
            template_fingerprint: CreateSandboxRequest::for_test("x", "y").template_digest,
            sandbox_id: "restored".into(),
            instance_name: job.instance_name.clone(),
            operation_id: "stop".into(),
            idempotency_key: "stop".into(),
        })
        .expect("the template tag binds");
        // S6: the disk image is gone right after init.
        assert!(!fake.has_image(&disk));
    }

    #[test]
    fn a_refused_restore_releases_only_on_root_absence_and_first_attempt() {
        let disk = format!("sha256:{}", "d".repeat(64));
        let refused = || {
            Err(DispatchFailure::Rejected(DispatchError {
                reason: None,
                code: SandboxErrorCode::ImageUnavailable.into(),
                message: "image fetch refused".into(),
            }))
        };
        for (first, partial, released) in [
            (true, false, true),
            (false, false, false),
            (true, true, false),
        ] {
            let fake = FakeRuntime::new();
            fake.fixture_root().unwrap();
            if partial {
                // A stopped partial root a cold reconnect would release on.
                let create = CreateSandboxRequest::for_test("restored", "seed");
                fake.create_sandbox_on_storage(&create, &fake.fixture_root().unwrap())
                    .unwrap();
                fake.stop_sandbox(&StopSandboxRequest {
                    template_fingerprint: create.template_digest.clone(),
                    sandbox_id: "restored".into(),
                    instance_name: create.instance_name.clone(),
                    operation_id: "stop".into(),
                    idempotency_key: "stop".into(),
                })
                .unwrap();
            }
            let job = restore_job(&disk, first);
            let result = classify_allocation_refusal(&fake, &job.dispatch, first, refused());
            assert_eq!(
                matches!(result, Err(DispatchFailure::Rejected(_))),
                released,
                "first={first} partial={partial}"
            );
            if !released {
                assert!(matches!(result, Err(DispatchFailure::AllocationUnknown(_))));
            }
        }
    }
}
