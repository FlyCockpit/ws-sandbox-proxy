//! Host half of the C52 terminal channel: binds C51 runtime PTY sessions to
//! relay terminal sessions, pumps bytes both ways, and enforces fences,
//! sequences, credit windows, session caps and the open rate.
//!
//! Ownership and threads:
//! - [`TerminalHost`] lives on the socket-loop thread for one relay
//!   connection. It never opens, reads, writes, closes or drops a
//!   `PtySession`, and never waits on one: every PTY call (including open,
//!   which binds against Incus, and close/drop, which can take ~12–17 s)
//!   runs on that session's dedicated pump thread.
//! - Socket loop → pump: a bounded control channel (input, resize, output
//!   credit) and a lock-free stop request. Pump → socket loop: a bounded
//!   per-session event channel drained a bounded number per tick, so one
//!   flooding PTY cannot delay heartbeats, dispatch or cancellation.
//! - [`TerminalSlots`] is process-wide (it survives reconnects): a live PTY
//!   holds its per-host and per-sandbox slot until its pump confirms the
//!   reap. An uncertain reap keeps the slot charged: the pump thread stays
//!   on as that slot's reconciliation sweep (C55), retrying the reap every
//!   [`REAP_SWEEP_INTERVAL`] and releasing the slot only on a confirmed
//!   reap, which it reports with a second `terminal.exit { reaped: true }`.
//! - Reattach (WP8, D5): the process-wide [`TerminalSlots`] also holds the
//!   DETACHED session table, so the terminal state outlives one relay
//!   connection. When a connection that negotiated `terminalResume` ends, its
//!   ready SANDBOX sessions move there for the node's `terminal_resume_grace`
//!   (host-target sessions are never detached and close as before). Output
//!   always goes through the session's sequenced ring ([`OutputRing`],
//!   256 KiB): attached, the pump reads only within the server's credit
//!   window; detached, it keeps reading and evicts the oldest frames, refuses
//!   input, and closes the PTY itself at the deadline or when the lease
//!   authority check fails (C55 closes apply at once). `terminal.resume` on a
//!   later connection matches the terminal id, sandbox and generation against
//!   this table, never anything the frame alone asserts.
//! - Lock order: the slots mutex, the detached table and each session's ring
//!   are leaves; none is held across a channel send, runtime call, journal or
//!   authority lock, or while taking another of them.
//!
//! The PTY's sandbox, generation, template fingerprint and guest identity
//! come from the journal's accepted lease record; a frame names only the
//! sandbox and generation it expects, and a mismatch refuses the open.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use sandbox_protocol::{
    DaemonControlMessage, HostTerminalOpenPolicyV11, OperationDispatch, ProtocolErrorDetail,
    SandboxErrorCode, ServerControlMessage, TERMINAL_ENDED_SESSION_TOMBSTONES,
    TERMINAL_FENCE_VIOLATION_LIMIT, TERMINAL_INPUT_WINDOW_FRAMES,
    TERMINAL_MAX_LIVE_SESSIONS_PER_SANDBOX, TERMINAL_MAX_SESSIONS_PER_HOST,
    TERMINAL_OPENS_PER_MINUTE_PER_HOST, TERMINAL_OUTPUT_WINDOW_FRAMES, TerminalCloseIntent,
    TerminalDataKind, TerminalDataMetadata, TerminalFence, TerminalTargetV11,
    encode_terminal_frame,
};
use sandbox_runtime::{
    OpenPtyRequest, PtyCloseIntent, PtyEvent, PtySession, PtySize, PtyTermination, SandboxRuntime,
};

use super::authority::HostAuthority;
use super::journal::{HostJournal, TransportBindingV11};

/// Pending control items per session: the input window, output credits for
/// the output window, a few resizes, and slack.
const CONTROL_QUEUE: usize =
    (TERMINAL_INPUT_WINDOW_FRAMES + TERMINAL_OUTPUT_WINDOW_FRAMES) as usize + 8;
/// Pump → socket events per session (output window plus control replies).
const EVENT_QUEUE: usize = TERMINAL_OUTPUT_WINDOW_FRAMES as usize + 8;
/// Events forwarded per session per socket-loop tick.
const EVENTS_PER_TICK: usize = TERMINAL_OUTPUT_WINDOW_FRAMES as usize + 2;
const PUMP_WAIT: Duration = Duration::from_millis(20);
const AUDIT_LOGS: usize = 16;
const OPEN_RATE_WINDOW: Duration = Duration::from_secs(60);
/// WP8: output a detached (or not yet acknowledged) session keeps for replay.
pub(super) const RESUME_RING_BYTES: usize = 256 * 1024;
/// WP8: how often a detached pump re-checks its sandbox's lease authority.
const DETACHED_CHECK_INTERVAL: Duration = Duration::from_millis(250);
/// Retry cadence of an uncertain reap's reconciliation sweep (C55). One
/// non-blocking reap attempt each (a `/proc` read and a `waitpid(WNOHANG)`).
pub(super) const REAP_SWEEP_INTERVAL: Duration = Duration::from_millis(250);

/// Something the socket loop must send to the server.
#[derive(Debug)]
pub(super) enum Outgoing {
    Text(Box<DaemonControlMessage>),
    Binary(Vec<u8>),
}

#[derive(Debug, Default)]
struct SlotState {
    live: usize,
    /// Of `live`: slots held only by an uncertain reap (C55). Shutdown does
    /// not wait for these; their sweeps own them.
    uncertain: usize,
    per_sandbox: HashMap<String, usize>,
    opens: VecDeque<(Instant, Option<String>)>,
    guest_live: usize,
    per_creator: HashMap<String, usize>,
}

/// Process-wide PTY capacity, counted until each PTY is confirmed reaped,
/// plus the detached sessions (WP8) that outlive their relay connection.
#[derive(Debug)]
pub(super) struct TerminalSlots {
    state: Mutex<SlotState>,
    idle: Condvar,
    detached: DetachedTable,
    /// `terminal_resume_grace` (D5), already clamped to the advertised range.
    resume_grace: Duration,
}

impl Default for TerminalSlots {
    fn default() -> Self {
        Self::with_resume_grace(Duration::from_millis(
            sandbox_protocol::TERMINAL_RESUME_GRACE_DEFAULT_MS,
        ))
    }
}

/// Sandbox sessions whose relay connection ended, keyed by terminal id.
#[derive(Default)]
struct DetachedTable(Mutex<HashMap<String, Live>>);

impl std::fmt::Debug for DetachedTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DetachedTable")
            .field("sessions", &self.lock().len())
            .finish()
    }
}

impl DetachedTable {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Live>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The node's reattach grace: `terminal_resume_grace` from the config, or in
/// debug builds the WP1 chaos knob's `terminal_grace` field
/// (`WSSP_TEST_RELAY_TIMING`). Either is clamped to what the hello may
/// advertise (1 s ..= 10 min), so the server's grace and the node's agree.
pub(super) fn resume_grace(config: &crate::config::Config) -> Result<Duration> {
    #[cfg(debug_assertions)]
    if let Some(grace) =
        super::test_timing::installed_relay_test_timing().and_then(|timing| timing.terminal_grace)
    {
        return Ok(clamp_resume_grace(grace));
    }
    Ok(clamp_resume_grace(config.terminal_resume_grace()))
}

pub(super) fn clamp_resume_grace(grace: Duration) -> Duration {
    grace.clamp(
        Duration::from_millis(sandbox_protocol::TERMINAL_RESUME_GRACE_MIN_MS),
        Duration::from_millis(sandbox_protocol::TERMINAL_RESUME_GRACE_MAX_MS),
    )
}

/// One charged PTY slot. Released only by [`SlotGuard::release`] after a
/// confirmed reap; dropping it without release keeps the slot charged.
#[derive(Debug)]
pub(super) struct SlotGuard {
    slots: Arc<TerminalSlots>,
    sandbox_id: String,
    creator: Option<String>,
    /// Set (under the slots lock) once this PTY no longer counts toward its
    /// sandbox's live limit: released, or an evicted detached PTY (WP8).
    sandbox_uncounted: Arc<AtomicBool>,
}

impl SlotGuard {
    /// The reap is uncertain: the slot stays charged, now counted as held
    /// by its reconciliation sweep ([`UncertainSlot`]).
    fn into_uncertain(self) -> UncertainSlot {
        let mut state = self.slots.lock();
        state.uncertain += 1;
        drop(state);
        self.slots.idle.notify_all();
        UncertainSlot(self)
    }

    fn release(self) {
        let mut state = self.slots.lock();
        state.live = state.live.saturating_sub(1);
        if let Some(creator) = &self.creator {
            state.guest_live = state.guest_live.saturating_sub(1);
            if let Some(count) = state.per_creator.get_mut(creator) {
                *count = count.saturating_sub(1);
            }
            if state.per_creator.get(creator) == Some(&0) {
                state.per_creator.remove(creator);
            }
        }
        if !self.sandbox_uncounted.swap(true, Ordering::AcqRel) {
            uncount_sandbox(&mut state, &self.sandbox_id);
        }
        drop(state);
        self.slots.idle.notify_all();
    }
}

fn uncount_sandbox(state: &mut SlotState, key: &str) {
    if let Some(count) = state.per_sandbox.get_mut(key) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            state.per_sandbox.remove(key);
        }
    }
}

/// A slot whose PTY reap is uncertain (C55). Only [`UncertainSlot::release`]
/// after a CONFIRMED reap frees it; dropping it keeps the slot charged
/// (never released optimistically).
#[derive(Debug)]
pub(super) struct UncertainSlot(SlotGuard);

impl UncertainSlot {
    fn release(self) {
        let mut state = self.0.slots.lock();
        state.uncertain = state.uncertain.saturating_sub(1);
        drop(state);
        self.0.release();
    }
}

impl TerminalSlots {
    pub(super) fn with_resume_grace(grace: Duration) -> Self {
        Self {
            state: Mutex::default(),
            idle: Condvar::new(),
            detached: DetachedTable::default(),
            resume_grace: clamp_resume_grace(grace),
        }
    }

    /// The hello's `terminalResume` offer: only a node that can open guest
    /// terminals offers to keep them.
    pub(super) fn resume_capability(
        &self,
        pty_capable: bool,
    ) -> Option<sandbox_protocol::TerminalResumeCapabilityV11> {
        pty_capable.then(|| sandbox_protocol::TerminalResumeCapabilityV11 {
            grace_ms: u64::try_from(self.resume_grace.as_millis()).unwrap_or(u64::MAX),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, SlotState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[cfg(test)]
    pub(super) fn try_acquire(
        self: &Arc<Self>,
        sandbox_id: &str,
        now: Instant,
    ) -> Result<SlotGuard, (SandboxErrorCode, &'static str)> {
        self.try_acquire_target(
            &TerminalTargetV11::Sandbox {
                sandbox_id: sandbox_id.into(),
                generation: 1,
            },
            Some(sandbox_id),
            now,
        )
    }
    #[cfg(test)]
    fn try_acquire_target(
        self: &Arc<Self>,
        target: &TerminalTargetV11,
        creator: Option<&str>,
        now: Instant,
    ) -> Result<SlotGuard, (SandboxErrorCode, &'static str)> {
        self.try_acquire_evicting(target, creator, now, None)
            .map(|(slot, _)| slot)
    }
    /// Charge one PTY slot. `evictable` (WP8) is the oldest detached PTY of
    /// the same sandbox: when the sandbox's live limit is the only thing in
    /// the way, it stops counting toward that limit (it is about to be
    /// closed; it stays charged to the host and creator caps until its reap)
    /// and the second value is `true`. Check and charge are one step.
    fn try_acquire_evicting(
        self: &Arc<Self>,
        target: &TerminalTargetV11,
        creator: Option<&str>,
        now: Instant,
        evictable: Option<&Arc<AtomicBool>>,
    ) -> Result<(SlotGuard, bool), (SandboxErrorCode, &'static str)> {
        let mut state = self.lock();
        while state
            .opens
            .front()
            .is_some_and(|(at, _)| now.saturating_duration_since(*at) >= OPEN_RATE_WINDOW)
        {
            state.opens.pop_front();
        }
        let guest = matches!(target, TerminalTargetV11::Sandbox { .. });
        if guest != creator.is_some() {
            return Err((
                SandboxErrorCode::AccessDenied,
                "terminal creator unavailable",
            ));
        }
        if state.opens.len() >= TERMINAL_OPENS_PER_MINUTE_PER_HOST
            || guest
                && (state.opens.iter().filter(|(_, c)| c.is_some()).count()
                    >= TERMINAL_OPENS_PER_MINUTE_PER_HOST
                        - sandbox_protocol::TERMINAL_RESERVED_HOST_OPENS_PER_MINUTE
                    || state
                        .opens
                        .iter()
                        .filter(|(_, c)| c.as_deref() == creator)
                        .count()
                        >= sandbox_protocol::TERMINAL_OPENS_PER_MINUTE_PER_GUEST_CREATOR)
        {
            return Err((SandboxErrorCode::RateLimited, "terminal open rate exceeded"));
        }
        let key = target_key(target);
        let in_sandbox = state.per_sandbox.get(&key).copied().unwrap_or(0);
        let evict = in_sandbox == TERMINAL_MAX_LIVE_SESSIONS_PER_SANDBOX
            && evictable.is_some_and(|flag| !flag.load(Ordering::Acquire));
        if state.live >= TERMINAL_MAX_SESSIONS_PER_HOST
            || in_sandbox >= TERMINAL_MAX_LIVE_SESSIONS_PER_SANDBOX && !evict
            || guest
                && (state.guest_live >= sandbox_protocol::TERMINAL_MAX_GUEST_SESSIONS_PER_HOST
                    || creator.is_some_and(|c| {
                        state.per_creator.get(c).copied().unwrap_or(0)
                            >= sandbox_protocol::TERMINAL_MAX_SESSIONS_PER_GUEST_CREATOR
                    }))
        {
            return Err((SandboxErrorCode::HostCapacity, "terminal capacity reached"));
        }
        if evict && let Some(flag) = evictable {
            flag.store(true, Ordering::Release);
            uncount_sandbox(&mut state, &key);
        }
        state.opens.push_back((now, creator.map(str::to_owned)));
        state.live += 1;
        *state.per_sandbox.entry(key.clone()).or_default() += 1;
        if let Some(creator) = creator {
            state.guest_live += 1;
            *state.per_creator.entry(creator.into()).or_default() += 1;
        }
        Ok((
            SlotGuard {
                slots: self.clone(),
                sandbox_id: key,
                creator: creator.map(str::to_owned),
                sandbox_uncounted: Arc::new(AtomicBool::new(false)),
            },
            evict,
        ))
    }

    #[cfg(test)]
    pub(super) fn in_sandbox(&self, sandbox_id: &str) -> usize {
        self.lock()
            .per_sandbox
            .get(&format!("sandbox:{sandbox_id}"))
            .copied()
            .unwrap_or(0)
    }

    #[cfg(test)]
    pub(super) fn detached_sessions(&self) -> usize {
        self.detached.lock().len()
    }

    #[cfg(test)]
    pub(super) fn live(&self) -> usize {
        self.lock().live
    }

    #[cfg(test)]
    pub(super) fn uncertain(&self) -> usize {
        self.lock().uncertain
    }

    /// Wait (bounded) until every PTY slot is released or held only by an
    /// uncertain reap's sweep (which shutdown cannot speed up). Shutdown only.
    pub(super) fn wait_idle(&self, bound: Duration) -> bool {
        let deadline = Instant::now() + bound;
        let mut state = self.lock();
        while state.live > state.uncertain {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            state = self
                .idle
                .wait_timeout(state, remaining)
                .map(|(guard, _)| guard)
                .unwrap_or_else(|e| e.into_inner().0);
        }
        true
    }
}

/// Daemon shutdown (carry-in: shutdown closes every PTY). The runtime-wide
/// close runs on its own thread, never the caller's; the caller then waits a
/// bounded time for the pumps to confirm their reaps.
pub(super) fn shutdown_terminals(
    runtime: &Arc<dyn SandboxRuntime>,
    slots: &TerminalSlots,
    bound: Duration,
) {
    let runtime = runtime.clone();
    let closer = thread::Builder::new()
        .name("wssp-terminal-shutdown".into())
        .spawn(move || {
            runtime.close_pty_sessions(None, PtyCloseIntent::Shutdown);
        });
    if closer.is_err() {
        tracing::warn!("terminal shutdown closer could not start; pumps close on their own");
    }
    if !slots.wait_idle(bound) {
        tracing::warn!("terminal sessions still closing at shutdown");
    }
    let uncertain = slots.lock().uncertain;
    if uncertain > 0 {
        tracing::warn!(uncertain, "terminal reaps still uncertain at shutdown");
    }
}

fn target_key(target: &TerminalTargetV11) -> String {
    match target {
        TerminalTargetV11::Host {} => "host".into(),
        TerminalTargetV11::Sandbox { sandbox_id, .. } => format!("sandbox:{sandbox_id}"),
    }
}

enum OpenRequest {
    Guest(OpenPtyRequest),
    Host {
        session_id: String,
        size: PtySize,
        opener: Arc<dyn sandbox_runtime::HostPtyOpener>,
        cancel: Arc<AtomicBool>,
    },
}
impl OpenRequest {
    #[cfg(test)]
    fn session_id(&self) -> &str {
        match self {
            Self::Guest(r) => &r.session_id,
            Self::Host { session_id, .. } => session_id,
        }
    }
    fn open(
        &self,
        runtime: &dyn SandboxRuntime,
    ) -> Result<PtySession, sandbox_runtime::PtyOpenFailure> {
        match self {
            Self::Guest(r) => runtime.open_pty(r),
            Self::Host {
                session_id,
                size,
                opener,
                cancel,
            } => opener.open(session_id, *size, cancel.clone()),
        }
    }
}

/// A session's sequenced PTY output (WP8). Every output frame is pushed here
/// with the next sequence; the socket loop forwards from it within the credit
/// window. It keeps at most [`RESUME_RING_BYTES`], evicting the oldest frames:
/// while attached the pump reads only within the window (at most 8 frames of
/// 16 KiB, well under the bound), so an unsent frame is never evicted; while
/// detached the pump keeps reading and the oldest output is lost, which a
/// resume reports as an `outputSeq` past the requested one.
#[derive(Debug, Default)]
pub(super) struct OutputRing {
    frames: VecDeque<(u64, Vec<u8>)>,
    bytes: usize,
    next: u64,
}

impl OutputRing {
    /// Append one frame (at most `TERMINAL_DATA_MAX_BYTES`); its sequence.
    /// Frames at or after `protect` (attached: the credit base, i.e. every
    /// unacknowledged frame, including a resume's promised replay range) are
    /// never evicted; the ring may then exceed its bound by the output of one
    /// outstanding read, until the server acknowledges.
    pub(super) fn push(&mut self, frame: Vec<u8>, protect: Option<u64>) -> u64 {
        while self.bytes + frame.len() > RESUME_RING_BYTES
            && self
                .frames
                .front()
                .is_some_and(|(sequence, _)| protect.is_none_or(|floor| *sequence < floor))
        {
            if let Some((_, old)) = self.frames.pop_front() {
                self.bytes -= old.len();
            }
        }
        let sequence = self.next;
        self.bytes += frame.len();
        self.frames.push_back((sequence, frame));
        self.next += 1;
        sequence
    }
    /// The sequence the next frame gets.
    pub(super) fn next(&self) -> u64 {
        self.next
    }
    /// The oldest sequence still held (`next` when empty).
    pub(super) fn first(&self) -> u64 {
        self.frames
            .front()
            .map_or(self.next, |(sequence, _)| *sequence)
    }
    pub(super) fn get(&self, sequence: u64) -> Option<&[u8]> {
        let index = usize::try_from(sequence.checked_sub(self.first())?).ok()?;
        self.frames.get(index).map(|(_, bytes)| bytes.as_slice())
    }
    #[cfg(test)]
    pub(super) fn bytes(&self) -> usize {
        self.bytes
    }
    /// Where a resume asking for `requested` continues: `requested` itself
    /// when still held (or exactly `next`), else the oldest held frame (the
    /// gap the browser is told about). `None` when `requested` is past
    /// anything this PTY ever produced (never answered with `ready`).
    pub(super) fn resume_from(&self, requested: u64) -> Option<u64> {
        (requested <= self.next).then(|| requested.max(self.first()))
    }
}

/// State shared by a session's pump and the socket loop (a leaf lock).
#[derive(Debug, Default)]
struct PtyState {
    ring: OutputRing,
    /// Output frames before this sequence were acknowledged by the server
    /// (or skipped by a resume): the credit window's base.
    acked: u64,
    /// Bumped on every detach and resume: control items and events of an
    /// older attachment are stale and dropped.
    attach: u64,
    /// `Some(deadline)` while detached (WP8).
    detached: Option<Instant>,
}

#[derive(Debug, Default)]
struct PtyShared(Mutex<PtyState>);

impl PtyShared {
    fn lock(&self) -> std::sync::MutexGuard<'_, PtyState> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// While detached, the pump's own C55 lease-authority check (the same one
/// every socket-loop tick applies), so a lapse closes the PTY at once even
/// when no relay connection exists.
type DetachedCheck = Arc<dyn Fn() -> Option<TerminalCloseIntent> + Send + Sync>;

enum Control {
    /// `(attach, sequence, bytes)`.
    Input(u64, u64, Vec<u8>),
    /// `(attach, request id, size)`; answered by `ready` when applied.
    Resize(u64, String, PtySize),
    /// WP8 `(attach, request id, size)`: always answered by `ready` with the
    /// size the PTY has (a failed resize keeps the old one).
    Resume(u64, String, PtySize),
}

#[derive(Debug)]
enum Event {
    Ready {
        attach: u64,
        request_id: String,
        rows: u16,
        cols: u16,
    },
    /// `(attach, sequence)`.
    InputAck(u64, u64),
    Exit {
        request_id: Option<String>,
        exit_code: Option<i32>,
        intent: Option<TerminalCloseIntent>,
        reaped: bool,
        error: Option<(SandboxErrorCode, String)>,
    },
    /// The reconciliation sweep confirmed an uncertain reap (C55); the slot
    /// is already released. Follows an `Exit { reaped: false }`.
    Reaped,
}

#[derive(Debug, Clone)]
struct StopRequest {
    intent: TerminalCloseIntent,
    request_id: Option<String>,
    error: Option<(SandboxErrorCode, String)>,
}

#[derive(Default)]
struct Stop {
    requested: Arc<AtomicBool>,
    request: Mutex<Option<StopRequest>>,
}

impl Stop {
    /// First request wins; never blocks on the pump.
    fn request(&self, request: StopRequest) {
        let mut slot = self.request.lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_none() {
            *slot = Some(request);
            self.requested.store(true, Ordering::Release);
        }
    }
    fn take(&self) -> Option<StopRequest> {
        if !self.requested.load(Ordering::Acquire) {
            return None;
        }
        self.request
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

struct Live {
    host_policy: Option<HostTerminalOpenPolicyV11>,
    opened_at: Instant,
    last_input: Instant,
    fence: TerminalFence,
    control: mpsc::SyncSender<Control>,
    events: mpsc::Receiver<Event>,
    stop: Arc<Stop>,
    ready: bool,
    /// Next expected server→host input sequence.
    input_next: u64,
    /// Input frames received and not yet acknowledged.
    input_unacked: u64,
    /// Output frames forwarded to the server so far.
    output_sent: u64,
    /// Output frames the server acknowledged (credit returned).
    output_acked: u64,
    violations: u32,
    /// CLI logins (§10.4 Free): the leases whose env this guest shell was
    /// opened with. When one leaves the daemon's memory (free, revoke,
    /// teardown) the session is closed: a freed login never stays in a shell.
    credential_leases: std::collections::BTreeSet<String>,
    /// The output ring, credit base, attachment and detach state (WP8).
    shared: Arc<PtyShared>,
    /// This side's attachment number (see [`PtyState::attach`]).
    attach: u64,
    /// WP8: an outstanding `terminal.resume` (request id, `outputSeq`).
    resume_answer: Option<(String, u64)>,
    /// The pump's exit, held until the output before it is forwarded.
    ended: Option<Ended>,
    /// When the session was detached (WP8); `None` while on a connection.
    detached_since: Option<Instant>,
    /// The slot's per-sandbox flag (eviction of a detached PTY, WP8).
    sandbox_uncounted: Arc<AtomicBool>,
}

/// A pump's final exit, as the socket loop forwards it.
#[derive(Debug)]
struct Ended {
    request_id: Option<String>,
    exit_code: Option<i32>,
    intent: Option<TerminalCloseIntent>,
    reaped: bool,
    error: Option<(SandboxErrorCode, String)>,
    /// Whether the reconciliation sweep can still confirm an uncertain reap.
    sweep: bool,
}

impl Live {
    fn sandbox_target(&self) -> bool {
        matches!(self.fence.target, TerminalTargetV11::Sandbox { .. })
    }

    fn stopping(&self) -> bool {
        self.stop.requested.load(Ordering::Acquire)
    }

    /// Record a pump event while no attachment can receive it: stale
    /// replies are dropped; the exit (and a later reap confirmation) is kept
    /// for a resume to report.
    fn absorb_detached(&mut self, event: Event) {
        match event {
            Event::Exit {
                request_id: _,
                exit_code,
                intent,
                reaped,
                error,
            } => {
                self.ended = Some(Ended {
                    request_id: None,
                    exit_code,
                    intent,
                    reaped,
                    error,
                    sweep: !reaped,
                });
            }
            Event::Reaped => {
                if let Some(ended) = &mut self.ended {
                    ended.reaped = true;
                    ended.sweep = false;
                }
            }
            Event::Ready { .. } | Event::InputAck(..) => {}
        }
    }

    /// Drain the pump's events (bounded) while detached.
    fn drain_detached(&mut self) {
        for _ in 0..EVENT_QUEUE {
            match self.events.try_recv() {
                Ok(event) => self.absorb_detached(event),
                Err(mpsc::TryRecvError::Empty) => return,
                Err(mpsc::TryRecvError::Disconnected) => {
                    if self.ended.is_none() {
                        self.ended = Some(Ended::pump_lost());
                    }
                    return;
                }
            }
        }
    }

    /// The relay connection ended: keep the PTY for `deadline` (WP8). Input
    /// queued for the old attachment is dropped by the pump, never written
    /// later; replies to it are discarded.
    fn detach(&mut self, now: Instant, deadline: Instant) {
        {
            let mut state = self.shared.lock();
            state.attach += 1;
            state.detached = Some(deadline);
            self.attach = state.attach;
        }
        self.ready = false;
        self.resume_answer = None;
        self.detached_since = Some(now);
        self.drain_detached();
    }
}

impl Ended {
    fn pump_lost() -> Self {
        Self {
            request_id: None,
            exit_code: None,
            intent: None,
            reaped: false,
            error: Some((
                SandboxErrorCode::Internal,
                "terminal pump ended without an exit".into(),
            )),
            sweep: false,
        }
    }
}

/// Only a proven cleanup-free failure may become retryable not-issued.
/// A typed failure's cleanup handle always keeps its original uncertainty.
pub(super) fn open_error_code(code: SandboxErrorCode) -> SandboxErrorCode {
    match code {
        SandboxErrorCode::UnknownOutcome => SandboxErrorCode::HostEffectNotIssued,
        other => other,
    }
}

fn pty_intent(intent: TerminalCloseIntent) -> PtyCloseIntent {
    match intent {
        TerminalCloseIntent::Detached | TerminalCloseIntent::HostDisconnected => {
            PtyCloseIntent::Detached
        }
        TerminalCloseIntent::Expired => PtyCloseIntent::Expired,
        TerminalCloseIntent::SandboxStopped => PtyCloseIntent::SandboxStopped,
        TerminalCloseIntent::SandboxDestroyed => PtyCloseIntent::SandboxDestroyed,
        TerminalCloseIntent::LifecycleUnconfirmed => PtyCloseIntent::LifecycleUnconfirmed,
        TerminalCloseIntent::Shutdown => PtyCloseIntent::Shutdown,
        TerminalCloseIntent::Client
        | TerminalCloseIntent::Replaced
        | TerminalCloseIntent::Backpressure
        | TerminalCloseIntent::Revoked
        | TerminalCloseIntent::Superseded
        | TerminalCloseIntent::ProtocolViolation => PtyCloseIntent::Client,
    }
}

fn wire_intent(intent: PtyCloseIntent) -> TerminalCloseIntent {
    match intent {
        PtyCloseIntent::Client => TerminalCloseIntent::Client,
        PtyCloseIntent::Detached => TerminalCloseIntent::Detached,
        PtyCloseIntent::Expired => TerminalCloseIntent::Expired,
        PtyCloseIntent::SandboxStopped => TerminalCloseIntent::SandboxStopped,
        PtyCloseIntent::SandboxDestroyed => TerminalCloseIntent::SandboxDestroyed,
        PtyCloseIntent::Shutdown => TerminalCloseIntent::Shutdown,
        PtyCloseIntent::LifecycleUnconfirmed => TerminalCloseIntent::LifecycleUnconfirmed,
    }
}

/// Unwind safety for one pump (C52-CC-3). The normal paths take the slot
/// (and the session) out of the guard, which then does nothing. If the pump
/// unwinds instead — debug and test builds; release builds abort on panic —
/// the guard closes the PTY on this same thread, releases the slot only after
/// a confirmed reap, and still sends the session's final `terminal.exit`.
struct PumpGuard {
    slot: Option<SlotGuard>,
    session: Option<PtySession>,
    events: mpsc::SyncSender<Event>,
}

impl Drop for PumpGuard {
    fn drop(&mut self) {
        let Some(slot) = self.slot.take() else {
            return;
        };
        let reaped = match self.session.take() {
            Some(mut session) => {
                let reaped = match session.close(PtyCloseIntent::Client) {
                    PtyTermination::Closed { reaped, .. } => reaped,
                    PtyTermination::ChildExited { .. } => true,
                };
                drop(session);
                reaped
            }
            // Unwound inside `open_pty`: whether a child started is unknown.
            None => false,
        };
        if reaped {
            slot.release();
        } else {
            // Unwinding (debug/test builds only): no sweep can run here, so
            // the slot stays charged for the process's life, counted as
            // uncertain so shutdown does not wait on it.
            std::mem::forget(slot.into_uncertain());
        }
        let _ = self.events.send(Event::Exit {
            request_id: None,
            exit_code: None,
            intent: None,
            reaped,
            error: Some((
                SandboxErrorCode::Internal,
                "terminal pump failed".to_string(),
            )),
        });
    }
}

/// The dedicated thread that owns one `PtySession` for its whole life.
#[allow(clippy::too_many_arguments)]
fn pump(
    runtime: Arc<dyn SandboxRuntime>,
    request: OpenRequest,
    open_request_id: String,
    control: mpsc::Receiver<Control>,
    events: mpsc::SyncSender<Event>,
    stop: Arc<Stop>,
    slot: SlotGuard,
    shared: Arc<PtyShared>,
    detached_check: Option<DetachedCheck>,
) {
    let mut guard = PumpGuard {
        slot: Some(slot),
        session: None,
        events: events.clone(),
    };
    let session = match request.open(runtime.as_ref()) {
        Ok(session) => guard.session.insert(session),
        Err(failure) => {
            let uncertain = failure.cleanup.is_some();
            guard.session = failure.cleanup;
            let slot = guard.slot.take().and_then(|slot| {
                if uncertain {
                    Some(slot.into_uncertain())
                } else {
                    slot.release();
                    None
                }
            });
            let _ = events.send(Event::Exit {
                request_id: Some(open_request_id),
                exit_code: None,
                intent: None,
                reaped: !uncertain,
                error: Some((
                    if uncertain {
                        failure.error.code
                    } else {
                        open_error_code(failure.error.code)
                    },
                    "terminal setup failed".into(),
                )),
            });
            if let (Some(slot), Some(session)) = (slot, guard.session.as_mut()) {
                reconcile_reap(session, slot, &events);
            }
            return;
        }
    };
    #[cfg(test)]
    pump_faults::after_open(request.session_id());
    if stop.requested.load(Ordering::Acquire) {
        let reaped = !matches!(
            session.close(PtyCloseIntent::Client),
            PtyTermination::Closed { reaped: false, .. }
        );
        let _ = events.send(Event::Exit {
            request_id: Some(open_request_id),
            exit_code: None,
            intent: stop.take().map(|s| s.intent),
            reaped,
            error: None,
        });
        if let Some(slot) = guard.slot.take() {
            if reaped {
                slot.release();
            } else if let Some(session) = guard.session.as_mut() {
                reconcile_reap(session, slot.into_uncertain(), &events);
            }
        }
        return;
    }
    let size = session.size();
    // Ready precedes any output or exit of this session on the wire.
    let mut connected = events
        .send(Event::Ready {
            attach: shared.lock().attach,
            request_id: open_request_id.clone(),
            rows: size.rows(),
            cols: size.cols(),
        })
        .is_ok();
    // `(attach, sequence, bytes)`: input keeps the attachment it came from.
    let mut pending: VecDeque<(u64, u64, Vec<u8>)> = VecDeque::new();
    let mut requested: Option<StopRequest> = None;
    let mut last_check = Instant::now();
    let termination = loop {
        if !connected {
            requested.get_or_insert(StopRequest {
                intent: TerminalCloseIntent::HostDisconnected,
                request_id: None,
                error: None,
            });
        }
        if let Some(stop) = stop.take() {
            requested.get_or_insert(stop);
        }
        // WP8: a detached PTY refuses input, ends at its deadline, and
        // re-checks its own lease authority (no socket loop may be running).
        let detached = shared.lock().detached;
        if let Some(deadline) = detached {
            pending.clear();
            let now = Instant::now();
            if now >= deadline {
                requested.get_or_insert(StopRequest {
                    intent: TerminalCloseIntent::HostDisconnected,
                    request_id: None,
                    error: None,
                });
            } else if now.saturating_duration_since(last_check) >= DETACHED_CHECK_INTERVAL {
                last_check = now;
                if let Some(intent) = detached_check.as_ref().and_then(|check| check()) {
                    requested.get_or_insert(StopRequest {
                        intent,
                        request_id: None,
                        error: None,
                    });
                }
            }
        }
        if let Some(stop) = &requested {
            break session.close(pty_intent(stop.intent));
        }
        while let Ok(item) = control.try_recv() {
            // Items of an older attachment (or any while detached) are stale.
            let (attach, detached) = {
                let state = shared.lock();
                (state.attach, state.detached.is_some())
            };
            match item {
                Control::Input(at, sequence, bytes) => {
                    if at == attach && !detached {
                        pending.push_back((at, sequence, bytes));
                    }
                }
                Control::Resize(at, request_id, size) => {
                    if at == attach && !detached && session.resize(size).is_ok() {
                        connected &= events
                            .send(Event::Ready {
                                attach: at,
                                request_id,
                                rows: size.rows(),
                                cols: size.cols(),
                            })
                            .is_ok();
                    }
                }
                Control::Resume(at, request_id, size) => {
                    if at == attach && !detached {
                        let _ = session.resize(size);
                        let size = session.size();
                        connected &= events
                            .send(Event::Ready {
                                attach: at,
                                request_id,
                                rows: size.rows(),
                                cols: size.cols(),
                            })
                            .is_ok();
                    }
                }
            }
        }
        while let Some((at, sequence, bytes)) = pending.front() {
            if stop.requested.load(Ordering::Acquire) {
                break;
            }
            #[cfg(test)]
            pump_faults::checkpoint("before_write", request.session_id());
            // The write happens under the shared lock, so a detach (or a new
            // attachment) cannot slip between this check and the write:
            // input of an attachment that is no longer current, or any input
            // while detached, never reaches the PTY. `write_input` only
            // enqueues (never blocks), so the leaf lock is held briefly.
            let written = {
                let state = shared.lock();
                if state.attach != *at || state.detached.is_some() {
                    None
                } else {
                    Some(session.write_input(bytes))
                }
            };
            match written {
                // Stale: dropped, never written and never acknowledged.
                None => {
                    pending.pop_front();
                }
                Some(Ok(())) => {
                    // Acknowledged under the attachment it came from.
                    connected &= events.send(Event::InputAck(*at, *sequence)).is_ok();
                    pending.pop_front();
                }
                // The PTY input queue is full: retry next turn; the server
                // never has more than the input window outstanding.
                Some(Err(error)) if error.code == SandboxErrorCode::RateLimited => break,
                Some(Err(_)) => break,
            }
        }
        // Attached: read only within the server's credit window, so the PTY
        // back-pressures the shell. Detached: keep reading into the ring.
        let credit = {
            let state = shared.lock();
            state.detached.is_some()
                || state.ring.next().saturating_sub(state.acked) < TERMINAL_OUTPUT_WINDOW_FRAMES
        };
        if !credit {
            thread::sleep(PUMP_WAIT);
            if let Some(termination) = session.termination()
                && matches!(termination, PtyTermination::Closed { .. })
            {
                break termination;
            }
            continue;
        }
        match session.next_event(PUMP_WAIT) {
            Ok(Some(PtyEvent::Output(bytes))) => {
                #[cfg(test)]
                pump_faults::checkpoint("before_push", request.session_id());
                // The mode is re-read with the push: a resume may have
                // attached while this read was outstanding, and then every
                // frame from its promised `outputSeq` (the credit base) is
                // protected from eviction.
                let mut state = shared.lock();
                let protect = state.detached.is_none().then_some(state.acked);
                if bytes.len() <= sandbox_protocol::TERMINAL_DATA_MAX_BYTES {
                    // One frame's worth: push the read buffer itself. An
                    // empty read pushes nothing, as `chunks` would.
                    if !bytes.is_empty() {
                        state.ring.push(bytes, protect);
                    }
                } else {
                    for chunk in bytes.chunks(sandbox_protocol::TERMINAL_DATA_MAX_BYTES) {
                        state.ring.push(chunk.to_vec(), protect);
                    }
                }
            }
            Ok(Some(PtyEvent::Ended(termination))) => break termination,
            Ok(None) => {}
            Err(error) => {
                requested.get_or_insert(StopRequest {
                    intent: TerminalCloseIntent::Client,
                    request_id: None,
                    error: Some((error.code, "terminal setup failed".into())),
                });
                break session.close(PtyCloseIntent::Client);
            }
        }
    };
    // Close is idempotent; the session is closed and dropped on THIS thread.
    let termination = match termination {
        PtyTermination::Closed { .. } => termination,
        exited => {
            session.close(PtyCloseIntent::Client);
            exited
        }
    };
    let (exit_code, intent, reaped) = match termination {
        PtyTermination::ChildExited { exit_code } => (exit_code, None, true),
        PtyTermination::Closed {
            intent,
            exit_code,
            reaped,
        } => (
            exit_code,
            Some(
                requested
                    .as_ref()
                    .map_or_else(|| wire_intent(intent), |stop| stop.intent),
            ),
            reaped,
        ),
    };
    let slot = guard.slot.take();
    let uncertain = match slot {
        Some(slot) if reaped => {
            drop(guard.session.take());
            slot.release();
            None
        }
        // Reap uncertain: the child may still hold host resources; the slot
        // stays charged (C51 `reaped: false` contract) and this thread keeps
        // the session to reconcile it (C55).
        Some(slot) => Some(slot.into_uncertain()),
        None => None,
    };
    let (request_id, error) = requested
        .map(|stop| (stop.request_id, stop.error))
        .unwrap_or((None, None));
    let _ = events.send(Event::Exit {
        request_id,
        exit_code: if intent.is_some() { None } else { exit_code },
        intent,
        reaped,
        error,
    });
    if let (Some(slot), Some(session)) = (uncertain, guard.session.as_mut()) {
        reconcile_reap(session, slot, &events);
    }
    drop(guard.session.take());
}

/// The reconciliation sweep for one uncertain reap (C52-F-4 / C55): retry
/// the reap on this pump thread until the runtime CONFIRMS it, then release
/// the slot and report the confirmation. There is no timeout that releases
/// the slot: a child that is never reaped keeps it charged for the life of
/// the process (bounded by the per-host cap), exactly as the contract says.
fn reconcile_reap(session: &mut PtySession, slot: UncertainSlot, events: &mpsc::SyncSender<Event>) {
    loop {
        if session.reap_confirmed() {
            slot.release();
            // A gone connection is fine: its server count ended with it.
            let _ = events.send(Event::Reaped);
            return;
        }
        thread::sleep(REAP_SWEEP_INTERVAL);
    }
}

/// Per-connection terminal dispatch (lives on the socket-loop thread).
pub(super) struct TerminalHost {
    slots: Arc<TerminalSlots>,
    runtime: Arc<dyn SandboxRuntime>,
    journal: Arc<HostJournal>,
    authority: HostAuthority,
    host_id: String,
    /// Set by the validated 1.0 `hello.ok`.
    epoch: Option<u64>,
    binding: Option<TransportBindingV11>,
    sessions: HashMap<String, Live>,
    /// Sessions that exited with an uncertain reap, awaiting their sweep's
    /// confirmation (C55). Bounded by the per-host slot cap.
    unreaped: HashMap<String, (TerminalFence, mpsc::Receiver<Event>)>,
    tombstones: VecDeque<String>,
    audits: usize,
    host_policy: super::host_policy::Policy,
    host_opener: Option<Arc<dyn sandbox_runtime::HostPtyOpener>>,
    /// CLI logins: installed credential env joins guest shells (§10.6).
    credentials: Option<super::credentials::service::CredentialService>,
    /// WP7: the process-wide quiesce request, read at each open (never a
    /// snapshot: SIGUSR1 may land while the session blocks in a read).
    quiesce: Option<Arc<super::quiesce::QuiesceState>>,
    /// WP8: this connection's `hello.ok` answered `terminalResume: true`.
    resume: bool,
}

/// C55 lease authority of a sandbox terminal: `None` while it may run.
fn sandbox_refusal(
    journal: &HostJournal,
    authority: &HostAuthority,
    credentials: Option<&super::credentials::service::CredentialService>,
    sandbox_id: &str,
    generation: u64,
    credential_leases: &std::collections::BTreeSet<String>,
) -> Option<TerminalCloseIntent> {
    let current = journal
        .lease(sandbox_id)
        .is_some_and(|row| row.generation == generation)
        && !authority.terminal_superseded(sandbox_id, generation);
    if !current {
        Some(TerminalCloseIntent::Superseded)
    } else if !journal.work_allowed(sandbox_id, generation, "terminal.open") {
        Some(TerminalCloseIntent::Expired)
    } else if !credential_leases.is_empty()
        && credentials.is_none_or(|service| {
            let installed = service.installed_env_leases(sandbox_id);
            !credential_leases.is_subset(&installed)
        })
    {
        // A login this shell was opened with was freed or revoked.
        Some(TerminalCloseIntent::Revoked)
    } else {
        None
    }
}

impl TerminalHost {
    pub(super) fn new(
        slots: Arc<TerminalSlots>,
        runtime: Arc<dyn SandboxRuntime>,
        journal: Arc<HostJournal>,
        authority: HostAuthority,
        host_id: String,
    ) -> Self {
        Self {
            slots,
            runtime,
            journal,
            authority,
            host_id,
            epoch: None,
            binding: None,
            sessions: HashMap::new(),
            unreaped: HashMap::new(),
            tombstones: VecDeque::new(),
            audits: 0,
            host_policy: super::host_policy::Policy {
                enabled: false,
                required: true,
                revision: 0,
            },
            host_opener: None,
            credentials: None,
            quiesce: None,
            resume: false,
        }
    }

    /// WP7: refuse new terminal opens while quiescing (live ones continue
    /// until the restart's shutdown closes them).
    pub(super) fn set_quiesce(&mut self, quiesce: Arc<super::quiesce::QuiesceState>) {
        self.quiesce = Some(quiesce);
    }

    /// WP8: whether this connection's `hello.ok` answered `terminalResume`.
    /// Without it every session closes with its connection, as before.
    pub(super) fn negotiate_resume(&mut self, negotiated: bool) {
        self.resume = negotiated;
    }

    /// The process's credential service (CLI logins), once it exists.
    pub(super) fn set_credentials(
        &mut self,
        credentials: Option<super::credentials::service::CredentialService>,
    ) {
        self.credentials = credentials;
    }

    pub(super) fn configure_host(
        &mut self,
        policy: super::host_policy::Policy,
        opener: Option<Arc<dyn sandbox_runtime::HostPtyOpener>>,
    ) {
        if self.host_policy != policy {
            for live in self.sessions.values() {
                if matches!(live.fence.target, TerminalTargetV11::Host {}) {
                    live.stop.request(StopRequest {
                        intent: TerminalCloseIntent::Revoked,
                        request_id: None,
                        error: None,
                    });
                }
            }
        }
        self.host_policy = policy;
        self.host_opener = opener;
    }

    /// `hello.ok` established the current connection epoch.
    pub(super) fn enable(&mut self, epoch: u64, binding: TransportBindingV11) {
        self.epoch = Some(epoch);
        self.binding = Some(binding);
    }

    #[cfg(test)]
    pub(super) fn live_sessions(&self) -> usize {
        self.sessions.len()
    }

    #[cfg(test)]
    pub(super) fn unreaped_sessions(&self) -> usize {
        self.unreaped.len()
    }

    /// Per-frame lease authority (C52-F-2): the same check every tick makes,
    /// applied to each input frame before any byte reaches the pump.
    fn input_allowed(&self, live: &Live) -> Option<TerminalCloseIntent> {
        let fence = &live.fence;
        let TerminalTargetV11::Sandbox {
            sandbox_id,
            generation,
        } = &fence.target
        else {
            if !self.host_policy.enabled
                || live.host_policy.as_ref().is_none_or(|p| {
                    p.policy_revision != self.host_policy.revision
                        || p.proof_required != self.host_policy.required
                })
            {
                return Some(TerminalCloseIntent::Revoked);
            }
            if Instant::now()
                .saturating_duration_since(live.opened_at)
                .as_millis()
                >= u128::from(sandbox_protocol::TERMINAL_HOST_MAX_LIFETIME_MS)
                || Instant::now()
                    .saturating_duration_since(live.last_input)
                    .as_millis()
                    >= u128::from(sandbox_protocol::TERMINAL_HOST_INPUT_IDLE_MS)
            {
                return Some(TerminalCloseIntent::Expired);
            }
            return None;
        };
        sandbox_refusal(
            &self.journal,
            &self.authority,
            self.credentials.as_ref(),
            sandbox_id,
            *generation,
            &live.credential_leases,
        )
    }

    fn audit(&mut self, reason: &str, session_id: &str) {
        if self.audits < AUDIT_LOGS {
            self.audits += 1;
            tracing::warn!("terminal frame dropped ({reason}) session={session_id}");
        }
    }

    fn exit_now(
        request_id: &str,
        fence: &TerminalFence,
        code: SandboxErrorCode,
        message: &str,
    ) -> Outgoing {
        Outgoing::Text(Box::new(DaemonControlMessage::TerminalExit {
            request_id: Some(request_id.to_string()),
            fence: fence.clone(),
            exit_code: None,
            intent: None,
            reaped: true,
            error: Some(ProtocolErrorDetail {
                reason: None,
                code: code.into(),
                message: message.to_string(),
                operation_id: None,
                sandbox_id: match &fence.target {
                    TerminalTargetV11::Sandbox { sandbox_id, .. } => Some(sandbox_id.clone()),
                    _ => None,
                },
            }),
        }))
    }

    /// Connection-level fence (host + epoch). A mismatch is a foreign frame.
    fn connection_matches(&self, fence: &TerminalFence) -> Result<bool> {
        let Some(epoch) = self.epoch else {
            bail!("terminal frame before a negotiated terminal session");
        };
        Ok(fence.host_id == self.host_id && fence.epoch == epoch)
    }

    /// The live session the frame names, with its full fence matched. A
    /// mismatching frame for a live session is a counted violation.
    fn session_for(&mut self, fence: &TerminalFence) -> Result<Option<&mut Live>> {
        let matches = self.connection_matches(fence)?;
        let known = self.sessions.contains_key(&fence.session_id);
        if !known {
            if !self.tombstones.contains(&fence.session_id) {
                self.audit("foreign terminal frame", &fence.session_id.clone());
            }
            return Ok(None);
        }
        let exact = matches
            && self
                .sessions
                .get(&fence.session_id)
                .is_some_and(|live| live.fence == *fence);
        if !exact {
            self.audit("terminal fence mismatch", &fence.session_id.clone());
            self.violation(&fence.session_id);
            return Ok(None);
        }
        Ok(self.sessions.get_mut(&fence.session_id))
    }

    fn violation(&mut self, session_id: &str) {
        if let Some(live) = self.sessions.get_mut(session_id) {
            live.violations += 1;
            if live.violations >= TERMINAL_FENCE_VIOLATION_LIMIT {
                live.stop.request(StopRequest {
                    intent: TerminalCloseIntent::ProtocolViolation,
                    request_id: None,
                    error: Some((
                        SandboxErrorCode::ProtocolError,
                        "repeated terminal protocol violations".into(),
                    )),
                });
            }
        }
    }

    /// Server terminal control frames. Returns frames to send immediately.
    pub(super) fn handle_control(
        &mut self,
        message: ServerControlMessage,
    ) -> Result<Vec<Outgoing>> {
        match message {
            ServerControlMessage::TerminalOpen {
                host_policy,
                request_id,
                fence,
                rows,
                cols,
                cwd,
            } => self.open(request_id, fence, rows, cols, host_policy, cwd),
            ServerControlMessage::TerminalResize {
                request_id,
                fence,
                rows,
                cols,
            } => {
                let violated = match (self.session_for(&fence)?, PtySize::new(rows, cols)) {
                    (Some(live), _)
                        if !live.ready || live.stop.requested.load(Ordering::Acquire) =>
                    {
                        false
                    }
                    (Some(live), Ok(size)) => live
                        .control
                        .try_send(Control::Resize(live.attach, request_id, size))
                        .is_err(),
                    (Some(_), Err(_)) => true,
                    (None, _) => false,
                };
                if violated {
                    self.violation(&fence.session_id);
                }
                Ok(Vec::new())
            }
            ServerControlMessage::TerminalClose {
                request_id,
                fence,
                intent,
            } => {
                if let Some(live) = self.session_for(&fence)? {
                    live.stop.request(StopRequest {
                        intent,
                        request_id: Some(request_id),
                        error: None,
                    });
                }
                Ok(Vec::new())
            }
            ServerControlMessage::TerminalResume {
                request_id,
                fence,
                next_output_seq,
                rows,
                cols,
            } => self.resume(request_id, fence, next_output_seq, rows, cols),
            ServerControlMessage::TerminalAck { fence, sequence } => {
                let violated = match self.session_for(&fence)? {
                    Some(live) if sequence >= live.output_acked && sequence < live.output_sent => {
                        live.output_acked = sequence + 1;
                        // The pump reads the credit base from the shared state.
                        let mut state = live.shared.lock();
                        state.acked = state.acked.max(live.output_acked);
                        false
                    }
                    Some(_) => true,
                    None => false,
                };
                if violated {
                    self.violation(&fence.session_id);
                }
                Ok(Vec::new())
            }
            _ => Ok(Vec::new()),
        }
    }

    /// Server→host input bytes. A fence mismatch, duplicate, gap or window
    /// overrun writes ZERO bytes to the PTY.
    pub(super) fn handle_input(
        &mut self,
        metadata: TerminalDataMetadata,
        body: Vec<u8>,
    ) -> Result<()> {
        let fence = metadata.fence;
        if self.session_for(&fence)?.is_none() {
            return Ok(());
        }
        // C52-F-2: lease, generation and supersession are re-checked for
        // EVERY input frame, not only once per tick: input arriving after a
        // supersession or expiry writes zero bytes and stops the session.
        let refused = self
            .sessions
            .get(&fence.session_id)
            .and_then(|live| self.input_allowed(live));
        let Some(live) = self.sessions.get_mut(&fence.session_id) else {
            return Ok(());
        };
        if let Some(intent) = refused {
            live.stop.request(StopRequest {
                intent,
                request_id: None,
                error: None,
            });
            return Ok(());
        }
        if !live.ready || live.stop.requested.load(Ordering::Acquire) {
            return Ok(());
        }
        let nonempty = !body.is_empty();
        let violated = if metadata.sequence < live.input_next {
            // Duplicate or replayed input.
            true
        } else if metadata.sequence > live.input_next {
            // A gap on an ordered transport: the input stream lost integrity.
            live.stop.request(StopRequest {
                intent: TerminalCloseIntent::ProtocolViolation,
                request_id: None,
                error: Some((
                    SandboxErrorCode::ProtocolError,
                    "terminal input sequence gap".into(),
                )),
            });
            false
        } else if live.input_unacked >= TERMINAL_INPUT_WINDOW_FRAMES {
            // The server overran the input window.
            true
        } else if live
            .control
            .try_send(Control::Input(live.attach, metadata.sequence, body))
            .is_ok()
        {
            if nonempty {
                live.last_input = Instant::now();
            }
            live.input_next += 1;
            live.input_unacked += 1;
            false
        } else {
            true
        };
        if violated {
            self.violation(&fence.session_id);
        }
        Ok(())
    }

    fn open(
        &mut self,
        request_id: String,
        fence: TerminalFence,
        rows: u16,
        cols: u16,
        host_policy: Option<HostTerminalOpenPolicyV11>,
        cwd: Option<String>,
    ) -> Result<Vec<Outgoing>> {
        if !self.connection_matches(&fence)? {
            self.audit("foreign terminal open", &fence.session_id.clone());
            return Ok(Vec::new());
        }
        if self.sessions.contains_key(&fence.session_id)
            || self.tombstones.contains(&fence.session_id)
        {
            // A reused session id never reaches a PTY (and never ends the
            // live session it collides with).
            self.audit("duplicate terminal open", &fence.session_id.clone());
            self.violation(&fence.session_id);
            return Ok(Vec::new());
        }
        let refuse =
            |code, message: &str| Ok(vec![Self::exit_now(&request_id, &fence, code, message)]);
        if self.quiesce.as_ref().is_some_and(|q| q.quiescing()) {
            return refuse(
                SandboxErrorCode::Disconnected,
                "host is restarting; try again shortly",
            );
        }
        let Ok(size) = PtySize::new(rows, cols) else {
            return refuse(SandboxErrorCode::ProtocolError, "invalid terminal size");
        };
        let stop = Arc::new(Stop::default());
        let mut credential_leases = std::collections::BTreeSet::new();
        let (request, creator) = match &fence.target {
            TerminalTargetV11::Host {} => {
                if cwd.is_some() {
                    return refuse(SandboxErrorCode::ProtocolError, "invalid host terminal cwd");
                }
                if !self.host_policy.enabled
                    || host_policy.as_ref().is_none_or(|p| {
                        p.policy_revision != self.host_policy.revision
                            || p.proof_required != self.host_policy.required
                    })
                {
                    return refuse(
                        SandboxErrorCode::AccessDenied,
                        "host terminal policy changed",
                    );
                }
                let Some(opener) = self.host_opener.clone() else {
                    return refuse(
                        SandboxErrorCode::UnsupportedCapability,
                        "host terminal unavailable",
                    );
                };
                (
                    OpenRequest::Host {
                        session_id: fence.session_id.clone(),
                        size,
                        opener,
                        cancel: stop.requested.clone(),
                    },
                    None,
                )
            }
            TerminalTargetV11::Sandbox {
                sandbox_id,
                generation,
            } => {
                if host_policy.is_some() {
                    return refuse(
                        SandboxErrorCode::ProtocolError,
                        "invalid guest terminal policy",
                    );
                }
                // The journal binding is the only identity source (carry-in 3).
                let Some(record) = self.journal.lease(sandbox_id) else {
                    return refuse(
                        SandboxErrorCode::SandboxNotFound,
                        "sandbox has no accepted lease",
                    );
                };
                let bound = self.binding.as_ref().is_some_and(|b| *b == record.binding);
                if !bound
                    || record.generation != *generation
                    || !self
                        .journal
                        .work_allowed(sandbox_id, *generation, "terminal.open")
                    || self.authority.terminal_superseded(sandbox_id, *generation)
                {
                    return refuse(
                        SandboxErrorCode::StateConflict,
                        "terminal binding is not the current sandbox generation",
                    );
                }
                // D1: build VMs (which may run guest root) never open a terminal.
                if record.build_id.is_some() {
                    return refuse(
                        SandboxErrorCode::UnsupportedCapability,
                        "build sandboxes have no terminal",
                    );
                }
                let (Some(template_fingerprint), Some(guest)) =
                    (record.template_fingerprint.clone(), record.guest.clone())
                else {
                    return refuse(
                        SandboxErrorCode::UnsupportedCapability,
                        "sandbox has no recorded terminal identity",
                    );
                };
                if !self.runtime.pty_capability() {
                    return refuse(
                        SandboxErrorCode::UnsupportedCapability,
                        "Unsupported capability: terminal",
                    );
                }
                let mut env = match self.journal.execution_env(
                    sandbox_id,
                    *generation,
                    record.private_config.as_ref(),
                ) {
                    Ok(env) => env,
                    Err(_) => {
                        return refuse(SandboxErrorCode::ProtocolError, "terminal setup failed");
                    }
                };
                // §10.6: private defaults ∪ installed credential env (memory
                // only; names never collide, admission refuses that). Env
                // still being restored after a daemon restart is retryable.
                if let Some(service) = &self.credentials {
                    match service.env_with_leases(sandbox_id) {
                        Ok((extra, leases)) => {
                            for (name, value) in extra {
                                if !env.iter().any(|(existing, _)| *existing == name) {
                                    env.push((name, value));
                                }
                            }
                            credential_leases = leases;
                        }
                        Err(_) => {
                            return refuse(
                                SandboxErrorCode::CredentialEnvPending,
                                "credential env pending",
                            );
                        }
                    }
                }
                // The duration cap applies to every env-bearing shell: private
                // env or any env-bearing login lease (§10.4 daemon restart row).
                let max_duration = if env.is_empty() && credential_leases.is_empty() {
                    None
                } else {
                    let now = match self.journal.clock.now_ms() {
                        Ok(now) => now,
                        Err(_) => {
                            return refuse(
                                SandboxErrorCode::ProtocolError,
                                "terminal setup failed",
                            );
                        }
                    };
                    let remaining =
                        Duration::from_millis(record.lease.deadline_unix_ms.saturating_sub(now));
                    if remaining.is_zero() {
                        return refuse(SandboxErrorCode::StateConflict, "terminal setup failed");
                    }
                    Some(remaining.min(sandbox_runtime::PTY_DEFAULT_SESSION))
                };
                let request = OpenPtyRequest {
                    template_fingerprint,
                    sandbox_id: sandbox_id.clone(),
                    session_id: fence.session_id.clone(),
                    guest: guest.identity(),
                    size,
                    max_duration,
                    env,
                    // The revision's default cwd (frame-validated); the
                    // runtime validates it again as a guest path.
                    cwd,
                    setup_cancel: stop.requested.clone(),
                };
                (
                    OpenRequest::Guest(request),
                    Some(record.sandbox_owner_id.clone()),
                )
            }
        };
        // WP8: detached PTYs count toward the sandbox's live limit; an open
        // beyond it evicts the oldest DETACHED one (never an attached one).
        let evictable = self.oldest_detached(&fence.target);
        let (slot, evicted) = match self.slots.try_acquire_evicting(
            &fence.target,
            creator.as_deref(),
            Instant::now(),
            evictable.as_ref().map(|(_, flag)| flag),
        ) {
            Ok(acquired) => acquired,
            Err((code, message)) => return refuse(code, message),
        };
        if evicted && let Some((id, _)) = &evictable {
            let removed = self.slots.detached.lock().remove(id);
            if let Some(live) = removed {
                live.stop.request(StopRequest {
                    intent: TerminalCloseIntent::Replaced,
                    request_id: None,
                    error: None,
                });
            }
        }
        let detached_check: Option<DetachedCheck> = match &fence.target {
            TerminalTargetV11::Sandbox {
                sandbox_id,
                generation,
            } => {
                let journal = self.journal.clone();
                let authority = self.authority.clone();
                let credentials = self.credentials.clone();
                let sandbox_id = sandbox_id.clone();
                let generation = *generation;
                let leases = credential_leases.clone();
                Some(Arc::new(move || {
                    sandbox_refusal(
                        &journal,
                        &authority,
                        credentials.as_ref(),
                        &sandbox_id,
                        generation,
                        &leases,
                    )
                }))
            }
            TerminalTargetV11::Host {} => None,
        };
        let shared = Arc::new(PtyShared::default());
        let sandbox_uncounted = slot.sandbox_uncounted.clone();
        let (control_tx, control_rx) = mpsc::sync_channel(CONTROL_QUEUE);
        let (events_tx, events_rx) = mpsc::sync_channel(EVENT_QUEUE);
        let runtime = self.runtime.clone();
        let pump_stop = stop.clone();
        let pump_shared = shared.clone();
        let open_request_id = request_id.clone();
        // The slot moves into the pump; if the spawn fails the closure is
        // dropped with it, and a never-started PTY must not stay charged.
        let slots = self.slots.clone();
        let sandbox_id = target_key(&fence.target);
        let slot_creator = creator.clone();
        let slot_flag = sandbox_uncounted.clone();
        let spawned = thread::Builder::new()
            .name("wssp-terminal-pump".into())
            .spawn(move || {
                pump(
                    runtime,
                    request,
                    open_request_id,
                    control_rx,
                    events_tx,
                    pump_stop,
                    slot,
                    pump_shared,
                    detached_check,
                )
            });
        if spawned.is_err() {
            SlotGuard {
                slots,
                sandbox_id,
                creator: slot_creator,
                sandbox_uncounted: slot_flag,
            }
            .release();
            return refuse(
                SandboxErrorCode::HostEffectNotIssued,
                "terminal pump could not start",
            );
        }
        self.sessions.insert(
            fence.session_id.clone(),
            Live {
                host_policy,
                opened_at: Instant::now(),
                last_input: Instant::now(),
                fence,
                control: control_tx,
                events: events_rx,
                stop,
                ready: false,
                input_next: 0,
                input_unacked: 0,
                output_sent: 0,
                output_acked: 0,
                violations: 0,
                credential_leases,
                shared,
                attach: 0,
                resume_answer: None,
                ended: None,
                detached_since: None,
                sandbox_uncounted,
            },
        );
        Ok(Vec::new())
    }

    /// WP8: the oldest detached PTY of `target`'s sandbox that still counts
    /// toward its live limit (the one a new open may evict).
    fn oldest_detached(&self, target: &TerminalTargetV11) -> Option<(String, Arc<AtomicBool>)> {
        let TerminalTargetV11::Sandbox { .. } = target else {
            return None;
        };
        let key = target_key(target);
        self.slots
            .detached
            .lock()
            .iter()
            .filter(|(_, live)| {
                target_key(&live.fence.target) == key
                    && !live.sandbox_uncounted.load(Ordering::Acquire)
            })
            .min_by_key(|(_, live)| (live.detached_since, live.opened_at))
            .map(|(id, live)| (id.clone(), live.sandbox_uncounted.clone()))
    }

    /// WP8 `terminal.resume`: rebind a detached sandbox PTY to this
    /// connection under the new fence. The terminal id, sandbox and
    /// generation must all match the daemon's own record of the PTY, and the
    /// same lease, generation and transport-binding gates as an open apply.
    /// Answered by `ready` with `outputSeq` (from `poll`), or `terminal.exit`.
    fn resume(
        &mut self,
        request_id: String,
        fence: TerminalFence,
        next_output_seq: u64,
        rows: u16,
        cols: u16,
    ) -> Result<Vec<Outgoing>> {
        if !self.connection_matches(&fence)? {
            self.audit("foreign terminal resume", &fence.session_id.clone());
            return Ok(Vec::new());
        }
        if self.sessions.contains_key(&fence.session_id)
            || self.tombstones.contains(&fence.session_id)
        {
            // Never takes over (or ends) a session live on this connection.
            self.audit("duplicate terminal resume", &fence.session_id.clone());
            self.violation(&fence.session_id);
            return Ok(Vec::new());
        }
        let refuse =
            |code, message: &str| Ok(vec![Self::exit_now(&request_id, &fence, code, message)]);
        if !self.resume {
            return refuse(
                SandboxErrorCode::UnsupportedCapability,
                "Unsupported capability: terminalResume",
            );
        }
        let TerminalTargetV11::Sandbox { sandbox_id, .. } = &fence.target else {
            // Host-target terminals are never detached, so never resumed.
            return refuse(
                SandboxErrorCode::UnsupportedCapability,
                "host terminals cannot be resumed",
            );
        };
        let Ok(size) = PtySize::new(rows, cols) else {
            return refuse(SandboxErrorCode::ProtocolError, "invalid terminal size");
        };
        // Identity: only the PTY recorded under this terminal id, for this
        // very sandbox and generation on this host. Any mismatch leaves the
        // detached PTY untouched and reveals nothing about it.
        let taken = {
            let mut table = self.slots.detached.lock();
            let same_pty = table.get(&fence.session_id).is_some_and(|live| {
                live.fence.target == fence.target && live.fence.host_id == fence.host_id
            });
            same_pty.then(|| table.remove(&fence.session_id)).flatten()
        };
        let Some(mut live) = taken else {
            return refuse(
                SandboxErrorCode::StateConflict,
                "terminal is not available to resume",
            );
        };
        // A refused resume leaves the PTY detached as it was (its own
        // deadline and checks still apply).
        let slots = self.slots.clone();
        let unavailable = |live: Live| {
            slots
                .detached
                .lock()
                .insert(live.fence.session_id.clone(), live);
        };
        // The same gates as an open: this connection's transport binding is
        // the lease's, the generation is current, the lease allows work.
        let bound = self
            .journal
            .lease(sandbox_id)
            .is_some_and(|row| self.binding.as_ref() == Some(&row.binding));
        let refusal = if bound {
            self.input_allowed(&live)
        } else {
            Some(TerminalCloseIntent::Revoked)
        };
        if let Some(intent) = refusal {
            live.stop.request(StopRequest {
                intent,
                request_id: None,
                error: None,
            });
            unavailable(live);
            return refuse(
                SandboxErrorCode::StateConflict,
                "terminal is not available to resume",
            );
        }
        if live.stopping() {
            unavailable(live);
            return refuse(
                SandboxErrorCode::StateConflict,
                "terminal is not available to resume",
            );
        }
        live.drain_detached();
        let resumed = if live.ended.is_some() {
            // The shell ended while detached: the answer is its exit.
            Some((0, live.attach))
        } else {
            let mut state = live.shared.lock();
            // The grace is checked under the same lock that ends it: a
            // deadline that already passed is never cancelled by a resume
            // (the pump closes the PTY at its next turn).
            if state
                .detached
                .is_none_or(|deadline| Instant::now() >= deadline)
            {
                drop(state);
                unavailable(live);
                return refuse(
                    SandboxErrorCode::StateConflict,
                    "terminal is not available to resume",
                );
            }
            state.ring.resume_from(next_output_seq).map(|from| {
                state.acked = from;
                state.attach += 1;
                state.detached = None;
                (from, state.attach)
            })
        };
        let Some((output_seq, attach)) = resumed else {
            // The server asks for output this PTY never produced.
            unavailable(live);
            return refuse(
                SandboxErrorCode::ProtocolError,
                "terminal resume sequence is past the output",
            );
        };
        live.fence = fence;
        live.attach = attach;
        live.ready = false;
        // Input sequences restart at 0 on the new fence; nothing queued on
        // the lost connection is ever written (the pump dropped it).
        live.input_next = 0;
        live.input_unacked = 0;
        live.output_sent = output_seq;
        live.output_acked = output_seq;
        live.violations = 0;
        live.detached_since = None;
        live.resume_answer = Some((request_id.clone(), output_seq));
        if live.ended.is_none()
            && live
                .control
                .try_send(Control::Resume(attach, request_id.clone(), size))
                .is_err()
        {
            live.stop.request(StopRequest {
                intent: TerminalCloseIntent::Client,
                request_id: Some(request_id),
                error: Some((SandboxErrorCode::Internal, "terminal resume failed".into())),
            });
        }
        self.sessions.insert(live.fence.session_id.clone(), live);
        Ok(Vec::new())
    }

    /// Close this connection's sessions of `sandbox_id` (all when `None`),
    /// and the detached ones (WP8) too.
    pub(super) fn close_sandbox(&mut self, sandbox_id: Option<&str>, intent: TerminalCloseIntent) {
        let matches = |live: &Live| {
            sandbox_id.is_none_or(|id| matches!(&live.fence.target, TerminalTargetV11::Sandbox { sandbox_id, .. } if id == sandbox_id))
        };
        let stop = |live: &Live| {
            live.stop.request(StopRequest {
                intent,
                request_id: None,
                error: None,
            })
        };
        self.sessions.values().filter(|l| matches(l)).for_each(stop);
        self.slots
            .detached
            .lock()
            .values()
            .filter(|l| matches(l))
            .for_each(stop);
    }

    /// Graceful daemon shutdown (C55, C52-TB-3): every session of this
    /// connection is asked to close with intent `shutdown` (its pump kills
    /// and reaps the supervised shell group, never the VM), and the exits are
    /// forwarded through `send` until none is live or `bound` passes. An
    /// uncertain reap's later confirmation is not waited for. Detached PTYs
    /// close too; no server session is waiting for their exits.
    pub(super) fn shutdown(
        &mut self,
        bound: Duration,
        mut send: impl FnMut(Outgoing) -> Result<()>,
    ) -> Result<()> {
        self.close_sandbox(None, TerminalCloseIntent::Shutdown);
        let deadline = Instant::now() + bound;
        loop {
            for frame in self.poll()? {
                send(frame)?;
            }
            if self.sessions.is_empty() || Instant::now() >= deadline {
                return Ok(());
            }
            thread::sleep(PUMP_WAIT);
        }
    }

    /// Lifecycle supersession from an admitted dispatch (carry-in 2): stop
    /// and kill end every terminal of the sandbox; a newer create/reconnect
    /// generation ends terminals bound to older generations. Detached PTYs
    /// (WP8) included.
    pub(super) fn on_dispatch(&mut self, dispatch: &OperationDispatch) {
        let supersede = |live: &Live| {
            let TerminalTargetV11::Sandbox {
                sandbox_id,
                generation,
            } = &live.fence.target
            else {
                return;
            };
            if sandbox_id != &dispatch.sandbox_id {
                return;
            }
            let superseded = match dispatch.kind.as_str() {
                "sandbox.stop" | "sandbox.kill" => true,
                "sandbox.create" | "sandbox.reconnect" => dispatch.generation > *generation,
                _ => false,
            };
            if superseded {
                live.stop.request(StopRequest {
                    intent: TerminalCloseIntent::Superseded,
                    request_id: None,
                    error: None,
                });
            }
        };
        self.sessions.values().for_each(supersede);
        self.slots.detached.lock().values().for_each(supersede);
    }

    /// WP8: the detached table's share of a tick. C55 authority applies at
    /// once (the pump also checks it on its own), exits are recorded for a
    /// later resume, and an ended PTY is forgotten once its grace is over.
    fn poll_detached(&mut self) {
        // The authority reads (journal, authority, credentials) run with no
        // table lock held: snapshot what they need first.
        let snapshot: Vec<_> = self
            .slots
            .detached
            .lock()
            .values()
            .filter_map(|live| match &live.fence.target {
                TerminalTargetV11::Sandbox {
                    sandbox_id,
                    generation,
                } => Some((
                    live.stop.clone(),
                    sandbox_id.clone(),
                    *generation,
                    live.credential_leases.clone(),
                )),
                TerminalTargetV11::Host {} => None,
            })
            .collect();
        if snapshot.is_empty() {
            return;
        }
        for (stop, sandbox_id, generation, leases) in snapshot {
            if let Some(intent) = sandbox_refusal(
                &self.journal,
                &self.authority,
                self.credentials.as_ref(),
                &sandbox_id,
                generation,
                &leases,
            ) {
                stop.request(StopRequest {
                    intent,
                    request_id: None,
                    error: None,
                });
            }
        }
        let now = Instant::now();
        let mut table = self.slots.detached.lock();
        for live in table.values_mut() {
            live.drain_detached();
        }
        table.retain(|_, live| {
            live.ended.is_none() || live.shared.lock().detached.is_some_and(|d| now < d)
        });
    }

    /// Forward this session's ring output within the credit window (bounded
    /// per tick). `false` when the ring no longer holds the next frame.
    fn forward_output(live: &mut Live, out: &mut Vec<Outgoing>) -> Result<bool> {
        let state = live.shared.lock();
        for _ in 0..EVENTS_PER_TICK {
            if live.output_sent >= state.ring.next()
                || live.output_sent - live.output_acked >= TERMINAL_OUTPUT_WINDOW_FRAMES
            {
                break;
            }
            let Some(bytes) = state.ring.get(live.output_sent) else {
                return Ok(false);
            };
            out.push(Outgoing::Binary(encode_terminal_frame(
                &TerminalDataMetadata {
                    r#type: TerminalDataKind::Data,
                    fence: live.fence.clone(),
                    sequence: live.output_sent,
                },
                bytes,
            )?));
            live.output_sent += 1;
        }
        Ok(true)
    }

    /// One socket-loop tick: re-check every session's lease authority and
    /// forward a bounded number of pump events and output frames per session.
    pub(super) fn poll(&mut self) -> Result<Vec<Outgoing>> {
        let mut out = Vec::new();
        let mut ended: Vec<(String, bool)> = Vec::new();
        // Reconciliation confirmations first (C55): a confirmed reap releases
        // the server's held count with a second, final `terminal.exit`.
        self.unreaped
            .retain(|_, (fence, events)| match events.try_recv() {
                Ok(Event::Reaped) => {
                    out.push(Outgoing::Text(Box::new(
                        DaemonControlMessage::TerminalExit {
                            request_id: None,
                            fence: fence.clone(),
                            exit_code: None,
                            intent: None,
                            reaped: true,
                            error: None,
                        },
                    )));
                    false
                }
                Ok(_) | Err(mpsc::TryRecvError::Empty) => true,
                // The sweep cannot confirm any more: the server keeps holding the
                // count until this connection ends (never released optimistically).
                Err(mpsc::TryRecvError::Disconnected) => false,
            });
        self.poll_detached();
        let refusals: HashMap<_, _> = self
            .sessions
            .iter()
            .filter_map(|(id, live)| self.input_allowed(live).map(|intent| (id.clone(), intent)))
            .collect();
        for (id, live) in &mut self.sessions {
            if let Some(intent) = refusals.get(id) {
                live.stop.request(StopRequest {
                    intent: *intent,
                    request_id: None,
                    error: None,
                });
            }
            for _ in 0..EVENTS_PER_TICK {
                if live.ended.is_some() {
                    break;
                }
                let event = match live.events.try_recv() {
                    Ok(event) => event,
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        // The pump ended without its exit (it always sends
                        // one, even when unwinding): still end the session on
                        // the server, reap unknown.
                        live.ended = Some(Ended::pump_lost());
                        break;
                    }
                };
                match event {
                    Event::Ready {
                        attach,
                        request_id,
                        rows,
                        cols,
                    } => {
                        if attach != live.attach || live.stopping() {
                            continue;
                        }
                        // Only the answer to an outstanding resume carries
                        // where output continues (WP8).
                        let output_seq = match &live.resume_answer {
                            Some((resume, seq)) if *resume == request_id => Some(*seq),
                            _ => None,
                        };
                        if output_seq.is_some() {
                            live.resume_answer = None;
                        }
                        live.ready = true;
                        out.push(Outgoing::Text(Box::new(
                            DaemonControlMessage::TerminalReady {
                                request_id,
                                fence: live.fence.clone(),
                                rows,
                                cols,
                                output_seq,
                            },
                        )));
                    }
                    Event::InputAck(attach, sequence) => {
                        if attach != live.attach {
                            continue;
                        }
                        live.input_unacked = live.input_unacked.saturating_sub(1);
                        out.push(Outgoing::Text(Box::new(
                            DaemonControlMessage::TerminalAck {
                                fence: live.fence.clone(),
                                sequence,
                            },
                        )));
                    }
                    Event::Exit {
                        request_id,
                        exit_code,
                        intent,
                        reaped,
                        error,
                    } => {
                        live.ended = Some(Ended {
                            request_id,
                            exit_code,
                            intent,
                            reaped,
                            error,
                            sweep: !reaped,
                        });
                    }
                    // Only ever follows this session's uncertain exit.
                    Event::Reaped => {}
                }
            }
            // Output is never forwarded before `ready` or after a close was
            // requested (the host ends the session anyway).
            if live.ready && !live.stopping() && !Self::forward_output(live, &mut out)? {
                live.stop.request(StopRequest {
                    intent: TerminalCloseIntent::Client,
                    request_id: None,
                    error: Some((
                        SandboxErrorCode::Internal,
                        "terminal output ring overrun".into(),
                    )),
                });
            }
            // The exit follows every output frame before it.
            let flushed = !live.ready
                || live.stopping()
                || live.output_sent >= live.shared.lock().ring.next();
            if flushed && let Some(end) = live.ended.take() {
                let fence = &live.fence;
                let request_id = end
                    .request_id
                    .or_else(|| live.resume_answer.take().map(|(request, _)| request));
                out.push(Outgoing::Text(Box::new(
                    DaemonControlMessage::TerminalExit {
                        request_id,
                        fence: fence.clone(),
                        exit_code: end.exit_code,
                        intent: end.intent,
                        reaped: end.reaped,
                        error: end.error.map(|(code, message)| ProtocolErrorDetail {
                            reason: None,
                            code: code.into(),
                            message: bounded(message),
                            operation_id: None,
                            sandbox_id: match &fence.target {
                                TerminalTargetV11::Sandbox { sandbox_id, .. } => {
                                    Some(sandbox_id.clone())
                                }
                                _ => None,
                            },
                        }),
                    },
                )));
                ended.push((id.clone(), end.sweep));
            }
        }
        for (id, uncertain) in ended {
            if let Some(live) = self.sessions.remove(&id)
                && uncertain
            {
                self.unreaped.insert(id.clone(), (live.fence, live.events));
            }
            self.tombstones.push_back(id);
            if self.tombstones.len() > TERMINAL_ENDED_SESSION_TOMBSTONES {
                self.tombstones.pop_front();
            }
        }
        Ok(out)
    }
}

/// Error text on the wire is bounded like receipt errors.
fn bounded(mut message: String) -> String {
    let limit = sandbox_protocol::RECEIPT_LIMITS.error_bytes;
    if message.len() > limit {
        let mut end = limit;
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        message.truncate(end);
    }
    message
}

impl Drop for TerminalHost {
    /// Connection end (relay drop, replacement, revocation, shutdown, any
    /// error). With `terminalResume` negotiated (WP8), every ready sandbox
    /// session (or one whose resume is still unanswered) is detached into the
    /// process-wide table for the grace; every other session stops, as
    /// before. The pumps close their PTYs on their own threads; nothing here
    /// waits for them.
    fn drop(&mut self) {
        let now = Instant::now();
        let deadline = now + self.slots.resume_grace;
        let slots = self.slots.clone();
        let mut table = slots.detached.lock();
        for (id, mut live) in self.sessions.drain() {
            let resumable = self.resume
                && live.sandbox_target()
                && (live.ready || live.resume_answer.is_some())
                && live.ended.is_none()
                && !live.stopping();
            if resumable {
                live.detach(now, deadline);
                table.insert(id, live);
            } else {
                live.stop.request(StopRequest {
                    intent: TerminalCloseIntent::HostDisconnected,
                    request_id: None,
                    error: None,
                });
            }
        }
    }
}

/// Test-only fault injection for the pump (C52-CC-3 regression).
#[cfg(test)]
pub(super) mod pump_faults {
    use std::sync::Mutex;

    static PANIC_AFTER_OPEN: Mutex<Vec<String>> = Mutex::new(Vec::new());
    type OpenPause = (
        String,
        std::sync::mpsc::SyncSender<()>,
        std::sync::mpsc::Receiver<()>,
    );
    static PAUSE_AFTER_OPEN: Mutex<Vec<OpenPause>> = Mutex::new(Vec::new());
    pub(in crate::sandbox_relay) fn pause_after_open(
        session_id: &str,
    ) -> (
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::SyncSender<()>,
    ) {
        let (entered, ready) = std::sync::mpsc::sync_channel(1);
        let (release, wait) = std::sync::mpsc::sync_channel(1);
        PAUSE_AFTER_OPEN
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((session_id.into(), entered, wait));
        (ready, release)
    }

    type Pause = (
        String,
        std::sync::mpsc::SyncSender<()>,
        std::sync::mpsc::Receiver<()>,
    );
    static PAUSES: Mutex<Vec<Pause>> = Mutex::new(Vec::new());
    /// The pump of `session_id` stops once at `point` (`before_write`,
    /// `before_push`): the first receiver fires when it arrived, sending on
    /// the second lets it go on.
    pub(in crate::sandbox_relay) fn pause_at(
        point: &str,
        session_id: &str,
    ) -> (
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::SyncSender<()>,
    ) {
        let (entered, ready) = std::sync::mpsc::sync_channel(1);
        let (release, wait) = std::sync::mpsc::sync_channel(1);
        PAUSES.lock().unwrap_or_else(|e| e.into_inner()).push((
            format!("{point}:{session_id}"),
            entered,
            wait,
        ));
        (ready, release)
    }
    pub(super) fn checkpoint(point: &str, session_id: &str) {
        let key = format!("{point}:{session_id}");
        let pause = {
            let mut pauses = PAUSES.lock().unwrap_or_else(|e| e.into_inner());
            pauses
                .iter()
                .position(|(id, _, _)| *id == key)
                .map(|index| pauses.swap_remove(index))
        };
        if let Some((_, entered, wait)) = pause {
            let _ = entered.send(());
            let _ = wait.recv();
        }
    }

    /// The pump of `session_id` panics right after its PTY opened.
    pub(in crate::sandbox_relay) fn panic_after_open(session_id: &str) {
        PANIC_AFTER_OPEN
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(session_id.to_string());
    }

    pub(super) fn after_open(session_id: &str) {
        let pause = {
            let mut pauses = PAUSE_AFTER_OPEN.lock().unwrap_or_else(|e| e.into_inner());
            pauses
                .iter()
                .position(|(id, _, _)| id == session_id)
                .map(|index| pauses.swap_remove(index))
        };
        if let Some((_, entered, wait)) = pause {
            let _ = entered.send(());
            let _ = wait.recv();
        }
        let mut ids = PANIC_AFTER_OPEN.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(index) = ids.iter().position(|id| id == session_id) {
            ids.remove(index);
            drop(ids);
            panic!("injected terminal pump panic");
        }
    }
}

#[cfg(test)]
#[path = "terminal_tests.rs"]
mod tests;
