//! Single-consumer terminal (PTY) sessions (C51).
//!
//! A [`PtySession`] is the ONE attachment to one guest shell. It is not
//! `Clone`; every IO method takes `&mut self`, so a second reader or writer
//! cannot exist by construction. The runtime keeps only a close-capable weak
//! handle (see [`PtyRegistry`]) so sandbox stop/destroy, expiry and shutdown
//! can close and reap the session without a consumer.
//!
//! Lifecycle and close intent:
//! - A child that exits on its own ends as [`PtyTermination::ChildExited`].
//! - A runtime close (client, detach, expiry, stop/destroy, shutdown) ends as
//!   [`PtyTermination::Closed`] with the [`PtyCloseIntent`] that caused it.
//! - Close is idempotent: the first terminal state wins and every later close
//!   returns it unchanged, issuing no further signal.
//!
//! Every exit path reaps the child before the controller (PTY master) is
//! released, and output pumping is bounded: at most
//! [`PTY_OUTPUT_QUEUE_CHUNKS`] chunks of at most [`PTY_OUTPUT_CHUNK_BYTES`] are
//! queued; a slow consumer back-pressures the reader instead of growing memory.
//! Input is bounded the same way ([`PTY_INPUT_QUEUE_CHUNKS`]).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, Weak};
use std::thread;
use std::time::{Duration, Instant};

use sandbox_protocol::SandboxErrorCode;

use crate::error::RuntimeError;

/// Inclusive terminal dimension bounds. Out-of-range sizes are REFUSED
/// (`PROTOCOL_ERROR`), never clamped: a caller cannot widen a session beyond
/// what it asked for, and zero is never forwarded to the kernel.
pub const PTY_MIN_DIMENSION: u16 = 1;
pub const PTY_MAX_ROWS: u16 = 512;
pub const PTY_MAX_COLS: u16 = 1024;
/// One output event carries at most this many bytes.
pub const PTY_OUTPUT_CHUNK_BYTES: usize = 16 * 1024;
/// Output events buffered between the PTY reader and the consumer.
pub const PTY_OUTPUT_QUEUE_CHUNKS: usize = 64;
/// One `write_input` call carries at most this many bytes.
pub const PTY_INPUT_MAX_BYTES: usize = 64 * 1024;
/// Input writes buffered between the consumer and the PTY writer.
pub const PTY_INPUT_QUEUE_CHUNKS: usize = 16;
/// Session lifetime when the request names none, and the hard ceiling.
pub const PTY_DEFAULT_SESSION: Duration = Duration::from_secs(4 * 60 * 60);
pub const PTY_MAX_SESSION: Duration = Duration::from_secs(12 * 60 * 60);
/// After a natural child exit, undelivered output is kept at most this long
/// for a stalled consumer before the controller is released anyway.
pub const PTY_EXIT_DRAIN_GRACE: Duration = Duration::from_secs(5);

const POLL: Duration = Duration::from_millis(10);
const SUPERVISOR_POLL: Duration = Duration::from_millis(20);
const JOIN_BOUND: Duration = Duration::from_secs(5);
const UNBLOCK_BOUND: Duration = Duration::from_secs(2);

/// Validated terminal dimensions (rows x cols).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtySize {
    rows: u16,
    cols: u16,
}

impl PtySize {
    pub fn new(rows: u16, cols: u16) -> Result<Self, RuntimeError> {
        if !(PTY_MIN_DIMENSION..=PTY_MAX_ROWS).contains(&rows)
            || !(PTY_MIN_DIMENSION..=PTY_MAX_COLS).contains(&cols)
        {
            return Err(RuntimeError::new(
                SandboxErrorCode::ProtocolError,
                format!(
                    "terminal size {rows}x{cols} is outside 1..={PTY_MAX_ROWS} rows and 1..={PTY_MAX_COLS} cols"
                ),
            ));
        }
        Ok(Self { rows, cols })
    }
    pub fn rows(self) -> u16 {
        self.rows
    }
    pub fn cols(self) -> u16 {
        self.cols
    }
}

/// Why the runtime (not the child) ended a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtyCloseIntent {
    /// The attached consumer asked to close.
    Client,
    /// The consumer dropped its session handle without closing.
    Detached,
    /// The session outlived its lifetime bound.
    Expired,
    /// The sandbox VM was stopped.
    SandboxStopped,
    /// The sandbox VM was destroyed.
    SandboxDestroyed,
    /// The node daemon is shutting down.
    Shutdown,
    /// A sandbox stop or destroy was attempted but NOT confirmed (refused,
    /// preempted, failed or unknown outcome). The terminal was closed
    /// conservatively; the VM may still be running.
    LifecycleUnconfirmed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtyTermination {
    /// The shell (or the `incus exec` client) exited on its own. The child
    /// is always reaped: an exit is only observed through a reap.
    ChildExited { exit_code: Option<i32> },
    /// The runtime closed the session and terminated the child.
    ///
    /// `reaped` is `true` only when the child was actually reaped. `false`
    /// means the reap did not complete within its bound (for example a child
    /// stuck in uninterruptible sleep): the child may still hold host
    /// resources, so anything charged to the session (quota, capacity) must
    /// stay charged.
    Closed {
        intent: PtyCloseIntent,
        exit_code: Option<i32>,
        reaped: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PtyEvent {
    Output(Vec<u8>),
    Ended(PtyTermination),
}

/// Open a terminal in a sandbox. There is deliberately no instance-name
/// field: the managed name derives from `sandbox_id` and is then positively
/// bound against host metadata. `guest` is the identity recorded for the
/// sandbox (journal / template contract), never browser input.
#[derive(Clone)]
pub struct OpenPtyRequest {
    pub template_fingerprint: String,
    pub sandbox_id: String,
    pub session_id: String,
    pub guest: crate::GuestIdentity,
    pub size: PtySize,
    pub max_duration: Option<Duration>,
    pub env: Vec<(String, String)>,
    /// The shell's working directory; `None` is the guest home.
    pub cwd: Option<String>,
    /// Independent of admission-only RuntimePermit::close().
    pub setup_cancel: Arc<AtomicBool>,
}

impl std::fmt::Debug for OpenPtyRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OpenPtyRequest([REDACTED])")
    }
}

/// An internal open failure retains uncertain children and IO workers. It is
/// never a ready/input-capable terminal and is not a wire error payload.
#[derive(Debug)]
pub struct PtyOpenFailure {
    pub error: RuntimeError,
    pub cleanup: Option<PtySession>,
}
impl From<RuntimeError> for PtyOpenFailure {
    fn from(error: RuntimeError) -> Self {
        Self {
            error: RuntimeError::new(error.code, "terminal setup failed"),
            cleanup: None,
        }
    }
}
impl std::ops::Deref for PtyOpenFailure {
    type Target = RuntimeError;
    fn deref(&self) -> &RuntimeError {
        &self.error
    }
}
impl PtyOpenFailure {
    /// Even failure before the IO pumps start must retain an uncertain child.
    #[cfg(target_os = "linux")]
    pub(crate) fn after_spawn(
        reservation: PtyReservation,
        size: PtySize,
        mut child: Box<dyn PtyChild>,
    ) -> Self {
        let reaped = child.terminate_and_reap().is_some();
        // Hang up the controller even on uncertainty; retain the child handle.
        child.release();
        if !reaped {
            return Self::retain_cleanup(reservation, size, child);
        }
        RuntimeError::new(SandboxErrorCode::Internal, "terminal setup failed").into()
    }

    fn with_session(mut session: PtySession, error: RuntimeError) -> Self {
        session.close(PtyCloseIntent::Client);
        let cleanup = (!session.reap_confirmed()).then_some(session);
        Self {
            error: RuntimeError::new(error.code, "terminal setup failed"),
            cleanup,
        }
    }
    /// The setup watchdog has already closed the child and bounded its joins.
    /// Keep ownership for later reconciliation when either proof is missing.
    #[cfg(target_os = "linux")]
    pub(crate) fn retain_cleanup(
        reservation: PtyReservation,
        size: PtySize,
        child: Box<dyn PtyChild>,
    ) -> Self {
        let (_, output) = mpsc::sync_channel(1);
        let session = PtySession {
            core: Arc::new(Core {
                sandbox_id: reservation.sandbox_id.clone(),
                session_id: reservation.session_id.clone(),
                deadline: Instant::now(),
                flags: Arc::new(Flags {
                    reader_done: AtomicBool::new(true),
                    writer_done: AtomicBool::new(true),
                    ..Flags::default()
                }),
                threads: Mutex::new(Vec::new()),
                state: Mutex::new(State {
                    child: None,
                    termination: Some(PtyTermination::Closed {
                        intent: PtyCloseIntent::Client,
                        exit_code: None,
                        reaped: false,
                    }),
                    exited_at: None,
                    size,
                    unreaped: Some(child),
                    reap_confirmed: false,
                }),
            }),
            output,
            input: None,
        };
        Self {
            error: RuntimeError::new(SandboxErrorCode::UnknownOutcome, "terminal setup failed"),
            cleanup: Some(session),
        }
    }
}

impl OpenPtyRequest {
    pub fn validate(&self) -> Result<Duration, RuntimeError> {
        sandbox_protocol::validate_env(&self.env)
            .map_err(|(code, _)| RuntimeError::new(code, "terminal setup failed"))?;
        if self
            .env
            .iter()
            .any(|(key, _)| matches!(key.as_str(), "HOME" | "SHELL" | "TERM"))
            || self.setup_cancel.load(Ordering::Acquire)
        {
            return Err(RuntimeError::new(
                SandboxErrorCode::ProtocolError,
                "terminal setup failed",
            ));
        }
        validate_session_id(&self.session_id)?;
        self.guest.validate()?;
        crate::resolve_managed_instance_name(&self.sandbox_id, None)?;
        match self.max_duration {
            Some(duration) if duration.is_zero() => Err(RuntimeError::new(
                SandboxErrorCode::ProtocolError,
                "terminal session lifetime must be positive",
            )),
            Some(duration) => Ok(duration.min(PTY_MAX_SESSION)),
            None => Ok(PTY_DEFAULT_SESSION),
        }
    }
}

pub fn validate_session_id(id: &str) -> Result<(), RuntimeError> {
    let valid = (1..=128).contains(&id.len())
        && id.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !valid {
        // The rejected value is never echoed: it is unbounded caller input.
        return Err(RuntimeError::new(
            SandboxErrorCode::ProtocolError,
            format!(
                "invalid terminal session id ({} bytes): 1..=128 ASCII letters, digits, `-` or `_`, starting alphanumeric",
                id.len()
            ),
        ));
    }
    Ok(())
}

/// The process side of one session: a real `incus exec -t` child behind a
/// host PTY, or the FakeRuntime's scripted adapter.
pub(crate) trait PtyChild: Send {
    /// Non-blocking. `Some(code)` once the child exited AND was reaped.
    fn try_reap(&mut self) -> Option<Option<i32>>;
    /// Terminate (hang up, then kill) and reap. Never signals a reaped child.
    /// `Some(code)` once reaped, like `try_reap`; `None` when the reap did not
    /// complete within its bound (reap uncertain).
    fn terminate_and_reap(&mut self) -> Option<Option<i32>>;
    fn resize(&mut self, size: PtySize) -> Result<(), RuntimeError>;
    /// Called after reap and before release while the input writer may still
    /// be blocked on a full input queue nobody will read again.
    fn unblock_writer(&mut self, writer_done: &dyn Fn() -> bool, deadline: Instant) {
        let _ = (writer_done, deadline);
    }
    /// Drop the controller. Only called after the child is reaped.
    fn release(&mut self);
}

pub(crate) struct PtyParts {
    pub child: Box<dyn PtyChild>,
    pub reader: Box<dyn Read + Send>,
    pub writer: Box<dyn Write + Send>,
    /// Constant helper failure after DONE; the reader strips its private marker.
    pub setup_failed: Option<Arc<AtomicBool>>,
}

#[derive(Default)]
struct Flags {
    setup_failed: Arc<AtomicBool>,
    /// Writer must stop (session ended).
    input_closed: AtomicBool,
    /// Writer thread has dropped its controller handle.
    writer_done: AtomicBool,
    /// Runtime close: discard undelivered output.
    discard_output: AtomicBool,
    /// Child exited naturally; output drain grace is running.
    exited: AtomicBool,
    /// Reader thread has dropped its controller handle.
    reader_done: AtomicBool,
}

struct State {
    child: Option<Box<dyn PtyChild>>,
    termination: Option<PtyTermination>,
    exited_at: Option<Instant>,
    size: PtySize,
    /// After an uncertain reap (`Closed { reaped: false }`) the child handle is
    /// RETAINED here (controller already released) so a reconciliation sweep
    /// can confirm the reap later ([`PtySession::reap_confirmed`], C55).
    /// Dropping it runs the child's own bounded terminate-and-reap backstop.
    unreaped: Option<Box<dyn PtyChild>>,
    /// The child is confirmed reaped (natural exit, a reaped close, or a
    /// later sweep). Never set on uncertainty.
    reap_confirmed: bool,
}

struct Core {
    sandbox_id: String,
    session_id: String,
    deadline: Instant,
    flags: Arc<Flags>,
    state: Mutex<State>,
    threads: Mutex<Vec<thread::JoinHandle<()>>>,
}

impl Core {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn termination(&self) -> Option<PtyTermination> {
        self.lock().termination
    }

    /// Observe a natural exit. The child is already reaped by `try_reap`.
    fn poll_exit(&self) -> Option<PtyTermination> {
        let mut state = self.lock();
        if state.termination.is_some() {
            return state.termination;
        }
        let code = state.child.as_mut()?.try_reap()?;
        let termination = PtyTermination::ChildExited { exit_code: code };
        state.exited_at = Some(Instant::now());
        self.flags.exited.store(true, Ordering::Release);
        self.finish(&mut state, termination);
        Some(termination)
    }

    /// Idempotent runtime close. The first terminal state wins.
    fn close(&self, intent: PtyCloseIntent) -> PtyTermination {
        let mut state = self.lock();
        if let Some(termination) = state.termination {
            return termination;
        }
        self.flags.discard_output.store(true, Ordering::Release);
        let termination = match state.child.as_mut() {
            Some(child) => match child.try_reap() {
                // The child beat the close: report the exit, not the intent.
                Some(exit_code) => PtyTermination::ChildExited { exit_code },
                None => {
                    let reap = child.terminate_and_reap();
                    PtyTermination::Closed {
                        intent,
                        exit_code: reap.flatten(),
                        reaped: reap.is_some(),
                    }
                }
            },
            // Unreachable while unterminated (`finish` takes the child and
            // sets the termination together); never claim a reap here.
            None => PtyTermination::Closed {
                intent,
                exit_code: None,
                reaped: false,
            },
        };
        self.finish(&mut state, termination);
        termination
    }

    /// Normally the child is reaped here. After an uncertain reap
    /// (`Closed { reaped: false }`) the controller is released anyway, which
    /// hangs up the tty for the stuck child; the termination carries the
    /// uncertainty. Stop the writer, unblock it if the child left it on a
    /// full input queue, then release the controller.
    fn finish(&self, state: &mut State, termination: PtyTermination) {
        state.termination = Some(termination);
        self.flags.input_closed.store(true, Ordering::Release);
        let uncertain = matches!(termination, PtyTermination::Closed { reaped: false, .. });
        state.reap_confirmed = !uncertain;
        if let Some(mut child) = state.child.take() {
            let flags = self.flags.clone();
            child.unblock_writer(
                &move || flags.writer_done.load(Ordering::Acquire),
                Instant::now() + UNBLOCK_BOUND,
            );
            child.release();
            if uncertain {
                state.unreaped = Some(child);
            }
        }
    }

    /// One non-blocking reconciliation attempt for an uncertain reap.
    fn reap_confirmed(&self) -> bool {
        let mut state = self.lock();
        if state.reap_confirmed {
            return true;
        }
        if state.termination.is_none() {
            return false;
        }
        let reaped = state
            .unreaped
            .as_mut()
            .is_some_and(|child| child.try_reap().is_some());
        if reaped {
            // Reaped: dropping the handle signals nothing more.
            state.unreaped = None;
            state.reap_confirmed = true;
        }
        reaped
    }

    fn join_threads(&self) {
        let mut threads =
            std::mem::take(&mut *self.threads.lock().unwrap_or_else(|e| e.into_inner()));
        let deadline = Instant::now() + JOIN_BOUND;
        while !threads.is_empty() && Instant::now() < deadline {
            let mut index = 0;
            while index < threads.len() {
                if threads[index].is_finished() {
                    let _ = threads.swap_remove(index).join();
                } else {
                    index += 1;
                }
            }
            if !threads.is_empty() {
                thread::sleep(POLL);
            }
        }
        // Retain unfinished workers for the cleanup handle / next bounded join.
        self.threads
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend(threads);
    }
}

/// The single attachment to one guest terminal.
pub struct PtySession {
    core: Arc<Core>,
    output: mpsc::Receiver<Vec<u8>>,
    input: Option<mpsc::SyncSender<Vec<u8>>>,
}

impl std::fmt::Debug for PtySession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PtySession")
            .field("sandbox_id", &self.core.sandbox_id)
            .field("session_id", &self.core.session_id)
            .finish_non_exhaustive()
    }
}

impl PtySession {
    pub(crate) fn start(
        reservation: PtyReservation,
        size: PtySize,
        lifetime: Duration,
        parts: PtyParts,
    ) -> Result<Self, PtyOpenFailure> {
        let PtyParts {
            child,
            reader,
            writer,
            setup_failed,
        } = parts;
        let flags = Arc::new(Flags {
            setup_failed: setup_failed.unwrap_or_default(),
            ..Flags::default()
        });
        let core = Arc::new(Core {
            sandbox_id: reservation.sandbox_id.clone(),
            session_id: reservation.session_id.clone(),
            deadline: Instant::now() + lifetime,
            flags: flags.clone(),
            state: Mutex::new(State {
                child: Some(child),
                termination: None,
                exited_at: None,
                size,
                unreaped: None,
                reap_confirmed: false,
            }),
            threads: Mutex::new(Vec::new()),
        });
        let (output_tx, output) = mpsc::sync_channel(PTY_OUTPUT_QUEUE_CHUNKS);
        let (input_tx, input_rx) = mpsc::sync_channel(PTY_INPUT_QUEUE_CHUNKS);
        flags.reader_done.store(true, Ordering::Release);
        flags.writer_done.store(true, Ordering::Release);
        let spawned = (|| -> std::io::Result<()> {
            let reader_flags = flags.clone();
            flags.reader_done.store(false, Ordering::Release);
            let reader = thread::Builder::new()
                .name("wssp-pty-reader".into())
                .spawn(move || pump_output(reader, output_tx, reader_flags));
            match reader {
                Ok(handle) => core
                    .threads
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(handle),
                Err(error) => {
                    flags.reader_done.store(true, Ordering::Release);
                    return Err(error);
                }
            }
            let writer_flags = flags.clone();
            flags.writer_done.store(false, Ordering::Release);
            let writer = thread::Builder::new()
                .name("wssp-pty-writer".into())
                .spawn(move || pump_input(writer, input_rx, writer_flags));
            match writer {
                Ok(handle) => core
                    .threads
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(handle),
                Err(error) => {
                    flags.writer_done.store(true, Ordering::Release);
                    return Err(error);
                }
            }
            let watched = Arc::downgrade(&core);
            let supervisor = thread::Builder::new()
                .name("wssp-pty-supervisor".into())
                .spawn(move || supervise(watched))?;
            core.threads
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(supervisor);
            Ok(())
        })();
        let session = Self {
            core: core.clone(),
            output,
            input: Some(input_tx),
        };
        match spawned {
            Ok(()) => {}
            Err(err) => {
                // Dropping `session` closes, reaps and releases.
                let _ = err;
                return Err(PtyOpenFailure::with_session(
                    session,
                    RuntimeError::new(SandboxErrorCode::Internal, "terminal setup failed"),
                ));
            }
        }
        reservation.commit(&core, session)
    }

    pub fn sandbox_id(&self) -> &str {
        &self.core.sandbox_id
    }

    pub fn session_id(&self) -> &str {
        &self.core.session_id
    }

    pub fn size(&self) -> PtySize {
        self.core.lock().size
    }

    pub fn termination(&self) -> Option<PtyTermination> {
        self.core.termination()
    }

    /// Both pump threads have dropped their controller handles (test hook:
    /// a descendant still holding the tty keeps the reader blocked).
    pub(crate) fn pumps_released(&self) -> bool {
        self.core.flags.reader_done.load(Ordering::Acquire)
            && self.core.flags.writer_done.load(Ordering::Acquire)
    }

    fn ended() -> RuntimeError {
        RuntimeError::new(
            SandboxErrorCode::StateConflict,
            "terminal session is closed",
        )
    }

    /// Queue guest input. Never blocks: a full queue is `RATE_LIMITED`.
    pub fn write_input(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        if bytes.len() > PTY_INPUT_MAX_BYTES {
            return Err(RuntimeError::new(
                SandboxErrorCode::RequestTooLarge,
                format!("terminal input exceeds {PTY_INPUT_MAX_BYTES} bytes"),
            ));
        }
        if self.core.termination().is_some() {
            return Err(Self::ended());
        }
        if bytes.is_empty() {
            return Ok(());
        }
        let Some(input) = &self.input else {
            return Err(Self::ended());
        };
        match input.try_send(bytes.to_vec()) {
            Ok(()) => Ok(()),
            Err(mpsc::TrySendError::Full(_)) => Err(RuntimeError::new(
                SandboxErrorCode::RateLimited,
                "terminal input queue is full",
            )),
            Err(mpsc::TrySendError::Disconnected(_)) => Err(Self::ended()),
        }
    }

    /// Resize the PTY; the kernel delivers SIGWINCH to the child's
    /// foreground process group (`incus exec` forwards it to the guest).
    pub fn resize(&mut self, size: PtySize) -> Result<(), RuntimeError> {
        let mut state = self.core.lock();
        if state.termination.is_some() {
            return Err(Self::ended());
        }
        let child = state.child.as_mut().ok_or_else(Self::ended)?;
        child.resize(size)?;
        state.size = size;
        Ok(())
    }

    fn check_setup_failure(&self) -> Result<(), RuntimeError> {
        if self.core.flags.setup_failed.load(Ordering::Acquire) {
            Err(RuntimeError::new(
                SandboxErrorCode::GuestUnavailable,
                "terminal setup failed",
            ))
        } else {
            Ok(())
        }
    }

    /// Wait up to `wait` for the next event. `Ok(None)` means nothing yet.
    /// After a natural exit, queued output is delivered before `Ended`; after
    /// a runtime close, undelivered output is discarded. `Ended` repeats.
    pub fn next_event(&mut self, wait: Duration) -> Result<Option<PtyEvent>, RuntimeError> {
        let deadline = Instant::now() + wait;
        loop {
            self.check_setup_failure()?;
            let termination = self.core.termination();
            if let Some(closed @ PtyTermination::Closed { .. }) = termination {
                return Ok(Some(PtyEvent::Ended(closed)));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            match self.output.recv_timeout(remaining.min(POLL)) {
                Ok(bytes) => return Ok(Some(PtyEvent::Output(bytes))),
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    self.check_setup_failure()?;
                    if let Some(done) = termination.or_else(|| self.core.poll_exit()) {
                        return Ok(Some(PtyEvent::Ended(done)));
                    }
                    // Reader saw EOF before the reap: poll without spinning.
                    thread::sleep(remaining.min(POLL));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if let Some(exited) = termination {
                        let grace_over = self
                            .core
                            .lock()
                            .exited_at
                            .is_none_or(|at| at.elapsed() >= PTY_EXIT_DRAIN_GRACE);
                        if grace_over || self.core.flags.reader_done.load(Ordering::Acquire) {
                            return Ok(Some(PtyEvent::Ended(exited)));
                        }
                    }
                }
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
        }
    }

    /// Whether the child is confirmed reaped. After `Closed { reaped: false }`
    /// each call makes ONE non-blocking reap attempt on the retained child
    /// (the C55 reconciliation sweep), and returns `true` from the first
    /// confirmed reap on. The termination itself never changes: the
    /// uncertainty stays the session's recorded outcome. `false` while the
    /// session is still running.
    pub fn reap_confirmed(&mut self) -> bool {
        self.core.reap_confirmed() && self.pumps_released()
    }

    /// Idempotent close: terminates and reaps the child (unless it already
    /// exited), releases the PTY, and joins the pumps (bounded).
    pub fn close(&mut self, intent: PtyCloseIntent) -> PtyTermination {
        let termination = self.core.close(intent);
        self.input = None;
        self.core.join_threads();
        termination
    }
}

impl Drop for PtySession {
    fn drop(&mut self) {
        self.close(PtyCloseIntent::Detached);
    }
}

fn pump_output(mut reader: Box<dyn Read + Send>, tx: mpsc::SyncSender<Vec<u8>>, flags: Arc<Flags>) {
    let mut buf = vec![0u8; PTY_OUTPUT_CHUNK_BYTES];
    'read: loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            // EIO once the child is gone and no slave descriptor remains.
            Err(_) => break,
        };
        let mut chunk = buf[..n].to_vec();
        let mut full_since: Option<Instant> = None;
        loop {
            if flags.discard_output.load(Ordering::Acquire) {
                break 'read;
            }
            match tx.try_send(chunk) {
                Ok(()) => break,
                Err(mpsc::TrySendError::Disconnected(_)) => break 'read,
                Err(mpsc::TrySendError::Full(back)) => {
                    chunk = back;
                    if flags.exited.load(Ordering::Acquire) {
                        let since = *full_since.get_or_insert_with(Instant::now);
                        if since.elapsed() >= PTY_EXIT_DRAIN_GRACE {
                            break 'read;
                        }
                    }
                    thread::sleep(POLL);
                }
            }
        }
    }
    drop(reader);
    flags.reader_done.store(true, Ordering::Release);
}

fn pump_input(mut writer: Box<dyn Write + Send>, rx: mpsc::Receiver<Vec<u8>>, flags: Arc<Flags>) {
    while !flags.input_closed.load(Ordering::Acquire) {
        match rx.recv_timeout(POLL) {
            Ok(bytes) => {
                if writer
                    .write_all(&bytes)
                    .and_then(|()| writer.flush())
                    .is_err()
                {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    drop(writer);
    flags.writer_done.store(true, Ordering::Release);
}

/// Owns exit and expiry detection without a consumer. Holds only a weak
/// reference so a dropped session is never kept alive by its supervisor.
fn supervise(core: Weak<Core>) {
    loop {
        let Some(core) = core.upgrade() else {
            return;
        };
        if core.termination().is_some() {
            return;
        }
        if Instant::now() >= core.deadline {
            core.close(PtyCloseIntent::Expired);
            return;
        }
        if core.poll_exit().is_some() {
            return;
        }
        drop(core);
        thread::sleep(SUPERVISOR_POLL);
    }
}

struct Entry {
    sandbox_id: String,
    core: Weak<Core>,
    /// Set when the sandbox was stopped/destroyed while this open was in
    /// flight; the commit then closes the new session immediately.
    doomed: Option<PtyCloseIntent>,
    pending: bool,
}

/// Runtime-wide close authority over live sessions. Shared by runtime clones.
/// Lock order: registry -> session state (liveness reads in `reserve`) is the
/// only nesting; no session-state holder ever takes the registry, and the
/// registry mutex is never held while a session is closed.
#[derive(Clone, Default)]
pub(crate) struct PtyRegistry(Arc<Mutex<HashMap<SessionKey, Entry>>>);

/// Session ids are scoped to their sandbox: `(sandbox_id, session_id)`.
type SessionKey = (String, String);

impl std::fmt::Debug for PtyRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PtyRegistry(..)")
    }
}

impl PtyRegistry {
    fn entries(&self) -> std::sync::MutexGuard<'_, HashMap<SessionKey, Entry>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Reserve `session_id` in `sandbox_id` before any spawn. A live or
    /// in-flight session with the same id in the same sandbox refuses: one
    /// attachment per session. Other sandboxes' ids never collide.
    pub(crate) fn reserve(
        &self,
        session_id: &str,
        sandbox_id: &str,
    ) -> Result<PtyReservation, RuntimeError> {
        let mut entries = self.entries();
        entries.retain(|_, entry| {
            entry.pending
                || entry
                    .core
                    .upgrade()
                    .is_some_and(|core| core.termination().is_none())
        });
        let key = (sandbox_id.to_string(), session_id.to_string());
        if entries.contains_key(&key) {
            return Err(RuntimeError::new(
                SandboxErrorCode::StateConflict,
                format!("terminal session `{session_id}` is already attached"),
            ));
        }
        entries.insert(
            key,
            Entry {
                sandbox_id: sandbox_id.to_string(),
                core: Weak::new(),
                doomed: None,
                pending: true,
            },
        );
        Ok(PtyReservation {
            registry: self.clone(),
            session_id: session_id.to_string(),
            sandbox_id: sandbox_id.to_string(),
            committed: false,
        })
    }

    /// Close every session of `sandbox_id` (or all when `None`). Returns how
    /// many live sessions this call closed or doomed.
    ///
    /// Live sessions are closed CONCURRENTLY (one scoped thread each), so the
    /// call takes about one session's bounded close, not one per session: a
    /// caller holding a sandbox lock or a deadline is not held N times over.
    pub(crate) fn close_matching(&self, sandbox_id: Option<&str>, intent: PtyCloseIntent) -> usize {
        let mut doomed = 0;
        let mut live = Vec::new();
        {
            let mut entries = self.entries();
            for entry in entries.values_mut() {
                if sandbox_id.is_some_and(|id| id != entry.sandbox_id) {
                    continue;
                }
                if entry.pending {
                    entry.doomed.get_or_insert(intent);
                    doomed += 1;
                } else if let Some(core) = entry.core.upgrade() {
                    live.push(core);
                }
            }
        }
        live.retain(|core| core.termination().is_none());
        let closed = doomed + live.len();
        match live.as_slice() {
            [] => {}
            [only] => {
                only.close(intent);
            }
            many => thread::scope(|scope| {
                for core in many {
                    let spawned = thread::Builder::new()
                        .name("wssp-pty-close".into())
                        .spawn_scoped(scope, move || {
                            core.close(intent);
                        });
                    if spawned.is_err() {
                        // No thread available: close inline (still bounded).
                        core.close(intent);
                    }
                }
            }),
        }
        closed
    }
}

/// An admitted, not yet started session id.
pub(crate) struct PtyReservation {
    registry: PtyRegistry,
    session_id: String,
    sandbox_id: String,
    committed: bool,
}

impl PtyReservation {
    #[cfg(target_os = "linux")]
    pub(crate) fn cancellation(&self) -> impl Fn() -> bool + Send + 'static {
        let registry = self.registry.clone();
        let key = self.key();
        move || {
            registry
                .entries()
                .get(&key)
                .is_none_or(|entry| entry.doomed.is_some())
        }
    }
    fn key(&self) -> SessionKey {
        (self.sandbox_id.clone(), self.session_id.clone())
    }

    fn commit(
        mut self,
        core: &Arc<Core>,
        session: PtySession,
    ) -> Result<PtySession, PtyOpenFailure> {
        let doomed = {
            let mut entries = self.registry.entries();
            match entries.get_mut(&self.key()) {
                Some(entry) => {
                    entry.core = Arc::downgrade(core);
                    entry.pending = false;
                    entry.doomed
                }
                None => Some(PtyCloseIntent::Shutdown),
            }
        };
        self.committed = true;
        if let Some(intent) = doomed {
            let mut session = session;
            session.close(intent);
            return Err(PtyOpenFailure::with_session(
                session,
                RuntimeError::new(SandboxErrorCode::SandboxNotRunning, "terminal setup failed"),
            ));
        }
        Ok(session)
    }
}

impl Drop for PtyReservation {
    fn drop(&mut self) {
        if !self.committed {
            let key = self.key();
            self.registry.entries().remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_are_refused_not_clamped() {
        for (rows, cols) in [
            (0, 80),
            (24, 0),
            (0, 0),
            (PTY_MAX_ROWS + 1, 80),
            (24, PTY_MAX_COLS + 1),
            (u16::MAX, u16::MAX),
        ] {
            let err = PtySize::new(rows, cols).expect_err("out of range");
            assert_eq!(err.code, SandboxErrorCode::ProtocolError);
        }
        let edge = PtySize::new(PTY_MAX_ROWS, PTY_MAX_COLS).unwrap();
        assert_eq!((edge.rows(), edge.cols()), (PTY_MAX_ROWS, PTY_MAX_COLS));
        let min = PtySize::new(1, 1).unwrap();
        assert_eq!((min.rows(), min.cols()), (1, 1));
    }

    #[test]
    fn session_ids_and_sandbox_ids_reject_injection() {
        for id in [
            "",
            "-x",
            "--",
            "a b",
            "a;b",
            "a/b",
            "a\nb",
            "--project=x",
            &"a".repeat(129),
        ] {
            assert!(validate_session_id(id).is_err(), "{id:?}");
        }
        validate_session_id("term-1_a").unwrap();
        // C51-TB-6: the rejected value is never echoed, whatever its size.
        let hostile = format!("{}\u{202e}", "x".repeat(100_000));
        let message = validate_session_id(&hostile).unwrap_err().message;
        assert!(message.len() < 200 && !message.contains("xxx"), "{message}");
        let base = OpenPtyRequest {
            template_fingerprint: "fp".into(),
            sandbox_id: "sbx-1".into(),
            session_id: "term-1".into(),
            guest: Default::default(),
            size: PtySize::new(24, 80).unwrap(),
            max_duration: None,
            env: Vec::new(),
            cwd: None,
            setup_cancel: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        assert_eq!(base.validate().unwrap(), PTY_DEFAULT_SESSION);
        // WP8: the server's resume gate bounds reattach by the same lifetime.
        assert_eq!(
            PTY_DEFAULT_SESSION.as_millis(),
            u128::from(sandbox_protocol::TERMINAL_GUEST_MAX_LIFETIME_MS)
        );
        for sandbox_id in [
            "-sbx", "--", "sbx/../x", "sbx 1", "sbx;rm", "", "sbx\n1", "%2F",
        ] {
            let request = OpenPtyRequest {
                sandbox_id: sandbox_id.into(),
                ..base.clone()
            };
            assert!(request.validate().is_err(), "{sandbox_id:?}");
        }
        let zero = OpenPtyRequest {
            max_duration: Some(Duration::ZERO),
            ..base.clone()
        };
        assert!(zero.validate().is_err());
        let long = OpenPtyRequest {
            max_duration: Some(Duration::from_secs(u64::MAX / 4)),
            ..base.clone()
        };
        assert_eq!(long.validate().unwrap(), PTY_MAX_SESSION);
        for shell in ["-i", "bash", "/bin/bash -i", "/bin/../bin/sh", "/bin/sh\n"] {
            let guest = crate::GuestIdentity {
                guest_shell: shell.into(),
                ..Default::default()
            };
            let request = OpenPtyRequest {
                guest,
                ..base.clone()
            };
            // Absolute, component-clean, control-free shells only; a space
            // stays inert because the shell is one argv element after `--`.
            if shell == "/bin/bash -i" {
                assert!(request.validate().is_ok());
            } else {
                assert!(request.validate().is_err(), "{shell:?}");
            }
        }
    }
}

#[cfg(test)]
mod registry_tests {
    use super::*;

    /// C51-TB-5: session ids are scoped to their sandbox. The same id in two
    /// sandboxes neither collides nor shares a reservation, and a sandbox's
    /// close dooms only its own entry.
    #[test]
    fn session_ids_are_scoped_to_their_sandbox() {
        let registry = PtyRegistry::default();
        let a = registry.reserve("term-1", "sbx-a").unwrap();
        let b = registry.reserve("term-1", "sbx-b").unwrap();
        assert_eq!(
            registry.reserve("term-1", "sbx-a").err().map(|e| e.code),
            Some(SandboxErrorCode::StateConflict)
        );
        assert_eq!(
            registry.close_matching(Some("sbx-a"), PtyCloseIntent::SandboxStopped),
            1
        );
        let doomed =
            |sandbox: &str| registry.entries()[&(sandbox.to_string(), "term-1".to_string())].doomed;
        assert_eq!(doomed("sbx-a"), Some(PtyCloseIntent::SandboxStopped));
        assert_eq!(doomed("sbx-b"), None);
        // Dropping one sandbox's reservation frees only that key.
        drop(a);
        assert!(registry.entries().len() == 1 && doomed("sbx-b").is_none());
        let _a = registry.reserve("term-1", "sbx-a").unwrap();
        drop(b);
        let _b = registry.reserve("term-1", "sbx-b").unwrap();
    }
}
