//! Graceful quiesce-then-restart for daemon upgrades (reconnect plan WP7,
//! decisions D6 and D9).
//!
//! `wssp daemon quiesce` (the service's `ExecReload`) sends SIGUSR1 to a
//! daemon whose control file ([`CONTROL_FILE`]) proves it understands it.
//! The signal watcher (`crate::shutdown`) records the request here, never in
//! the shutdown slot, so a later SIGTERM still works as it always did. Then:
//!
//! 1. The daemon is *quiescing*. The session loop sends `host.quiesce`
//!    (negotiated capability `quiesce`) once registered ([`QuiesceLink`]).
//! 2. The server answers `host.quiesce.ack` and from then on holds new
//!    `command.run` work in its queue. Without an ack within [`ACK_WAIT`]
//!    the daemon falls back to the ordinary graceful shutdown (SIGTERM path).
//!    A server whose `hello.ok` did not negotiate `quiesce` gets that
//!    fallback at once.
//! 3. Every reconnect while quiescing carries `hello.quiescing: true`; the
//!    server sets its hold atomically with registration, so that hello
//!    counts as the ack.
//! 4. New terminal opens are refused locally. Dispatches that still arrive
//!    (claimed by the server before its hold) are accepted and count as
//!    running work.
//! 5. [`QuiesceWorker`] waits for running `command.run` attempts, at most
//!    `quiesce_max` (default 10 min) from the request, then requests the
//!    normal shutdown: terminals closed, bounded waits, journal kept. The
//!    process exits 0 and the service manager starts the new binary. The
//!    commands still running at the cap are logged and revoked. A command
//!    counts until the server confirmed its result: one that exited during
//!    the drain first publishes its tail output and its result.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::connect::ShutdownSignal;
use sandbox_protocol::{DaemonControlMessage, HostQuiesceV11};

/// How long the daemon waits for `host.quiesce.ack` before it falls back to
/// the ordinary graceful shutdown.
pub(crate) const ACK_WAIT: Duration = Duration::from_secs(30);
/// After the ack, the drain is judged no earlier than this: a dispatch the
/// server claimed just before its hold may still be on the wire.
pub(crate) const DRAIN_SETTLE: Duration = Duration::from_secs(1);
/// The worker's longest sleep between checks.
const POLL: Duration = Duration::from_millis(250);

/// The running daemon's private control file, in its relay state directory
/// (`<data>/relay/<sha256(host id)>/`).
pub const CONTROL_FILE: &str = "daemon.json";
/// The feature `wssp daemon quiesce` looks for before it sends SIGUSR1.
pub const QUIESCE_FEATURE: &str = "quiesce";

/// The process-wide quiesce request, shared by the signal watcher, every
/// relay session and the [`QuiesceWorker`].
#[derive(Debug, Default)]
pub struct QuiesceState {
    inner: Mutex<Inner>,
    changed: Condvar,
}

#[derive(Debug, Default, Clone, Copy)]
struct Inner {
    /// The SIGUSR1 handler is registered: only then is the control file
    /// written and the capability offered.
    enabled: bool,
    requested_at: Option<Instant>,
    acked_at: Option<Instant>,
}

impl QuiesceState {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The quiesce signal handler is registered (`crate::shutdown`).
    pub fn enable(&self) {
        self.lock().enabled = true;
    }

    pub fn enabled(&self) -> bool {
        self.lock().enabled
    }

    /// Start quiescing. True for the first request only; a repeat is a
    /// no-op. Ignored unless enabled.
    pub fn request(&self) -> bool {
        let mut inner = self.lock();
        if !inner.enabled || inner.requested_at.is_some() {
            return false;
        }
        inner.requested_at = Some(Instant::now());
        drop(inner);
        self.changed.notify_all();
        true
    }

    pub fn quiescing(&self) -> bool {
        self.lock().requested_at.is_some()
    }

    pub(crate) fn acked(&self) -> bool {
        self.lock().acked_at.is_some()
    }

    /// The server holds new commands for this host (an ack, or a quiescing
    /// hello it registered).
    pub(crate) fn acknowledge(&self) {
        let mut inner = self.lock();
        if inner.requested_at.is_some() && inner.acked_at.is_none() {
            inner.acked_at = Some(Instant::now());
            drop(inner);
            self.changed.notify_all();
        }
    }

    /// Wakes the worker (a shutdown request or a stop).
    pub(crate) fn wake(&self) {
        self.changed.notify_all();
    }

    fn snapshot(&self) -> Inner {
        *self.lock()
    }

    fn wait(&self, timeout: Duration) {
        let inner = self.lock();
        let _ = self
            .changed
            .wait_timeout(inner, timeout)
            .unwrap_or_else(|e| e.into_inner());
    }
}

/// One relay connection's part of the protocol.
#[derive(Debug, Default)]
pub(super) struct QuiesceLink {
    /// This connection's hello carried `quiescing: true`.
    hello_quiescing: bool,
    /// `hello.ok` answered; whether it negotiated `quiesce`.
    negotiated: Option<bool>,
    /// The `host.quiesce` sequence sent on this connection.
    sent: Option<u64>,
}

impl QuiesceLink {
    /// Called as the connection's hello is built.
    pub(super) fn new(shutdown: &ShutdownSignal) -> Self {
        let state = shutdown.quiesce();
        Self {
            hello_quiescing: state.enabled() && state.quiescing(),
            ..Self::default()
        }
    }

    /// `hello.capabilities.quiesce`: offered only by a daemon that can quiesce.
    pub(super) fn capability(shutdown: &ShutdownSignal) -> bool {
        shutdown.quiesce().enabled()
    }

    /// `hello.quiescing` for this connection.
    pub(super) fn hello_flag(&self) -> bool {
        self.hello_quiescing
    }

    /// `hello.ok` registered this connection. A quiescing hello the server
    /// negotiated is held from registration on: that is the ack.
    pub(super) fn registered(&mut self, shutdown: &ShutdownSignal, negotiated: bool) {
        self.negotiated = Some(negotiated);
        if self.hello_quiescing && negotiated {
            shutdown.quiesce().acknowledge();
        }
    }

    /// The `host.quiesce` frame to send now, if any. `epoch` is the
    /// registered connection's epoch. A server that did not negotiate the
    /// capability gets the ordinary graceful shutdown at once.
    pub(super) fn poll(
        &mut self,
        shutdown: &ShutdownSignal,
        epoch: Option<u64>,
    ) -> Result<Option<DaemonControlMessage>> {
        let state = shutdown.quiesce();
        if !state.quiescing() || state.acked() || self.sent.is_some() {
            return Ok(None);
        }
        let Some(epoch) = epoch else {
            return Ok(None);
        };
        match self.negotiated {
            Some(true) => {
                self.sent = Some(1);
                Ok(Some(DaemonControlMessage::HostQuiesce(HostQuiesceV11 {
                    connection_epoch: u32::try_from(epoch)?,
                    sequence: 1,
                })))
            }
            Some(false) => {
                tracing::warn!(
                    "the relay server does not support a graceful quiesce; restarting now"
                );
                shutdown.request();
                Ok(None)
            }
            None => Ok(None),
        }
    }

    /// `host.quiesce.ack`: counts only for this connection's own sequence.
    pub(super) fn ack(&mut self, shutdown: &ShutdownSignal, sequence: u64) {
        if self.sent == Some(sequence) {
            shutdown.quiesce().acknowledge();
        }
    }
}

/// The worker's bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct QuiesceTiming {
    pub ack_wait: Duration,
    pub settle: Duration,
    pub max: Duration,
}

impl QuiesceTiming {
    pub(super) fn with_max(max: Duration) -> Self {
        Self {
            ack_wait: ACK_WAIT,
            settle: DRAIN_SETTLE,
            max,
        }
    }
}

/// Why the quiesce ends in a shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum QuiesceEnd {
    /// No `host.quiesce.ack` within the wait: the ordinary graceful path.
    NoAck,
    /// Every command finished and the server confirmed its result.
    Drained,
    /// `quiesce_max` passed with these commands still outstanding.
    Cap { remaining: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Step {
    Wait(Duration),
    Shutdown(QuiesceEnd),
}

/// The state machine's next step, given the request and ack times and the
/// outstanding `command.run` count.
pub(super) fn next_step(
    now: Instant,
    requested_at: Instant,
    acked_at: Option<Instant>,
    running: usize,
    timing: QuiesceTiming,
) -> Step {
    let elapsed = now.saturating_duration_since(requested_at);
    let Some(acked_at) = acked_at else {
        return match timing.ack_wait.checked_sub(elapsed) {
            Some(left) if !left.is_zero() => Step::Wait(left.min(POLL)),
            _ => Step::Shutdown(QuiesceEnd::NoAck),
        };
    };
    let settled = now.saturating_duration_since(acked_at) >= timing.settle;
    if running == 0 && settled {
        return Step::Shutdown(QuiesceEnd::Drained);
    }
    match timing.max.checked_sub(elapsed) {
        Some(left) if !left.is_zero() => Step::Wait(left.min(POLL)),
        _ => Step::Shutdown(QuiesceEnd::Cap { remaining: running }),
    }
}

/// Counts outstanding `command.run` work: queued, running, or finished with
/// output, result or the server's confirmation still pending
/// (`RelaySupervisor::quiesce_outstanding`).
pub(super) type RunningCommands = Box<dyn Fn() -> usize + Send>;

/// Drives a requested quiesce to its shutdown. Stopped and joined on drop.
pub(super) struct QuiesceWorker {
    stop: Arc<AtomicBool>,
    shutdown: ShutdownSignal,
    handle: Option<JoinHandle<()>>,
}

impl QuiesceWorker {
    pub(super) fn start(
        shutdown: ShutdownSignal,
        timing: QuiesceTiming,
        running: RunningCommands,
    ) -> Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let handle = std::thread::Builder::new()
            .name("wssp-quiesce".into())
            .spawn({
                let stop = stop.clone();
                let shutdown = shutdown.clone();
                move || run_worker(&shutdown, &stop, timing, running.as_ref())
            })
            .context("start the quiesce worker")?;
        Ok(Self {
            stop,
            shutdown,
            handle: Some(handle),
        })
    }
}

impl Drop for QuiesceWorker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.shutdown.quiesce().wake();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn run_worker(
    shutdown: &ShutdownSignal,
    stop: &AtomicBool,
    timing: QuiesceTiming,
    running: &dyn Fn() -> usize,
) {
    let state = shutdown.quiesce();
    loop {
        if stop.load(Ordering::Acquire) || shutdown.requested() {
            return;
        }
        let snapshot = state.snapshot();
        let Some(requested_at) = snapshot.requested_at else {
            state.wait(POLL);
            continue;
        };
        match next_step(
            Instant::now(),
            requested_at,
            snapshot.acked_at,
            running(),
            timing,
        ) {
            Step::Wait(left) => state.wait(left),
            Step::Shutdown(end) => {
                match end {
                    QuiesceEnd::NoAck => tracing::warn!(
                        wait_secs = timing.ack_wait.as_secs(),
                        "the relay server did not acknowledge the quiesce; restarting now"
                    ),
                    QuiesceEnd::Drained => tracing::info!(
                        remaining = 0,
                        "quiesce complete: every command finished and its result was confirmed; restarting"
                    ),
                    QuiesceEnd::Cap { remaining } => tracing::warn!(
                        remaining,
                        quiesce_max_secs = timing.max.as_secs(),
                        "quiesce_max reached; restarting with commands still running or unconfirmed (running ones are stopped)"
                    ),
                }
                shutdown.request();
                return;
            }
        }
    }
}

/// The control file `wssp daemon quiesce` reads. Unknown fields are
/// ignored, so a newer daemon's file stays readable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlFile {
    pub pid: u32,
    /// The process start time (`/proc/<pid>/stat` field 22, clock ticks
    /// since boot): a recycled pid never matches.
    pub start_time: u64,
    pub version: String,
    pub features: Vec<String>,
}

impl ControlFile {
    pub fn supports_quiesce(&self) -> bool {
        self.features.iter().any(|f| f == QUIESCE_FEATURE)
    }
}

/// The start time of `pid` (`/proc/<pid>/stat` field 22), if readable.
pub fn process_start_time(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_start_time(&stat)
}

/// Field 22 of a `/proc/<pid>/stat` line. The command name (field 2) may
/// hold spaces and parentheses, so fields are counted after its last `)`.
pub(crate) fn parse_start_time(stat: &str) -> Option<u64> {
    let rest = &stat[stat.rfind(')')? + 1..];
    // `rest` starts at field 3 (state); field 22 is the 20th after it.
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// The running daemon's control file, removed when dropped (process exit).
#[derive(Debug)]
pub(super) struct ControlFileGuard {
    path: PathBuf,
}

impl ControlFileGuard {
    /// Write `<state_dir>/daemon.json` (0600, atomically). Call only after
    /// the SIGUSR1 handler is registered.
    pub(super) fn write(state_dir: &Path) -> Result<Self> {
        let pid = std::process::id();
        let start_time = process_start_time(pid).context("reading this process's start time")?;
        let file = ControlFile {
            pid,
            start_time,
            version: env!("CARGO_PKG_VERSION").to_string(),
            features: vec![QUIESCE_FEATURE.to_string()],
        };
        let path = state_dir.join(CONTROL_FILE);
        let mut temp = tempfile::Builder::new()
            .prefix(".daemon-json-")
            .tempfile_in(state_dir)
            .context("creating the daemon control file")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            temp.as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600))
                .context("making the daemon control file private")?;
        }
        let bytes = serde_json::to_vec(&file).context("encoding the daemon control file")?;
        std::io::Write::write_all(&mut temp, &bytes).context("writing the daemon control file")?;
        temp.as_file()
            .sync_all()
            .context("flushing the daemon control file")?;
        temp.persist(&path)
            .map_err(|error| error.error)
            .context("publishing the daemon control file")?;
        Ok(Self { path })
    }
}

impl Drop for ControlFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Everything a daemon run holds for quiescing: the worker and the control
/// file. Both end when this drops.
pub(super) struct Quiesce {
    _worker: QuiesceWorker,
    _control: Option<ControlFileGuard>,
}

/// The worker's `quiesce_max`: the debug-build timing knob, else the config.
fn quiesce_max(config: &crate::config::Config) -> Result<Duration> {
    #[cfg(debug_assertions)]
    if let Some(max) =
        super::connect::installed_relay_test_timing().and_then(|timing| timing.quiesce_max)
    {
        return Ok(max);
    }
    Ok(config.quiesce_max())
}

/// Start quiescing support for this daemon run, if its SIGUSR1 handler is
/// registered: the worker first, then the control file that advertises it.
/// Without the file `wssp daemon quiesce` restarts this daemon with SIGTERM,
/// as before; the worker still serves a SIGUSR1 sent by hand.
pub(super) fn start(
    shutdown: &ShutdownSignal,
    state_dir: &Path,
    config: &crate::config::Config,
    running: RunningCommands,
) -> Result<Option<Quiesce>> {
    if !shutdown.quiesce().enabled() {
        return Ok(None);
    }
    let timing = QuiesceTiming::with_max(quiesce_max(config)?);
    let worker = QuiesceWorker::start(shutdown.clone(), timing, running)?;
    let control = ControlFileGuard::write(state_dir)
        .inspect_err(|error| {
            tracing::warn!(
                "graceful reload unavailable: {error:#}; `wssp daemon quiesce` restarts this daemon"
            );
        })
        .ok();
    Ok(Some(Quiesce {
        _worker: worker,
        _control: control,
    }))
}

#[cfg(test)]
#[path = "quiesce_tests.rs"]
mod tests;
