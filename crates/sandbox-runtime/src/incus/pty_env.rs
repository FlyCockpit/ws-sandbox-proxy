//! Independent setup timer. Blocking reader/writer workers never own the child,
//! admission mutex, registry mutex or active-session map. Only this watchdog may
//! publish the completed streams, or kill/reap/drain and retain uncertain work.
use super::*;
use std::io::{Cursor, Write};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread::{self, JoinHandle};

pub(crate) const OVERALL: Duration = Duration::from_secs(30);
pub(crate) const HANDSHAKE: Duration = Duration::from_secs(5);
const CAPTURE: usize = 8192;
const JOIN: Duration = Duration::from_secs(5);
const DRAIN: Duration = Duration::from_secs(2);

#[derive(Clone, Copy)]
pub(crate) struct Limits {
    pub overall: Duration,
    pub handshake: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            overall: OVERALL,
            handshake: HANDSHAKE,
        }
    }
}
#[cfg(test)]
thread_local! { pub(crate) static TEST_LIMITS: std::cell::Cell<Limits> = std::cell::Cell::new(Limits::default()); }
#[cfg(test)]
#[derive(Default)]
pub(crate) struct Observation {
    pub ready: std::sync::Mutex<Option<Instant>>,
    pub closed: std::sync::Mutex<Option<Instant>>,
    pub writer_started: AtomicBool,
    pub writer_blocked_at_close: AtomicBool,
    pub writer_finished: AtomicBool,
    pub deadline_fired: AtomicBool,
    pub workers_finished: AtomicBool,
}
#[cfg(test)]
thread_local! { pub(crate) static TEST_OBSERVATION: std::cell::RefCell<Option<Arc<Observation>>> = const { std::cell::RefCell::new(None) }; }
fn ready_deadline(overall: Instant, parsed: Instant, budget: Duration) -> Instant {
    overall.min(parsed + budget)
}
fn limits() -> Limits {
    #[cfg(test)]
    {
        TEST_LIMITS.with(|v| v.get())
    }
    #[cfg(not(test))]
    {
        Limits::default()
    }
}

type Reader = Box<dyn Read + Send>;
type Writer = Box<dyn Write + Send>;
enum Progress {
    Child(IncusPtyChild),
    Ready(Instant),
    Read(Result<(Reader, Vec<u8>), ()>),
    Written(Result<Writer, ()>),
    Abort,
}
pub(super) struct Opened {
    pub reservation: crate::pty::PtyReservation,
    pub parts: PtyParts,
    pub lifetime: Duration,
}
pub(super) struct Pending {
    tx: mpsc::Sender<Progress>,
    result: mpsc::Receiver<Result<Opened, crate::PtyOpenFailure>>,
    thread: Option<JoinHandle<()>>,
}

fn failure() -> crate::PtyOpenFailure {
    RuntimeError::new(SandboxErrorCode::GuestUnavailable, "terminal setup failed").into()
}

/// No workload bytes are sent until the guest READY AND the outer tty's raw
/// state are established. Alphabet-only envelope; exact binary-frame validator
/// is shared with piped commands in the guest helper.
pub(crate) fn envelope(frame: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if frame.len() > 16397 {
        return Err(failure().error);
    }
    let mut encoded = Vec::with_capacity(frame.len().div_ceil(3) * 4);
    for chunk in frame.chunks(3) {
        let a = chunk[0] as usize;
        let b = chunk.get(1).copied().unwrap_or_default() as usize;
        let c = chunk.get(2).copied().unwrap_or_default() as usize;
        encoded.push(ALPHABET[a >> 2]);
        encoded.push(ALPHABET[((a & 3) << 4) | (b >> 4)]);
        encoded.push(if chunk.len() > 1 {
            ALPHABET[((b & 15) << 2) | (c >> 6)]
        } else {
            b'='
        });
        encoded.push(if chunk.len() > 2 {
            ALPHABET[c & 63]
        } else {
            b'='
        });
    }
    let mut out = format!("{:08x}:", encoded.len()).into_bytes();
    out.extend(encoded);
    Ok(out)
}

/// Verify effective raw/no-echo state at READY; never infer it from spawn or
/// from the helper's guest tty. OPOST off disables every output translation.
pub(in crate::incus) fn raw(master: &dyn portable_pty::MasterPty) -> bool {
    master.get_termios().is_some_and(|mode| {
        mode.local_flags.bits() & (libc::ECHO | libc::ICANON | libc::ISIG) == 0
            && mode.input_flags.bits() & (libc::IXON | libc::ICRNL | libc::INLCR | libc::IGNCR) == 0
            && mode.output_flags.bits() & libc::OPOST == 0
    })
}

fn read_setup(
    mut reader: Reader,
    nonce: &str,
    tx: &mpsc::Sender<Progress>,
    frame_written: &AtomicBool,
) -> Result<(Reader, Vec<u8>), ()> {
    let ready = format!("\x1eWSSP_ENV_READY {nonce}\x1f").into_bytes();
    let done = format!("\x1eWSSP_ENV_DONE {nonce}\x1f").into_bytes();
    let mut pending = Vec::new();
    let mut total = 0usize;
    let mut ready_seen = false;
    loop {
        let mut buf = [0u8; 4096];
        let n = reader.read(&mut buf).map_err(|_| ())?;
        if n == 0 {
            return Err(());
        }
        pending.extend_from_slice(&buf[..n]);
        loop {
            let marker = if ready_seen { &done } else { &ready };
            // Suppress all pre-DONE output; a marker prefix must match exactly.
            let at = pending
                .iter()
                .position(|b| *b == 0x1e)
                .unwrap_or(pending.len());
            total += at;
            if total > CAPTURE {
                return Err(());
            }
            pending.drain(..at);
            let compared = pending.len().min(marker.len());
            if pending[..compared] != marker[..compared] {
                return Err(());
            }
            if pending.len() < marker.len() {
                break;
            }
            total += marker.len();
            if total > CAPTURE {
                return Err(());
            }
            pending.drain(..marker.len());
            if ready_seen {
                if !frame_written.load(Ordering::Acquire) {
                    return Err(());
                }
                return Ok((reader, pending));
            }
            // Bytes captured alongside READY predate ANY allowed frame write.
            // A complete/partial forged DONE in that same chunk cannot advance.
            if !pending.is_empty() {
                return Err(());
            }
            ready_seen = true;
            tx.send(Progress::Ready(Instant::now())).map_err(|_| ())?;
        }
    }
}

struct Done(Arc<AtomicBool>);
impl Drop for Done {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

impl Pending {
    /// Started BEFORE guest spawn (and before the read-only tool probe). The
    /// timer can revoke that probe and mark setup closed independently of IO.
    pub(super) fn start(
        master: Box<dyn portable_pty::MasterPty + Send>,
        reservation: crate::pty::PtyReservation,
        request: &OpenPtyRequest,
        lifetime: Duration,
        permit: Arc<crate::RuntimePermit>,
        nonce: String,
        frame: Vec<u8>,
    ) -> Result<Self, crate::PtyOpenFailure> {
        let reader = master.try_clone_reader().map_err(|_| failure())?;
        let writer = master.take_writer().map_err(|_| failure())?;
        #[cfg(test)]
        let observation = TEST_OBSERVATION.with(|o| o.borrow().clone());
        let failure_marker = format!("\x1eWSSP_ENV_FAILED {nonce}\x1f").into_bytes();
        let size = request.size;
        let cancel = request.setup_cancel.clone();
        let doomed = reservation.cancellation();
        let started = Instant::now();
        let limits = limits();
        let overall = started
            + limits
                .overall
                .min(lifetime)
                .min(permit.remaining().unwrap_or(lifetime));
        let (tx, rx) = mpsc::channel();
        let (result_tx, result) = mpsc::sync_channel(1);
        let progress = tx.clone();
        let thread = thread::Builder::new()
            .name("wssp-pty-setup-watchdog".into())
            .spawn(move || {
                let closed = Arc::new(AtomicBool::new(false));
                let writer_done = Arc::new(AtomicBool::new(false));
                let (go, wait) = mpsc::sync_channel(1);
                let frame_written = Arc::new(AtomicBool::new(false));
                let read_written = frame_written.clone();
                let read_tx = progress.clone();
                let read_worker = thread::Builder::new()
                    .name("wssp-pty-setup-reader".into())
                    .spawn(move || {
                        let value = read_setup(reader, &nonce, &read_tx, &read_written);
                        let _ = read_tx.send(Progress::Read(value));
                    });
                let write_tx = progress.clone();
                let write_closed = closed.clone();
                let done = Done(writer_done.clone());
                #[cfg(test)]
                let write_observation = observation.clone();
                let write_worker = thread::Builder::new()
                    .name("wssp-pty-setup-writer".into())
                    .spawn(move || {
                        let _done = done;
                        let mut writer = writer;
                        let value = if wait.recv().is_ok() && !write_closed.load(Ordering::Acquire)
                        {
                            #[cfg(test)]
                            if let Some(o) = &write_observation {
                                o.writer_started.store(true, Ordering::Release);
                            }
                            writer
                                .write_all(&frame)
                                .and_then(|()| writer.flush())
                                .map(|()| {
                                    frame_written.store(true, Ordering::Release);
                                    writer
                                })
                                .map_err(|_| ())
                        } else {
                            Err(())
                        };
                        #[cfg(test)]
                        if let Some(o) = &write_observation {
                            o.writer_finished.store(true, Ordering::Release);
                        }
                        let _ = write_tx.send(Progress::Written(value));
                    });
                let mut workers = Vec::new();
                let mut failed = read_worker.is_err() || write_worker.is_err();
                if let Ok(worker) = read_worker {
                    workers.push(worker);
                }
                if let Ok(worker) = write_worker {
                    workers.push(worker);
                }
                let mut master = Some(master);
                let mut child: Option<IncusPtyChild> = None;
                let mut deadline = overall;
                let mut ready = false;
                let mut read = None;
                let mut written = None;
                let mut go = Some(go);
                let mut abandoned = false;
                loop {
                    #[cfg(test)]
                    if Instant::now() >= deadline
                        && let Some(o) = &observation
                    {
                        o.deadline_fired.store(true, Ordering::Release);
                    }
                    if Instant::now() >= deadline
                        || cancel.load(Ordering::Acquire)
                        || doomed()
                        || permit.is_cancelled()
                    {
                        failed = true;
                    }
                    if failed {
                        #[cfg(test)]
                        if let Some(o) = &observation {
                            o.closed
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .get_or_insert(Instant::now());
                            o.writer_blocked_at_close.store(
                                o.writer_started.load(Ordering::Acquire)
                                    && !o.writer_finished.load(Ordering::Acquire),
                                Ordering::Release,
                            );
                        }
                        closed.store(true, Ordering::Release);
                        permit.revoke();
                        go.take();
                        if child.is_some() || abandoned {
                            break;
                        }
                    }
                    if !failed && child.is_some() && read.is_some() && written.is_some() {
                        // Atomic with respect to this timer's state: once transferred,
                        // no competing timer/reader survives to touch these streams.
                        break;
                    }
                    let wait = if failed {
                        POLL
                    } else {
                        deadline.saturating_duration_since(Instant::now()).min(POLL)
                    };
                    match rx.recv_timeout(wait) {
                        Ok(Progress::Child(mut process)) => {
                            process.master = master.take();
                            child = Some(process);
                        }
                        Ok(Progress::Ready(at)) if !ready && !failed => {
                            ready = true;
                            #[cfg(test)]
                            if let Some(o) = &observation {
                                *o.ready.lock().unwrap_or_else(|e| e.into_inner()) = Some(at);
                            }
                            deadline = ready_deadline(overall, at, limits.handshake);
                            let tty_raw = child
                                .as_ref()
                                .and_then(|c| c.master.as_ref())
                                .or(master.as_ref())
                                .is_some_and(|m| raw(&**m));
                            if !tty_raw || Instant::now() >= deadline {
                                failed = true;
                            } else if let Some(go) = go.take() {
                                let _ = go.send(());
                            }
                        }
                        Ok(Progress::Read(Ok(value))) if ready && !failed => read = Some(value),
                        Ok(Progress::Written(Ok(value))) if !failed => written = Some(value),
                        Ok(Progress::Abort) => {
                            abandoned = true;
                            failed = true;
                        }
                        Ok(_) => failed = true,
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => {
                            abandoned = true;
                            failed = true;
                        }
                    }
                }
                closed.store(true, Ordering::Release);
                go.take();
                if !failed {
                    // Workers sent their owned streams and are now exiting. Joining
                    // finished workers is bounded and cannot wait on terminal IO.
                    join_finished(&mut workers, Instant::now() + JOIN);
                    if workers.is_empty()
                        && let (Some(child), Some((reader, after)), Some(writer)) =
                            (child.take(), read.take(), written.take())
                    {
                        let setup_failed = Arc::new(AtomicBool::new(false));
                        let parts = PtyParts {
                            child: Box::new(child),
                            reader: Box::new(SetupOutput {
                                reader: Box::new(Cursor::new(after).chain(reader)),
                                marker: failure_marker,
                                prefix: Vec::new(),
                                checked: false,
                                failed: setup_failed.clone(),
                            }),
                            writer,
                            setup_failed: Some(setup_failed),
                        };
                        let _ = result_tx.send(Ok(Opened {
                            reservation,
                            parts,
                            lifetime: lifetime.saturating_sub(started.elapsed()),
                        }));
                        return;
                    }
                }
                // Refusal suppresses all setup output, including late DONE. The timer
                // fires before any cleanup join, even with blocked read AND write.
                permit.revoke();
                drop(read);
                drop(written);
                let mut reaped = child
                    .as_mut()
                    .is_none_or(|c| c.terminate_and_reap().is_some());
                if let Some(process) = child.as_mut() {
                    process.unblock_writer(
                        &|| writer_done.load(Ordering::Acquire),
                        Instant::now() + DRAIN,
                    );
                    process.release();
                }
                master.take();
                join_finished(&mut workers, Instant::now() + JOIN);
                reaped &= workers.is_empty();
                #[cfg(test)]
                if let Some(o) = &observation {
                    o.workers_finished
                        .store(workers.is_empty(), Ordering::Release);
                }
                let error = if reaped {
                    failure()
                } else if let Some(child) = child {
                    crate::PtyOpenFailure::retain_cleanup(
                        reservation,
                        size,
                        Box::new(Cleanup {
                            child,
                            workers,
                            writer_done,
                        }),
                    )
                } else {
                    failure()
                };
                let _ = result_tx.send(Err(error));
            })
            .map_err(|_| failure())?;
        Ok(Self {
            tx,
            result,
            thread: Some(thread),
        })
    }
    pub(super) fn attach(&self, child: IncusPtyChild) {
        let _ = self.tx.send(Progress::Child(child));
    }
    pub(super) fn abort(self) -> crate::PtyOpenFailure {
        let _ = self.tx.send(Progress::Abort);
        self.finish().err().unwrap_or_else(failure)
    }
    pub(super) fn finish(mut self) -> Result<Opened, crate::PtyOpenFailure> {
        let result = self.result.recv().unwrap_or_else(|_| Err(failure()));
        if let Some(worker) = self.thread.take() {
            let mut workers = vec![worker];
            join_finished(&mut workers, Instant::now() + JOIN);
        }
        result
    }
}
impl Drop for Pending {
    fn drop(&mut self) {
        let _ = self.tx.send(Progress::Abort);
    }
}
fn join_finished(workers: &mut Vec<JoinHandle<()>>, deadline: Instant) {
    while !workers.is_empty() && Instant::now() < deadline {
        let mut i = 0;
        while i < workers.len() {
            if workers[i].is_finished() {
                let _ = workers.swap_remove(i).join();
            } else {
                i += 1;
            }
        }
        if !workers.is_empty() {
            thread::sleep(POLL);
        }
    }
}
/// The helper may fail execve after writing DONE. Only its fixed failure
/// marker is recognized/stripped at the start of post-DONE output. A normal
/// shell's bytes (including the first chunk after DONE) remain unchanged.
struct SetupOutput {
    reader: Reader,
    marker: Vec<u8>,
    prefix: Vec<u8>,
    checked: bool,
    failed: Arc<AtomicBool>,
}
impl Read for SetupOutput {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if !self.checked {
            while self.prefix.len() < self.marker.len() {
                let mut byte = [0];
                if self.reader.read(&mut byte)? == 0 {
                    break;
                }
                self.prefix.push(byte[0]);
                if self.prefix.last() != self.marker.get(self.prefix.len() - 1) {
                    break;
                }
            }
            self.checked = true;
            if !self.prefix.is_empty() && self.marker.starts_with(&self.prefix) {
                self.prefix.clear();
                self.failed.store(true, Ordering::Release);
                return Err(std::io::Error::other("terminal setup failed"));
            }
        }
        if !self.prefix.is_empty() {
            let count = out.len().min(self.prefix.len());
            out[..count].copy_from_slice(&self.prefix[..count]);
            self.prefix.drain(..count);
            return Ok(count);
        }
        self.reader.read(out)
    }
}

struct Cleanup {
    child: IncusPtyChild,
    workers: Vec<JoinHandle<()>>,
    writer_done: Arc<AtomicBool>,
}
impl PtyChild for Cleanup {
    fn try_reap(&mut self) -> Option<Option<i32>> {
        let status = self.child.try_reap();
        let mut index = 0;
        while index < self.workers.len() {
            if self.workers[index].is_finished() {
                let _ = self.workers.swap_remove(index).join();
            } else {
                index += 1;
            }
        }
        if self.workers.is_empty() {
            status
        } else {
            None
        }
    }
    fn terminate_and_reap(&mut self) -> Option<Option<i32>> {
        self.child.terminate_and_reap();
        self.child.unblock_writer(
            &|| self.writer_done.load(Ordering::Acquire),
            Instant::now() + DRAIN,
        );
        join_finished(&mut self.workers, Instant::now() + JOIN);
        self.try_reap()
    }
    fn resize(&mut self, _: PtySize) -> Result<(), RuntimeError> {
        Err(failure().error)
    }
    fn release(&mut self) {
        self.child.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pty_env_production_caps_and_ready_instant_never_extend_overall() {
        assert_eq!(OVERALL, Duration::from_secs(30));
        assert_eq!(HANDSHAKE, Duration::from_secs(5));
        let parsed = Instant::now();
        let overall = parsed + Duration::from_secs(3);
        assert_eq!(ready_deadline(overall, parsed, HANDSHAKE), overall);
        let earlier = parsed - Duration::from_secs(2);
        assert_eq!(
            ready_deadline(overall, earlier, Duration::from_secs(1)),
            earlier + Duration::from_secs(1)
        );
        assert!(ready_deadline(overall, earlier, Duration::from_secs(1)) < parsed);
    }
    struct OneByte(Cursor<Vec<u8>>);
    impl Read for OneByte {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(&mut out[..1])
        }
    }
    #[test]
    fn pty_env_parser_strips_byte_split_markers_and_preserves_same_chunk_shell_output() {
        for split in [true, false] {
            let (tx, _rx) = mpsc::channel();
            let data = b"\x1eWSSP_ENV_READY nonce\x1f\x1eWSSP_ENV_DONE nonce\x1fSHELL".to_vec();
            // A complete DONE captured alongside READY is a forged order.
            if !split {
                assert!(
                    read_setup(
                        Box::new(Cursor::new(data)),
                        "nonce",
                        &tx,
                        &AtomicBool::new(true)
                    )
                    .is_err()
                );
                continue;
            }
            let (mut reader, after) = read_setup(
                Box::new(OneByte(Cursor::new(data))),
                "nonce",
                &tx,
                &AtomicBool::new(true),
            )
            .unwrap();
            let mut output = after;
            reader.read_to_end(&mut output).unwrap();
            assert_eq!(output, b"SHELL");
        }
        let (tx, _rx) = mpsc::channel();
        let data = b"\x1eWSSP_ENV_READY nonce\x1f\x1eWSSP_ENV_DONE nonce\x1f".to_vec();
        assert!(
            read_setup(
                Box::new(OneByte(Cursor::new(data))),
                "nonce",
                &tx,
                &AtomicBool::new(false)
            )
            .is_err()
        );
    }
}
