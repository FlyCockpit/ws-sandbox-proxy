//! FakeRuntime terminal adapter (C51): deterministic, in-memory, scripted.
//!
//! The adapter plugs into the SAME session core as the Incus PTY, so
//! close/reap/expiry/backpressure semantics are shared. Tests drive the fake
//! child through [`FakePtyControl`]: scripted output, EOF and exit, and
//! observation of input, resizes, termination, reap and controller release.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::sync::{Arc, Condvar, Mutex};

use crate::pty::{PtyChild, PtyParts, PtySize};

/// The fake child's recorded input is capped like a real tty would refuse to
/// buffer without bound; writes past the cap fail.
const FAKE_INPUT_CAP: usize = 1024 * 1024;
/// End-of-transmission (^D): the fake shell treats it as EOF on stdin.
const EOT: u8 = 0x04;

#[derive(Debug, Default)]
struct Wire {
    output: VecDeque<u8>,
    output_eof: bool,
    input: Vec<u8>,
    sizes: Vec<PtySize>,
    exit: Option<Option<i32>>,
    echo: bool,
    terminated: bool,
    reaped: bool,
    released: bool,
    /// Scripted: termination never completes a reap (a child stuck in
    /// uninterruptible sleep).
    unreapable: bool,
}

#[derive(Debug, Default)]
struct Inner {
    wire: Mutex<Wire>,
    changed: Condvar,
}

impl Inner {
    fn with<T>(&self, f: impl FnOnce(&mut Wire) -> T) -> T {
        let mut wire = self.wire.lock().unwrap_or_else(|e| e.into_inner());
        let out = f(&mut wire);
        self.changed.notify_all();
        out
    }
}

/// Test/driver handle for one fake terminal. Never an attachment: it cannot
/// read the session's output stream or write through the session.
#[derive(Clone)]
pub struct FakePtyControl {
    inner: Arc<Inner>,
    instance_name: String,
    guest: crate::GuestIdentity,
    env: Vec<(String, String)>,
    cwd: Option<String>,
}

impl std::fmt::Debug for FakePtyControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FakePtyControl([REDACTED])")
    }
}
impl FakePtyControl {
    pub(super) fn set_env(&mut self, env: Vec<(String, String)>) {
        self.env = env;
    }
    pub fn env(&self) -> &[(String, String)] {
        &self.env
    }
    pub(super) fn set_cwd(&mut self, cwd: Option<String>) {
        self.cwd = cwd;
    }
    /// The shell's requested working directory (`None`: the guest home).
    pub fn cwd(&self) -> Option<&str> {
        self.cwd.as_deref()
    }

    /// The managed instance the session resolved (from the sandbox id).
    pub fn instance_name(&self) -> &str {
        &self.instance_name
    }
    /// The declared guest identity the shell runs as.
    pub fn guest(&self) -> &crate::GuestIdentity {
        &self.guest
    }
    /// Script a child that termination cannot reap within its bound.
    pub fn make_unreapable(&self) {
        self.inner.with(|wire| wire.unreapable = true);
    }
    /// The stuck child finally exits: the next reap attempt (a C55
    /// reconciliation sweep) succeeds.
    pub fn complete_stuck_reap(&self) {
        self.inner.with(|wire| {
            wire.unreapable = false;
            wire.exit.get_or_insert(None);
        });
    }
    /// Script child output.
    pub fn emit(&self, bytes: &[u8]) {
        self.inner.with(|wire| {
            if !wire.output_eof {
                wire.output.extend(bytes);
            }
        });
    }
    /// Echo input back as output (on by default, like a cooked tty).
    pub fn set_echo(&self, echo: bool) {
        self.inner.with(|wire| wire.echo = echo);
    }
    /// The child exits on its own with `code` (`None`: killed by a signal).
    pub fn exit(&self, code: Option<i32>) {
        self.inner.with(|wire| {
            wire.output_eof = true;
            wire.exit.get_or_insert(code);
        });
    }
    pub fn input(&self) -> Vec<u8> {
        self.inner.with(|wire| wire.input.clone())
    }
    /// Every size the child observed: the initial size, then each resize.
    pub fn sizes(&self) -> Vec<PtySize> {
        self.inner.with(|wire| wire.sizes.clone())
    }
    /// Bytes the child produced that the session reader has not pulled yet.
    pub fn pending_output(&self) -> usize {
        self.inner.with(|wire| wire.output.len())
    }
    pub fn terminated(&self) -> bool {
        self.inner.with(|wire| wire.terminated)
    }
    pub fn reaped(&self) -> bool {
        self.inner.with(|wire| wire.reaped)
    }
    pub fn released(&self) -> bool {
        self.inner.with(|wire| wire.released)
    }
}

struct FakeChild(Arc<Inner>);

impl PtyChild for FakeChild {
    fn try_reap(&mut self) -> Option<Option<i32>> {
        self.0.with(|wire| {
            let exit = wire.exit?;
            wire.reaped = true;
            Some(exit)
        })
    }
    fn terminate_and_reap(&mut self) -> Option<Option<i32>> {
        self.0.with(|wire| {
            wire.terminated = true;
            wire.output_eof = true;
            if wire.unreapable {
                return None;
            }
            wire.reaped = true;
            Some(*wire.exit.get_or_insert(None))
        })
    }
    fn resize(&mut self, size: PtySize) -> Result<(), crate::RuntimeError> {
        self.0.with(|wire| wire.sizes.push(size));
        Ok(())
    }
    fn release(&mut self) {
        self.0.with(|wire| {
            wire.released = true;
            wire.output_eof = true;
        });
    }
}

struct FakeReader(Arc<Inner>);

impl Read for FakeReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut wire = self.0.wire.lock().unwrap_or_else(|e| e.into_inner());
        while wire.output.is_empty() && !wire.output_eof {
            wire = self.0.changed.wait(wire).unwrap_or_else(|e| e.into_inner());
        }
        let n = buf.len().min(wire.output.len());
        for (slot, byte) in buf.iter_mut().zip(wire.output.drain(..n)) {
            *slot = byte;
        }
        Ok(n)
    }
}

struct FakeWriter(Arc<Inner>);

impl Write for FakeWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.with(|wire| {
            if wire.released || wire.exit.is_some() {
                return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
            }
            if wire.input.len() + buf.len() > FAKE_INPUT_CAP {
                return Err(std::io::Error::other("fake terminal input cap"));
            }
            wire.input.extend_from_slice(buf);
            if wire.echo {
                wire.output.extend(buf);
            }
            if buf.contains(&EOT) {
                // The fake shell reads EOF and exits cleanly.
                wire.output_eof = true;
                wire.exit.get_or_insert(Some(0));
            }
            Ok(buf.len())
        })
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(crate) fn fake_parts(
    instance_name: String,
    guest: crate::GuestIdentity,
    size: PtySize,
) -> (FakePtyControl, PtyParts) {
    let inner = Arc::new(Inner::default());
    inner.with(|wire| {
        wire.echo = true;
        wire.sizes.push(size);
    });
    let control = FakePtyControl {
        inner: inner.clone(),
        instance_name,
        guest,
        env: Vec::new(),
        cwd: None,
    };
    let parts = PtyParts {
        setup_failed: None,
        child: Box::new(FakeChild(inner.clone())),
        reader: Box::new(FakeReader(inner.clone())),
        writer: Box::new(FakeWriter(inner)),
    };
    (control, parts)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use sandbox_protocol::SandboxErrorCode;

    use crate::{
        CreateSandboxRequest, FakeRuntime, KillSandboxRequest, OpenPtyRequest, PtyCloseIntent,
        PtyEvent, PtySession, PtySize, PtyTermination, SandboxRuntime, StopSandboxRequest,
    };

    fn runtime() -> (FakeRuntime, String) {
        let runtime = FakeRuntime::new();
        let create = CreateSandboxRequest::for_test("sbx-1", "create-1");
        runtime.create_fixture(&create).unwrap();
        (runtime, create.template_digest)
    }

    fn request(fp: &str, session_id: &str) -> OpenPtyRequest {
        OpenPtyRequest {
            template_fingerprint: fp.into(),
            sandbox_id: "sbx-1".into(),
            session_id: session_id.into(),
            guest: Default::default(),
            size: PtySize::new(24, 80).unwrap(),
            max_duration: None,
            env: Vec::new(),
            cwd: None,
            setup_cancel: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    fn collect(session: &mut PtySession, want: usize) -> Vec<u8> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut out = Vec::new();
        while out.len() < want && Instant::now() < deadline {
            match session.next_event(Duration::from_millis(20)).unwrap() {
                Some(PtyEvent::Output(bytes)) => out.extend(bytes),
                Some(PtyEvent::Ended(done)) => panic!("ended early: {done:?}"),
                None => {}
            }
        }
        out
    }

    fn ended(session: &mut PtySession) -> PtyTermination {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Some(PtyEvent::Ended(done)) =
                session.next_event(Duration::from_millis(20)).unwrap()
            {
                return done;
            }
        }
        panic!("never ended")
    }

    fn wait(cond: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !cond() {
            assert!(Instant::now() < deadline, "condition never held");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn c51_fake_parity_identity_echo_output_resize_and_eof() {
        let (runtime, fp) = runtime();
        assert!(runtime.pty_capability());
        let mut session = runtime.open_pty(&request(&fp, "term-1")).unwrap();
        let control = runtime.pty_control("sbx-1", "term-1").unwrap();
        // Derived from the request (sandbox id and declared identity). The
        // exact `incus exec -t` trace is proven by the Incus shim test
        // `c51_trace_is_exactly_incus_exec_t_for_the_resolved_sandbox_and_never_a_host_shell`;
        // the fake has no argv to prove.
        assert_eq!(control.instance_name(), "wssp-sbx-sbx-1");
        assert_eq!(control.guest(), &crate::GuestIdentity::default());
        session.write_input(b"hi\n").unwrap();
        assert_eq!(collect(&mut session, 3), b"hi\n");
        control.emit(b"prompt$ ");
        assert_eq!(collect(&mut session, 8), b"prompt$ ");
        session.resize(PtySize::new(40, 100).unwrap()).unwrap();
        assert_eq!(
            control.sizes(),
            [
                PtySize::new(24, 80).unwrap(),
                PtySize::new(40, 100).unwrap()
            ]
        );
        assert_eq!(session.size(), PtySize::new(40, 100).unwrap());
        session.write_input(b"\x04").unwrap();
        assert_eq!(collect(&mut session, 1), b"\x04");
        assert_eq!(
            ended(&mut session),
            PtyTermination::ChildExited { exit_code: Some(0) }
        );
        assert!(control.reaped() && control.released() && !control.terminated());
        assert_eq!(control.input(), b"hi\n\x04");
        // Close after exit is a no-op that reports the exit.
        assert_eq!(
            session.close(PtyCloseIntent::Client),
            PtyTermination::ChildExited { exit_code: Some(0) }
        );
        assert!(!control.terminated());
    }

    #[test]
    fn c51_fake_destroy_stop_expiry_and_shutdown_close_and_reap() {
        for case in ["destroy", "stop", "expiry", "shutdown", "client", "detach"] {
            let (runtime, fp) = runtime();
            let mut req = request(&fp, "term-1");
            if case == "expiry" {
                req.max_duration = Some(Duration::from_millis(100));
            }
            let mut session = runtime.open_pty(&req).unwrap();
            let control = runtime.pty_control("sbx-1", "term-1").unwrap();
            let expected = match case {
                "destroy" => {
                    runtime
                        .kill_fixture(&KillSandboxRequest {
                            template_fingerprint: fp.clone(),
                            sandbox_id: "sbx-1".into(),
                            instance_name: "wssp-sbx-sbx-1".into(),
                            operation_id: "kill".into(),
                            idempotency_key: "kill".into(),
                        })
                        .unwrap();
                    PtyCloseIntent::SandboxDestroyed
                }
                "stop" => {
                    runtime
                        .stop_sandbox(&StopSandboxRequest {
                            template_fingerprint: fp.clone(),
                            sandbox_id: "sbx-1".into(),
                            instance_name: "wssp-sbx-sbx-1".into(),
                            operation_id: "stop".into(),
                            idempotency_key: "stop".into(),
                        })
                        .unwrap();
                    PtyCloseIntent::SandboxStopped
                }
                "expiry" => PtyCloseIntent::Expired,
                "shutdown" => {
                    assert_eq!(
                        runtime.close_pty_sessions(None, PtyCloseIntent::Shutdown),
                        1
                    );
                    PtyCloseIntent::Shutdown
                }
                "client" => {
                    session.close(PtyCloseIntent::Client);
                    PtyCloseIntent::Client
                }
                _ => {
                    drop(session);
                    wait(|| control.released());
                    assert!(control.terminated() && control.reaped());
                    continue;
                }
            };
            // No consumer read was needed for the close/reap itself.
            wait(|| control.released());
            assert!(control.terminated() && control.reaped(), "{case}");
            let done = PtyTermination::Closed {
                intent: expected,
                exit_code: None,
                reaped: true,
            };
            assert_eq!(ended(&mut session), done, "{case}");
            // Idempotent: repeated closes and runtime sweeps change nothing.
            assert_eq!(session.close(PtyCloseIntent::Client), done);
            assert_eq!(
                runtime.close_pty_sessions(Some("sbx-1"), PtyCloseIntent::Shutdown),
                0
            );
            assert_eq!(session.termination(), Some(done));
            assert_eq!(
                session.write_input(b"x").unwrap_err().code,
                SandboxErrorCode::StateConflict
            );
            if matches!(case, "destroy" | "stop") {
                assert!(runtime.open_pty(&request(&fp, "term-2")).is_err());
            }
        }
    }

    #[test]
    fn c51_fake_output_queue_is_bounded_and_lossless_while_attached() {
        let (runtime, fp) = runtime();
        let mut session = runtime.open_pty(&request(&fp, "term-1")).unwrap();
        let control = runtime.pty_control("sbx-1", "term-1").unwrap();
        let total = crate::PTY_OUTPUT_QUEUE_CHUNKS * crate::PTY_OUTPUT_CHUNK_BYTES * 4;
        let payload: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        control.emit(&payload);
        std::thread::sleep(Duration::from_millis(300));
        // The reader stops pulling once the bounded queue is full: at most
        // the queue plus one in-flight chunk left the child.
        let pulled = total - control.pending_output();
        assert!(
            pulled <= (crate::PTY_OUTPUT_QUEUE_CHUNKS + 1) * crate::PTY_OUTPUT_CHUNK_BYTES,
            "runtime buffered {pulled} bytes"
        );
        let mut received = Vec::new();
        while received.len() < total {
            match session.next_event(Duration::from_secs(5)).unwrap() {
                Some(PtyEvent::Output(bytes)) => {
                    assert!(bytes.len() <= crate::PTY_OUTPUT_CHUNK_BYTES);
                    received.extend(bytes);
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(received, payload);
    }

    #[test]
    fn c51_fake_input_queue_is_bounded() {
        let (runtime, fp) = runtime();
        let mut session = runtime.open_pty(&request(&fp, "term-1")).unwrap();
        assert_eq!(
            session
                .write_input(&vec![b'a'; crate::PTY_INPUT_MAX_BYTES + 1])
                .unwrap_err()
                .code,
            SandboxErrorCode::RequestTooLarge
        );
        session.write_input(b"").unwrap();
    }

    #[test]
    fn c51_fake_refuses_foreign_missing_or_duplicate_sessions() {
        let (runtime, fp) = runtime();
        let mut foreign = request(&format!("sha256:{}", "0".repeat(64)), "term-1");
        assert_eq!(
            runtime.open_pty(&foreign).unwrap_err().code,
            SandboxErrorCode::IdempotencyConflict
        );
        foreign.template_fingerprint = fp.clone();
        foreign.sandbox_id = "sbx-missing".into();
        assert_eq!(
            runtime.open_pty(&foreign).unwrap_err().code,
            SandboxErrorCode::SandboxNotFound
        );
        let mut first = runtime.open_pty(&request(&fp, "term-1")).unwrap();
        assert_eq!(
            runtime.open_pty(&request(&fp, "term-1")).unwrap_err().code,
            SandboxErrorCode::StateConflict
        );
        first.close(PtyCloseIntent::Client);
        let mut again = runtime.open_pty(&request(&fp, "term-1")).unwrap();
        again.close(PtyCloseIntent::Client);
        let permit = std::sync::Arc::new(crate::RuntimePermit::default());
        permit.revoke();
        assert!(
            runtime
                .with_cancellation(permit)
                .open_pty(&request(&fp, "term-3"))
                .is_err()
        );
    }

    /// C51-CC-3: a close reports whether the child was actually reaped.
    #[test]
    fn c51_close_distinguishes_a_reaped_child_from_an_uncertain_reap() {
        let (runtime, fp) = runtime();
        let mut reaped = runtime.open_pty(&request(&fp, "term-1")).unwrap();
        let mut stuck = runtime.open_pty(&request(&fp, "term-2")).unwrap();
        let stuck_control = runtime.pty_control("sbx-1", "term-2").unwrap();
        stuck_control.make_unreapable();
        assert_eq!(
            reaped.close(PtyCloseIntent::Client),
            PtyTermination::Closed {
                intent: PtyCloseIntent::Client,
                exit_code: None,
                reaped: true,
            }
        );
        let uncertain = PtyTermination::Closed {
            intent: PtyCloseIntent::Client,
            exit_code: None,
            reaped: false,
        };
        assert_eq!(stuck.close(PtyCloseIntent::Client), uncertain);
        assert!(stuck_control.terminated() && !stuck_control.reaped());
        // The uncertainty is the stable terminal state, never upgraded.
        assert_eq!(stuck.close(PtyCloseIntent::Shutdown), uncertain);
        assert_eq!(ended(&mut stuck), uncertain);
    }

    /// C55 (C52-F-4): an uncertain reap is confirmed only by a later sweep
    /// attempt that actually reaps the retained child. Never optimistic, never
    /// rewriting the recorded termination.
    #[test]
    fn c55_uncertain_reap_is_confirmed_only_by_a_later_successful_reap() {
        let (runtime, fp) = runtime();
        let mut running = runtime.open_pty(&request(&fp, "term-1")).unwrap();
        assert!(!running.reap_confirmed(), "a live session is not reaped");
        assert_eq!(
            running.close(PtyCloseIntent::Client),
            PtyTermination::Closed {
                intent: PtyCloseIntent::Client,
                exit_code: None,
                reaped: true,
            }
        );
        assert!(
            running.reap_confirmed(),
            "a reaped close is confirmed at once"
        );

        let mut stuck = runtime.open_pty(&request(&fp, "term-2")).unwrap();
        let control = runtime.pty_control("sbx-1", "term-2").unwrap();
        control.make_unreapable();
        let uncertain = stuck.close(PtyCloseIntent::Client);
        assert!(matches!(
            uncertain,
            PtyTermination::Closed { reaped: false, .. }
        ));
        for _ in 0..3 {
            assert!(!stuck.reap_confirmed(), "the sweep never assumes a reap");
        }
        assert!(!control.reaped());
        control.complete_stuck_reap();
        assert!(stuck.reap_confirmed());
        assert!(control.reaped());
        // Idempotent, and the recorded outcome stays the uncertainty.
        assert!(stuck.reap_confirmed());
        assert_eq!(stuck.termination(), Some(uncertain));
    }

    /// A pre-pump attach failure retains uncertainty after releasing the tty.
    #[cfg(target_os = "linux")]
    #[test]
    fn attach_failure_retains_child_until_reap_proof() {
        let registry = crate::pty::PtyRegistry::default();
        let reservation = registry.reserve("term-1", "sbx-1").unwrap();
        let size = PtySize::new(24, 80).unwrap();
        let (control, parts) = super::fake_parts("wssp-sbx-sbx-1".into(), Default::default(), size);
        control.make_unreapable();
        let failure = crate::PtyOpenFailure::after_spawn(reservation, size, parts.child);
        assert_eq!(failure.error.message, "terminal setup failed");
        let mut cleanup = failure.cleanup.unwrap();
        assert!(control.terminated() && !control.reaped() && control.released());
        assert!(cleanup.write_input(b"never delivered").is_err());
        assert!(!cleanup.reap_confirmed());
        control.complete_stuck_reap();
        assert!(cleanup.reap_confirmed());
        assert!(control.reaped() && control.released());
    }

    /// C51-TB-5: the same session id in two sandboxes is two sessions.
    #[test]
    fn c51_session_ids_do_not_collide_across_sandboxes() {
        let (runtime, fp) = runtime();
        runtime
            .create_fixture(&CreateSandboxRequest::for_test("sbx-2", "create-2"))
            .unwrap();
        let a = runtime.open_pty(&request(&fp, "term-1")).unwrap();
        let mut other = request(&fp, "term-1");
        other.sandbox_id = "sbx-2".into();
        let mut b = runtime.open_pty(&other).unwrap();
        let control_b = runtime.pty_control("sbx-2", "term-1").unwrap();
        assert_eq!(control_b.instance_name(), "wssp-sbx-sbx-2");
        assert_eq!(
            runtime.close_pty_sessions(Some("sbx-1"), PtyCloseIntent::Shutdown),
            1
        );
        assert!(a.termination().is_some() && b.termination().is_none());
        b.write_input(b"still-here\n").unwrap();
        assert_eq!(collect(&mut b, 11), b"still-here\n");
        b.close(PtyCloseIntent::Client);
    }

    /// A stop/destroy that lands between admission and start dooms the
    /// reservation: the new child is terminated and reaped, never attached.
    #[test]
    fn c51_close_during_open_dooms_the_reservation() {
        let registry = crate::pty::PtyRegistry::default();
        let reservation = registry.reserve("term-1", "sbx-1").unwrap();
        assert_eq!(
            registry.close_matching(Some("sbx-1"), PtyCloseIntent::SandboxDestroyed),
            1
        );
        let size = PtySize::new(24, 80).unwrap();
        let (control, parts) = super::fake_parts("wssp-sbx-sbx-1".into(), Default::default(), size);
        let err = PtySession::start(reservation, size, Duration::from_secs(60), parts).unwrap_err();
        assert_eq!(err.code, SandboxErrorCode::SandboxNotRunning);
        assert!(control.terminated() && control.reaped() && control.released());
        // The id is free again and unrelated sandboxes are untouched.
        let _other = registry.reserve("term-1", "sbx-1").unwrap();
        assert_eq!(
            registry.close_matching(Some("sbx-2"), PtyCloseIntent::Shutdown),
            0
        );
    }
}
