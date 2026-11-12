//! C52 host terminal tests: real `TerminalHost` + pump threads + journal +
//! authority over the FakeRuntime PTY adapter (no Incus, no socket).
use super::*;
use crate::sandbox_relay::journal::{HostJournal, TransportBindingV11, intent_from_dispatch};
use crate::sandbox_relay::test_support::FixtureRuntime;
use sandbox_protocol::parse_terminal_frame;
use sandbox_runtime::{CreateSandboxRequest, FakeRuntime};
use serde_json::json;

/// Test view of [`Outgoing`] without the box.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum Out {
    Text(DaemonControlMessage),
    Binary(Vec<u8>),
}
impl From<Outgoing> for Out {
    fn from(out: Outgoing) -> Self {
        match out {
            Outgoing::Text(message) => Out::Text(*message),
            Outgoing::Binary(bytes) => Out::Binary(bytes),
        }
    }
}
fn outs(out: Vec<Outgoing>) -> Vec<Out> {
    out.into_iter().map(Out::from).collect()
}

const FP: &str = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

struct Rig {
    _dir: tempfile::TempDir,
    fake: FakeRuntime,
    journal: Arc<HostJournal>,
    authority: HostAuthority,
    slots: Arc<TerminalSlots>,
    host: TerminalHost,
}

fn binding() -> TransportBindingV11 {
    TransportBindingV11 {
        server: "wss://relay.test/ws/sandbox-host".into(),
        host_owner_id: "owner-1".into(),
        host_id: "host-1".into(),
    }
}

fn accept(journal: &HostJournal, sandbox: &str, generation: u64, guest: bool) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let op = format!("create-{sandbox}-{generation}");
    let mut value = json!({"sandboxOwnerId":"owner",
        "operationId": op, "sandboxId": sandbox, "kind": "sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(),
        "generation": generation, "attempt": 1, "idempotencyKey": op,
        "bodyHash": "a".repeat(64), "incusFingerprint": FP, "templateDigest": FP,
        "lease": {"revision": generation, "deadlineUnixMs": now + 3_600_000,
                  "action": "stop", "expiryPolicy": "retry-force-60s"},
    });
    if guest {
        value["guestUid"] = json!(1234);
        value["guestGid"] = json!(2345);
        value["guestHome"] = json!("/home/declared");
        value["guestShell"] = json!("/bin/zsh");
    }
    let d: OperationDispatch = serde_json::from_value(value).unwrap();
    journal
        .record_fixture_intent(&intent_from_dispatch(journal, &binding(), &d))
        .unwrap();
    journal.accept_fixture_lease(&d).unwrap();
}

fn rig() -> Rig {
    rig_with(|fake| Arc::new(fake))
}

/// A rig whose terminal host drives `wrap(fake)` instead of the fake itself.
fn rig_with(wrap: impl FnOnce(FakeRuntime) -> Arc<dyn SandboxRuntime>) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let journal =
        Arc::new(crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap());
    accept(&journal, "sbx-1", 1, true);
    let fake = FakeRuntime::new();
    fake.fixture_root().unwrap();
    fake.create_fixture(&CreateSandboxRequest::for_test("sbx-1", "create-sbx-1-1"))
        .unwrap();
    let authority = HostAuthority::with_journal(journal.clone());
    let slots = Arc::new(TerminalSlots::default());
    let runtime = wrap(fake.clone());
    let mut host = TerminalHost::new(
        slots.clone(),
        runtime,
        journal.clone(),
        authority.clone(),
        "host-1".into(),
    );
    host.enable(5, binding());
    Rig {
        _dir: dir,
        fake,
        journal,
        authority,
        slots,
        host,
    }
}

fn fence(session: &str) -> TerminalFence {
    TerminalFence {
        session_id: session.into(),
        operation_id: format!("top-{session}"),
        host_id: "host-1".into(),
        target: sandbox_protocol::TerminalTargetV11::Sandbox {
            sandbox_id: "sbx-1".into(),
            generation: 1,
        },
        epoch: 5,
    }
}

fn open(rig: &mut Rig, fence: &TerminalFence) -> Vec<Out> {
    outs(
        rig.host
            .handle_control(ServerControlMessage::TerminalOpen {
                host_policy: None,
                request_id: format!("open-{}", fence.session_id),
                fence: fence.clone(),
                rows: 24,
                cols: 80,
                cwd: None,
            })
            .unwrap(),
    )
}

fn input(rig: &mut Rig, fence: &TerminalFence, sequence: u64, bytes: &[u8]) {
    rig.host
        .handle_input(
            TerminalDataMetadata {
                r#type: TerminalDataKind::Data,
                fence: fence.clone(),
                sequence,
            },
            bytes.to_vec(),
        )
        .unwrap();
}

/// Poll until `done` holds over everything collected so far (10 s bound).
fn drive(rig: &mut Rig, done: impl Fn(&[Out]) -> bool) -> Vec<Out> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut out = Vec::new();
    loop {
        out.extend(outs(rig.host.poll().unwrap()));
        if done(&out) {
            return out;
        }
        assert!(Instant::now() < deadline, "never reached: {out:?}");
        thread::sleep(Duration::from_millis(5));
    }
}

/// Poll for a fixed time (for "nothing more happens" assertions).
fn settle(rig: &mut Rig, wait: Duration) -> Vec<Out> {
    let deadline = Instant::now() + wait;
    let mut out = Vec::new();
    while Instant::now() < deadline {
        out.extend(outs(rig.host.poll().unwrap()));
        thread::sleep(Duration::from_millis(5));
    }
    out
}

fn ready(out: &[Out]) -> bool {
    out.iter()
        .any(|o| matches!(o, Out::Text(DaemonControlMessage::TerminalReady { .. })))
}
fn exit(out: &[Out]) -> Option<DaemonControlMessage> {
    out.iter().find_map(|o| match o {
        Out::Text(m @ DaemonControlMessage::TerminalExit { .. }) => Some(m.clone()),
        _ => None,
    })
}
fn acks(out: &[Out]) -> Vec<u64> {
    out.iter()
        .filter_map(|o| match o {
            Out::Text(DaemonControlMessage::TerminalAck { sequence, .. }) => Some(*sequence),
            _ => None,
        })
        .collect()
}
fn output(out: &[Out]) -> Vec<(u64, Vec<u8>)> {
    out.iter()
        .filter_map(|o| match o {
            Out::Binary(bytes) => {
                let (meta, body) = parse_terminal_frame(bytes).unwrap().unwrap();
                Some((meta.sequence, body))
            }
            _ => None,
        })
        .collect()
}

fn opened(rig: &mut Rig, session: &str) -> (TerminalFence, sandbox_runtime::FakePtyControl) {
    let fence = fence(session);
    assert!(open(rig, &fence).is_empty());
    drive(rig, ready);
    let control = rig
        .fake
        .pty_control("sbx-1", session)
        .expect("pty allocated");
    (fence, control)
}

#[test]
fn c52_open_takes_identity_from_the_journal_and_echoes_the_request_id() {
    let mut rig = rig();
    let fence = fence("term-1");
    assert!(open(&mut rig, &fence).is_empty());
    let out = drive(&mut rig, ready);
    match &out[0] {
        Out::Text(DaemonControlMessage::TerminalReady {
            request_id,
            fence: echoed,
            rows,
            cols,
            ..
        }) => {
            assert_eq!(request_id, "open-term-1");
            assert_eq!(echoed, &fence);
            assert_eq!((*rows, *cols), (24, 80));
        }
        other => panic!("first frame must be ready: {other:?}"),
    }
    let control = rig.fake.pty_control("sbx-1", "term-1").unwrap();
    assert_eq!(control.instance_name(), "wssp-sbx-sbx-1");
    assert_eq!(control.guest().guest_uid, 1234);
    assert_eq!(control.guest().guest_gid, 2345);
    assert_eq!(control.guest().guest_home, "/home/declared");
    assert_eq!(control.guest().guest_shell, "/bin/zsh");
}

/// WP7: a quiescing daemon refuses new opens locally (no PTY), with the
/// host-unavailable code; live sessions are not touched.
#[test]
fn wp7_a_quiescing_daemon_refuses_new_terminal_opens() {
    let mut rig = rig();
    let (live, _) = opened(&mut rig, "term-live");
    // The shared request, read at the open itself (a
    // snapshot taken before a blocking read went stale).
    let state = Arc::new(crate::sandbox_relay::quiesce::QuiesceState::default());
    rig.host.set_quiesce(state.clone());
    assert!(open(&mut rig, &fence("term-before")).is_empty());
    state.enable();
    state.request();
    let refused = fence("term-new");
    let out = open(&mut rig, &refused);
    let Some(DaemonControlMessage::TerminalExit {
        request_id,
        fence: echoed,
        error: Some(error),
        ..
    }) = exit(&out)
    else {
        panic!("refusal expected: {out:?}");
    };
    assert_eq!(request_id.as_deref(), Some("open-term-new"));
    assert_eq!(echoed, refused);
    assert_eq!(error.code, SandboxErrorCode::Disconnected);
    assert!(rig.fake.pty_control("sbx-1", "term-new").is_none());
    assert!(exit(&settle(&mut rig, Duration::from_millis(50))).is_none());
    assert!(rig.host.sessions.contains_key(&live.session_id));
}

#[test]
fn e1_a_06_guest_terminal_opens_in_the_frame_cwd_else_the_home() {
    let mut rig = rig();
    let fence = fence("term-cwd");
    rig.host
        .handle_control(ServerControlMessage::TerminalOpen {
            host_policy: None,
            request_id: "open-term-cwd".into(),
            fence: fence.clone(),
            rows: 24,
            cols: 80,
            cwd: Some("/srv/app".into()),
        })
        .unwrap();
    drive(&mut rig, ready);
    let control = rig.fake.pty_control("sbx-1", "term-cwd").unwrap();
    assert_eq!(control.cwd(), Some("/srv/app"));
    let mut rig = self::rig();
    let (_, control) = opened(&mut rig, "term-home");
    assert_eq!(control.cwd(), None);
}

#[test]
fn c52_input_is_sequenced_acked_and_duplicates_or_gaps_write_zero_bytes() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "term-1");
    control.set_echo(false);
    input(&mut rig, &fence, 0, b"ab");
    assert_eq!(acks(&drive(&mut rig, |o| !acks(o).is_empty())), vec![0]);
    // Replayed input: zero bytes, no ack.
    input(&mut rig, &fence, 0, b"ab");
    input(&mut rig, &fence, 1, b"c");
    assert_eq!(acks(&drive(&mut rig, |o| !acks(o).is_empty())), vec![1]);
    assert_eq!(control.input(), b"abc");
    // A gap closes the session; the gapped bytes never reach the PTY.
    input(&mut rig, &fence, 5, b"zzz");
    let out = drive(&mut rig, |o| exit(o).is_some());
    match exit(&out).unwrap() {
        DaemonControlMessage::TerminalExit {
            intent,
            error,
            reaped,
            ..
        } => {
            assert_eq!(intent, Some(TerminalCloseIntent::ProtocolViolation));
            assert_eq!(error.unwrap().code, SandboxErrorCode::ProtocolError);
            assert!(reaped);
        }
        _ => unreachable!(),
    }
    assert_eq!(control.input(), b"abc");
    assert!(control.reaped());
}

#[test]
fn c52_mismatched_identity_legs_write_zero_bytes_and_repeat_violations_close() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "term-1");
    control.set_echo(false);
    // Unknown session id: foreign, dropped, not a violation of the live one.
    input(
        &mut rig,
        &TerminalFence {
            session_id: "term-other".into(),
            ..fence.clone()
        },
        0,
        b"x",
    );
    let legs = [
        TerminalFence {
            target: sandbox_protocol::TerminalTargetV11::Sandbox {
                sandbox_id: "sbx-1".into(),
                generation: 2,
            },
            ..fence.clone()
        },
        TerminalFence {
            epoch: 6,
            ..fence.clone()
        },
        TerminalFence {
            host_id: "host-2".into(),
            ..fence.clone()
        },
        TerminalFence {
            operation_id: "top-forged".into(),
            ..fence.clone()
        },
        TerminalFence {
            target: sandbox_protocol::TerminalTargetV11::Sandbox {
                sandbox_id: "sbx-2".into(),
                generation: 1,
            },
            ..fence.clone()
        },
    ];
    // Two violations keep the session alive and deliver nothing.
    for leg in &legs[..2] {
        input(&mut rig, leg, 0, b"x");
    }
    let out = settle(&mut rig, Duration::from_millis(150));
    assert!(acks(&out).is_empty() && exit(&out).is_none(), "{out:?}");
    assert!(control.input().is_empty());
    // The genuine fence still works.
    input(&mut rig, &fence, 0, b"ok");
    drive(&mut rig, |o| acks(o) == [0]);
    assert_eq!(control.input(), b"ok");
    // The third violation closes it; every remaining leg writes zero bytes.
    for leg in &legs[2..] {
        input(&mut rig, leg, 1, b"x");
    }
    let out = drive(&mut rig, |o| exit(o).is_some());
    assert!(matches!(
        exit(&out),
        Some(DaemonControlMessage::TerminalExit {
            intent: Some(TerminalCloseIntent::ProtocolViolation),
            ..
        })
    ));
    assert_eq!(control.input(), b"ok");
    assert!(acks(&out).is_empty());
}

#[test]
fn c52_output_window_bounds_unacknowledged_frames() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "term-1");
    // Far more than the PTY queue plus the window can hold.
    control.emit(&vec![b'y'; 200 * sandbox_protocol::TERMINAL_DATA_MAX_BYTES]);
    let out = settle(&mut rig, Duration::from_millis(400));
    let frames = output(&out);
    assert_eq!(frames.len() as u64, TERMINAL_OUTPUT_WINDOW_FRAMES, "window");
    assert_eq!(
        frames.iter().map(|(s, _)| *s).collect::<Vec<_>>(),
        (0..TERMINAL_OUTPUT_WINDOW_FRAMES).collect::<Vec<_>>()
    );
    assert!(control.pending_output() > 0, "the shell is back-pressured");
    // An ack beyond what was sent is a violation and returns no credit.
    rig.host
        .handle_control(ServerControlMessage::TerminalAck {
            fence: fence.clone(),
            sequence: 50,
        })
        .unwrap();
    assert!(output(&settle(&mut rig, Duration::from_millis(150))).is_empty());
    // Acknowledging the window returns exactly one window of credit.
    rig.host
        .handle_control(ServerControlMessage::TerminalAck {
            fence: fence.clone(),
            sequence: TERMINAL_OUTPUT_WINDOW_FRAMES - 1,
        })
        .unwrap();
    let more = output(&settle(&mut rig, Duration::from_millis(400)));
    assert_eq!(more.len() as u64, TERMINAL_OUTPUT_WINDOW_FRAMES);
    assert_eq!(more[0].0, TERMINAL_OUTPUT_WINDOW_FRAMES);
}

#[test]
fn c52_exit_before_open_ack_is_ordered_ready_output_exit() {
    let mut rig = rig();
    let fence = fence("term-1");
    assert!(open(&mut rig, &fence).is_empty());
    // The child prints and exits before the socket loop forwarded `ready`.
    let deadline = Instant::now() + Duration::from_secs(10);
    let control = loop {
        if let Some(control) = rig.fake.pty_control("sbx-1", "term-1") {
            break control;
        }
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(1));
    };
    control.set_echo(false);
    control.emit(b"bye");
    control.exit(Some(3));
    let out = drive(&mut rig, |o| exit(o).is_some());
    assert!(matches!(
        out.first(),
        Some(Out::Text(DaemonControlMessage::TerminalReady { .. }))
    ));
    assert_eq!(output(&out), vec![(0, b"bye".to_vec())]);
    assert!(matches!(
        out.last(),
        Some(Out::Text(DaemonControlMessage::TerminalExit {
            exit_code: Some(3),
            intent: None,
            reaped: true,
            error: None,
            ..
        }))
    ));
    assert!(rig.slots.wait_idle(Duration::from_secs(5)));
    // The ended id is tombstoned: a late frame for it is silently dropped
    // and a re-open of the same id never reaches a PTY.
    input(&mut rig, &fence, 0, b"late");
    assert!(open(&mut rig, &fence).is_empty());
    assert_eq!(rig.host.live_sessions(), 0);
}

#[test]
fn c52_stale_foreign_or_unbound_opens_allocate_no_pty() {
    let mut rig = rig();
    accept(&rig.journal, "sbx-noguest", 1, false);
    let refused = |rig: &mut Rig, fence: TerminalFence| -> Option<SandboxErrorCode> {
        let out = open(rig, &fence);
        assert!(
            rig.fake
                .pty_control(
                    match &fence.target {
                        sandbox_protocol::TerminalTargetV11::Sandbox { sandbox_id, .. } =>
                            sandbox_id,
                        _ => unreachable!(),
                    },
                    &fence.session_id
                )
                .is_none()
        );
        exit(&out).map(|m| match m {
            DaemonControlMessage::TerminalExit { error, reaped, .. } => {
                assert!(reaped);
                error.unwrap().code.known().unwrap()
            }
            _ => unreachable!(),
        })
    };
    // Stale generation (the journal holds generation 1).
    assert_eq!(
        refused(
            &mut rig,
            TerminalFence {
                target: sandbox_protocol::TerminalTargetV11::Sandbox {
                    sandbox_id: "sbx-1".into(),
                    generation: 2
                },
                ..fence("t-gen")
            }
        ),
        Some(SandboxErrorCode::StateConflict)
    );
    // Unknown sandbox and a sandbox without a recorded guest identity.
    assert_eq!(
        refused(
            &mut rig,
            TerminalFence {
                target: sandbox_protocol::TerminalTargetV11::Sandbox {
                    sandbox_id: "sbx-none".into(),
                    generation: 1
                },
                ..fence("t-none")
            }
        ),
        Some(SandboxErrorCode::SandboxNotFound)
    );
    assert_eq!(
        refused(
            &mut rig,
            TerminalFence {
                target: sandbox_protocol::TerminalTargetV11::Sandbox {
                    sandbox_id: "sbx-noguest".into(),
                    generation: 1
                },
                ..fence("t-ng")
            }
        ),
        Some(SandboxErrorCode::UnsupportedCapability)
    );
    // Foreign epoch / host: dropped without any reply or PTY.
    assert_eq!(
        refused(
            &mut rig,
            TerminalFence {
                epoch: 4,
                ..fence("t-ep")
            }
        ),
        None
    );
    assert_eq!(
        refused(
            &mut rig,
            TerminalFence {
                host_id: "host-2".into(),
                ..fence("t-h")
            }
        ),
        None
    );
    // A superseded generation (observed by authority) is refused too.
    rig.authority
        .accept_dispatch("stop-1", "sbx-1", "sandbox.stop", 2, 1)
        .unwrap();
    assert_eq!(
        refused(&mut rig, fence("t-sup")),
        Some(SandboxErrorCode::StateConflict)
    );
    assert_eq!(rig.slots.live(), 0);
    assert_eq!(rig.host.live_sessions(), 0);
}

#[test]
fn c52_frames_before_terminal_negotiation_are_a_protocol_error() {
    let rig = rig();
    let mut host = TerminalHost::new(
        rig.slots.clone(),
        Arc::new(rig.fake.clone()),
        rig.journal.clone(),
        rig.authority.clone(),
        "host-1".into(),
    );
    assert!(
        host.handle_control(ServerControlMessage::TerminalOpen {
            host_policy: None,
            request_id: "r".into(),
            fence: fence("t"),
            rows: 24,
            cols: 80,
            cwd: None,
        })
        .is_err()
    );
    assert!(rig.fake.pty_control("sbx-1", "t").is_none());
}

#[test]
fn c52_session_caps_and_open_rate_hold_under_concurrent_opens() {
    // Concurrent admission on one process-wide slot pool: exactly the caps win.
    let slots = Arc::new(TerminalSlots::default());
    let barrier = Arc::new(std::sync::Barrier::new(32));
    let handles: Vec<_> = (0..32)
        .map(|i| {
            let slots = slots.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                slots.try_acquire(&format!("sbx-{}", i % 3), Instant::now())
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let won: Vec<_> = results.iter().filter_map(|r| r.as_ref().ok()).collect();
    // 3 sandboxes x 2 live each = 6 < host cap 8.
    assert_eq!(won.len(), 3 * TERMINAL_MAX_LIVE_SESSIONS_PER_SANDBOX);
    for sandbox in 0..3 {
        assert_eq!(
            won.iter()
                .filter(|g| g.sandbox_id == format!("sandbox:sbx-{sandbox}"))
                .count(),
            TERMINAL_MAX_LIVE_SESSIONS_PER_SANDBOX
        );
    }
    assert!(
        results
            .iter()
            .filter_map(|r| r.as_ref().err())
            .all(|(code, _)| *code == SandboxErrorCode::HostCapacity)
    );
    assert_eq!(slots.live(), 6);
    for guard in results.into_iter().flatten() {
        guard.release();
    }
    assert_eq!(slots.live(), 0);

    // Host cap across many sandboxes, concurrently.
    let slots = Arc::new(TerminalSlots::default());
    let barrier = Arc::new(std::sync::Barrier::new(24));
    let won = (0..24)
        .map(|i| {
            let slots = slots.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                slots.try_acquire(&format!("sbx-{i}"), Instant::now()).ok()
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .filter_map(|h| h.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        won.len(),
        sandbox_protocol::TERMINAL_MAX_GUEST_SESSIONS_PER_HOST
    );
    for guard in won {
        guard.release();
    }

    // Open rate: the 31st open inside one minute is refused even when every
    // earlier session already closed.
    let slots = Arc::new(TerminalSlots::default());
    let now = Instant::now();
    for _ in 0..sandbox_protocol::TERMINAL_OPENS_PER_MINUTE_PER_GUEST_CREATOR {
        slots.try_acquire("sbx-r", now).unwrap().release();
    }
    assert_eq!(
        slots.try_acquire("sbx-r", now).unwrap_err().0,
        SandboxErrorCode::RateLimited
    );
    assert!(slots.try_acquire("sbx-r", now + OPEN_RATE_WINDOW).is_ok());

    // End to end: a third live PTY for one sandbox is refused, no PTY.
    let mut rig = rig();
    opened(&mut rig, "t-a");
    opened(&mut rig, "t-b");
    let out = open(&mut rig, &fence("t-c"));
    assert!(matches!(
        exit(&out),
        Some(DaemonControlMessage::TerminalExit {
            error: Some(ProtocolErrorDetail {
                reason: None,
                code: sandbox_protocol::WireErrorCode::Known(SandboxErrorCode::HostCapacity),
                ..
            }),
            ..
        })
    ));
    assert!(rig.fake.pty_control("sbx-1", "t-c").is_none());
}

#[test]
fn c52_close_supersession_and_connection_end_close_every_pty() {
    let mut rig = rig();
    // Explicit close: the final exit echoes the request id and the intent.
    let (fence, control) = opened(&mut rig, "t-close");
    rig.host
        .handle_control(ServerControlMessage::TerminalClose {
            request_id: "close-1".into(),
            fence: fence.clone(),
            intent: TerminalCloseIntent::Backpressure,
        })
        .unwrap();
    let out = drive(&mut rig, |o| exit(o).is_some());
    assert!(matches!(
        exit(&out),
        Some(DaemonControlMessage::TerminalExit {
            request_id: Some(ref id),
            intent: Some(TerminalCloseIntent::Backpressure),
            reaped: true,
            ..
        }) if id == "close-1"
    ));
    assert!(control.terminated() && control.reaped() && control.released());

    // Supersession by an admitted stop.
    let (_, control) = opened(&mut rig, "t-stop");
    let stop: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner",
        "operationId": "stop-1", "sandboxId": "sbx-1", "kind": "sandbox.stop", "allocation": crate::sandbox_relay::test_support::allocation(),
        "generation": 1, "attempt": 1, "idempotencyKey": "stop-1"
    }))
    .unwrap();
    rig.host.on_dispatch(&stop);
    let out = drive(&mut rig, |o| exit(o).is_some());
    assert!(matches!(
        exit(&out),
        Some(DaemonControlMessage::TerminalExit {
            intent: Some(TerminalCloseIntent::Superseded),
            ..
        })
    ));
    assert!(control.reaped());

    // Connection end (any relay exit): dropping the host stops every pump.
    let (_, control) = opened(&mut rig, "t-drop");
    let Rig { host, slots, .. } = rig;
    drop(host);
    assert!(slots.wait_idle(Duration::from_secs(10)));
    assert!(control.terminated() && control.reaped() && control.released());
}

#[test]
fn c52_lease_expiry_closes_the_terminal() {
    let mut rig = rig();
    let (_, control) = opened(&mut rig, "t-exp");
    let row = rig.journal.lease("sbx-1").unwrap();
    assert!(
        rig.journal
            .expire_lease_now_for_test("sbx-1", row.generation, row.lease.revision)
    );
    let out = drive(&mut rig, |o| exit(o).is_some());
    assert!(matches!(
        exit(&out),
        Some(DaemonControlMessage::TerminalExit {
            intent: Some(TerminalCloseIntent::Expired),
            ..
        })
    ));
    assert!(control.reaped());
}

#[test]
fn c52_uncertain_reap_keeps_the_slot_charged() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "t-d");
    control.make_unreapable();
    rig.host
        .handle_control(ServerControlMessage::TerminalClose {
            request_id: "close-d".into(),
            fence,
            intent: TerminalCloseIntent::Client,
        })
        .unwrap();
    let out = drive(&mut rig, |o| exit(o).is_some());
    assert!(matches!(
        exit(&out),
        Some(DaemonControlMessage::TerminalExit { reaped: false, .. })
    ));
    assert_eq!(rig.slots.live(), 1, "uncertain reap retains capacity");
}

#[test]
fn c52_runtime_open_failure_is_reported_and_unknown_outcome_is_not_issued() {
    assert_eq!(
        open_error_code(SandboxErrorCode::UnknownOutcome),
        SandboxErrorCode::HostEffectNotIssued
    );
    assert_eq!(
        open_error_code(SandboxErrorCode::SandboxNotRunning),
        SandboxErrorCode::SandboxNotRunning
    );
    let mut rig = rig();
    // The runtime refuses (VM gone) although the journal lease is current.
    rig.fake
        .kill_fixture(&sandbox_runtime::KillSandboxRequest {
            template_fingerprint: FP.into(),
            sandbox_id: "sbx-1".into(),
            instance_name: "wssp-sbx-sbx-1".into(),
            operation_id: "kill".into(),
            idempotency_key: "kill".into(),
        })
        .unwrap();
    let out = {
        open(&mut rig, &fence("t-x"));
        drive(&mut rig, |o| exit(o).is_some())
    };
    match exit(&out).unwrap() {
        DaemonControlMessage::TerminalExit {
            request_id,
            error: Some(error),
            reaped: true,
            ..
        } => {
            assert_eq!(request_id.as_deref(), Some("open-t-x"));
            assert_ne!(error.code, SandboxErrorCode::UnknownOutcome);
        }
        other => panic!("{other:?}"),
    }
    assert!(!ready(&out));
    assert!(rig.slots.wait_idle(Duration::from_secs(5)));
}

/// What [`FaultyOpen::open_pty`] does instead of opening a PTY.
#[derive(Clone, Copy)]
enum OpenFault {
    Error(SandboxErrorCode),
    Panic,
    Pending,
    Cleanup,
}

/// The FakeRuntime with a fault injected at the `open_pty` boundary.
struct FaultyOpen {
    fake: FakeRuntime,
    fault: OpenFault,
    pending_entered: Option<std::sync::mpsc::SyncSender<()>>,
}

macro_rules! delegate {
    (create_sandbox, $request:ty, $response:ty) => {
        fn create_sandbox_on_storage(
            &self,
            request: &$request,
            root: &sandbox_runtime::RootDisk,
        ) -> $response {
            self.fake.create_sandbox_on_storage(request, root)
        }
        fn default_storage_pool(&self) -> Result<String, sandbox_runtime::RuntimeError> {
            self.fake.default_storage_pool()
        }
        fn initialize_storage_pool(
            &self,
            n: &str,
            p: Option<&sandbox_runtime::StoragePoolIdentity>,
        ) -> Result<sandbox_runtime::StoragePoolIdentity, sandbox_runtime::RuntimeError> {
            self.fake.initialize_storage_pool(n, p)
        }
        fn observe_storage_pool(
            &self,
            p: &sandbox_runtime::StoragePoolIdentity,
        ) -> Result<sandbox_runtime::StoragePoolObservation, sandbox_runtime::RuntimeError> {
            self.fake.observe_storage_pool(p)
        }
        fn storage_root_census(
            &self,
            p: &sandbox_runtime::StoragePoolIdentity,
        ) -> Result<sandbox_runtime::StorageRootCensus, sandbox_runtime::RuntimeError> {
            self.fake.storage_root_census(p)
        }
        fn storage_physical_usage(
            &self,
            p: &sandbox_runtime::StoragePoolIdentity,
            roots: &[String],
            c: u64,
        ) -> Result<sandbox_runtime::PhysicalUsage, sandbox_runtime::RuntimeError> {
            self.fake.storage_physical_usage(p, roots, c)
        }
        fn prove_root_absent(
            &self,
            p: &sandbox_runtime::RootDisk,
            n: &str,
        ) -> Result<sandbox_runtime::RootAbsenceProof, sandbox_runtime::RuntimeError> {
            self.fake.prove_root_absent(p, n)
        }
    };
    (reconnect_sandbox, $request:ty, $response:ty) => {
        fn reconnect_sandbox_on_storage(
            &self,
            request: &$request,
            root: &sandbox_runtime::RootDisk,
        ) -> $response {
            self.fake.reconnect_sandbox_on_storage(request, root)
        }
    };
    (kill_sandbox, $request:ty, $response:ty) => {
        fn kill_sandbox_on_storage(
            &self,
            request: &$request,
            root: &sandbox_runtime::RootDisk,
        ) -> $response {
            self.fake.kill_sandbox_on_storage(request, root)
        }
    };
    ($method:ident, $request:ty, $response:ty) => {
        fn $method(&self, request: &$request) -> $response {
            self.fake.$method(request)
        }
    };
}

impl SandboxRuntime for FaultyOpen {
    fn with_cancellation(
        &self,
        permit: Arc<sandbox_runtime::RuntimePermit>,
    ) -> Box<dyn SandboxRuntime> {
        self.fake.with_cancellation(permit)
    }
    fn query_sandbox(
        &self,
        sandbox_id: &str,
        instance_name: Option<&str>,
        template_fingerprint: Option<&str>,
    ) -> std::result::Result<
        Option<sandbox_protocol::SandboxLifecycleState>,
        sandbox_runtime::RuntimeError,
    > {
        self.fake
            .query_sandbox(sandbox_id, instance_name, template_fingerprint)
    }
    fn pty_capability(&self) -> bool {
        true
    }
    fn open_pty(
        &self,
        _request: &OpenPtyRequest,
    ) -> std::result::Result<sandbox_runtime::PtySession, sandbox_runtime::PtyOpenFailure> {
        match self.fault {
            OpenFault::Error(code) => {
                Err(sandbox_runtime::RuntimeError::new(code, "injected open failure").into())
            }
            OpenFault::Panic => panic!("injected open_pty panic"),
            OpenFault::Pending if _request.session_id == "first" => {
                self.pending_entered.as_ref().unwrap().send(()).unwrap();
                while !_request.setup_cancel.load(Ordering::Acquire) {
                    std::thread::park_timeout(Duration::from_millis(2));
                }
                Err(sandbox_runtime::RuntimeError::new(
                    SandboxErrorCode::Cancelled,
                    "synthetic-private-open-error",
                )
                .into())
            }
            OpenFault::Pending => self.fake.open_pty(_request),
            OpenFault::Cleanup => {
                let mut session = self.fake.open_pty(_request)?;
                self.fake
                    .pty_control(&_request.sandbox_id, &_request.session_id)
                    .unwrap()
                    .make_unreapable();
                session.close(PtyCloseIntent::Client);
                Err(sandbox_runtime::PtyOpenFailure {
                    error: sandbox_runtime::RuntimeError::new(
                        SandboxErrorCode::UnknownOutcome,
                        "synthetic-private-open-error",
                    ),
                    cleanup: Some(session),
                })
            }
        }
    }
    fn close_pty_sessions(&self, sandbox_id: Option<&str>, intent: PtyCloseIntent) -> usize {
        self.fake.close_pty_sessions(sandbox_id, intent)
    }
    delegate!(
        create_sandbox,
        sandbox_runtime::CreateSandboxRequest,
        sandbox_runtime::EffectOutcome<sandbox_runtime::CreateSandboxResponse>
    );
    delegate!(
        kill_sandbox,
        sandbox_runtime::KillSandboxRequest,
        sandbox_runtime::EffectOutcome<sandbox_runtime::KillSandboxResponse>
    );
    delegate!(
        run_command,
        sandbox_runtime::RunCommandRequest,
        sandbox_runtime::EffectOutcome<sandbox_runtime::RunCommandResponse>
    );
    delegate!(
        read_file,
        sandbox_runtime::ReadFileRequest,
        std::result::Result<sandbox_runtime::ReadFileResponse, sandbox_runtime::RuntimeError>
    );
    delegate!(
        write_file,
        sandbox_runtime::WriteFileRequest,
        sandbox_runtime::EffectOutcome<sandbox_runtime::WriteFileResponse>
    );
    delegate!(
        probe_sandbox,
        sandbox_runtime::ProbeSandboxRequest,
        std::result::Result<sandbox_runtime::ProbeSandboxResponse, sandbox_runtime::RuntimeError>
    );
    delegate!(
        reconnect_sandbox,
        sandbox_runtime::ReconnectSandboxRequest,
        sandbox_runtime::EffectOutcome<sandbox_runtime::ReconnectSandboxResponse>
    );
    delegate!(
        stop_sandbox,
        sandbox_runtime::StopSandboxRequest,
        sandbox_runtime::EffectOutcome<sandbox_runtime::StopSandboxResponse>
    );
    delegate!(
        list_dir,
        sandbox_runtime::ListDirRequest,
        std::result::Result<sandbox_runtime::ListDirResponse, sandbox_runtime::RuntimeError>
    );
    delegate!(
        stat_path,
        sandbox_runtime::StatPathRequest,
        std::result::Result<sandbox_runtime::EntryInfo, sandbox_runtime::RuntimeError>
    );
    delegate!(
        mkdir,
        sandbox_runtime::MkdirRequest,
        sandbox_runtime::EffectOutcome<sandbox_runtime::MkdirResponse>
    );
    delegate!(
        remove_path,
        sandbox_runtime::RemovePathRequest,
        sandbox_runtime::EffectOutcome<sandbox_runtime::RemovePathResponse>
    );
    delegate!(
        move_path,
        sandbox_runtime::MovePathRequest,
        sandbox_runtime::EffectOutcome<sandbox_runtime::EntryInfo>
    );
    fn cancel_operation(&self, operation_id: &str) -> sandbox_runtime::EffectOutcome<()> {
        self.fake.cancel_operation(operation_id)
    }
    delegate!(
        list_processes,
        sandbox_runtime::ListProcessesRequest,
        std::result::Result<sandbox_runtime::ListProcessesResponse, sandbox_runtime::RuntimeError>
    );
    delegate!(
        signal_process,
        sandbox_runtime::SignalProcessRequest,
        sandbox_runtime::EffectOutcome<sandbox_runtime::SignalOutcome>
    );
    delegate!(
        write_stdin,
        sandbox_runtime::WriteStdinRequest,
        sandbox_runtime::EffectOutcome<()>
    );
    delegate!(
        create_snapshot,
        sandbox_runtime::SnapshotRequest,
        sandbox_runtime::EffectOutcome<sandbox_runtime::SnapshotResponse>
    );
    delegate!(
        restore_snapshot,
        sandbox_runtime::SnapshotRequest,
        sandbox_runtime::EffectOutcome<sandbox_runtime::SnapshotResponse>
    );
    delegate!(
        fork_sandbox,
        sandbox_runtime::ForkSandboxRequest,
        sandbox_runtime::EffectOutcome<sandbox_runtime::ForkSandboxResponse>
    );
}

fn faulty(fault: OpenFault) -> Rig {
    rig_with(|fake| {
        Arc::new(FaultyOpen {
            fake,
            fault,
            pending_entered: None,
        })
    })
}

/// C52-CO-4(a): the runtime itself answers UNKNOWN_OUTCOME; the wire says
/// not-issued (retryable), and the slot is free again.
#[test]
fn c52_unknown_outcome_from_open_pty_is_reported_not_issued_on_the_wire() {
    let mut rig = faulty(OpenFault::Error(SandboxErrorCode::UnknownOutcome));
    open(&mut rig, &fence("t-u"));
    let out = drive(&mut rig, |o| exit(o).is_some());
    match exit(&out).unwrap() {
        DaemonControlMessage::TerminalExit {
            request_id,
            error: Some(error),
            reaped: true,
            ..
        } => {
            assert_eq!(request_id.as_deref(), Some("open-t-u"));
            assert_eq!(error.code, SandboxErrorCode::HostEffectNotIssued);
        }
        other => panic!("{other:?}"),
    }
    assert!(!ready(&out));
    assert_eq!(rig.slots.live(), 0);
}

/// C52-CO-4(b): every identity leg, sent ALONE as the first violation on a
/// live session (no stop requested), writes zero bytes and acks nothing.
#[test]
fn c52_each_identity_leg_alone_writes_zero_bytes_to_a_live_session() {
    let mut rig = rig();
    type Forge = fn(&TerminalFence) -> TerminalFence;
    let legs: [(&str, Forge); 5] = [
        ("generation", |f| TerminalFence {
            target: sandbox_protocol::TerminalTargetV11::Sandbox {
                sandbox_id: "sbx-1".into(),
                generation: 2,
            },
            ..f.clone()
        }),
        ("epoch", |f| TerminalFence {
            epoch: 6,
            ..f.clone()
        }),
        ("host", |f| TerminalFence {
            host_id: "host-2".into(),
            ..f.clone()
        }),
        ("operation", |f| TerminalFence {
            operation_id: "top-forged".into(),
            ..f.clone()
        }),
        ("sandbox", |f| TerminalFence {
            target: sandbox_protocol::TerminalTargetV11::Sandbox {
                sandbox_id: "sbx-2".into(),
                generation: 1,
            },
            ..f.clone()
        }),
    ];
    for (name, forge) in legs {
        let session = format!("t-leg-{name}");
        let (fence, control) = opened(&mut rig, &session);
        control.set_echo(false);
        input(&mut rig, &forge(&fence), 0, b"FORGED");
        let out = settle(&mut rig, Duration::from_millis(100));
        assert!(
            acks(&out).is_empty() && exit(&out).is_none(),
            "{name}: {out:?}"
        );
        assert!(
            control.input().is_empty(),
            "{name}: forged bytes reached the PTY"
        );
        // The session is live (not stopping): the genuine sequence 0 lands.
        input(&mut rig, &fence, 0, b"ok");
        drive(&mut rig, |o| acks(o) == [0]);
        assert_eq!(control.input(), b"ok", "{name}");
        rig.host
            .handle_control(ServerControlMessage::TerminalClose {
                request_id: format!("close-{name}"),
                fence,
                intent: TerminalCloseIntent::Client,
            })
            .unwrap();
        drive(&mut rig, |o| exit(o).is_some());
    }
}

/// C52-CC-3: a pump that unwinds after its PTY opened still closes the PTY,
/// releases its slot after the confirmed reap and sends the final exit.
#[test]
fn c52_pump_panic_closes_the_pty_releases_the_slot_and_sends_exit() {
    let mut rig = rig();
    pump_faults::panic_after_open("t-panic");
    open(&mut rig, &fence("t-panic"));
    let out = drive(&mut rig, |o| exit(o).is_some());
    match exit(&out).unwrap() {
        DaemonControlMessage::TerminalExit {
            error: Some(error),
            reaped,
            ..
        } => {
            assert_eq!(error.code, SandboxErrorCode::Internal);
            assert!(reaped);
        }
        other => panic!("{other:?}"),
    }
    let control = rig
        .fake
        .pty_control("sbx-1", "t-panic")
        .expect("pty opened");
    assert!(control.reaped() && control.released());
    assert!(rig.slots.wait_idle(Duration::from_secs(5)));
    assert_eq!(rig.host.live_sessions(), 0);
    // The sandbox can open again.
    opened(&mut rig, "t-after");
}

/// C52-CC-3: unwinding inside `open_pty` cannot prove no child started: the
/// exit is still sent, with `reaped: false`, and the slot stays charged.
#[test]
fn c52_open_pty_panic_sends_exit_and_keeps_the_uncertain_slot() {
    let mut rig = faulty(OpenFault::Panic);
    open(&mut rig, &fence("t-open-panic"));
    let out = drive(&mut rig, |o| exit(o).is_some());
    assert!(matches!(
        exit(&out),
        Some(DaemonControlMessage::TerminalExit {
            reaped: false,
            error: Some(ProtocolErrorDetail {
                reason: None,
                code: sandbox_protocol::WireErrorCode::Known(SandboxErrorCode::Internal),
                ..
            }),
            ..
        })
    ));
    assert_eq!(rig.slots.live(), 1);
}

/// C55 (C52-F-4 / C52-CC-1): an uncertain reap keeps its slot charged through
/// every sweep until the runtime CONFIRMS the reap; only then is the slot
/// released and the server told with a second, final `terminal.exit
/// { reaped: true }` for the same fence. Shutdown does not wait on it.
#[test]
fn c55_uncertain_reap_is_released_only_by_the_reconciliation_sweep() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "t-u");
    control.make_unreapable();
    rig.host
        .handle_control(ServerControlMessage::TerminalClose {
            request_id: "close-u".into(),
            fence: fence.clone(),
            intent: TerminalCloseIntent::Client,
        })
        .unwrap();
    let out = drive(&mut rig, |o| exit(o).is_some());
    assert!(matches!(
        exit(&out),
        Some(DaemonControlMessage::TerminalExit { reaped: false, .. })
    ));
    // Several sweep intervals: still charged, still unconfirmed, no report.
    let later = settle(&mut rig, REAP_SWEEP_INTERVAL * 6);
    assert!(
        exit(&later).is_none(),
        "no optimistic confirmation: {later:?}"
    );
    assert_eq!((rig.slots.live(), rig.slots.uncertain()), (1, 1));
    assert_eq!(rig.host.unreaped_sessions(), 1);
    // Shutdown's wait does not block on a reap only the sweep can settle.
    let started = Instant::now();
    assert!(rig.slots.wait_idle(Duration::from_secs(5)));
    assert!(started.elapsed() < Duration::from_secs(1));
    // The stuck child finally dies: the sweep confirms and releases once.
    control.complete_stuck_reap();
    let confirmed = drive(&mut rig, |o| exit(o).is_some());
    let Some(DaemonControlMessage::TerminalExit {
        fence: confirmed_fence,
        reaped: true,
        intent: None,
        error: None,
        request_id: None,
        ..
    }) = exit(&confirmed)
    else {
        panic!("expected the reconciliation exit: {confirmed:?}");
    };
    assert_eq!(confirmed_fence, fence);
    assert!(control.reaped());
    assert_eq!((rig.slots.live(), rig.slots.uncertain()), (0, 0));
    assert_eq!(rig.host.unreaped_sessions(), 0);
    // Exactly one confirmation, ever.
    let after = settle(&mut rig, REAP_SWEEP_INTERVAL * 4);
    assert!(exit(&after).is_none(), "{after:?}");
    // The freed slot is usable again.
    opened(&mut rig, "t-u2");
}

/// C55: a confirmation for a connection that already ended still releases
/// the host slot (the server count ended with the socket).
#[test]
fn c55_sweep_releases_the_slot_after_the_connection_ended() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "t-gone");
    control.make_unreapable();
    rig.host
        .handle_control(ServerControlMessage::TerminalClose {
            request_id: "close-gone".into(),
            fence,
            intent: TerminalCloseIntent::Client,
        })
        .unwrap();
    drive(&mut rig, |o| exit(o).is_some());
    let Rig { host, slots, .. } = rig;
    drop(host);
    assert_eq!(slots.live(), 1);
    control.complete_stuck_reap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while slots.live() > 0 {
        assert!(Instant::now() < deadline, "sweep never released the slot");
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(slots.uncertain(), 0);
}

/// C55 (C52-F-2): lease authority is checked per input frame, not only per
/// tick. Input arriving after the lease expired writes ZERO bytes and the
/// session ends `expired`, even before the next tick's check runs.
#[test]
fn c55_input_after_lease_expiry_writes_zero_bytes_before_the_next_tick() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "t-f2");
    control.set_echo(false);
    let row = rig.journal.lease("sbx-1").unwrap();
    assert!(
        rig.journal
            .expire_lease_now_for_test("sbx-1", row.generation, row.lease.revision)
    );
    // No poll() between the expiry and the frame, and none for a while
    // after it: the pump (a 20 ms turn) would have written the frame long
    // before the next tick's check could stop it.
    input(&mut rig, &fence, 0, b"LATE");
    thread::sleep(Duration::from_millis(300));
    let out = drive(&mut rig, |o| exit(o).is_some());
    assert!(matches!(
        exit(&out),
        Some(DaemonControlMessage::TerminalExit {
            intent: Some(TerminalCloseIntent::Expired),
            reaped: true,
            ..
        })
    ));
    assert!(control.input().is_empty(), "{:?}", control.input());
    assert!(acks(&out).is_empty(), "late input was never acknowledged");
}

/// C55 kill scoping: closing one terminal kills only that PTY's child. The
/// VM keeps running and a sibling terminal of the same sandbox keeps working.
#[test]
fn c55_closing_a_terminal_never_touches_the_vm_or_a_sibling_terminal() {
    let mut rig = rig();
    let (closing, closed_control) = opened(&mut rig, "t-a");
    let (sibling, sibling_control) = opened(&mut rig, "t-b");
    rig.host
        .handle_control(ServerControlMessage::TerminalClose {
            request_id: "close-a".into(),
            fence: closing,
            intent: TerminalCloseIntent::Client,
        })
        .unwrap();
    drive(&mut rig, |o| exit(o).is_some());
    assert!(closed_control.terminated() && closed_control.reaped());
    assert!(!sibling_control.terminated(), "sibling PTY untouched");
    assert_eq!(
        rig.fake.query_sandbox("sbx-1", None, None).unwrap(),
        Some(sandbox_protocol::SandboxLifecycleState::Ready),
        "the VM is never stopped by a terminal close"
    );
    input(&mut rig, &sibling, 0, b"still-here");
    drive(&mut rig, |o| acks(o) == vec![0]);
    assert_eq!(sibling_control.input(), b"still-here");
}

/// C55 (C52-TB-3) CLI shutdown ordering: every live PTY of the connection
/// gets exactly one `terminal.exit` with intent `shutdown`, each shell is
/// killed and reaped, every slot is free, and the drain is bounded.
#[test]
fn c55_daemon_shutdown_closes_every_terminal_with_one_shutdown_exit() {
    let mut rig = rig();
    let (first, first_control) = opened(&mut rig, "t-s1");
    let (second, second_control) = opened(&mut rig, "t-s2");
    let mut sent = Vec::new();
    let started = Instant::now();
    rig.host
        .shutdown(Duration::from_secs(5), |frame| {
            sent.push(Out::from(frame));
            Ok(())
        })
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(5), "bounded drain");
    for fence in [&first, &second] {
        let exits: Vec<_> = sent
            .iter()
            .filter_map(|o| match o {
                Out::Text(DaemonControlMessage::TerminalExit {
                    fence: f,
                    intent,
                    reaped,
                    ..
                }) if f == fence => Some((*intent, *reaped)),
                _ => None,
            })
            .collect();
        assert_eq!(
            exits,
            vec![(Some(TerminalCloseIntent::Shutdown), true)],
            "{}",
            fence.session_id
        );
    }
    for control in [&first_control, &second_control] {
        assert!(control.terminated() && control.reaped() && control.released());
    }
    assert_eq!(rig.host.live_sessions(), 0);
    assert_eq!(rig.slots.live(), 0);
    // Idempotent: a second shutdown has nothing left to close or report.
    let mut again = Vec::new();
    rig.host
        .shutdown(Duration::from_millis(100), |frame| {
            again.push(Out::from(frame));
            Ok(())
        })
        .unwrap();
    assert!(exit(&again).is_none(), "{again:?}");
}

/// C55-CO-3 (host twin): the VM is deleted while resizes are in flight. The
/// session ends with exactly one exit, nothing (no resize answer) follows the
/// exit, a resize naming the ended session is inert, and the slot is free.
#[test]
fn c55_vm_deletion_during_resize_ends_once_and_later_resizes_are_inert() {
    let mut rig = rig();
    let (fence, control) = opened(&mut rig, "t-rz");
    let resize = |rig: &mut Rig, id: &str, rows: u16, cols: u16| {
        rig.host
            .handle_control(ServerControlMessage::TerminalResize {
                request_id: id.into(),
                fence: fence.clone(),
                rows,
                cols,
            })
            .unwrap()
    };
    assert!(resize(&mut rig, "rz-1", 30, 100).is_empty());
    rig.fake
        .kill_fixture(&sandbox_runtime::KillSandboxRequest {
            template_fingerprint: FP.into(),
            sandbox_id: "sbx-1".into(),
            instance_name: "wssp-sbx-sbx-1".into(),
            operation_id: "kill".into(),
            idempotency_key: "kill".into(),
        })
        .unwrap();
    assert!(resize(&mut rig, "rz-2", 40, 110).is_empty());
    let out = drive(&mut rig, |o| exit(o).is_some());
    let exits = out
        .iter()
        .filter(|o| matches!(o, Out::Text(DaemonControlMessage::TerminalExit { .. })))
        .count();
    assert_eq!(exits, 1, "{out:?}");
    let exit_at = out
        .iter()
        .position(|o| matches!(o, Out::Text(DaemonControlMessage::TerminalExit { .. })))
        .unwrap();
    assert_eq!(exit_at, out.len() - 1, "nothing after the exit: {out:?}");
    assert!(control.terminated() && control.reaped());
    // The session is gone: a later resize is inert (no violation, no frame).
    assert!(resize(&mut rig, "rz-3", 50, 120).is_empty());
    let later = settle(&mut rig, Duration::from_millis(200));
    assert!(later.is_empty(), "{later:?}");
    assert!(
        !control.sizes().iter().any(|s| s.rows() == 50),
        "{:?}",
        control.sizes()
    );
    assert!(rig.slots.wait_idle(Duration::from_secs(5)));
    assert_eq!(rig.host.live_sessions(), 0);
}

#[test]
fn pty_env_handshake_takeover_cancels_opening_session() {
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let mut rig = rig_with(|fake| {
        Arc::new(FaultyOpen {
            fake,
            fault: OpenFault::Pending,
            pending_entered: Some(tx),
        })
    });
    let first = fence("first");
    assert!(open(&mut rig, &first).is_empty());
    rx.recv_timeout(Duration::from_secs(3)).unwrap();
    input(&mut rig, &first, 0, b"forged-before-DONE");
    rig.host
        .handle_control(ServerControlMessage::TerminalResize {
            request_id: "early-resize".into(),
            fence: first.clone(),
            rows: 50,
            cols: 120,
        })
        .unwrap();
    // Takeover is an explicit close of the opening attachment, then a distinct
    // fenced open. The server suppresses stale old attachment events as well.
    rig.host
        .handle_control(ServerControlMessage::TerminalClose {
            request_id: "replace".into(),
            fence: first.clone(),
            intent: TerminalCloseIntent::Replaced,
        })
        .unwrap();
    let old = drive(&mut rig, |out| exit(out).is_some());
    assert!(!ready(&old));
    assert!(matches!(
        exit(&old),
        Some(DaemonControlMessage::TerminalExit {
            fence,
            reaped: true,
            ..
        }) if fence == first
    ));
    assert!(!format!("{old:?}").contains("synthetic-private-open-error"));
    assert_eq!(rig.slots.live(), 0);
    let (replacement, control) = opened(&mut rig, "replacement");
    assert!(control.input().is_empty());
    input(&mut rig, &replacement, 0, b"new");
    // An input ack only proves admission to PtySession's writer queue. Use
    // the echoed output channel as the delivery gate: FakeWriter records the
    // input before echoing it, and the reader/pump forward that echo here.
    drive(&mut rig, |out| {
        acks(out) == [0]
            && output(out)
                .into_iter()
                .flat_map(|(_, bytes)| bytes)
                .eq(b"new".iter().copied())
    });
    assert_eq!(control.input(), b"new");
}

#[test]
fn pty_env_open_failure_retains_uncertain_cleanup_and_charge_until_proof() {
    let mut rig = faulty(OpenFault::Cleanup);
    open(&mut rig, &fence("uncertain-open"));
    let out = drive(&mut rig, |out| exit(out).is_some());
    assert!(!ready(&out));
    assert!(matches!(
        exit(&out),
        Some(DaemonControlMessage::TerminalExit {
            reaped: false,
            error: Some(ProtocolErrorDetail {
                reason: None,
                code: sandbox_protocol::WireErrorCode::Known(SandboxErrorCode::UnknownOutcome),
                ..
            }),
            ..
        })
    ));
    assert!(!format!("{out:?}").contains("synthetic-private-open-error"));
    assert_eq!(rig.slots.live(), 1);
    assert_eq!(rig.slots.uncertain(), 1);
    rig.fake
        .pty_control("sbx-1", "uncertain-open")
        .unwrap()
        .complete_stuck_reap();
    let reaped = drive(&mut rig, |out| {
        out.iter().any(|out| {
            matches!(
                out,
                Out::Text(DaemonControlMessage::TerminalExit { reaped: true, .. })
            )
        })
    });
    assert!(reaped.iter().any(|out| matches!(
        out,
        Out::Text(DaemonControlMessage::TerminalExit { reaped: true, .. })
    )));
    assert_eq!(rig.slots.live(), 0);
}

#[test]
fn pty_env_opening_input_and_resize_are_refused_then_post_open_resize_works() {
    let mut rig = rig();
    let fence = fence("gated-open");
    let (entered, release) = pump_faults::pause_after_open(&fence.session_id);
    open(&mut rig, &fence);
    entered.recv_timeout(Duration::from_secs(3)).unwrap();
    let control = rig.fake.pty_control("sbx-1", &fence.session_id).unwrap();
    input(&mut rig, &fence, 0, b"early-input");
    rig.host
        .handle_control(ServerControlMessage::TerminalResize {
            request_id: "early".into(),
            fence: fence.clone(),
            rows: 40,
            cols: 100,
        })
        .unwrap();
    release.send(()).unwrap();
    drive(&mut rig, ready);
    input(&mut rig, &fence, 0, b"after");
    drive(&mut rig, |out| acks(out) == [0]);
    assert_eq!(control.input(), b"after");
    assert_eq!(control.sizes(), [PtySize::new(24, 80).unwrap()]);
    rig.host
        .handle_control(ServerControlMessage::TerminalResize {
            request_id: "after".into(),
            fence: fence.clone(),
            rows: 40,
            cols: 100,
        })
        .unwrap();
    drive(&mut rig, |out| {
        out.iter().any(|event| matches!(event, Out::Text(DaemonControlMessage::TerminalReady { request_id, .. }) if request_id == "after"))
    });
    assert_eq!(
        control.sizes().last(),
        Some(&PtySize::new(40, 100).unwrap())
    );
}

struct InjectedHostOpener(FakeRuntime);
impl sandbox_runtime::HostPtyOpener for InjectedHostOpener {
    fn open(
        &self,
        session_id: &str,
        size: PtySize,
        cancel: Arc<AtomicBool>,
    ) -> Result<PtySession, sandbox_runtime::PtyOpenFailure> {
        self.0.open_pty(&OpenPtyRequest {
            template_fingerprint: FP.into(),
            sandbox_id: "sbx-1".into(),
            session_id: session_id.into(),
            guest: sandbox_runtime::GuestIdentity {
                guest_uid: 1234,
                guest_gid: 2345,
                guest_home: "/home/declared".into(),
                guest_shell: "/bin/zsh".into(),
            },
            size,
            max_duration: None,
            env: Vec::new(),
            cwd: None,
            setup_cancel: cancel,
        })
    }
}
fn host_fence(id: &str) -> TerminalFence {
    TerminalFence {
        target: TerminalTargetV11::Host {},
        ..fence(id)
    }
}
fn open_host(rig: &mut Rig, fence: &TerminalFence, revision: u64, required: bool) -> Vec<Out> {
    outs(
        rig.host
            .handle_control(ServerControlMessage::TerminalOpen {
                request_id: format!("open-{}", fence.session_id),
                fence: fence.clone(),
                rows: 24,
                cols: 80,
                cwd: None,
                host_policy: Some(HostTerminalOpenPolicyV11 {
                    policy_revision: revision,
                    proof_required: required,
                }),
            })
            .unwrap(),
    )
}
#[test]
fn t1_host_hot_off_under_flood_rejects_stale_opens_and_preserves_guest() {
    let mut rig = rig();
    let opener: Arc<dyn sandbox_runtime::HostPtyOpener> =
        Arc::new(InjectedHostOpener(rig.fake.clone()));
    let mut policy = super::super::host_policy::Policy {
        enabled: true,
        required: false,
        revision: 1,
    };
    rig.host.configure_host(policy, Some(opener.clone()));
    let (guest, guest_control) = opened(&mut rig, "guest-survives");
    let host = host_fence("host-live");
    assert!(open_host(&mut rig, &host, 1, false).is_empty());
    drive(&mut rig, |out| {
        out.iter().any(|o| matches!(o, Out::Text(DaemonControlMessage::TerminalReady { fence, .. }) if fence == &host))
    });
    let control = rig.fake.pty_control("sbx-1", "host-live").unwrap();
    input(&mut rig, &host, 0, b"before");
    drive(&mut rig, |o| !acks(o).is_empty());
    policy.enabled = false;
    policy.revision += 1;
    rig.host.configure_host(policy, Some(opener.clone()));
    for seq in 1..1000 {
        input(&mut rig, &host, seq, b"after");
    }
    drive(&mut rig, |o| exit(o).is_some());
    assert_eq!(control.input(), b"before");
    let refused = open_host(&mut rig, &host_fence("stale"), 1, false);
    assert!(exit(&refused).is_some());
    assert!(rig.fake.pty_control("sbx-1", "stale").is_none());
    input(&mut rig, &guest, 0, b"guest-ok");
    drive(&mut rig, |o| !acks(o).is_empty());
    assert_eq!(guest_control.input(), b"guest-ok");
    // No restart: a new required revision refuses an old optional grant.
    policy.enabled = true;
    policy.required = true;
    policy.revision += 1;
    rig.host.configure_host(policy, Some(opener));
    assert!(exit(&open_host(&mut rig, &host_fence("optional"), 1, false)).is_some());
    assert!(open_host(&mut rig, &host_fence("required"), 3, true).is_empty());
}
#[test]
fn t1_host_idle_output_resize_does_not_reset_and_lifetime_is_monotonic() {
    let mut rig = rig();
    let opener: Arc<dyn sandbox_runtime::HostPtyOpener> =
        Arc::new(InjectedHostOpener(rig.fake.clone()));
    rig.host.configure_host(
        super::super::host_policy::Policy {
            enabled: true,
            required: true,
            revision: 4,
        },
        Some(opener),
    );
    let host = host_fence("idle");
    open_host(&mut rig, &host, 4, true);
    drive(&mut rig, |o| {
        o.iter()
            .any(|o| matches!(o, Out::Text(DaemonControlMessage::TerminalReady { .. })))
    });
    let control = rig.fake.pty_control("sbx-1", "idle").unwrap();
    control.emit(b"output-only");
    rig.host.sessions.get_mut("idle").unwrap().last_input =
        Instant::now() - Duration::from_millis(sandbox_protocol::TERMINAL_HOST_INPUT_IDLE_MS);
    input(&mut rig, &host, 0, b"too-late");
    let out = drive(&mut rig, |o| exit(o).is_some());
    assert!(matches!(
        exit(&out),
        Some(DaemonControlMessage::TerminalExit {
            intent: Some(TerminalCloseIntent::Expired),
            ..
        })
    ));
    assert!(control.input().is_empty());
    let host = host_fence("lifetime");
    open_host(&mut rig, &host, 4, true);
    drive(&mut rig, |o| {
        o.iter()
            .any(|o| matches!(o, Out::Text(DaemonControlMessage::TerminalReady { .. })))
    });
    let live = rig.host.sessions.get_mut("lifetime").unwrap();
    live.opened_at =
        Instant::now() - Duration::from_millis(sandbox_protocol::TERMINAL_HOST_MAX_LIFETIME_MS);
    live.last_input = Instant::now();
    let out = drive(&mut rig, |o| exit(o).is_some());
    assert!(matches!(
        exit(&out),
        Some(DaemonControlMessage::TerminalExit {
            intent: Some(TerminalCloseIntent::Expired),
            ..
        })
    ));
}
#[test]
fn t1_creator_caps_host_reservations_and_uncertain_reap_remain_charged() {
    let slots = Arc::new(TerminalSlots::default());
    let now = Instant::now();
    let target = |id: &str| TerminalTargetV11::Sandbox {
        sandbox_id: id.into(),
        generation: 1,
    };
    let mut guests = Vec::new();
    for creator in ["creator-a", "creator-b"] {
        for n in 0..3 {
            guests.push(
                slots
                    .try_acquire_target(&target(&format!("{creator}-{n}")), Some(creator), now)
                    .unwrap(),
            );
        }
        assert!(
            slots
                .try_acquire_target(&target("extra"), Some(creator), now)
                .is_err()
        );
    }
    let host = slots
        .try_acquire_target(&TerminalTargetV11::Host {}, None, now)
        .unwrap();
    let replacement = slots
        .try_acquire_target(&TerminalTargetV11::Host {}, None, now)
        .unwrap();
    assert_eq!(slots.live(), 8);
    assert!(
        slots
            .try_acquire_target(&TerminalTargetV11::Host {}, None, now)
            .is_err()
    );
    let uncertain = guests.pop().unwrap().into_uncertain();
    assert_eq!(slots.live(), 8);
    assert!(
        slots
            .try_acquire_target(&target("late"), Some("creator-b"), now)
            .is_err()
    );
    uncertain.release();
    host.release();
    replacement.release();
    for g in guests {
        g.release();
    }
    let slots = Arc::new(TerminalSlots::default());
    for creator in ["a", "b"] {
        for _ in 0..14 {
            slots
                .try_acquire_target(&target("g"), Some(creator), now)
                .unwrap()
                .release();
        }
    }
    assert!(
        slots
            .try_acquire_target(&target("g"), Some("c"), now)
            .is_err()
    );
    for _ in 0..2 {
        slots
            .try_acquire_target(&TerminalTargetV11::Host {}, None, now)
            .unwrap()
            .release();
    }
    assert!(
        slots
            .try_acquire_target(&TerminalTargetV11::Host {}, None, now)
            .is_err()
    );
}

struct PendingHostOpener {
    fake: FakeRuntime,
    entered: mpsc::SyncSender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}
impl sandbox_runtime::HostPtyOpener for PendingHostOpener {
    fn open(
        &self,
        id: &str,
        size: PtySize,
        cancel: Arc<AtomicBool>,
    ) -> Result<PtySession, sandbox_runtime::PtyOpenFailure> {
        self.entered.send(()).unwrap();
        self.release.lock().unwrap().recv().unwrap();
        InjectedHostOpener(self.fake.clone()).open(id, size, cancel)
    }
}
#[test]
fn t1_policy_change_cancels_pending_host_open_before_ready_or_input() {
    let mut rig = rig();
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let opener: Arc<dyn sandbox_runtime::HostPtyOpener> = Arc::new(PendingHostOpener {
        fake: rig.fake.clone(),
        entered: entered_tx,
        release: Mutex::new(release_rx),
    });
    let policy = super::super::host_policy::Policy {
        enabled: true,
        required: false,
        revision: 1,
    };
    rig.host.configure_host(policy, Some(opener.clone()));
    let f = host_fence("pending-host");
    assert!(open_host(&mut rig, &f, 1, false).is_empty());
    entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    rig.host.configure_host(
        super::super::host_policy::Policy {
            required: true,
            revision: 2,
            ..policy
        },
        Some(opener),
    );
    input(&mut rig, &f, 0, b"refused");
    release_tx.send(()).unwrap();
    let out = drive(&mut rig, |o| exit(o).is_some());
    assert!(!out.iter().any(|o| matches!(
        o,
        Out::Text(DaemonControlMessage::TerminalReady { .. }) | Out::Binary(_)
    )));
    assert!(rig.fake.pty_control("sbx-1", "pending-host").is_none());
    assert!(rig.slots.wait_idle(Duration::from_secs(2)));
}

/// D1: a build VM (which may run guest root) never opens a terminal, even
/// with a complete recorded guest identity.
#[test]
fn build_sandboxes_never_open_a_terminal() {
    let mut rig = rig();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let d: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner",
        "operationId": "create-sbx-b", "sandboxId": "sbx-b", "kind": "sandbox.create",
        "allocation": crate::sandbox_relay::test_support::allocation(),
        "generation": 1, "attempt": 1, "idempotencyKey": "create-sbx-b",
        "bodyHash": "a".repeat(64), "incusFingerprint": FP, "templateDigest": FP,
        "lease": {"revision": 1, "deadlineUnixMs": now + 3_600_000,
                  "action": "stop", "expiryPolicy": "retry-force-60s"},
        "guestUid": 1234, "guestGid": 2345, "guestHome": "/home/declared",
        "guestShell": "/bin/zsh", "build": {"buildId": "build-1"},
    }))
    .unwrap();
    rig.journal
        .record_fixture_intent(&intent_from_dispatch(&rig.journal, &binding(), &d))
        .unwrap();
    rig.journal.accept_fixture_lease(&d).unwrap();
    rig.fake
        .create_fixture(&CreateSandboxRequest::for_test("sbx-b", "create-sbx-b"))
        .unwrap();
    let fence = TerminalFence {
        target: sandbox_protocol::TerminalTargetV11::Sandbox {
            sandbox_id: "sbx-b".into(),
            generation: 1,
        },
        ..fence("t-build")
    };
    let out = open(&mut rig, &fence);
    assert!(rig.fake.pty_control("sbx-b", "t-build").is_none());
    match exit(&out) {
        Some(DaemonControlMessage::TerminalExit { error, .. }) => assert_eq!(
            error.map(|e| e.code),
            Some(SandboxErrorCode::UnsupportedCapability.into())
        ),
        other => panic!("{other:?}"),
    }
}

/// C10 (§10.4 Free, §10.6): a guest shell opened while a login's env is
/// installed gets that env merged after the private defaults, carries the
/// duration cap, and is closed (`revoked`) as soon as the login is freed.
#[test]
fn c10_freed_login_closes_the_shell_opened_with_its_env() {
    let mut rig = rig();
    let dir = tempfile::tempdir().unwrap();
    let credentials =
        crate::sandbox_relay::credentials::service::CredentialService::start(dir.path(), "host-1")
            .unwrap();
    credentials.install_test_env("sbx-1", "lease-1", "TOOL_TOKEN", b"c10-terminal-token");
    rig.host.set_credentials(Some(credentials.clone()));
    let (_fence, control) = opened(&mut rig, "term-1");
    assert!(
        control
            .env()
            .iter()
            .any(|(name, value)| name == "TOOL_TOKEN" && value == "c10-terminal-token")
    );
    // Nothing closes it while the login stays installed.
    assert!(exit(&settle(&mut rig, Duration::from_millis(50))).is_none());
    credentials.revoke_lease("lease-1");
    let out = drive(&mut rig, |o| exit(o).is_some());
    match exit(&out).unwrap() {
        DaemonControlMessage::TerminalExit { intent, .. } => {
            assert_eq!(intent, Some(TerminalCloseIntent::Revoked));
        }
        other => panic!("{other:?}"),
    }
    // A shell opened afterwards has no login env and stays open.
    let (_fence, control) = opened(&mut rig, "term-2");
    assert!(control.env().iter().all(|(name, _)| name != "TOOL_TOKEN"));
    assert!(exit(&settle(&mut rig, Duration::from_millis(50))).is_none());
}

/// A shell opened without any login env is never closed by credential
/// bookkeeping (no service, or a service with nothing installed).
#[test]
fn c10_shell_without_login_env_ignores_credential_revocations() {
    let mut rig = rig();
    let dir = tempfile::tempdir().unwrap();
    let credentials =
        crate::sandbox_relay::credentials::service::CredentialService::start(dir.path(), "host-1")
            .unwrap();
    rig.host.set_credentials(Some(credentials.clone()));
    let (_fence, _control) = opened(&mut rig, "term-1");
    credentials.revoke_lease("lease-1");
    assert!(exit(&settle(&mut rig, Duration::from_millis(50))).is_none());
}

#[path = "terminal_resume_tests.rs"]
mod resume;
