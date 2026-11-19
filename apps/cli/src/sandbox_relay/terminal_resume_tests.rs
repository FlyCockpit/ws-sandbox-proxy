//! WP8 (D5) terminal reattach on the host: the output ring, detach on
//! connection loss, `terminal.resume` identity matching, the grace, C55
//! closes while detached and the per-sandbox limit with detached PTYs. Real
//! `TerminalHost` + pump threads over the FakeRuntime PTY (no socket).
use super::*;

const GRACE: Duration = Duration::from_secs(120);

/// A rig whose connection negotiated `terminalResume`, with `grace`.
fn resume_rig(grace: Duration) -> Rig {
    let mut rig = rig();
    rig.slots = Arc::new(TerminalSlots::with_resume_grace(grace));
    rig.host = connection(&rig, 5);
    rig
}

/// A new relay connection on the same process state (`epoch`), negotiated.
fn connection(rig: &Rig, epoch: u64) -> TerminalHost {
    let mut host = TerminalHost::new(
        rig.slots.clone(),
        Arc::new(rig.fake.clone()),
        rig.journal.clone(),
        rig.authority.clone(),
        "host-1".into(),
    );
    host.enable(epoch, binding());
    host.negotiate_resume(true);
    host
}

/// The relay connection ends (the old `TerminalHost` drops) and a new one
/// registers with `epoch`.
fn reconnect(rig: &mut Rig, epoch: u64) {
    let next = connection(rig, epoch);
    drop(std::mem::replace(&mut rig.host, next));
}

fn fence_on(session: &str, epoch: u64, generation: u64) -> TerminalFence {
    TerminalFence {
        operation_id: format!("top-{session}-{epoch}"),
        epoch,
        target: TerminalTargetV11::Sandbox {
            sandbox_id: "sbx-1".into(),
            generation,
        },
        ..fence(session)
    }
}

fn resume(rig: &mut Rig, fence: &TerminalFence, next_output_seq: u64) -> Vec<Out> {
    outs(
        rig.host
            .handle_control(ServerControlMessage::TerminalResume {
                request_id: format!("resume-{}", fence.operation_id),
                fence: fence.clone(),
                next_output_seq,
                rows: 30,
                cols: 100,
            })
            .unwrap(),
    )
}

fn resumed_at(out: &[Out]) -> Option<u64> {
    out.iter().find_map(|o| match o {
        Out::Text(DaemonControlMessage::TerminalReady { output_seq, .. }) => *output_seq,
        _ => None,
    })
}

fn refused_with(out: &[Out]) -> Option<sandbox_protocol::WireErrorCode> {
    match exit(out) {
        Some(DaemonControlMessage::TerminalExit {
            error: Some(error),
            reaped: true,
            ..
        }) => Some(error.code),
        _ => None,
    }
}

fn ack(rig: &mut Rig, fence: &TerminalFence, sequence: u64) {
    rig.host
        .handle_control(ServerControlMessage::TerminalAck {
            fence: fence.clone(),
            sequence,
        })
        .unwrap();
}

fn wait(what: &str, done: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < deadline, "never: {what}");
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn wp8_ring_sequences_bounds_and_resume_points() {
    let mut ring = OutputRing::default();
    assert_eq!((ring.first(), ring.next()), (0, 0));
    assert_eq!(ring.resume_from(0), Some(0));
    assert_eq!(ring.resume_from(1), None, "never produced");
    let frame = vec![7u8; sandbox_protocol::TERMINAL_DATA_MAX_BYTES];
    let per_ring = RESUME_RING_BYTES / frame.len();
    for expected in 0..per_ring as u64 {
        assert_eq!(ring.push(frame.clone(), None), expected);
    }
    assert_eq!(ring.first(), 0, "exactly full: nothing evicted yet");
    assert_eq!(ring.bytes(), RESUME_RING_BYTES);
    // Past the bound the oldest frames go; sequences never restart.
    for _ in 0..10 {
        ring.push(frame.clone(), None);
    }
    assert!(ring.bytes() <= RESUME_RING_BYTES);
    assert_eq!(ring.next(), per_ring as u64 + 10);
    assert_eq!(ring.first(), 10);
    assert!(ring.get(9).is_none());
    assert_eq!(ring.get(10).map(<[u8]>::len), Some(frame.len()));
    assert!(ring.get(ring.next()).is_none());
    // Held: continue there. Evicted: the oldest held (the browser is told).
    // Exactly `next`: nothing to replay. Past `next`: refused.
    assert_eq!(ring.resume_from(12), Some(12));
    assert_eq!(ring.resume_from(3), Some(10));
    assert_eq!(ring.resume_from(ring.next()), Some(ring.next()));
    assert_eq!(ring.resume_from(ring.next() + 1), None);
    // Small frames: the byte bound, not a frame count.
    let mut small = OutputRing::default();
    for _ in 0..(RESUME_RING_BYTES + 100) {
        small.push(vec![1], None);
    }
    assert_eq!(small.bytes(), RESUME_RING_BYTES);
    assert_eq!(small.first(), 100);
    // Attached: frames from the credit base on are never evicted; the ring
    // overshoots by what one read added, then trims once acknowledged.
    let floor = small.first();
    small.push(vec![2; 10], Some(floor));
    assert_eq!(small.first(), floor);
    assert_eq!(small.bytes(), RESUME_RING_BYTES + 10);
    small.push(vec![3], Some(floor + 20));
    assert_eq!(small.first(), floor + 11);
    assert_eq!(small.bytes(), RESUME_RING_BYTES);
}

#[test]
fn wp8_grace_is_clamped_and_offered_only_by_a_terminal_node() {
    assert_eq!(
        clamp_resume_grace(Duration::ZERO),
        Duration::from_secs(1),
        "the shortest grace a hello may carry"
    );
    assert_eq!(
        clamp_resume_grace(Duration::from_secs(3600)),
        Duration::from_secs(600)
    );
    assert_eq!(clamp_resume_grace(GRACE), GRACE);
    let slots = TerminalSlots::with_resume_grace(Duration::from_secs(86_400));
    assert_eq!(
        slots.resume_capability(true),
        Some(sandbox_protocol::TerminalResumeCapabilityV11 { grace_ms: 600_000 })
    );
    assert_eq!(slots.resume_capability(false), None);
    let offer = TerminalSlots::default().resume_capability(true).unwrap();
    assert_eq!(offer.grace_ms, 120_000);
    assert!(offer.is_valid());
    // The config path (no debug override in this process): default 120 s.
    if std::env::var_os(crate::sandbox_relay::test_timing::RELAY_TIMING_ENV).is_none() {
        assert_eq!(
            resume_grace(&crate::config::Config::default()).unwrap(),
            GRACE
        );
        let config = crate::config::Config {
            terminal_resume_grace: Some("2h".into()),
            ..Default::default()
        };
        assert_eq!(resume_grace(&config).unwrap(), Duration::from_secs(600));
    }
}

#[test]
fn wp8_resume_after_loss_replays_exactly_once_and_never_retypes_input() {
    let mut rig = resume_rig(GRACE);
    let (first, control) = opened(&mut rig, "term-r");
    control.set_echo(false);
    control.emit(b"seen");
    assert_eq!(
        output(&drive(&mut rig, |o| !output(o).is_empty())),
        vec![(0, b"seen".to_vec())]
    );
    ack(&mut rig, &first, 0);
    input(&mut rig, &first, 0, b"ab");
    assert_eq!(acks(&drive(&mut rig, |o| !acks(o).is_empty())), vec![0]);
    // Delivered to the PTY but never reached the browser before the drop.
    control.emit(b"lost-in-flight");
    drive(&mut rig, |o| !output(o).is_empty());

    reconnect(&mut rig, 6);
    assert_eq!(rig.slots.detached_sessions(), 1);
    assert_eq!(rig.slots.live(), 1, "the same PTY stays charged");
    // Detached: output keeps flowing into the ring; input has no path.
    control.emit(b"while-away");
    input(&mut rig, &first, 1, b"stale");
    assert!(settle(&mut rig, Duration::from_millis(150)).is_empty());
    assert!(!control.terminated());

    // The browser saw frame 0 only; it resumes at 1.
    let second = fence_on("term-r", 6, 1);
    assert!(resume(&mut rig, &second, 1).is_empty());
    let out = drive(&mut rig, |o| output(o).len() >= 2);
    assert_eq!(resumed_at(&out), Some(1));
    match &out[0] {
        Out::Text(DaemonControlMessage::TerminalReady {
            request_id,
            fence,
            rows,
            cols,
            ..
        }) => {
            assert_eq!(request_id, "resume-top-term-r-6");
            assert_eq!(fence, &second, "answered under the new fence");
            assert_eq!((*rows, *cols), (30, 100), "resized to the new size");
        }
        other => panic!("ready precedes replay: {other:?}"),
    }
    // Exactly the frames after the browser's position, each once.
    let replayed = output(&out);
    assert_eq!(replayed[0], (1, b"lost-in-flight".to_vec()));
    assert_eq!(replayed[1], (2, b"while-away".to_vec()));
    assert!(output(&settle(&mut rig, Duration::from_millis(150))).is_empty());
    assert_eq!(rig.slots.detached_sessions(), 0);
    // Input restarts at 0 on the new fence; nothing typed before is resent.
    input(&mut rig, &second, 0, b"cd");
    assert_eq!(acks(&drive(&mut rig, |o| !acks(o).is_empty())), vec![0]);
    // An ack means queued; the PTY writer thread delivers afterwards.
    assert_eq!(
        control.wait_for_input(b"abcd", Duration::from_secs(10)),
        b"abcd"
    );
    // The old fence is foreign on the new connection: zero bytes.
    input(&mut rig, &first, 2, b"old");
    settle(&mut rig, Duration::from_millis(50));
    assert_eq!(control.input(), b"abcd");
    // Output continues after the replay, acknowledged from `outputSeq`.
    ack(&mut rig, &second, 2);
    control.emit(b"after");
    assert_eq!(
        output(&drive(&mut rig, |o| !output(o).is_empty())),
        vec![(3, b"after".to_vec())]
    );
    assert_eq!(rig.slots.live(), 1);
}

#[test]
fn wp8_evicted_output_resumes_past_the_gap() {
    let mut rig = resume_rig(GRACE);
    let (_, control) = opened(&mut rig, "term-g");
    control.set_echo(false);
    reconnect(&mut rig, 6);
    // Far more than the ring while nobody is attached: the shell is not
    // back-pressured, the oldest output is evicted.
    let total = 2 * RESUME_RING_BYTES;
    control.emit(&vec![b'x'; total]);
    wait("detached pump drains the shell", || {
        control.pending_output() == 0
    });
    let fence = fence_on("term-g", 6, 1);
    assert!(resume(&mut rig, &fence, 0).is_empty());
    let mut out = drive(&mut rig, |o| resumed_at(o).is_some());
    let from = resumed_at(&out).unwrap();
    assert!(from > 0, "outputSeq past the request reports the loss");
    // Only the credit window is in flight, starting at the gap.
    out.extend(settle(&mut rig, Duration::from_millis(200)));
    let frames = output(&out);
    assert_eq!(frames.len() as u64, TERMINAL_OUTPUT_WINDOW_FRAMES);
    assert_eq!(frames[0].0, from);
    let replayed: usize = frames.iter().map(|(_, b)| b.len()).sum();
    assert!(replayed <= RESUME_RING_BYTES);
}

#[test]
fn wp8_resume_identity_must_match_the_daemons_own_record() {
    let mut rig = resume_rig(GRACE);
    let (_, control) = opened(&mut rig, "term-id");
    reconnect(&mut rig, 6);
    // Another generation, another sandbox, another terminal id, the host
    // target, a sequence never produced: each refused, the PTY untouched.
    let wrong_generation = fence_on("term-id", 6, 2);
    assert_eq!(
        refused_with(&resume(&mut rig, &wrong_generation, 0)),
        Some(SandboxErrorCode::StateConflict.into())
    );
    let wrong_sandbox = TerminalFence {
        target: TerminalTargetV11::Sandbox {
            sandbox_id: "sbx-2".into(),
            generation: 1,
        },
        ..fence_on("term-id", 6, 1)
    };
    assert_eq!(
        refused_with(&resume(&mut rig, &wrong_sandbox, 0)),
        Some(SandboxErrorCode::StateConflict.into())
    );
    assert_eq!(
        refused_with(&resume(&mut rig, &fence_on("term-other", 6, 1), 0)),
        Some(SandboxErrorCode::StateConflict.into())
    );
    let host_target = TerminalFence {
        target: TerminalTargetV11::Host {},
        ..fence_on("term-id", 6, 1)
    };
    assert_eq!(
        refused_with(&resume(&mut rig, &host_target, 0)),
        Some(SandboxErrorCode::UnsupportedCapability.into())
    );
    assert_eq!(
        refused_with(&resume(&mut rig, &fence_on("term-id", 6, 1), 50)),
        Some(SandboxErrorCode::ProtocolError.into())
    );
    // A frame on a stale epoch is foreign: no answer at all.
    assert!(resume(&mut rig, &fence_on("term-id", 5, 1), 0).is_empty());
    assert!(!control.terminated());
    assert_eq!(rig.slots.detached_sessions(), 1);
    assert_eq!(rig.host.live_sessions(), 0);
    // The exact identity still resumes the same PTY.
    let fence = fence_on("term-id", 6, 1);
    assert!(resume(&mut rig, &fence, 0).is_empty());
    assert_eq!(resumed_at(&drive(&mut rig, ready)), Some(0));
    // Resuming it again while attached never takes it over.
    let again = TerminalFence {
        operation_id: "top-again".into(),
        ..fence.clone()
    };
    assert!(resume(&mut rig, &again, 0).is_empty());
    input(&mut rig, &fence, 0, b"still-mine");
    drive(&mut rig, |o| !acks(o).is_empty());
    assert_eq!(
        control.wait_for_input(b"still-mine", Duration::from_secs(10)),
        b"still-mine"
    );

    // Without the negotiated capability nothing is detached or resumed.
    let mut plain = TerminalHost::new(
        rig.slots.clone(),
        Arc::new(rig.fake.clone()),
        rig.journal.clone(),
        rig.authority.clone(),
        "host-1".into(),
    );
    plain.enable(7, binding());
    let refused = outs(
        plain
            .handle_control(ServerControlMessage::TerminalResume {
                request_id: "r-plain".into(),
                fence: fence_on("term-id", 7, 1),
                next_output_seq: 0,
                rows: 24,
                cols: 80,
            })
            .unwrap(),
    );
    assert_eq!(
        refused_with(&refused),
        Some(SandboxErrorCode::UnsupportedCapability.into())
    );
}

#[test]
fn wp8_unnegotiated_connections_and_host_targets_are_never_detached() {
    let mut rig = resume_rig(GRACE);
    let opener: Arc<dyn sandbox_runtime::HostPtyOpener> =
        Arc::new(InjectedHostOpener(rig.fake.clone()));
    rig.host.configure_host(
        crate::sandbox_relay::host_policy::Policy {
            enabled: true,
            required: false,
            revision: 1,
        },
        Some(opener),
    );
    let host = host_fence("host-t");
    assert!(open_host(&mut rig, &host, 1, false).is_empty());
    drive(&mut rig, ready);
    let host_control = rig.fake.pty_control("sbx-1", "host-t").unwrap();
    let (_, guest_control) = opened(&mut rig, "guest-t");
    reconnect(&mut rig, 6);
    wait("host PTY closed with its connection", || {
        host_control.terminated() && host_control.reaped()
    });
    assert!(!guest_control.terminated());
    assert_eq!(rig.slots.detached_sessions(), 1, "only the sandbox PTY");
    // A connection whose server did not answer `terminalResume` closes all.
    rig.host.negotiate_resume(false);
    assert!(open(&mut rig, &fence_on("plain-t", 6, 1)).is_empty());
    drive(&mut rig, ready);
    let control = rig.fake.pty_control("sbx-1", "plain-t").unwrap();
    reconnect(&mut rig, 7);
    wait("unnegotiated PTY closed", || control.terminated());
    wait("its slot released", || rig.slots.in_sandbox("sbx-1") == 1);
    // An open still waiting for its answer is never detached either.
    let fence = fence_on("opening-t", 7, 1);
    let (entered, release) = pump_faults::pause_after_open("opening-t");
    assert!(open(&mut rig, &fence).is_empty());
    entered.recv().unwrap();
    reconnect(&mut rig, 8);
    release.send(()).unwrap();
    let opening = rig.fake.pty_control("sbx-1", "opening-t").unwrap();
    wait("unanswered open closed", || opening.terminated());
    assert_eq!(rig.slots.detached_sessions(), 1);
}

#[test]
fn wp8_detached_pty_closes_at_the_grace_and_is_then_unknown() {
    let mut rig = resume_rig(Duration::from_secs(1));
    let (_, control) = opened(&mut rig, "term-e");
    // No relay connection at all: the pump enforces the deadline itself.
    let deadline = Instant::now();
    reconnect(&mut rig, 6);
    wait("grace expiry", || {
        control.terminated() && control.released()
    });
    assert!(deadline.elapsed() >= Duration::from_millis(900));
    assert!(rig.slots.wait_idle(Duration::from_secs(5)));
    assert_eq!(rig.slots.live(), 0);
    // The record is forgotten after its grace: a late resume is refused.
    settle(&mut rig, Duration::from_millis(50));
    assert_eq!(rig.slots.detached_sessions(), 0);
    assert_eq!(
        refused_with(&resume(&mut rig, &fence_on("term-e", 6, 1), 0)),
        Some(SandboxErrorCode::StateConflict.into())
    );
}

#[test]
fn wp8_c55_closes_apply_at_once_while_detached() {
    // Lease expiry with no connection: the pump's own authority check.
    let mut rig = resume_rig(GRACE);
    let (_, control) = opened(&mut rig, "term-lease");
    reconnect(&mut rig, 6);
    let row = rig.journal.lease("sbx-1").unwrap();
    assert!(
        rig.journal
            .expire_lease_now_for_test("sbx-1", row.generation, row.lease.revision)
    );
    wait("lease expiry closes the detached PTY", || {
        control.terminated() && control.released()
    });
    assert_eq!(
        refused_with(&resume(&mut rig, &fence_on("term-lease", 6, 1), 0)),
        Some(SandboxErrorCode::StateConflict.into()),
        "an expired lease never resumes"
    );

    // An admitted stop on the next connection stops the detached PTY too.
    let mut rig = resume_rig(GRACE);
    let (_, control) = opened(&mut rig, "term-stop");
    reconnect(&mut rig, 6);
    let stop: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner",
        "operationId": "stop-1", "sandboxId": "sbx-1", "kind": "sandbox.stop", "allocation": crate::sandbox_relay::test_support::allocation(),
        "generation": 1, "attempt": 1, "idempotencyKey": "stop-1"
    }))
    .unwrap();
    rig.host.on_dispatch(&stop);
    wait("stop closes the detached PTY", || control.terminated());
    assert_eq!(
        refused_with(&resume(&mut rig, &fence_on("term-stop", 6, 1), 0)),
        Some(SandboxErrorCode::StateConflict.into())
    );

    // Daemon shutdown closes detached PTYs with the live ones.
    let mut rig = resume_rig(GRACE);
    let (_, control) = opened(&mut rig, "term-down");
    reconnect(&mut rig, 6);
    rig.host
        .shutdown(Duration::from_secs(5), |_| Ok(()))
        .unwrap();
    wait("shutdown closes the detached PTY", || control.terminated());
}

#[test]
fn wp8_shell_exit_while_detached_answers_the_resume_with_its_exit() {
    let mut rig = resume_rig(GRACE);
    let (_, control) = opened(&mut rig, "term-x");
    reconnect(&mut rig, 6);
    control.exit(Some(7));
    wait("shell exit while detached", || control.released());
    settle(&mut rig, Duration::from_millis(50));
    let fence = fence_on("term-x", 6, 1);
    assert!(resume(&mut rig, &fence, 0).is_empty());
    let out = drive(&mut rig, |o| exit(o).is_some());
    assert!(!ready(&out));
    assert!(matches!(
        exit(&out),
        Some(DaemonControlMessage::TerminalExit {
            request_id: Some(ref id),
            fence: ref answered,
            exit_code: Some(7),
            reaped: true,
            ..
        }) if id == "resume-top-term-x-6" && answered == &fence
    ));
    assert_eq!(rig.host.live_sessions(), 0);
    assert_eq!(rig.slots.detached_sessions(), 0);
}

#[test]
fn wp8_detached_ptys_count_and_a_new_open_evicts_the_oldest_detached_one() {
    let mut rig = resume_rig(GRACE);
    let (_, oldest) = opened(&mut rig, "term-1");
    reconnect(&mut rig, 6);
    thread::sleep(Duration::from_millis(5));
    let attached_fence = fence_on("term-2", 6, 1);
    assert!(open(&mut rig, &attached_fence).is_empty());
    drive(&mut rig, ready);
    let attached = rig.fake.pty_control("sbx-1", "term-2").unwrap();
    assert_eq!(rig.slots.in_sandbox("sbx-1"), 2, "detached PTYs count");
    // Limit reached by one detached and one attached PTY: the open evicts
    // the detached one, never the attached one.
    let third = fence_on("term-3", 6, 1);
    assert!(open(&mut rig, &third).is_empty());
    drive(&mut rig, |o| {
        o.iter().any(|o| matches!(o, Out::Text(DaemonControlMessage::TerminalReady { fence, .. }) if fence == &third))
    });
    wait("oldest detached PTY evicted", || oldest.terminated());
    assert!(!attached.terminated());
    assert_eq!(rig.slots.detached_sessions(), 0);
    assert_eq!(
        refused_with(&resume(&mut rig, &fence_on("term-1", 6, 1), 0)),
        Some(SandboxErrorCode::StateConflict.into())
    );
    // Two attached PTYs: nothing to evict, so the limit refuses as before.
    wait("evicted PTY reaped", || oldest.released());
    wait("evicted slot released", || rig.slots.live() == 2);
    assert_eq!(rig.slots.in_sandbox("sbx-1"), 2);
    assert_eq!(
        refused_with(&open(&mut rig, &fence_on("term-4", 6, 1))),
        Some(SandboxErrorCode::HostCapacity.into())
    );
    assert!(!attached.terminated());

    // Two detached PTYs (term-2 older than term-3): the next open evicts
    // term-2 only and term-3 still resumes.
    reconnect(&mut rig, 7);
    let third_control = rig.fake.pty_control("sbx-1", "term-3").unwrap();
    assert_eq!(rig.slots.detached_sessions(), 2);
    let fifth = fence_on("term-5", 7, 1);
    let refused = open(&mut rig, &fifth);
    assert!(refused.is_empty(), "{refused:?}");
    drive(&mut rig, ready);
    wait("older detached PTY evicted", || attached.terminated());
    assert!(!third_control.terminated());
    assert!(resume(&mut rig, &fence_on("term-3", 7, 1), 0).is_empty());
    assert_eq!(
        resumed_at(&drive(&mut rig, |o| resumed_at(o).is_some())),
        Some(0)
    );
}

#[test]
fn wp8_r1_input_validated_before_a_detach_is_never_written_or_acked_later() {
    let mut rig = resume_rig(GRACE);
    let (first, control) = opened(&mut rig, "term-in");
    control.set_echo(false);
    // The pump took the input for attachment 0 and stops right before the
    // write; the connection drops there.
    let (entered, release) = pump_faults::pause_at("before_write", "term-in");
    input(&mut rig, &first, 0, b"old");
    entered.recv().unwrap();
    reconnect(&mut rig, 6);
    release.send(()).unwrap();
    thread::sleep(Duration::from_millis(100));
    assert_eq!(control.input(), b"", "never written while detached");
    // Resumed: the stale write is not acknowledged on the new fence, and
    // the new attachment's input starts at 0.
    let second = fence_on("term-in", 6, 1);
    assert!(resume(&mut rig, &second, 0).is_empty());
    drive(&mut rig, ready);
    input(&mut rig, &second, 0, b"new");
    let out = drive(&mut rig, |o| !acks(o).is_empty());
    assert_eq!(acks(&out), vec![0]);
    assert!(acks(&settle(&mut rig, Duration::from_millis(100))).is_empty());
    assert_eq!(
        control.wait_for_input(b"new", Duration::from_secs(10)),
        b"new"
    );
}

#[test]
fn wp8_r1_a_read_outstanding_across_resume_never_evicts_the_promised_replay() {
    let mut rig = resume_rig(GRACE);
    let (_, control) = opened(&mut rig, "term-rd");
    control.set_echo(false);
    reconnect(&mut rig, 6);
    // A full detached ring...
    control.emit(&vec![
        b'f';
        RESUME_RING_BYTES
            + 4 * sandbox_protocol::TERMINAL_DATA_MAX_BYTES
    ]);
    wait("detached ring full", || control.pending_output() == 0);
    // ...and one more read outstanding while the resume picks the oldest frame.
    let (entered, release) = pump_faults::pause_at("before_push", "term-rd");
    control.emit(b"late");
    entered.recv().unwrap();
    let fence = fence_on("term-rd", 6, 1);
    assert!(resume(&mut rig, &fence, 0).is_empty());
    release.send(()).unwrap();
    let mut out = drive(&mut rig, |o| resumed_at(o).is_some());
    let from = resumed_at(&out).unwrap();
    assert!(from > 0);
    // Forward everything, acknowledging each window: every frame from the
    // promise on arrives once, in order, and the PTY stays open.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut seen: Vec<u64> = Vec::new();
    loop {
        out.extend(outs(rig.host.poll().unwrap()));
        let frames = output(&out);
        if let Some((last, _)) = frames.last()
            && seen.last() != Some(last)
        {
            seen.extend(frames.iter().map(|(s, _)| *s).skip(seen.len()));
            ack(&mut rig, &fence, *last);
        }
        assert!(exit(&out).is_none(), "valid PTY closed: {:?}", exit(&out));
        if frames.last().is_some_and(|(_, b)| b.as_slice() == b"late") {
            break;
        }
        assert!(Instant::now() < deadline, "replay never finished");
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(seen[0], from);
    assert!(
        seen.windows(2).all(|w| w[1] == w[0] + 1),
        "no gap, no duplicate"
    );
    assert!(!control.terminated());
}

#[test]
fn wp8_r1_a_resume_after_the_deadline_never_cancels_the_expiry() {
    let mut rig = resume_rig(Duration::from_secs(1));
    let (_, control) = opened(&mut rig, "term-dl");
    control.set_echo(false);
    reconnect(&mut rig, 6);
    // The pump is held inside a read, so it cannot act on its deadline.
    let (entered, release) = pump_faults::pause_at("before_push", "term-dl");
    control.emit(b"x");
    entered.recv().unwrap();
    thread::sleep(Duration::from_millis(1100));
    assert_eq!(
        refused_with(&resume(&mut rig, &fence_on("term-dl", 6, 1), 0)),
        Some(SandboxErrorCode::StateConflict.into())
    );
    release.send(()).unwrap();
    wait("expired PTY closed", || control.terminated());
    assert_eq!(rig.host.live_sessions(), 0);
}
