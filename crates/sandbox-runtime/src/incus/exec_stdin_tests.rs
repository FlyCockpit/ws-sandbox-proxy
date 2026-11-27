use super::*;
use crate::incus::shim_tests::{client_for_with_log, run_req};

fn supervisor() -> ExecSupervisor {
    ExecSupervisor::new(IncusClient::new("/no-such-incus", "default"))
}

fn input(op: &str, bytes: usize, eof: bool) -> WriteStdinRequest {
    WriteStdinRequest {
        operation_id: op.into(),
        generation: 1,
        attempt: 1,
        bytes: vec![b'x'; bytes],
        eof,
    }
}

fn usage(supervisor: &ExecSupervisor) -> (usize, usize, usize) {
    let state = supervisor.stdin_budget.0.lock().unwrap();
    (state.host_chunks, state.host_bytes, state.per_op.len())
}

/// An idle receiver models a command whose pipe pump is blocked on a write.
fn mailbox(supervisor: &ExecSupervisor, op: &str) -> mpsc::Receiver<StdinMsg> {
    let bound = supervisor.client.local_test_bound();
    supervisor.test_track_signal(&bound, &run_req(op));
    let (tx, rx) = mpsc::channel();
    supervisor.active.lock().unwrap().get_mut(op).unwrap().stdin = Some(StdinSender::new(tx));
    rx
}

fn capacity_refusal(outcome: EffectOutcome<()>) {
    let error = outcome.expect_err("stdin must refuse excess storage");
    assert!(matches!(error, EffectError::NotIssued(_)), "{error:?}");
    assert_eq!(error.code, SandboxErrorCode::HostCapacity);
}

fn wait_for(mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !ready() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for stdin fixture"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn pending_per_operation_byte_and_chunk_limits_release_on_close() {
    for (count, size) in [
        (EXEC_STDIN_PER_OP_MAX_CHUNKS, 1),
        (1, EXEC_STDIN_PER_OP_MAX_BYTES),
    ] {
        let supervisor = supervisor();
        let writer = supervisor.clone();
        for _ in 0..count {
            writer.write_stdin(&input("pending", size, false)).unwrap();
        }
        capacity_refusal(writer.write_stdin(&input("pending", 1, false)));
        assert_eq!(usage(&supervisor), (count, count * size, 1));
        // EOF folds into the existing entry even when its data budget is full.
        for _ in 0..100 {
            writer.write_stdin(&input("pending", 0, true)).unwrap();
        }
        assert_eq!(usage(&supervisor), (count, count * size, 1));
        let pending = supervisor.test_pending_stdin(&run_req("pending")).unwrap();
        assert_eq!(pending, (vec![b'x'; count * size], true));
        supervisor.close_stdin("pending", 1, 1);
        assert_eq!(usage(&supervisor), (0, 0, 0));
        writer
            .write_stdin(&input("replacement", size, false))
            .unwrap();
        supervisor.retain_pending_stdin(|_| false);
        assert_eq!(usage(&supervisor), (0, 0, 0));
    }
}

#[test]
fn pending_empty_requests_and_eof_only_entries_cannot_grow_without_budget() {
    let supervisor = supervisor();
    for index in 0..EXEC_STDIN_HOST_MAX_CHUNKS * 2 {
        supervisor
            .write_stdin(&input(&format!("noop-{index}"), 0, false))
            .unwrap();
    }
    assert!(supervisor.pending_stdin.lock().unwrap().is_empty());
    for index in 0..EXEC_STDIN_HOST_MAX_CHUNKS {
        let request = input(&format!("eof-{index}"), 0, true);
        for _ in 0..3 {
            supervisor.write_stdin(&request).unwrap();
        }
    }
    assert_eq!(
        usage(&supervisor),
        (EXEC_STDIN_HOST_MAX_CHUNKS, 0, EXEC_STDIN_HOST_MAX_CHUNKS)
    );
    for index in 0..100 {
        capacity_refusal(supervisor.write_stdin(&input(&format!("refused-{index}"), 0, true)));
        capacity_refusal(supervisor.write_stdin(&input(
            &format!("refused-data-{index}"),
            1,
            false,
        )));
    }
    assert_eq!(
        supervisor.pending_stdin.lock().unwrap().len(),
        EXEC_STDIN_HOST_MAX_CHUNKS
    );
    supervisor.close_stdin("eof-0", 1, 1);
    supervisor
        .write_stdin(&input("replacement", 0, true))
        .unwrap();
    supervisor.retain_pending_stdin(|_| false);
    assert_eq!(usage(&supervisor), (0, 0, 0));
    assert!(supervisor.pending_stdin.lock().unwrap().is_empty());
}

#[test]
fn live_mailbox_byte_and_chunk_limits_include_a_dequeued_message() {
    for (count, size) in [
        (EXEC_STDIN_PER_OP_MAX_CHUNKS, 1),
        (1, EXEC_STDIN_PER_OP_MAX_BYTES),
    ] {
        let supervisor = supervisor();
        let rx = mailbox(&supervisor, "live");
        for _ in 0..count {
            supervisor.write_stdin(&input("live", size, false)).unwrap();
        }
        capacity_refusal(supervisor.write_stdin(&input("live", 1, false)));
        let in_flight = rx.recv().unwrap();
        assert_eq!(usage(&supervisor), (count, count * size, 1));
        capacity_refusal(supervisor.write_stdin(&input("live", 1, false)));
        drop(in_flight);
        supervisor.write_stdin(&input("live", size, false)).unwrap();
        assert_eq!(usage(&supervisor), (count, count * size, 1));
        supervisor.close_stdin("live", 1, 1);
        assert_eq!(
            supervisor
                .write_stdin(&input("live", 1, false))
                .unwrap_err()
                .code,
            SandboxErrorCode::NotFound
        );
        assert!(supervisor.pending_stdin.lock().unwrap().is_empty());
        // Disconnect does not release data still owned by the receiver/pump.
        assert_eq!(usage(&supervisor), (count, count * size, 1));
        drop(rx);
        assert_eq!(usage(&supervisor), (0, 0, 0));
    }
}

#[test]
fn pending_and_live_operations_share_host_byte_and_chunk_limits() {
    for (count, size) in [
        (EXEC_STDIN_PER_OP_MAX_CHUNKS, 1),
        (1, EXEC_STDIN_PER_OP_MAX_BYTES),
    ] {
        let supervisor = supervisor();
        let writer = supervisor.with_client(supervisor.client.clone());
        let live_a = mailbox(&supervisor, "live-a");
        let live_b = mailbox(&supervisor, "live-b");
        let replacement = mailbox(&supervisor, "replacement");
        for op in ["pending-a", "pending-b", "live-a", "live-b"] {
            for _ in 0..count {
                writer.write_stdin(&input(op, size, false)).unwrap();
            }
        }
        assert_eq!(usage(&supervisor), (4 * count, 4 * count * size, 4));
        capacity_refusal(writer.write_stdin(&input("replacement", 1, false)));
        capacity_refusal(writer.write_stdin(&input("refused-pending", 1, false)));
        assert_eq!(supervisor.pending_stdin.lock().unwrap().len(), 2);
        supervisor.close_stdin("live-a", 1, 1);
        capacity_refusal(writer.write_stdin(&input("replacement", 1, false)));
        drop(live_a);
        for _ in 0..count {
            writer
                .write_stdin(&input("replacement", size, false))
                .unwrap();
        }
        assert_eq!(usage(&supervisor), (4 * count, 4 * count * size, 4));
        supervisor.cancel("pending-a").unwrap();
        assert_eq!(usage(&supervisor), (3 * count, 3 * count * size, 3));
        drop(live_b);
        drop(replacement);
        supervisor.retain_pending_stdin(|_| false);
        assert_eq!(usage(&supervisor), (0, 0, 0));
    }
}

#[test]
fn saturated_mailbox_eof_disconnects_once_despite_sender_clones() {
    let supervisor = supervisor();
    let rx = mailbox(&supervisor, "live");
    for _ in 0..EXEC_STDIN_PER_OP_MAX_CHUNKS {
        supervisor.write_stdin(&input("live", 1, false)).unwrap();
    }
    // EOF must be deliverable even at the data limit, without a queued marker.
    supervisor.write_stdin(&input("live", 0, true)).unwrap();
    let sender = supervisor.active.lock().unwrap()["live"]
        .stdin
        .clone()
        .unwrap();
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let sender = sender.clone();
            thread::spawn(move || {
                for _ in 0..100 {
                    sender.close();
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    for _ in 0..EXEC_STDIN_PER_OP_MAX_CHUNKS {
        assert_eq!(rx.recv().unwrap().bytes, b"x");
    }
    assert!(matches!(
        rx.try_recv(),
        Err(mpsc::TryRecvError::Disconnected)
    ));
    assert_eq!(usage(&supervisor), (0, 0, 0));
    assert_eq!(
        supervisor
            .write_stdin(&input("live", 0, true))
            .unwrap_err()
            .code,
        SandboxErrorCode::NotFound
    );
    assert!(supervisor.pending_stdin.lock().unwrap().is_empty());
    // Keeping clones alive cannot postpone EOF.
    drop(sender);
}

#[test]
fn data_and_eof_are_one_ordered_handoff_and_failed_sends_release_capacity() {
    let supervisor = supervisor();
    let rx = mailbox(&supervisor, "live");
    supervisor.write_stdin(&input("live", 3, true)).unwrap();
    assert_eq!(rx.recv().unwrap().bytes, b"xxx");
    assert!(matches!(
        rx.try_recv(),
        Err(mpsc::TryRecvError::Disconnected)
    ));
    assert_eq!(usage(&supervisor), (0, 0, 0));
    let failed_rx = mailbox(&supervisor, "failed");
    drop(failed_rx);
    assert_eq!(
        supervisor
            .write_stdin(&input("failed", 10, false))
            .unwrap_err()
            .code,
        SandboxErrorCode::NotFound
    );
    assert_eq!(usage(&supervisor), (0, 0, 0));
    // A live attempt with no pipe is also closed, never a new pending entry.
    let bound = supervisor.client.local_test_bound();
    supervisor.test_track_signal(&bound, &run_req("no-pipe"));
    assert_eq!(
        supervisor
            .write_stdin(&input("no-pipe", 1, false))
            .unwrap_err()
            .code,
        SandboxErrorCode::NotFound
    );
    let mut stale = input("no-pipe", 1, false);
    stale.generation += 1;
    assert_eq!(
        supervisor.write_stdin(&stale).unwrap_err().code,
        SandboxErrorCode::NotFound
    );
    stale.generation = 1;
    stale.attempt += 1;
    assert_eq!(
        supervisor.write_stdin(&stale).unwrap_err().code,
        SandboxErrorCode::NotFound
    );
    assert!(supervisor.pending_stdin.lock().unwrap().is_empty());
}

struct BlockedWrite {
    entered: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
}

impl Write for BlockedWrite {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        self.entered.send(()).unwrap();
        self.release.recv_timeout(Duration::from_secs(20)).unwrap();
        Err(std::io::ErrorKind::BrokenPipe.into())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn blocking_pipe_write_keeps_permit_and_overflow_does_not_block_cancel() {
    let supervisor = supervisor();
    let rx = mailbox(&supervisor, "blocked");
    let size = EXEC_STDIN_PER_OP_MAX_BYTES / 2;
    supervisor
        .write_stdin(&input("blocked", size, false))
        .unwrap();
    supervisor
        .write_stdin(&input("blocked", size, false))
        .unwrap();
    let failed = Arc::new(AtomicBool::new(false));
    let (entered_tx, entered) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    let pump_failed = failed.clone();
    let pump = thread::spawn(move || {
        pump_stdin(
            BlockedWrite {
                entered: entered_tx,
                release: release_rx,
            },
            None,
            rx,
            &pump_failed,
            None,
        );
    });
    entered.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(usage(&supervisor), (2, 2 * size, 1));
    let worker = supervisor.clone();
    let (done, result) = mpsc::channel();
    let control = thread::spawn(move || {
        capacity_refusal(worker.write_stdin(&input("blocked", 1, false)));
        worker.cancel("blocked").unwrap();
        assert_eq!(
            worker
                .write_stdin(&input("blocked", 1, false))
                .unwrap_err()
                .code,
            SandboxErrorCode::NotFound
        );
        done.send(()).unwrap();
    });
    let responsive = result.recv_timeout(Duration::from_secs(5));
    let retained = usage(&supervisor);
    // Release before assertions so a failed check cannot strand the pump.
    release.send(()).unwrap();
    pump.join().unwrap();
    control.join().unwrap();
    responsive.expect("overflow and priority cancel must not wait for pipe IO");
    assert_eq!(retained, (2, 2 * size, 1));
    assert!(failed.load(Ordering::Acquire));
    assert_eq!(usage(&supervisor), (0, 0, 0));
}

#[test]
fn real_supervisor_inline_stdin_uses_the_pending_attempt_budget_before_spawn() {
    let (client, _) = client_for_with_log("passthrough");
    let supervisor = ExecSupervisor::new(client);
    let mut request = run_req("inline");
    request.stdin = Some(vec![b'x'; EXEC_STDIN_PER_OP_MAX_BYTES]);
    supervisor.write_stdin(&input("inline", 1, false)).unwrap();
    let error = supervisor
        .run(&supervisor.bind(&request).unwrap(), &request)
        .unwrap_err();
    assert!(matches!(error, EffectError::NotIssued(_)), "{error:?}");
    assert_eq!(error.code, SandboxErrorCode::HostCapacity);
    assert!(supervisor.active.lock().unwrap().is_empty());
    assert_eq!(usage(&supervisor), (1, 1, 1));
    supervisor.close_stdin("inline", 1, 1);
    assert_eq!(usage(&supervisor), (0, 0, 0));
}

#[test]
fn real_supervisor_transfers_pending_budget_and_delivers_eof() {
    let (client, log) = client_for_with_log("passthrough");
    let ops = log.parent().unwrap().join("exec-stdin-ops");
    std::fs::create_dir_all(&ops).unwrap();
    let _ops = set_test_guest_ops_dir(Some(ops));
    let supervisor = ExecSupervisor::new(client);
    let mut request = run_req("pending-cat");
    request.argv = vec!["cat".into()];
    request.timeout_ms = Some(20_000);
    // Saturate the slot limit so transfer cannot acquire a second reservation.
    for index in 0..EXEC_STDIN_PER_OP_MAX_CHUNKS {
        supervisor
            .write_stdin(&input(
                "pending-cat",
                1,
                index + 1 == EXEC_STDIN_PER_OP_MAX_CHUNKS,
            ))
            .unwrap();
    }
    for _ in 0..100 {
        supervisor
            .write_stdin(&input("pending-cat", 0, true))
            .unwrap();
    }
    let response = supervisor
        .run(&supervisor.bind(&request).unwrap(), &request)
        .unwrap()
        .into_value();
    assert_eq!(response.command.exit_code, Some(0));
    let stdout: Vec<_> = response
        .command
        .chunks
        .iter()
        .filter(|chunk| chunk.stream == CommandStream::Stdout)
        .flat_map(|chunk| chunk.bytes.iter().copied())
        .collect();
    assert_eq!(stdout, vec![b'x'; EXEC_STDIN_PER_OP_MAX_CHUNKS]);
    wait_for(|| usage(&supervisor) == (0, 0, 0));
    assert!(supervisor.pending_stdin.lock().unwrap().is_empty());
}

#[test]
fn real_supervisor_blocked_stdin_overflow_cancel_preserves_tail_output() {
    let (client, log) = client_for_with_log("passthrough");
    let ops = log.parent().unwrap().join("exec-stdin-ops");
    std::fs::create_dir_all(&ops).unwrap();
    let ready = ops.join("ready");
    let _ops = set_test_guest_ops_dir(Some(ops));
    let output = crate::CommandOutput::default();
    let supervisor = ExecSupervisor::new(client).with_output(output.clone());
    let mut request = run_req("blocked-stdin");
    // The shim uses the host's /proc for the real termination helper.
    request.guest.guest_uid = std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    request.argv = vec![
        "python3".into(),
        "-c".into(),
        format!(
            "import signal,time,sys\ndef stop(*_):\n print('cancel-tail',file=sys.stderr,flush=True)\n raise SystemExit(0)\nsignal.signal(signal.SIGTERM,stop)\nopen({:?},'w').close()\nwhile True: time.sleep(0.05)\n",
            ready.to_str().unwrap()
        ),
    ];
    request.timeout_ms = Some(30_000);
    let worker = supervisor.clone();
    let live = request.clone();
    let (done, result) = mpsc::channel();
    let command = thread::spawn(move || {
        let bound = worker.bind(&live).unwrap();
        let outcome =
            worker.run_with_admission(&bound, &live, || Ok((Arc::new(AtomicBool::new(false)), ())));
        done.send(outcome).unwrap();
    });
    wait_for(|| ready.exists() && supervisor.active_birth("blocked-stdin").is_some());
    let mut overflow = false;
    for _ in 0..EXEC_STDIN_HOST_MAX_CHUNKS {
        match supervisor.write_stdin(&input("blocked-stdin", 16 * 1024, false)) {
            Ok(_) => {}
            Err(error) => {
                assert_eq!(error.code, SandboxErrorCode::HostCapacity);
                overflow = true;
                break;
            }
        }
    }
    let retained = usage(&supervisor);
    // The command owner handles termination; the control worker only requests it.
    supervisor.close_stdin("blocked-stdin", 1, 1);
    supervisor.cancel("blocked-stdin").unwrap();
    let settled = result.recv_timeout(Duration::from_secs(40));
    if settled.is_err() {
        supervisor.kill_local_groups();
    }
    command.join().unwrap();
    let error = settled
        .expect("cancel must release blocked stdin")
        .expect_err("an interrupted stdin write retains the existing UNKNOWN classification");
    assert!(matches!(error, EffectError::Unknown(_)), "{error:?}");
    assert!(
        overflow,
        "a non-reading command must saturate downstream storage"
    );
    assert!(retained.0 > 0 && retained.0 <= EXEC_STDIN_PER_OP_MAX_CHUNKS);
    assert!(retained.1 > 0 && retained.1 <= EXEC_STDIN_PER_OP_MAX_BYTES);
    let mut stderr = Vec::new();
    while let Some(chunk) = output.pop() {
        if chunk.stream == CommandStream::Stderr {
            stderr.extend_from_slice(&chunk.bytes);
        }
    }
    assert_eq!(stderr, b"cancel-tail\n");
    wait_for(|| usage(&supervisor) == (0, 0, 0));
    assert!(supervisor.pending_stdin.lock().unwrap().is_empty());
}
