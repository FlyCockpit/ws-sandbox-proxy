// 4b.3 fair host admission: the ordinary file/process pool, the separate
// guest-signal pool, the quick control coordinator and the reserved
// lifecycle path. Every barrier is a FakeRuntime guest-IO hook that observes
// the scoped permit, so revocation and teardown can always end a held call.
mod ordinary_pool {
    use super::*;
    use std::collections::HashSet;

    #[derive(Default)]
    struct GateState {
        held: HashSet<String>,
        released: HashSet<String>,
        all_released: bool,
        /// Operation IDs in the order they reached simulated guest IO.
        entered: Vec<String>,
    }
    type Gate = Arc<(Mutex<GateState>, Condvar)>;

    struct Pool {
        gate: Gate,
        relay: RelaySupervisor,
        journal: Arc<HostJournal>,
        authority: HostAuthority,
        binding: TransportBindingV11,
        fake: FakeRuntime,
        finished: Mutex<HashMap<String, FinishedOp>>,
        _dir: tempfile::TempDir,
    }
    impl Drop for Pool {
        fn drop(&mut self) {
            // A failed assertion must never leave a worker parked on a gate.
            self.release_all();
        }
    }
    impl Pool {
        fn new(command_delay: Duration, command_limit: u32) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let binding = TransportBindingV11 {
                server: "wss://example".into(),
                host_owner_id: "owner".into(),
                host_id: "host".into(),
            };
            let journal = Arc::new(crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap());
            let gate: Gate = Arc::default();
            let hook_gate = gate.clone();
            let fake = FakeRuntime::with_command_delay(command_delay).with_guest_io_hook(
                move |io: &sandbox_runtime::FakeGuestIo<'_>| {
                    let (lock, ready) = &*hook_gate;
                    let mut state = lock.lock().unwrap();
                    state.entered.push(io.operation_id.to_string());
                    ready.notify_all();
                    // A held call models a guest page/helper blocked for up to
                    // 30 s; only release, revocation or the bound ends it.
                    let deadline = Instant::now() + Duration::from_secs(30);
                    while state.held.contains(io.operation_id)
                        && !state.released.contains(io.operation_id)
                        && !state.all_released
                        && Instant::now() < deadline
                    {
                        if io.permit.is_some_and(RuntimePermit::is_cancelled) {
                            return Err(RuntimeError::new(
                                SandboxErrorCode::UnknownOutcome,
                                "held guest IO preempted",
                            ));
                        }
                        state = ready
                            .wait_timeout(state, Duration::from_millis(10))
                            .unwrap()
                            .0;
                    }
                    Ok(())
                },
            );
        fake.fixture_root().unwrap();
            for id in ["a", "b", "c", "d", "e", "f"] {
                fake.create_fixture(&CreateSandboxRequest::for_test(id, id))
                    .unwrap();
            }
            let authority = HostAuthority::default();
            let relay = RelaySupervisor::start_with_command_limit(
                Arc::new(fake.clone()),
                journal.clone(),
                authority.clone(),
                #[cfg(target_os = "linux")]
                None,
                command_limit,
            );
            Self {
                gate,
                relay,
                journal,
                authority,
                binding,
                fake,
                finished: Mutex::default(),
                _dir: dir,
            }
        }
        fn hold(&self, id: &str) {
            self.gate.0.lock().unwrap().held.insert(id.into());
        }
        fn release(&self, id: &str) {
            self.gate.0.lock().unwrap().released.insert(id.into());
            self.gate.1.notify_all();
        }
        fn release_all(&self) {
            self.gate.0.lock().unwrap().all_released = true;
            self.gate.1.notify_all();
        }
        fn entered(&self) -> Vec<String> {
            self.gate.0.lock().unwrap().entered.clone()
        }
        fn wait_entered(&self, id: &str, timeout: Duration) -> bool {
            let (lock, ready) = &*self.gate;
            let deadline = Instant::now() + timeout;
            let mut state = lock.lock().unwrap();
            while !state.entered.iter().any(|entered| entered == id) {
                let now = Instant::now();
                if now >= deadline {
                    return false;
                }
                state = ready.wait_timeout(state, deadline - now).unwrap().0;
            }
            true
        }
        fn request(id: &str, kind: &str, sandbox: &str) -> OperationDispatch {
            let mut d = dispatch(id, kind, 1);
            d.sandbox_id = sandbox.into();
            d.sandbox_owner_id = format!("creator-{sandbox}");
            if kind == "process.signal" {
                d.pid = Some(4242);
                d.signal = Some("SIGTERM".into());
                d.target_operation_id = Some(format!("cmd-{sandbox}"));
                d.process = Some(sandbox_protocol::results::ProcessRef {
                    sandbox_id: sandbox.into(),
                    generation: 1,
                    process_id: format!("proc-{sandbox}"),
                    attempt: 1,
                    pid: 4242,
                });
            }
            d
        }
        /// The production order before the relay: durable intent, authority
        /// admission, then scheduler admission (which may refuse).
        fn try_admit(&self, d: OperationDispatch) -> anyhow::Result<()> {
            self.journal
                .record_fixture_intent(&intent_from_dispatch(&self.journal, &self.binding, &d))
                .unwrap();
            assert!(
                self.authority
                    .accept_dispatch(
                        &d.operation_id,
                        &d.sandbox_id,
                        &d.kind,
                        d.generation,
                        d.attempt
                    )
                    .unwrap()
            );
            let upload = (d.kind == "file.put")
                .then(|| sandbox_runtime::FileContent::from_bytes(b"payload").unwrap());
            let instance = sandbox_runtime::default_incus_instance_name(&d.sandbox_id);
            self.relay.submit(d, instance, upload)
        }
        fn admit(&self, id: &str, kind: &str, sandbox: &str) {
            self.try_admit(Self::request(id, kind, sandbox))
                .unwrap_or_else(|error| panic!("{id} refused: {error}"));
        }
        fn pump(&self) {
            for frame in self.relay.poll_output().expect("encode output") {
                self.relay.ack_output(
                    frame.metadata.operation_id.clone(),
                    frame.metadata.generation,
                    frame.metadata.attempt,
                    frame.metadata.sequence,
                    frame.metadata.offset.unwrap_or(0) + frame.body_len() as u64,
                );
            }
            let mut finished = self.finished.lock().unwrap();
            for op in self.relay.poll_finished() {
                if !op.interim {
                    finished.insert(op.operation_id.clone(), op);
                }
            }
        }
        fn finished(&self, id: &str) -> Option<FinishedOp> {
            self.pump();
            self.finished.lock().unwrap().get(id).cloned()
        }
        fn wait_done(&self, id: &str, timeout: Duration) -> Option<FinishedOp> {
            let deadline = Instant::now() + timeout;
            loop {
                if let Some(op) = self.finished(id) {
                    return Some(op);
                }
                if Instant::now() >= deadline {
                    return None;
                }
                thread::sleep(Duration::from_millis(2));
            }
        }
        fn done(&self, id: &str) -> FinishedOp {
            self.wait_done(id, Duration::from_secs(5))
                .unwrap_or_else(|| panic!("no completion for {id}"))
        }
    }

    fn assert_idle(queue: &CommandQueue) {
        let state = queue.state.lock().unwrap();
        assert_eq!(state.queued, 0, "queued count drained");
        assert!(state.queues.is_empty(), "empty subqueues are retired");
        assert!(state.turns.is_empty(), "no ready turns remain");
        assert!(state.active.is_empty(), "every active slot was released");
        assert_eq!(state.ordinary_active, 0, "host budget fully returned");
    }

    #[test]
    fn upload_reserves_admission_before_bytes_and_keeps_it_through_submit() {
        let mut p = Pool::new(Duration::ZERO, 4);
        p.hold("a-0");
        p.admit("a-0", "file.stat", "a");
        assert!(p.wait_entered("a-0", Duration::from_secs(2)));
        for n in 1..=4 {
            p.admit(&format!("a-{n}"), "file.stat", "a");
        }
        assert!(
            p.relay.reserve_upload("a").is_err(),
            "full pool must refuse before bytes"
        );
        p.release("a-0");
        for n in 0..=4 {
            p.done(&format!("a-{n}"));
        }
        p.hold("a-held");
        p.admit("a-held", "file.stat", "a");
        assert!(p.wait_entered("a-held", Duration::from_secs(2)));
        let reservation = p.relay.reserve_upload("a").unwrap();
        for n in 1..=3 {
            p.admit(&format!("fill-{n}"), "file.stat", "a");
        }
        assert!(p.relay.reserve_upload("a").is_err());
        assert!(
            p.try_admit(Pool::request("overflow", "file.stat", "a"))
                .is_err()
        );
        let d = Pool::request("upload", "file.put", "a");
        p.journal
            .record_fixture_intent(&intent_from_dispatch(&p.journal, &p.binding, &d))
            .unwrap();
        p.authority
            .accept_dispatch(
                &d.operation_id,
                &d.sandbox_id,
                &d.kind,
                d.generation,
                d.attempt,
            )
            .unwrap();
        p.relay
            .submit_upload(
                d,
                sandbox_runtime::default_incus_instance_name("a"),
                sandbox_runtime::FileContent::from_bytes(b"payload").unwrap(),
                reservation,
            )
            .unwrap();
        p.release("a-held");
        assert_ne!(
            p.done("upload").error.map(|e| e.code),
            Some(SandboxErrorCode::HostCapacity.into())
        );
        // Abort/failure/cancel/disconnect all drop the same RAII owner.
        p.journal.record_fixture_intent(&intent_from_dispatch(&p.journal, &p.binding, &Pool::request("bind-b", "file.stat", "b"))).unwrap();
        let mut held = Vec::new();
        for _ in 0..4 {
            held.push(p.relay.reserve_upload("b").unwrap());
        }
        assert!(p.relay.reserve_upload("b").is_err());
        drop(held.pop());
        assert!(p.relay.reserve_upload("b").is_ok());
        p.relay.shutdown_workers();
    }

    #[test]
    fn flooding_a_queues_at_most_four_and_b_is_admitted_before_a_drains() {
        let _staging = crate::sandbox_relay::test_support::staging_quota();
        let pool = Pool::new(Duration::ZERO, 16);
        pool.hold("a-0");
        pool.admit("a-0", "file.stat", "a");
        assert!(pool.wait_entered("a-0", Duration::from_secs(3)));
        // More than sixteen queued attempts for A alone.
        let mut admitted = Vec::new();
        let mut refused = Vec::new();
        for n in 1..=20 {
            let id = format!("a-{n}");
            match pool.try_admit(Pool::request(&id, "file.stat", "a")) {
                Ok(()) => admitted.push(id),
                Err(error) => {
                    assert_eq!(error.to_string(), "host work queue full or closed");
                    refused.push(id);
                }
            }
        }
        assert_eq!(admitted, ["a-1", "a-2", "a-3", "a-4"]);
        assert_eq!(refused.len(), 16);
        {
            let state = pool.relay.ordinary.state.lock().unwrap();
            assert_eq!(state.queues["a"].len(), 4, "A holds four queued slots");
            assert_eq!(state.queued, 4);
            assert_eq!(state.active["a"], 1);
        }
        // B is admitted and finishes while A's head is still blocked.
        pool.admit("b-0", "file.put", "b");
        let b = pool.done("b-0");
        assert_eq!(b.state, OperationState::Succeeded);
        assert!(
            pool.finished("a-0").is_none(),
            "A had not drained when B finished"
        );
        assert_eq!(
            pool.entered()
                .iter()
                .filter(|id| id.starts_with("a-"))
                .count(),
            1,
            "one active ordinary job per sandbox"
        );
        pool.release("a-0");
        for id in ["a-0", "a-1", "a-2", "a-3", "a-4"] {
            pool.done(id);
        }
        let order: Vec<_> = pool
            .entered()
            .into_iter()
            .filter(|id| id.starts_with("a-"))
            .collect();
        assert_eq!(order, ["a-0", "a-1", "a-2", "a-3", "a-4"], "FIFO within A");
        for id in &refused {
            assert!(pool.finished(id).is_none(), "{id} never ran");
        }
        assert_idle(&pool.relay.ordinary);
        // Released exactly once: the same capacity is available again, no
        // more (a double release would admit a fifth queued job).
        pool.hold("a-again-0");
        pool.admit("a-again-0", "file.stat", "a");
        assert!(pool.wait_entered("a-again-0", Duration::from_secs(3)));
        for n in 1..=4 {
            pool.admit(&format!("a-again-{n}"), "file.stat", "a");
        }
        assert!(
            pool.try_admit(Pool::request("a-again-5", "file.stat", "a"))
                .is_err()
        );
        pool.release("a-again-0");
        for n in 0..=4 {
            pool.done(&format!("a-again-{n}"));
        }
        assert_idle(&pool.relay.ordinary);
    }

    #[test]
    fn the_total_of_sixteen_refuses_only_when_several_sandboxes_fill_it() {
        let _staging = crate::sandbox_relay::test_support::staging_quota();
        let pool = Pool::new(Duration::ZERO, 16);
        for sandbox in ["a", "b", "c", "d"] {
            let head = format!("{sandbox}-0");
            pool.hold(&head);
            pool.admit(&head, "file.stat", sandbox);
            assert!(pool.wait_entered(&head, Duration::from_secs(3)), "{head}");
        }
        for sandbox in ["a", "b", "c"] {
            for n in 1..=4 {
                pool.admit(&format!("{sandbox}-{n}"), "file.stat", sandbox);
            }
        }
        // Twelve queued: D still has its own admission.
        for n in 1..=4 {
            pool.admit(&format!("d-{n}"), "file.stat", "d");
        }
        assert_eq!(pool.relay.ordinary.state.lock().unwrap().queued, 16);
        assert!(
            pool.try_admit(Pool::request("e-0", "file.stat", "e"))
                .is_err()
        );
        pool.release_all();
        for sandbox in ["a", "b", "c", "d"] {
            for n in 0..=4 {
                pool.done(&format!("{sandbox}-{n}"));
            }
        }
        assert_idle(&pool.relay.ordinary);
        pool.admit("e-1", "file.stat", "e");
        pool.done("e-1");
    }

    #[test]
    fn a_blocked_thirty_second_page_on_a_does_not_delay_a_transfer_on_b() {
        let _staging = crate::sandbox_relay::test_support::staging_quota();
        let pool = Pool::new(Duration::ZERO, 16);
        pool.hold("a-page");
        let mut page = Pool::request("a-page", "file.list", "a");
        page.path = Some("/".into());
        pool.try_admit(page).unwrap();
        assert!(pool.wait_entered("a-page", Duration::from_secs(3)));
        let started = Instant::now();
        pool.admit("b-put", "file.put", "b");
        let put = pool.wait_done("b-put", Duration::from_secs(3));
        let blocked = pool.finished("a-page").is_none();
        pool.release("a-page");
        let put = put.expect("B transfer completed while A's page was blocked");
        assert_eq!(put.state, OperationState::Succeeded);
        assert!(blocked, "A's page was still blocked");
        assert!(started.elapsed() < Duration::from_secs(3));
        pool.done("a-page");
        assert_idle(&pool.relay.ordinary);
    }

    #[test]
    fn sigkill_starts_while_both_guest_signal_workers_are_blocked() {
        let _staging = crate::sandbox_relay::test_support::staging_quota();
        let pool = Pool::new(Duration::from_secs(30), 4);
        let mut command = Pool::request("cmd-c", "command.run", "c");
        command.process_id = Some("proc-c".into());
        pool.try_admit(command).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let start = loop {
            if let Some(start) = pool.relay.poll_started().into_iter().next() {
                break start;
            }
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(2));
        };
        for (id, sandbox) in [("sig-a", "a"), ("sig-b", "b")] {
            pool.hold(id);
            pool.admit(id, "process.signal", sandbox);
            assert!(pool.wait_entered(id, Duration::from_secs(3)));
        }
        let mut kill = Pool::request("kill-c", "process.signal", "c");
        kill.signal = Some("SIGKILL".into());
        kill.pid = Some(start.pid);
        kill.process.as_mut().unwrap().pid = start.pid;
        let began = Instant::now();
        pool.try_admit(kill).unwrap();
        let result = pool.wait_done("kill-c", Duration::from_secs(1));
        let both_blocked = pool.finished("sig-a").is_none() && pool.finished("sig-b").is_none();
        pool.release_all();
        assert_eq!(
            result.expect("reserved kill starts promptly").state,
            OperationState::Succeeded
        );
        assert!(both_blocked);
        assert!(began.elapsed() < Duration::from_secs(2));
        assert!(
            !pool.entered().iter().any(|id| id == "kill-c"),
            "kill is bookkeeping, no guest helper"
        );
        assert_ne!(pool.done("cmd-c").state, OperationState::Succeeded);
    }

    #[test]
    fn a_slow_signal_on_a_does_not_delay_cancel_or_stdin_on_b() {
        let _staging = crate::sandbox_relay::test_support::staging_quota();
        let pool = Pool::new(Duration::from_secs(30), 16);
        pool.admit("cmd-b", "command.run", "b");
        pool.hold("sig-a");
        pool.admit("sig-a", "process.signal", "a");
        assert!(pool.wait_entered("sig-a", Duration::from_secs(3)));
        // B's cancel and stdin take the coordinator, as connect.rs does.
        pool.authority.accept_cancel("cmd-b", 1, 1).unwrap();
        pool.journal.record_cancel("cmd-b", 1, 1).unwrap();
        let (control_tx, control_rx) = mpsc::channel();
        let (runtime, tx) = (pool.fake.clone(), control_tx.clone());
        pool.relay
            .control(move || {
                let _ = runtime.cancel_operation("cmd-b");
                let _ = tx.send("cancel");
            })
            .unwrap();
        let (runtime, tx) = (pool.fake.clone(), control_tx);
        pool.relay
            .control(move || {
                let _ = runtime.write_stdin(&WriteStdinRequest {
                    operation_id: "cmd-b".into(),
                    generation: 1,
                    attempt: 1,
                    bytes: b"input".to_vec(),
                    eof: true,
                });
                let _ = tx.send("stdin");
            })
            .unwrap();
        let first = control_rx.recv_timeout(Duration::from_secs(1));
        let second = control_rx.recv_timeout(Duration::from_secs(1));
        let cancelled = pool.wait_done("cmd-b", Duration::from_secs(3));
        let still_held = pool.finished("sig-a").is_none();
        pool.release("sig-a");
        assert_eq!(first.expect("B cancel ran on the coordinator"), "cancel");
        assert_eq!(second.expect("B stdin ran on the coordinator"), "stdin");
        let cancelled = cancelled.expect("B command settled while A's signal was slow");
        assert_ne!(cancelled.state, OperationState::Succeeded);
        assert!(still_held, "A's signal helper was still in flight");
        pool.done("sig-a");
        assert_idle(&pool.relay.signals);
    }

    #[test]
    fn signals_have_their_own_pool_beside_a_saturated_ordinary_pool() {
        let _staging = crate::sandbox_relay::test_support::staging_quota();
        let pool = Pool::new(Duration::ZERO, 16);
        for sandbox in ["a", "b", "c", "d"] {
            let head = format!("{sandbox}-page");
            pool.hold(&head);
            pool.admit(&head, "file.stat", sandbox);
            assert!(pool.wait_entered(&head, Duration::from_secs(3)), "{head}");
        }
        pool.admit("a-queued", "file.stat", "a");
        // Every ordinary worker is blocked; A's signal still reaches its helper.
        pool.hold("sig-a");
        pool.admit("sig-a", "process.signal", "a");
        let a_entered = pool.wait_entered("sig-a", Duration::from_secs(2));
        // A slow A signal does not hold back B's signal (two workers), and a
        // second A signal waits in A's own FIFO.
        pool.admit("sig-a-2", "process.signal", "a");
        pool.admit("sig-b", "process.signal", "b");
        let b_signal = pool.wait_done("sig-b", Duration::from_secs(2));
        let second_waited = !pool.entered().iter().any(|id| id == "sig-a-2");
        pool.release_all();
        assert!(a_entered, "signal waited behind ordinary work");
        assert!(b_signal.is_some(), "B signal waited behind A's slow signal");
        assert!(second_waited, "one active signal job per sandbox");
        for id in [
            "a-page", "b-page", "c-page", "d-page", "a-queued", "sig-a", "sig-a-2",
        ] {
            pool.done(id);
        }
        let order: Vec<_> = pool
            .entered()
            .into_iter()
            .filter(|id| id.starts_with("sig-a"))
            .collect();
        assert_eq!(order, ["sig-a", "sig-a-2"]);
        assert_idle(&pool.relay.ordinary);
        assert_idle(&pool.relay.signals);
    }

    #[test]
    fn full_pools_still_admit_urgent_lifecycle_which_fences_queued_work() {
        let _staging = crate::sandbox_relay::test_support::staging_quota();
        let pool = Pool::new(Duration::from_secs(30), 1);
        let mut heads = Vec::new();
        for sandbox in ["a", "b", "c", "d"] {
            let head = format!("{sandbox}-0");
            pool.hold(&head);
            pool.admit(&head, "file.stat", sandbox);
            assert!(pool.wait_entered(&head, Duration::from_secs(3)), "{head}");
            heads.push(head);
            for n in 1..=4 {
                pool.admit(&format!("{sandbox}-{n}"), "file.stat", sandbox);
            }
        }
        assert!(
            pool.try_admit(Pool::request("e-0", "file.stat", "e"))
                .is_err(),
            "ordinary pool is full"
        );
        for sandbox in ["a", "b"] {
            let head = format!("sig-{sandbox}");
            pool.hold(&head);
            pool.admit(&head, "process.signal", sandbox);
            assert!(pool.wait_entered(&head, Duration::from_secs(3)), "{head}");
            heads.push(head);
        }
        for sandbox in ["c", "d"] {
            for n in 0..4 {
                pool.admit(&format!("sig-{sandbox}-{n}"), "process.signal", sandbox);
            }
        }
        assert!(
            pool.try_admit(Pool::request("sig-e", "process.signal", "e"))
                .is_err(),
            "signal pool is full"
        );
        // Command pool: one running (limit one) plus sixteen queued.
        for n in 0..17 {
            pool.admit(&format!("cmd-{n}"), "command.run", if n == 16 { "e" } else { "f" });
        }
        assert!(
            pool.try_admit(Pool::request("cmd-full", "command.run", "f"))
                .is_err(),
            "command pool is full"
        );
        // Urgent lifecycle still runs, and fences that sandbox's queued work.
        pool.admit("stop-a", "sandbox.stop", "a");
        pool.admit("kill-b", "sandbox.kill", "b");
        assert_eq!(pool.done("stop-a").state, OperationState::Succeeded);
        assert_eq!(pool.done("kill-b").state, OperationState::Succeeded);
        for id in ["a-0", "sig-a", "b-0", "sig-b"] {
            assert_ne!(pool.done(id).state, OperationState::Succeeded, "{id}");
        }
        for id in ["a-1", "a-4", "b-1", "b-4"] {
            let op = pool.done(id);
            assert_eq!(op.error.map(|e| e.code), Some(SandboxErrorCode::Cancelled.into()));
        }
        // Unfenced signals for C and D take the freed signal workers.
        for sandbox in ["c", "d"] {
            for n in 0..4 {
                let id = format!("sig-{sandbox}-{n}");
                pool.done(&id);
                heads.push(id);
            }
        }
        let entered: HashSet<_> = pool.entered().into_iter().collect();
        let expected: HashSet<_> = heads.iter().cloned().collect();
        assert_eq!(
            entered, expected,
            "fenced queued jobs never reached the guest"
        );
    }

    #[test]
    fn teardown_closes_every_pool_and_drains_its_workers() {
        let _staging = crate::sandbox_relay::test_support::staging_quota();
        let mut pool = Pool::new(Duration::from_secs(30), 16);
        let mut heads = HashSet::new();
        for sandbox in ["a", "b"] {
            let head = format!("{sandbox}-0");
            pool.hold(&head);
            pool.admit(&head, "file.stat", sandbox);
            assert!(pool.wait_entered(&head, Duration::from_secs(3)), "{head}");
            heads.insert(head);
            pool.admit(&format!("{sandbox}-1"), "file.stat", sandbox);
        }
        pool.hold("sig-a");
        pool.admit("sig-a", "process.signal", "a");
        assert!(pool.wait_entered("sig-a", Duration::from_secs(3)));
        heads.insert("sig-a".into());
        pool.admit("sig-a-2", "process.signal", "a");
        pool.admit("cmd-c", "command.run", "c");
        // Held IO observes revocation, queued jobs drain without reaching the
        // guest, and every worker thread exits before the bounded deadline.
        let started = Instant::now();
        pool.relay.shutdown_workers();
        assert!(
            pool.relay.workers.is_empty(),
            "teardown drained every worker"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        let entered: HashSet<_> = pool.entered().into_iter().collect();
        assert_eq!(entered, heads, "no queued job reached the guest");
        // Bypass the (now closed) authority: the scheduler itself refuses.
        assert!(
            pool.relay
                .submit(
                    Pool::request("late", "file.stat", "c"),
                    "wssp-sbx-c".into(),
                    None
                )
                .is_err(),
            "a closed pool admits nothing"
        );
        assert_idle(&pool.relay.ordinary);
        assert_idle(&pool.relay.signals);
    }
}
