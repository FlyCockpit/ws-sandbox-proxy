mod lifecycle_pool {
    use super::*;

    #[test]
    fn e43_unknown_retry_cycle_yields_cleanup_worker_and_resumes() {
        let dir = tempfile::tempdir().unwrap();
        let binding = TransportBindingV11 { server: "wss://example".into(), host_owner_id: "owner".into(), host_id: "host".into() };
        let journal = Arc::new(crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap());
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = attempts.clone();
        let fake = FakeRuntime::new().with_lifecycle_hook(move |stage| {
            if stage == "destroy" && count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < 3 {
                return Err(sandbox_runtime::RuntimeError::new(SandboxErrorCode::Internal, "unresolved teardown"));
            }
            Ok(())
        });
        fake.fixture_root().unwrap();
        for id in ["sbx", "other"] { fake.create_fixture(&CreateSandboxRequest::for_test(id, &format!("create-{id}"))).unwrap(); }
        let runtime = fake.clone();
        let authority = HostAuthority::default();
        let relay = RelaySupervisor::start(Arc::new(fake), journal.clone(), authority.clone(),
            #[cfg(target_os = "linux")] None,
        );
        admit(&relay, &journal, &binding, &authority, dispatch("unknown", "sandbox.kill", 2));
        assert_eq!(done(&relay, "unknown").state, OperationState::UnknownOutcome);
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 3);
        assert_eq!(runtime.query_sandbox("sbx", None, None).unwrap(), Some(sandbox_protocol::SandboxLifecycleState::Ready));
        let mut other = dispatch("other-kill", "sandbox.kill", 2);
        other.sandbox_id = "other".into();
        journal.record_fixture_intent(&intent_from_dispatch(&journal, &binding, &other)).unwrap();
        authority.accept_dispatch("other-kill", "other", "sandbox.kill", 2, 1).unwrap();
        relay.submit(other, "wssp-sbx-other".into(), None).unwrap();
        assert_eq!(done(&relay, "other-kill").state, OperationState::Succeeded);
        relay.resume_teardowns(&journal, &binding).unwrap();
        assert_eq!(done(&relay, "unknown").state, OperationState::Succeeded);
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 5);
        assert_eq!(runtime.query_sandbox("sbx", None, None).unwrap(), None);
    }

    #[test]
    fn e43_published_unknown_teardown_resumes_on_heartbeat() {
        let dir = tempfile::tempdir().unwrap();
        let binding = TransportBindingV11 { server: "wss://example".into(), host_owner_id: "owner".into(), host_id: "host".into() };
        let journal = Arc::new(crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap());
        let fake = FakeRuntime::new();
        fake.fixture_root().unwrap();
        fake.create_fixture(&CreateSandboxRequest::for_test("sbx", "create")).unwrap();
        let authority = HostAuthority::default();
        let d = dispatch("teardown", "sandbox.kill", 2);
        journal.record_fixture_intent(&intent_from_dispatch(&journal, &binding, &d)).unwrap();
        authority.accept_dispatch("teardown", "sbx", "sandbox.kill", 2, 1).unwrap();
        journal.record_result("teardown", OperationState::UnknownOutcome, None, Some(SandboxErrorCode::UnknownOutcome), None).unwrap();
        // The worker is gone after a transient result-journal write failure.
        // The reader published UNKNOWN but retained authority for a later upgrade.
        assert!(authority.pending("teardown").is_some());
        assert!(!authority.accept_dispatch("teardown", "sbx", "sandbox.kill", 2, 1).unwrap(), "wire duplicates retain replay semantics");
        let runtime = fake.clone();
        let relay = RelaySupervisor::start(Arc::new(fake), journal.clone(), authority,
            #[cfg(target_os = "linux")] None,
        );
        relay.resume_teardowns(&journal, &binding).unwrap();
        assert_eq!(done(&relay, "teardown").state, OperationState::Succeeded);
        assert_eq!(runtime.query_sandbox("sbx", None, None).unwrap(), None);
    }

    #[test]
    fn e43_unknown_teardown_is_retried_until_positive_completion() {
        for kind in ["sandbox.kill", "sandbox.stop"] {
            let dir = tempfile::tempdir().unwrap();
            let binding = TransportBindingV11 { server: "wss://example".into(), host_owner_id: "owner".into(), host_id: "host".into() };
            let journal = Arc::new(crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap());
            let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let count = attempts.clone();
            let (retry_tx, retry_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let release_rx = Mutex::new(release_rx);
            let fake = FakeRuntime::new().with_lifecycle_hook(move |stage| {
                if !matches!(stage, "destroy" | "stop") { return Ok(()); }
                if count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    return Err(sandbox_runtime::RuntimeError::new(SandboxErrorCode::Internal, "uncertain daemon response"));
                }
                retry_tx.send(()).unwrap();
                release_rx.lock().unwrap().recv_timeout(Duration::from_secs(20)).unwrap();
                Ok(())
            });
        fake.fixture_root().unwrap();
            fake.create_fixture(&CreateSandboxRequest::for_test("sbx", "create")).unwrap();
            let runtime = fake.clone();
            let authority = HostAuthority::default();
            let relay = RelaySupervisor::start(Arc::new(fake), journal.clone(), authority.clone(),
                #[cfg(target_os = "linux")] None,
            );
            let dispatch = dispatch("teardown", kind, 2);
            journal.record_fixture_intent(&intent_from_dispatch(&journal, &binding, &dispatch)).unwrap();
            authority.accept_dispatch("teardown", "sbx", kind, 2, 1).unwrap();
            relay.submit(dispatch, "wssp-sbx-sbx".into(), None).unwrap();
            let retried = retry_rx.recv_timeout(Duration::from_secs(5));
            let during = journal.lookup("teardown").unwrap();
            let premature = relay.poll_finished();
            release_tx.send(()).unwrap();
            assert!(retried.is_ok(), "{kind}: UNKNOWN teardown was abandoned");
            assert_eq!(during.phase, super::super::super::journal::ReceiptPhase::Effect);
            assert!(premature.is_empty(), "unknown must retain its active lifecycle owner");
            assert_eq!(done(&relay, "teardown").state, OperationState::Succeeded);
            assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 2);
            assert_eq!(runtime.query_sandbox("sbx", None, None).unwrap(), if kind == "sandbox.kill" { None } else { Some(sandbox_protocol::SandboxLifecycleState::Stopped) });
        }
    }

    #[test]
    fn e43_restart_resumes_unknown_teardown_but_never_superseded_authority() {
        for kind in ["sandbox.kill", "sandbox.stop"] {
            let dir = tempfile::tempdir().unwrap();
            let binding = TransportBindingV11 { server: "wss://example".into(), host_owner_id: "owner".into(), host_id: "host".into() };
            let fake = FakeRuntime::new();
        fake.fixture_root().unwrap();
            for id in ["sbx", "newer"] { fake.create_fixture(&CreateSandboxRequest::for_test(id, &format!("{id}-create"))).unwrap(); }
            {
                let journal = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap();
                for (id, sandbox) in [("teardown", "sbx"), ("obsolete", "newer")] {
                    let mut d = dispatch(id, kind, 2);
                    d.sandbox_id = sandbox.into();
                    journal.record_fixture_intent(&intent_from_dispatch(&journal, &binding, &d)).unwrap();
                    journal.record_result(id, OperationState::UnknownOutcome, None, Some(SandboxErrorCode::UnknownOutcome), None).unwrap();
                }
                let mut later = dispatch("later", "sandbox.reconnect", 3);
                later.sandbox_id = "newer".into();
                journal.record_fixture_intent(&intent_from_dispatch(&journal, &binding, &later)).unwrap();
            }
            let journal = Arc::new(crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap());
            let runtime = fake.clone();
            let relay = RelaySupervisor::start(Arc::new(fake), journal.clone(), HostAuthority::default(),
                #[cfg(target_os = "linux")] None,
            );
            // The same entry point is used after hello and on later heartbeats.
            relay.resume_teardowns(&journal, &binding).unwrap();
            assert_eq!(done(&relay, "teardown").state, OperationState::Succeeded);
            relay.resume_teardowns(&journal, &binding).unwrap();
            assert!(relay.poll_finished().is_empty());
            assert_eq!(runtime.query_sandbox("sbx", None, None).unwrap(), if kind == "sandbox.kill" { None } else { Some(sandbox_protocol::SandboxLifecycleState::Stopped) });
            assert_eq!(runtime.query_sandbox("newer", None, None).unwrap(), Some(sandbox_protocol::SandboxLifecycleState::Ready));
            assert_eq!(journal.lookup("obsolete").unwrap().state, OperationState::UnknownOutcome);
        }
    }


    fn probe_setup(ids: &[String]) -> (tempfile::TempDir, TransportBindingV11, Arc<HostJournal>, FakeRuntime, mpsc::Receiver<()>, mpsc::Sender<()>) {
        probe_setup_gated(ids, 1)
    }

    /// Like `probe_setup`, but the first `gates` destroys each block.
    fn probe_setup_gated(ids: &[String], gates: usize) -> (tempfile::TempDir, TransportBindingV11, Arc<HostJournal>, FakeRuntime, mpsc::Receiver<()>, mpsc::Sender<()>) {
        let dir = tempfile::tempdir().unwrap();
        let binding = TransportBindingV11 { server: "wss://example".into(), host_owner_id: "owner".into(), host_id: "host".into() };
        let journal = Arc::new(crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap());
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let release_rx = Mutex::new(release_rx);
        let remaining = Arc::new(std::sync::atomic::AtomicUsize::new(gates));
        let fake = FakeRuntime::new().with_lifecycle_hook(move |stage| {
            if stage == "destroy"
                && remaining
                    .try_update(std::sync::atomic::Ordering::SeqCst, std::sync::atomic::Ordering::SeqCst, |n| n.checked_sub(1))
                    .is_ok()
            {
                entered_tx.send(()).unwrap();
                let _ = release_rx.lock().unwrap().recv_timeout(Duration::from_secs(20));
            }
            Ok(())
        });
        fake.fixture_root().unwrap();
        for id in ids { fake.create_fixture(&CreateSandboxRequest::for_test(id, &format!("create-{id}"))).unwrap(); }
        (dir, binding, journal, fake, entered_rx, release_tx)
    }

    #[test]
    fn probe_bdc_resume_saturates_urgent_queue_and_refuses_fresh_kill() {
        let mut ids: Vec<String> = (0..16).map(|i| format!("s{i}")).collect();
        ids.push("blocker".into());
        ids.push("fresh".into());
        let (_dir, binding, journal, fake, entered, release) = probe_setup(&ids);
        let authority = HostAuthority::default();
        let relay = RelaySupervisor::start(Arc::new(fake), journal.clone(), authority.clone(),
            #[cfg(target_os = "linux")] None,
        );
        let mut blocker = dispatch("blocker-kill", "sandbox.kill", 2);
        blocker.sandbox_id = "blocker".into();
        admit(&relay, &journal, &binding, &authority, blocker);
        entered.recv_timeout(Duration::from_secs(5)).unwrap_or_else(|e| panic!("runtime gate not reached: {e:?}; {:?}", relay.poll_finished()));
        let blocker_gate = Running { stage: "destroy".into(), release };
        for i in 0..16 {
            let mut d = dispatch(&format!("k{i}"), "sandbox.kill", 2);
            d.sandbox_id = format!("s{i}");
            d.sandbox_owner_id = "foreign-creator".into();
            journal.record_fixture_intent(&intent_from_dispatch(&journal, &binding, &d)).unwrap();
            journal.record_result(&format!("k{i}"), OperationState::UnknownOutcome, None, Some(SandboxErrorCode::UnknownOutcome), None).unwrap();
        }
        for _ in 0..20 { relay.resume_teardowns(&journal, &binding).unwrap(); }
        {
            let state = relay.lifecycle.state.lock().unwrap();
            assert_eq!(state.urgent_queued, 2);
            let resumed: Vec<_> = state.queues.values().flatten().filter(|job| job.resumed).collect();
            assert_eq!(resumed.len(), 2);
            assert!(resumed.iter().all(|job| job.dispatch.sandbox_owner_id == "foreign-creator"));
        }
        let mut fresh = dispatch("fresh-kill", "sandbox.kill", 2);
        fresh.sandbox_id = "fresh".into();
        journal.record_fixture_intent(&intent_from_dispatch(&journal, &binding, &fresh)).unwrap();
        authority.accept_dispatch("fresh-kill", "fresh", "sandbox.kill", 2, 1).unwrap();
        let submitted = relay.submit(fresh, "wssp-sbx-fresh".into(), None);
        eprintln!("PROBE fresh wire kill submit after resume: {:?}", submitted.as_ref().map_err(|e| e.to_string()));
        assert!(submitted.is_ok(), "fresh user kill refused because resumed retries filled the urgent queue");
        // Keep the reserved lane blocked until spare capacity completes the
        // fresh wire request ahead of every queued resumed teardown.
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut completed = Vec::new();
        while !completed.iter().any(|id| id == "fresh-kill") {
            completed.extend(relay.poll_finished().into_iter().map(|op| op.operation_id));
            assert!(Instant::now() < deadline, "fresh kill delayed behind resumes");
            std::thread::yield_now();
        }
        drop(blocker_gate);
        let fresh_at = completed.iter().position(|id| id == "fresh-kill").unwrap();
        assert!(!completed[..fresh_at].iter().any(|id| id.starts_with('k')),
            "resumed teardown ran before fresh wire kill: {completed:?}");
    }

    #[test]
    fn probe_bdc_shutdown_turns_queued_resumed_unknown_into_failed() {
        for known_unknown in [false, true] {
        let ids: Vec<String> = vec!["blocker".into(), "s0".into()];
        let (_dir, binding, journal, fake, entered, release) = probe_setup(&ids);
        let authority = HostAuthority::default();
        let relay = RelaySupervisor::start(Arc::new(fake), journal.clone(), authority.clone(),
            #[cfg(target_os = "linux")] None,
        );
        let mut blocker = dispatch("blocker-kill", "sandbox.kill", 2);
        blocker.sandbox_id = "blocker".into();
        admit(&relay, &journal, &binding, &authority, blocker);
        entered.recv_timeout(Duration::from_secs(5)).unwrap_or_else(|e| panic!("runtime gate not reached: {e:?}; {:?}", relay.poll_finished()));
        let mut d = dispatch("k0", "sandbox.kill", 2);
        d.sandbox_id = "s0".into();
        journal.record_fixture_intent(&intent_from_dispatch(&journal, &binding, &d)).unwrap();
        journal.record_effect("k0").unwrap();
        if known_unknown { journal.record_result("k0", OperationState::UnknownOutcome, None, Some(SandboxErrorCode::UnknownOutcome), None).unwrap(); }
        relay.resume_teardowns(&journal, &binding).unwrap();
        authority.shutdown();
        release.send(()).unwrap();
        drop(relay); // session end / disconnect / shutdown
        let receipt = journal.lookup("k0").unwrap();
        eprintln!("PROBE after shutdown: phase={:?} state={:?} code={:?}", receipt.phase, receipt.state, receipt.error_code);
        assert_eq!(receipt.state, OperationState::UnknownOutcome, "uncertain teardown was rewritten as a terminal result");
        assert_eq!(receipt.phase, super::super::super::journal::ReceiptPhase::Effect);
        }
    }

    #[test]
    fn d2_queued_intent_teardown_survives_shutdown_and_next_session_settles() {
        for kind in ["sandbox.kill", "sandbox.stop"] {
            let ids = vec!["blocker".into(), "s0".into()];
            let (_dir, binding, journal, fake, entered, release) = probe_setup(&ids);
            let runtime = fake.clone();
            let authority = HostAuthority::default();
            let relay = RelaySupervisor::start(Arc::new(fake), journal.clone(), authority.clone(),
                #[cfg(target_os = "linux")] None,
            );
            let mut blocker = dispatch("blocker-kill", "sandbox.kill", 2);
            blocker.sandbox_id = "blocker".into();
            admit(&relay, &journal, &binding, &authority, blocker);
            entered.recv_timeout(Duration::from_secs(5)).unwrap_or_else(|e| panic!("runtime gate not reached: {e:?}; {:?}", relay.poll_finished()));
            let mut teardown = dispatch("queued-intent", kind, 2);
            teardown.sandbox_id = "s0".into();
            journal.record_fixture_intent(&intent_from_dispatch(&journal, &binding, &teardown)).unwrap();
            let before = journal.lookup("queued-intent").unwrap().written_at_unix_ms;
            relay.resume_teardowns(&journal, &binding).unwrap();
            assert_eq!(relay.lifecycle.state.lock().unwrap().resumed_queued, 1);
            authority.shutdown();
            release.send(()).unwrap();
            drop(relay);
            let receipt = journal.lookup("queued-intent").unwrap();
            assert!(receipt.written_at_unix_ms > before, "deferred recovery must rotate its queue age");
            assert_eq!(receipt.phase, super::super::super::journal::ReceiptPhase::Intent);
            assert_eq!(receipt.state, OperationState::Accepted);
            let next = RelaySupervisor::start(Arc::new(runtime.clone()), journal.clone(), HostAuthority::default(),
                #[cfg(target_os = "linux")] None,
            );
            next.resume_teardowns(&journal, &binding).unwrap();
            assert_eq!(done(&next, "queued-intent").state, OperationState::Succeeded);
            assert_eq!(runtime.query_sandbox("s0", None, None).unwrap(),
                if kind == "sandbox.kill" { None } else { Some(sandbox_protocol::SandboxLifecycleState::Stopped) });
        }
    }

    #[test]
    fn d2_queued_wire_teardown_survives_shutdown_and_reopen() {
        for kind in ["sandbox.kill", "sandbox.stop"] {
            let ids = vec!["blocker".into(), "blocker2".into(), "s0".into()];
            let (dir, binding, journal, fake, entered, release) = probe_setup_gated(&ids, 2);
            let runtime = fake.clone();
            let authority = HostAuthority::default();
            // One ordinary lifecycle worker plus the reserved lane, both held
            // by gated teardowns, so the wire teardown below stays queued.
            let relay = RelaySupervisor::start_with_limits(Arc::new(fake), journal.clone(), authority.clone(),
                #[cfg(target_os = "linux")] None,
                CommandLimits { host: 1, per_sandbox: 1 },
            );
            for blocker_id in ["blocker", "blocker2"] {
                let mut blocker = dispatch(&format!("{blocker_id}-kill"), "sandbox.kill", 2);
                blocker.sandbox_id = blocker_id.into();
                admit(&relay, &journal, &binding, &authority, blocker);
                entered.recv_timeout(Duration::from_secs(5)).unwrap_or_else(|e| panic!("runtime gate not reached: {e:?}; {:?}", relay.poll_finished()));
            }
            let mut teardown = dispatch("queued-wire", kind, 2);
            teardown.sandbox_id = "s0".into();
            admit(&relay, &journal, &binding, &authority, teardown);
            {
                let queue = relay.lifecycle.state.lock().unwrap();
                assert_eq!(queue.urgent_queued, 1);
                assert_eq!(queue.resumed_queued, 0, "test must cover a wire dispatch");
            }
            authority.shutdown();
            release.send(()).unwrap();
            release.send(()).unwrap();
            drop(relay);
            drop(journal);
            // Reopen from disk: neither terminal FAILED nor volatile deferral
            // may replace the durable, unissued teardown obligation.
            let journal = Arc::new(crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap());
            let receipt = journal.lookup("queued-wire").unwrap();
            assert_eq!(receipt.phase, super::super::super::journal::ReceiptPhase::Intent);
            assert_eq!(receipt.state, OperationState::Accepted);
            assert!(receipt.error_code.is_none());
            assert_eq!(runtime.query_sandbox("s0", None, None).unwrap(),
                Some(sandbox_protocol::SandboxLifecycleState::Ready));
            let next = RelaySupervisor::start(Arc::new(runtime.clone()), journal.clone(), HostAuthority::default(),
                #[cfg(target_os = "linux")] None,
            );
            // Both blockers' teardowns resume too; the resumed lane holds at
            // most RESUME_CAP, so keep resuming until the wire teardown settles.
            let deadline = Instant::now() + Duration::from_secs(10);
            let settled = loop {
                next.resume_teardowns(&journal, &binding).unwrap();
                if let Some(op) = next.poll_finished().into_iter().find(|op| op.operation_id == "queued-wire") {
                    break op;
                }
                assert!(Instant::now() < deadline, "queued-wire never settled");
                thread::sleep(Duration::from_millis(5));
            };
            assert_eq!(settled.state, OperationState::Succeeded);
            assert_eq!(runtime.query_sandbox("s0", None, None).unwrap(),
                if kind == "sandbox.kill" { None } else { Some(sandbox_protocol::SandboxLifecycleState::Stopped) });
        }
    }

    #[test]
    fn d2_wire_teardown_live_authority_refusal_stays_failed() {
        for kind in ["sandbox.kill", "sandbox.stop"] {
            let ids = vec!["blocker".into(), "blocker2".into(), "s0".into()];
            let (_dir, binding, journal, fake, entered, release) = probe_setup_gated(&ids, 2);
            let authority = HostAuthority::default();
            // Hold both lifecycle lanes so the refusal is observed before any effect.
            let relay = RelaySupervisor::start_with_limits(Arc::new(fake), journal.clone(), authority.clone(),
                #[cfg(target_os = "linux")] None,
                CommandLimits { host: 1, per_sandbox: 1 },
            );
            for blocker_id in ["blocker", "blocker2"] {
                let mut blocker = dispatch(&format!("{blocker_id}-kill"), "sandbox.kill", 2);
                blocker.sandbox_id = blocker_id.into();
                admit(&relay, &journal, &binding, &authority, blocker);
                entered.recv_timeout(Duration::from_secs(5)).unwrap_or_else(|e| panic!("runtime gate not reached: {e:?}; {:?}", relay.poll_finished()));
            }
            let mut teardown = dispatch("refused-wire", kind, 2);
            teardown.sandbox_id = "s0".into();
            admit(&relay, &journal, &binding, &authority, teardown);
            // Revoke this operation without closing the session. A genuine
            // authority refusal remains a fresh C-26 failure, not recovery.
            assert_eq!(relay.lifecycle.state.lock().unwrap().urgent_queued, 1);
            authority.complete("refused-wire");
            release.send(()).unwrap();
            release.send(()).unwrap();
            assert_eq!(done(&relay, "refused-wire").state, OperationState::Failed);
            let receipt = journal.lookup("refused-wire").unwrap();
            assert_eq!(receipt.phase, super::super::super::journal::ReceiptPhase::Result);
            assert_eq!(receipt.state, OperationState::Failed);
            relay.resume_teardowns(&journal, &binding).unwrap();
            assert!(relay.poll_finished().iter().all(|op| op.operation_id != "refused-wire"));
        }
    }

    #[test]
    fn resumed_jobs_never_consume_wire_capacity_and_wire_runs_first() {
        let queue = Arc::new(CommandQueue::lifecycle(1));
        for (resumed, count) in [(true, 2), (false, 16)] {
            for n in 0..count {
                let id = format!("{resumed}-{n}");
                let mut d = dispatch(&id, "sandbox.kill", 2);
                d.sandbox_id = id.clone();
                queue.submit(DispatchJob { owner: None, first_allocation_attempt: false, tracked: TrackedCommands::default(), resumed, output: None, dispatch: d,
                    instance_name: id, upload: None }).unwrap();
            }
        }
        let (job, slot) = queue.next_for(Some(true)).unwrap();
        assert!(!job.resumed, "wire teardown must precede every queued resume");
        drop(slot);
    }

    struct Running {
        stage: String,
        release: mpsc::Sender<()>,
    }
    impl Drop for Running {
        fn drop(&mut self) {
            let _ = self.release.send(());
        }
    }
    #[derive(Default)]
    struct Observed {
        active: usize,
        peak: usize,
        stages: Vec<String>,
    }
    struct Fixture {
        started: mpsc::Receiver<Running>,
        relay: RelaySupervisor,
        journal: Arc<HostJournal>,
        authority: HostAuthority,
        binding: TransportBindingV11,
        observed: Arc<Mutex<Observed>>,
        _dir: tempfile::TempDir,
    }
    impl Fixture {
        fn new(cap: usize) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let binding = TransportBindingV11 {
                server: "wss://example".into(),
                host_owner_id: "owner".into(),
                host_id: "host".into(),
            };
            let journal = Arc::new(crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap());
            let observed = Arc::new(Mutex::new(Observed::default()));
            let counts = observed.clone();
            let (started_tx, started) = mpsc::channel();
            let fake = FakeRuntime::new().with_lifecycle_hook(move |stage| {
                {
                    let mut counts = counts.lock().unwrap();
                    counts.active += 1;
                    counts.peak = counts.peak.max(counts.active);
                    counts.stages.push(stage.into());
                }
                let (release, wait) = mpsc::channel();
                started_tx.send(Running { stage: stage.into(), release }).unwrap();
                let result = wait.recv_timeout(Duration::from_secs(60));
                counts.lock().unwrap().active -= 1;
                result.expect("lifecycle test gate was not released");
                Ok(())
            });
        fake.fixture_root().unwrap();
            let authority = HostAuthority::default();
            let relay = RelaySupervisor::start_with_limits(
                Arc::new(fake), journal.clone(), authority.clone(),
                #[cfg(target_os = "linux")]
                None,
                CommandLimits { host: cap, per_sandbox: 1 },
            );
            Self { started, relay, journal, authority, binding, observed, _dir: dir }
        }
        fn submit(&self, id: &str, sandbox: &str, kind: &str, generation: u64) {
            let mut d = dispatch(id, kind, generation);
            d.sandbox_id = sandbox.into();
            d.sandbox_owner_id = format!("creator-{sandbox}");
            self.journal.record_fixture_intent(&intent_from_dispatch(&self.journal, &self.binding, &d)).unwrap();
            self.authority.accept_dispatch(id, sandbox, kind, generation, 1).unwrap();
            self.relay.submit(d, format!("wssp-sbx-{sandbox}"), None).unwrap();
        }
        fn running(&self, stage: &str) -> Running {
            let running = self.started.recv_timeout(Duration::from_secs(5))
                .expect("lifecycle operation starts while earlier gates remain closed");
            assert_eq!(running.stage, stage);
            running
        }
        fn drain(&self, n: usize) -> Vec<FinishedOp> {
            let mut completed = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(10);
            while completed.len() < n {
                completed.extend(self.relay.poll_finished());
                assert!(Instant::now() < deadline, "missing lifecycle completions");
                thread::yield_now();
            }
            completed
        }
    }

    #[test]
    fn d2_stop_then_kill_waits_for_stop_and_destroy_wins() {
        let f = Fixture::new(1);
        f.submit("create-a", "a", "sandbox.create", 1);
        drop(f.running("create"));
        assert_eq!(f.drain(1)[0].state, OperationState::Succeeded);
        f.submit("stop-a", "a", "sandbox.stop", 2);
        let stop = f.running("stop");
        f.submit("kill-a", "a", "sandbox.kill", 3);
        {
            let state = f.relay.lifecycle.state.lock().unwrap();
            assert_eq!(state.active["a"], 1);
            assert_eq!(state.queues["a"].front().unwrap().dispatch.operation_id, "kill-a");
        }
        assert!(f.started.try_recv().is_err(), "kill raced the still-issued stop");
        drop(stop);
        drop(f.running("destroy"));
        let completed = f.drain(2);
        assert_ne!(completed.iter().find(|r| r.operation_id == "stop-a").unwrap().state, OperationState::Succeeded);
        let killed = completed.iter().find(|r| r.operation_id == "kill-a").unwrap();
        assert_eq!(killed.state, OperationState::Succeeded);
        assert_eq!(killed.payload.as_ref().unwrap()["state"], "deleted");
        assert_eq!(f.observed.lock().unwrap().stages, ["create", "stop", "destroy"]);
    }

    #[test]
    fn different_sandbox_creates_overlap_inside_fake_runtime() {
        let f = Fixture::new(2);
        f.submit("create-a", "a", "sandbox.create", 1);
        let a = f.running("create");
        f.submit("create-b", "b", "sandbox.create", 1);
        let b = f.running("create");
        assert_eq!(f.observed.lock().unwrap().active, 2);
        drop(a);
        drop(b);
        assert!(f.drain(2).iter().all(|r| r.state == OperationState::Succeeded));
    }

    #[test]
    fn same_sandbox_lifecycle_is_ordered_including_delete_racing_create() {
        for kind in ["sandbox.reconnect", "sandbox.stop", "sandbox.kill"] {
            let f = Fixture::new(2);
            f.submit("create-a", "a", "sandbox.create", 1);
            let a = f.running("create");
            f.submit("next-a", "a", kind, if kind == "sandbox.reconnect" { 1 } else { 2 });
            f.submit("create-b", "b", "sandbox.create", 1);
            let b = f.running("create");
            {
                let state = f.relay.lifecycle.state.lock().unwrap();
                assert_eq!(state.active["a"], 1);
                assert_eq!(state.queues["a"].front().unwrap().dispatch.operation_id, "next-a");
                assert_eq!(state.queued, 1);
            }
            assert_eq!(f.observed.lock().unwrap().stages, ["create", "create"]);
            drop(b);
            // Free B's worker while A still owns its key. A's queued job must
            // remain queued even though there is now host capacity.
            let b_done = done(&f.relay, "create-b");
            assert_eq!(b_done.state, OperationState::Succeeded);
            assert_eq!(f.relay.lifecycle.state.lock().unwrap().active["a"], 1);
            drop(a);
            if kind != "sandbox.reconnect" {
                // A's cancelled create never made a VM. Cleanup still runs
                // after it, and absence is a successful teardown proof.
                drop(f.running(if kind == "sandbox.kill" { "destroy" } else { "stop" }));
            }
            let completed = f.drain(2);
            assert_eq!(completed.iter().find(|r| r.operation_id == "next-a").unwrap().state,
                OperationState::Succeeded);
            assert_eq!(f.observed.lock().unwrap().active, 0);
        }
    }

    #[test]
    fn lifecycle_host_bound_holds_at_capacity_plus_one() {
        let f = Fixture::new(2);
        f.submit("a", "a", "sandbox.create", 1);
        let a = f.running("create");
        f.submit("b", "b", "sandbox.create", 1);
        let b = f.running("create");
        f.submit("c", "c", "sandbox.create", 1);
        {
            let state = f.relay.lifecycle.state.lock().unwrap();
            assert_eq!(state.active.values().sum::<usize>(), 2);
            assert_eq!(state.queued, 1);
        }
        assert_eq!(f.observed.lock().unwrap().active, 2);
        drop(a);
        let c = f.running("create");
        assert_eq!(f.observed.lock().unwrap().peak, 2);
        drop(b);
        drop(c);
        assert!(f.drain(3).iter().all(|r| r.state == OperationState::Succeeded));
    }

    #[test]
    fn reserved_cleanup_progresses_when_create_pool_and_queue_are_full() {
        let f = Fixture::new(2);
        f.submit("a", "a", "sandbox.create", 1);
        let a = f.running("create");
        f.submit("b", "b", "sandbox.create", 1);
        let b = f.running("create");
        for n in 0..QUEUE_CAP {
            f.submit(&format!("queued{n}"), &format!("q{n}"), "sandbox.create", 1);
        }
        f.submit("stop", "other", "sandbox.stop", 2);
        let stop = f.running("stop");
        assert_eq!(f.observed.lock().unwrap().active, 3);
        drop(stop);
        assert_eq!(done(&f.relay, "stop").state, OperationState::Succeeded);
        f.authority.shutdown();
        drop(a);
        drop(b);
        assert!(f.drain(QUEUE_CAP + 2).iter().all(|r| r.state != OperationState::Succeeded));
        assert!(f.started.try_recv().is_err());
    }

    #[test]
    fn shutdown_revokes_concurrent_creates_drains_queue_and_joins_workers() {
        let f = Fixture::new(2);
        f.submit("a", "a", "sandbox.create", 1);
        let a = f.running("create");
        f.submit("b", "b", "sandbox.create", 1);
        let b = f.running("create");
        f.submit("c", "c", "sandbox.create", 1);
        let Fixture { mut relay, started, journal, authority, observed, _dir, .. } = f;
        let queue = relay.lifecycle.clone();
        let shutdown = thread::spawn(move || {
            relay.shutdown_workers();
            assert!(relay.workers.is_empty(), "shutdown detached a lifecycle worker");
        });
        {
            let mut state = queue.state.lock().unwrap();
            while !state.closed {
                state = queue.ready.wait(state).unwrap();
            }
        }
        assert!(authority.accept_stream("a", 1, 1).is_err());
        assert!(authority.accept_stream("b", 1, 1).is_err());
        drop(a);
        drop(b);
        shutdown.join().unwrap();
        assert!(started.try_recv().is_err(), "queued create reached runtime after shutdown");
        assert_eq!(observed.lock().unwrap().stages, ["create", "create"]);
        assert!(queue.state.lock().unwrap().active.is_empty());
        for id in ["a", "b", "c"] {
            assert_ne!(journal.lookup(id).unwrap().state, OperationState::Succeeded);
        }
        assert_eq!(Arc::strong_count(&queue), 1);
        drop(journal);
        drop(_dir);
    }

    #[test]
    fn probe_bbc_stop_behind_queued_renew_is_not_starved_by_create_pool() {
        let f = Fixture::new(1);
        f.submit("create-a", "a", "sandbox.create", 1);
        let a = f.running("create");
        // Earlier ordinary work for x (revoked by the stop's admission).
        f.submit("renew-x", "x", "sandbox.lease.renew", 1);
        f.submit("stop-x", "x", "sandbox.stop", 2);
        // Base: urgent lane ran stop immediately. Expect stop to start while
        // unrelated create-a still occupies the only ordinary slot.
        let got = f.started.recv_timeout(Duration::from_secs(3));
        let started = got.is_ok();
        if let Ok(running) = &got { assert_eq!(running.stage, "stop"); }
        drop(got);
        drop(a);
        assert!(started, "stop-x starved behind ordinary pool held by unrelated create");
        let finished = f.drain(3);
        assert_eq!(finished.iter().find(|r| r.operation_id == "stop-x").unwrap().state, OperationState::Succeeded);
        assert_ne!(finished.iter().find(|r| r.operation_id == "renew-x").unwrap().state, OperationState::Succeeded);
        assert!(!f.observed.lock().unwrap().stages.iter().any(|s| s == "renew"));
    }
    #[test]
    fn urgent_cleanup_does_not_consume_ordinary_capacity() {
        let f = Fixture::new(1);
        f.submit("stop-x", "x", "sandbox.stop", 2);
        let stop = f.running("stop");
        f.submit("create-a", "a", "sandbox.create", 1);
        let create = f.running("create");
        assert_eq!(f.observed.lock().unwrap().active, 2);
        assert_eq!(f.relay.lifecycle.state.lock().unwrap().ordinary_active, 1);
        drop(stop);
        drop(create);
        assert!(f.drain(2).iter().all(|r| r.state == OperationState::Succeeded));
    }

    #[test]
    fn parallel_kills_of_different_sandboxes_run_concurrently() {
        // Reserved lane + spare ordinary lifecycle workers: four teardowns of
        // four sandboxes are all inside the runtime at once, not serialized
        // behind the single reserved worker.
        let f = Fixture::new(4);
        for sandbox in ["a", "b", "c", "d"] {
            f.submit(&format!("kill-{sandbox}"), sandbox, "sandbox.kill", 2);
        }
        let running: Vec<_> = (0..4).map(|_| f.running("destroy")).collect();
        assert_eq!(f.observed.lock().unwrap().active, 4, "teardowns serialized");
        drop(running);
        assert!(f.drain(4).iter().all(|r| r.state == OperationState::Succeeded));
        assert_eq!(f.observed.lock().unwrap().peak, 4);
    }

    #[test]
    fn kill_still_runs_when_every_ordinary_lifecycle_worker_is_busy() {
        let f = Fixture::new(2);
        f.submit("a", "a", "sandbox.create", 1);
        let a = f.running("create");
        f.submit("b", "b", "sandbox.create", 1);
        let b = f.running("create");
        // Ordinary workers are all held by creates; the reserved lane runs the kill.
        f.submit("kill-x", "x", "sandbox.kill", 2);
        let first = f.running("destroy");
        f.submit("kill-y", "y", "sandbox.kill", 2);
        assert!(f.started.recv_timeout(Duration::from_millis(200)).is_err(),
            "second kill took capacity that does not exist");
        drop(first);
        // The reserved lane frees and takes the queued kill while both creates still run.
        let second = f.running("destroy");
        assert_eq!(f.observed.lock().unwrap().active, 3);
        drop(second);
        drop(a);
        drop(b);
        assert!(f.drain(4).iter().all(|r| r.state == OperationState::Succeeded));
    }

    #[test]
    fn same_sandbox_teardowns_never_overlap_on_spill_workers() {
        let f = Fixture::new(4);
        f.submit("stop-a", "a", "sandbox.stop", 2);
        let stop = f.running("stop");
        f.submit("kill-a", "a", "sandbox.kill", 3);
        assert!(f.started.recv_timeout(Duration::from_millis(200)).is_err(),
            "a spare ordinary worker ran a second lifecycle job for the same sandbox");
        drop(stop);
        drop(f.running("destroy"));
        f.drain(2);
        assert_eq!(f.observed.lock().unwrap().peak, 1);
    }

}
