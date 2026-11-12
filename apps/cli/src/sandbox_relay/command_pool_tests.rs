mod command_pool {
    use super::*;

    struct Running {
        id: String,
        permit: Arc<RuntimePermit>,
        release: mpsc::Sender<()>,
    }
    impl Running {
        fn finish(self) {
            self.release.send(()).unwrap();
        }
    }
    impl Drop for Running {
        fn drop(&mut self) {
            // A failed assertion must release the gate before relay teardown.
            let _ = self.release.send(());
        }
    }
    #[derive(Default)]
    struct Observed {
        active: HashMap<String, usize>,
        peak_host: usize,
        peak_sandbox: usize,
    }
    struct Fixture {
        // Drop unclaimed Running gates before joining workers on assertion failure.
        started: mpsc::Receiver<Running>,
        relay: RelaySupervisor,
        journal: Arc<HostJournal>,
        authority: HostAuthority,
        binding: TransportBindingV11,
        observed: Arc<Mutex<Observed>>,
        _dir: tempfile::TempDir,
    }
    impl Fixture {
        fn new(host: usize, per_sandbox: usize) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let binding = TransportBindingV11 {
                server: "wss://example".into(),
                host_owner_id: "owner".into(),
                host_id: "host".into(),
            };
            let journal = Arc::new(crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap());
            let fake = FakeRuntime::new();
        fake.fixture_root().unwrap();
            for id in ["a", "b", "c"] {
                fake.create_fixture(&CreateSandboxRequest::for_test(id, id))
                    .unwrap();
            }
            let (started_tx, started) = mpsc::channel();
            let observed = Arc::new(Mutex::new(Observed::default()));
            let counts = observed.clone();
            let hook: CommandHook = Arc::new(move |request, permit| {
                {
                    let mut counts = counts.lock().unwrap();
                    *counts.active.entry(request.sandbox_id.clone()).or_default() += 1;
                    counts.peak_host = counts.peak_host.max(counts.active.values().sum());
                    counts.peak_sandbox = counts
                        .peak_sandbox
                        .max(counts.active.values().copied().max().unwrap());
                }
                let (release, wait) = mpsc::channel();
                started_tx
                    .send(Running {
                        id: request.operation_id.clone(),
                        permit: permit.clone(),
                        release,
                    })
                    .unwrap();
                // A channel gate is the proof: the command cannot finish until
                // the test releases it. Journal fsyncs for later submissions may
                // take arbitrarily long; they must not release this gate.
                // Running::drop also releases it during assertion teardown.
                // This generous timeout is only a hang guard for plain cargo
                // test; channel release remains the admission proof.
                let released = wait.recv_timeout(Duration::from_secs(60));
                *counts
                    .lock()
                    .unwrap()
                    .active
                    .get_mut(&request.sandbox_id)
                    .unwrap() -= 1;
                released.expect("test command gate was not released within 60 seconds");
                permit.admit().map(|_| ())
            });
            let (entered, _) = mpsc::sync_channel(1);
            let (_, release) = mpsc::channel();
            let (cancelled, _) = mpsc::channel();
            let runtime = Arc::new(GatedRuntime {
                inner: Arc::new(fake),
                kind: "unused",
                entered,
                release: Arc::new(Mutex::new(release)),
                cancelled,
                timeout: false,
                permit: None,
                command_hook: Some(hook),
            });
            let authority = HostAuthority::default();
            let relay = RelaySupervisor::start_with_limits(
                runtime,
                journal.clone(),
                authority.clone(),
                #[cfg(target_os = "linux")]
                None,
                CommandLimits { host, per_sandbox },
            );
            Self {
                relay,
                journal,
                authority,
                binding,
                started,
                observed,
                _dir: dir,
            }
        }
        fn submit(&self, id: &str, sandbox: &str) {
            let mut request = dispatch(id, "command.run", 1);
            request.sandbox_id = sandbox.into();
            request.sandbox_owner_id = format!("creator-{sandbox}");
            admit(
                &self.relay,
                &self.journal,
                &self.binding,
                &self.authority,
                request,
            );
        }
        fn running(&self, id: &str) -> Running {
            let running = self
                .started
                .recv_timeout(Duration::from_secs(3))
                .expect("command starts with capacity available");
            assert_eq!(running.id, id);
            running
        }
    }

    #[test]
    fn a_long_command_in_one_sandbox_does_not_delay_another_sandbox() {
        let f = Fixture::new(16, 8);
        f.submit("a-long", "a");
        let a = f.running("a-long");
        f.submit("b-echo", "b");
        let b = f.started.recv_timeout(Duration::from_secs(3));
        let Ok(b) = b else {
            // Restore progress before failing under the single-worker fault:
            // even the negative test must join its workers without leaking.
            a.finish();
            f.running("b-echo").finish();
            panic!("B did not start while A was still gated");
        };
        assert_eq!(b.id, "b-echo");
        b.finish();
        assert_eq!(done(&f.relay, "b-echo").state, OperationState::Succeeded);
        assert_eq!(f.observed.lock().unwrap().active["a"], 1);
        assert!(!a.permit.is_cancelled());
        a.finish();
        assert_eq!(done(&f.relay, "a-long").state, OperationState::Succeeded);
    }

    #[test]
    fn per_sandbox_cap_and_host_cap_are_enforced() {
        let f = Fixture::new(3, 2);
        f.submit("a0", "a");
        let a0 = f.running("a0");
        f.submit("a1", "a");
        let a1 = f.running("a1");
        f.submit("a2", "a");
        // A is capped, but B must still get the spare host slot.
        f.submit("b0", "b");
        let b0 = f.running("b0");
        f.submit("a3", "a");
        f.submit("b1", "b");
        f.submit("c0", "c");
        {
            let state = f.relay.commands.state.lock().unwrap();
            assert_eq!(state.active.values().sum::<usize>(), 3);
            assert_eq!(state.active["a"], 2);
            assert_eq!(state.queued, 4);
        }
        a0.finish();
        let a2 = f.running("a2");
        b0.finish();
        let b1 = f.running("b1");
        a1.finish();
        let c0 = f.running("c0");
        a2.finish();
        let a3 = f.running("a3");
        b1.finish();
        c0.finish();
        a3.finish();
        // Drain all completions before checking observed peaks.
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut completed = 0;
        while completed < 7 {
            completed += f.relay.poll_finished_consumed().len();
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
        let observed = f.observed.lock().unwrap();
        assert_eq!(observed.peak_host, 3);
        assert_eq!(observed.peak_sandbox, 2);
        assert!(observed.active.values().all(|n| *n == 0));
    }

    #[test]
    fn fair_round_robin_across_sandboxes() {
        let f = Fixture::new(1, 1);
        f.submit("a0", "a");
        let a0 = f.running("a0");
        for n in 1..=10 {
            f.submit(&format!("a{n}"), "a");
        }
        f.submit("b0", "b");
        a0.finish();
        f.running("a1").finish();
        // Only one queued A command may precede B, despite A's backlog.
        f.running("b0").finish();
        for n in 2..=10 {
            f.running(&format!("a{n}")).finish();
        }
    }

    #[test]
    fn stop_and_kill_revoke_running_and_queued_commands_without_affecting_b() {
        for kind in ["sandbox.stop", "sandbox.kill"] {
            let f = Fixture::new(3, 2);
            f.submit("a0", "a");
            let a0 = f.running("a0");
            f.submit("a1", "a");
            let a1 = f.running("a1");
            f.submit("a2", "a");
            f.submit("a3", "a");
            f.submit("b0", "b");
            let b0 = f.running("b0");
            let mut stop = dispatch("stop", kind, 2);
            stop.sandbox_id = "a".into();
            stop.sandbox_owner_id = "creator-a".into();
            admit(&f.relay, &f.journal, &f.binding, &f.authority, stop);
            // Stop completes while all three command slots are gated.
            let finished = done(&f.relay, "stop");
            assert_eq!(finished.state, OperationState::Succeeded, "{kind}: {finished:?}");
            assert!(a0.permit.is_cancelled());
            assert!(a1.permit.is_cancelled());
            assert!(!b0.permit.is_cancelled());
            a0.finish();
            a1.finish();
            b0.finish();
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut completed = HashMap::new();
            while completed.len() < 5 {
                for done in f.relay.poll_finished_consumed() {
                    completed.insert(done.operation_id.clone(), done);
                }
                assert!(Instant::now() < deadline);
                thread::yield_now();
            }
            assert_eq!(completed["b0"].state, OperationState::Succeeded);
            for id in ["a0", "a1", "a2", "a3"] {
                assert_ne!(completed[id].state, OperationState::Succeeded);
            }
            assert!(
                f.started.try_recv().is_err(),
                "queued A commands reached the runtime"
            );
            assert_eq!(
                f.journal.lookup("a2").unwrap().error_code,
                Some(SandboxErrorCode::Cancelled.into())
            );
        }
    }

    #[test]
    fn shutdown_with_commands_running_joins_every_pool_thread() {
        let f = Fixture::new(3, 2);
        f.submit("a0", "a");
        let a0 = f.running("a0");
        f.submit("a1", "a");
        let a1 = f.running("a1");
        f.submit("b0", "b");
        let b0 = f.running("b0");
        f.submit("a2", "a");
        let Fixture {
            relay,
            started,
            journal,
            _dir,
            ..
        } = f;
        let queue = relay.commands.clone();
        let shutdown = thread::spawn(move || {
            let mut relay = relay;
            // 3 commands + 3 lifecycle + urgent + 4 ordinary + 2 signal
            // + reserved kill + storage health, observation and control lanes.
            assert_eq!(relay.workers.len(), 17);
            relay.shutdown_workers();
            assert!(relay.workers.is_empty(), "shutdown detached a worker");
        });
        let deadline = Instant::now() + Duration::from_secs(3);
        while !a0.permit.is_cancelled() || !b0.permit.is_cancelled() {
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
        a0.finish();
        a1.finish();
        b0.finish();
        shutdown.join().unwrap();
        // Every worker drops its receiver/queue Arc before it can be joined.
        assert_eq!(Arc::strong_count(&queue), 1);
        assert!(queue.state.lock().unwrap().active.is_empty());
        assert!(started.try_recv().is_err());
        drop(journal);
        drop(_dir);
    }

    #[test]
    fn queue_and_output_admission_remain_bounded_at_large_host_caps() {
        let f = Fixture::new(20, 8);
        let mut running = Vec::new();
        for (sandbox, count) in [("a", 8), ("b", 8), ("c", 4)] {
            for n in 0..count {
                let id = format!("{sandbox}{n}");
                f.submit(&id, sandbox);
                running.push(f.running(&id));
            }
        }
        // More than the old 17 output windows must be accepted.
        assert_eq!(f.relay.outputs.lock().unwrap().len(), 20);
        for n in 0..QUEUE_CAP {
            f.submit(&format!("queued{n}"), if n == QUEUE_CAP - 1 { "b" } else { "a" });
        }
        assert_eq!(f.relay.outputs.lock().unwrap().len(), 20 + QUEUE_CAP);
        let mut extra = dispatch("extra", "command.run", 1);
        extra.sandbox_id = "a".into();
        extra.sandbox_owner_id = "creator-a".into();
        f.journal.record_fixture_intent(&intent_from_dispatch(&f.journal, &f.binding, &extra)).unwrap();
        assert!(f.relay.submit(extra, "wssp-sbx-a".into(), None).is_err());
        assert_eq!(f.relay.commands.state.lock().unwrap().queued, QUEUE_CAP);
        // Shutdown invalidates queued work before any gated command releases.
        f.authority.shutdown();
        for command in running {
            command.finish();
        }
    }
    #[test]
    fn default_per_sandbox_limit_never_exceeds_the_host_limit() {
        for (host, expected) in [(1, 1), (3, 3), (16, 8), (256, 8)] {
            let limits = CommandLimits::new(host);
            assert_eq!(limits.host, host as usize);
            assert_eq!(limits.per_sandbox, expected);
        }
    }

    #[test]
    fn supervisor_derives_reservations_from_lineage_and_refuses_a_forged_creator() {
        let f = Fixture::new(3, 2);
        f.submit("a-running", "a");
        let running = f.running("a-running");
        let reservation = f.relay.reserve_upload("a").unwrap();
        assert_eq!(reservation.creator(), "creator-a");
        assert!(f.relay.reserve_upload("unbound").is_err());
        let mut spoof = dispatch("spoof", "command.run", 1);
        spoof.sandbox_id = "a".into();
        spoof.sandbox_owner_id = "creator-b".into();
        assert!(f.relay.submit(spoof, "wssp-sbx-a".into(), None).is_err());
        drop(reservation);
        running.finish();
        assert_eq!(done(&f.relay, "a-running").state, OperationState::Succeeded);
    }
    fn creator_job(id: &str, sandbox: &str, creator: &str) -> DispatchJob {
        let mut d = dispatch(id, "command.run", 1);
        d.sandbox_id = sandbox.into();
        d.sandbox_owner_id = creator.into();
        DispatchJob { owner: None,
            first_allocation_attempt: false, tracked: TrackedCommands::default(),
            resumed: false, output: None, dispatch: d,
            instance_name: format!("wssp-sbx-{sandbox}"), upload: None,
        }
    }
    #[test]
    fn one_creator_cannot_fill_all_waiting_jobs_across_sandboxes() {
        let queue = CommandQueue::new(CommandLimits::new(16));
        for i in 0..15 {
            queue.submit(creator_job(&format!("a-{i}"), &format!("a-{i}"), "a")).unwrap();
        }
        assert!(queue.submit(creator_job("a-full", "a-extra", "a")).is_err());
        queue.submit(creator_job("b-first", "b", "b")).unwrap();
        assert!(queue.submit(creator_job("c-full", "c", "c")).is_err());
        assert_eq!(queue.state.lock().unwrap().queued, 16);
    }
    #[test]
    fn creator_active_cap_spans_sandboxes_and_keeps_an_arrival_slot() {
        let queue = Arc::new(CommandQueue::new(CommandLimits::new(3)));
        for i in 0..3 {
            queue.submit(creator_job(&format!("a-{i}"), &format!("a-{i}"), "a")).unwrap();
        }
        let (a0, slot0) = queue.next().unwrap();
        let (a1, slot1) = queue.next().unwrap();
        assert_eq!((a0.dispatch.operation_id.as_str(), a1.dispatch.operation_id.as_str()), ("a-0", "a-1"));
        queue.submit(creator_job("b", "b", "b")).unwrap();
        let (b, slot_b) = queue.next().unwrap();
        assert_eq!(b.dispatch.operation_id, "b");
        assert_eq!(queue.state.lock().unwrap().creator_active["a"], 2);
        drop(slot0);
        let (a2, slot2) = queue.next().unwrap();
        assert_eq!(a2.dispatch.operation_id, "a-2");
        drop((slot1, slot2, slot_b));
        assert!(queue.state.lock().unwrap().creator_active.is_empty());
    }
    #[test]
    fn upload_reservations_count_toward_the_same_creator_queue_cap() {
        let queue = Arc::new(CommandQueue::fair(4, 4, 16));
        let reservations: Vec<_> = (0..15).map(|i| queue.reserve(&format!("a-{i}"), "a").unwrap()).collect();
        assert!(queue.reserve("a-extra", "a").is_err());
        let b = queue.reserve("b", "b").unwrap();
        assert!(queue.reserve("c", "c").is_err());
        let a = reservations.into_iter().next().unwrap();
        assert!(queue.submit_reserved(creator_job("spoof", &a.sandbox, "b"), Some(a)).is_err());
        drop(b);
        assert!(queue.state.lock().unwrap().reservations.is_empty());
        assert!(queue.state.lock().unwrap().reserved_creators.is_empty());
    }
    #[test]
    fn command_queue_rejects_the_seventeenth_waiting_job() {
        let queue = CommandQueue::new(CommandLimits::new(16));
        for n in 0..=QUEUE_CAP {
            let result = queue.submit(DispatchJob { owner: None, first_allocation_attempt: false,
                tracked: TrackedCommands::default(),
                resumed: false,
                dispatch: {
                    let mut d = dispatch(&format!("queued{n}"), "command.run", 1);
                    d.sandbox_owner_id = format!("creator-{n}");
                    d.sandbox_id = format!("sandbox-{n}");
                    d
                },
                instance_name: "wssp-sbx-sbx".into(),
                output: None,
                upload: None,
            });
            assert_eq!(result.is_ok(), n < QUEUE_CAP);
        }
        assert_eq!(queue.state.lock().unwrap().queued, QUEUE_CAP);
    }

    #[test]
    fn scheduler_handles_empty_turns_and_drains_nonempty_turns_before_closing() {
        let empty = Arc::new(CommandQueue::new(CommandLimits::new(2)));
        empty.close();
        assert!(empty.next().is_none());

        let queue = Arc::new(CommandQueue::new(CommandLimits::new(2)));
        for (id, sandbox) in [("a0", "a"), ("a1", "a"), ("b0", "b")] {
            let mut request = dispatch(id, "command.run", 1);
            request.sandbox_id = sandbox.into();
            request.sandbox_owner_id = format!("creator-{sandbox}");
            queue
                .submit(DispatchJob { owner: None, first_allocation_attempt: false,
                    tracked: TrackedCommands::default(),
                    resumed: false,
                    dispatch: request,
                    instance_name: format!("wssp-sbx-{sandbox}"),
                    output: None,
                    upload: None,
                })
                .unwrap();
        }
        queue.close();
        for expected in ["a0", "b0", "a1"] {
            let (job, slot) = queue
                .next()
                .expect("closed queue must drain its remaining turns");
            assert_eq!(job.dispatch.operation_id, expected);
            drop(slot);
        }
        assert!(queue.next().is_none());
        let state = queue.state.lock().unwrap();
        assert!(state.turns.is_empty());
        assert!(state.queues.is_empty());
        assert!(state.active.is_empty());
        assert_eq!(state.queued, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_supervised_exec_progresses_in_another_sandbox_while_a_is_gated() {
        use std::io::Write;
        struct Release(std::fs::File);
        impl Drop for Release {
            fn drop(&mut self) {
                let _ = self.0.write_all(b"release\n");
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("release-a");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        // Linux O_RDWR opens the FIFO without blocking and keeps a writer alive.
        let release = Release(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&fifo)
                .unwrap(),
        );
        let shim = dir.path().join("incus-shim");
        crate::sandbox_relay::test_support::install_executable(
            &shim,
            r#"#!/bin/sh
root=$(dirname "$0")
if [ "$1" = "--project" ]; then shift 2; fi
if [ "$1" = "--quiet" ]; then shift; fi
case "$1" in
  version) exit 0 ;;
  profile) printf '[{"name":"default","devices":{"root":{"type":"disk","path":"/","pool":"test"},"eth0":{"type":"nic","network":"test"}}}]'; exit 0 ;;
  query)
    case "$*" in *wssp-sbx-a*) sandbox=a ;; *) sandbox=b ;; esac
    printf '{"status":"Running","status_code":103,"type":"virtual-machine","config":{"user.flycockpit.sandbox_id":"%s","user.flycockpit.template_digest":"sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789","volatile.base_image":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"}}' "$sandbox"
    exit 0 ;;
  exec)
    instance=$2
    while [ "$#" -gt 0 ]; do
      case "$1" in
        -c) script=$2; shift 2 ;;
        wssp-run)
          rest=${script#*WSSP_PID }
          nonce=${rest%% *}
          printf 'WSSP_PID %s 4242\n' "$nonce" >&2
          if [ "$instance" = "wssp-sbx-a" ]; then
            touch "$root/started-a"
            read -r ignored < "$root/release-a"
          fi
          printf '\nWSSP_EXIT %s 0\n' "$nonce" >&2
          exit 0 ;;
        *) shift ;;
      esac
    done ;;
esac
exit 1
"#,
            0o700,
        );
        let runtime = IncusKvmRuntime::new(IncusConfig {
            binary: shim.to_string_lossy().into_owned(),
            project: "default".into(),
        })
        .unwrap();
        let exec = runtime.exec_supervisor();
        let binding = TransportBindingV11 {
            server: "wss://example".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        };
        let journal = Arc::new(crate::sandbox_relay::test_support::open_journal(dir.path().join("journal"), &binding).unwrap());
        let authority = HostAuthority::default();
        let relay = RelaySupervisor::start(
            Arc::new(runtime),
            journal.clone(),
            authority.clone(),
            Some(exec.clone()),
        );
        // Release the FIFO before relay teardown even if an assertion fails.
        let mut release = release;
        for sandbox in ["a", "b"] {
            let mut d = dispatch(sandbox, "command.run", 1);
            d.sandbox_id = sandbox.into();
            journal
                .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &d))
                .unwrap();
            authority
                .accept_dispatch(sandbox, sandbox, "command.run", 1, 1)
                .unwrap();
            relay
                .submit(d, format!("wssp-sbx-{sandbox}"), None)
                .unwrap();
            if sandbox == "a" {
                let deadline = Instant::now() + Duration::from_secs(3);
                while !dir.path().join("started-a").exists() {
                    let finished = relay.poll_finished();
                    assert!(finished.is_empty(), "A failed before gate: {finished:?}");
                    assert!(Instant::now() < deadline, "A never reached FIFO barrier");
                    thread::yield_now();
                }
            }
        }
        assert_eq!(done(&relay, "b").state, OperationState::Succeeded);
        assert!(
            exec.active_guest_pid("a").is_some(),
            "A must remain running until release"
        );
        release.0.write_all(b"release\n").unwrap();
        assert_eq!(done(&relay, "a").state, OperationState::Succeeded);
        let queue = relay.commands.clone();
        drop(relay);
        assert_eq!(Arc::strong_count(&queue), 1);
    }
}
