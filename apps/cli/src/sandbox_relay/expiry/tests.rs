use super::*;
#[cfg(test)]
use crate::sandbox_relay::test_support::FixtureRuntime;
use crate::sandbox_relay::{
    clock::{ClockSource, LeaseClock},
    journal::{TransportBindingV11, intent_from_dispatch},
    supervisor::RelaySupervisor,
};
use sandbox_protocol::{OperationDispatch, SandboxLifecycleState};
use sandbox_runtime::{CreateSandboxRequest, FakeRuntime};
use std::sync::{Mutex, atomic::AtomicU64, mpsc};
use std::time::Instant;

#[derive(Debug)]
struct TestClock {
    wall: AtomicU64,
    mono: AtomicU64,
}
impl ClockSource for TestClock {
    fn sample(&self) -> Result<(u64, u64)> {
        if self.wall.load(Ordering::SeqCst) == u64::MAX {
            bail!("clock unavailable");
        }
        Ok((
            self.wall.load(Ordering::SeqCst),
            self.mono.load(Ordering::SeqCst),
        ))
    }
}
fn wall() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
fn setup() -> (tempfile::TempDir, Arc<HostJournal>, Arc<TestClock>) {
    let dir = tempfile::tempdir().unwrap();
    let source = Arc::new(TestClock {
        wall: AtomicU64::new(wall()),
        mono: AtomicU64::new(0),
    });
    let mut j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
    j.clock = Arc::new(LeaseClock::new(source.clone()));
    (dir, Arc::new(j), source)
}
fn binding() -> TransportBindingV11 {
    TransportBindingV11 {
        server: "wss://expiry.test/ws/sandbox-host".into(),
        host_owner_id: "owner".into(),
        host_id: "host".into(),
    }
}
#[cfg(test)]
fn dispatch(j: &HostJournal, kind: &str, revision: u64, action: LeaseAction) -> OperationDispatch {
    let deadline = j.clock.now_ms().unwrap() + 1000;
    let mut value = serde_json::json!({"sandboxOwnerId":"owner", "operationId":format!("{}-{revision}",kind.replace('.',"-")), "sandboxId":"sbx", "generation":1, "attempt":1,
        "kind":kind, "idempotencyKey":format!("{}-{revision}",kind.replace('.',"-")), "bodyHash":"a".repeat(64),
        "incusFingerprint":CreateSandboxRequest::for_test("sbx", "key").template_digest,
        "lease":{"revision":revision,"deadlineUnixMs":deadline,"action":action,"expiryPolicy":"retry-force-60s"}});
    if matches!(kind, "sandbox.create" | "sandbox.reconnect") {
        value["cpuCount"] = serde_json::json!(1);
        value["memoryMiB"] = serde_json::json!(1024);
    }
    if matches!(
        kind,
        "sandbox.create" | "sandbox.reconnect" | "sandbox.stop" | "sandbox.kill"
    ) {
        value["allocation"] =
            serde_json::to_value(crate::sandbox_relay::test_support::allocation()).unwrap();
    }
    crate::sandbox_relay::test_support::current_fixture_dispatch(
        &serde_json::from_value(value).unwrap(),
    )
}
fn accept(j: &HostJournal, d: &OperationDispatch) {
    j.record_fixture_intent(&intent_from_dispatch(j, &binding(), d))
        .unwrap();
    j.accept_lease(d).unwrap();
}
fn seed(j: &HostJournal, fake: &FakeRuntime, action: LeaseAction) {
    let d = dispatch(j, "sandbox.create", 1, action);
    accept(j, &d);
    let mut req = CreateSandboxRequest::for_test("sbx", &d.idempotency_key);
    // The journal's lease runs on the test clock (deadline = setup's wall
    // sample + 1 s); the fake validates against the REAL wall clock, so a
    // loaded runner taking >1 s since `setup()` failed the seed itself. Seed
    // the VM under the dispatch's lease with the fixture's far deadline.
    req.lease = sandbox_protocol::HostLease {
        deadline_unix_ms: sandbox_protocol::HostLease::for_test().deadline_unix_ms,
        ..d.lease.unwrap()
    };
    fake.create_fixture(&req).unwrap();
}

#[test]
fn stop_worker_cannot_complete_an_upgraded_enforcement_loss_intent() {
    let (_dir, journal, clock) = setup();
    let (stop_entered, stopped) = mpsc::channel();
    let (release_stop, stop_gate) = mpsc::channel();
    let stop_gate = Mutex::new(stop_gate);
    let (kill_entered, killing) = mpsc::channel();
    let (release_kill, kill_gate) = mpsc::channel();
    let kill_gate = Mutex::new(kill_gate);
    let first = AtomicBool::new(true);
    let fake = FakeRuntime::new().with_lifecycle_hook(move |stage| {
        if stage == "stop" && first.swap(false, Ordering::SeqCst) {
            stop_entered.send(()).unwrap();
            stop_gate.lock().unwrap().recv().unwrap();
        }
        if stage == "destroy" {
            kill_entered.send(()).unwrap();
            kill_gate.lock().unwrap().recv().unwrap();
        }
        Ok(())
    });
    fake.fixture_root().unwrap();
    seed(&journal, &fake, LeaseAction::Stop);
    clock.mono.store(1001, Ordering::SeqCst);
    let expiry = ExpiryService::start(
        Arc::new(fake.clone()),
        journal.clone(),
        HostAuthority::with_journal(journal.clone()),
    );
    stopped.recv_timeout(Duration::from_secs(3)).unwrap();
    let stop_intent = journal.lease("sbx").unwrap();
    journal
        .settle_enforcement_loss(&stop_intent, sandbox_runtime::EnforcementLossStage::Prepare)
        .unwrap();
    release_stop.send(()).unwrap();
    // The old worker has returned, but the stronger worker has not destroyed.
    until(|| !expiry.failures().is_empty() || journal.lease("sbx").unwrap().expiry_complete);
    let pending = journal.lease("sbx").unwrap();
    assert!(
        !pending.expiry_complete && !pending.instance_absent,
        "stop-only completion is not destruction proof"
    );
    assert!(
        expiry.completions().is_empty(),
        "stale worker cannot publish a completion"
    );
    assert!(
        journal.finish_expiry(&stop_intent).is_err(),
        "shared boundary also rejects the old intent"
    );
    assert!(!journal.work_allowed("sbx", 2, "sandbox.reconnect"));
    let mut rearm = dispatch(&journal, "sandbox.reconnect", 2, LeaseAction::Stop);
    rearm.generation = 2;
    journal
        .record_fixture_intent(&intent_from_dispatch(&journal, &binding(), &rearm))
        .unwrap();
    assert!(
        journal.accept_lease(&rearm).is_err(),
        "old worker must not authorize rearming"
    );
    killing.recv_timeout(Duration::from_secs(3)).unwrap();
    assert!(!journal.lease("sbx").unwrap().expiry_complete);
    release_kill.send(()).unwrap();
    until(|| journal.lease("sbx").unwrap().expiry_complete);
    let done = journal.lease("sbx").unwrap();
    assert!(
        done.instance_absent && done.enforcement_loss,
        "upgraded worker completes actual destruction"
    );
    assert!(fake.query_sandbox("sbx", None, None).unwrap().is_none());
    // Published in memory only AFTER the durable settle (expiry.rs
    // `checkpoint`): the journal flag alone does not order this read.
    until(|| expiry.completions().contains_key("sbx"));
    assert_eq!(expiry.completions().get("sbx"), Some(&(1, 1)));
    assert!(
        !journal.work_allowed("sbx", 2, "sandbox.reconnect"),
        "destroyed loss arms never rearm as stopped VMs"
    );
    assert!(journal.accept_lease(&rearm).is_err());
}

#[test]
fn failed_loss_lease_persistence_retains_intent_and_retries_before_destruction() {
    let (dir, journal, _clock) = setup();
    let fake = FakeRuntime::new();
    fake.fixture_root().unwrap();
    seed(&journal, &fake, LeaseAction::Stop);
    let row = journal.lease("sbx").unwrap();
    // Real filesystem failure, not a mocked successful durability claim.
    let leases = dir.path().join("leases");
    let held = dir.path().join("held-leases");
    std::fs::rename(&leases, &held).unwrap();
    std::fs::write(&leases, "blocked").unwrap();
    assert!(
        journal
            .settle_enforcement_loss(&row, sandbox_runtime::EnforcementLossStage::Prepare)
            .is_err()
    );
    assert!(
        journal.lease("sbx").unwrap().enforcement_loss,
        "failed persistence retains the lease-backed retry intent"
    );
    let expiry = ExpiryService::start(
        Arc::new(fake.clone()),
        journal.clone(),
        HostAuthority::with_journal(journal.clone()),
    );
    until(|| !expiry.failures().is_empty());
    assert!(!journal.lease("sbx").unwrap().expiry_complete);
    assert_eq!(
        fake.query_sandbox("sbx", None, None).unwrap(),
        Some(SandboxLifecycleState::Stopped),
        "failed durable Prepare retries restrictive stop, never destruction"
    );
    std::fs::remove_file(&leases).unwrap();
    std::fs::rename(&held, &leases).unwrap();
    until(|| journal.lease("sbx").unwrap().expiry_complete);
    assert!(fake.query_sandbox("sbx", None, None).unwrap().is_none());
    let done = journal.lease("sbx").unwrap();
    assert!(done.instance_absent && !done.timer_expired);
    drop(expiry);
    drop(journal);
    // The old runtime keeps its installed loss hook, but the hook ended with
    // the service (it can no longer settle through this journal), so the
    // journal and its exclusive lock are released: a second daemon instance
    // opens the state directory while the old runtime handle still lives.
    let reopened =
        crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
    assert_eq!(reopened.lease("sbx").unwrap(), done);
    // Restart the daemon: the old runtime and its lifecycle authority are
    // discarded, exactly as process exit would discard them.
    let daemon = fake.restart_policy_reconciler().unwrap();
    drop(fake);
    assert!(daemon.query_sandbox("sbx", None, None).unwrap().is_none());
}

/// The runtime's loss hook holds the daemon state weakly: once the expiry
/// service (its only strong owner) is gone, the hook keeps no journal alive
/// and every later capture vetoes Prepare (no destruction authority).
#[test]
fn loss_hook_outliving_its_service_holds_no_journal_and_vetoes_prepare() {
    use sandbox_runtime::EnforcementLossLifecycle;
    let (_dir, journal, _clock) = setup();
    let fake = FakeRuntime::new();
    fake.fixture_root().unwrap();
    seed(&journal, &fake, LeaseAction::Stop);
    let state = Arc::new(super::LossLifecycleState {
        journal: journal.clone(),
        authority: HostAuthority::with_journal(journal.clone()),
        completions: Arc::default(),
    });
    let hook = super::LossLifecycle(Arc::downgrade(&state));
    let before = Arc::strong_count(&journal);
    drop(state);
    assert_eq!(
        Arc::strong_count(&journal),
        before - 2,
        "the hook keeps neither the journal nor the authority's journal"
    );
    let refused = hook.capture("sbx").prepare().unwrap_err();
    assert_eq!(refused.code, sandbox_protocol::SandboxErrorCode::Internal);
    assert!(
        !journal.lease("sbx").unwrap().enforcement_loss,
        "an ended hook settles nothing"
    );
}

#[test]
fn completed_loss_reopens_on_stopped_inventory_but_completed_stop_does_not() {
    for loss in [false, true] {
        let (_dir, journal, clock) = setup();
        let fake = FakeRuntime::new();
        fake.fixture_root().unwrap();
        seed(&journal, &fake, LeaseAction::Stop);
        if loss {
            let row = journal.lease("sbx").unwrap();
            journal
                .settle_enforcement_loss(&row, sandbox_runtime::EnforcementLossStage::Prepare)
                .unwrap();
        } else {
            clock.mono.store(1001, Ordering::SeqCst);
        }
        let row = journal.poll_expiry().unwrap().pop().unwrap();
        expire(&fake, &row, true).unwrap();
        journal.finish_expiry(&row).unwrap();
        check_inventory(
            &journal,
            &[sandbox_runtime::RuntimeInventoryEntry {
                sandbox_id: "sbx".into(),
                state: SandboxLifecycleState::Stopped,
                configured_size: sandbox_runtime::ConfiguredSize::Configured(
                    sandbox_protocol::VmSize::defaults().unwrap(),
                ),
            }],
        )
        .unwrap();
        let observed = journal.lease("sbx").unwrap();
        assert_eq!(
            observed.expiry_complete, !loss,
            "only ordinary completed stops may remain present"
        );
        assert!(!observed.instance_absent);
    }
}

#[test]
fn enforcement_loss_observation_keeps_its_captured_generation_across_runtime_io() {
    use crate::sandbox_relay::live_admission::LiveSandboxAdmission;
    use sandbox_protocol::OperationState;
    use sandbox_runtime::EnforcementLossStage::{Complete, Prepare};
    let (_dir, journal, _clock) = setup();
    let fake = FakeRuntime::new();
    fake.fixture_root().unwrap();
    seed(&journal, &fake, LeaseAction::Stop);
    let authority = HostAuthority::with_journal(journal.clone());
    let completions = Arc::new(Mutex::new(ExpiryCompletions::new()));
    let old =
        EnforcementLossSettlement::capture(journal.clone(), authority.clone(), completions.clone());
    let mut slots =
        LiveSandboxAdmission::new(1, crate::sandbox_relay::live_admission::test_capacity());
    slots
        .try_acquire(
            "sbx",
            "create",
            1,
            sandbox_protocol::VmSize::defaults().unwrap(),
        )
        .unwrap();
    slots.finish_allocation("sbx", "create", OperationState::Succeeded);
    // The daemon observation is still in flight while generation 2 is accepted.
    let mut next = dispatch(&journal, "sandbox.reconnect", 2, LeaseAction::Stop);
    next.generation = 2;
    accept(&journal, &next);
    slots
        .try_acquire(
            "sbx",
            &next.operation_id,
            2,
            sandbox_protocol::VmSize::defaults().unwrap(),
        )
        .unwrap();
    slots.finish_allocation("sbx", &next.operation_id, OperationState::Succeeded);
    let current = journal.lease("sbx").unwrap();
    authority
        .accept_dispatch("current-exec", "sbx", "command.run", 2, 1)
        .unwrap();
    for stage in [Prepare, Complete] {
        let err = old.checkpoint("sbx", stage).unwrap_err();
        assert_eq!(
            err.code,
            if stage == Prepare {
                sandbox_protocol::SandboxErrorCode::IdempotencyConflict
            } else {
                sandbox_protocol::SandboxErrorCode::Internal
            },
            "only stale Prepare asks the detector to capture and verify anew"
        );
        assert_eq!(journal.lease("sbx").unwrap(), current);
        assert!(completions.lock().unwrap().is_empty());
        assert!(authority.accept_stream("current-exec", 2, 1).is_ok());
    }
    assert!(!slots.release_expired("sbx", 1));
    assert_eq!(slots.held(), 1);
    // Independent current-generation loss has the inverse effect at the SAME
    // boundary: durable completion + authority revocation + local release.
    let new =
        EnforcementLossSettlement::capture(journal.clone(), authority.clone(), completions.clone());
    new.checkpoint("sbx", Prepare).unwrap();
    assert!(!journal.lease("sbx").unwrap().expiry_complete);
    assert!(completions.lock().unwrap().is_empty());
    assert!(authority.accept_stream("current-exec", 2, 1).is_err());
    new.checkpoint("sbx", Complete).unwrap();
    assert_eq!(completions.lock().unwrap().get("sbx"), Some(&(2, 2)));
    assert!(slots.release_expired("sbx", 2));
    slots
        .try_acquire(
            "replacement",
            "replacement",
            1,
            sandbox_protocol::VmSize::defaults().unwrap(),
        )
        .unwrap();
}

#[test]
fn enforcement_loss_recovery_destroys_even_a_stop_lease_without_waiting_for_its_timer() {
    let (dir, journal, clock) = setup();
    let fake = FakeRuntime::new();
    fake.fixture_root().unwrap();
    seed(&journal, &fake, LeaseAction::Stop);
    let row = journal.lease("sbx").unwrap();
    journal
        .settle_enforcement_loss(&row, sandbox_runtime::EnforcementLossStage::Prepare)
        .unwrap();
    drop(journal);
    // Crash after durable intent, before the runtime's delete/completion.
    let mut reopened =
        crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
    reopened.clock = Arc::new(LeaseClock::new(clock.clone()));
    let journal = Arc::new(reopened);
    let expiry = ExpiryService::start(
        Arc::new(fake.clone()),
        journal.clone(),
        HostAuthority::with_journal(journal.clone()),
    );
    until(|| journal.lease("sbx").unwrap().expiry_complete);
    assert_eq!(clock.mono.load(Ordering::SeqCst), 0, "no timer advance");
    assert!(fake.query_sandbox("sbx", None, None).unwrap().is_none());
    let complete = journal.lease("sbx").unwrap();
    assert!(complete.instance_absent && complete.enforcement_loss && !complete.timer_expired);
    assert_eq!(complete.lease, row.lease);
    // Published in memory only AFTER the durable settle (expiry.rs
    // `checkpoint`): the journal flag alone does not order this read.
    until(|| expiry.completions().contains_key("sbx"));
    assert_eq!(
        expiry.completions().get("sbx"),
        Some(&(row.generation, row.lease.revision))
    );
}
fn until(mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(4);
    while !f() {
        assert!(Instant::now() < deadline, "condition did not settle");
        thread::sleep(Duration::from_millis(5));
    }
}
#[test]
fn expiry_invalid_clock_expires_but_recovered_clock_can_rearm() {
    let (_dir, j, c) = setup();
    let fake = FakeRuntime::new();
    fake.fixture_root().unwrap();
    seed(&j, &fake, LeaseAction::Stop);
    let wall = c.wall.load(Ordering::SeqCst);
    c.wall.store(u64::MAX, Ordering::SeqCst);
    let expiry = ExpiryService::start(
        Arc::new(fake.clone()),
        j.clone(),
        HostAuthority::with_journal(j.clone()),
    );
    until(|| j.lease("sbx").unwrap().expiry_complete);
    assert_eq!(
        fake.query_sandbox("sbx", None, None).unwrap(),
        Some(SandboxLifecycleState::Stopped)
    );
    assert_ne!(j.lease("sbx").unwrap().observed_unix_ms, u64::MAX);
    c.wall.store(wall + 2000, Ordering::SeqCst);
    c.mono.store(2000, Ordering::SeqCst);
    let mut cold = dispatch(&j, "sandbox.reconnect", 2, LeaseAction::Stop);
    cold.generation = 2;
    accept(&j, &cold);
    assert!(!j.lease("sbx").unwrap().expired);
    assert!(j.work_allowed("sbx", 2, "command.run"));
    drop(expiry);
}
#[test]
fn expiry_clock_jumps_duplicate_ticks_and_renewal_preserve_the_effective_deadline() {
    let (_dir, j, c) = setup();
    let stops = Arc::new(AtomicU64::new(0));
    let count = stops.clone();
    let fake = FakeRuntime::new().with_lifecycle_hook(move |s| {
        if s == "stop" {
            count.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    });
    fake.fixture_root().unwrap();
    seed(&j, &fake, LeaseAction::Stop);
    let authority = HostAuthority::with_journal(j.clone());
    let expiry = ExpiryService::start(Arc::new(fake.clone()), j.clone(), authority.clone());
    c.mono.store(500, Ordering::SeqCst);
    c.wall.fetch_sub(100_000, Ordering::SeqCst);
    let renew = dispatch(&j, "sandbox.lease.renew", 2, LeaseAction::Stop);
    accept(&j, &renew);
    c.mono.store(1000, Ordering::SeqCst);
    assert!(
        j.poll_expiry().unwrap().is_empty(),
        "renewal must outlive old timer"
    );
    assert_eq!(
        fake.query_sandbox("sbx", None, None).unwrap(),
        Some(SandboxLifecycleState::Ready)
    );
    c.mono.store(1500, Ordering::SeqCst);
    until(|| j.lease("sbx").unwrap().expiry_complete);
    for _ in 0..3 {
        assert!(j.poll_expiry().unwrap().is_empty());
    }
    assert_eq!(
        stops.load(Ordering::SeqCst),
        1,
        "duplicate timer repeated a completed action"
    );
    assert_eq!(
        fake.query_sandbox("sbx", None, None).unwrap(),
        Some(SandboxLifecycleState::Stopped)
    );
    let later = dispatch(&j, "sandbox.lease.renew", 3, LeaseAction::Stop);
    j.record_fixture_intent(&intent_from_dispatch(&j, &binding(), &later))
        .unwrap();
    assert!(j.accept_lease(&later).is_err());
    drop(expiry);
    // A forward wall jump expires immediately, without waiting for elapsed time.
    let (_dir, j, c) = setup();
    let fake = FakeRuntime::new();
    fake.fixture_root().unwrap();
    seed(&j, &fake, LeaseAction::Destroy);
    let expiry = ExpiryService::start(
        Arc::new(fake.clone()),
        j.clone(),
        HostAuthority::with_journal(j.clone()),
    );
    c.wall.fetch_add(1001, Ordering::SeqCst);
    until(|| j.lease("sbx").unwrap().expiry_complete);
    assert_eq!(fake.query_sandbox("sbx", None, None).unwrap(), None);
    drop(expiry);
}
#[test]
fn expiry_revokes_streams_and_blocked_create_without_waiting_for_dispatch_workers() {
    for kind in ["sandbox.create", "command.run"] {
        let (_dir, j, c) = setup();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release = Mutex::new(release_rx);
        let fake = FakeRuntime::with_command_delay(Duration::from_secs(60)).with_lifecycle_hook(
            move |stage| {
                if stage == "create" && kind == "sandbox.create" {
                    entered_tx.send(()).unwrap();
                    release.lock().unwrap().recv().unwrap();
                }
                Ok(())
            },
        );
        fake.fixture_root().unwrap();
        let mut d = dispatch(&j, "sandbox.create", 1, LeaseAction::Stop);
        let authority = HostAuthority::with_journal(j.clone());
        if kind == "command.run" {
            seed(&j, &fake, LeaseAction::Stop);
            d = dispatch(&j, kind, 2, LeaseAction::Stop);
            d.argv = Some(vec!["true".into()]);
        }
        // Runtime admission validates REAL time while expiry uses our test
        // clock. Keep admission live regardless of disk latency, then move
        // the virtual clock past this exact deadline only after entry.
        let deadline = sandbox_protocol::HostLease::for_test().deadline_unix_ms;
        d.lease.as_mut().unwrap().deadline_unix_ms = deadline;
        let expired_mono = deadline - c.wall.load(Ordering::SeqCst) + 1;
        j.record_fixture_intent(&intent_from_dispatch(&j, &binding(), &d))
            .unwrap();
        authority
            .accept_dispatch(&d.operation_id, &d.sandbox_id, kind, 1, 1)
            .unwrap();
        let runtime: Arc<dyn SandboxRuntime> = Arc::new(fake.clone());
        let relay = RelaySupervisor::start(
            runtime.clone(),
            j.clone(),
            authority.clone(),
            #[cfg(target_os = "linux")]
            None,
        );
        let expiry = ExpiryService::start(runtime, j.clone(), authority.clone());
        relay
            .submit(d.clone(), "wssp-sbx-sbx".into(), None)
            .unwrap();
        if kind == "sandbox.create" {
            entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        } else {
            until(|| authority.runtime_registered(&d.operation_id));
        }
        c.mono.store(expired_mono, Ordering::SeqCst);
        until(|| j.lease("sbx").unwrap().expired);
        until(|| authority.accept_stream(&d.operation_id, 1, 1).is_err());
        if kind == "sandbox.create" {
            until(|| fake.query_sandbox("sbx", None, None).unwrap().is_none());
            assert!(
                !j.lease("sbx").unwrap().expiry_complete,
                "cannot finish while a late start could still return"
            );
            release_tx.send(()).unwrap();
        }
        until(|| {
            c.mono.fetch_add(100, Ordering::SeqCst);
            j.lease("sbx").unwrap().expiry_complete
        });
        assert!(!matches!(
            fake.query_sandbox("sbx", None, None).unwrap(),
            Some(SandboxLifecycleState::Ready)
        ));
        assert!(
            authority
                .accept_dispatch("late", "sbx", "file.put", 1, 1)
                .is_err()
        );
        assert!(authority.register_runtime(&d.operation_id, 1, 1).is_err());
        drop(expiry);
        drop(relay);
    }
}
#[test]
fn expiry_restart_replays_each_action_and_fences_ready_without_booting() {
    for action in [LeaseAction::Stop, LeaseAction::Destroy] {
        for stage in ["intent", "stop", "destroy", "complete"] {
            let (dir, j, c) = setup();
            let fake = FakeRuntime::new();
            fake.fixture_root().unwrap();
            seed(&j, &fake, action);
            c.mono.store(1001, Ordering::SeqCst);
            let row = j.poll_expiry().unwrap().pop().unwrap();
            if stage != "intent" {
                expire(
                    &fake,
                    &LeaseRecord {
                        lease: sandbox_protocol::HostLease {
                            action: LeaseAction::Stop,
                            ..row.lease.clone()
                        },
                        ..row.clone()
                    },
                    true,
                )
                .unwrap();
            }
            if matches!(stage, "destroy" | "complete") {
                expire(&fake, &row, true).unwrap();
            }
            if stage == "complete" {
                j.finish_expiry(&row).unwrap();
            } else if stage == "destroy" {
                j.inject_crash(crate::sandbox_relay::journal::CrashPoint::BeforeExpiryComplete);
                assert!(j.finish_expiry(&row).is_err());
            }
            drop(j);
            let reopened = Arc::new(
                crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap(),
            );
            let expiry = ExpiryService::start(
                Arc::new(fake.clone()),
                reopened.clone(),
                HostAuthority::with_journal(reopened.clone()),
            );
            expiry.reconcile().unwrap();
            assert!(reopened.lease("sbx").unwrap().expiry_complete);
            assert_eq!(
                fake.query_sandbox("sbx", None, None).unwrap(),
                if action == LeaseAction::Stop {
                    Some(SandboxLifecycleState::Stopped)
                } else {
                    None
                }
            );
            drop(expiry);
        }
    }
}
#[test]
fn expiry_failed_destroy_forces_stop_first_and_retries_with_bounded_backoff() {
    let (_dir, j, c) = setup();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let out = calls.clone();
    let failures = Arc::new(AtomicU64::new(1));
    let remaining = failures.clone();
    let fake = FakeRuntime::new().with_lifecycle_hook(move |s| {
        // The loss sweep's policy observation may land first; only the
        // lifecycle order matters here.
        if !s.starts_with("policy-observe") {
            out.lock().unwrap().push(s.to_string());
        }
        if s == "destroy" && remaining.swap(0, Ordering::SeqCst) > 0 {
            return Err(sandbox_runtime::RuntimeError::new(
                sandbox_protocol::SandboxErrorCode::UnknownOutcome,
                "injected delete failure",
            ));
        }
        Ok(())
    });
    fake.fixture_root().unwrap();
    seed(&j, &fake, LeaseAction::Destroy);
    let expiry = ExpiryService::start(
        Arc::new(fake.clone()),
        j.clone(),
        HostAuthority::with_journal(j.clone()),
    );
    c.mono.store(1001, Ordering::SeqCst);
    until(|| failures.load(Ordering::SeqCst) == 0);
    assert_eq!(
        fake.query_sandbox("sbx", None, None).unwrap(),
        Some(SandboxLifecycleState::Stopped),
        "failed delete must not leave a running VM"
    );
    assert!(!j.lease("sbx").unwrap().expiry_complete);
    let first = calls.lock().unwrap().clone();
    assert_eq!(&first[..3], &["create", "stop", "destroy"]);
    // Backoff uses Instant independently of wall jumps. Advance lease time while waiting.
    until(|| {
        c.mono.fetch_add(1000, Ordering::SeqCst);
        j.lease("sbx").unwrap().expiry_complete
    });
    assert_eq!(fake.query_sandbox("sbx", None, None).unwrap(), None);
    assert_eq!(
        calls
            .lock()
            .unwrap()
            .iter()
            .filter(|s| *s == "destroy")
            .count(),
        2
    );
    drop(expiry);
}

#[test]
fn expiry_restart_uses_renewed_journal_and_detects_completed_checkpoint_drift() {
    let (dir, j, c) = setup();
    let fake = FakeRuntime::new();
    fake.fixture_root().unwrap();
    seed(&j, &fake, LeaseAction::Stop);
    c.mono.store(500, Ordering::SeqCst);
    let renew = dispatch(&j, "sandbox.lease.renew", 2, LeaseAction::Stop);
    accept(&j, &renew);
    let wall = c.wall.load(Ordering::SeqCst);
    drop(j);
    let mut j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
    let source = Arc::new(TestClock {
        wall: AtomicU64::new(wall + 1100),
        mono: AtomicU64::new(0),
    });
    j.clock = Arc::new(LeaseClock::new(source.clone()));
    let j = Arc::new(j);
    let expiry = ExpiryService::start(
        Arc::new(fake.clone()),
        j.clone(),
        HostAuthority::with_journal(j.clone()),
    );
    expiry.reconcile().unwrap();
    assert_eq!(
        fake.query_sandbox("sbx", None, None).unwrap(),
        Some(SandboxLifecycleState::Ready),
        "boot-arm deadline must not replace journal renewal"
    );
    source.mono.store(401, Ordering::SeqCst);
    until(|| j.lease("sbx").unwrap().expiry_complete);
    drop(expiry);
    // Host reality can diverge from a completed checkpoint. Restart must repeat
    // the selected action and must never start the instance to reconcile it.
    let row = j.lease("sbx").unwrap();
    let req = sandbox_runtime::ReconnectSandboxRequest {
        vm_size: sandbox_protocol::VmSize::defaults().unwrap(),
        lease: sandbox_protocol::HostLease::for_test(),
        sandbox_id: "sbx".into(),
        instance_name: "wssp-sbx-sbx".into(),
        operation_id: "operator".into(),
        idempotency_key: "operator".into(),
        template_fingerprint: CreateSandboxRequest::for_test("sbx", "create").template_digest,
        guest: Default::default(),
        architecture: Some("x86_64".into()),
        egress_policy: None,
        egress_policy_hash: None,
        egress_admission: sandbox_runtime::egress::EgressAdmission::PERMITTED,
        guest_sudo: false,
    };
    fake.reconnect_fixture(&req).unwrap();
    assert!(row.expiry_complete);
    check_inventory(&j, &fake.sandbox_inventory().unwrap()).unwrap();
    assert!(!j.lease("sbx").unwrap().expiry_complete);
    let expiry = ExpiryService::start(
        Arc::new(fake.clone()),
        j.clone(),
        HostAuthority::with_journal(j.clone()),
    );
    expiry.reconcile().unwrap();
    assert_eq!(
        fake.query_sandbox("sbx", None, None).unwrap(),
        Some(SandboxLifecycleState::Stopped)
    );
    drop(expiry);
}
#[test]
fn expiry_arm_capacity_reserves_all_cleanup_slots_and_releases_confirmed_teardown() {
    let (_dir, j, _c) = setup();
    for i in 0..MAX_ACTIONS {
        let mut d = dispatch(&j, "sandbox.create", 1, LeaseAction::Stop);
        d.sandbox_id = format!("vm-{i}");
        d.operation_id = format!("create-{i}");
        d.idempotency_key = d.operation_id.clone();
        accept(&j, &d);
    }
    let mut extra = dispatch(&j, "sandbox.create", 1, LeaseAction::Stop);
    extra.operation_id = "extra".into();
    extra.idempotency_key = "extra".into();
    j.record_fixture_intent(&intent_from_dispatch(&j, &binding(), &extra))
        .unwrap();
    assert!(
        j.accept_lease(&extra)
            .unwrap_err()
            .to_string()
            .contains("expiry capacity")
    );
    let mut renew = dispatch(&j, "sandbox.lease.renew", 2, LeaseAction::Stop);
    renew.sandbox_id = "vm-0".into();
    accept(&j, &renew);
    let mut stop = dispatch(&j, "sandbox.stop", 3, LeaseAction::Stop);
    stop.sandbox_id = "vm-0".into();
    stop.generation = 2;
    j.record_fixture_intent(&intent_from_dispatch(&j, &binding(), &stop))
        .unwrap();
    j.record_result(
        &stop.operation_id,
        sandbox_protocol::OperationState::Succeeded,
        Some(serde_json::json!({"state":"stopped"})),
        None,
        None,
    )
    .unwrap();
    assert!(j.lease("vm-0").unwrap().expiry_complete);
    j.accept_lease(&extra).unwrap();
}

#[test]
fn expiry_failed_stop_keeps_the_latch_and_cannot_rearm_until_retry_succeeds() {
    let (_dir, j, c) = setup();
    let failed = Arc::new(AtomicBool::new(true));
    let flag = failed.clone();
    let calls = Arc::new(AtomicU64::new(0));
    let count = calls.clone();
    let fake = FakeRuntime::new().with_lifecycle_hook(move |s| {
        if s == "stop" {
            count.fetch_add(1, Ordering::SeqCst);
            if flag.load(Ordering::SeqCst) {
                return Err(sandbox_runtime::RuntimeError::new(
                    sandbox_protocol::SandboxErrorCode::UnknownOutcome,
                    "injected force failure",
                ));
            }
        }
        Ok(())
    });
    fake.fixture_root().unwrap();
    seed(&j, &fake, LeaseAction::Stop);
    let expiry = ExpiryService::start(
        Arc::new(fake.clone()),
        j.clone(),
        HostAuthority::with_journal(j.clone()),
    );
    c.mono.store(1001, Ordering::SeqCst);
    until(|| calls.load(Ordering::SeqCst) == 1);
    assert!(!j.lease("sbx").unwrap().expiry_complete);
    assert_eq!(
        fake.query_sandbox("sbx", None, None).unwrap(),
        Some(SandboxLifecycleState::Ready)
    );
    let mut cold = dispatch(&j, "sandbox.reconnect", 2, LeaseAction::Stop);
    cold.generation = 2;
    j.record_fixture_intent(&intent_from_dispatch(&j, &binding(), &cold))
        .unwrap();
    assert!(j.accept_lease(&cold).is_err());
    failed.store(false, Ordering::SeqCst);
    until(|| {
        c.mono.fetch_add(100, Ordering::SeqCst);
        j.lease("sbx").unwrap().expiry_complete
    });
    // Rearm with a fresh deadline after expiry completion. Old timer ticks
    // cannot run cleanup against this new generation.
    cold.lease.as_mut().unwrap().deadline_unix_ms = j.clock.now_ms().unwrap() + 1000;
    cold.operation_id = "fresh-cold".into();
    cold.idempotency_key = "fresh-cold".into();
    accept(&j, &cold);
    assert!(j.poll_expiry().unwrap().is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    drop(expiry);
}

#[test]
fn expiry_checkpoint_fault_closes_admission_but_keeps_enforcing_durable_intent() {
    let (dir, j, c) = setup();
    let fake = FakeRuntime::new();
    fake.fixture_root().unwrap();
    seed(&j, &fake, LeaseAction::Stop);
    j.inject_crash(crate::sandbox_relay::journal::CrashPoint::BeforeExpiry);
    c.mono.store(1001, Ordering::SeqCst);
    let expiry = ExpiryService::start(
        Arc::new(fake.clone()),
        j.clone(),
        HostAuthority::with_journal(j.clone()),
    );
    until(|| j.lease("sbx").unwrap().expiry_complete);
    assert!(j.io_failed());
    assert_eq!(
        fake.query_sandbox("sbx", None, None).unwrap(),
        Some(SandboxLifecycleState::Stopped)
    );
    let mut cold = dispatch(&j, "sandbox.reconnect", 2, LeaseAction::Stop);
    cold.generation = 2;
    j.record_fixture_intent(&intent_from_dispatch(&j, &binding(), &cold))
        .unwrap();
    assert!(j.accept_lease(&cold).is_err());
    drop(expiry);
    drop(j);
    // Restart the daemon (discarding the runtime's lifecycle authority, which
    // holds the old journal lock); the fake daemon survives.
    let daemon = fake.restart_policy_reconciler().unwrap();
    drop(fake);
    let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
    assert!(j.lease("sbx").unwrap().expiry_complete);
    assert_eq!(
        daemon.query_sandbox("sbx", None, None).unwrap(),
        Some(SandboxLifecycleState::Stopped)
    );
}

#[test]
fn expiry_restart_wall_rollback_cannot_extend_the_persisted_clock_floor() {
    let (dir, j, c) = setup();
    let fake = FakeRuntime::new();
    fake.fixture_root().unwrap();
    seed(&j, &fake, LeaseAction::Stop);
    let earlier = c.wall.load(Ordering::SeqCst) - 1;
    drop(j);
    let mut j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
    j.clock = Arc::new(LeaseClock::new(Arc::new(TestClock {
        wall: AtomicU64::new(earlier),
        mono: AtomicU64::new(0),
    })));
    let j = Arc::new(j);
    let expiry = ExpiryService::start(
        Arc::new(fake.clone()),
        j.clone(),
        HostAuthority::with_journal(j.clone()),
    );
    expiry.reconcile().unwrap();
    assert!(j.lease("sbx").unwrap().expiry_complete);
    assert_eq!(
        fake.query_sandbox("sbx", None, None).unwrap(),
        Some(SandboxLifecycleState::Stopped)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn expiry_incus_service_uses_durable_template_binding_and_retries_real_actions() {
    let (dir, j, c) = setup();
    let d = dispatch(&j, "sandbox.create", 1, LeaseAction::Destroy);
    accept(&j, &d);
    let mut renew = dispatch(&j, "sandbox.lease.renew", 2, LeaseAction::Destroy);
    renew.incus_fingerprint = None;
    accept(&j, &renew);
    assert_eq!(
        j.lease("sbx").unwrap().template_fingerprint,
        d.incus_fingerprint
    );
    let shim = dir.path().join("incus-double");
    crate::sandbox_relay::test_support::install_executable(
        &shim,
        r#"#!/usr/bin/env python3
import sys,json,pathlib
root=pathlib.Path(__file__).parent
args=sys.argv[1:]
if args[:1]==['--project']:args=args[2:]
cmd=args[0]
if cmd=='version':sys.exit(0)
if cmd=='profile':
 print(json.dumps([{'name':'default','devices':{'root':{'type':'disk','path':'/','pool':'test'},'nic':{'type':'nic','network':'test'}}}]))
 sys.exit(0)
if cmd=='storage' and args[1:4]==['volume','file','pull']:
 print('wssp-storage-v1\n'+'a'*32)
 sys.exit(0)
if cmd=='query':
 path=args[-1].split('?')[0]
 if path.startswith('/1.0/storage-pools/default'):
  if '/volumes/custom/' in path:
   value={'name':'wssp-pool-marker','type':'custom','content_type':'filesystem','config':{'user.wssp.storage-id':'a'*32}}
  elif path.endswith('/resources'):
   value={'space':{'total':2**40,'used':2**36}}
  elif '/volumes/virtual-machine/' in path:
   if (root/'deleted').exists():
    print(json.dumps({'type':'error','error_code':404,'error':'Not Found'}));sys.exit(1)
   value={'usage':{'total':32*2**30}} if path.endswith('/state') else {'name':'wssp-sbx-sbx','type':'virtual-machine','content_type':'block','config':{'size':'32GiB'}}
  elif path.endswith('/volumes'):
   value=[] if (root/'deleted').exists() else [{'name':'wssp-sbx-sbx','type':'virtual-machine','project':'default','config':{'size':'32GiB'}}]
  else:value={'driver':'dir','status':'Created'}
  print(json.dumps({'type':'sync','metadata':value}));sys.exit(0)
 if args[-1].startswith('/1.0/projects/'):
  print(json.dumps({'type':'sync','metadata':{'name':'default','config':{}}}))
  sys.exit(0)
 # Egress state of the running guest is unreadable, so the 2 s policy
 # reconciler stays inconclusive and never breach-halts it by force: the
 # stops logged below are the expiry worker's alone (C55 ordering). This
 # precedes the network 404s: an ABSENT network on a running guest is a
 # confirmed breach the reconciler halts at once by design (it did, in
 # 19 of 20 contended runs, and won the race 7 of 24 times).
 if not args[-1].startswith('/1.0/instances/') and not (root/'stopped').exists():
  print('Error: daemon unreachable',file=sys.stderr)
  sys.exit(1)
 if path.startswith('/1.0/networks/') or path.startswith('/1.0/network-acls/'):
  print(json.dumps({'type':'error','error_code':404,'error':'Not Found'}));sys.exit(1)
 if (root/'deleted').exists():
  print(json.dumps({'type':'error','error_code':404,'error':'Not Found'}))
 else:
  stopped=(root/'stopped').exists()
  fp='abcdef0123456789'*4
  print(json.dumps({'type':'sync','metadata':{'name':'wssp-sbx-sbx','status':'Stopped' if stopped else 'Running','status_code':102 if stopped else 103,'type':'virtual-machine','devices':{'root':{'type':'disk','path':'/','pool':'default','size':'32GiB'}},'expanded_devices':{'root':{'type':'disk','path':'/','pool':'default','size':'32GiB'}},'config':{'limits.cpu':'1','limits.memory':'1024MiB','user.flycockpit.sandbox_id':'sbx','user.flycockpit.template_digest':'sha256:'+fp,'volatile.base_image':fp,'user.flycockpit.lease':'obsolete boot-arm metadata is not the deadline authority'}}}))
 sys.exit(0)
with (root/'calls').open('a') as log:log.write(' '.join(args)+'\n')
if cmd=='stop':
 if '--timeout' in args:
  # C55 graceful-first: never forced; this guest ignores the shutdown.
  assert '--force' not in args
  sys.exit(1)
 assert '--force' in args
 if not (root/'failed-once').exists():
  (root/'failed-once').touch()
  sys.exit(1)
 (root/'stopped').touch()
 sys.exit(0)
if cmd=='delete':
 assert (root/'stopped').exists()
 (root/'deleted').touch()
 sys.exit(0)
raise RuntimeError('unexpected mutation')
"#,
        0o700,
    );
    // Root cause of the former flake: this guest is unenforced, and the
    // policy reconciler (first pass at service start, then every 2 s) halts a
    // running unenforced VM with an immediate forced stop, by design never
    // graceful. Under load it could win the sandbox lock before the expiry
    // worker, logging ["stop --force", "stop --timeout 10", "stop --force"].
    // The shim above keeps that observation inconclusive while running.
    let mut runtime = sandbox_runtime::IncusKvmRuntime::new(sandbox_runtime::IncusConfig {
        binary: shim.to_string_lossy().into(),
        project: "default".into(),
    })
    .unwrap();
    // Shim host: a synthetic healthy egress guard for the start fence.
    runtime.set_guard_probe(Arc::new(
        sandbox_runtime::guard_probe::FakeGuardProbe::healthy(),
    ));
    let expiry = ExpiryService::start(
        Arc::new(runtime),
        j.clone(),
        HostAuthority::with_journal(j.clone()),
    );
    c.mono.store(1001, Ordering::SeqCst);
    // A hang guard, not a deadline under test: the arm needs one 1 s retry
    // backoff plus dozens of python shim calls, which took 6.6-9.3 s here
    // with other suites running. The attempts themselves are pinned below.
    let deadline = Instant::now() + Duration::from_secs(60);
    while !j.lease("sbx").unwrap().expiry_complete {
        assert!(
            Instant::now() < deadline,
            "local expiry did not enforce the journal-bound Incus action"
        );
        thread::sleep(Duration::from_millis(10));
    }
    assert!(dir.path().join("deleted").exists());
    let calls = std::fs::read_to_string(dir.path().join("calls")).unwrap();
    let stops: Vec<_> = calls.lines().filter(|l| l.starts_with("stop ")).collect();
    // C55: every attempt asks gracefully first, then forces; the forced
    // retry contract is unchanged (one failed, one successful forced stop).
    assert_eq!(stops.iter().filter(|l| l.contains("--force")).count(), 2);
    assert!(
        stops.first().is_some_and(|l| l.contains("--timeout")),
        "{stops:?}"
    );
    assert!(
        stops
            .iter()
            .all(|l| l.contains("--force") != l.contains("--timeout"))
    );
    assert_eq!(
        calls.lines().filter(|l| l.starts_with("delete ")).count(),
        1
    );
    assert!(!calls.contains("start "));
    drop(expiry);
}

/// A failing forced stop must not withhold the census: reconcile returns once
/// the failure is recorded, the census carries it with the timer latch, the
/// connected status frame publishes it, and recovery clears it.
#[test]
fn expiry_failure_is_published_without_blocking_and_clears_on_recovery() {
    use crate::sandbox_relay::reconcile::{
        ExpiryReported, expiry_digest, expiry_status_offer, inventory_census,
    };
    let (_dir, j, c) = setup();
    let failing = Arc::new(AtomicBool::new(true));
    let flag = failing.clone();
    let fake = FakeRuntime::new().with_lifecycle_hook(move |s| {
        if s == "stop" && flag.load(Ordering::SeqCst) {
            return Err(sandbox_runtime::RuntimeError::new(
                sandbox_protocol::SandboxErrorCode::UnknownOutcome,
                "injected\nforce failure",
            ));
        }
        Ok(())
    });
    fake.fixture_root().unwrap();
    seed(&j, &fake, LeaseAction::Stop);
    c.mono.store(1001, Ordering::SeqCst);
    let expiry = ExpiryService::start(
        Arc::new(fake.clone()),
        j.clone(),
        HostAuthority::with_journal(j.clone()),
    );
    let started = Instant::now();
    expiry.reconcile().unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "a recorded failure must end the reconcile wait"
    );
    let census = inventory_census(&j, &fake, &expiry.failures()).unwrap();
    let lease = census[0].lease.as_ref().unwrap();
    assert!(lease.expired && !lease.expiry_complete && lease.timer_expired);
    let failure = lease.expiry_failure.as_ref().unwrap();
    assert_eq!(failure.reason, "unknown_outcome: injected force failure");
    assert!(failure.attempts >= 1);
    assert_eq!(census[0].state, SandboxLifecycleState::Ready);

    let mut reported = ExpiryReported::new();
    let offer = expiry_status_offer(
        &j,
        &fake,
        &expiry.failures(),
        &expiry.completions(),
        &reported,
        Default::default(),
        &Default::default(),
    )
    .unwrap();
    assert_eq!(offer.entries.len(), 1);
    assert!(
        offer.entries[0]
            .lease
            .as_ref()
            .unwrap()
            .expiry_failure
            .is_some()
    );
    reported = expiry_digest(&expiry.failures(), &expiry.completions());
    let offer = expiry_status_offer(
        &j,
        &fake,
        &expiry.failures(),
        &expiry.completions(),
        &reported,
        Default::default(),
        &Default::default(),
    )
    .unwrap();
    assert!(
        offer.entries.is_empty(),
        "converged failure is not republished"
    );

    failing.store(false, Ordering::SeqCst);
    until(|| {
        c.mono.fetch_add(1000, Ordering::SeqCst);
        j.lease("sbx").unwrap().expiry_complete
    });
    until(|| expiry.failures().is_empty());
    let offer = expiry_status_offer(
        &j,
        &fake,
        &expiry.failures(),
        &expiry.completions(),
        &reported,
        Default::default(),
        &Default::default(),
    )
    .unwrap();
    let entries = offer.entries;
    assert_eq!(entries.len(), 1, "recovery must be offered");
    let lease = entries[0].lease.as_ref().unwrap();
    assert!(lease.expiry_complete && lease.timer_expired && lease.expiry_failure.is_none());
    assert_eq!(entries[0].state, SandboxLifecycleState::Stopped);
    drop(expiry);
}

/// An action that neither completes nor fails is still bounded.
#[test]
fn expiry_reconcile_wait_is_bounded_for_a_hung_action() {
    let (_dir, j, c) = setup();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let release = Mutex::new(release_rx);
    let fake = FakeRuntime::new().with_lifecycle_hook(move |s| {
        if s == "stop" {
            let _ = release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(10));
        }
        Ok(())
    });
    fake.fixture_root().unwrap();
    seed(&j, &fake, LeaseAction::Stop);
    c.mono.store(1001, Ordering::SeqCst);
    let expiry = ExpiryService::start(
        Arc::new(fake.clone()),
        j.clone(),
        HostAuthority::with_journal(j.clone()),
    );
    let started = Instant::now();
    expiry.reconcile_within(Duration::from_millis(300)).unwrap();
    assert!(started.elapsed() < Duration::from_secs(3));
    let row = j.lease("sbx").unwrap();
    assert!(row.expired && !row.expiry_complete);
    release_tx.send(()).unwrap();
    until(|| j.lease("sbx").unwrap().expiry_complete);
    drop(expiry);
}

/// Opt-in live proof against a real Incus daemon and the host-local `wssp-base`
/// image: `WSSP_LIVE_INCUS=1 cargo test -p wssp --lib live_incus -- --ignored`
/// (run under the `incus-admin` group). Boots and deletes real KVM VMs.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "boots real Incus KVM VMs; opt in with WSSP_LIVE_INCUS=1"]
fn expiry_live_incus_stop_destroy_and_restart_reconciliation() {
    if std::env::var("WSSP_LIVE_INCUS").as_deref() != Ok("1") {
        eprintln!("skipping: set WSSP_LIVE_INCUS=1 to boot real Incus VMs");
        return;
    }
    let image_ref = std::env::var("WSSP_INCUS_IMAGE").unwrap_or_else(|_| "wssp-base".into());
    // Every identifier is random per run, and everything runs in a project this
    // run proves it created, so cleanup can never reach a VM it does not own.
    let run_id = {
        let mut bytes = [0u8; 6];
        std::io::Read::read_exact(
            &mut std::fs::File::open("/dev/urandom").unwrap(),
            &mut bytes,
        )
        .unwrap();
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    };
    let project = format!("wssp-livexp-{run_id}");
    let run = |args: &[&str]| {
        let out = std::process::Command::new("incus")
            .args(args)
            .output()
            .unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).trim().to_string(),
        )
    };
    let incus = |args: &[&str]| run(&[&["--project", project.as_str()], args].concat());
    struct Cleanup {
        project: String,
        owns_project: bool,
        instances: Vec<(String, String)>,
        state_dir: std::path::PathBuf,
    }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            if !self.owns_project {
                return;
            }
            let incus = |args: &[&str]| {
                std::process::Command::new("incus")
                    .args(["--project", self.project.as_str()])
                    .args(args)
                    .output()
            };
            for (sandbox_id, name) in &self.instances {
                let owned = incus(&["config", "get", name, "user.flycockpit.sandbox_id"])
                    .is_ok_and(|out| {
                        out.status.success()
                            && String::from_utf8_lossy(&out.stdout).trim() == sandbox_id
                    });
                if owned {
                    let _ = incus(&["delete", "--force", name]);
                }
            }
            // Network-aware teardown: a directly deleted VM (the stop-action
            // sandbox) leaves its bridge and ACL behind, and the random
            // project tag means no later run's drain can ever find them.
            let mut client =
                sandbox_runtime::IncusClient::new("incus".to_string(), self.project.clone());
            client.set_host_state_dir(self.state_dir.clone());
            for (sandbox_id, _) in &self.instances {
                let _ = client.teardown_owned_sandbox_network(sandbox_id);
            }
            // Verified absence: report any surviving marked resource.
            for (sandbox_id, _) in &self.instances {
                let (network, acl) = sandbox_runtime::sandbox_network_names(sandbox_id);
                if incus(&["network", "show", &network]).is_ok_and(|out| out.status.success()) {
                    eprintln!("live expiry cleanup: bridge {network} survived");
                }
                if incus(&["network", "acl", "show", &acl]).is_ok_and(|out| out.status.success()) {
                    eprintln!("live expiry cleanup: ACL {acl} survived");
                }
            }
            // Refused by Incus while anything (ours or not) is left inside.
            let _ = std::process::Command::new("incus")
                .args(["project", "delete", self.project.as_str()])
                .output();
        }
    }
    let stop_id = format!("livexp-stop-{run_id}");
    let destroy_id = format!("livexp-destroy-{run_id}");

    eprintln!("live expiry runs in isolated project `{project}`");
    let dir = tempfile::tempdir().unwrap();
    // Assert absence BEFORE constructing the runtime: IncusKvmRuntime::new
    // runs ensure_project, which CREATES the project — checking afterwards
    // would always find it and panic while the (unguarded) project remains.
    assert!(
        !run(&["project", "show", &project]).0,
        "random project `{project}` already exists; refusing to use it"
    );
    let mut kvm = sandbox_runtime::IncusKvmRuntime::new(sandbox_runtime::IncusConfig {
        binary: "incus".into(),
        project: project.clone(),
    })
    .unwrap();
    // Runtime state (network journal, allocation lock) stays in the
    // fixture's temp dir, not the host default state root.
    kvm.set_host_state_dir(dir.path().join("runtime-state"));
    // The project exists now; install the cleanup guard IMMEDIATELY so any
    // failure in subsequent setup still reclaims project, VMs, and network.
    let _cleanup = Cleanup {
        project: project.clone(),
        owns_project: true,
        instances: [&stop_id, &destroy_id]
            .into_iter()
            .map(|id| (id.clone(), sandbox_runtime::default_incus_instance_name(id)))
            .collect(),
        state_dir: dir.path().join("runtime-state"),
    };
    let runtime: Arc<dyn SandboxRuntime> = Arc::new(kvm);
    // E-25: a host restart is a new process, so each simulated restart gets a
    // fresh runtime. `ExpiryService::start` installs an enforcement-loss
    // lifecycle on the runtime that holds an `Arc<HostJournal>`; reusing the
    // old runtime would keep the previous journal (and its exclusive host
    // state lock) alive, and the reopen below would fail with "would block".
    let fresh_runtime = || -> Arc<dyn SandboxRuntime> {
        let mut kvm = sandbox_runtime::IncusKvmRuntime::new(sandbox_runtime::IncusConfig {
            binary: "incus".into(),
            project: project.clone(),
        })
        .unwrap();
        kvm.set_host_state_dir(dir.path().join("runtime-state"));
        Arc::new(kvm)
    };
    let image = runtime.resolve_image_ref(&image_ref).unwrap();
    let lease_dispatch = |j: &HostJournal, id: &str, action: LeaseAction, in_ms: u64| {
        let deadline = j.clock.now_ms().unwrap() + in_ms;
        let op = format!("{id}-create");
        serde_json::from_value::<OperationDispatch>(serde_json::json!({"sandboxOwnerId":"owner",
            "operationId": op, "sandboxId": id, "generation": 1, "attempt": 1,
            "kind": "sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(), "idempotencyKey": op, "bodyHash": "a".repeat(64),
            "incusFingerprint": image.fingerprint,
            "lease": {"revision": 1, "deadlineUnixMs": deadline, "action": action,
                      "expiryPolicy": "retry-force-60s"}}))
        .unwrap()
    };
    let j =
        Arc::new(crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap());

    // Create both VMs through the production runtime before their leases are armed.
    for (id, action) in [
        (&stop_id, LeaseAction::Stop),
        (&destroy_id, LeaseAction::Destroy),
    ] {
        let d = lease_dispatch(&j, id, action, 120_000);
        let created = runtime.create_fixture(&CreateSandboxRequest {
            refused_dns_hints: false,
            first_attempt: false,
            vm_size: sandbox_protocol::VmSize::defaults().unwrap(),
            lease: d.lease.clone().unwrap(),
            sandbox_id: id.clone(),
            instance_name: sandbox_runtime::default_incus_instance_name(id),
            idempotency_key: d.idempotency_key.clone(),
            template_digest: image.fingerprint.clone(),
            incus_fingerprint: Some(image.fingerprint.clone()),
            guest: sandbox_runtime::GuestIdentity::default(),
            architecture: Some(image.architecture.clone()),
            egress_policy: None,
            egress_policy_hash: None,
            egress_settings: sandbox_runtime::egress::EgressSettings::default(),
            egress_admission: sandbox_runtime::egress::EgressAdmission::PERMITTED,
            guest_privilege: Default::default(),
            readiness: Default::default(),
            restore: None,
        });
        assert_eq!(
            created.unwrap().sandbox.state,
            SandboxLifecycleState::Ready,
            "{id}"
        );
        let name = sandbox_runtime::default_incus_instance_name(id);
        let (_, autostart) = incus(&["config", "get", &name, "boot.autostart"]);
        assert_eq!(autostart, "false", "{name} must not autostart on host boot");
        let (_, lease) = incus(&["config", "get", &name, "user.flycockpit.lease"]);
        assert!(!lease.is_empty(), "{name} carries boot-arm lease metadata");
    }

    let mut armed_at = Vec::new();
    for (id, action) in [
        (&stop_id, LeaseAction::Stop),
        (&destroy_id, LeaseAction::Destroy),
    ] {
        let d = lease_dispatch(&j, id, action, 3_000);
        j.record_fixture_intent(&intent_from_dispatch(&j, &binding(), &d))
            .unwrap();
        j.accept_lease(&d).unwrap();
        armed_at.push(d.lease.unwrap().deadline_unix_ms);
    }
    let started = Instant::now();
    let expiry = ExpiryService::start(
        runtime.clone(),
        j.clone(),
        HostAuthority::with_journal(j.clone()),
    );
    let settle = Instant::now() + Duration::from_secs(3 + 60);
    while !(j.lease(&stop_id).unwrap().expiry_complete
        && j.lease(&destroy_id).unwrap().expiry_complete)
    {
        assert!(
            Instant::now() < settle,
            "expiry did not settle within deadline + 60 s"
        );
        thread::sleep(Duration::from_millis(100));
    }
    let elapsed = started.elapsed();
    let completed_wall = wall();
    eprintln!(
        "live expiry settled after {elapsed:?}; wall past deadline: stop={}ms destroy={}ms",
        completed_wall.saturating_sub(armed_at[0]),
        completed_wall.saturating_sub(armed_at[1])
    );
    assert!(elapsed >= Duration::from_millis(2_500), "expired early");
    let stop_name = sandbox_runtime::default_incus_instance_name(&stop_id);
    let destroy_name = sandbox_runtime::default_incus_instance_name(&destroy_id);
    assert_eq!(
        incus(&["list", &format!("^{stop_name}$"), "-f", "csv", "-c", "s"]).1,
        "STOPPED"
    );
    assert!(
        !incus(&["info", &destroy_name]).0,
        "destroy lease deletes the VM"
    );

    // Restart with the VM stopped: reconciliation must not boot it.
    drop(expiry);
    drop(j);
    drop(runtime);
    let runtime = fresh_runtime();
    let j =
        Arc::new(crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap());
    check_inventory(&j, &runtime.sandbox_inventory().unwrap()).unwrap();
    let expiry = ExpiryService::start(
        runtime.clone(),
        j.clone(),
        HostAuthority::with_journal(j.clone()),
    );
    expiry.reconcile().unwrap();
    assert_eq!(
        incus(&["list", &format!("^{stop_name}$"), "-f", "csv", "-c", "s"]).1,
        "STOPPED"
    );
    drop(expiry);
    drop(j);

    // Something outside the node daemon boots the expired VM while it is down.
    // The next start must re-open the completed expiry and force it off again.
    assert!(incus(&["start", &stop_name]).0);
    assert_eq!(
        incus(&["list", &format!("^{stop_name}$"), "-f", "csv", "-c", "s"]).1,
        "RUNNING"
    );
    drop(runtime);
    let runtime = fresh_runtime();
    let j =
        Arc::new(crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap());
    check_inventory(&j, &runtime.sandbox_inventory().unwrap()).unwrap();
    assert!(
        !j.lease(&stop_id).unwrap().expiry_complete,
        "running expired VM re-arms expiry"
    );
    let restarted = Instant::now();
    let expiry = ExpiryService::start(
        runtime.clone(),
        j.clone(),
        HostAuthority::with_journal(j.clone()),
    );
    expiry.reconcile().unwrap();
    eprintln!(
        "restart reconciliation re-stopped the VM after {:?}",
        restarted.elapsed()
    );
    assert!(j.lease(&stop_id).unwrap().expiry_complete);
    assert_eq!(
        incus(&["list", &format!("^{stop_name}$"), "-f", "csv", "-c", "s"]).1,
        "STOPPED"
    );
    drop(expiry);
}

/// Records every lifecycle stage the fake runtime enters, in order.
fn staged(fake: FakeRuntime, refuse_graceful: bool) -> (FakeRuntime, Arc<Mutex<Vec<String>>>) {
    let stages = Arc::new(Mutex::new(Vec::new()));
    let seen = stages.clone();
    let fake = fake.with_graceful_stop().with_lifecycle_hook(move |stage| {
        seen.lock().unwrap().push(stage.to_string());
        if refuse_graceful && stage == "stop_graceful" {
            // The guest ignored the shutdown request within its timeout.
            return Err(sandbox_runtime::RuntimeError::new(
                sandbox_protocol::SandboxErrorCode::Timeout,
                "guest did not shut down",
            ));
        }
        Ok(())
    });
    (fake, stages)
}

/// C55 graceful-first expiry: the guest is asked to stop first; the forced
/// path still runs and is the completion proof (on a stopped VM it only
/// observes), for both stop and destroy leases.
#[test]
fn c55_expiry_stops_gracefully_first_then_runs_the_forced_proof() {
    for (action, want) in [
        (LeaseAction::Stop, vec!["stop_graceful", "stop"]),
        (
            LeaseAction::Destroy,
            vec!["stop_graceful", "stop", "destroy"],
        ),
    ] {
        let (_dir, j, c) = setup();
        let (fake, stages) = staged(FakeRuntime::new(), false);
        seed(&j, &fake, action);
        let expiry = ExpiryService::start(
            Arc::new(fake.clone()),
            j.clone(),
            HostAuthority::with_journal(j.clone()),
        );
        c.mono.store(1001, Ordering::SeqCst);
        until(|| j.lease("sbx").unwrap().expiry_complete);
        let seen: Vec<String> = stages
            .lock()
            .unwrap()
            .iter()
            .filter(|s| ["stop_graceful", "stop", "destroy"].contains(&s.as_str()))
            .cloned()
            .collect();
        assert_eq!(seen, want, "{action:?}");
        let state = fake.query_sandbox("sbx", None, None).unwrap();
        match action {
            LeaseAction::Stop => assert_eq!(state, Some(SandboxLifecycleState::Stopped)),
            _ => assert_eq!(state, None),
        }
        drop(expiry);
    }
}

/// C55: a guest that ignores the graceful stop never stalls expiry: the
/// forced stop follows, and the expiry completes on its proof.
#[test]
fn c55_expiry_falls_back_to_force_when_the_guest_ignores_the_graceful_stop() {
    let (_dir, j, c) = setup();
    let (fake, stages) = staged(FakeRuntime::new(), true);
    seed(&j, &fake, LeaseAction::Stop);
    let expiry = ExpiryService::start(
        Arc::new(fake.clone()),
        j.clone(),
        HostAuthority::with_journal(j.clone()),
    );
    c.mono.store(1001, Ordering::SeqCst);
    until(|| j.lease("sbx").unwrap().expiry_complete);
    let seen = stages.lock().unwrap().clone();
    let graceful = seen.iter().position(|s| s == "stop_graceful");
    let forced = seen.iter().position(|s| s == "stop");
    assert!(
        graceful.is_some() && forced.is_some() && graceful < forced,
        "{seen:?}"
    );
    assert_eq!(
        fake.query_sandbox("sbx", None, None).unwrap(),
        Some(SandboxLifecycleState::Stopped)
    );
    assert!(
        expiry.failures().is_empty(),
        "the fallback is not a failure"
    );
    drop(expiry);
}

/// C55: an enforcement-loss expiry never waits on the guest: no graceful
/// attempt, straight to the forced stop and destruction.
#[test]
fn c55_enforcement_loss_expiry_skips_the_graceful_stop() {
    let (_dir, j, _c) = setup();
    let (fake, stages) = staged(FakeRuntime::new(), false);
    seed(&j, &fake, LeaseAction::Stop);
    let row = j.lease("sbx").unwrap();
    j.settle_enforcement_loss(&row, sandbox_runtime::EnforcementLossStage::Prepare)
        .unwrap();
    let expiry = ExpiryService::start(
        Arc::new(fake.clone()),
        j.clone(),
        HostAuthority::with_journal(j.clone()),
    );
    until(|| j.lease("sbx").unwrap().expiry_complete);
    let seen = stages.lock().unwrap().clone();
    assert!(!seen.iter().any(|s| s == "stop_graceful"), "{seen:?}");
    assert!(seen.iter().any(|s| s == "stop"), "{seen:?}");
    assert!(fake.query_sandbox("sbx", None, None).unwrap().is_none());
    drop(expiry);
}

/// C55-CC-1: graceful-first is once per lease arm. A guest that ignores the
/// graceful stop and a forced stop that fails twice (Incus busy) yield ONE
/// graceful attempt and three forced attempts: every retry goes straight to
/// the forced stop instead of spending another guest timeout.
#[test]
fn c55_graceful_stop_runs_once_per_arm_and_retries_go_straight_to_force() {
    let (_dir, j, c) = setup();
    let stages = Arc::new(Mutex::new(Vec::new()));
    let seen = stages.clone();
    let forced_failures = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let ff = forced_failures.clone();
    let fake = FakeRuntime::new()
        .with_graceful_stop()
        .with_lifecycle_hook(move |stage| {
            seen.lock().unwrap().push(stage.to_string());
            if stage == "stop_graceful" {
                return Err(sandbox_runtime::RuntimeError::new(
                    sandbox_protocol::SandboxErrorCode::Timeout,
                    "guest did not shut down",
                ));
            }
            if stage == "stop" && ff.fetch_add(1, Ordering::SeqCst) < 2 {
                return Err(sandbox_runtime::RuntimeError::new(
                    sandbox_protocol::SandboxErrorCode::Internal,
                    "incus busy",
                ));
            }
            Ok(())
        });
    fake.fixture_root().unwrap();
    seed(&j, &fake, LeaseAction::Stop);
    let expiry = ExpiryService::start(
        Arc::new(fake.clone()),
        j.clone(),
        HostAuthority::with_journal(j.clone()),
    );
    c.mono.store(1001, Ordering::SeqCst);
    let deadline = Instant::now() + Duration::from_secs(20);
    while !j.lease("sbx").unwrap().expiry_complete {
        assert!(Instant::now() < deadline, "did not settle");
        thread::sleep(Duration::from_millis(5));
    }
    let seen = stages.lock().unwrap().clone();
    let graceful = seen.iter().filter(|s| *s == "stop_graceful").count();
    let forced = seen.iter().filter(|s| *s == "stop").count();
    assert_eq!((graceful, forced), (1, 3), "{seen:?}");
    let first_graceful = seen.iter().position(|s| s == "stop_graceful");
    let first_forced = seen.iter().position(|s| s == "stop");
    assert!(
        first_graceful < first_forced,
        "graceful still runs first: {seen:?}"
    );
    assert_eq!(
        fake.query_sandbox("sbx", None, None).unwrap(),
        Some(SandboxLifecycleState::Stopped)
    );
    drop(expiry);
}

// DNS grant refresh (domain egress): the expiry service is the production
// owner of the runtime's refresh pass.

#[test]
fn the_service_drives_dns_refresh_for_active_leases_only() {
    let (_dir, journal, clock) = setup();
    let fake = FakeRuntime::new();
    fake.fixture_root().unwrap();
    seed(&journal, &fake, LeaseAction::Stop);
    let expiry = ExpiryService::start(
        Arc::new(fake.clone()),
        journal.clone(),
        HostAuthority::with_journal(journal.clone()),
    );
    // Recurring passes over the active lease, not a one-shot.
    until(|| {
        fake.dns_refresh_passes()
            .iter()
            .filter(|ids| ids == &&vec!["sbx".to_string()])
            .count()
            >= 2
    });
    // Expiry (stop) takes the sandbox out of the active set: no pass names
    // it again, and with nothing active no pass runs at all.
    clock.mono.store(1001, Ordering::SeqCst);
    until(|| journal.lease("sbx").unwrap().expiry_complete);
    let settled = fake.dns_refresh_passes().len();
    thread::sleep(Duration::from_millis(2500));
    let passes = fake.dns_refresh_passes();
    assert!(
        passes[settled..]
            .iter()
            .all(|ids| !ids.contains(&"sbx".to_string())),
        "an expired sandbox is never refreshed again: {passes:?}"
    );
    assert!(
        passes.len() <= settled + 1,
        "no passes without active sandboxes: {passes:?}"
    );
    drop(expiry);
}

#[test]
fn shutdown_cancels_and_joins_the_dns_refresh_pass() {
    let (_dir, journal, _clock) = setup();
    let fake = FakeRuntime::new();
    fake.fixture_root().unwrap();
    seed(&journal, &fake, LeaseAction::Stop);
    // Each pass would block a full minute unless its permit is revoked.
    fake.set_dns_refresh_hold(Duration::from_secs(60));
    let expiry = ExpiryService::start(
        Arc::new(fake.clone()),
        journal.clone(),
        HostAuthority::with_journal(journal.clone()),
    );
    until(|| fake.dns_refresh_activity().0 == 1);
    let started = Instant::now();
    drop(expiry);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "shutdown never waits out a refresh pass: {:?}",
        started.elapsed()
    );
    assert_eq!(
        fake.dns_refresh_activity(),
        (0, 1),
        "the in-flight pass observed cancellation and was joined before shutdown returned"
    );
    let passes = fake.dns_refresh_passes().len();
    thread::sleep(Duration::from_millis(1500));
    assert_eq!(
        fake.dns_refresh_passes().len(),
        passes,
        "no refresh pass starts after shutdown"
    );
}

/// C38-M28: the periodic loss sweep inspects every active lease's policy
/// BEFORE each drain. Progress is observed on the drain (which runs with or
/// without inspection; the first sweep starts at once), so omitting the
/// inspection fails this assertion rather than an observation deadline.
#[test]
fn the_periodic_loss_sweep_inspects_active_policies_before_each_drain() {
    let (_dir, journal, _clock) = setup();
    let fake = FakeRuntime::new();
    fake.fixture_root().unwrap();
    seed(&journal, &fake, LeaseAction::Stop);
    let expiry = ExpiryService::start(
        Arc::new(fake.clone()),
        journal.clone(),
        HostAuthority::with_journal(journal.clone()),
    );
    until(|| fake.policy_sweep_calls().iter().any(|call| call == "drain"));
    drop(expiry);
    let calls = fake.policy_sweep_calls();
    let drains: Vec<_> = calls
        .iter()
        .enumerate()
        .filter(|(_, call)| *call == "drain")
        .map(|(at, _)| at)
        .collect();
    assert!(!drains.is_empty(), "{calls:?}");
    for at in drains {
        assert_eq!(
            at.checked_sub(1).map(|prev| calls[prev].as_str()),
            Some("reconcile:sbx"),
            "each drain follows an inspection of the active lease: {calls:?}"
        );
    }
}

/// G10R-1: the service never detaches its loss sweep. Shutdown waits for the
/// in-flight pass (here blocked inside its policy observation, where a real
/// daemon has an `incus` child running), and once shutdown is requested the
/// pass starts no new runtime work: no drain after the observation returns.
#[test]
fn shutdown_joins_the_in_flight_loss_sweep_and_starts_no_new_work() {
    let (_dir, journal, _clock) = setup();
    let (entered_tx, entered) = mpsc::channel();
    let (release, released) = mpsc::channel::<()>();
    let released = Mutex::new(released);
    let blocked = std::sync::atomic::AtomicBool::new(false);
    let fake = FakeRuntime::new().with_lifecycle_hook(move |stage| {
        if stage == "policy-observe:sbx" && !blocked.swap(true, Ordering::SeqCst) {
            let _ = entered_tx.send(());
            let _ = released
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(30));
        }
        Ok(())
    });
    fake.fixture_root().unwrap();
    seed(&journal, &fake, LeaseAction::Stop);
    let expiry = ExpiryService::start(
        Arc::new(fake.clone()),
        journal.clone(),
        HostAuthority::with_journal(journal.clone()),
    );
    entered.recv_timeout(Duration::from_secs(4)).unwrap();
    let (dropped_tx, dropped) = mpsc::channel();
    let dropping = thread::spawn(move || {
        drop(expiry);
        let _ = dropped_tx.send(Instant::now());
    });
    assert!(
        dropped.recv_timeout(Duration::from_millis(300)).is_err(),
        "shutdown returned while the sweep was still in flight"
    );
    let released_at = Instant::now();
    release.send(()).unwrap();
    let returned_at = dropped.recv_timeout(Duration::from_secs(4)).unwrap();
    dropping.join().unwrap();
    assert!(returned_at >= released_at, "shutdown joined the sweep");
    let calls = fake.policy_sweep_calls();
    assert_eq!(
        calls,
        ["reconcile:sbx"],
        "no runtime work starts after shutdown: {calls:?}"
    );
}

#[test]
fn shortened_lease_revokes_running_work_at_the_monotonic_deadline() {
    let (_dir, journal, clock) = setup();
    let fake = FakeRuntime::with_command_delay(Duration::from_secs(60));
    fake.fixture_root().unwrap();
    seed(&journal, &fake, LeaseAction::Stop);
    let authority = HostAuthority::with_journal(journal.clone());
    let relay = RelaySupervisor::start(
        Arc::new(fake.clone()),
        journal.clone(),
        authority.clone(),
        #[cfg(target_os = "linux")]
        None,
    );
    let mut command = dispatch(&journal, "command.run", 2, LeaseAction::Stop);
    command.lease = None;
    command.argv = Some(vec!["true".into()]);
    journal
        .record_fixture_intent(&intent_from_dispatch(&journal, &binding(), &command))
        .unwrap();
    authority
        .accept_dispatch(&command.operation_id, "sbx", "command.run", 1, 1)
        .unwrap();
    relay
        .submit(command.clone(), "wssp-sbx-sbx".into(), None)
        .unwrap();
    until(|| authority.runtime_registered(&command.operation_id));

    let mut shorten = dispatch(&journal, "sandbox.lease.renew", 2, LeaseAction::Stop);
    shorten.lease.as_mut().unwrap().deadline_unix_ms = clock.wall.load(Ordering::SeqCst) + 500;
    journal
        .record_fixture_intent(&intent_from_dispatch(&journal, &binding(), &shorten))
        .unwrap();
    authority
        .accept_dispatch(&shorten.operation_id, "sbx", "sandbox.lease.renew", 1, 1)
        .unwrap();
    relay
        .submit(shorten.clone(), "wssp-sbx-sbx".into(), None)
        .unwrap();
    let mut acknowledgement = None;
    until(|| {
        acknowledgement = relay
            .poll_finished()
            .into_iter()
            .find(|done| done.operation_id == shorten.operation_id);
        acknowledgement.is_some()
    });
    let acknowledgement = acknowledgement.unwrap();
    assert_eq!(
        acknowledgement.state,
        sandbox_protocol::OperationState::Succeeded
    );
    assert_eq!(
        acknowledgement.payload.unwrap()["lease"],
        serde_json::json!(shorten.lease)
    );
    assert_eq!(journal.lease("sbx").unwrap().lease, shorten.lease.unwrap());

    // Rollback of wall time cannot postpone the new, earlier deadline.
    clock.wall.fetch_sub(100_000, Ordering::SeqCst);
    clock.mono.store(499, Ordering::SeqCst);
    assert!(journal.poll_expiry().unwrap().is_empty());
    let expiry = ExpiryService::start(Arc::new(fake.clone()), journal.clone(), authority.clone());
    clock.mono.store(500, Ordering::SeqCst);
    until(|| journal.lease("sbx").unwrap().expiry_complete);
    assert!(
        authority
            .accept_stream(&command.operation_id, 1, 1)
            .is_err()
    );
    assert_eq!(
        fake.query_sandbox("sbx", None, None).unwrap(),
        Some(SandboxLifecycleState::Stopped)
    );
    assert_eq!(journal.lease("sbx").unwrap().lease.revision, 2);
    let late = dispatch(&journal, "sandbox.lease.renew", 3, LeaseAction::Stop);
    journal
        .record_fixture_intent(&intent_from_dispatch(&journal, &binding(), &late))
        .unwrap();
    assert!(
        journal.accept_lease(&late).is_err(),
        "expiry cannot be revived"
    );
    assert!(
        authority
            .accept_dispatch("late-command", "sbx", "command.run", 1, 1)
            .is_err()
    );
    drop(expiry);
    drop(relay);
}

// E-42: the timer may have observed/bound the VM before the server's kill.
// Gate the failing runtime phase so the competing kill is complete before
// the local error returns; no scheduler timing determines either order.
#[test]
fn expiry_resolves_when_server_kill_wins_before_stop_or_between_stop_and_destroy() {
    for failed_stage in ["stop", "destroy"] {
        let (_dir, journal, clock) = setup();
        let (entered_tx, entered) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        let wait = Mutex::new(wait);
        let first = AtomicBool::new(true);
        let fake = FakeRuntime::new().with_lifecycle_hook(move |stage| {
            if stage == failed_stage && first.swap(false, Ordering::SeqCst) {
                entered_tx.send(()).unwrap();
                wait.lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap();
                return Err(sandbox_runtime::RuntimeError::new(
                    sandbox_protocol::SandboxErrorCode::SandboxNotFound,
                    "bound instance disappeared during local expiry",
                ));
            }
            Ok(())
        });
        fake.fixture_root().unwrap();
        seed(&journal, &fake, LeaseAction::Destroy);
        clock.mono.store(1001, Ordering::SeqCst);
        let row = journal.poll_expiry().unwrap().pop().unwrap();
        let local = fake.clone();
        let intent = row.clone();
        let timer = thread::spawn(move || expire(&local, &intent, false));
        entered.recv_timeout(Duration::from_secs(5)).unwrap();
        fake.kill_fixture(&KillSandboxRequest {
            operation_id: "server-kill".into(),
            template_fingerprint: row.template_fingerprint.clone().unwrap(),
            sandbox_id: row.sandbox_id.clone(),
            instance_name: sandbox_runtime::default_incus_instance_name(&row.sandbox_id),
            idempotency_key: "server-kill".into(),
        })
        .unwrap();
        release.send(()).unwrap();
        timer
            .join()
            .unwrap()
            .expect("completed competing kill resolves local expiry");
        journal.finish_expiry(&row).unwrap();
        assert!(journal.lease("sbx").unwrap().expiry_complete);
        assert_eq!(fake.query_sandbox("sbx", None, None).unwrap(), None);
    }
}

#[test]
fn expiry_failure_without_a_competing_kill_remains_unresolved() {
    for failed_stage in ["stop", "destroy"] {
        let (_dir, journal, clock) = setup();
        let fake = FakeRuntime::new().with_lifecycle_hook(move |stage| {
            if stage == failed_stage {
                return Err(sandbox_runtime::RuntimeError::new(
                    sandbox_protocol::SandboxErrorCode::UnknownOutcome,
                    "genuine expiry failure",
                ));
            }
            Ok(())
        });
        fake.fixture_root().unwrap();
        seed(&journal, &fake, LeaseAction::Destroy);
        clock.mono.store(1001, Ordering::SeqCst);
        let row = journal.poll_expiry().unwrap().pop().unwrap();
        assert!(expire(&fake, &row, false).is_err());
        assert!(!journal.lease("sbx").unwrap().expiry_complete);
        assert_eq!(
            fake.query_sandbox("sbx", None, None).unwrap(),
            Some(if failed_stage == "stop" {
                SandboxLifecycleState::Ready
            } else {
                SandboxLifecycleState::Stopped
            })
        );
    }
}

#[test]
fn expiry_already_absent_and_timer_before_server_kill_are_idempotent() {
    for server_first in [true, false] {
        let (_dir, journal, clock) = setup();
        let fake = FakeRuntime::new();
        fake.fixture_root().unwrap();
        seed(&journal, &fake, LeaseAction::Destroy);
        clock.mono.store(1001, Ordering::SeqCst);
        let row = journal.poll_expiry().unwrap().pop().unwrap();
        let kill = || {
            fake.kill_fixture(&KillSandboxRequest {
                operation_id: "server-kill".into(),
                template_fingerprint: row.template_fingerprint.clone().unwrap(),
                sandbox_id: row.sandbox_id.clone(),
                instance_name: sandbox_runtime::default_incus_instance_name(&row.sandbox_id),
                idempotency_key: "server-kill".into(),
            })
            .unwrap()
        };
        if server_first {
            kill();
        }
        expire(&fake, &row, false).unwrap();
        if !server_first {
            kill();
        }
        journal.finish_expiry(&row).unwrap();
        assert!(journal.lease("sbx").unwrap().expiry_complete);
    }
}

#[test]
fn dns_refresh_logs_changed_at_info_unchanged_at_debug_with_only_counts() {
    for format in [crate::cli::LogFormat::Text, crate::cli::LogFormat::Json] {
        let (_, captured) = crate::logging::with_subscriber(
            format,
            tracing_subscriber::EnvFilter::new("trace"),
            || {
                for changed_grants in [true, false] {
                    log_dns_refresh(&sandbox_runtime::DnsRefreshReport {
                        sandbox_id: "sbx-dns-log".into(),
                        domain_count: 3,
                        changed_grants,
                        changed_addresses: if changed_grants { 5 } else { 0 },
                        added_addresses: if changed_grants { 2 } else { 0 },
                        removed_addresses: if changed_grants { 3 } else { 0 },
                        next_refresh_unix_secs: 1_800_000_150,
                        warning: None,
                    });
                }
            },
        );
        let text = String::from_utf8(captured).unwrap();
        assert_eq!(
            text.matches("DNS grant refresh completed").count(),
            2,
            "{text}"
        );
        assert!(text.contains("INFO") && text.contains("DEBUG"), "{text}");
        assert!(text.contains("sbx-dns-log"), "{text}");
        for field in [
            "domain_count",
            "changed_addresses",
            "added_addresses",
            "removed_addresses",
            "next_refresh_unix_secs",
        ] {
            assert_eq!(
                text.matches(field).count(),
                2,
                "missing structured count: {text}"
            );
        }
        assert!(!text.contains("128.66.") && !text.contains("example.com"));
        if matches!(format, crate::cli::LogFormat::Json) {
            let events: Vec<serde_json::Value> = text
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            assert_eq!(events[0]["level"], "INFO");
            assert_eq!(events[1]["level"], "DEBUG");
            for (event, changed, added, removed) in [(&events[0], 5, 2, 3), (&events[1], 0, 0, 0)] {
                assert_eq!(event["fields"]["domain_count"], 3);
                assert_eq!(event["fields"]["changed_addresses"], changed);
                assert_eq!(event["fields"]["added_addresses"], added);
                assert_eq!(event["fields"]["removed_addresses"], removed);
                assert_eq!(event["fields"]["next_refresh_unix_secs"], 1_800_000_150);
            }
        }
    }
}

#[test]
fn retired_loss_cannot_destroy_a_vm_but_can_acknowledge_absent_cleanup() {
    let (_dir, journal, _clock) = setup();
    let settlement = EnforcementLossSettlement::capture(
        journal.clone(),
        HostAuthority::default(),
        Arc::new(Mutex::new(ExpiryCompletions::new())),
    );
    assert_eq!(
        settlement
            .checkpoint("sbx", sandbox_runtime::EnforcementLossStage::Prepare)
            .unwrap_err()
            .code,
        sandbox_protocol::SandboxErrorCode::SandboxNotFound
    );
    settlement
        .checkpoint("sbx", sandbox_runtime::EnforcementLossStage::Complete)
        .unwrap();
    // A newer obligation after capture must veto even the absent leg.
    let d = dispatch(&journal, "sandbox.create", 1, LeaseAction::Destroy);
    accept(&journal, &d);
    assert!(
        settlement
            .checkpoint("sbx", sandbox_runtime::EnforcementLossStage::Complete)
            .is_err()
    );
}

#[test]
fn census_pause_joins_refresh_and_resumes_after_error_without_stopping_expiry() {
    let (_dir, journal, clock) = setup();
    let fake = FakeRuntime::new();
    fake.fixture_root().unwrap();
    seed(&journal, &fake, LeaseAction::Destroy);
    fake.set_dns_refresh_hold(Duration::from_secs(60));
    let expiry = ExpiryService::start(
        Arc::new(fake.clone()),
        journal.clone(),
        HostAuthority::with_journal(journal.clone()),
    );
    until(|| fake.dns_refresh_activity().0 == 1);
    let shutdown = super::super::connect::ShutdownSignal::default();
    let pause = expiry.pause_dns_refresh(&shutdown).unwrap();
    assert_eq!(fake.dns_refresh_activity(), (0, 1));
    let passes = fake.dns_refresh_passes().len();
    let failure: Result<()> = (|| {
        let _pause = pause;
        bail!("injected census failure");
    })();
    assert!(failure.is_err());
    until(|| fake.dns_refresh_passes().len() > passes);
    let pause = expiry.pause_dns_refresh(&shutdown).unwrap();
    let passes = fake.dns_refresh_passes().len();
    // A census does not suspend the sandbox lease-expiry supervisor.
    clock.mono.store(1001, Ordering::SeqCst);
    until(|| journal.leases().iter().all(|row| row.expiry_complete));
    assert_eq!(fake.dns_refresh_passes().len(), passes);
    drop(pause);
    drop(expiry);
    assert_eq!(fake.dns_refresh_activity().0, 0);
}

/// CLI logins (§10.4 Expiry): local expiry runs its credential phase
/// (pre-checks → quiesce → pack → seal → upload → outcome → scrub) before the
/// graceful stop, all within the reconcile budget, then settles the binding.
#[test]
fn expiry_captures_and_scrubs_credentials_before_the_graceful_stop() {
    use crate::sandbox_relay::credentials::journal::{BindingPhase, BindingPurpose, BindingRecord};
    use crate::sandbox_relay::credentials::service::CredentialService;
    use sandbox_protocol::{DaemonControlMessage, ServerControlMessage};
    let (dir, j, c) = setup();
    let base = FakeRuntime::new();
    let probe = base.clone();
    let at_graceful = Arc::new(Mutex::new(None));
    let seen = at_graceful.clone();
    let fake = base.with_graceful_stop().with_lifecycle_hook(move |stage| {
        if stage == "stop_graceful" {
            let ops: Vec<String> = probe
                .credential_calls()
                .into_iter()
                .map(|(op, _)| op)
                .collect();
            *seen.lock().unwrap() = Some(ops);
        }
        Ok(())
    });
    seed(&j, &fake, LeaseAction::Stop);
    // An installed login on the sandbox, and an acked return key.
    let credentials = CredentialService::start(dir.path(), "host").unwrap();
    let rng = ring::rand::SystemRandom::new();
    let private =
        ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::X25519, &rng).unwrap();
    let public = crate::sandbox_relay::credentials::seal::ReturnPublicKey::from_bytes(
        private
            .compute_public_key()
            .unwrap()
            .as_ref()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    credentials
        .store()
        .install_return_key(&sandbox_protocol::CredentialReturnKeyV11 {
            kid_r: public.kid_r().to_owned(),
            epoch: 1,
            public_key: public.to_base64url(),
            server_origin: "https://wssp.example.com".into(),
        })
        .unwrap();
    let lease: sandbox_protocol::SpecLeaseV11 = serde_json::from_value(serde_json::json!({
        "leaseId":"lease-1","credentialId":"cred-1","instanceId":"inst-1",
        "definitionDigest":"ab".repeat(32),"maxBytes":4096,"delivery":"guest","exclusive":true,
        "copyBack":true,"rotates":"unknown","kind":"workload","action":"inject",
        "files":{"required":[".config/tool"],"optional":[],"exclude":[]},"env":[],"proxy":[]}))
    .unwrap();
    credentials
        .store()
        .journal()
        .record_binding(BindingRecord {
            binding_id: "bind-1".into(),
            lease_id: "lease-1".into(),
            sandbox_id: "sbx".into(),
            credential_id: "cred-1".into(),
            instance_id: "inst-1".into(),
            spec_digest: "a".repeat(64),
            copy_back: true,
            exclusive: true,
            purpose: BindingPurpose::Install,
            install_intent: None,
            installed_seq: Some(1),
            phase: BindingPhase::Active,
            teardown: None,
            scrubbed_verified: false,
            spec: Some(lease),
            proxy_handles: Vec::new(),
        })
        .unwrap();
    fake.set_guest_file(
        "sbx",
        ".config/tool/hosts.yml",
        b"token: rotated-before-expiry",
    );
    // The control plane answers every capture COMMITTED.
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let server = {
        let (service, stop) = (credentials.clone(), stop.clone());
        thread::spawn(move || {
            let mut counts = std::collections::HashMap::new();
            while !stop.load(Ordering::SeqCst) {
                for frame in service.drain() {
                    match frame {
                        DaemonControlMessage::CredentialCaptureBegin(b) => {
                            counts.insert(b.capture_id, b.chunk_count);
                        }
                        DaemonControlMessage::CredentialCaptureChunk(chunk)
                            if counts.get(&chunk.capture_id) == Some(&(chunk.seq + 1)) =>
                        {
                            service.handle_server(ServerControlMessage::CredentialCaptureAck(
                                sandbox_protocol::CredentialCaptureAckV11 {
                                    capture_id: chunk.capture_id,
                                    outcome: sandbox_protocol::CaptureAckOutcome::Committed,
                                    reason: None,
                                },
                            ));
                        }
                        _ => {}
                    }
                }
                thread::sleep(Duration::from_millis(2));
            }
        })
    };
    let expiry = ExpiryService::start_with_credentials(
        Arc::new(fake.clone()),
        j.clone(),
        HostAuthority::with_journal(j.clone()),
        crate::sandbox_relay::carry::CarryPolicy::default(),
        Some(credentials.clone()),
    );
    let started = Instant::now();
    c.mono.store(1001, Ordering::SeqCst);
    until(|| j.lease("sbx").unwrap().expiry_complete);
    assert!(started.elapsed() < RECONCILE_BUDGET);
    assert_eq!(
        at_graceful
            .lock()
            .unwrap()
            .clone()
            .expect("graceful stop ran"),
        vec!["probe", "quiesce", "pack", "scrub"],
        "the credential phase completes before the graceful stop"
    );
    assert!(fake.guest_file("sbx", ".config/tool/hosts.yml").is_none());
    assert_eq!(credentials.store().outbox().pending().count(), 0);
    // Settled with the completed expiry: the scrubbed binding is forgotten.
    until(|| credentials.store().journal().binding("bind-1").is_none());
    drop(expiry);
    stop.store(true, Ordering::SeqCst);
    server.join().unwrap();
}

#[test]
fn a_destroying_expiry_waits_for_an_in_flight_disk_offload_publish() {
    // A lease-expiry destroy, like a kill, never
    // deletes the VM under a running `incus publish`; it cancels the offload
    // and waits for the publish to end (bounded by `IMAGE_IO_TIMEOUT`).
    let (dir, j, c) = setup();
    let destroyed_at: Arc<Mutex<Option<Instant>>> = Arc::default();
    let seen = destroyed_at.clone();
    let fake = FakeRuntime::new().with_lifecycle_hook(move |s| {
        if s == "destroy" {
            seen.lock().unwrap().get_or_insert_with(Instant::now);
        }
        Ok(())
    });
    fake.fixture_root().unwrap();
    seed(&j, &fake, LeaseAction::Destroy);
    fake.stop_sandbox(&sandbox_runtime::StopSandboxRequest {
        operation_id: "stop".into(),
        template_fingerprint: CreateSandboxRequest::for_test("sbx", "key").template_digest,
        sandbox_id: "sbx".into(),
        instance_name: sandbox_runtime::default_incus_instance_name("sbx"),
        idempotency_key: "stop".into(),
    })
    .unwrap();
    let images = crate::sandbox_relay::images::ImageService::start(
        Arc::new(fake.clone()),
        &dir.path().join("images"),
        crate::sandbox_relay::images::ImageSettings {
            size: crate::config::ImageCacheSize::Gib(4),
            accept_foreign: false,
            foreign_grace: Duration::from_secs(600),
            builder: false,
            accept_foreign_builds: false,
        },
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .into(),
        "http://127.0.0.1:9",
        "wssp_host_test-secret",
    )
    .unwrap()
    .unwrap();
    images.on_registered("owner");
    let offload = crate::sandbox_relay::offload::OffloadService::start(
        images,
        Arc::new(fake.clone()),
        Arc::new(|id: &str| {
            (id == "sbx").then_some(crate::sandbox_relay::offload::LocalSandbox {
                disk_gib: 1,
                build: false,
            })
        }),
        crate::sandbox_relay::offload::OffloadSettings::default(),
    )
    .unwrap();
    fake.set_publish_hold(Some(Duration::from_millis(600)));
    offload.handle_server(sandbox_protocol::ServerControlMessage::DiskOffloadRequest(
        sandbox_protocol::DiskOffloadRequestV11 {
            sandbox_id: "sbx".into(),
            generation: 1,
            offload_id: "off-1".into(),
            seq: 1,
        },
    ));
    until(|| fake.publishes_in_flight() == 1);
    let publishing = Instant::now();
    let expiry = ExpiryService::start(
        Arc::new(fake.clone()),
        j.clone(),
        HostAuthority::with_journal(j.clone()),
    );
    expiry.install_offload(offload.clone());
    c.mono.store(1001, Ordering::SeqCst);
    until(|| j.lease("sbx").unwrap().expiry_complete);
    let destroyed = destroyed_at.lock().unwrap().expect("destroyed");
    assert!(
        destroyed.duration_since(publishing) >= Duration::from_millis(400),
        "the destroy ran mid-publish"
    );
    assert_eq!(fake.publishes_in_flight(), 0);
    assert_eq!(fake.query_sandbox("sbx", None, None).unwrap(), None);
    // The preempted offload left nothing behind.
    until(|| offload.entry("sbx").is_none());
    drop(expiry);
}

/// An offload service whose journal holds a `stored` entry of `sbx`.
fn stored_offload(
    dir: &tempfile::TempDir,
    fake: &FakeRuntime,
) -> (
    crate::sandbox_relay::offload::OffloadService,
    crate::sandbox_relay::offload::OffloadEntry,
) {
    stored_offload_with(
        dir,
        fake,
        Arc::new(|id: &str| {
            (id == "sbx").then_some(crate::sandbox_relay::offload::LocalSandbox {
                disk_gib: 1,
                build: false,
            })
        }),
    )
}

fn stored_offload_with(
    dir: &tempfile::TempDir,
    fake: &FakeRuntime,
    lookup: crate::sandbox_relay::offload::SandboxLookup,
) -> (
    crate::sandbox_relay::offload::OffloadService,
    crate::sandbox_relay::offload::OffloadEntry,
) {
    let images = crate::sandbox_relay::images::ImageService::start(
        Arc::new(fake.clone()),
        &dir.path().join("images"),
        crate::sandbox_relay::images::ImageSettings {
            size: crate::config::ImageCacheSize::Gib(4),
            accept_foreign: false,
            foreign_grace: Duration::from_secs(600),
            builder: false,
            accept_foreign_builds: false,
        },
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .into(),
        "http://127.0.0.1:9",
        "wssp_host_test-secret",
    )
    .unwrap()
    .unwrap();
    images.on_registered("owner");
    let stored = crate::sandbox_relay::offload::OffloadEntry {
        offload_id: "off-1".into(),
        seq: 1,
        generation: 1,
        phase: crate::sandbox_relay::offload::OffloadPhase::Stored,
        alias: "wssp-off-x-off-1".into(),
        staged_sha256: Some("a".repeat(64)),
        last_used_at: None,
        cloud_init_instance_id: None,
        evict_grant_id: None,
        evict_expires_at_unix_ms: None,
    };
    crate::sandbox_relay::offload::OffloadJournal::open(&images.state_dir())
        .unwrap()
        .put("sbx", stored.clone())
        .unwrap();
    let offload = crate::sandbox_relay::offload::OffloadService::start(
        images,
        Arc::new(fake.clone()),
        lookup,
        crate::sandbox_relay::offload::OffloadSettings::default(),
    )
    .unwrap();
    (offload, stored)
}

#[test]
fn a_completed_destroying_expiry_drops_the_stored_offload_entry() {
    // A destroy-lease expiry removes the root as a kill
    // does, so its `stored` offload entry (never reported by the inventory)
    // is dropped too, instead of outliving the VM in the journal forever.
    let (dir, j, c) = setup();
    let fake = FakeRuntime::new();
    fake.fixture_root().unwrap();
    seed(&j, &fake, LeaseAction::Destroy);
    let (offload, stored) = stored_offload(&dir, &fake);
    // A preemption of the expiry keeps a stored copy (it is the server's).
    assert_eq!(offload.entry("sbx"), Some(stored));
    let expiry = ExpiryService::start(
        Arc::new(fake.clone()),
        j.clone(),
        HostAuthority::with_journal(j.clone()),
    );
    expiry.install_offload(offload.clone());
    c.mono.store(1001, Ordering::SeqCst);
    until(|| j.lease("sbx").unwrap().expiry_complete);
    assert_eq!(fake.query_sandbox("sbx", None, None).unwrap(), None);
    until(|| offload.entry("sbx").is_none());
    drop(expiry);
}

#[test]
fn a_slow_offload_forget_never_delays_another_sandboxs_expiry() {
    // The forget after sandbox A's destroying expiry lists
    // Incus aliases; held for 3 s, it must not keep the expiry loop from
    // dispatching sandbox B's expiry, due 500 ms after A's.
    let (dir, j, c) = setup();
    let fake = FakeRuntime::new();
    fake.fixture_root().unwrap();
    seed(&j, &fake, LeaseAction::Destroy);
    let mut b = dispatch(&j, "sandbox.create", 1, LeaseAction::Stop);
    b.sandbox_id = "sbx-b".into();
    b.operation_id = "sandbox-create-b".into();
    b.idempotency_key = "sandbox-create-b".into();
    if let Some(lease) = b.lease.as_mut() {
        lease.deadline_unix_ms += 500;
    }
    accept(&j, &b);
    let mut req = CreateSandboxRequest::for_test("sbx-b", &b.idempotency_key);
    req.lease = sandbox_protocol::HostLease {
        deadline_unix_ms: sandbox_protocol::HostLease::for_test().deadline_unix_ms,
        ..b.lease.clone().unwrap()
    };
    fake.create_fixture(&req).unwrap();
    fake.set_alias_list_hold(Some(Duration::from_secs(3)));
    let (offload, _) = stored_offload(&dir, &fake);
    let expiry = ExpiryService::start(
        Arc::new(fake.clone()),
        j.clone(),
        HostAuthority::with_journal(j.clone()),
    );
    expiry.install_offload(offload.clone());
    c.mono.store(1001, Ordering::SeqCst);
    until(|| j.lease("sbx").unwrap().expiry_complete);
    // A's forget is now listing aliases; B comes due.
    c.mono.store(1501, Ordering::SeqCst);
    let due = Instant::now();
    let deadline = due + Duration::from_millis(1500);
    while !j.lease("sbx-b").unwrap().expiry_complete {
        assert!(
            Instant::now() < deadline,
            "B's expiry waited on A's offload forget"
        );
        thread::sleep(Duration::from_millis(5));
    }
    // A's forget still completes, off the loop.
    let deadline = Instant::now() + Duration::from_secs(10);
    while offload.entry("sbx").is_some() {
        assert!(
            Instant::now() < deadline,
            "A's stored entry never forgotten"
        );
        thread::sleep(Duration::from_millis(10));
    }
    fake.set_alias_list_hold(None);
    drop(expiry);
}

#[test]
fn a_restart_forgets_a_stored_entry_left_by_a_crash_after_expiry_completed() {
    // The daemon dies after `finish_expiry` persisted a
    // destroying expiry, before the stored offload entry's forget ran (here:
    // no offload service was running at all). On restart, the offload
    // recovery finds a stored entry with no live lease and an absent VM and
    // forgets it.
    let (dir, j, c) = setup();
    let fake = FakeRuntime::new();
    fake.fixture_root().unwrap();
    seed(&j, &fake, LeaseAction::Destroy);
    let expiry = ExpiryService::start(
        Arc::new(fake.clone()),
        j.clone(),
        HostAuthority::with_journal(j.clone()),
    );
    c.mono.store(1001, Ordering::SeqCst);
    until(|| j.lease("sbx").unwrap().expiry_complete);
    drop(expiry);
    assert_eq!(fake.query_sandbox("sbx", None, None).unwrap(), None);
    // The restart: the lookup reads the lease journal as `connect` does.
    let leases = j.clone();
    let (offload, _) = stored_offload_with(
        &dir,
        &fake,
        Arc::new(move |id: &str| {
            let lease = leases.lease(id)?;
            (!lease.instance_absent && !lease.root_deleted).then_some(
                crate::sandbox_relay::offload::LocalSandbox {
                    disk_gib: 1,
                    build: false,
                },
            )
        }),
    );
    until(|| offload.entry("sbx").is_none());
}

/// Each lifecycle action takes less than its own budget, while their total
/// exceeds one budget. Destruction must finish on the first expiry arm.
#[test]
fn expiry_stop_and_destroy_have_independent_action_budgets() {
    let (_dir, journal, _clock) = setup();
    let fake = FakeRuntime::new().with_lifecycle_hook(|stage| {
        if matches!(stage, "stop" | "destroy") {
            std::thread::sleep(Duration::from_secs(3));
        }
        Ok(())
    });
    seed(&journal, &fake, LeaseAction::Destroy);
    let row = journal.lease("sbx").unwrap();
    expiry_action(&fake, &row, true).expect("destroy completes on the first arm");
    assert_eq!(fake.query_sandbox("sbx", None, None).unwrap(), None);
}

#[test]
fn expiry_fallback_proof_gets_a_live_permit_after_stop_or_destroy_times_out() {
    for timeout_stage in ["stop", "destroy"] {
        let (_dir, journal, _clock) = setup();
        let fake = FakeRuntime::new();
        seed(&journal, &fake, LeaseAction::Destroy);
        let row = journal.lease("sbx").unwrap();
        let root =
            super::super::journal::storage::allocation_root(row.allocation.as_ref().unwrap());
        let other = fake.clone();
        let row_for_hook = row.clone();
        let root_for_hook = root.clone();
        let fake = fake.with_lifecycle_hook(move |stage| {
            if stage == timeout_stage {
                std::thread::sleep(ACTION_BUDGET + Duration::from_millis(50));
                // A server teardown completes while local expiry's action
                // permit expires. The subsequent proof must observe it.
                other
                    .kill_sandbox_on_storage(
                        &KillSandboxRequest {
                            operation_id: "concurrent-destroy".into(),
                            template_fingerprint: row_for_hook
                                .template_fingerprint
                                .clone()
                                .unwrap(),
                            sandbox_id: row_for_hook.sandbox_id.clone(),
                            instance_name: sandbox_runtime::default_incus_instance_name(
                                &row_for_hook.sandbox_id,
                            ),
                            idempotency_key: "concurrent-destroy".into(),
                        },
                        &root_for_hook,
                    )
                    .unwrap();
            }
            Ok(())
        });
        expiry_action(&fake, &row, true).expect("fresh proof sees concurrent teardown");
        fake.prove_root_absent(
            &root,
            &sandbox_runtime::default_incus_instance_name(&row.sandbox_id),
        )
        .unwrap();
    }
}
