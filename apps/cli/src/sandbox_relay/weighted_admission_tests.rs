use super::*;
#[cfg(test)]
use crate::sandbox_relay::test_support::FixtureRuntime;
use crate::sandbox_relay::{
    clock::{ClockSource, LeaseClock},
    journal::intent_from_dispatch,
};
use sandbox_protocol::{OperationDispatch, ReceiptConfirmation};
use sandbox_runtime::{ConfiguredSize, RuntimeError, RuntimeInventoryEntry};
use std::sync::Arc;

#[derive(Debug)]
struct TestClock(u64);
impl ClockSource for TestClock {
    fn sample(&self) -> Result<(u64, u64)> {
        Ok((self.0, 0))
    }
}
fn binding() -> TransportBindingV11 {
    TransportBindingV11 {
        server: "wss://weighted.test".into(),
        host_owner_id: "owner".into(),
        host_id: "host".into(),
    }
}
fn journal(dir: &std::path::Path) -> HostJournal {
    let mut j = crate::sandbox_relay::test_support::open_journal(dir, &binding()).unwrap();
    j.clock = Arc::new(LeaseClock::new(Arc::new(TestClock(1000))));
    j
}
fn size(memory: u32) -> VmSize {
    VmSize::new(2, memory).unwrap()
}
fn dispatch(id: &str, generation: u64, size: Option<VmSize>) -> OperationDispatch {
    let mut d: OperationDispatch = serde_json::from_value(serde_json::json!({"sandboxOwnerId":"owner",
        "operationId":id, "sandboxId":"a", "kind":"sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(), "generation":generation,
        "attempt":1, "idempotencyKey":id, "bodyHash":"a".repeat(64),
        "lease":{"revision":generation,"deadlineUnixMs":100000,"action":"stop","expiryPolicy":"retry-force-60s"}
    })).unwrap();
    if let Some(size) = size {
        d.cpu_count = Some(size.cpu_count);
        d.memory_mi_b = Some(size.memory_mi_b);
    }
    crate::sandbox_relay::test_support::pinned_dispatch(&d)
}
fn effect(j: &HostJournal, d: &OperationDispatch) {
    j.record_intent(&intent_from_dispatch(j, &binding(), d))
        .unwrap();
    j.record_effect(&d.operation_id).unwrap();
    j.record_result(
        &d.operation_id,
        OperationState::UnknownOutcome,
        None,
        None,
        None,
    )
    .unwrap();
}
fn inventory(memory: u32) -> RuntimeInventoryEntry {
    RuntimeInventoryEntry {
        sandbox_id: "a".into(),
        state: SandboxLifecycleState::Ready,
        configured_size: ConfiguredSize::Configured(size(memory)),
    }
}

#[test]
fn weighted_slots_share_charged_memory_and_enforce_independent_cpu_budgets() {
    let mut slots = LiveSandboxAdmission::new(8, VmCapacity::new(4864, 4).unwrap());
    for (sandbox, operation) in [
        ("a", "first"),
        ("a", "duplicate"),
        ("a", "newer"),
        ("b", "second"),
    ] {
        slots
            .try_acquire(sandbox, operation, 1, VmSize::new(4, 2048).unwrap())
            .unwrap();
    }
    assert_eq!(slots.held(), 2);
    assert_eq!(slots.memory_held_mib().unwrap(), 4736);
    assert_eq!(
        slots.try_acquire("c", "full", 1, size(512)),
        Err(SandboxErrorCode::HostCapacity)
    );
    slots.finish_allocation("a", "duplicate", OperationState::Failed);
    assert_eq!(slots.memory_held_mib().unwrap(), 4736);
    slots.release_confirmed("b");
    assert_eq!(slots.memory_held_mib().unwrap(), 2368);
    // RAM and slots are available: only the per-VM CPU cap can refuse this.
    assert_eq!(
        slots.try_acquire("c", "cpu", 1, VmSize::new(5, 512).unwrap()),
        Err(SandboxErrorCode::HostCapacity)
    );
    slots.try_acquire("c", "fits", 1, size(2048)).unwrap();
}

#[test]
fn missing_lease_and_historical_effect_weight_never_disable_the_host() {
    let dir = tempfile::tempdir().unwrap();
    let j = journal(dir.path());
    let mut slots = LiveSandboxAdmission::new(4, VmCapacity::new(4864, 4).unwrap());
    slots.rebuild(&[inventory(2048)], &j, &binding()).unwrap();
    assert_eq!(slots.memory_held_mib().unwrap(), 2368);
    slots.try_acquire("b", "fresh", 1, size(2048)).unwrap();
    let old = dispatch("old", 1, None);
    effect(&j, &old);
    let rebuilt = slots.rebuild(&[], &j, &binding());
    assert!(
        rebuilt.is_ok(),
        "missing historical size must remain schedulable"
    );
    rebuilt.unwrap();
    assert_eq!(slots.memory_held_mib().unwrap(), 1344);
    slots.try_acquire("fresh", "fresh", 1, size(3072)).unwrap();
    assert_eq!(slots.memory_held_mib().unwrap(), 4736);
    assert_eq!(slots.held(), 2);
}

#[test]
fn several_receipts_and_runtime_for_one_sandbox_count_one_weight() {
    let dir = tempfile::tempdir().unwrap();
    let j = journal(dir.path());
    for (id, generation) in [("create", 1), ("reconnect", 2), ("retry", 2)] {
        effect(&j, &dispatch(id, generation, Some(size(3072))));
    }
    let mut slots = LiveSandboxAdmission::new(4, VmCapacity::new(4864, 4).unwrap());
    slots.rebuild(&[inventory(3072)], &j, &binding()).unwrap();
    assert_eq!(slots.held(), 1);
    assert_eq!(slots.memory_held_mib().unwrap(), 3392);
    slots.try_acquire("b", "fits", 1, size(1024)).unwrap();
}

#[test]
fn canonical_and_invalid_config_conflicts_charge_max_and_block_only_that_sandbox() {
    for config in [
        ConfiguredSize::Configured(size(2048)),
        ConfiguredSize::Configured(size(6144)),
        ConfiguredSize::Conflict,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let j = journal(dir.path());
        let d = dispatch("create", 1, Some(size(4096)));
        effect(&j, &d);
        j.accept_fixture_lease(&d).unwrap();
        let expected = match config {
            ConfiguredSize::Configured(s) => s.memory_mi_b.max(4096),
            _ => 4096,
        };
        let mut slots = LiveSandboxAdmission::new(8, VmCapacity::new(9216, 4).unwrap());
        slots
            .rebuild(
                &[RuntimeInventoryEntry {
                    sandbox_id: "a".into(),
                    state: SandboxLifecycleState::Ready,
                    configured_size: config,
                }],
                &j,
                &binding(),
            )
            .unwrap();
        assert_eq!(
            slots.memory_held_mib().unwrap(),
            u64::from(sandbox_protocol::vm_live_memory_charge_mi_b(expected).unwrap())
        );
        assert_eq!(
            slots.try_acquire("a", "refused", 2, size(4096)),
            Err(SandboxErrorCode::VmSizeMismatch)
        );
        slots.try_acquire("b", "unaffected", 1, size(2048)).unwrap();
    }
}

#[test]
fn shrunk_budget_keeps_existing_work_and_cleanup_without_clamping() {
    let dir = tempfile::tempdir().unwrap();
    let j = journal(dir.path());
    let mut slots = LiveSandboxAdmission::new(4, VmCapacity::new(4864, 4).unwrap());
    let mut b = inventory(3072);
    b.sandbox_id = "b".into();
    slots
        .rebuild(&[inventory(3072), b], &j, &binding())
        .unwrap();
    assert_eq!(slots.memory_held_mib().unwrap(), 6784);
    slots.try_acquire("a", "warm", 2, size(3072)).unwrap();
    assert_eq!(slots.memory_held_mib().unwrap(), 6784);
    assert_eq!(
        slots.try_acquire("c", "full", 1, size(512)),
        Err(SandboxErrorCode::HostCapacity)
    );
    slots.finish_allocation("a", "warm", OperationState::Succeeded);
    slots.release_confirmed("a");
    slots.try_acquire("c", "fits", 1, size(1024)).unwrap();
    assert_eq!(slots.memory_held_mib().unwrap(), 4736);
}

#[test]
fn cleanup_watermark_and_expiry_are_generation_fenced_for_weighted_effects() {
    for cleanup_generation in [1, 2, 3] {
        let dir = tempfile::tempdir().unwrap();
        let j = journal(dir.path());
        effect(&j, &dispatch("uncertain", 2, Some(size(3072))));
        let mut kill = dispatch("kill", cleanup_generation, None);
        kill.kind = "sandbox.kill".into();
        kill.digest_scheme = Some("sha256-env-free-v1".into());
        kill.digest_key_id = None;
        j.record_intent(&intent_from_dispatch(&j, &binding(), &kill))
            .unwrap();
        j.record_result(
            "kill",
            OperationState::Succeeded,
            Some(serde_json::json!({"state":"deleted"})),
            None,
            None,
        )
        .unwrap();
        assert!(
            j.confirm(
                &binding(),
                &ReceiptConfirmation {
                    sandbox_owner_id: "owner".into(),
                    operation_id: "kill".into(),
                    sandbox_id: "a".into(),
                    generation: cleanup_generation,
                    attempt: 1,
                    body_hash: kill.body_hash.unwrap(),
                    idempotency_key: "kill".into(),
                    kind: "sandbox.kill".into(),
                    cleanup_generation: None,
                    retire_command: false,
                }
            )
            .unwrap()
        );
        drop(j);
        let j = journal(dir.path());
        let mut slots = LiveSandboxAdmission::new(4, VmCapacity::new(4864, 4).unwrap());
        slots.rebuild(&[], &j, &binding()).unwrap();
        assert_eq!(
            slots.memory_held_mib().unwrap(),
            if cleanup_generation < 2 { 3392 } else { 0 }
        );
        if cleanup_generation < 2 {
            assert!(!slots.release_expired("a", 1));
            assert_eq!(slots.memory_held_mib().unwrap(), 3392);
            assert!(slots.release_expired("a", 2));
        }
    }
}

#[test]
fn pruned_receipt_restart_stop_and_cold_boot_keep_lease_and_runtime_weight() {
    use sandbox_runtime::{
        CreateSandboxRequest, FakeRuntime, ReconnectSandboxRequest, RuntimePermit, SandboxRuntime,
        StopSandboxRequest,
    };
    use std::{
        sync::Mutex,
        time::{Duration, Instant},
    };
    let fake = FakeRuntime::new().with_command_clock(Arc::new(Mutex::new(Instant::now())));
    fake.fixture_root().unwrap();
    let runtime = fake.with_cancellation(Arc::new(RuntimePermit::with_timeout(
        Duration::from_secs(60),
    )));
    let mut create = CreateSandboxRequest::for_test("a", "create");
    create.vm_size = size(3072);
    let dir = tempfile::tempdir().unwrap();
    let mut j = journal(dir.path());
    j.clock = Arc::new(LeaseClock::new(Arc::new(TestClock(
        create.lease.deadline_unix_ms - 14_400_000,
    ))));
    let mut d = dispatch("create", 1, Some(create.vm_size));
    d.lease = Some(create.lease.clone());
    j.record_intent(&intent_from_dispatch(&j, &binding(), &d))
        .unwrap();
    j.accept_fixture_lease(&d).unwrap();
    j.record_effect("create").unwrap();
    runtime.create_fixture(&create).unwrap();
    j.record_result(
        "create",
        OperationState::Succeeded,
        Some(serde_json::json!({"state":"ready"})),
        None,
        None,
    )
    .unwrap();
    j.confirm(
        &binding(),
        &ReceiptConfirmation {
            sandbox_owner_id: "owner".into(),
            operation_id: "create".into(),
            sandbox_id: "a".into(),
            generation: 1,
            attempt: 1,
            body_hash: d.body_hash.unwrap(),
            idempotency_key: "create".into(),
            kind: "sandbox.create".into(),
            cleanup_generation: None,
            retire_command: false,
        },
    )
    .unwrap();
    drop(j);
    let j = journal(dir.path());
    assert!(j.lookup("create").is_none());
    assert_eq!(j.lease("a").unwrap().vm_size, size(3072));
    let mut slots = LiveSandboxAdmission::new(4, VmCapacity::new(4864, 4).unwrap());
    slots
        .rebuild(&runtime.sandbox_inventory().unwrap(), &j, &binding())
        .unwrap();
    assert_eq!(slots.memory_held_mib().unwrap(), 3392);
    runtime
        .stop_sandbox(&StopSandboxRequest {
            sandbox_id: "a".into(),
            instance_name: create.instance_name.clone(),
            template_fingerprint: create.template_digest.clone(),
            operation_id: "stop".into(),
            idempotency_key: "stop".into(),
        })
        .unwrap();
    slots
        .rebuild(&runtime.sandbox_inventory().unwrap(), &j, &binding())
        .unwrap();
    // A VM-only census cannot release a bound live fact. Reconstruction
    // verifies the original pool and stopped VM before publishing that fact.
    assert_eq!(slots.memory_held_mib().unwrap(), 3392);
    let root = j.retained_roots()["a"].root();
    runtime.observe_storage_pool(&root.pool).unwrap();
    assert!(!runtime.sandbox_may_be_running("a").unwrap());
    j.release_retained("a", 1, false).unwrap();
    slots
        .rebuild(&runtime.sandbox_inventory().unwrap(), &j, &binding())
        .unwrap();
    assert_eq!(slots.memory_held_mib().unwrap(), 0);
    slots
        .try_acquire("a", "cold", 2, j.lease("a").unwrap().vm_size)
        .unwrap();
    runtime
        .reconnect_fixture(&ReconnectSandboxRequest {
            vm_size: create.vm_size,
            lease: create.lease,
            template_fingerprint: create.template_digest,
            architecture: create.architecture,
            guest: create.guest,
            sandbox_id: "a".into(),
            instance_name: create.instance_name,
            operation_id: "cold".into(),
            idempotency_key: "cold".into(),
            egress_policy: None,
            egress_policy_hash: None,
            egress_admission: sandbox_runtime::egress::EgressAdmission::PERMITTED,
            guest_sudo: false,
        })
        .unwrap();
    slots.finish_allocation("a", "cold", OperationState::Succeeded);
    assert_eq!(slots.memory_held_mib().unwrap(), 3392);
}

#[test]
fn warm_reconnect_survives_cpu_and_memory_shrink_but_cold_starts_do_not() {
    let dir = tempfile::tempdir().unwrap();
    let j = journal(dir.path());
    let allocation = VmSize::new(4, 4096).unwrap();
    for capacity in [
        VmCapacity::new(8192, 2).unwrap(),
        VmCapacity::new(2048, 4).unwrap(),
    ] {
        let mut slots = LiveSandboxAdmission::new(4, capacity);
        let mut entry = inventory(4096);
        entry.configured_size = ConfiguredSize::Configured(allocation);
        slots.rebuild(&[entry.clone()], &j, &binding()).unwrap();
        slots.try_acquire("a", "warm", 2, allocation).unwrap();
        assert_eq!(slots.memory_held_mib().unwrap(), 4416);
        slots.finish_allocation("a", "warm", OperationState::Succeeded);
        entry.state = SandboxLifecycleState::Stopped;
        slots.rebuild(&[entry], &j, &binding()).unwrap();
        assert_eq!(
            slots.try_acquire("a", "cold", 3, allocation),
            Err(SandboxErrorCode::HostCapacity)
        );
        assert_eq!(
            slots.try_acquire("new", "new", 1, allocation),
            Err(SandboxErrorCode::HostCapacity)
        );
    }
}

#[test]
fn vm_absence_keeps_bound_weight_and_transient_reads_use_fallback_then_retry() {
    let dir = tempfile::tempdir().unwrap();
    let j = journal(dir.path());
    let d = dispatch("uncertain", 1, Some(size(2048)));
    effect(&j, &d);
    j.accept_fixture_lease(&d).unwrap();
    let mut slots = LiveSandboxAdmission::new(4, VmCapacity::new(4864, 4).unwrap());
    let mut entry = inventory(2048);
    entry.configured_size = ConfiguredSize::NoInstance;
    slots.rebuild(&[entry.clone()], &j, &binding()).unwrap();
    // A VM-only 404 does not prove absence on the pinned storage pool.
    assert_eq!(slots.held(), 1);
    assert_eq!(slots.memory_held_mib().unwrap(), 2368);
    slots
        .try_acquire("a", "cleanup-shared", 2, size(2048))
        .unwrap();
    entry.configured_size = ConfiguredSize::Unobserved(RuntimeError::new(
        SandboxErrorCode::Internal,
        "temporary read failure",
    ));
    slots.rebuild(&[entry.clone()], &j, &binding()).unwrap();
    assert_eq!(slots.memory_held_mib().unwrap(), 2368);
    slots.try_acquire("a", "fallback", 2, size(2048)).unwrap();
    entry.configured_size = ConfiguredSize::Configured(size(3072));
    slots.rebuild(&[entry], &j, &binding()).unwrap();
    assert_eq!(slots.memory_held_mib().unwrap(), 3392);
    assert_eq!(
        slots.try_acquire("a", "observed-conflict", 3, size(2048)),
        Err(SandboxErrorCode::VmSizeMismatch)
    );
}

#[test]
fn cpu_only_config_conflict_refuses_only_its_sandbox() {
    let dir = tempfile::tempdir().unwrap();
    let j = journal(dir.path());
    let d = dispatch("cpu", 1, Some(size(2048)));
    effect(&j, &d);
    j.accept_fixture_lease(&d).unwrap();
    let mut entry = inventory(2048);
    entry.configured_size = ConfiguredSize::Configured(VmSize::new(4, 2048).unwrap());
    let mut slots = LiveSandboxAdmission::new(8, VmCapacity::new(4864, 4).unwrap());
    slots.rebuild(&[entry], &j, &binding()).unwrap();
    assert_eq!(slots.memory_held_mib().unwrap(), 2368);
    assert_eq!(
        slots.try_acquire("a", "conflict", 2, size(2048)),
        Err(SandboxErrorCode::VmSizeMismatch)
    );
    slots.try_acquire("b", "unaffected", 1, size(2048)).unwrap();
}

#[test]
fn receipt_only_unknown_create_faces_lowered_caps_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let allocation = VmSize::new(4, 4096).unwrap();
    {
        let j = journal(dir.path());
        let mut slots = LiveSandboxAdmission::new(4, VmCapacity::new(8192, 4).unwrap());
        slots.try_acquire("a", "uncertain", 1, allocation).unwrap();
        effect(&j, &dispatch("uncertain", 1, Some(allocation)));
        slots.finish_allocation("a", "uncertain", OperationState::UnknownOutcome);
        // Same-session acquisitions already passed this session's caps.
        slots
            .try_acquire("a", "same-session", 2, allocation)
            .unwrap();
    }
    let j = journal(dir.path());
    for capacity in [
        VmCapacity::new(2048, 2).unwrap(),
        VmCapacity::new(8192, 2).unwrap(),
        VmCapacity::new(2048, 4).unwrap(),
    ] {
        let mut slots = LiveSandboxAdmission::new(4, capacity);
        slots.rebuild(&[], &j, &binding()).unwrap();
        assert_eq!(slots.memory_held_mib().unwrap(), 4416);
        assert_eq!(
            slots.try_acquire("a", "retry", 2, allocation),
            Err(SandboxErrorCode::HostCapacity),
            "an UNKNOWN receipt without a census VM cannot exempt a cold launch"
        );
        assert_eq!(slots.memory_held_mib().unwrap(), 4416);
    }
}
