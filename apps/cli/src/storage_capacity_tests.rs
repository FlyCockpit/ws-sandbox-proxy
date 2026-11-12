use super::*;
use crate::sandbox_relay::{
    journal::{CrashPoint, HostJournal, TransportBindingV11, intent_from_dispatch},
    live_admission::LiveSandboxAdmission,
};
use sandbox_protocol::{OperationDispatch, OperationState, SandboxErrorCode, VmCapacity};
fn binding() -> TransportBindingV11 {
    TransportBindingV11 {
        server: "wss://example".into(),
        host_owner_id: "owner".into(),
        host_id: "host".into(),
    }
}
fn dispatch(id: &str, pool: &StoragePoolV11) -> OperationDispatch {
    let mut d:OperationDispatch=serde_json::from_value(serde_json::json!({"sandboxOwnerId":"owner", "operationId":id,"sandboxId":id,"kind":"sandbox.create","generation":1,"attempt":1,"idempotencyKey":id,"bodyHash":"a".repeat(64)})).unwrap();
    d.allocation = Some(PinnedAllocationV11 {
        cpu_count: 1,
        memory_mi_b: 512,
        disk_gi_b: 32,
        storage_pool_name: pool.name.clone(),
        storage_marker: pool.marker.clone(),
        charged_memory_mi_b: sandbox_protocol::vm_live_memory_charge_mi_b(512).unwrap(),
        charged_vcpu: 1,
        root_charge_gi_b: sandbox_protocol::vm_root_charge_gi_b(32).unwrap(),
    });
    d
}
#[test]
fn sparse_roots_never_ratchet_167_to_317_and_zero_is_healthy() {
    let gib = GIB_BYTES;
    let initial = derive(
        StorageResources::new(1840 * gib, 1581 * gib).unwrap(),
        0,
        0,
        None,
    )
    .unwrap();
    assert_eq!(initial.capacity_gi_b, 167);
    let sparse = derive(
        StorageResources::new(1840 * gib, 1596 * gib).unwrap(),
        165 * gib,
        15 * gib,
        Some(initial.capacity_gi_b),
    )
    .unwrap();
    assert_eq!(sparse.capacity_gi_b, 167);
    assert_eq!(
        derive(
            StorageResources::new(1840 * gib, 1596 * gib).unwrap(),
            165 * gib,
            0,
            Some(167)
        )
        .unwrap()
        .capacity_gi_b,
        152
    );
    assert_eq!(
        derive(StorageResources::new(1, 1).unwrap(), 0, 0, None)
            .unwrap()
            .capacity_gi_b,
        0
    );
    assert_eq!(
        derive(
            StorageResources::new(100 * gib, 0).unwrap(),
            gib,
            10 * gib,
            None
        )
        .unwrap()
        .actual_bytes,
        gib
    );
    assert!(
        derive(
            StorageResources::new(u64::MAX, 0).unwrap(),
            u64::MAX,
            u64::MAX,
            None
        )
        .is_ok()
    );
}
#[test]
fn ceiling_survives_crash_before_hello_shrink_free_recovery_and_omission() {
    let dir = tempfile::tempdir().unwrap();
    let pool = StoragePoolIdentity {
        name: "default".into(),
        storage_id: "a".repeat(32),
    };
    {
        let j = HostJournal::open(dir.path(), &binding()).unwrap();
        assert!(j.lower_implicit_ceiling(&pool, 167, false).is_err());
        assert_eq!(j.lower_implicit_ceiling(&pool, 167, true).unwrap(), 167);
        assert_eq!(j.lower_implicit_ceiling(&pool, 317, false).unwrap(), 167);
        j.maintain().unwrap();
    }
    let j = HostJournal::open(dir.path(), &binding()).unwrap();
    assert_eq!(j.implicit_ceiling(&pool.storage_id), Some(167));
    assert_eq!(j.lower_implicit_ceiling(&pool, 100, false).unwrap(), 100);
    drop(j);
    let j = HostJournal::open(dir.path(), &binding()).unwrap();
    assert_eq!(j.lower_implicit_ceiling(&pool, 1000, false).unwrap(), 100);
    assert_eq!(j.pool_lineages(), vec![pool]);
}
#[test]
fn explicit_replaces_default_and_unavailable_pool_does_not_hide_siblings() {
    let dir = tempfile::tempdir().unwrap();
    let j = HostJournal::open(dir.path(), &binding()).unwrap();
    let runtime = sandbox_runtime::FakeRuntime::new();
    let cfg = Config {
        storage_pools: vec![
            crate::config::StoragePoolConfig {
                name: "a".into(),
                capacity_gib: 96,
                draining: true,
            },
            crate::config::StoragePoolConfig {
                name: "b".into(),
                capacity_gib: 64,
                draining: false,
            },
        ],
        ..Config::default()
    };
    let pools = connect_pools(&runtime, &cfg, &j).unwrap();
    assert_eq!(pools.len(), 2);
    assert!(pools.iter().all(|p| p.name != "default"));
    assert_eq!(pools[0].capacity_gi_b, 96);
    for p in &pools {
        assert!(j.implicit_ceiling(&p.marker).is_some());
        serde_json::from_value::<StoragePoolV11>(serde_json::to_value(p).unwrap()).unwrap();
    }
    runtime.set_storage_pool_available("a", false);
    let pools = connect_pools(&runtime, &cfg, &j).unwrap();
    assert_eq!(pools[0].health, StorageHealth::Unavailable);
    assert_eq!(pools[1].health, StorageHealth::Healthy);
    let h = observe_health(std::sync::Arc::new(runtime), &pools);
    assert_eq!(h[0].health, StorageHealth::Unavailable);
    assert_eq!(h[1].health, StorageHealth::Healthy);
}
#[test]
fn retained_intent_crash_matrix_stop_prune_restart_and_deleted_tombstone() {
    for crash in [
        CrashPoint::AfterIntent,
        CrashPoint::AfterEffect,
        CrashPoint::AfterResult,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let runtime = sandbox_runtime::FakeRuntime::new();
        let (pool, d) = {
            let j = HostJournal::open(dir.path(), &binding()).unwrap();
            let pool = connect_pools(&runtime, &Config::default(), &j)
                .unwrap()
                .remove(0);
            let d = dispatch("sbx", &pool);
            j.inject_crash(crash);
            let _ = j.record_intent(&intent_from_dispatch(&j, &binding(), &d));
            if crash != CrashPoint::AfterIntent {
                let _ = j.record_effect("sbx");
            }
            if crash == CrashPoint::AfterResult {
                let _ = j.record_result("sbx", OperationState::UnknownOutcome, None, None, None);
            }
            (pool, d)
        };
        let j = HostJournal::open(dir.path(), &binding()).unwrap();
        assert_eq!(j.retained_roots().len(), 1);
        let pinned = j.retained_roots()["sbx"].allocation.clone();
        assert_eq!(pinned, d.allocation.unwrap());
        j.release_retained("sbx", 1, false).unwrap();
        j.maintain().unwrap();
        assert!(!j.retained_roots()["sbx"].live);
        drop(j);
        let j = HostJournal::open(dir.path(), &binding()).unwrap();
        assert_eq!(j.retained_roots().len(), 1);
        j.release_retained("sbx", 1, true).unwrap();
        drop(j);
        let j = HostJournal::open(dir.path(), &binding()).unwrap();
        assert!(j.retained_roots().is_empty());
        assert!(j.implicit_ceiling(&pool.marker).is_some());
    }
}
#[test]
fn zero_disk_cap_allows_retained_cold_start_but_checks_live_budgets_and_pins_charges() {
    let dir = tempfile::tempdir().unwrap();
    let j = HostJournal::open(dir.path(), &binding()).unwrap();
    let runtime = sandbox_runtime::FakeRuntime::new();
    let mut pool = connect_pools(&runtime, &Config::default(), &j)
        .unwrap()
        .remove(0);
    let mut d = dispatch("sbx", &pool);
    j.record_intent(&intent_from_dispatch(&j, &binding(), &d))
        .unwrap();
    j.release_retained("sbx", 1, false).unwrap();
    pool.capacity_gi_b = 0;
    let mut slots = LiveSandboxAdmission::new(8, VmCapacity::new(4096, 4).unwrap());
    slots.rebuild(&[], &j, &binding()).unwrap();
    slots.release_confirmed("sbx");
    slots.set_pools(vec![pool.clone()]);
    let new = dispatch("new", &pool);
    assert_eq!(
        slots.try_acquire_pinned(&new),
        Err(SandboxErrorCode::HostCapacity)
    );
    d.kind = "sandbox.reconnect".into();
    d.operation_id = "cold".into();
    d.generation = 2;
    slots.try_acquire_pinned(&d).unwrap();
    assert_eq!(
        slots.memory_held_mib().unwrap(),
        u64::from(d.allocation.as_ref().unwrap().charged_memory_mi_b)
    );
    assert_eq!(slots.vcpu_held(), 1);
    let mut forged = d.clone();
    forged.allocation.as_mut().unwrap().charged_memory_mi_b = 512;
    assert_eq!(
        slots.try_acquire_pinned(&forged),
        Err(SandboxErrorCode::VmSizeMismatch)
    );
    slots.expire_storage_health();
    assert_eq!(
        slots.try_acquire_pinned(&d),
        Err(SandboxErrorCode::HostCapacity)
    );
}
#[test]
fn four_small_guests_pay_overhead_and_vcpu_is_independent() {
    let mut slots = LiveSandboxAdmission::new(4, VmCapacity::new(3328, 4).unwrap());
    for id in ["a", "b", "c", "d"] {
        slots
            .try_acquire(id, id, 1, sandbox_protocol::VmSize::new(1, 512).unwrap())
            .unwrap();
    }
    assert_eq!(
        slots.memory_held_mib().unwrap(),
        4 * u64::from(sandbox_protocol::vm_live_memory_charge_mi_b(512).unwrap())
    );
    assert_eq!(slots.vcpu_held(), 4);
    assert_eq!(
        slots.try_acquire("e", "e", 1, sandbox_protocol::VmSize::new(1, 512).unwrap()),
        Err(SandboxErrorCode::HostCapacity)
    );
}

#[test]
fn retained_guard_includes_stopped_roots_and_cleanup_releases_exactly_once() {
    let dir = tempfile::tempdir().unwrap();
    let j = HostJournal::open(dir.path(), &binding()).unwrap();
    let runtime = sandbox_runtime::FakeRuntime::new();
    let mut pool = connect_pools(&runtime, &Config::default(), &j)
        .unwrap()
        .remove(0);
    pool.capacity_gi_b = 1_000_000;
    let mut slots = LiveSandboxAdmission::new(8192, VmCapacity::new(16777216, 32).unwrap());
    slots.set_pools(vec![pool.clone()]);
    let ceiling = sandbox_protocol::vm_size_limits()
        .unwrap()
        .host_managed_sandbox_ceiling;
    for n in 0..ceiling {
        let d = dispatch(&format!("s{n}"), &pool);
        slots.try_acquire_pinned(&d).unwrap();
        slots.finish_allocation(&d.sandbox_id, &d.operation_id, OperationState::Succeeded);
        slots.release_confirmed(&d.sandbox_id);
    }
    assert_eq!(slots.held(), 0);
    assert_eq!(
        slots.try_acquire_pinned(&dispatch("next", &pool)),
        Err(SandboxErrorCode::HostCapacity)
    );
    slots.release_root_confirmed("s0", 0);
    assert_eq!(
        slots.try_acquire_pinned(&dispatch("next", &pool)),
        Err(SandboxErrorCode::HostCapacity)
    );
    slots.release_root_confirmed("s0", 1);
    slots.release_root_confirmed("s0", 1);
    slots.try_acquire_pinned(&dispatch("next", &pool)).unwrap();
    assert_eq!(
        slots.try_acquire_pinned(&dispatch("too-many", &pool)),
        Err(SandboxErrorCode::HostCapacity)
    );
}
#[test]
fn observations_change_health_without_repricing_frozen_caps_and_frames_share_tuple() {
    let dir = tempfile::tempdir().unwrap();
    let j = HostJournal::open(dir.path(), &binding()).unwrap();
    let runtime = std::sync::Arc::new(sandbox_runtime::FakeRuntime::new());
    let pools = connect_pools(runtime.as_ref(), &Config::default(), &j).unwrap();
    let capacity = HostStaticCapacityV11 {
        vm_capacity: VmCapacityV11 {
            memory_budget_mi_b: 4096,
            max_cpu_count: 4,
            vcpu_budget: 8,
        },
        storage_pools: pools.clone(),
    };
    let fixture: HostHelloV11 = serde_json::from_str(include_str!(
        "../../../crates/sandbox-protocol/fixtures/control_hello_daemon.json"
    ))
    .unwrap();
    let hello = hello_frame(fixture.daemon, true, 0, &capacity);
    let admission = admission_frame(
        &j,
        1,
        sandbox_protocol::RuntimeKind::Fake,
        false,
        false,
        &capacity,
    );
    assert_eq!(hello.vm_capacity, admission.vm_capacity);
    assert_eq!(hello.storage_pools, admission.storage_pools);
    serde_json::from_value::<HostHelloV11>(serde_json::to_value(&hello).unwrap()).unwrap();
    serde_json::from_value::<HostAdmissionV11>(serde_json::to_value(&admission).unwrap()).unwrap();
    assert!(sandbox_protocol::known_protocol_version("1.0"));
    let health = observe_health(runtime.clone(), &pools);
    let report = inventory_frame("host", 1, 1, 0, health.clone());
    serde_json::from_value::<HostInventoryUpdateV11>(serde_json::to_value(report).unwrap())
        .unwrap();
    let mut holds = LiveSandboxAdmission::new(8, VmCapacity::new(4096, 4).unwrap());
    holds.set_pools(pools.clone());
    holds.update_health(&health);
    holds.expire_storage_health();
    holds.update_health(&health);
    assert_eq!(j.pool_snapshot(&pools[0].marker).unwrap(), pools[0]);
    let mut unavailable = pools.clone();
    unavailable[0].health = StorageHealth::Unavailable;
    let mut unproven = LiveSandboxAdmission::new(8, VmCapacity::new(4096, 4).unwrap());
    unproven.set_pools(unavailable);
    unproven.update_health(&health);
    assert_eq!(
        unproven.try_acquire_pinned(&dispatch("unproven", &pools[0])),
        Err(SandboxErrorCode::HostCapacity)
    );
    runtime.set_storage_pool_available(&pools[0].name, false);
    let health = observe_health(runtime, &pools);
    holds.update_health(&health);
    assert_eq!(
        holds.try_acquire_pinned(&dispatch("bad", &pools[0])),
        Err(SandboxErrorCode::HostCapacity)
    );
}

#[test]
fn offline_pool_vm_only_absence_preserves_live_and_root_charges_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let j = HostJournal::open(dir.path(), &binding()).unwrap();
    let runtime = sandbox_runtime::FakeRuntime::new();
    let pool = connect_pools(&runtime, &Config::default(), &j)
        .unwrap()
        .remove(0);
    let d = dispatch("sbx", &pool);
    j.record_intent(&intent_from_dispatch(&j, &binding(), &d))
        .unwrap();
    j.record_effect("sbx").unwrap();
    runtime.set_storage_pool_available(&pool.name, false);
    reconstruct_live(&runtime, &j).unwrap();
    let mut holds = LiveSandboxAdmission::new(8, VmCapacity::new(4096, 4).unwrap());
    let inventory = [sandbox_runtime::RuntimeInventoryEntry {
        sandbox_id: "sbx".into(),
        state: sandbox_protocol::SandboxLifecycleState::Unreachable,
        configured_size: sandbox_runtime::ConfiguredSize::NoInstance,
    }];
    holds.rebuild(&inventory, &j, &binding()).unwrap();
    assert_eq!(
        holds.memory_held_mib().unwrap(),
        u64::from(d.allocation.as_ref().unwrap().charged_memory_mi_b)
    );
    assert_eq!(holds.vcpu_held(), 1);
    assert_eq!(j.retained_roots().len(), 1);
    runtime.set_storage_pool_available(&pool.name, true);
    reconstruct_live(&runtime, &j).unwrap();
    holds.rebuild(&inventory, &j, &binding()).unwrap();
    assert_eq!(holds.held(), 0);
    assert_eq!(j.retained_roots().len(), 1);
}

#[test]
fn crash_after_root_before_receipt_reclaims_only_positive_absence_and_allows_original_retry() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = sandbox_runtime::FakeRuntime::new();
    let d = {
        let j = HostJournal::open(dir.path(), &binding()).unwrap();
        let pool = connect_pools(&runtime, &Config::default(), &j)
            .unwrap()
            .remove(0);
        let d = dispatch("sbx", &pool);
        j.inject_crash(CrashPoint::AfterRetainedRoot);
        assert!(
            j.record_intent(&intent_from_dispatch(&j, &binding(), &d))
                .is_err()
        );
        assert!(j.lookup("sbx").is_none());
        d
    };
    let j = HostJournal::open(dir.path(), &binding()).unwrap();
    assert_eq!(j.retained_roots().len(), 1);
    runtime.set_storage_pool_available(&d.allocation.as_ref().unwrap().storage_pool_name, false);
    reconstruct_live(&runtime, &j).unwrap();
    assert_eq!(j.retained_roots().len(), 1);
    runtime.set_storage_pool_available(&d.allocation.as_ref().unwrap().storage_pool_name, true);
    reconstruct_live(&runtime, &j).unwrap();
    assert!(j.retained_roots().is_empty());
    j.record_intent(&intent_from_dispatch(&j, &binding(), &d))
        .unwrap();
    assert_eq!(j.retained_roots().len(), 1);
}

/// §4.9 / MUST-DO 8: a create queued behind the effect gate when the relay
/// dropped has a receipt (so `unissued_root` already refuses the never-issued
/// release) but no worker holds `lease_work` yet and no VM exists. Only the
/// carried-set fence keeps reconnect recovery from releasing its live hold.
#[test]
fn carried_intent_create_keeps_its_live_hold_through_reconnect_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let j = HostJournal::open(dir.path(), &binding()).unwrap();
    let runtime = sandbox_runtime::FakeRuntime::new();
    let pool = connect_pools(&runtime, &Config::default(), &j)
        .unwrap()
        .remove(0);
    let d = dispatch("sbx", &pool);
    j.record_intent(&intent_from_dispatch(&j, &binding(), &d))
        .unwrap();
    assert!(!j.root_never_issued("sbx", 1), "a receipt exists");
    let busy = std::collections::HashSet::from(["sbx".to_string()]);
    reconstruct_live_except(&runtime, &j, &busy).unwrap();
    assert!(
        j.retained_roots()["sbx"].live,
        "carried create keeps its hold"
    );
    let mut holds = LiveSandboxAdmission::new(8, VmCapacity::new(4096, 4).unwrap());
    holds.rebuild(&[], &j, &binding()).unwrap();
    assert_eq!(holds.held(), 1, "the reconnect still charges it");
    // Without the fence, the same absence would release the live charge.
    reconstruct_live(&runtime, &j).unwrap();
    assert!(!j.retained_roots()["sbx"].live);
}

#[test]
fn shutdown_interrupted_census_is_not_reported_as_damaged_storage() {
    // R2-2: the verdict comes from whether the census was interrupted, never
    // from the error text. The fake's unavailable-pool error matches none of
    // the old text patterns, just like `internal: … marker is incomplete`.
    for interrupted in [true, false] {
        let (pools, logs) = crate::logging::with_subscriber(
            crate::cli::LogFormat::Text,
            tracing_subscriber::EnvFilter::new("info"),
            || {
                let dir = tempfile::tempdir().unwrap();
                let j = HostJournal::open(dir.path(), &binding()).unwrap();
                let runtime = sandbox_runtime::FakeRuntime::new();
                runtime.set_storage_pool_available("default", false);
                connect_pools_until(&runtime, &Config::default(), &j, &|| interrupted).unwrap()
            },
        );
        let logs = String::from_utf8(logs).unwrap();
        assert!(
            pools.is_empty(),
            "an unbound pool has no identity to advertise"
        );
        assert_eq!(
            logs.contains("the census was interrupted"),
            interrupted,
            "{logs}"
        );
        assert_eq!(logs.contains("storage unavailable"), !interrupted, "{logs}");
    }
}

#[test]
fn image_cache_reserve_is_carved_out_of_available_capacity() {
    const GIB: u64 = 1 << 30;
    let resources = StorageResources::new(1000 * GIB, 800 * GIB).unwrap();
    let plain = derive(resources, 0, 0, None).unwrap();
    let carved = derive_with_image_reserve(resources, 0, 0, None, 100 * GIB).unwrap();
    assert!(
        carved.capacity_gi_b + 100 <= plain.capacity_gi_b.max(100)
            || carved.capacity_gi_b < plain.capacity_gi_b
    );
    assert_eq!(
        carved.total_based_capacity_gi_b,
        plain.total_based_capacity_gi_b
    );
    // A reserve larger than what is free leaves no capacity, never an underflow.
    let exhausted = derive_with_image_reserve(resources, 0, 0, None, 2000 * GIB).unwrap();
    assert_eq!(exhausted.capacity_gi_b, 0);
}
