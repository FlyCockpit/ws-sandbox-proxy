use sandbox_protocol::{SandboxErrorCode, SandboxLifecycleState};
use sandbox_runtime::{
    CreateSandboxRequest, EnforcementLossStage, FakePolicyDrift, FakeRuntime, ReadFileRequest,
    SandboxRuntime,
};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "wssp-c38-policy-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn ids() -> Vec<String> {
    vec!["sbx-1".into()]
}
fn read() -> ReadFileRequest {
    ReadFileRequest {
        sandbox_owner_id: "owner".into(),
        template_fingerprint: CreateSandboxRequest::for_test("sbx-1", "key").template_digest,
        guest: Default::default(),
        sandbox_id: "sbx-1".into(),
        instance_name: "wssp-sbx-sbx-1".into(),
        operation_id: "read".into(),
        idempotency_key: "read".into(),
        path: "/tmp/x".into(),
    }
}

#[test]
fn fake_policy_drift_is_durable_before_dispatch_and_restart_resumes_cleanup() {
    for drift in [
        FakePolicyDrift::Acl,
        FakePolicyDrift::Network,
        FakePolicyDrift::Nic,
    ] {
        let fixture = Fixture::new();
        let runtime = FakeRuntime::new()
            .with_policy_state_dir(fixture.0.clone())
            .unwrap();
        runtime
            .create_sandbox_on_storage(
                &CreateSandboxRequest::for_test("sbx-1", "key"),
                &runtime.fixture_root().expect("fixture root"),
            )
            .unwrap();
        runtime.inject_policy_drift("sbx-1", Some(drift));
        runtime.reconcile_policies(&ids()).unwrap();
        assert_eq!(
            runtime.sandbox_inventory().unwrap()[0].state,
            SandboxLifecycleState::Stopped
        );
        assert!(
            runtime.read_file(&read()).is_err(),
            "no further operation dispatch"
        );
        assert!(fixture.0.join("enforcement-losses/sbx-1.json").exists());
        let restarted = runtime.restart_policy_reconciler().unwrap();
        assert_eq!(restarted.policy_reconciler_health().drift, 1);
        let stages = std::cell::RefCell::new(Vec::new());
        restarted
            .drain_enforcement_losses(&|_, stage| {
                stages.borrow_mut().push(stage);
                Ok(())
            })
            .unwrap();
        assert_eq!(
            *stages.borrow(),
            [
                EnforcementLossStage::Prepare,
                EnforcementLossStage::Complete
            ]
        );
        assert!(restarted.sandbox_inventory().unwrap().is_empty());
        assert!(!fixture.0.join("enforcement-losses/sbx-1.json").exists());
    }
}

#[test]
fn fake_policy_foreign_inconclusive_and_verified_controls_do_not_stop_or_delete() {
    for drift in [
        Some(FakePolicyDrift::Foreign),
        Some(FakePolicyDrift::Inconclusive),
        None,
    ] {
        let fixture = Fixture::new();
        let runtime = FakeRuntime::new()
            .with_policy_state_dir(fixture.0.clone())
            .unwrap();
        runtime
            .create_sandbox_on_storage(
                &CreateSandboxRequest::for_test("sbx-1", "key"),
                &runtime.fixture_root().expect("fixture root"),
            )
            .unwrap();
        runtime.inject_policy_drift("sbx-1", drift);
        runtime.reconcile_policies(&ids()).unwrap();
        runtime
            .drain_enforcement_losses(&|_, _| {
                panic!("no lifecycle authority requested for controls")
            })
            .unwrap();
        assert_eq!(
            runtime.sandbox_inventory().unwrap()[0].state,
            SandboxLifecycleState::Ready
        );
        assert!(!fixture.0.join("enforcement-losses/sbx-1.json").exists());
        let health = runtime.policy_reconciler_health();
        assert_eq!(
            health.foreign,
            u32::from(drift == Some(FakePolicyDrift::Foreign))
        );
        assert_eq!(
            health.inconclusive,
            u32::from(drift == Some(FakePolicyDrift::Inconclusive))
        );
        if drift.is_some() {
            assert_eq!(
                runtime.read_file(&read()).unwrap_err().code,
                SandboxErrorCode::Internal
            );
        }
        let body = std::fs::read_to_string(fixture.0.join("state.json")).unwrap();
        assert!(body.contains("sbx-1"), "refusal is journaled");
    }
}

#[test]
fn fake_policy_cleanup_checkpoint_vetoes_and_absent_restart_retry() {
    let fixture = Fixture::new();
    let runtime = FakeRuntime::new()
        .with_policy_state_dir(fixture.0.clone())
        .unwrap();
    runtime
        .create_sandbox_on_storage(
            &CreateSandboxRequest::for_test("sbx-1", "key"),
            &runtime.fixture_root().expect("fixture root"),
        )
        .unwrap();
    runtime.inject_policy_drift("sbx-1", Some(FakePolicyDrift::Acl));
    runtime.reconcile_policies(&ids()).unwrap();
    let veto = || sandbox_runtime::RuntimeError::new(SandboxErrorCode::Internal, "checkpoint veto");
    runtime
        .drain_enforcement_losses(&|_, _| Err(veto()))
        .unwrap_err();
    assert_eq!(
        runtime.sandbox_inventory().unwrap().len(),
        1,
        "no destruction without Prepare"
    );
    runtime
        .drain_enforcement_losses(&|_, stage| {
            if stage == EnforcementLossStage::Complete {
                Err(veto())
            } else {
                Ok(())
            }
        })
        .unwrap_err();
    assert!(runtime.sandbox_inventory().unwrap().is_empty());
    assert!(
        fixture.0.join("enforcement-losses/sbx-1.json").exists(),
        "no retirement without Complete"
    );
    let restarted = runtime.restart_policy_reconciler().unwrap();
    restarted.drain_enforcement_losses(&|_, _| Ok(())).unwrap();
    assert!(!fixture.0.join("enforcement-losses/sbx-1.json").exists());
}

#[test]
fn fake_policy_bounded_rotation_and_failure_isolation_reach_all_candidates() {
    let fixture = Fixture::new();
    let runtime = FakeRuntime::new()
        .with_policy_state_dir(fixture.0.clone())
        .unwrap();
    let ids: Vec<_> = (0..35).map(|n| format!("sbx-{n:03}")).collect();
    for id in &ids {
        runtime
            .create_sandbox_on_storage(
                &CreateSandboxRequest::for_test(id, id),
                &runtime.fixture_root().expect("fixture root"),
            )
            .unwrap();
        runtime.inject_policy_drift(id, Some(FakePolicyDrift::Acl));
    }
    runtime.reconcile_policies(&ids).unwrap();
    assert_eq!(runtime.policy_reconciler_health().drift, 16);
    // Cursor/observations must survive restart, not just process-local state.
    let runtime = runtime.restart_policy_reconciler().unwrap();
    for pass in 2..=3 {
        runtime.reconcile_policies(&ids).unwrap();
        assert_eq!(
            runtime.policy_reconciler_health().drift,
            (pass * 16).min(35)
        );
    }
    // A retained failing first record cannot prevent later records completing.
    runtime
        .drain_enforcement_losses(&|id, _| {
            if id == "sbx-000" {
                Err(sandbox_runtime::RuntimeError::new(
                    SandboxErrorCode::Internal,
                    "persistently failing",
                ))
            } else {
                Ok(())
            }
        })
        .ok();
    assert!(runtime.sandbox_inventory().unwrap().len() < 35);
    for _ in 0..3 {
        let _ = runtime.drain_enforcement_losses(&|id, _| {
            if id == "sbx-000" {
                Err(sandbox_runtime::RuntimeError::new(
                    SandboxErrorCode::Internal,
                    "persistently failing",
                ))
            } else {
                Ok(())
            }
        });
    }
    assert_eq!(runtime.sandbox_inventory().unwrap().len(), 1);
    runtime.drain_enforcement_losses(&|_, _| Ok(())).unwrap();
    assert!(runtime.sandbox_inventory().unwrap().is_empty());
}

#[test]
fn fake_policy_observer_failure_is_inconclusive_and_does_not_abort_the_batch() {
    let fixture = Fixture::new();
    let runtime = FakeRuntime::new()
        .with_policy_state_dir(fixture.0.clone())
        .unwrap()
        .with_lifecycle_hook(|stage| {
            if stage == "policy-observe:sbx-0" {
                Err(sandbox_runtime::RuntimeError::new(
                    SandboxErrorCode::Internal,
                    "unreadable first candidate",
                ))
            } else {
                Ok(())
            }
        });
    for id in ["sbx-0", "sbx-1"] {
        runtime
            .create_sandbox_on_storage(
                &CreateSandboxRequest::for_test(id, id),
                &runtime.fixture_root().expect("fixture root"),
            )
            .unwrap();
        runtime.inject_policy_drift(id, Some(FakePolicyDrift::Acl));
    }
    runtime
        .reconcile_policies(&["sbx-0".into(), "sbx-1".into()])
        .unwrap();
    let health = runtime.policy_reconciler_health();
    assert_eq!(health.inconclusive, 1);
    assert_eq!(health.drift, 1);
    let rows = runtime.sandbox_inventory().unwrap();
    assert_eq!(
        rows.iter()
            .find(|entry| entry.sandbox_id == "sbx-0")
            .unwrap()
            .state,
        SandboxLifecycleState::Ready
    );
    assert_eq!(
        rows.iter()
            .find(|entry| entry.sandbox_id == "sbx-1")
            .unwrap()
            .state,
        SandboxLifecycleState::Stopped
    );
}

#[test]
fn fake_policy_cleanup_rechecks_positive_evidence_immediately_before_mutation() {
    for replacement in [
        None,
        Some(FakePolicyDrift::Foreign),
        Some(FakePolicyDrift::Inconclusive),
    ] {
        let fixture = Fixture::new();
        let runtime = FakeRuntime::new()
            .with_policy_state_dir(fixture.0.clone())
            .unwrap();
        runtime
            .create_sandbox_on_storage(
                &CreateSandboxRequest::for_test("sbx-1", "key"),
                &runtime.fixture_root().expect("fixture root"),
            )
            .unwrap();
        runtime.inject_policy_drift("sbx-1", Some(FakePolicyDrift::Acl));
        runtime.reconcile_policies(&ids()).unwrap();
        let external = runtime.clone();
        let runtime = runtime.with_lifecycle_hook(move |stage| {
            if stage == "policy-destroy:sbx-1" {
                external.inject_policy_drift("sbx-1", replacement);
            }
            Ok(())
        });
        runtime.drain_enforcement_losses(&|_, _| Ok(())).unwrap();
        assert_eq!(
            runtime.sandbox_inventory().unwrap().len(),
            1,
            "never delete fresh healthy/foreign/inconclusive state"
        );
        assert!(
            fixture.0.join("enforcement-losses/sbx-1.json").exists(),
            "a veto cannot publish completion"
        );
        runtime.inject_policy_drift("sbx-1", None);
        runtime.drain_enforcement_losses(&|_, _| Ok(())).unwrap();
        assert_eq!(runtime.sandbox_inventory().unwrap().len(), 1);
        assert!(
            !fixture.0.join("enforcement-losses/sbx-1.json").exists(),
            "verified recovery retires without deleting"
        );
    }
}
