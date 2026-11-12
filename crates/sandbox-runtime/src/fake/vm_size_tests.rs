use super::*;

#[test]
fn create_refusal_requires_first_attempt_and_actual_absence() {
    for first_attempt in [true, false] {
        for leftover_key in [false, true] {
            let runtime = FakeRuntime::new();
            let mut create = CreateSandboxRequest::for_test("refused", "create");
            create.first_attempt = first_attempt;
            if leftover_key {
                runtime
                    .state
                    .lock()
                    .unwrap()
                    .create_idempotency
                    .insert(create.idempotency_key.clone(), create.sandbox_id.clone());
            }
            // A definite validation refusal, before any fake VM is inserted.
            create.guest.guest_uid = 0;
            let error = runtime.create_fixture(&create).unwrap_err();
            assert_eq!(error.code, SandboxErrorCode::ProtocolError);
            assert_eq!(
                error.state(),
                if first_attempt {
                    sandbox_protocol::OperationState::Failed
                } else {
                    sandbox_protocol::OperationState::UnknownOutcome
                },
                "first={first_attempt}, leftover_key={leftover_key}"
            );
            assert!(!runtime.sandbox_exists(&create.sandbox_id).unwrap());
        }
    }
}

#[test]
fn create_refusal_with_existence_error_stays_unknown() {
    let runtime = FakeRuntime::new().with_inventory_hook(|stage| {
        assert_eq!(stage, "exists");
        Err(RuntimeError::new(
            SandboxErrorCode::Internal,
            "lookup unavailable",
        ))
    });
    let mut create = CreateSandboxRequest::for_test("refused", "create");
    create.guest.guest_uid = 0;
    let error = runtime.create_fixture(&create).unwrap_err();
    assert_eq!(error.code, SandboxErrorCode::ProtocolError);
    assert_eq!(
        error.state(),
        sandbox_protocol::OperationState::UnknownOutcome
    );
}

#[test]
fn leftover_create_key_after_kill_is_not_an_existing_vm() {
    let runtime = FakeRuntime::new();
    let create = CreateSandboxRequest::for_test("leftover", "create");
    runtime.create_fixture(&create).unwrap();
    runtime
        .kill_fixture(&KillSandboxRequest {
            sandbox_id: create.sandbox_id.clone(),
            instance_name: create.instance_name.clone(),
            template_fingerprint: create.template_digest.clone(),
            operation_id: "kill".into(),
            idempotency_key: "kill".into(),
        })
        .unwrap();
    assert!(
        runtime
            .state
            .lock()
            .unwrap()
            .create_idempotency
            .contains_key("create")
    );
    assert!(!runtime.sandbox_exists("leftover").unwrap());
    runtime
        .create_fixture(&create)
        .expect("an absent VM takes the fresh path despite its old key");
    assert!(runtime.sandbox_exists("leftover").unwrap());
}
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[test]
fn allocation_survives_stop_and_refuses_create_retry_and_reconnect_drift() {
    let fake = FakeRuntime::new();
    let runtime = fake.with_cancellation(Arc::new(crate::RuntimePermit::with_test_clock(
        Duration::from_secs(60),
        Arc::new(Mutex::new(Instant::now())),
    )));
    let mut create = CreateSandboxRequest::for_test("sized", "sized-create");
    create.vm_size = sandbox_protocol::VmSize::new(2, 2048).unwrap();
    runtime.create_fixture(&create).unwrap();
    assert_eq!(
        runtime.sandbox_inventory().unwrap()[0].configured_size,
        crate::ConfiguredSize::Configured(create.vm_size)
    );
    runtime.create_fixture(&create).unwrap();
    let reconnect = ReconnectSandboxRequest {
        vm_size: create.vm_size,
        lease: create.lease.clone(),
        template_fingerprint: create.template_digest.clone(),
        architecture: create.architecture.clone(),
        guest: create.guest.clone(),
        sandbox_id: create.sandbox_id.clone(),
        instance_name: create.instance_name.clone(),
        operation_id: "reconnect".into(),
        idempotency_key: "reconnect".into(),
        egress_policy: None,
        egress_policy_hash: None,
        egress_admission: crate::egress::EgressAdmission::PERMITTED,
        guest_sudo: false,
    };
    runtime.reconnect_fixture(&reconnect).unwrap();
    runtime
        .stop_sandbox(&StopSandboxRequest {
            template_fingerprint: create.template_digest.clone(),
            sandbox_id: create.sandbox_id.clone(),
            instance_name: create.instance_name.clone(),
            operation_id: "stop".into(),
            idempotency_key: "stop".into(),
        })
        .unwrap();
    assert_eq!(
        runtime.sandbox_inventory().unwrap()[0].state,
        SandboxLifecycleState::Stopped
    );
    runtime.reconnect_fixture(&reconnect).unwrap();
    create.vm_size = sandbox_protocol::VmSize::new(4, 4096).unwrap();
    assert_eq!(
        runtime.create_fixture(&create).unwrap_err().code,
        SandboxErrorCode::VmSizeMismatch
    );
    let changed = ReconnectSandboxRequest {
        vm_size: create.vm_size,
        ..reconnect
    };
    assert_eq!(
        runtime.reconnect_fixture(&changed).unwrap_err().code,
        SandboxErrorCode::VmSizeMismatch
    );
    assert_eq!(
        runtime.sandbox_inventory().unwrap()[0].configured_size,
        crate::ConfiguredSize::Configured(sandbox_protocol::VmSize::new(2, 2048).unwrap())
    );
    assert_eq!(
        runtime.host_resources().unwrap(),
        crate::HostResources::new(8 * 1024 * 1024 * 1024, 4).unwrap()
    );
}

#[test]
fn forged_invalid_allocation_has_no_fake_effect() {
    for (cpu_count, memory_mi_b) in [(0, 1024), (33, 1024), (1, 513), (1, u32::MAX)] {
        let runtime = FakeRuntime::new();
        let mut create = CreateSandboxRequest::for_test("invalid", "invalid");
        create.vm_size = sandbox_protocol::VmSize {
            cpu_count,
            memory_mi_b,
        };
        assert_eq!(
            runtime.create_fixture(&create).unwrap_err().code,
            SandboxErrorCode::ProtocolError
        );
        assert!(runtime.sandbox_inventory().unwrap().is_empty());
    }
}

#[test]
fn identity_conflicts_precede_size_mismatch_on_reconnect_and_create_retry() {
    let runtime = FakeRuntime::new();
    let mut create = CreateSandboxRequest::for_test("identity", "identity-create");
    runtime.create_fixture(&create).unwrap();
    let wrong_size = sandbox_protocol::VmSize::new(2, 2048).unwrap();
    let reconnect = ReconnectSandboxRequest {
        vm_size: wrong_size,
        lease: create.lease.clone(),
        template_fingerprint: create.template_digest.clone(),
        architecture: create.architecture.clone(),
        guest: create.guest.clone(),
        sandbox_id: "absent".into(),
        instance_name: crate::default_incus_instance_name("absent"),
        operation_id: "reconnect".into(),
        idempotency_key: "reconnect".into(),
        egress_policy: None,
        egress_policy_hash: None,
        egress_admission: crate::egress::EgressAdmission::PERMITTED,
        guest_sudo: false,
    };
    assert_eq!(
        runtime.reconnect_fixture(&reconnect).unwrap_err().code,
        SandboxErrorCode::IdempotencyConflict
    );
    let foreign = format!("sha256:{}", "f".repeat(64));
    let reconnect = ReconnectSandboxRequest {
        sandbox_id: create.sandbox_id.clone(),
        instance_name: create.instance_name.clone(),
        template_fingerprint: foreign.clone(),
        ..reconnect
    };
    assert_eq!(
        runtime.reconnect_fixture(&reconnect).unwrap_err().code,
        SandboxErrorCode::IdempotencyConflict
    );
    // Foreign-owner drift is also identity evidence, even when the template
    // itself still matches. It must retain the pre-size conflict precedence.
    runtime.inject_policy_drift("identity", Some(FakePolicyDrift::Foreign));
    let owned_template = ReconnectSandboxRequest {
        template_fingerprint: create.template_digest.clone(),
        ..reconnect
    };
    assert_eq!(
        runtime.reconnect_fixture(&owned_template).unwrap_err().code,
        SandboxErrorCode::IdempotencyConflict
    );
    create.vm_size = wrong_size;
    assert_eq!(
        runtime.create_fixture(&create).unwrap_err().code,
        SandboxErrorCode::IdempotencyConflict
    );
    runtime.inject_policy_drift("identity", None);
    create.template_digest = foreign.clone();
    create.incus_fingerprint = Some(foreign);
    assert_eq!(
        runtime.create_fixture(&create).unwrap_err().code,
        SandboxErrorCode::IdempotencyConflict
    );
    assert_eq!(
        runtime.sandbox_inventory().unwrap()[0].configured_size,
        crate::ConfiguredSize::Configured(sandbox_protocol::VmSize::defaults().unwrap())
    );
}

#[test]
fn existing_vm_refusals_are_unknown_in_both_power_states() {
    for stopped in [false, true] {
        for refusal in [
            "size",
            "template",
            "owner",
            "readiness",
            "create-key",
            "policy",
        ] {
            let runtime = FakeRuntime::new();
            let mut create = CreateSandboxRequest::for_test("existing", "create");
            runtime.create_fixture(&create).unwrap();
            if stopped {
                runtime
                    .stop_sandbox(&StopSandboxRequest {
                        template_fingerprint: create.template_digest.clone(),
                        sandbox_id: create.sandbox_id.clone(),
                        instance_name: create.instance_name.clone(),
                        operation_id: "stop".into(),
                        idempotency_key: "stop".into(),
                    })
                    .unwrap();
            }
            match refusal {
                "size" => create.vm_size = sandbox_protocol::VmSize::new(2, 2048).unwrap(),
                "template" => {
                    create.template_digest = format!("sha256:{}", "f".repeat(64));
                    create.incus_fingerprint = Some(create.template_digest.clone());
                }
                "owner" => runtime.inject_policy_drift("existing", Some(FakePolicyDrift::Foreign)),
                "readiness" => create.architecture = Some("aarch64".into()),
                "create-key" => create.idempotency_key = "different".into(),
                "policy" => runtime.inject_policy_drift("existing", Some(FakePolicyDrift::Acl)),
                _ => unreachable!(),
            }
            let before = runtime.sandbox_inventory().unwrap();
            let error = runtime.create_fixture(&create).unwrap_err();
            assert!(
                matches!(error, crate::EffectError::Unknown(_)),
                "{refusal}, stopped={stopped}: {error:?}"
            );
            assert_eq!(error.state(), OperationState::UnknownOutcome);
            // A reconnect does not compare a new create idempotency key.
            if refusal != "create-key" {
                let error = runtime
                    .reconnect_fixture(&ReconnectSandboxRequest {
                        vm_size: create.vm_size,
                        lease: create.lease.clone(),
                        template_fingerprint: create.template_digest.clone(),
                        architecture: create.architecture.clone(),
                        guest: create.guest.clone(),
                        sandbox_id: create.sandbox_id.clone(),
                        instance_name: create.instance_name.clone(),
                        operation_id: "reconnect".into(),
                        idempotency_key: "reconnect".into(),
                        egress_policy: None,
                        egress_policy_hash: None,
                        egress_admission: crate::egress::EgressAdmission::PERMITTED,
                        guest_sudo: false,
                    })
                    .unwrap_err();
                assert!(
                    matches!(error, crate::EffectError::Unknown(_)),
                    "{refusal}, stopped={stopped}: {error:?}"
                );
                assert_eq!(error.state(), OperationState::UnknownOutcome);
            }
            assert_eq!(
                runtime.sandbox_inventory().unwrap(),
                before,
                "refusal must not mutate the VM"
            );
        }
    }
}

trait FixtureRuntime {
    fn create_fixture(
        &self,
        r: &crate::CreateSandboxRequest,
    ) -> crate::EffectOutcome<crate::CreateSandboxResponse>;
    fn reconnect_fixture(
        &self,
        r: &crate::ReconnectSandboxRequest,
    ) -> crate::EffectOutcome<crate::ReconnectSandboxResponse>;
}
impl FixtureRuntime for dyn crate::SandboxRuntime {
    fn create_fixture(
        &self,
        r: &crate::CreateSandboxRequest,
    ) -> crate::EffectOutcome<crate::CreateSandboxResponse> {
        self.create_sandbox_on_storage(r, &fixture_root(self)?)
    }
    fn reconnect_fixture(
        &self,
        r: &crate::ReconnectSandboxRequest,
    ) -> crate::EffectOutcome<crate::ReconnectSandboxResponse> {
        self.reconnect_sandbox_on_storage(r, &fixture_root(self)?)
    }
}
fn fixture_root(
    runtime: &dyn crate::SandboxRuntime,
) -> Result<crate::RootDisk, crate::RuntimeError> {
    Ok(crate::RootDisk {
        pool: runtime.initialize_storage_pool("default", None)?,
        disk_gi_b: sandbox_protocol::vm_size_limits()
            .map_err(|_| {
                crate::RuntimeError::new(
                    sandbox_protocol::SandboxErrorCode::Internal,
                    "invalid policy",
                )
            })?
            .disk_gi_b_default,
    })
}
