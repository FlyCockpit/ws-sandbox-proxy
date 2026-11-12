//! The fake's retire-helper emulation, one test per rule.
use std::time::Duration;

use super::{FAKE_BOOT_ID, FakeCommandScope, FakeRuntime, FakeUidRoots};
use crate::r#trait::{
    CommandBirth, CreateSandboxRequest, GuestIdentity, RetireCommandRequest, RetireMode,
    RetireObservation, SandboxRuntime,
};

fn fake() -> FakeRuntime {
    let fake = FakeRuntime::new();
    fake.create_fixture(&CreateSandboxRequest::for_test("sbx-1", "create"))
        .unwrap();
    fake
}

fn request(mode: RetireMode, uid: Option<u32>, budget_ms: u64) -> RetireCommandRequest {
    RetireCommandRequest {
        template_fingerprint: String::new(),
        guest: GuestIdentity::default(),
        sandbox_id: "sbx-1".into(),
        instance_name: "wssp-sbx-sbx-1".into(),
        operation_id: "cmd".into(),
        birth: CommandBirth {
            pid: 42,
            boot_id: FAKE_BOOT_ID.into(),
            start_ticks: 7,
            started_at_ms: 0,
        },
        generation: 1,
        attempt: 1,
        uid,
        budget_ms,
        mode,
        host_proof_only: false,
        qemu: None,
    }
}

fn gone(result: &Result<RetireObservation, crate::RuntimeError>) -> bool {
    matches!(result, Ok(RetireObservation::Gone(_)))
}

#[test]
fn an_absent_or_empty_scope_proves_the_attempt_gone_without_a_kill() {
    for scope in [None, Some(FakeCommandScope::Empty)] {
        let fake = fake();
        if let Some(scope) = scope {
            fake.set_command_scope("cmd", scope);
        }
        assert!(gone(&fake.retire_command_group(&request(
            RetireMode::Observe,
            Some(1000),
            0
        ))));
        assert!(fake.retire_kills().is_empty());
        assert_eq!(fake.retired_command_groups().len(), 1);
    }
}

#[test]
fn observe_keeps_a_populated_scope_running_and_never_kills() {
    let fake = fake();
    fake.set_command_scope("cmd", FakeCommandScope::Populated { killable: true });
    let result = fake.retire_command_group(&request(RetireMode::Observe, Some(1000), 5000));
    assert_eq!(
        result.unwrap(),
        RetireObservation::Running { not_due: None }
    );
    assert!(fake.retire_kills().is_empty());
}

#[test]
fn kill_cancel_kills_the_scope_once_then_proves_it_gone() {
    let fake = fake();
    fake.set_command_scope("cmd", FakeCommandScope::Populated { killable: true });
    assert!(gone(&fake.retire_command_group(&request(
        RetireMode::KillCancel,
        Some(1000),
        0
    ))));
    assert_eq!(
        fake.retire_kills(),
        [("cmd".into(), RetireMode::KillCancel)]
    );
    // Already gone: no second kill.
    assert!(gone(&fake.retire_command_group(&request(
        RetireMode::KillCancel,
        Some(1000),
        0
    ))));
    assert_eq!(fake.retire_kills().len(), 1);
}

#[test]
fn kill_deadline_waits_for_budget_plus_slack_on_the_active_clock() {
    let fake = fake();
    fake.set_command_scope("cmd", FakeCommandScope::Populated { killable: true });
    let deadline = request(RetireMode::KillDeadline, Some(1000), 10_000);
    // No active-enter time: the gate fails, nothing is killed.
    assert_eq!(
        fake.retire_command_group(&deadline).unwrap(),
        RetireObservation::Running { not_due: None }
    );
    fake.set_command_scope_active_for("cmd", Duration::from_secs(25));
    assert_eq!(
        fake.retire_command_group(&deadline).unwrap(),
        RetireObservation::Running {
            not_due: Some(Duration::from_secs(5))
        }
    );
    // Budget 0 is never due.
    assert_eq!(
        fake.retire_command_group(&request(RetireMode::KillDeadline, Some(1000), 0))
            .unwrap(),
        RetireObservation::Running { not_due: None }
    );
    assert!(fake.retire_kills().is_empty());
    fake.set_command_scope_active_for("cmd", Duration::from_secs(30));
    assert!(gone(&fake.retire_command_group(&deadline)));
    assert_eq!(
        fake.retire_kills(),
        [("cmd".into(), RetireMode::KillDeadline)]
    );
}

#[test]
fn an_unkillable_scope_or_a_kernel_without_cgroup_kill_is_unproven() {
    let fake = fake();
    fake.set_command_scope("cmd", FakeCommandScope::Populated { killable: false });
    assert!(
        fake.retire_command_group(&request(RetireMode::KillCancel, Some(1000), 0))
            .is_err()
    );
    let fake = self::fake();
    fake.set_command_scope("cmd", FakeCommandScope::Populated { killable: true });
    fake.set_scope_kill_unsupported(true);
    assert!(
        fake.retire_command_group(&request(RetireMode::KillCancel, Some(1000), 0))
            .is_err()
    );
    assert!(fake.retire_kills().is_empty());
    assert!(fake.retired_command_groups().is_empty());
}

#[test]
fn a_populated_or_second_uid_root_blocks_every_proof() {
    for (roots, proven) in [
        (FakeUidRoots::None, true),
        (FakeUidRoots::OneEmpty, true),
        (FakeUidRoots::OnePopulated, false),
        (FakeUidRoots::Two, false),
    ] {
        let fake = fake();
        fake.set_uid_roots(roots);
        fake.set_command_scope("cmd", FakeCommandScope::Populated { killable: true });
        let result = fake.retire_command_group(&request(RetireMode::KillCancel, Some(1000), 0));
        assert_eq!(gone(&result), proven, "{roots:?}");
        // The check runs after the kill, never before.
        assert_eq!(fake.retire_kills().len(), 1, "{roots:?}");
    }
}

#[test]
fn a_marker_or_legacy_hierarchy_or_no_uid_keeps_todays_reboot_arm() {
    for setup in ["marker", "legacy", "no-uid"] {
        let fake = fake();
        let uid = (setup != "no-uid").then_some(1000);
        match setup {
            "marker" => fake.set_unscoped_marker(true),
            "legacy" => fake.set_legacy_cgroups(true),
            _ => {}
        }
        // Same boot: unproven.
        assert!(
            fake.retire_command_group(&request(RetireMode::KillCancel, uid, 0))
                .is_err(),
            "{setup}"
        );
        // Another boot: today's arm proves it.
        let mut rebooted = request(RetireMode::KillCancel, uid, 0);
        rebooted.birth.boot_id = "00000000-0000-4000-8000-0000000000ff".into();
        assert!(gone(&fake.retire_command_group(&rebooted)), "{setup}");
        assert!(fake.retire_kills().is_empty(), "{setup}");
    }
    // A marker does not matter while the scope itself exists.
    let fake = fake();
    fake.set_unscoped_marker(true);
    fake.set_command_scope("cmd", FakeCommandScope::Empty);
    assert!(gone(&fake.retire_command_group(&request(
        RetireMode::Observe,
        Some(1000),
        0
    ))));
}

#[test]
fn a_stopped_vm_still_proves_without_the_helper() {
    let fake = fake();
    fake.set_command_scope("cmd", FakeCommandScope::Populated { killable: false });
    fake.set_uid_roots(FakeUidRoots::Two);
    fake.stop_sandbox(&crate::StopSandboxRequest {
        sandbox_id: "sbx-1".into(),
        instance_name: "wssp-sbx-sbx-1".into(),
        operation_id: "stop".into(),
        idempotency_key: "stop".into(),
        template_fingerprint: String::new(),
    })
    .unwrap();
    assert!(gone(&fake.retire_command_group(&request(
        RetireMode::KillCancel,
        Some(1000),
        0
    ))));
    assert!(fake.retire_kills().is_empty());
}
