//! `IncusKvmRuntime::retire_command_group` against the executable
//! `incus` shim (never a live VM): the exact root argv per mode, the verdict
//! mapping, `unscoped`/`legacy` through today's reboot arm with the helper's
//! own boot (no second exec), and a receipt without a journaled uid keeping
//! today's guest-uid boot exec.
use std::fs;

use super::shim_tests::runtime_for;
use crate::r#trait::{
    CommandBirth, GuestIdentity, RetireCommandRequest, RetireMode, RetireObservation,
    SandboxRuntime,
};

const BIRTH_BOOT: &str = "00000000-0000-4000-8000-000000000001";
const OTHER_BOOT: &str = "00000000-0000-4000-8000-000000000002";

fn request(mode: RetireMode, uid: Option<u32>) -> RetireCommandRequest {
    RetireCommandRequest {
        template_fingerprint:
            "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".into(),
        guest: GuestIdentity::default(),
        sandbox_id: "sbx-1".into(),
        instance_name: "wssp-sbx-sbx-1".into(),
        operation_id: "op-1".into(),
        birth: CommandBirth {
            pid: 42,
            boot_id: BIRTH_BOOT.into(),
            start_ticks: 7,
            started_at_ms: 0,
        },
        generation: 2,
        attempt: 3,
        uid,
        budget_ms: 5000,
        mode,
        host_proof_only: false,
        qemu: None,
    }
}

fn exec_lines(log: &std::path::Path) -> Vec<String> {
    fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .filter(|line| line.starts_with("exec "))
        .map(String::from)
        .collect()
}

#[test]
fn the_root_helper_runs_once_per_retirement_with_the_exact_argv() {
    for (mode, arg) in [
        (RetireMode::Observe, "observe"),
        (RetireMode::KillCancel, "kill-cancel"),
        (RetireMode::KillDeadline, "kill-deadline"),
    ] {
        let (runtime, log) = runtime_for("default");
        let observation = runtime
            .retire_command_group(&request(mode, Some(1000)))
            .unwrap_or_else(|e| panic!("{e:?} {}", fs::read_to_string(&log).unwrap_or_default()));
        assert!(matches!(observation, RetireObservation::Gone(_)), "{arg}");
        let execs = exec_lines(&log);
        assert_eq!(execs.len(), 1, "{execs:?}");
        let line = &execs[0];
        assert!(
            line.starts_with(
                "exec wssp-sbx-sbx-1 -T --user 0 --group 0 --cwd / -- python3 -I -S -B -c "
            ),
            "{line}"
        );
        assert!(line.contains("Plan §10 retire helper"), "{line}");
        let tail: Vec<_> = line.rsplit(' ').take(5).collect();
        assert_eq!(tail[0], "5000");
        assert_eq!(tail[1], "wssp-cmd-op-1-2-3.scope");
        assert_eq!(tail[2], "1000");
        assert_eq!(tail[3].len(), 32);
        assert_eq!(tail[4], arg);
        assert!(!line.contains("--env"), "no guest env: {line}");
    }
}

#[test]
fn helper_verdicts_map_to_proofs_running_or_unproven() {
    for (verdict, expected) in [
        ("absent", Some(true)),
        ("empty", Some(true)),
        ("killed", Some(true)),
        ("populated", None),
        ("not_due 1500", None),
        ("unsupported", Some(false)),
        ("uid_populated", Some(false)),
        ("timeout", Some(false)),
        ("garbage", Some(false)),
    ] {
        let (runtime, log) = runtime_for("default");
        let dir = log.parent().unwrap();
        fs::write(dir.join("retire-verdict"), verdict).unwrap();
        let result = runtime.retire_command_group(&request(RetireMode::KillDeadline, Some(1000)));
        match (expected, result) {
            (Some(true), Ok(RetireObservation::Gone(proof))) => {
                assert_eq!(proof.birth().pid, 42, "{verdict}");
            }
            (Some(false), Err(error)) => {
                assert_eq!(
                    error.code,
                    sandbox_protocol::SandboxErrorCode::UnknownOutcome,
                    "{verdict}"
                );
            }
            (None, Ok(RetireObservation::Running { not_due })) => {
                assert_eq!(
                    not_due,
                    (verdict == "not_due 1500").then(|| std::time::Duration::from_millis(1500)),
                    "{verdict}"
                );
            }
            (_, other) => panic!("{verdict}: {other:?}"),
        }
        assert_eq!(exec_lines(&log).len(), 1, "{verdict}: one exec");
    }
}

/// `unscoped` and `legacy` keep today's reboot arm, compared with the
/// helper's root-read boot: no second (guest-uid) boot exec.
#[test]
fn unscoped_and_legacy_use_the_helpers_boot_for_todays_reboot_arm() {
    for verdict in ["unscoped", "legacy"] {
        for (boot, proven) in [(BIRTH_BOOT, false), (OTHER_BOOT, true)] {
            let (runtime, log) = runtime_for("default");
            let dir = log.parent().unwrap();
            fs::write(dir.join("retire-verdict"), verdict).unwrap();
            fs::write(dir.join("retire-boot"), boot).unwrap();
            let result = runtime.retire_command_group(&request(RetireMode::KillCancel, Some(1000)));
            assert_eq!(
                matches!(result, Ok(RetireObservation::Gone(_))),
                proven,
                "{verdict} {boot}: {result:?}"
            );
            if !proven {
                assert!(result.is_err());
            }
            let execs = exec_lines(&log);
            assert_eq!(execs.len(), 1, "{execs:?}");
            assert!(!execs[0].contains("wssp-boot"));
        }
    }
}

/// N2: without a journaled uid the helper never runs; today's guest-uid
/// boot read decides alone, exactly as before.
#[test]
fn a_receipt_without_a_journaled_uid_keeps_todays_boot_exec() {
    for (boot, proven) in [(BIRTH_BOOT, false), (OTHER_BOOT, true)] {
        let (runtime, log) = runtime_for("default");
        fs::write(log.parent().unwrap().join("retire-boot"), boot).unwrap();
        let result = runtime.retire_command_group(&request(RetireMode::KillCancel, None));
        assert_eq!(matches!(result, Ok(RetireObservation::Gone(_))), proven);
        let execs = exec_lines(&log);
        assert_eq!(execs.len(), 1, "{execs:?}");
        assert!(
            execs[0].starts_with("exec wssp-sbx-sbx-1 -T --user 1000 --group 1000"),
            "{}",
            execs[0]
        );
        assert!(execs[0].contains(" wssp-boot "), "{}", execs[0]);
        assert!(!execs[0].contains("retire helper"));
    }
}

/// Every preflight Incus read (stopped probe, binding,
/// running check, QEMU identity, the exec's refresh) shares
/// `RETIRE_PREFLIGHT_BUDGET`, never the 120 s client default, and a read the
/// budget cuts short fails unproven: no proof, no helper exec, no retirement.
#[test]
fn a_stalled_preflight_query_fails_unproven_within_the_preflight_budget() {
    use super::command_scope::RETIRE_PREFLIGHT_BUDGET;
    // 0: the stopped/absent probe; 1: the binding read.
    for skips in ["0", "1"] {
        let (runtime, log) = runtime_for("default");
        fs::write(log.parent().unwrap().join("stall-instance-query"), skips).unwrap();
        let started = std::time::Instant::now();
        let result = runtime.retire_command_group(&request(RetireMode::KillDeadline, Some(1000)));
        let elapsed = started.elapsed();
        let error = match result {
            Err(error) => error,
            other => panic!("skips {skips}: a stalled read must stay unproven: {other:?}"),
        };
        assert_ne!(
            error.code,
            sandbox_protocol::SandboxErrorCode::SandboxNotFound,
            "skips {skips}: a timeout is never absence"
        );
        // The budget bounds the whole preflight (slack for a loaded host's
        // process kill and reap), far below the 120 s client default.
        assert!(
            elapsed < RETIRE_PREFLIGHT_BUDGET + std::time::Duration::from_secs(15),
            "skips {skips}: took {elapsed:?}"
        );
        assert!(exec_lines(&log).is_empty(), "skips {skips}: no helper exec");
    }
}

/// On the preflight budget, the QEMU identity's two state reads
/// share the absolute deadline (each bounded by what is left), so two slow
/// answers together never stretch the preflight past the budget.
#[test]
fn two_slow_qemu_identity_reads_stay_within_the_preflight_budget() {
    use super::command_scope::RETIRE_PREFLIGHT_BUDGET;
    let (runtime, log) = runtime_for("default");
    // Each read alone fits the budget; two of them do not.
    fs::write(log.parent().unwrap().join("slow-instance-state-query"), "7").unwrap();
    let mut retire = request(RetireMode::KillDeadline, Some(1000));
    retire.qemu = Some(crate::QemuIdentity {
        pid: 1,
        start_ticks: 1,
    });
    let started = std::time::Instant::now();
    let result = runtime.retire_command_group(&retire);
    let elapsed = started.elapsed();
    assert!(
        result.is_err(),
        "an exhausted budget is unproven: {result:?}"
    );
    // Slack for a loaded host's kill and reap; without the shared deadline
    // the two reads alone take 14 s.
    assert!(
        elapsed < RETIRE_PREFLIGHT_BUDGET + std::time::Duration::from_millis(2500),
        "took {elapsed:?}"
    );
    assert!(
        exec_lines(&log).is_empty(),
        "no helper exec past the budget"
    );
}
