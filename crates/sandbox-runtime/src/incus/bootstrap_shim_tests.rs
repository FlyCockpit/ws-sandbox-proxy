//! Bootstrap readiness (community bases, D-C, I11) against the fake `incus`
//! shim: a raw upstream guest (`ubuntu` 1000:1001, no `/home/user`) never
//! passes standard readiness, and passes bootstrap readiness inside the same
//! restart-tolerant pass (agent wait, binding and architecture, boot settle
//! as the declared uid, guest sudo, network). Never a live VM.

use super::shim_tests::{create_req, runtime_for};
use crate::{CreateSandboxRequest, ReadinessMode, SandboxRuntime};
use sandbox_protocol::{ReadinessFailureReason, SandboxErrorCode};
use std::fs;
use std::path::Path;

fn bootstrap_req() -> CreateSandboxRequest {
    let mut request = create_req();
    request.readiness = ReadinessMode::BuildBootstrap;
    request
}

fn exec_lines(log: &Path, needle: &str) -> Vec<String> {
    fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .filter(|line| line.starts_with("exec ") && line.contains(needle))
        .map(str::to_owned)
        .collect()
}

fn settles(log: &Path) -> u32 {
    fs::read_to_string(log.parent().unwrap().join("settles"))
        .map(|n| n.parse().unwrap())
        .unwrap_or(0)
}

/// I12 backstop: standard readiness refuses the raw upstream identity.
#[test]
fn a_raw_identity_guest_under_standard_readiness_is_guest_unavailable() {
    let (runtime, log) = runtime_for("raw_identity");
    let err = runtime
        .create_bound(&create_req())
        .expect_err("standard readiness on a raw upstream guest")
        .into_error();
    assert_eq!(err.code, SandboxErrorCode::GuestUnavailable, "{err}");
    assert_eq!(
        err.readiness_reason(),
        Some(ReadinessFailureReason::GuestUser)
    );
    assert_eq!(settles(&log), 0, "standard readiness never runs the settle");
}

/// D-C: bootstrap readiness reaches READY on the same raw guest, runs the
/// settle as the declared uid with cwd `/` (never root, never HOME), and
/// skips the identity script and the repo ensure. With a static image
/// sudoers grant and `guestSudo = false`, a build VM runs revoke only (no
/// create-time audit, U2), so the image's own grant does not fail it.
#[test]
fn bootstrap_readiness_on_a_raw_identity_guest_with_a_static_grant_is_ready() {
    let (runtime, log) = runtime_for("raw_identity");
    let dir = log.parent().unwrap();
    // The audit would see the image's `90-cloud-init-users` NOPASSWD rule.
    fs::write(
        dir.join("sudo-verdict-revoke-audit"),
        "root_granted sudo_ws sudo_rule",
    )
    .unwrap();
    let request = bootstrap_req();
    assert!(!request.guest_privilege.sudo && !request.guest_privilege.audit);
    let created = runtime
        .create_bound(&request)
        .expect("bootstrap readiness on a raw upstream guest");
    assert_eq!(created.into_value().readiness_restarts, 0);
    assert_eq!(settles(&log), 1);
    let settle = exec_lines(&log, "is-system-running");
    assert_eq!(settle.len(), 1, "{settle:?}");
    for token in ["--user 1000", "--group 1000", "--cwd /"] {
        assert!(settle[0].contains(token), "{}", settle[0]);
    }
    assert!(!settle[0].contains("--user 0"), "{}", settle[0]);
    assert!(exec_lines(&log, "wssp-readiness").is_empty());
    assert!(exec_lines(&log, "/home/user/repo").is_empty());
    assert_eq!(
        fs::read_to_string(dir.join("sudo-log")).unwrap(),
        "revoke\n",
        "a build VM revokes only"
    );
}

/// I11: a fresh create persists the gate's mode with the readiness spec,
/// `mode` before `privilege`.
#[test]
fn a_new_vm_persists_its_readiness_mode() {
    for (readiness, persisted) in [
        (ReadinessMode::BuildBootstrap, "build_bootstrap"),
        (ReadinessMode::Standard, "standard"),
    ] {
        let (runtime, log) = runtime_for("fix6_new_ready");
        let mut request = create_req();
        request.readiness = readiness;
        let _ = runtime.create_bound(&request);
        let text = fs::read_to_string(
            log.parent()
                .unwrap()
                .join("config/user.flycockpit.readiness"),
        )
        .expect("spec written at init");
        let spec: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(spec["mode"], persisted);
        assert!(text.find("\"mode\"").unwrap() < text.find("\"privilege\"").unwrap());
    }
}

/// Seed the persisted spec of the shim's pre-existing VM.
fn seed_spec(log: &Path, request: &CreateSandboxRequest) {
    let config = log.parent().unwrap().join("config");
    fs::create_dir_all(&config).unwrap();
    fs::write(
        config.join("user.flycockpit.readiness"),
        serde_json::to_string(&super::client::ReadinessSpec {
            guest: request.guest.clone(),
            architecture: "x86_64".into(),
            mode: request.readiness,
            privilege: Default::default(),
            root_disk_bytes: None,
        })
        .unwrap(),
    )
    .unwrap();
}

/// `degraded` is settled; `maintenance` (or anything else) never is and
/// re-passes until the restart bound; `starting` once then `running` is one
/// tolerated re-pass.
#[test]
fn the_boot_settle_accepts_running_or_degraded_and_re_passes_otherwise() {
    let (runtime, _) = runtime_for("bootstrap_degraded");
    runtime.create_bound(&bootstrap_req()).expect("degraded");

    // An answer without a settled state (the system bus not up yet early in
    // a boot, live 26.04) is retried inside the pass, never counted as a
    // restart.
    let (runtime, log) = runtime_for("bootstrap_starting_once");
    let created = runtime.create_bound(&bootstrap_req()).expect("settles");
    assert_eq!(created.into_value().readiness_restarts, 0);
    assert_eq!(settles(&log), 2);

    let (runtime, log) = runtime_for("bootstrap_maintenance");
    let err = runtime
        .create_bound(&bootstrap_req())
        .expect_err("never settles")
        .into_error();
    assert_eq!(err.code, SandboxErrorCode::GuestUnavailable, "{err}");
    assert!(
        matches!(
            err.readiness_reason(),
            Some(ReadinessFailureReason::GuestRestarts | ReadinessFailureReason::AgentTimeout)
        ),
        "{err}"
    );
    assert!(settles(&log) > super::client::MAX_GUEST_RESTARTS + 1);
}

/// Live 1: one first-boot reboot after the agent answered (under the
/// settle) is one re-pass, then READY in bootstrap mode.
#[test]
fn one_reboot_after_the_agent_wait_is_one_re_pass_then_ready() {
    let (runtime, log) = runtime_for("bootstrap_reboot_once");
    let created = runtime
        .create_bound(&bootstrap_req())
        .expect("bootstrap survives one first-boot reboot");
    assert_eq!(created.into_value().readiness_restarts, 1);
    assert_eq!(settles(&log), 2);
    let boots = fs::read_to_string(log.parent().unwrap().join("boots")).unwrap();
    assert_eq!(boots, "2");
}

/// Past MAX_GUEST_RESTARTS (three reboots) the create is GuestUnavailable
/// with the `guest_restarts` reason, never READY.
#[test]
fn three_reboots_are_guest_unavailable_with_the_restarts_reason() {
    let (runtime, log) = runtime_for("bootstrap_reboot_always");
    let err = runtime
        .create_bound(&bootstrap_req())
        .expect_err("a guest that reboots under every settle")
        .into_error();
    assert_eq!(err.code, SandboxErrorCode::GuestUnavailable, "{err}");
    assert_eq!(
        err.readiness_reason(),
        Some(ReadinessFailureReason::GuestRestarts)
    );
    assert!(err.message.contains("guest_restarts"), "{err}");
    assert_eq!(settles(&log), super::client::MAX_GUEST_RESTARTS + 1);
}

/// I11: after a daemon restart, allocation recovery and probes read the
/// persisted bootstrap mode (a running raw guest is READY), and a standard
/// spec on the same guest is not.
#[test]
fn recovery_and_probes_read_the_persisted_mode() {
    let (runtime, log) = runtime_for("raw_identity");
    let request = bootstrap_req();
    seed_spec(&log, &request);
    runtime.create_bound(&request).expect("bootstrap create");
    // A fresh runtime over the same host: nothing in memory carries the mode.
    let mut fresh = crate::IncusKvmRuntime::new(crate::IncusConfig {
        binary: log
            .parent()
            .unwrap()
            .join("incus")
            .to_string_lossy()
            .into_owned(),
        project: "default".into(),
    })
    .unwrap();
    fresh.override_network_test_state(log.parent().unwrap().join("host-state"), Vec::new());
    assert_eq!(
        fresh
            .query_sandbox("sbx-1", Some("create-1"), Some(&request.template_digest))
            .unwrap(),
        Some(sandbox_protocol::SandboxLifecycleState::Ready)
    );
    let probe = crate::ProbeSandboxRequest {
        template_fingerprint: request.template_digest.clone(),
        sandbox_id: "sbx-1".into(),
        instance_name: request.instance_name.clone(),
        operation_id: "op-probe".into(),
        idempotency_key: "probe-1".into(),
        guest: request.guest.clone(),
        architecture: request.architecture.clone(),
    };
    assert_eq!(
        fresh.probe_sandbox(&probe).unwrap().state,
        crate::SandboxLiveProbeState::GuestReady
    );
    // The same guest with a standard spec: recovery is GuestUnavailable.
    let spec_path = log
        .parent()
        .unwrap()
        .join("config/user.flycockpit.readiness");
    let mut spec: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&spec_path).unwrap()).unwrap();
    spec["mode"] = "standard".into();
    fs::write(&spec_path, spec.to_string()).unwrap();
    let err = fresh
        .query_sandbox("sbx-1", Some("create-1"), Some(&request.template_digest))
        .expect_err("standard recovery of a raw guest");
    assert_eq!(err.code, SandboxErrorCode::GuestUnavailable, "{err}");
    assert_eq!(
        fresh.probe_sandbox(&probe).unwrap().state,
        crate::SandboxLiveProbeState::Unreachable
    );
}

/// Ubuntu 26.04: a community prep build VM can need 205 s for its agent,
/// past the standard 120 s budget. Bootstrap readiness gets at
/// least `BOOTSTRAP_AGENT_TIMEOUT`; standard readiness keeps the configured
/// budget, and a larger configured budget is never lowered.
#[test]
fn bootstrap_readiness_gets_the_longer_first_boot_budget() {
    use super::client::{BOOTSTRAP_AGENT_TIMEOUT, IncusClient};
    use std::time::Duration;
    // Never executed: only the readiness budget is computed. A path that
    // cannot exist keeps the no-live-incus guard satisfied.
    let mut client = IncusClient::new("/nonexistent/wssp-test-incus", "default");
    client.agent_timeout = Duration::from_secs(120);
    assert_eq!(
        client.readiness_wait(ReadinessMode::Standard).budget(),
        Duration::from_secs(120)
    );
    assert_eq!(
        client
            .readiness_wait(ReadinessMode::BuildBootstrap)
            .budget(),
        BOOTSTRAP_AGENT_TIMEOUT
    );
    assert!(BOOTSTRAP_AGENT_TIMEOUT >= Duration::from_secs(300));
    client.agent_timeout = Duration::from_secs(900);
    assert_eq!(
        client
            .readiness_wait(ReadinessMode::BuildBootstrap)
            .budget(),
        Duration::from_secs(900)
    );
}
