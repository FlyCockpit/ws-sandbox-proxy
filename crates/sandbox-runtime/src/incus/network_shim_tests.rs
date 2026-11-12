//! C35 executable-shim tests for per-sandbox bridge networks and ACLs. A fake
//! `incus` binary records argv; no VM ever launches.

use super::shim_tests::FixtureRuntime;
use std::fs;
use std::path::Path;

use sandbox_protocol::{EgressPolicy, SandboxErrorCode};

use super::network::{sandbox_network_names, test_plan};
use super::shim_tests::{client_for, client_for_with_log, create_req, log_invoked, runtime_for};
use crate::r#trait::SandboxRuntime;

#[path = "policy_shim_tests.rs"]
mod policy_tests;

type FreshEvidenceWrites = Vec<(std::path::PathBuf, Vec<u8>)>;

#[derive(Debug, Clone, Default)]
struct TestLossLifecycle {
    epoch: std::sync::Arc<std::sync::atomic::AtomicU64>,
    prepared: std::sync::Arc<std::sync::Mutex<Vec<u64>>>,
    fresh_writes: std::sync::Arc<std::sync::Mutex<FreshEvidenceWrites>>,
}
struct TestLossIntent {
    lifecycle: TestLossLifecycle,
    captured: u64,
}
impl crate::EnforcementLossLifecycle for TestLossLifecycle {
    fn capture(&self, _: &str) -> Box<dyn crate::EnforcementLossIntent> {
        let captured = self.epoch.load(std::sync::atomic::Ordering::SeqCst);
        if captured != 0 {
            for (path, bytes) in self.fresh_writes.lock().unwrap().drain(..) {
                assert!(
                    path.ancestors()
                        .any(|p| p.join("stopped-instance").exists()),
                    "stale authority must halt before recapturing"
                );
                fs::write(path, bytes).unwrap();
            }
        }
        Box::new(TestLossIntent {
            lifecycle: self.clone(),
            captured,
        })
    }
}
impl crate::EnforcementLossIntent for TestLossIntent {
    fn prepare(&self) -> Result<(), crate::RuntimeError> {
        self.lifecycle.prepared.lock().unwrap().push(self.captured);
        if self.captured
            != self
                .lifecycle
                .epoch
                .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(crate::RuntimeError::new(
                SandboxErrorCode::IdempotencyConflict,
                "stale test arm",
            ));
        }
        Ok(())
    }
}

fn policy_with_cidr(cidr: &str) -> (EgressPolicy, String) {
    let policy = EgressPolicy {
        mode: sandbox_protocol::EgressMode::Allowlist,
        domains: Vec::new(),
        cidrs: vec![cidr.to_string()],
    };
    // Same canonical text as the control plane: {"cidrs":[...],"domains":[]}.
    let canonical = format!(
        "{{\"cidrs\":[{}],\"domains\":[]}}",
        policy
            .cidrs
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join(",")
    );
    let digest = ring::digest::digest(&ring::digest::SHA256, canonical.as_bytes());
    let hash = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    (policy, hash)
}

fn create_with_policy() -> crate::CreateSandboxRequest {
    let (policy, hash) = policy_with_cidr("128.66.0.0/24");
    let mut req = create_req();
    req.egress_policy = Some(policy);
    req.egress_policy_hash = Some(hash);
    req
}

fn log_lines(log: &Path) -> Vec<String> {
    fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
}

#[test]
fn golden_incus_argv_and_config_for_policy_launch() {
    // `fix6_new_ready`: the instance is absent until the shim records `init`.
    let (runtime, log) = runtime_for("fix6_new_ready");
    runtime.create_bound(&create_with_policy()).expect("create");
    let (network, acl) = sandbox_network_names("sbx-1");
    let lines = log_lines(&log);
    let find = |needle: &str| {
        lines
            .iter()
            .find(|line| line.contains(needle))
            .unwrap_or_else(|| panic!("missing `{needle}` in {}", lines.join("\n")))
            .clone()
    };
    // ACL ownership is created first; one atomic request installs both directions.
    let acl_create = find(&format!("network acl create {acl}"));
    assert!(
        acl_create.contains("user.wssp.sandbox_id=sbx-1"),
        "{acl_create}"
    );
    assert!(
        !lines
            .iter()
            .any(|line| line.contains("network acl rule add"))
    );
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.contains("-X PUT") && line.contains("/network-acls/"))
            .count(),
        1
    );
    let body: serde_json::Value =
        serde_json::from_slice(&fs::read(log.parent().unwrap().join("last-acl-put.json")).unwrap())
            .unwrap();
    let mut rule_lines = Vec::new();
    for direction in ["egress", "ingress"] {
        for rule in body[direction].as_array().unwrap() {
            let mut line = format!("{acl} {direction}");
            for field in [
                "action",
                "protocol",
                "source",
                "destination",
                "source_port",
                "destination_port",
                "description",
            ] {
                if let Some(value) = rule.get(field).and_then(serde_json::Value::as_str) {
                    line.push_str(&format!(" {field}={value}"));
                }
            }
            rule_lines.push(line);
        }
    }
    // Incus ACL directions are relative to the instance NIC: guest requests
    // are egress rules, the bridge's replies are ingress rules.
    let expected_rules = [
        format!(
            "{acl} egress action=allow protocol=udp destination=255.255.255.255/32 source_port=68 destination_port=67 description=wssp-dhcp"
        ),
        format!(
            "{acl} egress action=allow protocol=udp destination=GATEWAY/32 destination_port=53 description=wssp-dns-udp"
        ),
        format!(
            "{acl} egress action=allow protocol=tcp destination=GATEWAY/32 destination_port=53 description=wssp-dns-tcp"
        ),
        format!("{acl} egress action=allow destination=128.66.0.0/24 description=wssp-grant"),
        // §2.1 2d (M12): tcp/25 is rejected to PUBLIC_V4 in allowlist mode
        // too (default node setting), so a grant to a mail host is reachable
        // only on authenticated submission ports.
        format!(
            "{acl} egress action=reject protocol=tcp destination={} destination_port=25 description=wssp-smtp-reject",
            crate::egress::sandbox_public_v4_text().unwrap()
        ),
        format!(
            "{acl} ingress action=allow protocol=udp source=GATEWAY/32 source_port=67 destination_port=68 description=wssp-dhcp-reply"
        ),
        format!(
            "{acl} ingress action=allow protocol=udp source=GATEWAY/32 source_port=53 description=wssp-dns-udp-reply"
        ),
        format!(
            "{acl} ingress action=allow protocol=tcp source=GATEWAY/32 source_port=53 description=wssp-dns-tcp-reply"
        ),
    ];
    // The gateway is the collision-checked allocation for this sandbox.
    let gateway = super::network::allocate_gateway("sbx-1", &[])
        .expect("gateway")
        .to_string();
    assert_eq!(rule_lines.len(), expected_rules.len(), "{rule_lines:?}");
    for (line, expected) in rule_lines.iter().zip(&expected_rules) {
        let expected = expected.replace("GATEWAY", &gateway);
        assert!(
            line.contains(&expected),
            "rule mismatch:\nline:     {line}\nexpected: {expected}"
        );
    }
    // Dedicated bridge: deny defaults both directions, IPv6 off, ACL attached.
    let network_create = find(&format!("network create {network}"));
    for fragment in [
        "--type bridge",
        &format!("ipv4.address={gateway}/24"),
        "ipv4.nat=true",
        &format!("dns.nameservers={gateway}"),
        "ipv6.address=none",
        &format!("security.acls={acl}"),
        "security.acls.default.ingress.action=drop",
        "security.acls.default.egress.action=drop",
        // C36: the bridge resolver never forwards to upstreams (the log
        // escapes the multiline value as \n).
        "raw.dnsmasq=# wssp managed sandbox DNS policy (C36): no upstream resolvers;\\n# only the exact host-published answers below are served.\\nno-resolv\\nlocal-ttl=0",
        "user.wssp.sandbox_id=sbx-1",
    ] {
        assert!(
            network_create.contains(fragment),
            "{fragment}\n{network_create}"
        );
    }
    // The only NIC: pinned onto the sandbox bridge with anti-spoof options,
    // installed as a COMPLETE local device AFTER init (init --device would
    // merge onto the profile device, R22-F2).
    let init = lines
        .iter()
        .find(|line| line.split_whitespace().next() == Some("init"))
        .expect("init line")
        .clone();
    assert!(
        !init.contains("--device"),
        "init never merges NIC keys onto the profile device: {init}"
    );
    let add = lines
        .iter()
        .find(|line| line.contains("config device add"))
        .expect("device add line")
        .clone();
    let device = format!(
        "eth0 nic network={network} security.mac_filtering=true security.ipv4_filtering=true security.ipv6_filtering=true security.port_isolation=true"
    );
    assert!(add.contains(&device), "{add}");
    // The audited profile is selected explicitly; an image's own profile
    // list is never trusted.
    assert!(init.contains("--profile default"), "{init}");
}

#[test]
fn apply_is_idempotent_across_create_retries() {
    let (runtime, log) = runtime_for("running");
    let request = create_with_policy();
    runtime.create_bound(&request).expect("create");
    runtime.create_bound(&request).expect("retry");
    let (network, acl) = sandbox_network_names("sbx-1");
    let lines = log_lines(&log);
    let creates = |needle: &str| lines.iter().filter(|line| line.contains(needle)).count();
    assert_eq!(creates(&format!("network acl create {acl}")), 1);
    assert_eq!(creates(&format!("network create {network}")), 1);
}

#[test]
fn partial_rule_apply_rolls_back_the_acl() {
    let (runtime, log) = runtime_for("egress_rule_partial");
    // Older supported CLIs retain the identity writer and can leave a partial
    // install. Current CLIs install the complete rule set atomically.
    fs::write(log.parent().unwrap().join("cli-without-query-headers"), "").unwrap();
    let err = runtime
        .create_bound(&create_with_policy())
        .expect_err("rule add fails mid-apply");
    assert_ne!(err.code, SandboxErrorCode::ProtocolError);
    let (_, acl) = sandbox_network_names("sbx-1");
    let lines = log_lines(&log);
    assert!(
        lines
            .iter()
            .any(|line| line.contains(&format!("network acl delete {acl}"))),
        "rollback must delete the partially applied ACL: {}",
        lines.join("\n")
    );
    assert!(!log_invoked(&log, "init"), "VM must never launch");
}

#[test]
fn network_create_failure_rolls_back_the_acl() {
    let (runtime, log) = runtime_for("egress_network_create_fail");
    runtime
        .create_bound(&create_with_policy())
        .expect_err("network create fails");
    let (_, acl) = sandbox_network_names("sbx-1");
    let lines = log_lines(&log);
    assert!(
        lines
            .iter()
            .any(|line| line.contains(&format!("network acl delete {acl}"))),
        "rollback must delete the orphaned ACL: {}",
        lines.join("\n")
    );
    assert!(!log_invoked(&log, "init"));
}

#[test]
fn readback_mismatch_rolls_back_network_and_acl() {
    let (runtime, log) = runtime_for("egress_readback_mismatch");
    runtime
        .create_bound(&create_with_policy())
        .expect_err("effective config mismatch");
    let (network, acl) = sandbox_network_names("sbx-1");
    let lines = log_lines(&log);
    for needle in [
        format!("network delete {network}"),
        format!("network acl delete {acl}"),
    ] {
        assert!(
            lines.iter().any(|line| line.contains(&needle)),
            "rollback must run `{needle}`: {}",
            lines.join("\n")
        );
    }
    assert!(!log_invoked(&log, "init"));
}

#[test]
fn foreign_tagged_network_is_never_adopted_or_deleted() {
    let (runtime, log) = runtime_for("running");
    let (network, _) = sandbox_network_names("sbx-1");
    let statedir = log.parent().expect("log parent");
    fs::create_dir_all(statedir.join("networks")).unwrap();
    fs::write(
        statedir.join("networks").join(format!("{network}.conf")),
        "ipv4.address=10.9.9.1/24\nuser.wssp.project=default\nuser.wssp.sandbox_id=sbx-OTHER\n",
    )
    .unwrap();
    let err = runtime
        .create_bound(&create_with_policy())
        .expect_err("foreign network");
    assert_eq!(err.code, SandboxErrorCode::IdempotencyConflict);
    let lines = log_lines(&log);
    assert!(
        !lines
            .iter()
            .any(|line| line.contains(&format!("network delete {network}"))),
        "must not delete another sandbox's network: {}",
        lines.join("\n")
    );
    assert!(!log_invoked(&log, "init"));
}

#[test]
fn foreign_tagged_acl_is_never_adopted_or_deleted() {
    let (runtime, log) = runtime_for("running");
    let (_, acl) = sandbox_network_names("sbx-1");
    let statedir = log.parent().expect("log parent");
    let (policy, hash) = policy_with_cidr("128.66.0.0/24");
    let plan = super::network::compile_network_plan(
        "sbx-1",
        Some(&policy),
        Some(&hash),
        &|_domain, _wait| Ok(Vec::new()),
        super::network::allocate_gateway("sbx-1", &[]).expect("gateway"),
        &super::network::CompileLimits {
            deadline: std::time::Instant::now() + super::network::COMPILE_BUDGET,
            cancelled: None,
        },
    )
    .expect("plan compiles");
    fs::create_dir_all(statedir.join("acls")).unwrap();
    // A rule-identical ACL owned by another sandbox must still be refused.
    fs::write(
        statedir.join("acls").join(format!("{acl}.conf")),
        "user.wssp.sandbox_id=sbx-OTHER\nuser.wssp.project=default\n",
    )
    .unwrap();
    for direction in [
        super::network::AclDirection::Ingress,
        super::network::AclDirection::Egress,
    ] {
        let lines: Vec<String> = plan
            .rules
            .iter()
            .filter(|rule| rule.direction == direction)
            .map(|rule| rule.cli_args().join(" "))
            .collect();
        fs::write(
            statedir
                .join("acls")
                .join(format!("{acl}.{}", direction.as_str())),
            lines.join("\n") + "\n",
        )
        .unwrap();
    }
    let err = runtime
        .create_bound(&create_with_policy())
        .expect_err("foreign acl");
    assert_eq!(err.code, SandboxErrorCode::IdempotencyConflict);
    let lines = log_lines(&log);
    assert!(
        !lines
            .iter()
            .any(|line| line.contains(&format!("network acl delete {acl}"))),
        "must not delete another sandbox's ACL: {}",
        lines.join("\n")
    );
    assert!(!log_invoked(&log, "init"));
}

#[test]
fn unsafe_default_profile_is_rejected_before_any_host_mutation() {
    let (runtime, log) = runtime_for("unsafe_profile");
    let err = runtime
        .create_bound(&create_with_policy())
        .expect_err("unsafe profile");
    assert_eq!(err.code, SandboxErrorCode::Internal);
    let lines = log_lines(&log);
    assert!(!log_invoked(&log, "init"), "VM must never launch");
    assert!(
        !lines.iter().any(|line| line.contains("network create")),
        "preflight precedes network apply: {}",
        lines.join("\n")
    );
    assert!(
        !lines.iter().any(|line| line.contains("network acl create")),
        "preflight precedes ACL apply: {}",
        lines.join("\n")
    );
}

#[test]
fn capability_reflects_daemon_evidence() {
    let (runtime, _) = runtime_for("running");
    assert!(
        runtime
            .egress_enforcement_capability()
            .expect("capability query")
    );
    let (runtime, _) = runtime_for("egress_daemon_unsupported");
    assert!(
        !runtime
            .egress_enforcement_capability()
            .expect("capability query")
    );
    let (runtime, _) = runtime_for("egress_old_daemon");
    assert!(
        !runtime
            .egress_enforcement_capability()
            .expect("capability query")
    );
    // R22-F1: CVE-2025-52890 — 6.12/6.13 advertise network_acl but cannot
    // reliably enforce anti-spoofing; only the fixed 6.14+ is accepted.
    for mode in ["egress_vulnerable_6_12", "egress_vulnerable_6_13"] {
        let (runtime, _) = runtime_for(mode);
        assert!(
            !runtime
                .egress_enforcement_capability()
                .expect("capability query"),
            "{mode}: a vulnerable release must not advertise enforcement"
        );
    }
}

#[test]
fn unsupported_daemon_fails_create_closed() {
    for mode in [
        "egress_daemon_unsupported",
        "egress_old_daemon",
        "egress_vulnerable_6_12",
        "egress_vulnerable_6_13",
    ] {
        let (runtime, log) = runtime_for(mode);
        let err = runtime.create_bound(&create_with_policy()).expect_err(mode);
        assert_eq!(err.code, SandboxErrorCode::UnsupportedCapability, "{mode}");
        assert!(!log_invoked(&log, "init"), "{mode}: VM must never launch");
        assert!(
            !log_lines(&log)
                .iter()
                .any(|line| line.starts_with("network create")),
            "{mode}: the apply path must never provision on a vulnerable daemon"
        );
    }
}

#[test]
fn kill_tears_down_the_sandbox_network_and_acl() {
    let (runtime, log) = runtime_for("running");
    runtime.create_bound(&create_with_policy()).expect("create");
    runtime
        .kill_bound(&crate::KillSandboxRequest {
            template_fingerprint: create_req().template_digest,
            sandbox_id: "sbx-1".to_string(),
            instance_name: "wssp-sbx-sbx-1".to_string(),
            operation_id: "op-kill".to_string(),
            idempotency_key: "kill-1".to_string(),
        })
        .expect("kill");
    let (network, acl) = sandbox_network_names("sbx-1");
    let lines = log_lines(&log);
    let delete_network = lines
        .iter()
        .position(|line| line.contains(&format!("network delete {network}")))
        .expect("network delete");
    let delete_acl = lines
        .iter()
        .position(|line| line.contains(&format!("network acl delete {acl}")))
        .expect("acl delete");
    assert!(
        delete_network < delete_acl,
        "the network is deleted before the ACL it references"
    );
}

#[test]
fn policy_hash_mismatch_fails_closed_before_host_io() {
    let (runtime, log) = runtime_for("running");
    let (policy, _) = policy_with_cidr("128.66.0.0/24");
    let mut req = create_req();
    req.egress_policy = Some(policy);
    req.egress_policy_hash = Some("b".repeat(64));
    let err = runtime.create_bound(&req).expect_err("hash mismatch");
    assert_eq!(err.code, SandboxErrorCode::ProtocolError);
    let lines = log_lines(&log);
    assert!(
        !lines.iter().any(|line| line.contains("network")),
        "no network IO before policy verification: {}",
        lines.join("\n")
    );
}

#[test]
fn ipv6_policy_grant_fails_closed_before_host_io() {
    let (runtime, log) = runtime_for("running");
    let (policy, hash) = policy_with_cidr("2001:db8::/32");
    let mut req = create_req();
    req.egress_policy = Some(policy);
    req.egress_policy_hash = Some(hash);
    let err = runtime.create_bound(&req).expect_err("ipv6 grant");
    assert_eq!(err.code, SandboxErrorCode::UnsupportedCapability);
    assert!(!log_invoked(&log, "init"));
}

#[test]
fn init_selects_the_audited_profile_and_verifies_effective_devices() {
    // Golden covers the happy path; here the daemon reports devices that do
    // not match the audited set even though init was handed the override.
    let (runtime, log) = runtime_for("fix6_new_ready");
    let statedir = log.parent().expect("log parent");
    fs::write(statedir.join("force-legacy-devices"), "").unwrap();
    let err = runtime
        .create_bound(&create_with_policy())
        .expect_err("drifted devices");
    assert_eq!(err.code, SandboxErrorCode::IdempotencyConflict);
    let lines = log_lines(&log);
    let init = lines
        .iter()
        .find(|line| line.split_whitespace().next() == Some("init"))
        .expect("init line");
    assert!(init.contains("--profile default"), "{init}");
    assert!(
        !lines
            .iter()
            .any(|line| line.split_whitespace().next() == Some("start")),
        "a VM whose effective devices were not proven must never start: {}",
        lines.join("\n")
    );
}

#[test]
fn running_legacy_nic_vm_is_never_adopted() {
    // Pre-C35 VM: running, eth0 on unrestricted incusbr0, valid binding.
    let (runtime, log) = runtime_for("egress_legacy_nic");
    let err = runtime
        .create_bound(&create_with_policy())
        .expect_err("legacy NIC");
    assert_eq!(err.code, SandboxErrorCode::IdempotencyConflict);
    let lines = log_lines(&log);
    assert!(
        !lines.iter().any(|line| line.contains("device override")),
        "a running VM is never reconfigured: {}",
        lines.join("\n")
    );
}

#[test]
fn stopped_legacy_nic_vm_is_reconfigured_onto_its_bridge() {
    let (runtime, log) = runtime_for("egress_legacy_nic_stopped");
    runtime
        .create_bound(&create_with_policy())
        .expect("stopped VM is safely reconfigured");
    let (network, _) = sandbox_network_names("sbx-1");
    let lines = log_lines(&log);
    // The inherited legacy NIC is replaced by a COMPLETE local device of the
    // same name (R20-F2): `override` would merge and retain incompatible
    // inherited properties.
    let add_at = lines
        .iter()
        .position(|line| {
            line.contains("config device add")
                && line.contains(&format!("eth0 nic network={network}"))
        })
        .expect("device add replaces the inherited NIC");
    let start_at = lines
        .iter()
        .position(|line| line.split_whitespace().next() == Some("start"))
        .expect("start");
    assert!(
        add_at < start_at,
        "the pinned NIC is in place before the VM starts: {}",
        lines.join("\n")
    );
}

/// R5-F1: a NIC carrying permissive device-level ACL overrides widens the
/// deny-default policy; verification must reject it even though the five
/// pinning properties match.
#[test]
fn permissive_nic_acl_overrides_fail_verification() {
    let (runtime, _log) = runtime_for("egress_permissive_nic");
    let err = runtime
        .create_bound(&create_with_policy())
        .expect_err("permissive NIC-level overrides are refused");
    assert_eq!(err.code, SandboxErrorCode::IdempotencyConflict);
}

/// R5-F2, updated by R20-F2: every C35 VM's eth0 is LOCAL (init
/// `--device`), and drift on it is repaired by REPLACING the device
/// (`device remove` + `device add` with the complete audited definition) —
/// `set` would merge keys and retain incompatible leftover properties.
#[test]
fn drifted_local_nic_is_replaced_wholesale_not_merged() {
    let (runtime, log) = runtime_for("egress_drifted_local_nic_stopped");
    runtime
        .create_bound(&create_with_policy())
        .expect("a stopped VM's drifted local NIC is repaired");
    let (network, _) = sandbox_network_names("sbx-1");
    let lines = log_lines(&log);
    let remove_at = lines
        .iter()
        .position(|line| line.contains("config device remove") && line.contains("eth0"))
        .expect("the drifted local NIC is removed first");
    let add_at = lines
        .iter()
        .position(|line| {
            line.contains("config device add")
                && line.contains(&format!("eth0 nic network={network}"))
        })
        .expect("the complete audited device is added");
    assert!(
        !lines.iter().any(|line| line.contains("config device set"))
            && !lines
                .iter()
                .any(|line| line.contains("config device override")),
        "a drifted NIC is never key-merged: {}",
        lines.join("\n")
    );
    let start_at = lines
        .iter()
        .position(|line| line.split_whitespace().next() == Some("start"))
        .expect("start");
    assert!(
        remove_at < add_at && add_at < start_at,
        "the NIC is replaced and verified in place before the VM starts"
    );
}

#[test]
fn disabled_rule_readback_fails_closed() {
    let (runtime, log) = runtime_for("running");
    let (_, acl) = sandbox_network_names("sbx-1");
    let statedir = log.parent().expect("log parent");
    let (policy, hash) = policy_with_cidr("128.66.0.0/24");
    let plan = super::network::compile_network_plan(
        "sbx-1",
        Some(&policy),
        Some(&hash),
        &|_domain, _wait| Ok(Vec::new()),
        super::network::allocate_gateway("sbx-1", &[]).expect("gateway"),
        &super::network::CompileLimits {
            deadline: std::time::Instant::now() + super::network::COMPILE_BUDGET,
            cancelled: None,
        },
    )
    .expect("plan compiles");
    fs::create_dir_all(statedir.join("acls")).unwrap();
    fs::write(
        statedir.join("acls").join(format!("{acl}.conf")),
        "user.wssp.sandbox_id=sbx-1\nuser.wssp.project=default\n",
    )
    .unwrap();
    for direction in [
        super::network::AclDirection::Ingress,
        super::network::AclDirection::Egress,
    ] {
        let lines: Vec<String> = plan
            .rules
            .iter()
            .filter(|rule| rule.direction == direction)
            // A rule whose effective state is disabled denies the grant it
            // was recorded to allow; the readback must not accept it.
            .map(|rule| format!("{} state=disabled", rule.cli_args().join(" ")))
            .collect();
        fs::write(
            statedir
                .join("acls")
                .join(format!("{acl}.{}", direction.as_str())),
            lines.join("\n") + "\n",
        )
        .unwrap();
    }
    let err = runtime
        .create_bound(&create_with_policy())
        .expect_err("disabled rules");
    assert_eq!(err.code, SandboxErrorCode::IdempotencyConflict);
}

#[test]
fn missing_rule_state_evidence_fails_readback_and_rolls_back() {
    let (runtime, log) = runtime_for("egress_rule_state_missing");
    let err = runtime
        .create_bound(&create_with_policy())
        .expect_err("missing rule state");
    assert_eq!(err.code, SandboxErrorCode::Internal);
    let (_, acl) = sandbox_network_names("sbx-1");
    assert!(
        log_lines(&log)
            .iter()
            .any(|line| line.contains(&format!("network acl delete {acl}"))),
        "rollback removes the unverifiable ACL"
    );
}

#[test]
fn revoked_worker_still_rolls_back_the_partial_apply() {
    let (runtime, log) = runtime_for("egress_rule_add_fail");
    let statedir = log.parent().expect("log parent").to_path_buf();
    fs::write(statedir.join("device-root"), "root,pool=default,size=32GiB").unwrap();
    let permit = std::sync::Arc::new(crate::RuntimePermit::default());
    let scoped = runtime.with_cancellation(permit.clone());
    let watcher = std::thread::spawn(move || {
        // Revoke once the apply has definitely mutated (the ACL exists).
        for _ in 0..3000 {
            if statedir.join("acls").exists()
                && fs::read_dir(statedir.join("acls"))
                    .map(|mut d| d.next().is_some())
                    .unwrap_or(false)
            {
                permit.revoke();
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    });
    let _ = scoped
        .create_bound(&create_with_policy())
        .expect_err("rule add fails");
    watcher.join().expect("watcher");
    let (_, acl) = sandbox_network_names("sbx-1");
    let lines = log_lines(&log);
    assert!(
        lines
            .iter()
            .any(|line| line.contains(&format!("network acl delete {acl}"))),
        "rollback must not share the revoked permit: {}",
        lines.join("\n")
    );
    assert!(
        !log.parent()
            .unwrap()
            .join("host-state/network-cleanups/sbx-1.json")
            .exists(),
        "successful rollback leaves no pending cleanup record"
    );
}

#[test]
fn unfinishable_rollback_is_persisted_and_drained_under_fence() {
    let (runtime, log) = runtime_for("egress_apply_fail_teardown_fail");
    let host_state = log.parent().expect("log parent").join("host-state");
    let record = host_state.join("network-cleanups/sbx-1.json");
    let err = runtime
        .create_bound(&create_with_policy())
        .expect_err("apply fails, rollback cannot finish");
    assert_ne!(err.code, SandboxErrorCode::ProtocolError);
    assert!(
        record.exists(),
        "the unresolved cleanup obligation is durable"
    );
    let (_, acl) = sandbox_network_names("sbx-1");
    let statedir = log.parent().unwrap();
    assert!(
        statedir.join("acls").join(format!("{acl}.conf")).exists(),
        "the partial ACL is still there until the drain"
    );
    // The fenced drain finishes it once the daemon cooperates again.
    fs::write(statedir.join("teardown-allowed"), "").unwrap();
    runtime.sandbox_inventory().expect("inventory drains");
    assert!(!record.exists(), "drained record is removed");
    assert!(!statedir.join("acls").join(format!("{acl}.conf")).exists());
}

#[test]
fn kill_is_incomplete_until_network_teardown_completes() {
    let (runtime, log) = runtime_for("egress_teardown_fail");
    let statedir = log.parent().expect("log parent").to_path_buf();
    runtime.create_bound(&create_with_policy()).expect("create");
    let kill = || {
        runtime.kill_bound(&crate::KillSandboxRequest {
            template_fingerprint: create_req().template_digest,
            sandbox_id: "sbx-1".to_string(),
            instance_name: "wssp-sbx-sbx-1".to_string(),
            operation_id: "op-kill".to_string(),
            idempotency_key: "kill-1".to_string(),
        })
    };
    assert!(
        kill().is_err(),
        "teardown failure must not confirm the kill"
    );
    assert!(
        statedir
            .join("host-state/network-cleanups/sbx-1.json")
            .exists(),
        "kill teardown failure is persisted"
    );
    // The VM is gone, but kill completion evidence requires network absence.
    let state = runtime.query_sandbox("sbx-1", None, None).expect("query");
    assert_eq!(
        state,
        Some(sandbox_protocol::SandboxLifecycleState::Provisioning),
        "leftover bridge/ACL means the sandbox is not yet gone"
    );
    fs::write(statedir.join("teardown-allowed"), "").unwrap();
    let state = runtime.query_sandbox("sbx-1", None, None).expect("query");
    assert_eq!(state, None, "the fenced drain finished the kill");
    assert!(
        !statedir
            .join("host-state/network-cleanups/sbx-1.json")
            .exists()
    );
}

#[test]
fn bridge_names_fit_the_linux_interface_limit_in_the_shim() {
    // The shim enforces IFNAMSIZ; a regression to over-long bridge names
    // fails create here even though the file-backed double could store them.
    let (runtime, _log) = runtime_for("fix6_new_ready");
    runtime
        .create_bound(&create_with_policy())
        .expect("valid names create");
    let (network, _) = sandbox_network_names("sbx-1");
    assert!(network.len() <= super::network::MAX_INTERFACE_NAME);
}

#[test]
fn subnet_allocation_skips_colliding_managed_bridges() {
    let (runtime, log) = runtime_for("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    // Another sandbox's bridge already holds this sandbox's hash-preferred /24.
    let preferred = super::network::allocate_gateway("sbx-1", &[]).expect("preferred");
    fs::create_dir_all(statedir.join("networks")).unwrap();
    fs::write(
        statedir.join("networks").join("wsn-fffffffff0.conf"),
        format!(
            "ipv4.address={}/24\nuser.wssp.project=default\nuser.wssp.sandbox_id=sbx-OTHER\n",
            preferred
        ),
    )
    .unwrap();
    runtime
        .create_bound(&create_with_policy())
        .expect("create with collision");
    let (network, _) = sandbox_network_names("sbx-1");
    let create = log_lines(&log)
        .into_iter()
        .find(|line| line.contains(&format!("network create {network}")))
        .expect("network create");
    let taken = format!("ipv4.address={preferred}/24");
    assert!(!create.contains(&taken), "collision avoided: {create}");
    assert!(create.contains("ipv4.address=10."), "{create}");
}

#[test]
fn inherited_extra_device_fails_verification_before_start() {
    // The drift is visible ONLY in expanded_devices (an extra inherited
    // proxy device); local devices hold exactly the audited override. A
    // verifier reading local `devices` would wrongly accept this VM.
    let (runtime, log) = runtime_for("egress_expanded_extra");
    let err = runtime
        .create_bound(&create_with_policy())
        .expect_err("inherited extra device");
    assert_eq!(err.code, SandboxErrorCode::IdempotencyConflict);
    assert!(
        !log_lines(&log)
            .iter()
            .any(|line| line.split_whitespace().next() == Some("start")),
        "a VM whose effective devices were not proven must never start: {}",
        log_lines(&log).join("\n")
    );
}

#[test]
fn create_retry_binds_the_vm_before_any_nic_mutation() {
    // A stopped VM on a legacy bridge carrying ANOTHER sandbox's metadata:
    // rejection must come from the binding check, before any device override.
    let (runtime, log) = runtime_for("egress_legacy_nic_stopped");
    let statedir = log.parent().expect("log parent");
    fs::write(
        statedir.join("config/user.flycockpit.sandbox_id"),
        "sbx-OTHER",
    )
    .unwrap();
    let err = runtime
        .create_bound(&create_with_policy())
        .expect_err("foreign VM");
    assert_eq!(err.code, SandboxErrorCode::IdempotencyConflict);
    assert!(
        !log_lines(&log)
            .iter()
            .any(|line| line.contains("config device override")),
        "a foreign or mismatched VM is never mutated: {}",
        log_lines(&log).join("\n")
    );
    let record = statedir.join("host-state/network-cleanups/sbx-1.json");
    assert!(
        !record.exists(),
        "preflight must not create provisioning intent"
    );
    assert!(
        !log_lines(&log)
            .iter()
            .any(|line| line.starts_with("network ")),
        "foreign binding refuses before network planning"
    );
    // R8-F1: recovery must preserve a PREVIOUS attempt's obligation too.
    // The early-refused retry no longer creates one as a side effect: model
    // the prior crash window explicitly, retaining its immutable binding.
    let mut plan = super::network::test_plan("sbx-1");
    plan.binding = Some(super::network::PlanBinding {
        template_fingerprint: create_req().template_digest,
        create_key: Some(create_req().idempotency_key),
    });
    runtime
        .client()
        .apply_sandbox_network(&plan)
        .expect("prior attempt network");
    let prior = fs::read(&record).unwrap();
    fs::write(&log, "").unwrap();
    runtime
        .client()
        .drain_pending_network_cleanups()
        .expect("drain");
    assert!(
        !log_lines(&log)
            .iter()
            .any(|line| line.contains("config device")),
        "the drain never mutates a VM that does not carry this sandbox's binding"
    );
    assert!(
        record.exists(),
        "a foreign VM never retires this sandbox's provisioning intent"
    );
    assert_eq!(
        fs::read(record).unwrap(),
        prior,
        "foreign recovery preserves the prior obligation"
    );
}

#[test]
fn inventory_never_reports_absent_while_network_cleanup_is_outstanding() {
    // Kill deleted the VM but network teardown failed: the census must not
    // omit the sandbox — downstream that omission is accepted as
    // successful-kill evidence.
    let (runtime, log) = runtime_for("egress_teardown_fail");
    let statedir = log.parent().expect("log parent").to_path_buf();
    runtime.create_bound(&create_with_policy()).expect("create");
    let kill = crate::KillSandboxRequest {
        template_fingerprint: create_req().template_digest,
        sandbox_id: "sbx-1".to_string(),
        instance_name: "wssp-sbx-sbx-1".to_string(),
        operation_id: "op-kill".to_string(),
        idempotency_key: "kill-1".to_string(),
    };
    assert!(runtime.kill_bound(&kill).is_err());
    let inventory = runtime.sandbox_inventory().expect("inventory");
    assert!(
        inventory.iter().any(|entry| entry.sandbox_id == "sbx-1"
            && entry.state == sandbox_protocol::SandboxLifecycleState::Provisioning
            && entry.configured_size == crate::ConfiguredSize::NoInstance),
        "outstanding cleanup keeps the sandbox out of the absent set: {inventory:?}"
    );
    // Once the drain can finish, the census is clean again.
    fs::write(statedir.join("teardown-allowed"), "").unwrap();
    let inventory = runtime.sandbox_inventory().expect("inventory");
    assert!(
        !inventory.iter().any(|entry| entry.sandbox_id == "sbx-1"),
        "{inventory:?}"
    );
}

#[test]
fn inventory_surfaces_marked_orphans_without_deleting_a_live_attempt() {
    // A bridge stamped with an incarnation marker but no journal record is a
    // live attempt's resource (or an unresolvable crash case): the census
    // reports it as provisioning and reconciliation never reconstructs a
    // deletion obligation for it.
    let (runtime, log) = runtime_for("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    let (network, _) = sandbox_network_names("sbx-9");
    fs::create_dir_all(statedir.join("networks")).unwrap();
    fs::write(
        statedir.join("networks").join(format!("{network}.conf")),
        "ipv4.address=10.200.9.1/24\nuser.wssp.project=default\nuser.wssp.sandbox_id=sbx-9\nuser.wssp.attempt=abc123\n",
    )
    .unwrap();
    let inventory = runtime.sandbox_inventory().expect("inventory");
    assert!(
        inventory.iter().any(|entry| entry.sandbox_id == "sbx-9"
            && entry.state == sandbox_protocol::SandboxLifecycleState::Provisioning),
        "{inventory:?}"
    );
    assert!(
        statedir
            .join("networks")
            .join(format!("{network}.conf"))
            .exists(),
        "a stamped network is never reconstructed away"
    );
}

#[test]
fn pending_cleanup_is_durable_and_drained_by_a_restarted_daemon() {
    let (client, log) = client_for_with_log("egress_apply_fail_teardown_fail");
    let statedir = log.parent().expect("log parent").to_path_buf();
    let plan = test_plan("sbx-1");
    client
        .apply_sandbox_network(&plan)
        .expect_err("apply fails, rollback cannot finish");
    let record = statedir.join("host-state/network-cleanups/sbx-1.json");
    let body = fs::read_to_string(&record).expect("durable record");
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("record json");
    assert!(
        !parsed
            .get("attempt")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .is_empty(),
        "the obligation binds the failed incarnation: {body}"
    );
    assert!(
        !statedir
            .join("host-state/network-cleanups/.sbx-1.json.tmp")
            .exists(),
        "atomic rename leaves no temp file"
    );
    // "Restart": a fresh client over the same daemon and journal dir.
    let mut restarted = super::client::IncusClient::new(
        statedir.join("incus").to_string_lossy().into_owned(),
        "default".to_string(),
    );
    restarted.host_routes = Some(Vec::new());
    restarted.state_dir = Some(statedir.join("host-state"));
    restarted
        .drain_pending_network_cleanups()
        .expect("drain fails while the daemon refuses");
    assert!(record.exists(), "teardown still fails; obligation stays");
    fs::write(statedir.join("teardown-allowed"), "").unwrap();
    restarted
        .drain_pending_network_cleanups()
        .expect("drain after restart");
    assert!(!record.exists(), "drained obligation is cleared");
    let (_, acl) = sandbox_network_names("sbx-1");
    assert!(!statedir.join("acls").join(format!("{acl}.conf")).exists());
}

#[test]
fn drain_drops_stale_records_and_never_deletes_a_rebuilt_network() {
    // The journal holds attempt A's record, but the bridge on disk was
    // rebuilt by attempt B: the fenced drain drops the record and deletes
    // nothing.
    let (client, log) = client_for_with_log("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    let (network, _) = sandbox_network_names("sbx-1");
    fs::create_dir_all(statedir.join("networks")).unwrap();
    fs::write(
        statedir.join("networks").join(format!("{network}.conf")),
        "ipv4.address=10.200.1.1/24\nuser.wssp.project=default\nuser.wssp.sandbox_id=sbx-1\nuser.wssp.attempt=attempt-B\n",
    )
    .unwrap();
    client
        .persist_pending_cleanup("sbx-1", "attempt-A")
        .expect("record");
    client.drain_pending_network_cleanups().expect("drain");
    assert!(
        statedir
            .join("networks")
            .join(format!("{network}.conf"))
            .exists(),
        "the rebuilt network survives the stale drain"
    );
    assert!(
        !statedir
            .join("host-state/network-cleanups/sbx-1.json")
            .exists(),
        "stale record dropped"
    );
}

#[test]
fn concurrent_drain_and_retry_never_delete_the_new_attempt() {
    // Barrier-driven retry-vs-drain: a stale record from a failed attempt is
    // drained concurrently with the create retry re-applying the network.
    let (client, log) = client_for_with_log("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    client
        .persist_pending_cleanup("sbx-1", "stale-attempt")
        .expect("record");
    let plan = test_plan("sbx-1");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let drain_client = client.clone();
    let drain_barrier = barrier.clone();
    let drain = std::thread::spawn(move || {
        drain_barrier.wait();
        for _ in 0..50 {
            drain_client
                .drain_pending_network_cleanups()
                .expect("drain");
        }
    });
    barrier.wait();
    {
        // Production callers hold the sandbox lock across apply-to-adoption;
        // the direct client-level retry must do the same to serialize with
        // the drain's fence-to-delete section.
        let sandbox_lock = client.sandbox_lock("sbx-1");
        let _guard = sandbox_lock.lock().unwrap_or_else(|err| err.into_inner());
        client.apply_sandbox_network(&plan).expect("retry applies");
        client.clear_pending_cleanup("sbx-1").expect("adoption");
    }
    drain.join().expect("drain thread");
    let (network, acl) = sandbox_network_names("sbx-1");
    assert!(
        statedir
            .join("networks")
            .join(format!("{network}.conf"))
            .exists(),
        "the retry's network is never drained away"
    );
    assert!(statedir.join("acls").join(format!("{acl}.conf")).exists());
    assert!(
        !statedir
            .join("host-state/network-cleanups/sbx-1.json")
            .exists(),
        "adoption retires the obligation"
    );
}

#[test]
fn reconnect_reuses_the_persisted_expansion_across_dns_rotation() {
    let (mut runtime, log) = runtime_for("fix6_new_ready");
    let answers = std::sync::Arc::new(std::sync::Mutex::new((
        vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            128, 66, 0, 10,
        ))],
        0usize,
    )));
    let shared = answers.clone();
    runtime.override_resolver(std::sync::Arc::new(move |_domain, _wait| {
        let mut guard = shared.lock().unwrap();
        guard.1 += 1;
        Ok(guard.0.clone())
    }));
    let policy = EgressPolicy {
        mode: sandbox_protocol::EgressMode::Allowlist,
        domains: vec!["grants.example.com".to_string()],
        cidrs: Vec::new(),
    };
    let hash = super::network::policy_hash_hex(&policy);
    let mut request = create_req();
    request.egress_policy = Some(policy.clone());
    request.egress_policy_hash = Some(hash.clone());
    runtime.create_bound(&request).expect("create");
    assert_eq!(answers.lock().unwrap().1, 1, "create resolves once");
    let rule_adds = || {
        log_lines(&log)
            .iter()
            .filter(|line| line.contains("-X PUT") && line.contains("/network-acls/"))
            .count()
    };
    let created_rules = rule_adds();
    assert_eq!(
        created_rules, 2,
        "one static ACL installation and one atomic DNS policy update"
    );
    // DNS rotates under the SAME recorded policy: reconnect must not
    // re-resolve or demand the new answer.
    answers.lock().unwrap().0 = vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(
        128, 66, 0, 20,
    ))];
    let reconnect = |policy: EgressPolicy, hash: String| {
        runtime.reconnect_bound(&crate::ReconnectSandboxRequest {
            vm_size: sandbox_protocol::VmSize::defaults().unwrap(),
            lease: sandbox_protocol::HostLease::for_test(),
            template_fingerprint: create_req().template_digest,
            architecture: Some("x86_64".into()),
            guest: Default::default(),
            sandbox_id: "sbx-1".to_string(),
            instance_name: "wssp-sbx-sbx-1".to_string(),
            operation_id: "op-re".to_string(),
            idempotency_key: "re-1".to_string(),
            egress_policy: Some(policy),
            egress_policy_hash: Some(hash),
            egress_admission: crate::egress::EgressAdmission::PERMITTED,
            guest_sudo: false,
        })
    };
    reconnect(policy.clone(), hash.clone()).expect("reconnect after rotation");
    assert_eq!(
        answers.lock().unwrap().1,
        1,
        "the persisted expansion is reused; DNS is not re-resolved"
    );
    assert_eq!(
        rule_adds(),
        created_rules,
        "reconnect rewrites no ACL rules"
    );
    // A genuinely different policy (different hash) never reuses the
    // expansion: it re-resolves and conflicts with the immutable ACL.
    let changed = EgressPolicy {
        mode: sandbox_protocol::EgressMode::Allowlist,
        domains: vec!["grants.example.com".to_string()],
        cidrs: vec!["128.66.0.99/32".to_string()],
    };
    let changed_hash = super::network::policy_hash_hex(&changed);
    let err = reconnect(changed, changed_hash).expect_err("changed policy");
    assert_eq!(err.code, SandboxErrorCode::IdempotencyConflict);
    assert_eq!(answers.lock().unwrap().1, 2, "a new policy re-resolves");
}

#[test]
fn shim_client_applies_and_verifies_directly() {
    let client = client_for("running");
    let plan = test_plan("sbx-1");
    client.apply_sandbox_network(&plan).expect("apply");
    // Idempotent re-apply validates instead of recreating.
    client.apply_sandbox_network(&plan).expect("re-apply");
    client.teardown_sandbox_network("sbx-1").expect("teardown");
    // Teardown is idempotent too.
    client
        .teardown_sandbox_network("sbx-1")
        .expect("teardown again");
}

// ---- C35 round 3 ----

/// F1: two projects on one daemon. A dedicated project without network
/// isolation inherits the default project's networks; the project tag must
/// scope census, adoption, and teardown to the owning project.
#[test]
fn project_tag_scopes_census_and_teardown_to_the_owning_project() {
    let (default_client, log) = client_for_with_log("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    let plan = test_plan("sbx-1");
    {
        let lock = default_client.sandbox_lock("sbx-1");
        let _guard = lock.lock().unwrap_or_else(|err| err.into_inner());
        default_client.apply_sandbox_network(&plan).expect("apply");
        default_client
            .clear_pending_cleanup("sbx-1")
            .expect("adopt");
    }
    let (network, _acl) = sandbox_network_names("sbx-1");
    let conf_path = statedir.join("networks").join(format!("{network}.conf"));
    let conf = fs::read_to_string(&conf_path).unwrap();
    assert!(
        conf.contains("user.wssp.project=default"),
        "create stamps the owning project: {conf}"
    );
    // A second project on the same daemon: inherits the network (the shim
    // models features.networks=false) but never manages it.
    let mut tenant = crate::IncusClient::new(
        statedir.join("incus").to_string_lossy().into_owned(),
        "tenant".to_string(),
    );
    tenant.host_routes = Some(Vec::new());
    tenant.state_dir = Some(statedir.join("host-state"));
    assert!(
        default_client
            .network_cleanup_sandbox_ids()
            .expect("census")
            .contains(&"sbx-1".to_string()),
        "the owning project censuses its sandbox"
    );
    assert!(
        !tenant
            .network_cleanup_sandbox_ids()
            .expect("tenant census")
            .contains(&"sbx-1".to_string()),
        "an inheriting project never censuses another project's sandbox"
    );
    let err = tenant
        .teardown_owned_sandbox_network("sbx-1")
        .expect_err("foreign teardown refused");
    assert_eq!(err.code, SandboxErrorCode::IdempotencyConflict);
    assert!(
        conf_path.exists(),
        "a foreign project never deletes the network"
    );
    // Untagged resources do not prove ownership to either project.
    let legacy = statedir.join("networks").join("wsn-legacy00.conf");
    fs::write(
        &legacy,
        "ipv4.address=10.222.0.1/24\nuser.wssp.sandbox_id=sbx-legacy\n",
    )
    .unwrap();
    assert!(
        !default_client
            .network_cleanup_sandbox_ids()
            .expect("census")
            .contains(&"sbx-legacy".to_string())
    );
    assert!(
        !tenant
            .network_cleanup_sandbox_ids()
            .expect("tenant census")
            .contains(&"sbx-legacy".to_string()),
        "untagged resources never prove project ownership"
    );
    // R4-F4: outstanding obligations are project-scoped too. With two
    // projects sharing a state root, one project's drain must never process
    // (its teardown would conflict on the project fence) or UNLINK the other
    // project's record.
    let attempt = fs::read_to_string(&conf_path)
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("user.wssp.attempt="))
        .expect("attempt marker")
        .to_string();
    default_client
        .persist_pending_cleanup("sbx-1", &attempt)
        .expect("outstanding obligation");
    let record_path = statedir.join("host-state/network-cleanups/sbx-1.json");
    let record = fs::read_to_string(&record_path).expect("record");
    assert!(
        record.contains("\"project\":\"default\""),
        "the obligation persists its owning project: {record}"
    );
    tenant
        .drain_pending_network_cleanups()
        .expect("tenant drain");
    assert!(
        record_path.exists(),
        "a foreign project's drain never unlinks this project's obligation"
    );
    assert!(
        conf_path.exists(),
        "a foreign project's drain never touches this project's resources"
    );
    default_client
        .drain_pending_network_cleanups()
        .expect("owning drain");
    assert!(
        !conf_path.exists(),
        "the owning project's drain settles its own obligation"
    );
    assert!(!record_path.exists());
}

/// F2: the drain's fence read and its deletion are one serialized section per
/// sandbox. With the fence barrier held (fence passed, delete pending), a
/// concurrent retry must not restamp; once released, the stale attempt is
/// deleted and the retry rebuilds under a fresh incarnation.
#[test]
fn drain_fence_to_delete_is_serialized_against_a_retry() {
    let (client, log) = client_for_with_log("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    let (network, _acl) = sandbox_network_names("sbx-1");
    let conf_path = statedir.join("networks").join(format!("{network}.conf"));
    {
        let lock = client.sandbox_lock("sbx-1");
        let _guard = lock.lock().unwrap_or_else(|err| err.into_inner());
        client
            .apply_sandbox_network(&test_plan("sbx-1"))
            .expect("apply A");
        client.clear_pending_cleanup("sbx-1").expect("adopt");
    }
    let attempt_a = fs::read_to_string(&conf_path)
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("user.wssp.attempt="))
        .expect("attempt A")
        .to_string();
    // A crash-window record fencing to attempt A.
    client
        .persist_pending_cleanup("sbx-1", &attempt_a)
        .expect("record");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let mut drain_client = client.clone();
    drain_client.fence_barrier = Some(barrier.clone());
    let drain = std::thread::spawn(move || {
        drain_client
            .drain_pending_network_cleanups()
            .expect("drain");
    });
    // The drain passed the incarnation fence and holds the sandbox lock.
    barrier.wait();
    let retry_client = client.clone();
    let retry = std::thread::spawn(move || {
        let lock = retry_client.sandbox_lock("sbx-1");
        let _guard = lock.lock().unwrap_or_else(|err| err.into_inner());
        retry_client
            .apply_sandbox_network(&test_plan("sbx-1"))
            .expect("retry apply");
        retry_client.clear_pending_cleanup("sbx-1").expect("adopt");
    });
    std::thread::sleep(std::time::Duration::from_millis(150));
    assert!(
        !retry.is_finished(),
        "the retry must block on the sandbox lock during the fence-to-delete window"
    );
    assert!(
        fs::read_to_string(&conf_path)
            .unwrap()
            .contains(&format!("user.wssp.attempt={attempt_a}")),
        "no restamp while the drain is inside its critical section"
    );
    barrier.wait();
    drain.join().expect("drain thread");
    retry.join().expect("retry thread");
    let after = fs::read_to_string(&conf_path).expect("network rebuilt");
    let marker = after
        .lines()
        .find_map(|line| line.strip_prefix("user.wssp.attempt="))
        .expect("attempt B");
    assert_ne!(marker, attempt_a, "the retry rebuilt a fresh incarnation");
    let lines = log_lines(&log);
    let delete_at = lines
        .iter()
        .position(|line| line.contains(&format!("network delete {network}")))
        .expect("delete logged");
    let create_at = lines
        .iter()
        .rposition(|line| line.contains(&format!("network create {network}")))
        .expect("recreate logged");
    assert!(
        delete_at < create_at,
        "the stale attempt's deletion strictly precedes the retry's create"
    );
}

/// R4-F1: the drain reads the obligation UNDER the sandbox lock, not before
/// it. While the drain is blocked, a failed retry can durably replace the
/// record with the CURRENT incarnation's teardown obligation; a drain that
/// fenced its pre-lock snapshot against live resources and unlinked the
/// fresh record would orphan them permanently.
#[test]
fn drain_reads_the_obligation_under_the_sandbox_lock() {
    let (client, log) = client_for_with_log("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    let (network, acl) = sandbox_network_names("sbx-1");
    let conf_path = statedir.join("networks").join(format!("{network}.conf"));
    let acl_path = statedir.join("acls").join(format!("{acl}.conf"));
    let record_path = statedir.join("host-state/network-cleanups/sbx-1.json");
    {
        let lock = client.sandbox_lock("sbx-1");
        let _guard = lock.lock().unwrap_or_else(|err| err.into_inner());
        client
            .apply_sandbox_network(&test_plan("sbx-1"))
            .expect("apply");
        client.clear_pending_cleanup("sbx-1").expect("adopt");
    }
    let attempt = fs::read_to_string(&conf_path)
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("user.wssp.attempt="))
        .expect("attempt marker")
        .to_string();
    // The snapshot a pre-lock read would see: a stale obligation.
    client
        .persist_pending_cleanup("sbx-1", "attempt-stale")
        .expect("stale record");
    let drain_lock = client.sandbox_lock("sbx-1");
    let guard = drain_lock.lock().unwrap_or_else(|err| err.into_inner());
    let drain_client = client.clone();
    let drain = std::thread::spawn(move || {
        drain_client
            .drain_pending_network_cleanups()
            .expect("drain");
    });
    std::thread::sleep(std::time::Duration::from_millis(150));
    assert!(!drain.is_finished(), "the drain is blocked on the lock");
    // While it waits, the failed retry durably replaces the obligation with
    // the live incarnation's.
    client
        .persist_pending_cleanup("sbx-1", &attempt)
        .expect("fresh obligation");
    drop(guard);
    drain.join().expect("drain thread");
    assert!(
        !conf_path.exists() && !acl_path.exists(),
        "the drain fenced on the CURRENT record, not its pre-lock snapshot"
    );
    assert!(!record_path.exists(), "settled obligation removed");
}

/// R4-F2: a retry writes its fresh provisioning intent BEFORE restamping.
/// A crash right after that write leaves attempt-A resources; the journal
/// must still cover A (previous incarnations are retained), and the drain
/// recovers the orphan instead of dropping the record as stale.
#[test]
fn crash_between_retry_intent_and_restamp_is_recovered() {
    let (client, log) = client_for_with_log("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    let (network, acl) = sandbox_network_names("sbx-1");
    let conf_path = statedir.join("networks").join(format!("{network}.conf"));
    let acl_path = statedir.join("acls").join(format!("{acl}.conf"));
    let record_path = statedir.join("host-state/network-cleanups/sbx-1.json");
    {
        let lock = client.sandbox_lock("sbx-1");
        let _guard = lock.lock().unwrap_or_else(|err| err.into_inner());
        client
            .apply_sandbox_network(&test_plan("sbx-1"))
            .expect("apply A");
    }
    let attempt_a = fs::read_to_string(&conf_path)
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("user.wssp.attempt="))
        .expect("attempt A")
        .to_string();
    // The retry's write-ahead (production path): merges the live markers.
    client
        .persist_provisioning_intent("sbx-1", "attempt-B", test_plan("sbx-1").binding.as_ref())
        .expect("retry write-ahead");
    let record = fs::read_to_string(&record_path).expect("record");
    assert!(
        record.contains("attempt-B") && record.contains(&attempt_a),
        "the journal covers both incarnations: {record}"
    );
    // Crash before any restamp. The restart drain finds no VM.
    client.drain_pending_network_cleanups().expect("drain");
    assert!(
        !conf_path.exists() && !acl_path.exists(),
        "the crashed retry's previous-incarnation resources are recovered"
    );
    assert!(!record_path.exists());
}

/// R4-F2: a crash BETWEEN the ACL and bridge restamps leaves mixed
/// incarnations; the journal covers both and the drain recovers both.
#[test]
fn crash_between_retry_restamps_is_recovered() {
    let (client, log) = client_for_with_log("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    let (network, acl) = sandbox_network_names("sbx-1");
    let conf_path = statedir.join("networks").join(format!("{network}.conf"));
    let acl_path = statedir.join("acls").join(format!("{acl}.conf"));
    let record_path = statedir.join("host-state/network-cleanups/sbx-1.json");
    {
        let lock = client.sandbox_lock("sbx-1");
        let _guard = lock.lock().unwrap_or_else(|err| err.into_inner());
        client
            .apply_sandbox_network(&test_plan("sbx-1"))
            .expect("apply A");
    }
    client
        .persist_provisioning_intent("sbx-1", "attempt-B", test_plan("sbx-1").binding.as_ref())
        .expect("retry write-ahead");
    // Crash window: the ACL was restamped to B, the bridge was not.
    let out = client
        .run(
            &[
                "network",
                "acl",
                "set",
                &acl,
                super::network::NETWORK_ATTEMPT_TAG,
                "attempt-B",
            ],
            false,
        )
        .expect("restamp");
    assert_eq!(out.exit_code, 0);
    client.drain_pending_network_cleanups().expect("drain");
    assert!(
        !conf_path.exists() && !acl_path.exists(),
        "mixed-incarnation leftovers are both recovered"
    );
    assert!(!record_path.exists());
}

/// R4-F5: a directory fsync failure fails journal creation CLOSED — the
/// apply errors before its first host mutation instead of provisioning on a
/// non-durable journal hierarchy.
#[test]
fn journal_directory_sync_failure_fails_closed_before_any_mutation() {
    let (client, log) = client_for_with_log("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    let mut failing = client.clone();
    failing.fail_dir_sync = true;
    failing.state_dir = Some(statedir.join("deep").join("fresh"));
    let err = failing
        .persist_pending_cleanup("sbx-1", "attempt-1")
        .expect_err("a failed directory fsync propagates");
    assert_eq!(err.code, SandboxErrorCode::Internal);
    let err = failing
        .apply_sandbox_network(&test_plan("sbx-1"))
        .expect_err("apply fails closed on an undurable journal");
    assert_eq!(err.code, SandboxErrorCode::Internal);
    let lines = log_lines(&log);
    assert!(
        !lines
            .iter()
            .any(|line| line.contains("network create") || line.contains("network acl create")),
        "no host mutation when the journal cannot be made durable"
    );
}

/// F3: a recorded policy at the input bound (64 CIDRs) plus one domain
/// reconnects through the persisted expansion. The reuse path merges the
/// recorded CIDRs with the persisted grants (129 inputs before dedup); the
/// input bound governs the recorded policy only, the compiled bound the
/// merged result.
#[test]
fn reconnect_with_64_cidrs_and_one_domain_reuses_persisted_expansion() {
    let (mut runtime, _log) = runtime_for("fix6_new_ready");
    runtime.override_resolver(std::sync::Arc::new(|_domain, _wait| {
        Ok(vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            128, 66, 0, 10,
        ))])
    }));
    let policy = EgressPolicy {
        mode: sandbox_protocol::EgressMode::Allowlist,
        domains: vec!["grants.example.com".to_string()],
        // Public /24s: the sandbox protected set (198.18/15 included) is
        // refused as a grant.
        cidrs: (0..64).map(|i| format!("44.{i}.0.0/24")).collect(),
    };
    let hash = super::network::policy_hash_hex(&policy);
    let mut request = create_req();
    request.egress_policy = Some(policy.clone());
    request.egress_policy_hash = Some(hash.clone());
    runtime
        .create_bound(&request)
        .expect("create with 64 CIDRs + 1 domain");
    runtime
        .reconnect_bound(&crate::ReconnectSandboxRequest {
            vm_size: sandbox_protocol::VmSize::defaults().unwrap(),
            lease: sandbox_protocol::HostLease::for_test(),
            template_fingerprint: create_req().template_digest,
            architecture: Some("x86_64".into()),
            guest: Default::default(),
            sandbox_id: "sbx-1".to_string(),
            instance_name: "wssp-sbx-sbx-1".to_string(),
            operation_id: "op-re".to_string(),
            idempotency_key: "re-1".to_string(),
            egress_policy: Some(policy),
            egress_policy_hash: Some(hash),
            egress_admission: crate::egress::EgressAdmission::PERMITTED,
            guest_sudo: false,
        })
        .expect("reconnect reuses the persisted expansion (129 merged inputs, 65 destinations)");
}

/// F3: the expansion itself may exceed the input bound; only the compiled
/// destination bound and the ACL body bound (m12) apply to it. 64 static
/// CIDRs plus one domain resolving to 70 addresses is 134 destinations,
/// beyond the 128 input bound, within the 64 KiB ACL body.
#[test]
fn domain_expansion_beyond_the_input_bound_compiles() {
    let (mut runtime, _log) = runtime_for("fix6_new_ready");
    runtime.override_resolver(std::sync::Arc::new(|_domain, _wait| {
        Ok((0..70)
            .map(|i| std::net::IpAddr::V4(std::net::Ipv4Addr::new(128, 66, 0, i)))
            .collect())
    }));
    let policy = EgressPolicy {
        mode: sandbox_protocol::EgressMode::Allowlist,
        domains: vec!["many.example.com".to_string()],
        cidrs: (0..64).map(|i| format!("44.{i}.0.0/24")).collect(),
    };
    let hash = super::network::policy_hash_hex(&policy);
    let mut request = create_req();
    request.egress_policy = Some(policy);
    request.egress_policy_hash = Some(hash);
    runtime
        .create_bound(&request)
        .expect("134 resolved destinations compile within the destination and body bounds");
}

/// m12: an expansion whose ACL PUT body exceeds 64 KiB is refused before any
/// host mutation with the typed `egress_policy_too_large` reason — never
/// truncated. One name with 130 addresses needs ~87 KiB of rules.
#[test]
fn an_expansion_beyond_the_acl_body_bound_is_refused_before_host_io() {
    let (mut runtime, log) = runtime_for("fix6_new_ready");
    runtime.override_resolver(std::sync::Arc::new(|_domain, _wait| {
        Ok((0..130)
            .map(|i| std::net::IpAddr::V4(std::net::Ipv4Addr::new(128, 66, 0, i)))
            .collect())
    }));
    let policy = EgressPolicy {
        mode: sandbox_protocol::EgressMode::Allowlist,
        domains: vec!["many.example.com".to_string()],
        cidrs: Vec::new(),
    };
    let hash = super::network::policy_hash_hex(&policy);
    let mut request = create_req();
    request.egress_policy = Some(policy);
    request.egress_policy_hash = Some(hash);
    let err = runtime
        .create_bound(&request)
        .expect_err("an over-bound ACL body is refused");
    let err = match err {
        crate::EffectError::NotIssued(proof) => proof.into_error(),
        other => panic!("refusal must be NotIssued: {other:?}"),
    };
    assert_eq!(
        err.egress_refusal(),
        Some(crate::egress::EgressRefusal::PolicyTooLarge)
    );
    assert!(
        !log_lines(&log)
            .iter()
            .any(|line| line.contains("network create") || line.contains("network acl create")),
        "no network object exists for a refused policy"
    );
}

/// Recorded-policy validation precedes provisioning IO. Refusal classification
/// may only read VM existence, never query profiles or take an allocation lock.
#[test]
fn recorded_policy_input_bounds_fail_before_host_io() {
    let (runtime, log) = runtime_for("fix6_new_ready");
    let policy = EgressPolicy {
        mode: sandbox_protocol::EgressMode::Allowlist,
        domains: Vec::new(),
        cidrs: (0..129).map(|i| format!("198.{i}.0.0/24")).collect(),
    };
    let hash = super::network::policy_hash_hex(&policy);
    let mut request = create_req();
    request.egress_policy = Some(policy);
    request.egress_policy_hash = Some(hash);
    let invocations = log_lines(&log).len();
    let err = runtime
        .create_bound(&request)
        .expect_err("129 recorded CIDRs exceed the input bound");
    assert_eq!(err.code, SandboxErrorCode::ProtocolError);
    assert_eq!(
        log_lines(&log).len(),
        invocations + 1,
        "an out-of-bounds recorded policy only observes existence"
    );
    assert!(
        log_lines(&log)
            .last()
            .unwrap()
            .contains("query --raw /1.0/instances/wssp-sbx-sbx-1")
    );
}

/// R4-F6: reconnect also validates the recorded policy before binding the VM
/// or opening the allocation lock.
#[test]
fn reconnect_input_bounds_fail_before_any_daemon_invocation() {
    let (runtime, log) = runtime_for("fix6_new_ready");
    runtime.create_bound(&create_req()).expect("create");
    let policy = EgressPolicy {
        mode: sandbox_protocol::EgressMode::Allowlist,
        domains: Vec::new(),
        cidrs: (0..129).map(|i| format!("198.{i}.0.0/24")).collect(),
    };
    let hash = super::network::policy_hash_hex(&policy);
    let invocations = log_lines(&log).len();
    let err = runtime
        .reconnect_bound(&crate::ReconnectSandboxRequest {
            vm_size: sandbox_protocol::VmSize::defaults().unwrap(),
            lease: sandbox_protocol::HostLease::for_test(),
            template_fingerprint: create_req().template_digest,
            architecture: Some("x86_64".into()),
            guest: Default::default(),
            sandbox_id: "sbx-1".to_string(),
            instance_name: "wssp-sbx-sbx-1".to_string(),
            operation_id: "op-oob".to_string(),
            idempotency_key: "oob-1".to_string(),
            egress_policy: Some(policy),
            egress_policy_hash: Some(hash),
            egress_admission: crate::egress::EgressAdmission::PERMITTED,
            guest_sudo: false,
        })
        .expect_err("129 recorded CIDRs exceed the input bound");
    assert_eq!(err.code, SandboxErrorCode::ProtocolError);
    assert_eq!(
        log_lines(&log).len(),
        invocations,
        "an out-of-bounds recorded policy never even binds the VM"
    );
}

/// F4: the provisioning intent is written BEFORE the first host mutation, so
/// a crash in the apply-to-init window leaves a fenced obligation. The
/// restart drain finds no VM and completes the teardown.
#[test]
fn crash_after_apply_before_init_is_drained_from_the_provisioning_record() {
    let (client, log) = client_for_with_log("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    let (network, acl) = sandbox_network_names("sbx-1");
    {
        let lock = client.sandbox_lock("sbx-1");
        let _guard = lock.lock().unwrap_or_else(|err| err.into_inner());
        client
            .apply_sandbox_network(&test_plan("sbx-1"))
            .expect("apply");
    }
    let record_path = statedir.join("host-state/network-cleanups/sbx-1.json");
    let record = fs::read_to_string(&record_path).expect("provisioning record");
    assert!(
        record.contains("\"phase\":\"provisioning\""),
        "write-ahead intent: {record}"
    );
    assert!(
        statedir
            .join("networks")
            .join(format!("{network}.conf"))
            .exists()
    );
    assert!(statedir.join("acls").join(format!("{acl}.conf")).exists());
    // Host crash: the VM is never created. A restarted daemon drains.
    let restarted = client.clone();
    restarted.drain_pending_network_cleanups().expect("drain");
    assert!(
        !statedir
            .join("networks")
            .join(format!("{network}.conf"))
            .exists(),
        "the crashed attempt's bridge is removed"
    );
    assert!(
        !statedir.join("acls").join(format!("{acl}.conf")).exists(),
        "the crashed attempt's ACL is removed"
    );
    assert!(!record_path.exists(), "the obligation is retired");
}

/// F4: adoption (the VM exists) retires the provisioning record and the
/// drain never tears down a live sandbox's network.
#[test]
fn adoption_retires_the_intent_and_the_drain_keeps_live_networks() {
    let (runtime, log) = runtime_for("fix6_new_ready");
    runtime.create_bound(&create_req()).expect("create");
    let statedir = log.parent().expect("log parent").to_path_buf();
    let record_dir = statedir.join("host-state/network-cleanups");
    assert!(
        !record_dir.join("sbx-1.json").exists(),
        "adoption retired the provisioning record"
    );
    // A record that outlived its adoption (crash between VM creation and the
    // bookkeeping) is dropped, not acted on: the VM is the durable proof.
    // Modern writers always persist the full instance binding with the
    // intent; the drain re-verifies it before retiring (a binding-less or
    // conflicting record would fail closed instead).
    fs::create_dir_all(&record_dir).unwrap();
    fs::write(
        record_dir.join("sbx-1.json"),
        r#"{"sandbox_id":"sbx-1","attempts":["stale"],"project":"default","phase":"provisioning","binding":{"template_fingerprint":"sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789","create_key":"create-1"}}"#,
    )
    .unwrap();
    runtime
        .client()
        .drain_pending_network_cleanups()
        .expect("drain");
    let (network, acl) = sandbox_network_names("sbx-1");
    assert!(
        statedir
            .join("networks")
            .join(format!("{network}.conf"))
            .exists(),
        "a live sandbox's network is never drained"
    );
    assert!(statedir.join("acls").join(format!("{acl}.conf")).exists());
    assert!(!record_dir.join("sbx-1.json").exists(), "record dropped");
}

/// F5: the first record in a fresh, deeply nested state dir is written
/// through durable directory creation (every new component's parent is
/// synced) and is visible to a fresh client rooted there.
#[test]
fn first_record_in_a_fresh_deep_state_dir_survives() {
    let (client, log) = client_for_with_log("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    let deep = statedir.join("fresh").join("nested").join("state");
    assert!(!deep.exists());
    let mut fresh = client.clone();
    fresh.state_dir = Some(deep.clone());
    fresh
        .persist_pending_cleanup("sbx-1", "attempt-1")
        .expect("durable write into a fresh dir");
    assert!(deep.join("network-cleanups/sbx-1.json").exists());
    let mut rereader = client.clone();
    rereader.state_dir = Some(deep);
    assert!(
        rereader
            .network_cleanup_outstanding("sbx-1")
            .expect("outstanding"),
        "a fresh client rooted at the new dir observes the record"
    );
}

/// F6: the daemon-wide allocation lock serializes subnet choice with bridge
/// creation. Two colliding seeds: while one runtime holds the lock, the
/// other performs no network IO; after release it rechecks and picks a
/// different subnet.
#[test]
fn subnet_allocation_lock_serializes_concurrent_allocations() {
    // Find a second sandbox id whose hash-derived start collides with sbx-a's.
    let start_of = |id: &str| {
        let digest = ring::digest::digest(&ring::digest::SHA256, id.as_bytes());
        (digest.as_ref()[6], digest.as_ref()[7])
    };
    let target = start_of("sbx-a");
    let id_b = (0..500_000u32)
        .map(|i| format!("sbx-r{i}"))
        .find(|id| start_of(id) == target)
        .expect("a colliding sandbox id exists");
    let (client_a, log) = client_for_with_log("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    // A second host identity: same daemon, DIFFERENT state root. The lock is
    // daemon-wide (keyed by the daemon's server name), so B must still
    // serialize behind A.
    let mut client_b = client_a.clone();
    client_b.state_dir = Some(statedir.join("other-host-state"));
    let guard_a = client_a.lock_subnet_allocation().expect("lock A");
    let (_, acl_b) = sandbox_network_names(&id_b);
    let acl_b_path = statedir.join("acls").join(format!("{acl_b}.conf"));
    let worker = std::thread::spawn(move || {
        let _guard_b = client_b.lock_subnet_allocation().expect("lock B");
        let gateway_b = client_b.gateway_for(&id_b).expect("gateway B");
        let mut plan = test_plan(&id_b);
        plan.gateway = gateway_b;
        client_b.apply_sandbox_network(&plan).expect("apply B");
        gateway_b
    });
    std::thread::sleep(std::time::Duration::from_millis(150));
    assert!(
        !acl_b_path.exists(),
        "the second allocation performs no network mutation while the lock is held"
    );
    // A allocates and creates its bridge under the lock.
    let gateway_a = client_a.gateway_for("sbx-a").expect("gateway A");
    let mut plan_a = test_plan("sbx-a");
    plan_a.gateway = gateway_a;
    client_a.apply_sandbox_network(&plan_a).expect("apply A");
    drop(guard_a);
    let gateway_b = worker.join().expect("worker");
    assert_ne!(
        gateway_a, gateway_b,
        "the blocked allocation rechecks under the lock and avoids A's subnet"
    );
}

/// R5-F3: with a shared state root, a kill issued by one project must never
/// read, merge into, overwrite, or clear another project's obligation for
/// the same sandbox id.
#[test]
fn kill_in_one_project_never_overwrites_another_projects_obligation() {
    let (default_runtime, log) = runtime_for("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    let (network, acl) = sandbox_network_names("sbx-1");
    {
        let lock = default_runtime.client().sandbox_lock("sbx-1");
        let _guard = lock.lock().unwrap_or_else(|err| err.into_inner());
        default_runtime
            .client()
            .apply_sandbox_network(&test_plan("sbx-1"))
            .expect("apply");
    }
    // Default project's obligation is outstanding (VM never created).
    let record_path = statedir.join("host-state/network-cleanups/sbx-1.json");
    let before = fs::read_to_string(&record_path).expect("default obligation");
    // A tenant node daemon on the same Incus daemon, sharing the state root, kills
    // the same sandbox id (absent in the tenant project).
    let mut tenant = super::kvm::IncusKvmRuntime::new(super::kvm::IncusConfig {
        binary: statedir.join("incus").to_string_lossy().into_owned(),
        project: "tenant".to_string(),
    })
    .expect("tenant runtime");
    tenant.override_network_test_state(statedir.join("host-state"), Vec::new());
    let err = tenant
        .kill_bound(&crate::KillSandboxRequest {
            template_fingerprint: create_req().template_digest,
            sandbox_id: "sbx-1".to_string(),
            instance_name: "wssp-sbx-sbx-1".to_string(),
            operation_id: "op-tenant-kill".to_string(),
            idempotency_key: "tenant-kill-1".to_string(),
        })
        .expect_err("a foreign obligation is never overwritten");
    assert_eq!(err.code, SandboxErrorCode::IdempotencyConflict);
    assert_eq!(
        fs::read_to_string(&record_path).expect("record survives"),
        before,
        "the default project's obligation is byte-for-byte untouched"
    );
    assert!(
        statedir
            .join("networks")
            .join(format!("{network}.conf"))
            .exists()
            && statedir.join("acls").join(format!("{acl}.conf")).exists(),
        "the default project's resources are untouched"
    );
    // The owning project still settles its own obligation.
    default_runtime
        .client()
        .drain_pending_network_cleanups()
        .expect("owning drain");
    assert!(!record_path.exists());
}

/// R5-F4: a failed parent fsync leaves a visible but non-durable directory;
/// the retry must resync the parent chain before admitting records.
#[test]
fn retry_after_failed_parent_sync_resyncs_the_chain() {
    let (client, log) = client_for_with_log("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    let mut failing = client.clone();
    failing.state_dir = Some(statedir.join("deep").join("fresh"));
    failing.fail_dir_sync = true;
    failing
        .persist_pending_cleanup("sbx-1", "attempt-1")
        .expect_err("create succeeded but the parent sync failed");
    assert!(
        statedir.join("deep/fresh/network-cleanups").is_dir(),
        "the hierarchy is visible despite the failed sync"
    );
    // Retry with the sync of one ALREADY-VISIBLE directory's parent failing:
    // the retry must still attempt it (and therefore fail), proving visible
    // directories are never treated as durable.
    let mut retry = client.clone();
    retry.state_dir = Some(statedir.join("deep").join("fresh"));
    retry.fail_dir_sync_for = Some(statedir.join("deep"));
    let err = retry
        .persist_pending_cleanup("sbx-1", "attempt-1")
        .expect_err("the parent chain of visible directories is resynced");
    assert_eq!(err.code, SandboxErrorCode::Internal);
    retry.fail_dir_sync_for = None;
    retry
        .persist_pending_cleanup("sbx-1", "attempt-1")
        .expect("durable once the chain syncs");
    assert!(
        statedir
            .join("deep/fresh/network-cleanups/sbx-1.json")
            .exists()
    );
}

/// R5-F5: sandbox-lock registry entries are reclaimable; the registry never
/// grows without bound and concurrent lookups always share one lock.
#[test]
fn sandbox_lock_registry_reclaims_idle_entries() {
    let (client, _log) = client_for_with_log("fix6_new_ready");
    for i in 0..64 {
        let lock = client.sandbox_lock(&format!("sbx-idle-{i}"));
        drop(lock);
    }
    let _sweep = client.sandbox_lock("sbx-sweep");
    assert!(
        client.sandbox_lock_registry_len() <= 2,
        "idle entries are reclaimed: {}",
        client.sandbox_lock_registry_len()
    );
    let a = client.sandbox_lock("sbx-shared");
    let b = client.sandbox_lock("sbx-shared");
    assert!(
        std::sync::Arc::ptr_eq(&a, &b),
        "concurrent callers share one lock per sandbox"
    );
}

/// R6-F1: ownership is established BEFORE the per-drain budget is charged,
/// and a rotating cursor stops persistently failing records from starving
/// the ones behind them. 256 permanently-failing own records (a foreign
/// incarnation's resources cannot be fenced away) plus 50 foreign-project
/// records sit in front of one settleable own record: without
/// ownership-first filtering the foreign records consume the budget, and
/// without the cursor the 256 failures fill every drain forever.
#[test]
fn drain_filters_ownership_before_budget_and_rotates_past_failures() {
    let (client, log) = client_for_with_log("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    let dir = statedir.join("host-state/network-cleanups");
    fs::create_dir_all(&dir).expect("journal dir");
    let record = |sandbox: &str, project: &str| {
        format!(
            "{{\"sandbox_id\":\"{sandbox}\",\"attempts\":[\"x\"],\"phase\":\"teardown\",\"project\":\"{project}\"}}"
        )
    };
    // Foreign-project obligations, sorting BEFORE every own record.
    for i in 0..50 {
        fs::write(
            dir.join(format!("sbx-0{i:03}.json")),
            record(&format!("sbx-0{i:03}"), "tenant"),
        )
        .expect("foreign record");
    }
    // 256 own records whose teardown fails FOREVER: the fence matches
    // (marker `x`) but the daemon refuses every delete.
    fs::create_dir_all(statedir.join("networks")).expect("networks dir");
    for i in 0..256 {
        let id = format!("sbx-1{i:03}");
        fs::write(dir.join(format!("{id}.json")), record(&id, "default")).expect("own record");
        let (network, _) = sandbox_network_names(&id);
        fs::write(
            statedir.join("networks").join(format!("{network}.conf")),
            format!("ipv4.address=10.200.1.1/24\nuser.wssp.project=default\nuser.wssp.sandbox_id={id}\nuser.wssp.attempt=x\n"),
        )
        .expect("fenced resource");
        fs::write(statedir.join(format!("fail-delete-{network}")), "").expect("delete pin");
    }
    // One healthy own record sorting last; without ownership filtering +
    // rotation it is NEVER reached.
    fs::write(dir.join("sbx-9000.json"), record("sbx-9000", "default")).expect("healthy record");
    client.drain_pending_network_cleanups().expect("drain 1");
    assert!(
        dir.join("sbx-9000.json").exists(),
        "the first drain's budget went to the failing records"
    );
    client.drain_pending_network_cleanups().expect("drain 2");
    assert!(
        !dir.join("sbx-9000.json").exists(),
        "the cursor rotation reaches the settleable record behind 256 failures"
    );
    for i in 0..50 {
        assert!(
            dir.join(format!("sbx-0{i:03}.json")).exists(),
            "foreign obligations are never processed or unlinked"
        );
    }
    assert!(
        dir.join("sbx-1000.json").exists(),
        "persistently failing records stay for later drains"
    );
}

/// R6-F2: unreadable or malformed records are PRESERVED and reported —
/// ownership cannot be verified, so they are never unlinked — while the
/// drain still settles the verifiable records behind them.
#[test]
fn drain_preserves_and_reports_unverifiable_records() {
    let (client, log) = client_for_with_log("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    let dir = statedir.join("host-state/network-cleanups");
    fs::create_dir_all(&dir).expect("journal dir");
    let malformed = dir.join("sbx-bad1.json");
    fs::write(&malformed, "this is not json").expect("malformed record");
    let unreadable = dir.join("sbx-bad2.json");
    fs::write(
        &unreadable,
        "{\"sandbox_id\":\"sbx-bad2\",\"attempts\":[\"x\"],\"phase\":\"teardown\",\"project\":\"tenant\"}",
    )
    .expect("unreadable record");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o0)).expect("chmod 000");
    }
    // R7-F2: syntactically valid but structurally invalid records are just
    // as unverifiable — none of them may collapse into a legacy
    // default-project teardown with an adopt-any-marker empty attempt set.
    for (name, body) in [
        ("sbx-bad3", "null"),
        ("sbx-bad4", "{}"),
        (
            "sbx-bad5",
            "{\"sandbox_id\":\"sbx-bad5\",\"attempts\":[null],\"phase\":\"teardown\"}",
        ),
        (
            "sbx-bad6",
            "{\"sandbox_id\":\"sbx-bad6\",\"attempts\":[],\"phase\":\"teardown\"}",
        ),
        // Identity must match the filename.
        (
            "sbx-bad7",
            "{\"sandbox_id\":\"sbx-other\",\"attempts\":[\"x\"],\"phase\":\"teardown\",\"project\":\"default\"}",
        ),
        (
            "sbx-bad8",
            "{\"sandbox_id\":\"sbx-bad8\",\"attempt\":\"x\",\"phase\":3}",
        ),
    ] {
        fs::write(dir.join(format!("{name}.json")), body).expect("invalid record");
    }
    // R9-F3: a MODERN record (phase/project present) with NO attempt fields
    // must never degrade to the unfenced legacy shape — that would let the
    // drain adopt the resources' CURRENT marker and delete a newer
    // incarnation. Seed the resource such a record would otherwise destroy.
    let (bad9_network, _) = sandbox_network_names("sbx-bad9");
    fs::create_dir_all(statedir.join("networks")).expect("networks");
    fs::write(
        statedir
            .join("networks")
            .join(format!("{bad9_network}.conf")),
        "user.flycockpit.attempt=newer-incarnation\n",
    )
    .expect("stamped network");
    fs::write(
        dir.join("sbx-bad9.json"),
        "{\"sandbox_id\":\"sbx-bad9\",\"phase\":\"teardown\",\"project\":\"default\"}",
    )
    .expect("unfenced modern record");
    // A verifiable own obligation still settles in the same drain.
    fs::write(
        dir.join("sbx-good.json"),
        "{\"sandbox_id\":\"sbx-good\",\"attempts\":[\"x\"],\"phase\":\"teardown\",\"project\":\"default\"}",
    )
    .expect("good record");
    let err = client
        .drain_pending_network_cleanups()
        .expect_err("unverifiable records are reported, not silently dropped");
    assert_eq!(err.code, SandboxErrorCode::Internal);
    assert!(malformed.exists(), "a malformed record is preserved");
    assert!(unreadable.exists(), "an unreadable record is preserved");
    for name in [
        "sbx-bad3", "sbx-bad4", "sbx-bad5", "sbx-bad6", "sbx-bad7", "sbx-bad8", "sbx-bad9",
    ] {
        assert!(
            dir.join(format!("{name}.json")).exists(),
            "structurally invalid record {name} is preserved, never adopted or dropped"
        );
    }
    assert!(
        !dir.join("sbx-good.json").exists(),
        "the drain is still best-effort for verifiable records"
    );
    assert!(
        statedir
            .join("networks")
            .join(format!("{bad9_network}.conf"))
            .exists(),
        "an unfenced modern record authorizes NO deletion of the newer incarnation"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o600));
    }
}

/// R7-F1: restart recovery must never accept a VM before egress enforcement
/// is verified. Crash window: the network apply completed and the VM exists
/// (running), but the NIC check never ran — the daemon reports the plain
/// profile NIC. The drain must NOT retire the provisioning intent, and the
/// recovered-allocation query must NOT report success. Once enforcement is
/// verifiably in place, the intent retires.
#[test]
fn crash_before_nic_verification_never_retires_or_recovers() {
    let (runtime, log) = runtime_for("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    let client = runtime.client();
    client
        .apply_sandbox_network(&test_plan("sbx-1"))
        .expect("apply");
    let record = statedir.join("host-state/network-cleanups/sbx-1.json");
    assert!(record.exists(), "the provisioning intent is outstanding");
    // The VM exists and runs, but its effective devices are the unenforced
    // profile NIC (the crash happened before the NIC verification).
    fs::write(statedir.join("launched"), "").unwrap();
    fs::write(statedir.join("force-legacy-devices"), "").unwrap();
    client.drain_pending_network_cleanups().expect("drain");
    assert!(
        record.exists(),
        "an unverified VM never retires the provisioning intent"
    );
    let err = runtime
        .query_sandbox(
            "sbx-1",
            Some("create-1"),
            Some("sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"),
        )
        .expect_err("recovery refuses unenforced networking");
    // C37 R2: the VM is RUNNING — the bound-enforcement boundary surfaces
    // GuestUnavailable (cleanup-triggering), not a bare refusal.
    assert_eq!(err.code, SandboxErrorCode::GuestUnavailable);
    // Enforcement verifiably in place: recovery may proceed and the drain
    // retires the intent.
    fs::remove_file(statedir.join("force-legacy-devices")).unwrap();
    client.drain_pending_network_cleanups().expect("drain");
    assert!(!record.exists(), "verified enforcement retires the intent");
}

/// R7-F4 + R9-F2: the subnet-allocation lock is machine-wide AND
/// namespace-proof: the lock location is a fixed, administrator-provisioned
/// system path that sits OUTSIDE every private-temp-affected location.
/// systemd PrivateTmp isolates BOTH /tmp and /var/tmp per service, so a
/// lock anywhere under them would hand two isolated services driving the
/// same daemon DIFFERENT lock files at the identical pathname.
#[test]
fn allocation_lock_path_is_machine_wide_not_per_process() {
    let dir = crate::IncusClient::daemon_lock_dir();
    assert_eq!(
        dir,
        std::path::Path::new("/var/lib/wssp/incus-daemon-locks"),
        "the lock lives at an explicitly shared fixed system path"
    );
    assert!(
        !dir.starts_with(std::env::temp_dir()),
        "the lock location must not derive from this process's temp dir"
    );
    for private_tmp_affected in ["/tmp", "/var/tmp", "/dev/shm", "/run/user"] {
        assert!(
            !dir.starts_with(private_tmp_affected),
            "the lock location must not sit under {private_tmp_affected}: PrivateTmp and per-user namespaces would split it"
        );
    }
}

/// R9-F1/F2: the lock directory is administrator-PROVISIONED and validated
/// at use time. A missing directory, a symlinked directory, or a wrongly
/// permissioned directory fails closed with the operator provisioning
/// command — the runtime never auto-creates it at a shared location and
/// never repairs permissions it does not own.
#[test]
fn allocation_lock_requires_a_provisioned_trusted_directory() {
    let (mut client, log) = client_for_with_log("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    // Missing directory: clear operator-facing error.
    client.daemon_lock_dir_override = Some(statedir.join("never-provisioned"));
    let err = client
        .lock_subnet_allocation()
        .expect_err("an unprovisioned lock directory fails closed");
    assert_eq!(err.code, SandboxErrorCode::Internal);
    assert!(
        err.message.contains("sudo install -d -m 2770"),
        "the error carries the operator provisioning command: {}",
        err.message
    );
    // Wrong mode (no setgid, world-accessible): refused, never repaired.
    let dir = statedir.join("loose-locks");
    fs::create_dir(&dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    }
    client.daemon_lock_dir_override = Some(dir.clone());
    let err = client
        .lock_subnet_allocation()
        .expect_err("a wrongly-permissioned lock directory is refused");
    assert!(err.message.contains("mode 2770"), "{}", err.message);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o7777,
            0o755,
            "the runtime never repairs permissions on a directory it did not provision"
        );
    }
    // Symlinked directory: refused without following.
    let link = statedir.join("linked-locks");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&dir, &link).unwrap();
    client.daemon_lock_dir_override = Some(link);
    client
        .lock_subnet_allocation()
        .expect_err("a symlinked lock directory is refused");
    // Correctly provisioned (as the test harness models it): works — and a
    // SECOND identity (client) over the same provisioned directory contends
    // on the same lock (proven by subnet_allocation_lock_serializes...).
    let (client_ok, _) = client_for_with_log("fix6_new_ready");
    client_ok.lock_subnet_allocation().expect("provisioned dir");
    // Not provable in this sandbox: acquisition across genuinely distinct
    // UIDs (needs root/chown) and cross-PrivateTmp namespace contention
    // (needs mount-namespace privileges). The design covers both by
    // construction: group-based access at a path no namespace splits.
}

/// R8-F2: recovery verifies EFFECTIVE enforcement, not presence. An ACL
/// that gained an allow-all rule (or a bridge that lost its ACL attachment)
/// must fail recovery: the drain keeps the intent and the recovered-allocation
/// query refuses Ready.
#[test]
fn recovery_fails_closed_when_acl_rules_drift() {
    let (runtime, log) = runtime_for("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    let client = runtime.client();
    client
        .apply_sandbox_network(&test_plan("sbx-1"))
        .expect("apply");
    fs::write(statedir.join("launched"), "").unwrap();
    let record = statedir.join("host-state/network-cleanups/sbx-1.json");
    let (_, acl) = sandbox_network_names("sbx-1");
    // The ACL gains an allow-all egress rule (tampering between apply and
    // recovery).
    let mut rules = fs::read_to_string(statedir.join("acls").join(format!("{acl}.egress")))
        .expect("egress rules");
    rules.push_str("action=allow\n");
    fs::write(statedir.join("acls").join(format!("{acl}.egress")), rules).unwrap();
    client.drain_pending_network_cleanups().expect("drain");
    assert!(
        record.exists(),
        "a drifted ACL never retires the provisioning intent"
    );
    let err = runtime
        .query_sandbox(
            "sbx-1",
            Some("create-1"),
            Some("sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"),
        )
        .expect_err("a drifted ACL is never reported as recovered");
    // C37 R2: the VM is RUNNING — the bound-enforcement boundary surfaces
    // GuestUnavailable so the settle replay reaches the relay's cleanup.
    assert_eq!(err.code, SandboxErrorCode::GuestUnavailable, "{err:?}");
}

/// R8-F2 (bridge half): a bridge whose ACL attachment was removed still
/// "exists" — recovery must fail closed.
#[test]
fn recovery_fails_closed_when_bridge_loses_acl_attachment() {
    let (runtime, log) = runtime_for("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    let client = runtime.client();
    client
        .apply_sandbox_network(&test_plan("sbx-1"))
        .expect("apply");
    fs::write(statedir.join("launched"), "").unwrap();
    let record = statedir.join("host-state/network-cleanups/sbx-1.json");
    let (network, _) = sandbox_network_names("sbx-1");
    let conf_path = statedir.join("networks").join(format!("{network}.conf"));
    let conf = fs::read_to_string(&conf_path).expect("network conf");
    let stripped: Vec<&str> = conf
        .lines()
        .filter(|line| !line.starts_with("security.acls="))
        .collect();
    fs::write(&conf_path, stripped.join("\n") + "\n").unwrap();
    client.drain_pending_network_cleanups().expect("drain");
    assert!(
        record.exists(),
        "a bridge without its ACL attachment never retires the intent"
    );
    assert!(
        runtime
            .query_sandbox(
                "sbx-1",
                Some("create-1"),
                Some("sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"),
            )
            .is_err(),
        "recovery refuses a bridge with no ACL attached"
    );
}

/// R8-F3: the shared lock directory contents are adversary-controlled. A
/// predictable-name symlink must be rejected WITHOUT following it (the
/// target's permissions are untouched), and a non-regular file must be
/// rejected.
#[test]
fn allocation_lock_rejects_symlink_and_nonregular_files() {
    let (client, log) = client_for_with_log("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    let dir = statedir.join("daemon-locks");
    assert!(dir.is_dir(), "the harness provisions the shared lock dir");
    // Symlink attack: the lock path points at a daemon-owned file.
    let target = statedir.join("pretend-ssh-key");
    fs::write(&target, "secret").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let key = client.daemon_lock_key_for_test();
        let lock_path = dir.join(format!("{key}.lock"));
        let _ = fs::remove_file(&lock_path);
        std::os::unix::fs::symlink(&target, &lock_path).unwrap();
        let err = client
            .lock_subnet_allocation()
            .expect_err("a symlink lock file is rejected");
        assert_eq!(err.code, SandboxErrorCode::Internal);
        let meta = fs::metadata(&target).unwrap();
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o600,
            "the symlink target's permissions are never touched"
        );
        assert_eq!(fs::read_to_string(&target).unwrap(), "secret");
        let _ = fs::remove_file(&lock_path);
        // Non-regular file: a directory at the lock path is rejected.
        fs::create_dir(&lock_path).unwrap();
        client
            .lock_subnet_allocation()
            .expect_err("a non-regular lock path is rejected");
        let _ = fs::remove_dir(&lock_path);
    }
}

/// R8-F4: a held allocation lock never parks a worker: the wait is bounded
/// AND observes cancellation.
#[test]
fn held_allocation_lock_times_out_and_observes_cancellation() {
    let (client_a, log) = client_for_with_log("fix6_new_ready");
    let _statedir = log.parent().expect("log parent").to_path_buf();
    let _guard_a = client_a.lock_subnet_allocation().expect("lock A");
    // Bounded: a short-budget waiter fails fast with Timeout.
    let mut client_b = client_a.clone();
    client_b.allocation_lock_wait = Some(std::time::Duration::from_millis(200));
    let start = std::time::Instant::now();
    let err = client_b
        .lock_subnet_allocation()
        .expect_err("the held lock is not waited on forever");
    assert_eq!(err.code, SandboxErrorCode::Timeout);
    assert!(start.elapsed() < std::time::Duration::from_secs(5));
    // Cancellable: revocation DURING the wait aborts it promptly (the
    // permit is live for the daemon query, revoked mid-wait).
    let permit = std::sync::Arc::new(crate::RuntimePermit::default());
    let mut client_c = client_a.clone();
    client_c.cancelled = Some(permit.clone());
    client_c.allocation_lock_wait = Some(std::time::Duration::from_secs(60));
    let revoker = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(100));
        permit.revoke();
    });
    let start = std::time::Instant::now();
    let err = client_c
        .lock_subnet_allocation()
        .expect_err("cancellation aborts the lock wait");
    assert_eq!(err.code, SandboxErrorCode::UnknownOutcome);
    assert!(
        start.elapsed() < std::time::Duration::from_secs(5),
        "cancellation releases the waiter promptly"
    );
    revoker.join().expect("revoker");
}

/// R10-F1: a lock file owned by ANOTHER authorized daemon user is
/// validated, never chmodded (chmod by a non-owner fails with EPERM and
/// would block that user's every create/reconnect). Modelled via the
/// cfg(test) euid override — a genuinely foreign-UID file needs root, which
/// this sandbox cannot provide; what IS proven: the non-owner branch never
/// calls chmod and enforces the inherited group mode.
#[test]
fn allocation_lock_non_owner_validates_without_chmod() {
    let (mut client, log) = client_for_with_log("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    let dir = statedir.join("daemon-locks");
    let key = client.daemon_lock_key_for_test();
    let lock_path = dir.join(format!("{key}.lock"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // A well-formed lock file provisioned by "another" user: we are
        // (per the override) not its owner, so acquisition must NOT chmod
        // it — and must succeed.
        fs::write(&lock_path, "").unwrap();
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o660)).unwrap();
        client.lock_file_euid_override = Some(4_000_000);
        client
            .lock_subnet_allocation()
            .expect("a non-owner acquires a well-formed shared lock");
        assert_eq!(
            fs::metadata(&lock_path).unwrap().permissions().mode() & 0o777,
            0o660,
            "the non-owner path never modifies the file"
        );
        // A malformed one (group cannot write) is rejected, not repaired.
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o640)).unwrap();
        let err = client
            .lock_subnet_allocation()
            .expect_err("a non-owner must not chmod a badly-moded lock file");
        assert_eq!(err.code, SandboxErrorCode::Internal);
        // The REAL owner still initializes/repairs permissions.
        client.lock_file_euid_override = None;
        client
            .lock_subnet_allocation()
            .expect("the owner initializes permissions");
        assert_eq!(
            fs::metadata(&lock_path).unwrap().permissions().mode() & 0o777,
            0o660
        );
    }
}

/// R10-F2: a RELATIVE state root (e.g. WSSP_DATA_DIR=data) must not break
/// durable journal creation — the ancestor walk used to add the empty path
/// (`Path::parent("data")`) and `create_dir("")` failed, so enrollment
/// succeeded but the first provisioning record errored.
#[test]
fn relative_state_root_creates_durable_journal() {
    let (mut client, _log) = client_for_with_log("fix6_new_ready");
    let relative = std::path::PathBuf::from(format!("wssp-rel-state-{}", std::process::id()));
    assert!(relative.is_relative());
    client.state_dir = Some(relative.clone());
    client
        .apply_sandbox_network(&test_plan("sbx-1"))
        .expect("a relative state root must not break durable journal creation");
    assert!(
        relative.join("network-cleanups/sbx-1.json").exists(),
        "the provisioning record landed under the relative state root"
    );
    assert!(
        relative.join("network-cleanups/.wssp-durable").exists(),
        "the durability marker was written"
    );
    let _ = fs::remove_dir_all(&relative);
}

/// R11-F1: enrollment preflight fails closed on REAL access denial, not
/// just bad metadata. A provisioned directory beneath a search-denied
/// parent yields a genuine EACCES (no root or foreign UID needed); the
/// preflight must refuse with operator guidance BEFORE the relay connects
/// and advertises an egress-capable host. (Probing an access-denied create
/// inside a directory whose metadata still validates requires a foreign
/// owner — impossible without root; the acquisition path itself fail-closes
/// on the same EACCES.)
#[test]
fn enrollment_preflight_fails_closed_on_real_eacces() {
    let (_client, log) = client_for_with_log("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    let dir = statedir.join("daemon-locks");
    // Happy path: provisioned + usable.
    crate::IncusClient::preflight_daemon_lock_dir(&dir).expect("usable dir");
    assert_eq!(
        fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("access-probe"))
            .count(),
        0,
        "the probe cleans up after itself"
    );
    // Real EACCES: the lock dir's parent denies search (execute) permission.
    let jail = statedir.join("jail");
    let jailed_locks = jail.join("locks");
    fs::create_dir_all(&jailed_locks).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&jailed_locks, fs::Permissions::from_mode(0o2770)).unwrap();
        fs::set_permissions(&jail, fs::Permissions::from_mode(0o600)).unwrap();
        let err = crate::IncusClient::preflight_daemon_lock_dir(&jailed_locks)
            .expect_err("an inaccessible lock dir fails preflight");
        assert_eq!(err.code, SandboxErrorCode::Internal);
        assert!(
            err.message.contains("install -d -m 2770") || err.message.contains("usermod"),
            "the error carries operator guidance: {}",
            err.message
        );
        fs::set_permissions(&jail, fs::Permissions::from_mode(0o700)).unwrap();
    }
}

/// R11-F2: concurrent enrollments probe the shared directory WITHOUT
/// racing: uniquely named, create_new probes mean no daemon ever opens,
/// truncates, or removes another's probe file.
#[test]
fn concurrent_enrollment_probes_do_not_race() {
    let (_client, log) = client_for_with_log("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    let dir = std::sync::Arc::new(statedir.join("daemon-locks"));
    let mut threads = Vec::new();
    for _ in 0..8 {
        let dir = dir.clone();
        threads.push(std::thread::spawn(move || {
            for _ in 0..25 {
                crate::IncusClient::preflight_daemon_lock_dir(&dir)
                    .expect("concurrent preflights never race on a probe file");
            }
        }));
    }
    for thread in threads {
        thread.join().expect("probe thread");
    }
    assert_eq!(
        fs::read_dir(dir.as_ref())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("access-probe"))
            .count(),
        0,
        "every probe removed exactly its own file"
    );
}

/// R12-F1: recovery applies the FULL bind_instance authorization. A stopped
/// VM carrying this sandbox's tag but a conflicting template fingerprint,
/// base image, or create key is rejected by the normal create path; the
/// drain must equally refuse to repair its NIC or retire the intent. Only
/// the fully matching VM is recovered.
#[test]
fn drain_never_repairs_a_binding_conflicting_vm() {
    for (key, conflicting) in [
        (
            "user.flycockpit.template_digest",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        ),
        (
            "volatile.base_image",
            "1111111111111111111111111111111111111111111111111111111111111111",
        ),
        ("user.flycockpit.create_idempotency_key", "create-OTHER"),
    ] {
        let (runtime, log) = runtime_for("egress_legacy_nic_stopped");
        let statedir = log.parent().expect("log parent").to_path_buf();
        runtime
            .client()
            .apply_sandbox_network(&test_plan("sbx-1"))
            .expect("apply");
        let record = statedir.join("host-state/network-cleanups/sbx-1.json");
        assert!(record.exists(), "the provisioning intent is durable");
        // The VM's binding now conflicts on exactly one axis.
        fs::write(statedir.join("config").join(key), conflicting).unwrap();
        runtime
            .client()
            .drain_pending_network_cleanups()
            .expect("drain");
        assert!(
            !log_lines(&log)
                .iter()
                .any(|line| line.contains("config device")),
            "a VM whose {key} conflicts is never reconfigured by recovery"
        );
        assert!(
            record.exists(),
            "a VM whose {key} conflicts never retires the intent"
        );
    }
    // Control: the fully matching VM IS recovered and retires the intent.
    let (runtime, log) = runtime_for("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    runtime
        .client()
        .apply_sandbox_network(&test_plan("sbx-1"))
        .expect("apply");
    fs::write(statedir.join("launched"), "").unwrap();
    let record = statedir.join("host-state/network-cleanups/sbx-1.json");
    runtime
        .client()
        .drain_pending_network_cleanups()
        .expect("drain");
    assert!(
        !record.exists(),
        "a fully bound, enforced VM retires the intent"
    );
}

/// R13-F1+F2: an interrupted COLD reconnect (the VM is STOPPED; crash or
/// failure between the network apply and the adoption bookkeeping) leaves a
/// provisioning intent that (a) journals the VM's ORIGINAL create binding —
/// never the reconnect operation's key — so the drain's bind check matches
/// the legitimately bound VM, and (b) is NOT retired until the NIC is
/// verifiably enforced, so a failed repair keeps the obligation.
/// C37 R2: a RUNNING VM with an unenforced NIC no longer takes this path —
/// it surfaces GuestUnavailable (cleanup) at the bound-enforcement boundary.
#[test]
fn interrupted_reconnect_preserves_intent_with_original_binding() {
    let (runtime, log) = runtime_for("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    runtime.create_bound(&create_req()).expect("create");
    let record = statedir.join("host-state/network-cleanups/sbx-1.json");
    // Cold reconnect: the daemon reports the VM stopped, so the verify
    // failure is the non-destructive, journaled refusal.
    fs::write(statedir.join("stopped-instance"), "").unwrap();
    // The NIC drifted away: verification (and later the repair) must fail
    // before any start.
    fs::remove_file(statedir.join("device-eth0")).unwrap();
    fs::write(statedir.join("fail-device-add"), "").unwrap();
    let template = crate::CreateSandboxRequest::for_test("sbx-1", "create-1").template_digest;
    let err = runtime
        .reconnect_bound(&crate::ReconnectSandboxRequest {
            vm_size: sandbox_protocol::VmSize::defaults().unwrap(),
            lease: sandbox_protocol::HostLease::for_test(),
            template_fingerprint: template.clone(),
            architecture: Some("x86_64".into()),
            guest: Default::default(),
            sandbox_id: "sbx-1".to_string(),
            instance_name: "wssp-sbx-sbx-1".to_string(),
            operation_id: "op-re".to_string(),
            idempotency_key: "reconnect-9".to_string(),
            egress_policy: None,
            egress_policy_hash: None,
            egress_admission: crate::egress::EgressAdmission::PERMITTED,
            guest_sudo: false,
        })
        .expect_err("the pinned NIC repair failure fails the reconnect");
    let _ = err;
    // F2: the failed verification did NOT retire the provisioning intent.
    let body = fs::read_to_string(&record).expect("intent survives a failed NIC repair");
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    // F1: the journaled binding is the VM's ORIGINAL create key, not the
    // reconnect operation's idempotency key.
    assert_eq!(
        json["binding"]["create_key"].as_str(),
        Some("create-1"),
        "the intent journals the VM's original create binding, not the reconnect key"
    );
    assert_ne!(json["binding"]["create_key"].as_str(), Some("reconnect-9"));
    assert_eq!(
        json["binding"]["template_fingerprint"].as_str(),
        Some(template.as_str())
    );
    // Recovery: the drain binds the VM with the ORIGINAL key and repairs it.
    fs::remove_file(statedir.join("fail-device-add")).unwrap();
    fs::write(statedir.join("stopped-instance"), "").unwrap();
    runtime
        .client()
        .drain_pending_network_cleanups()
        .expect("drain");
    assert!(
        !record.exists(),
        "the drain binds with the original key, repairs, and retires"
    );
    assert!(
        statedir.join("device-eth0").exists(),
        "recovery restored the NIC"
    );
}

/// R13-F3: surface cleanup handles mixed incarnation markers. A crash
/// between a retry's restamps leaves bridge and ACL stamped with DIFFERENT
/// incarnations; cleanup must authorize and remove BOTH (and failure would
/// propagate with journaled evidence, never report success over an owned
/// leftover).
#[test]
fn mixed_incarnation_markers_are_both_torn_down() {
    let (client, log) = client_for_with_log("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    client
        .apply_sandbox_network(&test_plan("sbx-1"))
        .expect("apply");
    let (network_name, acl_name) = sandbox_network_names("sbx-1");
    let bridge_conf = statedir
        .join("networks")
        .join(format!("{network_name}.conf"));
    // Restamp ONLY the bridge: a crash between a retry's two restamps.
    let body = fs::read_to_string(&bridge_conf).unwrap();
    let restamped = body
        .lines()
        .map(|line| {
            if line.starts_with("user.wssp.attempt=") {
                "user.wssp.attempt=stale-incarnation".to_string()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert_ne!(restamped, body, "the bridge marker was actually restamped");
    fs::write(&bridge_conf, restamped + "\n").unwrap();
    client
        .teardown_owned_sandbox_network("sbx-1")
        .expect("cleanup fences BOTH owned incarnations");
    assert!(!bridge_conf.exists(), "bridge removed");
    assert!(
        !statedir
            .join("acls")
            .join(format!("{acl_name}.conf"))
            .exists(),
        "the differently-stamped owned ACL is removed too"
    );
}

/// R17-F2: a failed mixed-incarnation teardown journals EVERY observed owned
/// marker, so the restart drain keeps cleanup authority over both resources
/// instead of rejecting the differently-stamped one as a conflict and
/// dropping the obligation over a live owned ACL.
#[test]
fn failed_mixed_incarnation_teardown_journals_every_marker() {
    let (client, log) = client_for_with_log("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    client
        .apply_sandbox_network(&test_plan("sbx-1"))
        .expect("apply");
    let (network_name, acl_name) = sandbox_network_names("sbx-1");
    let bridge_conf = statedir
        .join("networks")
        .join(format!("{network_name}.conf"));
    let acl_conf = statedir.join("acls").join(format!("{acl_name}.conf"));
    let acl_marker = fs::read_to_string(&acl_conf)
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("user.wssp.attempt="))
        .expect("acl marker")
        .to_string();
    // Restamp ONLY the bridge: a crash between a retry's two restamps.
    let body = fs::read_to_string(&bridge_conf).unwrap();
    let restamped = body
        .lines()
        .map(|line| {
            if line.starts_with("user.wssp.attempt=") {
                "user.wssp.attempt=stale-incarnation".to_string()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&bridge_conf, restamped + "\n").unwrap();
    // Clear the provisioning-intent record (as VM adoption would), so the
    // failed teardown's journal is exactly what the teardown observed.
    client
        .clear_pending_cleanup("sbx-1")
        .expect("clear provisioning intent");
    // BOTH deletions fail mid-teardown: the bridge AND the differently-
    // stamped ACL both survive, so the journal must cover both markers.
    fs::write(statedir.join(format!("fail-delete-{network_name}")), "").unwrap();
    fs::write(statedir.join(format!("fail-delete-{acl_name}")), "").unwrap();
    client
        .teardown_owned_sandbox_network("sbx-1")
        .expect_err("the pinned deletions fail the teardown");
    assert!(bridge_conf.exists());
    assert!(acl_conf.exists());
    // The durable obligation must cover BOTH incarnations.
    let record_path = statedir.join("host-state/network-cleanups/sbx-1.json");
    let record: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&record_path).expect("obligation journaled"))
            .unwrap();
    let attempts: Vec<&str> = record["attempts"]
        .as_array()
        .expect("attempts list")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert!(
        attempts.contains(&"stale-incarnation") && attempts.contains(&acl_marker.as_str()),
        "every observed owned marker is journaled: {attempts:?}"
    );
    // Restart recovery: the drain fences on BOTH incarnations, removes both
    // resources, and retires the record.
    fs::remove_file(statedir.join(format!("fail-delete-{network_name}"))).unwrap();
    fs::remove_file(statedir.join(format!("fail-delete-{acl_name}"))).unwrap();
    client.drain_pending_network_cleanups().expect("drain");
    assert!(!bridge_conf.exists(), "bridge removed by the drain");
    assert!(!acl_conf.exists(), "the differently-stamped ACL is removed");
    assert!(!record_path.exists(), "the obligation is retired");
}

/// An owned resource without an incarnation marker still produces a
/// schema-valid journal record: an empty `attempts` list would fail the
/// read-side validation and wedge every later kill/drain retry.
#[test]
fn unmarked_owned_resource_still_journals_a_valid_record() {
    let (client, log) = client_for_with_log("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    let (network, _) = sandbox_network_names("sbx-1");
    fs::create_dir_all(statedir.join("networks")).unwrap();
    fs::write(
        statedir.join("networks").join(format!("{network}.conf")),
        "ipv4.address=10.200.1.1/24\nuser.wssp.project=default\nuser.wssp.sandbox_id=sbx-1\n",
    )
    .unwrap();
    client.prepare_network_cleanup("sbx-1").expect("prepare");
    let body = fs::read_to_string(statedir.join("host-state/network-cleanups/sbx-1.json"))
        .expect("record");
    let record: serde_json::Value = serde_json::from_str(&body).unwrap();
    let attempts = record["attempts"].as_array().expect("attempts list");
    assert!(!attempts.is_empty(), "the record is re-readable");
    // And it really does round-trip through the validated reader.
    client
        .drain_pending_network_cleanups()
        .expect("the drain can read the record");
}

/// R18-F1: a crash after restamping ONLY the ACL during legacy-pair
/// adoption leaves a marked ACL + unmarked bridge. The journal must fence
/// BOTH — including the empty-string incarnation — or recovery rejects the
/// bridge as a newer incarnation, drops the obligation, and strands the
/// marked ACL forever.
#[test]
fn mixed_marked_unmarked_pair_keeps_the_empty_fence() {
    let (client, log) = client_for_with_log("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    let (network, acl) = sandbox_network_names("sbx-1");
    client
        .apply_sandbox_network(&test_plan("sbx-1"))
        .expect("apply");
    let bridge_conf = statedir.join("networks").join(format!("{network}.conf"));
    let acl_conf = statedir.join("acls").join(format!("{acl}.conf"));
    let acl_marker = fs::read_to_string(&acl_conf)
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("user.wssp.attempt="))
        .expect("acl marker")
        .to_string();
    // The bridge is unmarked (legacy); the ACL was already restamped.
    let body = fs::read_to_string(&bridge_conf).unwrap();
    let unmarked = body
        .lines()
        .filter(|line| !line.starts_with("user.wssp.attempt="))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&bridge_conf, unmarked + "\n").unwrap();
    client
        .persist_provisioning_intent("sbx-1", "adopt-2", test_plan("sbx-1").binding.as_ref())
        .expect("intent");
    let record_path = statedir.join("host-state/network-cleanups/sbx-1.json");
    let record: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&record_path).unwrap()).unwrap();
    let attempts: Vec<&str> = record["attempts"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert!(
        attempts.contains(&"") && attempts.contains(&acl_marker.as_str()),
        "the empty fence survives alongside marked incarnations: {attempts:?}"
    );
    // Recovery (no VM exists): the drain tears down BOTH and retires the
    // obligation — the unmarked bridge is not rejected as a newer
    // incarnation, and the marked ACL is not stranded.
    client.drain_pending_network_cleanups().expect("drain");
    assert!(!bridge_conf.exists(), "unmarked bridge removed");
    assert!(!acl_conf.exists(), "marked ACL removed");
    assert!(!record_path.exists(), "obligation retired");
}

/// R18-F1 (teardown path): a failed teardown over a marked ACL + unmarked
/// bridge journals BOTH the marker and the empty-string fence, so the drain
/// tears the whole pair down instead of fencing itself off the unmarked
/// half.
#[test]
fn failed_teardown_over_mixed_pair_journals_the_empty_fence() {
    let (client, log) = client_for_with_log("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    client
        .apply_sandbox_network(&test_plan("sbx-1"))
        .expect("apply");
    let (network_name, acl_name) = sandbox_network_names("sbx-1");
    let bridge_conf = statedir
        .join("networks")
        .join(format!("{network_name}.conf"));
    let acl_conf = statedir.join("acls").join(format!("{acl_name}.conf"));
    let acl_marker = fs::read_to_string(&acl_conf)
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("user.wssp.attempt="))
        .expect("acl marker")
        .to_string();
    // Strip the bridge's marker: legacy/unstamped resource.
    let body = fs::read_to_string(&bridge_conf).unwrap();
    let unmarked = body
        .lines()
        .filter(|line| !line.starts_with("user.wssp.attempt="))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&bridge_conf, unmarked + "\n").unwrap();
    client
        .clear_pending_cleanup("sbx-1")
        .expect("clear provisioning intent");
    // Both deletions fail: both resources survive to be journaled.
    fs::write(statedir.join(format!("fail-delete-{network_name}")), "").unwrap();
    fs::write(statedir.join(format!("fail-delete-{acl_name}")), "").unwrap();
    client
        .teardown_owned_sandbox_network("sbx-1")
        .expect_err("pinned deletions fail the teardown");
    let record_path = statedir.join("host-state/network-cleanups/sbx-1.json");
    let record: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&record_path).unwrap()).unwrap();
    let attempts: Vec<&str> = record["attempts"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert!(
        attempts.contains(&"") && attempts.contains(&acl_marker.as_str()),
        "the empty fence is journaled alongside the marked ACL: {attempts:?}"
    );
    fs::remove_file(statedir.join(format!("fail-delete-{network_name}"))).unwrap();
    fs::remove_file(statedir.join(format!("fail-delete-{acl_name}"))).unwrap();
    client.drain_pending_network_cleanups().expect("drain");
    assert!(!bridge_conf.exists());
    assert!(!acl_conf.exists());
    assert!(!record_path.exists());
}

/// R18-F1 (owner teardown): teardown_owned_sandbox_network fences to the
/// markers it observed — including the empty string for an unmarked owned
/// resource — so a marked/unmarked pair is torn down together.
#[test]
fn owned_teardown_covers_an_unmarked_half_of_a_mixed_pair() {
    let (client, log) = client_for_with_log("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    client
        .apply_sandbox_network(&test_plan("sbx-1"))
        .expect("apply");
    let (network_name, acl_name) = sandbox_network_names("sbx-1");
    let bridge_conf = statedir
        .join("networks")
        .join(format!("{network_name}.conf"));
    let body = fs::read_to_string(&bridge_conf).unwrap();
    let unmarked = body
        .lines()
        .filter(|line| !line.starts_with("user.wssp.attempt="))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&bridge_conf, unmarked + "\n").unwrap();
    client
        .teardown_owned_sandbox_network("sbx-1")
        .expect("the unmarked bridge is covered by the empty fence");
    assert!(!bridge_conf.exists(), "unmarked bridge removed");
    assert!(
        !statedir
            .join("acls")
            .join(format!("{acl_name}.conf"))
            .exists(),
        "marked ACL removed"
    );
}

/// R20-F1: a valid host profile may name its root disk "rootfs" instead of
/// "root". Preflight accepts it (the audit checks properties, not names), so
/// create AND the recovery-time enforcement re-verification must accept the
/// VM's devices too — a name-keyed verification would strand a fully
/// provisioned sandbox behind an unrepairable mismatch.
#[test]
fn create_and_recovery_accept_a_rootfs_named_root_disk() {
    let (runtime, log) = runtime_for("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    fs::write(statedir.join("profile-root-name"), "rootfs").unwrap();
    runtime
        .create_bound(&create_req())
        .expect("create with a rootfs-named root disk");
    // Recovery path: enforcement re-verification over the same expanded set.
    runtime
        .client()
        .verify_provisioned_enforcement("sbx-1")
        .expect("recovery accepts the rootfs-named root disk");
}

/// R20-F2 (local legacy NIC): a stopped VM whose LOCAL eth0 still carries
/// legacy bridged properties is repaired by REPLACING the device wholesale —
/// the incompatible `parent` must not survive next to network=<bridge>,
/// which is what `device set`'s key merge would leave behind.
#[test]
fn repair_replaces_a_local_legacy_nic_wholesale() {
    let (runtime, log) = runtime_for("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    runtime.create_bound(&create_req()).expect("create");
    // Daemon-side drift: the local eth0 reverts to a legacy bridged NIC.
    fs::write(
        statedir.join("device-eth0"),
        "eth0,nictype=bridged,parent=br0",
    )
    .unwrap();
    let _ = fs::remove_file(statedir.join("started"));
    fs::write(statedir.join("stopped-instance"), "").unwrap();
    let plan = test_plan("sbx-1");
    runtime
        .client()
        .ensure_instance_egress_device("wssp-sbx-sbx-1", &plan)
        .expect("the stopped VM's legacy NIC is repaired");
    let spec = fs::read_to_string(statedir.join("device-eth0")).unwrap();
    assert!(
        !spec.contains("parent="),
        "the legacy parent property was replaced, not merged: {spec}"
    );
    assert!(
        spec.contains(&format!("network={}", plan.network_name)),
        "the repaired NIC is on the sandbox bridge: {spec}"
    );
    assert!(spec.contains("security.mac_filtering=true"), "{spec}");
}

/// R20-F2 (inherited legacy NIC): a VM whose eth0 comes ONLY from the
/// profile (legacy bridged properties) is repaired by adding a complete
/// local device that SHADOWS the inherited one — `device override`'s merge
/// would retain the incompatible `parent`.
#[test]
fn repair_shadows_an_inherited_legacy_nic_wholesale() {
    let (runtime, log) = runtime_for("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    runtime.create_bound(&create_req()).expect("create");
    // The local audited override disappears; the profile's eth0 is legacy.
    fs::remove_file(statedir.join("device-eth0")).unwrap();
    fs::write(statedir.join("profile-eth0"), "nictype=bridged,parent=br0").unwrap();
    let _ = fs::remove_file(statedir.join("started"));
    fs::write(statedir.join("stopped-instance"), "").unwrap();
    let plan = test_plan("sbx-1");
    runtime
        .client()
        .ensure_instance_egress_device("wssp-sbx-sbx-1", &plan)
        .expect("the inherited legacy NIC is shadowed by the audited device");
    let spec = fs::read_to_string(statedir.join("device-eth0")).unwrap();
    assert!(
        !spec.contains("parent="),
        "the inherited parent property is shadowed, not merged: {spec}"
    );
    assert!(
        spec.contains(&format!("network={}", plan.network_name)),
        "{spec}"
    );
}

/// R21-F1: the journal temp file is created O_EXCL|O_NOFOLLOW — a symlink
/// planted at the predictable temp name is REJECTED and its target's bytes
/// are untouched; a stale REGULAR temp file from a crashed write is
/// reclaimed instead of being fatal.
#[test]
fn journal_temp_file_never_follows_a_planted_symlink() {
    let (client, log) = client_for_with_log("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    let journal = statedir.join("host-state/network-cleanups");
    fs::create_dir_all(&journal).unwrap();
    let victim = statedir.join("victim.json");
    fs::write(&victim, b"precious").unwrap();
    // The temp path is writer-unique (C36 r20 F3): `.{name}.{pid}.{n}.tmp`.
    // The counter is PROCESS-GLOBAL, and the test binary runs tests in
    // parallel — another test's durable write may advance it between the
    // peek and this write. Plant a WINDOW of upcoming names so any
    // interleaved bump still lands on a planted path (the window is this
    // test's own directory; no other writer ever touches it).
    const WINDOW: u64 = 512;
    let base = super::acl::peek_durable_tmp_counter();
    let tmp_name = |n: u64| journal.join(format!(".sbx-1.json.{}.{n}.tmp", std::process::id()));
    let planted: Vec<std::path::PathBuf> = (base..base + WINDOW).map(&tmp_name).collect();
    for path in &planted {
        std::os::unix::fs::symlink(&victim, path).unwrap();
    }
    client
        .persist_provisioning_intent("sbx-1", "attempt-1", test_plan("sbx-1").binding.as_ref())
        .expect_err("a planted symlink at the journal temp path is rejected");
    assert_eq!(
        fs::read(&victim).unwrap(),
        b"precious",
        "the planted symlink's target is untouched"
    );
    for path in &planted {
        let _ = fs::remove_file(path);
    }
    // A stale REGULAR temp file (crashed write) is reclaimed, not fatal.
    let base = super::acl::peek_durable_tmp_counter();
    let stale: Vec<std::path::PathBuf> = (base..base + WINDOW).map(&tmp_name).collect();
    for path in &stale {
        fs::write(path, b"partial").unwrap();
    }
    client
        .persist_provisioning_intent("sbx-1", "attempt-1", test_plan("sbx-1").binding.as_ref())
        .expect("a stale regular temp file is reclaimed");
    for path in &stale {
        let _ = fs::remove_file(path);
    }
}

/// R22-F2: a fresh create against a valid LEGACY profile (eth0 =
/// nictype=bridged,parent=br0, which preflight accepts) must install the
/// pinned NIC as a COMPLETE local shadow: init never passes --device (its
/// merge would retain parent=br0 next to the sandbox bridge), the VM is
/// initialized stopped, the full device is added, and verification passes
/// before start.
#[test]
fn fresh_create_shadows_a_legacy_profile_nic_wholesale() {
    let (runtime, log) = runtime_for("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    fs::write(statedir.join("profile-eth0"), "nictype=bridged,parent=br0").unwrap();
    runtime
        .create_bound(&create_req())
        .expect("fresh create on a legacy profile");
    let lines = log_lines(&log);
    assert!(
        !lines.iter().any(|line| line.contains("--device")),
        "init must not merge NIC keys onto the profile device: {}",
        lines.join("\n")
    );
    let add_at = lines
        .iter()
        .position(|line| line.contains("config device add") && line.contains("eth0 nic network="))
        .expect("the complete NIC is installed post-init");
    let start_at = lines
        .iter()
        .position(|line| line.split_whitespace().next() == Some("start"))
        .expect("start");
    assert!(add_at < start_at, "the NIC shadow precedes first start");
    let spec = fs::read_to_string(statedir.join("device-eth0")).unwrap();
    assert!(
        !spec.contains("parent="),
        "no inherited property survives: {spec}"
    );
    assert!(spec.contains("security.mac_filtering=true"), "{spec}");
}

// ---------------------------------------------------------------------------
// C37 — verified-policy-before-start lifecycle ordering (issue #18).
// ---------------------------------------------------------------------------

fn reconnect_req(
    policy: Option<EgressPolicy>,
    hash: Option<String>,
) -> crate::ReconnectSandboxRequest {
    crate::ReconnectSandboxRequest {
        vm_size: sandbox_protocol::VmSize::defaults().unwrap(),
        lease: sandbox_protocol::HostLease::for_test(),
        template_fingerprint: create_req().template_digest,
        architecture: Some("x86_64".into()),
        guest: Default::default(),
        sandbox_id: "sbx-1".to_string(),
        instance_name: "wssp-sbx-sbx-1".to_string(),
        operation_id: "op-re".to_string(),
        idempotency_key: "re-1".to_string(),
        egress_policy: policy,
        egress_policy_hash: hash,
        egress_admission: crate::egress::EgressAdmission::PERMITTED,
        guest_sudo: false,
    }
}

fn start_lines(lines: &[String]) -> Vec<usize> {
    lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.split_whitespace().next() == Some("start"))
        .map(|(i, _)| i)
        .collect()
}

/// C37's core ordering invariant on a fake command trace: EVERY start is
/// preceded by an ACL readback against the recorded policy, with no ACL
/// mutation in between (a readback that a later mutation invalidated would
/// prove nothing).
fn assert_acl_readback_precedes_every_start(lines: &[String], acl: &str) {
    let is_acl_mutation = |line: &String| {
        line.contains("network acl create")
            || line.contains("network acl rule add")
            || line.contains("network acl rule remove")
            || line.contains("network acl delete")
            || line.contains("network acl set")
    };
    let is_acl_read = |line: &String| {
        line.contains("query") && line.contains(&format!("/1.0/network-acls/{acl}"))
    };
    let starts = start_lines(lines);
    assert!(!starts.is_empty(), "expected at least one start");
    for start_at in starts {
        let nearest = lines[..start_at]
            .iter()
            .rev()
            .find(|line| is_acl_mutation(line) || is_acl_read(line));
        assert!(
            matches!(nearest, Some(line) if is_acl_read(line)),
            "start at line {start_at} is not preceded by a fresh ACL readback:\n{}",
            lines.join("\n")
        );
    }
}

/// C37 acceptance: the fake command trace proves ACL verification precedes
/// EVERY start — the create's first start AND a cold resume after the
/// daemon reports the instance stopped.
#[test]
fn acl_readback_precedes_every_start_create_and_cold_resume() {
    let (runtime, log) = runtime_for("fix6_cold_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    let (policy, hash) = policy_with_cidr("128.66.0.0/24");
    // fix6_cold_* models a pre-existing stopped VM: create takes the
    // adopt-and-start path.
    runtime
        .create_bound(&create_with_policy())
        .expect("create adopts and starts");
    // The daemon later reports the instance stopped (cold reconnect).
    fs::remove_file(statedir.join("started")).unwrap();
    runtime
        .reconnect_bound(&reconnect_req(Some(policy), Some(hash)))
        .expect("cold resume");
    let (_, acl) = sandbox_network_names("sbx-1");
    let lines = log_lines(&log);
    assert_eq!(start_lines(&lines).len(), 2, "create start + resume start");
    assert_acl_readback_precedes_every_start(&lines, &acl);
}

/// C37 design requirement 4 (runtime bypass refusal): a DIRECT client start
/// — no create, no reconnect, no apply — must refuse when the recorded
/// network policy cannot be verified, and the start must never be issued.
#[test]
fn direct_start_without_verified_policy_is_refused_pre_issue() {
    let (client, log) = client_for_with_log("running");
    let bound = client
        .bind_instance(
            "wssp-sbx-sbx-1",
            "sbx-1",
            &create_req().template_digest,
            None,
        )
        .expect("bind");
    let err = client
        .start_bound(&bound, sandbox_protocol::VmSize::defaults().unwrap())
        .expect_err("unenforced start refuses");
    assert!(
        matches!(err, crate::EffectError::NotIssued(_)),
        "the fence refuses before issue: {err:?}"
    );
    assert!(
        !log_invoked(&log, "start"),
        "the bypassed start never reached the daemon"
    );
}

/// C37 acceptance (modified ACL): an ACL tampered with out-of-band fails the
/// reconnect's revalidation — the VM is never resumed.
#[test]
fn reconnect_with_modified_acl_never_resumes() {
    let (runtime, log) = runtime_for("fix6_cold_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    let (policy, hash) = policy_with_cidr("128.66.0.0/24");
    runtime.create_bound(&create_with_policy()).expect("create");
    fs::remove_file(statedir.join("started")).unwrap();
    // Out-of-band tampering: the ACL gains an allow-all egress rule.
    let (_, acl) = sandbox_network_names("sbx-1");
    let rules_path = statedir.join("acls").join(format!("{acl}.egress"));
    let mut rules = fs::read_to_string(&rules_path).expect("egress rules");
    rules.push_str("action=allow\n");
    fs::write(&rules_path, rules).unwrap();
    let err = runtime
        .reconnect_bound(&reconnect_req(Some(policy), Some(hash)))
        .expect_err("a modified ACL refuses the resume");
    assert!(
        err.code == SandboxErrorCode::IdempotencyConflict || err.code == SandboxErrorCode::Internal,
        "{err:?}"
    );
    assert_eq!(
        start_lines(&log_lines(&log)).len(),
        1,
        "only the original create started the VM"
    );
    // Fenced AND journaled: the refusal leaves a durable obligation for the
    // existing recovery machinery (C37 R1 spec semantics).
    assert!(
        statedir
            .join("host-state/network-cleanups/sbx-1.json")
            .exists(),
        "the fenced refusal is journaled"
    );
}

/// C37 acceptance (lost ACL, spec refusal semantics): an ACL lost out-of-band
/// PREVENTS the resume — reconnect never rebuilds enforcement around a VM.
/// The refusal is durable (a retry refuses again) and journaled, and the
/// existing recovery machinery (the restart drain) keeps the sandbox fenced
/// without rebuilding or tearing down anything under the bound VM.
#[test]
fn reconnect_refuses_a_lost_acl_and_stays_fenced() {
    let (runtime, log) = runtime_for("fix6_cold_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    let (policy, hash) = policy_with_cidr("128.66.0.0/24");
    runtime.create_bound(&create_with_policy()).expect("create");
    fs::remove_file(statedir.join("started")).unwrap();
    // The daemon loses the ACL (e.g. a host rebuilt from partial state).
    let (network, acl) = sandbox_network_names("sbx-1");
    for suffix in ["conf", "ingress", "egress", "project"] {
        fs::remove_file(statedir.join("acls").join(format!("{acl}.{suffix}"))).unwrap();
    }
    let err = runtime
        .reconnect_bound(&reconnect_req(Some(policy.clone()), Some(hash.clone())))
        .expect_err("a lost ACL refuses the resume");
    assert_eq!(err.code, SandboxErrorCode::IdempotencyConflict, "{err:?}");
    let lines = log_lines(&log);
    assert_eq!(
        start_lines(&lines).len(),
        1,
        "only the original create started the VM"
    );
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.contains(&format!("network acl create {acl}")))
            .count(),
        1,
        "the lost ACL is NEVER rebuilt by a reconnect"
    );
    // Fenced with recovery via the journal: the obligation is durable and
    // carries the VM's ORIGINAL create binding for the drain's bind check.
    let record = statedir.join("host-state/network-cleanups/sbx-1.json");
    let body = fs::read_to_string(&record).expect("the fenced refusal is journaled");
    assert!(
        body.contains("create-1"),
        "the journaled obligation binds the original create: {body}"
    );
    // Nothing was torn down or rebuilt: the bridge is left exactly as found.
    assert!(
        statedir
            .join("networks")
            .join(format!("{network}.conf"))
            .exists(),
        "the refusal mutates no enforcement objects"
    );
    // The refusal is durable: a retry refuses again.
    runtime
        .reconnect_bound(&reconnect_req(Some(policy), Some(hash)))
        .expect_err("the refusal is durable");
    // Recovery runs through the existing journal: the restart drain binds
    // the VM, re-verifies enforcement, and — still unverifiable — keeps the
    // sandbox fenced. It neither rebuilds the ACL nor tears the network
    // down from under the bound VM.
    runtime
        .client()
        .drain_pending_network_cleanups()
        .expect("drain");
    assert!(
        record.exists(),
        "the drain keeps the fenced obligation while enforcement is unverifiable"
    );
    assert!(
        statedir
            .join("networks")
            .join(format!("{network}.conf"))
            .exists(),
        "the drain does not tear down a bound VM's network"
    );
    let lines = log_lines(&log);
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.contains(&format!("network acl create {acl}")))
            .count(),
        1,
        "nobody — reconnect or drain — rebuilds the lost ACL"
    );
    assert_eq!(
        start_lines(&lines).len(),
        1,
        "still only the original create started the VM"
    );
}

/// C37 acceptance (failed create): a create whose VM init fails leaves the
/// unused network fenced under the provisioning intent, and the restart
/// drain cleans it up; the VM never starts.
#[test]
fn failed_create_cleans_up_the_unused_network() {
    let (runtime, log) = runtime_for("fix6_launch_absent");
    let statedir = log.parent().expect("log parent").to_path_buf();
    runtime
        .create_bound(&create_with_policy())
        .expect_err("init fails");
    let (network, acl) = sandbox_network_names("sbx-1");
    assert!(
        !log_invoked(&log, "start"),
        "a failed policy/VM setup never starts"
    );
    // The unused network is retained (fenced) until the drain confirms the
    // VM never existed — never torn down while uncertainty remains.
    let record = statedir.join("host-state/network-cleanups/sbx-1.json");
    assert!(record.exists(), "the provisioning obligation is durable");
    runtime
        .client()
        .drain_pending_network_cleanups()
        .expect("drain");
    assert!(
        !statedir
            .join("networks")
            .join(format!("{network}.conf"))
            .exists(),
        "the failed create's bridge is cleaned up"
    );
    assert!(
        !statedir.join("acls").join(format!("{acl}.conf")).exists(),
        "the failed create's ACL is cleaned up"
    );
    assert!(!record.exists(), "the obligation is retired");
}

/// C37 crash matrix (DNS publish): a crash issuing the initial DNS
/// publication — after the bridge and base ACL exist — rolls the whole
/// apply back; the VM is never initialized; the retry recomputes and
/// succeeds.
#[test]
fn crash_after_bridge_create_before_dns_publish_rolls_back() {
    let (mut runtime, log) = runtime_for("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    runtime.override_resolver(std::sync::Arc::new(|_domain, _wait| {
        Ok(vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            128, 66, 0, 10,
        ))])
    }));
    let policy = EgressPolicy {
        mode: sandbox_protocol::EgressMode::Allowlist,
        domains: vec!["grants.example.com".to_string()],
        cidrs: Vec::new(),
    };
    let hash = super::network::policy_hash_hex(&policy);
    let mut req = create_req();
    req.egress_policy = Some(policy);
    req.egress_policy_hash = Some(hash);
    fs::write(statedir.join("fail-raw-dnsmasq"), "").unwrap();
    runtime
        .create_bound(&req)
        .expect_err("the DNS publication crash fails the create");
    let (network, acl) = sandbox_network_names("sbx-1");
    let lines = log_lines(&log);
    assert!(
        lines
            .iter()
            .any(|line| line.contains(&format!("network delete {network}"))),
        "rollback removes the bridge: {}",
        lines.join("\n")
    );
    assert!(
        lines
            .iter()
            .any(|line| line.contains(&format!("network acl delete {acl}"))),
        "rollback removes the ACL"
    );
    assert!(!log_invoked(&log, "init"), "the VM is never initialized");
    assert!(!log_invoked(&log, "start"), "the VM never starts");
    fs::remove_file(statedir.join("fail-raw-dnsmasq")).unwrap();
    runtime
        .create_bound(&req)
        .expect("the retry recomputes, republishes, and starts");
}

/// C37 crash matrix (start): a crash AT the start command — after init and
/// the verified policy — leaves a stopped VM with its enforced network
/// retained; the create retry re-verifies and resumes it.
#[test]
fn crash_after_init_before_start_is_recovered_by_the_retry() {
    let (runtime, log) = runtime_for("c37_start_gated");
    let statedir = log.parent().expect("log parent").to_path_buf();
    fs::write(statedir.join("fail-start-once"), "").unwrap();
    runtime
        .create_bound(&create_with_policy())
        .expect_err("the crashed start fails the create");
    let (network, acl) = sandbox_network_names("sbx-1");
    let lines = log_lines(&log);
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.split_whitespace().next() == Some("init"))
            .count(),
        1,
        "one init"
    );
    assert_eq!(start_lines(&lines).len(), 1, "one crashed start attempt");
    // Uncertain-but-stopped: the enforced network is RETAINED for recovery.
    assert!(
        statedir
            .join("networks")
            .join(format!("{network}.conf"))
            .exists()
    );
    assert!(statedir.join("acls").join(format!("{acl}.conf")).exists());
    runtime
        .create_bound(&create_with_policy())
        .expect("the retry adopts, re-verifies, and resumes");
    let lines = log_lines(&log);
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.split_whitespace().next() == Some("init"))
            .count(),
        1,
        "the retry never re-initializes the VM"
    );
    assert_eq!(start_lines(&lines).len(), 2, "the retry starts it");
    assert_acl_readback_precedes_every_start(&lines, &acl);
}

/// C37 crash matrix (post-start): the start lands but readiness evidence
/// never arrives (guest agent down). Create fails without reporting Ready,
/// the sandbox reads back as NOT ready (fenced), and kill still tears the
/// network down after the confirmed destroy.
#[test]
fn crash_after_start_before_readiness_is_fenced_then_cleaned() {
    let (mut runtime, log) = runtime_for("c37_agent_down");
    let statedir = log.parent().expect("log parent").to_path_buf();
    runtime.override_agent_timeout(std::time::Duration::from_millis(300));
    let err = runtime
        .create_bound(&create_with_policy())
        .expect_err("readiness never arrives");
    assert_eq!(err.code, SandboxErrorCode::GuestUnavailable, "{err:?}");
    assert!(log_invoked(&log, "start"), "the start was issued");
    // Fenced: a guest-less Running VM is never reported Ready.
    runtime
        .query_sandbox(
            "sbx-1",
            Some("create-1"),
            Some("sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"),
        )
        .expect_err("unverifiable guest evidence is never Ready");
    // Kill is still safe: teardown follows the confirmed destroy.
    runtime
        .kill_bound(&crate::KillSandboxRequest {
            template_fingerprint: create_req().template_digest,
            sandbox_id: "sbx-1".to_string(),
            instance_name: "wssp-sbx-sbx-1".to_string(),
            operation_id: "op-kill".to_string(),
            idempotency_key: "kill-1".to_string(),
        })
        .expect("kill");
    let (network, acl) = sandbox_network_names("sbx-1");
    assert!(
        !statedir
            .join("networks")
            .join(format!("{network}.conf"))
            .exists()
    );
    assert!(!statedir.join("acls").join(format!("{acl}.conf")).exists());
}

/// C37 design requirement 7 (window closure): enforcement breaking BETWEEN
/// the pre-start fence and readiness evidence — the ACL gains an allow-all
/// rule at start — must be caught by the readiness fence: the create fails
/// closed even though the guest agent is healthy, and the sandbox never
/// reads Ready. C37 R1: the failure surfaces as GuestUnavailable — the
/// positively bound VM's enforcement loss is a READINESS failure, so the
/// relay queues the bound lifecycle cleanup (`guest_unavailable`) instead
/// of leaving a running, broadened-egress VM to normal lease expiry.
#[test]
fn readiness_fails_closed_when_enforcement_breaks_during_boot() {
    let (runtime, log) = runtime_for("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    fs::write(statedir.join("tamper-acl-on-start"), "").unwrap();
    let err = runtime
        .create_bound(&create_with_policy())
        .expect_err("a boot-time ACL break fails the create closed");
    assert_eq!(
        err.code,
        SandboxErrorCode::GuestUnavailable,
        "enforcement loss at readiness is a readiness failure (relay cleanup), not a binding conflict: {err:?}"
    );
    assert!(
        err.message.contains("enforcement"),
        "the readiness failure names the cause: {err:?}"
    );
    assert!(
        log_invoked(&log, "start"),
        "the start landed; the POST-start fence caught the tamper"
    );
    runtime
        .query_sandbox(
            "sbx-1",
            Some("create-1"),
            Some("sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"),
        )
        .expect_err("an unenforced guest never reads Ready");
}

/// C37 design requirement 5: network teardown runs only AFTER the destroy
/// is CONFIRMED (the post-delete absence observation), never on a requested
/// deletion alone.
#[test]
fn kill_tears_down_network_only_after_confirmed_destroy() {
    let (runtime, log) = runtime_for("running");
    runtime.create_bound(&create_with_policy()).expect("create");
    runtime
        .kill_bound(&crate::KillSandboxRequest {
            template_fingerprint: create_req().template_digest,
            sandbox_id: "sbx-1".to_string(),
            instance_name: "wssp-sbx-sbx-1".to_string(),
            operation_id: "op-kill".to_string(),
            idempotency_key: "kill-1".to_string(),
        })
        .expect("kill");
    let (network, _) = sandbox_network_names("sbx-1");
    let lines = log_lines(&log);
    let delete_at = lines
        .iter()
        .position(|line| line.split_whitespace().next() == Some("delete"))
        .expect("instance delete");
    let confirmed_at = lines[delete_at + 1..]
        .iter()
        .position(|line| line.contains("/1.0/instances/wssp-sbx-sbx-1"))
        .map(|i| delete_at + 1 + i)
        .expect("the absence observation follows the delete");
    let network_delete_at = lines
        .iter()
        .position(|line| line.contains(&format!("network delete {network}")))
        .expect("network delete");
    assert!(
        delete_at < confirmed_at && confirmed_at < network_delete_at,
        "teardown follows the CONFIRMED destroy:\n{}",
        lines.join("\n")
    );
}

/// C37 design requirement 5 (uncertain stop/destroy): when the destroy
/// cannot be confirmed, the kill fails, the restrictive rules stay in
/// place, and the obligation is journaled for recovery.
#[test]
fn uncertain_destroy_retains_restrictive_rules_and_journals() {
    let (runtime, log) = runtime_for("lifecycle_incomplete_delete");
    let statedir = log.parent().expect("log parent").to_path_buf();
    runtime.create_bound(&create_with_policy()).expect("create");
    runtime
        .kill_bound(&crate::KillSandboxRequest {
            template_fingerprint: create_req().template_digest,
            sandbox_id: "sbx-1".to_string(),
            instance_name: "wssp-sbx-sbx-1".to_string(),
            operation_id: "op-kill".to_string(),
            idempotency_key: "kill-1".to_string(),
        })
        .expect_err("the unconfirmed destroy fails the kill");
    let (network, acl) = sandbox_network_names("sbx-1");
    let lines = log_lines(&log);
    assert!(
        !lines
            .iter()
            .any(|line| line.contains(&format!("network delete {network}"))),
        "no network teardown while the destroy is unconfirmed"
    );
    assert!(
        !lines
            .iter()
            .any(|line| line.contains(&format!("network acl delete {acl}"))),
        "no ACL teardown while the destroy is unconfirmed"
    );
    assert!(
        statedir.join("acls").join(format!("{acl}.conf")).exists(),
        "the restrictive rules are retained"
    );
    assert!(
        statedir
            .join("host-state/network-cleanups/sbx-1.json")
            .exists(),
        "the teardown obligation is journaled"
    );
}

/// C37 design requirement 3: a default profile carrying config keys (raw.*,
/// security.acls*, boot.*, …) is rejected before any host mutation — the
/// launch pins its own config, so a profile key can only be an override.
#[test]
fn profile_with_config_keys_is_rejected_before_any_mutation() {
    for injected in [
        "raw.lxc=lxc.aa_profile=unconfined",
        "security.acls=permissive-acl",
    ] {
        let (runtime, log) = runtime_for("fix6_new_ready");
        let statedir = log.parent().expect("log parent").to_path_buf();
        fs::write(statedir.join("profile-config"), format!("{injected}\n")).unwrap();
        runtime
            .create_bound(&create_with_policy())
            .expect_err("a profile carrying config keys is refused");
        let lines = log_lines(&log);
        assert!(
            !lines.iter().any(|line| line.contains("network acl create")),
            "no network mutation for {injected}"
        );
        assert!(!log_invoked(&log, "init"), "no VM init for {injected}");
    }
}

/// C37-R8-2: conservative template-property preflight refuses config-like
/// image property names before allocating any VM or networking resources.
#[test]
fn template_config_preflight_blocks_allocation() {
    let (runtime, log) = runtime_for("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    fs::write(statedir.join("image-config"), "security.privileged=true\n").unwrap();
    runtime
        .create_bound(&create_with_policy())
        .expect_err("an image-injected config key refuses the launch");
    let lines = log_lines(&log);
    assert!(
        !log_invoked(&log, "init"),
        "no VM init for a rejected template"
    );
    assert!(
        !lines.iter().any(|line| line.starts_with("network ")),
        "no network mutation for a rejected template: {lines:?}"
    );
    assert!(
        !log_invoked(&log, "start"),
        "the injected config blocks the start:\n{}",
        lines.join("\n")
    );
}

/// C37 R1 (P1): a rejected launch config stays rejected on the create RETRY
/// — the template preflight runs again before any allocation.
#[test]
fn rejected_launch_config_create_retry_never_launches() {
    let (runtime, log) = runtime_for("c37_start_gated");
    let statedir = log.parent().expect("log parent").to_path_buf();
    fs::write(statedir.join("image-config"), "security.privileged=true\n").unwrap();
    runtime
        .create_bound(&create_with_policy())
        .expect_err("the first create is refused");
    runtime
        .create_bound(&create_with_policy())
        .expect_err("the retry is refused before allocation again");
    let lines = log_lines(&log);
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.split_whitespace().next() == Some("init"))
            .count(),
        0,
        "neither attempt initializes a VM:\n{}",
        lines.join("\n")
    );
    assert!(
        !log_invoked(&log, "start"),
        "no start on either attempt:\n{}",
        lines.join("\n")
    );
}

/// C37 R1 (P1): a rejected launch config stays rejected on RECONNECT — the
/// cold resume passes the same start boundary.
#[test]
fn rejected_launch_config_reconnect_never_launches() {
    let (runtime, log) = runtime_for("c37_start_gated");
    let statedir = log.parent().expect("log parent").to_path_buf();
    // An existing stopped VM with later config drift still reaches the
    // shared start fence (rather than the new template preflight).
    fs::write(statedir.join("fail-start-once"), "").unwrap();
    runtime
        .create_bound(&create_with_policy())
        .expect_err("the uncertain start leaves a stopped VM");
    fs::write(&log, "").unwrap(); // Observe only the rejected start boundary.
    fs::write(statedir.join("image-config"), "security.privileged=true\n").unwrap();
    let (policy, hash) = policy_with_cidr("128.66.0.0/24");
    let err = runtime
        .reconnect_bound(&reconnect_req(Some(policy), Some(hash)))
        .expect_err("the reconnect is refused by the same launch-config fence");
    assert_eq!(err.code, SandboxErrorCode::IdempotencyConflict, "{err:?}");
    assert!(
        !log_invoked(&log, "start"),
        "the reconnect never starts the rejected instance:\n{}",
        log_lines(&log).join("\n")
    );
}

/// C37 R1 (P1): a rejected launch config stays rejected on a DIRECT client
/// start — the fence is at the shared start boundary, not at any one caller.
#[test]
fn rejected_launch_config_direct_start_is_refused() {
    let (runtime, log) = runtime_for("c37_start_gated");
    let statedir = log.parent().expect("log parent").to_path_buf();
    // An existing stopped VM with later config drift still reaches the
    // shared start fence (rather than the new template preflight).
    fs::write(statedir.join("fail-start-once"), "").unwrap();
    runtime
        .create_bound(&create_with_policy())
        .expect_err("the uncertain start leaves a stopped VM");
    fs::write(&log, "").unwrap(); // Observe only the rejected start boundary.
    fs::write(statedir.join("image-config"), "security.privileged=true\n").unwrap();
    let bound = runtime
        .client()
        .bind_instance(
            "wssp-sbx-sbx-1",
            "sbx-1",
            &create_req().template_digest,
            None,
        )
        .expect("bind");
    let err = runtime
        .client()
        .start_bound(&bound, sandbox_protocol::VmSize::defaults().unwrap())
        .expect_err("the direct start is refused pre-issue");
    assert!(
        matches!(err, crate::EffectError::NotIssued(_)),
        "the fence refuses before issue: {err:?}"
    );
    assert!(
        !log_invoked(&log, "start"),
        "the rejected instance is never started:\n{}",
        log_lines(&log).join("\n")
    );
}

/// C37 design requirement 7: readiness includes the DNS fence state. A
/// committed-elsewhere revocation marker that never reconciled blocks the
/// reconnect's verified-policy path — the guest answering is not enough.
#[test]
fn reconnect_is_refused_while_a_dns_revocation_marker_is_pending() {
    let (mut runtime, log) = runtime_for("fix6_cold_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    runtime.override_resolver(std::sync::Arc::new(|_domain, _wait| {
        Ok(vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            128, 66, 0, 10,
        ))])
    }));
    let policy = EgressPolicy {
        mode: sandbox_protocol::EgressMode::Allowlist,
        domains: vec!["grants.example.com".to_string()],
        cidrs: Vec::new(),
    };
    let hash = super::network::policy_hash_hex(&policy);
    let mut req = create_req();
    req.egress_policy = Some(policy.clone());
    req.egress_policy_hash = Some(hash.clone());
    runtime.create_bound(&req).expect("create");
    fs::remove_file(statedir.join("started")).unwrap();
    // Plant an unreconciled revocation marker (a refresh that journaled the
    // denial and died before committing).
    let markers = statedir.join("host-state/dns-revocations");
    fs::create_dir_all(&markers).unwrap();
    fs::write(
        markers.join("sbx-1.json"),
        serde_json::json!({
            "sandbox_id": "sbx-1",
            "policy_hash": hash,
            "project": "default",
            "revoked": ["grants.example.com"],
            "revoked_generations": {},
            "pending": [],
            "next_request": 0,
            "standing_fences": [],
            "refresh_owed": false,
            "published_attempts": []
        })
        .to_string(),
    )
    .unwrap();
    assert!(runtime.client().dns_refresh_owed("sbx-1"));
    runtime
        .reconnect_bound(&reconnect_req(Some(policy), Some(hash)))
        .expect_err("a pending DNS revocation fences the resume");
    assert_eq!(
        start_lines(&log_lines(&log)).len(),
        1,
        "only the original create started the VM"
    );
}

/// C37 crash matrix (lease race): a lease that expires while the network
/// apply is in flight must never resume the VM — the reconnect revalidates
/// the lease after the apply and before any start.
#[test]
fn lease_expiring_mid_reconnect_never_resumes() {
    let (runtime, log) = runtime_for("fix6_cold_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    runtime.create_bound(&create_with_policy()).expect("create");
    fs::remove_file(statedir.join("started")).unwrap();
    // Park the reconnect's first ACL read until the lease has lapsed.
    fs::write(statedir.join("barrier-acl-read"), "0").unwrap();
    let release = statedir.join("release-acl-read-barrier");
    let releaser = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(2500));
        fs::write(release, "").unwrap();
    });
    let deadline = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64
        + 1_500;
    // The reconnect carries the RECORDED policy (immutable); only the lease
    // is short-lived.
    let (policy, hash) = policy_with_cidr("128.66.0.0/24");
    let mut request = reconnect_req(Some(policy), Some(hash));
    request.lease = sandbox_protocol::HostLease {
        revision: 1,
        deadline_unix_ms: deadline,
        action: sandbox_protocol::LeaseAction::Stop,
        expiry_policy: sandbox_protocol::ExpiryPolicy::RetryForce60s,
        shorten_only: false,
        from_ready_ms: None,
    };
    let err = runtime
        .reconnect_bound(&request)
        .expect_err("the lapsed lease refuses the resume");
    releaser.join().expect("releaser");
    assert_eq!(err.code, SandboxErrorCode::StateConflict, "{err:?}");
    assert_eq!(
        start_lines(&log_lines(&log)).len(),
        1,
        "no resume after the lease lapsed"
    );
}

// ---------------------------------------------------------------------
// C37 R2 (P1): ONE bound-enforcement boundary across every readiness /
// runnability consumer. A positively bound RUNNING VM whose enforcement is
// lost or tampered must surface GuestUnavailable — the wire code the
// relay's generation-fenced cleanup consumes — on every consumer; stopped
// and foreign VMs keep the non-destructive refusal.
// ---------------------------------------------------------------------

/// Out-of-band ACL tamper: append an allow-all egress rule (the finding's
/// exact scenario).
fn tamper_acl_allow_all(statedir: &Path) {
    let (_, acl) = sandbox_network_names("sbx-1");
    let rules_path = statedir.join("acls").join(format!("{acl}.egress"));
    let mut rules = fs::read_to_string(&rules_path).expect("egress rules");
    rules.push_str("action=allow\n");
    fs::write(&rules_path, rules).unwrap();
}

fn probe_req() -> crate::ProbeSandboxRequest {
    crate::ProbeSandboxRequest {
        template_fingerprint: create_req().template_digest,
        architecture: Some("x86_64".into()),
        sandbox_id: "sbx-1".to_string(),
        instance_name: "wssp-sbx-sbx-1".to_string(),
        operation_id: "op-probe".to_string(),
        idempotency_key: "probe-1".to_string(),
        guest: Default::default(),
    }
}

/// C37 R2 acceptance (the finding's scenario): a WARM reconnect — the bound
/// VM is RUNNING — whose ACL gained an allow-all rule out-of-band surfaces
/// GuestUnavailable, so the op result feeds the relay's generation-fenced
/// cleanup. The host neither restarts the VM nor journals a fenced refusal
/// (the drain only repairs devices and retries verification — it cannot
/// fence a RUNNING VM's traffic), and tears nothing down on its own
/// authority: cleanup ownership moves to the relay.
#[test]
fn warm_reconnect_with_modified_acl_triggers_cleanup_semantics() {
    let (runtime, log) = runtime_for("fix6_cold_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    let (policy, hash) = policy_with_cidr("128.66.0.0/24");
    runtime.create_bound(&create_with_policy()).expect("create");
    // No out-of-band stop: the VM is still RUNNING — a warm reconnect.
    tamper_acl_allow_all(&statedir);
    let err = runtime
        .reconnect_bound(&reconnect_req(Some(policy), Some(hash)))
        .expect_err("a running, unenforced VM refuses the warm reconnect");
    assert_eq!(
        err.code,
        SandboxErrorCode::GuestUnavailable,
        "a running bound VM's enforcement loss is cleanup-triggering, not a refusal: {err:?}"
    );
    assert_eq!(
        start_lines(&log_lines(&log)).len(),
        1,
        "the warm reconnect never restarts the VM"
    );
    assert!(
        !statedir
            .join("host-state/network-cleanups/sbx-1.json")
            .exists(),
        "no fenced-refusal journal: the drain cannot fence a running VM"
    );
    let (network, _) = sandbox_network_names("sbx-1");
    assert!(
        statedir
            .join("networks")
            .join(format!("{network}.conf"))
            .exists(),
        "the host tears nothing down on its own authority"
    );
}

/// C37 R2 (clean leg): a warm reconnect with enforcement intact verifies
/// through the same boundary and succeeds WITHOUT restarting the VM.
#[test]
fn warm_reconnect_with_verified_enforcement_resumes() {
    let (runtime, log) = runtime_for("fix6_cold_ready");
    let (policy, hash) = policy_with_cidr("128.66.0.0/24");
    runtime.create_bound(&create_with_policy()).expect("create");
    runtime
        .reconnect_bound(&reconnect_req(Some(policy), Some(hash)))
        .expect("a warm reconnect with intact enforcement succeeds");
    let lines = log_lines(&log);
    assert_eq!(
        start_lines(&lines).len(),
        1,
        "a warm reconnect never restarts the VM"
    );
    let (_, acl) = sandbox_network_names("sbx-1");
    assert_acl_readback_precedes_every_start(&lines, &acl);
}

/// C37 R2 (foreign leg): a warm reconnect to a VM re-labeled out-of-band —
/// with the ACL tampered, so the boundary WOULD fail — still raises the
/// non-destructive conflict: a foreign instance never reaches the boundary
/// and never triggers cleanup semantics.
#[test]
fn warm_reconnect_to_a_foreign_vm_never_reaches_the_cleanup_boundary() {
    let (runtime, log) = runtime_for("fix6_cold_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    let (policy, hash) = policy_with_cidr("128.66.0.0/24");
    runtime.create_bound(&create_with_policy()).expect("create");
    tamper_acl_allow_all(&statedir);
    // The VM is re-labeled out-of-band: it is no longer positively bound.
    fs::write(
        statedir.join("config/user.flycockpit.sandbox_id"),
        "sbx-OTHER",
    )
    .unwrap();
    let err = runtime
        .reconnect_bound(&reconnect_req(Some(policy), Some(hash)))
        .expect_err("a foreign VM refuses");
    assert_eq!(
        err.code,
        SandboxErrorCode::IdempotencyConflict,
        "foreign is the non-destructive refusal, never the cleanup code: {err:?}"
    );
    assert_eq!(
        start_lines(&log_lines(&log)).len(),
        1,
        "the foreign VM is never restarted"
    );
    let (network, _) = sandbox_network_names("sbx-1");
    assert!(
        statedir
            .join("networks")
            .join(format!("{network}.conf"))
            .exists(),
        "nothing is torn down"
    );
}

/// C37 R2 (query leg): the state query — the result a restart receipt
/// settle consumes — surfaces GuestUnavailable for a bound RUNNING VM whose
/// enforcement broke, so the settle replay reaches the relay's cleanup
/// instead of stranding the sandbox READY.
#[test]
fn query_sandbox_running_unenforced_surfaces_cleanup_code() {
    let (runtime, log) = runtime_for("fix6_cold_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    runtime.create_bound(&create_with_policy()).expect("create");
    // The adopt path carries no readiness metadata; seed what a fresh
    // create's launch would have written.
    fs::write(
        statedir.join("config/user.flycockpit.readiness"),
        serde_json::to_string(&super::client::ReadinessSpec {
            guest: Default::default(),
            architecture: "x86_64".into(),
            mode: Default::default(),
            privilege: Default::default(),
        })
        .unwrap(),
    )
    .unwrap();
    // Clean control: the verified running VM reads Ready.
    let state = runtime
        .query_sandbox(
            "sbx-1",
            Some("create-1"),
            Some(&create_req().template_digest),
        )
        .expect("query");
    assert_eq!(
        state,
        Some(sandbox_protocol::SandboxLifecycleState::Ready),
        "the enforced running VM reads Ready"
    );
    tamper_acl_allow_all(&statedir);
    let err = runtime
        .query_sandbox(
            "sbx-1",
            Some("create-1"),
            Some(&create_req().template_digest),
        )
        .expect_err("an unenforced running VM never reads Ready");
    assert_eq!(
        err.code,
        SandboxErrorCode::GuestUnavailable,
        "the query surfaces the cleanup-triggering code: {err:?}"
    );
}

/// C37 R2 (probe leg): a live probe certifies GuestReady only through the
/// boundary — a bound RUNNING VM whose enforcement broke is reported
/// unreachable (the error the probe callers map to "unreachable"), never
/// GuestReady.
#[test]
fn probe_never_reports_guest_ready_for_an_unenforced_running_vm() {
    let (runtime, log) = runtime_for("fix6_cold_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    runtime.create_bound(&create_with_policy()).expect("create");
    // Clean control: the enforced running VM probes GuestReady.
    let clean = runtime.probe_sandbox(&probe_req()).expect("probe");
    assert_eq!(
        clean.state,
        crate::SandboxLiveProbeState::GuestReady,
        "the enforced running VM probes GuestReady"
    );
    tamper_acl_allow_all(&statedir);
    let err = runtime
        .probe_sandbox(&probe_req())
        .expect_err("an unenforced running VM never probes GuestReady");
    assert_eq!(
        err.code,
        SandboxErrorCode::GuestUnavailable,
        "the probe surfaces the cleanup-semantics code: {err:?}"
    );
}

/// C37 R2 (inventory leg): the census passes the same boundary — a bound
/// RUNNING VM reads Ready only with verified enforcement; a lost/tampered
/// ACL reads Unreachable, never a false Ready.
#[test]
fn inventory_certifies_running_ready_only_through_the_boundary() {
    let (runtime, log) = runtime_for("fix6_cold_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    runtime.create_bound(&create_with_policy()).expect("create");
    let inventory = runtime.sandbox_inventory().expect("inventory");
    assert!(
        inventory.iter().any(|entry| entry.sandbox_id == "sbx-1"
            && entry.state == sandbox_protocol::SandboxLifecycleState::Ready),
        "the enforced running VM reads Ready: {inventory:?}"
    );
    tamper_acl_allow_all(&statedir);
    let inventory = runtime.sandbox_inventory().expect("inventory");
    assert!(
        inventory.iter().any(|entry| entry.sandbox_id == "sbx-1"
            && entry.state == sandbox_protocol::SandboxLifecycleState::Unreachable),
        "the unenforced running VM reads Unreachable, never Ready: {inventory:?}"
    );
}

/// C37 R3: the durable enforcement-loss record path for a sandbox.
fn loss_record(statedir: &Path) -> std::path::PathBuf {
    statedir.join("host-state/enforcement-losses/sbx-1.json")
}

/// C37 R3 finding 1 (end-to-end acceptance): a sandbox whose create
/// receipt CONFIRMED later loses enforcement; the loss is detected by the
/// PROBE path — a consumer with no cleanup authority of its own. The
/// detection is DURABLE (a loss record persists), and the always-running
/// drain — the same pass the expiry service and the census drive — binds
/// the instance, re-confirms the drift coherently, and tears the VM and
/// its network down through the kill-shaped fenced path. Nothing is left:
/// no VM, no network, no ACL, no journal, no record, no census row.
#[test]
fn detected_enforcement_loss_is_durable_and_the_drain_cleans_up() {
    let (runtime, log) = runtime_for("fix6_cold_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    // The confirmed-create receipt: the sandbox completed create Ready.
    runtime.create_bound(&create_with_policy()).expect("create");
    // Enforcement breaks out-of-band; the probe detects it.
    tamper_acl_allow_all(&statedir);
    let err = runtime
        .probe_sandbox(&probe_req())
        .expect_err("an unenforced running VM never probes GuestReady");
    assert_eq!(err.code, SandboxErrorCode::GuestUnavailable, "{err:?}");
    assert!(
        loss_record(&statedir).exists(),
        "detection is DURABLE: no consumer drops the signal"
    );
    // The drain — the always-running consumer — fences and cleans up.
    runtime
        .drain_enforcement_losses(&|_, _| Ok(()))
        .expect("drain");
    let lines = log_lines(&log);
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("delete ") && line.contains("wssp-sbx-sbx-1")),
        "the drain tears the unenforced VM down: {}",
        lines.join("\n")
    );
    let (network, acl) = sandbox_network_names("sbx-1");
    assert!(
        !statedir
            .join("networks")
            .join(format!("{network}.conf"))
            .exists(),
        "the network is gone"
    );
    assert!(
        !statedir.join("acls").join(format!("{acl}.conf")).exists(),
        "the ACL is gone"
    );
    assert!(
        !statedir
            .join("host-state/network-cleanups/sbx-1.json")
            .exists(),
        "the fenced obligation retired"
    );
    assert!(!loss_record(&statedir).exists(), "the loss record retired");
    let inventory = runtime.sandbox_inventory().expect("inventory");
    assert!(
        !inventory.iter().any(|entry| entry.sandbox_id == "sbx-1"),
        "the next census never reports the cleaned sandbox: {inventory:?}"
    );
}

/// C37 R3 finding 1 (census leg): detection by the inventory census feeds
/// the SAME durable record. A census has no lifecycle authority: it must
/// observe Unreachable without deleting behind the connected relay's back.
/// Only the service drain, with lifecycle checkpoints, may destroy it.
#[test]
fn census_detected_loss_requires_the_lifecycle_owned_drain() {
    let (runtime, log) = runtime_for("fix6_cold_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    runtime.create_bound(&create_with_policy()).expect("create");
    tamper_acl_allow_all(&statedir);
    let inventory = runtime.sandbox_inventory().expect("census");
    assert!(
        inventory.iter().any(|entry| entry.sandbox_id == "sbx-1"
            && entry.state == sandbox_protocol::SandboxLifecycleState::Unreachable),
        "the lost VM reads Unreachable: {inventory:?}"
    );
    let lines = log_lines(&log);
    assert!(
        !lines
            .iter()
            .any(|line| line.starts_with("delete ") && line.contains("wssp-sbx-sbx-1")),
        "the census cannot bypass lifecycle settlement"
    );
    assert!(loss_record(&statedir).exists());
    runtime
        .drain_enforcement_losses(&|_, _| Ok(()))
        .expect("service drain");
    let (network, _) = sandbox_network_names("sbx-1");
    assert!(
        !statedir
            .join("networks")
            .join(format!("{network}.conf"))
            .exists()
    );
    assert!(!loss_record(&statedir).exists());
    let next = runtime.sandbox_inventory().expect("census");
    assert!(
        !next.iter().any(|entry| entry.sandbox_id == "sbx-1"),
        "the sandbox is gone: {next:?}"
    );
}

#[test]
fn loss_cleanup_cannot_bypass_either_lifecycle_checkpoint() {
    use crate::EnforcementLossStage::{Complete, Prepare};
    let (runtime, log) = runtime_for("fix6_cold_ready");
    let statedir = log.parent().unwrap();
    runtime.create_bound(&create_with_policy()).unwrap();
    tamper_acl_allow_all(statedir);
    runtime
        .probe_sandbox(&probe_req())
        .expect_err("confirmed loss");
    let veto = || crate::RuntimeError::new(SandboxErrorCode::Internal, "checkpoint veto");
    // Stale/unwritable lifecycle intent never grants destruction authority,
    // but MUST immediately halt a confirmed breach on its independent permit.
    runtime
        .drain_enforcement_losses(&|_, stage| {
            assert_eq!(stage, Prepare);
            Err(veto())
        })
        .expect_err("prepare veto");
    assert!(log_lines(&log).iter().any(|line| line.starts_with("stop ")));
    assert!(
        !log_lines(&log)
            .iter()
            .any(|line| line.starts_with("delete "))
    );
    assert!(loss_record(statedir).exists());
    // Destruction without durable completion cannot retire the retry signal.
    runtime
        .drain_enforcement_losses(&|_, stage| {
            if stage == Complete {
                Err(veto())
            } else {
                Ok(())
            }
        })
        .expect_err("completion veto");
    assert!(
        log_lines(&log)
            .iter()
            .any(|line| line.starts_with("delete "))
    );
    assert!(loss_record(statedir).exists());
    // Crash/failed-checkpoint recovery is already-absent, but still crosses
    // BOTH checkpoints and completes only after authoritative absence.
    let stages = std::cell::RefCell::new(Vec::new());
    runtime
        .drain_enforcement_losses(&|id, stage| {
            assert_eq!(id, "sbx-1");
            if stage == Complete {
                assert_eq!(runtime.query_sandbox(id, None, None).unwrap(), None);
            }
            stages.borrow_mut().push(stage);
            Ok(())
        })
        .unwrap();
    assert_eq!(*stages.borrow(), [Prepare, Complete]);
    assert!(!loss_record(statedir).exists());
}

/// C37 R3 finding 1 (controls): the drain NEVER acts on a healthy, a
/// foreign, or an inconclusive sandbox. A recorded loss whose enforcement
/// verifies cleanly was a transient detection error — the record retires
/// and the VM is untouched. A foreign instance at the managed name is
/// never touched and its record is preserved. Only confirmed drift on a
/// bound instance is destroyed — including a VM that STOPPED between
/// detection and the drain.
#[test]
fn enforcement_loss_drain_controls_healthy_foreign_and_stopped() {
    let (runtime, log) = runtime_for("fix6_cold_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    runtime.create_bound(&create_with_policy()).expect("create");
    // Healthy control: a stale record with enforcement INTACT retires
    // with no action.
    runtime
        .client()
        .persist_enforcement_loss("sbx-1", "transient test record")
        .expect("persist the transient test record");
    runtime
        .drain_enforcement_losses(&|_, _| Ok(()))
        .expect("drain");
    assert!(
        !loss_record(&statedir).exists(),
        "a transient record retires once enforcement verifies"
    );
    assert!(
        !log_lines(&log)
            .iter()
            .any(|line| line.starts_with("delete ")),
        "a healthy VM is never deleted"
    );
    let (network, _) = sandbox_network_names("sbx-1");
    assert!(
        statedir
            .join("networks")
            .join(format!("{network}.conf"))
            .exists(),
        "a healthy network is never touched"
    );
    // Foreign control: the VM re-labeled out-of-band is never touched,
    // and its record is preserved (the census binding check fails closed
    // on the same condition).
    fs::write(
        statedir.join("config/user.flycockpit.sandbox_id"),
        "sbx-OTHER",
    )
    .unwrap();
    runtime
        .client()
        .persist_enforcement_loss("sbx-1", "foreign test record")
        .expect("persist the foreign test record");
    runtime
        .drain_enforcement_losses(&|_, _| Ok(()))
        .expect("drain");
    assert!(
        loss_record(&statedir).exists(),
        "a foreign instance's record is preserved, never acted on"
    );
    assert!(
        !log_lines(&log)
            .iter()
            .any(|line| line.starts_with("delete ")),
        "a foreign VM is never deleted"
    );
    assert!(
        statedir
            .join("networks")
            .join(format!("{network}.conf"))
            .exists(),
        "a foreign sandbox's network is never touched"
    );
    fs::remove_file(statedir.join("host-state/enforcement-losses/sbx-1.json")).unwrap();
    // Stopped leg: the VM crashed between detection and the drain. The
    // drift is still on record and still confirmed — the stopped VM is
    // torn down through the same fenced path.
    fs::write(statedir.join("config/user.flycockpit.sandbox_id"), "sbx-1").unwrap();
    fs::write(statedir.join("stopped-instance"), "").unwrap();
    tamper_acl_allow_all(&statedir);
    runtime
        .client()
        .persist_enforcement_loss("sbx-1", "detected while running")
        .expect("persist the drift test record");
    runtime
        .drain_enforcement_losses(&|_, _| Ok(()))
        .expect("drain");
    let lines = log_lines(&log);
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("delete ") && line.contains("wssp-sbx-sbx-1")),
        "a confirmed loss is cleaned up even after the VM stopped"
    );
    assert!(
        !statedir
            .join("networks")
            .join(format!("{network}.conf"))
            .exists()
    );
    assert!(!loss_record(&statedir).exists());
}
/// C37 R4 finding 1 (transport/timeout leg): an INCONCLUSIVE enforcement
/// observation — the ACL readback fails with a transport error — must never
/// convict a healthy bound running VM: no GuestUnavailable (the cleanup
/// code), no loss record, no deletion. The failure is retryable; once the
/// transport heals the sandbox probes Ready again.
#[test]
fn a_transport_error_during_verification_never_convicts_a_healthy_sandbox() {
    let (runtime, log) = runtime_for("fix6_cold_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    runtime.create_bound(&create_with_policy()).expect("create");
    // The ACL read fails with a transport error for every attempt.
    fs::write(statedir.join("fail-acl-read"), "32").unwrap();
    let err = runtime
        .probe_sandbox(&probe_req())
        .expect_err("an unreadable ACL is an inconclusive observation");
    assert_ne!(
        err.code,
        SandboxErrorCode::GuestUnavailable,
        "an inconclusive observation is NEVER the cleanup-triggering code: {err:?}"
    );
    assert_eq!(
        err.code,
        SandboxErrorCode::Internal,
        "the transport failure keeps its own retryable diagnostic: {err:?}"
    );
    assert!(
        !loss_record(&statedir).exists(),
        "inconclusive observations never write the loss record"
    );
    assert!(
        !log_lines(&log)
            .iter()
            .any(|line| line.starts_with("delete ")),
        "a healthy VM is never deleted on an inconclusive observation"
    );
    // The drain agrees: a planted record under the same transport failure
    // is KEPT (not acted on) — only confirmed drift authorizes cleanup.
    runtime
        .client()
        .persist_enforcement_loss("sbx-1", "detection under a transport failure")
        .expect("persist");
    runtime
        .drain_enforcement_losses(&|_, _| Ok(()))
        .expect("drain");
    assert!(
        loss_record(&statedir).exists(),
        "the drain keeps the record while the observation is inconclusive"
    );
    assert!(
        !log_lines(&log)
            .iter()
            .any(|line| line.starts_with("delete ")),
        "the drain never deletes on an inconclusive observation"
    );
    // Heal the transport: the record was a transient-detection leftover and
    // retires, and the sandbox is Ready again — retryable WITHOUT cleanup.
    fs::remove_file(statedir.join("fail-acl-read")).unwrap();
    runtime
        .drain_enforcement_losses(&|_, _| Ok(()))
        .expect("drain");
    assert!(
        !loss_record(&statedir).exists(),
        "a verified-healthy record retires"
    );
    runtime
        .probe_sandbox(&probe_req())
        .expect("the healthy sandbox probes Ready once the transport heals");
    // Inner-readback leg: the snapshot's OUTER ACL read succeeds and the
    // INNER readback inside the plan verification fails — an inconclusive
    // observation at that depth is equally non-convicting.
    fs::write(statedir.join("fail-acl-read-after"), "1").unwrap();
    let err = runtime
        .probe_sandbox(&probe_req())
        .expect_err("an inner-readback transport failure is inconclusive");
    assert_ne!(
        err.code,
        SandboxErrorCode::GuestUnavailable,
        "an inner-readback failure is NEVER the cleanup-triggering code: {err:?}"
    );
    assert!(
        !loss_record(&statedir).exists(),
        "no loss record on an inconclusive inner readback"
    );
    assert!(
        !log_lines(&log)
            .iter()
            .any(|line| line.starts_with("delete ")),
        "nothing is deleted on an inconclusive inner readback"
    );
    runtime
        .probe_sandbox(&probe_req())
        .expect("the healthy sandbox probes Ready once the inner read heals");
}

/// C37 R4 finding 1 (nested-read leg): a failure of the INSTANCE metadata
/// read (the device-comparison evidence source) is likewise inconclusive —
/// never GuestUnavailable, never a record, never a deletion.
#[test]
fn a_nested_read_error_never_convicts_a_healthy_sandbox() {
    let (runtime, log) = runtime_for("fix6_cold_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    runtime.create_bound(&create_with_policy()).expect("create");
    // Corrupt the instance-metadata readback: the client's query response
    // no longer parses — a read error, not drift evidence.
    fs::write(statedir.join("instance-metadata"), "not-json").unwrap();
    // The BOUNDARY itself classifies the nested read error as inconclusive.
    let err = runtime
        .client()
        .verify_bound_enforcement("sbx-1", true)
        .expect_err("an unparseable instance readback cannot verify");
    assert_ne!(
        err.code,
        SandboxErrorCode::GuestUnavailable,
        "a nested read error is NEVER the cleanup-triggering code: {err:?}"
    );
    assert_ne!(
        err.code,
        SandboxErrorCode::IdempotencyConflict,
        "a nested read error is never drift evidence either: {err:?}"
    );
    // The probe consumer degrades to Unreachable — never a false Ready,
    // never a conviction.
    let response = runtime
        .probe_sandbox(&probe_req())
        .expect("the probe answers with a degraded state, not a conviction");
    assert_eq!(
        response.state,
        crate::SandboxLiveProbeState::Unreachable,
        "an unreadable guest is Unreachable, never Ready: {response:?}"
    );
    assert!(
        !loss_record(&statedir).exists(),
        "inconclusive observations never write the loss record"
    );
    assert!(
        !log_lines(&log)
            .iter()
            .any(|line| line.starts_with("delete ")),
        "a healthy VM is never deleted on a nested read error"
    );
    fs::remove_file(statedir.join("instance-metadata")).unwrap();
    runtime
        .probe_sandbox(&probe_req())
        .expect("the healthy sandbox probes Ready once the read heals");
}

/// C37 R4 finding 1 (coherence-budget leg): an observation that cannot be
/// made coherently within its budget is inconclusive (Internal), never a
/// conviction — no GuestUnavailable, no record, no deletion.
#[test]
fn coherence_budget_exhaustion_is_inconclusive_never_a_conviction() {
    let (mut runtime, log) = runtime_for("fix6_cold_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    runtime.create_bound(&create_with_policy()).expect("create");
    runtime.client_mut().coherence_budget_override = Some(std::time::Duration::from_millis(300));
    // A managed DNS transition is in flight for the whole observation
    // window, so the snapshot can never be taken coherently.
    let _guard = runtime.client().begin_dns_transition("sbx-1");
    let err = runtime
        .probe_sandbox(&probe_req())
        .expect_err("an incoherent observation cannot convict");
    assert_eq!(
        err.code,
        SandboxErrorCode::Internal,
        "budget exhaustion is the inconclusive code: {err:?}"
    );
    assert!(
        !loss_record(&statedir).exists(),
        "an inconclusive observation never writes the loss record"
    );
    assert!(
        !log_lines(&log)
            .iter()
            .any(|line| line.starts_with("delete ")),
        "a healthy VM is never deleted on an incoherent observation"
    );
    drop(_guard);
    runtime.client_mut().coherence_budget_override = None;
    runtime
        .probe_sandbox(&probe_req())
        .expect("the healthy sandbox probes Ready once the transition settles");
}

/// C37 R4 finding 1 (readiness leg): the same transport failure landing on
/// the POST-START readiness fence fails the create with the retryable code,
/// NOT GuestUnavailable — and the retried create succeeds with the SAME
/// healthy VM still in place (nothing cleaned up).
#[test]
fn a_transport_error_at_readiness_is_retryable_never_cleanup() {
    let (runtime, log) = runtime_for("fix6_new_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    fs::write(statedir.join("fail-acl-read-once-running"), "").unwrap();
    let err = runtime
        .create_bound(&create_with_policy())
        .expect_err("an unreadable ACL at readiness is inconclusive");
    assert_ne!(
        err.code,
        SandboxErrorCode::GuestUnavailable,
        "readiness must not convert an inconclusive observation to the cleanup code: {err:?}"
    );
    assert!(
        !loss_record(&statedir).exists(),
        "no loss record on an inconclusive readiness observation"
    );
    assert!(
        !log_lines(&log)
            .iter()
            .any(|line| line.starts_with("delete ")),
        "nothing is torn down"
    );
    // Retryable WITHOUT cleanup: the same create request now succeeds.
    runtime
        .create_bound(&create_with_policy())
        .expect("the retried create succeeds once the transport heals");
}

/// C37 R4 finding 2: an interrupted (truncated/empty) loss-record write
/// never wedges observational cleanup. A partial record is REWRITTEN by the
/// next detection, and the drain treats an unparseable record as actionable
/// evidence to re-verify — never as a reason to skip the sandbox.
#[test]
fn a_partial_loss_record_is_rewritten_and_still_drains() {
    let (runtime, log) = runtime_for("fix6_cold_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    runtime.create_bound(&create_with_policy()).expect("create");
    let record = loss_record(&statedir);
    // Leg 1: a truncated record (an interrupted write) plus REAL drift is
    // rewritten into a well-formed record by the next detection, and the
    // drain cleans up.
    fs::create_dir_all(record.parent().unwrap()).unwrap();
    fs::write(&record, "{\"sandbox_id\":").unwrap();
    tamper_acl_allow_all(&statedir);
    let err = runtime
        .probe_sandbox(&probe_req())
        .expect_err("confirmed drift still convicts");
    assert_eq!(err.code, SandboxErrorCode::GuestUnavailable, "{err:?}");
    let body = fs::read_to_string(&record).expect("the rewritten record");
    let parsed: serde_json::Value =
        serde_json::from_str(&body).expect("the partial write was repaired");
    assert_eq!(
        parsed.get("sandbox_id").and_then(|v| v.as_str()),
        Some("sbx-1"),
        "the rewritten record is well-formed"
    );
    runtime
        .drain_enforcement_losses(&|_, _| Ok(()))
        .expect("drain");
    assert!(
        log_lines(&log)
            .iter()
            .any(|line| line.starts_with("delete ") && line.contains("wssp-sbx-sbx-1")),
        "the drain cleans up behind a repaired record"
    );
    assert!(!record.exists(), "the record retires after cleanup");

    // Leg 2: an EMPTY (zero-byte) record — enumeration must treat it as
    // actionable rather than skipping the sandbox into permanent loss.
    // Recreate the sandbox (the leg-1 drain deleted it), plant the empty
    // record with real drift, and let the drain be the FIRST consumer (no
    // re-detection beforehand).
    fs::remove_file(statedir.join("deleted-instance")).unwrap();
    runtime
        .create_bound(&create_with_policy())
        .expect("recreate");
    fs::create_dir_all(record.parent().unwrap()).unwrap();
    fs::write(&record, "").unwrap();
    tamper_acl_allow_all(&statedir);
    runtime
        .drain_enforcement_losses(&|_, _| Ok(()))
        .expect("drain");
    assert!(
        log_lines(&log)
            .iter()
            .filter(|line| line.starts_with("delete ") && line.contains("wssp-sbx-sbx-1"))
            .count()
            >= 2,
        "an empty record still reaches the drain's re-verification: {}",
        log_lines(&log).join("\n")
    );
    assert!(!record.exists(), "the empty record's sandbox is cleaned up");
}

/// C37 R4 finding 2: a persistence FAILURE is actionable — it surfaces in
/// the detection error, never silently "recorded" — and recovery once the
/// lifecycle authority is captured before the failed write and immediate halt.
/// Automatic storage-only recovery is covered by the connected wire tests.
#[test]
fn a_loss_record_persistence_failure_prepares_lifecycle_before_halting() {
    let (mut runtime, log) = runtime_for("fix6_cold_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    runtime.create_bound(&create_with_policy()).expect("create");
    let lifecycle = TestLossLifecycle::default();
    runtime.set_enforcement_loss_lifecycle(std::sync::Arc::new(lifecycle.clone()));
    tamper_acl_allow_all(&statedir);
    // Make the loss-journal directory fsync fail: write_durable_record
    // fails closed.
    runtime.client_mut().fail_dir_sync_for = Some(statedir.join("host-state/enforcement-losses"));
    let err = runtime
        .probe_sandbox(&probe_req())
        .expect_err("confirmed drift still convicts even when the record write fails");
    assert_eq!(
        err.code,
        SandboxErrorCode::GuestUnavailable,
        "a persistence failure never masks the drift signal: {err:?}"
    );
    assert!(
        err.message.contains("could not be persisted"),
        "the persistence failure is ACTIONABLE — named in the error, never silently recorded: {err:?}"
    );
    assert!(
        !loss_record(&statedir).exists(),
        "no record landed while the journal was failing"
    );
    assert_eq!(
        *lifecycle.prepared.lock().unwrap(),
        vec![0],
        "the lifecycle owns recovery even without a loss record"
    );
    // C37 R5: the confirmed breach does NOT wait for re-detection — the
    // boundary took the permit-independent restrictive action itself.
    assert!(
        err.message.contains("force-stopped"),
        "the fail-safe stop is named: {err:?}"
    );
    assert!(
        log_lines(&log)
            .iter()
            .any(|line| line.starts_with("stop ") && line.contains("wssp-sbx-sbx-1")),
        "the breached VM was stopped: {}",
        log_lines(&log).join("\n")
    );
    let (network, _) = sandbox_network_names("sbx-1");
    assert!(
        statedir
            .join("networks")
            .join(format!("{network}.conf"))
            .exists(),
        "the fail-safe STOPS, never tears down — teardown stays with the drain/relay cleanup"
    );
}

#[test]
fn loss_lifecycle_capture_precedes_observation_and_only_drift_prepares() {
    use std::sync::atomic::Ordering;
    let (runtime, log) = runtime_for("fix6_cold_ready");
    let statedir = log.parent().unwrap().to_path_buf();
    runtime.create_bound(&create_with_policy()).unwrap();
    let lifecycle = TestLossLifecycle::default();
    runtime.set_enforcement_loss_lifecycle(std::sync::Arc::new(lifecycle.clone()));
    runtime.probe_sandbox(&probe_req()).unwrap();
    assert!(
        lifecycle.prepared.lock().unwrap().is_empty(),
        "healthy never prepares"
    );
    fs::write(statedir.join("fail-acl-read"), "32").unwrap();
    let err = runtime.probe_sandbox(&probe_req()).unwrap_err();
    assert_ne!(err.code, SandboxErrorCode::GuestUnavailable);
    assert!(
        lifecycle.prepared.lock().unwrap().is_empty(),
        "inconclusive never prepares"
    );
    fs::remove_file(statedir.join("fail-acl-read")).unwrap();
    fs::write(
        statedir.join("config/user.flycockpit.sandbox_id"),
        "foreign",
    )
    .unwrap();
    runtime.probe_sandbox(&probe_req()).unwrap_err();
    assert!(
        lifecycle.prepared.lock().unwrap().is_empty(),
        "foreign never prepares"
    );
    assert!(
        !log_lines(&log)
            .iter()
            .any(|l| l.starts_with("stop ") || l.starts_with("delete "))
    );
    fs::write(statedir.join("config/user.flycockpit.sandbox_id"), "sbx-1").unwrap();
    tamper_acl_allow_all(&statedir);
    // A real read barrier changes the arm WHILE observation is in flight.
    fs::write(statedir.join("barrier-acl-read"), "0").unwrap();
    let cloned = runtime.clone();
    let worker = std::thread::spawn(move || cloned.probe_sandbox(&probe_req()));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while statedir.join("barrier-acl-read").exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "observation did not reach barrier"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    lifecycle.epoch.store(1, Ordering::SeqCst);
    fs::write(statedir.join("release-acl-read-barrier"), "").unwrap();
    let err = worker.join().unwrap().unwrap_err();
    assert_eq!(err.code, SandboxErrorCode::GuestUnavailable);
    assert_eq!(
        *lifecycle.prepared.lock().unwrap(),
        vec![0, 1],
        "stale observation refuses its old arm; fresh verification prepares the new arm"
    );
    assert!(!err.message.contains("lifecycle prepare failed"));
    assert!(
        log_lines(&log).iter().any(|l| l.starts_with("stop ")),
        "failed lifecycle prepare still halts drift"
    );
    // No manual restart or extra probe is needed to establish recovery.
}

#[test]
fn loss_lifecycle_stale_capture_requires_fresh_evidence_before_preparing() {
    use std::sync::atomic::Ordering;
    for mode in ["healthy", "inconclusive", "foreign"] {
        let (runtime, log) = runtime_for("fix6_cold_ready");
        let statedir = log.parent().unwrap().to_path_buf();
        runtime.create_bound(&create_with_policy()).unwrap();
        let (_, acl) = sandbox_network_names("sbx-1");
        let acl_path = statedir.join("acls").join(format!("{acl}.egress"));
        let healthy_acl = fs::read(&acl_path).unwrap();
        let lifecycle = TestLossLifecycle::default();
        let write = match mode {
            "healthy" => (acl_path, healthy_acl),
            "inconclusive" => (statedir.join("fail-acl-read"), b"32".to_vec()),
            _ => (
                statedir.join("config/user.flycockpit.sandbox_id"),
                b"foreign".to_vec(),
            ),
        };
        lifecycle.fresh_writes.lock().unwrap().push(write);
        runtime.set_enforcement_loss_lifecycle(std::sync::Arc::new(lifecycle.clone()));
        tamper_acl_allow_all(&statedir);
        // An actual mid-observation authority change, not a pre-probe change.
        fs::write(statedir.join("barrier-acl-read"), "0").unwrap();
        let cloned = runtime.clone();
        let worker = std::thread::spawn(move || cloned.probe_sandbox(&probe_req()));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while statedir.join("barrier-acl-read").exists() {
            assert!(std::time::Instant::now() < deadline, "{mode}: barrier");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        lifecycle.epoch.store(1, Ordering::SeqCst);
        fs::write(statedir.join("release-acl-read-barrier"), "").unwrap();
        let err = worker.join().unwrap().unwrap_err();
        assert_ne!(err.code, SandboxErrorCode::GuestUnavailable, "{mode}");
        assert_eq!(
            *lifecycle.prepared.lock().unwrap(),
            vec![0],
            "{mode}: the old verdict never prepares the new authority"
        );
        assert!(!loss_record(&statedir).exists(), "{mode}: no stale record");
        assert!(statedir.join("stopped-instance").exists(), "{mode}");
        assert!(
            !log_lines(&log).iter().any(|l| l.starts_with("delete ")),
            "{mode}: restrictive stop is NOT destruction authority"
        );
    }
}
/// C37 R5 finding 1 (marker leg): an UNREADABLE DNS revocation marker is
/// unavailable evidence, not divergence — the observation is inconclusive
/// (Internal): no GuestUnavailable, no record, no stop, no delete. Paired
/// genuine-drift control: a tampered ACL still convicts.
#[test]
fn an_unreadable_marker_is_inconclusive_and_never_convicts() {
    let (runtime, log) = runtime_for("fix6_cold_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    runtime.create_bound(&create_with_policy()).expect("create");
    let marker_dir = statedir.join("host-state/dns-revocations");
    fs::create_dir_all(&marker_dir).unwrap();
    let marker = marker_dir.join("sbx-1.json");
    // Corrupt (unparseable) marker: the evidence exists but cannot be read.
    fs::write(&marker, [0xffu8, 0xfe, 0xfd]).unwrap();
    let err = runtime
        .probe_sandbox(&probe_req())
        .expect_err("an unreadable marker cannot verify");
    assert_eq!(
        err.code,
        SandboxErrorCode::Internal,
        "unavailable evidence is inconclusive, never the cleanup code: {err:?}"
    );
    assert!(
        !loss_record(&statedir).exists(),
        "inconclusive evidence never writes the loss record"
    );
    let lines = log_lines(&log);
    assert!(
        !lines
            .iter()
            .any(|l| l.starts_with("delete ") || l.starts_with("stop ")),
        "a healthy sandbox is never stopped or deleted on unreadable evidence: {}",
        lines.join("\n")
    );
    // Heal: the marker was spurious; the sandbox is Ready again.
    fs::remove_file(&marker).unwrap();
    runtime
        .probe_sandbox(&probe_req())
        .expect("healthy once the evidence reads");
    // Genuine-drift control: a tampered ACL convicts on the same path.
    tamper_acl_allow_all(&statedir);
    let err = runtime
        .probe_sandbox(&probe_req())
        .expect_err("genuine drift still convicts");
    assert_eq!(err.code, SandboxErrorCode::GuestUnavailable, "{err:?}");
    assert!(loss_record(&statedir).exists());
    runtime
        .drain_enforcement_losses(&|_, _| Ok(()))
        .expect("drain");
}

/// C37 R5 finding 1 (plan leg): an unreadable or unparseable persisted
/// PLAN is unavailable evidence — inconclusive — never plan-absence drift.
/// Covers both a corrupt record and an EACCES directory.
#[test]
fn an_unreadable_plan_is_inconclusive_and_never_convicts() {
    let (runtime, log) = runtime_for("fix6_cold_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    runtime.create_bound(&create_with_policy()).expect("create");
    let plans_dir = statedir.join("host-state/network-plans");
    let plan = plans_dir.join("sbx-1.json");
    // The healthy record body, for the healthy and foreign controls below.
    let healthy_body = fs::read_to_string(&plan).expect("the create persisted a plan");
    // Leg 1: corrupt (partial-write) plan record.
    fs::write(&plan, "{\"sandbox_id\":").unwrap();
    let err = runtime
        .probe_sandbox(&probe_req())
        .expect_err("an unparseable plan cannot verify");
    assert_eq!(
        err.code,
        SandboxErrorCode::Internal,
        "an unparseable plan is inconclusive: {err:?}"
    );
    assert!(!loss_record(&statedir).exists());
    assert!(
        !log_lines(&log)
            .iter()
            .any(|l| l.starts_with("delete ") || l.starts_with("stop ")),
        "untouched on unreadable plan evidence"
    );
    // Leg 2: EACCES on the plan directory — a read failure, not absence.
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(&plans_dir).unwrap().permissions();
    perms.set_mode(0o000);
    fs::set_permissions(&plans_dir, perms.clone()).unwrap();
    let err = runtime
        .probe_sandbox(&probe_req())
        .expect_err("an unreadable plan directory cannot verify");
    assert_eq!(
        err.code,
        SandboxErrorCode::Internal,
        "EACCES is inconclusive, never drift: {err:?}"
    );
    assert!(!loss_record(&statedir).exists());
    perms.set_mode(0o755);
    fs::set_permissions(&plans_dir, perms).unwrap();
    // Leg 3 (C37 R7): valid JSON but structurally MALFORMED plan records —
    // a missing or wrongly typed identity and any missing/mistyped
    // structural field are unavailable EVIDENCE, never positive proof of a
    // foreign plan. Before this fix each of these read as `Ok(None)`,
    // manufactured confirmed drift, and the drain deleted a healthy VM.
    for (label, body) in [
        ("empty object", "{}"),
        ("json null", "null"),
        ("non-string identity", "{\"sandbox_id\":42}"),
        (
            "identity only, no structural fields",
            "{\"sandbox_id\":\"sbx-1\"}",
        ),
        // A foreign id with an otherwise MALFORMED record is still
        // inconclusive: shape validation must complete BEFORE the
        // identity comparison may convict.
        (
            "foreign id, malformed body",
            "{\"sandbox_id\":\"sbx-OTHER\"}",
        ),
        (
            "unparseable gateway",
            "{\"sandbox_id\":\"sbx-1\",\"gateway\":\"not-an-ip\",\"rules\":[],\"grants\":[],\"policy_cidrs\":[]}",
        ),
        (
            "missing rules array",
            "{\"sandbox_id\":\"sbx-1\",\"gateway\":\"10.127.0.1\",\"grants\":[],\"policy_cidrs\":[]}",
        ),
        (
            "non-CIDR grant entry",
            "{\"sandbox_id\":\"sbx-1\",\"gateway\":\"10.127.0.1\",\"rules\":[],\"grants\":[\"nope\"],\"policy_cidrs\":[]}",
        ),
        (
            "non-string policy_cidrs entry",
            "{\"sandbox_id\":\"sbx-1\",\"gateway\":\"10.127.0.1\",\"rules\":[],\"grants\":[],\"policy_cidrs\":[7]}",
        ),
    ] {
        fs::write(&plan, body).unwrap();
        let err = runtime
            .probe_sandbox(&probe_req())
            .expect_err("a structurally malformed plan cannot verify");
        assert_eq!(
            err.code,
            SandboxErrorCode::Internal,
            "{label}: malformed shape is inconclusive, never drift: {err:?}"
        );
        assert!(
            !loss_record(&statedir).exists(),
            "{label}: no conviction on malformed plan evidence"
        );
        assert!(
            !log_lines(&log)
                .iter()
                .any(|l| l.starts_with("delete ") || l.starts_with("stop ")),
            "{label}: untouched on malformed plan evidence"
        );
    }
    // Healthy control: the intact record verifies.
    fs::write(&plan, &healthy_body).unwrap();
    runtime
        .probe_sandbox(&probe_req())
        .expect("the well-formed own plan verifies");
    assert!(!loss_record(&statedir).exists());
    // Genuinely foreign control: a WELL-FORMED record positively recorded
    // for a DIFFERENT sandbox is the only `None` that still convicts.
    let foreign_body = healthy_body.replacen("\"sbx-1\"", "\"sbx-OTHER\"", 1);
    assert_ne!(foreign_body, healthy_body, "the swap must take");
    fs::write(&plan, &foreign_body).unwrap();
    let err = runtime
        .probe_sandbox(&probe_req())
        .expect_err("a positively foreign plan is drift evidence");
    assert_eq!(err.code, SandboxErrorCode::GuestUnavailable, "{err:?}");
    assert!(
        loss_record(&statedir).exists(),
        "a positively foreign plan convicts"
    );
    fs::remove_file(loss_record(&statedir)).unwrap();
    fs::remove_file(&plan).unwrap();
    // Genuine-drift control: the corrupt record removed outright (plan
    // ABSENT — positively observed, not unreadable) plus a tampered ACL
    // convicts on the same path (the foreign leg above already removed
    // the plan record).
    tamper_acl_allow_all(&statedir);
    let err = runtime
        .probe_sandbox(&probe_req())
        .expect_err("genuine drift convicts (plan absence is positively observed)");
    assert_eq!(err.code, SandboxErrorCode::GuestUnavailable, "{err:?}");
    assert!(loss_record(&statedir).exists());
    runtime
        .drain_enforcement_losses(&|_, _| Ok(()))
        .expect("drain");
}

/// C37 R5 finding 1 (DNS publication leg): an unreadable DNS publication
/// state file must not manufacture a `raw.dnsmasq` mismatch out of a local
/// read failure — inconclusive, never drift.
#[test]
fn unreadable_dns_publication_state_is_inconclusive_and_never_convicts() {
    let (runtime, log) = runtime_for("fix6_cold_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    runtime.create_bound(&create_with_policy()).expect("create");
    let dns_dir = statedir.join("host-state/dns-policy");
    fs::create_dir_all(&dns_dir).unwrap();
    fs::write(dns_dir.join("sbx-1.json"), "not-json").unwrap();
    let err = runtime
        .probe_sandbox(&probe_req())
        .expect_err("an unparseable DNS publication state cannot verify");
    assert_eq!(
        err.code,
        SandboxErrorCode::Internal,
        "unavailable publication evidence is inconclusive: {err:?}"
    );
    assert!(
        !loss_record(&statedir).exists(),
        "no conviction on unreadable publication state"
    );
    assert!(
        !log_lines(&log)
            .iter()
            .any(|l| l.starts_with("delete ") || l.starts_with("stop ")),
        "untouched on unreadable publication evidence"
    );
    fs::remove_file(dns_dir.join("sbx-1.json")).unwrap();
    runtime
        .probe_sandbox(&probe_req())
        .expect("healthy once the state file is gone (base policy stands)");
    // Genuine-drift control.
    tamper_acl_allow_all(&statedir);
    let err = runtime
        .probe_sandbox(&probe_req())
        .expect_err("genuine drift still convicts");
    assert_eq!(err.code, SandboxErrorCode::GuestUnavailable, "{err:?}");
    runtime
        .drain_enforcement_losses(&|_, _| Ok(()))
        .expect("drain");
}

/// C37 R6 finding 2: when the loss record persisted fine but the drain's
/// TEARDOWN bookkeeping fails (the network-cleanup journal is
/// unwritable), the confirmed breach is still HALTED through the one
/// shared permit-independent boundary — no later detection re-runs the
/// boundary's persistence-failure stop (the record already stands), so
/// without this halt unauthorized traffic would stay live until lease
/// expiry. Stop — never delete: destruction authority stays behind the
/// journal write; the retained record retries the teardown next pass.
#[test]
fn the_drain_halts_a_confirmed_breach_when_teardown_bookkeeping_fails() {
    let (mut runtime, log) = runtime_for("fix6_cold_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    runtime.create_bound(&create_with_policy()).expect("create");
    let (network, _) = sandbox_network_names("sbx-1");
    // Confirmed drift on the bound RUNNING VM, detected and recorded while
    // every journal still works.
    tamper_acl_allow_all(&statedir);
    let err = runtime
        .probe_sandbox(&probe_req())
        .expect_err("the drift is confirmed");
    assert_eq!(err.code, SandboxErrorCode::GuestUnavailable, "{err:?}");
    assert!(loss_record(&statedir).exists(), "the loss record stands");
    // The teardown journal now fails: the drain cannot write ahead.
    runtime.client_mut().fail_dir_sync_for = Some(statedir.join("host-state/network-cleanups"));
    let err = runtime
        .drain_enforcement_losses(&|_, _| Ok(()))
        .expect_err("the bookkeeping failure surfaces, actionable");
    assert_eq!(err.code, SandboxErrorCode::Internal, "{err:?}");
    let lines = log_lines(&log);
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("stop ") && line.contains("wssp-sbx-sbx-1")),
        "the breach is halted even though the teardown journal failed: {}",
        lines.join("\n")
    );
    assert!(
        !lines
            .iter()
            .any(|line| line.starts_with("delete ") && line.contains("wssp-sbx-sbx-1")),
        "destruction authority stays behind the journal write: no delete"
    );
    assert!(
        statedir
            .join("networks")
            .join(format!("{network}.conf"))
            .exists(),
        "the fail-safe stops, never tears down the network"
    );
    assert!(
        loss_record(&statedir).exists(),
        "the record is retained — the teardown retries next pass"
    );
    // The journal heals: the next drain pass completes the fenced teardown
    // (the stopped VM is deleted, the network removed, the record retired).
    runtime.client_mut().fail_dir_sync_for = None;
    runtime
        .drain_enforcement_losses(&|_, _| Ok(()))
        .expect("drain after heal");
    let lines = log_lines(&log);
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("delete ") && line.contains("wssp-sbx-sbx-1")),
        "the healed drain completes the teardown"
    );
    assert!(
        !statedir
            .join("networks")
            .join(format!("{network}.conf"))
            .exists(),
        "the network teardown completes"
    );
    assert!(!loss_record(&statedir).exists(), "the record retires");
}

/// C37 R6 finding 2 (controls): the drain's fail-safe halt fires ONLY on
/// confirmed drift — never on a healthy verdict (the transient record
/// retires), never on an inconclusive observation (the record is kept for
/// retry), and never on a foreign instance (untouched, record preserved) —
/// even with the teardown journal unwritable throughout.
#[test]
fn the_drain_never_halts_without_confirmed_drift() {
    let (mut runtime, log) = runtime_for("fix6_cold_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    runtime.create_bound(&create_with_policy()).expect("create");
    runtime.client_mut().fail_dir_sync_for = Some(statedir.join("host-state/network-cleanups"));
    // Healthy control: a stale record with enforcement INTACT retires with
    // no action — the teardown journal is never even consulted.
    runtime
        .client()
        .persist_enforcement_loss("sbx-1", "transient test record")
        .expect("persist the transient record");
    runtime
        .drain_enforcement_losses(&|_, _| panic!("non-drift cannot cross lifecycle settlement"))
        .expect("a verified-healthy record retires even with the cleanup journal failing");
    assert!(
        !loss_record(&statedir).exists(),
        "a transient record retires once enforcement verifies"
    );
    assert!(
        !log_lines(&log)
            .iter()
            .any(|line| line.starts_with("stop ") || line.starts_with("delete ")),
        "a healthy VM is never stopped or deleted"
    );
    // Inconclusive control: an unreadable ACL keeps the record, acts never.
    fs::write(statedir.join("fail-acl-read"), "32").unwrap();
    runtime
        .client()
        .persist_enforcement_loss("sbx-1", "detection under a transport failure")
        .expect("persist the inconclusive-leg record");
    runtime
        .drain_enforcement_losses(&|_, _| panic!("non-drift cannot cross lifecycle settlement"))
        .expect("drain");
    assert!(
        loss_record(&statedir).exists(),
        "an inconclusive observation keeps the record"
    );
    assert!(
        !log_lines(&log)
            .iter()
            .any(|line| line.starts_with("stop ") || line.starts_with("delete ")),
        "an inconclusive observation never halts"
    );
    fs::remove_file(statedir.join("fail-acl-read")).unwrap();
    runtime
        .drain_enforcement_losses(&|_, _| panic!("non-drift cannot cross lifecycle settlement"))
        .expect("drain");
    assert!(
        !loss_record(&statedir).exists(),
        "the inconclusive-leg record retires once the observation verifies"
    );
    // Foreign control: a re-labeled instance at the managed name is never
    // touched, even with the teardown journal failing.
    fs::write(
        statedir.join("config/user.flycockpit.sandbox_id"),
        "sbx-OTHER",
    )
    .unwrap();
    runtime
        .client()
        .persist_enforcement_loss("sbx-1", "foreign test record")
        .expect("persist the foreign-leg record");
    runtime
        .drain_enforcement_losses(&|_, _| panic!("non-drift cannot cross lifecycle settlement"))
        .expect("drain");
    assert!(
        loss_record(&statedir).exists(),
        "a foreign instance's record is preserved, never acted on"
    );
    assert!(
        !log_lines(&log)
            .iter()
            .any(|line| line.starts_with("stop ") || line.starts_with("delete ")),
        "a foreign VM is never stopped or deleted"
    );
}

/// C37 R7 finding 1: one persistently FAILING loss record must never
/// strand the breaches behind it. The reviewer's scenario, on one shim:
/// two recorded breaches, the teardown journal unwritable — the first
/// record's pass halts its VM but cannot journal the teardown, so it
/// fails; the drain must STILL reach and halt the second recorded breach
/// in the same pass, then surface the failure AFTER the pass. (The
/// second "breach" here is a foreign-tagged instance at the next name —
/// the pass reaching it is observable in the daemon log; a foreign
/// instance is probed and left untouched.)
#[test]
fn a_persistently_failing_loss_record_never_strands_later_breaches() {
    let (mut runtime, log) = runtime_for("fix6_cold_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    runtime.create_bound(&create_with_policy()).expect("create");
    // Confirmed drift on the bound RUNNING VM, recorded while the journal
    // still works — then the teardown journal starts failing for every
    // later write.
    tamper_acl_allow_all(&statedir);
    runtime
        .probe_sandbox(&probe_req())
        .expect_err("the drift is confirmed");
    assert!(loss_record(&statedir).exists());
    // A second recorded breach, sorting AFTER sbx-1: it must be reached in
    // the SAME pass that sbx-1's record fails in.
    runtime
        .client()
        .persist_enforcement_loss("sbx-2", "a second recorded breach")
        .expect("persist the second record");
    runtime.client_mut().fail_dir_sync_for = Some(statedir.join("host-state/network-cleanups"));
    let before = log_lines(&log).len();
    let err = runtime
        .drain_enforcement_losses(&|_, _| Ok(()))
        .expect_err("the first record's failure is surfaced after the pass");
    assert_eq!(err.code, SandboxErrorCode::Internal, "{err:?}");
    let lines = log_lines(&log);
    let pass = &lines[before..];
    assert!(
        pass.iter()
            .any(|line| line.starts_with("stop ") && line.contains("wssp-sbx-sbx-1")),
        "the first breach is still halted: {}",
        pass.join("\n")
    );
    assert!(
        pass.iter().any(|line| line.contains("wssp-sbx-sbx-2")),
        "failure isolation: the pass CONTINUED past the failing record and \
         processed the second recorded breach (old code returned early): {}",
        pass.join("\n")
    );
    assert!(
        pass.iter()
            .any(|line| line.contains("wssp-sbx-sbx-2") && line.contains("query")),
        "the second record was bound and re-verified, not just enumerated"
    );
    assert!(
        !pass
            .iter()
            .any(|line| line.starts_with("stop ") && line.contains("wssp-sbx-sbx-2")),
        "the foreign second instance is probed but never halted"
    );
    assert!(
        loss_record(&statedir).exists(),
        "the failing record is retained for the next pass"
    );
    assert!(
        statedir
            .join("host-state/enforcement-losses/sbx-2.json")
            .exists(),
        "the foreign-tagged record is preserved"
    );
    // The progress cursor advanced past BOTH attempted records, so the
    // next pass rotates (asserted in the rotation regression below).
    assert_eq!(
        fs::read_to_string(statedir.join("host-state/enforcement-losses/.drain-cursor"))
            .expect("the pass records its progress cursor")
            .trim(),
        "sbx-2"
    );
    // Heal + finish: the teardown completes and both records retire.
    fs::remove_file(statedir.join("host-state/enforcement-losses/sbx-2.json")).unwrap();
    runtime.client_mut().fail_dir_sync_for = None;
    runtime
        .drain_enforcement_losses(&|_, _| Ok(()))
        .expect("drain after heal");
    assert!(!loss_record(&statedir).exists(), "the first record retires");
}

/// C37 R7 finding 1 (rotation): the pass resumes AFTER the last record
/// the previous pass attempted (`.drain-cursor`), wrapping around, so a
/// retained record can never monopolize the head of every sweep — the
/// same scheduling boundary the network-cleanup drain enforces. With the
/// cursor preset past `sbx-b`, the pass MUST process sbx-c before
/// wrapping to sbx-a and sbx-b.
#[test]
fn the_loss_drain_rotates_past_retained_records() {
    let (runtime, log) = runtime_for("fix6_cold_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    // Three retained records and no live VM: each pass probes the
    // (foreign/absent) instance and keeps the record — nothing ever
    // retires, so ordering is the only progress mechanism.
    for id in ["sbx-a", "sbx-b", "sbx-c"] {
        runtime
            .client()
            .persist_enforcement_loss(id, "retained test record")
            .expect("persist a record");
    }
    fs::write(
        statedir.join("host-state/enforcement-losses/.drain-cursor"),
        "sbx-b",
    )
    .unwrap();
    runtime
        .drain_enforcement_losses(&|_, _| Ok(()))
        .expect("the pass completes");
    let lines = log_lines(&log);
    let first = |needle: &str| {
        lines
            .iter()
            .position(|line| line.contains(needle))
            .unwrap_or_else(|| panic!("the pass never processed {needle}: {}", lines.join("\n")))
    };
    let (c, a, b) = (
        first("wssp-sbx-sbx-c"),
        first("wssp-sbx-sbx-a"),
        first("wssp-sbx-sbx-b"),
    );
    assert!(
        c < a && a < b,
        "the pass resumed AFTER the cursor (sbx-c, then wraps to sbx-a, sbx-b): \
         c={c} a={a} b={b}\n{}",
        lines.join("\n")
    );
    assert_eq!(
        fs::read_to_string(statedir.join("host-state/enforcement-losses/.drain-cursor"))
            .expect("the cursor is recorded")
            .trim(),
        "sbx-b",
        "the cursor tracks the last attempted record"
    );
    // The records all remain (nothing was actionable), and a second pass
    // rotates the same way rather than starving behind sbx-a.
    for id in ["sbx-a", "sbx-b", "sbx-c"] {
        assert!(
            statedir
                .join("host-state/enforcement-losses")
                .join(format!("{id}.json"))
                .exists(),
            "the retained record {id} survives the pass"
        );
    }
}

/// SEED-5 (R5/R6-M6): expiry/revocation of the caller while the halt
/// observes ownership cannot cancel the already-required restrictive stop.
#[test]
fn halt_still_stops_when_the_callers_permit_is_revoked_mid_observation() {
    let (mut client, log) = client_for_with_log("running");
    let permit = std::sync::Arc::new(crate::RuntimePermit::default());
    client.cancelled = Some(permit.clone());
    client.halt_observation_revoke = Some(permit.clone());
    assert!(!permit.is_revoked());
    assert!(
        client
            .halt_confirmed_breach("sbx-1")
            .expect("confirmed halt")
    );
    assert!(permit.is_revoked(), "the observation hook actually fired");
    assert!(log_invoked(&log, "stop"));
    assert!(log.parent().unwrap().join("stopped-instance").exists());
    assert!(
        !log_invoked(&log, "delete"),
        "halt has no destruction authority"
    );
}

/// E-11 classification boundary: the daemon's start-time device refusal on
/// a fresh create, with the VM observed Stopped afterwards, is a COMPLETED
/// failure (FAILED) carrying the daemon's reason — never an opaque UNKNOWN.
const BR_NETFILTER_REFUSAL: &str = "Error: Failed to start device \"eth0\": security.ipv6_filtering requires bridge netfilter: br_netfilter kernel module not loaded\nTry `incus info --show-log wssp-sbx-sbx-1` for more info\n";

#[test]
fn deterministic_start_refusal_fails_the_create_with_the_incus_reason() {
    let (runtime, log) = runtime_for("c37_start_gated");
    let statedir = log.parent().expect("log parent").to_path_buf();
    fs::write(statedir.join("start-error"), BR_NETFILTER_REFUSAL).unwrap();
    let err = runtime
        .create_bound(&create_with_policy())
        .expect_err("the refused start fails the create");
    assert_eq!(
        err.state(),
        sandbox_protocol::OperationState::Failed,
        "{err:?}"
    );
    assert_eq!(err.code, SandboxErrorCode::SandboxNotRunning, "{err:?}");
    assert!(
        err.message
            .contains("br_netfilter kernel module not loaded")
            && err.message.contains("Failed to start device \"eth0\""),
        "the reason reaches the failure detail: {}",
        err.message
    );
    assert!(
        !err.message.contains("Try `incus info"),
        "only the daemon's error line is carried: {}",
        err.message
    );
    assert_create_resources(&runtime, &log, false);
    assert_eq!(start_lines(&log_lines(&log)).len(), 1, "one start attempt");
}

#[test]
fn first_start_refusal_retains_unknown_when_vm_cleanup_does_not_prove_absence() {
    let (runtime, log) = runtime_for("c37_start_gated");
    let dir = log.parent().unwrap();
    fs::write(dir.join("start-error"), BR_NETFILTER_REFUSAL).unwrap();
    fs::write(dir.join("refuse-delete"), "").unwrap();
    let error = runtime.create_bound(&create_with_policy()).unwrap_err();
    assert_eq!(error.code, SandboxErrorCode::SandboxNotRunning);
    assert_eq!(
        error.state(),
        sandbox_protocol::OperationState::UnknownOutcome
    );
    assert!(runtime.sandbox_exists("sbx-1").unwrap());
    assert!(log_invoked(&log, "delete"));
}

fn assert_create_resources(runtime: &super::kvm::IncusKvmRuntime, log: &Path, present: bool) {
    assert_eq!(
        runtime.client().instance_exists("wssp-sbx-sbx-1").unwrap(),
        present,
        "VM presence after start outcome"
    );
    let dir = log.parent().unwrap();
    let (network, acl) = sandbox_network_names("sbx-1");
    assert_eq!(
        dir.join("networks")
            .join(format!("{network}.conf"))
            .exists(),
        present,
        "bridge"
    );
    assert_eq!(
        dir.join("acls").join(format!("{acl}.conf")).exists(),
        present,
        "ACL"
    );
    if !present {
        runtime
            .client()
            .verify_sandbox_network_absent("sbx-1")
            .unwrap();
    }
}

/// The existing-VM create retry (adoption) reaches the same boundary
/// through `reconcile_existing_create`.
#[test]
fn start_refusal_on_adopting_retry_retains_unknown_and_resources() {
    let (runtime, log) = runtime_for("c37_start_gated");
    let statedir = log.parent().expect("log parent").to_path_buf();
    fs::write(statedir.join("fail-start-once"), "").unwrap();
    let first = runtime
        .create_bound(&create_with_policy())
        .expect_err("the crashed start fails the create");
    assert_eq!(
        first.state(),
        sandbox_protocol::OperationState::UnknownOutcome,
        "a non-daemon start error stays uncertain: {first:?}"
    );
    fs::write(statedir.join("start-error"), BR_NETFILTER_REFUSAL).unwrap();
    let retry = runtime
        .create_bound(&create_with_policy())
        .expect_err("the refused start fails the retry");
    assert_eq!(
        retry.state(),
        sandbox_protocol::OperationState::UnknownOutcome,
        "{retry:?}"
    );
    assert_create_resources(&runtime, &log, true);
    assert!(
        !log_invoked(&log, "delete"),
        "retry refusal cannot authorize cleanup"
    );
    assert!(retry.message.contains("br_netfilter"), "{}", retry.message);
}

/// Inverse: every case the rule does not prove stays UNKNOWN_OUTCOME, now
/// with the daemon's reason when it gave one.
#[test]
fn uncertain_start_failures_stay_unknown() {
    // (stderr, forced post-start status) → must stay UNKNOWN.
    let cases: [(&str, Option<&str>); 5] = [
        // No daemon device refusal (e.g. a client/transport error).
        (
            "Error: Get \"http://unix.socket/1.0/operations/x/wait\": EOF\n",
            None,
        ),
        // A refusal shape without the device prefix.
        ("Error: start pinned by test\n", None),
        // A device refusal, but the VM is not observed Stopped.
        (BR_NETFILTER_REFUSAL, Some("Error 112")),
        (BR_NETFILTER_REFUSAL, Some("Starting 106")),
        // No daemon error line at all.
        ("something went wrong\n", None),
    ];
    for (stderr, status) in cases {
        let (runtime, log) = runtime_for("c37_start_gated");
        let statedir = log.parent().expect("log parent").to_path_buf();
        fs::write(statedir.join("start-error"), stderr).unwrap();
        if let Some(status) = status {
            // Present from the first query on: the pre-start state read in
            // init is skipped for a fresh create, so only the post-start
            // observation sees it.
            fs::write(statedir.join("instance-status"), status).unwrap();
        }
        let err = runtime
            .create_bound(&create_with_policy())
            .expect_err("the start never lands");
        assert_eq!(
            err.state(),
            sandbox_protocol::OperationState::UnknownOutcome,
            "{stderr:?} / {status:?}: {err:?}"
        );
        assert_create_resources(&runtime, &log, true);
        if stderr.starts_with("Error: ") {
            let line = stderr.lines().next().unwrap().trim_start_matches("Error: ");
            assert!(
                err.message.contains(line),
                "{stderr:?}: the daemon's reason is kept in the detail: {}",
                err.message
            );
        }
    }
}

/// E-06: the runtime names WHY the capability is absent, with the version
/// the daemon reported; a capable daemon has no reason.
#[test]
fn unavailable_egress_reason_names_the_daemon_version() {
    let (runtime, _) = runtime_for("running");
    assert_eq!(runtime.egress_enforcement_unavailable_reason(), None);
    for (mode, needle) in [
        ("egress_old_daemon", "incus 5.21.2 is older than 6.14"),
        ("egress_vulnerable_6_13", "incus 6.13.1 is older than 6.14"),
        ("egress_daemon_unsupported", "`network_acl`"),
    ] {
        let (runtime, _) = runtime_for(mode);
        let reason = runtime
            .egress_enforcement_unavailable_reason()
            .unwrap_or_else(|| panic!("{mode}: a reason"));
        assert!(reason.contains(needle), "{mode}: {reason}");
    }
}

// E-11 start classification: only a completed, positive-exit daemon device
// refusal followed by an observed Stopped re-read is FAILED.
fn create_with_start_injection(files: &[(&str, &str)]) -> crate::EffectError {
    let (runtime, log) = runtime_for("c37_start_gated");
    let statedir = log.parent().expect("log parent").to_path_buf();
    for (name, body) in files {
        fs::write(statedir.join(name), body).unwrap();
    }
    runtime
        .create_bound(&create_with_policy())
        .expect_err("create fails")
}

#[test]
fn start_refusal_but_running_is_not_failed() {
    let (runtime, log) = runtime_for("c37_start_gated");
    let statedir = log.parent().expect("log parent").to_path_buf();
    fs::write(statedir.join("start-error"), BR_NETFILTER_REFUSAL).unwrap();
    fs::write(statedir.join("instance-status"), "Running 103").unwrap();
    let out = runtime.create_bound(&create_with_policy());
    assert!(
        out.is_ok(),
        "observed Running wins over the refusal text: {out:?}"
    );
}

#[test]
fn start_refusal_on_second_error_line_is_unknown() {
    let stderr = "Error: Get \"http://unix.socket/1.0/operations/x/wait\": EOF\nError: Failed to start device \"eth0\": crafted\n";
    let err = create_with_start_injection(&[("start-error", stderr)]);
    assert_eq!(
        err.state(),
        sandbox_protocol::OperationState::UnknownOutcome,
        "{err:?}"
    );
}

#[test]
fn start_refusal_embedded_not_prefix_is_unknown() {
    let stderr = "Error: Post failed: Failed to start device \"eth0\": x\n";
    let err = create_with_start_injection(&[("start-error", stderr)]);
    assert_eq!(
        err.state(),
        sandbox_protocol::OperationState::UnknownOutcome,
        "{err:?}"
    );
}

#[test]
fn start_refusal_killed_by_signal_is_unknown() {
    let err = create_with_start_injection(&[("start-error-signal", BR_NETFILTER_REFUSAL)]);
    assert_eq!(
        err.state(),
        sandbox_protocol::OperationState::UnknownOutcome,
        "{err:?}"
    );
}

#[test]
fn start_refusal_with_exit0_is_unknown() {
    let err = create_with_start_injection(&[("start-error-exit0", BR_NETFILTER_REFUSAL)]);
    assert_eq!(
        err.state(),
        sandbox_protocol::OperationState::UnknownOutcome,
        "{err:?}"
    );
}

#[test]
fn start_refusal_with_frozen_is_unknown() {
    let err = create_with_start_injection(&[
        ("start-error", BR_NETFILTER_REFUSAL),
        ("instance-status", "Frozen 110"),
    ]);
    assert_eq!(
        err.state(),
        sandbox_protocol::OperationState::UnknownOutcome,
        "{err:?}"
    );
}

#[test]
fn start_cold_reconnect_refusal_retains_unknown_and_resources() {
    let (runtime, log) = runtime_for("fix6_cold_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    let (policy, hash) = policy_with_cidr("128.66.0.0/24");
    runtime.create_bound(&create_with_policy()).expect("create");
    fs::remove_file(statedir.join("started")).unwrap();
    fs::write(statedir.join("start-error"), BR_NETFILTER_REFUSAL).unwrap();
    let err = runtime
        .reconnect_bound(&reconnect_req(Some(policy), Some(hash)))
        .expect_err("refused");
    assert_eq!(
        err.state(),
        sandbox_protocol::OperationState::UnknownOutcome,
        "{err:?}"
    );
    assert_eq!(err.code, SandboxErrorCode::SandboxNotRunning);
    assert!(err.message.contains("br_netfilter"));
    assert_create_resources(&runtime, &log, true);
    assert!(
        !log_invoked(&log, "delete"),
        "reconnect refusal cannot authorize cleanup"
    );
}

/// E-16: under a permissive umask (002, Ubuntu's default) every directory
/// the host-state journal creates is owner-only 0700 and every file it
/// writes (records, the `.wssp-durable` marker, the drain cursor) is 0600.
/// The whole created tree is walked, so a new state file that skips the
/// private boundary fails here. A pre-existing ancestor keeps its own mode.
/// The umask is process-wide, so the check runs in a child test process
/// started under `umask 002`.
#[test]
fn host_state_created_under_umask_002_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    const CHILD: &str = "WSSP_E16_UMASK_CHILD_ROOT";
    if let Some(root) = std::env::var_os(CHILD) {
        let root = std::path::PathBuf::from(root);
        let (mut client, _log) = client_for_with_log("fix6_new_ready");
        let state = root.join("data/relay/host/runtime");
        client.state_dir = Some(state.clone());
        client
            .apply_sandbox_network(&test_plan("sbx-1"))
            .expect("provisioned");
        let _ = client.drain_pending_network_cleanups();
        assert!(
            state.join("network-cleanups/.wssp-durable").is_file(),
            "the durable marker was written"
        );
        assert!(
            state.join("network-cleanups/.drain-cursor").is_file(),
            "the drain wrote its cursor"
        );
        let mut stack = vec![root.join("data")];
        let mut seen = 0;
        while let Some(path) = stack.pop() {
            let meta = fs::symlink_metadata(&path).unwrap();
            let mode = meta.permissions().mode() & 0o7777;
            if meta.is_dir() {
                assert_eq!(mode, 0o700, "directory {}", path.display());
                for entry in fs::read_dir(&path).unwrap() {
                    stack.push(entry.unwrap().path());
                }
            } else {
                assert_eq!(mode, 0o600, "file {}", path.display());
            }
            seen += 1;
        }
        assert!(seen >= 7, "walked {seen} entries");
        // The caller-owned root existed before and keeps its mode.
        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o7777,
            0o755
        );
        return;
    }
    let root = std::env::temp_dir().join(format!("wssp-e16-umask-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    let output = std::process::Command::new("/bin/sh")
        .args(["-c", "umask 002 && exec \"$@\"", "sh"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "incus::network_shim_tests::host_state_created_under_umask_002_is_owner_only",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, &root)
        .output()
        .unwrap();
    let _ = fs::remove_dir_all(&root);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "child failed: {:?}\nstdout:\n{stdout}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

/// HR-R5: the refusal rule matches the CLI's English `Error: ` prefix. The
/// shim translates its message unless the caller pins `LC_ALL=C`; a pinned
/// run still classifies the refusal as FAILED with the daemon's reason.
#[test]
fn start_refusal_is_classified_under_a_translated_caller_locale() {
    let err = create_with_start_injection(&[("start-error-localized", BR_NETFILTER_REFUSAL)]);
    assert_eq!(
        err.state(),
        sandbox_protocol::OperationState::Failed,
        "a translated prefix must not degrade the refusal: {err:?}"
    );
    assert_eq!(err.code, SandboxErrorCode::SandboxNotRunning, "{err:?}");
    assert!(
        err.message
            .contains("br_netfilter kernel module not loaded"),
        "{}",
        err.message
    );
}

/// Real create entry points share one daemon lock, but slow DNS holds none
/// of it. Independent executable shims isolate VM state, never launch Incus.
#[test]
fn concurrent_creates_resolve_dns_before_allocation_lock() {
    concurrent_creates_pause_outside_allocation("dns", true);
}

#[test]
fn parallel_creates_release_allocation_before_acl_installation_and_publication() {
    for egress in [false, true] {
        concurrent_creates_pause_outside_allocation("after_subnet_allocation", egress);
    }
}

fn concurrent_creates_pause_outside_allocation(phase: &'static str, egress: bool) {
    use std::sync::{Arc, Condvar, Mutex, mpsc};
    use std::time::Duration;
    const N: usize = 4;
    let (shared, _shared_log) = runtime_for("fix6_new_ready");
    let shared_lock_dir = shared.client().daemon_lock_dir_override.clone().unwrap();
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let (entered_tx, entered_rx) = mpsc::channel();
    let mut workers = Vec::new();
    let mut observers = Vec::new();
    let mut monitor = None;
    for n in 0..N {
        let (mut runtime, log) = runtime_for("fix6_new_ready");
        let id = format!("dns-create-{n}");
        let binary = runtime.client().binary.clone();
        fs::write(
            &binary,
            fs::read_to_string(&binary)
                .unwrap()
                .replace("sbx-1", &id)
                .replace(r#"shim-$(basename "$statedir")"#, "batch-b-shared-daemon"),
        )
        .unwrap();
        let root = log.parent().unwrap();
        fs::write(root.join("config/user.flycockpit.sandbox_id"), &id).unwrap();
        let (network, _) = sandbox_network_names(&id);
        fs::write(root.join("device-eth0"), format!("eth0,network={network},security.mac_filtering=true,security.ipv4_filtering=true,security.ipv6_filtering=true,security.port_isolation=true")).unwrap();
        runtime.client_mut().daemon_lock_dir_override = Some(shared_lock_dir.clone());
        let ready = entered_tx.clone();
        let pause_gate = gate.clone();
        let pause = move || {
            ready.send(()).unwrap();
            let (open, changed) = &*pause_gate;
            let open = open.lock().unwrap();
            let (open, timeout) = changed
                .wait_timeout_while(open, Duration::from_secs(20), |open| !*open)
                .unwrap();
            assert!(*open && !timeout.timed_out(), "create gate not opened");
        };
        if phase == "dns" {
            runtime.client_mut().resolver =
                Some(super::client::TestResolver(Arc::new(move |_, _| {
                    pause();
                    Ok(vec!["8.8.8.8".parse().unwrap()])
                })));
        } else {
            let barrier = Arc::new(std::sync::Barrier::new(2));
            runtime.client_mut().create_barrier = Some((phase, barrier.clone()));
            observers.push(std::thread::spawn(move || {
                barrier.wait();
                pause();
                barrier.wait();
            }));
            runtime.client_mut().resolver = Some(super::client::TestResolver(Arc::new(|_, _| {
                Ok(vec!["8.8.8.8".parse().unwrap()])
            })));
        }
        if let Some(previous) = &monitor {
            let previous: &super::client::IncusClient = previous;
            assert_eq!(
                previous.daemon_lock_key_for_test(),
                runtime.client().daemon_lock_key_for_test()
            );
        }
        monitor = Some(runtime.client().clone());
        let mut request = create_req();
        request.sandbox_id = id.clone();
        request.instance_name = format!("wssp-sbx-{id}");
        if egress {
            let policy = EgressPolicy {
                mode: sandbox_protocol::EgressMode::Allowlist,
                domains: vec!["example.com".into()],
                cidrs: vec![],
            };
            request.egress_policy_hash = Some(super::network::policy_hash_hex(&policy));
            request.egress_policy = Some(policy);
        }
        workers.push(std::thread::spawn(move || runtime.create_bound(&request)));
    }
    drop(entered_tx);
    let all_resolving = (0..N).all(|_| entered_rx.recv_timeout(Duration::from_secs(10)).is_ok());
    let mut monitor = monitor.unwrap();
    monitor.allocation_lock_wait = Some(Duration::from_millis(200));
    let lock_is_free = monitor.lock_subnet_allocation().is_ok();
    // Always open and join on assertion failure too; no detached gated work.
    *gate.0.lock().unwrap() = true;
    gate.1.notify_all();
    for observer in observers {
        observer.join().unwrap();
    }
    let results: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
    assert!(
        all_resolving,
        "all creates must reach {phase} while every create gate is closed"
    );
    assert!(lock_is_free, "{phase} must not hold the allocation lock");
    for result in results {
        result.expect("concurrent create must not time out on allocation");
    }
}

#[test]
fn cancelled_boot_starts_teardown_before_readiness_gate_opens() {
    use std::sync::{Arc, mpsc};
    use std::time::{Duration, Instant};
    for kill in [false, true] {
        let (runtime, log) = runtime_for("fix6_new_ready");
        let root = log.parent().unwrap();
        let binary = &runtime.client().binary;
        let script = fs::read_to_string(binary).unwrap().replace("      true)\n", "      true)\n        touch \"$statedir/boot-entered\"\n        while [ ! -f \"$statedir/boot-release\" ]; do sleep 0.01; done\n");
        fs::write(binary, script).unwrap();
        let permit = Arc::new(crate::RuntimePermit::default());
        let boot = runtime.with_cancellation(permit.clone());
        let (finished_tx, finished_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            finished_tx
                .send(boot.create_bound(&create_with_policy()))
                .unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        while !root.join("boot-entered").exists() {
            assert!(
                Instant::now() < deadline,
                "create must enter the gated readiness probe"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        permit.revoke();
        let finished = finished_rx.recv_timeout(Duration::from_secs(5));
        if finished.is_err() {
            fs::write(root.join("boot-release"), "").unwrap();
        }
        let outcome =
            finished.expect("revocation must interrupt readiness with boot gate still closed");
        assert!(
            matches!(outcome, Err(crate::EffectError::Unknown(_))),
            "{outcome:?}"
        );
        if kill {
            runtime
                .kill_bound(&crate::KillSandboxRequest {
                    sandbox_id: "sbx-1".into(),
                    instance_name: "wssp-sbx-sbx-1".into(),
                    template_fingerprint: create_req().template_digest,
                    operation_id: "kill-boot".into(),
                    idempotency_key: "kill-boot".into(),
                })
                .unwrap();
        } else {
            runtime
                .stop_sandbox(&crate::StopSandboxRequest {
                    sandbox_id: "sbx-1".into(),
                    instance_name: "wssp-sbx-sbx-1".into(),
                    template_fingerprint: create_req().template_digest,
                    operation_id: "stop-boot".into(),
                    idempotency_key: "stop-boot".into(),
                })
                .unwrap();
        }
        assert!(
            root.join(if kill {
                "deleted-instance"
            } else {
                "stopped-instance"
            })
            .exists()
        );
        assert!(
            !root.join("boot-release").exists(),
            "teardown must finish before boot gate opens"
        );
        fs::write(root.join("boot-release"), "").unwrap();
        worker.join().unwrap();
    }
}

/// The CLI is a separate process: revoke while an actual init/config command
/// has only partially applied, rather than simulating a completed create.
fn teardown_create_phase(phase: &'static str, stop: bool) {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::sync::{Arc, Barrier, mpsc};
    use std::time::Duration;

    let (mut runtime, log) = runtime_for("c37_start_gated");
    runtime = runtime
        .with_root_disk(&crate::RootDisk {
            pool: crate::StoragePoolIdentity {
                name: "default".into(),
                storage_id: "a".repeat(32),
            },
            disk_gi_b: 32,
        })
        .unwrap();
    let root = log.parent().unwrap();
    let binary = runtime.client().binary.clone();
    let barrier = Arc::new(Barrier::new(2));
    let socket = UnixListener::bind(root.join("gate.sock")).unwrap();
    let shim_phase = matches!(phase, "during_init" | "network" | "config");
    if shim_phase {
        let marker = match phase {
            "during_init" => "    : > \"$statedir/launched\"\n",
            "network" => "        : > \"$statedir/networks/$name.conf\"\n",
            _ => "  config)\n",
        };
        let gate = r#"if [ ! -f "$statedir/create-phase-gated" ]; then
touch "$statedir/create-phase-gated"
python3 - "$statedir/gate.sock" <<'E43GATE'
import socket,sys
s = socket.socket(socket.AF_UNIX)
s.settimeout(20)
s.connect(sys.argv[1])
s.sendall(b'x')
assert s.recv(1) == b'x'
E43GATE
fi
"#;
        let script = fs::read_to_string(&binary).unwrap();
        assert!(script.contains(marker));
        let script = script.replacen(marker, &format!("{marker}{gate}"), 1);
        super::shim_tests::install_executable(Path::new(&binary), &script, 0o755);
    } else if phase == "readiness" {
        runtime.client_mut().readiness_barrier = Some(barrier.clone());
    } else {
        runtime.client_mut().create_barrier = Some((phase, barrier.clone()));
    }
    let permit = Arc::new(crate::RuntimePermit::default());
    let creating = runtime.with_cancellation(permit.clone());
    let (created_tx, created_rx) = mpsc::channel();
    let create = std::thread::spawn(move || {
        created_tx
            .send(creating.create_bound(&create_with_policy()))
            .unwrap();
    });
    let mut connection = if shim_phase {
        let (mut connection, _) = socket.accept().unwrap();
        connection
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        let mut entered = [0];
        connection.read_exact(&mut entered).unwrap();
        Some(connection)
    } else {
        barrier.wait();
        None
    };
    permit.revoke();
    // A killed CLI is not evidence that its daemon operation has stopped.
    // The gate, not elapsed time, owns completion. This bounded receive is a
    // negative assertion while the gate is closed, never a scheduling sleep.
    let premature = shim_phase.then(|| created_rx.recv_timeout(Duration::from_millis(200)));
    let cleanup = runtime.clone();
    let mut kill = Some(std::thread::spawn(move || {
        if stop {
            cleanup
                .stop_sandbox(&crate::StopSandboxRequest {
                    sandbox_id: "sbx-1".into(),
                    instance_name: "wssp-sbx-sbx-1".into(),
                    template_fingerprint: create_req().template_digest,
                    operation_id: "e46-stop".into(),
                    idempotency_key: "e46-stop".into(),
                })
                .map(|proof| proof.into_value().sandbox)
        } else {
            cleanup
                .kill_bound(&crate::KillSandboxRequest {
                    sandbox_id: "sbx-1".into(),
                    instance_name: "wssp-sbx-sbx-1".into(),
                    template_fingerprint: create_req().template_digest,
                    operation_id: "e43-kill".into(),
                    idempotency_key: "e43-kill".into(),
                })
                .map(|proof| proof.into_value().sandbox)
        }
    }));
    // Readiness holds no mutation lock: kill must finish before it opens.
    let early_kill = if phase == "readiness" {
        Some(kill.take().unwrap().join().unwrap())
    } else {
        None
    };
    let mut released = Ok(());
    if let Some(connection) = &mut connection {
        released = connection.write_all(b"x");
    } else {
        barrier.wait();
    }
    let outcome = if let Some(Ok(outcome)) = premature.as_ref() {
        outcome.clone()
    } else {
        created_rx.recv_timeout(Duration::from_secs(20)).unwrap()
    };
    create.join().unwrap();
    let result = match early_kill {
        Some(result) => result,
        None => kill.take().unwrap().join().unwrap(),
    };
    assert!(
        premature.is_none_or(|result| result.is_err()),
        "{phase}: revoked create abandoned an in-flight daemon effect"
    );
    released.unwrap();
    assert!(outcome.is_err(), "{phase}: revoked create reported ready");
    assert_eq!(
        result.unwrap().state,
        if stop && !matches!(phase, "before_init" | "network") {
            sandbox_protocol::SandboxLifecycleState::Stopped
        } else if stop {
            sandbox_protocol::SandboxLifecycleState::Absent
        } else {
            sandbox_protocol::SandboxLifecycleState::Deleted
        }
    );
    // Check before cold reconnect can legitimately create the start marker.
    // Init/config settlement must never borrow authority to launch the guest.
    assert!(
        !root.join("started").exists() || phase == "readiness",
        "{phase}: revoked create started the guest during settlement"
    );
    let disk_kept = stop && !matches!(phase, "before_init" | "network");
    // Query/reconciliation may itself drain orphaned networks. Stop's own
    // completion must already include absence, before any such observation.
    if !disk_kept {
        runtime
            .client()
            .verify_sandbox_network_absent("sbx-1")
            .unwrap();
    }
    assert_eq!(
        runtime
            .query_sandbox("sbx-1", None, Some(&create_req().template_digest))
            .unwrap(),
        disk_kept.then_some(sandbox_protocol::SandboxLifecycleState::Stopped)
    );
    if !disk_kept {
        runtime
            .client()
            .verify_sandbox_network_absent("sbx-1")
            .unwrap();
    } else {
        // The original binding, NIC and immutable network survive partial
        // init/config settlement; a cold start can verify and reuse them.
        let req = create_with_policy();
        runtime.client_mut().readiness_barrier = None;
        // Model Incus clearing the stopped status when its next start lands.
        let script = fs::read_to_string(&binary).unwrap();
        super::shim_tests::install_executable(
            Path::new(&binary),
            &script.replace(
                "    : > \"$started\"",
                "    rm -f \"$statedir/stopped-instance\"\n    : > \"$started\"",
            ),
            0o755,
        );
        runtime
            .reconnect_bound(&crate::ReconnectSandboxRequest {
                vm_size: sandbox_protocol::VmSize::defaults().unwrap(),
                lease: req.lease,
                template_fingerprint: req.template_digest,
                architecture: req.architecture,
                guest: req.guest,
                sandbox_id: req.sandbox_id,
                instance_name: req.instance_name,
                operation_id: "restart".into(),
                idempotency_key: "restart".into(),
                egress_policy: req.egress_policy,
                egress_policy_hash: req.egress_policy_hash,
                egress_admission: crate::egress::EgressAdmission::PERMITTED,
                guest_sudo: false,
            })
            .unwrap();
    }
    assert!(!root.join("host-state/network-cleanups/sbx-1.json").exists());
    // Repeating teardown consumes no further allocation and remains proven.
    runtime
        .kill_bound(&crate::KillSandboxRequest {
            sandbox_id: "sbx-1".into(),
            instance_name: "wssp-sbx-sbx-1".into(),
            template_fingerprint: create_req().template_digest,
            operation_id: "e43-repeat".into(),
            idempotency_key: "e43-repeat".into(),
        })
        .unwrap();
}

#[test]
fn e43_kill_before_init() {
    teardown_create_phase("before_init", false);
}
#[test]
fn e43_kill_during_init() {
    teardown_create_phase("during_init", false);
}
#[test]
fn e43_kill_during_network_apply() {
    teardown_create_phase("network", false);
}
#[test]
fn e43_kill_during_config() {
    teardown_create_phase("config", false);
}
#[test]
fn e43_kill_before_start() {
    teardown_create_phase("before_start", false);
}
#[test]
fn e43_kill_during_readiness() {
    teardown_create_phase("readiness", false);
}

#[test]
fn d2_stop_create_before_init() {
    teardown_create_phase("before_init", true);
}
#[test]
fn d2_stop_create_during_init() {
    teardown_create_phase("during_init", true);
}
#[test]
fn d2_stop_create_network() {
    teardown_create_phase("network", true);
}
#[test]
fn d2_stop_create_config() {
    teardown_create_phase("config", true);
}
#[test]
fn d2_stop_create_before_start() {
    teardown_create_phase("before_start", true);
}
#[test]
fn d2_stop_create_readiness() {
    teardown_create_phase("readiness", true);
}

#[test]
fn e43_settled_create_preserves_cumulative_deadline() {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::sync::{Arc, mpsc};
    use std::time::Duration;
    let (runtime, log) = runtime_for("c37_start_gated");
    let root = log.parent().unwrap();
    let socket = UnixListener::bind(root.join("deadline.sock")).unwrap();
    let binary = runtime.client().binary.clone();
    let marker = "    : > \"$statedir/launched\"\n";
    let gate = r#"python3 - "$statedir/deadline.sock" <<'E43DEADLINE'
import socket,sys
s = socket.socket(socket.AF_UNIX)
s.settimeout(20)
s.connect(sys.argv[1])
s.sendall(b'x')
s.recv(1)
E43DEADLINE
"#;
    let script =
        fs::read_to_string(&binary)
            .unwrap()
            .replacen(marker, &format!("{marker}{gate}"), 1);
    super::shim_tests::install_executable(Path::new(&binary), &script, 0o755);
    // The larger host-call bound must not replace this whole-create deadline.
    let scoped = runtime.with_cancellation(Arc::new(crate::RuntimePermit::with_timeout(
        Duration::from_secs(2),
    )));
    let (tx, rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        tx.send(scoped.create_bound(&create_with_policy())).unwrap();
    });
    let (mut connection, _) = socket.accept().unwrap();
    connection
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut entered = [0];
    connection.read_exact(&mut entered).unwrap();
    let bounded = rx.recv_timeout(Duration::from_secs(5));
    // Always release and join on an inverse failure too.
    let _ = connection.write_all(b"x");
    worker.join().unwrap();
    assert!(
        bounded.is_ok(),
        "settled create ignored its cumulative runtime deadline"
    );
    assert!(bounded.unwrap().is_err());
    assert!(!root.join("started").exists());
    runtime
        .kill_bound(&crate::KillSandboxRequest {
            sandbox_id: "sbx-1".into(),
            instance_name: "wssp-sbx-sbx-1".into(),
            template_fingerprint: create_req().template_digest,
            operation_id: "deadline-cleanup".into(),
            idempotency_key: "deadline-cleanup".into(),
        })
        .unwrap();
    runtime
        .client()
        .verify_sandbox_network_absent("sbx-1")
        .unwrap();
}

#[test]
fn allocation_lock_wait_converges_after_more_than_sixty_seconds() {
    let (client, _) = client_for_with_log("fix6_new_ready");
    let guard = client.lock_subnet_allocation().unwrap();
    let writer = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(61));
        drop(guard);
    });
    let began = std::time::Instant::now();
    let result = client.lock_subnet_allocation();
    writer.join().unwrap();
    result.expect("concurrent provisioning can legitimately exceed the old one-minute lock bound");
    assert!(began.elapsed() > std::time::Duration::from_secs(60));
}

#[test]
fn atomic_acl_fifo_preserves_fences_and_rejects_a_stale_whole_acl_write() {
    let (client, log) = client_for_with_log("fix6_new_ready");
    client
        .apply_sandbox_network(&super::network::test_plan("sbx-1"))
        .unwrap();
    let (_, acl) = sandbox_network_names("sbx-1");
    let path = format!("/1.0/network-acls/{acl}?project=default");
    let old = client.query_raw(&path).unwrap();
    let etag = super::acl::acl_etag(&old).unwrap();
    let turn = client
        .acl_edit_turn(
            &acl,
            std::time::Instant::now() + std::time::Duration::from_secs(5),
        )
        .unwrap();
    // A stalled ACL cannot queue an unrelated sandbox behind itself.
    let other_acl = sandbox_network_names("sbx-2").1;
    let other_turn = client
        .acl_edit_turn(&other_acl, std::time::Instant::now())
        .unwrap();
    drop(other_turn);
    let (completed, results) = std::sync::mpsc::channel();
    let mut writers = Vec::new();
    for n in 0..2 {
        let writer_client = client.clone();
        let name = acl.clone();
        let completed = completed.clone();
        writers.push(std::thread::spawn(move || {
            let result =
                writer_client.update_acl(&name, std::time::Duration::from_secs(10), |metadata| {
                    metadata["egress"]
                        .as_array_mut()
                        .unwrap()
                        .push(serde_json::json!({
                            "action": if n == 0 {"allow"} else {"reject"}, "state":"enabled",
                            "destination":"128.66.0.7/32", "description":format!("fifo-{n}")
                        }));
                    Ok(())
                });
            completed.send(n).unwrap();
            result
        }));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while client.acl_edits.lock().unwrap().get(&acl).unwrap().len() < n + 2 {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
    assert!(results.try_recv().is_err());
    drop(turn);
    for writer in writers {
        writer.join().unwrap().unwrap();
    }
    assert_eq!(results.recv().unwrap(), 0);
    assert_eq!(results.recv().unwrap(), 1);
    let current = client.query_raw(&path).unwrap();
    assert!(
        current["egress"]
            .as_array()
            .unwrap()
            .iter()
            .any(|rule| rule["description"] == "fifo-1")
    );
    let stale = client.query_body_timed(
        "PUT",
        &path,
        &old.to_string(),
        &[&format!("If-Match: \"{etag}\"")],
        std::time::Duration::from_secs(5),
    );
    assert!(
        stale.is_err(),
        "a late request must not erase a newer fence"
    );
    assert_eq!(client.query_raw(&path).unwrap(), current);
    assert!(
        !log_lines(&log)
            .iter()
            .any(|line| line.contains("network acl rule"))
    );
}

/// Label the shim's instance as a restored one (base
/// image = the stored disk, `user.flycockpit.restore_base` tag) and bind it
/// the way the daemon does from its lease record.
fn relabel_restored(runtime: &super::kvm::IncusKvmRuntime, statedir: &Path) {
    const DISK: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    fs::write(statedir.join("config/volatile.base_image"), DISK).unwrap();
    fs::write(
        statedir.join("config/user.flycockpit.restore_base"),
        format!("sha256:{DISK}"),
    )
    .unwrap();
    runtime.bind_restore_base("sbx-1", &format!("sha256:{DISK}"));
}

#[test]
fn a_restored_instance_enforcement_loss_still_drains() {
    let (runtime, log) = runtime_for("fix6_cold_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    runtime.create_bound(&create_with_policy()).expect("create");
    relabel_restored(&runtime, &statedir);
    tamper_acl_allow_all(&statedir);
    let err = runtime
        .probe_sandbox(&probe_req())
        .expect_err("an unenforced restored VM never probes GuestReady");
    assert_eq!(err.code, SandboxErrorCode::GuestUnavailable, "{err:?}");
    assert!(loss_record(&statedir).exists());
    runtime
        .drain_enforcement_losses(&|_, _| Ok(()))
        .expect("drain");
    assert!(
        log_lines(&log)
            .iter()
            .any(|line| line.starts_with("delete ") && line.contains("wssp-sbx-sbx-1")),
        "the drain tears the unenforced restored VM down"
    );
    assert!(!loss_record(&statedir).exists(), "the loss record retired");
}

#[test]
fn a_restored_instance_breach_is_halted_when_teardown_bookkeeping_fails() {
    let (mut runtime, log) = runtime_for("fix6_cold_ready");
    let statedir = log.parent().expect("log parent").to_path_buf();
    runtime.create_bound(&create_with_policy()).expect("create");
    relabel_restored(&runtime, &statedir);
    tamper_acl_allow_all(&statedir);
    runtime
        .probe_sandbox(&probe_req())
        .expect_err("the drift is confirmed");
    runtime.client_mut().fail_dir_sync_for = Some(statedir.join("host-state/network-cleanups"));
    runtime
        .drain_enforcement_losses(&|_, _| Ok(()))
        .expect_err("the bookkeeping failure surfaces");
    assert!(
        log_lines(&log)
            .iter()
            .any(|line| line.starts_with("stop ") && line.contains("wssp-sbx-sbx-1")),
        "the restored VM's breach is halted"
    );
}
