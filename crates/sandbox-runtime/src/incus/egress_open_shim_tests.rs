//! Executable-shim tests for default-open egress on the Incus runtime (see
//! docs/guide/network.md#refusal-reasons).
//! A fake `incus` binary records argv; no VM ever launches.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sandbox_protocol::{EgressMode, EgressPolicy, SandboxErrorCode};

use super::network::{policy_hash_hex, sandbox_network_names};
use super::shim_tests::{create_req, runtime_for};
use crate::egress::{DomainBlocklist, EgressAdmission, EgressRefusal, EgressSettings};
use crate::guard_probe::FakeGuardProbe;
use crate::r#trait::SandboxRuntime;

fn log_lines(log: &Path) -> Vec<String> {
    fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
}

fn statedir(log: &Path) -> PathBuf {
    log.parent().expect("log parent").to_path_buf()
}

fn open_policy() -> (EgressPolicy, String) {
    let policy = EgressPolicy {
        mode: EgressMode::Open,
        domains: Vec::new(),
        cidrs: Vec::new(),
    };
    let hash = policy_hash_hex(&policy);
    (policy, hash)
}

fn allowlist_policy() -> (EgressPolicy, String) {
    let policy = EgressPolicy {
        mode: EgressMode::Allowlist,
        domains: Vec::new(),
        cidrs: vec!["128.66.0.0/24".into()],
    };
    let hash = policy_hash_hex(&policy);
    (policy, hash)
}

fn create_open(settings: EgressSettings) -> crate::CreateSandboxRequest {
    let (policy, hash) = open_policy();
    let mut request = create_req();
    request.egress_policy = Some(policy);
    request.egress_policy_hash = Some(hash);
    request.egress_settings = settings;
    request
}

fn reconnect(
    policy: &(EgressPolicy, String),
    admission: EgressAdmission,
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
        egress_policy: Some(policy.0.clone()),
        egress_policy_hash: Some(policy.1.clone()),
        egress_admission: admission,
        guest_sudo: false,
    }
}

fn record(statedir: &Path) -> serde_json::Value {
    serde_json::from_str(
        &fs::read_to_string(statedir.join("host-state/network-plans/sbx-1.json"))
            .expect("plan record"),
    )
    .unwrap()
}

fn raw_dnsmasq(statedir: &Path) -> String {
    let (network, _) = sandbox_network_names("sbx-1");
    fs::read_to_string(statedir.join("networks").join(format!("{network}.raw"))).unwrap_or_default()
}

fn acl_egress_path(statedir: &Path) -> PathBuf {
    let (_, acl) = sandbox_network_names("sbx-1");
    statedir.join("acls").join(format!("{acl}.egress"))
}

fn start_count(log: &Path) -> usize {
    log_lines(log)
        .iter()
        .filter(|line| line.split_whitespace().next() == Some("start"))
        .count()
}

/// A stopped VM for refusal cases (the shim keeps reporting it Stopped).
fn stop_vm(statedir: &Path) {
    let _ = fs::remove_file(statedir.join("started"));
    fs::write(statedir.join("stopped-instance"), "").unwrap();
}

/// A stopped VM that a later `start` brings back (shim mode `stopped`:
/// Stopped until `start` records `started`).
fn stop_restartable(statedir: &Path) {
    fs::remove_file(statedir.join("started")).expect("the VM was running");
}

fn refusal(err: crate::EffectError) -> crate::RuntimeError {
    err.into_error()
}

fn deny_settings() -> EgressSettings {
    EgressSettings {
        domain_blocklist: DomainBlocklist {
            root_digest: Some("sha256:root".into()),
            deployment_digest: None,
            names: vec!["bad.example".into()],
        },
        ..Default::default()
    }
}

/// §2.2/§2.6: an open-mode create builds the bridge with the small deny-all
/// base (argv unchanged), publishes the recorded open resolver through the
/// stdin PATCH and reads it back BEFORE the start, and the record carries
/// mode, settings, resolver base and denied grants.
#[test]
fn open_mode_create_publishes_the_resolver_before_the_start_and_records_the_plan() {
    let (runtime, log) = runtime_for("fix6_new_ready");
    let dir = statedir(&log);
    let settings = deny_settings();
    runtime
        .create_bound(&create_open(settings.clone()))
        .expect("open create");
    let (network, _) = sandbox_network_names("sbx-1");
    let lines = log_lines(&log);
    let create = lines
        .iter()
        .position(|line| line.contains(&format!("network create {network}")))
        .expect("bridge created");
    assert!(
        lines[create].contains("no-resolv"),
        "the bridge is created with the deny-all base: {}",
        lines[create]
    );
    let patch = lines
        .iter()
        .position(|line| {
            line.contains("-X PATCH") && line.contains(&format!("/1.0/networks/{network}"))
        })
        .expect("resolver published by PATCH");
    let start = lines
        .iter()
        .position(|line| line.split_whitespace().next() == Some("start"))
        .expect("started");
    assert!(create < patch && patch < start, "{lines:#?}");
    let open_body = super::dns::render_open_dnsmasq_config(&settings).unwrap();
    assert_eq!(raw_dnsmasq(&dir), open_body);
    assert!(open_body.contains("local=/bad.example/"));
    let record = record(&dir);
    assert_eq!(record["mode"], "open");
    assert_eq!(record["dnsmasq_base"], open_body);
    assert_eq!(record["denied_grants"], serde_json::json!([]));
    assert_eq!(
        serde_json::from_value::<EgressSettings>(record["settings"].clone()).unwrap(),
        settings
    );
    let egress = fs::read_to_string(acl_egress_path(&dir)).unwrap();
    assert!(egress.contains("description=wssp-open"), "{egress}");
    assert!(egress.contains("description=wssp-smtp-reject"), "{egress}");
    // Round trip through the observation boundary.
    let plan = runtime
        .client()
        .persisted_enforcement_plan_checked("sbx-1")
        .unwrap()
        .unwrap();
    assert_eq!(plan.mode, EgressMode::Open);
    assert_eq!(plan.settings, Some(settings));
    assert_eq!(plan.dnsmasq_base, open_body);
}

/// §2.6 (M3): node settings changed after materialization (SMTP off, DNS
/// blocked, upstreams, a blocked domain) never convict a sandbox: a create
/// retry adopting the existing VM, a warm reconnect and a cold reconnect all
/// verify against the RECORD, and the ACL is not rewritten.
#[test]
fn node_setting_changes_after_materialization_are_not_convicted() {
    let (runtime, log) = runtime_for("stopped");
    let dir = statedir(&log);
    runtime
        .create_bound(&create_open(EgressSettings::default()))
        .expect("open create");
    let acl_before = fs::read_to_string(acl_egress_path(&dir)).unwrap();
    let raw_before = raw_dnsmasq(&dir);
    let changed = EgressSettings {
        block_smtp: false,
        block_external_dns: true,
        dns_upstreams: vec![std::net::Ipv4Addr::new(9, 9, 9, 9)],
        ..deny_settings()
    };
    runtime
        .create_bound(&create_open(changed))
        .expect("an adopting create retry uses the record");
    runtime
        .reconnect_bound(&reconnect(&open_policy(), EgressAdmission::PERMITTED))
        .expect("warm reconnect");
    stop_restartable(&dir);
    runtime
        .reconnect_bound(&reconnect(&open_policy(), EgressAdmission::PERMITTED))
        .expect("cold reconnect");
    assert_eq!(
        fs::read_to_string(acl_egress_path(&dir)).unwrap(),
        acl_before
    );
    assert_eq!(raw_dnsmasq(&dir), raw_before);
    assert_eq!(record(&dir)["settings"]["block_smtp"], true);
}

/// §1.5: a COLD reconnect of an open sandbox whose node owner withdrew
/// consent, or with the guard down, is refused with the typed reason —
/// after the read-only verification, with no intent journaled, no NIC
/// mutation and no start; the VM stays stopped and its network intact.
#[test]
fn cold_reconnect_refusals_journal_nothing_and_mutate_nothing() {
    let (runtime, log) = runtime_for("stopped");
    let dir = statedir(&log);
    runtime
        .create_bound(&create_open(EgressSettings::default()))
        .expect("open create");
    stop_restartable(&dir);
    let starts = start_count(&log);
    for (admission, reason) in [
        (
            EgressAdmission {
                open_egress_permitted: false,
                guard_ok: true,
            },
            EgressRefusal::OpenEgressNotPermitted,
        ),
        (
            EgressAdmission {
                open_egress_permitted: true,
                guard_ok: false,
            },
            EgressRefusal::GuardUnavailable,
        ),
    ] {
        let before = log_lines(&log).len();
        let err = refusal(
            runtime
                .reconnect_bound(&reconnect(&open_policy(), admission))
                .expect_err("cold reconnect refused"),
        );
        assert_eq!(err.egress_refusal(), Some(reason));
        assert_eq!(err.code, SandboxErrorCode::UnsupportedCapability);
        let after = log_lines(&log);
        assert!(
            after[before..]
                .iter()
                .all(|line| !line.contains("config device")
                    && !line.contains("network acl")
                    && line.split_whitespace().next() != Some("start")
                    && !line.contains("-X PATCH")
                    && !line.contains("-X PUT")),
            "no mutation: {:#?}",
            &after[before..]
        );
        assert!(
            !dir.join("host-state/network-cleanups/sbx-1.json").exists(),
            "no provisioning intent is journaled"
        );
        assert!(
            !dir.join("host-state/enforcement-losses/sbx-1.json")
                .exists(),
            "no refusal fence: enforcement is fine"
        );
        assert!(!dir.join("started").exists(), "the VM stays stopped");
    }
    assert_eq!(start_count(&log), starts);
    // Consent restored: the cold reconnect proceeds.
    runtime
        .reconnect_bound(&reconnect(&open_policy(), EgressAdmission::PERMITTED))
        .expect("cold reconnect after consent returns");
}

/// §1.5: warm reconnect (VM running) is never refused for consent or guard
/// reasons; an own allowlist sandbox's cold reconnect ignores consent.
#[test]
fn warm_reconnect_and_allowlist_cold_reconnect_ignore_consent() {
    let (runtime, log) = runtime_for("fix6_new_ready");
    let dir = statedir(&log);
    runtime
        .create_bound(&create_open(EgressSettings::default()))
        .expect("open create");
    runtime
        .reconnect_bound(&reconnect(
            &open_policy(),
            EgressAdmission {
                open_egress_permitted: false,
                guard_ok: false,
            },
        ))
        .expect("a warm reconnect is never refused");

    let (runtime, log) = runtime_for("stopped");
    let dir2 = statedir(&log);
    let mut request = create_req();
    let policy = allowlist_policy();
    request.egress_policy = Some(policy.0.clone());
    request.egress_policy_hash = Some(policy.1.clone());
    runtime.create_bound(&request).expect("allowlist create");
    stop_restartable(&dir2);
    runtime
        .reconnect_bound(&reconnect(
            &policy,
            EgressAdmission {
                open_egress_permitted: false,
                guard_ok: true,
            },
        ))
        .expect("consent never applies to an allowlist sandbox");
    let _ = dir;
}

/// §1.5: the create check runs before any host IO.
#[test]
fn create_refusals_happen_before_any_host_io() {
    for (admission, open, reason) in [
        (
            EgressAdmission {
                open_egress_permitted: true,
                guard_ok: false,
            },
            false,
            EgressRefusal::GuardUnavailable,
        ),
        (
            EgressAdmission {
                open_egress_permitted: false,
                guard_ok: true,
            },
            true,
            EgressRefusal::OpenEgressNotPermitted,
        ),
    ] {
        let (runtime, log) = runtime_for("fix6_new_ready");
        let before = log_lines(&log).len();
        let mut request = if open {
            create_open(EgressSettings::default())
        } else {
            let mut request = create_req();
            let policy = allowlist_policy();
            request.egress_policy = Some(policy.0);
            request.egress_policy_hash = Some(policy.1);
            request
        };
        request.egress_admission = admission;
        let err = runtime.create_bound(&request).expect_err("refused");
        assert!(matches!(err, crate::EffectError::NotIssued(_)), "{err:?}");
        assert_eq!(err.into_error().egress_refusal(), Some(reason));
        // Only the post-refusal, read-only existence observation that
        // classifies FAILED versus UNKNOWN may follow; nothing before it.
        let after = log_lines(&log);
        assert!(
            after[before..]
                .iter()
                .all(|line| line == "query --raw /1.0/instances/wssp-sbx-sbx-1?project=default"),
            "no host IO before the refusal: {:#?}",
            &after[before..]
        );
    }
}

/// §2.0.5: the start fence attests through the `GuardProbe` AFTER the
/// ACL/DNS readback and immediately before `start`; an unhealthy guard, a
/// lease that expired between the daemon's create check and the fence, or a
/// guard that never covers this bridge refuses NotIssued — nothing starts.
#[test]
fn the_start_fence_refuses_when_the_guard_probe_says_unhealthy() {
    let expired = {
        let mut status = FakeGuardProbe::healthy_status(&[]);
        status.lease_until_boottime_ns = 1;
        status.verified_boottime_ns = 0;
        status
    };
    for case in ["unhealthy", "lease_expired", "bridge_not_covered"] {
        let (mut runtime, log) = runtime_for("fix6_new_ready");
        let probe = FakeGuardProbe::healthy();
        match case {
            "unhealthy" => probe.set_healthy(false),
            "lease_expired" => probe.set_status(Some(expired.clone())),
            _ => probe.set_cover_all(false),
        }
        runtime.set_guard_probe(Arc::new(probe.clone()));
        runtime.set_guard_fence_wait(Duration::from_millis(100));
        // The daemon's early check passed (guard_ok was true a moment ago).
        let err = runtime
            .create_bound(&create_open(EgressSettings::default()))
            .expect_err("the fence refuses");
        let err = err.into_error();
        assert_eq!(
            err.egress_refusal(),
            Some(EgressRefusal::GuardUnavailable),
            "{case}: {err:?}"
        );
        assert_eq!(start_count(&log), 0, "{case}: nothing is started");
        assert!(probe.status_calls() > 0, "{case}: a fresh status was read");
        // The ACL/DNS readback preceded the attestation.
        let lines = log_lines(&log);
        assert!(
            lines.iter().any(|line| line.contains("-X PATCH")),
            "{case}: the resolver was published and read back first"
        );
    }
}

/// m15: the record is persisted with the gateway chosen under the allocation
/// lock and BEFORE the bridge exists.
#[test]
fn the_write_ahead_record_precedes_the_bridge() {
    let (mut runtime, log) = runtime_for("fix6_new_ready");
    let dir = statedir(&log);
    let barrier = Arc::new(std::sync::Barrier::new(2));
    runtime.client_mut().create_barrier = Some(("after_write_ahead", barrier.clone()));
    let (network, _) = sandbox_network_names("sbx-1");
    let observer = {
        let log = log.clone();
        let dir = dir.clone();
        let network = network.clone();
        std::thread::spawn(move || {
            barrier.wait();
            let record = record(&dir);
            let gateway = record["gateway"].as_str().unwrap().to_string();
            assert_eq!(record["mode"], "open");
            assert!(
                !log_lines(&log)
                    .iter()
                    .any(|line| line.contains(&format!("network create {network}"))),
                "no bridge exists yet"
            );
            barrier.wait();
            gateway
        })
    };
    runtime
        .create_bound(&create_open(EgressSettings::default()))
        .expect("create");
    let gateway = observer.join().expect("observer");
    let lines = log_lines(&log);
    let create = lines
        .iter()
        .find(|line| line.contains(&format!("network create {network}")))
        .unwrap();
    assert!(
        create.contains(&format!("ipv4.address={gateway}/24")),
        "the bridge uses the recorded gateway"
    );
}

/// m15 crash windows.
#[test]
fn write_ahead_crash_windows_fail_closed() {
    // (a) The PATCH never landed (crash between bridge create and the
    // resolver publication): the start fence's readback convicts the
    // bridge's raw.dnsmasq against the record's dnsmasq_base.
    let (runtime, log) = runtime_for("fix6_new_ready");
    let dir = statedir(&log);
    runtime
        .create_bound(&create_open(EgressSettings::default()))
        .expect("create");
    let (network, _) = sandbox_network_names("sbx-1");
    fs::write(
        dir.join("networks").join(format!("{network}.raw")),
        super::dns::base_dnsmasq_config(),
    )
    .unwrap();
    stop_vm(&dir);
    let starts = start_count(&log);
    let err = runtime
        .reconnect_bound(&reconnect(&open_policy(), EgressAdmission::PERMITTED))
        .expect_err("raw.dnsmasq differs from the record");
    assert_eq!(err.into_error().code, SandboxErrorCode::IdempotencyConflict);
    assert_eq!(start_count(&log), starts);

    // (b) A failed publication rolls the fresh apply back: no bridge, no
    // record survives, and the retry recompiles.
    let (runtime, log) = runtime_for("fix6_new_ready");
    let dir = statedir(&log);
    fs::write(dir.join("fail-raw-dnsmasq"), "").unwrap();
    runtime
        .create_bound(&create_open(EgressSettings::default()))
        .expect_err("publication fails");
    assert!(!dir.join("host-state/network-plans/sbx-1.json").exists());
    assert_eq!(start_count(&log), 0);
    fs::remove_file(dir.join("fail-raw-dnsmasq")).unwrap();
    runtime
        .create_bound(&create_open(EgressSettings::default()))
        .expect("the retry recompiles and publishes");

    // (c) The bridge exists but the record names another gateway: a retry
    // fails closed instead of rewriting the record.
    let (runtime, log) = runtime_for("fix6_new_ready");
    let dir = statedir(&log);
    runtime
        .create_bound(&create_open(EgressSettings::default()))
        .expect("create");
    let path = dir.join("host-state/network-plans/sbx-1.json");
    let mut body = record(&dir);
    body["gateway"] = serde_json::json!("10.254.254.1");
    fs::write(&path, body.to_string()).unwrap();
    let err = runtime
        .create_bound(&create_open(EgressSettings::default()))
        .expect_err("gateway mismatch");
    assert_eq!(err.into_error().code, SandboxErrorCode::IdempotencyConflict);
}

/// Drift on the new rule families is convicted before any start: a widened
/// `wssp-open`, a removed SMTP reject, an edited resolver.
#[test]
fn drift_on_the_open_rule_families_is_convicted() {
    for tamper in ["widen_open", "drop_smtp", "edit_resolver"] {
        let (runtime, log) = runtime_for("fix6_new_ready");
        let dir = statedir(&log);
        runtime
            .create_bound(&create_open(EgressSettings::default()))
            .expect("create");
        match tamper {
            "widen_open" => {
                let path = acl_egress_path(&dir);
                let rules = fs::read_to_string(&path).unwrap();
                let widened = rules.replacen("destination=1.0.0.0/8,", "destination=0.0.0.0/0,", 1);
                assert_ne!(rules, widened);
                fs::write(&path, widened).unwrap();
            }
            "drop_smtp" => {
                let path = acl_egress_path(&dir);
                let rules: String = fs::read_to_string(&path)
                    .unwrap()
                    .lines()
                    .filter(|line| !line.contains("wssp-smtp-reject"))
                    .map(|line| format!("{line}\n"))
                    .collect();
                fs::write(&path, rules).unwrap();
            }
            _ => {
                let (network, _) = sandbox_network_names("sbx-1");
                let path = dir.join("networks").join(format!("{network}.raw"));
                let body = fs::read_to_string(&path).unwrap();
                fs::write(&path, format!("{body}server=10.0.0.1\n")).unwrap();
            }
        }
        stop_vm(&dir);
        let starts = start_count(&log);
        let err = runtime
            .reconnect_bound(&reconnect(&open_policy(), EgressAdmission::PERMITTED))
            .expect_err("drift is convicted");
        assert_eq!(
            err.into_error().code,
            SandboxErrorCode::IdempotencyConflict,
            "{tamper}"
        );
        assert_eq!(start_count(&log), starts, "{tamper}");
    }
}

/// M19: an allowlist create with a blocked grant records it, never resolves
/// it, publishes the blocked `local=` line and the surviving grant only.
#[test]
fn allowlist_create_denies_blocked_grants_end_to_end() {
    let (mut runtime, log) = runtime_for("fix6_new_ready");
    let dir = statedir(&log);
    let asked = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let seen = asked.clone();
    runtime.override_resolver(Arc::new(move |domain, _wait| {
        seen.lock().unwrap().push(domain.to_string());
        Ok(vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            93, 184, 216, 34,
        ))])
    }));
    let policy = EgressPolicy {
        mode: EgressMode::Allowlist,
        domains: vec!["api.bad.example".into(), "good.example".into()],
        cidrs: Vec::new(),
    };
    let hash = policy_hash_hex(&policy);
    let mut request = create_req();
    request.egress_policy = Some(policy);
    request.egress_policy_hash = Some(hash);
    request.egress_settings = deny_settings();
    runtime.create_bound(&request).expect("create");
    let asked = asked.lock().unwrap().clone();
    assert!(asked.iter().all(|name| name == "good.example"), "{asked:?}");
    assert!(!asked.is_empty());
    let record = record(&dir);
    assert_eq!(
        record["denied_grants"],
        serde_json::json!(["api.bad.example"])
    );
    let raw = raw_dnsmasq(&dir);
    assert!(
        raw.contains("host-record=good.example,93.184.216.34"),
        "{raw}"
    );
    assert!(!raw.contains("bad.example,"), "{raw}");
    assert!(raw.contains("local=/bad.example/"), "{raw}");
}

fn fake_reconnect(
    policy: &(EgressPolicy, String),
    admission: EgressAdmission,
) -> crate::ReconnectSandboxRequest {
    let create = crate::CreateSandboxRequest::for_test("sbx-1", "create-1");
    crate::ReconnectSandboxRequest {
        template_fingerprint: create.template_digest,
        ..reconnect(policy, admission)
    }
}

/// Lane B e2e (FakeRuntime + executable shim, both modes): create → start →
/// warm reconnect → stop → cold reconnect. The compiled ACL each Incus
/// sandbox runs with keeps protected space dropped, rejects SMTP in BOTH
/// modes, and denies a blocked grant; the FakeRuntime applies the same
/// §1.5 table; and the start fence refuses whenever the `GuardProbe` says
/// the guard is unhealthy.
#[test]
fn lane_e2e_create_start_reconnect_in_both_modes() {
    use super::network::{Packet, plan_allows};
    let settings = deny_settings();
    let open = open_policy();
    let allowlist = {
        let policy = EgressPolicy {
            mode: EgressMode::Allowlist,
            domains: vec!["mail.example.com".into(), "api.bad.example".into()],
            cidrs: vec!["128.66.0.0/24".into()],
        };
        let hash = policy_hash_hex(&policy);
        (policy, hash)
    };
    let pkt = |destination: &str, port: u16| Packet {
        from_guest: true,
        established_reply: false,
        protocol: Some("tcp"),
        source: "10.0.0.50".parse().unwrap(),
        destination: destination.parse().unwrap(),
        source_port: Some(40000),
        destination_port: Some(port),
    };
    for (mode, policy) in [
        (EgressMode::Open, &open),
        (EgressMode::Allowlist, &allowlist),
    ] {
        // --- Incus runtime over the shim: the real compiler and verifier.
        let (mut runtime, log) = runtime_for("stopped");
        let dir = statedir(&log);
        runtime.override_resolver(Arc::new(|_domain, _wait| {
            Ok(vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                93, 184, 216, 34,
            ))])
        }));
        let probe = FakeGuardProbe::healthy();
        runtime.set_guard_probe(Arc::new(probe.clone()));
        runtime.set_guard_fence_wait(Duration::from_millis(100));
        let mut request = create_req();
        request.egress_policy = Some(policy.0.clone());
        request.egress_policy_hash = Some(policy.1.clone());
        request.egress_settings = settings.clone();
        runtime.create_bound(&request).expect("create + start");
        assert_eq!(start_count(&log), 1, "{mode:?}");
        let plan = runtime
            .client()
            .persisted_enforcement_plan_checked("sbx-1")
            .unwrap()
            .unwrap();
        assert_eq!(plan.mode, mode);
        // Protected drops (by the bridge default; no rule admits them).
        for protected in [
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.169.254",
            "168.63.129.16",
            "100.100.100.200",
            "100.64.0.7",
        ] {
            assert!(
                !plan_allows(&plan, &pkt(protected, 443)),
                "{mode:?} {protected}"
            );
        }
        // SMTP rejected in both modes, even to a granted address.
        assert!(!plan_allows(&plan, &pkt("128.66.0.9", 25)), "{mode:?}");
        assert!(!plan_allows(&plan, &pkt("93.184.216.34", 25)), "{mode:?}");
        assert!(
            plan.rules
                .iter()
                .any(|rule| rule.description == super::network::SMTP_REJECT_TAG),
            "{mode:?}"
        );
        match mode {
            EgressMode::Open => {
                assert!(plan_allows(&plan, &pkt("1.1.1.1", 443)));
                assert!(plan.denied_grants.is_empty());
            }
            EgressMode::Allowlist => {
                assert!(plan_allows(&plan, &pkt("128.66.0.9", 443)));
                assert!(plan_allows(&plan, &pkt("93.184.216.34", 443)));
                assert!(!plan_allows(&plan, &pkt("1.1.1.1", 443)));
                // Domain deny: recorded, never ruled, never published.
                assert_eq!(plan.denied_grants, vec!["api.bad.example".to_string()]);
                let tag = super::network::dns_tag_hex("api.bad.example");
                assert!(
                    plan.rules
                        .iter()
                        .all(|rule| !rule.description.contains(&tag))
                );
                assert!(!raw_dnsmasq(&dir).contains("api.bad.example,"));
            }
        }
        assert!(
            raw_dnsmasq(&dir).contains("local=/bad.example/"),
            "{mode:?}"
        );
        // Warm reconnect: never refused, even with the guard down.
        runtime
            .reconnect_bound(&reconnect(
                policy,
                EgressAdmission {
                    open_egress_permitted: false,
                    guard_ok: false,
                },
            ))
            .expect("warm reconnect");
        // Cold reconnect with the guard healthy: starts again.
        stop_restartable(&dir);
        runtime
            .reconnect_bound(&reconnect(policy, EgressAdmission::PERMITTED))
            .expect("cold reconnect");
        assert_eq!(start_count(&log), 2, "{mode:?}");
        // Guard goes unhealthy after the daemon's check: the start fence
        // refuses the cold start; nothing is started.
        stop_restartable(&dir);
        probe.set_healthy(false);
        let err = runtime
            .reconnect_bound(&reconnect(policy, EgressAdmission::PERMITTED))
            .expect_err("the start fence refuses");
        assert_eq!(
            err.into_error().egress_refusal(),
            Some(EgressRefusal::GuardUnavailable),
            "{mode:?}"
        );
        assert_eq!(start_count(&log), 2, "{mode:?}");

        // --- FakeRuntime: the same §1.5 table on the dispatch path.
        let fake = crate::FakeRuntime::new();
        let mut request = crate::CreateSandboxRequest::for_test("sbx-1", "create-1");
        request.egress_policy = Some(policy.0.clone());
        request.egress_policy_hash = Some(policy.1.clone());
        fake.guard().set_healthy(false);
        fake.create_fixture(&request)
            .expect_err("no guard, no create");
        fake.guard().set_healthy(true);
        fake.create_fixture(&request).expect("fake create");
        assert_eq!(fake.recorded_egress_mode("sbx-1"), Some(mode));
        fake.reconnect_fixture(&fake_reconnect(
            policy,
            EgressAdmission {
                open_egress_permitted: false,
                guard_ok: false,
            },
        ))
        .expect("warm fake reconnect is never refused");
        fake.stop_sandbox(&crate::StopSandboxRequest {
            template_fingerprint: request.template_digest.clone(),
            sandbox_id: "sbx-1".into(),
            instance_name: "wssp-sbx-sbx-1".into(),
            operation_id: "op-stop".into(),
            idempotency_key: "stop-1".into(),
        })
        .expect("stop");
        let consent_off = fake.reconnect_fixture(&fake_reconnect(
            policy,
            EgressAdmission {
                open_egress_permitted: false,
                guard_ok: true,
            },
        ));
        match mode {
            EgressMode::Open => assert_eq!(
                consent_off
                    .expect_err("refused")
                    .into_error()
                    .egress_refusal(),
                Some(EgressRefusal::OpenEgressNotPermitted)
            ),
            EgressMode::Allowlist => {
                consent_off.expect("consent never applies to allowlist");
                fake.stop_sandbox(&crate::StopSandboxRequest {
                    template_fingerprint: request.template_digest.clone(),
                    sandbox_id: "sbx-1".into(),
                    instance_name: "wssp-sbx-sbx-1".into(),
                    operation_id: "op-stop-2".into(),
                    idempotency_key: "stop-2".into(),
                })
                .expect("stop");
            }
        }
        fake.guard().set_healthy(false);
        assert_eq!(
            fake.reconnect_fixture(&fake_reconnect(policy, EgressAdmission::PERMITTED))
                .expect_err("cold fake reconnect with the guard down")
                .into_error()
                .egress_refusal(),
            Some(EgressRefusal::GuardUnavailable)
        );
        fake.guard().set_healthy(true);
        fake.reconnect_fixture(&fake_reconnect(policy, EgressAdmission::PERMITTED))
            .expect("cold fake reconnect");
    }
}

/// CLI logins proxy mode: an open create with a
/// proxied login records the one gateway allow, the runtime then names the
/// gateway to the proxy, and the record stays the drift reference: a warm
/// and a cold reconnect verify against it and never rewrite the ACL. A
/// create without one records no allow and has no proxy gateway.
#[test]
fn open_create_with_the_credential_proxy_records_the_gateway_allow() {
    let (runtime, log) = runtime_for("stopped");
    let dir = statedir(&log);
    assert!(runtime.supports_credential_proxy());
    assert_eq!(runtime.credential_proxy_endpoint("sbx-1"), None);
    // Not the default port: the endpoint is the sandbox's own record.
    let settings = EgressSettings {
        credential_proxy_port: Some(48123),
        ..EgressSettings::default()
    };
    runtime
        .create_bound(&create_open(settings.clone()))
        .expect("open create with the proxy");
    let egress = fs::read_to_string(acl_egress_path(&dir)).unwrap();
    assert!(
        egress.contains("description=wssp-credential-proxy"),
        "{egress}"
    );
    let plan = runtime
        .client()
        .persisted_enforcement_plan_checked("sbx-1")
        .unwrap()
        .unwrap();
    assert_eq!(plan.settings, Some(settings));
    // The recorded endpoint (gateway and port), so a daemon restart under
    // a changed `credential_proxy_port` re-binds where the guest points.
    assert_eq!(
        runtime.credential_proxy_endpoint("sbx-1"),
        Some(std::net::SocketAddrV4::new(plan.gateway, 48123))
    );
    let acl_before = fs::read_to_string(acl_egress_path(&dir)).unwrap();
    runtime
        .reconnect_bound(&reconnect(&open_policy(), EgressAdmission::PERMITTED))
        .expect("warm reconnect verifies the recorded proxy allow");
    stop_restartable(&dir);
    runtime
        .reconnect_bound(&reconnect(&open_policy(), EgressAdmission::PERMITTED))
        .expect("cold reconnect verifies the recorded proxy allow");
    assert_eq!(
        fs::read_to_string(acl_egress_path(&dir)).unwrap(),
        acl_before
    );
    assert_eq!(record(&dir)["settings"]["credential_proxy_port"], 48123);
    assert_eq!(
        runtime.credential_proxy_endpoint("sbx-1"),
        Some(std::net::SocketAddrV4::new(plan.gateway, 48123))
    );
}

#[test]
fn a_create_without_a_proxied_login_has_no_proxy_gateway() {
    let (runtime, log) = runtime_for("stopped");
    let dir = statedir(&log);
    runtime
        .create_bound(&create_open(EgressSettings::default()))
        .expect("open create");
    let egress = fs::read_to_string(acl_egress_path(&dir)).unwrap();
    assert!(!egress.contains("wssp-credential-proxy"), "{egress}");
    assert!(
        record(&dir)["settings"]
            .get("credential_proxy_port")
            .is_none()
    );
    assert_eq!(runtime.credential_proxy_endpoint("sbx-1"), None);
}

fn create_allowlist_build(refused_dns_hints: bool) -> crate::CreateSandboxRequest {
    let (policy, hash) = allowlist_policy();
    let mut request = create_req();
    request.egress_policy = Some(policy);
    request.egress_policy_hash = Some(hash);
    request.refused_dns_hints = refused_dns_hints;
    request
}

/// No resolver config ever carries a dnsmasq `log-*` option (its sink can
/// fall back to syslog or stall DNS).
fn assert_no_query_logging(raw: &str) {
    for option in ["log-queries", "log-facility", "log-async", "log-debug"] {
        assert!(!raw.contains(option), "{option}: {raw}");
    }
}

/// B12 on real hosts (coordinator ruling (c)): only a TEMPLATE_BUILD VM in
/// allowlist mode forwards non-granted names to the daemon's loopback DNS
/// stub (recorded in the plan's settings); a workload in allowlist mode and
/// a build in open mode get no stub. No resolver logs queries.
#[test]
fn only_allowlist_build_vms_forward_to_the_in_memory_dns_stub() {
    let (runtime, log) = runtime_for("stopped");
    let dir = statedir(&log);
    runtime
        .create_bound(&create_allowlist_build(true))
        .expect("allowlist build create");
    let settings: EgressSettings =
        serde_json::from_value(record(&dir)["settings"].clone()).unwrap();
    let port = settings.refused_dns_stub_port.expect("stub port recorded");
    assert_eq!(runtime.client().dns_stubs.port("sbx-1"), Some(port));
    let base = record(&dir)["dnsmasq_base"].as_str().unwrap().to_string();
    assert!(base.contains("no-resolv\n"), "{base}");
    assert!(
        base.contains(&format!("\nserver=127.0.0.1#{port}\n")),
        "{base}"
    );
    assert_eq!(base.matches("server=").count(), 1, "{base}");
    assert_no_query_logging(&base);
    assert_eq!(raw_dnsmasq(&dir), base);
    // Nothing reported yet; the drain is local and empty.
    assert!(runtime.drain_refused_dns_names().is_empty());
    assert!(runtime.refused_dns_hints_capability());

    for (mode, request) in [
        ("workload allowlist", create_allowlist_build(false)),
        ("open build", {
            let mut request = create_open(EgressSettings::default());
            request.refused_dns_hints = true;
            request
        }),
        ("open workload", create_open(EgressSettings::default())),
    ] {
        let (runtime, log) = runtime_for("stopped");
        let dir = statedir(&log);
        runtime.create_bound(&request).expect(mode);
        assert!(
            record(&dir)["settings"]
                .get("refused_dns_stub_port")
                .is_none(),
            "{mode}"
        );
        assert_eq!(runtime.client().dns_stubs.port("sbx-1"), None, "{mode}");
        let raw = raw_dnsmasq(&dir);
        assert!(!raw.contains("127.0.0.1"), "{mode}: {raw}");
        assert_no_query_logging(&raw);
    }
}

/// A stub port in the settings of an open-mode compile is refused: no
/// caller-supplied settings can give an open resolver the stub, and the
/// create path strips any supplied port before deciding.
#[test]
fn an_open_build_never_gets_a_stub_even_from_supplied_settings() {
    let (runtime, log) = runtime_for("stopped");
    let dir = statedir(&log);
    let mut request = create_open(EgressSettings {
        refused_dns_stub_port: Some(5353),
        ..EgressSettings::default()
    });
    request.refused_dns_hints = true;
    runtime.create_bound(&request).expect("open build create");
    assert!(
        record(&dir)["settings"]
            .get("refused_dns_stub_port")
            .is_none()
    );
    assert!(!raw_dnsmasq(&dir).contains("127.0.0.1"));

    let (runtime, log) = runtime_for("stopped");
    let dir = statedir(&log);
    let mut request = create_allowlist_build(false);
    request.egress_settings.refused_dns_stub_port = Some(5353);
    runtime.create_bound(&request).expect("workload create");
    assert!(
        record(&dir)["settings"]
            .get("refused_dns_stub_port")
            .is_none()
    );
    assert!(!raw_dnsmasq(&dir).contains("127.0.0.1"));
}

/// A restarted daemon (its stubs stopped with it) re-binds the recorded port
/// on its first drain; teardown stops the stub and retires the record.
#[test]
fn the_dns_stub_is_rebound_after_restart_and_released_on_teardown() {
    let (runtime, _log) = runtime_for("stopped");
    runtime
        .create_bound(&create_allowlist_build(true))
        .expect("allowlist build create");
    let port = runtime.client().dns_stubs.port("sbx-1").expect("stub runs");
    // Restart: the old process's stubs are gone.
    runtime.client().dns_stubs.release("sbx-1");
    let recorded = runtime.client().recorded_dns_stubs();
    assert_eq!(recorded.len(), 1);
    assert_eq!(
        (recorded[0].sandbox_id.as_str(), recorded[0].port),
        ("sbx-1", port)
    );
    assert!(runtime.drain_refused_dns_names().is_empty());
    assert!(runtime.wait_hint_maintenance(), "the stubs recover");
    assert_eq!(runtime.client().dns_stubs.port("sbx-1"), Some(port));

    runtime
        .client()
        .teardown_sandbox_network("sbx-1")
        .expect("teardown");
    assert_eq!(runtime.client().dns_stubs.port("sbx-1"), None);
    assert!(runtime.client().recorded_dns_stubs().is_empty());
}

/// After a restart the re-bound stub knows the recorded granted names, so a
/// lookup of a granted domain is never reported as a refusal.
#[test]
fn the_rebound_dns_stub_keeps_the_recorded_granted_names() {
    let (mut runtime, _log) = runtime_for("stopped");
    runtime.override_resolver(Arc::new(|_domain, _wait| {
        Ok(vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            93, 184, 216, 34,
        ))])
    }));
    let policy = EgressPolicy {
        mode: EgressMode::Allowlist,
        domains: vec!["pypi.org".into()],
        cidrs: Vec::new(),
    };
    let hash = policy_hash_hex(&policy);
    let mut request = create_allowlist_build(true);
    request.egress_policy = Some(policy);
    request.egress_policy_hash = Some(hash);
    runtime
        .create_bound(&request)
        .expect("allowlist build create");
    let port = runtime.client().dns_stubs.port("sbx-1").expect("stub runs");
    // Restart: the old process's stubs are gone.
    runtime.client().dns_stubs.release("sbx-1");
    let recorded = runtime.client().recorded_dns_stubs();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].port, port);
    assert_eq!(
        recorded[0].granted.iter().collect::<Vec<_>>(),
        vec!["pypi.org"]
    );
    assert!(runtime.drain_refused_dns_names().is_empty());
    assert!(runtime.wait_hint_maintenance(), "the stubs recover");
    assert_eq!(runtime.client().dns_stubs.port("sbx-1"), Some(port));
}

/// Run one hint drain on another thread: how long it took, or `None` when
/// it did not return within `limit` (it is then left running).
fn timed_drain(runtime: &Arc<super::IncusKvmRuntime>, limit: Duration) -> Option<Duration> {
    let (tx, rx) = std::sync::mpsc::channel();
    let runtime = runtime.clone();
    std::thread::spawn(move || {
        let began = std::time::Instant::now();
        runtime.drain_refused_dns_names();
        let _ = tx.send(began.elapsed());
    });
    rx.recv_timeout(limit).ok()
}

/// A restarted daemon whose build stub must be re-bound, with the recorded
/// stubs' read made slow by `delay`.
fn restarted_with_slow_recovery(delay: Duration) -> (super::IncusKvmRuntime, u16) {
    let (runtime, _log) = runtime_for("stopped");
    runtime
        .create_bound(&create_allowlist_build(true))
        .expect("allowlist build create");
    let port = runtime.client().dns_stubs.port("sbx-1").expect("stub runs");
    // Restart: the old process's stubs are gone.
    runtime.client().dns_stubs.release("sbx-1");
    *runtime
        .client()
        .dns_stubs
        .slow_recorded
        .delay
        .lock()
        .unwrap() = Some(delay);
    (runtime, port)
}

/// The hint drain is the only hint work on the socket thread, which must
/// keep reading control frames (an `egress.blocklist` applies at once) while
/// the stub recovery runs: a slow read of the recorded stubs never delays
/// the drain, because the recovery runs on the maintenance worker.
#[test]
fn a_slow_stub_recovery_never_delays_the_hint_drain_or_the_blocklist_behind_it() {
    let (runtime, port) = restarted_with_slow_recovery(Duration::from_secs(3));
    let runtime = Arc::new(runtime);
    let took = timed_drain(&runtime, Duration::from_secs(10)).expect("the drain returns");
    assert!(
        took < Duration::from_millis(500),
        "the drain waited {took:?} for the stub recovery"
    );
    let hook = &runtime.client().dns_stubs.slow_recorded;
    // The drain only starts the worker; wait (bounded) for it to be scheduled.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !hook.entered.load(std::sync::atomic::Ordering::SeqCst) {
        assert!(
            std::time::Instant::now() < deadline,
            "the worker reads the recorded stubs"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        runtime.client().dns_stubs.port("sbx-1"),
        None,
        "still in flight"
    );
    // A second drain while the worker is busy neither waits nor starts another.
    let took = timed_drain(&runtime, Duration::from_secs(10)).expect("the drain returns");
    assert!(took < Duration::from_millis(500), "{took:?}");
    assert!(runtime.wait_hint_maintenance(), "the stubs recover");
    assert_eq!(runtime.client().dns_stubs.port("sbx-1"), Some(port));
    assert!(!hook.cancelled.load(std::sync::atomic::Ordering::SeqCst));
}

/// The maintenance worker is cancellable: dropping the runtime while the
/// recovery is in flight revokes the worker's permit and joins the worker
/// promptly.
#[test]
fn dropping_the_runtime_cancels_an_in_flight_stub_recovery() {
    let (runtime, _port) = restarted_with_slow_recovery(Duration::from_secs(60));
    let stubs = runtime.client().dns_stubs.clone();
    assert!(runtime.drain_refused_dns_names().is_empty());
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !stubs
        .slow_recorded
        .entered
        .load(std::sync::atomic::Ordering::SeqCst)
    {
        assert!(std::time::Instant::now() < deadline, "the recovery started");
        std::thread::sleep(Duration::from_millis(10));
    }
    std::thread::sleep(Duration::from_millis(200));
    let began = std::time::Instant::now();
    drop(runtime);
    assert!(
        began.elapsed() < Duration::from_secs(15),
        "the drop waited {:?}",
        began.elapsed()
    );
    // Joined, not detached: the worker saw the revoked permit before the
    // drop returned.
    assert!(
        stubs
            .slow_recorded
            .cancelled
            .load(std::sync::atomic::Ordering::SeqCst),
        "the in-flight read was preempted by the revoked permit"
    );
}

/// The FIFO-era query-log migration is gone (DD-3): a leftover plan record
/// whose settings carry `refused_dns_log`, in either record version, is
/// unavailable evidence (`EgressSettings` refuses unknown fields), never a
/// silently weaker reference.
#[test]
fn a_leftover_fifo_era_plan_record_fails_closed() {
    let (runtime, log) = runtime_for("stopped");
    let dir = statedir(&log);
    runtime
        .create_bound(&create_allowlist_build(true))
        .expect("allowlist build create");
    let path = dir.join("host-state/network-plans/sbx-1.json");
    let mut legacy = record(&dir);
    let settings = legacy["settings"].as_object_mut().unwrap();
    settings.remove("refused_dns_stub_port").unwrap();
    settings.insert(
        "refused_dns_log".into(),
        "/var/lib/wssp/dns-query-logs/sbx-1.fifo".into(),
    );
    for version in [None, Some(2)] {
        let mut forged = legacy.clone();
        match version {
            None => drop(forged.as_object_mut().unwrap().remove("version")),
            Some(version) => forged["version"] = version.into(),
        }
        fs::write(&path, forged.to_string()).unwrap();
        assert!(
            runtime
                .client()
                .persisted_enforcement_plan_checked("sbx-1")
                .is_err(),
            "{forged}"
        );
    }
}
