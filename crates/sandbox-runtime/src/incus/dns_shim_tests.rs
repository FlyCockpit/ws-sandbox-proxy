//! C36 executable-shim tests for DNS-aware egress: host-resolved, validated,
//! TTL-clamped domain grants with fail-closed publish ordering. The fake
//! `incus` binary records argv and stores network/ACL state; the fake DNS
//! transport scripts wire answers. No VM, no real DNS.

use std::collections::BTreeSet;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

use sandbox_protocol::{EgressPolicy, SandboxErrorCode};

use super::client::IncusClient;
use super::dns::{FakeDnsOutcome, FakeDnsRecord, FakeDnsTransport, unix_now};
use super::network::{
    dns_lease_fence_tag, dns_rule_tag, policy_hash_hex, sandbox_network_names, test_plan,
};
use super::shim_tests::{DnsTestClock, client_for_with_log};
use crate::r#trait::SandboxRuntime;

// These historical fault histories include accepted, deferred per-rule daemon
// requests. Keep exercising their upgrade recovery even when a phase is clean.
fn runtime_for(mode: &str) -> (super::kvm::IncusKvmRuntime, std::path::PathBuf) {
    let (mut runtime, log) = super::shim_tests::runtime_for(mode);
    runtime.client_mut().force_legacy_dns_recovery = true;
    (runtime, log)
}

fn legacy_client(binary: impl Into<String>, project: impl Into<String>) -> IncusClient {
    let mut client = IncusClient::new(binary, project);
    client.force_legacy_dns_recovery = true;
    client
}

const SERVER: Ipv4Addr = Ipv4Addr::new(128, 66, 2, 53);

fn servers() -> Vec<Ipv4Addr> {
    vec![SERVER]
}

fn domain_policy(domains: &[&str], cidrs: &[&str]) -> (EgressPolicy, String) {
    let policy = EgressPolicy {
        mode: sandbox_protocol::EgressMode::Allowlist,
        domains: domains.iter().map(|d| d.to_string()).collect(),
        cidrs: cidrs.iter().map(|c| c.to_string()).collect(),
    };
    let hash = policy_hash_hex(&policy);
    (policy, hash)
}

/// A client whose sandbox network+ACL were applied (deny-all plan).
fn applied_client(mode: &str, sandbox_id: &str) -> (IncusClient, std::path::PathBuf) {
    let (mut client, log) = client_for_with_log(mode);
    // These cases reproduce pre-batching request histories, including late
    // identity-specific daemon requests that remain recoverable after upgrade.
    client.force_legacy_dns_recovery = true;
    client
        .apply_sandbox_network(&test_plan(sandbox_id))
        .expect("apply");
    (client, log)
}

/// Re-key the plan record the fixture apply persisted to THIS policy hash:
/// refresh fences the supplied policy against the recorded binding
/// (network-plans/<id>.json) before resolving or mutating.
fn bind_recorded_policy(log: &Path, sandbox_id: &str, hash: &str) {
    let path = log
        .parent()
        .expect("statedir")
        .join("host-state/network-plans")
        .join(format!("{sandbox_id}.json"));
    let mut parsed: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).expect("plan record")).expect("parse");
    parsed["hash"] = serde_json::Value::String(hash.to_string());
    fs::write(&path, parsed.to_string()).expect("rebind");
}

fn log_lines(log: &Path) -> Vec<String> {
    fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
}

fn raw_dnsmasq(log: &Path, network: &str) -> String {
    let path = log
        .parent()
        .expect("statedir")
        .join("networks")
        .join(format!("{network}.raw"));
    fs::read_to_string(path).unwrap_or_default()
}

fn acl_egress(log: &Path, acl: &str) -> String {
    let path = log
        .parent()
        .expect("statedir")
        .join("acls")
        .join(format!("{acl}.egress"));
    fs::read_to_string(path).unwrap_or_default()
}

/// Land accepted daemon requests at a controlled point in a fault history.
fn apply_queued_acl_adds(statedir: &Path) -> usize {
    let client = legacy_client(statedir.join("incus").to_str().unwrap(), "default");
    let queued: Vec<_> = fs::read_dir(statedir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("queued-add-")
        })
        .collect();
    assert!(!queued.is_empty(), "an accepted request must be queued");
    for path in &queued {
        let body = fs::read_to_string(path).unwrap();
        let mut lines = body.lines();
        let target = Path::new(lines.next().expect("queued ACL target"));
        let acl = target.file_stem().unwrap().to_str().unwrap();
        let direction = target.extension().unwrap().to_str().unwrap();
        let mut args = vec!["network", "acl", "rule", "add", acl, direction];
        args.extend(lines);
        let result = client.run(&args, false).expect("land the queued request");
        assert_eq!(result.exit_code, 0, "{result:?}");
        fs::remove_file(path).unwrap();
    }
    queued.len()
}

/// The DNS publication log line: a stdin-bodied config PATCH (argv could
/// never carry an in-bound publication past MAX_ARG_STRLEN).
fn is_dns_publish(line: &str, network: &str) -> bool {
    line.contains("query")
        && line.contains("PATCH")
        && line.contains(&format!("/1.0/networks/{network}"))
}

fn refresh(
    client: &IncusClient,
    sandbox_id: &str,
    policy: &EgressPolicy,
    hash: &str,
    transport: &dyn super::dns::DnsTransport,
) -> Result<crate::DnsRefreshOutcome, crate::RuntimeError> {
    client.refresh_sandbox_dns_policy(sandbox_id, policy, hash, transport, &servers())
}

/// Script logical transport latency before each answer, using the same
/// clock as the refresh and lease code. No real TTL wait is involved.
struct LogicalDnsTransport<'a> {
    inner: &'a FakeDnsTransport,
    clock: &'a DnsTestClock,
    delays: std::sync::Mutex<std::collections::VecDeque<u64>>,
}

impl super::dns::DnsTransport for LogicalDnsTransport<'_> {
    fn query(&self, server: Ipv4Addr, message: &[u8]) -> std::io::Result<Vec<u8>> {
        let seconds = self.delays.lock().unwrap().pop_front().unwrap_or(0);
        self.clock.advance(seconds);
        super::dns::DnsTransport::query(self.inner, server, message)
    }
}

/// A client whose sandbox network+ACL were applied from a plan compiled with
/// the given static CIDR grants (no domains).
fn applied_client_with_cidrs(
    mode: &str,
    sandbox_id: &str,
    cidrs: &[&str],
) -> (IncusClient, std::path::PathBuf) {
    let (mut client, log) = client_for_with_log(mode);
    client.force_legacy_dns_recovery = true;
    let (policy, hash) = domain_policy(&[], cidrs);
    let mut plan = super::network::compile_network_plan(
        sandbox_id,
        Some(&policy),
        Some(&hash),
        &|_domain, _wait| panic!("cidr-only plan must not resolve domains"),
        Ipv4Addr::new(10, 9, 9, 1),
        &super::network::CompileLimits {
            deadline: std::time::Instant::now() + super::network::COMPILE_BUDGET,
            cancelled: None,
        },
    )
    .expect("plan compiles");
    plan.binding = test_plan(sandbox_id).binding;
    client.apply_sandbox_network(&plan).expect("apply");
    (client, log)
}

#[test]
fn refresh_publishes_only_allowlisted_answers_after_replacing_rules() {
    let (mut client, log) = applied_client_with_cidrs("running", "sbx-1", &["128.66.0.0/24"]);
    let clock = DnsTestClock::install(&mut client);
    let answered_at = clock.now();
    fs::write(log.parent().unwrap().join("slow-publish"), "1").unwrap();
    let (network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &["128.66.0.0/24"]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            60,
        )])],
    );
    let outcome = refresh(&client, "sbx-1", &policy, &hash, &transport).expect("refresh");
    assert_eq!(outcome.published_names, 1);
    assert!(
        outcome.denied_names.is_empty(),
        "{:?}",
        outcome.denied_names
    );
    // The PATCH consumes exactly one second of logical lifetime.
    assert_eq!(outcome.refresh_after, Duration::from_secs(59));
    assert_eq!(clock.now(), answered_at + 1);

    // Ordering: every ACL mutation precedes the dnsmasq publish — rules are
    // replaced BEFORE answers become usable.
    let lines = log_lines(&log);
    let last_acl = lines
        .iter()
        .rposition(|line| line.contains("network acl rule"))
        .expect("acl mutation");
    let publish = lines
        .iter()
        .rposition(|line| is_dns_publish(line, &network))
        .expect("publish");
    assert!(last_acl < publish, "{}", lines.join("\n"));

    // The published policy serves exactly the allowlisted name, with no
    // upstream resolvers and no wildcard directive: its only `server=` line
    // sends the name's subdomains to the (absent) default servers.
    let raw = raw_dnsmasq(&log, &network);
    assert!(raw.contains("no-resolv\n"), "{raw}");
    assert!(
        raw.contains("host-record=grants.example.com,128.66.0.7\n"),
        "{raw}"
    );
    assert!(
        raw.contains("local=/grants.example.com/\nserver=/*.grants.example.com/#\n"),
        "{raw}"
    );
    assert_eq!(raw.matches("server=").count(), 1, "{raw}");
    assert!(!raw.contains("address="), "{raw}");

    // The ACL gained the per-name tagged rule; static grant and
    // infrastructure rules are untouched. (C36 r26 F1: the first
    // issuance now allocates a durable identity — generation 1.)
    let egress = acl_egress(&log, &acl);
    let tag = dns_rule_tag("grants.example.com", 1);
    assert!(
        egress.contains(&format!("destination=128.66.0.7/32 description={tag}")),
        "{egress}"
    );
    assert!(
        egress.contains("destination=128.66.0.0/24 description=wssp-grant"),
        "{egress}"
    );
    // The bridge DNS access rules survive the refresh (they are
    // infrastructure, not dynamic); the refreshed destination is covered by
    // the static CIDR grant, so no DNS/DoT reject companions are added.
    for infra in ["wssp-dns-udp", "wssp-dns-tcp"] {
        assert!(
            egress.contains(&format!("description={infra}")),
            "{infra} removed: {egress}"
        );
    }
    assert_eq!(
        egress.matches(&format!("description={tag}")).count(),
        1,
        "exactly one dynamic grant rule: {egress}"
    );
    assert!(
        !egress.contains("description=wssp-dns-reject-"),
        "static-CIDR-covered destination keeps DNS/DoT: {egress}"
    );

    // State is durable under the host state dir and drives readback
    // verification of the published config.
    let state = client
        .state_dir
        .as_ref()
        .expect("state dir")
        .join("dns-policy")
        .join("sbx-1.json");
    let body = fs::read_to_string(state).expect("dns state persisted");
    assert!(body.contains("grants.example.com"), "{body}");
    assert_eq!(
        client.expected_dnsmasq_config("sbx-1"),
        raw,
        "readback expectation is the persisted published config"
    );
    // A steady-state refresh is idempotent: same answers, no rule churn.
    let before = log_lines(&log).len();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            60,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("steady refresh");
    let window = &log_lines(&log)[before..];
    assert!(
        !window.iter().any(|line| line.contains("network acl rule")),
        "no rule churn on an unchanged answer: {}",
        window.join("\n")
    );
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn refresh_rotation_expires_old_addresses_before_new_answers() {
    let (client, log) = applied_client("running", "sbx-1");
    let (network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            60,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("first refresh");
    let before = log_lines(&log).len();

    // DNS rotates: the old answer must leave the ACL (rule remove) BEFORE
    // the new one is added and BEFORE the new answers are published.
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 9),
            60,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("second refresh");
    let lines = log_lines(&log);
    let window = &lines[before..];
    let remove = window
        .iter()
        .position(|line| line.contains("network acl rule remove") && line.contains("128.66.0.7/32"))
        .unwrap_or_else(|| panic!("old rule removed: {}", window.join("\n")));
    let add = window
        .iter()
        .position(|line| line.contains("network acl rule add") && line.contains("128.66.0.9/32"))
        .unwrap_or_else(|| panic!("new rule added: {}", window.join("\n")));
    // The DNS/DoT reject companions install BEFORE the unrestricted allow:
    // an interrupted install can never leave the allow without them.
    let first_add = window
        .iter()
        .find(|line| line.contains("network acl rule add") && line.contains("128.66.0.9/32"))
        .expect("first add for the new address");
    assert!(
        first_add.contains("action=reject"),
        "rejects land before the allow: {first_add}"
    );
    let publish = window
        .iter()
        .position(|line| is_dns_publish(line, &network))
        .expect("publish");
    assert!(remove < add, "shrink before grow: {}", window.join("\n"));
    assert!(add < publish, "rules before answers: {}", window.join("\n"));

    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "old address expired: {egress}"
    );
    assert!(egress.contains("128.66.0.9/32"), "{egress}");
    // No static CIDR covers the rotated address: its DNS/DoT reject
    // companions rotated with it.
    assert!(
        egress.contains("action=reject") && egress.contains("destination_port=853"),
        "reject companions follow the grant: {egress}"
    );
    // The bridge DNS access rules are infrastructure, not dynamic: both
    // survive every refresh, including the removal path.
    for infra in ["wssp-dns-udp", "wssp-dns-tcp"] {
        assert!(
            egress.contains(&format!("description={infra}")),
            "{infra} removed by refresh: {egress}"
        );
    }
    let raw = raw_dnsmasq(&log, &network);
    assert!(!raw.contains("128.66.0.7"), "old answer unpublished: {raw}");
    assert!(
        raw.contains("host-record=grants.example.com,128.66.0.9"),
        "{raw}"
    );
}

#[test]
fn empty_lookup_denies_and_removes_the_grant_immediately() {
    let (client, log) = applied_client("running", "sbx-1");
    let (network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("first refresh");
    assert!(acl_egress(&log, &acl).contains("128.66.0.7/32"));

    // NXDOMAIN: the grant is removed now, not at TTL expiry.
    transport.script("grants.example.com", [FakeDnsOutcome::Rcode(3)]);
    let outcome = refresh(&client, "sbx-1", &policy, &hash, &transport).expect("refresh");
    assert_eq!(outcome.published_names, 0);
    assert_eq!(outcome.denied_names, vec!["grants.example.com".to_string()]);
    assert!(
        !acl_egress(&log, &acl).contains("128.66.0.7"),
        "grant removed"
    );
    let raw = raw_dnsmasq(&log, &network);
    assert!(!raw.contains("host-record="), "no answers published: {raw}");
    assert!(raw.contains("no-resolv"), "{raw}");
}

#[test]
fn transient_resolver_failure_keeps_the_unexpired_grant() {
    let (client, log) = applied_client("running", "sbx-1");
    let (network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("first refresh");
    let before = log_lines(&log).len();

    transport.script("grants.example.com", [FakeDnsOutcome::TransportError]);
    let outcome = refresh(&client, "sbx-1", &policy, &hash, &transport).expect("refresh");
    assert_eq!(
        outcome.published_names, 1,
        "prior grant survives a transient failure"
    );
    let window = &log_lines(&log)[before..];
    assert!(
        !window
            .iter()
            .any(|line| line.contains("network acl rule remove")),
        "an unexpired grant is not removed: {}",
        window.join("\n")
    );
    assert!(acl_egress(&log, &acl).contains("128.66.0.7/32"));
    assert!(raw_dnsmasq(&log, &network).contains("host-record=grants.example.com"));
}

#[test]
fn publish_failure_aborts_after_rules_change_and_persists_nothing() {
    let (client, log) = applied_client("running", "sbx-1");
    let (network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            60,
        )])],
    );
    let statedir = log.parent().expect("statedir");
    fs::write(statedir.join("fail-raw-dnsmasq"), "").unwrap();
    let err = refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect_err("publish failure surfaces");
    assert_ne!(err.code, SandboxErrorCode::ProtocolError);
    // The ACL was updated (rules before answers) but no answers became
    // usable and no state claims otherwise: deny-direction everywhere.
    assert!(acl_egress(&log, &acl).contains("128.66.0.7/32"));
    assert!(
        !raw_dnsmasq(&log, &network).contains("host-record="),
        "answers never published"
    );
    let state = client
        .state_dir
        .as_ref()
        .expect("state dir")
        .join("dns-policy")
        .join("sbx-1.json");
    assert!(!state.exists(), "nothing persisted");
    // Recovery: the next refresh converges.
    fs::remove_file(statedir.join("fail-raw-dnsmasq")).unwrap();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            60,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("retry");
    assert!(raw_dnsmasq(&log, &network).contains("host-record=grants.example.com"));
    assert!(state.exists());
}

#[test]
fn acl_failure_mid_refresh_leaves_answers_unpublished() {
    let (client, log) = applied_client("running", "sbx-1");
    let (network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("first refresh");

    // Rotation with the rule ADD pinned to fail: the stale rule is removed
    // (shrink), the new rule never lands, and the new answer is never
    // published. The published (.7) answer then has NO rule: fail-closed.
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 9),
            60,
        )])],
    );
    let statedir = log.parent().expect("statedir");
    fs::write(statedir.join("fail-acl-rule-add"), "").unwrap();
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect_err("add fails");
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "stale rule removed first: {egress}"
    );
    assert!(
        !egress.contains("128.66.0.9"),
        "new rule never added: {egress}"
    );
    let raw = raw_dnsmasq(&log, &network);
    assert!(
        raw.contains("128.66.0.7"),
        "answers unchanged (guest can resolve but cannot connect): {raw}"
    );
    assert!(!raw.contains("128.66.0.9"), "{raw}");
}

#[test]
fn refresh_is_fenced_against_foreign_networks() {
    let (client, log) = applied_client("running", "sbx-1");
    let (network, _) = sandbox_network_names("sbx-1");
    let statedir = log.parent().expect("statedir");
    let conf_path = statedir.join("networks").join(format!("{network}.conf"));
    let conf = fs::read_to_string(&conf_path).unwrap();
    fs::write(
        &conf_path,
        conf.replace(
            "user.wssp.sandbox_id=sbx-1",
            "user.wssp.sandbox_id=sbx-OTHER",
        ),
    )
    .unwrap();
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            60,
        )])],
    );
    let before = log_lines(&log).len();
    let err =
        refresh(&client, "sbx-1", &policy, &hash, &transport).expect_err("foreign network refused");
    assert_eq!(err.code, SandboxErrorCode::IdempotencyConflict);
    let lines = log_lines(&log);
    let window = &lines[before..];
    assert!(
        !window.iter().any(|line| is_dns_publish(line, &network)),
        "never publishes onto a foreign network: {}",
        window.join("\n")
    );
    assert!(
        !window.iter().any(|line| line.contains("network acl rule")),
        "never mutates rules: {}",
        window.join("\n")
    );
}

#[test]
fn a_rebound_protected_address_is_never_installed() {
    let (client, log) = applied_client("running", "sbx-1");
    let (network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![
            FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 7), 60),
            // Rebinding: a private address among public ones.
            FakeDnsRecord::A(Ipv4Addr::new(10, 9, 8, 7), 60),
        ])],
    );
    let outcome = refresh(&client, "sbx-1", &policy, &hash, &transport).expect("refresh");
    assert_eq!(outcome.published_names, 0, "the whole name denies");
    assert_eq!(outcome.denied_names, vec!["grants.example.com".to_string()]);
    let egress = acl_egress(&log, &acl);
    assert!(!egress.contains("10.9.8.7"), "no rule installed: {egress}");
    assert!(
        !egress.contains("128.66.0.7"),
        "not even the public half: {egress}"
    );
    let raw = raw_dnsmasq(&log, &network);
    assert!(!raw.contains("host-record="), "no answer published: {raw}");
}

#[test]
fn concurrent_refreshes_cannot_broaden_another_sandboxs_policy() {
    let (client, log) = applied_client("running", "sbx-a");
    client
        .apply_sandbox_network(&test_plan("sbx-b"))
        .expect("apply sbx-b");
    let (network_a, acl_a) = sandbox_network_names("sbx-a");
    let (network_b, acl_b) = sandbox_network_names("sbx-b");
    let (policy_a, hash_a) = domain_policy(&["a.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-a", &hash_a);
    let (policy_b, hash_b) = domain_policy(&["b.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-b", &hash_b);
    let transport = std::sync::Arc::new(FakeDnsTransport::new());
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            60,
        )])],
    );
    transport.script(
        "b.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 1, 7),
            60,
        )])],
    );
    // Both refreshes rendezvous inside resolution: they provably overlap.
    transport.set_barrier(std::sync::Arc::new(std::sync::Barrier::new(2)));
    std::thread::scope(|scope| {
        let a = scope.spawn(|| {
            refresh(&client, "sbx-a", &policy_a, &hash_a, transport.as_ref()).expect("refresh A")
        });
        let b = scope.spawn(|| {
            refresh(&client, "sbx-b", &policy_b, &hash_b, transport.as_ref()).expect("refresh B")
        });
        a.join().expect("A");
        b.join().expect("B");
    });
    let raw_a = raw_dnsmasq(&log, &network_a);
    let raw_b = raw_dnsmasq(&log, &network_b);
    assert!(
        raw_a.contains("host-record=a.example.com,128.66.0.7"),
        "{raw_a}"
    );
    assert!(!raw_a.contains("b.example.com"), "{raw_a}");
    assert!(
        raw_b.contains("host-record=b.example.com,128.66.1.7"),
        "{raw_b}"
    );
    assert!(!raw_b.contains("a.example.com"), "{raw_b}");
    let egress_a = acl_egress(&log, &acl_a);
    let egress_b = acl_egress(&log, &acl_b);
    assert!(egress_a.contains("128.66.0.7/32"), "{egress_a}");
    assert!(!egress_a.contains("128.66.1.7"), "{egress_a}");
    assert!(egress_b.contains("128.66.1.7/32"), "{egress_b}");
    assert!(!egress_b.contains("128.66.0.7"), "{egress_b}");
}

#[test]
fn refresh_refuses_a_missing_sandbox_network() {
    let (client, _log) = client_for_with_log("running");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    let transport = FakeDnsTransport::new();
    let err = refresh(&client, "sbx-1", &policy, &hash, &transport).expect_err("absent network");
    assert_eq!(err.code, SandboxErrorCode::SandboxNotFound);
}

#[test]
fn create_publishes_initial_answers_and_allowlisted_only_dns() {
    let (mut runtime, log) = runtime_for("fix6_new_ready");
    runtime.override_resolver(std::sync::Arc::new(|_domain, _wait| {
        Ok(vec![std::net::IpAddr::V4(Ipv4Addr::new(128, 66, 0, 10))])
    }));
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    let mut request = super::shim_tests::create_req();
    request.egress_policy = Some(policy);
    request.egress_policy_hash = Some(hash);
    runtime.create_bound(&request).expect("create");
    let (network, _acl) = sandbox_network_names("sbx-1");
    let lines = log_lines(&log);
    // First boot: the bridge resolver has no upstream resolvers (deny-all
    // base), created atomically with the network.
    let create = lines
        .iter()
        .find(|line| line.contains(&format!("network create {network}")))
        .expect("network create");
    assert!(create.contains("raw.dnsmasq="), "{create}");
    assert!(create.contains("no-resolv"), "{create}");
    // The compiled domain grant is published as an exact host-record AFTER
    // its ACL rule exists.
    let tag = dns_rule_tag("grants.example.com", 1);
    let rule = lines
        .iter()
        .position(|line| line.contains("network acl rule add") && line.contains(&tag))
        .expect("dns grant rule");
    let publish = lines
        .iter()
        .position(|line| is_dns_publish(line, &network))
        .expect("initial publish");
    assert!(rule < publish, "rules before answers: {}", lines.join("\n"));
    let raw = raw_dnsmasq(&log, &network);
    assert!(
        raw.contains("host-record=grants.example.com,128.66.0.10\n"),
        "{raw}"
    );
    assert!(raw.contains("no-resolv"), "{raw}");
}

#[test]
fn reconnect_after_a_committed_refresh_verifies() {
    // Create (persists the network plan) -> refresh PARTIALLY rotates the
    // answers (one address of one domain out of two multi-address domains)
    // -> reconnect with the SAME recorded policy. Refresh retains unchanged
    // rules in place and appends new ones, so the live order diverges from
    // name/address order; the persisted plan must carry the AS-INSTALLED
    // order or the positional reconnect readback rejects a healthy ACL.
    let (mut runtime, log) = runtime_for("fix6_new_ready");
    runtime.override_resolver(std::sync::Arc::new(|domain, _wait| {
        let answers: &[&str] = match domain {
            "a.example.com" => &["128.66.0.10", "128.66.0.11"],
            _ => &["128.66.1.10", "128.66.1.11"],
        };
        Ok(answers
            .iter()
            .map(|text| std::net::IpAddr::V4(text.parse().unwrap()))
            .collect())
    }));
    let (policy, hash) = domain_policy(&["a.example.com", "b.example.com"], &[]);
    let mut request = super::shim_tests::create_req();
    request.egress_policy = Some(policy.clone());
    request.egress_policy_hash = Some(hash.clone());
    runtime.create_bound(&request).expect("create");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let egress = acl_egress(&log, &acl);
    assert!(egress.contains("128.66.0.10/32"), "{egress}");
    assert!(egress.contains("128.66.1.10/32"), "{egress}");

    // Refresh through a second client over the same daemon and host state:
    // domain A drops .10 and gains .20; B is untouched (rules retained in
    // place, so live order is B's rules before A's new ones).
    let statedir = log.parent().expect("log parent").to_path_buf();
    let mut client = legacy_client(
        statedir.join("incus").to_string_lossy().into_owned(),
        "default".to_string(),
    );
    client.host_routes = Some(Vec::new());
    client.state_dir = Some(statedir.join("host-state"));
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![
            FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 11), 60),
            FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 20), 60),
        ])],
    );
    transport.script(
        "b.example.com",
        [FakeDnsOutcome::Answer(vec![
            FakeDnsRecord::A(Ipv4Addr::new(128, 66, 1, 10), 60),
            FakeDnsRecord::A(Ipv4Addr::new(128, 66, 1, 11), 60),
        ])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("partial rotation");
    let egress = acl_egress(&log, &acl);
    assert!(egress.contains("128.66.0.20/32"), "{egress}");
    assert!(!egress.contains("128.66.0.10"), "{egress}");
    assert!(egress.contains("128.66.1.10/32"), "{egress}");

    // The persisted plan carries the installed rule set IN OBSERVED ORDER.
    let rules = client
        .persisted_plan_rules("sbx-1", &hash)
        .expect("persisted plan");
    let destinations: Vec<&str> = rules
        .iter()
        .filter_map(|rule| rule.destination.as_deref())
        .collect();
    for kept in [
        "128.66.0.11/32",
        "128.66.0.20/32",
        "128.66.1.10/32",
        "128.66.1.11/32",
    ] {
        assert!(destinations.contains(&kept), "persisted plan tracks {kept}");
    }
    assert!(
        !destinations.contains(&"128.66.0.10/32"),
        "stale address left the persisted plan"
    );
    // B's untouched rules retain their positions ahead of A's appended
    // replacement rules — the live ACL's actual order.
    let pos = |needle: &str| {
        destinations
            .iter()
            .position(|dest| *dest == needle)
            .expect(needle)
    };
    assert!(
        pos("128.66.1.10/32") < pos("128.66.0.20/32"),
        "persisted order is the observed order: {destinations:?}"
    );
    // ...so reconnect verifies instead of entering rollback.
    runtime
        .reconnect_bound(&crate::ReconnectSandboxRequest {
            vm_size: sandbox_protocol::VmSize::defaults().unwrap(),
            lease: sandbox_protocol::HostLease::for_test(),
            template_fingerprint: super::shim_tests::create_req().template_digest,
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
        .expect("reconnect after a committed refresh verifies");
}

#[test]
fn exhausted_resolver_budget_still_removes_expired_grants() {
    // The resolution budget is gone (every lookup would fail): the refresh
    // must STILL drop expired grants from the ACL and unpublish them, never
    // abort with stale destinations installed.
    let (client, log) = applied_client("running", "sbx-1");
    let (network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("first refresh");
    assert!(acl_egress(&log, &acl).contains("128.66.0.7/32"));

    // The committed grant has since expired (operator-visible clock move,
    // or a long-partitioned node daemon): rewrite the durable state with a
    // past expiry, as crash recovery would find it.
    let statedir = log.parent().expect("log parent").to_path_buf();
    let state_path = statedir.join("host-state/dns-policy/sbx-1.json");
    let mut state: super::dns::SandboxDnsState =
        serde_json::from_str(&fs::read_to_string(&state_path).expect("state")).expect("decode");
    for grant in &mut state.grants {
        grant.expires_at = 1; // long past
    }
    client.persist_dns_state(&state).expect("expire the grant");

    let queries_before = transport.queries().len();
    let outcome = client
        .refresh_sandbox_dns_policy_with_budget(
            "sbx-1",
            &policy,
            &hash,
            &transport,
            &servers(),
            std::time::Duration::ZERO,
        )
        .expect("budget exhaustion still applies expiry cleanup");
    assert_eq!(outcome.published_names, 0);
    assert_eq!(outcome.denied_names, vec!["grants.example.com".to_string()]);
    assert_eq!(
        transport.queries().len(),
        queries_before,
        "no lookup ran on an exhausted budget"
    );
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "expired grant removed despite the exhausted budget: {egress}"
    );
    for infra in ["wssp-dns-udp", "wssp-dns-tcp"] {
        assert!(
            egress.contains(&format!("description={infra}")),
            "{infra} survives: {egress}"
        );
    }
    let raw = raw_dnsmasq(&log, &network);
    assert!(
        !raw.contains("128.66.0.7"),
        "expired answer unpublished: {raw}"
    );
    assert!(!raw.contains("host-record="), "no answers remain: {raw}");
    assert!(raw.contains("no-resolv"), "{raw}");
    // The persisted expectation tracks the publication: readback verifies.
    assert_eq!(client.expected_dnsmasq_config("sbx-1"), raw);
}

#[test]
fn interrupted_install_never_leaves_an_allow_without_its_rejects() {
    // The allow rule lands only after its DNS/DoT reject companions: an
    // interruption at the allow leaves the address resolver-blocked and
    // unpublished (deny direction), and a retry completes the install.
    let (client, log) = applied_client("running", "sbx-1");
    let (network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            60,
        )])],
    );
    let statedir = log.parent().expect("log parent").to_path_buf();
    fs::write(statedir.join("fail-acl-rule-add-allow"), "").unwrap();
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect_err("allow add fails");

    // Every rule add attempted BEFORE the allow was a reject; the allow
    // attempt came last and failed, so no answers were published and nothing
    // was persisted.
    let adds: Vec<String> = log_lines(&log)
        .into_iter()
        .filter(|line| line.contains("network acl rule add") && line.contains("128.66.0.7"))
        .collect();
    assert_eq!(
        adds.len(),
        5,
        "three rejects, the fence, then the allow: {adds:?}"
    );
    assert!(
        adds[..3].iter().all(|line| line.contains("action=reject")),
        "rejects install first: {adds:?}"
    );
    assert!(
        adds[3].contains("action=reject") && adds[3].contains("wssp-dns-quarantine-"),
        "the preventive fence precedes the allow: {adds:?}"
    );
    assert!(adds[4].contains("action=allow"), "{adds:?}");
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("action=allow destination=128.66.0.7/32"),
        "no unrestricted allow without its rejects: {egress}"
    );
    assert!(
        !raw_dnsmasq(&log, &network).contains("128.66.0.7"),
        "answers never published"
    );
    assert!(
        !statedir.join("host-state/dns-policy/sbx-1.json").exists(),
        "nothing persisted"
    );

    // Recovery: remove the failure; the retry adds only the missing allow.
    fs::remove_file(statedir.join("fail-acl-rule-add-allow")).unwrap();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            60,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("retry completes");
    let egress = acl_egress(&log, &acl);
    assert!(
        egress.contains("action=allow destination=128.66.0.7/32"),
        "{egress}"
    );
    assert!(
        raw_dnsmasq(&log, &network).contains("host-record=grants.example.com,128.66.0.7\n"),
        "published after the full rule set exists"
    );
}

/// Tamper one installed DNS reject companion in the daemon state, then prove
/// a no-op refresh REPAIRS it (remove + re-add) instead of ratifying it.
fn assert_reject_repair(tamper: impl FnOnce(String) -> String, marker: &str) {
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            60,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("first refresh");
    let egress_path = log
        .parent()
        .expect("log parent")
        .join("acls")
        .join(format!("{acl}.egress"));
    let body = fs::read_to_string(&egress_path).expect("egress");
    assert!(body.contains("destination_port=853"), "{body}");
    fs::write(&egress_path, tamper(body)).expect("tamper");

    // Same answers: a set-identity diff would see "the rule" present and
    // skip it; the effective readback must see the tampered rule as absent.
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            60,
        )])],
    );
    let before = log_lines(&log).len();
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("refresh repairs");
    let window = &log_lines(&log)[before..];
    assert!(
        window
            .iter()
            .any(|line| line.contains("network acl rule remove")
                && line.contains("destination_port=853")),
        "tampered rule removed: {}",
        window.join("\n")
    );
    assert!(
        window
            .iter()
            .any(|line| line.contains("network acl rule add")
                && line.contains("destination_port=853")),
        "planned rule re-added: {}",
        window.join("\n")
    );
    let egress = acl_egress(&log, &acl);
    assert!(!egress.contains(marker), "tamper repaired: {egress}");
}

#[test]
fn refresh_refuses_to_ratify_duplicate_dynamic_rules() {
    // A duplicated dynamic rule (operator error) is corruption, not an
    // idempotent success: the refresh refuses rather than ratifying a
    // multiplicity the model cannot represent.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            60,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("first refresh");
    let egress_path = log
        .parent()
        .expect("log parent")
        .join("acls")
        .join(format!("{acl}.egress"));
    let body = fs::read_to_string(&egress_path).expect("egress");
    let line = body
        .lines()
        .find(|line| line.contains("destination_port=853"))
        .expect("reject line")
        .to_string();
    fs::write(&egress_path, format!("{body}{line}\n")).expect("duplicate");
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            60,
        )])],
    );
    let err = refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect_err("duplicate dynamic rules refuse");
    assert_eq!(err.code, SandboxErrorCode::Internal);
}

#[test]
fn refresh_repairs_a_disabled_dns_reject_before_publishing() {
    assert_reject_repair(
        |body| {
            body.replacen(
                "destination_port=853 description=",
                "destination_port=853 state=disabled description=",
                1,
            )
        },
        "state=disabled",
    );
}

#[test]
fn refresh_repairs_a_source_restricted_dns_reject_before_publishing() {
    assert_reject_repair(
        |body| {
            body.replacen(
                "destination_port=853 description=",
                "destination_port=853 source=10.9.9.9/32 description=",
                1,
            )
        },
        "source=10.9.9.9/32",
    );
}

#[test]
fn reconnect_racing_a_refresh_revalidates_under_the_sandbox_lock() {
    // The reconnect plan snapshot is read BEFORE the sandbox lock is taken;
    // a refresh committing in between must not let the stale snapshot reject
    // the healthy refreshed ACL into rollback. The apply re-reads the
    // persisted rule set under the lock.
    let (mut runtime, log) = runtime_for("fix6_new_ready");
    runtime.override_resolver(std::sync::Arc::new(|_domain, _wait| {
        Ok(vec![std::net::IpAddr::V4(Ipv4Addr::new(128, 66, 0, 10))])
    }));
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    let mut request = super::shim_tests::create_req();
    request.egress_policy = Some(policy.clone());
    request.egress_policy_hash = Some(hash.clone());
    runtime.create_bound(&request).expect("create");
    let (_network, acl) = sandbox_network_names("sbx-1");

    // Refresh thread: shares the runtime client's lock registry (clone), so
    // it holds the sandbox lock while parked inside the resolver barrier.
    let client = runtime.client().clone();
    let transport = std::sync::Arc::new(FakeDnsTransport::new());
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    transport.set_barrier(barrier.clone());
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 20),
            60,
        )])],
    );
    let refresh_policy = policy.clone();
    let refresh_hash = hash.clone();
    let refresh_transport = transport.clone();
    let refresh_thread = std::thread::spawn(move || {
        client.refresh_sandbox_dns_policy(
            "sbx-1",
            &refresh_policy,
            &refresh_hash,
            refresh_transport.as_ref(),
            &servers(),
        )
    });
    // The refresh now holds the sandbox lock, parked in its first query.
    std::thread::sleep(std::time::Duration::from_millis(400));
    // Release the refresh (A query, then the AAAA query) only after the
    // reconnect below has read its pre-lock snapshot: the tripper arrives
    // late, so the reconnect's snapshot is provably stale when it blocks on
    // the lock.
    let tripper = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(500));
        barrier.wait();
        std::thread::sleep(std::time::Duration::from_millis(200));
        barrier.wait();
    });
    let reconnect = runtime.reconnect_bound(&crate::ReconnectSandboxRequest {
        vm_size: sandbox_protocol::VmSize::defaults().unwrap(),
        lease: sandbox_protocol::HostLease::for_test(),
        template_fingerprint: super::shim_tests::create_req().template_digest,
        architecture: Some("x86_64".into()),
        guest: Default::default(),
        sandbox_id: "sbx-1".to_string(),
        instance_name: "wssp-sbx-sbx-1".to_string(),
        operation_id: "op-race".to_string(),
        idempotency_key: "race-1".to_string(),
        egress_policy: Some(policy),
        egress_policy_hash: Some(hash),
        egress_admission: crate::egress::EgressAdmission::PERMITTED,
        guest_sudo: false,
    });
    refresh_thread
        .join()
        .expect("refresh thread")
        .expect("refresh commits");
    tripper.join().expect("tripper");
    reconnect.expect("stale snapshot must not reject the refreshed ACL");
    let egress = acl_egress(&log, &acl);
    assert!(
        egress.contains("128.66.0.20/32"),
        "the refreshed rules survive: {egress}"
    );
}

#[test]
fn refresh_with_a_different_policy_changes_nothing() {
    // The supplied policy must be the sandbox's RECORDED policy: a refresh
    // carrying a different one (here: a covering CIDR that would exempt the
    // recorded grant address from its DNS/DoT rejects) is refused UNDER the
    // sandbox lock BEFORE any resolution or mutation.
    let (mut runtime, log) = runtime_for("fix6_new_ready");
    runtime.override_resolver(std::sync::Arc::new(|_domain, _wait| {
        Ok(vec![std::net::IpAddr::V4(Ipv4Addr::new(128, 66, 0, 7))])
    }));
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    let mut request = super::shim_tests::create_req();
    request.egress_policy = Some(policy);
    request.egress_policy_hash = Some(hash.clone());
    runtime.create_bound(&request).expect("create");
    let (network, acl) = sandbox_network_names("sbx-1");
    let before_log = log_lines(&log).len();
    let before_acl = acl_egress(&log, &acl);
    let before_raw = raw_dnsmasq(&log, &network);

    let (other, other_hash) = domain_policy(&["grants.example.com"], &["128.66.0.0/24"]);
    let client = runtime.client().clone();
    let transport = FakeDnsTransport::new();
    let err = refresh(&client, "sbx-1", &other, &other_hash, &transport)
        .expect_err("a mismatched policy is refused");
    assert_eq!(err.code, SandboxErrorCode::IdempotencyConflict);
    // Zero queries, zero mutations, zero persistence drift.
    assert!(
        transport.queries().is_empty(),
        "the fence fires before resolution: {:?}",
        transport.queries()
    );
    let window = &log_lines(&log)[before_log..];
    assert!(
        !window.iter().any(|line| line.contains("network acl rule")
            || line.contains("network set")
            || line.contains("network delete")),
        "zero mutations: {}",
        window.join("\n")
    );
    assert_eq!(acl_egress(&log, &acl), before_acl, "ACL untouched");
    assert_eq!(raw_dnsmasq(&log, &network), before_raw, "DNS untouched");
    assert_eq!(
        client.recorded_policy_hash("sbx-1").flatten().as_deref(),
        Some(hash.as_str()),
        "the recorded binding is still the original policy"
    );
    assert!(
        client.persisted_plan_rules("sbx-1", &hash).is_some(),
        "the recorded rule set survived"
    );
}

#[test]
fn refresh_never_ratifies_an_injected_static_allow() {
    // An unrestricted allow with a NON-dynamic description injected into the
    // live ACL is drift against the recorded plan: the refresh refuses
    // BEFORE mutating and never persists it as authoritative.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            60,
        )])],
    );
    let egress_path = log
        .parent()
        .expect("log parent")
        .join("acls")
        .join(format!("{acl}.egress"));
    let body = fs::read_to_string(&egress_path).expect("egress");
    fs::write(
        &egress_path,
        format!("{body}action=allow description=operator-added\n"),
    )
    .expect("inject");

    let before_log = log_lines(&log).len();
    let err = refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect_err("static drift refuses the refresh");
    assert_eq!(err.code, SandboxErrorCode::Internal);
    let window = &log_lines(&log)[before_log..];
    assert!(
        !window
            .iter()
            .any(|line| line.contains("network acl rule") || line.contains("network set")),
        "zero mutations: {}",
        window.join("\n")
    );
    let recorded = client
        .persisted_plan_rules("sbx-1", &hash)
        .expect("recorded plan");
    assert!(
        recorded
            .iter()
            .all(|rule| rule.description != "operator-added"),
        "the injected rule never became authoritative"
    );
    assert!(
        !log.parent()
            .expect("statedir")
            .join("host-state/dns-policy/sbx-1.json")
            .exists(),
        "nothing was published or persisted"
    );
}

#[test]
fn refresh_never_ratifies_static_rules_with_a_malformed_recorded_plan() {
    // A plan record with a VALID sandbox id/hash but an UNDECODABLE `rules`
    // field must not pass the fence with the recorded-static comparison
    // silently disabled: an injected unrestricted static allow would
    // otherwise survive and be persisted as authoritative reconnect state.
    // The refresh refuses BEFORE any resolution or mutation.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            60,
        )])],
    );
    // Corrupt the recorded plan's rules field (valid id/hash, junk rules).
    let plan_path = log
        .parent()
        .expect("statedir")
        .join("host-state/network-plans")
        .join("sbx-1.json");
    let mut parsed: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&plan_path).expect("plan record")).expect("parse");
    parsed["rules"] = serde_json::Value::String("undecodable".to_string());
    fs::write(&plan_path, parsed.to_string()).expect("corrupt");
    assert!(client.persisted_plan_rules("sbx-1", &hash).is_none());
    // Inject an unrestricted static allow (the drift the comparison catches).
    let egress_path = log
        .parent()
        .expect("log parent")
        .join("acls")
        .join(format!("{acl}.egress"));
    let body = fs::read_to_string(&egress_path).expect("egress");
    fs::write(
        &egress_path,
        format!("{body}action=allow description=operator-added\n"),
    )
    .expect("inject");

    let before_log = log_lines(&log).len();
    let err = refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect_err("an undecodable recorded plan refuses the refresh");
    // A malformed plan cannot supply a trusted policy binding.
    assert_eq!(err.code, SandboxErrorCode::IdempotencyConflict);
    let window = &log_lines(&log)[before_log..];
    assert!(
        !window
            .iter()
            .any(|line| line.contains("network acl rule") || line.contains("network set")),
        "zero mutations: {}",
        window.join("\n")
    );
    assert!(
        transport.queries().is_empty(),
        "refused before resolution: {:?}",
        transport.queries()
    );
    // No persistence: the corrupted record is untouched, nothing published.
    assert!(
        fs::read_to_string(&plan_path)
            .expect("plan record")
            .contains("undecodable"),
        "the malformed record was not ratified over"
    );
    assert!(
        !log.parent()
            .expect("statedir")
            .join("host-state/dns-policy/sbx-1.json")
            .exists(),
        "nothing was published or persisted"
    );
}

#[test]
fn interrupted_revocation_is_never_restored_by_a_transient_retry() {
    // Grant installed → the name goes NXDOMAIN → the refresh removes the
    // ACL rules but publication FAILS, leaving the OLD persisted grant in
    // place. A durable revocation marker (written before any mutation) must
    // keep a later TRANSIENT failure — even after a restart — from
    // retaining and reinstalling the denied grant without a new successful
    // resolution.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            60,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("first refresh grants");
    let statedir = log.parent().expect("statedir").to_path_buf();
    assert!(
        acl_egress(&log, &acl).contains("action=allow destination=128.66.0.7/32"),
        "grant installed"
    );
    // The name vanishes (NXDOMAIN) and publication fails: rules are removed,
    // the OLD state with the grant survives, the marker is durable.
    transport.script("grants.example.com", [FakeDnsOutcome::Rcode(3)]);
    fs::write(statedir.join("fail-raw-dnsmasq"), "").unwrap();
    let err = refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect_err("publication failure aborts the refresh");
    assert_eq!(err.code, SandboxErrorCode::Internal);
    assert!(
        !acl_egress(&log, &acl).contains("128.66.0.7"),
        "rules removed before publication: {}",
        acl_egress(&log, &acl)
    );
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    let marker = fs::read_to_string(&marker_path).expect("durable revocation marker");
    assert!(marker.contains("grants.example.com"), "{marker}");
    let old_state = fs::read_to_string(statedir.join("host-state/dns-policy/sbx-1.json"))
        .expect("old state survives");
    assert!(old_state.contains("128.66.0.7"), "{old_state}");
    // RESTART: a fresh client over the same host state.
    let mut restarted = legacy_client(client.binary.clone(), "default".to_string());
    restarted.state_dir = Some(statedir.join("host-state"));
    // Transient failure on the retry: WITHOUT the marker, plan_refresh would
    // retain the old grant and REINSTALL its allow rules.
    fs::remove_file(statedir.join("fail-raw-dnsmasq")).unwrap();
    transport.script("grants.example.com", [FakeDnsOutcome::TransportError]);
    let before = log_lines(&log).len();
    refresh(&restarted, "sbx-1", &policy, &hash, &transport).expect("retry completes, denied");
    let window = &log_lines(&log)[before..];
    assert!(
        !window
            .iter()
            .any(|line| line.contains("network acl rule add") && line.contains("128.66.0.7")),
        "the revoked grant is never reinstalled without resolution: {}",
        window.join("\n")
    );
    assert!(
        !acl_egress(&log, &acl).contains("128.66.0.7"),
        "denial stands: {}",
        acl_egress(&log, &acl)
    );
    // The retry committed a state without the grant; the marker is spent.
    let new_state = fs::read_to_string(statedir.join("host-state/dns-policy/sbx-1.json"))
        .expect("new state persisted");
    assert!(!new_state.contains("128.66.0.7"), "{new_state}");
    assert!(!marker_path.exists(), "marker cleared after commit");
}

#[test]
fn reconnect_refuses_readiness_while_a_revocation_is_pending() {
    // Crash window: the refresh persists the revocation marker and dies
    // BEFORE the first ACL mutation — old ACL + publication + persisted
    // plan still AGREE, but the grant was denied. A restart's reconnect
    // (apply/readiness verification, NOT another refresh) must refuse.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            60,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("first refresh grants");
    let statedir = log.parent().expect("statedir").to_path_buf();
    // The name goes NXDOMAIN; the FIRST rule removal fails: the marker is
    // durable, the ACL still carries the (denied) allow.
    transport.script("grants.example.com", [FakeDnsOutcome::Rcode(3)]);
    fs::write(statedir.join("fail-acl-rule-remove"), "").unwrap();
    let err = refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect_err("removal failure aborts the refresh");
    assert_eq!(err.code, SandboxErrorCode::Internal);
    assert!(
        acl_egress(&log, &acl).contains("action=allow destination=128.66.0.7/32"),
        "ACL untouched — the stale grant is still installed"
    );
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    assert!(marker_path.exists(), "durable revocation marker");
    // RESTART + recovery/readiness verification (NOT another refresh): the
    // pending marker must refuse the Ready gate.
    let mut restarted = legacy_client(client.binary.clone(), "default".to_string());
    restarted.state_dir = Some(statedir.join("host-state"));
    let err = restarted
        .verify_provisioned_enforcement("sbx-1")
        .expect_err("pending revocation refuses readiness");
    // C58 NEW-1 (D-1): an owed revocation still refuses readiness, but as
    // INCONCLUSIVE (retryable, never cleanup-triggering), not drift.
    assert_eq!(err.code, SandboxErrorCode::Internal);
    assert!(err.is_enforcement_inconclusive(), "{err:?}");
    assert!(marker_path.exists(), "refusal keeps the marker pending");
    // Recovery: a refresh COMMITS the denial (clears the marker), then the
    // readiness gate verifies again.
    fs::remove_file(statedir.join("fail-acl-rule-remove")).unwrap();
    transport.script("grants.example.com", [FakeDnsOutcome::Rcode(3)]);
    refresh(&restarted, "sbx-1", &policy, &hash, &transport).expect("denial commits");
    assert!(!marker_path.exists(), "marker cleared after commit");
    restarted
        .verify_provisioned_enforcement("sbx-1")
        .expect("readiness verifies once the denial is committed");
}

#[test]
fn teardown_preserves_unresolved_dns_mutations() {
    // C36 r22 F2: an interrupted refresh's revocation marker SURVIVES
    // teardown — its pending-mutation journal is the only record
    // protecting a future same-named ACL incarnation from a deferred
    // daemon-side apply. The plan and DNS state records still retire
    // with the sandbox.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, _acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            60,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("first refresh grants");
    let statedir = log.parent().expect("statedir").to_path_buf();
    transport.script("grants.example.com", [FakeDnsOutcome::Rcode(3)]);
    fs::write(statedir.join("fail-acl-rule-remove"), "").unwrap();
    refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect_err("interrupted refresh leaves the marker");
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    assert!(marker_path.exists(), "marker pending before teardown");
    client
        .teardown_sandbox_network("sbx-1")
        .expect("teardown succeeds");
    assert!(
        marker_path.exists(),
        "unresolved mutations survive teardown for the next incarnation"
    );
    assert!(
        !statedir.join("host-state/dns-policy/sbx-1.json").exists(),
        "dns state retired"
    );
    assert!(
        !statedir
            .join("host-state/network-plans/sbx-1.json")
            .exists(),
        "plan retired"
    );
}

#[test]
fn grants_expiring_during_acl_work_are_never_published_or_retained() {
    // Planning captures expiries BEFORE the ACL work; with thousands of
    // sequential Incus calls that work can outlast a grant's safe
    // publication window. The expiry is rechecked after enforcement: the
    // lapsed grant is revoked (never published, never persisted, rules
    // removed), and the returned delay is measured at ACTUAL completion.
    let (mut client, log) = applied_client("running", "sbx-1");
    let clock = DnsTestClock::install(&mut client);
    let answered_at = clock.now();
    let (network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com", "slow.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            35, // above the churn floor: the ~8s of ACL work lapses its safe window
        )])],
    );
    transport.script(
        "slow.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            60,
        )])],
    );
    let statedir = log.parent().expect("statedir").to_path_buf();
    // Delay ADDITIONS, REMOVALS and PUBLICATION (one second each): expiry
    // rechecks must hold after every enforcement pass and around the PATCH.
    fs::write(statedir.join("slow-acl-ops"), "1").unwrap();
    fs::write(statedir.join("slow-acl-removals"), "1").unwrap();
    fs::write(statedir.join("slow-publish"), "10").unwrap();
    let outcome = refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("refresh completes with the lapsed grant revoked");
    assert!(
        outcome
            .denied_names
            .iter()
            .any(|name| name == "grants.example.com"),
        "lapsed grant reported denied: {:?}",
        outcome.denied_names
    );
    assert_eq!(outcome.published_names, 1, "only the surviving grant");
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "lapsed grant's rules removed: {egress}"
    );
    assert!(
        egress.contains("action=allow destination=128.66.0.8/32"),
        "surviving grant installed: {egress}"
    );
    let raw = raw_dnsmasq(&log, &network);
    assert!(
        !raw.contains("grants.example.com"),
        "never published: {raw}"
    );
    assert!(
        raw.contains("host-record=slow.example.com,128.66.0.8\n"),
        "{raw}"
    );
    let state = fs::read_to_string(statedir.join("host-state/dns-policy/sbx-1.json"))
        .expect("state persisted");
    assert!(
        !state.contains("\"name\":\"grants.example.com\""),
        "not retained: {state}"
    );
    assert!(state.contains("slow.example.com"), "{state}");
    // Completed ACL work and the PATCH advance the same clock used at
    // answer receipt, expiry rechecks and final completion.
    let elapsed = clock.now() - answered_at;
    assert!(
        elapsed > 5 && elapsed < 30,
        "the short grant lapses its publication window while the survivor stays live: {elapsed}"
    );
    assert_eq!(outcome.refresh_after, Duration::from_secs(60 - elapsed));
    assert!(
        !statedir
            .join("host-state/dns-revocations/sbx-1.json")
            .exists(),
        "marker cleared after commit"
    );
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn successive_interrupted_refreshes_keep_the_full_revocation_set() {
    // The revocation marker is the UNION of every uncommitted denial: a
    // retry that denies nothing but fails again BEFORE committing must not
    // erase an earlier pending revocation — otherwise a later transient
    // failure retains the denied grant from the stale persisted state and
    // REINSTALLS it.
    let (client, log) = applied_client("running", "sbx-1");
    let (network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            60,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("first refresh grants");
    let statedir = log.parent().expect("statedir").to_path_buf();
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    // First interruption: NXDOMAIN revokes the grant (rules removed), but
    // PUBLICATION fails — marker holds the denial, state still lists .7.
    transport.script("grants.example.com", [FakeDnsOutcome::Rcode(3)]);
    fs::write(statedir.join("fail-raw-dnsmasq"), "").unwrap();
    refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect_err("publication failure interrupts the refresh");
    assert!(marker_path.exists(), "first revocation pending");
    assert!(
        !acl_egress(&log, &acl).contains("128.66.0.7"),
        "revoked rules removed"
    );
    // RESTART, second interruption: the name resolves a NEW address; this
    // retry denies nothing, yet publication fails again. The earlier
    // revocation must survive (union, not overwrite).
    let mut restarted = legacy_client(client.binary.clone(), "default".to_string());
    restarted.state_dir = Some(statedir.join("host-state"));
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 9),
            60,
        )])],
    );
    refresh(&restarted, "sbx-1", &policy, &hash, &transport)
        .expect_err("the second interruption also fails before commit");
    let marker = fs::read_to_string(&marker_path).expect("marker still pending");
    assert!(
        marker.contains("grants.example.com"),
        "the earlier revocation survives a denial-free interrupted retry: {marker}"
    );
    // A later TRANSIENT failure: the stale state still lists the grant, but
    // the pending revocation excludes it — it is denied, never reinstalled,
    // and the uncommitted .9 from the failed retry is withdrawn.
    fs::remove_file(statedir.join("fail-raw-dnsmasq")).unwrap();
    transport.script("grants.example.com", [FakeDnsOutcome::TransportError]);
    let before = log_lines(&log).len();
    refresh(&restarted, "sbx-1", &policy, &hash, &transport)
        .expect("transient failure completes with the denial");
    let window = &log_lines(&log)[before..];
    assert!(
        !window
            .iter()
            .any(|line| { line.contains("network acl rule add") && !line.contains("quarantine-") }),
        "no rule is ever reinstalled for the revoked name (an autonomous \
         denial FENCE of either family is enforcement, not reinstallation — \
         C36 r32 F1 records the uncommitted identity, so the watcher may \
         fence the denied destination concurrently): {}",
        window.join("\n")
    );
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "the revoked grant is never reinstalled: {egress}"
    );
    // The uncommitted .9 identity is withdrawn — by the refresh or by the
    // autonomous denial boundary (which blind-fences first and releases
    // once the withdrawal evidence is durable); poll to convergence.
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let egress = acl_egress(&log, &acl);
        if !egress.contains("128.66.0.9") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the uncommitted retry's rules are withdrawn: {egress}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    assert!(
        !raw_dnsmasq(&log, &network).contains("grants.example.com"),
        "not published"
    );
    let state = fs::read_to_string(statedir.join("host-state/dns-policy/sbx-1.json"))
        .expect("state persisted");
    assert!(
        !state.contains("\"name\":\"grants.example.com\""),
        "not retained: {state}"
    );
    assert!(!marker_path.exists(), "marker cleared after commit");
    // C36 r25 F5: revocation retirement is POST-COMMIT ONLY. Re-grant
    // the name, revoke it with a publication failure (marker holds the
    // denial, stale state still lists .7), then run a re-grant refresh
    // that PUBLISHES .9 but cannot persist the commit: the revocation
    // evidence must survive the interruption — pruning it pre-commit
    // would let a later transient retry retain and reinstall the denied
    // .7 from the stale state.
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            60,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the re-grant commits");
    transport.script("grants.example.com", [FakeDnsOutcome::Rcode(3)]);
    fs::write(statedir.join("fail-raw-dnsmasq"), "").unwrap();
    refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect_err("the revocation's publication failure interrupts the refresh");
    assert!(marker_path.exists(), "the second revocation is pending");
    fs::remove_file(statedir.join("fail-raw-dnsmasq")).unwrap();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 9),
            60,
        )])],
    );
    // The commit's state write fails (the dns-policy directory is
    // read-only) AFTER publication succeeds.
    let policy_dir = statedir.join("host-state/dns-policy");
    let metadata = fs::metadata(&policy_dir).expect("dir");
    let mut readonly = metadata.permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        readonly.set_mode(0o555);
        fs::set_permissions(&policy_dir, readonly.clone()).expect("readonly");
    }
    let interrupted = refresh(&client, "sbx-1", &policy, &hash, &transport);
    #[cfg(unix)]
    {
        let mut restore = readonly;
        use std::os::unix::fs::PermissionsExt;
        restore.set_mode(0o755);
        fs::set_permissions(&policy_dir, restore).expect("restore");
    }
    interrupted.expect_err("the commit fails after publication");
    let marker = fs::read_to_string(&marker_path).expect("marker survives the interruption");
    assert!(
        marker.contains("grants.example.com"),
        "revocation evidence survives a post-publication interruption: {marker}"
    );
    let state = fs::read_to_string(policy_dir.join("sbx-1.json")).expect("stale state persists");
    assert!(
        state.contains("128.66.0.7"),
        "the interrupted commit left the OLD state in place: {state}"
    );
    // A transient retry retains nothing: the surviving revocation
    // filters the stale grant out of the prior state, and the
    // uncommitted .9 broadening is withdrawn — .7 is never reinstalled.
    transport.script("grants.example.com", [FakeDnsOutcome::TransportError]);
    refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("the transient retry completes with the denial");
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "the denied grant is never reinstalled from the stale state: {egress}"
    );
    // Same convergence: the autonomous denial boundary may be
    // mid-enforcement on the interrupted .9 identity (blind fence, then
    // withdrawal, then release).
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let egress = acl_egress(&log, &acl);
        if !egress.contains("128.66.0.9") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the interrupted re-grant is withdrawn: {egress}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    // Inverse: once a re-grant COMMITS, its stale revocation is retired
    // — the marker clears and the fresh answer is what stands.
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 9),
            60,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the re-grant commits");
    assert!(
        !marker_path.exists(),
        "a successful commit retires the revocation"
    );
    let egress = acl_egress(&log, &acl);
    assert!(
        egress.contains("128.66.0.9"),
        "the committed re-grant is installed: {egress}"
    );
}

#[test]
fn grants_lapsing_in_later_passes_or_publication_are_revoked_and_republished() {
    // Lifetimes go stale across EVERY wall-clock stage, not just the first
    // enforcement pass: `lapsed` survives the add pass but its remaining
    // lifetime is consumed by a slow PUBLICATION; `survivor` survives the
    // publication recheck... no — `survivor` lapses during the slow REMOVAL
    // pass that the first revocation triggers. Both are revoked (marker
    // extended before each removal) and the final publication carries
    // neither; the returned delay is the empty-set floor.
    let (client, log) = applied_client("running", "sbx-1");
    let (network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["lapsed.example.com", "survivor.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "lapsed.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            45,
        )])],
    );
    transport.script(
        "survivor.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            // Unsafe once its remaining lifetime reaches the churn floor
            // (~30s after the answer). The slow removal pass for `lapsed`
            // (4 rules x 4s, after ~8s of slow adds and the 12s slow
            // publication) cannot end before ~38s even with zero process
            // overhead, so the pre-publication recheck ALWAYS catches the
            // lapse — independent of the exact moment the watcher thread
            // restores fast operations.
            60,
        )])],
    );
    let statedir = log.parent().expect("statedir").to_path_buf();
    // ~8s of additions keep both grants safe; the 12s publication lapses
    // `lapsed`; the 4s-per-rule removal pass that follows lapses
    // `survivor` before the SECOND pass's recheck would publish it.
    fs::write(statedir.join("slow-acl-ops"), "1").unwrap();
    fs::write(statedir.join("slow-acl-removals"), "4").unwrap();
    fs::write(statedir.join("slow-publish"), "12").unwrap();
    let outcome = std::thread::scope(|scope| {
        let running = scope.spawn(|| refresh(&client, "sbx-1", &policy, &hash, &transport));
        // Once the publication-lapsed grant is fully removed (its slow
        // removal pass has finished), restore fast operations so the
        // remaining passes and republication complete quickly.
        let deadline = std::time::Instant::now() + Duration::from_secs(180);
        while !acl_egress(&log, &acl).contains("128.66.0.7") {
            assert!(
                std::time::Instant::now() < deadline,
                "first pass installed the grants"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        while acl_egress(&log, &acl).contains("128.66.0.7") {
            assert!(
                std::time::Instant::now() < deadline,
                "the removal pass progressed"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        fs::write(statedir.join("slow-acl-removals"), "0").unwrap();
        fs::write(statedir.join("slow-publish"), "0").unwrap();
        running.join().expect("refresh thread")
    })
    .expect("refresh completes with every lapsed grant revoked");
    assert!(
        outcome
            .denied_names
            .iter()
            .any(|name| name == "lapsed.example.com"),
        "publication-lapsed grant revoked: {:?}",
        outcome.denied_names
    );
    assert!(
        outcome
            .denied_names
            .iter()
            .any(|name| name == "survivor.example.com"),
        "grant lapsed in the later pass revoked: {:?}",
        outcome.denied_names
    );
    assert_eq!(outcome.published_names, 0, "nothing lapsed is published");
    // The autonomous boundary (C36 r31 F2) may have blind-fenced a lapsed
    // destination mid-pass; its journaled release follows the positive
    // withdrawal on the next watcher tick.
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let egress = acl_egress(&log, &acl);
        if !egress.contains("128.66.0.7") && !egress.contains("128.66.0.8") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "removed (any blind fence released after the proven withdrawal): {egress}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    let raw = raw_dnsmasq(&log, &network);
    assert!(
        !raw.contains("lapsed.example.com"),
        "republished without it: {raw}"
    );
    assert!(
        !raw.contains("survivor.example.com"),
        "republished without it: {raw}"
    );
    let state = fs::read_to_string(statedir.join("host-state/dns-policy/sbx-1.json"))
        .expect("state persisted");
    assert!(
        !state.contains("\"name\":\"lapsed.example.com\"")
            && !state.contains("\"name\":\"survivor.example.com\""),
        "nothing lapsed is persisted: {state}"
    );
    assert_eq!(
        outcome.refresh_after,
        Duration::from_secs(30),
        "empty set returns the churn floor, measured at completion"
    );
    assert!(
        !statedir
            .join("host-state/dns-revocations/sbx-1.json")
            .exists(),
        "marker cleared after commit"
    );
}

#[test]
fn answers_expire_from_answer_time_not_planning_time() {
    // The first answer's grant expires at ANSWER time + TTL, never at
    // planning time: a delayed later lookup must not extend the early
    // grant past its real expiry (the enforcement rechecks can't detect an
    // expiry that was itself extended).
    let (mut client, log) = applied_client("running", "sbx-1");
    let clock = DnsTestClock::install(&mut client);
    let (network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["early.example.com", "late.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "early.example.com",
        [
            FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 7), 31)]),
            FakeDnsOutcome::Answer(vec![]), // AAAA NODATA
        ],
    );
    transport.script(
        "late.example.com",
        [
            FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 8), 60)]),
            FakeDnsOutcome::Answer(vec![]), // AAAA NODATA
        ],
    );
    // early is answered at ~t0 (expires t0+31, above the 30s churn floor);
    // late's lookup takes 2s, so planning and enforcement happen at ~t0+2
    // — the safe publication window (t0+32) already exceeds early's REAL
    // expiry: it is revoked before publication. Planning-time expiry
    // (t0+33) would have kept it.
    let before = log_lines(&log).len();
    let timed = LogicalDnsTransport {
        inner: &transport,
        clock: &clock,
        delays: std::sync::Mutex::new([0, 0, 2, 0].into()),
    };
    let outcome = refresh(&client, "sbx-1", &policy, &hash, &timed)
        .expect("refresh completes with the stale-window grant revoked");
    let window = &log_lines(&log)[before..];
    assert!(
        !window
            .iter()
            .any(|line| line.contains("network acl rule add") && line.contains("128.66.0.7")),
        "an expired destination NEVER receives an allow-add (revoked before \
         the first enforcement pass — withholding DNS publication does not \
         stop a guest connecting by IP): {}",
        window.join("\n")
    );
    assert!(
        outcome
            .denied_names
            .iter()
            .any(|name| name == "early.example.com"),
        "answer-time expiry revoked the early grant: {:?}",
        outcome.denied_names
    );
    assert_eq!(outcome.published_names, 1, "only the late grant");
    let egress = acl_egress(&log, &acl);
    assert!(!egress.contains("128.66.0.7"), "withdrawn: {egress}");
    assert!(
        egress.contains("action=allow destination=128.66.0.8/32"),
        "late grant installed: {egress}"
    );
    let raw = raw_dnsmasq(&log, &network);
    assert!(!raw.contains("early.example.com"), "never published: {raw}");
    assert!(
        raw.contains("host-record=late.example.com,128.66.0.8\n"),
        "{raw}"
    );
    let statedir = log.parent().expect("statedir").to_path_buf();
    let state = fs::read_to_string(statedir.join("host-state/dns-policy/sbx-1.json"))
        .expect("state persisted");
    assert!(
        !state.contains("\"name\":\"early.example.com\""),
        "not retained: {state}"
    );
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn an_unreadable_revocation_marker_refuses_mutation() {
    // Only NotFound means no marker. Invalid UTF-8 (or any other read
    // failure) is fail-closed EVIDENCE: the refresh refuses to mutate and
    // never overwrites it — otherwise a transient retry would retain the
    // stale persisted grant and erase a pending revocation.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            // TTL 600: the stale allow must survive for the WHOLE
            // test — with TTL 60 the lease-expiry watcher lawfully
            // withdraws it mid-test under full-workspace gate load
            // (the expiry fence needs no readable marker), failing the
            // preserved-verbatim assertion below. Expiry plays no part
            // in this test.
            600,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("first refresh grants");
    let statedir = log.parent().expect("statedir").to_path_buf();
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    // Interrupted revocation: NXDOMAIN, but the first removal fails — the
    // marker is durable while the stale allow (and stale state) survive.
    transport.script("grants.example.com", [FakeDnsOutcome::Rcode(3)]);
    fs::write(statedir.join("fail-acl-rule-remove"), "").unwrap();
    refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect_err("interrupted revocation leaves the marker");
    assert!(marker_path.exists());
    // The removal pin stays until the FINAL assertion: the lease watcher
    // enforces the journaled revocation on its own ≤60s tick, and under
    // full-workspace gate load that tick can land mid-test — lifting the
    // pin here would let it lawfully withdraw the stale allow before the
    // marker is corrupted, failing the preserved-verbatim assertion
    // below. With the pin in place the withdrawal fails closed and the
    // crash state survives (an over-denying fence beside the allow is
    // fine — the assertion is that the allow survives).
    // Corrupt the marker: invalid UTF-8.
    fs::write(&marker_path, [0xffu8, 0xfe, 0xfd]).unwrap();
    // RESTART + transient retry: the refresh must REFUSE to mutate.
    let mut restarted = legacy_client(client.binary.clone(), "default".to_string());
    restarted.state_dir = Some(statedir.join("host-state"));
    transport.script("grants.example.com", [FakeDnsOutcome::TransportError]);
    let before = log_lines(&log).len();
    let err = refresh(&restarted, "sbx-1", &policy, &hash, &transport)
        .expect_err("an unreadable marker refuses mutation");
    assert_eq!(err.code, SandboxErrorCode::Internal);
    assert_eq!(
        fs::read(&marker_path).expect("marker still present"),
        vec![0xffu8, 0xfe, 0xfd],
        "the corrupt evidence is never overwritten"
    );
    let window = &log_lines(&log)[before..];
    assert!(
        !window.iter().any(|line| line.contains("network acl rule")),
        "no ACL mutation while the marker is unreadable: {}",
        window.join("\n")
    );
    // C37 R5: an UNREADABLE marker is unavailable evidence — readiness
    // still refuses (fail closed), but the classification is INCONCLUSIVE
    // (Internal), never drift: nothing is convicted or cleaned up.
    let err = restarted
        .verify_provisioned_enforcement("sbx-1")
        .expect_err("readiness stays refused with an unreadable marker");
    assert_eq!(err.code, SandboxErrorCode::Internal);
    let egress = acl_egress(&log, &acl);
    assert!(
        egress.contains("action=allow destination=128.66.0.7/32"),
        "the refusal changes nothing — the interrupted crash state is preserved verbatim: {egress}"
    );
    fs::remove_file(statedir.join("fail-acl-rule-remove")).unwrap();
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn an_unstatable_revocation_marker_fails_readiness_closed() {
    // The readiness fence stats the marker with error propagation: an
    // unsearchable dns-revocations directory (or any metadata I/O error)
    // must NOT read as "no marker" — exists() would convert the error to
    // false and accept a revoked grant as enforceable.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, _acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            60,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("first refresh grants");
    let statedir = log.parent().expect("statedir").to_path_buf();
    // Interrupted revocation: the marker is durable, the stale
    // ACL/publication/plan trio still agrees.
    transport.script("grants.example.com", [FakeDnsOutcome::Rcode(3)]);
    fs::write(statedir.join("fail-acl-rule-remove"), "").unwrap();
    refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect_err("interrupted revocation leaves the marker");
    let marker_dir = statedir.join("host-state/dns-revocations");
    assert!(marker_dir.join("sbx-1.json").exists(), "marker pending");
    // RESTART. Make the marker directory unsearchable: the metadata check
    // must FAIL CLOSED, not read as absence.
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(&marker_dir).unwrap().permissions();
    perms.set_mode(0o000);
    fs::set_permissions(&marker_dir, perms.clone()).unwrap();
    let mut restarted = legacy_client(client.binary.clone(), "default".to_string());
    restarted.state_dir = Some(statedir.join("host-state"));
    // C37 R5: an unstatable marker is unavailable evidence — readiness
    // still refuses (fail closed), but the observation is INCONCLUSIVE
    // (Internal), never the drift/cleanup classification.
    let err = restarted
        .verify_provisioned_enforcement("sbx-1")
        .expect_err("a metadata failure refuses readiness");
    assert_eq!(err.code, SandboxErrorCode::Internal);
    // Restore searchability: the pending marker still fences; commit the
    // denial, then readiness verifies.
    perms.set_mode(0o755);
    fs::set_permissions(&marker_dir, perms).unwrap();
    fs::remove_file(statedir.join("fail-acl-rule-remove")).unwrap();
    transport.script("grants.example.com", [FakeDnsOutcome::Rcode(3)]);
    refresh(&restarted, "sbx-1", &policy, &hash, &transport).expect("denial commits");
    restarted
        .verify_provisioned_enforcement("sbx-1")
        .expect("readiness verifies once the denial is committed");
}

#[test]
fn failed_publication_still_revokes_and_withdraws_lapsed_grants() {
    // The completion-time expiry check must run on FAILED publication too,
    // and the failure-path cleanup must be a revoke-only LOOP: a logical
    // 32s PATCH failure lapses the 45s grant's safe window. Grant removals
    // then consume logical time and lapse the 65s grant's safe window — the
    // cleanup rechecks survivors after EACH pass and records the second
    // revocation durably BEFORE removing it.
    let (mut client, log) = applied_client("running", "sbx-1");
    let clock = DnsTestClock::install(&mut client);
    let answered_at = clock.now();
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com", "survivor.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            45,
        )])],
    );
    transport.script(
        "survivor.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            65,
        )])],
    );
    let statedir = log.parent().expect("statedir").to_path_buf();
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    fs::write(statedir.join("slow-publish"), "32").unwrap();
    fs::write(statedir.join("slow-acl-grant-removals"), "10").unwrap();
    fs::write(statedir.join("fail-raw-dnsmasq"), "").unwrap();
    // Hold companion cleanup after the first allow disappears, so the
    // observer cannot miss this ordering when logical work finishes fast.
    fs::write(statedir.join("barrier-acl-reject-remove"), "").unwrap();
    let err = std::thread::scope(|scope| {
        let running = scope.spawn(|| refresh(&client, "sbx-1", &policy, &hash, &transport));
        // Once the first withdrawal pass has removed the first grant's
        // ALLOW (its slow removals are what lapse the second grant),
        // restore fast removals so the second withdrawal completes
        // quickly. The condition watches the ALLOW rules only: since C36
        // r21 F1 the expiry lease fences the lapsed destination the
        // moment its authorization expires, and that fence is released
        // only after the whole withdrawal is proven — so a transient
        // state with NO trace of the lapsed destination while the
        // survivor's allow is still installed no longer occurs (and
        // never races the lease watcher into existence).
        let deadline = std::time::Instant::now() + Duration::from_secs(180);
        loop {
            let egress = acl_egress(&log, &acl);
            if egress.contains("action=allow destination=128.66.0.8/32")
                && !egress.contains("action=allow destination=128.66.0.7/32")
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the first withdrawal pass progressed: {egress}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(
            clock.now() >= answered_at + 42,
            "cleanup consumed lifetime after the failed PATCH"
        );
        fs::write(statedir.join("slow-acl-grant-removals"), "0").unwrap();
        fs::write(statedir.join("release-reject-barrier"), "").unwrap();
        running.join().expect("refresh thread")
    })
    .expect_err("the slow publication fails");
    assert_eq!(err.code, SandboxErrorCode::Internal);
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "the lapsed grant is withdrawn even on the failure path: {egress}"
    );
    assert!(
        !egress.contains("128.66.0.8"),
        "a grant expiring DURING cleanup is withdrawn too: {egress}"
    );
    let marker = fs::read_to_string(&marker_path).expect("revocation recorded durably");
    assert!(
        marker.contains("grants.example.com"),
        "the marker records the first expiry revocation: {marker}"
    );
    assert!(
        marker.contains("survivor.example.com"),
        "the marker records the grant that lapsed DURING cleanup: {marker}"
    );
    // Recovery: the denials commit and the marker clears.
    fs::remove_file(statedir.join("fail-raw-dnsmasq")).unwrap();
    fs::remove_file(statedir.join("slow-publish")).unwrap();
    transport.script("grants.example.com", [FakeDnsOutcome::Rcode(3)]);
    transport.script("survivor.example.com", [FakeDnsOutcome::Rcode(3)]);
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("denials commit");
    assert!(!marker_path.exists(), "marker cleared after commit");
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7") && !egress.contains("128.66.0.8"),
        "never reinstalled: {egress}"
    );
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn an_expired_grant_is_never_added_during_a_slow_pass() {
    // The per-ADDITION lifetime gate: expiry was previously checked before
    // and after the whole replacement pass, not before INDIVIDUAL allow
    // additions — a slow removal phase (44s) pushes a 40s grant's allow
    // addition past its expiry, and the guest can connect by IP until the
    // post-pass withdrawal. The allow must NEVER be installed.
    let (mut client, log) = applied_client("running", "sbx-1");
    // Keep the full 44 seconds of logical cleanup and the 40-second grant,
    // without exhausting real child deadlines while two callers serialize.
    let _clock = DnsTestClock::install(&mut client);
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(
        &["stale.example.com", "fresh.example.com"],
        &["128.66.1.0/24"],
    );
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "stale.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    transport.script("fresh.example.com", [FakeDnsOutcome::Rcode(3)]);
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("first refresh installs");
    assert!(
        acl_egress(&log, &acl).contains("action=allow destination=128.66.0.7/32"),
        "stale grant installed"
    );
    let statedir = log.parent().expect("statedir").to_path_buf();
    // Second refresh: the stale grant NXDOMAINs (its 4 rules are removed
    // at 11s each); the fresh grant answers with a 40s TTL on a
    // static-CIDR-covered address (allow rule only) — its addition lands
    // ~44s in, AFTER its expiry.
    transport.script("stale.example.com", [FakeDnsOutcome::Rcode(3)]);
    transport.script(
        "fresh.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 1, 9),
            40,
        )])],
    );
    fs::write(statedir.join("slow-acl-removals"), "11").unwrap();
    let before = log_lines(&log).len();
    let outcome = refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("refresh completes with the expired grant never installed");
    let window = &log_lines(&log)[before..];
    assert!(
        !window
            .iter()
            .any(|line| line.contains("network acl rule add")
                && line.contains("action=allow")
                && line.contains("128.66.1.9")),
        "an allow for the expired grant is NEVER installed: {}",
        window.join("\n")
    );
    assert!(
        outcome
            .denied_names
            .iter()
            .any(|name| name == "fresh.example.com"),
        "mid-pass lapse reported denied: {:?}",
        outcome.denied_names
    );
    assert!(
        outcome
            .denied_names
            .iter()
            .any(|name| name == "stale.example.com"),
        "{:?}",
        outcome.denied_names
    );
    assert_eq!(outcome.published_names, 0);
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "stale rules withdrawn: {egress}"
    );
    assert!(
        !egress.contains("destination=128.66.1.9/32"),
        "expired grant absent: {egress}"
    );
    assert!(
        !statedir
            .join("host-state/dns-revocations/sbx-1.json")
            .exists(),
        "marker cleared after commit"
    );
}

#[test]
fn a_stalled_allow_mutation_never_becomes_effective() {
    // The per-addition gate checks BEFORE issuing the command, but the
    // mutation itself must be bounded by the grant's remaining lifetime: a
    // 45s grant's allow mutation stalling 50s would otherwise install an
    // already-expired destination at t=50s. The bounded command is killed
    // at its 45s deadline and the uncertain outcome fenced as
    // revoked-pending-reconciliation — the allow NEVER becomes effective.
    // Slow removals (2s) keep a pre-fix allow visible across many 100ms
    // polls while leaving room for serialized refresh/watcher cleanup.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            45,
        )])],
    );
    let statedir = log.parent().expect("statedir").to_path_buf();
    fs::write(statedir.join("slow-acl-allow-add"), "50").unwrap();
    fs::write(statedir.join("slow-acl-removals"), "2").unwrap();
    let (outcome, saw_allow) = std::thread::scope(|scope| {
        let running = scope.spawn(|| refresh(&client, "sbx-1", &policy, &hash, &transport));
        let mut saw_allow = false;
        let deadline = std::time::Instant::now() + Duration::from_secs(180);
        while !running.is_finished() {
            assert!(std::time::Instant::now() < deadline, "refresh progresses");
            if acl_egress(&log, &acl).contains("action=allow destination=128.66.0.7/32") {
                saw_allow = true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        (running.join().expect("refresh thread"), saw_allow)
    });
    assert!(
        !saw_allow,
        "an expired allow never becomes effective — the stalled mutation is bounded and fenced"
    );
    let outcome = outcome.expect("refresh completes with the fenced revocation reported denied");
    assert!(
        outcome
            .denied_names
            .iter()
            .any(|name| name == "grants.example.com"),
        "{:?}",
        outcome.denied_names
    );
    assert_eq!(outcome.published_names, 0);
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("action=allow destination=128.66.0.7/32"),
        "the allow never landed: {egress}"
    );
    assert!(
        egress.lines().any(|line| {
            line.contains("action=reject")
                && line.contains("destination=128.66.0.7/32")
                && line.contains("wssp-dns-quarantine-")
                && !line.contains("destination_port")
        }),
        "a destination-wide quarantine (TCP/443 included) denies the address while the \
         mutation is unreconciled — port-scoped companions alone are insufficient: {egress}"
    );
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    let marker = fs::read_to_string(&marker_path)
        .expect("the uncertain mutation keeps the revocation marker pending past the commit");
    assert!(
        marker.contains("grants.example.com") && marker.contains("128.66.0.7/32"),
        "marker records the denial and the pending mutation: {marker}"
    );
    // A later refresh reconciles — but the allow NEVER landed, and absence
    // is not proof of cancellation: the daemon may apply the accepted
    // mutation later (C36 r15). The pending entry and its destination-wide
    // quarantine HOLD until definitive evidence (an observed withdrawal, or
    // a superseding re-grant).
    transport.script("grants.example.com", [FakeDnsOutcome::Rcode(3)]);
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("reconciling refresh");
    let marker = fs::read_to_string(&marker_path)
        .expect("no definitive completion: the fence holds past the reconciling refresh");
    assert!(
        marker.contains("grants.example.com") && marker.contains("128.66.0.7/32"),
        "pending mutation retained: {marker}"
    );
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("action=allow destination=128.66.0.7/32"),
        "no allow: {egress}"
    );
    assert!(
        egress.lines().any(|line| {
            line.contains("action=reject")
                && line.contains("destination=128.66.0.7/32")
                && line.contains("wssp-dns-quarantine-")
                && !line.contains("destination_port")
        }),
        "the destination-wide quarantine holds: {egress}"
    );
    // A RE-GRANT of the same address does NOT retire the older uncertain
    // mutation (C36 r16): the fresh allow carries a NEW rule generation, so
    // the stale request — which may still be applied daemon-side — keeps
    // its pending entry and the marker keeps fencing readiness. The
    // quarantine is suppressed only while the re-grant intentionally allows
    // the destination.
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            120,
        )])],
    );
    fs::remove_file(statedir.join("slow-acl-allow-add")).unwrap();
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("re-granting refresh");
    let marker = fs::read_to_string(&marker_path)
        .expect("a re-grant is not definitive reconciliation: the stale mutation stays pending");
    assert!(
        marker.contains("128.66.0.7/32"),
        "stale pending mutation retained: {marker}"
    );
    let egress = acl_egress(&log, &acl);
    // Fence epochs share the durable identity counter with allow
    // generations (C36 r17), so the re-grant's generation is whatever the
    // counter reached — assert the SHAPE (generation-scoped, distinct
    // from the interrupted legacy identity), not the number.
    let stale_tag = dns_rule_tag("grants.example.com", 0);
    assert!(
        egress.lines().any(|line| {
            line.contains("action=allow destination=128.66.0.7/32")
                && line.contains("wssp-dns-g")
                && !line.contains(&format!("description={stale_tag}"))
        }),
        "the re-grant installs a NEW-generation allow: {egress}"
    );
    assert!(
        !egress.contains("wssp-dns-quarantine-"),
        "quarantine suppressed while the destination is granted: {egress}"
    );
}

#[test]
fn fresh_answers_at_the_ttl_floor_install_and_publish() {
    // The churn floor is transient-RETENTION headroom, not an eligibility
    // bar: fresh answers with TTL <= 30 must install and publish
    // successfully (expires_at = answer time + clamped TTL; the per-rule
    // budget is the remaining ABSOLUTE lifetime). TTLs 0, 5, and 30 all
    // clamp to the floor.
    for ttl in [0u32, 5, 30] {
        let sandbox = format!("sbx-ttl{ttl}");
        let (mut client, log) = applied_client("running", &sandbox);
        let clock = DnsTestClock::install(&mut client);
        let answered_at = clock.now();
        fs::write(log.parent().unwrap().join("slow-publish"), "1").unwrap();
        let (_network, acl) = sandbox_network_names(&sandbox);
        let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
        bind_recorded_policy(&log, &sandbox, &hash);
        let transport = FakeDnsTransport::new();
        transport.script(
            "grants.example.com",
            [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
                Ipv4Addr::new(128, 66, 0, 7),
                ttl,
            )])],
        );
        let outcome = refresh(&client, &sandbox, &policy, &hash, &transport)
            .unwrap_or_else(|err| panic!("TTL {ttl} refresh succeeds: {err}"));
        assert_eq!(outcome.published_names, 1, "TTL {ttl}");
        assert!(
            outcome.denied_names.is_empty(),
            "TTL {ttl}: {:?}",
            outcome.denied_names
        );
        let egress = acl_egress(&log, &acl);
        assert!(
            egress.contains("action=allow destination=128.66.0.7/32"),
            "TTL {ttl} installed: {egress}"
        );
        assert_eq!(outcome.refresh_after, Duration::from_secs(29), "TTL {ttl}");
        assert_eq!(clock.now(), answered_at + 1);
        assert!(
            !log.parent()
                .expect("statedir")
                .join(format!("host-state/dns-revocations/{sandbox}.json"))
                .exists(),
            "TTL {ttl}: no revocation marker"
        );
        client.debug_reset_dns_lease_owner(&sandbox);
    }
}

#[test]
fn a_daemon_side_allow_completing_after_the_cli_stays_fenced_until_reconciled() {
    // Killing the CLI at the grant's deadline does NOT cancel daemon-side
    // work: the allow mutation can complete AFTER the CLI died, behind the
    // best-effort withdrawal and the readback. The fenced grant keeps its
    // revocation marker PENDING (readiness refused) with reject companions
    // denying the destination, until a LATER refresh reconciles absence.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            40,
        )])],
    );
    let statedir = log.parent().expect("statedir").to_path_buf();
    // The daemon accepts the allow and applies it at +45s; the CLI stalls
    // and is killed at the grant's 40s deadline.
    fs::write(statedir.join("defer-acl-allow-add"), "45").unwrap();
    let outcome = refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("refresh completes with the uncertain grant fenced");
    assert!(
        outcome
            .denied_names
            .iter()
            .any(|name| name == "grants.example.com"),
        "{:?}",
        outcome.denied_names
    );
    assert_eq!(outcome.published_names, 0);
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    let marker =
        fs::read_to_string(&marker_path).expect("the uncertain mutation keeps the marker pending");
    assert!(
        marker.contains("grants.example.com") && marker.contains("128.66.0.7/32"),
        "denial and pending mutation recorded: {marker}"
    );
    // The daemon-side apply lands AFTER the CLI died and the commit drain
    // checked: the address is never unprotected — reject companions deny
    // it while the marker fences readiness.
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let egress = acl_egress(&log, &acl);
        if egress.contains("action=allow destination=128.66.0.7/32") {
            assert!(
                egress.lines().any(|line| {
                    line.contains("action=reject")
                        && line.contains("destination=128.66.0.7/32")
                        && line.contains("wssp-dns-quarantine-")
                        && !line.contains("destination_port")
                }),
                "a destination-wide quarantine (TCP/443 included) denies the late-applied \
                 allow — port-scoped companions alone are insufficient: {egress}"
            );
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the daemon-side apply lands behind the killed CLI: {egress}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    // A later refresh reconciles: withdraws the late-applied allow,
    // confirms absence, retires the deny companions, clears the marker.
    transport.script("grants.example.com", [FakeDnsOutcome::Rcode(3)]);
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("reconciling refresh");
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "late-applied allow withdrawn and companions retired: {egress}"
    );
    assert!(!marker_path.exists(), "marker cleared after reconciliation");
}

#[test]
fn a_stalled_mutation_is_bounded_by_the_earliest_grants_deadline() {
    // Grant A (30s on re-answer) is already installed; grant B (300s)
    // stalls 90s in its allow mutation. B's own budget would let the stall
    // outlast A's expiry by ~60s with A reachable the whole time — the
    // mutation must be bounded by the EARLIEST live grant's deadline, and
    // the lapsed grant withdrawn before the pass continues.
    let (mut client, log) = applied_client("running", "sbx-1");
    let clock = DnsTestClock::install(&mut client);
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["first.example.com", "second.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "first.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    transport.script("second.example.com", [FakeDnsOutcome::Rcode(3)]);
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("first refresh installs");
    assert!(
        acl_egress(&log, &acl).contains("action=allow destination=128.66.0.7/32"),
        "first grant installed"
    );
    let statedir = log.parent().expect("statedir").to_path_buf();
    transport.script(
        "first.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            30,
        )])],
    );
    transport.script(
        "second.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            300,
        )])],
    );
    // B's resolution consumes 29 logical seconds after A's answer. The
    // production budget therefore has one real second left for A versus
    // 300 for B; the command itself remains a genuine blocked subprocess.
    let answered_at = clock.now();
    let timed = LogicalDnsTransport {
        inner: &transport,
        clock: &clock,
        delays: std::sync::Mutex::new([0, 0, 29, 0].into()),
    };
    let permit = std::sync::Arc::new(crate::RuntimePermit::default());
    client.cancelled = Some(permit.clone());
    fs::write(statedir.join("slow-acl-allow-add"), "90").unwrap();
    std::thread::scope(|scope| {
        let (done, completed) = std::sync::mpsc::channel();
        let work = || refresh(&client, "sbx-1", &policy, &hash, &timed);
        let running = scope.spawn(move || {
            let outcome = work();
            done.send(()).unwrap();
            outcome
        });
        // Wait for issuance, then advance past A's absolute expiry while
        // B's command would still be stalled without the earliest budget.
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        loop {
            let seen = log_lines(&log).iter().any(|line| {
                line.contains("network acl rule add")
                    && line.contains("action=allow")
                    && line.contains("128.66.0.8")
            });
            if seen {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the stalled allow mutation started"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(
            clock.now(),
            answered_at + 29,
            "one second remains for A at issuance"
        );
        clock.advance(11);
        client.debug_wake_dns_lease_owner("sbx-1");
        let bounded = completed.recv_timeout(Duration::from_secs(15)).is_ok();
        if !bounded {
            // Bound a broken implementation too, so the fault cannot leave
            // the scoped thread parked for the full 90-second injection.
            permit.revoke();
        }
        let result = running.join().expect("refresh thread");
        assert!(
            bounded,
            "the other grant's mutation obeys the earliest grant deadline"
        );
        let egress = acl_egress(&log, &acl);
        assert!(
            !egress.contains("action=allow destination=128.66.0.7/32"),
            "the earliest grant is withdrawn at its own deadline even while \
             ANOTHER grant's mutation stalls: {egress}"
        );
        result.expect("refresh completes with both grants denied")
    });
    // The stalled allow never landed — and absence is not proof of
    // cancellation (C36 r15): the reconciling refresh KEEPS the pending
    // entry and its destination-wide quarantine; the marker fences
    // readiness until definitive evidence (an observed withdrawal, or a
    // superseding re-grant).
    transport.script("first.example.com", [FakeDnsOutcome::Rcode(3)]);
    transport.script("second.example.com", [FakeDnsOutcome::Rcode(3)]);
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("reconciling refresh");
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("action=allow destination=128.66.0.7/32")
            && !egress.contains("action=allow destination=128.66.0.8/32"),
        "no allows remain: {egress}"
    );
    assert!(
        egress.lines().any(|line| {
            line.contains("action=reject")
                && line.contains("destination=128.66.0.8/32")
                && line.contains("wssp-dns-quarantine-")
                && !line.contains("destination_port")
        }),
        "the quarantine fencing the uncertain mutation holds: {egress}"
    );
    let marker = fs::read_to_string(statedir.join("host-state/dns-revocations/sbx-1.json"))
        .expect("no definitive completion: the marker fences readiness");
    assert!(
        marker.contains("second.example.com") && marker.contains("128.66.0.8/32"),
        "pending mutation retained: {marker}"
    );
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn cancelled_publication_cleanup_still_withdraws_lapsed_allows() {
    // Cancellation mid-publication revokes the issuing permit — but the
    // failure-path cleanup must STILL withdraw the now-lapsed allow: it
    // runs through an independently bounded cleanup client carrying no
    // permit, as network rollback does.
    let (mut client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            35,
        )])],
    );
    let permit = std::sync::Arc::new(crate::RuntimePermit::default());
    client.cancelled = Some(permit.clone());
    let statedir = log.parent().expect("statedir").to_path_buf();
    fs::write(statedir.join("slow-publish"), "30").unwrap();
    let err = std::thread::scope(|scope| {
        let running = scope.spawn(|| refresh(&client, "sbx-1", &policy, &hash, &transport));
        // Cancel once publication is in flight (the allow is installed and
        // its 35s safe window lapses during the 30s PATCH).
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            if log_lines(&log).iter().any(|line| line.contains("PATCH")) {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "publication in flight"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        std::thread::sleep(Duration::from_secs(8));
        permit.revoke();
        running.join().expect("refresh thread")
    })
    .expect_err("cancelled publication fails the refresh");
    assert!(
        err.code == SandboxErrorCode::UnknownOutcome || err.code == SandboxErrorCode::Timeout,
        "cancelled publication surfaces uncertainty: {err}"
    );
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "the lapsed allow is withdrawn even though the issuing permit is revoked: {egress}"
    );
    let marker = fs::read_to_string(statedir.join("host-state/dns-revocations/sbx-1.json"))
        .expect("the revocation is recorded durably");
    assert!(
        marker.contains("grants.example.com"),
        "marker records the lapse: {marker}"
    );
}

#[test]
fn create_publication_failure_rolls_back_so_the_retry_republishes() {
    // The network plan persists before the initial DNS publication. If
    // publication fails, the apply rolls back (retiring the persisted plan
    // and DNS state records) so the retry RECOMPILES and republishes —
    // create can never report readiness over an unpublished deny-all
    // resolver while every allowed domain is unresolvable.
    let (mut runtime, log) = runtime_for("fix6_new_ready");
    runtime.override_resolver(std::sync::Arc::new(|_domain, _wait| {
        Ok(vec![std::net::IpAddr::V4(Ipv4Addr::new(128, 66, 0, 7))])
    }));
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    let mut request = super::shim_tests::create_req();
    request.egress_policy = Some(policy);
    request.egress_policy_hash = Some(hash);
    let statedir = log.parent().expect("statedir").to_path_buf();
    let (network, acl) = sandbox_network_names("sbx-1");
    fs::write(statedir.join("fail-raw-dnsmasq"), "").unwrap();
    runtime
        .create_bound(&request)
        .expect_err("a failed publication fails the create");
    // Rolled back: nothing enforced, nothing persisted as resumable state.
    assert!(raw_dnsmasq(&log, &network).is_empty(), "the bridge is gone");
    assert!(acl_egress(&log, &acl).is_empty(), "the ACL is gone");
    assert!(
        !statedir
            .join("host-state/network-plans/sbx-1.json")
            .exists(),
        "no persisted expansion to reuse"
    );
    assert!(
        !statedir.join("host-state/dns-policy/sbx-1.json").exists(),
        "no DNS state"
    );
    // Retry recompiles and publishes.
    fs::remove_file(statedir.join("fail-raw-dnsmasq")).unwrap();
    runtime
        .create_bound(&request)
        .expect("retry recompiles and publishes");
    let raw = raw_dnsmasq(&log, &network);
    assert!(
        raw.contains("host-record=grants.example.com,128.66.0.7\n"),
        "the retry published the answers: {raw}"
    );
    assert!(statedir.join("host-state/dns-policy/sbx-1.json").exists());
}

#[test]
fn interrupted_reject_repair_withdraws_the_allow_first() {
    // Reject REPAIR ordering: a mismatched reject must never be removed
    // while the overlapping unrestricted allow stays installed. The refresh
    // withdraws the allow FIRST; a failed replacement then leaves the
    // address denied (no DNS/DoT hole), never allow-without-rejects.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            60,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("first refresh");
    let statedir = log.parent().expect("statedir").to_path_buf();
    let (network, _acl2) = sandbox_network_names("sbx-1");
    // Positive control: the publication detector matches the REAL network
    // name, so the no-republication assertion below is not vacuous.
    let publish_line = log_lines(&log)
        .into_iter()
        .find(|line| is_dns_publish(line, &network))
        .unwrap_or_else(|| panic!("the first publish is detected under {network}"));
    // Negative control: it must NOT match a different network's name.
    assert!(
        !is_dns_publish(&publish_line, &sandbox_network_names("sbx-2").0),
        "detector is network-specific"
    );
    // Tamper: source-constrain one reject companion so it must be REPAIRED.
    let egress_path = statedir.join("acls").join(format!("{acl}.egress"));
    let body = fs::read_to_string(&egress_path).expect("egress");
    fs::write(
        &egress_path,
        body.replacen(
            "protocol=udp destination=128.66.0.7/32 destination_port=53",
            "protocol=udp destination=128.66.0.7/32 source=10.9.9.9/32 destination_port=53",
            1,
        ),
    )
    .expect("tamper");
    // Fail reject REPLACEMENTS: the repair cannot complete.
    fs::write(statedir.join("fail-acl-rule-add-reject"), "").unwrap();
    let before = log_lines(&log).len();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            60,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect_err("repair fails");
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("action=allow destination=128.66.0.7/32"),
        "the allow was withdrawn before the failed repair: {egress}"
    );
    assert!(
        !egress.contains("source=10.9.9.9/32"),
        "the tampered reject was removed: {egress}"
    );
    // Ordering: the allow removal precedes every reject mutation for the
    // address (allow removals carry no action= token).
    let window = &log_lines(&log)[before..];
    let first = window
        .iter()
        .find(|line| line.contains("network acl rule remove") && line.contains("128.66.0.7"))
        .expect("allow withdrawn first");
    assert!(
        !first.contains("action="),
        "first removal is the allow: {first}"
    );
    // Nothing was published or persisted (asserted against the REAL network
    // name — a wrong needle here would make this assertion vacuous).
    let raw = raw_dnsmasq(&log, &network);
    assert!(raw.contains("host-record=grants.example.com,128.66.0.7\n"));
    assert!(
        !window.iter().any(|line| is_dns_publish(line, &network)),
        "no republication: {}",
        window.join("\n")
    );
    // Recovery: the next refresh restores the full rule set.
    fs::remove_file(statedir.join("fail-acl-rule-add-reject")).unwrap();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            60,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("retry completes");
    let egress = acl_egress(&log, &acl);
    assert!(
        egress.contains("action=allow destination=128.66.0.7/32"),
        "{egress}"
    );
    assert!(
        egress.contains("action=reject protocol=udp destination=128.66.0.7/32 destination_port=53"),
        "{egress}"
    );
}

#[test]
fn missing_reject_companion_withdraws_the_allow_before_repair() {
    // A reject companion that VANISHED (not just mismatched) must also
    // trigger allow withdrawal: the destination has no reject in the
    // removals set, so a repair driven only by removed rules would try to
    // add the missing reject while the unrestricted allow stays installed —
    // a failed addition would leave direct DNS/DoT open.
    let (client, log) = applied_client("running", "sbx-1");
    let (network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            60,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("first refresh");
    let statedir = log.parent().expect("statedir").to_path_buf();
    // Delete the udp/53 reject companion entirely.
    let path = statedir.join("acls").join(format!("{acl}.egress"));
    let rules = fs::read_to_string(&path).unwrap();
    let without: Vec<&str> = rules
        .lines()
        .filter(|line| {
            !(line.contains("action=reject")
                && line.contains("destination=128.66.0.7/32")
                && line.contains("destination_port=53")
                && line.contains("protocol=udp"))
        })
        .collect();
    assert_eq!(without.len() + 1, rules.lines().count());
    fs::write(&path, without.join("\n") + "\n").unwrap();
    // Re-adding the companion fails: the overlapping allow must be gone.
    fs::write(statedir.join("fail-acl-rule-add-reject"), "").unwrap();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            60,
        )])],
    );
    let before = log_lines(&log).len();
    let err = refresh(&client, "sbx-1", &policy, &hash, &transport).unwrap_err();
    assert_eq!(err.code, SandboxErrorCode::Internal);
    let window = &log_lines(&log)[before..];
    assert!(
        window
            .iter()
            .any(|line| line.contains("network acl rule remove")
                && line.contains("128.66.0.7")
                && !line.contains("action=")),
        "the overlapping allow is withdrawn before the repair: {}",
        window.join("\n")
    );
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("action=allow destination=128.66.0.7/32"),
        "no unrestricted DNS/DoT allow remains: {egress}"
    );
    assert!(
        !egress
            .contains("action=reject protocol=udp destination=128.66.0.7/32 destination_port=53"),
        "the failed re-add did not partially land: {egress}"
    );
    assert!(
        !window.iter().any(|line| is_dns_publish(line, &network)),
        "no republication"
    );
    // Recovery: the next refresh restores the full rule set.
    fs::remove_file(statedir.join("fail-acl-rule-add-reject")).unwrap();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            60,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("retry completes");
    let egress = acl_egress(&log, &acl);
    assert!(
        egress.contains("action=allow destination=128.66.0.7/32")
            && egress.contains(
                "action=reject protocol=udp destination=128.66.0.7/32 destination_port=53"
            ),
        "{egress}"
    );
}

#[test]
fn refresh_refuses_an_injected_dynamic_ingress_rule() {
    // A dynamically tagged INGRESS rule escapes the egress-only diff and the
    // static check's dynamic exclusion: it must be refused outright, never
    // ratified into the persisted plan reconnect trusts.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let ingress_path = log
        .parent()
        .expect("statedir")
        .join("acls")
        .join(format!("{acl}.ingress"));
    let body = fs::read_to_string(&ingress_path).expect("ingress");
    fs::write(
        &ingress_path,
        format!("{body}action=allow description=wssp-dns-g0-deadbeef\n"),
    )
    .expect("inject");
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            60,
        )])],
    );
    let before = log_lines(&log).len();
    let err = refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect_err("dynamic ingress rule refuses the refresh");
    assert_eq!(err.code, SandboxErrorCode::Internal);
    let window = &log_lines(&log)[before..];
    assert!(
        !window
            .iter()
            .any(|line| line.contains("network acl rule") || line.contains("PATCH")),
        "zero mutations: {}",
        window.join("\n")
    );
    let recorded = client
        .persisted_plan_rules("sbx-1", &hash)
        .expect("recorded plan");
    assert!(
        recorded
            .iter()
            .all(|rule| rule.description != "wssp-dns-g0-deadbeef"),
        "the injected rule never became trusted reconnect state"
    );
}

#[test]
fn refresh_refuses_a_static_rule_moved_between_directions() {
    // Direction is part of a static rule's identity: an egress rule moved to
    // ingress is drift, and the refresh must refuse it.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let statedir = log.parent().expect("statedir").to_path_buf();
    let egress_path = statedir.join("acls").join(format!("{acl}.egress"));
    let ingress_path = statedir.join("acls").join(format!("{acl}.ingress"));
    let egress = fs::read_to_string(&egress_path).expect("egress");
    let mut lines: Vec<&str> = egress.lines().collect();
    let moved = lines.pop().expect("a static rule to move");
    fs::write(&egress_path, lines.join("\n") + "\n").expect("rewrite egress");
    let ingress = fs::read_to_string(&ingress_path).expect("ingress");
    fs::write(&ingress_path, format!("{ingress}{moved}\n")).expect("move");
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            60,
        )])],
    );
    let before = log_lines(&log).len();
    let err = refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect_err("a direction move is drift");
    assert_eq!(err.code, SandboxErrorCode::Internal);
    let window = &log_lines(&log)[before..];
    assert!(
        !window
            .iter()
            .any(|line| line.contains("network acl rule") || line.contains("PATCH")),
        "zero mutations: {}",
        window.join("\n")
    );
    assert!(
        client.persisted_plan_rules("sbx-1", &hash).is_some(),
        "the recorded plan is unchanged"
    );
}

#[test]
fn publication_past_the_argv_limit_uses_stdin() {
    // A permitted policy at the record bound (128 forty-character names x 32
    // shared addresses = 4096 records) renders ~280 KiB of raw.dnsmasq —
    // past Linux's per-argument limit (MAX_ARG_STRLEN, 128 KiB on 4 KiB-page
    // hosts). Publication must travel over a stdin-bodied config PATCH and
    // read back exactly.
    let (client, log) = applied_client("running", "sbx-1");
    let (network, _acl) = sandbox_network_names("sbx-1");
    let answers: Vec<(String, Vec<Ipv4Addr>)> = (0..128)
        .map(|i| {
            (
                format!("d{i:029}.example.com"),
                (0..32).map(|j| Ipv4Addr::new(128, 66, 1, j)).collect(),
            )
        })
        .collect();
    let content = super::dns::render_dnsmasq_config(&answers, 60);
    assert!(
        content.len() > 131_072,
        "the publication exceeds MAX_ARG_STRLEN: {} bytes",
        content.len()
    );
    let before = log_lines(&log).len();
    client
        .publish_dnsmasq_config_within(&network, &content, None)
        .expect("stdin-bodied publication");
    assert_eq!(
        raw_dnsmasq(&log, &network),
        content,
        "the readback equals the full publication"
    );
    let window = &log_lines(&log)[before..];
    assert_eq!(
        window
            .iter()
            .filter(|line| is_dns_publish(line, &network))
            .count(),
        1,
        "one stdin-bodied publication: {}",
        window.join("\n")
    );
    assert!(
        !window.iter().any(|line| line.contains("network set")),
        "argv never carries the payload: {}",
        window.join("\n")
    );
    assert!(
        window
            .iter()
            .filter(|line| is_dns_publish(line, &network))
            .all(|line| line.contains(" --data-file - ") && !line.contains(" -d ")),
        "the body travels on stdin via `--data-file -` (E-26): {}",
        window.join("\n")
    );
}

/// E-26 shim fidelity: `incus query -d @-` never read stdin in any Incus
/// release (6.0-7.5.1 json-decode the `-d` value, else send it as a JSON
/// string), so the fake rejects it the way the real network endpoint does.
/// A regression to `-d @-` cannot pass the shim tests.
#[test]
fn shim_rejects_the_at_stdin_data_form() {
    let (client, log) = applied_client("running", "sbx-1");
    let (network, _acl) = sandbox_network_names("sbx-1");
    let before = raw_dnsmasq(&log, &network);
    let path = super::acl::network_url(&network, &client.project);
    let out = client
        .run_with_stdin_timed(
            &["query", "--raw", "-X", "PATCH", "-d", "@-", path.as_str()],
            br#"{"config":{"raw.dnsmasq":"server=/x/"}}"#,
            false,
            Duration::from_secs(10),
        )
        .expect("shim ran");
    assert!(
        out.stdout.contains("cannot unmarshal string") && out.stdout.contains("400"),
        "`-d @-` sends the literal string and is rejected: {out:?}"
    );
    assert_eq!(raw_dnsmasq(&log, &network), before, "nothing was published");
}

/// E-26: an incus CLI older than 7.4 has no `query --data-file`. It rejects
/// the flag while parsing arguments (no request sent), and an in-bound
/// small policy is retried as an inline `-d <json>` body that publishes and
/// reads back exactly.
#[test]
fn publication_without_data_file_falls_back_to_an_inline_body() {
    let (client, log) = applied_client("running", "sbx-1");
    let (network, _acl) = sandbox_network_names("sbx-1");
    fs::write(
        log.parent()
            .expect("statedir")
            .join("cli-without-data-file"),
        "",
    )
    .expect("old cli knob");
    let answers = vec![(
        "example.com".to_string(),
        vec![Ipv4Addr::new(128, 66, 1, 7)],
    )];
    let content = super::dns::render_dnsmasq_config(&answers, 60);
    let before = log_lines(&log).len();
    client
        .publish_dnsmasq_config_within(&network, &content, Some(Duration::from_secs(20)))
        .expect("inline publication on a pre-7.4 CLI");
    assert_eq!(raw_dnsmasq(&log, &network), content, "readback is exact");
    client
        .clone()
        .publish_dnsmasq_config_within(&network, &content, Some(Duration::from_secs(20)))
        .expect("cached inline publication on a cloned client");
    let window = &log_lines(&log)[before..];
    let publishes: Vec<&String> = window
        .iter()
        .filter(|line| is_dns_publish(line, &network))
        .collect();
    assert_eq!(
        publishes.len(),
        3,
        "two publications: one rejected data-file attempt, then two inline spawns: {window:?}"
    );
    assert!(publishes[0].contains(" --data-file - "), "{window:?}");
    for publish in &publishes[1..] {
        assert!(
            publish.contains(" -d {") && !publish.contains("--data-file"),
            "{window:?}"
        );
    }
}

/// E-26: on a pre-7.4 CLI a body past `INLINE_QUERY_BODY_MAX` cannot travel
/// at all; it fails closed with a message naming the requirement, and is
/// never put on argv.
#[test]
fn oversize_publication_without_data_file_fails_closed() {
    let (client, log) = applied_client("running", "sbx-1");
    let (network, _acl) = sandbox_network_names("sbx-1");
    fs::write(
        log.parent()
            .expect("statedir")
            .join("cli-without-data-file"),
        "",
    )
    .expect("old cli knob");
    let before_raw = raw_dnsmasq(&log, &network);
    let content = "x".repeat(super::client::INLINE_QUERY_BODY_MAX + 1);
    let before = log_lines(&log).len();
    let err = client
        .publish_dnsmasq_config_within(&network, &content, None)
        .expect_err("cannot carry the body");
    assert_eq!(err.code, SandboxErrorCode::Internal, "{err}");
    assert!(err.message.contains("Incus 7.4"), "{err}");
    assert_eq!(raw_dnsmasq(&log, &network), before_raw, "unchanged");
    let window = &log_lines(&log)[before..];
    assert!(
        !window.iter().any(|line| line.contains(" -d ")),
        "the oversize body never reaches argv: {window:?}"
    );
}

#[test]
fn reconciling_before_the_deferred_apply_keeps_the_fence() {
    // C36 r15: absence before an accepted daemon-side apply is not
    // completion evidence. Queue the TTL-40 grant's uncertain allow, advance
    // to +65s, reconcile while absent, and only then replay the old request.
    let (mut client, log) = applied_client("running", "sbx-1");
    let clock = DnsTestClock::install(&mut client);
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            40,
        )])],
    );
    let statedir = log.parent().expect("statedir").to_path_buf();
    // The daemon accepts the request but the transport loses its reply.
    // Explicit replay controls the apply independently of TTL time.
    fs::write(statedir.join("defer-acl-allow-add-fail"), "queue").unwrap();
    let outcome = refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("refresh completes with the uncertain grant fenced");
    assert!(
        outcome
            .denied_names
            .iter()
            .any(|name| name == "grants.example.com"),
        "{:?}",
        outcome.denied_names
    );
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    assert!(marker_path.exists(), "the uncertain mutation is journaled");
    // Either fence family (refresh- or lease-installed, C36 r18 F1).
    let quarantined = |egress: &str| fence_present(egress, "128.66.0.7/32");
    // Reconcile after expiry, BEFORE the accepted daemon apply lands:
    // absence is observed, but the pending entry must NOT retire.
    clock.advance(65);
    transport.script("grants.example.com", [FakeDnsOutcome::Rcode(3)]);
    refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("the early reconciling refresh completes");
    let marker = fs::read_to_string(&marker_path)
        .expect("absence is not proof: the pending fence survives the early reconcile");
    assert!(
        marker.contains("128.66.0.7/32"),
        "pending mutation retained: {marker}"
    );
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("action=allow destination=128.66.0.7/32"),
        "no allow yet: {egress}"
    );
    assert!(
        quarantined(&egress),
        "the destination-wide quarantine holds: {egress}"
    );
    // Stop the watcher so it cannot consume the late allow before the
    // assertion, then land the old request behind the quarantine on EVERY
    // port (TCP/443 included).
    client.debug_reset_dns_lease_owner("sbx-1");
    land_queued_acl_requests(&log, "add");
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let egress = acl_egress(&log, &acl);
        if egress.contains("action=allow destination=128.66.0.7/32") {
            assert!(
                quarantined(&egress),
                "the late-applied allow lands behind the quarantine: {egress}"
            );
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the deferred daemon-side apply lands: {egress}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    // NOW reconciliation has definitive evidence: present -> withdrawn.
    refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("the post-apply refresh reconciles");
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "late-applied allow and quarantine withdrawn: {egress}"
    );
    assert!(
        !marker_path.exists(),
        "marker cleared once the pending mutation is definitively withdrawn"
    );
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn cancellation_during_an_allow_mutation_preserves_the_pending_journal() {
    // C36 r15/r16: cancel the permit DURING a live grant's allow mutation,
    // with a genuinely DEFERRED daemon-side apply behind it. The intent is
    // journaled BEFORE issuance, and the destination-wide quarantine is
    // installed through an INDEPENDENTLY bounded client — the revoked
    // issuing permit cannot leave the destination unprotected while
    // nothing has lapsed for the still-live 300s grant. The deferred apply
    // then lands BEHIND the quarantine, and a later refresh (fresh permit)
    // withdraws the observed rule and retires the pending entry on that
    // definitive evidence.
    let (mut client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    let permit = std::sync::Arc::new(crate::RuntimePermit::default());
    client.cancelled = Some(permit.clone());
    let statedir = log.parent().expect("statedir").to_path_buf();
    // The daemon accepts the allow and applies it at +20s; the CLI stalls
    // forever and is killed by the cancellation.
    fs::write(statedir.join("defer-acl-allow-add"), "20").unwrap();
    std::thread::scope(|scope| {
        let running = scope.spawn(|| refresh(&client, "sbx-1", &policy, &hash, &transport));
        // Cancel while the allow mutation is in flight — but only once the
        // shim's detached "daemon" applier is ARMED in its own session. The
        // old fixed 2 s sleep after the CLI's log line raced the shim under
        // host load: the group kill could land before the applier escaped
        // the CLI's process group, so the deferred apply never happened
        // (also flaky before this fix).
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        while !statedir.join("defer-acl-allow-add.armed").exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "the allow mutation started and its deferred apply armed"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        permit.revoke();
        running
            .join()
            .expect("refresh thread")
            .expect_err("cancelling mid-mutation fails the refresh");
    });
    // The pending mutation is durable even though the pass errored (the
    // readback ran through the revoked permit): the marker fences
    // readiness for the destination.
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    let marker = fs::read_to_string(&marker_path)
        .expect("the pending mutation is journaled BEFORE issuance");
    assert!(
        marker.contains("grants.example.com") && marker.contains("128.66.0.7/32"),
        "pending mutation survives the error path: {marker}"
    );
    // Either fence family (refresh- or lease-installed, C36 r18 F1).
    let quarantined = |egress: &str| fence_present(egress, "128.66.0.7/32");
    // The quarantine installed DESPITE the revoked issuing permit (C36
    // r16 F1: through the permit-free fence client).
    let egress = acl_egress(&log, &acl);
    assert!(
        quarantined(&egress),
        "the quarantine is installed even though the issuing permit is revoked: {egress}"
    );
    // The deferred daemon-side apply lands behind the quarantine.
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let egress = acl_egress(&log, &acl);
        if egress.contains("action=allow destination=128.66.0.7/32") {
            assert!(
                quarantined(&egress),
                "the late-applied allow lands behind the quarantine: {egress}"
            );
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the deferred daemon-side apply lands: {egress}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    // Reconcile with a fresh permit: the observed rule is withdrawn and the
    // pending entry retires on that definitive evidence.
    client.cancelled = Some(std::sync::Arc::new(crate::RuntimePermit::default()));
    transport.script("grants.example.com", [FakeDnsOutcome::Rcode(3)]);
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("reconciling refresh");
    assert!(
        !marker_path.exists(),
        "marker cleared once the pending rule was observed and withdrawn"
    );
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "allow and quarantine withdrawn: {egress}"
    );
}

#[test]
fn ttl_floor_grants_schedule_refresh_by_remaining_lifetime() {
    // C36 r15: a TTL-30 answer followed by ~16s of enforcement and ~5s of
    // publication has ~9-14s left at completion — the returned delay AND
    // the published local-ttl must be capped by the REMAINING lifetime,
    // never rounded up to the 30s churn floor (a caller honoring a 30s
    // delay would leave the old address allowed past expiry). Expiry is
    // anchored at ANSWER time, so the delayed resolution below does not
    // count — the slow ACL additions do.
    let (mut client, log) = applied_client("running", "sbx-1");
    let clock = DnsTestClock::install(&mut client);
    let (_network, _acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [
            FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 7), 30)]),
            FakeDnsOutcome::Answer(vec![]), // AAAA NODATA
        ],
    );
    let statedir = log.parent().expect("statedir").to_path_buf();
    fs::write(statedir.join("slow-acl-ops"), "4").unwrap();
    fs::write(statedir.join("slow-publish"), "5").unwrap();
    let timed = LogicalDnsTransport {
        inner: &transport,
        clock: &clock,
        delays: std::sync::Mutex::new([2, 0].into()),
    };
    let outcome = refresh(&client, "sbx-1", &policy, &hash, &timed)
        .expect("a TTL-30 grant with delayed resolution publishes");
    assert_eq!(outcome.published_names, 1);
    let secs = outcome.refresh_after.as_secs();
    assert_eq!(
        secs, 5,
        "five additions consume 20s and the PATCH consumes 5s"
    );
    let state = fs::read_to_string(statedir.join("host-state/dns-policy/sbx-1.json"))
        .expect("state persisted");
    // The published local-ttl is rendered just before the PATCH, the
    // returned delay at completion — both capped by the remaining lifetime
    // (strictly below the 30s churn floor), never floored up.
    let published_ttl: u64 = state
        .split("\\n")
        .find_map(|line| line.strip_prefix("local-ttl="))
        .expect("published local-ttl present")
        .parse()
        .expect("numeric local-ttl");
    assert_eq!(
        published_ttl, 0,
        "guest caches cannot outlive a policy rotation"
    );
    assert!(
        !statedir
            .join("host-state/dns-revocations/sbx-1.json")
            .exists(),
        "no revocation marker"
    );
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn failure_cleanup_preserves_quarantines_for_pending_mutations() {
    // C36 r16 F2: a pending deferred mutation's quarantine must survive
    // failure-path expiry cleanup. Refresh#0 leaves grant A fenced with a
    // pending deferred mutation (quarantine installed) and grant B live.
    // Refresh#1 re-answers B with a TTL<=30 (ABSOLUTE lapse only — no churn
    // floor) so B expires DURING refresh#1's failed 20s publication: the
    // cleanup loop then runs a revoke-only replacement pass. Pre-fix that
    // pass built its desired set only from surviving grants and stripped
    // A's quarantine; post-fix the quarantine is preserved and A's late
    // apply stays denied.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) =
        domain_policy(&["aaa-pending.example.com", "zzz-lapsing.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    let statedir = log.parent().expect("statedir").to_path_buf();
    // B installs FIRST, without the defer pin (the pin stalls EVERY allow
    // add — B must already be in place so only A's mutation defers).
    transport.script("aaa-pending.example.com", [FakeDnsOutcome::Rcode(3)]);
    transport.script(
        "zzz-lapsing.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("B installs");
    assert!(
        acl_egress(&log, &acl).contains("action=allow destination=128.66.0.8/32"),
        "B installed"
    );
    // Refresh#0b: A's allow defers daemon-side 90s and is killed at its
    // 40s deadline (fenced uncertain, quarantine installed, pending entry
    // journaled); B re-answers unchanged (no rule churn) and publishes
    // cleanly.
    transport.script(
        "aaa-pending.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            40,
        )])],
    );
    transport.script(
        "zzz-lapsing.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            300,
        )])],
    );
    fs::write(statedir.join("defer-acl-allow-add"), "90").unwrap();
    let outcome = refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("refresh#0 completes with A fenced");
    assert!(
        outcome
            .denied_names
            .iter()
            .any(|name| name == "aaa-pending.example.com"),
        "{:?}",
        outcome.denied_names
    );
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    let marker = fs::read_to_string(&marker_path).expect("pending mutation journaled");
    assert!(
        marker.contains("aaa-pending.example.com") && marker.contains("128.66.0.7/32"),
        "{marker}"
    );
    // Either fence family (refresh- or lease-installed, C36 r18 F1).
    let quarantined = |egress: &str| fence_present(egress, "128.66.0.7/32");
    let egress = acl_egress(&log, &acl);
    assert!(quarantined(&egress), "quarantine installed: {egress}");
    assert!(
        egress.contains("action=allow destination=128.66.0.8/32"),
        "B installed: {egress}"
    );
    // Refresh#1: A is withdrawn from the policy answers (NXDOMAIN — the
    // pending entry is NOT retired by absence), B is re-answered with the
    // same address and TTL 15 (floor-clamped to the 30s churn floor; a
    // floor-clamped grant lapses ABSOLUTELY), and the 35s publication
    // FAILS: B lapses mid-PATCH, so the failure cleanup runs a revoke-only
    // replacement while A's quarantine is pending.
    fs::write(statedir.join("fail-raw-dnsmasq"), "").unwrap();
    fs::write(statedir.join("slow-publish"), "35").unwrap();
    transport.script("aaa-pending.example.com", [FakeDnsOutcome::Rcode(3)]);
    transport.script(
        "zzz-lapsing.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            15,
        )])],
    );
    let err = refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect_err("publication fails; B lapses during the slow PATCH");
    let _ = err;
    let egress = acl_egress(&log, &acl);
    assert!(
        quarantined(&egress),
        "the pending mutation's quarantine survives failure cleanup: {egress}"
    );
    assert!(
        !egress.contains("128.66.0.8"),
        "the lapsed grant B is withdrawn by the cleanup: {egress}"
    );
    let marker = fs::read_to_string(&marker_path).expect("marker retained");
    assert!(
        marker.contains("aaa-pending.example.com") && marker.contains("128.66.0.7/32"),
        "pending mutation recorded: {marker}"
    );
    // A's deferred apply lands at +90s — behind the preserved quarantine.
    let deadline = std::time::Instant::now() + Duration::from_secs(80);
    loop {
        let egress = acl_egress(&log, &acl);
        if egress.contains("action=allow destination=128.66.0.7/32") {
            assert!(
                quarantined(&egress),
                "the deferred allow lands behind the preserved quarantine: {egress}"
            );
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the deferred daemon-side apply lands: {egress}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    // Reconcile: the observed pending rule is withdrawn and retires; the
    // marker clears. Publication recovers once the pins are removed.
    fs::remove_file(statedir.join("fail-raw-dnsmasq")).unwrap();
    fs::remove_file(statedir.join("slow-publish")).unwrap();
    transport.script("aaa-pending.example.com", [FakeDnsOutcome::Rcode(3)]);
    transport.script("zzz-lapsing.example.com", [FakeDnsOutcome::Rcode(3)]);
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("reconciling refresh");
    assert!(!marker_path.exists(), "marker cleared after reconciliation");
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7") && !egress.contains("128.66.0.8"),
        "everything withdrawn: {egress}"
    );
}

#[test]
fn a_regrant_does_not_reconcile_the_earlier_mutation() {
    // C36 r16 F3: uncertain queued apply -> expiry -> shorter fresh
    // re-grant -> expiry/revocation -> original late apply. The newer
    // request must never reconcile the old identity: its journal and fence
    // survive until definitive withdrawal of that old request.
    let (mut client, log) = applied_client("running", "sbx-1");
    let clock = DnsTestClock::install(&mut client);
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            40,
        )])],
    );
    let statedir = log.parent().expect("statedir").to_path_buf();
    fs::write(statedir.join("defer-acl-allow-add-fail"), "queue").unwrap();
    let outcome = refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("refresh completes with the uncertain grant fenced");
    assert!(
        outcome
            .denied_names
            .iter()
            .any(|name| name == "grants.example.com"),
        "{:?}",
        outcome.denied_names
    );
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    assert!(marker_path.exists(), "pending mutation journaled");
    // Either fence family (refresh- or lease-installed, C36 r18 F1).
    let quarantined = |egress: &str| fence_present(egress, "128.66.0.7/32");
    // Re-grant the same address with a shorter TTL: the new-generation
    // allow installs, the quarantine is suppressed while granted — and the
    // OLD pending entry is NOT retired. The pin is removed so the RE-GRANT's
    // add proceeds normally; the original request stays queued with its
    // OLD generation tag after its TTL expires.
    fs::remove_file(statedir.join("defer-acl-allow-add-fail")).unwrap();
    client.debug_reset_dns_lease_owner("sbx-1");
    clock.advance(40);
    client
        .recover_dns_expiry_obligations("sbx-1")
        .expect("settle the original expiry before the shorter re-grant");
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            30,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("re-granting refresh");
    let marker = fs::read_to_string(&marker_path)
        .expect("the re-grant does not retire the older pending mutation");
    assert!(
        marker.contains("128.66.0.7/32"),
        "stale pending entry retained: {marker}"
    );
    let egress = acl_egress(&log, &acl);
    assert!(
        egress.lines().any(|line| {
            line.contains("action=allow destination=128.66.0.7/32") && line.contains("wssp-dns-g3-")
        }),
        "the re-grant installed a fresh durable-identity allow (C36 r17 F1): {egress}"
    );
    assert!(
        !egress.lines().any(|line| {
            line.contains("action=allow destination=128.66.0.7/32")
                && !line.contains("wssp-dns-g3-")
        }),
        "no stale-generation allow yet: {egress}"
    );
    // The re-grant expires (30s) and the next refresh revokes it: the
    // quarantine returns BEFORE the stale allow can be useful.
    transport.script("grants.example.com", [FakeDnsOutcome::Rcode(3)]);
    client.debug_reset_dns_lease_owner("sbx-1");
    clock.advance(30);
    client
        .recover_dns_expiry_obligations("sbx-1")
        .expect("settle the shorter re-grant before revocation");
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("revoking refresh");
    let egress = acl_egress(&log, &acl);
    assert!(
        quarantined(&egress),
        "the quarantine returns once the re-grant is revoked: {egress}"
    );
    assert!(
        !egress.contains("action=allow destination=128.66.0.7/32"),
        "no allow installed: {egress}"
    );
    assert!(marker_path.exists(), "still fenced pending the stale apply");
    // Land the ORIGINAL request behind the quarantine, with the OLD
    // generation tag. Stop autonomous repair until the assertion observes it.
    client.debug_reset_dns_lease_owner("sbx-1");
    land_queued_acl_requests(&log, "add");
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let egress = acl_egress(&log, &acl);
        let stale_allow = egress.lines().any(|line| {
            line.contains("action=allow destination=128.66.0.7/32")
                && !line.contains("wssp-dns-g3-")
        });
        if stale_allow {
            assert!(
                quarantined(&egress),
                "the stale late apply lands behind the quarantine: {egress}"
            );
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the original deferred apply lands: {egress}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    // Reconciliation withdraws the observed stale rule and retires the
    // pending entry on that definitive evidence; the marker clears.
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("reconciling refresh");
    assert!(
        !marker_path.exists(),
        "marker cleared after definitive withdrawal"
    );
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "stale allow and quarantine withdrawn: {egress}"
    );
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn a_nonzero_exit_without_rejection_evidence_stays_uncertain() {
    // C36 r16 F4: the daemon ACCEPTS a deferred allow apply but the CLI
    // exits nonzero with a transport signature ("connection reset") before
    // acknowledging it. A nonzero exit is NOT positive evidence of a
    // daemon-side rejection: the outcome must be fenced as uncertain —
    // journaled, revoked, quarantined — and reconciled when the deferred
    // apply lands.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    let statedir = log.parent().expect("statedir").to_path_buf();
    fs::write(statedir.join("defer-acl-allow-add-fail"), "20").unwrap();
    let outcome = refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("the unacknowledged add is fenced, not fatal");
    assert!(
        outcome
            .denied_names
            .iter()
            .any(|name| name == "grants.example.com"),
        "fenced as denied: {:?}",
        outcome.denied_names
    );
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    let marker = fs::read_to_string(&marker_path)
        .expect("a nonzero exit without rejection evidence stays PENDING");
    assert!(
        marker.contains("grants.example.com") && marker.contains("128.66.0.7/32"),
        "pending mutation recorded: {marker}"
    );
    // Either fence family (refresh- or lease-installed, C36 r18 F1).
    let quarantined = |egress: &str| fence_present(egress, "128.66.0.7/32");
    let egress = acl_egress(&log, &acl);
    assert!(
        quarantined(&egress),
        "the destination is quarantined despite the nonzero exit: {egress}"
    );
    // The accepted daemon-side apply lands at +20s — behind the quarantine.
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let egress = acl_egress(&log, &acl);
        if egress.contains("action=allow destination=128.66.0.7/32") {
            assert!(
                quarantined(&egress),
                "the unacknowledged allow lands behind the quarantine: {egress}"
            );
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the deferred daemon-side apply lands: {egress}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    // Reconcile: the observed rule is withdrawn, the entry retires, the
    // marker clears.
    transport.script("grants.example.com", [FakeDnsOutcome::Rcode(3)]);
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("reconciling refresh");
    assert!(
        !marker_path.exists(),
        "marker cleared after definitive withdrawal"
    );
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "allow and quarantine withdrawn: {egress}"
    );
}

// ---------------------------------------------------------------------------
// C36 r17: durable request identities, preventive fences, the enforcement-
// level expiry lease, permission-effect mutation classification, and
// authorization-derived fence necessity.
// ---------------------------------------------------------------------------

/// True when `egress` holds a destination-wide DNS fence for `dest`.
fn fence_present(egress: &str, dest: &str) -> bool {
    // Either fence family: refresh-installed (`wssp-dns-quarantine-`) or
    // lease-installed (`wssp-dns-lease-quarantine-`) (C36 r18 F1).
    egress.lines().any(|line| {
        line.contains("action=reject")
            && line.contains(&format!("destination={dest}"))
            && line.contains("quarantine-")
            && !line.contains("destination_port")
    })
}

#[test]
fn an_interrupted_rotation_allocates_a_fresh_durable_identity() {
    // C36 r17 F1 (rotation direction): an address change whose allow
    // mutation is interrupted mid-flight leaves a journaled pending entry;
    // the retry BEFORE the original deferred request lands must allocate a
    // FRESH generation from the crash-durable marker counter — never
    // reissue the in-flight identity.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("initial grant commits");
    let statedir = log.parent().expect("statedir").to_path_buf();
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    // The address rotates to .9; the allow add is deferred daemon-side and
    // the CLI is killed at its bounded deadline.
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 9),
            40,
        )])],
    );
    fs::write(statedir.join("defer-acl-allow-add"), "90").unwrap();
    let outcome = refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("refresh completes with the uncertain grant fenced");
    assert!(
        outcome
            .denied_names
            .iter()
            .any(|name| name == "grants.example.com"),
        "the interrupted grant is denied, never served: {:?}",
        outcome.denied_names
    );
    let marker = fs::read_to_string(&marker_path).expect("pending mutation journaled");
    assert!(
        marker.contains("wssp-dns-g3-"),
        "the interrupted request carried a fresh generation 3 (C36 r26 F1: the \
         first issuance consumes a durable identity; C36 r27 F1: its \
         preventive-fence epoch survives the marker clear in the floor): {marker}"
    );
    assert!(
        marker.contains("next_request"),
        "the identity counter is crash-durable: {marker}"
    );
    // Retry BEFORE the deferred apply lands (defer 90s): the same .9 answer
    // re-grants under a FRESH generation — a non-durable counter would
    // reissue the interrupted identity.
    fs::remove_file(statedir.join("defer-acl-allow-add")).unwrap();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 9),
            300,
        )])],
    );
    // The interrupted grant's expiry (TTL 40) can fire while this
    // refresh is in flight: its expiry settle releases the armed entry's
    // fence and the commit's live-ACL validation lawfully REFUSES
    // (fail closed — a rule the refreshed plan expects is gone) when the
    // settle interposes between planning and commit. The refusal is
    // retryable by design: a fresh pass re-derives from the settled
    // truth. Scripts are consumed per query, so re-script per attempt.
    let mut attempts = 0;
    loop {
        match refresh(&client, "sbx-1", &policy, &hash, &transport) {
            Ok(_) => break,
            Err(err) => {
                attempts += 1;
                assert!(attempts < 8, "re-granting refresh: {err:?}");
                transport.script(
                    "grants.example.com",
                    [
                        FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
                            Ipv4Addr::new(128, 66, 0, 9),
                            300,
                        )]),
                        FakeDnsOutcome::Rcode(3),
                    ],
                );
                std::thread::sleep(Duration::from_secs(2));
            }
        }
    }
    let egress = acl_egress(&log, &acl);
    let retry_tag = egress
        .lines()
        .find(|line| line.contains("action=allow destination=128.66.0.9/32"))
        .and_then(|line| {
            line.split_whitespace()
                .find(|token| token.starts_with("description="))
        })
        .map(|token| token.trim_start_matches("description=").to_string())
        .expect("the retry installed an allow");
    assert!(
        retry_tag != "wssp-dns-g3-2db8f324" && retry_tag != "wssp-dns-g0-2db8f324",
        "the retry allocated a fresh durable identity, not a reused one: {retry_tag}"
    );
    let marker = fs::read_to_string(&marker_path).expect("stale pending entry retained");
    assert!(
        marker.contains("wssp-dns-g3-"),
        "the retry does not retire the earlier pending mutation: {marker}"
    );
    // The deferred generation-3 apply lands late; a final refresh withdraws
    // it and retires the entry on definitive evidence.
    let deadline = std::time::Instant::now() + Duration::from_secs(70);
    loop {
        let egress = acl_egress(&log, &acl);
        if egress.contains("action=allow destination=128.66.0.9/32 description=wssp-dns-g3-") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the deferred generation-3 apply lands: {egress}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 9),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("reconciling refresh");
    assert!(!marker_path.exists(), "marker cleared after reconciliation");
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("wssp-dns-g3-"),
        "the stale identity is withdrawn: {egress}"
    );
    assert!(
        egress.contains(&format!(
            "action=allow destination=128.66.0.9/32 description={retry_tag}"
        )),
        "the live grant survives reconciliation: {egress}"
    );
}

#[test]
fn an_interrupted_restore_allocates_a_fresh_identity() {
    // C36 r17 F1 (restore direction): a committed rule lost daemon-side is
    // restored under a FRESH generation — the restore must not reuse the
    // identity a still-deferred earlier request may be carrying. Interrupt
    // the restore itself and the retry must be fresh again.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("initial grant commits");
    let statedir = log.parent().expect("statedir").to_path_buf();
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    // The daemon loses one reject companion (no host-side record of it).
    let egress_path = statedir.join("acls").join(format!("{acl}.egress"));
    let body = fs::read_to_string(&egress_path).expect("egress rules");
    let mut lines: Vec<&str> = body.lines().collect();
    let pos = lines
        .iter()
        .position(|line| line.contains("wssp-dns-reject-") && line.contains("protocol=udp"))
        .expect("udp reject companion present");
    lines.remove(pos);
    fs::write(&egress_path, lines.join("\n") + "\n").unwrap();
    // The restore is interrupted mid-flight (deferred daemon-side apply).
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            45,
        )])],
    );
    fs::write(statedir.join("defer-acl-allow-add"), "90").unwrap();
    let outcome = refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("refresh completes with the interrupted restore fenced");
    assert!(
        outcome
            .denied_names
            .iter()
            .any(|name| name == "grants.example.com"),
        "the interrupted restore is denied, never served: {:?}",
        outcome.denied_names
    );
    let marker = fs::read_to_string(&marker_path).expect("restore journaled");
    assert!(
        marker.contains("wssp-dns-g3-"),
        "the restore carried a FRESH generation (3), not the committed 1 — the \
         first issuance's fence epoch is preserved in the floor (C36 r27 F1): {marker}"
    );
    // Retry before the deferred restore lands: fresh identity again.
    fs::remove_file(statedir.join("defer-acl-allow-add")).unwrap();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    // The interrupted restore's expiry (TTL 45) can fire while this
    // refresh is in flight: its expiry settle proves the deferred
    // allow absent and releases the armed entry's lease fence, and the
    // commit's live-ACL validation lawfully REFUSES (fail closed — a
    // rule the refreshed plan expects is gone) when the release
    // interposes between planning and commit. The refusal is retryable
    // by design: a fresh pass re-derives from the settled truth.
    // Scripts are consumed per query, so re-script per attempt.
    let mut attempts = 0;
    loop {
        match refresh(&client, "sbx-1", &policy, &hash, &transport) {
            Ok(_) => break,
            Err(err) => {
                attempts += 1;
                assert!(attempts < 8, "re-granting refresh: {err:?}");
                transport.script(
                    "grants.example.com",
                    [
                        FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
                            Ipv4Addr::new(128, 66, 0, 7),
                            300,
                        )]),
                        FakeDnsOutcome::Rcode(3),
                    ],
                );
                std::thread::sleep(Duration::from_secs(2));
            }
        }
    }
    let egress = acl_egress(&log, &acl);
    let retry_tag = egress
        .lines()
        .find(|line| line.contains("action=allow destination=128.66.0.7/32"))
        .and_then(|line| {
            line.split_whitespace()
                .find(|token| token.starts_with("description="))
        })
        .map(|token| token.trim_start_matches("description=").to_string())
        .expect("the retry installed an allow");
    assert!(
        retry_tag != "wssp-dns-g3-2db8f324" && retry_tag != "wssp-dns-g0-2db8f324",
        "the retry allocated a fresh identity, not the interrupted restore's: {retry_tag}"
    );
    // The deferred generation-3 restore lands late and is reconciled away.
    let deadline = std::time::Instant::now() + Duration::from_secs(70);
    loop {
        if acl_egress(&log, &acl)
            .contains("action=allow destination=128.66.0.7/32 description=wssp-dns-g3-")
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the deferred restore lands"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("reconciling refresh");
    assert!(!marker_path.exists(), "marker cleared after reconciliation");
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("wssp-dns-g3-"),
        "the stale restore identity is withdrawn: {egress}"
    );
    assert!(
        egress.contains(&format!(
            "action=allow destination=128.66.0.7/32 description={retry_tag}"
        )),
        "the live grant survives: {egress}"
    );
}

#[test]
fn a_daemon_crash_after_allow_issuance_leaves_the_destination_fenced() {
    // C36 r17 F2 (crash direction): the preventive fence is installed and
    // confirmed BEFORE the broadening allow is issued, so a daemon dying
    // right after issuance (here: the bounded CLI killed mid-flight while
    // the daemon applies the add 60s later) can never leave an unconfirmed
    // allow unfenced.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            40,
        )])],
    );
    let statedir = log.parent().expect("statedir").to_path_buf();
    fs::write(statedir.join("defer-acl-allow-add"), "60").unwrap();
    let outcome = refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("refresh completes with the uncertain grant fenced");
    assert!(
        outcome
            .denied_names
            .iter()
            .any(|name| name == "grants.example.com"),
        "never served: {:?}",
        outcome.denied_names
    );
    // The fence add was issued BEFORE the allow add.
    let lines = log_lines(&log);
    let fence_pos = lines
        .iter()
        .position(|line| {
            line.contains("network acl rule add")
                && line.contains("wssp-dns-quarantine-")
                && line.contains("128.66.0.7")
        })
        .expect("fence add logged");
    let allow_pos = lines
        .iter()
        .position(|line| {
            line.contains("network acl rule add")
                && line.contains("action=allow destination=128.66.0.7/32")
        })
        .expect("allow add logged");
    assert!(
        fence_pos < allow_pos,
        "the preventive fence precedes the broadening issuance"
    );
    // Immediately on return the fence is already in place — no cleanup
    // window exists in which a daemon-side apply would be unfenced.
    let egress = acl_egress(&log, &acl);
    assert!(
        fence_present(&egress, "128.66.0.7/32"),
        "the fence outlives the killed request: {egress}"
    );
    // The deferred daemon-side apply lands behind the fence.
    let deadline = std::time::Instant::now() + Duration::from_secs(50);
    loop {
        let egress = acl_egress(&log, &acl);
        if egress.contains("action=allow destination=128.66.0.7/32") {
            assert!(
                fence_present(&egress, "128.66.0.7/32"),
                "the deferred allow lands fenced: {egress}"
            );
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the deferred apply lands: {egress}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    // Reconciliation withdraws it and releases the fence once nothing
    // unauthorized remains.
    transport.script("grants.example.com", [FakeDnsOutcome::Rcode(3)]);
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("reconciling refresh");
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "stale allow withdrawn and fence released: {egress}"
    );
}

#[test]
fn a_failed_fence_install_never_issues_the_allow() {
    // C36 r17 F2 (failure direction): the preventive fence install fails —
    // the broadening allow must NEVER be issued, nothing may be committed
    // or published.
    let (client, log) = applied_client("running", "sbx-1");
    let (network, _acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            60,
        )])],
    );
    let statedir = log.parent().expect("statedir").to_path_buf();
    fs::write(statedir.join("fail-acl-fence-add"), "").unwrap();
    let err = refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect_err("a failed preventive fence fails the refresh closed");
    assert_eq!(err.code, SandboxErrorCode::Internal);
    let lines = log_lines(&log);
    assert!(
        !lines
            .iter()
            .any(|line| line.contains("network acl rule add")
                && line.contains("action=allow destination=128.66.0.7/32")),
        "the allow was never issued: {lines:?}"
    );
    assert!(
        !lines.iter().any(|line| is_dns_publish(line, &network)),
        "nothing published: {lines:?}"
    );
    assert!(
        !statedir.join("host-state/dns/sbx-1.json").exists(),
        "nothing committed"
    );
}

#[test]
fn the_expiry_lease_withdraws_a_stalled_grant_at_its_absolute_expiry() {
    // C36 r17 F3: a TTL-45 grant whose publication stalls (90s slow PATCH,
    // killed at the remaining-lifetime deadline) must stop being effective
    // AT its absolute expiry even though the refresh is still working —
    // here the post-lapse withdrawal pass is stretched to 15s per removal,
    // so only the enforcement-level lease can withdraw the rules on time.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            45,
        )])],
    );
    let statedir = log.parent().expect("statedir").to_path_buf();
    fs::write(statedir.join("slow-publish"), "90").unwrap();
    let start = std::time::Instant::now();
    let running = std::thread::scope(|scope| {
        let refresh_thread = scope.spawn(|| refresh(&client, "sbx-1", &policy, &hash, &transport));
        // Wait for the allow to be installed (fast adds), then let the
        // publish stall begin.
        let deadline = start + Duration::from_secs(30);
        while !acl_egress(&log, &acl).contains("action=allow destination=128.66.0.7/32") {
            assert!(
                std::time::Instant::now() < deadline,
                "the grant is installed before the stall"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        // The grant expires ~45s after resolution. The enforcement-level
        // lease must withdraw the allow within seconds of that absolute
        // expiry, while the refresh is still inside its stalled
        // publication/cleanup (the 90s PATCH is killed at the
        // remaining-lifetime deadline, which is itself part of the fix).
        let gone_by = start + Duration::from_secs(56);
        loop {
            let egress = acl_egress(&log, &acl);
            if !egress.contains("action=allow destination=128.66.0.7/32") {
                break;
            }
            assert!(
                std::time::Instant::now() < gone_by,
                "the lease withdrew the allow at its absolute expiry: {egress}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        // Assert CONTINUOUS denial past expiry until the refresh returns.
        while !refresh_thread.is_finished() {
            let egress = acl_egress(&log, &acl);
            assert!(
                !egress.contains("action=allow destination=128.66.0.7/32"),
                "denial holds continuously past expiry: {egress}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        refresh_thread.join().expect("refresh thread")
    });
    // Publication was killed at the grant's deadline: the refresh reports
    // the failure; the lapsed grant is revoked and withdrawn regardless.
    let err = running.expect_err("the stalled publication fails");
    assert!(
        matches!(
            err.code,
            SandboxErrorCode::Internal
                | SandboxErrorCode::UnknownOutcome
                | SandboxErrorCode::Timeout
        ),
        "publication failure surfaces: {err:?}"
    );
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "the lapsed grant is withdrawn: {egress}"
    );
    let marker = fs::read_to_string(statedir.join("host-state/dns-revocations/sbx-1.json"))
        .expect("the lapsed grant's revocation is recorded durably");
    assert!(
        marker.contains("grants.example.com"),
        "revocation recorded: {marker}"
    );
}

#[test]
fn a_deferred_fence_release_cannot_strike_a_reissued_fence() {
    // C36 r17 F4: the fence release is a BROADENING removal — journaled
    // pre-issuance, retried until definitive, and a fence that is needed
    // again while its release is unresolved is re-issued under a FRESH
    // epoch. A removal the daemon accepted but applied late can only ever
    // strike the OLD identity.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    let statedir = log.parent().expect("statedir").to_path_buf();
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    // Refresh 1: the fence release removal is accepted by the daemon but
    // applied 60s late with a transport-signature failure (uncertain).
    fs::write(statedir.join("defer-acl-rule-remove"), "60").unwrap();
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("grant commits");
    let egress = acl_egress(&log, &acl);
    assert!(
        fence_present(&egress, "128.66.0.7/32"),
        "an unproven release keeps the fence installed: {egress}"
    );
    let marker = fs::read_to_string(&marker_path).expect("release journaled");
    assert!(
        marker.contains("FenceRelease") && marker.contains("wssp-dns-quarantine-g"),
        "the uncertain release is journaled as a broadening mutation: {marker}"
    );
    // Refresh 2: revoke the grant; the release retry is deferred AGAIN
    // (second late applier), so the fence stays.
    transport.script("grants.example.com", [FakeDnsOutcome::Rcode(3)]);
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("revoking refresh");
    let egress = acl_egress(&log, &acl);
    assert!(
        fence_present(&egress, "128.66.0.7/32"),
        "the fence survives its second unproven release: {egress}"
    );
    assert!(
        !egress.contains("action=allow destination=128.66.0.7/32"),
        "the grant itself is revoked: {egress}"
    );
    // Refresh 3: re-grant the same destination. The old fence has an
    // unresolved release, so the fence for the new request is re-issued
    // under a FRESH epoch; the re-grant's own release succeeds.
    fs::remove_file(statedir.join("defer-acl-rule-remove")).unwrap();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("re-granting refresh");
    let egress = acl_egress(&log, &acl);
    let regrant_tag = egress
        .lines()
        .find(|line| line.contains("action=allow destination=128.66.0.7/32"))
        .and_then(|line| {
            line.split_whitespace()
                .find(|token| token.starts_with("description="))
        })
        .map(|token| token.trim_start_matches("description=").to_string())
        .expect("the re-grant installed an allow");
    assert!(
        regrant_tag != "wssp-dns-g0-2db8f324",
        "the re-grant carries a fresh identity: {regrant_tag}"
    );
    let quarantine_tags: Vec<String> = log_lines(&log)
        .into_iter()
        .filter(|line| line.contains("network acl rule add"))
        .filter_map(|line| {
            line.split_whitespace()
                .find(|token| token.starts_with("description=wssp-dns-quarantine-"))
                .map(|token| token.trim_start_matches("description=").to_string())
        })
        .collect();
    let unique_epochs: std::collections::BTreeSet<&String> = quarantine_tags.iter().collect();
    assert!(
        unique_epochs.len() >= 2,
        "the fence was re-issued under a FRESH epoch while its release was unresolved: {quarantine_tags:?}"
    );
    // Both deferred removals land late (+60s from their issuance); they
    // carry the OLD fence identity and can strike nothing newer: the live
    // allow is never removed.
    let appliers_done = std::time::Instant::now() + Duration::from_secs(75);
    while std::time::Instant::now() < appliers_done {
        let egress = acl_egress(&log, &acl);
        assert!(
            egress.contains(&format!(
                "action=allow destination=128.66.0.7/32 description={regrant_tag}"
            )),
            "the deferred removals never strike the live allow: {egress}"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("final refresh");
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("wssp-dns-quarantine-"),
        "no fence remains once every release is definitive: {egress}"
    );
    assert!(
        egress.contains(&format!(
            "action=allow destination=128.66.0.7/32 description={regrant_tag}"
        )),
        "the authorized allow stands: {egress}"
    );
}

#[test]
fn a_shared_destination_is_not_fenced_while_authorized_by_another_grant() {
    // C36 r17 F5 (shared-domain inverse): an unresolved uncertain allow
    // mutation for a destination does NOT hold a fence while ANY live grant
    // (any name) effectively authorizes that destination — fencing it would
    // override the legitimate grant. The stale identity is still withdrawn
    // on reconciliation once observed.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["aaa.example.com", "bbb.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "aaa.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            40,
        )])],
    );
    transport.script(
        "bbb.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("both grants commit on the shared destination");
    let statedir = log.parent().expect("statedir").to_path_buf();
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    // A's allow disappears daemon-side; its restore is deferred (the pin
    // is scoped to A's name hash — stable across generations, so it
    // catches the contested restore's fresh identity too — leaving B's
    // rules untouched).
    let egress_path = statedir.join("acls").join(format!("{acl}.egress"));
    let body = fs::read_to_string(&egress_path).expect("egress rules");
    let a_tag = dns_rule_tag("aaa.example.com", 1);
    let a_hex = a_tag
        .strip_prefix("wssp-dns-g1-")
        .expect("generation-scoped tag shape")
        .to_string();
    let kept: Vec<&str> = body
        .lines()
        .filter(|line| !(line.contains("action=allow") && line.contains(&a_tag)))
        .collect();
    assert_eq!(
        kept.len() + 1,
        body.lines().count(),
        "drained exactly A's allow"
    );
    fs::write(&egress_path, kept.join("\n") + "\n").unwrap();
    fs::write(
        statedir.join("defer-acl-allow-add-tag"),
        format!("70 {a_hex}"),
    )
    .unwrap();
    // Fake-DNS scripts are consumed per query: re-script both names so the
    // refresh re-resolves (and keeps) the same addresses. A's short TTL
    // bounds the killed add attempt to ~40s — well BEFORE the deferred
    // daemon-side apply lands (70s) — so the uncertain-path withdrawal
    // provably misses and the pending entry stays journaled for reconcile
    // (a withdrawal that positively removes the rule retires the entry
    // immediately instead).
    transport.script(
        "aaa.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            40,
        )])],
    );
    transport.script(
        "bbb.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            300,
        )])],
    );
    let outcome = refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("refresh completes with the uncertain restore handled");
    assert!(
        outcome
            .denied_names
            .iter()
            .any(|name| name == "aaa.example.com"),
        "the uncertain restore is not served: {:?}",
        outcome.denied_names
    );
    let marker = fs::read_to_string(&marker_path).expect("restore journaled");
    assert!(
        marker.contains("128.66.0.8/32"),
        "the pending mutation is journaled: {marker}"
    );
    let egress = acl_egress(&log, &acl);
    assert!(
        egress.contains("action=allow destination=128.66.0.8/32"),
        "B's grant authorizes the destination: {egress}"
    );
    assert!(
        !fence_present(&egress, "128.66.0.8/32"),
        "no fence overrides a live legitimate grant (F5): {egress}"
    );
    // The next refresh runs BEFORE the deferred restore lands: the pending
    // entry survives reconcile (absence is not proof), so the boundary
    // evaluates fence necessity with the entry outstanding — and the
    // complete effective authorization (B's live grant AND A's re-grant)
    // suppresses the fence.
    transport.script(
        "aaa.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            300,
        )])],
    );
    transport.script(
        "bbb.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            300,
        )])],
    );
    fs::remove_file(statedir.join("defer-acl-allow-add-tag")).unwrap();
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("re-granting refresh");
    let egress = acl_egress(&log, &acl);
    assert!(
        !fence_present(&egress, "128.66.0.8/32"),
        "no fence while the destination is effectively authorized (F5): {egress}"
    );
    assert!(
        fs::read_to_string(&marker_path)
            .expect("the stale entry is still journaled")
            .contains("128.66.0.8/32"),
        "the unobserved pending mutation survives reconcile"
    );
    // The deferred restore lands (behind NO fence — the destination stays
    // authorized by B) and the commit-drain or the next reconcile withdraws
    // the stale identity. Depending on the race the stale line may already
    // be drained by the time it could be observed, so the loop asserts the
    // INVARIANTS that must hold at every instant — no fence over a live
    // grant, B's allow never struck — rather than a fleeting presence.
    let stale_tag = {
        let marker = fs::read_to_string(&marker_path).expect("pending marker");
        marker
            .split('"')
            .find(|token| token.starts_with("wssp-dns-") && token.contains(&a_hex))
            .expect("journaled pending description")
            .to_string()
    };
    let deferred_window = std::time::Instant::now() + Duration::from_secs(90);
    while std::time::Instant::now() < deferred_window {
        let egress = acl_egress(&log, &acl);
        assert!(
            !fence_present(&egress, "128.66.0.8/32"),
            "the deferred apply of an authorized destination is never fenced: {egress}"
        );
        assert!(
            egress.contains(&format!(
                "action=allow destination=128.66.0.8/32 description={}",
                dns_rule_tag("bbb.example.com", 2)
            )) || egress.lines().any(|line| {
                line.contains("action=allow destination=128.66.0.8/32") && !line.contains(&a_hex)
            }),
            "B's live allow is never struck: {egress}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    transport.script(
        "aaa.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            300,
        )])],
    );
    transport.script(
        "bbb.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("reconciling refresh");
    assert!(
        !marker_path.exists(),
        "marker cleared after reconciliation: {}",
        fs::read_to_string(&marker_path).unwrap_or_default()
    );
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains(&stale_tag),
        "the stale identity is withdrawn: {egress}"
    );
    assert!(
        egress.contains("action=allow destination=128.66.0.8/32"),
        "the legitimate grants stand: {egress}"
    );
    assert!(
        !egress.contains("wssp-dns-quarantine-"),
        "no fence at any point: {egress}"
    );
}

#[test]
fn a_covering_static_cidr_suppresses_the_fence() {
    // C36 r17 F5 (covering-CIDR inverse): a destination covered by a static
    // allow CIDR is effectively authorized regardless of DNS grants, so an
    // uncertain allow mutation for it installs NO fence.
    let (client, log) = applied_client_with_cidrs("running", "sbx-1", &["128.66.0.0/24"]);
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &["128.66.0.0/24"]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            40,
        )])],
    );
    let statedir = log.parent().expect("statedir").to_path_buf();
    fs::write(statedir.join("defer-acl-allow-add"), "70").unwrap();
    let outcome = refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("refresh completes with the uncertain grant handled");
    assert!(
        outcome
            .denied_names
            .iter()
            .any(|name| name == "grants.example.com"),
        "the uncertain grant is not served: {:?}",
        outcome.denied_names
    );
    let marker = fs::read_to_string(statedir.join("host-state/dns-revocations/sbx-1.json"))
        .expect("pending mutation journaled");
    assert!(
        marker.contains("128.66.0.7/32"),
        "the uncertain mutation is journaled: {marker}"
    );
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("wssp-dns-quarantine-"),
        "a statically authorized destination is never fenced: {egress}"
    );
    // Re-refresh BEFORE the deferred apply lands: the pending entry
    // survives reconcile, so the boundary evaluates fence necessity with
    // the mutation outstanding — the covering static CIDR suppresses the
    // fence (F5).
    fs::remove_file(statedir.join("defer-acl-allow-add")).unwrap();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("re-granting refresh");
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("wssp-dns-quarantine-"),
        "a statically authorized destination is never fenced, even with an outstanding mutation: {egress}"
    );
    // The deferred apply lands — authorized by the static CIDR, so no
    // fence ever appears — and a final refresh reconciles the duplicate.
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let egress = acl_egress(&log, &acl);
        if egress
            .lines()
            .filter(|line| line.contains("action=allow destination=128.66.0.7/32"))
            .count()
            > 1
        {
            assert!(
                !egress.contains("wssp-dns-quarantine-"),
                "still no fence: {egress}"
            );
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the deferred duplicate apply lands: {egress}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("reconciling refresh");
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("wssp-dns-quarantine-"),
        "no fence at any point: {egress}"
    );
    let marker_now = fs::read_to_string(statedir.join("host-state/dns-revocations/sbx-1.json"))
        .unwrap_or_default();
    assert!(
        marker_now.is_empty(),
        "marker cleared after reconciliation: {marker_now}"
    );
}

#[test]
fn a_committed_grant_is_withdrawn_at_expiry_without_any_refresh() {
    // C36 r17 F3 (enforcement independence): with NO refresh running, the
    // lease armed by the last boundary entry withdraws the grant's rules at
    // its absolute expiry. Nothing else could withdraw them here — the
    // state commit already happened and no cleanup is in flight.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            45,
        )])],
    );
    let start = std::time::Instant::now();
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("grant commits");
    let egress = acl_egress(&log, &acl);
    assert!(
        egress.contains("action=allow destination=128.66.0.7/32"),
        "installed: {egress}"
    );
    // The grant expires ~45s after resolution; the lease must withdraw the
    // rules within seconds, with no refresh call in between.
    let deadline = start + Duration::from_secs(56);
    loop {
        let egress = acl_egress(&log, &acl);
        if !egress.contains("128.66.0.7") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the lease withdrew the committed grant at expiry: {egress}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    // Planning still records the revocation at the next refresh.
    let outcome = refresh(&client, "sbx-1", &policy, &hash, &transport).expect("refresh");
    assert!(
        outcome
            .denied_names
            .iter()
            .any(|name| name == "grants.example.com"),
        "the lapsed grant is revoked by planning too: {:?}",
        outcome.denied_names
    );
}

#[test]
fn a_positively_withdrawn_uncertain_allow_retires_its_journal_at_once() {
    // C36 r17 F4 (proven-withdrawal retirement): the deferred daemon-side
    // apply of an uncertain allow lands BEFORE the killed CLI's deadline,
    // so the uncertain path's immediate withdrawal POSITIVELY removes the
    // rule (clean exit 0: the request had already completed daemon-side,
    // and a request completes at most once). That is the same definitive
    // evidence reconcile retires on — the journaled entry must retire at
    // once; keeping it would fence readiness forever, because reconcile
    // can never observe the rule again and absence alone is not proof.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            90,
        )])],
    );
    let statedir = log.parent().expect("statedir").to_path_buf();
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    // The daemon applies the add 5s in; the killed CLI's deadline is the
    // grant's remaining lifetime (~88s), so the uncertain path's immediate
    // withdrawal observes and positively removes the landed rule. The wide
    // margin keeps the landing strictly before the budget kill.
    fs::write(statedir.join("defer-acl-allow-add"), "5").unwrap();
    let outcome = refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("refresh completes with the uncertain grant denied");
    assert!(
        outcome
            .denied_names
            .iter()
            .any(|name| name == "grants.example.com"),
        "never served: {:?}",
        outcome.denied_names
    );
    // Two legitimate interleavings: the uncertain path's own withdrawal
    // removes the landed rule (kill at ~88s, landing at ~7s), or — the
    // deadline IS the grant's expiry — the expiry lease fires first and
    // positively withdraws it instead (recording durable evidence). Either
    // way the landed rule must go promptly; poll rather than assume the
    // winner.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let egress = acl_egress(&log, &acl);
        if !egress
            .lines()
            .any(|line| line.contains("action=allow destination=128.66.0.7/32"))
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the landed rule is positively withdrawn: {egress}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    // The next refresh re-grants cleanly — nothing stale is carried: the
    // journaled entry is retired (by the withdrawal's own clean exit, or
    // by the lease's positive-withdrawal evidence via reconcile/drain), so
    // the fence releases and the marker clears.
    fs::remove_file(statedir.join("defer-acl-allow-add")).unwrap();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("re-granting refresh");
    let egress = acl_egress(&log, &acl);
    assert!(
        egress.contains("action=allow destination=128.66.0.7/32"),
        "the re-grant installs cleanly: {egress}"
    );
    assert!(
        !egress.contains("wssp-dns-quarantine-"),
        "the fence is released once the mutation is resolved: {egress}"
    );
    assert!(
        !marker_path.exists(),
        "no marker survives: {}",
        fs::read_to_string(&marker_path).unwrap_or_default()
    );
}

#[test]
fn a_lease_withdrawn_uncertain_allow_retires_on_positive_evidence() {
    // C36 r17 F3/F4 (follow-through): an uncertain allow whose CLI
    // reported a transport failure AFTER the daemon accepted it (applied
    // 20s later) is journaled and fenced. No refresh is running when the
    // grant's own expiry lease fires: the lease positively withdraws the
    // landed rule, and that positive removal — recorded durably — is the
    // definitive evidence that retires the journaled entry. Without the
    // evidence the entry could NEVER retire (the rule can never be
    // observed again; absence is not proof) and the destination would
    // stay fenced forever.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            60,
        )])],
    );
    let statedir = log.parent().expect("statedir").to_path_buf();
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    let start = std::time::Instant::now();
    fs::write(statedir.join("defer-acl-allow-add-fail"), "20").unwrap();
    let outcome = refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("refresh completes with the uncertain grant denied");
    assert!(
        outcome
            .denied_names
            .iter()
            .any(|name| name == "grants.example.com"),
        "never served: {:?}",
        outcome.denied_names
    );
    // The unproven mutation is journaled and the destination fenced.
    let marker = fs::read_to_string(&marker_path).expect("the mutation is journaled");
    assert!(
        marker.contains("128.66.0.7/32"),
        "the uncertain mutation is journaled: {marker}"
    );
    let egress = acl_egress(&log, &acl);
    assert!(
        fence_present(&egress, "128.66.0.7/32"),
        "fenced while unresolved: {egress}"
    );
    // The deferred daemon-side apply lands behind the fence (~20s).
    let deadline = start + Duration::from_secs(40);
    loop {
        let egress = acl_egress(&log, &acl);
        if egress.contains("action=allow destination=128.66.0.7/32") {
            assert!(
                fence_present(&egress, "128.66.0.7/32"),
                "the deferred allow lands fenced: {egress}"
            );
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the deferred apply lands: {egress}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    // The grant expires ~60s after resolution: the lease positively
    // withdraws the landed rule with no refresh in flight.
    let deadline = start + Duration::from_secs(80);
    loop {
        let egress = acl_egress(&log, &acl);
        if !egress
            .lines()
            .any(|line| line.contains("action=allow destination=128.66.0.7/32"))
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the lease positively withdrew the landed rule: {egress}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    // The recorded evidence lets the next refresh retire the entry and
    // release the fence — no livelock.
    fs::remove_file(statedir.join("defer-acl-allow-add-fail")).unwrap();
    transport.script("grants.example.com", [FakeDnsOutcome::Rcode(3)]);
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("reconciling refresh");
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "the fence is released once the mutation is proven resolved: {egress}"
    );
    assert!(
        !marker_path.exists(),
        "the positive-withdrawal evidence retires the journal: {}",
        fs::read_to_string(&marker_path).unwrap_or_default()
    );
}

// ---------------------------------------------------------------------
// The expiry lease is an enforcement surface. One enforced
// withdrawal boundary, a synchronized lease owner, restart-durable
// obligations.
// ---------------------------------------------------------------------

/// Lease-obligations record path for this fixture's sandbox.
fn lease_obligations_path(statedir: &Path, sandbox_id: &str) -> std::path::PathBuf {
    statedir
        .join("host-state/dns-revocations")
        .join(format!("{sandbox_id}.lease.json"))
}

/// The lease fence family renders `wssp-dns-lease-quarantine-<epoch>-<hex8>`.
fn lease_fence_present(egress: &str, dest: &str) -> bool {
    egress.lines().any(|line| {
        line.contains("action=reject")
            && line.contains(&format!("destination={dest}"))
            && line.contains("wssp-dns-lease-quarantine-")
            && !line.contains("destination_port")
    })
}

#[test]
fn a_final_authorization_expiry_restores_the_fence_around_an_unresolved_mutation() {
    // C36 r18 F1: an uncertain allow is fenced and journaled; a shorter
    // re-grant refreshes WITHOUT another refresh afterwards; the fence is
    // LOST daemon-side (drift) before the re-grant expires. When the final
    // live authorization for the destination expires, the expiry lease
    // must RESTORE a canonical fence around the still-unresolved mutation
    // — and the deferred apply then lands BEHIND it. The r17 watcher only
    // ever removed rules: the destination would sit WIDE OPEN from the
    // re-grant's expiry until the deferred allow landed.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 9),
            40,
        )])],
    );
    let statedir = log.parent().expect("statedir").to_path_buf();
    let start = std::time::Instant::now();
    // The first issuance's allow add hangs at the CLI (killed at the
    // grant's deadline — uncertain) while the daemon accepts it, applying
    // it 90s later: unresolved across the re-grant's expiry. The pin is
    // scoped to the first issuance's tag (generation 1 — C36 r26 F1) so
    // the RE-GRANT's addition is unaffected.
    let gen0_tag = dns_rule_tag("grants.example.com", 1);
    fs::write(
        statedir.join("defer-acl-allow-add-tag"),
        format!("90 {gen0_tag}"),
    )
    .unwrap();
    let outcome = refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("refresh completes with the uncertain grant denied");
    assert!(
        outcome
            .denied_names
            .iter()
            .any(|name| name == "grants.example.com"),
        "the uncertain grant is denied: {:?}",
        outcome.denied_names
    );
    let egress = acl_egress(&log, &acl);
    assert!(
        fence_present(&egress, "128.66.0.9/32"),
        "fenced while unresolved: {egress}"
    );
    // The re-grant (TTL 40, expiring BEFORE the deferred apply lands at
    // ~+90) installs a fresh identity. No refresh happens after it.
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 9),
            40,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("re-granting refresh");
    let egress = acl_egress(&log, &acl);
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow destination=128.66.0.9/32")),
        "the re-grant installed a fresh allow: {egress}"
    );
    // The re-grant CONFIRMS a fresh authorization, so the fence is
    // legitimately RELEASED — the destination sits unfenced while the
    // generation-0 mutation is still unresolved. This is exactly the
    // finding's setup: the lease must RESTORE the fence when that final
    // authorization expires; "we never released it" does not satisfy the
    // proof.
    let egress = acl_egress(&log, &acl);
    assert!(
        !fence_present(&egress, "128.66.0.9/32"),
        "the confirmed re-grant released the fence: {egress}"
    );
    // The re-grant expires ~40s after its resolution: the lease withdraws
    // it AND restores the fence around the unresolved generation-0
    // mutation. The deferred apply lands (~+90) BEHIND the restored fence.
    let deadline = start + Duration::from_secs(110);
    let mut fence_seen = false;
    loop {
        let egress = acl_egress(&log, &acl);
        let fence = fence_present(&egress, "128.66.0.9/32");
        let gen0_landed = egress.lines().any(|line| {
            line.contains("action=allow")
                && line.contains("destination=128.66.0.9/32")
                && line.contains(&format!("description={gen0_tag}"))
        });
        fence_seen |= fence;
        if gen0_landed {
            assert!(
                fence,
                "the deferred apply must land BEHIND the restored fence: {egress}"
            );
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the deferred apply lands behind a lease-restored fence: {egress}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(
        fence_seen,
        "the lease restored the fence at the final authorization's expiry"
    );
}

#[test]
fn an_unproven_allow_withdrawal_fences_and_keeps_companions() {
    // C36 r18 F2/F3: at expiry the daemon REFUSES the allow's removal with
    // a rejection that is neither proven absence nor a duplicate-match
    // refusal — the allow is STILL INSTALLED. The boundary must fence the
    // destination and leave the reject companions UNTOUCHED (removing
    // rejects while the allow lingers opens arbitrary DNS), retrying until
    // the withdrawal proves out. The r17 watcher removed companions FIRST
    // and read any rejection as success.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            45,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("grant commits");
    let statedir = log.parent().expect("statedir").to_path_buf();
    let expiry = std::time::Instant::now() + Duration::from_secs(45);
    fs::write(statedir.join("fail-acl-allow-remove"), "1").unwrap();
    // Past expiry, with the refusal pinned: the allow LINGERS, the fence
    // is installed, and the companions are NEVER touched.
    let probe_end = expiry + Duration::from_secs(12);
    let mut saw_fenced = false;
    while std::time::Instant::now() < probe_end {
        std::thread::sleep(Duration::from_millis(500));
        if std::time::Instant::now() < expiry {
            continue;
        }
        let egress = acl_egress(&log, &acl);
        if !egress
            .lines()
            .any(|line| line.contains("action=allow destination=128.66.0.7/32"))
        {
            continue; // not yet fired
        }
        saw_fenced |= lease_fence_present(&egress, "128.66.0.7/32");
        assert!(
            egress.lines().any(|line| line.contains("wssp-dns-reject-")
                && line.contains("destination=128.66.0.7/32")),
            "companions are never removed while the allow is unproven: {egress}"
        );
    }
    assert!(
        saw_fenced,
        "the refusal fenced the destination while the allow lingers"
    );
    // The refusal clears: the retry withdraws the allow and its
    // companions. Allow removal and companion removal are separate
    // sub-operations of one settle pass, so poll for BOTH gone rather
    // than sampling the boundary.
    fs::remove_file(statedir.join("fail-acl-allow-remove")).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let egress = acl_egress(&log, &acl);
        let allow_gone = !egress
            .lines()
            .any(|line| line.contains("action=allow destination=128.66.0.7/32"));
        let companions_gone = !egress.lines().any(|line| {
            line.contains("wssp-dns-reject-") && line.contains("destination=128.66.0.7/32")
        });
        if allow_gone && companions_gone {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the retried withdrawal completes (allow and companions): {egress}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    // Clean-expiry residue (C36 r20 F1): once the allow is PROVEN gone,
    // the deadline fence is withdrawn again in the same settle — a clean
    // expiry leaves no rule behind. (The fence only outlives the
    // withdrawal while it still defends an unresolved broadening
    // mutation.)
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let egress = acl_egress(&log, &acl);
        if !lease_fence_present(&egress, "128.66.0.7/32") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the deadline fence is withdrawn once the allow is proven gone: {egress}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
}

#[test]
fn a_duplicate_allow_is_forced_out_before_its_companions() {
    // C36 r18 F3: the daemon holds TWO copies of the allow (e.g. an
    // operator double-applied). The plain removal refuses with "More than
    // one matching rule" — every match is STILL INSTALLED. The boundary
    // retries once with --force; only when the allow set is proven gone
    // are the companions removed. Reading the refusal as success (r17)
    // left a duplicate allow installed with its companions removed.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("grant commits");
    let statedir = log.parent().expect("statedir").to_path_buf();
    // Plant the daemon-side duplicate.
    let egress_path = statedir.join("acls").join(format!("{acl}.egress"));
    let body = fs::read_to_string(&egress_path).expect("egress rules");
    let allow_line = body
        .lines()
        .find(|line| line.contains("action=allow destination=128.66.0.7/32"))
        .expect("allow present")
        .to_string();
    fs::write(&egress_path, format!("{body}{allow_line}\n")).unwrap();
    // Revoke: the refresh must prove BOTH copies gone, then withdraw the
    // companions, and verify clean.
    transport.script("grants.example.com", [FakeDnsOutcome::Rcode(3)]);
    refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("the duplicate is forced out and the refresh verifies");
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "no trace of the grant remains: {egress}"
    );
    let log_body = fs::read_to_string(&log).unwrap_or_default();
    assert!(
        log_body.contains("--force"),
        "the duplicate-match refusal was retried with --force"
    );
}

#[test]
fn a_failed_expiry_observation_preserves_the_obligation() {
    // C36 r18 F4: the ACL read fails with a transport error exactly when a
    // grant expires. The obligation must SURVIVE the failed observation
    // and be settled once the daemon is readable again — the r17 watcher
    // discarded every due obligation it could not observe, abandoning
    // enforcement permanently.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            40,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("grant commits");
    let statedir = log.parent().expect("statedir").to_path_buf();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    assert!(
        obligations.exists(),
        "obligations are persisted while a grant lives"
    );
    let expiry = std::time::Instant::now() + Duration::from_secs(40);
    // Failed ACL reads across the expiry tick, AND an unreadable
    // revocation marker: the lease cannot know whether a broadening
    // mutation is unresolved, so the eventual withdrawal must fence
    // fail-closed and the obligation must stay armed.
    let pin_path = statedir.join("fail-acl-read");
    fs::write(&pin_path, "6").unwrap();
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    fs::write(&marker_path, "{ not json").unwrap();
    // Wait until at least two expiry-time observations have FAILED (the
    // pin counter decrements per failure), then prove nothing settled:
    // the rules are still installed and the obligation survives.
    let deadline = expiry + Duration::from_secs(20);
    loop {
        let left: i32 = fs::read_to_string(&pin_path)
            .unwrap_or_default()
            .trim()
            .parse()
            .unwrap_or(-1);
        if (0..=4).contains(&left) {
            let egress = acl_egress(&log, &acl);
            assert!(
                egress
                    .lines()
                    .any(|line| line.contains("action=allow destination=128.66.0.7/32")),
                "a failed observation never settles the obligation: {egress}"
            );
            assert!(obligations.exists(), "the obligation survives the failure");
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the pinned read failures happen across the expiry"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    // Reads recover while the marker is still unreadable: the boundary
    // degrades fail-closed — the allow is withdrawn behind a lease fence
    // (a pending mutation cannot be ruled out) — but the obligation stays
    // armed because the marker failure means the settlement cannot be
    // accounted for.
    let deadline = std::time::Instant::now() + Duration::from_secs(40);
    loop {
        let egress = acl_egress(&log, &acl);
        if !egress
            .lines()
            .any(|line| line.contains("action=allow destination=128.66.0.7/32"))
        {
            assert!(
                lease_fence_present(&egress, "128.66.0.7/32"),
                "unreadable marker: withdrawn behind a fail-closed fence: {egress}"
            );
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the obligation settles once observation recovers: {egress}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    // Give the watcher a couple of settle ticks: a build that accounts
    // the withdrawal DESPITE the unreadable marker would retire the
    // obligation here.
    std::thread::sleep(Duration::from_secs(3));
    assert!(
        obligations.exists(),
        "the obligation stays armed while the marker is unreadable"
    );
    // The marker recovers: the next pass observes the absence, records the
    // evidence, and retires the obligation.
    fs::remove_file(&marker_path).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(40);
    while obligations.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "the obligation retires once the marker is readable"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
}

#[test]
fn a_renewed_grant_survives_its_original_expiry() {
    // C36 r18 F5, hardened to BARRIER-DRIVEN contention (C36 r19 review):
    // instead of hoping a sleep lines the renewal up with the original
    // expiry, a shim barrier holds the expiry withdrawal IN FLIGHT (the
    // removal CLI is started and parked, the settle holding the owner
    // lock) while the renewal re-arms. Renewal and withdrawal linearize
    // under the owner lock, so exactly one ordering is observable and the
    // renewed allow must survive the ORIGINAL deadline either way. The
    // r17 watcher's superseded copy could fire after renewal and delete
    // the renewed allow.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            30,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("grant commits");
    let start = std::time::Instant::now();
    let statedir = log.parent().expect("statedir").to_path_buf();
    // Barrier every DNS allow removal, then wait until the expiry
    // withdrawal is genuinely IN FLIGHT: the removal command is logged
    // (the CLI started) while the barrier still holds it.
    fs::write(statedir.join("barrier-acl-allow-remove"), "").unwrap();
    let deadline = start + Duration::from_secs(45);
    loop {
        let body = fs::read_to_string(&log).unwrap_or_default();
        if body.lines().any(|line| {
            line.contains("rule remove") && line.contains(&dns_rule_tag("grants.example.com", 1))
        }) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the expiry withdrawal reaches the barrier"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let egress = acl_egress(&log, &acl);
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow destination=128.66.0.7/32")),
        "the barrier holds the in-flight withdrawal past the original expiry: {egress}"
    );
    // C36 r20 F1 (regression assert, fixing this test's pre-r20 inverse
    // hole): an UNFENCED allow must never be observable past the expiry —
    // the settle installed the deadline fence BEFORE attempting the
    // removal, so the stalled destination is already denied.
    assert!(
        lease_fence_present(&egress, "128.66.0.7/32"),
        "the stalled expiry is fenced BEFORE its removal is attempted: {egress}"
    );
    let expired_tag = dns_rule_tag("grants.example.com", 1);
    // Renew while the withdrawal is in flight, AND defer the renewal's
    // re-add: the daemon accepts the new identity but applies it only
    // 45s later while the CLI reports failure, so the pass leaves a
    // journaled uncertain pending entry (C36 r20 F2: evidence scoped to
    // the exact issuance — the OLD identity's withdrawal evidence must
    // NOT retire the NEW issuance's pending entry).
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    // The daemon "accepts" each add attempt but the CLI reports a
    // transport failure and applies it only 8s later: the renewal pass
    // issues the (deferred) add, gets an Uncertain outcome, journals it,
    // and DENIES the grant for this refresh (an uncertain allow is never
    // served) — the pending entry stays journaled for reconcile.
    fs::write(statedir.join("defer-acl-allow-add-fail"), "8").unwrap();
    let outcome = std::thread::scope(|scope| {
        let renewal = scope.spawn(|| {
            std::thread::sleep(Duration::from_secs(2));
            refresh(&client, "sbx-1", &policy, &hash, &transport)
        });
        std::thread::sleep(Duration::from_secs(4));
        fs::write(statedir.join("release-allow-barrier"), "").unwrap();
        // The deferred issuance is a NEW identity, not a re-add of the
        // expired one: the journaled pending entry carries a generationed
        // tag DISTINCT from the expired identity, while the durable
        // withdrawal evidence is scoped to the expired identity — old
        // evidence must not retire the new entry (only the new entry's
        // own proven withdrawal may).
        let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let pending: Vec<String> = loop {
            let parsed = fs::read_to_string(&marker_path)
                .ok()
                .and_then(|body| serde_json::from_str::<serde_json::Value>(&body).ok());
            if let Some(marker) = parsed {
                let pending: Vec<String> = marker["pending"]
                    .as_array()
                    .map(|entries| {
                        entries
                            .iter()
                            .filter_map(|entry| entry["description"].as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                if pending
                    .iter()
                    .any(|tag| *tag != expired_tag && tag.contains("-g"))
                {
                    break pending;
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the deferred re-add is journaled under a fresh, request-unique identity"
            );
            std::thread::sleep(Duration::from_millis(200));
        };
        assert!(
            !pending.contains(&expired_tag),
            "the deferred re-add never reuses the expired identity: {pending:?}"
        );
        let evidence =
            fs::read_to_string(statedir.join("host-state/dns-revocations/sbx-1.lease-withdrawals"))
                .expect("the settle's withdrawal evidence is durable");
        assert!(
            evidence.contains(&expired_tag),
            "the old identity's positive withdrawal evidence exists: {evidence}"
        );
        assert!(
            pending.iter().all(|tag| !evidence.contains(tag)),
            "old evidence is scoped to the exact issuance — it must not cover the new identity"
        );
        // Continuous denial while the renewal is unresolved: the expired
        // identity is gone and the destination is never observable as an
        // UNFENCED allow past the original expiry.
        let egress = acl_egress(&log, &acl);
        assert!(
            !egress
                .lines()
                .any(|line| line.contains(&expired_tag) && line.contains("action=allow")),
            "the expired identity stays withdrawn: {egress}"
        );
        assert!(
            lease_fence_present(&egress, "128.66.0.7/32")
                || fence_present(&egress, "128.66.0.7/32"),
            "the destination stays fenced while the renewal is unresolved \
             (the settle's lease fence is withdrawn with the clean expiry; \
             the renewal's own preventive fence takes over): {egress}"
        );
        // The pending entry is persisted BEFORE issuance: observing it
        // does not prove the CLI consumed the deferral pin yet. Keep the
        // pin until the renewal completes, then lift it for the retry.
        let result = renewal.join().expect("renewal thread");
        fs::remove_file(statedir.join("defer-acl-allow-add-fail")).unwrap();
        result
    });
    let first = outcome.expect("the first renewal completes");
    assert!(
        first
            .denied_names
            .iter()
            .any(|name| name == "grants.example.com"),
        "the deferred re-add fails closed: never served while uncertain: {first:?}"
    );
    // Retry with a clean daemon: the contested gen-2 identity is never
    // reused — the retry plans ANOTHER fresh issuance, commits, and the
    // deferred gen-2 apply (landing ~8s after its issuance) is reconciled
    // under evidence scoped to gen-2 alone.
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    let renewal =
        refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the retried renewal commits");
    assert!(
        !renewal
            .denied_names
            .iter()
            .any(|name| name == "grants.example.com"),
        "the retried renewal is served: {renewal:?}"
    );
    // Continuous-denial contract past the ORIGINAL expiry (C36 r20):
    // until the renewal committed, the expired identity was never
    // reachable — an unfenced allow for the ORIGINAL identity must never
    // have been observable. Verify retroactively over the remaining
    // window: the original tag never reappears unfenced, and the renewed
    // allow (a NEW identity) survives.
    while std::time::Instant::now() < start + Duration::from_secs(50) {
        let egress = acl_egress(&log, &acl);
        let original_installed = egress
            .lines()
            .any(|line| line.contains(&expired_tag) && line.contains("action=allow"));
        assert!(
            !original_installed || lease_fence_present(&egress, "128.66.0.7/32"),
            "the expired identity is never reachable unfenced past its expiry: {egress}"
        );
        assert!(
            egress
                .lines()
                .any(|line| line.contains("action=allow destination=128.66.0.7/32")),
            "the renewed allow survives its original expiry: {egress}"
        );
        std::thread::sleep(Duration::from_millis(400));
    }
    // Revoke for cleanliness: withdrawal still works after renewal.
    transport.script("grants.example.com", [FakeDnsOutcome::Rcode(3)]);
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("revoking refresh");
    let egress = acl_egress(&log, &acl);
    assert!(!egress.contains("128.66.0.7"), "revoked cleanly: {egress}");
}

#[test]
fn a_restarted_daemon_settles_expired_obligations_and_rearms_live_grants() {
    // C36 r18 F6: the process dies (the in-memory lease and its watcher
    // vanish; only the fsynced obligations survive). While down, one grant
    // expires. The restarted daemon must settle the expired obligation —
    // withdraw its rules BEFORE the sandbox verifies as Ready — and rearm
    // the still-live grant's lease so IT expires on schedule too.
    let (mut runtime, log) = runtime_for("fix6_new_ready");
    runtime.override_resolver(std::sync::Arc::new(|domain, _wait| {
        let last: u8 = match domain {
            "a.example.com" => 7,
            "b.example.com" => 8,
            _ => 250,
        };
        Ok(vec![std::net::IpAddr::V4(Ipv4Addr::new(128, 66, 0, last))])
    }));
    let (policy, hash) = domain_policy(&["a.example.com", "b.example.com"], &[]);
    let mut request = super::shim_tests::create_req();
    request.egress_policy = Some(policy.clone());
    request.egress_policy_hash = Some(hash.clone());
    runtime.create_bound(&request).expect("create");
    let (_network, acl) = sandbox_network_names("sbx-1");
    // Re-TTL the grants: a expires in 40s, b in 75s. Same addresses, same
    // identities — only the lease obligations change.
    let statedir = log.parent().expect("statedir").to_path_buf();
    let mut client = legacy_client(
        statedir.join("incus").to_string_lossy().into_owned(),
        "default".to_string(),
    );
    client.host_routes = Some(Vec::new());
    client.state_dir = Some(statedir.join("host-state"));
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            40,
        )])],
    );
    transport.script(
        "b.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            75,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("re-TTL refresh");
    let refreshed_at = std::time::Instant::now();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    let body = fs::read_to_string(&obligations).expect("obligations persisted");
    for (name, generation) in [("a.example.com", 1), ("b.example.com", 2)] {
        assert!(
            body.contains(&dns_rule_tag(name, generation)),
            "obligation armed for {name}: {body}"
        );
    }
    // Process death: the watcher is gone; nothing enforces while down.
    client.debug_reset_dns_lease_owner("sbx-1");
    while std::time::Instant::now() < refreshed_at + Duration::from_secs(43) {
        std::thread::sleep(Duration::from_millis(300));
    }
    let egress = acl_egress(&log, &acl);
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow destination=128.66.0.7/32")),
        "no enforcement happened while the daemon was down: {egress}"
    );
    // Restart: reconnect settles the expired obligation and verifies.
    runtime
        .reconnect_bound(&crate::ReconnectSandboxRequest {
            vm_size: sandbox_protocol::VmSize::defaults().unwrap(),
            lease: sandbox_protocol::HostLease::for_test(),
            template_fingerprint: super::shim_tests::create_req().template_digest,
            architecture: Some("x86_64".into()),
            guest: Default::default(),
            sandbox_id: "sbx-1".to_string(),
            instance_name: "wssp-sbx-sbx-1".to_string(),
            operation_id: "op-re".to_string(),
            idempotency_key: "re-1".to_string(),
            egress_policy: Some(policy),
            egress_policy_hash: Some(hash.clone()),
            egress_admission: crate::egress::EgressAdmission::PERMITTED,
            guest_sudo: false,
        })
        .expect("reconnect settles the expired obligation and verifies");
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "the expired grant is withdrawn before readiness: {egress}"
    );
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow destination=128.66.0.8/32")),
        "the live grant survives: {egress}"
    );
    // The persisted plan caught up with the settlement.
    let rules = client
        .persisted_plan_rules("sbx-1", &hash)
        .expect("persisted plan");
    assert!(
        !rules
            .iter()
            .any(|rule| rule.destination.as_deref() == Some("128.66.0.7/32")),
        "the persisted plan no longer lists the expired grant"
    );
    // The surviving obligation is rearmed: b expires on schedule with no
    // further input.
    let body = fs::read_to_string(&obligations).expect("the live obligation persists");
    assert!(
        body.contains(&dns_rule_tag("b.example.com", 2))
            && !body.contains(&dns_rule_tag("a.example.com", 1)),
        "only the live grant stays armed: {body}"
    );
    let deadline = refreshed_at + Duration::from_secs(95);
    loop {
        let egress = acl_egress(&log, &acl);
        if !egress
            .lines()
            .any(|line| line.contains("action=allow destination=128.66.0.8/32"))
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the rearmed lease withdraws the surviving grant on schedule: {egress}"
        );
        std::thread::sleep(Duration::from_millis(400));
    }
}

#[test]
fn a_slow_fence_install_cannot_burn_past_the_allows_expiry() {
    // C36 r18 F7: preventive fencing + durable journaling consume wall
    // clock against the grant's ABSOLUTE deadline. A 45s fence install
    // (companions stay fast — only the fence is stalled) against a 40s
    // grant must end with the allow NEVER ISSUED (the at-issuance
    // recheck revokes it) — the r17 code computed the budget before
    // fencing and issued the allow with a stale lifetime.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            40,
        )])],
    );
    let statedir = log.parent().expect("statedir").to_path_buf();
    fs::write(statedir.join("slow-acl-fence-add"), "45").unwrap();
    let outcome = refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("the refresh completes with the grant denied");
    assert!(
        outcome
            .denied_names
            .iter()
            .any(|name| name == "grants.example.com"),
        "the expired-at-issuance grant is denied: {:?}",
        outcome.denied_names
    );
    let log_body = fs::read_to_string(&log).unwrap_or_default();
    assert!(
        !log_body.lines().any(|line| {
            line.contains("rule")
                && line.contains("add")
                && line.contains("action=allow")
                && line.contains("128.66.0.7")
        }),
        "the allow was never issued: {log_body}"
    );
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "nothing lingers — the fence was removed once the intent retired unissued: {egress}"
    );
    // Inverse: a fence install WITHIN the grant's lifetime stays usable.
    fs::remove_file(statedir.join("slow-acl-fence-add")).unwrap();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("re-grant commits");
    let egress = acl_egress(&log, &acl);
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow destination=128.66.0.8/32")),
        "a live grant issues normally: {egress}"
    );
}

#[test]
fn a_drifted_fence_is_repaired_never_trusted() {
    // C36 r18 F8: an existing quarantine is protection ONLY if it is the
    // complete canonical identity (enabled, reject, the exact destination,
    // no protocol/source/port narrowing). A port-narrowed or disabled
    // fence is DRIFT: the pass must install the canonical fence and remove
    // the impostor. A VALID fence is adopted and never reissued (inverse).
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com", "b.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    for (name, last) in [("a.example.com", 7u8), ("b.example.com", 8u8)] {
        transport.script(
            name,
            [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
                Ipv4Addr::new(128, 66, 0, last),
                60,
            )])],
        );
    }
    let statedir = log.parent().expect("statedir").to_path_buf();
    // Keep both accepted requests queued until the canonical fences have
    // been checked, so the late landing cannot race fixture setup.
    fs::write(statedir.join("defer-acl-allow-add-fail"), "queue").unwrap();
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("uncertain refresh");
    let fence_adds = |dest: &str| -> usize {
        // The REFRESH family only: the autonomous boundary's lease-family
        // blind fence for the recorded revocation (C36 r31 F2) is its own
        // pre-observation enforcement, not a reissue by the refresh pass.
        fs::read_to_string(&log)
            .unwrap_or_default()
            .lines()
            .filter(|line| {
                line.contains("rule")
                    && line.contains("add")
                    && line.contains("description=wssp-dns-quarantine-")
                    && line.contains(dest)
            })
            .count()
    };
    // A second refresh while the mutations are unresolved ADOPTS the valid
    // fences — it must not reissue them. NXDOMAIN keeps both names denied
    // so no re-grant is attempted.
    transport.script("a.example.com", [FakeDnsOutcome::Rcode(3)]);
    transport.script("b.example.com", [FakeDnsOutcome::Rcode(3)]);
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("adopting refresh");
    assert_eq!(fence_adds("128.66.0.7"), 1, "a valid fence is adopted");
    assert_eq!(fence_adds("128.66.0.8"), 1, "a valid fence is adopted");
    // Drift: a's fence becomes port-narrowed, b's becomes disabled.
    let egress_path = statedir.join("acls").join(format!("{acl}.egress"));
    let body = fs::read_to_string(&egress_path).expect("egress rules");
    let mut kept: Vec<String> = Vec::new();
    for line in body.lines() {
        if line.contains("description=wssp-dns-quarantine-") && line.contains("128.66.0.7") {
            kept.push(format!("{line} destination_port=53"));
        } else if line.contains("description=wssp-dns-quarantine-") && line.contains("128.66.0.8") {
            kept.push(format!("{line} state=disabled"));
        } else {
            kept.push(line.to_string());
        }
    }
    fs::write(&egress_path, kept.join("\n") + "\n").unwrap();
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("repairing refresh");
    let egress = acl_egress(&log, &acl);
    for dest in ["128.66.0.7/32", "128.66.0.8/32"] {
        assert!(
            fence_present(&egress, dest),
            "a canonical fence protects {dest}: {egress}"
        );
    }
    for line in egress.lines() {
        if line.contains("quarantine-") {
            assert!(
                !line.contains("destination_port") && !line.contains("state=disabled"),
                "the drifted fence is removed, never trusted: {line}"
            );
        }
    }
    // The autonomous watcher may provide a canonical lease fence while
    // refresh repairs the impostor. The checks above require effective
    // protection and removal of every narrowed or disabled fence.
    fs::remove_file(statedir.join("defer-acl-allow-add-fail")).unwrap();
    assert_eq!(apply_queued_acl_adds(&statedir), 2);
    transport.script("a.example.com", [FakeDnsOutcome::Rcode(3)]);
    transport.script("b.example.com", [FakeDnsOutcome::Rcode(3)]);
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("reconciling refresh");
    // The autonomous boundary's lease fences release through the journaled
    // path once the withdrawal evidence is durable (C36 r31 F2) — a tick
    // behind the commit.
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let egress = acl_egress(&log, &acl);
        if !egress.contains("128.66.0.7") && !egress.contains("128.66.0.8") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "everything retires: {egress}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
}

#[test]
fn a_recovered_expiry_never_recycles_a_request_identity() {
    // C36 r19 F1: expiry recovery must NEVER prune the persisted
    // generation history. If it does, a re-grant of the same name
    // re-allocates the FIRST generation — the SAME rule identity an
    // already-retired mutation carried — and the durable positive-
    // withdrawal evidence recorded for the OLD identity can "prove" the
    // NEW re-grant's deferred issuance, retiring a pending entry whose
    // request was never observed to complete. (C36 r26 F1: every
    // issuance now allocates a durable identity, so the first grant is
    // generation 1 and the re-grant generation 3 (the fence epoch is preserved in the floor, C36 r27 F1).)
    //
    // Choreography: a committed gen-1 grant expires while the daemon is
    // down; recovery settles it (positive withdrawal of the gen-1
    // identity, evidence logged). A re-grant then defers its allow: the
    // pending entry must carry generation 3, so the stale gen-1 evidence
    // cannot match it.
    let (mut client, log) = applied_client("running", "sbx-1");
    let clock = DnsTestClock::install(&mut client);
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            40,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("grant commits");
    let statedir = log.parent().expect("statedir").to_path_buf();
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    // Process death BEFORE the expiry: only the fsync'd obligation
    // survives; the deferred window below lets the grant expire while
    // down.
    client.debug_reset_dns_lease_owner("sbx-1");
    clock.advance(43);
    // Restart recovery settles the expired gen-1 identity (positive
    // withdrawal — the allow is still installed) and rewrites the
    // persisted state. The generation history must SURVIVE the rewrite.
    client
        .recover_dns_expiry_obligations("sbx-1")
        .expect("recovery settles the expired obligation");
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "recovery withdrew the expired grant: {egress}"
    );
    let recovered = client
        .load_dns_state("sbx-1", &hash)
        .expect("recovered state");
    assert_eq!(
        recovered.generations.get("grants.example.com"),
        Some(&1),
        "recovery preserves the retired issuance history"
    );
    // Re-grant the same address with a DEFERRED daemon-side apply: the
    // re-grant must allocate generation 3 — never the retired gen-1
    // identity, whose positive-withdrawal evidence is still durable.
    fs::write(statedir.join("defer-acl-allow-add-fail"), "queue").unwrap();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            40,
        )])],
    );
    let outcome = refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("the re-grant refresh completes with the grant fenced");
    assert!(
        outcome
            .denied_names
            .iter()
            .any(|name| name == "grants.example.com"),
        "the uncertain re-grant is not committed: {:?}",
        outcome.denied_names
    );
    let marker =
        fs::read_to_string(&marker_path).expect("the re-grant's pending entry is journaled");
    assert!(
        marker.contains(&dns_rule_tag("grants.example.com", 3)),
        "the re-grant carries a FRESH generation (3 — the gen-1 issuance's fence \
         epoch is preserved in the floor, C36 r27 F1; stale gen-1 evidence \
         cannot retire it): {marker}"
    );
    assert!(
        !marker.contains(&dns_rule_tag("grants.example.com", 1)),
        "the retired gen-1 identity is never recycled: {marker}"
    );
    // Expire the uncertain re-grant, then land the accepted daemon work.
    // Stop autonomous repair so it cannot consume the late allow before
    // the original fence assertion observes it.
    client.debug_reset_dns_lease_owner("sbx-1");
    clock.advance(40);
    land_queued_acl_requests(&log, "add");
    // The deferred gen-3 apply lands behind the fence.
    let deadline = std::time::Instant::now() + Duration::from_secs(70);
    loop {
        let egress = acl_egress(&log, &acl);
        if egress
            .lines()
            .any(|line| line.contains("action=allow destination=128.66.0.7/32"))
        {
            assert!(
                fence_present(&egress, "128.66.0.7/32"),
                "the deferred re-grant lands behind the fence: {egress}"
            );
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the deferred apply lands: {egress}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    // Inverse: the entry retires on definitive evidence for ITS OWN
    // identity — reconcile observes the landed gen-3 rule and withdraws
    // it; only then does the marker clear and the fence release.
    fs::remove_file(statedir.join("defer-acl-allow-add-fail")).unwrap();
    transport.script("grants.example.com", [FakeDnsOutcome::Rcode(3)]);
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("reconciling refresh");
    assert!(
        !marker_path.exists(),
        "the pending entry retires on its own positive withdrawal"
    );
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "everything withdrawn, fence released: {egress}"
    );
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn an_overdue_unsettled_obligation_survives_a_rearm() {
    // C36 r19 F2: arming on a FRESH owner must load the durable ledger
    // before merging, and must retain overdue-unsettled obligations —
    // expiry makes an obligation DUE, not settled. The pre-fix arm
    // overwrote the file with only the live re-armed set, silently
    // dropping an obligation whose grant had expired unsettled: its rule
    // would stay installed forever.
    let (mut client, log) = applied_client("running", "sbx-1");
    let clock = DnsTestClock::install(&mut client);
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            40,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("grant commits");
    let statedir = log.parent().expect("statedir").to_path_buf();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    let armed_tag = dns_rule_tag("grants.example.com", 1);
    let body = fs::read_to_string(&obligations).expect("obligation persisted");
    assert!(body.contains(&armed_tag), "obligation armed: {body}");
    // Process death, then time passes: the obligation is OVERDUE and
    // UNSETTLED (its rule is still installed) when a fresh owner re-arms.
    client.debug_reset_dns_lease_owner("sbx-1");
    clock.advance(43);
    let egress = acl_egress(&log, &acl);
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow destination=128.66.0.7/32")),
        "nothing enforced while the daemon was down: {egress}"
    );
    // A re-arm of an UNRELATED identity on the fresh owner (a new grant's
    // arm): the overdue obligation must be loaded and retained — and the
    // watcher this arm spawns must settle it WITHOUT any refresh.
    let now = clock.now();
    let other: super::dns::DnsLeaseEntry = serde_json::from_value(serde_json::json!({
        "name": "other.example.com",
        "expires_at": now + 3600,
        "allow_tag": dns_rule_tag("other.example.com", 0),
        "reject_tag": dns_rule_tag("other.example.com", 0).replace("wssp-dns-", "wssp-dns-reject-"),
        "destinations": ["128.66.1.7/32"],
        "fence_on_expiry": []
    }))
    .expect("fabricated obligation entry");
    client
        .arm_dns_expiry_lease("sbx-1", vec![other])
        .expect("the re-arm merges the durable ledger");
    let deadline = std::time::Instant::now() + Duration::from_secs(40);
    loop {
        let egress = acl_egress(&log, &acl);
        if !egress
            .lines()
            .any(|line| line.contains("action=allow destination=128.66.0.7/32"))
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the retained overdue obligation settles without a refresh: {egress}"
        );
        std::thread::sleep(Duration::from_millis(400));
    }
    // Inverses: the settled obligation retires; the unrelated re-armed
    // identity stays armed.
    let deadline = std::time::Instant::now() + Duration::from_secs(40);
    loop {
        match fs::read_to_string(&obligations) {
            Ok(body) if body.contains(&armed_tag) => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the settled obligation retires: {body}"
                );
                std::thread::sleep(Duration::from_millis(300));
            }
            Ok(body) => {
                assert!(
                    body.contains(&dns_rule_tag("other.example.com", 0)),
                    "the unrelated re-armed identity stays armed: {body}"
                );
                break;
            }
            Err(_) => panic!("the live obligation must stay persisted"),
        }
    }
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn a_failed_refresh_revocation_fences_the_destination() {
    // C36 r19 F3 (refresh path): a revocation whose allow removal FAILS
    // (daemon error, not proven absence) must route through the enforced
    // withdrawal boundary: the destination is fenced, the companions are
    // preserved (an overlapping allow might still be installed), and the
    // pass fails LOUDLY. The pre-fix removal phase withdrew companions
    // around an unproven allow and left the destination reachable.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("grant commits");
    let statedir = log.parent().expect("statedir").to_path_buf();
    // Revoke with the allow removal failing: the boundary fences.
    transport.script("grants.example.com", [FakeDnsOutcome::Rcode(3)]);
    fs::write(statedir.join("fail-acl-allow-remove"), "").unwrap();
    let outcome = refresh(&client, "sbx-1", &policy, &hash, &transport);
    let err = outcome.expect_err("an unproven revocation fails the refresh closed");
    assert!(
        err.to_string().contains("the destination stays fenced"),
        "the failure comes from the enforced withdrawal boundary, not a downstream accident: {err}"
    );
    let egress = acl_egress(&log, &acl);
    assert!(
        fence_present(&egress, "128.66.0.7/32"),
        "the unproven revocation fences the destination: {egress}"
    );
    assert!(
        egress
            .lines()
            .any(|line| line.contains("wssp-dns-reject-") && line.contains("destination_port=53")),
        "companions are preserved while the allow is unproven: {egress}"
    );
    // Inverse: once the daemon behaves, the revocation proves out, the
    // companions withdraw, and the unneeded fence releases — no residue.
    fs::remove_file(statedir.join("fail-acl-allow-remove")).unwrap();
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("revoking refresh");
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "a proven revocation leaves nothing behind: {egress}"
    );
}

#[test]
fn a_failed_reconcile_withdrawal_keeps_the_fence() {
    // C36 r19 F3 (reconcile path): the deferred daemon-side apply of an
    // uncertain allow lands after its grant was revoked; reconcile must
    // withdraw it through the enforced boundary. When that withdrawal
    // FAILS the destination stays fenced and the pass fails — the
    // pre-fix reconcile removed the observed rule directly, bypassing
    // fencing, and could strip the companions/fence around an allow it
    // failed to remove.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            40,
        )])],
    );
    let statedir = log.parent().expect("statedir").to_path_buf();
    fs::write(statedir.join("defer-acl-allow-add-fail"), "queue").unwrap();
    refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("refresh completes with the uncertain grant fenced");
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    assert!(marker_path.exists(), "pending mutation journaled");
    // Hold withdrawal failure before landing the accepted request, so the
    // watcher cannot settle it before the explicit reconciliation attempt.
    fs::remove_file(statedir.join("defer-acl-allow-add-fail")).unwrap();
    fs::write(statedir.join("fail-acl-allow-remove"), "").unwrap();
    assert_eq!(apply_queued_acl_adds(&statedir), 1);
    transport.script("grants.example.com", [FakeDnsOutcome::Rcode(3)]);
    let outcome = refresh(&client, "sbx-1", &policy, &hash, &transport);
    let err = outcome.expect_err("an unproven reconcile withdrawal fails the refresh closed");
    assert!(
        err.to_string().contains("the destination stays fenced"),
        "the failure comes from the enforced withdrawal boundary, not a downstream accident: {err}"
    );
    let egress = acl_egress(&log, &acl);
    assert!(
        fence_present(&egress, "128.66.0.7/32"),
        "the fence survives the failed reconcile withdrawal: {egress}"
    );
    assert!(
        marker_path.exists(),
        "the pending entry survives its unproven withdrawal"
    );
    // Inverse: a working daemon lets reconcile withdraw the stale rule,
    // retire the entry, and release the fence.
    fs::remove_file(statedir.join("fail-acl-allow-remove")).unwrap();
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("reconciling refresh");
    assert!(!marker_path.exists(), "the entry retires on proof");
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "everything withdrawn, fence released: {egress}"
    );
}

#[test]
fn recovery_refuses_to_ratify_acl_drift() {
    // C36 r19 F4: restart recovery settles overdue obligations and then
    // commits the post-settlement plan — DERIVED from the trusted record,
    // never copied from the live ACL. An ACL carrying UNRELATED drift
    // (here: an injected allow) must REFUSE the settlement — and leave
    // the trusted plan untouched — instead of ratifying the drift into
    // the persisted plan.
    let (mut runtime, log) = runtime_for("fix6_new_ready");
    let clock = DnsTestClock::install(runtime.client_mut());
    runtime.override_resolver(std::sync::Arc::new(|domain, _wait| {
        let last: u8 = match domain {
            "a.example.com" => 7,
            _ => 250,
        };
        Ok(vec![std::net::IpAddr::V4(Ipv4Addr::new(128, 66, 0, last))])
    }));
    let (policy, hash) = domain_policy(&["a.example.com"], &[]);
    let mut request = super::shim_tests::create_req();
    request.egress_policy = Some(policy.clone());
    request.egress_policy_hash = Some(hash.clone());
    runtime.create_bound(&request).expect("create");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let statedir = log.parent().expect("statedir").to_path_buf();
    let mut client = legacy_client(
        statedir.join("incus").to_string_lossy().into_owned(),
        "default".to_string(),
    );
    client.dns_clock = runtime.client().dns_clock.clone();
    client.host_routes = Some(Vec::new());
    client.state_dir = Some(statedir.join("host-state"));
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            40,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("re-TTL refresh");
    let reconnect =
        |runtime: &mut crate::incus::kvm::IncusKvmRuntime, policy: EgressPolicy, hash: &str| {
            runtime.reconnect_bound(&crate::ReconnectSandboxRequest {
                vm_size: sandbox_protocol::VmSize::defaults().unwrap(),
                lease: sandbox_protocol::HostLease::for_test(),
                template_fingerprint: super::shim_tests::create_req().template_digest,
                architecture: Some("x86_64".into()),
                guest: Default::default(),
                sandbox_id: "sbx-1".to_string(),
                instance_name: "wssp-sbx-sbx-1".to_string(),
                operation_id: format!("op-{}", std::time::Instant::now().elapsed().as_nanos()),
                idempotency_key: format!("re-{}", std::time::Instant::now().elapsed().as_nanos()),
                egress_policy: Some(policy),
                egress_policy_hash: Some(hash.to_string()),
                egress_admission: crate::egress::EgressAdmission::PERMITTED,
                guest_sudo: false,
            })
        };
    // Process death; the grant expires while down.
    client.debug_reset_dns_lease_owner("sbx-1");
    clock.advance(43);
    // Out-of-band drift: an injected allow the plan never recorded.
    let egress_path = statedir.join(format!("acls/{acl}.egress"));
    {
        use std::io::Write as _;
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&egress_path)
            .expect("acl file");
        writeln!(
            file,
            "action=allow destination=128.66.1.99/32 description=attacker-injected"
        )
        .unwrap();
    }
    // Recovery must REFUSE: the live ACL carries more than the derived
    // post-settlement truth.
    let outcome = reconnect(&mut runtime, policy.clone(), &hash);
    assert!(
        outcome.is_err(),
        "recovery refuses to ratify unrelated ACL drift"
    );
    let rules = client
        .persisted_plan_rules("sbx-1", &hash)
        .expect("persisted plan");
    assert!(
        !rules
            .iter()
            .any(|rule| rule.destination.as_deref() == Some("128.66.1.99/32")),
        "the trusted plan never absorbed the drift"
    );
    assert!(
        rules
            .iter()
            .any(|rule| rule.destination.as_deref() == Some("128.66.0.7/32")),
        "the unsettled plan keeps the expired grant (settlement refused)"
    );
    // C36 r20 (inverse-check gap): a refused settlement commits NOTHING —
    // the persisted DNS state is byte-for-byte the pre-settlement record
    // (validation runs before any persistence).
    let state_body = fs::read_to_string(statedir.join("host-state/dns-policy/sbx-1.json"))
        .expect("persisted DNS state");
    assert!(
        state_body.contains("a.example.com"),
        "the DNS state is untouched when the settlement refuses: {state_body}"
    );
    // Inverse: with the drift removed, recovery settles cleanly.
    let cleaned = fs::read_to_string(&egress_path)
        .unwrap()
        .lines()
        .filter(|line| !line.contains("attacker-injected"))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&egress_path, format!("{cleaned}\n")).unwrap();
    reconnect(&mut runtime, policy, &hash).expect("clean recovery verifies");
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "the expired grant is withdrawn before readiness: {egress}"
    );
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn a_settled_expiry_commits_the_lifecycle_transition() {
    // C36 r19 F5: expiry settlement IS a lifecycle state transition —
    // the in-process watcher's settle rewrites the persisted DNS state
    // and network plan BEFORE the obligations retire, so a later
    // readiness/reconnect (with NO refresh in between) verifies against
    // the settled truth instead of failing against the stale pre-expiry
    // plan.
    let (mut runtime, log) = runtime_for("fix6_new_ready");
    runtime.override_resolver(std::sync::Arc::new(|domain, _wait| {
        let last: u8 = match domain {
            "a.example.com" => 7,
            _ => 250,
        };
        Ok(vec![std::net::IpAddr::V4(Ipv4Addr::new(128, 66, 0, last))])
    }));
    let (policy, hash) = domain_policy(&["a.example.com"], &[]);
    let mut request = super::shim_tests::create_req();
    request.egress_policy = Some(policy.clone());
    request.egress_policy_hash = Some(hash.clone());
    runtime.create_bound(&request).expect("create");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let statedir = log.parent().expect("statedir").to_path_buf();
    let mut client = legacy_client(
        statedir.join("incus").to_string_lossy().into_owned(),
        "default".to_string(),
    );
    client.host_routes = Some(Vec::new());
    client.state_dir = Some(statedir.join("host-state"));
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            40,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("re-TTL refresh");
    // The in-process watcher settles the expiry — no restart, and NO
    // REFRESH afterwards.
    let deadline = std::time::Instant::now() + Duration::from_secs(70);
    loop {
        let egress = acl_egress(&log, &acl);
        if !egress
            .lines()
            .any(|line| line.contains("action=allow destination=128.66.0.7/32"))
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the lease withdraws the expired grant without a refresh: {egress}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    // Reconnect with no refresh: the settled plan is what verification
    // compares against.
    runtime
        .reconnect_bound(&crate::ReconnectSandboxRequest {
            vm_size: sandbox_protocol::VmSize::defaults().unwrap(),
            lease: sandbox_protocol::HostLease::for_test(),
            template_fingerprint: super::shim_tests::create_req().template_digest,
            architecture: Some("x86_64".into()),
            guest: Default::default(),
            sandbox_id: "sbx-1".to_string(),
            instance_name: "wssp-sbx-sbx-1".to_string(),
            operation_id: "op-settled".to_string(),
            idempotency_key: "re-settled".to_string(),
            egress_policy: Some(policy.clone()),
            egress_policy_hash: Some(hash.clone()),
            egress_admission: crate::egress::EgressAdmission::PERMITTED,
            guest_sudo: false,
        })
        .expect("reconnect verifies against the settled plan without a refresh");
    let rules = client
        .persisted_plan_rules("sbx-1", &hash)
        .expect("persisted plan");
    assert!(
        !rules
            .iter()
            .any(|rule| rule.destination.as_deref() == Some("128.66.0.7/32")),
        "the settle committed the expiry to the persisted plan"
    );
    // Inverse: an UNEXPLAINED extra rule still fails verification — the
    // transition commit did not weaken the equality check.
    let egress_path = statedir.join(format!("acls/{acl}.egress"));
    {
        use std::io::Write as _;
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&egress_path)
            .expect("acl file");
        writeln!(
            file,
            "action=allow destination=128.66.1.99/32 description=attacker-injected"
        )
        .unwrap();
    }
    let outcome = runtime.reconnect_bound(&crate::ReconnectSandboxRequest {
        vm_size: sandbox_protocol::VmSize::defaults().unwrap(),
        lease: sandbox_protocol::HostLease::for_test(),
        template_fingerprint: super::shim_tests::create_req().template_digest,
        architecture: Some("x86_64".into()),
        guest: Default::default(),
        sandbox_id: "sbx-1".to_string(),
        instance_name: "wssp-sbx-sbx-1".to_string(),
        operation_id: "op-drifted".to_string(),
        idempotency_key: "re-drifted".to_string(),
        egress_policy: Some(policy),
        egress_policy_hash: Some(hash),
        egress_admission: crate::egress::EgressAdmission::PERMITTED,
        guest_sudo: false,
    });
    assert!(
        outcome.is_err(),
        "an unexplained extra rule still refuses readiness"
    );
}

#[test]
fn a_bound_sized_obligation_ledger_recovers_after_restart() {
    // C36 r19 F6: the obligation reader and writer share ONE bound — two
    // live identities per policy domain (live + not-yet-settled
    // historical). A policy at the domain bound that just rotated one
    // identity persists 129 obligations; the pre-fix reader (bound 128)
    // refused a file the writer had itself persisted, wedging readiness
    // forever.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, _acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            3600,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("grant commits");
    let statedir = log.parent().expect("statedir").to_path_buf();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    let real: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&obligations).expect("obligations persisted"))
            .expect("obligations json");
    let template = real["entries"][0].clone();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let fabricate = |count: usize| {
        let mut doc = real.clone();
        let entries: Vec<serde_json::Value> = (0..count)
            .map(|i| {
                let mut entry = template.clone();
                entry["expires_at"] = serde_json::json!(now + 3600);
                entry["allow_tag"] = serde_json::json!(format!("wssp-dns-g0-{i:08x}"));
                entry["reject_tag"] = serde_json::json!(format!("wssp-dns-reject-g0-{i:08x}"));
                entry["destinations"] = serde_json::json!([format!("128.66.1.{}/32", i % 250)]);
                entry["fence_on_expiry"] = serde_json::json!([] as [&str; 0]);
                entry
            })
            .collect();
        doc["entries"] = serde_json::json!(entries);
        serde_json::to_string_pretty(&doc).unwrap()
    };
    // 129 obligations (the rotated-policy high-water mark the user
    // pinned): recovery loads and re-arms them.
    fs::write(&obligations, fabricate(129)).unwrap();
    client.debug_reset_dns_lease_owner("sbx-1");
    client
        .recover_dns_expiry_obligations("sbx-1")
        .expect("129 persisted obligations recover after restart");
    client.debug_reset_dns_lease_owner("sbx-1");
    // Inverse: a ledger beyond the shared bound is refused CLOSED, not
    // silently truncated.
    fs::write(&obligations, fabricate(257)).unwrap();
    let outcome = client.recover_dns_expiry_obligations("sbx-1");
    assert!(
        outcome.is_err(),
        "an oversized obligation ledger refuses closed"
    );
    fs::remove_file(&obligations).unwrap();
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn a_reconnect_apply_settles_overdue_obligations_before_verifying() {
    // C36 r19 F5 (apply path): the reconnect APPLY path settles
    // restart-durable expiry obligations BEFORE its idempotency
    // equality check. Without that ordering an overdue grant's rules —
    // still installed while the daemon was down — are accepted as
    // matching the stale pre-expiry plan: the expired allow lingers and
    // the lease is never re-armed to enforce it.
    let (mut client, log) = applied_client("running", "sbx-1");
    let clock = DnsTestClock::install(&mut client);
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            40,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("grant commits");
    let statedir = log.parent().expect("statedir").to_path_buf();
    // Process death; the grant expires while down with no watcher.
    client.debug_reset_dns_lease_owner("sbx-1");
    clock.advance(43);
    let egress = acl_egress(&log, &acl);
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow destination=128.66.0.7/32")),
        "nothing enforced while the daemon was down: {egress}"
    );
    // The reconnect apply: recovery runs FIRST (settling the overdue
    // obligation through the boundary and committing the lifecycle
    // transition), so the equality check compares the settled truth.
    // §2.6: the reconnect apply carries the RECORDED policy identity; the
    // record (post-settlement) is its reference.
    let mut plan = test_plan("sbx-1");
    plan.policy_hash = Some(hash.clone());
    client
        .apply_sandbox_network(&plan)
        .expect("the apply settles overdue obligations before verifying");
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "the expired grant is withdrawn during the apply, not ratified: {egress}"
    );
    // The settlement committed the lifecycle transition: the persisted
    // DNS state no longer carries the expired grant.
    let state_body = fs::read_to_string(statedir.join("host-state/dns-policy/sbx-1.json"))
        .expect("persisted DNS state");
    assert!(
        state_body.contains("\"grants\":[]"),
        "the persisted DNS state caught up with the settlement: {state_body}"
    );
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn a_stalled_expiry_withdrawal_still_denies_on_schedule() {
    // C36 r20 F1: deadline enforcement is separated from the potentially
    // slow cleanup. The lease's own removal command is stalled at a shim
    // barrier; the expired destination must be DENIED (fenced) at its
    // deadline without waiting for that removal — and a second grant
    // expiring DURING the stall must be fenced at its own deadline too
    // (the first removal's budget is derived from the next live expiry,
    // so the stall cannot order the second deadline behind it).
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com", "b.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            40,
        )])],
    );
    transport.script(
        "b.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            50,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("both grants commit");
    let start = std::time::Instant::now();
    let statedir = log.parent().expect("statedir").to_path_buf();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    assert!(obligations.exists(), "obligations armed for both grants");
    // Stall the LEASE'S OWN removal at the barrier (the reviewer's
    // requirement: the withdrawal itself stalls, not a publication).
    fs::write(statedir.join("barrier-acl-allow-remove"), "").unwrap();
    // Wait until the first expiry's withdrawal is genuinely IN FLIGHT.
    let deadline = start + Duration::from_secs(45);
    loop {
        let body = fs::read_to_string(&log).unwrap_or_default();
        if body.lines().any(|line| {
            line.contains("rule remove") && line.contains(&dns_rule_tag("a.example.com", 1))
        }) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the first expiry's removal reaches the barrier"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    // The deadline fence landed BEFORE the stalled removal was attempted:
    // the expired destination is denied even though its allow is still
    // installed (the removal is parked).
    let egress = acl_egress(&log, &acl);
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow destination=128.66.0.7/32")),
        "the stalled removal never completed: {egress}"
    );
    assert!(
        lease_fence_present(&egress, "128.66.0.7/32"),
        "expiry is fenced at its deadline without waiting for the removal: {egress}"
    );
    // While the first removal stays parked, the SECOND grant expires
    // (+50): it must be fenced at its own deadline — the stalled removal
    // was abandoned at its budget, not waited out. Continuous invariant
    // throughout: the first destination is never observable as an
    // UNFENCED allow past its expiry.
    let deadline = start + Duration::from_secs(75);
    let second_fenced = loop {
        let egress = acl_egress(&log, &acl);
        let first_allow = egress
            .lines()
            .any(|line| line.contains("action=allow destination=128.66.0.7/32"));
        assert!(
            !first_allow || lease_fence_present(&egress, "128.66.0.7/32"),
            "the stalled expiry is never unfenced past its deadline: {egress}"
        );
        if lease_fence_present(&egress, "128.66.0.8/32") {
            break std::time::Instant::now();
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the second grant is fenced at its own deadline despite the stall: {egress}"
        );
        std::thread::sleep(Duration::from_millis(300));
    };
    assert!(
        second_fenced < start + Duration::from_secs(65),
        "the second deadline was not delayed by the stalled removal"
    );
    assert!(
        !statedir.join("release-allow-barrier").exists(),
        "both deadlines were enforced while the removal was still stalled"
    );
    // Inverse: release the barrier — the stalled withdrawals complete,
    // the obligations retire, and a clean expiry leaves NO rule behind
    // (the deadline fences are withdrawn once the allows are proven
    // gone).
    fs::write(statedir.join("release-allow-barrier"), "").unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(90);
    while obligations.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "the stalled obligations retire once the removal proceeds"
        );
        std::thread::sleep(Duration::from_millis(400));
    }
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "first grant withdrawn: {egress}"
    );
    assert!(
        !egress.contains("128.66.0.8"),
        "second grant withdrawn: {egress}"
    );
    assert!(
        !egress.contains("wssp-dns-lease-quarantine-"),
        "a clean expiry leaves no fence behind: {egress}"
    );
}

#[test]
fn a_lease_settlement_commit_serializes_with_a_refresh_commit() {
    // C36 r20 F3: ONE serialized, version-checked commit boundary for the
    // refresh and the lease settlement. A test barrier holds the REFRESH
    // commit (a rotation of `b`) under the commit lock after its durable
    // read, while an overdue settlement for `a` runs against it. With the
    // lock the two commits serialize and everything stays consistent;
    // without it the settlement reads the pre-rotation record and its
    // validation against the rotated ACL must refuse (the regression
    // observes exactly that refusal in the mutant).
    let (mut client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com", "b.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            40,
        )])],
    );
    transport.script(
        "b.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("both grants commit");
    let statedir = log.parent().expect("statedir").to_path_buf();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    // Process death: no watcher; `a` expires while down.
    client.debug_reset_dns_lease_owner("sbx-1");
    std::thread::sleep(Duration::from_secs(43));
    // The rotation: `a` is gone from the world (the refresh withdraws
    // it), `b` rotates to a new address (same identity, new destination).
    transport.script("a.example.com", [FakeDnsOutcome::Rcode(3)]);
    transport.script(
        "b.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 9),
            300,
        )])],
    );
    // Hold the refresh commit between its durable read and its
    // persistence; run the overdue settlement against that window.
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    client.dns_commit_barrier = Some(barrier.clone());
    let client = &client;
    let transport = &transport;
    let policy = &policy;
    let hash = &hash;
    let log = &log;
    let acl = &acl;
    let refresh = std::thread::scope(|scope| {
        let refresh = scope.spawn(move || refresh(client, "sbx-1", policy, hash, transport));
        // Rendezvous: the refresh commit is parked pre-persistence,
        // holding the commit lock.
        barrier.wait();
        // The settlement: settles `a` (the refresh already withdrew its
        // rule), then its commit blocks on the lock the refresh holds.
        let settle = scope.spawn(move || client.recover_dns_expiry_obligations("sbx-1"));
        // Wait until the settlement's deadline fence is installed (it is
        // about to reach its commit) before releasing the refresh.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            let egress = acl_egress(log, acl);
            if lease_fence_present(&egress, "128.66.0.7/32") || !egress.contains("128.66.0.7") {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the settlement reaches its commit while the refresh is parked"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        std::thread::sleep(Duration::from_millis(800));
        barrier.wait();
        let settled = settle.join().expect("settle thread");
        let rotated = refresh.join().expect("refresh thread");
        (settled, rotated)
    });
    refresh.0.expect("the settlement commits");
    refresh.1.expect("the rotation commits");
    // Everything consistent afterwards: the publication, the persisted
    // DNS state, the generation history, the recorded plan rules, and
    // the remaining obligations all tell the same post-rotation,
    // post-settlement story.
    let egress = acl_egress(log, acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "the expired grant is withdrawn: {egress}"
    );
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow destination=128.66.0.9/32")),
        "the rotation is published: {egress}"
    );
    let state_body = fs::read_to_string(statedir.join("host-state/dns-policy/sbx-1.json"))
        .expect("persisted DNS state");
    let state: serde_json::Value = serde_json::from_str(&state_body).expect("state json");
    assert!(
        state["grants"]
            .as_array()
            .expect("grants")
            .iter()
            .all(|grant| grant["name"].as_str() != Some("a.example.com")),
        "the settlement's commit stands — the expired grant is not resurrected: {state_body}"
    );
    assert!(
        state["generations"].get("a.example.com").is_some(),
        "the settled identity stays in the monotone history (never re-issued): {state_body}"
    );
    assert!(
        state_body.contains("128.66.0.9"),
        "the refresh's commit stands — the rotation is not lost: {state_body}"
    );
    let rules = client
        .persisted_plan_rules("sbx-1", hash)
        .expect("persisted plan");
    assert!(
        rules
            .iter()
            .any(|rule| rule.destination.as_deref() == Some("128.66.0.9/32")),
        "the recorded plan carries the rotation"
    );
    assert!(
        !rules
            .iter()
            .any(|rule| rule.destination.as_deref() == Some("128.66.0.7/32")),
        "the recorded plan carries the settlement"
    );
    let ledger = fs::read_to_string(&obligations).expect("obligations persist for b");
    assert!(
        !ledger.contains(&dns_rule_tag("a.example.com", 1)),
        "the settled obligation retired: {ledger}"
    );
    assert!(
        ledger.contains(&dns_rule_tag("b.example.com", 2)),
        "the live grant's obligation survives: {ledger}"
    );
}

#[test]
fn teardown_retires_the_expiry_lease_and_tombstones_its_identities() {
    // C36 r20 F4: teardown retires the lease WITH the sandbox — the
    // owner, the obligations, the withdrawal evidence, the fence-epoch
    // counter — and tombstones the identity history so a recreated
    // incarnation never reuses a request identity. Regression: overdue
    // obligations plus retained evidence, then teardown, then recreate.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            40,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("grant commits");
    let statedir = log.parent().expect("statedir").to_path_buf();
    // Walk the incarnation up to generation 2 first (a daemon-side
    // vanished allow is restored under a fresh identity; C36 r26 F1
    // numbers the first issuance 1), so the tombstone's floor is
    // LOAD-BEARING: the recreated incarnation must floor at generation
    // 3, not merely "not zero".
    let egress_path = statedir.join("acls").join(format!("{acl}.egress"));
    let body = fs::read_to_string(&egress_path).expect("egress rules");
    let gen1_tag = dns_rule_tag("grants.example.com", 1);
    let kept: Vec<&str> = body
        .lines()
        .filter(|line| !(line.contains("action=allow") && line.contains(&gen1_tag)))
        .collect();
    fs::write(&egress_path, kept.join("\n") + "\n").unwrap();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            40,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("the restore re-issues under a fresh generation");
    let egress = acl_egress(&log, &acl);
    assert!(
        egress.contains(&dns_rule_tag("grants.example.com", 3)),
        "the restore carried generation 3 (the gen-1 issuance's fence epoch is \
         preserved in the floor across the marker clear, C36 r27 F1): {egress}"
    );
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    let evidence = statedir.join("host-state/dns-revocations/sbx-1.lease-withdrawals");
    let counter = statedir.join("host-state/dns-revocations/sbx-1.lease-counter");
    let history = statedir.join("host-state/dns-revocations/sbx-1.lease-history");
    assert!(obligations.exists(), "obligations armed");
    // Process death; the grant expires while down (overdue obligation),
    // and retained withdrawal evidence crosses the boundary.
    client.debug_reset_dns_lease_owner("sbx-1");
    std::thread::sleep(Duration::from_secs(43));
    fs::write(
        &evidence,
        format!("{} 128.66.0.7/32\n", dns_rule_tag("grants.example.com", 3)),
    )
    .unwrap();
    fs::write(&counter, "3").unwrap();
    client
        .teardown_sandbox_network("sbx-1")
        .expect("teardown retires the lease");
    assert!(
        !obligations.exists(),
        "obligations retired with the sandbox"
    );
    // The fence-epoch counter and the withdrawal evidence SURVIVE
    // teardown (C36 r23 F5): deleting them would re-enable a fence-epoch
    // collision for a recreated sandbox and lose the completion evidence
    // unresolved identities still need for a later retirement. The
    // recreated allocator reads the tombstone's floor and continues the
    // epoch sequence.
    assert!(
        evidence.exists(),
        "withdrawal evidence is preserved across teardown"
    );
    assert!(
        counter.exists(),
        "the fence-epoch counter is preserved across teardown"
    );
    assert!(
        fs::read_to_string(&history)
            .expect("tombstone body")
            .contains("\"lease_fence_floor\":3"),
        "the tombstone floors the fence epoch at the retired counter value"
    );
    let tombstone = fs::read_to_string(&history).expect("identity history tombstoned");
    assert!(
        tombstone.contains("grants.example.com"),
        "the identity history is tombstoned: {tombstone}"
    );
    // Inverse: recovery on the torn-down sandbox is a clean no-op — the
    // retired state cannot error a later readiness.
    client
        .recover_dns_expiry_obligations("sbx-1")
        .expect("recovery after retirement is a no-op");
    assert!(!obligations.exists(), "nothing re-appears");
    // Recreate: the retained-then-retired evidence must not break the
    // recreate, and the re-grant is a FRESH identity (the tombstone
    // floors generation 2 as used). Re-script the answer with a fresh
    // lifetime (the original answer's expiry has lapsed by now).
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    client
        .apply_sandbox_network(&test_plan("sbx-1"))
        .expect("recreate applies");
    bind_recorded_policy(&log, "sbx-1", &hash);
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("recreate commits");
    let state_body = fs::read_to_string(statedir.join("host-state/dns-policy/sbx-1.json"))
        .expect("persisted DNS state");
    let state: serde_json::Value = serde_json::from_str(&state_body).expect("state json");
    let generation = state["generations"]["grants.example.com"]
        .as_u64()
        .expect("the recreated grant has an identity");
    assert!(
        generation >= 4,
        "the recreated incarnation floors above the tombstoned high-water \
         generation (3): a late mutation of the old incarnation can never \
         collide with a re-issued identity: {state_body}"
    );
    let egress = acl_egress(&log, &acl);
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow destination=128.66.0.7/32")),
        "the recreated grant is enforced: {egress}"
    );
    for retired in [1, 2, 3] {
        assert!(
            !egress.contains(&dns_rule_tag("grants.example.com", retired)),
            "the retired generation-{retired} identity is never re-issued: {egress}"
        );
    }
}

#[test]
fn a_stale_teardown_cannot_retire_a_newer_incarnations_lease() {
    // C36 r20 F4 (incarnation fence): the lease retirement sits AFTER the
    // ownership-fenced deletions, so a stale cleanup record — one whose
    // incarnation set does not match the live resources — errors before
    // any deletion and must NOT stop the newer incarnation's lease.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            3600,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("grant commits");
    let statedir = log.parent().expect("statedir").to_path_buf();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    assert!(obligations.exists(), "lease armed");
    // The stale teardown: fenced to an incarnation the live resources do
    // not carry.
    let outcome =
        client.teardown_sandbox_network_fenced("sbx-1", &["stale-incarnation".to_string()]);
    assert!(outcome.is_err(), "the stale teardown is refused");
    let egress = acl_egress(&log, &acl);
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow destination=128.66.0.7/32")),
        "the newer incarnation's rules are untouched: {egress}"
    );
    assert!(
        obligations.exists(),
        "the newer incarnation's lease is still armed"
    );
    // The refused teardown must not TOMBSTONE the living incarnation.
    // (C36 r27 F1: the file may exist carrying only the request-identity
    // high-water mark, folded in when the grant's commit cleared its
    // marker — what must stay empty is the GENERATION history.)
    let tombstone_path = statedir.join("host-state/dns-revocations/sbx-1.lease-history");
    if let Ok(body) = fs::read_to_string(&tombstone_path) {
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("tombstone json");
        assert_eq!(
            parsed["generations"].as_object().map(|map| map.len()),
            Some(0),
            "no generation is tombstoned for the living incarnation: {body}"
        );
    }
}

#[test]
fn recovery_treats_a_torn_down_acl_as_moot() {
    // A crash during teardown can leave obligations behind after the ACL
    // and state disappear. Recovery must settle-and-stop when the ACL is
    // absent; the leftover records must never block a recreate.
    let (mut client, log) = applied_client("running", "sbx-1");
    let clock = DnsTestClock::install(&mut client);
    let (_network, _acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            40,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("grant commits");
    let statedir = log.parent().expect("statedir").to_path_buf();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    // Process death; the grant expires while down.
    client.debug_reset_dns_lease_owner("sbx-1");
    clock.advance(43);
    // Simulate teardown interrupted after removing the ACL and DNS state,
    // before retiring the lease records.
    let acl_name = sandbox_network_names("sbx-1").1;
    for ext in ["conf", "ingress", "egress", "project"] {
        fs::remove_file(statedir.join(format!("acls/{acl_name}.{ext}"))).ok();
    }
    fs::remove_file(statedir.join("host-state/dns-policy/sbx-1.json")).ok();
    assert!(
        client.read_sandbox_acl(&acl_name).expect("read").is_none(),
        "the ACL is gone, the records remain: {}",
        obligations.exists()
    );
    assert!(obligations.exists(), "the leftover obligation survives");
    client
        .recover_dns_expiry_obligations("sbx-1")
        .expect("recovery moots obligations whose ACL is gone");
    assert!(
        !obligations.exists(),
        "the mooted obligation ledger is cleared"
    );
    // And recovery stays a clean no-op afterwards (no state reappears).
    client
        .recover_dns_expiry_obligations("sbx-1")
        .expect("idempotent");
    assert!(!obligations.exists(), "nothing re-appears");
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn colliding_domain_identities_are_rejected_before_mutation() {
    // C36 r20 F2: domain-rule identities truncate the name hash to 32
    // bits — two names sharing the truncated hash share every
    // generation-scoped identity and would overwrite each other in the
    // expiry map. The collision is REJECTED before any mutation.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    // Find two policy-valid names with the same 32-bit tag hash.
    let mut seen: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut pair = None;
    for n in 0..200_000u64 {
        let name = format!("collide-{n}.example.com");
        let hex = super::network::dns_tag_hex(&name);
        if let Some(other) = seen.insert(hex, name.clone()) {
            pair = Some((other, name));
            break;
        }
    }
    let (first, second) = pair.expect("a 32-bit collision is found quickly");
    let (policy, hash) = domain_policy(&[&first, &second], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        first.as_str(),
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            3600,
        )])],
    );
    transport.script(
        second.as_str(),
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            60,
        )])],
    );
    let outcome = refresh(&client, "sbx-1", &policy, &hash, &transport);
    assert!(outcome.is_err(), "the colliding policy is refused");
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7") && !egress.contains("128.66.0.8"),
        "the rejection happens before ANY mutation: {egress}"
    );
    let statedir = log.parent().expect("statedir").to_path_buf();
    assert!(
        !statedir.join("host-state/dns-policy/sbx-1.json").exists(),
        "no state is persisted for the refused policy"
    );
    // Inverse: either name alone enforces fine — the rejection is the
    // collision, not the names. (Re-script the answer: the refused
    // refresh consumed the scripted record while resolving, before the
    // collision check.)
    transport.script(
        first.as_str(),
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            3600,
        )])],
    );
    let (single_policy, single_hash) = domain_policy(&[first.as_str()], &[]);
    bind_recorded_policy(&log, "sbx-1", &single_hash);
    refresh(&client, "sbx-1", &single_policy, &single_hash, &transport)
        .expect("a single name enforces");
    let egress = acl_egress(&log, &acl);
    assert!(
        egress.contains("128.66.0.7"),
        "the non-colliding policy commits: {egress}"
    );
}

#[test]
fn the_obligation_bound_holds_at_exactly_256_identities() {
    // C36 r20 (inverse-check gap): the reader and the writer share ONE
    // bound — exactly 256 entries (two identities per policy domain).
    // A ledger at exactly the bound recovers; arming a 257th distinct
    // identity refuses closed rather than silently evicting.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, _acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            3600,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("grant commits");
    let statedir = log.parent().expect("statedir").to_path_buf();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    let real: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&obligations).expect("obligations persisted"))
            .expect("obligations json");
    let template = real["entries"][0].clone();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let fabricate = |count: usize| {
        let mut doc = real.clone();
        let entries: Vec<serde_json::Value> = (0..count)
            .map(|i| {
                let mut entry = template.clone();
                entry["expires_at"] = serde_json::json!(now + 3600);
                entry["allow_tag"] = serde_json::json!(format!("wssp-dns-g0-{i:08x}"));
                entry["reject_tag"] = serde_json::json!(format!("wssp-dns-reject-g0-{i:08x}"));
                entry["destinations"] = serde_json::json!([format!("128.66.1.{}/32", i % 250)]);
                entry["fence_on_expiry"] = serde_json::json!([] as [&str; 0]);
                entry
            })
            .collect();
        doc["entries"] = serde_json::json!(entries);
        serde_json::to_string_pretty(&doc).unwrap()
    };
    // Exactly 256 — the exact writer boundary — recovers.
    fs::write(&obligations, fabricate(256)).unwrap();
    client.debug_reset_dns_lease_owner("sbx-1");
    client
        .recover_dns_expiry_obligations("sbx-1")
        .expect("a ledger at exactly the bound recovers");
    // Arming a 257th DISTINCT identity refuses closed (the writer half of
    // the boundary).
    let extra = super::dns::DnsLeaseEntry {
        expires_at: now + 3600,
        allow_tag: "wssp-dns-g0-ffffffff".to_string(),
        reject_tag: "wssp-dns-reject-g0-ffffffff".to_string(),
        name: "extra.example.com".to_string(),
        destinations: ["128.66.2.1/32".to_string()].into_iter().collect(),
        fence_on_expiry: Default::default(),
    };
    let outcome = client.arm_dns_expiry_lease("sbx-1", vec![extra]);
    assert!(
        outcome.is_err(),
        "the writer refuses beyond the shared bound"
    );
    // The refusal did not drop the armed set.
    let ledger: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&obligations).expect("ledger intact"))
            .expect("ledger json");
    assert_eq!(
        ledger["entries"].as_array().map(Vec::len),
        Some(256),
        "the armed set is untouched by the refused arm"
    );
    client.debug_reset_dns_lease_owner("sbx-1");
}
#[test]
fn an_initial_grant_is_fenced_at_expiry_when_its_withdrawal_fails() {
    // C36 r21 F1: the INITIAL arm of the expiry lease must derive
    // `fence_on_expiry` from STATIC policy CIDR coverage only — a resolved
    // domain /32 is an expiring authorization, never cover for itself.
    // Pre-fix the initial publication computed coverage from the resolved
    // plan (which includes the answer's own /32), so every initial dynamic
    // destination looked "covered": at expiry the settlement skipped the
    // fence AND the withdrawal, and an unwithdrawable initial allow left
    // the destination reachable by IP past its expiry.
    let (mut runtime, log) = runtime_for("fix6_new_ready");
    runtime.override_resolver(std::sync::Arc::new(|_domain, _wait| {
        Ok(vec![std::net::IpAddr::V4(Ipv4Addr::new(128, 66, 0, 7))])
    }));
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    let mut request = super::shim_tests::create_req();
    request.egress_policy = Some(policy);
    request.egress_policy_hash = Some(hash);
    runtime.create_bound(&request).expect("create");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let statedir = log.parent().expect("statedir").to_path_buf();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    // THE boundary assertion: the initial lease entry fences the dynamic
    // destination on expiry (nothing static covers it).
    let ledger: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&obligations).expect("obligations armed at initial publication"),
    )
    .expect("obligations json");
    let entry = ledger["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .find(|entry| {
            entry["destinations"]
                .as_array()
                .is_some_and(|dests| dests.iter().any(|d| d.as_str() == Some("128.66.0.7/32")))
        })
        .expect("an obligation covers the granted destination")
        .clone();
    assert!(
        entry["fence_on_expiry"]
            .as_array()
            .is_some_and(|dests| dests.iter().any(|d| d.as_str() == Some("128.66.0.7/32"))),
        "the initial arm fences the expiring destination: {entry}"
    );
    // End-to-end through the settlement boundary: with the allow removal
    // FAILING, the expiry must still deny the destination (fence), never
    // leave it reachable. The grant is armed at the 300s upper clamp
    // (create-time resolution carries no TTL); expire the obligation in
    // the durable ledger and recover it, exactly like a restart finding
    // an overdue obligation.
    fs::write(statedir.join("fail-acl-allow-remove"), "").unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut expired = ledger.clone();
    expired["entries"][0]["expires_at"] = serde_json::json!(now);
    fs::write(
        &obligations,
        serde_json::to_string_pretty(&expired).unwrap(),
    )
    .unwrap();
    let mut daemon = legacy_client(
        statedir.join("incus").to_str().unwrap(),
        "default".to_string(),
    );
    daemon.state_dir = Some(statedir.join("host-state"));
    daemon.debug_reset_dns_lease_owner("sbx-1");
    // Recovery refuses (fail closed): the withdrawal cannot be proven, so
    // the obligation stays armed for retry — but the fence must be
    // installed first, and the armed obligation keeps re-enforcing it.
    let _ = daemon.recover_dns_expiry_obligations("sbx-1");
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let egress = acl_egress(&log, &acl);
        if lease_fence_present(&egress, "128.66.0.7/32") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the expired initial grant is fenced despite the failed withdrawal: {egress}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    // Stable denial: while the withdrawal stays unproven, the allow is
    // never observable without the fence.
    for _ in 0..8 {
        let egress = acl_egress(&log, &acl);
        assert!(
            !egress
                .lines()
                .any(|line| line.contains("action=allow destination=128.66.0.7/32"))
                || lease_fence_present(&egress, "128.66.0.7/32"),
            "never unfenced past expiry: {egress}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    daemon.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn a_covering_static_cidr_suppresses_the_initial_expiry_fence() {
    // C36 r21 F1 (inverse): a destination covered by a STATIC policy CIDR
    // is authorized regardless of the DNS grant — the initial lease entry
    // must NOT fence it at expiry (the fence would be pure over-denial of
    // a statically allowed address), and the grant settles clean.
    let (mut runtime, log) = runtime_for("fix6_new_ready");
    runtime.override_resolver(std::sync::Arc::new(|_domain, _wait| {
        Ok(vec![std::net::IpAddr::V4(Ipv4Addr::new(128, 66, 0, 7))])
    }));
    let (policy, hash) = domain_policy(&["grants.example.com"], &["128.66.0.0/24"]);
    let mut request = super::shim_tests::create_req();
    request.egress_policy = Some(policy);
    request.egress_policy_hash = Some(hash);
    runtime.create_bound(&request).expect("create");
    let statedir = log.parent().expect("statedir").to_path_buf();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    let ledger: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&obligations).expect("obligations armed at initial publication"),
    )
    .expect("obligations json");
    let entry = ledger["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .find(|entry| {
            entry["destinations"]
                .as_array()
                .is_some_and(|dests| dests.iter().any(|d| d.as_str() == Some("128.66.0.7/32")))
        })
        .expect("an obligation covers the granted destination")
        .clone();
    assert!(
        entry["fence_on_expiry"]
            .as_array()
            .is_none_or(|dests| !dests.iter().any(|d| d.as_str() == Some("128.66.0.7/32"))),
        "a statically covered destination is not fenced on expiry: {entry}"
    );
    // Expire the obligation and recover: the settlement withdraws the
    // grant WITHOUT ever fencing the covered destination.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut expired = ledger.clone();
    expired["entries"][0]["expires_at"] = serde_json::json!(now);
    fs::write(
        &obligations,
        serde_json::to_string_pretty(&expired).unwrap(),
    )
    .unwrap();
    let mut daemon = legacy_client(
        statedir.join("incus").to_str().unwrap(),
        "default".to_string(),
    );
    daemon.state_dir = Some(statedir.join("host-state"));
    daemon.debug_reset_dns_lease_owner("sbx-1");
    daemon
        .recover_dns_expiry_obligations("sbx-1")
        .expect("recovery settles the overdue obligation");
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let retired = match fs::read_to_string(&obligations) {
            Ok(body) => !body.contains("128.66.0.7/32"),
            Err(_) => true,
        };
        if retired {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the covered grant settles at its expiry"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let logged = log_lines(&log).join("\n");
    assert!(
        !logged.contains("wssp-dns-lease-quarantine-"),
        "a statically authorized destination is never fenced: {logged}"
    );
    daemon.debug_reset_dns_lease_owner("sbx-1");
}

/// Check the actual cleanup budget before advancing the second lifetime.
/// A timeout below is only a hung-test guard; this bound proves cleanup
/// cannot consume the default 20 seconds ahead of a three-second expiry.
fn assert_withdrawals_bounded_by_next_expiry(
    budgets: &super::client::DnsWithdrawalBudgets,
    destination: &str,
    gap: Duration,
) {
    let budgets = budgets.lock().expect("withdrawal budgets");
    let matching: Vec<_> = budgets
        .iter()
        .filter(|(dest, _)| dest == destination)
        .collect();
    assert!(!matching.is_empty(), "the stalled withdrawal was issued");
    for (_, budget) in matching {
        assert!(
            budget.is_some_and(|budget| budget <= gap),
            "withdrawal budget {budget:?} exceeds the gap {gap:?} to the next expiry"
        );
    }
}

fn wait_for_dns_shim_condition(message: &str, mut ready: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(90);
    while !ready() {
        assert!(std::time::Instant::now() < deadline, "{message}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_stalled_companion_removal_cannot_delay_the_next_expiry() {
    // C36 r21 F2 (companion leg): EVERY serial operation of the lease
    // withdrawal boundary is bounded by the next live expiry — not just
    // the allow withdrawal (which r17 already bounded). The first grant's
    // REJECT COMPANION removals stall at a shim barrier; the second
    // grant must still be fenced at its own deadline, and the stalled
    // companions are abandoned (retried), never waited out past it.
    let (mut client, log) = applied_client("running", "sbx-1");
    let clock = DnsTestClock::install(&mut client);
    let budgets = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    client.dns_withdrawal_budgets = Some(budgets.clone());
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com", "b.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            40,
        )])],
    );
    transport.script(
        "b.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            43,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("both grants commit");
    budgets.lock().expect("withdrawal budgets").clear();
    let statedir = log.parent().expect("statedir").to_path_buf();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    // Stall ONLY the companion (reject) removals: the allow withdrawal
    // and the deadline fence proceed; the companions park at the barrier.
    fs::write(statedir.join("barrier-acl-reject-remove"), "").unwrap();
    // Expire a, then wait for the shim to enter the actual blocking
    // removal (argv logging alone happens before the barrier is reached).
    client.debug_advance_dns_lease_clock("sbx-1", || clock.advance(40));
    wait_for_dns_shim_condition(
        "the first expiry reaches the reject removal barrier",
        || statedir.join("reject-remove-entered").exists(),
    );
    let egress = acl_egress(&log, &acl);
    assert!(
        lease_fence_present(&egress, "128.66.0.7/32"),
        "a is fenced: {egress}"
    );
    assert!(
        !egress
            .lines()
            .any(|line| line.contains("action=allow destination=128.66.0.7/32")),
        "a's allow was withdrawn: {egress}"
    );
    assert_withdrawals_bounded_by_next_expiry(&budgets, "128.66.0.7/32", Duration::from_secs(3));
    // Lifetime and command budgets deliberately use different clocks:
    // advance b to its deadline while a's real command is still parked.
    // The measured budget above proves the bound, and this observation
    // proves the timeout resumes enforcement without releasing cleanup.
    clock.advance(3);
    wait_for_dns_shim_condition("b is fenced despite the stalled reject removal", || {
        lease_fence_present(&acl_egress(&log, &acl), "128.66.0.8/32")
    });
    assert!(
        !statedir.join("release-reject-barrier").exists(),
        "both deadlines were enforced while cleanup remained stalled"
    );
    // The stalled rounds must NOT retire the obligations: the stranded
    // reject companions are deny-leftovers the cleanup still owes. Poll
    // well past the second grant's round (the pass persists only after a
    // round completes) — both entries stay ARMED and fenced, and the
    // next rounds retry the removals.
    let tag_a = dns_rule_tag("a.example.com", 1);
    let tag_b = dns_rule_tag("b.example.com", 2);
    let deadline = std::time::Instant::now() + Duration::from_secs(35);
    while std::time::Instant::now() < deadline {
        let ledger = fs::read_to_string(&obligations)
            .expect("an obligation with unproven companion cleanup stays armed");
        assert!(
            ledger.contains(&tag_a) && ledger.contains(&tag_b),
            "a stalled obligation is not retired with stranded companions: {ledger}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    // Inverse: release the barrier — the stalled removals proceed, both
    // obligations retire, and a clean expiry leaves nothing behind.
    fs::write(statedir.join("release-reject-barrier"), "").unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    while obligations.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "the stalled obligations retire once the removals proceed"
        );
        std::thread::sleep(Duration::from_millis(400));
    }
    let egress = acl_egress(&log, &acl);
    assert!(!egress.contains("128.66.0.7"), "first grant gone: {egress}");
    assert!(
        !egress.contains("128.66.0.8"),
        "second grant gone: {egress}"
    );
    assert!(
        !egress.contains("wssp-dns-lease-quarantine-"),
        "a clean expiry leaves no fence behind: {egress}"
    );
}

#[test]
fn a_failed_companion_removal_keeps_the_obligation_armed() {
    // C36 r21 F2 (companion-verdict leg): a companion removal that
    // completes UNPROVEN (the daemon refuses, the reject rule stays
    // installed) must not retire the obligation — retirement ends the
    // cleanup retries for the stranded deny-leftovers. The destination
    // stays fenced and the obligation armed until a later round proves
    // the removal; only then does the expiry retire clean.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            40,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("grant commits");
    let start = std::time::Instant::now();
    let statedir = log.parent().expect("statedir").to_path_buf();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    // The companion (reject) removals are REFUSED outright: an unproven
    // verdict, not a transport error.
    fs::write(statedir.join("fail-acl-reject-remove"), "").unwrap();
    let tag_a = dns_rule_tag("a.example.com", 1);
    // The expiry still denies on schedule: the allow is withdrawn and
    // the deadline fence lands at +40.
    let deadline = start + Duration::from_secs(60);
    loop {
        let egress = acl_egress(&log, &acl);
        if !egress
            .lines()
            .any(|line| line.contains("action=allow destination=128.66.0.7/32"))
            && lease_fence_present(&egress, "128.66.0.7/32")
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the expiry denies on schedule: {egress}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    // Well past the round's persist: the obligation stays ARMED and the
    // destination FENCED while the companion removals are unproven.
    let deadline = std::time::Instant::now() + Duration::from_secs(25);
    while std::time::Instant::now() < deadline {
        let ledger = fs::read_to_string(&obligations)
            .expect("an obligation with unproven companion cleanup stays armed");
        assert!(
            ledger.contains(&tag_a),
            "the obligation is not retired with stranded companions: {ledger}"
        );
        let egress = acl_egress(&log, &acl);
        assert!(
            lease_fence_present(&egress, "128.66.0.7/32"),
            "the destination stays fenced for the retry: {egress}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    // Inverse: the daemon behaves again — a later round proves the
    // removals, withdraws the fence, and the expiry retires clean.
    fs::remove_file(statedir.join("fail-acl-reject-remove")).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    while obligations.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "the obligation retires once the companion removal proves out"
        );
        std::thread::sleep(Duration::from_millis(400));
    }
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "a clean expiry leaves nothing behind: {egress}"
    );
    assert!(
        !egress.contains("wssp-dns-lease-quarantine-"),
        "a clean expiry leaves no fence behind: {egress}"
    );
}

#[test]
fn a_stalled_fence_withdrawal_cannot_delay_the_next_expiry() {
    // C36 r21 F2 (fence-removal leg): the clean-expiry fence withdrawal
    // (Phase C) is a serial blocking operation in the settle loop like
    // any other — it must be bounded by the next live expiry. Stall the
    // first grant's fence REMOVAL at a barrier: the second grant's
    // deadline fence must still land on time.
    let (mut client, log) = applied_client("running", "sbx-1");
    let clock = DnsTestClock::install(&mut client);
    let budgets = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    client.dns_withdrawal_budgets = Some(budgets.clone());
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com", "b.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            40,
        )])],
    );
    transport.script(
        "b.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            43,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("both grants commit");
    budgets.lock().expect("withdrawal budgets").clear();
    let statedir = log.parent().expect("statedir").to_path_buf();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    fs::write(statedir.join("barrier-acl-lease-fence-remove"), "").unwrap();
    // Expire a, then wait for the shim to enter the actual blocking
    // removal (argv logging alone happens before the barrier is reached).
    client.debug_advance_dns_lease_clock("sbx-1", || clock.advance(40));
    wait_for_dns_shim_condition(
        "the first expiry reaches the lease-fence removal barrier",
        || statedir.join("lease-fence-remove-entered").exists(),
    );
    let egress = acl_egress(&log, &acl);
    assert!(
        lease_fence_present(&egress, "128.66.0.7/32"),
        "a is fenced: {egress}"
    );
    assert!(
        !egress
            .lines()
            .any(|line| line.contains("action=allow destination=128.66.0.7/32")),
        "a's allow was withdrawn: {egress}"
    );
    assert_withdrawals_bounded_by_next_expiry(&budgets, "128.66.0.7/32", Duration::from_secs(3));
    // Lifetime and command budgets deliberately use different clocks:
    // advance b to its deadline while a's real command is still parked.
    // The measured budget above proves the bound, and this observation
    // proves the timeout resumes enforcement without releasing cleanup.
    clock.advance(3);
    wait_for_dns_shim_condition(
        "b is fenced despite the stalled lease-fence removal",
        || lease_fence_present(&acl_egress(&log, &acl), "128.66.0.8/32"),
    );
    assert!(
        !statedir.join("release-lease-fence-barrier").exists(),
        "both deadlines were enforced while cleanup remained stalled"
    );
    // Inverse: release — both fences withdraw and the obligations retire.
    fs::write(statedir.join("release-lease-fence-barrier"), "").unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    while obligations.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "the obligations retire once the fence withdrawal proceeds"
        );
        std::thread::sleep(Duration::from_millis(400));
    }
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7") && !egress.contains("128.66.0.8"),
        "both grants retire clean: {egress}"
    );
}

#[test]
fn a_cancelled_revocation_still_fences_the_destination() {
    // C36 r21 F3: revocation fencing is PERMIT-INDEPENDENT. A revocation
    // (NXDOMAIN) whose allow withdrawal cannot be proven must fence the
    // destination through an enforcement client that carries NO permit —
    // cancelling the operation mid-withdrawal must not let the fence
    // install be refused, leaving the revoked destination reachable.
    let (mut client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("grant commits");
    let statedir = log.parent().expect("statedir").to_path_buf();
    let permit = std::sync::Arc::new(crate::RuntimePermit::default());
    client.cancelled = Some(permit.clone());
    // Revoke; the allow removal is slow (20s per command) and then FAILS
    // (no proof of absence): the withdrawal is unproven, so the boundary
    // must fence. Cancel the issuing permit while the removal is in
    // flight — the fence install must proceed regardless.
    transport.script("grants.example.com", [FakeDnsOutcome::Rcode(3)]);
    fs::write(statedir.join("slow-acl-removals"), "20").unwrap();
    fs::write(statedir.join("fail-acl-allow-remove"), "").unwrap();
    let tag = dns_rule_tag("grants.example.com", 1);
    let outcome = std::thread::scope(|scope| {
        let running = scope.spawn(|| refresh(&client, "sbx-1", &policy, &hash, &transport));
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            let body = fs::read_to_string(&log).unwrap_or_default();
            if body
                .lines()
                .any(|line| line.contains("rule remove") && line.contains(&tag))
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the revocation's allow removal is in flight"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        permit.revoke();
        running.join().expect("refresh thread")
    });
    assert!(
        outcome.is_err(),
        "an unproven revocation under cancellation fails the refresh closed"
    );
    let egress = acl_egress(&log, &acl);
    assert!(
        fence_present(&egress, "128.66.0.7/32"),
        "the revoked destination is fenced even though the issuing permit was revoked: {egress}"
    );
    // Inverse: a working daemon (fresh client, permit never revoked)
    // proves the withdrawal, retires the companions, and releases the
    // fence — no residue.
    fs::remove_file(statedir.join("fail-acl-allow-remove")).unwrap();
    fs::remove_file(statedir.join("slow-acl-removals")).unwrap();
    let mut recovered = legacy_client(
        statedir.join("incus").to_str().unwrap(),
        "default".to_string(),
    );
    recovered.state_dir = Some(statedir.join("host-state"));
    refresh(&recovered, "sbx-1", &policy, &hash, &transport).expect("revoking refresh");
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "a proven revocation leaves nothing behind: {egress}"
    );
}

#[test]
fn an_interrupted_initial_allow_is_fenced_journaled_and_never_effective() {
    // C36 r21 F4: the initial allow issuance goes through the journaled,
    // fenced, tombstone-aware DNS mutation boundary — not a raw rule-add
    // loop. Interrupt the INITIAL allow (the daemon queues it while the CLI
    // reports a transport failure; the test lands it after the retry): the
    // create completes
    // with the destination fenced and the mutation journaled, the late
    // daemon-side apply lands BEHIND the fence, and a later refresh
    // reconciles the stale rule away — the interrupted destination is
    // never effective.
    let (mut runtime, log) = runtime_for("fix6_new_ready");
    let answers = std::sync::Arc::new(std::sync::Mutex::new(vec![std::net::IpAddr::V4(
        Ipv4Addr::new(128, 66, 0, 7),
    )]));
    let shared = answers.clone();
    runtime.override_resolver(std::sync::Arc::new(move |_domain, _wait| {
        Ok(shared.lock().unwrap().clone())
    }));
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    let mut request = super::shim_tests::create_req();
    request.egress_policy = Some(policy.clone());
    request.egress_policy_hash = Some(hash.clone());
    let statedir = log.parent().expect("statedir").to_path_buf();
    let (network, acl) = sandbox_network_names("sbx-1");
    // Scoped to the DNS allow: the base allow rules must install. (C36
    // r26 F1: the first issuance is generation 1.)
    let tag0 = dns_rule_tag("grants.example.com", 1);
    fs::write(
        statedir.join("defer-acl-allow-add-fail"),
        format!("queue {tag0}"),
    )
    .unwrap();
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    // The create FAILS CLOSED: the boundary journaled the interrupted
    // issuance and denied the grant, so readiness over a pending mutation
    // is refused (the verify gate) and the created resources roll back.
    let err = runtime
        .create_bound(&request)
        .expect_err("readiness over a pending interrupted mutation must fail closed");
    assert!(
        err.to_string().contains("pending DNS revocations"),
        "the refusal names the pending DNS mutation: {err}"
    );
    // Boundary evidence: the rollback PRESERVED the journal — the pending
    // mutation is the only record that lets a retry reconcile the
    // deferred daemon-side apply instead of meeting it unprotected.
    let marker = fs::read_to_string(&marker_path)
        .expect("the interrupted issuance's journal survives the rollback");
    assert!(
        marker.contains("128.66.0.7/32"),
        "the pending mutation is durable across the rollback: {marker}"
    );
    assert!(
        !statedir.join(format!("acls/{acl}.conf")).exists(),
        "the rolled-back network is gone"
    );
    assert!(
        !raw_dnsmasq(&log, &network).contains("128.66.0.7"),
        "a denied grant is never published"
    );
    // An immediate retry with a ROTATED answer SUCCEEDS under C36 r22
    // F2: the rollback deleted the ACL, so the retry's fresh incarnation
    // reconciles the unresolved mutation into a STANDING fence
    // obligation — installed BEFORE anything broadens — and readiness is
    // safe to report. The journal is spent down to the standing
    // obligation, which keeps the destination fenced indefinitely.
    fs::remove_file(statedir.join("defer-acl-allow-add-fail")).unwrap();
    *answers.lock().unwrap() = vec![std::net::IpAddr::V4(Ipv4Addr::new(128, 66, 0, 8))];
    runtime
        .create_bound(&request)
        .expect("the retry is usable: the standing fence protects it");
    let marker = fs::read_to_string(&marker_path).expect("the standing obligation persists");
    assert!(
        marker.contains("standing_fences") && marker.contains("128.66.0.7/32"),
        "the unresolved mutation converted to a standing fence obligation: {marker}"
    );
    assert!(
        fence_present(&acl_egress(&log, &acl), "128.66.0.7/32"),
        "the standing fence is installed before readiness: {}",
        acl_egress(&log, &acl)
    );
    // The deferred daemon-side apply then fires against the LIVE
    // recreated ACL: the name-keyed update succeeds — and lands BEHIND
    // the standing fence, so the interrupted destination is never
    // effective. It lands only now: a fixed +25 s delay landed it DURING
    // the retry under load, whose verification then refused the unexpected
    // allow (fail closed, but not this scenario).
    assert_eq!(apply_queued_acl_adds(&statedir), 1);
    let egress_after_apply = acl_egress(&log, &acl);
    assert!(
        egress_after_apply
            .lines()
            .any(|line| line.contains("action=allow") && line.contains("128.66.0.7")),
        "the deferred old apply landed (the race is real): {egress_after_apply}"
    );
    assert!(
        fence_present(&egress_after_apply, "128.66.0.7/32"),
        "the late apply landed behind the standing fence — never effective: {egress_after_apply}"
    );
    // Recovery: teardown now PRESERVES the stranded marker (C36 r22 F2)
    // — a real teardown no longer strands the journal — and the recreate
    // with a rotated answer reconciles it on a fresh incarnation: the
    // unresolved mutation becomes a STANDING fence obligation and the
    // create succeeds. The old destination is never effective (the
    // standing fence denies it) and generation 1 stays tombstoned.
    let mut daemon = legacy_client(
        statedir.join("incus").to_str().unwrap(),
        "default".to_string(),
    );
    daemon.state_dir = Some(statedir.join("host-state"));
    daemon
        .teardown_sandbox_network("sbx-1")
        .expect("teardown succeeds with the marker preserved");
    assert!(
        marker_path.exists(),
        "teardown preserves the unresolved mutation journal (C36 r22 F2)"
    );
    runtime
        .create_bound(&request)
        .expect("the recovered create succeeds with the rotated answer");
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress
            .lines()
            .any(|line| line.contains("action=allow") && line.contains("128.66.0.7")),
        "the interrupted destination is never re-activated: {egress}"
    );
    assert!(
        fence_present(&egress, "128.66.0.7/32"),
        "the standing fence protects the recreated incarnation: {egress}"
    );
    let marker = fs::read_to_string(&marker_path).expect("the standing obligation persists");
    assert!(
        marker.contains("standing_fences") && marker.contains("128.66.0.7/32"),
        "the unresolved mutation converted to a standing fence obligation: {marker}"
    );
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow destination=128.66.0.8/32")),
        "the rotated answer is installed: {egress}"
    );
    assert!(
        !raw_dnsmasq(&log, &network).contains("128.66.0.7"),
        "the interrupted destination is never published"
    );
    // Tombstone floor: the reissue ran under a fresh generation and
    // gen-1's identity (the interrupted original) is never re-issued
    // for a later request.
    let state_body = fs::read_to_string(statedir.join("host-state/dns-policy/sbx-1.json"))
        .expect("persisted DNS state");
    let state: serde_json::Value = serde_json::from_str(&state_body).expect("state json");
    let generation = state["generations"]["grants.example.com"]
        .as_u64()
        .expect("generation recorded");
    assert!(
        generation >= 2,
        "the retry re-issued under a fresh identity"
    );
    let tag0 = dns_rule_tag("grants.example.com", 1);
    assert!(
        !acl_egress(&log, &acl).contains(&tag0),
        "the tombstoned generation-1 identity is never re-issued"
    );
}

#[test]
fn a_refused_lease_arm_leaves_the_owner_state_unchanged() {
    // C36 r21 F5: a REFUSED arm (bound exceeded, or the durable ledger
    // write failing) must leave the live owner exactly as it was —
    // candidate merged, validated and persisted BEFORE anything is
    // published. A refused entry must never become live in the owner
    // (settle-able) even though its identity was merged.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, _acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            3600,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("grant commits");
    let statedir = log.parent().expect("statedir").to_path_buf();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    let real: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&obligations).expect("obligations persisted"))
            .expect("obligations json");
    let template = real["entries"][0].clone();
    let fabricate = |count: usize| {
        let mut doc = real.clone();
        let entries: Vec<serde_json::Value> = (0..count)
            .map(|i| {
                let mut entry = template.clone();
                entry["expires_at"] = serde_json::json!(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                        + 3600
                );
                entry["allow_tag"] = serde_json::json!(format!("wssp-dns-g0-{i:08x}"));
                entry["reject_tag"] = serde_json::json!(format!("wssp-dns-reject-g0-{i:08x}"));
                entry["destinations"] = serde_json::json!([format!("128.66.1.{}/32", i % 250)]);
                entry["fence_on_expiry"] = serde_json::json!([] as [&str; 0]);
                entry
            })
            .collect();
        doc["entries"] = serde_json::json!(entries);
        serde_json::to_string_pretty(&doc).unwrap()
    };
    // Owner live at the 256-identity bound.
    fs::write(&obligations, fabricate(256)).unwrap();
    client.debug_reset_dns_lease_owner("sbx-1");
    client
        .recover_dns_expiry_obligations("sbx-1")
        .expect("a ledger at the bound recovers");
    // A 257th DISTINCT identity, due in 3s and fencing a destination:
    // refused at the bound...
    let soon = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3;
    let extra = super::dns::DnsLeaseEntry {
        expires_at: soon,
        allow_tag: "wssp-dns-g0-ffffffff".to_string(),
        reject_tag: "wssp-dns-reject-g0-ffffffff".to_string(),
        name: "extra.example.com".to_string(),
        destinations: ["128.66.2.1/32".to_string()].into_iter().collect(),
        fence_on_expiry: ["128.66.2.1/32".to_string()].into_iter().collect(),
    };
    assert!(
        client.arm_dns_expiry_lease("sbx-1", vec![extra]).is_err(),
        "the writer refuses beyond the shared bound"
    );
    // ...and the refusal is ATOMIC: the durable ledger is untouched and
    // the refused entry never becomes live in the owner (a buggy
    // publish-then-validate arm would settle it at +3s and attempt its
    // fence — observable in the shim log).
    let ledger: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&obligations).expect("ledger intact"))
            .expect("ledger json");
    let entries = ledger["entries"].as_array().expect("entries");
    assert_eq!(entries.len(), 256, "the armed set is untouched");
    assert!(
        !entries
            .iter()
            .any(|entry| entry["allow_tag"].as_str() == Some("wssp-dns-g0-ffffffff")),
        "the refused identity is not persisted"
    );
    std::thread::sleep(Duration::from_secs(6));
    let logged = log_lines(&log).join("\n");
    assert!(
        !logged.contains("128.66.2.1"),
        "the refused entry never becomes live in the owner: {logged}"
    );
    // Persistence failure: one slot below the bound, the durable write
    // fails (the ledger directory is read-only) — the arm refuses and
    // the owner stays exactly as it was.
    fs::write(&obligations, fabricate(255)).unwrap();
    client.debug_reset_dns_lease_owner("sbx-1");
    client
        .recover_dns_expiry_obligations("sbx-1")
        .expect("recover below the bound");
    let dir = statedir.join("host-state/dns-revocations");
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(&dir).unwrap().permissions();
    perms.set_mode(0o555);
    fs::set_permissions(&dir, perms.clone()).unwrap();
    let soon = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3;
    let extra = super::dns::DnsLeaseEntry {
        expires_at: soon,
        allow_tag: "wssp-dns-g0-eeeeeeee".to_string(),
        reject_tag: "wssp-dns-reject-g0-eeeeeeee".to_string(),
        name: "extra.example.com".to_string(),
        destinations: ["128.66.2.2/32".to_string()].into_iter().collect(),
        fence_on_expiry: ["128.66.2.2/32".to_string()].into_iter().collect(),
    };
    assert!(
        client.arm_dns_expiry_lease("sbx-1", vec![extra]).is_err(),
        "an unpersistable arm refuses closed"
    );
    let ledger: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&obligations).expect("ledger intact"))
            .expect("ledger json");
    assert_eq!(
        ledger["entries"].as_array().map(Vec::len),
        Some(255),
        "the failed persist leaves the ledger as it was"
    );
    // The owner-poisoning tell: had the refused entry leaked into the
    // live owner, the NEXT valid arm would merge it into its candidate
    // (256 + 1 > bound) and refuse too — and a woken watcher would
    // settle the leaked identity. A refused arm leaves the owner EXACTLY
    // as it was: the follow-up arm is accepted and only IT settles.
    perms.set_mode(0o755);
    fs::set_permissions(&dir, perms).unwrap();
    let soon = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3;
    let extra = super::dns::DnsLeaseEntry {
        expires_at: soon,
        allow_tag: "wssp-dns-g0-dddddddd".to_string(),
        reject_tag: "wssp-dns-reject-g0-dddddddd".to_string(),
        name: "extra.example.com".to_string(),
        destinations: ["128.66.2.3/32".to_string()].into_iter().collect(),
        fence_on_expiry: ["128.66.2.3/32".to_string()].into_iter().collect(),
    };
    client
        .arm_dns_expiry_lease("sbx-1", vec![extra])
        .expect("a persistable arm after the refusal is accepted");
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let body = fs::read_to_string(&log).unwrap_or_default();
        if body
            .lines()
            .any(|line| line.contains("rule add") && line.contains("128.66.2.3"))
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "an accepted arm settles on schedule (fence attempted)"
        );
        std::thread::sleep(Duration::from_millis(150));
    }
    assert!(
        !log_lines(&log).join("\n").contains("128.66.2.2"),
        "the refused identity never settles even after the owner wakes"
    );
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn a_parked_refresh_commit_cannot_resurrect_a_settled_grant() {
    // C36 r21 F6: the refresh commit must re-validate its snapshot
    // against the LIVE ACL under the commit lock. A refresh whose
    // snapshot retains grant `a` parks BEFORE the commit lock; while it
    // is parked, `a`'s lease expires and the settlement completes
    // end-to-end (ACL withdrawal AND its own commit). The parked refresh
    // then commits as the LAST writer — it must NOT persist its stale
    // snapshot: the settled grant and its rules stay gone from the
    // durable records.
    let (mut client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com", "b.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            40,
        )])],
    );
    transport.script(
        "b.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("both grants commit");
    let statedir = log.parent().expect("statedir").to_path_buf();
    // The parked refresh re-answers UNCHANGED (no ACL drift, so the
    // settlement's derived commit validates): `a` re-answers with the
    // same short TTL — its fresh expiry lands inside the parked window.
    // Both scripts are re-armed: each resolve consumes one scripted
    // outcome, and the setup refresh already consumed the first.
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            40,
        )])],
    );
    transport.script(
        "b.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            300,
        )])],
    );
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    client.dns_commit_pre_lock_barrier = Some(barrier.clone());
    let client = &client;
    let transport = &transport;
    let policy = &policy;
    let hash = &hash;
    let log = &log;
    let acl = &acl;
    let state_path = statedir.join("host-state/dns-policy/sbx-1.json");
    let refresh_outcome = std::thread::scope(|scope| {
        let refresh = scope.spawn(move || refresh(client, "sbx-1", policy, hash, transport));
        // The refresh commit is parked BEFORE the commit lock: the
        // settlement can complete end-to-end while it waits, leaving the
        // refresh as the LAST writer of the durable records.
        barrier.wait();
        // `a`'s armed lease expires while the refresh is parked: the
        // watcher settles it (fence, withdraw, release) AND commits the
        // post-settlement records — the settled grant is gone from the
        // durable state before the refresh is released.
        let deadline = std::time::Instant::now() + Duration::from_secs(90);
        loop {
            let settled_acl = !acl_egress(log, acl)
                .lines()
                .any(|line| line.contains("action=allow destination=128.66.0.7/32"));
            let settled_records = fs::read_to_string(&state_path)
                .ok()
                .and_then(|body| serde_json::from_str::<serde_json::Value>(&body).ok())
                .is_some_and(|state| {
                    state["grants"].as_array().is_some_and(|grants| {
                        grants
                            .iter()
                            .all(|grant| grant["name"].as_str() != Some("a.example.com"))
                    })
                });
            if settled_acl && settled_records {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the settlement completes — ACL and records — while the refresh is parked"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
        barrier.wait();
        refresh.join().expect("refresh thread")
    });
    refresh_outcome.expect("the refresh commits after the settlement completed");
    // The refresh's commit stands (b's grant survives) but the settled
    // grant is NOT resurrected — not in the persisted DNS state, not in
    // the recorded plan rules.
    let egress = acl_egress(log, acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "the settled grant stays withdrawn: {egress}"
    );
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow destination=128.66.0.8/32")),
        "the surviving grant is untouched: {egress}"
    );
    let state_body = fs::read_to_string(statedir.join("host-state/dns-policy/sbx-1.json"))
        .expect("persisted DNS state");
    let state: serde_json::Value = serde_json::from_str(&state_body).expect("state json");
    assert!(
        state["grants"]
            .as_array()
            .expect("grants")
            .iter()
            .all(|grant| grant["name"].as_str() != Some("a.example.com")),
        "the settled grant is not resurrected in the durable state: {state_body}"
    );
    assert!(
        state["grants"]
            .as_array()
            .expect("grants")
            .iter()
            .any(|grant| grant["name"].as_str() == Some("b.example.com")),
        "the surviving grant is not lost: {state_body}"
    );
    let rules = client
        .persisted_plan_rules("sbx-1", hash)
        .expect("persisted plan");
    assert!(
        !rules
            .iter()
            .any(|rule| rule.destination.as_deref() == Some("128.66.0.7/32")),
        "the recorded plan drops the settled grant's rules"
    );
    assert!(
        rules
            .iter()
            .any(|rule| rule.destination.as_deref() == Some("128.66.0.8/32")),
        "the recorded plan keeps the surviving grant"
    );
}

// ---------------------------------------------------------------------------
// Lease deadlines propagate through every owner-lock-held
// operation (preliminary reads, commit waits, lock-held re-observations,
// duplicate-match retries); unresolved mutations survive teardown and ACL
// name reuse behind standing fences; coverage means surviving verified
// authorization; the commit refuses unexplained live-rule loss; owed
// withdrawal evidence flushes on every settlement attempt.
// ---------------------------------------------------------------------------

#[test]
fn a_stalled_preliminary_read_cannot_delay_the_next_expiry() {
    // C36 r22 F1 (preliminary-read leg): the watcher's pre-settle ACL
    // read runs UNDER the owner lock and must be bounded by the next
    // live expiry. The first read parks at a one-shot shim barrier; it
    // must be killed at the second grant's deadline, and both grants
    // then settle — never waited out past it.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com", "b.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            40,
        )])],
    );
    transport.script(
        "b.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            55,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("both grants commit");
    let start = std::time::Instant::now();
    let statedir = log.parent().expect("statedir").to_path_buf();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    // The NEXT individual-ACL read (the watcher's pre-settle read at
    // +40) parks until released.
    fs::write(statedir.join("barrier-acl-read"), "0").unwrap();
    // Just before the first parked read is killed at the second grant's
    // deadline (+55), park the settle's FIRST post-kill observation too
    // (skip the fast retry pre-read): without the blind pre-fence (C36
    // r23 F10), the second grant's fencing would wait out THAT stall
    // (~20s round budget) — with it, the fence is installed at the
    // deadline, before any observation.
    let rearm = std::thread::spawn({
        let statedir = statedir.clone();
        move || {
            std::thread::sleep(Duration::from_secs(52));
            fs::write(statedir.join("barrier-acl-read"), "1").unwrap();
        }
    });
    // Both expiries are enforced on schedule despite the parked reads.
    let deadline = start + Duration::from_secs(85);
    let second_fenced = loop {
        let elapsed = std::time::Instant::now().duration_since(start).as_secs();
        let egress = acl_egress(&log, &acl);
        let second_allow = egress
            .lines()
            .any(|line| line.contains("action=allow destination=128.66.0.8/32"));
        // C36 r23 F10: the blind pre-fence installs the second grant's
        // quarantine at ITS OWN deadline (55) — before ANY observation —
        // so the destination is fenced by ~deadline+5 even while the
        // preliminary read is parked; no fence-wait, no retry tick.
        assert!(
            !second_allow || elapsed < 60 || lease_fence_present(&egress, "128.66.0.8/32"),
            "the second expiry is never unfenced past its own deadline: {egress}"
        );
        if lease_fence_present(&egress, "128.66.0.8/32") {
            break std::time::Instant::now();
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the second grant is fenced at its own deadline despite the stalled read: {egress}"
        );
        std::thread::sleep(Duration::from_millis(250));
    };
    rearm.join().expect("rearm thread");
    assert!(
        second_fenced < start + Duration::from_secs(62),
        "the stalled preliminary read did not delay the second deadline"
    );
    assert!(
        !statedir.join("release-acl-read-barrier").exists(),
        "both deadlines were enforced while the read was parked"
    );
    // Inverse: release the barrier (cleanup for the killed shim spin);
    // both obligations settle and retire cleanly.
    fs::write(statedir.join("release-acl-read-barrier"), "").unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    while obligations.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "both obligations retire once the reads proceed"
        );
        std::thread::sleep(Duration::from_millis(400));
    }
    let egress = acl_egress(&log, &acl);
    assert!(!egress.contains("128.66.0.7"), "first grant gone: {egress}");
    assert!(
        !egress.contains("128.66.0.8"),
        "second grant gone: {egress}"
    );
    assert!(
        !egress.contains("wssp-dns-lease-quarantine-"),
        "a clean expiry leaves no fence behind: {egress}"
    );
}

#[test]
fn a_stalled_commit_wait_cannot_delay_the_next_expiry() {
    // C36 r22 F1 (commit-wait leg): the lease settlement's commit runs
    // under the owner lock; waiting on the commit lock behind a parked
    // refresh commit must be bounded by the next live expiry — the
    // settlement fails closed and retries instead of delaying the
    // second grant's fencing.
    let (mut client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com", "b.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            40,
        )])],
    );
    transport.script(
        "b.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            55,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("both grants commit");
    let start = std::time::Instant::now();
    let statedir = log.parent().expect("statedir").to_path_buf();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    // A renewal re-answers both (scripts are consumed per resolve):
    // `a` re-arms to ~+43, `b` to ~+58 — and its commit parks UNDER the
    // commit lock, blocking the settlement's rewrite.
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            40,
        )])],
    );
    transport.script(
        "b.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            55,
        )])],
    );
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    client.dns_commit_barrier = Some(barrier.clone());
    let refresh_outcome = std::thread::scope(|scope| {
        let refresh = scope.spawn(|| refresh(&client, "sbx-1", &policy, &hash, &transport));
        barrier.wait();
        // The refresh commit is parked holding the commit lock. `a`'s
        // settlement fences and withdraws on schedule, then its commit
        // must NOT wait past `b`'s deadline behind the park.
        let deadline = start + Duration::from_secs(90);
        let mut fenced_at = None;
        while std::time::Instant::now() < deadline {
            let elapsed = std::time::Instant::now().duration_since(start).as_secs();
            let egress = acl_egress(&log, &acl);
            let second_allow = egress
                .lines()
                .any(|line| line.contains("action=allow destination=128.66.0.8/32"));
            assert!(
                !second_allow || elapsed < 58 || lease_fence_present(&egress, "128.66.0.8/32"),
                "the second expiry is never unfenced past its deadline: {egress}"
            );
            if lease_fence_present(&egress, "128.66.0.8/32") {
                fenced_at = Some(std::time::Instant::now());
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        // Release the parked commit BEFORE asserting, so a failing
        // build never deadlocks the parked thread.
        barrier.wait();
        (refresh.join().expect("refresh thread"), fenced_at)
    });
    let fenced_at = fenced_opt_expect(refresh_outcome.1);
    assert!(
        fenced_at < start + Duration::from_secs(80),
        "the stalled commit wait did not delay the second deadline"
    );
    // The released refresh commit now TOLERATES the missing rules (C36
    // r23 F7): the settlement's withdrawal evidence for `a` is durable
    // the moment the proof exists (r23 F8), so the absence is EXPLAINED
    // by an affirmative settlement even though the settlement's own
    // commit lost the lock race — the refresh revalidation drops the
    // settled grant (C36 r21 F6) instead of resurrecting it, and the
    // settlement's retry commits the lifecycle transition.
    refresh_outcome
        .0
        .expect("the commit tolerates the evidence-backed settlement loss");
    // Inverse: with the commit lock free, the settlement's retry commits
    // and both obligations retire cleanly.
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    while obligations.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "the settlements commit on retry and retire"
        );
        std::thread::sleep(Duration::from_millis(400));
    }
    let egress = acl_egress(&log, &acl);
    assert!(!egress.contains("128.66.0.7"), "first grant gone: {egress}");
    assert!(
        !egress.contains("128.66.0.8"),
        "second grant gone: {egress}"
    );
    assert!(
        !egress.contains("wssp-dns-lease-quarantine-"),
        "a clean expiry leaves no fence behind: {egress}"
    );
}

/// Scoped unwrap for the fencing timestamp (keeps the release ordering
/// above panic-free).
fn fenced_opt_expect(value: Option<std::time::Instant>) -> std::time::Instant {
    value.expect("the second grant was fenced")
}

#[test]
fn a_delayed_duplicate_match_retry_cannot_delay_the_next_expiry() {
    // C36 r22 F1 (duplicate-match retry leg): the plain removal and the
    // `--force` retry share ONE absolute deadline — the retry gets only
    // what remains, so a slow refusal plus a slow retry can never push
    // the pair past the next expiry's fencing.
    let (mut client, log) = applied_client("running", "sbx-1");
    let clock = DnsTestClock::install(&mut client);
    let budgets = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    client.dns_withdrawal_budgets = Some(budgets.clone());
    let attempts = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    client.dns_withdrawal_attempts = Some(attempts.clone());
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com", "b.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            40,
        )])],
    );
    transport.script(
        "b.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            43,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("both grants commit");
    budgets.lock().expect("withdrawal budgets").clear();
    attempts.lock().expect("withdrawal attempts").clear();
    let statedir = log.parent().expect("statedir").to_path_buf();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    // Each completed removal consumes two logical seconds. The plain
    // refusal and force retry span b's expiry without any TTL sleep.
    // Park the subsequent fence cleanup so enforcement stays observable.
    fs::write(statedir.join("slow-acl-removals"), "2").unwrap();
    fs::write(statedir.join("duplicate-acl-allow-remove"), "").unwrap();
    fs::write(statedir.join("barrier-acl-lease-fence-remove"), "").unwrap();
    client.debug_advance_dns_lease_clock("sbx-1", || clock.advance(40));
    wait_for_dns_shim_condition("the duplicate retry reaches fence cleanup", || {
        statedir.join("lease-fence-remove-entered").exists()
    });
    assert_withdrawals_bounded_by_next_expiry(&budgets, "128.66.0.7/32", Duration::from_secs(3));
    // Observe the deadlines actually passed to the command boundary:
    // restarting a full timeout for --force must fail even if both shim
    // processes finish quickly on this machine.
    {
        let attempts = attempts.lock().expect("withdrawal attempts");
        let tag = dns_rule_tag("a.example.com", 1);
        let plain = attempts
            .iter()
            .find(|(id, force, _)| id == &tag && !force)
            .expect("plain removal was issued");
        let forced = attempts
            .iter()
            .find(|(id, force, _)| id == &tag && *force)
            .expect("duplicate refusal was retried with --force");
        assert!(plain.2.is_some(), "the plain attempt has a deadline");
        assert_eq!(
            forced.2, plain.2,
            "both attempts spend one absolute deadline"
        );
    }
    wait_for_dns_shim_condition("b is fenced despite the duplicate retry", || {
        lease_fence_present(&acl_egress(&log, &acl), "128.66.0.8/32")
    });
    assert!(
        !statedir.join("release-lease-fence-barrier").exists(),
        "b's deadline was enforced before cleanup was released"
    );
    // Inverse: the daemon behaves again — the stalled pair retries,
    // both obligations retire, nothing is left behind.
    fs::remove_file(statedir.join("slow-acl-removals")).unwrap();
    fs::remove_file(statedir.join("duplicate-acl-allow-remove")).unwrap();
    fs::write(statedir.join("release-lease-fence-barrier"), "").unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    while obligations.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "both obligations retire once the removals proceed"
        );
        std::thread::sleep(Duration::from_millis(400));
    }
    let egress = acl_egress(&log, &acl);
    assert!(!egress.contains("128.66.0.7"), "first grant gone: {egress}");
    assert!(
        !egress.contains("128.66.0.8"),
        "second grant gone: {egress}"
    );
    assert!(
        !egress.contains("wssp-dns-lease-quarantine-"),
        "a clean expiry leaves no fence behind: {egress}"
    );
}

#[test]
fn a_stalled_owner_lock_read_cannot_delay_the_next_expiry() {
    // C36 r22 F1 (owner-lock re-observation leg): the refresh's stale
    // lease-fence release re-reads the ACL while holding the OWNER
    // state lock — the same lock the watcher settles under. That read
    // must be bounded by the live grants' deadlines: a parked read is
    // killed at the next expiry (the refresh fails closed) instead of
    // delaying the settlement behind it.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com", "b.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    transport.script(
        "b.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            40,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("both grants commit");
    let start = std::time::Instant::now();
    let statedir = log.parent().expect("statedir").to_path_buf();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    // Plant a stale LEASE fence on `a`'s still-authorized destination:
    // the next refresh classifies it for the owner-lock release phase.
    let fence_tag = dns_lease_fence_tag("128.66.0.7/32", 77);
    let egress_path = statedir.join("acls").join(format!("{acl}.egress"));
    let body = fs::read_to_string(&egress_path).expect("egress");
    fs::write(
        &egress_path,
        format!("{body}action=reject destination=128.66.0.7/32 description={fence_tag}\n"),
    )
    .expect("plant the stale lease fence");
    // Park the THIRD individual-ACL read of the refresh — the first is
    // the tail's missing-names observation, the second the pass's
    // opening observation; the third is the owner-lock-held
    // release-phase re-observation.
    fs::write(statedir.join("barrier-acl-read"), "2").unwrap();
    // A watchdog releases the park late so a failing (unbounded) build
    // still terminates instead of hanging the test.
    let release_path = statedir.join("release-acl-read-barrier");
    let watchdog = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(70));
        fs::write(release_path, "").unwrap();
    });
    // The renewal re-answers both (scripts are consumed per resolve).
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    transport.script(
        "b.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            40,
        )])],
    );
    let outcome = refresh(&client, "sbx-1", &policy, &hash, &transport);
    // Bounded: the parked read is killed at `b`'s deadline and the
    // refresh fails CLOSED (nothing was broadened; the stale fence is
    // kept-expected and retried).
    let err = outcome.expect_err("a killed owner-lock read fails the pass closed");
    assert!(
        std::time::Instant::now() < start + Duration::from_secs(60),
        "the parked read was killed at the live deadline, not waited out: {err}"
    );
    // `b`'s settlement was never delayed behind the stalled read: the
    // expired grant is DENIED on schedule (a clean settle withdraws the
    // transient fence with the rules, so the assertion is the allow's
    // absence, not the fence's presence).
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let egress = acl_egress(&log, &acl);
        if !egress
            .lines()
            .any(|line| line.contains("action=allow destination=128.66.0.8/32"))
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the second grant is withdrawn at its own deadline: {egress}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    watchdog.join().expect("watchdog");
    // Inverse: a clean refresh commits (the failed pass's lapsed-grant
    // cleanup already revoked `b`; `a` stays live throughout).
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    transport.script(
        "b.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the retry releases the fence");
    let egress = acl_egress(&log, &acl);
    assert!(
        !lease_fence_present(&egress, "128.66.0.7/32"),
        "the stale fence is released once the read proceeds: {egress}"
    );
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow destination=128.66.0.7/32")),
        "the live grant is untouched: {egress}"
    );
    let _ = obligations;
}

#[test]
fn a_missing_companion_is_not_coverage_for_a_withdrawal() {
    // C36 r22 F3: coverage for an allow withdrawal must come from a
    // SURVIVING VERIFIED authorization — an installed allow whose whole
    // reject-companion group is observed and untouched — never from
    // desired-answer membership. A refresh that must repair a missing
    // companion withdraws the overlapping allow first; when that
    // withdrawal is REFUSED, the destination is fenced, because the
    // identity being repaired cannot vouch for its own coverage.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            60,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("first refresh");
    let statedir = log.parent().expect("statedir").to_path_buf();
    // Knock out ONE companion (udp/53) of the live identity.
    let egress_path = statedir.join("acls").join(format!("{acl}.egress"));
    let body = fs::read_to_string(&egress_path).expect("egress");
    let victim = body
        .lines()
        .find(|line| {
            line.contains("destination=128.66.0.7/32")
                && line.contains("destination_port=53")
                && line.contains("protocol=udp")
                && line.contains("wssp-dns-reject-")
        })
        .expect("udp/53 companion")
        .to_string();
    let tampered: String = body
        .lines()
        .filter(|line| *line != victim)
        .map(|line| format!("{line}\n"))
        .collect();
    fs::write(&egress_path, tampered).expect("tamper");
    // The allow withdrawal is REFUSED outright (the rule stays).
    fs::write(statedir.join("fail-acl-allow-remove"), "").unwrap();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            60,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect_err("the refused repair withdrawal fails the pass");
    let egress = acl_egress(&log, &acl);
    // The unproven allow stays installed but the destination is FENCED:
    // without the companion the resolver path is open, so the refused
    // withdrawal must never treat the destination as covered.
    assert!(
        egress.contains("action=allow destination=128.66.0.7/32"),
        "the refused withdrawal left the allow installed: {egress}"
    );
    assert!(
        fence_present(&egress, "128.66.0.7/32"),
        "the refused repair withdrawal quarantines the destination: {egress}"
    );
    // Inverse: the daemon behaves again — the repair completes (fresh
    // identity, full companions), the fence releases.
    fs::remove_file(statedir.join("fail-acl-allow-remove")).unwrap();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            60,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the repair completes");
    let egress = acl_egress(&log, &acl);
    for needle in ["destination_port=53", "destination_port=853"] {
        assert!(
            egress
                .lines()
                .filter(|line| line.contains("destination=128.66.0.7/32")
                    && line.contains(needle)
                    && line.contains("wssp-dns-reject-"))
                .count()
                >= 1,
            "the repaired companions are installed ({needle}): {egress}"
        );
    }
    assert!(
        !fence_present(&egress, "128.66.0.7/32"),
        "the fence releases once the grant is verified whole: {egress}"
    );
}

#[test]
fn an_unexplained_live_rule_loss_refuses_the_commit() {
    // C36 r22 F4: the commit revalidation must REFUSE a live ACL that
    // lost rules the durable plan still claims — only a proven
    // settlement explains an absence. A refresh parked BEFORE the
    // commit lock has a live reject companion deleted underneath it;
    // the commit must refuse without rewriting any trusted record.
    let (mut client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com", "b.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    transport.script(
        "b.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("both grants commit");
    let statedir = log.parent().expect("statedir").to_path_buf();
    let state_path = statedir.join("host-state/dns-policy/sbx-1.json");
    let state_before = fs::read_to_string(&state_path).expect("durable state");
    let rules_before = client
        .persisted_plan_rules("sbx-1", &hash)
        .expect("persisted plan")
        .len();
    // The parked refresh re-answers unchanged (scripts re-armed).
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    transport.script(
        "b.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            300,
        )])],
    );
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    client.dns_commit_pre_lock_barrier = Some(barrier.clone());
    let refresh_outcome = std::thread::scope(|scope| {
        let refresh = scope.spawn(|| refresh(&client, "sbx-1", &policy, &hash, &transport));
        barrier.wait();
        // The commit is parked BEFORE the commit lock: delete ONE live
        // reject companion of `a` underneath it — no settlement ran, so
        // nothing explains the loss.
        let egress_path = statedir.join("acls").join(format!("{acl}.egress"));
        let body = fs::read_to_string(&egress_path).expect("egress");
        let victim = body
            .lines()
            .find(|line| {
                line.contains("destination=128.66.0.7/32")
                    && line.contains("destination_port=853")
                    && line.contains("wssp-dns-reject-")
            })
            .expect("tcp/853 companion")
            .to_string();
        let tampered: String = body
            .lines()
            .filter(|line| *line != victim)
            .map(|line| format!("{line}\n"))
            .collect();
        fs::write(&egress_path, tampered).expect("tamper");
        barrier.wait();
        refresh.join().expect("refresh thread")
    });
    let err = refresh_outcome.expect_err("the commit refuses the unexplained loss");
    assert!(
        err.to_string().contains("lost rules"),
        "the refusal names the unexplained loss: {err}"
    );
    // The parked-commit hook is spent: later refreshes run free.
    client.dns_commit_pre_lock_barrier = None;
    // The trusted records are byte-identical: the refusal committed
    // NOTHING (no collapsed plan, no rewritten state).
    assert_eq!(
        fs::read_to_string(&state_path).expect("durable state"),
        state_before,
        "the durable DNS state is untouched by the refused commit"
    );
    let rules = client
        .persisted_plan_rules("sbx-1", &hash)
        .expect("persisted plan");
    assert_eq!(
        rules.len(),
        rules_before,
        "the recorded plan is untouched by the refused commit"
    );
    assert!(
        rules
            .iter()
            .any(|rule| rule.destination_port.as_deref() == Some("853")
                && rule.destination.as_deref() == Some("128.66.0.7/32")),
        "the recorded plan still claims the lost companion"
    );
    // Inverse: the next refresh reconciles against the still-trusted
    // records and REPAIRS the live ACL (fresh identity, full group).
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    transport.script(
        "b.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the retry repairs");
    let egress = acl_egress(&log, &acl);
    assert!(
        egress
            .lines()
            .any(|line| line.contains("destination=128.66.0.7/32")
                && line.contains("destination_port=853")
                && line.contains("wssp-dns-reject-")),
        "the lost companion is repaired: {egress}"
    );
}

#[test]
fn a_deferred_allow_landing_after_recreate_never_becomes_effective() {
    // C36 r22 F2: teardown and recreate with a ROTATED answer BEFORE the
    // old deferred apply fires. The old destination must never become
    // effectively allowed on the recreated ACL: the marker survives the
    // teardown, the recreate converts the unresolved mutation into a
    // STANDING fence, and the late daemon-side apply lands behind it.
    let (mut runtime, log) = runtime_for("fix6_new_ready");
    let answers = std::sync::Arc::new(std::sync::Mutex::new(vec![std::net::IpAddr::V4(
        Ipv4Addr::new(128, 66, 0, 7),
    )]));
    let shared = answers.clone();
    runtime.override_resolver(std::sync::Arc::new(move |_domain, _wait| {
        Ok(shared.lock().unwrap().clone())
    }));
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    let mut request = super::shim_tests::create_req();
    request.egress_policy = Some(policy.clone());
    request.egress_policy_hash = Some(hash.clone());
    let statedir = log.parent().expect("statedir").to_path_buf();
    let (network, acl) = sandbox_network_names("sbx-1");
    let tag0 = dns_rule_tag("grants.example.com", 1);
    fs::write(
        statedir.join("defer-acl-allow-add-fail"),
        format!("queue {tag0}"),
    )
    .unwrap();
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    runtime
        .create_bound(&request)
        .expect_err("the interrupted initial issuance fails closed");
    assert!(marker_path.exists(), "the rollback preserved the journal");
    // TEARDOWN the rolled-back sandbox and recreate BEFORE the deferred
    // apply fires: the marker survives the teardown, and the recreate
    // reconciles the unresolved mutation into a standing fence.
    let mut daemon = legacy_client(
        statedir.join("incus").to_str().unwrap(),
        "default".to_string(),
    );
    daemon.state_dir = Some(statedir.join("host-state"));
    daemon
        .teardown_sandbox_network("sbx-1")
        .expect("teardown succeeds with the marker preserved");
    assert!(
        marker_path.exists(),
        "the unresolved mutation survives the teardown (C36 r22 F2)"
    );
    fs::remove_file(statedir.join("defer-acl-allow-add-fail")).unwrap();
    // C36 r36 F1: recreate with a DOMAIN-FREE policy first. No DNS
    // answers need publication, but the preserved standing obligation
    // must still be enforced on the fresh incarnation — pre-fix the
    // publication boundary returned early, no fence was installed,
    // readiness passed (standing-only markers do not gate it), and the
    // delayed old allow would land EFFECTIVE with no expiry watcher
    // armed. The marker also crosses a policy-hash generation here: the
    // reborn boundary re-scopes the preserved obligations.
    let (free_policy, free_hash) = domain_policy(&[], &[]);
    let mut free_request = super::shim_tests::create_req();
    free_request.egress_policy = Some(free_policy);
    free_request.egress_policy_hash = Some(free_hash);
    runtime
        .create_bound(&free_request)
        .expect("the domain-free recreation enforces the preserved obligation");
    let egress = acl_egress(&log, &acl);
    assert!(
        fence_present(&egress, "128.66.0.7/32"),
        "the standing fence is installed on the domain-free incarnation: {egress}"
    );
    assert!(
        !egress
            .lines()
            .any(|line| line.contains("action=allow") && line.contains("128.66.0.7")),
        "no allow for the old destination: {egress}"
    );
    // Inverse (C36 r36 F1): a domain-free recreation whose static policy
    // EXPLICITLY AUTHORIZES the destination suppresses the fence — and
    // the obligation itself survives (only positive withdrawal evidence
    // retires it).
    let mut daemon_free = legacy_client(
        statedir.join("incus").to_str().unwrap(),
        "default".to_string(),
    );
    daemon_free.state_dir = Some(statedir.join("host-state"));
    daemon_free
        .teardown_sandbox_network("sbx-1")
        .expect("teardown succeeds with the marker preserved");
    let (cidr_policy, cidr_hash) = domain_policy(&[], &["128.66.0.7/32"]);
    let mut cidr_request = super::shim_tests::create_req();
    cidr_request.egress_policy = Some(cidr_policy);
    cidr_request.egress_policy_hash = Some(cidr_hash);
    runtime
        .create_bound(&cidr_request)
        .expect("the CIDR-authorizing domain-free recreation succeeds");
    let egress = acl_egress(&log, &acl);
    assert!(
        !fence_present(&egress, "128.66.0.7/32"),
        "an explicitly authorized CIDR suppresses the fence: {egress}"
    );
    let marker: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&marker_path).expect("the standing obligation persists"),
    )
    .expect("marker json");
    assert!(
        marker["standing_fences"]
            .as_array()
            .is_some_and(|fences| fences.iter().any(|fence| {
                fence["destination"].as_str() == Some("128.66.0.7/32")
                    || fence.as_str() == Some("128.66.0.7/32")
            })),
        "authorization suppresses the fence, never the obligation: {marker}"
    );
    let mut daemon_post = legacy_client(
        statedir.join("incus").to_str().unwrap(),
        "default".to_string(),
    );
    daemon_post.state_dir = Some(statedir.join("host-state"));
    daemon_post
        .teardown_sandbox_network("sbx-1")
        .expect("teardown succeeds");
    *answers.lock().unwrap() = vec![std::net::IpAddr::V4(Ipv4Addr::new(128, 66, 0, 8))];
    runtime
        .create_bound(&request)
        .expect("the recreate is usable: the standing fence protects it");
    let egress = acl_egress(&log, &acl);
    assert!(
        fence_present(&egress, "128.66.0.7/32"),
        "the standing fence is installed before readiness: {egress}"
    );
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow destination=128.66.0.8/32")),
        "the rotated answer is installed: {egress}"
    );
    // The deferred OLD apply then fires against the LIVE recreated ACL:
    // it lands — and stays behind the standing fence, never effective.
    assert_eq!(apply_queued_acl_adds(&statedir), 1);
    let egress = acl_egress(&log, &acl);
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow") && line.contains("128.66.0.7")),
        "the deferred old apply landed (the race is real): {egress}"
    );
    assert!(
        fence_present(&egress, "128.66.0.7/32"),
        "the late apply landed behind the standing fence: {egress}"
    );
    assert!(
        !raw_dnsmasq(&log, &network).contains("128.66.0.7"),
        "the old destination is never published"
    );
    // Inverse: a CLEAN teardown/recreate (no unresolved mutations beyond
    // the standing obligation) stays plainly usable.
    let mut daemon2 = legacy_client(
        statedir.join("incus").to_str().unwrap(),
        "default".to_string(),
    );
    daemon2.state_dir = Some(statedir.join("host-state"));
    daemon2
        .teardown_sandbox_network("sbx-1")
        .expect("teardown succeeds");
    runtime
        .create_bound(&request)
        .expect("a clean recreate succeeds");
    let egress = acl_egress(&log, &acl);
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow destination=128.66.0.8/32")),
        "the clean recreate installs the answer: {egress}"
    );
    // The standing obligation still protects the OLD destination.
    assert!(
        fence_present(&egress, "128.66.0.7/32"),
        "the standing fence persists across clean recreates: {egress}"
    );
    // C36 r23 F2, reauthorization leg: rotate the answer BACK to the old
    // destination and recreate — a same-destination reauthorization.
    // Authorization SUPPRESSES the standing fence at planning time but
    // must NEVER remove it: only positive withdrawal evidence for the
    // preserved identity retires it, and the old allow vanished with the
    // torn-down ACL — no evidence exists.
    *answers.lock().unwrap() = vec![std::net::IpAddr::V4(Ipv4Addr::new(128, 66, 0, 7))];
    let mut daemon3 = legacy_client(
        statedir.join("incus").to_str().unwrap(),
        "default".to_string(),
    );
    daemon3.state_dir = Some(statedir.join("host-state"));
    daemon3
        .teardown_sandbox_network("sbx-1")
        .expect("teardown succeeds");
    runtime
        .create_bound(&request)
        .expect("the same-destination reauthorization is usable");
    let egress = acl_egress(&log, &acl);
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow destination=128.66.0.7/32")),
        "the reauthorized answer is installed: {egress}"
    );
    // Authorization SUPPRESSES the standing fence (it is released only
    // behind the verified replacement), but the OBLIGATION survives: no
    // positive withdrawal evidence for the preserved identity exists —
    // the old allow vanished with the torn-down ACL.
    let marker: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&marker_path).expect("the standing obligation persists"),
    )
    .expect("marker json");
    assert!(
        marker["standing_fences"]
            .as_array()
            .is_some_and(|fences| fences.iter().any(|fence| {
                fence["destination"].as_str() == Some("128.66.0.7/32")
                    || fence.as_str() == Some("128.66.0.7/32")
            })),
        "the reauthorization alone never retires the standing obligation: {marker}"
    );
    // C36 r23 F2, expiry leg: the reauthorized grant expires. The settle
    // withdraws it; the STANDING fence still does not retire (the expiry
    // withdrew the NEW identity, not the preserved one), so a deferred
    // apply of the original identity can still only land behind it.
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    let ledger: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&obligations).expect("obligations armed"))
            .expect("obligations json");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut expired = ledger.clone();
    for entry in expired["entries"].as_array_mut().expect("entries") {
        entry["expires_at"] = serde_json::json!(now);
    }
    fs::write(
        &obligations,
        serde_json::to_string_pretty(&expired).unwrap(),
    )
    .unwrap();
    let mut daemon4 = legacy_client(
        statedir.join("incus").to_str().unwrap(),
        "default".to_string(),
    );
    daemon4.state_dir = Some(statedir.join("host-state"));
    daemon4.debug_reset_dns_lease_owner("sbx-1");
    daemon4
        .recover_dns_expiry_obligations("sbx-1")
        .expect("recovery settles the expired reauthorization");
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    loop {
        let egress = acl_egress(&log, &acl);
        let reauthorized_allow_gone = !egress
            .lines()
            .any(|line| line.contains("action=allow destination=128.66.0.7/32"));
        if reauthorized_allow_gone {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the expired reauthorization settles: {egress}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    let egress = acl_egress(&log, &acl);
    assert!(
        fence_present(&egress, "128.66.0.7/32"),
        "the suppression ends with the reauthorization's expiry — the \
         destination is fenced again, so a deferred apply of the original \
         identity can only ever land behind a fence: {egress}"
    );
    // The next commit settles standing obligations with withdrawal
    // evidence for a DIFFERENT identity of the same destination on file
    // (the expired reauthorization's): only evidence for the PRESERVED
    // identity may retire the obligation.
    *answers.lock().unwrap() = vec![std::net::IpAddr::V4(Ipv4Addr::new(128, 66, 0, 8))];
    let mut daemon5 = legacy_client(
        statedir.join("incus").to_str().unwrap(),
        "default".to_string(),
    );
    daemon5.state_dir = Some(statedir.join("host-state"));
    daemon5
        .teardown_sandbox_network("sbx-1")
        .expect("teardown succeeds");
    runtime
        .create_bound(&request)
        .expect("the rotated recreate is usable");
    let marker: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&marker_path).expect("the standing obligation survives"),
    )
    .expect("marker json");
    assert!(
        marker["standing_fences"]
            .as_array()
            .is_some_and(|fences| fences.iter().any(|fence| {
                fence["destination"].as_str() == Some("128.66.0.7/32")
                    || fence.as_str() == Some("128.66.0.7/32")
            })),
        "evidence for another identity never retires the obligation: {marker}"
    );
    let egress = acl_egress(&log, &acl);
    assert!(
        fence_present(&egress, "128.66.0.7/32"),
        "the standing fence is re-planned on the rotated recreate: {egress}"
    );
    let _ = &network;
    daemon4.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn owed_evidence_flushes_without_a_new_withdrawal() {
    // C36 r22 F5: owed withdrawal evidence is retried on EVERY
    // settlement attempt, independently of new withdrawals. A grant
    // whose destination is static-CIDR-covered needs no fence counter
    // write; make ONLY the evidence log unwritable for the expiry round
    // (the withdrawal itself succeeds), then restore storage: the next
    // attempt flushes the owed evidence and retires the journal and
    // obligation with no further refresh or grant.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com"], &["128.66.0.0/24"]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            40,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("grant commits");
    let start = std::time::Instant::now();
    let statedir = log.parent().expect("statedir").to_path_buf();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    let tag_a = dns_rule_tag("a.example.com", 1);
    // Storage fails for the whole dns-revocations directory: the
    // evidence write (and the obligation re-persist) fail while the
    // shim-side withdrawal succeeds.
    let revocations_dir = statedir.join("host-state/dns-revocations");
    let metadata = fs::metadata(&revocations_dir).expect("dir");
    let mut readonly = metadata.permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        readonly.set_mode(0o555);
        fs::set_permissions(&revocations_dir, readonly.clone()).expect("readonly");
    }
    // The expiry still withdraws the allow on schedule (no fence: the
    // destination is static-covered) — but the obligation must stay
    // ARMED: the withdrawal evidence is not durable.
    let deadline = start + Duration::from_secs(70);
    loop {
        let egress = acl_egress(&log, &acl);
        if !egress
            .lines()
            .any(|line| line.contains("action=allow destination=128.66.0.7/32"))
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the expiry withdraws the allow on schedule: {egress}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    // Well past the failed round: the obligation stays armed (its ledger
    // write also failed, so the file still lists the identity).
    let deadline = std::time::Instant::now() + Duration::from_secs(12);
    while std::time::Instant::now() < deadline {
        let ledger =
            fs::read_to_string(&obligations).expect("an obligation with owed evidence stays armed");
        assert!(
            ledger.contains(&tag_a),
            "retirement is still conditional on durable proof: {ledger}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    // Storage recovers: the NEXT settlement attempt flushes the owed
    // evidence and retires — no new withdrawal, refresh, or grant.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut writable = fs::metadata(&revocations_dir).expect("dir").permissions();
        writable.set_mode(0o755);
        fs::set_permissions(&revocations_dir, writable).expect("writable");
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while obligations.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "the owed evidence flushes and the obligation retires without a new withdrawal"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "the static-covered expiry leaves nothing behind: {egress}"
    );
    assert!(
        !egress.contains("wssp-dns-lease-quarantine-"),
        "a static-covered expiry never fences: {egress}"
    );
}

#[test]
fn a_stalled_commit_read_cannot_delay_the_next_expiry() {
    // C36 r22 F1 (commit-read leg): the settlement's under-commit-lock
    // ACL read is bounded by the round's deadline. Drive the settlement
    // commit boundary DIRECTLY with its read parked (no expiry is due,
    // so the watcher never reads concurrently): an unbounded read would
    // park until the watchdog release; the bounded read is killed at
    // the passed deadline and the commit errors with nothing persisted.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the grant commits");
    let statedir = log.parent().expect("statedir").to_path_buf();
    let state_path = statedir.join("host-state/dns-policy/sbx-1.json");
    let records_before = fs::read_to_string(&state_path).expect("durable state");
    fs::write(statedir.join("barrier-acl-read"), "0").unwrap();
    let release_path = statedir.join("release-acl-read-barrier");
    let watchdog = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(20));
        fs::write(release_path, "").unwrap();
    });
    let start = std::time::Instant::now();
    let empty_tags = std::collections::BTreeSet::new();
    let empty_dests = std::collections::BTreeSet::new();
    let outcome = client.rewrite_persisted_state_after_lease_settlement(
        "sbx-1",
        &acl,
        unix_now().expect("now"),
        &empty_tags,
        &empty_dests,
        &[],
        Some(std::time::Instant::now() + Duration::from_secs(3)),
    );
    let elapsed = std::time::Instant::now().duration_since(start);
    let err = outcome.expect_err("the stalled commit read is killed at the deadline");
    assert!(
        err.to_string().contains("without a confirmed outcome")
            || err.to_string().contains("exceeded the lease deadline"),
        "the refusal is the killed read, not a later failure: {err}"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "the stalled read was killed at the deadline, not the watchdog: {elapsed:?}"
    );
    assert!(
        !statedir.join("release-acl-read-barrier").exists(),
        "the deadline fired while the read was parked"
    );
    assert_eq!(
        fs::read_to_string(&state_path).expect("durable state"),
        records_before,
        "the killed commit persisted nothing"
    );
    watchdog.join().expect("watchdog");
    // Inverse: with reads proceeding, the same commit succeeds.
    client
        .rewrite_persisted_state_after_lease_settlement(
            "sbx-1",
            &acl,
            unix_now().expect("now"),
            &empty_tags,
            &empty_dests,
            &[],
            Some(std::time::Instant::now() + Duration::from_secs(30)),
        )
        .expect("the unblocked commit succeeds");
}

#[test]
fn a_revocation_without_pending_mutations_still_blocks_readiness() {
    // C36 r23 F1: readiness must refuse while ANY identity's revocation
    // is owed to the live ACL — not only while pending mutations exist.
    // The crash window is BETWEEN the last removal and the commit: every
    // pending mutation is spent (the removals all landed), but the
    // revocation was never committed to the durable records — the ACL,
    // the publication, and the persisted plan still AGREE on the old
    // state. Seed exactly that marker state and verify readiness refuses
    // until a full commit proves the loss durable.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, _acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("first grant commits");
    client
        .verify_provisioned_enforcement("sbx-1")
        .expect("a committed grant verifies");
    let statedir = log.parent().expect("statedir").to_path_buf();
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    // The crash window: `pending` is EMPTY (the removals landed) and
    // `revoked` still owes the denial to the durable records.
    fs::write(
        &marker_path,
        serde_json::json!({
            "sandbox_id": "sbx-1",
            "policy_hash": hash,
            "project": "default",
            "revoked": ["grants.example.com"],
            "revoked_generations": {},
            "pending": [],
            "next_request": 1,
            "standing_fences": [],
            "refresh_owed": false,
            "published_attempts": []
        })
        .to_string(),
    )
    .unwrap();
    let err = client
        .verify_provisioned_enforcement("sbx-1")
        .expect_err("an owed revocation refuses readiness");
    // C58 NEW-1 (D-1): refused as INCONCLUSIVE, never drift.
    assert_eq!(err.code, SandboxErrorCode::Internal);
    assert!(err.is_enforcement_inconclusive(), "{err:?}");
    let marker: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&marker_path).expect("marker persists"))
            .expect("marker json");
    assert!(
        marker["pending"].as_array().is_some_and(|p| p.is_empty()),
        "no pending mutation remains: {marker}"
    );
    assert!(
        marker["revoked"].as_array().is_some_and(|r| !r.is_empty()),
        "the refusal kept the owed revocation: {marker}"
    );
    // A restart (fresh client, same state dir) refuses identically — the
    // decision is durable, not in-memory.
    let mut restarted = legacy_client(client.binary.clone(), "default".to_string());
    restarted.state_dir = Some(statedir.join("host-state"));
    let err = restarted
        .verify_provisioned_enforcement("sbx-1")
        .expect_err("a restart refuses on `revoked` alone");
    assert_eq!(err.code, SandboxErrorCode::Internal);
    assert!(err.is_enforcement_inconclusive(), "{err:?}");
    // Recovery: a refresh COMMITS the denial (clears the revocation),
    // then the readiness gate verifies again.
    transport.script("grants.example.com", [FakeDnsOutcome::Rcode(3)]);
    refresh(&restarted, "sbx-1", &policy, &hash, &transport).expect("denial commits");
    assert!(!marker_path.exists(), "marker cleared after commit");
    restarted
        .verify_provisioned_enforcement("sbx-1")
        .expect("readiness verifies once the denial is committed");
}

#[test]
fn a_failed_replacement_never_releases_the_refresh_fence() {
    // C36 r23 F3: a refresh-family fence protecting an unresolved
    // identity is released only BEHIND a verified replacement
    // authorization — never in the pre-add removal pass. The first
    // issuance is interrupted (the destination is fenced, the request
    // stays unresolved); the re-grant then fails installing the
    // replacement companions. The fence must survive the failed pass.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    let statedir = log.parent().expect("statedir").to_path_buf();
    let tag0 = dns_rule_tag("a.example.com", 1);
    fs::write(
        statedir.join("defer-acl-allow-add-fail"),
        format!("queue {tag0}"),
    )
    .unwrap();
    let interrupted = refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("the interrupted issuance reports, it does not crash");
    assert!(
        interrupted
            .denied_names
            .iter()
            .any(|n| n == "a.example.com"),
        "the interrupted issuance fails closed: {interrupted:?}"
    );
    let egress = acl_egress(&log, &acl);
    assert!(
        fence_present(&egress, "128.66.0.7/32"),
        "the interrupted issuance fences the destination: {egress}"
    );
    fs::remove_file(statedir.join("defer-acl-allow-add-fail")).unwrap();
    // The re-grant: the fence leaves the desired set (the destination is
    // authorized again), but the replacement companions fail to install.
    // The pass aborts — with the fence still standing.
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    fs::write(statedir.join("fail-acl-rule-add-reject"), "").unwrap();
    let _ = refresh(&client, "sbx-1", &policy, &hash, &transport);
    let egress = acl_egress(&log, &acl);
    assert!(
        fence_present(&egress, "128.66.0.7/32"),
        "the fence is never released ahead of a verified replacement: {egress}"
    );
    fs::remove_file(statedir.join("fail-acl-rule-add-reject")).unwrap();
    // Recovery: a clean re-grant releases the fence BEHIND the verified
    // replacement — the allow is effective and the fence retires.
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the retry commits");
    let egress = acl_egress(&log, &acl);
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow destination=128.66.0.7/32")),
        "the replacement is installed: {egress}"
    );
    assert!(
        !fence_present(&egress, "128.66.0.7/32"),
        "the fence retires once the replacement is verified: {egress}"
    );
}

#[test]
fn a_crash_between_fence_releases_reissues_under_a_fresh_epoch() {
    // C36 r23 F4: a lease fence whose release is JOURNALED but unresolved
    // is never adopted on retry — it is removed (retry of the release)
    // and re-issued under a FRESH epoch, because the fence may be
    // attacker-replaced. Park lease-fence removals through the first
    // expiry attempt: the release is journaled, the removal is killed at
    // the round deadline, and the attempt fails. Releasing the barrier
    // must produce a fresh-epoch fence install before the grant retires.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            40,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("grant commits");
    let start = std::time::Instant::now();
    let statedir = log.parent().expect("statedir").to_path_buf();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    let releases = statedir.join("host-state/dns-revocations/sbx-1.lease-releases");
    fs::write(statedir.join("barrier-acl-lease-fence-remove"), "").unwrap();
    // The expiry attempt: the fence is installed, its release journaled,
    // and the removal parks until the round deadline kills it.
    let deadline = start + Duration::from_secs(150);
    let fence_epoch = loop {
        let egress = acl_egress(&log, &acl);
        let fence = egress.lines().find(|line| {
            line.contains("wssp-dns-lease-quarantine-")
                && line.contains("destination=128.66.0.7/32")
                && !line.contains("destination_port")
        });
        let journaled = fs::read_to_string(&releases)
            .map(|body| !body.trim().is_empty())
            .unwrap_or(false);
        if let (Some(line), true) = (fence, journaled) {
            let tag = line
                .split_whitespace()
                .find(|field| field.starts_with("description=wssp-dns-lease-quarantine-"))
                .expect("fence tag")
                .trim_start_matches("description=wssp-dns-lease-quarantine-")
                .to_string();
            let epoch: u64 = tag
                .split('-')
                .next()
                .and_then(|component| component.strip_prefix('g'))
                .expect("epoch component")
                .parse()
                .expect("numeric epoch");
            break epoch;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the first attempt journals the release and stalls: {}",
            acl_egress(&log, &acl)
        );
        std::thread::sleep(Duration::from_millis(250));
    };
    assert!(
        obligations.exists(),
        "the killed release leaves the obligation armed"
    );
    // The discriminating check (C36 r23 F4): with the fence's release
    // JOURNALED AND UNRESOLVED (the removal is still parked), the shared
    // boundary is asked to fence the destination again — it must REFUSE
    // to adopt the release-pending fence (its deferred daemon-side
    // removal could still complete) and issue a FRESH epoch instead.
    let mut fresh_alloc = |dest: &str| {
        let epoch = client.allocate_lease_fence_epoch("sbx-1")?;
        let addr = dest
            .strip_suffix("/32")
            .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
            .expect("ipv4 /32");
        Ok(super::network::domain_lease_fence_rule(addr, epoch))
    };
    let reissue = client
        .enforce_destination_withdrawal(
            "sbx-1",
            &acl,
            "128.66.0.7/32",
            &[],
            &[],
            true,
            false,
            None,
            Some(std::time::Instant::now() + Duration::from_secs(10)),
            true,
            &mut fresh_alloc,
        )
        .expect("the fencing pass runs");
    let new_fence = reissue
        .fence_added
        .expect("the release-pending fence is never adopted: a fresh fence is issued");
    let new_epoch: u64 = new_fence
        .description
        .trim_start_matches("wssp-dns-lease-quarantine-g")
        .split('-')
        .next()
        .and_then(|digits| digits.parse().ok())
        .expect("numeric epoch");
    assert!(
        new_epoch > fence_epoch,
        "the re-issued fence carries a FRESH epoch ({new_epoch} > {fence_epoch})"
    );
    // Release the barrier: the retries remove the journaled fences and
    // the grant retires.
    fs::write(statedir.join("release-lease-fence-barrier"), "").unwrap();
    // Withdraw the fence the discriminating call installed (test cleanup
    // through the same boundary; the withdrawing settle may race it,
    // which a proven-absence outcome absorbs).
    let probe_tag = new_fence.description.clone();
    let mut no_alloc = |dest: &str| -> Result<super::network::AclRule, crate::RuntimeError> {
        panic!("no fence allocation needed for {dest}")
    };
    let cleanup = client.enforce_destination_withdrawal(
        "sbx-1",
        &acl,
        "128.66.0.7/32",
        &[],
        std::slice::from_ref(&probe_tag),
        false,
        true,
        None,
        Some(std::time::Instant::now() + Duration::from_secs(30)),
        false,
        &mut no_alloc,
    );
    assert!(cleanup.is_ok(), "the probe fence withdraws cleanly");
    let deadline = std::time::Instant::now() + Duration::from_secs(180);
    loop {
        let retired = match fs::read_to_string(&obligations) {
            Ok(body) => !body.contains("128.66.0.7/32"),
            Err(_) => true,
        };
        if retired {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the grant retires once the releases proceed"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    let logged = log_lines(&log).join("\n");
    let reissued = logged
        .lines()
        .filter(|line| line.contains("wssp-dns-lease-quarantine-") && line.contains("rule add"))
        .filter_map(|line| {
            let marker = "wssp-dns-lease-quarantine-g";
            let at = line.find(marker)? + marker.len();
            line[at..]
                .split(|c: char| !c.is_ascii_digit())
                .next()?
                .parse::<u64>()
                .ok()
        })
        .max();
    assert!(
        reissued.is_some_and(|epoch| epoch > fence_epoch),
        "the unresolved release is re-issued under a fresh epoch (> {fence_epoch}): {logged}"
    );
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("wssp-dns-lease-quarantine-"),
        "a clean expiry leaves no fence behind: {egress}"
    );
}

#[test]
fn an_unconfirmed_grant_never_counts_as_expiry_coverage() {
    // C36 r23 F6: an armed-but-never-installed overlapping obligation is
    // NOT authorization coverage. Two names resolve to the same
    // destination; the longer grant's ENTIRE rule group is lost live (a
    // failed issuance the records cannot confirm), and the shorter
    // grant's expiry withdrawal is refused by the daemon. The settle
    // must quarantine the destination: an observed, COMPLETE surviving
    // group would suppress the fence; an unconfirmed obligation never
    // does. Fence adds are slowed past the blind pre-fence's tight
    // bound so the RELIABLE fencing decision (the coverage check under
    // test) is what installs the quarantine.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com", "b.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    for (name, ttl) in [("a.example.com", 40u32), ("b.example.com", 300u32)] {
        transport.script(
            name,
            [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
                Ipv4Addr::new(128, 66, 0, 7),
                ttl,
            )])],
        );
    }
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("both grants commit");
    let start = std::time::Instant::now();
    let statedir = log.parent().expect("statedir").to_path_buf();
    // The longer grant's whole group vanishes live (its obligation stays
    // armed and unexpired).
    let egress_path = statedir.join("acls").join(format!("{acl}.egress"));
    let b_tag = dns_rule_tag("b.example.com", 2);
    let body = fs::read_to_string(&egress_path).expect("egress");
    let b_reject_tag = b_tag.replacen("wssp-dns-", "wssp-dns-reject-", 1);
    let b_lines: Vec<String> = body
        .lines()
        .filter(|line| line.contains(&b_tag) || line.contains(&b_reject_tag))
        .map(str::to_string)
        .collect();
    assert!(
        b_lines.len() == 4,
        "the longer grant's complete group is present before the loss: {b_lines:?}"
    );
    let tampered: String = body
        .lines()
        .filter(|line| !line.contains(&b_tag) && !line.contains(&b_reject_tag))
        .map(|line| format!("{line}\n"))
        .collect();
    fs::write(&egress_path, tampered).expect("tamper");
    // The expiry withdrawal is REFUSED (unproven: the allow stays), and
    // fence adds take 8s — past the blind pre-fence's 5s bound, inside
    // the reliable install's round budget.
    fs::write(statedir.join("fail-acl-allow-remove"), "").unwrap();
    fs::write(statedir.join("slow-acl-fence-add"), "8").unwrap();
    // The shorter grant expires at +40: the destination must end up
    // FENCED even though its allow refuses to withdraw — the unconfirmed
    // longer grant is no coverage.
    let deadline = start + Duration::from_secs(120);
    loop {
        let egress = acl_egress(&log, &acl);
        if lease_fence_present(&egress, "128.66.0.7/32") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the expired, unwithdrawable destination is fenced — an \
             uninstalled grant is no coverage: {egress}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    // Inverse: the daemon behaving again — and the longer grant's group
    // restored (its loss was never settlement-explained, so the
    // settlement commit rightly refuses to ratify it) — lets the
    // settlement withdraw and retire the shorter obligation.
    fs::remove_file(statedir.join("fail-acl-allow-remove")).unwrap();
    fs::remove_file(statedir.join("slow-acl-fence-add")).unwrap();
    let restored: String = acl_egress(&log, &acl)
        .lines()
        .chain(b_lines.iter().map(String::as_str))
        .map(|line| format!("{line}\n"))
        .collect();
    fs::write(&egress_path, restored).expect("restore the longer grant's group");
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    let deadline = std::time::Instant::now() + Duration::from_secs(150);
    loop {
        let settled = match fs::read_to_string(&obligations) {
            Ok(body) => !body.contains(&dns_rule_tag("a.example.com", 1)),
            Err(_) => true,
        };
        if settled {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the shorter obligation settles once the daemon behaves"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn a_newly_installed_rule_loss_refuses_the_commit() {
    // C36 r23 F7 (newly-installed leg): the commit gate refuses the
    // disappearance of a rule installed by THIS pass — not only of rules
    // the previous durable plan claimed. A re-grant with a rotated
    // answer installs a fresh group; a companion deleted underneath the
    // parked commit is explained by NO settlement evidence, so the
    // commit refuses and persists nothing.
    let (mut client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("first grant commits");
    let statedir = log.parent().expect("statedir").to_path_buf();
    let state_path = statedir.join("host-state/dns-policy/sbx-1.json");
    let state_before = fs::read_to_string(&state_path).expect("durable state");
    // The rotated re-grant installs a NEW group (128.66.0.8/32).
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            300,
        )])],
    );
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    client.dns_commit_pre_lock_barrier = Some(barrier.clone());
    let refresh_outcome = std::thread::scope(|scope| {
        let refresh = scope.spawn(|| refresh(&client, "sbx-1", &policy, &hash, &transport));
        barrier.wait();
        // Parked before the commit lock: delete the NEWLY INSTALLED
        // tcp/853 companion of the rotated group.
        let egress_path = statedir.join("acls").join(format!("{acl}.egress"));
        let body = fs::read_to_string(&egress_path).expect("egress");
        let victim = body
            .lines()
            .find(|line| {
                line.contains("destination=128.66.0.8/32")
                    && line.contains("destination_port=853")
                    && line.contains("wssp-dns-reject-")
            })
            .expect("new tcp/853 companion")
            .to_string();
        let tampered: String = body
            .lines()
            .filter(|line| *line != victim)
            .map(|line| format!("{line}\n"))
            .collect();
        fs::write(&egress_path, tampered).expect("tamper");
        barrier.wait();
        refresh.join().expect("refresh thread")
    });
    let err = refresh_outcome.expect_err("the commit refuses the unexplained loss");
    assert!(
        err.to_string().contains("lost rules"),
        "the refusal names the unexplained loss: {err}"
    );
    client.dns_commit_pre_lock_barrier = None;
    assert_eq!(
        fs::read_to_string(&state_path).expect("durable state"),
        state_before,
        "the refusal committed nothing"
    );
    // Inverse: the retry repairs and commits.
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the retry repairs");
    let egress = acl_egress(&log, &acl);
    assert!(
        egress
            .lines()
            .any(|line| line.contains("destination=128.66.0.8/32")
                && line.contains("destination_port=853")
                && line.contains("wssp-dns-reject-")),
        "the lost companion is repaired: {egress}"
    );
}

#[test]
fn a_failed_post_withdrawal_read_preserves_the_evidence() {
    // C36 r23 F8: positive withdrawal evidence is durable the moment the
    // proof exists — a failed read AFTER the removal can no longer lose
    // it. Park the settle's post-withdrawal re-observation read: the
    // allow removal succeeds, the read is killed at the round deadline,
    // the boundary fails — and the append-only evidence log already
    // holds the (allow tag, destination) pair.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            40,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("grant commits");
    let start = std::time::Instant::now();
    let statedir = log.parent().expect("statedir").to_path_buf();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    let evidence = statedir.join("host-state/dns-revocations/sbx-1.withdrawal-evidence");
    let tag_a = dns_rule_tag("a.example.com", 1);
    // Skip the reads ahead of the post-withdrawal re-observation, then
    // park it: the kill fails the boundary after the removal.
    fs::write(statedir.join("barrier-acl-read"), "5").unwrap();
    let deadline = start + Duration::from_secs(150);
    loop {
        let recorded = fs::read_to_string(&evidence)
            .map(|body| {
                body.lines()
                    .any(|line| line.contains(&tag_a) && line.contains("128.66.0.7/32"))
            })
            .unwrap_or(false);
        if recorded {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the evidence is durable even though the post-withdrawal read fails: {}",
            acl_egress(&log, &acl)
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    assert!(
        !statedir.join("release-acl-read-barrier").exists(),
        "the evidence landed while the read was parked"
    );
    // Inverse: release the barrier; the obligation settles and retires
    // (the durable evidence lets the journal complete with no new proof).
    fs::write(statedir.join("release-acl-read-barrier"), "").unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(150);
    loop {
        let retired = match fs::read_to_string(&obligations) {
            Ok(body) => !body.contains("128.66.0.7/32"),
            Err(_) => true,
        };
        if retired {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the obligation retires once the reads proceed"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "the grant is fully withdrawn: {egress}"
    );
}

#[test]
fn a_failed_initial_settlement_still_retries_autonomously() {
    // C36 r23 F9: a failed initial settlement must NOT suppress the
    // autonomous retry loop. Recovery with ACL reads failing surfaces
    // the error — and the spawned watcher still settles the overdue
    // obligation once storage recovers, with no further recovery call.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("grant commits");
    let statedir = log.parent().expect("statedir").to_path_buf();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    // Make the obligation overdue, crash the owner, and recover with
    // every ACL read failing: the initial settlement attempt fails.
    let ledger: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&obligations).expect("obligations armed"))
            .expect("obligations json");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut expired = ledger.clone();
    for entry in expired["entries"].as_array_mut().expect("entries") {
        entry["expires_at"] = serde_json::json!(now);
    }
    fs::write(
        &obligations,
        serde_json::to_string_pretty(&expired).unwrap(),
    )
    .unwrap();
    fs::write(statedir.join("fail-acl-read"), "50").unwrap();
    let mut daemon = legacy_client(
        statedir.join("incus").to_str().unwrap(),
        "default".to_string(),
    );
    daemon.state_dir = Some(statedir.join("host-state"));
    daemon.debug_reset_dns_lease_owner("sbx-1");
    daemon
        .recover_dns_expiry_obligations("sbx-1")
        .expect_err("the initial settlement failure surfaces");
    // Storage recovers: the autonomous retry settles the obligation with
    // NO further recovery call.
    fs::remove_file(statedir.join("fail-acl-read")).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(180);
    loop {
        let retired = match fs::read_to_string(&obligations) {
            Ok(body) => !body.contains("128.66.0.7/32"),
            Err(_) => true,
        };
        if retired {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the autonomous retry settles the overdue obligation: {}",
            acl_egress(&log, &acl)
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "the overdue grant is fully withdrawn: {egress}"
    );
    daemon.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn a_refresh_never_adopts_a_lease_fence_with_an_unresolved_release() {
    // C36 r24 F1: a fence whose release is unresolved in the LEASE's
    // journal is as inadoptable as one in the refresh's own pending
    // journal — its deferred daemon-side removal could still complete.
    // Two canonical fences sit on the destination, oldest first: a
    // lease fence with an unresolved lease-side release, then the newer
    // refresh fence currently protecting the destination. A revoke-only
    // pass with a standing obligation needs a fence: it must keep the
    // NEWER refresh fence and remove the release-uncertain lease fence
    // (companion position, journaled), never the other way around.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("first grant commits");
    let statedir = log.parent().expect("statedir").to_path_buf();
    let revocations = statedir.join("host-state/dns-revocations");
    let egress_path = statedir.join("acls").join(format!("{acl}.egress"));
    let lease_tag = "wssp-dns-lease-quarantine-g1-abcdef01";
    let refresh_tag = "wssp-dns-quarantine-g0-0f0f0f0f";
    let mut body = fs::read_to_string(&egress_path).expect("egress");
    body.push_str(&format!(
        "action=reject destination=128.66.0.7/32 description={lease_tag}\n"
    ));
    body.push_str(&format!(
        "action=reject destination=128.66.0.7/32 description={refresh_tag}\n"
    ));
    fs::write(&egress_path, body).expect("seed both fences");
    fs::write(
        revocations.join("sbx-1.lease-releases"),
        format!("{lease_tag}\n"),
    )
    .unwrap();
    fs::write(revocations.join("sbx-1.lease-counter"), "5").unwrap();
    // The destination loses its grant but keeps a standing fence
    // obligation, so the pass must retain exactly one trusted fence.
    let (policy2, hash2) = domain_policy(&[], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash2);
    fs::write(
        revocations.join("sbx-1.json"),
        serde_json::json!({
            "sandbox_id": "sbx-1",
            "policy_hash": hash2,
            "project": "default",
            "revoked": [],
            "revoked_generations": {},
            "pending": [],
            "next_request": 2,
            "standing_fences": [{
                "destination": "128.66.0.7/32",
                "description": "wssp-dns-g0-deadbeef"
            }],
            "refresh_owed": false,
            "published_attempts": []
        })
        .to_string(),
    )
    .unwrap();
    let transport2 = FakeDnsTransport::new();
    refresh(&client, "sbx-1", &policy2, &hash2, &transport2).expect("revoke-only pass commits");
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains(lease_tag),
        "the release-uncertain lease fence is never adopted — it is withdrawn: {egress}"
    );
    assert!(
        egress.contains(refresh_tag),
        "the newer refresh fence remains the destination's protection: {egress}"
    );
    // The companion-position removal was journaled AND retired on proof.
    let journal = fs::read_to_string(revocations.join("sbx-1.lease-releases")).unwrap_or_default();
    assert!(
        !journal.contains(lease_tag),
        "the proven companion removal retired the release-journal entry: {journal}"
    );
    // C36 r25 F4: the release journal fails CLOSED. Re-seed the lease
    // fence (ahead of the protecting refresh fence, as before) with the
    // journal UNREADABLE — invalid UTF-8: the set of release-uncertain
    // fences is then UNKNOWN, so the pass must refuse to adopt ANY
    // seeded fence and instead protect the destination under a FRESH
    // identity (installed before any undesired fence moves). The old
    // degrade-to-empty behavior would ADOPT the re-seeded lease fence —
    // whose deferred removal may still be in flight — and release the
    // newer refresh fence around it.
    let mut body = fs::read_to_string(&egress_path).expect("egress");
    body.push_str(&format!(
        "action=reject destination=128.66.0.7/32 description={lease_tag}\n"
    ));
    fs::write(&egress_path, body).expect("re-seed the lease fence");
    fs::write(revocations.join("sbx-1.lease-releases"), [0xff, 0xfe])
        .expect("corrupt the release journal");
    refresh(&client, "sbx-1", &policy2, &hash2, &transport2)
        .expect_err("an unreadable release journal fails the pass closed");
    let egress = acl_egress(&log, &acl);
    assert!(
        egress.contains(refresh_tag),
        "the protecting fence is never removed while the journal is unreadable: {egress}"
    );
    assert!(
        egress.contains(lease_tag),
        "the unadoptable fence is left alone while the journal is unreadable: {egress}"
    );
    let fresh_tags: Vec<String> = egress
        .lines()
        .filter_map(|line| {
            line.rsplit("description=")
                .next()
                .filter(|tag| tag.starts_with("wssp-dns-quarantine-") && *tag != refresh_tag)
                .map(str::to_string)
        })
        .collect();
    assert!(
        !fresh_tags.is_empty(),
        "protection continues under a FRESH identity installed before the \
         pass failed closed — nothing was adopted: {egress}"
    );
    // Readable-empty inverse: a journal that reads cleanly as EMPTY
    // restores the normal adoption path — the pass commits, adopts the
    // protecting refresh fence, and withdraws both leftover identities
    // through the journaled path.
    fs::write(revocations.join("sbx-1.lease-releases"), "").unwrap();
    refresh(&client, "sbx-1", &policy2, &hash2, &transport2)
        .expect("a readable journal restores adoption");
    let egress = acl_egress(&log, &acl);
    assert!(
        egress.contains(refresh_tag),
        "the protecting fence is adopted once the journal reads: {egress}"
    );
    assert!(
        !egress.contains(lease_tag),
        "the leftover lease fence is withdrawn once the journal reads: {egress}"
    );
    for tag in &fresh_tags {
        assert!(
            !egress.contains(tag.as_str()),
            "the interrupted pass's fresh fence is withdrawn once the journal reads: {egress}"
        );
    }
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn a_stalled_fence_release_never_outlives_the_earliest_deadline() {
    // C36 r24 F2: the owner-locked release phase is bounded by ONE
    // absolute deadline — the earliest armed expiry — not by a per-call
    // budget that drops deadlines as they lapse. Grant A expires at +40;
    // two stale lease fences on the longer-lived grants B and C need
    // releasing, and the daemon stalls every lease-fence removal. The
    // first stalled release may consume A's remaining lifetime; the
    // second must then be SKIPPED so the watcher — blocked on the owner
    // lock — settles A on time.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com", "b.example.com", "c.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    for (name, last, ttl) in [
        ("a.example.com", 7u8, 40u32),
        ("b.example.com", 8, 300),
        ("c.example.com", 9, 300),
    ] {
        transport.script(
            name,
            [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
                Ipv4Addr::new(128, 66, 0, last),
                ttl,
            )])],
        );
    }
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("all three grants commit");
    let statedir = log.parent().expect("statedir").to_path_buf();
    let revocations = statedir.join("host-state/dns-revocations");
    // Stale canonical lease fences on the two long-lived destinations.
    let egress_path = statedir.join("acls").join(format!("{acl}.egress"));
    let mut body = fs::read_to_string(&egress_path).expect("egress");
    body.push_str(
        "action=reject destination=128.66.0.8/32 description=wssp-dns-lease-quarantine-g1-aaaa0001\n",
    );
    body.push_str(
        "action=reject destination=128.66.0.9/32 description=wssp-dns-lease-quarantine-g2-bbbb0002\n",
    );
    fs::write(&egress_path, body).expect("seed stale lease fences");
    fs::write(revocations.join("sbx-1.lease-counter"), "5").unwrap();
    // The daemon stalls every lease-fence removal until released.
    fs::write(statedir.join("barrier-acl-lease-fence-remove"), "").unwrap();
    // At +25, renew: A re-arms to the SAME absolute expiry (+40) with a
    // floor-clamped TTL, so the release phase's earliest deadline is
    // 15s out when the pass runs.
    let renew_transport = std::sync::Arc::new(FakeDnsTransport::new());
    renew_transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            15,
        )])],
    );
    for (name, last) in [("b.example.com", 8u8), ("c.example.com", 9)] {
        renew_transport.script(
            name,
            [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
                Ipv4Addr::new(128, 66, 0, last),
                300,
            )])],
        );
    }
    std::thread::sleep(Duration::from_secs(25));
    let renew_at = std::time::Instant::now();
    let renew_client = client.clone();
    let renew_transport2 = renew_transport.clone();
    let (policy_renew, hash_renew) = (policy.clone(), hash.clone());
    let refresh_thread = std::thread::spawn(move || {
        renew_client.refresh_sandbox_dns_policy(
            "sbx-1",
            &policy_renew,
            &hash_renew,
            renew_transport2.as_ref(),
            &servers(),
        )
    });
    // The first stalled release dies at A's deadline; the phase then
    // yields the owner lock and A settles on schedule.
    let deadline = renew_at + Duration::from_secs(32);
    loop {
        let egress = acl_egress(&log, &acl);
        if lease_fence_present(&egress, "128.66.0.7/32") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "A's expiry is enforced on time despite the stalled fence release: {egress}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    // Inverse: releasing the barrier lets the stalled removals finish
    // and the renewal commit.
    fs::write(statedir.join("release-lease-fence-barrier"), "").unwrap();
    refresh_thread
        .join()
        .expect("refresh thread")
        .expect("the renewal commits once the releases proceed");
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn a_complete_but_expired_group_never_counts_as_coverage() {
    // C36 r24 F3: coverage requires an UNEXPIRED authorization. Two
    // grants share a destination and expire together; both groups are
    // COMPLETE on the ACL, both are expired, and the daemon refuses the
    // allow withdrawals. Neither expired group may count as coverage
    // for the other: the destination is fenced. Fence adds are slowed
    // past the blind pre-fence's tight bound so the reliable,
    // coverage-gated install is what must act.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com", "b.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    for name in ["a.example.com", "b.example.com"] {
        transport.script(
            name,
            [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
                Ipv4Addr::new(128, 66, 0, 7),
                40,
            )])],
        );
    }
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("both grants commit");
    let start = std::time::Instant::now();
    let statedir = log.parent().expect("statedir").to_path_buf();
    fs::write(statedir.join("fail-acl-allow-remove"), "").unwrap();
    fs::write(statedir.join("slow-acl-fence-add"), "8").unwrap();
    let deadline = start + Duration::from_secs(75);
    loop {
        let egress = acl_egress(&log, &acl);
        if lease_fence_present(&egress, "128.66.0.7/32") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "two complete but EXPIRED groups never cover each other: {egress}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    // Inverse: the daemon behaving again lets both withdrawals prove
    // and both obligations retire.
    fs::remove_file(statedir.join("fail-acl-allow-remove")).unwrap();
    fs::remove_file(statedir.join("slow-acl-fence-add")).unwrap();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    let deadline = std::time::Instant::now() + Duration::from_secs(150);
    loop {
        let settled = match fs::read_to_string(&obligations) {
            Ok(body) => !body.contains("128.66.0.7/32"),
            Err(_) => true,
        };
        if settled {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "both expired obligations settle once the daemon behaves"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn a_failed_withdrawal_never_leaves_a_blind_fence_over_a_live_grant() {
    // C36 r24 F4: the blind pre-fence knows nothing of overlapping
    // coverage. A and B share a destination; A expires at +40 while B
    // stays authorized for 300s; A's withdrawal is REFUSED by the
    // daemon. The blind fence lands at A's deadline — and must then be
    // reconciled away against B's verified, unexpired, complete group
    // independently of A's withdrawal ever succeeding. B's traffic is
    // never denied for more than the reconciliation delay.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com", "b.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    for (name, ttl) in [("a.example.com", 40u32), ("b.example.com", 300u32)] {
        transport.script(
            name,
            [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
                Ipv4Addr::new(128, 66, 0, 7),
                ttl,
            )])],
        );
    }
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("both grants commit");
    let start = std::time::Instant::now();
    let statedir = log.parent().expect("statedir").to_path_buf();
    fs::write(statedir.join("fail-acl-allow-remove"), "").unwrap();
    let b_allow = format!(
        "action=allow destination=128.66.0.7/32 description={}",
        dns_rule_tag("b.example.com", 2)
    );
    // Continuously: B's allow stays installed, and past A's expiry plus
    // the reconciliation delay no lease fence covers the destination.
    let deadline = start + Duration::from_secs(90);
    loop {
        let egress = acl_egress(&log, &acl);
        let elapsed = std::time::Instant::now().duration_since(start).as_secs();
        assert!(
            egress.lines().any(|line| line.contains(&b_allow)),
            "B's live grant is never withdrawn: {egress}"
        );
        if elapsed > 55 {
            assert!(
                !lease_fence_present(&egress, "128.66.0.7/32"),
                "the blind fence over B's live grant is reconciled away \
                 even though A's withdrawal keeps failing: {egress}"
            );
        }
        if elapsed > 75 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the reconciliation is bounded: {egress}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    // Inverse: the daemon behaving again lets A withdraw and retire.
    fs::remove_file(statedir.join("fail-acl-allow-remove")).unwrap();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    let deadline = std::time::Instant::now() + Duration::from_secs(150);
    loop {
        let settled = match fs::read_to_string(&obligations) {
            Ok(body) => !body.contains(&dns_rule_tag("a.example.com", 1)),
            Err(_) => true,
        };
        if settled {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "A's obligation settles once the daemon behaves"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    client.debug_reset_dns_lease_owner("sbx-1");
}

// ---------------------------------------------------------------------------
// Deadline-aware destination-deduplicated blind pre-fencing
// with an expiry-keyed attempt cache; revoked names are never coverage;
// the lease release journal fails closed; revocation retirement is
// strictly post-commit.
// ---------------------------------------------------------------------------

#[test]
fn a_stalled_multi_destination_prefence_still_settles_the_newer_expiry() {
    // C36 r25 F1: the blind pre-fence is ONE deadline-aware,
    // destination-deduplicated boundary. Grant A expires at +40 with
    // THREE destinations whose fence adds stall (killed at the per-add
    // bound); grant B expires at +44 on another destination. The pass
    // must stop at B's deadline — never stall past it on A's
    // serialized adds — and B must be withdrawn/fenced promptly after
    // its own expiry, not after A's full stall drains.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com", "b.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![
            FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 7), 40),
            FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 8), 40),
            FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 10), 40),
        ])],
    );
    transport.script(
        "b.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 9),
            44,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("both grants commit");
    let start = std::time::Instant::now();
    let statedir = log.parent().expect("statedir").to_path_buf();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    // Every fence ADD takes 4s. The first pass opens at +40 with B's
    // expiry (+44) as its deadline: A's first add is killed at the
    // deadline (~1s over the 4s stall) and the pass STOPS — the next
    // pass discovers B, fences it first (most-recently-expired first),
    // and B's fence lands at ~+48. The pre-fix boundary serializes A's
    // three 4s adds (pass ends +52) over a due-snapshot frozen at +40,
    // discovers B only in the NEXT pass, and fences it at ~+56 — twelve
    // seconds expired and reachable.
    fs::write(statedir.join("slow-acl-fence-add"), "4").unwrap();
    let deadline = start + Duration::from_secs(90);
    loop {
        let egress = acl_egress(&log, &acl);
        let b_allow = egress
            .lines()
            .any(|line| line.contains("action=allow destination=128.66.0.9/32"));
        let elapsed = std::time::Instant::now().duration_since(start).as_secs();
        if lease_fence_present(&egress, "128.66.0.9/32") || !b_allow {
            assert!(
                elapsed < 56,
                "B is protected promptly after its own deadline despite A's \
                 stalled multi-destination pre-fence (took {elapsed}s)"
            );
            break;
        }
        assert!(
            elapsed < 51,
            "B is fenced by its own deadline +5s even while A's fence adds \
             stall — the pre-fence pass must yield at +44 and re-enter: {egress}"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "B settles despite A's stalled pre-fence: {egress}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    // Fast-path inverse: with the adds merely slow (not refused), every
    // obligation settles and retires — the deadline logic never strands
    // work that the reliable path can complete.
    let _ = fs::remove_file(statedir.join("slow-acl-fence-add"));
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    while obligations.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "both obligations retire once fence operations behave"
        );
        std::thread::sleep(Duration::from_millis(400));
    }
    let egress = acl_egress(&log, &acl);
    for addr in ["128.66.0.7", "128.66.0.8", "128.66.0.9", "128.66.0.10"] {
        assert!(!egress.contains(addr), "{addr} fully withdrawn: {egress}");
    }
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn a_fast_prefence_fences_every_due_destination_before_the_settle() {
    // C36 r25 F1 (fast-path inverse): with the daemon behaving, the
    // deadline-aware deduplicated pass still blind-fences EVERY due
    // destination inside its tick — dedup and the deadline never skip
    // work that fits. Withdrawals are failed so the fences persist for
    // observation; the dedup means A's two destinations get one fence
    // each, and B's destination is fenced in the same pass.
    let (mut client, log) = applied_client("running", "sbx-1");
    let clock = DnsTestClock::install(&mut client);
    let answered_at = clock.now();
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com", "b.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![
            FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 7), 30),
            FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 8), 30),
        ])],
    );
    transport.script(
        "b.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 9),
            30,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("both grants commit");
    let start = std::time::Instant::now();
    let statedir = log.parent().expect("statedir").to_path_buf();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    fs::write(statedir.join("fail-acl-allow-remove"), "").unwrap();
    clock.advance(30);
    let deadline = start + Duration::from_secs(55);
    loop {
        client.debug_wake_dns_lease_owner("sbx-1");
        let egress = acl_egress(&log, &acl);
        if ["128.66.0.7/32", "128.66.0.8/32", "128.66.0.9/32"]
            .iter()
            .all(|dest| lease_fence_present(&egress, dest))
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "every due destination is blind-fenced inside the tick: {egress}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    assert_eq!(
        clock.now(),
        answered_at + 30,
        "all due destinations are fenced in the same logical tick"
    );
    // Inverse tail: the daemon behaving again lets every withdrawal
    // complete, the journaled fences release, and the obligations
    // retire.
    fs::remove_file(statedir.join("fail-acl-allow-remove")).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(150);
    while obligations.exists() {
        client.debug_wake_dns_lease_owner("sbx-1");
        assert!(
            std::time::Instant::now() < deadline,
            "all obligations retire once the daemon behaves"
        );
        std::thread::sleep(Duration::from_millis(400));
    }
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("wssp-dns-lease-quarantine-"),
        "a clean expiry leaves no fence behind: {egress}"
    );
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn a_renewed_identity_is_blind_fenced_again_at_its_second_expiry() {
    // C36 r25 F2: the blind pre-fence cache is keyed by the armed
    // EXPIRY and invalidated at every fence release, so a RENEWED
    // identity — same allow tag, later deadline — is blind-fenced
    // again when its second expiry arrives with observation stalled.
    // First expiry: the blind fence E1 lands while the ACL read is
    // parked. Renewal: the refresh releases E1 once the destination is
    // authorized again. Second expiry, reads parked again: a FRESH
    // blind fence must land — a stale cache hit would skip it and
    // leave the expired destination reachable behind the parked read.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            30,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("first grant commits");
    let start = std::time::Instant::now();
    let statedir = log.parent().expect("statedir").to_path_buf();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    // Park the post-expiry observation and refuse the withdrawal: the
    // blind fence is then the ONLY enforcement, and it must persist.
    std::thread::sleep(Duration::from_secs(25).saturating_sub(start.elapsed()));
    fs::write(statedir.join("barrier-acl-read"), "0").unwrap();
    fs::write(statedir.join("fail-acl-allow-remove"), "").unwrap();
    let deadline = start + Duration::from_secs(45);
    loop {
        let egress = acl_egress(&log, &acl);
        if lease_fence_present(&egress, "128.66.0.7/32") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the first expiry is blind-fenced while the read is parked: {egress}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    // Let the settle proceed: the withdrawal refuses, so the fence and
    // the obligation stay.
    fs::write(statedir.join("release-acl-read-barrier"), "").unwrap();
    std::thread::sleep(Duration::from_secs(2));
    // Renew the SAME identity (same name, unchanged address — the rule
    // group is re-authorized in place, so the refresh commits with no
    // withdrawal) with a longer lifetime. The allow-removal hook (which
    // matches every wssp-dns-* removal, fences included) stays armed
    // through the FIRST renewal — it needs no removal, and the hook
    // stops a racing settle round from retiring the identity
    // mid-renewal — then lifts for the SECOND renewal, which releases
    // the stale lease fence now that the destination is no longer due.
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            60,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("renewal commits");
    fs::remove_file(statedir.join("fail-acl-allow-remove")).unwrap();
    // Scripted outcomes are consumed per query: the second renewal needs
    // its own answer — an empty queue would NXDOMAIN into a DENIAL, which
    // the autonomous boundary (C36 r31 F2) now enforces immediately
    // instead of leaving inert until expiry.
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            60,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("the second renewal releases the stale fence");
    fs::write(statedir.join("fail-acl-allow-remove"), "").unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let egress = acl_egress(&log, &acl);
        if !lease_fence_present(&egress, "128.66.0.7/32") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the renewed destination's stale lease fence is released: {egress}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    // Second expiry (renewal lifetime 60s): park observation and refuse
    // the withdrawal again. The blind pre-fence MUST fire again — the
    // renewed entry carries a new expiry, and the release above
    // invalidated the cache.
    let obligations_body = fs::read_to_string(&obligations).expect("obligation armed");
    assert!(
        obligations_body.contains(&dns_rule_tag("a.example.com", 1)),
        "the renewed identity stays armed: {obligations_body}"
    );
    let expiry2 = std::time::Instant::now() + Duration::from_secs(60);
    std::thread::sleep(Duration::from_secs(55));
    // Re-arm the barrier for the second expiry: the release file must go
    // first — a parked read frees instantly while it exists.
    let _ = fs::remove_file(statedir.join("release-acl-read-barrier"));
    fs::write(statedir.join("barrier-acl-read"), "0").unwrap();
    fs::write(statedir.join("fail-acl-allow-remove"), "").unwrap();
    let deadline = expiry2 + Duration::from_secs(15);
    loop {
        let egress = acl_egress(&log, &acl);
        if lease_fence_present(&egress, "128.66.0.7/32") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the renewed identity is blind-fenced at its SECOND expiry: {egress}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    // Inverse: release everything; the withdrawal completes, the fence
    // is released through the journaled path, and the obligation
    // retires.
    fs::write(statedir.join("release-acl-read-barrier"), "").unwrap();
    fs::remove_file(statedir.join("fail-acl-allow-remove")).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(150);
    while obligations.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "the obligation retires once the daemon behaves"
        );
        std::thread::sleep(Duration::from_millis(400));
    }
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "the destination is fully withdrawn: {egress}"
    );
    assert!(
        !egress.contains("wssp-dns-lease-quarantine-"),
        "no fence is left behind: {egress}"
    );
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn a_revoked_groups_surviving_rules_never_count_as_coverage() {
    // C36 r25 F3: coverage requires an EFFECTIVE authorization — a
    // complete observed group whose name is REVOKED in the durable
    // marker is not one. B's revocation is recorded, but its withdrawal
    // keeps failing, so its complete rule group survives. When A (the
    // other grant over the same destination) expires, the settlement
    // must fence the destination — never treat the revoked B group as
    // authorization.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com", "b.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            40,
        )])],
    );
    transport.script(
        "b.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            // Outlives the whole assertion window (A expires at +40) but
            // retires soon after, keeping the tail cheap: B's armed
            // obligation is never dropped by a re-arm that denies it.
            120,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("both grants commit");
    let start = std::time::Instant::now();
    let statedir = log.parent().expect("statedir").to_path_buf();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    // B is revoked by NXDOMAIN while its allow removal is refused: the
    // marker records the denial BEFORE any mutation; the refresh then
    // fails, leaving B's complete group live with no authorization.
    std::thread::sleep(Duration::from_secs(10).saturating_sub(start.elapsed()));
    fs::write(statedir.join("fail-acl-allow-remove"), "").unwrap();
    transport.script("b.example.com", [FakeDnsOutcome::Rcode(3)]);
    refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect_err("the refused revocation withdrawal fails the refresh");
    let marker = fs::read_to_string(&marker_path).expect("revocation marker");
    assert!(
        marker.contains("b.example.com"),
        "the denial is durable before any mutation: {marker}"
    );
    // A expires at +40. B's group is complete and live but REVOKED:
    // the destination must be fenced, and the fence must SURVIVE —
    // reconciliation treats only effective authorizations as coverage.
    let deadline = start + Duration::from_secs(75);
    let mut fence_seen = false;
    loop {
        let elapsed = std::time::Instant::now().duration_since(start).as_secs();
        let egress = acl_egress(&log, &acl);
        let fenced = lease_fence_present(&egress, "128.66.0.7/32");
        if (42..=65).contains(&elapsed) {
            assert!(
                fenced,
                "a revoked grant's surviving group is never coverage — \
                 the destination stays fenced after A's expiry: {egress}"
            );
        }
        fence_seen |= fenced;
        if elapsed > 65 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the fencing assertion window completes: {egress}"
        );
        std::thread::sleep(Duration::from_millis(400));
    }
    assert!(fence_seen, "the expired destination was fenced");
    // Inverse: restore the daemon and let A's settlement finish FIRST
    // (withdrawal, fence release, retirement) so the re-run below does
    // not race it; then re-run the SAME policy (the marker is
    // hash-bound). B is still NXDOMAIN, so the refresh re-records the
    // denial, withdraws B's leftover group through the covered path,
    // and the commit retires the revocation from the marker. A's fresh
    // answer keeps the destination authorized throughout.
    fs::remove_file(statedir.join("fail-acl-allow-remove")).unwrap();
    let tag_a = dns_rule_tag("a.example.com", 1);
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    loop {
        let retired = match fs::read_to_string(&obligations) {
            Ok(body) => !body.contains(&tag_a),
            Err(_) => true,
        };
        if retired {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "A's obligation settles once the daemon behaves"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            40,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("the re-run commits with the revoked group withdrawn");
    let marker = fs::read_to_string(&marker_path).unwrap_or_default();
    assert!(
        !marker.contains("\"b.example.com\""),
        "the committed denial retires from the marker: {marker}"
    );
    let egress = acl_egress(&log, &acl);
    assert!(
        egress.contains("action=allow destination=128.66.0.7/32"),
        "A's fresh grant keeps the destination authorized: {egress}"
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(150);
    while obligations.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "every obligation retires once the daemon behaves: {} || {}",
            fs::read_to_string(&obligations).unwrap_or_default(),
            acl_egress(&log, &acl)
        );
        std::thread::sleep(Duration::from_millis(400));
    }
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "the destination is fully withdrawn: {egress}"
    );
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn a_crashed_first_issuance_never_reuses_its_identity_across_recreate() {
    // C36 r26 F1: a FIRST issuance interrupted after its allow was
    // accepted daemon-side (deferred apply) but before any state commit
    // leaves only the journaled pending mutation. Teardown preserves the
    // journal; the recreate reconciles the entry into a standing
    // obligation carrying the ORIGINAL identity; the re-issued grant
    // must carry a FRESH crash-durable identity — never the interrupted
    // request's — so the retry's withdrawal evidence can never retire
    // the original's standing obligation and release its protection
    // before the original's deferred apply lands.
    let (mut runtime, log) = runtime_for("fix6_new_ready");
    let answers = std::sync::Arc::new(std::sync::Mutex::new(vec![std::net::IpAddr::V4(
        Ipv4Addr::new(128, 66, 0, 7),
    )]));
    let shared = answers.clone();
    runtime.override_resolver(std::sync::Arc::new(move |_domain, _wait| {
        Ok(shared.lock().unwrap().clone())
    }));
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    let mut request = super::shim_tests::create_req();
    request.egress_policy = Some(policy.clone());
    request.egress_policy_hash = Some(hash.clone());
    let statedir = log.parent().expect("statedir").to_path_buf();
    let (_network, acl) = sandbox_network_names("sbx-1");
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    // The daemon ACCEPTS the first grant's allow but the CLI reports a
    // connection failure; keep the daemon request queued until recreation.
    // Pinned by destination so it matches whatever identity the grant is
    // issued under — that identity is exactly what is under test.
    fs::write(
        statedir.join("defer-acl-allow-add-fail"),
        "queue 128.66.0.7",
    )
    .unwrap();
    // And the process dies BEFORE THE STATE COMMIT: the durable state
    // directory is read-only, so the refresh journals the interrupted
    // issuance (the marker is written before any mutation) but never
    // records the per-name generation history — the reviewer's crash
    // window exactly. (C36 r26 F1: the identity survives anyway because
    // the ALLOCATION bumps the durable request counter in the marker
    // before issuance; pre-fix nothing durable named the first grant.)
    let policy_dir = statedir.join("host-state/dns-policy");
    fs::create_dir_all(&policy_dir).expect("policy dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut readonly = fs::metadata(&policy_dir).expect("dir").permissions();
        readonly.set_mode(0o555);
        fs::set_permissions(&policy_dir, readonly).expect("readonly");
    }
    runtime
        .create_bound(&request)
        .expect_err("the crashed first issuance fails before its state commit");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut writable = fs::metadata(&policy_dir).expect("dir").permissions();
        writable.set_mode(0o755);
        fs::set_permissions(&policy_dir, writable).expect("restore");
    }
    assert!(
        marker_path.exists(),
        "the journaled pending mutation survives the crash"
    );
    assert!(
        !policy_dir.join("sbx-1.json").exists(),
        "the state commit never happened — no generation history was recorded"
    );
    let original_tag = {
        let marker: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&marker_path).expect("journal"))
                .expect("marker json");
        marker["pending"]
            .as_array()
            .expect("pending")
            .iter()
            .filter(|entry| entry["destination"].as_str() == Some("128.66.0.7/32"))
            .filter_map(|entry| entry["description"].as_str())
            .find(|tag| {
                tag.starts_with("wssp-dns-")
                    && !tag.contains("-reject-")
                    && !tag.contains("quarantine")
            })
            .expect("the interrupted allow is journaled")
            .to_string()
    };
    // Teardown preserves the journal (C36 r22 F2); the recreate
    // reconciles the unresolved mutation into a STANDING obligation
    // carrying the ORIGINAL identity.
    let mut daemon = legacy_client(
        statedir.join("incus").to_str().unwrap(),
        "default".to_string(),
    );
    daemon.state_dir = Some(statedir.join("host-state"));
    daemon
        .teardown_sandbox_network("sbx-1")
        .expect("teardown preserves the marker");
    assert!(
        marker_path.exists(),
        "the unresolved mutation survives the teardown (C36 r22 F2)"
    );
    fs::remove_file(statedir.join("defer-acl-allow-add-fail")).unwrap();
    runtime
        .create_bound(&request)
        .expect("the recreate is usable");
    let retry_tag = {
        let egress = acl_egress(&log, &acl);
        egress
            .lines()
            .find(|line| {
                line.contains("action=allow")
                    && line.contains("destination=128.66.0.7/32")
                    && line.contains("description=wssp-dns-")
            })
            .and_then(|line| line.rsplit("description=").next())
            .expect("the retried grant is installed")
            .to_string()
    };
    assert_ne!(
        retry_tag, original_tag,
        "the retried issuance NEVER reuses the interrupted request's identity"
    );
    // Withdraw the retry: force its obligation due and settle. The
    // withdrawal produces positive evidence FOR THE RETRY'S identity —
    // which must not match the original's standing obligation.
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    let ledger: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&obligations).expect("obligations armed"))
            .expect("obligations json");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut expired = ledger.clone();
    for entry in expired["entries"].as_array_mut().expect("entries") {
        entry["expires_at"] = serde_json::json!(now);
    }
    fs::write(
        &obligations,
        serde_json::to_string_pretty(&expired).unwrap(),
    )
    .unwrap();
    let mut daemon2 = legacy_client(
        statedir.join("incus").to_str().unwrap(),
        "default".to_string(),
    );
    daemon2.state_dir = Some(statedir.join("host-state"));
    daemon2.debug_reset_dns_lease_owner("sbx-1");
    daemon2
        .recover_dns_expiry_obligations("sbx-1")
        .expect("recovery settles the expired retry");
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    loop {
        let egress = acl_egress(&log, &acl);
        let retry_gone = !egress.lines().any(|line| {
            line.contains("action=allow")
                && line.contains("128.66.0.7")
                && line.contains(&retry_tag)
        });
        if retry_gone {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the retried grant settles: {egress}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    // Rotate and recreate: the standing obligation — which the retry's
    // evidence says NOTHING about — is re-planned as a fence. (Pre-fix
    // the retry reuses the original identity; its evidence retires the
    // standing obligation here and nothing protects the destination when
    // the deferred original lands.)
    *answers.lock().unwrap() = vec![std::net::IpAddr::V4(Ipv4Addr::new(128, 66, 0, 8))];
    let mut daemon3 = legacy_client(
        statedir.join("incus").to_str().unwrap(),
        "default".to_string(),
    );
    daemon3.state_dir = Some(statedir.join("host-state"));
    daemon3
        .teardown_sandbox_network("sbx-1")
        .expect("teardown succeeds");
    runtime
        .create_bound(&request)
        .expect("the rotated recreate is usable");
    let marker: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&marker_path).expect("the standing obligation survives"),
    )
    .expect("marker json");
    assert!(
        marker["standing_fences"]
            .as_array()
            .is_some_and(|fences| fences.iter().any(|fence| {
                fence["destination"].as_str() == Some("128.66.0.7/32")
                    || fence.as_str() == Some("128.66.0.7/32")
            })),
        "the retry's withdrawal evidence never retires the original's \
         standing obligation: {marker}"
    );
    let egress = acl_egress(&log, &acl);
    assert!(
        fence_present(&egress, "128.66.0.7/32"),
        "the standing fence is re-planned on the rotated recreate: {egress}"
    );
    // The deferred ORIGINAL apply now lands — behind the fence.
    assert_eq!(apply_queued_acl_adds(&statedir), 1);
    let egress = acl_egress(&log, &acl);
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow") && line.contains("128.66.0.7")),
        "the deferred original apply landed (the race is real): {egress}"
    );
    assert!(
        fence_present(&egress, "128.66.0.7/32"),
        "the late original apply lands behind the standing fence: {egress}"
    );

    // ==== C36 r32 F1 leg: a denial must name EVERY request identity
    // outstanding at journal time — including an ARMED-BUT-UNCOMMITTED
    // re-grant. Rotate to 128.66.0.9 with a refresh that installs and
    // publishes the fresh generation but dies at the state commit
    // (read-only state directory), leaving the durable state one
    // generation behind. The NXDOMAIN that follows journals the
    // committed generation from the plan state; the uncommitted
    // generation is durable only in the lease ledger. A refresh crash
    // before the withdrawal then leaves the DENIED uncommitted allow
    // effective, and watcher-only recovery must enforce it anyway —
    // pre-r32 the marker named only the committed generation, so the
    // autonomous boundary explicitly skipped the live one.
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 9),
            300,
        )])],
    );
    let committed_before: u64 = {
        let state: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(policy_dir.join("sbx-1.json")).expect("committed state"),
        )
        .expect("state json");
        state["generations"]["grants.example.com"]
            .as_u64()
            .expect("committed generation")
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut readonly = fs::metadata(&policy_dir).expect("dir").permissions();
        readonly.set_mode(0o555);
        fs::set_permissions(&policy_dir, readonly).expect("readonly");
    }
    refresh(&daemon3, "sbx-1", &policy, &hash, &transport)
        .expect_err("the re-grant installs and publishes but dies at the state commit");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut writable = fs::metadata(&policy_dir).expect("dir").permissions();
        writable.set_mode(0o755);
        fs::set_permissions(&policy_dir, writable).expect("restore");
    }
    let uncommitted_tag = {
        let egress = acl_egress(&log, &acl);
        egress
            .lines()
            .find(|line| {
                line.contains("action=allow") && line.contains("destination=128.66.0.9/32")
            })
            .and_then(|line| line.rsplit("description=").next())
            .expect("the uncommitted re-grant's allow is installed")
            .to_string()
    };
    {
        let state: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(policy_dir.join("sbx-1.json")).expect("committed state"),
        )
        .expect("state json");
        assert_eq!(
            state["generations"]["grants.example.com"].as_u64(),
            Some(committed_before),
            "the durable state is still one generation behind (the crash is real)"
        );
    }
    // The SECOND denial: journaled, then interrupted before any
    // withdrawal lands.
    transport.script("grants.example.com", [FakeDnsOutcome::Rcode(3)]);
    fs::write(statedir.join("fail-acl-rule-remove"), "").unwrap();
    refresh(&daemon3, "sbx-1", &policy, &hash, &transport)
        .expect_err("the denial is journaled but its withdrawal is interrupted");
    fs::remove_file(statedir.join("fail-acl-rule-remove")).unwrap();
    {
        let marker: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&marker_path).expect("marker"))
                .expect("marker json");
        let recorded: Vec<u64> = marker["revoked_generations"]["grants.example.com"]
            .as_array()
            .expect("the denied generation set is journaled")
            .iter()
            .filter_map(serde_json::Value::as_u64)
            .collect();
        let uncommitted_generation =
            super::network::dns_tag_request_id(&uncommitted_tag).expect("tag generation");
        assert!(
            recorded.contains(&committed_before) && recorded.contains(&uncommitted_generation),
            "the denial names EVERY outstanding identity (committed {committed_before} AND \
             armed-but-uncommitted {uncommitted_generation}): {recorded:?}"
        );
    }
    let egress = acl_egress(&log, &acl);
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow") && line.contains("128.66.0.9")),
        "the interrupted denial left the uncommitted allow effective: {egress}"
    );
    // WATCHER-ONLY recovery: no refresh ever commits this denial. The
    // autonomous boundary must enforce it against the uncommitted
    // identity (pre-r32 it skipped the generation mismatch and the
    // denied destination stayed reachable until the TTL).
    let mut daemon4 = legacy_client(
        statedir.join("incus").to_str().unwrap(),
        "default".to_string(),
    );
    daemon4.state_dir = Some(statedir.join("host-state"));
    daemon4.debug_reset_dns_lease_owner("sbx-1");
    let _ = daemon4.recover_dns_expiry_obligations("sbx-1");
    // Secure outcomes (C36 r34 F2 re-times the watcher/refresh race
    // around the revoked destination's fence): EITHER the withdrawal of
    // the uncommitted identity proves out (deny-default then blocks the
    // destination; the clean settle withdraws its own deadline fence,
    // exactly like a clean expiry) OR a fence covers a destination
    // whose withdrawal is still unproven. Pre-r32 NEITHER happened for
    // the uncommitted generation: its allow stayed effective and
    // unfenced until the TTL.
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let egress = acl_egress(&log, &acl);
        let allow_gone = !egress
            .lines()
            .any(|line| line.contains("action=allow") && line.contains("128.66.0.9"));
        if allow_gone || fence_present(&egress, "128.66.0.9/32") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "watcher-only recovery enforces the denial against the uncommitted identity: {egress}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    // The withdrawal must complete behind whatever fence covers the
    // window: the denied identity never survives its own settlement.
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    loop {
        let egress = acl_egress(&log, &acl);
        if !egress
            .lines()
            .any(|line| line.contains("action=allow") && line.contains("128.66.0.9"))
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the denied identity's withdrawal completes: {egress}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    // Inverse: an identity issued AFTER the denial stays exempt — the
    // re-grant commits, clears the marker, and its allow is never
    // touched by the autonomous boundary.
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 9),
            300,
        )])],
    );
    refresh(&daemon4, "sbx-1", &policy, &hash, &transport)
        .expect("the post-denial re-grant commits");
    for _ in 0..8 {
        let egress = acl_egress(&log, &acl);
        assert!(
            egress
                .lines()
                .any(|line| line.contains("action=allow") && line.contains("128.66.0.9")),
            "an identity issued after the denial is exempt from it: {egress}"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    daemon4.debug_reset_dns_lease_owner("sbx-1");
    daemon2.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn a_stalled_prefence_and_parked_read_still_fence_the_new_expiry() {
    // C36 r26 F2: ONE absolute deadline carries across the pre-fence AND
    // the preliminary observation. A's three fence adds (4s each) consume
    // the pass until B expires (+52); the read must NOT then get a fresh
    // 20s budget that excludes the newly-expired B: the deadline-exhausted
    // pass re-discovers and fences B BEFORE any more observation — even
    // with the read parked at a barrier.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com", "b.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![
            FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 7), 44),
            FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 8), 44),
            FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 10), 44),
        ])],
    );
    transport.script(
        "b.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 9),
            52,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("both grants commit");
    let start = std::time::Instant::now();
    let statedir = log.parent().expect("statedir").to_path_buf();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    // Every fence add takes 4s; the first ACL read after this parks at a
    // barrier until released (it is never released during the assertion
    // window). The pass opens at +44 with B's expiry (+52) as its ONE
    // deadline: A's first add succeeds (44→48), the second is killed at
    // the deadline, and the pass STOPS. With the deadline carried into
    // the observation budget, nothing is left for the read — the newly
    // due B is re-discovered and fenced first (~+56). Pre-fix the read
    // budget is recomputed AFTER the pre-fence, excludes the now-expired
    // B, and parks for 20s: B stays allowed and unfenced until ~+72.
    fs::write(statedir.join("slow-acl-fence-add"), "4").unwrap();
    fs::write(statedir.join("barrier-acl-read"), "0").unwrap();
    let deadline = start + Duration::from_secs(100);
    loop {
        let egress = acl_egress(&log, &acl);
        let elapsed = std::time::Instant::now().duration_since(start).as_secs();
        if lease_fence_present(&egress, "128.66.0.9/32") {
            assert!(
                elapsed < 61,
                "B is fenced promptly after its own deadline even when the \
                 pre-fence stall consumed it and the read is parked (took \
                 {elapsed}s)"
            );
            break;
        }
        assert!(
            elapsed < 59,
            "B is fenced at its own deadline even when the pre-fence consumed \
             it and the preliminary read is parked: {egress}"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "B is eventually fenced: {egress}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    // Inverse/cleanup: release the barrier and let the adds behave —
    // every obligation settles and retires.
    let _ = fs::remove_file(statedir.join("barrier-acl-read"));
    let _ = fs::remove_file(statedir.join("slow-acl-fence-add"));
    let _ = fs::remove_file(statedir.join("release-acl-read-barrier"));
    let deadline = std::time::Instant::now() + Duration::from_secs(150);
    while obligations.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "every obligation retires once reads and fence operations behave"
        );
        std::thread::sleep(Duration::from_millis(400));
    }
    let egress = acl_egress(&log, &acl);
    for addr in ["128.66.0.7", "128.66.0.8", "128.66.0.9", "128.66.0.10"] {
        assert!(!egress.contains(addr), "{addr} fully withdrawn: {egress}");
    }
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn a_successful_sibling_withdrawal_never_releases_the_fence_over_a_revoked_survivor() {
    // C36 r26 F3: fence release requires DESTINATION-WIDE proof. B is
    // revoked by NXDOMAIN but ONLY B's allow removal is refused — A's
    // withdrawal and the companion cleanup keep working, and A's live
    // grant suppresses any fence at revocation time. When A later
    // expires, coverage correctly rejects the revoked B, a fence is
    // installed, and A's withdrawal succeeds — but that clean withdrawal
    // must NOT release the fence while B's unauthorized allow survives:
    // the destination stays protected until B's withdrawal proves out.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com", "b.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    // A answers every resolution (refresh1, the revoking refresh2, the
    // committing refresh3): scripts are consumed per query, and an
    // exhausted queue would deny A too — destroying the sibling coverage
    // this scenario needs. The revoking refresh2 FAILS, so A's armed
    // expiry stays the refresh1 one (+40).
    let a_answer =
        || FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 7), 40)]);
    transport.script("a.example.com", [a_answer(), a_answer(), a_answer()]);
    transport.script(
        "b.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            // Outlives the assertion window (A expires at +40) but
            // retires soon after: B's armed obligation is never dropped
            // by a re-arm that denies it.
            120,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("both grants commit");
    let start = std::time::Instant::now();
    let statedir = log.parent().expect("statedir").to_path_buf();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    // The armed identities, robust against generation numbering.
    let (tag_a, tag_b) = {
        let ledger: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&obligations).expect("obligations armed"))
                .expect("obligations json");
        let tag_of = |name: &str| {
            ledger["entries"]
                .as_array()
                .expect("entries")
                .iter()
                .find(|entry| entry["name"].as_str() == Some(name))
                .expect("armed entry")
                .clone()["allow_tag"]
                .as_str()
                .expect("allow tag")
                .to_string()
        };
        (tag_of("a.example.com"), tag_of("b.example.com"))
    };
    // Revoke B by NXDOMAIN with ONLY B's allow removal refused.
    std::thread::sleep(Duration::from_secs(10).saturating_sub(start.elapsed()));
    fs::write(statedir.join("fail-acl-allow-remove-only"), &tag_b).unwrap();
    transport.script("b.example.com", [FakeDnsOutcome::Rcode(3)]);
    refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect_err("the refused revocation withdrawal fails the refresh");
    let marker = fs::read_to_string(&marker_path).expect("revocation marker");
    assert!(
        marker.contains("b.example.com"),
        "the denial is durable before any mutation: {marker}"
    );
    let egress = acl_egress(&log, &acl);
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow") && line.contains(&tag_b)),
        "B's unauthorized group survives its refused withdrawal: {egress}"
    );
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow") && line.contains(&tag_a)),
        "A's live authorization is untouched by B's failed revocation: {egress}"
    );
    // A's verified coverage suppressed any fence at revocation time —
    // the fence tested below is the SETTLEMENT's own. The autonomous
    // boundary may still BLIND-fence the recorded revocation for a
    // sub-tick window before any observation (C36 r31 F2); the
    // coverage-aware settle reconciles that fence away (C36 r31 F3), so
    // the assertion is the STABLE state: no fence across a full watcher
    // tick.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut clean_polls = 0u32;
    loop {
        let egress = acl_egress(&log, &acl);
        if !fence_present(&egress, "128.66.0.7/32") {
            clean_polls += 1;
            if clean_polls >= 8 {
                break;
            }
        } else {
            clean_polls = 0;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "A's verified coverage keeps the destination stably unfenced: {egress}"
        );
        std::thread::sleep(Duration::from_millis(700));
    }
    // A expires at +40 and settles; its withdrawal SUCCEEDS. From the
    // moment A's allow is gone, the fence over the destination must hold
    // CONTINUOUSLY — the clean sibling withdrawal must never release it
    // while B's unauthorized allow survives.
    let deadline = start + Duration::from_secs(80);
    let mut a_withdrawn = false;
    loop {
        let elapsed = std::time::Instant::now().duration_since(start).as_secs();
        let egress = acl_egress(&log, &acl);
        let a_allow = egress
            .lines()
            .any(|line| line.contains("action=allow") && line.contains(&tag_a));
        if a_withdrawn {
            assert!(
                lease_fence_present(&egress, "128.66.0.7/32"),
                "the fence survives the sibling's successful withdrawal while \
                 a revoked allow remains installed: {egress}"
            );
        }
        a_withdrawn |= !a_allow;
        if elapsed > 70 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the assertion window completes: {egress}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    assert!(a_withdrawn, "A's withdrawal really succeeded in the window");
    // Inverse: restore the daemon and re-run the SAME policy (the marker
    // is hash-bound). B's leftover group withdraws through the covered
    // path, the commit retires the revocation, and A's fresh answer keeps
    // the destination authorized.
    fs::remove_file(statedir.join("fail-acl-allow-remove-only")).unwrap();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            40,
        )])],
    );
    transport.script("b.example.com", [FakeDnsOutcome::Rcode(3)]);
    refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("the re-run commits with the revoked group withdrawn");
    let marker = fs::read_to_string(&marker_path).unwrap_or_default();
    assert!(
        !marker.contains("\"b.example.com\""),
        "the committed denial retires from the marker: {marker}"
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(150);
    while obligations.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "every obligation retires once the daemon behaves: {} || {}",
            fs::read_to_string(&obligations).unwrap_or_default(),
            acl_egress(&log, &acl)
        );
        std::thread::sleep(Duration::from_millis(400));
    }
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("128.66.0.7"),
        "the destination is fully withdrawn: {egress}"
    );
    client.debug_reset_dns_lease_owner("sbx-1");
}

/// Release requests accepted by the fake daemon, independently of elapsed
/// time. The owner is stopped before replay, so no watcher can repair an
/// epoch collision or withdraw a late allow before the test observes it.
fn land_queued_acl_requests(log: &Path, operation: &str) {
    let mut requests: Vec<_> = fs::read_dir(log.parent().expect("statedir"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(&format!("queued-{operation}-"))
        })
        .collect();
    requests.sort();
    assert!(
        !requests.is_empty(),
        "the daemon accepted {operation} requests"
    );
    for request in requests {
        let body = fs::read_to_string(&request).unwrap();
        let mut fields = body.lines();
        let target = fields.next().expect("ACL path");
        let args: Vec<_> = fields.filter(|arg| *arg != "--force").collect();
        let current = fs::read_to_string(target).unwrap();
        let next = match operation {
            "remove" => current
                .lines()
                .filter(|line| {
                    !args
                        .iter()
                        .all(|arg| line.split_whitespace().any(|token| token == *arg))
                })
                .map(|line| format!("{line}\n"))
                .collect(),
            "add" => format!("{current}{}\n", args.join(" ")),
            _ => panic!("unknown daemon operation"),
        };
        fs::write(target, next).unwrap();
        fs::remove_file(request).unwrap();
    }
}

#[test]
fn a_retired_marker_never_lets_a_fence_epoch_repeat() {
    // C36 r27 F1: clearing the revocation marker must preserve the
    // request-identity high-water mark. `next_request` counts FENCE
    // EPOCHS as well as allow generations, but the committed generation
    // history records only allows. One grant with two addresses
    // allocates generation 1 plus fence epochs 2 (128.66.0.7) and 3
    // (128.66.0.8); the fence releases are UNCERTAIN (deferred
    // daemon-side removals), then successfully retried, so a clean
    // commit clears the marker and retains only generation 1. A revoke +
    // re-grant of the SECOND address then allocates generation 2 and
    // installs its preventive fence — pre-fix the floor is the
    // generation history (plus the fresh marker's 2), so the fence
    // REUSES epoch 3 for the same destination, and the first pass's
    // deferred removal (still in flight) deletes the NEW fence by its
    // identical identity string; the re-grant's deferred allow lands
    // EFFECTIVE. Post-fix the floor survives in the tombstone, the
    // re-issued fence carries a fresh epoch, and the deferred removal
    // matches nothing.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    let grant = |transport: &FakeDnsTransport| {
        transport.script(
            "a.example.com",
            [FakeDnsOutcome::Answer(vec![
                FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 7), 300),
                FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 8), 300),
            ])],
        );
    };
    grant(&transport);
    let statedir = log.parent().expect("statedir").to_path_buf();
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    let retired_fences = || -> BTreeSet<String> {
        let tags: BTreeSet<_> = fs::read_dir(&statedir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("queued-remove-")
            })
            .flat_map(|path| {
                fs::read_to_string(path)
                    .unwrap()
                    .lines()
                    .filter(|line| line.starts_with("description="))
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .collect();
        assert!(
            !tags.is_empty(),
            "retired fence removals are still in flight"
        );
        tags
    };
    let assert_fresh_fence_issuance = |from: usize, retired: &BTreeSet<String>| {
        let issued: BTreeSet<_> = log_lines(&log)
            .into_iter()
            .skip(from)
            .filter(|line| line.contains("network acl rule add"))
            .flat_map(|line| {
                line.split_whitespace()
                    .filter(|field| field.starts_with("description=wssp-dns-quarantine-"))
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .collect();
        assert!(
            !issued.is_empty(),
            "this leg really exercises refresh-fence allocation: {:?}",
            log_lines(&log).into_iter().skip(from).collect::<Vec<_>>()
        );
        assert!(
            issued.is_disjoint(retired),
            "a new fence request never reuses a retired identity, even if a lease fence masks it: issued {issued:?}, retired {retired:?}"
        );
    };

    // The fence RELEASES are uncertain: the daemon accepts each removal
    // and queues its eventual apply while the CLI reports a transport
    // failure. The test releases the queued daemon work explicitly.
    fs::write(statedir.join("defer-acl-rule-remove"), "queue").unwrap();
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the grant commits");
    assert!(
        marker_path.exists(),
        "the unproven fence releases stay journaled"
    );
    let consumed = || {
        let record: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&marker_path).expect("journaled fence epochs"),
        )
        .unwrap();
        record["next_request"].as_u64().expect("request counter")
    };
    let assert_retired_floor = |consumed| {
        let history = statedir.join("host-state/dns-revocations/sbx-1.lease-history");
        let floor = fs::read_to_string(history)
            .ok()
            .and_then(|body| serde_json::from_str::<serde_json::Value>(&body).ok())
            .and_then(|record| record["request_floor"].as_u64())
            .unwrap_or(0);
        assert!(
            floor >= consumed,
            "marker retirement preserves every consumed fence epoch: floor {floor}, consumed {consumed}"
        );
    };
    let first_consumed = consumed();
    // The retry (before the deferred removals land) positively removes
    // both fences: the pending releases retire and the clean commit
    // CLEARS the marker — pre-fix losing the consumed fence epochs.
    fs::remove_file(statedir.join("defer-acl-rule-remove")).unwrap();
    grant(&transport);
    refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("the reconciling refresh clears the marker");
    assert!(
        !marker_path.exists(),
        "the marker is cleared once the pending releases retire"
    );
    assert_retired_floor(first_consumed);
    // Revoke, commit, then re-grant the SECOND address with an
    // uncertain issuance (queued daemon apply): pre-fix its fence
    // reuses epoch 3 — the identity the first pass's deferred removal
    // for 128.66.0.8 still names.
    transport.script("a.example.com", [FakeDnsOutcome::Rcode(3)]);
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the revocation commits");
    let retired = retired_fences();
    let regrant_start = log_lines(&log).len();
    fs::write(
        statedir.join("defer-acl-allow-add-fail"),
        "queue 128.66.0.8",
    )
    .unwrap();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            300,
        )])],
    );
    let outcome =
        refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the re-grant pass completes");
    assert_fresh_fence_issuance(regrant_start, &retired);
    assert!(
        outcome.denied_names.contains(&"a.example.com".to_string()),
        "the re-grant's uncertain issuance is denied this pass"
    );
    let egress = acl_egress(&log, &acl);
    assert!(
        fence_present(&egress, "128.66.0.8/32"),
        "the re-grant's destination is fenced while unresolved: {egress}"
    );
    // The OLD deferred fence removal lands first: pre-fix it deletes
    // the epoch-reused replacement fence.
    // Stop autonomous repair before replay: it must neither mask a reused
    // fence nor withdraw the late allow before we observe it.
    client.debug_reset_dns_lease_owner("sbx-1");
    land_queued_acl_requests(&log, "remove");
    let egress = acl_egress(&log, &acl);
    assert!(
        fence_present(&egress, "128.66.0.8/32"),
        "the deferred removal of the RETIRED fence cannot strike the re-issued fence: {egress}"
    );
    // The deferred re-grant apply lands next — behind the fence.
    land_queued_acl_requests(&log, "add");
    let egress = acl_egress(&log, &acl);
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow") && line.contains("128.66.0.8")),
        "the deferred re-grant apply landed (the reuse race is real): {egress}"
    );
    assert!(
        fence_present(&egress, "128.66.0.8/32"),
        "the late allow lands behind the fence: {egress}"
    );
    // Cleanup: withdraw the re-grant and retire.
    fs::remove_file(statedir.join("defer-acl-allow-add-fail")).unwrap();
    transport.script("a.example.com", [FakeDnsOutcome::Rcode(3)]);
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the withdrawal commits");
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let egress = acl_egress(&log, &acl);
        if !egress.contains("128.66.0.8") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the destination is fully withdrawn: {egress}"
        );
        transport.script("a.example.com", [FakeDnsOutcome::Rcode(3)]);
        let _ = refresh(&client, "sbx-1", &policy, &hash, &transport);
        std::thread::sleep(Duration::from_millis(500));
    }
    client.debug_reset_dns_lease_owner("sbx-1");

    // ==== C36 r28 F1 leg: a revocation-ONLY pass whose allow withdrawal
    // is REFUSED performs a fence-only allocation — it must be floored by
    // the tombstone too. Grant .8 with an uncertain fence RELEASE
    // (queued daemon removal), retry it clean (the marker clears,
    // carrying the fence's epoch into the tombstone floor), then revoke
    // with the allow withdrawal refused: the replacement fence's epoch
    // must be one the retired release can never name. Pre-fix the
    // fence-only allocation bypassed the tombstone and REISSUED the
    // retired epoch, so the deferred removal deletes the replacement
    // fence while the revoked allow stays installed.
    fs::write(statedir.join("defer-acl-rule-remove"), "queue").unwrap();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("the leg grant commits with an uncertain fence release");
    assert!(
        marker_path.exists(),
        "the leg's uncertain fence release stays journaled"
    );
    let allow_tag = |log: &std::path::Path, acl: &str| {
        acl_egress(log, acl)
            .lines()
            .find(|line| line.contains("action=allow") && line.contains("128.66.0.8"))
            .and_then(|line| {
                line.split_whitespace()
                    .find(|field| field.starts_with("description="))
            })
            .map(str::to_string)
    };
    let granted_tag = allow_tag(&log, &acl).expect("the leg grant's allow is installed");
    let leg_consumed = consumed();
    fs::remove_file(statedir.join("defer-acl-rule-remove")).unwrap();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("the reconciling renewal clears the marker");
    assert!(
        !marker_path.exists(),
        "the marker clears once the pending release retires"
    );
    assert_retired_floor(leg_consumed);
    // Inverse: an unchanged healthy renewal keeps its allow identity.
    assert_eq!(
        allow_tag(&log, &acl).expect("the renewed allow is installed"),
        granted_tag,
        "an unchanged healthy renewal retains its allow identity"
    );
    // Revoke with the allow withdrawal REFUSED, before the deferred
    // removal fires: the unproven withdrawal fences the destination —
    // the fence-only allocation the tombstone floor must cover.
    // The refusal hook STAYS SET past the deferred removal's landing:
    // the autonomous boundary (C36 r31 F2) retries the recorded
    // revocation's withdrawal, and only a persistent refusal keeps the
    // revoked allow installed for the epoch-strike window below.
    // A lease fence could satisfy the withdrawal boundary before its
    // refresh allocator runs, masking a repeated refresh epoch. Stop the
    // owner and refuse only lease-fence adds for this leg: the refresh's
    // own freshly allocated fence must protect the refused withdrawal.
    client.debug_reset_dns_lease_owner("sbx-1");
    fs::write(statedir.join("fail-acl-lease-fence-add"), "").unwrap();
    fs::write(statedir.join("fail-acl-allow-remove"), "1").unwrap();
    transport.script("a.example.com", [FakeDnsOutcome::Rcode(3)]);
    let retired = retired_fences();
    let revoke_start = log_lines(&log).len();
    let _ = refresh(&client, "sbx-1", &policy, &hash, &transport);
    assert_fresh_fence_issuance(revoke_start, &retired);
    let egress = acl_egress(&log, &acl);
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow") && line.contains("128.66.0.8")),
        "the refused withdrawal left the revoked allow installed: {egress}"
    );
    assert!(
        fence_present(&egress, "128.66.0.8/32"),
        "the unproven withdrawal fences the destination: {egress}"
    );
    // The deferred removal of the RETIRED fence lands next: pre-fix it
    // deletes the epoch-reused replacement, leaving the revoked allow
    // effective and unfenced.
    client.debug_reset_dns_lease_owner("sbx-1");
    land_queued_acl_requests(&log, "remove");
    let egress = acl_egress(&log, &acl);
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow") && line.contains("128.66.0.8")),
        "the revoked allow is still installed: {egress}"
    );
    assert!(
        fence_present(&egress, "128.66.0.8/32"),
        "the retired fence's deferred removal cannot strike the replacement fence: {egress}"
    );
    // Cleanup: lift the refusal; the autonomous retry withdraws.
    fs::remove_file(statedir.join("fail-acl-lease-fence-add")).unwrap();
    fs::remove_file(statedir.join("fail-acl-allow-remove")).unwrap();
    transport.script("a.example.com", [FakeDnsOutcome::Rcode(3)]);
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let egress = acl_egress(&log, &acl);
        if !egress.contains("128.66.0.8") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the destination is fully withdrawn: {egress}"
        );
        transport.script("a.example.com", [FakeDnsOutcome::Rcode(3)]);
        let _ = refresh(&client, "sbx-1", &policy, &hash, &transport);
        std::thread::sleep(Duration::from_millis(500));
    }
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn a_revoked_grants_cached_confirmation_never_releases_the_shared_fence() {
    // C36 r27 F2: the ensured-fence release must revalidate its
    // authorization against THIS pass's revocations. Grant A's first
    // address X installs successfully; A's second address fails
    // uncertainly, revoking A (the sweep removes A's installed X group);
    // grant B's allow for the SHARED X also fails uncertainly. Pre-fix
    // the release loop trusts A's cached, unexpired confirmation and
    // removes X's fence — B's deferred allow can then land EFFECTIVE.
    // Post-fix the fence survives and B's late apply lands behind it.
    // The live-overlap inverse is retained by
    // `a_shared_destination_never_unfences_the_survivors_cover`.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com", "b.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![
            FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 7), 300),
            FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 200), 300),
        ])],
    );
    transport.script(
        "b.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    let statedir = log.parent().expect("statedir").to_path_buf();
    // A's SECOND address AND B's shared allow are both accepted
    // daemon-side but reported lost (deferred applies at +45s). A's X
    // add — which must SUCCEED — matches neither pin.
    let b_hash = dns_rule_tag("b.example.com", 2)
        .rsplit('-')
        .next()
        .expect("a generation-scoped tag carries a name hash")
        .to_string();
    fs::write(
        statedir.join("defer-acl-allow-add-fail"),
        format!("45 128.66.0.200\n45 {b_hash}\n"),
    )
    .unwrap();
    let outcome = refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("the pass completes with both grants unresolved");
    for name in ["a.example.com", "b.example.com"] {
        assert!(
            outcome.denied_names.contains(&name.to_string()),
            "{name} is denied while unresolved"
        );
    }
    let egress = acl_egress(&log, &acl);
    // The fence must be the ORIGINAL (epoch 3: generations a=1, b=2, then
    // the fence epochs in add order) — never released on the revoked
    // grant's cached confirmation. A release-then-drift-repair would
    // re-install it under a FRESH epoch, leaving a window in which B's
    // deferred allow could land unfenced (and, if the daemon exits
    // mid-pass, indefinitely).
    assert!(
        fence_present(&egress, "128.66.0.7/32") && egress.contains("wssp-dns-quarantine-g3-"),
        "X stays fenced by its ORIGINAL fence — the revoked grant's cached \
         confirmation is not authorization to release it: {egress}"
    );
    assert!(
        !egress
            .lines()
            .any(|line| line.contains("action=allow") && line.contains("128.66.0.7")),
        "the revoked grant's swept allow is gone: {egress}"
    );
    // The deferred applies land at +45s — B's behind the fence.
    let deadline = std::time::Instant::now() + Duration::from_secs(70);
    loop {
        let egress = acl_egress(&log, &acl);
        let b_landed = egress.lines().any(|line| {
            line.contains("action=allow") && line.contains("128.66.0.7") && line.contains(&b_hash)
        });
        if b_landed {
            assert!(
                fence_present(&egress, "128.66.0.7/32"),
                "B's deferred allow lands behind the fence, never effective: {egress}"
            );
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "B's deferred allow lands: {egress}"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    // Cleanup: withdraw everything and retire.
    fs::remove_file(statedir.join("defer-acl-allow-add-fail")).unwrap();
    transport.script("a.example.com", [FakeDnsOutcome::Rcode(3)]);
    transport.script("b.example.com", [FakeDnsOutcome::Rcode(3)]);
    let deadline = std::time::Instant::now() + Duration::from_secs(90);
    loop {
        let _ = refresh(&client, "sbx-1", &policy, &hash, &transport);
        let egress = acl_egress(&log, &acl);
        if !egress.contains("128.66.0.7") && !egress.contains("128.66.0.200") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "both destinations are fully withdrawn: {egress}"
        );
        transport.script("a.example.com", [FakeDnsOutcome::Rcode(3)]);
        transport.script("b.example.com", [FakeDnsOutcome::Rcode(3)]);
        std::thread::sleep(Duration::from_millis(500));
    }
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn a_restarted_owner_fences_before_its_first_recovery_probe() {
    // C36 r27 F3: recovery must enter the deadline boundary BEFORE its
    // first ACL probe. An expired allow outlives a process restart; the
    // restarted owner's recovery stalls its initial probe (the Incus
    // read hangs) — pre-fix nothing fences the destination for the
    // entire stall (refusing readiness does not stop a running VM, and
    // no watcher exists yet). Post-fix the permit-independent pre-fence
    // fires BEFORE the probe, the probe itself is deadline-bounded, and
    // once the read is released the settlement completes.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the grant commits");
    let statedir = log.parent().expect("statedir").to_path_buf();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    let egress = acl_egress(&log, &acl);
    assert!(
        !fence_present(&egress, "128.66.0.7/32"),
        "the confirmed grant carries no fence: {egress}"
    );
    // The grant expires while the daemon is DOWN: force the obligation
    // overdue, then simulate the restart.
    let ledger: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&obligations).expect("obligations armed"))
            .expect("obligations json");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut expired = ledger.clone();
    for entry in expired["entries"].as_array_mut().expect("entries") {
        entry["expires_at"] = serde_json::json!(now);
    }
    fs::write(
        &obligations,
        serde_json::to_string_pretty(&expired).unwrap(),
    )
    .unwrap();
    client.debug_reset_dns_lease_owner("sbx-1");
    // The restarted owner's recovery parks on its very first ACL read
    // (the blind pre-fence needs no observation — it installs fresh
    // epochs without reading — so the parked read IS the probe).
    fs::write(statedir.join("barrier-acl-read"), "0").unwrap();
    fs::remove_file(statedir.join("release-acl-read-barrier")).ok();
    let (tx, rx) = std::sync::mpsc::channel();
    let probe_client = client.clone();
    let probe = std::thread::spawn(move || {
        let outcome = probe_client.recover_dns_expiry_obligations("sbx-1");
        let _ = tx.send(());
        outcome
    });
    // While the probe is parked, the overdue destination is fenced —
    // bounded by the ownership-probe budget, never by any host-call
    // timeout (C36 r34 F2: the blind fence now first attempts a tightly
    // bounded ownership read — itself parked here, killed at its 5s
    // budget, falling back to the blind add — so enforcement lands
    // within seconds even while reads hang; pre-r23-F10 nothing fenced
    // until the whole stall ended).
    // Watch the append-only operation LOG, not the live ACL: a clean
    // settlement withdraws its own deadline fence right after the
    // withdrawal proves, so a fence visible only between those two
    // steps must not be missed by a slow poll.
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        if log_lines(&log).iter().any(|line| {
            line.contains("rule add")
                && line.contains("lease-quarantine-")
                && line.contains("128.66.0.7")
        }) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the restarted owner fences the overdue destination while its first probe hangs: {}",
            acl_egress(&log, &acl)
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    // Enforcement never lags exposure: the fence add is ordered BEFORE
    // any removal of the expired allow (the withdrawal only ever runs
    // behind a landed fence).
    let ops = log_lines(&log);
    let fence_add = ops.iter().position(|line| {
        line.contains("rule add") && line.contains("quarantine-") && line.contains("128.66.0.7")
    });
    let allow_remove = ops.iter().position(|line| {
        line.contains("rule remove")
            && line.contains("destination=128.66.0.7")
            && !line.contains("quarantine-")
    });
    assert!(
        matches!((fence_add, allow_remove), (Some(add), Some(remove)) if add < remove)
            || (fence_add.is_some() && allow_remove.is_none()),
        "the deadline fence lands before the expired allow is withdrawn"
    );
    // The probe itself is DEADLINE-BOUNDED like the watcher's
    // preliminary read (C36 r26 F2): the parked read fails at its
    // budget (the barrier consumed itself when it parked, so the
    // settlement's own reads proceed), the settlement completes, and
    // the recovery returns on its own — an UNBOUNDED probe would still
    // be parked here.
    rx.recv_timeout(Duration::from_secs(35))
        .expect("the bounded probe fails the parked read and the recovery completes on its own");
    fs::write(statedir.join("release-acl-read-barrier"), "1").unwrap();
    probe
        .join()
        .expect("the recovery thread completes")
        .expect("the recovery settles");
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let egress = acl_egress(&log, &acl);
        if !egress.contains("128.66.0.7") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the expired grant settles once the probe is released: {egress}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    assert!(
        !obligations.exists(),
        "the settled obligations retire: {}",
        obligations.display()
    );
    client.debug_reset_dns_lease_owner("sbx-1");

    // ==== C36 r28 F2 leg: ONE deadline must carry across the recovery
    // pre-fence AND the probe. Three grants: A and C already overdue, B
    // expiring in 7s. Fence adds stall 4s (under the pre-fence's 5s
    // per-add cap), so fencing the overdue destinations consumes B's
    // remaining lifetime: A's add lands, C's add is killed at the
    // deadline, and the pass ends EXHAUSTED. Pre-fix the probe budget
    // was computed AFTER pre-fencing: B — by then expired — is excluded
    // from the gap, the probe re-arms a fresh 20s budget, and NO new
    // fencing happens — with the probe parked, B's expired allow stays
    // effective and unfenced for the whole stall. Post-fix the deadline
    // is captured before pre-fencing; its exhaustion re-discovers and
    // fences the newly-due destinations (C, then B) and skips the probe
    // outright.
    let (policy2, hash2) = domain_policy(&["a.example.com", "b.example.com", "c.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash2);
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    transport.script(
        "b.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            300,
        )])],
    );
    transport.script(
        "c.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 9),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy2, &hash2, &transport).expect("all grants commit");
    let egress = acl_egress(&log, &acl);
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow") && line.contains("128.66.0.8")),
        "B is usable before its expiry: {egress}"
    );
    // A and C expire while the daemon is DOWN; B expires 7 seconds later.
    let ledger: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&obligations).expect("obligations armed"))
            .expect("obligations json");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut expired = ledger.clone();
    for entry in expired["entries"].as_array_mut().expect("entries") {
        if entry["name"].as_str() == Some("b.example.com") {
            entry["expires_at"] = serde_json::json!(now + 7);
        } else {
            entry["expires_at"] = serde_json::json!(now);
        }
    }
    fs::write(
        &obligations,
        serde_json::to_string_pretty(&expired).unwrap(),
    )
    .unwrap();
    client.debug_reset_dns_lease_owner("sbx-1");
    fs::write(statedir.join("slow-acl-fence-add"), "4").unwrap();
    // Every ACL READ fails (C36 r34 F2 choreography: the single-park
    // barrier's one slot is now consumed by the pre-fence's bounded
    // ownership probe, so this leg blocks reads outright instead — the
    // blind pre-fence must fire with reads UNAVAILABLE, which is the
    // r23 F10 property this leg pins).
    fs::write(statedir.join("fail-acl-read"), "200").unwrap();
    fs::remove_file(statedir.join("release-acl-read-barrier")).ok();
    let (tx2, rx2) = std::sync::mpsc::channel();
    let probe_client = client.clone();
    let probe = std::thread::spawn(move || {
        let outcome = probe_client.recover_dns_expiry_obligations("sbx-1");
        let _ = tx2.send(());
        outcome
    });
    // B stays usable until its expiry: while the overdue destinations'
    // fence adds stall, B is not yet due and must NOT be fenced.
    std::thread::sleep(Duration::from_secs(2));
    let egress = acl_egress(&log, &acl);
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow") && line.contains("128.66.0.8"))
            && !fence_present(&egress, "128.66.0.8/32"),
        "B remains usable until its own expiry: {egress}"
    );
    // A's fence lands first (4s); C's add is killed at the pass
    // deadline, so C is fenced by the re-discovery pass that the
    // EXHAUSTED deadline triggers — pre-fix nothing re-fences until the
    // parked probe's fresh 20s budget expires (~27s).
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let egress = acl_egress(&log, &acl);
        if fence_present(&egress, "128.66.0.7/32") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "A's overdue destination is fenced first: {egress}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(14);
    loop {
        let egress = acl_egress(&log, &acl);
        if fence_present(&egress, "128.66.0.8/32") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the exhausted deadline re-fences the newly-due B before the probe: {egress}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(16);
    loop {
        let egress = acl_egress(&log, &acl);
        if fence_present(&egress, "128.66.0.9/32") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the killed add is retried by the exhausted deadline's re-fencing: {egress}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let egress = acl_egress(&log, &acl);
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow") && line.contains("128.66.0.8")),
        "B's expired allow is still installed — behind its fence: {egress}"
    );
    // Every read failed throughout: the recovery could not settle
    // anything (fail closed — an observation failure never settles),
    // and it returned on its own, bounded. Lifting the failure lets
    // the WATCHER (spawned by the recovery's first phase) settle every
    // obligation and retire it.
    fs::remove_file(statedir.join("slow-acl-fence-add")).unwrap();
    // Release is monotonic: a concurrent shim may still rewrite its failure
    // counter after reading it. Keep that counter present so settlement also
    // proves a stale counter cannot re-arm the fault after release.
    fs::write(statedir.join("release-acl-read-failures"), "1").unwrap();
    rx2.recv_timeout(Duration::from_secs(60))
        .expect("the bounded recovery returned on its own while reads failed");
    let _ = probe.join().expect("the recovery thread completes");
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let egress = acl_egress(&log, &acl);
        if !egress.contains("128.66.0.7")
            && !egress.contains("128.66.0.8")
            && !egress.contains("128.66.0.9")
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "every expired grant settles: {egress}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    // Retirement trails the last rule removal by the settle's commit
    // phase (state rewrite + validation + fsyncs): under full-workspace
    // gate load that tail can lag the egress snapshot by seconds, so
    // retirement gets its own bounded window rather than a zero-grace
    // assertion on the loop above.
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        if !obligations.exists() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "every obligation retires: {}",
            obligations.display()
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn a_denied_reconcile_release_never_drops_the_fence_before_its_replacement() {
    // C36 r28 F3: a pending fence-release retry in reconciliation must go
    // through the same destination-wide release boundary as every other
    // release path. Grant .7 with an uncertain ALLOW ISSUANCE (deferred
    // apply at +120) — the unresolved broadening stays pending behind a
    // preventive fence. A re-grant confirms a fresh allow and its ensured
    // fence release is made UNCERTAIN (deferred removal at +90): an
    // unresolved old allow and a pending fence release now coexist. A
    // later DENIAL with fence adds failing must NOT remove the fence
    // first: pre-fix the reconcile retry withdraws the fence on sight,
    // the enforcement's replacement fence fails, and the refresh returns
    // with the stale apply free to land unfenced at +120. Post-fix the
    // retry is gated — unauthorized, so a RELIABLE replacement must be
    // installed first; that fails too, so the old fence stays.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    let statedir = log.parent().expect("statedir").to_path_buf();
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    let started = std::time::Instant::now();
    fs::write(statedir.join("defer-acl-allow-add-fail"), "120 128.66.0.7").unwrap();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    let outcome =
        refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the grant pass completes");
    assert!(
        outcome.denied_names.contains(&"a.example.com".to_string()),
        "the uncertain issuance is denied this pass"
    );
    assert!(marker_path.exists(), "the unresolved allow stays pending");
    let egress = acl_egress(&log, &acl);
    assert!(
        fence_present(&egress, "128.66.0.7/32"),
        "the unresolved broadening is fenced: {egress}"
    );
    // Re-grant: the fresh allow lands and confirms; the ensured fence
    // release is uncertain (deferred removal at +90).
    fs::remove_file(statedir.join("defer-acl-allow-add-fail")).unwrap();
    fs::write(statedir.join("defer-acl-rule-remove"), "90").unwrap();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the re-grant commits");
    assert!(
        marker_path.exists(),
        "the uncertain fence release stays journaled alongside the unresolved allow"
    );
    // Later denial + failed replacement fencing, before the deferred
    // removal and the stale apply fire.
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "the denial happens inside the race window"
    );
    fs::remove_file(statedir.join("defer-acl-rule-remove")).unwrap();
    fs::write(statedir.join("fail-acl-fence-add"), "1").unwrap();
    transport.script("a.example.com", [FakeDnsOutcome::Rcode(3)]);
    let _ = refresh(&client, "sbx-1", &policy, &hash, &transport);
    let egress = acl_egress(&log, &acl);
    assert!(
        fence_present(&egress, "128.66.0.7/32"),
        "the gated retry keeps the old fence when its replacement fails (pre-fix it is removed on sight): {egress}"
    );
    // With fencing working again, the retry installs a RELIABLE
    // replacement (fresh epoch, read back) BEFORE removing the old
    // identity — the deferred removal at +90 can then only strike the
    // superseded fence.
    fs::remove_file(statedir.join("fail-acl-fence-add")).unwrap();
    transport.script("a.example.com", [FakeDnsOutcome::Rcode(3)]);
    let _ = refresh(&client, "sbx-1", &policy, &hash, &transport);
    let egress = acl_egress(&log, &acl);
    assert!(
        fence_present(&egress, "128.66.0.7/32"),
        "the replacement fence is installed before the old identity is released: {egress}"
    );
    // The stale apply lands at +120 — behind the fence that survived.
    let wait = Duration::from_secs(125).saturating_sub(started.elapsed());
    std::thread::sleep(wait);
    let egress = acl_egress(&log, &acl);
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow") && line.contains("128.66.0.7")),
        "the deferred apply landed (the race is real): {egress}"
    );
    assert!(
        fence_present(&egress, "128.66.0.7/32"),
        "the deferred apply lands behind the fence: {egress}"
    );
    // Cleanup: withdraw and retire.
    transport.script("a.example.com", [FakeDnsOutcome::Rcode(3)]);
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let egress = acl_egress(&log, &acl);
        if !egress.contains("128.66.0.7") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the destination is fully withdrawn: {egress}"
        );
        transport.script("a.example.com", [FakeDnsOutcome::Rcode(3)]);
        let _ = refresh(&client, "sbx-1", &policy, &hash, &transport);
        std::thread::sleep(Duration::from_millis(500));
    }
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn an_unreadable_release_journal_never_adopts_a_refresh_fence() {
    // C36 r28 F4: when the revocation marker (the refresh-family release
    // journal) is UNREADABLE, no observed refresh fence may be adopted —
    // its release-pending state is unknown, and it could be one whose
    // deferred removal is still in flight. Inverse first: with a
    // READABLE marker and an EMPTY journal, an installed refresh fence
    // IS adopted (no fresh fence is issued). Then make that fence's
    // release uncertain (deferred removal at +90), corrupt the marker,
    // and stall the allow withdrawal: the withdrawal boundary must
    // install a FRESH lease-family fence instead of adopting — pre-fix
    // the adoption leaves the release-pending fence as the destination's
    // only protection, and the deferred removal deletes it while the
    // expired allow stays effective.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    let statedir = log.parent().expect("statedir").to_path_buf();
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    let mut lease_alloc = |dest: &str| {
        let epoch = client.allocate_lease_fence_epoch("sbx-1")?;
        let addr = dest
            .strip_suffix("/32")
            .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
            .expect("ipv4 /32");
        Ok(super::network::domain_lease_fence_rule(addr, epoch))
    };
    let tags_of = |log: &std::path::Path, acl: &str| -> (Vec<String>, Vec<String>) {
        let mut allows = Vec::new();
        let mut companions = Vec::new();
        for line in acl_egress(log, acl).lines() {
            if !line.contains("128.66.0.7") {
                continue;
            }
            if let Some(field) = line
                .split_whitespace()
                .find(|field| field.starts_with("description=wssp-dns-"))
            {
                let tag = field.trim_start_matches("description=").to_string();
                if line.contains("action=allow") {
                    allows.push(tag);
                } else if line.contains("destination_port=") {
                    companions.push(tag);
                }
            }
        }
        (allows, companions)
    };
    // Grant .7 cleanly, then revoke with the allow withdrawal REFUSED:
    // the revocation pass leaves the refresh fence installed with the
    // marker retained and its release journal EMPTY.
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the grant commits");
    fs::write(statedir.join("fail-acl-allow-remove"), "1").unwrap();
    transport.script("a.example.com", [FakeDnsOutcome::Rcode(3)]);
    let _ = refresh(&client, "sbx-1", &policy, &hash, &transport);
    let egress = acl_egress(&log, &acl);
    assert!(
        fence_present(&egress, "128.66.0.7/32"),
        "the refused withdrawal leaves the refresh fence installed: {egress}"
    );
    assert!(marker_path.exists(), "the revocation marker is retained");
    // Inverse: the marker is READABLE with an EMPTY release journal, so
    // the installed refresh fence is adopted — no fresh fence is issued.
    fs::remove_file(statedir.join("fail-acl-allow-remove")).unwrap();
    let (allow_tags, companion_tags) = tags_of(&log, &acl);
    let adopt = client
        .enforce_destination_withdrawal(
            "sbx-1",
            &acl,
            "128.66.0.7/32",
            &allow_tags,
            &companion_tags,
            true,
            false,
            None,
            Some(std::time::Instant::now() + Duration::from_secs(15)),
            true,
            &mut lease_alloc,
        )
        .expect("the withdrawal boundary runs");
    assert!(
        adopt.fence_added.is_none() && adopt.fence_present.is_some(),
        "a readable marker with an empty journal still adopts the installed refresh fence"
    );
    // Re-grant: the fresh allow lands and confirms; the fence's release
    // is made UNCERTAIN — the deferred removal fires at +90 while the
    // fence stays installed.
    let armed = std::time::Instant::now();
    fs::write(statedir.join("defer-acl-rule-remove"), "90").unwrap();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the re-grant commits");
    let egress = acl_egress(&log, &acl);
    assert!(
        fence_present(&egress, "128.66.0.7/32"),
        "the release-pending refresh fence is still installed: {egress}"
    );
    assert!(
        marker_path.exists(),
        "the uncertain release keeps the marker"
    );
    // The release journal becomes UNREADABLE and the withdrawal stalls:
    // the boundary must install a FRESH lease-family fence rather than
    // adopt the fence whose deferred removal is still in flight.
    fs::write(&marker_path, "not json").unwrap();
    fs::write(statedir.join("fail-acl-allow-remove"), "1").unwrap();
    let (allow_tags, companion_tags) = tags_of(&log, &acl);
    // The call fences FIRST, then fails on the stalled withdrawal — the
    // discriminating state is on the ACL: a FRESH lease-family fence
    // must be installed rather than the release-pending refresh fence
    // being adopted (pre-fix nothing new appears here).
    let _ = client.enforce_destination_withdrawal(
        "sbx-1",
        &acl,
        "128.66.0.7/32",
        &allow_tags,
        &companion_tags,
        true,
        false,
        None,
        Some(std::time::Instant::now() + Duration::from_secs(15)),
        true,
        &mut lease_alloc,
    );
    let egress = acl_egress(&log, &acl);
    assert!(
        egress.lines().any(|line| {
            line.contains("wssp-dns-lease-quarantine-") && line.contains("128.66.0.7/32")
        }),
        "an unreadable release journal disqualifies adoption: a fresh lease fence is issued: {egress}"
    );
    // The deferred removal lands at +90: it deletes the release-pending
    // REFRESH fence; the fresh lease fence survives, still covering the
    // allow whose withdrawal is stalled.
    let wait = Duration::from_secs(95).saturating_sub(armed.elapsed());
    std::thread::sleep(wait);
    let egress = acl_egress(&log, &acl);
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow") && line.contains("128.66.0.7")),
        "the stalled withdrawal leaves the expired allow installed: {egress}"
    );
    assert!(
        egress.lines().any(|line| {
            line.contains("wssp-dns-lease-quarantine-") && line.contains("128.66.0.7/32")
        }),
        "the deferred removal cannot strike the freshly issued lease fence: {egress}"
    );
    // Cleanup: a VALID marker again, withdrawals unblocked, settle.
    fs::remove_file(&marker_path).unwrap();
    fs::remove_file(statedir.join("fail-acl-allow-remove")).unwrap();
    transport.script("a.example.com", [FakeDnsOutcome::Rcode(3)]);
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let egress = acl_egress(&log, &acl);
        if !egress
            .lines()
            .any(|line| line.contains("action=allow") && line.contains("128.66.0.7"))
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the allow is withdrawn once removals work again: {egress}"
        );
        transport.script("a.example.com", [FakeDnsOutcome::Rcode(3)]);
        let _ = refresh(&client, "sbx-1", &policy, &hash, &transport);
        std::thread::sleep(Duration::from_millis(500));
    }
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn startup_inventory_recovers_expired_dns_obligations() {
    // C36 r29 F1: normal host startup calls `sandbox_inventory` — never
    // reconnect, refresh, or the recovery helper directly. A grant that
    // expired while the daemon was down must be settled BY THE INVENTORY
    // (withdrawn, ledger retired) before the census reports the running
    // VM Ready; pre-fix the inventory never recovers, so the expired
    // allow stays installed until some unrelated operation happens to
    // trigger recovery.
    let (runtime, log) = runtime_for("running");
    let client = runtime.client().clone();
    client
        .apply_sandbox_network(&test_plan("sbx-1"))
        .expect("apply");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the grant commits");
    let statedir = log.parent().expect("statedir").to_path_buf();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    assert!(obligations.exists(), "the obligation is armed");
    // The grant expires while the daemon is DOWN: force the obligation
    // overdue and simulate the restart (no owner in memory).
    let mut ledger: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&obligations).expect("obligations"))
            .expect("obligations json");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for entry in ledger["entries"].as_array_mut().expect("entries") {
        entry["expires_at"] = serde_json::json!(now);
    }
    fs::write(&obligations, serde_json::to_string_pretty(&ledger).unwrap()).unwrap();
    client.debug_reset_dns_lease_owner("sbx-1");
    // STARTUP: the inventory itself must recover — no reconnect, no
    // refresh, no direct recovery call.
    // The reviewer's scenario is a HEALTHY running VM: no outstanding
    // network cleanup intent, so the fenced drain inside the inventory
    // never reaches verification for it (that path recovers too, post
    // fix). Retire the provisioning-phase intent left from setup so the
    // inventory recovery boundary alone owns the settlement.
    let _ = fs::remove_file(statedir.join("host-state/network-cleanups/sbx-1.json"));
    let inventory = runtime.sandbox_inventory().expect("inventory recovers");
    assert!(
        inventory.iter().any(|entry| entry.sandbox_id == "sbx-1"),
        "the running VM is still reported: {inventory:?}"
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let egress = acl_egress(&log, &acl);
        let allow_gone = !egress
            .lines()
            .any(|line| line.contains("action=allow") && line.contains("128.66.0.7"));
        if allow_gone && !obligations.exists() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "startup inventory settled the expired grant (allow withdrawn, ledger retired): {egress}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn verification_recovers_dns_obligations_before_its_first_outer_read() {
    // C36 r29 F1 (verification leg): `verify_provisioned_enforcement`
    // used to perform ordinary network/ACL reads BEFORE reaching
    // recovery, so a stalled outer read left an expired allow effective
    // for the whole stall. Post-fix recovery runs first; its blind
    // pre-fence needs no observation, so the overdue destination is
    // fenced even while every ACL read is parked.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the grant commits");
    let statedir = log.parent().expect("statedir").to_path_buf();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    let mut ledger: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&obligations).expect("obligations"))
            .expect("obligations json");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for entry in ledger["entries"].as_array_mut().expect("entries") {
        entry["expires_at"] = serde_json::json!(now);
    }
    fs::write(&obligations, serde_json::to_string_pretty(&ledger).unwrap()).unwrap();
    client.debug_reset_dns_lease_owner("sbx-1");
    // Park EVERY ACL read; verification's outer reads used to come
    // first, so pre-fix nothing fences the expired destination until
    // the barrier is released.
    fs::write(statedir.join("barrier-acl-read"), "0").unwrap();
    fs::remove_file(statedir.join("release-acl-read-barrier")).ok();
    let (tx, rx) = std::sync::mpsc::channel();
    let verify_client = client.clone();
    let verify = std::thread::spawn(move || {
        let outcome = verify_client.verify_provisioned_enforcement("sbx-1");
        let _ = tx.send(());
        outcome
    });
    // Watch the append-only operation LOG, not the live ACL: a clean
    // settlement withdraws its own deadline fence right after the
    // withdrawal proves, so a fence visible only between those two
    // steps must not be missed by a slow poll. C36 r34 F2: the blind
    // fence first attempts a tightly bounded ownership read — itself
    // parked here, killed at its 5s budget, falling back to the blind
    // add — so enforcement lands within seconds even while every read
    // hangs.
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        if log_lines(&log).iter().any(|line| {
            line.contains("rule add")
                && line.contains("lease-quarantine-")
                && line.contains("128.66.0.7")
        }) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "recovery's blind pre-fence fires while the parked outer read hangs: {}",
            acl_egress(&log, &acl)
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    // Enforcement never lags exposure: the fence add is ordered BEFORE
    // any removal of the expired allow (the withdrawal only ever runs
    // behind a landed fence).
    let ops = log_lines(&log);
    let fence_add = ops.iter().position(|line| {
        line.contains("rule add") && line.contains("quarantine-") && line.contains("128.66.0.7")
    });
    let allow_remove = ops.iter().position(|line| {
        line.contains("rule remove")
            && line.contains("destination=128.66.0.7")
            && !line.contains("quarantine-")
    });
    assert!(
        matches!((fence_add, allow_remove), (Some(add), Some(remove)) if add < remove)
            || (fence_add.is_some() && allow_remove.is_none()),
        "the deadline fence lands before the expired allow is withdrawn"
    );
    fs::write(statedir.join("release-acl-read-barrier"), "1").unwrap();
    rx.recv_timeout(Duration::from_secs(60))
        .expect("verification completes once the read is released");
    verify
        .join()
        .expect("the verification thread completes")
        .expect("verification passes against the settled truth");
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn reconciliation_never_rolls_back_the_request_counter() {
    // C36 r29 F2: reconciliation holds a marker SNAPSHOT read before its
    // loop; its replacement-fence branch allocates durably (advancing
    // `next_request` on disk), and the retirement write-back of the
    // snapshot used to roll the counter backward. Compose: an uncertain
    // issuance (pending allow + preventive fence), a re-grant whose
    // ensured-fence release is uncertain (pending release), a denial
    // whose reconcile installs a replacement fence (successful
    // replacement reconciliation), an interruption, a reauthorization,
    // and a later uncertain release + denial. The consumed-identity
    // high-water mark must NEVER decrease, and no fence epoch may ever
    // repeat a retired one.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    let statedir = log.parent().expect("statedir").to_path_buf();
    let counter_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    let marker_next = || -> u64 {
        let body = fs::read_to_string(&counter_path).expect("marker exists");
        serde_json::from_str::<serde_json::Value>(&body).expect("marker json")["next_request"]
            .as_u64()
            .expect("counter")
    };
    let fence_epoch = |log: &std::path::Path, acl: &str| -> Option<u64> {
        acl_egress(log, acl)
            .lines()
            .find(|line| {
                line.contains("destination=128.66.0.7/32")
                    && line.contains("wssp-dns-quarantine-")
                    && !line.contains("destination_port")
            })
            .and_then(|line| {
                line.split_whitespace()
                    .find(|field| field.starts_with("description=wssp-dns-quarantine-g"))
            })
            .and_then(|field| {
                field
                    .trim_start_matches("description=wssp-dns-quarantine-g")
                    .split('-')
                    .next()
                    .and_then(|digits| digits.parse().ok())
            })
    };
    let answer = |transport: &FakeDnsTransport| {
        transport.script(
            "a.example.com",
            [FakeDnsOutcome::Answer(vec![
                FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 7), 300),
                FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 8), 300),
            ])],
        );
    };
    // Keep the accepted allow queued throughout the composition. Its
    // unresolved intent retains the marker independently of host speed.
    // Two re-grant destinations force two replacement allocations, so the
    // counter must cover the first replacement strictly as asserted below.
    fs::write(statedir.join("fail-acl-lease-fence-add"), "").unwrap();
    fs::write(
        statedir.join("defer-acl-allow-add-fail"),
        "queue 128.66.0.7",
    )
    .unwrap();
    answer(&transport);
    let outcome =
        refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the grant pass completes");
    assert!(
        outcome.denied_names.contains(&"a.example.com".to_string()),
        "the uncertain issuance is denied this pass"
    );
    let e1 = fence_epoch(&log, &acl).expect("the preventive fence is installed");
    // Re-grant: the fresh allow confirms; the ensured release of F1 is
    // uncertain (queued daemon removal).
    fs::remove_file(statedir.join("defer-acl-allow-add-fail")).unwrap();
    fs::write(statedir.join("defer-acl-rule-remove"), "queue").unwrap();
    answer(&transport);
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the re-grant commits");
    assert!(
        counter_path.exists(),
        "the unresolved allow and the pending release stay journaled"
    );
    let high_water = marker_next();
    // Denial: the held stale allow remains unresolved. With the
    // destination unauthorized, reconciliation installs replacement R BEFORE
    // retiring F1's pending release, durably advancing the counter, and
    // finally writes its snapshot back.
    fs::remove_file(statedir.join("defer-acl-rule-remove")).unwrap();
    transport.script("a.example.com", [FakeDnsOutcome::Rcode(3)]);
    let _ = refresh(&client, "sbx-1", &policy, &hash, &transport);
    let replacement = fence_epoch(&log, &acl).expect("the replacement fence is installed");
    assert!(
        replacement > e1,
        "the replacement carries a fresh epoch ({replacement} > {e1})"
    );
    assert!(
        counter_path.exists(),
        "the unresolved allow keeps the marker retained"
    );
    let after_reconcile = marker_next();
    assert!(
        after_reconcile > high_water && after_reconcile > replacement,
        "reconciliation never decreases the consumed-identity high-water mark \
         ({after_reconcile} > {high_water}, and covers the replacement epoch {replacement})"
    );
    // Interruption, reauthorization: the re-grant's ensured release of R
    // is uncertain again (queued daemon removal).
    client.debug_reset_dns_lease_owner("sbx-1");
    fs::write(statedir.join("defer-acl-rule-remove"), "queue").unwrap();
    answer(&transport);
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the reauthorization commits");
    assert!(
        counter_path.exists(),
        "the reauthorization's uncertain release stays journaled"
    );
    let high_water = marker_next();
    // The later uncertain release's reconcile: the replacement R2 must
    // carry an epoch NEVER consumed before — pre-fix the rolled-back
    // counter can reissue R's epoch, whose deferred removal is still in
    // flight.
    fs::remove_file(statedir.join("defer-acl-rule-remove")).unwrap();
    transport.script("a.example.com", [FakeDnsOutcome::Rcode(3)]);
    let _ = refresh(&client, "sbx-1", &policy, &hash, &transport);
    let second = fence_epoch(&log, &acl).expect("the second replacement fence is installed");
    assert!(
        second != e1 && second != replacement,
        "no fence epoch ever repeats a retired one ({second} vs {e1}, {replacement})"
    );
    assert!(
        marker_next() > high_water.max(second),
        "the high-water mark is monotone across the whole composition"
    );
    // Release the accepted daemon work in order after all counter checks.
    client.debug_reset_dns_lease_owner("sbx-1");
    land_queued_acl_requests(&log, "remove");
    land_queued_acl_requests(&log, "add");
    fs::remove_file(statedir.join("fail-acl-lease-fence-add")).unwrap();
    // Cleanup: positively withdraw the now-landed old identity and retire.
    transport.script("a.example.com", [FakeDnsOutcome::Rcode(3)]);
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let egress = acl_egress(&log, &acl);
        if !egress.contains("128.66.0.7") && !egress.contains("128.66.0.8") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the destination is fully withdrawn: {egress}"
        );
        transport.script("a.example.com", [FakeDnsOutcome::Rcode(3)]);
        let _ = refresh(&client, "sbx-1", &policy, &hash, &transport);
        std::thread::sleep(Duration::from_millis(500));
    }
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn startup_recovery_activates_every_owner_before_settling_any() {
    // C36 r30 F1: startup recovery used to process ledgers SERIALLY and
    // return on the first error — a malformed ledger (or a stalled
    // settlement) for sandbox A prevented sandbox B's owner and watcher
    // from ever starting, so B's expired allow stayed effective despite
    // its valid ledger and functioning ACL. Recovery now ACTIVATES every
    // recoverable owner (ledger read, adoption, watcher spawn) before any
    // fallible daemon settlement, isolates per-sandbox failures, and
    // aggregates the errors afterwards.
    let (client, log) = applied_client("running", "sbx-1");
    client
        .apply_sandbox_network(&test_plan("sbx-2"))
        .expect("apply sbx-2");
    let statedir = log.parent().expect("statedir").to_path_buf();
    let (_network2, acl2) = sandbox_network_names("sbx-2");
    let transport = FakeDnsTransport::new();
    let (policy, hash) = domain_policy(&["b.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-2", &hash);
    transport.script(
        "b.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 9),
            300,
        )])],
    );
    refresh(&client, "sbx-2", &policy, &hash, &transport).expect("the grant commits");
    // Healthy inverse: nothing due, no malformed ledger — recovery is a
    // clean no-op and the live grant is untouched.
    client
        .recover_all_dns_expiry_obligations()
        .expect("healthy inverse: nothing to settle");
    let egress = acl_egress(&log, &acl2);
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow") && line.contains("128.66.0.9")),
        "the live grant survives a healthy startup recovery: {egress}"
    );
    // Sandbox A's ledger is MALFORMED; sandbox B's grant expired while
    // the daemon was down.
    fs::write(
        statedir.join("host-state/dns-revocations/sbx-1.lease.json"),
        "not json",
    )
    .unwrap();
    let obligations2 = lease_obligations_path(&statedir, "sbx-2");
    let mut ledger: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&obligations2).expect("obligations"))
            .expect("obligations json");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for entry in ledger["entries"].as_array_mut().expect("entries") {
        entry["expires_at"] = serde_json::json!(now);
    }
    fs::write(
        &obligations2,
        serde_json::to_string_pretty(&ledger).unwrap(),
    )
    .unwrap();
    client.debug_reset_dns_lease_owner("sbx-2");
    // The aggregate failure names A — and B is STILL settled: its owner
    // was activated and its settlement ran independently of A's failure.
    let err = client
        .recover_all_dns_expiry_obligations()
        .expect_err("A's malformed ledger is reported after the fan-out");
    assert!(
        err.to_string().contains("sbx-1"),
        "the aggregate error names the failed sandbox: {err}"
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let egress = acl_egress(&log, &acl2);
        let allow_gone = !egress
            .lines()
            .any(|line| line.contains("action=allow") && line.contains("128.66.0.9"));
        if allow_gone && !obligations2.exists() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "B recovered independently of A's malformed ledger (allow withdrawn, ledger retired): {egress}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    client.debug_reset_dns_lease_owner("sbx-2");
}

#[test]
fn startup_inventory_enforces_recorded_denials() {
    // C36 r30 F3: recovery settled only ELAPSED TTLs. A refresh that
    // journaled an NXDOMAIN and crashed before its first ACL mutation
    // left the denied address reachable until the old TTL expired, and
    // the startup census labeled the running VM Ready without any
    // readiness gate noticing. Recovery now enforces recorded revocations
    // through the shared withdrawal boundary BEFORE readiness reports,
    // preserving the denial evidence until a refresh commits it.
    let (runtime, log) = runtime_for("running");
    let client = runtime.client().clone();
    client
        .apply_sandbox_network(&test_plan("sbx-1"))
        .expect("apply");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the grant commits");
    let statedir = log.parent().expect("statedir").to_path_buf();
    // Committed/live-grant inverse: the census reports the sandbox and
    // leaves the live allow alone.
    let inventory = runtime.sandbox_inventory().expect("inventory");
    assert!(inventory.iter().any(|entry| entry.sandbox_id == "sbx-1"));
    let egress = acl_egress(&log, &acl);
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow") && line.contains("128.66.0.7")),
        "a committed live grant is untouched by the census: {egress}"
    );
    // The pre-mutation crash: the denial is journaled durably, the first
    // ACL mutation fails, and the daemon dies before any withdrawal.
    transport.script("a.example.com", [FakeDnsOutcome::Rcode(3)]);
    fs::write(statedir.join("fail-acl-rule-remove"), "").unwrap();
    refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect_err("the interrupted revocation leaves the marker");
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    assert!(marker_path.exists(), "the denial is journaled");
    let egress = acl_egress(&log, &acl);
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow") && line.contains("128.66.0.7")),
        "the crash left the denied allow installed: {egress}"
    );
    // RESTART: the owner is gone; the daemon-side removal works again
    // (the crash was daemon-side). The provisioning-phase cleanup intent
    // from setup is retired so the census's OWN recovery boundary — not
    // the fenced drain's verification — owns the enforcement.
    client.debug_reset_dns_lease_owner("sbx-1");
    fs::remove_file(statedir.join("fail-acl-rule-remove")).unwrap();
    let _ = fs::remove_file(statedir.join("host-state/network-cleanups/sbx-1.json"));
    let inventory = runtime
        .sandbox_inventory()
        .expect("the census recovers and enforces the recorded denial");
    assert!(
        inventory.iter().any(|entry| entry.sandbox_id == "sbx-1"),
        "the running VM is still reported: {inventory:?}"
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let egress = acl_egress(&log, &acl);
        if !egress
            .lines()
            .any(|line| line.contains("action=allow") && line.contains("128.66.0.7"))
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the recorded denial is enforced before readiness reports: {egress}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    // Denial evidence is PRESERVED until a refresh commits it.
    let marker: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&marker_path).expect("the marker survives recovery"),
    )
    .expect("marker json");
    assert!(
        marker["revoked"]
            .as_array()
            .is_some_and(|names| names.iter().any(|name| name == "a.example.com")),
        "the denial evidence is preserved until commit: {marker}"
    );
    // A committing refresh retires the evidence.
    transport.script("a.example.com", [FakeDnsOutcome::Rcode(3)]);
    let _ = refresh(&client, "sbx-1", &policy, &hash, &transport);
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn issuance_skips_the_fence_only_behind_current_authorization() {
    // C36 r30 F2: the issuance skip-fence check trusted `confirmed_dests`,
    // captured when the pass read the ACL, without checking the
    // authorizing grant's expiry, revocation, or continued installation.
    // A already authorizes X; an unrelated addition stalls the pass until
    // A expires and the lease cleanly withdraws it; the fresh grant B for
    // X still found X in the cache and issued its allow with NO
    // preventive fence — a crash or deferred apply then leaves B
    // effective with no confirmed authorization. Issuance now consults
    // the SAME current-authorization gate as the release paths.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let transport = FakeDnsTransport::new();
    let statedir = log.parent().expect("statedir").to_path_buf();
    let rule_adds_for = |log: &std::path::Path, needle: &str| -> Vec<String> {
        log_lines(log)
            .into_iter()
            .filter(|line| line.contains("network acl rule add") && line.contains(needle))
            .collect()
    };
    // A authorizes X; B, C, D, E are all denied. The policy NEVER
    // changes below — the persisted state (and with it transient
    // retention, which is keyed by policy hash) survives into the
    // stalling pass, so A's installed allow keeps X in the pass-start
    // confirmed_dests cache while B's re-grant (after its revocation)
    // issues a FRESH allow identity for the same destination. Name
    // order makes B's generation the HIGHEST (fresh identities are
    // allocated in alphabetical name order), so its rule group sorts
    // last in the add phase.
    let (policy_ab, hash_ab) = domain_policy(
        &[
            "a.example.com",
            "c.example.com",
            "d.example.com",
            "e.example.com",
            "z.example.com",
        ],
        &[],
    );
    bind_recorded_policy(&log, "sbx-1", &hash_ab);
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    for denied in [
        "z.example.com",
        "c.example.com",
        "d.example.com",
        "e.example.com",
    ] {
        transport.script(denied, [FakeDnsOutcome::Rcode(3)]);
    }
    refresh(&client, "sbx-1", &policy_ab, &hash_ab, &transport).expect("A commits");
    // Force A's grant to expire mid-pass: the persisted state expiry
    // (retained on a transient failure only while it clears the churn
    // floor — expires_at >= now + MIN_REFRESH_TTL_SECS) and the armed
    // lease obligation both move to now+55: A survives planning AND the
    // pass's ACL snapshot (so the stale confirmed_dests cache holds X
    // under A's RETAINED generation), but its authorization lapses while
    // the stalled pass below is still fencing the other fresh grants,
    // and the LIVE owner's watcher settles it at expiry.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let state_path = statedir.join("host-state/dns-policy/sbx-1.json");
    let mut dns_state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&state_path).expect("dns state"))
            .expect("dns state json");
    for grant in dns_state["grants"].as_array_mut().expect("grants") {
        if grant["name"] == "a.example.com" {
            grant["expires_at"] = serde_json::json!(now + 55);
        }
    }
    fs::write(
        &state_path,
        serde_json::to_string_pretty(&dns_state).unwrap(),
    )
    .unwrap();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    let mut ledger: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&obligations).expect("obligations"))
            .expect("obligations json");
    for entry in ledger["entries"].as_array_mut().expect("entries") {
        if entry["name"] == "a.example.com" {
            entry["expires_at"] = serde_json::json!(now + 55);
        }
    }
    fs::write(&obligations, serde_json::to_string_pretty(&ledger).unwrap()).unwrap();
    // The stalling pass, SAME policy hash: A is retained from its prior
    // grant (transient failure, generation preserved — so X stays in the
    // pass-start cache); B, C, D, E resolve now, re-grants after
    // revocation whose rules are all fresh issuances. FENCE adds stall
    // 20s apiece (fencing is bounded by the earliest working grant's
    // deadline but not killed mid-install the way grant-budgeted rule
    // adds are), so C's, D's, and E's preventive fences burn past A's
    // expiry before B's group — the LAST by tag order — is reached;
    // E's grant-budgeted allow is then killed at A's expired deadline,
    // which revokes A out of the budget map, and B's companion rejects
    // land on a healthy budget. B's allow issuance is DECIDED after A's
    // expiry, and the invocation — plus its ordering against the fence —
    // is what the assertions discriminate on. A's own settlement fence
    // (lease family) cannot land before B's decision: the settlement's
    // fence install is itself stalled 20s, and the pre-fence adoption
    // check runs before it lands.
    fs::write(statedir.join("slow-acl-fence-add"), "20").unwrap();
    transport.script("a.example.com", [FakeDnsOutcome::TransportError]);
    transport.script(
        "z.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    transport.script(
        "c.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            300,
        )])],
    );
    transport.script(
        "d.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 9),
            300,
        )])],
    );
    transport.script(
        "e.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 10),
            300,
        )])],
    );
    // Only THIS pass's mutations count: pass 1 installed A's own
    // preventive fence before A's allow, and the ordering assertion must
    // discriminate on B's issuance alone.
    fs::remove_file(&log).ok();
    let pass_start = std::time::Instant::now();
    let _ = refresh(&client, "sbx-1", &policy_ab, &hash_ab, &transport);
    fs::remove_file(statedir.join("slow-acl-fence-add")).unwrap();
    assert!(
        pass_start.elapsed() >= Duration::from_secs(60),
        "the pass really stalled past A's expiry"
    );
    let adds = rule_adds_for(&log, "128.66.0.7/32");
    let allow_pos = adds.iter().rposition(|line| line.contains("action=allow"));
    let fence_pos = adds.iter().rposition(|line| {
        line.contains("action=reject")
            && line.contains("wssp-dns-quarantine-")
            && !line.contains("destination_port")
    });
    assert!(
        allow_pos.is_some(),
        "B's allow for the shared destination was issued: {}",
        adds.join("\n")
    );
    assert!(
        fence_pos.is_some_and(|fence| Some(fence) < allow_pos),
        "B's allow issued BEHIND a preventive fence — A's authorization was no longer current: {}",
        adds.join("\n")
    );
    // The retained inverse, on a FRESH fixture so the main leg's crash
    // state cannot interfere: GENUINELY LIVE overlapping grants sharing a
    // destination — the second grant's allow, issued after the first
    // grant's allow was installed and confirmed by the SAME pass, needs
    // no fence of its own. Exactly ONE preventive fence covers the
    // destination's first-ever issuance.
    let (client2, log2) = applied_client("running", "sbx-1");
    let transport2 = FakeDnsTransport::new();
    let (policy_de, hash_de) = domain_policy(&["d.example.com", "e.example.com"], &[]);
    bind_recorded_policy(&log2, "sbx-1", &hash_de);
    transport2.script(
        "d.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            300,
        )])],
    );
    transport2.script(
        "e.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            300,
        )])],
    );
    let de_out = refresh(&client2, "sbx-1", &policy_de, &hash_de, &transport2);
    assert!(
        de_out.as_ref().is_ok_and(|out| out.denied_names.is_empty()),
        "the inverse pass commits cleanly: {de_out:?}"
    );
    let adds = rule_adds_for(&log2, "128.66.0.8/32");
    assert_eq!(
        adds.iter()
            .filter(|line| line.contains("action=allow"))
            .count(),
        2,
        "both overlapping grants issued their allows: {}",
        adds.join("\n")
    );
    assert_eq!(
        adds.iter()
            .filter(|line| line.contains("action=reject")
                && line.contains("wssp-dns-quarantine-")
                && !line.contains("destination_port"))
            .count(),
        1,
        "exactly one preventive fence for the first-ever issuance; the live overlap needs none: {}",
        adds.join("\n")
    );
    client2.debug_reset_dns_lease_owner("sbx-1");
    // Cleanup: withdraw everything and retire.
    fs::remove_file(&log).ok();
    let (policy_off, hash_off) = domain_policy(&[], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash_off);
    let deadline = std::time::Instant::now() + Duration::from_secs(300);
    loop {
        let egress = acl_egress(&log, &acl);
        let allows_left = ["128.66.0.7", "128.66.0.8", "128.66.0.9", "128.66.0.10"]
            .iter()
            .any(|dest| {
                egress
                    .lines()
                    .any(|line| line.contains("action=allow") && line.contains(dest))
            });
        // Standing quarantine fences for the revoked destinations are the
        // correct end state; only the allows must be gone.
        if !allows_left {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "all destinations withdrawn: {egress}"
        );
        let _ = refresh(&client, "sbx-1", &policy_off, &hash_off, &transport);
        std::thread::sleep(Duration::from_millis(500));
    }
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn rotation_reissues_behind_a_fence_not_the_retired_group() {
    // C36 r31 F1 (rotation leg): the issuance gate trusted the PASS-START
    // ACL snapshot. On a partial rotation {X,Y} -> {X,Z} the removal phase
    // withdraws the old generation's group, but its still-installed rules
    // and unexpired lease obligation authorized the replacement allow for
    // X WITHOUT a preventive fence — a crash after issuance (or a deferred
    // daemon-side apply) then leaves the new allow effective with no fence
    // behind it. The gate now authorizes only a group that SURVIVES the
    // pass (the snapshot minus this pass's removals, plus this pass's
    // confirmed additions) under the request identity's own unexpired,
    // non-revoked armed grant.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let transport = FakeDnsTransport::new();
    let statedir = log.parent().expect("statedir").to_path_buf();
    let rule_adds_for = |log: &std::path::Path, needle: &str| -> Vec<String> {
        log_lines(log)
            .into_iter()
            .filter(|line| line.contains("network acl rule add") && line.contains(needle))
            .collect()
    };
    let (policy, hash) = domain_policy(&["a.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![
            FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 7), 300),
            FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 8), 300),
        ])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the first pass commits");
    // Partial rotation: X kept, Y dropped, Z added. Same policy hash, so
    // the old generation's obligation stays armed and unexpired.
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![
            FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 7), 300),
            FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 9), 300),
        ])],
    );
    // Only THIS pass's mutations count: pass 1 fenced X for the
    // first-ever issuance and released that fence at commit.
    fs::remove_file(&log).ok();
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the rotation commits");
    let adds = rule_adds_for(&log, "128.66.0.7/32");
    let allow_pos = adds.iter().rposition(|line| line.contains("action=allow"));
    let fence_pos = adds.iter().rposition(|line| {
        line.contains("action=reject")
            && line.contains("wssp-dns-quarantine-")
            && !line.contains("destination_port")
    });
    assert!(
        allow_pos.is_some(),
        "the rotation re-issued an allow for the kept destination: {}",
        adds.join("\n")
    );
    assert!(
        fence_pos.is_some_and(|fence| Some(fence) < allow_pos),
        "the retiring generation's group is not an authorization: the re-issued allow lands BEHIND a preventive fence: {}",
        adds.join("\n")
    );
    // Cleanup: withdraw everything and retire.
    fs::remove_file(&log).ok();
    let (policy_off, hash_off) = domain_policy(&[], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash_off);
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    loop {
        let egress = acl_egress(&log, &acl);
        let allows_left = ["128.66.0.7", "128.66.0.8", "128.66.0.9"]
            .iter()
            .any(|dest| {
                egress
                    .lines()
                    .any(|line| line.contains("action=allow") && line.contains(dest))
            });
        if !allows_left {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "all destinations withdrawn: {egress}"
        );
        let _ = refresh(&client, "sbx-1", &policy_off, &hash_off, &transport);
        std::thread::sleep(Duration::from_millis(500));
    }
    client.debug_reset_dns_lease_owner("sbx-1");
    let _ = statedir;
}

#[test]
fn issuance_revalidates_a_same_pass_authorizer_at_expiry() {
    // C36 r31 F1 (same-pass invalidation leg): the destination-only
    // `issued_this_pass` shortcut never re-checked the authorizing
    // grant's lifetime. D issues X behind A's live group; the pass then
    // stalls past BOTH A's and D's expiry (the authorizer's own fence is
    // long released — A authorized D, so D never fenced); Z's later
    // issuance for X still found X in the shortcut and issued with NO
    // fence. The expiry settlement's own fencing is stalled here, so the
    // discriminating observation is the PASS's fence: Z's allow must be
    // issued behind a preventive quarantine fence installed for Z's own
    // issuance. The gate now consults only surviving groups under
    // CURRENT expiry/revocation state, so the expired authorizers
    // (and the revoked stall domain) no longer legitimize Z.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let transport = FakeDnsTransport::new();
    let statedir = log.parent().expect("statedir").to_path_buf();
    let rule_adds_for = |log: &std::path::Path, needle: &str| -> Vec<String> {
        log_lines(log)
            .into_iter()
            .filter(|line| line.contains("network acl rule add") && line.contains(needle))
            .collect()
    };
    // Name order is add order: A (the pass-start authorizer, short TTL),
    // D (re-issues X this pass behind A, short TTL), M (the stall — its
    // fresh destination's fence add parks the pass past both expiries),
    // Z (re-issues X last).
    let (policy, hash) = domain_policy(
        &[
            "a.example.com",
            "d.example.com",
            "m.example.com",
            "z.example.com",
        ],
        &[],
    );
    bind_recorded_policy(&log, "sbx-1", &hash);
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            30,
        )])],
    );
    transport.script(
        "d.example.com",
        [FakeDnsOutcome::Answer(vec![
            FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 7), 30),
            FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 100), 30),
        ])],
    );
    transport.script(
        "m.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 102),
            300,
        )])],
    );
    transport.script(
        "z.example.com",
        [FakeDnsOutcome::Answer(vec![
            FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 7), 300),
            FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 101), 300),
        ])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the first pass commits");
    // Pass 2: A renews unchanged (no adds, no fence of its own); D and Z
    // rotate (fresh generations, so their X allows are fresh issuances);
    // M moves to a fresh destination. FENCE adds stall 35s apiece, so
    // M's preventive fence parks the pass past A's and D's expiry
    // (T0+30); M's grant-budgeted allow is then killed at the expired
    // deadline, revoking M and sweeping the expired A and D into the
    // pass's revocation set before Z's group is reached. The watcher's
    // own settlement fence for X is stalled by the same hook, so a fence
    // observed ahead of Z's allow can only be the PASS's. Scripted
    // outcomes are consumed per query: EVERY name is re-scripted (A
    // renews on the same answer).
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            30,
        )])],
    );
    transport.script(
        "d.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            30,
        )])],
    );
    transport.script(
        "m.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 103),
            300,
        )])],
    );
    transport.script(
        "z.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    fs::write(statedir.join("slow-acl-fence-add"), "35").unwrap();
    fs::remove_file(&log).ok();
    let pass_start = std::time::Instant::now();
    let _ = refresh(&client, "sbx-1", &policy, &hash, &transport);
    fs::remove_file(statedir.join("slow-acl-fence-add")).unwrap();
    assert!(
        pass_start.elapsed() >= Duration::from_secs(40),
        "the pass really stalled past the authorizers' expiry"
    );
    let adds = rule_adds_for(&log, "128.66.0.7/32");
    assert!(
        adds.iter()
            .filter(|line| line.contains("action=allow"))
            .count()
            >= 2,
        "D and Z both re-issued an allow for the shared destination: {}",
        adds.join("\n")
    );
    let allow_pos = adds.iter().rposition(|line| line.contains("action=allow"));
    let fence_pos = adds.iter().rposition(|line| {
        line.contains("action=reject")
            && line.contains("wssp-dns-quarantine-")
            && !line.contains("destination_port")
    });
    assert!(
        fence_pos.is_some_and(|fence| Some(fence) < allow_pos),
        "Z's allow issued BEHIND a preventive fence — its same-pass authorizer had expired: {}",
        adds.join("\n")
    );
    // Cleanup: withdraw everything and retire. Pass 2 failed with its
    // in-pass revocations journaled under THIS policy's hash — a refresh
    // under any other policy refuses to mutate while that marker stands.
    // Commit the denial under the SAME policy first (every scripted
    // outcome is consumed by now, so all four names NXDOMAIN): the commit
    // retires the marker and withdraws every grant directly.
    fs::remove_file(&log).ok();
    let deadline = std::time::Instant::now() + Duration::from_secs(180);
    loop {
        let egress = acl_egress(&log, &acl);
        let allows_left = [
            "128.66.0.7",
            "128.66.0.100",
            "128.66.0.101",
            "128.66.0.102",
            "128.66.0.103",
        ]
        .iter()
        .any(|dest| {
            egress
                .lines()
                .any(|line| line.contains("action=allow") && line.contains(dest))
        });
        if !allows_left {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "all destinations withdrawn: {egress}"
        );
        let _ = refresh(&client, "sbx-1", &policy, &hash, &transport);
        std::thread::sleep(Duration::from_millis(500));
    }
    let (policy_off, hash_off) = domain_policy(&[], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash_off);
    let _ = refresh(&client, "sbx-1", &policy_off, &hash_off, &transport);
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn the_watcher_enforces_a_recorded_denial_after_recoverys_probe_is_exhausted() {
    // C36 r31 F2: recorded revocations had no AUTONOMOUS enforcement —
    // recovery ran a single one-shot pass against the pass deadline, and
    // when the probe consumed that budget (or the withdrawal was
    // refused) the denied destination stayed reachable until the old
    // TTL expired. A durably journaled revocation is now an
    // immediately-due obligation in the lease boundary itself: the
    // watcher fences it BEFORE any observation and retries the
    // withdrawal until it proves out, with no further API call.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let transport = FakeDnsTransport::new();
    let statedir = log.parent().expect("statedir").to_path_buf();
    let (policy, hash) = domain_policy(&["a.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the grant commits");
    // The marker-only crash: the denial is journaled durably, the first
    // ACL mutation fails, and the daemon dies before any withdrawal.
    transport.script("a.example.com", [FakeDnsOutcome::Rcode(3)]);
    fs::write(statedir.join("fail-acl-rule-remove"), "").unwrap();
    refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect_err("the interrupted revocation leaves the marker");
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    assert!(marker_path.exists(), "the denial is journaled");
    let egress = acl_egress(&log, &acl);
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow") && line.contains("128.66.0.7")),
        "the crash left the denied allow installed: {egress}"
    );
    // RESTART with the daemon-side removal still refused AND every ACL
    // read parked: the recovery probe is killed at the pass deadline
    // having consumed the whole budget, and the refused withdrawal then
    // fails the recovery — but the pre-observation fence is already in
    // place and the watcher owns the retries.
    client.debug_reset_dns_lease_owner("sbx-1");
    fs::write(statedir.join("barrier-acl-read"), "0").unwrap();
    fs::remove_file(statedir.join("release-acl-read-barrier")).ok();
    let _ = client
        .recover_dns_expiry_obligations("sbx-1")
        .expect_err("recovery fails: the probe is exhausted and the withdrawal is refused");
    let _ = fs::remove_file(statedir.join("release-acl-read-barrier"));
    let egress = acl_egress(&log, &acl);
    assert!(
        lease_fence_present(&egress, "128.66.0.7/32"),
        "the denied destination was fenced BEFORE any observation: {egress}"
    );
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow") && line.contains("128.66.0.7")),
        "the refused withdrawal left the allow installed: {egress}"
    );
    // The daemon recovers; with NO further API call the watcher retries
    // and withdraws the denied identity.
    fs::remove_file(statedir.join("fail-acl-rule-remove")).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(90);
    loop {
        let egress = acl_egress(&log, &acl);
        if !egress
            .lines()
            .any(|line| line.contains("action=allow") && line.contains("128.66.0.7"))
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the watcher enforced the recorded denial autonomously: {egress}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    // Denial evidence is PRESERVED until a refresh commits it.
    let marker: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&marker_path).expect("the marker survives the autonomous enforcement"),
    )
    .expect("marker json");
    assert!(
        marker["revoked"]
            .as_array()
            .is_some_and(|names| names.iter().any(|name| name == "a.example.com")),
        "the denial evidence is preserved until commit: {marker}"
    );
    // A committing refresh retires the evidence.
    let _ = refresh(&client, "sbx-1", &policy, &hash, &transport);
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn denial_recovery_fences_only_an_uncovered_destination() {
    // C36 r31 F3: denial recovery passed `covered=false` unconditionally,
    // so a REFUSED withdrawal installed a destination-wide quarantine
    // even when a live sibling grant or the recorded static policy still
    // authorized the destination — startup recovery blocked traffic the
    // refresh/expiry paths preserve. The withdrawal boundary now derives
    // coverage from the verified non-revoked surviving groups and the
    // recorded static policy: only an UNCOVERED refused destination is
    // quarantined.
    let fence_of_any_family = |egress: &str, dest: &str| {
        egress.lines().any(|line| {
            line.contains("action=reject")
                && line.contains(&format!("destination={dest}"))
                && line.contains("quarantine-")
                && !line.contains("destination_port")
        })
    };

    // Leg 1 — a VERIFIED, unexpired, non-revoked sibling group covers the
    // destination: the refused withdrawal of the denied sibling must not
    // quarantine it.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let transport = FakeDnsTransport::new();
    let statedir = log.parent().expect("statedir").to_path_buf();
    let (policy, hash) = domain_policy(&["a.example.com", "b.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    for name in ["a.example.com", "b.example.com"] {
        transport.script(
            name,
            [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
                Ipv4Addr::new(128, 66, 0, 7),
                300,
            )])],
        );
    }
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("both grants commit");
    // Scripted outcomes are consumed per query: re-script BOTH names for
    // the denying pass (an empty queue answers NXDOMAIN — B must keep
    // resolving so only A is denied).
    transport.script("a.example.com", [FakeDnsOutcome::Rcode(3)]);
    transport.script(
        "b.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    fs::write(statedir.join("fail-acl-rule-remove"), "").unwrap();
    refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect_err("the interrupted denial leaves the marker");
    client.debug_reset_dns_lease_owner("sbx-1");
    let _ = client
        .recover_dns_expiry_obligations("sbx-1")
        .expect_err("the withdrawal is still refused");
    // The deny pass's own fence-first quarantine (REFRESH family) is the
    // denial's standing enforcement and is the next committing refresh's
    // to reconcile — the RECOVERY boundary's family is the lease fence.
    // While removals are refused the blind pre-observation fence cannot
    // be RELEASED either (a release is a removal), so a lease fence may
    // persist transiently — but the boundary must recognize the
    // coverage: neither allow is touched, and once removals recover the
    // lease fence is reconciled AWAY (a boundary that treated the
    // destination as uncovered would KEEP it as an unauthorized-survivor
    // quarantine behind the withdrawn identity).
    let settled = std::time::Instant::now() + Duration::from_secs(12);
    while std::time::Instant::now() < settled {
        std::thread::sleep(Duration::from_secs(3));
        let egress = acl_egress(&log, &acl);
        assert!(
            egress
                .lines()
                .filter(|line| line.contains("action=allow") && line.contains("128.66.0.7"))
                .count()
                == 2,
            "both allows survive the refused phase: {egress}"
        );
    }
    fs::remove_file(statedir.join("fail-acl-rule-remove")).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(90);
    loop {
        let egress = acl_egress(&log, &acl);
        let allows = egress
            .lines()
            .filter(|line| line.contains("action=allow") && line.contains("128.66.0.7"))
            .count();
        if allows == 1 && !lease_fence_present(&egress, "128.66.0.7/32") {
            // Only B's allow remains — A's was withdrawn and the
            // transient lease fence RELEASED behind the verified
            // coverage.
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the denied identity is withdrawn, the lease fence released, the sibling untouched: {egress}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    client.debug_reset_dns_lease_owner("sbx-1");

    // Leg 2 — the RECORDED STATIC POLICY covers the destination: same
    // refusal, and the RECOVERY boundary installs no fence of its own
    // (the deny pass's refresh-family quarantine is the denial's standing
    // enforcement, reconciled by the next committing refresh — only the
    // lease family is this boundary's to judge). (The plan record is
    // edited directly to carry the static grant: a dynamic allow for a
    // statically covered destination is otherwise never installed, so
    // the coverage change post-dates the grant.)
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let transport = FakeDnsTransport::new();
    let statedir = log.parent().expect("statedir").to_path_buf();
    let (policy, hash) = domain_policy(&["a.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the grant commits");
    let plan_path = statedir.join("host-state/network-plans/sbx-1.json");
    let mut plan: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&plan_path).expect("plan record"))
            .expect("plan json");
    plan["policy_cidrs"]
        .as_array_mut()
        .expect("policy_cidrs array")
        .push(serde_json::json!("128.66.0.7/32"));
    fs::write(&plan_path, plan.to_string()).unwrap();
    transport.script("a.example.com", [FakeDnsOutcome::Rcode(3)]);
    fs::write(statedir.join("fail-acl-rule-remove"), "").unwrap();
    refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect_err("the interrupted denial leaves the marker");
    client.debug_reset_dns_lease_owner("sbx-1");
    let _ = client
        .recover_dns_expiry_obligations("sbx-1")
        .expect_err("the withdrawal is still refused");
    let settled = std::time::Instant::now() + Duration::from_secs(12);
    while std::time::Instant::now() < settled {
        std::thread::sleep(Duration::from_secs(3));
        let egress = acl_egress(&log, &acl);
        assert!(
            !lease_fence_present(&egress, "128.66.0.7/32"),
            "a destination the recorded static policy authorizes is never lease-fenced: {egress}"
        );
    }
    fs::remove_file(statedir.join("fail-acl-rule-remove")).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(90);
    loop {
        let egress = acl_egress(&log, &acl);
        if !egress
            .lines()
            .any(|line| line.contains("action=allow") && line.contains("128.66.0.7"))
            && !lease_fence_present(&egress, "128.66.0.7/32")
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the denied identity is withdrawn, still without a lease fence: {egress}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    client.debug_reset_dns_lease_owner("sbx-1");

    // Leg 3 — NOTHING covers the destination: the refused withdrawal
    // must quarantine it (and keep it fenced) until the withdrawal
    // proves out.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let transport = FakeDnsTransport::new();
    let statedir = log.parent().expect("statedir").to_path_buf();
    let (policy, hash) = domain_policy(&["a.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the grant commits");
    transport.script("a.example.com", [FakeDnsOutcome::Rcode(3)]);
    fs::write(statedir.join("fail-acl-rule-remove"), "").unwrap();
    refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect_err("the interrupted denial leaves the marker");
    client.debug_reset_dns_lease_owner("sbx-1");
    let _ = client
        .recover_dns_expiry_obligations("sbx-1")
        .expect_err("the withdrawal is still refused");
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let egress = acl_egress(&log, &acl);
        if fence_of_any_family(&egress, "128.66.0.7/32") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "an uncovered refused destination is quarantined: {egress}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    let egress = acl_egress(&log, &acl);
    assert!(
        lease_fence_present(&egress, "128.66.0.7/32"),
        "the recovery boundary's own fence covers the refusal: {egress}"
    );
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow") && line.contains("128.66.0.7")),
        "the refused withdrawal left the allow installed behind the fence: {egress}"
    );
    fs::remove_file(statedir.join("fail-acl-rule-remove")).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(90);
    loop {
        let egress = acl_egress(&log, &acl);
        if !egress
            .lines()
            .any(|line| line.contains("action=allow") && line.contains("128.66.0.7"))
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the retried withdrawal completes: {egress}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn dns_recovery_never_adopts_another_projects_lease_ledger() {
    // C36 r32 F2: startup recovery enumerated every ledger in the shared
    // state root with no project binding: a network-isolated TENANT daemon
    // could adopt the default project's obligations, observe no ACL in its
    // own project, and purge the foreign ledger as "gone" — leaving the
    // owning daemon's running guest without its expiry watcher. Durable
    // DNS records and the owner identity are now project-bound, recovery
    // filters foreign ledgers BEFORE any activation, and a per-sandbox
    // recovery against a foreign ledger fails closed.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the grant commits");
    let statedir = log.parent().expect("statedir").to_path_buf();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    // The ledger is project-bound at write time.
    let ledger: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&obligations).expect("obligations"))
            .expect("obligations json");
    assert_eq!(
        ledger["project"].as_str(),
        Some("default"),
        "the durable ledger carries its owning project: {ledger}"
    );
    // The grant expired while the owning daemon was down.
    let mut expired = ledger.clone();
    let now = unix_now().expect("clock");
    for entry in expired["entries"].as_array_mut().expect("entries") {
        entry["expires_at"] = serde_json::json!(now);
    }
    fs::write(
        &obligations,
        serde_json::to_string_pretty(&expired).unwrap(),
    )
    .unwrap();
    let before = fs::read_to_string(&obligations).expect("ledger");
    // A tenant node daemon on the same Incus daemon, SHARING the state root,
    // runs startup recovery: the foreign ledger is left exactly as
    // found — never adopted, never purged — and its absence in the
    // tenant's own project is not an error.
    let mut tenant = legacy_client(
        statedir.join("incus").to_str().unwrap(),
        "tenant".to_string(),
    );
    tenant.state_dir = Some(statedir.join("host-state"));
    tenant
        .recover_all_dns_expiry_obligations()
        .expect("a foreign project's ledger is skipped, not a failure");
    assert_eq!(
        fs::read_to_string(&obligations).expect("the foreign ledger survives"),
        before,
        "the tenant's recovery leaves the foreign ledger byte-for-byte untouched"
    );
    // The per-sandbox entry point fails CLOSED on the foreign ledger.
    tenant
        .recover_dns_expiry_obligations("sbx-1")
        .expect_err("per-sandbox recovery of a foreign ledger fails closed");
    assert_eq!(
        fs::read_to_string(&obligations).expect("the foreign ledger survives"),
        before,
        "even the refusing path never mutates the foreign ledger"
    );
    // And nothing settled: the expired allow is still installed (only
    // the OWNING project may enforce its deadlines).
    std::thread::sleep(Duration::from_secs(3));
    let egress = acl_egress(&log, &acl);
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow") && line.contains("128.66.0.7")),
        "the tenant's recovery never settled the foreign obligation: {egress}"
    );
    assert_eq!(
        fs::read_to_string(&obligations).expect("the foreign ledger survives"),
        before,
        "the tenant never spawned a watcher that purged the ledger"
    );
    // Inverse: the OWNING project's recovery still activates and settles.
    client.debug_reset_dns_lease_owner("sbx-1");
    client
        .recover_all_dns_expiry_obligations()
        .expect("the owning project's recovery runs");
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let egress = acl_egress(&log, &acl);
        let allow_gone = !egress
            .lines()
            .any(|line| line.contains("action=allow") && line.contains("128.66.0.7"));
        if allow_gone && !obligations.exists() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the owning project settles its own expired grant: {egress}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn commit_drain_releases_a_pending_fence_only_behind_current_authorization() {
    // C36 r32 F3: the commit-time drain removed observed fence-release
    // rules on sight — no current-authorization check, no verified
    // replacement, no owner synchronization, no deadline. A pending
    // release could reach the drain while an older allow stayed
    // unresolved; once the temporary authorizer expired and replacement
    // fencing failed, the drain stripped the destination's remaining
    // protection and the deferred allow could land effective. The drain
    // now routes through the shared release boundary.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    let statedir = log.parent().expect("statedir").to_path_buf();
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    let marker_has_pending_release = |tag: &str| -> bool {
        fs::read_to_string(&marker_path)
            .unwrap_or_default()
            .contains(tag)
    };

    // Inverse first — STILL AUTHORIZED: an uncertain preventive-fence
    // release (deferred removal) stays journaled while the grant lives.
    fs::write(statedir.join("defer-acl-rule-remove"), "300").unwrap();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the grant commits");
    let fence_tag_7 = {
        let egress = acl_egress(&log, &acl);
        egress
            .lines()
            .find(|line| {
                line.contains("action=reject")
                    && line.contains("destination=128.66.0.7/32")
                    && line.contains("quarantine-")
                    && !line.contains("destination_port")
            })
            .and_then(|line| {
                line.split_whitespace()
                    .find(|field| field.starts_with("description="))
                    .map(str::to_string)
            })
            .expect("the preventive fence over the destination")
            .trim_start_matches("description=")
            .to_string()
    };
    assert!(
        marker_has_pending_release(&fence_tag_7),
        "the uncertain fence release stays journaled"
    );
    // An EXHAUSTED propagated deadline leaves the release pending —
    // the boundary never releases on an authorization it can no
    // longer re-verify within the deadline.
    let drained = client
        .drain_pending_mutations("sbx-1", &hash, &acl, Some(std::time::Instant::now()))
        .expect("an exhausted deadline is not an error");
    assert!(
        !drained.drained,
        "the exhausted deadline leaves the entry pending"
    );
    let egress = acl_egress(&log, &acl);
    assert!(
        egress.contains(&fence_tag_7),
        "an exhausted deadline never touches the fence: {egress}"
    );
    // Authorized release: the live grant covers the destination, the
    // removal proves out, and the fence goes.
    fs::remove_file(statedir.join("defer-acl-rule-remove")).unwrap();
    client
        .drain_pending_mutations("sbx-1", &hash, &acl, None)
        .expect("the authorized drain releases");
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains(&fence_tag_7),
        "a currently-authorized pending release completes: {egress}"
    );
    assert!(
        egress
            .lines()
            .any(|line| line.contains("action=allow") && line.contains("128.66.0.7")),
        "the authorized destination stays reachable through the release: {egress}"
    );

    // The expiry case: rotate to 128.66.0.8 with another uncertain
    // fence release, then let the authorizer EXPIRE. The expiry
    // settlement withdraws the allow and installs its own lease fence;
    // the pending refresh-fence release reaches the drain with NO
    // current authorization, and replacement fencing fails.
    fs::write(statedir.join("defer-acl-rule-remove"), "300").unwrap();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            45,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the rotation commits");
    fs::remove_file(statedir.join("defer-acl-rule-remove")).unwrap();
    let fence_tag_8 = {
        let egress = acl_egress(&log, &acl);
        egress
            .lines()
            .find(|line| {
                line.contains("action=reject")
                    && line.contains("destination=128.66.0.8/32")
                    && line.contains("quarantine-")
                    && !line.contains("destination_port")
            })
            .and_then(|line| {
                line.split_whitespace()
                    .find(|field| field.starts_with("description="))
                    .map(str::to_string)
            })
            .expect("the preventive fence over the rotated destination")
            .trim_start_matches("description=")
            .to_string()
    };
    assert!(
        marker_has_pending_release(&fence_tag_8),
        "the rotation's uncertain fence release stays journaled"
    );
    // Expire the authorizer and settle: the allow is withdrawn, the
    // lease installs its own fence, the authorization is GONE.
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    let mut ledger: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&obligations).expect("obligations"))
            .expect("obligations json");
    let now = unix_now().expect("clock");
    for entry in ledger["entries"].as_array_mut().expect("entries") {
        if entry["destinations"]
            .as_array()
            .is_some_and(|dests| dests.iter().any(|dest| dest == "128.66.0.8/32"))
        {
            entry["expires_at"] = serde_json::json!(now);
        }
    }
    fs::write(&obligations, serde_json::to_string_pretty(&ledger).unwrap()).unwrap();
    client.debug_reset_dns_lease_owner("sbx-1");
    client
        .recover_dns_expiry_obligations("sbx-1")
        .expect("the expiry settles");
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress
            .lines()
            .any(|line| line.contains("action=allow") && line.contains("128.66.0.8")),
        "the expired authorizer is withdrawn: {egress}"
    );
    assert!(
        fence_present(&egress, "128.66.0.8/32"),
        "the destination is NEVER unfenced — the expiry leaves a \
         destination-wide fence of either family (the still-standing \
         pending-release fence is adopted as that cover): {egress}"
    );
    assert!(
        egress.contains(&fence_tag_8),
        "the pending-release fence still stands before the drain: {egress}"
    );
    // The drain with NO current authorization and a FAILING
    // replacement: the old fence — the remaining protection against a
    // still-possible deferred apply — must NOT be removed.
    fs::write(statedir.join("fail-acl-fence-add"), "").unwrap();
    let drained = client
        .drain_pending_mutations("sbx-1", &hash, &acl, None)
        .expect("a failed replacement is not an error");
    assert!(!drained.drained, "the unauthorized release stays pending");
    let egress = acl_egress(&log, &acl);
    assert!(
        egress.contains(&fence_tag_8),
        "the drain never strips the remaining protection when the authorizer is \
         gone and the replacement fails: {egress}"
    );
    assert!(
        marker_has_pending_release(&fence_tag_8),
        "the entry stays journaled for retry"
    );
    // Recovery: with the replacement working again the drain installs a
    // verified replacement BEFORE removing the old identity.
    fs::remove_file(statedir.join("fail-acl-fence-add")).unwrap();
    client
        .drain_pending_mutations("sbx-1", &hash, &acl, None)
        .expect("the retried drain completes the replacement");
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains(&fence_tag_8),
        "the old identity retires behind its verified replacement: {egress}"
    );
    assert!(
        fence_present(&egress, "128.66.0.8/32"),
        "the destination is never left unfenced by the drain: {egress}"
    );
    client.debug_reset_dns_lease_owner("sbx-1");
}

/// The destination is REACHABLE: an enabled allow rule for it and no
/// destination-wide fence of either family covering it.
fn assert_dest_reachable(egress: &str, dest: &str) {
    assert!(
        egress.lines().any(|line| {
            line.contains("action=allow") && line.contains(&format!("destination={dest}"))
        }),
        "an enabled allow covers {dest}: {egress}"
    );
    assert!(
        !fence_present(egress, dest),
        "no fence of either family covers {dest}: {egress}"
    );
}

#[test]
fn reconcile_preserves_sibling_coverage_for_a_stale_pending_allow() {
    // C36 r32 F4: reconciliation withdrew a stale pending allow with
    // `covered = false` unconditionally, so a REFUSED withdrawal
    // installed a destination-wide refresh fence even when a complete
    // live sibling group still authorized the destination — blocking the
    // legitimate sibling. Coverage now derives through the shared
    // current-authorization predicate, excluding the identity being
    // withdrawn. The policy never changes here: one pass's issuance is
    // interrupted (deferred daemon-side), the retry commits fresh
    // identities, and the stale originals land afterwards.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com", "b.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    let statedir = log.parent().expect("statedir").to_path_buf();
    let answer = |t: &FakeDnsTransport| {
        t.script(
            "a.example.com",
            [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
                Ipv4Addr::new(128, 66, 0, 7),
                300,
            )])],
        );
        t.script(
            "b.example.com",
            [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
                Ipv4Addr::new(128, 66, 0, 7),
                300,
            )])],
        );
    };
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    // The interrupted pass: both allow adds are accepted daemon-side but
    // reported failed (queued; the test lands them after the retry) — both
    // grants are denied, fenced, and journaled pending.
    fs::write(
        statedir.join("defer-acl-allow-add-fail"),
        "queue 128.66.0.7",
    )
    .unwrap();
    answer(&transport);
    let outcome = refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("the interrupted pass completes with both grants denied");
    for name in ["a.example.com", "b.example.com"] {
        assert!(
            outcome.denied_names.contains(&name.to_string()),
            "{name} is denied while unresolved"
        );
    }
    let stale: Vec<String> = {
        let body = fs::read_to_string(&marker_path).expect("the pending mutations are journaled");
        let marker: serde_json::Value = serde_json::from_str(&body).expect("marker parses");
        marker["pending"]
            .as_array()
            .expect("pending entries")
            .iter()
            .filter(|entry| entry["kind"].as_str() == Some("Allow"))
            .map(|entry| entry["description"].as_str().expect("tag").to_string())
            .collect()
    };
    assert_eq!(stale.len(), 2, "both interrupted issuances are journaled");
    // The retry: fresh identities install and confirm; the fence
    // releases; the stale originals are still in flight.
    fs::remove_file(statedir.join("defer-acl-allow-add-fail")).unwrap();
    answer(&transport);
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the retry commits");
    let egress = acl_egress(&log, &acl);
    assert_dest_reachable(&egress, "128.66.0.7/32");
    // The stale applies land only now, after the retry committed (a fixed
    // +8 s delay landed them DURING the retry under load, which then saw an
    // unexplained extra allow): BOTH generations of each allow coexist.
    assert_eq!(apply_queued_acl_adds(&statedir), 2);
    let egress = acl_egress(&log, &acl);
    for tag in &stale {
        assert!(
            egress.contains(tag.as_str()),
            "the stale pending applies land daemon-side: {egress}"
        );
    }
    // The reconcile: the stale allows' withdrawal is REFUSED. Coverage
    // must keep the destination un-fenced — the live retry identities
    // still authorize it — and the stale entries stay journaled.
    fs::write(statedir.join("fail-acl-allow-remove"), "").unwrap();
    answer(&transport);
    let _ = refresh(&client, "sbx-1", &policy, &hash, &transport);
    let egress = acl_egress(&log, &acl);
    assert_dest_reachable(&egress, "128.66.0.7/32");
    for tag in &stale {
        assert!(
            egress.contains(tag.as_str()),
            "the refused withdrawal leaves the stale rule: {tag}"
        );
    }
    // With removals working again, the reconcile withdraws the stale
    // rules cleanly — still without ever fencing the covered
    // destination.
    fs::remove_file(statedir.join("fail-acl-allow-remove")).unwrap();
    answer(&transport);
    refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("the reconciling pass withdraws the stale rules");
    let egress = acl_egress(&log, &acl);
    assert_dest_reachable(&egress, "128.66.0.7/32");
    for tag in &stale {
        assert!(
            !egress.contains(tag.as_str()),
            "the stale rule is withdrawn: {tag}"
        );
    }
    assert!(
        !marker_path.exists(),
        "the journal retires once every mutation is resolved"
    );
    // Cleanup: policy off commits the withdrawal of everything.
    let (policy_off, hash_off) = domain_policy(&[], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash_off);
    let deadline = std::time::Instant::now() + Duration::from_secs(150);
    loop {
        let _ = refresh(&client, "sbx-1", &policy_off, &hash_off, &transport);
        let egress = acl_egress(&log, &acl);
        if !egress.contains("128.66.0.7") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "everything retires: {egress}"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn a_drain_succeeded_fence_release_commits_and_clears_the_marker() {
    // C36 r33 F2: the preventive fence's ensured release fails
    // uncertainly ONCE (the daemon may or may not have applied the
    // removal); the commit-time drain's retry then succeeds. The commit
    // must fold the drain's PROVEN removal into its expected snapshot —
    // pre-fix the fence was still in `installed`, so its disappearance
    // at the live re-read was rejected as unexplained rule loss (a
    // journaled fence withdrawal produces none of the allow-withdrawal
    // evidence the commit checks) and the journaled entry was never
    // retired, so the marker could never clear.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    let statedir = log.parent().expect("statedir").to_path_buf();
    fs::write(statedir.join("fail-acl-fence-remove-once"), "").unwrap();
    let outcome = refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("the refresh commits: the drain's proven release is carried into the snapshot");
    assert!(outcome.denied_names.is_empty(), "nothing denied");
    let egress = acl_egress(&log, &acl);
    assert!(
        egress.contains("action=allow destination=128.66.0.7/32"),
        "the grant is installed: {egress}"
    );
    assert!(
        !fence_present(&egress, "128.66.0.7/32"),
        "the drain-released fence is gone: {egress}"
    );
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    assert!(
        !marker_path.exists(),
        "the drained entry retires at the drain and the marker clears"
    );
    // Readiness: the persisted plan records exactly the live rules and a
    // follow-up refresh is clean.
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    let outcome = refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("the follow-up refresh is clean");
    assert!(outcome.denied_names.is_empty(), "nothing denied");
    let egress = acl_egress(&log, &acl);
    assert!(
        egress.contains("action=allow destination=128.66.0.7/32")
            && !fence_present(&egress, "128.66.0.7/32"),
        "steady state: authorized destination, no fence: {egress}"
    );
    assert!(
        !marker_path.exists(),
        "the marker stays cleared across the follow-up refresh"
    );

    // --- C36 r34 F1: the full P1 sequence. Interrupted denial, re-grant,
    // a drain that must treat the FRESH generation as authorized, and an
    // actual readiness verification of the committed result. ---

    // Phase B: interrupt an NXDOMAIN refresh AFTER the withdrawal but
    // BEFORE the publication. The revocation marker retains the denial
    // (name plus outstanding generation), the allow is gone, nothing
    // committed.
    transport.script("a.example.com", [FakeDnsOutcome::Rcode(3)]);
    fs::write(statedir.join("fail-raw-dnsmasq"), "").unwrap();
    let err = refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect_err("the denial refresh is interrupted at the publish");
    assert_ne!(err.code, SandboxErrorCode::ProtocolError);
    fs::remove_file(statedir.join("fail-raw-dnsmasq")).unwrap();
    let marker_body =
        fs::read_to_string(&marker_path).expect("the interrupted denial is journaled");
    assert!(
        marker_body.contains("a.example.com"),
        "the revocation is journaled: {marker_body}"
    );
    assert!(
        !acl_egress(&log, &acl).contains("action=allow destination=128.66.0.7/32"),
        "the withdrawal applied before the interruption: {}",
        acl_egress(&log, &acl)
    );
    // The refresh's own withdrawal already proved out, so the watcher
    // has nothing to settle — the re-grant starts from a quiesced ACL
    // carrying only the journaled denial.

    // Phase C: re-grant. The fresh generation's fence release fails
    // ONCE, so the commit-time drain retries it. Pre-fix, the drain's
    // authorization vetoed by NAME — the retained revocation made the
    // fresh generation look denied, the drain installed a replacement
    // fence the commit never learned about, the destination stayed
    // fenced, and the persisted plan silently omitted the live fence so
    // readiness verification failed forever. Post-fix the drain's
    // generation-exact authorization proves the fresh generation,
    // removes the fence, and the commit reconciles.
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    fs::write(statedir.join("fail-acl-fence-remove-once"), "").unwrap();
    let outcome = refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("the re-grant commits: the fresh generation authorizes the drain's release");
    assert!(outcome.denied_names.is_empty(), "nothing denied");
    assert!(
        !marker_path.exists(),
        "the drained release retires and the marker clears"
    );
    // The destination converges to reachable with NO fence (any
    // watcher-installed lease fence is released once the fresh
    // generation authorizes it).
    let converge_deadline = std::time::Instant::now() + Duration::from_secs(120);
    loop {
        let egress = acl_egress(&log, &acl);
        if egress.contains("action=allow destination=128.66.0.7/32")
            && !fence_present(&egress, "128.66.0.7/32")
        {
            break;
        }
        assert!(
            std::time::Instant::now() < converge_deadline,
            "the re-granted destination is reachable and unfenced: {egress}"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    // ACTUAL readiness: the persisted plan must equal the live ACL —
    // the exact verification a reconnect runs. Pre-fix this refused the
    // sandbox forever because the drain-installed fence was live but
    // absent from the plan (and here also because the destination
    // stayed fenced).
    let readiness_deadline = std::time::Instant::now() + Duration::from_secs(120);
    loop {
        match client.verify_sandbox_network(&test_plan("sbx-1")) {
            Ok(()) => break,
            Err(err) => {
                assert!(
                    std::time::Instant::now() < readiness_deadline,
                    "readiness verifies after the re-grant commit: {err}"
                );
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    }

    // Cleanup: policy off commits the withdrawal of everything.
    let (policy_off, hash_off) = domain_policy(&[], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash_off);
    let deadline = std::time::Instant::now() + Duration::from_secs(150);
    loop {
        let _ = refresh(&client, "sbx-1", &policy_off, &hash_off, &transport);
        let egress = acl_egress(&log, &acl);
        if !egress.contains("128.66.0.7") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "everything retires: {egress}"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn a_stalled_reconcile_release_yields_the_owner_lock_for_an_expiry() {
    // C36 r33 F1: reconciliation retried a journaled fence release with
    // NO deadline, holding the lease-owner state lock across the stalled
    // removal under the plain 120s host timeout. While it stalled, an
    // UNRELATED grant expired — its watcher needs the same lock to
    // install the expiry fence, so the destination stayed reachable past
    // its lifetime. The release boundary now derives ONE absolute
    // deadline from the caller's deadline and every armed expiry, and
    // yields at the earliest of the two.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com", "b.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    let script_ab = |transport: &FakeDnsTransport, b: FakeDnsOutcome| {
        transport.script(
            "a.example.com",
            [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
                Ipv4Addr::new(128, 66, 0, 7),
                300,
            )])],
        );
        transport.script("b.example.com", [b]);
    };
    // Pass 1: both grants install; BOTH preventive-fence releases are
    // uncertain (deferred, failing removals) → journaled FenceReleases.
    script_ab(
        &transport,
        FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 8), 30)]),
    );
    let statedir = log.parent().expect("statedir").to_path_buf();
    fs::write(statedir.join("defer-acl-rule-remove"), "300").unwrap();
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the grant pass commits");
    fs::remove_file(statedir.join("defer-acl-rule-remove")).unwrap();
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    let marker_body = fs::read_to_string(&marker_path).expect("the marker");
    assert!(
        marker_body.matches("FenceRelease").count() == 2,
        "both uncertain fence releases are journaled: {marker_body}"
    );
    // The fence tag installed over a's destination.
    let tag_7: String = {
        let egress = acl_egress(&log, &acl);
        egress
            .lines()
            .find(|line| {
                line.contains("action=reject")
                    && line.contains("destination=128.66.0.7/32")
                    && line.contains("quarantine-")
                    && !line.contains("destination_port")
            })
            .and_then(|line| {
                line.split_whitespace()
                    .find(|field| field.starts_with("description="))
                    .map(str::to_string)
            })
            .expect("the preventive fence over 128.66.0.7")
            .trim_start_matches("description=")
            .to_string()
    };
    let marker_body = fs::read_to_string(&marker_path).expect("the marker");
    assert!(
        marker_body.contains(&format!("\"description\":\"{tag_7}\"")),
        "a's uncertain fence release is journaled: {marker_body}"
    );
    // Pass 2: every release attempt on a's fence fails uncertainly
    // (reconcile retry, plan-phase release, commit-time drain) so it
    // stays journaled, while b's release succeeds — 128.66.0.8 is left
    // UNFENCED for its coming expiry.
    fs::write(statedir.join("fail-acl-fence-remove-tag"), &tag_7).unwrap();
    script_ab(
        &transport,
        FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 8), 30)]),
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the renewal pass commits");
    fs::remove_file(statedir.join("fail-acl-fence-remove-tag")).unwrap();
    let marker_body = fs::read_to_string(&marker_path).expect("the marker");
    assert!(
        marker_body.contains(&tag_7) && !marker_body.contains("128.66.0.8"),
        "only a's release stays journaled: {marker_body}"
    );
    let egress = acl_egress(&log, &acl);
    assert!(
        egress.contains("action=allow destination=128.66.0.8/32")
            && !fence_present(&egress, "128.66.0.8/32"),
        "b's destination is live and unfenced before its expiry: {egress}"
    );
    let b_expiry = std::time::Instant::now() + Duration::from_secs(30);
    // Pass 3 (thread): a's journaled release retry parks on the barrier
    // WHILE HOLDING the owner lock; b's answer vanishes.
    fs::write(statedir.join("barrier-acl-fence-remove"), &tag_7).unwrap();
    let thread_transport = std::sync::Arc::new(FakeDnsTransport::new());
    script_ab(&thread_transport, FakeDnsOutcome::Rcode(3));
    let thread_client = client.clone();
    let thread_policy = policy.clone();
    let thread_hash = hash.clone();
    let thread_servers = servers();
    let renew = std::thread::spawn({
        let thread_transport = thread_transport.clone();
        move || {
            thread_client.refresh_sandbox_dns_policy(
                "sbx-1",
                &thread_policy,
                &thread_hash,
                thread_transport.as_ref(),
                &thread_servers,
            )
        }
    });
    // b's expiry must still be enforced on time: the stalled release
    // hits its armed-expiry deadline (b's ~30s), yields the lock, and
    // 128.66.0.8 becomes UNREACHABLE — either the watcher wins the race
    // and fences it, or the refresh thread's own NXDOMAIN revocation
    // withdraws its allow first (deny-default then blocks it). Both are
    // the enforced outcome; what must never happen is the destination
    // staying reachable past its lease while the reconcile stalls.
    let fence_deadline = std::time::Instant::now() + Duration::from_secs(75);
    loop {
        let egress = acl_egress(&log, &acl);
        if fence_present(&egress, "128.66.0.8/32")
            || !egress.contains("action=allow destination=128.66.0.8/32")
        {
            break;
        }
        assert!(
            std::time::Instant::now() < fence_deadline,
            "b's expiry is enforced on time despite the stalled reconcile release: {egress}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    assert!(
        std::time::Instant::now() < b_expiry + Duration::from_secs(45),
        "the enforcement lands at the armed expiry, not at the barrier cap"
    );
    // Releasing the barrier lets the refresh thread's remaining work
    // finish (b is revoked by the NXDOMAIN re-resolution).
    fs::remove_file(statedir.join("barrier-acl-fence-remove")).unwrap();
    fs::write(statedir.join("release-fence-barrier"), "").unwrap();
    let outcome = renew
        .join()
        .expect("the refresh thread joins")
        .expect("the refresh completes once the daemon behaves");
    assert!(
        outcome.denied_names.contains(&"b.example.com".to_string()),
        "the vanished name is revoked: {:?}",
        outcome.denied_names
    );
    // Inverse: once the daemon behaves, the journaled release completes
    // and a's fence is gone.
    let deadline = std::time::Instant::now() + Duration::from_secs(150);
    loop {
        script_ab(&transport, FakeDnsOutcome::Rcode(3));
        let _ = refresh(&client, "sbx-1", &policy, &hash, &transport);
        let egress = acl_egress(&log, &acl);
        if !fence_present(&egress, "128.66.0.7/32")
            && egress.contains("action=allow destination=128.66.0.7/32")
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the journaled release completes once the daemon behaves: {egress}"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    // Cleanup: policy off commits the withdrawal of everything.
    let (policy_off, hash_off) = domain_policy(&[], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash_off);
    let deadline = std::time::Instant::now() + Duration::from_secs(150);
    loop {
        let _ = refresh(&client, "sbx-1", &policy_off, &hash_off, &transport);
        let egress = acl_egress(&log, &acl);
        if !egress.contains("128.66.0.7") && !egress.contains("128.66.0.8") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "everything retires: {egress}"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn a_drain_installed_replacement_fence_enters_the_committed_plan() {
    // C36 r34 F1 (the persisted-plan half of the P1 sequence): a fence
    // release journaled against a destination that is LATER revoked is
    // drained unauthorized — the boundary installs a verified
    // replacement fence and removes the old one. The commit must fold
    // BOTH directions into its expected snapshot; pre-fix only the
    // removal was explained, so the live replacement fence was silently
    // dropped from the persisted plan and every reconnect verification
    // would refuse the sandbox.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    let statedir = log.parent().expect("statedir").to_path_buf();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the grant commits");

    // Rotate .7 -> .8 with EVERY rule removal deferred: the preventive
    // fence's ensured release is deferred (journaled FenceRelease), the
    // drain's retry is deferred too, and the old address group stays
    // installed past the pass.
    fs::write(statedir.join("defer-acl-rule-remove"), "300").unwrap();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("the rotation commits with the release journaled");
    let egress = acl_egress(&log, &acl);
    assert!(
        egress
            .lines()
            .any(|line| line.contains("quarantine-") && line.contains("destination=128.66.0.8/32")),
        "the preventive fence is still installed: {egress}"
    );
    let marker_path = statedir.join("host-state/dns-revocations/sbx-1.json");
    assert!(marker_path.exists(), "the deferred release stays journaled");

    // The revoking refresh: `a` NXDOMAINs. The drain retries the
    // journaled release against a REVOKED destination — unauthorized —
    // so it installs a verified replacement fence (fresh epoch) before
    // the old one's (deferred, unproven) removal.
    transport.script("a.example.com", [FakeDnsOutcome::Rcode(3)]);
    let outcome =
        refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the revocation commits");
    assert_eq!(outcome.denied_names, vec!["a.example.com".to_string()]);
    let egress = acl_egress(&log, &acl);
    let live_fences: BTreeSet<String> = egress
        .lines()
        .filter(|line| line.contains("quarantine-") && line.contains("destination=128.66.0.8/32"))
        .filter_map(|line| {
            line.split_whitespace()
                .find_map(|token| token.strip_prefix("description="))
        })
        .map(str::to_string)
        .collect();
    // The original fence's removal stays deferred, so it is still live;
    // the reconcile and the commit-time drain each installed a fresh
    // replacement around it (the destination is revoked — an
    // unauthorized release must replace, never bare-remove).
    assert!(
        live_fences.len() >= 2,
        "fresh replacement fences cover the revoked destination: {egress}"
    );

    // THE assertion: EVERY fence live on the destination is named by the
    // committed plan — including the one the COMMIT-TIME drain installed
    // after the pass's observation (pre-fix the commit carried only the
    // drain's REMOVALS, so a replacement installed between the
    // observation and the commit's live re-read was silently filtered
    // out of the persisted rules and every reconnect verification would
    // refuse the sandbox). Asserting one opportune tag is not enough:
    // an earlier replacement can enter the plan through the NEXT pass's
    // observation while the final drain's addition is dropped.
    let plan_path = statedir.join("host-state/network-plans").join("sbx-1.json");
    let plan_body = fs::read_to_string(&plan_path).expect("the committed plan record");
    let plan_rules: serde_json::Value = serde_json::from_str(&plan_body).expect("plan json");
    let planned: BTreeSet<String> = plan_rules["rules"]
        .as_array()
        .expect("plan rules")
        .iter()
        .filter_map(|rule| rule["description"].as_str().map(str::to_string))
        .collect();
    let unnamed: Vec<&String> = live_fences
        .iter()
        .filter(|tag| !planned.contains(*tag))
        .collect();
    assert!(
        unnamed.is_empty(),
        "the committed plan names every live fence (unnamed: {unnamed:?}): {plan_body}"
    );

    fs::remove_file(statedir.join("defer-acl-rule-remove")).unwrap();
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn a_journaled_fence_release_never_mutates_a_foreign_acl() {
    // C36 r34 F2 (release direction): the journaled fence-release
    // boundary reads the ACL but pre-fix never validated the
    // sandbox/project tags — a same-named ACL retagged to ANOTHER
    // sandbox would receive the replacement-fence ADD and the rule
    // REMOVAL. The boundary now refuses before either mutation.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    let statedir = log.parent().expect("statedir").to_path_buf();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the grant commits");

    // Journal a fence release that survives its own pass (deferred
    // removal), exactly like `a_drain_installed_replacement_fence_...`.
    fs::write(statedir.join("defer-acl-rule-remove"), "300").unwrap();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("the rotation commits with the release journaled");
    let egress_before = acl_egress(&log, &acl);
    assert!(
        fence_present(&egress_before, "128.66.0.8/32"),
        "the journaled fence is installed: {egress_before}"
    );

    // Retag the ACL to a FOREIGN sandbox (the same-named replacement /
    // retag window the finding describes) and refresh again: the
    // journaled release must refuse ownership BEFORE any mutation.
    let conf_path = statedir.join("acls").join(format!("{acl}.conf"));
    let mut conf = fs::read_to_string(&conf_path).expect("acl conf");
    conf.push_str("user.wssp.sandbox_id=foreign-sandbox\n");
    fs::write(&conf_path, &conf).unwrap();
    let err = refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect_err("the release boundary refuses a foreign ACL");
    assert_eq!(err.code, SandboxErrorCode::IdempotencyConflict);
    // ZERO adds and removals: byte-identical egress.
    assert_eq!(
        acl_egress(&log, &acl),
        egress_before,
        "not one rule was added to or removed from the foreign ACL"
    );

    // Healthy inverse: restore the ownership tag, drop the deferral;
    // the very next refresh reconciles the journaled release and
    // converges.
    let conf = conf.replace("user.wssp.sandbox_id=foreign-sandbox\n", "");
    fs::write(&conf_path, &conf).unwrap();
    fs::remove_file(statedir.join("defer-acl-rule-remove")).unwrap();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            300,
        )])],
    );
    let outcome = refresh(&client, "sbx-1", &policy, &hash, &transport)
        .expect("the healthy release converges once ownership is restored");
    assert!(outcome.denied_names.is_empty());
    let egress = acl_egress(&log, &acl);
    assert!(
        egress.contains("action=allow destination=128.66.0.8/32")
            && !fence_present(&egress, "128.66.0.8/32"),
        "the fence released behind current authorization: {egress}"
    );
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn a_blind_prefence_never_mutates_a_foreign_acl() {
    // C36 r34 F2 (pre-fence direction): recovery with an overdue owned
    // ledger blind-fences the expired destination — pre-fix without ANY
    // ownership check, so a same-named retagged ACL received reject
    // rules from another sandbox's lease obligations. The boundary now
    // proves ownership from the read before the add; a successful read
    // showing foreign tags vetoes the pass with ZERO mutations.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            2,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the short grant commits");
    let egress_before = acl_egress(&log, &acl);
    assert!(
        egress_before.contains("action=allow destination=128.66.0.7/32"),
        "the grant is installed: {egress_before}"
    );

    // Retag the ACL foreign, then force the lease OVERDUE — the TTL
    // churn floor (~30s) would otherwise keep the entry live past the
    // observation window and the pre-fence boundary would never be
    // reached at all (the window must contain a DUE tick to prove
    // anything). Recovery is driven explicitly: every readiness check
    // runs it, so each loop iteration reaches the pre-fence boundary
    // (a vetoed pass caches nothing, so the boundary re-fires).
    let conf_path = log
        .parent()
        .expect("statedir")
        .join("acls")
        .join(format!("{acl}.conf"));
    let statedir = log.parent().expect("statedir").to_path_buf();
    let mut conf = fs::read_to_string(&conf_path).expect("acl conf");
    conf.push_str("user.wssp.sandbox_id=foreign-sandbox\n");
    fs::write(&conf_path, &conf).unwrap();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    let mut ledger: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&obligations).expect("obligations"))
            .expect("obligations json");
    let now = unix_now().expect("now");
    for entry in ledger["entries"].as_array_mut().expect("entries") {
        entry["expires_at"] = serde_json::json!(now);
    }
    fs::write(&obligations, serde_json::to_string_pretty(&ledger).unwrap()).unwrap();
    client.debug_reset_dns_lease_owner("sbx-1");
    // Recovery's pre-fence and settle must both refuse the foreign ACL —
    // no fence is added, the foreign allow is not removed (enforcement
    // is delayed, never misdirected).
    let observe_deadline = std::time::Instant::now() + Duration::from_secs(12);
    while std::time::Instant::now() < observe_deadline {
        let _ = client.verify_provisioned_enforcement("sbx-1");
        let egress = acl_egress(&log, &acl);
        assert_eq!(
            egress, egress_before,
            "no fence added and no rule removed on the foreign ACL past expiry: {egress}"
        );
        std::thread::sleep(Duration::from_millis(500));
    }

    // Healthy inverse: restore ownership and recovery enforces the
    // overdue lease on the owned ACL — the expired allow is withdrawn
    // through the enforced boundary (a clean expiry then also withdraws
    // its own deadline fence, so the secure end state is "allow gone";
    // a transient fence is fine).
    let conf = conf.replace("user.wssp.sandbox_id=foreign-sandbox\n", "");
    fs::write(&conf_path, &conf).unwrap();
    let enforce_deadline = std::time::Instant::now() + Duration::from_secs(120);
    loop {
        let _ = client.verify_provisioned_enforcement("sbx-1");
        let egress = acl_egress(&log, &acl);
        if !egress.contains("action=allow destination=128.66.0.7/32") {
            break;
        }
        assert!(
            std::time::Instant::now() < enforce_deadline,
            "the overdue lease withdraws once ownership is restored: {egress}"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn the_prefence_cache_stays_bounded_across_rotation_and_settlement() {
    // C36 r34 F4: the pre-fence cache prunes to currently-armed
    // (identity, destination, expiry) triples, so repeated
    // rotation-and-settlement rounds never accumulate retired tuples —
    // the cache is bounded by the armed ledger, not lifetime traffic.
    // Round k's fence must leave exactly ONE cached triple, never k.
    let (mut client, log) = applied_client("running", "sbx-1");
    let clock = DnsTestClock::install(&mut client);
    let (fenced_tx, fenced_rx) = std::sync::mpsc::channel();
    client.dns_prefence_hook = Some(super::client::TestDnsPrefenceHook(std::sync::Arc::new(
        move |cached| {
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            fenced_tx
                .send((cached, release_tx))
                .expect("report pre-fence");
            release_rx
                .recv_timeout(Duration::from_secs(120))
                .expect("release pre-fence observation");
        },
    )));
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    let addrs = [
        Ipv4Addr::new(128, 66, 0, 7),
        Ipv4Addr::new(128, 66, 0, 8),
        Ipv4Addr::new(128, 66, 0, 9),
    ];
    for (round, addr) in addrs.iter().enumerate() {
        transport.script(
            "a.example.com",
            [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(*addr, 2)])],
        );
        refresh(&client, "sbx-1", &policy, &hash, &transport)
            .unwrap_or_else(|err| panic!("round {round} grant commits: {err}"));
        // Expire only after refresh commits: wall-clock load must not
        // consume the grant before the test starts observing it. TTL 2
        // is clamped to the production minimum of 30 seconds.
        client.debug_advance_dns_lease_clock("sbx-1", || {
            clock.advance(u64::from(super::dns::MIN_REFRESH_TTL_SECS));
        });
        // Hold the worker AFTER the successful blind fence/cache update,
        // BEFORE settlement. Polling a transient live ACL can miss the
        // entire install/withdraw/release cycle. The hook reports the
        // cache size while holding the owner lock; re-locking it here
        // would deadlock instead of observing the pre-settlement bound.
        let dest = format!("{addr}/32");
        let (cached, release) = fenced_rx
            .recv_timeout(Duration::from_secs(120))
            .unwrap_or_else(|err| {
                panic!("round {round}: the expired destination is fenced: {err}")
            });
        let egress = acl_egress(&log, &acl);
        assert!(
            fence_present(&egress, &dest),
            "round {round}: the expired destination is fenced: {egress}"
        );
        assert!(
            egress.contains(&format!("action=allow destination={dest}")),
            "round {round}: the fence precedes allow withdrawal: {egress}"
        );
        assert_eq!(
            cached, 1,
            "round {round}: exactly the armed triple is cached; retired rounds must not accumulate"
        );
        release.send(()).expect("resume settlement");
        // Let the settle retire the armed entry before the next round.
        let settle_deadline = std::time::Instant::now() + Duration::from_secs(120);
        loop {
            let egress = acl_egress(&log, &acl);
            if !egress.contains(&format!("action=allow destination={dest}")) {
                break;
            }
            assert!(
                std::time::Instant::now() < settle_deadline,
                "round {round}: the expired allow withdraws: {egress}"
            );
            std::thread::sleep(Duration::from_millis(250));
        }
        // The live allow disappears before the settlement commit retires
        // its armed entry. Taking the owner lock waits for that commit.
        assert!(client.debug_prefenced_cache_len("sbx-1") <= 1);
    }
    // Steady state after the final settlement: at most the last pass's
    // own triple remains cached — the prune runs at the head of every
    // pre-fence pass, so a fully settled sandbox with a stopped watcher
    // may carry ONE leftover that the next pass drops. What must never
    // happen is accumulation across rounds (asserted per round above).
    assert!(
        client.debug_prefenced_cache_len("sbx-1") <= 1,
        "the cache is bounded by the last armed set, not lifetime traffic"
    );
    client.debug_reset_dns_lease_owner("sbx-1");
}

/// C36 r35 F1 shared scripting helpers: the fake transport CONSUMES
/// one scripted outcome per query (A, then AAAA — the second falls back
/// to NXDOMAIN), so every name in the policy must be re-scripted before
/// every refresh.
fn r35_answer(transport: &FakeDnsTransport, name: &str, addr: Ipv4Addr) {
    transport.script(
        name,
        [
            FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(addr, 300)]),
            FakeDnsOutcome::Rcode(3),
        ],
    );
}

fn r35_nxdomain(transport: &FakeDnsTransport, name: &str) {
    transport.script(name, [FakeDnsOutcome::Rcode(3), FakeDnsOutcome::Rcode(3)]);
}

/// Grant a (.7) and b (.8) (and c (.9) when the policy carries it),
/// then revoke `a` CLEANLY — the withdrawal proves out and its evidence
/// is durable, so the pair is quiet for every later due check. That is
/// the deterministic stand-in for the r34 orphan window (a blind
/// pre-fence installed between the revocation journal and the durable
/// proof): `debug_settle_dns_lease_with_blind_fences` then installs the
/// blind fence exactly as the watcher's pre-observation pass would and
/// runs the REAL settle with it.
fn r35_grant_and_revoke(
    client: &IncusClient,
    policy: &EgressPolicy,
    hash: &str,
    transport: &FakeDnsTransport,
) {
    r35_answer(transport, "a.example.com", Ipv4Addr::new(128, 66, 0, 7));
    r35_answer(transport, "b.example.com", Ipv4Addr::new(128, 66, 0, 8));
    r35_answer(transport, "c.example.com", Ipv4Addr::new(128, 66, 0, 9));
    refresh(client, "sbx-1", policy, hash, transport).expect("grants commit");
    r35_nxdomain(transport, "a.example.com");
    r35_answer(transport, "b.example.com", Ipv4Addr::new(128, 66, 0, 8));
    r35_answer(transport, "c.example.com", Ipv4Addr::new(128, 66, 0, 9));
    refresh(client, "sbx-1", policy, hash, transport).expect("the revocation commits");
}

/// Rewrite `name`'s armed expiry to `now + in_secs` and reload the owner
/// (a restart finding a nearly-due ledger), returning the deadline as an
/// Instant measured from the ledger write.
fn r35_expire_grant_in(
    statedir: &Path,
    client: &IncusClient,
    name: &str,
    in_secs: u64,
) -> std::time::Instant {
    let obligations = lease_obligations_path(statedir, "sbx-1");
    let mut ledger: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&obligations).expect("obligations"))
            .expect("obligations json");
    let now = client.dns_clock.unix_now().expect("clock");
    for entry in ledger["entries"].as_array_mut().expect("entries") {
        if entry["name"].as_str() == Some(name) {
            entry["expires_at"] = serde_json::json!(now + in_secs);
        }
    }
    fs::write(&obligations, serde_json::to_string_pretty(&ledger).unwrap()).unwrap();
    let expiry = std::time::Instant::now() + Duration::from_secs(in_secs);
    client.debug_reset_dns_lease_owner("sbx-1");
    client
        .recover_dns_expiry_obligations("sbx-1")
        .expect("recovery reloads the ledger");
    expiry
}

#[test]
fn a_stalled_orphan_sweep_read_cannot_delay_the_next_expiry() {
    // C36 r35 F1 (stalled READ): the orphan-fence sweep runs under the
    // lease-owner lock, so its observation must share ONE absolute
    // deadline with the next armed expiry — a fresh 5s read budget
    // would let a stalled sweep delay the fencing of a grant expiring
    // mid-sweep. At the deadline the sweep stops and deadline fencing
    // resumes; the unswept orphan stays installed (over-denial) for a
    // later settle.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com", "b.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    r35_grant_and_revoke(&client, &policy, &hash, &transport);
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("action=allow destination=128.66.0.7/32"),
        "a revoked cleanly: {egress}"
    );
    assert!(
        egress.contains("action=allow destination=128.66.0.8/32"),
        "b survives a's revocation: {egress}"
    );
    let statedir = log.parent().expect("statedir").to_path_buf();
    // b expires 3s from the ledger write — DURING the stalled sweep
    // read (a fresh 5s budget would outlast it; the remaining budget
    // does not).
    let expiry = r35_expire_grant_in(&statedir, &client, "b.example.com", 3);
    // Park the settle's SECOND ACL read: the first is the round's
    // coverage snapshot, the second is the sweep's own observation.
    fs::write(statedir.join("barrier-acl-read"), "1").unwrap();
    fs::remove_file(statedir.join("release-acl-read-barrier")).ok();
    // The settle runs CONCURRENTLY: the assertion must observe the
    // fencing deadline while the stalled sweep read still holds the
    // owner lock — polling only after the call returns could not see
    // WHEN the fence landed.
    let settle_client = client.clone();
    let settle = std::thread::spawn(move || {
        settle_client.debug_settle_dns_lease_with_blind_fences("sbx-1", &["128.66.0.7/32"])
    });
    // THE boundary assertion: b is fenced at its own deadline — the
    // stalled sweep read was killed at the remaining budget, and the
    // settle resumed deadline fencing before finishing cleanup. Pre-fix
    // the read held the lock for a fresh 5s — past expiry + 1.5s.
    let deadline = expiry + Duration::from_millis(1500);
    loop {
        let egress = acl_egress(&log, &acl);
        if lease_fence_present(&egress, "128.66.0.8/32") {
            break;
        }
        if std::time::Instant::now() >= deadline {
            // Failure-only diagnostics: the exact shim op sequence.
            panic!(
                "b is fenced at its own expiry despite the stalled sweep read: {egress}\nDIAG-OPS:\n{}",
                fs::read_to_string(&log).unwrap_or_default()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    settle
        .join()
        .expect("settle thread")
        .expect("the settle runs (the stalled sweep read is killed at the deadline)");
    // The abandoned cleanup is over-denial, never a silent mutation:
    // the orphan fence stays installed for a later settle to release.
    let egress = acl_egress(&log, &acl);
    assert!(
        lease_fence_present(&egress, "128.66.0.7/32"),
        "the unswept orphan fence stays installed (over-denial): {egress}"
    );
    // And b's expiry really SETTLES — the armed obligation survived the
    // sweep (never retired unprocessed, which would strand the allow
    // forever with the ledger gone quiet): the watcher withdraws it.
    let settle_deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let egress = acl_egress(&log, &acl);
        if !egress.contains("action=allow destination=128.66.0.8/32") {
            break;
        }
        assert!(
            std::time::Instant::now() < settle_deadline,
            "b's expiry settles (allow withdrawn), it was not retired unprocessed: {egress}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    fs::remove_file(statedir.join("barrier-acl-read")).ok();
    fs::remove_file(statedir.join("release-acl-read-barrier")).ok();
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn stalled_orphan_sweep_removals_cannot_delay_the_next_expiry() {
    // C36 r35 F1 (stalled REMOVALS): every orphan fence release used to
    // receive a FRESH 5s budget, so K stalled removals held the owner
    // lock for ~5K seconds while a grant expired unfenced. The sweep now
    // checks the ONE absolute deadline per fence and stops cleanup when
    // it arrives.
    let (mut client, log) = applied_client("running", "sbx-1");
    let clock = DnsTestClock::install(&mut client);
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com", "b.example.com", "c.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    r35_grant_and_revoke(&client, &policy, &hash, &transport);
    // c revoked cleanly too: a second quiet destination, a second
    // orphan fence to sweep.
    r35_nxdomain(&transport, "a.example.com");
    r35_answer(&transport, "b.example.com", Ipv4Addr::new(128, 66, 0, 8));
    r35_nxdomain(&transport, "c.example.com");
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("c's revocation commits");
    let statedir = log.parent().expect("statedir").to_path_buf();
    r35_expire_grant_in(&statedir, &client, "b.example.com", 3);
    // A true barrier cannot complete a removal before its command budget
    // kills it. Advance lifetime only AFTER the sweep enters the barrier.
    fs::write(statedir.join("barrier-acl-lease-fence-remove"), "").unwrap();
    let budgets = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    client.dns_withdrawal_budgets = Some(budgets.clone());
    let before_sweep = log_lines(&log).len();
    // The settle runs CONCURRENTLY (see the read variant): the fencing
    // deadline must be met while the stalled removals still hold the
    // owner lock.
    let settle_client = client.clone();
    let settle = std::thread::spawn(move || {
        settle_client
            .debug_settle_dns_lease_with_blind_fences("sbx-1", &["128.66.0.7/32", "128.66.0.9/32"])
    });
    let arrival = std::time::Instant::now() + Duration::from_secs(120);
    while !statedir.join("lease-fence-remove-entered").exists() {
        assert!(
            std::time::Instant::now() < arrival,
            "sweep reaches removal barrier"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    clock.advance(3);
    settle
        .join()
        .expect("settle thread")
        .expect("the settle runs (stalled removals are killed at the deadline)");
    // Inspect the REAL withdrawal boundary's input, independent of wall-clock
    // scheduling. The sweep starts with at most b's three-second logical gap;
    // observation and journaling can only reduce the removal's remaining budget.
    // A fresh five-second budget would preserve event order but violate this bound.
    let removal_budget = budgets
        .lock()
        .expect("withdrawal budgets")
        .iter()
        .find(|(destination, _)| matches!(destination.as_str(), "128.66.0.7/32" | "128.66.0.9/32"))
        .expect("the stalled orphan removal reaches the withdrawal boundary")
        .1
        .expect("the orphan removal has a bounded budget");
    assert!(
        removal_budget <= Duration::from_secs(3),
        "orphan removal budget {removal_budget:?} exceeds the three-second gap to b's expiry"
    );
    // Assert causal order, not scheduler slack: after the first removal
    // stalls, b's deadline fence must be issued BEFORE another orphan release.
    let lines = log_lines(&log);
    let sweep = &lines[before_sweep..];
    let fenced = sweep
        .iter()
        .position(|line| {
            line.contains("network acl rule add")
                && line.contains("wssp-dns-lease-quarantine-")
                && line.contains("destination=128.66.0.8/32")
        })
        .expect("b is fenced by the unfinished sweep before returning");
    let releases = sweep[..fenced]
        .iter()
        .filter(|line| {
            line.contains("network acl rule remove") && line.contains("wssp-dns-lease-quarantine-")
        })
        .count();
    assert_eq!(
        releases, 1,
        "deadline fencing outranks the second orphan release: {sweep:?}"
    );
    let egress = acl_egress(&log, &acl);
    assert!(
        lease_fence_present(&egress, "128.66.0.8/32"),
        "b is fenced: {egress}"
    );
    // Let b's settlement proceed. The abandoned cleanup left BOTH orphan
    // fences installed; no timed-out removal silently applied.
    fs::write(statedir.join("release-lease-fence-barrier"), "").unwrap();
    let settle_deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let egress = acl_egress(&log, &acl);
        if !egress.contains("action=allow destination=128.66.0.8/32") {
            break;
        }
        assert!(
            std::time::Instant::now() < settle_deadline,
            "b settles once the removals behave: {egress}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let egress = acl_egress(&log, &acl);
    assert!(
        lease_fence_present(&egress, "128.66.0.7/32")
            && lease_fence_present(&egress, "128.66.0.9/32"),
        "both unswept orphan fences stay installed (over-denial): {egress}"
    );
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn a_healthy_orphan_sweep_releases_only_the_orphaned_fence() {
    // C36 r35 F1 inverse: with the daemon healthy, the sweep releases
    // exactly the orphaned blind pre-fences — never a fence over a
    // destination whose allow still survives (it may be mid-withdrawal
    // under another actor), and never a live grant's rules.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com", "b.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    r35_grant_and_revoke(&client, &policy, &hash, &transport);
    // The healthy settle with blind pre-fences for the quiet .7 (a true
    // orphan: no allow survives, nothing pending) and for .8, whose
    // grant is LIVE — a fence over a surviving allow is protection the
    // sweep must never release.
    client
        .debug_settle_dns_lease_with_blind_fences("sbx-1", &["128.66.0.7/32", "128.66.0.8/32"])
        .expect("the settle runs");
    let egress = acl_egress(&log, &acl);
    assert!(
        !lease_fence_present(&egress, "128.66.0.7/32"),
        "the orphaned blind fence is released: {egress}"
    );
    assert!(
        lease_fence_present(&egress, "128.66.0.8/32"),
        "the fence over the live destination stays: {egress}"
    );
    assert!(
        egress.contains("action=allow destination=128.66.0.8/32"),
        "the live grant is untouched: {egress}"
    );
    client.debug_reset_dns_lease_owner("sbx-1");
}

#[test]
fn a_durable_withdrawal_retires_without_a_fresh_attempt() {
    // C36 r35 F1 follow-through (the restarted-owner retirement flake,
    // made deterministic): retirement must accept a destination whose
    // withdrawal evidence is DURABLE, not only one ATTEMPTED in the
    // same settle. Phase B never re-attempts a durable pair, and a
    // fully-proven pair never becomes due again — so an attempt-only
    // gate strands the entry armed forever (the watcher sleeps; no
    // later settle ever sees it) exactly when the trailing flush lands
    // the evidence after the last round's selection. Here one
    // destination (.7) carries durable evidence BEFORE the expiry
    // settle — the state an earlier, partially-failed settle leaves —
    // while .8 is withdrawn by this settle.
    let (client, log) = applied_client("running", "sbx-1");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let (policy, hash) = domain_policy(&["a.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    // One grant, TWO destinations: one entry carrying .7 and .8.
    transport.script(
        "a.example.com",
        [
            FakeDnsOutcome::Answer(vec![
                FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 7), 300),
                FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 8), 300),
            ]),
            FakeDnsOutcome::Rcode(3),
        ],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("the grant commits");
    let statedir = log.parent().expect("statedir").to_path_buf();
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    let ledger: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&obligations).expect("obligations"))
            .expect("obligations json");
    let allow_tag = ledger["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .find(|entry| entry["name"].as_str() == Some("a.example.com"))
        .expect("the entry")
        .get("allow_tag")
        .and_then(|tag| tag.as_str())
        .expect("allow tag")
        .to_string();
    // Durable positive-withdrawal evidence for .7, exactly as an earlier
    // settle's trailing flush would have left it, with the live ACL
    // consistent (the .7 allow is already gone).
    fs::write(
        statedir.join("host-state/dns-revocations/sbx-1.lease-withdrawals"),
        format!("{allow_tag} 128.66.0.7/32\n"),
    )
    .unwrap();
    let egress_path = statedir.join("acls").join(format!("{acl}.egress"));
    let body = fs::read_to_string(&egress_path).expect("egress rules");
    let kept: Vec<&str> = body
        .lines()
        .filter(|line| !(line.contains("action=allow") && line.contains("128.66.0.7/32")))
        .collect();
    fs::write(&egress_path, kept.join("\n") + "\n").unwrap();
    // Expire the grant: the watcher settles due to .8 (attempted); .7
    // is never attempted — its evidence is already durable.
    r35_expire_grant_in(&statedir, &client, "a.example.com", 2);
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let retired = match fs::read_to_string(&obligations) {
            Ok(body) => !body.contains("a.example.com"),
            Err(_) => true,
        };
        if retired {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "an entry whose destinations are attempted-or-durable retires: {}",
            fs::read_to_string(&obligations).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let egress = acl_egress(&log, &acl);
    assert!(
        !egress.contains("action=allow destination=128.66.0.8/32"),
        "the settle withdrew the attempted destination: {egress}"
    );
    client.debug_reset_dns_lease_owner("sbx-1");
}

/// C37 R3 finding 2 (the mechanism, deterministic): a managed DNS
/// transition fences/removes rules BEFORE its persisted plan commit, so a
/// verification snapshot straddling it compares the NEW live ACL against
/// the OLD plan. Pre-fix that skew convicted a healthy sandbox of drift —
/// post-R2 a deletion. The transition seqlock makes the overlap
/// observable: the verifier retries for a coherent snapshot and NEVER
/// convicts the in-flight transition; once the transition's commit
/// restores coherence and ends, the same verification passes.
#[test]
fn verification_retries_across_a_managed_transition_and_never_convicts_it() {
    let (client, log) = applied_client("running", "sbx-1");
    client
        .verify_provisioned_enforcement("sbx-1")
        .expect("the clean applied state verifies");
    let (_network, acl) = sandbox_network_names("sbx-1");
    let egress_path = log
        .parent()
        .expect("statedir")
        .join("acls")
        .join(format!("{acl}.egress"));
    let original = fs::read_to_string(&egress_path).expect("egress rules");
    let removed = original
        .lines()
        .find(|line| line.contains("action=allow") && line.contains("destination_port=67"))
        .expect("a planned DHCP rule to skew")
        .to_string();
    // The transition begins; mid-transition the live ACL has already lost
    // a rule whose plan commit lands later.
    let transition = client.begin_dns_transition("sbx-1");
    let skewed: Vec<&str> = original.lines().filter(|line| *line != removed).collect();
    fs::write(&egress_path, skewed.join("\n") + "\n").unwrap();
    let verifier = {
        let client = client.clone();
        std::thread::spawn(move || client.verify_provisioned_enforcement("sbx-1"))
    };
    std::thread::sleep(Duration::from_millis(400));
    assert!(
        !verifier.is_finished(),
        "the verifier waits for a coherent snapshot across the in-flight transition instead of convicting the skew"
    );
    // The transition's commit restores coherence, then the transition ends.
    fs::write(&egress_path, &original).unwrap();
    drop(transition);
    verifier
        .join()
        .expect("verifier thread")
        .expect("a coherent post-transition snapshot verifies");
}

/// C37 R3 finding 2 (barrier-driven end-to-end): an expiry settlement IN
/// FLIGHT — the withdrawal parked at the shim's allow-removal barrier — is
/// a managed transition, not drift. A concurrent bound-enforcement query
/// on the RUNNING VM must never surface GuestUnavailable, and the VM is
/// never deleted; once the settle commits, the query certifies Ready
/// against the coherently committed state.
#[test]
fn expiry_during_verification_never_convicts_a_healthy_sandbox() {
    let (mut runtime, log) = runtime_for("fix6_new_ready");
    runtime.override_resolver(std::sync::Arc::new(|_domain, _wait| {
        Ok(vec![std::net::IpAddr::V4(Ipv4Addr::new(128, 66, 0, 7))])
    }));
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    let mut request = super::shim_tests::create_req();
    request.egress_policy = Some(policy);
    request.egress_policy_hash = Some(hash);
    runtime.create_bound(&request).expect("create");
    let statedir = log.parent().expect("statedir").to_path_buf();
    // Expire the armed grant in the durable ledger.
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    let mut ledger: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&obligations).expect("armed ledger"))
            .expect("ledger json");
    let now = unix_now().expect("clock");
    for entry in ledger["entries"].as_array_mut().expect("entries") {
        entry["expires_at"] = serde_json::json!(now);
    }
    fs::write(&obligations, serde_json::to_string_pretty(&ledger).unwrap()).unwrap();
    // Park the settlement mid-transition at the allow-removal barrier.
    fs::write(statedir.join("barrier-acl-allow-remove"), "").unwrap();
    let settle_client = runtime.client().clone();
    settle_client.debug_reset_dns_lease_owner("sbx-1");
    let settle = std::thread::spawn(move || settle_client.recover_dns_expiry_obligations("sbx-1"));
    // Wait until the withdrawal is genuinely IN FLIGHT: the removal CLI
    // has started (logged) while the barrier still holds it.
    let deadline = std::time::Instant::now() + Duration::from_secs(45);
    loop {
        let body = fs::read_to_string(&log).unwrap_or_default();
        if body
            .lines()
            .any(|line| line.contains("rule remove") && line.contains("128.66.0.7/32"))
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the expiry withdrawal reaches the barrier"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    // While the transition is in flight, the bound-enforcement query on
    // the RUNNING VM must never convict: no GuestUnavailable, no delete.
    let query = std::thread::spawn(move || {
        runtime.query_sandbox(
            "sbx-1",
            Some("create-1"),
            Some(&super::shim_tests::create_req().template_digest),
        )
    });
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        !query.is_finished(),
        "the query never convicts an in-flight expiry transition"
    );
    // Release the in-flight withdrawal (the shim barrier parks until the
    // release marker appears) and disarm the pin for any later removals.
    fs::write(statedir.join("release-allow-barrier"), "").unwrap();
    fs::remove_file(statedir.join("barrier-acl-allow-remove")).unwrap();
    settle.join().expect("settle thread").expect("settle");
    let state = query.join().expect("query thread");
    assert_eq!(
        state.expect("the healthy sandbox is never convicted"),
        Some(sandbox_protocol::SandboxLifecycleState::Ready),
        "once the settle commits, the query certifies Ready"
    );
    let lines = log_lines(&log);
    assert!(
        !lines.iter().any(|line| line.starts_with("delete ")),
        "a healthy sandbox is never killed by a managed expiry: {}",
        lines.join("\n")
    );
}

/// C37 R3 finding 2 (the load-bearing marking): a policy REFRESH holds no
/// DNS owner lock across its mutations, so the transition seqlock is the
/// ONLY thing standing between a concurrent verification and the
/// mid-refresh live-vs-plan skew. The one-shot ACL-read barrier parks the
/// refresh in flight; the verifier must wait it out (never convict), and
/// once the refresh commits, the verifier certifies the coherent new
/// state. (Pre-fix, or with the refresh unmarked, the verifier returns
/// immediately — the `!is_finished` assertion kills that mutant.)
#[test]
fn refresh_in_flight_never_convicts_a_concurrent_verification() {
    let (client, log) = applied_client("running", "sbx-1");
    let statedir = log.parent().expect("statedir").to_path_buf();
    let (policy, hash) = domain_policy(&["a.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "a.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            30,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("grant commits");
    client
        .verify_provisioned_enforcement("sbx-1")
        .expect("the granted state verifies");
    // Park the refresh's first ACL read: the one-shot barrier is consumed
    // by the refresh thread (spawned before the verifier exists), holding
    // the marked transition open.
    fs::write(statedir.join("barrier-acl-read"), "0").unwrap();
    // Same recorded policy — the ANSWER moves (128.66.0.7 → .9), so the
    // refresh replaces the live rules before its plan commit.
    let refreshing = {
        let client = client.clone();
        let policy = policy.clone();
        std::thread::spawn(move || {
            let transport = FakeDnsTransport::new();
            transport.script(
                "a.example.com",
                [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
                    Ipv4Addr::new(128, 66, 0, 9),
                    30,
                )])],
            );
            refresh(&client, "sbx-1", &policy, &hash, &transport)
        })
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(45);
    while statedir.join("barrier-acl-read").exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "the refresh reaches the barrier"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let verifier = {
        let client = client.clone();
        std::thread::spawn(move || client.verify_provisioned_enforcement("sbx-1"))
    };
    std::thread::sleep(Duration::from_millis(400));
    assert!(
        !verifier.is_finished(),
        "the verifier waits out the in-flight refresh instead of convicting it"
    );
    fs::write(statedir.join("release-acl-read-barrier"), "").unwrap();
    refreshing
        .join()
        .expect("refresh thread")
        .expect("the refresh commits");
    verifier
        .join()
        .expect("verifier thread")
        .expect("the coherent post-refresh state verifies");
}

/// C37 R6 finding 1: transition marking tracks ACTUAL mutations, never a
/// prediction. A grant whose expiry lands DURING the recovery probe —
/// beyond the old +2s entry-time prediction window (the probe deadline
/// deliberately runs right up to the earliest future expiry, up to 20s
/// out) — is fenced and settled as a MARKED transition: in flight during
/// the settle, epoch advanced after it. Pre-fix this settle ran UNMARKED,
/// so a concurrent verifier whose own recovery had finished compared the
/// old plan to the narrowed ACL and convicted a healthy expiry of drift.
/// The no-op control: a later recovery pass with nothing to do never
/// marks (the epoch is untouched).
#[test]
fn an_expiry_during_the_recovery_probe_is_a_marked_transition() {
    let (mut runtime, log) = runtime_for("fix6_new_ready");
    runtime.override_resolver(std::sync::Arc::new(|_domain, _wait| {
        Ok(vec![std::net::IpAddr::V4(Ipv4Addr::new(128, 66, 0, 7))])
    }));
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    let mut request = super::shim_tests::create_req();
    request.egress_policy = Some(policy);
    request.egress_policy_hash = Some(hash);
    runtime.create_bound(&request).expect("create");
    let statedir = log.parent().expect("statedir").to_path_buf();
    // No-op control (armed, undisturbed): a recovery pass over live
    // obligations has nothing to do and must NEVER mark — an eager
    // mark-at-entry would churn the epoch of every healthy leased sandbox.
    let epoch_fresh = runtime.client().dns_transition_observation("sbx-1").0;
    runtime
        .client()
        .recover_dns_expiry_obligations("sbx-1")
        .expect("a no-op recovery over live obligations");
    let (epoch_noop_pre, in_flight_pre) = runtime.client().dns_transition_observation("sbx-1");
    assert!(
        !in_flight_pre && epoch_noop_pre == epoch_fresh,
        "an undisturbed recovery pass never marks ({epoch_fresh} -> {epoch_noop_pre})"
    );
    // Expire the armed grant 5s out — BEYOND the old +2s prediction at
    // pass entry, INSIDE the window the probe can span.
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    let mut ledger: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&obligations).expect("armed ledger"))
            .expect("ledger json");
    let now = unix_now().expect("clock");
    for entry in ledger["entries"].as_array_mut().expect("entries") {
        entry["expires_at"] = serde_json::json!(now + 5);
    }
    fs::write(&obligations, serde_json::to_string_pretty(&ledger).unwrap()).unwrap();
    let epoch_before = runtime.client().dns_transition_observation("sbx-1").0;
    // Park the recovery probe (the pass deadline — the expiry itself —
    // kills the parked read, so the probe SPANS the expiry), and park the
    // settle's allow-removal so the mutating window is observable.
    fs::write(statedir.join("barrier-acl-read"), "0").unwrap();
    fs::write(statedir.join("barrier-acl-allow-remove"), "").unwrap();
    let settle_client = runtime.client().clone();
    settle_client.debug_reset_dns_lease_owner("sbx-1");
    let log_lines_before = fs::read_to_string(&log)
        .map(|body| body.lines().count())
        .unwrap_or(0);
    let settle = std::thread::spawn(move || settle_client.recover_dns_expiry_obligations("sbx-1"));
    // Wait until the withdrawal of the probe-spanned expiry is genuinely
    // IN FLIGHT: the removal CLI has started while the barrier holds it.
    // Only lines logged AFTER the recovery started count (create itself
    // logs removals for this destination).
    let deadline = std::time::Instant::now() + Duration::from_secs(45);
    loop {
        let body = fs::read_to_string(&log).unwrap_or_default();
        if body
            .lines()
            .skip(log_lines_before)
            .any(|line| line.contains("rule remove") && line.contains("128.66.0.7/32"))
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the recovery settles the grant that expired during its probe"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    // THE regression assertion: the settle of a grant that expired DURING
    // the probe is a MARKED transition. (Pre-fix the entry-time prediction
    // saw nothing due within +2s, so this whole settle ran unmarked.)
    let (_, in_flight) = runtime.client().dns_transition_observation("sbx-1");
    assert!(
        in_flight,
        "a recovery that became mutating mid-probe is a marked transition"
    );
    // Release the in-flight withdrawal and let the commit land.
    fs::write(statedir.join("release-allow-barrier"), "").unwrap();
    fs::remove_file(statedir.join("barrier-acl-allow-remove")).unwrap();
    settle.join().expect("settle thread").expect("settle");
    let (epoch_after, in_flight_after) = runtime.client().dns_transition_observation("sbx-1");
    assert!(!in_flight_after, "the transition is complete");
    assert!(
        epoch_after > epoch_before,
        "the mutating recovery advanced the transition epoch ({epoch_before} -> {epoch_after})"
    );
    // No-op control: the obligations are settled — a further recovery pass
    // has nothing to do and must NEVER churn the epoch.
    runtime
        .client()
        .recover_dns_expiry_obligations("sbx-1")
        .expect("a no-op recovery");
    let (epoch_noop, in_flight_noop) = runtime.client().dns_transition_observation("sbx-1");
    assert!(
        !in_flight_noop && epoch_noop == epoch_after,
        "a no-op recovery pass never marks ({epoch_after} -> {epoch_noop}, in_flight={in_flight_noop})"
    );
    // The healthy sandbox verifies cleanly once the transition committed.
    let state = runtime
        .query_sandbox(
            "sbx-1",
            Some("create-1"),
            Some(&super::shim_tests::create_req().template_digest),
        )
        .expect("the healthy sandbox is never convicted");
    assert_eq!(
        state,
        Some(sandbox_protocol::SandboxLifecycleState::Ready),
        "once the settle commits, the query certifies Ready"
    );
}

/// C37 R6 finding 1 (unfenced leg): the same probe-spanned expiry for a
/// grant WITHOUT fence-on-expiry — the settle's only mutations are the
/// allow removal and the plan commit, so no fence add ever reaches the
/// pre-fence's lazy acquisition. The settle-condition mark at the shared
/// boundary is what keeps this withdrawal a marked transition.
#[test]
fn an_unfenced_expiry_during_the_recovery_probe_is_a_marked_transition() {
    let (mut runtime, log) = runtime_for("fix6_new_ready");
    runtime.override_resolver(std::sync::Arc::new(|_domain, _wait| {
        Ok(vec![std::net::IpAddr::V4(Ipv4Addr::new(128, 66, 0, 7))])
    }));
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    let mut request = super::shim_tests::create_req();
    request.egress_policy = Some(policy);
    request.egress_policy_hash = Some(hash);
    runtime.create_bound(&request).expect("create");
    let statedir = log.parent().expect("statedir").to_path_buf();
    // Expire 5s out, beyond the old +2s prediction — and with NO
    // fence-on-expiry, so the settle never adds a fence (removal-only
    // mutations: nothing reaches the pre-fence's mutation marking).
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    let mut ledger: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&obligations).expect("armed ledger"))
            .expect("ledger json");
    let now = unix_now().expect("clock");
    for entry in ledger["entries"].as_array_mut().expect("entries") {
        entry["expires_at"] = serde_json::json!(now + 5);
        entry["fence_on_expiry"] = serde_json::json!([] as [&str; 0]);
    }
    fs::write(&obligations, serde_json::to_string_pretty(&ledger).unwrap()).unwrap();
    let epoch_before = runtime.client().dns_transition_observation("sbx-1").0;
    fs::write(statedir.join("barrier-acl-read"), "0").unwrap();
    fs::write(statedir.join("barrier-acl-allow-remove"), "").unwrap();
    let settle_client = runtime.client().clone();
    settle_client.debug_reset_dns_lease_owner("sbx-1");
    let log_lines_before = fs::read_to_string(&log)
        .map(|body| body.lines().count())
        .unwrap_or(0);
    let settle = std::thread::spawn(move || settle_client.recover_dns_expiry_obligations("sbx-1"));
    let deadline = std::time::Instant::now() + Duration::from_secs(45);
    loop {
        let body = fs::read_to_string(&log).unwrap_or_default();
        if body
            .lines()
            .skip(log_lines_before)
            .any(|line| line.contains("rule remove") && line.contains("128.66.0.7/32"))
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the recovery withdraws the grant that expired during its probe"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let (_, in_flight) = runtime.client().dns_transition_observation("sbx-1");
    assert!(
        in_flight,
        "a removal-only settle of a probe-spanned expiry is still a marked transition"
    );
    fs::write(statedir.join("release-allow-barrier"), "").unwrap();
    fs::remove_file(statedir.join("barrier-acl-allow-remove")).unwrap();
    settle.join().expect("settle thread").expect("settle");
    let (epoch_after, in_flight_after) = runtime.client().dns_transition_observation("sbx-1");
    assert!(!in_flight_after);
    assert!(
        epoch_after > epoch_before,
        "the mutating recovery advanced the transition epoch ({epoch_before} -> {epoch_after})"
    );
}

/// C37 R6 finding 1 (mutation-boundary leg): the transition mark is
/// acquired AT the shared mutation boundary — before the first actual
/// fence mutation lands, never downstream of it. Parking the blind fence
/// ADD itself must already observe the transition in flight: a verifier
/// landing between two fence installations of one pass reads only
/// marked-transition (incoherent, retryable) snapshots, never a
/// convictable skew.
#[test]
fn the_prefence_mutation_itself_is_already_a_marked_transition() {
    let (mut runtime, log) = runtime_for("fix6_new_ready");
    runtime.override_resolver(std::sync::Arc::new(|_domain, _wait| {
        Ok(vec![std::net::IpAddr::V4(Ipv4Addr::new(128, 66, 0, 7))])
    }));
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    let mut request = super::shim_tests::create_req();
    request.egress_policy = Some(policy);
    request.egress_policy_hash = Some(hash);
    runtime.create_bound(&request).expect("create");
    let statedir = log.parent().expect("statedir").to_path_buf();
    // The grant is ALREADY due at pass entry, so the recovery's first
    // mutation is the blind fence add — parked at the barrier.
    let obligations = lease_obligations_path(&statedir, "sbx-1");
    let mut ledger: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&obligations).expect("armed ledger"))
            .expect("ledger json");
    let now = unix_now().expect("clock");
    for entry in ledger["entries"].as_array_mut().expect("entries") {
        entry["expires_at"] = serde_json::json!(now);
    }
    fs::write(&obligations, serde_json::to_string_pretty(&ledger).unwrap()).unwrap();
    fs::write(statedir.join("barrier-acl-lease-fence-add"), "").unwrap();
    let settle_client = runtime.client().clone();
    settle_client.debug_reset_dns_lease_owner("sbx-1");
    let log_lines_before = fs::read_to_string(&log)
        .map(|body| body.lines().count())
        .unwrap_or(0);
    let settle = std::thread::spawn(move || settle_client.recover_dns_expiry_obligations("sbx-1"));
    // Wait until the fence ADD is genuinely parked at the barrier (the
    // CLI has started, the barrier holds it — BEFORE the mutation lands).
    let deadline = std::time::Instant::now() + Duration::from_secs(45);
    loop {
        let body = fs::read_to_string(&log).unwrap_or_default();
        if body
            .lines()
            .skip(log_lines_before)
            .any(|line| line.contains("rule add") && line.contains("wssp-dns-lease-quarantine-"))
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the recovery fences the due grant"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    // THE mutation-boundary assertion: the FIRST actual mutation of the
    // pass is already inside a marked transition.
    // THE mutation-boundary assertion: while the fence ADD is parked, the
    // transition is in flight (the mark precedes the mutation). Poll: the
    // parked add holds for seconds, so a genuine mark is observed
    // immediately; an absent mark never appears.
    let mark_deadline = std::time::Instant::now() + Duration::from_secs(4);
    let marked = loop {
        let (_, in_flight) = runtime.client().dns_transition_observation("sbx-1");
        if in_flight {
            break true;
        }
        if std::time::Instant::now() >= mark_deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(
        marked,
        "the fence mutation itself is already marked — marking lives at the mutation boundary"
    );
    fs::write(statedir.join("release-lease-fence-add-barrier"), "").unwrap();
    fs::remove_file(statedir.join("barrier-acl-lease-fence-add")).unwrap();
    settle.join().expect("settle thread").expect("settle");
    assert!(
        !runtime.client().dns_transition_observation("sbx-1").1,
        "the transition completes"
    );
}

/// Graceful close refuses new admission without cancelling a refresh whose
/// ACL work and readback already finished. The barrier is at the production
/// persistence decision, so closure cannot race the admission in this test.
#[test]
fn an_admitted_refresh_commits_after_admission_closes() {
    let (mut client, log) = applied_client("running", "sbx-1");
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let permit = std::sync::Arc::new(crate::RuntimePermit::with_timeout(Duration::from_secs(120)));
    client.cancelled = Some(permit.clone());
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    client.dns_commit_barrier = Some(barrier.clone());
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    std::thread::scope(|scope| {
        let running = scope.spawn(|| refresh(&client, "sbx-1", &policy, &hash, &transport));
        barrier.wait();
        permit.close();
        assert!(
            !permit.is_cancelled(),
            "close does not revoke admitted work"
        );
        assert!(permit.admit().is_err(), "new admission is refused");
        barrier.wait();
        let outcome = running
            .join()
            .unwrap()
            .expect("admitted refresh commits after close");
        assert_eq!(outcome.published_names, 1);
    });
    let state = client
        .load_dns_state("sbx-1", &hash)
        .expect("DNS state committed");
    assert_eq!(state.grants.len(), 1);
    assert!(
        !client.dns_commit_owed("sbx-1"),
        "plan and owed retirement committed"
    );
    client.dns_commit_barrier = None;
    assert!(
        refresh(&client, "sbx-1", &policy, &hash, &transport).is_err(),
        "new refresh refused"
    );
    client.debug_reset_dns_lease_owner("sbx-1");
}

/// Both cancellation modes land at the existing post-read barrier, while
/// the refresh owns the real commit lock and before either durable write.
fn assert_refresh_cancelled_before_persistence(expire: bool) {
    let (mut client, log) = applied_client("running", "sbx-1");
    let clock = DnsTestClock::install(&mut client);
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("seed committed records");
    let state_path = client.dns_state_dir().join("sbx-1.json");
    let plan_path = log
        .parent()
        .expect("fixture dir")
        .join("host-state/network-plans/sbx-1.json");
    let state_before = fs::read(&state_path).expect("seed DNS state");
    let plan_before = fs::read(&plan_path).expect("seed network plan");

    let permit = std::sync::Arc::new(clock.permit(Duration::from_secs(120)));
    client.cancelled = Some(permit.clone());
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    client.dns_commit_barrier = Some(barrier.clone());
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 8),
            300,
        )])],
    );
    let outcome = std::thread::scope(|scope| {
        let running = scope.spawn(|| refresh(&client, "sbx-1", &policy, &hash, &transport));
        barrier.wait();
        // No wall-clock wait controls when cancellation wins: the refresh
        // cannot leave this persistence boundary until we release it.
        if expire {
            clock.advance(120);
        } else {
            permit.revoke();
        }
        barrier.wait();
        running.join().expect("refresh thread")
    });
    // Stop the seed refresh's watcher before assertions, including a fault
    // failure, so it cannot outlive the fixture or rewrite the evidence.
    client.debug_reset_dns_lease_owner("sbx-1");
    assert!(permit.is_cancelled(), "cancellation was injected");
    assert_eq!(
        permit.is_revoked(),
        !expire,
        "deadline is separate from revoke"
    );
    assert_eq!(
        fs::read(&state_path).expect("DNS state retained"),
        state_before,
        "post-lock cancellation must stop DNS state persistence"
    );
    assert_eq!(
        fs::read(&plan_path).expect("network plan retained"),
        plan_before,
        "post-lock cancellation must stop plan persistence"
    );
    assert_eq!(
        outcome.expect_err("cancelled commit must fail").code,
        SandboxErrorCode::UnknownOutcome
    );
}

#[test]
fn a_refresh_revoked_after_commit_lock_does_not_persist() {
    assert_refresh_cancelled_before_persistence(false);
}

#[test]
fn a_refresh_expired_after_commit_lock_does_not_persist() {
    assert_refresh_cancelled_before_persistence(true);
}

/// The legacy-history fixtures above deliberately exercise the identity-specific
/// recovery path. These cases use production's atomic policy publication path.
#[test]
fn atomic_acl_policy_batches_thirty_domains_and_rotation_without_partial_rules() {
    let (mut client, log) = applied_client("running", "sbx-1");
    client.force_legacy_dns_recovery = false;
    let names: Vec<String> = (0..30).map(|n| format!("d{n}.example.com")).collect();
    let (policy, hash) = domain_policy(&names.iter().map(String::as_str).collect::<Vec<_>>(), &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    let (_, acl) = sandbox_network_names("sbx-1");
    for address in [7, 8] {
        for name in &names {
            transport.script(
                name,
                [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
                    Ipv4Addr::new(128, 66, 0, address),
                    300,
                )])],
            );
        }
        let before = log_lines(&log).len();
        refresh(&client, "sbx-1", &policy, &hash, &transport).unwrap();
        let calls = log_lines(&log);
        let window = &calls[before..];
        assert_eq!(
            window
                .iter()
                .filter(|line| line.contains("-X PUT") && line.contains("/network-acls/"))
                .count(),
            1
        );
        assert!(
            !window.iter().any(|line| line.contains("network acl rule")),
            "{window:?}"
        );
        let egress = acl_egress(&log, &acl);
        assert_eq!(
            egress
                .lines()
                .filter(|line| line.contains("wssp-dns-") && line.contains("destination=128.66.0."))
                .count(),
            120
        );
        assert_eq!(
            egress
                .lines()
                .filter(|line| line.contains("action=allow")
                    && line.contains(&format!("destination=128.66.0.{address}/32")))
                .count(),
            30
        );
        assert!(!egress.contains("quarantine-"));
        if address == 8 {
            assert!(!egress.contains("destination=128.66.0.7/32"));
        }
    }
}

#[test]
fn atomic_acl_rotation_retires_superseded_leases_across_multiple_ttls() {
    let (mut client, log) = applied_client("running", "sbx-1");
    client.force_legacy_dns_recovery = false;
    let clock = super::shim_tests::DnsTestClock::install(&mut client);
    let (policy, hash) = domain_policy(&["rotate.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    for n in 1..=6 {
        transport.script(
            "rotate.example.com",
            [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
                Ipv4Addr::new(128, 66, 0, n),
                300,
            )])],
        );
        let before = log_lines(&log).len();
        refresh(&client, "sbx-1", &policy, &hash, &transport).unwrap();
        let calls = log_lines(&log);
        let calls = &calls[before..];
        assert_eq!(
            calls
                .iter()
                .filter(|line| line.contains("-X PUT") && line.contains("/network-acls/"))
                .count(),
            1
        );
        assert!(
            !calls.iter().any(|line| line.contains("network acl rule")),
            "{calls:?}"
        );
        let ledger: serde_json::Value = serde_json::from_slice(
            &fs::read(
                log.parent()
                    .unwrap()
                    .join("host-state/dns-revocations/sbx-1.lease.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            ledger["entries"].as_array().unwrap().len(),
            1,
            "obsolete identities stay retired: {ledger}"
        );
        // Beyond the first generation's absolute TTL by the third rotation.
        // Its watcher must have nothing obsolete left to fence or withdraw.
        clock.advance(151);
    }
}

#[test]
fn atomic_acl_policy_refuses_static_and_duplicate_drift_without_ratification() {
    for duplicate in [false, true] {
        let (mut client, log) = applied_client("running", "sbx-1");
        client.force_legacy_dns_recovery = false;
        let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
        bind_recorded_policy(&log, "sbx-1", &hash);
        let transport = FakeDnsTransport::new();
        transport.script(
            "grants.example.com",
            [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
                Ipv4Addr::new(128, 66, 0, 7),
                300,
            )])],
        );
        refresh(&client, "sbx-1", &policy, &hash, &transport).unwrap();
        let (_, acl) = sandbox_network_names("sbx-1");
        let path = log
            .parent()
            .unwrap()
            .join("acls")
            .join(format!("{acl}.egress"));
        let mut rules = fs::read_to_string(&path).unwrap();
        if duplicate {
            let extra = rules
                .lines()
                .find(|line| line.contains("wssp-dns-") && line.contains("action=allow"))
                .unwrap()
                .to_string();
            rules.push_str(&format!("{extra}\n"));
        } else {
            rules.push_str(
                "action=allow state=enabled description=unmanaged destination=128.66.0.99/32\n",
            );
        }
        fs::write(&path, &rules).unwrap();
        let plan = client.persisted_plan_rules("sbx-1", &hash).unwrap();
        let before = log_lines(&log).len();
        transport.script(
            "grants.example.com",
            [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
                Ipv4Addr::new(128, 66, 0, 7),
                300,
            )])],
        );
        refresh(&client, "sbx-1", &policy, &hash, &transport).expect_err("drift is never ratified");
        assert!(
            !log_lines(&log)[before..]
                .iter()
                .any(|line| line.contains("-X PUT"))
        );
        assert_eq!(client.persisted_plan_rules("sbx-1", &hash).unwrap(), plan);
        assert_eq!(fs::read_to_string(&path).unwrap(), rules);
    }
}

#[test]
fn atomic_acl_timeout_is_bounded_journaled_and_recovers_without_partial_publication() {
    let (mut client, log) = applied_client("running", "sbx-1");
    client.force_legacy_dns_recovery = false;
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    let script = || {
        transport.script(
            "grants.example.com",
            [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
                Ipv4Addr::new(128, 66, 0, 7),
                300,
            )])],
        )
    };
    let (_, acl) = sandbox_network_names("sbx-1");
    let before = acl_egress(&log, &acl);
    // The PUT stalls for 90 s; every host call of the pass is bounded by
    // `agent_timeout`. The pass makes five calls (three reads, the PUT, a
    // re-read), each ~0.1 s quiet, so 5 s is ample even at load ~25, where
    // the former 250 ms let a READ before the PUT time out (nothing was
    // journaled yet). The pass therefore ends within 5 x 5 s = 25 s, which
    // the 45 s bound checks with margin: well before the 90 s stall, so the
    // stalled write was cut, never waited out.
    let stall = Duration::from_secs(90);
    fs::write(
        log.parent().unwrap().join("slow-acl-put"),
        stall.as_secs().to_string(),
    )
    .unwrap();
    client.agent_timeout = Duration::from_secs(5);
    script();
    let calls_before = log_lines(&log).len();
    let started = std::time::Instant::now();
    let error =
        refresh(&client, "sbx-1", &policy, &hash, &transport).expect_err("stalled atomic write");
    assert!(started.elapsed() < stall / 2, "{:?}", started.elapsed());
    assert_eq!(error.code, SandboxErrorCode::Timeout, "{error:?}");
    // It is the atomic PUT that timed out, not an earlier read.
    assert!(
        log_lines(&log)[calls_before..]
            .iter()
            .any(|line| line.contains("-X PUT") && line.contains("/network-acls/")),
        "the stalled PUT was issued"
    );
    assert_eq!(acl_egress(&log, &acl), before);
    let marker: serde_json::Value = serde_json::from_slice(
        &fs::read(
            log.parent()
                .unwrap()
                .join("host-state/dns-revocations/sbx-1.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(
        !marker["pending"].as_array().unwrap().is_empty(),
        "{marker}"
    );
    fs::remove_file(log.parent().unwrap().join("slow-acl-put")).unwrap();
    client.agent_timeout = Duration::from_secs(30);
    script();
    refresh(&client, "sbx-1", &policy, &hash, &transport).expect("durable recovery after timeout");
}

#[test]
fn atomic_acl_grants_expire_without_a_renewal_pass() {
    let (mut client, log) = applied_client("running", "sbx-1");
    client.force_legacy_dns_recovery = false;
    let clock = super::shim_tests::DnsTestClock::install(&mut client);
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            30,
        )])],
    );
    refresh(&client, "sbx-1", &policy, &hash, &transport).unwrap();
    let (_, acl) = sandbox_network_names("sbx-1");
    assert!(acl_egress(&log, &acl).contains("destination=128.66.0.7/32"));
    // Census may pause renewals for longer than a TTL. Its pause never closes
    // the independent expiry owner or extends this armed absolute deadline.
    clock.advance(31);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        client.debug_wake_dns_lease_owner("sbx-1");
        let rules = acl_egress(&log, &acl);
        if !rules
            .lines()
            .any(|line| line.contains("action=allow") && line.contains("destination=128.66.0.7/32"))
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "expired allow remained: {rules}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn atomic_acl_old_cli_parser_refusal_keeps_supported_legacy_enforcement() {
    let (mut client, log) = client_for_with_log("running");
    fs::write(log.parent().unwrap().join("cli-without-query-headers"), "").unwrap();
    client.apply_sandbox_network(&test_plan("sbx-1")).unwrap();
    assert!(!client.supports_atomic_acl_updates());
    client.force_legacy_dns_recovery = false;
    let (policy, hash) = domain_policy(&["grants.example.com"], &[]);
    bind_recorded_policy(&log, "sbx-1", &hash);
    let transport = FakeDnsTransport::new();
    transport.script(
        "grants.example.com",
        [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
            Ipv4Addr::new(128, 66, 0, 7),
            300,
        )])],
    );
    let before = log_lines(&log).len();
    refresh(&client, "sbx-1", &policy, &hash, &transport).unwrap();
    assert!(
        !log_lines(&log)[before..]
            .iter()
            .any(|line| line.contains("-X PUT")),
        "do not repeatedly probe a known old CLI"
    );
    let (_, acl) = sandbox_network_names("sbx-1");
    assert_eq!(
        acl_egress(&log, &acl)
            .lines()
            .filter(|line| line.contains("destination=128.66.0.7/32"))
            .count(),
        4
    );
}

#[test]
fn atomic_acl_body_above_the_argv_limit_uses_stdin() {
    let (client, log) = applied_client("running", "sbx-1");
    let (_, acl) = sandbox_network_names("sbx-1");
    let rules: Vec<serde_json::Value> = (0..1000)
        .map(|n| {
            serde_json::json!({
                "action":"reject", "state":"enabled", "destination":"128.66.0.7/32",
                "description": format!("rule-{n}-{}", "x".repeat(100))
            })
        })
        .collect();
    assert!(serde_json::to_vec(&rules).unwrap().len() > 131_072);
    client
        .update_acl(&acl, Duration::from_secs(10), |metadata| {
            metadata["egress"] = rules.into();
            Ok(())
        })
        .unwrap();
    let body: serde_json::Value =
        serde_json::from_slice(&fs::read(log.parent().unwrap().join("last-acl-put.json")).unwrap())
            .unwrap();
    assert_eq!(body["egress"].as_array().unwrap().len(), 1000);
    let calls = log_lines(&log);
    let put = calls
        .iter()
        .rev()
        .find(|line| line.contains("-X PUT"))
        .unwrap();
    assert!(put.contains("--data-file -"));
    assert!(put.len() < 1024, "the body is absent from argv");
}
