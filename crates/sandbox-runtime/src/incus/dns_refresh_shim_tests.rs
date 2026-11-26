//! Executable-shim tests for the production DNS grant refresh scheduler
//! (`dns_refresh`): create-time domain grants are kept alive by the
//! scheduled pass, rotate, fail closed, and stop with the sandbox. The fake
//! `incus` binary stores network/ACL state; the test resolver stands in for
//! the host system resolver. No VM, no real DNS.

use super::shim_tests::FixtureRuntime;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use sandbox_protocol::EgressPolicy;

use super::dns::unix_now;
use super::dns_refresh::{REFRESH_BATCH, REFRESH_PARALLELISM, refresh_pass_at};
use super::kvm::IncusKvmRuntime;
use super::network::{policy_hash_hex, sandbox_network_names};
use super::shim_tests::{DnsTestClock, create_req, runtime_for};
use crate::r#trait::SandboxRuntime;

const DOMAIN: &str = "grants.example.com";

type Answer = Result<Vec<Ipv4Addr>, String>;

/// A runtime with a controllable resolver: the current answer for every
/// name, and a count of lookups issued.
struct Fixture {
    runtime: IncusKvmRuntime,
    log: PathBuf,
    answer: Arc<Mutex<Answer>>,
    lookups: Arc<AtomicUsize>,
}

impl Fixture {
    fn new(initial: &[Ipv4Addr]) -> Self {
        let (mut runtime, log) = runtime_for("fix6_new_ready");
        // Preserve coverage of in-flight identity-specific requests written by
        // older daemons; new atomic-policy cases use the production default.
        runtime.client_mut().force_legacy_dns_recovery = true;
        let answer: Arc<Mutex<Answer>> = Arc::new(Mutex::new(Ok(initial.to_vec())));
        let lookups = Arc::new(AtomicUsize::new(0));
        let (seen, count) = (answer.clone(), lookups.clone());
        runtime.override_resolver(Arc::new(move |_domain, _wait| {
            count.fetch_add(1, Ordering::SeqCst);
            match &*seen.lock().unwrap() {
                Ok(addrs) => Ok(addrs.iter().copied().map(IpAddr::V4).collect()),
                Err(message) => Err(crate::RuntimeError::new(
                    sandbox_protocol::SandboxErrorCode::Internal,
                    message.clone(),
                )),
            }
        }));
        Self {
            runtime,
            log,
            answer,
            lookups,
        }
    }

    fn create(&self, domains: &[&str], cidrs: &[&str]) {
        let policy = EgressPolicy {
            mode: sandbox_protocol::EgressMode::Allowlist,
            domains: domains.iter().map(|d| d.to_string()).collect(),
            cidrs: cidrs.iter().map(|c| c.to_string()).collect(),
        };
        let mut request = create_req();
        request.egress_policy_hash = Some(policy_hash_hex(&policy));
        request.egress_policy = Some(policy);
        self.runtime.create_bound(&request).expect("create");
    }

    fn statedir(&self) -> PathBuf {
        self.log.parent().expect("statedir").to_path_buf()
    }

    fn egress(&self) -> String {
        let acl = sandbox_network_names("sbx-1").1;
        fs::read_to_string(self.statedir().join("acls").join(format!("{acl}.egress")))
            .unwrap_or_default()
    }

    fn dnsmasq(&self) -> String {
        let network = sandbox_network_names("sbx-1").0;
        fs::read_to_string(
            self.statedir()
                .join("networks")
                .join(format!("{network}.raw")),
        )
        .unwrap_or_default()
    }

    fn allows(&self, addr: &str) -> bool {
        self.egress().lines().any(|line| {
            line.contains("action=allow") && line.contains(&format!("destination={addr}/32"))
        })
    }

    /// The persisted grant expiries for DOMAIN (DNS state).
    fn state_expiry(&self) -> Option<u64> {
        let body =
            fs::read_to_string(self.statedir().join("host-state/dns-policy/sbx-1.json")).ok()?;
        let parsed: serde_json::Value = serde_json::from_str(&body).ok()?;
        parsed["grants"]
            .as_array()?
            .iter()
            .find(|g| g["name"] == DOMAIN)
            .and_then(|g| g["expires_at"].as_u64())
    }

    /// Rewrite DOMAIN's persisted grant expiry (stands in for elapsed time
    /// on the durable schedule the planner and scheduler read).
    fn set_state_expiry(&self, expires_at: u64) {
        let path = self.statedir().join("host-state/dns-policy/sbx-1.json");
        let mut parsed: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("dns state")).expect("json");
        for grant in parsed["grants"].as_array_mut().expect("grants") {
            if grant["name"] == DOMAIN {
                grant["expires_at"] = serde_json::json!(expires_at);
            }
        }
        fs::write(&path, parsed.to_string()).expect("rewrite dns state");
    }

    /// The armed lease deadline for the obligation covering `dest`.
    fn lease_expiry(&self, dest: &str) -> Option<u64> {
        let body = fs::read_to_string(
            self.statedir()
                .join("host-state/dns-revocations/sbx-1.lease.json"),
        )
        .ok()?;
        let parsed: serde_json::Value = serde_json::from_str(&body).ok()?;
        parsed["entries"]
            .as_array()?
            .iter()
            .filter(|entry| {
                entry["destinations"]
                    .as_array()
                    .is_some_and(|d| d.iter().any(|d| d.as_str() == Some(dest)))
            })
            .filter_map(|entry| entry["expires_at"].as_u64())
            .max()
    }

    fn pass(&self, now: u64) -> super::dns_refresh::DnsRefreshPass {
        refresh_pass_at(
            self.runtime.client(),
            self.runtime.dns_refresh_scheduler(),
            &["sbx-1".to_string()],
            now,
        )
        .expect("pass")
    }

    fn started(&self) -> usize {
        self.runtime
            .dns_refresh_scheduler()
            .stats
            .started
            .load(Ordering::SeqCst)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Stop the process-global lease watcher for this test's state root.
        self.runtime.client().debug_reset_dns_lease_owner("sbx-1");
    }
}

const A: Ipv4Addr = Ipv4Addr::new(128, 66, 0, 7);
const B: Ipv4Addr = Ipv4Addr::new(128, 66, 0, 8);

/// DNS-P2-1: exercise the actual bounded resolver executor through BOTH
/// production callers. A timed-out lookup (and repeated attempts by its
/// sandbox) cannot starve another sandbox's create or scheduled refresh.
#[test]
fn one_sandbox_stalled_in_libc_cannot_starve_refresh_or_create() {
    use std::time::Duration;

    let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    let (entered, started) = std::sync::mpsc::channel();
    let blocker = gate.clone();
    let pool = Arc::new(
        super::network::ResolverPool::with_resolver(
            4,
            Arc::new(move |name| {
                if name.starts_with("stalled") {
                    let _ = entered.send(());
                    let (lock, wake) = &*blocker;
                    let mut released = lock.lock().unwrap();
                    while !*released {
                        released = wake.wait(released).unwrap();
                    }
                }
                Ok(vec![IpAddr::V4(A)])
            }),
        )
        .unwrap(),
    );
    let mut fx = Fixture::new(&[A]);
    let mut client = fx.runtime.client().clone();
    client.resolver = None;
    client.resolver_pool = Some(pool.clone());
    let clock = DnsTestClock::install(&mut client);
    fx.runtime = IncusKvmRuntime::from_test_client(client.clone());

    // Its caller timed out, but libc still owns the slot. Repeated names,
    // from any clone of the same sandbox client, must not consume more slots.
    client
        .resolve_domain("hog", "stalled-0.example.com", Duration::ZERO)
        .unwrap_err();
    started.recv_timeout(Duration::from_secs(5)).unwrap();
    for i in 1..9 {
        client
            .clone()
            .resolve_domain("hog", &format!("stalled-{i}.example.com"), Duration::ZERO)
            .unwrap_err();
    }
    fx.create(&[DOMAIN], &[]);
    let first = fx.state_expiry().unwrap();
    clock.advance(160);
    let pass = fx.pass(clock.now());
    // Release even before assertions so a failing mutant leaves no stuck
    // helper threads in a libtest run.
    *gate.0.lock().unwrap() = true;
    gate.1.notify_all();
    assert_eq!(pass.refreshed, vec!["sbx-1".to_string()], "{pass:?}");
    assert!(pass.failed.is_empty(), "{pass:?}");
    assert!(fx.state_expiry().unwrap() > first);
    assert!(fx.allows("128.66.0.7"));
}

#[test]
fn a_domain_grant_is_renewed_before_expiry_across_cycles() {
    let mut fx = Fixture::new(&[A]);
    let mut client = fx.runtime.client().clone();
    let clock = DnsTestClock::install(&mut client);
    fx.runtime = IncusKvmRuntime::from_test_client(client);
    fx.create(&[DOMAIN], &[]);
    let created = fx.lookups.load(Ordering::SeqCst);
    let first = fx.state_expiry().expect("initial grant persisted");
    assert!(fx.allows("128.66.0.7"));
    assert_eq!(first, clock.now() + 300);
    // Scheduling, answer timestamps and enforcement share logical time.
    let pass = super::dns_refresh::refresh_pass(
        fx.runtime.client(),
        fx.runtime.dns_refresh_scheduler(),
        &["sbx-1".to_string()],
    )
    .unwrap();
    assert!(pass.refreshed.is_empty() && pass.failed.is_empty());
    assert_eq!(
        fx.lookups.load(Ordering::SeqCst),
        created,
        "nothing re-resolved"
    );
    // Several cycles on the scheduling clock, each inside the grant's
    // second half-life and spaced by the retry interval: every one
    // re-resolves, re-commits and re-arms the lease from the fresh answer.
    for cycle in 0..3 {
        let near = fx.state_expiry().unwrap();
        clock.advance(160);
        let before = fx.lookups.load(Ordering::SeqCst);
        let pass = super::dns_refresh::refresh_pass(
            fx.runtime.client(),
            fx.runtime.dns_refresh_scheduler(),
            &["sbx-1".to_string()],
        )
        .unwrap();
        assert_eq!(
            pass.refreshed,
            vec!["sbx-1".to_string()],
            "cycle {cycle}: {pass:?}"
        );
        assert!(
            fx.lookups.load(Ordering::SeqCst) > before,
            "cycle {cycle} re-resolved"
        );
        let renewed = fx.state_expiry().expect("grant retained");
        assert!(renewed > near, "cycle {cycle}: deadline advances");
        assert_eq!(
            renewed,
            clock.now() + 300,
            "cycle {cycle}: fresh answer lifetime"
        );
        assert_eq!(
            fx.lease_expiry("128.66.0.7/32"),
            Some(renewed),
            "cycle {cycle}: the expiry lease is re-armed with the renewed deadline"
        );
        assert!(fx.allows("128.66.0.7"), "cycle {cycle}: still allowed");
        assert!(
            fx.dnsmasq().contains("128.66.0.7"),
            "cycle {cycle}: still answered"
        );
    }
}

#[test]
fn changed_answers_replace_the_old_destination() {
    let fx = Fixture::new(&[A]);
    fx.create(&[DOMAIN], &[]);
    assert!(fx.allows("128.66.0.7"));
    *fx.answer.lock().unwrap() = Ok(vec![B]);
    let expiry = fx.state_expiry().unwrap();
    let pass = fx.pass(expiry - 100);
    assert_eq!(pass.refreshed, vec!["sbx-1".to_string()], "{pass:?}");
    assert!(
        fx.allows("128.66.0.8"),
        "the new address is granted: {}",
        fx.egress()
    );
    assert!(
        !fx.allows("128.66.0.7"),
        "the old address's allow is withdrawn: {}",
        fx.egress()
    );
    let dns = fx.dnsmasq();
    assert!(
        dns.contains("128.66.0.8") && !dns.contains("128.66.0.7"),
        "{dns}"
    );
}

#[test]
fn resolver_failure_never_extends_and_then_withdraws_the_grant() {
    let fx = Fixture::new(&[A]);
    fx.create(&[DOMAIN], &[]);
    let original = fx.state_expiry().unwrap();
    let armed = fx.lease_expiry("128.66.0.7/32").unwrap();
    *fx.answer.lock().unwrap() = Err("lookup failed".to_string());
    // A failed lookup with plenty of lifetime left keeps the grant at its
    // ORIGINAL deadline: never extended.
    let pass = fx.pass(original - 100);
    assert!(pass.failed.is_empty(), "{pass:?}");
    assert_eq!(
        fx.state_expiry(),
        Some(original),
        "transient failure never extends"
    );
    assert_eq!(
        fx.lease_expiry("128.66.0.7/32"),
        Some(armed),
        "lease not extended"
    );
    assert!(
        fx.allows("128.66.0.7"),
        "still inside its original lifetime"
    );
    // The same failure once the grant is inside the churn floor withdraws
    // it (fail closed) instead of retaining a stale answer.
    let near = unix_now().unwrap() + 20;
    fx.set_state_expiry(near);
    let pass = fx.pass(original - 80);
    assert!(pass.failed.is_empty(), "{pass:?}");
    assert_eq!(fx.state_expiry(), None, "the lapsing grant is dropped");
    assert!(!fx.allows("128.66.0.7"), "withdrawn: {}", fx.egress());
    assert!(!fx.dnsmasq().contains("128.66.0.7"), "no longer answered");
    // Recovery: once the name resolves again, the missing grant is retried.
    *fx.answer.lock().unwrap() = Ok(vec![A]);
    let pass = fx.pass(original - 80 + super::dns_refresh::MISSING_RETRY_SECS);
    assert_eq!(pass.refreshed, vec!["sbx-1".to_string()], "{pass:?}");
    assert!(fx.allows("128.66.0.7"), "re-granted after recovery");
}

#[test]
fn a_protected_answer_on_refresh_denies_immediately() {
    let fx = Fixture::new(&[A]);
    fx.create(&[DOMAIN], &[]);
    *fx.answer.lock().unwrap() = Ok(vec![A, Ipv4Addr::new(10, 0, 0, 5)]);
    let expiry = fx.state_expiry().unwrap();
    fx.pass(expiry - 100);
    assert_eq!(fx.state_expiry(), None, "rebinding denies the whole name");
    assert!(
        !fx.allows("128.66.0.7") && !fx.allows("10.0.0.5"),
        "{}",
        fx.egress()
    );
}

#[test]
fn no_refresh_for_sandboxes_without_domain_grants() {
    let fx = Fixture::new(&[A]);
    fx.create(&[], &["128.66.1.0/24"]);
    let now = unix_now().unwrap();
    for offset in [0, 200, 400, 10_000] {
        let pass = fx.pass(now + offset);
        assert!(
            pass.refreshed.is_empty() && pass.failed.is_empty() && pass.skipped.is_empty(),
            "{pass:?}"
        );
    }
    assert_eq!(fx.lookups.load(Ordering::SeqCst), 0, "nothing resolved");
    assert_eq!(fx.started(), 0, "no refresh was ever scheduled");
}

#[test]
fn refresh_stops_when_the_sandbox_is_stopped_or_destroyed() {
    let fx = Fixture::new(&[A]);
    fx.create(&[DOMAIN], &[]);
    let expiry = fx.state_expiry().unwrap();
    let create = create_req();
    fx.runtime
        .stop_sandbox(&crate::StopSandboxRequest {
            template_fingerprint: create.template_digest.clone(),
            sandbox_id: create.sandbox_id.clone(),
            instance_name: create.instance_name.clone(),
            operation_id: "stop".into(),
            idempotency_key: "stop".into(),
        })
        .expect("stop");
    let before = fx.lookups.load(Ordering::SeqCst);
    let pass = fx.pass(expiry - 100);
    assert!(
        pass.refreshed.is_empty(),
        "a stopped VM is not refreshed: {pass:?}"
    );
    assert_eq!(fx.lookups.load(Ordering::SeqCst), before);
    fx.runtime
        .kill_bound(&crate::KillSandboxRequest {
            template_fingerprint: create.template_digest.clone(),
            sandbox_id: create.sandbox_id.clone(),
            instance_name: create.instance_name.clone(),
            operation_id: "kill".into(),
            idempotency_key: "kill".into(),
        })
        .expect("kill");
    let pass = fx.pass(expiry + 1_000);
    assert!(
        pass.refreshed.is_empty() && pass.skipped.is_empty() && pass.failed.is_empty(),
        "a destroyed sandbox has no recorded policy left: {pass:?}"
    );
    assert_eq!(fx.lookups.load(Ordering::SeqCst), before);
    // Leaving the active set forgets the schedule.
    refresh_pass_at(
        fx.runtime.client(),
        fx.runtime.dns_refresh_scheduler(),
        &[],
        expiry + 2_000,
    )
    .unwrap();
    assert!(fx.runtime.dns_refresh_scheduler().tracked().is_empty());
}

#[test]
fn a_cancelled_pass_starts_no_refresh() {
    let fx = Fixture::new(&[A]);
    fx.create(&[DOMAIN], &[]);
    let expiry = fx.state_expiry().unwrap();
    let permit = Arc::new(crate::RuntimePermit::default());
    permit.revoke();
    let mut scoped = fx.runtime.client().clone();
    scoped.cancelled = Some(permit);
    let before = fx.lookups.load(Ordering::SeqCst);
    let pass = refresh_pass_at(
        &scoped,
        fx.runtime.dns_refresh_scheduler(),
        &["sbx-1".to_string()],
        expiry - 100,
    )
    .unwrap();
    assert_eq!(pass.skipped, vec!["sbx-1".to_string()], "{pass:?}");
    assert_eq!(
        fx.lookups.load(Ordering::SeqCst),
        before,
        "no lookup after shutdown"
    );
    // Not penalized: the next (uncancelled) pass refreshes at once.
    let pass = fx.pass(expiry - 100);
    assert_eq!(pass.refreshed, vec!["sbx-1".to_string()], "{pass:?}");
}

#[test]
fn a_drift_refused_sandbox_is_not_renewed() {
    let fx = Fixture::new(&[A]);
    fx.create(&[DOMAIN], &[]);
    let expiry = fx.state_expiry().unwrap();
    fx.runtime
        .client()
        .policy_refusals
        .lock()
        .unwrap()
        .insert("sbx-1".to_string());
    let before = fx.lookups.load(Ordering::SeqCst);
    let pass = fx.pass(expiry - 100);
    assert_eq!(pass.skipped, vec!["sbx-1".to_string()], "{pass:?}");
    assert_eq!(fx.lookups.load(Ordering::SeqCst), before);
}

/// Record a domain policy for `id` exactly as apply persists it (no VM, no
/// DNS state: every name is "missing", so the sandbox is due).
fn record_domain_policy(statedir: &Path, id: &str) {
    let policy = EgressPolicy {
        mode: sandbox_protocol::EgressMode::Allowlist,
        domains: vec![DOMAIN.to_string()],
        cidrs: Vec::new(),
    };
    let dir = statedir.join("host-state/network-plans");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join(format!("{id}.json")),
        serde_json::json!({
            "version": super::acl::PLAN_RECORD_VERSION,
            "sandbox_id": id,
            "gateway": "10.9.9.1",
            "rules": [],
            "grants": [],
            "policy_cidrs": [],
            "policy_domains": policy.domains,
            "hash": policy_hash_hex(&policy),
            "mode": policy.mode,
            "settings": crate::egress::EgressSettings::default(),
            "dnsmasq_base": super::dns::allowlist_dnsmasq_base(&crate::egress::EgressSettings::default()).unwrap(),
            "denied_grants": [],
        })
        .to_string(),
    )
    .unwrap();
}

#[test]
fn a_pass_is_bounded_in_batch_and_concurrency() {
    let fx = Fixture::new(&[A]);
    let statedir = fx.statedir();
    let ids: Vec<String> = (0..(REFRESH_BATCH * 3))
        .map(|n| format!("sbx-many-{n}"))
        .collect();
    for id in &ids {
        record_domain_policy(&statedir, id);
    }
    let scheduler = fx.runtime.dns_refresh_scheduler();
    *scheduler.stats.hold.lock().unwrap() = Some(std::time::Duration::from_millis(30));
    let now = unix_now().unwrap();
    let pass = refresh_pass_at(fx.runtime.client(), scheduler, &ids, now).unwrap();
    let handled = pass.refreshed.len() + pass.skipped.len() + pass.failed.len();
    assert_eq!(
        handled, REFRESH_BATCH,
        "one pass handles at most a batch: {pass:?}"
    );
    assert_eq!(
        scheduler.stats.started.load(Ordering::SeqCst),
        REFRESH_BATCH
    );
    let peak = scheduler.stats.max_in_flight.load(Ordering::SeqCst);
    assert!(
        (2..=REFRESH_PARALLELISM).contains(&peak),
        "refreshes run concurrently but never above the bound: {peak}"
    );
    assert_eq!(
        scheduler.stats.in_flight.load(Ordering::SeqCst),
        0,
        "all joined"
    );
    // The attempted batch backs off; the next pass takes the next batch.
    let pass = refresh_pass_at(fx.runtime.client(), scheduler, &ids, now + 1).unwrap();
    let second: Vec<String> = pass
        .refreshed
        .iter()
        .chain(&pass.skipped)
        .chain(pass.failed.iter().map(|(id, _)| id))
        .cloned()
        .collect();
    assert_eq!(second.len(), REFRESH_BATCH);
    assert_eq!(
        scheduler.tracked().len(),
        REFRESH_BATCH * 2,
        "both batches are backing off"
    );
}

#[test]
fn the_runtime_entry_point_refreshes_due_grants_on_the_wall_clock() {
    let fx = Fixture::new(&[A]);
    fx.create(&[DOMAIN], &[]);
    // Not due yet on the wall clock: the trait entry point does nothing.
    let before = fx.lookups.load(Ordering::SeqCst);
    let reports = Mutex::new(Vec::new());
    let observe = |report: &crate::DnsRefreshReport| reports.lock().unwrap().push(report.clone());
    fx.runtime
        .refresh_dns_grants_observed(&["sbx-1".to_string()], &observe)
        .expect("pass");
    assert_eq!(fx.lookups.load(Ordering::SeqCst), before);
    assert!(
        reports.lock().unwrap().is_empty(),
        "not-due passes emit no diagnostic"
    );
    // Past half-life on the durable schedule: the SAME entry point the host
    // daemon calls renews it.
    let near = unix_now().unwrap() + 100;
    fx.set_state_expiry(near);
    fx.runtime
        .refresh_dns_grants_observed(&["sbx-1".to_string()], &observe)
        .expect("pass");
    assert!(fx.lookups.load(Ordering::SeqCst) > before, "re-resolved");
    assert!(fx.state_expiry().is_some_and(|renewed| renewed > near));
    assert!(fx.allows("128.66.0.7"));
    let reports = reports.lock().unwrap();
    assert_eq!(
        reports.len(),
        1,
        "one diagnostic per completed sandbox refresh"
    );
    let report = &reports[0];
    assert_eq!(report.sandbox_id, "sbx-1");
    assert_eq!(report.domain_count, 1);
    assert!(report.changed_grants, "renewal changes the grant deadline");
    assert_eq!(
        (
            report.changed_addresses,
            report.added_addresses,
            report.removed_addresses
        ),
        (0, 0, 0)
    );
    assert_eq!(
        report.next_refresh_unix_secs,
        fx.state_expiry().unwrap() - 150
    );
}

#[test]
fn a_busy_sandbox_lock_defers_without_waiting_or_mutating() {
    let fx = Fixture::new(&[A]);
    fx.create(&[DOMAIN], &[]);
    let expiry = fx.state_expiry().unwrap();
    let near = unix_now().unwrap() + 100;
    fx.set_state_expiry(near);
    let lock = fx.runtime.client().sandbox_lock("sbx-1");
    let held = lock.lock().unwrap();
    let started = std::time::Instant::now();
    let pass = fx.pass(expiry - 100);
    assert!(started.elapsed() < std::time::Duration::from_secs(20));
    assert_eq!(pass.skipped, vec!["sbx-1".to_string()], "{pass:?}");
    assert_eq!(
        fx.state_expiry(),
        Some(near),
        "nothing committed behind the lock"
    );
    drop(held);
    // Not backed off: the next pass refreshes at once.
    let pass = fx.pass(expiry - 99);
    assert_eq!(pass.refreshed, vec!["sbx-1".to_string()], "{pass:?}");
}

/// DNS-P2-2: expiry gets its normal five-second action permit while a
/// refresh waits behind the real commit lock for six seconds. Only the
/// production lock loop observes cancellation; the holder merely blocks.
/// Stop preempts the refresh; kill also needs its sandbox lock.
#[test]
fn lifecycle_priority_preempts_a_six_second_refresh_commit() {
    use std::time::{Duration, Instant};
    for action in ["stop", "kill"] {
        let mut fx = Fixture::new(&[A]);
        fx.create(&[DOMAIN], &[]);
        let due = fx.state_expiry().unwrap() - 100;
        *fx.answer.lock().unwrap() = Ok(vec![B]);
        // The refresh's commit lock stays held until this test releases it
        // (120 s is only a hang guard): preemption is proven by order, the
        // lifecycle request and the refresh pass both finishing while the
        // lock is still held, not by racing a six-second wall-clock hold.
        let hold = Arc::new(super::client::DnsCommitHold {
            entered: std::sync::atomic::AtomicBool::new(false),
            release: std::sync::atomic::AtomicBool::new(false),
            lapsed: std::sync::atomic::AtomicBool::new(false),
            duration: Duration::from_secs(120),
        });
        fx.runtime.client_mut().dns_commit_hold = Some(hold.clone());
        let barrier = Arc::new(std::sync::Barrier::new(2));
        fx.runtime.client_mut().dns_commit_pre_lock_barrier = Some(barrier.clone());
        let (done, completed) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                done.send(fx.pass(due)).unwrap();
            });
            barrier.wait(); // refresh has finished ACL mutations and reached commit
            scope.spawn(|| fx.runtime.client().debug_hold_dns_commit("sbx-1"));
            let arrival = Instant::now() + Duration::from_secs(120);
            while !hold.entered.load(Ordering::Acquire) {
                assert!(Instant::now() < arrival, "refresh reaches its commit");
                std::thread::sleep(Duration::from_millis(10));
            }
            barrier.wait(); // release into the production contended-lock loop
            // The expiry action's production budget (5 s), on a logical
            // clock: the shimmed kill/stop spends real CPU on dozens of
            // python `incus` stand-ins, which on a loaded machine alone
            // exceeds 5 s of wall time. Waiting for the held lock instead
            // would never finish while it is held, which `lapsed` catches.
            let lifecycle =
                fx.runtime
                    .with_cancellation(Arc::new(crate::RuntimePermit::with_test_clock(
                        Duration::from_secs(5),
                        Arc::new(std::sync::Mutex::new(Instant::now())),
                    )));
            let create = create_req();
            match action {
                "stop" => {
                    lifecycle
                        .stop_sandbox(&crate::StopSandboxRequest {
                            template_fingerprint: create.template_digest,
                            sandbox_id: create.sandbox_id,
                            instance_name: create.instance_name,
                            operation_id: "expiry-stop".into(),
                            idempotency_key: "expiry-stop".into(),
                        })
                        .expect("expiry stop completes on its normal permit");
                }
                _ => {
                    lifecycle
                        .kill_bound(&crate::KillSandboxRequest {
                            template_fingerprint: create.template_digest,
                            sandbox_id: create.sandbox_id,
                            instance_name: create.instance_name,
                            operation_id: "expiry-kill".into(),
                            idempotency_key: "expiry-kill".into(),
                        })
                        .expect("expiry kill completes on its normal permit");
                }
            }
            let pass = completed
                .recv_timeout(Duration::from_secs(120))
                .expect("the lifecycle request preempts the held refresh");
            assert!(
                !hold.lapsed.load(Ordering::Acquire),
                "{action}: the lifecycle request and the refresh finished only after the commit lock was free"
            );
            hold.release.store(true, Ordering::Release);
            assert!(
                pass.refreshed.is_empty() && !pass.failed.is_empty(),
                "{action}: {pass:?}"
            );
        });
    }
}

#[test]
fn lifecycle_wants_lock_defers_new_refreshes_until_the_request_ends() {
    let fx = Fixture::new(&[A]);
    fx.create(&[DOMAIN], &[]);
    let due = fx.state_expiry().unwrap() - 100;
    let before = fx.lookups.load(Ordering::SeqCst);
    let priority = fx.runtime.client().request_lifecycle_priority("sbx-1");
    let pass = fx.pass(due);
    assert_eq!(pass.skipped, vec!["sbx-1".to_string()], "{pass:?}");
    assert_eq!(fx.lookups.load(Ordering::SeqCst), before);
    drop(priority);
    let pass = fx.pass(due);
    assert_eq!(pass.refreshed, vec!["sbx-1".to_string()], "{pass:?}");
}

// Refresh races against lifecycle operations, rebinding answers, and
// reconnect after a scheduled rotation.

fn wait_for_lookup_after(fx: &Fixture, after: usize) {
    let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while fx.lookups.load(Ordering::SeqCst) <= after {
        assert!(
            std::time::Instant::now() < until,
            "pass never reached the resolver"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// Kill lands WHILE the refresh resolves outside the sandbox lock: the
/// fresh answer B must never be installed on (or recreate) the torn-down
/// sandbox, and no DNS state may be resurrected.
#[test]
fn refresh_kill_during_unlocked_resolution_installs_nothing() {
    let fx = Fixture::new(&[A]);
    fx.create(&[DOMAIN], &[]);
    let expiry = fx.state_expiry().unwrap();
    *fx.answer.lock().unwrap() = Ok(vec![B]);
    let before = fx.lookups.load(Ordering::SeqCst);
    let gate = fx.answer.lock().unwrap();
    std::thread::scope(|s| {
        let h = s.spawn(|| fx.pass(expiry - 100));
        wait_for_lookup_after(&fx, before);
        let create = create_req();
        fx.runtime
            .kill_bound(&crate::KillSandboxRequest {
                template_fingerprint: create.template_digest.clone(),
                sandbox_id: create.sandbox_id.clone(),
                instance_name: create.instance_name.clone(),
                operation_id: "kill".into(),
                idempotency_key: "kill".into(),
            })
            .expect("kill");
        drop(gate);
        let pass = h.join().unwrap();
        assert!(pass.refreshed.is_empty(), "{pass:?}");
    });
    assert!(
        !fx.allows("128.66.0.8"),
        "B installed after kill: {}",
        fx.egress()
    );
    assert!(!fx.allows("128.66.0.7"), "A survived kill: {}", fx.egress());
    assert_eq!(fx.state_expiry(), None, "dns state resurrected");
}

/// Stop lands while resolving: the under-lock running re-check must win.
#[test]
fn refresh_stop_during_unlocked_resolution_does_not_renew() {
    let fx = Fixture::new(&[A]);
    fx.create(&[DOMAIN], &[]);
    let expiry = fx.state_expiry().unwrap();
    let armed = fx.lease_expiry("128.66.0.7/32").unwrap();
    let before = fx.lookups.load(Ordering::SeqCst);
    let gate = fx.answer.lock().unwrap();
    std::thread::scope(|s| {
        let h = s.spawn(|| fx.pass(expiry - 100));
        wait_for_lookup_after(&fx, before);
        let create = create_req();
        fx.runtime
            .stop_sandbox(&crate::StopSandboxRequest {
                template_fingerprint: create.template_digest.clone(),
                sandbox_id: create.sandbox_id.clone(),
                instance_name: create.instance_name.clone(),
                operation_id: "stop".into(),
                idempotency_key: "stop".into(),
            })
            .expect("stop");
        drop(gate);
        let pass = h.join().unwrap();
        assert!(pass.refreshed.is_empty(), "stopped VM renewed: {pass:?}");
    });
    assert_eq!(fx.state_expiry(), Some(expiry), "grant extended after stop");
    assert_eq!(
        fx.lease_expiry("128.66.0.7/32"),
        Some(armed),
        "lease re-armed after stop"
    );
}

/// An OVERDUE grant (deadline passed, watcher may not have settled) with a
/// failing resolver is dropped, never retained or re-armed.
#[test]
fn refresh_overdue_grant_with_failing_resolver_is_withdrawn() {
    let fx = Fixture::new(&[A]);
    fx.create(&[DOMAIN], &[]);
    let original = fx.state_expiry().unwrap();
    let past = unix_now().unwrap() - 5;
    fx.set_state_expiry(past);
    *fx.answer.lock().unwrap() = Err("SERVFAIL".to_string());
    fx.pass(original);
    assert_eq!(fx.state_expiry(), None);
    assert!(!fx.allows("128.66.0.7"), "{}", fx.egress());
    let lease = fx.lease_expiry("128.66.0.7/32");
    assert!(
        lease.is_none_or(|l| l <= original),
        "lease extended: {lease:?}"
    );
}

/// Rebinding variants on refresh: link-local metadata, CGNAT, loopback,
/// and an IPv6-only answer all deny the name.
#[test]
fn refresh_refresh_rebinding_variants_deny() {
    for bad in [
        vec![Ipv4Addr::new(169, 254, 169, 254)],
        vec![B, Ipv4Addr::new(127, 0, 0, 1)],
        vec![B, Ipv4Addr::new(100, 64, 0, 1)],
        vec![B, Ipv4Addr::new(192, 168, 1, 1)],
        vec![],
    ] {
        let fx = Fixture::new(&[A]);
        fx.create(&[DOMAIN], &[]);
        *fx.answer.lock().unwrap() = Ok(bad.clone());
        let expiry = fx.state_expiry().unwrap();
        fx.pass(expiry - 100);
        assert_eq!(fx.state_expiry(), None, "{bad:?} retained a grant");
        assert!(
            !fx.allows("128.66.0.7") && !fx.allows("128.66.0.8"),
            "{bad:?}: {}",
            fx.egress()
        );
        drop(fx);
    }
}

/// Scheduled refresh rotates A -> B, then a warm reconnect reuses the
/// persisted expansion (whose `grants` still list the create-time answer A):
/// A must not come back as an allow, and a later refresh must still work.
#[test]
fn refresh_reconnect_after_scheduled_rotation_does_not_resurrect_old_answer() {
    let fx = Fixture::new(&[A]);
    fx.create(&[DOMAIN], &[]);
    *fx.answer.lock().unwrap() = Ok(vec![B]);
    let expiry = fx.state_expiry().unwrap();
    let pass = fx.pass(expiry - 100);
    assert_eq!(pass.refreshed, vec!["sbx-1".to_string()], "{pass:?}");
    assert!(
        fx.allows("128.66.0.8") && !fx.allows("128.66.0.7"),
        "{}",
        fx.egress()
    );
    let policy = EgressPolicy {
        mode: sandbox_protocol::EgressMode::Allowlist,
        domains: vec![DOMAIN.to_string()],
        cidrs: vec![],
    };
    let hash = policy_hash_hex(&policy);
    let _reconnect = fx.runtime.reconnect_bound(&crate::ReconnectSandboxRequest {
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
    });
    assert!(
        !fx.allows("128.66.0.7"),
        "stale create-time answer resurrected: {}",
        fx.egress()
    );
    // A later refresh still renews.
    let before = fx.state_expiry();
    let pass = fx.pass(expiry - 60);
    assert_eq!(pass.refreshed, vec!["sbx-1".to_string()], "{pass:?}");
    assert!(fx.state_expiry() >= before, "a later refresh must renew");
    assert!(!fx.allows("128.66.0.7"), "{}", fx.egress());
}

// C58 NEW-1: a refresh that mutates live enforcement and then fails before
// its commit leaves a refresh OWED, never drift. The 2 s policy reconciler
// and the enforcement-loss drain must not stop or destroy the healthy
// sandbox; the next refresh commits; real broadening still convicts.

fn marker(fx: &Fixture) -> serde_json::Value {
    fs::read_to_string(fx.statedir().join("host-state/dns-revocations/sbx-1.json"))
        .ok()
        .and_then(|body| serde_json::from_str(&body).ok())
        .unwrap_or(serde_json::Value::Null)
}

fn lifecycle_lines(fx: &Fixture) -> Vec<String> {
    fs::read_to_string(&fx.log)
        .unwrap_or_default()
        .lines()
        .filter(|line| line.starts_with("stop ") || line.starts_with("delete "))
        .map(str::to_string)
        .collect()
}

fn reconcile(fx: &Fixture) -> sandbox_protocol::PolicyReconcilerHealth {
    fx.runtime
        .reconcile_policies(&["sbx-1".to_string()])
        .expect("reconcile");
    fx.runtime.policy_reconciler_health()
}

fn refused(fx: &Fixture) -> bool {
    fx.runtime
        .client()
        .policy_refusals
        .lock()
        .unwrap()
        .contains("sbx-1")
}

/// Leave sbx-1 with an owed refresh: `answer` is installed by the pass,
/// then the dnsmasq publication fails before the commit.
fn owed_refresh(fx: &Fixture, answer: Vec<Ipv4Addr>) -> u64 {
    fx.create(&[DOMAIN], &[]);
    assert!(fx.allows("128.66.0.7"));
    *fx.answer.lock().unwrap() = Ok(answer);
    fs::write(fx.statedir().join("fail-raw-dnsmasq"), "").unwrap();
    let expiry = fx.state_expiry().unwrap();
    let pass = fx.pass(expiry - 100);
    assert_eq!(pass.failed.len(), 1, "{pass:?}");
    assert_eq!(marker(fx)["refresh_owed"], serde_json::json!(true));
    expiry
}

fn assert_owed_not_drift(fx: &Fixture) {
    let health = reconcile(fx);
    assert_eq!(
        (health.drift, health.inconclusive),
        (0, 1),
        "an owed refresh is inconclusive, never drift: {health:?}"
    );
    assert!(refused(fx), "guest dispatch stays fenced while owed");
    let verdict = fx.runtime.client().enforcement_observation("sbx-1");
    assert!(
        matches!(
            verdict,
            super::acl::EnforcementVerdict::Inconclusive(ref err)
                if err.message.contains("refresh owed")
        ),
        "{verdict:?}"
    );
    fx.runtime
        .drain_enforcement_losses(&|_, _| Ok(()))
        .expect("drain");
    let dir = fx.statedir();
    assert!(!dir.join("stopped-instance").exists(), "never halted");
    assert!(!dir.join("deleted-instance").exists(), "never destroyed");
    assert!(
        lifecycle_lines(fx).is_empty(),
        "no stop/delete: {:?}",
        lifecycle_lines(fx)
    );
    assert!(
        !dir.join("host-state/enforcement-losses/sbx-1.json")
            .exists(),
        "no loss record"
    );
}

fn assert_next_refresh_commits(fx: &Fixture, expiry: u64) {
    fs::remove_file(fx.statedir().join("fail-raw-dnsmasq")).unwrap();
    // The reconciler refused the sandbox; the owed refresh still runs.
    let pass = fx.pass(expiry - 100 + super::dns_refresh::REFRESH_RETRY_SECS);
    assert_eq!(pass.refreshed, vec!["sbx-1".to_string()], "{pass:?}");
    let marker = marker(fx);
    assert!(
        marker.is_null() || marker["refresh_owed"] == serde_json::json!(false),
        "the commit retires the owed mark: {marker}"
    );
    let health = reconcile(fx);
    assert_eq!(health.verified, 1, "{health:?}");
    assert!(!refused(fx), "verification lifts the refusal");
    assert!(!fx.statedir().join("stopped-instance").exists());
}

/// NEW-1 regression: the refresh DENIES the name (rebinding) and withdraws
/// it, then the publication fails. Convicting drift here would force-stop
/// the VM and let the drain delete it.
#[test]
fn new1_uncommitted_refresh_denial_is_owed_not_drift() {
    let fx = Fixture::new(&[A]);
    let expiry = owed_refresh(&fx, vec![A, Ipv4Addr::new(10, 0, 0, 5)]);
    assert!(!fx.allows("128.66.0.7"), "denied grant fenced first");
    assert_eq!(marker(&fx)["revoked"], serde_json::json!([DOMAIN]));
    assert_owed_not_drift(&fx);
    // Still never broader than policy while owed.
    assert!(!fx.allows("128.66.0.7"), "{}", fx.egress());
    assert_next_refresh_commits(&fx, expiry);
    assert!(!fx.allows("128.66.0.7") && !fx.allows("10.0.0.5"));
}

/// NEW-1 class (no denial): a rotation A -> B installs B (lease-armed) and
/// withdraws A, then the publication fails. Same verdict: owed.
#[test]
fn new1_uncommitted_rotation_is_owed_not_drift() {
    let fx = Fixture::new(&[A]);
    let expiry = owed_refresh(&fx, vec![B]);
    assert!(fx.allows("128.66.0.8") && !fx.allows("128.66.0.7"));
    assert_owed_not_drift(&fx);
    assert_next_refresh_commits(&fx, expiry);
    assert!(fx.allows("128.66.0.8") && !fx.allows("128.66.0.7"));
}

/// NEW-1 class: the rotation's publication LANDS, then its commit fails
/// (the DNS state directory refuses the durable write). The journaled
/// attempt explains the live `raw.dnsmasq`; an unjournaled body does not.
#[test]
fn new1_landed_publication_is_explained_only_when_journaled() {
    use std::os::unix::fs::PermissionsExt;
    let fx = Fixture::new(&[A]);
    fx.create(&[DOMAIN], &[]);
    *fx.answer.lock().unwrap() = Ok(vec![B]);
    let state_dir = fx.statedir().join("host-state/dns-policy");
    fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o555)).unwrap();
    let expiry = fx.state_expiry().unwrap();
    let pass = fx.pass(expiry - 100);
    fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(pass.failed.len(), 1, "{pass:?}");
    assert!(
        fx.dnsmasq().contains("128.66.0.8"),
        "published: {}",
        fx.dnsmasq()
    );
    assert_eq!(marker(&fx)["refresh_owed"], serde_json::json!(true));
    assert_owed_not_drift(&fx);
    // An unjournaled body is drift even while owed.
    let network = sandbox_network_names("sbx-1").0;
    let raw = fx
        .statedir()
        .join("networks")
        .join(format!("{network}.raw"));
    fs::write(&raw, "address=/grants.example.com/128.66.1.66\n").unwrap();
    let health = reconcile(&fx);
    assert_eq!(health.drift, 1, "{health:?}");
}

/// Inverse: an owed refresh never masks real broadening. Each tamper is
/// convicted, halted and torn down exactly as without the owed refresh.
#[test]
fn new1_owed_refresh_still_convicts_real_broadening() {
    let network = sandbox_network_names("sbx-1").0;
    let acl = sandbox_network_names("sbx-1").1;
    for tamper in [
        "static-allow-all",
        "unarmed-dynamic-allow",
        "missing-companion",
        "config-key",
    ] {
        let fx = Fixture::new(&[A]);
        owed_refresh(&fx, vec![B]);
        let dir = fx.statedir();
        let egress = dir.join("acls").join(format!("{acl}.egress"));
        let mut rules = fs::read_to_string(&egress).unwrap();
        match tamper {
            "static-allow-all" => rules.push_str("action=allow\n"),
            "unarmed-dynamic-allow" => rules.push_str(
                "action=allow destination=128.66.1.9/32 description=wssp-dns-g99-deadbeef\n",
            ),
            "missing-companion" => {
                rules = rules
                    .lines()
                    .filter(|line| {
                        !(line.contains("destination=128.66.0.8/32")
                            && line.contains("protocol=tcp")
                            && line.contains("destination_port=853"))
                    })
                    .map(|line| format!("{line}\n"))
                    .collect();
            }
            _ => {
                let conf = dir.join("networks").join(format!("{network}.conf"));
                let body = fs::read_to_string(&conf).unwrap().replace(
                    "security.acls.default.egress.action=drop",
                    "security.acls.default.egress.action=allow",
                );
                fs::write(conf, body).unwrap();
            }
        }
        fs::write(&egress, rules).unwrap();
        let health = reconcile(&fx);
        assert_eq!(health.drift, 1, "{tamper}: {health:?}");
        assert!(dir.join("stopped-instance").exists(), "{tamper}: halted");
        fx.runtime
            .drain_enforcement_losses(&|_, _| Ok(()))
            .expect("drain");
        assert!(dir.join("deleted-instance").exists(), "{tamper}: torn down");
        drop(fx);
    }
}

/// SEED-1: DNS expiry RECOVERY fails (the revoked allow will not
/// withdraw) while the refresh is owed. The old recovery-error arm
/// convicted drift with no coherence check; now the observation is
/// inconclusive — and real broadening is still convicted coherently.
#[test]
fn seed1_recovery_failure_is_inconclusive_but_real_drift_convicts() {
    for tampered in [false, true] {
        let fx = Fixture::new(&[A]);
        fx.create(&[DOMAIN], &[]);
        let dir = fx.statedir();
        *fx.answer.lock().unwrap() = Ok(vec![Ipv4Addr::new(10, 0, 0, 5)]);
        fs::write(dir.join("fail-acl-allow-remove"), "").unwrap();
        let expiry = fx.state_expiry().unwrap();
        let pass = fx.pass(expiry - 100);
        assert_eq!(pass.failed.len(), 1, "{pass:?}");
        let recovery = fx.runtime.client().recover_dns_expiry_obligations("sbx-1");
        assert!(recovery.is_err(), "the revoked allow will not settle");
        if tampered {
            let acl = sandbox_network_names("sbx-1").1;
            let egress = dir.join("acls").join(format!("{acl}.egress"));
            let mut rules = fs::read_to_string(&egress).unwrap();
            rules.push_str("action=allow\n");
            fs::write(&egress, rules).unwrap();
        }
        let health = reconcile(&fx);
        if tampered {
            assert_eq!(health.drift, 1, "{health:?}");
            assert!(dir.join("stopped-instance").exists());
        } else {
            assert_eq!((health.drift, health.inconclusive), (0, 1), "{health:?}");
            assert!(
                lifecycle_lines(&fx).is_empty(),
                "{:?}",
                lifecycle_lines(&fx)
            );
            assert!(
                !effectively_allows(&fx, "128.66.0.7"),
                "inconclusive only because the denied destination is fenced: {}",
                fx.egress()
            );
        }
        fs::remove_file(dir.join("fail-acl-allow-remove")).unwrap();
        drop(fx);
    }
}

/// DNS-P2-4: a committed rotation rewrites the plan record's flat `grants`
/// expansion with the rules, so it lists B and no longer A.
#[test]
fn dns_p2_4_rotation_rewrites_the_plan_grants() {
    let fx = Fixture::new(&[A]);
    fx.create(&[DOMAIN], &["128.66.1.0/24"]);
    let record = || -> serde_json::Value {
        serde_json::from_str(
            &fs::read_to_string(fx.statedir().join("host-state/network-plans/sbx-1.json")).unwrap(),
        )
        .unwrap()
    };
    assert_eq!(
        record()["grants"],
        serde_json::json!(["128.66.0.7/32", "128.66.1.0/24"])
    );
    *fx.answer.lock().unwrap() = Ok(vec![B]);
    let expiry = fx.state_expiry().unwrap();
    let pass = fx.pass(expiry - 100);
    assert_eq!(pass.refreshed, vec!["sbx-1".to_string()], "{pass:?}");
    assert_eq!(
        record()["grants"],
        serde_json::json!(["128.66.0.8/32", "128.66.1.0/24"])
    );
}

/// DNS-P2-6: while a lifecycle operation holds the sandbox lock across
/// several passes, the due sandbox is NOT re-resolved every pass.
#[test]
fn dns_p2_6_busy_lock_does_not_re_resolve_every_pass() {
    let fx = Fixture::new(&[A]);
    fx.create(&[DOMAIN], &[]);
    let expiry = fx.state_expiry().unwrap();
    fx.set_state_expiry(unix_now().unwrap() + 100);
    let lock = fx.runtime.client().sandbox_lock("sbx-1");
    let held = lock.lock().unwrap();
    let before = fx.lookups.load(Ordering::SeqCst);
    for offset in 0..5 {
        let pass = fx.pass(expiry - 100 + offset);
        assert_eq!(pass.skipped, vec!["sbx-1".to_string()], "{pass:?}");
    }
    assert_eq!(
        fx.lookups.load(Ordering::SeqCst),
        before,
        "no resolution behind a busy lock"
    );
    drop(held);
    let pass = fx.pass(expiry - 94);
    assert_eq!(pass.refreshed, vec!["sbx-1".to_string()], "{pass:?}");
}

// C58 G1 r2: owed-mode inverse matrix, adopted from the r1 security review
// probes (RV-1..RV-5). Real broadening convicts even while a refresh is owed.

/// Is `addr` reachable: an allow to it and no destination-wide reject?
fn effectively_allows(fx: &Fixture, addr: &str) -> bool {
    let egress = fx.egress();
    let dest = format!("destination={addr}/32");
    let allowed = egress
        .lines()
        .any(|line| line.contains("action=allow") && line.contains(&dest));
    let fenced = egress.lines().any(|line| {
        line.contains("action=reject")
            && line.contains(&dest)
            && !line.contains("destination_port=")
            && !line.contains("protocol=")
    });
    allowed && !fenced
}

fn append_egress(fx: &Fixture, line: &str) {
    let acl = sandbox_network_names("sbx-1").1;
    let egress = fx.statedir().join("acls").join(format!("{acl}.egress"));
    let mut rules = fs::read_to_string(&egress).unwrap();
    rules.push_str(line);
    rules.push('\n');
    fs::write(&egress, rules).unwrap();
}

const STATELESS_ALLOW_ALL: &str =
    "action=allow-stateless destination=0.0.0.0/0 description=wssp-dns-g99-deadbeef";

/// G1-R1-1 (regression): a DNS-tagged rule with a broadening action other
/// than the literal `allow` (Incus `allow-stateless`) is never skipped as
/// deny-direction by the owed-mode classifier.
#[test]
fn owed_refresh_convicts_a_non_allow_broadening_action() {
    let fx = Fixture::new(&[A]);
    owed_refresh(&fx, vec![B]);
    append_egress(&fx, STATELESS_ALLOW_ALL);
    let health = reconcile(&fx);
    assert_eq!(
        health.drift, 1,
        "allow-stateless broadening masked: {health:?}"
    );
}

/// G1-R1-1 control: the same tamper without an owed refresh convicts.
#[test]
fn without_owed_refresh_a_non_allow_broadening_action_convicts() {
    let fx = Fixture::new(&[A]);
    fx.create(&[DOMAIN], &[]);
    append_egress(&fx, STATELESS_ALLOW_ALL);
    let health = reconcile(&fx);
    assert_eq!(health.drift, 1, "{health:?}");
}

/// Carry-in: an Incus `logged` rule is ACTIVE. A tampered logged allow is
/// drift, with or without an owed refresh — never permanently inconclusive.
#[test]
fn a_logged_allow_convicts_with_or_without_an_owed_refresh() {
    for owed in [false, true] {
        let fx = Fixture::new(&[A]);
        if owed {
            owed_refresh(&fx, vec![B]);
        } else {
            fx.create(&[DOMAIN], &[]);
        }
        append_egress(
            &fx,
            "action=allow destination=128.66.1.7/32 state=logged description=wssp-dns-g99-deadbeef",
        );
        let health = reconcile(&fx);
        assert_eq!(health.drift, 1, "owed={owed}: {health:?}");
        drop(fx);
    }
}

/// G1-R1-2 (regression): BOTH the allow withdrawal AND the fence fail, so
/// the denied destination stays open. A denied grant is not "our own
/// work": this still convicts and halts.
#[test]
fn owed_refresh_convicts_a_denied_grant_that_cannot_be_fenced() {
    let fx = Fixture::new(&[A]);
    fx.create(&[DOMAIN], &[]);
    let dir = fx.statedir();
    *fx.answer.lock().unwrap() = Ok(vec![Ipv4Addr::new(10, 0, 0, 5)]);
    fs::write(dir.join("fail-acl-allow-remove"), "").unwrap();
    fs::write(dir.join("fail-acl-fence-add"), "").unwrap();
    let expiry = fx.state_expiry().unwrap();
    let pass = fx.pass(expiry - 100);
    assert_eq!(pass.failed.len(), 1, "{pass:?}");
    assert!(
        effectively_allows(&fx, "128.66.0.7"),
        "precondition: the denied destination is open: {}",
        fx.egress()
    );
    let health = reconcile(&fx);
    assert_eq!(
        health.drift, 1,
        "denied destination open while classified non-drift: {health:?}"
    );
    assert!(
        dir.join("stopped-instance").exists(),
        "the breach is halted"
    );
}

/// G1-R1-2 (regression): after an owed DENIAL refresh withdrew A, an
/// out-of-band re-add of A's exact allow and companions reopens a denied
/// destination. Drift, although the owed refresh is still uncommitted.
#[test]
fn owed_refresh_convicts_a_re_added_denied_grant() {
    let fx = Fixture::new(&[A]);
    fx.create(&[DOMAIN], &[]);
    let original: Vec<String> = fx
        .egress()
        .lines()
        .filter(|line| line.contains("destination=128.66.0.7/32"))
        .map(str::to_string)
        .collect();
    assert!(!original.is_empty());
    *fx.answer.lock().unwrap() = Ok(vec![A, Ipv4Addr::new(10, 0, 0, 5)]);
    fs::write(fx.statedir().join("fail-raw-dnsmasq"), "").unwrap();
    let expiry = fx.state_expiry().unwrap();
    let pass = fx.pass(expiry - 100);
    assert_eq!(pass.failed.len(), 1, "{pass:?}");
    assert!(!effectively_allows(&fx, "128.66.0.7"), "{}", fx.egress());
    // Tamper: drop any fence on A and restore the original rules.
    let acl = sandbox_network_names("sbx-1").1;
    let egress = fx.statedir().join("acls").join(format!("{acl}.egress"));
    let mut rules: String = fs::read_to_string(&egress)
        .unwrap()
        .lines()
        .filter(|line| !line.contains("destination=128.66.0.7/32"))
        .map(|line| format!("{line}\n"))
        .collect();
    for line in &original {
        rules.push_str(line);
        rules.push('\n');
    }
    fs::write(&egress, rules).unwrap();
    assert!(effectively_allows(&fx, "128.66.0.7"));
    let health = reconcile(&fx);
    assert_eq!(
        health.drift, 1,
        "re-added denied grant stays open and unconvicted: {health:?}"
    );
    assert!(fx.statedir().join("stopped-instance").exists());
}

/// A stale `refresh_owed` (a crashed process marked and never mutated) on
/// an otherwise exact sandbox is inconclusive, is retried and retired by
/// the next refresh, and a real broadening added while it is set still
/// convicts.
#[test]
fn stale_owed_mark_is_inconclusive_retried_and_still_convicts() {
    for tamper in [false, true] {
        let fx = Fixture::new(&[A]);
        fx.create(&[DOMAIN], &[]);
        let path = fx.statedir().join("host-state/dns-revocations/sbx-1.json");
        let hash = policy_hash_hex(&EgressPolicy {
            mode: sandbox_protocol::EgressMode::Allowlist,
            domains: vec![DOMAIN.to_string()],
            cidrs: vec![],
        });
        let mut record = marker(&fx);
        if record.is_null() {
            record = serde_json::json!({
                "sandbox_id": "sbx-1",
                "policy_hash": hash,
                "project": "default",
                "revoked": [],
                "revoked_generations": {},
                "pending": [],
                "next_request": 0,
                "standing_fences": [],
                "published_attempts": []
            });
        }
        record["refresh_owed"] = serde_json::json!(true);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, record.to_string()).unwrap();
        if tamper {
            append_egress(&fx, "action=allow destination=128.66.1.0/24");
            let health = reconcile(&fx);
            assert_eq!(
                health.drift, 1,
                "stale owed masks static broadening: {health:?}"
            );
            continue;
        }
        let health = reconcile(&fx);
        assert_eq!((health.drift, health.inconclusive), (0, 1), "{health:?}");
        let expiry = fx.state_expiry().unwrap();
        // Not due by grant expiry: the owed mark alone schedules it.
        let pass = fx.pass(expiry.saturating_sub(250));
        assert_eq!(pass.refreshed, vec!["sbx-1".to_string()], "{pass:?}");
        assert_eq!(reconcile(&fx).verified, 1);
    }
}

/// A commit that fails FOREVER: the sandbox is never halted, stays
/// refused, is retried at the retry spacing, and its live egress never
/// includes the denied destination.
#[test]
fn persistent_commit_failure_stays_fenced_and_unconvicted() {
    let fx = Fixture::new(&[A]);
    let expiry = owed_refresh(&fx, vec![A, Ipv4Addr::new(10, 0, 0, 5)]);
    let mut attempts = 0;
    for step in 0..6u64 {
        let pass = fx.pass(expiry - 100 + step * super::dns_refresh::REFRESH_RETRY_SECS);
        attempts += pass.failed.len();
        let health = reconcile(&fx);
        assert_eq!(health.drift, 0, "step {step}: {health:?}");
        assert!(refused(&fx));
        assert!(!effectively_allows(&fx, "128.66.0.7"), "{}", fx.egress());
        assert!(!effectively_allows(&fx, "10.0.0.5"));
    }
    assert!(attempts >= 5, "owed refresh retried: {attempts}");
    assert!(lifecycle_lines(&fx).is_empty());
}

/// G1-R1-3: the owed refresh runs despite a reconciler refusal ONLY when
/// that refusal's cause was the owed refresh. A refusal for another reason
/// (unreadable ACL evidence) still blocks it, even with work owed.
#[test]
fn owed_refresh_bypasses_only_a_refusal_caused_by_the_owed_refresh() {
    let fx = Fixture::new(&[A]);
    let expiry = owed_refresh(&fx, vec![A, Ipv4Addr::new(10, 0, 0, 5)]);
    let dir = fx.statedir();
    fs::remove_file(dir.join("fail-raw-dnsmasq")).unwrap();
    fs::write(dir.join("fail-acl-read"), "1000").unwrap();
    let health = reconcile(&fx);
    assert_eq!(health.inconclusive, 1, "{health:?}");
    assert!(refused(&fx));
    fs::remove_file(dir.join("fail-acl-read")).unwrap();
    let pass = fx.pass(expiry - 100 + super::dns_refresh::REFRESH_RETRY_SECS);
    assert_eq!(pass.skipped, vec!["sbx-1".to_string()], "{pass:?}");
    // Re-observed: the cause is now the owed refresh, which may run.
    let health = reconcile(&fx);
    assert_eq!((health.drift, health.inconclusive), (0, 1), "{health:?}");
    let pass = fx.pass(expiry - 100 + 2 * super::dns_refresh::REFRESH_RETRY_SECS);
    assert_eq!(pass.refreshed, vec!["sbx-1".to_string()], "{pass:?}");
    assert_eq!(reconcile(&fx).verified, 1);
}

/// G1-R1-2 inverse (over-correction guard): a denied identity whose
/// withdrawal failed is NOT open when another, still-granted name keeps the
/// same destination authorized (with its own companions). Owed, not drift.
#[test]
fn a_denied_identity_on_a_destination_still_granted_elsewhere_is_owed() {
    const OTHER: &str = "mirror.example.com";
    let mut fx = Fixture::new(&[A]);
    let deny = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = deny.clone();
    fx.runtime.override_resolver(Arc::new(move |domain, _wait| {
        if domain == DOMAIN && flag.load(Ordering::SeqCst) {
            Ok(vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))])
        } else {
            Ok(vec![IpAddr::V4(A)])
        }
    }));
    fx.create(&[DOMAIN, OTHER], &[]);
    let dir = fx.statedir();
    deny.store(true, Ordering::SeqCst);
    fs::write(dir.join("fail-acl-allow-remove"), "").unwrap();
    fs::write(dir.join("fail-acl-fence-add"), "").unwrap();
    let expiry = fx.state_expiry().unwrap();
    let pass = fx.pass(expiry - 100);
    assert_eq!(pass.failed.len(), 1, "{pass:?}");
    assert!(effectively_allows(&fx, "128.66.0.7"), "{}", fx.egress());
    let health = reconcile(&fx);
    assert_eq!(
        (health.drift, health.inconclusive),
        (0, 1),
        "a destination another grant still authorizes is not open: {health:?}"
    );
    assert!(!dir.join("stopped-instance").exists());
}

// C58 G1 r3 (G1-R2-1): an owed refresh explains only DNS-managed ACL rules
// and the dnsmasq publication — never an instance device.

/// Point eth0 at the shared, unrestricted `incusbr0`: the VM's egress
/// bypasses the sandbox bridge and its ACL entirely.
fn repoint_eth0_to_an_unrestricted_bridge(fx: &Fixture) {
    let path = fx.statedir().join("device-eth0");
    let spec = fs::read_to_string(&path).expect("device-eth0");
    let network = sandbox_network_names("sbx-1").0;
    let tampered = spec.replace(&format!("network={network}"), "network=incusbr0");
    assert_ne!(
        spec, tampered,
        "precondition: spec carries the bridge: {spec}"
    );
    fs::write(&path, tampered).unwrap();
}

/// Control: the device tamper convicts with nothing owed.
#[test]
fn a_device_broadening_convicts_without_an_owed_refresh() {
    let fx = Fixture::new(&[A]);
    fx.create(&[DOMAIN], &[]);
    repoint_eth0_to_an_unrestricted_bridge(&fx);
    let health = reconcile(&fx);
    assert_eq!(health.drift, 1, "{health:?}");
}

/// Regression: an owed refresh (rotation whose publication failed) never
/// masks a device-level broadening.
#[test]
fn an_owed_refresh_never_masks_a_device_broadening() {
    let fx = Fixture::new(&[A]);
    owed_refresh(&fx, vec![B]);
    repoint_eth0_to_an_unrestricted_bridge(&fx);
    let health = reconcile(&fx);
    assert_eq!(
        health.drift, 1,
        "device broadening masked while owed: {health:?}"
    );
    assert!(fx.statedir().join("stopped-instance").exists(), "halted");
}

/// Regression: a bare stale owed mark (exact ACL) never masks a
/// device-level broadening either — this exact state stays convicted.
#[test]
fn a_stale_owed_mark_never_masks_a_device_broadening() {
    let fx = Fixture::new(&[A]);
    fx.create(&[DOMAIN], &[]);
    let path = fx.statedir().join("host-state/dns-revocations/sbx-1.json");
    let hash = policy_hash_hex(&EgressPolicy {
        mode: sandbox_protocol::EgressMode::Allowlist,
        domains: vec![DOMAIN.to_string()],
        cidrs: vec![],
    });
    let mut record = marker(&fx);
    if record.is_null() {
        record = serde_json::json!({
            "sandbox_id": "sbx-1", "policy_hash": hash,
            "project": "default", "revoked": [], "revoked_generations": {},
            "pending": [], "next_request": 0, "standing_fences": [],
            "published_attempts": []
        });
    }
    record["refresh_owed"] = serde_json::json!(true);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, record.to_string()).unwrap();
    repoint_eth0_to_an_unrestricted_bridge(&fx);
    let health = reconcile(&fx);
    assert_eq!(
        health.drift, 1,
        "device broadening masked by a bare owed mark: {health:?}"
    );
}

// ---------------------------------------------------------------------
// C58 G1 r4: generic fault sweeps (adopted from the r2/r3 security-review
// probes). Every refresh mutation point x {definite error, uncertain
// transport error, true crash + restart}: never widen, never over-convict,
// a denied destination left open convicts, and every non-convicted state
// RECOVERS (verifies) through bounded retries — no stranding.
// ---------------------------------------------------------------------

/// Crash-point sweep: let k mutations of a refresh succeed, then fail
/// every later mutation (a crash: nothing further lands, including the
/// fence-first recovery). Then (a) the fault clears and the reconciler
/// observes, or (b) the fault persists through the observation.
fn fault_sweep(
    scenario: &str,
    answer: Vec<Ipv4Addr>,
    keep_fault: bool,
    uncertain: bool,
) -> Vec<String> {
    let mut rows = Vec::new();
    let mut unexpected = Vec::new();
    for k in 0..80u32 {
        let mut fx = Fixture::new(&[A]);
        fx.runtime.client_mut().policy_observation_budget_override =
            Some(std::time::Duration::from_secs(30));
        fx.create(&[DOMAIN], &[]);
        *fx.answer.lock().unwrap() = Ok(answer.clone());
        let pin = fx.statedir().join("fail-mutations-after");
        fs::write(&pin, k.to_string()).unwrap();
        if uncertain {
            fs::write(fx.statedir().join("fail-mutations-uncertain"), "").unwrap();
        }
        let expiry = fx.state_expiry().unwrap();
        let pass = fx.pass(expiry - 100);
        if pass.failed.is_empty() {
            rows.push(format!("{scenario} k={k}: refresh completed ({pass:?})"));
            drop(fx);
            break;
        }
        if !keep_fault {
            fs::remove_file(&pin).unwrap();
            let _ = fs::remove_file(fx.statedir().join("fail-mutations-uncertain"));
        }
        let a_open_before = effectively_allows(&fx, "128.66.0.7");
        let bad_open_before = effectively_allows(&fx, "10.0.0.5");
        let health = reconcile(&fx);
        let a_open = effectively_allows(&fx, "128.66.0.7");
        let bad_open = effectively_allows(&fx, "10.0.0.5");
        let halted = fx.statedir().join("stopped-instance").exists();
        let row = format!(
            "{scenario} keep={keep_fault} k={k}: owed={} drift={} inconc={} verified={} halted={halted} A_open(before/after)={a_open_before}/{a_open} bad_open={bad_open_before}/{bad_open}",
            marker(&fx)["refresh_owed"],
            health.drift,
            health.inconclusive,
            health.verified
        );
        if bad_open_before || bad_open {
            unexpected.push(format!("WIDENED: {row}"));
        }
        let denial = scenario == "denial";
        // Ruling: a denied destination still open convicts; otherwise an
        // untampered, host-only sequence must never convict.
        let convict_ok = denial && a_open;
        if health.drift > 0 && !convict_ok {
            unexpected.push(format!("OVER-CONVICT: {row}"));
        }
        if health.drift == 0 && denial && a_open && health.verified == 0 {
            unexpected.push(format!("DENIED-OPEN-UNCONVICTED: {row}"));
        }
        if health.verified > 0 && marker(&fx)["refresh_owed"] == serde_json::json!(true) {
            unexpected.push(format!("VERIFIED-WHILE-OWED: {row}"));
        }
        if !keep_fault && health.drift == 0 {
            // A bounded observation can time out under host load. Its refusal
            // correctly blocks refresh until a later observation identifies
            // the owed work, so drive both periodic callers through retries.
            let mut health2 = health.clone();
            let mut row2 = String::new();
            for attempt in 1..=3 {
                let retry =
                    fx.pass(expiry - 100 + attempt * super::dns_refresh::REFRESH_RETRY_SECS);
                health2 = reconcile(&fx);
                row2.push_str(&format!(
                    "\n  retry {attempt}: refreshed={:?} failed={:?} skipped={:?} -> {health2:?}",
                    retry.refreshed, retry.failed, retry.skipped,
                ));
                let denied_open = denial && effectively_allows(&fx, "128.66.0.7");
                if effectively_allows(&fx, "10.0.0.5") || denied_open {
                    unexpected.push(format!("WIDENED: {row}{row2}"));
                }
                if health2.drift > 0 {
                    unexpected.push(format!("OVER-CONVICT: {row}{row2}"));
                    break;
                }
                if health2.verified > 0 && marker(&fx)["refresh_owed"] == serde_json::json!(true) {
                    unexpected.push(format!("VERIFIED-WHILE-OWED: {row}{row2}"));
                }
                if health2.verified == 1 {
                    break;
                }
            }
            if health2.verified != 1 {
                unexpected.push(format!("NOT-RECOVERED: {row}{row2}"));
            }
            rows.push(format!("{row}\n{row2}"));
        } else {
            rows.push(row);
        }
        drop(fx);
    }
    for row in &rows {
        eprintln!("{row}");
    }
    assert!(
        rows.last().is_some_and(|r| r.contains("completed")),
        "sweep never reached a completed refresh"
    );
    unexpected
}

/// One fault mode per test (definite cleared, definite persistent, and
/// G1-R3-2 UNCERTAIN transport error cleared): the modes are independent,
/// so splitting them lets the runner schedule them concurrently instead of
/// one test serially walking every mode's ~80 fixtures.
fn sweep_mode(scenario: &str, answer: Vec<Ipv4Addr>, keep_fault: bool, uncertain: bool) {
    let bad = fault_sweep(scenario, answer, keep_fault, uncertain);
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn an_uncertain_add_at_the_fourth_mutation_recovers() {
    let mut fx = Fixture::new(&[A]);
    fx.runtime.client_mut().policy_observation_budget_override =
        Some(std::time::Duration::from_secs(30));
    fx.create(&[DOMAIN], &[]);
    *fx.answer.lock().unwrap() = Ok(vec![A, B]);
    let dir = fx.statedir();
    fs::write(dir.join("fail-mutations-after"), "4").unwrap();
    fs::write(dir.join("fail-mutations-uncertain"), "").unwrap();
    let expiry = fx.state_expiry().unwrap();
    let first = fx.pass(expiry - 100);
    assert_eq!(first.failed.len(), 1, "{first:?}");
    fs::remove_file(dir.join("fail-mutations-after")).unwrap();
    fs::remove_file(dir.join("fail-mutations-uncertain")).unwrap();
    let health = reconcile(&fx);
    assert_eq!((health.drift, health.inconclusive), (0, 1), "{health:?}");
    let retry = fx.pass(expiry - 100 + super::dns_refresh::REFRESH_RETRY_SECS);
    let health = reconcile(&fx);
    assert_eq!(health.verified, 1, "{retry:?}; {health:?}");
}

macro_rules! sweep_tests {
    ($($name:ident: $scenario:literal, $answer:expr, $keep:literal, $uncertain:literal;)*) => {
        $(
            #[test]
            fn $name() {
                sweep_mode($scenario, $answer, $keep, $uncertain);
            }
        )*
    };
}

sweep_tests! {
    refresh_fault_sweep_rotation_cleared_never_widens_strands_or_overconvicts: "rotation", vec![B], false, false;
    refresh_fault_sweep_rotation_persistent_never_widens_strands_or_overconvicts: "rotation", vec![B], true, false;
    refresh_fault_sweep_rotation_uncertain_never_widens_strands_or_overconvicts: "rotation", vec![B], false, true;
    refresh_fault_sweep_denial_cleared_never_widens_strands_or_overconvicts: "denial", vec![A, Ipv4Addr::new(10, 0, 0, 5)], false, false;
    refresh_fault_sweep_denial_persistent_never_widens_strands_or_overconvicts: "denial", vec![A, Ipv4Addr::new(10, 0, 0, 5)], true, false;
    refresh_fault_sweep_denial_uncertain_never_widens_strands_or_overconvicts: "denial", vec![A, Ipv4Addr::new(10, 0, 0, 5)], false, true;
    refresh_fault_sweep_add_cleared_never_widens_strands_or_overconvicts: "add", vec![A, B], false, false;
    refresh_fault_sweep_add_persistent_never_widens_strands_or_overconvicts: "add", vec![A, B], true, false;
    refresh_fault_sweep_add_uncertain_never_widens_strands_or_overconvicts: "add", vec![A, B], false, true;
}

/// Replace sbx-1's runtime with a freshly constructed one over the SAME
/// shim and host state (a daemon restart): no in-memory refusals,
/// scheduler history, leases or lease owner survive.
fn restart_runtime(fx: &mut Fixture) {
    fx.runtime.client().debug_reset_dns_lease_owner("sbx-1");
    let binary = fx.runtime.client().binary.clone();
    let mut runtime = IncusKvmRuntime::new(super::kvm::IncusConfig {
        binary,
        project: "default".to_string(),
    })
    .expect("restarted runtime");
    runtime.override_network_test_state(fx.statedir().join("host-state"), Vec::new());
    let (seen, count) = (fx.answer.clone(), fx.lookups.clone());
    runtime.override_resolver(Arc::new(move |_domain, _wait| {
        count.fetch_add(1, Ordering::SeqCst);
        match &*seen.lock().unwrap() {
            Ok(addrs) => Ok(addrs.iter().copied().map(IpAddr::V4).collect()),
            Err(message) => Err(crate::RuntimeError::new(
                sandbox_protocol::SandboxErrorCode::Internal,
                message.clone(),
            )),
        }
    }));
    fx.runtime = runtime;
}

/// TRUE crash-point sweep: the shim snapshots the WHOLE state dir (live
/// Incus objects + host durable records) at the instant the (k+1)-th live
/// mutation is attempted, i.e. after exactly k mutations and before any
/// host error handling runs. The state dir is then rolled back to that
/// snapshot and a fresh runtime (restart) observes it, retries, observes.
fn crash_point_sweep(scenario: &str, answer: Vec<Ipv4Addr>) -> (Vec<String>, Vec<String>) {
    let mut rows = Vec::new();
    let mut bad = Vec::new();
    for k in 0..80u32 {
        let mut fx = Fixture::new(&[A]);
        fx.create(&[DOMAIN], &[]);
        *fx.answer.lock().unwrap() = Ok(answer.clone());
        let dir = fx.statedir();
        fs::write(dir.join("crash-snapshot"), "").unwrap();
        fs::write(dir.join("fail-mutations-after"), k.to_string()).unwrap();
        let expiry = fx.state_expiry().unwrap();
        let pass = fx.pass(expiry - 100);
        let crash = PathBuf::from(format!("{}.crash", dir.display()));
        if pass.failed.is_empty() && !crash.exists() {
            rows.push(format!("{scenario} k={k}: refresh completed"));
            drop(fx);
            break;
        }
        assert!(crash.exists(), "{scenario} k={k}: no snapshot ({pass:?})");
        // Roll the world back to the crash instant, then restart.
        fx.runtime.client().debug_reset_dns_lease_owner("sbx-1");
        let dead = PathBuf::from(format!("{}.dead", dir.display()));
        fs::rename(&dir, &dead).unwrap();
        fs::rename(&crash, &dir).unwrap();
        let _ = fs::remove_file(dir.join("fail-mutations-after"));
        let _ = fs::remove_file(dir.join("crash-snapshot"));
        restart_runtime(&mut fx);
        let owed = marker(&fx)["refresh_owed"].clone();
        let a_before = effectively_allows(&fx, "128.66.0.7");
        let health = reconcile(&fx);
        let a_after = effectively_allows(&fx, "128.66.0.7");
        let bad_open = effectively_allows(&fx, "10.0.0.5");
        let halted = dir.join("stopped-instance").exists();
        let row = format!(
            "{scenario} k={k}: owed={owed} A_open={a_before}/{a_after} bad_open={bad_open} drift={} inconc={} verified={} halted={halted}",
            health.drift, health.inconclusive, health.verified
        );
        if bad_open {
            bad.push(format!("WIDENED: {row}"));
        }
        let denial = scenario == "denial";
        if health.drift > 0 && !(denial && a_after) {
            bad.push(format!("OVER-CONVICT: {row}"));
        }
        if health.drift == 0 && denial && a_after {
            bad.push(format!("DENIED-OPEN-UNCONVICTED: {row}"));
        }
        if health.verified > 0 && marker(&fx)["refresh_owed"] == serde_json::json!(true) {
            bad.push(format!("VERIFIED-WHILE-OWED: {row}"));
        }
        if health.drift == 0 {
            let retry = fx.pass(expiry - 100 + super::dns_refresh::REFRESH_RETRY_SECS);
            let health2 = reconcile(&fx);
            let row2 = format!(
                "  retry: refreshed={:?} failed={} -> verified={} drift={} inconc={} A_open={} bad_open={}",
                retry.refreshed,
                retry.failed.len(),
                health2.verified,
                health2.drift,
                health2.inconclusive,
                effectively_allows(&fx, "128.66.0.7"),
                effectively_allows(&fx, "10.0.0.5"),
            );
            if health2.verified != 1 {
                bad.push(format!("NOT-RECOVERED: {row}{row2}"));
            }
            if effectively_allows(&fx, "10.0.0.5")
                || (denial && effectively_allows(&fx, "128.66.0.7"))
            {
                bad.push(format!("WIDENED-AFTER-RETRY: {row}{row2}"));
            }
            rows.push(format!("{row}\n{row2}"));
        } else {
            rows.push(row);
        }
        let _ = fs::remove_dir_all(&dead);
        drop(fx);
    }
    assert!(
        rows.last().is_some_and(|r| r.contains("completed")),
        "{scenario}: sweep never reached a completed refresh"
    );
    (rows, bad)
}

#[test]
fn a_crash_at_any_refresh_mutation_never_widens_strands_or_overconvicts() {
    let mut all_bad = Vec::new();
    for (scenario, answer) in [
        ("rotation", vec![B]),
        ("denial", vec![A, Ipv4Addr::new(10, 0, 0, 5)]),
        ("add", vec![A, B]),
    ] {
        let (rows, bad) = crash_point_sweep(scenario, answer);
        for row in rows {
            eprintln!("{row}");
        }
        all_bad.extend(bad);
    }
    assert!(all_bad.is_empty(), "{}", all_bad.join("\n"));
}

/// Owed-mode must still run EVERY non-DNS check and convict. Two owed
/// shapes: (a) refresh owed (rotation, publication failed); (b) SEED-1
/// settlement owed (recovery failing). Each tamper must convict + halt.
fn owed_shape(fx: &Fixture, shape: &str) {
    if shape == "refresh" {
        owed_refresh(fx, vec![B]);
        return;
    }
    // SEED-1 shape: a denial whose allow cannot be withdrawn (fenced
    // instead); recovery keeps failing in every observation.
    fx.create(&[DOMAIN], &[]);
    *fx.answer.lock().unwrap() = Ok(vec![Ipv4Addr::new(10, 0, 0, 5)]);
    fs::write(fx.statedir().join("fail-acl-allow-remove"), "").unwrap();
    let expiry = fx.state_expiry().unwrap();
    let pass = fx.pass(expiry - 100);
    assert_eq!(pass.failed.len(), 1, "{pass:?}");
    assert!(
        fx.runtime
            .client()
            .recover_dns_expiry_obligations("sbx-1")
            .is_err()
    );
}

#[test]
fn owed_mode_still_runs_and_convicts_every_non_dns_check() {
    let network = sandbox_network_names("sbx-1").0;
    let acl = sandbox_network_names("sbx-1").1;
    let mut failures = Vec::new();
    for shape in ["refresh", "seed1-recovery-failing"] {
        // Control: untampered owed shape never convicts.
        {
            let mut fx = Fixture::new(&[A]);
            fx.runtime.client_mut().policy_observation_budget_override =
                Some(std::time::Duration::from_secs(30));
            owed_shape(&fx, shape);
            let health = reconcile(&fx);
            eprintln!("{shape} control: {health:?}");
            if health.drift != 0 {
                failures.push(format!("{shape} control convicted: {health:?}"));
            }
        }
        for tamper in [
            "net-detach-acl",
            "net-default-ingress-allow",
            "net-nat-off",
            "net-foreign-tag",
            "acl-foreign-tag",
            "ingress-allow",
            "static-allow-cidr",
            "eth0-ipv4-filter-off",
            "eth0-mac-filter-off",
            "eth0-port-isolation-off",
            "eth0-extra-routes",
            "eth0-repoint",
        ] {
            let mut fx = Fixture::new(&[A]);
            fx.runtime.client_mut().policy_observation_budget_override =
                Some(std::time::Duration::from_secs(30));
            owed_shape(&fx, shape);
            let dir = fx.statedir();
            let conf = dir.join("networks").join(format!("{network}.conf"));
            let edit = |path: &Path, from: &str, to: &str| {
                let body = fs::read_to_string(path).unwrap();
                let new = body.replace(from, to);
                assert_ne!(
                    body,
                    new,
                    "{tamper}: precondition {from} in {}",
                    path.display()
                );
                fs::write(path, new).unwrap();
            };
            let dev = dir.join("device-eth0");
            match tamper {
                "net-detach-acl" => edit(&conf, &format!("security.acls={acl}"), "security.acls="),
                "net-default-ingress-allow" => edit(
                    &conf,
                    "security.acls.default.ingress.action=drop",
                    "security.acls.default.ingress.action=allow",
                ),
                "net-nat-off" => edit(&conf, "ipv4.nat=true", "ipv4.nat=false"),
                "net-foreign-tag" => edit(&conf, "=sbx-1", "=sbx-2"),
                "acl-foreign-tag" => edit(
                    &dir.join("acls").join(format!("{acl}.conf")),
                    "=sbx-1",
                    "=sbx-2",
                ),
                "ingress-allow" => {
                    let path = dir.join("acls").join(format!("{acl}.ingress"));
                    let mut body = fs::read_to_string(&path).unwrap();
                    body.push_str("action=allow\n");
                    fs::write(path, body).unwrap();
                }
                "static-allow-cidr" => append_egress(
                    &fx,
                    "action=allow destination=128.66.1.0/24 description=wssp-grant",
                ),
                "eth0-ipv4-filter-off" => edit(
                    &dev,
                    "security.ipv4_filtering=true",
                    "security.ipv4_filtering=false",
                ),
                "eth0-mac-filter-off" => edit(
                    &dev,
                    "security.mac_filtering=true",
                    "security.mac_filtering=false",
                ),
                "eth0-port-isolation-off" => edit(
                    &dev,
                    "security.port_isolation=true",
                    "security.port_isolation=false",
                ),
                "eth0-extra-routes" => {
                    let mut body = fs::read_to_string(&dev).unwrap();
                    body.push_str(",ipv4.routes=0.0.0.0/0");
                    fs::write(&dev, body).unwrap();
                }
                _ => repoint_eth0_to_an_unrestricted_bridge(&fx),
            }
            let health = reconcile(&fx);
            let halted = dir.join("stopped-instance").exists();
            eprintln!("{shape} {tamper}: {health:?} halted={halted}");
            if health.drift != 1 || !halted {
                failures.push(format!(
                    "{shape} {tamper}: NOT convicted: {health:?} halted={halted}"
                ));
            }
            drop(fx);
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// C58 G1 r4 regressions for previously exit-less states (G1-R3-1/2/3).

fn stop_sbx1(fx: &Fixture) {
    let create = create_req();
    fx.runtime
        .stop_sandbox(&crate::StopSandboxRequest {
            template_fingerprint: create.template_digest.clone(),
            sandbox_id: create.sandbox_id.clone(),
            instance_name: create.instance_name.clone(),
            operation_id: "stop".into(),
            idempotency_key: "stop".into(),
        })
        .expect("stop");
}

/// G1-R3-1: a sandbox stopped while its refresh is owed is committed by the
/// refresh pass WHILE STOPPED, so its start fence verifies again. Before r4
/// the pass skipped stopped VMs and every start/reconnect was refused until
/// teardown. Both the no-op renewal (first mutation fails) and the
/// post-mutation rotation (publication fails) shapes.
#[test]
fn a_stopped_vm_with_an_owed_refresh_is_committed_and_can_start_again() {
    for variant in ["renewal-first-mutation-fails", "rotation-publication-fails"] {
        let fx = Fixture::new(&[A]);
        fx.create(&[DOMAIN], &[]);
        let dir = fx.statedir();
        if variant.starts_with("renewal") {
            fs::write(dir.join("fail-mutations-after"), "0").unwrap();
        } else {
            *fx.answer.lock().unwrap() = Ok(vec![B]);
            fs::write(dir.join("fail-raw-dnsmasq"), "").unwrap();
        }
        let expiry = fx.state_expiry().unwrap();
        let pass = fx.pass(expiry - 100);
        assert_eq!(pass.failed.len(), 1, "{variant}: {pass:?}");
        assert_eq!(marker(&fx)["refresh_owed"], serde_json::json!(true));
        let _ = fs::remove_file(dir.join("fail-mutations-after"));
        let _ = fs::remove_file(dir.join("fail-raw-dnsmasq"));
        stop_sbx1(&fx);
        let pass = fx.pass(expiry - 100 + super::dns_refresh::REFRESH_RETRY_SECS);
        assert_eq!(
            pass.refreshed,
            vec!["sbx-1".to_string()],
            "{variant}: the owed commit runs for a stopped VM: {pass:?}"
        );
        let marker = marker(&fx);
        assert!(
            marker.is_null() || marker["refresh_owed"] == serde_json::json!(false),
            "{variant}: {marker}"
        );
        fx.runtime
            .client()
            .verify_provisioned_enforcement("sbx-1")
            .unwrap_or_else(|err| panic!("{variant}: the start fence verifies: {err:?}"));
        // Not owed any more: a stopped VM is not renewed by later passes.
        let pass = fx.pass(expiry - 100 + 2 * super::dns_refresh::REFRESH_RETRY_SECS);
        assert!(pass.refreshed.is_empty(), "{variant}: {pass:?}");
        drop(fx);
    }
}

/// G1-R3-2: an allow add that ends with an UNCERTAIN transport error (the
/// request may or may not land) at rotation k=8 / add k=8 / add k=13 must
/// not keep the sandbox inconclusive forever: once a later refresh commits,
/// the never-landed request is a non-blocking obligation and the sandbox
/// verifies. Never halted, and B (granted) is the only new address open.
#[test]
fn an_uncertain_allow_never_strands_the_sandbox() {
    for (scenario, answer, k) in [
        ("rotation", vec![B], 8u32),
        ("add", vec![A, B], 8),
        ("add", vec![A, B], 13),
    ] {
        let fx = Fixture::new(&[A]);
        fx.create(&[DOMAIN], &[]);
        *fx.answer.lock().unwrap() = Ok(answer.clone());
        let dir = fx.statedir();
        fs::write(dir.join("fail-mutations-after"), k.to_string()).unwrap();
        fs::write(dir.join("fail-mutations-uncertain"), "").unwrap();
        let expiry = fx.state_expiry().unwrap();
        let pass = fx.pass(expiry - 100);
        assert_eq!(pass.failed.len(), 1, "{scenario} k={k}: {pass:?}");
        let _ = fs::remove_file(dir.join("fail-mutations-after"));
        let _ = fs::remove_file(dir.join("fail-mutations-uncertain"));
        let mut verified = false;
        for step in 1..=3u64 {
            let health = reconcile(&fx);
            assert_eq!(health.drift, 0, "{scenario} k={k} step {step}: {health:?}");
            if health.verified == 1 {
                verified = true;
                break;
            }
            fx.pass(expiry - 100 + step * super::dns_refresh::REFRESH_RETRY_SECS);
        }
        assert!(
            verified,
            "{scenario} k={k}: stranded inconclusive; marker={}",
            marker(&fx)
        );
        assert!(!dir.join("stopped-instance").exists());
        assert!(!effectively_allows(&fx, "10.0.0.5"));
        drop(fx);
    }
}

/// G1-R3-2 (crash + restart): the daemon dies at the instant of the same
/// allow mutation (state rolled back to the crash point, fresh runtime).
/// The sandbox must verify again within a bounded number of passes.
#[test]
fn a_crash_interrupted_allow_never_strands_the_sandbox() {
    for (scenario, answer, k) in [
        ("rotation", vec![B], 8u32),
        ("add", vec![A, B], 8),
        ("add", vec![A, B], 13),
    ] {
        let mut fx = Fixture::new(&[A]);
        fx.create(&[DOMAIN], &[]);
        *fx.answer.lock().unwrap() = Ok(answer.clone());
        let dir = fx.statedir();
        fs::write(dir.join("crash-snapshot"), "").unwrap();
        fs::write(dir.join("fail-mutations-after"), k.to_string()).unwrap();
        let expiry = fx.state_expiry().unwrap();
        let _ = fx.pass(expiry - 100);
        let crash = PathBuf::from(format!("{}.crash", dir.display()));
        assert!(crash.exists(), "{scenario} k={k}: crash point reached");
        fx.runtime.client().debug_reset_dns_lease_owner("sbx-1");
        let dead = PathBuf::from(format!("{}.dead", dir.display()));
        fs::rename(&dir, &dead).unwrap();
        fs::rename(&crash, &dir).unwrap();
        let _ = fs::remove_file(dir.join("fail-mutations-after"));
        let _ = fs::remove_file(dir.join("crash-snapshot"));
        restart_runtime(&mut fx);
        let mut verified = false;
        for step in 0..=3u64 {
            let health = reconcile(&fx);
            assert_eq!(health.drift, 0, "{scenario} k={k} step {step}: {health:?}");
            if health.verified == 1 {
                verified = true;
                break;
            }
            fx.pass(expiry - 100 + (step + 1) * super::dns_refresh::REFRESH_RETRY_SECS);
        }
        assert!(
            verified,
            "{scenario} k={k}: stranded after restart; marker={}",
            marker(&fx)
        );
        let _ = fs::remove_dir_all(&dead);
        drop(fx);
    }
}

/// G1-R3-2 exit for a LANDED uncertain request: the journaled identity
/// appears live after the sandbox verified (a late daemon-side apply). It is
/// host-issued, so not drift — even once its expiry-ledger entry has settled
/// ("settled": the journal is then the only record of it). The sandbox is
/// owed (`RefreshOwed`), the next refresh withdraws it and retires the
/// journal entry, and it verifies.
#[test]
fn a_late_landing_uncertain_allow_is_withdrawn_by_the_next_refresh() {
    for ledger in ["armed", "settled"] {
        let fx = Fixture::new(&[A]);
        fx.create(&[DOMAIN], &[]);
        *fx.answer.lock().unwrap() = Ok(vec![B]);
        let dir = fx.statedir();
        fs::write(dir.join("fail-mutations-after"), "8").unwrap();
        fs::write(dir.join("fail-mutations-uncertain"), "").unwrap();
        let expiry = fx.state_expiry().unwrap();
        fx.pass(expiry - 100);
        let _ = fs::remove_file(dir.join("fail-mutations-after"));
        let _ = fs::remove_file(dir.join("fail-mutations-uncertain"));
        fx.pass(expiry - 100 + super::dns_refresh::REFRESH_RETRY_SECS);
        assert_eq!(
            reconcile(&fx).verified,
            1,
            "{ledger}: marker={}",
            marker(&fx)
        );
        let pending = marker(&fx)["pending"]
            .as_array()
            .and_then(|pending| pending.first().cloned())
            .expect("the uncertain request stays journaled (non-blocking)");
        let (description, destination) = (
            pending["description"].as_str().unwrap().to_string(),
            pending["destination"].as_str().unwrap().to_string(),
        );
        if ledger == "settled" {
            // The uncertain identity's expiry obligation has settled: drop it
            // from the durable ledger (and the in-memory owner).
            let path = dir.join("host-state/dns-revocations/sbx-1.lease.json");
            let mut parsed: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
            parsed["entries"]
                .as_array_mut()
                .unwrap()
                .retain(|entry| entry["allow_tag"] != description.as_str());
            fs::write(&path, parsed.to_string()).unwrap();
            fx.runtime.client().debug_reset_dns_lease_owner("sbx-1");
        }
        // The late apply lands.
        append_egress(
            &fx,
            &format!("action=allow destination={destination} description={description}"),
        );
        let health = reconcile(&fx);
        assert_eq!(
            (health.drift, health.inconclusive),
            (0, 1),
            "{ledger}: a landed host-issued request is owed work, not drift: {health:?}"
        );
        let pass = fx.pass(expiry - 100 + 2 * super::dns_refresh::REFRESH_RETRY_SECS);
        assert_eq!(
            pass.refreshed,
            vec!["sbx-1".to_string()],
            "{ledger}: {pass:?}"
        );
        assert!(
            !fx.egress().contains(&format!("description={description}")),
            "{ledger}: the landed request is withdrawn: {}",
            fx.egress()
        );
        assert_eq!(
            reconcile(&fx).verified,
            1,
            "{ledger}: marker={}",
            marker(&fx)
        );
        assert!(!dir.join("stopped-instance").exists());
        drop(fx);
    }
}

/// G1-R3-3: the observation's read budget is a CHILD of the caller's
/// permit. A revocation that arrives while the (re-scoped) reads are
/// parked stops the observation; it never verifies.
#[test]
fn a_parent_revocation_stops_the_rescoped_reads() {
    for skips in 0..4u32 {
        let fx = Fixture::new(&[A]);
        fx.create(&[DOMAIN], &[]);
        let mut client = fx.runtime.client().clone();
        let permit = Arc::new(crate::RuntimePermit::with_timeout(
            std::time::Duration::from_secs(4),
        ));
        client.cancelled = Some(permit.clone());
        let dir = fx.statedir();
        fs::write(dir.join("barrier-acl-read"), skips.to_string()).unwrap();
        let handle = std::thread::spawn(move || client.enforcement_observation("sbx-1"));
        while dir.join("barrier-acl-read").exists() && !handle.is_finished() {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        if dir.join("barrier-acl-read").exists() {
            // Fewer reads than `skips`: nothing parked; nothing to test.
            assert!(skips > 1, "the observation reads the ACL at least twice");
            drop(fx);
            continue;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
        permit.revoke();
        std::thread::sleep(std::time::Duration::from_millis(1500));
        // Before the parked read is released: the revocation alone must
        // have ended the observation.
        let finished_before_release = handle.is_finished();
        fs::write(dir.join("release-acl-read-barrier"), "").unwrap();
        let verdict = handle.join().unwrap();
        assert!(
            matches!(verdict, super::acl::EnforcementVerdict::Inconclusive(_)),
            "skips={skips}: {verdict:?}"
        );
        // The parked read was cut by the REVOCATION (propagated to the
        // child), not by the read budget, which runs to ~4 s.
        // skips=0 parks DNS expiry recovery's own probe, which is
        // permit-free by design (it must finish fencing); from skips=1 the
        // parked read is the observation's own.
        assert!(
            skips == 0 || finished_before_release,
            "skips={skips}: the revocation must reach the re-scoped reads"
        );
        drop(fx);
    }
}

/// G1-R3-3: a permit already elapsed (or revoked) before the observation
/// gets no fresh read budget: inconclusive, as before C58.
#[test]
fn a_spent_or_revoked_permit_is_never_rescoped() {
    for spent in ["elapsed", "revoked"] {
        let fx = Fixture::new(&[A]);
        fx.create(&[DOMAIN], &[]);
        let mut client = fx.runtime.client().clone();
        let permit = Arc::new(crate::RuntimePermit::with_timeout(
            std::time::Duration::from_millis(if spent == "elapsed" { 0 } else { 1000 }),
        ));
        if spent == "revoked" {
            permit.revoke();
        }
        client.cancelled = Some(permit);
        let verdict = client.enforcement_observation("sbx-1");
        assert!(
            matches!(verdict, super::acl::EnforcementVerdict::Inconclusive(_)),
            "{spent}: {verdict:?}"
        );
        drop(fx);
    }
}

// C58 G1F-1 (final review): a create retry that ADOPTS an existing VM must
// never roll back that VM's bridge and ACL. Adopted from the final review's
// probes.

fn policy_create_request() -> crate::CreateSandboxRequest {
    let policy = EgressPolicy {
        mode: sandbox_protocol::EgressMode::Allowlist,
        domains: vec![DOMAIN.to_string()],
        cidrs: vec![],
    };
    let mut request = create_req();
    request.egress_policy_hash = Some(policy_hash_hex(&policy));
    request.egress_policy = Some(policy);
    request
}

fn network_teardown_lines(fx: &Fixture) -> Vec<String> {
    fs::read_to_string(&fx.log)
        .unwrap_or_default()
        .lines()
        .filter(|line| {
            line.contains("network delete")
                || line.contains("network acl delete")
                || line.starts_with("stop ")
                || line.starts_with("delete ")
        })
        .map(str::to_string)
        .collect()
}

/// G1F-1 regression: a verified sandbox with a pending-only uncertain allow
/// (never landed, or landed late) gets a create retry over its EXISTING VM.
/// The retry may be refused (owed work), but it never deletes the live
/// bridge/ACL, and the sandbox is never convicted, halted or destroyed.
#[test]
fn a_create_retry_over_an_existing_vm_never_tears_down_its_network() {
    for variant in ["committed", "pending-never-landed", "pending-landed-late"] {
        let fx = Fixture::new(&[A]);
        fx.create(&[DOMAIN], &[]);
        *fx.answer.lock().unwrap() = Ok(vec![B]);
        let dir = fx.statedir();
        let expiry = fx.state_expiry().unwrap();
        if variant == "committed" {
            fx.pass(expiry - 100);
        } else {
            fs::write(dir.join("fail-mutations-after"), "8").unwrap();
            fs::write(dir.join("fail-mutations-uncertain"), "").unwrap();
            fx.pass(expiry - 100);
            let _ = fs::remove_file(dir.join("fail-mutations-after"));
            let _ = fs::remove_file(dir.join("fail-mutations-uncertain"));
            fx.pass(expiry - 100 + super::dns_refresh::REFRESH_RETRY_SECS);
        }
        assert_eq!(
            reconcile(&fx).verified,
            1,
            "{variant}: verified before the retry"
        );
        if variant == "pending-landed-late" {
            let pending = marker(&fx)["pending"]
                .as_array()
                .and_then(|pending| pending.first().cloned())
                .expect("journaled uncertain request");
            append_egress(
                &fx,
                &format!(
                    "action=allow destination={} description={}",
                    pending["destination"].as_str().unwrap(),
                    pending["description"].as_str().unwrap()
                ),
            );
        }
        let before = network_teardown_lines(&fx).len();
        let result = fx.runtime.create_bound(&policy_create_request());
        let teardown: Vec<String> = network_teardown_lines(&fx)
            .into_iter()
            .skip(before)
            .collect();
        assert!(
            teardown.is_empty(),
            "{variant}: the retry tore the live sandbox down: {teardown:?} (create={:?})",
            result
                .as_ref()
                .map(|_| ())
                .map_err(|err| format!("{err:?}"))
        );
        let network = sandbox_network_names("sbx-1").0;
        assert!(
            dir.join("networks")
                .join(format!("{network}.conf"))
                .exists()
        );
        if variant != "pending-landed-late" {
            assert!(result.is_ok(), "{variant}: {:?}", result.err());
        }
        let health = reconcile(&fx);
        assert_eq!(health.drift, 0, "{variant}: {health:?}");
        fx.runtime
            .drain_enforcement_losses(&|_, _| Ok(()))
            .expect("drain");
        assert!(
            network_teardown_lines(&fx).len() == before,
            "{variant}: no conviction teardown afterwards: {:?}",
            network_teardown_lines(&fx)
        );
        drop(fx);
    }
}

/// An uncertain allow to B, then the grant
/// rotates AWAY from B and commits; B's late apply then lands. B is never
/// effectively open, readiness never verifies while it is live, and the
/// next refresh withdraws it.
#[test]
fn a_late_landing_to_an_ungranted_destination_is_never_open() {
    const C: Ipv4Addr = Ipv4Addr::new(128, 66, 0, 9);
    let fx = Fixture::new(&[A]);
    fx.create(&[DOMAIN], &[]);
    *fx.answer.lock().unwrap() = Ok(vec![B]);
    let dir = fx.statedir();
    fs::write(dir.join("fail-mutations-after"), "8").unwrap();
    fs::write(dir.join("fail-mutations-uncertain"), "").unwrap();
    let expiry = fx.state_expiry().unwrap();
    fx.pass(expiry - 100);
    let _ = fs::remove_file(dir.join("fail-mutations-after"));
    let _ = fs::remove_file(dir.join("fail-mutations-uncertain"));
    *fx.answer.lock().unwrap() = Ok(vec![C]);
    let mut t = expiry - 100;
    for _ in 1..=4u64 {
        t += super::dns_refresh::REFRESH_RETRY_SECS;
        fx.pass(t);
        reconcile(&fx);
    }
    let pending: Vec<(String, String)> = marker(&fx)["pending"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|p| {
            (
                p["description"].as_str().unwrap_or("").to_string(),
                p["destination"].as_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    assert!(!pending.is_empty(), "the uncertain request stays journaled");
    for (description, destination) in &pending {
        append_egress(
            &fx,
            &format!("action=allow destination={destination} description={description}"),
        );
        let ip = destination.trim_end_matches("/32");
        assert!(
            !effectively_allows(&fx, ip),
            "{destination} open after late landing"
        );
        assert_ne!(
            reconcile(&fx).verified,
            1,
            "verified while {destination} live"
        );
        t += super::dns_refresh::REFRESH_RETRY_SECS;
        fx.pass(t);
        assert!(
            !fx.egress().contains(&format!("description={description}")),
            "{description} not withdrawn"
        );
        assert_eq!(reconcile(&fx).verified, 1);
    }
    assert!(!dir.join("stopped-instance").exists());
}

/// Coordinator ruling (byte budget): a refresh whose recompiled ACL body
/// would exceed 64 KiB publishes NOTHING — no ACL change, no resolver PATCH,
/// no state commit — keeps the last-good rules and reports the typed
/// `egress_refresh_over_budget` warning. A later in-budget refresh publishes.
#[test]
fn a_refresh_over_the_byte_budget_keeps_the_last_good_rules() {
    let fx = Fixture::new(&[A]);
    fx.create(&[DOMAIN], &[]);
    assert!(fx.allows("128.66.0.7"));
    let near = unix_now().unwrap() + 100;
    fx.set_state_expiry(near);
    let (egress, dnsmasq) = (fx.egress(), fx.dnsmasq());
    let state_path = fx.statedir().join("host-state/dns-policy/sbx-1.json");
    let plan_path = fx.statedir().join("host-state/network-plans/sbx-1.json");
    let (state, plan) = (
        fs::read_to_string(&state_path).unwrap(),
        fs::read_to_string(&plan_path).unwrap(),
    );
    // 120 addresses x ~660 B of rules each: ~79 KiB, over the budget and
    // inside the 96 KiB inline-fallback window growth must never use.
    let grown: Vec<Ipv4Addr> = (1..=120).map(|i| Ipv4Addr::new(128, 66, 1, i)).collect();
    *fx.answer.lock().unwrap() = Ok(grown);
    let reports = Mutex::new(Vec::new());
    let observe = |report: &crate::DnsRefreshReport| reports.lock().unwrap().push(report.clone());
    fx.runtime
        .refresh_dns_grants_observed(&["sbx-1".to_string()], &observe)
        .expect("an over-budget refresh is a warning, not a failure");
    {
        let reports = reports.lock().unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(
            reports[0].warning,
            Some(crate::EgressRefusal::RefreshOverBudget)
        );
        assert_eq!(
            reports[0].warning.unwrap().as_str(),
            "egress_refresh_over_budget"
        );
        assert!(!reports[0].changed_grants);
    }
    assert_eq!(fx.egress(), egress, "the last-good ACL stays");
    assert_eq!(fx.dnsmasq(), dnsmasq, "the last-good resolver stays");
    assert_eq!(fs::read_to_string(&state_path).unwrap(), state);
    assert_eq!(fs::read_to_string(&plan_path).unwrap(), plan);
    assert!(!fx.allows("128.66.1.5"));
    assert!(
        !fs::read_to_string(&fx.log)
            .unwrap_or_default()
            .lines()
            .any(|line| line.contains("-X PUT") && line.contains("-d ")),
        "growth never takes the inline fallback"
    );
    // Back within budget: the next due refresh (past the attempt backoff)
    // publishes.
    *fx.answer.lock().unwrap() = Ok(vec![Ipv4Addr::new(128, 66, 1, 9)]);
    let pass = fx.pass(unix_now().unwrap() + 60);
    assert_eq!(pass.refreshed, vec!["sbx-1".to_string()], "{pass:?}");
    assert!(fx.allows("128.66.1.9"));
}

/// The DNS refresh's host-owned binding serves a
/// restored instance (base image = the stored disk, tagged restore base).
#[test]
fn a_restored_instance_domain_grant_is_refreshed() {
    const B: Ipv4Addr = Ipv4Addr::new(128, 66, 0, 9);
    const DISK: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    let mut fx = Fixture::new(&[A]);
    let mut client = fx.runtime.client().clone();
    let clock = DnsTestClock::install(&mut client);
    fx.runtime = IncusKvmRuntime::from_test_client(client);
    fx.create(&[DOMAIN], &[]);
    let statedir = fx.statedir();
    fs::write(statedir.join("config/volatile.base_image"), DISK).unwrap();
    fs::write(
        statedir.join("config/user.flycockpit.restore_base"),
        format!("sha256:{DISK}"),
    )
    .unwrap();
    *fx.answer.lock().unwrap() = Ok(vec![B]);
    clock.advance(160);
    let pass = super::dns_refresh::refresh_pass(
        fx.runtime.client(),
        fx.runtime.dns_refresh_scheduler(),
        &["sbx-1".to_string()],
    )
    .unwrap();
    assert_eq!(pass.refreshed, vec!["sbx-1".to_string()], "{pass:?}");
    assert!(fx.allows("128.66.0.9"), "the restored VM's grant moved");
    // A forged lineage (restored base, no valid tag) is never refreshed.
    fs::write(
        statedir.join("config/user.flycockpit.restore_base"),
        "not-a-fingerprint",
    )
    .unwrap();
    clock.advance(160);
    let pass = super::dns_refresh::refresh_pass(
        fx.runtime.client(),
        fx.runtime.dns_refresh_scheduler(),
        &["sbx-1".to_string()],
    );
    assert!(
        pass.as_ref()
            .map_or(true, |pass| !pass.refreshed.contains(&"sbx-1".to_string())),
        "{pass:?}"
    );
}
