use super::*;
use crate::sandbox_relay::test_support::FakeGuardServer;
use sandbox_runtime::FakeRuntime;
use sandbox_runtime::guard_probe::FakeGuardProbe;

fn node(probe: Option<Arc<dyn GuardProbe>>) -> NodeEgress {
    NodeEgress::new(probe, &crate::config::Config::default())
}

#[test]
fn the_server_clear_is_pushed_and_a_new_instance_is_pushed_again() {
    let guard = FakeGuardServer::start();
    let node = node(Some(guard.probe()));
    // Before any tick: nothing observed, nothing renewed.
    let report = node.report();
    assert!(!report.guard_ok);
    assert_eq!(report.guard_reason.as_deref(), Some("guard_unreachable"));
    // The server's explicit `configured:false` frame.
    assert!(node.receive_blocklist(&frame(&[])));

    node.tick();
    let first = node.report();
    assert!(first.guard_ok, "{first:?}");
    assert_eq!(first.guard_reason, None);
    assert_eq!(
        first.guard_instance_id.as_deref(),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
    assert!(first.guard_generation.unwrap() >= 1);
    assert!(first.message(1, 1).is_valid());
    node.tick();
    assert_eq!(guard.pushes().len(), 1, "same instance: no re-push");

    // Guard restart: deployment is `unknown` again until the daemon pushes.
    guard.restart_as("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    node.tick();
    let second = node.report();
    assert!(second.guard_ok, "{second:?}");
    assert_eq!(
        second.guard_instance_id.as_deref(),
        Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    );
    assert!(!second.same_state(&first));
    assert_eq!(
        guard.pushes(),
        [
            ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(), false),
            ("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(), false),
        ]
    );
}

#[test]
fn an_unhealthy_guard_reports_its_reason_and_identity_but_never_ok() {
    let guard = FakeGuardServer::start();
    let node = node(Some(guard.probe()));
    assert!(node.receive_blocklist(&frame(&[])));
    node.tick();
    guard.set_healthy(false);
    node.tick();
    let report = node.report();
    assert!(!report.guard_ok);
    assert_eq!(report.guard_reason.as_deref(), Some("guard_not_ok"));
    assert!(report.guard_instance_id.is_some() && report.guard_generation.is_some());
    let message = report.message(3, 9);
    assert!(message.is_valid());
    assert!(!message.guard_ok);
    guard.set_healthy(true);
    node.tick();
    assert!(node.report().guard_ok);
}

#[test]
fn unreachable_missing_and_stale_observations_never_renew_the_lease() {
    let none = node(None);
    none.tick();
    assert_eq!(
        none.report().guard_reason.as_deref(),
        Some("guard_unreachable")
    );
    let gone = node(Some(Arc::new(
        sandbox_runtime::guard::client::SocketGuardProbe::new("/nonexistent/wssp-guard.sock"),
    )));
    gone.tick();
    let report = gone.report();
    assert!(!report.guard_ok && report.guard_instance_id.is_none());
    assert!(report.message(1, 1).is_valid());

    // A healthy observation that is too old reads as unreachable.
    let fake = node(Some(Arc::new(FakeGuardProbe::healthy())));
    fake.tick();
    assert!(fake.report().guard_ok);
    if let Some(observation) = lock(&fake.observation).as_mut() {
        observation.at = Instant::now()
            .checked_sub(OBSERVATION_MAX_AGE + Duration::from_secs(1))
            .unwrap();
    }
    assert_eq!(
        fake.report().guard_reason.as_deref(),
        Some("guard_unreachable")
    );
}

#[test]
fn a_stale_generation_of_the_same_instance_is_ignored() {
    let probe = FakeGuardProbe::healthy();
    let node = node(Some(Arc::new(probe.clone())));
    assert!(node.receive_blocklist(&frame(&[])));
    let mut status = FakeGuardProbe::healthy_status(&[]);
    status.generation = 5;
    probe.set_status(Some(status.clone()));
    node.tick();
    assert_eq!(node.report().guard_generation, Some(5));
    // An older answer (and an unhealthy one) from the same instance.
    status.generation = 3;
    status.ok = false;
    probe.set_status(Some(status));
    node.tick();
    let report = node.report();
    assert!(report.guard_ok);
    assert_eq!(report.guard_generation, Some(5));
    assert_eq!(probe.pushes(), [false], "pushed once, configured:false");
}

#[test]
fn generation_zero_or_an_invalid_instance_is_not_ok() {
    let probe = FakeGuardProbe::healthy();
    let node = node(Some(Arc::new(probe.clone())));
    let mut status = FakeGuardProbe::healthy_status(&[]);
    status.generation = 0;
    probe.set_status(Some(status.clone()));
    node.tick();
    let report = node.report();
    assert!(!report.guard_ok && report.guard_generation.is_none());
    assert!(report.message(1, 1).is_valid());
    status.generation = 2;
    status.instance_id = "not valid!".into();
    probe.set_status(Some(status));
    node.tick();
    assert!(!node.report().guard_ok);
}

#[test]
fn open_egress_is_permitted_for_own_sandboxes_or_with_live_consent() {
    let runtime = FakeRuntime::new();
    let node = node(Some(Arc::new(FakeGuardProbe::healthy())));
    // Before hello.ok nobody is "own".
    assert!(!node.admission("owner-1", &runtime).open_egress_permitted);
    node.set_host_owner("owner-1");
    let own = node.admission("owner-1", &runtime);
    assert!(own.open_egress_permitted && own.guard_ok);
    assert!(
        !node
            .admission("someone-else", &runtime)
            .open_egress_permitted
    );
    node.apply_policy(true, true, EgressSettings::default());
    assert!(
        node.admission("someone-else", &runtime)
            .open_egress_permitted
    );
    node.apply_policy(false, true, EgressSettings::default());
    assert!(
        !node
            .admission("someone-else", &runtime)
            .open_egress_permitted
    );
    // guard_ok is the runtime's fresh check, not the heartbeat.
    runtime.guard().set_healthy(false);
    assert!(!node.admission("owner-1", &runtime).guard_ok);
}

#[test]
fn guest_sudo_consent_is_own_always_foreign_only_with_consent_and_reloads_live() {
    let fresh = node(None);
    // Before hello.ok nobody is "own"; the default consent still allows.
    assert!(fresh.guest_sudo_permitted("owner-1"));
    fresh.apply_policy(false, false, EgressSettings::default());
    assert!(
        !fresh.guest_sudo_permitted("owner-1"),
        "no owner yet: foreign"
    );
    fresh.set_host_owner("owner-1");
    assert!(
        fresh.guest_sudo_permitted("owner-1"),
        "own is always permitted"
    );
    assert!(!fresh.guest_sudo_permitted("someone-else"));
    assert!(!fresh.guest_sudo_permitted(""));
    fresh.apply_policy(false, true, EgressSettings::default());
    assert!(fresh.guest_sudo_permitted("someone-else"), "live reload");
    assert!(fresh.report().allow_guest_sudo_for_others);
    fresh.apply_policy(false, false, EgressSettings::default());
    assert!(!fresh.report().allow_guest_sudo_for_others);
}

#[test]
fn create_settings_carry_node_config_and_the_guard_blocklist_or_refuse() {
    let node = node(None);
    let settings = EgressSettings {
        block_smtp: false,
        block_external_dns: true,
        dns_upstreams: vec!["9.9.9.9".parse().unwrap()],
        ..Default::default()
    };
    node.apply_policy(false, true, settings.clone());
    assert_eq!(node.create_settings().unwrap(), settings);

    let guard = FakeGuardServer::start();
    let with_guard = super::NodeEgress::new(Some(guard.probe()), &crate::config::Config::default());
    let captured = with_guard.create_settings().unwrap();
    assert_eq!(
        captured.domain_blocklist.root_digest.as_deref(),
        Some("sha256:root")
    );
    assert!(captured.block_smtp);

    let gone = super::NodeEgress::new(
        Some(Arc::new(
            sandbox_runtime::guard::client::SocketGuardProbe::new("/nonexistent/wssp-guard.sock"),
        )),
        &crate::config::Config::default(),
    );
    let refused = gone.create_settings().unwrap_err();
    assert_eq!(
        refused.egress_refusal(),
        Some(sandbox_runtime::egress::EgressRefusal::GuardUnavailable)
    );
}

fn frame(entries: &[&str]) -> sandbox_protocol::EgressBlocklistV11 {
    let entries: Vec<String> = entries.iter().map(|e| e.to_string()).collect();
    sandbox_protocol::EgressBlocklistV11 {
        configured: !entries.is_empty(),
        digest: blocklist_digest(&entries),
        entries,
        invalid: false,
    }
}

fn invalid_frame() -> sandbox_protocol::EgressBlocklistV11 {
    sandbox_protocol::EgressBlocklistV11 {
        configured: true,
        entries: Vec::new(),
        digest: blocklist_digest(&[]),
        invalid: true,
    }
}

#[test]
fn blocklist_digest_matches_the_shared_fixture() {
    let cases: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../crates/sandbox-protocol/fixtures/egress_blocklist_cases.json"
    ))
    .unwrap();
    let mut checked = 0;
    for case in cases["env"].as_array().unwrap() {
        let Some(digest) = case["digest"].as_str() else {
            continue;
        };
        let entries: Vec<String> = serde_json::from_value(case["entries"].clone()).unwrap();
        assert_eq!(blocklist_digest(&entries), digest, "{}", case["name"]);
        checked += 1;
    }
    assert!(checked >= 3);
    for frame in cases["frames"]["valid"].as_array().unwrap() {
        let mut body = frame.clone();
        body.as_object_mut().unwrap().remove("type");
        let list: sandbox_protocol::EgressBlocklistV11 = serde_json::from_value(body).unwrap();
        assert_eq!(blocklist_digest(&list.entries), list.digest);
    }
}

#[test]
fn server_blocklist_is_pushed_persisted_and_restored_on_restart() {
    let guard = FakeGuardServer::start();
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join(DEPLOYMENT_BLOCKLIST_FILE);
    let node = node(Some(guard.probe())).with_deployment_store(store.clone());
    // Never received a list: unknown, nothing pushed, not ok.
    node.tick();
    assert!(!node.report().guard_ok);
    assert!(guard.pushes().is_empty());
    // A frame whose digest does not match is ignored (no push, no file).
    let mut forged = frame(&["203.0.113.0/24"]);
    forged.digest = blocklist_digest(&["198.51.100.0/24".to_string()]);
    assert!(!node.receive_blocklist(&forged));
    node.tick();
    assert!(!store.exists());
    // The server's list: pushed on the next tick, kept on disk.
    assert!(node.receive_blocklist(&frame(&["203.0.113.0/24", "bad.example"])));
    assert!(store.exists());
    node.tick();
    assert!(node.report().guard_ok, "{:?}", node.report());
    // The same list again is not a change.
    assert!(node.receive_blocklist(&frame(&["203.0.113.0/24", "bad.example"])));
    node.tick();
    let aaaa = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
    assert_eq!(guard.pushes(), [(aaaa, true)]);

    // A daemon restart re-pushes the persisted list, never configured:false.
    let restarted = super::NodeEgress::new(Some(guard.probe()), &crate::config::Config::default())
        .with_deployment_store(store.clone());
    guard.restart_as("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    restarted.tick();
    assert!(restarted.report().guard_ok);
    assert_eq!(
        guard.pushes().last().unwrap(),
        &("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(), true)
    );
    // The server's list later becomes invalid: the last list stays.
    assert!(restarted.receive_blocklist(&invalid_frame()));
    restarted.tick();
    assert!(restarted.report().guard_ok);
    assert_eq!(guard.pushes().len(), 2, "invalid is never pushed");
    // Explicit configured:false clears it (the server unset the variable).
    assert!(restarted.receive_blocklist(&frame(&[])));
    restarted.tick();
    assert_eq!(
        guard.pushes().last().unwrap(),
        &("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(), false)
    );
}

/// M13: an invalid server list with no earlier list from the server refuses
/// new sandboxes (heartbeat and early admission) instead of running empty.
#[test]
fn an_invalid_server_list_without_an_earlier_one_refuses_admission() {
    let guard = FakeGuardServer::start();
    let runtime = FakeRuntime::new();
    let node = node(Some(guard.probe()));
    node.set_host_owner("owner-1");
    // FakeRuntime's own guard is healthy: only the refusal gates admission.
    assert!(node.admission("owner-1", &runtime).guard_ok);

    assert!(node.receive_blocklist(&invalid_frame()));
    node.tick();
    let report = node.report();
    assert!(!report.guard_ok);
    assert_eq!(
        report.guard_reason.as_deref(),
        Some("guard_deployment_source")
    );
    assert!(!node.admission("owner-1", &runtime).guard_ok);
    let refused = node
        .admission("owner-1", &runtime)
        .check(sandbox_protocol::EgressMode::Allowlist)
        .unwrap_err();
    assert_eq!(
        refused.wire_reason(),
        Some(sandbox_protocol::EgressRefusalReason::EgressGuardUnavailable.into())
    );

    // The server's list is fixed: admitted again.
    assert!(node.receive_blocklist(&frame(&["bad.example"])));
    node.tick();
    assert!(node.report().guard_ok);
    assert!(node.admission("owner-1", &runtime).guard_ok);
}

#[test]
fn guard_refusals_carry_their_typed_wire_reason() {
    use sandbox_runtime::egress::EgressAdmission;
    let open = EgressAdmission {
        open_egress_permitted: false,
        guard_ok: true,
    }
    .check(sandbox_protocol::EgressMode::Open)
    .unwrap_err();
    assert_eq!(
        open.wire_reason(),
        Some(sandbox_protocol::EgressRefusalReason::OpenEgressNotPermitted.into())
    );
    let gone = super::NodeEgress::new(
        Some(Arc::new(
            sandbox_runtime::guard::client::SocketGuardProbe::new("/nonexistent/wssp-guard.sock"),
        )),
        &crate::config::Config::default(),
    );
    let refused = gone.create_settings().unwrap_err();
    assert_eq!(
        crate::sandbox_relay::supervisor::runtime_err(refused).reason,
        Some(sandbox_protocol::EgressRefusalReason::EgressGuardUnavailable.into())
    );
    // Size refusals keep their code alone.
    let too_large = sandbox_runtime::egress::EgressRefusal::PolicyTooLarge.error("too large");
    assert_eq!(too_large.wire_reason(), None);
}

/// Review P1-3: bootstrap is UNKNOWN. A daemon whose persisted list is
/// missing or corrupt must never push an explicit clear (`configured:false`)
/// that would wipe the guard's last-good deployment list; it pushes only
/// after a valid server frame says what the list is, and stays not-ok
/// (refusing new sandboxes) until then.
#[test]
fn a_missing_or_corrupt_persisted_list_never_clears_the_guard() {
    let dir = tempfile::tempdir().unwrap();
    let corrupt = dir.path().join("corrupt.json");
    std::fs::write(&corrupt, b"{not json").unwrap();
    for store in [dir.path().join("absent.json"), corrupt] {
        let guard = FakeGuardServer::start();
        let node = node(Some(guard.probe())).with_deployment_store(store);
        node.tick();
        node.tick();
        assert!(guard.pushes().is_empty(), "{:?}", guard.pushes());
        let report = node.report();
        assert!(!report.guard_ok);
        assert_eq!(
            report.guard_reason.as_deref(),
            Some("guard_deployment_source")
        );
        // An invalid server frame is not an authorization to clear either.
        assert!(node.receive_blocklist(&invalid_frame()));
        node.tick();
        assert!(guard.pushes().is_empty());
        assert!(!node.report().guard_ok);
        // Only an explicit, valid server frame does.
        assert!(node.receive_blocklist(&frame(&[])));
        node.tick();
        assert_eq!(
            guard.pushes(),
            [("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(), false)]
        );
        assert!(node.report().guard_ok);
    }
}

/// Post-connect window: the server's `egress.blocklist` wakes the monitor,
/// which pushes it to the guard at once (not on its next poll), and the push
/// and the guard turning healthy each advance `progress`, which makes the
/// relay loop send `host.egress-state` immediately instead of at the next
/// 5 s renewal.
#[test]
fn a_new_server_list_is_pushed_at_once_and_reported_without_waiting() {
    let guard = FakeGuardServer::start();
    let node = Arc::new(node(Some(guard.probe())));
    // A poll interval far longer than the test: only a wake can push.
    let monitor = GuardMonitor::start(node.clone(), Duration::from_secs(600));
    let wait_for = |what: &str, done: &dyn Fn() -> bool| {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !done() {
            assert!(Instant::now() < deadline, "{what}");
            std::thread::sleep(Duration::from_millis(10));
        }
    };
    // The first tick runs at start: no list yet, nothing pushed, not ok.
    wait_for("first observation", &|| {
        node.report().guard_reason.as_deref() != Some("guard_unreachable")
    });
    assert!(guard.pushes().is_empty());
    assert!(!node.report().guard_ok);
    let before = node.progress();
    let started = Instant::now();
    assert!(node.receive_blocklist(&frame(&["203.0.113.0/24"])));
    wait_for("pushed on arrival", &|| !guard.pushes().is_empty());
    wait_for("healthy after the push", &|| node.report().guard_ok);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(node.progress() > before, "the push is reported at once");
    // Nothing new: no further progress, so only the renewal timer reports.
    let settled = node.progress();
    node.tick();
    assert_eq!(node.progress(), settled);
    drop(monitor);
}
