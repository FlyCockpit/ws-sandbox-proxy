//! Preview tunnels: runtime tunnel-port changes (`tunnel_ports.rs`) against
//! the executable incus shim (no VM).

use std::sync::{Arc, Mutex};

use sandbox_protocol::{SandboxErrorCode, TunnelPortsOutcomeV11 as Outcome};

use super::client::IncusClient;
use super::network::{
    SandboxNetworkPlan, TUNNEL_INGRESS_RULE_TAG, sandbox_network_names, test_plan,
    with_tunnel_variant,
};
use super::shim_tests::client_for;
use crate::egress::TunnelPortsPending;

fn tunnel_plan(ports: &[u16]) -> SandboxNetworkPlan {
    let mut plan = test_plan("sbx-1");
    let settings = plan.settings.as_mut().expect("settings");
    settings.tunnel_ports = Some(ports.to_vec());
    plan.rules = with_tunnel_variant(&plan.rules, plan.gateway, ports);
    plan
}

fn applied(client: &IncusClient, plan: &SandboxNetworkPlan) {
    let lock = client.sandbox_lock("sbx-1");
    let _guard = lock.lock().unwrap_or_else(|err| err.into_inner());
    client.apply_sandbox_network(plan).expect("apply");
    client.clear_pending_cleanup("sbx-1").expect("adopt");
}

/// The live ACL against the record (with the pending-variant tolerance),
/// as readiness and reconnect compare them; and, while nothing is pending,
/// a re-apply validates (instead of recreating) too.
fn live_matches_record(client: &IncusClient, plan: &SandboxNetworkPlan) -> bool {
    let matches = client.live_acl_matches_record("sbx-1");
    if matches
        && client
            .persisted_enforcement_plan("sbx-1")
            .unwrap()
            .settings
            .unwrap()
            .tunnel_pending
            .is_none()
    {
        let lock = client.sandbox_lock("sbx-1");
        let _guard = lock.lock().unwrap_or_else(|err| err.into_inner());
        client
            .apply_sandbox_network(plan)
            .expect("re-apply validates");
    }
    matches
}

/// The live tunnel rule's destination ports, or None without one.
fn live_tunnel_ports(client: &IncusClient) -> Option<String> {
    let (_, acl) = sandbox_network_names("sbx-1");
    let observed = client.read_sandbox_acl(&acl).expect("read").expect("acl");
    let tagged: Vec<_> = observed
        .ingress
        .iter()
        .filter(|rule| rule.description == TUNNEL_INGRESS_RULE_TAG)
        .collect();
    assert!(tagged.len() <= 1);
    if let Some(rule) = tagged.first() {
        assert_eq!(
            observed.ingress[0].description, TUNNEL_INGRESS_RULE_TAG,
            "the tunnel rule stays the first ingress rule"
        );
        return Some(rule.destination_port.clone());
    }
    None
}

fn recorded(client: &IncusClient) -> crate::egress::EgressSettings {
    client
        .persisted_enforcement_plan("sbx-1")
        .and_then(|plan| plan.settings)
        .expect("recorded settings")
}

fn update(
    client: &IncusClient,
    revision: u64,
    ports: &[u16],
) -> (crate::TunnelPortsUpdate, Vec<Vec<u16>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    let result = client
        .update_tunnel_ports("sbx-1", revision, ports, &move |kept: &[u16]| {
            sink.lock().unwrap().push(kept.to_vec());
        })
        .expect("update");
    let seen = seen.lock().unwrap().clone();
    (result, seen)
}

#[test]
fn ports_are_added_and_removed_in_the_acl_and_the_record_together() {
    let client = client_for("running");
    let plan = tunnel_plan(&[3000]);
    applied(&client, &plan);
    assert_eq!(live_tunnel_ports(&client).as_deref(), Some("3000"));

    // Add 4000: the client may keep forwarding only what both variants keep.
    let (result, kept) = update(&client, 1, &[3000, 4000]);
    assert_eq!(result.outcome, Outcome::Applied);
    assert_eq!(result.revision, 1);
    assert_eq!(kept, vec![vec![3000]]);
    assert_eq!(live_tunnel_ports(&client).as_deref(), Some("3000,4000"));
    let settings = recorded(&client);
    assert_eq!(settings.tunnel_ports, Some(vec![3000, 4000]));
    assert_eq!(settings.tunnel_revision, 1);
    assert_eq!(settings.tunnel_pending, None);
    assert!(live_matches_record(&client, &plan));

    // A stale or repeated revision changes nothing and reports the recorded one.
    let (result, kept) = update(&client, 1, &[9999]);
    assert_eq!((result.outcome, result.revision), (Outcome::Applied, 1));
    assert!(kept.is_empty(), "no client is touched for a stale revision");
    assert_eq!(live_tunnel_ports(&client).as_deref(), Some("3000,4000"));

    // Remove 3000: the client must stop forwarding it before the ACL changes.
    let (result, kept) = update(&client, 2, &[4000]);
    assert_eq!((result.outcome, result.revision), (Outcome::Applied, 2));
    assert_eq!(kept, vec![vec![4000]]);
    assert_eq!(live_tunnel_ports(&client).as_deref(), Some("4000"));
    assert!(live_matches_record(&client, &plan));

    // Remove every port: pinned, nothing admitted.
    let (result, kept) = update(&client, 3, &[]);
    assert_eq!((result.outcome, result.revision), (Outcome::Applied, 3));
    assert_eq!(kept, vec![Vec::<u16>::new()]);
    assert_eq!(live_tunnel_ports(&client), None);
    assert_eq!(recorded(&client).tunnel_ports, Some(vec![]));
    assert!(live_matches_record(&client, &plan));
    assert!(
        client
            .persisted_enforcement_plan("sbx-1")
            .unwrap()
            .pinned_guest_address()
            .is_some(),
        "a tunnel sandbox with no ports stays pinned"
    );

    // And back.
    let (result, _) = update(&client, 4, &[5173]);
    assert_eq!((result.outcome, result.revision), (Outcome::Applied, 4));
    assert_eq!(live_tunnel_ports(&client).as_deref(), Some("5173"));
    assert!(live_matches_record(&client, &plan));
}

#[test]
fn only_tunnel_sandboxes_with_a_recorded_plan_change_ports() {
    let client = client_for("running");
    // No plan on this host.
    let (result, kept) = update(&client, 1, &[3000]);
    assert_eq!(result.outcome, Outcome::Absent);
    assert!(kept.is_empty());
    // A sandbox created without tunnels is never pinned at runtime.
    let plain = test_plan("sbx-1");
    applied(&client, &plain);
    let (result, kept) = update(&client, 1, &[3000]);
    assert_eq!(result.outcome, Outcome::Refused);
    assert!(kept.is_empty());
    assert_eq!(live_tunnel_ports(&client), None);
    // Malformed requests never reach the host's state.
    let err = client
        .update_tunnel_ports("sbx-1", 1, &[4000, 3000], &|_| {})
        .expect_err("unordered");
    assert_eq!(err.code, SandboxErrorCode::ProtocolError);
    let err = client
        .update_tunnel_ports("sbx-1", 0, &[3000], &|_| {})
        .expect_err("revision 0");
    assert_eq!(err.code, SandboxErrorCode::ProtocolError);
}

/// Write an unconfirmed change by hand: the record says pending, the live
/// ACL carries `live` (one of the variants, or another one).
fn leave_pending(client: &IncusClient, revision: u64, ports: &[u16], live: &[u16]) {
    let path = client.plans_dir().join("sbx-1.json");
    let mut record: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    record["settings"]["tunnel_pending"] = serde_json::to_value(TunnelPortsPending {
        revision,
        ports: ports.to_vec(),
    })
    .unwrap();
    std::fs::write(&path, record.to_string()).unwrap();
    let plan = client.persisted_enforcement_plan("sbx-1").unwrap();
    let (_, acl) = sandbox_network_names("sbx-1");
    client
        .update_acl(&acl, std::time::Duration::from_secs(10), |metadata| {
            let rules = with_tunnel_variant(&plan.rules, plan.gateway, live);
            metadata["ingress"] = rules
                .iter()
                .filter(|rule| rule.direction == super::network::AclDirection::Ingress)
                .map(super::acl::api_rule)
                .collect::<Vec<_>>()
                .into();
            Ok(())
        })
        .expect("seed the live ACL");
}

#[test]
fn an_unconfirmed_change_is_tolerated_only_as_its_two_variants_and_rolled_back_first() {
    let client = client_for("running");
    let plan = tunnel_plan(&[3000]);
    applied(&client, &plan);

    // The write landed but the commit did not (a crash): no drift.
    leave_pending(&client, 1, &[3000, 4000], &[3000, 4000]);
    assert!(live_matches_record(&client, &plan));
    // The client may forward only what both variants admit.
    assert_eq!(
        client
            .persisted_enforcement_plan("sbx-1")
            .unwrap()
            .tunnel_target_ports(),
        vec![3000]
    );
    // The write never landed: no drift either.
    leave_pending(&client, 1, &[3000, 4000], &[3000]);
    assert!(live_matches_record(&client, &plan));
    // Any third variant is drift.
    leave_pending(&client, 1, &[3000, 4000], &[3000, 9999]);
    assert!(!live_matches_record(&client, &plan));
    // ... and the update refuses to launder it.
    let err = client
        .update_tunnel_ports("sbx-1", 2, &[5173], &|_| {})
        .expect_err("unknown live variant");
    assert_eq!(err.code, SandboxErrorCode::IdempotencyConflict);
    assert_eq!(live_tunnel_ports(&client).as_deref(), Some("3000,9999"));

    // A known variant is rolled back (confirmed) before the next change.
    leave_pending(&client, 1, &[3000, 4000], &[3000, 4000]);
    let (result, kept) = update(&client, 2, &[5173]);
    assert_eq!((result.outcome, result.revision), (Outcome::Applied, 2));
    assert_eq!(kept, vec![Vec::<u16>::new()], "3000 is not kept by 2");
    assert_eq!(live_tunnel_ports(&client).as_deref(), Some("5173"));
    let settings = recorded(&client);
    assert_eq!(settings.tunnel_ports, Some(vec![5173]));
    assert_eq!(settings.tunnel_pending, None);
    assert!(live_matches_record(&client, &plan));

    // Resolving on its own (the DNS refresh's entry) restores the committed
    // variant and clears the pending change.
    leave_pending(&client, 3, &[1234], &[1234]);
    {
        let lock = client.sandbox_lock("sbx-1");
        let _guard = lock.lock().unwrap_or_else(|err| err.into_inner());
        client
            .resolve_tunnel_pending_locked("sbx-1")
            .expect("resolve");
    }
    assert_eq!(live_tunnel_ports(&client).as_deref(), Some("5173"));
    assert_eq!(recorded(&client).tunnel_pending, None);
    assert_eq!(recorded(&client).tunnel_revision, 2);
}

#[test]
fn the_recorded_rule_keeps_its_gateway_and_pin_across_changes() {
    let client = client_for("running");
    applied(&client, &tunnel_plan(&[3000]));
    let before = client.persisted_enforcement_plan("sbx-1").unwrap();
    update(&client, 1, &[3000, 8080]);
    let after = client.persisted_enforcement_plan("sbx-1").unwrap();
    assert_eq!(after.gateway, before.gateway);
    assert_eq!(after.pinned_guest_address(), before.pinned_guest_address());
    let rule = after
        .rules
        .iter()
        .find(|rule| rule.description == TUNNEL_INGRESS_RULE_TAG)
        .expect("tunnel rule");
    assert_eq!(rule.source, Some(format!("{}/32", after.gateway)));
    assert_eq!(rule.destination_port.as_deref(), Some("3000,8080"));
    // Every other recorded rule is untouched, in order.
    let others = |plan: &SandboxNetworkPlan| {
        plan.rules
            .iter()
            .filter(|rule| rule.description != TUNNEL_INGRESS_RULE_TAG)
            .cloned()
            .collect::<Vec<_>>()
    };
    assert_eq!(others(&after), others(&before));
}
