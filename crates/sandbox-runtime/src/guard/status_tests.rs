//! Security-critical: status production against the shared lease rule (M18).

use std::net::Ipv4Addr;

use super::*;
use crate::guard::sources::{PolicyContent, parse_entries};
use crate::guard_probe::{
    FakeGuardProbe, GuardExpectations, GuardGateway, GuardSources, GuardUnhealthy, attest_bridge,
    evaluate_guard,
};

const BOOT: &str = "4f1c7a1e-0000-4000-8000-000000000001";
const NOW: u64 = 500_000_000_000;

fn produced(root: &Source, deployment: &Source) -> GuardStatus {
    let mut status = FakeGuardProbe::healthy_status(&[GuardGateway {
        bridge: "wsn-0123456789".into(),
        gateway: Ipv4Addr::new(10, 1, 2, 1),
    }]);
    status.boot_id = BOOT.into();
    status.sources = GuardSources {
        root: source_status(root),
        deployment: source_status(deployment),
    };
    status.verified_boottime_ns = NOW - 1_000_000_000;
    status.lease_until_boottime_ns = NOW - 1_000_000_000 + crate::guard::LEASE.as_nanos() as u64;
    status
}

fn expect(digest: Option<String>, now: u64) -> GuardExpectations {
    GuardExpectations {
        min_guard_version: crate::guard::GUARD_VERSION,
        boot_id: BOOT.into(),
        now_boottime_ns: now,
        deployment_digest: digest,
    }
}

fn pushed(entries: &[&str]) -> (Source, String) {
    let content =
        parse_entries(&entries.iter().map(|e| e.to_string()).collect::<Vec<_>>()).unwrap();
    let digest = content.digest();
    let mut source = Source::starting(None);
    source.accept(content, true);
    (source, digest)
}

#[test]
fn our_version_is_accepted_by_the_runtime_rule() {
    const { assert!(crate::guard::GUARD_VERSION >= crate::guard_probe::MIN_GUARD_VERSION) };
}

#[test]
fn produced_status_passes_with_the_pushed_digest_only() {
    let mut root = Source::starting(None);
    root.accept_root_file(PolicyContent::default());
    let (deployment, digest) = pushed(&["203.0.113.0/24"]);
    let status = produced(&root, &deployment);
    assert_eq!(
        evaluate_guard(&status, &expect(Some(digest.clone()), NOW)),
        Ok(())
    );
    assert_eq!(
        evaluate_guard(&status, &expect(Some("sha256:other".into()), NOW)),
        Err(GuardUnhealthy::DeploymentSource)
    );
    // configured:false push <-> expectation None.
    let mut cleared = Source::starting(None);
    cleared.accept(PolicyContent::default(), false);
    assert_eq!(
        evaluate_guard(&produced(&root, &cleared), &expect(None, NOW)),
        Ok(())
    );
    assert_eq!(
        evaluate_guard(&produced(&root, &cleared), &expect(Some(digest), NOW)),
        Err(GuardUnhealthy::DeploymentSource)
    );
}

#[test]
fn unhealthy_sources_and_expired_lease_refuse() {
    let (deployment, digest) = pushed(&["1.1.1.1"]);
    let mut root = Source::starting(Some(PolicyContent::default()));
    // Unknown root (guard just started).
    assert_eq!(
        evaluate_guard(
            &produced(&root, &deployment),
            &expect(Some(digest.clone()), NOW)
        ),
        Err(GuardUnhealthy::RootSource)
    );
    root.reject(SourceState::Missing);
    assert_eq!(
        evaluate_guard(
            &produced(&root, &deployment),
            &expect(Some(digest.clone()), NOW)
        ),
        Err(GuardUnhealthy::RootSource)
    );
    root.accept_root_file(PolicyContent::default());
    // Deployment unknown after a guard restart, until the daemon re-pushes.
    let restarted = Source::starting(deployment.last_valid.clone());
    assert_eq!(
        evaluate_guard(
            &produced(&root, &restarted),
            &expect(Some(digest.clone()), NOW)
        ),
        Err(GuardUnhealthy::DeploymentSource)
    );
    // Lease = last resync + 15 s on BOOTTIME.
    let status = produced(&root, &deployment);
    let until = status.lease_until_boottime_ns;
    assert_eq!(
        evaluate_guard(&status, &expect(Some(digest.clone()), until - 1)),
        Ok(())
    );
    assert_eq!(
        evaluate_guard(&status, &expect(Some(digest.clone()), until)),
        Err(GuardUnhealthy::LeaseExpired)
    );
    // Quarantine and boot mismatch.
    let mut quarantined = status.clone();
    quarantined.quarantined = Some("unsupported_packet_path:flowtable:inet/q/ft".into());
    quarantined.ok = false;
    quarantined.live_bridges.clear();
    assert_eq!(
        evaluate_guard(&quarantined, &expect(Some(digest.clone()), NOW)),
        Err(GuardUnhealthy::Quarantined)
    );
    let mut rebooted = expect(Some(digest.clone()), NOW);
    rebooted.boot_id = "other".into();
    assert_eq!(
        evaluate_guard(&status, &rebooted),
        Err(GuardUnhealthy::BootMismatch)
    );
    // Start fence: the exact pair.
    let gw = Ipv4Addr::new(10, 1, 2, 1);
    let e = expect(Some(digest), NOW);
    assert_eq!(attest_bridge(&status, &e, "wsn-0123456789", gw), Ok(()));
    assert_eq!(
        attest_bridge(&status, &e, "wsn-0123456789", Ipv4Addr::new(10, 1, 2, 9)),
        Err(GuardUnhealthy::BridgeNotCovered)
    );
}

#[test]
fn source_reason_codes_carry_the_line_never_contents() {
    let mut root = Source::starting(None);
    root.reject(SourceState::Invalid {
        line: Some(7),
        reason: "CIDR has host bits set".into(),
    });
    assert_eq!(
        source_reason("root", &root).as_deref(),
        Some("root_source:invalid:line:7")
    );
    assert_eq!(
        source_reason("deployment", &Source::starting(None)).as_deref(),
        Some("deployment_source:unknown")
    );
    let (ok, _) = pushed(&["1.1.1.1"]);
    assert_eq!(source_reason("deployment", &ok), None);
    // A rejected source still reports the digest of what it enforces.
    let (mut kept, digest) = pushed(&["1.1.1.1"]);
    kept.reject(SourceState::Missing);
    assert_eq!(source_status(&kept).digest, Some(digest));
}

#[test]
fn produced_status_round_trips_the_strict_wire_type() {
    let (deployment, _) = pushed(&["1.1.1.1"]);
    let mut root = Source::starting(None);
    root.accept_root_file(PolicyContent::default());
    let status = produced(&root, &deployment);
    let value = serde_json::to_value(&status).unwrap();
    assert_eq!(value["sources"]["deployment"]["state"], "valid");
    assert_eq!(value["sources"]["root"]["state"], "not_configured");
    let back: GuardStatus = serde_json::from_value(value).unwrap();
    assert_eq!(back, status);
}

#[test]
fn older_generation_of_the_same_instance_is_stale() {
    let mut fence = GenerationFence::default();
    let mut status = FakeGuardProbe::healthy_status(&[]);
    status.generation = 7;
    assert!(fence.observe(&status));
    status.generation = 6;
    assert!(!fence.observe(&status));
    status.generation = 7;
    assert!(fence.observe(&status));
    status.instance_id = "bb".into();
    status.generation = 1;
    assert!(fence.observe(&status));
    assert_ne!(new_instance_id().unwrap(), new_instance_id().unwrap());
    assert_eq!(new_instance_id().unwrap().len(), 32);
}
