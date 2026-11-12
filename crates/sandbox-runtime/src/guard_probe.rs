//! Egress guard attestation (see docs/guide/hosts.md#egress-guard).
//!
//! The root-owned egress guard (G1) answers `status` on its socket with a
//! [`GuardStatus`]. This module owns:
//!
//! - the status FORMAT the guard must produce and the daemon parses (G1's
//!   socket server and `/run/wssp-guard/status.json` emit exactly this JSON);
//! - the [`GuardProbe`] trait the runtime start fence and the daemon's early
//!   create / cold-reconnect check call — one fresh `status` per decision,
//!   never cached across it (G1 implements the socket client; tests and the
//!   fake runtime use [`FakeGuardProbe`]);
//! - the pure `guard_ok` lease rule and the per-sandbox bridge attestation.
//!
//! Until G1/E3 install a real probe the Incus runtime uses
//! [`UnavailableGuardProbe`]: no guard, no start (fail closed, M11).

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sandbox_protocol::SandboxErrorCode;

use crate::RuntimeError;
use crate::egress::EgressRefusal;

/// The minimum guard protocol/ruleset version this runtime accepts. An older
/// guard reports `guard_outdated` ("run `sudo wssp guard install`").
pub const MIN_GUARD_VERSION: u32 = 1;

/// Provenance state of one guard policy source (§2.0.4). Only `valid` and
/// `not_configured` are healthy; `invalid`, `missing` and `unknown` keep the
/// last valid set in the kernel and make the guard unhealthy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardSourceState {
    Valid,
    NotConfigured,
    Invalid,
    Missing,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardSourceStatus {
    pub state: GuardSourceState,
    /// Content digest of the applied (last valid) set; never the contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardSources {
    /// `/etc/wssp/egress-blocklist` (root operator list).
    pub root: GuardSourceStatus,
    /// The control-plane list the daemon pushes (`push_deployment`).
    pub deployment: GuardSourceStatus,
}

/// One `(wsn-* bridge, its single .1 address)` pair in the guard's
/// `gateways` set (m14).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardGateway {
    pub bridge: String,
    pub gateway: Ipv4Addr,
}

/// The guard's `status` answer (§2.0.5), JSON with snake_case keys, one
/// length-prefixed frame on `/run/wssp-guard/guard.sock` and the same object
/// in `/run/wssp-guard/status.json`. Unknown fields are refused so a format
/// change is a version bump, never a silent misread.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardStatus {
    pub guard_version: u32,
    /// Random 128-bit hex token per guard process start.
    pub instance_id: String,
    /// `/proc/sys/kernel/random/boot_id` as the guard read it.
    pub boot_id: String,
    /// Monotonic per instance; advances on every fully successful resync.
    pub generation: u64,
    /// Last resync fully succeeded and nothing is quarantined.
    pub ok: bool,
    /// Quarantine reason code (`unsupported_packet_path:<what>`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarantined: Option<String>,
    /// Machine reason codes, never free text.
    #[serde(default)]
    pub reasons: Vec<String>,
    pub sources: GuardSources,
    /// `wsn-*` bridges the dead-man set currently admits.
    pub live_bridges: Vec<String>,
    pub gateways: Vec<GuardGateway>,
    pub uplinks: Vec<String>,
    /// Set sizes and repair counters (diagnostics only).
    #[serde(default)]
    pub counts: std::collections::BTreeMap<String, u64>,
    /// CLOCK_BOOTTIME of the last fully successful resync.
    pub verified_boottime_ns: u64,
    /// `verified_boottime_ns + 15 s`: the guard's own health lease.
    pub lease_until_boottime_ns: u64,
}

/// What the daemon expects of a healthy guard at decision time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardExpectations {
    pub min_guard_version: u32,
    /// The daemon's own read of `/proc/sys/kernel/random/boot_id`.
    pub boot_id: String,
    /// The daemon's CLOCK_BOOTTIME now (suspend-aware; wall-clock changes
    /// cannot extend a lease).
    pub now_boottime_ns: u64,
    /// The deployment digest the daemon last pushed; `None` means it pushed
    /// `configured:false`, so the source must read `not_configured`.
    pub deployment_digest: Option<String>,
}

/// Status reason a node daemon adds while another wssp daemon's marker on
/// its Incus server is live (one daemon per Incus server): new sandboxes are
/// refused exactly as for an unhealthy guard, running ones carry on.
pub const INCUS_SERVER_SHARED_REASON: &str = "incus_server_shared";

/// Why a guard is not ok, as a bounded machine code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardUnhealthy {
    Unreachable,
    NotOk,
    Quarantined,
    BootMismatch,
    LeaseExpired,
    Outdated,
    RootSource,
    DeploymentSource,
    BridgeNotCovered,
    /// A host firewall (ufw, firewalld, Docker) drops `wsn-*` traffic, so a
    /// sandbox would boot with no DHCP lease, DNS or internet.
    HostFirewall,
    /// Another wssp daemon drives this node's Incus server.
    IncusServerShared,
}

impl GuardUnhealthy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unreachable => "guard_unreachable",
            Self::NotOk => "guard_not_ok",
            Self::Quarantined => "guard_quarantined",
            Self::BootMismatch => "guard_boot_mismatch",
            Self::LeaseExpired => "guard_lease_expired",
            Self::Outdated => "guard_outdated",
            Self::RootSource => "guard_root_source",
            Self::DeploymentSource => "guard_deployment_source",
            Self::BridgeNotCovered => "guard_bridge_not_covered",
            Self::HostFirewall => crate::guard::path::HOST_FIREWALL_REASON,
            Self::IncusServerShared => INCUS_SERVER_SHARED_REASON,
        }
    }

    pub(crate) fn error(self) -> RuntimeError {
        if self == Self::IncusServerShared {
            return EgressRefusal::GuardUnavailable.error(
                "another wssp daemon drives this node's Incus server (one daemon per Incus \
                 server is supported); new sandboxes cannot start here",
            );
        }
        EgressRefusal::GuardUnavailable.error(format!(
            "this node's network guard is not healthy ({}); new sandboxes cannot start here",
            self.as_str()
        ))
    }
}

/// The daemon `guard_ok` rule (§2.0.5): healthy, not quarantined, same boot,
/// unexpired lease on BOOTTIME, current version, both sources valid or
/// explicitly not configured, and the deployment source exactly what the
/// daemon last pushed.
pub fn evaluate_guard(
    status: &GuardStatus,
    expect: &GuardExpectations,
) -> Result<(), GuardUnhealthy> {
    if status.guard_version < expect.min_guard_version {
        return Err(GuardUnhealthy::Outdated);
    }
    if status.quarantined.is_some() {
        return Err(GuardUnhealthy::Quarantined);
    }
    if !status.ok {
        if status
            .reasons
            .iter()
            .any(|reason| reason == INCUS_SERVER_SHARED_REASON)
        {
            return Err(GuardUnhealthy::IncusServerShared);
        }
        let firewall = status.reasons.iter().any(|reason| {
            reason
                .split(':')
                .next()
                .is_some_and(|code| code == crate::guard::path::HOST_FIREWALL_REASON)
        });
        return Err(if firewall {
            GuardUnhealthy::HostFirewall
        } else {
            GuardUnhealthy::NotOk
        });
    }
    if status.boot_id != expect.boot_id || status.boot_id.is_empty() {
        return Err(GuardUnhealthy::BootMismatch);
    }
    if status.lease_until_boottime_ns <= expect.now_boottime_ns
        || status.verified_boottime_ns > status.lease_until_boottime_ns
    {
        return Err(GuardUnhealthy::LeaseExpired);
    }
    if !matches!(
        status.sources.root.state,
        GuardSourceState::Valid | GuardSourceState::NotConfigured
    ) {
        return Err(GuardUnhealthy::RootSource);
    }
    let deployment = &status.sources.deployment;
    let deployment_ok = match &expect.deployment_digest {
        Some(digest) => {
            deployment.state == GuardSourceState::Valid
                && deployment.digest.as_deref() == Some(digest.as_str())
        }
        None => deployment.state == GuardSourceState::NotConfigured,
    };
    if !deployment_ok {
        return Err(GuardUnhealthy::DeploymentSource);
    }
    Ok(())
}

/// The start-fence attestation (§2.0.5): `guard_ok` AND this sandbox's
/// bridge admitted by the dead-man set AND its exact `(bridge, gateway)`
/// pair in the guard's gateway set.
pub fn attest_bridge(
    status: &GuardStatus,
    expect: &GuardExpectations,
    bridge: &str,
    gateway: Ipv4Addr,
) -> Result<(), GuardUnhealthy> {
    evaluate_guard(status, expect)?;
    let live = status.live_bridges.iter().any(|live| live == bridge);
    let paired = status
        .gateways
        .iter()
        .any(|pair| pair.bridge == bridge && pair.gateway == gateway);
    if !live || !paired {
        return Err(GuardUnhealthy::BridgeNotCovered);
    }
    Ok(())
}

/// One fresh guard `status` call per decision (§2.0.5). Implementations
/// never cache a status across calls. G1 provides the socket client.
pub trait GuardProbe: Send + Sync + std::fmt::Debug {
    /// A fresh `status` answer. `Err` means the guard is unreachable.
    fn status(&self) -> Result<GuardStatus, RuntimeError>;
    /// The daemon-side expectations at this instant (boot id, BOOTTIME now,
    /// minimum version, last pushed deployment digest).
    fn expectations(&self) -> Result<GuardExpectations, RuntimeError>;
    /// The other wssp daemon on this node's Incus server, while its marker
    /// is live (one daemon per Incus server). New work that writes the
    /// shared image store is refused meanwhile ([`refuse_shared_incus_server`]).
    fn shared_incus_server(&self) -> Option<String> {
        None
    }
    /// Notification that a start fence is about to attest this bridge. Real
    /// probes ignore it; the fake uses it to model a guard that sees every
    /// link event at once.
    fn will_attest(&self, _bridge: &str, _gateway: Ipv4Addr) {}
    /// `push_deployment` (§2.0.4): hand the guard the deployment blocklist
    /// (`configured:false` clears it explicitly). On success the guard's
    /// digest becomes the expected deployment digest of
    /// [`GuardProbe::expectations`]. Fail-closed default: no inbox.
    fn push_deployment(
        &self,
        _configured: bool,
        _entries: Vec<String>,
    ) -> Result<String, RuntimeError> {
        Err(RuntimeError::new(
            SandboxErrorCode::UnsupportedCapability,
            "this egress guard has no deployment inbox",
        ))
    }
    /// The node's egress ceiling (`{"op":"ceiling"}`), for host sockets
    /// opened on a sandbox's behalf (the credential proxy). `Ok`
    /// only when the status published with it passes the lease rule
    /// ([`evaluate_guard`]) against this probe's expectations. Fail-closed
    /// default: unavailable.
    fn egress_ceiling(&self) -> Result<crate::guard::ceiling::EgressCeiling, RuntimeError> {
        Err(RuntimeError::new(
            SandboxErrorCode::UnsupportedCapability,
            "this egress guard cannot answer `ceiling`",
        ))
    }
    /// The validated operator domain blocklist (both sources), captured into
    /// `EgressSettings` at materialization (§2.0.4). The daemon never parses
    /// a blocklist itself. Fail-closed default: unavailable.
    fn domain_blocklist(&self) -> Result<crate::egress::DomainBlocklist, RuntimeError> {
        Err(RuntimeError::new(
            SandboxErrorCode::UnsupportedCapability,
            "this egress guard cannot answer `policy`",
        ))
    }
}

/// Refuse new image fetches and imports while another wssp daemon drives
/// this node's Incus server: they would write the shared image store.
pub fn refuse_shared_incus_server(probe: &dyn GuardProbe) -> Result<(), RuntimeError> {
    match probe.shared_incus_server() {
        Some(_) => Err(GuardUnhealthy::IncusServerShared.error()),
        None => Ok(()),
    }
}

/// `guard_ok` from one fresh probe call, as a typed refusal.
pub fn check_guard(probe: &dyn GuardProbe) -> Result<(), RuntimeError> {
    refuse_shared_incus_server(probe)?;
    let status = probe
        .status()
        .map_err(|_| GuardUnhealthy::Unreachable.error())?;
    let expect = probe
        .expectations()
        .map_err(|_| GuardUnhealthy::Unreachable.error())?;
    evaluate_guard(&status, &expect).map_err(GuardUnhealthy::error)
}

/// The runtime start fence: fresh status calls until this bridge is covered
/// or `wait` elapses (a just-created bridge appears at the guard's next link
/// event). An unhealthy guard refuses at once; only a missing bridge waits.
pub fn attest_sandbox_bridge(
    probe: &dyn GuardProbe,
    bridge: &str,
    gateway: Ipv4Addr,
    wait: Duration,
) -> Result<(), RuntimeError> {
    refuse_shared_incus_server(probe)?;
    probe.will_attest(bridge, gateway);
    let deadline = Instant::now() + wait;
    loop {
        let status = probe
            .status()
            .map_err(|_| GuardUnhealthy::Unreachable.error())?;
        let expect = probe
            .expectations()
            .map_err(|_| GuardUnhealthy::Unreachable.error())?;
        match attest_bridge(&status, &expect, bridge, gateway) {
            Ok(()) => return Ok(()),
            Err(GuardUnhealthy::BridgeNotCovered) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50).min(wait));
            }
            Err(reason) => return Err(reason.error()),
        }
    }
}

/// Default probe until a guard client is installed: unreachable, so every
/// create, cold reconnect and start is refused (no guard, no start).
#[derive(Debug, Default)]
pub struct UnavailableGuardProbe;

impl GuardProbe for UnavailableGuardProbe {
    fn status(&self) -> Result<GuardStatus, RuntimeError> {
        Err(RuntimeError::new(
            SandboxErrorCode::UnsupportedCapability,
            "no egress guard client is configured: run `sudo wssp guard install`",
        ))
    }
    fn expectations(&self) -> Result<GuardExpectations, RuntimeError> {
        Err(RuntimeError::new(
            SandboxErrorCode::UnsupportedCapability,
            "no egress guard client is configured",
        ))
    }
}

/// `/proc/sys/kernel/random/boot_id`, trimmed.
pub fn read_boot_id() -> Result<String, RuntimeError> {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|id| id.trim().to_string())
        .map_err(|err| {
            RuntimeError::new(
                SandboxErrorCode::Internal,
                format!("cannot read the boot id: {err}"),
            )
        })
}

/// CLOCK_BOOTTIME in nanoseconds from `/proc/uptime` (which counts suspend),
/// centisecond resolution. No FFI: the crate forbids `unsafe`.
pub fn boottime_now_ns() -> Result<u64, RuntimeError> {
    let text = std::fs::read_to_string("/proc/uptime").map_err(|err| {
        RuntimeError::new(
            SandboxErrorCode::Internal,
            format!("cannot read the boot clock: {err}"),
        )
    })?;
    parse_uptime_ns(&text)
        .ok_or_else(|| RuntimeError::new(SandboxErrorCode::Internal, "malformed /proc/uptime"))
}

fn parse_uptime_ns(text: &str) -> Option<u64> {
    let first = text.split_whitespace().next()?;
    let (secs, frac) = first.split_once('.').unwrap_or((first, ""));
    let secs: u64 = secs.parse().ok()?;
    let mut nanos: u64 = 0;
    let mut scale: u64 = 100_000_000;
    for digit in frac.bytes().take(9) {
        if !digit.is_ascii_digit() {
            return None;
        }
        nanos += u64::from(digit - b'0') * scale;
        scale /= 10;
    }
    secs.checked_mul(1_000_000_000)?.checked_add(nanos)
}

#[derive(Debug)]
struct FakeGuardState {
    healthy: bool,
    /// Cover every bridge the fence asks about (a guard that sees each link
    /// event at once). Off: only `bridges` are covered.
    cover_all: bool,
    bridges: Vec<GuardGateway>,
    /// Explicit status override (expired lease, quarantine, sources...).
    status: Option<GuardStatus>,
    status_calls: usize,
    /// `push_deployment` calls as `configured` flags, in order.
    pushes: Vec<bool>,
    /// Fence asks recorded as `(bridge, gateway)`.
    asked: Vec<(String, Ipv4Addr)>,
}

/// Settable test / fake-stack guard. Healthy by default.
#[derive(Debug, Clone)]
pub struct FakeGuardProbe {
    state: Arc<Mutex<FakeGuardState>>,
}

const FAKE_BOOT_ID: &str = "00000000-0000-4000-8000-000000000000";
const FAKE_NOW_NS: u64 = 1_000_000_000_000;

impl FakeGuardProbe {
    pub fn healthy() -> Self {
        Self {
            state: Arc::new(Mutex::new(FakeGuardState {
                healthy: true,
                cover_all: true,
                bridges: Vec::new(),
                status: None,
                status_calls: 0,
                pushes: Vec::new(),
                asked: Vec::new(),
            })),
        }
    }

    pub fn unhealthy() -> Self {
        let probe = Self::healthy();
        probe.set_healthy(false);
        probe
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, FakeGuardState> {
        self.state.lock().unwrap_or_else(|err| err.into_inner())
    }

    pub fn set_healthy(&self, healthy: bool) {
        self.lock().healthy = healthy;
    }
    pub fn set_cover_all(&self, cover_all: bool) {
        self.lock().cover_all = cover_all;
    }
    pub fn cover_bridge(&self, bridge: &str, gateway: Ipv4Addr) {
        self.lock().bridges.push(GuardGateway {
            bridge: bridge.to_string(),
            gateway,
        });
    }
    /// Replace the answer outright (`None` restores the synthesized one).
    pub fn set_status(&self, status: Option<GuardStatus>) {
        self.lock().status = status;
    }
    pub fn status_calls(&self) -> usize {
        self.lock().status_calls
    }
    /// `push_deployment` calls seen so far (`configured` flags, in order).
    pub fn pushes(&self) -> Vec<bool> {
        self.lock().pushes.clone()
    }

    /// A healthy status at the fake clock, covering `bridges`.
    pub fn healthy_status(bridges: &[GuardGateway]) -> GuardStatus {
        GuardStatus {
            guard_version: MIN_GUARD_VERSION,
            instance_id: "0123456789abcdef0123456789abcdef".into(),
            boot_id: FAKE_BOOT_ID.into(),
            generation: 1,
            ok: true,
            quarantined: None,
            reasons: Vec::new(),
            sources: GuardSources {
                root: GuardSourceStatus {
                    state: GuardSourceState::NotConfigured,
                    digest: None,
                },
                deployment: GuardSourceStatus {
                    state: GuardSourceState::NotConfigured,
                    digest: None,
                },
            },
            live_bridges: bridges.iter().map(|pair| pair.bridge.clone()).collect(),
            gateways: bridges.to_vec(),
            uplinks: vec!["eth0".into()],
            counts: Default::default(),
            verified_boottime_ns: FAKE_NOW_NS - 1_000_000_000,
            lease_until_boottime_ns: FAKE_NOW_NS + 14_000_000_000,
        }
    }
}

impl GuardProbe for FakeGuardProbe {
    fn status(&self) -> Result<GuardStatus, RuntimeError> {
        let mut state = self.lock();
        state.status_calls += 1;
        if let Some(status) = &state.status {
            return Ok(status.clone());
        }
        let mut bridges = state.bridges.clone();
        if state.cover_all {
            bridges.extend(state.asked.iter().map(|(bridge, gateway)| GuardGateway {
                bridge: bridge.clone(),
                gateway: *gateway,
            }));
        }
        let mut status = Self::healthy_status(&bridges);
        if !state.healthy {
            status.ok = false;
            status.reasons = vec!["guard_stopped".into()];
        }
        Ok(status)
    }

    fn expectations(&self) -> Result<GuardExpectations, RuntimeError> {
        Ok(GuardExpectations {
            min_guard_version: MIN_GUARD_VERSION,
            boot_id: FAKE_BOOT_ID.into(),
            now_boottime_ns: FAKE_NOW_NS,
            deployment_digest: None,
        })
    }

    fn will_attest(&self, bridge: &str, gateway: Ipv4Addr) {
        self.lock().asked.push((bridge.to_string(), gateway));
    }

    /// The fake enforces no deployment list: it accepts only the explicit
    /// `configured:false` its synthesized `not_configured` status reports.
    fn push_deployment(
        &self,
        configured: bool,
        _entries: Vec<String>,
    ) -> Result<String, RuntimeError> {
        self.lock().pushes.push(configured);
        if configured {
            return Err(RuntimeError::new(
                SandboxErrorCode::UnsupportedCapability,
                "the fake egress guard enforces no deployment blocklist",
            ));
        }
        Ok("sha256:fake-not-configured".into())
    }

    fn domain_blocklist(&self) -> Result<crate::egress::DomainBlocklist, RuntimeError> {
        Ok(crate::egress::DomainBlocklist::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expect() -> GuardExpectations {
        FakeGuardProbe::healthy().expectations().unwrap()
    }

    fn healthy() -> GuardStatus {
        FakeGuardProbe::healthy_status(&[GuardGateway {
            bridge: "wsn-0123456789".into(),
            gateway: Ipv4Addr::new(10, 1, 2, 1),
        }])
    }

    #[test]
    fn status_format_round_trips_and_refuses_unknown_fields() {
        let status = healthy();
        let json = serde_json::to_value(&status).unwrap();
        for key in [
            "guard_version",
            "instance_id",
            "boot_id",
            "generation",
            "ok",
            "reasons",
            "sources",
            "live_bridges",
            "gateways",
            "uplinks",
            "counts",
            "verified_boottime_ns",
            "lease_until_boottime_ns",
        ] {
            assert!(json.get(key).is_some(), "{key}");
        }
        assert_eq!(json["sources"]["root"]["state"], "not_configured");
        assert_eq!(json["gateways"][0]["bridge"], "wsn-0123456789");
        let back: GuardStatus = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(back, status);
        let mut extra = json;
        extra["surprise"] = serde_json::json!(true);
        assert!(serde_json::from_value::<GuardStatus>(extra).is_err());
    }

    #[test]
    fn lease_rule_truth_table() {
        let e = expect();
        assert_eq!(evaluate_guard(&healthy(), &e), Ok(()));
        type Mutation = Box<dyn Fn(&mut GuardStatus)>;
        let cases: Vec<(Mutation, GuardUnhealthy)> = vec![
            (Box::new(|s| s.ok = false), GuardUnhealthy::NotOk),
            (
                Box::new(|s| {
                    s.ok = false;
                    s.reasons = vec!["host_firewall_blocks_sandboxes:ip/filter/INPUT".into()];
                }),
                GuardUnhealthy::HostFirewall,
            ),
            (
                Box::new(|s| s.quarantined = Some("unsupported_packet_path:flowtable".into())),
                GuardUnhealthy::Quarantined,
            ),
            (
                Box::new(|s| s.boot_id = "other-boot".into()),
                GuardUnhealthy::BootMismatch,
            ),
            (
                Box::new(|s| s.lease_until_boottime_ns = FAKE_NOW_NS),
                GuardUnhealthy::LeaseExpired,
            ),
            (Box::new(|s| s.guard_version = 0), GuardUnhealthy::Outdated),
            (
                Box::new(|s| s.sources.root.state = GuardSourceState::Missing),
                GuardUnhealthy::RootSource,
            ),
            (
                Box::new(|s| s.sources.root.state = GuardSourceState::Invalid),
                GuardUnhealthy::RootSource,
            ),
            (
                Box::new(|s| s.sources.deployment.state = GuardSourceState::Unknown),
                GuardUnhealthy::DeploymentSource,
            ),
        ];
        for (mutate, reason) in cases {
            let mut status = healthy();
            mutate(&mut status);
            assert_eq!(evaluate_guard(&status, &e), Err(reason));
        }
        // A valid root source is healthy; the deployment digest must equal
        // what the daemon last pushed.
        let mut status = healthy();
        status.sources.root = GuardSourceStatus {
            state: GuardSourceState::Valid,
            digest: Some("sha256:root".into()),
        };
        status.sources.deployment = GuardSourceStatus {
            state: GuardSourceState::Valid,
            digest: Some("sha256:a".into()),
        };
        let mut pushed = e.clone();
        pushed.deployment_digest = Some("sha256:a".into());
        assert_eq!(evaluate_guard(&status, &pushed), Ok(()));
        pushed.deployment_digest = Some("sha256:b".into());
        assert_eq!(
            evaluate_guard(&status, &pushed),
            Err(GuardUnhealthy::DeploymentSource)
        );
        assert_eq!(
            evaluate_guard(&status, &e),
            Err(GuardUnhealthy::DeploymentSource)
        );
    }

    #[test]
    fn bridge_attestation_needs_the_live_bridge_and_its_exact_gateway_pair() {
        let e = expect();
        let status = healthy();
        let gw = Ipv4Addr::new(10, 1, 2, 1);
        assert_eq!(attest_bridge(&status, &e, "wsn-0123456789", gw), Ok(()));
        assert_eq!(
            attest_bridge(&status, &e, "wsn-0123456789", Ipv4Addr::new(10, 1, 2, 2)),
            Err(GuardUnhealthy::BridgeNotCovered)
        );
        assert_eq!(
            attest_bridge(&status, &e, "wsn-ffffffffff", gw),
            Err(GuardUnhealthy::BridgeNotCovered)
        );
        let mut dead = status.clone();
        dead.live_bridges.clear();
        assert_eq!(
            attest_bridge(&dead, &e, "wsn-0123456789", gw),
            Err(GuardUnhealthy::BridgeNotCovered)
        );
    }

    #[test]
    fn the_fence_waits_only_for_a_missing_bridge_and_refuses_typed() {
        let probe = FakeGuardProbe::healthy();
        probe.set_cover_all(false);
        let gw = Ipv4Addr::new(10, 1, 2, 1);
        let started = Instant::now();
        let err = attest_sandbox_bridge(&probe, "wsn-0123456789", gw, Duration::from_millis(200))
            .unwrap_err();
        assert!(started.elapsed() >= Duration::from_millis(200));
        assert!(probe.status_calls() > 1, "fresh status per poll");
        assert_eq!(err.egress_refusal(), Some(EgressRefusal::GuardUnavailable));
        probe.cover_bridge("wsn-0123456789", gw);
        attest_sandbox_bridge(&probe, "wsn-0123456789", gw, Duration::ZERO).unwrap();
        // Unhealthy refuses at once, without waiting.
        probe.set_healthy(false);
        let started = Instant::now();
        let err = attest_sandbox_bridge(&probe, "wsn-0123456789", gw, Duration::from_secs(5))
            .unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(err.code, SandboxErrorCode::UnsupportedCapability);
        assert!(check_guard(&probe).is_err());
        assert!(check_guard(&UnavailableGuardProbe).is_err());
    }

    #[test]
    fn uptime_parses_to_nanoseconds() {
        assert_eq!(parse_uptime_ns("12.34 56.78\n"), Some(12_340_000_000));
        assert_eq!(parse_uptime_ns("7 1"), Some(7_000_000_000));
        assert_eq!(parse_uptime_ns("x"), None);
        assert_eq!(parse_uptime_ns("1.2x"), None);
    }
}
