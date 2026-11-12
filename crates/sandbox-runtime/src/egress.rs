//! Shared sandbox egress model for the host runtime (see
//! docs/guide/network.md#what-is-always-blocked).
//!
//! - The sandbox protected IPv4 set is READ from the shared contract fixture
//!   (`crates/sandbox-protocol/fixtures/egress_policy_cases.json`,
//!   `sandboxProtectedV4`), the same file the TypeScript contracts read, so
//!   grant refusal, the DNS-answer filter and the open-mode `PUBLIC_V4`
//!   complement can never drift from the control plane again.
//! - `PUBLIC_V4` is the minimal CIDR complement of that set, computed here and
//!   golden-tested against the fixture's `sandboxPublicV4`.
//! - `EgressSettings` are the node settings an ACL plan is compiled with. They
//!   are captured at materialization and snapshotted into the persisted plan
//!   record, so a later node-setting change never re-derives a running
//!   sandbox's enforcement.
//! - `EgressRefusal` is the typed reason a create / cold reconnect / start
//!   fence refusal carries (mapped onto the wire by the daemon).

use std::net::Ipv4Addr;
use std::sync::OnceLock;

use sandbox_protocol::SandboxErrorCode;

use crate::RuntimeError;

/// The shared contract fixture, embedded at compile time.
const EGRESS_POLICY_CASES_JSON: &str =
    include_str!("../../sandbox-protocol/fixtures/egress_policy_cases.json");

/// One IPv4 network as `(base, prefix)`, base canonical (host bits zero).
pub type Ipv4Net = (u32, u8);

fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    }
}

/// Parse a canonical `a.b.c.d/p` IPv4 CIDR (base address, decimal prefix
/// without leading zeros). Anything else is `None`.
pub fn parse_ipv4_net(text: &str) -> Option<Ipv4Net> {
    let (address, prefix) = text.split_once('/')?;
    if prefix.is_empty()
        || (prefix.len() > 1 && prefix.starts_with('0'))
        || !prefix.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let prefix: u8 = prefix.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    let address: Ipv4Addr = address.parse().ok()?;
    let base = u32::from(address);
    (base & mask(prefix) == base).then_some((base, prefix))
}

pub fn format_ipv4_net((base, prefix): Ipv4Net) -> String {
    format!("{}/{prefix}", Ipv4Addr::from(base))
}

pub fn net_contains((base, prefix): Ipv4Net, ip: Ipv4Addr) -> bool {
    u32::from(ip) & mask(prefix) == base
}

/// True when the two networks share at least one address.
pub fn nets_intersect(a: Ipv4Net, b: Ipv4Net) -> bool {
    let m = mask(a.1.min(b.1));
    a.0 & m == b.0 & m
}

/// `inner` lies entirely inside `outer`.
pub fn net_within(inner: Ipv4Net, outer: Ipv4Net) -> bool {
    inner.1 >= outer.1 && inner.0 & mask(outer.1) == outer.0
}

/// Minimal CIDR cover of `[0, 2^32)` minus `removed`.
pub fn complement(removed: &[Ipv4Net]) -> Vec<Ipv4Net> {
    let mut intervals: Vec<(u64, u64)> = removed
        .iter()
        .map(|&(base, prefix)| {
            let start = u64::from(base);
            (start, start + (1u64 << (32 - u32::from(prefix))))
        })
        .collect();
    intervals.sort_unstable();
    let mut out = Vec::new();
    let mut cursor: u64 = 0;
    for (start, end) in intervals {
        if start > cursor {
            cover(cursor, start, &mut out);
        }
        cursor = cursor.max(end);
    }
    if cursor < 1u64 << 32 {
        cover(cursor, 1u64 << 32, &mut out);
    }
    out
}

/// Emit the maximal aligned blocks covering `[start, end)`.
fn cover(mut start: u64, end: u64, out: &mut Vec<Ipv4Net>) {
    while start < end {
        let mut size: u64 = if start == 0 {
            1u64 << 32
        } else {
            1u64 << start.trailing_zeros()
        };
        while start + size > end {
            size >>= 1;
        }
        let prefix = 32 - size.trailing_zeros() as u8;
        out.push((start as u32, prefix));
        start += size;
    }
}

#[derive(serde::Deserialize)]
struct ProtectedFixture {
    #[serde(rename = "sandboxProtectedV4")]
    sandbox_protected_v4: Vec<String>,
}

struct Ranges {
    protected: Vec<Ipv4Net>,
    public: Vec<Ipv4Net>,
    public_text: String,
}

fn load_ranges() -> Result<Ranges, String> {
    let fixture: ProtectedFixture = serde_json::from_str(EGRESS_POLICY_CASES_JSON)
        .map_err(|err| format!("egress contract fixture is invalid: {err}"))?;
    let mut protected = Vec::with_capacity(fixture.sandbox_protected_v4.len());
    for text in &fixture.sandbox_protected_v4 {
        protected.push(
            parse_ipv4_net(text)
                .ok_or_else(|| format!("egress contract fixture has a bad CIDR `{text}`"))?,
        );
    }
    if protected.is_empty() {
        return Err("egress contract fixture has an empty protected set".into());
    }
    let public = complement(&protected);
    let public_text = public
        .iter()
        .map(|net| format_ipv4_net(*net))
        .collect::<Vec<_>>()
        .join(",");
    Ok(Ranges {
        protected,
        public,
        public_text,
    })
}

fn ranges() -> Result<&'static Ranges, RuntimeError> {
    static RANGES: OnceLock<Result<Ranges, String>> = OnceLock::new();
    RANGES
        .get_or_init(load_ranges)
        .as_ref()
        .map_err(|err| RuntimeError::new(SandboxErrorCode::Internal, err.clone()))
}

/// `SANDBOX_PROTECTED_V4` (shared fixture): private, loopback, link-local and
/// metadata (incl. the Azure wireserver), CGNAT and tailnet, special-purpose.
pub fn sandbox_protected_v4() -> Result<&'static [Ipv4Net], RuntimeError> {
    ranges().map(|ranges| ranges.protected.as_slice())
}

/// `PUBLIC_V4`: the minimal complement of `SANDBOX_PROTECTED_V4`.
pub fn sandbox_public_v4() -> Result<&'static [Ipv4Net], RuntimeError> {
    ranges().map(|ranges| ranges.public.as_slice())
}

/// `PUBLIC_V4` as the comma-separated ACL destination list.
pub fn sandbox_public_v4_text() -> Result<&'static str, RuntimeError> {
    ranges().map(|ranges| ranges.public_text.as_str())
}

/// A destination a guest must never reach, through a grant or a DNS answer.
/// Fails closed: an unavailable table protects everything.
pub fn is_protected_v4(ip: Ipv4Addr) -> bool {
    match sandbox_protected_v4() {
        Ok(protected) => protected.iter().any(|net| net_contains(*net, ip)),
        Err(_) => true,
    }
}

/// Bounds of `EgressSettings` (§2.0.4, §2.2, §3).
pub const MAX_DNS_UPSTREAMS: usize = 4;
pub const MAX_BLOCKED_DOMAINS: usize = 2048;
/// Rendered open-mode dnsmasq body bound: fits the stdin PATCH and the
/// 96 KiB inline fallback for incus < 7.4.
pub const MAX_DNSMASQ_BODY_BYTES: usize = 64 * 1024;
/// Exact `update_acl` PUT body bound (m12).
pub const MAX_ACL_BODY_BYTES: usize = 64 * 1024;
/// Bounded digest token of a blocklist source.
const MAX_DIGEST_LEN: usize = 128;

/// The operator domain blocklist as the guard validated it (§2.0.4): per-
/// source digests (provenance) and the union of names. Captured from the
/// guard's `policy` answer at materialization, never parsed by the daemon.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainBlocklist {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_digest: Option<String>,
    #[serde(default)]
    pub names: Vec<String>,
}

/// Node settings a sandbox's ACL plan and resolver are compiled with (§2.1).
/// Captured at materialization and snapshotted into the persisted plan
/// record: a later change applies only to sandboxes materialized afterwards.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressSettings {
    /// `wssp-smtp-reject` (tcp/25 to `PUBLIC_V4`), both modes. Default on.
    pub block_smtp: bool,
    /// `wssp-dns-ext-reject` (tcp+udp 53,853 to `PUBLIC_V4`), both modes.
    /// Default off.
    pub block_external_dns: bool,
    /// Open-mode guest resolver upstreams (m13); empty = host resolvers.
    #[serde(default)]
    pub dns_upstreams: Vec<Ipv4Addr>,
    #[serde(default)]
    pub domain_blocklist: DomainBlocklist,
    /// CLI-logins proxy mode: the TCP port of the credential proxy
    /// on this sandbox's bridge gateway. `Some` only for a sandbox created
    /// with a proxy-delivery login on a daemon running the proxy; compiles
    /// to the one `wssp-credential-proxy` gateway allow (both modes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_proxy_port: Option<u16>,
    /// B12 blocked-name hints: the loopback UDP port of the daemon's
    /// in-memory DNS stub a TEMPLATE_BUILD sandbox's allowlist-mode resolver
    /// forwards non-granted names to (`server=127.0.0.1#<port>`). `Some`
    /// only for build VMs in allowlist mode; no resolver ever logs queries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused_dns_stub_port: Option<u16>,
}

impl Default for EgressSettings {
    fn default() -> Self {
        Self {
            block_smtp: true,
            block_external_dns: false,
            dns_upstreams: Vec::new(),
            domain_blocklist: DomainBlocklist::default(),
            credential_proxy_port: None,
            refused_dns_stub_port: None,
        }
    }
}

fn settings_error(message: impl Into<String>) -> RuntimeError {
    RuntimeError::new(SandboxErrorCode::ProtocolError, message)
}

fn valid_digest(digest: &str) -> bool {
    !digest.is_empty()
        && digest.len() <= MAX_DIGEST_LEN
        && digest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b':' || b == b'-' || b == b'_')
}

/// Exact lowercase DNS name with at least two labels. One implementation,
/// shared with the guard's source parser and `validate_policy_domain`.
pub use crate::guard::sources::valid_domain_name;

impl EgressSettings {
    /// Validate before any compile or render: bounded, injection-free inputs.
    pub fn validate(&self) -> Result<(), RuntimeError> {
        // The proxy port never aliases a gateway service the plan already
        // allows (DNS 53, DHCP 67) and is never 0.
        if matches!(self.credential_proxy_port, Some(0 | 53 | 67)) {
            return Err(settings_error(
                "the credential proxy port must be a non-zero port other than 53 and 67",
            ));
        }
        if self.refused_dns_stub_port == Some(0) {
            return Err(settings_error("the DNS stub port must be non-zero"));
        }
        if self.dns_upstreams.len() > MAX_DNS_UPSTREAMS {
            return Err(settings_error("egress DNS upstreams exceed 4 entries"));
        }
        for upstream in &self.dns_upstreams {
            let octets = upstream.octets();
            if upstream.is_unspecified()
                || upstream.is_broadcast()
                || upstream.is_multicast()
                || octets[0] == 0
                || octets[0] >= 240
            {
                return Err(settings_error("egress DNS upstream is not a unicast IPv4"));
            }
        }
        let blocklist = &self.domain_blocklist;
        if blocklist.names.len() > MAX_BLOCKED_DOMAINS {
            return Err(settings_error(
                "egress domain blocklist exceeds 2048 entries",
            ));
        }
        if !blocklist.names.iter().all(|name| valid_domain_name(name)) {
            return Err(settings_error(
                "egress domain blocklist holds an invalid domain",
            ));
        }
        if [&blocklist.root_digest, &blocklist.deployment_digest]
            .into_iter()
            .flatten()
            .any(|digest| !valid_digest(digest))
        {
            return Err(settings_error("egress domain blocklist digest is invalid"));
        }
        Ok(())
    }
}

/// M19: one predicate at every point a grant name becomes an address. A name
/// is denied when it equals a blocked domain or is a subdomain of one.
pub fn domain_denied(name: &str, settings: &EgressSettings) -> bool {
    settings.domain_blocklist.names.iter().any(|blocked| {
        name == blocked
            || name
                .strip_suffix(blocked.as_str())
                .is_some_and(|head| head.ends_with('.'))
    })
}

/// Typed egress refusal reasons (§1.4, §1.5, §2.1). Carried on the runtime
/// error; the daemon maps them onto the wire `details.reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressRefusal {
    /// The node's egress guard is missing, unhealthy, outdated, its lease
    /// expired, or it does not cover this sandbox's bridge. Retryable.
    GuardUnavailable,
    /// An open-mode sandbox on a node whose owner does not allow open egress
    /// for other users' sandboxes. Terminal for the sandbox.
    OpenEgressNotPermitted,
    /// The compiled ACL body exceeds its bound (m12).
    PolicyTooLarge,
    /// A DNS refresh whose recompiled ACL body would exceed the byte budget
    /// was not published: the last-good rules stay (fails narrow).
    RefreshOverBudget,
}

impl EgressRefusal {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GuardUnavailable => "egress_guard_unavailable",
            Self::OpenEgressNotPermitted => "open_egress_not_permitted",
            Self::PolicyTooLarge => "egress_policy_too_large",
            Self::RefreshOverBudget => "egress_refresh_over_budget",
        }
    }

    /// The typed wire reason (`details.reason` with `unsupported_capability`).
    /// The size refusals travel as their code alone.
    pub fn wire_reason(self) -> Option<sandbox_protocol::EgressRefusalReason> {
        match self {
            Self::GuardUnavailable => {
                Some(sandbox_protocol::EgressRefusalReason::EgressGuardUnavailable)
            }
            Self::OpenEgressNotPermitted => {
                Some(sandbox_protocol::EgressRefusalReason::OpenEgressNotPermitted)
            }
            Self::PolicyTooLarge | Self::RefreshOverBudget => None,
        }
    }

    pub fn error(self, message: impl Into<String>) -> RuntimeError {
        let code = match self {
            Self::GuardUnavailable | Self::OpenEgressNotPermitted => {
                SandboxErrorCode::UnsupportedCapability
            }
            Self::PolicyTooLarge | Self::RefreshOverBudget => SandboxErrorCode::RequestTooLarge,
        };
        RuntimeError::new(code, message).with_egress_refusal(self)
    }
}

/// The daemon's early admission inputs for a create / cold reconnect (§1.5):
/// computed from the dispatch, the hello owner, the live host policy and a
/// fresh guard status. The runtime start fence stays authoritative.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EgressAdmission {
    /// `sandbox_owner_id == host_owner_id || allow_open_egress_for_others`.
    pub open_egress_permitted: bool,
    /// The daemon's guard check (§2.0.5), never cached across a decision.
    pub guard_ok: bool,
}

impl EgressAdmission {
    /// Test and fake-stack default: own node, healthy guard.
    pub const PERMITTED: Self = Self {
        open_egress_permitted: true,
        guard_ok: true,
    };

    /// §1.5 table: refuse when the guard is not ok (both modes), or when the
    /// mode is open and open egress is not permitted on this node.
    pub fn check(self, mode: sandbox_protocol::EgressMode) -> Result<(), RuntimeError> {
        if !self.guard_ok {
            return Err(EgressRefusal::GuardUnavailable.error(
                "this node's network guard is not running; new sandboxes cannot start here",
            ));
        }
        if mode == sandbox_protocol::EgressMode::Open && !self.open_egress_permitted {
            return Err(EgressRefusal::OpenEgressNotPermitted.error(
                "this node's owner does not allow open internet for other users' sandboxes",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reported_denied_grants_are_sorted_unique_and_bounded() {
        let grants = crate::bounded_denied_grants(vec![
            "b.example".into(),
            "a.example".into(),
            "b.example".into(),
        ]);
        assert_eq!(grants, ["a.example", "b.example"]);
        let many: Vec<String> = (0..500).map(|i| format!("d{i:03}.example")).collect();
        assert_eq!(
            crate::bounded_denied_grants(many).len(),
            crate::MAX_REPORTED_DENIED_GRANTS
        );
        let long: Vec<String> = (0..100)
            .map(|i| format!("{}.d{i:03}.example", "a".repeat(200)))
            .collect();
        let cut = crate::bounded_denied_grants(long);
        assert!(!cut.is_empty());
        assert!(serde_json::to_vec(&cut).unwrap().len() <= crate::MAX_REPORTED_DENIED_GRANT_BYTES);
    }

    fn fixture() -> serde_json::Value {
        serde_json::from_str(EGRESS_POLICY_CASES_JSON).unwrap()
    }

    fn strings(value: &serde_json::Value) -> Vec<String> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn protected_set_is_the_shared_fixture() {
        let expected = strings(&fixture()["sandboxProtectedV4"]);
        let actual: Vec<String> = sandbox_protected_v4()
            .unwrap()
            .iter()
            .map(|net| format_ipv4_net(*net))
            .collect();
        assert_eq!(actual, expected);
        assert!(expected.contains(&"168.63.129.16/32".to_string()));
    }

    #[test]
    fn public_v4_golden_matches_the_fixture_complement() {
        let expected = strings(&fixture()["sandboxPublicV4"]);
        let actual: Vec<String> = sandbox_public_v4()
            .unwrap()
            .iter()
            .map(|net| format_ipv4_net(*net))
            .collect();
        assert_eq!(actual, expected);
        assert_eq!(actual.len(), 139);
        assert_eq!(sandbox_public_v4_text().unwrap(), expected.join(","));
        // Disjoint from, and together with, the protected set covers all of
        // IPv4 exactly once.
        let protected = sandbox_protected_v4().unwrap();
        let mut total: u64 = 0;
        for public in sandbox_public_v4().unwrap() {
            assert!(protected.iter().all(|p| !nets_intersect(*public, *p)));
            total += 1u64 << (32 - u32::from(public.1));
        }
        for p in protected {
            total += 1u64 << (32 - u32::from(p.1));
        }
        assert_eq!(total, 1u64 << 32);
    }

    #[test]
    fn protected_verdicts_match_the_fixture() {
        for case in fixture()["protectedVerdicts"].as_array().unwrap() {
            let address: Ipv4Addr = case["address"].as_str().unwrap().parse().unwrap();
            let protected = case["protected"].as_bool().unwrap();
            assert_eq!(is_protected_v4(address), protected, "{address}");
        }
    }

    #[test]
    fn subtraction_cases_match_the_fixture() {
        for case in fixture()["subtractions"].as_array().unwrap() {
            let cidr = parse_ipv4_net(case["cidr"].as_str().unwrap()).unwrap();
            let removed: Vec<Ipv4Net> = strings(&case["remove"])
                .iter()
                .map(|t| parse_ipv4_net(t).unwrap())
                .collect();
            // Complement within `cidr`: complement of (removed ∪ outside).
            let mut blockers = removed.clone();
            blockers.extend(complement(&[cidr]));
            let actual: Vec<String> = complement(&blockers)
                .into_iter()
                .map(format_ipv4_net)
                .collect();
            assert_eq!(actual, strings(&case["result"]), "{case}");
        }
    }

    #[test]
    fn domain_deny_is_exact_or_suffix_on_a_label_boundary() {
        let settings = EgressSettings {
            domain_blocklist: DomainBlocklist {
                names: vec!["bad.example".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(domain_denied("bad.example", &settings));
        assert!(domain_denied("api.bad.example", &settings));
        assert!(domain_denied("a.b.bad.example", &settings));
        assert!(!domain_denied("notbad.example", &settings));
        assert!(!domain_denied("example", &settings));
        assert!(!domain_denied("bad.example.com", &settings));
        assert!(!domain_denied("good.example", &settings));
    }

    #[test]
    fn settings_validation_bounds_every_input() {
        assert!(EgressSettings::default().validate().is_ok());
        let mut s = EgressSettings {
            dns_upstreams: vec![Ipv4Addr::new(1, 1, 1, 1); 5],
            ..Default::default()
        };
        assert!(s.validate().is_err());
        s.dns_upstreams = vec![Ipv4Addr::new(224, 0, 0, 1)];
        assert!(s.validate().is_err());
        s.dns_upstreams = vec![Ipv4Addr::new(9, 9, 9, 9), Ipv4Addr::new(192, 168, 1, 1)];
        assert!(s.validate().is_ok());
        s.domain_blocklist.names = vec!["Bad.example".into()];
        assert!(s.validate().is_err());
        s.domain_blocklist.names = vec!["bad.example\nserver=1.2.3.4".into()];
        assert!(s.validate().is_err());
        s.domain_blocklist.names = vec!["x.example".into(); MAX_BLOCKED_DOMAINS + 1];
        assert!(s.validate().is_err());
        s.domain_blocklist.names = vec!["x.example".into()];
        s.domain_blocklist.root_digest = Some("sha256:ab cd".into());
        assert!(s.validate().is_err());
    }

    #[test]
    fn admission_table() {
        use sandbox_protocol::EgressMode::{Allowlist, Open};
        let check = |guard_ok, open_egress_permitted, mode| {
            EgressAdmission {
                open_egress_permitted,
                guard_ok,
            }
            .check(mode)
            .map_err(|err| err.egress_refusal())
        };
        assert_eq!(check(true, true, Open), Ok(()));
        assert_eq!(check(true, false, Allowlist), Ok(()));
        assert_eq!(
            check(true, false, Open),
            Err(Some(EgressRefusal::OpenEgressNotPermitted))
        );
        for mode in [Open, Allowlist] {
            assert_eq!(
                check(false, true, mode),
                Err(Some(EgressRefusal::GuardUnavailable))
            );
        }
    }
}
