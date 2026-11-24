//! Host-managed per-sandbox bridge network and ACL lifecycle (M5, C35).
//!
//! Apply order is ACL then network (the network references the ACL); every
//! step is idempotent so a retried create resumes a partial apply, and any
//! failure after the first mutation rolls back through the tag-checked
//! teardown. Reads go through `incus query` (JSON), mutations through the
//! CLI; the effective configuration is read back and compared against the
//! compiled plan before the launch proceeds.

use std::path::PathBuf;

use sandbox_protocol::SandboxErrorCode;

use super::client::{IncusClient, host_cli_error, percent_encode, with_query_params};
use super::network::{
    AclDirection, AclRule, NETWORK_ATTEMPT_TAG, NETWORK_PROJECT_TAG, NETWORK_SANDBOX_TAG,
    SandboxNetworkPlan, allocate_gateway, devices_match_plan, host_route_networks,
    sandbox_network_names,
};
use crate::error::RuntimeError;

/// C37 R4: the typed three-way verdict of a bound-enforcement observation.
/// ONLY `ConfirmedDrift` — a coherent comparison failure against the
/// persisted plan (missing or foreign enforcement objects, absent plan,
/// rule/config/device mismatch) — ever authorizes enforcement-loss
/// cleanup. `Inconclusive` (timeout, cancellation, transport/daemon
/// failure, an unsettleable DNS obligation, or an exhausted coherence
/// budget) carries no drift evidence: it is retryable at every consumer
/// and must never become the cleanup-triggering code or write a loss
/// record.
#[derive(Debug)]
pub(crate) enum EnforcementVerdict {
    Verified,
    ConfirmedDrift(String),
    Inconclusive(RuntimeError),
}

/// Captured locally BEFORE ownership/daemon reads. Private fields bind the
/// detector to its original sandbox and lifecycle provider, not a later arm.
pub(crate) struct CapturedEnforcementLoss {
    sandbox_id: String,
    lifecycle: Option<std::sync::Arc<dyn crate::EnforcementLossLifecycle>>,
    intent: Option<Box<dyn crate::EnforcementLossIntent>>,
}

/// Oldest Incus release whose network ACL enforcement wssp trusts: the
/// CVE-2025-52890 anti-spoofing fix shipped in 6.14 (see
/// `server_egress_support`). Operator-facing copy names this floor.
pub(crate) const MIN_EGRESS_INCUS_VERSION: &str = "6.14";

/// Why a daemon can or cannot enforce recorded egress policies. Only
/// `Supported` grants the capability; every other verdict is a fail-closed
/// diagnosis surfaced to the operator, never an admission input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EgressSupport {
    Supported,
    /// The daemon lacks the `network_acl` API extension.
    MissingAclExtension,
    /// The daemon reported no parseable `server_version`.
    VersionUnknown,
    /// The daemon's release is older than `MIN_EGRESS_INCUS_VERSION`.
    VersionTooOld(String),
}

impl EgressSupport {
    /// Operator diagnosis; `None` when enforcement is available.
    pub(crate) fn unavailable_reason(&self) -> Option<String> {
        match self {
            Self::Supported => None,
            Self::MissingAclExtension => {
                Some("the incus daemon does not offer the `network_acl` API extension".to_string())
            }
            Self::VersionUnknown => Some(format!(
                "the incus daemon reported no parseable version; egress enforcement needs incus {MIN_EGRESS_INCUS_VERSION} or later"
            )),
            Self::VersionTooOld(version) => Some(format!(
                "incus {version} is older than {MIN_EGRESS_INCUS_VERSION}; releases before {MIN_EGRESS_INCUS_VERSION} cannot reliably enforce network ACLs (CVE-2025-52890), so this host cannot create sandboxes until incus is upgraded"
            )),
        }
    }
}

/// Daemon capability required before the host may declare `egressPolicy` in
/// its relay hello or apply a sandbox network. Fails closed: any missing or
/// unparseable evidence is "unsupported"; only `Supported` grants it.
pub(super) fn server_egress_support(metadata: &serde_json::Value) -> EgressSupport {
    let has_acl_extension = metadata
        .get("api_extensions")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|extensions| extensions.iter().any(|e| e.as_str() == Some("network_acl")));
    if !has_acl_extension {
        return EgressSupport::MissingAclExtension;
    }
    // Bridge-network ACLs became stateful in Incus 6.0; an earlier daemon
    // would need an unrestricted egress fallback to pass allowed replies.
    let Some(version) = metadata
        .get("environment")
        .and_then(|e| e.get("server_version"))
        .and_then(serde_json::Value::as_str)
    else {
        return EgressSupport::VersionUnknown;
    };
    // CVE-2025-52890 (GHSA-p7fw-vjjm-2rwp): Incus 6.12 and 6.13 carry an
    // nftables anti-spoofing bypass on ACL-enabled bridges — the daemon
    // ACCEPTS the pinned security properties but cannot reliably enforce
    // them. The fix shipped in 6.14; the daemon exposes no patched-backport
    // marker, so the release boundary is the only evidence. Unpatched
    // releases fail closed: advertising enforcement we cannot trust is
    // worse than declaring the host unsupported.
    let mut parts = version.split(['.', '-', '+']);
    let major = parts.next().and_then(|part| part.parse::<u64>().ok());
    let minor = parts
        .next()
        .and_then(|part| part.parse::<u64>().ok())
        .unwrap_or(0);
    match major {
        Some(major) if major > 6 || (major == 6 && minor >= 14) => EgressSupport::Supported,
        Some(_) => EgressSupport::VersionTooOld(display_version(version)),
        None => EgressSupport::VersionUnknown,
    }
}

/// Daemon-reported version text, bounded and reduced to version characters
/// before it reaches operator copy.
fn display_version(version: &str) -> String {
    version
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+' | '~'))
        .take(32)
        .collect()
}

/// One ACL rule as read back from `GET /1.0/network-acls/<name>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ObservedRule {
    pub(crate) action: String,
    pub(crate) state: String,
    pub(crate) protocol: String,
    pub(crate) source: String,
    pub(crate) destination: String,
    pub(crate) source_port: String,
    pub(crate) destination_port: String,
    pub(crate) description: String,
}

impl ObservedRule {
    pub(super) fn from_json(value: &serde_json::Value) -> Result<Self, RuntimeError> {
        let get = |key: &str| {
            value
                .get(key)
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        if !value.is_object() {
            return Err(RuntimeError::new(
                SandboxErrorCode::Internal,
                "incus network ACL rule is not an object",
            ));
        }
        // Missing or malformed rule-state evidence is never "enabled": a rule
        // whose enforcement state cannot be proven fails the readback.
        // `logged` is Incus's third state: the rule is ACTIVE (and logs
        // matches). It is modelled, not refused (C58 carry-in): refusing it
        // made every readback of a tampered logged allow inconclusive
        // forever. A logged rule never equals a planned (`enabled`) rule,
        // so it reads back as drift, and the owed-mode classifier treats it
        // as active.
        let state = value.get("state").and_then(serde_json::Value::as_str);
        if !matches!(state, Some("enabled" | "disabled" | "logged")) {
            return Err(RuntimeError::new(
                SandboxErrorCode::Internal,
                "incus network ACL rule is missing effective state evidence",
            ));
        }
        Ok(Self {
            action: get("action"),
            state: state.unwrap_or_default().to_string(),
            protocol: get("protocol"),
            source: get("source"),
            destination: get("destination"),
            source_port: get("source_port"),
            destination_port: get("destination_port"),
            description: get("description"),
        })
    }

    pub(super) fn matches_plan(&self, rule: &AclRule) -> bool {
        self.action == rule.action.as_str()
            && self.state == "enabled"
            && self.protocol == rule.protocol.as_deref().unwrap_or_default()
            && self.source == rule.source.as_deref().unwrap_or_default()
            && self.destination == rule.destination.as_deref().unwrap_or_default()
            && self.source_port == rule.source_port.as_deref().unwrap_or_default()
            && self.destination_port == rule.destination_port.as_deref().unwrap_or_default()
            && self.description == rule.description
    }

    /// View this observed rule as a plan rule (empty fields become `None`).
    /// Used to persist the rule set AS INSTALLED (observed order) after a
    /// DNS refresh, so the positional reconnect readback compares like with
    /// like. Only the two actions a plan can express are representable.
    pub(crate) fn as_acl_rule(
        &self,
        direction: super::network::AclDirection,
    ) -> Result<AclRule, RuntimeError> {
        let action = match self.action.as_str() {
            "allow" => super::network::AclAction::Allow,
            "reject" => super::network::AclAction::Reject,
            other => {
                return Err(RuntimeError::new(
                    SandboxErrorCode::Internal,
                    format!("incus sandbox ACL rule carries an unmanaged action `{other}`"),
                ));
            }
        };
        let nonempty = |value: &str| (!value.is_empty()).then(|| value.to_string());
        Ok(AclRule {
            action,
            direction,
            protocol: nonempty(&self.protocol),
            source: nonempty(&self.source),
            destination: nonempty(&self.destination),
            source_port: nonempty(&self.source_port),
            destination_port: nonempty(&self.destination_port),
            description: self.description.clone(),
        })
    }
}

pub(crate) struct ObservedAcl {
    pub(crate) sandbox_tag: Option<String>,
    /// Owning-project tag; absence never proves ownership.
    pub(crate) project_tag: Option<String>,
    pub(crate) ingress: Vec<ObservedRule>,
    pub(crate) egress: Vec<ObservedRule>,
}

/// Incus's API struct order is part of its ETag hash (driver_common.Etag,
/// util.EtagHash). Retain omitted strings, null slices and sorted config keys
/// exactly as Go's encoding/json does; never send an unconditional replacement.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct ApiAclRule {
    action: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    source: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    destination: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    protocol: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    source_port: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    destination_port: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    icmp_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    icmp_code: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    description: String,
    state: String,
}

pub(super) fn acl_etag(metadata: &serde_json::Value) -> Result<String, RuntimeError> {
    #[derive(serde::Deserialize)]
    struct Document {
        name: String,
        #[serde(default)]
        description: String,
        ingress: Option<Vec<ApiAclRule>>,
        egress: Option<Vec<ApiAclRule>>,
        config: Option<std::collections::BTreeMap<String, String>>,
    }
    let doc: Document = serde_json::from_value(metadata.clone()).map_err(|err| {
        RuntimeError::new(
            SandboxErrorCode::Internal,
            format!("cannot decode ACL ETag inputs: {err}"),
        )
    })?;
    let encoded = serde_json::to_string(&(
        doc.name,
        doc.description,
        doc.ingress,
        doc.egress,
        doc.config,
    ))
    .map_err(|err| {
        RuntimeError::new(
            SandboxErrorCode::Internal,
            format!("cannot encode ACL ETag inputs: {err}"),
        )
    })?;
    let encoded = encoded
        .replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
        + "\n";
    Ok(
        ring::digest::digest(&ring::digest::SHA256, encoded.as_bytes())
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    )
}

pub(super) fn api_rule(rule: &AclRule) -> serde_json::Value {
    let mut value = serde_json::json!({"action": rule.action.as_str(), "state": "enabled", "description": rule.description});
    for (key, field) in [
        ("protocol", &rule.protocol),
        ("source", &rule.source),
        ("destination", &rule.destination),
        ("source_port", &rule.source_port),
        ("destination_port", &rule.destination_port),
    ] {
        if let Some(field) = field {
            value[key] = serde_json::Value::String(field.clone());
        }
    }
    value
}

impl IncusClient {
    pub(crate) fn supports_atomic_acl_updates(&self) -> bool {
        self.acl_update_mode
            .load(std::sync::atomic::Ordering::Acquire)
            != 1
    }

    /// One read-modify-PUT under the FIFO lane, with one cumulative call budget.
    /// A unique config revision prevents ABA after a late, uncertain PUT. The
    /// conditional request cannot reintroduce an allow withdrawn by a newer edit.
    pub(crate) fn update_acl(
        &self,
        name: &str,
        timeout: std::time::Duration,
        edit: impl FnOnce(&mut serde_json::Value) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        if !self.supports_atomic_acl_updates() {
            return Err(RuntimeError::new(
                SandboxErrorCode::HostRuntimeUnsupported,
                "incus CLI does not support conditional ACL updates",
            ));
        }
        let deadline = std::time::Instant::now() + timeout;
        let _turn = self.acl_edit_turn(name, deadline)?;
        let path = acl_url(name, &self.project);
        let mut metadata = self.query_raw_timed(
            &path,
            deadline.saturating_duration_since(std::time::Instant::now()),
        )?;
        let etag = acl_etag(&metadata)?;
        edit(&mut metadata)?;
        let mut revision = [0u8; 16];
        getrandom::fill(&mut revision).map_err(|err| {
            RuntimeError::new(
                SandboxErrorCode::Internal,
                format!("cannot allocate ACL revision: {err}"),
            )
        })?;
        metadata["config"]["user.wssp.acl-revision"] = revision
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
            .into();
        let body = serde_json::json!({
            "description": metadata.get("description").and_then(serde_json::Value::as_str).unwrap_or_default(),
            "config": metadata["config"], "ingress": metadata["ingress"], "egress": metadata["egress"],
        });
        self.query_body_timed(
            "PUT",
            &path,
            &body.to_string(),
            &[&format!("If-Match: \"{etag}\"")],
            deadline.saturating_duration_since(std::time::Instant::now()),
        )?;
        Ok(())
    }
}

/// A durable cleanup journal entry. `phase` separates a provisioning intent
/// (recorded BEFORE the first apply mutation; retired by adoption or a
/// verified rollback) from a teardown obligation (kill write-ahead / failed
/// rollback). Every record must identify its phase and project.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CleanupPhase {
    Provisioning,
    Teardown,
}

#[derive(Debug, Clone)]
struct CleanupRecord {
    phase: CleanupPhase,
    /// Incarnations the obligation covers. A retry writes its fresh token
    /// BEFORE restamping, so the record must retain the previous (and any
    /// transitional) incarnation: a crash mid-restamp leaves resources whose
    /// markers the sole journal entry must still fence. Empty sets are invalid.
    attempts: Vec<String>,
    /// Owning project. A drain processes and removes only its own project's
    /// records: two projects sharing a state root must never unlink each
    /// other's obligations.
    project: String,
    /// The full instance binding (the `bind_instance` tuple) this
    /// provisioning intent was written for. Recovery must verify the
    /// EXISTING VM against it before any repair or adoption: the normal
    /// create path rejects a VM with a conflicting template, base image, or
    /// create key, and the drain must never mutate an instance that
    /// authorization path rejected. Provisioning records require the binding;
    /// teardown records do not authorize provisioning repairs.
    binding: Option<super::network::PlanBinding>,
}

pub(crate) fn network_url(name: &str, project: &str) -> String {
    with_query_params(
        &format!("/1.0/networks/{}", percent_encode(name)),
        &[("project", project)],
    )
}

fn acl_url(name: &str, project: &str) -> String {
    with_query_params(
        &format!("/1.0/network-acls/{}", percent_encode(name)),
        &[("project", project)],
    )
}

fn unsupported_egress() -> RuntimeError {
    RuntimeError::new(
        SandboxErrorCode::UnsupportedCapability,
        "incus daemon cannot enforce sandbox egress policies (requires network ACLs, stateful bridge ACLs, and the CVE-2025-52890 fix: Incus >= 6.14)",
    )
}

/// Held while a sandbox subnet is chosen and its bridge is created. The
/// `flock` releases on drop, including on panic paths.
#[derive(Debug)]
pub(crate) struct SubnetAllocationGuard {
    /// Holding the file holds the flock; released on drop.
    _file: std::fs::File,
}

pub(crate) fn foreign_object(kind: &str, name: &str) -> RuntimeError {
    RuntimeError::new(
        SandboxErrorCode::IdempotencyConflict,
        format!(
            "incus {kind} `{name}` is not owned by this sandbox; refusing to address another sandbox's rules"
        ),
    )
}

/// Read budget for an enforcement observation whose caller permit elapsed
/// while DNS expiry recovery ran (C58 G1 r3): the reconciler's own
/// per-candidate budget.
const OBSERVATION_READ_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

/// C58 NEW-1: does an OWED DNS refresh/settlement fully explain how the
/// live ACL differs from the persisted plan? The test admits only the
/// host's own journaled DNS work, in the never-broader direction:
///
/// - ingress and every non-DNS (static/base) egress rule match the plan
///   exactly, in order — a refresh never touches them;
/// - a DNS-tagged rule may appear or vanish freely ONLY when it provably
///   narrows: state `disabled`, or action `reject`/`drop` (Incus rejects
///   outrank allows). Every other DNS-tagged rule is treated as an allow
///   and must be exactly a canonical `allow` in state `enabled`; an
///   `allow-stateless`, a `logged` allow or any unknown action is
///   unexplained (G1-R1-1);
/// - a planned DNS allow may be ABSENT (withdrawn, denied, lapsed);
/// - every DNS allow present is destination-wide fenced, or is a
///   planned or ledger-armed identity (the ledger is persisted before any
///   allow is issued) carrying its exact DNS/DoT reject companions unless
///   a static policy CIDR covers it;
/// - an allow whose identity the refresh DENIED (uncommitted revocation)
///   is never "our own work" (G1-R1-2): if it is live and unfenced, and no
///   other explained, non-denied allow or static CIDR still authorizes its
///   destination, the denied destination is OPEN — real broadening against
///   the intended policy — and it convicts exactly as before C58.
///
/// Anything else — a foreign or unarmed allow, a missing companion, a
/// changed static rule — is unexplained: the caller convicts drift.
fn acl_explained_by_owed_dns_work(
    observed: &ObservedAcl,
    planned: &[AclRule],
    static_grants: &[super::network::GrantCidr],
    owed: &super::dns::DnsOwedEvidence,
) -> OwedExplanation {
    use super::network::is_dns_dynamic_tag;
    let planned_ingress: Vec<&AclRule> = planned
        .iter()
        .filter(|rule| rule.direction == AclDirection::Ingress)
        .collect();
    if planned_ingress.len() != observed.ingress.len()
        || !planned_ingress
            .iter()
            .zip(&observed.ingress)
            .all(|(rule, observed)| observed.matches_plan(rule))
    {
        return OwedExplanation::Unexplained;
    }
    let planned_static: Vec<&AclRule> = planned
        .iter()
        .filter(|rule| {
            rule.direction == AclDirection::Egress && !is_dns_dynamic_tag(&rule.description)
        })
        .collect();
    let observed_static: Vec<&ObservedRule> = observed
        .egress
        .iter()
        .filter(|rule| !is_dns_dynamic_tag(&rule.description))
        .collect();
    if planned_static.len() != observed_static.len()
        || !planned_static
            .iter()
            .zip(&observed_static)
            .all(|(rule, observed)| observed.matches_plan(rule))
    {
        return OwedExplanation::Unexplained;
    }
    let planned_allows: std::collections::BTreeSet<(&str, &str)> = planned
        .iter()
        .filter(|rule| {
            rule.direction == AclDirection::Egress
                && rule.action == super::network::AclAction::Allow
                && is_dns_dynamic_tag(&rule.description)
        })
        .filter_map(|rule| {
            rule.destination
                .as_deref()
                .map(|dest| (rule.description.as_str(), dest))
        })
        .collect();
    let static_covered = |dest: &str| {
        dest.strip_suffix("/32")
            .and_then(|ip| ip.parse::<std::net::Ipv4Addr>().ok())
            .is_some_and(|ip| static_grants.iter().any(|grant| grant.contains(ip)))
    };
    let fenced = |dest: &str| {
        observed
            .egress
            .iter()
            .any(|fence| super::dns::is_canonical_dns_fence(fence, dest))
    };
    // Denied-but-live identities are judged AFTER every other allow, so a
    // destination still legitimately authorized by a non-denied explained
    // allow is not misread as open.
    let mut denied_live: Vec<&str> = Vec::new();
    let mut authorized: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for rule in observed
        .egress
        .iter()
        .filter(|rule| is_dns_dynamic_tag(&rule.description))
    {
        if rule.state == "disabled" || matches!(rule.action.as_str(), "reject" | "drop") {
            // Provably narrowing or inert: never broadens.
            continue;
        }
        if rule.action != "allow" || rule.state != "enabled" {
            // Active and not an exact managed allow (allow-stateless, a
            // logged allow, an unknown action): unexplained.
            return OwedExplanation::Unexplained;
        }
        if !rule.protocol.is_empty()
            || !rule.source.is_empty()
            || !rule.source_port.is_empty()
            || !rule.destination_port.is_empty()
        {
            return OwedExplanation::Unexplained;
        }
        let dest = rule.destination.as_str();
        if fenced(dest) {
            // Destination-wide reject outranks the allow: fully denied.
            continue;
        }
        if owed.is_denied_identity(&rule.description) {
            denied_live.push(dest);
            continue;
        }
        let identity = (rule.description.clone(), rule.destination.clone());
        // Host-issued: planned, armed in the expiry ledger, or a journaled
        // uncertain request that landed late (C58 G1-R3-2).
        let ours = planned_allows.contains(&(rule.description.as_str(), dest))
            || owed.armed.contains(&identity)
            || owed.pending_allows.contains(&identity);
        if !ours {
            return OwedExplanation::Unexplained;
        }
        if static_covered(dest) {
            authorized.insert(dest);
            continue;
        }
        if dns_allow_companion_tag(&rule.description).is_none() {
            return OwedExplanation::Unexplained;
        }
        let companions_present =
            [("udp", "53"), ("tcp", "53"), ("tcp", "853")]
                .iter()
                .all(|(protocol, port)| {
                    observed.egress.iter().any(|companion| {
                        companion.action == "reject"
                            && companion.state == "enabled"
                            // Any DNS-managed companion closes the resolver
                        // hole for this destination (C58 G1-R3-2): a
                        // late-landed old identity is covered by the
                        // current grant's companions.
                        && is_dns_dynamic_tag(&companion.description)
                            && companion.destination == dest
                            && companion.protocol == *protocol
                            && companion.destination_port == *port
                            && companion.source.is_empty()
                            && companion.source_port.is_empty()
                    })
                });
        if !companions_present {
            return OwedExplanation::Unexplained;
        }
        authorized.insert(dest);
    }
    // A denied identity still live and unfenced leaves its destination
    // open unless something else the policy still grants covers it.
    if denied_live
        .iter()
        .all(|dest| authorized.contains(dest) || static_covered(dest))
    {
        OwedExplanation::Explained
    } else {
        OwedExplanation::DeniedDestinationOpen
    }
}

/// The owed-mode classifier's verdict. A denied destination left open is
/// reported apart from other unexplained differences; both convict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OwedExplanation {
    Explained,
    Unexplained,
    DeniedDestinationOpen,
}

/// The DNS/DoT companion tag of a domain ALLOW tag (including compile-time
/// generation zero); `None` for any other
/// DNS tag family (an allow carrying a reject or fence tag is not ours).
fn dns_allow_companion_tag(allow: &str) -> Option<String> {
    let rest = allow.strip_prefix("wssp-dns-")?;
    if rest.starts_with("reject-")
        || rest.starts_with("quarantine-")
        || rest.starts_with("lease-quarantine-")
    {
        return None;
    }
    Some(format!("wssp-dns-reject-{rest}"))
}

/// Parse an `a.b.c.d/prefix` interface address into its (base, prefix)
/// network. Rejects IPv6 and malformed text; `none` yields `None`.
fn parse_ipv4_network(address: &str) -> Option<(u32, u8)> {
    let (addr, prefix) = address.split_once('/')?;
    let addr: std::net::Ipv4Addr = addr.parse().ok()?;
    let prefix: u8 = prefix.parse().ok().filter(|p| *p <= 32)?;
    let shift = 32 - u32::from(prefix);
    let mask = if shift == 32 { 0 } else { u32::MAX << shift };
    Some((u32::from(addr) & mask, prefix))
}

/// Process-wide counter making every durable-record temp path unique
/// (C36 r20 F3); see `write_durable_record`.
fn durable_tmp_counter() -> &'static std::sync::atomic::AtomicU64 {
    static DURABLE_TMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    &DURABLE_TMP_COUNTER
}

/// Test-only peek at the next durable-record temp counter value, so a test
/// can plant a symlink at exactly the temp path the next write will use.
#[cfg(test)]
pub(crate) fn peek_durable_tmp_counter() -> u64 {
    durable_tmp_counter().load(std::sync::atomic::Ordering::Relaxed)
}

impl IncusClient {
    /// Daemon-level evidence for the relay hello capability. The hello wiring
    /// maps any error to `false` — the capability is only ever advertised on
    /// positive proof.
    pub(crate) fn egress_enforcement_capability(&self) -> Result<bool, RuntimeError> {
        Ok(self.egress_support()? == EgressSupport::Supported)
    }

    /// The daemon's typed egress verdict (one `incus query /1.0`).
    pub(crate) fn egress_support(&self) -> Result<EgressSupport, RuntimeError> {
        let metadata = self.query_raw(&with_query_params(
            "/1.0",
            &[("project", self.project.as_str())],
        ))?;
        Ok(server_egress_support(&metadata))
    }

    /// ACL config map only (no rule bodies). Teardown must work even when
    /// the rules are unparseable — a corrupt owned ACL is exactly what
    /// rollback deletes.
    fn read_acl_config(
        &self,
        name: &str,
    ) -> Result<Option<serde_json::Map<String, serde_json::Value>>, RuntimeError> {
        match self.query_raw(&acl_url(name, &self.project)) {
            Ok(metadata) => Ok(metadata
                .get("config")
                .and_then(serde_json::Value::as_object)
                .cloned()),
            Err(err) if err.code == SandboxErrorCode::SandboxNotFound => Ok(None),
            Err(err) => Err(err),
        }
    }

    /// Ownership tag only.
    fn read_acl_tag(&self, name: &str) -> Result<Option<Option<String>>, RuntimeError> {
        Ok(self.read_acl_config(name)?.map(|config| {
            config
                .get(NETWORK_SANDBOX_TAG)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        }))
    }

    pub(crate) fn read_sandbox_acl(&self, name: &str) -> Result<Option<ObservedAcl>, RuntimeError> {
        self.read_sandbox_acl_within(name, None)
    }

    /// Caller-bounded variant (C36 r21 F2): the lease settlement's
    /// readbacks are capped by the next live expiry, so a stalled ACL
    /// read can never delay a later deadline behind the owner lock.
    pub(crate) fn read_sandbox_acl_within(
        &self,
        name: &str,
        budget: Option<std::time::Duration>,
    ) -> Result<Option<ObservedAcl>, RuntimeError> {
        let metadata = match match budget {
            Some(budget) => self.query_raw_timed(&acl_url(name, &self.project), budget),
            None => self.query_raw(&acl_url(name, &self.project)),
        } {
            Ok(metadata) => metadata,
            Err(err) if err.code == SandboxErrorCode::SandboxNotFound => return Ok(None),
            Err(err) => return Err(err),
        };
        let parse_rules = |key: &str| -> Result<Vec<ObservedRule>, RuntimeError> {
            metadata
                .get(key)
                .and_then(serde_json::Value::as_array)
                .map(|rules| rules.iter().map(ObservedRule::from_json).collect())
                .unwrap_or_else(|| Ok(Vec::new()))
        };
        Ok(Some(ObservedAcl {
            sandbox_tag: metadata
                .get("config")
                .and_then(|c| c.get(NETWORK_SANDBOX_TAG))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            project_tag: metadata
                .get("config")
                .and_then(|c| c.get(NETWORK_PROJECT_TAG))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            ingress: parse_rules("ingress")?,
            egress: parse_rules("egress")?,
        }))
    }

    pub(crate) fn read_network_config(
        &self,
        name: &str,
    ) -> Result<Option<serde_json::Map<String, serde_json::Value>>, RuntimeError> {
        match self.query_raw(&network_url(name, &self.project)) {
            Ok(metadata) => Ok(metadata
                .get("config")
                .and_then(serde_json::Value::as_object)
                .cloned()),
            Err(err) if err.code == SandboxErrorCode::SandboxNotFound => Ok(None),
            Err(err) => Err(err),
        }
    }

    fn acl_rules_match(&self, observed: &ObservedAcl, planned: &[AclRule]) -> bool {
        let planned_ingress: Vec<&AclRule> = planned
            .iter()
            .filter(|rule| rule.direction == AclDirection::Ingress)
            .collect();
        let planned_egress: Vec<&AclRule> = planned
            .iter()
            .filter(|rule| rule.direction == AclDirection::Egress)
            .collect();
        planned_ingress.len() == observed.ingress.len()
            && planned_egress.len() == observed.egress.len()
            && planned_ingress
                .iter()
                .zip(&observed.ingress)
                .all(|(rule, observed)| observed.matches_plan(rule))
            && planned_egress
                .iter()
                .zip(&observed.egress)
                .all(|(rule, observed)| observed.matches_plan(rule))
    }

    /// Verify the live ACL against its persisted enforcement record.
    fn acl_matches_effective(&self, observed: &ObservedAcl, plan: &SandboxNetworkPlan) -> bool {
        self.effective_planned_rules(plan)
            .as_ref()
            .is_some_and(|rules| {
                self.acl_rules_match(observed, rules)
                // Preview tunnels: an unconfirmed runtime port change's
                // variant (and only it) is no drift either.
                || self
                    .tunnel_pending_variant(&plan.sandbox_id, rules)
                    .is_some_and(|variant| self.acl_rules_match(observed, &variant))
            })
    }

    /// Tests: the live ACL against the record (`acl_matches_effective`),
    /// with no side effect.
    #[cfg(test)]
    pub(crate) fn live_acl_matches_record(&self, sandbox_id: &str) -> bool {
        let Some(plan) = self.persisted_enforcement_plan(sandbox_id) else {
            return false;
        };
        let Ok(Some(observed)) = self.read_sandbox_acl(&plan.acl_name) else {
            return false;
        };
        self.acl_matches_effective(&observed, &plan)
    }

    /// The rule set `acl_matches_effective` compares against, materialized
    /// for the owed-mode readback (C58 NEW-1). `None` = no record (the
    /// comparison fails closed exactly as above).
    fn effective_planned_rules(&self, plan: &SandboxNetworkPlan) -> Option<Vec<AclRule>> {
        self.recorded_reference_rules(plan)
    }

    /// The persisted record's rules for this plan: hash-bound when the plan
    /// carries its recorded policy hash; a record-derived plan (readiness,
    /// census) carries none and reads its own record.
    fn recorded_reference_rules(&self, plan: &SandboxNetworkPlan) -> Option<Vec<AclRule>> {
        match plan.policy_hash.as_deref() {
            Some(hash) => self.persisted_plan_rules(&plan.sandbox_id, hash),
            None => self
                .persisted_enforcement_plan(&plan.sandbox_id)
                .map(|recorded| recorded.rules),
        }
    }

    /// §2.6: once a sandbox's bridge exists, the persisted record ALONE is
    /// the reference — its rules, mode, settings, resolver base and denied
    /// grants replace this attempt's fresh compile (node settings may have
    /// changed since materialization). The record must exist and be bound to
    /// the same recorded policy hash; anything else fails closed.
    pub(crate) fn overlay_recorded_plan(
        &self,
        plan: &mut SandboxNetworkPlan,
    ) -> Result<(), RuntimeError> {
        let drift =
            |message: &str| RuntimeError::new(SandboxErrorCode::IdempotencyConflict, message);
        let recorded = self
            .persisted_enforcement_plan_checked(&plan.sandbox_id)?
            .ok_or_else(|| drift("the sandbox network exists without its recorded egress plan"))?;
        if self.recorded_policy_hash(&plan.sandbox_id) != Some(plan.policy_hash.clone()) {
            return Err(drift(
                "the sandbox's recorded egress plan belongs to a different policy",
            ));
        }
        plan.rules = recorded.rules;
        plan.mode = recorded.mode;
        plan.settings = recorded.settings;
        plan.dnsmasq_base = recorded.dnsmasq_base;
        plan.denied_grants = recorded.denied_grants;
        Ok(())
    }

    /// m15 gateway-bound write-ahead, run inside the allocation section with
    /// the gateway just chosen under the daemon-wide lock and BEFORE any
    /// object that depends on the gateway or the rules (bridge, rule install,
    /// `raw.dnsmasq` publication). A retry may rewrite the record only while
    /// no bridge exists; once one exists its gateway must equal the record's.
    fn bind_gateway_write_ahead(
        &self,
        plan: &mut SandboxNetworkPlan,
        gateway: std::net::Ipv4Addr,
        bridge_existed: bool,
    ) -> Result<(), RuntimeError> {
        if plan.settings.is_none() {
            return Err(unsupported_egress());
        }
        if bridge_existed {
            let recorded = self
                .persisted_enforcement_plan_checked(&plan.sandbox_id)?
                .ok_or_else(|| {
                    RuntimeError::new(
                        SandboxErrorCode::IdempotencyConflict,
                        "the sandbox network exists without its recorded egress plan",
                    )
                })?;
            if recorded.gateway != gateway {
                return Err(RuntimeError::new(
                    SandboxErrorCode::IdempotencyConflict,
                    "the sandbox bridge's gateway differs from the recorded egress plan",
                ));
            }
            plan.set_gateway(gateway);
            return Ok(());
        }
        plan.set_gateway(gateway);
        #[cfg(test)]
        self.pause_create_for_test("before_write_ahead");
        self.persist_resolved_plan(plan)?;
        #[cfg(test)]
        self.pause_create_for_test("after_write_ahead");
        Ok(())
    }

    /// The start-fence guard attestation (§2.0.5) for this sandbox's
    /// RECORDED bridge and gateway.
    pub(crate) fn attest_guard_for_start(&self, sandbox_id: &str) -> Result<(), RuntimeError> {
        let recorded = self
            .persisted_enforcement_plan_checked(sandbox_id)?
            .ok_or_else(|| {
                RuntimeError::new(
                    SandboxErrorCode::IdempotencyConflict,
                    "no recorded egress plan to attest the guard against",
                )
            })?;
        crate::guard::probe::attest_sandbox_bridge(
            self.guard_probe.as_ref(),
            &recorded.network_name,
            recorded.gateway,
            self.guard_fence_wait,
        )
    }

    /// The recorded egress mode of this sandbox (§1.5 cold-reconnect check):
    /// a missing or invalid record is unavailable evidence.
    pub(crate) fn recorded_egress_mode(
        &self,
        sandbox_id: &str,
    ) -> Result<sandbox_protocol::EgressMode, RuntimeError> {
        self.persisted_enforcement_plan_checked(sandbox_id)?
            .map(|recorded| recorded.mode)
            .ok_or_else(|| {
                RuntimeError::new(
                    SandboxErrorCode::IdempotencyConflict,
                    "no recorded egress plan for this sandbox",
                )
            })
    }

    /// §2.2 publication of the recorded resolver base: the bridge is created
    /// with the deny-all base (small argv), then — before any verification
    /// or start — the recorded body (open-mode resolver, or allowlist base
    /// plus blocked `local=` lines) is published through the stdin PATCH
    /// boundary and read back. A bridge still at the creation base is ours
    /// to publish; anything else is left to the readback, which convicts it.
    /// A sandbox whose DNS publication owns `raw.dnsmasq` is untouched.
    fn publish_recorded_dnsmasq_base(&self, plan: &SandboxNetworkPlan) -> Result<(), RuntimeError> {
        if plan.settings.is_none() {
            return Err(unsupported_egress());
        }
        if plan.dnsmasq_base == super::dns::base_dnsmasq_config() {
            return Ok(());
        }
        if self.dns_state_exists(&plan.sandbox_id)? {
            return Ok(());
        }
        let config = self
            .read_network_config(&plan.network_name)?
            .ok_or_else(unsupported_egress)?;
        let live = config
            .get("raw.dnsmasq")
            .and_then(serde_json::Value::as_str);
        if live == Some(plan.dnsmasq_base.as_str()) {
            return Ok(());
        }
        if live != Some(super::dns::base_dnsmasq_config().as_str()) {
            return Err(RuntimeError::new(
                SandboxErrorCode::IdempotencyConflict,
                "incus sandbox network resolver config differs from the recorded plan",
            ));
        }
        #[cfg(test)]
        self.pause_create_for_test("before_dnsmasq_publish");
        self.publish_dnsmasq_config_within(&plan.network_name, &plan.dnsmasq_base, None)
    }

    /// Fresh per-apply incarnation token. Never persisted outside the
    /// network/ACL config and the fenced cleanup journal.
    pub(crate) fn new_attempt_token() -> Result<String, RuntimeError> {
        use ring::rand::SecureRandom;
        let mut bytes = [0u8; 16];
        ring::rand::SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| {
                RuntimeError::new(
                    SandboxErrorCode::Internal,
                    "cannot generate a network apply attempt token",
                )
            })?;
        Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
    }

    fn ensure_sandbox_acl(
        &self,
        plan: &SandboxNetworkPlan,
        attempt: &str,
    ) -> Result<bool, RuntimeError> {
        if let Some(observed) = self.read_sandbox_acl(&plan.acl_name)? {
            let managed = observed
                .project_tag
                .as_deref()
                .map(|project| project == self.project)
                .unwrap_or(false);
            if observed.sandbox_tag.as_deref() != Some(plan.sandbox_id.as_str()) || !managed {
                return Err(foreign_object("network acl", &plan.acl_name));
            }
            if !self.acl_matches_effective(&observed, plan) {
                return Err(RuntimeError::new(
                    SandboxErrorCode::IdempotencyConflict,
                    "incus network ACL rules differ from the recorded egress policy",
                ));
            }
            // Restamp the incarnation so a stale cleanup record from an
            // earlier failed attempt can never delete this ACL.
            self.stamp_attempt_acl(&plan.acl_name, attempt)?;
            return Ok(false);
        }
        let create = self.run(
            &[
                "network",
                "acl",
                "create",
                &plan.acl_name,
                &format!("{}={}", NETWORK_SANDBOX_TAG, plan.sandbox_id),
                &format!("{NETWORK_ATTEMPT_TAG}={attempt}"),
                &format!("{NETWORK_PROJECT_TAG}={}", self.project),
            ],
            false,
        )?;
        if create.exit_code != 0 {
            return Err(host_cli_error("network acl create", &create));
        }
        Ok(true)
    }

    fn install_sandbox_acl_rules(
        &self,
        plan: &SandboxNetworkPlan,
        attempt: &str,
    ) -> Result<(), RuntimeError> {
        let result = self.update_acl(&plan.acl_name, self.agent_timeout, |metadata| {
            let config = &metadata["config"];
            if config[NETWORK_SANDBOX_TAG].as_str() != Some(&plan.sandbox_id)
                || config[NETWORK_PROJECT_TAG].as_str() != Some(&self.project)
                || config[NETWORK_ATTEMPT_TAG].as_str() != Some(attempt)
                || ["ingress", "egress"].iter().any(|key| {
                    metadata[*key]
                        .as_array()
                        .is_some_and(|rules| !rules.is_empty())
                })
            {
                return Err(RuntimeError::new(
                    SandboxErrorCode::IdempotencyConflict,
                    "new ACL changed before initial policy installation",
                ));
            }
            // Domain allows still enter through the journaled DNS boundary.
            for direction in [AclDirection::Ingress, AclDirection::Egress] {
                metadata[direction.as_str()] = plan
                    .rules
                    .iter()
                    .filter(|rule| {
                        rule.direction == direction
                            && !(direction == AclDirection::Egress
                                && super::network::is_dns_dynamic_tag(&rule.description))
                    })
                    .map(api_rule)
                    .collect::<Vec<_>>()
                    .into();
            }
            Ok(())
        });
        if let Err(error) = result {
            if self.supports_atomic_acl_updates() {
                return Err(error);
            }
            // A CLI that predates query --header never issued the PUT. Keep
            // the supported older CLI's ETag-protected identity edit behavior.
            for rule in plan.rules.iter().filter(|rule| {
                !(rule.direction == AclDirection::Egress
                    && super::network::is_dns_dynamic_tag(&rule.description))
            }) {
                let mut args = vec![
                    "network".to_string(),
                    "acl".into(),
                    "rule".into(),
                    "add".into(),
                    plan.acl_name.clone(),
                    rule.direction.as_str().into(),
                ];
                args.extend(rule.cli_args());
                let out = self.run(&args, false)?;
                if out.exit_code != 0 {
                    return Err(host_cli_error("network acl rule add", &out));
                }
            }
        }
        Ok(())
    }

    fn stamp_attempt_acl(&self, name: &str, attempt: &str) -> Result<(), RuntimeError> {
        let out = self.run(
            &["network", "acl", "set", name, NETWORK_ATTEMPT_TAG, attempt],
            false,
        )?;
        if out.exit_code != 0 {
            return Err(host_cli_error("network acl set", &out));
        }
        Ok(())
    }

    fn stamp_attempt_network(&self, name: &str, attempt: &str) -> Result<(), RuntimeError> {
        let out = self.run(
            &["network", "set", name, NETWORK_ATTEMPT_TAG, attempt],
            false,
        )?;
        if out.exit_code != 0 {
            return Err(host_cli_error("network set", &out));
        }
        Ok(())
    }

    /// Preview tunnels: the sandbox's live bridge exists, is this sandbox's
    /// and matches its recorded plan. A plan left behind by a teardown
    /// (e.g. one whose unlink failed before a daemon restart) never names
    /// a target once its bridge, and so its subnet, is gone.
    pub(crate) fn live_network_matches(&self, plan: &SandboxNetworkPlan) -> bool {
        let Ok(Some(config)) = self.read_network_config(&plan.network_name) else {
            return false;
        };
        config
            .get(NETWORK_SANDBOX_TAG)
            .and_then(serde_json::Value::as_str)
            == Some(plan.sandbox_id.as_str())
            && self.manages(&config)
            && self.verify_network_config(&config, plan, None).is_ok()
    }

    fn ensure_sandbox_network(
        &self,
        plan: &SandboxNetworkPlan,
        attempt: &str,
    ) -> Result<(), RuntimeError> {
        if let Some(config) = self.read_network_config(&plan.network_name)? {
            let tag = config
                .get(NETWORK_SANDBOX_TAG)
                .and_then(serde_json::Value::as_str);
            if tag != Some(plan.sandbox_id.as_str()) || !self.manages(&config) {
                return Err(foreign_object("network", &plan.network_name));
            }
            self.verify_network_config(&config, plan, None)?;
            // Restamp the incarnation; see ensure_sandbox_acl.
            self.stamp_attempt_network(&plan.network_name, attempt)?;
            // Preview tunnels: a launch on a surviving bridge re-admits
            // applies a failed teardown may have fenced.
            crate::teardown_hook::network_created(&plan.sandbox_id);
            return Ok(());
        }
        let mut args = vec![
            "network".to_string(),
            "create".to_string(),
            plan.network_name.clone(),
            "--type".to_string(),
            "bridge".to_string(),
        ];
        for (key, value) in plan.network_config() {
            args.push(format!("{key}={value}"));
        }
        args.push(format!("{NETWORK_ATTEMPT_TAG}={attempt}"));
        args.push(format!("{NETWORK_PROJECT_TAG}={}", self.project));
        let out = self.run(&args, false)?;
        if out.exit_code != 0 {
            return Err(host_cli_error("network create", &out));
        }
        // Preview tunnels: a brand-new bridge is a new incarnation the
        // sandbox's client may be applied to again.
        crate::teardown_hook::network_created(&plan.sandbox_id);
        Ok(())
    }

    fn verify_network_config(
        &self,
        config: &serde_json::Map<String, serde_json::Value>,
        plan: &SandboxNetworkPlan,
        owed: Option<&super::dns::DnsOwedEvidence>,
    ) -> Result<(), RuntimeError> {
        let mismatch = || {
            // C37 R4: a comparison against the persisted plan is DRIFT
            // evidence — it must carry the drift code so the enforcement
            // verdict can distinguish it from an inconclusive observation
            // (timeout, cancellation, transport/daemon error).
            RuntimeError::new(
                SandboxErrorCode::IdempotencyConflict,
                "incus sandbox network effective config differs from the compiled plan",
            )
        };
        for (key, value) in plan.network_config() {
            // `raw.dnsmasq` is refresh-managed (C36): after the initial
            // publish the effective value is the last durably published DNS
            // policy, not the deny-all base the bridge was created with. The
            // expectation still comes from OUR persisted state, never from
            // the daemon — a tampered or crashed publish reads back as a
            // mismatch and fails closed.
            let expected;
            let want = if key == "raw.dnsmasq" {
                // C37 R5: an unreadable DNS publication state is
                // unavailable evidence — the error propagates with its own
                // (inconclusive) code, never manufacturing a mismatch.
                expected = self.expected_dnsmasq_config_checked(&plan.sandbox_id)?;
                expected.as_str()
            } else {
                value.as_str()
            };
            let live = config.get(&key).and_then(serde_json::Value::as_str);
            if live != Some(want) {
                // C58 NEW-1: an OWED refresh may have landed a publication
                // whose commit then failed. Only a body this host journaled
                // BEFORE issuing it is explained; anything else is drift.
                let attempted = key == "raw.dnsmasq"
                    && owed.zip(live).is_some_and(|(owed, live)| {
                        owed.published_attempts
                            .contains(&super::dns::dns_publication_digest(live))
                    });
                if !attempted {
                    return Err(mismatch());
                }
            }
        }
        Ok(())
    }

    /// Read back the effective ACL and network and prove they equal the plan.
    /// This inspection is what lets the host stand behind the advertised
    /// `egressEnforcement` capability for this sandbox.
    /// `pub(crate)` for the C36 r34 DNS drain/commit tests, which prove the
    /// drain-installed replacement fence lands in the persisted plan by
    /// running the same readiness verification a reconnect would.
    /// (Production applies go through `verify_applied_network`.)
    #[cfg(test)]
    pub(crate) fn verify_sandbox_network(
        &self,
        plan: &SandboxNetworkPlan,
    ) -> Result<(), RuntimeError> {
        self.verify_applied_network(plan, true)
    }

    /// The apply readback. `pending_blocks`: whether journaled uncertain
    /// allows block even when not live — true for a FRESH create (its own
    /// exit is rollback + retry), false when adopting an EXISTING VM, which
    /// takes the observation rule (C58 G1F-1).
    fn verify_applied_network(
        &self,
        plan: &SandboxNetworkPlan,
        pending_blocks: bool,
    ) -> Result<(), RuntimeError> {
        // Restart-durable DNS expiry obligations first (C36 r18 F6): grants
        // that expired while the daemon was down are settled through the
        // enforced withdrawal boundary, and surviving grants rearm the
        // in-memory lease — BEFORE the effective ACL may verify as
        // enforceable. A settlement failure refuses readiness (fail
        // closed); an expired allow must never linger past a restart.
        self.recover_dns_expiry_obligations(&plan.sandbox_id)?;
        // A FRESH create keeps journaled uncertain allows blocking (fail
        // closed, C36 r21 F4): its own exit is rollback, then a retry whose
        // reborn ACL converts them to standing fence obligations. Adoption
        // of an existing VM passes `false` (see `apply_allocated_sandbox_network`).
        match self.verify_sandbox_network_recovered(plan, None, pending_blocks)? {
            Some(owed) => Err(owed),
            None => Ok(()),
        }
    }

    /// The readback AFTER DNS expiry recovery ran. `recovery_failed`
    /// carries the recovery error when it did not settle (C58 SEED-1):
    /// the readback then runs in owed mode — it can still convict drift
    /// the owed work does not explain, and it never verifies.
    ///
    /// C58 G1-R2-1: "owed" is a VALUE (`Ok(Some(refusal))`), never an early
    /// `Err`. An owed refresh explains only DNS-managed ACL rules and the
    /// `raw.dnsmasq` publication; every other check in the observation —
    /// this function's static/base rules and bridge config, and the
    /// caller's instance-device verification — must still run and convict
    /// on a mismatch. Only after ALL of them pass may the caller surface
    /// the owed refusal. `Err` here is drift (`IdempotencyConflict`) or
    /// unavailable evidence.
    fn verify_sandbox_network_recovered(
        &self,
        plan: &SandboxNetworkPlan,
        recovery_failed: Option<&RuntimeError>,
        pending_blocks: bool,
    ) -> Result<Option<RuntimeError>, RuntimeError> {
        // C58 NEW-1 (supersedes the C37 R4 marker-is-drift rule): a durable
        // marker recording an UNCOMMITTED refresh, uncommitted revocations
        // or unresolved pending mutations is the host's OWN journaled work
        // ahead of a commit — a refresh OWED, never drift. The old rule
        // returned the drift code before looking at the ACL, so a refresh
        // that withdrew a denied grant (fail closed) and then failed to
        // publish or commit got its healthy, over-denied VM halted and
        // destroyed by the reconciler. Now the live state is compared
        // FIRST: a divergence the owed work fully explains (narrowing, or
        // an issuance armed in the durable ledger before it was issued) is
        // refused INCONCLUSIVE — readiness still fails closed, nothing is
        // convicted, and the refresh scheduler retries the commit. Any
        // divergence it does not explain (a static rule, a foreign or
        // unarmed allow, a missing companion, a config key, an unjournaled
        // publication) is still drift. Unreadable or malformed records
        // are inconclusive (C37 R5): a local read failure is unavailable
        // evidence, not divergence.
        let owed = match recovery_failed {
            Some(recovery) => Some(
                self.dns_settlement_owed_evidence(&plan.sandbox_id, recovery)
                    .map_err(|err| {
                        RuntimeError::new(
                            SandboxErrorCode::Internal,
                            format!(
                                "cannot read the DNS revocation marker for `{}`; the observation is inconclusive: {err}",
                                plan.sandbox_id
                            ),
                        )
                    })?,
            ),
            None => self.dns_owed_evidence(&plan.sandbox_id).map_err(|err| {
                RuntimeError::new(
                    SandboxErrorCode::Internal,
                    format!("cannot stat the DNS revocation marker; failing closed: {err}"),
                )
            })?,
        };
        let acl = self
            .read_sandbox_acl(&plan.acl_name)?
            .ok_or_else(unsupported_egress)?;
        let drift = || {
            RuntimeError::new(
                // C37 R4: comparison failures are drift-coded (see
                // verify_network_config).
                SandboxErrorCode::IdempotencyConflict,
                "incus sandbox ACL effective rules differ from the compiled plan",
            )
        };
        if acl.sandbox_tag.as_deref() != Some(plan.sandbox_id.as_str()) {
            return Err(drift());
        }
        // C58 G1-R3-2: journaled uncertain ALLOW requests owe a refresh only
        // while one of them is LIVE (it landed late, or was applied after
        // all). One that never lands is a non-blocking obligation: its
        // preventive fence is in the committed plan, which the strict
        // comparison below verifies. Without this, an uncertain allow that
        // never landed kept the sandbox inconclusive until its lease ended.
        let owed = owed.filter(|owed| {
            pending_blocks
                || owed.commit_owed
                || owed
                    .pending_allows
                    .iter()
                    .any(|(description, destination)| {
                        acl.egress.iter().any(|rule| {
                            &rule.description == description && &rule.destination == destination
                        })
                    })
        });
        // While owed, the classifier runs EVEN on an exact match (G1-R1-2):
        // the old plan may itself still carry a grant the refresh denied,
        // and "live equals the old plan" must not hide a denied-but-open
        // destination.
        if owed.is_some() || !self.acl_matches_effective(&acl, plan) {
            let static_grants: Vec<super::network::GrantCidr> = plan
                .policy_cidrs
                .iter()
                .filter_map(|raw| super::network::parse_policy_cidr(raw).ok())
                .collect();
            let explanation = match (owed.as_ref(), self.effective_planned_rules(plan)) {
                (Some(owed), Some(planned)) => {
                    match acl_explained_by_owed_dns_work(&acl, &planned, &static_grants, owed) {
                        OwedExplanation::Explained => OwedExplanation::Explained,
                        // Preview tunnels: the same check against an
                        // unconfirmed runtime port change's variant.
                        unexplained => self
                            .tunnel_pending_variant(&plan.sandbox_id, &planned)
                            .map_or(unexplained, |variant| {
                                acl_explained_by_owed_dns_work(&acl, &variant, &static_grants, owed)
                            }),
                    }
                }
                _ => OwedExplanation::Unexplained,
            };
            if explanation != OwedExplanation::Explained {
                return Err(drift());
            }
        }
        let config = self
            .read_network_config(&plan.network_name)?
            .ok_or_else(unsupported_egress)?;
        self.verify_network_config(&config, plan, owed.as_ref())?;
        match owed {
            // Everything that differs is explained, but the persisted plan
            // is not the live truth until the owed refresh commits:
            // INCONCLUSIVE, never Ready, never drift.
            // The cause is typed (G1-R1-3) only for an owed REFRESH: the
            // refresh is what clears it. A failed recovery stays plain
            // inconclusive.
            Some(owed) if recovery_failed.is_none() => Ok(Some(
                RuntimeError::new(SandboxErrorCode::Internal, owed.reason).refresh_owed(),
            )),
            Some(owed) => Ok(Some(RuntimeError::new(
                SandboxErrorCode::Internal,
                owed.reason,
            ))),
            None => Ok(None),
        }
    }

    /// Idempotently create (or validate) the sandbox's bridge and ACL. Any
    /// failure after the first mutation rolls back through the tag-checked
    /// teardown so a failed apply never leaves a partially enforced sandbox.
    /// Rollback runs on a separately-scoped, bounded cleanup permit: revoking
    /// the issuing worker's permit (relay disconnect, lease expiry) must not
    /// strand a partial apply. If rollback itself cannot complete, the cleanup
    /// obligation is persisted durably for the fenced drain.
    ///
    /// A provisioning-intent record is written BEFORE the first mutation and
    /// retained until the VM is adopted (see kvm) or a rollback is verified:
    /// a host crash anywhere in the apply-to-init window leaves a bounded,
    /// fenced obligation, never an untracked bridge/ACL. Callers must hold
    /// the sandbox lock (`sandbox_lock`) across apply-to-adoption so a
    /// restart drain cannot interleave.
    #[cfg(test)]
    pub(crate) fn apply_sandbox_network(
        &self,
        plan: &SandboxNetworkPlan,
    ) -> Result<(), RuntimeError> {
        self.apply_sandbox_network_for(&mut plan.clone(), false, false)
    }

    /// Apply for a create retry that ADOPTS an existing VM (C58 G1F-1). A
    /// bridge or ACL that existed before this apply belongs to that VM, so a
    /// failure here NEVER rolls it back: destroying a live VM's network is
    /// the lifecycle drain's job, after a coherent conviction, never a
    /// side-effect of a refused retry. The provisioning intent is left for
    /// the fenced drain, exactly as a crash mid-adoption would leave it (the
    /// drain binds the VM, verifies and retires it). The readback takes the
    /// observation rule for journaled uncertain allows (blocking only while
    /// live), so a never-landed request no longer fails the retry.
    pub(crate) fn apply_allocated_sandbox_network(
        &self,
        plan: &mut SandboxNetworkPlan,
        adopting: bool,
    ) -> Result<(), RuntimeError> {
        self.apply_sandbox_network_for(plan, adopting, true)
    }

    fn apply_sandbox_network_for(
        &self,
        plan: &mut SandboxNetworkPlan,
        adopting: bool,
        allocating: bool,
    ) -> Result<(), RuntimeError> {
        if plan.settings.is_none() || !self.egress_enforcement_capability()? {
            return Err(unsupported_egress());
        }
        // Process autonomous DNS expiry obligations BEFORE any ACL
        // equality check (C36 r19 F5): an expiry the lease enforced —
        // or that came due while the daemon was down — is a legitimate
        // lifecycle transition, and settlement rewrites the persisted
        // plan to the post-settlement truth HERE, so a healthy,
        // already-expired ACL never trips the idempotency equality check
        // into a rollback. Settlement runs under the lease owner lock,
        // not behind refresh work.
        self.recover_dns_expiry_obligations(&plan.sandbox_id)?;
        // §2.6 (M3): once this sandbox's bridge exists, the persisted record
        // alone is the reference — never a fresh compile against node
        // settings that may have changed since materialization. A fresh
        // compile is used only to create a brand-new bridge and ACL.
        let bridge_existed = self.read_network_config(&plan.network_name)?.is_some();
        if bridge_existed {
            self.overlay_recorded_plan(plan)?;
        }
        // C58 G1F-1: a bridge or ACL that existed BEFORE this apply belongs
        // to the existing VM being adopted. It is never rolled back here, and
        // the readback takes the observation rule for journaled uncertain
        // allows. Objects this apply creates itself (an existing VM whose
        // network was missing) keep the fresh-create semantics: strict
        // readback and rollback.
        let live_network =
            adopting && (bridge_existed || self.read_acl_config(&plan.acl_name)?.is_some());
        let rollback = |sandbox_id: &str, attempt: &str| -> Result<(), RuntimeError> {
            if live_network {
                return Ok(());
            }
            self.rollback_applied_network(sandbox_id, attempt)
        };
        // Every apply stamps a fresh incarnation on the objects it creates or
        // adopts; cleanup records fence on it (see persist_pending_cleanup).
        let attempt = Self::new_attempt_token()?;
        // Write-ahead BEFORE the first mutation: the intent is durable before
        // the bridge/ACL can exist without a journal trail.
        self.persist_provisioning_intent(&plan.sandbox_id, &attempt, plan.binding.as_ref())?;
        // Bootstrap the BASE network first (C36 r21 F4): bridge plus ACL
        // with only the static/base rules. Domain grants are issued
        // afterwards through the journaled, fenced, identity-safe DNS
        // mutation boundary (`publish_initial_answers`), and the full
        // verification runs LAST, against the boundary's committed record.
        let applied = (|| {
            // An unattached ACL has no consumers. Create its deny-all shell
            // before entering the daemon-wide allocation section.
            let fresh_acl = self.ensure_sandbox_acl(plan, &attempt)?;
            if allocating {
                let allocation = self.lock_subnet_allocation()?;
                let gateway = self.gateway_for(&plan.sandbox_id)?;
                // m15: the record is persisted with the gateway chosen under
                // the allocation lock, BEFORE the bridge, the rule install
                // and the resolver publication that depend on it.
                self.bind_gateway_write_ahead(plan, gateway, bridge_existed)?;
                self.ensure_sandbox_network(plan, &attempt)?;
                drop(allocation);
                #[cfg(test)]
                self.pause_create_for_test("after_subnet_allocation");
                // Provisioning for distinct ACLs now proceeds independently.
                if fresh_acl {
                    self.install_sandbox_acl_rules(plan, &attempt)?;
                }
                Ok(())
            } else {
                // The non-allocating branch persists before its first rule
                // install likewise.
                let gateway = plan.gateway;
                self.bind_gateway_write_ahead(plan, gateway, bridge_existed)?;
                if fresh_acl {
                    self.install_sandbox_acl_rules(plan, &attempt)?;
                }
                self.ensure_sandbox_network(plan, &attempt)
            }
        })();
        match applied {
            Ok(()) => {
                // The provisioning record is retained until VM adoption: a
                // crash between apply and init must still be recoverable. Its
                // resolved expansion is durable for immutable reconnect reuse.
                // A journal failure here fails the apply; a create retry is
                // idempotent and completes the bookkeeping.
                //
                // On the immutable reconnect-reuse path, persist the rule
                // set the verification ACTUALLY validated: lease recovery
                // inside verify may have settled expired obligations and
                // re-recorded the post-settlement rules (C36 r18 F6) —
                // re-persisting the pre-recovery snapshot would resurrect
                // the expired grants' rules in the durable record.

                // C36: publish the initial guest-facing DNS answers for the
                // compiled domain grants — issued through the journaled,
                // fenced, identity-safe DNS mutation boundary (C36 r21 F4),
                // which installs the domain rules BEFORE the answers become
                // resolvable, commits the DNS state and recorded plan, and
                // arms the expiry lease. A publication failure rolls back
                // like any apply failure — teardown also retires the
                // persisted plan and DNS state records — so the create retry
                // RECOMPILES and republishes. Otherwise the retry would
                // reuse the persisted expansion (empty resolved_domains),
                // the unchanged deny-all DNS config would verify,
                // publication would be skipped, and create would report
                // readiness with every allowed domain unresolvable.
                // §2.2: publish the recorded resolver base (open-mode
                // resolver / blocked `local=` lines) through the stdin PATCH
                // boundary and read it back, before any DNS answer, any
                // verification and any start.
                if let Err(err) = self.publish_recorded_dnsmasq_base(plan) {
                    rollback(&plan.sandbox_id, &attempt)?;
                    return Err(err);
                }
                if let Err(err) = super::dns::publish_initial_answers(self, plan) {
                    rollback(&plan.sandbox_id, &attempt)?;
                    return Err(err);
                }
                // Full verification LAST (C36 r21 F4): the domain rules now
                // exist, issued and committed by the boundary.
                if let Err(err) = self.verify_applied_network(plan, !live_network) {
                    rollback(&plan.sandbox_id, &attempt)?;
                    return Err(err);
                }
                Ok(())
            }
            Err(err) => {
                rollback(&plan.sandbox_id, &attempt)?;
                Err(err)
            }
        }
    }

    /// Roll back a failed apply: fenced teardown of the bridge/ACL (which
    /// also retires the persisted plan and DNS state records) plus verified
    /// absence; an incomplete rollback persists the cleanup obligation for
    /// the fenced drain.
    fn rollback_applied_network(
        &self,
        sandbox_id: &str,
        attempt: &str,
    ) -> Result<(), RuntimeError> {
        let cleanup = self.cleanup_scoped();
        let rollback = cleanup
            .rollback_sandbox_network(sandbox_id)
            .and_then(|()| cleanup.verify_sandbox_network_absent(sandbox_id));
        match rollback {
            Ok(()) => {
                // Verified rollback: the provisioning intent is
                // retired; nothing is owed.
                self.clear_pending_cleanup(sandbox_id)?;
            }
            Err(cleanup_err) => {
                if let Err(persist_err) = self.persist_pending_cleanup(sandbox_id, attempt) {
                    return Err(RuntimeError::new(
                        SandboxErrorCode::Internal,
                        format!(
                            "egress rollback failed ({cleanup_err}) and the cleanup obligation could not be persisted ({persist_err})"
                        ),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Surface-harness cleanup: fenced teardown of everything this sandbox's
    /// apply could have created, then verified absence. Returns `Ok` when
    /// nothing remains; foreign-tagged objects are never touched.
    pub fn teardown_owned_sandbox_network(&self, sandbox_id: &str) -> Result<(), RuntimeError> {
        let sandbox_lock = self.sandbox_lock(sandbox_id);
        let _guard = self.lock_runtime(&sandbox_lock)?;
        // Collect the authorized markers from BOTH owned resources: a crash
        // between a retry's restamps legitimately leaves the bridge and ACL
        // on DIFFERENT incarnations, and fencing to only one would delete
        // one resource while rejecting (and leaking) the other.
        let mut markers = Vec::new();
        {
            let (network_name, acl_name) = sandbox_network_names(sandbox_id);
            for config in [
                self.read_network_config(&network_name)?,
                self.read_acl_config(&acl_name)?,
            ]
            .into_iter()
            .flatten()
            {
                if !self.manages(&config) {
                    continue;
                }
                // An owned but UNMARKED resource fences as the empty-string
                // incarnation: skipping it would fence this teardown (and
                // the drain) against the unmarked half of a mixed pair.
                markers.push(
                    config
                        .get(NETWORK_ATTEMPT_TAG)
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                );
            }
            markers.dedup();
        }
        let result = if markers.is_empty() {
            self.teardown_sandbox_network_inner(sandbox_id, None)
        } else {
            self.teardown_sandbox_network_inner(sandbox_id, Some(&markers))
        }
        .and_then(|()| self.verify_sandbox_network_absent(sandbox_id));
        if result.is_err() {
            // Retain cleanup evidence: an owned resource that survived the
            // teardown must stay journaled (a fenced teardown record) so the
            // drain — not silence — owns the retry, and the failure itself
            // is propagated, never reported as success.
            let _ = self.prepare_network_cleanup(sandbox_id);
        }
        result
    }

    /// Daemon-wide subnet-allocation lock. Sandbox subnet choice reads the
    /// host's route table and every existing bridge; without this lock two
    /// concurrent creates with colliding seeds both see the same free range
    /// and race to claim it. The guard is held from the `gateway_for`
    /// snapshot through the bridge creation.
    ///
    /// The lock location is an ADMINISTRATOR-PROVISIONED, explicitly shared
    /// system directory (`/var/lib/wssp/incus-daemon-locks`), NOT created at
    /// use time and NOT anywhere under a private-temp-affected path (`/tmp`
    /// and `/var/tmp` are isolated per-service by systemd PrivateTmp; a
    /// temp-derived path would give two isolated services driving the same
    /// daemon DIFFERENT lock files, and any world-writable first-creator
    /// scheme lets an unrelated local user squat the directory and exclude
    /// legitimate daemon users). The directory is provisioned by
    /// setup/enrollment: group-owned by the group of authorized daemon
    /// users, mode 2770 (setgid, so lock files inherit the group; no world
    /// access). The runtime VALIDATES the provisioning at every acquisition
    /// and fails closed with an operator-facing error when it is wrong — it
    /// never "repairs" permissions it does not own.
    pub(crate) fn lock_subnet_allocation(&self) -> Result<SubnetAllocationGuard, RuntimeError> {
        let key = self.daemon_lock_key()?;
        let dir = self.effective_daemon_lock_dir();
        Self::validate_daemon_lock_dir(&dir)?;
        let path = dir.join(format!("{key}.lock"));
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // O_NOFOLLOW: a predictable-name symlink planted in the shared
            // directory is rejected outright, never followed. O_CLOEXEC
            // keeps the flock-scoped descriptor out of exec'd helpers.
            // (libc values: they differ per architecture, C55.)
            options
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .mode(0o660);
        }
        let file = options.open(&path).map_err(|err| {
            RuntimeError::new(
                SandboxErrorCode::Internal,
                format!("cannot open the subnet allocation lock: {err}"),
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = file.metadata().map_err(|err| {
                RuntimeError::new(
                    SandboxErrorCode::Internal,
                    format!("cannot stat the subnet allocation lock: {err}"),
                )
            })?;
            if !meta.is_file() {
                return Err(RuntimeError::new(
                    SandboxErrorCode::Internal,
                    "the subnet allocation lock is not a regular file",
                ));
            }
            // Permission handling is owner-only: the file's OWNER
            // initializes mode 0660 through the VALIDATED descriptor (never
            // by path — a path-based chmod could hit a replaced file). Every
            // other authorized daemon user can open the file via the shared
            // group but MUST NOT chmod it (chmod by a non-owner fails with
            // EPERM, which would block their creates entirely); they
            // validate the existing mode and group instead.
            use std::os::unix::fs::MetadataExt;
            let ours = {
                #[cfg(test)]
                if let Some(euid) = self.lock_file_euid_override {
                    euid
                } else {
                    Self::process_euid()?
                }
                #[cfg(not(test))]
                Self::process_euid()?
            };
            if meta.uid() == ours {
                file.set_permissions(std::fs::Permissions::from_mode(0o660))
                    .map_err(|err| {
                        RuntimeError::new(
                            SandboxErrorCode::Internal,
                            format!("cannot restrict the subnet allocation lock: {err}"),
                        )
                    })?;
            } else {
                // Non-owner: validate, never modify. The setgid directory
                // makes the file inherit the authorized-users group.
                let mode = meta.permissions().mode() & 0o777;
                let dir_gid = std::fs::metadata(&dir).map(|m| m.gid()).map_err(|err| {
                    RuntimeError::new(
                        SandboxErrorCode::Internal,
                        format!("cannot stat the subnet allocation lock dir: {err}"),
                    )
                })?;
                if mode != 0o660 || meta.gid() != dir_gid {
                    return Err(RuntimeError::new(
                        SandboxErrorCode::Internal,
                        "the subnet allocation lock file has unexpected ownership, mode, or group; an administrator must reprovision the daemon lock directory",
                    ));
                }
            }
        }
        // Match the image-init ceiling: concurrent egress provisioning can
        // legitimately occupy this lane for more than a minute under IO load.
        // This is a lock-admission bound, independent of the init/agent calls.
        // Bounded, cancellation-aware wait: try_lock retries observe the
        // caller's permit and a hard deadline, so a stuck or hostile lock
        // holder parks no worker indefinitely and disconnect cancellation
        // releases waiters.
        #[cfg(test)]
        let budget = self
            .allocation_lock_wait
            .unwrap_or(std::time::Duration::from_secs(600));
        #[cfg(not(test))]
        let budget = std::time::Duration::from_secs(600);
        let deadline = std::time::Instant::now() + budget;
        loop {
            match file.try_lock() {
                Ok(()) => break,
                Err(std::fs::TryLockError::WouldBlock) => {
                    if let Some(permit) = &self.cancelled {
                        // Drop the admission guard immediately: no lock is
                        // held across the sleep.
                        let _admitted = permit.admit()?;
                    }
                    if std::time::Instant::now() >= deadline {
                        return Err(RuntimeError::new(
                            SandboxErrorCode::Timeout,
                            "the subnet allocation lock was not acquired within its budget",
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
                Err(err) => {
                    return Err(RuntimeError::new(
                        SandboxErrorCode::Internal,
                        format!("cannot take the subnet allocation lock: {err}"),
                    ));
                }
            }
        }
        Ok(SubnetAllocationGuard { _file: file })
    }

    /// The process's effective uid, read from /proc/self (no libc dep).
    #[cfg(unix)]
    fn process_euid() -> Result<u32, RuntimeError> {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata("/proc/self")
            .map(|meta| meta.uid())
            .map_err(|err| {
                RuntimeError::new(
                    SandboxErrorCode::Internal,
                    format!("cannot determine the process owner: {err}"),
                )
            })
    }

    /// The machine-wide allocation-lock directory: a fixed, explicitly
    /// shared, administrator-provisioned system path. It sits OUTSIDE every
    /// private-temp-affected location (`/tmp`, `/var/tmp`, TMPDIR, `$XDG_*`),
    /// so mount namespacing (systemd PrivateTmp) and per-process temp
    /// settings can never split it, and its provisioning — not whichever
    /// user happens to run first — decides who may participate.
    pub(crate) fn daemon_lock_dir() -> &'static std::path::Path {
        std::path::Path::new("/var/lib/wssp/incus-daemon-locks")
    }

    /// The lock directory this client uses. Resolution order: the test
    /// fixture override, then the `WSSP_INCUS_DAEMON_LOCK_DIR` dev/test
    /// seam (same spirit as `WSSP_INCUS_BINARY` — shim-driven integration
    /// harnesses cannot provision /var/lib), then the fixed production
    /// path. Every resolved directory faces the SAME strict validation
    /// below, so the seam can relocate the lock for a harness but never
    /// weaken its trust requirements.
    fn effective_daemon_lock_dir(&self) -> std::path::PathBuf {
        #[cfg(test)]
        if let Some(dir) = &self.daemon_lock_dir_override {
            return dir.clone();
        }
        Self::configured_daemon_lock_dir()
    }

    /// The `WSSP_INCUS_DAEMON_LOCK_DIR` dev/test seam, else the fixed
    /// production path. Setup provisioning and lock acquisition both resolve
    /// through here so they always validate the same directory.
    fn configured_daemon_lock_dir() -> std::path::PathBuf {
        if let Some(dir) = std::env::var_os("WSSP_INCUS_DAEMON_LOCK_DIR") {
            return std::path::PathBuf::from(dir);
        }
        Self::daemon_lock_dir().to_path_buf()
    }

    /// Validate the administrator-provisioned lock directory: it must
    /// already exist as a real directory (never a symlink), be owned by
    /// root or this euid, and be mode 2770 — setgid so lock files inherit
    /// the authorized daemon-users group, with no world access. Anything
    /// else fails closed with an operator-facing error; the runtime never
    /// repairs permissions on a directory it did not provision.
    fn validate_daemon_lock_dir(dir: &std::path::Path) -> Result<(), RuntimeError> {
        let provision_hint = || {
            format!(
                "provision the shared daemon lock directory first: `sudo install -d -m 2770 -o root -g <daemon-users-group> {}` (every user running a node daemon against this Incus daemon must belong to that group)",
                dir.display()
            )
        };
        let meta = std::fs::symlink_metadata(dir).map_err(|err| {
            RuntimeError::new(
                SandboxErrorCode::Internal,
                format!(
                    "the daemon lock directory {} is unavailable: {err}; {}",
                    dir.display(),
                    provision_hint()
                ),
            )
        })?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(RuntimeError::new(
                SandboxErrorCode::Internal,
                format!(
                    "the daemon lock directory {} is not a real directory; {}",
                    dir.display(),
                    provision_hint()
                ),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            use std::os::unix::fs::PermissionsExt;
            let ours = Self::process_euid()?;
            if meta.uid() != 0 && meta.uid() != ours {
                return Err(RuntimeError::new(
                    SandboxErrorCode::Internal,
                    format!(
                        "the daemon lock directory {} is owned by an unexpected uid {}; {}",
                        dir.display(),
                        meta.uid(),
                        provision_hint()
                    ),
                ));
            }
            if meta.permissions().mode() & 0o7777 != 0o2770 {
                return Err(RuntimeError::new(
                    SandboxErrorCode::Internal,
                    format!(
                        "the daemon lock directory {} must be mode 2770 (setgid, group-only); {}",
                        dir.display(),
                        provision_hint()
                    ),
                ));
            }
        }
        Ok(())
    }

    /// Validate the provisioned directory AND prove this user can actually
    /// use it. Metadata alone is insufficient: a root-owned 2770 directory
    /// whose group excludes this user passes every metadata check but fails
    /// every lock open with EACCES (automatic root provisioning produces
    /// exactly that). The probe performs the real operation — create/open a
    /// file in the directory as the current user, fsync it, then remove it.
    pub(crate) fn preflight_daemon_lock_dir(dir: &std::path::Path) -> Result<(), RuntimeError> {
        Self::validate_daemon_lock_dir(dir)?;
        // A UNIQUELY named probe per invocation, opened with create_new:
        // concurrent enrollments against the shared directory must never
        // race on one filename (one daemon removing another's probe would
        // abort it with misleading permission guidance), and each
        // invocation removes only its own file.
        static PROBE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let probe = dir.join(format!(
            ".wssp-access-probe-{}-{}",
            std::process::id(),
            PROBE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .mode(0o660);
        }
        options
            .open(&probe)
            .and_then(|file| file.sync_all())
            .and_then(|()| std::fs::remove_file(&probe))
            .map_err(|err| {
                RuntimeError::new(
                    SandboxErrorCode::Internal,
                    format!(
                        "the daemon lock directory {} passes ownership/mode checks but is not usable by this user ({err}); add every node-daemon user to the directory's group (`sudo usermod -aG <daemon-users-group> $USER`) or reprovision it: `sudo install -d -m 2770 -o root -g <daemon-users-group> {}`",
                        dir.display(),
                        dir.display()
                    ),
                )
            })
    }

    /// Enrollment/setup provisioning: create the shared daemon lock
    /// directory when possible (root installs, or a writable parent), then
    /// validate it — metadata AND actual usability (see
    /// `preflight_daemon_lock_dir`). Failure is returned with the exact
    /// operator command — the caller surfaces it during `wssp host run`
    /// setup, BEFORE the relay advertises an egress-capable host whose
    /// every create would fail at lock acquisition.
    pub fn ensure_daemon_lock_dir_provisioned() -> Result<(), RuntimeError> {
        let configured = Self::configured_daemon_lock_dir();
        let dir = configured.as_path();
        // E2E-P3-1: only a directory THIS call created gets the 2770 mode.
        // A pre-existing directory is the operator's: it is validated, never
        // repaired, so a wrong mode fails below with the reprovision command.
        let mut created = false;
        if std::fs::symlink_metadata(dir).is_err() {
            if let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
                // Ancestors keep the umask default: every daemon user must be
                // able to traverse them to reach the shared lock directory.
                let _ = std::fs::create_dir_all(parent);
            }
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o770);
            }
            created = builder.create(dir).is_ok();
        }
        #[cfg(unix)]
        if created {
            use std::os::unix::fs::MetadataExt;
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::symlink_metadata(dir) {
                let ours = Self::process_euid().unwrap_or(u32::MAX);
                if meta.is_dir() && !meta.file_type().is_symlink() && meta.uid() == ours {
                    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o2770));
                }
            }
        }
        #[cfg(not(unix))]
        let _ = created;
        Self::preflight_daemon_lock_dir(dir)
    }

    /// Where the kernel exposes bridge netfilter once `br_netfilter` is
    /// loaded. Every sandbox NIC sets `security.ipv6_filtering`, which Incus
    /// refuses to start without it.
    pub const BRIDGE_NETFILTER_PROC: &'static str = "/proc/sys/net/bridge";

    /// Connect-time host preflight (E-11): without bridge netfilter every
    /// sandbox VM fails to start (`security.ipv6_filtering requires bridge
    /// netfilter`), so `wssp host run` refuses to serve creates and names the
    /// exact operator commands instead. `proc_path` is
    /// `BRIDGE_NETFILTER_PROC` outside tests.
    pub fn preflight_bridge_netfilter(proc_path: &std::path::Path) -> Result<(), RuntimeError> {
        if proc_path.is_dir() {
            // HR-R2: Incus also needs bridged IPv6 traffic passed to
            // ip6tables; the module can be loaded with the sysctl at 0.
            let sysctl = proc_path.join("bridge-nf-call-ip6tables");
            let value = std::fs::read_to_string(&sysctl).unwrap_or_default();
            if value.trim() == "1" {
                return Ok(());
            }
            return Err(RuntimeError::new(
                SandboxErrorCode::HostRuntimeUnsupported,
                format!(
                    "bridge netfilter is loaded but `net.bridge.bridge-nf-call-ip6tables` is not 1 (read `{}`): sandbox NICs use `security.ipv6_filtering`, which Incus refuses to start without it; enable it with `sudo sysctl -w net.bridge.bridge-nf-call-ip6tables=1`, keep it across reboots with `echo net.bridge.bridge-nf-call-ip6tables=1 | sudo tee /etc/sysctl.d/90-wssp-bridge-nf.conf`, then run `wssp host run` again",
                    sysctl.display()
                ),
            ));
        }
        Err(RuntimeError::new(
            SandboxErrorCode::HostRuntimeUnsupported,
            format!(
                "bridge netfilter is unavailable (`{}` is missing): sandbox NICs use `security.ipv6_filtering`, which needs the `br_netfilter` kernel module; load it with `sudo modprobe br_netfilter`, keep it loaded across reboots with `echo br_netfilter | sudo tee /etc/modules-load.d/wssp-br_netfilter.conf`, then run `wssp host run` again",
                proc_path.display()
            ),
        ))
    }

    /// Test accessor for the daemon lock key (adversarial lock-path tests).
    #[cfg(test)]
    pub(crate) fn daemon_lock_key_for_test(&self) -> String {
        self.daemon_lock_key().expect("daemon key")
    }

    /// A stable identity for the daemon this client drives: the server's
    /// `environment.server_name` from `/1.0`, hashed. When the daemon does
    /// not report a name, all clients of the local default remote fall back
    /// to one shared key — which is correct for the common single-daemon
    /// host and keeps the lock daemon-wide rather than host-identity-scoped.
    fn daemon_lock_key(&self) -> Result<String, RuntimeError> {
        let metadata = self.query_raw(&with_query_params(
            "/1.0",
            &[("project", self.project.as_str())],
        ))?;
        let name = metadata
            .get("environment")
            .and_then(|environment| environment.get("server_name"))
            .and_then(serde_json::Value::as_str)
            .filter(|name| !name.is_empty())
            .unwrap_or("local");
        let digest = ring::digest::digest(&ring::digest::SHA256, name.as_bytes());
        Ok(digest.as_ref()[..8]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect())
    }

    /// A bounded client for cleanup work that must outlive the issuing
    /// worker's permit. The fresh permit carries only a deadline; it is not
    /// linked to relay cancellation, and every teardown stays tag-fenced.
    fn cleanup_scoped(&self) -> Self {
        let mut client = self.clone();
        client.cancelled = Some(std::sync::Arc::new(crate::RuntimePermit::with_timeout(
            std::time::Duration::from_secs(60),
        )));
        client
    }

    /// Durable host-side state root: the caller-provided host state dir,
    /// else the daemon's established data dir (`WSSP_DATA_DIR`), else the
    /// platform data dir. Runtime network state lives under a `runtime/`
    /// child so it cannot collide with relay journals when the two share a
    /// data dir.
    pub(crate) fn state_root(&self) -> PathBuf {
        if let Some(dir) = &self.state_dir {
            return dir.clone();
        }
        if let Ok(dir) = std::env::var("WSSP_DATA_DIR") {
            return PathBuf::from(dir).join("runtime");
        }
        let base = std::env::var("XDG_DATA_HOME")
            .map(PathBuf::from)
            .ok()
            .filter(|path| !path.as_os_str().is_empty())
            .or_else(|| {
                std::env::var("HOME")
                    .ok()
                    .map(|home| PathBuf::from(home).join(".local/share"))
            })
            .unwrap_or_else(std::env::temp_dir);
        base.join("wssp").join("runtime")
    }

    /// Root for durable, unresolved network-cleanup obligations.
    fn pending_cleanup_dir(&self) -> PathBuf {
        self.state_root().join("network-cleanups")
    }

    /// Directory builder for host state (E-16): owner-only 0700 on Unix.
    /// `mkdir` applies the umask, which can only clear bits, so a created
    /// directory is never wider than 0700.
    pub(crate) fn private_dir_builder() -> std::fs::DirBuilder {
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
    }

    /// Create or truncate a small host-state file as owner-only 0600 (E-16),
    /// never following a symlink at `path`. An existing file keeps its mode.
    pub(crate) fn write_private_file(path: &std::path::Path, body: &[u8]) -> std::io::Result<()> {
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .mode(0o600);
        }
        options.open(path)?.write_all(body)
    }

    /// Crash-durable directory creation: every newly created component's
    /// parent is fsynced, matching the host journal, so the first record in
    /// a fresh state dir survives a crash. Open/sync failures propagate: a
    /// journal hierarchy that cannot be made crash-durable fails the caller
    /// BEFORE any host mutation instead of provisioning on silent state.
    fn create_dir_all_durable(&self, dir: &std::path::Path) -> Result<(), RuntimeError> {
        // A marker file records that this directory's WHOLE ancestor chain
        // was synced after creation. "Exists" is never treated as "durable":
        // a failed earlier attempt can leave a visible directory whose
        // parent sync never completed, so without a marker the chain is
        // walked and resynced (up to the first marked ancestor or the
        // filesystem root) before any record is admitted.
        const MARKER: &str = ".wssp-durable";
        if dir.join(MARKER).is_file() {
            return Ok(());
        }
        let mut chain: Vec<&std::path::Path> = Vec::new();
        let mut cursor = Some(dir);
        while let Some(path) = cursor {
            chain.push(path);
            if path != dir && path.is_dir() && path.join(MARKER).is_file() {
                break;
            }
            // A relative path's topmost component has parent "" — the walk
            // ends there (the implicit root is the cwd), never with the
            // empty path, which `create_dir("")` would reject.
            cursor = path.parent().filter(|p| !p.as_os_str().is_empty());
        }
        // Create the missing components (chain is dir-first; iterate from
        // the topmost ancestor downwards).
        for path in chain.iter().rev() {
            if path.is_dir() {
                continue;
            }
            // E-16: every component this call creates is owner-only (0700),
            // whatever the process umask; pre-existing directories keep the
            // mode their owner gave them.
            match Self::private_dir_builder().create(path) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(err) => {
                    return Err(RuntimeError::new(
                        SandboxErrorCode::Internal,
                        format!("cannot create the host state journal: {err}"),
                    ));
                }
            }
        }
        // Resync the parent of EVERY chain component: creation is only
        // durable once the parent's directory data reached stable storage.
        for path in &chain {
            match path.parent() {
                Some(parent) if !parent.as_os_str().is_empty() => {
                    self.fsync_dir_checked(parent)?;
                }
                // A relative chain's topmost entry's parent is the cwd.
                Some(_) => self.fsync_dir_checked(std::path::Path::new("."))?,
                None => {}
            }
        }
        // The chain is durable; mark the journal dir (marker write + fsync
        // of the dir itself) so later calls skip the resync.
        Self::write_private_file(&dir.join(MARKER), b"").map_err(|err| {
            RuntimeError::new(
                SandboxErrorCode::Internal,
                format!("cannot mark the host state journal durable: {err}"),
            )
        })?;
        self.fsync_dir_checked(dir)?;
        Ok(())
    }

    /// Write a small JSON record atomically and fsync file + directory: the
    /// obligation must survive a host crash between the destructive step and
    /// the next reconciliation.
    pub(crate) fn write_durable_record(
        &self,
        dir: &std::path::Path,
        name: &str,
        body: &str,
    ) -> Result<(), RuntimeError> {
        use std::io::Write;
        self.create_dir_all_durable(dir)?;
        // Writer-UNIQUE temp path (C36 r20 F3): two serialized writers of
        // the same record (the refresh commit and the lease-settlement
        // commit) used to share one predictable temp name, and the stale-
        // file recovery below would unlink the OTHER writer's ACTIVE temp
        // file mid-write. Uniqueness is the hygiene half of the fix; the
        // commit lock is the correctness half.
        let tmp = dir.join(format!(
            ".{name}.{}.{}.tmp",
            std::process::id(),
            durable_tmp_counter().fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        ));
        let durable = |err: std::io::Error| {
            RuntimeError::new(
                SandboxErrorCode::Internal,
                format!("cannot persist host state record {name}: {err}"),
            )
        };
        // Exclusive, no-follow creation (same pattern as the daemon locks):
        // a symlink planted at the predictable temp path is REJECTED, never
        // followed — `File::create` would have truncated its target. A stale
        // REGULAR temp file from a crashed write is unlinked (unlink never
        // follows) and retried once; the retry is still exclusive.
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .mode(0o600);
        }
        let mut file = match options.open(&tmp) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                let meta = std::fs::symlink_metadata(&tmp).map_err(durable)?;
                if !meta.file_type().is_file() {
                    return Err(RuntimeError::new(
                        SandboxErrorCode::Internal,
                        format!(
                            "refusing to write host state record {name}: its temp path is not a regular file"
                        ),
                    ));
                }
                std::fs::remove_file(&tmp).map_err(durable)?;
                options.open(&tmp).map_err(durable)?
            }
            Err(err) => return Err(durable(err)),
        };
        file.write_all(body.as_bytes()).map_err(durable)?;
        file.sync_all().map_err(durable)?;
        drop(file);
        std::fs::rename(&tmp, dir.join(name)).map_err(durable)?;
        // The post-rename directory fsync goes through the SAME checked
        // boundary as hierarchy creation, so the per-directory failure
        // injection covers every durable write to an existing journal too
        // (C37 R6 — the teardown-journal-failure drain regression).
        self.fsync_dir_checked(dir)?;
        Ok(())
    }

    /// Best-effort directory fsync after REMOVAL: a lost sync only leaves a
    /// stale record behind, which the drain reconciles as already-absent.
    pub(crate) fn fsync_dir(dir: &std::path::Path) {
        if let Ok(dir_fd) = std::fs::File::open(dir) {
            let _ = dir_fd.sync_all();
        }
    }

    /// Strict directory fsync for durable CREATION: open or sync failure is
    /// a hard error, never silently ignored.
    fn fsync_dir_checked(&self, dir: &std::path::Path) -> Result<(), RuntimeError> {
        let dir_fd = std::fs::File::open(dir).map_err(|err| {
            RuntimeError::new(
                SandboxErrorCode::Internal,
                format!("cannot open {} for durability sync: {err}", dir.display()),
            )
        })?;
        #[cfg(test)]
        let sync_result = if self.fail_dir_sync || self.fail_dir_sync_for.as_deref() == Some(dir) {
            Err(std::io::Error::other("injected directory sync failure"))
        } else {
            dir_fd.sync_all()
        };
        #[cfg(not(test))]
        let sync_result = dir_fd.sync_all();
        sync_result.map_err(|err| {
            RuntimeError::new(
                SandboxErrorCode::Internal,
                format!("cannot durably sync {}: {err}", dir.display()),
            )
        })
    }

    fn persist_cleanup_record(
        &self,
        sandbox_id: &str,
        phase: CleanupPhase,
        observed: &[String],
        binding: Option<&super::network::PlanBinding>,
    ) -> Result<(), RuntimeError> {
        crate::validate_managed_instance_name(&crate::default_incus_instance_name(sandbox_id))?;
        // Retain every incarnation the journal already covers, then add this
        // one. A retry writes its fresh token BEFORE restamping the previous
        // attempt's resources; the previous incarnations' obligations must
        // survive until adoption completes or a fenced teardown finishes.
        let existing = self.read_pending_cleanup(sandbox_id)?;
        if let Some(record) = &existing
            && record.project != self.project
        {
            // A shared state root must never let one project merge into,
            // overwrite, or clear another project's obligation.
            return Err(RuntimeError::new(
                SandboxErrorCode::IdempotencyConflict,
                format!(
                    "the network cleanup obligation for `{sandbox_id}` belongs to another project; refusing to overwrite it"
                ),
            ));
        }
        let mut attempts: Vec<String> = existing.map(|record| record.attempts).unwrap_or_default();
        if phase == CleanupPhase::Provisioning {
            // Cover the transitional window: resources still stamped with an
            // earlier incarnation until this attempt restamps them. (Teardown
            // records must NOT re-read live markers here: a newer incarnation
            // may already own them — the teardown journals only the markers
            // it observed at teardown start.)
            let (network_name, acl_name) = sandbox_network_names(sandbox_id);
            for config in [
                self.read_network_config(&network_name)?,
                self.read_acl_config(&acl_name)?,
            ]
            .into_iter()
            .flatten()
            {
                if self.manages(&config) {
                    // An owned resource WITHOUT an incarnation marker still
                    // needs its fence: the empty-string attempt matches the
                    // unmarked readback, so a mixed marked/unmarked pair
                    // (a crash mid-adoption restamp) never strands the
                    // unmarked half as a "newer incarnation".
                    let marker = config
                        .get(NETWORK_ATTEMPT_TAG)
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default();
                    attempts.push(marker.to_owned());
                }
            }
        }
        attempts.extend(observed.iter().cloned());
        attempts.dedup();
        if attempts.is_empty() {
            // The journal schema rejects an empty incarnation list; an
            // unmarked resource still needs a durable (empty-string) attempt.
            attempts.push(String::new());
        }
        let attempt = observed.first().cloned().unwrap_or_default();
        let phase_str = match phase {
            CleanupPhase::Provisioning => "provisioning",
            CleanupPhase::Teardown => "teardown",
        };
        let record = serde_json::json!({
            "sandbox_id": sandbox_id,
            "attempt": attempt,
            "attempts": attempts,
            "binding": binding,
            "phase": phase_str,
            "project": self.project,
        })
        .to_string();
        self.write_durable_record(
            &self.pending_cleanup_dir(),
            &format!("{sandbox_id}.json"),
            &record,
        )
    }

    /// Durably record that this sandbox's network/ACL teardown is owed. The
    /// record binds the obligation to the apply/kill incarnation that
    /// incurred it (`attempt`); the drain re-derives object names, re-checks
    /// ownership tags and only tears down resources still stamped with this
    /// incarnation, so a stale record can never delete a network a newer
    /// provisioning attempt rebuilt.
    pub(crate) fn persist_pending_cleanup(
        &self,
        sandbox_id: &str,
        attempt: &str,
    ) -> Result<(), RuntimeError> {
        self.persist_cleanup_record(
            sandbox_id,
            CleanupPhase::Teardown,
            &[attempt.to_owned()],
            None,
        )
    }

    /// Teardown write-ahead covering EVERY incarnation observed: a retry
    /// that restamps the bridge but crashes before the ACL leaves mixed
    /// markers, and fencing the drain to only one of them would reject the
    /// other as a conflict and drop the obligation over a live owned object.
    pub(crate) fn persist_pending_cleanup_markers(
        &self,
        sandbox_id: &str,
        markers: &[String],
    ) -> Result<(), RuntimeError> {
        self.persist_cleanup_record(sandbox_id, CleanupPhase::Teardown, markers, None)
    }

    /// Provisioning write-ahead: persisted BEFORE the apply's first host
    /// mutation, so a crash anywhere between bridge creation and VM adoption
    /// leaves a bounded, fenced obligation the restart drain can complete.
    /// Retired by VM adoption (the VM is proof of provisioning) or by a
    /// verified rollback; a drain that finds no VM completes the teardown.
    /// The record RETAINS every incarnation the journal and the live
    /// resources already cover, so a crash between this write-ahead and the
    /// restamp (or between the ACL and bridge restamps) never orphans
    /// resources whose marker disagrees with the journal.
    pub(crate) fn persist_provisioning_intent(
        &self,
        sandbox_id: &str,
        attempt: &str,
        binding: Option<&super::network::PlanBinding>,
    ) -> Result<(), RuntimeError> {
        let binding = binding.ok_or_else(|| {
            RuntimeError::new(
                SandboxErrorCode::Internal,
                "cannot journal sandbox provisioning without an instance binding",
            )
        })?;
        self.persist_cleanup_record(
            sandbox_id,
            CleanupPhase::Provisioning,
            &[attempt.to_owned()],
            Some(binding),
        )
    }

    /// The obligation is fulfilled; clear it (durable removal).
    pub(crate) fn clear_pending_cleanup(&self, sandbox_id: &str) -> Result<(), RuntimeError> {
        let dir = self.pending_cleanup_dir();
        let record = dir.join(format!("{sandbox_id}.json"));
        if let Some(existing) = self.read_pending_cleanup(sandbox_id)?
            && existing.project != self.project
        {
            return Err(RuntimeError::new(
                SandboxErrorCode::IdempotencyConflict,
                format!(
                    "the network cleanup obligation for `{sandbox_id}` belongs to another project; refusing to clear it"
                ),
            ));
        }
        match std::fs::remove_file(&record) {
            Ok(()) => {
                Self::fsync_dir(&dir);
                Ok(())
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(RuntimeError::new(
                SandboxErrorCode::Internal,
                format!("cannot clear the network cleanup obligation: {err}"),
            )),
        }
    }

    /// The journal entry for one sandbox. Fallible and exact: absence is
    /// `Ok(None)`; a read or parse FAILURE is `Err` — ownership of an
    /// unverifiable record is never assumed, so it must be preserved and
    /// reported, never silently treated as absent or dropped.
    fn read_pending_cleanup(
        &self,
        sandbox_id: &str,
    ) -> Result<Option<CleanupRecord>, RuntimeError> {
        let record = self
            .pending_cleanup_dir()
            .join(format!("{sandbox_id}.json"));
        let body = match std::fs::read_to_string(&record) {
            Ok(body) => body,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(RuntimeError::new(
                    SandboxErrorCode::Internal,
                    format!("cannot read the network cleanup obligation {sandbox_id}: {err}"),
                ));
            }
        };
        let parsed: serde_json::Value = serde_json::from_str(&body).map_err(|err| {
            RuntimeError::new(
                SandboxErrorCode::Internal,
                format!("cannot parse the network cleanup obligation {sandbox_id}: {err}"),
            )
        })?;
        // Missing ownership or incarnation evidence cannot authorize cleanup.
        let malformed = |why: &str| {
            RuntimeError::new(
                SandboxErrorCode::Internal,
                format!("malformed network cleanup obligation {sandbox_id}: {why}"),
            )
        };
        let object = parsed
            .as_object()
            .ok_or_else(|| malformed("not an object"))?;
        // Identity must match the filename: a record claiming another sandbox
        // is never honored under this name.
        match object.get("sandbox_id") {
            Some(serde_json::Value::String(id)) if id == sandbox_id => {}
            Some(_) => return Err(malformed("sandbox_id does not match the filename")),
            None => return Err(malformed("missing sandbox_id")),
        }
        let phase = match object.get("phase") {
            None => return Err(malformed("missing phase")),
            Some(serde_json::Value::String(phase)) if phase == "provisioning" => {
                CleanupPhase::Provisioning
            }
            Some(serde_json::Value::String(phase)) if phase == "teardown" => CleanupPhase::Teardown,
            Some(_) => return Err(malformed("unrecognized phase")),
        };
        let project = match object.get("project") {
            None => return Err(malformed("missing project")),
            Some(serde_json::Value::String(project)) if !project.is_empty() => project.clone(),
            Some(_) => return Err(malformed("project is not a string")),
        };
        let attempts = match (object.get("attempts"), object.get("attempt")) {
            (Some(serde_json::Value::Array(list)), _) => {
                let mut attempts = Vec::with_capacity(list.len());
                for entry in list {
                    match entry {
                        serde_json::Value::String(attempt) => attempts.push(attempt.clone()),
                        _ => return Err(malformed("attempts must be strings")),
                    }
                }
                if attempts.is_empty() {
                    // A present-but-empty attempt set is not a legacy shape:
                    // it would read as permission to adopt any marker.
                    return Err(malformed("empty attempts"));
                }
                attempts
            }
            (Some(_), _) => return Err(malformed("attempts is not an array")),
            (None, _) => return Err(malformed("missing attempts")),
        };
        let binding = match object.get("binding") {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::Object(binding)) => {
                let fingerprint = match binding.get("template_fingerprint") {
                    Some(serde_json::Value::String(fp)) => fp.clone(),
                    _ => return Err(malformed("binding.template_fingerprint is not a string")),
                };
                let create_key = match binding.get("create_key") {
                    None | Some(serde_json::Value::Null) => None,
                    Some(serde_json::Value::String(key)) => Some(key.clone()),
                    _ => return Err(malformed("binding.create_key is not a string")),
                };
                Some(super::network::PlanBinding {
                    template_fingerprint: fingerprint,
                    create_key,
                })
            }
            Some(_) => return Err(malformed("binding is not an object")),
        };
        if phase == CleanupPhase::Provisioning && binding.is_none() {
            return Err(malformed("provisioning record without an instance binding"));
        }
        Ok(Some(CleanupRecord {
            phase,
            attempts,
            project,
            binding,
        }))
    }

    /// Whether this client's project manages a network/ACL with this config.
    /// Dedicated projects without network isolation INHERIT the default
    /// project's networks, so project-scoped reads alone cannot prove
    /// ownership: only an explicit matching project tag proves ownership.
    pub(crate) fn manages(&self, config: &serde_json::Map<String, serde_json::Value>) -> bool {
        match config
            .get(NETWORK_PROJECT_TAG)
            .and_then(serde_json::Value::as_str)
        {
            Some(project) => project == self.project,
            None => false,
        }
    }

    /// Write-ahead for destructive teardown (kill): if any network resource
    /// still exists, or a provisioning intent is still outstanding, the
    /// obligation is durable BEFORE the VM is touched, so no crash window can
    /// leave untracked bridge/ACL state. The record adopts the resources'
    /// current incarnation marker.
    pub(crate) fn prepare_network_cleanup(&self, sandbox_id: &str) -> Result<(), RuntimeError> {
        let (network_name, acl_name) = sandbox_network_names(sandbox_id);
        let network = self.read_network_config(&network_name)?;
        let acl = self.read_acl_config(&acl_name)?;
        let owned = [network.as_ref(), acl.as_ref()]
            .into_iter()
            .flatten()
            .filter(|config| self.manages(config))
            .collect::<Vec<_>>();
        if owned.is_empty() {
            // No managed resources: only an outstanding journal record keeps
            // the obligation alive.
            if let Some(record) = self.read_pending_cleanup(sandbox_id)? {
                self.persist_cleanup_record(
                    sandbox_id,
                    CleanupPhase::Teardown,
                    &record.attempts,
                    None,
                )?;
            }
            return Ok(());
        }
        // Journal EVERY owned marker still live — not just the first
        // config's. A retry can restamp the bridge and crash before
        // restamping the ACL (mixed incarnations); fencing the drain to
        // only one marker would reject the differently-stamped resource
        // and drop the obligation over a live owned object.
        let mut markers: Vec<String> = owned
            .iter()
            .map(|config| {
                // Unmarked owned resources keep their empty-string fence even
                // when marked resources coexist: omitting it would fence the
                // drain against the unmarked half of a mixed pair.
                config
                    .get(NETWORK_ATTEMPT_TAG)
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            })
            .collect();
        markers.dedup();
        self.persist_pending_cleanup_markers(sandbox_id, &markers)
    }

    /// Prove the sandbox bridge and ACL are both gone. Kill completion
    /// evidence requires this: VM absence alone leaves the bridge, its
    /// dnsmasq and the ACL behind.
    pub(crate) fn verify_sandbox_network_absent(
        &self,
        sandbox_id: &str,
    ) -> Result<(), RuntimeError> {
        let (network_name, acl_name) = sandbox_network_names(sandbox_id);
        if self.read_network_config(&network_name)?.is_some()
            || self.read_sandbox_acl(&acl_name)?.is_some()
        {
            return Err(RuntimeError::new(
                SandboxErrorCode::Internal,
                "sandbox network teardown is incomplete",
            ));
        }
        Ok(())
    }

    /// Whether any cleanup is still owed for this sandbox: a durable record
    /// or leftover managed objects.
    pub(crate) fn network_cleanup_outstanding(
        &self,
        sandbox_id: &str,
    ) -> Result<bool, RuntimeError> {
        if self
            .pending_cleanup_dir()
            .join(format!("{sandbox_id}.json"))
            .exists()
        {
            return Ok(true);
        }
        let (network_name, acl_name) = sandbox_network_names(sandbox_id);
        Ok(self.read_network_config(&network_name)?.is_some()
            || self.read_acl_tag(&acl_name)?.is_some())
    }

    /// Bounded, separately-authorized drain of durable cleanup obligations.
    /// Each record is tag-fenced AND incarnation-fenced at teardown: a
    /// resource stamped by a newer provisioning attempt is never deleted, and
    /// the stale record is dropped. Ownership (project AND name validity) is
    /// established BEFORE the per-drain budget is charged: foreign or
    /// invalid records never consume a slot, and a rotating cursor
    /// (`.drain-cursor` in the journal directory) makes every drain resume
    /// where the previous one stopped, so persistently failing records can
    /// never starve the ones behind them. Unreadable/malformed records are
    /// NEVER unlinked — ownership cannot be verified, so they are preserved
    /// and the failure is reported. Runs at inventory time (restart
    /// reconciliation), never on the ordinary-work path.
    pub(crate) fn drain_pending_network_cleanups(&self) -> Result<(), RuntimeError> {
        self.drain_pending_network_cleanups_skipping(&std::collections::HashSet::new())
    }

    /// The drain, leaving `busy` sandboxes' records (their lifecycle lock may
    /// be held by in-flight work) for a later drain instead of waiting.
    pub(crate) fn drain_pending_network_cleanups_skipping(
        &self,
        busy: &std::collections::HashSet<String>,
    ) -> Result<(), RuntimeError> {
        let dir = self.pending_cleanup_dir();
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return Ok(());
        };
        let mut records: Vec<PathBuf> = entries
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("json"))
            .collect();
        records.sort();
        // Probe every candidate BEFORE charging the budget: only records this
        // project owns (and whose sandbox id is a valid managed name) count
        // against the per-drain limit. Foreign, invalid, and unverifiable
        // records are handled below without consuming a slot.
        let mut owned: Vec<PathBuf> = Vec::new();
        let mut first_unreadable: Option<RuntimeError> = None;
        for record in &records {
            let sandbox_id = record
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string();
            let valid = crate::default_incus_instance_name(&sandbox_id);
            if sandbox_id.is_empty() || crate::validate_managed_instance_name(&valid).is_err() {
                let _ = std::fs::remove_file(record);
                continue;
            }
            if busy.contains(&sandbox_id) {
                continue;
            }
            match self.read_pending_cleanup(&sandbox_id) {
                Ok(Some(entry)) if entry.project == self.project => {
                    owned.push(record.clone());
                }
                // Another project's obligation in a shared state root: never
                // process it (the teardown would conflict on the project
                // fence) and NEVER unlink it — its own project's drain owns
                // the record. Ok(None): the record vanished between listing
                // and probing; nothing to do.
                Ok(_) => {}
                Err(err) => {
                    if first_unreadable.is_none() {
                        first_unreadable = Some(err);
                    }
                }
            }
        }
        // Rotate: resume after the last record the previous drain attempted,
        // wrapping around, so a record that keeps failing cannot monopolize
        // the head of every drain. The cursor is a best-effort progress
        // hint, not evidence: losing it restarts from the beginning.
        let cursor = std::fs::read_to_string(dir.join(".drain-cursor"))
            .map(|body| body.trim().to_owned())
            .unwrap_or_default();
        let start = owned
            .iter()
            .position(|record| {
                record
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .is_some_and(|id| id > cursor.as_str())
            })
            .unwrap_or(0);
        let mut ordered: Vec<PathBuf> = owned[start..].to_vec();
        ordered.extend_from_slice(&owned[..start]);
        ordered.truncate(256);
        let mut last_attempted: Option<String> = None;
        for record in ordered {
            let sandbox_id = record
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string();
            last_attempted = Some(sandbox_id.clone());
            // Serialize the record read, the fence-to-delete window and the
            // journal update with any concurrent apply/retry for this
            // sandbox: the record must be re-read under the lock, because a
            // retry can durably replace the obligation (fresh incarnation
            // after a failed rollback) while this drain was still waiting.
            let sandbox_lock = self.sandbox_lock(&sandbox_id);
            let _guard = self.lock_runtime(&sandbox_lock)?;
            let entry = match self.read_pending_cleanup(&sandbox_id) {
                Ok(Some(entry)) => entry,
                // Vanished while waiting: nothing to do. Read/parse failure
                // under the lock: preserve the record and report the failure.
                Ok(None) => continue,
                Err(err) => {
                    if first_unreadable.is_none() {
                        first_unreadable = Some(err);
                    }
                    continue;
                }
            };
            if entry.project != self.project {
                // Re-checked under the lock (the probe raced a replacement):
                // never process and NEVER unlink another project's record.
                continue;
            }
            let cleanup = if self.cancelled.is_some() {
                self.clone()
            } else {
                self.cleanup_scoped()
            };
            if entry.phase == CleanupPhase::Provisioning
                && cleanup
                    .instance_exists(&crate::default_incus_instance_name(&sandbox_id))
                    .unwrap_or(false)
            {
                // Existence alone is NOT proof of adoption: a crash after the
                // network apply but before the NIC verification leaves a VM
                // whose egress was never enforced. And the VM must carry THIS
                // sandbox's immutable binding before any recovery mutation:
                // a foreign-tagged VM is never reconfigured or adopted, no
                // matter what the record says. Only then: repair a stopped
                // drifted NIC, and retire the intent once the full
                // enforcement identity verifies.
                let name = crate::default_incus_instance_name(&sandbox_id);
                // The FULL bind_instance authorization, not a subset: a VM
                // with a conflicting template, base image, or create key is
                // rejected by the normal create path AFTER networking and
                // the intent exist — the drain must not then accept, repair,
                // or adopt it. A record without a persisted binding fails
                // closed.
                let bound = entry.binding.as_ref().is_some_and(|binding| {
                    cleanup
                        .bind_instance(
                            &name,
                            &sandbox_id,
                            &binding.template_fingerprint,
                            binding.create_key.as_deref(),
                        )
                        .is_ok()
                });
                if bound {
                    // Preview tunnels: a tunnel sandbox's NIC carries its
                    // pinned address, which only its recorded plan names;
                    // every other sandbox keeps the identity-only plan.
                    let plan = cleanup
                        .persisted_enforcement_plan(&sandbox_id)
                        .filter(|plan| plan.pinned_guest_address().is_some())
                        .unwrap_or_else(|| super::network::enforcement_identity_plan(&sandbox_id));
                    let _ = cleanup.ensure_instance_egress_device(&name, &plan);
                    if cleanup.verify_provisioned_enforcement(&sandbox_id).is_ok() {
                        let _ = std::fs::remove_file(&record);
                        Self::fsync_dir(&dir);
                    }
                }
                continue;
            }
            // The obligation covers every incarnation the journal has seen:
            // the failed restamp of a crashed retry leaves previous or
            // transitional markers on live resources, and the teardown must
            // fence-match any of them rather than dropping the record as
            // stale. Only the incarnations recorded before effects authorize cleanup.
            let attempts = entry.attempts.clone();
            match cleanup
                .teardown_sandbox_network_fenced(&sandbox_id, &attempts)
                .and_then(|()| cleanup.verify_sandbox_network_absent(&sandbox_id))
            {
                Ok(()) => {
                    let _ = std::fs::remove_file(&record);
                    Self::fsync_dir(&dir);
                }
                Err(err) if err.code == SandboxErrorCode::IdempotencyConflict => {
                    // Foreign-tagged objects are never touched, and stale
                    // incarnations are a newer attempt's concern; either way
                    // the record is meaningless and would loop forever.
                    let _ = std::fs::remove_file(&record);
                    Self::fsync_dir(&dir);
                }
                Err(_) => {}
            }
        }
        if let Some(id) = last_attempted {
            // Best-effort progress hint: the next drain resumes AFTER this
            // record (wrapping), so persistently failing records cannot
            // starve the ones behind them. A lost cursor only restarts the
            // rotation; it is not evidence and needs no durability.
            let _ = Self::write_private_file(&dir.join(".drain-cursor"), id.as_bytes());
        }
        if let Some(err) = first_unreadable {
            return Err(err);
        }
        Ok(())
    }

    /// `incus network acl list --format json` names.
    fn list_acl_names(&self) -> Result<Vec<String>, RuntimeError> {
        let out = self.run(&["network", "acl", "list", "--format", "json"], false)?;
        if out.exit_code != 0 {
            return Err(host_cli_error("network acl list", &out));
        }
        let rows: Vec<serde_json::Value> = serde_json::from_str(&out.stdout).map_err(|err| {
            RuntimeError::new(
                SandboxErrorCode::Internal,
                format!("failed to parse incus network acl list JSON: {err}"),
            )
        })?;
        Ok(rows
            .iter()
            .filter_map(|row| {
                row.get("name")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
            .collect())
    }

    /// All sandbox ids with network-cleanup relevance: journal records plus
    /// every owned bridge/ACL still present. Used so a census never reports
    /// absence while teardown evidence is outstanding.
    pub(crate) fn network_cleanup_sandbox_ids(&self) -> Result<Vec<String>, RuntimeError> {
        let mut ids: Vec<String> = Vec::new();
        if let Ok(entries) = std::fs::read_dir(self.pending_cleanup_dir()) {
            for entry in entries.flatten() {
                if let Some(id) = entry
                    .path()
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .map(str::to_owned)
                    && !id.is_empty()
                    && !id.starts_with('.')
                    // Records are project-scoped: a shared state root must
                    // never let one project's census claim (or its drain
                    // settle) another project's obligations. An UNREADABLE
                    // record is conservatively counted as own: the census
                    // must never report absence while evidence cannot be
                    // verified.
                    && !matches!(
                        self.read_pending_cleanup(&id),
                        Ok(Some(record))
                            if record.project != self.project
                    )
                {
                    ids.push(id);
                }
            }
        }
        let tag_of = |config: &serde_json::Map<String, serde_json::Value>| {
            config
                .get(NETWORK_SANDBOX_TAG)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        };
        for name in self.list_network_names()? {
            if !name.starts_with(super::network::NETWORK_NAME_PREFIX) {
                continue;
            }
            if let Some(config) = self.read_network_config(&name)?
                && self.manages(&config)
                && let Some(id) = tag_of(&config)
            {
                ids.push(id);
            }
        }
        for name in self.list_acl_names()? {
            if !name.starts_with(super::network::ACL_NAME_PREFIX) {
                continue;
            }
            if let Some(config) = self.read_acl_config(&name)?
                && self.manages(&config)
                && let Some(id) = tag_of(&config)
            {
                ids.push(id);
            }
        }
        ids.sort();
        ids.dedup();
        Ok(ids)
    }

    /// Choose the bridge gateway for a sandbox: reuse the address of an
    /// already-applied owned bridge (create retries must not renumber), else
    /// allocate a /24 that overlaps neither existing managed bridges nor host
    /// routes. The choice is persisted in the network's `ipv4.address`.
    pub(crate) fn gateway_for(&self, sandbox_id: &str) -> Result<std::net::Ipv4Addr, RuntimeError> {
        let (network_name, _) = sandbox_network_names(sandbox_id);
        if let Some(config) = self.read_network_config(&network_name)? {
            let tag = config
                .get(NETWORK_SANDBOX_TAG)
                .and_then(serde_json::Value::as_str);
            if tag != Some(sandbox_id) || !self.manages(&config) {
                return Err(foreign_object("network", &network_name));
            }
            return config
                .get("ipv4.address")
                .and_then(serde_json::Value::as_str)
                .and_then(|address| address.split('/').next())
                .and_then(|address| address.parse().ok())
                .ok_or_else(|| {
                    RuntimeError::new(
                        SandboxErrorCode::Internal,
                        "sandbox network is missing its gateway address",
                    )
                });
        }
        let mut taken = match &self.host_routes {
            Some(routes) => routes.clone(),
            None => host_route_networks()?,
        };
        for name in self.list_network_names()? {
            if let Some(config) = self.read_network_config(&name)?
                && let Some((base, prefix)) = config
                    .get("ipv4.address")
                    .and_then(serde_json::Value::as_str)
                    .and_then(parse_ipv4_network)
            {
                taken.push((base, prefix));
            }
        }
        allocate_gateway(sandbox_id, &taken)
    }

    /// `incus network list --format json` names (managed and unmanaged).
    fn list_network_names(&self) -> Result<Vec<String>, RuntimeError> {
        let out = self.run(&["network", "list", "--format", "json"], false)?;
        if out.exit_code != 0 {
            return Err(host_cli_error("network list", &out));
        }
        let rows: Vec<serde_json::Value> = serde_json::from_str(&out.stdout).map_err(|err| {
            RuntimeError::new(
                SandboxErrorCode::Internal,
                format!("failed to parse incus network list JSON: {err}"),
            )
        })?;
        Ok(rows
            .iter()
            .filter_map(|row| {
                row.get("name")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
            .collect())
    }

    /// Raw instance metadata (status + devices) for device verification.
    /// The instance's ORIGINAL create binding key (immutable metadata set at
    /// creation). Reconnect journals this — never its own operation key — so
    /// restart recovery's bind check matches the VM the create path bound.
    pub(crate) fn instance_create_key(&self, name: &str) -> Result<Option<String>, RuntimeError> {
        let metadata = self.query_instance_metadata(name)?;
        let (_, key_tag, _) = Self::metadata_keys();
        Ok(metadata
            .get("config")
            .and_then(|config| config.get(key_tag))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned))
    }

    fn query_instance_metadata(&self, name: &str) -> Result<serde_json::Value, RuntimeError> {
        crate::validate_managed_instance_name(name)?;
        self.query_raw(&with_query_params(
            &format!("/1.0/instances/{name}"),
            &[("project", self.project.as_str())],
        ))
    }

    /// The instance's effective device set: `expanded_devices`, which is what
    /// the daemon actually enforces — profile-inherited devices merged with
    /// local ones. Local `devices` alone both rejects valid VMs (the root
    /// disk is inherited from the profile, not local) and misses inherited
    /// extras. Missing expansion evidence fails closed.
    fn expanded_devices(metadata: &serde_json::Value) -> serde_json::Value {
        metadata
            .get("expanded_devices")
            .cloned()
            .unwrap_or(serde_json::Value::Null)
    }

    /// Verify the instance's effective devices equal the audited set: root
    /// disk plus the single anti-spoof NIC on the sandbox bridge. Runs after
    /// init and before first start, and before accepting an existing VM.
    pub(crate) fn verify_instance_devices(
        &self,
        name: &str,
        plan: &SandboxNetworkPlan,
    ) -> Result<(), RuntimeError> {
        let metadata = self.query_instance_metadata(name)?;
        devices_match_plan(&Self::expanded_devices(&metadata), plan)
    }

    /// Restart-recovery acceptance: egress enforcement must be VERIFIED
    /// before a provisioning intent is retired or a recovered VM is reported
    /// as a successful allocation. Checks the whole enforcement identity:
    /// the sandbox bridge and ACL exist and are owned by this project, and
    /// the instance's effective devices equal the audited launch devices.
    /// Existence of the VM alone is NOT proof: a crash between network apply
    /// and the NIC check leaves a VM whose networking was never enforced.
    /// Coherence-retry budget for the enforcement observation. Tests
    /// override it to exercise the exhaustion path without a 25s stall.
    fn coherence_budget(&self) -> std::time::Duration {
        #[cfg(test)]
        if let Some(budget) = self.coherence_budget_override {
            return budget;
        }
        std::time::Duration::from_secs(25)
    }

    /// C37 R4: the typed three-way verdict of an enforcement observation.
    /// ONLY `ConfirmedDrift` — a coherent comparison failure against the
    /// persisted plan — ever authorizes enforcement-loss cleanup.
    /// `Inconclusive` (timeout, cancellation, transport/daemon failure, an
    /// unsettleable DNS obligation, or an exhausted coherence budget) is
    /// retryable at every consumer and NEVER cleanup-triggering.
    pub(crate) fn enforcement_observation(&self, sandbox_id: &str) -> EnforcementVerdict {
        // Settle restart-durable DNS expiry obligations BEFORE the
        // ordinary network/ACL reads below (C36 r29 F1): those reads
        // carry no deadline discipline of their own and can stall, and
        // an expired allow must never stay effective through the stall
        // — recovery's blind pre-fence needs no observation. A recovery
        // FAILURE is inconclusive, never drift (C37 R4): the blind
        // pre-fence keeps the expired destination denied, so the sandbox
        // is over-DENIED, not broadened — the observation is simply
        // untrustworthy and stays retryable.
        // C58 SEED-1: a recovery FAILURE no longer short-circuits the
        // verdict. The old arm convicted drift whenever a pending marker
        // existed, without the coherence check below — so an owed
        // refresh/settlement (our own journaled work, with the blind
        // pre-fence and the watcher still enforcing) was convicted, and a
        // concurrent managed transition could be too. The failure is now
        // carried INTO the coherent snapshot loop, whose readback runs in
        // owed mode: drift that the owed work does not explain still
        // convicts (coherently), everything else is inconclusive — never
        // verified, never cleanup-triggering.
        // C58 G1 r3/r4 (G1-R3-3): recovery is bounded by its OWN
        // withdrawal deadline and deliberately ignores the caller's permit,
        // so it must not consume the observation's READ budget: a failing
        // settle (an unfenceable denied destination) could use up the
        // reconciler's whole 5 s permit, and the reads then never ran — the
        // state that must convict (G1-R1-2) stayed inconclusive on every
        // pass. The read budget the caller had BEFORE recovery (capped at
        // OBSERVATION_READ_BUDGET) is restored on a CHILD permit, which is
        // revoked whenever the caller's permit is. A permit already elapsed
        // before recovery, an unbounded permit, or one recovery did not
        // shorten is left as is.
        let read_budget = self
            .cancelled
            .as_ref()
            .and_then(|permit| permit.remaining().map(|left| (permit.clone(), left)));
        let recovery_failed = self.recover_dns_expiry_obligations(sandbox_id).err();
        if let Some((parent, before)) = read_budget
            && !before.is_zero()
            && !parent.is_revoked()
            && parent.remaining().is_some_and(|after| after < before)
        {
            let mut observer = self.clone();
            observer.cancelled = Some(std::sync::Arc::new(crate::RuntimePermit::child(
                parent,
                before.min(OBSERVATION_READ_BUDGET),
            )));
            return observer.observe_enforcement_coherently(sandbox_id, recovery_failed);
        }
        self.observe_enforcement_coherently(sandbox_id, recovery_failed)
    }

    /// The coherent snapshot loop of [`Self::enforcement_observation`],
    /// AFTER DNS expiry recovery ran (`recovery_failed` is its error).
    fn observe_enforcement_coherently(
        &self,
        sandbox_id: &str,
        recovery_failed: Option<RuntimeError>,
    ) -> EnforcementVerdict {
        let unenforced = || {
            RuntimeError::new(
                SandboxErrorCode::IdempotencyConflict,
                format!(
                    "sandbox `{sandbox_id}` networking is not verifiably enforced; refusing to treat provisioning as complete"
                ),
            )
        };
        // C37 R3: the plan snapshot and the live readback must be COHERENT
        // with the autonomous DNS expiry watcher (and any concurrent
        // refresh/recovery): a managed transition fences/removes rules
        // BEFORE its persisted plan commit, so a read pair straddling it
        // compares the new live ACL against the old plan and would convict
        // a healthy, correctly narrowed sandbox of drift. The transition
        // seqlock (`begin_dns_transition`) makes the overlap observable:
        // retry the whole snapshot until it is transition-free. Only the
        // verifier waits; deadline enforcement is never blocked.
        let deadline = std::time::Instant::now() + self.coherence_budget();
        loop {
            if self
                .cancelled
                .as_ref()
                .is_some_and(|permit| permit.is_cancelled())
            {
                return EnforcementVerdict::Inconclusive(RuntimeError::new(
                    SandboxErrorCode::UnknownOutcome,
                    "enforcement observation permit expired or was revoked",
                ));
            }
            let before = self.dns_transition_observation(sandbox_id);
            let result =
                self.verify_enforcement_snapshot(sandbox_id, &unenforced, recovery_failed.as_ref());
            let after = self.dns_transition_observation(sandbox_id);
            let coherent = before == after && !after.1;
            match (result, coherent) {
                (Ok(()), true) => return EnforcementVerdict::Verified,
                // C37 R4: ONLY the drift-coded comparison failure (missing
                // or foreign enforcement objects, absent plan, rule/config/
                // device mismatch) is confirmed drift. Every other error —
                // Timeout, Cancelled, UnknownOutcome, Internal — provides
                // no drift evidence and is inconclusive.
                (Err(err), true) if err.code == SandboxErrorCode::IdempotencyConflict => {
                    return EnforcementVerdict::ConfirmedDrift(err.message);
                }
                (Err(err), true) => return EnforcementVerdict::Inconclusive(err),
                (outcome, false) => {
                    if std::time::Instant::now() >= deadline {
                        return EnforcementVerdict::Inconclusive(RuntimeError::new(
                            SandboxErrorCode::Internal,
                            format!(
                                "sandbox `{sandbox_id}` enforcement could not be observed coherently across a managed DNS transition: {}",
                                outcome
                                    .map(|()| "ok".to_string())
                                    .unwrap_or_else(|err| err.message),
                            ),
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
            }
        }
    }

    /// Wire-code adapter over [`Self::enforcement_observation`] for callers
    /// that only need pass/fail (the start fence): verified passes, drift
    /// keeps the historical conflict refusal, an inconclusive observation
    /// propagates its own retryable error.
    pub(crate) fn verify_provisioned_enforcement(
        &self,
        sandbox_id: &str,
    ) -> Result<(), RuntimeError> {
        match self.enforcement_observation(sandbox_id) {
            EnforcementVerdict::Verified => {
                self.policy_refusals
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(sandbox_id);
                Ok(())
            }
            EnforcementVerdict::ConfirmedDrift(reason) => Err(RuntimeError::new(
                SandboxErrorCode::IdempotencyConflict,
                reason,
            )),
            EnforcementVerdict::Inconclusive(err) => Err(err.enforcement_inconclusive()),
        }
    }

    /// One enforcement snapshot: persisted plan and ownership tags, the
    /// live bridge/ACL readback against it, and the instance's effective
    /// devices. Callers needing coherence with managed DNS transitions must
    /// bracket it with the transition seqlock (see the caller above).
    fn verify_enforcement_snapshot(
        &self,
        sandbox_id: &str,
        unenforced: &dyn Fn() -> RuntimeError,
        recovery_failed: Option<&RuntimeError>,
    ) -> Result<(), RuntimeError> {
        let (network_name, acl_name) = sandbox_network_names(sandbox_id);
        let network = self.read_network_config(&network_name)?;
        let acl = self.read_acl_config(&acl_name)?;
        let (Some(network), Some(acl)) = (network, acl) else {
            return Err(unenforced());
        };
        if !self.manages(&network) || !self.manages(&acl) {
            return Err(unenforced());
        }
        // The SAME readback apply performed: ownership tags, the bridge's
        // ACL attachment + deny defaults, and the ACL's rules and states
        // must equal the persisted plan — presence alone proves nothing (a
        // detached bridge or an added allow-all rule still "exists").
        // C37 R5: an UNREADABLE plan record is unavailable evidence —
        // inconclusive, never drift. Only a cleanly absent (or foreign)
        // record convicts.
        let plan = match self.persisted_enforcement_plan_checked(sandbox_id) {
            Ok(Some(plan)) => plan,
            Ok(None) => return Err(unenforced()),
            Err(err) => return Err(err),
        };
        // C37 R4: only the drift-coded COMPARISON failure maps to the
        // unenforced verdict; a timeout/cancellation/transport error from
        // the readback (or from the recovery inside) propagates with its
        // own code so the verdict classifies it as inconclusive.
        // The caller already ran DNS expiry recovery (once per observation,
        // BEFORE these reads); a failed recovery switches the readback to
        // owed mode (C58 SEED-1).
        let owed = self
            .verify_sandbox_network_recovered(&plan, recovery_failed, false)
            .map_err(|err| {
                if err.code == SandboxErrorCode::IdempotencyConflict {
                    unenforced()
                } else {
                    err
                }
            })?;
        // C58 G1-R2-1: the device check runs (and convicts) whether or not
        // a refresh is owed — an owed refresh never explains a NIC, device
        // or attachment difference. Only then is the owed refusal surfaced.
        let name = crate::default_incus_instance_name(sandbox_id);
        self.verify_instance_devices(&name, &plan)?;
        match owed {
            Some(owed) => Err(owed),
            None => Ok(()),
        }
    }

    /// THE bound-enforcement boundary (C37 R2): every consumer that reports
    /// or relies on a positively bound sandbox's readiness/runnability must
    /// pass through here. Only CONFIRMED DRIFT on a bound RUNNING VM is
    /// GuestUnavailable — the cleanup-triggering signal the relay's
    /// generation-fenced lifecycle cleanup consumes — plus the durable
    /// enforcement-loss record (C37 R3). An INCONCLUSIVE observation
    /// (timeout, cancellation, transport/daemon failure, coherence budget)
    /// propagates its own retryable error on every path, running or not:
    /// it never becomes the cleanup code and never writes a record (C37
    /// R4). A STOPPED bound VM's confirmed drift keeps the non-destructive
    /// IdempotencyConflict refusal (a stopped VM can be re-fenced, so
    /// detection is not a cleanup mandate).
    pub(crate) fn verify_bound_enforcement(
        &self,
        sandbox_id: &str,
        running: bool,
    ) -> Result<(), RuntimeError> {
        self.with_verified_enforcement(sandbox_id, running, || Ok(()))
    }

    /// The existing lifecycle gate covers observation through its readiness
    /// consumer. Never hold it over a boot polling loop or sleep.
    pub(crate) fn with_verified_enforcement<T>(
        &self,
        sandbox_id: &str,
        running: bool,
        ready: impl FnOnce() -> Result<T, RuntimeError>,
    ) -> Result<T, RuntimeError> {
        let lock = self.sandbox_lock(sandbox_id);
        let _guard = self.lock_runtime(&lock)?;
        self.verify_bound_enforcement_locked(sandbox_id, running)?;
        ready()
    }

    /// Caller already owns the existing lifecycle gate (apply/reconnect/poller).
    pub(crate) fn verify_bound_enforcement_locked(
        &self,
        sandbox_id: &str,
        running: bool,
    ) -> Result<(), RuntimeError> {
        self.verify_captured_bound_enforcement(running, self.capture_enforcement_loss(sandbox_id))
    }

    pub(crate) fn capture_enforcement_loss(&self, sandbox_id: &str) -> CapturedEnforcementLoss {
        // Capture BEFORE observation/IO. Never apply this verdict to a renewed
        // lease or newer generation. All actual readiness producers
        // share this boundary, including probes that discard the returned error.
        let lifecycle = self
            .loss_lifecycle
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let intent = lifecycle.as_ref().map(|l| l.capture(sandbox_id));
        CapturedEnforcementLoss {
            sandbox_id: sandbox_id.to_owned(),
            lifecycle,
            intent,
        }
    }

    /// The same C37 boundary, with authority captured before an outer
    /// ownership read. Never replace the capture with a post-IO snapshot.
    pub(crate) fn verify_captured_bound_enforcement(
        &self,
        running: bool,
        captured: CapturedEnforcementLoss,
    ) -> Result<(), RuntimeError> {
        let CapturedEnforcementLoss {
            sandbox_id,
            lifecycle,
            intent,
        } = captured;
        let sandbox_id = sandbox_id.as_str();
        match self.enforcement_observation(sandbox_id) {
            EnforcementVerdict::Verified => {
                self.policy_refusals
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(sandbox_id);
                Ok(())
            }
            EnforcementVerdict::Inconclusive(err) => Err(err.enforcement_inconclusive()),
            EnforcementVerdict::ConfirmedDrift(reason) if running => {
                // Confirmed drift on a positively bound RUNNING VM leaves a
                // DURABLE record in addition to the cleanup-triggering code,
                // so EVERY detection path — operation result, receipt
                // settle, inventory census, live probe — feeds the
                // always-running enforcement-loss drain. No detection path
                // drops the signal. A persistence FAILURE stays actionable
                // (C37 R4): it is named in the error and — because a
                // malformed/absent record never blocks a rewrite — the next
                // detection pass retries the write.
                let mut message =
                    format!("egress enforcement unverifiable on a running instance: {reason}");
                let mut must_halt = false;
                let mut preparation = intent.map(|intent| intent.prepare());
                // A renewal/replacement can win during the daemon read. Its
                // failed CAS retained NO lease intent. Stop restrictively now,
                // then capture fresh authority BEFORE fresh ownership checks
                // and coherent verification, even though our halt stopped the
                // VM. Only that NEW verdict may prepare the new arm. This is
                // the same boundary for every producer, not another marker.
                while preparation.as_ref().is_some_and(|result| {
                    result
                        .as_ref()
                        .is_err_and(|err| err.code == SandboxErrorCode::IdempotencyConflict)
                }) {
                    let halt = self.halt_confirmed_breach(sandbox_id);
                    message.push_str(&format!(
                        "; captured lease changed; restrictive stop: {halt:?}"
                    ));
                    let fresh = lifecycle.as_ref().map(|l| l.capture(sandbox_id));
                    let recovery = self.cleanup_scoped();
                    recovery.bind_owned_instance(
                        &crate::default_incus_instance_name(sandbox_id),
                        sandbox_id,
                    )?;
                    match recovery.enforcement_observation(sandbox_id) {
                        EnforcementVerdict::ConfirmedDrift(_) => {
                            preparation = fresh.map(|intent| intent.prepare());
                        }
                        EnforcementVerdict::Verified => {
                            return Err(RuntimeError::new(
                                SandboxErrorCode::IdempotencyConflict,
                                "enforcement changed after the captured lease; retry readiness",
                            ));
                        }
                        EnforcementVerdict::Inconclusive(err) => {
                            return Err(err.enforcement_inconclusive());
                        }
                    }
                }
                // The lease is the recovery authority even if the runtime loss
                // directory is unwritable. Prepare cannot publish completion.
                if let Some(Err(err)) = preparation {
                    message.push_str(&format!("; lifecycle prepare failed: {err}"));
                    must_halt = true;
                }
                if let Err(err) = self.persist_enforcement_loss(sandbox_id, &reason) {
                    message.push_str(&format!(
                        "; the enforcement-loss record could not be persisted: {err}"
                    ));
                    must_halt = true;
                }
                if must_halt {
                    // C37 R5/R6: without the durable record the autonomous
                    // drain cannot see this breach and a probe caller
                    // discards the diagnostic — a confirmed broadened ACL
                    // must not stay effective until re-detection. The
                    // boundary takes THE shared permit-independent
                    // restrictive action (`halt_confirmed_breach`): an
                    // ownership-fenced force-stop on a separately scoped
                    // cleanup permit. A halt failure is diagnostic-only:
                    // the drift signal below still stands.
                    match self.halt_confirmed_breach(sandbox_id) {
                        Ok(true) => message
                            .push_str("; the running VM was force-stopped to halt the breach"),
                        Ok(false) => {
                            message.push_str("; fail-safe stop skipped (instance not bound)")
                        }
                        Err(err) => message.push_str(&format!(
                            "; the fail-safe stop could not be confirmed: {err}"
                        )),
                    }
                }
                Err(RuntimeError::new(
                    SandboxErrorCode::GuestUnavailable,
                    message,
                ))
            }
            EnforcementVerdict::ConfirmedDrift(reason) => Err(RuntimeError::new(
                SandboxErrorCode::IdempotencyConflict,
                reason,
            )),
        }
    }

    /// C37 R6: THE confirmed-breach halt — the single permit-INDEPENDENT
    /// restrictive action shared by the boundary's loss-record-persistence
    /// failure path (C37 R5) and the drain's teardown-bookkeeping failure
    /// path. The invariant: CONFIRMED drift on a bound RUNNING VM always
    /// halts traffic, even when every journal (the loss record OR the
    /// network-cleanup journal) is unwritable. Runs on a separately scoped
    /// cleanup permit so relay revocation of the caller's permit cannot
    /// strand the breach. Stop — never delete: halting the VM cuts the
    /// unauthorized traffic while destruction authority stays with the
    /// relay's lifecycle cleanup and the drain's fenced teardown.
    /// `Ok(true)` when the owned VM was force-stopped; `Ok(false)` when no
    /// OWNED instance is bound (a foreign or absent instance is never
    /// touched); `Err` when the halt could not be confirmed.
    pub(crate) fn halt_confirmed_breach(&self, sandbox_id: &str) -> Result<bool, RuntimeError> {
        let name = crate::default_incus_instance_name(sandbox_id);
        let halt = self.cleanup_scoped();
        let observed = halt.bind_owned_instance(&name, sandbox_id);
        // SEED-5: revoke between the halt's ownership observation and its
        // stop IO. The cleanup scope must remain independent of the caller.
        #[cfg(test)]
        if let Some(permit) = &self.halt_observation_revoke {
            permit.revoke();
        }
        match observed {
            Ok(bound) => halt
                .stop_force(&bound)
                .map_err(crate::EffectError::into_error)
                .map(|_| true),
            Err(err)
                if err.code == SandboxErrorCode::IdempotencyConflict
                    || err.code == SandboxErrorCode::SandboxNotFound =>
            {
                Ok(false)
            }
            Err(err) => Err(err),
        }
    }

    pub(crate) fn enforcement_loss_dir(&self) -> PathBuf {
        self.state_root().join("enforcement-losses")
    }

    /// C37 R3/R4: durably record confirmed enforcement loss on a positively
    /// bound RUNNING VM through the SAME atomic, crash-durable journal
    /// write path as the provisioning journal (`write_durable_record`:
    /// unique no-follow temp, file fsync, atomic rename, directory fsync).
    /// First detection stands — but only a WELL-FORMED own-project record
    /// counts: an absent, unreadable, truncated, or malformed record (an
    /// interrupted write) is (re)written, so a partial write never wedges
    /// the signal (C37 R4). A persistence failure is returned, never
    /// silently treated as recorded.
    pub(crate) fn persist_enforcement_loss(
        &self,
        sandbox_id: &str,
        reason: &str,
    ) -> Result<(), RuntimeError> {
        crate::validate_managed_instance_name(&crate::default_incus_instance_name(sandbox_id))
            .map_err(|err| {
                RuntimeError::new(
                    SandboxErrorCode::Internal,
                    format!("invalid sandbox id for the enforcement-loss journal: {err}"),
                )
            })?;
        let dir = self.enforcement_loss_dir();
        let record = dir.join(format!("{sandbox_id}.json"));
        if let Ok(body) = std::fs::read_to_string(&record)
            && let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body)
            && parsed.get("sandbox_id").and_then(|v| v.as_str()) == Some(sandbox_id)
            && parsed
                .get("project")
                .and_then(|v| v.as_str())
                .map(|project| project == self.project)
                .unwrap_or(false)
        {
            // A well-formed own record already stands.
            return Ok(());
        }
        let body = serde_json::json!({
            "sandbox_id": sandbox_id,
            "project": self.project,
            "reason": reason,
        });
        let body = serde_json::to_string(&body).map_err(|err| {
            RuntimeError::new(
                SandboxErrorCode::Internal,
                format!("cannot encode the enforcement-loss record: {err}"),
            )
        })?;
        self.write_durable_record(&dir, &format!("{sandbox_id}.json"), &body)
    }

    /// The durably recorded enforcement losses, validated (own project,
    /// well-formed): a malformed or foreign record is preserved on disk
    /// but never acted on. All actionable ids, SORTED: the per-pass bound
    /// (256) is applied by the drain AFTER rotating past its cursor (C37
    /// R7) — capping here would let the first 256 alphabetical records
    /// permanently hide the rest behind them.
    pub(crate) fn enforcement_loss_sandbox_ids(&self) -> Result<Vec<String>, RuntimeError> {
        let mut ids: Vec<String> = Vec::new();
        let entries = match std::fs::read_dir(self.enforcement_loss_dir()) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(ids),
            Err(err) => {
                return Err(RuntimeError::new(
                    SandboxErrorCode::Internal,
                    format!("cannot read the enforcement-loss journal: {err}"),
                ));
            }
        };
        for entry in entries.flatten() {
            let Some(id) = entry
                .path()
                .file_stem()
                .and_then(|s| s.to_str())
                .map(str::to_owned)
            else {
                continue;
            };
            if id.is_empty() || id.starts_with('.') {
                continue;
            }
            // Well-formed AND own-project records are actionable. So is an
            // UNREADABLE or MALFORMED record (C37 R4): skipping it would
            // let one interrupted write permanently disable observational
            // cleanup for that sandbox. The drain re-verifies from live
            // daemon state before it touches anything, so a conservative
            // (possibly foreign) entry is re-derived safely — a well-formed
            // record provably owned by ANOTHER project is the only skip.
            let owns = match std::fs::read_to_string(entry.path()) {
                Ok(body) => match serde_json::from_str::<serde_json::Value>(&body) {
                    Ok(parsed) => {
                        parsed.get("sandbox_id").and_then(|v| v.as_str()) == Some(id.as_str())
                            && parsed
                                .get("project")
                                .and_then(|v| v.as_str())
                                .map(|project| project == self.project)
                                .unwrap_or(false)
                    }
                    Err(_) => true,
                },
                Err(_) => true,
            };
            if owns {
                ids.push(id);
            }
        }
        ids.sort();
        Ok(ids)
    }

    /// Called only after verified recovery or lifecycle-completed teardown:
    /// retire the record and reclaim its shared dispatch refusal.
    pub(crate) fn clear_enforcement_loss(&self, sandbox_id: &str) -> Result<(), RuntimeError> {
        let dir = self.enforcement_loss_dir();
        match std::fs::remove_file(dir.join(format!("{sandbox_id}.json"))) {
            Ok(()) => {
                Self::fsync_dir(&dir);
                Ok(())
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(RuntimeError::new(
                SandboxErrorCode::Internal,
                format!("cannot retire the enforcement-loss record {sandbox_id}: {err}"),
            )),
        }?;
        self.policy_refusals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(sandbox_id);
        Ok(())
    }

    /// C37 R1: launch-config hardening at the START boundary — the
    /// instance's EFFECTIVE config must carry only the audited allowlist:
    /// flycockpit metadata, daemon-managed `volatile.*`, and the two keys
    /// the launch itself sets. A config key baked into the template image
    /// survives init into the effective config; refused once, the instance
    /// must stay unlaunchable through every path that skips init (create
    /// retry, reconnect resume, direct start).
    pub(crate) fn verify_launch_config(
        &self,
        instance_name: &str,
        vm_size: sandbox_protocol::VmSize,
    ) -> Result<(), RuntimeError> {
        crate::resources::validate_vm_size(vm_size)?;
        let metadata = self.query_instance_metadata(instance_name)?;
        let config = metadata
            .get("expanded_config")
            .or_else(|| metadata.get("config"))
            .and_then(serde_json::Value::as_object);
        let Some(config) = config else {
            return Err(RuntimeError::new(
                SandboxErrorCode::IdempotencyConflict,
                format!(
                    "instance `{instance_name}` effective config is not auditable; refusing start"
                ),
            ));
        };
        for key in config.keys() {
            let allowed = key.starts_with("user.flycockpit.")
                || key.starts_with("volatile.")
                || key.starts_with("image.")
                || key == "security.agent.metrics"
                || key == "boot.autostart"
                || key == "limits.cpu"
                || key == "limits.memory";
            if !allowed {
                return Err(RuntimeError::new(
                    SandboxErrorCode::IdempotencyConflict,
                    format!(
                        "instance `{instance_name}` effective config carries unaudited key `{key}`; refusing start"
                    ),
                ));
            }
        }
        crate::resources::verify_vm_size(config, vm_size, false)?;
        self.verify_expected_root(instance_name)
    }

    /// Recorded-policy immutability on reconnect (C37 R2): with the
    /// re-apply retired, the request's policy identity must equal the
    /// persisted record — a reconnect carrying a DIFFERENT policy than the
    /// recorded one is a conflict, never a silent re-policy; a sandbox with
    /// NO record was never policy-bound here, so it refuses closed.
    pub(crate) fn verify_recorded_policy_identity(
        &self,
        sandbox_id: &str,
        egress_policy_hash: Option<&str>,
    ) -> Result<(), RuntimeError> {
        let matches = match self.recorded_policy_hash(sandbox_id) {
            Some(recorded) => recorded.as_deref() == egress_policy_hash,
            None => false,
        };
        if !matches {
            return Err(RuntimeError::new(
                SandboxErrorCode::IdempotencyConflict,
                format!(
                    "sandbox `{sandbox_id}` recorded egress policy differs from the request; refusing to resume"
                ),
            ));
        }
        Ok(())
    }

    /// Accept an existing VM only when its NIC provably enforces the plan. A
    /// stopped VM is safely reconfigured (fenced device override + read-back);
    /// a running VM on the wrong devices fails closed — it is never adopted
    /// with unenforced networking.
    pub(crate) fn ensure_instance_egress_device(
        &self,
        name: &str,
        plan: &SandboxNetworkPlan,
    ) -> Result<(), RuntimeError> {
        let metadata = self.query_instance_metadata(name)?;
        let devices = Self::expanded_devices(&metadata);
        if devices_match_plan(&devices, plan).is_ok() {
            return Ok(());
        }
        let status = metadata
            .get("status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let status_code = metadata
            .get("status_code")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_default();
        if status.eq_ignore_ascii_case("running") || status_code == 103 {
            return Err(RuntimeError::new(
                SandboxErrorCode::IdempotencyConflict,
                "running instance is not attached to its sandbox bridge; refusing to adopt it",
            ));
        }
        // Replace eth0 with the COMPLETE audited definition. `device set`
        // and `device override` only MERGE keys: a legacy NIC's incompatible
        // properties (e.g. nictype=bridged,parent=br0 next to network=…)
        // would survive and the repair would keep failing. A LOCAL eth0 is
        // removed first; an INHERITED one is fully shadowed by the fresh
        // local device of the same name (Incus semantics: a local device
        // replaces the inherited one wholesale — unlike override).
        let local_nic = metadata
            .get("devices")
            .and_then(|devices| devices.get("eth0"))
            .is_some();
        if local_nic {
            let out = self.run(
                &[
                    "config".to_string(),
                    "device".to_string(),
                    "remove".to_string(),
                    name.to_string(),
                    "eth0".to_string(),
                ],
                false,
            )?;
            if out.exit_code != 0 {
                return Err(host_cli_error("config device remove", &out));
            }
        }
        let mut args: Vec<String> = vec![
            "config".to_string(),
            "device".to_string(),
            "add".to_string(),
            name.to_string(),
            "eth0".to_string(),
            "nic".to_string(),
        ];
        args.extend(plan.nic_device_args());
        let out = self.run(&args, false)?;
        if out.exit_code != 0 {
            return Err(host_cli_error("config device repair", &out));
        }
        self.verify_instance_devices(name, plan)
    }

    /// Delete the sandbox's network then ACL. Objects carrying another
    /// sandbox's tag are never touched. When `expected_attempts` is set, a
    /// resource stamped with an incarnation OUTSIDE that set is left alone —
    /// a stale cleanup record must never delete what a newer apply rebuilt.
    /// The set covers every incarnation the journal has seen, so a retry's
    /// crashed mid-restamp resources (previous or transitional markers)
    /// still fence-match their own obligation.
    fn teardown_sandbox_network_inner(
        &self,
        sandbox_id: &str,
        expected_attempts: Option<&[String]>,
    ) -> Result<(), RuntimeError> {
        let (network_name, acl_name) = sandbox_network_names(sandbox_id);
        let fence = |config: &serde_json::Map<String, serde_json::Value>,
                     kind: &str|
         -> Result<(), RuntimeError> {
            if let Some(expected) = expected_attempts {
                let marker = config
                    .get(NETWORK_ATTEMPT_TAG)
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                if !expected.iter().any(|attempt| attempt == marker) {
                    return Err(RuntimeError::new(
                        SandboxErrorCode::IdempotencyConflict,
                        format!(
                            "incus {kind} `{network_name}` belongs to a newer provisioning attempt; the cleanup record is stale"
                        ),
                    ));
                }
            }
            Ok(())
        };
        let network = self.read_network_config(&network_name)?;
        if let Some(config) = &network {
            let tag = config
                .get(NETWORK_SANDBOX_TAG)
                .and_then(serde_json::Value::as_str);
            if tag != Some(sandbox_id) || !self.manages(config) {
                return Err(foreign_object("network", &network_name));
            }
            fence(config, "network")?;
        }
        // Preview tunnels: only a teardown that passed the bridge's ownership
        // and incarnation fence stops (and reaps) the sandbox's client,
        // before its subnet can be released and reused.
        crate::teardown_hook::before_network_teardown(sandbox_id)?;
        if network.is_some() {
            #[cfg(test)]
            if let Some(barrier) = &self.fence_barrier {
                // Test hook: widen the fence-to-delete window so tests can
                // prove the per-sandbox lock serializes a concurrent apply.
                // Two rendezvous: the first reports arrival (fence passed),
                // the second holds the deletion until the test releases it.
                barrier.wait();
                barrier.wait();
            }
            let out = self.run(&["network", "delete", &network_name], false)?;
            if out.exit_code != 0 {
                return Err(host_cli_error("network delete", &out));
            }
        }
        if let Some(config) = self.read_acl_config(&acl_name)? {
            let tag = config
                .get(NETWORK_SANDBOX_TAG)
                .and_then(serde_json::Value::as_str);
            if tag != Some(sandbox_id) || !self.manages(&config) {
                return Err(foreign_object("network acl", &acl_name));
            }
            fence(&config, "network acl")?;
            let out = self.run(&["network", "acl", "delete", &acl_name], false)?;
            if out.exit_code != 0 {
                return Err(host_cli_error("network acl delete", &out));
            }
        }
        // The DNS expiry lease dies with the sandbox (C36 r20 F4): retire
        // the owner and its durable records AFTER the ownership-fenced
        // resource deletions above — a stale teardown refused by those
        // fences never reaches here, so it can never stop a newer
        // incarnation's lease. The identity history is tombstoned inside
        // (before the records go) so a recreated sandbox's request
        // identities stay unique against late mutations of this one.
        self.retire_dns_expiry_lease(sandbox_id)?;
        // An owed refresh dies with the objects it was owed against (C58
        // NEW-1); the pending journal and standing fences are preserved.
        self.retire_dns_refresh_owed(sandbox_id)?;
        // B12: the build's DNS stub dies with the network (its dnsmasq,
        // the only forwarder to it, is gone).
        self.dns_stubs.release(sandbox_id);
        // The resolved-plan expansion and the DNS policy state are
        // sandbox-scoped state; they die with the network they were applied
        // for.
        let plan = self.plans_dir().join(format!("{sandbox_id}.json"));
        let plan_gone = match std::fs::remove_file(&plan) {
            Ok(()) => {
                Self::fsync_dir(&self.plans_dir());
                true
            }
            Err(err) => err.kind() == std::io::ErrorKind::NotFound,
        };
        // Preview tunnels: only once the recorded plan is confirmed gone can
        // no apply name a target, so only then may the sandbox's teardown
        // fence drop. A plan that failed to unlink keeps the fence (until a
        // new bridge is created for the sandbox); teardown itself proceeds
        // as before.
        if plan_gone {
            crate::teardown_hook::network_removed(sandbox_id);
        }
        let dns_state = self.dns_state_dir().join(format!("{sandbox_id}.json"));
        if std::fs::remove_file(&dns_state).is_ok() {
            Self::fsync_dir(&self.dns_state_dir());
        }
        // The DNS revocation marker is NEVER purged here (C36 r22 F2):
        // its pending-mutation journal and standing fence obligations are
        // the ONLY record protecting a future same-named ACL incarnation
        // from a deferred daemon-side apply of an interrupted issuance —
        // the old request may complete against the recreated ACL at any
        // time, and only the marker lets the recreate's DNS boundary
        // fence the destination before anything broadens. A clean
        // sandbox's marker is fully spent and cleared by its own commits
        // long before teardown, so this retains exactly the unresolved
        // mutations; an inert leftover marker simply fail-closes
        // readiness for that id until a create reconciles it.
        Ok(())
    }

    /// Same-attempt teardown (rollback, kill): the caller owns the sequence.
    pub(crate) fn teardown_sandbox_network(&self, sandbox_id: &str) -> Result<(), RuntimeError> {
        self.teardown_sandbox_network_inner(sandbox_id, None)
    }

    /// Create-rollback teardown (C36 r21 F4, unified with teardown by C36
    /// r22 F2): the owned resources go; the DNS revocation marker —
    /// carrying the pending-mutation journal — is PRESERVED so a retry's
    /// boundary reconciles the late daemon-side apply instead of meeting
    /// it unprotected.
    pub(crate) fn rollback_sandbox_network(&self, sandbox_id: &str) -> Result<(), RuntimeError> {
        self.teardown_sandbox_network_inner(sandbox_id, None)
    }

    /// Journal-drained teardown, fenced to the recorded incarnations.
    pub(crate) fn teardown_sandbox_network_fenced(
        &self,
        sandbox_id: &str,
        expected_attempts: &[String],
    ) -> Result<(), RuntimeError> {
        self.teardown_sandbox_network_inner(sandbox_id, Some(expected_attempts))
    }

    /// Root for persisted resolved-plan expansions (immutable reconnect reuse).
    pub(crate) fn plans_dir(&self) -> PathBuf {
        self.state_root().join("network-plans")
    }

    /// Persist the applied plan's enforcement identity: the resolved grant
    /// expansion (immutable reconnect reuse — DNS answers may rotate under
    /// an unchanged policy) AND the full rule set + gateway, so restart
    /// recovery can perform the SAME readback apply performed
    /// (`verify_sandbox_network`) instead of a weaker presence check.
    pub(crate) fn persist_resolved_plan(
        &self,
        plan: &SandboxNetworkPlan,
    ) -> Result<(), RuntimeError> {
        let grants: Vec<&str> = plan
            .grants
            .iter()
            .map(|grant| grant.text.as_str())
            .collect();
        let mut record = serde_json::json!({
            "version": PLAN_RECORD_VERSION,
            "sandbox_id": plan.sandbox_id,
            "gateway": plan.gateway.to_string(),
            "rules": plan.rules,
            "grants": grants,
            "policy_cidrs": plan.policy_cidrs,
            // The recorded policy's domain list (DNS refresh scheduler): the
            // DNS state only lists names with LIVE grants, so a denied or
            // lapsed name could never be re-resolved without it. Bound to
            // `hash` and re-verified against it before any refresh.
            "policy_domains": plan.policy_domains,
        });
        // §2.6: plans compiled with node settings record the mode, the
        // settings, the resolver base and the denied grants they were
        // compiled with; the record is their verification reference.
        {
            let settings = plan.settings.as_ref().ok_or_else(|| {
                RuntimeError::new(
                    SandboxErrorCode::Internal,
                    "cannot persist an enforcement plan without settings",
                )
            })?;
            record["mode"] = serde_json::to_value(plan.mode).map_err(|err| {
                RuntimeError::new(
                    SandboxErrorCode::Internal,
                    format!("cannot encode the egress mode: {err}"),
                )
            })?;
            record["settings"] = serde_json::to_value(settings).map_err(|err| {
                RuntimeError::new(
                    SandboxErrorCode::Internal,
                    format!("cannot encode the egress settings: {err}"),
                )
            })?;
            record["dnsmasq_base"] = serde_json::Value::String(plan.dnsmasq_base.clone());
            record["denied_grants"] = serde_json::json!(plan.denied_grants);
        }
        if let Some(hash) = &plan.policy_hash {
            record["hash"] = serde_json::Value::String(hash.clone());
        }
        let record = record.to_string();
        self.write_durable_record(
            &self.plans_dir(),
            &format!("{}.json", plan.sandbox_id),
            &record,
        )
    }

    /// B12 restart recovery: every recorded allowlist plan with a DNS stub
    /// port, with its granted names (bounded scan of the plan records).
    pub(crate) fn recorded_dns_stubs(&self) -> Vec<super::dns_stub::RecordedStub> {
        let Ok(entries) = std::fs::read_dir(self.plans_dir()) else {
            return Vec::new();
        };
        entries
            .flatten()
            .take(4096)
            .filter_map(|entry| {
                let name = entry.file_name();
                let sandbox_id = name.to_str()?.strip_suffix(".json")?.to_string();
                let plan = self.persisted_enforcement_plan(&sandbox_id)?;
                let port = plan.settings.as_ref()?.refused_dns_stub_port?;
                if plan.mode != sandbox_protocol::EgressMode::Allowlist {
                    return None;
                }
                // The plan reader leaves `policy_domains` empty (it is the
                // refresh scheduler's hash-bound field), so the granted
                // names come straight from the record: a stub re-bound
                // with none would report every granted lookup as refused.
                let granted = self
                    .recorded_policy_domains(&sandbox_id)
                    .iter()
                    .map(|domain| domain.to_ascii_lowercase())
                    .collect();
                Some(super::dns_stub::RecordedStub {
                    sandbox_id,
                    port,
                    granted,
                })
            })
            .collect()
    }

    /// The recorded policy's domain list (`policy_domains`), or none when
    /// the record is absent, foreign, malformed, or predates the field.
    fn recorded_policy_domains(&self, sandbox_id: &str) -> Vec<String> {
        let record = self.plans_dir().join(format!("{sandbox_id}.json"));
        let Ok(body) = std::fs::read_to_string(record) else {
            return Vec::new();
        };
        let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body) else {
            return Vec::new();
        };
        if parsed.get("sandbox_id").and_then(serde_json::Value::as_str) != Some(sandbox_id) {
            return Vec::new();
        }
        parsed
            .get("policy_domains")
            .and_then(serde_json::Value::as_array)
            .map(|domains| {
                domains
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The persisted enforcement identity for recovery readback. Absent or
    /// malformed → `None`, and recovery must fail CLOSED (unverifiable
    /// enforcement is unenforced).
    pub(crate) fn persisted_enforcement_plan(
        &self,
        sandbox_id: &str,
    ) -> Option<SandboxNetworkPlan> {
        self.persisted_enforcement_plan_checked(sandbox_id)
            .ok()
            .flatten()
    }

    /// Fallible plan read for the observation boundary (C37 R5): an
    /// unreadable or unparseable plan record is unavailable EVIDENCE —
    /// the caller must classify it as inconclusive, never as plan absence
    /// (which IS drift evidence). Only a cleanly absent record, or one
    /// positively recorded for a DIFFERENT sandbox, reads as `None`.
    pub(crate) fn persisted_enforcement_plan_checked(
        &self,
        sandbox_id: &str,
    ) -> Result<Option<SandboxNetworkPlan>, RuntimeError> {
        fn unreadable(sandbox_id: &str, err: impl std::fmt::Display) -> RuntimeError {
            RuntimeError::new(
                SandboxErrorCode::Internal,
                format!("cannot read the persisted enforcement plan for `{sandbox_id}`: {err}"),
            )
        }
        let record = self.plans_dir().join(format!("{sandbox_id}.json"));
        let body = match std::fs::read_to_string(&record) {
            Ok(body) => body,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(unreadable(sandbox_id, err)),
        };
        let parsed: serde_json::Value =
            serde_json::from_str(&body).map_err(|err| unreadable(sandbox_id, err))?;
        // C37 R7: shape-validate the WHOLE record BEFORE the identity
        // comparison. A valid-JSON but structurally malformed record —
        // `{}`, `null`, `{"sandbox_id":42}`, a missing `rules` array, a
        // non-CIDR grant — is unavailable EVIDENCE (inconclusive), never
        // positive proof of a FOREIGN plan: reading `{}` as "no plan for
        // this sandbox" manufactured confirmed drift out of a partial or
        // corrupted write, and the drain then deleted a healthy VM. Only
        // a WELL-FORMED record positively recorded for a DIFFERENT
        // sandbox reads as `None`.
        let recorded_id = parsed
            .get("sandbox_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| unreadable(sandbox_id, "missing or non-string sandbox_id"))?;
        let gateway: std::net::Ipv4Addr = parsed
            .get("gateway")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| unreadable(sandbox_id, "missing gateway"))
            .and_then(|raw| raw.parse().map_err(|err| unreadable(sandbox_id, err)))?;
        let rules: Vec<super::network::AclRule> = parsed
            .get("rules")
            .cloned()
            .ok_or_else(|| unreadable(sandbox_id, "missing rules"))
            .and_then(|raw| {
                serde_json::from_value(raw).map_err(|err| unreadable(sandbox_id, err))
            })?;
        // `grants` and `policy_cidrs` are mandatory string arrays (the
        // writer always emits them, possibly empty); every grant string
        // must parse as a CIDR.
        let string_array = |key: &str| -> Result<Vec<String>, RuntimeError> {
            parsed
                .get(key)
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| unreadable(sandbox_id, format!("missing or non-array {key}")))?
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_string)
                        .ok_or_else(|| unreadable(sandbox_id, format!("non-string {key} entry")))
                })
                .collect()
        };
        let grants: Vec<super::network::GrantCidr> = string_array("grants")?
            .iter()
            .map(|text| {
                super::network::parse_policy_cidr(text).map_err(|err| unreadable(sandbox_id, err))
            })
            .collect::<Result<_, _>>()?;
        let policy_cidrs: Vec<String> = string_array("policy_cidrs")?;
        record_version(&parsed).map_err(|err| unreadable(sandbox_id, err))?;
        let (mode, settings, dnsmasq_base, denied_grants) = match parsed.get("settings") {
            None => return Err(unreadable(sandbox_id, "missing settings")),
            Some(raw) => {
                let settings: crate::egress::EgressSettings =
                    serde_json::from_value(raw.clone())
                        .map_err(|err| unreadable(sandbox_id, err))?;
                settings
                    .validate()
                    .map_err(|err| unreadable(sandbox_id, err))?;
                let mode: sandbox_protocol::EgressMode = parsed
                    .get("mode")
                    .cloned()
                    .ok_or_else(|| unreadable(sandbox_id, "missing mode"))
                    .and_then(|raw| {
                        serde_json::from_value(raw).map_err(|err| unreadable(sandbox_id, err))
                    })?;
                let dnsmasq_base = parsed
                    .get("dnsmasq_base")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| unreadable(sandbox_id, "missing dnsmasq_base"))?
                    .to_string();
                let denied_grants = string_array("denied_grants")?;
                (mode, Some(settings), dnsmasq_base, denied_grants)
            }
        };
        if recorded_id != sandbox_id {
            // Shape-valid and positively recorded for a DIFFERENT sandbox:
            // that is the only `None` that means "no plan of ours here".
            return Ok(None);
        }
        let (network_name, acl_name) = sandbox_network_names(sandbox_id);
        Ok(Some(SandboxNetworkPlan {
            sandbox_id: sandbox_id.to_string(),
            binding: None,
            network_name,
            acl_name,
            gateway,
            grants,
            rules,
            policy_hash: None,
            policy_domains: Vec::new(),
            policy_cidrs,
            resolved_domains: Vec::new(),
            mode,
            settings,
            dnsmasq_base,
            denied_grants,
        }))
    }

    /// The policy hash RECORDED for this sandbox (`network-plans/<id>.json`),
    /// if a well-formed record exists: `Some(Some(hash))` with a policy,
    /// `Some(None)` without one, `None` when no record exists (or it is
    /// malformed/foreign). Refresh fences the supplied policy against this
    /// binding before resolving or mutating.
    pub(crate) fn recorded_policy_hash(&self, sandbox_id: &str) -> Option<Option<String>> {
        self.persisted_enforcement_plan_checked(sandbox_id).ok()??;
        let record = self.plans_dir().join(format!("{sandbox_id}.json"));
        let body = std::fs::read_to_string(record).ok()?;
        let parsed: serde_json::Value = serde_json::from_str(&body).ok()?;
        if parsed.get("sandbox_id").and_then(serde_json::Value::as_str) != Some(sandbox_id) {
            return None;
        }
        Some(
            parsed
                .get("hash")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
        )
    }

    /// The recorded DOMAIN policy the DNS refresh scheduler re-resolves:
    /// `(policy, hash)` from `network-plans/<id>.json` when the record is
    /// well-formed, ours, carries a policy hash AND at least one domain, and
    /// the domains/CIDRs hash to that recorded hash. Anything else — no
    /// record, a domain-free policy, a record predating `policy_domains`, a
    /// malformed or mismatched record — is `None`: nothing is refreshed and
    /// any live grant lapses at its armed expiry (fail closed).
    pub(crate) fn recorded_refresh_policy(
        &self,
        sandbox_id: &str,
    ) -> Option<(sandbox_protocol::EgressPolicy, String)> {
        self.persisted_enforcement_plan_checked(sandbox_id).ok()??;
        let record = self.plans_dir().join(format!("{sandbox_id}.json"));
        let body = std::fs::read_to_string(record).ok()?;
        let parsed: serde_json::Value = serde_json::from_str(&body).ok()?;
        if parsed.get("sandbox_id").and_then(serde_json::Value::as_str) != Some(sandbox_id) {
            return None;
        }
        let hash = parsed.get("hash")?.as_str()?.to_owned();
        let strings = |key: &str| -> Option<Vec<String>> {
            parsed
                .get(key)?
                .as_array()?
                .iter()
                .map(|value| value.as_str().map(str::to_owned))
                .collect()
        };
        let mode = serde_json::from_value(parsed.get("mode")?.clone()).ok()?;
        let policy = sandbox_protocol::EgressPolicy {
            mode,
            domains: strings("policy_domains")?,
            cidrs: strings("policy_cidrs")?,
        };
        // Open mode carries no domains: the refresh scheduler does nothing.
        if policy.domains.is_empty() || mode != sandbox_protocol::EgressMode::Allowlist {
            return None;
        }
        super::network::verify_policy_presence_and_hash(Some(&policy), Some(&hash)).ok()?;
        Some((policy, hash))
    }

    /// The persisted resolved grant expansion for this exact recorded policy
    /// hash, if any. A hash mismatch (a different policy) never reuses.
    pub(crate) fn persisted_plan_grants(
        &self,
        sandbox_id: &str,
        hash: &str,
    ) -> Option<Vec<String>> {
        self.persisted_enforcement_plan_checked(sandbox_id).ok()??;
        let record = self.plans_dir().join(format!("{sandbox_id}.json"));
        let body = std::fs::read_to_string(record).ok()?;
        let parsed: serde_json::Value = serde_json::from_str(&body).ok()?;
        if parsed.get("hash").and_then(serde_json::Value::as_str) != Some(hash) {
            return None;
        }
        let grants = parsed
            .get("grants")?
            .as_array()?
            .iter()
            .map(|grant| grant.as_str().map(str::to_owned))
            .collect::<Option<Vec<String>>>()?;
        Some(grants)
    }

    /// The persisted RULE SET for this exact recorded policy hash, if any.
    /// Reconnect reuses it verbatim (immutable re-apply): rule identity —
    /// including the per-domain `wssp-dns-*` tags the C36 refresh diffs by —
    /// is preserved exactly as applied, never recompiled from the flat
    /// expansion (which could not reproduce it).
    pub(crate) fn persisted_plan_rules(
        &self,
        sandbox_id: &str,
        hash: &str,
    ) -> Option<Vec<AclRule>> {
        self.persisted_enforcement_plan_checked(sandbox_id).ok()??;
        let record = self.plans_dir().join(format!("{sandbox_id}.json"));
        let body = std::fs::read_to_string(record).ok()?;
        let parsed: serde_json::Value = serde_json::from_str(&body).ok()?;
        if parsed.get("hash").and_then(serde_json::Value::as_str) != Some(hash) {
            return None;
        }
        serde_json::from_value(parsed.get("rules")?.clone()).ok()
    }

    /// Persist the rule set AS INSTALLED by a committed DNS refresh
    /// (observed order, read back from the daemon) for this exact recorded
    /// policy hash: the reconnect path's verbatim reuse must see the SAME
    /// rules in the SAME order — refresh retains unchanged rules in place
    /// and appends new ones, so recomputing an order here would diverge
    /// from the live ACL and fail the positional reconnect readback closed
    /// (IdempotencyConflict) against a correctly refreshed ACL. Absent
    /// record or hash mismatch → nothing to update (reconnect would not
    /// reuse it anyway).
    pub(crate) fn update_persisted_plan_rules(
        &self,
        sandbox_id: &str,
        hash: &str,
        installed_rules: &[AclRule],
    ) -> Result<(), RuntimeError> {
        if self
            .persisted_enforcement_plan_checked(sandbox_id)?
            .is_none()
        {
            return Ok(());
        }
        let record = self.plans_dir().join(format!("{sandbox_id}.json"));
        let Ok(body) = std::fs::read_to_string(&record) else {
            return Ok(());
        };
        let Ok(mut parsed) = serde_json::from_str::<serde_json::Value>(&body) else {
            return Ok(());
        };
        if parsed.get("hash").and_then(serde_json::Value::as_str) != Some(hash) {
            return Ok(());
        }
        parsed["rules"] = serde_json::to_value(installed_rules).map_err(|err| {
            RuntimeError::new(
                SandboxErrorCode::Internal,
                format!("cannot encode the refreshed network plan rules: {err}"),
            )
        })?;
        // DNS-P2-4: the flat `grants` expansion (immutable reconnect reuse)
        // is rewritten in the SAME write, from the same truth: the static
        // policy CIDRs plus every destination an installed domain allow
        // grants — exactly what a fresh compilation would expand to. A
        // rotation or settlement used to leave the create-time answers
        // here. Static texts are normalized exactly as compilation does;
        // an unreadable `policy_cidrs` keeps the old field rather than
        // inventing one (the record stays as consistent as it was).
        if let Some(policy_cidrs) = parsed
            .get("policy_cidrs")
            .and_then(serde_json::Value::as_array)
            .and_then(|cidrs| {
                cidrs
                    .iter()
                    .map(|cidr| {
                        cidr.as_str()
                            .and_then(|raw| super::network::parse_policy_cidr(raw).ok())
                            .map(|cidr| cidr.text)
                    })
                    .collect::<Option<Vec<String>>>()
            })
        {
            let mut grants: Vec<String> = policy_cidrs
                .into_iter()
                .chain(
                    installed_rules
                        .iter()
                        .filter(|rule| {
                            rule.direction == AclDirection::Egress
                                && rule.action == super::network::AclAction::Allow
                                && super::network::is_dns_dynamic_tag(&rule.description)
                        })
                        .filter_map(|rule| rule.destination.clone()),
                )
                .collect();
            grants.sort();
            grants.dedup();
            parsed["grants"] = serde_json::json!(grants);
        }
        self.write_durable_record(
            &self.plans_dir(),
            &format!("{sandbox_id}.json"),
            &parsed.to_string(),
        )
    }

    /// Host preflight before any VM creation: the default profile must carry a
    /// root disk and at most a single NIC named `eth0` (which init overrides
    /// onto the sandbox bridge). Anything else — proxy devices, forwards,
    /// extra NICs, host mounts, passthrough devices — is refused.
    pub(crate) fn verify_launch_profile_safety(
        &self,
        vm_size: sandbox_protocol::VmSize,
    ) -> Result<(), RuntimeError> {
        self.profile_root_device(vm_size).map(|_| ())
    }

    /// Read-only, audited default root selection; explicit pools may override
    /// its pool without probing that profile pool's availability.
    pub fn profile_root_device(
        &self,
        vm_size: sandbox_protocol::VmSize,
    ) -> Result<(String, String), RuntimeError> {
        let out = self.run(&["profile", "list", "--format", "json"], false)?;
        if out.exit_code != 0 {
            return Err(host_cli_error("profile list", &out));
        }
        let profiles: Vec<serde_json::Value> =
            serde_json::from_str(&out.stdout).map_err(|err| {
                RuntimeError::new(
                    SandboxErrorCode::Internal,
                    format!("invalid default profile: {err}"),
                )
            })?;
        let devices = profiles
            .iter()
            .find(|profile| profile.get("name").and_then(|v| v.as_str()) == Some("default"))
            .and_then(|profile| profile.get("devices"))
            .and_then(serde_json::Value::as_object);
        let unsafe_profile = || {
            RuntimeError::new(
                SandboxErrorCode::Internal,
                "incus default profile is unsafe for sandbox launches: only a root disk and a single eth0 NIC are allowed (no proxy devices, forwards, host mounts or extra NICs)",
            )
        };
        let Some(devices) = devices else {
            return Err(unsafe_profile());
        };
        // C37: profile config admits only the two exact allocation keys,
        // whose values must match the request. All other keys (including
        // limits.* siblings) are refused before any host mutation.
        let config_keys = profiles
            .iter()
            .find(|profile| profile.get("name").and_then(|v| v.as_str()) == Some("default"))
            .and_then(|profile| profile.get("config"))
            .and_then(serde_json::Value::as_object);
        if let Some(config) = config_keys
            && let Some(key) = config
                .keys()
                .find(|key| key.as_str() != "limits.cpu" && key.as_str() != "limits.memory")
        {
            return Err(RuntimeError::new(
                SandboxErrorCode::Internal,
                format!(
                    "incus default profile is unsafe for sandbox launches: it carries config key `{key}` (the launch pins its own config; a profile key can only be an override)"
                ),
            ));
        }
        if let Some(config) = config_keys {
            crate::resources::verify_vm_size(config, vm_size, true)?;
        }
        let mut root = None;
        for (name, device) in devices {
            let device_type = device.get("type").and_then(serde_json::Value::as_str);
            match device_type {
                Some("disk") => {
                    let is_root = device.get("path").and_then(serde_json::Value::as_str)
                        == Some("/")
                        && device
                            .get("pool")
                            .and_then(serde_json::Value::as_str)
                            .is_some_and(|pool| !pool.is_empty());
                    if !is_root || root.is_some() {
                        return Err(unsafe_profile());
                    }
                    super::storage::validate_root_keys(device).map_err(|_| unsafe_profile())?;
                    root = Some((
                        name.clone(),
                        device
                            .get("pool")
                            .and_then(serde_json::Value::as_str)
                            .ok_or_else(unsafe_profile)?
                            .to_string(),
                    ));
                }
                Some("nic") => {
                    if name != "eth0" {
                        return Err(unsafe_profile());
                    }
                }
                _ => return Err(unsafe_profile()),
            }
        }
        root.ok_or_else(unsafe_profile)
    }
}

/// The sole plan record version this daemon writes and accepts.
pub(crate) const PLAN_RECORD_VERSION: u64 = 2;

/// Refuse missing and unsupported versions before interpreting a plan.
pub(crate) fn record_version(record: &serde_json::Value) -> Result<u64, String> {
    match record.get("version") {
        None => Err("missing plan record version".into()),
        Some(raw) => match raw.as_u64() {
            Some(PLAN_RECORD_VERSION) => Ok(PLAN_RECORD_VERSION),
            _ => Err(format!("unknown plan record version {raw}")),
        },
    }
}

#[cfg(test)]
mod plan_record_tests {
    use super::record_version;

    #[test]
    fn only_known_plan_record_versions_are_readable() {
        assert!(record_version(&serde_json::json!({})).is_err());
        assert!(record_version(&serde_json::json!({ "version": 1 })).is_err());
        assert_eq!(record_version(&serde_json::json!({ "version": 2 })), Ok(2));
        assert!(record_version(&serde_json::json!({ "version": 0 })).is_err());
        assert!(record_version(&serde_json::json!({ "version": 3 })).is_err());
        assert!(record_version(&serde_json::json!({ "version": "2" })).is_err());
    }
}

#[cfg(test)]
mod host_readiness_tests {
    use super::{EgressSupport, IncusClient, server_egress_support};
    use sandbox_protocol::SandboxErrorCode;

    #[test]
    fn acl_etag_matches_incus_go_encoding_including_null_and_html_escaping() {
        // Incus common.Etag is [name, description, ingress, egress, config];
        // util.EtagHash uses encoding/json Encoder.Encode (including newline).
        let metadata = serde_json::json!({
            "name":"wssp-acl-test", "description":"line\u{2028}end", "ingress":null,
            "egress":[{"state":"enabled","description":"<grant>&", "action":"allow",
                "source":"", "destination":"128.66.0.7/32", "protocol":"tcp", "destination_port":"443"}],
            "config":{"z":"last", "a":"<value>&"}
        });
        assert_eq!(
            super::acl_etag(&metadata).unwrap(),
            "3d3fab075bcd771e642868185730abfb48d5a6b93fa70b2ed81704bfd52921f6"
        );
        let mut empty = metadata.clone();
        empty["ingress"] = serde_json::json!([]);
        assert_ne!(
            super::acl_etag(&empty).unwrap(),
            super::acl_etag(&metadata).unwrap()
        );
        empty["egress"][0].as_object_mut().unwrap().remove("state");
        assert!(
            super::acl_etag(&empty).is_err(),
            "unreadable state fails closed"
        );
    }

    fn daemon(version: Option<&str>, acl: bool) -> serde_json::Value {
        let extensions: Vec<&str> = if acl { vec!["network_acl"] } else { vec![] };
        match version {
            Some(version) => serde_json::json!({
                "api_extensions": extensions,
                "environment": { "server_version": version },
            }),
            None => serde_json::json!({ "api_extensions": extensions, "environment": {} }),
        }
    }

    /// E-06: the gate itself is unchanged (6.14 floor, fail closed); the
    /// verdict now also says WHY, with the detected version.
    #[test]
    fn egress_verdict_keeps_the_6_14_floor_and_names_the_detected_version() {
        for version in ["6.14", "6.14.0", "6.15", "7.0", "6.14-rc1"] {
            assert_eq!(
                server_egress_support(&daemon(Some(version), true)),
                EgressSupport::Supported,
                "{version}"
            );
            assert_eq!(
                server_egress_support(&daemon(Some(version), true)).unavailable_reason(),
                None
            );
        }
        for version in ["6.0.0", "6.0.5", "6.12", "6.13.1", "5.21.2", "6"] {
            let verdict = server_egress_support(&daemon(Some(version), true));
            assert_eq!(
                verdict,
                EgressSupport::VersionTooOld(version.to_string()),
                "{version}"
            );
            let reason = verdict.unavailable_reason().expect("reason");
            assert!(
                reason.starts_with(&format!("incus {version} is older than 6.14"))
                    && reason.contains("CVE-2025-52890"),
                "{reason}"
            );
        }
        assert_eq!(
            server_egress_support(&daemon(Some("6.14"), false)),
            EgressSupport::MissingAclExtension
        );
        assert!(
            EgressSupport::MissingAclExtension
                .unavailable_reason()
                .is_some_and(|r| r.contains("network_acl"))
        );
        for metadata in [daemon(None, true), daemon(Some("devel"), true)] {
            assert_eq!(
                server_egress_support(&metadata),
                EgressSupport::VersionUnknown
            );
        }
    }

    /// Daemon-supplied version text is reduced and bounded before it reaches
    /// operator copy.
    #[test]
    fn reported_version_text_is_sanitized_and_bounded() {
        let hostile = format!("6.0\n`rm -rf`{}", "9".repeat(200));
        let EgressSupport::VersionTooOld(shown) =
            server_egress_support(&daemon(Some(&hostile), true))
        else {
            panic!("an old version");
        };
        assert!(shown.len() <= 32, "{shown}");
        assert!(
            shown
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || ".-+~".contains(c))
        );
    }

    /// E-11 preflight: present bridge netfilter with the ip6tables sysctl
    /// at 1 passes; a missing one (or a non-directory), or the sysctl off
    /// (HR-R2), refuses with the exact operator commands.
    #[test]
    fn bridge_netfilter_preflight_passes_only_when_the_proc_dir_exists() {
        let dir = std::env::temp_dir().join(format!(
            "wssp-br-netfilter-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("bridge")).unwrap();
        std::fs::write(dir.join("file"), "").unwrap();
        // HR-R2: the module alone is not enough; the ip6tables sysctl must
        // read 1 (absent, 0 or garbage refuses with the sysctl command).
        let sysctl = dir.join("bridge/bridge-nf-call-ip6tables");
        for value in [None, Some("0\n"), Some(""), Some("10\n")] {
            if let Some(value) = value {
                std::fs::write(&sysctl, value).unwrap();
            }
            let err = IncusClient::preflight_bridge_netfilter(&dir.join("bridge"))
                .expect_err("ip6tables sysctl off");
            assert_eq!(err.code, SandboxErrorCode::HostRuntimeUnsupported);
            for needle in [
                "`sudo sysctl -w net.bridge.bridge-nf-call-ip6tables=1`",
                "/etc/sysctl.d/90-wssp-bridge-nf.conf",
                "security.ipv6_filtering",
                &sysctl.display().to_string(),
            ] {
                assert!(err.message.contains(needle), "{needle}: {}", err.message);
            }
        }
        std::fs::write(&sysctl, "1\n").unwrap();
        IncusClient::preflight_bridge_netfilter(&dir.join("bridge")).expect("loaded");
        for missing in [dir.join("absent"), dir.join("file")] {
            let err = IncusClient::preflight_bridge_netfilter(&missing).expect_err("missing");
            assert_eq!(err.code, SandboxErrorCode::HostRuntimeUnsupported);
            for needle in [
                "`sudo modprobe br_netfilter`",
                "`echo br_netfilter | sudo tee /etc/modules-load.d/wssp-br_netfilter.conf`",
                "security.ipv6_filtering",
                &missing.display().to_string(),
            ] {
                assert!(err.message.contains(needle), "{needle}: {}", err.message);
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(IncusClient::BRIDGE_NETFILTER_PROC, "/proc/sys/net/bridge");
    }
}

#[cfg(test)]
mod persisted_state_tests {
    use super::*;

    #[test]
    fn provisioning_writer_requires_a_binding_and_emits_readable_records() {
        let (client, log) = crate::incus::shim_tests::client_for_with_log("fix6_new_ready");
        client
            .persist_provisioning_intent("sbx-1", "attempt-1", None)
            .expect_err("an unbound provisioning intent is rejected before IO");
        assert!(!client.pending_cleanup_dir().join("sbx-1.json").exists());
        assert!(std::fs::read_to_string(log).unwrap_or_default().is_empty());

        let binding = super::super::network::test_plan("sbx-1").binding.unwrap();
        client
            .persist_provisioning_intent("sbx-1", "attempt-1", Some(&binding))
            .expect("a bound intent is persisted");
        let record = client.read_pending_cleanup("sbx-1").unwrap().unwrap();
        assert!(matches!(record.phase, CleanupPhase::Provisioning));
        assert_eq!(record.attempts, ["attempt-1"]);
        let recorded = record.binding.expect("the binding survives persistence");
        assert_eq!(recorded.template_fingerprint, binding.template_fingerprint);
        assert_eq!(recorded.create_key, binding.create_key);
    }

    struct TestRoot(std::path::PathBuf);
    impl TestRoot {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "wssp-state-test-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }
    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn client(root: &std::path::Path) -> IncusClient {
        let mut client = IncusClient::new("unused-incus-test-binary", "default");
        client.set_host_state_dir(root);
        client
    }

    #[test]
    fn incomplete_cleanup_records_never_authorize_mutations_or_default_project_ownership() {
        let root = TestRoot::new();
        let client = client(root.path());
        std::fs::create_dir_all(client.pending_cleanup_dir()).unwrap();
        let current = serde_json::json!({"sandbox_id":"sbx-1", "phase":"teardown",
            "project":"default", "attempts":["attempt-1"], "binding":null});
        let path = client.pending_cleanup_dir().join("sbx-1.json");
        std::fs::write(&path, current.to_string()).unwrap();
        assert!(client.read_pending_cleanup("sbx-1").unwrap().is_some());
        for field in ["phase", "project", "attempts"] {
            let mut incomplete = current.clone();
            incomplete.as_object_mut().unwrap().remove(field);
            std::fs::write(&path, incomplete.to_string()).unwrap();
            assert!(client.read_pending_cleanup("sbx-1").is_err(), "{field}");
            assert!(client.clear_pending_cleanup("sbx-1").is_err(), "{field}");
            assert!(path.exists());
        }
        let untagged = serde_json::Map::new();
        assert!(!client.manages(&untagged));
    }

    #[test]
    fn incomplete_enforcement_records_never_default_to_open_or_allowlist() {
        let root = TestRoot::new();
        let client = client(root.path());
        std::fs::create_dir_all(client.plans_dir()).unwrap();
        let current = serde_json::json!({"version":PLAN_RECORD_VERSION, "sandbox_id":"sbx-1",
            "gateway":"10.100.0.1", "rules":[], "grants":[], "policy_cidrs":[],
            "mode":"open", "settings":crate::egress::EgressSettings::default(),
            "dnsmasq_base":"", "denied_grants":[]});
        let path = client.plans_dir().join("sbx-1.json");
        std::fs::write(&path, current.to_string()).unwrap();
        assert_eq!(
            client.recorded_egress_mode("sbx-1").unwrap(),
            sandbox_protocol::EgressMode::Open
        );
        for field in [
            "version",
            "settings",
            "mode",
            "dnsmasq_base",
            "denied_grants",
        ] {
            let mut incomplete = current.clone();
            incomplete.as_object_mut().unwrap().remove(field);
            std::fs::write(&path, incomplete.to_string()).unwrap();
            assert!(
                client.persisted_enforcement_plan_checked("sbx-1").is_err(),
                "{field}"
            );
            assert!(client.recorded_egress_mode("sbx-1").is_err(), "{field}");
            assert!(client.recorded_policy_hash("sbx-1").is_none(), "{field}");
            assert!(
                client.persisted_plan_rules("sbx-1", "hash").is_none(),
                "{field}"
            );
            assert!(
                client.persisted_plan_grants("sbx-1", "hash").is_none(),
                "{field}"
            );
            assert!(
                client
                    .update_persisted_plan_rules("sbx-1", "hash", &[])
                    .is_err(),
                "{field}"
            );
        }
        let historical = serde_json::json!({"sandbox_id":"sbx-1", "gateway":"10.100.0.1",
            "rules":[], "grants":[], "policy_cidrs":[]});
        std::fs::write(&path, historical.to_string()).unwrap();
        assert!(client.persisted_enforcement_plan_checked("sbx-1").is_err());
    }
}
