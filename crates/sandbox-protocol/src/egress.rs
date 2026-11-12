//! Sandbox egress wire types: the recorded policy carried on VM launches, the
//! hello capability, and the live `host.egress-state` report.
//!
//! The allowlist policy omits `mode`; open egress uses an explicit mode
//! and requires the runtime's `egress.open` capability. Server placement and
//! dispatch enforce that capability. Shared contract cases live in
//! `fixtures/egress_policy_cases.json` and `fixtures/control_host_egress_state.json`,
//! read by both this crate and `@wssp/sandbox-contracts`.

use serde::{Deserialize, Deserializer, Serialize};

/// Egress mode of a recorded policy. `Allowlist` is the default and is never
/// written on the wire; `Open` is written as `"mode":"open"`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressMode {
    Open,
    #[default]
    Allowlist,
}

impl EgressMode {
    pub fn is_allowlist(&self) -> bool {
        matches!(self, Self::Allowlist)
    }
}

/// An optional field that, when present, must carry a value: `null` is
/// refused (absent is the only spelling of "none"), matching zod `.optional()`.
pub(crate) fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// Only `"open"` may appear on the wire: an explicit `"allowlist"` is a
/// second spelling of the default and is refused, like the TypeScript
/// `egressPolicyFromWire`.
fn deserialize_wire_mode<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<EgressMode, D::Error> {
    match EgressMode::deserialize(deserializer)? {
        EgressMode::Open => Ok(EgressMode::Open),
        EgressMode::Allowlist => Err(serde::de::Error::custom(
            "egress mode \"allowlist\" is implied by omission and must not be sent",
        )),
    }
}

/// Server-normalized egress policy carried on VM-launch dispatches. In open
/// mode `domains`/`cidrs` are fallback grants recorded with the request; the
/// effective open policy the server dispatches has none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EgressPolicy {
    #[serde(
        default,
        skip_serializing_if = "EgressMode::is_allowlist",
        deserialize_with = "deserialize_wire_mode"
    )]
    pub mode: EgressMode,
    pub domains: Vec<String>,
    pub cidrs: Vec<String>,
}

impl EgressPolicy {
    /// Canonical JSON text identical to `canonicalEgressPolicyJson` in
    /// `@wssp/sandbox-contracts`: `{"cidrs":[…],"domains":[…]}` (both
    /// sorted) for allowlist, plus `"mode":"open"` last for open. The
    /// recorded policy hash is SHA-256 of exactly this text. Policy strings
    /// are ASCII without characters serde_json and JSON.stringify escape
    /// differently.
    pub fn canonical_json(&self) -> String {
        let mut cidrs = self.cidrs.clone();
        let mut domains = self.domains.clone();
        cidrs.sort();
        domains.sort();
        #[derive(Serialize)]
        struct Canonical<'a> {
            cidrs: Vec<String>,
            domains: Vec<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            mode: Option<&'a str>,
        }
        let mode = (self.mode == EgressMode::Open).then_some("open");
        serde_json::to_string(&Canonical {
            cidrs,
            domains,
            mode,
        })
        .unwrap_or_default()
    }
}

/// Hello capability (`daemon.capabilities.egress`), required in every hello:
/// whether this daemon run can offer open egress and has a healthy guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EgressCapabilitiesV11 {
    /// Static per daemon run: the guard was healthy at startup and the host
    /// resolver probe works, so open-mode policies can be enforced.
    pub open: bool,
    /// The egress guard's health at hello time (the live, leased value
    /// travels in `host.egress-state`).
    pub guard: bool,
}

/// Bounded machine token: guard reasons are codes, never free text.
pub const EGRESS_GUARD_REASON_MAX_LEN: usize = 64;
/// Guard process instance ids are opaque `[A-Za-z0-9_-]` tokens.
pub const EGRESS_GUARD_INSTANCE_ID_MAX_LEN: usize = 64;
const SAFE_INTEGER_MAX: u64 = 9_007_199_254_740_991;

pub fn valid_egress_guard_reason(reason: &str) -> bool {
    !reason.is_empty()
        && reason.len() <= EGRESS_GUARD_REASON_MAX_LEN
        && reason
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

pub fn valid_egress_guard_instance_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= EGRESS_GUARD_INSTANCE_ID_MAX_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Current-link egress report (`host.egress-state`), sent every 5 s and on
/// any change. It is a lease renewal: the server sets its guard lease from
/// its own clock on each valid `guard_ok=true` report. Fenced like
/// `HostLeasePolicyV11` (current socket, epoch, monotonic sequence) plus the
/// guard instance and generation, so a report from an older guard process or
/// generation is ignored.
///
/// Shape rules (`is_valid`): `guard_ok` ⇔ no `guard_reason`; a healthy guard
/// always names its instance and generation; the instance and generation are
/// present together or not at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostEgressStateV11 {
    pub connection_epoch: u32,
    pub sequence: u64,
    /// Live node-owner consent: other users' sandboxes may get open egress.
    pub allow_open_for_others: bool,
    /// Live node-owner consent for guest sudo on other users' sandboxes.
    pub allow_guest_sudo_for_others: bool,
    pub guard_ok: bool,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub guard_reason: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub guard_instance_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub guard_generation: Option<u64>,
}

impl HostEgressStateV11 {
    pub fn is_valid(&self) -> bool {
        self.connection_epoch > 0
            && self.connection_epoch <= i32::MAX as u32
            && self.sequence > 0
            && self.sequence <= SAFE_INTEGER_MAX
            && self.guard_ok == self.guard_reason.is_none()
            && self
                .guard_reason
                .as_deref()
                .is_none_or(valid_egress_guard_reason)
            && self.guard_instance_id.is_some() == self.guard_generation.is_some()
            && (!self.guard_ok || self.guard_instance_id.is_some())
            && self
                .guard_instance_id
                .as_deref()
                .is_none_or(valid_egress_guard_instance_id)
            && self
                .guard_generation
                .is_none_or(|g| g > 0 && g <= SAFE_INTEGER_MAX)
    }
}

/// Typed node-policy refusal reasons on the wire (`details.reason` of an
/// `unsupported_capability` error, default-open egress §1.5 and guest sudo
/// consent). Mirrors `egressRefusalReasonSchema` in `@wssp/sandbox-contracts`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressRefusalReason {
    /// An open-mode sandbox on a node whose owner does not allow open egress
    /// for other users' sandboxes. Terminal for the sandbox.
    OpenEgressNotPermitted,
    /// The node's egress guard is missing, unhealthy or not covering the
    /// sandbox. Retryable once the guard runs again.
    EgressGuardUnavailable,
    /// A `guestSudo` sandbox on a node whose owner does not allow guest sudo
    /// for other users' sandboxes (`allow_guest_sudo_for_others = false`).
    /// Terminal for the sandbox on this node.
    GuestSudoNotPermitted,
}

/// Most entries one `egress.blocklist` may carry: the guard's per-source
/// limits (4096 CIDRs plus 2048 domains). The frame limit binds first.
pub const EGRESS_BLOCKLIST_MAX_ENTRIES: usize = 4096 + 2048;
/// One entry: a canonical IPv4 CIDR or a lowercase DNS name.
pub const EGRESS_BLOCKLIST_ENTRY_MAX_LEN: usize = 253;

/// Deployment-wide egress blocklist (`egress.blocklist`, E6), sent by the
/// server after `hello.ok` to daemons that advertise the egress capability.
/// The daemon relays it to the guard as the `deployment` source (§2.0.4).
///
/// - `configured:false` with no entries clears the source explicitly
///   (`not_configured`); `configured:true` carries ≥ 1 entry unless
///   `invalid`.
/// - Entries are the server-normalized list: canonical `a.b.c.d/p` CIDRs and
///   lowercase domains, sorted and unique, charset `[0-9a-z./-]`. The guard
///   is the authoritative parser; an entry it refuses rejects the whole push
///   and keeps the last valid list (M13).
/// - `digest` is `sha256:<hex>` of the JSON array text of `entries`
///   (`JSON.stringify(entries)`); the daemon recomputes it and ignores a
///   frame whose digest does not match.
///
/// A server whose configured list is invalid sends `invalid:true` with
/// `configured:true` and no entries (M13): it never becomes an empty list.
/// The daemon keeps the last list the server gave it; a daemon that never had
/// one refuses new sandboxes until a valid list (or `configured:false`)
/// arrives. `invalid` is omitted when false.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EgressBlocklistV11 {
    pub configured: bool,
    pub entries: Vec<String>,
    pub digest: String,
    #[serde(
        default,
        skip_serializing_if = "std::ops::Not::not",
        deserialize_with = "true_only"
    )]
    pub invalid: bool,
}

/// `invalid` is written only as `true`; an explicit `false` is a second
/// spelling of the default and is refused (zod `z.literal(true).optional()`).
fn true_only<'de, D: Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    if bool::deserialize(deserializer)? {
        Ok(true)
    } else {
        Err(serde::de::Error::custom("`invalid` is omitted when false"))
    }
}

fn valid_blocklist_entry(entry: &str) -> bool {
    !entry.is_empty()
        && entry.len() <= EGRESS_BLOCKLIST_ENTRY_MAX_LEN
        && entry.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'/' | b'-')
        })
}

fn valid_sha256_digest(digest: &str) -> bool {
    digest.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// The text an `egress.blocklist` digest is computed over:
/// `JSON.stringify(entries)` (the entry charset needs no escaping, so both
/// languages produce the same bytes).
pub fn egress_blocklist_digest_input(entries: &[String]) -> String {
    serde_json::to_string(entries).unwrap_or_default()
}

impl EgressBlocklistV11 {
    pub fn is_valid(&self) -> bool {
        let shape = if self.invalid {
            self.configured && self.entries.is_empty()
        } else {
            self.configured == !self.entries.is_empty()
        };
        shape
            && self.entries.len() <= EGRESS_BLOCKLIST_MAX_ENTRIES
            && self.entries.iter().all(|e| valid_blocklist_entry(e))
            && self.entries.windows(2).all(|pair| pair[0] < pair[1])
            && valid_sha256_digest(&self.digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_mode_is_omitted_and_never_accepted_explicitly() {
        let policy: EgressPolicy =
            serde_json::from_str(r#"{"domains":["example.com"],"cidrs":[]}"#).unwrap();
        assert_eq!(policy.mode, EgressMode::Allowlist);
        assert_eq!(
            serde_json::to_string(&policy).unwrap(),
            r#"{"domains":["example.com"],"cidrs":[]}"#
        );
        assert!(
            serde_json::from_str::<EgressPolicy>(r#"{"mode":"allowlist","domains":[],"cidrs":[]}"#)
                .is_err()
        );
        for bad in [
            r#"{"mode":"closed","domains":[],"cidrs":[]}"#,
            r#"{"mode":null,"domains":[],"cidrs":[]}"#,
            r#"{"mode":"open","domains":[]}"#,
            r#"{"mode":"open","domains":[],"cidrs":[],"presets":[]}"#,
        ] {
            assert!(serde_json::from_str::<EgressPolicy>(bad).is_err(), "{bad}");
        }
        let open: EgressPolicy =
            serde_json::from_str(r#"{"mode":"open","domains":[],"cidrs":[]}"#).unwrap();
        assert_eq!(open.mode, EgressMode::Open);
        assert_eq!(
            open.canonical_json(),
            r#"{"cidrs":[],"domains":[],"mode":"open"}"#
        );
    }
}
