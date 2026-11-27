//! Managed-instance census sent during reconciliation, before `reconcile.complete`.
//! Pages are strictly ascending by sandbox id and acknowledged one at a time, so
//! the server can conclude absence only from a complete, ordered census.
use serde::{Deserialize, Serialize};

use crate::{HostLease, SandboxLifecycleState};

pub const INVENTORY_PAGE_MAX_ENTRIES: usize = 64;
/// Matches the host journal's lease capacity (65,536 records / 64 per page).
pub const INVENTORY_MAX_PAGES: u64 = 1024;
pub const EXPIRY_FAILURE_REASON_MAX_BYTES: usize = 160;

/// The server's judgement of one census entry (`inventory.ack`
/// `entryResults`, negotiated by `censusEntryResults`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CensusEntryOutcome {
    Converged,
    NotConverged,
    /// The root evidence was refused only because pool health was not
    /// current; the same evidence under a current observation may converge.
    StaleStorage,
    /// Only in `sandbox.expiry_status.ack` (`observationFence`): the
    /// observation may predate a lifecycle result the server received, so it
    /// was not judged; the host offers a newer observation (bounded). Never
    /// valid in `inventory.ack`.
    Superseded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CensusEntryResult {
    pub sandbox_id: String,
    pub outcome: CensusEntryOutcome,
    /// The exact offered root is durably retired, independently of lease adoption.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub root_retired: bool,
}

/// Results answer a page exactly: one per entry, same ids, same order.
pub fn census_results_match(entries: &[InventoryEntry], results: &[CensusEntryResult]) -> bool {
    entries.len() == results.len()
        && entries.iter().zip(results).all(|(entry, result)| {
            entry.sandbox_id == result.sandbox_id
                && (!result.root_retired
                    || (result.outcome == CensusEntryOutcome::Converged
                        && entry.state == SandboxLifecycleState::Absent
                        && entry.root.as_ref().is_some_and(|root| {
                            root.state == RootState::Absent && root.network_cleanup_complete
                        })))
        })
}

/// A host-enforced expiry the host has attempted and not yet completed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExpiryFailure {
    pub reason: String,
    pub attempts: u32,
    pub since_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InventoryLease {
    pub generation: u64,
    pub lease: HostLease,
    pub expired: bool,
    pub expiry_complete: bool,
    /// The latch came from the host's own deadline timer, not an explicit
    /// stop/kill or an idle retirement.
    pub timer_expired: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry_failure: Option<ExpiryFailure>,
}

/// Printable ASCII only, bounded, so a runtime error cannot carry control
/// characters or unbounded text to the dashboard.
pub fn sanitize_expiry_reason(raw: &str) -> String {
    let mut out = String::new();
    for c in raw.chars() {
        let c = if c.is_ascii_graphic() || c == ' ' {
            c
        } else {
            ' '
        };
        if c == ' ' && (out.is_empty() || out.ends_with(' ')) {
            continue;
        }
        if out.len() >= EXPIRY_FAILURE_REASON_MAX_BYTES {
            break;
        }
        out.push(c);
    }
    let trimmed = out.trim_end();
    if trimmed.is_empty() {
        "expiry action failed".into()
    } else {
        trimmed.into()
    }
}

fn valid_expiry_failure(failure: &ExpiryFailure) -> bool {
    !failure.reason.is_empty()
        && failure.reason.len() <= EXPIRY_FAILURE_REASON_MAX_BYTES
        && failure
            .reason
            .bytes()
            .all(|b| b.is_ascii_graphic() || b == b' ')
        && failure.attempts >= 1
}

fn valid_entry(entry: &InventoryEntry) -> bool {
    valid_inventory_sandbox_id(&entry.sandbox_id)
        && entry
            .sandbox_owner_id
            .as_deref()
            .is_none_or(crate::valid_terminal_id)
        && entry.root.as_ref().is_none_or(|r| {
            !r.storage_pool_name.is_empty()
                && r.storage_pool_name.len() <= 63
                && !r.storage_marker.is_empty()
                && r.storage_marker.len() <= 128
                && crate::vm_root_charge_gi_b(r.disk_gi_b).is_ok()
                && r.observation_sequence <= 9_007_199_254_740_991
        })
        && entry.lease.as_ref().is_none_or(|lease| {
            (!lease.timer_expired || lease.expired)
                && lease.expiry_failure.as_ref().is_none_or(|failure| {
                    lease.expired && !lease.expiry_complete && valid_expiry_failure(failure)
                })
        })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RootObservation {
    pub storage_pool_name: String,
    pub storage_marker: String,
    pub disk_gi_b: u32,
    pub state: RootState,
    pub network_cleanup_complete: bool,
    pub observation_sequence: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RootState {
    Present,
    Absent,
}
fn required_owner<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(d)
}
fn required_root<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<RootObservation>, D::Error> {
    Option::<RootObservation>::deserialize(d)
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InventoryEntry {
    #[serde(deserialize_with = "required_owner")]
    pub sandbox_owner_id: Option<String>,
    #[serde(deserialize_with = "required_root")]
    pub root: Option<RootObservation>,
    pub sandbox_id: String,
    pub state: SandboxLifecycleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<InventoryLease>,
}

pub fn valid_inventory_sandbox_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Page shape only; cross-page ordering is enforced by the receiver.
pub fn valid_inventory_page(page: u64, entries: &[InventoryEntry]) -> bool {
    page < INVENTORY_MAX_PAGES
        && entries.len() <= INVENTORY_PAGE_MAX_ENTRIES
        && valid_inventory_entries(entries)
}

/// Bounded, ascending, well-formed entries; shared by census pages and the
/// connected expiry status frame.
pub fn valid_inventory_entries(entries: &[InventoryEntry]) -> bool {
    entries.len() <= INVENTORY_PAGE_MAX_ENTRIES
        && entries.iter().all(valid_entry)
        && entries
            .windows(2)
            .all(|pair| pair[0].sandbox_id < pair[1].sandbox_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str) -> InventoryEntry {
        InventoryEntry {
            sandbox_owner_id: Some("owner".into()),
            root: None,
            sandbox_id: id.into(),
            state: SandboxLifecycleState::Stopped,
            lease: None,
        }
    }

    #[test]
    fn pages_must_be_bounded_ordered_and_identifier_safe() {
        assert!(valid_inventory_page(0, &[entry("a"), entry("b")]));
        assert!(!valid_inventory_page(0, &[entry("b"), entry("a")]));
        assert!(!valid_inventory_page(0, &[entry("a"), entry("a")]));
        assert!(!valid_inventory_page(0, &[entry("a/b")]));
        assert!(!valid_inventory_page(INVENTORY_MAX_PAGES, &[]));
        let many: Vec<_> = (0..=INVENTORY_PAGE_MAX_ENTRIES)
            .map(|i| entry(&format!("s{i:04}")))
            .collect();
        assert!(!valid_inventory_page(0, &many));
        assert!(valid_inventory_page(0, &many[..INVENTORY_PAGE_MAX_ENTRIES]));
    }

    #[test]
    fn expiry_failure_is_bounded_sanitized_and_only_on_pending_expiry() {
        let reason =
            sanitize_expiry_reason(&format!("stop\u{1b}[31m\n failed {}", "x".repeat(400)));
        assert!(reason.len() <= EXPIRY_FAILURE_REASON_MAX_BYTES);
        assert!(reason.starts_with("stop [31m failed x"));
        assert_eq!(sanitize_expiry_reason("\n\t"), "expiry action failed");
        let lease = |expired, complete, failure: Option<ExpiryFailure>| InventoryEntry {
            sandbox_owner_id: Some("owner".into()),
            root: None,
            sandbox_id: "a".into(),
            state: SandboxLifecycleState::Ready,
            lease: Some(InventoryLease {
                generation: 1,
                lease: HostLease {
                    revision: 1,
                    deadline_unix_ms: 1,
                    action: crate::LeaseAction::Stop,
                    expiry_policy: crate::ExpiryPolicy::RetryForce60s,
                    shorten_only: false,
                    from_ready_ms: None,
                },
                expired,
                expiry_complete: complete,
                timer_expired: expired,
                expiry_failure: failure,
            }),
        };
        let failure = ExpiryFailure {
            reason: "stop failed".into(),
            attempts: 1,
            since_unix_ms: 5,
        };
        assert!(valid_inventory_entries(&[lease(
            true,
            false,
            Some(failure.clone())
        )]));
        assert!(!valid_inventory_entries(&[lease(
            true,
            true,
            Some(failure.clone())
        )]));
        assert!(!valid_inventory_entries(&[lease(
            false,
            false,
            Some(failure.clone())
        )]));
        assert!(!valid_inventory_entries(&[lease(
            true,
            false,
            Some(ExpiryFailure {
                reason: "bad\nreason".into(),
                ..failure
            })
        )]));
        let mut untimed = lease(false, false, None);
        if let Some(l) = untimed.lease.as_mut() {
            l.timer_expired = true;
        }
        assert!(!valid_inventory_entries(&[untimed]));
    }
}
