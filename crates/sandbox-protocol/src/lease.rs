//! Lease carried in every create/reconnect/renew and echoed by durable ACK.
use serde::{Deserialize, Serialize};

/// Far-future deadline (9999-12-31T23:59:59.999Z) meaning "no lease timer".
/// Canonical value: `packages/sandbox-contracts/src/lease-limits.json`
/// (`unlimitedDeadlineMs`); a parity test pins the two together.
pub const LEASE_UNLIMITED_DEADLINE_MS: u64 = 253_402_300_799_999;

/// Shared lease-limit manifest, read by the parity tests on both sides.
pub const LEASE_LIMITS_JSON: &str =
    include_str!("../../../packages/sandbox-contracts/src/lease-limits.json");
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LeaseAction {
    Stop,
    Destroy,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExpiryPolicy {
    #[serde(rename = "retry-force-60s")]
    RetryForce60s,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostLease {
    pub revision: u64,
    pub deadline_unix_ms: u64,
    pub action: LeaseAction,
    pub expiry_policy: ExpiryPolicy,
    /// Set only on the server's lease-policy system renewals: the host may
    /// store it only as a shortening. A later deadline than the one stored
    /// for this generation is clamped to the stored deadline (never an
    /// extension through the keyless system path). Omitted when false, so
    /// every other lease's bytes are unchanged.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub shorten_only: bool,
    /// Lease from READY (creates only, `leaseFromReady` hosts): the relative
    /// timeout. `deadline_unix_ms` is then only the provisional backstop; at
    /// READY the host rewrites the deadline to readyAt + this value and ACKs
    /// that. Omitted when absent so existing lease records keep their bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_ready_ms: Option<u64>,
}
impl HostLease {
    /// Structural check only: the deadline is in the future and no later than
    /// the far-future "no lease timer" value. The host's own lease ceiling is
    /// enforced by the daemon journal, which knows the local configuration.
    pub fn validate(&self, now_ms: u64) -> Result<(), &'static str> {
        if now_ms == 0
            || self.revision == 0
            || self.revision > i32::MAX as u64
            || self.deadline_unix_ms <= now_ms
            || self.deadline_unix_ms > LEASE_UNLIMITED_DEADLINE_MS
        {
            return Err("invalid or expired lease deadline/revision");
        }
        Ok(())
    }
    pub fn validate_now(&self) -> Result<(), &'static str> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "invalid host clock")?
            .as_millis();
        self.validate(now.try_into().map_err(|_| "invalid host clock")?)
    }
    /// Fixtures still traverse the production deadline checks.
    pub fn for_test() -> Self {
        static DEADLINE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
        Self {
            revision: 1,
            deadline_unix_ms: *DEADLINE.get_or_init(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("test clock")
                    .as_millis() as u64
                    // Well past the longest serial test suite (an
                    // hour-plus): a fixture deadline must never lapse
                    // mid-suite, or late-running tests fail on the
                    // production expiry check for purely chronological
                    // reasons.
                    + 14_400_000
            }),
            action: LeaseAction::Stop,
            expiry_policy: ExpiryPolicy::RetryForce60s,
            shorten_only: false,
            from_ready_ms: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000_000;

    fn lease(deadline_unix_ms: u64) -> HostLease {
        HostLease {
            revision: 1,
            deadline_unix_ms,
            action: LeaseAction::Stop,
            expiry_policy: ExpiryPolicy::RetryForce60s,
            shorten_only: false,
            from_ready_ms: None,
        }
    }

    #[test]
    fn accepts_leases_beyond_24h_up_to_the_unlimited_deadline() {
        assert!(lease(NOW + 90_000_000).validate(NOW).is_ok(), "25h");
        assert!(lease(NOW + 2_073_600_000).validate(NOW).is_ok(), "24 days");
        assert!(lease(LEASE_UNLIMITED_DEADLINE_MS).validate(NOW).is_ok());
        assert!(
            lease(LEASE_UNLIMITED_DEADLINE_MS + 1)
                .validate(NOW)
                .is_err()
        );
        assert!(lease(u64::MAX).validate(NOW).is_err());
    }

    #[test]
    fn keeps_the_existing_structural_refusals() {
        assert!(lease(NOW).validate(NOW).is_err(), "deadline == now");
        assert!(lease(NOW - 1).validate(NOW).is_err(), "past deadline");
        assert!(lease(NOW + 1).validate(0).is_err(), "zero clock");
        let mut bad = lease(NOW + 1);
        bad.revision = 0;
        assert!(bad.validate(NOW).is_err());
        bad.revision = i32::MAX as u64 + 1;
        assert!(bad.validate(NOW).is_err());
    }

    #[test]
    fn unlimited_deadline_matches_the_shared_manifest() {
        let limits: serde_json::Value =
            serde_json::from_str(LEASE_LIMITS_JSON).expect("lease limit manifest");
        assert_eq!(
            limits["unlimitedDeadlineMs"].as_u64(),
            Some(LEASE_UNLIMITED_DEADLINE_MS)
        );
        assert_eq!(limits["limitMinMs"].as_u64(), Some(300_000));
        assert_eq!(limits["finiteMaxMs"].as_u64(), Some(2_073_600_000));
    }
}
