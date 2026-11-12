//! How long work survives a relay outage (reconnect plan WP3, D1–D4).
//!
//! A transport loss *detaches* in-flight work instead of revoking it; the
//! reconnect adopts it. While detached, each carried attempt ends at the
//! first of:
//!
//! - **Work that never started** (queued, or parked at the effect gate):
//!   `carry_intent_window` (default 10 min) after the outage's first detach,
//!   or the sandbox lease, whichever comes first. It is revoked and settles
//!   `host_effect_not_issued`.
//! - **Work whose effect was issued**: its own timer (a command's
//!   `timeoutMs` gives `timeout`) or the lease (today's lease behaviour)
//!   end it naturally. Neither is decided here. Only `max_carry` (default
//!   24 h) after the first detach is: a running command is stopped through
//!   the ordinary cancel proof path and, once its stop is proven, settles
//!   FAILED `host_disconnect_expired` (UNKNOWN without proof); other issued
//!   work is revoked and settles by its journaled receipt.
//!
//! The anchor is the outage's first detach (`HostAuthority::detach`):
//! failed reconnects never move it, and the window never extends a lease or
//! a timer.
//!
//! Costs of long carries: every Intent-phase attempt parked at the effect
//! gate holds its lane worker for up to the window (bounded by the lanes and
//! the adopt cap); output produced during an outage is not streamed, so the
//! output gap the server sees widens with the outage.
use std::time::Duration;

/// Default `carry_intent_window`.
pub(super) const DEFAULT_INTENT_WINDOW: Duration = Duration::from_secs(10 * 60);
/// Default `max_carry`.
pub(super) const DEFAULT_MAX_CARRY: Duration = Duration::from_secs(24 * 60 * 60);
/// The effect gate's own backstop outlasts the window by this much, so it
/// only fires if the expiry tick stalls (the old 60 s grace had 90 s).
const EFFECT_GATE_SLACK: Duration = Duration::from_secs(90);

/// The node's carry limits, resolved once at daemon start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CarryPolicy {
    intent_window: Duration,
    max_carry: Duration,
}

impl Default for CarryPolicy {
    fn default() -> Self {
        Self::new(DEFAULT_INTENT_WINDOW, DEFAULT_MAX_CARRY)
    }
}

#[cfg(test)]
thread_local! {
    /// Test override of the whole policy, read on the daemon's thread.
    pub(super) static CARRY_POLICY_OVERRIDE: std::cell::Cell<Option<CarryPolicy>> =
        const { std::cell::Cell::new(None) };
}

impl CarryPolicy {
    pub fn new(intent_window: Duration, max_carry: Duration) -> Self {
        Self {
            intent_window,
            max_carry,
        }
    }
    /// The flat config keys (`carry_intent_window`, `max_carry`); a debug
    /// build's `WSSP_TEST_RELAY_TIMING` overrides them (a malformed value
    /// fails the start, never silently keeps production timing).
    pub fn for_daemon(config: &crate::config::Config) -> anyhow::Result<Self> {
        #[cfg(test)]
        if let Some(policy) = CARRY_POLICY_OVERRIDE.with(std::cell::Cell::get) {
            return Ok(policy);
        }
        let policy = Self::new(config.carry_intent_window(), config.max_carry());
        Ok(policy.with_test_timing(super::connect::installed_relay_test_timing()))
    }
    /// Apply the WP1 chaos-harness knob's `intent_window` and `max_carry`.
    #[cfg(debug_assertions)]
    pub(super) fn with_test_timing(
        self,
        timing: Option<super::test_timing::RelayTestTiming>,
    ) -> Self {
        let Some(timing) = timing else {
            return self;
        };
        Self::new(
            timing.intent_window.unwrap_or(self.intent_window),
            timing.max_carry.unwrap_or(self.max_carry),
        )
    }
    #[cfg(not(debug_assertions))]
    pub(super) fn with_test_timing(
        self,
        timing: Option<super::test_timing::RelayTestTiming>,
    ) -> Self {
        // Release builds never construct an override.
        let _ = timing;
        self
    }
    /// Intent-phase window: never past `max_carry`. The lease clamp is per
    /// sandbox (see [`decide`]).
    pub fn intent_window(&self) -> Duration {
        self.intent_window.min(self.max_carry)
    }
    pub fn max_carry(&self) -> Duration {
        self.max_carry
    }
    /// How long carried work may wait at the effect gate before failing
    /// closed as a session closure: the window plus slack for a slow tick.
    pub fn effect_gate_max_wait(&self) -> Duration {
        self.intent_window().saturating_add(EFFECT_GATE_SLACK)
    }
}

/// What one expiry tick does to one carried attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CarryDecision {
    /// Keep carrying: its own timer, the lease or a reconnect ends it.
    Keep,
    /// Revoke: never started (`host_effect_not_issued`), or issued work
    /// other than a command at `max_carry` (settled by its receipt).
    Revoke,
    /// Stop the running command durably (`ext.cancelReason`), so its owner
    /// proves the stop and settles `host_disconnect_expired`.
    Stop,
}

/// The per-entry rule. `outage` is the time since the outage's first
/// detach; `issued` means the attempt passed its effect gate; `lease_due`
/// means its sandbox's lease expired (the expiry service tears it down
/// with today's lease behaviour).
pub(super) fn decide(
    policy: &CarryPolicy,
    kind: &str,
    issued: bool,
    outage: Duration,
    lease_due: bool,
) -> CarryDecision {
    if !issued {
        return if lease_due || outage >= policy.intent_window() {
            CarryDecision::Revoke
        } else {
            CarryDecision::Keep
        };
    }
    if outage < policy.max_carry() {
        CarryDecision::Keep
    } else if kind == "command.run" {
        CarryDecision::Stop
    } else {
        CarryDecision::Revoke
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: Duration = Duration::from_secs(60);

    fn policy() -> CarryPolicy {
        CarryPolicy::new(10 * MIN, 24 * 60 * MIN)
    }

    /// The per-entry expiry table (D1–D4).
    #[test]
    fn per_entry_expiry_table() {
        use CarryDecision::*;
        let p = policy();
        let hour = 60 * MIN;
        for (name, kind, issued, outage, lease_due, expected) in [
            // A running command outlives the old 60 s grace and the window:
            // only its own timer, the lease or max_carry end it.
            (
                "running past 60 s",
                "command.run",
                true,
                2 * MIN,
                false,
                Keep,
            ),
            (
                "running past window",
                "command.run",
                true,
                11 * MIN,
                false,
                Keep,
            ),
            (
                "running at 23 h",
                "command.run",
                true,
                23 * hour,
                false,
                Keep,
            ),
            // The lease ends issued work through the expiry service (today's
            // lease behaviour), not through a carry decision.
            (
                "running, lease due",
                "command.run",
                true,
                5 * MIN,
                true,
                Keep,
            ),
            (
                "running at max_carry",
                "command.run",
                true,
                24 * hour,
                false,
                Stop,
            ),
            (
                "running past max_carry",
                "command.run",
                true,
                25 * hour,
                true,
                Stop,
            ),
            (
                "issued file op at cap",
                "file.get",
                true,
                24 * hour,
                false,
                Revoke,
            ),
            (
                "issued create at cap",
                "sandbox.create",
                true,
                24 * hour,
                false,
                Revoke,
            ),
            (
                "issued file op before cap",
                "file.put",
                true,
                hour,
                false,
                Keep,
            ),
            // Work that never started: min(window, lease).
            (
                "intent inside window",
                "command.run",
                false,
                9 * MIN,
                false,
                Keep,
            ),
            (
                "intent at window",
                "command.run",
                false,
                10 * MIN,
                false,
                Revoke,
            ),
            (
                "intent create at window",
                "sandbox.create",
                false,
                10 * MIN,
                false,
                Revoke,
            ),
            (
                "intent, lease first",
                "command.run",
                false,
                MIN,
                true,
                Revoke,
            ),
            (
                "intent stop, lease first",
                "sandbox.stop",
                false,
                Duration::ZERO,
                true,
                Revoke,
            ),
        ] {
            assert_eq!(
                decide(&p, kind, issued, outage, lease_due),
                expected,
                "{name}"
            );
        }
    }

    #[test]
    fn intent_window_never_exceeds_max_carry_and_gate_wait_follows_it() {
        let p = CarryPolicy::new(24 * 60 * MIN, 10 * MIN);
        assert_eq!(p.intent_window(), 10 * MIN);
        assert_eq!(
            decide(&p, "command.run", false, 10 * MIN, false),
            CarryDecision::Revoke
        );
        assert_eq!(p.effect_gate_max_wait(), 10 * MIN + EFFECT_GATE_SLACK);
        let d = CarryPolicy::default();
        assert_eq!(d.intent_window(), DEFAULT_INTENT_WINDOW);
        assert_eq!(d.max_carry(), DEFAULT_MAX_CARRY);
        assert_eq!(d.effect_gate_max_wait(), Duration::from_secs(690));
    }

    #[cfg(debug_assertions)]
    #[test]
    fn config_keys_and_the_debug_timing_knob_feed_the_policy() {
        let mut config = crate::config::Config::default();
        assert_eq!(
            CarryPolicy::for_daemon(&config).unwrap(),
            CarryPolicy::default()
        );
        config.set_carry_intent_window(Some(
            crate::config::CarryIntentWindow::parse("30m").unwrap(),
        ));
        config.set_max_carry(Some(crate::config::MaxCarry::parse("2d").unwrap()));
        let configured = CarryPolicy::new(config.carry_intent_window(), config.max_carry());
        assert_eq!(configured.intent_window(), 30 * MIN);
        assert_eq!(configured.max_carry(), 48 * 60 * MIN);
        let timing = super::super::test_timing::parse_relay_test_timing(",300ms,2s,,").unwrap();
        let knob = configured.with_test_timing(Some(timing));
        assert_eq!(knob.intent_window(), Duration::from_millis(300));
        assert_eq!(knob.max_carry(), Duration::from_secs(2));
        // Empty fields keep the configured values.
        let timing = super::super::test_timing::parse_relay_test_timing("5s,,,,").unwrap();
        assert_eq!(configured.with_test_timing(Some(timing)), configured);
        assert_eq!(configured.with_test_timing(None), configured);
    }

    /// The shared fixture's carry rows are the decisions this module makes.
    #[test]
    fn lifecycle_fault_matrix_carry_rows_match_the_decision_table() {
        let matrix: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../crates/sandbox-protocol/fixtures/lifecycle_fault_matrix.json"
        ))
        .unwrap();
        let rows = matrix["carry"].as_array().expect("carry rows");
        assert!(!rows.is_empty());
        let p = policy();
        for row in rows {
            let id = row["id"].as_str().unwrap();
            let issued = row["phase"] == "effect";
            let kind = row["kind"].as_str().unwrap();
            let (outage, lease_due) = match row["ending"].as_str().unwrap() {
                "reconnect" | "own_timer" => (p.intent_window() + MIN, false),
                "lease" => (MIN, true),
                "intent_window" => (p.intent_window(), false),
                "max_carry" => (p.max_carry(), false),
                other => panic!("{id}: unknown ending {other}"),
            };
            let expected = match row["decision"].as_str().unwrap() {
                "keep" => CarryDecision::Keep,
                "revoke" => CarryDecision::Revoke,
                "stop" => CarryDecision::Stop,
                other => panic!("{id}: unknown decision {other}"),
            };
            assert_eq!(
                decide(&p, kind, issued, outage, lease_due),
                expected,
                "{id}"
            );
        }
    }
}
