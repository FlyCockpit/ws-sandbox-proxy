//! B12 blocked-name hints: turns the runtime's raw allowlist-resolver
//! refusals into bounded `egress.refused` frames. Per sandbox: names are
//! lowercased and grammar-checked, each name is reported once, at most
//! `PENDING_MAX` wait and `REPORTED_MAX` are remembered, and at most one frame
//! of ≤ 16 names leaves every 2 s (plus `SEND_MARGIN`). Tracked sandboxes are
//! bounded too; the oldest is forgotten first (a forgotten sandbox may repeat
//! a name once).
//!
//! E3B-01 step-end barrier: the server attributes a hint to the build step
//! running when the frame arrives, so a name refused during a step must reach
//! the server before that step's operation result. Names the rate limit held
//! back used to leave after the result (a short step's late names landed on
//! the next step, or nowhere once the build had ended). `completion_barrier`
//! lets the daemon send a sandbox's due names right before one of its
//! completions and hold the completion while names still wait for the rate
//! window (bounded by `HOLD_MAX`).

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use sandbox_protocol::{
    EGRESS_REFUSED_MIN_INTERVAL_MS, EGRESS_REFUSED_NAMES_MAX, EgressRefusedV11,
    valid_hint_dns_name, valid_inventory_sandbox_id,
};

const PENDING_MAX: usize = 64;
const REPORTED_MAX: usize = 256;
const SANDBOXES_MAX: usize = 1024;
/// Slack over the protocol's 2 s interval, so a frame never reaches the
/// server's own per-sandbox throttle early (queueing delays the previous
/// frame's handling, never the clock it is measured against).
const SEND_MARGIN: Duration = Duration::from_millis(250);
/// Longest a completion waits behind its sandbox's pending names; then the
/// rest follow on the normal schedule.
pub(crate) const HOLD_MAX: Duration = Duration::from_secs(10);

fn send_interval() -> Duration {
    Duration::from_millis(EGRESS_REFUSED_MIN_INTERVAL_MS) + SEND_MARGIN
}

#[derive(Default)]
struct SandboxHints {
    pending: Vec<String>,
    reported: BTreeSet<String>,
    last_sent: Option<Instant>,
    touched: u64,
    /// When a completion of this sandbox first waited for pending names.
    held_since: Option<Instant>,
}

impl SandboxHints {
    /// The next frame, when names wait and the rate window is open.
    fn take_frame(&mut self, sandbox_id: &str, now: Instant) -> Option<EgressRefusedV11> {
        if self.pending.is_empty()
            || self
                .last_sent
                .is_some_and(|last| now.saturating_duration_since(last) < send_interval())
        {
            return None;
        }
        let take = self.pending.len().min(EGRESS_REFUSED_NAMES_MAX);
        let names: Vec<String> = self.pending.drain(..take).collect();
        self.reported.extend(names.iter().cloned());
        self.last_sent = Some(now);
        Some(EgressRefusedV11 {
            sandbox_id: sandbox_id.to_string(),
            names,
        })
    }
}

#[derive(Default)]
pub(crate) struct RefusedNameReporter {
    sandboxes: BTreeMap<String, SandboxHints>,
    clock: u64,
}

impl RefusedNameReporter {
    /// Record one raw refusal; invalid ids or names are dropped silently.
    pub(crate) fn observe(&mut self, sandbox_id: &str, name: &str) {
        let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
        if !valid_inventory_sandbox_id(sandbox_id) || !valid_hint_dns_name(&name) {
            return;
        }
        if !self.sandboxes.contains_key(sandbox_id) && self.sandboxes.len() >= SANDBOXES_MAX {
            let oldest = self
                .sandboxes
                .iter()
                .min_by_key(|(_, hints)| hints.touched)
                .map(|(id, _)| id.clone());
            if let Some(oldest) = oldest {
                self.sandboxes.remove(&oldest);
            }
        }
        self.clock += 1;
        let hints = self.sandboxes.entry(sandbox_id.to_string()).or_default();
        hints.touched = self.clock;
        if hints.reported.contains(&name)
            || hints.pending.contains(&name)
            || hints.pending.len() >= PENDING_MAX
            || hints.reported.len() >= REPORTED_MAX
        {
            return;
        }
        hints.pending.push(name);
    }

    /// Frames due at `now`: one per sandbox with pending names whose last
    /// frame left at least 2 s ago.
    pub(crate) fn drain(&mut self, now: Instant) -> Vec<EgressRefusedV11> {
        self.sandboxes
            .iter_mut()
            .filter_map(|(sandbox_id, hints)| hints.take_frame(sandbox_id, now))
            .collect()
    }

    /// Step-end barrier (E3B-01), called with every refusal the runtime
    /// recorded before a completion of `sandbox_id` was polled already
    /// observed. Returns the frame to send before that completion (if one is
    /// due) and whether the completion may be published now: false while
    /// names still wait for the rate window, for at most `HOLD_MAX`.
    pub(crate) fn completion_barrier(
        &mut self,
        sandbox_id: &str,
        now: Instant,
    ) -> (Option<EgressRefusedV11>, bool) {
        let Some(hints) = self.sandboxes.get_mut(sandbox_id) else {
            return (None, true);
        };
        let frame = hints.take_frame(sandbox_id, now);
        let held_since = *hints.held_since.get_or_insert(now);
        let clear =
            hints.pending.is_empty() || now.saturating_duration_since(held_since) >= HOLD_MAX;
        if clear {
            hints.held_since = None;
        }
        (frame, clear)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_are_bounded_deduplicated_and_rate_limited() {
        let mut reporter = RefusedNameReporter::default();
        let start = Instant::now();
        for i in 0..40 {
            reporter.observe("sbx-1", &format!("host{i}.example"));
        }
        reporter.observe("sbx-1", "HOST0.example.");
        reporter.observe("sbx-1", "bad\u{1b}[31m.example");
        reporter.observe("../x", "ok.example");
        let first = reporter.drain(start);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].names.len(), EGRESS_REFUSED_NAMES_MAX);
        assert!(first[0].is_valid());
        assert_eq!(first[0].names[0], "host0.example");
        // Within 2 s (plus the margin) nothing more leaves; after, the next
        // batch does.
        let interval = send_interval();
        assert!(interval > Duration::from_secs(2));
        assert!(
            reporter
                .drain(start + interval - Duration::from_millis(1))
                .is_empty()
        );
        let second = reporter.drain(start + interval);
        assert_eq!(second[0].names[0], "host16.example");
        // A reported name never repeats.
        reporter.observe("sbx-1", "host0.example");
        let third = reporter.drain(start + interval * 2);
        assert_eq!(third[0].names.len(), 8);
        assert!(reporter.drain(start + Duration::from_secs(9)).is_empty());
    }

    #[test]
    fn pending_names_are_capped() {
        let mut reporter = RefusedNameReporter::default();
        for i in 0..(PENDING_MAX + 10) {
            reporter.observe("sbx", &format!("h{i}.example"));
        }
        assert_eq!(reporter.sandboxes["sbx"].pending.len(), PENDING_MAX);
    }

    /// E3B-01: names refused late in a short step wait for the rate window;
    /// the step's completion waits for them, then they leave first.
    #[test]
    fn a_completion_waits_for_its_sandboxs_pending_names() {
        let mut reporter = RefusedNameReporter::default();
        let start = Instant::now();
        for name in ["a.example", "b.example", "c.example"] {
            reporter.observe("sbx-1", name);
        }
        assert_eq!(reporter.drain(start)[0].names.len(), 3);
        for name in ["d.example", "e.example", "f.example", "g.example"] {
            reporter.observe("sbx-1", name);
        }
        let step_end = start + Duration::from_millis(1100);
        // No other sandbox's completion waits.
        assert_eq!(reporter.completion_barrier("sbx-2", step_end), (None, true));
        assert_eq!(
            reporter.completion_barrier("sbx-1", step_end),
            (None, false)
        );
        let (frame, clear) = reporter.completion_barrier("sbx-1", start + send_interval());
        assert!(clear);
        assert_eq!(
            frame.unwrap().names,
            ["d.example", "e.example", "f.example", "g.example"]
        );
        // Nothing pending: later completions pass at once.
        assert_eq!(
            reporter.completion_barrier("sbx-1", start + send_interval()),
            (None, true)
        );
    }

    /// A completion never waits longer than `HOLD_MAX`.
    #[test]
    fn a_completion_waits_at_most_hold_max() {
        let mut reporter = RefusedNameReporter::default();
        let start = Instant::now();
        for i in 0..PENDING_MAX {
            reporter.observe("sbx-1", &format!("h{i}.example"));
        }
        let mut now = start;
        let mut frames = 0;
        loop {
            let (frame, clear) = reporter.completion_barrier("sbx-1", now);
            frames += usize::from(frame.is_some());
            if clear {
                break;
            }
            now += Duration::from_millis(100);
            assert!(now <= start + HOLD_MAX, "held past HOLD_MAX");
        }
        assert_eq!(frames, PENDING_MAX / EGRESS_REFUSED_NAMES_MAX);
        // More names than the hold can carry: released at HOLD_MAX.
        for i in 0..PENDING_MAX * 2 {
            reporter.observe("sbx-2", &format!("x{i}.example"));
        }
        assert!(!reporter.completion_barrier("sbx-2", now).1);
        reporter.observe("sbx-2", "late.example");
        assert!(
            !reporter
                .completion_barrier("sbx-2", now + Duration::from_secs(9))
                .1
        );
        assert!(reporter.completion_barrier("sbx-2", now + HOLD_MAX).1);
    }
}
