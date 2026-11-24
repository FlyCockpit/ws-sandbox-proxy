//! Root and expiry evidence is re-offered until the server confirms it
//! converged, or it becomes obsolete (reconnect plan WP2 section 9).
//!
//! "Reported" is not "converged". With `expiryStatusResults` negotiated every
//! connected `sandbox.expiry_status` carries a batch and the server judges
//! each entry (`sandbox.expiry_status.ack`), as it judges census pages with
//! `censusEntryResults`. An entry is offered again only for a refusal the
//! host can cure by observing again, and only under a newer observation:
//!
//! - `stale_storage`: the evidence aged out or was overtaken (a page that
//!   crossed the server's storage TTL, a newer negative observation). It is
//!   offered again once a newer storage observation is published, whatever
//!   kind of entry it is (an expiry arm or a plain stopped/missing VM);
//! - `not_converged` while the entry's pool was unhealthy as of the stamped
//!   observation: offered again under the first newer observation in which
//!   that pool is healthy. A `not_converged` under a healthy pool is the
//!   settled answer, except absent roots still owing network cleanup and
//!   completed expiry lacking root evidence, which get bounded local retries.
//!
//! Each retry is keyed by (entry, observation sequence): one offer per newer
//! sequence at most, one batch in flight at a time, so there is no busy loop;
//! a storage report (5 s) paces any retry.
//!
//! An entry without root evidence (its pool could not be observed) is keyed
//! to the pool its journal binds it to, so pool recovery still re-arms it.
//!
//! Observation fence (`observationFence`, negotiated with
//! `expiryStatusResults`): every observation that is offered gets the next
//! session observation number, carried by all of its batches. A new
//! observation starts only after every batch of the previous one was
//! acknowledged, so an observation numbered past the one in flight when the
//! server received a lifecycle result began after that result was built.
//! The server judges non-expired evidence from an older observation
//! `not_converged` (the result it received is newer truth); a correct daemon
//! therefore never downgrades a sandbox whose reconnect it just reported.
use anyhow::{Result, bail};
use sandbox_protocol::{
    CensusEntryOutcome, CensusEntryResult, DaemonControlMessage, InventoryEntry,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::{Duration, Instant};

/// Published pool health: `(name, marker, healthy)`.
pub(super) type PoolHealth = Vec<(String, String, bool)>;

/// The server answers each batch on its serialized lane; a batch unanswered
/// this long means the transport is gone.
pub(super) const EXPIRY_ACK_TIMEOUT: Duration = Duration::from_secs(30);

/// One digest arm per sandbox: `(generation, revision, state)`.
/// Last published state of a sandbox's lease arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ExpiryArmState {
    /// The arm's expiry completed, on the first attempt or after failures.
    Complete,
    /// The arm's expiry is still failing; the attempt count is published so a
    /// retry changes the digest.
    Failing(u32),
}

/// Last published expiry arm per sandbox: (generation, revision, state).
pub(super) type ExpiryReported = std::collections::BTreeMap<String, (u64, u64, ExpiryArmState)>;

type Arm = (u64, u64, ExpiryArmState);

/// The journal's pool binding of an entry's root: `(name, marker)`.
pub(super) type PoolBinding = (String, String);

/// Pool health of `binding` as published (`None`: not published).
fn binding_healthy(health: &PoolHealth, (pool, marker): &PoolBinding) -> Option<bool> {
    health
        .iter()
        .find(|(name, mark, _)| name == pool && mark == marker)
        .map(|(_, _, healthy)| *healthy)
}

fn pool_healthy(health: &PoolHealth, entry: &InventoryEntry) -> Option<bool> {
    let root = entry.root.as_ref()?;
    health
        .iter()
        .find(|(name, marker, _)| *name == root.storage_pool_name && *marker == root.storage_marker)
        .map(|(_, _, healthy)| *healthy)
}

/// Why a judged entry is offered again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Reoffer {
    /// Refused for stale storage under observation `sequence`.
    Stale { sequence: u64 },
    /// Not converged while its pool (`name`, `marker`) was unhealthy as of
    /// observation `sequence`.
    Unhealthy {
        sequence: u64,
        pool: String,
        marker: String,
    },
    /// Completed expiry evidence without root evidence (its root census
    /// failed) was not converged: the server needs root evidence. Offered
    /// again under a newer observation, at most [`ROOTLESS_RETRIES`] times;
    /// its arm stays unreported meanwhile.
    Rootless { sequence: u64, attempts: u32 },
    /// Absent root still owes network cleanup; retry local proof under newer
    /// healthy observations, bounded like missing root evidence.
    Cleanup { sequence: u64, attempts: u32 },
    /// `superseded`: the server did not judge it because the observation may
    /// predate a lifecycle result it received (observation fence). Observed
    /// again under a newer storage observation (one report, about 5 s, paces
    /// it), at most [`FENCED_RETRIES`] times; its arm stays unreported.
    Fenced { sequence: u64, attempts: u32 },
}

/// How often evidence the observation fence superseded is observed again
/// before it waits for the next reconnect's census.
pub(super) const FENCED_RETRIES: u32 = 8;

/// How often completed expiry evidence refused for lacking root evidence is
/// re-observed before it waits for the next reconnect's census.
/// Rootless and cleanup proofs share this budget even when they alternate.
pub(super) const ROOTLESS_RETRIES: u32 = 8;

impl Reoffer {
    /// What `outcome` for `entry`, stamped with `sequence` while `health` was
    /// published, asks of the host. `binding` is the journal's pool binding
    /// for an entry observed without a root (its pool was unobservable).
    pub(super) fn after(
        outcome: CensusEntryOutcome,
        entry: &InventoryEntry,
        binding: Option<&PoolBinding>,
        sequence: u64,
        health: &PoolHealth,
        previous: Option<&Self>,
    ) -> Option<Self> {
        match outcome {
            CensusEntryOutcome::Converged => None,
            CensusEntryOutcome::StaleStorage => Some(Self::Stale { sequence }),
            CensusEntryOutcome::Superseded => Some(Self::Fenced {
                sequence,
                attempts: match previous {
                    Some(Self::Fenced { attempts, .. }) => attempts + 1,
                    _ => 1,
                },
            }),
            CensusEntryOutcome::NotConverged => {
                let Some(root) = entry.root.as_ref() else {
                    // Omitted root evidence is inconclusive; use its pool
                    // binding to retry after a failed pool observation once
                    // that pool is healthy under a newer observation.
                    if let Some(binding) =
                        binding.filter(|binding| binding_healthy(health, binding) != Some(true))
                    {
                        return Some(Self::Unhealthy {
                            sequence,
                            pool: binding.0.clone(),
                            marker: binding.1.clone(),
                        });
                    }
                    let completed = entry
                        .lease
                        .as_ref()
                        .is_some_and(|lease| lease.expired && lease.expiry_complete);
                    let attempts = match previous {
                        Some(Self::Rootless { attempts, .. } | Self::Cleanup { attempts, .. }) => {
                            attempts + 1
                        }
                        _ => 1,
                    };
                    return completed.then_some(Self::Rootless { sequence, attempts });
                };
                if pool_healthy(health, entry) != Some(true) {
                    Some(Self::Unhealthy {
                        sequence,
                        pool: root.storage_pool_name.clone(),
                        marker: root.storage_marker.clone(),
                    })
                } else if root.state == sandbox_protocol::RootState::Absent
                    && !root.network_cleanup_complete
                {
                    Some(Self::Cleanup {
                        sequence,
                        attempts: match previous {
                            Some(
                                Self::Rootless { attempts, .. } | Self::Cleanup { attempts, .. },
                            ) => attempts + 1,
                            _ => 1,
                        },
                    })
                } else {
                    None
                }
            }
        }
    }

    /// Whether the observation published now (`current`, `health`) is the
    /// newer one this refusal waits for.
    pub(super) fn due(&self, current: u64, health: &PoolHealth) -> bool {
        match self {
            Self::Stale { sequence } => current > *sequence,
            Self::Rootless { sequence, attempts } | Self::Cleanup { sequence, attempts } => {
                *attempts <= ROOTLESS_RETRIES && current > *sequence
            }
            Self::Fenced { sequence, attempts } => {
                *attempts <= FENCED_RETRIES && current > *sequence
            }
            Self::Unhealthy {
                sequence,
                pool,
                marker,
            } => {
                current > *sequence
                    && health
                        .iter()
                        .any(|(name, mark, healthy)| name == pool && mark == marker && *healthy)
            }
        }
    }
}

struct Batch {
    batch: u64,
    entries: Vec<InventoryEntry>,
    /// Per entry: the journal's pool binding when it carries no root.
    bindings: Vec<Option<PoolBinding>>,
    /// Per entry: the digest change this offer reports (`Some(None)` clears
    /// the arm), or `None` for a pure re-offer.
    changes: Vec<Option<Option<Arm>>>,
    sequence: u64,
    health: PoolHealth,
    sent_at: Instant,
}

/// One session's connected evidence (with `expiryStatusResults`).
#[derive(Default)]
pub(super) struct Evidence {
    reoffers: BTreeMap<String, Reoffer>,
    outstanding: VecDeque<Batch>,
    last_batch: u64,
    /// The last observation offered this session (`observationFence`).
    last_observation: u64,
}

impl Evidence {
    /// A judged census page: refusals the host can cure are offered again.
    /// `bindings` holds the journal's pool binding of entries without a root.
    pub(super) fn record_census(
        &mut self,
        entries: &[InventoryEntry],
        results: &[CensusEntryResult],
        bindings: &BTreeMap<String, PoolBinding>,
        sequence: u64,
        health: &PoolHealth,
    ) {
        for (entry, result) in entries.iter().zip(results) {
            let binding = bindings.get(&entry.sandbox_id);
            self.judged(entry, binding, result.outcome, sequence, health);
        }
    }

    fn judged(
        &mut self,
        entry: &InventoryEntry,
        binding: Option<&PoolBinding>,
        outcome: CensusEntryOutcome,
        sequence: u64,
        health: &PoolHealth,
    ) {
        let previous = self.reoffers.get(&entry.sandbox_id);
        match Reoffer::after(outcome, entry, binding, sequence, health, previous) {
            Some(reoffer) => {
                self.reoffers.insert(entry.sandbox_id.clone(), reoffer);
            }
            None => {
                self.reoffers.remove(&entry.sandbox_id);
            }
        }
    }

    /// Entries due for another offer under the observation published now.
    pub(super) fn due(&self, current: u64, health: &PoolHealth) -> BTreeSet<String> {
        self.reoffers
            .iter()
            .filter(|(_, reoffer)| reoffer.due(current, health))
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Entries with a refusal not yet due: their digest change waits for the
    /// re-offer instead of being sent again under the same observation.
    pub(super) fn blocked(&self, current: u64, health: &PoolHealth) -> BTreeSet<String> {
        self.reoffers
            .iter()
            .filter(|(_, reoffer)| !reoffer.due(current, health))
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// A batch is waiting for its judgement (no new observation starts).
    pub(super) fn awaiting(&self) -> bool {
        !self.outstanding.is_empty()
    }

    /// The oldest unanswered batch has waited past [`EXPIRY_ACK_TIMEOUT`].
    pub(super) fn overdue(&self, now: Instant) -> bool {
        self.outstanding
            .front()
            .is_some_and(|batch| now.saturating_duration_since(batch.sent_at) >= EXPIRY_ACK_TIMEOUT)
    }

    /// `id` no longer has evidence to offer (its lease and VM are gone).
    pub(super) fn forget(&mut self, id: &str) {
        self.reoffers.remove(id);
    }

    /// Frames offering `entries` (observed under `sequence` while `health`
    /// was published), each batch recorded as outstanding. `changes` holds
    /// the digest change each changed entry reports, `bindings` the pool
    /// binding of entries without a root. All the frames carry one new
    /// observation number; none is spent on an empty offer.
    pub(super) fn offer(
        &mut self,
        entries: Vec<InventoryEntry>,
        changes: &BTreeMap<String, Option<Arm>>,
        bindings: &BTreeMap<String, PoolBinding>,
        sequence: u64,
        health: &PoolHealth,
        now: Instant,
    ) -> Vec<DaemonControlMessage> {
        let mut frames = Vec::new();
        if entries.is_empty() {
            return frames;
        }
        // Only after every earlier batch was judged (`awaiting`), so this
        // observation began after the server sent its last answer.
        debug_assert!(self.outstanding.is_empty(), "one observation at a time");
        self.last_observation += 1;
        for chunk in entries.chunks(sandbox_protocol::INVENTORY_PAGE_MAX_ENTRIES) {
            self.last_batch += 1;
            for entry in chunk {
                // A rootless or fenced refusal keeps its attempt count
                // across offers.
                if !matches!(
                    self.reoffers.get(&entry.sandbox_id),
                    Some(
                        Reoffer::Rootless { .. } | Reoffer::Cleanup { .. } | Reoffer::Fenced { .. }
                    )
                ) {
                    self.reoffers.remove(&entry.sandbox_id);
                }
            }
            self.outstanding.push_back(Batch {
                batch: self.last_batch,
                entries: chunk.to_vec(),
                changes: chunk
                    .iter()
                    .map(|entry| changes.get(&entry.sandbox_id).copied())
                    .collect(),
                bindings: chunk
                    .iter()
                    .map(|entry| bindings.get(&entry.sandbox_id).cloned())
                    .collect(),
                sequence,
                health: health.clone(),
                sent_at: now,
            });
            frames.push(DaemonControlMessage::SandboxExpiryStatus {
                entries: chunk.to_vec(),
                batch: Some(self.last_batch),
                observation: Some(self.last_observation),
            });
        }
        frames
    }

    /// The server judged `batch`: each digest change it carried is now
    /// reported, and each curable refusal is offered again later. The ACK
    /// must answer the oldest outstanding batch exactly.
    pub(super) fn acknowledge(
        &mut self,
        batch: u64,
        results: &[CensusEntryResult],
        reported: &mut ExpiryReported,
    ) -> Result<()> {
        let Some(front) = self.outstanding.front() else {
            bail!("expiry status acknowledgement without a batch");
        };
        if front.batch != batch || !sandbox_protocol::census_results_match(&front.entries, results)
        {
            bail!("expiry status acknowledgement does not judge its batch");
        }
        let Some(front) = self.outstanding.pop_front() else {
            bail!("expiry status acknowledgement without a batch");
        };
        for (((entry, change), binding), result) in front
            .entries
            .iter()
            .zip(&front.changes)
            .zip(&front.bindings)
            .zip(results)
        {
            self.judged(
                entry,
                binding.as_ref(),
                result.outcome,
                front.sequence,
                &front.health,
            );
            // Refused only for lacking root evidence, or not judged (fenced):
            // the arm stays unreported until judged evidence converges it.
            if matches!(
                self.reoffers.get(&entry.sandbox_id),
                Some(Reoffer::Rootless { .. } | Reoffer::Cleanup { .. } | Reoffer::Fenced { .. })
            ) {
                continue;
            }
            match change {
                Some(Some(arm)) => {
                    reported.insert(entry.sandbox_id.clone(), *arm);
                }
                Some(None) => {
                    reported.remove(&entry.sandbox_id);
                }
                None => {}
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn reoffer(&self, id: &str) -> Option<&Reoffer> {
        self.reoffers.get(id)
    }
}

/// Paces connected observations whose runtime read failed: without it a
/// fast-failing runtime is observed again at socket-loop
/// cadence. The delay doubles from [`OBSERVATION_RETRY_MIN`] up to
/// [`OBSERVATION_RETRY_MAX`] and resets on the first observation that
/// succeeds.
#[derive(Debug, Default)]
pub(super) struct ObservationBackoff {
    failures: u32,
    retry_at: Option<Instant>,
}

pub(super) const OBSERVATION_RETRY_MIN: Duration = Duration::from_secs(1);
pub(super) const OBSERVATION_RETRY_MAX: Duration = Duration::from_secs(30);

impl ObservationBackoff {
    /// Whether an observation may start at `now`.
    pub(super) fn ready(&self, now: Instant) -> bool {
        self.retry_at.is_none_or(|at| now >= at)
    }

    /// The observation started before `now` failed.
    pub(super) fn failed(&mut self, now: Instant) {
        self.failures = self.failures.saturating_add(1);
        let delay = OBSERVATION_RETRY_MIN
            .saturating_mul(1u32 << self.failures.saturating_sub(1).min(5))
            .min(OBSERVATION_RETRY_MAX);
        self.retry_at = Some(now + delay);
    }

    /// An observation succeeded: the next one is not delayed.
    pub(super) fn succeeded(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandbox_protocol::{RootObservation, RootState, SandboxLifecycleState};

    fn entry(id: &str, sequence: u64) -> InventoryEntry {
        InventoryEntry {
            sandbox_owner_id: Some("owner".into()),
            sandbox_id: id.into(),
            state: SandboxLifecycleState::Stopped,
            lease: None,
            root: Some(RootObservation {
                storage_pool_name: "default".into(),
                storage_marker: "a".repeat(32),
                disk_gi_b: 32,
                state: RootState::Present,
                network_cleanup_complete: false,
                observation_sequence: sequence,
            }),
        }
    }
    fn health(healthy: bool) -> PoolHealth {
        vec![("default".into(), "a".repeat(32), healthy)]
    }
    fn result(id: &str, outcome: CensusEntryOutcome) -> CensusEntryResult {
        CensusEntryResult {
            sandbox_id: id.into(),
            outcome,
        }
    }

    /// Codex review-integ3 #2: a census entry without an expiry arm (a plain
    /// stopped VM with an unexpired lease) judged `stale_storage` is offered
    /// again under the next observation, once, and settles when judged.
    #[test]
    fn a_stale_census_entry_without_an_arm_is_offered_again_once() {
        let mut evidence = Evidence::default();
        evidence.record_census(
            &[entry("sbx-a", 2), entry("sbx-b", 2)],
            &[
                result("sbx-a", CensusEntryOutcome::Converged),
                result("sbx-b", CensusEntryOutcome::StaleStorage),
            ],
            &BTreeMap::new(),
            2,
            &health(true),
        );
        assert!(
            evidence.due(2, &health(true)).is_empty(),
            "same observation"
        );
        assert_eq!(
            evidence.due(3, &health(true)),
            BTreeSet::from(["sbx-b".to_owned()])
        );
        let mut reported = ExpiryReported::new();
        let frames = evidence.offer(
            vec![entry("sbx-b", 3)],
            &BTreeMap::new(),
            &BTreeMap::new(),
            3,
            &health(true),
            Instant::now(),
        );
        assert_eq!(frames.len(), 1);
        assert!(evidence.awaiting());
        assert!(evidence.due(9, &health(true)).is_empty(), "in flight once");
        evidence
            .acknowledge(
                1,
                &[result("sbx-b", CensusEntryOutcome::Converged)],
                &mut reported,
            )
            .unwrap();
        assert!(!evidence.awaiting());
        assert!(evidence.due(10, &health(true)).is_empty(), "converged");
        assert!(reported.is_empty(), "a pure re-offer reports no arm");
    }

    /// Codex review-integ3 #3: `not_converged` while the pool was unavailable
    /// at the stamped sequence waits for a newer healthy observation; a
    /// `not_converged` under a healthy pool is final (no busy loop).
    #[test]
    fn not_converged_under_an_unhealthy_pool_waits_for_a_newer_healthy_sequence() {
        let mut evidence = Evidence::default();
        evidence.record_census(
            &[entry("sbx", 4)],
            &[result("sbx", CensusEntryOutcome::NotConverged)],
            &BTreeMap::new(),
            4,
            &health(false),
        );
        assert!(evidence.due(4, &health(true)).is_empty(), "not newer");
        assert!(
            evidence.due(5, &health(false)).is_empty(),
            "still unhealthy"
        );
        assert_eq!(evidence.due(5, &health(true)).len(), 1);
        let mut reported = ExpiryReported::new();
        evidence.offer(
            vec![entry("sbx", 5)],
            &BTreeMap::new(),
            &BTreeMap::new(),
            5,
            &health(true),
            Instant::now(),
        );
        evidence
            .acknowledge(
                1,
                &[result("sbx", CensusEntryOutcome::NotConverged)],
                &mut reported,
            )
            .unwrap();
        assert_eq!(evidence.reoffer("sbx"), None, "healthy refusal is final");
        assert!(evidence.due(100, &health(true)).is_empty());
        // Without root evidence nothing about the pool can be cured.
        let mut rootless = entry("bare", 1);
        rootless.root = None;
        evidence.record_census(
            &[rootless],
            &[result("bare", CensusEntryOutcome::NotConverged)],
            &BTreeMap::new(),
            1,
            &health(false),
        );
        assert!(evidence.due(100, &health(true)).is_empty());
    }

    /// Completed expiry evidence whose root census failed
    /// (`root: null`) and was refused stays unreported and is re-observed
    /// under each newer observation, a bounded number of times; meanwhile its
    /// digest change is paced by the re-offer (no re-send per tick).
    #[test]
    fn rootless_completed_expiry_is_retried_unreported_and_bounded() {
        let mut evidence = Evidence::default();
        let mut reported = ExpiryReported::new();
        let arm = (1, 1, ExpiryArmState::Complete);
        let changes = BTreeMap::from([("sbx".to_owned(), Some(arm))]);
        let mut completed = entry("sbx", 3);
        completed.root = None;
        completed.lease = Some(sandbox_protocol::InventoryLease {
            generation: 1,
            lease: sandbox_protocol::HostLease::for_test(),
            expired: true,
            expiry_complete: true,
            timer_expired: true,
            expiry_failure: None,
        });
        for round in 1..=ROOTLESS_RETRIES + 1 {
            let sequence = u64::from(round) + 2;
            evidence.offer(
                vec![completed.clone()],
                &changes,
                &BTreeMap::new(),
                sequence,
                &health(true),
                Instant::now(),
            );
            evidence
                .acknowledge(
                    u64::from(round),
                    &[result("sbx", CensusEntryOutcome::NotConverged)],
                    &mut reported,
                )
                .unwrap();
            assert!(reported.is_empty(), "never reported while refused");
            assert!(
                evidence.blocked(sequence, &health(true)).contains("sbx"),
                "the digest waits for the re-offer"
            );
            let due = !evidence.due(sequence + 1, &health(true)).is_empty();
            assert_eq!(due, round < ROOTLESS_RETRIES + 1, "round {round}");
        }
        // Exhausted: parked (blocked, never due) until the next census.
        assert!(evidence.due(1000, &health(true)).is_empty());
        assert!(evidence.blocked(1000, &health(true)).contains("sbx"));
        // Rootless evidence that is not completed expiry is final.
        let mut evidence = Evidence::default();
        let mut stopped = entry("other", 3);
        stopped.root = None;
        evidence.record_census(
            &[stopped],
            &[result("other", CensusEntryOutcome::NotConverged)],
            &BTreeMap::new(),
            3,
            &health(true),
        );
        assert!(evidence.due(100, &health(true)).is_empty());
        assert!(evidence.blocked(100, &health(true)).is_empty());
    }

    #[test]
    fn alternating_rootless_and_cleanup_evidence_shares_the_retry_bound() {
        for start_rootless in [false, true] {
            let mut evidence = Evidence::default();
            let mut reported = ExpiryReported::new();
            let arm = (1, 1, ExpiryArmState::Complete);
            let changes = BTreeMap::from([("sbx".to_owned(), Some(arm))]);
            for attempt in 1..=ROOTLESS_RETRIES + 1 {
                let sequence = u64::from(attempt);
                let rootless = (attempt % 2 == 1) == start_rootless;
                let mut unresolved = entry("sbx", sequence);
                unresolved.lease = Some(sandbox_protocol::InventoryLease {
                    generation: 1,
                    lease: sandbox_protocol::HostLease::for_test(),
                    expired: true,
                    expiry_complete: true,
                    timer_expired: true,
                    expiry_failure: None,
                });
                if rootless {
                    unresolved.root = None;
                } else {
                    unresolved.root.as_mut().unwrap().state = RootState::Absent;
                }
                evidence.offer(
                    vec![unresolved],
                    &changes,
                    &BTreeMap::new(),
                    sequence,
                    &health(true),
                    Instant::now(),
                );
                evidence
                    .acknowledge(
                        sequence,
                        &[result("sbx", CensusEntryOutcome::NotConverged)],
                        &mut reported,
                    )
                    .unwrap();
                let expected = if rootless {
                    Reoffer::Rootless {
                        sequence,
                        attempts: attempt,
                    }
                } else {
                    Reoffer::Cleanup {
                        sequence,
                        attempts: attempt,
                    }
                };
                assert_eq!(evidence.reoffer("sbx"), Some(&expected));
                assert!(reported.is_empty());
                assert_eq!(
                    evidence.due(sequence + 1, &health(true)).contains("sbx"),
                    attempt <= ROOTLESS_RETRIES
                );
            }
            assert!(evidence.due(1000, &health(true)).is_empty());
            assert!(evidence.blocked(1000, &health(true)).contains("sbx"));
        }
    }

    #[test]
    fn absent_roots_with_pending_network_cleanup_retry_bounded_then_converge() {
        let mut evidence = Evidence::default();
        let mut reported = ExpiryReported::new();
        let arm = (1, 1, ExpiryArmState::Complete);
        let changes = BTreeMap::from([("sbx".to_owned(), Some(arm))]);
        for attempt in 1..=ROOTLESS_RETRIES + 1 {
            let sequence = u64::from(attempt);
            let mut absent = entry("sbx", sequence);
            absent.root.as_mut().unwrap().state = RootState::Absent;
            evidence.offer(
                vec![absent],
                &changes,
                &BTreeMap::new(),
                sequence,
                &health(true),
                Instant::now(),
            );
            evidence
                .acknowledge(
                    sequence,
                    &[result("sbx", CensusEntryOutcome::NotConverged)],
                    &mut reported,
                )
                .unwrap();
            assert!(reported.is_empty());
            assert!(evidence.due(sequence, &health(true)).is_empty());
            assert_eq!(
                !evidence.due(sequence + 1, &health(true)).is_empty(),
                attempt <= ROOTLESS_RETRIES
            );
            assert!(evidence.blocked(sequence, &health(true)).contains("sbx"));
        }
        let mut clean = entry("sbx", 100);
        let root = clean.root.as_mut().unwrap();
        root.state = RootState::Absent;
        root.network_cleanup_complete = true;
        evidence.offer(
            vec![clean],
            &changes,
            &BTreeMap::new(),
            100,
            &health(true),
            Instant::now(),
        );
        evidence
            .acknowledge(
                u64::from(ROOTLESS_RETRIES) + 2,
                &[result("sbx", CensusEntryOutcome::Converged)],
                &mut reported,
            )
            .unwrap();
        assert_eq!(reported.get("sbx"), Some(&arm));
        assert!(evidence.reoffer("sbx").is_none());
    }

    /// Codex review-integ3 #1: a connected expiry arm judged `stale_storage`
    /// has its digest change recorded (the digest alone never re-sends it),
    /// and the refusal is offered again under the next observation until it
    /// converges.
    #[test]
    fn a_stale_connected_expiry_arm_is_offered_again_until_it_converges() {
        let mut evidence = Evidence::default();
        let mut reported = ExpiryReported::new();
        let arm = (1, 1, ExpiryArmState::Complete);
        let changes = BTreeMap::from([("sbx".to_owned(), Some(arm))]);
        evidence.offer(
            vec![entry("sbx", 7)],
            &changes,
            &BTreeMap::new(),
            7,
            &health(true),
            Instant::now(),
        );
        evidence
            .acknowledge(
                1,
                &[result("sbx", CensusEntryOutcome::StaleStorage)],
                &mut reported,
            )
            .unwrap();
        assert_eq!(reported.get("sbx"), Some(&arm));
        assert_eq!(
            evidence.reoffer("sbx"),
            Some(&Reoffer::Stale { sequence: 7 })
        );
        assert_eq!(evidence.due(8, &health(true)).len(), 1);
        evidence.offer(
            vec![entry("sbx", 8)],
            &BTreeMap::new(),
            &BTreeMap::new(),
            8,
            &health(true),
            Instant::now(),
        );
        // ACKs must judge exactly the oldest batch.
        assert!(
            evidence
                .acknowledge(
                    1,
                    &[result("sbx", CensusEntryOutcome::Converged)],
                    &mut reported
                )
                .is_err()
        );
        assert!(
            evidence
                .acknowledge(
                    2,
                    &[result("other", CensusEntryOutcome::Converged)],
                    &mut reported
                )
                .is_err()
        );
        evidence
            .acknowledge(
                2,
                &[result("sbx", CensusEntryOutcome::Converged)],
                &mut reported,
            )
            .unwrap();
        assert!(evidence.due(100, &health(true)).is_empty());
        assert!(!evidence.overdue(Instant::now()));
    }

    fn observation_of(frame: &DaemonControlMessage) -> (Option<u64>, Option<u64>) {
        match frame {
            DaemonControlMessage::SandboxExpiryStatus {
                batch, observation, ..
            } => (*batch, *observation),
            _ => panic!("not an expiry status"),
        }
    }

    /// Observation fence (WP2 follow-up): every offered observation gets the
    /// next session number, shared by all of its batches; an empty offer
    /// spends none, so numbers advance only with what the server sees.
    #[test]
    fn each_offered_observation_is_numbered_once_across_its_batches() {
        let mut evidence = Evidence::default();
        let mut reported = ExpiryReported::new();
        let many: Vec<_> = (0..sandbox_protocol::INVENTORY_PAGE_MAX_ENTRIES + 1)
            .map(|i| entry(&format!("sbx-{i:04}"), 1))
            .collect();
        let frames = evidence.offer(
            many.clone(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            1,
            &health(true),
            Instant::now(),
        );
        assert_eq!(
            frames.iter().map(observation_of).collect::<Vec<_>>(),
            [(Some(1), Some(1)), (Some(2), Some(1))]
        );
        for (batch, chunk) in many
            .chunks(sandbox_protocol::INVENTORY_PAGE_MAX_ENTRIES)
            .enumerate()
        {
            let results: Vec<_> = chunk
                .iter()
                .map(|e| result(&e.sandbox_id, CensusEntryOutcome::Converged))
                .collect();
            evidence
                .acknowledge(batch as u64 + 1, &results, &mut reported)
                .unwrap();
        }
        assert!(
            evidence
                .offer(
                    Vec::new(),
                    &BTreeMap::new(),
                    &BTreeMap::new(),
                    2,
                    &health(true),
                    Instant::now()
                )
                .is_empty()
        );
        let frames = evidence.offer(
            vec![entry("sbx-0000", 2)],
            &BTreeMap::new(),
            &BTreeMap::new(),
            2,
            &health(true),
            Instant::now(),
        );
        assert_eq!(
            frames.iter().map(observation_of).collect::<Vec<_>>(),
            [(Some(3), Some(2))]
        );
    }

    /// A `not_converged` entry observed without a root
    /// (its pool could not be observed) is keyed to the journal's pool
    /// binding and offered again under a newer observation once that pool
    /// is healthy, instead of being dropped.
    #[test]
    fn a_rootless_refusal_is_retried_after_its_bound_pool_recovers() {
        let mut evidence = Evidence::default();
        let mut bare = entry("sbx", 4);
        bare.root = None;
        let bindings = BTreeMap::from([("sbx".to_owned(), ("default".to_owned(), "a".repeat(32)))]);
        evidence.record_census(
            &[bare.clone()],
            &[result("sbx", CensusEntryOutcome::NotConverged)],
            &bindings,
            4,
            &health(false),
        );
        assert_eq!(
            evidence.reoffer("sbx"),
            Some(&Reoffer::Unhealthy {
                sequence: 4,
                pool: "default".into(),
                marker: "a".repeat(32),
            })
        );
        assert!(evidence.due(5, &health(false)).is_empty(), "still down");
        assert!(evidence.due(4, &health(true)).is_empty(), "not newer");
        assert_eq!(evidence.due(5, &health(true)).len(), 1);
        // An unpublished pool is not known healthy either.
        let mut other = Evidence::default();
        other.record_census(
            &[bare.clone()],
            &[result("sbx", CensusEntryOutcome::NotConverged)],
            &bindings,
            4,
            &Vec::new(),
        );
        assert!(matches!(
            other.reoffer("sbx"),
            Some(Reoffer::Unhealthy { .. })
        ));
        // Under a healthy bound pool the refusal is the server's answer.
        let mut settled = Evidence::default();
        settled.record_census(
            &[bare],
            &[result("sbx", CensusEntryOutcome::NotConverged)],
            &bindings,
            4,
            &health(true),
        );
        assert_eq!(settled.reoffer("sbx"), None);
        // The binding rides on an offered batch to its judgement.
        let mut offered = Evidence::default();
        let mut reported = ExpiryReported::new();
        let mut rootless = entry("sbx", 6);
        rootless.root = None;
        offered.offer(
            vec![rootless],
            &BTreeMap::new(),
            &bindings,
            6,
            &health(false),
            Instant::now(),
        );
        offered
            .acknowledge(
                1,
                &[result("sbx", CensusEntryOutcome::NotConverged)],
                &mut reported,
            )
            .unwrap();
        assert!(matches!(
            offered.reoffer("sbx"),
            Some(Reoffer::Unhealthy { sequence: 6, .. })
        ));
    }

    /// A failed observation delays the next one, doubling
    /// up to a cap, and a success clears the delay.
    #[test]
    fn failed_observations_are_paced_with_a_bounded_backoff() {
        let start = Instant::now();
        let mut backoff = ObservationBackoff::default();
        assert!(backoff.ready(start));
        backoff.failed(start);
        assert!(!backoff.ready(start));
        assert!(backoff.ready(start + OBSERVATION_RETRY_MIN));
        let mut delays = Vec::new();
        for _ in 0..8 {
            backoff.failed(start);
            let delay = (1..=60)
                .map(Duration::from_secs)
                .find(|d| backoff.ready(start + *d))
                .unwrap();
            delays.push(delay.as_secs());
        }
        assert_eq!(delays, [2, 4, 8, 16, 30, 30, 30, 30]);
        backoff.succeeded();
        assert!(backoff.ready(start));
    }

    /// Codex rc-fu-b r1 #2: evidence the observation fence superseded (a
    /// genuinely stopped VM re-offered while a result for it arrived, healthy
    /// pool) is never dropped like a final `not_converged`: it is observed
    /// again under each newer observation, at most `FENCED_RETRIES` times.
    #[test]
    fn superseded_evidence_is_reoffered_paced_and_bounded() {
        let mut evidence = Evidence::default();
        let mut reported = ExpiryReported::new();
        for round in 1..=FENCED_RETRIES + 1 {
            let sequence = u64::from(round) + 2;
            evidence.offer(
                vec![entry("sbx", sequence)],
                &BTreeMap::new(),
                &BTreeMap::new(),
                sequence,
                &health(true),
                Instant::now(),
            );
            evidence
                .acknowledge(
                    u64::from(round),
                    &[result("sbx", CensusEntryOutcome::Superseded)],
                    &mut reported,
                )
                .unwrap();
            assert!(
                evidence.due(sequence, &health(true)).is_empty(),
                "paced by a newer observation"
            );
            let due = !evidence.due(sequence + 1, &health(true)).is_empty();
            assert_eq!(due, round < FENCED_RETRIES + 1, "round {round}");
        }
        assert!(evidence.due(1000, &health(true)).is_empty(), "bounded");
        // Judged later: settled, and the count starts over on a new refusal.
        let mut evidence = Evidence::default();
        evidence.offer(
            vec![entry("sbx", 3)],
            &BTreeMap::new(),
            &BTreeMap::new(),
            3,
            &health(true),
            Instant::now(),
        );
        evidence
            .acknowledge(
                1,
                &[result("sbx", CensusEntryOutcome::Superseded)],
                &mut reported,
            )
            .unwrap();
        evidence.offer(
            vec![entry("sbx", 4)],
            &BTreeMap::new(),
            &BTreeMap::new(),
            4,
            &health(true),
            Instant::now(),
        );
        evidence
            .acknowledge(
                2,
                &[result("sbx", CensusEntryOutcome::Converged)],
                &mut reported,
            )
            .unwrap();
        assert_eq!(evidence.reoffer("sbx"), None);
    }
}
