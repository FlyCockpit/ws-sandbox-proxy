//! Service-owned expiry. Neither a socket, a dispatch queue nor a guest operation
//! owns this thread. Durable intent precedes revocation and every cleanup attempt.
use super::{
    authority::HostAuthority,
    carry::CarryPolicy,
    journal::{CancelReason, HostJournal, LeaseRecord, ReceiptPhase},
};
use anyhow::{Result, bail};
use sandbox_protocol::{ExpiryFailure, LeaseAction};
use sandbox_runtime::{KillSandboxRequest, RuntimePermit, SandboxRuntime, StopSandboxRequest};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const TICK: Duration = Duration::from_millis(50);
/// The post-revocation wait polls shutdown and the journal every [`TICK`] but
/// runs the runtime inventory census at most this often.
const CENSUS_INTERVAL: Duration = Duration::from_secs(1);
const ACTION_BUDGET: Duration = Duration::from_secs(5);
/// Graceful-first expiry (C55): the guest gets this long to shut down after
/// an ACPI-style stop request before the forced stop runs.
pub(super) const GRACEFUL_STOP_TIMEOUT: Duration = Duration::from_secs(10);
/// The graceful attempt's own permit: the guest timeout plus the process
/// slack, so it never spends the forced fallback's [`ACTION_BUDGET`].
pub(super) const GRACEFUL_STOP_BUDGET: Duration = Duration::from_secs(16);
pub(super) const MAX_ACTIONS: usize = 64;
/// Covers the credential phase (CLI logins, 20 s), one graceful attempt
/// (16 s), one forced stop (5 s), one destroy attempt (5 s), and a fresh
/// fallback absence proof (5 s) with 1 s margin. Past this the host publishes the unresolved expiry instead of
/// withholding its census.
pub(super) const RECONCILE_BUDGET: Duration = Duration::from_secs(52);
/// Cadence of the DNS grant refresh pass (domain egress). Each pass is cheap
/// when nothing is due: the runtime derives due-ness from durable local state
/// and only re-resolves grants at their half-life (about every 150 s for the
/// 300 s system-resolver grants).
const DNS_REFRESH_CADENCE: Duration = Duration::from_secs(1);
/// Permit for one refresh pass. Revoked on service shutdown; an exhausted
/// permit aborts the pass's remaining refreshes, which never extends a grant.
const DNS_REFRESH_BUDGET: Duration = Duration::from_secs(60);
/// Shutdown grace for an in-flight loss sweep (G10R-1): admission is closed
/// first, so no new `incus` command starts; the command already running gets
/// this long to finish before its permit is revoked (which kills and reaps
/// it). Matches the relay workers' 5 s shutdown deadline.
const LOSS_SWEEP_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Debug-build-only ordering control for the cross-language cancel-wire gate
/// (`apps/server/src/sandbox-relay/cancel-wire.contract.test.ts`). While the
/// file named by `WSSP_TEST_HOLD_POLICY_RECONCILER` exists, a periodic sweep
/// skips ONLY policy inspection (the enforcement-loss drain still runs) and
/// acknowledges by creating `<path>.held`. Sweeps are serialized, so the
/// acknowledgement proves no inspection is in flight until the hold is
/// removed. This lets live-probe cases own drift detection deterministically.
/// Release builds compile this to a constant `false`, like `test_barrier`.
#[cfg(debug_assertions)]
fn policy_reconciler_test_hold() -> bool {
    let Some(hold) = std::env::var_os("WSSP_TEST_HOLD_POLICY_RECONCILER") else {
        return false;
    };
    if !std::path::Path::new(&hold).exists() {
        return false;
    }
    let mut ack = hold;
    ack.push(".held");
    let _ = std::fs::write(ack, b"");
    true
}

#[cfg(not(debug_assertions))]
fn policy_reconciler_test_hold() -> bool {
    false
}

/// Last failed attempt for one accepted lease arm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExpiryFailureRecord {
    pub generation: u64,
    pub revision: u64,
    pub failure: ExpiryFailure,
}
pub(super) type ExpiryFailures = HashMap<String, ExpiryFailureRecord>;

/// Latest completed expiry per sandbox: (generation, revision) of the arm.
/// Retained only while the journal still holds exactly that completed arm, so
/// the map is bounded by the number of managed leases.
pub(super) type ExpiryCompletions = HashMap<String, (u64, u64)>;

/// Captured BEFORE runtime observation, shared by both destructive checkpoints.
/// Owning this snapshot prevents a completion from adopting whatever generation
/// happens to be current after a slow daemon call.
struct EnforcementLossSettlement {
    journal: Arc<HostJournal>,
    authority: HostAuthority,
    completions: Arc<Mutex<ExpiryCompletions>>,
    arms: HashMap<String, LeaseRecord>,
}

/// The daemon state behind the runtime's enforcement-loss hook, owned by
/// [`ExpiryService`].
struct LossLifecycleState {
    journal: Arc<HostJournal>,
    authority: HostAuthority,
    completions: Arc<Mutex<ExpiryCompletions>>,
}
/// The hook the runtime keeps. It holds the daemon state only weakly: the
/// runtime outlives the service whenever anything else still holds it (a
/// detached thread, a test's runtime clone), and a strong journal reference
/// here kept the journal, and the exclusive state-directory lock it owns,
/// alive after a clean in-process shutdown. Once the service is gone a
/// capture vetoes every prepare (no destruction authority, retry intent kept).
struct LossLifecycle(std::sync::Weak<LossLifecycleState>);
impl std::fmt::Debug for LossLifecycle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LossLifecycle")
    }
}
struct CapturedLossIntent {
    settlement: EnforcementLossSettlement,
    id: String,
}
impl sandbox_runtime::EnforcementLossIntent for CapturedLossIntent {
    fn prepare(&self) -> Result<(), sandbox_runtime::RuntimeError> {
        self.settlement
            .checkpoint(&self.id, sandbox_runtime::EnforcementLossStage::Prepare)
    }
}
/// A capture after the daemon's expiry service ended.
struct EndedLossIntent;
impl sandbox_runtime::EnforcementLossIntent for EndedLossIntent {
    fn prepare(&self) -> Result<(), sandbox_runtime::RuntimeError> {
        Err(sandbox_runtime::RuntimeError::new(
            sandbox_protocol::SandboxErrorCode::Internal,
            "enforcement-loss lifecycle ended with the daemon's expiry service",
        ))
    }
}
impl sandbox_runtime::EnforcementLossLifecycle for LossLifecycle {
    fn capture(&self, id: &str) -> Box<dyn sandbox_runtime::EnforcementLossIntent> {
        let Some(state) = self.0.upgrade() else {
            return Box::new(EndedLossIntent);
        };
        Box::new(CapturedLossIntent {
            settlement: EnforcementLossSettlement {
                journal: state.journal.clone(),
                authority: state.authority.clone(),
                completions: state.completions.clone(),
                arms: state
                    .journal
                    .lease(id)
                    .map(|r| (id.to_owned(), r))
                    .into_iter()
                    .collect(),
            },
            id: id.to_owned(),
        })
    }
}
impl EnforcementLossSettlement {
    fn capture(
        journal: Arc<HostJournal>,
        authority: HostAuthority,
        completions: Arc<Mutex<ExpiryCompletions>>,
    ) -> Self {
        let arms = journal
            .leases()
            .into_iter()
            .map(|row| (row.sandbox_id.clone(), row))
            .collect();
        Self {
            journal,
            authority,
            completions,
            arms,
        }
    }
    fn checkpoint(
        &self,
        id: &str,
        stage: sandbox_runtime::EnforcementLossStage,
    ) -> Result<(), sandbox_runtime::RuntimeError> {
        if !self.arms.contains_key(id) && self.journal.enforcement_loss_retired(id) {
            // Prepare is a veto for a present VM. Only the runtime's positively
            // absent leg may skip it; Complete follows network absence proof.
            return if stage == sandbox_runtime::EnforcementLossStage::Complete {
                Ok(())
            } else {
                Err(sandbox_runtime::RuntimeError::new(
                    sandbox_protocol::SandboxErrorCode::SandboxNotFound,
                    "enforcement loss belongs to a retired sandbox",
                ))
            };
        }
        let result = (|| -> Result<()> {
            let row = self
                .arms
                .get(id)
                .ok_or_else(|| anyhow::anyhow!("enforcement loss has no captured lease"))?;
            self.journal.settle_enforcement_loss(row, stage)?;
            self.authority.expire_sandbox(id, row.generation);
            if stage == sandbox_runtime::EnforcementLossStage::Complete {
                self.completions
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(id.to_owned(), (row.generation, row.lease.revision));
            }
            Ok(())
        })();
        result.map_err(|err| {
            sandbox_runtime::RuntimeError::new(
                if err.is::<super::journal::StaleEnforcementLossAuthority>() {
                    sandbox_protocol::SandboxErrorCode::IdempotencyConflict
                } else {
                    sandbox_protocol::SandboxErrorCode::Internal
                },
                format!("enforcement-loss lifecycle checkpoint failed: {err:#}"),
            )
        })
    }
}

type Credentials = Arc<std::sync::OnceLock<super::credentials::service::CredentialService>>;
type Offload = Arc<std::sync::OnceLock<super::offload::OffloadService>>;

pub(super) struct ExpiryService {
    journal: Arc<HostJournal>,
    runtime: Arc<dyn SandboxRuntime>,
    shutdown: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    failures: Arc<Mutex<ExpiryFailures>>,
    completions: Arc<Mutex<ExpiryCompletions>>,
    refresh_gate: Arc<Mutex<RefreshGate>>,
    /// The disk offload service, once installed: a destroying expiry waits
    /// out an in-flight publish of the sandbox like a kill does (F13).
    offload: Offload,
    /// The only strong owner of the runtime hook's state ([`LossLifecycle`]).
    _loss_lifecycle: Arc<LossLifecycleState>,
}

#[derive(Default)]
struct RefreshGate {
    paused: usize,
    active: Option<Arc<RuntimePermit>>,
}

pub(super) struct CensusRefreshPause(Arc<Mutex<RefreshGate>>);
impl Drop for CensusRefreshPause {
    fn drop(&mut self) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).paused -= 1;
    }
}

/// Owned handles onto [`ExpiryService`] state for reconciliation workers
/// (see [`ExpiryService::handle`]).
#[derive(Clone)]
pub(super) struct ExpiryHandle {
    journal: Arc<HostJournal>,
    failures: Arc<Mutex<ExpiryFailures>>,
    refresh_gate: Arc<Mutex<RefreshGate>>,
}

impl ExpiryHandle {
    /// Stop renewal admission and join the current mutation pass before census.
    /// Autonomous DNS expiry watchers and sandbox lease teardown keep running;
    /// pausing renewals never extends a grant's persisted absolute expiry.
    /// RAII resumes admission on both success and every error return.
    pub(super) fn pause_dns_refresh(
        &self,
        shutdown: &super::connect::ShutdownSignal,
    ) -> Result<CensusRefreshPause> {
        {
            let mut gate = self.refresh_gate.lock().unwrap_or_else(|e| e.into_inner());
            gate.paused += 1;
            if let Some(permit) = &gate.active {
                permit.revoke();
            }
        }
        let pause = CensusRefreshPause(self.refresh_gate.clone());
        loop {
            anyhow::ensure!(!shutdown.requested(), "daemon shutdown requested");
            if self
                .refresh_gate
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .active
                .is_none()
            {
                return Ok(pause);
            }
            thread::sleep(TICK);
        }
    }

    /// Give overdue durable actions a bounded chance (`budget`) to settle
    /// before hello and census. A failing or slow expiry is published, never
    /// waited out: the latch already refuses all lifecycle work for that
    /// sandbox. Ends early once `fenced` holds: a worker whose session was
    /// lost stops waiting (its result is discarded anyway).
    pub(super) fn reconcile_until(
        &self,
        budget: Duration,
        fenced: &dyn Fn() -> bool,
    ) -> Result<()> {
        let deadline = Instant::now() + budget;
        loop {
            let due = self.journal.poll_expiry()?;
            if due.is_empty() {
                return Ok(());
            }
            anyhow::ensure!(!fenced(), "expiry reconciliation fenced by a lost session");
            let failures = self.failures();
            let reported = due.iter().all(|r| {
                failures
                    .get(&r.sandbox_id)
                    .is_some_and(|f| f.generation == r.generation && f.revision == r.lease.revision)
            });
            if reported || Instant::now() >= deadline {
                tracing::warn!(
                    pending = due.len(),
                    "host expiry unresolved; publishing pending state"
                );
                return Ok(());
            }
            thread::sleep(TICK);
        }
    }

    /// Whether any lease expiry is currently due (journal only, no runtime IO).
    pub(super) fn any_due(&self) -> Result<bool> {
        Ok(!self.journal.poll_expiry()?.is_empty())
    }

    /// Snapshot of failed attempts for unfinished expiries.
    pub(super) fn failures(&self) -> ExpiryFailures {
        self.failures
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

struct Attempt {
    worker: Option<JoinHandle<Result<()>>>,
    /// Immutable intent actually passed to the worker, not the latest poll row.
    intent: LeaseRecord,
    failures: u32,
    next: Instant,
    /// The lease arm (`generation`, `revision`) whose graceful stop already
    /// ran (C55-CC-1). Graceful-first is once per arm: every retry of the
    /// same arm goes straight to the forced stop, so a guest that ignores
    /// ACPI costs the grace window at most one graceful timeout.
    graceful_arm: Option<(u64, u64)>,
}
fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}
fn record_failure(
    failures: &Mutex<ExpiryFailures>,
    row: &LeaseRecord,
    attempts: u32,
    reason: &str,
) {
    let mut map = failures.lock().unwrap_or_else(|e| e.into_inner());
    let since = map
        .get(&row.sandbox_id)
        .filter(|f| f.generation == row.generation && f.revision == row.lease.revision)
        .map_or_else(wall_ms, |f| f.failure.since_unix_ms);
    map.insert(
        row.sandbox_id.clone(),
        ExpiryFailureRecord {
            generation: row.generation,
            revision: row.lease.revision,
            failure: ExpiryFailure {
                reason: sandbox_protocol::sanitize_expiry_reason(reason),
                attempts: attempts.max(1),
                since_unix_ms: since,
            },
        },
    );
}
/// WP3 (D2): stop each running command carried past `max_carry` through the
/// ordinary cancel proof path, journaling [`CancelReason::CarryExpired`] as
/// `ext.cancelReason` first, so its owner settles the proven stop FAILED
/// `host_disconnect_expired` (UNKNOWN without proof). A command whose Result
/// is already journaled (it finished while carried) or whose cancel cannot
/// be made durable is revoked instead: its receipt settles it. Returns the
/// number of stops requested.
fn stop_carried_commands(
    journal: &HostJournal,
    authority: &HostAuthority,
    stop: &[(String, u64, u64)],
) -> usize {
    let mut stopped = 0;
    for (id, generation, attempt) in stop {
        let finished = journal.lookup(id).is_some_and(|receipt| {
            receipt.generation == *generation
                && receipt.attempt == *attempt
                && receipt.phase == ReceiptPhase::Result
        });
        let requested = !finished
            && matches!(
                journal.request_cancel_for(
                    authority,
                    id,
                    *generation,
                    *attempt,
                    Some(CancelReason::CarryExpired),
                ),
                Ok(Ok(_))
            );
        if requested {
            stopped += 1;
        } else {
            authority.revoke_carried(id);
        }
    }
    stopped
}

/// WP3 (D4): guest work revoked by the carry window or the lease before its
/// effect gate settles FAILED `host_effect_not_issued` in the journal now.
/// Its queued worker may stay blocked behind busy lanes, and a reconnect (or
/// restart) before it runs must not recover a never-run attempt as UNKNOWN.
/// The write is one compare-and-set on the exact Intent attempt
/// ([`HostJournal::settle_not_issued`]): a receipt that has since moved on
/// (settled, redispatched as a later attempt, in Effect) is never touched. A
/// later worker refusal finds the terminal Result and leaves it unchanged; a
/// failed write leaves the receipt to the worker and receipt recovery.
fn settle_not_issued(journal: &HostJournal, revoked: &[(String, u64, u64)]) {
    for (id, generation, attempt) in revoked {
        if journal
            .settle_not_issued(id, *generation, *attempt)
            .is_err()
        {
            tracing::warn!(operation_id = %id,
                "carry-window revocation could not be journaled; the worker settles it");
        }
    }
}

fn log_dns_refresh(report: &sandbox_runtime::DnsRefreshReport) {
    // E-21 convention: automatic logs contain metadata and counts, never
    // workload content. INFO includes renewals; retained, unchanged grants
    // are DEBUG. One line for each successfully completed sandbox refresh.
    macro_rules! completed {
        ($level:ident) => {
            tracing::$level!(
                sandbox_id = %report.sandbox_id,
                domain_count = report.domain_count,
                changed_addresses = report.changed_addresses,
                added_addresses = report.added_addresses,
                removed_addresses = report.removed_addresses,
                next_refresh_unix_secs = report.next_refresh_unix_secs,
                "DNS grant refresh completed"
            )
        };
    }
    if let Some(warning) = report.warning {
        // Typed refresh warning (egress byte budget): nothing was published,
        // the last-good rules stay. A code, never names or addresses.
        tracing::warn!(
            sandbox_id = %report.sandbox_id,
            domain_count = report.domain_count,
            warning = warning.as_str(),
            "DNS grant refresh kept the last published rules"
        );
        return;
    }
    if report.changed_grants {
        completed!(info);
    } else {
        completed!(debug);
    }
}

impl ExpiryService {
    #[cfg(test)]
    pub fn start(
        runtime: Arc<dyn SandboxRuntime>,
        journal: Arc<HostJournal>,
        authority: HostAuthority,
    ) -> Self {
        Self::start_with_carry(runtime, journal, authority, CarryPolicy::default())
    }
    #[cfg(test)]
    pub fn start_with_carry(
        runtime: Arc<dyn SandboxRuntime>,
        journal: Arc<HostJournal>,
        authority: HostAuthority,
        carry: CarryPolicy,
    ) -> Self {
        Self::start_with_credentials(runtime, journal, authority, carry, None)
    }
    /// `carry`: how long work carried across a relay transport drop may stay
    /// unadopted (WP3, see `carry.rs`). This always-running tick enforces it,
    /// connected or not, so flapping can never extend it; the effect gate's
    /// backstop is derived from it here. The credential service is in place
    /// before the first tick (an expiry due at startup captures).
    pub fn start_with_credentials(
        runtime: Arc<dyn SandboxRuntime>,
        journal: Arc<HostJournal>,
        authority: HostAuthority,
        carry: CarryPolicy,
        initial_credentials: Option<super::credentials::service::CredentialService>,
    ) -> Self {
        authority.set_effect_gate_max_wait(carry.effect_gate_max_wait());
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop = shutdown.clone();
        let refresh_gate = Arc::new(Mutex::new(RefreshGate::default()));
        let worker_gate = refresh_gate.clone();
        let failures: Arc<Mutex<ExpiryFailures>> = Arc::default();
        let failed = failures.clone();
        let completions: Arc<Mutex<ExpiryCompletions>> = Arc::default();
        let loss_lifecycle = Arc::new(LossLifecycleState {
            journal: journal.clone(),
            authority: authority.clone(),
            completions: completions.clone(),
        });
        runtime.set_enforcement_loss_lifecycle(Arc::new(LossLifecycle(Arc::downgrade(
            &loss_lifecycle,
        ))));
        let done_arms = completions.clone();
        let j = journal.clone();
        let worker_runtime = runtime.clone();
        let credentials: Credentials = Arc::default();
        if let Some(service) = initial_credentials {
            let _ = credentials.set(service);
        }
        let worker_credentials = credentials.clone();
        let offload: Offload = Arc::default();
        let worker_offload = offload.clone();
        let log_dispatch = tracing::dispatcher::get_default(|dispatch| dispatch.clone());
        let worker = thread::spawn(move || {
            let _log = tracing::dispatcher::set_default(&log_dispatch);
            let runtime = worker_runtime;
            let mut attempts: HashMap<String, Attempt> = HashMap::new();
            // C37 R3: the dedicated, always-running cleanup pass for
            // durably recorded bound-enforcement losses. Cadence-gated and
            // SPAWNED (never inline): teardown work must not delay the
            // lease-expiry deadlines this loop owns.
            // Its permit closes and the pass is joined when this service
            // stops: a detached sweep would orphan its `incus` child (each
            // runs in its own process group) when the daemon exits.
            let mut loss_sweep: Option<(JoinHandle<()>, Arc<RuntimePermit>)> = None;
            let mut last_loss_sweep = Instant::now() - Duration::from_secs(2);
            // Domain-egress DNS grant refresh: the only production caller of
            // the runtime's refresh. One pass at a time, spawned off the
            // lease-deadline path; its permit is revoked and the pass joined
            // when this service stops (daemon shutdown).
            let mut dns_refresh: Option<(JoinHandle<()>, Arc<RuntimePermit>)> = None;
            let mut last_dns_refresh = Instant::now() - DNS_REFRESH_CADENCE;
            while !stop.load(Ordering::Acquire) {
                if dns_refresh.as_ref().is_some_and(|(h, _)| h.is_finished())
                    && let Some((handle, _)) = dns_refresh.take()
                {
                    let _ = handle.join();
                    worker_gate.lock().unwrap_or_else(|e| e.into_inner()).active = None;
                }
                let rows = match j.poll_expiry() {
                    Ok(rows) => rows,
                    Err(_) => {
                        // IO uncertainty must not admit more guest work. Retry intent
                        // persistence; never silently exit the safety service.
                        authority.shutdown();
                        tracing::error!("expiry checkpoint failed; admission closed");
                        thread::sleep(Duration::from_secs(1));
                        continue;
                    }
                };
                if j.io_failed() {
                    authority.shutdown();
                }
                let now = Instant::now();
                let lease_due: HashMap<String, u64> = rows
                    .iter()
                    .map(|row| (row.sandbox_id.clone(), row.generation))
                    .collect();
                let expired = authority.expire_detached_work(now, &carry, &lease_due);
                let stopped = stop_carried_commands(&j, &authority, &expired.stop);
                settle_not_issued(&j, &expired.not_issued);
                if expired.revoked > 0 || stopped > 0 {
                    tracing::warn!(
                        revoked = expired.revoked,
                        stopped,
                        "relay stayed unreachable past the carry window or cap; carried work ended"
                    );
                }
                let mut completed = Vec::new();
                for row in &rows {
                    authority.expire_sandbox(&row.sandbox_id, row.generation);
                    let a = attempts.entry(row.sandbox_id.clone()).or_insert(Attempt {
                        worker: None,
                        intent: row.clone(),
                        failures: 0,
                        next: now,
                        graceful_arm: None,
                    });
                    if a.worker.as_ref().is_some_and(|h| h.is_finished()) {
                        let intent = &a.intent;
                        let outcome = match a.worker.take().map(JoinHandle::join) {
                            Some(Ok(Ok(()))) => j
                                .finish_expiry(intent)
                                .map_err(|_| "expiry checkpoint not completed".to_owned())
                                .inspect(|()| {
                                    let destroyed = intent.enforcement_loss
                                        || intent.lease.action == LeaseAction::Destroy;
                                    if let Some(service) = worker_credentials.get() {
                                        service.settle_teardown(&intent.sandbox_id, destroyed);
                                    }
                                    // A completed destroying expiry
                                    // removed the root, as a confirmed kill
                                    // does: its `stored` offload entry goes
                                    // the same way (the inventory never
                                    // reports stored entries). It only
                                    // enqueues: the alias IO
                                    // runs off this deadline loop.
                                    if destroyed && let Some(offload) = worker_offload.get() {
                                        offload.forget_on_kill(&intent.sandbox_id);
                                    }
                                }),
                            Some(Ok(Err(error))) => Err(format!("{error:#}")),
                            _ => Err("expiry worker stopped unexpectedly".to_owned()),
                        };
                        let reason = match outcome {
                            Ok(()) => {
                                // Published independently of failures: a
                                // first-attempt success must also reach the
                                // server while connected.
                                done_arms.lock().unwrap_or_else(|e| e.into_inner()).insert(
                                    row.sandbox_id.clone(),
                                    (intent.generation, intent.lease.revision),
                                );
                                completed.push(row.sandbox_id.clone());
                                continue;
                            }
                            Err(reason) => reason,
                        };
                        a.failures = a.failures.saturating_add(1);
                        record_failure(&failed, row, a.failures, &reason);
                        a.next = now
                            + Duration::from_secs(
                                (1u64 << a.failures.min(6).saturating_sub(1)).min(30),
                            );
                        tracing::warn!("expiry action unresolved; retry scheduled");
                    }
                }
                // Remove by the completed attempt, even if a new arm was admitted
                // immediately after finish_expiry released the journal lock.
                {
                    let mut map = failed.lock().unwrap_or_else(|e| e.into_inner());
                    for id in &completed {
                        map.remove(id);
                    }
                    // A renewed, completed or replaced arm is no longer failing.
                    map.retain(|id, f| {
                        rows.iter().any(|r| {
                            &r.sandbox_id == id
                                && r.generation == f.generation
                                && r.lease.revision == f.revision
                        })
                    });
                }
                {
                    let mut done = done_arms.lock().unwrap_or_else(|e| e.into_inner());
                    // Keep only completions the journal still holds as that exact
                    // completed arm; a replaced or retired arm is old news.
                    done.retain(|id, &mut (generation, revision)| {
                        j.lease(id).is_some_and(|row| {
                            row.generation == generation
                                && row.lease.revision == revision
                                && row.expiry_complete
                        })
                    });
                }
                for id in completed {
                    attempts.remove(&id);
                }
                attempts.retain(|id, _| rows.iter().any(|r| &r.sandbox_id == id));
                let mut active = attempts.values().filter(|a| a.worker.is_some()).count();
                for row in rows {
                    let Some(a) = attempts.get_mut(&row.sandbox_id) else {
                        continue;
                    };
                    if a.worker.is_some() || now < a.next || active >= MAX_ACTIONS {
                        continue;
                    }
                    let runtime = runtime.clone();
                    let journal = j.clone();
                    let credentials = worker_credentials.get().cloned();
                    let offload = worker_offload.get().cloned();
                    a.intent = row.clone();
                    // Once per lease arm (C55-CC-1): recorded at spawn, so a
                    // failed or interrupted graceful attempt is never re-run
                    // for the same arm. An enforcement loss never waits.
                    let arm = (row.generation, row.lease.revision);
                    let graceful = !row.enforcement_loss && a.graceful_arm != Some(arm);
                    if graceful {
                        a.graceful_arm = Some(arm);
                    }
                    a.worker = Some(thread::spawn(move || {
                        // Also retries an in-memory loss latch after failed
                        // persistence. No destruction before durable Prepare.
                        if row.enforcement_loss
                            && let Err(err) = journal.settle_enforcement_loss(
                                &row,
                                sandbox_runtime::EnforcementLossStage::Prepare,
                            )
                        {
                            // Persistence/worker veto never permits deletion,
                            // but must not suppress the restrictive retry.
                            if let Some(credentials) = &credentials {
                                credentials.enforcement_loss(&row.sandbox_id);
                            }
                            let _ = expiry_action(&*runtime, &row, false);
                            return Err(err);
                        }
                        // A destroying expiry cancels
                        // the sandbox's unfinished offload and waits (bounded
                        // by `IMAGE_IO_TIMEOUT`) for an in-flight publish, as
                        // a kill does; the hold keeps a new publish out. A
                        // publish still running fails this attempt (retried).
                        let destroying =
                            row.enforcement_loss || row.lease.action == LeaseAction::Destroy;
                        let _offload_hold = match &offload {
                            Some(offload) if destroying => {
                                Some(offload.preempt(&row.sandbox_id, &|| true).map_err(
                                    |error| {
                                        anyhow::anyhow!(
                                            "disk offload publish still running ({:?})",
                                            error.code
                                        )
                                    },
                                )?)
                            }
                            _ => None,
                        };
                        if let Some(credentials) = &credentials {
                            if row.enforcement_loss {
                                // Lock-free: no capture, no scrub (§10.4).
                                credentials.enforcement_loss(&row.sandbox_id);
                            } else if graceful {
                                // Once per arm, before the graceful stop.
                                credential_phase(credentials, &*runtime, &row);
                            }
                        }
                        expire(&*runtime, &row, graceful)
                    }));
                    active += 1;
                }
                // C37 R3: sweep recorded enforcement losses every 2s, off
                // the deadline path. Detection paths (operations, receipt
                // settles, censuses, probes) only RECORD; this pass is what
                // guarantees a bound, unenforced VM is fenced and cleaned
                // up without waiting for lease expiry.
                if loss_sweep.as_ref().is_some_and(|(h, _)| h.is_finished())
                    && let Some((handle, _)) = loss_sweep.take()
                {
                    let _ = handle.join();
                }
                if loss_sweep.is_none() && last_loss_sweep.elapsed() >= Duration::from_secs(2) {
                    last_loss_sweep = Instant::now();
                    let runtime = runtime.clone();
                    // Capture authority BEFORE any runtime observation/IO.
                    // A late sweep can never adopt the generation it finds
                    // after deleting an older instance.
                    let settlement = EnforcementLossSettlement::capture(
                        j.clone(),
                        authority.clone(),
                        done_arms.clone(),
                    );
                    let permit = Arc::new(RuntimePermit::with_timeout(Duration::from_secs(20)));
                    let scoped = runtime.with_cancellation(permit.clone());
                    let pass_permit = permit.clone();
                    let handle = thread::spawn(move || {
                        let runtime = scoped;
                        let ids: Vec<_> = settlement
                            .arms
                            .values()
                            .filter(|row| !row.expiry_complete)
                            .map(|row| row.sandbox_id.clone())
                            .collect();
                        // Always runs in release builds; see the test hold.
                        if !policy_reconciler_test_hold()
                            && let Err(err) = runtime.reconcile_policies(&ids)
                        {
                            tracing::warn!(
                                error = %err.message,
                                "policy reconciliation failed; continuing loss cleanup"
                            );
                        }
                        // Shutdown closed admission: leave the durable losses
                        // to the next daemon's drain instead of starting one.
                        if pass_permit.is_closed() {
                            return;
                        }
                        let settle = |id: &str, stage| {
                            // Autonomous drift cleanup shares the same original-pool
                            // fences as explicit destroy and deadline expiry.
                            if let Some(a) = settlement
                                .arms
                                .get(id)
                                .and_then(|row| row.allocation.as_ref())
                            {
                                let root = super::journal::storage::allocation_root(a);
                                match stage {
                                    sandbox_runtime::EnforcementLossStage::Prepare => {
                                        runtime.observe_storage_pool(&root.pool)?;
                                    }
                                    sandbox_runtime::EnforcementLossStage::Complete => {
                                        runtime.prove_root_absent(
                                            &root,
                                            &sandbox_runtime::default_incus_instance_name(id),
                                        )?;
                                    }
                                }
                            }
                            settlement.checkpoint(id, stage)
                        };
                        if let Err(err) = runtime.drain_enforcement_losses(&settle) {
                            tracing::warn!(
                                error = %err.message,
                                "enforcement-loss drain failed; retrying next sweep"
                            );
                        }
                    });
                    loss_sweep = Some((handle, permit));
                }
                let mut gate = worker_gate.lock().unwrap_or_else(|e| e.into_inner());
                if gate.paused == 0
                    && dns_refresh.is_none()
                    && last_dns_refresh.elapsed() >= DNS_REFRESH_CADENCE
                {
                    last_dns_refresh = Instant::now();
                    // Lifecycle-owned active ids only: a stopped, destroyed or
                    // expiring sandbox drops out here, which ends its refresh
                    // schedule (its grants then lapse at their armed expiry).
                    let ids: Vec<String> = j
                        .leases()
                        .into_iter()
                        .filter(|row| !row.expired && !row.expiry_complete)
                        .map(|row| row.sandbox_id)
                        .collect();
                    if !ids.is_empty() {
                        let permit = Arc::new(RuntimePermit::with_timeout(DNS_REFRESH_BUDGET));
                        let scoped = runtime.with_cancellation(permit.clone());
                        let log_dispatch =
                            tracing::dispatcher::get_default(|dispatch| dispatch.clone());
                        match thread::Builder::new()
                            .name("wssp-dns-refresh-pass".to_owned())
                            .spawn(move || {
                                let _log = tracing::dispatcher::set_default(&log_dispatch);
                                if let Err(err) =
                                    scoped.refresh_dns_grants_observed(&ids, &log_dns_refresh)
                                {
                                    tracing::warn!(
                                        error = %err.message,
                                        "DNS grant refresh incomplete; retrying next pass"
                                    );
                                }
                            }) {
                            Ok(handle) => {
                                gate.active = Some(permit.clone());
                                dns_refresh = Some((handle, permit));
                            }
                            Err(err) => tracing::warn!(
                                error = %err,
                                "cannot start the DNS grant refresh pass; retrying"
                            ),
                        }
                    }
                }
                drop(gate);
                thread::sleep(TICK);
            }
            // Daemon shutdown: abort and join the in-flight DNS refresh pass so
            // no refresh outlives the service (its grants keep their armed
            // expiry leases).
            if let Some((handle, permit)) = dns_refresh.take() {
                permit.revoke();
                let _ = handle.join();
            }
            // G10R-1: never detach the loss sweep. No new runtime command is
            // admitted; the in-flight one finishes within the grace, or is
            // preempted (killed and reaped) and its durable Prepare is left
            // for the next drain, exactly as after a crash.
            if let Some((handle, permit)) = loss_sweep.take() {
                permit.close();
                let deadline = Instant::now() + LOSS_SWEEP_SHUTDOWN_GRACE;
                while !handle.is_finished() && Instant::now() < deadline {
                    thread::sleep(TICK);
                }
                if !handle.is_finished() {
                    permit.revoke();
                }
                let _ = handle.join();
            }
            // Only service shutdown after idle or a process teardown reaches here.
            for (_, a) in attempts {
                if let Some(h) = a.worker {
                    let _ = h.join();
                }
            }
        });
        Self {
            journal,
            runtime,
            shutdown,
            worker: Some(worker),
            failures,
            completions,
            refresh_gate,
            offload,
            _loss_lifecycle: loss_lifecycle,
        }
    }

    /// Install the disk offload service: a destroying expiry then waits out
    /// an in-flight publish of its sandbox.
    pub(super) fn install_offload(&self, offload: super::offload::OffloadService) {
        let _ = self.offload.set(offload);
    }

    /// The owned, `'static` part of this service that a reconciliation
    /// worker needs (journal polls, the refresh gate, failure snapshots). A
    /// worker fenced by a lost session keeps only these handles alive, never
    /// the service (whose drop joins the expiry worker).
    pub(super) fn handle(&self) -> ExpiryHandle {
        ExpiryHandle {
            journal: self.journal.clone(),
            failures: self.failures.clone(),
            refresh_gate: self.refresh_gate.clone(),
        }
    }

    /// See [`ExpiryHandle::pause_dns_refresh`].
    pub fn pause_dns_refresh(
        &self,
        shutdown: &super::connect::ShutdownSignal,
    ) -> Result<CensusRefreshPause> {
        self.handle().pause_dns_refresh(shutdown)
    }

    /// See [`ExpiryHandle::reconcile_until`].
    #[cfg(all(test, unix))]
    pub fn reconcile(&self) -> Result<()> {
        self.reconcile_within(RECONCILE_BUDGET)
    }
    #[cfg(all(test, unix))]
    fn reconcile_within(&self, budget: Duration) -> Result<()> {
        self.handle().reconcile_until(budget, &|| false)
    }
    /// Snapshot of failed attempts for unfinished expiries.
    pub fn failures(&self) -> ExpiryFailures {
        self.handle().failures()
    }
    /// Snapshot of completed lease-arm expiries not yet known to be published.
    pub fn completions(&self) -> ExpiryCompletions {
        self.completions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    /// A terminal relay credential error ends only the relay. Keep the process
    /// and the exclusive journal lock alive until every accepted lease settles.
    /// Waits until every accepted lease settled AND, while the authority
    /// revocation marker exists, every managed VM is confirmed stopped or
    /// absent. Lease deadlines are not the only way out of a revocation: the
    /// stop obligation is retried here with fresh permits and backoff.
    pub(super) fn wait_idle_with(
        &self,
        shutdown: &super::connect::ShutdownSignal,
        mut obligation: super::revocation::StopObligation,
    ) {
        let mut last_census: Option<Instant> = None;
        while !shutdown.requested() {
            let stop_pending = obligation.poll(&self.journal, self.runtime.as_ref(), &|| {
                shutdown.requested()
            });
            let leases_pending = self.journal.leases().iter().any(|r| !r.expiry_complete);
            if !leases_pending && !stop_pending {
                return;
            }
            if !leases_pending {
                thread::sleep(TICK);
                continue;
            }
            if last_census.is_some_and(|at| at.elapsed() < CENSUS_INTERVAL) {
                thread::sleep(TICK);
                continue;
            }
            // Relay workers have lost authority. Already-stopped/absent guests
            // need no future stop; a stopped destroy lease still needs its timer.
            let Ok(scope) = super::connect::RuntimeIoGuard::arm(shutdown, Duration::from_secs(5))
            else {
                if stop_pending {
                    thread::sleep(TICK);
                    continue;
                }
                return;
            };
            last_census = Some(Instant::now());
            let runtime = self.runtime.with_cancellation(scope.permit.clone());
            if let Ok(inventory) = runtime.sandbox_inventory() {
                for row in self
                    .journal
                    .leases()
                    .into_iter()
                    .filter(|r| !r.expiry_complete && !r.expired)
                {
                    let state = inventory
                        .iter()
                        .find(|entry| entry.sandbox_id == row.sandbox_id)
                        .map(|entry| entry.state);
                    let absent = matches!(
                        state,
                        None | Some(
                            sandbox_protocol::SandboxLifecycleState::Deleted
                                | sandbox_protocol::SandboxLifecycleState::Absent
                        )
                    );
                    if absent
                        || (row.lease.action == LeaseAction::Stop
                            && state == Some(sandbox_protocol::SandboxLifecycleState::Stopped))
                    {
                        // Only absence is compaction proof: a stopped stop-lease
                        // VM still needs its durable record for the census.
                        let _ = self.journal.retire_inactive_lease(&row, absent);
                    }
                }
            }
            thread::sleep(TICK);
        }
    }
}
impl Drop for ExpiryService {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
/// Local expiry's credential phase (§10.4 Expiry): ≤ 20 s of pre-checks,
/// quiesce, pack, seal, upload attempt and scrub (destroy-on-expiry: no
/// scrub), joined with the server's expiry STOP on one teardown attempt.
/// A system teardown is never refused: whatever it could not capture stays
/// on the disk, recovery-required. Its outcome never blocks the stop.
fn credential_phase(
    credentials: &super::credentials::service::CredentialService,
    runtime: &dyn SandboxRuntime,
    row: &LeaseRecord,
) {
    use super::credentials::service::{
        EXPIRY_CREDENTIAL_PHASE, TeardownPath, TeardownRequest, TeardownVerdict,
    };
    let guest = row.guest.as_ref().map_or_else(
        || sandbox_runtime::CredentialGuest {
            sandbox_id: row.sandbox_id.clone(),
            uid: 1000,
            gid: 1000,
            home: "/home/user".into(),
        },
        |g| sandbox_runtime::CredentialGuest {
            sandbox_id: row.sandbox_id.clone(),
            uid: g.guest_uid,
            gid: g.guest_gid,
            home: g.guest_home.clone(),
        },
    );
    let request = TeardownRequest {
        operation_id: format!("local-expiry:{}:{}", row.generation, row.lease.revision),
        guest,
        sandbox_owner_id: row.sandbox_owner_id.clone(),
        host_owner_id: Some(row.binding.host_owner_id.clone()).filter(|id| !id.is_empty()),
        path: TeardownPath::Expiry {
            destroy: row.lease.action == LeaseAction::Destroy,
        },
        system: true,
        skip: false,
        spec_unverified: false,
        generation: row.generation,
        budget: EXPIRY_CREDENTIAL_PHASE,
    };
    let verdict = credentials.teardown(runtime, &request, None, &|| true, &|_| Ok(()));
    if matches!(verdict, TeardownVerdict::Uncertain) {
        tracing::warn!("expiry credential phase could not be journaled; stopping anyway");
    }
}

fn expire(runtime: &dyn SandboxRuntime, row: &LeaseRecord, graceful: bool) -> Result<()> {
    // Graceful first (C55): a bounded guest shutdown, then the forced path
    // ALWAYS runs. It is the only completion proof (on an already stopped VM
    // it just observes the stopped state), so terminal and quota release
    // semantics are unchanged. An enforcement loss never waits: a VM whose
    // egress is no longer enforced is stopped by force at once. `graceful` is
    // false on every retry of an arm whose graceful attempt already ran
    // (C55-CC-1).
    if graceful && !row.enforcement_loss {
        graceful_stop(runtime, row);
    }
    expiry_action(
        runtime,
        row,
        row.enforcement_loss || row.lease.action == LeaseAction::Destroy,
    )
}

/// One bounded graceful stop attempt. Its outcome is advisory only: success
/// or failure, the caller proceeds to the forced stop.
fn graceful_stop(runtime: &dyn SandboxRuntime, row: &LeaseRecord) -> bool {
    let runtime =
        runtime.with_cancellation(Arc::new(RuntimePermit::with_timeout(GRACEFUL_STOP_BUDGET)));
    let stopped = runtime
        .stop_sandbox_graceful(
            &StopSandboxRequest {
                operation_id: format!("local-expiry:{}:{}", row.generation, row.lease.revision),
                template_fingerprint: row.template_fingerprint.clone().unwrap_or_default(),
                sandbox_id: row.sandbox_id.clone(),
                instance_name: sandbox_runtime::default_incus_instance_name(&row.sandbox_id),
                idempotency_key: format!(
                    "local-expiry:{}:{}:graceful-stop",
                    row.generation, row.lease.revision
                ),
            },
            GRACEFUL_STOP_TIMEOUT,
        )
        .is_ok();
    if !stopped {
        tracing::info!("graceful expiry stop did not complete; forcing");
    }
    stopped
}
fn expiry_action(runtime: &dyn SandboxRuntime, row: &LeaseRecord, destroy: bool) -> Result<()> {
    // Existing stop is forced. Attempt it immediately, including before destroy,
    // so deletion failures cannot defer the required force attempt to +60 s.
    let stop_runtime =
        runtime.with_cancellation(Arc::new(RuntimePermit::with_timeout(ACTION_BUDGET)));
    let name = sandbox_runtime::default_incus_instance_name(&row.sandbox_id);
    let result = (|| -> Result<()> {
        stop_runtime
            .stop_sandbox(&StopSandboxRequest {
                operation_id: format!("local-expiry:{}:{}", row.generation, row.lease.revision),
                template_fingerprint: row.template_fingerprint.clone().unwrap_or_default(),
                sandbox_id: row.sandbox_id.clone(),
                instance_name: name.clone(),
                idempotency_key: format!(
                    "local-expiry:{}:{}:stop",
                    row.generation, row.lease.revision
                ),
            })
            .map_err(|e| anyhow::anyhow!(e.into_error()))?;
        if destroy {
            let request = KillSandboxRequest {
                operation_id: format!("local-expiry:{}:{}", row.generation, row.lease.revision),
                template_fingerprint: row.template_fingerprint.clone().unwrap_or_default(),
                sandbox_id: row.sandbox_id.clone(),
                instance_name: name,
                idempotency_key: format!(
                    "local-expiry:{}:{}:destroy",
                    row.generation, row.lease.revision
                ),
            };
            let destroy_runtime =
                runtime.with_cancellation(Arc::new(RuntimePermit::with_timeout(ACTION_BUDGET)));
            let result = if let Some(a) = &row.allocation {
                destroy_runtime
                    .kill_sandbox_on_storage(&request, &super::journal::storage::allocation_root(a))
            } else {
                anyhow::bail!("expiry requires the original pinned allocation")
            };
            result.map_err(|e| anyhow::anyhow!(e.into_error()))?;
        }
        Ok(())
    })();
    if result.is_err() {
        // The timer and a server teardown have independent authority. A
        // stop/delete can fail after binding a VM that the other caller then
        // deleted. Observe again before retrying: the runtime's absence proof
        // includes network cleanup, and the template binding prevents a
        // foreign/replaced instance from being mistaken for completion.
        let proof_runtime =
            runtime.with_cancellation(Arc::new(RuntimePermit::with_timeout(ACTION_BUDGET)));
        let observed =
            proof_runtime.query_sandbox(&row.sandbox_id, None, row.template_fingerprint.as_deref());
        let root_absent = row.allocation.as_ref().is_none_or(|a| {
            proof_runtime
                .prove_root_absent(
                    &super::journal::storage::allocation_root(a),
                    &sandbox_runtime::default_incus_instance_name(&row.sandbox_id),
                )
                .is_ok()
        });
        if (root_absent
            && matches!(
                observed,
                Ok(None
                    | Some(
                        sandbox_protocol::SandboxLifecycleState::Absent
                            | sandbox_protocol::SandboxLifecycleState::Deleted
                    ))
            ))
            || (!destroy
                && matches!(
                    observed,
                    Ok(Some(sandbox_protocol::SandboxLifecycleState::Stopped))
                ))
        {
            return Ok(());
        }
    }
    result
}

pub(super) fn check_inventory(
    journal: &HostJournal,
    inventory: &[sandbox_runtime::RuntimeInventoryEntry],
) -> Result<()> {
    for entry in inventory {
        let (id, state) = (&entry.sandbox_id, &entry.state);
        if matches!(
            state,
            sandbox_protocol::SandboxLifecycleState::Deleted
                | sandbox_protocol::SandboxLifecycleState::Absent
        ) {
            continue;
        }
        let Some(row) = journal.lease(id) else {
            bail!("managed instance has no durable lease; host admission refused");
        };
        if row.expired
            && row.expiry_complete
            && (row.enforcement_loss
                || row.lease.action == LeaseAction::Destroy
                || *state != sandbox_protocol::SandboxLifecycleState::Stopped)
        {
            journal.reopen_expiry(&row)?;
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests;
