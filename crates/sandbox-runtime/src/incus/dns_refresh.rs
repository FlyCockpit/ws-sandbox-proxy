//! Production DNS-grant refresh scheduler.
//!
//! Domain grants are host-resolved IPv4 destinations armed with an
//! enforcement-level expiry lease (`dns.rs`): at expiry the lease watcher
//! fences and withdraws the allow whether or not anything else runs. This
//! module is what keeps a LIVE sandbox's grants from lapsing: one bounded
//! pass, driven by the node daemon's expiry service off the lease-deadline
//! path, re-resolves the recorded domain policy of every due, running,
//! verified sandbox and re-issues the answers through the SAME journaled,
//! fenced `enforce_and_commit_refresh_plan` boundary the create path uses,
//! which re-arms the lease with the fresh deadline.
//!
//! Scheduling is derived from DURABLE state on every pass (the recorded plan
//! policy and the persisted DNS grants), so a restarted daemon resumes
//! without any in-memory schedule; the only memory is a per-sandbox
//! last-attempt time (retry backoff), pruned to the caller's active set.
//!
//! Failure never extends a grant: a failed lookup keeps only the UNEXPIRED
//! prior answer with its ORIGINAL expiry (planning), a failed or skipped
//! refresh leaves the armed lease untouched, and the watcher fences at that
//! expiry. Skipping is therefore always the safe choice: busy, stopped,
//! drift-refused, loss-recorded and unreadable sandboxes are skipped.
//!
//! Lock order: the scheduler's `attempts` mutex is never held across a
//! refresh. Names are resolved with NO lock held; the refresh then takes
//! `sandbox_lock` (try-lock only: a busy lifecycle operation defers the
//! sandbox to the next pass), re-checks the VM is running, and takes the DNS
//! lease owner locks inside the shared boundary, the same order the wire
//! refresh uses; the lease watcher never takes `sandbox_lock`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use sandbox_protocol::{EgressPolicy, SandboxErrorCode};

use super::client::IncusClient;
use super::dns::{MAX_REFRESH_TTL_SECS, MIN_REFRESH_TTL_SECS, SandboxDnsState};
use crate::{DnsRefreshReport, RuntimeError};

/// Concurrent refreshes per pass (each is mostly blocking resolver and
/// daemon IO).
pub(crate) const REFRESH_PARALLELISM: usize = 4;
/// Refreshes started per pass, most urgent first; the rest wait for the
/// next pass (the daemon runs one pass at a time, about once a second).
pub(crate) const REFRESH_BATCH: usize = 16;
/// Minimum spacing between attempts for a sandbox whose grants are due.
pub(crate) const REFRESH_RETRY_SECS: u64 = 15;
/// Spacing for re-resolving names that currently have NO grant (denied,
/// failed or lapsed), so a name that recovers is granted again.
pub(crate) const MISSING_RETRY_SECS: u64 = 60;
/// Resolution budget for one sandbox's refresh (all of its names).
pub(crate) const REFRESH_RESOLVE_BUDGET: Duration = Duration::from_secs(10);

/// Lifecycle priority is shared by scoped clients. The count is a
/// lifecycle-wants-lock flag; active refresh permits make that request
/// observable between host IO steps and during cancellable command waits.
#[derive(Debug, Default)]
pub(crate) struct DnsLifecyclePriority {
    state: Mutex<DnsPriorityState>,
}
#[derive(Debug, Default)]
struct DnsPriorityState {
    wants_lock: usize,
    refreshes: Vec<std::sync::Weak<crate::RuntimePermit>>,
}
pub(crate) type DnsPriorityRegistry =
    std::sync::Arc<Mutex<BTreeMap<String, std::sync::Weak<DnsLifecyclePriority>>>>;

pub(crate) struct LifecyclePriorityGuard(std::sync::Arc<DnsLifecyclePriority>);
impl Drop for LifecyclePriorityGuard {
    fn drop(&mut self) {
        let mut state = self.0.state.lock().unwrap_or_else(|err| err.into_inner());
        state.wants_lock = state.wants_lock.saturating_sub(1);
    }
}
struct RefreshPriorityGuard {
    priority: std::sync::Arc<DnsLifecyclePriority>,
    permit: std::sync::Arc<crate::RuntimePermit>,
}
impl Drop for RefreshPriorityGuard {
    fn drop(&mut self) {
        let own = std::sync::Arc::downgrade(&self.permit);
        self.priority
            .state
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .refreshes
            .retain(|permit| !permit.ptr_eq(&own) && permit.strong_count() > 0);
    }
}

impl IncusClient {
    fn dns_lifecycle_priority(&self, sandbox_id: &str) -> std::sync::Arc<DnsLifecyclePriority> {
        let mut registry = self
            .dns_priority
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        if let Some(existing) = registry.get(sandbox_id).and_then(std::sync::Weak::upgrade) {
            return existing;
        }
        registry.retain(|_, entry| entry.strong_count() > 0);
        let priority = std::sync::Arc::new(DnsLifecyclePriority::default());
        registry.insert(sandbox_id.to_owned(), std::sync::Arc::downgrade(&priority));
        priority
    }

    pub(crate) fn request_lifecycle_priority(&self, sandbox_id: &str) -> LifecyclePriorityGuard {
        let priority = self.dns_lifecycle_priority(sandbox_id);
        {
            let mut state = priority.state.lock().unwrap_or_else(|err| err.into_inner());
            state.wants_lock += 1;
            for permit in state.refreshes.iter().filter_map(std::sync::Weak::upgrade) {
                permit.revoke();
            }
        }
        LifecyclePriorityGuard(priority)
    }

    fn background_dns_scope(&self, sandbox_id: &str) -> Option<(Self, RefreshPriorityGuard)> {
        let priority = self.dns_lifecycle_priority(sandbox_id);
        let permit = std::sync::Arc::new(crate::RuntimePermit::linked(self.cancelled.clone()));
        {
            let mut state = priority.state.lock().unwrap_or_else(|err| err.into_inner());
            if state.wants_lock > 0 {
                return None;
            }
            state.refreshes.retain(|permit| permit.strong_count() > 0);
            state.refreshes.push(std::sync::Arc::downgrade(&permit));
        }
        let mut scoped = self.clone();
        scoped.cancelled = Some(permit.clone());
        Some((scoped, RefreshPriorityGuard { priority, permit }))
    }
}

/// In-memory scheduler state shared by every clone of the runtime.
#[derive(Default)]
pub(crate) struct DnsRefreshScheduler {
    /// sandbox id → UNIX seconds of the last attempt started.
    attempts: Mutex<BTreeMap<String, u64>>,
    #[cfg(test)]
    pub(crate) stats: RefreshStats,
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct RefreshStats {
    pub(crate) in_flight: AtomicUsize,
    pub(crate) max_in_flight: AtomicUsize,
    pub(crate) started: AtomicUsize,
    /// Optional per-refresh delay so tests can observe the concurrency bound.
    pub(crate) hold: Mutex<Option<Duration>>,
}

/// What one pass did (diagnostics and tests).
#[derive(Debug, Default)]
pub(crate) struct DnsRefreshPass {
    pub(crate) refreshed: Vec<String>,
    pub(crate) reports: Vec<DnsRefreshReport>,
    pub(crate) failed: Vec<(String, RuntimeError)>,
    /// Due but skipped (busy, not running, refused, loss recorded, cancelled).
    pub(crate) skipped: Vec<String>,
}

/// When is this sandbox due? `None` = not due. `Some(urgency)` sorts
/// ascending: the smallest remaining grant lifetime first; a sandbox whose
/// only reason is a missing grant sorts last.
pub(crate) fn refresh_due(
    domains: &[String],
    state: Option<&SandboxDnsState>,
    last_attempt: Option<u64>,
    now: u64,
) -> Option<u64> {
    let grants = state.map(|state| state.grants.as_slice()).unwrap_or(&[]);
    let since = last_attempt.map(|at| now.saturating_sub(at));
    let mut urgent: Option<u64> = None;
    for entry in grants {
        if !domains.contains(&entry.name) {
            continue;
        }
        let ttl = if entry.ttl == 0 {
            MAX_REFRESH_TTL_SECS
        } else {
            entry.ttl.max(MIN_REFRESH_TTL_SECS)
        };
        let remaining = entry.expires_at.saturating_sub(now);
        // Refresh at half-life: with the 300 s system-resolver grants that
        // leaves ~150 s of retries before the original expiry fences.
        if remaining <= u64::from(ttl / 2) {
            urgent = Some(urgent.map_or(remaining, |u| u.min(remaining)));
        }
    }
    if let Some(remaining) = urgent
        && since.is_none_or(|since| since >= REFRESH_RETRY_SECS)
    {
        return Some(remaining);
    }
    let missing = domains
        .iter()
        .any(|domain| !grants.iter().any(|entry| &entry.name == domain));
    if missing && since.is_none_or(|since| since >= MISSING_RETRY_SECS) {
        return Some(u64::MAX);
    }
    None
}

impl DnsRefreshScheduler {
    /// Forget sandboxes the caller no longer reports active (stopped,
    /// destroyed, expired): their schedule ends with their lease.
    fn prune(&self, active: &[String]) {
        self.attempts
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .retain(|id, _| active.contains(id));
    }

    fn last_attempt(&self, sandbox_id: &str) -> Option<u64> {
        self.attempts
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .get(sandbox_id)
            .copied()
    }

    fn mark(&self, sandbox_id: &str, now: u64) {
        self.attempts
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .insert(sandbox_id.to_owned(), now);
    }

    fn unmark(&self, sandbox_id: &str) {
        self.attempts
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .remove(sandbox_id);
    }

    #[cfg(test)]
    pub(crate) fn tracked(&self) -> Vec<String> {
        self.attempts
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .keys()
            .cloned()
            .collect()
    }
}

/// One bounded pass at wall-clock time.
pub(crate) fn refresh_pass(
    client: &IncusClient,
    scheduler: &DnsRefreshScheduler,
    active: &[String],
) -> Result<DnsRefreshPass, RuntimeError> {
    refresh_pass_at(client, scheduler, active, client.dns_clock.unix_now()?)
}

/// One bounded pass with an explicit scheduling clock (`now`, UNIX
/// seconds). Only the due/backoff decision uses `now`; grant expiries are
/// always computed by the refresh itself from the wall clock at answer time.
pub(crate) fn refresh_pass_at(
    client: &IncusClient,
    scheduler: &DnsRefreshScheduler,
    active: &[String],
    now: u64,
) -> Result<DnsRefreshPass, RuntimeError> {
    scheduler.prune(active);
    let mut due: Vec<(u64, String, EgressPolicy, String)> = Vec::new();
    for id in active {
        if crate::validate_managed_instance_name(&crate::default_incus_instance_name(id)).is_err() {
            continue;
        }
        // No recorded domain policy (domain-free, legacy or malformed
        // record, torn down): nothing to refresh.
        let Some((policy, hash)) = client.recorded_refresh_policy(id) else {
            continue;
        };
        let state = client.load_dns_state(id, &hash);
        let last_attempt = scheduler.last_attempt(id);
        let urgency =
            refresh_due(&policy.domains, state.as_ref(), last_attempt, now).or_else(|| {
                // An OWED refresh (C58 NEW-1: an earlier refresh mutated live
                // enforcement and failed before its commit, or left pending
                // mutations) is retried at the due-grant spacing even when no
                // grant is near expiry: until it commits, readiness refuses
                // the sandbox (inconclusive) and guest dispatch stays fenced.
                (commit_needed(client, id)
                    && last_attempt.is_none_or(|at| now.saturating_sub(at) >= REFRESH_RETRY_SECS))
                .then_some(0)
            });
        if let Some(urgency) = urgency {
            due.push((urgency, id.clone(), policy, hash));
        }
    }
    due.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    due.truncate(REFRESH_BATCH);
    for (_, id, _, _) in &due {
        scheduler.mark(id, now);
    }
    let pass = Mutex::new(DnsRefreshPass::default());
    let next = AtomicUsize::new(0);
    let worker = || {
        loop {
            let index = next.fetch_add(1, Ordering::AcqRel);
            let Some((_, id, policy, hash)) = due.get(index) else {
                return;
            };
            #[cfg(test)]
            let gauge = InFlight::enter(&scheduler.stats);
            let result = refresh_one(client, scheduler, id, policy, hash);
            #[cfg(test)]
            drop(gauge);
            let mut pass = pass.lock().unwrap_or_else(|err| err.into_inner());
            match result {
                Ok(Some(report)) => {
                    pass.refreshed.push(id.clone());
                    pass.reports.push(report);
                }
                Ok(None) => pass.skipped.push(id.clone()),
                Err(err) => pass.failed.push((id.clone(), err)),
            }
        }
    };
    let workers = REFRESH_PARALLELISM.min(due.len());
    // Scoped workers: every one is joined before the pass returns, so a
    // pass can never leak a thread past its caller (daemon shutdown joins the
    // caller).
    std::thread::scope(|scope| {
        for _ in 1..workers {
            // A failed spawn degrades parallelism, never correctness: the
            // calling thread below still drains the whole batch.
            let _ = std::thread::Builder::new()
                .name("wssp-dns-refresh".to_owned())
                .spawn_scoped(scope, worker);
        }
        if workers > 0 {
            worker();
        }
    });
    Ok(pass.into_inner().unwrap_or_else(|err| err.into_inner()))
}

/// Refresh one sandbox if it is safe to: `Ok(None)` = skipped.
fn refresh_one(
    client: &IncusClient,
    scheduler: &DnsRefreshScheduler,
    sandbox_id: &str,
    policy: &EgressPolicy,
    hash: &str,
) -> Result<Option<DnsRefreshReport>, RuntimeError> {
    let Some((scoped, _priority)) = client.background_dns_scope(sandbox_id) else {
        scheduler.unmark(sandbox_id);
        return Ok(None);
    };
    let client = &scoped;
    if client
        .cancelled
        .as_deref()
        .is_some_and(crate::RuntimePermit::is_cancelled)
    {
        // Daemon shutdown (or an exhausted pass budget): start nothing new.
        scheduler.unmark(sandbox_id);
        return Ok(None);
    }
    // Drift handling (C37/C38) owns a sandbox whose enforcement is not
    // currently verified: a recorded loss or a reconciler refusal. The grants
    // lapse at their armed expiry instead of being renewed. EXCEPT a refusal
    // whose cause is the owed refresh itself (C58 NEW-1, G1-R1-3): the
    // reconciler refuses an uncommitted refresh as inconclusive, and the
    // refresh is the only thing that can commit it — skipping it would
    // strand the sandbox refused until its lease ends. Any OTHER refusal
    // cause (unreadable evidence, a failed recovery, a stale-authority
    // conflict, startup) still blocks the refresh. The refresh stays
    // fail-closed on its own (recorded-policy fence, strict readback,
    // journaled issuance); a recorded LOSS still skips.
    let refused = client
        .policy_refusals
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .contains(sandbox_id);
    if refused {
        let owed_cause = client
            .owed_refusals
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .contains(sandbox_id);
        if !(owed_cause && client.dns_refresh_owed(sandbox_id)) {
            return Ok(None);
        }
    }
    match std::fs::symlink_metadata(
        client
            .enforcement_loss_dir()
            .join(format!("{sandbox_id}.json")),
    ) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        // A loss record (or an unreadable directory): never renew.
        _ => return Ok(None),
    }
    // Only a running VM is kept alive. Observed BEFORE resolving (no
    // lookups for stopped sandboxes) and again under the sandbox lock.
    // EXCEPT an owed commit (C58 G1-R3-1): the refresh mutates only the
    // host-side bridge and ACL, and it is the ONLY production trigger that
    // retires an owed mark — skipping a stopped VM left it refused at
    // every start and reconnect until teardown. A missing or foreign
    // instance is never refreshed (its teardown retires the mark).
    if !refreshable(client, sandbox_id)? {
        return Ok(None);
    }
    let lock = client.sandbox_lock(sandbox_id);
    // DNS-P2-6: probe the lock BEFORE resolving. A busy lifecycle
    // operation would make the post-resolution try-lock below fail and
    // unmark the sandbox, so every ~1 s pass would re-resolve every name
    // for as long as the operation runs. The probe is released at once
    // (resolution must never hold the lock); a lock taken between the
    // probe and the post-resolution try-lock still defers safely there.
    match lock.try_lock() {
        Ok(_) | Err(std::sync::TryLockError::Poisoned(_)) => {}
        Err(std::sync::TryLockError::WouldBlock) => {
            scheduler.unmark(sandbox_id);
            return Ok(None);
        }
    }
    // Resolve OUTSIDE the sandbox lock: lookups are bounded
    // (REFRESH_RESOLVE_BUDGET, the pass permit) but must never hold a
    // lifecycle operation (expiry stop, kill) behind DNS. Each outcome
    // carries its own answer-time expiry, so resolving early can only make
    // a grant expire earlier, never later.
    let limits = super::network::CompileLimits {
        deadline: std::time::Instant::now() + REFRESH_RESOLVE_BUDGET,
        cancelled: client.cancelled.as_deref(),
    };
    let mut resolved = BTreeMap::new();
    for domain in &policy.domains {
        let outcome = match limits.check() {
            Ok(()) => super::dns::resolve_policy_name_system(client, sandbox_id, domain, &limits),
            Err(err) => Err(super::dns::ResolveDeny::transient(err)),
        };
        resolved.insert(domain.clone(), outcome);
    }
    let resolved = Mutex::new(resolved);
    // A busy lifecycle operation (create, reconnect, stop, kill, probe)
    // owns the sandbox: never wait behind it; retry on the next pass.
    let _guard = match lock.try_lock() {
        Ok(guard) => guard,
        Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        Err(std::sync::TryLockError::WouldBlock) => {
            scheduler.unmark(sandbox_id);
            return Ok(None);
        }
    };
    // Re-observed under the lock: a stop or kill that ran meanwhile wins.
    if !refreshable(client, sandbox_id)? {
        return Ok(None);
    }
    // Both snapshots share the lifecycle lock with the successful commit.
    // A later stop/refresh cannot contaminate these diagnostics.
    let prior = client.load_dns_state(sandbox_id, hash);
    let refreshed = client.refresh_dns_policy_locked(
        sandbox_id,
        policy,
        hash,
        REFRESH_RESOLVE_BUDGET,
        &|domain, _limits| {
            resolved
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .remove(domain)
                .unwrap_or_else(|| {
                    Err(super::dns::ResolveDeny::transient(RuntimeError::new(
                        SandboxErrorCode::Internal,
                        format!("egress domain `{domain}` was not resolved this pass"),
                    )))
                })
        },
    );
    // Over the byte budget: nothing was published; report the typed
    // warning with the unchanged (last-good) state.
    let warning = match refreshed {
        Ok(_) => None,
        Err(err) if err.egress_refusal() == Some(crate::EgressRefusal::RefreshOverBudget) => {
            Some(crate::EgressRefusal::RefreshOverBudget)
        }
        Err(err) => return Err(err),
    };
    let committed = client.load_dns_state(sandbox_id, hash);
    let attempted_at = scheduler.last_attempt(sandbox_id).unwrap_or(0);
    let completed_at = client.dns_clock.unix_now().unwrap_or(attempted_at);
    let mut report = refresh_report(
        sandbox_id,
        policy,
        prior.as_ref(),
        committed.as_ref(),
        attempted_at,
        completed_at,
    );
    report.warning = warning;
    Ok(Some(report))
}

/// Only counts leave the runtime: domain names and resolved addresses stay local.
fn refresh_report(
    sandbox_id: &str,
    policy: &EgressPolicy,
    prior: Option<&SandboxDnsState>,
    committed: Option<&SandboxDnsState>,
    attempted_at: u64,
    completed_at: u64,
) -> DnsRefreshReport {
    let before = prior.map_or(&[][..], |state| state.grants.as_slice());
    let after = committed.map_or(&[][..], |state| state.grants.as_slice());
    let addresses = |grants: &[super::dns::DnsGrantEntry]| -> BTreeSet<(String, String)> {
        grants
            .iter()
            .flat_map(|entry| {
                entry
                    .addresses
                    .iter()
                    .map(|address| (entry.name.clone(), address.clone()))
            })
            .collect()
    };
    let before_addresses = addresses(before);
    let after_addresses = addresses(after);
    let added_addresses = after_addresses.difference(&before_addresses).count();
    let removed_addresses = before_addresses.difference(&after_addresses).count();
    // Mirror refresh_due: grant half-life, a 15s attempt backoff and a 60s
    // missing-name backoff. This is the next refresh, rather than grant expiry.
    let next_grant = after
        .iter()
        .filter(|entry| policy.domains.contains(&entry.name))
        .map(|entry| {
            let ttl = if entry.ttl == 0 {
                MAX_REFRESH_TTL_SECS
            } else {
                entry.ttl.max(MIN_REFRESH_TTL_SECS)
            };
            entry
                .expires_at
                .saturating_sub(u64::from(ttl / 2))
                .max(attempted_at.saturating_add(REFRESH_RETRY_SECS))
        })
        .min();
    let next_missing = policy
        .domains
        .iter()
        .any(|name| !after.iter().any(|entry| &entry.name == name))
        .then_some(attempted_at.saturating_add(MISSING_RETRY_SECS));
    let next_refresh_unix_secs = next_grant
        .into_iter()
        .chain(next_missing)
        .min()
        .unwrap_or_else(|| attempted_at.saturating_add(MISSING_RETRY_SECS))
        .max(completed_at);
    DnsRefreshReport {
        sandbox_id: sandbox_id.into(),
        domain_count: policy.domains.len(),
        changed_grants: before != after,
        changed_addresses: added_addresses + removed_addresses,
        added_addresses,
        removed_addresses,
        next_refresh_unix_secs,
        warning: None,
    }
}

/// Does this sandbox owe a COMMIT (C58 G1-R3-1/2): an uncommitted refresh
/// or revocation in the marker, or a reconciler refusal whose cause was the
/// owed refresh (a journaled uncertain allow that landed)?
fn commit_needed(client: &IncusClient, sandbox_id: &str) -> bool {
    client.dns_commit_owed(sandbox_id)
        || client
            .owed_refusals
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .contains(sandbox_id)
}

/// May this sandbox be refreshed now? A running owned VM always; a STOPPED
/// owned VM only to commit owed work (C58 G1-R3-1); absent or foreign never.
fn refreshable(client: &IncusClient, sandbox_id: &str) -> Result<bool, RuntimeError> {
    let name = crate::default_incus_instance_name(sandbox_id);
    match client.bind_owned_instance(&name, sandbox_id) {
        Ok(bound) => Ok(bound.is_running() || commit_needed(client, sandbox_id)),
        Err(err)
            if matches!(
                err.code,
                SandboxErrorCode::SandboxNotFound | SandboxErrorCode::IdempotencyConflict
            ) =>
        {
            Ok(false)
        }
        Err(err) => Err(err),
    }
}

#[cfg(test)]
struct InFlight<'a>(&'a RefreshStats);

#[cfg(test)]
impl<'a> InFlight<'a> {
    fn enter(stats: &'a RefreshStats) -> Self {
        stats.started.fetch_add(1, Ordering::AcqRel);
        let now = stats.in_flight.fetch_add(1, Ordering::AcqRel) + 1;
        stats.max_in_flight.fetch_max(now, Ordering::AcqRel);
        let hold = *stats.hold.lock().unwrap_or_else(|err| err.into_inner());
        if let Some(hold) = hold {
            std::thread::sleep(hold);
        }
        Self(stats)
    }
}

#[cfg(test)]
impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::incus::dns::DnsGrantEntry;

    fn state(grants: &[(&str, u64, u32)]) -> SandboxDnsState {
        SandboxDnsState {
            sandbox_id: "sbx-1".into(),
            policy_hash: "h".into(),
            grants: grants
                .iter()
                .map(|(name, expires_at, ttl)| DnsGrantEntry {
                    name: (*name).into(),
                    addresses: vec!["128.66.0.7".into()],
                    ttl: *ttl,
                    expires_at: *expires_at,
                    generation: 1,
                })
                .collect(),
            published: String::new(),
            generations: Default::default(),
        }
    }

    fn domains(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    #[test]
    fn reports_measure_address_churn_renewals_and_unchanged_grants() {
        let policy = EgressPolicy {
            mode: sandbox_protocol::EgressMode::Allowlist,
            domains: domains(&["a.example.com"]),
            cidrs: Vec::new(),
        };
        let before = state(&[("a.example.com", 1_300, 300)]);
        let mut after = state(&[("a.example.com", 1_600, 300)]);
        after.grants[0].addresses = vec!["128.66.0.8".into()];
        let rotation = refresh_report("sbx-1", &policy, Some(&before), Some(&after), 1_150, 1_153);
        assert_eq!(
            rotation,
            DnsRefreshReport {
                sandbox_id: "sbx-1".into(),
                domain_count: 1,
                changed_grants: true,
                changed_addresses: 2,
                added_addresses: 1,
                removed_addresses: 1,
                next_refresh_unix_secs: 1_450,
                warning: None,
            }
        );
        after.grants[0].addresses = before.grants[0].addresses.clone();
        let renewed = refresh_report("sbx-1", &policy, Some(&before), Some(&after), 1_150, 1_153);
        assert!(renewed.changed_grants);
        assert_eq!(
            renewed.changed_addresses, 0,
            "renewal changes time, not addresses"
        );
        let unchanged =
            refresh_report("sbx-1", &policy, Some(&before), Some(&before), 1_150, 1_153);
        assert!(!unchanged.changed_grants);
        assert_eq!(unchanged.changed_addresses, 0);
        assert_eq!(
            unchanged.next_refresh_unix_secs, 1_165,
            "due grants retry at 15s"
        );
        let removed = refresh_report("sbx-1", &policy, Some(&before), None, 1_150, 1_153);
        assert!(removed.changed_grants);
        assert_eq!(
            (
                removed.changed_addresses,
                removed.added_addresses,
                removed.removed_addresses
            ),
            (1, 0, 1)
        );
        assert_eq!(
            removed.next_refresh_unix_secs, 1_210,
            "missing names retry at 60s"
        );
        let added = refresh_report("sbx-1", &policy, None, Some(&after), 1_150, 1_153);
        assert_eq!(
            (
                added.changed_addresses,
                added.added_addresses,
                added.removed_addresses
            ),
            (1, 1, 0)
        );
    }

    #[test]
    fn report_next_refresh_tracks_short_ttl_missing_names_and_completion() {
        let policy = EgressPolicy {
            mode: sandbox_protocol::EgressMode::Allowlist,
            domains: domains(&["a.example.com", "b.example.com"]),
            cidrs: Vec::new(),
        };
        let after = state(&[("a.example.com", 1_300, 300)]);
        let report = refresh_report("sbx-1", &policy, None, Some(&after), 1_000, 1_002);
        assert_eq!(
            report.next_refresh_unix_secs, 1_060,
            "missing name precedes half-life"
        );
        let short = state(&[("a.example.com", 1_030, 30)]);
        let report = refresh_report("sbx-1", &policy, None, Some(&short), 1_000, 1_002);
        assert_eq!(report.next_refresh_unix_secs, 1_015);
        let report = refresh_report("sbx-1", &policy, None, Some(&short), 1_000, 1_040);
        assert_eq!(
            report.next_refresh_unix_secs, 1_040,
            "overdue work is eligible immediately"
        );
    }

    #[test]
    fn a_fresh_grant_is_not_due_until_its_half_life() {
        let d = domains(&["a.example.com"]);
        let s = state(&[("a.example.com", 1_300, 300)]);
        assert_eq!(refresh_due(&d, Some(&s), None, 1_000), None, "300 s left");
        assert_eq!(refresh_due(&d, Some(&s), None, 1_149), None, "151 s left");
        assert_eq!(refresh_due(&d, Some(&s), None, 1_150), Some(150));
        // Overdue (expired, not yet settled) is the most urgent.
        assert_eq!(refresh_due(&d, Some(&s), None, 1_400), Some(0));
    }

    #[test]
    fn due_grants_retry_with_backoff_and_missing_names_slower() {
        let d = domains(&["a.example.com", "b.example.com"]);
        let s = state(&[("a.example.com", 1_100, 300)]);
        // Due (100 s left) but just attempted: wait out the retry spacing.
        assert_eq!(refresh_due(&d, Some(&s), Some(1_000), 1_010), None);
        assert_eq!(refresh_due(&d, Some(&s), Some(1_000), 1_015), Some(85));
        // Only a missing name: first sight is due, then every 60 s.
        let fresh = state(&[("a.example.com", 1_300, 300)]);
        assert_eq!(refresh_due(&d, Some(&fresh), None, 1_000), Some(u64::MAX));
        assert_eq!(refresh_due(&d, Some(&fresh), Some(1_000), 1_059), None);
        assert_eq!(
            refresh_due(&d, Some(&fresh), Some(1_000), 1_060),
            Some(u64::MAX)
        );
        // No state at all (every grant lapsed or denied): missing.
        assert_eq!(refresh_due(&d, None, None, 1_000), Some(u64::MAX));
    }

    #[test]
    fn short_and_legacy_ttls_use_their_own_half_life() {
        let d = domains(&["a.example.com"]);
        // Floor-clamped 30 s grant: due at 15 s remaining.
        let s = state(&[("a.example.com", 1_030, 30)]);
        assert_eq!(refresh_due(&d, Some(&s), None, 1_014), None);
        assert_eq!(refresh_due(&d, Some(&s), None, 1_015), Some(15));
        // Legacy ttl 0 is treated as the upper clamp.
        let s = state(&[("a.example.com", 1_300, 0)]);
        assert_eq!(refresh_due(&d, Some(&s), None, 1_150), Some(150));
    }

    #[test]
    fn grants_for_names_outside_the_policy_never_drive_scheduling() {
        let d = domains(&["a.example.com"]);
        let s = state(&[("a.example.com", 1_300, 300), ("x.example.com", 1_001, 300)]);
        assert_eq!(refresh_due(&d, Some(&s), None, 1_000), None);
    }
}
