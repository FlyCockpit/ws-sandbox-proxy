//! The connection owns this guard; reader admission and worker registration share it.
//! Spawn admission retains the guard through local spawn and ActiveExec publication.
//! Order: authority → supervisor active. No waits, pipe reads or Incus responses under it.
use sandbox_protocol::SandboxErrorCode;
#[cfg(target_os = "linux")]
use std::collections::BTreeMap;
use std::collections::{HashMap, HashSet};
#[cfg(target_os = "linux")]
use std::sync::MutexGuard;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

const MAX_CANCEL_TOMBSTONES: usize = 1024;
/// Revoked carried attempts remembered for one late receipt each. Beyond the
/// bound the journal Result still reaches the server at the next reconnect.
const MAX_LATE_RECEIPTS: usize = 1024;
/// How long the effect gate re-checks between wake-ups.
const EFFECT_GATE_SLICE: Duration = Duration::from_millis(250);
/// How long `detach` waits for in-flight Intent→Effect transitions (journal
/// writes only). A transition still running then is revoked, never carried.
#[cfg(not(test))]
const ADMISSION_DRAIN: Duration = Duration::from_secs(5);
#[cfg(test)]
const ADMISSION_DRAIN: Duration = Duration::from_millis(500);

/// Held from a passed effect gate until the attempt's Effect is durable or
/// refused. Dropping it ends the transition.
#[must_use]
#[derive(Debug)]
pub struct EffectAdmission {
    authority: HostAuthority,
    id: String,
}
impl Drop for EffectAdmission {
    fn drop(&mut self) {
        let mut state = self.authority.0.lock().unwrap_or_else(|e| e.into_inner());
        state.admitting.remove(&self.id);
        state.gate.notify_all();
    }
}

// Wire counterpart of the API's CANCELLABLE_OPERATION_KINDS; protocol.test.ts
// checks parity through OPERATION_DISPATCH_KIND. Unknown kinds fail closed.
pub(super) const CANCELLABLE_DISPATCH_KINDS: &[&str] = &[
    "command.run",
    "file.get",
    "file.put",
    "file.list",
    "file.stat",
    "file.mkdir",
    "file.remove",
    "file.move",
    "process.list",
    "process.signal",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingWork {
    pub sandbox_id: String,
    pub generation: u64,
    pub attempt: u64,
    pub kind: String,
    /// Connection epoch that admitted (or adopted) this attempt. Work bound to
    /// another epoch is carried: it may keep executing an issued effect, but
    /// it neither starts a new effect nor publishes until adopted.
    pub epoch: Option<u64>,
    /// Live [`OwnershipToken`]s for this exact entry: a queued job, its
    /// worker, its completion awaiting publication, or a download window.
    /// Only owned work can be carried across a transport drop: an entry
    /// nobody will ever execute or complete must never be adopted. Tokens
    /// are move-only and release on drop, on every path.
    pub owners: std::collections::BTreeSet<u64>,
}

/// Move-only proof that something will execute, finish or publish one exact
/// pending attempt. Created when a job is queued, moved into its worker, then
/// into its completion and on to the publication path or download window.
/// Dropping it (normally, on an early return, or with a discarded batch)
/// releases ownership. Observations (stdin failures, interim results,
/// refusals) never carry one, so they can never release a live owner.
#[derive(Debug)]
pub struct OwnershipToken {
    authority: HostAuthority,
    id: String,
    nonce: u64,
}
impl OwnershipToken {
    pub fn operation_id(&self) -> &str {
        &self.id
    }
}
impl Drop for OwnershipToken {
    fn drop(&mut self) {
        let mut state = self.authority.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(work) = state.pending.get_mut(&self.id) {
            work.owners.remove(&self.nonce);
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityReject {
    /// Captured under the authority lock at refusal, never inferred later.
    pub session_closed: bool,
    admission_unavailable: bool,
    pub code: SandboxErrorCode,
    pub message: String,
}
impl AuthorityReject {
    /// Only the dispatch caller has the durable first-claim proof. Receipt
    /// replays, uncertain lineage and non-allocation work retain the old code.
    pub fn refusal_code(&self, kind: &str, first_claim: bool) -> SandboxErrorCode {
        if self.admission_unavailable
            && first_claim
            && matches!(kind, "sandbox.create" | "sandbox.reconnect")
        {
            SandboxErrorCode::HostEffectNotIssued
        } else {
            self.code
        }
    }
}
/// Carried work revoked before its first effect (grace, refused adoption,
/// revoking session end): not issued, and never reported as cancelled.
fn revoked_before_effect() -> AuthorityReject {
    AuthorityReject {
        session_closed: true,
        admission_unavailable: true,
        code: SandboxErrorCode::HostEffectNotIssued,
        message: "relay session closed before effect admission".into(),
    }
}
fn session_closed() -> AuthorityReject {
    AuthorityReject {
        session_closed: true,
        admission_unavailable: false,
        code: SandboxErrorCode::Cancelled,
        message: "relay session closed before effect admission".into(),
    }
}
fn rejected(message: &str) -> AuthorityReject {
    AuthorityReject {
        session_closed: false,
        admission_unavailable: false,
        code: SandboxErrorCode::ProtocolError,
        message: message.to_string(),
    }
}
#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
struct StdinStream {
    next: u64,
    buffered: BTreeMap<u64, (Vec<u8>, bool)>,
    bytes: usize,
    closed: bool,
}
// The private state cannot escape; dropping this lease releases spawn authority.
#[cfg(target_os = "linux")]
pub struct ExecGuard<'a> {
    _state: MutexGuard<'a, AuthorityState>,
}
#[derive(Debug, Default)]
struct AuthorityState {
    journal: Option<Arc<super::journal::HostJournal>>,
    closed: bool,
    sandbox_generation: HashMap<String, u64>,
    pending: HashMap<String, PendingWork>,
    seen: HashMap<String, PendingWork>,
    runtime_permits: HashMap<String, Arc<sandbox_runtime::RuntimePermit>>,
    executions: HashMap<String, Arc<AtomicBool>>,
    revoked_execs: Vec<String>,
    cancelled: HashSet<String>,
    cancel_tombstones: HashSet<(String, u64, u64)>,
    cancel_tombstones_full: bool,
    #[cfg(target_os = "linux")]
    stdin_sequences: HashMap<String, StdinStream>,
    /// Epoch of the attached session (`hello.ok`). `None` before the first
    /// attach, so authorities that never attach behave as before.
    session_epoch: Option<u64>,
    /// A transport loss detached the session; cleared by the next attach.
    detached: bool,
    /// First detach of the current outage. Repeated failed sessions never
    /// move it; only a fully registered session clears it (`end_outage`).
    detached_at: Option<Instant>,
    /// Attempts that passed their effect gate: carried, they are running
    /// (or finished) effects, ended by their own timer, the lease or
    /// `max_carry`; every other carried attempt never started.
    issued: HashSet<String>,
    /// Detached work never waits at the effect gate longer than this, even
    /// if the expiry tick stalls; it then fails closed as a session closure.
    /// `None`: derived from the default carry policy.
    effect_gate_max_wait: Option<Duration>,
    /// Carried attempts revoked before they could publish; each gets one
    /// exact-bound late receipt once its journal Result exists.
    late: HashSet<(String, u64, u64)>,
    late_overflow: bool,
    /// Wakes effect-gate waiters on adoption, revocation and shutdown.
    gate: Arc<Condvar>,
    /// Attempts between a passed effect gate and their durable Effect record
    /// (or refusal). `detach` waits for these, so a drop never interleaves
    /// with an Intent→Effect transition.
    admitting: HashSet<String>,
    /// Source of unique ownership-token identities.
    next_owner_nonce: u64,
    /// Connection epochs this process attached (bounded, newest kept): the
    /// dispatch audit may only deny receipt for an epoch this process owned.
    attached_epochs: std::collections::BTreeSet<u64>,
}
#[derive(Debug, Default, Clone)]
pub struct HostAuthority(Arc<Mutex<AuthorityState>>);

/// What one carry-expiry tick did (or still must do) to carried work.
#[derive(Debug, Default)]
pub struct CarryExpiry {
    pub revoked: usize,
    /// Running commands past `max_carry` to stop durably (journaled
    /// `CarryExpired` cancel): `(operation, generation, attempt)`.
    pub stop: Vec<(String, u64, u64)>,
    /// Revoked guest work that never reached its effect gate, to settle
    /// durably as FAILED `host_effect_not_issued` now, so a reconnect
    /// before its queued worker runs never recovers it as UNKNOWN.
    pub not_issued: Vec<(String, u64, u64)>,
}
impl AuthorityState {
    /// Bound to the attached session: may start effects and publish.
    fn attached(&self, work: &PendingWork) -> bool {
        !self.detached && work.epoch == self.session_epoch
    }
    fn remember_late(&mut self, id: &str, generation: u64, attempt: u64) {
        if self.late.len() < MAX_LATE_RECEIPTS {
            self.late.insert((id.to_string(), generation, attempt));
        } else {
            self.late_overflow = true;
        }
    }
    /// Revoke one carried entry exactly like a session teardown would.
    fn revoke(&mut self, id: &str) -> Option<PendingWork> {
        let work = self.pending.get(id).cloned()?;
        if self.executions.contains_key(id) {
            self.revoked_execs.push(id.to_string());
        }
        self.remember_late(id, work.generation, work.attempt);
        self.remove(id);
        Some(work)
    }
    fn current(
        &self,
        id: &str,
        generation: u64,
        attempt: u64,
    ) -> Result<PendingWork, AuthorityReject> {
        if self.closed {
            return Err(session_closed());
        }
        let work = self
            .pending
            .get(id)
            .ok_or_else(|| rejected("no pending operation"))?;
        if self
            .journal
            .as_ref()
            .is_some_and(|j| !j.work_allowed(&work.sandbox_id, generation, &work.kind))
            || work.generation != generation
            || work.attempt != attempt
            || self
                .sandbox_generation
                .get(&work.sandbox_id)
                .is_some_and(|current| generation < *current)
        {
            return Err(rejected("stale operation authority"));
        }
        Ok(work.clone())
    }
    fn remove(&mut self, id: &str) -> Option<PendingWork> {
        self.cancelled.remove(id);
        self.issued.remove(id);
        if let Some(permit) = self.runtime_permits.remove(id) {
            permit.revoke();
        }
        if let Some(cancelled) = self.executions.remove(id) {
            cancelled.store(true, Ordering::Release);
        }
        #[cfg(target_os = "linux")]
        self.stdin_sequences.remove(id);
        self.gate.notify_all();
        self.pending.remove(id)
    }
}
impl HostAuthority {
    pub fn with_journal(journal: Arc<super::journal::HostJournal>) -> Self {
        Self(Arc::new(Mutex::new(AuthorityState {
            journal: Some(journal),
            ..AuthorityState::default()
        })))
    }
    /// A new relay connection reopens admission. Work carried across a
    /// transport loss (`detach`) keeps its entries and `seen` records: it is
    /// bound to its old epoch, so it neither starts an effect nor publishes
    /// until the reconnect adopts it (`adopt`) or revokes it. Every other
    /// session end revoked its work already (`shutdown`), exactly as before.
    /// A journal IO failure still fails closed through the journal-wide `io_failed` latch and
    /// the expiry service re-latches `shutdown()` on its next tick. Observed
    /// generations survive.
    pub fn begin_session(&self) {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let AuthorityState { seen, pending, .. } = &mut *state;
        seen.retain(|id, _| pending.contains_key(id));
        state.revoked_execs.clear();
        state.cancel_tombstones.clear();
        state.cancel_tombstones_full = false;
        state.closed = false;
    }
    /// `hello.ok`: the session at `epoch` is attached. Carried work stays
    /// bound to its older epoch until adopted.
    pub fn attach(&self, epoch: u64) {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state.attached_epochs.insert(epoch);
        while state.attached_epochs.len() > 1024 {
            state.attached_epochs.pop_first();
        }
        state.session_epoch = Some(epoch);
        state.detached = false;
        state.gate.notify_all();
    }
    /// A positive transport loss: keep in-flight work (bounded by the grace)
    /// instead of revoking it. Returns the number of carried entries.
    ///
    /// Review #1/#2: only owned work is carried; an entry no worker owns (a
    /// send failed before submission, a staged upload, a finished worker's
    /// retained UNKNOWN) is forgotten so receipt recovery settles it. Every
    /// in-flight Intent→Effect transition finishes (or is revoked) before
    /// this returns, so carried phases are stable for adoption.
    pub fn detach(&self, now: Instant) -> usize {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state.detached = true;
        let deadline = Instant::now() + ADMISSION_DRAIN;
        while !state.admitting.is_empty() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                let stuck: Vec<String> = state.admitting.iter().cloned().collect();
                for id in stuck {
                    state.revoke(&id);
                }
                break;
            }
            let gate = state.gate.clone();
            state = gate
                .wait_timeout(state, remaining)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        let ownerless: Vec<String> = state
            .pending
            .iter()
            .filter(|(_, work)| work.owners.is_empty())
            .map(|(id, _)| id.clone())
            .collect();
        for id in ownerless {
            if state.executions.contains_key(&id) {
                state.revoked_execs.push(id.clone());
            }
            state.remove(&id);
        }
        if !state.pending.is_empty() && state.detached_at.is_none() {
            state.detached_at = Some(now);
        }
        state.pending.len()
    }
    /// This process attached `epoch` (so it owned that socket's frames).
    pub fn attached_epoch(&self, epoch: u64) -> bool {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .attached_epochs
            .contains(&epoch)
    }
    /// This process attached some epoch older than `epoch`.
    pub fn attached_before(&self, epoch: u64) -> bool {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .attached_epochs
            .first()
            .is_some_and(|first| *first < epoch)
    }
    /// Any pending (current or carried) work exists.
    pub fn has_pending(&self) -> bool {
        !self
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pending
            .is_empty()
    }
    /// When the current outage's first detach happened, if one is active.
    pub fn detached_since(&self) -> Option<Instant> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).detached_at
    }
    /// Something currently owns this exact pending attempt.
    pub fn owned(&self, id: &str, generation: u64, attempt: u64) -> bool {
        let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state.pending.get(id).is_some_and(|w| {
            !w.owners.is_empty() && w.generation == generation && w.attempt == attempt
        })
    }
    /// Take ownership of this exact pending attempt. `None` when it is no
    /// longer pending (revoked, superseded, completed).
    pub fn take_ownership(
        &self,
        id: &str,
        generation: u64,
        attempt: u64,
    ) -> Option<OwnershipToken> {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state.next_owner_nonce += 1;
        let nonce = state.next_owner_nonce;
        let work = state.pending.get_mut(id)?;
        if work.generation != generation || work.attempt != attempt {
            return None;
        }
        work.owners.insert(nonce);
        Some(OwnershipToken {
            authority: self.clone(),
            id: id.to_string(),
            nonce,
        })
    }
    /// Entries not bound to the attached session, oldest-generation last.
    pub fn carried(&self) -> Vec<(String, PendingWork)> {
        let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let mut carried: Vec<_> = state
            .pending
            .iter()
            .filter(|(_, work)| !state.attached(work))
            .map(|(id, work)| (id.clone(), work.clone()))
            .collect();
        carried.sort_by(|a, b| b.1.generation.cmp(&a.1.generation).then(a.0.cmp(&b.0)));
        carried
    }
    /// Sandboxes with pending lifecycle work (create, reconnect, stop, kill,
    /// lease renewal), which may hold the sandbox's runtime lock for long.
    pub fn pending_lifecycle_sandboxes(&self) -> HashSet<String> {
        let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state
            .pending
            .values()
            .filter(|work| {
                matches!(
                    work.kind.as_str(),
                    "sandbox.create"
                        | "sandbox.reconnect"
                        | "sandbox.stop"
                        | "sandbox.kill"
                        | "sandbox.lease.renew"
                )
            })
            .map(|work| work.sandbox_id.clone())
            .collect()
    }
    /// Sandboxes with any pending (carried or current) work.
    pub fn pending_sandboxes(&self) -> HashSet<String> {
        let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state
            .pending
            .values()
            .map(|work| work.sandbox_id.clone())
            .collect()
    }
    /// The server adopted this exact attempt for `epoch`. `false` when the
    /// entry is gone (revoked by the grace meanwhile).
    pub fn adopt(&self, id: &str, generation: u64, attempt: u64, epoch: u64) -> bool {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let Some(work) = state.pending.get_mut(id) else {
            return false;
        };
        if work.generation != generation || work.attempt != attempt {
            return false;
        }
        work.epoch = Some(epoch);
        if let Some(seen) = state.seen.get_mut(id) {
            seen.epoch = Some(epoch);
        }
        state.gate.notify_all();
        true
    }
    /// Refused, unsupported or over-bound carried work: revoke it like a
    /// session teardown. Its next gate refusal is a session closure, so stop
    /// and kill keep their durable deferral, and its journal Result is owed
    /// one late receipt.
    pub fn revoke_carried(&self, id: &str) -> Option<PendingWork> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).revoke(id)
    }
    /// Revoke an entry no worker owns (a staged upload, a finished download):
    /// no completion will drain for it, so no late receipt is recorded.
    pub fn forget(&self, id: &str) {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if state.executions.contains_key(id) {
            state.revoked_execs.push(id.to_string());
        }
        state.remove(id);
    }
    /// Pending operation ids of one dispatch kind.
    pub fn pending_of_kind(&self, kind: &str) -> Vec<String> {
        let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state
            .pending
            .iter()
            .filter(|(_, work)| work.kind == kind)
            .map(|(id, _)| id.clone())
            .collect()
    }
    /// The carry expiry (WP3), decided per carried attempt by
    /// [`super::carry::decide`] from the time since the outage's first
    /// detach. `lease_due` maps each sandbox whose lease expired to that
    /// lease's generation: work of it that never started is revoked now
    /// (the window never outlives the lease). Never-started work past the
    /// window is revoked (`host_effect_not_issued`); a running command past
    /// `max_carry` is returned in `stop` for the caller to cancel durably
    /// (B-4: its owner terminates the guest process and proves the stop);
    /// other issued work past `max_carry` is revoked. Runs on the
    /// always-running expiry tick, connected or not.
    pub fn expire_detached_work(
        &self,
        now: Instant,
        policy: &super::carry::CarryPolicy,
        lease_due: &HashMap<String, u64>,
    ) -> CarryExpiry {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let Some(since) = state.detached_at else {
            return CarryExpiry::default();
        };
        let outage = now.saturating_duration_since(since);
        // Until `end_outage` (a registered session), every pending entry is
        // work of this outage: adopted entries are bound to the reconnecting
        // session but still answer to `max_carry` from the first drop, so a
        // slow adoption, audit or census can never step over the cap.
        let carried: Vec<(String, PendingWork, bool)> = state
            .pending
            .iter()
            .filter(|(id, _)| !state.cancelled.contains(*id))
            .map(|(id, work)| (id.clone(), work.clone(), state.attached(work)))
            .collect();
        let mut expiry = CarryExpiry::default();
        for (id, work, adopted) in carried {
            let lease = lease_due
                .get(&work.sandbox_id)
                .is_some_and(|generation| work.generation <= *generation);
            let issued = state.issued.contains(&id);
            // Adopted work may start its effect any moment now: only the cap
            // applies to it, never the Intent window or the lease clamp.
            let decision = if adopted && !issued {
                if outage >= policy.max_carry() {
                    super::carry::CarryDecision::Revoke
                } else {
                    super::carry::CarryDecision::Keep
                }
            } else {
                super::carry::decide(policy, &work.kind, issued, outage, lease)
            };
            match decision {
                super::carry::CarryDecision::Keep => {}
                super::carry::CarryDecision::Stop => {
                    expiry.stop.push((id, work.generation, work.attempt));
                }
                super::carry::CarryDecision::Revoke => {
                    state.revoke(&id);
                    expiry.revoked += 1;
                    // Lifecycle work keeps its own refusal path (teardown
                    // deferral, allocation evidence); guest work that never
                    // passed its gate has definitely issued nothing.
                    if !issued && CANCELLABLE_DISPATCH_KINDS.contains(&work.kind.as_str()) {
                        expiry.not_issued.push((id, work.generation, work.attempt));
                    }
                }
            }
        }
        expiry
    }
    /// The effect gate's backstop follows the carry window.
    pub fn set_effect_gate_max_wait(&self, wait: Duration) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .effect_gate_max_wait = Some(wait);
    }
    /// The reconnected session is fully registered (adoption, audit and
    /// census all done): the outage is over and a later loss starts a fresh
    /// carry clock. Never earlier: a drop during the census after a
    /// successful adoption is the same outage, so `max_carry` keeps counting
    /// from its first drop.
    pub fn end_outage(&self) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).detached_at = None;
    }
    /// A revoked carried attempt still owed a late receipt; taking it clears it.
    pub fn take_late(&self, id: &str, generation: u64, attempt: u64) -> bool {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .late
            .remove(&(id.to_string(), generation, attempt))
    }
    /// The attached session's epoch, or `None` while detached.
    pub fn session_epoch(&self) -> Option<u64> {
        let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        (!state.detached).then_some(state.session_epoch).flatten()
    }
    /// M4: the Intent→Effect gate. Blocks while this attempt is carried
    /// (bound to an older epoch, or the session is detached) and returns once
    /// it is adopted. A revoked, superseded, cancelled-away or closed attempt
    /// is refused; a revocation is a session closure.
    pub fn wait_effect_admission(
        &self,
        id: &str,
        generation: u64,
        attempt: u64,
    ) -> Result<EffectAdmission, AuthorityReject> {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let deadline = Instant::now()
            + state
                .effect_gate_max_wait
                .unwrap_or_else(|| super::carry::CarryPolicy::default().effect_gate_max_wait());
        loop {
            if !state.closed
                && !state.pending.contains_key(id)
                && state.late.contains(&(id.to_string(), generation, attempt))
            {
                return Err(revoked_before_effect());
            }
            let work = state.current(id, generation, attempt)?;
            if state.attached(&work) {
                // Registered under the same lock that saw the session
                // attached: a concurrent detach waits for this transition.
                state.admitting.insert(id.to_string());
                state.issued.insert(id.to_string());
                return Ok(EffectAdmission {
                    authority: self.clone(),
                    id: id.to_string(),
                });
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(session_closed());
            }
            let gate = state.gate.clone();
            state = gate
                .wait_timeout(state, EFFECT_GATE_SLICE.min(deadline - now))
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }
    /// No runtime wait under this lock. Revocation closes every stream/spawn gate.
    pub fn expire_sandbox(&self, sandbox: &str, generation: u64) {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let ids: Vec<_> = state
            .pending
            .iter()
            .filter(|(_, work)| work.sandbox_id == sandbox && work.generation <= generation)
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            state.remove(&id);
        }
    }

    /// C52: a terminal bound to `generation` of `sandbox` lost its authority
    /// (connection closed, or a newer generation was observed).
    pub fn terminal_superseded(&self, sandbox: &str, generation: u64) -> bool {
        let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state.closed
            || state
                .sandbox_generation
                .get(sandbox)
                .is_some_and(|current| generation < *current)
    }

    pub fn accept_dispatch(
        &self,
        operation_id: &str,
        sandbox_id: &str,
        kind: &str,
        generation: u64,
        attempt: u64,
    ) -> Result<bool, AuthorityReject> {
        self.accept_dispatch_inner(operation_id, sandbox_id, kind, generation, attempt, false)
    }

    /// Only the journal recovery path may re-arm an already observed attempt.
    /// Wire duplicates retain their existing replay semantics. The ordinary
    /// generation, session and exact identity checks below still apply.
    pub fn resume_teardown(
        &self,
        receipt: &super::journal::HostReceipt,
    ) -> Result<bool, AuthorityReject> {
        if receipt.digest_pruned
            || receipt.phase == super::journal::ReceiptPhase::Result
            || !matches!(receipt.kind.as_str(), "sandbox.kill" | "sandbox.stop")
        {
            return Err(rejected("receipt has no unresolved teardown authority"));
        }
        self.accept_dispatch_inner(
            &receipt.operation_id,
            &receipt.sandbox_id,
            &receipt.kind,
            receipt.generation,
            receipt.attempt,
            true,
        )
    }

    /// Every refusal is logged once with a fixed reason token (B1: refusals
    /// before issue used to leave no trace in the daemon journal).
    fn accept_dispatch_inner(
        &self,
        operation_id: &str,
        sandbox_id: &str,
        kind: &str,
        generation: u64,
        attempt: u64,
        resume_teardown: bool,
    ) -> Result<bool, AuthorityReject> {
        let mut reason = "dispatch_authority";
        let result = self.accept_dispatch_checked(
            operation_id,
            sandbox_id,
            kind,
            generation,
            attempt,
            resume_teardown,
            &mut reason,
        );
        if let Err(reject) = &result {
            tracing::warn!(
                operation_id,
                sandbox_id,
                kind,
                generation,
                attempt,
                reason,
                code = ?reject.code,
                "host refused dispatch before issue"
            );
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn accept_dispatch_checked(
        &self,
        operation_id: &str,
        sandbox_id: &str,
        kind: &str,
        generation: u64,
        attempt: u64,
        resume_teardown: bool,
        reason: &mut &'static str,
    ) -> Result<bool, AuthorityReject> {
        let mut state = self.0.lock().unwrap_or_else(|err| err.into_inner());
        let current = state
            .sandbox_generation
            .get(sandbox_id)
            .copied()
            .unwrap_or(0);
        let refusal = if state.closed {
            Some("session_closed")
        } else {
            state
                .journal
                .as_ref()
                .and_then(|j| j.work_refusal(sandbox_id, generation, kind))
        };
        if let Some(refusal) = refusal {
            *reason = refusal;
            return Err(AuthorityReject {
                session_closed: state.closed,
                admission_unavailable: true,
                code: SandboxErrorCode::ProtocolError,
                message: "host refused dispatch before issue".into(),
            });
        }
        if generation == 0 || attempt == 0 {
            *reason = "invalid_generation_or_attempt";
            return Err(rejected("stale or invalid dispatch authority"));
        }
        // Retain unknown-attempt cancels for this connection, including repeated
        // dispatches. On saturation refuse new cancellable dispatches rather than
        // evicting a receipt. Lifecycle continuations must remain admissible.
        if CANCELLABLE_DISPATCH_KINDS.contains(&kind)
            && (state.cancel_tombstones_full
                || state
                    .cancel_tombstones
                    .contains(&(operation_id.into(), generation, attempt)))
        {
            *reason = "cancelled_before_admission";
            return Err(AuthorityReject {
                session_closed: false,
                admission_unavailable: false,
                code: SandboxErrorCode::Cancelled,
                message: "dispatch cancelled before admission".into(),
            });
        }
        if generation < current {
            *reason = "stale_generation";
            return Err(rejected("stale or invalid dispatch authority"));
        }
        if let Some(previous) = state.seen.get(operation_id) {
            if previous.sandbox_id != sandbox_id
                || previous.kind != kind
                || generation != previous.generation
                || attempt < previous.attempt
                || (state.pending.contains_key(operation_id) && attempt != previous.attempt)
            {
                *reason = "operation_identity_mismatch";
                return Err(rejected(
                    "dispatch does not match recorded operation authority",
                ));
            }
            if attempt == previous.attempt
                && (!resume_teardown || state.pending.contains_key(operation_id))
            {
                return Ok(false);
            }
        }
        // EVERY dispatch advances observed authority. Same-generation warm
        // reconnect changes nothing; older registered execs receive cancellation.
        state
            .sandbox_generation
            .insert(sandbox_id.to_string(), generation.max(current));
        let obsolete: Vec<_> = state
            .pending
            .iter()
            .filter(|(_, work)| {
                work.sandbox_id == sandbox_id
                    && (work.generation < generation
                        || matches!(kind, "sandbox.stop" | "sandbox.kill"))
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in obsolete {
            // Carried work superseded before adoption still owes its receipt.
            if state
                .pending
                .get(&id)
                .is_some_and(|work| !state.attached(work))
            {
                state.revoke(&id);
                continue;
            }
            if state.executions.contains_key(&id) {
                state.revoked_execs.push(id.clone());
            }
            state.remove(&id);
        }
        let work = PendingWork {
            sandbox_id: sandbox_id.to_string(),
            generation,
            attempt,
            kind: kind.to_string(),
            epoch: state.session_epoch,
            owners: std::collections::BTreeSet::new(),
        };
        state.issued.remove(operation_id);
        state.pending.insert(operation_id.to_string(), work.clone());
        state.seen.insert(operation_id.to_string(), work);
        Ok(true)
    }
    pub fn accept_stream(
        &self,
        id: &str,
        generation: u64,
        attempt: u64,
    ) -> Result<PendingWork, AuthorityReject> {
        let state = self.0.lock().unwrap_or_else(|err| err.into_inner());
        if state.cancelled.contains(id) {
            return Err(rejected("operation was cancelled"));
        }
        state.current(id, generation, attempt)
    }
    /// Publication gate: only work bound to the attached session publishes.
    pub fn accept_completion(
        &self,
        id: &str,
        generation: u64,
        attempt: u64,
    ) -> Result<PendingWork, AuthorityReject> {
        let state = self.0.lock().unwrap_or_else(|err| err.into_inner());
        let work = state.current(id, generation, attempt)?;
        if !state.attached(&work) {
            return Err(rejected("carried work is not adopted"));
        }
        Ok(work)
    }
    pub fn accept_cancel(
        &self,
        id: &str,
        generation: u64,
        attempt: u64,
    ) -> Result<PendingWork, AuthorityReject> {
        let mut state = self.0.lock().unwrap_or_else(|err| err.into_inner());
        if state
            .seen
            .get(id)
            .is_some_and(|work| !CANCELLABLE_DISPATCH_KINDS.contains(&work.kind.as_str()))
        {
            return Err(rejected(
                "lifecycle operations cannot be cancelled; use kill",
            ));
        }
        let work = match state.current(id, generation, attempt) {
            Ok(work) => work,
            Err(err) => {
                if !state.closed && generation > 0 && attempt > 0 {
                    let key = (id.to_string(), generation, attempt);
                    if !state.cancel_tombstones.contains(&key) {
                        if state.cancel_tombstones.len() < MAX_CANCEL_TOMBSTONES {
                            state.cancel_tombstones.insert(key);
                        } else {
                            state.cancel_tombstones_full = true;
                        }
                    }
                }
                return Err(err);
            }
        };
        if !state.cancelled.insert(id.to_string()) {
            return Err(rejected("operation already cancelled"));
        }
        // An exec's ordinary-work admission is revoked by its execution flag.
        // Its runtime permit remains the *cleanup* authority until lifecycle
        // supersession/shutdown revokes it. Other adapters have no cleanup owner.
        if !state.executions.contains_key(id)
            && let Some(permit) = state.runtime_permits.get(id)
        {
            permit.revoke();
        }
        if let Some(permit) = state.executions.get(id) {
            permit.store(true, Ordering::Release);
        }
        Ok(work)
    }
    #[cfg(test)]
    pub fn runtime_registered(&self, id: &str) -> bool {
        self.0.lock().unwrap().runtime_permits.contains_key(id)
    }
    pub fn register_runtime(
        &self,
        id: &str,
        generation: u64,
        attempt: u64,
    ) -> Result<Arc<sandbox_runtime::RuntimePermit>, AuthorityReject> {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state.current(id, generation, attempt)?;
        if state.cancelled.contains(id) {
            return Err(rejected("operation was cancelled"));
        }
        let permit = Arc::new(sandbox_runtime::RuntimePermit::default());
        state.runtime_permits.insert(id.into(), permit.clone());
        Ok(permit)
    }
    /// Called on the WORKER immediately before process spawn. Validation and
    /// registration are indivisible relative to lifecycle admission/shutdown.
    #[cfg(target_os = "linux")]
    pub fn register_exec(
        &self,
        id: &str,
        generation: u64,
        attempt: u64,
    ) -> Result<(Arc<AtomicBool>, ExecGuard<'_>), AuthorityReject> {
        let mut state = self.0.lock().unwrap_or_else(|err| err.into_inner());
        state.current(id, generation, attempt)?;
        if state.cancelled.contains(id) {
            return Err(rejected("operation was cancelled"));
        }
        if state.executions.contains_key(id) {
            return Err(rejected("exec already registered"));
        }
        let cancelled = Arc::new(AtomicBool::new(false));
        state.executions.insert(id.to_string(), cancelled.clone());
        Ok((cancelled, ExecGuard { _state: state }))
    }
    #[cfg(target_os = "linux")]
    pub fn start_stdin(&self, id: &str, next: u64) {
        let mut state = self.0.lock().unwrap_or_else(|err| err.into_inner());
        state
            .stdin_sequences
            .entry(id.into())
            .or_insert_with(|| StdinStream {
                next,
                ..StdinStream::default()
            });
    }
    #[cfg(target_os = "linux")]
    pub fn accept_stdin(
        &self,
        id: &str,
        generation: u64,
        attempt: u64,
        sequence: u64,
        bytes: Vec<u8>,
        eof: bool,
    ) -> Result<Vec<sandbox_runtime::WriteStdinRequest>, AuthorityReject> {
        let mut state = self.0.lock().unwrap_or_else(|err| err.into_inner());
        if state.cancelled.contains(id)
            || !state
                .current(id, generation, attempt)
                .is_ok_and(|work| work.kind == "command.run")
        {
            return Ok(Vec::new());
        }
        // Entry follows the pending attempt identity; dispatch seeds its starting counter.
        let stream = state.stdin_sequences.entry(id.to_string()).or_default();
        if stream.closed || sequence < stream.next || stream.buffered.contains_key(&sequence) {
            return Ok(Vec::new());
        }
        if sequence > stream.next
            && (stream.buffered.len() >= 64 || stream.bytes + bytes.len() > 1024 * 1024)
        {
            stream.closed = true;
            stream.buffered.clear();
            stream.bytes = 0;
            return Err(AuthorityReject {
                session_closed: false,
                admission_unavailable: false,
                code: SandboxErrorCode::RequestTooLarge,
                message: "stdin reorder buffer exceeded 64 chunks or 1 MiB".into(),
            });
        }
        stream.bytes += bytes.len();
        stream.buffered.insert(sequence, (bytes, eof));
        let mut ready = Vec::new();
        while let Some((bytes, eof)) = stream.buffered.remove(&stream.next) {
            stream.next += 1;
            stream.bytes -= bytes.len();
            ready.push(sandbox_runtime::WriteStdinRequest {
                operation_id: id.into(),
                generation,
                attempt,
                bytes,
                eof,
            });
            if eof {
                stream.closed = true;
                stream.buffered.clear();
                stream.bytes = 0;
                break;
            }
        }
        Ok(ready)
    }
    #[cfg(test)]
    pub fn cancel(&self, id: &str) {
        let mut state = self.0.lock().unwrap_or_else(|err| err.into_inner());
        if !state
            .pending
            .get(id)
            .is_some_and(|work| CANCELLABLE_DISPATCH_KINDS.contains(&work.kind.as_str()))
        {
            return;
        }
        state.cancelled.insert(id.to_string());
        if let Some(permit) = state.runtime_permits.get(id) {
            permit.revoke();
        }
        if let Some(permit) = state.executions.get(id) {
            permit.store(true, Ordering::Release);
        }
    }
    pub fn complete(&self, id: &str) -> Option<PendingWork> {
        self.0
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .remove(id)
    }
    pub fn pending(&self, id: &str) -> Option<PendingWork> {
        self.0
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .pending
            .get(id)
            .cloned()
    }
    #[cfg(target_os = "linux")]
    pub fn take_revoked_execs(&self) -> Vec<String> {
        std::mem::take(
            &mut self
                .0
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .revoked_execs,
        )
    }
    #[cfg(target_os = "linux")]
    pub fn pending_ids(&self) -> HashSet<String> {
        self.0
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .pending
            .keys()
            .cloned()
            .collect()
    }
    pub fn shutdown(&self) {
        let mut state = self.0.lock().unwrap_or_else(|err| err.into_inner());
        state.closed = true;
        let ids: Vec<_> = state.pending.keys().cloned().collect();
        for id in ids {
            state.remove(&id);
        }
        state.detached_at = None;
        state.gate.notify_all();
    }
    /// Revoke-and-reconnect (a server verdict or local protocol failure while
    /// the process continues): `shutdown`, remembering every revoked attempt
    /// for its late receipt in the next session.
    pub fn revoke_all(&self) -> usize {
        let mut state = self.0.lock().unwrap_or_else(|err| err.into_inner());
        let ids: Vec<_> = state.pending.keys().cloned().collect();
        for id in &ids {
            state.revoke(id);
        }
        state.closed = true;
        state.detached_at = None;
        state.gate.notify_all();
        ids.len()
    }
    /// The next stdin sequence a carried command expects, `None` once its
    /// stream is closed or for non-command work.
    #[cfg(target_os = "linux")]
    pub fn stdin_next(&self, id: &str) -> Option<u64> {
        let state = self.0.lock().unwrap_or_else(|err| err.into_inner());
        if state
            .pending
            .get(id)
            .is_none_or(|w| w.kind != "command.run")
        {
            return None;
        }
        state
            .stdin_sequences
            .get(id)
            .filter(|stream| !stream.closed)
            .map(|stream| stream.next)
    }
    #[cfg(not(target_os = "linux"))]
    pub fn stdin_next(&self, _id: &str) -> Option<u64> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox_relay::carry::CarryPolicy;

    fn no_lease() -> HashMap<String, u64> {
        HashMap::new()
    }

    /// One expiry tick with a 60 s window and a 1 h cap; the revoked count.
    fn expire(authority: &HostAuthority, now: Instant, window: Duration) -> usize {
        authority
            .expire_detached_work(
                now,
                &CarryPolicy::new(window, Duration::from_secs(3600)),
                &no_lease(),
            )
            .revoked
    }

    fn carried_authority() -> HostAuthority {
        let authority = HostAuthority::default();
        authority.attach(1);
        authority
            .accept_dispatch("op", "sbx", "sandbox.create", 1, 1)
            .expect("admit");
        // A queued or running worker owns it for the whole test.
        std::mem::forget(authority.take_ownership("op", 1, 1).expect("pending"));
        authority
    }

    #[test]
    fn detach_keeps_work_across_sessions_and_the_grace_anchor_never_moves() {
        let authority = carried_authority();
        let t0 = Instant::now();
        assert_eq!(authority.detach(t0), 1);
        authority.begin_session();
        assert!(authority.pending("op").is_some(), "carried across sessions");
        // A failed reconnect detaches again; the first detach stays the anchor.
        authority.attach(2);
        assert_eq!(authority.detach(t0 + Duration::from_secs(30)), 1);
        authority.begin_session();
        let window = Duration::from_secs(60);
        assert_eq!(expire(&authority, t0 + Duration::from_secs(59), window), 0);
        assert_eq!(expire(&authority, t0 + Duration::from_secs(60), window), 1);
        assert!(authority.pending("op").is_none());
        assert!(authority.take_late("op", 1, 1), "owed one late receipt");
        assert!(!authority.take_late("op", 1, 1));
    }

    /// Review #1: an entry no worker owns is never carried.
    #[test]
    fn detach_forgets_ownerless_entries_without_a_late_receipt() {
        let authority = carried_authority();
        authority
            .accept_dispatch("unsubmitted", "sbx", "command.run", 1, 1)
            .unwrap();
        assert_eq!(authority.detach(Instant::now()), 1, "only the owned entry");
        assert!(authority.pending("unsubmitted").is_none());
        assert!(!authority.take_late("unsubmitted", 1, 1));
        assert_eq!(authority.carried().len(), 1);
    }

    /// Review #2: a detach never interleaves with an Intent→Effect
    /// transition. It waits for a passed gate's admission to end, and gates
    /// after it block.
    #[test]
    fn detach_waits_for_an_in_flight_effect_admission() {
        let authority = carried_authority();
        let admission = authority
            .wait_effect_admission("op", 1, 1)
            .expect("attached work passes");
        let detacher = {
            let authority = authority.clone();
            std::thread::spawn(move || authority.detach(Instant::now()))
        };
        std::thread::sleep(Duration::from_millis(150));
        assert!(!detacher.is_finished(), "detach waits for the transition");
        // The worker records Effect, then ends the transition.
        drop(admission);
        assert_eq!(detacher.join().expect("join"), 1, "carried after Effect");
        // From now on the gate blocks this carried attempt.
        let blocked = {
            let authority = authority.clone();
            std::thread::spawn(move || authority.wait_effect_admission("op", 1, 1).is_ok())
        };
        std::thread::sleep(Duration::from_millis(150));
        assert!(!blocked.is_finished());
        authority.revoke_carried("op");
        assert!(!blocked.join().expect("join"));
    }

    /// Review #2: a transition stuck past the drain bound is revoked, never
    /// carried with an unstable phase.
    #[test]
    fn detach_revokes_a_stuck_effect_admission() {
        let authority = carried_authority();
        let admission = authority
            .wait_effect_admission("op", 1, 1)
            .expect("attached work passes");
        assert_eq!(authority.detach(Instant::now()), 0);
        assert!(authority.pending("op").is_none());
        assert!(authority.take_late("op", 1, 1), "owed its late receipt");
        drop(admission);
    }

    /// WP3 (D1–D3): a carried running command outlives the window and is
    /// stopped only at `max_carry` (B-4: exec flag set, cleanup permit kept,
    /// entry kept so its owner proves the stop); never-started work expires
    /// at the window; other issued work is revoked at the cap.
    #[cfg(target_os = "linux")]
    #[test]
    fn carry_expiry_stops_a_running_exec_only_at_max_carry() {
        let authority = HostAuthority::default();
        authority.attach(1);
        for (id, sandbox, kind) in [
            ("cmd", "sbx", "command.run"),
            ("get", "sbx", "file.get"),
            ("create", "other", "sandbox.create"),
        ] {
            authority.accept_dispatch(id, sandbox, kind, 1, 1).unwrap();
            std::mem::forget(authority.take_ownership(id, 1, 1).unwrap());
        }
        // `cmd` and `get` passed their effect gates; `create` is queued.
        drop(authority.wait_effect_admission("cmd", 1, 1).unwrap());
        drop(authority.wait_effect_admission("get", 1, 1).unwrap());
        let cleanup = authority.register_runtime("cmd", 1, 1).unwrap();
        let (exec, guard) = authority.register_exec("cmd", 1, 1).unwrap();
        drop(guard);
        let t0 = Instant::now();
        authority.detach(t0);
        let policy = CarryPolicy::new(Duration::from_secs(60), Duration::from_secs(600));
        let tick = |at: u64| {
            authority.expire_detached_work(t0 + Duration::from_secs(at), &policy, &no_lease())
        };
        let window = tick(61);
        assert_eq!(window.revoked, 1, "only the never-started create");
        assert!(window.not_issued.is_empty(), "lifecycle keeps its own path");
        assert!(
            window.stop.is_empty(),
            "the old 60 s grace no longer cancels"
        );
        assert!(authority.pending("create").is_none());
        assert!(authority.take_late("create", 1, 1));
        let quiet = tick(599);
        assert!(quiet.stop.is_empty() && quiet.revoked == 0);
        let cap = tick(600);
        assert_eq!(cap.stop, [("cmd".to_string(), 1, 1)]);
        assert_eq!(cap.revoked, 1, "the issued read is revoked at the cap");
        assert!(authority.pending("get").is_none());
        // The expiry thread makes the stop durable, then accepts it.
        assert!(authority.accept_cancel("cmd", 1, 1).is_ok());
        assert!(
            exec.load(Ordering::Acquire),
            "the exec owner terminates the guest"
        );
        assert!(!cleanup.is_cancelled(), "its cleanup permit survives");
        assert!(authority.pending("cmd").is_some(), "it settles itself");
        // Later ticks leave the stopping exec to its owner.
        let again = tick(700);
        assert!(again.stop.is_empty() && again.revoked == 0);
    }

    /// D4: never-started work expires at min(window, lease); the lease
    /// clamp applies only to that sandbox's due generation.
    #[test]
    fn intent_window_is_clamped_to_the_lease() {
        let authority = HostAuthority::default();
        authority.attach(1);
        for (id, sandbox) in [("a", "due"), ("b", "later")] {
            authority
                .accept_dispatch(id, sandbox, "command.run", 1, 1)
                .unwrap();
            std::mem::forget(authority.take_ownership(id, 1, 1).unwrap());
        }
        let t0 = Instant::now();
        authority.detach(t0);
        let policy = CarryPolicy::default();
        let at = t0 + Duration::from_secs(5);
        // An older generation's lease never clamps newer work.
        let stale = HashMap::from([("later".to_string(), 0)]);
        assert_eq!(
            authority.expire_detached_work(at, &policy, &stale).revoked,
            0
        );
        let due = HashMap::from([("due".to_string(), 1)]);
        let expired = authority.expire_detached_work(at, &policy, &due);
        assert_eq!(expired.revoked, 1);
        assert_eq!(expired.not_issued, [("a".to_string(), 1, 1)]);
        assert!(authority.pending("a").is_none(), "its lease came first");
        assert!(authority.pending("b").is_some(), "another sandbox's lease");
        // The gate refuses the revoked attempt as never issued.
        let refused = authority.wait_effect_admission("a", 1, 1).unwrap_err();
        assert!(refused.session_closed);
        assert_eq!(refused.code, SandboxErrorCode::HostEffectNotIssued);
        assert!(
            authority.take_late("a", 1, 1),
            "settles not issued by receipt"
        );
    }

    /// Adoption alone never ends the outage. A drop after a
    /// successful adoption (during the census) keeps the first drop as the
    /// `max_carry` anchor; only a registered session (`end_outage`) resets it.
    #[cfg(target_os = "linux")]
    #[test]
    fn adoption_without_registration_never_restarts_max_carry() {
        let authority = HostAuthority::default();
        authority.attach(1);
        authority
            .accept_dispatch("cmd", "sbx", "command.run", 1, 1)
            .unwrap();
        std::mem::forget(authority.take_ownership("cmd", 1, 1).unwrap());
        drop(authority.wait_effect_admission("cmd", 1, 1).unwrap());
        let policy = CarryPolicy::new(Duration::from_secs(60), Duration::from_secs(600));
        let t0 = Instant::now();
        authority.detach(t0);
        for (cycle, epoch) in (2..12u64).enumerate() {
            authority.begin_session();
            authority.attach(epoch);
            assert!(authority.adopt("cmd", 1, 1, epoch));
            // Dropped during the census, before registration.
            authority.detach(t0 + Duration::from_secs(100 * (cycle as u64 + 1)));
        }
        let cap =
            authority.expire_detached_work(t0 + Duration::from_secs(600), &policy, &no_lease());
        assert_eq!(
            cap.stop,
            [("cmd".to_string(), 1, 1)],
            "anchored at the first drop"
        );
        // A registered session ends the outage; the next drop starts afresh.
        let authority = carried_authority();
        authority.detach(t0);
        authority.begin_session();
        authority.attach(2);
        assert!(authority.adopt("op", 1, 1, 2));
        authority.end_outage();
        authority.detach(t0 + Duration::from_secs(500));
        assert_eq!(
            authority.detached_since(),
            Some(t0 + Duration::from_secs(500))
        );
    }

    /// Adopted work whose session is not registered yet (a
    /// slow audit or census) still answers to `max_carry` from the first
    /// drop; the window no longer applies to it once adopted.
    #[test]
    fn adopted_but_unregistered_work_still_hits_max_carry() {
        let authority = HostAuthority::default();
        authority.attach(1);
        for id in ["cmd", "queued"] {
            authority
                .accept_dispatch(id, "sbx", "command.run", 1, 1)
                .unwrap();
            std::mem::forget(authority.take_ownership(id, 1, 1).unwrap());
        }
        drop(authority.wait_effect_admission("cmd", 1, 1).unwrap());
        let policy = CarryPolicy::new(Duration::from_secs(60), Duration::from_secs(600));
        let t0 = Instant::now();
        authority.detach(t0);
        authority.begin_session();
        authority.attach(2);
        assert!(authority.adopt("cmd", 1, 1, 2));
        assert!(authority.adopt("queued", 1, 1, 2));
        // The census stalls: past the window nothing adopted is revoked ...
        let window =
            authority.expire_detached_work(t0 + Duration::from_secs(120), &policy, &no_lease());
        assert!(window.stop.is_empty() && window.revoked == 0);
        // ... but the cap from the first drop still stops the command.
        let cap =
            authority.expire_detached_work(t0 + Duration::from_secs(600), &policy, &no_lease());
        assert_eq!(cap.stop, [("cmd".to_string(), 1, 1)], "{cap:?}");
        assert_eq!(cap.revoked, 1, "the adopted, never-started command");
        assert_eq!(cap.not_issued, [("queued".to_string(), 1, 1)]);
        // Registration ends the outage: connected work is never expired.
        let authority = carried_authority();
        authority.detach(t0);
        authority.begin_session();
        authority.attach(2);
        assert!(authority.adopt("op", 1, 1, 2));
        authority.end_outage();
        let after =
            authority.expire_detached_work(t0 + Duration::from_secs(3600), &policy, &no_lease());
        assert!(after.stop.is_empty() && after.revoked == 0);
        assert!(authority.pending("op").is_some());
    }

    /// The effect gate's backstop follows the configured window.
    #[test]
    fn effect_gate_backstop_follows_the_carry_window() {
        let authority = carried_authority();
        authority.set_effect_gate_max_wait(Duration::from_millis(200));
        authority.detach(Instant::now());
        let started = Instant::now();
        let refused = authority.wait_effect_admission("op", 1, 1).unwrap_err();
        assert!(refused.session_closed, "fails closed as a session closure");
        assert!(started.elapsed() >= Duration::from_millis(200));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn publication_is_denied_until_adoption() {
        let authority = carried_authority();
        assert!(authority.accept_completion("op", 1, 1).is_ok());
        authority.detach(Instant::now());
        assert!(authority.accept_completion("op", 1, 1).is_err());
        authority.begin_session();
        authority.attach(2);
        assert!(authority.accept_completion("op", 1, 1).is_err());
        assert_eq!(authority.carried().len(), 1);
        // Execution gates ignore the epoch: issued effects keep running.
        assert!(authority.accept_stream("op", 1, 1).is_ok());
        assert!(!authority.adopt("op", 1, 2, 2), "exact attempt only");
        assert!(authority.adopt("op", 1, 1, 2));
        assert!(authority.accept_completion("op", 1, 1).is_ok());
        assert!(authority.carried().is_empty());
        authority.end_outage();
        // A finished adoption step clears the anchor: no stale grace.
        assert_eq!(
            expire(
                &authority,
                Instant::now() + Duration::from_secs(3600),
                Duration::ZERO
            ),
            0
        );
    }

    #[test]
    fn effect_gate_blocks_carried_work_then_releases_on_adoption() {
        let authority = carried_authority();
        authority.detach(Instant::now());
        authority.begin_session();
        let waiter = {
            let authority = authority.clone();
            std::thread::spawn(move || authority.wait_effect_admission("op", 1, 1))
        };
        std::thread::sleep(Duration::from_millis(100));
        assert!(!waiter.is_finished(), "a carried Intent job must not start");
        authority.attach(2);
        std::thread::sleep(Duration::from_millis(100));
        assert!(!waiter.is_finished(), "attach alone does not adopt");
        assert!(authority.adopt("op", 1, 1, 2));
        assert!(waiter.join().expect("join").is_ok());
        // Attached work passes straight through.
        assert!(authority.wait_effect_admission("op", 1, 1).is_ok());
    }

    #[test]
    fn effect_gate_rejects_revoked_work_as_a_session_closure() {
        let authority = carried_authority();
        authority.detach(Instant::now());
        let waiter = {
            let authority = authority.clone();
            std::thread::spawn(move || authority.wait_effect_admission("op", 1, 1))
        };
        std::thread::sleep(Duration::from_millis(50));
        assert!(authority.revoke_carried("op").is_some());
        let refused = waiter.join().expect("join").expect_err("revoked");
        assert!(refused.session_closed, "stop/kill keep their deferral");
        // Unknown work is refused without the closure marker.
        let unknown = authority
            .wait_effect_admission("other", 1, 1)
            .expect_err("unknown");
        assert!(!unknown.session_closed);
    }

    #[test]
    fn shutdown_and_revoke_all_still_revoke_everything() {
        let authority = carried_authority();
        authority.detach(Instant::now());
        let waiter = {
            let authority = authority.clone();
            std::thread::spawn(move || authority.wait_effect_admission("op", 1, 1))
        };
        std::thread::sleep(Duration::from_millis(50));
        authority.shutdown();
        assert!(
            waiter
                .join()
                .expect("join")
                .expect_err("closed")
                .session_closed
        );
        assert!(authority.pending("op").is_none());
        assert!(authority.carried().is_empty());

        let authority = carried_authority();
        assert_eq!(authority.revoke_all(), 1);
        authority.begin_session();
        let refused = authority
            .wait_effect_admission("op", 1, 1)
            .expect_err("revoked");
        assert!(refused.session_closed);
        assert!(authority.take_late("op", 1, 1));
    }

    #[test]
    fn unavailable_admission_requires_first_allocation_claim_for_not_issued_code() {
        let authority = HostAuthority::default();
        authority
            .accept_dispatch("newer", "sbx", "sandbox.reconnect", 2, 1)
            .unwrap();
        let stale = authority
            .accept_dispatch("stale", "sbx", "sandbox.create", 1, 1)
            .unwrap_err();
        assert_eq!(stale.code, SandboxErrorCode::ProtocolError);
        authority.shutdown();
        let closed = authority
            .accept_dispatch("cold", "sbx", "sandbox.reconnect", 3, 1)
            .unwrap_err();
        assert_eq!(closed.code, SandboxErrorCode::ProtocolError);
        for kind in [
            "sandbox.create",
            "sandbox.reconnect",
            "sandbox.stop",
            "sandbox.kill",
        ] {
            for first_claim in [false, true] {
                assert_eq!(
                    closed.refusal_code(kind, first_claim),
                    if first_claim && matches!(kind, "sandbox.create" | "sandbox.reconnect") {
                        SandboxErrorCode::HostEffectNotIssued
                    } else {
                        SandboxErrorCode::ProtocolError
                    },
                    "{kind}, first_claim={first_claim}"
                );
            }
        }
        assert_eq!(
            stale.refusal_code("sandbox.create", true),
            SandboxErrorCode::ProtocolError
        );
        assert!(closed.session_closed);
        assert!(authority.pending("cold").is_none());
    }

    #[test]
    fn lifecycle_continuations_reject_cancel_and_ignore_early_tombstones() {
        for kind in [
            "sandbox.create",
            "sandbox.stop",
            "sandbox.kill",
            "sandbox.reconnect",
        ] {
            let authority = HostAuthority::default();
            assert!(authority.accept_cancel("op", 1, 1).is_err());
            for saturated in [false, true] {
                authority.0.lock().expect("lock").cancel_tombstones_full = saturated;
                assert!(authority.accept_dispatch("op", "sbx", kind, 1, 1).is_ok());
                assert!(authority.accept_cancel("op", 1, 1).is_err());
                authority.cancel("op");
                assert!(authority.accept_completion("op", 1, 1).is_ok());
                assert!(!authority.0.lock().expect("lock").cancelled.contains("op"));
            }
            authority.complete("op");
            assert!(authority.accept_cancel("op", 1, 2).is_err());
            assert!(authority.accept_dispatch("op", "sbx", kind, 1, 2).is_ok());
        }
    }

    #[test]
    fn ordinary_guest_kinds_remain_cancellable() {
        for kind in CANCELLABLE_DISPATCH_KINDS {
            let authority = HostAuthority::default();
            authority
                .accept_dispatch("op", "sbx", kind, 1, 1)
                .expect("admit");
            assert!(authority.accept_cancel("op", 1, 1).is_ok());
            assert!(authority.accept_cancel("op", 1, 1).is_err());
        }
    }

    #[test]
    fn unknown_cancel_tombstone_refuses_exact_tuple_and_replay() {
        let authority = HostAuthority::default();
        assert!(authority.accept_cancel("early", 2, 1).is_err());
        for _ in 0..2 {
            assert_eq!(
                authority
                    .accept_dispatch("early", "sbx", "command.run", 2, 1)
                    .expect_err("cancelled before admission")
                    .code,
                SandboxErrorCode::Cancelled
            );
            assert!(authority.pending("early").is_none());
        }
        assert!(
            authority
                .accept_dispatch("early", "sbx", "command.run", 2, 2)
                .expect("new attempt")
        );
        authority.complete("early");
        authority
            .accept_dispatch("new-generation", "sbx", "sandbox.stop", 3, 1)
            .expect("advance generation");
        assert_eq!(
            authority
                .accept_dispatch("early", "sbx", "command.run", 2, 1)
                .expect_err("tombstone survives completion")
                .code,
            SandboxErrorCode::Cancelled
        );
        authority.shutdown();
        assert!(
            authority
                .accept_dispatch("fresh", "sbx", "command.run", 2, 1)
                .is_err()
        );
    }

    #[test]
    fn tombstone_capacity_fails_closed_without_eviction_or_growth() {
        let authority = HostAuthority::default();
        authority
            .accept_dispatch("active", "sbx", "command.run", 1, 1)
            .expect("active");
        for i in 0..=MAX_CANCEL_TOMBSTONES {
            assert!(
                authority
                    .accept_cancel(&format!("early-{i}"), 1, 1)
                    .is_err()
            );
        }
        assert_eq!(
            authority.0.lock().expect("lock").cancel_tombstones.len(),
            MAX_CANCEL_TOMBSTONES
        );
        for id in ["early-0", "early-1024", "new"] {
            assert_eq!(
                authority
                    .accept_dispatch(id, "sbx", "command.run", 1, 1)
                    .expect_err("saturated")
                    .code,
                SandboxErrorCode::Cancelled
            );
        }
        authority
            .accept_cancel("active", 1, 1)
            .expect("existing work still drains");
        authority.complete("active");
    }

    #[test]
    fn rejects_stale_put_bytes_after_newer_dispatch() {
        let authority = HostAuthority::default();
        authority
            .accept_dispatch("op-put", "sbx-1", "file.put", 2, 2)
            .expect("put");
        let err = authority
            .accept_stream("op-put", 1, 1)
            .expect_err("stale bytes");
        assert_eq!(err.code, SandboxErrorCode::ProtocolError);
    }

    #[test]
    fn rejects_stale_reconnect_and_command_after_stop() {
        let authority = HostAuthority::default();
        authority
            .accept_dispatch("op-stop", "sbx-1", "sandbox.stop", 3, 1)
            .expect("stop");
        let err = authority
            .accept_dispatch("op-re", "sbx-1", "sandbox.reconnect", 1, 1)
            .expect_err("stale reconnect");
        assert_eq!(err.code, SandboxErrorCode::ProtocolError);
        let err = authority
            .accept_dispatch("op-cmd", "sbx-1", "command.run", 1, 1)
            .expect_err("stale command");
        assert_eq!(err.code, SandboxErrorCode::ProtocolError);
    }

    #[test]
    fn ignores_stale_stdin_and_cancel() {
        let authority = HostAuthority::default();
        authority
            .accept_dispatch("op-cmd", "sbx-1", "command.run", 2, 2)
            .expect("cmd");
        assert!(authority.accept_stream("op-cmd", 1, 1).is_err());
        assert!(authority.accept_cancel("op-cmd", 1, 1).is_err());
        authority
            .accept_stream("op-cmd", 2, 2)
            .expect("current stdin");
    }

    #[test]
    fn stop_invalidates_pending_puts() {
        let authority = HostAuthority::default();
        authority
            .accept_dispatch("op-put", "sbx-1", "file.put", 1, 1)
            .expect("put");
        authority
            .accept_dispatch("op-stop", "sbx-1", "sandbox.stop", 2, 1)
            .expect("stop");
        assert!(authority.accept_stream("op-put", 1, 1).is_err());
    }
    #[test]
    fn duplicates_and_attempt_mismatch_cannot_replace_pending_work() {
        let authority = HostAuthority::default();
        assert!(
            authority
                .accept_dispatch("op", "sbx", "file.put", 2, 2)
                .expect("first")
        );
        assert!(
            !authority
                .accept_dispatch("op", "sbx", "file.put", 2, 2)
                .expect("duplicate")
        );
        for (generation, attempt) in [(1, 1), (2, 1), (2, 3), (3, 3)] {
            assert!(
                authority
                    .accept_dispatch("op", "sbx", "file.put", generation, attempt)
                    .is_err()
            );
        }
        assert!(
            authority
                .accept_dispatch("op", "other", "file.put", 2, 2)
                .is_err()
        );
        authority.complete("op");
        assert!(
            !authority
                .accept_dispatch("op", "sbx", "file.put", 2, 2)
                .expect("completed duplicate")
        );
        assert!(
            authority
                .accept_dispatch("op", "sbx", "file.put", 2, 3)
                .expect("new attempt")
        );
    }

    #[test]
    fn warm_reconnect_keeps_current_controls_puts_and_completion() {
        let authority = HostAuthority::default();
        authority
            .accept_dispatch("cmd", "sbx", "command.run", 2, 1)
            .expect("command");
        authority
            .accept_dispatch("put", "sbx", "file.put", 2, 1)
            .expect("put");
        authority
            .accept_dispatch("reconnect", "sbx", "sandbox.reconnect", 2, 1)
            .expect("reconnect");
        assert!(authority.accept_stream("cmd", 2, 1).is_ok());
        assert!(authority.accept_cancel("cmd", 2, 1).is_ok());
        assert!(authority.accept_stream("put", 2, 1).is_ok());
        assert!(authority.accept_completion("cmd", 2, 1).is_ok());
        authority
            .accept_dispatch("stop", "sbx", "sandbox.stop", 3, 1)
            .expect("stop");
        assert!(authority.accept_completion("cmd", 2, 1).is_err());
    }
    #[test]
    fn ordinary_dispatch_advances_observed_generation() {
        let authority = HostAuthority::default();
        authority
            .accept_dispatch("new", "sbx", "command.run", 4, 1)
            .expect("new");
        assert!(
            authority
                .accept_dispatch("old", "sbx", "command.run", 1, 1)
                .is_err()
        );
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn registered_execution_is_cancelled_by_disruption_and_shutdown() {
        use std::sync::Barrier;
        let authority = HostAuthority::default();
        authority
            .accept_dispatch("cmd", "sbx", "command.run", 1, 1)
            .expect("command");
        let barrier = Arc::new(Barrier::new(2));
        let registered = barrier.clone();
        let worker_authority = authority.clone();
        let worker = std::thread::spawn(move || {
            let (permit, guard) = worker_authority
                .register_exec("cmd", 1, 1)
                .expect("register");
            drop(guard);
            registered.wait();
            registered.wait();
            assert!(permit.load(Ordering::Acquire));
        });
        barrier.wait();
        authority
            .accept_dispatch("warm", "sbx", "sandbox.reconnect", 1, 1)
            .expect("warm");
        assert!(authority.accept_stream("cmd", 1, 1).is_ok());
        authority
            .accept_dispatch("stop", "sbx", "sandbox.stop", 2, 1)
            .expect("stop");
        barrier.wait();
        worker.join().expect("worker");
        authority
            .accept_dispatch("next", "sbx", "command.run", 3, 1)
            .expect("next");
        let (permit, guard) = authority.register_exec("next", 3, 1).expect("register");
        drop(guard);
        authority.shutdown();
        assert!(permit.load(Ordering::Acquire));
        assert!(authority.register_exec("next", 3, 1).is_err());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn cancel_keeps_worker_identity_until_completion() {
        let authority = HostAuthority::default();
        authority
            .accept_dispatch("cmd", "sbx", "command.run", 1, 1)
            .expect("command");
        let (permit, guard) = authority.register_exec("cmd", 1, 1).expect("register");
        drop(guard);
        authority.cancel("cmd");
        assert!(permit.load(Ordering::Acquire));
        assert!(authority.accept_stream("cmd", 1, 1).is_err());
        assert!(
            authority
                .accept_dispatch("cmd", "sbx", "command.run", 1, 2)
                .is_err()
        );
        assert!(authority.accept_completion("cmd", 1, 1).is_ok());
        authority.complete("cmd");
        assert!(
            authority
                .accept_dispatch("cmd", "sbx", "command.run", 1, 2)
                .is_ok()
        );
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn stdin_byte_bound_eof_and_new_attempt_start() {
        let authority = HostAuthority::default();
        authority
            .accept_dispatch("cmd", "sbx", "command.run", 1, 1)
            .expect("admit");
        assert!(
            authority
                .accept_stdin("cmd", 1, 1, 1, vec![0; 1024 * 1024], false)
                .expect("buffer")
                .is_empty()
        );
        assert_eq!(
            authority
                .accept_stdin("cmd", 1, 1, 2, vec![0], true)
                .expect_err("byte bound")
                .code,
            SandboxErrorCode::RequestTooLarge
        );
        assert!(
            authority
                .accept_stdin("cmd", 1, 1, 0, vec![1], false)
                .expect("closed")
                .is_empty()
        );
        authority.complete("cmd");
        authority
            .accept_dispatch("cmd", "sbx", "command.run", 1, 2)
            .expect("retry");
        authority.start_stdin("cmd", 7);
        assert!(
            authority
                .accept_stdin("cmd", 1, 2, 6, vec![1], false)
                .expect("old")
                .is_empty()
        );
        let ready = authority
            .accept_stdin("cmd", 1, 2, 7, Vec::new(), true)
            .expect("empty EOF");
        assert_eq!(ready.len(), 1);
        assert!(ready[0].eof);
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn revocation_contends_with_the_real_guard_between_permit_check_and_spawn() {
        use sandbox_runtime::{ExecSupervisor, IncusClient, RunCommandRequest};
        use std::sync::{Barrier, mpsc};
        use std::time::Duration;
        let dir = std::env::temp_dir().join(format!("wssp-c08-guard-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let shim = dir.join("shim");
        crate::sandbox_relay::test_support::install_executable(
            &shim,
            "#!/bin/sh\nif [ \"$1\" = \"query\" ]; then echo '{\"type\":\"sync\",\"metadata\":{\"status\":\"Running\",\"status_code\":103,\"type\":\"virtual-machine\",\"config\":{\"user.flycockpit.sandbox_id\":\"sbx\",\"user.flycockpit.template_digest\":\"sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\",\"volatile.base_image\":\"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\"}}}'; exit 0; fi\nsleep 60\n",
            0o700,
        );
        let supervisor = ExecSupervisor::new(IncusClient::new(shim.to_string_lossy(), "default"));
        let authority = HostAuthority::default();
        authority
            .accept_dispatch("cmd", "sbx", "command.run", 1, 1)
            .expect("admit");
        let checked = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        let worker = std::thread::spawn({
            let authority = authority.clone();
            let supervisor = supervisor.clone();
            let checked = checked.clone();
            let resume = resume.clone();
            move || {
                let request = RunCommandRequest {
                    template_fingerprint: sandbox_runtime::CreateSandboxRequest::for_test(
                        "sbx", "key",
                    )
                    .template_digest,
                    sandbox_id: "sbx".into(),
                    instance_name: "wssp-sbx-sbx".into(),
                    operation_id: "cmd".into(),
                    idempotency_key: "cmd".into(),
                    generation: 1,
                    attempt: 1,
                    argv: vec!["true".into()],
                    script: None,
                    cwd: None,
                    timeout_ms: Some(3000),
                    env: Vec::new(),
                    stdin: None,
                    guest: sandbox_runtime::GuestIdentity::default(),
                    build_step: None,
                };
                supervisor.run_with_admission(&supervisor.bind(&request).unwrap(), &request, || {
                    let permit = authority
                        .register_exec("cmd", 1, 1)
                        .expect("guarded permit check");
                    checked.wait();
                    resume.wait();
                    Ok(permit)
                })
            }
        });
        checked.wait();
        assert!(
            authority.0.try_lock().is_err(),
            "actual authority mutex stays held before spawn"
        );
        let (entered_tx, entered_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let revoke = std::thread::spawn({
            let authority = authority.clone();
            move || {
                entered_tx.send(()).expect("entered");
                authority.accept_cancel("cmd", 1, 1).expect("cancel");
                supervisor.kill_local_groups();
                done_tx.send(()).expect("done");
            }
        });
        entered_rx.recv().expect("revoker entering");
        let blocked = done_rx.recv_timeout(Duration::from_millis(50)).is_err();
        resume.wait();
        done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("revoke after publication");
        revoke.join().expect("revoker");
        let result = worker.join().expect("worker");
        assert!(
            blocked,
            "revocation cannot complete in the check/spawn interval"
        );
        assert_eq!(
            result.expect_err("revoked child").code,
            SandboxErrorCode::UnknownOutcome
        );
        std::fs::remove_dir_all(dir).expect("cleanup");
    }
}
