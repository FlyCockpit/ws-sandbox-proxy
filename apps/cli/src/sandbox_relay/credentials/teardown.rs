//! Daemon teardown: capture by default on every
//! stop, kill and local expiry, inside one persisted teardown attempt per
//! sandbox.
//!
//! - **Attempts.** A stop, kill, local expiry or server expiry STOP opens an
//!   attempt or joins the open one. A joiner never takes the guest slot
//!   while this process runs the attempt: it waits for the runner and
//!   reports the same capture ids (expiry checks the attempt before the
//!   slot). With no runner in this process (restart, superseded runner) the
//!   joiner runs the attempt itself and reuses every recorded capture.
//! - **Pre-checks before quiesce (N11).** Binding spec journaled, return key
//!   acked, host owner known, outbox room for the worst-case envelope,
//!   helper present. A user stop/kill that fails them is refused with no
//!   guest process touched.
//! - **Outcome rules.** Scrub only after COMMITTED/UNCHANGED, an
//!   authorized DISCARDED, or a durable envelope (DEFERRED or no answer)
//!   sealed under the newest acked key. REJECTED never scrubs.
//! - **Refusal.** A user stop/kill with any capture failure is refused:
//!   the attempt abort and the owed host lease re-bind are ONE credential
//!   journal write; the lease journal is re-bound right after (and replayed
//!   at startup), all before the FAILED receipt. The VM keeps running and
//!   keeps its env.
//!
//! Nothing here logs a value, a path or a frame body.

use super::*;
use sandbox_protocol::{
    CREDENTIAL_SCRUBBED_BINDINGS_MAX, CREDENTIAL_TEARDOWN_OUTCOMES_MAX,
    CredentialTeardownOutcomeV11, TeardownCaptureV11, TeardownScrubV11,
};
use sandbox_runtime::RuntimePermit;

use super::super::journal::{AttemptState, TeardownCaptureState};
use super::super::slot::{EXPIRY_SLOT_WAIT, SlotError, TEARDOWN_SLOT_WAIT};

/// Local expiry's credential phase (pre-checks, quiesce, pack, seal,
/// upload attempt, scrub) before its 16 s graceful stop.
pub const EXPIRY_CREDENTIAL_PHASE: Duration = Duration::from_secs(20);
/// A stop/kill's credential phase: slot wait (10 s) plus the outcome wait
/// (30 s) with margin for quiesce, pack and scrub.
pub const TEARDOWN_CREDENTIAL_BUDGET: Duration = Duration::from_secs(45);
/// How long a preempted slot holder gets to let go.
const SLOT_RELEASE: Duration = Duration::from_secs(5);

/// Which teardown runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeardownPath {
    Stop,
    Kill,
    /// Local lease expiry; `destroy` for a destroy-on-expiry lease.
    Expiry {
        destroy: bool,
    },
}

impl TeardownPath {
    fn kind(self) -> CaptureKind {
        match self {
            Self::Stop => CaptureKind::Stop,
            Self::Kill => CaptureKind::Kill,
            Self::Expiry { .. } => CaptureKind::Expiry,
        }
    }
    /// Stop paths scrub; kill and destroy-on-expiry destroy the disk.
    fn scrubs(self) -> bool {
        matches!(self, Self::Stop | Self::Expiry { destroy: false })
    }
}

#[derive(Debug, Clone)]
pub struct TeardownRequest {
    pub operation_id: String,
    pub guest: CredentialGuest,
    pub sandbox_owner_id: String,
    /// The host owner when no registration is known yet (offline expiry
    /// after a restart reads it from the lease record).
    pub host_owner_id: Option<String>,
    pub path: TeardownPath,
    /// Expiry/access/readiness writers and local expiry: never refused.
    pub system: bool,
    /// `credentialCapture: "skip"`.
    pub skip: bool,
    /// The dispatch named a spec that could not be fetched or verified: a
    /// pre-check failure for any binding still to capture.
    pub spec_unverified: bool,
    /// The stop/kill generation (the re-bind target of a refusal).
    pub generation: u64,
    pub budget: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TeardownVerdict {
    /// The sandbox holds no credential state: nothing to do or report.
    NoCredentials,
    /// Go ahead and stop/destroy; the receipt carries these outcomes.
    Proceed(Vec<CredentialTeardownOutcomeV11>),
    /// User stop/kill refused (`credential_capture_failed`): the abort and
    /// the host lease re-bind are durable; the VM keeps running.
    Refused(Vec<CredentialTeardownOutcomeV11>),
    /// The operation stopped being wanted (superseded, cancelled). The
    /// attempt stays open for the superseding teardown to join.
    Cancelled,
    /// The journal could not record the decision: the outcome is unknown.
    Uncertain,
}

/// A free's capture, for the attach/free lane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FreeCapture {
    /// Sealed durable; the free continues with its upload.
    Sealed(OutboxEntry),
    /// Revoked after sealing: the envelope is recorded under the open
    /// teardown attempt so the superseding stop joins it.
    RevokedRecorded(OutboxEntry),
    /// Revoked before sealing, or the pack failed.
    Abandoned,
}

#[derive(Debug, Clone)]
struct Done {
    attempt_id: String,
    outcomes: Vec<CredentialTeardownOutcomeV11>,
    scrubbed: bool,
    refused: bool,
}

#[derive(Debug, Default)]
struct Progress {
    /// The attempt this process is running now, with its runner's token.
    running: Option<String>,
    token: u64,
    /// The last attempt this process finished running.
    done: Option<Done>,
}

/// Per-sandbox coordination: the guest slot and teardown progress.
#[derive(Debug, Default)]
pub struct Coord {
    pub slot: CredSandbox,
    progress: Mutex<Progress>,
    cv: Condvar,
}

/// Clears `running` on every exit path of its runner (and only its own:
/// a joiner that took over an overrunning attempt holds a newer token).
struct Running<'a>(&'a Coord, u64);

impl<'a> Running<'a> {
    fn start(coord: &'a Coord, attempt_id: &str) -> Self {
        let mut progress = lock(&coord.progress);
        progress.token += 1;
        progress.running = Some(attempt_id.to_owned());
        Self(coord, progress.token)
    }
}

impl Drop for Running<'_> {
    fn drop(&mut self) {
        let mut progress = lock(&self.0.progress);
        if progress.token == self.1 {
            progress.running = None;
        }
        drop(progress);
        self.0.cv.notify_all();
    }
}

enum Joined {
    Outcomes(Vec<CredentialTeardownOutcomeV11>),
    Run,
    Cancelled,
}

/// Per-binding capture result inside one teardown (a binding without one
/// was not captured: copy-back off, proxy, skip, login, recovery-required).
#[derive(Debug, Clone)]
enum Captured {
    Acked {
        capture_id: String,
        outcome: CaptureAckOutcome,
        scrub_ok: bool,
    },
    Durable {
        capture_id: String,
        scrub_ok: bool,
    },
    Failed(&'static str),
}

impl Captured {
    fn failed(&self) -> bool {
        match self {
            Self::Acked { scrub_ok, .. } | Self::Durable { scrub_ok, .. } => !scrub_ok,
            Self::Failed(_) => true,
        }
    }
    fn wire(&self) -> TeardownCaptureV11 {
        match self {
            Self::Acked {
                capture_id,
                outcome,
                ..
            } => TeardownCaptureV11::Acked {
                capture_id: capture_id.clone(),
                outcome: *outcome,
            },
            Self::Durable { capture_id, .. } => TeardownCaptureV11::Durable {
                capture_id: capture_id.clone(),
            },
            Self::Failed(reason) => TeardownCaptureV11::Failed {
                reason: (*reason).to_owned(),
            },
        }
    }
}

/// Whether the teardown captures this binding at all.
pub(super) fn capturable(binding: &BindingRecord) -> bool {
    matches!(binding.phase, BindingPhase::Active | BindingPhase::Teardown)
        && binding.purpose != BindingPurpose::Login
        && binding.copy_back
        && binding.exclusive
        && binding
            .spec
            .as_ref()
            .is_none_or(|s| s.delivery == CredentialDelivery::Guest && s.files.includes_paths())
}

/// Whether a login finish (`credential.free` of a LOGIN lease)
/// captures this binding: a LOGIN binding that is live. Teardowns never
/// capture it (`capturable`): cancel, expiry and the destroy after a save
/// skip capture, and the login sandbox is destroyed, never scrubbed.
pub(super) fn login_capturable(binding: &BindingRecord) -> bool {
    matches!(binding.phase, BindingPhase::Active | BindingPhase::Teardown)
        && binding.purpose == BindingPurpose::Login
        && binding
            .spec
            .as_ref()
            .is_some_and(|s| s.delivery == CredentialDelivery::Guest && s.files.includes_paths())
}

/// Whether a stop scrubs this binding's paths (shareable included).
fn scrubbable(binding: &BindingRecord) -> bool {
    binding.phase != BindingPhase::RecoveryRequired
        && binding.purpose != BindingPurpose::Login
        && binding.spec.is_some()
}

fn outcomes_of(
    bindings: &[BindingRecord],
    captured: &BTreeMap<String, Captured>,
    scrub: &BTreeMap<String, TeardownScrubV11>,
) -> Vec<CredentialTeardownOutcomeV11> {
    bindings
        .iter()
        .take(CREDENTIAL_TEARDOWN_OUTCOMES_MAX)
        .map(|b| CredentialTeardownOutcomeV11 {
            lease_id: Some(b.lease_id.clone()),
            binding_id: b.binding_id.clone(),
            capture: captured
                .get(&b.binding_id)
                .map_or(TeardownCaptureV11::None, Captured::wire),
            scrub: scrub
                .get(&b.binding_id)
                .copied()
                .unwrap_or(TeardownScrubV11::NotRun),
        })
        .collect()
}

impl CredentialService {
    /// Applies every re-bind a refused teardown still owes the host lease
    /// journal (startup replay and before any new attempt). Returns false
    /// when one could not be applied.
    pub fn replay_rebinds(&self, rebind: &dyn Fn(&str, u64) -> anyhow::Result<()>) -> bool {
        self.replay_rebinds_where(&|_| true, rebind)
    }

    fn replay_rebinds_where(
        &self,
        only: &dyn Fn(&str) -> bool,
        rebind: &dyn Fn(&str, u64) -> anyhow::Result<()>,
    ) -> bool {
        let owed = self.inner.store.journal().pending_rebinds();
        let mut ok = true;
        for (sandbox_id, generation) in owed.into_iter().filter(|(id, _)| only(id)) {
            match rebind(&sandbox_id, generation) {
                Ok(()) => {
                    let _ = self
                        .inner
                        .store
                        .journal()
                        .mark_rebind_applied(&sandbox_id, generation);
                }
                Err(_) => {
                    tracing::warn!("refused teardown re-bind could not be applied");
                    ok = false;
                }
            }
        }
        ok
    }

    /// Enforcement loss (without the slot state lock): revokes the slot holder, marks
    /// every binding recovery-required (no capture, no scrub) and drops the
    /// env. Never takes the slot state lock or waits.
    pub fn enforcement_loss(&self, sandbox_id: &str) {
        self.coord(sandbox_id).slot.revoke();
        if self
            .inner
            .store
            .journal()
            .mark_recovery_required(sandbox_id)
            .is_err()
        {
            tracing::warn!("credential enforcement loss could not be journaled");
        }
        self.forget_sandbox_env(sandbox_id);
    }

    /// The VM stopped (`destroyed`: deleted) after its teardown: the attempt
    /// is done and settled bindings are forgotten.
    pub fn settle_teardown(&self, sandbox_id: &str, destroyed: bool) {
        let has_state = {
            let journal = self.inner.store.journal();
            journal.bindings_of(sandbox_id).next().is_some()
                || journal
                    .teardown_attempt(sandbox_id)
                    .is_some_and(|a| a.state == AttemptState::Open)
        };
        if has_state
            && self
                .inner
                .store
                .journal()
                .settle_teardown(sandbox_id, destroyed)
                .is_err()
        {
            tracing::warn!("credential teardown settlement could not be journaled");
        }
        self.forget_sandbox_env(sandbox_id);
        lock(&self.inner.sandboxes).remove(sandbox_id);
    }

    /// Stop/kill/expiry credential phase. `rebind(generation)` re-binds the
    /// host lease row of this sandbox (refusal only).
    pub fn teardown(
        &self,
        runtime: &dyn SandboxRuntime,
        req: &TeardownRequest,
        spec: Option<&CredentialSpecV11>,
        still_wanted: &dyn Fn() -> bool,
        rebind: &dyn Fn(u64) -> anyhow::Result<()>,
    ) -> TeardownVerdict {
        let deadline = Instant::now() + req.budget;
        let sandbox_id = req.guest.sandbox_id.clone();
        // A refused attempt's owed re-bind reaches the lease journal before
        // anything else (and before a new attempt replaces its record).
        if !self.replay_rebinds_where(&|id| id == sandbox_id, &|_, generation| rebind(generation)) {
            return TeardownVerdict::Uncertain;
        }
        // Replay of a refused user stop/kill (crash before its receipt).
        if !req.system {
            let refused = self
                .inner
                .store
                .journal()
                .refused_teardown(&sandbox_id, &req.operation_id);
            if refused.is_some() {
                let bindings: Vec<BindingRecord> = self
                    .inner
                    .store
                    .journal()
                    .bindings_of(&sandbox_id)
                    .cloned()
                    .collect();
                let failed = bindings
                    .iter()
                    .filter(|b| capturable(b))
                    .map(|b| (b.binding_id.clone(), Captured::Failed("capture_failed")))
                    .collect();
                return TeardownVerdict::Refused(outcomes_of(&bindings, &failed, &BTreeMap::new()));
            }
        }
        let residue: Vec<&sandbox_protocol::SpecResidueV11> = spec
            .filter(|s| s.sandbox_id == sandbox_id)
            .map(|s| {
                s.residue
                    .iter()
                    .filter(|r| r.action == SpecResidueAction::Scrub)
                    .collect()
            })
            .unwrap_or_default();
        let coord = self.coord(&sandbox_id);
        // Two rounds at most: a joiner whose runner was refused opens a
        // fresh attempt (an aborted attempt is never joined).
        for _ in 0..2 {
            let has_bindings = self
                .inner
                .store
                .journal()
                .bindings_of(&sandbox_id)
                .next()
                .is_some();
            if !has_bindings && residue.is_empty() {
                // A proxy-enabled sandbox whose logins were all freed keeps
                // its listener until here: it goes with the VM.
                self.forget_sandbox_env(&sandbox_id);
                return TeardownVerdict::NoCredentials;
            }
            // Expiry and every other path check the attempt before the slot.
            let handle = match self
                .inner
                .store
                .journal()
                .open_or_join_teardown(&sandbox_id, &req.operation_id)
            {
                Ok(handle) => handle,
                Err(_) => return TeardownVerdict::Uncertain,
            };
            if handle.joined {
                match self.join(&coord, &handle.attempt_id, req.path, deadline, still_wanted) {
                    Joined::Outcomes(outcomes) => return TeardownVerdict::Proceed(outcomes),
                    Joined::Cancelled => return TeardownVerdict::Cancelled,
                    Joined::Run => {}
                }
                // A refused runner aborted the attempt: open a fresh one.
                let aborted = self
                    .inner
                    .store
                    .journal()
                    .teardown_attempt(&sandbox_id)
                    .is_none_or(|a| {
                        a.attempt_id != handle.attempt_id || a.state != AttemptState::Open
                    });
                if aborted {
                    continue;
                }
            }
            let _running = Running::start(&coord, &handle.attempt_id);
            return self.run(
                runtime,
                req,
                &coord,
                &handle.attempt_id,
                &residue,
                deadline,
                still_wanted,
                rebind,
            );
        }
        TeardownVerdict::Uncertain
    }

    /// Waits for this process's runner of `attempt_id` (never for the slot).
    fn join(
        &self,
        coord: &Coord,
        attempt_id: &str,
        path: TeardownPath,
        deadline: Instant,
        still_wanted: &dyn Fn() -> bool,
    ) -> Joined {
        let mut progress = lock(&coord.progress);
        while progress.running.as_deref() == Some(attempt_id) {
            if !still_wanted() {
                return Joined::Cancelled;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                // The runner overran this joiner's budget: run it here
                // (recorded captures are reused; the slot preempts).
                return Joined::Run;
            }
            progress = coord
                .cv
                .wait_timeout(progress, left.min(POLL))
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
        match &progress.done {
            Some(done)
                if done.attempt_id == attempt_id
                    && !done.refused
                    && (done.scrubbed || !path.scrubs()) =>
            {
                Joined::Outcomes(done.outcomes.clone())
            }
            _ => Joined::Run,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn run(
        &self,
        runtime: &dyn SandboxRuntime,
        req: &TeardownRequest,
        coord: &Coord,
        attempt_id: &str,
        residue: &[&sandbox_protocol::SpecResidueV11],
        deadline: Instant,
        still_wanted: &dyn Fn() -> bool,
        rebind: &dyn Fn(u64) -> anyhow::Result<()>,
    ) -> TeardownVerdict {
        let sandbox_id = req.guest.sandbox_id.as_str();
        let store = &self.inner.store;
        let bindings: Vec<BindingRecord> =
            store.journal().bindings_of(sandbox_id).cloned().collect();
        let host_owner = req.host_owner_id.clone().or_else(|| self.host_owner());
        let candidates: Vec<&BindingRecord> = if req.skip {
            Vec::new()
        } else {
            bindings.iter().filter(|b| capturable(b)).collect()
        };
        let recorded = |b: &BindingRecord| {
            b.teardown.as_ref().is_some_and(|t| {
                t.attempt_id == attempt_id && t.state != TeardownCaptureState::Reserved
            })
        };
        let to_pack: Vec<&BindingRecord> = candidates
            .iter()
            .copied()
            .filter(|b| !recorded(b))
            .collect();
        let mut captured: BTreeMap<String, Captured> = BTreeMap::new();

        // --- pre-checks, before any guest effect (N11) ---------------------
        if !to_pack.is_empty() {
            let passed = !req.spec_unverified
                && self.prechecks(runtime, &req.guest, host_owner.is_some(), &to_pack);
            if !passed {
                if !req.system {
                    return self.refuse(
                        req,
                        coord,
                        attempt_id,
                        &bindings,
                        &BTreeMap::new(),
                        rebind,
                    );
                }
                for b in &to_pack {
                    captured.insert(b.binding_id.clone(), Captured::Failed("precheck_failed"));
                }
            }
        }

        // --- exclusive guest access ------------------------------------------
        let left = deadline.saturating_duration_since(Instant::now());
        let permit = Arc::new(RuntimePermit::with_timeout(
            left.max(Duration::from_secs(1)),
        ));
        let scoped = runtime.with_cancellation(permit.clone());
        let (user, wait) = match req.path {
            TeardownPath::Expiry { .. } => (SlotUser::Expiry, EXPIRY_SLOT_WAIT),
            _ => (SlotUser::Teardown, TEARDOWN_SLOT_WAIT),
        };
        let guard =
            coord
                .slot
                .acquire_preempting(user, wait.min(left), SLOT_RELEASE.min(left), &permit);
        let guard = match guard {
            Ok(guard) => Some(guard),
            Err(SlotError::HolderStuck | SlotError::Busy | SlotError::Revoked) => {
                if !req.system {
                    return self.refuse(
                        req,
                        coord,
                        attempt_id,
                        &bindings,
                        &BTreeMap::new(),
                        rebind,
                    );
                }
                for b in &candidates {
                    captured
                        .entry(b.binding_id.clone())
                        .or_insert(Captured::Failed("slot_busy"));
                }
                None
            }
        };
        let current_kid = store.journal().key_slot().map(|k| k.kid_r.clone());

        // --- quiesce, pack, seal (or reuse this attempt's captures) ----------
        let mut uploads: Vec<(String, OutboxEntry)> = Vec::new();
        if guard.is_some() {
            let packing = to_pack
                .iter()
                .any(|b| !captured.contains_key(&b.binding_id));
            if packing && scoped.credential_quiesce(&req.guest).is_err() {
                // Pack/scrub correctness never depends on quiesce.
                tracing::warn!("credential quiesce incomplete; capturing anyway");
            }
            for b in &candidates {
                if captured.contains_key(&b.binding_id) {
                    continue;
                }
                let result = self.capture_one(
                    scoped.as_ref(),
                    req,
                    host_owner.as_deref().unwrap_or_default(),
                    attempt_id,
                    b,
                );
                match result {
                    Ok(Ok(entry)) => uploads.push((b.binding_id.clone(), entry)),
                    Ok(Err(done)) => {
                        captured.insert(b.binding_id.clone(), done);
                    }
                    Err(reason) => {
                        captured.insert(b.binding_id.clone(), Captured::Failed(reason));
                    }
                }
            }
        }

        // --- upload → outcome (charged to the budget) ------------------------
        for (binding_id, entry) in uploads {
            if !still_wanted() {
                return TeardownVerdict::Cancelled;
            }
            let wait = deadline
                .saturating_duration_since(Instant::now())
                .min(ACK_WAIT);
            let under_current = current_kid.as_deref() == Some(entry.kid_r.as_str());
            let result = match self.upload_within(&entry, wait, still_wanted) {
                Ok(Some(ack)) => {
                    let scrub_ok = match ack.outcome {
                        CaptureAckOutcome::Committed | CaptureAckOutcome::Unchanged => true,
                        CaptureAckOutcome::Discarded => {
                            ack.reason.is_some_and(CaptureAckReason::is_discard)
                        }
                        CaptureAckOutcome::Deferred => under_current,
                        CaptureAckOutcome::Rejected => false,
                    };
                    Captured::Acked {
                        capture_id: entry.capture_id.clone(),
                        outcome: ack.outcome,
                        scrub_ok,
                    }
                }
                Ok(None) => Captured::Durable {
                    capture_id: entry.capture_id.clone(),
                    scrub_ok: under_current,
                },
                Err(LaunchFailure::Cancelled) => return TeardownVerdict::Cancelled,
                Err(_) => Captured::Failed("upload_failed"),
            };
            captured.insert(binding_id, result);
        }

        // --- outcome rules ---------------------------------------------
        let failed: Vec<String> = captured
            .iter()
            .filter(|(_, c)| c.failed())
            .map(|(id, _)| id.clone())
            .collect();
        if !failed.is_empty() && !req.system {
            drop(guard);
            return self.refuse(req, coord, attempt_id, &bindings, &captured, rebind);
        }
        if req.path.scrubs()
            && store
                .journal()
                .mark_bindings_recovery_required(&failed)
                .is_err()
        {
            tracing::warn!("credential recovery-required state could not be journaled");
        }

        // --- scrub every credential binding plus listed residue (stop) -------
        let mut scrub: BTreeMap<String, TeardownScrubV11> = BTreeMap::new();
        let mut last = 0;
        // Without the slot (a stuck holder) nothing touches the guest: the
        // VM stops with every file in place, recovery-required.
        if req.path.scrubs() && guard.is_some() {
            let targets: Vec<&BindingRecord> = bindings
                .iter()
                .filter(|b| scrubbable(b) && !failed.contains(&b.binding_id))
                .collect();
            let mut paths: Vec<String> = targets
                .iter()
                .filter_map(|b| b.spec.as_ref())
                .flat_map(super::super::ops::included_paths)
                .chain(residue.iter().flat_map(|r| r.paths.iter().cloned()))
                .collect();
            paths.sort();
            paths.dedup();
            let mut ids: Vec<String> = targets
                .iter()
                .map(|b| b.binding_id.clone())
                .chain(residue.iter().map(|r| r.binding_id.clone()))
                .collect();
            ids.sort();
            ids.dedup();
            ids.truncate(CREDENTIAL_SCRUBBED_BINDINGS_MAX);
            if !ids.is_empty() {
                let verified = scrub_paths(scoped.as_ref(), &req.guest, paths).unwrap_or(false);
                last = self.push(DaemonControlMessage::CredentialScrubbed(
                    CredentialScrubbedV11 {
                        sandbox_id: sandbox_id.to_owned(),
                        binding_ids: ids.clone(),
                        verified_absent: verified,
                    },
                ));
                if verified && store.journal().mark_scrubbed(&ids).is_err() {
                    tracing::warn!("credential scrub proof could not be journaled");
                }
                let state = if verified {
                    TeardownScrubV11::Verified
                } else {
                    TeardownScrubV11::Failed
                };
                for id in ids {
                    scrub.insert(id, state);
                }
            }
        }
        drop(guard);
        // The env leaves memory with the VM; the frames precede the result.
        self.forget_sandbox_env(sandbox_id);
        if last > 0 {
            let _ = self.flush(last, still_wanted);
        }
        let outcomes = outcomes_of(&bindings, &captured, &scrub);
        lock(&coord.progress).done = Some(Done {
            attempt_id: attempt_id.to_owned(),
            outcomes: outcomes.clone(),
            scrubbed: req.path.scrubs(),
            refused: false,
        });
        TeardownVerdict::Proceed(outcomes)
    }

    /// Pre-checks before any guest effect (N11).
    fn prechecks(
        &self,
        runtime: &dyn SandboxRuntime,
        guest: &CredentialGuest,
        host_owner_known: bool,
        to_pack: &[&BindingRecord],
    ) -> bool {
        let store = &self.inner.store;
        if !host_owner_known || store.current_key_epoch() == 0 {
            return false;
        }
        if to_pack.iter().any(|b| b.spec.is_none()) {
            return false;
        }
        {
            let outbox = store.outbox();
            let fits = to_pack.iter().all(|b| {
                let max = b.spec.as_ref().map_or(0, |s| s.max_bytes);
                outbox.has_room(
                    &b.lease_id,
                    CaptureKind::Stop,
                    CredentialStore::worst_case_envelope_bytes(max),
                )
            });
            if !fits {
                return false;
            }
        }
        matches!(runtime.credential_helper_present(guest), Ok(true))
    }

    /// One binding's capture in `attempt_id`: the recorded one when this
    /// attempt already captured it, else pack → seal → durable under a
    /// reserved capture id. `Ok(Err(_))` is an outcome already known.
    fn capture_one(
        &self,
        runtime: &dyn SandboxRuntime,
        req: &TeardownRequest,
        host_owner_id: &str,
        attempt_id: &str,
        binding: &BindingRecord,
    ) -> Result<Result<OutboxEntry, Captured>, &'static str> {
        let store = &self.inner.store;
        let reserved = store
            .journal()
            .reserve_teardown_capture(&binding.binding_id, attempt_id)
            .map_err(|_| "journal_failed")?;
        if reserved.state == TeardownCaptureState::Resolved {
            let outcome = reserved.outcome.unwrap_or(CaptureAckOutcome::Committed);
            return Ok(Err(Captured::Acked {
                capture_id: reserved.capture_id,
                outcome,
                scrub_ok: !matches!(
                    outcome,
                    CaptureAckOutcome::Rejected | CaptureAckOutcome::Deferred
                ),
            }));
        }
        let existing = store
            .outbox()
            .pending()
            .find(|e| e.capture_id == reserved.capture_id)
            .cloned();
        if let Some(entry) = existing {
            return Ok(Ok(entry));
        }
        if reserved.state == TeardownCaptureState::Durable {
            // Recorded durable but no longer pending: quarantined (REJECTED).
            let quarantined = store
                .outbox()
                .quarantined()
                .any(|e| e.capture_id == reserved.capture_id);
            if quarantined {
                return Ok(Err(Captured::Acked {
                    capture_id: reserved.capture_id,
                    outcome: CaptureAckOutcome::Rejected,
                    scrub_ok: false,
                }));
            }
        }
        let lease = binding.spec.as_ref().ok_or("precheck_failed")?;
        let ctx = CaptureContext {
            host_owner_id: host_owner_id.to_owned(),
            host_id: self.inner.host_id.clone(),
            sandbox_owner_id: req.sandbox_owner_id.clone(),
            sandbox_id: binding.sandbox_id.clone(),
            lease_id: binding.lease_id.clone(),
            binding_id: binding.binding_id.clone(),
            instance_id: binding.instance_id.clone(),
            credential_id: binding.credential_id.clone(),
            capture_id: reserved.capture_id.clone(),
            kind: req.path.kind(),
            residue_id: String::new(),
        };
        let entry = capture_binding(store, runtime, &req.guest, lease, &ctx, now_ms())
            .map_err(|_| "pack_failed")?;
        store
            .journal()
            .set_teardown_capture_state(
                &binding.binding_id,
                &reserved.capture_id,
                TeardownCaptureState::Durable,
            )
            .map_err(|_| "journal_failed")?;
        Ok(Ok(entry))
    }

    /// User stop/kill refusal: abort + owed re-bind in ONE journal write,
    /// then the lease-journal re-bind, all before the FAILED receipt.
    fn refuse(
        &self,
        req: &TeardownRequest,
        coord: &Coord,
        attempt_id: &str,
        bindings: &[BindingRecord],
        captured: &BTreeMap<String, Captured>,
        rebind: &dyn Fn(u64) -> anyhow::Result<()>,
    ) -> TeardownVerdict {
        let sandbox_id = req.guest.sandbox_id.as_str();
        let mut captured = captured.clone();
        for b in bindings.iter().filter(|b| capturable(b) && !req.skip) {
            captured
                .entry(b.binding_id.clone())
                .or_insert(Captured::Failed("capture_failed"));
        }
        let outcomes = outcomes_of(bindings, &captured, &BTreeMap::new());
        lock(&coord.progress).done = Some(Done {
            attempt_id: attempt_id.to_owned(),
            outcomes: outcomes.clone(),
            scrubbed: false,
            refused: true,
        });
        if self
            .inner
            .store
            .journal()
            .abort_teardown_with_rebind(sandbox_id, &req.operation_id, req.generation)
            .is_err()
        {
            return TeardownVerdict::Uncertain;
        }
        if rebind(req.generation).is_err() {
            // Owed in the journal: replayed at startup or by the next
            // teardown before any receipt can claim it.
            return TeardownVerdict::Uncertain;
        }
        let _ = self
            .inner
            .store
            .journal()
            .mark_rebind_applied(sandbox_id, req.generation);
        tracing::warn!(operation_id = %req.operation_id, "credential capture failed; teardown refused");
        TeardownVerdict::Refused(outcomes)
    }

    /// A free's pack → seal, without quiesce (the caller wires the
    /// remaining free steps). When the free is revoked after sealing, its
    /// envelope is recorded under the open teardown attempt, so the superseding stop
    /// joins it instead of capturing again.
    pub fn capture_for_free(
        &self,
        runtime: &dyn SandboxRuntime,
        guest: &CredentialGuest,
        sandbox_owner_id: &str,
        operation_id: &str,
        binding_id: &str,
        still_wanted: &dyn Fn() -> bool,
    ) -> FreeCapture {
        let store = &self.inner.store;
        let Some(binding) = store.journal().binding(binding_id).cloned() else {
            return FreeCapture::Abandoned;
        };
        let (Some(lease), Some(host_owner)) = (binding.spec.as_ref(), self.host_owner()) else {
            return FreeCapture::Abandoned;
        };
        if binding.sandbox_id != guest.sandbox_id || !still_wanted() {
            return FreeCapture::Abandoned;
        }
        // A LOGIN binding's finish captures kind `login`.
        let kind = if binding.purpose == BindingPurpose::Login {
            CaptureKind::Login
        } else {
            CaptureKind::Free
        };
        let ctx = CaptureContext {
            host_owner_id: host_owner,
            host_id: self.inner.host_id.clone(),
            sandbox_owner_id: sandbox_owner_id.to_owned(),
            sandbox_id: binding.sandbox_id.clone(),
            lease_id: binding.lease_id.clone(),
            binding_id: binding.binding_id.clone(),
            instance_id: binding.instance_id.clone(),
            credential_id: binding.credential_id.clone(),
            capture_id: random_id("cap"),
            kind,
            residue_id: String::new(),
        };
        let Ok(entry) = capture_binding(store, runtime, guest, lease, &ctx, now_ms()) else {
            return FreeCapture::Abandoned;
        };
        if still_wanted() {
            return FreeCapture::Sealed(entry);
        }
        // A login capture is never joined by a teardown (LOGIN bindings are
        // not teardown-capturable): its envelope uploads on its own and the
        // server discards it once the login sandbox's lease ended.
        if kind == CaptureKind::Login {
            return FreeCapture::RevokedRecorded(entry);
        }
        let recorded = (|| -> anyhow::Result<()> {
            let mut journal = store.journal();
            let attempt = journal.open_or_join_teardown(&guest.sandbox_id, operation_id)?;
            journal.record_teardown_capture(binding_id, &attempt.attempt_id, &entry.capture_id)
        })();
        if recorded.is_err() {
            tracing::warn!("revoked free's capture could not be recorded");
            return FreeCapture::Abandoned;
        }
        FreeCapture::RevokedRecorded(entry)
    }
}
