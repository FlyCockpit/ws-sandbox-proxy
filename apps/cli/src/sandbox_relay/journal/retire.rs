//! Per-command retirement of UNKNOWN `command.run` receipts.
//!
//! A nonterminal receipt normally retires only with a later sandbox cleanup
//! (stop/kill) proving its work dead, so an UNKNOWN command on an unlimited
//! lease was replayed on every reconnect forever. With the negotiated
//! `commandRetire`, the server answers the exact receipt it recorded as
//! UNKNOWN with `receipt.confirmed` `retireCommand` (honoured only when this
//! session's `hello.ok` answered `commandRetire`). The daemon admits it to
//! this journal's pending set, the session asks the runtime for a sound
//! proof that the command can no longer run, and only that proof deletes the
//! receipt. Proofs: the VM stopped or absent, the guest rebooted since the
//! bound birth, or (for a receipt that journaled its start uid) the root
//! retire helper proving the attempt's guest scope gone, empty or killed.
//! The helper kills only a due command (decision 1): a cancel was requested,
//! an interim stop is still unproven, or its budget plus 20 s passed on the
//! guest's monotonic clock. A command still running is re-observed inside
//! the session (paced, see [`RetirePacing`]). The server row stays UNKNOWN;
//! no sandbox stop is involved. Every step is idempotent: a lost request or
//! an unproven observation leaves the receipt, which the next session
//! replays.
use std::time::{Duration, Instant};

use anyhow::Result;
use sandbox_protocol::{OperationState, ReceiptConfirmation, TransportBindingV11};

use super::{HostJournal, HostReceipt, JournalState};

/// Proofs in flight at once (one observation-worker exec each).
pub(in crate::sandbox_relay) const RETIREMENTS_MAX: usize = 8;
/// In-flight slots retries may hold; the rest are reserved for fresh
/// requests.
pub(in crate::sandbox_relay) const RETIRE_RETRIES_MAX: usize = 6;
/// Entries one journal holds, pending plus in flight. A fresh request over
/// the bound is dropped (the next session re-requests it); a re-deferral
/// keeps its own slot and is never dropped.
pub(in crate::sandbox_relay) const RETIRE_PENDING_MAX: usize = 64;
/// Host-proof (`guest_root`) entries one sandbox, one owner and the journal
/// may hold, pending (parked included) plus in flight (DG-13). Admission-time
/// bounds: a `guest_root` rise on reconnect may re-classify entries admitted
/// earlier, so a cap can be exceeded transiently, never past
/// [`RETIRE_PENDING_MAX`]. At least 48 of the 64 slots stay for ordinary
/// retirement.
pub(in crate::sandbox_relay) const RETIRE_HOST_PROOF_PER_SANDBOX_MAX: usize = 4;
pub(in crate::sandbox_relay) const RETIRE_HOST_PROOF_PER_OWNER_MAX: usize = 8;
pub(in crate::sandbox_relay) const RETIRE_HOST_PROOF_MAX: usize = 16;

/// The ext key of the start journaled when it binds (decision 2).
pub(in crate::sandbox_relay) const COMMAND_START_EXT: &str = "commandStart";
/// The ext key set on an interim command observation: a cancel, revoked
/// permit or deadline stop that is not yet proven (`kill-cancel`).
pub(in crate::sandbox_relay) const COMMAND_STOP_UNPROVEN_EXT: &str = "commandStopUnproven";

/// In-session re-observation pacing (decision 1, T7/U3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::sandbox_relay) struct RetirePacing {
    /// At most one retry start per interval (plus jitter) across sessions.
    pub retry_interval: Duration,
    pub jitter: Duration,
    /// A still-populated scope is re-observed after this, doubling.
    pub backoff_base: Duration,
    pub backoff_cap: Duration,
    /// A not-yet-due command is retried this long after it becomes due.
    pub not_due_pad: Duration,
    /// A full observation queue retries after this.
    pub queue_full: Duration,
    /// A parked host-proof entry is rechecked from the host only (no guest
    /// exec: the VM's power state and QEMU identity) after this, plus
    /// jitter. Its own pacing: never the retry lane or its budget (U1).
    pub park_recheck: Duration,
}
impl RetirePacing {
    pub(in crate::sandbox_relay) const PRODUCTION: Self = Self {
        retry_interval: Duration::from_secs(15),
        jitter: Duration::from_secs(3),
        backoff_base: Duration::from_secs(30),
        backoff_cap: Duration::from_secs(600),
        not_due_pad: Duration::from_secs(5),
        queue_full: Duration::from_secs(1),
        park_recheck: Duration::from_secs(120),
    };
}

/// A pseudo-random duration in `[0, max]` (pacing jitter only).
fn jitter(max: Duration) -> Duration {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos()),
    );
    let max_ms = u64::try_from(max.as_millis()).unwrap_or(u64::MAX);
    Duration::from_millis(hasher.finish() % max_ms.saturating_add(1))
}

/// One pending-set entry. It keeps the session that admitted it (U1): only
/// that session can take, re-defer or delete with it.
#[derive(Debug, Clone)]
pub(in crate::sandbox_relay) struct RetireEntry {
    confirmation: ReceiptConfirmation,
    session: u64,
    in_flight: bool,
    /// After its first attempt.
    retry: bool,
    due: Instant,
    backoff: Duration,
    /// Host-proof-only and unproven while the same QEMU runs (T3): not on
    /// the retry lane. Due again at its slow host-only recheck or when a
    /// lifecycle event re-arms it ([`HostJournal::rearm_parked`]); a parked
    /// attempt never runs a guest exec (its kill ran once, on admission).
    parked: bool,
}

/// One retirement taken into flight: the confirmation that requested it,
/// what the runtime must prove (and may kill), and the admitting session.
#[derive(Debug, Clone)]
pub(in crate::sandbox_relay) struct CommandRetirement {
    pub confirmation: ReceiptConfirmation,
    pub request: sandbox_runtime::RetireCommandRequest,
    /// The negotiated session that admitted it; every kill and the delete
    /// re-check it.
    pub session: u64,
}

/// How one attempt ended (U2: settled atomically with its slot).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::sandbox_relay) enum RetireSettle {
    /// Proven (and deleted, or lost the race), unproven, or skipped.
    Done,
    /// Still running: re-defer after `Some(delay)`, or after the entry's
    /// doubling backoff (`None`).
    Retry(Option<Duration>),
    /// Host-proof-only and not provable from the host now: keep the slot,
    /// park until the host-only recheck or a re-arm (T3, U1).
    Park,
}

/// Only an UNKNOWN `command.run` receipt can be retired by a command proof.
fn retirable(receipt: &HostReceipt) -> bool {
    receipt.kind == "command.run"
        && receipt.state == OperationState::UnknownOutcome
        && !receipt.is_terminal()
        && !receipt.digest_pruned
}

/// A `process.started` frame naming exactly this attempt.
fn birth_of(
    receipt: &HostReceipt,
    value: &serde_json::Value,
) -> Option<sandbox_runtime::CommandBirth> {
    let started: sandbox_protocol::results::ProcessStarted =
        serde_json::from_value(value.clone()).ok()?;
    (started.validate()
        && started.operation_id == receipt.operation_id
        && started.sandbox_id == receipt.sandbox_id
        && u64::from(started.generation) == receipt.generation
        && u64::from(started.attempt) == receipt.attempt)
        .then_some(())?;
    Some(sandbox_runtime::CommandBirth {
        pid: started.pid,
        boot_id: started.boot_id,
        start_ticks: started.start_ticks.parse().ok()?,
        started_at_ms: 0,
    })
}

/// The journaled start (decision 2): `ext.commandStart` = `{birth, uid,
/// budgetMs}`. `Some(None)` when absent; `None` when present but invalid.
#[allow(clippy::option_option)]
fn journaled_start(
    receipt: &HostReceipt,
) -> Option<Option<(sandbox_runtime::CommandBirth, u32, u64)>> {
    let Some(start) = receipt.ext.get(COMMAND_START_EXT) else {
        return Some(None);
    };
    let birth = birth_of(receipt, start.get("birth")?)?;
    let uid = u32::try_from(start.get("uid")?.as_u64()?)
        .ok()
        .filter(|uid| *uid > 0)?;
    let budget_ms = start.get("budgetMs")?.as_u64()?;
    Some(Some((birth, uid, budget_ms)))
}

/// The QEMU identity journaled with the start (`ext.commandStart.qemu`), if
/// any and valid. Without runtime QEMU evidence this retirement arm cannot run.
fn journaled_qemu(receipt: &HostReceipt) -> Option<sandbox_runtime::QemuIdentity> {
    let value = receipt.ext.get(COMMAND_START_EXT)?.get("qemu")?;
    serde_json::from_value(value.clone()).ok()
}

/// The bound birth this receipt journaled, only when it names exactly this
/// attempt: the result's `birth`, the journaled start's, or both (S8:
/// compared semantically; a real mismatch, or an invalid one, is `None`).
fn receipt_birth(receipt: &HostReceipt) -> Option<sandbox_runtime::CommandBirth> {
    let from_result = match receipt
        .result
        .as_ref()
        .and_then(|result| result.get("birth"))
    {
        Some(value) => Some(birth_of(receipt, value)?),
        None => None,
    };
    let from_start = journaled_start(receipt)?.map(|(birth, _, _)| birth);
    match (from_result, from_start) {
        (Some(a), Some(b)) => same_birth(&a, &b).then_some(a),
        (a, b) => a.or(b),
    }
}

fn same_birth(a: &sandbox_runtime::CommandBirth, b: &sandbox_runtime::CommandBirth) -> bool {
    a.pid == b.pid && a.boot_id == b.boot_id && a.start_ticks == b.start_ticks
}

impl HostJournal {
    /// Called by [`HostJournal::confirm`] for an exact-binding confirmation
    /// carrying `retireCommand`: the one admission point. Deduplicated per
    /// session (U1): an entry of a stale session still in flight never
    /// shadows this session's request.
    pub(super) fn queue_retirement_locked(
        state: &mut JournalState,
        confirmed: &ReceiptConfirmation,
    ) {
        let Some(receipt) = state.receipts.get(&confirmed.operation_id) else {
            return;
        };
        let session = state.retire_session;
        if !state.command_retire
            || !retirable(receipt)
            || confirmed.cleanup_generation.is_some()
            || state.retirements.len() >= RETIRE_PENDING_MAX
            || state.retirements.iter().any(|entry| {
                entry.session == session
                    && entry.confirmation.operation_id == confirmed.operation_id
            })
        {
            return;
        }
        // DG-13: host-proof entries are capped per sandbox, per owner and in
        // total, counted across sessions (a stale in-flight entry holds its
        // slot). Ordinary entries are untouched.
        let lease_of = |sandbox_id: &str| state.leases.get(sandbox_id);
        if let Some(lease) = lease_of(&receipt.sandbox_id).filter(|lease| lease.guest_root) {
            let owner = lease.sandbox_owner_id.as_str();
            let (mut total, mut sandbox, mut by_owner) = (0usize, 0usize, 0usize);
            for entry in &state.retirements {
                let Some(other) = state.receipts.get(&entry.confirmation.operation_id) else {
                    continue;
                };
                let Some(other_lease) = lease_of(&other.sandbox_id).filter(|l| l.guest_root) else {
                    continue;
                };
                total += 1;
                sandbox += usize::from(other.sandbox_id == receipt.sandbox_id);
                by_owner += usize::from(other_lease.sandbox_owner_id == owner);
            }
            if total >= RETIRE_HOST_PROOF_MAX
                || sandbox >= RETIRE_HOST_PROOF_PER_SANDBOX_MAX
                || by_owner >= RETIRE_HOST_PROOF_PER_OWNER_MAX
            {
                return;
            }
        }
        state.retirements.push(RetireEntry {
            confirmation: confirmed.clone(),
            session,
            in_flight: false,
            retry: false,
            due: Instant::now(),
            backoff: Duration::ZERO,
            parked: false,
        });
    }

    /// U1: a lifecycle event for `sandbox_id` (a completed stop, kill,
    /// reconnect, create or a probe that observed it not running) makes its
    /// parked entries due now. The re-armed attempt is host-only like every
    /// parked one: it retires on a stopped or absent VM or a changed QEMU
    /// identity, and parks again otherwise. An entry whose receipt the event
    /// removed is dropped at the next take.
    pub(in crate::sandbox_relay) fn rearm_parked(&self, sandbox_id: &str) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let state = &mut *state;
        let now = Instant::now();
        for entry in &mut state.retirements {
            if entry.parked
                && !entry.in_flight
                && state
                    .receipts
                    .get(&entry.confirmation.operation_id)
                    .is_none_or(|receipt| receipt.sandbox_id == sandbox_id)
            {
                entry.due = now;
            }
        }
    }

    /// The `commandRetire` answer of the current session's `hello.ok`
    /// (`false` until it arrives). Every call starts a new retirement
    /// session: pending entries are dropped (the next replay requests them
    /// again), and attempts already in flight can no longer kill, re-defer
    /// or delete (their session is stale). In-flight entries keep their slot
    /// until they settle, so the bound still holds.
    pub(in crate::sandbox_relay) fn set_command_retire(&self, negotiated: bool) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.command_retire = negotiated;
        state.retire_session += 1;
        state.retirements.retain(|entry| entry.in_flight);
    }

    /// U2: settle one in-flight attempt under one lock. `Retry` moves it back
    /// to pending (keeping its slot) only while its own session is still
    /// the current negotiated one (U1); otherwise, and on `Done`, only that
    /// in-flight entry is removed.
    pub(in crate::sandbox_relay) fn settle_retirement(
        &self,
        operation_id: &str,
        session: u64,
        settle: RetireSettle,
        pacing: &RetirePacing,
    ) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let current = state.command_retire && state.retire_session == session;
        let Some(index) = state.retirements.iter().position(|entry| {
            entry.in_flight
                && entry.session == session
                && entry.confirmation.operation_id == operation_id
        }) else {
            return;
        };
        match settle {
            RetireSettle::Retry(after) if current => {
                let entry = &mut state.retirements[index];
                let delay = after.unwrap_or_else(|| {
                    entry.backoff = if entry.backoff.is_zero() {
                        pacing.backoff_base
                    } else {
                        entry.backoff.saturating_mul(2).min(pacing.backoff_cap)
                    };
                    entry.backoff + jitter(pacing.jitter)
                });
                entry.in_flight = false;
                entry.retry = true;
                entry.due = Instant::now() + delay;
            }
            RetireSettle::Park if current => {
                let entry = &mut state.retirements[index];
                entry.in_flight = false;
                entry.parked = true;
                entry.due = Instant::now() + pacing.park_recheck + jitter(pacing.jitter);
            }
            _ => {
                state.retirements.remove(index);
            }
        }
    }

    /// Take due entries into flight, each with its runtime request. Fresh
    /// requests first; retries (due kill modes first, then by due time) hold
    /// at most [`RETIRE_RETRIES_MAX`] slots and start at most once per paced
    /// interval. An entry whose operation is already in flight (a stale
    /// session's attempt) waits. A receipt without a valid bound birth, a
    /// sandbox without a lease record, or a template-build sandbox (D1: it
    /// refuses process control) is left to sandbox-level cleanup and its
    /// entry dropped. Each one returned stays in flight until
    /// [`Self::settle_retirement`].
    pub(in crate::sandbox_relay) fn take_retirements(
        &self,
        pacing: &RetirePacing,
    ) -> Vec<CommandRetirement> {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let state = &mut *state;
        let mut taken = Vec::new();
        if !state.command_retire {
            return taken;
        }
        let session = state.retire_session;
        let mut in_flight = state.retirements.iter().filter(|e| e.in_flight).count();
        let mut retries = state
            .retirements
            .iter()
            .filter(|e| e.in_flight && e.retry)
            .count();
        let busy: std::collections::HashSet<String> = state
            .retirements
            .iter()
            .filter(|e| e.in_flight)
            .map(|e| e.confirmation.operation_id.clone())
            .collect();
        let mut candidates = Vec::new();
        let mut dropped = Vec::new();
        for (index, entry) in state.retirements.iter().enumerate() {
            // U1: a parked entry whose receipt local cleanup removed (lease
            // expiry, enforcement loss) or settled is dropped at once, so it
            // never holds a host-proof slot for the rest of the session.
            if entry.parked
                && !entry.in_flight
                && state
                    .receipts
                    .get(&entry.confirmation.operation_id)
                    .is_none_or(|receipt| !retirable(receipt))
            {
                dropped.push(index);
                continue;
            }
            if entry.in_flight
                || entry.session != session
                || entry.due > now
                || busy.contains(&entry.confirmation.operation_id)
            {
                continue;
            }
            match Self::retirement_request(&state.receipts, &state.leases, &entry.confirmation) {
                // A parked attempt is host-only: observe, never a guest exec.
                Some(mut request) => {
                    if entry.parked {
                        request.mode = sandbox_runtime::RetireMode::Observe;
                    }
                    candidates.push((index, request));
                }
                None => dropped.push(index),
            }
        }
        candidates.sort_by_key(|(index, request)| {
            let entry = &state.retirements[*index];
            (
                entry.retry,
                request.host_proof_only,
                !request.mode.kills(),
                entry.due,
            )
        });
        for (index, request) in candidates {
            if in_flight >= RETIREMENTS_MAX {
                break;
            }
            let entry = &mut state.retirements[index];
            // A parked recheck has its own pacing (its due time): never the
            // retry lane or its budget.
            if entry.retry && !entry.parked {
                if retries >= RETIRE_RETRIES_MAX
                    || state.retry_paced_until.is_some_and(|until| until > now)
                {
                    continue;
                }
                retries += 1;
                state.retry_paced_until = Some(now + pacing.retry_interval + jitter(pacing.jitter));
            }
            entry.in_flight = true;
            in_flight += 1;
            taken.push(CommandRetirement {
                confirmation: entry.confirmation.clone(),
                request,
                session,
            });
        }
        dropped.sort_unstable();
        for index in dropped.into_iter().rev() {
            state.retirements.remove(index);
        }
        taken
    }

    /// I2 at check time (R9): the attempt's session is still the current
    /// negotiated one and its receipt is still the same retirable attempt.
    /// Checked right before a kill-mode exec.
    pub(in crate::sandbox_relay) fn retirement_current(
        &self,
        retirement: &CommandRetirement,
    ) -> bool {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.command_retire
            && state.retire_session == retirement.session
            && state
                .receipts
                .get(&retirement.confirmation.operation_id)
                .is_some_and(|receipt| {
                    retirable(receipt)
                        && receipt.generation == retirement.request.generation
                        && receipt.attempt == retirement.request.attempt
                        && receipt_birth(receipt)
                            .is_some_and(|birth| same_birth(&birth, &retirement.request.birth))
                })
    }

    fn retirement_request(
        receipts: &std::collections::HashMap<String, HostReceipt>,
        leases: &std::collections::HashMap<String, super::LeaseRecord>,
        confirmation: &ReceiptConfirmation,
    ) -> Option<sandbox_runtime::RetireCommandRequest> {
        let receipt = receipts.get(&confirmation.operation_id)?;
        if !retirable(receipt) {
            return None;
        }
        let birth = receipt_birth(receipt)?;
        let lease = leases.get(&receipt.sandbox_id)?;
        if lease.build_id.is_some() {
            return None;
        }
        let guest = lease.guest.as_ref().map_or_else(
            || sandbox_runtime::GuestIdentity {
                guest_uid: 1000,
                guest_gid: 1000,
                guest_home: "/home/user".into(),
                guest_shell: "/bin/bash".into(),
            },
            super::LeaseGuest::identity,
        );
        // N2/I6: the scoped helper takes the uid only from the journaled
        // start, never the lease default above. U6: only the launching
        // daemon writes it, at bind, so its launch ran the marker-aware
        // launcher; reconciliation keeps `ext` and never adds to it.
        let (uid, budget_ms) = journaled_start(receipt)?
            .map_or((None, 0), |(_, uid, budget_ms)| (Some(uid), budget_ms));
        let qemu = journaled_qemu(receipt);
        let stop_unproven = receipt
            .ext
            .get(COMMAND_STOP_UNPROVEN_EXT)
            .and_then(serde_json::Value::as_bool)
            == Some(true);
        let mode = if uid.is_none() {
            sandbox_runtime::RetireMode::Observe
        } else if receipt.cancel_requested || stop_unproven {
            sandbox_runtime::RetireMode::KillCancel
        } else if budget_ms > 0 {
            sandbox_runtime::RetireMode::KillDeadline
        } else {
            sandbox_runtime::RetireMode::Observe
        };
        Some(sandbox_runtime::RetireCommandRequest {
            template_fingerprint: receipt.template_fingerprint.clone()?,
            guest,
            sandbox_id: receipt.sandbox_id.clone(),
            instance_name: sandbox_runtime::default_incus_instance_name(&receipt.sandbox_id),
            operation_id: receipt.operation_id.clone(),
            birth,
            generation: receipt.generation,
            attempt: receipt.attempt,
            uid,
            budget_ms,
            mode,
            // I7: a guest that may reach root can forge every guest proof.
            host_proof_only: lease.guest_root,
            qemu,
        })
    }

    /// Decision 2: journal the start once, when it binds, for the exact
    /// non-terminal `command.run` attempt (`started` is its
    /// `process.started` frame). Never overwrites. A write failure latches
    /// the journal like every other writer; the command keeps running.
    /// Returns whether it wrote.
    pub fn record_command_start(
        &self,
        operation_id: &str,
        (generation, attempt): (u64, u64),
        started: serde_json::Value,
        uid: u32,
        budget_ms: u64,
        qemu: Option<sandbox_runtime::QemuIdentity>,
    ) -> Result<bool> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let Some(existing) = state.receipts.get(operation_id) else {
            return Ok(false);
        };
        if existing.kind != "command.run"
            || existing.generation != generation
            || existing.attempt != attempt
            || existing.is_terminal()
            || existing.digest_pruned
            || uid == 0
            || existing.ext.contains_key(COMMAND_START_EXT)
            || birth_of(existing, &started).is_none()
        {
            return Ok(false);
        }
        let mut stored = existing.clone();
        let mut start = serde_json::json!({"birth": started, "uid": uid, "budgetMs": budget_ms});
        // R11: the host-read QEMU identity at the start, when readable.
        if let Some(qemu) = qemu {
            start["qemu"] = serde_json::json!({"pid": qemu.pid, "startTicks": qemu.start_ticks});
        }
        stored.ext.insert(COMMAND_START_EXT.into(), start);
        // A start that does not fit is skipped (today's arms), never a latch.
        if !super::valid_ext(&stored.ext)
            || super::receipt_envelope_bytes(&stored)?.len()
                > sandbox_protocol::RECEIPT_LIMITS.receipt_bytes
        {
            return Ok(false);
        }
        super::persist_receipt(&self.io, &self.receipts_dir, &stored)?;
        state.receipts.insert(operation_id.into(), stored);
        Ok(true)
    }

    /// Delete the UNKNOWN receipt the proof is about. Re-checked under the
    /// journal mutex: the receipt is still the exact confirmed one, still
    /// UNKNOWN (a live owner that resolved it meanwhile wins), journals the
    /// proven birth, and the negotiated session it was taken in (`session`)
    /// is still current. Returns whether it was deleted.
    pub(in crate::sandbox_relay) fn retire_unknown_command(
        &self,
        binding: &TransportBindingV11,
        confirmed: &ReceiptConfirmation,
        proof: &sandbox_runtime::CommandGroupGone,
        session: u64,
    ) -> Result<bool> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if !state.command_retire || state.retire_session != session {
            return Ok(false);
        }
        let Some(receipt) = state.receipts.get(&confirmed.operation_id) else {
            return Ok(false);
        };
        if !confirmed.retire_command
            || !self.confirmation_binds(receipt, binding, confirmed)
            || !retirable(receipt)
            || receipt_birth(receipt).is_none_or(|birth| !same_birth(&birth, proof.birth()))
        {
            return Ok(false);
        }
        // Privilege is re-read under the delete lock: a same-generation
        // reconnect may have raised `guest_root` while this observation was
        // queued with `host_proof_only` false. Then only host evidence
        // deletes the receipt.
        if state
            .leases
            .get(&receipt.sandbox_id)
            .is_some_and(|lease| lease.guest_root)
            && !proof.host_proven()
        {
            return Ok(false);
        }
        self.delete_confirmed_receipt_locked(&mut state, &confirmed.operation_id)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{confirmation, receipt};
    use super::super::*;
    use super::{RETIRE_PENDING_MAX, RETIRE_RETRIES_MAX, RETIREMENTS_MAX};
    use crate::sandbox_relay::test_support::FixtureRuntime;
    use sandbox_runtime::SandboxRuntime as _;
    use std::time::{Duration, Instant};

    fn binding() -> TransportBindingV11 {
        TransportBindingV11 {
            server: "wss://api.example".into(),
            host_owner_id: "owner-1".into(),
            host_id: "host-1".into(),
        }
    }

    /// Fast pacing: the rate limit still applies (1 h) unless a test lifts it.
    const PACING: RetirePacing = RetirePacing {
        retry_interval: Duration::from_secs(3600),
        jitter: Duration::ZERO,
        backoff_base: Duration::ZERO,
        backoff_cap: Duration::ZERO,
        not_due_pad: Duration::ZERO,
        queue_full: Duration::ZERO,
        park_recheck: Duration::ZERO,
    };

    fn birth_frame(op: &str) -> serde_json::Value {
        let mut birth: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../crates/sandbox-protocol/fixtures/process_started.json"
        ))
        .unwrap();
        birth["operationId"] = serde_json::json!(op);
        birth["sandboxId"] = serde_json::json!("sbx-1");
        birth["generation"] = serde_json::json!(2);
        birth
    }

    /// A journal whose sandbox `sbx-1` has a lease record (an unlimited
    /// create, like a running sandbox) and an UNKNOWN `command.run` receipt
    /// `cmd` that journaled its bound birth.
    fn unknown_command(dir: &std::path::Path) -> (HostJournal, HostReceipt) {
        let j = crate::sandbox_relay::test_support::open_journal(dir, &binding()).unwrap();
        let create: OperationDispatch = serde_json::from_value(serde_json::json!({
            "sandboxOwnerId":"owner", "operationId":"create", "sandboxId":"sbx-1",
            "kind":"sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(),
            "cpuCount": 1, "memoryMiB": 1024, "generation":1, "attempt":1,
            "idempotencyKey":"create", "bodyHash":"a".repeat(64),
            "lease":sandbox_protocol::HostLease::for_test()}))
        .unwrap();
        j.record_fixture_intent(&intent_from_dispatch(&j, &binding(), &create))
            .unwrap();
        j.accept_fixture_lease(&create).unwrap();
        j.record_result(
            "create",
            OperationState::Succeeded,
            Some(serde_json::json!({"state":"ready","lease":create.lease})),
            None,
            None,
        )
        .unwrap();
        let r = add_unknown(&j, "cmd", true);
        // This session's `hello.ok` answered `commandRetire`.
        j.set_command_retire(true);
        (j, r)
    }

    /// Another UNKNOWN command receipt `op` (with its result birth when
    /// `with_birth`).
    fn add_unknown(j: &HostJournal, op: &str, with_birth: bool) -> HostReceipt {
        let mut r = receipt(op, 1);
        r.template_fingerprint = Some("f".repeat(64));
        j.record_intent(&r).unwrap();
        let body = with_birth.then(|| {
            let birth = birth_frame(op);
            serde_json::json!({"version":1,"observedAt":birth["observedAt"],
                "payload":null,"continuation":null,"birth":birth,
                "failure":{"resource":"command","effect":"unknown"}})
        });
        let r = j
            .record_result(
                op,
                OperationState::UnknownOutcome,
                body,
                Some(SandboxErrorCode::UnknownOutcome),
                None,
            )
            .unwrap();
        assert!(!r.is_terminal());
        r
    }

    /// The current retirement session token.
    fn session(j: &HostJournal) -> u64 {
        j.state.lock().unwrap().retire_session
    }

    fn retire(r: &HostReceipt) -> ReceiptConfirmation {
        let mut confirmed = confirmation(r);
        confirmed.retire_command = true;
        confirmed
    }

    fn take(j: &HostJournal) -> Vec<CommandRetirement> {
        j.take_retirements(&PACING)
    }

    /// (operation, session, in flight, retry) of every entry.
    fn entries(j: &HostJournal) -> Vec<(String, u64, bool, bool)> {
        j.state
            .lock()
            .unwrap()
            .retirements
            .iter()
            .map(|e| {
                (
                    e.confirmation.operation_id.clone(),
                    e.session,
                    e.in_flight,
                    e.retry,
                )
            })
            .collect()
    }

    /// The fixture's bound birth, proven gone by the fake runtime.
    fn proof(pid: u32) -> sandbox_runtime::CommandGroupGone {
        let fake = sandbox_runtime::FakeRuntime::new();
        let runtime: &dyn sandbox_runtime::SandboxRuntime = &fake;
        runtime
            .create_fixture(&sandbox_runtime::CreateSandboxRequest::for_test(
                "sbx-1", "create",
            ))
            .unwrap();
        fake.stop_sandbox(&sandbox_runtime::StopSandboxRequest {
            sandbox_id: "sbx-1".into(),
            instance_name: "wssp-sbx-sbx-1".into(),
            operation_id: "stop".into(),
            idempotency_key: "stop".into(),
            template_fingerprint: String::new(),
        })
        .unwrap();
        let observed = sandbox_runtime::SandboxRuntime::retire_command_group(
            &fake,
            &sandbox_runtime::RetireCommandRequest {
                template_fingerprint: String::new(),
                guest: sandbox_runtime::GuestIdentity::default(),
                sandbox_id: "sbx-1".into(),
                instance_name: "wssp-sbx-sbx-1".into(),
                operation_id: "cmd".into(),
                birth: sandbox_runtime::CommandBirth {
                    pid,
                    boot_id: "12345678-1234-4234-8234-123456789abc".into(),
                    start_ticks: 123456,
                    started_at_ms: 0,
                },
                generation: 2,
                attempt: 1,
                uid: None,
                budget_ms: 0,
                mode: sandbox_runtime::RetireMode::Observe,
                host_proof_only: false,
                qemu: None,
            },
        )
        .unwrap();
        match observed {
            sandbox_runtime::RetireObservation::Gone(proof) => proof,
            other => panic!("{other:?}"),
        }
    }

    /// Make sandbox `sandbox` (owner `owner`) a guest-root sandbox holding
    /// `count` UNKNOWN commands (cloned in memory from `r`), each admitted
    /// for retirement; returns how many entries the journal holds for it.
    fn root_sandbox(
        j: &HostJournal,
        r: &HostReceipt,
        sandbox: &str,
        owner: &str,
        count: usize,
        guest_root: bool,
    ) -> usize {
        let mut state = j.state.lock().unwrap();
        let mut lease = state.leases.get("sbx-1").unwrap().clone();
        lease.sandbox_id = sandbox.into();
        lease.sandbox_owner_id = owner.into();
        lease.guest_root = guest_root;
        state.leases.insert(sandbox.into(), lease);
        for i in 0..count {
            let mut receipt = r.clone();
            receipt.operation_id = format!("{sandbox}-cmd-{i}");
            receipt.sandbox_id = sandbox.into();
            receipt.sandbox_owner_id = owner.into();
            let confirmed = retire(&receipt);
            state.receipts.insert(receipt.operation_id.clone(), receipt);
            HostJournal::queue_retirement_locked(&mut state, &confirmed);
        }
        let receipts = &state.receipts;
        state
            .retirements
            .iter()
            .filter(|e| {
                receipts
                    .get(&e.confirmation.operation_id)
                    .is_some_and(|r| r.sandbox_id == sandbox)
            })
            .count()
    }

    #[test]
    fn host_proof_entries_are_capped_per_sandbox_owner_and_host_ordinary_ones_never() {
        let dir = tempfile::tempdir().unwrap();
        let (j, r) = unknown_command(dir.path());
        // 4 per sandbox.
        assert_eq!(root_sandbox(&j, &r, "a1", "o1", 64, true), 4);
        // 8 per owner across sandboxes.
        assert_eq!(root_sandbox(&j, &r, "a2", "o1", 64, true), 4);
        assert_eq!(root_sandbox(&j, &r, "a3", "o1", 64, true), 0);
        // 16 in total.
        assert_eq!(root_sandbox(&j, &r, "b1", "o2", 64, true), 4);
        assert_eq!(root_sandbox(&j, &r, "b2", "o2", 64, true), 4);
        assert_eq!(root_sandbox(&j, &r, "c1", "o3", 64, true), 0);
        // A non-root sandbox's fresh requests are still admitted.
        assert_eq!(root_sandbox(&j, &r, "plain", "o3", 20, false), 20);
        assert!(j.state.lock().unwrap().retirements.len() <= super::RETIRE_PENDING_MAX);
    }

    /// Offload plan sweep S8: a sandbox restored onto this host from a
    /// guest-root lineage carries `guestRoot` on its restore dispatch, so its
    /// UNKNOWN commands retire on host proof only here too.
    #[test]
    fn a_restore_lease_with_guest_root_retires_on_host_proof_only() {
        const DISK: &str =
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        let restore: OperationDispatch = serde_json::from_value(serde_json::json!({
            "sandboxOwnerId":"owner", "operationId":"restore", "sandboxId":"sbx-1",
            "kind":"sandbox.reconnect", "allocation": crate::sandbox_relay::test_support::allocation(),
            "cpuCount": 1, "memoryMiB": 1024, "generation":1, "attempt":1,
            "idempotencyKey":"restore", "bodyHash":"a".repeat(64),
            "image": {"fingerprint": DISK, "sizeBytes": 4096, "format": "unified", "source": "fetch"},
            "restore": {"offloadId": "off-1", "seq": 1, "fingerprint": DISK},
            "launchMode": "new_root", "guestRoot": true,
            "lease":sandbox_protocol::HostLease::for_test()}))
        .unwrap();
        j.record_intent(&intent_from_dispatch(&j, &binding(), &restore))
            .unwrap();
        j.accept_fixture_lease(&restore).unwrap();
        let lease = j.lease("sbx-1").unwrap();
        assert!(lease.guest_root);
        assert_eq!(lease.restore_base.as_deref(), Some(DISK));
        j.record_result(
            "restore",
            OperationState::Succeeded,
            Some(serde_json::json!({"state":"ready","lease":restore.lease})),
            None,
            None,
        )
        .unwrap();
        let r = add_unknown(&j, "cmd", true);
        j.set_command_retire(true);
        assert!(!j.confirm(&binding(), &retire(&r)).unwrap());
        let taken = take(&j);
        assert_eq!(taken.len(), 1);
        assert!(taken[0].request.host_proof_only);
    }

    #[test]
    fn a_host_proof_attempt_parks_until_a_lifecycle_rearm_and_runs_host_only() {
        let dir = tempfile::tempdir().unwrap();
        let (j, r) = unknown_command(dir.path());
        j.state
            .lock()
            .unwrap()
            .leases
            .get_mut("sbx-1")
            .unwrap()
            .guest_root = true;
        assert!(!j.confirm(&binding(), &retire(&r)).unwrap());
        let taken = take(&j);
        assert_eq!(taken.len(), 1);
        assert!(taken[0].request.host_proof_only);
        let slow = RetirePacing {
            park_recheck: Duration::from_secs(3600),
            ..PACING
        };
        j.settle_retirement("cmd", session(&j), RetireSettle::Park, &slow);
        // Parked: keeps its slot, never timer-due on the retry lane.
        assert_eq!(entries(&j).len(), 1);
        assert!(take(&j).is_empty());
        assert!(take(&j).is_empty());
        // A lifecycle event re-arms it; the re-armed attempt never execs in
        // the guest (observe mode).
        j.rearm_parked("sbx-1");
        let taken = take(&j);
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].request.mode, sandbox_runtime::RetireMode::Observe);
        j.settle_retirement("cmd", session(&j), RetireSettle::Park, &slow);
        // The host-only recheck is due on its own pacing.
        j.settle_retirement("cmd", session(&j), RetireSettle::Park, &PACING);
        assert_eq!(entries(&j).len(), 1);
    }

    #[test]
    fn the_slow_recheck_retires_a_parked_entry_after_a_restart_without_events() {
        let dir = tempfile::tempdir().unwrap();
        let (j, r) = unknown_command(dir.path());
        j.state
            .lock()
            .unwrap()
            .leases
            .get_mut("sbx-1")
            .unwrap()
            .guest_root = true;
        assert!(!j.confirm(&binding(), &retire(&r)).unwrap());
        assert_eq!(take(&j).len(), 1);
        // PACING rechecks at once: no lifecycle event is needed.
        j.settle_retirement("cmd", session(&j), RetireSettle::Park, &PACING);
        let recheck = take(&j);
        assert_eq!(recheck.len(), 1, "due by the host-only recheck");
        assert_eq!(
            recheck[0].request.mode,
            sandbox_runtime::RetireMode::Observe
        );
        j.settle_retirement("cmd", session(&j), RetireSettle::Done, &PACING);
        assert!(entries(&j).is_empty());
    }

    #[test]
    fn a_parked_entry_whose_receipt_local_cleanup_removed_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let (j, r) = unknown_command(dir.path());
        j.state
            .lock()
            .unwrap()
            .leases
            .get_mut("sbx-1")
            .unwrap()
            .guest_root = true;
        assert!(!j.confirm(&binding(), &retire(&r)).unwrap());
        assert_eq!(take(&j).len(), 1);
        let slow = RetirePacing {
            park_recheck: Duration::from_secs(3600),
            ..PACING
        };
        j.settle_retirement("cmd", session(&j), RetireSettle::Park, &slow);
        assert_eq!(entries(&j).len(), 1);
        // Lease expiry or enforcement loss removed the receipt locally.
        j.state.lock().unwrap().receipts.remove("cmd");
        assert!(take(&j).is_empty());
        assert!(entries(&j).is_empty(), "its host-proof slot is free again");
    }

    #[test]
    fn a_guest_root_lease_marks_requests_host_proof_and_journals_the_qemu_identity() {
        let dir = tempfile::tempdir().unwrap();
        let (j, _) = unknown_command(dir.path());
        add_unknown(&j, "q", false);
        let qemu = sandbox_runtime::QemuIdentity {
            pid: 4242,
            start_ticks: 99,
        };
        assert!(
            j.record_command_start("q", (2, 1), birth_frame("q"), 1000, 0, Some(qemu))
                .unwrap()
        );
        let start = &j.lookup("q").unwrap().ext[super::COMMAND_START_EXT];
        assert_eq!(
            start["qemu"],
            serde_json::json!({"pid": 4242, "startTicks": 99})
        );
        let receipt = j.lookup("q").unwrap();
        assert!(!j.confirm(&binding(), &retire(&receipt)).unwrap());
        let taken = take(&j);
        let request = &taken
            .iter()
            .find(|t| t.request.operation_id == "q")
            .unwrap()
            .request;
        assert_eq!(request.qemu, Some(qemu));
        assert!(!request.host_proof_only);
    }

    /// A guest-reported proof of the fixture's birth (the fake's running-VM
    /// boot arm, verdict `gone`): never host evidence.
    fn guest_proof(pid: u32) -> sandbox_runtime::CommandGroupGone {
        let fake = sandbox_runtime::FakeRuntime::new();
        let runtime: &dyn sandbox_runtime::SandboxRuntime = &fake;
        runtime
            .create_fixture(&sandbox_runtime::CreateSandboxRequest::for_test(
                "sbx-1", "create",
            ))
            .unwrap();
        let observed = runtime
            .retire_command_group(&sandbox_runtime::RetireCommandRequest {
                template_fingerprint: String::new(),
                guest: sandbox_runtime::GuestIdentity::default(),
                sandbox_id: "sbx-1".into(),
                instance_name: "wssp-sbx-sbx-1".into(),
                operation_id: "cmd".into(),
                birth: sandbox_runtime::CommandBirth {
                    pid,
                    boot_id: "12345678-1234-4234-8234-123456789abc".into(),
                    start_ticks: 123456,
                    started_at_ms: 0,
                },
                generation: 2,
                attempt: 1,
                uid: None,
                budget_ms: 0,
                mode: sandbox_runtime::RetireMode::Observe,
                host_proof_only: false,
                qemu: None,
            })
            .unwrap();
        match observed {
            sandbox_runtime::RetireObservation::Gone(proof) => {
                assert!(!proof.host_proven());
                proof
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_guest_root_rise_while_queued_refuses_a_guest_reported_proof_at_delete() {
        let dir = tempfile::tempdir().unwrap();
        let (j, r) = unknown_command(dir.path());
        assert!(!j.confirm(&binding(), &retire(&r)).unwrap());
        let taken = take(&j);
        assert!(
            !taken[0].request.host_proof_only,
            "snapshot before the rise"
        );
        // A same-generation reconnect raises guest_root meanwhile.
        j.state
            .lock()
            .unwrap()
            .leases
            .get_mut("sbx-1")
            .unwrap()
            .guest_root = true;
        assert!(
            !j.retire_unknown_command(&binding(), &retire(&r), &guest_proof(123), session(&j))
                .unwrap(),
            "a guest-reported proof no longer deletes"
        );
        assert!(j.lookup("cmd").is_some());
        assert!(proof(123).host_proven());
        assert!(
            j.retire_unknown_command(&binding(), &retire(&r), &proof(123), session(&j))
                .unwrap(),
            "host evidence still does"
        );
    }

    #[test]
    fn a_retire_confirmation_queues_a_proof_and_never_deletes_by_itself() {
        let dir = tempfile::tempdir().unwrap();
        let (j, r) = unknown_command(dir.path());
        // An ordinary confirmation never retires unknown work (unchanged).
        assert!(!j.confirm(&binding(), &confirmation(&r)).unwrap());
        assert!(take(&j).is_empty());
        // Twice: deduplicated, and the receipt is still journaled.
        assert!(!j.confirm(&binding(), &retire(&r)).unwrap());
        assert!(!j.confirm(&binding(), &retire(&r)).unwrap());
        assert!(j.lookup("cmd").is_some());
        let queued = take(&j);
        assert_eq!(queued.len(), 1);
        let request = &queued[0].request;
        assert_eq!(
            (
                request.birth.pid,
                request.birth.boot_id.as_str(),
                request.birth.start_ticks
            ),
            (123, "12345678-1234-4234-8234-123456789abc", 123456)
        );
        assert_eq!(request.instance_name, "wssp-sbx-sbx-1");
        assert_eq!(request.guest.guest_uid, 1000);
        assert_eq!((request.generation, request.attempt), (2, 1));
        // N2: no journaled start, so no uid for the helper (never the lease
        // default) and nothing may be killed.
        assert_eq!(request.uid, None);
        assert_eq!(request.mode, sandbox_runtime::RetireMode::Observe);
        assert!(take(&j).is_empty(), "drained");
        // A confirmation naming another request is not exact: nothing queued.
        let mut forged = retire(&r);
        forged.body_hash = "b".repeat(64);
        assert!(!j.confirm(&binding(), &forged).unwrap());
        assert!(take(&j).is_empty());
    }

    #[test]
    fn only_a_proof_of_the_journaled_birth_deletes_the_exact_unknown_receipt() {
        let dir = tempfile::tempdir().unwrap();
        let (j, r) = unknown_command(dir.path());
        assert!(
            !j.retire_unknown_command(&binding(), &retire(&r), &proof(124), session(&j))
                .unwrap(),
            "another incarnation's proof"
        );
        assert!(
            !j.retire_unknown_command(&binding(), &confirmation(&r), &proof(123), session(&j))
                .unwrap(),
            "a confirmation that never requested retirement"
        );
        let mut forged = retire(&r);
        forged.attempt = 2;
        assert!(
            !j.retire_unknown_command(&binding(), &forged, &proof(123), session(&j))
                .unwrap()
        );
        assert!(j.lookup("cmd").is_some());
        assert!(
            j.retire_unknown_command(&binding(), &retire(&r), &proof(123), session(&j))
                .unwrap()
        );
        assert!(j.lookup("cmd").is_none());
        // Idempotent: a repeated proof finds nothing; the deletion is durable.
        assert!(
            !j.retire_unknown_command(&binding(), &retire(&r), &proof(123), session(&j))
                .unwrap()
        );
        drop(j);
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        assert!(j.lookup("cmd").is_none());
    }

    /// A live owner that resolves the attempt before the proof lands wins;
    /// a receipt without a lease record or a bound birth is never requested.
    #[test]
    fn resolved_birthless_or_leaseless_receipts_are_never_retired() {
        let dir = tempfile::tempdir().unwrap();
        let (j, r) = unknown_command(dir.path());
        assert!(!j.confirm(&binding(), &retire(&r)).unwrap());
        j.record_result(
            "cmd",
            OperationState::Failed,
            None,
            Some(SandboxErrorCode::Internal),
            None,
        )
        .unwrap();
        assert!(take(&j).is_empty());
        assert!(entries(&j).is_empty(), "the stale entry is dropped");
        assert!(
            !j.retire_unknown_command(&binding(), &retire(&r), &proof(123), session(&j))
                .unwrap()
        );
        assert!(j.lookup("cmd").is_some());

        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        j.set_command_retire(true);
        let birthless = add_unknown(&j, "cmd", false);
        assert!(!j.confirm(&binding(), &retire(&birthless)).unwrap());
        assert!(take(&j).is_empty());
        assert!(j.lookup("cmd").is_some());
    }

    /// Review P2: `retireCommand` is honoured only when this session's
    /// `hello.ok` answered `commandRetire`; a new session starts unnegotiated.
    #[test]
    fn retire_command_is_ignored_unless_negotiated() {
        let dir = tempfile::tempdir().unwrap();
        let (j, r) = unknown_command(dir.path());
        j.set_command_retire(false);
        assert!(!j.confirm(&binding(), &retire(&r)).unwrap());
        assert!(take(&j).is_empty());
        // Queued under a negotiated session, then the next session is not.
        j.set_command_retire(true);
        assert!(!j.confirm(&binding(), &retire(&r)).unwrap());
        j.set_command_retire(false);
        assert!(take(&j).is_empty());
        assert!(j.lookup("cmd").is_some());
    }

    /// T3/U3: nothing within the bound is dropped. Eight proofs run; the
    /// rest wait pending. The bound (64) counts pending plus in flight.
    #[test]
    fn the_pending_set_holds_what_the_in_flight_bound_cannot() {
        let dir = tempfile::tempdir().unwrap();
        let (j, _) = unknown_command(dir.path());
        let mut receipts = Vec::new();
        for n in 0..RETIRE_PENDING_MAX + 2 {
            let r = add_unknown(&j, &format!("op-{n}"), true);
            assert!(!j.confirm(&binding(), &retire(&r)).unwrap());
            receipts.push(r);
        }
        assert_eq!(
            entries(&j).len(),
            RETIRE_PENDING_MAX,
            "over the bound is dropped"
        );
        let first = take(&j);
        assert_eq!(first.len(), RETIREMENTS_MAX);
        assert!(take(&j).is_empty(), "no more slots");
        // One settles: exactly one more is taken.
        j.settle_retirement(
            &first[0].request.operation_id,
            first[0].session,
            RetireSettle::Done,
            &PACING,
        );
        assert_eq!(take(&j).len(), 1);
        assert_eq!(entries(&j).len(), RETIRE_PENDING_MAX - 1);
        // A re-deferral keeps its own slot: the set never grows past the
        // bound, and the re-deferred entry is never dropped.
        let r = &receipts[RETIRE_PENDING_MAX];
        assert!(!j.confirm(&binding(), &retire(r)).unwrap());
        assert_eq!(entries(&j).len(), RETIRE_PENDING_MAX);
        j.settle_retirement(
            &first[1].request.operation_id,
            first[1].session,
            RetireSettle::Retry(Some(Duration::from_secs(60))),
            &PACING,
        );
        assert_eq!(entries(&j).len(), RETIRE_PENDING_MAX);
        assert!(entries(&j).iter().any(|(op, _, in_flight, retry)| *op
            == first[1].request.operation_id
            && !in_flight
            && *retry));
    }

    /// U2: a `Running` attempt re-defers in the same locked transition that
    /// releases its slot, so the re-deferral is never erased, never doubled,
    /// and a replayed confirmation stays deduplicated against it.
    #[test]
    fn a_running_attempt_re_defers_atomically_and_keeps_dedup() {
        let dir = tempfile::tempdir().unwrap();
        let (j, r) = unknown_command(dir.path());
        assert!(!j.confirm(&binding(), &retire(&r)).unwrap());
        let taken = take(&j);
        assert_eq!(taken.len(), 1);
        // In flight: a replayed confirmation is a duplicate.
        assert!(!j.confirm(&binding(), &retire(&r)).unwrap());
        assert_eq!(entries(&j).len(), 1);
        j.settle_retirement("cmd", taken[0].session, RetireSettle::Retry(None), &PACING);
        assert_eq!(entries(&j), [("cmd".into(), session(&j), false, true)]);
        assert!(!j.confirm(&binding(), &retire(&r)).unwrap());
        assert_eq!(entries(&j).len(), 1, "still deduplicated");
        // Due now (zero backoff): taken again as a retry.
        let again = take(&j);
        assert_eq!(again.len(), 1);
        // Settling twice is harmless: only the in-flight entry is removed.
        j.settle_retirement("cmd", again[0].session, RetireSettle::Done, &PACING);
        j.settle_retirement("cmd", again[0].session, RetireSettle::Done, &PACING);
        assert!(entries(&j).is_empty());
        // A not-due delay is honoured.
        assert!(!j.confirm(&binding(), &retire(&r)).unwrap());
        let taken = take(&j);
        j.settle_retirement(
            "cmd",
            taken[0].session,
            RetireSettle::Retry(Some(Duration::from_secs(3600))),
            &PACING,
        );
        assert!(take(&j).is_empty(), "not due yet");
    }

    /// U1: an attempt still in flight when its session ends never re-defers
    /// into the next session; the next session's own request is admitted
    /// beside it (dedup is per session), waits while the stale attempt runs,
    /// and is taken once that attempt settles.
    #[test]
    fn a_stale_session_attempt_never_re_defers_and_never_shadows_a_fresh_request() {
        let dir = tempfile::tempdir().unwrap();
        let (j, r) = unknown_command(dir.path());
        assert!(!j.confirm(&binding(), &retire(&r)).unwrap());
        let stale = take(&j);
        let a = stale[0].session;
        // Reconnect: B's hello, then its hello.ok answer.
        j.set_command_retire(false);
        j.set_command_retire(true);
        let b = session(&j);
        assert!(
            !j.retirement_current(&stale[0]),
            "A no longer authorizes a kill"
        );
        // B's confirmation is admitted although A's attempt is in flight.
        assert!(!j.confirm(&binding(), &retire(&r)).unwrap());
        assert_eq!(
            entries(&j),
            [
                ("cmd".into(), a, true, false),
                ("cmd".into(), b, false, false)
            ]
        );
        assert!(take(&j).is_empty(), "never two attempts of one operation");
        // A's attempt returns `Running`: dropped, not re-stamped into B.
        j.settle_retirement("cmd", a, RetireSettle::Retry(None), &PACING);
        assert_eq!(entries(&j), [("cmd".into(), b, false, false)]);
        let fresh = take(&j);
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].session, b);
        assert!(j.retirement_current(&fresh[0]));
    }

    /// Fresh requests first; retries hold at most six slots, start at most
    /// once per paced interval, kill modes first.
    #[test]
    fn retries_are_paced_and_never_take_the_reserved_slots() {
        let dir = tempfile::tempdir().unwrap();
        let (j, _) = unknown_command(dir.path());
        let ops: Vec<String> = (0..RETIREMENTS_MAX + 2)
            .map(|n| format!("op-{n}"))
            .collect();
        for op in &ops {
            let r = add_unknown(&j, op, true);
            assert!(!j.confirm(&binding(), &retire(&r)).unwrap());
        }
        // Mark every entry a due retry, as if each had run once.
        {
            let mut state = j.state.lock().unwrap();
            for entry in &mut state.retirements {
                entry.retry = true;
            }
        }
        let unpaced = RetirePacing {
            retry_interval: Duration::ZERO,
            ..PACING
        };
        assert_eq!(
            j.take_retirements(&PACING).len(),
            1,
            "one retry per interval"
        );
        assert!(j.take_retirements(&PACING).is_empty());
        // The interval passed.
        j.state.lock().unwrap().retry_paced_until = None;
        let mut taken = 1;
        for _ in 0..RETIREMENTS_MAX {
            taken += j.take_retirements(&unpaced).len();
        }
        assert_eq!(taken, RETIRE_RETRIES_MAX, "two slots stay reserved");
        // A fresh request still gets a reserved slot while six retries run.
        let fresh = add_unknown(&j, "fresh", true);
        assert!(!j.confirm(&binding(), &retire(&fresh)).unwrap());
        let got = j.take_retirements(&unpaced);
        assert_eq!(
            got.iter()
                .map(|r| r.request.operation_id.as_str())
                .collect::<Vec<_>>(),
            ["fresh"]
        );
    }

    /// The order among due retries: kill modes first, then by due time.
    #[test]
    fn due_kill_retries_go_first() {
        let dir = tempfile::tempdir().unwrap();
        let (j, _) = unknown_command(dir.path());
        for (op, cancel) in [("observe", false), ("cancelled", true)] {
            let r = add_unknown(&j, op, true);
            started(&j, op, 0);
            if cancel {
                j.record_cancel(op, 2, 1).unwrap();
            }
            assert!(!j.confirm(&binding(), &retire(&r)).unwrap());
        }
        {
            let mut state = j.state.lock().unwrap();
            let now = Instant::now();
            for entry in &mut state.retirements {
                entry.retry = true;
                // The observe-only entry has been due longer.
                entry.due = if entry.confirmation.operation_id == "observe" {
                    now - Duration::from_secs(10)
                } else {
                    now
                };
            }
        }
        let taken = take(&j);
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].request.operation_id, "cancelled");
        assert_eq!(
            taken[0].request.mode,
            sandbox_runtime::RetireMode::KillCancel
        );
    }

    /// Journal `op`'s start with `budget_ms` (decision 2).
    fn started(j: &HostJournal, op: &str, budget_ms: u64) -> bool {
        j.record_command_start(op, (2, 1), birth_frame(op), 1000, budget_ms, None)
            .unwrap()
    }

    /// Decision 2: the start is journaled once for the exact attempt, never
    /// overwritten, kept by every rewrite and across a restart; it alone
    /// supplies the helper's uid and budget; the mode follows decision 1.
    #[test]
    fn the_journaled_start_names_uid_budget_and_mode() {
        let dir = tempfile::tempdir().unwrap();
        let (j, r) = unknown_command(dir.path());
        assert!(
            !j.record_command_start("cmd", (2, 2), birth_frame("cmd"), 1000, 5, None)
                .unwrap(),
            "another attempt"
        );
        assert!(
            !j.record_command_start("cmd", (2, 1), birth_frame("other"), 1000, 5, None)
                .unwrap(),
            "another operation's frame"
        );
        assert!(
            !j.record_command_start("cmd", (2, 1), birth_frame("cmd"), 0, 5, None)
                .unwrap(),
            "uid 0"
        );
        assert!(started(&j, "cmd", 5000));
        assert!(!started(&j, "cmd", 9), "never overwritten");
        // A later result rewrite keeps it; so does a restart.
        add_unknown(&j, "unrelated", true);
        j.record_cancel("cmd", 2, 1).unwrap();
        drop(j);
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        j.set_command_retire(true);
        let stored = j.lookup("cmd").unwrap();
        assert_eq!(stored.ext["commandStart"]["uid"], 1000);
        assert_eq!(stored.ext["commandStart"]["budgetMs"], 5000);
        assert!(!j.confirm(&binding(), &retire(&r)).unwrap());
        let request = &take(&j)[0].request;
        assert_eq!((request.uid, request.budget_ms), (Some(1000), 5000));
        assert_eq!(request.mode, sandbox_runtime::RetireMode::KillCancel);
        // Without a cancel: deadline mode, or observe without a budget.
        let dir = tempfile::tempdir().unwrap();
        let (j, _) = unknown_command(dir.path());
        for (op, budget, mode) in [
            ("budget", 5000, sandbox_runtime::RetireMode::KillDeadline),
            ("unbounded", 0, sandbox_runtime::RetireMode::Observe),
        ] {
            let r = add_unknown(&j, op, true);
            assert!(started(&j, op, budget));
            assert!(!j.confirm(&binding(), &retire(&r)).unwrap());
            let taken = take(&j);
            assert_eq!(taken[0].request.mode, mode, "{op}");
        }
        // A terminal receipt never gains a start.
        let done = add_unknown(&j, "done", true);
        j.record_result("done", OperationState::Failed, None, None, None)
            .unwrap();
        assert!(
            j.lookup("done").is_some_and(|r| r.is_terminal()),
            "{done:?}"
        );
        assert!(!started(&j, "done", 1));
    }

    /// `commandStopUnproven` (an interim observation) makes the command due
    /// for `kill-cancel`, written with the UNKNOWN result itself.
    #[test]
    fn an_unproven_interim_stop_is_due_for_kill_cancel() {
        let dir = tempfile::tempdir().unwrap();
        let (j, _) = unknown_command(dir.path());
        let r = add_unknown(&j, "interim", true);
        assert!(started(&j, "interim", 0));
        let stored = j
            .record_attempt_result_ext(
                "interim",
                (2, 1),
                OperationState::UnknownOutcome,
                r.result.clone(),
                (Some(SandboxErrorCode::UnknownOutcome.into()), None, None),
                &[(
                    super::COMMAND_STOP_UNPROVEN_EXT,
                    serde_json::Value::Bool(true),
                )],
            )
            .unwrap()
            .unwrap();
        assert_eq!(stored.ext["commandStopUnproven"], true);
        assert!(stored.ext.contains_key("commandStart"));
        assert!(!j.confirm(&binding(), &retire(&r)).unwrap());
        assert_eq!(
            take(&j)[0].request.mode,
            sandbox_runtime::RetireMode::KillCancel
        );
    }

    /// S8: the result's birth and the journaled start's are compared
    /// semantically; either alone suffices; a mismatch (or an invalid
    /// start) is never retirable.
    #[test]
    fn births_are_compared_semantically() {
        let dir = tempfile::tempdir().unwrap();
        let (j, _) = unknown_command(dir.path());
        // Start only (a restart mid-run left no result birth).
        let only = add_unknown(&j, "start-only", false);
        let mut frame = birth_frame("start-only");
        // Reordered keys and another observedAt: the same birth.
        frame["observedAt"] = serde_json::json!("2026-10-27T00:00:01.000Z");
        assert!(
            j.record_command_start("start-only", (2, 1), frame, 1000, 0, None)
                .unwrap()
        );
        assert!(!j.confirm(&binding(), &retire(&only)).unwrap());
        assert_eq!(take(&j)[0].request.birth.pid, 123);
        // Both, differing only in observation time: retirable.
        let both = add_unknown(&j, "both", true);
        let mut frame = birth_frame("both");
        frame["observedAt"] = serde_json::json!("2026-10-27T00:00:02.000Z");
        assert!(
            j.record_command_start("both", (2, 1), frame, 1000, 0, None)
                .unwrap()
        );
        assert!(!j.confirm(&binding(), &retire(&both)).unwrap());
        assert_eq!(take(&j).len(), 1);
        // A real mismatch: never requested.
        let mismatch = add_unknown(&j, "mismatch", true);
        let mut frame = birth_frame("mismatch");
        frame["pid"] = serde_json::json!(999);
        assert!(
            j.record_command_start("mismatch", (2, 1), frame, 1000, 0, None)
                .unwrap()
        );
        assert!(!j.confirm(&binding(), &retire(&mismatch)).unwrap());
        assert!(take(&j).is_empty());
    }

    /// The start write latches the journal on an IO failure (S7); the
    /// receipt is unchanged.
    #[test]
    fn a_failed_start_write_latches_the_journal() {
        let dir = tempfile::tempdir().unwrap();
        let (j, _) = unknown_command(dir.path());
        j.io.fail_writes();
        assert!(
            j.record_command_start("cmd", (2, 1), birth_frame("cmd"), 1000, 0, None)
                .is_err()
        );
        assert!(j.io.failed());
        assert!(!j.lookup("cmd").unwrap().ext.contains_key("commandStart"));
    }

    /// A7 + U6: reconciliation settles an open command to UNKNOWN keeping
    /// the journaled start, and never adds one (only the launching daemon
    /// writes it, so `uid` implies the marker-aware launcher).
    #[test]
    fn reconciliation_keeps_the_start_and_never_adds_one() {
        let dir = tempfile::tempdir().unwrap();
        let (j, _) = unknown_command(dir.path());
        for (op, with_start) in [("kept", true), ("never", false)] {
            let mut r = receipt(op, 1);
            r.template_fingerprint = Some("f".repeat(64));
            j.record_intent(&r).unwrap();
            j.record_effect(op).unwrap();
            if with_start {
                assert!(started(&j, op, 7));
            }
            let settled = j
                .record_reconciled_result(
                    op,
                    OperationState::UnknownOutcome,
                    None,
                    Some(SandboxErrorCode::UnknownOutcome.into()),
                    None,
                )
                .unwrap();
            assert_eq!(settled.state, OperationState::UnknownOutcome);
            assert_eq!(settled.ext.contains_key("commandStart"), with_start, "{op}");
            assert!(
                settled
                    .ext
                    .get("commandStart")
                    .is_none_or(|start| start["budgetMs"] == 7)
            );
        }
    }

    /// A proof taken in negotiated session A whose worker only
    /// runs after the reconnect to session B (unnegotiated, or negotiated
    /// again) never deletes the receipt: the delete re-checks A's token.
    /// Its slot stays held until it settles, and a pending entry admitted in
    /// A is dropped by the reset.
    #[test]
    fn a_proof_queued_in_one_session_never_deletes_in_the_next() {
        let dir = tempfile::tempdir().unwrap();
        let (j, r) = unknown_command(dir.path());
        // Session A (negotiated): the proof is taken, its worker is blocked.
        assert!(!j.confirm(&binding(), &retire(&r)).unwrap());
        let taken = take(&j);
        assert_eq!(taken.len(), 1);
        let queued = add_unknown(&j, "queued", true);
        assert!(!j.confirm(&binding(), &retire(&queued)).unwrap());
        for negotiated_b in [false, true] {
            // Reconnect: B's hello, then its hello.ok answer.
            j.set_command_retire(false);
            j.set_command_retire(negotiated_b);
            let ids: Vec<_> = entries(&j)
                .into_iter()
                .map(|(op, _, in_flight, _)| (op, in_flight))
                .collect();
            assert_eq!(ids, [("cmd".into(), true)], "the pending entry is dropped");
            // The worker unblocks in B and runs A's proof: no delete.
            assert!(
                !j.retire_unknown_command(
                    &binding(),
                    &taken[0].confirmation,
                    &proof(123),
                    taken[0].session
                )
                .unwrap(),
                "negotiated in B: {negotiated_b}"
            );
            assert!(j.lookup("cmd").is_some());
        }
        // A's attempt settles; B can then retire it under its own token.
        j.settle_retirement("cmd", taken[0].session, RetireSettle::Done, &PACING);
        assert!(entries(&j).is_empty());
        assert!(!j.confirm(&binding(), &retire(&r)).unwrap());
        let again = take(&j);
        assert_eq!(again.len(), 1);
        assert!(
            j.retire_unknown_command(
                &binding(),
                &again[0].confirmation,
                &proof(123),
                again[0].session
            )
            .unwrap()
        );
    }

    /// A proof taken in session A that finishes after A ended
    /// (reconnect backoff, a failed dial), before any new `hello`, never
    /// deletes: the session's scope revoked its authority on exit.
    #[test]
    fn a_proof_finishing_after_its_session_ended_never_deletes() {
        let dir = tempfile::tempdir().unwrap();
        let (j, r) = unknown_command(dir.path());
        let j = std::sync::Arc::new(j);
        let scope = crate::sandbox_relay::command_retire::SessionScope::begin(&j);
        j.set_command_retire(true); // A's hello.ok
        assert!(!j.confirm(&binding(), &retire(&r)).unwrap());
        let taken = take(&j);
        assert_eq!(taken.len(), 1);
        drop(scope); // A ends; no new hello yet
        assert!(!j.retirement_current(&taken[0]));
        assert!(
            !j.retire_unknown_command(
                &binding(),
                &taken[0].confirmation,
                &proof(123),
                taken[0].session
            )
            .unwrap()
        );
        assert!(j.lookup("cmd").is_some());
    }
}
