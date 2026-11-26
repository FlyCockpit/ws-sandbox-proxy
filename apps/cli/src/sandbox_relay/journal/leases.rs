//! Lease decisions share the journal mutex with receipts and cleanup. No runtime
//! or network IO under it. The receipt is the write-ahead decision; the per-VM
//! checkpoint survives receipt confirmation. Recovery folds decisions forward.
use super::lease_record::{LeaseGuest, clamp_shorten_only, persist};
use super::*;
use sandbox_protocol::HostLease;

/// A failed authority CAS is different from failed persistence or an active
/// worker: only the latter have retained the captured arm's recovery intent.
#[derive(Debug)]
pub struct StaleEnforcementLossAuthority;
impl std::fmt::Display for StaleEnforcementLossAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("enforcement-loss lease changed")
    }
}
impl std::error::Error for StaleEnforcementLossAuthority {}

/// The dispatched lease ends later than the host's local lease ceiling allows.
/// Mapped to the `lease_exceeds_policy` relay error, never `state_conflict`.
#[derive(Debug)]
pub struct LeaseCeilingExceeded;
impl std::fmt::Display for LeaseCeilingExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("lease exceeds the host lease ceiling")
    }
}
impl std::error::Error for LeaseCeilingExceeded {}

/// Clock skew the ceiling check tolerates between the server and this host.
pub const LEASE_CEILING_SKEW_MS: u64 = 60_000;

/// M5: saturating, `Option`-aware. A lease within the ceiling, or no later
/// than the deadline already stored for this generation, is admitted; so
/// shortenings, pull-ins and a re-arm carrying the old effective deadline pass.
pub fn lease_within_ceiling(deadline: u64, current: u64, now: u64, ceiling: Option<u64>) -> bool {
    match ceiling {
        None => true,
        Some(ceiling) => {
            deadline
                <= current.max(
                    now.saturating_add(ceiling)
                        .saturating_add(LEASE_CEILING_SKEW_MS),
                )
        }
    }
}

/// The restore base a lifecycle dispatch binds. A
/// restore sets its `restore.fingerprint` (a new lineage); any other
/// lifecycle dispatch may name the server's `diskBaseFingerprint` and must
/// then agree with the record; a dispatch without one keeps the record's.
/// Non-lifecycle dispatches never change it.
fn lease_restore_base(
    previous: Option<&LeaseRecord>,
    d: &OperationDispatch,
    lifecycle: bool,
) -> Result<Option<String>> {
    let previous_base = previous.and_then(|r| r.restore_base.clone());
    if !lifecycle {
        return Ok(previous_base);
    }
    if let Some(restore) = &d.restore {
        return Ok(Some(restore.fingerprint.clone()));
    }
    match (d.disk_base_fingerprint.as_ref(), previous) {
        (Some(base), Some(record)) if record.restore_base.as_ref() != Some(base) => {
            bail!("lease restore base binding differs")
        }
        (None, _) => Ok(previous_base),
        (Some(base), _) => Ok(Some(base.clone())),
    }
}

impl HostJournal {
    /// The journaled restore base of `sandbox_id`.
    pub fn restore_base(&self, sandbox_id: &str) -> Option<String> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state
            .leases
            .get(sandbox_id)
            .and_then(|r| r.restore_base.clone())
    }
    /// Every journaled restore base (bound into the runtime at startup).
    pub fn restore_bases(&self) -> Vec<(String, String)> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state
            .leases
            .iter()
            .filter_map(|(id, r)| r.restore_base.clone().map(|base| (id.clone(), base)))
            .collect()
    }
    /// Set the host lease ceiling (`None` = unlimited) before dispatches run
    /// and after every local configuration change.
    pub fn set_lease_ceiling(&self, ceiling: Option<u64>) {
        *self.lease_ceiling.lock().unwrap_or_else(|e| e.into_inner()) = ceiling;
    }
    pub fn lease_ceiling(&self) -> Option<u64> {
        *self.lease_ceiling.lock().unwrap_or_else(|e| e.into_inner())
    }
    /// Live leases whose deadline lies beyond `ceiling` from `now` (the daemon
    /// logs this count; the server pulls them in after the report).
    pub fn leases_over_ceiling(&self, now: u64, ceiling: Option<u64>) -> usize {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state
            .leases
            .values()
            .filter(|r| !r.expired && !r.expiry_complete)
            .filter(|r| {
                // M7: a READY-based lease still pending READY carries the
                // provisioning backstop; its governed length is the timeout.
                let deadline = match r.lease.from_ready_ms {
                    Some(ms) => r.lease.deadline_unix_ms.min(now.saturating_add(ms)),
                    None => r.lease.deadline_unix_ms,
                };
                !lease_within_ceiling(deadline, 0, now, ceiling)
            })
            .count()
    }
    /// The clock is sampled under the same guard as expiry and revision checks.
    /// Persisting a decision is the linearization point, before boot/renew ACK.
    #[cfg(test)]
    pub(crate) fn accept_fixture_lease(&self, dispatch: &OperationDispatch) -> Result<HostLease> {
        let prior = self
            .lookup(&dispatch.operation_id)
            .ok_or_else(|| anyhow::anyhow!("lease has no durable intent"))?;
        let binding = TransportBindingV11 {
            server: prior.server,
            host_owner_id: prior.host_owner_id,
            host_id: prior.host_id,
        };
        crate::sandbox_relay::test_support::install_fixture_key(self, &binding);
        let dispatch = crate::sandbox_relay::test_support::current_fixture_dispatch(dispatch);
        self.accept_lease(&dispatch)
    }
    #[cfg(test)]
    pub(crate) fn accept_fixture_lease_at(
        &self,
        dispatch: &OperationDispatch,
        clock: impl FnOnce() -> Result<u64>,
    ) -> Result<HostLease> {
        let prior = self
            .lookup(&dispatch.operation_id)
            .ok_or_else(|| anyhow::anyhow!("lease has no durable intent"))?;
        let binding = TransportBindingV11 {
            server: prior.server,
            host_owner_id: prior.host_owner_id,
            host_id: prior.host_id,
        };
        crate::sandbox_relay::test_support::install_fixture_key(self, &binding);
        let dispatch = crate::sandbox_relay::test_support::current_fixture_dispatch(dispatch);
        self.accept_lease_at(&dispatch, clock)
    }
    pub fn accept_lease(&self, dispatch: &OperationDispatch) -> Result<HostLease> {
        self.accept_lease_at(dispatch, || self.clock.now_ms())
    }
    fn accept_lease_at(
        &self,
        d: &OperationDispatch,
        clock: impl FnOnce() -> Result<u64>,
    ) -> Result<HostLease> {
        // Reopened keyed digests stay opaque until authenticated key reinstall.
        // Compute outside the state lock: prepare_dispatch reads the receipt index.
        let prior = self
            .lookup(&d.operation_id)
            .ok_or_else(|| anyhow::anyhow!("lease has no durable intent"))?;
        let binding = TransportBindingV11 {
            server: prior.server,
            host_owner_id: prior.host_owner_id,
            host_id: prior.host_id,
        };
        let expected = self
            .prepare_dispatch(&binding, d)
            .map_err(|_| anyhow::anyhow!("lease digest refused"))?;
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if self.io.failed() {
            bail!("journal persistence previously failed");
        }
        let now = clock()?;
        let lease = d
            .lease
            .clone()
            .ok_or_else(|| anyhow::anyhow!("missing lease"))?;
        let mut receipt = state
            .receipts
            .get(&d.operation_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("lease has no durable intent"))?;
        if receipt.body_hash != expected.body_hash {
            bail!("lease intent differs");
        }
        // A warm reconnect whose queued lease has been overtaken by a renewal
        // is an observation of the healthy current lease, not a failure:
        // rejecting it would map a running sandbox to ERROR.
        let mut observation: Option<LeaseRecord> = None;
        if let Some(current) = state.leases.get(&d.sandbox_id) {
            if matches!(d.kind.as_str(), "sandbox.create" | "sandbox.reconnect")
                && current.vm_size != receipt.vm_size
            {
                bail!("lease VM size differs");
            }
            if now < current.observed_unix_ms {
                bail!("lease clock moved backwards");
            }
            if d.generation < current.generation {
                bail!("stale lease generation");
            }
            if d.generation == current.generation {
                if current.expired || now >= current.lease.deadline_unix_ms {
                    bail!("lease expiry won");
                }
                if lease.revision == current.lease.revision
                    && lease != current.lease
                    && clamp_shorten_only(&lease, Some(current), d.generation) != current.lease
                {
                    bail!("conflicting lease revision");
                }
                if lease.revision < current.lease.revision {
                    if d.kind == "sandbox.reconnect" {
                        observation = Some(current.clone());
                    } else {
                        bail!("stale or conflicting lease revision");
                    }
                }
                if d.kind == "sandbox.reconnect"
                    && lease.revision > current.lease.revision
                    && lease.deadline_unix_ms < current.lease.deadline_unix_ms
                {
                    bail!("connect cannot shorten a lease");
                }
                // A warm reconnect is an observation; it cannot revive expiry.
            } else {
                // The deadline is evaluated under the journal lock for every
                // generation, not only after the timer latched `expired`; a
                // reconnect must never bypass an overdue destroy lease. Only a
                // completed stop cleanup may be rearmed.
                let lapsed = current.expired || now >= current.lease.deadline_unix_ms;
                if (lapsed
                    && (!current.expiry_complete
                        || current.enforcement_loss
                        || current.lease.action == sandbox_protocol::LeaseAction::Destroy))
                    || d.kind == "sandbox.lease.renew"
                    || lease.revision <= current.lease.revision
                {
                    bail!("renew cannot restart a sandbox");
                }
            }
        } else if d.kind == "sandbox.lease.renew" {
            bail!("renew has no existing lease");
        }
        // A shorten-only lease is the server's keyless
        // system pull-in. It is a renewal, and the host stores it only as a
        // shortening of the deadline it holds for this generation.
        if lease.shorten_only && d.kind != "sandbox.lease.renew" {
            bail!("shorten-only lease on a non-renewal");
        }
        // M7: a READY-based lease belongs to a create only; its deadline is a
        // provisional backstop and the ceiling applies to the relative timeout.
        if lease.from_ready_ms.is_some() && d.kind != "sandbox.create" {
            bail!("lease from READY on a non-create");
        }
        // M1: the host ceiling applies only to a lease that will be stored —
        // never to an observation, never to an identical same-generation replay.
        let same_generation = state
            .leases
            .get(&d.sandbox_id)
            .filter(|current| current.generation == d.generation);
        let replay =
            same_generation.is_some_and(|current| lease.revision <= current.lease.revision);
        if observation.is_none() && !replay {
            let current = same_generation.map_or(0, |current| current.lease.deadline_unix_ms);
            let checked = match lease.from_ready_ms {
                Some(ms) => now.saturating_add(ms),
                None => lease.deadline_unix_ms,
            };
            if !lease_within_ceiling(checked, current, now, self.lease_ceiling()) {
                return Err(LeaseCeilingExceeded.into());
            }
        }
        // An observational reconnect is validated against the healthy current
        // lease: its queued lease may have been overtaken by a renewal, even
        // past the queued deadline. Every other decision validates the
        // dispatched lease itself.
        match &observation {
            Some(current) => current.lease.validate(now).map_err(anyhow::Error::msg)?,
            None => lease.validate(now).map_err(anyhow::Error::msg)?,
        }
        if state
            .cleanups
            .get(&d.sandbox_id)
            .is_some_and(|c| c.generation >= d.generation)
        {
            bail!("sandbox already stopped");
        }
        if !state.leases.contains_key(&d.sandbox_id) && state.leases.len() >= 65_536 {
            bail!("lease journal capacity");
        }
        if state
            .leases
            .get(&d.sandbox_id)
            .is_none_or(|r| r.expiry_complete)
            && state.leases.values().filter(|r| !r.expiry_complete).count() >= super::MAX_ACTIONS
        {
            bail!("host expiry capacity");
        }
        let template_fingerprint = receipt.template_fingerprint.clone().or_else(|| {
            state
                .leases
                .get(&d.sandbox_id)
                .and_then(|r| r.template_fingerprint.clone())
        });
        if state
            .leases
            .get(&d.sandbox_id)
            .and_then(|r| r.template_fingerprint.as_ref())
            .is_some_and(|old| Some(old) != template_fingerprint.as_ref())
        {
            bail!("lease template binding differs");
        }
        // Like the template, the declared guest is immutable for the sandbox.
        let previous_guest = state
            .leases
            .get(&d.sandbox_id)
            .and_then(|r| r.guest.clone());
        let guest = LeaseGuest::from_dispatch(d);
        if previous_guest
            .as_ref()
            .zip(guest.as_ref())
            .is_some_and(|(old, new)| old != new)
        {
            bail!("lease guest binding differs");
        }
        let guest = guest.or(previous_guest);
        // D1: only a create binds a build, and the binding never changes; a
        // reconnect of a build sandbox is refused (it carries no binding).
        let previous_build = state.leases.get(&d.sandbox_id).map(|r| r.build_id.clone());
        let requested_build = d.build.as_ref().map(|b| b.build_id.clone());
        let build_id = match previous_build {
            Some(previous) if matches!(d.kind.as_str(), "sandbox.create" | "sandbox.reconnect") => {
                if previous != requested_build {
                    bail!("lease build binding differs");
                }
                previous
            }
            Some(previous) => previous,
            None => requested_build,
        };
        // Guest privilege (guest sudo plan step 9): only lifecycle dispatches
        // carry the fields. `guest_sudo` never changes for the record;
        // `guest_root` may rise on a create or reconnect and never falls;
        // every other kind carries both unchanged.
        let lifecycle = matches!(d.kind.as_str(), "sandbox.create" | "sandbox.reconnect");
        if !lifecycle && (d.guest_sudo.is_some() || d.guest_root.is_some()) {
            bail!("guest privilege fields only on create or reconnect");
        }
        let new_sudo = d.guest_sudo == Some(true);
        let new_root = d.guest_root == Some(true);
        let (guest_sudo, guest_root) = match state.leases.get(&d.sandbox_id) {
            Some(previous) if !lifecycle => (previous.guest_sudo, previous.guest_root),
            Some(previous) => {
                if previous.guest_sudo != new_sudo {
                    bail!("lease guest sudo binding differs");
                }
                if previous.guest_root && !new_root {
                    bail!("lease guest root binding differs");
                }
                (previous.guest_sudo, previous.guest_root || new_root)
            }
            None => (new_sudo, new_root),
        };
        if guest_sudo && (!guest_root || build_id.is_some()) {
            bail!("guest sudo without guest root or with build");
        }
        let restore_base = lease_restore_base(state.leases.get(&d.sandbox_id), d, lifecycle)?;
        // The receipt always carries the immutable queued lease: the server
        // fences the ACK on it, including recovered results. The effective
        // observation is separate — returned for runtime work, never stored
        // over the ACK tuple. An observation rewrites no lease record.
        let previous_config = state
            .leases
            .get(&d.sandbox_id)
            .and_then(|r| r.private_config.clone());
        if previous_config
            .as_ref()
            .zip(d.private_config.as_ref())
            .is_some_and(|(old, new)| old != new)
            || (previous_config.is_some()
                && d.private_config.is_none()
                && matches!(d.kind.as_str(), "sandbox.create" | "sandbox.reconnect"))
        {
            bail!("private config binding differs");
        }
        let vm_size = state
            .leases
            .get(&d.sandbox_id)
            .map_or(receipt.vm_size, |current| current.vm_size);
        let record = LeaseRecord {
            version: JOURNAL_VERSION,
            sandbox_owner_id: receipt.sandbox_owner_id.clone(),
            root_deleted: false,
            // A lease renewal carries no resize or placement fields. Preserve
            // the exact original root and charges through every checkpoint.
            allocation: receipt.allocation.clone().or_else(|| {
                state
                    .leases
                    .get(&d.sandbox_id)
                    .and_then(|current| current.allocation.clone())
            }),
            vm_size,
            private_config: d.private_config.clone().or(previous_config),
            template_fingerprint,
            binding: TransportBindingV11 {
                server: receipt.server.clone(),
                host_owner_id: receipt.host_owner_id.clone(),
                host_id: receipt.host_id.clone(),
            },
            sandbox_id: d.sandbox_id.clone(),
            generation: d.generation,
            // The receipt keeps the queued lease: the server fences the ACK
            // on it. The stored record (below) may be a clamped shortening.
            lease: lease.clone(),
            expired: false,
            expiry_complete: false,
            observed_unix_ms: now,
            timer_expired: false,
            instance_absent: false,
            enforcement_loss: false,
            guest,
            build_id,
            stopped_generation: None,
            guest_sudo,
            guest_root,
            restore_base,
            evicted: false,
        };
        receipt.lease = Some(record.clone());
        let mut record = record;
        record.lease = clamp_shorten_only(&lease, state.leases.get(&d.sandbox_id), d.generation);
        // An observational reconnect that raises `guest_root` still raises it
        // on the current lease (its revision may be older than a renewal's).
        let raised = observation
            .as_ref()
            .filter(|_| guest_root)
            .and_then(|_| state.leases.get(&d.sandbox_id))
            .filter(|current| !current.guest_root)
            .map(|current| LeaseRecord {
                guest_root: true,
                ..current.clone()
            });
        // Never retry uncertain fsync in this process: a failed checkpoint poisons
        // further lease admission. On reopen the durable receipt repairs it.
        let written = (|| {
            self.maybe_crash(CrashPoint::BeforeLease)?;
            persist_receipt(&self.io, &self.receipts_dir, &receipt)?;
            state
                .receipts
                .insert(d.operation_id.clone(), receipt.clone());
            self.maybe_crash(CrashPoint::AfterLeaseDecision)?;
            match &raised {
                // An observation rewrites no lease, except the monotonic
                // `guest_root` rise (rise-only, so a max-merge is safe in any
                // revision order).
                Some(current) => persist(&self.io, &self.leases_dir, current),
                None if observation.is_some() => Ok(()),
                None => persist(&self.io, &self.leases_dir, &record),
            }
        })();
        if let Err(error) = written {
            self.io.trip();
            return Err(error);
        }
        state.receipts.insert(d.operation_id.clone(), receipt);
        if let Some(current) = raised {
            state.leases.insert(d.sandbox_id.clone(), current);
        } else if observation.is_none() {
            state.leases.insert(d.sandbox_id.clone(), record.clone());
        }
        Ok(match &observation {
            Some(current) => current.lease.clone(),
            None => record.lease,
        })
    }

    /// M7: at READY, a create's READY-based lease becomes readyAt + timeout
    /// (never past the provisional backstop). Returns the settled lease the
    /// host ACKs; `None` for an ordinary lease. Idempotent per generation.
    pub fn settle_ready_lease(&self, d: &OperationDispatch) -> Result<Option<HostLease>> {
        let Some(lease) = d.lease.as_ref().filter(|l| l.from_ready_ms.is_some()) else {
            return Ok(None);
        };
        self.settle_ready(&d.sandbox_id, d.generation, lease)
            .map(Some)
    }

    /// Settle (or re-read) the READY-based lease of `sandbox_id`; also used by
    /// restart recovery, which must ACK the settled deadline, never the
    /// provisional backstop the receipt queued.
    pub fn settle_ready(
        &self,
        sandbox_id: &str,
        generation: u64,
        queued: &HostLease,
    ) -> Result<HostLease> {
        let ms = queued
            .from_ready_ms
            .ok_or_else(|| anyhow::anyhow!("not a READY-based lease"))?;
        let now = self.clock.now_ms()?;
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut record = state
            .leases
            .get(sandbox_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("READY lease has no record"))?;
        if record.generation != generation || record.lease.revision != queued.revision {
            // A renewal overtook it: the newer lease already governs.
            return Ok(record.lease);
        }
        if record.lease.from_ready_ms.is_some() {
            let deadline = now
                .saturating_add(ms)
                .min(record.lease.deadline_unix_ms)
                .min(sandbox_protocol::LEASE_UNLIMITED_DEADLINE_MS);
            record.lease.deadline_unix_ms = deadline;
            persist(&self.io, &self.leases_dir, &record)?;
            state.leases.insert(sandbox_id.to_owned(), record.clone());
        }
        // The ACK echoes the relative timeout so the server applies its
        // READY-window fence, not the provisional-equality fence.
        Ok(HostLease {
            from_ready_ms: Some(ms),
            ..record.lease
        })
    }

    /// C32's timer calls this under the same guard as renew. A terminal latch is
    /// durable before any stop attempt, and a later renewal cannot clear it.
    pub fn expire_lease(&self, sandbox_id: &str, generation: u64, revision: u64) -> Result<bool> {
        self.expire_lease_at(sandbox_id, generation, revision, || self.clock.now_ms())
    }
    /// Test seam: latch the timer expiry as if the deadline had passed.
    #[cfg(test)]
    pub fn expire_lease_now_for_test(
        &self,
        sandbox_id: &str,
        generation: u64,
        revision: u64,
    ) -> bool {
        self.expire_lease_at(sandbox_id, generation, revision, || Ok(u64::MAX / 2))
            .unwrap_or(false)
    }
    fn expire_lease_at(
        &self,
        sandbox_id: &str,
        generation: u64,
        revision: u64,
        clock: impl FnOnce() -> Result<u64>,
    ) -> Result<bool> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let Some(mut row) = state.leases.get(sandbox_id).cloned() else {
            return Ok(false);
        };
        let now = clock()?;
        if row.generation != generation || row.lease.revision != revision || row.expired {
            return Ok(false);
        }
        if now >= row.observed_unix_ms && now < row.lease.deadline_unix_ms {
            return Ok(false);
        }
        row.expired = true;
        row.timer_expired = true;
        if let Err(error) = persist(&self.io, &self.leases_dir, &row) {
            self.io.trip();
            return Err(error);
        }
        state.leases.insert(sandbox_id.to_owned(), row);
        Ok(true)
    }
    /// Timer and renewal serialize here. Intent is durable before authority revocation
    /// or runtime IO. Persist the observed clock floor for restart rollback detection.
    pub fn poll_expiry(&self) -> Result<Vec<LeaseRecord>> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let now = self.clock.now_ms().ok();
        let mut due = Vec::new();
        let mut io_failed = false;
        for row in state.leases.values_mut() {
            if row.expiry_complete {
                continue;
            }
            // Fail closed on an unreadable clock without persisting a synthetic
            // time floor that would forbid valid cold rearm after recovery.
            let observed = now.unwrap_or(row.observed_unix_ms);
            let expired = row.expired
                || now.is_none_or(|time| {
                    time < row.observed_unix_ms || time >= row.lease.deadline_unix_ms
                });
            if expired != row.expired
                || (!expired && observed.saturating_sub(row.observed_unix_ms) >= 1000)
            {
                let mut next = row.clone();
                next.timer_expired |= expired && !row.expired;
                next.expired = expired;
                next.observed_unix_ms = next.observed_unix_ms.max(observed);
                if self
                    .maybe_crash(CrashPoint::BeforeExpiry)
                    .and_then(|()| persist(&self.io, &self.leases_dir, &next))
                    .is_err()
                {
                    // The accepted deadline/action itself is already durable intent.
                    // Never leave a VM running because its expiry checkpoint failed.
                    // Poison all admission; restart re-evaluates the durable deadline.
                    io_failed = true;
                    row.timer_expired |= expired && !row.expired;
                    row.expired = expired;
                } else {
                    *row = next;
                }
            }
            if row.expired {
                due.push(row.clone());
            }
        }
        if io_failed {
            self.io.trip();
        }
        Ok(due)
    }
    pub fn finish_expiry(&self, row: &LeaseRecord) -> Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        self.complete_expiry_locked(&mut state, row)
    }
    /// Shared completion CAS for timer workers AND autonomous loss drains.
    /// `row` is the immutable intent actually executed, never a fresh poll.
    fn complete_expiry_locked(&self, state: &mut JournalState, row: &LeaseRecord) -> Result<()> {
        if state
            .lease_workers
            .get(&row.sandbox_id)
            .copied()
            .unwrap_or(0)
            != 0
        {
            bail!("lifecycle work still settling");
        }
        let current = state
            .leases
            .get_mut(&row.sandbox_id)
            .ok_or_else(|| anyhow::anyhow!("missing expiry"))?;
        if current.generation != row.generation
            || current.lease != row.lease
            || current.binding != row.binding
            || current.template_fingerprint != row.template_fingerprint
            || current.enforcement_loss != row.enforcement_loss
            || !current.expired
        {
            bail!("expiry changed");
        }
        let mut next = current.clone();
        next.expiry_complete = true;
        // A completed destroy expiry deleted the instance; a completed stop
        // leaves the VM stopped on disk and the record must stay census-visible.
        next.instance_absent = current.enforcement_loss
            || current.lease.action == sandbox_protocol::LeaseAction::Destroy;
        next.root_deleted = next.instance_absent && next.allocation.is_some();
        self.maybe_crash(CrashPoint::BeforeExpiryComplete)?;
        persist(&self.io, &self.leases_dir, &next)?;
        let deleted = next.root_deleted;
        *current = next;
        self.release_storage_locked(state, &row.sandbox_id, row.generation, deleted)?;
        Ok(())
    }
    /// A retired journal can acknowledge an already-absent runtime loss.
    /// This grants no VM mutation authority and never releases a reservation.
    pub fn enforcement_loss_retired(&self, id: &str) -> bool {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        !state.leases.contains_key(id)
            && !state.storage.roots.contains_key(id)
            && state.lease_workers.get(id).copied().unwrap_or(0) == 0
            && !state.receipts.values().any(|r| {
                r.sandbox_id == id
                    && matches!(r.kind.as_str(), "sandbox.create" | "sandbox.reconnect")
                    && !r.is_terminal()
            })
    }
    /// The journal boundary for autonomous loss cleanup. The sweep's
    /// pre-observation arm is mandatory at both checkpoints: neither a stale
    /// result nor a renewal/new generation during runtime IO can settle a
    /// newer reservation. Clock-floor checkpoints are not authority changes.
    /// Active lifecycle workers veto settlement as in ordinary expiry.
    pub fn settle_enforcement_loss(
        &self,
        observed: &LeaseRecord,
        stage: sandbox_runtime::EnforcementLossStage,
    ) -> Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if stage == sandbox_runtime::EnforcementLossStage::Complete {
            // The drain executed a prepared destruction intent, including when
            // its pre-observation snapshot was an ordinary stop lease.
            let destruction = LeaseRecord {
                enforcement_loss: true,
                ..observed.clone()
            };
            return self.complete_expiry_locked(&mut state, &destruction);
        }
        let id = &observed.sandbox_id;
        let current = state
            .leases
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("missing enforcement-loss lease"))?;
        if current.generation != observed.generation
            || current.lease != observed.lease
            || current.binding != observed.binding
            || current.template_fingerprint != observed.template_fingerprint
        {
            return Err(StaleEnforcementLossAuthority.into());
        }
        let mut next = current.clone();
        next.expired = true;
        // Latch even while a lifecycle worker settles. It must lose admission,
        // but its presence vetoes destructive IO and completion below.
        next.expiry_complete &= next.instance_absent;
        next.enforcement_loss = true;
        // Retry durability even when the in-memory latch is already set: a
        // failed write must retain recovery intent, not grant delete authority.
        let written = persist(&self.io, &self.leases_dir, &next);
        state.leases.insert(id.clone(), next);
        if let Err(error) = written {
            self.io.trip();
            return Err(error);
        }
        if state.lease_workers.get(id).copied().unwrap_or(0) != 0 {
            bail!("lifecycle work still settling");
        }
        Ok(())
    }
    pub fn reopen_expiry(&self, row: &LeaseRecord) -> Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let current = state
            .leases
            .get_mut(&row.sandbox_id)
            .ok_or_else(|| anyhow::anyhow!("missing lease"))?;
        if current != row || !current.expired {
            bail!("lease changed during census");
        }
        let mut next = current.clone();
        next.expiry_complete = false;
        // The census just observed this instance present.
        next.instance_absent = false;
        persist(&self.io, &self.leases_dir, &next)?;
        *current = next;
        Ok(())
    }
    pub fn retire_inactive_lease(&self, row: &LeaseRecord, instance_absent: bool) -> Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state
            .lease_workers
            .get(&row.sandbox_id)
            .copied()
            .unwrap_or(0)
            != 0
        {
            bail!("lifecycle work still settling");
        }
        let current = state
            .leases
            .get_mut(&row.sandbox_id)
            .ok_or_else(|| anyhow::anyhow!("missing lease"))?;
        if current != row || current.expired {
            bail!("lease changed during census");
        }
        let mut next = current.clone();
        next.expired = true;
        next.expiry_complete = true;
        next.instance_absent = instance_absent;
        persist(&self.io, &self.leases_dir, &next)?;
        *current = next;
        self.release_storage_locked(&mut state, &row.sandbox_id, row.generation, false)?;
        Ok(())
    }
    pub fn leases(&self) -> Vec<LeaseRecord> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .leases
            .values()
            .cloned()
            .collect()
    }
    pub fn work_allowed(&self, id: &str, generation: u64, kind: &str) -> bool {
        self.work_refusal(id, generation, kind).is_none()
    }
    /// Why the host refuses `kind` at `generation` of `id` before issue, or
    /// `None` when the work is allowed. The reason is a fixed token, safe to
    /// log (no secrets, no server text).
    pub fn work_refusal(&self, id: &str, generation: u64, kind: &str) -> Option<&'static str> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if matches!(kind, "sandbox.stop" | "sandbox.kill") {
            return None;
        }
        if self.io.failed() {
            return Some("journal_io_failed");
        }
        let Some(row) = state.leases.get(id) else {
            return (!matches!(kind, "sandbox.create" | "sandbox.reconnect")).then_some("no_lease");
        };
        if generation > row.generation && matches!(kind, "sandbox.create" | "sandbox.reconnect") {
            // Mirror accept_lease: the deadline counts under the lock even
            // before the timer latches it, and only a completed stop cleanup
            // may be rearmed. An unreadable clock fails closed.
            let Ok(now) = self.clock.now_ms() else {
                return Some("clock_unavailable");
            };
            let lapsed = row.expired || now >= row.lease.deadline_unix_ms;
            let rearmable = row.expiry_complete
                && !row.enforcement_loss
                && row.lease.action == sandbox_protocol::LeaseAction::Stop;
            return (lapsed && !rearmable).then_some("lease_lapsed");
        }
        let live = self.live_lease_refusal(row, generation);
        if live.is_some() && kind == "sandbox.capture" {
            // B1: a STOPPED capture never runs under the lease (stop does not
            // carry one, and a settled stop retires it). Its authority is the
            // host's own confirmed stop. A READY capture on a stopped
            // instance fails at the guest freeze; the runtime additionally
            // refuses a STOPPED capture of an instance that may be running.
            return self.stopped_capture_refusal(&state, row, generation);
        }
        live
    }
    /// Ordinary work: the exact generation of a live, observed lease.
    fn live_lease_refusal(&self, row: &LeaseRecord, generation: u64) -> Option<&'static str> {
        let Ok(now) = self.clock.now_ms() else {
            return Some("clock_unavailable");
        };
        if generation != row.generation {
            Some("generation_mismatch")
        } else if row.expired {
            Some("lease_expired")
        } else if now < row.observed_unix_ms {
            Some("clock_before_observation")
        } else if now >= row.lease.deadline_unix_ms {
            Some("lease_deadline_passed")
        } else {
            None
        }
    }
    /// B1: a STOPPED capture is allowed at any generation at or after the
    /// host's confirmed stop of an instance that is still on disk, while no
    /// create/reconnect is settling. A newer start replaces the lease record
    /// (and its stop evidence), and the authority generation fence refuses
    /// the older capture. A settled stop lease (explicit, timer or census)
    /// is itself stop evidence at its generation. A destroy lease keeps its
    /// deadline: the stop is authority only until that deadline.
    fn stopped_capture_refusal(
        &self,
        state: &JournalState,
        row: &LeaseRecord,
        generation: u64,
    ) -> Option<&'static str> {
        if row.instance_absent || row.root_deleted {
            return Some("stopped_capture_instance_absent");
        }
        if row.enforcement_loss {
            return Some("stopped_capture_enforcement_loss");
        }
        if state
            .lease_workers
            .get(&row.sandbox_id)
            .copied()
            .unwrap_or(0)
            != 0
        {
            return Some("stopped_capture_lifecycle_settling");
        }
        let stopped_at = if row.expired {
            if !row.expiry_complete {
                return Some("stopped_capture_expiry_settling");
            }
            if row.lease.action != sandbox_protocol::LeaseAction::Stop {
                return Some("stopped_capture_no_stop_evidence");
            }
            row.stopped_generation.unwrap_or(row.generation)
        } else {
            let Some(stopped_at) = row.stopped_generation else {
                return Some("stopped_capture_no_stop_evidence");
            };
            let Ok(now) = self.clock.now_ms() else {
                return Some("clock_unavailable");
            };
            if now >= row.lease.deadline_unix_ms {
                return Some("lease_deadline_passed");
            }
            stopped_at
        };
        (generation < stopped_at).then_some("stopped_capture_stale_generation")
    }
    pub fn lease_work(&self, d: &OperationDispatch) -> LeaseWork<'_> {
        let id = matches!(d.kind.as_str(), "sandbox.create" | "sandbox.reconnect")
            .then(|| d.sandbox_id.clone());
        if let Some(id) = &id {
            *self
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .lease_workers
                .entry(id.clone())
                .or_default() += 1;
        }
        LeaseWork { journal: self, id }
    }
    /// WP2: any durable journal write has failed in this process (the
    /// journal-wide latch, see [`IoLatch`]).
    pub fn io_failed(&self) -> bool {
        self.io.failed()
    }
    /// D3a: the sandbox's journaled lease ends within `margin` by the same
    /// rollback-resistant [`LeaseClock`](super::super::clock::LeaseClock)
    /// that expiry uses, or is already expired by it. An unreadable clock, or
    /// one before the lease's last observation (expiry treats both as
    /// expired), counts as ending now. `false` when no lease is journaled.
    pub fn lease_ends_within(&self, sandbox_id: &str, margin: std::time::Duration) -> bool {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let Some(row) = state.leases.get(sandbox_id) else {
            return false;
        };
        if row.expired {
            return true;
        }
        let Ok(now) = self.clock.now_ms() else {
            return true;
        };
        let margin = u64::try_from(margin.as_millis()).unwrap_or(u64::MAX);
        now < row.observed_unix_ms || now.saturating_add(margin) >= row.lease.deadline_unix_ms
    }
    /// The daemon deleted this
    /// sandbox's VM and proved its root absent. The lease is settled as a
    /// completed destroy (instance and root gone) and the root's storage is
    /// released, exactly as a completed destroy expiry leaves it. Refused
    /// while lifecycle work of the sandbox still runs (a live permit).
    pub fn record_evicted(&self, sandbox_id: &str) -> Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.lease_workers.get(sandbox_id).copied().unwrap_or(0) != 0 {
            bail!("lifecycle work still settling");
        }
        let Some(current) = state.leases.get_mut(sandbox_id) else {
            return Ok(());
        };
        let mut next = current.clone();
        next.expired = true;
        next.expiry_complete = true;
        next.instance_absent = true;
        next.evicted = true;
        next.root_deleted = next.allocation.is_some();
        // An eviction is a server-granted removal of a STOPPED disk whose
        // copy is in the store, never a destroy expiry (C32): settle it as a
        // completed stop, so a restore back onto this host at a later
        // generation may rearm instead of being refused `lease_lapsed`.
        next.lease.action = sandbox_protocol::LeaseAction::Stop;
        // This single write is the durable eviction. Everything
        // below is derived from it and replayed on open/maintain.
        persist(&self.io, &self.leases_dir, &next)?;
        self.maybe_crash(CrashPoint::AfterEvictedLease)?;
        let (generation, deleted) = (next.generation, next.root_deleted);
        *current = next;
        // §8.6 (N4, V6): the proven root absence also settles this host's
        // cleanup watermark. A stop's watermark proves no absence, so without
        // this the retained private config is never collected and a later
        // restore back onto this host (the same config at generation g + 1)
        // is refused forever.
        settle_absent_watermarks(&self.io, &self.cleanups_dir, &mut state)?;
        self.maybe_crash(CrashPoint::AfterEvictedWatermark)?;
        self.release_storage_locked(&mut state, sandbox_id, generation, deleted)?;
        // Best effort: `maintain` retries a GC that fails here.
        let _ = self.gc_configs_locked(&mut state);
        Ok(())
    }
    /// Whether lifecycle work of `sandbox_id` holds a lease worker (a live
    /// lifecycle permit): no eviction runs under one.
    pub fn lifecycle_busy(&self, sandbox_id: &str) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .lease_workers
            .get(sandbox_id)
            .copied()
            .unwrap_or(0)
            != 0
    }
    pub fn lease(&self, sandbox_id: &str) -> Option<LeaseRecord> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .leases
            .get(sandbox_id)
            .cloned()
    }
    /// CLI logins: a user stop/kill refused with
    /// `credential_capture_failed` leaves the VM running, and the server
    /// returns the sandbox to READY at the stop's generation. Re-bind the
    /// live lease row to that generation (deadline, revision and action
    /// untouched) so ordinary work at it passes [`Self::work_allowed`].
    /// Idempotent; never touches an expired, settled or newer row. The
    /// credential journal records the owed re-bind first (same write as the
    /// attempt abort) and replays it here after a crash.
    pub fn rebind_after_refused_teardown(&self, sandbox_id: &str, generation: u64) -> Result<bool> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let Some(row) = state.leases.get(sandbox_id) else {
            return Ok(false);
        };
        if row.generation >= generation || row.expired || row.expiry_complete {
            return Ok(false);
        }
        let mut next = row.clone();
        next.generation = generation;
        if let Err(error) = persist(&self.io, &self.leases_dir, &next) {
            self.io.trip();
            return Err(error);
        }
        state.leases.insert(sandbox_id.to_owned(), next);
        Ok(true)
    }
}

// A positive explicit teardown also releases its timer reservation. Never let a
// receipt supersede a timer's in-flight cleanup or a newer accepted generation.
// An already-settled lease may only gain deletion evidence from a
// generation-fenced kill: stop-then-kill must not strand the record forever.
pub(super) fn retire_cleanup(
    io: &IoLatch,
    dir: &Path,
    state: &mut JournalState,
    receipt: &HostReceipt,
) -> Result<()> {
    let Some(row) = state.leases.get_mut(&receipt.sandbox_id) else {
        return Ok(());
    };
    if receipt.generation < row.generation
        || state
            .lease_workers
            .get(&row.sandbox_id)
            .copied()
            .unwrap_or(0)
            != 0
        || !super::confirmed_release(&receipt.kind, receipt.state, receipt.result.as_ref())
    {
        return Ok(());
    }
    // B1: the host's own confirmed stop is the authority of a later STOPPED
    // capture (stop dispatches carry no lease). Only `stopped`: an `absent`
    // result left no root to capture.
    let stopped = receipt.kind == "sandbox.stop"
        && receipt
            .result
            .as_ref()
            .and_then(|v| v.get("state"))
            .and_then(|v| v.as_str())
            == Some("stopped");
    if receipt.kind == "sandbox.stop" && row.lease.action != sandbox_protocol::LeaseAction::Stop {
        // A destroy lease keeps its own deadline; the stop only records
        // evidence, it never retires the lease.
        if !stopped || row.expired || row.stopped_generation >= Some(receipt.generation) {
            return Ok(());
        }
        let mut next = row.clone();
        next.stopped_generation = Some(receipt.generation);
        persist(io, dir, &next)?;
        *row = next;
        return Ok(());
    }
    let mut next = row.clone();
    if row.expired {
        // Unfinished expiry owns the row; only a completed lease may take
        // deletion evidence, and only a kill is deletion evidence.
        if !row.expiry_complete || receipt.kind != "sandbox.kill" || row.instance_absent {
            return Ok(());
        }
        next.instance_absent = true;
    } else {
        next.expired = true;
        next.expiry_complete = true;
        // A kill deletes the instance; a stop leaves it on disk.
        next.instance_absent = receipt.kind == "sandbox.kill";
        if stopped {
            next.stopped_generation = Some(receipt.generation);
        }
    }
    persist(io, dir, &next)?;
    *row = next;
    Ok(())
}
/// C31: confirmed-settled lease records are durably removed so the admission
/// bound counts outstanding work, not lifetime creations. Fencing survives
/// removal through the cleanup watermark (same sandbox, generation >= the
/// record's), and a receipt still carrying the lease keeps the record. Only
/// proven-absent instances compact: a completed stop lease still binds the
/// stopped VM on disk, and the reconnect census rejects instances without a
/// durable lease. The caller holds the journal mutex; the watermark was
/// fsynced before this runs.
pub(super) fn compact_confirmed(
    io: &IoLatch,
    dir: &Path,
    cleanups_dir: &Path,
    state: &mut JournalState,
) -> Result<()> {
    // A record's durable absence reaches its watermark before the
    // record can go, so compaction never discards it behind a stale stop
    // watermark that proves no absence.
    settle_absent_watermarks(io, cleanups_dir, state)?;
    let ids: Vec<String> = state
        .leases
        .values()
        .filter(|row| {
            row.expiry_complete
                && row.instance_absent
                && state
                    .lease_workers
                    .get(&row.sandbox_id)
                    .copied()
                    .unwrap_or(0)
                    == 0
                && state
                    .cleanups
                    .get(&row.sandbox_id)
                    .is_some_and(|c| c.generation >= row.generation)
                && !state.receipts.values().any(|r| {
                    r.lease
                        .as_ref()
                        .is_some_and(|l| l.sandbox_id == row.sandbox_id)
                })
        })
        .map(|row| row.sandbox_id.clone())
        .collect();
    if ids.is_empty() {
        return Ok(());
    }
    for id in &ids {
        remove_durably(io, &dir.join(cleanup_file_name(id)), true)?;
    }
    sync_dir(io, dir)?;
    for id in ids {
        state.leases.remove(&id);
    }
    Ok(())
}

/// Derive the cleanup watermark's absence from a
/// lease record's durable absence proof (`expiry_complete` and
/// `instance_absent`), so a crash between the record and its watermark write
/// never strands the proof. An evicted record writes an absent watermark at
/// its generation even when none (or an older one) exists, exactly as
/// [`HostJournal::record_evicted`] does; any other proven-absent record only
/// upgrades a watermark already at or above its generation (the confirmation
/// rule: a lease absent at g proves absence at a cleanup generation >= g).
/// Idempotent; skipped while lifecycle work of the sandbox runs.
pub(super) fn settle_absent_watermarks(
    io: &IoLatch,
    cleanups_dir: &Path,
    state: &mut JournalState,
) -> Result<()> {
    let mut writes = Vec::new();
    for row in state.leases.values() {
        if !row.expiry_complete
            || !row.instance_absent
            || state
                .lease_workers
                .get(&row.sandbox_id)
                .copied()
                .unwrap_or(0)
                != 0
        {
            continue;
        }
        let old = state.cleanups.get(&row.sandbox_id);
        if old.is_some_and(|c| c.instance_absent && c.generation >= row.generation) {
            continue;
        }
        let watermark = match old {
            Some(c) if c.generation >= row.generation => CleanupWatermark {
                instance_absent: true,
                ..c.clone()
            },
            _ if row.evicted => CleanupWatermark {
                version: JOURNAL_VERSION,
                binding: row.binding.clone(),
                sandbox_owner_id: row.sandbox_owner_id.clone(),
                sandbox_id: row.sandbox_id.clone(),
                generation: row.generation,
                instance_absent: true,
                ext: JournalExt::default(),
            },
            _ => continue,
        };
        writes.push(watermark);
    }
    for watermark in writes {
        persist_cleanup(io, cleanups_dir, &watermark)?;
        state
            .cleanups
            .insert(watermark.sandbox_id.clone(), watermark);
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    fn binding() -> TransportBindingV11 {
        TransportBindingV11 {
            server: "wss://lease.test".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        }
    }
    fn dispatch(id: &str, revision: u64) -> OperationDispatch {
        serde_json::from_value(serde_json::json!({"sandboxOwnerId":"owner",  "operationId": id, "sandboxId": "lease-test", "generation": 1, "attempt": 1,
            "kind": if revision == 1 { "sandbox.create" } else { "sandbox.lease.renew" }, "idempotencyKey": id, "bodyHash": "a".repeat(64),
            "lease": { "revision": revision, "deadlineUnixMs": 100_000 + revision * 1000, "action": "stop", "expiryPolicy": "retry-force-60s" } })).unwrap()
    }
    fn intent(j: &HostJournal, d: &OperationDispatch) {
        assert!(matches!(
            j.record_intent(&intent_from_dispatch(j, &binding(), d))
                .unwrap(),
            Decision::Fresh
        ));
    }
    /// The lease record persists the restore base
    /// before the runtime call; a restore sets a new lineage, a later
    /// lifecycle dispatch must name the same `diskBaseFingerprint`, and
    /// non-lifecycle dispatches keep it. It survives a reopen.
    #[test]
    fn restore_base_is_journaled_before_the_runtime_and_binds_later_launches() {
        const DISK: &str =
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        const OTHER: &str =
            "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        let create = dispatch("create", 1);
        intent(&j, &create);
        j.accept_fixture_lease_at(&create, || Ok(1000)).unwrap();
        assert_eq!(j.restore_base("lease-test"), None);
        let launch = |id: &str, generation: u64, revision: u64| {
            let mut d = dispatch(id, revision);
            d.kind = "sandbox.reconnect".into();
            d.generation = generation;
            d
        };
        let mut restore = launch("restore", 2, 2);
        restore.restore = Some(sandbox_protocol::DispatchRestoreV11 {
            offload_id: "off-1".into(),
            seq: 1,
            fingerprint: DISK.into(),
            cloud_init_instance_id: None,
        });
        restore.launch_mode = Some(sandbox_protocol::LaunchMode::NewRoot);
        intent(&j, &restore);
        assert_eq!(
            j.lookup("restore").unwrap().launch_mode,
            Some(sandbox_protocol::LaunchMode::NewRoot)
        );
        j.accept_fixture_lease_at(&restore, || Ok(1000)).unwrap();
        assert_eq!(j.restore_base("lease-test").as_deref(), Some(DISK));
        drop(j);
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        assert_eq!(
            j.restore_bases(),
            vec![("lease-test".to_string(), DISK.to_string())]
        );
        // A later cold reconnect naming a different base is refused.
        let mut forged = launch("forged", 3, 3);
        forged.disk_base_fingerprint = Some(OTHER.into());
        intent(&j, &forged);
        assert!(
            j.accept_fixture_lease_at(&forged, || Ok(1000))
                .unwrap_err()
                .to_string()
                .contains("restore base binding differs")
        );
        let mut cold = launch("cold", 3, 3);
        cold.disk_base_fingerprint = Some(DISK.into());
        intent(&j, &cold);
        j.accept_fixture_lease_at(&cold, || Ok(1000)).unwrap();
        let mut renew = dispatch("renew", 4);
        renew.generation = 3;
        intent(&j, &renew);
        j.accept_fixture_lease_at(&renew, || Ok(1000)).unwrap();
        assert_eq!(j.restore_base("lease-test").as_deref(), Some(DISK));
    }

    #[test]
    fn vm_size_survives_wal_repair_pruning_and_renewal() {
        for crash in [
            None,
            Some(CrashPoint::AfterLeaseDecision),
            Some(CrashPoint::BeforeLease),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let j =
                crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
            let mut d = dispatch("create", 1);
            d.cpu_count = Some(3);
            d.memory_mi_b = Some(3072);
            let size = sandbox_protocol::VmSize::new(3, 3072).unwrap();
            intent(&j, &d);
            assert_eq!(j.lookup("create").unwrap().vm_size, size);
            if let Some(point) = crash {
                j.inject_crash(point);
            }
            let accepted = j.accept_fixture_lease_at(&d, || Ok(1000));
            assert_eq!(accepted.is_err(), crash.is_some());
            drop(j);
            let j =
                crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
            if crash == Some(CrashPoint::BeforeLease) {
                assert!(j.lease("lease-test").is_none());
                continue;
            }
            assert_eq!(j.lease("lease-test").unwrap().vm_size, size);
            j.record_result("create", OperationState::Succeeded, None, None, None)
                .unwrap();
            crate::sandbox_relay::test_support::install_fixture_key(&j, &binding());
            let r = j.lookup("create").unwrap();
            assert!(
                j.confirm(
                    &binding(),
                    &ReceiptConfirmation {
                        sandbox_owner_id: r.sandbox_owner_id.clone(),
                        operation_id: r.operation_id,
                        sandbox_id: r.sandbox_id,
                        generation: r.generation,
                        attempt: r.attempt,
                        body_hash: d.body_hash.clone().unwrap(),
                        idempotency_key: r.idempotency_key,
                        kind: r.kind,
                        cleanup_generation: None,
                        retire_command: false,
                    }
                )
                .unwrap()
            );
            drop(j);
            let j =
                crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
            assert!(j.lookup("create").is_none());
            assert_eq!(j.lease("lease-test").unwrap().vm_size, size);
            let renew = dispatch("renew", 2);
            intent(&j, &renew);
            j.accept_fixture_lease_at(&renew, || Ok(2000)).unwrap();
            assert_eq!(j.lease("lease-test").unwrap().vm_size, size);
            let mut conflicting = dispatch("reconnect", 2);
            conflicting.kind = "sandbox.reconnect".into();
            conflicting.cpu_count = Some(3);
            conflicting.memory_mi_b = Some(4096);
            intent(&j, &conflicting);
            assert!(
                j.accept_fixture_lease_at(&conflicting, || Ok(2000))
                    .unwrap_err()
                    .to_string()
                    .contains("VM size differs")
            );
        }
    }

    fn privileged(mut d: OperationDispatch, sudo: bool, root: bool) -> OperationDispatch {
        d.guest_sudo = sudo.then_some(true);
        d.guest_root = root.then_some(true);
        d
    }

    fn reconnect(id: &str, revision: u64, sudo: bool, root: bool) -> OperationDispatch {
        let mut d = dispatch(id, revision);
        d.kind = "sandbox.reconnect".into();
        privileged(d, sudo, root)
    }

    #[test]
    fn guest_privilege_persists_rises_never_falls_and_is_carried_by_renewals() {
        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        let create = privileged(dispatch("create", 1), true, true);
        intent(&j, &create);
        j.accept_fixture_lease_at(&create, || Ok(1000)).unwrap();
        let row = j.lease("lease-test").unwrap();
        assert!(row.guest_sudo && row.guest_root);
        // Survives a reopen.
        drop(j);
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        let row = j.lease("lease-test").unwrap();
        assert!(row.guest_sudo && row.guest_root);
        // A renewal carries both; it may not carry the fields.
        let renew = dispatch("renew", 2);
        intent(&j, &renew);
        j.accept_fixture_lease_at(&renew, || Ok(2000)).unwrap();
        let row = j.lease("lease-test").unwrap();
        assert!(row.guest_sudo && row.guest_root);
        let carrying = privileged(dispatch("renew-3", 3), false, true);
        intent(&j, &carrying);
        assert!(
            j.accept_fixture_lease_at(&carrying, || Ok(2000))
                .unwrap_err()
                .to_string()
                .contains("only on create or reconnect")
        );
        // guest_sudo never changes; guest_root never falls.
        for (id, sudo, root, message) in [
            ("r-nosudo", false, true, "guest sudo binding differs"),
            ("r-noroot", true, false, "guest root binding differs"),
        ] {
            let d = reconnect(id, 4, sudo, root);
            intent(&j, &d);
            assert!(
                j.accept_fixture_lease_at(&d, || Ok(2000))
                    .unwrap_err()
                    .to_string()
                    .contains(message),
                "{id}"
            );
        }
        let same = reconnect("r-same", 4, true, true);
        intent(&j, &same);
        j.accept_fixture_lease_at(&same, || Ok(2000)).unwrap();
    }

    #[test]
    fn guest_root_rises_on_reconnect_from_an_old_record() {
        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        let create = dispatch("create", 1);
        intent(&j, &create);
        j.accept_fixture_lease_at(&create, || Ok(1000)).unwrap();
        // An old record (no fields) keeps its exact bytes.
        let row = j.lease("lease-test").unwrap();
        let value = serde_json::to_value(&row).unwrap();
        assert!(value.get("guestSudo").is_none() && value.get("guestRoot").is_none());
        assert!(!row.guest_sudo && !row.guest_root);
        let rise = reconnect("rise", 2, false, true);
        intent(&j, &rise);
        j.accept_fixture_lease_at(&rise, || Ok(2000)).unwrap();
        assert!(j.lease("lease-test").unwrap().guest_root);
        // A second rise is accepted (idempotent).
        let again = reconnect("again", 3, false, true);
        intent(&j, &again);
        j.accept_fixture_lease_at(&again, || Ok(2000)).unwrap();
        let fall = reconnect("fall", 4, false, false);
        intent(&j, &fall);
        assert!(j.accept_fixture_lease_at(&fall, || Ok(2000)).is_err());
        // Granting sudo later is a guest_sudo change: refused.
        let grant = reconnect("grant", 4, true, true);
        intent(&j, &grant);
        assert!(j.accept_fixture_lease_at(&grant, || Ok(2000)).is_err());
    }

    #[test]
    fn an_observational_reconnect_still_raises_guest_root_on_the_current_lease() {
        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        let create = dispatch("create", 1);
        intent(&j, &create);
        j.accept_fixture_lease_at(&create, || Ok(1000)).unwrap();
        // A renewal (revision 2) lands before a warm reconnect queued with
        // revision 1 that carries the backfilled rise.
        let renew = dispatch("renew", 2);
        intent(&j, &renew);
        j.accept_fixture_lease_at(&renew, || Ok(2000)).unwrap();
        let warm = reconnect("warm", 1, false, true);
        intent(&j, &warm);
        assert_eq!(
            j.accept_fixture_lease_at(&warm, || Ok(3000))
                .unwrap()
                .revision,
            2
        );
        let row = j.lease("lease-test").unwrap();
        assert!(row.guest_root, "the rise is applied to the current lease");
        assert_eq!(row.lease.revision, 2, "the observation keeps the renewal");
        drop(j);
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        assert!(j.lease("lease-test").unwrap().guest_root, "durable");
    }

    #[test]
    fn recovery_keeps_a_guest_root_rise_whose_lease_write_crashed() {
        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        let create = dispatch("create", 1);
        intent(&j, &create);
        j.accept_fixture_lease_at(&create, || Ok(1000)).unwrap();
        // Same generation and revision: only the flag rises. The receipt is
        // durable, the lease write is lost.
        let rise = reconnect("rise", 1, false, true);
        intent(&j, &rise);
        j.inject_crash(CrashPoint::AfterLeaseDecision);
        assert!(j.accept_fixture_lease_at(&rise, || Ok(2000)).is_err());
        drop(j);
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        assert!(
            j.lease("lease-test").unwrap().guest_root,
            "recovery max-merges the accepted receipt's rise"
        );
        // And a later fall is refused against the recovered record.
        let fall = reconnect("fall", 2, false, false);
        intent(&j, &fall);
        assert!(j.accept_fixture_lease_at(&fall, || Ok(3000)).is_err());
    }

    #[test]
    fn guest_sudo_requires_guest_root_and_never_rides_a_build() {
        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        let sudo_only = privileged(dispatch("sudo-only", 1), true, false);
        intent(&j, &sudo_only);
        assert!(
            j.accept_fixture_lease_at(&sudo_only, || Ok(1000))
                .unwrap_err()
                .to_string()
                .contains("without guest root")
        );
        // A frame cannot carry an explicit false.
        let mut value = serde_json::to_value(dispatch("x", 1)).unwrap();
        value["guestSudo"] = serde_json::json!(false);
        assert!(serde_json::from_value::<OperationDispatch>(value).is_err());
        let mut value = serde_json::to_value(dispatch("x", 1)).unwrap();
        value["guestSudoName"] = serde_json::json!("user");
        assert!(
            serde_json::from_value::<OperationDispatch>(value).is_err(),
            "no name field exists"
        );
    }

    #[test]
    fn default_vm_size_is_explicit_and_survives_reopening() {
        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        let d = dispatch("create", 1);
        intent(&j, &d);
        j.accept_fixture_lease_at(&d, || Ok(1000)).unwrap();
        let r = j.lookup("create").unwrap();
        let row = j.lease("lease-test").unwrap();
        for value in [
            serde_json::to_value(&r).unwrap(),
            serde_json::to_value(&row).unwrap(),
        ] {
            assert_eq!(
                value["vmSize"],
                serde_json::to_value(default_vm_size()).unwrap()
            );
        }
        drop(j);
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        assert_eq!(j.lookup("create").unwrap().vm_size, default_vm_size());
        assert_eq!(j.lease("lease-test").unwrap().vm_size, default_vm_size());
    }

    #[test]
    fn enforcement_loss_settlement_is_durable_and_never_a_deadline_expiry() {
        use sandbox_runtime::EnforcementLossStage::{Complete, Prepare};
        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        let create = dispatch("create", 1);
        intent(&j, &create);
        j.accept_fixture_lease_at(&create, || Ok(1000)).unwrap();
        let row = j.lease("lease-test").unwrap();
        assert!(j.settle_enforcement_loss(&row, Complete).is_err());
        let worker = j.lease_work(&create);
        assert!(j.settle_enforcement_loss(&row, Prepare).is_err());
        assert!(j.lease("lease-test").unwrap().enforcement_loss);
        assert!(j.settle_enforcement_loss(&row, Complete).is_err());
        assert!(!j.lease("lease-test").unwrap().expiry_complete);
        drop(worker);
        j.settle_enforcement_loss(&row, Prepare).unwrap();
        let pending = j.lease("lease-test").unwrap();
        assert!(pending.expired && pending.enforcement_loss);
        assert!(!pending.expiry_complete && !pending.timer_expired && !pending.instance_absent);
        drop(j);
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        assert_eq!(j.lease("lease-test").unwrap(), pending);
        j.settle_enforcement_loss(&row, Complete).unwrap();
        j.settle_enforcement_loss(&row, Complete).unwrap();
        let done = j.lease("lease-test").unwrap();
        assert!(done.expired && done.expiry_complete && done.instance_absent);
        assert!(!done.timer_expired);
        assert_eq!(
            done.lease, row.lease,
            "never manufacture a different server lease"
        );
        drop(j);
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        assert_eq!(j.lease("lease-test").unwrap(), done);
    }

    #[test]
    fn expiry_completion_matches_full_captured_authority() {
        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        let create = dispatch("create", 1);
        intent(&j, &create);
        j.accept_fixture_lease_at(&create, || Ok(1000)).unwrap();
        assert!(j.expire_lease("lease-test", 1, 1).unwrap());
        let current = j.lease("lease-test").unwrap();
        for field in ["generation", "lease", "binding", "template", "intent"] {
            let mut stale = current.clone();
            match field {
                "generation" => stale.generation += 1,
                "lease" => stale.lease.revision += 1,
                "binding" => stale.binding.host_owner_id.push_str("-other"),
                "template" => stale.template_fingerprint = Some("other".into()),
                "intent" => stale.enforcement_loss = true,
                _ => unreachable!(),
            }
            assert!(
                j.finish_expiry(&stale).is_err(),
                "{field} cannot settle another authority"
            );
            assert_eq!(j.lease("lease-test").unwrap(), current);
        }
        j.finish_expiry(&current).unwrap();
        let done = j.lease("lease-test").unwrap();
        assert!(
            done.expiry_complete && !done.instance_absent,
            "the exact ordinary stop intent still completes"
        );
    }

    #[test]
    fn stale_loss_prepare_classifies_every_authority_change_without_latching() {
        use sandbox_runtime::EnforcementLossStage::Prepare;
        for field in [
            "generation",
            "revision",
            "deadline",
            "action",
            "owner",
            "host",
            "server",
            "template",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let j =
                crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
            let create = dispatch("create", 1);
            intent(&j, &create);
            j.accept_fixture_lease_at(&create, || Ok(1000)).unwrap();
            let current = j.lease("lease-test").unwrap();
            let mut old = current.clone();
            match field {
                "generation" => old.generation += 1,
                "revision" => old.lease.revision += 1,
                "deadline" => old.lease.deadline_unix_ms += 1,
                "action" => old.lease.action = sandbox_protocol::LeaseAction::Destroy,
                "owner" => old.binding.host_owner_id.push_str("-other"),
                "host" => old.binding.host_id.push_str("-other"),
                "server" => old.binding.server.push_str("-other"),
                _ => old.template_fingerprint = Some("other".into()),
            }
            let err = j.settle_enforcement_loss(&old, Prepare).unwrap_err();
            assert!(err.is::<StaleEnforcementLossAuthority>(), "{field}: {err}");
            assert_eq!(j.lease("lease-test").unwrap(), current, "{field}");
            j.settle_enforcement_loss(&current, Prepare).unwrap();
            assert!(j.lease("lease-test").unwrap().enforcement_loss, "{field}");
        }
    }
    #[test]
    fn stale_enforcement_loss_cannot_latch_or_complete_a_newer_arm() {
        use sandbox_runtime::EnforcementLossStage::{Complete, Prepare};
        for new_generation in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let j =
                crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
            let create = dispatch("create", 1);
            intent(&j, &create);
            j.accept_fixture_lease_at(&create, || Ok(1000)).unwrap();
            let old = j.lease("lease-test").unwrap();
            let mut next = dispatch("next", 2);
            if new_generation {
                next.generation = 2;
                next.kind = "sandbox.reconnect".into();
            }
            intent(&j, &next);
            j.accept_fixture_lease_at(&next, || Ok(2000)).unwrap();
            let current = j.lease("lease-test").unwrap();
            for stage in [Prepare, Complete] {
                assert!(j.settle_enforcement_loss(&old, stage).is_err());
                assert_eq!(j.lease("lease-test").unwrap(), current);
            }
            // The exact current arm still works: no unconditional veto can
            // satisfy the stale inverse.
            j.settle_enforcement_loss(&current, Prepare).unwrap();
            j.settle_enforcement_loss(&current, Complete).unwrap();
            assert!(j.lease("lease-test").unwrap().instance_absent);
        }
    }
    #[test]
    fn lease_decision_survives_checkpoint_failure_and_replays_original_ack() {
        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        let create = dispatch("create", 1);
        intent(&j, &create);
        j.accept_fixture_lease_at(&create, || Ok(1000)).unwrap();
        let renew = dispatch("renew", 2);
        intent(&j, &renew);
        j.inject_crash(CrashPoint::AfterLeaseDecision);
        assert!(j.accept_fixture_lease_at(&renew, || Ok(2000)).is_err());
        assert!(j.io_failed());
        drop(j);
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        assert_eq!(j.lease("lease-test").unwrap().lease.revision, 2);
        let receipt = super::super::super::reconcile::resolve_receipt(
            &j,
            &sandbox_runtime::FakeRuntime::new(),
            j.lookup("renew").unwrap(),
        )
        .unwrap();
        assert_eq!(receipt.state, OperationState::Succeeded);
        let next = dispatch("next", 3);
        intent(&j, &next);
        j.accept_fixture_lease_at(&next, || Ok(3000)).unwrap();
        match j
            .record_intent(&intent_from_dispatch(&j, &binding(), &renew))
            .unwrap()
        {
            Decision::Replay(r) => assert_eq!(r.result.unwrap()["lease"]["revision"], 2),
            decision => panic!("expected original receipt, got {decision:?}"),
        }
        assert_eq!(j.lease("lease-test").unwrap().lease.revision, 3);
    }
    #[test]
    fn stale_repeated_and_expired_renewals_cannot_replace_or_restart_lease() {
        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        for revision in [1, 3] {
            let d = dispatch(&format!("op-{revision}"), revision);
            intent(&j, &d);
            j.accept_fixture_lease_at(&d, || Ok(1000)).unwrap();
        }
        let stale = dispatch("stale", 2);
        intent(&j, &stale);
        assert!(
            j.accept_fixture_lease_at(&stale, || Ok(2000))
                .unwrap_err()
                .to_string()
                .contains("stale")
        );
        let mut repeat = dispatch("repeat", 3);
        intent(&j, &repeat);
        assert_eq!(
            j.accept_fixture_lease_at(&repeat, || Ok(2000))
                .unwrap()
                .revision,
            3
        );
        repeat.operation_id = "conflict".into();
        repeat.idempotency_key = "conflict".into();
        repeat.lease.as_mut().unwrap().deadline_unix_ms += 1;
        intent(&j, &repeat);
        assert!(j.accept_fixture_lease_at(&repeat, || Ok(2000)).is_err());
        let next = dispatch("expired", 4);
        intent(&j, &next);
        assert!(
            j.accept_fixture_lease_at(&next, || Ok(103_000))
                .unwrap_err()
                .to_string()
                .contains("expiry won")
        );
        assert!(j.expire_lease("lease-test", 1, 3).unwrap());
        assert!(j.accept_fixture_lease_at(&next, || Ok(2000)).is_err());
        j.finish_expiry(&j.lease("lease-test").unwrap()).unwrap();
        let mut cold = dispatch("cold", 5);
        cold.kind = "sandbox.reconnect".into();
        cold.generation = 2;
        intent(&j, &cold);
        assert_eq!(
            j.accept_fixture_lease_at(&cold, || Ok(3000))
                .unwrap()
                .revision,
            5
        );
    }
    /// C31: a warm reconnect carries the lease captured when it was queued. If
    /// a renewal lands first, the reconnect must succeed as an observation of
    /// the healthy current lease — rejecting it maps a running sandbox to
    /// ERROR. Covers both delivery orders and a same-revision conflict.
    #[test]
    fn warm_reconnect_observes_a_renewed_lease_instead_of_failing() {
        for renewal_first in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let j =
                crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
            let create = dispatch("create", 1);
            intent(&j, &create);
            j.accept_fixture_lease_at(&create, || Ok(1000)).unwrap();
            let mut warm = dispatch("warm", 1);
            warm.kind = "sandbox.reconnect".into();
            intent(&j, &warm);
            let renew = dispatch("renew", 2);
            intent(&j, &renew);
            if renewal_first {
                j.accept_fixture_lease_at(&renew, || Ok(2000)).unwrap();
                let observed = j.accept_fixture_lease_at(&warm, || Ok(3000)).unwrap();
                assert_eq!(observed.revision, 2, "observes the renewed lease");
                assert_eq!(observed.deadline_unix_ms, 102_000);
            } else {
                assert_eq!(
                    j.accept_fixture_lease_at(&warm, || Ok(2000))
                        .unwrap()
                        .revision,
                    1
                );
                j.accept_fixture_lease_at(&renew, || Ok(3000)).unwrap();
            }
            let row = j.lease("lease-test").unwrap();
            assert_eq!(row.lease.revision, 2);
            assert!(!row.expired);
            // The reconnect receipt is bound to the immutable queued lease:
            // the server fences the ACK on exactly that tuple, including
            // recovered results. The effective observation is not stored.
            assert_eq!(j.lookup("warm").unwrap().lease.unwrap().lease.revision, 1);
            // A stale renewal still fails; only reconnects are observational.
            let stale = dispatch("stale", 1);
            intent(&j, &stale);
            assert!(j.accept_fixture_lease_at(&stale, || Ok(4000)).is_err());
            // Conflicting bodies at one revision are never acknowledgements.
            let mut conflict = dispatch("conflict-warm", 2);
            conflict.kind = "sandbox.reconnect".into();
            conflict.lease.as_mut().unwrap().deadline_unix_ms += 1;
            intent(&j, &conflict);
            assert!(j.accept_fixture_lease_at(&conflict, || Ok(4000)).is_err());
            assert_eq!(
                j.lease("lease-test").unwrap().lease.deadline_unix_ms,
                102_000
            );
            drop(j);
        }
    }
    #[test]
    fn connect_only_extends_but_relative_renewal_can_shorten_the_durable_lease() {
        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        let create = dispatch("create", 1);
        intent(&j, &create);
        j.accept_fixture_lease_at(&create, || Ok(1000)).unwrap();

        let mut short_connect = dispatch("short-connect", 2);
        short_connect.kind = "sandbox.reconnect".into();
        short_connect.lease.as_mut().unwrap().deadline_unix_ms = 50_000;
        intent(&j, &short_connect);
        assert!(
            j.accept_fixture_lease_at(&short_connect, || Ok(2000))
                .is_err()
        );
        assert_eq!(j.lease("lease-test").unwrap().lease.revision, 1);
        assert!(j.lookup("short-connect").unwrap().lease.is_none());

        let mut connect = dispatch("connect", 2);
        connect.kind = "sandbox.reconnect".into();
        intent(&j, &connect);
        let extended = j.accept_fixture_lease_at(&connect, || Ok(2000)).unwrap();
        assert_eq!(extended.deadline_unix_ms, 102_000);

        let mut shorten = dispatch("shorten", 3);
        shorten.lease.as_mut().unwrap().deadline_unix_ms = 50_000;
        intent(&j, &shorten);
        let shortened = j.accept_fixture_lease_at(&shorten, || Ok(3000)).unwrap();
        assert_eq!(shortened.deadline_unix_ms, 50_000);

        // A later shortening cannot strand a previously queued warm intent.
        // Its exact receipt keeps the queued tuple, while runtime enforcement
        // and the checkpoint keep the current shorter lease.
        connect.operation_id = "delayed-connect".into();
        connect.idempotency_key = "delayed-connect".into();
        intent(&j, &connect);
        assert_eq!(
            j.accept_fixture_lease_at(&connect, || Ok(4000)).unwrap(),
            shortened
        );
        assert_eq!(j.lease("lease-test").unwrap().lease, shortened);
        assert_eq!(
            j.lookup("delayed-connect").unwrap().lease.unwrap().lease,
            extended
        );

        let late = dispatch("late-extension", 4);
        intent(&j, &late);
        assert!(j.accept_fixture_lease_at(&late, || Ok(50_000)).is_err());
        assert_eq!(j.lease("lease-test").unwrap().lease, shortened);
    }

    /// M7: a READY-based lease is create-only; the ceiling checks the
    /// relative timeout (not the provisional backstop); at READY the stored
    /// deadline becomes readyAt + timeout, capped by the backstop, and the
    /// settled ACK echoes `fromReadyMs`. Ordinary leases keep their bytes.
    #[test]
    fn ready_based_lease_is_checked_on_its_timeout_and_settles_at_ready() {
        const H: u64 = 3_600_000;
        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        j.set_lease_ceiling(Some(6 * H));
        let now = j.clock.now_ms().unwrap();
        let ready_based = |id: &str, timeout: u64| {
            let mut d = dispatch(id, 1);
            let lease = d.lease.as_mut().unwrap();
            // Provisional: acceptance + timeout + a 2 h provisioning backstop.
            lease.deadline_unix_ms = now + timeout + 2 * H;
            lease.from_ready_ms = Some(timeout);
            d
        };
        // Backstop past the ceiling, timeout within it: admitted.
        let create = ready_based("ready-create", 6 * H);
        intent(&j, &create);
        let stored = j.accept_fixture_lease_at(&create, || Ok(now)).unwrap();
        assert_eq!(
            stored.deadline_unix_ms,
            now + 8 * H,
            "provisional until READY"
        );
        // The pending backstop is not reported as over the ceiling.
        assert_eq!(j.leases_over_ceiling(now, Some(6 * H)), 0);
        let settled = j.settle_ready_lease(&create).unwrap().unwrap();
        let after = j.clock.now_ms().unwrap();
        assert!(
            settled.deadline_unix_ms >= now + 6 * H && settled.deadline_unix_ms <= after + 6 * H
        );
        assert_eq!(settled.from_ready_ms, Some(6 * H));
        assert_eq!(
            j.lease("lease-test").unwrap().lease.deadline_unix_ms,
            settled.deadline_unix_ms
        );
        // Settling again never moves the deadline later.
        let again = j.settle_ready_lease(&create).unwrap().unwrap();
        assert!(again.deadline_unix_ms <= settled.deadline_unix_ms);

        // A timeout over the ceiling is refused even with a near backstop.
        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        j.set_lease_ceiling(Some(6 * H));
        let over = ready_based("ready-over", 7 * H);
        intent(&j, &over);
        assert!(ceiling_refused(
            j.accept_fixture_lease_at(&over, || Ok(now))
        ));

        // Only a create may carry it.
        let mut renew = dispatch("ready-renew", 2);
        renew.lease.as_mut().unwrap().from_ready_ms = Some(H);
        intent(&j, &renew);
        assert!(j.accept_fixture_lease_at(&renew, || Ok(now)).is_err());

        // Ordinary leases serialize exactly as before (journal checksums unchanged).
        let plain = dispatch("plain", 1);
        assert!(
            !serde_json::to_string(&plain.lease)
                .unwrap()
                .contains("fromReadyMs")
        );
        assert!(j.settle_ready_lease(&plain).unwrap().is_none());
    }

    fn ceiling_refused(result: Result<HostLease>) -> bool {
        result.is_err_and(|e| e.downcast_ref::<LeaseCeilingExceeded>().is_some())
    }

    /// M1/M5: the host lease ceiling is enforced only on a dispatched lease
    /// that will be stored. Shortenings, pull-ins, observations and a re-arm
    /// that keeps the current deadline pass; the far-future deadline needs an
    /// unlimited ceiling; arithmetic never overflows.
    #[test]
    fn host_ceiling_applies_only_to_stored_leases() {
        const H: u64 = 3_600_000;
        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        // Default before the daemon sets the configured value: 24 hours.
        assert_eq!(j.lease_ceiling(), Some(86_400_000));
        let now = 1_000;
        let lease_at = |d: &mut OperationDispatch, deadline: u64| {
            d.lease.as_mut().unwrap().deadline_unix_ms = deadline;
        };
        let mut over = dispatch("over-default", 1);
        lease_at(&mut over, now + 24 * H + LEASE_CEILING_SKEW_MS + 1);
        intent(&j, &over);
        assert!(ceiling_refused(
            j.accept_fixture_lease_at(&over, || Ok(now))
        ));
        assert!(j.lease("lease-test").is_none(), "nothing stored");

        j.set_lease_ceiling(Some(6 * H));
        let mut create = dispatch("create", 1);
        lease_at(&mut create, now + 6 * H);
        intent(&j, &create);
        j.accept_fixture_lease_at(&create, || Ok(now)).unwrap();
        // The skew allowance admits a server clock up to a minute ahead.
        let mut skewed = dispatch("skewed", 2);
        lease_at(&mut skewed, now + 6 * H + LEASE_CEILING_SKEW_MS);
        intent(&j, &skewed);
        j.accept_fixture_lease_at(&skewed, || Ok(now)).unwrap();

        // The ceiling drops locally; existing leases stay until pulled in.
        j.set_lease_ceiling(Some(H));
        assert_eq!(j.leases_over_ceiling(now, Some(H)), 1);
        let mut extend = dispatch("extend", 3);
        lease_at(&mut extend, now + 6 * H + LEASE_CEILING_SKEW_MS + 1);
        intent(&j, &extend);
        assert!(ceiling_refused(
            j.accept_fixture_lease_at(&extend, || Ok(now))
        ));
        // M1: a warm re-arm carrying the current (effective) deadline passes.
        let mut rearm = dispatch("rearm", 3);
        rearm.kind = "sandbox.reconnect".into();
        lease_at(&mut rearm, now + 6 * H + LEASE_CEILING_SKEW_MS);
        intent(&j, &rearm);
        j.accept_fixture_lease_at(&rearm, || Ok(now)).unwrap();
        // The server's pull-in shortens: always admitted.
        let mut pull_in = dispatch("lease-policy-pull-in", 4);
        lease_at(&mut pull_in, now + H);
        intent(&j, &pull_in);
        j.accept_fixture_lease_at(&pull_in, || Ok(now)).unwrap();
        assert_eq!(j.leases_over_ceiling(now, Some(H)), 0);
        // M1: a queued older reconnect is an observation, even over the ceiling.
        let mut queued = dispatch("queued-connect", 2);
        queued.kind = "sandbox.reconnect".into();
        lease_at(&mut queued, now + 6 * H + LEASE_CEILING_SKEW_MS);
        intent(&j, &queued);
        let observed = j.accept_fixture_lease_at(&queued, || Ok(now)).unwrap();
        assert_eq!(observed.revision, 4, "the healthy current lease");
        // An identical replay of the stored revision is not re-checked.
        assert_eq!(
            j.accept_fixture_lease_at(&pull_in, || Ok(now))
                .unwrap()
                .revision,
            4
        );
        // The far-future deadline is refused under any finite ceiling.
        let mut forever = dispatch("forever", 5);
        lease_at(&mut forever, sandbox_protocol::LEASE_UNLIMITED_DEADLINE_MS);
        intent(&j, &forever);
        assert!(ceiling_refused(
            j.accept_fixture_lease_at(&forever, || Ok(now))
        ));
        // M5: an unlimited ceiling admits it, with no overflow anywhere.
        j.set_lease_ceiling(None);
        j.accept_fixture_lease_at(&forever, || Ok(now)).unwrap();
        assert_eq!(j.leases_over_ceiling(u64::MAX, None), 0);
        assert!(lease_within_ceiling(u64::MAX, 0, u64::MAX, Some(u64::MAX)));
        assert!(!lease_within_ceiling(u64::MAX, 0, 0, Some(H)));
        assert!(lease_within_ceiling(u64::MAX, u64::MAX, 0, Some(H)));
    }

    /// relay-drop integration: a pull-in the host never received is requeued
    /// by the server's dispatch audit and arrives as a fresh attempt 2. It
    /// keeps its shorten-only flag, so under a lowered ceiling it still passes
    /// as a shortening, while an unflagged renewal to the same deadline is
    /// refused by the ceiling.
    #[test]
    fn requeued_pull_in_keeps_its_shorten_only_flag_under_the_ceiling() {
        const H: u64 = 3_600_000;
        let now = 1_000;
        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        j.set_lease_ceiling(Some(6 * H));
        let mut create = dispatch("create", 1);
        create.lease.as_mut().unwrap().deadline_unix_ms = now + 6 * H;
        intent(&j, &create);
        j.accept_fixture_lease_at(&create, || Ok(now)).unwrap();
        j.set_lease_ceiling(Some(H));
        let mut requeued = dispatch("lease-policy-requeued", 2);
        requeued.attempt = 2;
        let lease = requeued.lease.as_mut().unwrap();
        lease.deadline_unix_ms = now + H;
        lease.shorten_only = true;
        let wire = serde_json::to_value(&requeued).unwrap();
        assert_eq!(
            wire["lease"]["shortenOnly"], true,
            "the flag survives the wire"
        );
        let requeued: OperationDispatch = serde_json::from_value(wire).unwrap();
        intent(&j, &requeued);
        let stored = j.accept_fixture_lease_at(&requeued, || Ok(now)).unwrap();
        assert_eq!(stored.deadline_unix_ms, now + H);
        assert_eq!(j.leases_over_ceiling(now, Some(H)), 0);
        // An unflagged renewal past the lowered ceiling is still refused.
        let mut extend = dispatch("extend", 3);
        extend.lease.as_mut().unwrap().deadline_unix_ms = now + 2 * H;
        intent(&j, &extend);
        assert!(ceiling_refused(
            j.accept_fixture_lease_at(&extend, || Ok(now))
        ));
    }

    /// A shorten-only system renewal never moves the
    /// host's deadline later, even when the server's acknowledged view lags a
    /// shorter lease the host already installed and a newer extension is
    /// queued; it keeps its revision, so it still supersedes that extension.
    #[test]
    fn shorten_only_renewal_never_extends_the_stored_deadline() {
        const H: u64 = 3_600_000;
        let now = 1_000;
        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        j.set_lease_ceiling(None);
        let at = |d: &mut OperationDispatch, deadline: u64, shorten_only: bool| {
            let lease = d.lease.as_mut().unwrap();
            lease.deadline_unix_ms = deadline;
            lease.shorten_only = shorten_only;
        };
        let mut create = dispatch("create", 1);
        at(&mut create, now + 20 * H, false);
        intent(&j, &create);
        j.accept_fixture_lease_at(&create, || Ok(now)).unwrap();
        // The user's shortening is installed; its ACK has not reached the server.
        let mut shorten = dispatch("shorten", 2);
        at(&mut shorten, now + H / 6, false);
        intent(&j, &shorten);
        j.accept_fixture_lease_at(&shorten, || Ok(now)).unwrap();
        // The server, still believing 20h, created a 6h extension (r3) and then
        // a system pull-in to 1h (r4). The pull-in arrives first.
        let mut extension = dispatch("extension", 3);
        at(&mut extension, now + 6 * H, false);
        let mut pull_in = dispatch("lease-policy-pull-in", 4);
        at(&mut pull_in, now + H, true);
        intent(&j, &extension);
        intent(&j, &pull_in);
        let effective = j.accept_fixture_lease_at(&pull_in, || Ok(now)).unwrap();
        assert_eq!(
            effective.deadline_unix_ms,
            now + H / 6,
            "clamped, not extended"
        );
        let stored = j.lease("lease-test").unwrap().lease;
        assert_eq!((stored.revision, stored.deadline_unix_ms), (4, now + H / 6));
        // The receipt keeps the queued lease for the server's ACK fence.
        assert_eq!(
            j.lookup("lease-policy-pull-in")
                .unwrap()
                .lease
                .unwrap()
                .lease
                .deadline_unix_ms,
            now + H
        );
        // A replay of the same pull-in is idempotent, not a conflict.
        assert_eq!(
            j.accept_fixture_lease_at(&pull_in, || Ok(now)).unwrap(),
            effective
        );
        // The superseded extension can no longer extend anything.
        assert!(j.accept_fixture_lease_at(&extension, || Ok(now)).is_err());
        assert_eq!(
            j.lease("lease-test").unwrap().lease.deadline_unix_ms,
            now + H / 6
        );
        // A shorter shorten-only lease does shorten.
        let mut tighter = dispatch("lease-policy-tighter", 5);
        at(&mut tighter, now + H / 12, true);
        intent(&j, &tighter);
        assert_eq!(
            j.accept_fixture_lease_at(&tighter, || Ok(now))
                .unwrap()
                .deadline_unix_ms,
            now + H / 12
        );
        // A shorten-only flag is never valid outside a renewal.
        let mut bad = dispatch("bad-reconnect", 6);
        bad.kind = "sandbox.reconnect".into();
        at(&mut bad, now + H / 12, true);
        intent(&j, &bad);
        assert!(j.accept_fixture_lease_at(&bad, || Ok(now)).is_err());
        // Reopen: the durable record keeps the clamp.
        drop(j);
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        assert_eq!(
            j.lease("lease-test").unwrap().lease.deadline_unix_ms,
            now + H / 12
        );
    }

    /// N1 (T5 on the host): the warm reconnect re-armed to the effective
    /// deadline (r+1) and the server's inline pull-in (r+2) are accepted in
    /// either arrival order under a ceiling the pull-in respects, and the
    /// stored lease always ends as the short pull-in.
    #[test]
    fn rearm_and_pull_in_are_accepted_in_both_arrival_orders() {
        const H: u64 = 3_600_000;
        let now = 1_000;
        for pull_in_first in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let j =
                crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
            let mut create = dispatch("create", 1);
            create.lease.as_mut().unwrap().deadline_unix_ms = now + 20 * H;
            intent(&j, &create);
            j.accept_fixture_lease_at(&create, || Ok(now)).unwrap();
            // The host's ceiling dropped to 2h; the server re-arms and pulls in.
            j.set_lease_ceiling(Some(2 * H));
            let mut rearm = dispatch("rearm", 2);
            rearm.kind = "sandbox.reconnect".into();
            rearm.lease.as_mut().unwrap().deadline_unix_ms = now + 20 * H;
            let mut pull_in = dispatch("pull-in", 3);
            pull_in.lease.as_mut().unwrap().deadline_unix_ms = now + 2 * H;
            intent(&j, &rearm);
            intent(&j, &pull_in);
            if pull_in_first {
                j.accept_fixture_lease_at(&pull_in, || Ok(now)).unwrap();
                // The overtaken reconnect is an observation of the short lease.
                let observed = j.accept_fixture_lease_at(&rearm, || Ok(now)).unwrap();
                assert_eq!(observed.revision, 3);
            } else {
                j.accept_fixture_lease_at(&rearm, || Ok(now)).unwrap();
                j.accept_fixture_lease_at(&pull_in, || Ok(now)).unwrap();
            }
            let stored = j.lease("lease-test").unwrap().lease;
            assert_eq!((stored.revision, stored.deadline_unix_ms), (3, now + 2 * H));
        }
    }

    /// CLI logins (§10.3): a refused user stop at generation 2 re-binds the
    /// live lease row, so ordinary work at 2 is admitted; idempotent,
    /// durable across reopen, and never touches an expired or newer row.
    #[test]
    fn refused_teardown_rebinds_the_live_lease_row_to_the_stop_generation() {
        use std::sync::atomic::{AtomicU64, Ordering};
        #[derive(Debug)]
        struct Clock(AtomicU64);
        impl crate::sandbox_relay::clock::ClockSource for Clock {
            fn sample(&self) -> Result<(u64, u64)> {
                Ok((self.0.load(Ordering::SeqCst), 0))
            }
        }
        let pinned = || {
            std::sync::Arc::new(crate::sandbox_relay::clock::LeaseClock::new(
                std::sync::Arc::new(Clock(AtomicU64::new(2000))),
            ))
        };
        let dir = tempfile::tempdir().unwrap();
        let mut j =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        let create = dispatch("create", 1);
        intent(&j, &create);
        j.accept_fixture_lease_at(&create, || Ok(1000)).unwrap();
        j.clock = pinned();
        assert!(j.work_allowed("lease-test", 1, "command.run"));
        // The stop at generation 2 failed: work at 2 is refused until re-bound.
        assert!(!j.work_allowed("lease-test", 2, "command.run"));
        assert!(j.rebind_after_refused_teardown("lease-test", 2).unwrap());
        assert!(j.work_allowed("lease-test", 2, "command.run"));
        assert!(!j.work_allowed("lease-test", 1, "command.run"));
        let row = j.lease("lease-test").unwrap();
        assert_eq!((row.generation, row.lease.revision), (2, 1));
        // Replays are no-ops; older generations never move it back.
        assert!(!j.rebind_after_refused_teardown("lease-test", 2).unwrap());
        assert!(!j.rebind_after_refused_teardown("lease-test", 1).unwrap());
        assert!(!j.rebind_after_refused_teardown("missing", 2).unwrap());
        drop(j);
        let mut j =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        j.clock = pinned();
        assert_eq!(j.lease("lease-test").unwrap().generation, 2);
        assert!(j.work_allowed("lease-test", 2, "command.run"));
        // An expired row is never re-bound.
        assert!(
            j.expire_lease_at("lease-test", 2, 1, || Ok(200_000))
                .unwrap()
        );
        assert!(!j.rebind_after_refused_teardown("lease-test", 3).unwrap());
        assert_eq!(j.lease("lease-test").unwrap().generation, 2);
    }

    /// A queued revision-1 reconnect delivered after revision 1's deadline but
    /// before the renewed revision-2 deadline is an observation of the healthy
    /// current lease: admission validates the current lease, returns it as the
    /// effective lease for runtime work, and still binds the receipt to the
    /// immutable queued lease the server's ACK fence requires.
    #[test]
    fn warm_reconnect_after_the_queued_deadline_observes_the_renewal() {
        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        let create = dispatch("create", 1);
        intent(&j, &create);
        j.accept_fixture_lease_at(&create, || Ok(1000)).unwrap();
        let renew = dispatch("renew", 2);
        intent(&j, &renew);
        j.accept_fixture_lease_at(&renew, || Ok(2000)).unwrap();
        let mut warm = dispatch("warm", 1);
        warm.kind = "sandbox.reconnect".into();
        intent(&j, &warm);
        // Revision 1's deadline (101_000) has passed; revision 2's (102_000)
        // has not. The queued lease alone no longer validates.
        let observed = j.accept_fixture_lease_at(&warm, || Ok(101_500)).unwrap();
        assert_eq!(observed.revision, 2, "effective lease is the renewal");
        assert_eq!(observed.deadline_unix_ms, 102_000);
        assert_eq!(
            j.lookup("warm").unwrap().lease.unwrap().lease.revision,
            1,
            "receipt keeps the immutable queued lease for the ACK"
        );
        let row = j.lease("lease-test").unwrap();
        assert_eq!(row.lease.revision, 2);
        assert!(!row.expired);
        // A renew may not ride the observation path: stale revisions still fail.
        let stale = dispatch("stale", 1);
        intent(&j, &stale);
        assert!(j.accept_fixture_lease_at(&stale, || Ok(101_600)).is_err());
    }
    /// C32: a new-generation reconnect must not bypass a lease whose deadline
    /// lapsed before the timer latched it. Destroy rearm is rejected even when
    /// complete; stop rearm waits for completed cleanup.
    #[test]
    fn new_generation_reconnect_cannot_bypass_an_overdue_lease() {
        use std::sync::atomic::{AtomicU64, Ordering};
        #[derive(Debug)]
        struct Clock(AtomicU64);
        impl crate::sandbox_relay::clock::ClockSource for Clock {
            fn sample(&self) -> Result<(u64, u64)> {
                Ok((self.0.load(Ordering::SeqCst), 0))
            }
        }
        for action in ["destroy", "stop"] {
            let dir = tempfile::tempdir().unwrap();
            let mut j =
                crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
            let create: OperationDispatch = serde_json::from_value(serde_json::json!({"sandboxOwnerId":"owner",
                "operationId": "create", "sandboxId": "lease-test", "generation": 1, "attempt": 1,
                "kind": "sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(), "idempotencyKey": "create", "bodyHash": "a".repeat(64),
                "lease": { "revision": 1, "deadlineUnixMs": 101_000, "action": action, "expiryPolicy": "retry-force-60s" } })).unwrap();
            intent(&j, &create);
            j.accept_fixture_lease_at(&create, || Ok(1000)).unwrap();
            // The deadline has lapsed but no timer tick has latched `expired`.
            // The reconnect's own lease lives on the test timeline; the journal
            // clock is pinned for the `work_allowed` assertions.
            let reconnect: OperationDispatch = serde_json::from_value(serde_json::json!({"sandboxOwnerId":"owner",
                "operationId": "reconnect", "sandboxId": "lease-test", "generation": 2, "attempt": 1,
                "kind": "sandbox.reconnect", "allocation": crate::sandbox_relay::test_support::allocation(), "idempotencyKey": "reconnect", "bodyHash": "b".repeat(64),
                "lease": { "revision": 2, "deadlineUnixMs": 200_000, "action": action, "expiryPolicy": "retry-force-60s" } })).unwrap();
            intent(&j, &reconnect);
            assert!(
                j.accept_fixture_lease_at(&reconnect, || Ok(102_000))
                    .is_err(),
                "{action}: overdue lease bypassed before expiry latch"
            );
            j.clock = std::sync::Arc::new(crate::sandbox_relay::clock::LeaseClock::new(
                std::sync::Arc::new(Clock(AtomicU64::new(102_000))),
            ));
            assert!(
                !j.work_allowed("lease-test", 2, "sandbox.reconnect"),
                "{action}: work_allowed bypassed the lapsed deadline"
            );
            assert!(
                j.expire_lease_at("lease-test", 1, 1, || Ok(102_000))
                    .unwrap()
            );
            j.finish_expiry(&j.lease("lease-test").unwrap()).unwrap();
            let accepted = j.accept_fixture_lease_at(&reconnect, || Ok(103_000));
            j.clock = std::sync::Arc::new(crate::sandbox_relay::clock::LeaseClock::new(
                std::sync::Arc::new(Clock(AtomicU64::new(104_000))),
            ));
            if action == "stop" {
                assert!(accepted.is_ok(), "completed stop cleanup may rearm");
                assert!(j.work_allowed("lease-test", 2, "sandbox.reconnect"));
            } else {
                assert!(accepted.is_err(), "destroy rearm stays rejected");
                assert!(!j.work_allowed("lease-test", 2, "sandbox.reconnect"));
            }
            drop(j);
        }
    }
    #[test]
    fn renewal_and_expiry_serialize_and_checkpoint_survives_confirmation() {
        use std::sync::{Arc, mpsc};
        let dir = tempfile::tempdir().unwrap();
        let j = Arc::new(
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap(),
        );
        let d = dispatch("create", 1);
        intent(&j, &d);
        j.accept_fixture_lease_at(&d, || Ok(1000)).unwrap();
        let renew = dispatch("renew", 2);
        intent(&j, &renew);
        let (locked_tx, locked_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker = j.clone();
        let d = renew.clone();
        let renewing = std::thread::spawn(move || {
            worker.accept_fixture_lease_at(&d, || {
                locked_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(100_999)
            })
        });
        locked_rx.recv().unwrap();
        let worker = j.clone();
        let (attempt_tx, attempt_rx) = mpsc::channel();
        let expiring = std::thread::spawn(move || {
            attempt_tx.send(()).unwrap();
            worker.expire_lease_at("lease-test", 1, 1, || Ok(101_000))
        });
        attempt_rx.recv().unwrap();
        release_tx.send(()).unwrap();
        renewing.join().unwrap().unwrap();
        assert!(!expiring.join().unwrap().unwrap());
        j.record_result(
            "renew",
            OperationState::Succeeded,
            Some(serde_json::json!({"lease": renew.lease})),
            None,
            None,
        )
        .unwrap();
        assert!(
            j.confirm(
                &binding(),
                &ReceiptConfirmation {
                    sandbox_owner_id: "owner".into(),
                    operation_id: "renew".into(),
                    sandbox_id: "lease-test".into(),
                    generation: 1,
                    attempt: 1,
                    body_hash: renew.body_hash.unwrap(),
                    idempotency_key: "renew".into(),
                    kind: "sandbox.lease.renew".into(),
                    cleanup_generation: None,
                    retire_command: false,
                }
            )
            .unwrap()
        );
        drop(j);
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        assert!(j.lookup("renew").is_none());
        assert_eq!(j.lease("lease-test").unwrap().lease.revision, 2);
        assert!(
            j.expire_lease_at("lease-test", 1, 2, || Ok(102_000))
                .unwrap()
        );
        let newer = dispatch("newer", 3);
        intent(&j, &newer);
        assert!(
            j.accept_fixture_lease_at(&newer, || Ok(102_000))
                .unwrap_err()
                .to_string()
                .contains("expiry won")
        );
    }
    #[test]
    fn renewal_contends_with_timer_poll_and_expiry_blocks_renewal() {
        use std::sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
            mpsc,
        };
        #[derive(Debug)]
        struct Clock(AtomicU64);
        impl crate::sandbox_relay::clock::ClockSource for Clock {
            fn sample(&self) -> Result<(u64, u64)> {
                Ok((self.0.load(Ordering::SeqCst), 0))
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let mut j =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        let clock = Arc::new(Clock(AtomicU64::new(101_000)));
        j.clock = Arc::new(crate::sandbox_relay::clock::LeaseClock::new(clock.clone()));
        let j = Arc::new(j);
        let create = dispatch("create", 1);
        intent(&j, &create);
        j.accept_fixture_lease_at(&create, || Ok(1000)).unwrap();
        let renew = dispatch("renew", 2);
        intent(&j, &renew);
        let (locked_tx, locked_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker = j.clone();
        let renewing = std::thread::spawn(move || {
            worker.accept_fixture_lease_at(&renew, || {
                locked_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(100_999)
            })
        });
        locked_rx.recv().unwrap();
        let (attempt_tx, attempt_rx) = mpsc::channel();
        let worker = j.clone();
        let timer = std::thread::spawn(move || {
            attempt_tx.send(()).unwrap();
            worker.poll_expiry()
        });
        attempt_rx.recv().unwrap();
        release_tx.send(()).unwrap();
        renewing.join().unwrap().unwrap();
        assert!(timer.join().unwrap().unwrap().is_empty());
        assert_eq!(j.lease("lease-test").unwrap().lease.revision, 2);
        clock.0.store(102_000, Ordering::SeqCst);
        assert_eq!(j.poll_expiry().unwrap().len(), 1);
        let late = dispatch("late", 3);
        intent(&j, &late);
        assert!(
            j.accept_fixture_lease(&late)
                .unwrap_err()
                .to_string()
                .contains("expiry won")
        );
    }
    /// Only the deadline timer marks a latch as timer expiry. A record written
    /// before the flag existed still verifies and loads.
    fn teardown(j: &HostJournal, kind: &str, generation: u64, state: &str) {
        let d: OperationDispatch = serde_json::from_value(serde_json::json!({
            "sandboxOwnerId":"owner", "operationId": format!("{}-{generation}", &kind[8..]),
            "sandboxId": "lease-test", "generation": generation, "attempt": 1, "kind": kind,
            "idempotencyKey": format!("{kind}-{generation}"), "bodyHash": "a".repeat(64),
            "allocation": crate::sandbox_relay::test_support::allocation()}))
        .unwrap();
        j.record_fixture_intent(&intent_from_dispatch(j, &binding(), &d))
            .unwrap();
        j.record_result(
            &d.operation_id,
            OperationState::Succeeded,
            Some(serde_json::json!({ "state": state })),
            None,
            None,
        )
        .unwrap();
    }
    /// B1: a STOPPED capture runs under the host's durable confirmed stop at
    /// or after its generation; every other kind keeps the live-lease fence.
    #[test]
    fn stopped_capture_authority_is_the_durable_confirmed_stop() {
        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        let create = dispatch("create", 1);
        intent(&j, &create);
        j.accept_fixture_lease_at(&create, || Ok(1000)).unwrap();
        // Before any stop: no evidence for a newer generation.
        assert_eq!(
            j.work_refusal("lease-test", 2, "sandbox.capture"),
            Some("stopped_capture_no_stop_evidence")
        );
        teardown(&j, "sandbox.stop", 2, "stopped");
        let row = j.lease("lease-test").unwrap();
        assert_eq!(row.stopped_generation, Some(2));
        assert!(row.expired && row.expiry_complete && !row.instance_absent);
        drop(j);
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        assert_eq!(j.work_refusal("lease-test", 2, "sandbox.capture"), None);
        assert_eq!(
            j.work_refusal("lease-test", 1, "sandbox.capture"),
            Some("stopped_capture_stale_generation")
        );
        // The fence for every other kind is unchanged.
        for kind in ["command.run", "file.put", "terminal.open", "sandbox.probe"] {
            assert_eq!(
                j.work_refusal("lease-test", 2, kind),
                Some("generation_mismatch"),
                "{kind}"
            );
        }
        // Deletion evidence ends the stop's authority.
        teardown(&j, "sandbox.kill", 3, "deleted");
        assert_eq!(
            j.work_refusal("lease-test", 3, "sandbox.capture"),
            Some("stopped_capture_instance_absent")
        );
        // A `stopped` result is required: an absent instance is no evidence.
        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        intent(&j, &create);
        j.accept_fixture_lease_at(&create, || Ok(1000)).unwrap();
        teardown(&j, "sandbox.stop", 2, "absent");
        assert_eq!(j.lease("lease-test").unwrap().stopped_generation, None);
        // A failed lease checkpoint refuses everything but teardown.
        j.io.trip();
        assert_eq!(
            j.work_refusal("lease-test", 2, "sandbox.capture"),
            Some("journal_io_failed")
        );
    }
    /// B11: a template-build VM (destroy lease, journaled build binding) is
    /// stopped by the build and then captured STOPPED. Its stop records
    /// evidence without retiring the destroy lease, so the capture runs under
    /// that stop until the re-anchored lease deadline, and the build binding
    /// survives the stop.
    #[test]
    fn build_vm_stopped_capture_runs_under_its_stop_until_the_lease_deadline() {
        use std::sync::atomic::{AtomicU64, Ordering};
        #[derive(Debug)]
        struct Clock(AtomicU64);
        impl crate::sandbox_relay::clock::ClockSource for Clock {
            fn sample(&self) -> Result<(u64, u64)> {
                Ok((self.0.load(Ordering::SeqCst), 0))
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let mut j =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        let create: OperationDispatch = serde_json::from_value(serde_json::json!({"sandboxOwnerId":"owner",
            "operationId": "create", "sandboxId": "lease-test", "generation": 1, "attempt": 1,
            "kind": "sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(),
            "idempotencyKey": "create", "bodyHash": "a".repeat(64), "build": {"buildId": "build-1"},
            "lease": { "revision": 1, "deadlineUnixMs": 101_000, "action": "destroy", "expiryPolicy": "retry-force-60s" } })).unwrap();
        intent(&j, &create);
        j.accept_fixture_lease_at(&create, || Ok(1000)).unwrap();
        j.clock = std::sync::Arc::new(crate::sandbox_relay::clock::LeaseClock::new(
            std::sync::Arc::new(Clock(AtomicU64::new(2000))),
        ));
        teardown(&j, "sandbox.stop", 2, "stopped");
        let row = j.lease("lease-test").unwrap();
        assert_eq!(row.stopped_generation, Some(2));
        assert_eq!(row.build_id.as_deref(), Some("build-1"));
        assert!(!row.expired && !row.instance_absent);
        assert_eq!(j.work_refusal("lease-test", 2, "sandbox.capture"), None);
        assert_eq!(j.work_refusal("lease-test", 3, "sandbox.capture"), None);
        assert_eq!(
            j.work_refusal("lease-test", 2, "command.run"),
            Some("generation_mismatch")
        );
        // The destroy lease keeps its deadline: the stop is authority only
        // until then.
        j.clock = std::sync::Arc::new(crate::sandbox_relay::clock::LeaseClock::new(
            std::sync::Arc::new(Clock(AtomicU64::new(101_000))),
        ));
        assert_eq!(
            j.work_refusal("lease-test", 2, "sandbox.capture"),
            Some("lease_deadline_passed")
        );
    }
    #[test]
    fn timer_latch_is_distinguished_from_explicit_teardown_and_old_records_load() {
        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        let create = dispatch("create", 1);
        intent(&j, &create);
        j.accept_fixture_lease_at(&create, || Ok(1000)).unwrap();
        let mut row = j.lease("lease-test").unwrap();
        assert!(!row.timer_expired);
        let legacy = serde_json::to_value(&row).unwrap();
        assert!(legacy.get("timerExpired").is_none());
        j.retire_inactive_lease(&row, false).unwrap();
        row = j.lease("lease-test").unwrap();
        assert!(row.expired && !row.timer_expired);

        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        intent(&j, &create);
        j.accept_fixture_lease_at(&create, || Ok(1000)).unwrap();
        assert!(
            j.expire_lease_at("lease-test", 1, 1, || Ok(101_000))
                .unwrap()
        );
        assert!(j.lease("lease-test").unwrap().timer_expired);
        drop(j);
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        assert!(j.lease("lease-test").unwrap().timer_expired);
    }
    #[test]
    fn invalid_clock_deadline_and_prewrite_failure_leave_no_effective_lease() {
        for now in [0, 102_000, u64::MAX] {
            let dir = tempfile::tempdir().unwrap();
            let j =
                crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
            let d = dispatch("create", 1);
            intent(&j, &d);
            assert!(j.accept_fixture_lease_at(&d, || Ok(now)).is_err());
            assert!(j.lease("lease-test").is_none());
        }
        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        let d = dispatch("create", 1);
        intent(&j, &d);
        j.inject_crash(CrashPoint::BeforeLease);
        assert!(j.accept_fixture_lease_at(&d, || Ok(1000)).is_err());
        drop(j);
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        assert!(j.lease("lease-test").is_none());
    }
}

pub struct LeaseWork<'a> {
    journal: &'a HostJournal,
    id: Option<String>,
}
impl Drop for LeaseWork<'_> {
    fn drop(&mut self) {
        if let Some(id) = &self.id {
            let mut state = self.journal.state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(count) = state.lease_workers.get_mut(id) {
                *count -= 1;
                if *count == 0 {
                    state.lease_workers.remove(id);
                }
            }
        }
    }
}
