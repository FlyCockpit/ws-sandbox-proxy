//! Eviction and discard of local disk copies, including clock skew and journal cleanup.
//!
//! - **Eviction.** A `stored` copy is evicted only under a server grant:
//!   the daemon asks (`disk.evict.request`, on a server `disk.evict.suggest`
//!   or local storage pressure, least recently used first), the server CASes
//!   and grants, and the daemon journals the grant before it deletes the VM,
//!   proves the root absent and answers `disk.evicted`. A grant is refused
//!   (left to expire) unless the journal says `stored` for that seq, no
//!   lifecycle permit of the sandbox is live, and the grant is more than
//!   60 s from expiry judged against the server time relayed by the last
//!   heartbeat. The entry is dropped on the server's ack (`disk.offload.cancel`
//!   with reason `evicted`). A restart re-deletes under a journaled grant that
//!   is still unexpired; past expiry the server's census decides.
//! - **Discard.** `disk.discard` deletes a stale copy: with the instance
//!   present it binds by sandbox id, create key and base image (a different
//!   binding is refused); with it absent the orphan root volume named by the
//!   copy row's pool and marker is deleted. Either arm answers
//!   `disk.discarded` with the root-absence proof, or a refusal code.

use super::*;
use sandbox_protocol::{
    DiskDiscardV11, DiskDiscardedV11, DiskEvictGrantV11, DiskEvictRefusedV11, DiskEvictRequestV11,
    DiskEvictedV11, RootObservation, RootState,
};

/// `disk.offload.cancel` reason the server acks a `disk.evicted` with.
pub(super) const EVICTED_ACK: &str = "evicted";
/// A grant this close to its expiry (server time) is refused (S11).
const GRANT_MARGIN_MS: u64 = 60_000;
/// Local pressure: a stored copy's pool this full asks for its eviction.
/// The server uses the same threshold (`OFFLOAD_PRESSURE_PERCENT`,
/// packages/api/src/sandbox/disk-offload/enqueue.ts) to export disks whose
/// offload policy would otherwise keep them local.
const PRESSURE_PERCENT: u64 = 90;
/// Requests in flight from local pressure at once.
const PRESSURE_MAX_PENDING: usize = 2;
/// The VM delete and root proof of one eviction or discard.
const EVICT_BUDGET: Duration = Duration::from_secs(120);

/// The node side of eviction and discard: deleting a VM or orphan root
/// and proving its root absent. `Err` carries a refusal code.
pub trait LocalDisks: Send + Sync {
    /// Delete the evicted sandbox's VM (under grant `grant_id`), prove its
    /// root absent and settle its lease as destroyed.
    fn evict(&self, sandbox_id: &str, grant_id: &str) -> Result<RootObservation, String>;
    /// One `disk.discard`, either arm.
    fn discard(&self, discard: &DiskDiscardV11) -> Result<RootObservation, String>;
    /// Whether the storage pool of the sandbox's root is under pressure.
    fn under_pressure(&self, sandbox_id: &str) -> bool;
    /// Whether lifecycle work of the sandbox holds a live permit.
    fn lifecycle_busy(&self, sandbox_id: &str) -> bool;
}

/// `HH:MM:SS` UTC RFC 3339 (`YYYY-MM-DDTHH:MM:SS[.fff]Z`, as
/// `Date.toISOString` writes it) to Unix milliseconds.
pub(super) fn parse_utc_ms(text: &str) -> Option<u64> {
    let text = text.strip_suffix('Z')?;
    let (date, time) = text.split_once('T')?;
    let mut date = date.splitn(3, '-').map(str::parse::<i64>);
    let (year, month, day) = (date.next()?.ok()?, date.next()?.ok()?, date.next()?.ok()?);
    let (clock, millis) = match time.split_once('.') {
        Some((clock, fraction)) => {
            let digits: String = fraction.chars().take(3).collect();
            if digits.is_empty() || !fraction.chars().all(|c| c.is_ascii_digit()) {
                return None;
            }
            let scale = 10_i64.pow(3 - digits.len() as u32);
            (clock, digits.parse::<i64>().ok()? * scale)
        }
        None => (time, 0),
    };
    let mut clock = clock.splitn(3, ':').map(str::parse::<i64>);
    let (hour, minute, second) = (
        clock.next()?.ok()?,
        clock.next()?.ok()?,
        clock.next()?.ok()?,
    );
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..24).contains(&hour)
        || !(0..60).contains(&minute)
        || !(0..61).contains(&second)
    {
        return None;
    }
    // Days from civil (Howard Hinnant), proleptic Gregorian.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let ms = ((days * 24 + hour) * 60 + minute) * 60_000 + second * 1000 + millis;
    u64::try_from(ms).ok()
}

impl OffloadService {
    /// Install the node's eviction and discard executor.
    pub fn install_local_disks(&self, disks: Arc<dyn LocalDisks>) {
        let _ = self.inner.disks.set(disks);
    }

    /// Record the server time a `heartbeat.pong` relayed (S11).
    pub fn note_server_time(&self, received_at: &str) {
        if let Some(ms) = parse_utc_ms(received_at) {
            *self
                .inner
                .server_time
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = Some((ms, Instant::now()));
        }
    }

    /// The server's clock now, from the last relayed sample; None before
    /// the first heartbeat answer.
    fn server_now_ms(&self) -> Option<u64> {
        let sample = *self
            .inner
            .server_time
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        sample.map(|(ms, at)| {
            ms.saturating_add(u64::try_from(at.elapsed().as_millis()).unwrap_or(u64::MAX))
        })
    }

    fn lifecycle_busy(&self, sandbox_id: &str) -> bool {
        let jobs = self.lock_jobs();
        jobs.holds.contains_key(sandbox_id)
            || jobs.active.contains_key(sandbox_id)
            || self
                .inner
                .disks
                .get()
                .is_some_and(|disks| disks.lifecycle_busy(sandbox_id))
    }

    /// `disk.evict.request` for the journaled `stored` copy `(offload, seq)`
    /// of `sandbox_id` (a server suggestion or local pressure). Nothing is
    /// asked for a copy this host does not hold as stored, while lifecycle
    /// work of the sandbox runs, or twice at once.
    pub(super) fn request_eviction(&self, sandbox_id: &str, offload_id: &str, seq: u64) {
        let Some(entry) = self.entry(sandbox_id) else {
            return;
        };
        if entry.phase != OffloadPhase::Stored || entry.offload_id != offload_id || entry.seq != seq
        {
            tracing::debug!(
                sandbox_id,
                "eviction not requested: no matching stored copy"
            );
            return;
        }
        if self.inner.disks.get().is_none() || self.lifecycle_busy(sandbox_id) {
            return;
        }
        if !self
            .inner
            .evict_pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(sandbox_id.to_owned())
        {
            return;
        }
        self.push(DaemonControlMessage::DiskEvictRequest(
            DiskEvictRequestV11 {
                sandbox_id: sandbox_id.to_owned(),
                offload_id: offload_id.to_owned(),
                seq,
            },
        ));
    }

    /// Local pressure (§7 step 1): stored copies whose pool is under
    /// pressure ask for eviction, least recently used first, a bounded
    /// number at once. Returns how many were asked for.
    pub fn pressure_evict(&self) -> usize {
        let Some(disks) = self.inner.disks.get().cloned() else {
            return 0;
        };
        let pending = self
            .inner
            .evict_pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len();
        let room = PRESSURE_MAX_PENDING.saturating_sub(pending);
        if room == 0 {
            return 0;
        }
        let mut stored: Vec<(String, OffloadEntry)> = self
            .lock_journal()
            .entries()
            .filter(|(_, e)| e.phase == OffloadPhase::Stored)
            .map(|(id, e)| (id.clone(), e.clone()))
            .collect();
        // LRU: the oldest `last_used_at` first (RFC 3339 sorts as text);
        // an unknown time counts as oldest.
        stored.sort_by(|a, b| a.1.last_used_at.cmp(&b.1.last_used_at));
        let mut asked = 0;
        for (sandbox_id, entry) in stored {
            if asked >= room {
                break;
            }
            if !disks.under_pressure(&sandbox_id) {
                continue;
            }
            let before = self
                .inner
                .evict_pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len();
            self.request_eviction(&sandbox_id, &entry.offload_id, entry.seq);
            let after = self
                .inner
                .evict_pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len();
            if after > before {
                asked += 1;
            }
        }
        asked
    }

    pub(super) fn on_evict_refused(&self, refused: &DiskEvictRefusedV11) {
        self.inner
            .evict_pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&refused.sandbox_id);
        tracing::info!(sandbox_id = %refused.sandbox_id, code = %refused.code, "disk eviction refused; the copy stays cached");
    }

    /// A grant (§7 step 5): journal it, then delete the VM and prove the
    /// root absent. A refused grant is simply left to expire.
    pub(super) fn on_evict_grant(&self, grant: &DiskEvictGrantV11) {
        let sandbox_id = grant.sandbox_id.as_str();
        self.inner
            .evict_pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(sandbox_id);
        let refuse = |why: &str| {
            tracing::info!(
                sandbox_id,
                why,
                "disk eviction grant refused; it expires unused"
            );
        };
        let Some(mut entry) = self.entry(sandbox_id) else {
            return refuse("no journaled copy");
        };
        if entry.offload_id != grant.offload_id
            || entry.seq != grant.seq
            || !matches!(entry.phase, OffloadPhase::Stored | OffloadPhase::Evicting)
            || entry
                .evict_grant_id
                .as_deref()
                .is_some_and(|id| id != grant.grant_id)
        {
            return refuse("journal is not stored for that seq");
        }
        if self.inner.disks.get().is_none() {
            return refuse("eviction unsupported");
        }
        if self.lifecycle_busy(sandbox_id) {
            return refuse("a lifecycle permit is live");
        }
        let Some(now) = self.server_now_ms() else {
            return refuse("no relayed server time yet");
        };
        if grant.expires_at_unix_ms < now.saturating_add(GRANT_MARGIN_MS) {
            return refuse("grant expires within its margin");
        }
        entry.phase = OffloadPhase::Evicting;
        entry.evict_grant_id = Some(grant.grant_id.clone());
        entry.evict_expires_at_unix_ms = Some(grant.expires_at_unix_ms);
        if self.transition(sandbox_id, &entry) != Ok(Moved::Applied) {
            return refuse("journal unwritable");
        }
        self.evict_journaled(sandbox_id, entry);
    }

    /// Delete the VM of a journaled grant and report `disk.evicted`.
    fn evict_journaled(&self, sandbox_id: &str, mut entry: OffloadEntry) {
        let (Some(disks), Some(grant_id)) = (
            self.inner.disks.get().cloned(),
            entry.evict_grant_id.clone(),
        ) else {
            return;
        };
        // Lifecycle work that started since the grant keeps the VM.
        if self.lifecycle_busy(sandbox_id) {
            tracing::info!(sandbox_id, "disk eviction deferred: lifecycle work runs");
            return;
        }
        match disks.evict(sandbox_id, &grant_id) {
            Ok(proof) => {
                entry.phase = OffloadPhase::Evicted;
                if self.transition(sandbox_id, &entry) != Ok(Moved::Applied) {
                    return;
                }
                self.push(DaemonControlMessage::DiskEvicted(DiskEvictedV11 {
                    sandbox_id: sandbox_id.to_owned(),
                    offload_id: entry.offload_id.clone(),
                    grant_id,
                    root_absence_proof: proof,
                }));
            }
            Err(code) => {
                // The grant expires; the server's census decides from what
                // the host then reports.
                tracing::warn!(sandbox_id, code = %code, "disk eviction did not complete");
            }
        }
    }

    /// Restart (§7, "Daemon crash mid-evict"): under a journaled grant still
    /// unexpired (local clock: no server time yet), delete again; an
    /// `evicted` entry re-proves and re-reports. Past expiry the entry is
    /// `stored` again and the census decides.
    pub(super) fn recover_eviction(&self, sandbox_id: &str, mut entry: OffloadEntry) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(u64::MAX);
        let live = entry
            .evict_expires_at_unix_ms
            .is_some_and(|expires| expires >= now.saturating_add(GRANT_MARGIN_MS));
        if entry.phase == OffloadPhase::Evicted || live {
            return self.evict_journaled(sandbox_id, entry);
        }
        entry.phase = OffloadPhase::Stored;
        entry.evict_grant_id = None;
        entry.evict_expires_at_unix_ms = None;
        let _ = self.transition(sandbox_id, &entry);
    }

    /// The server's ack of `disk.evicted` (T16): drop the entry, so a later
    /// restore onto this host never finds a stale `stored` one.
    pub(super) fn on_evicted_ack(&self, ack: &DiskOffloadCancelV11) {
        if let Some(entry) = self.entry(&ack.sandbox_id)
            && entry.offload_id == ack.offload_id
            && matches!(entry.phase, OffloadPhase::Evicting | OffloadPhase::Evicted)
        {
            self.journal_remove(&ack.sandbox_id, &ack.offload_id);
        }
    }

    /// `disk.discard` (S8), either arm; answered `disk.discarded`.
    pub(super) fn on_discard(&self, discard: &DiskDiscardV11) {
        let answer = |proof: Option<RootObservation>, code: Option<String>| {
            self.push(DaemonControlMessage::DiskDiscarded(DiskDiscardedV11 {
                sandbox_id: discard.sandbox_id.clone(),
                copy_id: discard.copy_id.clone(),
                root_absence_proof: proof,
                code,
            }));
        };
        let Some(disks) = self.inner.disks.get().cloned() else {
            return answer(None, Some("unsupported".into()));
        };
        if self.lifecycle_busy(&discard.sandbox_id) {
            return answer(None, Some("lifecycle_busy".into()));
        }
        match disks.discard(discard) {
            Ok(proof) => {
                // A local journal entry of that copy is over too: a stored
                // one is dropped; an unfinished one (e.g. `uploaded`, its
                // ack missed) also takes its alias image, export, staging
                // and reservation with it. No job runs for it
                // (`lifecycle_busy` refused that above).
                if let Some(entry) = self.entry(&discard.sandbox_id) {
                    if entry.phase.stored() {
                        self.journal_remove(&discard.sandbox_id, &entry.offload_id);
                    } else {
                        self.cleanup(&discard.sandbox_id, &entry);
                    }
                }
                answer(Some(proof), None)
            }
            Err(code) => answer(None, Some(code)),
        }
    }
}

/// [`LocalDisks`] over the host journal and the runtime.
pub struct JournalDisks {
    journal: Arc<super::super::journal::HostJournal>,
    runtime: Arc<dyn SandboxRuntime>,
}

impl JournalDisks {
    pub fn new(
        journal: Arc<super::super::journal::HostJournal>,
        runtime: Arc<dyn SandboxRuntime>,
    ) -> Self {
        Self { journal, runtime }
    }

    fn scoped(&self) -> Box<dyn SandboxRuntime> {
        self.runtime
            .with_cancellation(Arc::new(sandbox_runtime::RuntimePermit::with_timeout(
                EVICT_BUDGET,
            )))
    }
}

/// The server-anchored restore hint a discard binds a stale copy with (§7
/// N1), when the journal cannot supply one. The template tag is always the
/// server's template revision (`template`). A copy whose base image is the
/// template is a template lineage: no hint. A restored lineage whose lease
/// record journaled its restore base binds through that (already bound at
/// startup). Without one (journal lost, or the copy predates its lease
/// record), the copy row's base is the hint: the runtime's single
/// `base_bound` predicate still requires `volatile.base_image == hint ==`
/// the `restore_base` tag, the template tag, the managed name, the sandbox id
/// tag and the create key, so only that exact stale instance binds.
pub(super) fn discard_server_hint<'a>(
    journaled_restore_base: Option<&str>,
    base_fingerprint: &'a str,
    template_fingerprint: &str,
) -> Option<&'a str> {
    (journaled_restore_base.is_none() && base_fingerprint != template_fingerprint)
        .then_some(base_fingerprint)
}

fn absent_proof(pool_name: &str, marker: &str, disk_gib: u32) -> RootObservation {
    RootObservation {
        storage_pool_name: pool_name.to_owned(),
        storage_marker: marker.to_owned(),
        disk_gi_b: disk_gib,
        state: RootState::Absent,
        network_cleanup_complete: true,
        observation_sequence: 0,
    }
}

fn default_disk_gib() -> u32 {
    sandbox_protocol::vm_size_limits()
        .map(|limits| limits.disk_gi_b_default)
        .unwrap_or(20)
}

impl JournalDisks {
    /// The bound arms of [`LocalDisks::discard`]: delete the bound instance or
    /// the orphan root, then prove the root absent.
    fn discard_bound(
        runtime: &dyn SandboxRuntime,
        discard: &DiskDiscardV11,
        template: &str,
        root: &sandbox_runtime::RootDisk,
        name: &str,
    ) -> Result<(), String> {
        let sandbox_id = discard.sandbox_id.as_str();
        match runtime.query_sandbox(sandbox_id, Some(&discard.create_key), Some(template)) {
            // Bound by sandbox id, create key and base image: the stale copy.
            Ok(Some(_)) => {
                let key = format!("disk-discard:{}", discard.copy_id);
                runtime
                    .kill_sandbox_on_storage(
                        &sandbox_runtime::KillSandboxRequest {
                            template_fingerprint: template.to_owned(),
                            sandbox_id: sandbox_id.to_owned(),
                            instance_name: name.to_owned(),
                            operation_id: key.clone(),
                            idempotency_key: discard.create_key.clone(),
                        },
                        root,
                    )
                    .map_err(|_| "io".to_owned())?;
            }
            // Absent: the orphan root named by the copy row, if any.
            Ok(None) => runtime
                .delete_orphan_root(root, name)
                .map_err(|_| "orphan_root".to_owned())?,
            // Another binding (e.g. the sandbox lives here again under a new
            // create key): never touched; the server re-evaluates.
            Err(error) if error.code == SandboxErrorCode::IdempotencyConflict => {
                return Err("binding_mismatch".into());
            }
            Err(_) => return Err("io".into()),
        }
        runtime
            .prove_root_absent(root, name)
            .map_err(|_| "root_present".to_owned())?;
        Ok(())
    }
}

impl LocalDisks for JournalDisks {
    fn evict(&self, sandbox_id: &str, grant_id: &str) -> Result<RootObservation, String> {
        let lease = self
            .journal
            .lease(sandbox_id)
            .ok_or_else(|| "lease_missing".to_owned())?;
        let allocation = lease
            .allocation
            .clone()
            .ok_or_else(|| "allocation_missing".to_owned())?;
        let root = super::super::journal::storage::allocation_root(&allocation);
        let name = sandbox_runtime::default_incus_instance_name(sandbox_id);
        let runtime = self.scoped();
        let key = format!("disk-evict:{grant_id}");
        runtime
            .kill_sandbox_on_storage(
                &sandbox_runtime::KillSandboxRequest {
                    template_fingerprint: lease.template_fingerprint.clone().unwrap_or_default(),
                    sandbox_id: sandbox_id.to_owned(),
                    instance_name: name.clone(),
                    operation_id: key.clone(),
                    idempotency_key: key,
                },
                &root,
            )
            .map_err(|error| format!("{:?}", error.into_error().code).to_ascii_lowercase())?;
        runtime
            .prove_root_absent(&root, &name)
            .map_err(|_| "root_present".to_owned())?;
        self.journal
            .record_evicted(sandbox_id)
            .map_err(|_| "journal".to_owned())?;
        Ok(absent_proof(
            &allocation.storage_pool_name,
            &allocation.storage_marker,
            allocation.disk_gi_b,
        ))
    }

    fn discard(&self, discard: &DiskDiscardV11) -> Result<RootObservation, String> {
        let sandbox_id = discard.sandbox_id.as_str();
        let name = sandbox_runtime::default_incus_instance_name(sandbox_id);
        let disk_gib = self
            .journal
            .lease(sandbox_id)
            .and_then(|lease| lease.allocation)
            .filter(|a| {
                a.storage_pool_name == discard.storage_pool_name
                    && a.storage_marker == discard.storage_marker
            })
            .map_or_else(default_disk_gib, |a| a.disk_gi_b);
        let root = sandbox_runtime::RootDisk {
            pool: sandbox_runtime::StoragePoolIdentity {
                name: discard.storage_pool_name.clone(),
                storage_id: discard.storage_marker.clone(),
            },
            disk_gi_b: disk_gib,
        };
        // The binding names the instance's template tag (the server's
        // template revision) and, for a restored lineage, its restore base:
        // the journaled one, else the copy row's (server-anchored) base.
        let template = discard.template_fingerprint.clone();
        let journaled = self
            .journal
            .lease(sandbox_id)
            .and_then(|lease| lease.restore_base);
        let hint = discard_server_hint(journaled.as_deref(), &discard.base_fingerprint, &template);
        let runtime = self.scoped();
        if let Some(hint) = hint {
            runtime.bind_restore_base(sandbox_id, hint);
        }
        let outcome = Self::discard_bound(&*runtime, discard, &template, &root, &name);
        if hint.is_some() {
            // Never leave the copy row's hint bound: a lease record journaled
            // meanwhile re-binds its own base instead.
            match self
                .journal
                .lease(sandbox_id)
                .and_then(|lease| lease.restore_base)
            {
                Some(base) => runtime.bind_restore_base(sandbox_id, &base),
                None => runtime.unbind_restore_base(sandbox_id),
            }
        }
        outcome?;
        // The copy's lease, if this host still records one, is settled.
        if self
            .journal
            .lease(sandbox_id)
            .and_then(|lease| lease.allocation)
            .is_some_and(|a| {
                a.storage_pool_name == discard.storage_pool_name
                    && a.storage_marker == discard.storage_marker
            })
        {
            let _ = self.journal.record_evicted(sandbox_id);
        }
        Ok(absent_proof(
            &discard.storage_pool_name,
            &discard.storage_marker,
            disk_gib,
        ))
    }

    fn under_pressure(&self, sandbox_id: &str) -> bool {
        let Some(allocation) = self
            .journal
            .lease(sandbox_id)
            .and_then(|lease| lease.allocation)
        else {
            return false;
        };
        let root = super::super::journal::storage::allocation_root(&allocation);
        self.scoped()
            .observe_storage_pool(&root.pool)
            .is_ok_and(|observation| {
                let resources = observation.resources;
                resources.used_bytes().saturating_mul(100)
                    >= resources.total_bytes().saturating_mul(PRESSURE_PERCENT)
            })
    }

    fn lifecycle_busy(&self, sandbox_id: &str) -> bool {
        self.journal.lifecycle_busy(sandbox_id)
    }
}
