//! The durable lease row: one checksummed record per sandbox under the
//! leases directory, its load-time repair from accepted receipts, and the
//! record-level rules (shorten-only clamp, private-config prune) that both
//! the lease lifecycle and the storage/config ledgers rely on.
use super::*;
use sandbox_protocol::HostLease;

/// What the host stores for a dispatched lease: a shorten-only lease never
/// moves the deadline of the same generation later (it keeps the revision, so
/// it still supersedes every older queued renewal). Any other lease is stored
/// as dispatched.
pub(super) fn clamp_shorten_only(
    lease: &HostLease,
    current: Option<&LeaseRecord>,
    generation: u64,
) -> HostLease {
    match current {
        Some(current)
            if lease.shorten_only
                && current.generation == generation
                && lease.deadline_unix_ms > current.lease.deadline_unix_ms =>
        {
            HostLease {
                deadline_unix_ms: current.lease.deadline_unix_ms,
                ..lease.clone()
            }
        }
        _ => lease.clone(),
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LeaseRecord {
    pub version: u32,
    pub sandbox_owner_id: String,
    /// Bound runtime deletion includes root and network cleanup, unlike VM-only census absence.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub root_deleted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allocation: Option<sandbox_protocol::capacity_v11::PinnedAllocationV11>,
    pub vm_size: sandbox_protocol::VmSize,
    pub binding: TransportBindingV11,
    pub sandbox_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_config: Option<sandbox_protocol::PrivateConfigRef>,
    pub template_fingerprint: Option<String>,
    pub generation: u64,
    pub lease: HostLease,
    pub expired: bool,
    pub expiry_complete: bool,
    pub observed_unix_ms: u64,
    /// Set only when the deadline timer latched `expired`; explicit stop/kill
    /// and idle retirement latch without it. Omitted while false so records
    /// written before this field keep their checksum.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub timer_expired: bool,
    /// Durable proof that the guest instance is gone (kill receipt, completed
    /// destroy expiry, or an absent census). Only absent-proofed records may be
    /// compacted: a completed stop lease still binds the stopped VM on disk,
    /// and the reconnect census rejects instances without one. Omitted while
    /// false so records written before this field keep their checksum.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub instance_absent: bool,
    /// A confirmed enforcement breach closes this exact arm before autonomous
    /// destruction. Unlike the deadline timer it always requires destruction,
    /// even when the accepted lease's normal expiry action is stop.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub enforcement_loss: bool,
    /// C52: the declared guest identity this sandbox was launched with (from
    /// the accepted create/reconnect dispatch). A terminal open takes its
    /// guest identity ONLY from here, never from a relay frame or the browser.
    /// Omitted while absent so records written before this field keep their
    /// checksum; a sandbox without it cannot open a terminal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest: Option<LeaseGuest>,
    /// D1 (template builds): the build this sandbox was created for, from the
    /// accepted `sandbox.create`. Immutable for the sandbox. Only a record
    /// that carries it admits guest-root steps (`runAs`, `buildCopy`); it
    /// refuses reconnect, terminals and file IO other than the context put.
    /// Omitted while absent so existing records keep their checksum.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_id: Option<String>,
    /// B1: the generation of this host's own confirmed `sandbox.stop` (result
    /// `stopped`) that left the instance stopped on disk under this lease.
    /// Stop dispatches move the server generation forward without carrying a
    /// lease, so a STOPPED capture at that generation runs under this stop,
    /// never under the older lease (see [`HostJournal::work_allowed`]). A
    /// newer create/reconnect replaces the record and clears it. Omitted
    /// while absent so records written before this field keep their checksum.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stopped_generation: Option<u64>,
    /// Guest sudo grant (`guestSudo` on the accepted create). Fixed for the
    /// record's life: a reconnect that differs is refused. The daemon
    /// installs `/etc/sudoers.d/wssp-guest` on every boot it drives while
    /// set, and removes it otherwise. Omitted while false so records written
    /// before this field keep their checksum.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub guest_sudo: bool,
    /// The guest may reach root (`guestSudo` or a root-tainted revision).
    /// May rise on a create or reconnect, never falls. UNKNOWN `command.run`
    /// receipts of such a sandbox retire on host proof only. Omitted while
    /// false so records written before this field keep their checksum.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub guest_root: bool,
    /// The disk image a restored lineage was booted
    /// from (`restore.fingerprint`, later the server's
    /// `diskBaseFingerprint`). Persisted here before the runtime call and
    /// the binding source of every bind of this sandbox; never read from
    /// instance config alone. A restore replaces it; a template lineage has
    /// none. Omitted while absent so existing records keep their checksum.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restore_base: Option<String>,
    /// This record was settled by
    /// [`HostJournal::record_evicted`] (VM deleted, root proven absent). The
    /// one durable eviction fact: the absent cleanup watermark is derived
    /// from it (`leases::settle_absent_watermarks`) before any compaction, so no
    /// crash between the two writes leaves the stop's not-absent watermark
    /// fencing a later restore. A new create/reconnect record clears it.
    /// Omitted while false so existing records keep their checksum.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub evicted: bool,
}

/// Guest identity bound into a lease record (see [`LeaseRecord::guest`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LeaseGuest {
    pub guest_uid: u32,
    pub guest_gid: u32,
    pub guest_home: String,
    pub guest_shell: String,
}

impl LeaseGuest {
    /// Only a dispatch that declares the full identity binds one.
    pub(super) fn from_dispatch(d: &OperationDispatch) -> Option<Self> {
        Some(Self {
            guest_uid: d.guest_uid?,
            guest_gid: d.guest_gid?,
            guest_home: d.guest_home.clone()?,
            guest_shell: d.guest_shell.clone()?,
        })
    }
    pub fn identity(&self) -> sandbox_runtime::GuestIdentity {
        sandbox_runtime::GuestIdentity {
            guest_uid: self.guest_uid,
            guest_gid: self.guest_gid,
            guest_home: self.guest_home.clone(),
            guest_shell: self.guest_shell.clone(),
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    record: LeaseRecord,
    checksum: String,
}

pub(super) fn prune_private_config(
    io: &IoLatch,
    dir: &Path,
    state: &mut JournalState,
    sandbox_id: &str,
) -> Result<()> {
    if let Some(record) = state.leases.get_mut(sandbox_id)
        && record.private_config.is_some()
    {
        let mut next = record.clone();
        next.private_config = None;
        persist(io, dir, &next)?;
        *record = next;
    }
    Ok(())
}

pub(super) fn persist(io: &IoLatch, dir: &Path, record: &LeaseRecord) -> Result<()> {
    let checksum = sha256_hex(&serde_json::to_vec(record)?);
    persist_bytes(
        io,
        dir,
        &dir.join(cleanup_file_name(&record.sandbox_id)),
        &serde_json::to_vec(&Envelope {
            record: record.clone(),
            checksum,
        })?,
    )
}
#[cfg(unix)]
pub(super) fn load(
    dir: &Path,
    binding: &TransportBindingV11,
    receipts: &HashMap<String, HostReceipt>,
) -> Result<HashMap<String, LeaseRecord>> {
    let mut rows = HashMap::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        private_file(&path)?;
        if path
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.starts_with(".tmp"))
        {
            fs::remove_file(path)?;
            continue;
        }
        if fs::metadata(&path)?.len() > 8192 || rows.len() >= 65_536 {
            bail!("oversized lease journal");
        }
        let envelope: Envelope = serde_json::from_slice(&fs::read(&path)?)?;
        if envelope.checksum != sha256_hex(&serde_json::to_vec(&envelope.record)?)
            || path.file_name().and_then(|s| s.to_str())
                != Some(&cleanup_file_name(&envelope.record.sandbox_id))
        {
            bail!("corrupt lease record");
        }
        rows.insert(envelope.record.sandbox_id.clone(), envelope.record);
    }
    for receipt in receipts.values() {
        if let Some(row) = &receipt.lease {
            let newer = rows.get(&row.sandbox_id).is_none_or(|old| {
                (row.generation, row.lease.revision) > (old.generation, old.lease.revision)
            });
            if newer {
                // Repair applies the same shorten-only clamp as admission.
                let mut row = row.clone();
                row.lease =
                    clamp_shorten_only(&row.lease, rows.get(&row.sandbox_id), row.generation);
                // `guest_root` never falls within a generation.
                row.guest_root |= rows
                    .get(&row.sandbox_id)
                    .is_some_and(|old| old.generation == row.generation && old.guest_root);
                persist(&IoLatch::default(), dir, &row)?;
                rows.insert(row.sandbox_id.clone(), row);
            }
        }
    }
    // The `guest_root` rise is accepted with the receipt, possibly without a
    // newer (generation, revision) tuple (an observational or same-revision
    // reconnect): max-merge it from every accepted receipt of the current
    // generation, whatever the order.
    for receipt in receipts.values() {
        let Some(accepted) = &receipt.lease else {
            continue;
        };
        if let Some(row) = rows.get_mut(&accepted.sandbox_id)
            && accepted.guest_root
            && !row.guest_root
            && row.generation == accepted.generation
        {
            row.guest_root = true;
            persist(&IoLatch::default(), dir, row)?;
        }
    }
    if rows.values().any(|r| {
        r.version != JOURNAL_VERSION
            || !sandbox_protocol::valid_terminal_id(&r.sandbox_owner_id)
            || r.binding.server != binding.server
            || r.binding.host_id != binding.host_id
            || (!binding.host_owner_id.is_empty()
                && r.binding.host_owner_id != binding.host_owner_id)
    }) {
        bail!("lease belongs to a different host/owner/server");
    }
    Ok(rows)
}
