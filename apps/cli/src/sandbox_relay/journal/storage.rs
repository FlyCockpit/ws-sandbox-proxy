//! Retained roots and implicit ceilings outlive receipts, leases and config omission.
use super::*;
use sandbox_protocol::capacity_v11::PinnedAllocationV11;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetainedRoot {
    pub sandbox_owner_id: String,
    pub allocation: PinnedAllocationV11,
    pub generation: u64,
    pub live: bool,
}

/// Authority captured before runtime observation; never survives its session.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RootRetirementFence {
    root: RetainedRoot,
    epoch: u64,
    generation: u64,
    lease: Option<(u64, sandbox_protocol::HostLease, bool, bool)>,
}

pub(super) fn root_lifecycle(kind: &str) -> bool {
    matches!(
        kind,
        "sandbox.create"
            | "sandbox.reconnect"
            | "sandbox.stop"
            | "sandbox.kill"
            | "sandbox.lease.renew"
            | "credential.attach"
            | "credential.free"
    )
}

fn retirement_fence(state: &JournalState, id: &str) -> Option<RootRetirementFence> {
    if state.lease_workers.get(id).copied().unwrap_or(0) != 0
        || state
            .receipts
            .values()
            .any(|r| r.sandbox_id == id && root_lifecycle(&r.kind) && !r.is_terminal())
    {
        return None;
    }
    let root = state.storage.roots.get(id)?.clone();
    let lease = state.leases.get(id);
    let generation = state
        .receipts
        .values()
        .filter(|r| r.sandbox_id == id && root_lifecycle(&r.kind))
        .map(|r| r.generation)
        .chain(lease.map(|r| r.generation))
        .chain(state.cleanups.get(id).map(|r| r.generation))
        .fold(root.generation, u64::max);
    Some(RootRetirementFence {
        root,
        epoch: state.root_observation_epochs.get(id).copied().unwrap_or(0),
        generation,
        lease: lease.map(|r| (r.generation, r.lease.clone(), r.expired, r.expiry_complete)),
    })
}
impl RetainedRoot {
    pub fn root(&self) -> sandbox_runtime::RootDisk {
        allocation_root(&self.allocation)
    }
}
pub fn allocation_root(a: &PinnedAllocationV11) -> sandbox_runtime::RootDisk {
    sandbox_runtime::RootDisk {
        pool: sandbox_runtime::StoragePoolIdentity {
            name: a.storage_pool_name.clone(),
            storage_id: a.storage_marker.clone(),
        },
        disk_gi_b: a.disk_gi_b,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PoolLineage {
    pub name: String,
    pub ceiling_gib: u64,
    pub advertised: Option<sandbox_protocol::capacity_v11::StoragePoolV11>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StorageLedger {
    pub version: u32,
    pub binding: TransportBindingV11,
    pub pools: BTreeMap<String, PoolLineage>,
    pub roots: BTreeMap<String, RetainedRoot>,
    pub deleted: BTreeMap<String, u64>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    ledger: StorageLedger,
    checksum: String,
}
impl StorageLedger {
    pub fn empty(binding: &TransportBindingV11) -> Self {
        Self {
            version: JOURNAL_VERSION,
            binding: binding.clone(),
            pools: BTreeMap::new(),
            roots: BTreeMap::new(),
            deleted: BTreeMap::new(),
        }
    }
    pub fn load(path: &Path, binding: &TransportBindingV11) -> Result<Self> {
        if path.try_exists()? {
            private_file(path)?;
            anyhow::ensure!(
                fs::metadata(path)?.len() <= 4 * 1024 * 1024,
                "storage journal too large"
            );
        }
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::empty(binding)),
            Err(e) => return Err(e.into()),
        };
        private_file(path)?;
        anyhow::ensure!(bytes.len() <= 4 * 1024 * 1024, "storage journal too large");
        let e: Envelope = serde_json::from_slice(&bytes)
            .context("invalid storage journal; preserve state and restore original journal")?;
        anyhow::ensure!(
            e.checksum == sha256_hex(&serde_json::to_vec(&e.ledger)?),
            "storage journal checksum mismatch"
        );
        let l = e.ledger;
        anyhow::ensure!(
            l.version == JOURNAL_VERSION,
            "unsupported storage journal; retire old allocations with the original daemon and preserve its journal"
        );
        anyhow::ensure!(
            l.binding.server == binding.server
                && l.binding.host_id == binding.host_id
                && (binding.host_owner_id.is_empty()
                    || l.binding.host_owner_id.is_empty()
                    || l.binding.host_owner_id == binding.host_owner_id),
            "storage journal belongs to a different host"
        );
        for (marker, pool) in &l.pools {
            sandbox_runtime::StoragePoolIdentity {
                name: pool.name.clone(),
                storage_id: marker.clone(),
            }
            .validate()?;
            anyhow::ensure!(
                pool.ceiling_gib
                    <= u64::from(sandbox_protocol::vm_size_limits()?.storage_capacity_gi_b_max),
                "invalid implicit ceiling"
            );
        }
        for (id, row) in &l.roots {
            anyhow::ensure!(
                sandbox_protocol::valid_inventory_sandbox_id(id),
                "invalid retained sandbox id"
            );
            row.root().validate()?;
            anyhow::ensure!(
                l.pools
                    .get(&row.allocation.storage_marker)
                    .is_some_and(|p| p.name == row.allocation.storage_pool_name),
                "retained root missing original pool ceiling; restore journal"
            );
        }
        Ok(l)
    }
}
impl HostJournal {
    pub(crate) fn root_retirement_fence(&self, id: &str) -> Option<RootRetirementFence> {
        retirement_fence(&self.state.lock().unwrap_or_else(|e| e.into_inner()), id)
    }

    /// Only an exact ACK of the observed absence can discharge this root.
    /// The caller additionally excludes queued/carried/active/resolving work.
    pub(crate) fn acknowledge_root_retired(
        &self,
        entry: &sandbox_protocol::InventoryEntry,
        fence: &RootRetirementFence,
    ) -> Result<bool> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if self.io.failed()
            || retirement_fence(&state, &entry.sandbox_id).as_ref() != Some(fence)
            || entry.sandbox_owner_id.as_deref() != Some(fence.root.sandbox_owner_id.as_str())
            || entry.state != sandbox_protocol::SandboxLifecycleState::Absent
            || !entry.root.as_ref().is_some_and(|r| {
                r.state == sandbox_protocol::RootState::Absent
                    && r.network_cleanup_complete
                    && r.storage_pool_name == fence.root.allocation.storage_pool_name
                    && r.storage_marker == fence.root.allocation.storage_marker
                    && r.disk_gi_b == fence.root.allocation.disk_gi_b
            })
        {
            return Ok(false);
        }
        let mut next = state.storage.clone();
        next.roots.remove(&entry.sandbox_id);
        next.deleted
            .entry(entry.sandbox_id.clone())
            .and_modify(|g| *g = (*g).max(fence.generation))
            .or_insert(fence.generation);
        self.persist_storage(&next)?;
        state.storage = next;
        state.root_observation_epochs.remove(&entry.sandbox_id);
        Ok(true)
    }

    fn persist_storage(&self, ledger: &StorageLedger) -> Result<()> {
        let envelope = Envelope {
            checksum: sha256_hex(&serde_json::to_vec(ledger)?),
            ledger: ledger.clone(),
        };
        let dir = self
            .storage_path
            .parent()
            .context("storage journal has no directory")?;
        persist_bytes(
            &self.io,
            dir,
            &self.storage_path,
            &serde_json::to_vec(&envelope)?,
        )
    }
    /// Test setup for a previously retained disk, without fabricating an effect.
    #[cfg(test)]
    pub(crate) fn seed_fixture_root(
        &self,
        id: &str,
        allocation: &PinnedAllocationV11,
        generation: u64,
    ) -> Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut next = state.storage.clone();
        if !next.roots.contains_key(id) && !next.deleted.contains_key(id) {
            next.roots.insert(
                id.into(),
                RetainedRoot {
                    sandbox_owner_id: "owner".into(),
                    allocation: allocation.clone(),
                    generation,
                    live: false,
                },
            );
            self.persist_storage(&next)?;
            state.storage = next;
        }
        Ok(())
    }
    /// Test setup for an already retained root before a reconnect intent.
    #[cfg(test)]
    pub(crate) fn record_fixture_intent(&self, receipt: &HostReceipt) -> Result<Decision> {
        if receipt.kind == "sandbox.reconnect"
            && let Some(allocation) = &receipt.allocation
        {
            self.seed_fixture_root(&receipt.sandbox_id, allocation, receipt.generation)?;
        }
        self.record_intent(receipt)
    }
    pub fn retained_roots(&self) -> BTreeMap<String, RetainedRoot> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .storage
            .roots
            .clone()
    }
    pub(crate) fn root_deleted_generation(&self, id: &str) -> Option<u64> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .storage
            .deleted
            .get(id)
            .copied()
    }
    pub fn pool_lineages(&self) -> Vec<sandbox_runtime::StoragePoolIdentity> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .storage
            .pools
            .iter()
            .map(|(marker, p)| sandbox_runtime::StoragePoolIdentity {
                name: p.name.clone(),
                storage_id: marker.clone(),
            })
            .collect()
    }
    pub fn pool_snapshot(
        &self,
        marker: &str,
    ) -> Option<sandbox_protocol::capacity_v11::StoragePoolV11> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .storage
            .pools
            .get(marker)
            .and_then(|p| p.advertised.clone())
    }
    /// Commit P and the frozen connection tuple in one atomic/fsynced snapshot.
    pub fn freeze_pool(
        &self,
        frame: &mut sandbox_protocol::capacity_v11::StoragePoolV11,
        candidate: u64,
        unbound: bool,
    ) -> Result<()> {
        let pool = sandbox_runtime::StoragePoolIdentity {
            name: frame.name.clone(),
            storage_id: frame.marker.clone(),
        };
        pool.validate()?;
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut next = state.storage.clone();
        let prior = next.pools.get(&pool.storage_id);
        anyhow::ensure!(
            prior.is_some() || unbound,
            "bound pool is missing implicit ceiling; restore original journal"
        );
        anyhow::ensure!(
            next.pools
                .iter()
                .all(|(m, p)| p.name != pool.name || m == &pool.storage_id),
            "pool marker changed; restore original storage"
        );
        let p = prior.map_or(candidate, |p| p.ceiling_gib.min(candidate));
        if frame.capacity_source == sandbox_protocol::capacity_v11::CapacitySource::Implicit {
            frame.implicit_ceiling_gi_b = Some(p);
            frame.capacity_gi_b = frame.capacity_gi_b.min(p.try_into()?);
        }
        next.pools.insert(
            pool.storage_id,
            PoolLineage {
                name: pool.name,
                ceiling_gib: p,
                advertised: Some(frame.clone()),
            },
        );
        self.persist_storage(&next)?;
        state.storage = next;
        Ok(())
    }
    pub fn implicit_ceiling(&self, marker: &str) -> Option<u64> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .storage
            .pools
            .get(marker)
            .map(|p| p.ceiling_gib)
    }
    /// Caller has proven a new/unbound lineage or provided this marker's P.
    /// Persist even for explicit configuration, before hello or any root Effect.
    pub fn lower_implicit_ceiling(
        &self,
        pool: &sandbox_runtime::StoragePoolIdentity,
        candidate: u64,
        unbound: bool,
    ) -> Result<u64> {
        pool.validate()?;
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut next = state.storage.clone();
        let prior = next.pools.get(&pool.storage_id);
        anyhow::ensure!(
            prior.is_some() || unbound,
            "bound pool is missing implicit ceiling; restore original journal"
        );
        anyhow::ensure!(
            next.pools
                .iter()
                .all(|(m, p)| p.name != pool.name || m == &pool.storage_id),
            "pool marker changed; restore original storage"
        );
        let p = prior.map_or(candidate, |p| p.ceiling_gib.min(candidate));
        next.pools.insert(
            pool.storage_id.clone(),
            PoolLineage {
                name: pool.name.clone(),
                ceiling_gib: p,
                advertised: prior.and_then(|p| p.advertised.clone()),
            },
        );
        self.persist_storage(&next)?;
        state.storage = next;
        Ok(p)
    }
    /// A result releases live resources separately from exact-root deletion.
    /// Generation fencing prevents older stop/expiry facts freeing newer holds.
    pub(crate) fn release_retained(&self, id: &str, generation: u64, deleted: bool) -> Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut next = state.storage.clone();
        if let Some(row) = next.roots.get_mut(id) {
            if row.generation > generation {
                return Ok(());
            }
            row.live = false;
            if deleted {
                next.roots.remove(id);
                next.deleted
                    .entry(id.into())
                    .and_modify(|g| *g = (*g).max(generation))
                    .or_insert(generation);
            }
            self.persist_storage(&next)?;
            state.storage = next;
            if deleted {
                state.root_observation_epochs.remove(id);
            }
        }
        Ok(())
    }
    pub(super) fn retain_intent_locked(
        &self,
        state: &mut JournalState,
        receipt: &HostReceipt,
    ) -> Result<()> {
        let Some(a) = &receipt.allocation else {
            return Ok(());
        };
        if !matches!(
            receipt.kind.as_str(),
            "sandbox.create" | "sandbox.reconnect"
        ) {
            return Ok(());
        }
        // Each check refuses this one operation (`IntentRefused`), never the
        // relay session: a durable bad dispatch must not hold the host offline.
        macro_rules! refuse {
            ($ok:expr, $code:expr, $message:expr $(,)?) => {
                if !$ok {
                    return Err(super::IntentRefused::new($code, $message).into());
                }
            };
        }
        let mut next = state.storage.clone();
        refuse!(
            next.binding.server == receipt.server
                && next.binding.host_id == receipt.host_id
                && (next.binding.host_owner_id.is_empty()
                    || next.binding.host_owner_id == receipt.host_owner_id),
            SandboxErrorCode::StateConflict,
            "retained root belongs to a different owner"
        );
        next.binding.host_owner_id = receipt.host_owner_id.clone();
        refuse!(
            next.pools
                .get(&a.storage_marker)
                .is_some_and(|p| p.name == a.storage_pool_name),
            SandboxErrorCode::StateConflict,
            "allocation missing original pool ceiling"
        );
        refuse!(
            !next
                .deleted
                .get(&receipt.sandbox_id)
                .is_some_and(|g| *g >= receipt.generation),
            SandboxErrorCode::SandboxNotFound,
            "allocation predates deleted root"
        );
        let mut a = a.clone();
        if let Some(old) = next.roots.get(&receipt.sandbox_id) {
            refuse!(
                old.sandbox_owner_id == receipt.sandbox_owner_id
                    && old.root() == allocation_root(&a)
                    && old.allocation.root_charge_gi_b == a.root_charge_gi_b
                    && old.allocation.cpu_count == a.cpu_count
                    && old.allocation.memory_mi_b == a.memory_mi_b,
                SandboxErrorCode::VmSizeMismatch,
                "retained allocation differs"
            );
            // An existing possible-live hold uses its locally pinned weights.
            if old.live {
                refuse!(
                    a == old.allocation,
                    SandboxErrorCode::VmSizeMismatch,
                    "live charges differ from durable allocation"
                );
                a = old.allocation.clone();
            }
        } else {
            // A restore reconnect retains a new root.
            refuse!(
                receipt.allocation_kind() == Some(sandbox_runtime::AllocationKind::Create),
                SandboxErrorCode::SandboxNotFound,
                "cold start missing retained root: this host holds no disk for the \
                 sandbox, so nothing was started"
            );
            refuse!(
                next.roots.len()
                    < sandbox_protocol::vm_size_limits()?.host_managed_sandbox_ceiling as usize,
                SandboxErrorCode::HostCapacity,
                "managed root ceiling reached"
            );
        }
        if !next.roots.get(&receipt.sandbox_id).is_some_and(|r| r.live) {
            refuse!(
                a.charged_memory_mi_b
                    == sandbox_protocol::vm_live_memory_charge_mi_b(a.memory_mi_b)?
                    && a.charged_vcpu == a.cpu_count
                    && (next.roots.contains_key(&receipt.sandbox_id)
                        || a.root_charge_gi_b
                            == sandbox_protocol::vm_root_charge_gi_b(a.disk_gi_b)?),
                SandboxErrorCode::VmSizeMismatch,
                "new allocation charges differ from local policy"
            );
        }
        let generation = next
            .roots
            .get(&receipt.sandbox_id)
            .map_or(receipt.generation, |r| r.generation.max(receipt.generation));
        next.roots.insert(
            receipt.sandbox_id.clone(),
            RetainedRoot {
                sandbox_owner_id: receipt.sandbox_owner_id.clone(),
                allocation: a,
                generation,
                live: true,
            },
        );
        self.persist_storage(&next)?;
        state.storage = next;
        Ok(())
    }
}

/// Bounded read-only preview; never creates a state directory or takes the daemon lock.
pub fn preview_ledgers() -> Result<Vec<StorageLedgerPreview>> {
    let dir = crate::paths::data_dir()?.join("relay");
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut result = Vec::new();
    for (i, entry) in entries.enumerate() {
        anyhow::ensure!(i < 256, "too many host journals for read-only inspection");
        let path = entry?.path().join("storage.json");
        if !path.try_exists()? {
            continue;
        }
        private_file(&path)?;
        anyhow::ensure!(
            fs::metadata(&path)?.len() <= 4 * 1024 * 1024,
            "storage journal too large"
        );
        let envelope: Envelope = serde_json::from_slice(&fs::read(&path)?)?;
        let ledger = StorageLedger::load(&path, &envelope.ledger.binding)?;
        result.push(StorageLedgerPreview {
            ceilings: ledger
                .pools
                .into_iter()
                .map(|(id, p)| (id, (p.name, p.ceiling_gib)))
                .collect(),
            roots: ledger.roots,
        });
    }
    Ok(result)
}
#[derive(Debug)]
pub struct StorageLedgerPreview {
    pub ceilings: BTreeMap<String, (String, u64)>,
    pub roots: BTreeMap<String, RetainedRoot>,
}

impl HostJournal {
    pub(super) fn recover_storage(&self) -> Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut next = state.storage.clone();
        // Receipts and leases are independent durable release facts. Missing
        // ledger rows can only be reconstructed from complete pinned evidence.
        let mut receipts: Vec<_> = state.receipts.values().collect();
        receipts.sort_by_key(|r| r.generation);
        for r in receipts {
            let Some(a) = &r.allocation else { continue };
            anyhow::ensure!(
                next.pools
                    .get(&a.storage_marker)
                    .is_some_and(|p| p.name == a.storage_pool_name),
                "bound allocation missing implicit ceiling; restore original journal"
            );
            if matches!(r.kind.as_str(), "sandbox.create" | "sandbox.reconnect")
                && !next.roots.contains_key(&r.sandbox_id)
                && !next
                    .deleted
                    .get(&r.sandbox_id)
                    .is_some_and(|g| *g >= r.generation)
                && !state
                    .cleanups
                    .get(&r.sandbox_id)
                    .is_some_and(|c| c.generation >= r.generation && c.instance_absent)
            {
                next.roots.insert(
                    r.sandbox_id.clone(),
                    RetainedRoot {
                        sandbox_owner_id: r.sandbox_owner_id.clone(),
                        allocation: a.clone(),
                        generation: r.generation,
                        live: true,
                    },
                );
            }
            if super::confirmed_release(&r.kind, r.state, r.result.as_ref())
                && let Some(root) = next.roots.get_mut(&r.sandbox_id)
                && root.generation <= r.generation
                && root.root() == allocation_root(a)
            {
                root.live = false;
                if r.kind == "sandbox.kill" {
                    next.roots.remove(&r.sandbox_id);
                    next.deleted
                        .entry(r.sandbox_id.clone())
                        .and_modify(|g| *g = (*g).max(r.generation))
                        .or_insert(r.generation);
                }
            }
        }
        for lease in state.leases.values() {
            if lease.expiry_complete
                && let Some(root) = next.roots.get_mut(&lease.sandbox_id)
                && root.generation <= lease.generation
            {
                root.live = false;
                if lease.root_deleted
                    && lease
                        .allocation
                        .as_ref()
                        .is_some_and(|a| root.root() == allocation_root(a))
                {
                    next.roots.remove(&lease.sandbox_id);
                    next.deleted
                        .entry(lease.sandbox_id.clone())
                        .and_modify(|g| *g = (*g).max(lease.generation))
                        .or_insert(lease.generation);
                }
            }
        }
        if next != state.storage {
            self.persist_storage(&next)?;
            state.storage = next;
        }
        Ok(())
    }
}

impl HostJournal {
    pub(super) fn release_storage_locked(
        &self,
        state: &mut JournalState,
        id: &str,
        generation: u64,
        deleted: bool,
    ) -> Result<()> {
        let mut next = state.storage.clone();
        if let Some(root) = next.roots.get_mut(id)
            && root.generation <= generation
        {
            root.live = false;
            if deleted {
                next.roots.remove(id);
                next.deleted
                    .entry(id.into())
                    .and_modify(|g| *g = (*g).max(generation))
                    .or_insert(generation);
            }
            self.persist_storage(&next)?;
            state.storage = next;
            if deleted {
                state.root_observation_epochs.remove(id);
            }
        }
        Ok(())
    }
}

fn unissued_root(state: &JournalState, id: &str, generation: u64) -> bool {
    state
        .storage
        .roots
        .get(id)
        .is_some_and(|r| r.generation == generation)
        && !state.leases.contains_key(id)
        && !state.cleanups.contains_key(id)
        && state.lease_workers.get(id).copied().unwrap_or(0) == 0
        && !state.receipts.values().any(|r| r.sandbox_id == id)
}
impl HostJournal {
    pub(crate) fn root_never_issued(&self, id: &str, generation: u64) -> bool {
        unissued_root(
            &self.state.lock().unwrap_or_else(|e| e.into_inner()),
            id,
            generation,
        )
    }
    pub(crate) fn release_never_issued_root(
        &self,
        id: &str,
        generation: u64,
        proof: &sandbox_runtime::RootAbsenceProof,
    ) -> Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if !unissued_root(&state, id, generation) {
            return Ok(());
        }
        let root = state
            .storage
            .roots
            .get(id)
            .context("missing retained root")?;
        anyhow::ensure!(
            proof.pool() == &root.root().pool
                && proof.instance_name() == sandbox_runtime::default_incus_instance_name(id),
            "root absence proof differs"
        );
        let mut next = state.storage.clone();
        next.roots.remove(id);
        // No receipt ever existed, so no older receipt can resurrect this row.
        // Its original generation may safely retry after this positive proof.
        self.persist_storage(&next)?;
        state.storage = next;
        state.root_observation_epochs.remove(id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox_relay::live_admission::LiveSandboxAdmission;
    #[test]
    fn policy_change_rebuild_release_uses_durable_weights_then_new_cold_hold_uses_current_policy() {
        let dir = tempfile::tempdir().unwrap();
        let binding = TransportBindingV11 {
            server: "wss://example".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        };
        let pool = sandbox_runtime::StoragePoolIdentity {
            name: "default".into(),
            storage_id: "a".repeat(32),
        };
        let allocation = PinnedAllocationV11 {
            cpu_count: 1,
            memory_mi_b: 512,
            disk_gi_b: 32,
            storage_pool_name: pool.name.clone(),
            storage_marker: pool.storage_id.clone(),
            charged_memory_mi_b: 1536,
            charged_vcpu: 1,
            root_charge_gi_b: 33,
        };
        {
            let j = HostJournal::open(dir.path(), &binding).unwrap();
            j.lower_implicit_ceiling(&pool, 167, true).unwrap();
            // Fixture from an older policy: 1024 MiB overhead. The new policy
            // must never re-price this possible-live hold on reconstruction.
            let mut state = j.state.lock().unwrap();
            state.storage.roots.insert(
                "sbx".into(),
                RetainedRoot {
                    sandbox_owner_id: "owner".into(),
                    allocation: allocation.clone(),
                    generation: 1,
                    live: true,
                },
            );
            j.persist_storage(&state.storage).unwrap();
        }
        let j = HostJournal::open(dir.path(), &binding).unwrap();
        let mut holds =
            LiveSandboxAdmission::new(8, sandbox_protocol::VmCapacity::new(4096, 4).unwrap());
        holds.rebuild(&[], &j, &binding).unwrap();
        assert_eq!(holds.memory_held_mib().unwrap(), 1536);
        j.release_retained("sbx", 0, true).unwrap();
        assert_eq!(j.retained_roots().len(), 1);
        j.release_retained("sbx", 1, false).unwrap();
        holds.release_confirmed("sbx");
        assert_eq!(holds.memory_held_mib().unwrap(), 0);
        let mut d:OperationDispatch=serde_json::from_value(serde_json::json!({"sandboxOwnerId":"owner", "operationId":"cold","sandboxId":"sbx","kind":"sandbox.reconnect", "allocation": crate::sandbox_relay::test_support::allocation(),"generation":2,"attempt":1,"idempotencyKey":"cold","bodyHash":"a".repeat(64)})).unwrap();
        let mut new = allocation;
        new.charged_memory_mi_b = sandbox_protocol::vm_live_memory_charge_mi_b(512).unwrap();
        d.allocation = Some(new.clone());
        j.record_intent(&intent_from_dispatch(&j, &binding, &d))
            .unwrap();
        assert_eq!(
            j.retained_roots()["sbx"].allocation.charged_memory_mi_b,
            new.charged_memory_mi_b
        );
    }
}
