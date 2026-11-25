//! Socket-reader-owned capacity, one reservation per possibly-live sandbox.
//! Worker completions refer to durable receipts, never ephemeral authority entries.
use std::collections::{HashMap, HashSet};

use anyhow::Result;
use sandbox_protocol::{
    OperationState, SandboxErrorCode, SandboxLifecycleState, VmCapacity, VmSize,
};

use super::journal::{HostJournal, ReceiptPhase, TransportBindingV11};

#[derive(Debug)]
struct Reservation {
    size: VmSize,
    conflicted: bool,
    live: bool,
    running: bool,
    /// Census observed a VM, or admission passed the current session caps.
    charged_memory_mib: u32,
    charged_vcpu: u32,
    allocations: HashSet<String>,
    /// Highest lifecycle generation that acquired or proved this slot live.
    generation: u64,
}

impl Default for Reservation {
    fn default() -> Self {
        Self {
            size: super::journal::default_vm_size(),
            conflicted: false,
            live: false,
            running: false,
            charged_memory_mib: 0,
            charged_vcpu: 0,
            allocations: HashSet::new(),
            generation: 0,
        }
    }
}
impl Reservation {
    fn observe(&mut self, size: VmSize) {
        if self.charged_memory_mib == 0 {
            self.charged_memory_mib =
                sandbox_protocol::vm_live_memory_charge_mi_b(size.memory_mi_b).unwrap_or(u32::MAX);
            self.charged_vcpu = size.cpu_count;
        }
        if self.size != size {
            self.conflicted = true;
            self.size.memory_mi_b = self.size.memory_mi_b.max(size.memory_mi_b);
            self.size.cpu_count = self.size.cpu_count.max(size.cpu_count);
            self.charged_memory_mib = self.charged_memory_mib.max(
                sandbox_protocol::vm_live_memory_charge_mi_b(size.memory_mi_b).unwrap_or(u32::MAX),
            );
            self.charged_vcpu = self.charged_vcpu.max(size.cpu_count);
        }
    }
}

#[derive(Debug)]
pub struct LiveSandboxAdmission {
    vcpu_budget: u32,
    new_root_pools: HashSet<String>,
    pools: Vec<sandbox_protocol::capacity_v11::StoragePoolV11>,
    retained: HashMap<String, super::journal::storage::RetainedRoot>,
    capacity: VmCapacity,
    reservations: HashMap<String, Reservation>,
}

impl LiveSandboxAdmission {
    pub fn new(vcpu_budget: u32, capacity: VmCapacity) -> Self {
        Self {
            vcpu_budget,
            new_root_pools: HashSet::new(),
            pools: Vec::new(),
            retained: HashMap::new(),
            capacity,
            reservations: HashMap::new(),
        }
    }

    pub fn vcpu_budget(&self) -> u32 {
        self.vcpu_budget
    }
    pub fn release_root_confirmed(&mut self, id: &str, generation: u64) {
        if self
            .retained
            .get(id)
            .is_some_and(|r| r.generation <= generation)
        {
            self.retained.remove(id);
        }
    }
    pub fn managed_ceiling(&self) -> u32 {
        sandbox_protocol::vm_size_limits().map_or(0, |l| l.host_managed_sandbox_ceiling)
    }
    pub fn held(&self) -> usize {
        self.reservations.len()
    }
    pub fn memory_held_mib(&self) -> Result<u64> {
        self.reservations.values().try_fold(0_u64, |total, slot| {
            total
                .checked_add(u64::from(slot.charged_memory_mib))
                .ok_or_else(|| anyhow::anyhow!("host reservation memory overflow"))
        })
    }
    pub fn vcpu_held(&self) -> u64 {
        self.reservations
            .values()
            .map(|s| u64::from(s.charged_vcpu))
            .sum()
    }
    pub fn set_pools(&mut self, pools: Vec<sandbox_protocol::capacity_v11::StoragePoolV11>) {
        self.new_root_pools = pools
            .iter()
            .filter(|p| p.health == sandbox_protocol::capacity_v11::StorageHealth::Healthy)
            .map(|p| p.marker.clone())
            .collect();
        self.pools = pools;
    }
    pub fn sandbox_ids(&self) -> Vec<String> {
        self.reservations.keys().cloned().collect()
    }

    /// Run under the exclusive journal directory lock, before dispatch admission.
    /// The census includes VMs whose successful receipts have been confirmed and
    /// pruned. Unknown receipts cover effects missing from that inventory. After
    /// process restart there are no old workers: a census-confirmed stopped disk
    /// is authoritative even if an old create receipt never obtained its result.
    pub fn rebuild(
        &mut self,
        inventory: &[sandbox_runtime::RuntimeInventoryEntry],
        journal: &HostJournal,
        binding: &TransportBindingV11,
    ) -> Result<()> {
        let receipts = journal.matching(binding)?;
        let cleanups = journal.cleanup_generations(binding)?;
        let retained = journal.retained_roots();
        let stopped: HashSet<_> = inventory
            .iter()
            .filter(|entry| {
                (entry.state == SandboxLifecycleState::Stopped
                    || matches!(entry.configured_size, sandbox_runtime::ConfiguredSize::NoInstance))
                    // Bound live facts need the original-pool reconstruction
                    // fence, not a VM-only 404 from an unavailable pool.
                    && retained.get(&entry.sandbox_id).is_none_or(|r| !r.live)
            })
            .map(|entry| entry.sandbox_id.as_str())
            .collect();
        self.reservations.clear();
        self.retained = retained.into_iter().collect();
        for entry in inventory {
            let (id, state) = (&entry.sandbox_id, &entry.state);
            if *state != SandboxLifecycleState::Stopped {
                let lease = journal.lease(id);
                let fallback = lease
                    .as_ref()
                    .map(|row| row.vm_size)
                    .or_else(|| {
                        receipts
                            .iter()
                            .filter(|row| {
                                row.sandbox_id == *id
                                    && matches!(
                                        row.kind.as_str(),
                                        "sandbox.create" | "sandbox.reconnect"
                                    )
                            })
                            .max_by_key(|row| row.generation)
                            .map(|row| row.vm_size)
                    })
                    .unwrap_or_else(super::journal::default_vm_size);
                let (size, invalid) = match &entry.configured_size {
                    sandbox_runtime::ConfiguredSize::Configured(size) => (*size, false),
                    sandbox_runtime::ConfiguredSize::Conflict => (fallback, true),
                    sandbox_runtime::ConfiguredSize::NoInstance => continue,
                    sandbox_runtime::ConfiguredSize::Unobserved(_) => (fallback, false),
                };
                let slot = self
                    .reservations
                    .entry(id.clone())
                    .or_insert_with(|| Reservation {
                        size,
                        ..Reservation::default()
                    });
                slot.conflicted |= invalid;
                slot.observe(size);
                if let Some(lease) = lease {
                    slot.observe(lease.vm_size);
                }
                slot.live = true;
                slot.running = true;
                slot.generation = slot
                    .generation
                    .max(journal.lease(id).map_or(0, |row| row.generation));
            }
        }
        for receipt in &receipts {
            if receipt.phase != ReceiptPhase::Effect
                || !matches!(
                    receipt.kind.as_str(),
                    "sandbox.create" | "sandbox.reconnect"
                )
                || stopped.contains(receipt.sandbox_id.as_str())
                // A locally completed lease action is durable stop/deletion
                // proof even when the create result stayed UNKNOWN and no
                // explicit teardown receipt or server confirmation exists.
                // A newer uncertain launch must keep its own slot (C-26).
                || journal.lease(&receipt.sandbox_id).is_some_and(|row|
                    row.expired && row.expiry_complete && row.generation >= receipt.generation)
                || cleanups
                    .get(&receipt.sandbox_id)
                    .is_some_and(|generation| *generation >= receipt.generation)
            {
                continue;
            }
            let confirmed_cleanup = receipts.iter().any(|other| {
                other.sandbox_id == receipt.sandbox_id
                    && other.generation >= receipt.generation
                    && super::journal::confirmed_release(
                        &other.kind,
                        other.state,
                        other.result.as_ref(),
                    )
            });
            if !confirmed_cleanup {
                let slot = self
                    .reservations
                    .entry(receipt.sandbox_id.clone())
                    .or_insert_with(|| Reservation {
                        size: receipt.vm_size,
                        ..Reservation::default()
                    });
                slot.observe(receipt.vm_size);
                if let Some(lease) = journal.lease(&receipt.sandbox_id) {
                    slot.observe(lease.vm_size);
                }
                slot.live = true;
                slot.generation = slot.generation.max(receipt.generation);
            }
        }
        for (id, slot) in &mut self.reservations {
            if let Some(row) = self.retained.get(id) {
                slot.charged_memory_mib = if slot.size.memory_mi_b == row.allocation.memory_mi_b {
                    row.allocation.charged_memory_mi_b
                } else {
                    slot.charged_memory_mib
                        .max(row.allocation.charged_memory_mi_b)
                };
                slot.charged_vcpu = if slot.size.cpu_count == row.allocation.cpu_count {
                    row.allocation.charged_vcpu
                } else {
                    slot.charged_vcpu.max(row.allocation.charged_vcpu)
                };
                slot.conflicted |= row.allocation.cpu_count != slot.size.cpu_count
                    || row.allocation.memory_mi_b != slot.size.memory_mi_b;
            }
        }
        for (id, row) in &self.retained {
            if row.live && !stopped.contains(id.as_str()) {
                self.reservations
                    .entry(id.clone())
                    .or_insert_with(|| Reservation {
                        size: VmSize {
                            cpu_count: row.allocation.cpu_count,
                            memory_mi_b: row.allocation.memory_mi_b,
                        },
                        charged_memory_mib: row.allocation.charged_memory_mi_b,
                        charged_vcpu: row.allocation.charged_vcpu,
                        generation: row.generation,
                        live: true,
                        ..Reservation::default()
                    });
            }
        }
        for (id, slot) in &self.reservations {
            if slot.conflicted {
                tracing::warn!(sandbox_id = %id, memory_mib = slot.size.memory_mi_b,
                    cpu_count = slot.size.cpu_count, "VM allocation conflict; refusing starts for this sandbox");
            }
        }
        self.memory_held_mib()?;
        Ok(())
    }

    /// After `rebuild`: restore the hold of an Intent-phase create/reconnect
    /// carried across a relay transport drop (minor 4). Its allocation is
    /// journaled; Effect-phase launches and running VMs are already counted
    /// by `rebuild`. Restoring never refuses: the hold existed before the drop.
    pub fn restore_carried(&mut self, receipt: &super::journal::HostReceipt) {
        let Some(a) = receipt.allocation.as_ref() else {
            return;
        };
        if receipt.phase != ReceiptPhase::Intent
            || !matches!(
                receipt.kind.as_str(),
                "sandbox.create" | "sandbox.reconnect"
            )
        {
            return;
        }
        let Ok(size) = VmSize::new(a.cpu_count, a.memory_mi_b) else {
            return;
        };
        let slot = self
            .reservations
            .entry(receipt.sandbox_id.clone())
            .or_insert_with(|| Reservation {
                size,
                charged_memory_mib: a.charged_memory_mi_b,
                charged_vcpu: a.charged_vcpu,
                ..Reservation::default()
            });
        slot.observe(size);
        slot.allocations.insert(receipt.operation_id.clone());
        slot.generation = slot.generation.max(receipt.generation);
        self.retained
            .entry(receipt.sandbox_id.clone())
            .or_insert_with(|| super::journal::storage::RetainedRoot {
                sandbox_owner_id: receipt.sandbox_owner_id.clone(),
                allocation: a.clone(),
                generation: receipt.generation,
                live: true,
            });
    }

    /// Called only for fresh create/reconnect work after replay/refusal decisions.
    /// Every reconnect shares its sandbox's slot, including after supersession.
    pub fn try_acquire(
        &mut self,
        sandbox_id: &str,
        operation_id: &str,
        generation: u64,
        size: VmSize,
    ) -> Result<(), SandboxErrorCode> {
        VmSize::new(size.cpu_count, size.memory_mi_b)
            .map_err(|_| SandboxErrorCode::ProtocolError)?;
        let existing = self.reservations.get(sandbox_id);
        if existing.is_some_and(|slot| slot.conflicted || slot.size != size) {
            return Err(SandboxErrorCode::VmSizeMismatch);
        }
        let warm = existing.is_some_and(|slot| slot.running);
        if !warm {
            if size.cpu_count > self.capacity.max_cpu_count
                || existing.map_or_else(
                    || {
                        sandbox_protocol::vm_live_memory_charge_mi_b(size.memory_mi_b)
                            .unwrap_or(u32::MAX)
                    },
                    |slot| slot.charged_memory_mib,
                ) > self.capacity.memory_budget_mi_b
            {
                return Err(SandboxErrorCode::HostCapacity);
            }
            let memory = self
                .memory_held_mib()
                .map_err(|_| SandboxErrorCode::Internal)?;
            let extra = if existing.is_none() {
                u64::from(
                    sandbox_protocol::vm_live_memory_charge_mi_b(size.memory_mi_b)
                        .map_err(|_| SandboxErrorCode::Internal)?,
                )
            } else {
                0
            };
            let extra_cpu = if existing.is_none() {
                u64::from(size.cpu_count)
            } else {
                0
            };
            if (existing.is_none() && self.held() >= self.managed_ceiling() as usize)
                || memory
                    .checked_add(extra)
                    .is_none_or(|v| v > u64::from(self.capacity.memory_budget_mi_b))
                || self
                    .vcpu_held()
                    .checked_add(extra_cpu)
                    .is_none_or(|v| v > u64::from(self.vcpu_budget))
            {
                return Err(SandboxErrorCode::HostCapacity);
            }
        }
        let slot = self
            .reservations
            .entry(sandbox_id.into())
            .or_insert_with(|| Reservation {
                size,
                ..Reservation::default()
            });
        slot.observe(size);
        slot.allocations.insert(operation_id.into());
        slot.generation = slot.generation.max(generation);
        Ok(())
    }

    /// A refusal can remove only its own unissued allocation. An earlier live or
    /// unknown effect, or another queued allocation, still owns the shared slot.
    pub fn finish_allocation(
        &mut self,
        sandbox_id: &str,
        operation_id: &str,
        state: OperationState,
    ) {
        let Some(slot) = self.reservations.get_mut(sandbox_id) else {
            return;
        };
        if !slot.allocations.remove(operation_id) {
            return;
        }
        if matches!(
            state,
            OperationState::Succeeded | OperationState::UnknownOutcome
        ) {
            slot.live = true;
            slot.running |= state == OperationState::Succeeded;
        }
        if !slot.live && slot.allocations.is_empty() {
            self.reservations.remove(sandbox_id);
        }
    }

    /// Only a CURRENT stop/kill may revoke the sandbox's complete reservation.
    /// Superseded completions no longer own an allocation and cannot release a
    /// subsequently acquired slot, or resurrect a slot after confirmed cleanup.
    pub fn release_confirmed(&mut self, sandbox_id: &str) {
        self.reservations.remove(sandbox_id);
    }

    /// A completed local expiry of `generation` proves that arm inactive. It
    /// frees the slot only if nothing newer acquired it since: a later
    /// create/reconnect owns a higher generation and keeps its reservation.
    pub fn release_expired(&mut self, sandbox_id: &str, generation: u64) -> bool {
        if self
            .reservations
            .get(sandbox_id)
            .is_some_and(|slot| slot.generation <= generation && slot.allocations.is_empty())
        {
            self.reservations.remove(sandbox_id);
            return true;
        }
        false
    }
}

#[cfg(test)]
pub(crate) fn test_capacity() -> VmCapacity {
    VmCapacity::new(16777216, 32).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[test]
    fn restart_reconciles_only_proven_cleanup_not_unknown_effects() {
        use super::super::journal::intent_from_dispatch;
        for proof in ["unknown", "killed", "expired", "older-expiry", "stopped"] {
            let dir = tempfile::tempdir().unwrap();
            let binding = TransportBindingV11 {
                server: "wss://example".into(),
                host_owner_id: "owner".into(),
                host_id: "host".into(),
            };
            {
                let journal =
                    crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap();
                let create: sandbox_protocol::OperationDispatch = serde_json::from_value(
                    serde_json::json!({"sandboxOwnerId":"owner", "operationId":"create", "sandboxId":"old",
                        "kind":"sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(), "generation":1, "attempt":1,
                        "idempotencyKey":"create", "bodyHash":"a".repeat(64), "lease":sandbox_protocol::HostLease::for_test()})).unwrap();
                journal
                    .record_intent(&intent_from_dispatch(&journal, &binding, &create))
                    .unwrap();
                journal.accept_fixture_lease(&create).unwrap();
                journal.record_effect("create").unwrap();
                journal
                    .record_result(
                        "create",
                        OperationState::UnknownOutcome,
                        None,
                        Some(SandboxErrorCode::UnknownOutcome),
                        None,
                    )
                    .unwrap();
                let lease = journal.lease("old").unwrap();
                match proof {
                    "killed" => journal.retire_inactive_lease(&lease, true).unwrap(),
                    "expired" | "older-expiry" => {
                        journal
                            .settle_enforcement_loss(
                                &lease,
                                sandbox_runtime::EnforcementLossStage::Prepare,
                            )
                            .unwrap();
                        journal
                            .settle_enforcement_loss(
                                &lease,
                                sandbox_runtime::EnforcementLossStage::Complete,
                            )
                            .unwrap();
                    }
                    _ => {}
                }
                if proof == "older-expiry" {
                    let mut later = create.clone();
                    later.operation_id = "newer".into();
                    later.idempotency_key = "newer".into();
                    later.generation = 2;
                    journal
                        .record_intent(&intent_from_dispatch(&journal, &binding, &later))
                        .unwrap();
                    journal
                        .record_result("newer", OperationState::UnknownOutcome, None, None, None)
                        .unwrap();
                }
            }
            let journal =
                crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap();
            let mut slots = LiveSandboxAdmission::new(2, test_capacity());
            let inventory = if proof == "stopped" {
                vec![sandbox_runtime::RuntimeInventoryEntry {
                    sandbox_id: "old".into(),
                    state: SandboxLifecycleState::Stopped,
                    configured_size: sandbox_runtime::ConfiguredSize::Configured(
                        sandbox_protocol::VmSize::defaults().unwrap(),
                    ),
                }]
            } else {
                vec![]
            };
            slots.rebuild(&inventory, &journal, &binding).unwrap();
            assert_eq!(
                slots.held(),
                usize::from(matches!(proof, "unknown" | "older-expiry" | "stopped")),
                "{proof}"
            );
            slots
                .try_acquire(
                    "fresh",
                    "fresh-create",
                    1,
                    sandbox_protocol::VmSize::defaults().unwrap(),
                )
                .unwrap();
            assert_eq!(
                slots.held(),
                1 + usize::from(matches!(proof, "unknown" | "older-expiry" | "stopped")),
                "{proof}"
            );
        }
    }

    #[test]
    fn sandbox_lifetime_owns_slot_across_attempts_and_refusals() {
        let mut slots = LiveSandboxAdmission::new(1, test_capacity());
        slots
            .try_acquire(
                "a",
                "create",
                1,
                sandbox_protocol::VmSize::defaults().unwrap(),
            )
            .unwrap();
        slots
            .try_acquire(
                "a",
                "create",
                1,
                sandbox_protocol::VmSize::defaults().unwrap(),
            )
            .unwrap();
        slots
            .try_acquire(
                "a",
                "replacement",
                1,
                sandbox_protocol::VmSize::defaults().unwrap(),
            )
            .unwrap();
        slots.finish_allocation("a", "replacement", OperationState::Failed);
        assert_eq!(slots.held(), 1);
        slots.finish_allocation("a", "create", OperationState::UnknownOutcome);
        assert_eq!(
            slots.try_acquire(
                "b",
                "create-b",
                1,
                sandbox_protocol::VmSize::defaults().unwrap()
            ),
            Err(SandboxErrorCode::HostCapacity)
        );
        slots.release_confirmed("a");
        slots
            .try_acquire(
                "b",
                "create-b",
                1,
                sandbox_protocol::VmSize::defaults().unwrap(),
            )
            .unwrap();
        slots.finish_allocation("b", "create-b", OperationState::Failed);
        assert_eq!(slots.held(), 0);
    }

    #[test]
    fn expiry_release_is_generation_fenced_and_exactly_once() {
        let mut slots = LiveSandboxAdmission::new(1, test_capacity());
        slots
            .try_acquire(
                "a",
                "create",
                1,
                sandbox_protocol::VmSize::defaults().unwrap(),
            )
            .unwrap();
        slots.finish_allocation("a", "create", OperationState::Succeeded);
        // A newer reconnect holds the slot: the gen-1 expiry is stale.
        slots
            .try_acquire(
                "a",
                "reconnect",
                2,
                sandbox_protocol::VmSize::defaults().unwrap(),
            )
            .unwrap();
        assert!(
            !slots.release_expired("a", 2),
            "an in-flight allocation keeps its slot"
        );
        slots.finish_allocation("a", "reconnect", OperationState::Succeeded);
        assert!(!slots.release_expired("a", 1));
        assert_eq!(slots.held(), 1);
        assert!(slots.release_expired("a", 2));
        assert!(!slots.release_expired("a", 2));
        slots
            .try_acquire(
                "b",
                "create-b",
                1,
                sandbox_protocol::VmSize::defaults().unwrap(),
            )
            .unwrap();
        assert_eq!(slots.held(), 1);
        assert!(!slots.release_expired("a", 2));
        assert_eq!(
            slots.held(),
            1,
            "a released expiry cannot free another sandbox"
        );
    }
}

#[cfg(all(test, unix))]
#[path = "weighted_admission_tests.rs"]
mod weighted_tests;

impl LiveSandboxAdmission {
    /// Single reader owns the joint live/root decision before queuing workers.
    /// Safe dimension for a refused pinned request, observed on the ordered reader.
    pub fn capacity_reason(
        &self,
        d: &sandbox_protocol::OperationDispatch,
    ) -> sandbox_protocol::capacity_v11::CapacityReason {
        use sandbox_protocol::capacity_v11::{CapacityReason as R, StorageHealth};
        let Some(a) = &d.allocation else {
            return R::Storage;
        };
        let prior = self.retained.get(&d.sandbox_id);
        let pool = self
            .pools
            .iter()
            .find(|p| p.name == a.storage_pool_name && p.marker == a.storage_marker);
        if pool.is_none_or(|p| p.health != StorageHealth::Healthy || p.draining)
            || (prior.is_none() && !self.new_root_pools.contains(&a.storage_marker))
        {
            return R::Storage;
        }
        let extra = !self.reservations.contains_key(&d.sandbox_id);
        if a.memory_mi_b > self.capacity.max_memory_mi_b().unwrap_or(0)
            || self
                .memory_held_mib()
                .unwrap_or(u64::MAX)
                .saturating_add(if extra {
                    u64::from(a.charged_memory_mi_b)
                } else {
                    0
                })
                > u64::from(self.capacity.memory_budget_mi_b)
        {
            return R::Ram;
        }
        if extra && self.held() >= self.managed_ceiling() as usize
            || prior.is_none() && self.retained.len() >= self.managed_ceiling() as usize
        {
            return R::Ceiling;
        }
        if a.cpu_count > self.capacity.max_cpu_count
            || self
                .vcpu_held()
                .saturating_add(if extra { u64::from(a.charged_vcpu) } else { 0 })
                > u64::from(self.vcpu_budget)
        {
            return R::Vcpu;
        }
        R::Disk
    }

    pub fn try_acquire_pinned(
        &mut self,
        d: &sandbox_protocol::OperationDispatch,
    ) -> Result<(), SandboxErrorCode> {
        use sandbox_protocol::capacity_v11::StorageHealth;
        let a = d
            .allocation
            .as_ref()
            .ok_or(SandboxErrorCode::ProtocolError)?;
        let size =
            VmSize::new(a.cpu_count, a.memory_mi_b).map_err(|_| SandboxErrorCode::ProtocolError)?;
        let root = super::journal::storage::allocation_root(a);
        root.validate()
            .map_err(|_| SandboxErrorCode::VmSizeMismatch)?;
        let prior = self.retained.get(&d.sandbox_id);
        if let Some(prior) = prior {
            if prior.root() != root
                || prior.allocation.root_charge_gi_b != a.root_charge_gi_b
                || prior.allocation.cpu_count != a.cpu_count
                || prior.allocation.memory_mi_b != a.memory_mi_b
            {
                return Err(SandboxErrorCode::VmSizeMismatch);
            }
            if self.reservations.contains_key(&d.sandbox_id) && prior.allocation != *a {
                return Err(SandboxErrorCode::VmSizeMismatch);
            }
        } else if d.kind != "sandbox.create" && d.restore.is_none() {
            // A restore reconnect admits a new root.
            return Err(SandboxErrorCode::VmSizeMismatch);
        }
        if !self.reservations.contains_key(&d.sandbox_id)
            && (a.charged_memory_mi_b
                != sandbox_protocol::vm_live_memory_charge_mi_b(a.memory_mi_b)
                    .map_err(|_| SandboxErrorCode::Internal)?
                || a.charged_vcpu != a.cpu_count
                || (prior.is_none()
                    && a.root_charge_gi_b
                        != sandbox_protocol::vm_root_charge_gi_b(a.disk_gi_b)
                            .map_err(|_| SandboxErrorCode::Internal)?))
        {
            return Err(SandboxErrorCode::VmSizeMismatch);
        }
        let pool = self
            .pools
            .iter()
            .find(|p| p.name == a.storage_pool_name && p.marker == a.storage_marker);
        // Omitted pools still require fresh health at the common runtime fence.
        // Their retained roots remain known; never admit a new one there.
        if pool.is_some_and(|p| p.health != StorageHealth::Healthy)
            || (pool.is_none() && prior.is_none())
        {
            return Err(SandboxErrorCode::HostCapacity);
        }
        if prior.is_none() {
            if !self.new_root_pools.contains(&a.storage_marker) {
                return Err(SandboxErrorCode::HostCapacity);
            }
            let pool = pool.ok_or(SandboxErrorCode::HostCapacity)?;
            if a.root_charge_gi_b > pool.capacity_gi_b {
                return Err(SandboxErrorCode::HostCapacity);
            }
            let used: u64 = self
                .retained
                .values()
                .filter(|r| r.allocation.storage_marker == a.storage_marker)
                .map(|r| u64::from(r.allocation.root_charge_gi_b))
                .sum();
            if pool.draining
                || self.retained.len() >= self.managed_ceiling() as usize
                || used + u64::from(a.root_charge_gi_b) > u64::from(pool.capacity_gi_b)
            {
                return Err(SandboxErrorCode::HostCapacity);
            }
        }
        self.try_acquire(&d.sandbox_id, &d.operation_id, d.generation, size)?;
        // Existing local weights were already checked against durable proof.
        if let Some(slot) = self.reservations.get_mut(&d.sandbox_id) {
            slot.charged_memory_mib = a.charged_memory_mi_b;
            slot.charged_vcpu = a.charged_vcpu;
        }
        self.retained.insert(
            d.sandbox_id.clone(),
            super::journal::storage::RetainedRoot {
                sandbox_owner_id: "owner".into(),
                allocation: a.clone(),
                generation: d.generation,
                live: true,
            },
        );
        Ok(())
    }
}

impl LiveSandboxAdmission {
    pub fn update_health(
        &mut self,
        observations: &[sandbox_protocol::capacity_v11::StorageHealthV11],
    ) {
        for pool in &mut self.pools {
            if let Some(o) = observations
                .iter()
                .find(|o| o.marker == pool.marker && o.name == pool.name)
            {
                pool.health = o.health.clone();
                pool.reason = o.reason.clone();
                pool.total_bytes = o.total_bytes;
                pool.used_bytes = o.used_bytes;
                pool.free_bytes = o.free_bytes;
            } else {
                pool.health = sandbox_protocol::capacity_v11::StorageHealth::Unavailable;
                pool.reason = Some(sandbox_protocol::capacity_v11::StorageReason::Incomplete);
            }
        }
    }
    pub fn expire_storage_health(&mut self) {
        for pool in &mut self.pools {
            pool.health = sandbox_protocol::capacity_v11::StorageHealth::Unavailable;
            pool.reason = Some(sandbox_protocol::capacity_v11::StorageReason::Io);
        }
    }
}
