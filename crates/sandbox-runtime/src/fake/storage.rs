use super::*;
use crate::storage::{root_mismatch, storage_error, validate_pool_name};
use crate::{
    RootAbsenceProof, RootDisk, StoragePoolIdentity, StoragePoolObservation, StorageResources,
    StorageRootCensus,
};

impl FakeState {
    fn observe_pool(
        &self,
        pool: &StoragePoolIdentity,
    ) -> Result<StoragePoolObservation, RuntimeError> {
        pool.validate()?;
        if self.unavailable_pools.contains(&pool.name)
            || self.storage_pools.get(&pool.name) != Some(pool)
        {
            return Err(storage_error("fake storage pool unavailable"));
        }
        Ok(StoragePoolObservation {
            pool: pool.clone(),
            driver: crate::StorageDriver::Dir,
            resources: StorageResources::new(1024 * crate::GIB_BYTES, 0)?,
        })
    }
    fn verify_root(&self, name: &str, root: &RootDisk) -> Result<(), RuntimeError> {
        root.validate()?;
        self.observe_pool(&root.pool)?;
        if self.root_disks.get(name) != Some(root) {
            return Err(root_mismatch());
        }
        Ok(())
    }
}

impl FakeRuntime {
    /// Hermetic pool availability injection; never creates a pool or marker.
    pub fn set_storage_pool_available(&self, name: &str, available: bool) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if available {
            state.unavailable_pools.remove(name);
        } else {
            state.unavailable_pools.insert(name.into());
        }
    }
    pub(super) fn fake_initialize_storage_pool(
        &self,
        name: &str,
        expected: Option<&StoragePoolIdentity>,
    ) -> Result<StoragePoolIdentity, RuntimeError> {
        validate_pool_name(name)?;
        let _permit = self.cancelled.as_ref().map(|c| c.admit()).transpose()?;
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(expected) = expected {
            expected.validate()?;
            if name != expected.name {
                return Err(root_mismatch());
            }
            return state.observe_pool(expected).map(|v| v.pool);
        }
        if state.unavailable_pools.contains(name) {
            return Err(storage_error("fake storage pool unavailable"));
        }
        if let Some(pool) = state.storage_pools.get(name) {
            return Ok(pool.clone());
        }
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes)
            .map_err(|_| storage_error("fake marker random identity unavailable"))?;
        let storage_id: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let pool = StoragePoolIdentity {
            name: name.into(),
            storage_id,
        };
        state.storage_pools.insert(name.into(), pool.clone());
        Ok(pool)
    }
    pub(super) fn fake_observe_storage_pool(
        &self,
        pool: &StoragePoolIdentity,
    ) -> Result<StoragePoolObservation, RuntimeError> {
        let _permit = self.cancelled.as_ref().map(|c| c.admit()).transpose()?;
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .observe_pool(pool)
    }
    pub(super) fn fake_storage_root_census(
        &self,
        pool: &StoragePoolIdentity,
    ) -> Result<StorageRootCensus, RuntimeError> {
        let _permit = self.cancelled.as_ref().map(|c| c.admit()).transpose()?;
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let observation = state.observe_pool(pool)?;
        let mut roots: Vec<_> = state
            .root_disks
            .iter()
            .filter(|(_, root)| &root.pool == pool)
            .map(|(name, root)| crate::RootVolume {
                instance_name: name.clone(),
                size_bytes: Some(root.size_bytes()),
            })
            .collect();
        roots.sort_by(|a, b| a.instance_name.cmp(&b.instance_name));
        Ok(StorageRootCensus { observation, roots })
    }
    pub(super) fn fake_prove_root_absent(
        &self,
        root: &RootDisk,
        name: &str,
    ) -> Result<RootAbsenceProof, RuntimeError> {
        root.validate()?;
        crate::validate_managed_instance_name(name)?;
        let _permit = self.cancelled.as_ref().map(|c| c.admit()).transpose()?;
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.observe_pool(&root.pool)?;
        if state.root_disks.contains_key(name)
            || state
                .sandboxes
                .contains_key(&name[crate::INCUS_INSTANCE_NAME_PREFIX.len()..])
        {
            return Err(root_mismatch());
        }
        Ok(RootAbsenceProof {
            pool: root.pool.clone(),
            instance_name: name.into(),
        })
    }
    pub(super) fn fake_delete_orphan_root(
        &self,
        root: &RootDisk,
        name: &str,
    ) -> Result<(), RuntimeError> {
        root.validate()?;
        crate::validate_managed_instance_name(name)?;
        let _permit = self.cancelled.as_ref().map(|c| c.admit()).transpose()?;
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.observe_pool(&root.pool)?;
        if state
            .sandboxes
            .contains_key(&name[crate::INCUS_INSTANCE_NAME_PREFIX.len()..])
        {
            return Err(root_mismatch());
        }
        if state
            .root_disks
            .get(name)
            .is_some_and(|disk| disk.pool == root.pool)
        {
            state.root_disks.remove(name);
        }
        Ok(())
    }
    /// Tests: an orphan root volume `name` on `root.pool` with no instance.
    pub fn seed_orphan_root(&self, name: &str, root: RootDisk) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .root_disks
            .insert(name.to_owned(), root);
    }
    pub(super) fn fake_create_on_storage(
        &self,
        request: &CreateSandboxRequest,
        root: &RootDisk,
    ) -> crate::EffectOutcome<CreateSandboxResponse> {
        let outcome = (|| {
            root.validate()?;
            crate::validate_managed_instance_name(&request.instance_name)?;
            if request.instance_name != crate::default_incus_instance_name(&request.sandbox_id) {
                return Err(root_mismatch().into());
            }
            // §1.5 + §2.0.5, the same table as Incus: the daemon's create
            // check before any state change, then the guard fence.
            let mode = request
                .egress_policy
                .as_ref()
                .map(|policy| policy.mode)
                .unwrap_or_default();
            // Refused before any state change: not issued, as on Incus.
            request
                .egress_admission
                .check(mode)
                .map_err(crate::before_issue::not_issued)?;
            crate::guard_probe::check_guard(self.guard_probe.as_ref())
                .map_err(crate::before_issue::not_issued)?;
            self.lifecycle("create")?;
            let _permit = self.cancelled.as_ref().map(|c| c.admit()).transpose()?;
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.observe_pool(&root.pool)?;
            if state.sandboxes.contains_key(&request.sandbox_id)
                || state.root_disks.contains_key(&request.instance_name)
            {
                state.policy_binding(&request.sandbox_id)?;
                state.verify_binding(&request.sandbox_id, Some(&request.template_digest))?;
                state.verify_root(&request.instance_name, root)?;
            } else if let Some(error) = self.injected_create_failure() {
                return Err(SimulatedFailure::completed(error));
            }
            let created = state
                .create_sandbox(request)
                .map_err(SimulatedFailure::completed)?;
            state
                .egress_modes
                .entry(request.sandbox_id.clone())
                .or_insert(mode);
            state
                .root_disks
                .insert(request.instance_name.clone(), root.clone());
            if request.refused_dns_hints {
                state
                    .refused_dns_hint_creates
                    .insert(request.sandbox_id.clone());
            }
            if !request.egress_settings.tunnel_ports.is_empty() {
                state.tunnel_targets.insert(
                    request.sandbox_id.clone(),
                    (
                        std::net::Ipv4Addr::new(10, 0, 0, 2),
                        request.egress_settings.tunnel_ports.clone(),
                    ),
                );
            }
            Ok(simulated(created))
        })();
        outcome.map_err(|error: crate::EffectError| {
            error.for_create(
                request.first_attempt,
                self.sandbox_exists(&request.sandbox_id).ok(),
            )
        })
    }
    pub(super) fn fake_reconnect_on_storage(
        &self,
        request: &ReconnectSandboxRequest,
        root: &RootDisk,
    ) -> crate::EffectOutcome<ReconnectSandboxResponse> {
        let _permit = self.cancelled.as_ref().map(|c| c.admit()).transpose()?;
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.policy_binding(&request.sandbox_id)?;
        state.verify_binding(&request.sandbox_id, Some(&request.template_fingerprint))?;
        state.verify_root(&request.instance_name, root)?;
        // §1.5 cold reconnect (the VM is stopped): the RECORDED mode and the
        // guard decide, after the read-only checks and before any change.
        // A warm reconnect (VM running) is never refused.
        if state
            .sandboxes
            .get(&request.sandbox_id)
            .is_some_and(|sandbox| sandbox.state == SandboxLifecycleState::Stopped)
        {
            let mode = state
                .egress_modes
                .get(&request.sandbox_id)
                .copied()
                .unwrap_or_default();
            request.egress_admission.check(mode)?;
            crate::guard_probe::check_guard(self.guard_probe.as_ref())?;
        }
        state
            .reconnect_sandbox(request)
            .map(simulated)
            .map_err(Into::into)
    }
    pub(super) fn fake_kill_on_storage(
        &self,
        request: &KillSandboxRequest,
        root: &RootDisk,
    ) -> crate::EffectOutcome<KillSandboxResponse> {
        root.validate()?;
        if request.instance_name != crate::default_incus_instance_name(&request.sandbox_id) {
            return Err(root_mismatch().into());
        }
        self.lifecycle("destroy")?;
        let _permit = self.cancelled.as_ref().map(|c| c.admit()).transpose()?;
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.observe_pool(&root.pool)?;
        // Size conflicts do not disable teardown, but another pool's root
        // cannot authorize deletion on the expected original pool.
        if state
            .root_disks
            .get(&request.instance_name)
            .is_some_and(|r| r.pool != root.pool)
        {
            return Err(root_mismatch().into());
        }
        let result = state
            .kill_sandbox(request)
            .map(simulated)
            .map_err(SimulatedFailure::completed);
        drop(state);
        self.ptys.close_matching(
            Some(&request.sandbox_id),
            crate::PtyCloseIntent::SandboxDestroyed,
        );
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_fake_stop_retains_binding_and_unavailable_pool_does_not_prove_absence() {
        let runtime = FakeRuntime::new();
        let pool = runtime.initialize_storage_pool("primary", None).unwrap();
        let sibling = runtime.initialize_storage_pool("sibling", None).unwrap();
        let root = RootDisk {
            pool: pool.clone(),
            disk_gi_b: sandbox_protocol::vm_size_limits()
                .unwrap()
                .disk_gi_b_default,
        };
        let request = CreateSandboxRequest::for_test("sbx-1", "create");
        runtime.create_sandbox_on_storage(&request, &root).unwrap();
        runtime.create_sandbox_on_storage(&request, &root).unwrap();
        assert_eq!(runtime.storage_root_census(&pool).unwrap().roots.len(), 1);
        runtime
            .stop_sandbox(&StopSandboxRequest {
                template_fingerprint: request.template_digest.clone(),
                sandbox_id: request.sandbox_id.clone(),
                instance_name: request.instance_name.clone(),
                operation_id: "stop".into(),
                idempotency_key: "stop".into(),
            })
            .unwrap();
        assert_eq!(runtime.storage_root_census(&pool).unwrap().roots.len(), 1);
        assert!(
            runtime
                .prove_root_absent(&root, &request.instance_name)
                .is_err()
        );
        let reconnect = ReconnectSandboxRequest {
            vm_size: request.vm_size,
            lease: request.lease.clone(),
            template_fingerprint: request.template_digest.clone(),
            architecture: request.architecture.clone(),
            guest: request.guest.clone(),
            sandbox_id: request.sandbox_id.clone(),
            instance_name: request.instance_name.clone(),
            operation_id: "resume".into(),
            idempotency_key: "resume".into(),
            egress_policy: None,
            egress_policy_hash: None,
            egress_admission: crate::egress::EgressAdmission::PERMITTED,
            guest_sudo: false,
        };
        let mut changed = root.clone();
        changed.disk_gi_b += 1;
        assert_eq!(
            runtime
                .create_sandbox_on_storage(&request, &changed)
                .unwrap_err()
                .code,
            SandboxErrorCode::VmSizeMismatch
        );
        assert_eq!(
            runtime
                .reconnect_sandbox_on_storage(&reconnect, &changed)
                .unwrap_err()
                .code,
            SandboxErrorCode::VmSizeMismatch
        );
        runtime.set_storage_pool_available(&pool.name, false);
        assert!(
            runtime
                .reconnect_sandbox_on_storage(&reconnect, &root)
                .is_err()
        );
        assert!(
            runtime
                .prove_root_absent(&root, &request.instance_name)
                .is_err()
        );
        runtime.observe_storage_pool(&sibling).unwrap();
        runtime.set_storage_pool_available(&pool.name, true);
        runtime
            .reconnect_sandbox_on_storage(&reconnect, &root)
            .unwrap();
        let kill = KillSandboxRequest {
            template_fingerprint: request.template_digest,
            sandbox_id: request.sandbox_id,
            instance_name: request.instance_name.clone(),
            operation_id: "kill".into(),
            idempotency_key: "kill".into(),
        };
        runtime.set_storage_pool_available(&pool.name, false);
        assert!(runtime.kill_sandbox_on_storage(&kill, &root).is_err());
        runtime.set_storage_pool_available(&pool.name, true);
        runtime.kill_sandbox_on_storage(&kill, &root).unwrap();
        runtime
            .prove_root_absent(&root, &request.instance_name)
            .unwrap();
        assert!(runtime.storage_root_census(&pool).unwrap().roots.is_empty());
        assert_eq!(
            runtime
                .initialize_storage_pool(&pool.name, Some(&pool))
                .unwrap(),
            pool
        );
        assert!(
            crate::UnsupportedRuntime::new()
                .prove_root_absent(&root, &request.instance_name)
                .is_err()
        );
    }
}
