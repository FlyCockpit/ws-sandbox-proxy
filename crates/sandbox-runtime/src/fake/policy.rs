//! Deterministic daemon drift model. Never advertises packet enforcement.
use super::*;
use crate::reconcile::{POLICY_BATCH_MAX, PolicyJournal, PolicyObservation};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakePolicyDrift {
    Acl,
    Network,
    Nic,
    Inconclusive,
    Foreign,
}

#[derive(Debug, Default)]
pub(super) struct FakePolicy {
    pub journal: PolicyJournal,
    pub lifecycle: Option<Arc<dyn crate::EnforcementLossLifecycle>>,
    dir: Option<PathBuf>,
    losses: BTreeSet<String>,
}

fn io_error(error: impl std::fmt::Display) -> RuntimeError {
    RuntimeError::new(
        SandboxErrorCode::Internal,
        format!("fake policy journal: {error}"),
    )
}

/// Crash-durable fake fixture state, separate from its simulated daemon. The
/// production Incus path uses the existing write_durable_record boundary.
fn write_record(dir: &Path, name: &str, body: &[u8]) -> Result<(), RuntimeError> {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    // E-16: owner-only state, like the Incus host journal.
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir).map_err(io_error)?;
    let tmp = dir.join(format!(
        ".policy-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp).map_err(io_error)?;
        file.write_all(body).map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        std::fs::rename(&tmp, dir.join(name)).map_err(io_error)?;
        std::fs::File::open(dir)
            .and_then(|f| f.sync_all())
            .map_err(io_error)
    })();
    let _ = std::fs::remove_file(tmp);
    result
}

impl FakePolicy {
    fn persist(&self) -> Result<(), RuntimeError> {
        if let Some(dir) = &self.dir {
            write_record(
                dir,
                "state.json",
                &serde_json::to_vec(&self.journal).map_err(io_error)?,
            )?;
        }
        Ok(())
    }
    fn loss(&mut self, id: &str) -> Result<(), RuntimeError> {
        // Retain retry intent in memory even on storage failure, as C37 does.
        self.losses.insert(id.to_owned());
        if let Some(dir) = &self.dir {
            write_record(
                &dir.join("enforcement-losses"),
                &format!("{id}.json"),
                b"{}",
            )?;
        }
        Ok(())
    }
    fn clear(&mut self, id: &str) -> Result<(), RuntimeError> {
        if let Some(dir) = &self.dir {
            let path = dir.join("enforcement-losses").join(format!("{id}.json"));
            match std::fs::remove_file(path) {
                Ok(()) => std::fs::File::open(dir.join("enforcement-losses"))
                    .and_then(|f| f.sync_all())
                    .map_err(io_error)?,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(io_error(err)),
            }
        }
        self.losses.remove(id);
        Ok(())
    }
}

impl FakeRuntime {
    pub fn inject_policy_drift(&self, id: &str, drift: Option<FakePolicyDrift>) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(drift) = drift {
            state.policy_drift.insert(id.to_owned(), drift);
        } else {
            state.policy_drift.remove(id);
        }
    }

    pub fn with_policy_state_dir(self, dir: PathBuf) -> Result<Self, RuntimeError> {
        let mut policy = self.policy.lock().unwrap_or_else(|e| e.into_inner());
        policy.journal = match std::fs::read(dir.join("state.json")) {
            Ok(body) => serde_json::from_slice(&body).map_err(io_error)?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => PolicyJournal::default(),
            Err(err) => return Err(io_error(err)),
        };
        match std::fs::read_dir(dir.join("enforcement-losses")) {
            Ok(entries) => {
                for entry in entries {
                    let entry = entry.map_err(io_error)?;
                    if let Some(id) = entry.path().file_stem().and_then(|s| s.to_str())
                        && crate::validate_managed_instance_name(
                            &crate::default_incus_instance_name(id),
                        )
                        .is_ok()
                    {
                        policy.losses.insert(id.to_owned());
                    }
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(io_error(err)),
        }
        policy.dir = Some(dir);
        *self.policy_health.lock().unwrap_or_else(|e| e.into_inner()) =
            policy.journal.health.clone();
        drop(policy);
        Ok(self)
    }

    /// Simulates restarting the node daemon while the external fake Incus daemon survives.
    /// Reconciler memory and lifecycle authority are discarded; recovery MUST
    /// reload its durable journal and the caller must reinstall authority.
    pub fn restart_policy_reconciler(&self) -> Result<Self, RuntimeError> {
        let dir = self
            .policy
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .dir
            .clone();
        let runtime = Self {
            policy: Default::default(),
            policy_health: Default::default(),
            ..self.clone()
        };
        if let Some(dir) = dir {
            runtime.with_policy_state_dir(dir)
        } else {
            Ok(runtime)
        }
    }

    fn policy_evidence(&self, id: &str) -> PolicyObservation {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if !state.sandboxes.contains_key(id) {
            return PolicyObservation::Absent;
        }
        match state.policy_drift.get(id) {
            None => PolicyObservation::Verified,
            Some(FakePolicyDrift::Inconclusive) => PolicyObservation::Inconclusive,
            Some(FakePolicyDrift::Foreign) => PolicyObservation::Foreign,
            Some(_) => PolicyObservation::Drift,
        }
    }

    fn policy_stop(&self, id: &str) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.policy_drift.get(id) != Some(&FakePolicyDrift::Foreign)
            && let Some(row) = state.sandboxes.get_mut(id)
        {
            row.state = SandboxLifecycleState::Stopped;
        }
    }

    pub(super) fn inspect_policies(&self, ids: &[String]) -> Result<(), RuntimeError> {
        let mut policy = self.policy.lock().unwrap_or_else(|e| e.into_inner());
        let mut journal = std::mem::take(&mut policy.journal);
        let mut first_error = None;
        journal.inspect(ids, |id| {
            let mut intent = policy.lifecycle.as_ref().map(|l| l.capture(id));
            if self.lifecycle(&format!("policy-observe:{id}")).is_err() {
                return PolicyObservation::Inconclusive;
            }
            let verdict = self.policy_evidence(id);
            if verdict != PolicyObservation::Drift {
                return verdict;
            }
            if let Some(Err(err)) = intent.as_ref().map(|i| i.prepare()) {
                self.policy_stop(id);
                if err.code == SandboxErrorCode::IdempotencyConflict {
                    intent = policy.lifecycle.as_ref().map(|l| l.capture(id));
                    // Fresh evidence, not adoption of the stale verdict.
                    if self.policy_evidence(id) != PolicyObservation::Drift {
                        return PolicyObservation::Inconclusive;
                    }
                    if let Some(Err(err)) = intent.as_ref().map(|i| i.prepare()) {
                        first_error.get_or_insert(err);
                    }
                } else {
                    first_error.get_or_insert(err);
                }
            }
            if let Err(err) = policy.loss(id) {
                first_error.get_or_insert(err);
            }
            self.policy_stop(id);
            PolicyObservation::Drift
        });
        policy.journal = journal;
        *self.policy_health.lock().unwrap_or_else(|e| e.into_inner()) =
            policy.journal.health.clone();
        if let Err(err) = policy.persist() {
            first_error.get_or_insert(err);
        }
        first_error.map_or(Ok(()), Err)
    }

    pub(super) fn drain_policy_losses(
        &self,
        settle: &dyn Fn(&str, crate::EnforcementLossStage) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        let mut policy = self.policy.lock().unwrap_or_else(|e| e.into_inner());
        let ids: Vec<_> = policy.losses.iter().cloned().collect();
        let start = ids
            .iter()
            .position(|id| id > &policy.journal.cursor)
            .unwrap_or(0);
        let mut first_error = None;
        for id in ids[start..]
            .iter()
            .chain(ids[..start].iter())
            .take(POLICY_BATCH_MAX)
        {
            policy.journal.cursor = id.clone();
            let result = (|| {
                match self.policy_evidence(id) {
                    PolicyObservation::Inconclusive
                    | PolicyObservation::Foreign
                    | PolicyObservation::Pending => return Ok(()),
                    PolicyObservation::Verified => return policy.clear(id),
                    PolicyObservation::Drift | PolicyObservation::Absent => {}
                }
                settle(id, crate::EnforcementLossStage::Prepare)?;
                // Durable Prepare precedes deletion; current positive ownership
                // is checked again at the mutation boundary.
                self.lifecycle(&format!("policy-destroy:{id}"))?;
                if !matches!(
                    self.policy_evidence(id),
                    PolicyObservation::Drift | PolicyObservation::Absent
                ) {
                    return Ok(());
                }
                self.state
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .sandboxes
                    .remove(id);
                settle(id, crate::EnforcementLossStage::Complete)?;
                policy.clear(id)
            })();
            if let Err(err) = result {
                first_error.get_or_insert(err);
            }
        }
        if let Err(err) = policy.persist() {
            first_error.get_or_insert(err);
        }
        first_error.map_or(Ok(()), Err)
    }
}
