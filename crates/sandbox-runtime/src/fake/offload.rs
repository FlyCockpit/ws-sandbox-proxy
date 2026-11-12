//! FakeRuntime disk offload: `publish_stopped_instance`
//! with crash points, `last_used_at` per boot, the cloud-init instance id,
//! root usage, `wssp-off-*` aliases and running Incus operations.

use std::collections::{HashMap, HashSet};

use sandbox_protocol::{SandboxErrorCode, SandboxLifecycleState};

use super::{FakeRuntime, FakeState, sha256_hex};
use crate::RuntimeError;

/// Where an injected crash interrupts the next publish (one shot).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakePublishCrash {
    /// The image landed in the store but the alias did not (an interrupted
    /// `incus publish`); the call fails.
    BeforeAlias,
    /// Image and alias both landed, then the call failed (the daemon died
    /// before it journaled the result).
    AfterAlias,
}

#[derive(Debug, Default)]
pub(super) struct FakeOffloadState {
    publishes: u32,
    /// `(instance, alias)` of every completed or crashed publish, in order.
    calls: Vec<(String, String)>,
    /// Advances at every boot (`boot_qemu`), like Incus's `last_used_at`.
    pub(super) last_used: HashMap<String, String>,
    cloud_init: HashMap<String, Option<String>>,
    root_usage: HashMap<String, Option<u64>>,
    crash: Option<FakePublishCrash>,
    running_operations: HashSet<String>,
    publish_hold: Option<std::time::Duration>,
    publishing: usize,
    /// Every offload alias listing blocks this long first (a slow Incus).
    alias_list_hold: Option<std::time::Duration>,
}

fn sandbox_of(instance_name: &str) -> Result<&str, RuntimeError> {
    crate::validate_managed_instance_name(instance_name)?;
    instance_name
        .strip_prefix(crate::INCUS_INSTANCE_NAME_PREFIX)
        .ok_or_else(|| RuntimeError::new(SandboxErrorCode::ProtocolError, "invalid instance"))
}

impl FakeState {
    pub(super) fn note_boot_for_offload(&mut self, sandbox_id: &str, boot: u64) {
        self.offload
            .last_used
            .insert(sandbox_id.to_owned(), format!("fake-boot-{boot}"));
    }
}

impl FakeRuntime {
    fn offload_state(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Tests: a stopped VM `wssp-sbx-<sandbox_id>` exists on this host.
    pub fn seed_stopped_sandbox(&self, sandbox_id: &str) {
        let mut state = self.offload_state();
        state.sandboxes.insert(
            sandbox_id.to_owned(),
            crate::SandboxRecord {
                sandbox_id: sandbox_id.to_owned(),
                generation: 1,
                state: SandboxLifecycleState::Stopped,
                idempotency_key: format!("seed-{sandbox_id}"),
            },
        );
        state
            .offload
            .last_used
            .entry(sandbox_id.to_owned())
            .or_insert_with(|| "fake-boot-seed".to_owned());
    }

    /// Tests: crash the next publish at `point`.
    pub fn crash_next_publish(&self, point: FakePublishCrash) {
        self.offload_state().offload.crash = Some(point);
    }

    /// Tests: every publish blocks this long first.
    pub fn set_publish_hold(&self, hold: Option<std::time::Duration>) {
        self.offload_state().offload.publish_hold = hold;
    }

    /// Tests: every offload alias listing blocks this long first.
    pub fn set_alias_list_hold(&self, hold: Option<std::time::Duration>) {
        self.offload_state().offload.alias_list_hold = hold;
    }

    /// Publishes currently inside their hold.
    pub fn publishes_in_flight(&self) -> usize {
        self.offload_state().offload.publishing
    }

    /// Tests: Incus reports a running operation on `instance_name`.
    pub fn set_instance_operation_running(&self, instance_name: &str, running: bool) {
        let mut state = self.offload_state();
        if running {
            state
                .offload
                .running_operations
                .insert(instance_name.to_owned());
        } else {
            state.offload.running_operations.remove(instance_name);
        }
    }

    /// Tests: override the reported root usage (`None`: not reported).
    pub fn set_root_usage(&self, sandbox_id: &str, bytes: Option<u64>) {
        self.offload_state()
            .offload
            .root_usage
            .insert(sandbox_id.to_owned(), bytes);
    }

    /// Tests: override the reported cloud-init instance id.
    pub fn set_cloud_init_instance_id(&self, sandbox_id: &str, id: Option<&str>) {
        self.offload_state()
            .offload
            .cloud_init
            .insert(sandbox_id.to_owned(), id.map(str::to_owned));
    }

    /// `(instance, alias)` of every publish so far.
    pub fn publish_calls(&self) -> Vec<(String, String)> {
        self.offload_state().offload.calls.clone()
    }

    /// The fingerprint an alias names, if any.
    pub fn alias_target(&self, alias: &str) -> Option<String> {
        self.offload_state()
            .image_aliases
            .get(alias)
            .map(|(fp, _)| fp.clone())
    }

    pub(super) fn fake_publish_stopped_instance(
        &self,
        instance_name: &str,
        alias: &str,
    ) -> Result<crate::PublishedDisk, RuntimeError> {
        crate::validate_offload_alias(alias)?;
        let sandbox_id = sandbox_of(instance_name)?.to_owned();
        let hold = {
            let mut state = self.offload_state();
            match state.sandboxes.get(&sandbox_id).map(|s| s.state) {
                None => {
                    return Err(RuntimeError::new(
                        SandboxErrorCode::SandboxNotFound,
                        "instance not found",
                    ));
                }
                Some(SandboxLifecycleState::Stopped) => {}
                Some(_) => {
                    return Err(RuntimeError::new(
                        SandboxErrorCode::StateConflict,
                        "instance is not stopped",
                    ));
                }
            }
            if state.image_aliases.contains_key(alias) {
                return Err(RuntimeError::new(
                    SandboxErrorCode::StateConflict,
                    "image alias already exists",
                ));
            }
            state.offload.publishing += 1;
            state.offload.publish_hold
        };
        if let Some(hold) = hold {
            std::thread::sleep(hold);
        }
        let mut state = self.offload_state();
        state.offload.publishing -= 1;
        state.offload.publishes += 1;
        state
            .offload
            .calls
            .push((instance_name.to_owned(), alias.to_owned()));
        let bytes = format!("fake-offload:{sandbox_id}:{}", state.offload.publishes).into_bytes();
        let fp = format!("sha256:{}", sha256_hex(&bytes));
        state.images.insert(
            fp.clone(),
            ("x86_64".into(), crate::GuestIdentity::default(), true),
        );
        state.image_sizes.insert(fp.clone(), bytes.len() as u64);
        let size = bytes.len() as u64;
        state.image_bytes.insert(fp.clone(), bytes);
        let crash = state.offload.crash.take();
        if crash != Some(FakePublishCrash::BeforeAlias) {
            state
                .image_aliases
                .insert(alias.to_owned(), (fp.clone(), "x86_64".into()));
        }
        if crash.is_some() {
            return Err(RuntimeError::new(
                SandboxErrorCode::Internal,
                "fake publish crash",
            ));
        }
        Ok(crate::PublishedDisk {
            fingerprint: fp,
            size_bytes: Some(size),
        })
    }

    pub(super) fn fake_instance_last_used(
        &self,
        instance_name: &str,
    ) -> Result<Option<String>, RuntimeError> {
        let sandbox_id = sandbox_of(instance_name)?;
        let state = self.offload_state();
        if !state.sandboxes.contains_key(sandbox_id) {
            return Err(RuntimeError::new(
                SandboxErrorCode::SandboxNotFound,
                "instance not found",
            ));
        }
        Ok(state.offload.last_used.get(sandbox_id).cloned())
    }

    pub(super) fn fake_cloud_init_instance_id(
        &self,
        instance_name: &str,
    ) -> Result<Option<String>, RuntimeError> {
        let sandbox_id = sandbox_of(instance_name)?;
        let state = self.offload_state();
        Ok(state
            .offload
            .cloud_init
            .get(sandbox_id)
            .cloned()
            .unwrap_or_else(|| Some(format!("fake-cloud-init-{sandbox_id}"))))
    }

    pub(super) fn fake_instance_root_usage(
        &self,
        instance_name: &str,
    ) -> Result<Option<u64>, RuntimeError> {
        let sandbox_id = sandbox_of(instance_name)?;
        let state = self.offload_state();
        Ok(state
            .offload
            .root_usage
            .get(sandbox_id)
            .copied()
            .unwrap_or(Some(1 << 20)))
    }

    pub(super) fn fake_offload_aliases(&self) -> Result<Vec<crate::OffloadAlias>, RuntimeError> {
        let hold = self.offload_state().offload.alias_list_hold;
        if let Some(hold) = hold {
            std::thread::sleep(hold);
        }
        let state = self.offload_state();
        let mut aliases: Vec<crate::OffloadAlias> = state
            .image_aliases
            .iter()
            .filter(|(alias, _)| crate::validate_offload_alias(alias).is_ok())
            .map(|(alias, (fp, _))| crate::OffloadAlias {
                alias: alias.clone(),
                fingerprint: fp.clone(),
            })
            .collect();
        aliases.sort_by(|a, b| a.alias.cmp(&b.alias));
        Ok(aliases)
    }

    pub(super) fn fake_instance_operation_running(
        &self,
        instance_name: &str,
    ) -> Result<bool, RuntimeError> {
        crate::validate_managed_instance_name(instance_name)?;
        Ok(self
            .offload_state()
            .offload
            .running_operations
            .contains(instance_name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SandboxRuntime;

    #[test]
    fn publish_requires_a_stopped_instance_and_sets_the_alias() {
        let runtime = FakeRuntime::new();
        let missing = runtime
            .publish_stopped_instance("wssp-sbx-a", "wssp-off-o1")
            .unwrap_err();
        assert_eq!(missing.code, SandboxErrorCode::SandboxNotFound);
        runtime.seed_stopped_sandbox("a");
        let published = runtime
            .publish_stopped_instance("wssp-sbx-a", "wssp-off-o1")
            .unwrap();
        assert_eq!(
            runtime.alias_target("wssp-off-o1").as_deref(),
            Some(published.fingerprint.as_str())
        );
        assert_eq!(
            runtime.offload_aliases().unwrap(),
            [crate::OffloadAlias {
                alias: "wssp-off-o1".into(),
                fingerprint: published.fingerprint.clone(),
            }]
        );
        // Deleting the image deletes its alias, as in Incus.
        runtime.delete_image(&published.fingerprint).unwrap();
        assert!(runtime.offload_aliases().unwrap().is_empty());
        assert!(
            runtime
                .publish_stopped_instance("wssp-sbx-a", "not-an-offload")
                .is_err()
        );
    }

    #[test]
    fn crash_points_leave_the_image_with_or_without_its_alias() {
        let runtime = FakeRuntime::new();
        runtime.seed_stopped_sandbox("a");
        let before = runtime.list_image_fingerprints().unwrap().len();
        runtime.crash_next_publish(FakePublishCrash::BeforeAlias);
        assert!(
            runtime
                .publish_stopped_instance("wssp-sbx-a", "wssp-off-o1")
                .is_err()
        );
        assert!(runtime.offload_aliases().unwrap().is_empty());
        assert_eq!(runtime.list_image_fingerprints().unwrap().len(), before + 1);
        runtime.crash_next_publish(FakePublishCrash::AfterAlias);
        assert!(
            runtime
                .publish_stopped_instance("wssp-sbx-a", "wssp-off-o2")
                .is_err()
        );
        assert_eq!(runtime.offload_aliases().unwrap().len(), 1);
        // One shot: the next publish succeeds.
        assert!(
            runtime
                .publish_stopped_instance("wssp-sbx-a", "wssp-off-o3")
                .is_ok()
        );
    }

    #[test]
    fn facts_and_operations_are_reported() {
        let runtime = FakeRuntime::new();
        runtime.seed_stopped_sandbox("a");
        assert_eq!(
            runtime.instance_last_used("wssp-sbx-a").unwrap().as_deref(),
            Some("fake-boot-seed")
        );
        assert_eq!(
            runtime
                .cloud_init_instance_id("wssp-sbx-a")
                .unwrap()
                .as_deref(),
            Some("fake-cloud-init-a")
        );
        runtime.set_root_usage("a", None);
        assert_eq!(runtime.instance_root_usage("wssp-sbx-a").unwrap(), None);
        assert!(!runtime.instance_operation_running("wssp-sbx-a").unwrap());
        runtime.set_instance_operation_running("wssp-sbx-a", true);
        assert!(runtime.instance_operation_running("wssp-sbx-a").unwrap());
    }
}
