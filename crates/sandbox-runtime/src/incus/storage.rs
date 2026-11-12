//! Incus 7.5.1 storage boundary. No host-path access, pool provisioning,
//! metadata updates, marker repair, cache bookkeeping or guest attachment.
use super::client::{IncusClient, QueryEnvelope, parse_query_envelope, with_query_params};
use crate::storage::{root_mismatch, storage_error, validate_pool_name};
use crate::{
    PhysicalUsage, RootAbsenceProof, RootDisk, RootVolume, RuntimeError, STORAGE_MARKER_VOLUME,
    StorageDriver, StoragePoolIdentity, StoragePoolObservation, StorageResources,
    StorageRootCensus,
};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::time::{Duration, Instant};

const MARKER_KEY: &str = "user.wssp.storage-id";
const MARKER_FILE: &str = "wssp-pool-marker/storage-id";
const WALK_MAX: usize = 10_000;
const MARKER_WAIT: Duration = Duration::from_secs(2);

impl IncusClient {
    fn storage_path(&self, pool: &str, suffix: &str) -> Result<String, RuntimeError> {
        validate_pool_name(pool)?;
        super::client::validate_incus_identifier(&self.project, "project")?;
        Ok(with_query_params(
            &format!("/1.0/storage-pools/{pool}{suffix}"),
            &[("project", &self.project)],
        ))
    }

    fn storage_failure(&self, pool: &str) -> RuntimeError {
        storage_error(&format!(
            "storage pool `{pool}` in project `{}` is unavailable or its marker is incomplete; verify custom-volume/file rights and restore the original marker/backing storage; incomplete initialization requires operator inspection and zero-binding proof before recreation",
            self.project
        ))
    }

    /// Existing project sharing is never changed. Incus's default project
    /// always owns custom volumes, even when its feature key is absent.
    pub(super) fn verify_project_storage_volumes(&self) -> Result<(), RuntimeError> {
        let metadata = self.query_raw(&with_query_params(
            &format!(
                "/1.0/projects/{}",
                super::client::percent_encode(&self.project)
            ),
            &[("project", "default")],
        ))?;
        let config = metadata
            .get("config")
            .and_then(Value::as_object)
            .ok_or_else(|| storage_error("project custom-volume configuration is unavailable"))?;
        let owns = config
            .get("features.storage.volumes")
            .and_then(Value::as_str);
        if owns == Some("true") || (self.project == "default" && owns.is_none()) {
            Ok(())
        } else {
            Err(storage_error(&format!(
                "project `{}` must own custom volumes (features.storage.volumes=true); restore project isolation without sharing marker volumes",
                self.project
            )))
        }
    }

    fn marker_metadata(&self, pool: &str) -> Result<Value, RuntimeError> {
        let path = self.storage_path(pool, &format!("/volumes/custom/{STORAGE_MARKER_VOLUME}"))?;
        let out = self.read_bounded(&["query", "--raw", &path], self.agent_timeout, 1024 * 1024)?;
        match parse_query_envelope(&out) {
            QueryEnvelope::Sync(metadata) => Ok(metadata),
            QueryEnvelope::Error((404, _)) => Err(self.storage_failure(pool).storage_missing()),
            _ => Err(self.storage_failure(pool)),
        }
    }

    fn marker_identity(
        &self,
        pool: &str,
        metadata: &Value,
    ) -> Result<StoragePoolIdentity, RuntimeError> {
        if metadata.get("name").and_then(Value::as_str) != Some(STORAGE_MARKER_VOLUME)
            || metadata.get("type").and_then(Value::as_str) != Some("custom")
            || metadata.get("content_type").and_then(Value::as_str) != Some("filesystem")
        {
            return Err(self.storage_failure(pool));
        }
        let id = metadata
            .get("config")
            .and_then(|v| v.get(MARKER_KEY))
            .and_then(Value::as_str)
            .ok_or_else(|| self.storage_failure(pool))?;
        let identity = StoragePoolIdentity {
            name: pool.into(),
            storage_id: id.into(),
        };
        identity
            .validate()
            .map_err(|_| self.storage_failure(pool))?;
        Ok(identity)
    }

    /// Metadata -> bounded backing-file read -> full metadata equality. No
    /// ETag is fabricated: this API never updates volume metadata.
    pub fn read_storage_marker(&self, pool: &str) -> Result<StoragePoolIdentity, RuntimeError> {
        validate_pool_name(pool)?;
        self.verify_project_storage_volumes()?;
        let first = self.marker_metadata(pool)?;
        let identity = self.marker_identity(pool, &first)?;
        let file = self
            .read_bounded(
                &["storage", "volume", "file", "pull", pool, MARKER_FILE, "-"],
                self.agent_timeout,
                512,
            )
            .map_err(|_| self.storage_failure(pool))?;
        // Only the daemon's explicit ENOENT is absence. Permission, transport
        // and unavailable-pool errors retain the generic IO classification.
        if file.exit_code != 0
            && (file.stderr.contains("no such file or directory")
                || file.stderr.contains("File not found")
                || file.stderr.trim() == "Error: file does not exist")
        {
            return Err(self.storage_failure(pool).storage_missing());
        }
        if file.exit_code != 0 || file.stdout != marker_content(&identity.storage_id) {
            return Err(self.storage_failure(pool));
        }
        let second = self.marker_metadata(pool)?;
        if first != second {
            return Err(self.storage_failure(pool));
        }
        Ok(identity)
    }

    /// Connect only, under the same daemon allocation lock as subnet claims.
    /// `expected` means bound lineage: absence NEVER authorizes recreation.
    /// The custom volume is retained independently of every sandbox.
    pub fn initialize_storage_marker(
        &self,
        pool: &str,
        expected: Option<&StoragePoolIdentity>,
    ) -> Result<StoragePoolIdentity, RuntimeError> {
        validate_pool_name(pool)?;
        if let Some(expected) = expected {
            expected.validate()?;
            if expected.name != pool {
                return Err(root_mismatch());
            }
            let observed = self.read_storage_marker(pool)?;
            return if &observed == expected {
                Ok(observed)
            } else {
                Err(self.storage_failure(pool))
            };
        }
        let _allocation = self.lock_subnet_allocation()?;
        self.verify_project_storage_volumes()?;
        // A successful metadata GET (even incomplete) is existing lineage.
        // Only an exact 404 allows POST; denied/transport errors never do.
        let path = self.storage_path(pool, &format!("/volumes/custom/{STORAGE_MARKER_VOLUME}"))?;
        let out = self.read_bounded(&["query", "--raw", &path], self.agent_timeout, 1024 * 1024)?;
        match parse_query_envelope(&out) {
            QueryEnvelope::Sync(_) => return self.wait_storage_marker(pool),
            QueryEnvelope::Error((404, _)) => {}
            _ => return Err(self.storage_failure(pool)),
        }
        // The pool must exist and be supported before any marker effect.
        self.storage_resources(pool)?;
        let id = super::client::random_nonce()?;
        let body = json!({"name": STORAGE_MARKER_VOLUME, "type":"custom", "content_type":"filesystem", "config":{"size":"1GiB", MARKER_KEY:id}}).to_string();
        let path = self.storage_path(pool, "/volumes/custom")?;
        // Small JSON body is safe inline. No retry after ambiguous POST.
        let out = self
            .run(&["query", "--raw", "-X", "POST", "-d", &body, &path], false)
            .map_err(|_| self.storage_failure(pool))?;
        match parse_query_envelope(&out) {
            QueryEnvelope::Sync(_) if out.exit_code == 0 => {
                // Only the positive creator may write. Verify identity again
                // before writing; a replaced volume is never initialized.
                let metadata = self.marker_metadata(pool)?;
                let created = self.marker_identity(pool, &metadata)?;
                if created.storage_id != id {
                    return Err(self.storage_failure(pool));
                }
                let content = marker_content(&id);
                let pushed = self
                    .run_with_stdin_timed(
                        &[
                            "storage",
                            "volume",
                            "file",
                            "push",
                            "--mode",
                            "0600",
                            "-",
                            pool,
                            MARKER_FILE,
                        ],
                        content.as_bytes(),
                        false,
                        self.agent_timeout,
                    )
                    .map_err(|_| self.storage_failure(pool))?;
                if pushed.exit_code != 0 {
                    return Err(self.storage_failure(pool));
                }
                let readback = self.read_storage_marker(pool)?;
                if readback != created {
                    return Err(self.storage_failure(pool));
                }
                Ok(readback)
            }
            QueryEnvelope::Error((409, _)) => {
                // Independent creators never overwrite or take over.
                self.wait_storage_marker(pool)
            }
            _ => Err(self.storage_failure(pool)),
        }
    }

    fn wait_storage_marker(&self, pool: &str) -> Result<StoragePoolIdentity, RuntimeError> {
        let budget = MARKER_WAIT.min(self.agent_timeout);
        let permit = match &self.cancelled {
            Some(parent) => crate::RuntimePermit::child(parent.clone(), budget),
            None => crate::RuntimePermit::with_timeout(budget),
        };
        let reader = Self {
            cancelled: Some(std::sync::Arc::new(permit)),
            ..self.clone()
        };
        let deadline = Instant::now() + budget;
        loop {
            if let Ok(winner) = reader.read_storage_marker(pool) {
                return Ok(winner);
            }
            if Instant::now() >= deadline {
                return Err(self.storage_failure(pool));
            }
            if let Some(permit) = &reader.cancelled {
                let _guard = permit.admit().map_err(|_| self.storage_failure(pool))?;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    /// Read-only resource inspection, usable without runtime construction.
    pub fn storage_resources(
        &self,
        pool: &str,
    ) -> Result<(StorageDriver, StorageResources), RuntimeError> {
        let metadata = self.query_raw(&self.storage_path(pool, "")?)?;
        let driver = match metadata.get("driver").and_then(Value::as_str) {
            Some("dir") => StorageDriver::Dir,
            Some("lvm") => StorageDriver::Lvm,
            Some("zfs") => StorageDriver::Zfs,
            Some("btrfs") => StorageDriver::Btrfs,
            _ => return Err(self.storage_failure(pool)),
        };
        // Global status must be Created; explicit Pending/Unavailable fails.
        if metadata.get("status").and_then(Value::as_str) != Some("Created") {
            return Err(self.storage_failure(pool));
        }
        let value = self.query_raw(&self.storage_path(pool, "/resources")?)?;
        let total = value
            .pointer("/space/total")
            .and_then(Value::as_u64)
            .ok_or_else(|| self.storage_failure(pool))?;
        let used = value
            .pointer("/space/used")
            .and_then(Value::as_u64)
            .ok_or_else(|| self.storage_failure(pool))?;
        Ok((driver, StorageResources::new(total, used)?))
    }

    pub fn observe_storage_pool(
        &self,
        expected: &StoragePoolIdentity,
    ) -> Result<StoragePoolObservation, RuntimeError> {
        expected.validate()?;
        if self.read_storage_marker(&expected.name)? != *expected {
            return Err(self.storage_failure(&expected.name));
        }
        let (driver, resources) = self.storage_resources(&expected.name)?;
        // A pool lost/swapped during resource IO cannot publish health.
        if self.read_storage_marker(&expected.name)? != *expected {
            return Err(self.storage_failure(&expected.name));
        }
        Ok(StoragePoolObservation {
            pool: expected.clone(),
            driver,
            resources,
        })
    }

    /// Census only VM root volumes in this project; marker, native images,
    /// containers, snapshots and unrelated custom volumes are excluded.
    pub fn storage_root_census(
        &self,
        pool: &StoragePoolIdentity,
    ) -> Result<StorageRootCensus, RuntimeError> {
        self.observe_storage_pool(pool)?;
        let path = self.storage_path(&pool.name, "/volumes")?;
        let value = self.query_raw(&format!("{path}&recursion=1"))?;
        let rows = value
            .as_array()
            .filter(|v| v.len() <= WALK_MAX)
            .ok_or_else(|| self.storage_failure(&pool.name))?;
        let mut roots = Vec::new();
        let mut seen = HashSet::new();
        for row in rows {
            if row.get("type").and_then(Value::as_str) != Some("virtual-machine") {
                continue;
            }
            let name = row
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| self.storage_failure(&pool.name))?;
            if !name.starts_with(crate::INCUS_INSTANCE_NAME_PREFIX) || name.contains('/') {
                continue;
            }
            crate::validate_managed_instance_name(name)?;
            if row
                .get("project")
                .and_then(Value::as_str)
                .is_some_and(|p| p != self.project)
                || !seen.insert(name)
            {
                return Err(self.storage_failure(&pool.name));
            }
            roots.push(RootVolume {
                instance_name: name.into(),
                size_bytes: row
                    .pointer("/config/size")
                    .and_then(Value::as_str)
                    .and_then(volume_size_bytes),
            });
        }
        roots.sort_by(|a, b| a.instance_name.cmp(&b.instance_name));
        Ok(StorageRootCensus {
            observation: self.observe_storage_pool(pool)?,
            roots,
        })
    }

    /// Credit only the listed charged roots. Never substitute configured size
    /// for physical allocation. Dir quota and btrfs qgroup figures are not
    /// trusted as physical VM bytes (shared extents/compression). Thick LVM
    /// and unsupported state queries also receive zero credit.
    pub fn storage_physical_usage(
        &self,
        pool: &StoragePoolIdentity,
        charged_roots: &[String],
        commitments_bytes: u64,
    ) -> Result<PhysicalUsage, RuntimeError> {
        if charged_roots.len() > WALK_MAX {
            return Err(self.storage_failure(&pool.name));
        }
        let observation = self.observe_storage_pool(pool)?;
        let metadata = self.query_raw(&self.storage_path(&pool.name, "")?)?;
        let trusted = match observation.driver {
            StorageDriver::Lvm => {
                metadata
                    .pointer("/config/lvm.use_thinpool")
                    .and_then(Value::as_str)
                    != Some("false")
            }
            StorageDriver::Zfs => true, // daemon GetInstanceUsage uses ZFS `used`, not provisioned volsize
            _ => false,
        };
        let mut measured = 0_u128;
        let mut seen = HashSet::new();
        let mut complete = trusted;
        for name in charged_roots {
            crate::validate_managed_instance_name(name)?;
            if !seen.insert(name) {
                return Err(self.storage_failure(&pool.name));
            }
            if !trusted {
                continue;
            }
            let path = self.storage_path(
                &pool.name,
                &format!("/volumes/virtual-machine/{name}/state"),
            )?;
            match self
                .query_raw(&path)
                .ok()
                .and_then(|v| v.pointer("/usage/used").and_then(Value::as_u64))
            {
                Some(used) => measured += u128::from(used),
                None => complete = false,
            }
        }
        self.observe_storage_pool(pool)?;
        Ok(PhysicalUsage {
            charged_bytes: if complete {
                measured.min(u128::from(commitments_bytes)) as u64
            } else {
                0
            },
            trusted: complete,
        })
    }

    pub fn prove_root_absent(
        &self,
        expected: &RootDisk,
        instance_name: &str,
    ) -> Result<RootAbsenceProof, RuntimeError> {
        expected.validate()?;
        crate::validate_managed_instance_name(instance_name)?;
        self.observe_storage_pool(&expected.pool)?;
        if self.instance_exists(instance_name)? {
            return Err(root_mismatch());
        }
        let census = self.storage_root_census(&expected.pool)?;
        if census
            .roots
            .iter()
            .any(|root| root.instance_name == instance_name)
        {
            return Err(root_mismatch());
        }
        // Recheck both sides: absence is not inferred from a VM-only 404.
        if self.instance_exists(instance_name)? {
            return Err(root_mismatch());
        }
        self.observe_storage_pool(&expected.pool)?;
        Ok(RootAbsenceProof {
            pool: expected.pool.clone(),
            instance_name: instance_name.into(),
        })
    }

    pub fn with_root_disk(&self, root: &RootDisk) -> Result<Self, RuntimeError> {
        root.validate()?;
        Ok(Self {
            expected_root: Some(root.clone()),
            ..self.clone()
        })
    }

    pub(super) fn verify_expected_root(&self, name: &str) -> Result<(), RuntimeError> {
        if let Some(root) = &self.expected_root {
            self.verify_root_disk(name, root)?;
        }
        Ok(())
    }

    pub fn verify_root_disk(&self, name: &str, root: &RootDisk) -> Result<(), RuntimeError> {
        root.validate()?;
        crate::validate_managed_instance_name(name)?;
        self.observe_storage_pool(&root.pool)?;
        let metadata = self.query_raw(&with_query_params(
            &format!("/1.0/instances/{name}"),
            &[("project", &self.project)],
        ))?;
        if metadata.get("type").and_then(Value::as_str) != Some("virtual-machine") {
            return Err(root_mismatch());
        }
        let (device_name, effective) =
            root_device(metadata.get("expanded_devices").ok_or_else(root_mismatch)?)?;
        let local = metadata
            .get("devices")
            .and_then(|v| v.get(device_name))
            .ok_or_else(root_mismatch)?;
        for device in [effective, local] {
            validate_root_keys(device)?;
            if device.get("pool").and_then(Value::as_str) != Some(&root.pool.name)
                || device.get("size").and_then(Value::as_str)
                    != Some(format!("{}GiB", root.disk_gi_b).as_str())
            {
                return Err(root_mismatch());
            }
        }
        let volume = self.query_raw(
            &self.storage_path(&root.pool.name, &format!("/volumes/virtual-machine/{name}"))?,
        )?;
        if volume.get("name").and_then(Value::as_str) != Some(name)
            || volume.get("type").and_then(Value::as_str) != Some("virtual-machine")
            || volume.get("content_type").and_then(Value::as_str) != Some("block")
        {
            return Err(root_mismatch());
        }
        // Incus enforces the LOCAL root override and reports its effective
        // allocation through volume state, including when volume config is {}.
        let state = self.query_raw(&self.storage_path(
            &root.pool.name,
            &format!("/volumes/virtual-machine/{name}/state"),
        )?)?;
        let volume_bytes = state
            .pointer("/usage/total")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                storage_error("root volume size evidence is unavailable; refusing start")
            })?;
        if volume_bytes != root.size_bytes() {
            return Err(root_mismatch());
        }
        self.observe_storage_pool(&root.pool)?;
        Ok(())
    }
}

fn marker_content(id: &str) -> String {
    format!("wssp-storage-v1\n{id}\n")
}

pub(super) fn validate_root_keys(device: &Value) -> Result<(), RuntimeError> {
    let keys = device.as_object().ok_or_else(root_mismatch)?;
    if keys
        .keys()
        .any(|k| !matches!(k.as_str(), "type" | "path" | "pool" | "size"))
        || device.get("type").and_then(Value::as_str) != Some("disk")
        || device.get("path").and_then(Value::as_str) != Some("/")
        || !device
            .get("pool")
            .and_then(Value::as_str)
            .is_some_and(|s| validate_pool_name(s).is_ok())
        || device
            .get("size")
            .is_some_and(|v| v.as_str().and_then(volume_size_bytes).is_none())
    {
        return Err(root_mismatch());
    }
    Ok(())
}

pub(super) fn root_device(devices: &Value) -> Result<(&str, &Value), RuntimeError> {
    let mut roots = devices
        .as_object()
        .ok_or_else(root_mismatch)?
        .iter()
        .filter(|(_, v)| {
            v.get("type").and_then(Value::as_str) == Some("disk")
                && v.get("path").and_then(Value::as_str) == Some("/")
        });
    let (name, device) = roots.next().ok_or_else(root_mismatch)?;
    if roots.next().is_some() {
        return Err(root_mismatch());
    }
    validate_root_keys(device)?;
    super::client::validate_incus_identifier(name, "root device")?;
    Ok((name, device))
}

// Incus volume metadata may serialize bytes or IEC sizes; compare the exact
// integer allocation, never round, normalize percentages or accept fractions.
fn volume_size_bytes(text: &str) -> Option<u64> {
    let (digits, multiplier) = if let Some(n) = text.strip_suffix("GiB") {
        (n, 1 << 30)
    } else if let Some(n) = text.strip_suffix("MiB") {
        (n, 1 << 20)
    } else {
        (text, 1)
    };
    let n: u64 = digits.parse().ok()?;
    if digits != n.to_string() || n == 0 {
        return None;
    }
    n.checked_mul(multiplier)
}
