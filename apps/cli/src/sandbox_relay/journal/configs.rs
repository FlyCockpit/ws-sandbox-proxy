//! Private durable workload defaults, verified before every use.
use super::*;
use sandbox_protocol::{
    PRIVATE_CONFIG_MAX_BYTES, PrivateConfigAck, PrivateConfigInstall, PrivateConfigRefusalReason,
};
use std::io::Read;

const LOCAL_CONFIG_DOMAIN: &str = "wssp-host-private-config-v2";
const LOCAL_CONFIG_SCHEME: &str = "hmac-sha256-v1";

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct PrivateConfigRecord {
    version: u32,
    binding: TransportBindingV11,
    sandbox_owner_id: String,
    sandbox_id: String,
    generation: u64,
    config: sandbox_protocol::PrivateConfigRef,
    env: Vec<(String, String)>,
    checksum_scheme: String,
    checksum_key_id: String,
}

impl std::fmt::Debug for PrivateConfigRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PrivateConfigRecord([REDACTED])")
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfigEnvelope {
    record: PrivateConfigRecord,
    checksum: String,
}

pub(super) struct RetainedConfig {
    // Opaque until the matching authenticated memory key is reinstalled.
    record: PrivateConfigRecord,
    checksum: String,
}

impl RetainedConfig {
    pub(super) fn sandbox_owner(&self) -> &str {
        &self.record.sandbox_owner_id
    }
    pub(super) fn binds(&self, binding: &TransportBindingV11) -> bool {
        self.record.binding == *binding
    }
}

impl std::fmt::Debug for RetainedConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RetainedConfig([REDACTED])")
    }
}

/// A constant error with no source: filesystem errors may contain private paths.
#[derive(Debug)]
pub(crate) struct ConfigInstallIo;
impl std::fmt::Display for ConfigInstallIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("private config journal IO failed")
    }
}
impl std::error::Error for ConfigInstallIo {}

fn refused() -> anyhow::Error {
    anyhow::anyhow!("private config journal refused")
}

/// Only a newly renamed, unpublished file is eligible for rollback. Reinstall
/// failure must never unlink a previously accepted config used by a lease.
#[derive(Default)]
struct PendingConfigFile {
    path: Option<PathBuf>,
}

impl Drop for PendingConfigFile {
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            let _ = fs::remove_file(path);
            if let Some(parent) = path.parent() {
                let _ = File::open(parent).and_then(|dir| dir.sync_all());
            }
        }
    }
}

impl HostJournal {
    /// Values leave the journal only for the modeled guest environment. A
    /// lease binding cannot silently lose its defaults on later commands.
    pub fn execution_env(
        &self,
        sandbox_id: &str,
        generation: u64,
        config: Option<&sandbox_protocol::PrivateConfigRef>,
    ) -> Result<Vec<(String, String)>> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(lease) = state.leases.get(sandbox_id)
            && lease
                .private_config
                .as_ref()
                .is_some_and(|expected| Some(expected) != config)
        {
            return Err(refused());
        }
        let Some(config) = config else {
            if state.configs.contains_key(sandbox_id) {
                return Err(refused());
            }
            return Ok(Vec::new());
        };
        let guard = self.key.lock().unwrap_or_else(|e| e.into_inner());
        let key = guard
            .as_ref()
            .ok_or_else(|| anyhow::Error::msg(SandboxErrorCode::DigestKeyUnavailable))?;
        check_reference(
            &self.configs_dir,
            &state,
            key,
            &key.binding,
            sandbox_id,
            generation,
            config,
        )?;
        let retained = state.configs.get(sandbox_id).ok_or_else(refused)?;
        Ok(retained.record.env.clone())
    }

    /// A returned ACK is evidence of a file AND parent-directory fsync. Errors
    /// discard all source chains, including tempfile's value-bearing errors.
    pub fn install_config(
        &self,
        frame: &PrivateConfigInstall,
        binding: &TransportBindingV11,
        epoch: u64,
    ) -> Result<PrivateConfigAck> {
        self.install_config_inner(frame, binding, epoch)
            .map_err(|error| {
                if error.downcast_ref::<std::io::Error>().is_some()
                    || error.downcast_ref::<tempfile::PersistError>().is_some()
                {
                    anyhow::Error::new(ConfigInstallIo)
                } else if error.downcast_ref::<SandboxErrorCode>().is_some()
                    || error.downcast_ref::<PrivateConfigRefusalReason>().is_some()
                {
                    error
                } else {
                    refused()
                }
            })
    }

    fn install_config_inner(
        &self,
        frame: &PrivateConfigInstall,
        binding: &TransportBindingV11,
        epoch: u64,
    ) -> Result<PrivateConfigAck> {
        if !frame.is_valid()
            || frame.connection_epoch != epoch
            || frame.server != binding.server
            || frame.host_owner_id != binding.host_owner_id
            || frame.host_id != binding.host_id
            || serde_json::to_vec(frame)?.len() > PRIVATE_CONFIG_MAX_BYTES
        {
            return Err(refused());
        }
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state
            .sandbox_owner(&frame.sandbox_id)
            .is_some_and(|owner| owner != frame.sandbox_owner_id)
        {
            return Err(refused());
        }
        let key_guard = self.key.lock().unwrap_or_else(|e| e.into_inner());
        let key = key_guard
            .as_ref()
            .ok_or_else(|| anyhow::Error::msg(SandboxErrorCode::DigestKeyUnavailable))?;
        // Every identity fence precedes a checksum or payload comparison.
        if key.binding != *binding || key.key_id != frame.config.binding_key_id {
            return Err(anyhow::Error::msg(SandboxErrorCode::DigestKeyChanged));
        }
        let mut env = frame.env.clone();
        env.sort();
        let record = PrivateConfigRecord {
            version: JOURNAL_VERSION,
            binding: binding.clone(),
            sandbox_owner_id: frame.sandbox_owner_id.clone(),
            sandbox_id: frame.sandbox_id.clone(),
            generation: frame.generation,
            config: frame.config.clone(),
            env,
            checksum_scheme: LOCAL_CONFIG_SCHEME.into(),
            checksum_key_id: key.key_id.clone(),
        };
        let mut pending_file = PendingConfigFile::default();
        if let Some(old) = state.configs.get(&frame.sandbox_id) {
            verify_key_identity(old, key)?;
            if old.record.config.config_id != frame.config.config_id
                || old.record.generation != frame.generation
            {
                return Err(refused());
            }
            verify(old, key)?;
            if serde_json::to_vec(&old.record)? != serde_json::to_vec(&record)? {
                return Err(refused());
            }
        } else {
            // A cleanup watermark forbids resurrection, including a delayed
            // install. A later admission (a
            // same-host restore retry) installs once its explicit config
            // generation is above the watermark's AND the watermark proves
            // the prior instance and root gone with no unsettled work left.
            // Installs at or below the watermark generation stay refused.
            if state
                .cleanups
                .get(&frame.sandbox_id)
                .is_some_and(|watermark| {
                    frame.generation <= watermark.generation
                        || !watermark.instance_absent
                        || state.receipts.values().any(|r| {
                            r.sandbox_id == frame.sandbox_id
                                && r.generation <= watermark.generation
                                && !r.is_terminal()
                        })
                })
            {
                return Err(PrivateConfigRefusalReason::CleanupWatermark.into());
            }
            if state.configs.len() >= MAX_RECEIPTS {
                return Err(PrivateConfigRefusalReason::ConfigCountBound.into());
            }
            // A rename may succeed before a later IO fence fails. Such complete
            // but unacknowledged files are not installed in memory; count them
            // too, so repeated failures cannot bypass the durable storage bound.
            let disk_entries = fs::read_dir(&self.configs_dir)
                .and_then(|entries| {
                    entries
                        .take(MAX_RECEIPTS)
                        .try_fold(0, |count, entry| entry.map(|_| count + 1))
                })
                .map_err(|_| PrivateConfigRefusalReason::JournalIoBeforePersistence)?;
            if disk_entries >= MAX_RECEIPTS {
                return Err(PrivateConfigRefusalReason::ConfigCountBound.into());
            }
            let checksum = key.mac(LOCAL_CONFIG_DOMAIN, &serde_json::to_string(&record)?);
            let bytes = serde_json::to_vec(&ConfigEnvelope {
                record: record.clone(),
                checksum: checksum.clone(),
            })?;
            if bytes.len() > PRIVATE_CONFIG_MAX_BYTES {
                return Err(refused());
            }
            // Until persist is attempted, a failure cannot publish a config.
            // Never classify persist/readback/fsync-after-rename as pre-effect.
            let tmp = (|| -> Result<tempfile::NamedTempFile> {
                self.maybe_crash(CrashPoint::BeforeConfigPersist)?;
                let mut tmp = self
                    .io
                    .write(|| Ok(tempfile::NamedTempFile::new_in(&self.configs_dir)?))?;
                self.io.write(|| Ok(tmp.write_all(&bytes)?))?;
                self.maybe_crash(CrashPoint::BeforeConfigFileSync)?;
                self.io.write(|| Ok(tmp.as_file().sync_all()?))?;
                Ok(tmp)
            })()
            .map_err(|_| PrivateConfigRefusalReason::JournalIoBeforePersistence)?;
            let path = self.configs_dir.join(cleanup_file_name(&frame.sandbox_id));
            self.io.write(|| Ok(tmp.persist(&path)?))?;
            pending_file.path = Some(path);
        }
        // Also verify the actual retained file on idempotent reinstall; an
        // in-memory copy must never hide corruption on disk.
        let retained = read_one(&self.configs_dir.join(cleanup_file_name(&frame.sandbox_id)))?;
        verify(&retained, key)?;
        if serde_json::to_vec(&retained.record)? != serde_json::to_vec(&record)? {
            return Err(refused());
        }
        // A retained record may have been reopened after a crash following
        // rename. Re-establish both durability fences before every ACK.
        self.maybe_crash(CrashPoint::BeforeConfigFileSync)?;
        self.io.write(|| {
            Ok(
                File::open(self.configs_dir.join(cleanup_file_name(&frame.sandbox_id)))?
                    .sync_all()?,
            )
        })?;
        self.maybe_crash(CrashPoint::BeforeConfigDirectorySync)?;
        sync_dir(&self.io, &self.configs_dir)?;
        self.maybe_crash(CrashPoint::AfterConfigPersist)?;
        // Failed new installs must never become usable on this session. Publish
        // only after readback and both durability fences have succeeded.
        state.configs.insert(frame.sandbox_id.clone(), retained);
        pending_file.path = None;
        Ok(PrivateConfigAck {
            sandbox_owner_id: frame.sandbox_owner_id.clone(),
            connection_epoch: epoch,
            sandbox_id: frame.sandbox_id.clone(),
            generation: frame.generation,
            config: frame.config.clone(),
        })
    }
}

fn verify_key_identity(
    config: &RetainedConfig,
    key: &super::super::journal_key::MemoryJournalKey,
) -> Result<()> {
    // Wrong IDs refuse before any digest work, even if values were guessed.
    if config.record.checksum_key_id != key.key_id
        || config.record.config.binding_key_id != key.key_id
        || config.record.binding != key.binding
    {
        return Err(anyhow::Error::msg(SandboxErrorCode::DigestKeyChanged));
    }
    Ok(())
}

fn verify(
    config: &RetainedConfig,
    key: &super::super::journal_key::MemoryJournalKey,
) -> Result<()> {
    verify_key_identity(config, key)?;
    if config.checksum != key.mac(LOCAL_CONFIG_DOMAIN, &serde_json::to_string(&config.record)?) {
        return Err(refused());
    }
    Ok(())
}

/// Called under the journal mutex, before dispatch MACs or intent/lease writes.
/// Only execution_env releases verified values to a modeled guest environment.
pub(super) fn check_reference(
    dir: &Path,
    state: &JournalState,
    key: &super::super::journal_key::MemoryJournalKey,
    binding: &TransportBindingV11,
    sandbox_id: &str,
    generation: u64,
    config: &sandbox_protocol::PrivateConfigRef,
) -> Result<()> {
    (|| {
        if key.binding != *binding || key.key_id != config.binding_key_id {
            return Err(anyhow::Error::msg(SandboxErrorCode::DigestKeyChanged));
        }
        let retained = state.configs.get(sandbox_id).ok_or_else(refused)?;
        verify_key_identity(retained, key)?;
        if retained.record.config.config_id != config.config_id {
            return Err(refused());
        }
        verify(retained, key)?;
        let disk = read_one(&dir.join(cleanup_file_name(sandbox_id)))?;
        verify(&disk, key)?;
        if retained.record.generation > generation
            || retained.record.config != *config
            || disk.record.config != *config
            || serde_json::to_vec(&retained.record)? != serde_json::to_vec(&disk.record)?
        {
            return Err(refused());
        }
        Ok(())
    })()
    .map_err(|error: anyhow::Error| {
        if error.downcast_ref::<SandboxErrorCode>().is_some() {
            error
        } else {
            refused()
        }
    })
}

impl HostJournal {
    /// Key-free GC consumes already durable absence and settlement evidence.
    /// No new cleanup journal, config checksum comparison or rehash is needed.
    pub(super) fn gc_configs_locked(&self, state: &mut JournalState) -> Result<()> {
        (|| {
            let mut sandboxes: std::collections::BTreeSet<_> =
                state.configs.keys().cloned().collect();
            sandboxes.extend(
                state
                    .receipts
                    .values()
                    .filter(|r| covers_private(r) || r.digest_pruned)
                    .map(|r| r.sandbox_id.clone()),
            );
            for sandbox_id in sandboxes {
                let Some(watermark) = state.cleanups.get(&sandbox_id) else {
                    continue;
                };
                if !watermark.instance_absent
                    || state.lease_workers.get(&sandbox_id).copied().unwrap_or(0) != 0
                    || state.leases.get(&sandbox_id).is_some_and(|l| {
                        !l.expired
                            || !l.expiry_complete
                            || !l.instance_absent
                            || l.generation > watermark.generation
                    })
                    || state.configs.get(&sandbox_id).is_some_and(|c| {
                        c.record.generation > watermark.generation
                            || c.record.binding != watermark.binding
                    })
                    || state.receipts.values().any(|r| {
                        r.sandbox_id == sandbox_id
                            && (r.generation > watermark.generation
                                || (!r.digest_pruned && (!r.is_terminal() || covers_private(r)))
                                || !r.binds(&watermark.binding))
                    })
                {
                    continue;
                }
                // Unconfirmed results remain deliverable, with their original
                // digest fences. GC waits for exact confirmation to remove them;
                // Current pruned tombstones contain no private digest.
                self.maybe_crash(CrashPoint::AfterDigestPrune)?;
                // Every env-covering receipt is now removed or already pruned.
                // Strip the checkpoint binding before unlinking the config.
                lease_record::prune_private_config(&self.io, &self.leases_dir, state, &sandbox_id)?;
                self.maybe_crash(CrashPoint::BeforeConfigUnlink)?;
                if state.configs.contains_key(&sandbox_id) {
                    remove_durably(
                        &self.io,
                        &self.configs_dir.join(cleanup_file_name(&sandbox_id)),
                        true,
                    )?;
                    self.maybe_crash(CrashPoint::AfterConfigUnlink)?;
                    sync_dir(&self.io, &self.configs_dir)?;
                    state.configs.remove(&sandbox_id);
                }
            }
            Ok(())
        })()
        .map_err(|_: anyhow::Error| refused())
    }
}

fn covers_private(receipt: &HostReceipt) -> bool {
    // Only the closed cleanup kinds can prove their payloads are env-free.
    !receipt.digest_pruned
        && (!sandbox_protocol::KEY_FREE_CLEANUP_KINDS.contains(&receipt.kind.as_str())
            || receipt.digest_scheme.as_deref() == Some("hmac-sha256-v1")
            || receipt.private_config.is_some()
            || receipt
                .lease
                .as_ref()
                .is_some_and(|l| l.private_config.is_some()))
}

fn read_one(path: &Path) -> Result<RetainedConfig> {
    private_file(path)?;
    if fs::metadata(path)?.len() > PRIVATE_CONFIG_MAX_BYTES as u64 {
        return Err(refused());
    }
    let mut bytes = Vec::new();
    File::open(path)?
        .take((PRIVATE_CONFIG_MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > PRIVATE_CONFIG_MAX_BYTES {
        return Err(refused());
    }
    let envelope: ConfigEnvelope = serde_json::from_slice(&bytes).map_err(|_| refused())?;
    let r = envelope.record;
    if r.version != JOURNAL_VERSION
        || r.checksum_scheme != LOCAL_CONFIG_SCHEME
        || !sandbox_protocol::valid_key_id(&r.checksum_key_id)
        || !canonical_body_hash(&envelope.checksum)
        || !(PrivateConfigInstall {
            refusal_token: Some("install-token".into()),
            connection_epoch: 1,
            server: r.binding.server.clone(),
            host_owner_id: r.binding.host_owner_id.clone(),
            sandbox_owner_id: r.sandbox_owner_id.clone(),
            host_id: r.binding.host_id.clone(),
            sandbox_id: r.sandbox_id.clone(),
            generation: r.generation,
            config: r.config.clone(),
            env: r.env.clone(),
        })
        .is_valid()
        || path.file_name().and_then(|v| v.to_str()) != Some(&cleanup_file_name(&r.sandbox_id))
    {
        return Err(refused());
    }
    Ok(RetainedConfig {
        record: r,
        checksum: envelope.checksum,
    })
}

#[cfg(unix)]
pub(super) fn load(
    dir: &Path,
    binding: &TransportBindingV11,
) -> Result<HashMap<String, RetainedConfig>> {
    (|| {
        let mut configs = HashMap::new();
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            private_file(&path)?;
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(".tmp"))
            {
                fs::remove_file(path)?;
                continue;
            }
            if configs.len() >= MAX_RECEIPTS {
                return Err(refused());
            }
            let config = read_one(&path)?;
            if config.record.binding.server != binding.server
                || config.record.binding.host_id != binding.host_id
                || (!binding.host_owner_id.is_empty()
                    && config.record.binding.host_owner_id != binding.host_owner_id)
            {
                return Err(refused());
            }
            configs.insert(config.record.sandbox_id.clone(), config);
        }
        File::open(dir)?.sync_all()?;
        Ok(configs)
    })()
    .map_err(|_| refused())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    pub(super) fn fixture() -> (
        TransportBindingV11,
        sandbox_protocol::JournalKeyInstall,
        PrivateConfigInstall,
    ) {
        let binding = TransportBindingV11 {
            server: "wss://example.test/ws/sandbox-host".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        };
        let key = sandbox_protocol::JournalKeyInstall {
            connection_epoch: 1,
            key_version: 1,
            key_id: "d".repeat(32),
            key_hex: "ab".repeat(32),
            server: binding.server.clone(),
            host_owner_id: binding.host_owner_id.clone(),
            host_id: binding.host_id.clone(),
        };
        let config = PrivateConfigInstall {
            sandbox_owner_id: "owner".into(),
            refusal_token: Some("install-token".into()),
            connection_epoch: 1,
            server: binding.server.clone(),
            host_owner_id: binding.host_owner_id.clone(),
            host_id: binding.host_id.clone(),
            sandbox_id: "sbx".into(),
            generation: 1,
            config: sandbox_protocol::PrivateConfigRef {
                config_id: "config".into(),
                binding_scheme: "hmac-sha256-v1".into(),
                binding_key_id: key.key_id.clone(),
                binding_mac: "c".repeat(64),
            },
            env: vec![("K".into(), "private-config-sentinel".into())],
        };
        (binding, key, config)
    }

    #[test]
    fn v6_private_configs_share_only_the_transport_and_keep_creator_mac_identity_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let (transport, key, mut a) = fixture();
        a.sandbox_owner_id = "creator-a".into();
        a.sandbox_id = "sandbox-a".into();
        let mut b = a.clone();
        b.sandbox_owner_id = "creator-b".into();
        b.sandbox_id = "sandbox-b".into();
        b.config.config_id = "config-b".into();
        b.env = vec![("APP".into(), "private-b".into())];
        let j = HostJournal::open(dir.path(), &transport).unwrap();
        j.install_key(&key, &transport, 1).unwrap();
        for frame in [&a, &b] {
            let ack = j.install_config(frame, &transport, 1).unwrap();
            assert_eq!(ack.sandbox_owner_id, frame.sandbox_owner_id);
        }
        let mut spoof = a.clone();
        spoof.sandbox_owner_id = b.sandbox_owner_id.clone();
        assert!(j.install_config(&spoof, &transport, 1).is_err());
        drop(j);
        let j = HostJournal::open(dir.path(), &transport).unwrap();
        j.install_key(&key, &transport, 1).unwrap();
        assert_eq!(
            j.execution_env(&a.sandbox_id, 1, Some(&a.config)).unwrap(),
            a.env
        );
        assert_eq!(
            j.execution_env(&b.sandbox_id, 1, Some(&b.config)).unwrap(),
            b.env
        );
        assert!(j.install_config(&spoof, &transport, 1).is_err());
    }

    #[test]
    fn retained_execution_env_requires_key_exact_binding_and_actual_disk_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let (binding, key, config) = fixture();
        let j = HostJournal::open(dir.path(), &binding).unwrap();
        j.install_key(&key, &binding, 1).unwrap();
        j.install_config(&config, &binding, 1).unwrap();
        assert_eq!(
            j.execution_env("sbx", 2, Some(&config.config)).unwrap(),
            config.env
        );
        assert!(j.execution_env("sbx", 1, None).is_err());
        drop(j);
        let j = HostJournal::open(dir.path(), &binding).unwrap();
        assert_eq!(
            j.execution_env("sbx", 2, Some(&config.config))
                .unwrap_err()
                .downcast_ref::<SandboxErrorCode>(),
            Some(&SandboxErrorCode::DigestKeyUnavailable)
        );
        let mut key = key;
        key.connection_epoch = 2;
        j.install_key(&key, &binding, 2).unwrap();
        assert_eq!(
            j.execution_env("sbx", 2, Some(&config.config)).unwrap(),
            config.env
        );
        let path = j.configs_dir.join(cleanup_file_name("sbx"));
        let original = fs::read(&path).unwrap();
        let mut disk: serde_json::Value = serde_json::from_slice(&original).unwrap();
        disk["record"]["env"] = serde_json::json!([["K", "changed-private"]]);
        fs::write(&path, disk.to_string()).unwrap();
        let error = j.execution_env("sbx", 2, Some(&config.config)).unwrap_err();
        assert_eq!(format!("{error:#}"), "private config journal refused");
        assert_eq!(error.chain().count(), 1);
        fs::remove_file(&path).unwrap();
        assert!(j.execution_env("sbx", 2, Some(&config.config)).is_err());
        fs::write(&path, original).unwrap();
        assert_eq!(
            j.execution_env("sbx", 3, Some(&config.config)).unwrap(),
            config.env
        );
    }

    fn calls(j: &HostJournal) -> usize {
        j.key
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .mac_calls
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[test]
    fn pre_effect_config_refusals_are_typed_values_free_and_correlated() {
        use sandbox_protocol::{DaemonControlMessage, PrivateConfigRefusalReason as Reason};
        for reason in [
            Reason::CleanupWatermark,
            Reason::ConfigCountBound,
            Reason::JournalIoBeforePersistence,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let (binding, key, mut config) = fixture();
            let mut journal = HostJournal::open(dir.path(), &binding).unwrap();
            journal.install_key(&key, &binding, 1).unwrap();
            match reason {
                Reason::CleanupWatermark => {
                    let watermark = CleanupWatermark {
                        sandbox_owner_id: "owner".into(),
                        version: JOURNAL_VERSION,
                        binding: binding.clone(),
                        sandbox_id: "sbx".into(),
                        generation: 2,
                        instance_absent: true,
                        ext: JournalExt::new(),
                    };
                    persist_cleanup(&journal.io, &journal.cleanups_dir, &watermark).unwrap();
                    journal
                        .state
                        .lock()
                        .unwrap()
                        .cleanups
                        .insert("sbx".into(), watermark);
                }
                Reason::ConfigCountBound => {
                    for index in 0..MAX_RECEIPTS {
                        fs::write(journal.configs_dir.join(format!("bound-{index}")), b"").unwrap();
                    }
                }
                Reason::JournalIoBeforePersistence => {
                    journal.configs_dir = dir.path().join("private-config-io-path-sentinel");
                    fs::write(&journal.configs_dir, b"not a directory").unwrap();
                }
            }
            let control = super::super::super::journal_key::KeyControl {
                journal: &journal,
                binding: &binding,
                epoch: Some(1),
                credentials: None,
            };
            config.refusal_token = Some("install-token".into());
            let response = control.config_response(&config, 1).unwrap();
            let DaemonControlMessage::PrivateConfigRefused(refusal) = &response else {
                panic!("expected typed refusal")
            };
            assert_eq!(refusal.reason, reason);
            assert_eq!(refusal.refusal_token, "install-token");
            let wire = sandbox_protocol::WireCodes::CURRENT
                .encode(&response, None)
                .unwrap()
                .text;
            for private in [
                &config.env[0].1,
                &config.config.binding_mac,
                &config.config.binding_key_id,
                &config.server,
            ] {
                assert!(!wire.contains(private));
            }
            assert!(!wire.contains("path-sentinel"));
            assert!(journal.state.lock().unwrap().configs.is_empty());
        }
    }

    #[test]
    fn config_failure_after_persistence_never_nacks() {
        let dir = tempfile::tempdir().unwrap();
        let (binding, key, mut config) = fixture();
        config.refusal_token = Some("install-token".into());
        let journal = HostJournal::open(dir.path(), &binding).unwrap();
        journal.install_key(&key, &binding, 1).unwrap();
        journal.inject_crash(CrashPoint::BeforeConfigDirectorySync);
        let control = super::super::super::journal_key::KeyControl {
            journal: &journal,
            binding: &binding,
            epoch: Some(1),
            credentials: None,
        };
        assert!(control.config_response(&config, 1).is_none());
        assert!(journal.state.lock().unwrap().configs.is_empty());
    }

    #[test]
    fn config_install_io_failure_is_typed_and_redacted() {
        let dir = tempfile::tempdir().unwrap();
        let (binding, key, config) = fixture();
        let mut journal = HostJournal::open(dir.path(), &binding).unwrap();
        journal.install_key(&key, &binding, 1).unwrap();
        // A real filesystem error, without relying on permissions or root UID.
        journal.configs_dir = dir.path().join("private-config-io-path-sentinel");
        fs::write(&journal.configs_dir, b"not a directory").unwrap();
        let error = journal.install_config(&config, &binding, 1).unwrap_err();
        assert_eq!(
            error.downcast_ref::<PrivateConfigRefusalReason>(),
            Some(&PrivateConfigRefusalReason::JournalIoBeforePersistence)
        );
        assert_eq!(
            format!("{error:#}"),
            "private config journal IO before persistence"
        );
        assert_eq!(error.chain().count(), 1);
        assert!(journal.state.lock().unwrap().configs.is_empty());
    }

    #[test]
    fn failed_config_installs_cannot_bypass_the_disk_bound() {
        let dir = crate::sandbox_relay::test_support::journal_capacity_dir();
        let (binding, key, config) = fixture();
        let j = HostJournal::open(dir.path(), &binding).unwrap();
        j.install_key(&key, &binding, 1).unwrap();
        // Returned failures after rename must not survive as retained config.
        j.inject_crash(CrashPoint::BeforeConfigDirectorySync);
        for index in 0..MAX_RECEIPTS + 1 {
            let mut frame = config.clone();
            frame.sandbox_id = format!("failed-{index}");
            assert!(j.install_config(&frame, &binding, 1).is_err());
        }
        assert!(j.state.lock().unwrap().configs.is_empty());
        assert_eq!(fs::read_dir(&j.configs_dir).unwrap().count(), 0);
        drop(j);
        let j = HostJournal::open(dir.path(), &binding).unwrap();
        assert!(j.state.lock().unwrap().configs.is_empty());
        j.install_key(&key, &binding, 1).unwrap();
        assert_eq!(
            j.install_config(&config, &binding, 1).unwrap().config,
            config.config
        );
        // Failure on a later reinstall preserves the already accepted file.
        j.inject_crash(CrashPoint::BeforeConfigDirectorySync);
        assert!(j.install_config(&config, &binding, 1).is_err());
        drop(j);
        let j = HostJournal::open(dir.path(), &binding).unwrap();
        assert_eq!(j.state.lock().unwrap().configs.len(), 1);
        j.install_key(&key, &binding, 1).unwrap();
        assert!(j.install_config(&config, &binding, 1).is_ok());
    }

    #[test]
    fn config_journal_reopen_requires_key_and_verifies_checksum_before_ack() {
        let dir = tempfile::tempdir().unwrap();
        let (binding, key, config) = fixture();
        {
            let j = HostJournal::open(dir.path(), &binding).unwrap();
            assert_eq!(
                j.install_config(&config, &binding, 1)
                    .unwrap_err()
                    .downcast_ref::<SandboxErrorCode>(),
                Some(&SandboxErrorCode::DigestKeyUnavailable)
            );
            j.install_key(&key, &binding, 1).unwrap();
            let ack = j.install_config(&config, &binding, 1).unwrap();
            assert_eq!(ack.config, config.config);
            let disk = fs::read_to_string(j.configs_dir.join(cleanup_file_name("sbx"))).unwrap();
            let retained: ConfigEnvelope = serde_json::from_str(&disk).unwrap();
            assert_eq!(
                retained.checksum,
                "88fa8c1e0227838f7e84796a4e584460bb05028cc729b1c21f2b3b48bfb157c5"
            );
            assert_ne!(retained.checksum, ack.config.binding_mac);
            assert!(!format!("{j:?}").contains(&retained.checksum));
            assert!(disk.contains(&config.env[0].1)); // The explicit host-operator trust boundary.
            assert!(!disk.contains(&key.key_hex));
            assert!(!format!("{j:?} {config:?} {ack:?}").contains(&config.env[0].1));
            assert_eq!(
                fs::metadata(&j.configs_dir).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(j.configs_dir.join(cleanup_file_name("sbx")))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let j = HostJournal::open(dir.path(), &binding).unwrap();
        assert_eq!(
            j.install_config(&config, &binding, 1)
                .unwrap_err()
                .downcast_ref::<SandboxErrorCode>(),
            Some(&SandboxErrorCode::DigestKeyUnavailable)
        );
        j.install_key(&key, &binding, 1).unwrap();
        assert_eq!(
            j.install_config(&config, &binding, 1).unwrap().config,
            config.config
        );
        // A live in-memory copy cannot hide a changed retained value.
        let path = j.configs_dir.join(cleanup_file_name("sbx"));
        let mut disk: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let original = disk.clone();
        disk["checksum"] = serde_json::json!("0".repeat(64));
        fs::write(&path, disk.to_string()).unwrap();
        assert!(
            j.install_config(&config, &binding, 1).is_err(),
            "checksum must be checked even when the stored values match"
        );
        let mut disk = original;
        disk["record"]["env"][0][1] = serde_json::json!("changed-private-sentinel");
        fs::write(&path, disk.to_string()).unwrap();
        let error = j.install_config(&config, &binding, 1).unwrap_err();
        assert_eq!(format!("{error:#}"), "private config journal refused");
        drop(j);
        let j = HostJournal::open(dir.path(), &binding).unwrap();
        j.install_key(&key, &binding, 1).unwrap();
        assert!(j.install_config(&config, &binding, 1).is_err());
    }

    #[test]
    fn config_wrong_id_refuses_before_digest_and_same_id_wrong_key_is_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let (binding, key, config) = fixture();
        let j = HostJournal::open(dir.path(), &binding).unwrap();
        j.install_key(&key, &binding, 1).unwrap();
        j.install_config(&config, &binding, 1).unwrap();
        let changed = sandbox_protocol::JournalKeyInstall {
            key_id: "e".repeat(32),
            ..key.clone()
        };
        j.install_key(&changed, &binding, 1).unwrap();
        let mut incoming = config.clone();
        incoming.config.binding_key_id = changed.key_id;
        for frame in [&config, &incoming] {
            assert_eq!(
                j.install_config(frame, &binding, 1)
                    .unwrap_err()
                    .downcast_ref::<SandboxErrorCode>(),
                Some(&SandboxErrorCode::DigestKeyChanged)
            );
            assert_eq!(calls(&j), 0);
        }
        j.install_key(
            &sandbox_protocol::JournalKeyInstall {
                key_hex: "cd".repeat(32),
                ..key
            },
            &binding,
            1,
        )
        .unwrap();
        let error = j.install_config(&config, &binding, 1).unwrap_err();
        assert_eq!(format!("{error:#}"), "private config journal refused");
        assert!(calls(&j) > 0);
    }

    #[test]
    fn config_ack_requires_fsync_and_crash_reopen_is_idempotent() {
        let (binding, key, config) = fixture();
        for point in [
            CrashPoint::BeforeConfigPersist,
            CrashPoint::BeforeConfigFileSync,
            CrashPoint::BeforeConfigDirectorySync,
            CrashPoint::AfterConfigPersist,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let j = HostJournal::open(dir.path(), &binding).unwrap();
            j.install_key(&key, &binding, 1).unwrap();
            j.inject_crash(point);
            assert!(
                j.install_config(&config, &binding, 1).is_err(),
                "no ACK at {point:?}"
            );
            assert!(
                j.state.lock().unwrap().configs.is_empty(),
                "not installed at {point:?}"
            );
            assert!(!j.configs_dir.join(cleanup_file_name("sbx")).exists());
            drop(j);
            let j = HostJournal::open(dir.path(), &binding).unwrap();
            j.install_key(&key, &binding, 1).unwrap();
            assert_eq!(
                j.install_config(&config, &binding, 1).unwrap().config,
                config.config
            );
        }
    }

    #[test]
    fn config_size_corruption_and_binding_errors_are_constant() {
        let (binding, key, config) = fixture();
        for corrupt in ["json", "size", "unknown", "binding"] {
            let dir = tempfile::tempdir().unwrap();
            let j = HostJournal::open(dir.path(), &binding).unwrap();
            j.install_key(&key, &binding, 1).unwrap();
            j.install_config(&config, &binding, 1).unwrap();
            let path = j.configs_dir.join(cleanup_file_name("sbx"));
            let mut disk: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            match corrupt {
                "json" => {
                    fs::write(&path, "invalid-private-sentinel").unwrap();
                }
                "size" => {
                    fs::write(&path, "private-sentinel".repeat(PRIVATE_CONFIG_MAX_BYTES)).unwrap();
                }
                "unknown" => {
                    disk["private-sentinel"] = true.into();
                    fs::write(&path, disk.to_string()).unwrap();
                }
                "binding" => {
                    disk["record"]["binding"]["hostOwnerId"] = "private-sentinel".into();
                    fs::write(&path, disk.to_string()).unwrap();
                }
                _ => unreachable!(),
            }
            drop(j);
            let error = HostJournal::open(dir.path(), &binding).unwrap_err();
            assert_eq!(format!("{error:#}"), "private config journal refused");
        }
        let dir = tempfile::tempdir().unwrap();
        let j = HostJournal::open(dir.path(), &binding).unwrap();
        j.install_key(&key, &binding, 1).unwrap();
        for env in [
            vec![("K".into(), "x".repeat(4097))],
            vec![("K".into(), "a".into()), ("K".into(), "b".into())],
        ] {
            assert!(
                j.install_config(
                    &PrivateConfigInstall {
                        sandbox_owner_id: "owner".into(),
                        refusal_token: Some("install-token".into()),
                        env,
                        ..config.clone()
                    },
                    &binding,
                    1
                )
                .is_err()
            );
        }
        assert!(j.state.lock().unwrap().configs.is_empty());
    }
    fn work(
        id: &str,
        kind: &str,
        config: Option<sandbox_protocol::PrivateConfigRef>,
    ) -> OperationDispatch {
        serde_json::from_value(serde_json::json!({"sandboxOwnerId":"owner",
            "operationId":id, "sandboxId":"sbx", "kind":kind, "idempotencyKey":id,
            "generation":1, "attempt":1, "bodyHash":"a".repeat(64),
            "digestScheme":"hmac-sha256-v1", "digestKeyId":"d".repeat(32),
            "privateConfig":config, "lease":sandbox_protocol::HostLease::for_test()
        }))
        .unwrap()
    }

    fn seed(
        j: &HostJournal,
        binding: &TransportBindingV11,
        config: &PrivateConfigInstall,
    ) -> (OperationDispatch, OperationDispatch) {
        let create = work("a-create", "sandbox.create", Some(config.config.clone()));
        j.record_intent(&j.prepare_dispatch(binding, &create).unwrap())
            .unwrap();
        j.accept_lease(&create).unwrap();
        j.record_effect(&create.operation_id).unwrap();
        j.record_result(
            &create.operation_id,
            OperationState::Succeeded,
            Some(serde_json::json!({"state":"ready", "lease":create.lease})),
            None,
            None,
        )
        .unwrap();
        // This command has env of its own, without a sandbox config reference.
        let mut command = work("b-command", "command.run", None);
        command.env = Some(vec![("COMMAND_ONLY".into(), "command-env-sentinel".into())]);
        j.record_intent(&j.prepare_dispatch(binding, &command).unwrap())
            .unwrap();
        j.record_effect(&command.operation_id).unwrap();
        j.record_result(
            &command.operation_id,
            OperationState::Succeeded,
            Some(serde_json::json!({"exitCode":0,"pid":123,"outputBytes":9})),
            None,
            None,
        )
        .unwrap();
        (create, command)
    }

    fn confirm_result(j: &HostJournal, binding: &TransportBindingV11, operation_id: &str) {
        let r = j.lookup(operation_id).unwrap();
        assert!(
            j.confirm(
                binding,
                &sandbox_protocol::ReceiptConfirmation {
                    sandbox_owner_id: r.sandbox_owner_id.clone(),
                    operation_id: r.operation_id.clone(),
                    sandbox_id: r.sandbox_id.clone(),
                    generation: r.generation,
                    attempt: r.attempt,
                    body_hash: r.server_request_hash().unwrap().into(),
                    idempotency_key: r.idempotency_key,
                    kind: r.kind,
                    cleanup_generation: None,
                    retire_command: false,
                }
            )
            .unwrap()
        );
    }

    fn cleanup(
        j: &HostJournal,
        binding: &TransportBindingV11,
        kind: &str,
        confirm: bool,
    ) -> sandbox_protocol::ReceiptConfirmation {
        let d: OperationDispatch = serde_json::from_value(serde_json::json!({"sandboxOwnerId":"owner",
            "operationId":kind.replace('.', "-"),"sandboxId":"sbx","idempotencyKey":kind,
            "kind":kind,"generation":1,"attempt":1,"bodyHash":"f".repeat(64),"digestScheme":"sha256-env-free-v1"
        })).unwrap();
        j.record_intent(&j.prepare_dispatch(binding, &d).unwrap())
            .unwrap();
        j.record_effect(&d.operation_id).unwrap();
        j.record_result(
            &d.operation_id,
            OperationState::Succeeded,
            Some(
                serde_json::json!({"state":if kind == "sandbox.kill" {"deleted"} else {"stopped"}}),
            ),
            None,
            None,
        )
        .unwrap();
        let confirmation = sandbox_protocol::ReceiptConfirmation {
            sandbox_owner_id: d.sandbox_owner_id.clone(),
            operation_id: d.operation_id,
            sandbox_id: d.sandbox_id,
            generation: 1,
            attempt: 1,
            body_hash: d.body_hash.unwrap(),
            idempotency_key: d.idempotency_key,
            kind: d.kind,
            cleanup_generation: None,
            retire_command: false,
        };
        if confirm {
            assert!(j.confirm(binding, &confirmation).unwrap());
        }
        confirmation
    }

    #[test]
    fn config_gc_requires_absence_settled_work_watermark_and_no_active_worker() {
        for gate in ["watermark", "stopped", "work", "worker"] {
            let dir = tempfile::tempdir().unwrap();
            let (binding, key, config) = fixture();
            let j = HostJournal::open(dir.path(), &binding).unwrap();
            j.install_key(&key, &binding, 1).unwrap();
            j.install_config(&config, &binding, 1).unwrap();
            let (create, command) = seed(&j, &binding, &config);
            let path = j.configs_dir.join(cleanup_file_name("sbx"));
            if gate == "work" {
                let mut state = j.state.lock().unwrap();
                let r = state.receipts.get_mut(&command.operation_id).unwrap();
                r.phase = ReceiptPhase::Effect;
                r.state = OperationState::UnknownOutcome;
                persist_receipt(&j.io, &j.receipts_dir, r).unwrap();
            }
            // The real lease-work guard, rather than a mocked GC predicate.
            let worker = (gate == "worker").then(|| j.lease_work(&create));
            let confirmed = cleanup(
                &j,
                &binding,
                if gate == "stopped" {
                    "sandbox.stop"
                } else {
                    "sandbox.kill"
                },
                gate != "watermark",
            );
            j.maintain().unwrap();
            assert!(path.exists(), "{gate}: config retained");
            assert!(
                !j.lookup(&create.operation_id).unwrap().digest_pruned,
                "{gate}"
            );
            if gate == "watermark" {
                assert!(j.confirm(&binding, &confirmed).unwrap());
            }
            if gate == "work" {
                j.record_result(
                    &command.operation_id,
                    OperationState::Succeeded,
                    None,
                    None,
                    None,
                )
                .unwrap();
            }
            drop(worker);
            if gate == "worker" {
                // Once the lifecycle worker settles, an absent census can retire
                // the captured lease that cleanup conservatively left active.
                let row = j.lease("sbx").unwrap();
                j.retire_inactive_lease(&row, true).unwrap();
            }
            if gate == "stopped" {
                cleanup(&j, &binding, "sandbox.kill", true);
            }
            // A known result must remain deliverable until confirmed, even
            // after destruction. Final confirmation removes its digests before GC.
            assert!(path.exists());
            confirm_result(&j, &binding, &create.operation_id);
            assert!(path.exists());
            confirm_result(&j, &binding, &command.operation_id);
            j.maintain().unwrap();
            assert!(!path.exists(), "{gate}: confirmed destruction permits GC");
            assert!(j.lookup(&create.operation_id).is_none());
            assert!(j.lookup(&command.operation_id).is_none());
        }
    }

    #[test]
    fn config_gc_watermark_must_cover_config_and_every_receipt_generation() {
        let dir = tempfile::tempdir().unwrap();
        let (binding, key, config) = fixture();
        let j = HostJournal::open(dir.path(), &binding).unwrap();
        j.install_key(&key, &binding, 1).unwrap();
        j.install_config(&config, &binding, 1).unwrap();
        let (create, _) = seed(&j, &binding, &config);
        let confirmation = cleanup(&j, &binding, "sandbox.kill", false);
        // Keep config/receipts newer than a genuine but insufficient watermark.
        {
            let mut state = j.state.lock().unwrap();
            let r = state.receipts.get_mut(&create.operation_id).unwrap();
            r.generation = 2;
            persist_receipt(&j.io, &j.receipts_dir, r).unwrap();
        }
        assert!(j.confirm(&binding, &confirmation).unwrap());
        assert!(j.configs_dir.join(cleanup_file_name("sbx")).exists());
        assert!(!j.lookup(&create.operation_id).unwrap().digest_pruned);
        drop(j);
        let j = HostJournal::open(dir.path(), &binding).unwrap();
        assert!(j.configs_dir.join(cleanup_file_name("sbx")).exists());
    }

    #[test]
    fn config_gc_crash_reopen_prunes_all_macs_before_unlink_and_no_checkpoint_resurrection() {
        for point in [
            CrashPoint::AfterDigestPrune,
            CrashPoint::BeforeConfigUnlink,
            CrashPoint::AfterConfigUnlink,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let (binding, key, config) = fixture();
            let j = HostJournal::open(dir.path(), &binding).unwrap();
            j.install_key(&key, &binding, 1).unwrap();
            j.install_config(&config, &binding, 1).unwrap();
            let (create, command) = seed(&j, &binding, &config);
            let before: Vec<_> = [&create, &command]
                .into_iter()
                .flat_map(|d| {
                    let receipt = j.lookup(&d.operation_id).unwrap();
                    [
                        receipt.body_hash.unwrap(),
                        receipt.request_hash.unwrap(),
                        receipt.server_request_hash.unwrap(),
                    ]
                })
                .chain([config.config.binding_mac.clone()])
                .collect();
            // Simulate a journal written by the earlier GC implementation.
            // Reopen/GC must finish stripping its checkpoint before unlinking.
            j.seed_pruned_receipt_for_test(&create.operation_id);
            j.seed_pruned_receipt_for_test(&command.operation_id);
            let confirmation = cleanup(&j, &binding, "sandbox.kill", false);
            j.clear_key(); // Pruning is safe even before the next hello/key ACK.
            j.inject_crash(point);
            assert!(j.confirm(&binding, &confirmation).is_err(), "{point:?}");
            let config_path = j.configs_dir.join(cleanup_file_name("sbx"));
            assert_eq!(
                config_path.exists(),
                point != CrashPoint::AfterConfigUnlink,
                "config unlinked last at {point:?}"
            );
            if point == CrashPoint::BeforeConfigUnlink {
                for subdir in [&j.receipts_dir, &j.leases_dir] {
                    for entry in fs::read_dir(subdir).unwrap() {
                        let bytes = fs::read_to_string(entry.unwrap().path()).unwrap();
                        for mac in &before {
                            assert!(
                                !bytes.contains(mac),
                                "all env MACs must be gone before config unlink"
                            );
                        }
                    }
                }
            }
            drop(j);
            // Open resumes GC without trusting a private checksum or a key.
            let j = HostJournal::open(dir.path(), &binding).unwrap();
            assert!(!config_path.exists());
            assert!(j.lease("sbx").unwrap().private_config.is_none());
            for d in [&create, &command] {
                let tombstone = j.lookup(&d.operation_id).unwrap();
                assert!(tombstone.digest_pruned);
                assert_eq!(
                    j.prepare_dispatch(&binding, d).unwrap_err(),
                    SandboxErrorCode::ReceiptDigestPruned
                );
                let serialized = serde_json::to_string(&tombstone).unwrap();
                for mac in &before {
                    assert!(!serialized.contains(mac));
                }
                assert!(j.record_effect(&d.operation_id).is_err());
                assert!(
                    j.record_result(&d.operation_id, OperationState::Succeeded, None, None, None)
                        .is_err()
                );
            }
            j.install_key(&key, &binding, 1).unwrap();
            assert!(
                j.install_config(&config, &binding, 1).is_err(),
                "late install cannot resurrect a destroyed config"
            );
            for subdir in [&j.receipts_dir, &j.leases_dir, &j.configs_dir] {
                for entry in fs::read_dir(subdir).unwrap() {
                    let bytes = fs::read_to_string(entry.unwrap().path()).unwrap();
                    assert!(!bytes.contains(&key.key_hex));
                    assert!(!bytes.contains(&config.env[0].1));
                    for mac in &before {
                        assert!(!bytes.contains(mac));
                    }
                }
            }
            drop(j);
            let j = HostJournal::open(dir.path(), &binding).unwrap();
            assert!(j.lease("sbx").unwrap().private_config.is_none());
            assert!(j.lookup(&command.operation_id).unwrap().digest_pruned);
        }
    }

    #[test]
    fn config_reference_digest_excludes_retry_transport_fields() {
        let dir = tempfile::tempdir().unwrap();
        let (binding, key, config) = fixture();
        let journal = HostJournal::open(dir.path(), &binding).unwrap();
        journal.install_key(&key, &binding, 1).unwrap();
        journal.install_config(&config, &binding, 1).unwrap();
        let mut dispatch = work("command", "command.run", Some(config.config));
        let original = journal.prepare_dispatch(&binding, &dispatch).unwrap();
        journal.record_intent(&original).unwrap();
        journal.record_effect("command").unwrap();
        journal
            .record_result("command", OperationState::Succeeded, None, None, None)
            .unwrap();
        let stored = journal.lookup("command").unwrap();
        dispatch.attempt += 1;
        dispatch.stdin_sequence = Some(99);
        let retry = journal.prepare_dispatch(&binding, &dispatch).unwrap();
        assert_eq!(retry.body_hash, original.body_hash);
        assert_eq!(retry.request_hash, original.request_hash);
        assert!(
            matches!(journal.record_intent(&retry).unwrap(), Decision::Replay(receipt) if receipt == stored)
        );
        dispatch.argv = Some(vec!["different".into()]);
        assert_eq!(
            journal.prepare_dispatch(&binding, &dispatch).unwrap_err(),
            SandboxErrorCode::IdempotencyConflict
        );
        assert_eq!(journal.lookup("command").unwrap(), stored);
    }

    #[test]
    fn config_reference_requires_matching_reinstalled_key_checksum_and_exact_binding() {
        let dir = tempfile::tempdir().unwrap();
        let (binding, key, config) = fixture();
        let j = HostJournal::open(dir.path(), &binding).unwrap();
        j.install_key(&key, &binding, 1).unwrap();
        j.install_config(&config, &binding, 1).unwrap();
        let d = work("create", "sandbox.create", Some(config.config.clone()));
        let mut missing = d.clone();
        missing.private_config = None;
        assert_eq!(
            j.prepare_dispatch(&binding, &missing).unwrap_err(),
            SandboxErrorCode::ProtocolError
        );
        assert!(j.prepare_dispatch(&binding, &d).is_ok());
        drop(j);
        let j = HostJournal::open(dir.path(), &binding).unwrap();
        assert_eq!(
            j.prepare_dispatch(&binding, &d).unwrap_err(),
            SandboxErrorCode::DigestKeyUnavailable
        );
        j.install_key(&key, &binding, 1).unwrap();
        assert!(j.prepare_dispatch(&binding, &d).is_ok());
        let mut wrong = d.clone();
        wrong.private_config.as_mut().unwrap().binding_key_id = "e".repeat(32);
        let before = calls(&j);
        assert_eq!(
            j.prepare_dispatch(&binding, &wrong).unwrap_err(),
            SandboxErrorCode::DigestKeyChanged
        );
        assert_eq!(calls(&j), before);
        let path = j.configs_dir.join(cleanup_file_name("sbx"));
        let mut disk: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        disk["checksum"] = "0".repeat(64).into();
        fs::write(path, disk.to_string()).unwrap();
        assert_eq!(
            j.prepare_dispatch(&binding, &d).unwrap_err(),
            SandboxErrorCode::ProtocolError
        );
        assert!(j.state.lock().unwrap().receipts.is_empty());
    }
    /// After a failed restore's cleanup (a
    /// confirmed kill proving absence) and its config GC, a same-host retry
    /// at a later admission generation installs, also across a daemon
    /// restart; an install at or below the watermark generation, or above a
    /// watermark without proven absence, stays refused; the GC of the old
    /// attempt never removes the new config.
    #[test]
    fn a_retry_above_an_absent_cleanup_watermark_reinstalls_its_config() {
        use sandbox_protocol::PrivateConfigRefusalReason as Reason;
        let refused = |result: Result<_>| {
            result
                .err()
                .and_then(|e| e.downcast_ref::<Reason>().copied())
                == Some(Reason::CleanupWatermark)
        };
        for restart in [false, true] {
            for teardown in ["sandbox.kill", "sandbox.stop"] {
                let dir = tempfile::tempdir().unwrap();
                let (binding, key, config) = fixture();
                let mut j = HostJournal::open(dir.path(), &binding).unwrap();
                j.install_key(&key, &binding, 1).unwrap();
                j.install_config(&config, &binding, 1).unwrap();
                let path = j.configs_dir.join(cleanup_file_name("sbx"));
                cleanup(&j, &binding, teardown, true);
                j.maintain().unwrap();
                if teardown == "sandbox.kill" {
                    assert!(!path.exists(), "attempt g's config is GC'd");
                } else {
                    // A stop proves no absence: the config stays bound.
                    assert!(path.exists());
                    fs::remove_file(&path).unwrap();
                    j.state.lock().unwrap().configs.remove("sbx");
                }
                if restart {
                    drop(j);
                    j = HostJournal::open(dir.path(), &binding).unwrap();
                    j.install_key(&key, &binding, 1).unwrap();
                }
                // At or below the watermark generation: never resurrected.
                assert!(
                    refused(j.install_config(&config, &binding, 1)),
                    "{teardown}"
                );
                let mut retry = config.clone();
                retry.generation = 2;
                let installed = j.install_config(&retry, &binding, 1);
                if teardown == "sandbox.stop" {
                    assert!(refused(installed), "no absence, no re-admission");
                    continue;
                }
                installed.expect("a later admission installs");
                assert!(path.exists());
                // The GC of attempt g runs again: the g+1 config survives.
                j.maintain().unwrap();
                assert!(path.exists(), "the retry's config is never GC'd by g");
                drop(j);
                let j = HostJournal::open(dir.path(), &binding).unwrap();
                j.maintain().unwrap();
                assert!(path.exists());
            }
        }
    }

    /// A stopped sandbox evicted from this
    /// host (VM deleted, root proven absent) and later restored back onto it
    /// arrives with the same config at generation g + 1. The eviction proves
    /// absence, so the stop's watermark becomes an absent one, the old config
    /// is collected, the lease may be rearmed by the restore, and the
    /// restore's install succeeds; an install at or below the stopped
    /// generation stays refused.
    #[test]
    fn an_eviction_lets_a_restore_back_onto_this_host_install_its_config() {
        use sandbox_protocol::PrivateConfigRefusalReason as Reason;
        let dir = tempfile::tempdir().unwrap();
        let (binding, key, config) = fixture();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap();
        j.install_key(&key, &binding, 1).unwrap();
        j.install_config(&config, &binding, 1).unwrap();
        let mut create = serde_json::to_value(work(
            "create",
            "sandbox.create",
            Some(config.config.clone()),
        ))
        .unwrap();
        create["allocation"] =
            serde_json::to_value(crate::sandbox_relay::test_support::allocation()).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        create["lease"] = serde_json::json!({"revision":1,"deadlineUnixMs":now + 3_600_000,
            "action":"destroy","expiryPolicy":"retry-force-60s"});
        let create: OperationDispatch = serde_json::from_value(create).unwrap();
        j.record_intent(&j.prepare_dispatch(&binding, &create).unwrap())
            .unwrap();
        j.accept_lease(&create).unwrap();
        j.record_effect("create").unwrap();
        j.record_result(
            "create",
            OperationState::Succeeded,
            Some(serde_json::json!({"state":"ready"})),
            None,
            None,
        )
        .unwrap();
        confirm_result(&j, &binding, "create");
        cleanup(&j, &binding, "sandbox.stop", true);
        j.maintain().unwrap();
        let path = j.configs_dir.join(cleanup_file_name("sbx"));
        assert!(path.exists(), "a stop proves no absence");
        let mut restore = config.clone();
        restore.generation = 2;
        assert!(
            j.install_config(&restore, &binding, 1).is_err(),
            "before the eviction"
        );

        j.record_evicted("sbx").unwrap();
        assert!(
            !path.exists(),
            "the evicted generation's config is collected"
        );
        // An eviction settles like a completed stop, never a destroy expiry
        // (C32): the restore's new generation may rearm (no `lease_lapsed`).
        assert_eq!(j.work_refusal("sbx", 2, "sandbox.reconnect"), None);
        assert!(
            !j.work_allowed("sbx", 1, "command.run"),
            "the evicted lease runs nothing"
        );
        let stale = j.install_config(&config, &binding, 1);
        assert_eq!(
            stale
                .err()
                .and_then(|e| e.downcast_ref::<Reason>().copied()),
            Some(Reason::CleanupWatermark),
            "the evicted generation is never resurrected"
        );
        j.install_config(&restore, &binding, 1)
            .expect("the restore's config installs");
        drop(j);
        let j = HostJournal::open(dir.path(), &binding).unwrap();
        j.maintain().unwrap();
        assert!(
            path.exists(),
            "the restore's config survives a restart and GC"
        );
    }

    /// Review repro (offload C1–C8, P1): confirmed create (destroy lease, no
    /// allocation) → confirmed stop → eviction → maintenance → a restore
    /// back onto this host at a later generation (a new binding MAC)
    /// installs its config and is admitted.
    #[test]
    fn review_repro_eviction_then_maintenance_admits_a_same_host_restore() {
        let dir = tempfile::tempdir().unwrap();
        let (binding, key, config) = fixture();
        let j = HostJournal::open(dir.path(), &binding).unwrap();
        j.install_key(&key, &binding, 1).unwrap();
        j.install_config(&config, &binding, 1).unwrap();
        let mut create = work("create", "sandbox.create", Some(config.config.clone()));
        create.lease.as_mut().unwrap().action = sandbox_protocol::LeaseAction::Destroy;
        j.record_intent(&j.prepare_dispatch(&binding, &create).unwrap())
            .unwrap();
        j.accept_lease(&create).unwrap();
        j.record_effect("create").unwrap();
        j.record_result(
            "create",
            OperationState::Succeeded,
            Some(serde_json::json!({"state":"ready", "lease":create.lease})),
            None,
            None,
        )
        .unwrap();
        confirm_result(&j, &binding, "create");
        cleanup(&j, &binding, "sandbox.stop", true);
        j.record_evicted("sbx").unwrap();
        j.maintain().unwrap();
        let mut next = config.clone();
        next.generation = 3;
        next.config.binding_mac = "e".repeat(64);
        j.install_config(&next, &binding, 1)
            .expect("the restore's config installs after eviction + maintenance");
        let mut restore = create.clone();
        restore.operation_id = "restore".into();
        restore.idempotency_key = "restore".into();
        restore.kind = "sandbox.reconnect".into();
        restore.generation = 3;
        restore.private_config = Some(next.config.clone());
        restore.lease.as_mut().unwrap().revision = 2;
        j.record_intent(&j.prepare_dispatch(&binding, &restore).unwrap())
            .unwrap();
        j.accept_lease(&restore)
            .expect("the restore's lease is admitted");
    }

    /// A crash at each step boundary of an
    /// eviction (after the absent lease, after the cleanup watermark, inside
    /// the config GC) never leaves this host refusing a restore back onto
    /// it. After a restart and maintenance the restore's config at a later
    /// generation installs and its lease is admitted, while an install at or
    /// below the watermark stays refused. Covered with and without the
    /// confirmed stop's (not absent) watermark in place before the eviction.
    #[test]
    fn an_eviction_crash_at_each_step_still_admits_a_same_host_restore() {
        use sandbox_protocol::PrivateConfigRefusalReason as Reason;
        let points = [
            None,
            Some(CrashPoint::AfterEvictedLease),
            Some(CrashPoint::AfterEvictedWatermark),
            Some(CrashPoint::AfterDigestPrune),
            Some(CrashPoint::BeforeConfigUnlink),
            Some(CrashPoint::AfterConfigUnlink),
        ];
        for stop_confirmed in [true, false] {
            for point in points {
                let case = format!("stop_confirmed={stop_confirmed} crash={point:?}");
                let dir = tempfile::tempdir().unwrap();
                let (binding, key, config) = fixture();
                let j =
                    crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap();
                j.install_key(&key, &binding, 1).unwrap();
                j.install_config(&config, &binding, 1).unwrap();
                let mut create = work("create", "sandbox.create", Some(config.config.clone()));
                create.lease.as_mut().unwrap().action = sandbox_protocol::LeaseAction::Destroy;
                create.allocation = Some(crate::sandbox_relay::test_support::allocation());
                j.record_intent(&j.prepare_dispatch(&binding, &create).unwrap())
                    .unwrap();
                j.accept_lease(&create).unwrap();
                j.record_effect("create").unwrap();
                j.record_result(
                    "create",
                    OperationState::Succeeded,
                    Some(serde_json::json!({"state":"ready", "lease":create.lease})),
                    None,
                    None,
                )
                .unwrap();
                confirm_result(&j, &binding, "create");
                if stop_confirmed {
                    cleanup(&j, &binding, "sandbox.stop", true);
                    assert!(
                        !j.state.lock().unwrap().cleanups["sbx"].instance_absent,
                        "{case}: a stop proves no absence"
                    );
                }
                if let Some(point) = point {
                    j.inject_crash(point);
                }
                // A crash point inside the best-effort GC returns Ok; the
                // others fail the call. Either way the process dies here.
                let _ = j.record_evicted("sbx");
                drop(j);
                let j = HostJournal::open(dir.path(), &binding).unwrap();
                j.install_key(&key, &binding, 1).unwrap();
                j.maintain().unwrap();
                assert!(
                    !j.state.lock().unwrap().storage.roots.contains_key("sbx"),
                    "{case}: the evicted root's storage is released"
                );
                let stale = j.install_config(&config, &binding, 1);
                assert_eq!(
                    stale
                        .err()
                        .and_then(|e| e.downcast_ref::<Reason>().copied()),
                    Some(Reason::CleanupWatermark),
                    "{case}: the evicted generation is never resurrected"
                );
                let mut next = config.clone();
                next.generation = 3;
                next.config.binding_mac = "e".repeat(64);
                j.install_config(&next, &binding, 1)
                    .unwrap_or_else(|e| panic!("{case}: the restore's config installs: {e:#}"));
                let mut restore = create.clone();
                restore.operation_id = "restore".into();
                restore.idempotency_key = "restore".into();
                restore.kind = "sandbox.reconnect".into();
                restore.generation = 3;
                restore.private_config = Some(next.config.clone());
                restore.lease.as_mut().unwrap().revision = 2;
                // The released root is not retained: the restore boots from
                // the store's copy, not a warm root on this host.
                restore.allocation = None;
                j.record_intent(&j.prepare_dispatch(&binding, &restore).unwrap())
                    .unwrap();
                j.accept_lease(&restore)
                    .unwrap_or_else(|e| panic!("{case}: the restore's lease is admitted: {e:#}"));
            }
        }
    }

    #[test]
    fn config_gc_old_watermark_cannot_remove_newer_config() {
        let dir = tempfile::tempdir().unwrap();
        let (binding, key, mut config) = fixture();
        config.generation = 2;
        let j = HostJournal::open(dir.path(), &binding).unwrap();
        j.install_key(&key, &binding, 1).unwrap();
        j.install_config(&config, &binding, 1).unwrap();
        let watermark = CleanupWatermark {
            sandbox_owner_id: "owner".into(),
            version: JOURNAL_VERSION,
            binding: binding.clone(),
            sandbox_id: "sbx".into(),
            generation: 1,
            instance_absent: true,
            ext: JournalExt::new(),
        };
        persist_cleanup(&j.io, &j.cleanups_dir, &watermark).unwrap();
        j.state
            .lock()
            .unwrap()
            .cleanups
            .insert("sbx".into(), watermark);
        j.maintain().unwrap();
        assert!(j.configs_dir.join(cleanup_file_name("sbx")).exists());
        drop(j);
        let j = HostJournal::open(dir.path(), &binding).unwrap();
        assert!(j.configs_dir.join(cleanup_file_name("sbx")).exists());
    }

    #[test]
    fn config_gc_receipt_only_command_env_waits_for_confirmation() {
        let dir = tempfile::tempdir().unwrap();
        let (binding, key, _) = fixture();
        let j = HostJournal::open(dir.path(), &binding).unwrap();
        j.install_key(&key, &binding, 1).unwrap();
        let mut command = work("command", "command.run", None);
        command.env = Some(vec![("K".into(), "receipt-only-command-sentinel".into())]);
        j.record_intent(&j.prepare_dispatch(&binding, &command).unwrap())
            .unwrap();
        j.record_effect(&command.operation_id).unwrap();
        j.record_result(
            &command.operation_id,
            OperationState::Succeeded,
            Some(serde_json::json!({"exitCode":0})),
            None,
            None,
        )
        .unwrap();
        // A key-free confirmed kill provides absence even without a retained
        // lease/config, as for a command-only pre-config journal.
        j.clear_key();
        cleanup(&j, &binding, "sandbox.kill", true);
        let retained = j.lookup(&command.operation_id).unwrap();
        assert!(!retained.digest_pruned);
        assert_eq!(retained.result.unwrap()["exitCode"], 0);
        assert_eq!(fs::read_dir(&j.configs_dir).unwrap().count(), 0);
        drop(j);
        let j = HostJournal::open(dir.path(), &binding).unwrap();
        assert!(!j.lookup(&command.operation_id).unwrap().digest_pruned);
        j.install_key(&key, &binding, 1).unwrap();
        confirm_result(&j, &binding, &command.operation_id);
        assert!(j.lookup(&command.operation_id).is_none());
    }

    #[test]
    fn config_hello_owner_binding_is_checked_before_key_ack() {
        let dir = tempfile::tempdir().unwrap();
        let (binding, key, config) = fixture();
        {
            let j = HostJournal::open(dir.path(), &binding).unwrap();
            j.install_key(&key, &binding, 1).unwrap();
            j.install_config(&config, &binding, 1).unwrap();
        }
        let unbound = TransportBindingV11 {
            host_owner_id: String::new(),
            ..binding.clone()
        };
        let j = HostJournal::open(dir.path(), &unbound).unwrap();
        let other = TransportBindingV11 {
            host_owner_id: "other-owner".into(),
            ..binding.clone()
        };
        let other_key = sandbox_protocol::JournalKeyInstall {
            host_owner_id: other.host_owner_id.clone(),
            ..key.clone()
        };
        assert!(j.matching(&other).is_err());
        let error = j.install_key(&other_key, &other, 1).unwrap_err();
        assert_eq!(format!("{error:#}"), "private config journal refused");
        assert!(j.key.lock().unwrap().is_none());
        j.install_key(&key, &binding, 1).unwrap();
        assert!(j.matching(&binding).is_ok());
    }

    /// Review probe (s2b2 sec r1, F1): before this slice an unconfirmed terminal
    /// receipt is retired at the next hello by the server's exact-binding
    /// confirmation against its terminal row. Config GC must not tombstone it
    /// first: a tombstone refuses every confirmation and nothing else deletes
    /// it, so it occupies one of MAX_RECEIPTS admission slots forever.
    #[test]
    fn probe_gc_tombstone_keeps_unconfirmed_terminal_receipt_retirable() {
        let dir = tempfile::tempdir().unwrap();
        let (binding, key, config) = fixture();
        let j = HostJournal::open(dir.path(), &binding).unwrap();
        j.install_key(&key, &binding, 1).unwrap();
        j.install_config(&config, &binding, 1).unwrap();
        let (_create, command) = seed(&j, &binding, &config);
        let original = j.lookup(&command.operation_id).unwrap();
        let confirmation = sandbox_protocol::ReceiptConfirmation {
            sandbox_owner_id: original.sandbox_owner_id.clone(),
            operation_id: original.operation_id.clone(),
            sandbox_id: original.sandbox_id.clone(),
            generation: original.generation,
            attempt: original.attempt,
            body_hash: original.server_request_hash().unwrap().to_owned(),
            idempotency_key: original.idempotency_key.clone(),
            kind: original.kind.clone(),
            cleanup_generation: None,
            retire_command: false,
        };
        // The kill settles first (e.g. reconciliation order after an offline
        // destroy, or a command result the server fenced before the kill).
        cleanup(&j, &binding, "sandbox.kill", true);
        // Then the server's exact-binding confirmation for the SUCCEEDED command.
        let retained = j.lookup(&command.operation_id).unwrap();
        assert!(!retained.digest_pruned);
        assert_eq!(retained.result, original.result);
        assert_eq!(retained.body_hash, original.body_hash);
        assert!(j.configs_dir.join(cleanup_file_name("sbx")).exists());
        assert!(j.confirm(&binding, &confirmation).unwrap());
        assert!(
            j.lookup(&command.operation_id).is_none(),
            "a settled, exactly confirmed command receipt must not become a permanent tombstone"
        );
    }
}
