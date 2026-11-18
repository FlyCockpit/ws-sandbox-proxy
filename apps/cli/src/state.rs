//! One locked credential state and a durable, non-secret selection intent.
//!
//! Lock order: config-dir `auth.lock`, then data-dir `auth.lock` (once when both
//! directories canonicalize the same). Never hold the relay journal lock here.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use crate::auth::canonical_control_plane_origin;
use crate::config::Config;

pub const CONFIG_GENERATION_FILE: &str = ".wssp-config-generation";

const STAGING_PREFIX: &str = ".wssp-staging-";
const STAGING_SUFFIX: &str = ".tmp";
const TOMBSTONE_PREFIX: &str = ".wssp-tombstone-";
const STAGING_HEX_LEN: usize = 32;

/// Names the startup sweep may delete (strict staging/tombstone patterns only).
pub(crate) fn is_sweepable_staging_name(name: &str) -> bool {
    parse_staging_temp_name(name).is_some() || parse_tombstone_name(name).is_some()
}

fn parse_staging_temp_name(name: &str) -> Option<()> {
    let hex = name
        .strip_prefix(STAGING_PREFIX)?
        .strip_suffix(STAGING_SUFFIX)?;
    parse_fixed_hex(hex).map(|_| ())
}

fn parse_tombstone_name(name: &str) -> Option<()> {
    let hex = name.strip_prefix(TOMBSTONE_PREFIX)?;
    parse_fixed_hex(hex).map(|_| ())
}

fn parse_fixed_hex(hex: &str) -> Option<&str> {
    if hex.len() != STAGING_HEX_LEN || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(hex)
}

fn random_staging_hex() -> Result<String> {
    let mut random = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| anyhow::anyhow!("generating staging file nonce"))?;
    Ok(random.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn staging_temp_path(dir: &Path) -> Result<(PathBuf, File)> {
    loop {
        let name = format!("{STAGING_PREFIX}{}{STAGING_SUFFIX}", random_staging_hex()?);
        let path = dir.join(&name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            // Private from creation, not only after the later chmod (E-16).
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error).context("creating auth staging file"),
        }
    }
}

#[cfg(windows)]
fn unique_tombstone_path(parent: &Path) -> Result<PathBuf> {
    loop {
        let path = parent.join(format!("{TOMBSTONE_PREFIX}{}", random_staging_hex()?));
        if !path.exists() {
            return Ok(path);
        }
    }
}

fn config_generation_path(dir: &Path) -> PathBuf {
    dir.join(CONFIG_GENERATION_FILE)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CredentialKind {
    Device,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceCredential {
    pub origin: String,
    pub host_slug: String,
    pub host_id: String,
    pub credential_id: String,
    pub kind: CredentialKind,
    pub secret: String,
    pub generation: String,
}

#[derive(Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
enum Operation {
    Login,
    Logout,
    #[default]
    Idle,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Intent {
    generation: String,
    operation: Operation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    login_origin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    config_generation: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginStart {
    pub generation: String,
    pub server_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutOutcome {
    pub removed_device_credential: bool,
    pub removed_token_env: bool,
    pub warnings: Vec<String>,
}

pub struct AuthStore {
    _config_lock: File,
    _data_lock: Option<File>,
    dir: PathBuf,
    config_dir: PathBuf,
    config_path: PathBuf,
}

fn read_config_generation(dir: &Path) -> Result<u64> {
    match std::fs::read_to_string(config_generation_path(dir)) {
        Ok(text) => text
            .trim()
            .parse()
            .context("parsing config generation marker"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error).context("reading config generation marker"),
    }
}

fn bump_config_generation(dir: &Path) -> Result<u64> {
    let next = read_config_generation(dir)? + 1;
    atomic_write(&config_generation_path(dir), next.to_string().as_bytes())?;
    Ok(next)
}

/// The host device credential file inside the data directory.
pub const DEVICE_CREDENTIAL_FILE: &str = "device-auth.json";

impl AuthStore {
    pub fn open(deadline: Option<Instant>) -> Result<Self> {
        Self::at(
            crate::paths::data_dir()?,
            crate::paths::config_file()?,
            deadline,
        )
    }

    pub(crate) fn at(
        dir: PathBuf,
        config_path: PathBuf,
        deadline: Option<Instant>,
    ) -> Result<Self> {
        let config_dir = config_path
            .parent()
            .context("config path has no parent")?
            .to_path_buf();
        private_dir(&config_dir)?;
        if dir != config_dir {
            private_dir(&dir)?;
        }
        let config_lock = open_lock_file(&config_dir)?;
        wait_for_lock(&config_lock, deadline)?;
        let shared = same_lock_dir(&dir, &config_dir)?;
        let data_lock = if shared {
            None
        } else {
            let lock = open_lock_file(&dir)?;
            wait_for_lock(&lock, deadline)?;
            Some(lock)
        };
        let store = Self {
            _config_lock: config_lock,
            _data_lock: data_lock,
            dir,
            config_dir,
            config_path,
        };
        store.sweep()?;
        if store.intent()?.operation == Operation::Logout {
            let _ = store.finish_logout()?;
        }
        Ok(store)
    }

    fn intent_path(&self) -> PathBuf {
        self.dir.join("auth-intent.json")
    }
    fn credential_path(&self) -> PathBuf {
        self.dir.join(DEVICE_CREDENTIAL_FILE)
    }
    fn intent(&self) -> Result<Intent> {
        Ok(read_json(&self.intent_path())?.unwrap_or_default())
    }

    fn advance(
        &self,
        operation: Operation,
        login_origin: Option<String>,
        config_generation: Option<u64>,
    ) -> Result<String> {
        let mut random = [0_u8; 16];
        SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| anyhow::anyhow!("generating login nonce"))?;
        let generation: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        self.write_json(
            &self.intent_path(),
            &Intent {
                generation: generation.clone(),
                operation,
                login_origin,
                config_generation,
            },
        )?;
        Ok(generation)
    }

    fn sweep(&self) -> Result<()> {
        sweep_dir(&self.dir)?;
        if self.config_dir != self.dir {
            sweep_dir(&self.config_dir)?;
        }
        Ok(())
    }

    pub fn credential(&self) -> Result<Option<DeviceCredential>> {
        let path = self.credential_path();
        match std::fs::symlink_metadata(&path) {
            Ok(meta) => {
                anyhow::ensure!(
                    meta.is_file() && !meta.file_type().is_symlink(),
                    "credential state must be a regular file"
                );
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    anyhow::ensure!(
                        meta.permissions().mode() & 0o777 == 0o600,
                        "credential state must have owner-only mode 0600"
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("reading credential metadata"),
        }
        let credential: DeviceCredential = read_json(&path)?.context("missing credential state")?;
        crate::auth::validate_product_secret(&credential.secret, "wssp_device_")?;
        anyhow::ensure!(
            credential.origin == crate::auth::canonical_control_plane_origin(&credential.origin)?,
            "invalid credential origin"
        );
        crate::slug::validate_host_slug(&credential.host_slug)?;
        anyhow::ensure!(
            !credential.host_id.is_empty()
                && !credential.credential_id.is_empty()
                && !credential.generation.is_empty(),
            "invalid credential identity"
        );
        Ok(Some(credential))
    }

    pub fn snapshot(&self) -> Result<(Config, Option<DeviceCredential>)> {
        let device = self.credential()?;
        let intent = self.intent()?;
        let published_login = intent.operation == Operation::Login
            && device
                .as_ref()
                .is_some_and(|d| d.generation == intent.generation);
        let mut config = match Config::read(&self.config_path) {
            Ok(config) => config,
            Err(_) if published_login => Config::default(),
            Err(error) => return Err(error),
        };
        if published_login {
            config.host_token_env = None;
        }
        Ok((config, device))
    }

    /// Use connect's credential selection while retaining capacity diagnostics.
    pub(crate) fn inspect_config(&self) -> Result<(Config, Vec<&'static str>)> {
        let device = self.credential()?;
        let intent = self.intent()?;
        let published_login = intent.operation == Operation::Login
            && device
                .as_ref()
                .is_some_and(|d| d.generation == intent.generation);
        let (mut config, diagnostics) = match Config::read_for_inspection(&self.config_path) {
            Ok(view) => view,
            Err(_) if published_login => (
                Config::default(),
                vec!["config unavailable after device login"],
            ),
            Err(error) => return Err(error),
        };
        if published_login {
            config.host_token_env = None;
        }
        if config.host_token_env.is_none()
            && let Some(device) = device
        {
            config.server_url = Some(device.origin);
        }
        Ok((config, diagnostics))
    }

    fn reconcile_login(&self) -> Result<()> {
        let intent = self.intent()?;
        if intent.operation == Operation::Login
            && let Some(device) = self.credential()?
            && device.generation == intent.generation
        {
            let mut config = Config::read(&self.config_path)?;
            if config.host_token_env.take().is_some() {
                self.save_config(&config)?;
            }
        }
        Ok(())
    }

    pub fn begin_login(&self, server_override: Option<&str>, slug: &str) -> Result<LoginStart> {
        crate::slug::validate_host_slug(slug)?;
        self.reconcile_login()?;
        let config = Config::read(&self.config_path)?;
        let server_url = server_override.or(config.server_url.as_deref()).context(
            "server URL is not configured; pass `--server` or run `wssp host config set-server`",
        )?;
        let server_url = canonical_control_plane_origin(server_url)?;
        let config_generation = read_config_generation(&self.config_dir)?;
        let generation = self.advance(
            Operation::Login,
            Some(server_url.clone()),
            Some(config_generation),
        )?;
        Ok(LoginStart {
            generation,
            server_url,
        })
    }

    pub fn check_generation(&self, generation: &str) -> Result<()> {
        let intent = self.intent()?;
        anyhow::ensure!(
            intent.operation == Operation::Login && intent.generation == generation,
            "login superseded by a newer local selection; run `wssp host enroll` again"
        );
        Ok(())
    }

    pub fn publish(&self, generation: &str, credential: DeviceCredential) -> Result<()> {
        let ca_file = Config::read(&self.config_path)?.ca_file;
        self.publish_with_ca_file(generation, credential, ca_file)
    }

    pub fn publish_with_ca_file(
        &self,
        generation: &str,
        mut credential: DeviceCredential,
        ca_file: Option<PathBuf>,
    ) -> Result<()> {
        self.check_generation(generation)?;
        let intent = self.intent()?;
        let current = read_config_generation(&self.config_dir)?;
        anyhow::ensure!(
            intent.config_generation == Some(current),
            "configured server changed during login; run `wssp host enroll` again"
        );
        test_barrier("before_publish");
        self.sweep()?;
        credential.generation = generation.to_owned();
        self.write_json(&self.credential_path(), &credential)?;
        let mut config = Config::read(&self.config_path)?;
        config.host_token_env = None;
        config.server_url = Some(credential.origin.clone());
        config.ca_file = ca_file;
        self.save_config(&config)
            .context("credential saved; updating login defaults failed")?;
        self.write_json(
            &self.intent_path(),
            &Intent {
                generation: generation.to_owned(),
                operation: Operation::Idle,
                login_origin: None,
                config_generation: None,
            },
        )
    }

    pub fn update_config<T>(&self, mutate: impl FnOnce(&mut Config) -> Result<T>) -> Result<T> {
        self.reconcile_login()?;
        let mut config = Config::read(&self.config_path)?;
        let value = mutate(&mut config)?;
        self.advance(Operation::Idle, None, None)?;
        self.save_config(&config)?;
        Ok(value)
    }

    pub fn init_config(&self) -> Result<bool> {
        if self.config_path.try_exists()? {
            return Ok(false);
        }
        self.save_config(&Config::default())?;
        Ok(true)
    }

    fn save_config(&self, config: &Config) -> Result<()> {
        let dir = self
            .config_path
            .parent()
            .context("config path has no parent")?;
        private_dir(dir)?;
        // Advance the generation before committing the config: a failure between
        // the two writes then rejects a pending login instead of letting it
        // publish over a config change it never observed (C20-6).
        bump_config_generation(&self.config_dir)?;
        atomic_write(
            &self.config_path,
            toml::to_string_pretty(config)?.as_bytes(),
        )?;
        Ok(())
    }

    fn write_json(&self, path: &Path, value: &impl Serialize) -> Result<()> {
        atomic_write(path, &serde_json::to_vec_pretty(value)?)
    }

    pub fn logout(&self) -> Result<LogoutOutcome> {
        let removed_device = self.credential_path().try_exists()?;
        self.advance(Operation::Logout, None, None)?;
        let mut outcome = self.finish_logout()?;
        outcome.removed_device_credential = removed_device;
        Ok(outcome)
    }

    fn finish_logout(&self) -> Result<LogoutOutcome> {
        remove_durable(&self.credential_path())?;
        let mut removed_token_env = false;
        let mut warnings = Vec::new();
        match Config::read(&self.config_path) {
            Ok(mut config) => {
                if config.host_token_env.take().is_some() {
                    match self.save_config(&config) {
                        Ok(()) => removed_token_env = true,
                        Err(error) => warnings.push(format!(
                            "device credential removed; could not clear host token binding: {error:#}"
                        )),
                    }
                }
            }
            Err(error) => warnings.push(format!(
                "device credential removed; config file unchanged: {error:#}"
            )),
        }
        self.sweep()?;
        let mut intent = self.intent()?;
        intent.operation = Operation::Idle;
        intent.login_origin = None;
        intent.config_generation = None;
        self.write_json(&self.intent_path(), &intent)?;
        Ok(LogoutOutcome {
            removed_device_credential: false,
            removed_token_env,
            warnings,
        })
    }
}

fn same_lock_dir(left: &Path, right: &Path) -> Result<bool> {
    if left == right {
        return Ok(true);
    }
    Ok(std::fs::canonicalize(left)? == std::fs::canonicalize(right)?)
}

fn open_lock_file(dir: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(dir.join("auth.lock"))
        .context("opening auth state lock")
}

fn wait_for_lock(lock: &File, deadline: Option<Instant>) -> Result<()> {
    let deadline = deadline.unwrap_or_else(|| Instant::now() + Duration::from_secs(15));
    loop {
        match lock.try_lock() {
            Ok(()) => return Ok(()),
            Err(std::fs::TryLockError::WouldBlock) => {
                let remaining =
                    crate::auth::remaining(deadline).context("waiting for auth state lock")?;
                std::thread::sleep(remaining.min(Duration::from_millis(10)));
            }
            Err(error) => anyhow::bail!("locking auth state: {error}"),
        }
    }
}

#[cfg(debug_assertions)]
pub(crate) fn test_barrier(name: &str) {
    let Ok(flag) = std::env::var(format!("WSSP_TEST_BARRIER_{}", name.to_uppercase())) else {
        return;
    };
    let path = PathBuf::from(flag);
    let deadline = Instant::now() + Duration::from_secs(15);
    while !path.exists() {
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(not(debug_assertions))]
pub(crate) fn test_barrier(_name: &str) {}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>> {
    match std::fs::read(path) {
        Ok(bytes) => {
            Ok(Some(serde_json::from_slice(&bytes).with_context(|| {
                format!("parsing `{}`", path.display())
            })?))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("reading `{}`", path.display())),
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().context("state path has no parent")?;
    private_dir(dir)?;
    let (temp_path, mut temp) = staging_temp_path(dir)?;
    let write_result = (|| -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            temp.set_permissions(std::fs::Permissions::from_mode(0o600))
                .context("setting private auth file permissions")?;
        }
        temp.write_all(bytes)
            .context("writing auth temporary file")?;
        temp.sync_all().context("flushing auth temporary file")?;
        drop(temp);
        std::fs::rename(&temp_path, path).context("publishing auth file")?;
        sync_directory(dir)
    })();
    if write_result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    write_result
}

fn remove_durable(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("reading auth file metadata"),
        Ok(_) => {}
    }
    #[cfg(windows)]
    {
        let parent = path.parent().context("state path has no parent")?;
        let tombstone = unique_tombstone_path(parent)?;
        std::fs::rename(path, &tombstone).context("renaming auth file to tombstone")?;
        std::fs::remove_file(&tombstone).context("removing auth tombstone")?;
        sync_directory(parent)
    }
    #[cfg(not(windows))]
    {
        match std::fs::remove_file(path) {
            Ok(()) => sync_directory(path.parent().context("state path has no parent")?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("removing auth file"),
        }
    }
}

fn sweep_dir(dir: &Path) -> Result<()> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("scanning auth directory"),
    };
    for entry in entries {
        let entry = entry?;
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        if is_sweepable_staging_name(&name) {
            remove_durable(&entry.path())?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn create_durable_dir(path: &Path) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    create_durable_dir(parent)?;
    // E-16: every component created here is owner-only (0700) whatever the
    // process umask; existing ancestors keep their mode.
    let mut builder = std::fs::DirBuilder::new();
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(err) => return Err(err.into()),
    }
    File::open(parent)
        .context("opening auth directory parent")?
        .sync_all()
        .context("syncing auth directory parent")?;
    #[cfg(all(unix, debug_assertions))]
    if let Ok(marker) = std::env::var("WSSP_TEST_RECORD_PARENT_SYNC")
        && parent == Path::new(&marker)
    {
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(parent.join(".wssp-parent-sync-recorded"));
    }
    Ok(())
}

fn private_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        create_durable_dir(path)?;
        anyhow::ensure!(
            !std::fs::symlink_metadata(path)?.file_type().is_symlink(),
            "auth directory must not be a symlink"
        );
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(windows)]
    {
        std::fs::create_dir_all(path)?;
    }
    #[cfg(not(any(unix, windows)))]
    anyhow::bail!("unsupported credential storage platform");
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?
            .sync_all()
            .context("syncing auth directory")?;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const GENERIC_WRITE: u32 = 0x4000_0000;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        OpenOptions::new()
            .access_mode(GENERIC_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .read(true)
            .open(path)
            .context("opening auth directory for flush")?
            .sync_all()
            .context("flushing auth directory")?;
    }
    #[cfg(not(any(unix, windows)))]
    anyhow::bail!(
        "unsupported credential storage platform: {}",
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn store(root: &Path) -> AuthStore {
        AuthStore::at(root.join("data"), root.join("config/config.toml"), None).unwrap()
    }

    #[test]
    fn config_is_not_committed_when_generation_advance_fails() {
        let root = tempfile::tempdir().unwrap();
        let store = store(root.path());
        store
            .update_config(|config| {
                config.server_url = Some("https://old.example.test/".into());
                Ok(())
            })
            .unwrap();
        let before = std::fs::read_to_string(&store.config_path).unwrap();
        let marker = config_generation_path(&store.config_dir);
        std::fs::remove_file(&marker).unwrap();
        std::fs::create_dir(&marker).unwrap();
        let result = store.update_config(|config| {
            config.server_url = Some("https://new.example.test/".into());
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(std::fs::read_to_string(&store.config_path).unwrap(), before);
    }
    fn credential() -> DeviceCredential {
        DeviceCredential {
            origin: "https://example.test/".into(),
            host_slug: "desk-01".into(),
            host_id: "host-1".into(),
            credential_id: "cred-1".into(),
            kind: CredentialKind::Device,
            secret: format!("wssp_device_{}", "A".repeat(43)),
            generation: String::new(),
        }
    }
    #[test]
    fn empty_state_source_transitions_and_logout_recovery() {
        let root = tempfile::tempdir().unwrap();
        let store = store(root.path());
        assert_eq!(store.snapshot().unwrap(), (Config::default(), None));
        store
            .update_config(|cfg| {
                cfg.host_token_env = Some("WSSP_TOKEN".into());
                Ok(())
            })
            .unwrap();
        store
            .update_config(|cfg| {
                cfg.server_url = Some("https://example.test/".into());
                Ok(())
            })
            .unwrap();
        let start = store.begin_login(None, "desk-01").unwrap();
        store.publish(&start.generation, credential()).unwrap();
        assert!(store.snapshot().unwrap().0.host_token_env.is_none());
        // Inspection follows the published device selection.
        let (inspection, diagnostics) = store.inspect_config().unwrap();
        assert!(diagnostics.is_empty());
        assert!(inspection.host_token_env.is_none());
        assert_eq!(
            inspection.server_url.as_deref(),
            Some("https://example.test/")
        );
        store
            .update_config(|cfg| {
                cfg.host_token_env = Some("WSSP_NEW_TOKEN".into());
                Ok(())
            })
            .unwrap();
        assert_eq!(
            store.snapshot().unwrap().0.host_token_env.as_deref(),
            Some("WSSP_NEW_TOKEN")
        );
        assert_eq!(
            store.inspect_config().unwrap().0.host_token_env.as_deref(),
            Some("WSSP_NEW_TOKEN")
        );
        store.advance(Operation::Logout, None, None).unwrap(); // simulate crash before either deletion
        drop(store);
        let reopened = AuthStore::at(
            root.path().join("data"),
            root.path().join("config/config.toml"),
            None,
        )
        .unwrap();
        assert!(reopened.snapshot().unwrap().1.is_none());
        assert!(reopened.snapshot().unwrap().0.host_token_env.is_none());
        assert!(!reopened.logout().unwrap().removed_device_credential);
    }
    #[test]
    fn publish_sweeps_abandoned_temp_and_stale_nonce_cannot_overwrite() {
        let root = tempfile::tempdir().unwrap();
        let store = store(root.path());
        store
            .update_config(|cfg| {
                cfg.server_url = Some("https://example.test/".into());
                Ok(())
            })
            .unwrap();
        let old = store.begin_login(None, "desk-01").unwrap();
        let current = store.begin_login(None, "desk-01").unwrap();
        let abandoned = store.dir.join(format!(
            "{STAGING_PREFIX}{:0>32}{STAGING_SUFFIX}",
            "deadbeef"
        ));
        std::fs::write(&abandoned, credential().secret).unwrap();
        store.publish(&current.generation, credential()).unwrap();
        assert!(!abandoned.exists());
        assert!(store.publish(&old.generation, credential()).is_err());
        assert_eq!(
            store.credential().unwrap().unwrap().generation,
            current.generation
        );
    }

    #[test]
    fn durable_file_names_are_never_sweepable_staging_names() {
        for name in [
            "auth.lock",
            "auth-intent.json",
            "device-auth.json",
            "config.toml",
            CONFIG_GENERATION_FILE,
            ".wssp-auth-config-gen",
            ".wssp-auth-leftover.tmp",
        ] {
            assert!(
                !is_sweepable_staging_name(name),
                "{name} must not match the staging sweep parser"
            );
        }
        assert!(is_sweepable_staging_name(
            ".wssp-staging-0123456789abcdef0123456789abcdef.tmp"
        ));
        assert!(is_sweepable_staging_name(
            ".wssp-tombstone-fedcba9876543210fedcba9876543210"
        ));
    }

    /// E-16: under a permissive umask (002, Ubuntu's default) every
    /// directory the daemon creates for credentials, config and the relay
    /// journal is owner-only 0700, ancestors included, and every file is
    /// 0600. The created trees are walked whole, so a new state file that
    /// skips the private boundary fails here. A pre-existing root keeps its
    /// mode. The umask is process-wide, so the check runs in a child test
    /// process started under `umask 002`.
    #[cfg(unix)]
    #[test]
    fn daemon_state_created_under_umask_002_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        const CHILD: &str = "WSSP_E16_UMASK_CHILD_ROOT";
        if let Some(root) = std::env::var_os(CHILD) {
            let root = PathBuf::from(root);
            let store = store(&root);
            store
                .update_config(|cfg| {
                    cfg.server_url = Some("https://example.test/".into());
                    Ok(())
                })
                .unwrap();
            let start = store.begin_login(None, "desk-01").unwrap();
            store.publish(&start.generation, credential()).unwrap();
            let binding = crate::sandbox_relay::journal::TransportBindingV11 {
                server: "wss://example.test".into(),
                host_owner_id: "owner-1".into(),
                host_id: "host-1".into(),
            };
            let journal = crate::sandbox_relay::journal::HostJournal::open(
                root.join("data/relay").join("a".repeat(64)),
                &binding,
            )
            .unwrap();
            let mut seen = 0;
            let mut stack = vec![root.join("data"), root.join("config")];
            while let Some(path) = stack.pop() {
                let meta = std::fs::symlink_metadata(&path).unwrap();
                let mode = meta.permissions().mode() & 0o7777;
                if meta.is_dir() {
                    assert_eq!(mode, 0o700, "directory {}", path.display());
                    for entry in std::fs::read_dir(&path).unwrap() {
                        stack.push(entry.unwrap().path());
                    }
                } else {
                    assert_eq!(mode, 0o600, "file {}", path.display());
                }
                seen += 1;
            }
            drop(journal);
            assert!(seen >= 8, "walked {seen} entries");
            assert_eq!(
                std::fs::metadata(&root).unwrap().permissions().mode() & 0o7777,
                0o755
            );
            return;
        }
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let output = std::process::Command::new("/bin/sh")
            .args(["-c", "umask 002 && exec \"$@\"", "sh"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "state::tests::daemon_state_created_under_umask_002_is_owner_only",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, root.path())
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "child failed: {:?}\nstdout:\n{stdout}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
