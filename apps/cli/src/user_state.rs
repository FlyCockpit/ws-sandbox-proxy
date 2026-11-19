//! The user login of `wssp login`: a `/v1` SDK key (`wssp_sdk_…`) for the
//! person using this machine, separate from the host enrollment.
//!
//! Stored at `<data_dir>/user/login.json` (file 0600, directory 0700) under its
//! own `login.lock` and its own staging names (its sweep never touches host
//! staging files); `WSSP_USER_DIR` overrides the directory (never the host
//! data or config directory, and the default `<data_dir>/user` must be a real
//! directory, not a symlink; an existing override is used as it is, refused
//! when group or other writable, never chmodded). CI and scripts
//! may instead pass `WSSP_API_KEY` together with `WSSP_SERVER`; that pair wins
//! over the file. User commands never read `config.toml` or the host auth
//! store, and the host auth store never reads this directory.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::exit::{CodedError, ExitCode};

/// Override for the user login directory.
pub const USER_DIR_ENV: &str = "WSSP_USER_DIR";
/// CI credential: a `wssp_sdk_…` key. Requires [`SERVER_ENV`].
pub const API_KEY_ENV: &str = "WSSP_API_KEY";
/// CI credential: the control plane origin for [`API_KEY_ENV`].
pub const SERVER_ENV: &str = "WSSP_SERVER";
/// The login file inside the user directory.
pub const LOGIN_FILE: &str = "login.json";
const LOCK_FILE: &str = "login.lock";
/// Prefix of every `/v1` SDK key.
pub const SDK_KEY_PREFIX: &str = "wssp_sdk_";

/// Shown (exit 7) by every user command that runs without a login.
pub const NOT_LOGGED_IN_MESSAGE: &str = "not logged in; run `wssp login --server <url>`";

/// What `wssp login` saved. `secret` never leaves this file except as the
/// bearer of `/v1` requests to `origin`.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UserLogin {
    pub origin: String,
    pub key_id: String,
    pub name: String,
    pub secret: String,
    pub scopes: Vec<String>,
    pub pool_mode: String,
    pub pool_ids: Vec<String>,
    pub own_sandboxes_only: bool,
    pub expires_at: Option<String>,
    pub max_live_sandboxes: Option<u32>,
    pub user_email: String,
    pub created_at: String,
    /// The `--ca-file` given to `wssp login` (absolute), reused by later
    /// commands unless `WSSP_CA_FILE` overrides it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<PathBuf>,
}

impl std::fmt::Debug for UserLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserLogin")
            .field("origin", &self.origin)
            .field("key_id", &self.key_id)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl UserLogin {
    /// `write` when the key may change anything, else `read`.
    pub fn access(&self) -> &'static str {
        access_for(&self.scopes)
    }
}

/// `write` when any scope beyond reads is present.
pub fn access_for(scopes: &[String]) -> &'static str {
    if scopes.iter().any(|scope| !scope.ends_with(":read")) {
        "write"
    } else {
        "read"
    }
}

/// Where the credential of this invocation comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CredentialSource {
    /// `WSSP_API_KEY` + `WSSP_SERVER`.
    Env,
    /// The saved `wssp login`.
    File,
}

/// The credential a user command sends.
#[derive(Clone)]
pub struct UserCredential {
    pub origin: String,
    pub secret: String,
    pub source: CredentialSource,
    /// The saved login, when the credential came from the file.
    pub login: Option<UserLogin>,
    pub ca_file: Option<PathBuf>,
}

impl std::fmt::Debug for UserCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserCredential")
            .field("origin", &self.origin)
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

impl UserCredential {
    /// TLS trust: `WSSP_CA_FILE`, else the CA file saved by `wssp login`.
    pub fn trust(&self) -> Result<crate::tls::Trust> {
        let env = std::env::var_os("WSSP_CA_FILE").map(PathBuf::from);
        Ok(crate::tls::Trust::load(
            env.as_deref().or(self.ca_file.as_deref()),
        )?)
    }
}

/// The user login directory: `WSSP_USER_DIR`, else `<data_dir>/user`.
pub fn user_dir() -> Result<PathBuf> {
    Ok(resolve_user_dir()?.0)
}

/// The user login directory and, when `WSSP_USER_DIR` chose it, the path as
/// given. The resolved directory (the implicit default included) may not be,
/// contain or lie inside the host data or config directory, with one
/// exception: the default `<data_dir>/user` may lie inside them when it is
/// missing or a real directory (never a symlink) resolving to exactly
/// `<resolved data_dir>/user`. The user login and the host enrollment never
/// share a directory. The returned directory is the resolved path the check
/// validated; all IO uses it.
fn resolve_user_dir() -> Result<(PathBuf, Option<PathBuf>)> {
    let data = crate::paths::data_dir()?;
    let default = data.join("user");
    let given = std::env::var_os(USER_DIR_ENV)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from);
    let shown = given.clone().unwrap_or_else(|| default.clone());
    let chosen = resolved(&shown)?;
    let data_real = resolved(&data)?;
    let is_default = chosen == data_real.join("user")
        && match std::fs::symlink_metadata(&chosen) {
            Ok(meta) => meta.file_type().is_dir(),
            Err(error) => error.kind() == std::io::ErrorKind::NotFound,
        }
        && match std::fs::symlink_metadata(&default) {
            Ok(meta) => meta.file_type().is_dir(),
            Err(error) => error.kind() == std::io::ErrorKind::NotFound,
        };
    for (host, name) in [
        (data_real, "data"),
        (resolved(&crate::paths::config_dir()?)?, "config"),
    ] {
        // The default may lie inside a host directory, never be or hold one.
        let inside = chosen.starts_with(&host) && chosen != host;
        if (inside && !is_default) || host.starts_with(&chosen) {
            let what = if given.is_some() {
                format!("`{USER_DIR_ENV}` (`{}`)", shown.display())
            } else {
                format!("the user login directory `{}`", shown.display())
            };
            return Err(anyhow::anyhow!(
                "{what} overlaps the host {name} directory `{}`; choose a separate directory",
                host.display()
            ))
            .context(CodedError::new(ExitCode::Usage));
        }
    }
    // The implicit default is used only as a real directory (or missing)
    // at exactly `<resolved data_dir>/user`; a symlink anywhere else is
    // refused before anything is created, chmodded or locked there.
    if given.is_none() && !is_default {
        return Err(anyhow::anyhow!(
            "the user login directory `{}` must be a real directory, not a symlink or file; remove it or set `{USER_DIR_ENV}`",
            shown.display()
        ))
        .context(CodedError::new(ExitCode::Usage));
    }
    Ok((chosen, given))
}

/// Open `name` inside the user directory without following a symlink and
/// require a regular file (checked on the opened descriptor). `create`
/// creates it 0600 when missing; otherwise a missing file is `Ok(None)`.
fn open_regular_nofollow(dir: &Path, name: &str, create: bool) -> Result<Option<File>> {
    let path = dir.join(name);
    #[cfg(target_os = "linux")]
    let opened = {
        use rustix::fs::{Mode, OFlags};
        let mut flags = OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        flags |= if create {
            OFlags::RDWR | OFlags::CREATE
        } else {
            OFlags::RDONLY
        };
        match rustix::fs::open(&path, flags, Mode::from_raw_mode(0o600)) {
            Ok(fd) => File::from(fd),
            Err(rustix::io::Errno::NOENT) if !create => return Ok(None),
            Err(rustix::io::Errno::LOOP) => anyhow::bail!(
                "`{}` is a symlink; refused (it must be a regular file)",
                path.display()
            ),
            Err(error) => {
                return Err(std::io::Error::from(error))
                    .with_context(|| format!("opening `{}`", path.display()));
            }
        }
    };
    #[cfg(not(target_os = "linux"))]
    let opened = {
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => anyhow::bail!(
                "`{}` is a symlink; refused (it must be a regular file)",
                path.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && !create => {
                return Ok(None);
            }
            _ => {}
        }
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .write(create)
            .create(create)
            .truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options
            .open(&path)
            .with_context(|| format!("opening `{}`", path.display()))?
    };
    let meta = opened
        .metadata()
        .with_context(|| format!("inspecting `{}`", path.display()))?;
    anyhow::ensure!(
        meta.is_file(),
        "`{}` is not a regular file; refused",
        path.display()
    );
    // A hard link (e.g. to the host `auth.lock`) would share another file's
    // inode: the user store only ever uses files with exactly one link.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        anyhow::ensure!(
            meta.nlink() == 1,
            "`{}` has other hard links; refused",
            path.display()
        );
    }
    Ok(Some(opened))
}

/// `path` resolved with filesystem semantics, one component at a time: each
/// existing component is canonicalized (symlinks resolved) before a later
/// `..` applies to it, so `link/..` is the parent of the link's target, never
/// the directory holding the link. A missing component (and everything after
/// it) is appended as written; a dangling symlink is refused.
fn resolved(path: &Path) -> Result<PathBuf> {
    use std::path::Component;
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("reading the current directory")?
            .join(path)
    };
    let mut out = PathBuf::new();
    for part in absolute.components() {
        match part {
            Component::Prefix(_) | Component::RootDir => out.push(part.as_os_str()),
            Component::CurDir => {}
            // `out` is symlink-free: canonical, plus missing plain names.
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(name) => {
                let next = out.join(name);
                match std::fs::canonicalize(&next) {
                    Ok(real) => out = real,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        if std::fs::symlink_metadata(&next).is_ok() {
                            anyhow::bail!(
                                "`{}` is a symlink to a missing path; choose a real directory",
                                next.display()
                            );
                        }
                        out = next;
                    }
                    Err(error) => {
                        return Err(error)
                            .with_context(|| format!("resolving `{}`", next.display()));
                    }
                }
            }
        }
    }
    Ok(out)
}

/// Prepare a `WSSP_USER_DIR` override: create it owner-only when missing;
/// an existing one is used as it is (never chmodded) unless it is a symlink,
/// not a directory, or writable by group or others.
fn prepare_override_dir(given: &Path, dir: &Path) -> Result<()> {
    if std::fs::symlink_metadata(given).is_ok_and(|meta| meta.file_type().is_symlink()) {
        anyhow::bail!(
            "`{USER_DIR_ENV}` (`{}`) must be a directory, not a symlink or file",
            given.display()
        );
    }
    match std::fs::symlink_metadata(dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            crate::state::private_dir(dir).context("preparing the user login directory")
        }
        Err(error) => Err(error).context("reading the user login directory metadata"),
        Ok(meta) => {
            anyhow::ensure!(
                meta.file_type().is_dir(),
                "`{USER_DIR_ENV}` (`{}`) must be a directory, not a symlink or file",
                dir.display()
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = meta.permissions().mode() & 0o777;
                if mode & 0o022 != 0 {
                    return Err(anyhow::anyhow!(
                        "`{USER_DIR_ENV}` (`{}`) is writable by group or others (mode {mode:o}); run `chmod go-w` on it or choose another directory",
                        dir.display()
                    ))
                    .context(CodedError::new(ExitCode::Usage));
                }
            }
            Ok(())
        }
    }
}

/// Validate a `/v1` SDK key's shape without echoing it.
pub fn validate_sdk_key(secret: &str) -> Result<()> {
    crate::auth::validate_product_secret(secret, SDK_KEY_PREFIX)
        .context("expected a `wssp_sdk_` key")
}

/// The env credential, if `WSSP_API_KEY` or `WSSP_SERVER` is set. Both are
/// required together.
fn env_credential() -> Result<Option<UserCredential>> {
    let key = std::env::var(API_KEY_ENV).ok().filter(|v| !v.is_empty());
    let server = std::env::var(SERVER_ENV).ok().filter(|v| !v.is_empty());
    match (key, server) {
        (None, None) => Ok(None),
        (Some(secret), Some(server)) => {
            validate_sdk_key(&secret)
                .with_context(|| format!("`{API_KEY_ENV}` is not a valid SDK key"))
                .context(CodedError::new(ExitCode::Usage))?;
            let origin = crate::auth::canonical_control_plane_origin(&server)
                .with_context(|| format!("`{SERVER_ENV}` is not a valid server URL"))
                .context(CodedError::new(ExitCode::Usage))?;
            Ok(Some(UserCredential {
                origin,
                secret,
                source: CredentialSource::Env,
                login: None,
                ca_file: None,
            }))
        }
        _ => Err(anyhow::anyhow!(
            "`{API_KEY_ENV}` and `{SERVER_ENV}` must be set together"
        ))
        .context(CodedError::new(ExitCode::Usage)),
    }
}

/// The credential every user command uses: the env pair, else the saved
/// login; exit 7 before any network call when there is none.
pub fn require_credential() -> Result<UserCredential> {
    if let Some(credential) = env_credential()? {
        return Ok(credential);
    }
    // No login file: fail before creating any directory or taking a lock.
    let dir = user_dir()?;
    match std::fs::symlink_metadata(dir.join(LOGIN_FILE)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(anyhow::Error::msg(NOT_LOGGED_IN_MESSAGE))
                .context(CodedError::new(ExitCode::NotLoggedIn));
        }
        _ => {}
    }
    let login = UserStore::open()?.read()?;
    match login {
        Some(login) => Ok(UserCredential {
            origin: login.origin.clone(),
            secret: login.secret.clone(),
            source: CredentialSource::File,
            ca_file: login.ca_file.clone(),
            login: Some(login),
        }),
        None => Err(anyhow::Error::msg(NOT_LOGGED_IN_MESSAGE))
            .context(CodedError::new(ExitCode::NotLoggedIn)),
    }
}

/// Whether an env credential is configured (both or either variable set).
pub fn env_credential_present() -> bool {
    [API_KEY_ENV, SERVER_ENV]
        .iter()
        .any(|name| std::env::var_os(name).is_some_and(|v| !v.is_empty()))
}

/// The locked user login directory. Holding it serializes every read-modify-
/// write of `login.json` across processes.
pub struct UserStore {
    _lock: File,
    dir: PathBuf,
}

impl UserStore {
    pub fn open() -> Result<Self> {
        let (dir, given) = resolve_user_dir()?;
        if let Some(given) = given {
            prepare_override_dir(&given, &dir)?;
        } else {
            crate::state::private_dir(&dir).context("preparing the user login directory")?;
        }
        Self::locked(dir)
    }

    #[cfg(test)]
    pub(crate) fn at(dir: PathBuf) -> Result<Self> {
        crate::state::private_dir(&dir).context("preparing the user login directory")?;
        Self::locked(dir)
    }

    fn locked(dir: PathBuf) -> Result<Self> {
        let lock = open_regular_nofollow(&dir, LOCK_FILE, true)
            .context("opening the user login lock")?
            .context("the user login lock is missing")?;
        crate::state::wait_for_lock(&lock, Some(Instant::now() + Duration::from_secs(15)))
            .context("waiting for the user login lock")?;
        crate::state::sweep_dir_with(&dir, crate::state::USER_STAGING)?;
        Ok(Self { _lock: lock, dir })
    }

    pub fn path(&self) -> PathBuf {
        self.dir.join(LOGIN_FILE)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn read(&self) -> Result<Option<UserLogin>> {
        use std::io::Read;
        let path = self.path();
        let Some(mut file) = open_regular_nofollow(&self.dir, LOGIN_FILE, false)
            .context("reading the user login")?
        else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .with_context(|| format!("reading `{}`", path.display()))?;
        let login: UserLogin = serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing `{}`", path.display()))?;
        validate_sdk_key(&login.secret).context("the saved user login is corrupt")?;
        Ok(Some(login))
    }

    pub fn write(&self, login: &UserLogin) -> Result<()> {
        validate_sdk_key(&login.secret)?;
        // `open` prepared the directory: one the CLI created is 0700, a
        // validated `WSSP_USER_DIR` override keeps its own mode.
        crate::state::write_json_in_prepared_dir_with(
            &self.path(),
            login,
            crate::state::USER_STAGING,
        )
    }

    /// Remove the login; returns whether one existed.
    pub fn remove(&self) -> Result<bool> {
        let existed = std::fs::symlink_metadata(self.path()).is_ok();
        crate::state::remove_durable_with(&self.path(), crate::state::USER_STAGING)?;
        Ok(existed)
    }
}

/// The current UTC time as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn utc_now_iso() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    iso_from_unix(secs)
}

fn iso_from_unix(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn formats_utc() {
        assert_eq!(iso_from_unix(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso_from_unix(1_794_005_701), "2026-11-06T22:55:01Z");
        assert_eq!(iso_from_unix(951_782_400), "2000-02-29T00:00:00Z");
    }

    use super::*;

    fn login() -> UserLogin {
        UserLogin {
            origin: "https://example.test/".into(),
            key_id: "key-1".into(),
            name: "wssp login".into(),
            secret: format!("wssp_sdk_{}", "a".repeat(43)),
            scopes: vec!["sandboxes:read".into()],
            pool_mode: "ALL_USABLE".into(),
            pool_ids: vec![],
            own_sandboxes_only: false,
            expires_at: None,
            max_live_sandboxes: None,
            user_email: "person@example.test".into(),
            created_at: "2026-11-18T00:00:00Z".into(),
            ca_file: None,
        }
    }

    #[test]
    fn writes_private_file_and_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("user");
        let store = UserStore::at(dir.clone()).unwrap();
        assert!(store.read().unwrap().is_none());
        store.write(&login()).unwrap();
        assert_eq!(store.read().unwrap().unwrap().key_id, "key-1");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&dir), 0o700);
            assert_eq!(mode(&dir.join(LOGIN_FILE)), 0o600);
        }
        assert!(store.remove().unwrap());
        assert!(!store.remove().unwrap());
    }

    #[test]
    fn refuses_a_secret_of_another_kind() {
        let tmp = tempfile::tempdir().unwrap();
        let store = UserStore::at(tmp.path().join("user")).unwrap();
        let mut wrong = login();
        wrong.secret = format!("wssp_host_{}", "a".repeat(43));
        assert!(store.write(&wrong).is_err());
        assert!(!store.path().exists());
    }

    #[test]
    fn access_is_write_with_any_non_read_scope() {
        assert_eq!(access_for(&["sandboxes:read".into()]), "read");
        assert_eq!(
            access_for(&["sandboxes:read".into(), "sandboxes:create".into()]),
            "write"
        );
    }
}
