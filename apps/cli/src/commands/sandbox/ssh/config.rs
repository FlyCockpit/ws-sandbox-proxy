//! The local SSH identity of `wssp ssh` and the generated ssh config.
//!
//! OpenSSH checks a host key even over a ProxyCommand pipe. This install
//! keeps one ed25519 host key (`<user dir>/ssh/host_key`, 0600, made on
//! first use) and a wssp-managed known_hosts (`<user dir>/ssh/known_hosts`)
//! holding exactly its public key under the alias `wssp`, which the config
//! selects with `HostKeyAlias wssp`. The key authenticates nothing remote
//! and grants nothing (the wssp login over TLS authorizes every channel);
//! `wssp logout` keeps both files, `wssp ssh-config --rotate-host-key`
//! replaces them.
//!
//! `wssp ssh-config --install` writes `~/.ssh/config.d/wssp` (only that file,
//! and only when it is missing or wssp's own) and, after confirmation, puts
//! one `Include config.d/wssp` line at the top of `~/.ssh/config` unless
//! its first directive already is that Include. `~` is the home directory
//! of the account (as OpenSSH reads it), not `$HOME`. Installers are
//! serialized by a lock file in the wssp user directory; both files are
//! re-checked (identity, owner, mode and bytes) after the question and once
//! more right before an atomic exchange (`RENAME_EXCHANGE`). wssp never
//! deletes a file of the user's it displaced: the planned one is kept as a
//! private backup (`~/.ssh/config.wssp-backup-<utc>`, outside `config.d/`),
//! so even a program that opened it earlier and saves late loses nothing;
//! a file changed meanwhile goes back (or is kept as a conflict file).
//! Nothing else of the user's ssh config is changed.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use russh::keys::ssh_key::LineEnding;
use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::{HashAlg, PrivateKey};

use crate::exit::{CodedError, ExitCode};

/// The known_hosts alias (`HostKeyAlias`).
pub const HOST_KEY_ALIAS: &str = "wssp";
/// The first line of every file wssp manages in `~/.ssh`.
pub const MANAGED_HEADER: &str = "# Managed by wssp. Regenerate with `wssp ssh-config --install`.";
/// The line `--install` adds to `~/.ssh/config`.
pub const INCLUDE_LINE: &str = "Include config.d/wssp";
/// The `Host` patterns of the block. The ProxyCommand passes the host name
/// as `'%n'`; inside single quotes only `'` (and, for fish, `\`) means
/// anything to a shell, and the negated patterns keep names holding either
/// out of the block (OpenSSH 9.6 and later refuse such names anyway).
pub const HOST_PATTERNS: &str = "*.wssp \"!*'*\" \"!*\\*\"";
const SSH_DIR: &str = "ssh";
const HOST_KEY_FILE: &str = "host_key";
const KNOWN_HOSTS_FILE: &str = "known_hosts";
const LOCK_FILE: &str = "host_key.lock";
/// Serializes `wssp ssh-config --install` runs (in `<user dir>/ssh`).
const INSTALL_LOCK_FILE: &str = "install.lock";

/// The host key and where its files live.
pub struct HostKey {
    pub key: PrivateKey,
    /// `ssh-ed25519 AAAA…`.
    pub public: String,
    /// `SHA256:…`.
    pub fingerprint: String,
    pub key_path: PathBuf,
    pub known_hosts: PathBuf,
    /// The key was made by this call (first use or rotation).
    pub created: bool,
}

fn usage(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::msg(message.into()).context(CodedError::new(ExitCode::Usage))
}

fn failure(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::msg(message.into()).context(CodedError::new(ExitCode::Failure))
}

/// The private `<user dir>/ssh` directory (created 0700).
fn ssh_dir() -> Result<PathBuf> {
    // Opening the store prepares (and validates) the user directory.
    let store = crate::user_state::UserStore::open()?;
    let dir = store.dir().join(SSH_DIR);
    drop(store);
    crate::state::private_dir(&dir).context("preparing the ssh key directory")?;
    Ok(dir)
}

/// A regular file's bytes; `None` when missing. Symlinks are refused.
fn read_regular(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("reading `{}`", path.display())),
        Ok(meta) if !meta.file_type().is_file() => {
            anyhow::bail!("`{}` is not a regular file; refused", path.display())
        }
        Ok(_) => {}
    }
    std::fs::read(path)
        .map(Some)
        .with_context(|| format!("reading `{}`", path.display()))
}

/// Replace `path` atomically with `bytes` (a temporary file in the same
/// directory, flushed, then renamed), mode `mode`.
fn publish(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let dir = path.parent().context("the path has no directory")?;
    let mut temp = tempfile::Builder::new()
        .prefix(".wssp-ssh-")
        .tempfile_in(dir)
        .with_context(|| format!("writing into `{}`", dir.display()))?;
    temp.as_file()
        .set_permissions(std::fs::Permissions::from_mode(mode))
        .context("setting the file mode")?;
    temp.write_all(bytes)
        .with_context(|| format!("writing `{}`", path.display()))?;
    temp.as_file()
        .sync_all()
        .with_context(|| format!("writing `{}`", path.display()))?;
    temp.persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("writing `{}`", path.display()))?;
    sync_dir(dir)
}

fn sync_dir(dir: &Path) -> Result<()> {
    std::fs::File::open(dir)
        .and_then(|dir| dir.sync_all())
        .with_context(|| format!("syncing `{}`", dir.display()))
}

fn generate() -> Result<PrivateKey> {
    use ring::rand::SecureRandom;
    let mut seed = zeroize::Zeroizing::new([0_u8; 32]);
    ring::rand::SystemRandom::new()
        .fill(seed.as_mut())
        .map_err(|_| anyhow::anyhow!("the system random source failed"))?;
    let mut key = PrivateKey::from(Ed25519Keypair::from_seed(&seed));
    key.set_comment("wssp ssh endpoint");
    Ok(key)
}

/// The known_hosts content for `public`.
pub fn known_hosts_line(public: &str) -> String {
    format!("{HOST_KEY_ALIAS} {public}\n")
}

/// The host key, made on first use (or replaced with `rotate`), with the
/// known_hosts file made to match it. Serialized across processes.
pub fn host_key(rotate: bool) -> Result<HostKey> {
    let dir = ssh_dir()?;
    host_key_in(&dir, rotate)
}

/// [`host_key`] in an explicit directory (tests).
pub fn host_key_in(dir: &Path, rotate: bool) -> Result<HostKey> {
    let lock = crate::state::open_named_lock_file(dir, LOCK_FILE)?;
    crate::state::wait_for_lock(&lock, Some(Instant::now() + Duration::from_secs(15)))
        .context("waiting for the ssh key lock")?;
    let key_path = dir.join(HOST_KEY_FILE);
    let known_hosts = dir.join(KNOWN_HOSTS_FILE);
    let existing = if rotate {
        None
    } else {
        read_regular(&key_path)?
    };
    let created = existing.is_none();
    let key = match existing {
        Some(bytes) => {
            let key = PrivateKey::from_openssh(&bytes).with_context(|| {
                format!(
                    "the ssh host key `{}` is unreadable; replace it with `wssp ssh-config --rotate-host-key`",
                    key_path.display()
                )
            })?;
            anyhow::ensure!(
                key.algorithm() == russh::keys::Algorithm::Ed25519,
                "the ssh host key `{}` is not ed25519; replace it with `wssp ssh-config --rotate-host-key`",
                key_path.display()
            );
            key
        }
        None => {
            let key = generate()?;
            let pem = key
                .to_openssh(LineEnding::LF)
                .context("encoding the ssh host key")?;
            publish(&key_path, pem.as_bytes(), 0o600)?;
            key
        }
    };
    let mut public = key.public_key().clone();
    public.set_comment("");
    let public = public.to_openssh().context("encoding the ssh host key")?;
    let line = known_hosts_line(&public);
    if read_regular(&known_hosts)?.as_deref() != Some(line.as_bytes()) {
        publish(&known_hosts, line.as_bytes(), 0o600)?;
    }
    drop(lock);
    Ok(HostKey {
        fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
        key,
        public,
        key_path,
        known_hosts,
        created,
    })
}

/// The hint `wssp ssh --stdio` prints when it had to make the host key
/// itself. `wssp ssh-config` (and `wssp ssh`) make the key first, so a
/// ProxyCommand that finds none runs with another wssp user directory than
/// the one the ssh config's `UserKnownHostsFile` names.
pub fn new_key_hint(key: &HostKey) -> String {
    format!(
        "made a new ssh host key at `{}`; if ssh then reports \"Host key verification failed\", this run uses another wssp user directory (`WSSP_USER_DIR` or the XDG data directory) than the ssh config was generated with: run `wssp ssh-config --install` again in this environment",
        key.key_path.display()
    )
}

/// `path` in double quotes for ssh_config (and, in `ProxyCommand`, for the
/// shell ssh runs it with). Paths ssh would expand or the quotes cannot
/// carry are refused.
pub fn quoted(path: &Path) -> Result<String> {
    let text = path
        .to_str()
        .with_context(|| format!("`{}` is not valid UTF-8", path.display()))?;
    let plain = path.is_absolute()
        && !text
            .chars()
            .any(|c| c.is_control() || matches!(c, '"' | '\\' | '%' | '$' | '`' | '!'));
    if !plain {
        return Err(usage(format!(
            "`{}` cannot be written into an ssh config (it needs an absolute path without quotes, `\\`, `%`, `$`, backticks, `!` or control characters)",
            crate::output::remote_message(text)
        )));
    }
    Ok(format!("\"{text}\""))
}

/// The `ProxyCommand` value: this binary in `--stdio` mode for `'%n'`.
/// ssh pastes the host name into the string and hands it to the user's
/// shell, so the name stays inside single quotes (the CVE-2023-51385
/// pattern); `--stdio` then accepts only `<name-or-id>[.wssp]` with the
/// sandbox id charset before any network.
pub fn proxy_command(exe: &Path) -> Result<String> {
    Ok(format!("{} ssh --stdio '%n'", quoted(exe)?))
}

/// The options every `*.wssp` connection uses, as `(keyword, value)`.
pub fn options(exe: &Path, known_hosts: &Path) -> Result<Vec<(&'static str, String)>> {
    Ok(vec![
        ("ProxyCommand", proxy_command(exe)?),
        ("User", "wssp".to_owned()),
        ("HostKeyAlias", HOST_KEY_ALIAS.to_owned()),
        ("UserKnownHostsFile", quoted(known_hosts)?),
        ("GlobalKnownHostsFile", "/dev/null".to_owned()),
        ("StrictHostKeyChecking", "yes".to_owned()),
        ("HostKeyAlgorithms", "ssh-ed25519".to_owned()),
        ("CanonicalizeHostname", "no".to_owned()),
        ("IdentitiesOnly", "yes".to_owned()),
        ("IdentityFile", "none".to_owned()),
        ("ForwardAgent", "no".to_owned()),
        ("ForwardX11", "no".to_owned()),
        ("ServerAliveInterval", "30".to_owned()),
    ])
}

/// The `~/.ssh/config.d/wssp` block.
pub fn config_block(exe: &Path, known_hosts: &Path) -> Result<String> {
    let mut block = format!("{MANAGED_HEADER}\nHost {HOST_PATTERNS}\n");
    for (keyword, value) in options(exe, known_hosts)? {
        block.push_str(&format!("  {keyword} {value}\n"));
    }
    Ok(block)
}

/// The path the config names for this binary. A stable spelling is
/// preferred over the resolved file, so an upgrade behind a symlink (a
/// version manager, Nix, alternatives) keeps working: the invoked path when
/// it is absolute, else the `wssp` that `PATH` finds, each only when it
/// still resolves to the running binary. Otherwise the resolved path of the
/// running binary. Moving the binary needs `wssp ssh-config --install` again.
pub fn current_exe() -> Result<PathBuf> {
    let running = std::env::current_exe().context("finding the wssp binary")?;
    if running
        .to_str()
        .is_some_and(|text| text.ends_with(" (deleted)"))
    {
        return Err(failure(
            "the running wssp binary was replaced or removed; run `wssp ssh-config` with the installed one",
        ));
    }
    let canonical = std::fs::canonicalize(&running).unwrap_or(running);
    let invoked = std::env::args_os().next().map(PathBuf::from);
    let candidate = match invoked {
        Some(path) if path.is_absolute() => Some(path),
        Some(path) if path.components().count() == 1 && !path.as_os_str().is_empty() => {
            path.to_str().and_then(super::find_program)
        }
        _ => None,
    };
    Ok(candidate
        .filter(|path| std::fs::canonicalize(path).is_ok_and(|resolved| resolved == canonical))
        .unwrap_or(canonical))
}

/// What `--install` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    pub config_path: PathBuf,
    pub ssh_config: PathBuf,
    /// The `Include` line was added now (else it was there already).
    pub include_added: bool,
    /// The previous files this run replaced, each kept as a private backup
    /// (wssp never deletes them).
    pub backups: Vec<Backup>,
}

/// A replaced file and where wssp kept its previous version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backup {
    pub file: PathBuf,
    pub backup: PathBuf,
}

/// One ssh_config line as `(keyword, arguments)`; `None` for blank and
/// comment lines. Follows OpenSSH: `Keyword value`, `Keyword=value`,
/// double or single quotes, `\` before a quote, `\` or space, and a `#`
/// that starts an argument ends the line.
fn directive(line: &str) -> Option<(String, Vec<String>)> {
    let line = line.trim_start();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let end = line
        .find(|c: char| c.is_whitespace() || c == '=')
        .unwrap_or(line.len());
    let keyword = line[..end].to_owned();
    let mut rest = line[end..].trim_start();
    if let Some(after) = rest.strip_prefix('=') {
        rest = after.trim_start();
    }
    let mut args = Vec::new();
    let mut chars = rest.chars().peekable();
    loop {
        while chars.next_if(|c| c.is_whitespace()).is_some() {}
        match chars.peek() {
            None | Some('#') => break,
            Some(_) => {}
        }
        let mut arg = String::new();
        let mut quote = None;
        while let Some(c) = chars.next() {
            match (quote, c) {
                (_, '\\') if matches!(chars.peek(), Some('\'' | '"' | '\\')) => {
                    arg.extend(chars.next());
                }
                (None, '\\') if matches!(chars.peek(), Some(' ')) => {
                    arg.extend(chars.next());
                }
                (None, '"' | '\'') => quote = Some(c),
                (Some(open), c) if c == open => quote = None,
                (None, c) if c.is_whitespace() => break,
                (_, c) => arg.push(c),
            }
        }
        args.push(arg);
    }
    Some((keyword, args))
}

/// Whether an `Include` argument names the managed file: `config.d/wssp`
/// (relative to `~/.ssh`), `~/.ssh/config.d/wssp` or the absolute path.
/// A glob is not recognized (a second, explicit Include is harmless).
fn names_managed(arg: &str, ssh: &Path, home: &Path) -> bool {
    let target = ssh.join("config.d").join("wssp");
    let path = if let Some(rest) = arg.strip_prefix("~/") {
        home.join(rest)
    } else if Path::new(arg).is_absolute() {
        PathBuf::from(arg)
    } else {
        ssh.join(arg)
    };
    path == target
}

/// Whether `~/.ssh/config` already reads the managed file before anything
/// else, conservatively: its first directive (comments and blank lines
/// aside) is an `Include` whose first argument is the managed file.
/// OpenSSH keeps the first value it reads for each option, so anything
/// earlier (an option, a `Host`/`Match` scope, even `Host *`, or another
/// `Include`, whose file may set options) could win over the block; then
/// `--install` adds its line at the very top.
fn effective_include(text: &str, ssh: &Path, home: &Path) -> bool {
    text.lines()
        .find_map(directive)
        .is_some_and(|(keyword, args)| {
            keyword.eq_ignore_ascii_case("include")
                && args
                    .first()
                    .is_some_and(|arg| names_managed(arg, ssh, home))
        })
}

/// Create `dir` 0700 when missing; an existing directory keeps its mode. A
/// symlink is not followed.
fn ensure_dir(dir: &Path) -> Result<()> {
    match std::fs::symlink_metadata(dir) {
        Ok(meta) if meta.is_dir() => Ok(()),
        Ok(meta) if meta.file_type().is_symlink() => Err(usage(format!(
            "`{}` is a symlink, which wssp does not write through; save `wssp ssh-config` as `config.d/wssp` there and add `{INCLUDE_LINE}` at the top of `config` yourself",
            dir.display()
        ))),
        Ok(_) => anyhow::bail!("`{}` is not a directory; refused", dir.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(dir)
                .with_context(|| format!("creating `{}`", dir.display()))
        }
        Err(error) => Err(error).with_context(|| format!("reading `{}`", dir.display())),
    }
}

/// A file as `--install` planned against it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    dev: u64,
    ino: u64,
    links: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    bytes: Vec<u8>,
}

/// `path` as it is now; `None` when missing. Only a regular file is read.
fn observe(path: &Path) -> Result<Option<Seen>> {
    use std::os::unix::fs::MetadataExt;
    let before = match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("reading `{}`", path.display())),
        Ok(meta) => meta,
    };
    if !before.file_type().is_file() {
        anyhow::bail!("`{}` is not a regular file; refused", path.display());
    }
    let bytes = std::fs::read(path).with_context(|| format!("reading `{}`", path.display()))?;
    let after =
        std::fs::symlink_metadata(path).with_context(|| format!("reading `{}`", path.display()))?;
    anyhow::ensure!(
        (after.dev(), after.ino(), after.len()) == (before.dev(), before.ino(), bytes.len() as u64),
        "`{}` changed while it was read; run this again",
        path.display()
    );
    Ok(Some(Seen {
        dev: before.dev(),
        ino: before.ino(),
        links: before.nlink(),
        uid: before.uid(),
        gid: before.gid(),
        mode: before.mode() & 0o777,
        bytes,
    }))
}

fn changed(path: &Path) -> anyhow::Error {
    failure(format!(
        "`{}` changed while wssp was waiting (an editor or another program wrote it); wssp left it as it is now: run `wssp ssh-config --install` again",
        path.display()
    ))
}

/// Refuse unless `path` is still exactly what was planned.
fn unchanged(path: &Path, planned: Option<&Seen>) -> Result<()> {
    match observe(path) {
        Ok(now) if now.as_ref() == planned => Ok(()),
        _ => Err(changed(path)),
    }
}

/// Swap the directory entries `a` and `b` atomically (`RENAME_EXCHANGE`).
fn exchange(a: &Path, b: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    if let Some(error) = tests::exchange_override(a, b) {
        return Err(error);
    }
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        a,
        rustix::fs::CWD,
        b,
        rustix::fs::RenameFlags::EXCHANGE,
    )
    .map_err(std::io::Error::from)
}

/// The filesystem (or kernel) has no `RENAME_EXCHANGE`.
fn exchange_unsupported(error: &std::io::Error) -> bool {
    matches!(
        rustix::io::Errno::from_io_error(error),
        Some(rustix::io::Errno::INVAL | rustix::io::Errno::NOSYS | rustix::io::Errno::OPNOTSUPP)
    )
}

/// Keep the displaced file at `temp` for the user: mode 0600 (a regular
/// file only; its owner stays) and renamed, never over an existing file,
/// to `<base>-<utc>` (a backup or a conflict file). The inode itself is
/// kept, never copied, so a program that still holds it open and saves
/// late writes into the kept file. Returns where it is now (still `temp`
/// when the rename failed: the file is kept either way).
fn keep_aside(temp: &Path, base: &Path) -> PathBuf {
    use rustix::fs::{FileType, Mode, OFlags};
    if let Ok(fd) = rustix::fs::open(
        temp,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) && rustix::fs::fstat(&fd)
        .is_ok_and(|stat| FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile)
    {
        let _ = rustix::fs::fchmod(&fd, Mode::from_raw_mode(0o600));
    }
    let stamp = crate::user_state::utc_now_iso().replace(['-', ':'], "");
    for n in 0..100 {
        let mut name = base.as_os_str().to_owned();
        name.push(format!("-{stamp}"));
        if n > 0 {
            name.push(format!("-{n}"));
        }
        let target = PathBuf::from(name);
        match rustix::fs::renameat_with(
            rustix::fs::CWD,
            temp,
            rustix::fs::CWD,
            &target,
            rustix::fs::RenameFlags::NOREPLACE,
        ) {
            Ok(()) => return target,
            Err(rustix::io::Errno::EXIST) => {}
            Err(_) => break,
        }
    }
    temp.to_owned()
}

/// Where `publish_over` keeps what it displaced, outside every directory an
/// `Include` glob of wssp's reads (`config.d/`).
struct Aside<'a> {
    /// The previous file, after a publication: `<backup>-<utc>`.
    backup: &'a Path,
    /// A second edit that raced the exchange back: `<conflict>-<utc>`.
    conflict: &'a Path,
    /// What the user does by hand without `RENAME_EXCHANGE`.
    manual: &'a str,
}

/// Publish `bytes` at `path` only over what was planned: a temporary file
/// in the same directory with the planned mode and owner, flushed, a last
/// check, then (where nothing was) a no-clobber link, or (over an existing
/// file) an atomic exchange. wssp never unlinks a file of the user's it
/// displaced: when the displaced file is exactly the planned one it is
/// kept as the backup `<backup>-<utc>` (0600; returned), so a program that
/// opened it before and saves through its descriptor afterwards writes
/// into the backup; otherwise (an edit landed after the last check) it is
/// exchanged back into place, and whatever that second exchange displaces,
/// unless it is wssp's own new file untouched, is kept as
/// `<conflict>-<utc>`. Without `RENAME_EXCHANGE` (some filesystems) nothing
/// is replaced: `manual` tells the user what to do instead.
fn publish_over(
    path: &Path,
    bytes: &[u8],
    planned: Option<&Seen>,
    aside: &Aside<'_>,
) -> Result<Option<PathBuf>> {
    let Aside {
        backup,
        conflict,
        manual,
    } = *aside;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let dir = path.parent().context("the path has no directory")?;
    let mut temp = tempfile::Builder::new()
        .prefix(".wssp-ssh-")
        .tempfile_in(dir)
        .with_context(|| format!("writing into `{}`", dir.display()))?;
    if let Some(seen) = planned {
        let meta = temp.as_file().metadata().context("reading the new file")?;
        if (meta.uid(), meta.gid()) != (seen.uid, seen.gid) {
            std::os::unix::fs::fchown(temp.as_file(), Some(seen.uid), Some(seen.gid))
                .with_context(|| format!("keeping the owner of `{}`", path.display()))?;
        }
    }
    let mode = planned.map_or(0o600, |seen| seen.mode);
    temp.as_file()
        .set_permissions(std::fs::Permissions::from_mode(mode))
        .context("setting the file mode")?;
    temp.write_all(bytes)
        .with_context(|| format!("writing `{}`", path.display()))?;
    temp.as_file()
        .sync_all()
        .with_context(|| format!("writing `{}`", path.display()))?;
    unchanged(path, planned)?;
    #[cfg(test)]
    tests::before_rename(path);
    let Some(planned) = planned else {
        // Nothing was there: linked without replacing a file that appears
        // meanwhile.
        return match temp.persist_noclobber(path) {
            Ok(_) => sync_dir(dir).map(|()| None),
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(changed(path))
            }
            Err(error) => Err(error.error).with_context(|| format!("writing `{}`", path.display())),
        };
    };
    let ours = temp.as_file().metadata().context("reading the new file")?;
    let ours = (ours.dev(), ours.ino());
    // From here the temporary path is removed by hand: after the exchange
    // it names the user's file.
    let (file, temp) = temp
        .keep()
        .map_err(|error| error.error)
        .context("keeping the new file")?;
    drop(file);
    if let Err(error) = exchange(&temp, path) {
        let _ = std::fs::remove_file(&temp);
        if exchange_unsupported(&error) {
            return Err(usage(format!(
                "the filesystem of `{}` cannot swap two files atomically (no RENAME_EXCHANGE), so wssp left it unchanged rather than risk an edit made at the same moment; {manual}",
                path.display()
            )));
        }
        if error.kind() == std::io::ErrorKind::NotFound {
            return Err(changed(path));
        }
        return Err(error).with_context(|| format!("writing `{}`", path.display()));
    }
    #[cfg(test)]
    tests::after_exchange(path);
    // `temp` now holds what `path` held at the exchange.
    if observe(&temp).ok().flatten().as_ref() == Some(planned) {
        let kept = keep_aside(&temp, backup);
        sync_dir(dir)?;
        if kept.parent() != Some(dir) {
            let _ = kept.parent().map(sync_dir);
        }
        return Ok(Some(kept));
    }
    // An edit landed between the last check and the exchange: put it back.
    if let Err(error) = exchange(&temp, path) {
        let kept = keep_aside(&temp, conflict);
        let _ = sync_dir(dir);
        return Err(failure(format!(
            "`{}` changed while wssp was writing it, and wssp could not put the changed file back ({error}); it is kept as `{}`: merge it into `{}` (which now holds wssp's version) and remove it",
            path.display(),
            kept.display(),
            path.display()
        )));
    }
    #[cfg(test)]
    tests::after_exchange(path);
    // `temp` holds wssp's new file again, or a still later edit.
    let back = observe(&temp).ok().flatten();
    if back
        .as_ref()
        .is_some_and(|seen| (seen.dev, seen.ino) == ours && seen.bytes == bytes)
    {
        let _ = std::fs::remove_file(&temp);
        let _ = sync_dir(dir);
        return Err(changed(path));
    }
    let kept = keep_aside(&temp, conflict);
    let _ = sync_dir(dir);
    Err(failure(format!(
        "`{}` was changed twice while wssp was writing it; wssp put the first change back in place and kept the second as `{}`: merge what you need from it into `{}`, remove it and run `wssp ssh-config --install` again",
        path.display(),
        kept.display(),
        path.display()
    )))
}

/// The home directory OpenSSH reads `~/.ssh/config` from: the account's
/// (passwd) home, not `$HOME`. A different `$HOME` is refused, so an
/// install never lands where ssh does not look.
pub fn ssh_home() -> Result<PathBuf> {
    let env = dirs::home_dir();
    match (env, passwd_home()) {
        (Some(env), Some(account)) => {
            let same = |a: &Path, b: &Path| {
                a == b
                    || std::fs::canonicalize(a)
                        .ok()
                        .zip(std::fs::canonicalize(b).ok())
                        .is_some_and(|(a, b)| a == b)
            };
            if same(&env, &account) {
                Ok(account)
            } else {
                Err(usage(format!(
                    "`$HOME` is `{}`, but ssh reads `{}/.ssh/config` (your account's home directory); run `HOME={} wssp ssh-config --install`, or save `wssp ssh-config` and include it yourself",
                    env.display(),
                    account.display(),
                    account.display()
                )))
            }
        }
        (None, Some(account)) => Ok(account),
        (Some(env), None) => Ok(env),
        (None, None) => anyhow::bail!("could not determine the home directory"),
    }
}

/// The passwd home of this user (`getent`, so NSS users count; else
/// `/etc/passwd`). `None` when neither knows the user.
fn passwd_home() -> Option<PathBuf> {
    let uid = rustix::process::getuid().as_raw().to_string();
    let from_line = |line: &str| {
        let fields: Vec<&str> = line.trim_end_matches('\n').split(':').collect();
        (fields.len() >= 7 && fields[2] == uid && fields[5].starts_with('/'))
            .then(|| PathBuf::from(fields[5]))
    };
    // A user-facing lookup (pinned in `no_live_incus.rs`): getent needs
    // only PATH, so it inherits nothing else.
    let getent = std::process::Command::new("getent")
        .env_clear()
        .envs(std::env::var_os("PATH").map(|path| ("PATH", path)))
        .args(["passwd", &uid])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|text| text.lines().find_map(from_line));
    getent.or_else(|| {
        std::fs::read_to_string("/etc/passwd")
            .ok()?
            .lines()
            .find_map(from_line)
    })
}

/// Releases the install lock explicitly on every return: a child process
/// another thread forks meanwhile shares the open file until its `exec`,
/// so closing alone could keep the lock a moment longer.
struct Unlock(std::fs::File);

impl Drop for Unlock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

/// Write the managed config and add the `Include` line (after `confirm`
/// says yes). `home` is the user's home directory; `lock_dir` holds the
/// lock that serializes installers.
pub fn install(
    home: &Path,
    block: &str,
    lock_dir: &Path,
    confirm: impl FnOnce(&Path) -> Result<bool>,
) -> Result<Installed> {
    let lock = crate::state::open_named_lock_file(lock_dir, INSTALL_LOCK_FILE)?;
    match lock.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => {
            return Err(failure(
                "another `wssp ssh-config --install` is running; run this again once it ended",
            ));
        }
        Err(std::fs::TryLockError::Error(error)) => {
            return Err(error).context("locking the ssh config install");
        }
    }
    let _held = Unlock(lock);
    let ssh = home.join(".ssh");
    ensure_dir(&ssh)?;
    let config_d = ssh.join("config.d");
    ensure_dir(&config_d)?;
    let managed = config_d.join("wssp");
    let managed_seen = observe(&managed)?;
    if let Some(seen) = &managed_seen
        && !seen
            .bytes
            .split(|b| *b == b'\n')
            .next()
            .is_some_and(|first| first == MANAGED_HEADER.as_bytes())
    {
        return Err(usage(format!(
            "`{}` exists and was not written by wssp; move it away and run this again",
            managed.display()
        )));
    }
    // Both kept outside `config.d/`, so a `config.d/*` Include never reads
    // them.
    let write_managed = || -> Result<Option<Backup>> {
        if managed_seen
            .as_ref()
            .is_some_and(|seen| seen.bytes == block.as_bytes())
        {
            return unchanged(&managed, managed_seen.as_ref()).map(|()| None);
        }
        let kept = publish_over(
            &managed,
            block.as_bytes(),
            managed_seen.as_ref(),
            &Aside {
                backup: &ssh.join("config.d-wssp.wssp-backup"),
                conflict: &ssh.join("config.d-wssp.wssp-conflict"),
                manual: "save the output of `wssp ssh-config` as that file yourself",
            },
        )?;
        Ok(kept.map(|backup| Backup {
            file: managed.clone(),
            backup,
        }))
    };
    let ssh_config = ssh.join("config");
    let done = |include_added, backups: Vec<Option<Backup>>| Installed {
        config_path: managed.clone(),
        ssh_config: ssh_config.clone(),
        include_added,
        backups: backups.into_iter().flatten().collect(),
    };
    if std::fs::symlink_metadata(&ssh_config).is_ok_and(|meta| meta.file_type().is_symlink()) {
        if read_regular_through(&ssh_config)?
            .is_some_and(|text| effective_include(&text, &ssh, home))
        {
            let kept = write_managed()?;
            return Ok(done(false, vec![kept]));
        }
        return Err(usage(format!(
            "`{}` is a symlink, which wssp does not rewrite; add `{INCLUDE_LINE}` as its first line yourself",
            ssh_config.display()
        )));
    }
    let config_seen = observe(&ssh_config)?;
    let text = match &config_seen {
        Some(seen) => String::from_utf8(seen.bytes.clone())
            .with_context(|| format!("`{}` is not valid UTF-8", ssh_config.display()))?,
        None => String::new(),
    };
    if effective_include(&text, &ssh, home) {
        let kept = write_managed()?;
        return Ok(done(false, vec![kept]));
    }
    if config_seen.as_ref().is_some_and(|seen| seen.links > 1) {
        return Err(usage(format!(
            "`{}` has other hard links, which a rewrite would split; add `{INCLUDE_LINE}` as its first line yourself",
            ssh_config.display()
        )));
    }
    if !confirm(&ssh_config)? {
        return Err(failure(format!(
            "`{}` was left unchanged; `ssh <name>.wssp` needs `{INCLUDE_LINE}` at its top",
            ssh_config.display()
        )));
    }
    // After the answer, before anything is written: the config must still be
    // the one the question was about.
    unchanged(&ssh_config, config_seen.as_ref())?;
    let managed_kept = write_managed()?;
    // At the very top: an `Include` below a `Host` or `Match` line would
    // apply only inside that block, and the first value ssh reads wins.
    let mut updated = format!("{INCLUDE_LINE}\n");
    if !text.is_empty() {
        updated.push('\n');
        updated.push_str(&text);
    }
    let config_kept = publish_over(
        &ssh_config,
        updated.as_bytes(),
        config_seen.as_ref(),
        &Aside {
            backup: &ssh.join("config.wssp-backup"),
            conflict: &ssh.join("config.wssp-conflict"),
            manual: &format!("add `{INCLUDE_LINE}` as its first line yourself"),
        },
    )
    .map_err(|error| match &managed_kept {
        // The managed file was replaced already: say where its old version is.
        Some(kept) => error.context(format!(
            "`{}` was updated; wssp kept its previous version as `{}`",
            kept.file.display(),
            kept.backup.display()
        )),
        None => error,
    })?;
    Ok(done(
        true,
        vec![
            managed_kept,
            config_kept.map(|backup| Backup {
                file: ssh_config.clone(),
                backup,
            }),
        ],
    ))
}

/// A symlinked config's text, read through the link (never written).
fn read_regular_through(path: &Path) -> Result<Option<String>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).into_owned())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("reading `{}`", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type PathHook = Box<dyn FnMut(&Path)>;
    type ExchangeHook = Box<dyn FnMut(&Path, &Path) -> Option<std::io::Error>>;

    thread_local! {
        /// Runs between the last check and the rename or exchange (this
        /// thread, each publish).
        static BEFORE_RENAME: std::cell::RefCell<Option<PathHook>> =
            const { std::cell::RefCell::new(None) };
        /// Runs after each successful exchange.
        static AFTER_EXCHANGE: std::cell::RefCell<Option<PathHook>> =
            const { std::cell::RefCell::new(None) };
        /// Decides each exchange: `Some(error)` fails it instead.
        static EXCHANGE: std::cell::RefCell<Option<ExchangeHook>> =
            const { std::cell::RefCell::new(None) };
    }

    pub(super) fn before_rename(path: &Path) {
        BEFORE_RENAME.with(|hook| {
            if let Some(hook) = hook.borrow_mut().as_mut() {
                hook(path);
            }
        });
    }

    pub(super) fn after_exchange(path: &Path) {
        AFTER_EXCHANGE.with(|hook| {
            if let Some(hook) = hook.borrow_mut().as_mut() {
                hook(path);
            }
        });
    }

    pub(super) fn exchange_override(a: &Path, b: &Path) -> Option<std::io::Error> {
        EXCHANGE.with(|hook| hook.borrow_mut().as_mut().and_then(|hook| hook(a, b)))
    }

    fn on_before_rename(hook: impl FnMut(&Path) + 'static) {
        BEFORE_RENAME.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    }

    fn on_after_exchange(hook: impl FnMut(&Path) + 'static) {
        AFTER_EXCHANGE.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    }

    fn on_exchange(hook: impl FnMut(&Path, &Path) -> Option<std::io::Error> + 'static) {
        EXCHANGE.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    }

    /// Names in `dir` starting with `prefix`.
    fn named(dir: &Path, prefix: &str) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(prefix))
            .collect();
        names.sort();
        names
    }

    /// No temporary file is left in `~/.ssh` or `config.d`.
    fn assert_no_temp(homes: &Homes) {
        for dir in [homes.ssh(), homes.ssh().join("config.d")] {
            if dir.exists() {
                assert_eq!(named(&dir, ".wssp-ssh-"), Vec::<String>::new(), "{dir:?}");
            }
        }
    }

    /// An editor's save: a new file renamed over `path`.
    fn editor_save(path: &Path, text: &str) {
        let temp = path.with_file_name(".editor-save");
        std::fs::write(&temp, text).unwrap();
        std::fs::rename(temp, path).unwrap();
    }

    #[test]
    fn a_file_that_appears_just_before_the_rename_is_not_replaced() {
        let homes = Homes::new();
        let mut once = true;
        on_before_rename(move |path: &Path| {
            if std::mem::take(&mut once) {
                std::fs::write(path, "Host raced\n").unwrap();
            }
        });
        let error = homes.install(|_| Ok(true)).unwrap_err();
        assert!(format!("{error:#}").contains("changed while wssp was waiting"));
        // The managed file was the first to be published (and raced).
        assert_eq!(
            std::fs::read_to_string(homes.ssh().join("config.d/wssp")).unwrap(),
            "Host raced\n"
        );
        assert!(!homes.ssh().join("config").exists());
        assert_no_temp(&homes);
    }

    /// The review's race: an edit lands on an existing file after the last
    /// check, right before the exchange. It is put back in place, in the
    /// config and in the managed file alike, whether the editor wrote in
    /// place or renamed a new file over it.
    #[test]
    fn an_edit_that_lands_just_before_the_exchange_is_put_back() {
        use std::os::unix::fs::MetadataExt;
        let existing = "Host work\n  User me\n";
        let old_managed = format!("{MANAGED_HEADER}\nHost old.wssp\n");
        for target in ["config", "config.d/wssp"] {
            for in_place in [true, false] {
                let what = format!("{target}, in place: {in_place}");
                let homes = Homes::new();
                std::fs::create_dir(homes.ssh().join("config.d")).unwrap();
                std::fs::write(homes.ssh().join("config"), existing).unwrap();
                // The managed file is either up to date (only the config is
                // published) or outdated (it is published first).
                let managed = if target == "config" {
                    BLOCK.to_owned()
                } else {
                    old_managed.clone()
                };
                std::fs::write(homes.ssh().join("config.d/wssp"), &managed).unwrap();
                let raced = homes.ssh().join(target);
                let edit = format!("{MANAGED_HEADER}\n# edited meanwhile\nHost work\n");
                let (hook_target, hook_edit) = (raced.clone(), edit.clone());
                on_before_rename(move |path: &Path| {
                    if path == hook_target {
                        if in_place {
                            std::fs::write(path, &hook_edit).unwrap();
                        } else {
                            editor_save(path, &hook_edit);
                        }
                    }
                });
                let inode = std::fs::metadata(&raced).unwrap().ino();
                let error = homes.install(|_| Ok(true)).unwrap_err();
                assert!(
                    format!("{error:#}").contains("changed while wssp was waiting"),
                    "{what}: {error:#}"
                );
                assert_eq!(crate::exit::code_for(&error), ExitCode::Failure, "{what}");
                assert_eq!(std::fs::read_to_string(&raced).unwrap(), edit, "{what}");
                if in_place {
                    assert_eq!(std::fs::metadata(&raced).unwrap().ino(), inode, "{what}");
                }
                if target == "config.d/wssp" {
                    assert_eq!(
                        std::fs::read_to_string(homes.ssh().join("config")).unwrap(),
                        existing,
                        "{what}"
                    );
                }
                assert_eq!(
                    named(&homes.ssh(), "config.wssp-conflict"),
                    Vec::<String>::new()
                );
                assert_eq!(
                    named(&homes.ssh(), "config.d-wssp.wssp-conflict"),
                    Vec::<String>::new()
                );
                assert_no_temp(&homes);
            }
        }
    }

    /// A second edit lands while the first is being put back: the first
    /// stays in place, the second is kept as a private conflict file named
    /// in the error, and nothing is lost.
    #[test]
    fn a_second_edit_during_the_exchange_is_kept_as_a_conflict_file() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        for in_place in [true, false] {
            let homes = Homes::new();
            std::fs::create_dir(homes.ssh().join("config.d")).unwrap();
            std::fs::write(homes.ssh().join("config.d/wssp"), BLOCK).unwrap();
            let config = homes.ssh().join("config");
            std::fs::write(&config, "Host work\n").unwrap();
            std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o644)).unwrap();
            on_before_rename(|path: &Path| {
                if path.ends_with("config") {
                    editor_save(path, "Host first-edit\n");
                }
            });
            let mut calls = 0;
            on_after_exchange(move |path: &Path| {
                calls += 1;
                if calls == 1 {
                    if in_place {
                        std::fs::write(path, "Host second-edit\n").unwrap();
                    } else {
                        editor_save(path, "Host second-edit\n");
                    }
                }
            });
            let error = homes.install(|_| Ok(true)).unwrap_err();
            let message = format!("{error:#}");
            assert!(message.contains("changed twice"), "{message}");
            assert_eq!(crate::exit::code_for(&error), ExitCode::Failure);
            assert_eq!(
                std::fs::read_to_string(&config).unwrap(),
                "Host first-edit\n"
            );
            let kept = named(&homes.ssh(), "config.wssp-conflict-");
            assert_eq!(kept.len(), 1, "{kept:?}");
            let kept = homes.ssh().join(&kept[0]);
            assert!(message.contains(&kept.display().to_string()), "{message}");
            assert_eq!(
                std::fs::read_to_string(&kept).unwrap(),
                "Host second-edit\n"
            );
            let meta = std::fs::metadata(&kept).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
            assert_eq!(meta.uid(), rustix::process::getuid().as_raw());
            assert_no_temp(&homes);
        }
    }

    /// The exchange back fails: the edit is kept as a conflict file (never
    /// removed), and the error says where and what `config` holds now.
    #[test]
    fn an_edit_that_cannot_be_put_back_is_kept_as_a_conflict_file() {
        let homes = Homes::new();
        std::fs::create_dir(homes.ssh().join("config.d")).unwrap();
        std::fs::write(homes.ssh().join("config.d/wssp"), BLOCK).unwrap();
        let config = homes.ssh().join("config");
        std::fs::write(&config, "Host work\n").unwrap();
        on_before_rename(|path: &Path| editor_save(path, "Host edited\n"));
        let mut calls = 0;
        on_exchange(move |_, _| {
            calls += 1;
            (calls == 2)
                .then(|| std::io::Error::from_raw_os_error(rustix::io::Errno::IO.raw_os_error()))
        });
        let error = homes.install(|_| Ok(true)).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("could not put the changed file back"),
            "{message}"
        );
        let kept = named(&homes.ssh(), "config.wssp-conflict-");
        assert_eq!(kept.len(), 1, "{kept:?}");
        assert!(message.contains(&kept[0]), "{message}");
        assert_eq!(
            std::fs::read_to_string(homes.ssh().join(&kept[0])).unwrap(),
            "Host edited\n"
        );
        assert!(
            std::fs::read_to_string(&config)
                .unwrap()
                .starts_with(INCLUDE_LINE)
        );
        assert_no_temp(&homes);
    }

    /// Without RENAME_EXCHANGE nothing existing is replaced (no lossy
    /// fallback to a plain rename), for the config and the managed file.
    #[test]
    fn without_rename_exchange_an_existing_file_is_never_replaced() {
        let old_managed = format!("{MANAGED_HEADER}\nHost old.wssp\n");
        for errno in [rustix::io::Errno::INVAL, rustix::io::Errno::NOSYS] {
            for target in ["config", "config.d/wssp"] {
                let what = format!("{target}, {errno:?}");
                let homes = Homes::new();
                std::fs::create_dir(homes.ssh().join("config.d")).unwrap();
                std::fs::write(homes.ssh().join("config"), "Host work\n").unwrap();
                let managed = if target == "config" {
                    BLOCK
                } else {
                    old_managed.as_str()
                };
                std::fs::write(homes.ssh().join("config.d/wssp"), managed).unwrap();
                on_exchange(move |_, _| {
                    Some(std::io::Error::from_raw_os_error(errno.raw_os_error()))
                });
                let error = homes.install(|_| Ok(true)).unwrap_err();
                let message = format!("{error:#}");
                assert!(message.contains("RENAME_EXCHANGE"), "{what}: {message}");
                let hint = if target == "config" {
                    "add `Include config.d/wssp` as its first line yourself"
                } else {
                    "save the output of `wssp ssh-config` as that file yourself"
                };
                assert!(message.contains(hint), "{what}: {message}");
                assert_eq!(crate::exit::code_for(&error), ExitCode::Usage, "{what}");
                assert_eq!(
                    std::fs::read_to_string(homes.ssh().join("config")).unwrap(),
                    "Host work\n",
                    "{what}"
                );
                assert_eq!(
                    std::fs::read_to_string(homes.ssh().join("config.d/wssp")).unwrap(),
                    managed,
                    "{what}"
                );
                assert_no_temp(&homes);
            }
        }
        // A file that did not exist needs no exchange.
        let homes = Homes::new();
        on_exchange(|_, _| {
            Some(std::io::Error::from_raw_os_error(
                rustix::io::Errno::INVAL.raw_os_error(),
            ))
        });
        assert!(homes.install(|_| Ok(true)).unwrap().include_added);
    }

    /// The normal path over existing files: one exchange each, and each old
    /// file kept (never unlinked) as a private backup outside `config.d/`,
    /// reported by the install; no temporary file left behind.
    #[test]
    fn publishing_over_existing_files_exchanges_and_keeps_the_old_ones() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let homes = Homes::new();
        std::fs::create_dir(homes.ssh().join("config.d")).unwrap();
        let old_managed = format!("{MANAGED_HEADER}\nHost old.wssp\n");
        std::fs::write(homes.ssh().join("config.d/wssp"), &old_managed).unwrap();
        std::fs::write(homes.ssh().join("config"), "Host work\n").unwrap();
        std::fs::set_permissions(
            homes.ssh().join("config"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let inode = std::fs::metadata(homes.ssh().join("config")).unwrap().ino();
        let exchanged = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let seen = exchanged.clone();
        on_exchange(move |_, b| {
            seen.borrow_mut().push(b.to_owned());
            None
        });
        let done = homes.install(|_| Ok(true)).unwrap();
        assert!(done.include_added);
        assert_eq!(
            *exchanged.borrow(),
            vec![
                homes.ssh().join("config.d/wssp"),
                homes.ssh().join("config")
            ]
        );
        assert_eq!(
            std::fs::read_to_string(homes.ssh().join("config")).unwrap(),
            "Include config.d/wssp\n\nHost work\n"
        );
        assert_eq!(
            std::fs::read_to_string(homes.ssh().join("config.d/wssp")).unwrap(),
            BLOCK
        );
        assert_ne!(
            std::fs::metadata(homes.ssh().join("config")).unwrap().ino(),
            inode
        );
        // The new config keeps the old mode; the backups are private.
        assert_eq!(
            std::fs::metadata(homes.ssh().join("config"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        let files: Vec<&Path> = done
            .backups
            .iter()
            .map(|kept| kept.file.as_path())
            .collect();
        assert_eq!(
            files,
            [
                homes.ssh().join("config.d/wssp").as_path(),
                homes.ssh().join("config").as_path()
            ]
        );
        for (kept, prefix, old) in [
            (
                &done.backups[0],
                "config.d-wssp.wssp-backup-",
                old_managed.as_str(),
            ),
            (&done.backups[1], "config.wssp-backup-", "Host work\n"),
        ] {
            assert_eq!(kept.backup.parent(), Some(homes.ssh().as_path()));
            assert_eq!(named(&homes.ssh(), prefix).len(), 1, "{prefix}");
            assert!(
                kept.backup
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(prefix)
            );
            assert_eq!(std::fs::read_to_string(&kept.backup).unwrap(), old);
            let meta = std::fs::metadata(&kept.backup).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
            assert_eq!(meta.uid(), rustix::process::getuid().as_raw());
        }
        // The old config's inode is the backup itself.
        assert_eq!(
            std::fs::metadata(&done.backups[1].backup).unwrap().ino(),
            inode
        );
        assert_eq!(
            named(&homes.ssh(), "config.wssp-conflict"),
            Vec::<String>::new()
        );
        assert_eq!(
            named(&homes.ssh().join("config.d"), ""),
            vec!["wssp".to_owned()]
        );
        assert_no_temp(&homes);
        // An up-to-date install replaces nothing and keeps nothing more.
        let again = homes.install(|_| panic!("asked again")).unwrap();
        assert_eq!(again.backups, Vec::new());
        assert_eq!(named(&homes.ssh(), "config.wssp-backup-").len(), 1);
    }

    /// The review's lost save: a program opened `config` and the managed
    /// file before the publication and saves through those descriptors
    /// after it. The saves land in the backups (the very inodes it holds),
    /// so nothing it wrote is lost, and the published files stay wssp's.
    #[test]
    fn a_save_through_a_descriptor_opened_before_publication_lands_in_the_backup() {
        use std::io::{Seek, Write};
        let homes = Homes::new();
        std::fs::create_dir(homes.ssh().join("config.d")).unwrap();
        let config = homes.ssh().join("config");
        let managed = homes.ssh().join("config.d/wssp");
        std::fs::write(&managed, format!("{MANAGED_HEADER}\nHost old.wssp\n")).unwrap();
        std::fs::write(&config, "Host work\n").unwrap();
        let open = |path: &Path| {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .unwrap()
        };
        let mut late = [(open(&config), &config), (open(&managed), &managed)];
        let done = homes.install(|_| Ok(true)).unwrap();
        let saves = [
            "Host work\n  User saved-late\n".to_owned(),
            format!("{MANAGED_HEADER}\n# saved late\n"),
        ];
        for ((file, _), save) in late.iter_mut().zip(&saves) {
            file.set_len(0).unwrap();
            file.rewind().unwrap();
            file.write_all(save.as_bytes()).unwrap();
            file.sync_all().unwrap();
        }
        drop(late);
        for (path, save) in [(&config, &saves[0]), (&managed, &saves[1])] {
            let kept = done
                .backups
                .iter()
                .find(|kept| &kept.file == path)
                .unwrap_or_else(|| panic!("no backup of {path:?}: {:?}", done.backups));
            assert_eq!(&std::fs::read_to_string(&kept.backup).unwrap(), save);
        }
        assert_eq!(
            std::fs::read_to_string(&config).unwrap(),
            "Include config.d/wssp\n\nHost work\n"
        );
        assert_eq!(std::fs::read_to_string(&managed).unwrap(), BLOCK);
    }

    /// Backups never replace each other: a second one in the same second
    /// gets a counter, and both keep their bytes.
    #[test]
    fn a_backup_never_replaces_an_earlier_one() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("config.wssp-backup");
        let mut kept = Vec::new();
        for text in ["first\n", "second\n"] {
            let temp = dir.path().join(".wssp-ssh-temp");
            std::fs::write(&temp, text).unwrap();
            kept.push(keep_aside(&temp, &base));
            assert!(!temp.exists());
        }
        assert_ne!(kept[0], kept[1]);
        assert_eq!(std::fs::read_to_string(&kept[0]).unwrap(), "first\n");
        assert_eq!(std::fs::read_to_string(&kept[1]).unwrap(), "second\n");
    }

    #[test]
    fn the_host_key_is_made_once_private_and_matches_known_hosts() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let first = host_key_in(dir.path(), false).unwrap();
        assert!(first.created);
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&first.key_path), 0o600);
        assert_eq!(mode(&first.known_hosts), 0o600);
        assert!(first.public.starts_with("ssh-ed25519 "));
        assert!(first.fingerprint.starts_with("SHA256:"));
        assert_eq!(
            std::fs::read_to_string(&first.known_hosts).unwrap(),
            format!("wssp {}\n", first.public)
        );
        // Reused, and a damaged known_hosts is put back.
        std::fs::write(&first.known_hosts, "wssp ssh-ed25519 AAAAother\n").unwrap();
        let again = host_key_in(dir.path(), false).unwrap();
        assert!(!again.created);
        assert_eq!(again.public, first.public);
        assert_eq!(
            std::fs::read_to_string(&again.known_hosts).unwrap(),
            format!("wssp {}\n", first.public)
        );
        // Rotation replaces both.
        let rotated = host_key_in(dir.path(), true).unwrap();
        assert!(rotated.created);
        assert_ne!(rotated.public, first.public);
        assert_eq!(
            std::fs::read_to_string(&rotated.known_hosts).unwrap(),
            format!("wssp {}\n", rotated.public)
        );
        // The private key file is OpenSSH's format. The header is split so
        // this source holds no literal key header (the secret scan).
        let pem = std::fs::read_to_string(&rotated.key_path).unwrap();
        assert!(pem.starts_with(concat!("-----BEGIN OPENSSH ", "PRIVATE KEY-----")));
        // A symlinked key is refused, never followed.
        std::fs::remove_file(&rotated.key_path).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", &rotated.key_path).unwrap();
        assert!(host_key_in(dir.path(), false).is_err());
    }

    #[test]
    fn the_config_block_is_the_documented_one() {
        let block = config_block(
            Path::new("/opt/wssp bin/wssp"),
            Path::new("/home/u/.local/share/wssp/user/ssh/known_hosts"),
        )
        .unwrap();
        assert_eq!(
            block,
            "# Managed by wssp. Regenerate with `wssp ssh-config --install`.
Host *.wssp \"!*'*\" \"!*\\*\"
  ProxyCommand \"/opt/wssp bin/wssp\" ssh --stdio '%n'
  User wssp
  HostKeyAlias wssp
  UserKnownHostsFile \"/home/u/.local/share/wssp/user/ssh/known_hosts\"
  GlobalKnownHostsFile /dev/null
  StrictHostKeyChecking yes
  HostKeyAlgorithms ssh-ed25519
  CanonicalizeHostname no
  IdentitiesOnly yes
  IdentityFile none
  ForwardAgent no
  ForwardX11 no
  ServerAliveInterval 30
"
        );
        for bad in [
            "relative/wssp",
            "/a\"b",
            "/a%n",
            "/a$HOME",
            "/a`x`",
            "/a\nb",
            "/a\\b",
        ] {
            assert!(quoted(Path::new(bad)).is_err(), "{bad:?}");
        }
    }

    const BLOCK: &str =
        "# Managed by wssp. Regenerate with `wssp ssh-config --install`.\nHost *.wssp\n";

    /// A home and a separate wssp user directory (for the install lock).
    struct Homes {
        home: tempfile::TempDir,
        user: tempfile::TempDir,
    }

    impl Homes {
        fn new() -> Self {
            let homes = Self {
                home: tempfile::tempdir().unwrap(),
                user: tempfile::tempdir().unwrap(),
            };
            std::fs::create_dir(homes.ssh()).unwrap();
            homes
        }

        fn ssh(&self) -> PathBuf {
            self.home.path().join(".ssh")
        }

        fn install(&self, confirm: impl FnOnce(&Path) -> Result<bool>) -> Result<Installed> {
            install(self.home.path(), BLOCK, self.user.path(), confirm)
        }
    }

    #[test]
    fn install_adds_one_include_at_the_top_and_touches_nothing_else() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let user = tempfile::tempdir().unwrap();
        let block = BLOCK;
        // No ~/.ssh at all: created 0700, config created with the line.
        let done = install(home.path(), block, user.path(), |_| Ok(true)).unwrap();
        assert!(done.include_added);
        let ssh = home.path().join(".ssh");
        assert_eq!(
            std::fs::metadata(&ssh).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::read_to_string(ssh.join("config")).unwrap(),
            "Include config.d/wssp\n"
        );
        assert_eq!(std::fs::read_to_string(&done.config_path).unwrap(), block);
        // An existing config keeps every byte below the new first line, and
        // its mode.
        let existing = "Host work\n  User me\n\nMatch all\n  ForwardAgent no\n";
        std::fs::write(ssh.join("config"), existing).unwrap();
        std::fs::set_permissions(ssh.join("config"), std::fs::Permissions::from_mode(0o644))
            .unwrap();
        let mut asked = 0;
        let done = install(home.path(), block, user.path(), |_| {
            asked += 1;
            Ok(true)
        })
        .unwrap();
        assert!(done.include_added);
        assert_eq!(asked, 1);
        assert_eq!(
            std::fs::read_to_string(ssh.join("config")).unwrap(),
            format!("Include config.d/wssp\n\n{existing}")
        );
        assert_eq!(
            std::fs::metadata(ssh.join("config"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        // Idempotent: no second line, no question.
        let done = install(home.path(), block, user.path(), |_| panic!("asked again")).unwrap();
        assert!(!done.include_added);
        assert_eq!(
            std::fs::read_to_string(ssh.join("config"))
                .unwrap()
                .matches("Include config.d/wssp")
                .count(),
            1
        );
        // Declined: nothing is written, not even the managed file.
        let other = Homes::new();
        std::fs::write(other.ssh().join("config"), existing).unwrap();
        assert!(other.install(|_| Ok(false)).is_err());
        assert_eq!(
            std::fs::read_to_string(other.ssh().join("config")).unwrap(),
            existing
        );
        assert!(!other.ssh().join("config.d/wssp").exists());
        // A foreign config.d/wssp is never overwritten.
        let foreign = Homes::new();
        std::fs::create_dir_all(foreign.ssh().join("config.d")).unwrap();
        std::fs::write(foreign.ssh().join("config.d/wssp"), "Host mine\n").unwrap();
        assert!(foreign.install(|_| Ok(true)).is_err());
        assert_eq!(
            std::fs::read_to_string(foreign.ssh().join("config.d/wssp")).unwrap(),
            "Host mine\n"
        );
        // A symlinked config is not rewritten.
        let linked = Homes::new();
        std::fs::write(linked.home.path().join("dotfile"), existing).unwrap();
        std::os::unix::fs::symlink(
            linked.home.path().join("dotfile"),
            linked.ssh().join("config"),
        )
        .unwrap();
        assert!(linked.install(|_| Ok(true)).is_err());
        assert_eq!(
            std::fs::read_to_string(linked.home.path().join("dotfile")).unwrap(),
            existing
        );
        // ... unless it already includes the block (then only the managed
        // file is written).
        std::fs::write(
            linked.home.path().join("dotfile"),
            "Include config.d/wssp\n",
        )
        .unwrap();
        assert!(!linked.install(|_| panic!("asked")).unwrap().include_added);
        assert!(
            std::fs::symlink_metadata(linked.ssh().join("config"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        // A hard-linked config is not split by a rename.
        let hard = Homes::new();
        std::fs::write(hard.home.path().join("other"), existing).unwrap();
        std::fs::hard_link(hard.home.path().join("other"), hard.ssh().join("config")).unwrap();
        let error = hard.install(|_| Ok(true)).unwrap_err();
        assert!(format!("{error:#}").contains("hard links"), "{error:#}");
        assert_eq!(
            std::fs::read_to_string(hard.ssh().join("config")).unwrap(),
            existing
        );
        // A symlinked ~/.ssh is named as such and not written through.
        let dotfiles = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(dotfiles.path(), home.path().join(".ssh")).unwrap();
        let error = install(home.path(), block, user.path(), |_| Ok(true)).unwrap_err();
        assert!(format!("{error:#}").contains("is a symlink"), "{error:#}");
        assert_eq!(std::fs::read_dir(dotfiles.path()).unwrap().count(), 0);
    }

    #[test]
    fn an_edit_made_while_the_prompt_is_open_is_never_overwritten() {
        use std::os::unix::fs::PermissionsExt;
        let existing = "Host work\n  User me\n";
        type Hook = fn(&Path);
        let cases: [(&str, Hook); 5] = [
            ("an edit", |config| {
                std::fs::write(config, "Host work\n  User someone-else\n").unwrap()
            }),
            ("an editor's rename", |config| {
                let temp = config.with_file_name("config.swp");
                std::fs::write(&temp, "Host work\n  User me\n").unwrap();
                std::fs::rename(temp, config).unwrap();
            }),
            ("a symlink", |config| {
                let target = config.with_file_name("elsewhere");
                std::fs::write(&target, "Host work\n  User me\n").unwrap();
                std::fs::remove_file(config).unwrap();
                std::os::unix::fs::symlink(target, config).unwrap();
            }),
            ("a mode change", |config| {
                std::fs::set_permissions(config, std::fs::Permissions::from_mode(0o640)).unwrap()
            }),
            ("a foreign managed file", |config| {
                std::fs::write(config.with_file_name("config.d").join("wssp"), "Host x\n").unwrap()
            }),
        ];
        for (what, hook) in cases {
            let homes = Homes::new();
            let config = homes.ssh().join("config");
            std::fs::write(&config, existing).unwrap();
            std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
            let before_hook = |path: &Path| std::fs::read(path).ok();
            let error = homes
                .install(|path| {
                    hook(path);
                    Ok(true)
                })
                .unwrap_err();
            assert!(
                format!("{error:#}").contains("changed while wssp was waiting"),
                "{what}: {error:#}"
            );
            assert_eq!(crate::exit::code_for(&error), ExitCode::Failure, "{what}");
            // Whatever the hook left is what stays.
            let text = std::fs::read_to_string(&config).unwrap();
            assert!(!text.contains(INCLUDE_LINE), "{what}: {text}");
            let managed = before_hook(&homes.ssh().join("config.d/wssp"));
            assert!(
                managed.is_none() || managed.as_deref() == Some(b"Host x\n".as_slice()),
                "{what}"
            );
        }
        // A config that appears while the prompt is open is not clobbered.
        let homes = Homes::new();
        let error = homes
            .install(|path| {
                std::fs::write(path, "Host new\n").unwrap();
                Ok(true)
            })
            .unwrap_err();
        assert!(format!("{error:#}").contains("changed while wssp was waiting"));
        assert_eq!(
            std::fs::read_to_string(homes.ssh().join("config")).unwrap(),
            "Host new\n"
        );
        // A managed file that appears meanwhile (even wssp's own) is not
        // clobbered either.
        let homes = Homes::new();
        let error = homes
            .install(|path| {
                std::fs::write(path.with_file_name("config.d").join("wssp"), BLOCK).unwrap();
                Ok(true)
            })
            .unwrap_err();
        assert!(format!("{error:#}").contains("changed while wssp was waiting"));
        assert!(!homes.ssh().join("config").exists());
    }

    #[test]
    fn a_second_installer_is_refused_while_one_runs() {
        let homes = Homes::new();
        let done = homes
            .install(|_| {
                let error = homes.install(|_| Ok(true)).unwrap_err();
                assert!(
                    format!("{error:#}").contains("another `wssp ssh-config --install` is running"),
                    "{error:#}"
                );
                Ok(true)
            })
            .unwrap();
        assert!(done.include_added);
        assert_eq!(
            std::fs::read_to_string(homes.ssh().join("config")).unwrap(),
            "Include config.d/wssp\n"
        );
    }

    #[test]
    fn only_an_include_that_is_the_first_directive_counts() {
        let ssh = Path::new("/home/u/.ssh");
        let home = Path::new("/home/u");
        let counts = |text: &str| effective_include(text, ssh, home);
        for text in [
            "Include config.d/wssp\n",
            "  include ~/.ssh/config.d/wssp\n",
            "Include \"/home/u/.ssh/config.d/wssp\"\n",
            "Include=config.d/wssp\n",
            "Include = config.d/wssp # managed by wssp\n",
            "# a comment\n\n\tInclude config.d/wssp\nHost work\n  User me\n",
            "Include config.d/wssp config.d/other\n",
        ] {
            assert!(counts(text), "{text:?}");
        }
        for text in [
            "",
            "# Include config.d/wssp\n",
            "#Include config.d/wssp\n",
            "Include config.d/wssp2\n",
            "Include config.d/*\n",
            "Host config.d/wssp\n",
            "Include other # config.d/wssp\n",
            // Another file read first may set options for every host.
            "INCLUDE other config.d/wssp\n",
            "Include config.d/other\nInclude config.d/wssp\n",
            // Any scope first, even one for every host.
            "Host *\nInclude config.d/wssp\n",
            "Match all\nInclude config.d/wssp\n",
            "Host work\nInclude config.d/wssp\n",
            "Host work\n  User me\nMatch ALL\n  Include config.d/wssp\n",
            "Host *.wssp\n  Include config.d/wssp\n",
            // The review's case: an earlier `Host *.wssp` sets ProxyCommand.
            "Host *.wssp\n  ProxyCommand false\nHost *\n  Include config.d/wssp\n",
            // Any option first.
            "ForwardAgent yes\nInclude config.d/wssp\n",
            "User=bob\nInclude config.d/wssp\n",
        ] {
            assert!(!counts(text), "{text:?}");
        }
        // The reviews' regressions: each gets a line at the very top, and
        // the rest stays.
        for existing in [
            "Host work\n  Include config.d/wssp\n",
            "Host *.wssp\n  ProxyCommand false\nHost *\n  Include config.d/wssp\n",
            "Include config.d/other\nInclude config.d/wssp\n",
        ] {
            let homes = Homes::new();
            std::fs::write(homes.ssh().join("config"), existing).unwrap();
            assert!(
                homes.install(|_| Ok(true)).unwrap().include_added,
                "{existing:?}"
            );
            assert_eq!(
                std::fs::read_to_string(homes.ssh().join("config")).unwrap(),
                format!("Include config.d/wssp\n\n{existing}")
            );
        }
    }

    #[test]
    fn ssh_config_lines_split_like_openssh() {
        let parse = |line: &str| directive(line).map(|(k, a)| (k, a.join("|")));
        assert_eq!(parse("   "), None);
        assert_eq!(parse("  # x"), None);
        assert_eq!(parse("Host a b"), Some(("Host".into(), "a|b".into())));
        assert_eq!(parse("Host=a"), Some(("Host".into(), "a".into())));
        assert_eq!(parse("Host = a\t b"), Some(("Host".into(), "a|b".into())));
        assert_eq!(
            parse("Include \"a b\" 'c d' e\\ f # x"),
            Some(("Include".into(), "a b|c d|e f".into()))
        );
        assert_eq!(
            parse("Include \"a\\\"b\" c#d"),
            Some(("Include".into(), "a\"b|c#d".into()))
        );
    }

    /// The installed `~/.ssh/config` as the real OpenSSH reads it selects
    /// the block's values for `<sandbox>.wssp`, ahead of the user's own
    /// settings, for each user config (the reviews' cases included: an
    /// earlier `Host *.wssp` ProxyCommand before a `Host *` Include, and an
    /// earlier Include that sets one). ssh resolves a relative `Include` in
    /// the account's home (not `$HOME`), so the copy given to `ssh -F`
    /// names the temporary home's `config.d` absolutely; everything else is
    /// the installed text. The same rewrite of the config before the install
    /// shows each case really was broken.
    #[test]
    fn the_installed_config_selects_the_block_in_real_ssh() {
        let have_ssh = std::process::Command::new("ssh")
            .arg("-V")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
        if !have_ssh {
            assert!(
                std::env::var_os("WSSP_REQUIRE_SSH_TOOLS").is_none_or(|v| v != "1"),
                "`ssh` is required (WSSP_REQUIRE_SSH_TOOLS=1)"
            );
            eprintln!("skipped: `ssh` is not installed");
            return;
        }
        let block = config_block(
            Path::new("/opt/wssp/bin/wssp"),
            Path::new("/home/u/.local/share/wssp/user/ssh/known_hosts"),
        )
        .unwrap();
        let proxy = "proxycommand \"/opt/wssp/bin/wssp\" ssh --stdio '%n'";
        let cases = [
            "Host work\n  Include config.d/wssp\n\nHost *\n  User bob\n  ForwardAgent yes\n  ProxyCommand nc %h %p\n  CanonicalizeHostname always\n  StrictHostKeyChecking no\n  GlobalKnownHostsFile /etc/ssh/other\n",
            "Host *.wssp\n  ProxyCommand false\nHost *\n  Include config.d/wssp\n",
            "Include config.d/other\nInclude config.d/wssp\n",
        ];
        for user_config in cases {
            let homes = Homes::new();
            std::fs::create_dir(homes.ssh().join("config.d")).unwrap();
            std::fs::write(
                homes.ssh().join("config.d/other"),
                "Host *.wssp\n  ProxyCommand false\n  User other\n",
            )
            .unwrap();
            // The managed file is in place already: only the Include decides.
            std::fs::write(homes.ssh().join("config.d/wssp"), &block).unwrap();
            std::fs::write(homes.ssh().join("config"), user_config).unwrap();
            let config_d = homes.ssh().join("config.d");
            let effective = |text: &str, host: &str| {
                let copy = homes.ssh().join("config.absolute");
                let absolute = text.replace(
                    "Include config.d/",
                    &format!("Include {}/", config_d.display()),
                );
                std::fs::write(&copy, absolute).unwrap();
                let output = std::process::Command::new("ssh")
                    .arg("-F")
                    .arg(&copy)
                    .args(["-G", host])
                    .stdin(std::process::Stdio::null())
                    .output()
                    .unwrap();
                assert!(output.status.success(), "{output:?}");
                String::from_utf8(output.stdout).unwrap()
            };
            let before = effective(user_config, "dev-box.wssp");
            assert!(
                !before.lines().any(|line| line == proxy),
                "{user_config:?} already selected the block:\n{before}"
            );
            install(homes.home.path(), &block, homes.user.path(), |_| Ok(true)).unwrap();
            let installed = std::fs::read_to_string(homes.ssh().join("config")).unwrap();
            assert!(installed.starts_with(INCLUDE_LINE), "{installed}");
            let sandbox = effective(&installed, "dev-box.wssp");
            for expected in [
                proxy,
                "user wssp",
                "hostkeyalias wssp",
                "userknownhostsfile /home/u/.local/share/wssp/user/ssh/known_hosts",
                "globalknownhostsfile /dev/null",
                "stricthostkeychecking true",
                "hostkeyalgorithms ssh-ed25519",
                "canonicalizehostname false",
                "identitiesonly yes",
                "forwardagent no",
                "forwardx11 no",
                "serveraliveinterval 30",
            ] {
                assert!(
                    sandbox.lines().any(|line| line == expected),
                    "{user_config:?}: {expected:?} missing in:\n{sandbox}"
                );
            }
            if user_config.contains("User bob") {
                // Other hosts keep the user's own settings.
                let other = effective(&installed, "example.test");
                assert!(other.lines().any(|line| line == "user bob"), "{other}");
                assert!(
                    other.lines().any(|line| line == "proxycommand nc %h %p"),
                    "{other}"
                );
            }
        }
    }
}
