//! `wssp guard install` / `uninstall`.
//!
//! Install copies the RUNNING binary to `/usr/local/lib/wssp/wssp-guard.new`
//! (0755), fsyncs it and renames it over `wssp-guard` (a running guard keeps
//! its old inode), writes `/etc/wssp/guard.toml`, creates an empty
//! `/etc/wssp/egress-blocklist` if absent (never overwrites), installs the
//! unit, reloads systemd and restarts (or enables and starts) the service,
//! then waits for the new instance's status. The unit's `ExecStart` is the
//! fixed root-owned path, never the user-writable binary that ran install.
//!
//! Every directory written into is proven root-controlled first, component
//! by component from `/`: a real directory (never a symlink), owned by
//! root, not group/world-writable. Otherwise whoever controls a component
//! could swap the binary that `ExecStart` runs as root. Nothing is chmod-ed
//! or reused on trust; a bad component refuses the install.
//!
//! Uninstall confirms the service stopped, then quarantines the table that
//! stays loaded (empties `live_bridges`, read back) before it removes any
//! file or reports success.

use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use sandbox_runtime::guard::protocol::{Reply, Request, call};
use sandbox_runtime::guard_probe::{GuardSourceState, GuardStatus};

use super::paths::Paths;
use super::{GuardConfig, InstallArgs, UninstallArgs, preflight, tools};
use crate::output;

pub const UNIT_TEMPLATE: &str = include_str!("../../../examples/wssp-guard.service");

const BLOCKLIST_HEADER: &str = "\
# wssp egress guard: node operator blocklist. Root-owned; edit with sudoedit.
# One IPv4 CIDR (or address) or domain per line; `#` starts a comment.
# CIDRs apply live to every running sandbox and cut established flows.
# Domains apply to sandboxes created afterwards (best effort, DNS only).
# Limits: 1 MiB, 4096 CIDRs, 2048 domains. Any invalid line rejects the whole
# file and the last valid list stays enforced; new sandboxes are refused
# until it is fixed. Deleting this file is not a clear: leave it without
# entries to block nothing.
";

#[derive(Debug)]
pub struct InstallPlan {
    pub paths: Paths,
    /// Owner every directory component must have: root (0) for the live
    /// install; the test user under `--root-prefix`.
    pub owner_uid: u32,
    pub config: GuardConfig,
    pub source_binary: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
pub struct InstallReport {
    pub created_blocklist: bool,
}

/// One component: a real directory (no symlink), owned by `owner`, not
/// group/world-writable.
fn check_component(path: &Path, owner: u32) -> Result<()> {
    let meta = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspecting `{}`", path.display()))?;
    if meta.file_type().is_symlink() {
        bail!(
            "`{}` is a symlink; the guard installs only under real root-owned directories",
            path.display()
        );
    }
    sandbox_runtime::guard::sources::check_root_owned(
        &format!("`{}`", path.display()),
        meta.uid(),
        meta.mode(),
        owner,
        meta.file_type().is_dir(),
    )
    .map_err(anyhow::Error::msg)
}

/// Prove `dir` root-controlled: `root` and every component below it are
/// checked in order; a missing component is created (0755, one level at a
/// time, inside an already-proven parent) and then checked like the rest.
fn secure_dir(root: &Path, dir: &Path, owner: u32) -> Result<()> {
    let relative = dir
        .strip_prefix(root)
        .with_context(|| format!("`{}` is outside `{}`", dir.display(), root.display()))?;
    let mut current = root.to_path_buf();
    check_component(&current, owner)?;
    for part in relative.components() {
        let std::path::Component::Normal(name) = part else {
            bail!("unexpected component in `{}`", dir.display());
        };
        current.push(name);
        match std::fs::symlink_metadata(&current) {
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                use std::os::unix::fs::DirBuilderExt as _;
                std::fs::DirBuilder::new()
                    .mode(0o755)
                    .create(&current)
                    .with_context(|| format!("creating `{}`", current.display()))?;
                // Exactly 0755 whatever the umask; it is our new directory
                // in a parent nobody else can write.
                std::fs::set_permissions(&current, std::fs::Permissions::from_mode(0o755))
                    .with_context(|| format!("setting the mode of `{}`", current.display()))?;
            }
            Err(err) => {
                return Err(err).with_context(|| format!("inspecting `{}`", current.display()));
            }
        }
        check_component(&current, owner)?;
    }
    Ok(())
}

fn sync_dir(path: &Path) -> Result<()> {
    std::fs::File::open(path)
        .and_then(|dir| dir.sync_all())
        .with_context(|| format!("syncing `{}`", path.display()))
}

/// temp + fsync + rename + fsync(dir).
fn write_replace(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let dir = path.parent().context("path has no directory")?;
    let tmp = path.with_extension("new");
    let _ = std::fs::remove_file(&tmp);
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .with_context(|| format!("creating `{}`", tmp.display()))?;
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("replacing `{}`", path.display()))?;
    sync_dir(dir)
}

fn copy_binary(source: &Path, target: &Path) -> Result<()> {
    let meta = std::fs::metadata(source)
        .with_context(|| format!("cannot read the running binary `{}`", source.display()))?;
    if !meta.is_file() {
        bail!("`{}` is not a regular file", source.display());
    }
    let mut input = std::fs::File::open(source)
        .with_context(|| format!("cannot read the running binary `{}`", source.display()))?;
    let dir = target.parent().context("binary path has no directory")?;
    let tmp = target.with_extension("new");
    let _ = std::fs::remove_file(&tmp);
    {
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .with_context(|| format!("creating `{}`", tmp.display()))?;
        out.set_permissions(std::fs::Permissions::from_mode(0o755))?;
        std::io::copy(&mut input, &mut out).context("copying the guard binary")?;
        out.sync_all()?;
    }
    std::fs::rename(&tmp, target).with_context(|| format!("installing `{}`", target.display()))?;
    sync_dir(dir)
}

/// Write every installed file. Pure filesystem work (no systemctl), so the
/// `--root-prefix` unit test covers it.
pub fn install_files(plan: &InstallPlan) -> Result<InstallReport> {
    let paths = &plan.paths;
    let unit = paths.unit();
    let unit_dir = unit.parent().context("unit path has no directory")?;
    // Prove every target directory before writing anything.
    for dir in [
        paths.install_dir(),
        paths.config_dir(),
        unit_dir.to_path_buf(),
    ] {
        secure_dir(paths.root(), &dir, plan.owner_uid)?;
    }
    copy_binary(&plan.source_binary, &paths.binary())?;
    write_replace(&paths.config(), plan.config.render()?.as_bytes(), 0o644)?;
    let blocklist = paths.root_blocklist();
    let created_blocklist = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&blocklist)
    {
        Ok(mut file) => {
            file.set_permissions(std::fs::Permissions::from_mode(0o644))?;
            file.write_all(BLOCKLIST_HEADER.as_bytes())?;
            file.sync_all()?;
            sync_dir(&paths.config_dir())?;
            true
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(err) => {
            return Err(err).with_context(|| format!("creating `{}`", blocklist.display()));
        }
    };
    write_replace(&unit, UNIT_TEMPLATE.as_bytes(), 0o644)?;
    Ok(InstallReport { created_blocklist })
}

/// Remove the binary, unit and config; keep the root blocklist and state.
pub fn uninstall_files(paths: &Paths) -> Result<Vec<PathBuf>> {
    let mut removed = Vec::new();
    for path in [paths.unit(), paths.binary(), paths.config()] {
        match std::fs::remove_file(&path) {
            Ok(()) => removed.push(path),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err).with_context(|| format!("removing `{}`", path.display())),
        }
    }
    Ok(removed)
}

fn systemctl(args: &[&str]) -> Result<tools::ToolOutput> {
    tools::run("systemctl", args, None, Duration::from_secs(90))
}

fn systemctl_ok(args: &[&str]) -> Result<()> {
    let output = systemctl(args)?;
    if !output.success {
        bail!(
            "`systemctl {}` failed: {}",
            args.join(" "),
            output.stderr_line()
        );
    }
    Ok(())
}

fn current_status(paths: &Paths) -> Option<GuardStatus> {
    match call(&paths.socket(), &Request::Status {}, Duration::from_secs(2)) {
        Ok(Reply::Status { status }) => Some(*status),
        _ => None,
    }
}

fn require_root(command: &str) -> Result<()> {
    if !preflight::is_root() {
        bail!(
            "`wssp guard {command}` must run as root; run: sudo {} guard {command} …",
            std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "wssp".into())
        );
    }
    Ok(())
}

pub fn run_install(args: &InstallArgs) -> Result<()> {
    let source_binary = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .context("cannot locate the running binary")?;
    let Some(prefix) = &args.root_prefix else {
        return install_live(args, source_binary);
    };
    let config = GuardConfig {
        daemon_user: args.daemon_user.clone(),
        daemon_uid: lookup_uid(&args.daemon_user)?,
    };
    let report = install_files(&InstallPlan {
        paths: Paths::under(prefix),
        owner_uid: preflight::process_identity()?.0,
        config,
        source_binary,
    })?;
    output::line(format!(
        "installed the guard files under `{}`{}",
        prefix.display(),
        if report.created_blocklist {
            " (created an empty egress-blocklist)"
        } else {
            ""
        }
    ))
}

fn lookup_uid(user: &str) -> Result<u32> {
    let uid = sandbox_runtime::guard::lookup_user_uid(user)
        .with_context(|| format!("looking up user `{user}`"))?
        .with_context(|| format!("no such user `{user}`"))?;
    if uid == 0 {
        bail!("the daemon user must not be root");
    }
    Ok(uid)
}

/// The install's step log (E1-C-01): each step is announced on stderr, and
/// a failure names the step it stopped at and the steps already done, so a
/// partial install is never silent. Re-running the install is always safe.
pub struct Steps {
    done: Vec<String>,
    say: Box<dyn FnMut(String)>,
}

impl Steps {
    pub fn new(say: Box<dyn FnMut(String)>) -> Self {
        Self {
            done: Vec::new(),
            say,
        }
    }

    pub fn run<T>(&mut self, name: &str, step: impl FnOnce() -> Result<T>) -> Result<T> {
        (self.say)(format!("guard install: {name}"));
        match step() {
            Ok(value) => {
                self.done.push(name.to_string());
                Ok(value)
            }
            Err(err) => Err(err.context(format!(
                "`wssp guard install` stopped at step `{name}`{}; fix the cause above and re-run \
                 the same command (it is safe to re-run)",
                if self.done.is_empty() {
                    " before changing anything".to_string()
                } else {
                    format!(" after: {}", self.done.join(", "))
                }
            ))),
        }
    }
}

/// `systemctl is-enabled` / `is-active` must read `enabled` / `active`.
pub fn check_unit_state(enabled: &str, active: &str) -> Result<()> {
    let unit = sandbox_runtime::guard::UNIT_NAME;
    if enabled.trim() != "enabled" {
        bail!("`{unit}` is `{}`, not enabled", enabled.trim());
    }
    if active.trim() != "active" {
        bail!(
            "`{unit}` is `{}`, not active; check `journalctl -u {unit}`",
            active.trim()
        );
    }
    Ok(())
}

fn systemctl_state(verb: &str) -> Result<String> {
    let output = systemctl(&[verb, sandbox_runtime::guard::UNIT_NAME])?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// A dropped terminal or remote session (SIGHUP) must not stop the install
/// half way: the handler only records the signal.
fn survive_hangup() {
    let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    if let Err(err) = signal_hook::flag::register(signal_hook::consts::SIGHUP, flag) {
        tracing::warn!(error = %err, "cannot ignore SIGHUP during the install");
    }
}

fn configure_firewall(args: &InstallArgs, steps: &mut Steps) -> Result<()> {
    let host = super::firewall::Host::system();
    let mut say = |line: String| {
        let _ = output::line(line);
    };
    if args.configure_ufw {
        steps.run("configure ufw for the sandbox bridges", || {
            super::firewall::configure_ufw(&host, args.credential_proxy_port, &mut say)
        })?;
    }
    if args.configure_firewalld {
        steps.run("configure firewalld for the sandbox bridges", || {
            super::firewall::configure_firewalld(&host, args.credential_proxy_port, &mut say)
        })?;
    }
    Ok(())
}

fn has_host_firewall_reason(status: &GuardStatus) -> bool {
    status.reasons.iter().any(|reason| {
        reason.split(':').next() == Some(sandbox_runtime::guard::path::HOST_FIREWALL_REASON)
    })
}

fn install_live(args: &InstallArgs, source_binary: PathBuf) -> Result<()> {
    require_root("install")?;
    survive_hangup();
    let paths = Paths::system();
    let unit = sandbox_runtime::guard::UNIT_NAME;
    let config = GuardConfig {
        daemon_user: args.daemon_user.clone(),
        daemon_uid: lookup_uid(&args.daemon_user)?,
    };
    let mut steps = Steps::new(Box::new(|line| {
        let _ = output::diagnostic(line);
    }));
    let before = current_status(&paths).map(|s| s.instance_id);
    let report = steps.run("write the binary, config and unit", || {
        let report = install_files(&InstallPlan {
            paths: paths.clone(),
            owner_uid: 0,
            config,
            source_binary,
        })?;
        preflight::check_root_path(&paths.config_dir(), true)?;
        preflight::check_root_path(&paths.config(), false)?;
        Ok(report)
    })?;
    if report.created_blocklist {
        output::line("created an empty /etc/wssp/egress-blocklist")?;
    }
    configure_firewall(args, &mut steps)?;
    steps.run("systemctl daemon-reload", || {
        systemctl_ok(&["daemon-reload"])
    })?;
    let active = systemctl(&["is-active", "--quiet", unit])?.success;
    steps.run(&format!("enable {unit}"), || {
        systemctl_ok(&["enable", unit])
    })?;
    if active {
        steps.run(&format!("restart {unit}"), || {
            systemctl_ok(&["restart", unit])
        })?;
    } else {
        steps.run(&format!("start {unit}"), || systemctl_ok(&["start", unit]))?;
    }
    steps.run(&format!("verify {unit} is enabled and active"), || {
        check_unit_state(
            &systemctl_state("is-enabled")?,
            &systemctl_state("is-active")?,
        )
    })?;
    let status = steps.run("wait for the guard's first resync", || {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            // The new instance's first resync: a healthy one (generation 1)
            // or a quarantine.
            if let Some(status) = current_status(&paths)
                && before.as_deref() != Some(status.instance_id.as_str())
                && (status.generation >= 1 || status.quarantined.is_some())
            {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                bail!(
                    "the egress guard did not report a first resync within 20 s; check `journalctl -u {unit}`"
                );
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    })?;
    // Both a first install and an UPGRADE start with no deployment list in
    // the new guard instance until the daemon re-pushes it (about a second
    // later): wait for that, not just the first resync (E1-C-02, E2-C-01).
    let status = if awaits_push(&status) {
        output::line(format!(
            "guard: running; waiting for the daemon to push its deployment blocklist (up to {} s)...",
            PUSH_WAIT.as_secs()
        ))?;
        match wait_for_push(
            &mut || current_status(&paths),
            &status.instance_id,
            PUSH_WAIT,
            Duration::from_millis(250),
        ) {
            Some(pushed) => pushed,
            None => {
                if has_host_firewall_reason(&status) {
                    output::warning(sandbox_runtime::guard::path::HOST_FIREWALL_FIX)?;
                }
                return output::line(PUSH_TIMEOUT_HINT);
            }
        }
    } else {
        status
    };
    super::status::print_text(&status, "socket")?;
    if has_host_firewall_reason(&status) {
        output::warning(sandbox_runtime::guard::path::HOST_FIREWALL_FIX)?;
        return Ok(());
    }
    if status.quarantined.is_some() {
        bail!("the egress guard started but is quarantined; see the reasons above");
    }
    if super::status::is_healthy(&status) {
        output::line("guard healthy")?;
    }
    Ok(())
}

/// How long install waits for the daemon's deployment push.
const PUSH_WAIT: Duration = Duration::from_secs(15);

const PUSH_TIMEOUT_HINT: &str = "the guard is installed and holds sandbox forwarding until the daemon's \
     deployment push; start or restart `wssp connect`, then check `wssp guard status`";

/// The deployment source is settled: pushed (valid) or deliberately empty.
fn deployment_settled(status: &GuardStatus) -> bool {
    matches!(
        status.sources.deployment.state,
        GuardSourceState::Valid | GuardSourceState::NotConfigured
    )
}

/// The new instance is only waiting for the daemon: no deployment list yet
/// and no other reason to be quarantined.
fn awaits_push(status: &GuardStatus) -> bool {
    !deployment_settled(status)
        && matches!(
            status.quarantined.as_deref(),
            None | Some(AWAITING_DEPLOYMENT)
        )
}

/// After the first resync, wait until this instance's deployment source is
/// valid or not_configured and the deployment quarantine is lifted (a
/// running daemon pushes within about a second of a new guard instance).
fn wait_for_push(
    fetch: &mut dyn FnMut() -> Option<GuardStatus>,
    instance: &str,
    budget: Duration,
    poll: Duration,
) -> Option<GuardStatus> {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if let Some(status) = fetch()
            && status.instance_id == instance
            && status.quarantined.as_deref() != Some(AWAITING_DEPLOYMENT)
            && deployment_settled(&status)
        {
            return Some(status);
        }
        std::thread::sleep(poll);
    }
    None
}

/// The guard's quarantine while its first push is outstanding.
const AWAITING_DEPLOYMENT: &str = "source_unusable:deployment";

/// What `uninstall` established before removing anything.
#[derive(Debug, PartialEq, Eq)]
pub enum TableState {
    /// The table is loaded and `live_bridges` read back empty.
    Quarantined,
    /// No `inet wssp_guard` table is loaded.
    Absent,
}

/// Uninstall order: confirmed stop, then a verified quarantine, and only
/// then are files removed. Any failure leaves every file in place.
pub fn uninstall_with(
    paths: &Paths,
    stop: impl FnOnce() -> Result<()>,
    quarantine: impl FnOnce() -> Result<TableState>,
) -> Result<(Vec<PathBuf>, TableState)> {
    stop().context("the guard service was not confirmed stopped; nothing was removed")?;
    let table = quarantine()
        .context("the guard table was not confirmed quarantined; nothing was removed")?;
    Ok((uninstall_files(paths)?, table))
}

/// `systemctl is-active` states in which the process is gone.
fn stopped_state(state: &str) -> bool {
    matches!(state, "inactive" | "failed" | "unknown")
}

fn stop_service(paths: &Paths) -> Result<()> {
    let unit = sandbox_runtime::guard::UNIT_NAME;
    let disable = systemctl(&["disable", "--now", unit])?;
    let state = systemctl(&["is-active", unit])?;
    let state = String::from_utf8_lossy(&state.stdout).trim().to_string();
    if !stopped_state(&state) {
        bail!("`{unit}` is still `{state}`; stop it with `sudo systemctl stop {unit}` and re-run");
    }
    // Stopped but still enabled would start again on boot (unless the
    // unit file is already gone).
    if !disable.success && paths.unit().exists() {
        bail!(
            "`systemctl disable --now {unit}` failed: {}",
            disable.stderr_line()
        );
    }
    Ok(())
}

/// `live_bridges` has no element in an `nft -j list set` listing.
pub fn live_bridges_empty(listing: &serde_json::Value) -> Result<bool> {
    let set = listing["nftables"]
        .as_array()
        .context("set listing has no `nftables` array")?
        .iter()
        .find_map(|item| item.get("set"))
        .filter(|set| {
            set["name"] == "live_bridges" && set["table"] == sandbox_runtime::guard::TABLE
        })
        .context("the listing has no `live_bridges` set")?;
    Ok(match set.get("elem") {
        None => true,
        Some(serde_json::Value::Array(items)) => items.is_empty(),
        Some(_) => false,
    })
}

/// With the service stopped nothing renews the dead-man; cut forwarding
/// now instead of after its 30 s timeout, and read the set back.
fn quarantine_table() -> Result<TableState> {
    let table = sandbox_runtime::guard::TABLE;
    let present = tools::run(
        "nft",
        &["list", "table", "inet", table],
        None,
        sandbox_runtime::guard::CHILD_TIMEOUT,
    )?;
    if !present.success {
        if present.stderr_line().contains("No such file or directory") {
            return Ok(TableState::Absent);
        }
        bail!("cannot list `inet {table}`: {}", present.stderr_line());
    }
    let flush = tools::run(
        "nft",
        &["flush", "set", "inet", table, "live_bridges"],
        None,
        sandbox_runtime::guard::CHILD_TIMEOUT,
    )?;
    if !flush.success {
        bail!("cannot flush `live_bridges`: {}", flush.stderr_line());
    }
    let listing = tools::json(
        "nft",
        &["-j", "list", "set", "inet", table, "live_bridges"],
        sandbox_runtime::guard::CHILD_TIMEOUT,
    )?;
    if !live_bridges_empty(&listing)? {
        bail!("`live_bridges` still has elements after the flush");
    }
    Ok(TableState::Quarantined)
}

pub fn run_uninstall(args: &UninstallArgs) -> Result<()> {
    if let Some(prefix) = &args.root_prefix {
        let removed = uninstall_files(&Paths::under(prefix))?;
        return output::line(format!("removed {} guard files", removed.len()));
    }
    require_root("uninstall")?;
    let paths = Paths::system();
    let (removed, table) = uninstall_with(&paths, || stop_service(&paths), quarantine_table)?;
    systemctl_ok(&["daemon-reload"])?;
    let host = super::firewall::Host::system();
    let mut say = |line: String| {
        let _ = output::line(line);
    };
    if args.configure_ufw {
        let count = super::firewall::remove_ufw(&host, &mut say)?;
        output::line(format!("removed {count} wssp-guard managed ufw rules"))?;
    }
    if args.configure_firewalld {
        let count = super::firewall::remove_firewalld(&host, &mut say)?;
        output::line(format!(
            "removed {count} wssp-guard managed firewalld objects"
        ))?;
    }
    for path in removed {
        output::line(format!("removed `{}`", path.display()))?;
    }
    output::line(match table {
        TableState::Quarantined => {
            "stopped the guard and quarantined the `inet wssp_guard` table (verified): sandbox \
             forwarding on this node is cut now and this node takes no new sandboxes. Kept \
             /etc/wssp/egress-blocklist and /var/lib/wssp-guard. Once no sandboxes run here, remove \
             the table with: sudo nft delete table inet wssp_guard"
        }
        TableState::Absent => {
            "stopped the guard; no `inet wssp_guard` table was loaded, so nothing on this node \
             restricts sandbox traffic beyond the Incus ACLs, and this node takes no new sandboxes. \
             Kept /etc/wssp/egress-blocklist and /var/lib/wssp-guard."
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status_with(deployment: GuardSourceState) -> GuardStatus {
        let mut status = sandbox_runtime::guard_probe::FakeGuardProbe::healthy_status(&[]);
        status.sources.deployment.state = deployment;
        status
    }

    /// E2-C-01: on an upgrade the new instance's first resync has no
    /// deployment list; install waits for the daemon's push, not just that.
    #[test]
    fn install_waits_for_the_daemon_push_after_the_first_resync() {
        let unpushed = status_with(GuardSourceState::Unknown);
        assert!(awaits_push(&unpushed));
        assert!(!awaits_push(&status_with(GuardSourceState::Valid)));
        assert!(!awaits_push(&status_with(GuardSourceState::NotConfigured)));
        let mut other = status_with(GuardSourceState::Unknown);
        other.quarantined = Some("source_unusable:root".into());
        assert!(!awaits_push(&other));

        let mut polls = 0;
        let pushed = wait_for_push(
            &mut || {
                polls += 1;
                Some(status_with(if polls < 4 {
                    GuardSourceState::Unknown
                } else {
                    GuardSourceState::Valid
                }))
            },
            &unpushed.instance_id,
            Duration::from_secs(5),
            Duration::from_millis(1),
        )
        .expect("settles once the push lands");
        assert_eq!(polls, 4);
        assert!(deployment_settled(&pushed));
    }

    #[test]
    fn install_gives_up_waiting_when_the_daemon_never_pushes() {
        let unpushed = status_with(GuardSourceState::Unknown);
        let none = wait_for_push(
            &mut || Some(status_with(GuardSourceState::Unknown)),
            &unpushed.instance_id,
            Duration::from_millis(30),
            Duration::from_millis(1),
        );
        assert!(none.is_none());
        assert!(PUSH_TIMEOUT_HINT.contains("wssp connect"));
    }

    /// E1-C-01: a failed step names itself and what already happened.
    #[test]
    fn a_failed_install_step_names_where_it_stopped() {
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = log.clone();
        let mut steps = Steps::new(Box::new(move |line| sink.lock().unwrap().push(line)));
        steps
            .run("write the binary, config and unit", || Ok(()))
            .unwrap();
        steps.run("systemctl daemon-reload", || Ok(())).unwrap();
        let err = steps
            .run("enable wssp-guard.service", || -> Result<()> {
                bail!("`systemctl enable wssp-guard.service` failed: boom")
            })
            .unwrap_err();
        let text = format!("{err:#}");
        assert!(
            text.contains("stopped at step `enable wssp-guard.service` after: write the binary, config and unit, systemctl daemon-reload"),
            "{text}"
        );
        assert!(text.contains("boom"), "{text}");
        assert_eq!(log.lock().unwrap().len(), 3);
        let mut first = Steps::new(Box::new(|_| {}));
        let err = first
            .run("write the binary, config and unit", || -> Result<()> {
                bail!("denied")
            })
            .unwrap_err();
        assert!(format!("{err:#}").contains("before changing anything"));
    }

    #[test]
    fn the_install_requires_an_enabled_and_active_unit() {
        assert!(check_unit_state("enabled\n", "active\n").is_ok());
        let disabled = check_unit_state("disabled", "inactive").unwrap_err();
        assert!(format!("{disabled}").contains("not enabled"), "{disabled}");
        let inactive = check_unit_state("enabled", "failed").unwrap_err();
        assert!(format!("{inactive}").contains("not active"), "{inactive}");
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().mode() & 0o7777
    }

    #[test]
    fn install_under_root_prefix_writes_every_file() {
        let root = prefix();
        let source_dir = tempfile::tempdir().unwrap();
        let source = source_dir.path().join("wssp");
        std::fs::write(&source, b"#!binary v1").unwrap();
        let paths = Paths::under(root.path());
        let plan = InstallPlan {
            paths: paths.clone(),
            owner_uid: me(),
            config: GuardConfig {
                daemon_user: "tester".into(),
                daemon_uid: 4242,
            },
            source_binary: source.clone(),
        };
        assert_eq!(
            install_files(&plan).unwrap(),
            InstallReport {
                created_blocklist: true
            }
        );

        let binary = root.path().join("usr/local/lib/wssp/wssp-guard");
        assert_eq!(std::fs::read(&binary).unwrap(), b"#!binary v1");
        assert_eq!(mode(&binary), 0o755);
        assert!(!binary.with_extension("new").exists());
        assert_eq!(mode(&root.path().join("usr/local/lib/wssp")), 0o755);

        let config = root.path().join("etc/wssp/guard.toml");
        assert_eq!(mode(&config), 0o644);
        assert_eq!(
            GuardConfig::load(&config).unwrap(),
            GuardConfig {
                daemon_user: "tester".into(),
                daemon_uid: 4242
            }
        );
        assert_eq!(mode(&root.path().join("etc/wssp")), 0o755);

        let blocklist = root.path().join("etc/wssp/egress-blocklist");
        assert_eq!(mode(&blocklist), 0o644);
        let parsed =
            sandbox_runtime::guard::sources::parse_source(&std::fs::read(&blocklist).unwrap())
                .unwrap();
        assert!(parsed.is_empty(), "the created list must have no entries");

        let unit = root.path().join("etc/systemd/system/wssp-guard.service");
        assert_eq!(mode(&unit), 0o644);
        let text = std::fs::read_to_string(&unit).unwrap();
        assert!(text.contains("ExecStart=/usr/local/lib/wssp/wssp-guard guard run\n"));
        // Never the user-writable binary that ran install.
        assert!(!text.contains(source.to_str().unwrap()));
        assert!(!text.contains("%h") && !text.contains(".local/bin"));
        for line in [
            "User=root",
            "CapabilityBoundingSet=CAP_NET_ADMIN",
            "AmbientCapabilities=CAP_NET_ADMIN",
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "ReadOnlyPaths=/etc/wssp",
            "RuntimeDirectory=wssp-guard",
            "RuntimeDirectoryMode=0755",
            "RuntimeDirectoryPreserve=yes",
            "StateDirectory=wssp-guard",
            "StateDirectoryMode=0700",
            "RestrictAddressFamilies=AF_UNIX AF_NETLINK",
            "PrivateTmp=yes",
            "PrivateDevices=yes",
            "ProtectKernelModules=yes",
            "SystemCallFilter=@system-service",
            "Before=incus.service",
            "Restart=always",
            "RestartSec=1",
        ] {
            assert!(text.lines().any(|l| l == line), "unit lacks `{line}`");
        }

        // Operator edits survive a re-install (upgrade); the binary is replaced.
        std::fs::write(&blocklist, b"1.1.1.1\n").unwrap();
        std::fs::write(&source, b"#!binary v2").unwrap();
        let ino_before = std::fs::metadata(&binary).unwrap().ino();
        assert_eq!(
            install_files(&plan).unwrap(),
            InstallReport {
                created_blocklist: false
            }
        );
        assert_eq!(std::fs::read(&blocklist).unwrap(), b"1.1.1.1\n");
        assert_eq!(std::fs::read(&binary).unwrap(), b"#!binary v2");
        // Rename, not overwrite in place: a running guard keeps its inode.
        assert_ne!(std::fs::metadata(&binary).unwrap().ino(), ino_before);

        // Uninstall keeps the operator list.
        let removed = uninstall_files(&paths).unwrap();
        assert_eq!(removed.len(), 3);
        assert!(blocklist.exists());
        assert!(!binary.exists() && !unit.exists() && !config.exists());
    }

    #[test]
    fn install_refuses_an_unreadable_source_binary() {
        let root = prefix();
        let plan = InstallPlan {
            paths: Paths::under(root.path()),
            owner_uid: me(),
            config: GuardConfig {
                daemon_user: "tester".into(),
                daemon_uid: 4242,
            },
            source_binary: root.path().join("missing"),
        };
        assert!(install_files(&plan).is_err());
    }

    /// A test root that is itself acceptable (the temp dir may be created
    /// group/world-writable under this harness's umask).
    fn prefix() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        dir
    }

    /// Create `rel` under `base`, every level at 0755 (umask-proof).
    fn mkdirs(base: &Path, rel: &str) -> PathBuf {
        let mut path = base.to_path_buf();
        for part in rel.split('/') {
            path.push(part);
            if !path.exists() {
                std::fs::create_dir(&path).unwrap();
            }
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        path
    }

    fn me() -> u32 {
        preflight::process_identity().unwrap().0
    }

    fn plan_under(root: &Path, source: &Path) -> InstallPlan {
        InstallPlan {
            paths: Paths::under(root),
            owner_uid: me(),
            config: GuardConfig {
                daemon_user: "tester".into(),
                daemon_uid: 4242,
            },
            source_binary: source.to_path_buf(),
        }
    }

    fn source_binary() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("wssp");
        std::fs::write(&source, b"#!binary").unwrap();
        (dir, source)
    }

    /// Review P1-5: a symlink anywhere on the install path is refused before
    /// anything is written (it used to be followed).
    #[test]
    fn install_refuses_a_symlinked_install_dir() {
        let root = prefix();
        let (_src, source) = source_binary();
        let elsewhere = tempfile::tempdir().unwrap();
        mkdirs(root.path(), "usr/local/lib");
        std::os::unix::fs::symlink(elsewhere.path(), root.path().join("usr/local/lib/wssp"))
            .unwrap();
        let err = install_files(&plan_under(root.path(), &source)).unwrap_err();
        assert!(format!("{err:#}").contains("symlink"), "{err:#}");
        assert!(!elsewhere.path().join("wssp-guard").exists());

        // A symlinked ancestor as well.
        let root = prefix();
        mkdirs(elsewhere.path(), "lib");
        mkdirs(root.path(), "usr");
        std::os::unix::fs::symlink(elsewhere.path(), root.path().join("usr/local")).unwrap();
        assert!(install_files(&plan_under(root.path(), &source)).is_err());
        assert!(!elsewhere.path().join("lib/wssp").exists());
    }

    /// Review P1-5: a group/world-writable directory on the path is refused
    /// and left as it is (it used to be chmod-ed and reused).
    #[test]
    fn install_refuses_a_writable_dir_on_the_path() {
        let root = prefix();
        let (_src, source) = source_binary();
        let dir = mkdirs(root.path(), "usr/local/lib/wssp");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let err = install_files(&plan_under(root.path(), &source)).unwrap_err();
        let text = format!("{err:#}");
        assert!(
            text.contains("lib/wssp` is group- or world-writable"),
            "{text}"
        );
        assert_eq!(mode(&dir), 0o777);
        assert!(!dir.join("wssp-guard").exists());
    }

    /// Review P1-5: a directory owned by anyone but the expected owner (root
    /// in production) is refused, from the top component down.
    #[test]
    fn install_refuses_a_dir_owned_by_another_user() {
        let root = prefix();
        let (_src, source) = source_binary();
        let mut plan = plan_under(root.path(), &source);
        plan.owner_uid = me() + 1;
        let err = install_files(&plan).unwrap_err();
        assert!(format!("{err:#}").contains("not owned"), "{err:#}");
        assert!(!root.path().join("usr").exists(), "nothing written");
        // The live install demands root for `/`: a test user's tree fails.
        if me() != 0 {
            assert!(secure_dir(root.path(), root.path(), 0).is_err());
        }
    }

    /// Review P2-6: nothing is removed unless the stop AND the quarantine
    /// are confirmed.
    #[test]
    fn uninstall_removes_nothing_without_a_confirmed_stop_and_quarantine() {
        let root = prefix();
        let (_src, source) = source_binary();
        let plan = plan_under(root.path(), &source);
        install_files(&plan).unwrap();
        let binary = plan.paths.binary();

        let err =
            uninstall_with(&plan.paths, || bail!("still active"), || unreachable!()).unwrap_err();
        assert!(format!("{err:#}").contains("nothing was removed"));
        assert!(binary.exists());

        let err = uninstall_with(&plan.paths, || Ok(()), || bail!("flush failed")).unwrap_err();
        assert!(format!("{err:#}").contains("nothing was removed"));
        assert!(binary.exists());

        let (removed, table) =
            uninstall_with(&plan.paths, || Ok(()), || Ok(TableState::Quarantined)).unwrap();
        assert_eq!(removed.len(), 3);
        assert_eq!(table, TableState::Quarantined);
        assert!(!binary.exists());

        assert!(stopped_state("inactive") && stopped_state("failed"));
        assert!(!stopped_state("active") && !stopped_state("deactivating"));
    }

    #[test]
    fn live_bridges_readback() {
        let set = |elem: Option<serde_json::Value>| {
            let mut set = serde_json::json!({"family":"inet","name":"live_bridges","table":"wssp_guard","type":"ifname","flags":["timeout"]});
            if let Some(elem) = elem {
                set["elem"] = elem;
            }
            serde_json::json!({"nftables":[{"metainfo":{}},{"set":set}]})
        };
        assert!(live_bridges_empty(&set(None)).unwrap());
        assert!(live_bridges_empty(&set(Some(serde_json::json!([])))).unwrap());
        let live = serde_json::json!([{"elem":{"val":"wsn-a","timeout":30,"expires":29}}]);
        assert!(!live_bridges_empty(&set(Some(live))).unwrap());
        assert!(live_bridges_empty(&serde_json::json!({"nftables":[]})).is_err());
    }
}
