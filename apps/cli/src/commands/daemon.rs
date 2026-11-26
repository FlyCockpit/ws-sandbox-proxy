//! `wssp host daemon quiesce`: the service's `ExecReload` (reconnect plan WP7).
//!
//! The *new* binary on disk decides how to restart the *running* daemon:
//!
//! - SIGUSR1 (a graceful quiesce: running commands finish, new ones wait in
//!   the server queue, then the daemon exits 0 and the service manager starts
//!   the new binary) only when the daemon's private control file
//!   `<data>/relay/<host>/daemon.json` names exactly that process (pid and
//!   start time) and lists the `quiesce` feature, and only through a pidfd
//!   opened before that check, so a recycled pid is never signalled. The
//!   file is opened with
//!   `O_NOFOLLOW` and must be a regular file owned by this user with no
//!   group or other permissions.
//! - Otherwise, under systemd (`$MAINPID` set), SIGTERM requests a graceful
//!   restart (`Restart=always` starts the new binary). Missing or unverifiable
//!   control state never authorizes SIGUSR1.
//! - Run by hand (`$MAINPID` unset) it needs `--pid`, and it sends nothing
//!   unless the control file verifies that pid: it never SIGTERMs a process
//!   it cannot identify as a wssp daemon.

use std::path::Path;

use anyhow::{Context, Result};

use crate::exit::{CodedError, ExitCode};
use crate::sandbox_relay::quiesce::{CONTROL_FILE, ControlFile, process_start_time};

#[derive(Debug, clap::Args)]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, clap::Subcommand)]
pub enum Command {
    /// Gracefully restart the running daemon: finish running commands (up to
    /// `quiesce_max`, default 10 minutes), then exit for the service manager
    /// to restart. Use as the service's `ExecReload`.
    Quiesce(QuiesceArgs),
}

#[derive(Debug, clap::Args)]
pub struct QuiesceArgs {
    /// The daemon's process id, when not run by systemd (`$MAINPID` unset).
    /// Only a daemon whose control file verifies this pid is signalled.
    #[arg(long, value_parser = clap::value_parser!(u32).range(2..))]
    pub pid: Option<u32>,
}

/// What `wssp host daemon quiesce` does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// SIGUSR1: the daemon quiesces, then restarts.
    Quiesce(u32),
    /// SIGTERM: today's graceful restart (systemd's main pid only).
    Terminate { pid: u32, reason: String },
    /// Send nothing.
    Refuse(String),
}

/// The process to signal: systemd's `$MAINPID`, else `--pid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target {
    pub pid: u32,
    /// Named by the service manager (`$MAINPID`): authoritative, so an
    /// unverified daemon may still get SIGTERM.
    pub managed: bool,
}

pub fn target(main_pid: Option<&str>, explicit: Option<u32>) -> Result<Target, String> {
    match (main_pid.filter(|v| !v.is_empty()), explicit) {
        (Some(main), explicit) => {
            let pid = main
                .parse::<u32>()
                .ok()
                .filter(|pid| *pid > 1)
                .ok_or_else(|| format!("`$MAINPID` is not a process id: `{main}`"))?;
            match explicit {
                Some(other) if other != pid => Err(format!(
                    "`--pid {other}` differs from the service's `$MAINPID` {pid}"
                )),
                _ => Ok(Target { pid, managed: true }),
            }
        }
        (None, Some(pid)) => Ok(Target {
            pid,
            managed: false,
        }),
        (None, None) => Err(
            "`$MAINPID` is not set: run this as the service's `ExecReload`, or pass `--pid`"
                .to_string(),
        ),
    }
}

/// Decide from the control file found for `target.pid` (or why none was
/// usable), that process's live start time, and whether a pidfd pins it
/// (without one SIGUSR1, whose default action kills, is never sent).
pub fn decide(
    target: Target,
    control: Result<Option<ControlFile>, String>,
    live_start_time: Option<u64>,
    pinned: bool,
) -> Decision {
    let refusal = match control {
        Ok(Some(file)) if file.pid != target.pid => {
            format!(
                "the control file names pid {}, not {}",
                file.pid, target.pid
            )
        }
        Ok(Some(file)) if !file.supports_quiesce() => {
            "the running daemon does not support quiescing".to_string()
        }
        Ok(Some(file)) if live_start_time != Some(file.start_time) => {
            format!(
                "pid {} is not the daemon that wrote the control file",
                target.pid
            )
        }
        Ok(Some(_)) if !pinned => {
            "this kernel cannot pin the process (no pidfd), so it is not sent SIGUSR1".to_string()
        }
        Ok(Some(_)) => return Decision::Quiesce(target.pid),
        Ok(None) => format!("no daemon control file names pid {}", target.pid),
        Err(reason) => reason,
    };
    if target.managed {
        Decision::Terminate {
            pid: target.pid,
            reason: refusal,
        }
    } else {
        Decision::Refuse(format!(
            "{refusal}; nothing sent (restart the service instead, e.g. `systemctl --user restart wssp-host`)"
        ))
    }
}

/// The largest control file read.
const CONTROL_MAX_BYTES: u64 = 4096;
/// Host state directories scanned for a control file.
const SCAN_LIMIT: usize = 1024;

/// Read one control file: no symlinks, a regular file owned by this user,
/// private (no group/other bits), small. `Ok(None)` when absent.
pub fn read_control(path: &Path) -> Result<Option<ControlFile>, String> {
    use rustix::fs::{Mode, OFlags};
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    let fd = match rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(rustix::io::Errno::LOOP) => {
            return Err(format!("`{}` is a symlink; refused", path.display()));
        }
        Err(error) => return Err(format!("cannot open `{}`: {error}", path.display())),
    };
    let mut file = std::fs::File::from(fd);
    let meta = file
        .metadata()
        .map_err(|error| format!("cannot inspect `{}`: {error}", path.display()))?;
    if !meta.is_file() {
        return Err(format!("`{}` is not a regular file", path.display()));
    }
    if meta.uid() != rustix::process::geteuid().as_raw() {
        return Err(format!("`{}` is owned by another user", path.display()));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(format!("`{}` is readable by others", path.display()));
    }
    if meta.len() > CONTROL_MAX_BYTES {
        return Err(format!("`{}` is too large", path.display()));
    }
    let mut text = Vec::new();
    file.by_ref()
        .take(CONTROL_MAX_BYTES)
        .read_to_end(&mut text)
        .map_err(|error| format!("cannot read `{}`: {error}", path.display()))?;
    serde_json::from_slice(&text)
        .map(Some)
        .map_err(|_| format!("`{}` is not a daemon control file", path.display()))
}

/// The control file naming `pid` under `<data>/relay/*/`, preferring the one
/// whose start time matches the live process (`start_time`): a stale file
/// from a crashed daemon whose pid was reused never hides the current one.
/// Otherwise any file naming the pid (the decision then explains the
/// mismatch). An unusable file cannot be told apart from a forged one, so
/// the first such reason is reported when no usable file names the pid.
pub fn find_control(
    relay_dir: &Path,
    pid: u32,
    start_time: Option<u64>,
) -> Result<Option<ControlFile>, String> {
    let entries = match std::fs::read_dir(relay_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("cannot list `{}`: {error}", relay_dir.display())),
    };
    let mut unusable = None;
    let mut stale = None;
    for entry in entries.take(SCAN_LIMIT).flatten() {
        match read_control(&entry.path().join(CONTROL_FILE)) {
            Ok(Some(file)) if file.pid == pid && Some(file.start_time) == start_time => {
                return Ok(Some(file));
            }
            Ok(Some(file)) if file.pid == pid => {
                stale.get_or_insert(file);
            }
            Ok(_) => {}
            Err(reason) => {
                unusable.get_or_insert(reason);
            }
        }
    }
    match (stale, unusable) {
        (Some(file), _) => Ok(Some(file)),
        (None, Some(reason)) => Err(reason),
        (None, None) => Ok(None),
    }
}

pub fn run(args: &Args) -> Result<()> {
    match &args.command {
        Command::Quiesce(args) => quiesce(args),
    }
}

fn quiesce(args: &QuiesceArgs) -> Result<()> {
    let main_pid = std::env::var("MAINPID").ok();
    let target = target(main_pid.as_deref(), args.pid)
        .map_err(anyhow::Error::msg)
        .context(CodedError::new(ExitCode::Failure))?;
    let relay_dir = crate::paths::data_dir()?.join("relay");
    // Pin the process first: everything verified below is about the process
    // this pidfd names, and every signal goes through it.
    let process = Process::pin(target.pid)?;
    let live = process_start_time(target.pid);
    let decision = decide(
        target,
        find_control(&relay_dir, target.pid, live),
        live,
        process.pinned(),
    );
    match decision {
        Decision::Quiesce(pid) => {
            process.signal(rustix::process::Signal::USR1)?;
            crate::output::line(format!(
                "daemon {pid}: quiescing; it restarts once running commands finish"
            ))
        }
        Decision::Terminate { pid, reason } => {
            tracing::warn!("{reason}; restarting it with SIGTERM");
            process.signal(rustix::process::Signal::TERM)?;
            crate::output::line(format!(
                "daemon {pid}: restarting now (it cannot quiesce: {reason})"
            ))
        }
        Decision::Refuse(reason) => Err(anyhow::anyhow!("{reason}")),
    }
}

/// The target process, pinned by a pidfd where the kernel has them.
struct Process {
    pid: rustix::process::Pid,
    pidfd: Option<std::os::fd::OwnedFd>,
}

impl Process {
    fn pin(pid: u32) -> Result<Self> {
        let raw = i32::try_from(pid).context("process id out of range")?;
        let pid = rustix::process::Pid::from_raw(raw).context("invalid process id")?;
        let pidfd = match rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()) {
            Ok(fd) => Some(fd),
            Err(rustix::io::Errno::SRCH) => anyhow::bail!("no process {raw} is running"),
            // No pidfd support (Linux before 5.3, or a filter): only the
            // service manager's own pid may be signalled, and only SIGTERM.
            Err(_) => None,
        };
        Ok(Self { pid, pidfd })
    }

    fn pinned(&self) -> bool {
        self.pidfd.is_some()
    }

    /// Through the pidfd; a numeric kill only without one (`decide` allows
    /// that for SIGTERM to `$MAINPID` alone).
    fn signal(&self, signal: rustix::process::Signal) -> Result<()> {
        match &self.pidfd {
            Some(fd) => rustix::process::pidfd_send_signal(fd, signal),
            None => rustix::process::kill_process(self.pid, signal),
        }
        .with_context(|| format!("signalling daemon {}", self.pid.as_raw_nonzero()))
    }
}

#[cfg(test)]
#[path = "daemon_tests.rs"]
mod tests;
