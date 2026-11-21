//! `wssp ssh` and `wssp ssh-config`: plain OpenSSH (`ssh`, `scp`, `sftp`,
//! `rsync`, VS Code Remote-SSH, JetBrains Gateway) into a sandbox without
//! any user-managed SSH key or password.
//!
//! - `wssp ssh --stdio <name-or-id>.wssp` is the `ProxyCommand`: it opens one
//!   `wssp.connect.v1` connection with the wssp login and speaks SSH on its
//!   own stdin and stdout ([`server`]), mapping each SSH channel to a wssp
//!   channel ([`mapping`]). It never listens on any socket.
//! - `wssp ssh <sandbox> [-- SSH-ARGS…]` runs the system `ssh` with the
//!   options of the generated config, so it needs no config at all.
//! - `wssp ssh-config [--install] [--rotate-host-key] [--json]` prints (or
//!   installs) the `Host *.wssp` block and keeps the local host key and its
//!   known_hosts entry ([`config`]).
//!
//! The SSH here ends in this local process: the wssp server and the node
//! carry the bytes in plaintext to the guest, as for browser terminals. A
//! revoked login ends the connection, the process exits, and ssh sees its
//! ProxyCommand's stdio close (exit 255).

mod bridge;
mod config;
mod input;
mod mapping;
mod server;

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Serialize;

use super::segment;
use super::shell::{Purpose, wssp_side};
use crate::exit::{CodedError, ExitCode};
use crate::output;

#[derive(Debug, clap::Args)]
pub struct SshArgs {
    /// Speak SSH on stdin and stdout (the `ProxyCommand` of the generated config).
    #[arg(long)]
    pub stdio: bool,

    /// Sandbox id or name (with `--stdio` also `<name-or-id>.wssp`).
    #[arg(value_name = "SANDBOX")]
    pub target: String,

    /// Arguments for `ssh` after `--` (options, then the remote command).
    #[arg(last = true, value_name = "SSH-ARGS", conflicts_with = "stdio")]
    pub ssh_args: Vec<String>,
}

#[derive(Debug, clap::Args)]
pub struct SshConfigArgs {
    /// Write `~/.ssh/config.d/wssp` and add `Include config.d/wssp` at the top of `~/.ssh/config` (asks first).
    #[arg(long)]
    pub install: bool,

    /// With `--install`: edit `~/.ssh/config` without asking.
    #[arg(long, requires = "install")]
    pub yes: bool,

    /// Replace the local ssh host key and its known_hosts entry.
    #[arg(long)]
    pub rotate_host_key: bool,

    /// Emit JSON instead of human-readable text.
    #[arg(long)]
    pub json: bool,
}

/// `wssp ssh`.
pub fn ssh(args: &SshArgs) -> Result<()> {
    if args.stdio {
        stdio(args)
    } else {
        system_ssh(args)
    }
}

/// The ProxyCommand endpoint. Failures before the SSH session starts leave
/// one line on stderr, which ssh shows.
fn stdio(args: &SshArgs) -> Result<()> {
    hand_run_hint();
    let sandbox = segment(mapping::sandbox_of(&args.target))?.to_owned();
    let credential = crate::user_state::require_credential()?;
    let key = config::host_key(false)?;
    if key.created {
        // Before the session: ssh shows this line if its host key check fails.
        let _ = output::warning(config::new_key_hint(&key));
    }
    let connection =
        super::shell::connect(&credential, &sandbox, Purpose::Ssh).map_err(wssp_side)?;
    server::serve(connection, key.key)
}

/// Run by hand on a terminal, `--stdio` would just wait speaking SSH: one
/// line on stderr says what it is for (before any session, so it never
/// competes with the SSH transport).
fn hand_run_hint() {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        let _ = output::warning(
            "`wssp ssh --stdio` speaks SSH on stdin and stdout for ssh's ProxyCommand; \
             run `ssh <name-or-id>.wssp` or `wssp ssh <name-or-id>` instead (Ctrl-C to stop)",
        );
    }
}

/// The first executable `name` on `PATH`.
fn find_program(name: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(name))
        .find(|candidate| {
            std::fs::metadata(candidate)
                .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        })
}

/// `exec` the system ssh with the generated config's options.
fn system_ssh(args: &SshArgs) -> Result<()> {
    use std::os::unix::process::CommandExt;
    let sandbox = segment(mapping::sandbox_of(&args.target))?.to_owned();
    let Some(ssh) = find_program("ssh") else {
        return Err(anyhow::anyhow!(
            "no `ssh` on `PATH`; install the OpenSSH client (for example the `openssh-client` package)"
        )
        .context(CodedError::new(ExitCode::Failure)));
    };
    let key = config::host_key(false)?;
    let exe = config::current_exe()?;
    // The user's own ssh keeps the user's environment (SSH_AUTH_SOCK, TERM,
    // HOME, ...); this user-facing site is pinned in `no_live_incus.rs`.
    let mut command = std::process::Command::new(&ssh);
    // Command-line options come first, so they win over any `Host *.wssp`
    // block of the user's own config.
    for (keyword, value) in config::options(&exe, &key.known_hosts)? {
        command.arg("-o").arg(format!("{keyword}={value}"));
    }
    command
        .arg(format!("{sandbox}{}", mapping::HOST_SUFFIX))
        .args(&args.ssh_args);
    let error = command.exec();
    Err(anyhow::Error::new(error)).with_context(|| format!("running `{}` failed", ssh.display()))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfigReport<'a> {
    config: &'a str,
    host_key_fingerprint: &'a str,
    /// The known_hosts line (`wssp ssh-ed25519 …`).
    known_hosts_entry: String,
    host_key_path: String,
    known_hosts_path: String,
    host_key_rotated: bool,
    installed: Option<InstallReport>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InstallReport {
    config_path: String,
    ssh_config_path: String,
    include_added: bool,
    /// The previous files this run replaced and where wssp kept each.
    backups: Vec<BackupReport>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BackupReport {
    path: String,
    backup_path: String,
}

/// Ask before `~/.ssh/config` changes (stdin and stderr must be terminals).
fn confirm(path: &std::path::Path, yes: bool, json: bool) -> Result<bool> {
    use std::io::{BufRead, IsTerminal, Write};
    if yes {
        return Ok(true);
    }
    if json || !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return Err(anyhow::anyhow!(
            "`--install` edits `{}`; pass `--yes` to do it without a prompt",
            path.display()
        )
        .context(CodedError::new(ExitCode::Usage)));
    }
    {
        let mut stderr = std::io::stderr().lock();
        write!(
            stderr,
            "Add `{}` at the top of `{}`? [y/N] ",
            config::INCLUDE_LINE,
            path.display()
        )
        .context("writing to stderr")?;
        stderr.flush().context("writing to stderr")?;
    }
    let mut answer = String::new();
    std::io::Read::take(std::io::stdin().lock(), 64)
        .read_line(&mut answer)
        .context("reading the answer")?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "Yes" | "YES"))
}

/// `wssp ssh-config`.
pub fn ssh_config(args: &SshConfigArgs) -> Result<()> {
    output::set_json_errors(args.json);
    let key = config::host_key(args.rotate_host_key)?;
    let exe = config::current_exe()?;
    let block = config::config_block(&exe, &key.known_hosts)?;
    let installed = if args.install {
        let home = config::ssh_home()?;
        let lock_dir = key
            .key_path
            .parent()
            .context("the ssh key has no directory")?;
        Some(config::install(&home, &block, lock_dir, |path| {
            confirm(path, args.yes, args.json)
        })?)
    } else {
        None
    };
    if args.json {
        return output::json(&ConfigReport {
            config: &block,
            host_key_fingerprint: &key.fingerprint,
            known_hosts_entry: config::known_hosts_line(&key.public).trim_end().to_owned(),
            host_key_path: key.key_path.display().to_string(),
            known_hosts_path: key.known_hosts.display().to_string(),
            host_key_rotated: args.rotate_host_key,
            installed: installed.map(|done| InstallReport {
                config_path: done.config_path.display().to_string(),
                ssh_config_path: done.ssh_config.display().to_string(),
                include_added: done.include_added,
                backups: done
                    .backups
                    .iter()
                    .map(|kept| BackupReport {
                        path: kept.file.display().to_string(),
                        backup_path: kept.backup.display().to_string(),
                    })
                    .collect(),
            }),
        });
    }
    if args.rotate_host_key {
        output::line(format!(
            "replaced the ssh host key ({}); running sessions keep the old one until they end",
            key.fingerprint
        ))?;
    }
    match installed {
        None => output::text(&block),
        Some(done) => {
            output::line(format!("wrote `{}`", done.config_path.display()))?;
            if done.include_added {
                output::line(format!(
                    "added `{}` at the top of `{}`",
                    config::INCLUDE_LINE,
                    done.ssh_config.display()
                ))?;
            } else {
                output::line(format!(
                    "`{}` already includes it",
                    done.ssh_config.display()
                ))?;
            }
            for kept in &done.backups {
                output::line(format!(
                    "kept the previous `{}` as `{}`; delete it when you no longer need it",
                    kept.file.display(),
                    kept.backup.display()
                ))?;
            }
            output::line("`ssh <name-or-id>.wssp`, `scp` and `rsync` now reach your sandboxes")
        }
    }
}
