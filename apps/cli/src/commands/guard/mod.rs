//! `wssp guard`: the root-owned egress guard (see
//! docs/guide/hosts.md#egress-guard). This is the only code in wssp that runs as root. It reads only
//! root-owned files and its `SO_PEERCRED`-checked socket, its nftables table
//! contains only drops, and the daemon can add or change only the deployment
//! source. Daemons never run `sudo`; they print the install command.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

mod daemon;
mod firewall;
mod install;
mod paths;
mod preflight;
mod status;
pub use paths::Paths;
pub use status::local_snapshot;
mod tools;

#[derive(Debug, clap::Args)]
pub struct Args {
    #[command(subcommand)]
    pub command: GuardCommand,
}

#[derive(Debug, clap::Subcommand)]
pub enum GuardCommand {
    /// Install or upgrade the egress guard system service (run with sudo).
    Install(InstallArgs),
    /// Remove the egress guard service (run with sudo); keeps /etc/wssp/egress-blocklist.
    Uninstall(UninstallArgs),
    /// Show the egress guard's health lease, policy sources and bridges.
    Status(StatusArgs),
    /// Service entry point, started by `wssp-guard.service` as root.
    Run,
}

#[derive(Debug, clap::Args)]
pub struct InstallArgs {
    /// Unprivileged user that runs `wssp connect`; only it may push the deployment blocklist.
    #[arg(long, value_name = "USER")]
    pub daemon_user: String,
    /// Also add the minimal ufw rules sandbox bridges need (DHCP, DNS, login proxy in; routing in and out), printing each one.
    #[arg(long, conflicts_with = "configure_firewalld")]
    pub configure_ufw: bool,
    /// Also add a minimal firewalld zone and policy for the sandbox bridges, printing each command.
    #[arg(long)]
    pub configure_firewalld: bool,
    /// The daemon's `credential_proxy_port`, opened by `--configure-ufw`/`--configure-firewalld`.
    #[arg(long, value_name = "PORT", default_value_t = 48080)]
    pub credential_proxy_port: u16,
    /// Test-only: write the files under this directory and skip systemctl.
    #[arg(long, hide = true, value_name = "DIR")]
    pub root_prefix: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
pub struct UninstallArgs {
    /// Also remove the ufw rules `install --configure-ufw` added (only those).
    #[arg(long, conflicts_with = "configure_firewalld")]
    pub configure_ufw: bool,
    /// Also remove the firewalld zone and policy `install --configure-firewalld` added.
    #[arg(long)]
    pub configure_firewalld: bool,
    /// Test-only: remove the files under this directory and skip systemctl.
    #[arg(long, hide = true, value_name = "DIR")]
    pub root_prefix: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
pub struct StatusArgs {
    /// Print the status as JSON.
    #[arg(long)]
    pub json: bool,
}

/// `/etc/wssp/guard.toml` (root:root 0644).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardConfig {
    pub daemon_user: String,
    pub daemon_uid: u32,
}

impl GuardConfig {
    pub fn render(&self) -> Result<String> {
        Ok(format!(
            "# Written by `wssp guard install`; re-run it to change the daemon user.\n{}",
            toml::to_string(self).context("rendering guard.toml")?
        ))
    }

    pub fn parse(text: &str) -> Result<Self> {
        let config: Self = toml::from_str(text).context("`guard.toml` is invalid")?;
        if config.daemon_uid == 0 {
            bail!("`guard.toml` names uid 0 as the daemon; the daemon must be unprivileged");
        }
        Ok(config)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading `{}`", path.display()))?;
        Self::parse(&text)
    }
}

pub fn run(args: &Args) -> Result<()> {
    match &args.command {
        GuardCommand::Install(args) => install::run_install(args),
        GuardCommand::Uninstall(args) => install::run_uninstall(args),
        GuardCommand::Status(args) => status::run(args),
        GuardCommand::Run => daemon::run(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_round_trip_and_refusals() {
        let config = GuardConfig {
            daemon_user: "chris".into(),
            daemon_uid: 1000,
        };
        let text = config.render().unwrap();
        assert_eq!(GuardConfig::parse(&text).unwrap(), config);
        // Quoting is TOML's job: a hostile name cannot add keys.
        let odd = GuardConfig {
            daemon_user: "a\"\ndaemon_uid = 0\n#".into(),
            daemon_uid: 1000,
        };
        assert_eq!(GuardConfig::parse(&odd.render().unwrap()).unwrap(), odd);
        assert!(GuardConfig::parse("daemon_user = \"root\"\ndaemon_uid = 0\n").is_err());
        assert!(GuardConfig::parse("daemon_user = \"x\"\ndaemon_uid = 1\nextra = 1\n").is_err());
    }
}
