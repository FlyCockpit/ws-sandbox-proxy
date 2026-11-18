//! `wssp host …`: everything that makes this machine a wssp host — enrollment,
//! the node daemon (`host run`) and the node-local settings and tools.

use anyhow::Result;

/// `about` for `wssp host` on a machine that is not enrolled.
pub const ABOUT_NOT_ENROLLED: &str = "Run this machine as a wssp host — not enrolled here";

/// After-help shown under `wssp host --help` on a machine that is not enrolled.
pub const NOT_ENROLLED_AFTER_HELP: &str = "This machine is not an enrolled host, so only `enroll` is listed (`wssp host --help --all` shows every host command). Hosts guide: https://github.com/FlyCockpit/ws-sandbox-proxy/blob/main/docs/guide/hosts.md";

/// Error for a `wssp host` command that needs an enrollment (exit 6).
pub const NOT_ENROLLED_HOST_MESSAGE: &str = "this device is not an enrolled host; run `wssp host enroll --slug <slug>` or `wssp host enroll --token-env <ENV>` (or pass `--host-token-env`)";

#[derive(Debug, clap::Args)]
pub struct Args {
    /// With `--help`: list every host subcommand, also on a machine that is not enrolled.
    #[arg(long)]
    pub all: bool,

    #[command(subcommand)]
    pub command: HostCommand,
}

#[derive(Debug, clap::Subcommand)]
pub enum HostCommand {
    /// Enroll this machine as a host: device login for a host slug, or a dashboard host token's environment variable.
    Enroll(crate::commands::enroll::Args),

    /// Run the node daemon: connect to the sandbox host relay and execute dispatched operations.
    Run(crate::commands::run::RunArgs),

    /// Clear the stored host device credential and, best effort, any configured host token binding.
    Logout(crate::commands::logout::Args),

    /// Refuse new guest work on this host; running guests keep running.
    Drain(crate::commands::drain::Args),

    /// Restore admission on this host.
    Undrain(crate::commands::drain::Args),

    /// Inspect or prune the managed template image cache.
    Images(crate::commands::images::Args),

    /// Inspect and change node settings, the configuration file and resolved paths.
    Config(crate::commands::config::Args),

    /// Manage the running node daemon (graceful restart for upgrades).
    #[cfg(target_os = "linux")]
    Daemon(crate::commands::daemon::Args),

    /// Root-owned egress guard: install, uninstall and status.
    #[cfg(target_os = "linux")]
    Guard(crate::commands::guard::Args),

    /// Preview tunnels: install, inspect or remove the pinned `tunnel` client.
    #[cfg(target_os = "linux")]
    Tunnel(crate::commands::tunnel::Args),
}

impl HostCommand {
    /// Whether this command may run on a machine that is not an enrolled host.
    ///
    /// Only the commands that dial the control plane with the saved host
    /// credential need an enrollment: `run`, `drain` and `undrain` without an
    /// explicit `--host-token-env` (which carries its own credential selection
    /// for that one invocation, as docs/guide/hosts.md documents).
    ///
    /// Everything else is node-local and stays callable:
    /// - `enroll` creates the enrollment.
    /// - `guard` runs as root, which has no enrollment state, and is installed
    ///   before the first enrollment.
    /// - `config` saves defaults (`set-server`, `set-ca-file`, egress consent)
    ///   that docs/guide/hosts.md sets before enrolling; `tunnel` likewise
    ///   only configures this node.
    /// - `daemon` and `images` talk to a daemon already running here, which
    ///   may have been started with an explicit `--host-token-env` and no
    ///   recorded selection (the service's `ExecReload` must keep working).
    /// - `logout` is idempotent local cleanup, also of a half-finished enrollment.
    pub fn allowed_without_enrollment(&self) -> bool {
        match self {
            Self::Run(args) => args.host_token_env.is_some(),
            Self::Drain(args) | Self::Undrain(args) => args.host_token_env.is_some(),
            Self::Enroll(_) | Self::Config(_) | Self::Logout(_) | Self::Images(_) => true,
            #[cfg(target_os = "linux")]
            Self::Guard(_) | Self::Daemon(_) | Self::Tunnel(_) => true,
        }
    }

    /// Whether this command touches the daemon user's host auth store.
    pub fn uses_auth_store(&self) -> bool {
        match self {
            // The guard runs as root under `ProtectHome=yes`: it never touches
            // the daemon user's auth store.
            #[cfg(target_os = "linux")]
            Self::Guard(_) => false,
            _ => true,
        }
    }
}

pub fn run(args: &Args) -> Result<()> {
    match &args.command {
        HostCommand::Enroll(args) => crate::commands::enroll::run(args),
        HostCommand::Run(args) => crate::commands::run::run(args),
        HostCommand::Logout(args) => crate::commands::logout::run(args),
        HostCommand::Drain(args) => crate::commands::drain::run(args, true),
        HostCommand::Undrain(args) => crate::commands::drain::run(args, false),
        HostCommand::Images(args) => crate::commands::images::run(args),
        HostCommand::Config(args) => crate::commands::config::run(args),
        #[cfg(target_os = "linux")]
        HostCommand::Daemon(args) => crate::commands::daemon::run(args),
        #[cfg(target_os = "linux")]
        HostCommand::Guard(args) => crate::commands::guard::run(args),
        #[cfg(target_os = "linux")]
        HostCommand::Tunnel(args) => crate::commands::tunnel::run(args),
    }
}
