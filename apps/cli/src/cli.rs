//! Command-line interface definition.
//!
//! All argument parsing lives here (clap derive). Each subcommand's *logic*
//! lives in its own file under `src/commands/` — this file only declares the
//! shape of the CLI. Keeping parsing and logic separate keeps both readable and
//! makes commands easy to test in isolation.

use clap::{Parser, Subcommand, ValueEnum};

/// Top-level CLI. The `about` text is shown in `--help`.
#[derive(Debug, Parser)]
#[command(
    name = env!("CARGO_PKG_NAME"),
    version,
    about = env!("CARGO_PKG_DESCRIPTION"),
    // Let every subcommand report the same package version.
    propagate_version = true
)]
pub struct Cli {
    /// How to format log output. `text` is human-friendly; `json` is for
    /// machines (pipe into `jq`, ship to a log collector, etc.).
    #[arg(long, value_enum, default_value_t = LogFormat::Text, global = true)]
    pub log_format: LogFormat,

    /// Increase log verbosity (-v = debug, -vv = trace). Overridden by the
    /// `WSSP_LOG` / `RUST_LOG` env var if set.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Silence all logs except errors.
    #[arg(short, long, global = true, conflicts_with = "verbose")]
    pub quiet: bool,

    #[command(subcommand)]
    pub command: Command,
}

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    /// Human-readable, colored when attached to a terminal.
    Text,
    /// One JSON object per line.
    Json,
}

/// The subcommands. Add new ones here, then implement them in `src/commands/`.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Log in to a wssp server as yourself (device flow; the browser chooses what this login may do).
    Login(crate::commands::login::Args),

    /// Revoke this machine's user login on the server and remove it here.
    Logout(crate::commands::user_logout::Args),

    /// Show the user login of this machine and what its key may do.
    Whoami(crate::commands::whoami::Args),

    /// Create, inspect, run commands in and manage sandboxes through the `/v1` API.
    Sandbox(crate::commands::sandbox::Args),

    /// List templates and their revisions.
    Template(crate::commands::template::Args),

    /// Open an ssh session to a sandbox with the system `ssh` (no keys); `--stdio` is the ProxyCommand endpoint.
    #[cfg(feature = "ssh")]
    Ssh(crate::commands::sandbox::ssh::SshArgs),

    /// Print or install the ssh config for `ssh <name>.wssp`, `scp` and `rsync`, and keep its local host key.
    #[cfg(feature = "ssh")]
    SshConfig(crate::commands::sandbox::ssh::SshConfigArgs),

    /// Run this machine as a wssp host: enroll, run the node daemon, manage node settings.
    Host(crate::commands::host::Args),

    /// Generate shell completion scripts.
    Completions(crate::commands::completions::Args),
}
