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
    /// Inspect the configuration file and resolved paths.
    Config(crate::commands::config::Args),

    /// Generate shell completion scripts.
    Completions(crate::commands::completions::Args),

    /// Device-code login for host enrollment.
    Login(crate::commands::login::Args),

    /// Clear stored device credentials and, best effort, any configured host token binding.
    Logout(crate::commands::logout::Args),

    /// Configure dashboard host token environment variables.
    Token(crate::commands::token::Args),

    /// Refuse new guest work on this host; running guests keep running.
    Drain(crate::commands::drain::Args),

    /// Restore admission on this host.
    Undrain(crate::commands::drain::Args),

    /// Inspect or prune the managed template image cache.
    Images(crate::commands::images::Args),

    /// Connect to the sandbox host relay and execute dispatched operations.
    Connect(crate::commands::connect::ConnectArgs),

    /// Manage the running node daemon (graceful restart for upgrades).
    #[cfg(target_os = "linux")]
    Daemon(crate::commands::daemon::Args),

    /// Root-owned egress guard: install, status and the service entry point.
    #[cfg(target_os = "linux")]
    Guard(crate::commands::guard::Args),
}
