//! Subcommand implementations.
//!
//! One module per subcommand. Each module exposes:
//!   - an `Args` struct (clap-derived) describing its flags/positionals, and
//!   - a `run(args: &Args) -> anyhow::Result<()>` function with the logic.
//!
//! `src/cli.rs` wires the `Args` into the top-level `Command` enum; `main.rs`
//! calls `run`. To add a command, copy an existing command module, then
//! register it in both places.

pub mod completions;
pub mod config;
#[cfg(target_os = "linux")]
pub mod daemon;
pub mod drain;
pub mod enroll;
#[cfg(target_os = "linux")]
pub mod guard;
pub mod host;
pub mod images;
pub mod login;
pub mod logout;
pub mod run;
pub mod sandbox;
pub mod template;
#[cfg(target_os = "linux")]
pub mod tunnel;
pub mod user_logout;
pub mod whoami;
