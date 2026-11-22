//! Project automation for the CLI workspace.
//!
//! Run via the `cargo xtask` alias (see `.cargo/config.toml`):
//!
//!   cargo xtask sync-docs         # regenerate harness mirrors
//!   cargo xtask sync-docs --check # CI: fail on drift
//!   cargo xtask vendored-russh --check # CI: third_party/russh-0.65.4 is the crate plus its patch, in use
//!   cargo xtask vendored-russh --advisories # CI: RustSec advisories cargo-deny cannot see
//!   cargo xtask vendored-russh --update <version> # move the vendored copy (third_party/README.md)
//!
//! Written in Rust (not bash) so it behaves identically on every platform and
//! needs no tools beyond cargo.

mod sync;
mod vendored;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "xtask", about = "Project automation tasks")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Regenerate harness-specific docs (CLAUDE.md, .cursorrules) from AGENTS.md.
    SyncDocs(sync::Args),
    /// Check, audit or upgrade the vendored `third_party/russh-0.65.4`.
    VendoredRussh(vendored::Args),
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::SyncDocs(args) => sync::run(args),
        Command::VendoredRussh(args) => vendored::run(args),
    }
}

/// Locate the workspace root (the directory containing the root `Cargo.toml`
/// with a `[workspace]` table) by walking up from this crate.
fn workspace_root() -> std::path::PathBuf {
    // CARGO_MANIFEST_DIR for xtask is `<root>/xtask`; its parent is the root.
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask is always nested under the workspace root")
        .to_path_buf()
}
