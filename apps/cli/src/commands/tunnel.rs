//! `wssp host tunnel`: install, inspect or remove the pinned preview-tunnel
//! client this node runs outside its sandboxes.

use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;

use crate::config::TunnelConfig;
use crate::output;
use crate::state::{load_config, update_config};

#[derive(Debug, clap::Args)]
pub struct Args {
    #[command(subcommand)]
    pub command: TunnelCommand,
}

#[derive(Debug, clap::Subcommand)]
pub enum TunnelCommand {
    /// Copy a `tunnel` client binary into wssp's data directory after
    /// checking its SHA-256, and enable preview tunnels (restart applies).
    Install(InstallArgs),
    /// Show the configured client and whether it still verifies.
    Status {
        /// Print JSON.
        #[arg(long)]
        json: bool,
    },
    /// Disable preview tunnels on this node (restart applies).
    Remove,
}

#[derive(Debug, clap::Args)]
pub struct InstallArgs {
    /// The client binary to install (a static `tunnel` build).
    #[arg(long)]
    pub file: PathBuf,
    /// Its expected SHA-256 (64 lowercase hex characters).
    #[arg(long)]
    pub sha256: String,
    /// Most tunnel clients at once (1..=256).
    #[arg(long, default_value_t = 16)]
    pub max_tunnels: u32,
    /// Let sandboxes from other users' pools use tunnels here.
    #[arg(long)]
    pub allow_for_others: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Status {
    configured: bool,
    client: Option<PathBuf>,
    client_sha256: Option<String>,
    verified: bool,
    max_tunnels: Option<u32>,
    allow_for_others: Option<bool>,
}

pub fn run(args: &Args) -> Result<()> {
    match &args.command {
        TunnelCommand::Install(install) => run_install(install),
        TunnelCommand::Status { json } => run_status(*json),
        TunnelCommand::Remove => {
            update_config(|config| {
                config.tunnel = None;
                Ok(())
            })?;
            output::text("preview tunnels disabled; restart the daemon to apply")
        }
    }
}

fn run_status(json: bool) -> Result<()> {
    let config = load_config()?;
    let status = match &config.tunnel {
        Some(tunnel) => Status {
            configured: true,
            client: Some(tunnel.client.clone()),
            client_sha256: Some(tunnel.client_sha256.clone()),
            verified: crate::sandbox_relay::tunnel::verify_client(
                &tunnel.client,
                &tunnel.client_sha256,
            ),
            max_tunnels: Some(tunnel.max_tunnels),
            allow_for_others: Some(tunnel.allow_for_others),
        },
        None => Status {
            configured: false,
            client: None,
            client_sha256: None,
            verified: false,
            max_tunnels: None,
            allow_for_others: None,
        },
    };
    if json {
        return output::json(&status);
    }
    match (&status.client, &status.client_sha256) {
        (Some(client), Some(sha)) => output::text(format!(
            "client `{}`\nsha256 {sha}\nverified {}\nmax_tunnels {}\nallow_for_others {}",
            client.display(),
            status.verified,
            status.max_tunnels.unwrap_or_default(),
            status.allow_for_others.unwrap_or_default()
        )),
        _ => output::text("preview tunnels are not configured on this node"),
    }
}

fn run_install(args: &InstallArgs) -> Result<()> {
    let expected = args.sha256.to_ascii_lowercase();
    if args.allow_for_others
        && (std::env::var_os("WSSP_HOST_COMMAND").is_some()
            || std::env::var_os("WSSP_HOST_TERMINAL").is_some())
    {
        anyhow::bail!("a host command cannot allow tunnels for other users' sandboxes");
    }
    let bytes =
        std::fs::read(&args.file).with_context(|| format!("reading `{}`", args.file.display()))?;
    let digest = ring::digest::digest(&ring::digest::SHA256, &bytes);
    let actual: String = digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    anyhow::ensure!(
        actual == expected,
        "`{}` has SHA-256 {actual}, not the expected {expected}",
        args.file.display()
    );
    let dir = crate::paths::data_dir()?.join("tunnel");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .with_context(|| format!("creating `{}`", dir.display()))?;
    let target = dir.join(format!("tunnel-{}", &expected[..16]));
    install_file(&dir, &target, &bytes)?;
    let tunnel = TunnelConfig {
        client: target.clone(),
        client_sha256: expected,
        max_tunnels: args.max_tunnels,
        allow_for_others: args.allow_for_others,
    };
    tunnel.validate()?;
    update_config(|config| {
        config.tunnel = Some(tunnel);
        Ok(())
    })?;
    output::text(format!(
        "installed `{}`; restart the daemon to enable preview tunnels",
        target.display()
    ))
}

/// Write to a private temporary file in `dir`, fsync, mark read+exec only,
/// then rename over `target` and fsync the directory.
fn install_file(dir: &Path, target: &Path, bytes: &[u8]) -> Result<()> {
    let temp = dir.join(format!(".install-{}", std::process::id()));
    let _ = std::fs::remove_file(&temp);
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o700)
        .open(&temp)
        .with_context(|| format!("creating `{}`", temp.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o555))?;
    std::fs::rename(&temp, target).with_context(|| format!("installing `{}`", target.display()))?;
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}
