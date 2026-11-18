//! `wssp host images`: the managed template image cache of this machine's daemons.
//!
//! `list` first asks each running daemon to reconcile its journal with the
//! host image store (images deleted out of band drop out), then reads the
//! journal read-only; with no daemon answering it lists the journal as
//! recorded. `prune` asks the
//! running daemon, the journal's only writer, to evict every unpinned image no
//! sandbox or job uses (`--dry-run` lists them), and prints its answer.

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, Subcommand};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::sandbox_relay::images::journal::{CACHE_JOURNAL_FILE, CacheJournal};
use crate::sandbox_relay::images::{
    LIST_REQUEST_FILE, LIST_RESULT_FILE, PRUNE_REQUEST_FILE, PRUNE_RESULT_FILE,
};

#[derive(Debug, ClapArgs)]
pub struct Args {
    #[command(subcommand)]
    pub command: ImagesCommand,
}

#[derive(Debug, Subcommand)]
pub enum ImagesCommand {
    /// List managed cached images (fetched, captured, replicas).
    List {
        /// Print JSON.
        #[arg(long)]
        json: bool,
    },
    /// Evict unpinned images nothing uses (asks the running daemon).
    Prune {
        /// Only list what would be evicted.
        #[arg(long)]
        dry_run: bool,
        /// Print JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Row {
    daemon_dir: String,
    fingerprint: String,
    owners: Vec<String>,
    compressed_bytes: u64,
    origin: crate::sandbox_relay::images::journal::Origin,
    pinned: bool,
    last_used_unix_ms: u64,
}

fn daemon_dirs() -> Result<Vec<PathBuf>> {
    let relay = crate::paths::data_dir()?.join("relay");
    let mut dirs = Vec::new();
    let Ok(entries) = std::fs::read_dir(&relay) else {
        return Ok(dirs);
    };
    for entry in entries.flatten() {
        let images = entry.path().join("images");
        if images.join(CACHE_JOURNAL_FILE).is_file() {
            dirs.push(images);
        }
    }
    dirs.sort();
    Ok(dirs)
}

fn list_rows(dirs: &[PathBuf]) -> Result<Vec<Row>> {
    let mut rows = Vec::new();
    for dir in dirs {
        let journal = CacheJournal::open(dir)?;
        for entry in journal.file.entries.values() {
            rows.push(Row {
                daemon_dir: dir.display().to_string(),
                fingerprint: entry.fingerprint.clone(),
                owners: entry.owners.iter().cloned().collect(),
                compressed_bytes: entry.compressed_bytes,
                origin: entry.origin,
                pinned: entry.pinned,
                last_used_unix_ms: entry.last_used_unix_ms,
            });
        }
    }
    Ok(rows)
}

/// How long `list` waits for the running daemon (it polls every 5 s).
const LIST_RECONCILE_WAIT: Duration = Duration::from_secs(8);

/// Ask the running daemon (the journal's only writer) to reconcile its journal
/// with the host image store, so images deleted out of band are dropped
/// before `list` reads it. False when no daemon answered (or its inventory
/// read failed); the request is withdrawn and the raw journal is listed.
fn request_reconcile(dir: &Path, timeout: Duration) -> bool {
    let result = dir.join(LIST_RESULT_FILE);
    let _ = std::fs::remove_file(&result);
    if std::fs::write(dir.join(LIST_REQUEST_FILE), "{}").is_err() {
        return false;
    }
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(bytes) = std::fs::read(&result) {
            let _ = std::fs::remove_file(&result);
            return serde_json::from_slice::<serde_json::Value>(&bytes)
                .ok()
                .and_then(|v| v.get("reconciled").and_then(serde_json::Value::as_bool))
                .unwrap_or(false);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = std::fs::remove_file(dir.join(LIST_REQUEST_FILE));
    false
}

fn prune_dir(dir: &Path, dry_run: bool) -> Result<serde_json::Value> {
    let result = dir.join(PRUNE_RESULT_FILE);
    let _ = std::fs::remove_file(&result);
    std::fs::write(
        dir.join(PRUNE_REQUEST_FILE),
        serde_json::json!({ "dryRun": dry_run }).to_string(),
    )
    .with_context(|| format!("writing a prune request in `{}`", dir.display()))?;
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if let Ok(bytes) = std::fs::read(&result) {
            let _ = std::fs::remove_file(&result);
            return serde_json::from_slice(&bytes).context("parsing the daemon's prune result");
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let _ = std::fs::remove_file(dir.join(PRUNE_REQUEST_FILE));
    anyhow::bail!(
        "no running daemon answered for `{}` (prune is applied by `wssp host run`)",
        dir.display()
    )
}

pub fn run(args: &Args) -> Result<()> {
    let dirs = daemon_dirs()?;
    match &args.command {
        ImagesCommand::List { json } => {
            // All daemons at once: an idle cache directory costs one wait, not one each.
            std::thread::scope(|scope| {
                for dir in &dirs {
                    scope.spawn(move || {
                        if !request_reconcile(dir, LIST_RECONCILE_WAIT) {
                            tracing::warn!(
                                dir = %dir.display(),
                                "no running daemon reconciled this cache; listing its journal as recorded"
                            );
                        }
                    });
                }
            });
            let rows = list_rows(&dirs)?;
            if *json {
                return crate::output::json(&rows);
            }
            if rows.is_empty() {
                return crate::output::line("no managed images");
            }
            for row in rows {
                crate::output::line(format!(
                    "{}  {:>12} bytes  {:?}{}  owners={}",
                    row.fingerprint,
                    row.compressed_bytes,
                    row.origin,
                    if row.pinned { " (pinned)" } else { "" },
                    row.owners.len()
                ))?;
            }
            Ok(())
        }
        ImagesCommand::Prune { dry_run, json } => {
            let mut results = Vec::new();
            for dir in &dirs {
                results.push(prune_dir(dir, *dry_run)?);
            }
            if *json {
                return crate::output::json(&results);
            }
            for result in results {
                let list = result["fingerprints"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default();
                crate::output::line(format!(
                    "{} {} image(s)",
                    if *dry_run { "would evict" } else { "evicted" },
                    list.len()
                ))?;
                for fp in list {
                    crate::output::line(format!("  {}", fp.as_str().unwrap_or_default()))?;
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox_relay::images::journal::Origin;
    use crate::sandbox_relay::images::{ImageService, ImageSettings};
    use sandbox_runtime::{FakeRuntime, SandboxRuntime as _};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn daemon(runtime: &FakeRuntime, state: &Path) -> ImageService {
        ImageService::start(
            Arc::new(runtime.clone()),
            state,
            ImageSettings {
                size: crate::config::ImageCacheSize::Gib(4),
                accept_foreign: false,
                foreign_grace: Duration::from_secs(600),
                builder: true,
                accept_foreign_builds: false,
            },
            ureq::Agent::config_builder().build().into(),
            "http://127.0.0.1:9",
            "wssp_host_test-secret",
        )
        .expect("start")
        .expect("enabled")
    }

    #[test]
    fn list_asks_the_running_daemon_to_reconcile_first() {
        let runtime = FakeRuntime::default();
        let state = tempfile::tempdir().unwrap();
        let images = daemon(&runtime, state.path());
        images.on_registered("host-owner");
        let gone = runtime.seed_image_bytes(b"gone", "x86_64", false);
        let kept = runtime.seed_image_bytes(b"kept", "x86_64", false);
        images.record_for_test(&gone, "host-owner", 10, Origin::Captured, true);
        images.record_for_test(&kept, "host-owner", 20, Origin::Fetched, false);
        // `incus image delete <hex>` out of band.
        runtime.delete_image(&gone).unwrap();
        let dir = state.path().join("images");
        let stop = Arc::new(AtomicBool::new(false));
        let poller = {
            let (images, stop) = (images.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    images.poll_list_request();
                    std::thread::sleep(Duration::from_millis(20));
                }
            })
        };
        assert!(request_reconcile(&dir, Duration::from_secs(5)));
        stop.store(true, Ordering::Relaxed);
        poller.join().unwrap();
        let rows = list_rows(std::slice::from_ref(&dir)).unwrap();
        let listed: Vec<&str> = rows.iter().map(|r| r.fingerprint.as_str()).collect();
        assert_eq!(listed, vec![kept.as_str()]);
    }

    #[test]
    fn list_falls_back_to_the_journal_when_no_daemon_answers() {
        let state = tempfile::tempdir().unwrap();
        let dir = state.path().join("images");
        std::fs::create_dir_all(&dir).unwrap();
        let started = Instant::now();
        assert!(!request_reconcile(&dir, Duration::from_millis(300)));
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(!dir.join(LIST_REQUEST_FILE).exists(), "request withdrawn");
    }
}
