//! `wssp guard status [--json]` (any user). Asks the socket; falls back to
//! `/run/wssp-guard/status.json` when the socket is down. Prints source
//! states, digests and counts, never list contents. Exits 1 when the guard
//! is not healthy by the shared lease rule.

use std::time::Duration;

use anyhow::{Result, bail};
use sandbox_runtime::guard::protocol::{Reply, Request, call};
use sandbox_runtime::guard_probe::{
    GuardExpectations, GuardSourceState, GuardStatus, GuardUnhealthy, boottime_now_ns,
    evaluate_guard, read_boot_id,
};
use serde::Serialize;

use super::StatusArgs;
use super::paths::Paths;
use crate::output;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusOutput<'a> {
    source: &'a str,
    guard_ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<&'a GuardStatus>,
}

/// The node-local view: same boot, unexpired lease, current version, both
/// sources healthy. The deployment digest is the daemon's to compare, so
/// here any healthy deployment state passes.
fn verdict(status: &GuardStatus) -> Result<(), GuardUnhealthy> {
    let boot_id = read_boot_id().map_err(|_| GuardUnhealthy::Unreachable)?;
    let now = boottime_now_ns().map_err(|_| GuardUnhealthy::Unreachable)?;
    let deployment_digest = match status.sources.deployment.state {
        GuardSourceState::Valid => status.sources.deployment.digest.clone(),
        _ => None,
    };
    evaluate_guard(
        status,
        &GuardExpectations {
            min_guard_version: sandbox_runtime::guard::GUARD_VERSION,
            boot_id,
            now_boottime_ns: now,
            deployment_digest,
        },
    )
}

/// Whether the node-local verdict is healthy.
pub fn is_healthy(status: &GuardStatus) -> bool {
    verdict(status).is_ok()
}

fn state_name(state: GuardSourceState) -> &'static str {
    match state {
        GuardSourceState::Valid => "valid",
        GuardSourceState::NotConfigured => "not_configured",
        GuardSourceState::Invalid => "invalid",
        GuardSourceState::Missing => "missing",
        GuardSourceState::Unknown => "unknown",
    }
}

pub fn print_text(status: &GuardStatus, source: &str) -> Result<()> {
    match verdict(status) {
        Ok(()) => output::line("guard: ok")?,
        Err(reason) => output::line(format!("guard: NOT OK ({})", reason.as_str()))?,
    }
    if verdict(status) == Err(GuardUnhealthy::HostFirewall) {
        for line in sandbox_runtime::guard::path::HOST_FIREWALL_FIX.lines() {
            output::line(format!("  {line}"))?;
        }
    }
    output::line(format!(
        "  version {}, instance {}, generation {}, from {source}",
        status.guard_version, status.instance_id, status.generation
    ))?;
    if let Some(reason) = &status.quarantined {
        output::line(format!("  quarantined: {reason}"))?;
    }
    for reason in &status.reasons {
        output::line(format!("  reason: {reason}"))?;
    }
    let lease = match boottime_now_ns() {
        Ok(now) if status.lease_until_boottime_ns > now => format!(
            "valid for {:.1}s",
            (status.lease_until_boottime_ns - now) as f64 / 1e9
        ),
        _ => "expired".to_string(),
    };
    output::line(format!("  lease: {lease}"))?;
    for (name, source) in [
        ("root (/etc/wssp/egress-blocklist)", &status.sources.root),
        ("deployment", &status.sources.deployment),
    ] {
        output::line(format!(
            "  source {name}: {}{}",
            state_name(source.state),
            source
                .digest
                .as_deref()
                .map(|d| format!(" ({d})"))
                .unwrap_or_default()
        ))?;
    }
    output::line(format!(
        "  bridges: {} live; uplinks: {}",
        status.live_bridges.len(),
        if status.uplinks.is_empty() {
            "none".to_string()
        } else {
            status.uplinks.join(", ")
        }
    ))?;
    let counts: Vec<String> = status
        .counts
        .iter()
        .map(|(k, v)| format!("{k} {v}"))
        .collect();
    output::line(format!("  counts: {}", counts.join(", ")))
}

/// The node-local guard view used by `login`, `connect` and `config show`:
/// the status (socket first, then the status file), where it came from, and
/// the node-local verdict, at [`Paths::local`].
pub fn local_snapshot() -> (
    Option<GuardStatus>,
    &'static str,
    Result<(), GuardUnhealthy>,
) {
    snapshot(&Paths::local())
}

fn snapshot(
    paths: &Paths,
) -> (
    Option<GuardStatus>,
    &'static str,
    Result<(), GuardUnhealthy>,
) {
    let (status, source) = match call(&paths.socket(), &Request::Status {}, Duration::from_secs(2))
    {
        Ok(Reply::Status { status }) => (Some(*status), "socket"),
        _ => match std::fs::read(paths.status_file())
            .ok()
            .and_then(|bytes| serde_json::from_slice::<GuardStatus>(&bytes).ok())
        {
            Some(status) => (Some(status), "file"),
            None => (None, "none"),
        },
    };
    let verdict = match &status {
        Some(status) => verdict(status),
        None => Err(GuardUnhealthy::Unreachable),
    };
    (status, source, verdict)
}

pub fn run(args: &StatusArgs) -> Result<()> {
    let (status, source, verdict) = snapshot(&Paths::system());
    if args.json {
        output::json(&StatusOutput {
            source,
            guard_ok: verdict.is_ok(),
            reason: verdict.err().map(GuardUnhealthy::as_str),
            status: status.as_ref(),
        })?;
    } else if let Some(status) = &status {
        print_text(status, source)?;
    }
    match verdict {
        Ok(()) => Ok(()),
        Err(reason @ (GuardUnhealthy::Unreachable | GuardUnhealthy::Outdated)) => {
            let exe = std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "wssp".into());
            bail!(
                "egress guard {}: install or upgrade it with: sudo {exe} guard install --daemon-user <user>",
                reason.as_str()
            )
        }
        Err(reason) => bail!("egress guard is not healthy: {}", reason.as_str()),
    }
}
