use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::auth::{control_plane_url, direct_loopback_cleartext, resolve_connect};
use crate::exit::{CodedError, ExitCode};

#[derive(Debug, clap::Args)]
pub struct Args {
    #[command(flatten)]
    pub tls: crate::tls::TlsArgs,

    /// Control plane origin (defaults to the saved selection).
    #[arg(long)]
    pub server: Option<String>,
    /// Environment variable holding a dashboard host token.
    #[arg(long)]
    pub host_token_env: Option<String>,
    /// Host id (required with a dashboard host token).
    #[arg(long)]
    pub host_id: Option<String>,
    /// Print the committed drain state and live sandbox count as JSON.
    #[arg(long)]
    pub json: bool,
    /// Drain only: also offload this host's stopped sandboxes to the image
    /// store, whatever their offload policy, and free their host copies once
    /// another eligible host could restore them. Undrain clears it.
    #[arg(long)]
    pub offload: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DrainStatus {
    id: String,
    draining: bool,
    live_sandbox_count: u32,
    drained: bool,
    offload: bool,
}

pub fn run(args: &Args, draining: bool) -> Result<()> {
    if args.offload && !draining {
        return Err(anyhow::anyhow!(
            "--offload applies to `wssp host drain` only"
        ))
        .context(CodedError::new(ExitCode::Failure));
    }
    let offload = draining && args.offload;
    let trust = args.tls.load(&crate::config::Config::load()?)?;
    let resolved = resolve_connect(
        args.server.as_deref(),
        args.host_id.as_deref(),
        args.host_token_env.as_deref(),
    )?;
    let url = control_plane_url(&resolved.server_url)?.join("/api/sandbox-host/drain")?;
    let mut builder = ureq::Agent::config_builder()
        .max_redirects(0)
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(10)));
    if direct_loopback_cleartext(&resolved.server_url)? {
        builder = builder.proxy(None);
    }
    let agent = trust.http_agent(builder.build());
    let mut response = agent
        .post(url.as_str())
        .header("Authorization", format!("Bearer {}", resolved.secret))
        .header("Content-Type", "application/json")
        .send_json(serde_json::json!({
            "id": resolved.host_id,
            "draining": draining,
            "offload": offload,
        }))
        .map_err(|error| crate::tls::control_plane_error(&resolved.server_url, error))
        .context("host drain request failed")?;
    let status = response.status().as_u16();
    if status != 200 {
        let code = match status {
            401 | 403 => ExitCode::CredentialInactive,
            404 => ExitCode::NotFound,
            429 | 500..=599 => ExitCode::RelayUnavailable,
            _ => ExitCode::Failure,
        };
        return Err(anyhow::anyhow!(
            "host drain request failed with HTTP status {status}"
        ))
        .context(CodedError::new(code));
    }
    let body = response
        .body_mut()
        .with_config()
        .limit(4096)
        .read_to_string()
        .context("reading host drain response")?;
    let result: DrainStatus = serde_json::from_str(&body).context("parsing host drain response")?;
    validate_status(&result, &resolved.host_id, draining, offload)?;
    if args.json {
        crate::output::json(&result)
    } else {
        crate::output::line(format!(
            "host {}: draining={}, offload={}, live sandboxes={}, drained={}",
            result.id, result.draining, result.offload, result.live_sandbox_count, result.drained
        ))
    }
}

fn validate_status(
    result: &DrainStatus,
    host_id: &str,
    draining: bool,
    offload: bool,
) -> Result<()> {
    anyhow::ensure!(
        result.id == host_id
            && result.draining == draining
            && result.offload == offload
            && result.drained == (result.draining && result.live_sandbox_count == 0),
        "invalid host drain response"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_undrain_response_is_valid() {
        let result: DrainStatus = serde_json::from_str(
            r#"{"id":"host_1","draining":false,"liveSandboxCount":0,"drained":false,"offload":false}"#,
        )
        .unwrap();
        assert!(validate_status(&result, "host_1", false, false).is_ok());
    }

    #[test]
    fn offload_drain_response_must_echo_the_switch() {
        let mut result: DrainStatus = serde_json::from_str(
            r#"{"id":"host_1","draining":true,"liveSandboxCount":2,"drained":false,"offload":true}"#,
        )
        .unwrap();
        assert!(validate_status(&result, "host_1", true, true).is_ok());
        assert!(validate_status(&result, "host_1", true, false).is_err());
        result.offload = false;
        assert!(validate_status(&result, "host_1", true, true).is_err());
    }

    #[test]
    fn undrain_refuses_offload() {
        let args = Args {
            tls: crate::tls::TlsArgs::default(),
            server: None,
            host_token_env: None,
            host_id: None,
            json: false,
            offload: true,
        };
        let error = run(&args, false).unwrap_err();
        assert!(format!("{error:#}").contains("--offload"));
    }

    #[test]
    fn draining_idle_response_is_valid_and_inconsistent_states_are_rejected() {
        let mut result: DrainStatus = serde_json::from_str(
            r#"{"id":"host_1","draining":true,"liveSandboxCount":0,"drained":true,"offload":false}"#,
        )
        .unwrap();
        assert!(validate_status(&result, "host_1", true, false).is_ok());
        result.drained = false;
        assert!(validate_status(&result, "host_1", true, false).is_err());
        result.drained = true;
        result.live_sandbox_count = 1;
        assert!(validate_status(&result, "host_1", true, false).is_err());
        assert!(validate_status(&result, "other", true, false).is_err());
        assert!(validate_status(&result, "host_1", false, false).is_err());
    }
}
