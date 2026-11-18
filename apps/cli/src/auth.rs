//! Device flow wire contract and credential resolution. No compatibility shapes.

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::Deserialize;
use url::{Host, Url};

use crate::config::validate_env_name;
use crate::state::{AuthStore, CredentialKind, DeviceCredential};

pub const MAX_LOGIN_DURATION: Duration = Duration::from_secs(600);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub struct ResolvedConnect {
    pub server_url: String,
    pub host_id: String,
    pub secret: String,
}

pub fn resolve_connect(
    server_override: Option<&str>,
    host_id_override: Option<&str>,
    token_env_override: Option<&str>,
) -> Result<ResolvedConnect> {
    let store = AuthStore::open(None)?;
    let (config, device) = store.snapshot()?;
    let token_env = token_env_override.or(config.host_token_env.as_deref());
    let server_url = server_override
        .or_else(|| {
            if token_env.is_none() {
                device.as_ref().map(|d| d.origin.as_str())
            } else {
                None
            }
        })
        .or(config.server_url.as_deref())
        .context(
            "server URL is not configured; pass `--server` or run `wssp host config set-server`",
        )?;
    let origin = canonical_control_plane_origin(server_url)?;
    if let Some(env) = token_env {
        let secret = host_token_from_env(env)?;
        return Ok(ResolvedConnect {
            server_url: origin,
            host_id: host_id_override
                .context("host id is required with a dashboard host token; pass `--host-id`")?
                .to_owned(),
            secret,
        });
    }
    let device = device.context("no credential selected; run `wssp host enroll --slug <slug> --server <url>` or `wssp host enroll --token-env <ENV_VAR>`")?;
    if device.origin != origin {
        anyhow::bail!(
            "device credential was issued for `{}`; run `wssp host enroll` again to change servers",
            device.origin
        );
    }
    if host_id_override.is_some_and(|id| id != device.host_id) {
        anyhow::bail!("device credential is bound to host `{}`", device.host_id);
    }
    Ok(ResolvedConnect {
        server_url: origin,
        host_id: device.host_id,
        secret: device.secret,
    })
}

pub fn host_token_from_env(env: &str) -> Result<String> {
    validate_env_name(env)?;
    let secret = std::env::var(env)
        .with_context(|| format!("reading host token from environment variable `{env}`"))?;
    validate_product_secret(&secret, "wssp_host_")?;
    Ok(secret)
}

pub fn validate_product_secret(secret: &str, prefix: &str) -> Result<()> {
    let valid = secret.strip_prefix(prefix).is_some_and(|suffix| {
        suffix.len() == 43
            && suffix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    });
    anyhow::ensure!(valid, "invalid product credential format");
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct DeviceCodeStartResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub expires_in: u64,
    pub interval: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeviceCredentialExchangeResponse {
    credential_id: String,
    user_id: String,
    host_id: String,
    secret: String,
}

#[derive(Deserialize)]
struct RpcResponse<T> {
    json: T,
}

#[derive(Deserialize)]
struct RpcErrorBody {
    code: String,
    message: Option<String>,
    data: Option<RpcErrorData>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RpcErrorData {
    device_flow_error: Option<String>,
    retry_after_seconds: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceFlowState {
    Pending,
    SlowDown,
    Denied,
    Expired,
}

#[derive(Debug)]
pub enum ExchangeError {
    DeviceFlow(DeviceFlowState),
    RateLimited(Duration),
    Other(anyhow::Error),
}
impl From<anyhow::Error> for ExchangeError {
    fn from(error: anyhow::Error) -> Self {
        Self::Other(error)
    }
}

pub fn device_login_scope(host_slug: &str) -> String {
    format!("host-slug:{host_slug}")
}

pub fn remaining(deadline: Instant) -> Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    anyhow::ensure!(!remaining.is_zero(), "device authorization expired");
    Ok(remaining)
}

// One request builder: redirect refusal, all phase timeouts, body limit, transport gate.
fn post(
    trust: &crate::tls::Trust,
    server: &str,
    path: &str,
    request: serde_json::Value,
    deadline: Instant,
) -> Result<(u16, String)> {
    let url = control_plane_url(server)?.join(path)?;
    let timeout = remaining(deadline)?.min(REQUEST_TIMEOUT);
    let mut builder = ureq::Agent::config_builder()
        .max_redirects(0)
        .http_status_as_error(false)
        .timeout_global(Some(timeout))
        .timeout_resolve(Some(timeout.min(Duration::from_secs(5))))
        .timeout_connect(Some(timeout.min(Duration::from_secs(5))))
        .timeout_send_request(Some(timeout))
        .timeout_send_body(Some(timeout))
        .timeout_recv_response(Some(timeout))
        .timeout_recv_body(Some(timeout));
    if direct_loopback_cleartext(server)? {
        builder = builder.proxy(None);
    }
    let agent = trust.http_agent(builder.build());
    let mut response = agent
        .post(url.as_str())
        .header("Accept", "application/json")
        .header("Content-Type", "application/json")
        .header("x-csrf-token", "orpc")
        .send_json(request)
        .map_err(|error| crate::tls::control_plane_error(server, error))
        .context("device authorization HTTP request failed")?;
    let status = response.status().as_u16();
    let body = response
        .body_mut()
        .with_config()
        .limit(64 * 1024)
        .read_to_string()
        .context("reading device authorization response")?;
    remaining(deadline)?;
    Ok((status, body))
}

pub fn start_device_authorization(
    trust: &crate::tls::Trust,
    server: &str,
    slug: &str,
    deadline: Instant,
) -> Result<DeviceCodeStartResponse> {
    crate::slug::validate_host_slug(slug)?;
    let (status, body) = post(
        trust,
        server,
        "/api/auth/device/code",
        serde_json::json!({
            "client_id": "wssp", "scope": device_login_scope(slug),
        }),
        deadline,
    )?;
    anyhow::ensure!(
        status == 200,
        "device authorization failed with HTTP status {status}: {}",
        crate::output::remote_message(&body)
    );
    let started: DeviceCodeStartResponse =
        serde_json::from_str(&body).context("parsing device authorization response")?;
    anyhow::ensure!(
        !started.device_code.is_empty() && !started.user_code.is_empty() && started.expires_in > 0,
        "invalid device authorization response"
    );
    verification_url(&started.verification_uri)?;
    if let Some(url) = &started.verification_uri_complete {
        verification_url(url)?;
    }
    Ok(started)
}

pub fn exchange_device_code(
    trust: &crate::tls::Trust,
    server: &str,
    code: &str,
    slug: &str,
    deadline: Instant,
) -> std::result::Result<DeviceCredential, ExchangeError> {
    let (status, body) = post(
        trust,
        server,
        "/rpc/hostCredentials/exchangeDeviceCode",
        serde_json::json!({
            "json": { "deviceCode": code, "hostSlug": slug }
        }),
        deadline,
    )?;
    if status != 200 {
        return Err(classify_exchange_error(status, &body));
    }
    let RpcResponse { json: parsed }: RpcResponse<DeviceCredentialExchangeResponse> =
        serde_json::from_str(&body).context("parsing device credential response")?;
    if parsed.credential_id.is_empty() || parsed.user_id.is_empty() || parsed.host_id.is_empty() {
        return Err(anyhow::anyhow!("missing device credential identity").into());
    }
    validate_product_secret(&parsed.secret, "wssp_device_")?;
    Ok(DeviceCredential {
        credential_id: parsed.credential_id,
        host_id: parsed.host_id,
        host_slug: slug.to_owned(),
        origin: canonical_control_plane_origin(server)?,
        kind: CredentialKind::Device,
        secret: parsed.secret,
        generation: String::new(),
    })
}

#[derive(Clone, Copy)]
enum ContractOutcome {
    Flow(DeviceFlowState),
    RateLimited,
    Terminal,
}
// Mirrors docs/design/device-flow-contract.md, including terminal rows.
const ERROR_CONTRACT: &[(u16, &str, Option<&str>, ContractOutcome)] = &[
    (
        400,
        "BAD_REQUEST",
        Some("authorization_pending"),
        ContractOutcome::Flow(DeviceFlowState::Pending),
    ),
    (
        400,
        "BAD_REQUEST",
        Some("slow_down"),
        ContractOutcome::Flow(DeviceFlowState::SlowDown),
    ),
    (
        400,
        "BAD_REQUEST",
        Some("expired_token"),
        ContractOutcome::Flow(DeviceFlowState::Expired),
    ),
    (400, "BAD_REQUEST", None, ContractOutcome::Terminal),
    (
        403,
        "FORBIDDEN",
        Some("access_denied"),
        ContractOutcome::Flow(DeviceFlowState::Denied),
    ),
    (403, "FORBIDDEN", None, ContractOutcome::Terminal),
    (404, "NOT_FOUND", None, ContractOutcome::Terminal),
    (409, "CONFLICT", None, ContractOutcome::Terminal),
    (429, "TOO_MANY_REQUESTS", None, ContractOutcome::RateLimited),
    (
        503,
        "SERVICE_UNAVAILABLE",
        Some("authorization_pending"),
        ContractOutcome::Flow(DeviceFlowState::Pending),
    ),
];

fn classify_exchange_error(status: u16, body: &str) -> ExchangeError {
    let terminal = |message: &str| {
        ExchangeError::Other(anyhow::anyhow!(
            "device credential exchange failed (HTTP {status}): {}; run `wssp host enroll` again",
            crate::output::remote_message(message)
        ))
    };
    let Ok(wire) = serde_json::from_str::<serde_json::Value>(body) else {
        return terminal("invalid error envelope");
    };
    if wire
        .pointer("/json/data/deviceFlowError")
        .is_some_and(|tag| !tag.is_string())
    {
        return terminal("invalid deviceFlowError");
    }
    let Ok(RpcResponse { json: error }) = serde_json::from_str::<RpcResponse<RpcErrorBody>>(body)
    else {
        return terminal("invalid error envelope");
    };
    let tag = error
        .data
        .as_ref()
        .and_then(|d| d.device_flow_error.as_deref());
    let outcome = ERROR_CONTRACT
        .iter()
        .find(|(s, c, t, _)| *s == status && *c == error.code && *t == tag)
        .map(|row| row.3);
    match outcome {
        Some(ContractOutcome::Flow(state)) => ExchangeError::DeviceFlow(state),
        Some(ContractOutcome::RateLimited) => match error
            .data
            .and_then(|d| d.retry_after_seconds)
            .filter(|n| *n > 0)
        {
            Some(seconds) => ExchangeError::RateLimited(Duration::from_secs(seconds)),
            None => terminal("invalid retryAfterSeconds"),
        },
        _ => terminal(error.message.as_deref().unwrap_or(&error.code)),
    }
}

pub(crate) fn direct_loopback_cleartext(server: &str) -> Result<bool> {
    let url = control_plane_url(server)?;
    Ok(url.scheme() == "http")
}

/// All server transports use this validator. No credentials, query or fragment in server URLs.
fn transport_url(value: &str) -> Result<Url> {
    let url = Url::parse(value).context("invalid URL")?;
    anyhow::ensure!(url.host().is_some(), "URL requires a host");
    match url.scheme() {
        "https" | "wss" => {}
        "http" | "ws" => {
            let loopback = match url.host() {
                Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
                Some(Host::Ipv4(ip)) => ip.is_loopback(),
                Some(Host::Ipv6(ip)) => ip.is_loopback(),
                None => false,
            };
            anyhow::ensure!(
                loopback,
                "cleartext transport is allowed only on loopback; use HTTPS/WSS"
            );
        }
        _ => anyhow::bail!("URL must use http, https, ws, or wss"),
    }
    Ok(url)
}

pub fn control_plane_url(value: &str) -> Result<Url> {
    let mut url = transport_url(value)?;
    anyhow::ensure!(
        url.username().is_empty() && url.password().is_none(),
        "URL must not contain user information"
    );

    anyhow::ensure!(
        url.query().is_none() && url.fragment().is_none(),
        "server URL must not contain query or fragment"
    );
    let scheme = match url.scheme() {
        "ws" => "http",
        "wss" => "https",
        other => other,
    }
    .to_owned();
    url.set_scheme(&scheme)
        .map_err(|_| anyhow::anyhow!("invalid server scheme"))?;
    Ok(url)
}
pub fn canonical_control_plane_origin(value: &str) -> Result<String> {
    let mut url = control_plane_url(value)?;
    url.set_path("/");
    // url normalizes default ports itself; never discard a non-default port.
    Ok(url.to_string())
}
pub fn relay_url(value: &str) -> Result<Url> {
    let mut url = control_plane_url(value)?.join("/ws/sandbox-host")?;
    let scheme = if url.scheme() == "https" { "wss" } else { "ws" };
    url.set_scheme(scheme)
        .map_err(|_| anyhow::anyhow!("invalid relay scheme"))?;
    Ok(url)
}
fn verification_url(value: &str) -> Result<Url> {
    let url = transport_url(value)?;
    anyhow::ensure!(
        matches!(url.scheme(), "http" | "https"),
        "verification URI must use https or loopback http"
    );
    Ok(url)
}
pub fn approval_url(started: &DeviceCodeStartResponse) -> Result<String> {
    let value = started
        .verification_uri_complete
        .as_ref()
        .unwrap_or(&started.verification_uri);
    verification_url(value)?;
    Ok(value.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_contract_cross_product() {
        for status in [200, 201, 302, 400, 401, 403, 404, 409, 429, 500, 503] {
            for code in [
                "BAD_REQUEST",
                "FORBIDDEN",
                "NOT_FOUND",
                "CONFLICT",
                "TOO_MANY_REQUESTS",
                "SERVICE_UNAVAILABLE",
                "UNKNOWN",
            ] {
                for tag in [
                    None,
                    Some("authorization_pending"),
                    Some("slow_down"),
                    Some("expired_token"),
                    Some("access_denied"),
                    Some("unknown"),
                ] {
                    let mut data = serde_json::json!({"retryAfterSeconds":2});
                    if let Some(tag) = tag {
                        data["deviceFlowError"] = tag.into();
                    }
                    let body = serde_json::json!({"json":{"code":code,"data":data}}).to_string();
                    let actual = match classify_exchange_error(status, &body) {
                        ExchangeError::DeviceFlow(state) => format!("{state:?}"),
                        ExchangeError::RateLimited(delay) => {
                            assert_eq!(delay.as_secs(), 2);
                            "RateLimited".into()
                        }
                        ExchangeError::Other(_) => "Terminal".into(),
                    };
                    let expected = match (status, code, tag) {
                        (400, "BAD_REQUEST", Some("authorization_pending"))
                        | (503, "SERVICE_UNAVAILABLE", Some("authorization_pending")) => "Pending",
                        (400, "BAD_REQUEST", Some("slow_down")) => "SlowDown",
                        (400, "BAD_REQUEST", Some("expired_token")) => "Expired",
                        (403, "FORBIDDEN", Some("access_denied")) => "Denied",
                        (429, "TOO_MANY_REQUESTS", None) => "RateLimited",
                        _ => "Terminal",
                    };
                    assert_eq!(actual, expected, "{status}/{code}/{tag:?}");
                }
            }
        }
    }
    #[test]
    fn rate_limit_requires_positive_integer_and_honors_server_floor() {
        for retry in [
            serde_json::Value::Null,
            serde_json::json!(0),
            serde_json::json!(-1),
            serde_json::json!(1.5),
            serde_json::json!("1"),
        ] {
            let body = serde_json::json!({"json":{"code":"TOO_MANY_REQUESTS","data":{"retryAfterSeconds":retry}}}).to_string();
            assert!(matches!(
                classify_exchange_error(429, &body),
                ExchangeError::Other(_)
            ));
        }
        let body = serde_json::json!({"json":{"code":"TOO_MANY_REQUESTS","data":{"retryAfterSeconds":120}}}).to_string();
        assert!(
            matches!(classify_exchange_error(429, &body), ExchangeError::RateLimited(d) if d == Duration::from_secs(120))
        );
    }
    #[test]
    fn transport_origin_preserves_port_and_converts_schemes() {
        assert_eq!(
            canonical_control_plane_origin("wss://EXAMPLE.test:443/path").unwrap(),
            "https://example.test/"
        );
        assert_eq!(
            canonical_control_plane_origin("http://127.0.0.1:3010/path").unwrap(),
            "http://127.0.0.1:3010/"
        );
        assert_ne!(
            canonical_control_plane_origin("http://127.0.0.1:3010").unwrap(),
            canonical_control_plane_origin("http://127.0.0.1:3011").unwrap()
        );
        assert_eq!(
            relay_url("https://example.test:444").unwrap().as_str(),
            "wss://example.test:444/ws/sandbox-host"
        );
        for url in [
            "http://127.23.1.2",
            "ws://[::1]",
            "http://localhost",
            "https://example.test",
            "wss://example.test",
        ] {
            assert!(control_plane_url(url).is_ok(), "{url}");
        }
        for url in [
            "http://192.0.2.1",
            "ws://example.test",
            "http://localhost.evil",
            "ftp://localhost",
            "https://user:password@example.test",
            "file:///tmp/a",
            "https://example.test?token=a",
        ] {
            assert!(control_plane_url(url).is_err(), "{url}");
        }
        assert!(verification_url("https://different-web.test/en-US/device?user_code=123").is_ok());
        assert!(verification_url("http://[::1]:3000/device").is_ok());
        assert!(verification_url("http://web.test/device").is_err());
    }
}
