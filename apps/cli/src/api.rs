//! `/v1` HTTP client for the user commands (`wssp sandbox …`, `wssp template
//! …`, `wssp whoami`, `wssp logout`).
//!
//! Same transport rules as the device flow (`src/auth.rs`): HTTPS, or
//! cleartext only on loopback (then without a proxy); the extra CA trust of
//! `crate::tls`; no redirects; bounded timeouts and bodies. Every request
//! carries `Authorization: Bearer wssp_sdk_…` and nothing else identifying.
//!
//! A non-2xx answer becomes an [`ApiError`] (the `/v1` error envelope of
//! packages/sandbox-contracts/src/errors.ts) with a [`CodedError`] for its
//! exit code; see [`exit_code_for`].

use std::io::Read;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::exit::{CodedError, ExitCode};
use crate::user_state::UserCredential;

/// A plain request; held reads add their hold to this.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest JSON answer accepted (a full sandbox page is well below this).
const JSON_BODY_MAX_BYTES: u64 = 8 * 1024 * 1024;
/// Error bodies are read only this far.
const ERROR_BODY_MAX_BYTES: u64 = 64 * 1024;
/// Upper bound of one download (`TRANSFER_MAX_BYTES`).
pub const TRANSFER_MAX_BYTES: u64 = 1024 * 1024 * 1024;
/// Longest server hold of one long-poll read (`OPERATION_WAIT_MAX_MS`).
pub const WAIT_MAX_MS: u64 = 25_000;
/// The hold this client asks for on long-poll reads.
pub const WAIT_MS: u64 = 20_000;

/// One `/v1` error answer.
#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: u16,
    pub code: String,
    pub message: String,
    /// The envelope's `data`, else its other typed fields; `None` when bare.
    pub data: Option<Value>,
    pub retry_after_seconds: Option<u64>,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "`{}`: {}", self.code, self.message)
    }
}

impl std::error::Error for ApiError {}

impl ApiError {
    pub fn exit_code(&self) -> ExitCode {
        exit_code_for(self.status, &self.code)
    }
}

/// Codes that mean "a limit was reached" (exit 9) rather than a plain conflict.
pub fn is_limit_code(code: &str) -> bool {
    matches!(
        code,
        "sandbox.key_limit_reached"
            | "sandbox.capacity_queue_full"
            | "template.build_concurrency"
            | "template.build_minutes_exhausted"
    ) || code.contains("quota")
        || code.ends_with("limit")
        || code.ends_with("limit_reached")
}

/// The exit code of a `/v1` answer (README "Exit codes").
pub fn exit_code_for(status: u16, code: &str) -> ExitCode {
    match status {
        401 => ExitCode::NotLoggedIn,
        403 => ExitCode::Forbidden,
        409 if is_limit_code(code) => ExitCode::LimitReached,
        409 => ExitCode::Conflict,
        429 | 503 | 504 => ExitCode::Retryable,
        404 => ExitCode::NotFound,
        400 | 413 | 415 => ExitCode::Usage,
        _ => ExitCode::Failure,
    }
}

fn status_code_name(status: u16) -> &'static str {
    match status {
        400 => "BAD_REQUEST",
        401 => "UNAUTHORIZED",
        403 => "FORBIDDEN",
        404 => "NOT_FOUND",
        405 => "METHOD_NOT_SUPPORTED",
        409 => "CONFLICT",
        413 => "PAYLOAD_TOO_LARGE",
        415 => "UNSUPPORTED_MEDIA_TYPE",
        429 => "TOO_MANY_REQUESTS",
        502 => "BAD_GATEWAY",
        503 => "SERVICE_UNAVAILABLE",
        504 => "GATEWAY_TIMEOUT",
        _ => "HTTP_ERROR",
    }
}

/// Parse a `/v1` error body; a body that is not the envelope (a proxy page)
/// keeps only its status.
pub fn parse_error(status: u16, body: &str, retry_after: Option<u64>) -> ApiError {
    let bare = || ApiError {
        status,
        code: status_code_name(status).to_owned(),
        message: format!("the server answered HTTP {status}"),
        data: None,
        retry_after_seconds: retry_after,
    };
    let Ok(Value::Object(mut root)) = serde_json::from_str::<Value>(body) else {
        return bare();
    };
    let Some(Value::Object(mut error)) = root.remove("error") else {
        return bare();
    };
    let Some(Value::String(code)) = error.remove("code") else {
        return bare();
    };
    let message = match error.remove("message") {
        Some(Value::String(message)) => message,
        _ => String::new(),
    };
    error.remove("requestId");
    let retry_after_seconds = error
        .get("retryAfterSeconds")
        .and_then(Value::as_u64)
        .or(retry_after);
    let data = match error.remove("data") {
        Some(data) => Some(data),
        None if error.is_empty() => None,
        None => Some(Value::Object(error)),
    };
    ApiError {
        status,
        code: crate::output::remote_message(&code),
        message: crate::output::remote_message(&message),
        data,
        retry_after_seconds,
    }
}

/// Wrap an [`ApiError`] with its exit code.
pub fn into_error(error: ApiError) -> anyhow::Error {
    let code = error.exit_code();
    anyhow::Error::new(error).context(CodedError::new(code))
}

/// The first [`ApiError`] in an error chain.
pub fn api_error_of(err: &anyhow::Error) -> Option<&ApiError> {
    err.chain()
        .find_map(|cause| cause.downcast_ref::<ApiError>())
}

/// Whether an error is worth retrying unchanged: 429/503/504, or a transport
/// failure that a later attempt can cure (a timeout after the name resolved,
/// a refused, reset or dropped connection). TLS and certificate failures, DNS
/// failures, invalid URLs, redirects and protocol errors fail at once.
pub fn is_transient(err: &anyhow::Error) -> bool {
    if let Some(error) = api_error_of(err) {
        return matches!(error.status, 429 | 503 | 504);
    }
    err.chain().any(|cause| {
        cause
            .downcast_ref::<ureq::Error>()
            .is_some_and(is_transient_transport)
    })
}

fn is_transient_transport(error: &ureq::Error) -> bool {
    use std::io::ErrorKind;
    match error {
        ureq::Error::Timeout(timeout) => !matches!(timeout, ureq::Timeout::Resolve),
        ureq::Error::ConnectionFailed => true,
        ureq::Error::Io(io) => matches!(
            io.kind(),
            ErrorKind::ConnectionRefused
                | ErrorKind::ConnectionReset
                | ErrorKind::ConnectionAborted
                | ErrorKind::BrokenPipe
                | ErrorKind::UnexpectedEof
                | ErrorKind::TimedOut
                | ErrorKind::Interrupted
        ),
        _ => false,
    }
}

/// A fresh idempotency key (UUID v4 shape).
pub fn idempotency_key() -> Result<String> {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut bytes = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("generating an idempotency key"))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

/// `202` receipt of an accepted mutation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MutationReceipt {
    pub operation_id: String,
    pub state: String,
    pub location: String,
}

/// HTTP methods this client sends.
#[derive(Debug, Clone, Copy)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
}

impl Method {
    fn http(self) -> ureq::http::Method {
        match self {
            Self::Get => ureq::http::Method::GET,
            Self::Post => ureq::http::Method::POST,
            Self::Put => ureq::http::Method::PUT,
            Self::Delete => ureq::http::Method::DELETE,
        }
    }
}

/// A body to send.
pub enum Body<'a> {
    None,
    /// Encoded JSON (see [`encode_body`]).
    Json(&'a [u8]),
    Chunk {
        bytes: &'a [u8],
        offset: u64,
        total: u64,
    },
}

/// The one encoder of `/v1` request bodies (typed request DTOs, never relay frames).
pub fn encode_body<B: Serialize + ?Sized>(body: &B) -> Result<Vec<u8>> {
    serde_json::to_vec(body).context("encoding the request body")
}

/// Streamed download answer: verified length and SHA-256 (from its ETag).
pub struct Downloaded {
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone)]
pub struct Client {
    origin: String,
    secret: String,
    trust: crate::tls::Trust,
    direct: bool,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

impl Client {
    pub fn new(credential: &UserCredential) -> Result<Self> {
        let origin = crate::auth::canonical_control_plane_origin(&credential.origin)?;
        Ok(Self {
            direct: crate::auth::direct_loopback_cleartext(&origin)?,
            trust: credential.trust()?,
            secret: credential.secret.clone(),
            origin,
        })
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    fn agent(&self, timeout: Duration) -> ureq::Agent {
        let mut builder = ureq::Agent::config_builder()
            .max_redirects(0)
            .http_status_as_error(false)
            .timeout_global(Some(timeout))
            .timeout_resolve(Some(Duration::from_secs(10)))
            .timeout_connect(Some(Duration::from_secs(10)));
        if self.direct {
            builder = builder.proxy(None);
        }
        self.trust.http_agent(builder.build())
    }

    fn url(&self, path: &str, query: &[(&str, String)]) -> Result<url::Url> {
        anyhow::ensure!(path.starts_with("/v1/"), "invalid API path");
        let mut url = crate::auth::control_plane_url(&self.origin)?.join(path)?;
        if !query.is_empty() {
            let mut pairs = url.query_pairs_mut();
            for (key, value) in query {
                pairs.append_pair(key, value);
            }
        }
        Ok(url)
    }

    /// Send one request; a 2xx answer is returned with its body unread.
    fn exchange(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Body<'_>,
        idempotency_key: Option<&str>,
        timeout: Duration,
    ) -> Result<ureq::http::Response<ureq::Body>> {
        let url = self.url(path, query)?;
        let mut request = ureq::http::Request::builder()
            .method(method.http())
            .uri(url.as_str())
            .header("Authorization", format!("Bearer {}", self.secret));
        if let Some(key) = idempotency_key {
            request = request.header("Idempotency-Key", key);
        }
        let payload: Vec<u8> = match body {
            Body::None => {
                request = request.header("Accept", "application/json");
                Vec::new()
            }
            Body::Json(bytes) => {
                request = request
                    .header("Accept", "application/json")
                    .header("Content-Type", "application/json");
                bytes.to_vec()
            }
            Body::Chunk {
                bytes,
                offset,
                total,
            } => {
                let end = (offset + bytes.len() as u64).saturating_sub(1);
                request = request
                    .header("Accept", "application/json")
                    .header("Content-Type", "application/octet-stream")
                    .header("Content-Range", format!("bytes {offset}-{end}/{total}"));
                bytes.to_vec()
            }
        };
        let request = request.body(payload).context("building the request")?;
        let mut response = self
            .agent(timeout)
            .run(request)
            .map_err(|error| crate::tls::control_plane_error(&self.origin, error))
            .with_context(|| format!("request to `{}` failed", self.origin))?;
        let status = response.status().as_u16();
        if (200..300).contains(&status) {
            return Ok(response);
        }
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok());
        let text = response
            .body_mut()
            .with_config()
            .limit(ERROR_BODY_MAX_BYTES)
            .read_to_string()
            .unwrap_or_default();
        Err(into_error(parse_error(status, &text, retry_after)))
    }

    /// One JSON request and its JSON answer.
    pub fn request<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Body<'_>,
        idempotency_key: Option<&str>,
        timeout: Duration,
    ) -> Result<T> {
        let mut response = self.exchange(method, path, query, body, idempotency_key, timeout)?;
        let text = response
            .body_mut()
            .with_config()
            .limit(JSON_BODY_MAX_BYTES)
            .read_to_string()
            .context("reading the server answer")?;
        serde_json::from_str(&text).context("parsing the server answer")
    }

    pub fn get<T: DeserializeOwned>(&self, path: &str, query: &[(&str, String)]) -> Result<T> {
        self.request(Method::Get, path, query, Body::None, None, REQUEST_TIMEOUT)
    }

    /// A long-poll read held up to `wait_ms` by the server.
    pub fn get_held<T: DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, String)],
        wait_ms: u64,
    ) -> Result<T> {
        let wait_ms = wait_ms.min(WAIT_MAX_MS);
        let mut query = query.to_vec();
        if wait_ms > 0 {
            query.push(("waitMs", wait_ms.to_string()));
        }
        self.request(
            Method::Get,
            path,
            &query,
            Body::None,
            None,
            REQUEST_TIMEOUT + Duration::from_millis(wait_ms),
        )
    }

    /// A JSON request without an idempotency key (resource routes).
    pub fn send<T: DeserializeOwned, B: Serialize + ?Sized>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<T> {
        let bytes = body.map(encode_body).transpose()?;
        let body = bytes.as_deref().map_or(Body::None, Body::Json);
        self.request(method, path, &[], body, None, REQUEST_TIMEOUT)
    }

    /// An idempotent mutation: one key, re-sent unchanged while the answer is
    /// transient (429/503/504 or none), so a lost answer never doubles the
    /// action.
    pub fn mutate<T: DeserializeOwned, B: Serialize + ?Sized>(
        &self,
        method: Method,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let body = encode_body(body)?;
        let key = idempotency_key()?;
        retry_transient(Instant::now() + Duration::from_secs(120), || {
            self.request(
                method,
                path,
                &[],
                Body::Json(&body),
                Some(&key),
                REQUEST_TIMEOUT,
            )
        })
    }

    /// One upload chunk (`PUT /v1/transfers/{id}`), replay-safe.
    pub fn put_chunk(&self, path: &str, bytes: &[u8], offset: u64, total: u64) -> Result<Value> {
        retry_transient(Instant::now() + Duration::from_secs(120), || {
            self.request(
                Method::Put,
                path,
                &[],
                Body::Chunk {
                    bytes,
                    offset,
                    total,
                },
                None,
                REQUEST_TIMEOUT + Duration::from_secs(90),
            )
        })
    }

    /// Stream a completed capture (`GET /v1/operations/{id}/content`) into
    /// `out`, verifying its length and the SHA-256 of its strong ETag.
    pub fn download(&self, path: &str, out: &mut dyn std::io::Write) -> Result<Downloaded> {
        let mut response = self.exchange(
            Method::Get,
            path,
            &[],
            Body::None,
            None,
            Duration::from_secs(3600),
        )?;
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        let expected = header("etag")
            .map(|etag| etag.trim_matches('"').to_ascii_lowercase())
            .filter(|sha| sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit()))
            .context("the download is missing its SHA-256 ETag")?;
        let length = header("content-length").and_then(|v| v.parse::<u64>().ok());
        let mut reader = response
            .body_mut()
            .with_config()
            .limit(TRANSFER_MAX_BYTES)
            .reader();
        let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
        let mut buffer = vec![0_u8; 64 * 1024];
        let mut total = 0_u64;
        loop {
            let n = reader.read(&mut buffer).context("reading the download")?;
            if n == 0 {
                break;
            }
            digest.update(&buffer[..n]);
            out.write_all(&buffer[..n])
                .context("writing the downloaded bytes")?;
            total += n as u64;
        }
        if let Some(length) = length {
            anyhow::ensure!(
                length == total,
                "the download ended after {total} of {length} bytes"
            );
        }
        let sha256 = hex(digest.finish().as_ref());
        anyhow::ensure!(
            sha256 == expected,
            "the downloaded bytes do not match their SHA-256"
        );
        Ok(Downloaded {
            bytes: total,
            sha256,
        })
    }
}

/// Decode standard padded base64 (command output chunks).
pub fn decode_base64(text: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut buffer = 0_u32;
    let mut bits = 0_u32;
    let mut padding = false;
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                padding = true;
                continue;
            }
            _ => anyhow::bail!("invalid base64 in the server answer"),
        };
        anyhow::ensure!(!padding, "invalid base64 in the server answer");
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

/// An operation that ended without success (`GET /v1/operations/{id}`).
#[derive(Debug, Clone)]
pub struct OperationError {
    pub operation_id: String,
    /// `failed`, `cancelled` or `unknown`.
    pub outcome: String,
    pub state: String,
    pub error_code: Option<String>,
}

impl std::fmt::Display for OperationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (&self.error_code, self.outcome.as_str()) {
            (_, "unknown") => write!(
                f,
                "operation `{}` has an unknown outcome: the server cannot tell whether it took effect; check the resource before retrying",
                self.operation_id
            ),
            (Some(code), outcome) => {
                write!(f, "operation `{}` {outcome}: `{code}`", self.operation_id)
            }
            (None, outcome) => write!(f, "operation `{}` {outcome}", self.operation_id),
        }
    }
}

impl std::error::Error for OperationError {}

impl OperationError {
    /// The JSON error code: the operation's error code, else its outcome.
    pub fn code(&self) -> String {
        self.error_code
            .clone()
            .unwrap_or_else(|| format!("operation.{}", self.outcome))
    }

    pub fn exit_code(&self) -> ExitCode {
        match self.error_code.as_deref() {
            Some("fs_not_found") => ExitCode::NotFound,
            Some("fs_permission_denied") => ExitCode::Forbidden,
            _ => ExitCode::Failure,
        }
    }
}

/// The first [`OperationError`] in an error chain.
pub fn operation_error_of(err: &anyhow::Error) -> Option<&OperationError> {
    err.chain()
        .find_map(|cause| cause.downcast_ref::<OperationError>())
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// First locally generated backoff; it doubles up to [`MAX_BACKOFF`].
pub const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
/// Cap of the locally generated backoff (never of a server-requested delay).
pub const MAX_BACKOFF: Duration = Duration::from_secs(16);

/// The wait before retrying `error`, or `None` when it must be returned: it
/// is not transient, or its wait would end at or after `deadline`. A delay
/// the server requested (`retryAfterSeconds`, `Retry-After`) is honored
/// exactly, never shortened; only the local `backoff` is capped, and it
/// advances only when it was used.
pub fn retry_delay(
    error: &anyhow::Error,
    backoff: &mut Duration,
    now: Instant,
    deadline: Instant,
) -> Option<Duration> {
    if !is_transient(error) {
        return None;
    }
    let requested = api_error_of(error)
        .and_then(|e| e.retry_after_seconds)
        .map(Duration::from_secs);
    let delay = requested.unwrap_or(*backoff);
    if requested.is_none() {
        *backoff = (*backoff * 2).min(MAX_BACKOFF);
    }
    match now.checked_add(delay) {
        Some(at) if at < deadline => Some(delay),
        _ => None,
    }
}

/// Sleep `delay` in short slices; `false` as soon as `interrupted` holds.
pub fn sleep_unless(delay: Duration, interrupted: &dyn Fn() -> bool) -> bool {
    let until = Instant::now() + delay;
    loop {
        if interrupted() {
            return false;
        }
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return true;
        }
        std::thread::sleep(left.min(Duration::from_millis(50)));
    }
}

/// Retry `attempt` while it fails transiently (see [`retry_delay`]) until
/// `deadline`; a wait that would outlast the deadline returns the error.
pub fn retry_transient<T>(deadline: Instant, mut attempt: impl FnMut() -> Result<T>) -> Result<T> {
    let mut backoff = INITIAL_BACKOFF;
    loop {
        match attempt() {
            Ok(value) => return Ok(value),
            Err(error) => {
                let Some(delay) = retry_delay(&error, &mut backoff, Instant::now(), deadline)
                else {
                    return Err(error);
                };
                tracing::debug!(?delay, "retrying a transient /v1 answer");
                std::thread::sleep(delay);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_statuses_and_codes_to_exit_codes() {
        assert_eq!(exit_code_for(401, "UNAUTHORIZED"), ExitCode::NotLoggedIn);
        assert_eq!(exit_code_for(403, "FORBIDDEN"), ExitCode::Forbidden);
        for code in [
            "sandbox.key_limit_reached",
            "sandbox.capacity_queue_full",
            "sandbox.share_quota",
            "sandbox.tunnel_quota",
            "host_queue.limit",
            "credential.limit_reached",
        ] {
            assert_eq!(exit_code_for(409, code), ExitCode::LimitReached, "{code}");
        }
        // A full queue or store answers 429: retry later, not a fixed limit.
        assert_eq!(exit_code_for(429, "TRANSFER_QUOTA"), ExitCode::Retryable);
        assert_eq!(
            exit_code_for(409, "sandbox.state_conflict"),
            ExitCode::Conflict
        );
        for status in [429, 503, 504] {
            assert_eq!(exit_code_for(status, "X"), ExitCode::Retryable);
        }
        assert_eq!(exit_code_for(404, "sandbox.not_found"), ExitCode::NotFound);
        for status in [400, 413, 415] {
            assert_eq!(exit_code_for(status, "X"), ExitCode::Usage);
        }
        assert_eq!(
            exit_code_for(400, "sandbox.tunnel_ports_limit"),
            ExitCode::Usage
        );
        assert_eq!(exit_code_for(500, "X"), ExitCode::Failure);
    }

    #[test]
    fn parses_the_error_envelope_and_survives_other_bodies() {
        let body = serde_json::json!({"error":{"code":"sandbox.key_limit_reached","message":"This key's live sandbox limit is reached.","requestId":"00000000-0000-4000-8000-000000000000","data":{"maxLiveSandboxes":1,"liveSandboxes":1}}}).to_string();
        let error = parse_error(409, &body, None);
        assert_eq!(
            error.to_string(),
            "`sandbox.key_limit_reached`: This key's live sandbox limit is reached."
        );
        assert_eq!(
            error.data,
            Some(serde_json::json!({"maxLiveSandboxes":1,"liveSandboxes":1}))
        );
        let body = serde_json::json!({"error":{"code":"sandbox.pool_full","message":"m","requestId":"x","retryable":true,"retryAfterSeconds":5,"reason":"members"}}).to_string();
        let error = parse_error(409, &body, None);
        assert_eq!(error.retry_after_seconds, Some(5));
        assert_eq!(error.data.unwrap()["reason"], "members");
        let error = parse_error(503, "<html>bad gateway</html>", Some(3));
        assert_eq!(error.code, "SERVICE_UNAVAILABLE");
        assert_eq!(error.retry_after_seconds, Some(3));
        assert_eq!(error.exit_code(), ExitCode::Retryable);
    }

    #[test]
    fn retries_only_transient_transport_failures() {
        use std::io::{Error as IoError, ErrorKind};
        let wrap = |error: ureq::Error| anyhow::Error::new(error).context("request failed");
        for transient in [
            ureq::Error::Timeout(ureq::Timeout::Global),
            ureq::Error::Timeout(ureq::Timeout::Connect),
            ureq::Error::ConnectionFailed,
            ureq::Error::Io(IoError::from(ErrorKind::ConnectionReset)),
            ureq::Error::Io(IoError::from(ErrorKind::ConnectionRefused)),
        ] {
            assert!(is_transient(&wrap(transient)));
        }
        for permanent in [
            ureq::Error::Timeout(ureq::Timeout::Resolve),
            ureq::Error::HostNotFound,
            ureq::Error::Tls("bad certificate"),
            ureq::Error::BadUri("x".into()),
            ureq::Error::RedirectFailed,
            ureq::Error::TooManyRedirects,
            ureq::Error::Io(IoError::new(ErrorKind::InvalidData, "corrupt tls record")),
        ] {
            assert!(!is_transient(&wrap(permanent)));
        }
        assert!(is_transient(&into_error(parse_error(503, "", None))));
        assert!(!is_transient(&into_error(parse_error(500, "", None))));
    }

    #[test]
    fn honors_server_requested_delays_exactly_and_caps_only_local_backoff() {
        let now = Instant::now();
        let far = now + Duration::from_secs(3600);
        let busy = |retry: Option<u64>| into_error(parse_error(503, "", retry));
        // A server-requested 90 s wait is not shortened to 30 s.
        let mut backoff = INITIAL_BACKOFF;
        assert_eq!(
            retry_delay(&busy(Some(90)), &mut backoff, now, far),
            Some(Duration::from_secs(90))
        );
        assert_eq!(
            backoff, INITIAL_BACKOFF,
            "a server delay leaves the backoff"
        );
        // A wait the deadline cannot fit returns the error instead.
        let soon = now + Duration::from_secs(60);
        assert_eq!(retry_delay(&busy(Some(90)), &mut backoff, now, soon), None);
        assert_eq!(
            retry_delay(&busy(Some(u64::MAX)), &mut backoff, now, far),
            None
        );
        // Local backoff doubles up to its cap.
        let delays: Vec<u64> = (0..7)
            .map(|_| {
                retry_delay(&busy(None), &mut backoff, now, far)
                    .unwrap()
                    .as_secs()
            })
            .collect();
        assert_eq!(delays, [1, 2, 4, 8, 16, 16, 16]);
        // Not transient: never retried.
        let mut backoff = INITIAL_BACKOFF;
        assert_eq!(
            retry_delay(
                &into_error(parse_error(500, "", Some(1))),
                &mut backoff,
                now,
                far
            ),
            None
        );
    }

    #[test]
    fn decodes_base64() {
        assert_eq!(decode_base64("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(decode_base64("aGk=").unwrap(), b"hi");
        assert_eq!(decode_base64("").unwrap(), b"");
        assert!(decode_base64("a=b").is_err());
        assert!(decode_base64("a*").is_err());
    }

    #[test]
    fn idempotency_keys_are_fresh_uuids() {
        let a = idempotency_key().unwrap();
        let b = idempotency_key().unwrap();
        assert_ne!(a, b);
        assert_eq!(a.len(), 36);
        assert_eq!(&a[14..15], "4");
    }
}
