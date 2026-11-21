//! Helpers for writing command output.
//!
//! Command results go to stdout; logs and diagnostics go to stderr. Keeping the
//! stdout writes behind tiny helpers gives new commands one obvious pattern for
//! human-readable and machine-readable output.

use std::io::{self, Write};

use anyhow::{Context, Result};
use serde::Serialize;

/// Write a line of human-readable command output to stdout.
pub fn line(text: impl std::fmt::Display) -> Result<()> {
    let mut out = io::stdout().lock();
    writeln!(
        out,
        "{}",
        crate::logging::redact_product_credentials(&text.to_string())
    )
    .context("writing to stdout")
}

/// Write human-readable command output to stdout without appending a newline.
pub fn text(text: impl std::fmt::Display) -> Result<()> {
    let mut out = io::stdout().lock();
    write!(
        out,
        "{}",
        crate::logging::redact_product_credentials(&text.to_string())
    )
    .context("writing to stdout")
}

/// Write raw command output to stdout.
pub fn bytes(bytes: &[u8]) -> Result<()> {
    let mut out = io::stdout().lock();
    out.write_all(bytes).context("writing to stdout")
}

/// Write raw bytes to stdout and flush them under one lock, so no other
/// thread can take the lock while bytes are buffered.
pub fn bytes_flushed(bytes: &[u8]) -> Result<()> {
    let mut out = io::stdout().lock();
    out.write_all(bytes).context("writing to stdout")?;
    out.flush().context("flushing stdout")
}

/// Write raw bytes to stderr (a guest command's stderr stream).
pub fn stderr_bytes(bytes: &[u8]) -> Result<()> {
    let mut err = io::stderr().lock();
    err.write_all(bytes).context("writing to stderr")?;
    err.flush().context("flushing stderr")
}

/// Serialize a typed value as one JSON object to stdout.
pub fn json<T: Serialize>(value: &T) -> Result<()> {
    let json = encode(value)?;
    let mut out = io::stdout().lock();
    out.write_all(crate::logging::redact_product_credentials(&json).as_bytes())
        .context("writing JSON output")?;
    writeln!(out).context("writing to stdout")
}

/// The one JSON encoder of command output (stdout documents, stderr error lines).
fn encode<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).context("serializing JSON output")
}

/// Flush stdout before exiting the process explicitly.
pub fn flush_stdout() -> Result<()> {
    io::stdout().lock().flush().context("flushing stdout")
}

/// Write a diagnostic line to stderr.
pub fn diagnostic(text: impl std::fmt::Display) -> Result<()> {
    let mut err = io::stderr().lock();
    writeln!(
        err,
        "{}",
        crate::logging::redact_product_credentials(&text.to_string())
    )
    .context("writing to stderr")
}

/// Write a non-fatal warning to stderr.
pub fn warning(text: impl std::fmt::Display) -> Result<()> {
    diagnostic(format!("warning: {text}"))
}

/// Untrusted server text is bounded, stripped of terminal controls, and redacted.
pub fn remote_message(text: &str) -> String {
    crate::logging::redact_product_credentials(text)
        .chars()
        .filter(|c| !c.is_control())
        .take(512)
        .collect()
}

static JSON_ERRORS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// A user command with `--json` reports its failure as one JSON line on
/// stderr instead of `error: …` (stdout stays command output only).
pub fn set_json_errors(enabled: bool) {
    JSON_ERRORS.store(enabled, std::sync::atomic::Ordering::Relaxed);
}

pub fn json_errors() -> bool {
    JSON_ERRORS.load(std::sync::atomic::Ordering::Relaxed)
}

#[derive(Serialize)]
struct ErrorLine<'a> {
    error: ErrorBody<'a>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    code: &'a str,
    status: Option<u16>,
    message: &'a str,
    data: Option<&'a serde_json::Value>,
}

/// Write `{"error":{"code","status","message","data"}}` to stderr.
pub fn json_error(
    code: &str,
    status: Option<u16>,
    message: &str,
    data: Option<&serde_json::Value>,
) -> Result<()> {
    diagnostic(json_error_line(code, status, message, data)?)
}

/// The `{"error":{"code","status","message","data"}}` line [`json_error`]
/// writes.
pub fn json_error_line(
    code: &str,
    status: Option<u16>,
    message: &str,
    data: Option<&serde_json::Value>,
) -> Result<String> {
    encode(&ErrorLine {
        error: ErrorBody {
            code,
            status,
            message,
            data,
        },
    })
}
