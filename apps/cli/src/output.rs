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
    writeln!(out, "{}", redact_product_credentials(&text.to_string())).context("writing to stdout")
}

/// Write human-readable command output to stdout without appending a newline.
pub fn text(text: impl std::fmt::Display) -> Result<()> {
    let mut out = io::stdout().lock();
    write!(out, "{}", redact_product_credentials(&text.to_string())).context("writing to stdout")
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
    out.write_all(redact_product_credentials(&json).as_bytes())
        .context("writing JSON output")?;
    writeln!(out).context("writing to stdout")
}

/// One JSON object as a stdout line [`json`] would write (for a writer of
/// its own, such as `sandbox forward`'s line writer).
pub fn json_line<T: Serialize>(value: &T) -> Result<String> {
    Ok(redact_product_credentials(&encode(value)?))
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
    writeln!(err, "{}", redact_product_credentials(&text.to_string())).context("writing to stderr")
}

/// Write a non-fatal warning to stderr.
pub fn warning(text: impl std::fmt::Display) -> Result<()> {
    diagnostic(format!("warning: {text}"))
}

/// Untrusted server text is bounded, stripped of terminal controls, and redacted.
pub fn remote_message(text: &str) -> String {
    redact_product_credentials(text)
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

fn product_credential_secret_len(rest: &str) -> usize {
    rest.chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .map(|c| c.len_utf8())
        .sum()
}

/// Redact product credential patterns from formatted log output.
pub fn redact_product_credentials(message: &str) -> String {
    const PREFIXES: [(&str, &str); 4] = [
        ("wssp_host_", "wssp_host_[REDACTED]"),
        ("wssp_device_", "wssp_device_[REDACTED]"),
        ("wssp_sdk_", "wssp_sdk_[REDACTED]"),
        ("wssp_agent_", "wssp_agent_[REDACTED]"),
    ];

    let mut out = String::with_capacity(message.len());
    let mut index = 0;
    while index < message.len() {
        let slice = &message[index..];
        let mut matched = false;
        for (prefix, replacement) in PREFIXES {
            if let Some(rest) = slice.strip_prefix(prefix) {
                let secret_len = product_credential_secret_len(rest);
                if secret_len > 0 {
                    out.push_str(replacement);
                    index += prefix.len() + secret_len;
                    matched = true;
                    break;
                }
            }
        }
        if matched {
            continue;
        }
        let ch = slice.chars().next().expect("char");
        out.push(ch);
        index += ch.len_utf8();
    }
    out
}

#[cfg(test)]
mod redaction_tests {
    #[test]
    fn redact_product_credentials_masks_all_purposes() {
        let token = "wssp_host_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk";
        let line = format!("Authorization: Bearer {token}");
        let redacted = super::redact_product_credentials(&line);
        assert!(!redacted.contains(token));
        assert!(redacted.contains("wssp_host_[REDACTED]"));
        assert!(redacted.contains("Authorization: Bearer"));
    }

    #[test]
    fn agent_credentials_are_scrubbed() {
        assert_eq!(
            super::redact_product_credentials("prefix wssp_agent_fixture-token suffix"),
            "prefix wssp_agent_[REDACTED] suffix"
        );
    }
}
