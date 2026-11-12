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

/// Serialize a typed value as one JSON object to stdout.
pub fn json<T: Serialize>(value: &T) -> Result<()> {
    let mut out = io::stdout().lock();
    let json = serde_json::to_string(value).context("serializing JSON output")?;
    out.write_all(crate::logging::redact_product_credentials(&json).as_bytes())
        .context("writing JSON output")?;
    writeln!(out).context("writing to stdout")
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
