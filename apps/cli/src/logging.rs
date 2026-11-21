//! Logging setup (tracing).
//!
//! Filtering precedence (highest first):
//!   1. `WSSP_LOG` env var (e.g. `WSSP_LOG=wssp=debug,warn`)
//!   2. `RUST_LOG` env var
//!   3. `-v` / `-vv` / `--quiet` flags
//!
//! A confidentiality ceiling drops TRACE events from HTTP/WebSocket stack targets
//! (serialized requests may contain bearer tokens). It is ANDed with the user's
//! `EnvFilter` and never raises verbosity for any target.
//!
//! Logs go to **stderr** so they never corrupt machine-readable stdout (e.g.
//! `--json` output piped into `jq`).

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;
use tracing_subscriber::filter::dynamic_filter_fn;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::cli::LogFormat;

/// Product log-filter env var. Takes precedence over `RUST_LOG`.
pub const LOG_ENV: &str = "WSSP_LOG";

/// Targets whose TRACE logs may serialize HTTP requests (including Authorization).
fn http_serialization_target(target: &str) -> bool {
    target.starts_with("ureq")
        || target.starts_with("tungstenite")
        || target.starts_with("tokio_tungstenite")
        || target == "http"
        || target == "httparse"
        || target.starts_with("hyper")
        || target.starts_with("want")
        || target.starts_with("h2")
}

/// Layer filter: drop TRACE from handshake/HTTP stacks; all other events pass through to `EnvFilter`.
fn pass_confidentiality_ceiling(metadata: &tracing::Metadata<'_>) -> bool {
    if *metadata.level() != tracing::Level::TRACE {
        return true;
    }
    !http_serialization_target(metadata.target())
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

pub(crate) struct RedactingWriter<W: Write> {
    inner: W,
    buffer: Vec<u8>,
}

fn redacting_stderr_writer() -> impl Fn() -> RedactingWriter<std::io::Stderr> + Send + Sync + 'static
{
    move || RedactingWriter {
        inner: std::io::stderr(),
        buffer: Vec::new(),
    }
}

impl<W: Write> Write for RedactingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let text = String::from_utf8_lossy(&self.buffer);
        let redacted = redact_product_credentials(&text);
        self.inner.write_all(redacted.as_bytes())?;
        self.buffer.clear();
        self.inner.flush()
    }
}

impl<W: Write> Drop for RedactingWriter<W> {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

fn resolve_env_filter(verbose: u8, quiet: bool) -> EnvFilter {
    env_filter(LOG_ENV)
        .or_else(|| env_filter("RUST_LOG"))
        .unwrap_or_else(|| {
            DEFAULT_VERBOSITY.store(verbose == 0, Ordering::Relaxed);
            EnvFilter::new(default_directive(verbose, quiet))
        })
}

/// Set when the filter is the default (no `WSSP_LOG`/`RUST_LOG`, no `-v`).
static DEFAULT_VERBOSITY: AtomicBool = AtomicBool::new(false);

/// A user command's `--json` keeps stderr to its single JSON error line: at
/// the default verbosity only WARN and ERROR events pass once it is set. An
/// explicit `-v` or log filter still applies.
fn pass_json_quiet(metadata: &tracing::Metadata<'_>) -> bool {
    *metadata.level() <= tracing::Level::WARN
        || !DEFAULT_VERBOSITY.load(Ordering::Relaxed)
        || !crate::output::json_errors()
}

/// Set once a `sandbox shell` session's output writer owns stdout and
/// stderr, and kept until the process exits: every log event is dropped
/// then. An event is written on the
/// thread that emits it, and the session's connection thread (where the
/// WebSocket and TLS stacks log) must never wait on a stderr the writer is
/// blocked on.
static STDERR_HELD: AtomicBool = AtomicBool::new(false);

/// Drop every log event while `held` (see [`STDERR_HELD`]).
pub fn hold_stderr(held: bool) {
    STDERR_HELD.store(held, Ordering::SeqCst);
}

fn pass_stderr_free(_: &tracing::Metadata<'_>) -> bool {
    !STDERR_HELD.load(Ordering::SeqCst)
}

/// Build the tracing subscriber used by the binary (and tests). Does not install globally.
pub(crate) fn build_subscriber_with_filter<Mw, W>(
    format: LogFormat,
    filter: EnvFilter,
    make_writer: Mw,
    ansi: bool,
) -> Box<dyn tracing::Subscriber + Send + Sync>
where
    Mw: Fn() -> RedactingWriter<W> + Send + Sync + 'static,
    W: Write + Send + 'static,
{
    // Dynamic: `--json` is known only once the command runs.
    let ceiling = dynamic_filter_fn(|metadata, _| {
        pass_confidentiality_ceiling(metadata)
            && pass_json_quiet(metadata)
            && pass_stderr_free(metadata)
    });

    match format {
        LogFormat::Text => Box::new(
            tracing_subscriber::registry().with(filter).with(
                tracing_subscriber::fmt::layer()
                    .with_writer(make_writer)
                    .with_ansi(ansi)
                    .with_target(false)
                    .with_filter(ceiling),
            ),
        ),
        LogFormat::Json => Box::new(
            tracing_subscriber::registry().with(filter).with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_writer(make_writer)
                    .with_ansi(ansi)
                    .with_filter(ceiling),
            ),
        ),
    }
}

/// Run `f` with the production subscriber shape and a capture writer (tests).
#[cfg(test)]
pub(crate) fn with_subscriber<T>(
    format: LogFormat,
    filter: EnvFilter,
    f: impl FnOnce() -> T,
) -> (T, Vec<u8>) {
    use std::sync::{Arc, Mutex};

    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let buffer = Arc::new(Mutex::new(Vec::new()));
    let buffer_for_writer = Arc::clone(&buffer);
    let wrapped = move || RedactingWriter {
        inner: Capture(Arc::clone(&buffer_for_writer)),
        buffer: Vec::new(),
    };

    // tracing-core's single-dispatch fast path registers a new callsite
    // against the emitting thread's default. In parallel tests that thread
    // may have NO scoped subscriber, caching Interest::never even though our
    // capture is live. Keep a second dispatch alive so registration consults
    // the registry of live subscribers instead of that thread-local default.
    let _registration_guard = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
    let subscriber = build_subscriber_with_filter(format, filter, wrapped, false);
    let result = tracing::subscriber::with_default(subscriber, f);
    let captured = buffer.lock().unwrap().clone();
    (result, captured)
}

/// Initialize the global tracing subscriber. Call exactly once, early in
/// `main`. Safe to call before argument validation.
pub fn init(format: LogFormat, verbose: u8, quiet: bool) {
    let ansi = std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    let make_writer = redacting_stderr_writer();
    build_subscriber_with_filter(
        format,
        resolve_env_filter(verbose, quiet),
        make_writer,
        ansi,
    )
    .init();
}

fn env_filter(name: &str) -> Option<EnvFilter> {
    std::env::var_os(name)?;
    match EnvFilter::try_from_env(name) {
        Ok(filter) => Some(filter),
        Err(err) => {
            let _ = crate::output::diagnostic(format!(
                "warning: ignoring invalid `{name}` filter: {err}"
            ));
            None
        }
    }
}

/// Map the verbosity flags to an `EnvFilter` directive when no env var is set.
fn default_directive(verbose: u8, quiet: bool) -> String {
    if quiet {
        return "error".to_string();
    }
    match verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::Level;

    fn output_text(captured: &[u8]) -> String {
        String::from_utf8_lossy(captured).to_string()
    }

    #[test]
    fn a_callsite_first_seen_on_an_uncaptured_thread_is_still_captured() {
        fn event() {
            tracing::info!("worker capture survives uncaptured registration");
        }
        let (_, captured) = with_subscriber(LogFormat::Text, EnvFilter::new("trace"), || {
            // New threads do not inherit a scoped default. Register the SAME
            // callsite there first, just as another parallel relay test can.
            std::thread::spawn(event).join().unwrap();
            event();
        });
        assert!(output_text(&captured).contains("worker capture survives uncaptured registration"));
    }

    #[test]
    fn product_log_env_name() {
        assert_eq!(LOG_ENV, "WSSP_LOG");
    }

    #[test]
    fn redact_product_credentials_masks_all_purposes() {
        let token = "wssp_host_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk";
        let line = format!("Authorization: Bearer {token}");
        let redacted = redact_product_credentials(&line);
        assert!(!redacted.contains(token));
        assert!(redacted.contains("wssp_host_[REDACTED]"));
        assert!(redacted.contains("Authorization: Bearer"));
    }

    #[test]
    fn production_logger_redacts_tungstenite_style_trace_line() {
        use std::sync::{Arc, Mutex};

        let token = "wssp_host_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk";
        let serialized = format!(
            "Sending request\\r\\nGET /ws/sandbox-host HTTP/1.1\\r\\nAuthorization: Bearer {token}\\r\\n"
        );

        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl Write for Capture {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let buffer = Arc::new(Mutex::new(Vec::new()));
        let make_writer = {
            let buffer = Arc::clone(&buffer);
            move || RedactingWriter {
                inner: Capture(Arc::clone(&buffer)),
                buffer: Vec::new(),
            }
        };

        let subscriber = build_subscriber_with_filter(
            LogFormat::Text,
            EnvFilter::new("trace"),
            make_writer,
            false,
        );

        tracing::subscriber::with_default(subscriber, || {
            tracing::event!(
                target: "tungstenite::handshake::client",
                Level::DEBUG,
                "{serialized}"
            );
        });

        let captured = buffer.lock().unwrap();
        let output = String::from_utf8_lossy(&captured);
        assert!(!output.contains(token));
        assert!(output.contains("wssp_host_[REDACTED]"));
    }

    #[test]
    fn init_quiet_suppresses_tungstenite_debug_but_keeps_wssp_error() {
        let assert_no_tungstenite_debug = |out: &str| {
            assert!(!out.contains("Trying to contact"));
            assert!(!out.to_uppercase().contains("DEBUG"));
        };

        let (_, captured) = with_subscriber(LogFormat::Text, EnvFilter::new("error"), || {
            tracing::event!(
                target: "tungstenite::client",
                Level::DEBUG,
                "DEBUG Trying to contact ws://127.0.0.1/ws/sandbox-host"
            );
            tracing::event!(target: "wssp", Level::ERROR, "relay handshake failed: 401");
        });
        let out = output_text(&captured);
        assert_no_tungstenite_debug(&out);
        assert!(out.contains("relay handshake failed"));

        let (_, captured) = with_subscriber(LogFormat::Text, EnvFilter::new("off"), || {
            tracing::event!(
                target: "tungstenite::client",
                Level::DEBUG,
                "DEBUG Trying to contact ws://127.0.0.1/ws/sandbox-host"
            );
            tracing::event!(target: "wssp", Level::ERROR, "relay handshake failed: 401");
        });
        assert_no_tungstenite_debug(&output_text(&captured));
    }

    #[test]
    fn init_default_info_suppresses_tungstenite_debug() {
        let (_, captured) = with_subscriber(LogFormat::Text, EnvFilter::new("info"), || {
            tracing::event!(
                target: "tungstenite::client",
                Level::DEBUG,
                "DEBUG Trying to contact ws://127.0.0.1/ws/sandbox-host"
            );
        });
        let out = output_text(&captured);
        assert!(!out.contains("Trying to contact"));
    }

    #[test]
    fn init_trace_drops_tungstenite_trace_but_keeps_wssp_trace() {
        let filter =
            EnvFilter::try_new("trace,tungstenite::handshake::client=trace").expect("valid filter");
        let token = "wssp_host_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk";
        let (_, captured) = with_subscriber(LogFormat::Text, filter, || {
            tracing::event!(
                target: "tungstenite::handshake::client",
                Level::TRACE,
                "Request: Authorization: Bearer {token}"
            );
            tracing::event!(target: "wssp", Level::TRACE, "connect trace diagnostic");
        });
        let out = output_text(&captured);
        assert!(!out.contains(token));
        assert!(!out.contains("Authorization: Bearer"));
        assert!(out.contains("connect trace diagnostic"));
    }

    #[test]
    fn init_json_quiet_suppresses_tungstenite_debug_but_keeps_wssp_error() {
        let assert_no_tungstenite_debug = |out: &str| {
            assert!(!out.contains("Trying to contact"));
            assert!(!out.contains("\"level\":\"DEBUG\""));
        };

        let (_, captured) = with_subscriber(LogFormat::Json, EnvFilter::new("error"), || {
            tracing::event!(
                target: "tungstenite::client",
                Level::DEBUG,
                "DEBUG Trying to contact ws://127.0.0.1/ws/sandbox-host"
            );
            tracing::event!(target: "wssp", Level::ERROR, "relay handshake failed: 401");
        });
        let out = output_text(&captured);
        assert_no_tungstenite_debug(&out);
        assert!(out.contains("relay handshake failed"));

        let (_, captured) = with_subscriber(LogFormat::Json, EnvFilter::new("off"), || {
            tracing::event!(
                target: "tungstenite::client",
                Level::DEBUG,
                "DEBUG Trying to contact ws://127.0.0.1/ws/sandbox-host"
            );
            tracing::event!(target: "wssp", Level::ERROR, "relay handshake failed: 401");
        });
        assert_no_tungstenite_debug(&output_text(&captured));
    }

    #[test]
    fn init_json_trace_drops_tungstenite_trace_but_keeps_wssp_trace() {
        let filter =
            EnvFilter::try_new("trace,tungstenite::handshake::client=trace").expect("valid filter");
        let token = "wssp_host_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk";
        let (_, captured) = with_subscriber(LogFormat::Json, filter, || {
            tracing::event!(
                target: "tungstenite::handshake::client",
                Level::TRACE,
                "Request: Authorization: Bearer {token}"
            );
            tracing::event!(target: "wssp", Level::TRACE, "connect trace diagnostic");
        });
        let out = output_text(&captured);
        assert!(!out.contains(token));
        assert!(!out.contains("Authorization: Bearer"));
        assert!(out.contains("connect trace diagnostic"));
    }
}

#[cfg(test)]
mod agent_token_tests {
    #[test]
    fn agent_credentials_are_scrubbed() {
        assert_eq!(
            super::redact_product_credentials("prefix wssp_agent_fixture-token suffix"),
            "prefix wssp_agent_[REDACTED] suffix"
        );
    }
}
