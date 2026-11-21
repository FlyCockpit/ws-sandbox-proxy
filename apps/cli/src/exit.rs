//! Process exit codes.
//!
//! A CLI's exit code is part of its contract with scripts and daemons. Keep
//! these stable and documented. The convention here:
//!
//!   0  success
//!   1  generic runtime error (the default for any `anyhow::Error`)
//!   2  usage error (clap emits this automatically for bad arguments)
//!   3  the requested resource was not found
//!   4  host credential inactive (4003 close, upgrade 401/403) — terminal
//!   5  sandbox relay internal error (1011 close) — retryable
//!   6  this device is not an enrolled host (a `wssp host` command that needs
//!      an enrollment; run `wssp host enroll`)
//!   7  not logged in: no user login (`wssp login`), or the server answered 401
//!   8  forbidden: the server answered 403 (the login's scopes or pools do not
//!      allow the action)
//!   9  a limit was reached: `sandbox.key_limit_reached`, a quota or
//!      `sandbox.capacity_queue_full`
//!  10  conflict: any other 409 (state conflict, name taken, …)
//!  11  retryable: the server answered 429, 503 or 504; retry later
//! 130  interrupted (Ctrl-C) while `wssp sandbox exec` followed a command; its
//!      cancellation was requested (`wssp sandbox shell` without a tty: a
//!      second Ctrl-C within 2 s closed the channel)
//! 125  `wssp sandbox exec` and `wssp sandbox shell` only: wssp itself failed,
//!      the session was ended on the wssp side, or the command's outcome is
//!      unknown (the guest's own exit code is passed through otherwise; a
//!      `shell` death by signal N exits 128 + N)
//! 141  stdout closed early (128 + SIGPIPE): `wssp sandbox exec` (its
//!      cancellation was requested), `wssp sandbox logs` and
//!      `wssp sandbox files read` to stdout
//!
//! `/v1` answers map to these codes in `src/api.rs`: 404 → 3 and 400, 413 and
//! 415 → 2 as well.
//!
//! To give a specific error a non-default code, attach a [`CodedError`] via
//! `.context(CodedError::new(ExitCode::NotFound))` and [`code_for`] will pick it
//! up. The surrounding error should describe the concrete failure.

use std::fmt;
use std::io;

/// Stable exit codes. Document any code you add in the module comment above and
/// in `README.md` so users and scripts can rely on them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    Success = 0,
    Failure = 1,
    /// Bad arguments (clap emits this itself) or a request the server refused
    /// as invalid (400, 413, 415).
    Usage = 2,
    /// The requested resource was not found (e.g. `wssp host drain` on a 404).
    NotFound = 3,
    /// Host credential revoked, expired, banned, or policy-blocked (WebSocket 4003 or HTTP 401/403 on connect).
    CredentialInactive = 4,
    /// Relay infrastructure error during credential revalidation (WebSocket 1011).
    RelayUnavailable = 5,
    /// A `wssp host` command that needs an enrollment ran on a machine with no
    /// host device credential and no host token selection.
    NotEnrolledHost = 6,
    /// No user login, or the server refused the login's key (401).
    NotLoggedIn = 7,
    /// The server refused the action for this key (403).
    Forbidden = 8,
    /// A key, quota or queue limit was reached.
    LimitReached = 9,
    /// Any other conflict (409).
    Conflict = 10,
    /// The server is busy or unavailable (429, 503, 504); retry later.
    Retryable = 11,
    /// `wssp sandbox exec`/`shell`: wssp-side failure, a session the wssp
    /// side ended, or an unknown command outcome.
    ExecFailure = 125,
    /// Interrupted by Ctrl-C (the followed command's cancellation was requested).
    Interrupted = 130,
    /// stdout closed before the output was written (128 + SIGPIPE).
    OutputClosed = 141,
}

impl ExitCode {
    /// Stable machine name, used as the `code` of a local `--json` error.
    pub fn name(self) -> &'static str {
        match self {
            Self::Success => "ok",
            Self::Failure => "error",
            Self::Usage => "usage",
            Self::NotFound => "not_found",
            Self::CredentialInactive => "credential_inactive",
            Self::RelayUnavailable => "relay_unavailable",
            Self::NotEnrolledHost => "not_enrolled_host",
            Self::NotLoggedIn => "not_logged_in",
            Self::Forbidden => "forbidden",
            Self::LimitReached => "limit_reached",
            Self::Conflict => "conflict",
            Self::Retryable => "retryable",
            Self::ExecFailure => "exec_failed",
            Self::Interrupted => "interrupted",
            Self::OutputClosed => "output_closed",
        }
    }
}

/// Annotate an error to request a specific [`ExitCode`].
///
/// ```ignore
/// return Err(anyhow::Error::msg("no profile named `default`"))
///     .context(CodedError::new(ExitCode::NotFound));
/// ```
#[derive(Debug)]
pub struct CodedError {
    code: ExitCode,
}

impl CodedError {
    /// Create an exit-code marker.
    pub fn new(code: ExitCode) -> Self {
        Self { code }
    }

    /// Return the process exit code carried by this marker.
    pub fn code(&self) -> ExitCode {
        self.code
    }
}

impl fmt::Display for CodedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // This marker carries only the process exit code. The surrounding
        // anyhow error is responsible for the human-facing message.
        f.write_str("")
    }
}

impl std::error::Error for CodedError {}

/// End the process with this exact status and no message: `wssp sandbox exec`
/// passes the guest command's own exit code through.
#[derive(Debug)]
pub struct ProcessExit(pub i32);

impl fmt::Display for ProcessExit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("")
    }
}

impl std::error::Error for ProcessExit {}

/// The [`ProcessExit`] of an error, if any.
pub fn process_exit_of(err: &anyhow::Error) -> Option<i32> {
    err.chain()
        .find_map(|cause| cause.downcast_ref::<ProcessExit>())
        .map(|exit| exit.0)
}

/// Resolve the exit code for an error by looking for a [`CodedError`] anywhere
/// in it; defaults to [`ExitCode::Failure`].
pub fn code_for(err: &anyhow::Error) -> ExitCode {
    // anyhow's downcast sees a `CodedError` attached via `.context(...)`…
    if let Some(coded) = err.downcast_ref::<CodedError>() {
        return coded.code();
    }
    // …while walking the source chain sees one nested inside another error
    // (e.g. a thiserror `#[source]` field).
    for cause in err.chain() {
        if let Some(coded) = cause.downcast_ref::<CodedError>() {
            return coded.code();
        }
    }
    ExitCode::Failure
}

/// Whether this error came from writing to a downstream pipe that closed early.
pub fn is_broken_pipe(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(|err| err.kind() == io::ErrorKind::BrokenPipe)
    })
}

/// Format an error for stderr, excluding exit-code-only markers.
pub fn message_for(err: &anyhow::Error) -> String {
    err.chain()
        .filter(|cause| cause.downcast_ref::<CodedError>().is_none())
        .map(std::string::ToString::to_string)
        .filter(|message| !message.is_empty())
        .collect::<Vec<_>>()
        .join(": ")
}

/// Print a command failure to stderr (one JSON line with `--json`, else
/// `error: …`) and return its exit code.
pub fn report_failure(err: &anyhow::Error) -> ExitCode {
    if let Some(line) = failure_line(err) {
        let _ = crate::output::diagnostic(line);
    }
    code_for(err)
}

/// The stderr line [`report_failure`] prints for a failure: one JSON line
/// with `--json`, else `error: …`; `None` when the JSON cannot be encoded.
pub fn failure_line(err: &anyhow::Error) -> Option<String> {
    let code = code_for(err);
    if !crate::output::json_errors() {
        // Identifiers in error messages are wrapped in `backticks`, never
        // 'single quotes' — see AGENTS.md.
        return Some(format!("error: {}", message_for(err)));
    }
    let message = message_for(err);
    let line = match crate::api::api_error_of(err) {
        Some(api) => {
            crate::output::json_error_line(&api.code, Some(api.status), &message, api.data.as_ref())
        }
        None => match crate::api::operation_error_of(err) {
            Some(operation) => {
                let data = serde_json::json!({
                    "operationId": operation.operation_id,
                    "outcome": operation.outcome,
                    "state": operation.state,
                });
                crate::output::json_error_line(&operation.code(), None, &message, Some(&data))
            }
            None => match crate::connect_client::session_ended_of(err) {
                // `connect.<intent>` (or `connect.lost`) of a shell session.
                Some(ended) => {
                    let data = serde_json::json!({
                        "intent": ended.intent.map(crate::connect_client::wire::Intent::name),
                        "error": ended.error.as_ref().map(|error| serde_json::json!({
                            "code": crate::output::remote_message(&error.code),
                            "message": crate::output::remote_message(&error.message),
                        })),
                    });
                    crate::output::json_error_line(&ended.code(), None, &message, Some(&data))
                }
                None => crate::output::json_error_line(code.name(), None, &message, None),
            },
        },
    };
    line.ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_coded_error_from_context_chain() {
        let err = anyhow::Error::msg("no profile named `default`")
            .context(CodedError::new(ExitCode::NotFound));

        assert_eq!(code_for(&err), ExitCode::NotFound);
        assert_eq!(message_for(&err), "no profile named `default`");
    }

    #[test]
    fn extracts_coded_error_nested_as_a_source() {
        // A library error that carries a `CodedError` as its `source()` —
        // the thiserror `#[source]` pattern from `docs/error-handling.md`.
        #[derive(Debug)]
        struct Wrapper {
            source: CodedError,
        }
        impl fmt::Display for Wrapper {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("wrapper failed")
            }
        }
        impl std::error::Error for Wrapper {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.source)
            }
        }

        let err = anyhow::Error::new(Wrapper {
            source: CodedError::new(ExitCode::NotFound),
        });
        assert_eq!(code_for(&err), ExitCode::NotFound);
    }

    #[test]
    fn detects_broken_pipe_through_context() {
        let err = anyhow::Error::new(io::Error::from(io::ErrorKind::BrokenPipe))
            .context("writing to stdout");

        assert!(is_broken_pipe(&err));
    }
}
