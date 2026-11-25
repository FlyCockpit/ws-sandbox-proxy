//! Subcommand implementations.
//!
//! One module per subcommand. Each module exposes:
//!   - an `Args` struct (clap-derived) describing its flags/positionals, and
//!   - a `run(args: &Args) -> anyhow::Result<()>` function with the logic.
//!
//! `src/cli.rs` wires the `Args` into the top-level `Command` enum; `main.rs`
//! calls `run`. To add a command, copy an existing command module, then
//! register it in both places.

pub mod completions;
pub mod config;
#[cfg(target_os = "linux")]
pub mod daemon;
pub mod drain;
pub mod enroll;
#[cfg(target_os = "linux")]
pub mod guard;
pub mod host;
pub mod images;
pub mod login;
pub mod logout;
pub mod run;
pub mod sandbox;
pub mod template;
#[cfg(target_os = "linux")]
pub mod tunnel;
pub mod user_logout;
pub mod whoami;

/// Print a command failure to stderr (one JSON line with `--json`, else
/// `error: …`) and return its exit code.
pub fn report_failure(err: &anyhow::Error) -> crate::exit::ExitCode {
    if let Some(line) = failure_line(err) {
        let _ = crate::output::diagnostic(line);
    }
    crate::exit::code_for(err)
}

/// The stderr line [`report_failure`] prints for a failure: one JSON line
/// with `--json`, else `error: …`; `None` when the JSON cannot be encoded.
pub fn failure_line(err: &anyhow::Error) -> Option<String> {
    let code = crate::exit::code_for(err);
    if !crate::output::json_errors() {
        // Identifiers in error messages are wrapped in `backticks`, never
        // 'single quotes' — see AGENTS.md.
        return Some(format!("error: {}", crate::exit::message_for(err)));
    }
    let message = crate::exit::message_for(err);
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
