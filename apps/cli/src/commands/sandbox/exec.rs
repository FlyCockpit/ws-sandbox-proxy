//! `wssp sandbox exec`, `ps` and `logs`: commands and their output.
//!
//! `exec` starts the command (`POST /v1/sandboxes/{id}/commands`), then
//! follows `GET /v1/operations/{id}/output` with held reads from a follower
//! thread while the main thread writes the bytes. Ctrl-C is handled by a
//! watcher thread, independent of a writer blocked on an unread pipe: it
//! requests `POST /v1/operations/{id}/cancel` (bounded) and exits 130. A
//! closed stdout cancels too and exits 141. It exits with the guest command's own exit
//! code when the operation SUCCEEDED; any wssp-side failure, a failed or
//! cancelled operation, or an outcome the server cannot confirm, exits 125
//! with a typed error.
//!
//! The start is Ctrl-C aware too: no start is sent after an interrupt, and a
//! receipt that still arrives is cancelled. When an earlier attempt may have
//! been accepted without a receipt, the error names its idempotency key.
//! `--json` writes no diagnostics: gaps and restarts are fields of the result.

use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{client, parse_duration_ms, parse_key_value, result_operation, segment, str_field};
use crate::api::{
    Body, Client, Method, MutationReceipt, WAIT_MS, decode_base64, encode_body, idempotency_key,
};
use crate::exit::{CodedError, ExitCode, ProcessExit};
use crate::output;

#[derive(Debug, clap::Args)]
pub struct ExecArgs {
    /// Sandbox id.
    pub id: String,

    /// Command timeout, e.g. `90s` or `10m` (at most 30m; default 2m).
    #[arg(long, value_name = "DUR", value_parser = parse_duration_ms)]
    pub timeout: Option<u64>,

    /// Working directory in the guest (absolute).
    #[arg(long, value_name = "P")]
    pub cwd: Option<String>,

    /// Environment variable `KEY=VALUE` for the command (repeatable).
    #[arg(long = "env", value_name = "K=V", value_parser = parse_key_value)]
    pub env: Vec<(String, String)>,

    /// Start the command and print its operation id without waiting.
    #[arg(long)]
    pub detach: bool,

    /// Print `{operationId, exitCode, stdout, stderr, truncated, gaps, restarts}` at the end instead of streaming.
    #[arg(long)]
    pub json: bool,

    /// The command and its arguments, after `--`.
    #[arg(last = true, required = true, value_name = "ARGV")]
    pub argv: Vec<String>,
}

#[derive(Debug, clap::Args)]
pub struct LogsArgs {
    /// Operation id of the command (`wssp sandbox exec --detach` prints it).
    pub operation_id: String,

    /// Keep reading until the command completes.
    #[arg(long)]
    pub follow: bool,

    /// Print `{operationId, state, exitCode, complete, stdout, stderr, truncated, gaps, restarts}` instead of streaming.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, clap::Args)]
pub struct PsArgs {
    /// Sandbox id.
    pub id: String,

    /// Page size, 1–100.
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u16).range(1..=100))]
    pub limit: Option<u16>,

    /// Continue after a previous page (`nextCursor`).
    #[arg(long, value_name = "C")]
    pub cursor: Option<String>,

    /// Emit JSON instead of human-readable text.
    #[arg(long)]
    pub json: bool,
}

/// `GET /v1/operations/{id}/output` (packages/sandbox-contracts/src/output.ts).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OutputPage {
    operation_id: String,
    state: String,
    exit_code: Option<i64>,
    /// Dispatch attempt whose bytes these are; a new one restarts at 0.
    attempt: u64,
    chunks: Vec<OutputChunk>,
    gaps: Vec<OutputGap>,
    next_cursor: String,
    has_more: bool,
    truncated: bool,
    complete: bool,
}

#[derive(Debug, Deserialize)]
struct OutputChunk {
    stream: String,
    /// Aggregate offset of the chunk's first byte.
    offset: u64,
    data: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
struct OutputGap {
    start: u64,
    end: u64,
}

enum Event {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    /// Bytes `start..end` of the output were not retained.
    Gap(OutputGap),
    /// The command was dispatched again: its output restarts at offset 0.
    Restart,
    Done(Result<FollowEnd>),
}

struct FollowEnd {
    state: String,
    exit_code: Option<i64>,
    truncated: bool,
    complete: bool,
}

/// Events in flight between the follower and the writer: a writer that
/// cannot keep up (a paused `| less`) holds the follower back.
const EVENT_QUEUE: usize = 8;

fn send(events: &mpsc::SyncSender<Event>, event: Event) -> Result<()> {
    events
        .send(event)
        .map_err(|_| anyhow::anyhow!("the output writer stopped"))
}

/// One range of a page, in aggregate-offset order.
enum Range {
    Gap,
    Bytes { stderr: bool, bytes: Vec<u8> },
}

/// Read output pages until caught up (`follow`: until the completion
/// watermark), sending every byte, gap and restart as an event. Like the
/// TypeScript SDK, a range already delivered is never sent twice (a page may
/// reach back over delivered bytes) and a new dispatch attempt restarts at 0.
fn follow_output(
    client: &Client,
    operation_id: &str,
    follow: bool,
    events: &mpsc::SyncSender<Event>,
) -> Result<FollowEnd> {
    let path = format!("/v1/operations/{}/output", segment(operation_id)?);
    let mut cursor: Option<String> = None;
    let mut truncated = false;
    let mut attempt: Option<u64> = None;
    let mut delivered = 0_u64;
    loop {
        let query: Vec<(&str, String)> = cursor.iter().map(|c| ("cursor", c.clone())).collect();
        let started = Instant::now();
        let hold = if follow { WAIT_MS } else { 0 };
        let page: OutputPage =
            crate::api::retry_transient(Instant::now() + Duration::from_secs(120), || {
                client.get_held(&path, &query, hold)
            })?;
        anyhow::ensure!(
            page.operation_id == operation_id,
            "the output page belongs to a different operation"
        );
        if attempt.is_some_and(|known| known != page.attempt) {
            delivered = 0;
            truncated = false;
            send(events, Event::Restart)?;
        }
        attempt = Some(page.attempt);
        let mut ranges: Vec<(u64, u64, Range)> = page
            .gaps
            .iter()
            .map(|gap| (gap.start, gap.end, Range::Gap))
            .collect();
        for chunk in &page.chunks {
            let bytes = decode_base64(&chunk.data)?;
            let end = chunk.offset.saturating_add(bytes.len() as u64);
            let stderr = chunk.stream == "stderr";
            ranges.push((chunk.offset, end, Range::Bytes { stderr, bytes }));
        }
        ranges.sort_by_key(|(start, _, _)| *start);
        for (start, end, range) in ranges {
            if end <= delivered {
                continue;
            }
            let from = start.max(delivered);
            let event = match range {
                Range::Gap => Event::Gap(OutputGap { start: from, end }),
                Range::Bytes { stderr, mut bytes } => {
                    let skip = usize::try_from(from - start).context("output offset")?;
                    bytes.drain(..skip);
                    if stderr {
                        Event::Stderr(bytes)
                    } else {
                        Event::Stdout(bytes)
                    }
                }
            };
            send(events, event)?;
            delivered = end;
        }
        truncated |= page.truncated;
        anyhow::ensure!(
            !(page.has_more && cursor.as_deref() == Some(page.next_cursor.as_str())),
            "the output page made no progress"
        );
        cursor = Some(page.next_cursor);
        if page.has_more {
            continue;
        }
        if page.complete || !follow {
            return Ok(FollowEnd {
                state: page.state,
                exit_code: page.exit_code,
                truncated,
                complete: page.complete,
            });
        }
        if page.state == "UNKNOWN_OUTCOME" {
            let operation: Value =
                client.get(&format!("/v1/operations/{}", segment(operation_id)?), &[])?;
            if str_field(&operation, "outcome") == "unknown" {
                return Err(super::operation_failure(operation_id, &operation));
            }
        }
        // A server that answered early without holding: do not spin.
        if started.elapsed() < Duration::from_millis(500) {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
}

/// What `--json` keeps of one stream: the first 256 KiB and the last 768 KiB,
/// the same window the server retains.
const CAPTURE_HEAD_BYTES: usize = 256 * 1024;
const CAPTURE_TAIL_BYTES: usize = 768 * 1024;

#[derive(Default)]
struct Capture {
    head: Vec<u8>,
    tail: std::collections::VecDeque<u8>,
    dropped: u64,
}

impl Capture {
    fn push(&mut self, bytes: &[u8]) {
        let room = CAPTURE_HEAD_BYTES.saturating_sub(self.head.len());
        let (head, rest) = bytes.split_at(room.min(bytes.len()));
        self.head.extend_from_slice(head);
        // Only the last `CAPTURE_TAIL_BYTES` of `rest` can survive.
        let keep = &rest[rest.len().saturating_sub(CAPTURE_TAIL_BYTES)..];
        self.dropped += (rest.len() - keep.len()) as u64;
        self.tail.extend(keep);
        let excess = self.tail.len().saturating_sub(CAPTURE_TAIL_BYTES);
        if excess > 0 {
            self.tail.drain(..excess);
            self.dropped += excess as u64;
        }
    }

    fn text(&self) -> String {
        let mut all = self.head.clone();
        all.extend(self.tail.iter());
        String::from_utf8_lossy(&all).into_owned()
    }
}

/// `--json` records at most this many gaps of the current attempt.
const GAPS_MAX: usize = 256;

/// Collected output for `--json`, with what the stream would have noted on
/// stderr: the gaps of the current attempt and the number of restarts.
#[derive(Default)]
struct Collected {
    stdout: Capture,
    stderr: Capture,
    gaps: Vec<OutputGap>,
    /// Gaps beyond [`GAPS_MAX`] (not listed).
    gaps_omitted: u64,
    restarts: u32,
}

impl Collected {
    fn gap(&mut self, gap: OutputGap) {
        if self.gaps.len() < GAPS_MAX {
            self.gaps.push(gap);
        } else {
            self.gaps_omitted += 1;
        }
    }

    /// A new dispatch attempt: its output restarts, so does the capture.
    fn restart(&mut self) {
        *self = Self {
            restarts: self.restarts.saturating_add(1),
            ..Self::default()
        };
    }

    /// Whether this client dropped bytes of its own.
    fn truncated(&self) -> bool {
        self.stdout.dropped > 0 || self.stderr.dropped > 0
    }
}

type Flag = std::sync::Arc<std::sync::atomic::AtomicBool>;

/// The first Ctrl-C sets the flag; a second one, while the first is still
/// being handled (a cancel request in flight), exits 130 at once.
#[cfg(unix)]
fn interrupt_flag() -> Result<Flag> {
    let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    signal_hook::flag::register_conditional_shutdown(
        signal_hook::consts::SIGINT,
        ExitCode::Interrupted as i32,
        flag.clone(),
    )
    .context("installing the Ctrl-C handler")?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, flag.clone())
        .context("installing the Ctrl-C handler")?;
    Ok(flag)
}

#[cfg(not(unix))]
fn interrupt_flag() -> Result<Flag> {
    Ok(std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
        false,
    )))
}

/// Follow on a thread; write (or collect) on this one. Ctrl-C (exit 130) or a
/// closed output (exit 141) stops; with `cancel` the command's cancellation
/// is requested first.
fn pump(
    client: &Client,
    operation_id: &str,
    follow: bool,
    collect: Option<&mut Collected>,
    interrupted: &Flag,
    cancel: bool,
) -> Result<FollowEnd> {
    let (sender, events) = mpsc::sync_channel(EVENT_QUEUE);
    let follower = client.clone();
    let id = operation_id.to_owned();
    std::thread::spawn(move || {
        let result = follow_output(&follower, &id, follow, &sender);
        let _ = sender.send(Event::Done(result));
    });
    watch_interrupt(client, operation_id, interrupted, cancel);
    let mut collect = collect;
    let stop_on = |error: anyhow::Error| -> anyhow::Error {
        if crate::exit::is_broken_pipe(&error) {
            stop(
                client,
                operation_id,
                cancel,
                "the output was closed (broken pipe)",
                ExitCode::OutputClosed,
            )
        } else {
            error
        }
    };
    loop {
        if interrupted.load(std::sync::atomic::Ordering::Relaxed) {
            // The interrupt watcher cancels and exits the process.
            park_forever();
        }
        let written = match events.recv_timeout(Duration::from_millis(100)) {
            Ok(Event::Stdout(bytes)) => match collect.as_deref_mut() {
                Some(collected) => {
                    collected.stdout.push(&bytes);
                    Ok(())
                }
                None => output::bytes(&bytes).and_then(|()| output::flush_stdout()),
            },
            Ok(Event::Stderr(bytes)) => match collect.as_deref_mut() {
                Some(collected) => {
                    collected.stderr.push(&bytes);
                    Ok(())
                }
                None => output::stderr_bytes(&bytes),
            },
            Ok(Event::Gap(gap)) => match collect.as_deref_mut() {
                Some(collected) => {
                    collected.gap(gap);
                    Ok(())
                }
                None => output::diagnostic(format!(
                    "wssp: {} bytes of output were not retained (bytes {}–{})",
                    gap.end - gap.start,
                    gap.start,
                    gap.end
                )),
            },
            Ok(Event::Restart) => match collect.as_deref_mut() {
                Some(collected) => {
                    collected.restart();
                    Ok(())
                }
                None => output::diagnostic(
                    "wssp: the command was dispatched again; its output restarts",
                ),
            },
            Ok(Event::Done(_)) if interrupted.load(std::sync::atomic::Ordering::Relaxed) => {
                park_forever()
            }
            Ok(Event::Done(result)) => return result,
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(()),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                anyhow::bail!("the output follower stopped unexpectedly")
            }
        };
        written.map_err(stop_on)?;
    }
}

/// How long the interrupt watcher waits for the cancel request.
const INTERRUPT_CANCEL_BUDGET: Duration = Duration::from_secs(10);
/// How long the interrupt watcher waits to report the error before exiting.
const INTERRUPT_REPORT_BUDGET: Duration = Duration::from_secs(1);

/// Handle Ctrl-C independently of the writer thread, which may be blocked
/// forever on a stdout or stderr pipe nobody reads: once the flag is set,
/// request the cancellation (when `cancel`, bounded by
/// [`INTERRUPT_CANCEL_BUDGET`]), report the error (bounded too: stderr may be
/// the blocked pipe) and exit 130. A second Ctrl-C exits 130 at once (the
/// conditional shutdown of [`interrupt_flag`]).
fn watch_interrupt(client: &Client, operation_id: &str, interrupted: &Flag, cancel: bool) {
    let client = client.clone();
    let operation_id = operation_id.to_owned();
    let interrupted = interrupted.clone();
    std::thread::spawn(move || {
        while !interrupted.load(std::sync::atomic::Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(50));
        }
        let (sender, outcome) = mpsc::channel();
        let id = operation_id.clone();
        std::thread::spawn(move || {
            let error = stop(&client, &id, cancel, "interrupted", ExitCode::Interrupted);
            let _ = sender.send(error);
        });
        let error = outcome
            .recv_timeout(INTERRUPT_CANCEL_BUDGET)
            .unwrap_or_else(|_| {
                anyhow::Error::msg(format!(
                    "interrupted; requesting the cancellation of operation `{operation_id}` did not finish in time; cancel it with the dashboard or check `wssp sandbox logs {operation_id}`"
                ))
                .context(CodedError::new(ExitCode::Interrupted))
            });
        let (reported, done) = mpsc::channel();
        std::thread::spawn(move || {
            crate::commands::report_failure(&error);
            let _ = reported.send(());
        });
        let _ = done.recv_timeout(INTERRUPT_REPORT_BUDGET);
        // `exit` only try-locks stdout to flush it, so a writer blocked while
        // holding the lock cannot hold the process here.
        std::process::exit(ExitCode::Interrupted as i32);
    });
}

/// Leave the rest to the interrupt watcher, which exits the process.
fn park_forever() -> ! {
    loop {
        std::thread::park();
    }
}

/// Request the command's cancellation (one bounded attempt) when `cancel`,
/// and return the error with `code` (130 or 141).
fn stop(
    client: &Client,
    operation_id: &str,
    cancel: bool,
    reason: &str,
    code: ExitCode,
) -> anyhow::Error {
    if !cancel {
        return anyhow::Error::msg(reason.to_owned()).context(CodedError::new(code));
    }
    let result = segment(operation_id).and_then(|id| {
        let key = idempotency_key()?;
        client.request::<Value>(
            Method::Post,
            &format!("/v1/operations/{id}/cancel"),
            &[],
            Body::Json(b"{}"),
            Some(&key),
            Duration::from_secs(10),
        )
    });
    let message = match result {
        Ok(_) => format!("{reason}; cancellation of operation `{operation_id}` was requested"),
        Err(error) => format!(
            "{reason}; requesting the cancellation of operation `{operation_id}` failed ({}); cancel it with the dashboard or check `wssp sandbox logs {operation_id}`",
            crate::exit::message_for(&error)
        ),
    };
    anyhow::Error::msg(message).context(CodedError::new(code))
}

/// `POST /v1/sandboxes/{id}/commands` (`commandBodySchema`, argv form).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CommandBody<'a> {
    argv: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    cwd: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    envs: Option<std::collections::BTreeMap<&'a str, &'a str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timeout_ms: Option<u64>,
}

/// `resultListOptionsSchema`.
#[derive(Serialize)]
struct ListOptions<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecResult {
    operation_id: String,
    exit_code: i64,
    stdout: String,
    stderr: String,
    truncated: bool,
    #[serde(flatten)]
    notes: Notes,
}

/// What a streaming run notes on stderr, as `--json` fields.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Notes {
    /// Output ranges of the last attempt the server did not retain.
    gaps: Vec<OutputGap>,
    /// Gaps beyond the first 256 (not listed).
    gaps_omitted: u64,
    /// How often the command was dispatched again (its output restarted).
    restarts: u32,
}

impl Collected {
    fn notes(&mut self) -> Notes {
        Notes {
            gaps: std::mem::take(&mut self.gaps),
            gaps_omitted: self.gaps_omitted,
            restarts: self.restarts,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Detached<'a> {
    operation_id: &'a str,
    state: &'a str,
}

/// How long the start is re-sent while its answers are transient.
const SUBMIT_DEADLINE: Duration = Duration::from_secs(120);

/// Whether a failed attempt may still have been accepted: anything but a
/// 429 or a connection that was never made could have reached the server.
fn may_have_been_accepted(error: &anyhow::Error) -> bool {
    if let Some(api) = crate::api::api_error_of(error) {
        return api.status != 429;
    }
    !error.chain().any(|cause| {
        cause.downcast_ref::<ureq::Error>().is_some_and(|e| {
            matches!(
                e,
                ureq::Error::ConnectionFailed | ureq::Error::Timeout(ureq::Timeout::Connect)
            ) || matches!(e, ureq::Error::Io(io) if io.kind() == std::io::ErrorKind::ConnectionRefused)
        })
    })
}

/// `POST /v1/sandboxes/{id}/commands` with one idempotency key, re-sent
/// unchanged while transient (`api::retry_delay`) and never after a Ctrl-C.
/// An interrupt exits 130; when an earlier attempt may have been accepted the
/// error carries its idempotency key and where to look for the command.
fn submit(
    client: &Client,
    id: &str,
    body: &CommandBody<'_>,
    interrupted: &Flag,
) -> Result<MutationReceipt> {
    let is_interrupted = || interrupted.load(std::sync::atomic::Ordering::Relaxed);
    let body = encode_body(body)?;
    let key = idempotency_key()?;
    let path = format!("/v1/sandboxes/{id}/commands");
    let deadline = Instant::now() + SUBMIT_DEADLINE;
    let mut backoff = crate::api::INITIAL_BACKOFF;
    let mut ambiguous = false;
    let interrupted_error = |ambiguous: bool| {
        let message = if ambiguous {
            format!(
                "interrupted while starting the command; an earlier attempt may have been accepted (idempotency key `{key}`): check `wssp sandbox ps {id}` and cancel it with the dashboard"
            )
        } else {
            "interrupted before the command was started".to_owned()
        };
        anyhow::Error::msg(message).context(CodedError::new(ExitCode::Interrupted))
    };
    loop {
        if is_interrupted() {
            return Err(interrupted_error(ambiguous));
        }
        let error = match client.request::<MutationReceipt>(
            Method::Post,
            &path,
            &[],
            Body::Json(&body),
            Some(&key),
            Duration::from_secs(30),
        ) {
            Ok(receipt) => return Ok(receipt),
            Err(error) => error,
        };
        ambiguous |= may_have_been_accepted(&error);
        let Some(delay) = crate::api::retry_delay(&error, &mut backoff, Instant::now(), deadline)
        else {
            if is_interrupted() {
                // Interrupted while the attempt was in flight; it was refused.
                return Err(error.context(CodedError::new(ExitCode::Interrupted)));
            }
            return Err(error);
        };
        tracing::debug!(?delay, "retrying the command start");
        if !crate::api::sleep_unless(delay, &is_interrupted) {
            return Err(interrupted_error(ambiguous));
        }
    }
}

pub fn exec(args: &ExecArgs) -> Result<()> {
    output::set_json_errors(args.json);
    // No login (7) and an invalid id (2) keep their codes; any other failure
    // to load the credential (an unreadable or malformed login, the login
    // lock, an invalid env credential) is wssp-side: 125 …
    let credential = crate::user_state::require_credential().map_err(|error| {
        if crate::exit::code_for(&error) == ExitCode::NotLoggedIn {
            error
        } else {
            error.context(CodedError::new(ExitCode::ExecFailure))
        }
    })?;
    let id = segment(&args.id)?.to_owned();
    // … after that every failure is wssp-side: exit 125, never a code a guest
    // command could also return (a missing or invalid CA file included); 130
    // and 141 stay.
    let client = Client::new(&credential)
        .map_err(|error| error.context(CodedError::new(ExitCode::ExecFailure)))?;
    run_exec(&client, &id, args).map_err(|error| {
        let code = crate::exit::code_for(&error);
        if crate::exit::process_exit_of(&error).is_some()
            || matches!(code, ExitCode::Interrupted | ExitCode::OutputClosed)
        {
            error
        } else {
            error.context(CodedError::new(ExitCode::ExecFailure))
        }
    })
}

fn run_exec(client: &Client, id: &str, args: &ExecArgs) -> Result<()> {
    let body = CommandBody {
        argv: &args.argv,
        cwd: args.cwd.as_deref(),
        envs: (!args.env.is_empty()).then(|| {
            args.env
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect()
        }),
        timeout_ms: args.timeout,
    };
    // Installed before the start: a Ctrl-C while it is in flight cancels the
    // command as soon as its operation id is known.
    let interrupted = interrupt_flag()?;
    let receipt = submit(client, id, &body, &interrupted)?;
    if interrupted.load(std::sync::atomic::Ordering::Relaxed) {
        return Err(stop(
            client,
            &receipt.operation_id,
            true,
            "interrupted",
            ExitCode::Interrupted,
        ));
    }
    if args.detach {
        return if args.json {
            output::json(&Detached {
                operation_id: &receipt.operation_id,
                state: &receipt.state,
            })
        } else {
            output::line(&receipt.operation_id)
        }
        .map_err(super::output_closed);
    }
    let mut collected = Collected::default();
    let end = pump(
        client,
        &receipt.operation_id,
        true,
        args.json.then_some(&mut collected),
        &interrupted,
        true,
    )?;
    // The guest's exit code counts only for a command that ran to its end:
    // a FAILED, CANCELLED or unknown operation is wssp-side (125), whatever
    // exit code the page carries.
    if end.state != "SUCCEEDED" {
        super::await_operation(client, &receipt.operation_id)?;
    }
    let Some(exit_code) = end.exit_code else {
        anyhow::bail!(
            "command `{}` ended ({}) without an exit code",
            receipt.operation_id,
            end.state
        );
    };
    let Ok(exit_code) = u8::try_from(exit_code) else {
        anyhow::bail!(
            "command `{}` reported exit code {exit_code}, outside 0–255",
            receipt.operation_id
        );
    };
    let truncated = end.truncated || collected.truncated();
    if end.truncated && !args.json {
        output::diagnostic(
            "wssp: the output was truncated: the server keeps the first 256 KiB and the last 768 KiB",
        )
        .map_err(super::output_closed)?;
    }
    if args.json {
        output::json(&ExecResult {
            operation_id: receipt.operation_id.clone(),
            exit_code: i64::from(exit_code),
            stdout: collected.stdout.text(),
            stderr: collected.stderr.text(),
            truncated,
            notes: collected.notes(),
        })
        .map_err(super::output_closed)?;
    }
    if exit_code == 0 {
        Ok(())
    } else {
        Err(anyhow::Error::new(ProcessExit(i32::from(exit_code))))
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LogsResult {
    operation_id: String,
    state: String,
    exit_code: Option<i64>,
    complete: bool,
    stdout: String,
    stderr: String,
    truncated: bool,
    #[serde(flatten)]
    notes: Notes,
}

pub fn logs(args: &LogsArgs) -> Result<()> {
    let client = client(args.json)?;
    let id = segment(&args.operation_id)?.to_owned();
    let interrupted = interrupt_flag()?;
    let mut collected = Collected::default();
    let end = pump(
        &client,
        &id,
        args.follow,
        args.json.then_some(&mut collected),
        &interrupted,
        false,
    )?;
    if args.json {
        let truncated = end.truncated || collected.truncated();
        return output::json(&LogsResult {
            operation_id: id,
            state: end.state,
            exit_code: end.exit_code,
            complete: end.complete,
            stdout: collected.stdout.text(),
            stderr: collected.stderr.text(),
            truncated,
            notes: collected.notes(),
        })
        .map_err(super::output_closed);
    }
    if end.truncated {
        output::diagnostic(
            "wssp: the output was truncated: the server keeps the first 256 KiB and the last 768 KiB",
        )?;
    }
    if end.complete {
        output::diagnostic(format!(
            "wssp: {} exit code {}",
            end.state,
            end.exit_code
                .map_or_else(|| "none".to_owned(), |c| c.to_string())
        ))
    } else {
        output::diagnostic(format!(
            "wssp: the command is still {}; `--follow` keeps reading",
            end.state
        ))
    }
}

pub fn ps(args: &PsArgs) -> Result<()> {
    let client = client(args.json)?;
    let id = segment(&args.id)?;
    let body = ListOptions {
        limit: args.limit,
        cursor: args.cursor.as_deref(),
    };
    let result = result_operation(
        &client,
        &format!("/v1/sandboxes/{id}/processes/list"),
        &body,
    )?;
    if args.json {
        return output::json(&result);
    }
    let items = result
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if items.is_empty() {
        output::line("no running commands")?;
    } else {
        output::line(format!(
            "{:<8} {:<26} {:<25} COMMAND",
            "PID", "OPERATION", "STARTED"
        ))?;
    }
    for item in &items {
        let pid = item
            .pointer("/process/pid")
            .and_then(Value::as_i64)
            .unwrap_or_default();
        let mut command = vec![output::remote_message(str_field(item, "cmd"))];
        if let Some(args) = item.get("args").and_then(Value::as_array) {
            command.extend(
                args.iter()
                    .filter_map(Value::as_str)
                    .map(output::remote_message),
            );
        }
        output::line(format!(
            "{:<8} {:<26} {:<25} {}",
            pid,
            output::remote_message(str_field(item, "operationId")),
            str_field(item, "startedAt"),
            command.join(" ")
        ))?;
    }
    let mut command = format!("wssp sandbox ps {}", super::shell_quote(&args.id));
    if let Some(limit) = args.limit {
        command.push_str(&format!(" --limit {limit}"));
    }
    super::print_next_cursor(&result, &command)
}
