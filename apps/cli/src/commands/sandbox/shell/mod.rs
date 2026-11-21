//! `wssp sandbox shell`: an interactive shell, or a command, in a sandbox
//! over the connect plane (`GET /v1/sandboxes/{id}/connect`,
//! `src/connect_client/`).
//!
//! With a terminal on stdin and stdout (and no `--no-tty`) it opens a `pty`
//! channel: a login shell, or the argv after `--` run structurally (each word
//! one argv element, never joined into a shell string). The local terminal is
//! raw from the channel's `ready` to the end of the session (until then
//! Ctrl-C still interrupts a pending open), so Ctrl-C, Ctrl-Z and Ctrl-D
//! travel to the remote as bytes, and SIGWINCH sends the new size. Otherwise
//! it opens an `exec` channel: stdout and stderr stay separate, stdin is
//! piped and its EOF travels, and SIGINT, SIGTERM and SIGHUP become remote
//! signals; a second Ctrl-C within 2 s, or a second SIGTERM or SIGHUP at any
//! time, closes the channel and exits 128 + N (130, 143, 129). SIGQUIT has no
//! wire signal: it closes the channel and exits 131 in both modes. Before the
//! channel is `ready` any of them closes it (the node kills what it was
//! starting) and the CLI exits 128 + N. A close waits at most 2 s for the
//! channel's exit.
//!
//! The process exits with the remote status: the exit code, or 128 + N for a
//! death by signal N. A refusal before the upgrade keeps its `/v1` exit code
//! (7, 8, 3, 10, 11; a login without `sandboxes:connect` is told to log in
//! again); a session wssp ended (revoked, stopped, destroyed, expired, host
//! lost, server shutdown, protocol error) prints one line naming why and
//! exits 125, as does any other wssp-side failure or an unknown status.
//! There is no detach and no resume: a lost connection ends the shell. The
//! error line goes through the output writer too, after the output, or,
//! when the writer stopped on a failed write, through a short-lived thread
//! of its own. When the session ends while the writer stays blocked on a
//! stdout or stderr nobody reads (2 s for the output, then 2 s for the
//! error line), or the error line cannot be written within 2 s, the CLI
//! exits with that status at once and without its error line. Nothing is
//! written to stdout or stderr on this thread once the session started.
//!
//! Threads: this one owns the connection and decides everything; a stdin
//! reader, an output writer and a signal watcher only move bytes and events.
//! During the session this thread writes nothing to stdout or stderr: its
//! own lines (notices, a stdin failure) go through the writer, ordered with
//! the output, and log events are dropped, so a blocked stderr can never
//! stall the connection.
//! The writer reports each written-and-flushed frame back, and only then is
//! the frame acknowledged, so a stalled local reader holds the remote side's
//! credit instead of buffering without bound.

mod tty;

use std::collections::BTreeMap;
use std::io::Read;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde_json::Value;

use super::{parse_key_value, segment};
use crate::connect_client::mux::{Event, Outcome};
use crate::connect_client::wire::{Intent, Kind, Notice, OutputStream, PtyParams, Signal};
use crate::connect_client::{Connection, SessionEnded};
use crate::exit::{CodedError, ExitCode, ProcessExit};
use crate::output;
use crate::user_state::{CredentialSource, UserCredential};

/// The scope a key needs for the connect plane.
pub const CONNECT_SCOPE: &str = "sandboxes:connect";
/// A second Ctrl-C this soon after the first closes an exec channel.
const DOUBLE_INTERRUPT: Duration = Duration::from_secs(2);
/// stdin frames sent per loop turn at most, after the turn's acks, so a
/// slow uplink never queues a whole window ahead of them.
const STDIN_FRAMES_PER_TURN: usize = 4;
/// How long a local close waits for the channel's exit.
const CLOSE_WAIT: Duration = Duration::from_secs(2);
/// How long an ended session waits for the output writer to deliver what it
/// holds before treating it as stuck.
const WRITER_SETTLE: Duration = Duration::from_secs(2);
/// `TERM` when the local one is unset or unusable.
const DEFAULT_TERM: &str = "xterm-256color";
/// Pages of 100 searched when `<sandbox>` is a name.
const NAME_PAGES: usize = 20;
/// Every live state (all but `DELETED`).
const LIVE_STATES: &str = "REQUESTED,SCHEDULED,PROVISIONING,READY,STOPPING,STOPPED,RECLAIMING,UNREACHABLE,RECOVERED,HOST_LOST,ERROR,WAITING_FOR_CAPACITY,OFFLOADED";

#[derive(Debug, clap::Args)]
pub struct ShellArgs {
    /// Sandbox id or name.
    pub sandbox: String,

    /// Working directory in the guest (absolute; default: the guest user's home).
    #[arg(long, value_name = "PATH")]
    pub cwd: Option<String>,

    /// `TERM`, `COLORTERM`, `LANG` or `LC_*` for the remote side, `KEY=VALUE` (repeatable).
    #[arg(long = "env", value_name = "K=V", value_parser = parse_key_value)]
    pub env: Vec<(String, String)>,

    /// Never allocate a tty: separate stdout and stderr, piped stdin (the default when stdin or stdout is not a terminal).
    #[arg(short = 'T', long = "no-tty")]
    pub no_tty: bool,

    /// Report a failure as one JSON line on stderr (the session itself is raw bytes).
    #[arg(long)]
    pub json: bool,

    /// The command and its arguments, after `--` (default: a login shell).
    #[arg(last = true, value_name = "ARGV")]
    pub argv: Vec<String>,
}

/// What the user asked for, checked before any network call.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Request {
    kind: Kind,
    argv: Option<Vec<String>>,
    cwd: Option<String>,
    env: Option<BTreeMap<String, String>>,
    term: String,
}

fn usage(message: String) -> anyhow::Error {
    anyhow::Error::msg(message).context(CodedError::new(ExitCode::Usage))
}

/// `TERM` from `--env`, else the local `TERM` when the wire accepts it.
fn term_of(explicit: Option<&str>, local: Option<&str>) -> Result<String> {
    if let Some(term) = explicit {
        if !sandbox_protocol::valid_channel_term(term) {
            return Err(usage(format!(
                "`TERM={}` is not a usable terminal name",
                output::remote_message(term)
            )));
        }
        return Ok(term.to_owned());
    }
    Ok(local
        .filter(|term| sandbox_protocol::valid_channel_term(term))
        .unwrap_or(DEFAULT_TERM)
        .to_owned())
}

fn request(args: &ShellArgs, tty: bool, local_term: Option<&str>) -> Result<Request> {
    let mut env = BTreeMap::new();
    let mut term = None;
    for (name, value) in &args.env {
        if name == "TERM" {
            term = Some(value.as_str());
        } else if sandbox_protocol::valid_channel_env_name(name) {
            env.insert(name.clone(), value.clone());
        } else {
            return Err(usage(format!(
                "`--env {}` is not allowed; only `TERM`, `COLORTERM`, `LANG` and `LC_*` travel to a shell",
                output::remote_message(name)
            )));
        }
    }
    if !sandbox_protocol::valid_channel_env(&env) {
        return Err(usage(
            "`--env` values are too long, too many or contain NUL".to_owned(),
        ));
    }
    if let Some(cwd) = &args.cwd
        && !sandbox_protocol::valid_channel_cwd(cwd)
    {
        return Err(usage("`--cwd` must be an absolute guest path".to_owned()));
    }
    if !args.argv.is_empty() && !sandbox_protocol::valid_channel_argv(&args.argv) {
        return Err(usage("the command is too long or contains NUL".to_owned()));
    }
    Ok(Request {
        kind: if tty { Kind::Pty } else { Kind::Exec },
        argv: (!args.argv.is_empty()).then(|| args.argv.clone()),
        cwd: args.cwd.clone(),
        env: (!env.is_empty()).then_some(env),
        // `TERM` rides only on a tty; an exec channel has no terminal.
        term: term_of(term, local_term)?,
    })
}

/// The process exit status for a channel outcome; `local` is the status a
/// close this client decided carries (130 after a double Ctrl-C, 128 + N
/// after a signal to the CLI in pty mode).
fn outcome_status(outcome: Outcome, local: Option<i32>) -> Result<i32> {
    match (outcome, local) {
        (Outcome::Code(code), _) => match u8::try_from(code) {
            Ok(code) => Ok(i32::from(code)),
            Err(_) => Err(
                anyhow::anyhow!("the remote command exited {code}, outside 0–255")
                    .context(CodedError::new(ExitCode::ExecFailure)),
            ),
        },
        (Outcome::Signal(signal), _) => Ok(128 + i32::from(signal)),
        (
            Outcome::Closed {
                intent: Intent::Client,
                ..
            }
            | Outcome::Unknown,
            Some(status),
        ) => Ok(status),
        (Outcome::Closed { intent, error }, _) => Err(SessionEnded {
            intent: Some(intent),
            error,
            detail: None,
        })
        .context(CodedError::new(ExitCode::ExecFailure)),
        (Outcome::Unknown, None) => Err(anyhow::anyhow!(
            "the remote command ended without a known exit status"
        )
        .context(CodedError::new(ExitCode::ExecFailure))),
        (Outcome::Failed { error }, _) => {
            let code = match error.code.as_str() {
                "rate_limited" | "host_capacity" | "disconnected" => ExitCode::Retryable,
                _ => ExitCode::ExecFailure,
            };
            Err(anyhow::anyhow!(
                "the sandbox could not open the shell (`{}`: {})",
                output::remote_message(&error.code),
                output::remote_message(&error.message)
            )
            .context(CodedError::new(code)))
        }
    }
}

pub fn shell(args: &ShellArgs) -> Result<()> {
    output::set_json_errors(args.json);
    let tty = !args.no_tty && tty::stdin_is_tty() && tty::stdout_is_tty();
    let local_term = std::env::var("TERM").ok();
    let request = request(args, tty, local_term.as_deref())?;
    let target = segment(&args.sandbox)?.to_owned();
    let credential = crate::user_state::require_credential()?;
    let status = session(&credential, &target, &request).map_err(wssp_side)?;
    if status == 0 {
        Ok(())
    } else {
        Err(anyhow::Error::new(ProcessExit(status)))
    }
}

/// From the connect on every uncoded failure is wssp-side: exit 125.
pub(super) fn wssp_side(error: anyhow::Error) -> anyhow::Error {
    if crate::exit::code_for(&error) == ExitCode::Failure {
        error.context(CodedError::new(ExitCode::ExecFailure))
    } else {
        error
    }
}

/// What a connect is for, in the missing-scope hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Purpose {
    Shell,
    Forward,
    #[cfg(feature = "ssh")]
    Ssh,
}

/// A 403 on a login without the connect scope: say how to get it.
fn scope_hint(
    credential: &UserCredential,
    error: anyhow::Error,
    purpose: Purpose,
) -> anyhow::Error {
    let forbidden = crate::api::api_error_of(&error).is_some_and(|api| api.status == 403);
    if !forbidden {
        return error;
    }
    let lacks = match (&credential.source, &credential.login) {
        (CredentialSource::File, Some(login)) => !login.scopes.iter().any(|s| s == CONNECT_SCOPE),
        _ => false,
    };
    let message = match (purpose, lacks, credential.source == CredentialSource::Env) {
        (Purpose::Shell, true, _) => {
            "this login cannot open shells; log in again (`wssp login`) to get shell access"
        }
        (Purpose::Forward, true, _) => {
            "this login cannot forward ports; log in again (`wssp login`) to get port forwarding"
        }
        #[cfg(feature = "ssh")]
        (Purpose::Ssh, true, _) => {
            "this login cannot open ssh sessions; log in again (`wssp login`) to get shell access"
        }
        (Purpose::Shell, false, true) => {
            "the key may lack the `sandboxes:connect` scope or access to this sandbox; a dashboard SDK key needs that scope, or log in again (`wssp login`) to get shell access"
        }
        (Purpose::Forward, false, true) => {
            "the key may lack the `sandboxes:connect` scope or access to this sandbox; a dashboard SDK key needs that scope, or log in again (`wssp login`) to get port forwarding"
        }
        #[cfg(feature = "ssh")]
        (Purpose::Ssh, false, true) => {
            "the key may lack the `sandboxes:connect` scope or access to this sandbox; a dashboard SDK key needs that scope, or log in again (`wssp login`) to get shell access"
        }
        (_, false, false) => return error,
    };
    error.context(message)
}

/// Connect to `target` as an id, else as a sandbox name.
pub(super) fn connect(
    credential: &UserCredential,
    target: &str,
    purpose: Purpose,
) -> Result<Connection> {
    match Connection::connect(credential, target) {
        Ok(connection) => Ok(connection),
        Err(error) if crate::api::api_error_of(&error).is_some_and(|api| api.status == 404) => {
            match resolve_name(credential, target) {
                Ok(Some(id)) if id != target => Connection::connect(credential, &id)
                    .map_err(|e| scope_hint(credential, e, purpose)),
                // Not a name either (or names cannot be listed): the 404 stands.
                _ => Err(error),
            }
        }
        Err(error) => Err(scope_hint(credential, error, purpose)),
    }
}

/// The id of the live sandbox named `name`, searching bounded pages.
fn resolve_name(credential: &UserCredential, name: &str) -> Result<Option<String>> {
    let client = crate::api::Client::new(credential)?;
    let mut cursor: Option<String> = None;
    for _ in 0..NAME_PAGES {
        let mut query = vec![
            ("states", LIVE_STATES.to_owned()),
            ("limit", "100".to_owned()),
        ];
        if let Some(cursor) = &cursor {
            query.push(("cursor", cursor.clone()));
        }
        let page: Value = client.get("/v1/sandboxes", &query)?;
        let items = page.get("items").and_then(Value::as_array);
        if let Some(found) = items
            .into_iter()
            .flatten()
            .find(|item| item.get("name").and_then(Value::as_str) == Some(name))
        {
            return Ok(found.get("id").and_then(Value::as_str).map(str::to_owned));
        }
        match page.get("nextCursor").and_then(Value::as_str) {
            Some(next) => cursor = Some(next.to_owned()),
            None => return Ok(None),
        }
    }
    Ok(None)
}

/// What the helper threads tell the connection thread.
enum Local {
    Delivered {
        stream: OutputStream,
        seq: u64,
    },
    /// The writer wrote (or gave up on) one diagnostic line.
    Noted,
    /// A write failed and the writer stopped; [`Writer::failure`] has the error.
    WriteFailed,
    Signal(i32),
}

enum Input {
    Data(Vec<u8>),
    End,
    Failed(std::io::Error),
}

/// Read stdin in frame-sized chunks; the bounded channel is the back-pressure.
fn spawn_stdin(max: usize) -> Result<mpsc::Receiver<Input>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("wssp-shell-stdin".into())
        .spawn(move || {
            let mut stdin = std::io::stdin();
            let mut buffer = vec![0_u8; max.max(1)];
            loop {
                let item = match stdin.read(&mut buffer) {
                    Ok(0) => Input::End,
                    Ok(n) => Input::Data(buffer[..n].to_vec()),
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => Input::Failed(error),
                };
                let last = !matches!(item, Input::Data(_));
                if sender.send(item).is_err() || last {
                    return;
                }
            }
        })
        .context("starting the stdin reader")?;
    Ok(receiver)
}

/// One item for the writer, written in order.
enum Item {
    /// An output frame, acknowledged once delivered.
    Output(OutputStream, u64, Vec<u8>),
    /// One line of the CLI's own on stderr (a notice, a stdin failure).
    Diagnostic(String),
}

/// Diagnostic lines queued and not yet written; later ones are dropped. The
/// server sends at most 64 notices per channel and stdin fails once, so this
/// only bounds a misbehaving server.
const MAX_QUEUED_DIAGNOSTICS: usize = 64;

/// The output writer thread and the items handed to it that it has not
/// reported done yet.
///
/// During a session the connection thread never writes to stdout or stderr
/// itself: a stderr nobody reads blocks the writer while it holds the
/// stderr lock, and a write from the connection thread would then block it
/// too, so revocation, signals and the bounded drain would never run. Its
/// own lines travel here, ordered with the guest's output.
struct Writer {
    sender: mpsc::Sender<Item>,
    /// The writer thread; it returns the error of the write that stopped it.
    thread: Option<std::thread::JoinHandle<Option<anyhow::Error>>>,
    /// Output frames and diagnostic lines handed over and not yet reported.
    undelivered: usize,
    /// The diagnostic lines among them.
    diagnostics: usize,
    /// False once the writer reported a failed write and stopped.
    running: bool,
}

impl Writer {
    /// Write output in order and report each frame once written and flushed.
    fn spawn(events: mpsc::Sender<Local>) -> Result<Self> {
        let (sender, receiver) = mpsc::channel::<Item>();
        let thread = std::thread::Builder::new()
            .name("wssp-shell-output".into())
            .spawn(move || {
                for item in receiver {
                    let (stream, seq, bytes) = match item {
                        Item::Output(stream, seq, bytes) => (stream, seq, bytes),
                        Item::Diagnostic(line) => {
                            // A diagnostic that cannot be written is lost,
                            // as on the main thread; output may still work.
                            let _ = output::diagnostic(line);
                            if events.send(Local::Noted).is_err() {
                                return None;
                            }
                            continue;
                        }
                    };
                    let written = match stream {
                        // Written and flushed under one stdout lock, so the
                        // lock is free only while nothing is buffered.
                        OutputStream::Stdout => output::bytes_flushed(&bytes),
                        OutputStream::Stderr => output::stderr_bytes(&bytes),
                    };
                    match written {
                        Ok(()) => {
                            if events.send(Local::Delivered { stream, seq }).is_err() {
                                return None;
                            }
                        }
                        // The error travels back through the join, so a
                        // send that finds the writer gone still has it.
                        Err(error) => {
                            let _ = events.send(Local::WriteFailed);
                            return Some(error);
                        }
                    }
                }
                None
            })
            .context("starting the output writer")?;
        Ok(Self {
            sender,
            thread: Some(thread),
            undelivered: 0,
            diagnostics: 0,
            running: true,
        })
    }

    /// Hand one output frame over. When the writer is gone, the error is
    /// the failed write that stopped it (see [`Writer::failure`]).
    fn send(&mut self, stream: OutputStream, seq: u64, bytes: Vec<u8>) -> Result<()> {
        if self.sender.send(Item::Output(stream, seq, bytes)).is_err() {
            return Err(self.failure());
        }
        self.undelivered += 1;
        Ok(())
    }

    /// The writer stopped (it reported `WriteFailed`, or its queue is
    /// closed): the error of the write that stopped it. Call it only then,
    /// since it joins the writer thread, which has returned or is returning.
    fn failure(&mut self) -> anyhow::Error {
        self.running = false;
        match self.thread.take().map(std::thread::JoinHandle::join) {
            Some(Ok(Some(error))) => error,
            _ => anyhow::anyhow!("the output writer stopped"),
        }
    }

    /// Queue one diagnostic line for stderr, after the output handed over
    /// so far, and say whether it was queued. Dropped when
    /// [`MAX_QUEUED_DIAGNOSTICS`] are still queued or the writer stopped (it
    /// stops only on a failed write).
    fn note(&mut self, line: String) -> bool {
        if !self.running || self.diagnostics >= MAX_QUEUED_DIAGNOSTICS {
            return false;
        }
        if self.sender.send(Item::Diagnostic(line)).is_err() {
            return false;
        }
        self.undelivered += 1;
        self.diagnostics += 1;
        true
    }

    fn delivered(&mut self) {
        self.undelivered = self.undelivered.saturating_sub(1);
    }

    fn noted(&mut self) {
        self.undelivered = self.undelivered.saturating_sub(1);
        self.diagnostics = self.diagnostics.saturating_sub(1);
    }

    /// Whether the writer is stuck after the session ended: it still holds
    /// frames or diagnostic lines after waiting up to [`WRITER_SETTLE`]
    /// (draining `events`) for it to deliver them. A writer stuck this long is blocked on a pipe or
    /// terminal nobody reads, holding the stdout or stderr lock. After a
    /// natural exit nothing is undelivered and this returns at once.
    fn stuck(&mut self, events: &mpsc::Receiver<Local>) -> bool {
        let deadline = Instant::now() + WRITER_SETTLE;
        while self.running && self.undelivered > 0 {
            let left = deadline.saturating_duration_since(Instant::now());
            match events.recv_timeout(left) {
                Ok(Local::Delivered { .. }) => self.delivered(),
                Ok(Local::Noted) => self.noted(),
                // The writer stopped: it holds no lock any more.
                Ok(Local::WriteFailed) => self.running = false,
                Ok(Local::Signal(_)) => {}
                Err(mpsc::RecvTimeoutError::Timeout) => return true,
                Err(mpsc::RecvTimeoutError::Disconnected) => return false,
            }
        }
        false
    }
}

#[cfg(unix)]
fn spawn_signals(events: mpsc::Sender<Local>) -> Result<()> {
    use signal_hook::consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGWINCH};
    let mut signals =
        signal_hook::iterator::Signals::new([SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGWINCH])
            .context("installing the signal handlers")?;
    std::thread::Builder::new()
        .name("wssp-shell-signals".into())
        .spawn(move || {
            for signal in signals.forever() {
                if events.send(Local::Signal(signal)).is_err() {
                    return;
                }
            }
        })
        .context("starting the signal watcher")?;
    Ok(())
}

#[cfg(not(unix))]
fn spawn_signals(_events: mpsc::Sender<Local>) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
pub(super) mod signals {
    pub const INT: i32 = signal_hook::consts::SIGINT;
    pub const TERM: i32 = signal_hook::consts::SIGTERM;
    pub const HUP: i32 = signal_hook::consts::SIGHUP;
    pub const WINCH: i32 = signal_hook::consts::SIGWINCH;
}

#[cfg(not(unix))]
pub(super) mod signals {
    pub const INT: i32 = 2;
    pub const TERM: i32 = 15;
    pub const HUP: i32 = 1;
    pub const WINCH: i32 = 28;
}

/// The stderr line of a channel notice (`\r` ends it on a raw terminal).
fn notice_line(code: Notice, raw: bool) -> String {
    let text = match code {
        Notice::UnsupportedSignal => "wssp: the sandbox cannot deliver that signal",
        Notice::StateConflict => "wssp: the sandbox refused that request for this channel",
    };
    if raw {
        format!("{text}\r")
    } else {
        text.to_owned()
    }
}

/// One shell session: connect, open, pump, and the exit status.
fn session(credential: &UserCredential, target: &str, request: &Request) -> Result<i32> {
    let mut connection = connect(credential, target, Purpose::Shell)?;
    let (events_tx, events) = mpsc::channel::<Local>();
    // Signals are ours before the terminal goes raw, so none kills the
    // process with the terminal still raw (until then a Ctrl-C closes the
    // pending channel: the terminal is not raw before `ready`).
    spawn_signals(events_tx.clone())?;
    let size = tty::size().unwrap_or((24, 80));
    let (rows, cols) = crate::connect_client::clamp_size(size.0, size.1);
    let login = request.argv.is_none().then_some(true);
    let pty = (request.kind == Kind::Pty).then(|| PtyParams {
        rows,
        cols,
        term: request.term.clone(),
    });
    let mut writer = Writer::spawn(events_tx.clone())?;
    // A pty session's terminal goes raw on `ready` (in `pump`); the guard
    // lives here so every way out of `pump` restores it below.
    let mut raw: Option<tty::RawMode> = None;
    // From here the writer owns stdout and stderr: a log event would write
    // to stderr from this thread (see `Writer`), so none is written, up to
    // the process exit.
    crate::logging::hold_stderr(true);
    let result = pump(
        &mut connection,
        request,
        login,
        pty,
        (rows, cols),
        &mut raw,
        &mut writer,
        &events,
    );
    // However the session ended (exit, close deadline, `end`, a lost
    // socket, a failed write), the writer gets a bounded time to deliver.
    let mut stuck = writer.stuck(&events);
    drop(raw);
    // From here to the process exit nothing writes to stdout or stderr on
    // this thread, whatever state the writer is in: stderr may be full with
    // every frame already written, and a synchronous write would block on it
    // forever. The log hold stays set until the process exits.
    let result = result.map_err(wssp_side);
    let status = match &result {
        Ok(status) => *status,
        Err(error) => crate::exit::code_for(error) as i32,
    };
    let line = match &result {
        Err(error) if !stuck => crate::exit::failure_line(error),
        _ => None,
    };
    // A live writer takes the error line after the output, with the same
    // bounded time.
    let mut written = line.is_none();
    if let Some(line) = &line
        && writer.running
        && writer.note(line.clone())
    {
        stuck = writer.stuck(&events);
        written = writer.running && writer.undelivered == 0;
    }
    connection.finish();
    if stuck {
        // The writer is blocked on a stdout or stderr nobody reads and holds
        // that stream's lock: printing the error line or flushing stdout
        // would wait on it forever. End now with the status the session
        // produced and no message. `std::process::exit` is safe here: its
        // at-exit stdout cleanup only `try_lock`s
        // (library/std/src/io/stdio.rs `cleanup`, Rust 1.99.1: "We use
        // try_lock() instead of lock(), because someone might have leaked a
        // StdoutLock, which would otherwise cause a deadlock here."), and
        // stderr is unbuffered with no cleanup at all.
        std::process::exit(status);
    }
    if !writer.running || !written {
        // The writer stopped on a failed write (it holds no lock), before
        // or after the line was queued, or refused the line: the line, if
        // unwritten, and the stdout flush get a thread of their own and the
        // same bounded time.
        final_report(if written { None } else { line }, status);
    }
    // The writer is alive and idle (it flushed every stdout frame, so
    // stdout holds nothing buffered) and wrote the error line: `main` only
    // flushes the empty stdout and exits with the status, printing nothing.
    match result {
        Ok(status) => Ok(status),
        Err(_) => Err(anyhow::Error::new(ProcessExit(status))),
    }
}

/// End the process with `status` after a stopped writer: flush stdout and
/// write `line` to stderr from a short-lived thread, waiting at most
/// [`WRITER_SETTLE`] for it, so a full stderr (or a stdout that blocks again)
/// cannot hold the process. That thread keeps the stdout lock until the
/// process exits, so the at-exit stdout cleanup (`try_lock`, see
/// [`session`]) skips stdout instead of retrying bytes a failed write left
/// buffered.
pub(super) fn final_report(line: Option<String>, status: i32) -> ! {
    final_report_by(line, status, Instant::now() + WRITER_SETTLE)
}

/// [`final_report`], waiting for the stdout flush and the line only until
/// `deadline` (`wssp ssh --stdio`'s one teardown deadline).
pub(super) fn final_report_by(line: Option<String>, status: i32, deadline: Instant) -> ! {
    let (done_tx, done) = mpsc::channel::<()>();
    let spawned = std::thread::Builder::new()
        .name("wssp-shell-final".into())
        .spawn(move || {
            let mut out = std::io::stdout().lock();
            let _ = std::io::Write::flush(&mut out);
            if let Some(line) = line {
                let _ = output::diagnostic(line);
            }
            let _ = done_tx.send(());
            // Holds `out` until `process::exit` ends the process.
            loop {
                std::thread::park();
            }
        });
    if spawned.is_ok() {
        let _ = done.recv_timeout(deadline.saturating_duration_since(Instant::now()));
    }
    std::process::exit(status);
}

#[allow(clippy::too_many_arguments)]
fn pump(
    connection: &mut Connection,
    request: &Request,
    login: Option<bool>,
    pty: Option<PtyParams>,
    mut sent_size: (u16, u16),
    raw: &mut Option<tty::RawMode>,
    writer: &mut Writer,
    events: &mpsc::Receiver<Local>,
) -> Result<i32> {
    let channel = connection.open(
        request.kind,
        request.argv.clone(),
        login,
        request.cwd.clone(),
        request.env.clone(),
        pty,
    )?;
    // Read from `ready` on: on a tty, only once it is raw, so a Ctrl-D typed
    // while the channel opens is not taken as the end of input.
    let mut stdin: Option<mpsc::Receiver<Input>> = None;
    let mut stdin_open = true;
    let mut ready = false;
    let mut resize_due = false;
    let mut last_interrupt: Option<Instant> = None;
    // A SIGTERM or SIGHUP was forwarded already: the next one closes.
    let mut terminated = false;
    // A close this client decided: its exit status and the wait's deadline.
    let mut closing: Option<(i32, Instant)> = None;
    loop {
        let mut released = connection.poll()?;
        while let Ok(local) = events.try_recv() {
            match local {
                Local::Delivered { stream, seq } => {
                    writer.delivered();
                    released.extend(connection.delivered(channel, stream, seq));
                }
                Local::Noted => writer.noted(),
                Local::WriteFailed => {
                    let error = writer.failure();
                    return output_failed(connection, channel, error);
                }
                Local::Signal(signal) if signal == signals::WINCH => resize_due = true,
                Local::Signal(signal) => {
                    let now = Instant::now();
                    let double =
                        last_interrupt.is_some_and(|at| now.duration_since(at) < DOUBLE_INTERRUPT);
                    let forward = match request.kind {
                        // Before `ready` nothing runs yet to signal: like
                        // every other case below, the signal closes the
                        // pending channel (a close before `ready` is a kill
                        // on the node).
                        Kind::Exec if ready && signal == signals::INT && !double => {
                            last_interrupt = Some(now);
                            Some(Signal::Int)
                        }
                        Kind::Exec
                            if ready
                                && !terminated
                                && (signal == signals::TERM || signal == signals::HUP) =>
                        {
                            terminated = true;
                            Some(if signal == signals::TERM {
                                Signal::Term
                            } else {
                                Signal::Hup
                            })
                        }
                        // On a tty the keys travel as bytes; a signal sent
                        // to the CLI itself ends the session. A second
                        // Ctrl-C closes an exec channel (128 + 2 = 130), as
                        // does a second SIGTERM or SIGHUP (143, 129).
                        // The wire has no QUIT, so SIGQUIT always closes
                        // (128 + 3 = 131), through the raw-mode guard.
                        _ => None,
                    };
                    match forward {
                        Some(remote) => connection.signal(channel, remote)?,
                        None => {
                            connection.close_channel(channel)?;
                            if closing.is_none() {
                                closing = Some((128 + signal, now + CLOSE_WAIT));
                            }
                        }
                    }
                }
            }
        }
        for event in released {
            match event {
                Event::Ready { .. } => {
                    ready = true;
                    if request.kind == Kind::Pty {
                        resize_due = true;
                        if raw.is_none() {
                            *raw = Some(tty::RawMode::enter()?);
                        }
                    }
                    if stdin.is_none() {
                        stdin = Some(spawn_stdin(connection.data_max(request.kind))?);
                    }
                }
                Event::Output {
                    stream, seq, body, ..
                } => {
                    if let Err(error) = writer.send(stream, seq, body) {
                        return output_failed(connection, channel, error);
                    }
                }
                Event::Eof { .. } => {}
                Event::Notice { code, .. } => {
                    writer.note(notice_line(code, raw.is_some()));
                }
                Event::Exit { outcome, .. } => {
                    let local = closing.map(|(status, _)| status);
                    return outcome_status(outcome, local);
                }
            }
        }
        if let Some((status, deadline)) = closing
            && Instant::now() >= deadline
        {
            return Ok(status);
        }
        if ready && resize_due && request.kind == Kind::Pty {
            resize_due = false;
            if let Some((rows, cols)) = tty::size() {
                let size = crate::connect_client::clamp_size(rows, cols);
                if size != sent_size {
                    connection.resize(channel, size.0, size.1)?;
                    sent_size = size;
                }
            }
        }
        // The turn's acks go first: stdin queued behind them never delays
        // the remote side's credit, and at most a few frames leave per turn.
        connection.queue_acks()?;
        for _ in 0..STDIN_FRAMES_PER_TURN {
            let Some(input) = &stdin else { break };
            if !(stdin_open && closing.is_none() && connection.stdin_credit(channel)) {
                break;
            }
            let item = match input.try_recv() {
                Ok(item) => item,
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => Input::End,
            };
            match item {
                Input::Data(bytes) => connection.send_stdin(channel, &bytes)?,
                Input::Failed(error) => {
                    stdin_open = false;
                    let end = if raw.is_some() { "\r" } else { "" };
                    writer.note(format!("wssp: reading stdin failed: {error}{end}"));
                    if request.kind == Kind::Exec {
                        connection.stdin_eof(channel)?;
                    }
                }
                Input::End => {
                    stdin_open = false;
                    // A tty's end of input is a byte (Ctrl-D); only a piped
                    // stdin's EOF closes the remote stdin.
                    if request.kind == Kind::Exec {
                        connection.stdin_eof(channel)?;
                    }
                }
            }
        }
        connection.flush()?;
    }
}

/// A local write failed (`error`, from the writer): close the channel and
/// end with that failure, 141 for a closed stdout or stderr.
fn output_failed(connection: &mut Connection, channel: u32, error: anyhow::Error) -> Result<i32> {
    connection.close_channel(channel)?;
    let _ = connection.flush();
    Err(super::output_closed(error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connect_client::wire::WireError;

    fn args(env: &[(&str, &str)], argv: &[&str]) -> ShellArgs {
        ShellArgs {
            sandbox: "sbx_1".into(),
            cwd: None,
            env: env
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            no_tty: false,
            json: false,
            argv: argv.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    #[test]
    fn env_is_limited_to_terminal_and_locale_names() {
        let ok = request(
            &args(
                &[("TERM", "vt100"), ("LANG", "C.UTF-8"), ("LC_ALL", "C")],
                &[],
            ),
            true,
            Some("xterm"),
        )
        .unwrap();
        assert_eq!(ok.term, "vt100");
        assert_eq!(ok.kind, Kind::Pty);
        assert_eq!(ok.argv, None);
        assert_eq!(ok.env.unwrap().len(), 2);
        for bad in ["PATH", "HOME", "LC_", "lang", "TERMINFO"] {
            let error = request(&args(&[(bad, "x")], &[]), true, None).unwrap_err();
            assert_eq!(crate::exit::code_for(&error), ExitCode::Usage, "{bad}");
        }
        let error = request(&args(&[("TERM", "bad term")], &[]), true, None).unwrap_err();
        assert_eq!(crate::exit::code_for(&error), ExitCode::Usage);
    }

    #[test]
    fn the_local_term_is_used_only_when_valid() {
        assert_eq!(
            term_of(None, Some("screen-256color")).unwrap(),
            "screen-256color"
        );
        assert_eq!(term_of(None, Some("bad term")).unwrap(), DEFAULT_TERM);
        assert_eq!(term_of(None, None).unwrap(), DEFAULT_TERM);
    }

    #[test]
    fn argv_and_cwd_are_checked_locally() {
        let mut bad = args(&[], &["a\0b"]);
        assert!(request(&bad, false, None).is_err());
        bad = args(&[], &["ls"]);
        bad.cwd = Some("relative".into());
        assert!(request(&bad, false, None).is_err());
        let ok = request(
            &args(&[], &["sh", "-c", "echo \"$1\"", "--", ""]),
            false,
            None,
        )
        .unwrap();
        assert_eq!(ok.kind, Kind::Exec);
        assert_eq!(ok.argv.unwrap(), vec!["sh", "-c", "echo \"$1\"", "--", ""]);
    }

    #[test]
    fn a_send_to_a_stopped_writer_keeps_the_write_error() {
        // The writer failed on a closed stdout and returned before this
        // send: its queue is gone, but the error is still the broken pipe.
        let (sender, receiver) = mpsc::channel::<Item>();
        drop(receiver);
        let thread = std::thread::spawn(|| {
            Some(
                anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
                    .context("writing to stdout"),
            )
        });
        let mut writer = Writer {
            sender,
            thread: Some(thread),
            undelivered: 0,
            diagnostics: 0,
            running: true,
        };
        let error = writer
            .send(OutputStream::Stdout, 3, b"late".to_vec())
            .unwrap_err();
        assert!(!writer.running);
        assert_eq!(
            crate::exit::code_for(&super::super::output_closed(error)),
            ExitCode::OutputClosed
        );
        // A stopped writer queues no diagnostic line either.
        assert!(!writer.note("wssp: late".into()));
    }

    #[test]
    fn outcomes_map_to_exit_statuses() {
        assert_eq!(outcome_status(Outcome::Code(0), None).unwrap(), 0);
        assert_eq!(outcome_status(Outcome::Code(7), None).unwrap(), 7);
        assert_eq!(outcome_status(Outcome::Code(125), None).unwrap(), 125);
        assert_eq!(outcome_status(Outcome::Signal(15), None).unwrap(), 143);
        assert_eq!(outcome_status(Outcome::Signal(9), None).unwrap(), 137);
        let code =
            |outcome, local| crate::exit::code_for(&outcome_status(outcome, local).unwrap_err());
        assert_eq!(code(Outcome::Code(256), None), ExitCode::ExecFailure);
        assert_eq!(code(Outcome::Code(-1), None), ExitCode::ExecFailure);
        assert_eq!(code(Outcome::Unknown, None), ExitCode::ExecFailure);
        let revoked = outcome_status(
            Outcome::Closed {
                intent: Intent::Revoked,
                error: None,
            },
            None,
        )
        .unwrap_err();
        assert_eq!(crate::exit::code_for(&revoked), ExitCode::ExecFailure);
        assert!(crate::exit::message_for(&revoked).contains("`revoked`"));
        // A close this client decided keeps its own status.
        assert_eq!(
            outcome_status(
                Outcome::Closed {
                    intent: Intent::Client,
                    error: None
                },
                Some(130)
            )
            .unwrap(),
            130
        );
        assert_eq!(outcome_status(Outcome::Unknown, Some(143)).unwrap(), 143);
        let failed = |code: &str| Outcome::Failed {
            error: WireError {
                code: code.into(),
                message: "m".into(),
            },
        };
        assert_eq!(code(failed("host_capacity"), None), ExitCode::Retryable);
        assert_eq!(code(failed("rate_limited"), None), ExitCode::Retryable);
        assert_eq!(code(failed("disconnected"), None), ExitCode::Retryable);
        assert_eq!(
            code(failed("unsupported_capability"), None),
            ExitCode::ExecFailure
        );
    }
}
