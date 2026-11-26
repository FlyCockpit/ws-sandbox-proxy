//! Long-running guest commands: identity, wait, and cancel.
//!
//! E2B envd starts a process with `/bin/sh -c '… exec "$@"'` so the user binary
//! owns the tracked PID, then `SendSignal` / `commands.kill(pid)` signals that
//! PID (`SIGKILL` by default). We do the same wrap, and also `setsid` so the
//! command is a session/process-group leader. Incus guest agent is the parent,
//! not us; killing the group is the durable substitute for envd being able to
//! walk its own children.
//!
//! Stdin is the same `incus exec` pipe (no second exec — the guest agent can
//! only run one at a time). The pipe is opened only when the command starts
//! with stdin (`RunCommandRequest.stdin` or queued `write_stdin`); otherwise
//! stdin is `/dev/null` so `sleep` and timeouts stay reliable.

use crate::effect::PositiveEvidence;
use std::collections::HashMap;
use std::io::{Read, Write};
#[cfg(test)]
use std::os::unix::process::CommandExt;
#[cfg(test)]
use std::process::Command;
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use sandbox_protocol::{OperationState, SandboxErrorCode};

use crate::before_issue::incus as pre;
use crate::effect::{EffectResult, Observation};
use crate::error::RuntimeError;
use crate::r#trait::{
    CommandRecord, CommandStream, CommandStreamChunk, GuestProcess, ListProcessesResponse,
    ProcessSignal, RunCommandRequest, RunCommandResponse, WriteStdinRequest,
};
use crate::{EffectError, EffectOutcome};

use super::client::{self, BoundInstance, IncusClient, IncusCommandOutput, random_nonce};
use super::frames::{GuestPid, has_completion_frame, parse_supervised_frames};

const POLL: Duration = Duration::from_millis(20);
/// Approved Q2/A helper. Finite per-item deadline for the termination pool.
pub(super) const SIGNAL_HELPER_LAUNCH: &str = r#"
if ! command -v python3 >/dev/null 2>&1; then
    printf 'WSSP_SIGNAL %s interpreter_missing\n' "$3" >&2
    exit 127
fi
exec python3 -I -c "$@"
"#;
pub(super) const SIGNAL_HELPER: &str = include_str!("signal-helper.py");
const SIGNAL_HELPER_DEADLINE: Duration = Duration::from_secs(10);
/// Incus exec accepts only a primary UID/GID. The launcher selects an
/// optional guest systemd scope (OOMPolicy=continue keeps a workload OOM away
/// from incus-agent), then runs the fixed `DIRECT_HELPER` body with
/// `unit uid gid argv...`. Isolated Python ignores guest PYTHON* config.
///
/// The scope is the attempt's named, root-owned system scope
/// `wssp.slice/<unit>` ([`command_scope_unit`]). Both bodies share one
/// prefix (`scope_gate!`) that runs as guest root before anything else: it
/// pops `unit`, and unless this process provably runs in exactly that
/// scope it first records the per-boot marker `/run/wssp/unscoped`, failing
/// closed (exit 1, no workload) when the marker cannot be written. The
/// retire helper (`retire-helper.py`) reads that marker: a missing scope
/// proves the attempt gone only in a boot without an unscoped launch.
macro_rules! scoped_identity_helper {
    ($direct:literal) => {
        concat!(
            r#"
import os, re, subprocess, sys

UNIT_RE = r'"#,
            command_scope_unit_re!(),
            r#"'
DIRECT_HELPER = r""""#,
            scope_gate!(),
            $direct,
            r#""""

def scope_usable():
    # Read-only checks: the workload is never part of a capability probe.
    if not os.access('/usr/bin/systemd-run', os.X_OK):
        return False
    if not os.path.isdir('/run/systemd/system'):
        return False
    try:
        with open('/proc/1/comm', encoding='ascii') as comm:
            if comm.read().strip() != 'systemd':
                return False
        version = subprocess.run(
            ['/usr/bin/systemd-run', '--version'], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=2,
            check=False,
        )
        fields = version.stdout.split()
        return (version.returncode == 0 and len(fields) >= 2
                and fields[0] == b'systemd' and int(fields[1]) >= 254)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return False

if len(sys.argv) < 2 or re.fullmatch(UNIT_RE, sys.argv[1]) is None:
    os._exit(1)
if scope_usable():
    # Exec once. Even a scope failure after workload effects must never retry.
    # OOMPolicy=continue keeps a workload OOM from stopping incus-agent.service;
    # scope execution preserves pipes/cwd/env and disables argv $ expansion.
    try:
        os.execv('/usr/bin/systemd-run', [
            '/usr/bin/systemd-run', '--scope', '--quiet', '--collect',
            '--no-ask-password', '--description=wssp-command',
            '--property=OOMPolicy=continue', '--expand-environment=no',
            '--unit=' + sys.argv[1], '--slice=wssp.slice', '--',
            'python3', '-I', '-S', '-c', DIRECT_HELPER, *sys.argv[1:],
        ])
    except OSError:
        os._exit(1)
else:
    exec(DIRECT_HELPER)
"#
        )
    };
}

/// The prefix of both identity bodies (guest root, before any drop): pop and
/// re-validate `unit`; then, unless `/proc/self/cgroup` is exactly the single
/// line `0::/wssp.slice/<unit>`, write the unscoped marker. `/run/wssp` must
/// be a root-owned real directory that is neither group- nor world-writable,
/// and the marker a root-owned regular file; any failure exits 1 before the
/// drop, so no workload runs and no PID banner binds a start.
macro_rules! scope_gate {
    () => {
        concat!(
            r#"
import os, re, stat, sys
UNIT_RE = r'"#,
            command_scope_unit_re!(),
            r#"'
def _wssp_scope_gate():
    unit = sys.argv.pop(1)
    if re.fullmatch(UNIT_RE, unit) is None:
        os._exit(1)
    try:
        with open('/proc/self/cgroup', 'rb') as current:
            if current.read() == b'0::/wssp.slice/' + unit.encode() + b'\n':
                return
    except OSError:
        pass
    try:
        try:
            os.mkdir('/run/wssp', 0o755)
        except FileExistsError:
            pass
        info = os.lstat('/run/wssp')
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o022):
            raise OSError()
        run = os.open('/run/wssp',
                      os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(run)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                    or info.st_mode & 0o022):
                raise OSError()
            marker = os.open('unscoped', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW
                             | os.O_CLOEXEC | os.O_NONBLOCK, 0o644, dir_fd=run)
            try:
                info = os.fstat(marker)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
                    raise OSError()
            finally:
                os.close(marker)
        finally:
            os.close(run)
    except Exception:
        os._exit(1)
_wssp_scope_gate()
"#
        )
    };
}

/// The one unit-name grammar the launcher, its gate and the retire helper
/// accept (Python `re.fullmatch`): `wssp-cmd-<operation>-<gen>-<attempt>.scope`.
macro_rules! command_scope_unit_re {
    () => {
        r"wssp-cmd-[A-Za-z0-9_-]{1,128}-[0-9]{1,20}-[0-9]{1,20}\.scope"
    };
}

/// The attempt's guest scope unit, `wssp-cmd-<operationId>-<generation>-<attempt>.scope`
/// (at most 185 bytes for a valid operation id). The launcher places the
/// command in `wssp.slice/<unit>`; the retire helper derives the same name.
/// It parses unambiguously from the right: generation and attempt are digits.
pub fn command_scope_unit(
    operation_id: &str,
    generation: u64,
    attempt: u64,
) -> Result<String, RuntimeError> {
    validate_operation_id(operation_id)?;
    Ok(format!(
        "wssp-cmd-{operation_id}-{generation}-{attempt}.scope"
    ))
}

/// The Rust side of [`command_scope_unit_re`]: refuse any other unit name
/// before it reaches a guest argv.
pub(super) fn validate_command_scope_unit(unit: &str) -> Result<(), RuntimeError> {
    let digits =
        |part: &str| (1..=20).contains(&part.len()) && part.bytes().all(|b| b.is_ascii_digit());
    let valid = unit
        .strip_prefix("wssp-cmd-")
        .and_then(|rest| rest.strip_suffix(".scope"))
        .and_then(|rest| {
            let (rest, attempt) = rest.rsplit_once('-')?;
            let (operation, generation) = rest.rsplit_once('-')?;
            Some(validate_operation_id(operation).is_ok() && digits(generation) && digits(attempt))
        })
        .unwrap_or(false);
    if !valid {
        return Err(RuntimeError::new(
            SandboxErrorCode::ProtocolError,
            "invalid command scope unit",
        ));
    }
    Ok(())
}

// Guest user: initialize supplementary groups, then drop root and exec the
// fixed environment/bootstrap wrapper. uid/gid 0 is refused here.
const IDENTITY_HELPER: &str = scoped_identity_helper!(
    r#"
import os, pwd, sys
uid, gid = int(sys.argv[1]), int(sys.argv[2])
try:
    account = pwd.getpwuid(uid)
    if uid <= 0 or gid <= 0 or account.pw_gid != gid:
        raise ValueError()
    os.initgroups(account.pw_name, gid)
    os.setgid(gid)
    os.setuid(uid)
    os.execvp(sys.argv[3], sys.argv[3:])
except Exception:
    os._exit(1)
"#
);

// D1: template-build steps only. Same launcher and argv shape (`0 0 argv`),
// but the body stays guest root: it accepts nothing but uid/gid 0 while
// actually running as root, keeps only group 0, and execs the wrapper.
const ROOT_IDENTITY_HELPER: &str = scoped_identity_helper!(
    r#"
import os, sys
uid, gid = int(sys.argv[1]), int(sys.argv[2])
try:
    if uid != 0 or gid != 0 or os.getuid() != 0 or os.getgid() != 0:
        raise ValueError()
    os.setgroups([0])
    os.execvp(sys.argv[3], sys.argv[3:])
except Exception:
    os._exit(1)
"#
);

pub(super) const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(120);
pub(super) const MAX_COMMAND_TIMEOUT: Duration = Duration::from_secs(1800);

pub(super) fn effective_command_timeout(
    timeout_ms: Option<u64>,
    default: Duration,
) -> Result<Option<Duration>, RuntimeError> {
    sandbox_protocol::validate_command_timeout(timeout_ms)
        .map_err(|(code, message)| RuntimeError::new(code, message))?;
    let fallback = if default.is_zero() {
        DEFAULT_COMMAND_TIMEOUT
    } else {
        default.min(MAX_COMMAND_TIMEOUT)
    };
    Ok(match timeout_ms {
        Some(0) => None,
        Some(ms) => Some(Duration::from_millis(ms)),
        None => Some(fallback),
    })
}

// Allow VM-agent/transport startup in addition to the guest watchdog, so a
// typed guest setup failure can arrive before the host declares uncertainty.
pub(super) const HOST_SETUP_BUDGET: Duration =
    super::env_frame::SETUP_BUDGET.saturating_add(Duration::from_secs(10));

/// Execution starts once at the nonce-bound PID banner; READY precedes argv.
struct CommandTimer {
    setup_deadline: Instant,
    budget: Option<Duration>,
    execution_started: Option<Instant>,
}
impl CommandTimer {
    fn new(now: Instant, budget: Option<Duration>) -> Self {
        Self {
            setup_deadline: now + HOST_SETUP_BUDGET,
            budget,
            execution_started: None,
        }
    }
    /// A start is admissible only before the setup deadline (or once one
    /// started). A banner first seen later (a stalled supervisor draining a
    /// buffered head) never starts execution and never binds a start, so a
    /// bound start always began within `HOST_SETUP_BUDGET` of the spawn: the
    /// one bound the retire helper's deadline slack relies on.
    fn admits_start(&self, now: Instant) -> bool {
        self.execution_started.is_some() || now < self.setup_deadline
    }
    fn started(&mut self, now: Instant) {
        if self.admits_start(now) {
            self.execution_started.get_or_insert(now);
        }
    }
    fn deadline(&self) -> Option<Instant> {
        match self.execution_started {
            None => Some(self.setup_deadline),
            Some(start) => self.budget.map(|budget| start + budget),
        }
    }
    fn expired(&self, now: Instant) -> bool {
        self.deadline().is_some_and(|deadline| now >= deadline)
    }
}

type PendingStdin = HashMap<(String, u64, u64), (Vec<u8>, bool)>;
type ResolvedSignalTarget = (crate::CommandBirth, String, crate::GuestIdentity);

enum StdinMsg {
    Data(Vec<u8>),
    Close,
}

#[derive(Clone)]
struct ActiveExec {
    host_pid: Option<u32>,
    generation: u64,
    attempt: u64,
    instance: BoundInstance,
    guest_pid: Option<GuestPid>,
    /// Public start identity (4a), bound once from the fixed head record.
    birth: Option<crate::CommandBirth>,
    /// Host-local wrapper identity; never sent to the server.
    nonce: String,
    /// Accepted-request description for tracked listing/connect (4a).
    description: Option<crate::CommandDescription>,
    guest: crate::GuestIdentity,
    argv: Vec<String>,
    cancelled: bool,
    stdin: Option<mpsc::Sender<StdinMsg>>,
    /// The effective execution budget in ms (`0`: none), journaled with the
    /// start for the retire helper's deadline (S13).
    budget_ms: u64,
    /// The uid the launcher drops to; `None` for a build-root exec (D1),
    /// which never journals a start.
    start_uid: Option<u32>,
}

#[derive(Clone)]
pub struct ExecSupervisor {
    output: Option<crate::CommandOutput>,
    client: IncusClient,
    active: Arc<Mutex<HashMap<String, ActiveExec>>>,
    pending_stdin: Arc<Mutex<PendingStdin>>,
    #[cfg(test)]
    pub(super) stdin_error_barrier: Arc<Mutex<Option<Arc<std::sync::Barrier>>>>,
}

impl ExecSupervisor {
    fn command_now(&self) -> Instant {
        self.client
            .cancelled
            .as_ref()
            .map_or_else(Instant::now, |permit| permit.clock_now())
    }
    pub fn new(client: IncusClient) -> Self {
        Self {
            client,
            output: None,
            active: Arc::new(Mutex::new(HashMap::new())),
            pending_stdin: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(test)]
            stdin_error_barrier: Arc::new(Mutex::new(None)),
        }
    }

    /// Share execution bookkeeping, but use the caller's client for every IO
    /// path, including nested signal/cancel/timeout helpers.
    pub(super) fn with_client(&self, client: IncusClient) -> Self {
        Self {
            client,
            output: self.output.clone(),
            active: self.active.clone(),
            pending_stdin: self.pending_stdin.clone(),
            #[cfg(test)]
            stdin_error_barrier: self.stdin_error_barrier.clone(),
        }
    }

    pub fn with_output(&self, output: crate::CommandOutput) -> Self {
        let mut scoped = self.with_client(self.client.clone());
        scoped.output = Some(output);
        scoped
    }

    pub fn with_cancellation(&self, permit: Arc<crate::RuntimePermit>) -> Self {
        let mut client = self.client.clone();
        client.cancelled = Some(permit);
        self.with_client(client)
    }

    pub fn active_guest_pid(&self, operation_id: &str) -> Option<u32> {
        self.active
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .get(operation_id)
            .and_then(|exec| exec.guest_pid.and_then(GuestPid::banner))
    }

    /// Public start identity bound for an active command (4a), if any.
    pub fn active_birth(&self, operation_id: &str) -> Option<crate::CommandBirth> {
        self.birth_of(operation_id)
    }

    /// Tracked identity plus accepted-request description, only once started.
    pub fn active_process(
        &self,
        operation_id: &str,
    ) -> Option<(crate::CommandBirth, crate::CommandDescription)> {
        let active = self.active.lock().unwrap_or_else(|err| err.into_inner());
        let exec = active.get(operation_id)?;
        Some((exec.birth.clone()?, exec.description.clone()?))
    }

    /// Bind before acquiring admission/active-map locks. Every execution adapter
    /// below requires the capability, including callers that bypass the runtime.
    pub fn bind(&self, request: &RunCommandRequest) -> Result<BoundInstance, RuntimeError> {
        let bound = self.client.bind_instance(
            &request.instance_name,
            &request.sandbox_id,
            &request.template_fingerprint,
            None,
        )?;
        // A periodic inconclusive observation closes dispatch until fresh
        // verification. Ask for that verification here, before authority and
        // active-map locks, instead of relying on the next background sweep.
        let refused = self
            .client
            .policy_refusals
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .contains(&request.sandbox_id);
        if refused {
            self.client
                .verify_bound_enforcement(&request.sandbox_id, bound.is_running())?;
        }
        Ok(bound)
    }

    pub fn run(
        &self,
        bound: &BoundInstance,
        request: &RunCommandRequest,
    ) -> EffectOutcome<RunCommandResponse> {
        self.run_inner(
            bound,
            request,
            false,
            || Ok((Arc::new(AtomicBool::new(false)), ())),
            &|_| false,
        )
    }

    pub fn run_with_admission<G>(
        &self,
        bound: &BoundInstance,
        request: &RunCommandRequest,
        admit: impl FnOnce() -> Result<(Arc<AtomicBool>, G), RuntimeError>,
    ) -> EffectOutcome<RunCommandResponse> {
        self.run_inner(bound, request, true, admit, &|_| false)
    }

    /// The relay keeps this completion owner after publishing an uncertain
    /// cleanup observation. Returning false relinquishes retries (direct API).
    pub fn run_with_updates<G>(
        &self,
        bound: &BoundInstance,
        request: &RunCommandRequest,
        admit: impl FnOnce() -> Result<(Arc<AtomicBool>, G), RuntimeError>,
        observe_unknown: impl Fn(RunCommandResponse) -> bool,
    ) -> EffectOutcome<RunCommandResponse> {
        self.run_inner(bound, request, true, admit, &observe_unknown)
    }

    fn run_inner<G>(
        &self,
        bound: &BoundInstance,
        request: &RunCommandRequest,
        streaming_stdin: bool,
        admit: impl FnOnce() -> Result<(Arc<AtomicBool>, G), RuntimeError>,
        observe_unknown: &impl Fn(RunCommandResponse) -> bool,
    ) -> EffectOutcome<RunCommandResponse> {
        let scoped = self.with_client(
            self.client
                .with_guest(&request.guest)
                .with_root_exec(request.runs_as_root()),
        );
        let result = scoped.run_scoped(bound, request, streaming_stdin, admit, observe_unknown);
        match result {
            Err(crate::EffectError::Unknown(error)) => Err(
                super::effect_completion::command_guest_lost(&scoped.client, bound)
                    .unwrap_or(crate::EffectError::Unknown(error)),
            ),
            other => other,
        }
    }

    fn run_scoped<G>(
        &self,
        bound: &BoundInstance,
        request: &RunCommandRequest,
        streaming_stdin: bool,
        admit: impl FnOnce() -> Result<(Arc<AtomicBool>, G), RuntimeError>,
        observe_unknown: &impl Fn(RunCommandResponse) -> bool,
    ) -> EffectOutcome<RunCommandResponse> {
        pre::phase(
            |before| {
                pre::command(&before, request)?;
                // Check the supplied capability against this request, then refresh
                // before taking the authority/active locks (no host IO under them).
                self.client.check_request_binding(
                    bound,
                    &request.instance_name,
                    &request.sandbox_id,
                    &request.template_fingerprint,
                )?;
                pre::running(&before, &self.client, bound)?;

                let (mut argv, exit_nonce) = pre::wrapper(&before, request)?;
                let unit =
                    command_scope_unit(&request.operation_id, request.generation, request.attempt)?;
                let timeout =
                    effective_command_timeout(request.timeout_ms, self.client.command_timeout)?;
                let env_frame = super::env_frame::encode(&request.env)?;
                if env_frame.is_some() {
                    argv = self.client.env_wrapper(
                        bound,
                        &argv,
                        &exit_nonce,
                        super::env_frame::SETUP_BUDGET,
                    )?;
                }
                // Admission owns the authority guard through placeholder → local spawn → publication.
                // No child waits, pipe reads or Incus response waits in this critical section.
                let (cancelled, admission_guard) = pre::supervised_admission(&before, admit)?;
                if cancelled.load(Ordering::Acquire) {
                    return Err(RuntimeError::new(
                        SandboxErrorCode::Cancelled,
                        "exec authority revoked before spawn",
                    )
                    .into());
                }
                let mut active = self.active.lock().unwrap_or_else(|err| err.into_inner());
                if active.contains_key(&request.operation_id) {
                    return Err(RuntimeError::new(
                        SandboxErrorCode::StateConflict,
                        "exec is already active",
                    )
                    .into());
                }
                active.insert(
                    request.operation_id.clone(),
                    ActiveExec {
                        host_pid: None,
                        generation: request.generation,
                        attempt: request.attempt,
                        instance: bound.clone(),
                        guest_pid: None,
                        birth: None,
                        nonce: exit_nonce.clone(),
                        description: crate::CommandDescription::from_request(request),
                        guest: request.guest.clone(),
                        argv: request.argv.clone(),
                        cancelled: false,
                        stdin: None,
                        budget_ms: timeout.map_or(0, |budget| {
                            u64::try_from(budget.as_millis()).unwrap_or(u64::MAX)
                        }),
                        start_uid: (!request.runs_as_root()).then_some(request.guest.guest_uid),
                    },
                );
                let pipe_stdin = streaming_stdin
                    || request.stdin.is_some()
                    || self
                        .pending_stdin
                        .lock()
                        .unwrap_or_else(|err| err.into_inner())
                        .contains_key(&(
                            request.operation_id.clone(),
                            request.generation,
                            request.attempt,
                        ));
                // The independently bounded tools probe above must not consume
                // the guest watchdog's transport/startup allowance.
                let started = self.command_now();
                let spawned = before.issue(|| {
                    self.client.spawn_exec(
                        bound,
                        &unit,
                        &argv,
                        request.cwd.as_deref(),
                        pipe_stdin || env_frame.is_some(),
                    )
                });
                let issued = match spawned {
                    Ok(issued) => issued,
                    Err(err) => {
                        active.remove(&request.operation_id);
                        return Err(err);
                    }
                };
                Ok(issued.map(|child| {
                    (
                        child,
                        active,
                        cancelled,
                        admission_guard,
                        started,
                        timeout,
                        exit_nonce,
                        env_frame,
                        pipe_stdin,
                    )
                }))
            },
            |issued| {
                let (
                    mut child,
                    mut active,
                    cancelled,
                    admission_guard,
                    started,
                    timeout,
                    exit_nonce,
                    env_frame,
                    pipe_stdin,
                ) = issued;
                if let Some(exec) = active.get_mut(&request.operation_id) {
                    exec.host_pid = Some(child.id());
                }
                let io_failed = Arc::new(AtomicBool::new(false));
                let (stdin_tx, stdin_pump) = attach_stdin(
                    &mut child,
                    env_frame,
                    request.stdin.as_deref(),
                    pipe_stdin,
                    io_failed.clone(),
                    #[cfg(test)]
                    self.stdin_error_barrier
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone(),
                );
                let pending_stdin = self
                    .pending_stdin
                    .lock()
                    .unwrap_or_else(|err| err.into_inner())
                    .remove(&(
                        request.operation_id.clone(),
                        request.generation,
                        request.attempt,
                    ));
                if let (Some(tx), Some((bytes, eof))) = (&stdin_tx, pending_stdin) {
                    let _ = send_stdin(
                        tx,
                        &WriteStdinRequest {
                            operation_id: request.operation_id.clone(),
                            generation: request.generation,
                            attempt: request.attempt,
                            bytes,
                            eof,
                        },
                    );
                }
                if let Some(exec) = active.get_mut(&request.operation_id) {
                    exec.stdin = stdin_tx;
                }
                drop(active);
                drop(admission_guard);
                let mut pumps = PipePumps(stdin_pump.into_iter().collect());

                let result = self.wait_child(
                    bound,
                    request,
                    &mut child,
                    started,
                    timeout,
                    &io_failed,
                    &cancelled,
                    &mut pumps,
                    &exit_nonce,
                    observe_unknown,
                );
                // Final receipts repeat the bound identity (4a); read it before
                // the active entry is forgotten.
                let birth = self.birth_of(&request.operation_id);
                let out = match result {
                    Ok(out) => out,
                    Err(err) => {
                        self.forget(&request.operation_id);
                        return Err(crate::effect::PostIssueError::Unknown(
                            err.with_birth(birth),
                        ));
                    }
                };
                self.forget(&request.operation_id);
                match out {
                    WaitOutcome::Cancelled(proof) => Ok(proof),
                    WaitOutcome::TimedOut(proof) => Err(crate::effect::PostIssueError::Completed(
                        crate::effect::CompletionFailure::CommandTimedOut(proof),
                    )
                    .with_birth(birth)),
                    WaitOutcome::Natural(out) => super::effect_completion::command_outcome(
                        request,
                        &out.stdout,
                        &out.stderr,
                        &exit_nonce,
                    )
                    .map(|done| {
                        done.map(|mut response| {
                            response.command.birth = birth.clone();
                            response
                        })
                    })
                    .map_err(|error| error.with_birth(birth)),
                }
            },
        )
    }

    pub fn cancel(&self, operation_id: &str) -> EffectOutcome<()> {
        // Request only. The worker that owns child/pumps is the sole completion
        // owner. This local control receipt is never a command outcome.
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        let _permit = self
            .client
            .cancelled
            .as_ref()
            .map(|p| p.admit())
            .transpose()?;
        if let Some(exec) = active.get_mut(operation_id) {
            exec.cancelled = true;
        }
        Ok(local_control_completion(()))
    }

    pub fn kill_local_groups(&self) {
        self.kill_local_groups_for(None);
    }

    fn kill_local_groups_for(&self, operation_id: Option<&str>) {
        let pids: Vec<_> = {
            let mut active = self.active.lock().unwrap_or_else(|err| err.into_inner());
            active
                .iter_mut()
                .filter(|(id, _)| operation_id.is_none_or(|target| target == id.as_str()))
                .filter_map(|(_, exec)| {
                    exec.stdin.take();
                    exec.host_pid
                })
                .collect()
        };
        for pid in pids {
            let _ = IncusClient::kill_process_group(pid);
        }
    }

    pub fn list_processes(&self, instance_name: &str) -> ListProcessesResponse {
        let active = self.active.lock().unwrap_or_else(|err| err.into_inner());
        let mut processes: Vec<GuestProcess> = active
            .iter()
            .filter(|(_, exec)| exec.instance.name() == instance_name)
            .filter_map(|(operation_id, exec)| {
                exec.guest_pid
                    .and_then(GuestPid::banner)
                    .map(|pid| GuestProcess {
                        operation_id: operation_id.clone(),
                        pid,
                        argv: exec.argv.clone(),
                    })
            })
            .collect();
        processes.sort_by_key(|process| process.pid);
        ListProcessesResponse { processes }
    }

    /// Tracked-only control (4b). Every effect needs the full qualified
    /// target, matched against this host's own bound birth; a naked PID, a
    /// census PID or a PID file never authorizes anything. SIGKILL becomes a
    /// request to the command's single cancellation owner (the nonce-bound
    /// primary cancel helper and final E-19/E-20 proof). TERM/INT/HUP use only
    /// the open-then-verify group-pidfd helper.
    pub fn signal(
        &self,
        instance: &BoundInstance,
        pid: u32,
        signal: ProcessSignal,
        target: Option<&crate::SignalTarget>,
    ) -> EffectOutcome<crate::SignalOutcome> {
        enum Prepared {
            Kill,
            Helper(IncusCommandOutput, String),
        }
        pre::phase(
            |before| {
                pre::signal(&before, pid)?;
                let target = pre::signal_admission(
                    &before,
                    target.filter(|target| target.pid == pid).ok_or_else(|| {
                        RuntimeError::new(
                            SandboxErrorCode::UnsupportedCapability,
                            "process signal requires a full tracked target",
                        )
                    }),
                )?;
                // Exact local resolution first: an untracked target costs no IO.
                let resolved = pre::signal_admission(
                    &before,
                    self.resolve_target(instance, target, signal.is_kill()),
                )?;
                let Some((birth, nonce, guest)) = resolved else {
                    // No active entry supplies knowledge of this incarnation.
                    // Keep this distinct from a definite pre-issue fence refusal.
                    return Err(RuntimeError::new(
                        SandboxErrorCode::UnknownOutcome,
                        "process outcome is unknown",
                    )
                    .into());
                };
                if signal.is_kill() {
                    // Request only, like `cancel`: the worker owning child/pipes
                    // is the sole completion owner and runs the nonce-bound
                    // primary helper; a repeat adds no other signal sequence.
                    return before.issue(|| Ok(Prepared::Kill));
                }
                pre::bound(&before, &self.client, instance)?;
                let helper_nonce = random_nonce()?;
                let client = self.client.with_guest(&guest);
                before.issue(|| {
                    client
                        .exec_argv_effect_bounded(
                            instance,
                            &[
                                "/bin/sh".to_string(),
                                "-c".to_string(),
                                SIGNAL_HELPER_LAUNCH.to_string(),
                                "wssp-signal".to_string(),
                                SIGNAL_HELPER.to_string(),
                                "wssp-signal".to_string(),
                                helper_nonce.clone(),
                                birth.pid.to_string(),
                                birth.boot_id.clone(),
                                birth.start_ticks.to_string(),
                                guest.guest_uid.to_string(),
                                nonce.clone(),
                                signal.as_kill_arg().to_string(),
                            ],
                            SIGNAL_HELPER_DEADLINE,
                        )
                        .map(|out| Prepared::Helper(out, helper_nonce.clone()))
                })
            },
            |prepared| match prepared {
                Prepared::Kill => Ok(
                    local_control_completion(()).map(|()| crate::SignalOutcome::CancelRequested)
                ),
                Prepared::Helper(out, helper_nonce) => {
                    super::effect_completion::pidfd_signal_outcome(&helper_nonce, &out)
                        .map(|done| done.map(|()| crate::SignalOutcome::ProcessGroup))
                }
            },
        )
    }

    /// Resolve the exact tracked target under the active-map lock. Absence is
    /// UNKNOWN (exit/restart race); a qualifier mismatch is `process_not_found`;
    /// known-but-unstarted is
    /// `process_not_started`; a pending cancellation refuses new non-kill
    /// signals. SIGKILL marks the single cancellation owner here.
    fn resolve_target(
        &self,
        instance: &BoundInstance,
        target: &crate::SignalTarget,
        kill: bool,
    ) -> Result<Option<ResolvedSignalTarget>, RuntimeError> {
        let mut active = self.active.lock().unwrap_or_else(|err| err.into_inner());
        let _permit = self
            .client
            .cancelled
            .as_ref()
            .map(|permit| permit.admit())
            .transpose()?;
        let not_found =
            || RuntimeError::new(SandboxErrorCode::ProcessNotFound, "process not found");
        let Some(exec) = active.get_mut(&target.target_operation_id) else {
            return Ok(None);
        };
        if !(exec.instance.name() == instance.name()
            && exec.generation == target.generation
            && exec.attempt == target.attempt)
        {
            return Err(not_found());
        }
        let Some(birth) = exec.birth.clone() else {
            return Err(RuntimeError::new(
                SandboxErrorCode::ProcessNotStarted,
                "process has no start identity",
            ));
        };
        if birth.pid != target.pid {
            return Err(not_found());
        }
        if kill {
            exec.cancelled = true;
            if let Some(tx) = exec.stdin.take() {
                let _ = tx.send(StdinMsg::Close);
            }
        } else if exec.cancelled {
            return Err(RuntimeError::new(
                SandboxErrorCode::ProcessCancelPending,
                "process cancellation is pending",
            ));
        }
        Ok(Some((birth, exec.nonce.clone(), exec.guest.clone())))
    }

    #[cfg(test)]
    pub(super) fn test_track_signal(
        &self,
        instance: &BoundInstance,
        request: &RunCommandRequest,
    ) -> crate::SignalTarget {
        let birth = crate::CommandBirth {
            pid: 4242,
            boot_id: "00000000-0000-4000-8000-000000000000".into(),
            start_ticks: 1,
            started_at_ms: 1000,
        };
        self.active.lock().unwrap().insert(
            request.operation_id.clone(),
            ActiveExec {
                host_pid: None,
                generation: request.generation,
                attempt: request.attempt,
                instance: instance.clone(),
                guest_pid: None,
                birth: Some(birth.clone()),
                nonce: "test-wrapper-nonce".into(),
                description: None,
                guest: request.guest.clone(),
                argv: request.argv.clone(),
                cancelled: false,
                stdin: None,
                budget_ms: 0,
                start_uid: None,
            },
        );
        crate::SignalTarget {
            target_operation_id: request.operation_id.clone(),
            generation: request.generation,
            attempt: request.attempt,
            pid: birth.pid,
        }
    }

    #[cfg(test)]
    pub(super) fn test_pending_stdin(
        &self,
        request: &RunCommandRequest,
    ) -> Option<(Vec<u8>, bool)> {
        self.pending_stdin
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&(
                request.operation_id.clone(),
                request.generation,
                request.attempt,
            ))
            .cloned()
    }

    pub fn retain_pending_stdin(&self, keep: impl Fn(&str) -> bool) {
        self.pending_stdin
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .retain(|(operation_id, _, _), _| keep(operation_id));
    }

    pub fn write_stdin(&self, request: &WriteStdinRequest) -> EffectOutcome<()> {
        let active = self.active.lock().unwrap_or_else(|err| err.into_inner());
        let tx = active
            .get(&request.operation_id)
            .filter(|exec| exec.generation == request.generation && exec.attempt == request.attempt)
            .and_then(|exec| exec.stdin.clone());
        if let Some(tx) = tx {
            return send_stdin(&tx, request)
                .map(local_control_completion)
                .map_err(EffectError::from);
        }
        let mut pending = self
            .pending_stdin
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let entry = pending
            .entry((
                request.operation_id.clone(),
                request.generation,
                request.attempt,
            ))
            .or_insert_with(|| (Vec::new(), false));
        entry.0.extend_from_slice(&request.bytes);
        if request.eof {
            entry.1 = true;
        }
        Ok(local_control_completion(()))
    }

    #[allow(clippy::too_many_arguments)]
    fn wait_child(
        &self,
        bound: &BoundInstance,
        request: &RunCommandRequest,
        child: &mut Child,
        started: Instant,
        timeout: Option<Duration>,
        io_failed: &Arc<AtomicBool>,
        cancelled: &AtomicBool,
        pumps: &mut PipePumps,
        pid_nonce: &str,
        observe_unknown: &impl Fn(RunCommandResponse) -> bool,
    ) -> Result<WaitOutcome, Observation> {
        let mut timer = CommandTimer::new(started, timeout);
        let completion_seen = Arc::new(AtomicBool::new(false));
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let out_rx = PipeEvidence::default();
        let err_rx = PipeEvidence::default();
        let (out_tx, err_tx) = (out_rx.sink(), err_rx.sink());
        // Stdin finishes after its sender is dropped; output pumps must complete before success.
        let output_start = pumps.0.len();
        if let Some(stdout) = stdout {
            let failed = io_failed.clone();
            let output = self.output.clone();
            let seen = completion_seen.clone();
            pumps.0.push(thread::spawn(move || {
                pump_pipe(stdout, out_tx, &failed, output, None, &seen)
            }));
        }
        if let Some(stderr) = stderr {
            let failed = io_failed.clone();
            let output = self.output.clone();
            let seen = completion_seen.clone();
            let nonce = pid_nonce.to_string();
            pumps.0.push(thread::spawn(move || {
                pump_pipe(stderr, err_tx, &failed, output, Some(&nonce), &seen)
            }));
        }

        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();
        // An early hint can avoid unnecessary guest signals. Only the complete
        // final stream decides whether cancellation evidence is admissible.
        let mut natural_hint = false;
        let mut pid_head_decided = false;
        let max_head = format!("WSSP_PID {pid_nonce} ").len() + 11;
        let mut start_decided = false;
        let max_start_head = max_head + super::frames::READY_HEAD_MAX + pid_nonce.len();

        loop {
            if self
                .client
                .cancelled
                .as_ref()
                .is_some_and(|permit| permit.is_cancelled())
            {
                // Local cleanup of our own child is allowed after revocation;
                // new guest effects are not. Its outcome remains uncertain.
                self.kill_local_groups_for(Some(&request.operation_id));
                reap_child(child);
                return Err(unknown_wait(
                    request,
                    &out_rx,
                    &err_rx,
                    &mut stdout_buf,
                    &mut stderr_buf,
                    pumps,
                    output_start,
                ));
            }
            drain_pipe(&out_rx, &mut stdout_buf);
            drain_pipe(&err_rx, &mut stderr_buf);
            if !pid_head_decided {
                let head = &stderr_buf[..stderr_buf.len().min(max_head)];
                if let Some(pid) = parse_supervised_frames(&[], head, pid_nonce).pid_frame {
                    self.store_guest_pid(&request.operation_id, pid);
                }
                pid_head_decided = head.contains(&b'\n') || head.len() == max_head;
            }
            let observed_now = self.command_now();
            if !start_decided {
                let head = &stderr_buf[..stderr_buf.len().min(max_start_head)];
                start_decided = self.decide_start_at(
                    &timer,
                    observed_now,
                    request,
                    head,
                    head.len() == max_start_head,
                );
            }
            let natural = parse_supervised_frames(&stdout_buf, &stderr_buf, pid_nonce);
            // Only the nonce-bound PID banner proves the wrapper started.
            // A decided non-banner head is not start evidence. READY may be
            // absent (e.g. /proc unavailable), even for a running command.
            if natural.pid_frame.is_some() {
                timer.started(observed_now);
            }
            natural_hint |= natural.exit.is_some() || natural.setup_failed.is_some();
            if (cancelled.load(Ordering::Acquire) || self.take_cancelled(&request.operation_id))
                && natural.exit.is_none()
                && natural.setup_failed.is_none()
            {
                return self.finish_cancel(
                    Stop::Cancel,
                    bound,
                    request,
                    child,
                    pid_nonce,
                    &out_rx,
                    &err_rx,
                    &mut stdout_buf,
                    &mut stderr_buf,
                    pumps,
                    output_start,
                    io_failed,
                    &mut natural_hint,
                    observe_unknown,
                    &completion_seen,
                );
            }
            if io_failed.load(Ordering::Acquire) {
                self.kill_local_groups_for(Some(&request.operation_id));
                reap_child(child);
                return Err(unknown_wait(
                    request,
                    &out_rx,
                    &err_rx,
                    &mut stdout_buf,
                    &mut stderr_buf,
                    pumps,
                    output_start,
                ));
            }

            match child.try_wait() {
                Ok(Some(_status)) => {
                    if pumps.0[output_start..]
                        .iter()
                        .any(|pump| !pump.is_finished())
                    {
                        // A descendant can retain pipes after the parent exits. Keep polling
                        // authority and the deadline instead of blocking in JoinHandle::join.
                        if !timer.expired(self.command_now()) {
                            thread::sleep(POLL);
                            continue;
                        }
                        self.kill_local_groups_for(Some(&request.operation_id));
                        return Err(unknown_wait(
                            request,
                            &out_rx,
                            &err_rx,
                            &mut stdout_buf,
                            &mut stderr_buf,
                            pumps,
                            output_start,
                        ));
                    }
                    for pump in pumps.0.drain(output_start..) {
                        if pump.join().is_err() {
                            io_failed.store(true, Ordering::Release);
                        }
                    }
                    if io_failed.load(Ordering::Acquire) {
                        return Err(unknown_wait(
                            request,
                            &out_rx,
                            &err_rx,
                            &mut stdout_buf,
                            &mut stderr_buf,
                            pumps,
                            output_start,
                        ));
                    }
                    drain_pipe(&out_rx, &mut stdout_buf);
                    drain_pipe(&err_rx, &mut stderr_buf);
                    if let Some(pid) =
                        parse_supervised_frames(&[], &stderr_buf, pid_nonce).pid_frame
                    {
                        self.store_guest_pid(&request.operation_id, pid);
                    }
                    if !start_decided {
                        // Fast exit: the complete stream decides the fixed head once.
                        self.decide_start(request, &stderr_buf, true);
                    }
                    return Ok(WaitOutcome::Natural(SupervisedOutput {
                        stdout: stdout_buf,
                        stderr: stderr_buf,
                    }));
                }
                Ok(None) => {}
                Err(_err) => {
                    self.kill_local_groups_for(Some(&request.operation_id));
                    reap_child(child);
                    return Err(unknown_wait(
                        request,
                        &out_rx,
                        &err_rx,
                        &mut stdout_buf,
                        &mut stderr_buf,
                        pumps,
                        output_start,
                    ));
                }
            }

            let now = self.command_now();
            if timer.expired(now) {
                // E-19: with the nonce-bound banner the deadline stop runs the
                // same proven termination as a cancel, so a confirmed stop ends
                // as a typed timeout. Without a banner there is no termination
                // authority, and the outcome stays UNKNOWN below.
                // A banner always starts execution above, so setup expiry
                // has no banner and takes the local-only UNKNOWN path.
                if let Some(limit) = timeout
                    && natural.pid_frame.and_then(GuestPid::banner).is_some()
                    && natural.exit.is_none()
                    && natural.setup_failed.is_none()
                {
                    return self.finish_cancel(
                        Stop::Timeout(limit),
                        bound,
                        request,
                        child,
                        pid_nonce,
                        &out_rx,
                        &err_rx,
                        &mut stdout_buf,
                        &mut stderr_buf,
                        pumps,
                        output_start,
                        io_failed,
                        &mut natural_hint,
                        observe_unknown,
                        &completion_seen,
                    );
                }
                // Without the nonce-bound banner there is no termination
                // authority: stop only the locally owned transport (which also
                // releases inherited pipes). No PID file, no blind guest kill;
                // the outcome stays UNKNOWN for lifecycle reconciliation.
                self.kill_local_groups_for(Some(&request.operation_id));
                reap_child(child);
                return Err(unknown_wait(
                    request,
                    &out_rx,
                    &err_rx,
                    &mut stdout_buf,
                    &mut stderr_buf,
                    pumps,
                    output_start,
                ));
            }
            thread::sleep(timer.deadline().map_or(POLL, |deadline| {
                POLL.min(deadline.saturating_duration_since(now))
            }));
        }
    }

    /// Stop a running command (cancel request or `timeoutMs` deadline) and
    /// classify how it ended from final evidence only (`stop_verdict`).
    #[allow(clippy::too_many_arguments)]
    fn finish_cancel(
        &self,
        stop: Stop,
        bound: &BoundInstance,
        request: &RunCommandRequest,
        child: &mut Child,
        nonce: &str,
        out_rx: &PipeEvidence,
        err_rx: &PipeEvidence,
        stdout: &mut Vec<u8>,
        stderr: &mut Vec<u8>,
        pumps: &mut PipePumps,
        output_start: usize,
        io_failed: &AtomicBool,
        natural_hint: &mut bool,
        observe_unknown: &impl Fn(RunCommandResponse) -> bool,
        completion_seen: &AtomicBool,
    ) -> Result<WaitOutcome, Observation> {
        // Only the nonce-bound banner is termination authority; pid files remain advisory.
        let pgid = parse_supervised_frames(stdout, stderr, nonce)
            .pid_frame
            .and_then(GuestPid::banner);
        let mut published_unknown = false;
        // G3R-1: a stop was issued (helper or best-effort SIGKILL) whose effect
        // this owner could not observe. A later signal-death frame may then be
        // that stop's result, so it is neither natural nor attributed.
        let mut unconfirmed_stop = false;
        // G3R-2: helper attempts are bounded so a stop that can never be
        // proven still settles (UNKNOWN) and frees the command worker.
        let mut attempts = 0u32;
        loop {
            drain_pipe(out_rx, stdout);
            drain_pipe(err_rx, stderr);
            observe_natural_hint(natural_hint, stdout, stderr, nonce);
            *natural_hint |= completion_seen.load(Ordering::Acquire);
            let guest = pgid.filter(|_| !*natural_hint).and_then(|pgid| {
                attempts += 1;
                // The transport child may exit during guest TERM/grace. Keep
                // reaping/draining concurrently with verification (also prevents
                // dead pipe buffers from stalling the guest helper).
                let client = self.client.clone();
                let instance = bound.clone();
                let command_nonce = nonce.to_string();
                let (tx, rx) = mpsc::channel();
                thread::spawn(move || {
                    let _ = tx.send(client.terminate_guest_group(&instance, pgid, &command_nonce));
                });
                let record = loop {
                    let _ = child.try_wait();
                    drain_pipe(out_rx, stdout);
                    drain_pipe(err_rx, stderr);
                    observe_natural_hint(natural_hint, stdout, stderr, nonce);
                    *natural_hint |= completion_seen.load(Ordering::Acquire);
                    match rx.recv_timeout(POLL) {
                        Ok(result) => break result.ok(),
                        Err(mpsc::RecvTimeoutError::Disconnected) => break None,
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                    }
                };
                // Issued, but no parsed record: it may still have signalled.
                unconfirmed_stop |= record.is_none();
                record
            });
            // Completion may arrive with the helper's last message, or during
            // the final pipe drain. Natural framing takes precedence at every
            // continuation, including an earlier failed helper/UNKNOWN receipt.
            drain_pipe(out_rx, stdout);
            drain_pipe(err_rx, stderr);
            observe_natural_hint(natural_hint, stdout, stderr, nonce);
            *natural_hint |= completion_seen.load(Ordering::Acquire);
            if guest.is_some() || *natural_hint {
                self.kill_local_groups_for(Some(&request.operation_id));
                let local = drain_after_cancel(
                    child,
                    out_rx,
                    err_rx,
                    stdout,
                    stderr,
                    pumps,
                    output_start,
                    io_failed,
                );
                if let Some(local) = local {
                    // The buffers are final only after reap + clean pump joins
                    // + last channel drain. An unsampled frame followed by a
                    // tail must bar a stop verdict just like a sampled one does.
                    let framed = completion_seen.load(Ordering::Acquire)
                        || has_completion_frame(stderr, nonce);
                    let exit = parse_supervised_frames(stdout, stderr, nonce).exit;
                    let terminated =
                        guest.and_then(super::effect_completion::GroupGone::terminated);
                    match (
                        stop_verdict(framed, exit, terminated.is_some(), unconfirmed_stop),
                        terminated,
                    ) {
                        (StopVerdict::Stopped, Some(terminated)) => {
                            let mut response =
                                command_observation(request, stdout.clone(), stderr.clone());
                            response.command.guest_pid = pgid;
                            response.command.birth = self.birth_of(&request.operation_id);
                            return Ok(stop.proven(response, terminated, local));
                        }
                        (StopVerdict::Natural, _) => {
                            return Ok(WaitOutcome::Natural(SupervisedOutput {
                                stdout: std::mem::take(stdout),
                                stderr: std::mem::take(stderr),
                            }));
                        }
                        _ => {}
                    }
                }
                // Guest termination does not excuse a missing pipe/reap proof.
                return Err(EffectError::unknown_command(command_observation(
                    request,
                    stdout.clone(),
                    stderr.clone(),
                ))
                .into());
            }
            let response = command_observation(request, stdout.clone(), stderr.clone());
            let keep_owner = published_unknown || observe_unknown(response.clone());
            published_unknown = true;
            if !keep_owner
                || pgid.is_none()
                || attempts >= STOP_HELPER_ATTEMPTS
                || self
                    .client
                    .cancelled
                    .as_ref()
                    .is_some_and(|p| p.is_cancelled())
            {
                // Exhausted/unprovable stop (G3R-2/G3R-4, P2-3): stop only the
                // local transport. There is no blind numeric guest SIGKILL and
                // no PID-file adoption; guest work may remain alive and the
                // outcome is the command's own non-signal result or UNKNOWN.
                // Recovery is sandbox stop/kill (lease expiry is the backstop).
                self.kill_local_groups_for(Some(&request.operation_id));
                if !*natural_hint {
                    // Local transport death can itself end the guest work, so
                    // a later signal-death frame is never attributed.
                    unconfirmed_stop = true;
                }
                let local = drain_after_cancel(
                    child,
                    out_rx,
                    err_rx,
                    stdout,
                    stderr,
                    pumps,
                    output_start,
                    io_failed,
                );
                let framed =
                    completion_seen.load(Ordering::Acquire) || has_completion_frame(stderr, nonce);
                let exit = parse_supervised_frames(stdout, stderr, nonce).exit;
                if local.is_some()
                    && stop_verdict(framed, exit, false, unconfirmed_stop) == StopVerdict::Natural
                {
                    return Ok(WaitOutcome::Natural(SupervisedOutput {
                        stdout: std::mem::take(stdout),
                        stderr: std::mem::take(stderr),
                    }));
                }
                return Err(EffectError::unknown_command(command_observation(
                    request,
                    stdout.clone(),
                    stderr.clone(),
                ))
                .into());
            }
            // A failed guest helper keeps child/pipes with this owner for at
            // most STOP_HELPER_ATTEMPTS attempts, or until guest termination or
            // lifecycle/shutdown revocation.
            thread::sleep(POLL);
        }
    }

    /// [`Self::decide_start`] only while `timer` admits a start at `now`; a
    /// late head is decided unbound (the setup expiry then ends the wait).
    fn decide_start_at(
        &self,
        timer: &CommandTimer,
        now: Instant,
        request: &RunCommandRequest,
        head: &[u8],
        end: bool,
    ) -> bool {
        if !timer.admits_start(now) {
            return true;
        }
        self.decide_start(request, head, end)
    }

    /// Decide the fixed-position start record once. Returns whether the head
    /// is decided. Host clock only; the first valid record binds and nothing
    /// later in the stream can rebind (later bytes are user output).
    fn decide_start(&self, request: &RunCommandRequest, head: &[u8], end: bool) -> bool {
        let (nonce, budget_ms, start_uid) = {
            let active = self.active.lock().unwrap_or_else(|err| err.into_inner());
            match active.get(&request.operation_id) {
                Some(exec) => (exec.nonce.clone(), exec.budget_ms, exec.start_uid),
                None => return true,
            }
        };
        let Some(decision) = super::frames::decide_head(head, &nonce, end) else {
            return false;
        };
        if let Some(ready) = decision {
            let birth = crate::CommandBirth {
                pid: ready.pid,
                boot_id: ready.boot_id,
                start_ticks: ready.start_ticks,
                started_at_ms: host_now_ms(),
            };
            let bound = {
                let mut active = self.active.lock().unwrap_or_else(|err| err.into_inner());
                match active.get_mut(&request.operation_id) {
                    Some(exec) if exec.birth.is_none() => {
                        exec.birth = Some(birth.clone());
                        true
                    }
                    _ => false,
                }
            };
            if bound
                && let Some(output) = &self.output
                && output.bind_start(&birth) == crate::StartBinding::Bound
                && let Some(uid) = start_uid
            {
                // Decision 2: the journaled start (outside the active lock)
                // names the uid and budget the retire helper needs.
                output.record_start(&crate::CommandStart {
                    birth,
                    uid,
                    budget_ms,
                    // R11: read only after the birth bound, so a QEMU
                    // restart before this read can never look like one
                    // after it.
                    qemu: self.client.qemu_identity(&request.instance_name),
                });
            }
        }
        true
    }

    fn birth_of(&self, operation_id: &str) -> Option<crate::CommandBirth> {
        self.active
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .get(operation_id)
            .and_then(|exec| exec.birth.clone())
    }

    fn store_guest_pid(&self, operation_id: &str, pid: GuestPid) {
        let mut active = self.active.lock().unwrap_or_else(|err| err.into_inner());
        if let Some(exec) = active.get_mut(operation_id) {
            exec.guest_pid = Some(pid);
        }
    }

    fn take_cancelled(&self, operation_id: &str) -> bool {
        self.active
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .get(operation_id)
            .is_some_and(|exec| exec.cancelled)
    }

    fn forget(&self, operation_id: &str) {
        // Retain the group handle until all normal/error cleanup has signalled it,
        // including descendants that closed output but still retain an input pipe.
        self.kill_local_groups_for(Some(operation_id));
        self.active
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .remove(operation_id);
        self.pending_stdin
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .retain(|(id, _, _), _| id != operation_id);
    }
}

/// Host wall clock for start observations; guest timestamps are never used.
pub(crate) fn host_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// The guest's group-signal support (TERM/INT/HUP need Linux >= 6.9),
/// observed with the signal helper's own zero-signal probe as the guest user
/// `client` carries. Read-only and display-only: any failure is `None`.
pub(super) fn probe_group_signals(client: &IncusClient, instance: &BoundInstance) -> Option<bool> {
    let nonce = random_nonce().ok()?;
    let out = client
        .exec_argv_effect_bounded(
            instance,
            &[
                "/bin/sh".to_string(),
                "-c".to_string(),
                SIGNAL_HELPER_LAUNCH.to_string(),
                "wssp-signal".to_string(),
                SIGNAL_HELPER.to_string(),
                "wssp-signal-probe".to_string(),
                nonce.clone(),
            ],
            SIGNAL_HELPER_DEADLINE,
        )
        .ok()?;
    super::effect_completion::group_signal_probe_outcome(&nonce, &out)
}

pub fn validate_operation_id(id: &str) -> Result<(), RuntimeError> {
    let valid = (1..=128).contains(&id.len())
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !valid {
        return Err(RuntimeError::new(
            SandboxErrorCode::ProtocolError,
            format!("invalid operation id `{id}`"),
        ));
    }
    Ok(())
}

fn guest_ops_dir(guest: &crate::GuestIdentity) -> String {
    if let Some(dir) = test_guest_ops_dir() {
        return dir;
    }
    format!("{}/.wssp/ops", guest.guest_home)
}

#[cfg(test)]
pub(crate) mod test_guest_ops {
    use std::path::PathBuf;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    fn slot() -> &'static Mutex<Option<String>> {
        static DIR: OnceLock<Mutex<Option<String>>> = OnceLock::new();
        DIR.get_or_init(|| Mutex::new(None))
    }

    pub(super) fn get() -> Option<String> {
        slot().lock().unwrap_or_else(|err| err.into_inner()).clone()
    }

    /// The override is process-wide and read from worker threads, so a test
    /// that depends on it (set or unset) holds this guard for its whole body;
    /// concurrent tests otherwise overwrite or clear each other's directory.
    #[must_use]
    pub(crate) struct Override {
        _held: MutexGuard<'static, ()>,
    }

    impl Override {
        pub(crate) fn set(&self, dir: Option<PathBuf>) {
            *slot().lock().unwrap_or_else(|err| err.into_inner()) =
                dir.map(|path| path.to_string_lossy().into_owned());
        }
    }

    impl Drop for Override {
        fn drop(&mut self) {
            self.set(None);
        }
    }

    pub(crate) fn hold(dir: Option<PathBuf>) -> Override {
        static HELD: Mutex<()> = Mutex::new(());
        let guard = Override {
            _held: HELD.lock().unwrap_or_else(|err| err.into_inner()),
        };
        guard.set(dir);
        guard
    }
}

#[cfg(test)]
fn test_guest_ops_dir() -> Option<String> {
    test_guest_ops::get()
}

#[cfg(not(test))]
fn test_guest_ops_dir() -> Option<String> {
    None
}

#[cfg(test)]
pub(crate) fn set_test_guest_ops_dir(dir: Option<std::path::PathBuf>) -> test_guest_ops::Override {
    test_guest_ops::hold(dir)
}

/// Build-root commands (D1) keep their pid files on the guest's tmpfs, so a
/// root-owned directory never lands in the guest user's HOME or in a
/// captured image.
pub const ROOT_GUEST_OPS_DIR: &str = "/run/wssp/ops";

fn root_ops_dir() -> String {
    test_guest_ops_dir().unwrap_or_else(|| ROOT_GUEST_OPS_DIR.to_string())
}

fn pid_path_in(operation_id: &str, ops_dir: &str) -> Result<String, RuntimeError> {
    validate_operation_id(operation_id)?;
    Ok(format!("{ops_dir}/{operation_id}.pid"))
}

/// Post-setup, pre-exec start record (4a). The function has its own positional
/// parameters, so `set --` never touches the user's argv. Boot UUID and the
/// leader's start ticks (field 22 of `/proc/$$/stat`, the 20th field after
/// the `comm` terminator) distinguish reboot and PID reuse. The record is
/// mandatory: without it the wrapper never runs argv and reports a setup
/// failure (pre-effect `host_effect_not_issued`), so a command that ran always
/// has the identity its versioned result needs.
const READY_FN: &str = "wssp_ready() { n=$1; { IFS= read -r b < /proc/sys/kernel/random/boot_id && IFS= read -r s < /proc/$$/stat; } 2>/dev/null || return 1; s=${s##*\\) }; set -- $s; [ -n \"${20:-}\" ] || return 1; printf 'WSSP_READY %s %s %s %s\\n' \"$n\" \"$$\" \"$b\" \"${20}\" >&2; }";

/// `setsid` wrapper: reported PID is the session/process-group leader id.
pub fn wrap_user_command(
    operation_id: &str,
    argv: &[String],
    guest: &crate::GuestIdentity,
) -> Result<(Vec<String>, String), RuntimeError> {
    wrap_command_in(operation_id, argv, &guest_ops_dir(guest))
}

/// [`wrap_user_command`] for a build-root command (D1): pid files go to
/// [`ROOT_GUEST_OPS_DIR`].
pub fn wrap_build_root_command(
    operation_id: &str,
    argv: &[String],
) -> Result<(Vec<String>, String), RuntimeError> {
    wrap_command_in(operation_id, argv, &root_ops_dir())
}

fn wrap_command_in(
    operation_id: &str,
    argv: &[String],
    ops_dir: &str,
) -> Result<(Vec<String>, String), RuntimeError> {
    if argv.is_empty() {
        return Err(RuntimeError::new(
            SandboxErrorCode::ProtocolError,
            "exec requires at least one argv entry",
        ));
    }
    let path = pid_path_in(operation_id, ops_dir)?;
    let quote = |v: &str| format!("'{}'", v.replace('\'', "'\"'\"'"));
    let path = quote(&path);
    let ops_dir = quote(ops_dir);
    let exit_nonce = random_nonce()?;
    let script = format!(
        "trap ':' TERM INT HUP QUIT USR1 USR2; printf 'WSSP_PID {exit_nonce} %s\\n' \"$$\" >&2; {READY_FN}; if mkdir -p {ops_dir} && printf '%s\\n' \"$$\" > {path} && wssp_ready {exit_nonce}; then \"$@\"; code=$?; printf '\\nWSSP_EXIT {exit_nonce} %s\\n' \"$code\" >&2; exit $code; else code=$?; printf '\\nWSSP_SETUP_FAILED {exit_nonce} %s\\n' \"$code\" >&2; exit $code; fi"
    );
    // The Incus guest agent execs the command as a session leader, so plain
    // `setsid` forks and its parent exits at once. The agent stops relaying
    // stdin when that direct child exits; `-w` keeps it alive until the
    // wrapper finishes so streamed and queued stdin still reach the command.
    let mut wrapped = vec![
        "setsid".to_string(),
        "-w".to_string(),
        "/bin/sh".to_string(),
        "-c".to_string(),
        script,
        "wssp-run".to_string(),
    ];
    wrapped.extend(argv.iter().cloned());
    Ok((wrapped, exit_nonce))
}

fn script_argv(script: &str) -> [String; 3] {
    [
        "/bin/bash".to_string(),
        "-lc".to_string(),
        script.to_string(),
    ]
}

/// Supervised `setsid` wrapper for a `/bin/bash -lc` script body (one guest argument).
pub fn wrap_user_script(
    operation_id: &str,
    script: &str,
    guest: &crate::GuestIdentity,
) -> Result<(Vec<String>, String), RuntimeError> {
    wrap_user_command(operation_id, &script_argv(script), guest)
}

/// [`wrap_user_script`] for a build-root step (D1).
pub fn wrap_build_root_script(
    operation_id: &str,
    script: &str,
) -> Result<(Vec<String>, String), RuntimeError> {
    wrap_build_root_command(operation_id, &script_argv(script))
}

// Early hint only: suppress unnecessary guest helpers after a sampled suffix.
// Absence in snapshots is never proof of absence in the complete final stream.
fn observe_natural_hint(natural_hint: &mut bool, stdout: &[u8], stderr: &[u8], nonce: &str) {
    let frames = parse_supervised_frames(stdout, stderr, nonce);
    if frames.exit.is_some() || frames.setup_failed.is_some() {
        *natural_hint = true;
    }
}

#[allow(clippy::too_many_arguments)]
fn drain_after_cancel(
    child: &mut Child,
    out_rx: &PipeEvidence,
    err_rx: &PipeEvidence,
    stdout: &mut Vec<u8>,
    stderr: &mut Vec<u8>,
    pumps: &mut PipePumps,
    _output_start: usize,
    io_failed: &AtomicBool,
) -> Option<LocalDrained> {
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut reaped = false;
    let mut clean = true;
    loop {
        reaped |= child.try_wait().is_ok_and(|status| status.is_some());
        drain_pipe(out_rx, stdout);
        drain_pipe(err_rx, stderr);
        let mut i = 0;
        while i < pumps.0.len() {
            if pumps.0[i].is_finished() {
                clean &= pumps.0.swap_remove(i).join().is_ok();
            } else {
                i += 1;
            }
        }
        if reaped && pumps.0.is_empty() {
            drain_pipe(out_rx, stdout);
            drain_pipe(err_rx, stderr);
            return (clean && !io_failed.load(Ordering::Acquire)).then_some(LocalDrained(()));
        }
        if Instant::now() >= deadline {
            // Drop handles, never join unfinished pumps. Drop has no second deadline.
            pumps.0.clear();
            return None;
        }
        thread::sleep(POLL);
    }
}

struct LocalDrained(());
pub(crate) struct CancelledCompletion {
    response: RunCommandResponse,
    _guest: super::effect_completion::GroupTerminated,
    _local: LocalDrained,
}
impl PositiveEvidence for CancelledCompletion {
    type Value = RunCommandResponse;
    fn value(self) -> Self::Value {
        self.response
    }
}
fn command_observation(
    request: &RunCommandRequest,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
) -> RunCommandResponse {
    RunCommandResponse {
        command: CommandRecord {
            operation_id: request.operation_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            state: OperationState::UnknownOutcome,
            exit_code: None,
            guest_pid: None,
            birth: None,
            chunks: vec![
                CommandStreamChunk {
                    stream: CommandStream::Stdout,
                    sequence: 0,
                    bytes: stdout,
                    final_chunk: true,
                },
                CommandStreamChunk {
                    stream: CommandStream::Stderr,
                    sequence: 0,
                    bytes: stderr,
                    final_chunk: true,
                },
            ],
        },
    }
}

fn unknown_wait(
    request: &RunCommandRequest,
    out_rx: &PipeEvidence,
    err_rx: &PipeEvidence,
    stdout: &mut Vec<u8>,
    stderr: &mut Vec<u8>,
    pumps: &mut PipePumps,
    output_start: usize,
) -> Observation {
    let deadline = Instant::now() + Duration::from_secs(1);
    while pumps.0[output_start..]
        .iter()
        .any(|pump| !pump.is_finished())
        && Instant::now() < deadline
    {
        drain_pipe(out_rx, stdout);
        drain_pipe(err_rx, stderr);
        thread::sleep(POLL);
    }
    drain_pipe(out_rx, stdout);
    drain_pipe(err_rx, stderr);
    EffectError::unknown_command(RunCommandResponse {
        command: CommandRecord {
            operation_id: request.operation_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            state: OperationState::UnknownOutcome,
            exit_code: None,
            guest_pid: None,
            birth: None,
            chunks: vec![
                CommandStreamChunk {
                    stream: CommandStream::Stdout,
                    sequence: 0,
                    bytes: std::mem::take(stdout),
                    final_chunk: true,
                },
                CommandStreamChunk {
                    stream: CommandStream::Stderr,
                    sequence: 0,
                    bytes: std::mem::take(stderr),
                    final_chunk: true,
                },
            ],
        },
    })
    .into()
}

pub(crate) struct LocalControlCompletion(());
impl PositiveEvidence for LocalControlCompletion {
    type Value = ();
    fn value(self) {}
}
fn local_control_completion(value: ()) -> crate::Completed<()> {
    LocalControlCompletion(value).complete()
}

enum WaitOutcome {
    Natural(SupervisedOutput),
    Cancelled(crate::Completed<RunCommandResponse>),
    TimedOut(CommandTimedOut),
}

/// Why the supervisor stopped a running command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    Cancel,
    Timeout(Duration),
}

impl Stop {
    /// The typed outcome of a stop proven by `stop_verdict`: the helper
    /// signalled the running command and saw its group gone, and the local
    /// transport was reaped and drained cleanly. Cancel ⇒ CANCELLED; the
    /// command deadline ⇒ FAILED with the stable `timeout` code.
    fn proven(
        self,
        mut response: RunCommandResponse,
        guest: super::effect_completion::GroupTerminated,
        local: LocalDrained,
    ) -> WaitOutcome {
        match self {
            Self::Cancel => {
                response.command.state = OperationState::Cancelled;
                WaitOutcome::Cancelled(
                    CancelledCompletion {
                        response,
                        _guest: guest,
                        _local: local,
                    }
                    .complete(),
                )
            }
            Self::Timeout(limit) => {
                response.command.state = OperationState::Failed;
                WaitOutcome::TimedOut(CommandTimedOut {
                    error: RuntimeError::new(
                        SandboxErrorCode::Timeout,
                        format!("command exceeded its {} ms timeout", limit.as_millis()),
                    ),
                    response: Box::new(response),
                })
            }
        }
    }
}

/// The verdict after a supervisor stop, from the FINAL streams only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StopVerdict {
    /// The stop ended the command: report CANCELLED or `timeout`.
    Stopped,
    /// The wrapper reported its own result; it stands as the natural outcome.
    Natural,
    /// No proof either way: UNKNOWN_OUTCOME.
    Unknown,
}

/// The wrapper reports a command ended by the helper's TERM or KILL as the
/// shell status 128 + signal.
fn stop_signal_exit(code: i32) -> bool {
    code == 128 + 15 || code == 128 + 9
}

/// Helper attempts per stop (cancel or deadline) before the owner falls back
/// to the unproven local kill + best-effort guest SIGKILL and settles. Each
/// attempt is itself bounded by the helper's 2 s exec timeout.
const STOP_HELPER_ATTEMPTS: u32 = 3;

/// `framed`: the complete final stderr holds a nonce-bound completion frame.
/// `exit`: that frame's accepted exit code, when it is the final suffix.
/// `attributed`: the helper signalled the still-running command and then saw
/// its group gone (`group_terminated`).
/// `unconfirmed_stop`: a stop was issued for this command whose effect was not
/// observed (a helper with no parsed record, or the best-effort SIGKILL).
///
/// - Attributed, no frame: the wrapper died to the escalated KILL ⇒ Stopped.
/// - Attributed, frame with 143/137: the command died to the stop ⇒ Stopped.
/// - Unattributed 143/137 after an unconfirmed stop: it may be that stop's
///   result or the command's own exit ⇒ Unknown (G3R-1).
/// - Any other frame (a different code, or no attribution because the command
///   had already ended) is the command's own result ⇒ Natural, so an exit 143
///   the command produced itself, or a stop that raced a natural exit, never
///   becomes CANCELLED/timeout.
/// - No frame and no attribution ⇒ Unknown.
fn stop_verdict(
    framed: bool,
    exit: Option<i32>,
    attributed: bool,
    unconfirmed_stop: bool,
) -> StopVerdict {
    let signal_death = exit.is_some_and(stop_signal_exit);
    match (framed, attributed) {
        (false, true) => StopVerdict::Stopped,
        (true, true) if signal_death => StopVerdict::Stopped,
        (true, false) if signal_death && unconfirmed_stop => StopVerdict::Unknown,
        (true, _) => StopVerdict::Natural,
        (false, false) => StopVerdict::Unknown,
    }
}

/// E-19 completed failure: the command outlived `timeoutMs` and the deadline
/// stop is proven by `Stop::proven`. Only that constructor builds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandTimedOut {
    error: RuntimeError,
    response: Box<RunCommandResponse>,
}
impl CommandTimedOut {
    pub(crate) fn error(&self) -> &RuntimeError {
        &self.error
    }
    pub(crate) fn response(&self) -> &RunCommandResponse {
        &self.response
    }
    pub(crate) fn set_birth(&mut self, birth: Option<crate::CommandBirth>) {
        self.response.command.birth = birth;
    }
}
struct SupervisedOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Bounded frame evidence for one pipe, kept by its pump: the first 8 KiB and
/// a rolling ~8 KiB tail (a zero byte marks the join, so a gap cannot
/// manufacture a nonce frame). The pump records every chunk without ever
/// waiting for the supervisor, so frame evidence never throttles guest output
/// (user bytes go to `CommandOutput`). The supervisor samples it each pass.
#[derive(Default)]
struct PipeEvidence(Arc<Mutex<Evidence>>);
#[derive(Default)]
struct Evidence {
    bytes: Vec<u8>,
    #[cfg(test)]
    samples: std::sync::atomic::AtomicU64,
}
/// The pump's handle. Like a dropped channel receiver, a dropped
/// [`PipeEvidence`] (the supervisor gave up on this child) stops the pump.
struct EvidenceSink(std::sync::Weak<Mutex<Evidence>>);
impl PipeEvidence {
    fn sink(&self) -> EvidenceSink {
        EvidenceSink(Arc::downgrade(&self.0))
    }
    /// Supervisor samples so far; read under the lock that orders them
    /// against [`EvidenceSink::record`].
    #[cfg(test)]
    fn samples(&self) -> u64 {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .samples
            .load(Ordering::Relaxed)
    }
    #[cfg(test)]
    fn share(&self) -> Self {
        Self(self.0.clone())
    }
}
impl EvidenceSink {
    /// False once the supervisor dropped the evidence.
    fn record(&self, chunk: &[u8]) -> bool {
        let Some(evidence) = self.0.upgrade() else {
            return false;
        };
        let mut evidence = evidence.lock().unwrap_or_else(|e| e.into_inner());
        let dest = &mut evidence.bytes;
        dest.extend_from_slice(chunk);
        if dest.len() > 16384 {
            let tail = dest.len() - 8191;
            dest.drain(8192..tail);
            dest[8192] = 0; // A gap cannot manufacture a nonce frame across the join.
        }
        true
    }
}

fn pump_pipe(
    mut reader: impl Read,
    tx: EvidenceSink,
    failed: &AtomicBool,
    output: Option<crate::CommandOutput>,
    nonce: Option<&str>,
    seen: &AtomicBool,
) {
    let mut filter = nonce.map(super::frames::LiveStderr::new);
    let stream = if nonce.is_some() {
        CommandStream::Stderr
    } else {
        CommandStream::Stdout
    };
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf) {
            Ok(n) => {
                let ready = filter.as_mut().map(|f| f.feed(&buf[..n], n == 0, seen));
                if let Some(output) = &output {
                    output.push(stream, ready.as_deref().unwrap_or(&buf[..n]));
                }
                if n == 0 || !tx.record(&buf[..n]) {
                    break;
                }
            }
            Err(_) => {
                failed.store(true, Ordering::Release);
                break;
            }
        }
    }
}

/// Copy the pipe's current frame evidence (at most ~16 KiB) into `dest`.
fn drain_pipe(rx: &PipeEvidence, dest: &mut Vec<u8>) {
    let evidence = rx.0.lock().unwrap_or_else(|e| e.into_inner());
    #[cfg(test)]
    evidence.samples.fetch_add(1, Ordering::Relaxed);
    dest.clear();
    dest.extend_from_slice(&evidence.bytes);
}

/// Exec deadline of one guest terminate helper run (TERM, grace, KILL and
/// the group-gone proof inside a VM). Debug builds may only widen it
/// (`IncusKvmRuntime::set_guest_terminate_timeout`).
pub const GUEST_TERMINATE_TIMEOUT: Duration = Duration::from_secs(2);

impl IncusClient {
    /// Spawn a supervised `incus exec`. The supervisor starts the command
    /// deadline before this spawn so a blocked pre-start (no guest banner)
    /// still expires; without a banner it has no termination authority, so
    /// that expiry is UNKNOWN_OUTCOME, never a typed timeout.
    pub(super) fn spawn_exec(
        &self,
        name: &BoundInstance,
        unit: &str,
        argv: &[String],
        cwd: Option<&str>,
        pipe_stdin: bool,
    ) -> EffectResult<Child> {
        pre::phase(
            |before| {
                crate::validate_managed_instance_name(name.name())?;
                pre::guest(&before, &self.guest)?;
                if argv.is_empty() {
                    return Err(RuntimeError::new(
                        SandboxErrorCode::ProtocolError,
                        "exec requires at least one argv entry",
                    )
                    .into());
                }
                if let Some(cwd) = cwd {
                    super::client::validate_guest_path(cwd)?;
                }
                super::client::validate_incus_identifier(&self.project, "project")?;
                let mut command =
                    crate::host_child::command(&self.binary, crate::host_child::Environment::Incus);
                command.arg("--project").arg(&self.project);
                command.arg("exec").arg(name.name()).arg("-T");
                command.args(self.exec_spawn_args(cwd, unit, argv)?);
                command.stdout(Stdio::piped());
                command.stderr(Stdio::piped());
                command.stdin(if pipe_stdin {
                    Stdio::piped()
                } else {
                    Stdio::null()
                });
                before.issue(|| self.spawn_guest(name, &mut command))
            },
            Ok,
        )
    }

    /// `incus exec` arguments after `-T`: identity, `--`, the fixed identity
    /// launcher and `unit uid gid argv...`. A guest-user exec drops to the
    /// declared identity; a build-root exec (`exec_as_root`, D1) runs the root
    /// body with the root identity, cwd `/root` and `HOME=/root` by default.
    /// `unit` is the attempt's [`command_scope_unit`]; the launcher forwards
    /// it and the identity body pops it before reading `uid gid argv...`.
    pub(super) fn exec_spawn_args(
        &self,
        cwd: Option<&str>,
        unit: &str,
        argv: &[String],
    ) -> Result<Vec<String>, RuntimeError> {
        validate_command_scope_unit(unit)?;
        let mut args = self.guest_exec_args(cwd)?;
        let (helper, uid, gid) = if self.exec_as_root {
            (ROOT_IDENTITY_HELPER, 0, 0)
        } else {
            // Only this fixed helper runs as guest root. It drops identity
            // before processing the workload's environment, stdin or argv.
            args[1] = "0".into();
            args[3] = "0".into();
            (IDENTITY_HELPER, self.guest.guest_uid, self.guest.guest_gid)
        };
        args.push("--".into());
        args.extend(["python3", "-I", "-S", "-c", helper].map(String::from));
        args.push(unit.to_string());
        args.push(uid.to_string());
        args.push(gid.to_string());
        args.extend(argv.iter().cloned());
        Ok(args)
    }

    pub(super) fn guest_terminate_timeout(&self) -> Duration {
        #[cfg(any(test, debug_assertions))]
        if let Some(timeout) = self.guest_terminate_timeout_override {
            return timeout;
        }
        GUEST_TERMINATE_TIMEOUT
    }

    fn terminate_guest_group(
        &self,
        name: &BoundInstance,
        pgid: u32,
        command_nonce: &str,
    ) -> Result<super::effect_completion::GroupGone, RuntimeError> {
        let nonce = random_nonce()?;
        let out = self
            .exec_argv_effect(
                name,
                &[
                    "/bin/sh".into(),
                    "-c".into(),
                    client::GUEST_TERMINATE_SCRIPT.into(),
                    "wssp-terminate".into(),
                    nonce.clone(),
                    pgid.to_string(),
                    command_nonce.into(),
                ],
                None,
                Some(self.guest_terminate_timeout()),
            )
            .map_err(EffectError::into_error)?;
        super::effect_completion::group_gone(&nonce, &out)
    }
}

// No join waits forever, including IO-error, timeout and cancellation exits.
struct PipePumps(Vec<thread::JoinHandle<()>>);
impl Drop for PipePumps {
    fn drop(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !self.0.is_empty() && Instant::now() < deadline {
            let mut index = 0;
            while index < self.0.len() {
                if self.0[index].is_finished() {
                    let _ = self.0.swap_remove(index).join();
                } else {
                    index += 1;
                }
            }
            if !self.0.is_empty() {
                thread::sleep(POLL);
            }
        }
        // Any remaining pump detaches; caller already killed the process group.
    }
}
fn reap_child(child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(1);
    while matches!(child.try_wait(), Ok(None)) && Instant::now() < deadline {
        thread::sleep(POLL);
    }
}

fn attach_stdin(
    child: &mut Child,
    frame: Option<Vec<u8>>,
    initial: Option<&[u8]>,
    user_pipe: bool,
    failed: Arc<AtomicBool>,
    #[cfg(test)] error_barrier: Option<Arc<std::sync::Barrier>>,
) -> (
    Option<mpsc::Sender<StdinMsg>>,
    Option<thread::JoinHandle<()>>,
) {
    let Some(mut stdin) = child.stdin.take() else {
        return (None, None);
    };
    let (tx, rx) = mpsc::channel();
    let pump = thread::spawn(move || {
        while let Ok(msg) = rx.recv() {
            match msg {
                StdinMsg::Data(bytes) => {
                    if stdin
                        .write_all(&bytes)
                        .and_then(|()| stdin.flush())
                        .is_err()
                    {
                        failed.store(true, Ordering::Release);
                        #[cfg(test)]
                        if let Some(barrier) = &error_barrier {
                            barrier.wait();
                        }
                        break;
                    }
                }
                StdinMsg::Close => break,
            }
        }
        drop(stdin);
    });
    if let Some(frame) = frame {
        let _ = tx.send(StdinMsg::Data(frame));
        if !user_pipe {
            let _ = tx.send(StdinMsg::Close);
            return (None, Some(pump));
        }
    }
    if let Some(bytes) = initial {
        if !bytes.is_empty() {
            let _ = tx.send(StdinMsg::Data(bytes.to_vec()));
        }
        let _ = tx.send(StdinMsg::Close);
    }
    (Some(tx), Some(pump))
}

fn send_stdin(
    tx: &mpsc::Sender<StdinMsg>,
    request: &WriteStdinRequest,
) -> Result<(), RuntimeError> {
    if !request.bytes.is_empty() && tx.send(StdinMsg::Data(request.bytes.clone())).is_err() {
        return Err(RuntimeError::new(
            SandboxErrorCode::NotFound,
            "command stdin is no longer open",
        ));
    }
    if request.eof {
        let _ = tx.send(StdinMsg::Close);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::incus::effect_completion;
    use crate::r#trait::GuestIdentity;

    const TEST_UNIT: &str = "wssp-cmd-op-1-2-3.scope";

    /// Python that makes `/proc/self/cgroup` report the attempt's own scope,
    /// so the gate writes no marker (every other `open` is untouched).
    const IN_SCOPE: &str = r#"
import builtins, io
_real_open = builtins.open
def _in_scope_open(path, *args, **kwargs):
    if path == '/proc/self/cgroup':
        return io.BytesIO(b'0::/wssp.slice/wssp-cmd-op-1-2-3.scope\n')
    return _real_open(path, *args, **kwargs)
builtins.open = _in_scope_open
"#;

    /// The debug test daemon's widen-only terminate deadline reaches every
    /// client copy the terminate helper can run through: the runtime's, the
    /// supervisor the daemon takes from `exec_supervisor`, and its
    /// cancellation scopes. A shorter value never lowers the 2 s floor.
    #[test]
    fn widened_guest_terminate_timeout_reaches_every_client_copy() {
        let client = IncusClient::new("/no-such-incus", "default");
        assert_eq!(client.guest_terminate_timeout(), GUEST_TERMINATE_TIMEOUT);
        let mut runtime = super::super::IncusKvmRuntime::from_test_client(client);
        runtime.set_guest_terminate_timeout(Duration::from_secs(30));
        let supervisor = runtime.exec_supervisor();
        let scoped = supervisor.with_cancellation(Arc::new(crate::RuntimePermit::with_timeout(
            Duration::from_secs(4),
        )));
        for timeout in [
            runtime.client().guest_terminate_timeout(),
            supervisor.client.guest_terminate_timeout(),
            scoped.client.guest_terminate_timeout(),
        ] {
            assert_eq!(timeout, Duration::from_secs(30));
        }
        runtime.set_guest_terminate_timeout(Duration::from_millis(100));
        assert_eq!(
            runtime.exec_supervisor().client.guest_terminate_timeout(),
            GUEST_TERMINATE_TIMEOUT
        );
    }

    #[test]
    fn command_scope_units_are_exact_and_validated() {
        assert_eq!(
            command_scope_unit("op-1", 2, 3).unwrap(),
            "wssp-cmd-op-1-2-3.scope"
        );
        let longest = command_scope_unit(&"a".repeat(128), u64::MAX, u64::MAX).unwrap();
        assert_eq!(longest.len(), 185);
        assert!(validate_command_scope_unit(&longest).is_ok());
        assert!(command_scope_unit("bad/op", 1, 1).is_err());
        for bad in [
            "wssp-cmd-op-1.scope",
            "wssp-cmd--1-1.scope",
            "wssp-cmd-op-1-x.scope",
            "wssp-cmd-op-1-1.service",
            "other-op-1-1.scope",
            "wssp-cmd-op/x-1-1.scope",
            "wssp-cmd-op-1-123456789012345678901.scope",
        ] {
            assert!(validate_command_scope_unit(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn guest_identity_initializes_groups_before_dropping_root_and_execing() {
        let harness = format!(
            r#"
import os, pwd, sys, types
{IN_SCOPE}
calls = []
os.access = lambda path, mode: False
pwd.getpwuid = lambda uid: types.SimpleNamespace(pw_name='guest', pw_gid=2345)
os.initgroups = lambda name, gid: calls.append(('groups', name, gid))
os.setgid = lambda gid: calls.append(('gid', gid))
os.setuid = lambda uid: calls.append(('uid', uid))
def execute(program, argv):
    assert calls == [('groups', 'guest', 2345), ('gid', 2345), ('uid', 1234)]
    assert program == '/bin/true' and argv == ['/bin/true']
    print('groups-before-exec')
os.execvp = execute
source = sys.argv[1]
sys.argv = ['helper', '{TEST_UNIT}', '1234', '2345', '/bin/true']
exec(source)
"#
        );
        let out = std::process::Command::new("python3")
            .args(["-I", "-S", "-c", &harness, IDENTITY_HELPER])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.stdout, b"groups-before-exec\n");
        // Group lookup/setup failure cannot execute a workload as root.
        let denied = harness.replace(
            "os.initgroups = lambda name, gid: calls.append(('groups', name, gid))",
            "os.initgroups = lambda name, gid: (_ for _ in ()).throw(PermissionError())",
        );
        let out = std::process::Command::new("python3")
            .args(["-I", "-S", "-c", &denied, IDENTITY_HELPER])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1));
        assert!(out.stdout.is_empty());
    }

    #[test]
    fn root_identity_execs_only_as_actual_root_with_uid_and_gid_zero() {
        let harness = format!(
            r#"
import os, sys
{IN_SCOPE}
calls = []
os.access = lambda path, mode: False
os.getuid = lambda: int(os.environ.get('FAKE_UID', '0'))
os.getgid = lambda: 0
os.setgroups = lambda groups: calls.append(('groups', groups))
def execute(program, argv):
    assert calls == [('groups', [0])]
    assert program == '/bin/true' and argv == ['/bin/true']
    print('root-exec')
os.execvp = execute
source = sys.argv[1]
sys.argv = ['helper', '{TEST_UNIT}', sys.argv[2], sys.argv[3], '/bin/true']
exec(source)
"#
        );
        let run = |uid: &str, gid: &str, fake_uid: &str| {
            std::process::Command::new("python3")
                .args(["-S", "-c", &harness, ROOT_IDENTITY_HELPER, uid, gid])
                .env("FAKE_UID", fake_uid)
                .output()
                .unwrap()
        };
        let out = run("0", "0", "0");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.stdout, b"root-exec\n");
        // Any other identity, or a launcher not actually running as root,
        // never executes the workload.
        for (uid, gid, fake) in [("1000", "0", "0"), ("0", "1000", "0"), ("0", "0", "1000")] {
            let out = run(uid, gid, fake);
            assert_eq!(out.status.code(), Some(1), "{uid} {gid} {fake}");
            assert!(out.stdout.is_empty());
        }
        // The guest-user helper keeps refusing uid 0.
        assert!(IDENTITY_HELPER.contains("if uid <= 0 or gid <= 0"));
        assert!(!ROOT_IDENTITY_HELPER.contains("setuid"));
        // U9: both bodies run the one shared gate, before their own code.
        for helper in [IDENTITY_HELPER, ROOT_IDENTITY_HELPER] {
            let direct = helper.split("DIRECT_HELPER = r\"\"\"").nth(1).unwrap();
            let gate = direct.find("_wssp_scope_gate()\n").unwrap();
            assert!(gate < direct.find("int(sys.argv[1])").unwrap());
        }
    }

    #[test]
    fn root_exec_argv_uses_root_identity_and_root_helper_only_when_flagged() {
        let client = IncusClient::new("/nonexistent/wssp-test-incus", "default")
            .with_guest(&GuestIdentity::default());
        let argv = vec!["/bin/true".to_string()];
        let guest = client.exec_spawn_args(None, TEST_UNIT, &argv).unwrap();
        assert_eq!(
            guest[..10],
            [
                "--user",
                "0",
                "--group",
                "0",
                "--cwd",
                "/home/user",
                "--env",
                "HOME=/home/user",
                "--env",
                "SHELL=/bin/bash"
            ]
        );
        assert_eq!(guest[10..15], ["--", "python3", "-I", "-S", "-c"]);
        assert_eq!(guest[15], IDENTITY_HELPER);
        assert_eq!(guest[16..], [TEST_UNIT, "1000", "1000", "/bin/true"]);
        // A unit outside the grammar never reaches a guest argv.
        assert!(client.exec_spawn_args(None, "bad.scope", &argv).is_err());

        let root = client.with_root_exec(true);
        let argv_root = root.exec_spawn_args(None, TEST_UNIT, &argv).unwrap();
        assert_eq!(
            argv_root[..10],
            [
                "--user",
                "0",
                "--group",
                "0",
                "--cwd",
                "/root",
                "--env",
                "HOME=/root",
                "--env",
                "SHELL=/bin/sh"
            ]
        );
        assert_eq!(argv_root[15], ROOT_IDENTITY_HELPER);
        assert_eq!(argv_root[16..], [TEST_UNIT, "0", "0", "/bin/true"]);
        let cwd = root
            .exec_spawn_args(Some("/srv/app"), TEST_UNIT, &argv)
            .unwrap();
        assert_eq!(cwd[5], "/srv/app");
        assert!(
            root.exec_spawn_args(Some("relative"), TEST_UNIT, &argv)
                .is_err()
        );
        // A root exec still requires the sandbox's valid declared identity.
        let invalid = IncusClient::new("/nonexistent/wssp-test-incus", "default")
            .with_guest(&GuestIdentity {
                guest_uid: 0,
                ..GuestIdentity::default()
            })
            .with_root_exec(true);
        assert!(invalid.exec_spawn_args(None, TEST_UNIT, &argv).is_err());
        // Root pid files stay off the guest user's HOME.
        let _ops = set_test_guest_ops_dir(None);
        let (wrapped, _) = wrap_build_root_command("op-root", &argv).unwrap();
        assert!(
            wrapped[4].contains("'/run/wssp/ops/op-root.pid'"),
            "{}",
            wrapped[4]
        );
        let (wrapped, _) = wrap_user_command("op-user", &argv, &GuestIdentity::default()).unwrap();
        assert!(wrapped[4].contains("'/home/user/.wssp/ops/op-user.pid'"));
    }

    /// What one launcher run must show: whether it selected the scope,
    /// whether it wrote the unscoped marker (before any identity call), its
    /// exit code, and whether the workload ran.
    struct LaunchExpect {
        scoped: bool,
        marker: bool,
        exit_code: i32,
        ran: bool,
    }

    fn check_guest_command_path(mode: &str, expect: LaunchExpect) {
        // Run the exact guest bootstrap with synthetic guest capabilities,
        // cgroup membership, marker syscalls and identity syscalls. Never
        // contact the host service manager, write /run, or setuid.
        let harness = r#"
import builtins, io, os, pwd, stat, subprocess, sys, types
source, mode, unit = sys.argv[1:]
m = lambda name: name in mode.split('+')
calls = []
real_run = subprocess.run
real_open = os.open
real_close = os.close
scope_state = {'in': False}
def executable(path, flags):
    assert path == '/usr/bin/systemd-run' and flags == os.X_OK
    return not (m('missing') or m('non-executable'))
os.access = executable
os.path.isdir = lambda path: path == '/run/systemd/system' and not m('no-runtime-dir')
def read_file(path, *args, **kwargs):
    if path == '/proc/1/comm':
        return io.StringIO('init\n' if m('non-systemd') else 'systemd\n')
    if path == '/proc/self/cgroup':
        if m('cgroup-unreadable'):
            raise OSError()
        if m('hybrid') and scope_state['in']:
            return io.BytesIO(b'1:name=systemd:/x\n0::/wssp.slice/' + unit.encode() + b'\n')
        if scope_state['in'] and not m('slice-relocated'):
            return io.BytesIO(b'0::/wssp.slice/' + unit.encode() + b'\n')
        return io.BytesIO(b'0::/system.slice/incus-agent.service\n')
    raise AssertionError('unexpected open ' + path)
builtins.open = read_file
# The marker: /run/wssp and /run/wssp/unscoped, never the real /run.
RUN_FD = 9001
MARKER_FD = 9002
def mkdir(path, mode_bits):
    assert path == '/run/wssp' and mode_bits == 0o755
    if m('marker-eacces'):
        raise PermissionError()
    if not m('marker-exists'):
        raise FileExistsError()
os.mkdir = mkdir
def stat_result(kind, uid, bits):
    return types.SimpleNamespace(st_mode=kind | bits, st_uid=uid)
def lstat(path):
    assert path == '/run/wssp'
    if m('marker-symlink'):
        return stat_result(stat.S_IFLNK, 0, 0o777)
    if m('marker-not-root'):
        return stat_result(stat.S_IFDIR, 1000, 0o755)
    if m('marker-writable'):
        return stat_result(stat.S_IFDIR, 0, 0o777)
    return stat_result(stat.S_IFDIR, 0, 0o755)
os.lstat = lstat
def open_(path, flags, mode_bits=0o777, *, dir_fd=None):
    if path == '/run/wssp':
        assert flags & os.O_NOFOLLOW and flags & os.O_DIRECTORY and dir_fd is None
        return RUN_FD
    if path == 'unscoped':
        assert dir_fd == RUN_FD and mode_bits == 0o644
        for flag in (os.O_CREAT, os.O_NOFOLLOW, os.O_CLOEXEC, os.O_NONBLOCK, os.O_WRONLY):
            assert flags & flag, flag
        os.write(1, b'marker\n')
        calls.append(('marker',))
        return MARKER_FD
    return real_open(path, flags, mode_bits, dir_fd=dir_fd)
os.open = open_
def fstat(fd):
    if fd == RUN_FD:
        return stat_result(stat.S_IFDIR, 0, 0o755)
    assert fd == MARKER_FD
    if m('marker-fifo'):
        return stat_result(stat.S_IFIFO, 0, 0o644)
    return stat_result(stat.S_IFREG, 0, 0o644)
os.fstat = fstat
os.close = lambda fd: None if fd in (RUN_FD, MARKER_FD) else real_close(fd)
def version(argv, **kwargs):
    assert argv == ['/usr/bin/systemd-run', '--version']
    assert kwargs == dict(stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, timeout=2, check=False)
    if m('probe-timeout'):
        raise subprocess.TimeoutExpired(argv, 2)
    if m('probe-error'):
        raise OSError()
    return types.SimpleNamespace(
        returncode=1 if m('probe-failed') else 0,
        stdout=(b'systemd 253 (253.9)\n' if m('old') else
                b'systemd 254 (254.1)\n' if m('minimum-version') else
                b'garbage' if m('bad-version') else b'systemd 255 (255.4)\n'))
subprocess.run = version
pwd.getpwuid = lambda uid: types.SimpleNamespace(pw_name='guest', pw_gid=2345)
def groups(name, gid):
    # Also observe attempted retries whose identity-order assertion would fail.
    os.write(1, b'identity\n')
    calls.append(('groups', name, gid))
os.initgroups = groups
os.setgid = lambda gid: calls.append(('gid', gid))
os.setuid = lambda uid: calls.append(('uid', uid))
def execute(program, argv):
    marker = [('marker',)] if calls[:1] == [('marker',)] else []
    assert calls == marker + [('groups', 'guest', 2345), ('gid', 2345), ('uid', 1234)], calls
    assert program == '/bin/sh' and argv == sys.argv[3:]
    result = real_run(argv, check=False)
    assert result.returncode == 0
os.execvp = execute
def scope(program, argv):
    assert calls == [], 'scope must start before dropping root'
    assert program == '/usr/bin/systemd-run'
    assert argv[:15] == [program, '--scope', '--quiet', '--collect',
        '--no-ask-password', '--description=wssp-command',
        '--property=OOMPolicy=continue', '--expand-environment=no',
        '--unit=' + unit, '--slice=wssp.slice', '--',
        'python3', '-I', '-S', '-c']
    # The unit is forwarded unchanged; the identity body pops it.
    assert argv[16:] == sys.argv[1:] and argv[16] == unit
    os.write(1, b'scope\n')
    if m('scope-fails-before'):
        raise OSError()
    scope_state['in'] = True
    exec(argv[15])
    if m('scope-fails-after'):
        raise OSError()
    raise SystemExit(0)  # A successful exec cannot return to the selector.
os.execv = scope
sys.argv = ['helper', unit, '1234', '2345', '/bin/sh', '-c',
            'printf "user-command:%s\\n" "$1"', 'sh', '$LITERAL']
exec(source)
"#;
        let unit = if mode == "bad-unit" {
            "wssp-cmd-op.scope"
        } else {
            TEST_UNIT
        };
        let out = Command::new("python3")
            .args(["-I", "-S", "-c", harness, IDENTITY_HELPER, mode, unit])
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(expect.exit_code),
            "{mode}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let expected = format!(
            "{}{}{}",
            if expect.scoped { "scope\n" } else { "" },
            if expect.marker { "marker\n" } else { "" },
            if expect.ran {
                "identity\nuser-command:$LITERAL\n"
            } else {
                ""
            }
        );
        assert_eq!(out.stdout, expected.as_bytes(), "{mode}");
    }

    const SCOPED: LaunchExpect = LaunchExpect {
        scoped: true,
        marker: false,
        exit_code: 0,
        ran: true,
    };
    const UNSCOPED: LaunchExpect = LaunchExpect {
        scoped: false,
        marker: true,
        exit_code: 0,
        ran: true,
    };
    const REFUSED: LaunchExpect = LaunchExpect {
        scoped: false,
        marker: false,
        exit_code: 1,
        ran: false,
    };

    #[test]
    fn guest_command_uses_its_named_scope_on_supported_systemd_without_a_marker() {
        for mode in ["scope", "minimum-version"] {
            check_guest_command_path(mode, SCOPED);
        }
    }

    #[test]
    fn guest_command_falls_back_when_systemd_run_is_missing_or_not_executable() {
        for mode in ["missing", "non-executable"] {
            check_guest_command_path(mode, UNSCOPED);
        }
    }

    #[test]
    fn guest_command_falls_back_on_old_systemd() {
        check_guest_command_path("old", UNSCOPED);
    }

    #[test]
    fn guest_command_falls_back_without_systemd_pid1_or_runtime_dir() {
        for mode in ["non-systemd", "no-runtime-dir"] {
            check_guest_command_path(mode, UNSCOPED);
        }
    }

    #[test]
    fn guest_command_falls_back_when_read_only_version_probe_fails() {
        // The 2 s timeout fallback writes the marker too.
        for mode in [
            "probe-failed",
            "bad-version",
            "probe-timeout",
            "probe-error",
        ] {
            check_guest_command_path(mode, UNSCOPED);
        }
    }

    /// A scope that is not exactly `wssp.slice/<unit>` (a `Slice=` drop-in,
    /// a hybrid hierarchy's extra lines, an unreadable `/proc/self/cgroup`)
    /// writes the marker before the drop; the workload still runs.
    #[test]
    fn a_relocated_or_unreadable_scope_writes_the_marker_before_the_drop() {
        for mode in ["slice-relocated", "hybrid", "cgroup-unreadable"] {
            check_guest_command_path(
                mode,
                LaunchExpect {
                    scoped: true,
                    ..UNSCOPED
                },
            );
        }
        // A marker directory created by this launcher is fine.
        check_guest_command_path("old+marker-exists", UNSCOPED);
    }

    /// Fail closed: an unscoped launch whose marker cannot be written runs
    /// no workload, before any identity call (no banner can bind).
    #[test]
    fn an_unwritable_marker_fails_the_unscoped_launch_before_the_drop() {
        for mode in [
            "marker-eacces",
            "marker-symlink",
            "marker-not-root",
            "marker-writable",
        ] {
            check_guest_command_path(&format!("old+{mode}"), REFUSED);
        }
        check_guest_command_path(
            "old+marker-fifo",
            LaunchExpect {
                marker: true,
                ..REFUSED
            },
        );
        // An invalid unit never runs anything.
        check_guest_command_path("bad-unit", REFUSED);
    }

    #[test]
    fn guest_command_never_retries_after_selecting_scope() {
        check_guest_command_path(
            "scope-fails-before",
            LaunchExpect {
                scoped: true,
                exit_code: 1,
                ran: false,
                marker: false,
            },
        );
        check_guest_command_path(
            "scope-fails-after",
            LaunchExpect {
                scoped: true,
                exit_code: 1,
                ran: true,
                marker: false,
            },
        );
    }

    #[test]
    fn abandoned_cleanup_classifies_the_final_drain_not_an_intermediate_frame() {
        for kind in ["WSSP_EXIT", "WSSP_SETUP_FAILED"] {
            for reframed in [false, true] {
                let request = RunCommandRequest {
                    template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                        .template_digest,
                    sandbox_id: "sbx-1".into(),
                    instance_name: "wssp-sbx-sbx-1".into(),
                    operation_id: "op-abandon".into(),
                    idempotency_key: "op-abandon".into(),
                    generation: 1,
                    attempt: 1,
                    argv: vec!["true".into()],
                    script: None,
                    cwd: None,
                    timeout_ms: Some(1000),
                    env: Vec::new(),
                    stdin: None,
                    guest: GuestIdentity::default(),
                    build_step: None,
                };
                let supervisor =
                    ExecSupervisor::new(crate::incus::shim_tests::client_for("running"));
                let mut child = Command::new("/bin/sh")
                    .args(["-c", "exit 0"])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap();
                let initial = format!("WSSP_PID n 4242\n\n{kind} n 0\n");
                let tail = if reframed {
                    b"late-stderr\nWSSP_EXIT n 7\n".to_vec()
                } else {
                    b"late-stderr".to_vec()
                };
                let expected_stderr = [initial.as_bytes(), &tail].concat();
                let (start_tx, start_rx) = mpsc::channel();
                let out_rx = PipeEvidence::default();
                let err_rx = PipeEvidence::default();
                let (out_tx, err_tx) = (out_rx.sink(), err_rx.sink());
                let err_seen = err_rx.share();
                let mut pumps = PipePumps(vec![thread::spawn(move || {
                    start_rx.recv().unwrap();
                    assert!(err_tx.record(initial.as_bytes()));
                    // A sample counted after the record proves the supervisor
                    // took a snapshot holding the initial frame and not the
                    // later bytes, so they cannot join it. No sleeps.
                    let recorded = err_seen.samples();
                    while err_seen.samples() == recorded {
                        thread::yield_now();
                    }
                    assert!(out_tx.record(b"late-stdout"));
                    assert!(err_tx.record(&tail));
                })]);
                let output = supervisor.finish_cancel(
                    Stop::Cancel,
                    &supervisor.bind(&request).unwrap(),
                    &request,
                    &mut child,
                    "n",
                    &out_rx,
                    &err_rx,
                    &mut Vec::new(),
                    &mut Vec::new(),
                    &mut pumps,
                    0,
                    &AtomicBool::new(false),
                    &mut false,
                    &|_| {
                        // No frame exists until cleanup ownership is abandoned.
                        start_tx.send(()).unwrap();
                        false
                    },
                    &AtomicBool::new(false),
                );
                let result = match output {
                    Ok(WaitOutcome::Natural(out)) => {
                        effect_completion::command_outcome(&request, &out.stdout, &out.stderr, "n")
                            .map_err(EffectError::from)
                    }
                    Ok(WaitOutcome::Cancelled(_) | WaitOutcome::TimedOut(_)) => {
                        panic!("natural observation lost arbitration")
                    }
                    Err(err) => Err(EffectError::Unknown(err)),
                };
                if reframed {
                    let response = result.expect("final EXIT frame");
                    assert_eq!(response.command.exit_code, Some(7));
                    assert_eq!(response.command.chunks[0].bytes, b"late-stdout");
                    assert_eq!(
                        response.command.chunks[1].bytes,
                        format!("\n{kind} n 0\nlate-stderr").as_bytes()
                    );
                } else {
                    let err = result.expect_err("no final frame after late output");
                    assert_eq!(err.state(), OperationState::UnknownOutcome);
                    let response = err.command().expect("raw output retained");
                    assert_eq!(response.command.exit_code, None);
                    assert_eq!(response.command.chunks[0].bytes, b"late-stdout");
                    assert_eq!(response.command.chunks[1].bytes, expected_stderr);
                }
                assert!(pumps.0.is_empty());
            }
        }
    }

    /// D3a: a pump never waits for the supervisor's evidence pass. With no
    /// sampling at all it reads a 16 MiB stream to EOF (the old 4-slot
    /// channel blocked it after four chunks), every byte reaches
    /// `CommandOutput`, and the evidence keeps the head and the final frame.
    #[test]
    fn pump_never_blocks_on_unsampled_evidence() {
        const TOTAL: usize = 16 * 1024 * 1024;
        let mut stream = vec![b'x'; TOTAL];
        stream[..18].copy_from_slice(b"WSSP_PID nn 4242\n\n");
        let frame = b"\nWSSP_EXIT nn 0\n";
        stream[TOTAL - frame.len()..].copy_from_slice(frame);
        let evidence = PipeEvidence::default();
        let sink = evidence.sink();
        let output = crate::CommandOutput::default();
        let pump_output = output.clone();
        let (done_tx, done_rx) = mpsc::channel();
        let pump = thread::spawn(move || {
            let started = Instant::now();
            pump_pipe(
                std::io::Cursor::new(stream),
                sink,
                &AtomicBool::new(false),
                Some(pump_output),
                None,
                &AtomicBool::new(false),
            );
            let _ = done_tx.send(started.elapsed());
        });
        // Hang guard only: the old pump never finished without a sampler.
        let elapsed = done_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("pump blocked on unsampled evidence");
        pump.join().unwrap();
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
        assert_eq!(evidence.samples(), 0);
        assert_eq!(output.total(), TOTAL as u64);
        let mut seen = Vec::new();
        drain_pipe(&evidence, &mut seen);
        assert!(seen.len() <= 16384);
        assert!(seen.starts_with(b"WSSP_PID nn 4242\n"));
        assert!(seen.ends_with(frame));
        // A dropped supervisor view stops the pump, like a closed channel.
        let gone = PipeEvidence::default();
        let sink = gone.sink();
        drop(gone);
        assert!(!sink.record(b"late"));
    }

    /// E-19/E-20: the stop verdict table. Only an attributed stop can become
    /// CANCELLED/timeout; every frame that is not a signal death stays the
    /// command's own result, and no evidence at all stays UNKNOWN.
    #[test]
    fn g3_stop_verdict_requires_attribution_and_a_signal_death() {
        use StopVerdict::{Natural, Stopped, Unknown};
        for unconfirmed in [false, true] {
            for (framed, exit, attributed, expected) in [
                // The escalated KILL took the wrapper too: no frame.
                (false, None, true, Stopped),
                // TERM / KILL death of the running command, reported by the wrapper.
                (true, Some(143), true, Stopped),
                (true, Some(137), true, Stopped),
                // The command handled TERM and reported its own status.
                (true, Some(0), true, Natural),
                (true, Some(1), true, Natural),
                (true, Some(130), true, Natural),
                // A frame followed by more bytes: no accepted exit, never a stop.
                (true, None, true, Natural),
                (true, None, false, Natural),
                // An unattributed non-signal exit is always the command's own.
                (true, Some(0), false, Natural),
                (true, Some(1), false, Natural),
                // Group gone without attribution and no frame: no proof.
                (false, None, false, Unknown),
            ] {
                assert_eq!(
                    stop_verdict(framed, exit, attributed, unconfirmed),
                    expected,
                    "framed={framed} exit={exit:?} attributed={attributed} unconfirmed={unconfirmed}"
                );
            }
            // An unattributed signal-death code: the command's own exit when no
            // stop was issued blind (it had already ended when the helper looked,
            // or exited 143 itself), but UNKNOWN after an issued stop whose
            // effect was never observed (G3R-1: a lost helper reply).
            for code in [143, 137] {
                assert_eq!(
                    stop_verdict(true, Some(code), false, unconfirmed),
                    if unconfirmed { Unknown } else { Natural },
                    "code={code} unconfirmed={unconfirmed}"
                );
            }
        }
    }

    /// The terminate helper attributes a stop only while the user command (a
    /// live direct child of the wrapper leader) is running. A group whose
    /// leader has no running child, or a group already gone, is plain
    /// disappearance.
    #[test]
    fn g3_terminate_helper_attributes_only_a_running_command() {
        let run_helper = |pgid: u32, command_nonce: &str| {
            let nonce = random_nonce().unwrap();
            let out = Command::new("/bin/sh")
                .args([
                    "-c",
                    client::GUEST_TERMINATE_SCRIPT,
                    "wssp-terminate",
                    &nonce,
                    &pgid.to_string(),
                    command_nonce,
                ])
                .stdin(Stdio::null())
                .output()
                .unwrap();
            (
                String::from_utf8_lossy(&out.stderr).into_owned(),
                nonce,
                out.status.code(),
            )
        };
        // Like the real wrapper: `setsid -w` makes the shell a new group
        // leader and reaps it, so a finished leader leaves no zombie behind.
        let dir = std::env::temp_dir().join(format!("wssp-g3-term-{}", random_nonce().unwrap()));
        std::fs::create_dir_all(&dir).unwrap();
        let spawn_leader = |body: &str, command_nonce: &str| {
            let pid_file = dir.join(random_nonce().unwrap());
            let script = format!(
                "trap ':' TERM; : 'WSSP_PID {command_nonce} '; printf '%s' $$ > '{}'; {body}",
                pid_file.display()
            );
            let parent = Command::new("setsid")
                .args(["-w", "/bin/sh", "-c", &script, "wssp-run"])
                .process_group(0)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            let pgid = loop {
                if let Some(pid) = std::fs::read_to_string(&pid_file)
                    .ok()
                    .and_then(|text| text.parse::<u32>().ok())
                {
                    break pid;
                }
                assert!(Instant::now() < deadline, "leader never started");
                thread::sleep(POLL);
            };
            // Let the body reach its steady state (child running / builtin wait).
            thread::sleep(Duration::from_millis(200));
            (parent, pgid)
        };
        // 1. A wrapper-shaped leader waiting on a running child.
        let command_nonce = random_nonce().unwrap();
        let (mut parent, pgid) = spawn_leader("sleep 30; exit 0", &command_nonce);
        let (stderr, nonce, code) = run_helper(pgid, &command_nonce);
        assert_eq!(stderr, format!("WSSP_STATUS {nonce} group_terminated\n"));
        assert_eq!(code, Some(0));
        let _ = parent.wait();
        // 2. The leader alive with no running child: the command already ended.
        let command_nonce = random_nonce().unwrap();
        let (mut parent, pgid) = spawn_leader("read line", &command_nonce);
        let (stderr, nonce, code) = run_helper(pgid, &command_nonce);
        assert_eq!(stderr, format!("WSSP_STATUS {nonce} group_gone\n"));
        assert_eq!(code, Some(0));
        let _ = parent.wait();
        // 3. The group is already gone.
        let (stderr, nonce, _) = run_helper(pgid, &command_nonce);
        assert_eq!(stderr, format!("WSSP_STATUS {nonce} group_gone\n"));
        // The parser accepts exactly the two records, nothing else.
        for (stderr, attributed) in [
            (
                format!("WSSP_STATUS {nonce} group_terminated\n"),
                Some(true),
            ),
            (format!("WSSP_STATUS {nonce} group_gone\n"), Some(false)),
            (format!("WSSP_STATUS {nonce} group_terminated"), None),
            ("WSSP_STATUS other group_terminated\n".to_string(), None),
            (format!("x\nWSSP_STATUS {nonce} group_terminated\n"), None),
        ] {
            let out = IncusCommandOutput {
                stdout: String::new(),
                stderr,
                exit_code: 0,
            };
            assert_eq!(
                effect_completion::group_gone(&nonce, &out)
                    .ok()
                    .map(|gone| gone.terminated().is_some()),
                attributed,
                "{out:?}"
            );
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn c10_pid_or_cancel_flag_is_never_termination_evidence() {
        use sandbox_protocol::OperationState;
        let request = RunCommandRequest {
            template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                .template_digest,
            sandbox_id: "sbx".into(),
            instance_name: "wssp-sbx-sbx".into(),
            operation_id: "op-c10".into(),
            idempotency_key: "op-c10".into(),
            generation: 1,
            attempt: 1,
            argv: vec!["true".into()],
            script: None,
            cwd: None,
            timeout_ms: Some(1000),
            env: Vec::new(),
            stdin: None,
            guest: GuestIdentity::default(),
            build_step: None,
        };
        let (_, nonce) =
            wrap_user_command("op-c10", &["true".into()], &Default::default()).expect("wrap");
        let stderr = format!("WSSP_PID {nonce} 4242\n\nWSSP_EXIT {nonce} 0\n");
        assert!(
            effect_completion::command_outcome(&request, &[], b"", &nonce).is_err(),
            "cancelled without pid frame is uncertain"
        );
        let ok = effect_completion::command_outcome(&request, &[], stderr.as_bytes(), &nonce)
            .expect("cancelled with pid and exit evidence");
        assert_eq!(ok.command.state, OperationState::Succeeded);
        let pid_only = format!("WSSP_PID {nonce} 4242\n");
        assert_eq!(
            effect_completion::command_outcome(&request, &[], pid_only.as_bytes(), &nonce)
                .map_err(EffectError::from)
                .unwrap_err()
                .state(),
            OperationState::UnknownOutcome
        );
    }

    /// 4b: no local bookkeeping or naked PID request reaches any guest IO:
    /// the client binary does not even exist here.
    #[test]
    fn untracked_and_naked_signals_refuse_before_any_effect() {
        let client = IncusClient::new("/no-such-incus", "default");
        let bound = client.local_test_bound();
        let supervisor = ExecSupervisor::new(client);
        let target = crate::SignalTarget {
            target_operation_id: "forgotten".into(),
            generation: 1,
            attempt: 1,
            pid: 4242,
        };
        for (signal, target, code) in [
            (
                ProcessSignal::Sigterm,
                None,
                SandboxErrorCode::UnsupportedCapability,
            ),
            (
                ProcessSignal::Sigkill,
                None,
                SandboxErrorCode::UnsupportedCapability,
            ),
            (
                ProcessSignal::Sighup,
                Some(&target),
                SandboxErrorCode::UnknownOutcome,
            ),
            (
                ProcessSignal::Sigkill,
                Some(&target),
                SandboxErrorCode::UnknownOutcome,
            ),
        ] {
            let error = supervisor.signal(&bound, 4242, signal, target).unwrap_err();
            assert_eq!(
                error.state(),
                if code == SandboxErrorCode::UnknownOutcome {
                    sandbox_protocol::OperationState::UnknownOutcome
                } else {
                    sandbox_protocol::OperationState::Failed
                }
            );
            assert_eq!(error.code, code, "{signal:?}");
        }
        // Preserve C10's separate empty-control acknowledgment semantics.
        assert!(supervisor.cancel("forgotten").is_ok());
    }

    #[test]
    fn c15_wrap_user_script_preserves_multiline_body_as_single_bash_lc_argument() {
        let script = format!(
            "{}\n'quoted\" line\n  trailing spaces 世界\n",
            "x".repeat(520)
        );
        let (wrapped, nonce) = wrap_user_script("op-script", &script, &Default::default()).unwrap();
        assert_eq!(&wrapped[..2], ["setsid", "-w"]);
        assert_eq!(&wrapped[5..8], ["wssp-run", "/bin/bash", "-lc"]);
        assert_eq!(wrapped[8], script);
        assert!(wrapped[4].contains(&format!("WSSP_PID {nonce}")));
    }

    #[test]
    fn c15_golden_script_executes_with_literal_quotes_and_trailing_spaces() {
        use std::process::Command;
        let dir = std::env::temp_dir().join(format!("wssp-c15-golden-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ops = set_test_guest_ops_dir(Some(dir.join("ops")));
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../sandbox-protocol/fixtures/control_operation_dispatch_script.json"
        ))
        .unwrap();
        let script = fixture["script"].as_str().unwrap();
        let (wrapped, nonce) = wrap_user_script("op-golden", script, &Default::default()).unwrap();
        let out = Command::new(&wrapped[0])
            .args(&wrapped[1..])
            .current_dir(&dir)
            .output()
            .unwrap();
        let frames = parse_supervised_frames(&out.stdout, &out.stderr, &nonce);
        assert_eq!(frames.exit, Some(0));
        assert_eq!(
            out.stdout,
            "line1\nquote'\"\n世界  \n$(touch SHOULD_NOT_EXIST); `id`; \"quoted\"\n".as_bytes()
        );
        assert!(!dir.join("SHOULD_NOT_EXIST").exists());
        drop(ops);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn wrap_execs_user_argv_as_session_leader() {
        let (wrapped, nonce) = wrap_user_command(
            "op-1",
            &["sleep".to_string(), "5".to_string()],
            &Default::default(),
        )
        .unwrap();
        assert_eq!(&wrapped[..4], ["setsid", "-w", "/bin/sh", "-c"]);
        assert!(wrapped[4].contains(&format!("WSSP_PID {nonce}")));
        assert!(wrapped[4].contains("trap ':' TERM"));
        assert!(wrapped[4].contains("WSSP_EXIT"));
        assert!(wrapped[4].contains(&format!("WSSP_EXIT {nonce}")));
        assert!(wrapped[4].contains("op-1.pid"));
        assert!(!wrapped[4].contains("exec \"$@\""));
        assert_eq!(&wrapped[5..], ["wssp-run", "sleep", "5"]);
    }

    /// The Incus guest agent starts the command as a process-group (session)
    /// leader. In that position `setsid` must fork; the direct child must still
    /// live until the user command ends, or the agent stops relaying stdin.
    #[test]
    fn wrapper_started_as_group_leader_keeps_direct_child_and_stdin_alive() {
        use std::process::{Command, Stdio};
        let ops_dir = std::env::temp_dir().join(format!("wssp-wrap-leader-{}", std::process::id()));
        std::fs::create_dir_all(&ops_dir).expect("ops dir");
        let _ops = set_test_guest_ops_dir(Some(ops_dir.clone()));
        let (wrapped, nonce) = wrap_user_command(
            "op-leader",
            &[
                "/bin/sh".to_string(),
                "-c".to_string(),
                "read line; printf 'got:%s' \"$line\"; exit 7".to_string(),
            ],
            &Default::default(),
        )
        .expect("wrap");
        let mut child = Command::new(&wrapped[0])
            .args(&wrapped[1..])
            .process_group(0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn wrapper");
        thread::sleep(Duration::from_millis(300));
        assert!(
            child.try_wait().expect("try_wait").is_none(),
            "direct child exited before the user command read stdin"
        );
        let mut stdin = child.stdin.take().expect("stdin");
        stdin.write_all(b"late\n").expect("write stdin");
        drop(stdin);
        let out = child.wait_with_output().expect("wait");
        let frames = parse_supervised_frames(&out.stdout, &out.stderr, &nonce);
        assert_eq!(out.stdout, b"got:late");
        assert_eq!(frames.exit, Some(7));
        assert_eq!(out.status.code(), Some(7));
        std::fs::remove_dir_all(ops_dir).expect("cleanup");
    }

    /// 4a: the exact wrapper emits one post-setup READY record whose PID is
    /// the session leader (`$$`, the user command's parent), with the real boot
    /// UUID and leader start ticks. A user command that reads the real nonce
    /// from the wrapper's argv and forges a later record cannot rebind.
    #[test]
    fn real_wrapper_emits_one_post_setup_start_record_that_user_bytes_cannot_forge() {
        use std::process::Command;
        let ops_dir = std::env::temp_dir().join(format!("wssp-ready-ops-{}", std::process::id()));
        std::fs::create_dir_all(&ops_dir).expect("ops dir");
        let _ops = set_test_guest_ops_dir(Some(ops_dir.clone()));
        let user = "set -eu; n=$(tr '\\000' '\\n' < /proc/$PPID/cmdline | sed -n 's/.*WSSP_PID \\([^ ]*\\) .*/\\1/p' | head -n1); printf 'WSSP_READY %s 4242 00000000-0000-4000-8000-000000000009 1\\n' \"$n\" >&2; printf '%s %s\\n' \"$PPID\" \"$(cut -d' ' -f22 /proc/$PPID/stat)\"";
        let (wrapped, nonce) = wrap_user_command(
            "op-ready",
            &["/bin/sh".to_string(), "-c".to_string(), user.to_string()],
            &Default::default(),
        )
        .expect("wrap");
        let out = Command::new(&wrapped[0])
            .args(&wrapped[1..])
            .output()
            .expect("run wrapper");
        let frames = parse_supervised_frames(&out.stdout, &out.stderr, &nonce);
        let ready = frames.ready.clone().expect("start record");
        let stdout = String::from_utf8(out.stdout.clone()).unwrap();
        let mut fields = stdout.split_whitespace();
        let leader: u32 = fields.next().unwrap().parse().unwrap();
        let ticks: u64 = fields.next().unwrap().parse().unwrap();
        assert_eq!(ready.pid, leader);
        assert_eq!(frames.pid_frame.and_then(GuestPid::banner), Some(leader));
        assert_eq!(ready.start_ticks, ticks);
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
        assert_eq!(ready.boot_id, boot.trim());
        let forged = format!("WSSP_READY {nonce} 4242 00000000-0000-4000-8000-000000000009 1\n");
        assert_eq!(
            frames.user_stderr,
            forged.as_bytes(),
            "forgery stays user output"
        );
        assert_eq!(frames.exit, Some(0));

        // Setup failure (ops path is a file): no start record, no identity.
        let blocked = ops_dir.join("blocked");
        std::fs::write(&blocked, b"file").unwrap();
        drop(_ops);
        let _ops = set_test_guest_ops_dir(Some(blocked.join("sub")));
        let (wrapped, nonce) =
            wrap_user_command("op-setup", &["true".to_string()], &Default::default()).unwrap();
        let out = Command::new(&wrapped[0])
            .args(&wrapped[1..])
            .output()
            .unwrap();
        let frames = parse_supervised_frames(&out.stdout, &out.stderr, &nonce);
        assert_eq!(frames.ready, None);
        assert!(frames.setup_failed.is_some());

        // WP0: the start record is mandatory. A guest whose boot id cannot
        // be read (the same wrapper text, pointed at a missing file) never
        // runs argv: it reports a setup failure, which is pre-effect.
        drop(_ops);
        let _ops = set_test_guest_ops_dir(Some(ops_dir.clone()));
        let ran = ops_dir.join("argv-ran");
        let (mut wrapped, nonce) = wrap_user_command(
            "op-unready",
            &["touch".to_string(), ran.display().to_string()],
            &Default::default(),
        )
        .unwrap();
        let script = wrapped
            .iter_mut()
            .find(|arg| arg.contains("wssp_ready"))
            .unwrap();
        assert_eq!(script.matches("/proc/sys/kernel/random/boot_id").count(), 1);
        *script = script.replace("/proc/sys/kernel/random/boot_id", "/nonexistent/boot_id");
        let out = Command::new(&wrapped[0])
            .args(&wrapped[1..])
            .output()
            .unwrap();
        let frames = parse_supervised_frames(&out.stdout, &out.stderr, &nonce);
        assert_eq!(frames.ready, None);
        assert_eq!(frames.exit, None);
        assert!(frames.setup_failed.is_some());
        assert!(!ran.exists(), "argv never runs without its start record");
        let _ = std::fs::remove_dir_all(ops_dir);
    }

    #[test]
    fn rejects_unsafe_operation_ids() {
        assert!(validate_operation_id("../etc").is_err());
        assert!(validate_operation_id("op 1").is_err());
        assert!(validate_operation_id("op-1").is_ok());
    }

    #[test]
    fn generated_wrapper_preserves_stderr_and_exit_frames() {
        use std::process::Command;
        let ops_dir = std::env::temp_dir().join(format!("wssp-wrap-ops-{}", std::process::id()));
        std::fs::create_dir_all(&ops_dir).expect("ops dir");
        let _ops = set_test_guest_ops_dir(Some(ops_dir));
        let run = |user_argv: &[&str]| {
            let argv: Vec<String> = user_argv.iter().map(|s| s.to_string()).collect();
            let (wrapped, nonce) =
                wrap_user_command("op-wrap", &argv, &Default::default()).expect("wrap");
            let out = Command::new(&wrapped[0])
                .args(&wrapped[1..])
                .output()
                .expect("run wrapper");
            let frames = parse_supervised_frames(&out.stdout, &out.stderr, &nonce);
            (
                String::from_utf8(frames.user_stderr.to_vec()).unwrap(),
                frames.exit,
                out.status.code(),
            )
        };
        let (stderr, exit, status) = run(&["/bin/sh", "-c", "printf 'hello\\n' >&2"]);
        assert_eq!(stderr, "hello\n");
        assert_eq!(exit, Some(0));
        assert_eq!(status, Some(0));
        let (stderr, exit, status) = run(&["/bin/sh", "-c", "printf 'tail' >&2; exit 7"]);
        assert_eq!(stderr, "tail");
        assert_eq!(exit, Some(7));
        assert_eq!(status, Some(7));
        let (stderr, exit, _) = run(&[
            "/bin/sh",
            "-c",
            "printf 'before\\nWSSP_EXIT other-nonce 3\\nWSSP_STATUS ordinary text\\nWSSP_PID 777\\nafter\\n' >&2",
        ]);
        assert_eq!(
            stderr,
            "before\nWSSP_EXIT other-nonce 3\nWSSP_STATUS ordinary text\nWSSP_PID 777\nafter\n"
        );
        assert_eq!(exit, Some(0));
        let (stderr, _, _) = run(&["/bin/sh", "-c", "printf 'line\\r\\n' >&2"]);
        assert_eq!(stderr, "line\r\n");
    }

    #[test]
    fn effective_command_timeout_encoding_matrix() {
        for (wire, expected) in [
            (None, Some(DEFAULT_COMMAND_TIMEOUT)),
            (Some(0), None),
            (Some(1), Some(Duration::from_millis(1))),
            (Some(1_800_000), Some(MAX_COMMAND_TIMEOUT)),
        ] {
            assert_eq!(
                effective_command_timeout(wire, DEFAULT_COMMAND_TIMEOUT).unwrap(),
                expected
            );
        }
        assert!(effective_command_timeout(Some(1_800_001), DEFAULT_COMMAND_TIMEOUT).is_err());
        assert_eq!(
            effective_command_timeout(None, Duration::ZERO).unwrap(),
            Some(DEFAULT_COMMAND_TIMEOUT)
        );
    }
    #[test]
    fn command_timer_clock_setup_execution_and_renewal_are_independent() {
        let now = Instant::now();
        for wire in [None, Some(0), Some(1), Some(1_800_000)] {
            let budget = effective_command_timeout(wire, DEFAULT_COMMAND_TIMEOUT).unwrap();
            let mut setup = CommandTimer::new(now, budget);
            assert!(
                setup.expired(now + HOST_SETUP_BUDGET),
                "setup is always finite"
            );
            setup.started(now + Duration::from_secs(1));
            let original = setup.deadline();
            setup.started(now + Duration::from_secs(4)); // renewal cannot restart execution
            assert_eq!(setup.deadline(), original);
            assert_eq!(
                setup.expired(now + Duration::from_secs(122)),
                matches!(wire, None | Some(1))
            );
            if wire == Some(0) {
                assert_eq!(setup.deadline(), None);
            }
        }
    }
    /// A banner first accepted after `HOST_SETUP_BUDGET` (a
    /// supervision thread stalled 40 s on a 15 s budget) neither starts the
    /// execution timer nor binds a start. Otherwise the runtime deadline
    /// (late start + budget) could fall after the retire helper's due time
    /// (scope activation + budget + 20 s) and retirement could kill the
    /// command before its own timeout.
    #[test]
    fn a_banner_after_the_setup_budget_never_starts_or_binds() {
        let now = Instant::now();
        let budget = Duration::from_secs(15);
        let stalled = now + Duration::from_secs(40);
        let mut timer = CommandTimer::new(now, Some(budget));
        timer.started(stalled);
        assert_eq!(timer.deadline(), Some(now + HOST_SETUP_BUDGET));
        assert!(timer.expired(stalled));
        // Within the setup budget a start still counts, once.
        let mut timer = CommandTimer::new(now, Some(budget));
        let in_time = now + HOST_SETUP_BUDGET - Duration::from_millis(1);
        timer.started(in_time);
        timer.started(stalled);
        assert_eq!(timer.deadline(), Some(in_time + budget));
        // Invariant: a bound start's runtime deadline is never after the
        // earliest retire-kill time (scope activation >= spawn).
        assert!(
            in_time + budget < now + budget + crate::RETIRE_DEADLINE_SLACK,
            "the slack covers every admissible start"
        );

        // The bind gate: a late head never binds nor journals a start.
        let starts = Arc::new(Mutex::new(Vec::new()));
        let sink = starts.clone();
        let output =
            crate::CommandOutput::default().with_start_sink(move |start: &crate::CommandStart| {
                sink.lock().unwrap().push(start.clone())
            });
        let client = IncusClient::new("/nonexistent/wssp-test-incus", "default");
        let instance = client.local_test_bound();
        let supervisor = ExecSupervisor::new(client).with_output(output.clone());
        let mut request = crate::incus::shim_tests::run_req("late-banner");
        request.timeout_ms = Some(15_000);
        let track = |supervisor: &ExecSupervisor| {
            supervisor.active.lock().unwrap().insert(
                request.operation_id.clone(),
                ActiveExec {
                    host_pid: None,
                    generation: request.generation,
                    attempt: request.attempt,
                    instance: instance.clone(),
                    guest_pid: None,
                    birth: None,
                    nonce: "n".repeat(32),
                    description: None,
                    guest: request.guest.clone(),
                    argv: request.argv.clone(),
                    cancelled: false,
                    stdin: None,
                    budget_ms: 15_000,
                    start_uid: Some(1000),
                },
            );
        };
        track(&supervisor);
        let nonce = "n".repeat(32);
        let head = format!(
            "WSSP_PID {nonce} 4242\nWSSP_READY {nonce} 4242 00000000-0000-4000-8000-000000000001 77\n"
        );
        let timer = CommandTimer::new(now, Some(budget));
        assert!(supervisor.decide_start_at(&timer, stalled, &request, head.as_bytes(), true));
        assert!(supervisor.active_birth("late-banner").is_none());
        assert!(output.start().is_none());
        assert!(starts.lock().unwrap().is_empty());
        // The same head in time binds and journals once.
        assert!(supervisor.decide_start_at(&timer, in_time, &request, head.as_bytes(), true));
        assert_eq!(
            supervisor.active_birth("late-banner").map(|b| b.pid),
            Some(4242)
        );
        assert_eq!(starts.lock().unwrap().len(), 1);
    }

    #[test]
    fn admission_guard_lives_until_the_spawned_child_is_published() {
        use std::sync::{Barrier, MutexGuard};
        let dir = std::env::temp_dir().join(format!("wssp-c08-spawn-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("directory");
        let shim = dir.join("shim");
        crate::incus::shim_tests::install_executable(
            &shim,
            r#"#!/bin/sh
project=default
while [ $# -gt 0 ]; do
  case "$1" in
    --project) project=$2; shift 2 ;;
    *) break ;;
  esac
done
cmd=$1
shift
case "$cmd" in
  version) exit 0 ;;
  query)
    while [ $# -gt 0 ]; do shift; done
    printf '{"type":"sync","status":"Success","status_code":200,"metadata":{"status":"Running","status_code":103,"type":"virtual-machine","config":{"user.flycockpit.sandbox_id":"sbx","user.flycockpit.template_digest":"sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789","volatile.base_image":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"}}}\n'
    exit 0
    ;;
  exec)
    while [ $# -gt 0 ] && [ "$1" != "--" ]; do
      shift
    done
    [ "$1" = "--" ] && shift
    script=""
    prev=""
    for arg in "$@"; do
      if [ "$prev" = "-c" ]; then
        script=$arg
      fi
      prev=$arg
    done
    rest=${script#*WSSP_EXIT }
    nonce=${rest%% *}
    echo "WSSP_PID $nonce 1234" >&2
    printf '\nWSSP_EXIT %s 0\n' "$nonce" >&2
    exit 0
    ;;
  *) exit 0 ;;
esac
"#,
            0o700,
        );
        let supervisor = ExecSupervisor::new(IncusClient::new(shim.to_string_lossy(), "default"));
        struct Guard<'a> {
            _permit: MutexGuard<'a, ()>,
            supervisor: ExecSupervisor,
        }
        impl Drop for Guard<'_> {
            fn drop(&mut self) {
                let active = self.supervisor.active.lock().expect("active");
                assert!(
                    active.get("cmd").expect("placeholder").host_pid.is_some(),
                    "guard released before child publication"
                );
            }
        }
        let mutex = Arc::new(Mutex::new(()));
        let entered = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        let worker = thread::spawn({
            let mutex = mutex.clone();
            let entered = entered.clone();
            let resume = resume.clone();
            move || {
                let request = RunCommandRequest {
                    template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                        .template_digest,
                    sandbox_id: "sbx".into(),
                    instance_name: "wssp-sbx-sbx".into(),
                    operation_id: "cmd".into(),
                    idempotency_key: "cmd".into(),
                    generation: 1,
                    attempt: 1,
                    argv: vec!["true".into()],
                    script: None,
                    cwd: None,
                    timeout_ms: Some(1000),
                    env: Vec::new(),
                    stdin: None,
                    guest: GuestIdentity::default(),
                    build_step: None,
                };
                supervisor
                    .run_with_admission(&supervisor.bind(&request).unwrap(), &request, || {
                        let guard = Guard {
                            _permit: mutex.lock().expect("permit"),
                            supervisor: supervisor.clone(),
                        };
                        entered.wait();
                        resume.wait();
                        Ok((Arc::new(AtomicBool::new(false)), guard))
                    })
                    .expect("command");
            }
        });
        entered.wait();
        assert!(
            mutex.try_lock().is_err(),
            "revocation cannot pass guarded admission before spawn"
        );
        resume.wait();
        worker.join().expect("worker");
        assert!(mutex.try_lock().is_ok());
        std::fs::remove_dir_all(dir).expect("cleanup");
    }
    #[test]
    fn production_supervisor_parses_real_wrapper_once_and_preserves_raw_failures() {
        let dir = std::env::temp_dir().join(format!("wssp-c09-frames-{}", random_nonce().unwrap()));
        std::fs::create_dir_all(&dir).unwrap();
        let shim = dir.join("incus");
        crate::incus::shim_tests::install_executable(
            &shim,
            r#"#!/bin/sh
base=$(dirname "$0")
if [ "$1" = "query" ]; then echo '{"type":"sync","metadata":{"status":"Running","status_code":103,"type":"virtual-machine","config":{"user.flycockpit.sandbox_id":"sbx","user.flycockpit.template_digest":"sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789","volatile.base_image":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"}}}'; exit 0; fi
while [ "$1" != "--" ]; do shift; done
shift
if [ "${2:-}" = -I ] && [ "${3:-}" = -S ] && [ "${4:-}" = -c ]; then shift 8; fi
script=$5
rest=${script#*WSSP_EXIT }
WSSP_TEST_NONCE=${rest%% *}
export WSSP_TEST_NONCE
"$@" > "$base/stdout" 2> "$base/stderr-original"
mode=$(cat "$base/mode")
case "$mode" in
  missing_exit|missing_setup) sed '$d' "$base/stderr-original" > "$base/stderr" ;;
  no_pid) sed '1d' "$base/stderr-original" > "$base/stderr" ;;
  partial) printf 'WSSP_PID ' > "$base/stderr" ;;
  plus_pid) sed '1s/ [0-9][0-9]*$/ +4242/' "$base/stderr-original" > "$base/stderr" ;;
  cr_exit) sed '$s/$/\r/' "$base/stderr-original" > "$base/stderr" ;;
  padded_exit) sed '$s/ [0-9][0-9]*$/   +37  /' "$base/stderr-original" > "$base/stderr" ;;
  *) cp "$base/stderr-original" "$base/stderr" ;;
esac
cat "$base/stdout"
cat "$base/stderr" >&2
exit 0
"#,
            0o700,
        );
        let supervisor = ExecSupervisor::new(IncusClient::new(shim.to_string_lossy(), "default"));
        let guest_ops = set_test_guest_ops_dir(None);
        for mode in [
            "complete",
            "missing_exit",
            "no_pid",
            "partial",
            "plus_pid",
            "cr_exit",
            "padded_exit",
            "setup",
            "missing_setup",
        ] {
            let ops = dir.join(format!("ops-{mode}"));
            std::fs::create_dir_all(&ops).unwrap();
            if matches!(mode, "setup" | "missing_setup") {
                std::fs::create_dir(ops.join("cmd.pid")).unwrap();
            }
            guest_ops.set(Some(ops));
            std::fs::write(dir.join("mode"), mode).unwrap();
            let ran = dir.join(format!("ran-{mode}"));
            let request = RunCommandRequest {
                template_fingerprint: crate::CreateSandboxRequest::for_test("sbx", "key")
                    .template_digest,
                sandbox_id: "sbx".into(),
                instance_name: "wssp-sbx-sbx".into(),
                operation_id: "cmd".into(),
                idempotency_key: "cmd".into(),
                generation: 1,
                attempt: 1,
                argv: vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    format!(
                        "printf done > '{}'; printf '\\376stdout'; printf 'WSSP_PID %s ordinary-user-text\\nline\\r\\n\\377tail' \"$WSSP_TEST_NONCE\" >&2; exit 37",
                        ran.display()
                    ),
                ],
                script: None,
                cwd: None,
                timeout_ms: Some(2000),
                env: vec![],
                stdin: None,
                guest: GuestIdentity::default(),
                build_step: None,
            };
            let outcome = supervisor.run(&supervisor.bind(&request).unwrap(), &request);
            let raw_out = std::fs::read(dir.join("stdout")).unwrap();
            let raw_err = std::fs::read(dir.join("stderr")).unwrap();
            if mode == "setup" {
                let error = outcome.unwrap_err();
                assert!(matches!(error, EffectError::Completed(_)));
                assert_eq!(error.code, SandboxErrorCode::HostEffectNotIssued);
                assert!(!ran.exists(), "setup must never run argv");
                continue;
            }
            let response = if mode == "complete" {
                let response = outcome.unwrap().into_value();
                assert_eq!(response.command.exit_code, Some(37));
                assert_eq!(response.command.state, OperationState::Succeeded);
                response
            } else {
                let error = outcome.unwrap_err();
                assert!(matches!(error, EffectError::Unknown(_)), "{mode}");
                if mode == "missing_setup" {
                    assert!(!ran.exists());
                }
                error.command().unwrap().clone()
            };
            assert_eq!(response.command.chunks[0].bytes, raw_out, "{mode}: stdout");
            if mode == "complete" {
                // Head = private PID banner + fixed-position READY record (4a).
                let first_lf = raw_err.iter().position(|b| *b == b'\n').unwrap();
                assert!(raw_err[first_lf + 1..].starts_with(b"WSSP_READY "));
                let first_lf = first_lf
                    + 1
                    + raw_err[first_lf + 1..]
                        .iter()
                        .position(|b| *b == b'\n')
                        .unwrap();
                assert!(
                    response.command.birth.is_some(),
                    "complete run binds identity"
                );
                let tail = raw_err
                    .windows(b"\nWSSP_EXIT ".len())
                    .rposition(|w| w == b"\nWSSP_EXIT ")
                    .unwrap();
                assert_eq!(
                    response.command.chunks[1].bytes,
                    raw_err[first_lf + 1..tail]
                );
                assert!(
                    response.command.chunks[1].bytes.starts_with(b"WSSP_PID "),
                    "second PID-like user line is preserved"
                );
            } else {
                assert_eq!(
                    response.command.chunks[1].bytes, raw_err,
                    "{mode}: complete raw stderr including PID"
                );
            }
        }
        drop(guest_ops);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
