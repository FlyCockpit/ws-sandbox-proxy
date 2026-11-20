//! Incus adapter for CLI channels (see `crate::channel`).
//!
//! Every channel is ONE `incus exec` client:
//! `incus --project <p> exec --user 0 --group 0 --cwd <cwd> --env HOME=.. --env SHELL=..
//! [--env TERM=<term>] (-t|-T) <wssp-sbx-<id>> -- python3 -I -S -c <channel-helper> launch
//! <scope> <nonce> <uid> <gid> -- python3 -I -S -c <channel-helper> wrap WSSP_PID <nonce> …`.
//!
//! Only the fixed helper runs as guest root: it creates the channel's scope,
//! checks the cancel tombstone inside it and drops to the declared guest
//! identity before it touches the workload's argv or stdin. The wrapper then
//! prompts for its preamble (environment and frame secret), which only the
//! IO owner writes; nothing of the workload runs before its last byte.
//!
//! The spawn itself (instance binding, host spawn) carries no secret, so the
//! custody side never sees the environment or the frame secret.

use std::io::Read;
use std::process::{Child, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use sandbox_protocol::SandboxErrorCode;

use crate::before_issue::incus as pre;
use crate::channel::{
    CHANNEL_EXEC_READ_BYTES, CHANNEL_PREAMBLE_BUDGET, CHANNEL_PTY_READ_BYTES, ChannelBirth,
    ChannelClose, ChannelCustody, ChannelEnd, ChannelMode, ChannelOpenFailure, ChannelOutput,
    ChannelScope, ChannelScopeRef, ChannelSignalOutcome, IoRelease, KillScopesRequest, ProxyIo,
    ScopeKill, SpawnChannelRequest, SpawnedChannel,
};
use crate::error::RuntimeError;
use crate::pty::{PtyChild, PtySize};
use crate::{GuestIdentity, ProcessSignal};

use super::client::{BoundInstance, IncusClient, random_nonce};
use super::pty::IncusPtyChild;

pub(super) const CHANNEL_HELPER: &str = include_str!("channel-helper.py");
/// Bound of one kill-helper run (tombstone, kill, ≤ 5 s proof poll).
const KILL_HELPER_DEADLINE: Duration = Duration::from_secs(12);
/// Scopes per kill-helper run (its output stays below the capture cap).
const KILL_BATCH: usize = 8;
const KILL_OUTPUT_CAP: usize = 4096;
/// A natural end lets the host client exit on its own this long.
const FINISH_WAIT: Duration = Duration::from_millis(250);
/// A hangup gives the session this long before the host client is ended.
const HANGUP_WAIT: Duration = Duration::from_secs(5);
const REAP_BOUND: Duration = Duration::from_secs(5);
const UNBLOCK_BOUND: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(10);
const SIGNAL_DEADLINE: Duration = Duration::from_secs(10);

fn setup_failed(code: SandboxErrorCode) -> RuntimeError {
    RuntimeError::new(code, "channel setup failed")
}

/// Identity and launcher prefix: everything up to and including `launch`'s
/// `--`. The mode selects `-t` (pty) or `-T` (exec).
fn launcher_args(
    client: &IncusClient,
    bound: &BoundInstance,
    request: &SpawnChannelRequest,
    scope: &str,
) -> Result<Vec<String>, RuntimeError> {
    if client.exec_as_root {
        return Err(RuntimeError::new(
            SandboxErrorCode::UnsupportedCapability,
            "channels never run as guest root",
        ));
    }
    let name = bound.name();
    crate::validate_managed_instance_name(name)?;
    super::client::validate_incus_identifier(&client.project, "project")?;
    let mut identity = client.guest_exec_args(request.cwd.as_deref())?;
    // Only the fixed helper runs as guest root; it drops before the workload.
    identity[1] = "0".into();
    identity[3] = "0".into();
    let mut args = vec![
        "--project".to_string(),
        client.project.clone(),
        "exec".into(),
    ];
    args.extend(identity);
    match &request.mode {
        ChannelMode::Pty { term, .. } => {
            args.extend(["--env".into(), format!("TERM={term}"), "-t".into()]);
        }
        ChannelMode::Exec => args.push("-T".into()),
    }
    args.extend([name.to_string(), "--".into()]);
    args.extend(["python3", "-I", "-S", "-c", CHANNEL_HELPER].map(String::from));
    args.extend([
        "launch".to_string(),
        scope.to_string(),
        request.nonce.clone(),
        client.guest.guest_uid.to_string(),
        client.guest.guest_gid.to_string(),
        "--".into(),
    ]);
    Ok(args)
}

/// The wrapper argv: mode, login, the preamble budget and the env limits the
/// wrapper enforces on the preamble, then the workload argv.
fn wrap_args(request: &SpawnChannelRequest) -> Vec<String> {
    let mode = match request.mode {
        ChannelMode::Pty { .. } => "pty",
        ChannelMode::Exec => "exec",
    };
    let limits = sandbox_protocol::env_limits();
    let mut args: Vec<String> = [
        "python3",
        "-I",
        "-S",
        "-c",
        CHANNEL_HELPER,
        "wrap",
        "WSSP_PID",
    ]
    .map(String::from)
    .to_vec();
    args.extend([
        request.nonce.clone(),
        mode.to_string(),
        if request.login { "1" } else { "0" }.to_string(),
        CHANNEL_PREAMBLE_BUDGET.as_millis().to_string(),
        limits.max_entries.to_string(),
        limits.key_bytes.to_string(),
        limits.value_bytes.to_string(),
        limits.json_bytes.to_string(),
        "--".into(),
    ]);
    args.extend(request.argv.iter().flatten().cloned());
    args
}

fn channel_args(
    client: &IncusClient,
    bound: &BoundInstance,
    request: &SpawnChannelRequest,
    scope: &str,
) -> Result<Vec<String>, RuntimeError> {
    let mut args = launcher_args(client, bound, request, scope)?;
    args.extend(wrap_args(request));
    Ok(args)
}

/// Guest-scope kill authority of one channel.
#[derive(Clone)]
struct ScopeKiller {
    client: IncusClient,
    sandbox_id: String,
    template_fingerprint: String,
    unit: String,
}

impl ScopeKiller {
    fn kill(&self, forget: bool) -> ChannelScope {
        let request = KillScopesRequest {
            sandbox_id: self.sandbox_id.clone(),
            template_fingerprint: self.template_fingerprint.clone(),
            guest: self.client.guest.clone(),
            scopes: vec![ChannelScopeRef {
                unit: self.unit.clone(),
                forget,
            }],
        };
        let gone = kill_scopes(&self.client, &request).is_ok_and(|results| {
            results
                .iter()
                .any(|(unit, kill)| *unit == self.unit && *kill == ScopeKill::Gone)
        });
        if gone {
            ChannelScope::Killed
        } else {
            ChannelScope::Uncertain
        }
    }
}

/// Tombstone, kill and prove each scope gone (batched). A positively stopped
/// or absent instance is proof for every scope; a query error is not.
pub(super) fn kill_scopes(
    client: &IncusClient,
    request: &KillScopesRequest,
) -> Result<Vec<(String, ScopeKill)>, RuntimeError> {
    for scope in &request.scopes {
        crate::channel::validate_channel_scope_unit(&scope.unit)?;
    }
    let client = client.with_guest(&request.guest);
    let name = crate::resolve_managed_instance_name(&request.sandbox_id, None)?;
    let bound = match client.bind_instance(
        &name,
        &request.sandbox_id,
        &request.template_fingerprint,
        None,
    ) {
        Ok(bound) => bound,
        Err(error) if error.code == SandboxErrorCode::SandboxNotFound => {
            return Ok(gone_all(request));
        }
        Err(error) => return Err(error),
    };
    if bound.is_stopped() {
        return Ok(gone_all(request));
    }
    let mut results = Vec::new();
    for batch in request.scopes.chunks(KILL_BATCH) {
        let nonce = random_nonce()?;
        let mut argv: Vec<String> = ["python3", "-I", "-S", "-c", CHANNEL_HELPER, "kill"]
            .map(String::from)
            .to_vec();
        argv.push(nonce.clone());
        argv.extend(
            batch
                .iter()
                .map(|scope| format!("{}:{}", scope.unit, if scope.forget { 1 } else { 0 })),
        );
        let output = client
            .exec_root_helper_bounded_cap(&bound, &argv, KILL_HELPER_DEADLINE, KILL_OUTPUT_CAP)
            .map_err(crate::EffectError::into_error)?;
        let prefix = format!("WSSP_CHAN_KILL {nonce} ");
        for scope in batch {
            let verdict = output.stdout.lines().find_map(|line| {
                let rest = line.strip_prefix(&prefix)?;
                let (unit, verdict) = rest.split_once(' ')?;
                (unit == scope.unit).then_some(verdict)
            });
            let kill = match verdict {
                Some("gone") if output.exit_code == 0 => ScopeKill::Gone,
                _ => ScopeKill::Present,
            };
            results.push((scope.unit.clone(), kill));
        }
    }
    Ok(results)
}

fn gone_all(request: &KillScopesRequest) -> Vec<(String, ScopeKill)> {
    request
        .scopes
        .iter()
        .map(|scope| (scope.unit.clone(), ScopeKill::Gone))
        .collect()
}

pub(super) fn spawn(
    client: &IncusClient,
    request: &SpawnChannelRequest,
) -> Result<SpawnedChannel, ChannelOpenFailure> {
    request.validate()?;
    let scope = request.scope_unit()?;
    let client = client.with_guest(&request.guest);
    let name = crate::resolve_managed_instance_name(&request.sandbox_id, None)?;
    let bound = client.bind_instance(
        &name,
        &request.sandbox_id,
        &request.template_fingerprint,
        None,
    )?;
    if !bound.is_running() {
        return Err(setup_failed(SandboxErrorCode::SandboxNotRunning).into());
    }
    let args = channel_args(&client, &bound, request, &scope)?;
    let killer = ScopeKiller {
        client: client.clone(),
        sandbox_id: request.sandbox_id.clone(),
        template_fingerprint: request.template_fingerprint.clone(),
        unit: scope,
    };
    match &request.mode {
        ChannelMode::Exec => spawn_exec(&client, bound, request, args, killer),
        ChannelMode::Pty { size, .. } => spawn_pty(&client, &bound, *size, args, killer),
    }
}

/// A spawned process whose IO could not be set up: kill-closed by the caller.
fn after_spawn(custody: Box<dyn ChannelCustody>) -> ChannelOpenFailure {
    ChannelOpenFailure {
        error: setup_failed(SandboxErrorCode::Internal),
        custody: Some(custody),
    }
}

// --------------------------------------------------------------- exec ----

fn spawn_exec(
    client: &IncusClient,
    bound: BoundInstance,
    request: &SpawnChannelRequest,
    args: Vec<String>,
    killer: ScopeKiller,
) -> Result<SpawnedChannel, ChannelOpenFailure> {
    let mut command =
        crate::host_child::command(&client.binary, crate::host_child::Environment::Incus);
    command.args(&args);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = pre::phase(
        |before| before.issue(|| client.spawn_guest(&bound, &mut command)),
        Ok,
    )
    .map_err(crate::EffectError::into_error)?;
    let pid = child.id();
    let stdin = child.stdin.take();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let mut custody = ExecCustody {
        client: client.clone(),
        bound,
        guest: request.guest.clone(),
        nonce: request.nonce.clone(),
        child: Some(child),
        pid,
        killer,
        release: None,
        closed: false,
    };
    let mut io = ProxyIo::new(Box::new(|| true), None);
    let (Some(stdin), Some(stdout), Some(stderr)) = (stdin, stdout, stderr) else {
        return Err(after_spawn(Box::new(custody)));
    };
    let wired = (|| -> std::io::Result<()> {
        io.add_reader(
            ChannelOutput::Stdout,
            Box::new(stdout),
            CHANNEL_EXEC_READ_BYTES,
        )?;
        io.add_reader(
            ChannelOutput::Stderr,
            Box::new(stderr),
            CHANNEL_EXEC_READ_BYTES,
        )?;
        io.set_writer(Box::new(stdin))
    })();
    custody.release = Some(io.take_release());
    if wired.is_err() {
        return Err(after_spawn(Box::new(custody)));
    }
    Ok(SpawnedChannel {
        io: Box::new(io),
        custody: Box::new(custody),
    })
}

struct ExecCustody {
    client: IncusClient,
    bound: BoundInstance,
    guest: GuestIdentity,
    nonce: String,
    child: Option<Child>,
    pid: u32,
    killer: ScopeKiller,
    /// Dropped to let stdin close (after a kill: only once the scope is gone).
    release: Option<IoRelease>,
    closed: bool,
}

impl ExecCustody {
    fn poll_child(&mut self) {
        if let Some(child) = &mut self.child
            && let Ok(Some(_)) = child.try_wait()
        {
            self.child = None;
        }
    }

    fn wait_exit(&mut self, bound: Duration) {
        let deadline = Instant::now() + bound;
        loop {
            self.poll_child();
            if self.child.is_none() || Instant::now() >= deadline {
                return;
            }
            thread::sleep(POLL);
        }
    }

    fn helper_signal(&self, birth: &ChannelBirth, signal: ProcessSignal) -> ChannelSignalOutcome {
        let Ok(helper_nonce) = random_nonce() else {
            return ChannelSignalOutcome::Unsupported;
        };
        let client = self.client.with_guest(&self.guest);
        let argv = [
            "/bin/sh".to_string(),
            "-c".to_string(),
            super::exec::SIGNAL_HELPER_LAUNCH.to_string(),
            "wssp-signal".to_string(),
            super::exec::SIGNAL_HELPER.to_string(),
            "wssp-signal".to_string(),
            helper_nonce.clone(),
            birth.pid.to_string(),
            birth.boot_id.clone(),
            birth.start_ticks.to_string(),
            birth.uid.to_string(),
            self.nonce.clone(),
            signal.as_kill_arg().to_string(),
        ];
        let Ok(output) = client
            .exec_argv_effect_bounded(&self.bound, &argv, SIGNAL_DEADLINE)
            .map_err(crate::EffectError::into_error)
        else {
            return ChannelSignalOutcome::Unsupported;
        };
        let prefix = format!("WSSP_SIGNAL {helper_nonce} ");
        let verdicts: Vec<&str> = output
            .stderr
            .lines()
            .filter_map(|line| line.strip_prefix(&prefix))
            .collect();
        match verdicts.as_slice() {
            ["verified", "delivered"] => ChannelSignalOutcome::Delivered,
            ["verified", "exited"] | ["gone"] => ChannelSignalOutcome::Ended,
            _ => ChannelSignalOutcome::Unsupported,
        }
    }
}

impl ChannelCustody for ExecCustody {
    fn signal(&mut self, birth: &ChannelBirth, signal: ProcessSignal) -> ChannelSignalOutcome {
        if self.closed || signal.is_kill() {
            return ChannelSignalOutcome::Ended;
        }
        self.helper_signal(birth, signal)
    }

    fn close(&mut self, how: ChannelClose) -> ChannelEnd {
        self.closed = true;
        let scope = match how {
            ChannelClose::Finish => {
                self.release = None;
                self.wait_exit(FINISH_WAIT);
                ChannelScope::Released
            }
            ChannelClose::Hangup(birth) => {
                // sshd: the session's stdin ends, then it is hung up.
                self.release = None;
                if let Some(birth) = birth {
                    let _ = self.helper_signal(&birth, ProcessSignal::Sighup);
                }
                self.wait_exit(HANGUP_WAIT);
                ChannelScope::Released
            }
            ChannelClose::Kill { forget } => self.killer.kill(forget),
        };
        if scope == ChannelScope::Uncertain {
            // The workload may still run: neither its stdin EOF nor the end
            // of its host client may reach it before a later proof.
            return ChannelEnd {
                reaped: false,
                scope,
            };
        }
        let reaped = self.terminate();
        ChannelEnd { reaped, scope }
    }

    fn terminate(&mut self) -> bool {
        self.poll_child();
        if self.child.is_some() {
            let _ = IncusClient::kill_process_group(self.pid);
            self.wait_exit(REAP_BOUND);
        }
        // Stdin closes only now: after a kill, never ahead of it.
        self.release = None;
        self.child.is_none()
    }

    fn reap_confirmed(&mut self) -> bool {
        self.poll_child();
        self.child.is_none()
    }
}

impl Drop for ExecCustody {
    /// Backstop: an abandoned channel is never left running.
    fn drop(&mut self) {
        if !self.closed {
            self.close(ChannelClose::Kill { forget: false });
        }
    }
}

// ---------------------------------------------------------------- pty ----

fn spawn_pty(
    client: &IncusClient,
    bound: &BoundInstance,
    size: PtySize,
    args: Vec<String>,
    killer: ScopeKiller,
) -> Result<SpawnedChannel, ChannelOpenFailure> {
    let pair = portable_pty::native_pty_system()
        .openpty(super::pty::native_size(size))
        .map_err(|_| setup_failed(SandboxErrorCode::Internal))?;
    let portable_pty::PtyPair { slave, master } = pair;
    let tty = master.tty_name();
    // `slave` moves into (and is dropped with) the admission closure, so the
    // daemon holds no slave descriptor: master reads see EIO once the client
    // and its session are gone.
    let child = super::pty::spawn_admitted(client, bound, slave, &args)?;
    let mut custody = PtyCustody {
        child: IncusPtyChild::for_channel(child, tty),
        killer,
        release: None,
        closed: false,
    };
    let reader = master.try_clone_reader();
    let writer = master.take_writer();
    let (Ok(reader), Ok(writer)) = (reader, writer) else {
        return Err(after_spawn(Box::new(custody)));
    };
    let master = Arc::new(Mutex::new(master));
    let raw = master.clone();
    let resize = master;
    let mut io = ProxyIo::new(
        Box::new(move || {
            let master = raw.lock().unwrap_or_else(|e| e.into_inner());
            super::pty::env::raw(&**master)
        }),
        Some(Box::new(move |size: PtySize| {
            let master = resize.lock().unwrap_or_else(|e| e.into_inner());
            master.resize(super::pty::native_size(size)).map_err(|_| {
                RuntimeError::new(SandboxErrorCode::Internal, "terminal resize failed")
            })
        })),
    );
    let wired = (|| -> std::io::Result<()> {
        io.add_reader(
            ChannelOutput::Stdout,
            Box::new(reader) as Box<dyn Read + Send>,
            CHANNEL_PTY_READ_BYTES,
        )?;
        io.set_writer(writer)
    })();
    custody.release = Some(io.take_release());
    if wired.is_err() {
        return Err(after_spawn(Box::new(custody)));
    }
    Ok(SpawnedChannel {
        io: Box::new(io),
        custody: Box::new(custody),
    })
}

struct PtyCustody {
    child: IncusPtyChild,
    killer: ScopeKiller,
    /// Dropped once the client is gone (`portable_pty` writes an EOT when its
    /// writer drops; it must never reach a live session).
    release: Option<IoRelease>,
    closed: bool,
}

impl ChannelCustody for PtyCustody {
    fn signal(&mut self, _birth: &ChannelBirth, _signal: ProcessSignal) -> ChannelSignalOutcome {
        // Control keys travel as bytes on a tty.
        ChannelSignalOutcome::Unsupported
    }

    fn close(&mut self, how: ChannelClose) -> ChannelEnd {
        self.closed = true;
        let scope = match how {
            ChannelClose::Finish => {
                let deadline = Instant::now() + FINISH_WAIT;
                while self.child.try_reap().is_none() && Instant::now() < deadline {
                    thread::sleep(POLL);
                }
                ChannelScope::Released
            }
            // Hang up: SIGHUP to the client, then its process group; the
            // agent hangs the guest tty up.
            ChannelClose::Hangup(_) => ChannelScope::Released,
            ChannelClose::Kill { forget } => self.killer.kill(forget),
        };
        if scope == ChannelScope::Uncertain {
            // The workload may still run: no hangup and no EOT before a
            // later proof.
            return ChannelEnd {
                reaped: false,
                scope,
            };
        }
        let reaped = self.terminate();
        ChannelEnd { reaped, scope }
    }

    fn terminate(&mut self) -> bool {
        // The client (and with it the session) is gone first; only then may
        // stdin close (portable_pty writes an EOT as its writer drops).
        let reaped = self.child.terminate_and_reap().is_some();
        if let Some(mut release) = self.release.take() {
            let done = release.writer_done.clone();
            let progress = release.writer.clone();
            release.release();
            // A write already blocked on a full tty input queue is not woken
            // by the hangup: drain the queue until every chunk handed over is
            // finished (or the writer thread is done). A write that starts
            // after the hangup (more input, the closing EOT) fails at once,
            // and while the owner still holds the IO nothing is in flight.
            self.child.unblock_writer(
                &move || done.load(std::sync::atomic::Ordering::Acquire) || progress.idle(),
                Instant::now() + UNBLOCK_BOUND,
            );
        }
        if reaped {
            self.child.release();
        }
        reaped
    }

    fn reap_confirmed(&mut self) -> bool {
        self.child.try_reap().is_some()
    }
}

impl Drop for PtyCustody {
    /// Backstop: an abandoned channel is never left running.
    fn drop(&mut self) {
        if !self.closed {
            self.close(ChannelClose::Kill { forget: false });
        }
    }
}
