//! Host PTY around exactly one child process (C51):
//! `incus --project <p> exec <identity flags> -t <wssp-sbx-<id>> -- <declared-shell>`.
//!
//! - The PTY is allocated only for that child; no host shell is ever run.
//!   The program is the configured Incus client and argv is built
//!   structurally (no shell interpolation). The shell is ONE argv element
//!   after `--`, so a hostile value can never become an Incus flag.
//! - The instance is derived from the sandbox id and positively bound
//!   against host metadata before spawn (`IncusClient::bind_instance`).
//! - Guest UID/GID/cwd/HOME/SHELL match the exec template contract
//!   (`IncusClient::guest_exec_args`). The Incus client process gets a
//!   scrubbed environment, and the guest receives only HOME/SHELL/TERM: no
//!   control-plane credential reaches the guest.
//! - Spawn crosses the shared guest-spawn admission section (binding
//!   recheck, runtime permit, policy-refusal fence).
//! - Resize is TIOCSWINSZ on the PTY master; the kernel signals SIGWINCH to
//!   the `incus exec` client, which forwards the size to the guest.

#[path = "pty_env.rs"]
pub(super) mod env;

use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use sandbox_protocol::SandboxErrorCode;

use crate::before_issue::incus as pre;
use crate::error::RuntimeError;
use crate::pty::{OpenPtyRequest, PtyChild, PtyParts, PtySession, PtySize};

use super::client::{BoundInstance, IncusClient};

pub(crate) use crate::host_child::PTY_TERM;

const REAP_BOUND: Duration = Duration::from_secs(5);
/// SIGHUP grace for the `incus exec` client before the group is killed
/// (the same 5 x 50 ms portable-pty grants).
const HANGUP_GRACE: Duration = Duration::from_millis(250);
const POLL: Duration = Duration::from_millis(10);

/// `O_NOCTTY | O_NONBLOCK` from libc (C55, C51-TB-2): the values differ per
/// architecture (alpha, mips, parisc, sparc), so they are never hard-coded and
/// the input-queue drain runs on every Linux target.
const SLAVE_DRAIN_FLAGS: i32 = libc::O_NOCTTY | libc::O_NONBLOCK;

/// The exact argv (after the program) for the PTY child. Identity flags
/// precede `-t`, so the trace ends with exactly `-t <instance> -- <shell>`.
pub(crate) fn pty_exec_args(
    client: &IncusClient,
    bound: &BoundInstance,
    cwd: Option<&str>,
) -> Result<Vec<String>, RuntimeError> {
    let name = bound.name();
    crate::validate_managed_instance_name(name)?;
    super::client::validate_incus_identifier(&client.project, "project")?;
    // Validates the guest identity (absolute, component-clean shell/home)
    // and the shell's cwd (the revision's default cwd, else the home).
    let identity = client.guest_exec_args(cwd)?;
    let shell = &client.guest.guest_shell;
    if !shell.starts_with('/') {
        return Err(RuntimeError::new(
            SandboxErrorCode::ProtocolError,
            "declared guest shell must be an absolute path",
        ));
    }
    let mut args = vec![
        "--project".to_string(),
        client.project.clone(),
        "exec".into(),
    ];
    args.extend(identity);
    args.extend([
        "--env".into(),
        format!("TERM={PTY_TERM}"),
        "-t".into(),
        name.to_string(),
        "--".into(),
        shell.clone(),
    ]);
    Ok(args)
}

pub(super) fn native_size(size: PtySize) -> portable_pty::PtySize {
    portable_pty::PtySize {
        rows: size.rows(),
        cols: size.cols(),
        pixel_width: 0,
        pixel_height: 0,
    }
}

fn internal(what: &str, err: impl std::fmt::Display) -> RuntimeError {
    RuntimeError::new(SandboxErrorCode::Internal, format!("{what}: {err}"))
}

/// Open the PTY child for an already validated request on a positively
/// bound, running instance. `client` carries the request's guest identity.
pub(super) fn open(
    client: &IncusClient,
    bound: &BoundInstance,
    request: &OpenPtyRequest,
    reservation: crate::pty::PtyReservation,
    lifetime: Duration,
) -> Result<PtySession, crate::PtyOpenFailure> {
    let args = pty_exec_args(client, bound, request.cwd.as_deref())?;
    let pair = portable_pty::native_pty_system()
        .openpty(native_size(request.size))
        .map_err(|e| internal("terminal allocation failed", e))?;
    let portable_pty::PtyPair { slave, master } = pair;
    let child = spawn_admitted(client, bound, slave, &args)?;
    supervise_child(master, child, reservation, request.size, lifetime)
}

/// Shared process-only controller for guest-client and local host shells.
pub(crate) fn supervise_child(
    master: Box<dyn portable_pty::MasterPty + Send>,
    child: Box<dyn portable_pty::Child + Send + Sync>,
    reservation: crate::pty::PtyReservation,
    size: PtySize,
    lifetime: Duration,
) -> Result<PtySession, crate::PtyOpenFailure> {
    // `slave` was moved into (and dropped with) the admission closure, so
    // the parent holds no slave descriptor: master reads see EIO once the
    // child and its session are gone.
    let tty = master.tty_name();
    let mut process = IncusPtyChild {
        child,
        master: None,
        tty,
        reaped: None,
        group_killed: false,
    };
    let io = master
        .try_clone_reader()
        .and_then(|reader| Ok((reader, master.take_writer()?)));
    process.master = Some(master);
    let (reader, writer) = match io {
        Ok(io) => io,
        Err(_) => {
            return Err(crate::PtyOpenFailure::after_spawn(
                reservation,
                size,
                Box::new(process),
            ));
        }
    };
    PtySession::start(
        reservation,
        size,
        lifetime,
        PtyParts {
            setup_failed: None,
            child: Box::new(process),
            reader,
            writer,
        },
    )
}

/// Both PTY paths cross exactly the same guest-spawn admission boundary.
pub(super) fn spawn_admitted(
    client: &IncusClient,
    bound: &BoundInstance,
    slave: Box<dyn portable_pty::SlavePty + Send>,
    args: &[String],
) -> Result<Box<dyn portable_pty::Child + Send + Sync>, RuntimeError> {
    let mut builder = crate::host_child::incus_pty_command(&client.binary);
    builder.args(args);
    builder.cwd("/");
    let mut view =
        crate::host_child::command(&client.binary, crate::host_child::Environment::Incus);
    view.args(args);
    client
        .admit_guest_spawn(bound, &mut view, move |before, _| {
            pre::spawn_pty(before, &*slave, builder)
        })
        .map_err(crate::EffectError::into_error)
}

/// The empty-map branch above retains the original flags, program and streams.
pub(super) fn open_with_env(
    client: &IncusClient,
    request: &OpenPtyRequest,
    reservation: crate::pty::PtyReservation,
    lifetime: Duration,
) -> Result<PtySession, crate::PtyOpenFailure> {
    let frame = super::env_frame::encode(&request.env)?.ok_or_else(|| {
        RuntimeError::new(SandboxErrorCode::ProtocolError, "terminal setup failed")
    })?;
    let frame = env::envelope(&frame)?;
    let nonce = super::client::random_nonce()?;
    let permit = std::sync::Arc::new(match client.cancelled.clone() {
        Some(parent) => crate::RuntimePermit::child(parent, env::OVERALL.min(lifetime)),
        None => crate::RuntimePermit::with_timeout(env::OVERALL.min(lifetime)),
    });
    let mut scoped = client.clone();
    scoped.cancelled = Some(permit.clone());
    let pair = portable_pty::native_pty_system()
        .openpty(native_size(request.size))
        .map_err(|_| RuntimeError::new(SandboxErrorCode::Internal, "terminal setup failed"))?;
    let portable_pty::PtyPair { slave, master } = pair;
    let tty = master.tty_name();
    let pending = env::Pending::start(
        master,
        reservation,
        request,
        lifetime,
        permit,
        nonce.clone(),
        frame,
    )?;
    let args = (|| {
        let name = crate::resolve_managed_instance_name(&request.sandbox_id, None)?;
        let bound = scoped.bind_instance(
            &name,
            &request.sandbox_id,
            &request.template_fingerprint,
            None,
        )?;
        if !bound.is_running() {
            return Err(RuntimeError::new(
                SandboxErrorCode::SandboxNotRunning,
                "terminal setup failed",
            ));
        }
        let mut args = pty_exec_args(&scoped, &bound, request.cwd.as_deref())?;
        args.pop();
        args.extend(scoped.pty_env_wrapper(&bound, &nonce, env::OVERALL.min(lifetime))?);
        Ok::<_, RuntimeError>((bound, args))
    })();
    let (bound, args) = match args {
        Ok(args) => args,
        Err(_) => {
            drop(slave);
            return Err(pending.abort());
        }
    };
    let child = spawn_admitted(&scoped, &bound, slave, &args);
    let child = match child {
        Ok(child) => child,
        Err(_) => return Err(pending.abort()),
    };
    pending.attach(IncusPtyChild {
        child,
        master: None,
        tty,
        reaped: None,
        group_killed: false,
    });
    let opened = pending.finish()?;
    PtySession::start(
        opened.reservation,
        request.size,
        opened.lifetime,
        opened.parts,
    )
}

pub(super) struct IncusPtyChild {
    child: Box<dyn portable_pty::Child + Send + Sync>,
    master: Option<Box<dyn portable_pty::MasterPty + Send>>,
    tty: Option<PathBuf>,
    /// Exit code once reaped; a reaped child is never signalled again.
    reaped: Option<Option<i32>>,
    /// The child's process group was SIGKILLed while the leader was still
    /// unreaped (so the group id could not have been recycled).
    group_killed: bool,
}

/// What `/proc` says about an unreaped leader, WITHOUT reaping it.
enum Leader {
    Running,
    /// Exited (zombie): its PID, and so its process-group id, stay pinned
    /// until we reap it.
    Exited,
    /// `/proc` unreadable: no pre-reap evidence either way.
    Unknown,
}

fn leader_state(pid: u32) -> Leader {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return Leader::Unknown;
    };
    // `pid (comm) S ...`: comm may contain ')', so split at the LAST one.
    match stat
        .rsplit_once(')')
        .and_then(|(_, rest)| rest.trim_start().chars().next())
    {
        Some('Z' | 'X') => Leader::Exited,
        Some(_) => Leader::Running,
        None => Leader::Unknown,
    }
}

/// Whether `pid` leads its own process group (`pgid == pid`). Unreadable
/// `/proc` keeps the C51 behaviour (the spawn made it a setsid leader).
fn leads_own_group(pid: u32, group: Option<u32>) -> bool {
    group.is_none_or(|group| group == pid)
}

fn exit_code(status: &portable_pty::ExitStatus) -> Option<i32> {
    if status.signal().is_some() {
        None
    } else {
        i32::try_from(status.exit_code()).ok()
    }
}

impl IncusPtyChild {
    /// A channel PTY's client (wssp-ssh): the channel's IO owner holds the
    /// master, so this handle never resizes.
    pub(super) fn for_channel(
        child: Box<dyn portable_pty::Child + Send + Sync>,
        tty: Option<PathBuf>,
    ) -> Self {
        Self {
            child,
            master: None,
            tty,
            reaped: None,
            group_killed: false,
        }
    }

    /// SIGKILL the child's whole process group (the child is a `setsid`
    /// leader, so pgid == pid), reusing the exec path's group kill. Only
    /// called while the leader is unreaped, so the group id is still pinned
    /// to this session: descendants that ignored SIGHUP and still hold the
    /// tty die with it instead of keeping the reader and master alive.
    fn kill_group(&mut self) {
        if self.group_killed || self.reaped.is_some() {
            return;
        }
        self.group_killed = true;
        // Scoping (C55): only a group this child leads. A leader whose
        // `/proc` stat names another group (it never became a setsid leader)
        // gets the leader-only kill below, never a kill of someone else's
        // group; `kill_process_group` also refuses the daemon's own group.
        let killed = self.child.process_id().is_some_and(|pid| {
            leads_own_group(pid, super::client::process_group_of(&pid.to_string()))
                && IncusClient::kill_process_group(pid).is_ok()
        });
        if !killed {
            // No group kill available: at least kill the leader (SIGHUP,
            // grace, SIGKILL on the pid; portable-pty semantics).
            let _ = self.child.kill();
        }
    }
}

impl PtyChild for IncusPtyChild {
    fn try_reap(&mut self) -> Option<Option<i32>> {
        if let Some(code) = self.reaped {
            return Some(code);
        }
        // Never reap a leader before its group is killed: after the reap the
        // group id may be recycled, and descendants holding the tty would
        // outlive the session.
        if let Some(pid) = self.child.process_id() {
            match leader_state(pid) {
                Leader::Running => return None,
                Leader::Exited => self.kill_group(),
                Leader::Unknown => {}
            }
        }
        match self.child.try_wait() {
            Ok(Some(status)) => {
                let code = exit_code(&status);
                self.reaped = Some(code);
                Some(code)
            }
            // An unreadable status is not exit evidence: keep supervising;
            // close and expiry still terminate and reap.
            Ok(None) | Err(_) => None,
        }
    }

    fn terminate_and_reap(&mut self) -> Option<Option<i32>> {
        if let Some(code) = self.try_reap() {
            return Some(code);
        }
        // SIGHUP the leader only (no reap: the killer handle just signals),
        // a short grace, then SIGKILL the whole process group. The leader is
        // unreaped throughout, so neither its PID nor its group id can have
        // been reused.
        let _ = self.child.clone_killer().kill();
        if let Some(pid) = self.child.process_id() {
            let grace = Instant::now() + HANGUP_GRACE;
            while matches!(leader_state(pid), Leader::Running) && Instant::now() < grace {
                std::thread::sleep(POLL);
            }
        }
        self.kill_group();
        let deadline = Instant::now() + REAP_BOUND;
        while Instant::now() < deadline {
            if let Some(code) = self.try_reap() {
                return Some(code);
            }
            std::thread::sleep(POLL);
        }
        // Reap uncertain (e.g. uninterruptible sleep): reported as
        // `Closed { reaped: false }`, never as a confirmed reap.
        None
    }

    fn resize(&mut self, size: PtySize) -> Result<(), RuntimeError> {
        let master = self.master.as_ref().ok_or_else(|| {
            RuntimeError::new(
                SandboxErrorCode::StateConflict,
                "terminal session is closed",
            )
        })?;
        master
            .resize(native_size(size))
            .map_err(|e| internal("terminal resize failed", e))
    }

    /// A child that stopped reading leaves the writer blocked on a full tty
    /// input queue forever (hangup does not wake it). Drain that queue from
    /// a non-controlling, non-blocking slave descriptor until the writer has
    /// dropped its master handle, so no descriptor or thread leaks.
    fn unblock_writer(&mut self, writer_done: &dyn Fn() -> bool, deadline: Instant) {
        let Some(tty) = self.tty.as_ref() else {
            return;
        };
        if writer_done() || !tty.starts_with("/dev/pts/") {
            return;
        }
        let Ok(mut slave) = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(SLAVE_DRAIN_FLAGS)
            .open(tty)
        else {
            return;
        };
        let mut buf = [0u8; 4096];
        while !writer_done() && Instant::now() < deadline {
            while matches!(slave.read(&mut buf), Ok(n) if n > 0) {}
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    fn release(&mut self) {
        self.master = None;
    }
}

impl Drop for IncusPtyChild {
    /// Backstop: no path may drop an unreaped child (no zombies).
    fn drop(&mut self) {
        if self.reaped.is_none() {
            self.terminate_and_reap();
        }
    }
}

#[cfg(test)]
mod scoping_tests {
    use super::leads_own_group;

    /// C55 kill scoping: the PTY's group kill only targets a group the child
    /// leads; a child inside someone else's group is killed alone.
    #[test]
    fn c55_pty_group_kill_targets_only_a_group_the_child_leads() {
        assert!(leads_own_group(4242, Some(4242)));
        assert!(!leads_own_group(4242, Some(1)));
        assert!(!leads_own_group(4242, Some(std::process::id())));
        // `/proc` unreadable: the spawn made the child a setsid leader (C51).
        assert!(leads_own_group(4242, None));
    }
}
