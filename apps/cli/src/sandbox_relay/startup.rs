//! Template start/ready commands (template builds B9).
//!
//! After a `sandbox.create` or `sandbox.reconnect` that carries `startup`
//! has booted the VM, and before READY is reported, the daemon:
//!
//! 1. launches the start command in the background as the guest user (never
//!    root; D1), detached into its own session with stdio on a guest log
//!    file. Under `flock` a second launch while the first still runs is a
//!    no-op, so a reconnect of a VM that kept running does not start it twice;
//! 2. polls the ready command (same user, cwd and environment) until it exits
//!    0, or fails with `startup_timeout` once the budget is spent.
//!
//! Each guest command is an ordinary user command with its own derived
//! operation id (per launch attempt). A failure is reported on the launch as
//! an uncertain outcome with a typed code: the VM exists, so the server
//! queues its cleanup.

use std::time::{Duration, Instant};

use sandbox_protocol::{DispatchStartupV11, OperationDispatch, SandboxErrorCode};
use sandbox_runtime::{RunCommandRequest, RuntimeError, SandboxRuntime};

/// Guest file that receives the start command's stdout and stderr.
pub(super) const START_LOG: &str = "/tmp/wssp-start.log";
/// Lock held by a running start command (released when it exits or the VM
/// reboots).
const START_LOCK: &str = "/tmp/wssp-start.lock";
const LAUNCH_TIMEOUT_MS: u64 = 30_000;
const READY_POLL_TIMEOUT_MS: u64 = 10_000;
const READY_POLL_INTERVAL: Duration = Duration::from_millis(500);

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// The guest-user script that starts `command` in the background and returns.
pub(super) fn launch_script(command: &str) -> String {
    let inner = quote(command);
    let detached =
        |prefix: &str| format!("setsid {prefix}/bin/sh -c {inner} </dev/null >>{START_LOG} 2>&1 &");
    format!(
        "if command -v flock >/dev/null 2>&1; then\n  {}\nelse\n  {}\nfi\n",
        detached(&format!("flock -n {START_LOCK} ")),
        detached(""),
    )
}

fn failure(code: SandboxErrorCode, message: &str) -> RuntimeError {
    RuntimeError::new(code, message)
}

/// Run `startup` for the launch `d`. `env` is the sandbox's execution
/// environment (template defaults and private config), as for commands.
pub(super) fn run(
    runtime: &dyn SandboxRuntime,
    d: &OperationDispatch,
    instance_name: &str,
    env: &[(String, String)],
    startup: &DispatchStartupV11,
) -> Result<(), RuntimeError> {
    if !startup.is_valid() {
        return Err(failure(
            SandboxErrorCode::ProtocolError,
            "invalid startup commands",
        ));
    }
    let request = |suffix: &str, script: String, timeout_ms: u64| RunCommandRequest {
        template_fingerprint: d.incus_fingerprint.clone().unwrap_or_default(),
        generation: d.generation,
        attempt: d.attempt,
        sandbox_id: d.sandbox_id.clone(),
        instance_name: instance_name.to_string(),
        // Per attempt: a retried launch runs its startup again.
        operation_id: format!("{}_{}_{suffix}", d.operation_id, d.attempt),
        idempotency_key: format!("{}:{}:{suffix}", d.idempotency_key, d.attempt),
        argv: Vec::new(),
        script: Some(script),
        cwd: startup.cwd.clone(),
        timeout_ms: Some(timeout_ms),
        env: env.to_vec(),
        stdin: None,
        guest: super::supervisor::guest_from_dispatch(d),
        build_step: None,
    };
    let cancelled = |error: &RuntimeError| error.code == SandboxErrorCode::Cancelled;

    let launched = runtime.run_command(&request(
        "startup",
        launch_script(&startup.command),
        LAUNCH_TIMEOUT_MS,
    ));
    match launched {
        Ok(done) if done.command.exit_code == Some(0) => {}
        Ok(_) => {
            return Err(failure(
                SandboxErrorCode::StartupFailed,
                "start command could not be launched",
            ));
        }
        Err(error) => {
            let error = error.into_error();
            return Err(if cancelled(&error) {
                error
            } else {
                failure(
                    SandboxErrorCode::StartupFailed,
                    "start command could not be launched",
                )
            });
        }
    }

    let (Some(ready), Some(budget)) = (startup.ready.as_ref(), startup.ready_budget_ms()) else {
        return Ok(());
    };
    let deadline = Instant::now() + Duration::from_millis(u64::from(budget));
    for poll in 0u32.. {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let timeout = (remaining.as_millis() as u64).clamp(1, READY_POLL_TIMEOUT_MS);
        match runtime.run_command(&request(&format!("ready_{poll}"), ready.clone(), timeout)) {
            Ok(done) if done.command.exit_code == Some(0) => return Ok(()),
            Ok(_) => {}
            Err(error) => {
                let error = error.into_error();
                if cancelled(&error)
                    || matches!(
                        error.code,
                        SandboxErrorCode::SandboxNotRunning | SandboxErrorCode::SandboxNotFound
                    )
                {
                    return Err(if cancelled(&error) {
                        error
                    } else {
                        failure(
                            SandboxErrorCode::StartupFailed,
                            "sandbox stopped during startup",
                        )
                    });
                }
            }
        }
        let pause = READY_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now()));
        std::thread::sleep(pause);
    }
    Err(failure(
        SandboxErrorCode::StartupTimeout,
        "ready command did not succeed in time",
    ))
}

#[cfg(test)]
#[path = "startup_tests.rs"]
mod tests;
