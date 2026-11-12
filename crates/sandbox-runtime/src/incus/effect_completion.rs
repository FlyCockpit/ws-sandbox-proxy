//! Single inventory of Incus effect adapters and how terminal outcomes are proven.
//!
//! C09-2: mutating effects need guest-authored completion records or host inventory
//! proof; read-only adapters may fail on any error; inconclusive transport ⇒ UNKNOWN.

use crate::effect::PositiveEvidence;
use sandbox_protocol::{SandboxErrorCode, SandboxLifecycleState};

use crate::effect::{PostIssueError, PostIssueOutcome};
use crate::error::RuntimeError;

use super::client::{BoundInstance, GuestStatus, IncusCommandOutput};

pub(super) enum FileStatus {
    Ok,
    Failed(RuntimeError),
}

/// One exact, nonce-bound closed record. Extra diagnostics, duplicate records,
/// signal exits and unknown effect spellings cannot mint completion evidence.
pub(super) fn file_status(nonce: &str, out: &IncusCommandOutput) -> Option<FileStatus> {
    let status = out
        .stderr
        .strip_prefix(&format!("WSSP_STATUS {nonce} "))?
        .strip_suffix('\n')?;
    if status == "ok" && out.exit_code == 0 {
        return Some(FileStatus::Ok);
    }
    if out.exit_code <= 0 {
        return None;
    }
    let (code, effect) = status.split_once(' ')?;
    let code: SandboxErrorCode =
        serde_json::from_value(serde_json::Value::String(code.into())).ok()?;
    if !code.as_str().starts_with("fs_")
        && !matches!(
            code,
            SandboxErrorCode::Cancelled
                | SandboxErrorCode::PathRefused
                | SandboxErrorCode::ProtocolError
                | SandboxErrorCode::UnknownOutcome
        )
    {
        return None;
    }
    let effect = match effect {
        "none" => sandbox_protocol::results::FailureEffect::None,
        "partial" => sandbox_protocol::results::FailureEffect::Partial,
        "unknown" => sandbox_protocol::results::FailureEffect::Unknown,
        _ => return None,
    };
    if code == SandboxErrorCode::UnknownOutcome
        && effect != sandbox_protocol::results::FailureEffect::Unknown
    {
        return None;
    }
    Some(FileStatus::Failed(
        crate::metadata::fs_error(code).filesystem(effect),
    ))
}

/// Only this parser-backed branch can report a completed guest failure.
pub(super) fn helper_outcome(
    nonce: &str,
    out: &IncusCommandOutput,
    _action: &str,
    _path: &str,
) -> PostIssueOutcome<()> {
    match file_status(nonce, out) {
        Some(FileStatus::Ok) => Ok(completed(())),
        Some(FileStatus::Failed(error))
            if error
                .failure()
                .is_some_and(|f| f.effect != sandbox_protocol::results::FailureEffect::Unknown) =>
        {
            Err(GuestFailure::completed(error))
        }
        Some(FileStatus::Failed(error)) => Err(error.into()),
        None => Err(PostIssueError::from(
            RuntimeError::new(
                SandboxErrorCode::UnknownOutcome,
                "guest helper has no completion record",
            )
            .filesystem(sandbox_protocol::results::FailureEffect::Unknown),
        )),
    }
}

/// B2-C-1: the guest confirmed a host-refused fence (`cancelled <effect>`).
/// The refusal is host-authored runtime work preemption with the confirmed
/// effect; it keeps the retryable preemption code, not `cancelled`.
pub(super) fn preempted_refusal(nonce: &str, out: &IncusCommandOutput) -> Option<PostIssueError> {
    let Some(FileStatus::Failed(error)) = file_status(nonce, out) else {
        return None;
    };
    let effect = error.failure()?.effect.clone();
    if error.code != SandboxErrorCode::Cancelled
        || effect == sandbox_protocol::results::FailureEffect::Unknown
    {
        return None;
    }
    Some(GuestFailure::completed(
        RuntimeError::new(SandboxErrorCode::UnknownOutcome, "runtime work preempted")
            .filesystem(effect),
    ))
}

/// Crash recovery of one file-put attempt (C28). `committed` is positive only
/// because the destination hashed to the requested bytes; `not_committed` is a
/// guest-authored record that the attempt's staging file existed and was
/// removed, so its rename can no longer happen.
pub(super) fn recovery_outcome(
    token: &str,
    out: &IncusCommandOutput,
    path: &str,
) -> PostIssueOutcome<()> {
    let verdict = out
        .stdout
        .lines()
        .find_map(|line| line.strip_prefix(&format!("WSSP_RECOVERED {token} ")));
    match (super::client::parse_guest_status(token, out), verdict) {
        (Some(GuestStatus::Ok), Some("committed")) => Ok(completed(())),
        (Some(GuestStatus::Ok), Some("not_committed")) => Err(GuestFailure::completed(
            super::client::guest_status_error("write", path, GuestStatus::Cancelled),
        )),
        _ => Err(unknown(
            "file write recovery found no decisive guest evidence",
        )),
    }
}

/// Constructed only after a nonce-bound completion record was parsed below.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestFailure(RuntimeError);
impl GuestFailure {
    pub(crate) fn error(&self) -> &RuntimeError {
        &self.0
    }
    fn completed(error: RuntimeError) -> PostIssueError {
        PostIssueError::Completed(crate::effect::CompletionFailure::Guest(Self(error)))
    }
}

/// Group-pidfd helper verdicts (4b). Only an exact, nonce-bound final record
/// is evidence. Verdicts before `verified` are completed failures with no
/// effect; after `verified`, only `delivered` is success and `exited` is a
/// completed no-delivery; anything else (including a lost reply after the
/// boundary, or a missing record) stays UNKNOWN. Never a numeric fallback.
pub(super) fn pidfd_signal_outcome(nonce: &str, out: &IncusCommandOutput) -> PostIssueOutcome<()> {
    let unknown = || -> PostIssueError {
        RuntimeError::new(
            SandboxErrorCode::UnknownOutcome,
            "signal has no completion record",
        )
        .into()
    };
    // Only the launcher's exact nonce-bound, pre-exec missing-interpreter
    // record proves no helper started. Exit 127 alone is not evidence.
    if out.exit_code == 127
        && out.stdout.is_empty()
        && out.stderr == format!("WSSP_SIGNAL {nonce} interpreter_missing\n")
    {
        return Err(GuestFailure::completed(RuntimeError::new(
            SandboxErrorCode::SignalUnsupportedOnGuest,
            "guest cannot deliver a group signal",
        )));
    }
    if out.exit_code != 0 || out.stderr.len() > 512 {
        return Err(unknown());
    }
    let prefix = format!("WSSP_SIGNAL {nonce} ");
    let mut verdicts = Vec::new();
    for line in out.stderr.split_terminator('\n') {
        match line.strip_prefix(&prefix) {
            Some(verdict) if verdicts.len() < 2 => verdicts.push(verdict),
            _ => return Err(unknown()),
        }
    }
    if !out.stderr.ends_with('\n') || !out.stdout.is_empty() {
        return Err(unknown());
    }
    let failed = |code: SandboxErrorCode, message: &'static str| {
        Err(GuestFailure::completed(RuntimeError::new(code, message)))
    };
    match verdicts.as_slice() {
        ["unsupported"] => failed(
            SandboxErrorCode::SignalUnsupportedOnGuest,
            "guest cannot deliver a group signal",
        ),
        ["gone"] => failed(SandboxErrorCode::ProcessExited, "process exited"),
        ["mismatch"] | ["unverified"] => {
            failed(SandboxErrorCode::ProcessStale, "process identity mismatch")
        }
        ["verified", "delivered"] => Ok(completed(())),
        ["verified", "exited"] => failed(SandboxErrorCode::ProcessExited, "process exited"),
        _ => Err(unknown()),
    }
}

/// The helper's support probe (`wssp-signal-probe`): `Some(true)` only for
/// the exact nonce-bound `group` record, `Some(false)` for `unsupported` or
/// the launcher's exact missing-interpreter record (the verdicts a signal
/// call refuses with `signal_unsupported_on_guest`), `None` otherwise.
pub(super) fn group_signal_probe_outcome(nonce: &str, out: &IncusCommandOutput) -> Option<bool> {
    if !out.stdout.is_empty() {
        return None;
    }
    match out.exit_code {
        127 if out.stderr == format!("WSSP_SIGNAL {nonce} interpreter_missing\n") => Some(false),
        0 if out.stderr == format!("WSSP_SIGNAL {nonce} group\n") => Some(true),
        0 if out.stderr == format!("WSSP_SIGNAL {nonce} unsupported\n") => Some(false),
        _ => None,
    }
}

pub(super) fn command_outcome(
    request: &crate::RunCommandRequest,
    stdout: &[u8],
    stderr: &[u8],
    nonce: &str,
) -> PostIssueOutcome<crate::RunCommandResponse> {
    use super::frames::{GuestPid, parse_supervised_frames};
    use crate::{
        CommandRecord, CommandStream, CommandStreamChunk, EffectError, RunCommandResponse,
    };
    use sandbox_protocol::OperationState;
    let frames = parse_supervised_frames(stdout, stderr, nonce);
    let guest_pid = frames.pid_frame.and_then(GuestPid::banner);
    if guest_pid.is_some() && frames.setup_failed.is_some() {
        return Err(GuestFailure::completed(RuntimeError::new(
            SandboxErrorCode::HostEffectNotIssued,
            "guest wrapper setup failed before argv",
        )));
    }
    let state = if guest_pid.is_some() && frames.exit.is_some() {
        OperationState::Succeeded
    } else {
        OperationState::UnknownOutcome
    };
    let response = RunCommandResponse {
        command: CommandRecord {
            operation_id: request.operation_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            state,
            exit_code: frames.exit.filter(|_| guest_pid.is_some()),
            guest_pid,
            birth: None,
            chunks: vec![
                CommandStreamChunk {
                    stream: CommandStream::Stdout,
                    sequence: 0,
                    bytes: frames.user_stdout.to_vec(),
                    final_chunk: true,
                },
                CommandStreamChunk {
                    stream: CommandStream::Stderr,
                    sequence: 0,
                    bytes: frames.user_stderr.to_vec(),
                    final_chunk: true,
                },
            ],
        },
    };
    if state == OperationState::UnknownOutcome {
        Err(EffectError::unknown_command(response).into())
    } else {
        Ok(completed(response))
    }
}

/// A command transport ended without an exit record and the same positively
/// bound VM is now stopped. The command cannot still be running. This proves
/// guest loss, never OOM attribution or rollback of command side effects.
pub(super) fn command_guest_lost(
    client: &super::client::IncusClient,
    bound: &BoundInstance,
) -> Option<crate::EffectError> {
    if !bound.is_running() {
        return None;
    }
    let current = client.query_instance(bound).ok()?;
    current.is_stopped().then(|| {
        crate::EffectError::Completed(crate::effect::CompletionFailure::Guest(GuestFailure(
            RuntimeError::new(
                SandboxErrorCode::GuestUnavailable,
                "guest stopped before command completion was reported",
            ),
        )))
    })
}

// This module owns positive host/guest evidence. The proof constructor is private.
pub(crate) struct ObservedCompletion<T>(T);
impl<T> PositiveEvidence for ObservedCompletion<T> {
    type Value = T;
    fn value(self) -> T {
        self.0
    }
}
fn completed<T>(value: T) -> crate::Completed<T> {
    ObservedCompletion(value).complete()
}
fn unknown(message: &str) -> PostIssueError {
    RuntimeError::new(SandboxErrorCode::UnknownOutcome, message).into()
}

/// Constructed only by `running` below: a completed `incus start` that the
/// daemon refused with a start-time device error, followed by an inventory
/// read observing the bound instance Stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartRefusal(RuntimeError);
impl StartRefusal {
    pub(crate) fn error(&self) -> &RuntimeError {
        &self.0
    }
}

/// Daemon-authored refusals raised while Incus prepares the instance's
/// devices, BEFORE the hypervisor runs: the daemon's start operation has
/// ended in failure. Transport, wait or client errors never carry these
/// prefixes, so they stay uncertain.
const START_REFUSAL_PREFIXES: &[&str] = &[
    "Failed to start device ",
    "Failed pre-start check for device ",
];

/// Bound for the Incus reason carried in operation error detail.
const START_REASON_MAX_BYTES: usize = 300;

/// The daemon's start error from a completed CLI run: the first `Error: `
/// line, control characters replaced, bounded on a char boundary. `None`
/// for a clean exit or a run with no daemon error line.
pub(super) fn start_failure_reason(issued: &IncusCommandOutput) -> Option<String> {
    if issued.exit_code == 0 {
        return None;
    }
    let line = issued
        .stderr
        .lines()
        .find_map(|line| line.trim().strip_prefix("Error: "))?
        .trim();
    if line.is_empty() {
        return None;
    }
    let mut reason: String = line
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if reason.len() > START_REASON_MAX_BYTES {
        let mut end = START_REASON_MAX_BYTES;
        while !reason.is_char_boundary(end) {
            end -= 1;
        }
        reason.truncate(end);
        reason.push('…');
    }
    Some(reason)
}

/// Outcome rule for `incus start` (E-11). The effect is complete only when
/// the instance is observed Running. It is a COMPLETED failure only when all
/// of these hold: the CLI ran to completion (a timeout or cancellation never
/// reaches this function), it exited non-zero (a signal reads as -1 and is
/// excluded), its error is a daemon start-time device refusal, and the
/// re-read shows the instance Stopped. Anything else (no daemon refusal, a
/// transport error, a Starting/Frozen/Error status, a failed re-read) stays
/// UNKNOWN, now with the daemon's reason in the detail when it gave one.
/// `issued` is `None` when this call issued no start (an already-active VM).
pub(super) fn running(
    client: &super::client::IncusClient,
    name: &BoundInstance,
    issued: Option<&IncusCommandOutput>,
) -> PostIssueOutcome<()> {
    let instance = client.query_instance(name)?;
    if instance.is_running() {
        return Ok(completed(()));
    }
    let reason = issued
        .filter(|issued| issued.exit_code > 0)
        .and_then(start_failure_reason);
    match reason {
        Some(reason)
            if instance.is_stopped()
                && START_REFUSAL_PREFIXES
                    .iter()
                    .any(|prefix| reason.starts_with(prefix)) =>
        {
            Err(PostIssueError::Completed(
                crate::effect::CompletionFailure::StartRefused(StartRefusal(RuntimeError::new(
                    SandboxErrorCode::SandboxNotRunning,
                    format!("incus refused to start the instance: {reason}"),
                ))),
            ))
        }
        Some(reason) => Err(PostIssueError::from(RuntimeError::new(
            SandboxErrorCode::UnknownOutcome,
            format!("instance is not Running after `incus start` failed: {reason}"),
        ))),
        None => Err(unknown("instance is not Running")),
    }
}
pub(super) fn stopped_or_absent(
    client: &super::client::IncusClient,
    name: &BoundInstance,
) -> PostIssueOutcome<SandboxLifecycleState> {
    match client.query_instance(name) {
        Ok(instance) if instance.is_stopped() => Ok(completed(SandboxLifecycleState::Stopped)),
        Err(error) if error.code == SandboxErrorCode::SandboxNotFound => {
            Ok(completed(SandboxLifecycleState::Absent))
        }
        Err(error) => Err(error.into()),
        _ => Err(unknown("instance is not Stopped or absent")),
    }
}
pub(super) fn absent(client: &super::client::IncusClient, name: &str) -> PostIssueOutcome<()> {
    if !client.instance_exists(name)? {
        Ok(completed(()))
    } else {
        Err(unknown("instance is still present"))
    }
}
pub(super) fn config(
    client: &super::client::IncusClient,
    name: &BoundInstance,
    key: &str,
    value: &str,
) -> PostIssueOutcome<()> {
    if client.config_get(name, key)?.as_deref() == Some(value) {
        Ok(completed(()))
    } else {
        Err(unknown("config readback differs"))
    }
}
/// Guest group disappearance is a distinct observation from successful signal
/// delivery. Only the exact per-call nonce status can construct this proof.
#[derive(Debug)]
pub(super) struct GroupGone {
    terminated: Option<GroupTerminated>,
}
impl GroupGone {
    /// The stronger record: the helper signalled the group while the user
    /// command was still running, and the group is gone. Plain disappearance
    /// (`group_gone`) never attributes the end of the command to this stop.
    pub(super) fn terminated(self) -> Option<GroupTerminated> {
        self.terminated
    }
}
/// Constructed only from an exact `group_terminated` helper record.
#[derive(Debug)]
pub(super) struct GroupTerminated(());
pub(super) fn group_gone(nonce: &str, out: &IncusCommandOutput) -> Result<GroupGone, RuntimeError> {
    if out.exit_code == 0 {
        if out.stderr == format!("WSSP_STATUS {nonce} group_gone\n") {
            return Ok(GroupGone { terminated: None });
        }
        if out.stderr == format!("WSSP_STATUS {nonce} group_terminated\n") {
            return Ok(GroupGone {
                terminated: Some(GroupTerminated(())),
            });
        }
    }
    Err(RuntimeError::new(
        SandboxErrorCode::UnknownOutcome,
        "guest group disappearance unproven",
    ))
}

#[cfg(test)]
mod start_reason_tests {
    use super::{START_REASON_MAX_BYTES, start_failure_reason};
    use crate::incus::IncusCommandOutput;

    fn out(exit_code: i32, stderr: &str) -> IncusCommandOutput {
        IncusCommandOutput {
            stdout: String::new(),
            stderr: stderr.to_string(),
            exit_code,
        }
    }

    #[test]
    fn start_reason_is_the_daemon_error_line_sanitized_and_bounded() {
        assert_eq!(start_failure_reason(&out(0, "Error: ignored\n")), None);
        assert_eq!(start_failure_reason(&out(1, "no error line\n")), None);
        assert_eq!(start_failure_reason(&out(1, "Error:    \n")), None);
        assert_eq!(
            start_failure_reason(&out(
                1,
                "noise\nError: Failed to start device \"eth0\": x\nTry `incus info`\n"
            ))
            .as_deref(),
            Some("Failed to start device \"eth0\": x")
        );
        assert_eq!(
            start_failure_reason(&out(1, "Error: a\u{1b}[31mb\tc\n")).as_deref(),
            Some("a [31mb c")
        );
        let long = format!("Error: {}\n", "é".repeat(400));
        let reason = start_failure_reason(&out(1, &long)).expect("reason");
        assert!(
            reason.len() <= START_REASON_MAX_BYTES + '…'.len_utf8(),
            "{}",
            reason.len()
        );
        assert!(reason.ends_with('…'));
    }
}

#[cfg(test)]
mod file_status_tests {
    use super::*;
    #[test]
    fn file_completion_requires_nonce_exit_and_closed_effect_evidence() {
        let out = |stderr: String, exit_code| IncusCommandOutput {
            stdout: "sentinel-stdout".into(),
            stderr,
            exit_code,
        };
        for effect in ["none", "partial"] {
            let failed = helper_outcome(
                "nonce",
                &out(format!("WSSP_STATUS nonce fs_no_space {effect}\n"), 1),
                "write",
                "sentinel-path",
            )
            .unwrap_err();
            let failed = crate::EffectError::from(failed);
            assert_eq!(failed.state(), sandbox_protocol::OperationState::Failed);
            assert_eq!(
                failed.failure().unwrap().effect,
                if effect == "none" {
                    sandbox_protocol::results::FailureEffect::None
                } else {
                    sandbox_protocol::results::FailureEffect::Partial
                }
            );
            assert!(!format!("{failed:?}").contains("sentinel"));
        }
        for (status, exit) in [
            ("WSSP_STATUS nonce fs_no_space\n", 1),
            ("WSSP_STATUS other fs_no_space none\n", 1),
            ("WSSP_STATUS nonce fs_no_space rollback\n", 1),
            ("WSSP_STATUS nonce fs_no_space none\nextra\n", 1),
            ("WSSP_STATUS nonce fs_no_space none\n", -1),
            ("WSSP_STATUS nonce ok\n", 1),
            ("WSSP_STATUS nonce fs_no_space unknown\n", 1),
        ] {
            let error = crate::EffectError::from(
                helper_outcome(
                    "nonce",
                    &out(status.into(), exit),
                    "rename",
                    "sentinel-path",
                )
                .unwrap_err(),
            );
            assert_eq!(
                error.state(),
                sandbox_protocol::OperationState::UnknownOutcome
            );
            assert_eq!(
                error.failure().unwrap().effect,
                sandbox_protocol::results::FailureEffect::Unknown
            );
        }
    }
}
