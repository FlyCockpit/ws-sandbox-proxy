//! Credential guest operations over `incus exec`: one fixed
//! helper, control and payload on stdin, a framed report (and, for pack, the
//! bundle) on stdout. The child runs in its own process group and is killed
//! when the runtime permit is cancelled (a stop or kill taking the guest
//! slot) or its budget elapses.

use super::client::{BoundInstance, IncusClient};
use crate::RuntimeError;
use crate::credentials::{
    self as cred, CREDENTIAL_HELPER, CREDENTIAL_REPORT_MAX_BYTES, CredentialGuest,
    CredentialPackOutcome, CredentialPackRequest, CredentialQuiesceOutcome,
    CredentialRestoreOutcome, CredentialRestoreRequest, CredentialScrubOutcome,
    CredentialScrubRequest,
};
use sandbox_protocol::SandboxErrorCode;
use std::io::{Read, Write};
use std::process::Stdio;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Helper budget per mode (10 s inside the guest) plus `incus exec` slack.
pub(super) const CREDENTIAL_STEP_BUDGET: Duration = Duration::from_secs(20);
/// Quiesce: 3 s SIGTERM grace, ≤ 3 s freeze, ≤ 3 s kill wait, plus slack.
pub(super) const CREDENTIAL_QUIESCE_BUDGET: Duration = Duration::from_secs(25);
/// After the child exits, its stdout reader gets this long before the
/// process group is killed (a descendant holding the pipe open).
const READER_GRACE: Duration = Duration::from_secs(2);

/// The framed report and, for pack, the bundle.
type HelperOutput = (serde_json::Value, Option<Zeroizing<Vec<u8>>>);

/// One helper invocation: mode, stdin and output bounds.
pub(super) struct HelperCall<'a> {
    /// Run as root (quiesce) instead of the guest account.
    pub root: bool,
    pub mode: &'a str,
    pub control: serde_json::Value,
    /// Written to stdin after the control, in order.
    pub payload: &'a [&'a [u8]],
    /// Largest body the report may announce (0: none allowed).
    pub body_cap: usize,
    pub budget: Duration,
}

/// Raw result of one helper run: exit code and the framed output.
pub(super) struct HelperRun {
    pub exit: Option<i32>,
    pub report: Option<serde_json::Value>,
    pub body: Option<Zeroizing<Vec<u8>>>,
}

fn report_ok(report: &serde_json::Value) -> bool {
    report.get("ok").and_then(serde_json::Value::as_bool) == Some(true)
}

/// Reads `u32be len | report JSON [| body]`. The body is read straight into
/// one zeroizing buffer sized from the report (≤ `body_cap`), then EOF is
/// required.
fn read_output(mut stdout: impl Read, body_cap: usize) -> Result<HelperOutput, RuntimeError> {
    let mut len = [0u8; 4];
    stdout
        .read_exact(&mut len)
        .map_err(|_| cred::helper_malformed())?;
    let len = u32::from_be_bytes(len) as usize;
    if len > CREDENTIAL_REPORT_MAX_BYTES {
        return Err(cred::helper_malformed());
    }
    let mut raw = vec![0u8; len];
    stdout
        .read_exact(&mut raw)
        .map_err(|_| cred::helper_malformed())?;
    let report: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|_| cred::helper_malformed())?;
    if !report.is_object() {
        return Err(cred::helper_malformed());
    }
    let body = match report.get("bundleLen") {
        None => None,
        Some(value) => {
            let n = value
                .as_u64()
                .and_then(|n| usize::try_from(n).ok())
                .filter(|n| *n <= body_cap && report_ok(&report))
                .ok_or_else(cred::helper_malformed)?;
            let mut body = Zeroizing::new(vec![0u8; n]);
            stdout
                .read_exact(&mut body)
                .map_err(|_| cred::helper_malformed())?;
            Some(body)
        }
    };
    let mut extra = [0u8; 1];
    match stdout.read(&mut extra) {
        Ok(0) => Ok((report, body)),
        _ => Err(cred::helper_malformed()),
    }
}

impl IncusClient {
    fn credential_bound(&self, guest: &CredentialGuest) -> Result<BoundInstance, RuntimeError> {
        let name = crate::default_incus_instance_name(&guest.sandbox_id);
        let bound = self.bind_owned_instance(&name, &guest.sandbox_id)?;
        if !bound.is_running() {
            return Err(RuntimeError::new(
                SandboxErrorCode::SandboxNotRunning,
                "sandbox is not running",
            ));
        }
        Ok(bound)
    }

    /// Runs the helper in `mode` with `control` (and `payload` slices after
    /// it) on stdin. Errors only for spawn, transport, budget or
    /// cancellation; the exit code and report are the caller's to judge.
    pub(super) fn credential_helper_run(
        &self,
        guest: &CredentialGuest,
        call: HelperCall<'_>,
    ) -> Result<HelperRun, RuntimeError> {
        let HelperCall {
            root,
            mode,
            control,
            payload,
            body_cap,
            budget,
        } = call;
        let bound = self.credential_bound(guest)?;
        // Helper control (paths and counts, never plaintext), not a relay frame.
        let control = cred::frame(control.to_string().as_bytes())?;
        let mut command =
            crate::host_child::command(&self.binary, crate::host_child::Environment::Incus);
        command.args(["--project", &self.project, "exec", bound.name(), "-T"]);
        if root {
            command.args(["--user", "0", "--group", "0", "--cwd", "/"]);
        } else {
            command.args([
                "--user".to_owned(),
                guest.uid.to_string(),
                "--group".to_owned(),
                guest.gid.to_string(),
                "--cwd".to_owned(),
                guest.home.clone(),
                "--env".to_owned(),
                format!("HOME={}", guest.home),
            ]);
        }
        command
            .args([
                "--",
                "python3",
                "-I",
                "-S",
                "-B",
                "-c",
                CREDENTIAL_HELPER,
                mode,
            ])
            .env("LC_ALL", "C")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = self
            .spawn_guest(&bound, &mut command)
            .map_err(crate::EffectError::into_error)?;
        let mut stdin = child.stdin.take().ok_or_else(cred::helper_malformed)?;
        let stdout = child.stdout.take().ok_or_else(cred::helper_malformed)?;
        let pid = child.id();
        let deadline = Instant::now() + budget;
        std::thread::scope(|scope| {
            scope.spawn(move || {
                // EPIPE (the helper refused early) is the helper's report to make.
                if stdin.write_all(&control).is_ok() {
                    for part in payload {
                        if stdin.write_all(part).is_err() {
                            break;
                        }
                    }
                }
            });
            let reader = scope.spawn(move || read_output(stdout, body_cap));
            let mut interrupted: Option<RuntimeError> = None;
            let exit = loop {
                if self.cancelled.as_ref().is_some_and(|p| p.is_cancelled()) {
                    interrupted = Some(RuntimeError::new(
                        SandboxErrorCode::Cancelled,
                        format!("credential {mode} cancelled"),
                    ));
                } else if Instant::now() >= deadline {
                    interrupted = Some(RuntimeError::new(
                        SandboxErrorCode::Timeout,
                        format!("credential {mode} timed out"),
                    ));
                }
                if interrupted.is_some() {
                    let _ = IncusClient::kill_process_group(pid);
                    let _ = child.wait();
                    break None;
                }
                match child.try_wait() {
                    Ok(Some(status)) => break Some(status.code()),
                    Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                    Err(_) => {
                        let _ = IncusClient::kill_process_group(pid);
                        let _ = child.wait();
                        interrupted = Some(RuntimeError::new(
                            SandboxErrorCode::Internal,
                            format!("credential {mode} wait failed"),
                        ));
                        break None;
                    }
                }
            };
            let grace = Instant::now() + READER_GRACE;
            while !reader.is_finished() {
                if Instant::now() >= grace {
                    let _ = IncusClient::kill_process_group(pid);
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let output = reader
                .join()
                .unwrap_or_else(|_| Err(cred::helper_malformed()));
            if let Some(error) = interrupted {
                return Err(error);
            }
            let exit = exit.flatten();
            Ok(match output {
                Ok((report, body)) => HelperRun {
                    exit,
                    report: Some(report),
                    body,
                },
                Err(_) => HelperRun {
                    exit,
                    report: None,
                    body: None,
                },
            })
        })
    }

    pub fn credential_pack(
        &self,
        request: &CredentialPackRequest,
    ) -> Result<CredentialPackOutcome, RuntimeError> {
        cred::validate_pack(request)?;
        let cap = login_definition::limits::bundle_max_encoded_bytes(request.max_bytes);
        let run = self.credential_helper_run(
            &request.guest,
            HelperCall {
                root: false,
                mode: "pack",
                control: cred::pack_control(request),
                payload: &[],
                body_cap: cap,
                budget: CREDENTIAL_STEP_BUDGET,
            },
        )?;
        match (run.exit, run.report, run.body) {
            (Some(0), Some(report), Some(body)) if report_ok(&report) => {
                cred::pack_outcome(request, &report, body)
            }
            (_, Some(report), _) if !report_ok(&report) => {
                Err(cred::helper_failed("pack", &report))
            }
            _ => Err(cred::helper_malformed()),
        }
    }

    pub fn credential_restore(
        &self,
        request: &CredentialRestoreRequest<'_>,
    ) -> Result<CredentialRestoreOutcome, RuntimeError> {
        cred::validate_restore(request)?;
        let payload: Vec<&[u8]> = request
            .files
            .iter()
            .filter(|f| !f.data.is_empty())
            .map(|f| f.data)
            .collect();
        let run = self.credential_helper_run(
            &request.guest,
            HelperCall {
                root: false,
                mode: "restore",
                control: cred::restore_control(request),
                payload: &payload,
                body_cap: 0,
                budget: CREDENTIAL_STEP_BUDGET,
            },
        )?;
        match (run.exit, run.report) {
            (Some(0), Some(report)) if report_ok(&report) => cred::restore_outcome(&report),
            (_, Some(report)) if !report_ok(&report) => {
                Err(cred::helper_failed("restore", &report))
            }
            _ => Err(cred::helper_malformed()),
        }
    }

    pub fn credential_scrub(
        &self,
        request: &CredentialScrubRequest,
    ) -> Result<CredentialScrubOutcome, RuntimeError> {
        cred::validate_scrub(request)?;
        let run = self.credential_helper_run(
            &request.guest,
            HelperCall {
                root: false,
                mode: "scrub",
                control: cred::scrub_control(request),
                payload: &[],
                body_cap: 0,
                budget: CREDENTIAL_STEP_BUDGET,
            },
        )?;
        match run.report {
            Some(report) if report.get("verifiedAbsent").is_some() => {
                let outcome = cred::scrub_outcome(&report)?;
                if outcome.verified_absent && run.exit != Some(0) {
                    return Err(cred::helper_malformed());
                }
                Ok(outcome)
            }
            Some(report) if !report_ok(&report) => Err(cred::helper_failed("scrub", &report)),
            _ => Err(cred::helper_malformed()),
        }
    }

    pub fn credential_quiesce(
        &self,
        guest: &CredentialGuest,
    ) -> Result<CredentialQuiesceOutcome, RuntimeError> {
        cred::validate_quiesce(guest)?;
        let run = self.credential_helper_run(
            guest,
            HelperCall {
                root: true,
                mode: "quiesce",
                control: cred::quiesce_control(guest),
                payload: &[],
                body_cap: 0,
                budget: CREDENTIAL_QUIESCE_BUDGET,
            },
        )?;
        match (run.exit, run.report) {
            (Some(0), Some(report)) if report_ok(&report) => cred::quiesce_outcome(&report),
            (_, Some(report)) if !report_ok(&report) => {
                Err(cred::helper_failed("quiesce", &report))
            }
            _ => Err(cred::helper_malformed()),
        }
    }

    pub fn credential_helper_present(&self, guest: &CredentialGuest) -> Result<bool, RuntimeError> {
        cred::validate_guest(guest)?;
        let run = self.credential_helper_run(
            guest,
            HelperCall {
                root: false,
                mode: "probe",
                control: serde_json::json!({}),
                payload: &[],
                body_cap: 0,
                budget: CREDENTIAL_STEP_BUDGET,
            },
        )?;
        match (run.exit, run.report) {
            (Some(0), Some(report)) if report_ok(&report) => Ok(true),
            // `incus exec` reports a missing interpreter as 126/127.
            (Some(126 | 127), _) => Ok(false),
            _ => Err(cred::helper_malformed()),
        }
    }
}

#[cfg(test)]
#[path = "credentials_tests.rs"]
mod tests;
