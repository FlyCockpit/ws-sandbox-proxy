//! Workload values cross the guest boundary only as the first stdin message.
#![deny(clippy::indexing_slicing)]
use super::client::{BoundInstance, IncusClient, random_nonce};
use crate::RuntimeError;
use sandbox_protocol::{SandboxErrorCode, canonical_env_json, env_limits};
use std::time::Duration;

/// Guest watchdog shared with the host setup deadline.
pub(super) const SETUP_BUDGET: Duration = Duration::from_millis(5000);
// Tests whose setup must simply succeed widen this on a loaded host.
#[cfg(test)]
thread_local! { pub(super) static TEST_SETUP_BUDGET: std::cell::Cell<Duration> = const { std::cell::Cell::new(SETUP_BUDGET) }; }
fn setup_budget() -> Duration {
    #[cfg(test)]
    {
        TEST_SETUP_BUDGET.with(|v| v.get())
    }
    #[cfg(not(test))]
    {
        SETUP_BUDGET
    }
}

pub(super) const ENV_HELPER: &str = include_str!("env-helper.py");

pub(super) fn encode(env: &[(String, String)]) -> Result<Option<Vec<u8>>, RuntimeError> {
    // Validate the supplied map first, including names ignored for identity.
    sandbox_protocol::validate_env(env).map_err(|(c, m)| RuntimeError::new(c, m))?;
    let effective: Vec<_> = env
        .iter()
        .filter(|(k, _)| k != "HOME" && k != "SHELL")
        .cloned()
        .collect();
    if effective.is_empty() {
        return Ok(None);
    }
    let payload = canonical_env_json(&effective).map_err(|(c, m)| RuntimeError::new(c, m))?;
    let n = u32::try_from(payload.len()).map_err(|_| {
        RuntimeError::new(
            SandboxErrorCode::RequestTooLarge,
            "environment frame too large",
        )
    })?;
    let mut frame = b"WSSPENV\0\x01".to_vec();
    frame.extend_from_slice(&n.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(Some(frame))
}

impl IncusClient {
    pub(super) fn pty_env_wrapper(
        &self,
        bound: &BoundInstance,
        nonce: &str,
        budget: Duration,
    ) -> Result<Vec<String>, RuntimeError> {
        self.env_wrapper_mode(bound, EnvMode::Pty(&self.guest.guest_shell), nonce, budget)
    }

    /// A fresh read-only readiness probe, bound to this guest, before admission.
    /// No tool cache survives a boot/readiness change. Never use workload PATH
    /// to resolve infrastructure, or pre-resolve the user's argv[0].
    pub(super) fn env_wrapper(
        &self,
        bound: &BoundInstance,
        wrapper: &[String],
        nonce: &str,
        budget: Duration,
    ) -> Result<Vec<String>, RuntimeError> {
        self.env_wrapper_mode(bound, EnvMode::Piped(wrapper), nonce, budget)
    }

    fn env_wrapper_mode(
        &self,
        bound: &BoundInstance,
        mode: EnvMode<'_>,
        nonce: &str,
        budget: Duration,
    ) -> Result<Vec<String>, RuntimeError> {
        let budget = self
            .cancelled
            .as_ref()
            .and_then(|permit| permit.remaining_time())
            .map_or(budget, |remaining| remaining.min(budget));
        if budget.is_zero() {
            return Err(RuntimeError::new(
                SandboxErrorCode::UnknownOutcome,
                "guest environment setup authority expired",
            ));
        }
        let started = std::time::Instant::now();
        let marker = random_nonce()?;
        let output = self.exec_argv_opts(bound, &[
            "/bin/sh".into(), "-c".into(),
            "set -eu; python=$(command -v python3); setsid=$(command -v setsid); case $python in /*) ;; *) exit 1;; esac; case $setsid in /*) ;; *) exit 1;; esac; [ -x \"$python\" ]; [ -x \"$setsid\" ]; printf 'WSSP_ENV_TOOLS %s\\n%s\\n%s\\n' \"$1\" \"$python\" \"$setsid\"".into(),
            "wssp-env-tools".into(), marker.clone(),
        ], None, Some(budget.min(setup_budget())))?;
        let invalid = || {
            RuntimeError::new(
                SandboxErrorCode::GuestUnavailable,
                "guest environment tools unavailable",
            )
        };
        if output.exit_code != 0 || output.stdout.len() > 8192 {
            return Err(invalid());
        }
        let mut lines = output.stdout.lines();
        if lines.next() != Some(format!("WSSP_ENV_TOOLS {marker}").as_str()) {
            return Err(invalid());
        }
        let python = lines.next().ok_or_else(invalid)?;
        let setsid = lines.next().ok_or_else(invalid)?;
        if lines.next().is_some()
            || [python, setsid].iter().any(|p| {
                !p.starts_with('/')
                    || p.len() > 4096
                    || p.contains('\0')
                    || p.chars().any(char::is_control)
            })
        {
            return Err(invalid());
        }
        let remaining = budget.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(RuntimeError::new(
                SandboxErrorCode::Timeout,
                "guest environment setup deadline exceeded",
            ));
        }
        Ok(env_argv(python, setsid, nonce, remaining, mode))
    }
}

enum EnvMode<'a> {
    Piped(&'a [String]),
    Pty(&'a str),
}

fn env_argv(
    python: &str,
    setsid: &str,
    nonce: &str,
    remaining: Duration,
    mode: EnvMode<'_>,
) -> Vec<String> {
    let (name, timeout_ms) = match mode {
        EnvMode::Piped(_) => (
            "piped",
            remaining.as_millis().clamp(1, setup_budget().as_millis()),
        ),
        EnvMode::Pty(_) => ("pty", setup_budget().as_millis()),
    };
    let limits = env_limits();
    let mut argv = vec![
        python.into(),
        "-I".into(),
        "-c".into(),
        ENV_HELPER.into(),
        name.into(),
        nonce.into(),
        timeout_ms.to_string(),
        limits.max_entries.to_string(),
        limits.key_bytes.to_string(),
        limits.value_bytes.to_string(),
        limits.json_bytes.to_string(),
        "--".into(),
    ];
    match mode {
        EnvMode::Piped(wrapper) => {
            argv.push(setsid.into());
            argv.extend(wrapper.iter().skip(1).cloned());
        }
        EnvMode::Pty(shell) => argv.push(shell.into()),
    }
    argv
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_argv_layouts_remain_exact_for_piped_and_pty() {
        let wrapper = [
            "setsid".into(),
            "/bin/sh".into(),
            "-c".into(),
            "printf hi".into(),
        ];
        let limits = env_limits();
        let expected = |mode: &str, timeout: &str, tail: &[&str]| {
            let mut argv: Vec<String> = [
                "/usr/bin/python3",
                "-I",
                "-c",
                ENV_HELPER,
                mode,
                "nonce",
                timeout,
            ]
            .into_iter()
            .map(String::from)
            .collect();
            argv.extend([
                limits.max_entries.to_string(),
                limits.key_bytes.to_string(),
                limits.value_bytes.to_string(),
                limits.json_bytes.to_string(),
                "--".into(),
            ]);
            argv.extend(tail.iter().map(|arg| (*arg).to_owned()));
            argv
        };
        for (remaining, piped_timeout) in [
            (Duration::ZERO, "1"),
            (Duration::from_millis(123), "123"),
            (Duration::from_secs(9), "5000"),
        ] {
            assert_eq!(
                env_argv(
                    "/usr/bin/python3",
                    "/usr/bin/setsid",
                    "nonce",
                    remaining,
                    EnvMode::Piped(&wrapper)
                ),
                expected(
                    "piped",
                    piped_timeout,
                    &["/usr/bin/setsid", "/bin/sh", "-c", "printf hi"]
                ),
            );
            assert_eq!(
                env_argv(
                    "/usr/bin/python3",
                    "/usr/bin/setsid",
                    "nonce",
                    remaining,
                    EnvMode::Pty("/bin/sh")
                ),
                expected("pty", "5000", &["/bin/sh"]),
            );
        }
    }
}
