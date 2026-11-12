//! Running-VM retirement of an UNKNOWN `command.run` attempt
//! through its named, root-owned guest scope `wssp.slice/<unit>`.
//!
//! The launcher (`exec.rs`) enforces at launch: every workload runs in its
//! attempt's scope, or the launcher first records the per-boot marker
//! `/run/wssp/unscoped` (and fails closed when it cannot). The retire helper
//! (`retire-helper.py`, one host-pushed guest-root exec per retirement)
//! derives at retire: the scope gone (no marker), empty or killed, and no
//! populated cgroup root of the guest uid. Its inputs are host-known only
//! (unit, uid, budget) plus root-read kernel and PID 1 state.
use std::time::Duration;

use sandbox_protocol::SandboxErrorCode;

use super::client::{BoundInstance, IncusClient, IncusCommandOutput};
use crate::error::RuntimeError;
use crate::r#trait::RetireCommandRequest;

/// The helper source, pushed per exec (never an in-image copy).
pub(super) const RETIRE_HELPER: &str = include_str!("retire-helper.py");
/// One retirement exec, including the helper's own 2 s kill wait and its
/// 2 s `systemctl show` bound.
pub(super) const RETIRE_HELPER_DEADLINE: Duration = Duration::from_secs(5);
/// Every host-side Incus read a retirement makes before (and around) the
/// helper: the stopped/absent probe, the binding, the running check, the QEMU
/// identity reads and the exec's own binding refresh. One budget for the
/// whole preflight, not per call: these are local-socket metadata reads a
/// healthy incusd answers in milliseconds, so 10 s already means a stalled
/// daemon. The 120 s client default (`DEFAULT_AGENT_TIMEOUT_SECS`) would park
/// the serial retirement loop for minutes per receipt. A read cut short is
/// never a proof: it fails the attempt as unproven, the receipt stays, and
/// the paced retry observes again.
pub(super) const RETIRE_PREFLIGHT_BUDGET: Duration = Duration::from_secs(10);

/// The helper's verdict (`WSSP_RETIRE <nonce> <boot> <verdict> [ms]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum RetireVerdict {
    Absent,
    Empty,
    Killed,
    Populated,
    NotDue(u64),
    Unscoped,
    /// No cgroup2 on `/sys/fs/cgroup`: environmental, today's arms.
    Legacy,
    Unsupported,
    UidPopulated,
    Timeout,
}

/// One parsed record: the guest's current boot (root-read) and the verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RetireRecord {
    pub boot_id: String,
    pub verdict: RetireVerdict,
}

/// The exact helper argv (n3): `python3 -I -S -B -c <helper> <mode> <nonce>
/// <uid> <unit> <budget-ms>`, every field host-derived.
pub(super) fn retire_helper_argv(
    request: &RetireCommandRequest,
    uid: u32,
    nonce: &str,
) -> Result<Vec<String>, RuntimeError> {
    if uid == 0 {
        return Err(RuntimeError::new(
            SandboxErrorCode::ProtocolError,
            "the retire helper never targets uid 0",
        ));
    }
    let unit = super::exec::command_scope_unit(
        &request.operation_id,
        request.generation,
        request.attempt,
    )?;
    Ok(vec![
        "python3".into(),
        "-I".into(),
        "-S".into(),
        "-B".into(),
        "-c".into(),
        RETIRE_HELPER.into(),
        request.mode.as_arg().into(),
        nonce.into(),
        uid.to_string(),
        unit,
        request.budget_ms.to_string(),
    ])
}

/// Strictly parse the single stderr record (empty stdout, exit 0), like
/// `frames::parse_boot_record`. Anything else is `None` (unproven).
pub(super) fn parse_retire_record(nonce: &str, out: &IncusCommandOutput) -> Option<RetireRecord> {
    if out.exit_code != 0 || !out.stdout.is_empty() {
        return None;
    }
    let body = out
        .stderr
        .strip_prefix(&format!("WSSP_RETIRE {nonce} "))?
        .strip_suffix('\n')?;
    if body.contains('\n') {
        return None;
    }
    let mut fields = body.split(' ');
    let (Some(boot), Some(verdict)) = (fields.next(), fields.next()) else {
        return None;
    };
    if !super::frames::valid_boot_id(boot.as_bytes()) {
        return None;
    }
    let extra = fields.next();
    if fields.next().is_some() {
        return None;
    }
    let verdict = match (verdict, extra) {
        ("absent", None) => RetireVerdict::Absent,
        ("empty", None) => RetireVerdict::Empty,
        ("killed", None) => RetireVerdict::Killed,
        ("populated", None) => RetireVerdict::Populated,
        ("not_due", Some(ms))
            if (1..=16).contains(&ms.len())
                && ms.bytes().all(|b| b.is_ascii_digit())
                && !ms.starts_with('0') =>
        {
            RetireVerdict::NotDue(ms.parse().ok()?)
        }
        ("unscoped", None) => RetireVerdict::Unscoped,
        ("legacy", None) => RetireVerdict::Legacy,
        ("unsupported", None) => RetireVerdict::Unsupported,
        ("uid_populated", None) => RetireVerdict::UidPopulated,
        ("timeout", None) => RetireVerdict::Timeout,
        _ => return None,
    };
    Some(RetireRecord {
        boot_id: boot.to_string(),
        verdict,
    })
}

impl IncusClient {
    /// One root retire-helper exec in the bound instance.
    pub(super) fn run_retire_helper(
        &self,
        bound: &BoundInstance,
        request: &RetireCommandRequest,
        uid: u32,
    ) -> Result<RetireRecord, RuntimeError> {
        let nonce = super::client::random_nonce()?;
        let argv = retire_helper_argv(request, uid, &nonce)?;
        let out = self
            .exec_root_helper_bounded(bound, &argv, RETIRE_HELPER_DEADLINE)
            .map_err(crate::EffectError::into_error)?;
        parse_retire_record(&nonce, &out).ok_or_else(|| {
            RuntimeError::new(
                SandboxErrorCode::UnknownOutcome,
                "command retire helper gave no valid record",
            )
        })
    }
}

#[cfg(test)]
#[path = "command_scope_tests.rs"]
mod tests;
