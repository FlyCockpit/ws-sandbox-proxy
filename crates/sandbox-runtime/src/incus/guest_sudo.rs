//! Per-sandbox guest sudo (guest sudo plan step 11): the daemon's fixed,
//! host-pushed root helper (`guest-sudo-helper.py`) installs or removes
//! `/etc/sudoers.d/wssp-guest` on every boot the daemon drives, after the
//! last guest restart, and at create (sudo off, no guest root possible, not a
//! build VM) runs a hygiene audit for common static root grants.
//!
//! - The grant names the guest only by `#<uid>`; no guest-derived name is
//!   sent, journaled or persisted. The authoritative check is `sudo -n true`
//!   as the guest uid after the install, so any sudo implementation works or
//!   the create fails with `guest_sudo_unavailable`.
//! - The audit is hygiene, not a security control: it runs on the guest's
//!   own `python3`.
//! - The record is constant tokens only (`WSSP_SUDO <nonce> <verdict> <impl>
//!   [<form>]`), never guest text. `<impl>` is a diagnostic label.
//!
//! Commands, files and terminals always run as the guest user.
use std::time::Duration;

use sandbox_protocol::{ReadinessFailureReason, SandboxErrorCode};

use super::client::{BoundInstance, IncusClient, IncusCommandOutput};
use crate::error::RuntimeError;

/// The helper source, pushed per exec (never an in-image copy).
pub(super) const GUEST_SUDO_HELPER: &str = include_str!("guest-sudo-helper.py");
/// One helper exec: `sudo -V`, two `visudo -c`, `sudo -n true` or the audit's
/// `sudo -l`, each bounded inside the helper.
pub(super) const GUEST_SUDO_DEADLINE: Duration = Duration::from_secs(45);

/// What the helper does on one boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GuestSudoStep {
    /// Effective `guestSudo`: install and prove the drop-in.
    Grant,
    /// `guestSudo` off: remove the drop-in. `strict` (create) refuses a
    /// failure; otherwise (reconnect, recovery) it is logged and boot goes
    /// on, since nothing a non-root guest can do re-adds a grant.
    Revoke { strict: bool },
    /// Create with `guestSudo` off and no guest root possible: revoke, then
    /// the hygiene audit (DG-4).
    RevokeAudit,
}

impl GuestSudoStep {
    pub(crate) fn for_create(privilege: crate::GuestPrivilege) -> Self {
        if privilege.sudo {
            Self::Grant
        } else if privilege.audit {
            Self::RevokeAudit
        } else {
            Self::Revoke { strict: true }
        }
    }
    pub(crate) fn for_boot(sudo: bool) -> Self {
        if sudo {
            Self::Grant
        } else {
            Self::Revoke { strict: false }
        }
    }
    pub(crate) fn sudo(self) -> bool {
        matches!(self, Self::Grant)
    }
    fn mode(self) -> &'static str {
        match self {
            Self::Grant => "grant",
            Self::Revoke { .. } => "revoke",
            Self::RevokeAudit => "revoke-audit",
        }
    }
}

/// The helper's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SudoVerdict {
    Granted,
    SudoMissing,
    UnsafeDir,
    Invalid,
    NotEffective,
    Revoked,
    Clean,
    AuditInconclusive,
    RootGranted(&'static str),
}

/// The constant forms a `root_granted` record may name.
const ROOT_FORMS: &[&str] = &[
    "unsafe_dir",
    "sudoers_dir",
    "sudoers_tmp_dir",
    "revoke_failed",
    "uid0_alias",
    "gid0",
    "sudo_rule",
    "group_sudo",
    "group_wheel",
    "group_admin",
    "group_root",
    "group_docker",
    "group_lxd",
    "group_incus",
    "group_incus_admin",
    "group_libvirt",
    "group_disk",
    "group_staff",
    "doas",
    "root_password_empty",
    "guest_password",
];

/// The sudo implementation the helper saw (`sudo -V`), diagnostics only.
const IMPLS: &[&str] = &["sudo_ws", "sudo_rs", "unknown", "none"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SudoRecord {
    pub verdict: SudoVerdict,
    pub implementation: &'static str,
}

/// `python3 -I -S -B -c <helper> <mode> <nonce> <uid> <gid>`, every field
/// host-derived. The guest uid is never 0.
pub(super) fn guest_sudo_argv(
    step: GuestSudoStep,
    nonce: &str,
    guest: &crate::GuestIdentity,
) -> Result<Vec<String>, RuntimeError> {
    if guest.guest_uid == 0 {
        return Err(RuntimeError::new(
            SandboxErrorCode::ProtocolError,
            "the guest sudo helper never targets uid 0",
        ));
    }
    Ok(vec![
        "python3".into(),
        "-I".into(),
        "-S".into(),
        "-B".into(),
        "-c".into(),
        GUEST_SUDO_HELPER.into(),
        step.mode().into(),
        nonce.into(),
        guest.guest_uid.to_string(),
        guest.guest_gid.to_string(),
    ])
}

/// Strictly parse the single stderr record (empty stdout, exit 0). Anything
/// else is `None`. Verdicts must belong to the step's mode.
pub(super) fn parse_sudo_record(
    step: GuestSudoStep,
    nonce: &str,
    out: &IncusCommandOutput,
) -> Option<SudoRecord> {
    if out.exit_code != 0 || !out.stdout.is_empty() {
        return None;
    }
    let body = out
        .stderr
        .strip_prefix(&format!("WSSP_SUDO {nonce} "))?
        .strip_suffix('\n')?;
    if body.contains('\n') {
        return None;
    }
    let mut fields = body.split(' ');
    let (Some(verdict), Some(implementation)) = (fields.next(), fields.next()) else {
        return None;
    };
    let implementation = *IMPLS.iter().find(|label| **label == implementation)?;
    let form = fields.next();
    if fields.next().is_some() {
        return None;
    }
    let grant = step == GuestSudoStep::Grant;
    let audit = step == GuestSudoStep::RevokeAudit;
    let verdict = match (verdict, form) {
        ("granted", None) if grant => SudoVerdict::Granted,
        ("sudo_missing", None) if grant => SudoVerdict::SudoMissing,
        ("unsafe_dir", None) if grant => SudoVerdict::UnsafeDir,
        ("invalid", None) if grant => SudoVerdict::Invalid,
        ("not_effective", None) if grant => SudoVerdict::NotEffective,
        ("revoked", None) if matches!(step, GuestSudoStep::Revoke { .. }) => SudoVerdict::Revoked,
        ("clean", None) if audit => SudoVerdict::Clean,
        ("audit_inconclusive", None) if audit => SudoVerdict::AuditInconclusive,
        ("root_granted", Some(form)) if !grant => {
            SudoVerdict::RootGranted(ROOT_FORMS.iter().find(|known| **known == form)?)
        }
        _ => return None,
    };
    Some(SudoRecord {
        verdict,
        implementation,
    })
}

fn unavailable(reason: ReadinessFailureReason, label: &'static str) -> RuntimeError {
    RuntimeError::new(
        SandboxErrorCode::GuestUnavailable,
        format!("guest sudo step failed ({label})"),
    )
    .with_readiness_reason(reason)
    .with_diagnostic(label)
}

/// Fence and cancellation codes keep their own retryable meaning.
fn keeps_code(error: &RuntimeError) -> bool {
    matches!(
        error.code,
        SandboxErrorCode::IdempotencyConflict
            | SandboxErrorCode::UnknownOutcome
            | SandboxErrorCode::Cancelled
            | SandboxErrorCode::SandboxNotRunning
    ) || error.is_enforcement_inconclusive()
}

/// How one record (or its absence) decides the boot. The runtime crate does
/// not log: a failure's constant label rides in its message and diagnostic,
/// and a non-strict revoke (reconnect, recovery) never fails the boot.
pub(super) fn decide(step: GuestSudoStep, record: Option<SudoRecord>) -> Result<(), RuntimeError> {
    use SudoVerdict as V;
    match (step, record.map(|r| r.verdict)) {
        (GuestSudoStep::Grant, Some(V::Granted)) => Ok(()),
        (GuestSudoStep::Grant, verdict) => {
            let label = match verdict {
                Some(V::SudoMissing) => "sudo_missing",
                Some(V::UnsafeDir) => "unsafe_dir",
                Some(V::Invalid) => "invalid",
                Some(_) => "not_effective",
                None => "no_record",
            };
            Err(unavailable(
                ReadinessFailureReason::GuestSudoUnavailable,
                label,
            ))
        }
        // Hygiene only (DG-4, U7): an audit the image's sudo could not
        // answer is not a refusal.
        (_, Some(V::Revoked | V::Clean | V::AuditInconclusive)) => Ok(()),
        // After create nothing a non-root guest does re-adds a grant, and a
        // guest-root sandbox may hold one by design: never fail the boot.
        (GuestSudoStep::Revoke { strict: false }, _) => Ok(()),
        (_, Some(V::RootGranted(form))) => {
            Err(unavailable(ReadinessFailureReason::GuestRootGranted, form))
        }
        (_, _) => Err(unavailable(ReadinessFailureReason::GuestCheck, "no_record")),
    }
}

impl IncusClient {
    /// One guest sudo helper exec as guest root in the bound instance,
    /// decided per [`decide`]. Fence and cancellation errors propagate.
    pub(super) fn guest_sudo_step(
        &self,
        bound: &BoundInstance,
        step: GuestSudoStep,
    ) -> Result<(), RuntimeError> {
        let nonce = super::client::random_nonce()?;
        let argv = guest_sudo_argv(step, &nonce, &self.guest)?;
        // Inside readiness the client's agent timeout is the remaining
        // readiness budget; the helper never outlives it.
        let deadline = GUEST_SUDO_DEADLINE.min(self.agent_timeout);
        let record = match self.exec_root_helper_bounded(bound, &argv, deadline) {
            Ok(out) => parse_sudo_record(step, &nonce, &out),
            Err(error) => {
                let error = error.into_error();
                if keeps_code(&error) {
                    return Err(error);
                }
                None
            }
        };
        decide(step, record)
    }
}

#[cfg(test)]
#[path = "guest_sudo_tests.rs"]
mod tests;
