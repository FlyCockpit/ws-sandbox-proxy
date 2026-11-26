//! Template-build gate (guest root runs only inside build VMs).
//!
//! Every dispatch passes [`gate`] before any lease, Effect record or runtime
//! call. The decision uses only this host's journaled sandbox record (its
//! `build_id`, bound by the accepted `sandbox.create`) and local config, never
//! a frame field alone:
//!
//! - `runAs`/`buildCopy` are refused unless the record carries a build id
//!   (and this node still runs builds); a `buildCopy` may only read that
//!   build's own staged context path.
//! - A build record refuses `sandbox.reconnect`, `process.signal` and every
//!   file operation except the `file.put` of its context. Terminals are
//!   refused in `terminal.rs` from the same record.
//! - A `sandbox.create` carrying `build` is refused when `builder = false`.
//! - A `sandbox.create` carrying `build` together with `guestSudo` is refused:
//!   build VMs never have guest sudo (DG-6); the lease rule refuses it too.
//! - `build.bootstrap` (community bases) yields bootstrap readiness only for
//!   the `sandbox.create` that carries it, with builds enabled. An upstream
//!   image plan without it is refused (the protocol refuses it too). D1 is
//!   unchanged: bootstrap grants no root step, COPY or file access.

use sandbox_protocol::{OperationDispatch, SandboxErrorCode};

use super::journal::HostJournal;
use super::supervisor::DispatchError;

/// Proof that a dispatch targets a sandbox whose journaled record carries a
/// build id. Only [`gate`] constructs one; the command request builder needs
/// it to run anything as guest root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BuildBinding {
    build_id: String,
}

impl BuildBinding {
    #[cfg(test)]
    pub(super) fn build_id(&self) -> &str {
        &self.build_id
    }
}

/// What [`gate`] admitted: the root-step binding (root steps only) and the
/// readiness a create gets (bootstrap only for a bootstrap build create).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct GateProof {
    pub(super) root: Option<BuildBinding>,
    pub(super) readiness: sandbox_runtime::ReadinessMode,
}

impl From<Option<BuildBinding>> for GateProof {
    fn from(root: Option<BuildBinding>) -> Self {
        Self {
            root,
            readiness: sandbox_runtime::ReadinessMode::Standard,
        }
    }
}

fn refused(code: SandboxErrorCode, message: &str) -> DispatchError {
    DispatchError {
        reason: None,
        code: code.into(),
        message: message.into(),
    }
}

/// Decide `d` against the journaled build binding of its sandbox. A root
/// binding is returned only for a root step on a build record; bootstrap
/// readiness only for a bootstrap build create.
pub(super) fn gate(
    journal: &HostJournal,
    builds_enabled: bool,
    d: &OperationDispatch,
) -> Result<GateProof, DispatchError> {
    let bootstrap = d.build.as_ref().is_some_and(|build| build.bootstrap);
    let upstream = d
        .image
        .as_ref()
        .is_some_and(|image| image.upstream.is_some());
    if (bootstrap || upstream) && d.kind != "sandbox.create" {
        return Err(refused(
            SandboxErrorCode::ProtocolError,
            "bootstrap readiness rides only on a create",
        ));
    }
    if upstream && !bootstrap {
        return Err(refused(
            SandboxErrorCode::ProtocolError,
            "upstream images boot only in a bootstrap build",
        ));
    }
    let proof = root_gate(journal, builds_enabled, d)?;
    Ok(GateProof {
        readiness: if bootstrap {
            sandbox_runtime::ReadinessMode::BuildBootstrap
        } else {
            sandbox_runtime::ReadinessMode::Standard
        },
        ..proof.into()
    })
}

fn root_gate(
    journal: &HostJournal,
    builds_enabled: bool,
    d: &OperationDispatch,
) -> Result<Option<BuildBinding>, DispatchError> {
    let record_build = journal
        .lease(&d.sandbox_id)
        .and_then(|record| record.build_id);
    let root_step = d.run_as.is_some() || d.build_copy.is_some();
    match d.kind.as_str() {
        "sandbox.create" if d.build.is_some() && d.guest_sudo.is_some() => Err(refused(
            SandboxErrorCode::ProtocolError,
            "build sandboxes never carry guest sudo",
        )),
        "sandbox.create" if d.build.is_some() && !builds_enabled => Err(refused(
            SandboxErrorCode::UnsupportedCapability,
            "template builds are disabled on this host",
        )),
        "sandbox.reconnect" if record_build.is_some() => Err(refused(
            SandboxErrorCode::UnsupportedCapability,
            "build sandboxes cannot reconnect",
        )),
        "process.signal" if record_build.is_some() => Err(refused(
            SandboxErrorCode::UnsupportedCapability,
            "build sandboxes accept no process signals",
        )),
        "command.run" if root_step => {
            let Some(build_id) = record_build else {
                return Err(refused(
                    SandboxErrorCode::ProtocolError,
                    "root steps run only in build sandboxes",
                ));
            };
            if !builds_enabled {
                return Err(refused(
                    SandboxErrorCode::UnsupportedCapability,
                    "template builds are disabled on this host",
                ));
            }
            if let Some(copy) = &d.build_copy
                && sandbox_protocol::build_context_path(&build_id).as_deref()
                    != Some(copy.context_path.as_str())
            {
                return Err(refused(
                    SandboxErrorCode::ProtocolError,
                    "build copy names another build's context",
                ));
            }
            Ok(Some(BuildBinding { build_id }))
        }
        kind if kind.starts_with("file.") => match record_build {
            None => Ok(None),
            Some(build_id)
                if kind == "file.put"
                    && d.path.is_some()
                    && sandbox_protocol::build_context_path(&build_id) == d.path =>
            {
                Ok(None)
            }
            Some(_) => Err(refused(
                SandboxErrorCode::UnsupportedCapability,
                "build sandboxes accept only their context upload",
            )),
        },
        _ => Ok(None),
    }
}

#[cfg(test)]
#[path = "build_tests.rs"]
mod tests;
