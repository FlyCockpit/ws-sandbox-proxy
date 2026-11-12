//! Host-dispatch kind allowlist. Snapshot/restore/fork fail closed.

use crate::error::SandboxErrorCode;

/// Exact system/key-free cleanup allowlist, mirrored by the shared JSON contract.
pub const KEY_FREE_CLEANUP_KINDS: &[&str] = &["sandbox.kill", "sandbox.stop"];

pub const ALLOWED_HOST_DISPATCH_KINDS: &[&str] = &[
    "sandbox.create",
    "sandbox.lease.renew",
    "sandbox.kill",
    "sandbox.reconnect",
    "sandbox.stop",
    "command.run",
    "file.get",
    "file.put",
    "file.list",
    "file.stat",
    "file.mkdir",
    "file.remove",
    "file.move",
    "process.list",
    "process.signal",
    "sandbox.probe",
    "sandbox.capture",
    "credential.attach",
    "credential.free",
];

pub const RELAY_CONTROL_DISPATCH_KINDS: &[&str] = &["process.stdin", "operation.cancel"];

pub const UNSUPPORTED_HOST_DISPATCH_KINDS: &[&str] =
    &["snapshot.create", "snapshot.restore", "sandbox.fork"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchKindClass {
    Allowed,
    Control,
    UnsupportedCapability,
    Unknown,
}

pub fn classify_dispatch_kind(kind: &str) -> DispatchKindClass {
    if UNSUPPORTED_HOST_DISPATCH_KINDS.contains(&kind) {
        DispatchKindClass::UnsupportedCapability
    } else if RELAY_CONTROL_DISPATCH_KINDS.contains(&kind) {
        DispatchKindClass::Control
    } else if ALLOWED_HOST_DISPATCH_KINDS.contains(&kind) {
        DispatchKindClass::Allowed
    } else {
        DispatchKindClass::Unknown
    }
}

pub fn unsupported_dispatch_error(kind: &str) -> (SandboxErrorCode, String) {
    (
        SandboxErrorCode::UnsupportedCapability,
        format!("Unsupported capability: {kind}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_free_cleanup_allowlist_is_exact_and_shared() {
        let kinds: Vec<String> = serde_json::from_str(include_str!(
            "../../../packages/config/src/sandbox-key-free-cleanup.json"
        ))
        .unwrap();
        assert_eq!(kinds, KEY_FREE_CLEANUP_KINDS);
        assert_eq!(KEY_FREE_CLEANUP_KINDS, ["sandbox.kill", "sandbox.stop"]);
    }

    #[test]
    fn snapshot_restore_fork_fail_closed() {
        for kind in UNSUPPORTED_HOST_DISPATCH_KINDS {
            assert_eq!(
                classify_dispatch_kind(kind),
                DispatchKindClass::UnsupportedCapability
            );
        }
    }

    #[test]
    fn allowed_host_kinds_are_dispatchable() {
        for kind in ALLOWED_HOST_DISPATCH_KINDS {
            assert_eq!(classify_dispatch_kind(kind), DispatchKindClass::Allowed);
        }
    }

    #[test]
    fn unknown_kind_is_not_allowed() {
        assert_eq!(
            classify_dispatch_kind("sandbox.explode"),
            DispatchKindClass::Unknown
        );
    }
}
