//! Stable, cross-language sandbox error codes.

use serde::{Deserialize, Serialize};

// One declaration generates the enum and exhaustive inventory together.
macro_rules! error_codes {
    ($($variant:ident),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum SandboxErrorCode { $($variant),+ }
        impl SandboxErrorCode {
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];
            #[cfg(test)]
            fn assert_enumerated(self) {
                match self { $(Self::$variant => assert!(Self::ALL.contains(&Self::$variant))),+ }
            }
        }
    };
}
error_codes! {
    HostRuntimeUnsupported,
    HostEffectNotIssued,
    HostDisconnectExpired,
    HostCapacity,
    VmSizeMismatch,
    ProtocolVersionUnsupported,
    ProtocolError,
    EgressResolutionFailed,
    Transport,
    Timeout,
    Disconnected,
    Cancelled,
    AccessDenied,
    GuestPermissionDenied,
    GuestOperationFailed,
    PathRefused,
    NotFound,
    SandboxNotFound,
    OperationNotFound,
    IdempotencyConflict,
    DigestKeyChanged,
    DigestKeyUnavailable,
    ReceiptDigestPruned,
    StateConflict,
    LeaseExceedsPolicy,
    RequestTooLarge,
    RateLimited,
    Internal,
    UnknownOutcome,
    GuestUnavailable,
    SandboxNotRunning,
    SnapshotFailed,
    UnsupportedCapability,
    FsNotFound,
    FsIsDirectory,
    FsNotDirectory,
    FsNotRegular,
    FsPermissionDenied,
    FsReadOnly,
    FsAlreadyExists,
    FsNotEmpty,
    FsCrossDevice,
    FsNoSpace,
    FsSymlinkRefused,
    FsEntryTooLarge,
    FsListingLimit,
    FsInvalidEncoding,
    FsMetadataUnrepresentable,
    ProcessNotFound,
    ProcessExited,
    ProcessStale,
    ProcessNotStarted,
    ProcessStdinClosed,
    ProcessCancelPending,
    ProcessPermissionDenied,
    SignalUnsupportedOnGuest,
    ImageUnavailable,
    ImageCacheFull,
    ImageCorrupt,
    ImageRejected,
    ImageFetchTimeout,
    CaptureFailed,
    CaptureFreezeFailed,
    CaptureStoreFailed,
    StartupFailed,
    StartupTimeout,
    GuestNetworkUnavailable,
    CredentialInstallFailed,
    CredentialSpecInvalid,
    CredentialEnvPending,
    CredentialCaptureFailed,
    // A cached cold reconnect's retained root is not the stored offload it
    // expected; nothing was started.
    DiskStale,

}

impl std::fmt::Display for SandboxErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl SandboxErrorCode {
    pub const fn as_str(&self) -> &'static str {
        match *self {
            Self::VmSizeMismatch => "vm_size_mismatch",
            Self::HostCapacity => "host_capacity",
            Self::HostRuntimeUnsupported => "host_runtime_unsupported",
            Self::HostEffectNotIssued => "host_effect_not_issued",
            Self::HostDisconnectExpired => "host_disconnect_expired",
            Self::ProtocolVersionUnsupported => "protocol_version_unsupported",
            Self::ProtocolError => "protocol_error",
            Self::EgressResolutionFailed => "egress_resolution_failed",
            Self::Transport => "transport",
            Self::Timeout => "timeout",
            Self::Disconnected => "disconnected",
            Self::Cancelled => "cancelled",
            Self::AccessDenied => "access_denied",
            Self::GuestPermissionDenied => "guest_permission_denied",
            Self::GuestOperationFailed => "guest_operation_failed",
            Self::PathRefused => "path_refused",
            Self::NotFound => "not_found",
            Self::SandboxNotFound => "sandbox_not_found",
            Self::OperationNotFound => "operation_not_found",
            Self::DigestKeyChanged => "digest_key_changed",
            Self::DigestKeyUnavailable => "digest_key_unavailable",
            Self::ReceiptDigestPruned => "receipt_digest_pruned",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::StateConflict => "state_conflict",
            Self::LeaseExceedsPolicy => "lease_exceeds_policy",
            Self::RequestTooLarge => "request_too_large",
            Self::RateLimited => "rate_limited",
            Self::Internal => "internal",
            Self::UnknownOutcome => "unknown_outcome",
            Self::GuestUnavailable => "guest_unavailable",
            Self::SandboxNotRunning => "sandbox_not_running",
            Self::SnapshotFailed => "snapshot_failed",
            Self::UnsupportedCapability => "unsupported_capability",
            Self::FsNotFound => "fs_not_found",
            Self::FsIsDirectory => "fs_is_directory",
            Self::FsNotDirectory => "fs_not_directory",
            Self::FsNotRegular => "fs_not_regular",
            Self::FsPermissionDenied => "fs_permission_denied",
            Self::FsReadOnly => "fs_read_only",
            Self::FsAlreadyExists => "fs_already_exists",
            Self::FsNotEmpty => "fs_not_empty",
            Self::FsCrossDevice => "fs_cross_device",
            Self::FsNoSpace => "fs_no_space",
            Self::FsSymlinkRefused => "fs_symlink_refused",
            Self::FsEntryTooLarge => "fs_entry_too_large",
            Self::FsListingLimit => "fs_listing_limit",
            Self::FsInvalidEncoding => "fs_invalid_encoding",
            Self::FsMetadataUnrepresentable => "fs_metadata_unrepresentable",
            Self::ProcessNotFound => "process_not_found",
            Self::ProcessExited => "process_exited",
            Self::ProcessStale => "process_stale",
            Self::ProcessNotStarted => "process_not_started",
            Self::ProcessStdinClosed => "process_stdin_closed",
            Self::ProcessCancelPending => "process_cancel_pending",
            Self::ProcessPermissionDenied => "process_permission_denied",
            Self::SignalUnsupportedOnGuest => "signal_unsupported_on_guest",
            Self::ImageUnavailable => "image_unavailable",
            Self::ImageCacheFull => "image_cache_full",
            Self::ImageCorrupt => "image_corrupt",
            Self::ImageRejected => "image_rejected",
            Self::ImageFetchTimeout => "image_fetch_timeout",
            Self::CaptureFailed => "capture_failed",
            Self::CaptureFreezeFailed => "capture_freeze_failed",
            Self::CaptureStoreFailed => "capture_store_failed",
            Self::StartupFailed => "startup_failed",
            Self::StartupTimeout => "startup_timeout",
            Self::GuestNetworkUnavailable => "guest_network_unavailable",
            Self::CredentialInstallFailed => "credential_install_failed",
            Self::CredentialSpecInvalid => "credential_spec_invalid",
            Self::CredentialEnvPending => "credential_env_pending",
            Self::CredentialCaptureFailed => "credential_capture_failed",
            Self::DiskStale => "disk_stale",
        }
    }
}

/// An error code on the wire or in the journal. A newer peer may send a code
/// this build does not know; it is carried verbatim as [`WireErrorCode::Other`]
/// so it can be journaled and replayed byte-identically. The encoding is
/// canonical: a catalog spelling always decodes to [`WireErrorCode::Known`],
/// and `Other` is `[a-z_]{1,64}` outside the catalog. Serializing an `Other`
/// that breaks either rule fails, so it never reaches a frame or the journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireErrorCode {
    Known(SandboxErrorCode),
    Other(String),
}

pub const WIRE_ERROR_CODE_MAX_BYTES: usize = 64;

impl SandboxErrorCode {
    /// The catalog code for an exact wire spelling.
    pub fn from_wire(text: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|code| code.as_str() == text)
    }
}

impl WireErrorCode {
    /// Canonical decode: catalog spellings are `Known`, other well-formed
    /// codes are `Other`, anything else is `None`.
    pub fn parse(text: &str) -> Option<Self> {
        if let Some(code) = SandboxErrorCode::from_wire(text) {
            return Some(Self::Known(code));
        }
        valid_other_code(text).then(|| Self::Other(text.to_owned()))
    }
    /// True for every `Known` and for an `Other` in canonical form.
    pub fn is_canonical(&self) -> bool {
        match self {
            Self::Known(_) => true,
            Self::Other(text) => {
                valid_other_code(text) && SandboxErrorCode::from_wire(text).is_none()
            }
        }
    }
    pub fn as_str(&self) -> &str {
        match self {
            Self::Known(code) => code.as_str(),
            Self::Other(text) => text,
        }
    }
    /// The catalog code; `None` for a code this build does not know.
    pub fn known(&self) -> Option<SandboxErrorCode> {
        match self {
            Self::Known(code) => Some(*code),
            Self::Other(_) => None,
        }
    }
    /// Local comparisons match only catalog codes; `Other` never equals one.
    pub fn is(&self, code: SandboxErrorCode) -> bool {
        self.known() == Some(code)
    }
}

fn valid_other_code(text: &str) -> bool {
    (1..=WIRE_ERROR_CODE_MAX_BYTES).contains(&text.len())
        && text.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
}

impl From<SandboxErrorCode> for WireErrorCode {
    fn from(code: SandboxErrorCode) -> Self {
        Self::Known(code)
    }
}

impl PartialEq<SandboxErrorCode> for WireErrorCode {
    fn eq(&self, other: &SandboxErrorCode) -> bool {
        self.is(*other)
    }
}

impl std::fmt::Display for WireErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for WireErrorCode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if !self.is_canonical() {
            return Err(serde::ser::Error::custom("non-canonical error code"));
        }
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for WireErrorCode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).ok_or_else(|| serde::de::Error::custom("invalid error code"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_capability_serializes_snake_case() {
        let json = serde_json::to_string(&SandboxErrorCode::UnsupportedCapability).expect("json");
        assert_eq!(json, "\"unsupported_capability\"");
        let parsed: SandboxErrorCode = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed, SandboxErrorCode::UnsupportedCapability);
    }

    #[test]
    fn sandbox_not_running_serializes_snake_case() {
        let json = serde_json::to_string(&SandboxErrorCode::SandboxNotRunning).expect("json");
        assert_eq!(json, "\"sandbox_not_running\"");
        let parsed: SandboxErrorCode = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed, SandboxErrorCode::SandboxNotRunning);
    }

    #[test]
    fn guest_permission_denied_serializes_snake_case() {
        let json = serde_json::to_string(&SandboxErrorCode::GuestPermissionDenied).expect("json");
        assert_eq!(json, "\"guest_permission_denied\"");
        let parsed: SandboxErrorCode = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed, SandboxErrorCode::GuestPermissionDenied);
    }

    #[test]
    fn guest_operation_failed_serializes_snake_case() {
        let json = serde_json::to_string(&SandboxErrorCode::GuestOperationFailed).expect("json");
        assert_eq!(json, "\"guest_operation_failed\"");
        let parsed: SandboxErrorCode = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed, SandboxErrorCode::GuestOperationFailed);
    }

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ResultErrorEntry {
        message: String,
        resource: crate::results::FailureResource,
    }

    /// B1-K-2: the result-error catalog has exactly the fs/process/signal
    /// wire codes, and each fixed `resource` tag parses and matches its family.
    #[test]
    fn result_error_catalog_matches_wire_codes_and_resources() {
        use crate::results::FailureResource;
        let fixture = include_str!("../../../packages/config/src/sandbox-result-errors.json");
        let entries: std::collections::BTreeMap<String, ResultErrorEntry> =
            serde_json::from_str(fixture).expect("result errors json");
        let mut expected: Vec<String> = SandboxErrorCode::ALL
            .iter()
            .map(|code| {
                serde_json::from_value::<String>(serde_json::to_value(code).expect("serialize"))
                    .expect("wire name")
            })
            .filter(|code| {
                code.starts_with("fs_")
                    || code.starts_with("process_")
                    || code.starts_with("signal_")
            })
            .collect();
        expected.sort();
        assert_eq!(entries.keys().cloned().collect::<Vec<_>>(), expected);
        for (code, entry) in entries {
            assert!(!entry.message.is_empty(), "{code}");
            let family = if code.starts_with("fs_") {
                FailureResource::Filesystem
            } else {
                FailureResource::Process
            };
            assert_eq!(entry.resource, family, "{code}");
        }
    }

    #[test]
    fn wire_codes_match_shared_fixture() {
        let fixture = include_str!("../../../packages/config/src/sandbox-error-codes.json");
        let codes: Vec<String> = serde_json::from_str(fixture).expect("fixture json");
        let mut rust_codes: Vec<String> = SandboxErrorCode::ALL
            .iter()
            .map(|code| {
                code.assert_enumerated();
                serde_json::from_value(serde_json::to_value(code).expect("serialize"))
                    .expect("wire name")
            })
            .collect();
        let mut codes = codes;
        codes.sort();
        rust_codes.sort();
        assert_eq!(codes, rust_codes);
    }

    #[test]
    fn host_disconnect_expired_serializes_snake_case() {
        let json = serde_json::to_string(&SandboxErrorCode::HostDisconnectExpired).expect("json");
        assert_eq!(json, "\"host_disconnect_expired\"");
        let parsed: SandboxErrorCode = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed, SandboxErrorCode::HostDisconnectExpired);
        assert_eq!(parsed.as_str(), "host_disconnect_expired");
    }

    #[test]
    fn wire_error_code_is_canonical_and_open() {
        for code in SandboxErrorCode::ALL {
            let parsed: WireErrorCode =
                serde_json::from_value(serde_json::json!(code.as_str())).expect("known");
            assert_eq!(parsed, WireErrorCode::Known(*code));
            assert_eq!(serde_json::to_value(&parsed).unwrap(), code.as_str());
        }
        let future: WireErrorCode = serde_json::from_str("\"future_code\"").expect("open");
        assert_eq!(future, WireErrorCode::Other("future_code".into()));
        assert_eq!(serde_json::to_string(&future).unwrap(), "\"future_code\"");
        assert!(!future.is(SandboxErrorCode::Internal));
        assert_eq!(future.known(), None);
        let longest = "x".repeat(WIRE_ERROR_CODE_MAX_BYTES);
        assert!(WireErrorCode::parse(&longest).is_some());
        for bad in [
            "",
            "Upper",
            "dash-code",
            "digit1",
            "sp ace",
            &*"x".repeat(65),
        ] {
            assert!(WireErrorCode::parse(bad).is_none(), "{bad}");
            assert!(serde_json::from_value::<WireErrorCode>(serde_json::json!(bad)).is_err());
            // An Other that breaks the rules never serializes.
            assert!(serde_json::to_string(&WireErrorCode::Other(bad.into())).is_err());
        }
        assert!(serde_json::from_str::<WireErrorCode>("7").is_err());
        // Other never holds a catalog spelling.
        let aliased = WireErrorCode::Other("timeout".into());
        assert!(!aliased.is_canonical());
        assert!(serde_json::to_string(&aliased).is_err());
    }

    #[test]
    fn path_refused_serializes_snake_case() {
        let json = serde_json::to_string(&SandboxErrorCode::PathRefused).expect("json");
        assert_eq!(json, "\"path_refused\"");
        let parsed: SandboxErrorCode = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed, SandboxErrorCode::PathRefused);
    }
}
