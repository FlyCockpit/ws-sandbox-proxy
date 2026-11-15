//! Capability and inventory types exchanged during `hello`.

use serde::{Deserialize, Serialize};

use crate::version::SANDBOX_RELAY_PROTOCOL_VERSION;
use crate::{SANDBOX_BINARY_CHUNK_MAX_BYTES, SANDBOX_STREAM_WINDOW_CHUNKS};

/// Observational reconciler health, NOT packet evidence or dispatch authority.
/// Counts cover the current lease set; pending entries have not been inspected.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyReconcilerHealth {
    pub enabled: bool,
    pub last_pass_unix_ms: u64,
    pub verified: u32,
    pub drift: u32,
    pub inconclusive: u32,
    pub foreign: u32,
    pub absent: u32,
    pub pending: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeKind {
    Fake,
    IncusKvm,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DaemonCapabilities {
    pub protocol_version: String,
    pub binary_frames: bool,
    pub cancellation: bool,
    pub operation_wal: bool,
    pub host_inventory: bool,
    pub max_binary_chunk_bytes: usize,
    pub stream_window_chunks: usize,
    pub runtime_kind: RuntimeKind,
    /// M5 (C34): the host enforces recorded sandbox egress policies
    /// (deny-default). `false` until the runtime enforcement chunks land.
    pub egress_policy: bool,
    /// C52: the runtime can open guest terminals (`pty_capability`). The
    /// server opens a guest terminal only on a current session advertising this.
    pub terminal: bool,
    pub host_terminal: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub host_commands: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub host_files: bool,
    #[serde(
        default,
        deserialize_with = "crate::egress::present",
        skip_serializing_if = "Option::is_none"
    )]
    pub host_command_max_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub agent_policy_revision: u64,
    pub require_host_terminal_totp: bool,
    pub policy_revision: u64,
    pub host_managed_sandbox_ceiling: u32,
    /// Host lease ceiling in milliseconds; null means unlimited. Required on the wire.
    #[serde(deserialize_with = "Option::deserialize")]
    pub max_lease_ms: Option<u64>,
    /// Optional image-cache runtime features.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<crate::ImageCapabilitiesV11>,
    /// Optional resolver refusal diagnostics.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub egress_refused_hints: bool,
    /// Optional template start and ready command support.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub template_startup: bool,
    /// Optional credential runtime features.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<crate::CredentialCapabilitiesV11>,
    /// Required open-egress and guard capability evidence.
    pub egress: crate::EgressCapabilitiesV11,
    /// Required command-output chunk ceiling offered to the server.
    #[serde(deserialize_with = "crate::egress::present")]
    pub max_output_chunk_bytes: Option<u32>,
    /// Required support for per-entry inventory census results.
    pub census_entry_results: bool,
    /// Optional graceful quiesce support.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub quiesce: bool,
    /// Optional reattachment grace for detached sandbox terminals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_resume: Option<crate::TerminalResumeCapabilityV11>,
    /// Required support for receipts still being resolved after reconnect.
    pub pending_receipts: bool,
    /// Required support for per-entry connected expiry results.
    pub expiry_status_results: bool,
    /// Required observation ordering for connected expiry results.
    pub observation_fence: bool,
    /// Required support for retiring unknown commands on host proof.
    pub command_retire: bool,
    /// Optional guest sudo runtime support.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub guest_sudo: bool,
    /// Optional stopped-disk transfer support; requires image fetching.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disk_offload: bool,
}

/// The default finite host lease ceiling.
pub const DEFAULT_MAX_LEASE_MS: u64 = 86_400_000;
/// Smallest and largest finite host ceiling (`lease-limits.json`).
pub const LEASE_CEILING_MIN_MS: u64 = 300_000;
pub const LEASE_CEILING_MAX_MS: u64 = 2_073_600_000;

/// A reported ceiling is unlimited or within the shared finite range.
pub fn valid_lease_ceiling(value: Option<u64>) -> bool {
    value.is_none_or(|ms| (LEASE_CEILING_MIN_MS..=LEASE_CEILING_MAX_MS).contains(&ms))
}

impl Default for DaemonCapabilities {
    fn default() -> Self {
        Self {
            protocol_version: SANDBOX_RELAY_PROTOCOL_VERSION.to_string(),
            binary_frames: true,
            cancellation: true,
            operation_wal: true,
            host_inventory: true,
            max_binary_chunk_bytes: SANDBOX_BINARY_CHUNK_MAX_BYTES,
            stream_window_chunks: SANDBOX_STREAM_WINDOW_CHUNKS,
            runtime_kind: RuntimeKind::Unsupported,
            egress_policy: false,
            terminal: false,
            host_terminal: false,
            host_commands: false,
            host_files: false,
            host_command_max_ms: None,
            agent_policy_revision: 0,
            require_host_terminal_totp: true,
            policy_revision: 0,
            host_managed_sandbox_ceiling: 250,
            max_lease_ms: Some(DEFAULT_MAX_LEASE_MS),
            image: None,
            egress_refused_hints: false,
            template_startup: false,
            credentials: None,
            egress: crate::EgressCapabilitiesV11 {
                open: false,
                guard: false,
            },
            max_output_chunk_bytes: Some(crate::SANDBOX_OUTPUT_CHUNK_OFFER_BYTES as u32),
            census_entry_results: true,
            quiesce: false,
            terminal_resume: None,
            pending_receipts: true,
            expiry_status_results: true,
            observation_fence: true,
            command_retire: true,
            guest_sudo: false,
            disk_offload: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NegotiatedCapabilities {
    pub protocol_version: String,
    pub binary_frames: bool,
    pub cancellation: bool,
    pub max_binary_chunk_bytes: usize,
    pub stream_window_chunks: usize,
    /// Required command-output chunk ceiling accepted by the server.
    #[serde(deserialize_with = "crate::egress::present")]
    pub output_chunk_bytes: Option<u32>,
    /// Optional graceful quiesce support.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub quiesce: bool,
    /// Required support for per-entry inventory census results.
    pub census_entry_results: bool,
    /// Optional reattachment grace for detached sandbox terminals.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub terminal_resume: bool,
    /// Required support for receipts still being resolved after reconnect.
    pub pending_receipts: bool,
    /// Required support for per-entry connected expiry results.
    pub expiry_status_results: bool,
    /// Required observation ordering for connected expiry results.
    pub observation_fence: bool,
    /// Required support for retiring unknown commands on host proof.
    pub command_retire: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostInventorySnapshot {
    pub host_id: String,
    pub schedulable: bool,
    pub sandbox_count: u32,
}

/// Current-link policy report; sequence and epoch freshness are receiver checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostTerminalPolicyV11 {
    pub connection_epoch: u32,
    pub sequence: u64,
    pub host_terminal: bool,
    pub require_host_terminal_totp: bool,
    pub policy_revision: u64,
}
impl HostTerminalPolicyV11 {
    pub fn is_valid(&self) -> bool {
        self.connection_epoch > 0
            && self.connection_epoch <= i32::MAX as u32
            && self.sequence > 0
            && self.sequence <= 9_007_199_254_740_991
            && self.policy_revision <= 9_007_199_254_740_991
    }
}

/// Current-link host lease ceiling report (`host.lease-policy`). Same fences
/// as the terminal policy report: current socket, epoch, monotonic sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostLeasePolicyV11 {
    pub connection_epoch: u32,
    pub sequence: u64,
    /// Required on the wire; `null` means unlimited.
    #[serde(deserialize_with = "Option::deserialize")]
    pub max_lease_ms: Option<u64>,
}
/// WP7 (D9): the daemon is quiescing for a restart (`host.quiesce`). Fenced
/// like the policy reports: current epoch, monotonic sequence. The server
/// stops sending new `command.run` work and answers `host.quiesce.ack`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostQuiesceV11 {
    pub connection_epoch: u32,
    pub sequence: u64,
}
impl HostQuiesceV11 {
    pub fn is_valid(&self) -> bool {
        self.connection_epoch > 0
            && self.connection_epoch <= i32::MAX as u32
            && valid_quiesce_sequence(self.sequence)
    }
}

/// The server's answer to `host.quiesce`: from here on it holds new
/// `command.run` work for this host in its queue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostQuiesceAckV11 {
    pub sequence: u64,
}
impl HostQuiesceAckV11 {
    pub fn is_valid(&self) -> bool {
        valid_quiesce_sequence(self.sequence)
    }
}

fn valid_quiesce_sequence(sequence: u64) -> bool {
    sequence > 0 && sequence <= 9_007_199_254_740_991
}

impl HostLeasePolicyV11 {
    pub fn is_valid(&self) -> bool {
        self.connection_epoch > 0
            && self.connection_epoch <= i32::MAX as u32
            && self.sequence > 0
            && self.sequence <= 9_007_199_254_740_991
            && valid_lease_ceiling(self.max_lease_ms)
    }
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}
