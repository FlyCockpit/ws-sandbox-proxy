//! JSON control messages on the sandbox host relay WebSocket.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::capabilities::{DaemonCapabilities, HostInventorySnapshot, NegotiatedCapabilities};
use crate::command_limits::json_control_max_bytes;
use crate::egress::EgressPolicy;
use crate::error::{SandboxErrorCode, WireErrorCode};
use crate::ids::{valid_journal_identity, valid_terminal_id};
use crate::state::{OperationState, SandboxLifecycleState};
use crate::terminal::{TerminalCloseIntent, TerminalFence, valid_terminal_size};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolErrorDetail {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<ProtocolErrorReason>,
    /// Open code: a newer peer's code is carried verbatim as `Other`.
    pub code: WireErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox_id: Option<String>,
}

/// Which guest readiness check failed (`details.reason` of a
/// `guest_unavailable` create or cold reconnect). Constant labels only: never
/// guest output. Mirrors `READINESS_FAILURE_REASONS` in
/// `@wssp/sandbox-contracts`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessFailureReason {
    /// The guest agent did not answer within the readiness budget.
    AgentTimeout,
    /// The VM stopped and stayed stopped, or entered an error or other
    /// non-boot state, during readiness.
    VmNotRunning,
    /// The guest restarted more often than readiness tolerates.
    GuestRestarts,
    /// The instance architecture differs from the template's.
    Architecture,
    /// The declared guest user, uid or gid does not match.
    GuestUser,
    /// The guest user's HOME is missing, not writable or wrongly owned.
    GuestHome,
    /// The guest user's login shell is missing or differs.
    GuestShell,
    /// `$HOME/repo` is missing, not writable or wrongly owned.
    GuestRepo,
    /// A required guest tool (`setsid`, `python3`, ...) is missing.
    GuestTooling,
    /// A readiness check failed without a more specific reason.
    GuestCheck,
    /// `guestSudo` was requested but the daemon's grant could not make
    /// `sudo -n true` succeed for the guest user (sudo missing, unsafe
    /// parent directories, an invalid or ineffective drop-in).
    GuestSudoUnavailable,
    /// `guestSudo` is off but the image grants the guest user root
    /// statically (create-time hygiene audit; not a security control).
    GuestRootGranted,
    /// The create's disk is larger than the image's root, and the guest's
    /// root partition or filesystem did not grow to it (create-time check;
    /// guest-attested hygiene, not a security control).
    RootDiskNotGrown,
}

impl ReadinessFailureReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AgentTimeout => "agent_timeout",
            Self::VmNotRunning => "vm_not_running",
            Self::GuestRestarts => "guest_restarts",
            Self::Architecture => "architecture",
            Self::GuestUser => "guest_user",
            Self::GuestHome => "guest_home",
            Self::GuestShell => "guest_shell",
            Self::GuestRepo => "guest_repo",
            Self::GuestTooling => "guest_tooling",
            Self::GuestCheck => "guest_check",
            Self::GuestSudoUnavailable => "guest_sudo_unavailable",
            Self::GuestRootGranted => "guest_root_granted",
            Self::RootDiskNotGrown => "root_disk_not_grown",
        }
    }
}

/// Typed `reason` of an error detail. A capacity reason belongs only to
/// `host_capacity`, an egress refusal reason only to
/// `unsupported_capability`, a readiness reason only to `guest_unavailable`
/// ([`ProtocolErrorReason::fits`]); the server's `protocolErrorDetailSchema`
/// applies the same pairing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProtocolErrorReason {
    Capacity(crate::capacity_v11::CapacityReason),
    Egress(crate::EgressRefusalReason),
    Readiness(ReadinessFailureReason),
}

impl ProtocolErrorReason {
    pub fn fits(self, code: SandboxErrorCode) -> bool {
        match self {
            Self::Capacity(_) => code == SandboxErrorCode::HostCapacity,
            Self::Egress(_) => code == SandboxErrorCode::UnsupportedCapability,
            Self::Readiness(_) => code == SandboxErrorCode::GuestUnavailable,
        }
    }
    /// [`Self::fits`] for a wire code; false for every `Other` code, since a
    /// typed reason pairs only with its catalog code.
    pub fn fits_wire(self, code: &WireErrorCode) -> bool {
        code.known().is_some_and(|code| self.fits(code))
    }
    pub fn capacity(self) -> Option<crate::capacity_v11::CapacityReason> {
        match self {
            Self::Capacity(reason) => Some(reason),
            Self::Egress(_) | Self::Readiness(_) => None,
        }
    }
    pub fn egress(self) -> Option<crate::EgressRefusalReason> {
        match self {
            Self::Egress(reason) => Some(reason),
            Self::Capacity(_) | Self::Readiness(_) => None,
        }
    }
    pub fn readiness(self) -> Option<ReadinessFailureReason> {
        match self {
            Self::Readiness(reason) => Some(reason),
            Self::Capacity(_) | Self::Egress(_) => None,
        }
    }
}

impl From<ReadinessFailureReason> for ProtocolErrorReason {
    fn from(reason: ReadinessFailureReason) -> Self {
        Self::Readiness(reason)
    }
}

impl From<crate::capacity_v11::CapacityReason> for ProtocolErrorReason {
    fn from(reason: crate::capacity_v11::CapacityReason) -> Self {
        Self::Capacity(reason)
    }
}

impl From<crate::EgressRefusalReason> for ProtocolErrorReason {
    fn from(reason: crate::EgressRefusalReason) -> Self {
        Self::Egress(reason)
    }
}

/// A targeted never-issued answer; false also covers runtime observation errors.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AllocationVerdict {
    pub sandbox_owner_id: String,
    pub sandbox_id: String,
    pub settled_never_issued: bool,
}

fn valid_allocation_request(epoch: u64, barrier: u64, ids: &[String]) -> bool {
    epoch > 0
        && epoch <= i32::MAX as u64
        && barrier > 0
        && barrier <= 9_007_199_254_740_991
        && !ids.is_empty()
        && ids.len() <= 256
        && ids.iter().all(|id| crate::valid_inventory_sandbox_id(id))
        && ids.windows(2).all(|pair| pair[0] < pair[1])
}

// One definition supplies the public decoder and the private serde remote.
// No public Serialize implementation exists: even json! and direct Serializer
// calls must go through WireCodes::encode.
macro_rules! daemon_control {
    ($($body:tt)*) => {
        /// Daemon frames can only be encoded by `WireCodes::encode`.
        /// ```compile_fail
        /// let frame = sandbox_protocol::DaemonControlMessage::ReconcileComplete { pending_receipts: None };
        /// let _ = serde_json::json!(frame);
        /// ```
        /// ```compile_fail
        /// let frame = sandbox_protocol::DaemonControlMessage::ReconcileComplete { pending_receipts: None };
        /// let _ = serde::Serialize::serialize(&frame, serde_json::value::Serializer);
        /// ```
        /// ```compile_fail
        /// let frame = sandbox_protocol::DaemonControlMessage::ReconcileComplete { pending_receipts: None };
        /// let _ = serde_json::to_value(&frame);
        /// ```
        #[derive(Debug, Clone, Deserialize)]
        #[serde(tag = "type", rename_all = "camelCase", rename_all_fields = "camelCase", deny_unknown_fields)]
        pub enum DaemonControlMessage { $($body)* }

        #[derive(Serialize)]
        #[serde(remote = "DaemonControlMessage", tag = "type", rename_all = "camelCase", rename_all_fields = "camelCase")]
        enum DaemonControlWire { $($body)* }
    };
}
daemon_control! {
    #[serde(rename = "host.agent-policy")]
    HostAgentPolicy(crate::HostAgentPolicyV11),
    #[serde(rename = "host.policy.lower.result")]
    HostPolicyLowerResult(crate::HostPolicyLowerResultV11),
    #[serde(rename = "host.exec.started")]
    HostExecStarted(crate::HostExecStartedV11),
    #[serde(rename = "host.exec.rejected")]
    HostExecRejected(crate::HostExecRejectedV11),
    #[serde(rename = "host.exec.status")]
    HostExecStatus(crate::HostExecStatusV11),
    #[serde(rename = "host.exec.stdin.result")]
    HostExecStdinResult(crate::HostExecStdinResultV11),
    #[serde(rename = "host.file.result")]
    HostFileResult(crate::HostFileResultV11),

    #[serde(rename = "host.terminal-policy")]
    HostTerminalPolicy(crate::HostTerminalPolicyV11),
    #[serde(rename = "host.lease-policy")]
    HostLeasePolicy(crate::HostLeasePolicyV11),
    /// WP7: negotiated (`quiesce`); see `HostQuiesceV11`.
    #[serde(rename = "host.quiesce")]
    HostQuiesce(crate::HostQuiesceV11),
    #[serde(rename = "host.egress-state")]
    HostEgressState(crate::HostEgressStateV11),
    #[serde(rename = "tunnel.status")]
    TunnelStatus(crate::TunnelStatusV11),
    #[serde(rename = "tunnel.portsStatus")]
    TunnelPortsStatus(crate::TunnelPortsStatusV11),
    #[serde(rename = "process.started")]
    ProcessStarted {
        operation_id: String,
        sandbox_id: String,
        generation: u32,
        process_id: String,
        attempt: u32,
        pid: u32,
        boot_id: String,
        start_ticks: String,
        started_at: String,
        observed_at: String,
    },
    #[serde(rename = "operation.receipt.pruned")]
    OperationReceiptPruned {
        sandbox_owner_id: String,
        operation_id: String,
        sandbox_id: String,
        generation: u64,
        attempt: u64,
        idempotency_key: String,
        kind: String,
    },
    #[serde(rename = "private.config.ack")]
    PrivateConfigAck(crate::PrivateConfigAck),
    #[serde(rename = "private.config.refused")]
    PrivateConfigRefused(crate::PrivateConfigRefused),
    #[serde(rename = "hello")]
    Hello {
        id: String,
        protocol_version: String,
        supported_protocol_versions: Vec<String>,
        daemon: DaemonHello,
        inventory: HostInventorySnapshot,
        vm_capacity: crate::capacity_v11::VmCapacityV11,
        storage_pools: Vec<crate::capacity_v11::StoragePoolV11>,
        /// WP7: a (re)connect while quiescing for a restart. Sent only with
        /// the `quiesce` capability and never at its default, so other
        /// hellos stay byte-identical.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        quiescing: bool,
    },
    #[serde(rename = "journal.key.ack")]
    JournalKeyAck {
        connection_epoch: u64,
        key_version: u32,
        key_id: String,
    },
    #[serde(rename = "host.admission")]
    HostAdmission {
        journal_id: String,
        vm_capacity: crate::capacity_v11::VmCapacityV11,
        storage_pools: Vec<crate::capacity_v11::StoragePoolV11>,
        connection_epoch: u64,
        runtime_kind: crate::RuntimeKind,
        schedulable: bool,
        egress_policy: bool,
        terminal: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        image: Option<crate::ImageAdmissionV11>,
        /// Static `egressOpen` feature bit (`daemonFeatures.egressOpen`): the
        /// runtime can enforce open-mode policies. Omitted when false.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        egress_open: bool,
    },
    #[serde(rename = "availability.result")]
    AvailabilityResult {
        request_id: String,
        connection_epoch: u64,
        page: u64,
        entries: Vec<crate::AvailabilityVerdict>,
    },
    #[serde(rename = "inventory.update")]
    InventoryUpdate {
        id: String,
        connection_epoch: u32,
        observation_sequence: u64,
        inventory: HostInventorySnapshot,
        storage_pools: Vec<crate::capacity_v11::StorageHealthV11>,
    },
    #[serde(rename = "heartbeat")]
    Heartbeat {
        id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        sent_at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        policy_reconciler: Option<crate::PolicyReconcilerHealth>,
    },
    #[serde(rename = "operation.progress")]
    OperationProgress {
        id: String,
        operation_id: String,
        sandbox_id: String,
        generation: u64,
        attempt: u64,
        state: OperationState,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        progress: Option<crate::OperationProgressV11>,
    },
    #[serde(rename = "operation.result")]
    OperationResult {
        id: String,
        operation_id: String,
        sandbox_id: String,
        generation: u64,
        attempt: u64,
        state: OperationState,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<ProtocolErrorDetail>,
        #[serde(skip_serializing_if = "Option::is_none")]
        result: Option<serde_json::Value>,
    },
    #[serde(rename = "operation.receipt")]
    OperationReceipt {
        sandbox_owner_id: String,
        operation_id: String,
        sandbox_id: String,
        generation: u64,
        attempt: u64,
        body_hash: String,
        idempotency_key: String,
        kind: String,
        state: OperationState,
        result: Option<serde_json::Value>,
        error: Option<ProtocolErrorDetail>,
        /// The launch mode the host journaled for this
        /// launch (a restore resolves with create proofs). Omitted when
        /// absent, so other receipts are byte-identical.
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "crate::egress::present"
        )]
        launch_mode: Option<crate::LaunchMode>,
    },
    /// Reconnect-time adoption of an attempt this host journaled under an
    /// earlier connection epoch and still owns (sent before
    /// `reconcile.complete`). The server answers `operation.adopt.result`.
    #[serde(rename = "operation.adopt")]
    OperationAdopt {
        sandbox_owner_id: String,
        operation_id: String,
        sandbox_id: String,
        generation: u64,
        attempt: u64,
        body_hash: String,
        idempotency_key: String,
        kind: String,
        phase: AdoptPhase,
        /// The next stdin sequence the host expects; `None` once the stream
        /// is closed or the operation is not a command.
        stdin_next_sequence: Option<u64>,
    },
    /// Reconnect dispatch audit (before `reconcile.complete`): ask for the
    /// next page of attempts the server still believes it dispatched to this
    /// host on an older epoch and never saw acknowledged.
    #[serde(rename = "dispatch.audit.request")]
    DispatchAuditRequest { page: u64 },
    /// The host's verdict for every entry of one audit page. `received:
    /// false` is a positive proof that this process attached that epoch and
    /// its journal never recorded the operation.
    #[serde(rename = "dispatch.audit.result")]
    DispatchAuditResult {
        page: u64,
        entries: Vec<DispatchAuditVerdict>,
    },
    #[serde(rename = "allocation.attest.result")]
    AllocationAttestResult {
        connection_epoch: u64,
        barrier: u64,
        journal_id: String,
        entries: Vec<AllocationVerdict>,
    },
    #[serde(rename = "sandbox.inventory")]
    SandboxInventory {
        page: u64,
        complete: bool,
        entries: Vec<crate::InventoryEntry>,
    },
    #[serde(rename = "reconcile.complete")]
    ReconcileComplete {
        /// WP2 (D11), only with `pendingReceipts`: operations whose receipt the
        /// host is still resolving. The server leaves them unsettled (no
        /// interim unknown outcome) until their receipt arrives or this
        /// session ends. At most [`crate::PENDING_RECEIPTS_MAX`].
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "crate::egress::present"
        )]
        pending_receipts: Option<Vec<String>>,
    },
    /// After reconciliation: host-enforced expiries whose failure state changed
    /// (failed, still failing, or recovered), and evidence the host re-offers
    /// until the server judged it. Explicit evidence only; silence here means
    /// nothing.
    #[serde(rename = "sandbox.expiry_status")]
    SandboxExpiryStatus {
        entries: Vec<crate::InventoryEntry>,
        /// Only with `expiryStatusResults`: strictly increasing per session;
        /// answered by `sandbox.expiry_status.ack` with the same batch.
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "crate::egress::present"
        )]
        batch: Option<u64>,
        /// Only with `observationFence`, on every batch: the observation the
        /// batch's entries come from, numbered from 1 per session and
        /// shared by its batches. An observation starts only after every
        /// batch of the previous one was acknowledged, so the server rejects
        /// non-expired evidence from any observation that may predate a
        /// lifecycle result it received.
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "crate::egress::present"
        )]
        observation: Option<u64>,
    },
    #[serde(rename = "file.chunk.ack")]
    FileChunkAck {
        operation_id: String,
        generation: u64,
        attempt: u64,
        sequence: u64,
        offset: u64,
    },
    #[serde(rename = "sandbox.probe.result")]
    SandboxProbeResult { request_id: String, state: String },
    #[serde(rename = "image.verify.result")]
    ImageVerifyResult {
        request_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        incus_fingerprint: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        architecture: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<ProtocolErrorDetail>,
        /// Compressed image size and format (peer-mode placement facts).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        size_bytes: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        format: Option<String>,
    },
    #[serde(rename = "image.fetch.request")]
    ImageFetchRequest(crate::ImageFetchRequestV11),
    #[serde(rename = "image.cached")]
    ImageCached(crate::ImageCachedV11),
    #[serde(rename = "image.evicted")]
    ImageEvicted(crate::ImageEvictedV11),
    #[serde(rename = "image.fetch.failed")]
    ImageFetchFailed(crate::ImageFetchFailedV11),
    #[serde(rename = "image.cache.census")]
    ImageCacheCensus(crate::ImageCacheCensusV11),
    #[serde(rename = "image.links.request")]
    ImageLinksRequest(crate::ImageLinksRequestV11),
    #[serde(rename = "image.part.ack")]
    ImagePartAck(crate::ImagePartAckV11),
    #[serde(rename = "image.upload.begin")]
    ImageUploadBegin(crate::ImageUploadBeginV11),
    #[serde(rename = "image.upload.parts")]
    ImageUploadParts(crate::ImageUploadPartsV11),
    #[serde(rename = "image.upload.complete")]
    ImageUploadComplete(crate::ImageTransferRefV11),
    #[serde(rename = "image.job.resume")]
    ImageJobResume(crate::ImageJobResumeV11),
    #[serde(rename = "image.job.failed")]
    ImageJobFailed(crate::ImageJobFailedV11),
    #[serde(rename = "image.upload.progress")]
    ImageUploadProgress(crate::ImageUploadProgressV11),
    #[serde(rename = "image.upload.renew")]
    ImageUploadRenew(crate::ImageUploadRenewV11),
    // Disk offload; only on `diskOffload` sessions.
    #[serde(rename = "disk.upload.begin")]
    DiskUploadBegin(crate::DiskUploadBeginV11),
    #[serde(rename = "disk.upload.parts")]
    DiskUploadParts(crate::DiskUploadPartsV11),
    #[serde(rename = "disk.upload.resume")]
    DiskUploadResume(crate::DiskUploadResumeV11),
    #[serde(rename = "disk.upload.complete")]
    DiskUploadComplete(crate::DiskUploadCompleteV11),
    #[serde(rename = "disk.offload.failed")]
    DiskOffloadFailed(crate::DiskOffloadFailedV11),
    #[serde(rename = "disk.evict.request")]
    DiskEvictRequest(crate::DiskEvictRequestV11),
    #[serde(rename = "disk.evicted")]
    DiskEvicted(crate::DiskEvictedV11),
    #[serde(rename = "disk.discarded")]
    DiskDiscarded(crate::DiskDiscardedV11),
    #[serde(rename = "disk.offload.inventory")]
    DiskOffloadInventory(crate::DiskOffloadInventoryV11),
    #[serde(rename = "disk.offload.released")]
    DiskOffloadReleased(crate::DiskOffloadReleasedV11),
    /// B12: names the sandbox's allowlist resolver refused (build hints).
    #[serde(rename = "egress.refused")]
    EgressRefused(crate::EgressRefusedV11),
    #[serde(rename = "credential.spec.request")]
    CredentialSpecRequest(crate::CredentialSpecRequestV11),
    #[serde(rename = "credential.bundle.request")]
    CredentialBundleRequest(crate::CredentialBundleRequestV11),
    #[serde(rename = "credential.capture.begin")]
    CredentialCaptureBegin(crate::CredentialCaptureBeginV11),
    #[serde(rename = "credential.capture.chunk")]
    CredentialCaptureChunk(crate::CredentialCaptureChunkV11),
    #[serde(rename = "credential.installed")]
    CredentialInstalled(crate::CredentialInstalledV11),
    #[serde(rename = "credential.scrubbed")]
    CredentialScrubbed(crate::CredentialScrubbedV11),
    #[serde(rename = "credential.return.key.ack")]
    CredentialReturnKeyAck(crate::CredentialReturnKeyAckV11),
    #[serde(rename = "credential.census")]
    CredentialCensus(crate::CredentialCensusV11),
    #[serde(rename = "credential.quarantine.discarded")]
    CredentialQuarantineDiscarded(crate::CredentialQuarantineDiscardedV11),
    /// The PTY is open (answers `terminal.open`), reattached (answers
    /// `terminal.resume`, with `output_seq`) or a resize was applied
    /// (answers `terminal.resize`); `request_id` echoes the request.
    #[serde(rename = "terminal.ready")]
    TerminalReady {
        request_id: String,
        fence: TerminalFence,
        rows: u16,
        cols: u16,
        /// WP8, only on the answer to `terminal.resume`: the sequence of the
        /// next output frame (>= the requested `next_output_seq`).
        #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "crate::terminal::present_terminal_field")]
        output_seq: Option<u64>,
    },
    /// Credit: every server→host input frame up to `sequence` was written.
    #[serde(rename = "terminal.ack")]
    TerminalAck { fence: TerminalFence, sequence: u64 },
    /// The session's end. No intent and no error: the shell exited on its
    /// own. `intent`: the runtime or daemon closed it. `error`: the open was
    /// refused before any PTY existed, or the session was closed for a
    /// protocol violation. `request_id` echoes the `terminal.close` or
    /// `terminal.open` that caused it, if any. It is the host's final frame
    /// of the session, except after `reaped: false` (the PTY child's reap is
    /// uncertain and its capacity stays charged): the host's reconciliation
    /// sweep then sends ONE more, bare `terminal.exit` for the same fence
    /// (`reaped: true`, no request id, intent, error or exit code) once the
    /// reap is confirmed, and that one is final (C55).
    #[serde(rename = "terminal.exit")]
    TerminalExit {
        #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "crate::terminal::present_terminal_field")]
        request_id: Option<String>,
        fence: TerminalFence,
        #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "crate::terminal::present_terminal_field")]
        exit_code: Option<i32>,
        #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "crate::terminal::present_terminal_field")]
        intent: Option<TerminalCloseIntent>,
        reaped: bool,
        #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "crate::terminal::present_terminal_field")]
        error: Option<ProtocolErrorDetail>,
    },
    /// The channel's process is running; `pty` is the applied PTY size.
    #[serde(rename = "channel.ready")]
    ChannelReady {
        fence: crate::ChannelFence,
        #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "crate::terminal::present_terminal_field")]
        pty: Option<crate::ChannelPtySize>,
    },
    /// Cumulative credit: the highest written `stdin` `seq`.
    #[serde(rename = "channel.ack")]
    ChannelAck { fence: crate::ChannelFence, stream: crate::ChannelStream, seq: u64 },
    /// End of `stdout` or `stderr` after `frames` data frames.
    #[serde(rename = "channel.eof")]
    ChannelEof { fence: crate::ChannelFence, stream: crate::ChannelStream, frames: u64 },
    /// A non-fatal refusal of one request on a live channel.
    #[serde(rename = "channel.error")]
    ChannelError { fence: crate::ChannelFence, code: crate::ChannelNotice },
    /// The channel's last frame, sent after every output frame and eof. At
    /// most one of `exit_code` and `signal`.
    #[serde(rename = "channel.exit")]
    ChannelExit {
        fence: crate::ChannelFence,
        #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "crate::terminal::present_terminal_field")]
        exit_code: Option<i32>,
        #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "crate::terminal::present_terminal_field")]
        signal: Option<u8>,
        #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "crate::terminal::present_terminal_field")]
        intent: Option<crate::ChannelCloseIntent>,
        #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "crate::terminal::present_terminal_field")]
        error: Option<ProtocolErrorDetail>,
        reaped: bool,
        frames: crate::ChannelExitFrames,
    },
}

struct DaemonControlEncoder<'a>(&'a DaemonControlMessage);
impl Serialize for DaemonControlEncoder<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        DaemonControlWire::serialize(self.0, serializer)
    }
}

impl From<crate::results::ProcessStarted> for DaemonControlMessage {
    fn from(started: crate::results::ProcessStarted) -> Self {
        Self::ProcessStarted {
            operation_id: started.operation_id,
            sandbox_id: started.sandbox_id,
            generation: started.generation,
            process_id: started.process_id,
            attempt: started.attempt,
            pid: started.pid,
            boot_id: started.boot_id,
            start_ticks: started.start_ticks,
            started_at: started.started_at,
            observed_at: started.observed_at,
        }
    }
}

/// One attempt the server may have lost in transit to this host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DispatchAuditEntry {
    pub sandbox_owner_id: String,
    pub operation_id: String,
    pub sandbox_id: String,
    pub generation: u64,
    pub attempt: u64,
    pub connection_epoch: u64,
    pub idempotency_key: String,
    pub kind: String,
}

/// The host's verdict on one audited attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DispatchAuditVerdict {
    pub operation_id: String,
    pub generation: u64,
    pub attempt: u64,
    pub received: bool,
}

/// Bound on one dispatch-audit page.
pub const DISPATCH_AUDIT_PAGE_MAX: usize = 64;
/// WP2 (D11): the most receipts one `reconcile.complete` may name as still
/// resolving: the host's global bound on in-flight receipt resolutions.
pub const PENDING_RECEIPTS_MAX: usize = 4;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// `pendingReceipts`: at most [`PENDING_RECEIPTS_MAX`] distinct operation ids.
pub fn valid_pending_receipts(ids: &[String]) -> bool {
    ids.len() <= PENDING_RECEIPTS_MAX
        && ids.iter().all(|id| crate::valid_terminal_id(id))
        && ids
            .iter()
            .enumerate()
            .all(|(index, id)| !ids[..index].contains(id))
}

/// The journal phase an adopted attempt reached on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AdoptPhase {
    /// Intent journaled; no effect issued yet.
    Intent,
    /// An effect may have been issued.
    Effect,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DaemonHello {
    pub host_id: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub capabilities: DaemonCapabilities,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationDispatch {
    pub sandbox_owner_id: String,
    /// Required pooled binding for launch and cleanup dispatches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allocation: Option<crate::capacity_v11::PinnedAllocationV11>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::vm_size::optional_dimension"
    )]
    pub cpu_count: Option<u32>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::vm_size::optional_dimension"
    )]
    pub memory_mi_b: Option<u32>,
    #[serde(default)]
    pub template_revision_id: Option<String>,
    #[serde(default)]
    pub verification_connection_epoch: Option<u64>,

    #[serde(default)]
    pub lease: Option<crate::HostLease>,
    pub operation_id: String,
    pub sandbox_id: String,
    pub idempotency_key: String,
    pub kind: String,
    pub generation: u64,
    pub attempt: u64,
    #[serde(default)]
    pub template_digest: Option<String>,
    #[serde(default)]
    pub incus_fingerprint: Option<String>,
    #[serde(default)]
    pub architecture: Option<String>,
    #[serde(default)]
    pub guest_uid: Option<u32>,
    #[serde(default)]
    pub guest_gid: Option<u32>,
    #[serde(default)]
    pub guest_home: Option<String>,
    #[serde(default)]
    pub guest_shell: Option<String>,
    #[serde(default)]
    pub incus_name: Option<String>,
    #[serde(default)]
    pub argv: Option<Vec<String>>,
    #[serde(default)]
    pub script: Option<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub stdin_sequence: Option<u64>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub dest_path: Option<String>,
    #[serde(default)]
    pub recursive: Option<bool>,
    #[serde(default)]
    pub max_depth: Option<u32>,
    #[serde(default)]
    pub env: Option<Vec<(String, String)>>,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub signal: Option<String>,
    #[serde(default)]
    pub body_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest_scheme: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_config: Option<crate::PrivateConfigRef>,
    /// Normalized immutable egress policy on VM launches (M5, C34). The host
    /// applies it verbatim; it never re-derives policy from guest metadata.
    #[serde(default)]
    pub egress_policy: Option<EgressPolicy>,
    #[serde(default)]
    pub egress_policy_hash: Option<String>,
    #[serde(default)]
    pub file_size: Option<u64>,
    #[serde(default)]
    pub file_sha256: Option<String>,
    /// Server-minted immutable process identity for command.run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_id: Option<String>,
    /// Full qualified target for process.signal (4b). The host
    /// revalidates it against its own bound birth before any effect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<crate::results::ProcessRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_operation_id: Option<String>,
    /// Typed results are selected per dispatch and retained exactly in receipts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_version: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation: Option<crate::results::host::ResultContinuation>,
    /// Planned image fetch (only to hosts advertising `image.fetch`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<crate::DispatchImageV11>,
    /// `sandbox.capture` body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture: Option<crate::DispatchCaptureV11>,
    /// Template build binding; `sandbox.create` only (see `build.rs`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<crate::DispatchBuildV11>,
    /// Guest root for a build step; `command.run` on build records only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as: Option<crate::RunAsV11>,
    /// Recipe COPY through the daemon's fixed helper; `command.run` on build
    /// records only, implies root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_copy: Option<crate::BuildCopyV11>,
    /// Template start/ready commands; launches only (see `startup.rs`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub startup: Option<crate::DispatchStartupV11>,
    /// Credential spec reference; fetched with
    /// `credential.spec.request`, never inline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_spec: Option<crate::CredentialSpecRefV11>,
    /// `skip` on a stop/kill; absent means capture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_capture: Option<crate::CredentialCaptureMode>,
    /// `system` on a stop/kill written by the expiry, access or readiness
    /// writer (never fails on a capture failure); absent is a user stop/kill.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_teardown: Option<crate::CredentialTeardownOrigin>,
    /// Guest sudo grant (`sandbox.create` / `sandbox.reconnect` only). Present
    /// only as `true`; an explicit `false` is refused (one encoding per
    /// meaning, so absent fields keep every existing receipt digest).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "true_only"
    )]
    pub guest_sudo: Option<bool>,
    /// The guest may reach root (`guestSudo` or a root-tainted revision):
    /// UNKNOWN commands retire on host proof only. Same encoding rule.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "true_only"
    )]
    pub guest_root: Option<bool>,
    /// A `sandbox.reconnect` that boots a new root
    /// from the stored disk (with `launchMode: new_root` and a `fetch`
    /// image of the same fingerprint). Only to `diskOffload` daemons.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::egress::present"
    )]
    pub restore: Option<crate::DispatchRestoreV11>,
    /// The operation's immutable launch mode (launches only).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::egress::present"
    )]
    pub launch_mode: Option<crate::LaunchMode>,
    /// §8.1: a cold reconnect of a cached offloaded copy.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::egress::present"
    )]
    pub expect_disk: Option<crate::DispatchExpectDiskV11>,
    /// N1: the restored lineage's base image, for binding; absent for a
    /// template lineage.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::egress::present"
    )]
    pub disk_base_fingerprint: Option<String>,
    /// The sandbox's declared tunnel ports (launches of a tunnel sandbox
    /// only, possibly empty): compiled into the recorded ACL plan as the one
    /// host→guest ingress allow, with the guest address pinned.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::tunnel::deserialize_tunnel_ports"
    )]
    pub tunnel_ports: Option<Vec<u16>>,
    /// The revision of `tunnel_ports` (with them only): a freshly
    /// materialized plan records it, so a `tunnel.ports` of an older
    /// revision never applies after the launch.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::egress::present"
    )]
    pub tunnel_ports_revision: Option<u64>,
}

/// `Some(true)` only: an explicit `false` is a second spelling of absent.
fn true_only<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<bool>, D::Error> {
    if bool::deserialize(deserializer)? {
        Ok(Some(true))
    } else {
        Err(serde::de::Error::custom(
            "guest privilege fields are omitted when false",
        ))
    }
}

impl std::fmt::Debug for OperationDispatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperationDispatch")
            .field("operation_id", &self.operation_id)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AllocationProbe {
    pub sandbox_owner_id: String,
    pub sandbox_id: String,
    pub allocation: crate::capacity_v11::PinnedAllocationV11,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ServerControlMessage {
    #[serde(rename = "host.policy.lower")]
    HostPolicyLower(crate::HostPolicyLowerV11),
    #[serde(rename = "tunnel.apply")]
    TunnelApply(crate::TunnelApplyV11),
    #[serde(rename = "tunnel.clear")]
    TunnelClear(crate::TunnelClearV11),
    #[serde(rename = "tunnel.ports")]
    TunnelPorts(crate::TunnelPortsV11),
    #[serde(rename = "host.exec.start")]
    HostExecStart(crate::HostExecStartV11),
    #[serde(rename = "host.exec.poll")]
    HostExecPoll(crate::HostExecPollV11),
    #[serde(rename = "host.exec.stdin")]
    HostExecStdin(crate::HostExecStdinV11),
    #[serde(rename = "host.exec.cancel")]
    HostExecCancel(crate::HostExecCancelV11),
    #[serde(rename = "host.file.request")]
    HostFileRequest(crate::HostFileRequestV11),

    #[serde(rename = "host.terminal-policy.raise")]
    HostTerminalPolicyRaise {
        connection_epoch: u32,
        request_id: String,
    },
    #[serde(rename = "allocation.attest.request")]
    AllocationAttestRequest {
        connection_epoch: u64,
        barrier: u64,
        sandbox_ids: Vec<String>,
        // Required exact-root probes for the sole 1.0 contract.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        allocations: Option<Vec<AllocationProbe>>,
    },
    #[serde(rename = "private.config.install")]
    PrivateConfigInstall(crate::PrivateConfigInstall),
    #[serde(rename = "journal.key.install")]
    JournalKeyInstall(crate::JournalKeyInstall),
    #[serde(rename = "file.chunk.ack")]
    FileChunkAck {
        operation_id: String,
        generation: u64,
        attempt: u64,
        sequence: u64,
        offset: u64,
    },
    #[serde(rename = "command.output.ack")]
    CommandOutputAck {
        operation_id: String,
        generation: u64,
        attempt: u64,
        sequence: u64,
        offset: u64,
    },
    #[serde(rename = "hello.ok")]
    HelloOk {
        id: String,
        protocol_version: String,
        capabilities: NegotiatedCapabilities,
        #[serde(default)]
        supported_protocol_versions: Vec<String>,
        host_owner_id: String,
        /// Required connection fence: the server's
        /// connection epoch every terminal fence must carry.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        connection_epoch: Option<u64>,
    },
    #[serde(rename = "receipt.confirmed")]
    ReceiptConfirmed(crate::ReceiptConfirmation),
    #[serde(rename = "receipt.pruned.ack")]
    ReceiptPrunedAck(crate::PrunedReceiptAck),
    #[serde(rename = "receipt.ack")]
    ReceiptAck { operation_id: String },
    #[serde(rename = "dispatch.audit.page")]
    DispatchAuditPage {
        page: u64,
        complete: bool,
        entries: Vec<DispatchAuditEntry>,
    },
    #[serde(rename = "operation.adopt.result")]
    OperationAdoptResult {
        operation_id: String,
        generation: u64,
        attempt: u64,
        adopted: bool,
    },
    #[serde(rename = "inventory.ack")]
    InventoryAck {
        page: u64,
        /// One per page entry, in order; only with `censusEntryResults`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        entry_results: Option<Vec<crate::CensusEntryResult>>,
    },
    /// WP2, only with `expiryStatusResults`: the judgement of one
    /// `sandbox.expiry_status` batch, one result per entry, in order.
    #[serde(rename = "sandbox.expiry_status.ack")]
    SandboxExpiryStatusAck {
        batch: u64,
        entry_results: Vec<crate::CensusEntryResult>,
    },
    #[serde(rename = "heartbeat.pong")]
    HeartbeatPong { id: String, received_at: String },
    #[serde(rename = "operation.dispatch")]
    OperationDispatch(Box<OperationDispatch>),
    #[serde(rename = "operation.cancel")]
    OperationCancel {
        operation_id: String,
        generation: u64,
        attempt: u64,
        reason: SandboxErrorCode,
    },
    #[serde(rename = "sandbox.state")]
    SandboxState {
        sandbox_id: String,
        generation: u64,
        state: SandboxLifecycleState,
    },
    #[serde(rename = "protocol.error")]
    ProtocolError {
        failure: SandboxErrorCode,
        message: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        operation_id: Option<String>,
    },
    #[serde(rename = "sandbox.probe.request")]
    SandboxProbeRequest {
        incus_fingerprint: String,
        request_id: String,
        sandbox_owner_id: String,
        host_owner_id: String,
        host_id: String,
        sandbox_id: String,
        generation: u64,
        architecture: String,
        guest_uid: u32,
        guest_gid: u32,
        guest_home: String,
        guest_shell: String,
    },
    #[serde(rename = "availability.request")]
    AvailabilityRequest {
        request_id: String,
        connection_epoch: u64,
        page: u64,
        bindings: Vec<crate::AvailabilityBinding>,
    },
    #[serde(rename = "image.verify.request")]
    ImageVerifyRequest {
        request_id: String,
        image_ref: String,
        expected_architecture: String,
    },
    /// Open a PTY for the fenced sandbox generation. The host takes the guest
    /// identity and template binding from its own journal, never the frame.
    #[serde(rename = "terminal.open")]
    TerminalOpen {
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "crate::terminal::present_terminal_field"
        )]
        host_policy: Option<crate::HostTerminalOpenPolicyV11>,
        request_id: String,
        fence: TerminalFence,
        rows: u16,
        cols: u16,
        /// Guest opens only: the shell's working directory (the revision's
        /// default cwd); absent means the guest home.
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "crate::terminal::present_terminal_field"
        )]
        cwd: Option<String>,
    },
    #[serde(rename = "terminal.resize")]
    TerminalResize {
        request_id: String,
        fence: TerminalFence,
        rows: u16,
        cols: u16,
    },
    /// WP8: reattach a detached sandbox PTY (only to a node that negotiated
    /// `terminalResume`, only after its `reconcile.complete`). `fence.sessionId`
    /// is the terminal id; the operation id and epoch are this connection's.
    /// Answered by `terminal.ready` with `output_seq`, or `terminal.exit`.
    #[serde(rename = "terminal.resume")]
    TerminalResume {
        request_id: String,
        fence: TerminalFence,
        next_output_seq: u64,
        rows: u16,
        cols: u16,
    },
    /// Explicit close intent (distinct from a dropped socket). The host
    /// answers with the session's final `terminal.exit`.
    #[serde(rename = "terminal.close")]
    TerminalClose {
        request_id: String,
        fence: TerminalFence,
        intent: TerminalCloseIntent,
    },
    /// Credit: every host→server output frame up to `sequence` was delivered.
    #[serde(rename = "terminal.ack")]
    TerminalAck { fence: TerminalFence, sequence: u64 },
    /// Open a channel (a PTY shell, an exec, or a byte stream to a guest
    /// loopback TCP `port` or guest Unix socket `path`) in the fenced sandbox
    /// generation. The host takes the guest identity from its own journal,
    /// never the frame. Answered by `channel.ready` or `channel.exit`.
    #[serde(rename = "channel.open")]
    ChannelOpen {
        fence: crate::ChannelFence,
        kind: crate::ChannelKind,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "crate::terminal::present_terminal_field"
        )]
        argv: Option<Vec<String>>,
        login: bool,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "crate::terminal::present_terminal_field"
        )]
        cwd: Option<String>,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "crate::terminal::present_terminal_field"
        )]
        env: Option<std::collections::BTreeMap<String, String>>,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "crate::terminal::present_terminal_field"
        )]
        pty: Option<crate::ChannelPtyParams>,
        /// `tcp` only: the guest loopback port (never a host).
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "crate::terminal::present_terminal_field"
        )]
        port: Option<u16>,
        /// `unix` only: the absolute guest socket path.
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "crate::terminal::present_terminal_field"
        )]
        path: Option<String>,
    },
    /// Cumulative credit: the highest delivered output `seq` of `stream`
    /// (`stdout` or `stderr`).
    #[serde(rename = "channel.ack")]
    ChannelAck {
        fence: crate::ChannelFence,
        stream: crate::ChannelStream,
        seq: u64,
    },
    /// End of `stdin` after `frames` data frames.
    #[serde(rename = "channel.eof")]
    ChannelEof {
        fence: crate::ChannelFence,
        stream: crate::ChannelStream,
        frames: u64,
    },
    /// PTY channels only.
    #[serde(rename = "channel.resize")]
    ChannelResize {
        fence: crate::ChannelFence,
        rows: u16,
        cols: u16,
    },
    /// Exec channels only.
    #[serde(rename = "channel.signal")]
    ChannelSignal {
        fence: crate::ChannelFence,
        signal: crate::ChannelSignal,
    },
    /// `client` is a normal close; any other intent kill-closes the channel.
    #[serde(rename = "channel.close")]
    ChannelClose {
        fence: crate::ChannelFence,
        intent: crate::ChannelCloseIntent,
    },
    #[serde(rename = "image.fetch.grant")]
    ImageFetchGrant(crate::ImageFetchGrantV11),
    #[serde(rename = "image.fetch.refused")]
    ImageFetchRefused(crate::ImageFetchRefusedV11),
    #[serde(rename = "image.serve.request")]
    ImageServeRequest(crate::ImageServeRequestV11),
    #[serde(rename = "image.publish.request")]
    ImagePublishRequest(crate::ImagePublishRequestV11),
    #[serde(rename = "image.links.grant")]
    ImageLinksGrant(crate::ImageLinksGrantV11),
    #[serde(rename = "image.upload.grant")]
    ImageUploadGrant(crate::ImageUploadGrantV11),
    #[serde(rename = "image.job.resume.result")]
    ImageJobResumeResult(crate::ImageJobResumeResultV11),
    #[serde(rename = "image.job.cancel")]
    ImageJobCancel(crate::ImageJobCancelV11),
    #[serde(rename = "image.release")]
    ImageRelease(crate::ImageReleaseV11),
    #[serde(rename = "image.cache.census.ack")]
    ImageCacheCensusAck(crate::ImageCacheCensusAckV11),
    #[serde(rename = "report.ack")]
    ReportAck(crate::ReportAckV11),
    // Disk offload; only to `diskOffload` sessions.
    #[serde(rename = "disk.offload.request")]
    DiskOffloadRequest(crate::DiskOffloadRequestV11),
    #[serde(rename = "disk.offload.stored")]
    DiskOffloadStored(crate::DiskOffloadStoredV11),
    #[serde(rename = "disk.offload.cancel")]
    DiskOffloadCancel(crate::DiskOffloadCancelV11),
    #[serde(rename = "disk.upload.grant")]
    DiskUploadGrant(crate::DiskUploadGrantV11),
    #[serde(rename = "disk.upload.resumed")]
    DiskUploadResumed(crate::DiskUploadResumedV11),
    #[serde(rename = "disk.evict.suggest")]
    DiskEvictSuggest(crate::DiskEvictSuggestV11),
    #[serde(rename = "disk.evict.grant")]
    DiskEvictGrant(crate::DiskEvictGrantV11),
    #[serde(rename = "disk.evict.refused")]
    DiskEvictRefused(crate::DiskEvictRefusedV11),
    #[serde(rename = "disk.discard")]
    DiskDiscard(crate::DiskDiscardV11),
    #[serde(rename = "credential.return.key")]
    CredentialReturnKey(crate::CredentialReturnKeyV11),
    #[serde(rename = "credential.spec.chunk")]
    CredentialSpecChunk(crate::CredentialSpecChunkV11),
    #[serde(rename = "credential.spec.refused")]
    CredentialSpecRefused(crate::CredentialSpecRefusedV11),
    #[serde(rename = "credential.bundle.begin")]
    CredentialBundleBegin(crate::CredentialBundleBeginV11),
    #[serde(rename = "credential.bundle.chunk")]
    CredentialBundleChunk(crate::CredentialBundleChunkV11),
    #[serde(rename = "credential.bundle.refused")]
    CredentialBundleRefused(crate::CredentialBundleRefusedV11),
    #[serde(rename = "credential.quarantine.discard")]
    CredentialQuarantineDiscard(crate::CredentialQuarantineDiscardV11),
    #[serde(rename = "credential.capture.ack")]
    CredentialCaptureAck(crate::CredentialCaptureAckV11),
    #[serde(rename = "credential.revoke")]
    CredentialRevoke(crate::CredentialRevokeV11),
    #[serde(rename = "credential.census.ack")]
    CredentialCensusAck(crate::CredentialCensusAckV11),
    /// Deployment-wide egress blocklist (E6), sent after `hello.ok` to
    /// daemons advertising the egress capability.
    #[serde(rename = "egress.blocklist")]
    EgressBlocklist(crate::EgressBlocklistV11),
    /// WP7: the answer to `host.quiesce` (negotiated `quiesce`): from here
    /// on the server holds new `command.run` work for this host.
    #[serde(rename = "host.quiesce.ack")]
    HostQuiesceAck(crate::HostQuiesceAckV11),
}

#[derive(Debug, Error)]
pub enum ControlError {
    #[error("JSON control frame exceeds {} bytes", json_control_max_bytes())]
    TooLarge,
    #[error("invalid receipt bounds")]
    InvalidReceipt,
    #[error("invalid admission or availability frame")]
    InvalidAdmission,
    #[error("invalid inventory page")]
    InvalidInventory,
    #[error("invalid terminal frame")]
    InvalidTerminal,
    #[error("invalid channel frame")]
    InvalidChannel,
    #[error("invalid environment map")]
    InvalidEnvironment,
    #[error("invalid image frame")]
    InvalidImage,
    #[error("invalid build fields")]
    InvalidBuild,
    #[error("invalid startup field")]
    InvalidStartup,
    #[error("invalid credential frame")]
    InvalidCredential,
    #[error("invalid disk offload frame")]
    InvalidDisk,
    #[error("failed to serialize control message")]
    Serialize,
    #[error("failed to parse control message")]
    Parse,
}

pub(crate) fn encode_daemon_control(
    message: &DaemonControlMessage,
) -> Result<String, ControlError> {
    validate_daemon_receipt(message)?;
    let text = serde_json::to_string(&DaemonControlEncoder(message))
        .map_err(|_| ControlError::Serialize)?;
    if text.len() > daemon_control_limit(message) {
        return Err(ControlError::TooLarge);
    }
    Ok(text)
}

/// Required launch size and exact retained-root identity, checked before intent/effect.
pub fn dispatch_vm_size(
    dispatch: &OperationDispatch,
    version: &str,
) -> Result<Option<crate::VmSize>, ControlError> {
    if !crate::known_protocol_version(version) {
        return Err(ControlError::InvalidAdmission);
    }
    let launch = matches!(
        dispatch.kind.as_str(),
        "sandbox.create" | "sandbox.reconnect"
    );
    let bound = launch || matches!(dispatch.kind.as_str(), "sandbox.kill" | "sandbox.stop");
    if bound {
        let a = dispatch
            .allocation
            .as_ref()
            .ok_or(ControlError::InvalidAdmission)?;
        serde_json::from_value::<crate::capacity_v11::PinnedAllocationV11>(
            serde_json::to_value(a).map_err(|_| ControlError::InvalidAdmission)?,
        )
        .map_err(|_| ControlError::InvalidAdmission)?;
        if launch
            && (dispatch.cpu_count != Some(a.cpu_count)
                || dispatch.memory_mi_b != Some(a.memory_mi_b))
        {
            return Err(ControlError::InvalidAdmission);
        }
    } else if dispatch.allocation.is_some() {
        return Err(ControlError::InvalidAdmission);
    }
    if !launch {
        return if dispatch.cpu_count.is_some() || dispatch.memory_mi_b.is_some() {
            Err(ControlError::InvalidAdmission)
        } else {
            Ok(None)
        };
    }
    match (dispatch.cpu_count, dispatch.memory_mi_b) {
        (Some(cpu), Some(memory)) => crate::VmSize::new(cpu, memory)
            .map(Some)
            .map_err(|_| ControlError::InvalidAdmission),
        _ => Err(ControlError::InvalidAdmission),
    }
}

/// Validate the sole supported version and strict dispatch before encoding.
pub fn encode_server_control_for_version(
    message: &ServerControlMessage,
    version: &str,
) -> Result<String, ControlError> {
    if !crate::known_protocol_version(version) {
        return Err(ControlError::Parse);
    }
    validate_server_admission(message)?;
    if let ServerControlMessage::OperationDispatch(dispatch) = message {
        dispatch_vm_size(dispatch, version)?;
    }
    encode_server_control(message)
}

pub fn parse_server_control_for_version(
    text: &str,
    version: &str,
) -> Result<ServerControlMessage, ControlError> {
    if !crate::known_protocol_version(version) {
        return Err(ControlError::Parse);
    }
    let message = parse_server_control(text)?;
    if let ServerControlMessage::OperationDispatch(dispatch) = &message {
        dispatch_vm_size(dispatch, version)?;
    }
    Ok(message)
}

pub fn parse_daemon_control_for_version(
    text: &str,
    version: &str,
) -> Result<DaemonControlMessage, ControlError> {
    if !crate::known_protocol_version(version) {
        return Err(ControlError::Parse);
    }
    let message = parse_daemon_control(text)?;
    Ok(message)
}

pub fn parse_server_control(text: &str) -> Result<ServerControlMessage, ControlError> {
    if text.len() > crate::HOST_CONTROL_MAX_BYTES {
        return Err(ControlError::TooLarge);
    }
    let message = serde_json::from_str(text).map_err(|_| ControlError::Parse)?;
    if text.len() > server_control_limit(&message) {
        return Err(ControlError::TooLarge);
    }
    validate_server_admission(&message)?;
    validate_server_terminal(&message)?;
    validate_server_channel(&message)?;
    validate_server_env(&message)?;
    Ok(message)
}

pub fn encode_server_control(message: &ServerControlMessage) -> Result<String, ControlError> {
    validate_server_admission(message)?;
    validate_server_terminal(message)?;
    validate_server_channel(message)?;
    validate_server_env(message)?;
    let text = serde_json::to_string(message).map_err(|_| ControlError::Serialize)?;
    if text.len() > server_control_limit(message) {
        return Err(ControlError::TooLarge);
    }
    Ok(text)
}

fn validate_server_admission(message: &ServerControlMessage) -> Result<(), ControlError> {
    if !crate::image::valid_server_image(message) {
        return Err(ControlError::InvalidImage);
    }
    if !crate::disk::valid_server_disk(message) {
        return Err(ControlError::InvalidDisk);
    }
    if let ServerControlMessage::OperationDispatch(dispatch) = message
        && !crate::disk::valid_dispatch_disk_fields(dispatch)
    {
        return Err(ControlError::InvalidDisk);
    }
    if !crate::credentials::valid_server_credential(message) {
        return Err(ControlError::InvalidCredential);
    }
    // Declared tunnel ports ride only on launches (the plan is compiled
    // there), always with their revision.
    if let ServerControlMessage::OperationDispatch(dispatch) = message
        && (dispatch.tunnel_ports.is_some() != dispatch.tunnel_ports_revision.is_some()
            || (dispatch.tunnel_ports.is_some()
                && !matches!(
                    dispatch.kind.as_str(),
                    "sandbox.create" | "sandbox.reconnect"
                )))
    {
        return Err(ControlError::InvalidAdmission);
    }
    if let ServerControlMessage::EgressBlocklist(list) = message
        && !list.is_valid()
    {
        return Err(ControlError::InvalidAdmission);
    }
    if let ServerControlMessage::HostQuiesceAck(ack) = message
        && !ack.is_valid()
    {
        return Err(ControlError::InvalidAdmission);
    }
    if let ServerControlMessage::OperationDispatch(dispatch) = message
        && (!crate::image::valid_dispatch_image_fields(dispatch)
            || dispatch
                .capture
                .as_ref()
                .is_some_and(|capture| !capture.is_valid() || dispatch.kind != "sandbox.capture")
            || (dispatch.kind == "sandbox.capture" && dispatch.capture.is_none()))
    {
        return Err(ControlError::InvalidImage);
    }
    if let ServerControlMessage::OperationDispatch(dispatch) = message
        && !crate::build::valid_dispatch_build_fields(dispatch)
    {
        return Err(ControlError::InvalidBuild);
    }
    if let ServerControlMessage::OperationDispatch(dispatch) = message
        && !crate::startup::valid_dispatch_startup(dispatch)
    {
        return Err(ControlError::InvalidStartup);
    }
    if let ServerControlMessage::SandboxExpiryStatusAck {
        batch,
        entry_results,
    } = message
        && (*batch == 0
            || *batch > MAX_SAFE_INTEGER
            || entry_results.is_empty()
            || entry_results.len() > crate::INVENTORY_PAGE_MAX_ENTRIES
            || entry_results.iter().any(|r| {
                !crate::valid_inventory_sandbox_id(&r.sandbox_id)
                    || (r.root_retired && r.outcome != crate::CensusEntryOutcome::Converged)
            }))
    {
        return Err(ControlError::InvalidInventory);
    }
    if let ServerControlMessage::InventoryAck {
        entry_results: Some(results),
        ..
    } = message
        && (results.len() > crate::INVENTORY_PAGE_MAX_ENTRIES
            || results.iter().any(|r| {
                !crate::valid_inventory_sandbox_id(&r.sandbox_id)
                    || r.outcome == crate::CensusEntryOutcome::Superseded
                    || (r.root_retired && r.outcome != crate::CensusEntryOutcome::Converged)
            }))
    {
        return Err(ControlError::InvalidAdmission);
    }
    if let ServerControlMessage::HelloOk {
        protocol_version,
        capabilities,
        connection_epoch,
        ..
    } = message
        && (!crate::known_protocol_version(protocol_version)
            || capabilities.protocol_version != *protocol_version
            || !capabilities.census_entry_results
            || !capabilities.pending_receipts
            || !capabilities.expiry_status_results
            || !capabilities.observation_fence
            || !capabilities.command_retire
            || capabilities.output_chunk_bytes.is_none()
            || capabilities
                .output_chunk_bytes
                .is_some_and(|bytes| !crate::valid_output_chunk_bytes(bytes))
            || connection_epoch.is_none_or(|epoch| epoch == 0 || epoch > i32::MAX as u64))
    {
        return Err(ControlError::InvalidAdmission);
    }
    if let ServerControlMessage::AllocationAttestRequest {
        connection_epoch,
        barrier,
        sandbox_ids,
        allocations,
    } = message
        && (!valid_allocation_request(*connection_epoch, *barrier, sandbox_ids)
            || allocations.as_ref().is_none_or(|probes| {
                probes.len() != sandbox_ids.len()
                    || probes.iter().zip(sandbox_ids).any(|(p, id)| {
                        p.sandbox_id != *id || !crate::valid_terminal_id(&p.sandbox_owner_id)
                    })
            }))
    {
        return Err(ControlError::InvalidAdmission);
    }
    if let ServerControlMessage::OperationDispatch(dispatch) = message
        && !crate::valid_terminal_id(&dispatch.sandbox_owner_id)
    {
        return Err(ControlError::InvalidAdmission);
    }
    if let ServerControlMessage::OperationDispatch(dispatch) = message
        && (dispatch.cpu_count.is_some() || dispatch.memory_mi_b.is_some())
    {
        dispatch_vm_size(dispatch, crate::SANDBOX_RELAY_PROTOCOL_VERSION)?;
    }
    if let ServerControlMessage::ReceiptConfirmed(ack) = message
        && !crate::valid_terminal_id(&ack.sandbox_owner_id)
    {
        return Err(ControlError::InvalidReceipt);
    }
    if let ServerControlMessage::SandboxProbeRequest {
        sandbox_owner_id,
        host_owner_id,
        ..
    } = message
        && (!crate::valid_terminal_id(sandbox_owner_id) || !crate::valid_terminal_id(host_owner_id))
    {
        return Err(ControlError::InvalidAdmission);
    }
    if let ServerControlMessage::DispatchAuditPage { page, entries, .. } = message
        && (*page > 1024
            || entries.len() > DISPATCH_AUDIT_PAGE_MAX
            || entries.iter().any(|e| {
                !crate::valid_terminal_id(&e.sandbox_owner_id)
                    || !crate::valid_terminal_id(&e.operation_id)
                    || !crate::valid_terminal_id(&e.sandbox_id)
                    || e.generation == 0
                    || e.generation > i32::MAX as u64
                    || e.attempt > i32::MAX as u64
                    || e.connection_epoch == 0
                    || e.connection_epoch > i32::MAX as u64
                    || e.idempotency_key.is_empty()
                    || e.idempotency_key.len() > crate::RECEIPT_LIMITS.idempotency_key_bytes
                    || !crate::RECEIPT_LIMITS.kinds.contains(&e.kind)
            }))
    {
        return Err(ControlError::InvalidReceipt);
    }
    if let ServerControlMessage::ReceiptPrunedAck(ack) = message
        && !ack.is_valid()
    {
        return Err(ControlError::InvalidReceipt);
    }
    if let ServerControlMessage::PrivateConfigInstall(config) = message
        && (!config.is_valid()
            || serde_json::to_vec(config)
                .map_err(|_| ControlError::Serialize)?
                .len()
                > crate::PRIVATE_CONFIG_MAX_BYTES)
    {
        return Err(ControlError::InvalidAdmission);
    }
    if let ServerControlMessage::JournalKeyInstall(key) = message
        && !key.is_valid()
    {
        return Err(ControlError::InvalidAdmission);
    }
    if let ServerControlMessage::AvailabilityRequest {
        request_id,
        connection_epoch,
        page,
        bindings,
    } = message
        && (bindings.is_empty()
            || !crate::valid_availability_page(request_id, *connection_epoch, *page, bindings))
    {
        return Err(ControlError::InvalidAdmission);
    }
    Ok(())
}

fn validate_server_env(message: &ServerControlMessage) -> Result<(), ControlError> {
    if let ServerControlMessage::OperationDispatch(dispatch) = message
        && dispatch
            .private_config
            .as_ref()
            .is_some_and(|config| !config.is_valid())
    {
        return Err(ControlError::InvalidAdmission);
    }

    if let ServerControlMessage::OperationDispatch(dispatch) = message
        && let Some(env) = &dispatch.env
    {
        crate::validate_env(env).map_err(|_| ControlError::InvalidEnvironment)?;
    }
    Ok(())
}

fn terminal_request(request_id: &str, fence: &TerminalFence) -> bool {
    valid_terminal_id(request_id) && fence.is_valid()
}

fn validate_server_terminal(message: &ServerControlMessage) -> Result<(), ControlError> {
    let valid = match message {
        ServerControlMessage::HostPolicyLower(frame) => frame.is_valid(),
        ServerControlMessage::TunnelApply(frame) => frame.is_valid(),
        ServerControlMessage::TunnelClear(frame) => frame.is_valid(),
        ServerControlMessage::TunnelPorts(frame) => frame.is_valid(),
        ServerControlMessage::HostExecStart(frame) => frame.is_valid(),
        ServerControlMessage::HostExecPoll(frame) => frame.is_valid(),
        ServerControlMessage::HostExecStdin(frame) => frame.is_valid(),
        ServerControlMessage::HostExecCancel(frame) => frame.is_valid(),
        ServerControlMessage::HostFileRequest(frame) => frame.is_valid(),

        ServerControlMessage::HostTerminalPolicyRaise {
            connection_epoch,
            request_id,
        } => {
            *connection_epoch > 0
                && *connection_epoch <= i32::MAX as u32
                && valid_terminal_id(request_id)
        }
        ServerControlMessage::TerminalOpen {
            request_id,
            fence,
            rows,
            cols,
            host_policy,
            cwd,
        } => crate::TerminalControlV11::Open {
            request_id: request_id.clone(),
            fence: fence.clone(),
            rows: *rows,
            cols: *cols,
            host_policy: host_policy.clone(),
            cwd: cwd.clone(),
        }
        .is_valid(),
        ServerControlMessage::TerminalResize {
            request_id,
            fence,
            rows,
            cols,
        } => terminal_request(request_id, fence) && valid_terminal_size(*rows, *cols),
        ServerControlMessage::TerminalResume {
            request_id,
            fence,
            next_output_seq,
            rows,
            cols,
        } => crate::valid_terminal_resume(request_id, fence, *next_output_seq, *rows, *cols),
        ServerControlMessage::TerminalClose {
            request_id, fence, ..
        } => terminal_request(request_id, fence),
        ServerControlMessage::TerminalAck { fence, sequence } => {
            fence.is_valid() && *sequence <= 9_007_199_254_740_991
        }
        _ => true,
    };
    if valid {
        Ok(())
    } else {
        Err(ControlError::InvalidTerminal)
    }
}

fn validate_daemon_terminal(message: &DaemonControlMessage) -> Result<(), ControlError> {
    let valid = match message {
        DaemonControlMessage::HostAgentPolicy(frame) => frame.is_valid(),
        DaemonControlMessage::HostPolicyLowerResult(frame) => frame.is_valid(),
        DaemonControlMessage::HostExecStarted(frame) => frame.is_valid(),
        DaemonControlMessage::HostExecRejected(frame) => frame.is_valid(),
        DaemonControlMessage::HostExecStatus(frame) => frame.is_valid(),
        DaemonControlMessage::HostExecStdinResult(frame) => frame.is_valid(),
        DaemonControlMessage::HostFileResult(frame) => frame.is_valid(),

        DaemonControlMessage::Hello { daemon, .. } => {
            crate::valid_host_agent_policy(
                daemon.capabilities.host_commands,
                daemon.capabilities.host_files,
                daemon.capabilities.host_command_max_ms,
                daemon.capabilities.agent_policy_revision,
            ) && daemon
                .capabilities
                .tunnel
                .as_ref()
                .is_none_or(crate::TunnelCapabilityV11::is_valid)
        }
        DaemonControlMessage::HostTerminalPolicy(policy) => policy.is_valid(),
        DaemonControlMessage::HostLeasePolicy(policy) => policy.is_valid(),
        DaemonControlMessage::HostQuiesce(quiesce) => quiesce.is_valid(),
        DaemonControlMessage::HostEgressState(state) => state.is_valid(),
        DaemonControlMessage::TunnelStatus(status) => status.is_valid(),
        DaemonControlMessage::TunnelPortsStatus(status) => status.is_valid(),
        DaemonControlMessage::TerminalReady {
            request_id,
            fence,
            rows,
            cols,
            output_seq,
        } => {
            terminal_request(request_id, fence)
                && valid_terminal_size(*rows, *cols)
                && output_seq.is_none_or(|seq| seq <= 9_007_199_254_740_991)
        }
        DaemonControlMessage::TerminalAck { fence, sequence } => {
            fence.is_valid() && *sequence <= 9_007_199_254_740_991
        }
        DaemonControlMessage::TerminalExit {
            request_id,
            fence,
            error,
            ..
        } => {
            fence.is_valid()
                && request_id.as_deref().is_none_or(valid_terminal_id)
                && error
                    .as_ref()
                    .is_none_or(|e| e.message.len() <= crate::RECEIPT_LIMITS.error_bytes)
        }
        _ => true,
    };
    if valid {
        Ok(())
    } else {
        Err(ControlError::InvalidTerminal)
    }
}

fn validate_server_channel(message: &ServerControlMessage) -> Result<(), ControlError> {
    let valid = match message {
        // The echo of the daemon's offer: as strict as the offer itself.
        ServerControlMessage::HelloOk { capabilities, .. } => capabilities
            .channels
            .as_ref()
            .is_none_or(crate::ChannelsCapability::is_valid),
        ServerControlMessage::ChannelOpen {
            fence,
            kind,
            argv,
            login,
            cwd,
            env,
            pty,
            port,
            path,
        } => crate::valid_channel_open(
            fence,
            &crate::ChannelOpenFields {
                kind: *kind,
                login: *login,
                argv: argv.as_deref(),
                cwd: cwd.as_deref(),
                env: env.as_ref(),
                pty: pty.as_ref(),
                port: *port,
                path: path.as_deref(),
            },
        ),
        ServerControlMessage::ChannelAck { fence, stream, seq } => {
            fence.is_valid() && stream.is_output() && crate::channel::valid_channel_seq(*seq)
        }
        ServerControlMessage::ChannelEof {
            fence,
            stream,
            frames,
        } => {
            fence.is_valid()
                && *stream == crate::ChannelStream::Stdin
                && crate::channel::valid_channel_seq(*frames)
        }
        ServerControlMessage::ChannelResize { fence, rows, cols } => {
            fence.is_valid() && valid_terminal_size(*rows, *cols)
        }
        ServerControlMessage::ChannelSignal { fence, .. }
        | ServerControlMessage::ChannelClose { fence, .. } => fence.is_valid(),
        _ => true,
    };
    if valid {
        Ok(())
    } else {
        Err(ControlError::InvalidChannel)
    }
}

fn validate_daemon_channel(message: &DaemonControlMessage) -> Result<(), ControlError> {
    let valid = match message {
        DaemonControlMessage::Hello { daemon, .. } => daemon
            .capabilities
            .channels
            .as_ref()
            .is_none_or(crate::ChannelsCapability::is_valid),
        DaemonControlMessage::ChannelReady { fence, pty } => {
            fence.is_valid() && pty.is_none_or(|p| valid_terminal_size(p.rows, p.cols))
        }
        DaemonControlMessage::ChannelAck { fence, stream, seq } => {
            fence.is_valid()
                && *stream == crate::ChannelStream::Stdin
                && crate::channel::valid_channel_seq(*seq)
        }
        DaemonControlMessage::ChannelEof {
            fence,
            stream,
            frames,
        } => fence.is_valid() && stream.is_output() && crate::channel::valid_channel_seq(*frames),
        DaemonControlMessage::ChannelError { fence, .. } => fence.is_valid(),
        DaemonControlMessage::ChannelExit {
            fence,
            exit_code,
            signal,
            error,
            frames,
            ..
        } => crate::valid_channel_exit(fence, *exit_code, *signal, error.as_ref(), frames),
        _ => true,
    };
    if valid {
        Ok(())
    } else {
        Err(ControlError::InvalidChannel)
    }
}

pub fn parse_daemon_control(text: &str) -> Result<DaemonControlMessage, ControlError> {
    if text.len() > crate::HOST_CONTROL_MAX_BYTES {
        return Err(ControlError::TooLarge);
    }
    let message = serde_json::from_str(text).map_err(|_| ControlError::Parse)?;
    if text.len() > daemon_control_limit(&message) {
        return Err(ControlError::TooLarge);
    }
    validate_daemon_receipt(&message)?;
    if matches!(message, DaemonControlMessage::OperationReceipt { .. })
        && text.len() > crate::RECEIPT_LIMITS.receipt_bytes
    {
        return Err(ControlError::TooLarge);
    }
    Ok(message)
}

fn validate_daemon_receipt(message: &DaemonControlMessage) -> Result<(), ControlError> {
    if !crate::image::valid_daemon_image(message) {
        return Err(ControlError::InvalidImage);
    }
    if !crate::disk::valid_daemon_disk(message) {
        return Err(ControlError::InvalidDisk);
    }
    if !crate::credentials::valid_daemon_credential(message) {
        return Err(ControlError::InvalidCredential);
    }
    if let DaemonControlMessage::HostAdmission {
        image: Some(image), ..
    } = message
        && !image.is_valid()
    {
        return Err(ControlError::InvalidAdmission);
    }
    if let DaemonControlMessage::EgressRefused(report) = message
        && !report.is_valid()
    {
        return Err(ControlError::InvalidBuild);
    }
    match message {
        DaemonControlMessage::Hello { .. } => {
            let value = serde_json::to_value(DaemonControlEncoder(message))
                .map_err(|_| ControlError::Serialize)?;
            serde_json::from_value::<crate::capacity_v11::HostHelloV11>(value)
                .map_err(|_| ControlError::InvalidAdmission)?;
        }
        DaemonControlMessage::InventoryUpdate { .. } => {
            let value = serde_json::to_value(DaemonControlEncoder(message))
                .map_err(|_| ControlError::Serialize)?;
            serde_json::from_value::<crate::capacity_v11::HostInventoryUpdateV11>(value)
                .map_err(|_| ControlError::InvalidAdmission)?;
        }
        _ => {}
    }

    let detail = match message {
        DaemonControlMessage::OperationResult { error, .. }
        | DaemonControlMessage::OperationReceipt { error, .. }
        | DaemonControlMessage::ImageVerifyResult { error, .. }
        | DaemonControlMessage::TerminalExit { error, .. }
        | DaemonControlMessage::ChannelExit { error, .. } => error.as_ref(),
        _ => None,
    };
    if detail.is_some_and(|e| {
        !e.code.is_canonical() || e.reason.is_some_and(|reason| !reason.fits_wire(&e.code))
    }) {
        return Err(ControlError::InvalidReceipt);
    }
    if let DaemonControlMessage::OperationReceiptPruned {
        sandbox_owner_id,
        operation_id,
        sandbox_id,
        generation,
        attempt,
        idempotency_key,
        kind,
    } = message
        && (!valid_terminal_id(sandbox_owner_id)
            || !valid_terminal_id(operation_id)
            || !valid_terminal_id(sandbox_id)
            || *generation == 0
            || *generation > i32::MAX as u64
            || *attempt == 0
            || *attempt > i32::MAX as u64
            || idempotency_key.is_empty()
            || idempotency_key.len() > crate::RECEIPT_LIMITS.idempotency_key_bytes
            || !crate::RECEIPT_LIMITS.kinds.contains(kind))
    {
        return Err(ControlError::InvalidReceipt);
    }

    if let DaemonControlMessage::PrivateConfigRefused(refusal) = message
        && !refusal.is_valid()
    {
        return Err(ControlError::InvalidAdmission);
    }
    if let DaemonControlMessage::PrivateConfigAck(ack) = message
        && !ack.is_valid()
    {
        return Err(ControlError::InvalidAdmission);
    }
    if let DaemonControlMessage::JournalKeyAck {
        connection_epoch,
        key_version,
        key_id,
    } = message
        && (*connection_epoch == 0
            || *connection_epoch > i32::MAX as u64
            || *key_version != 1
            || key_id.len() != 32
            || !key_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    {
        return Err(ControlError::InvalidAdmission);
    }

    match message {
        DaemonControlMessage::HostAdmission {
            connection_epoch,
            journal_id,
            vm_capacity,
            storage_pools,
            ..
        } => {
            if *connection_epoch == 0
                || *connection_epoch > i32::MAX as u64
                || !valid_journal_identity(journal_id)
            {
                return Err(ControlError::InvalidAdmission);
            }
            let capacity = crate::capacity_v11::HostStaticCapacityV11 {
                vm_capacity: vm_capacity.clone(),
                storage_pools: storage_pools.clone(),
            };
            serde_json::from_value::<crate::capacity_v11::HostStaticCapacityV11>(
                serde_json::to_value(capacity).map_err(|_| ControlError::InvalidAdmission)?,
            )
            .map_err(|_| ControlError::InvalidAdmission)?;
        }
        DaemonControlMessage::AvailabilityResult {
            request_id,
            connection_epoch,
            page,
            entries,
        } => {
            let bindings: Vec<_> = entries.iter().map(|e| e.binding.clone()).collect();
            if !crate::valid_availability_page(request_id, *connection_epoch, *page, &bindings) {
                return Err(ControlError::InvalidAdmission);
            }
        }
        _ => {}
    }
    validate_daemon_terminal(message)?;
    validate_daemon_channel(message)?;
    if let DaemonControlMessage::AllocationAttestResult {
        connection_epoch,
        barrier,
        journal_id,
        entries,
    } = message
    {
        let ids: Vec<_> = entries.iter().map(|e| e.sandbox_id.clone()).collect();
        if !valid_allocation_request(*connection_epoch, *barrier, &ids)
            || !valid_journal_identity(journal_id)
            || entries
                .iter()
                .any(|entry| !crate::valid_terminal_id(&entry.sandbox_owner_id))
        {
            return Err(ControlError::InvalidAdmission);
        }
    }
    if let DaemonControlMessage::SandboxInventory { page, entries, .. } = message
        && !crate::valid_inventory_page(*page, entries)
    {
        return Err(ControlError::InvalidInventory);
    }
    if let DaemonControlMessage::SandboxExpiryStatus {
        entries,
        batch,
        observation,
    } = message
        && (entries.is_empty()
            || !crate::valid_inventory_entries(entries)
            || batch.is_some_and(|batch| batch == 0 || batch > MAX_SAFE_INTEGER)
            || observation.is_some_and(|o| o == 0 || o > MAX_SAFE_INTEGER)
            // An observation numbers batches; it never stands alone.
            || (observation.is_some() && batch.is_none()))
    {
        return Err(ControlError::InvalidInventory);
    }
    if let DaemonControlMessage::ReconcileComplete {
        pending_receipts: Some(ids),
    } = message
        && !valid_pending_receipts(ids)
    {
        return Err(ControlError::InvalidReceipt);
    }
    if let DaemonControlMessage::DispatchAuditResult { page, entries } = message
        && (*page > 1024
            || entries.len() > DISPATCH_AUDIT_PAGE_MAX
            || entries.iter().any(|e| {
                !crate::valid_terminal_id(&e.operation_id)
                    || e.generation == 0
                    || e.generation > i32::MAX as u64
                    || e.attempt > i32::MAX as u64
            }))
    {
        return Err(ControlError::InvalidReceipt);
    }
    if let DaemonControlMessage::DispatchAuditRequest { page } = message
        && *page > 1024
    {
        return Err(ControlError::InvalidReceipt);
    }
    if let DaemonControlMessage::OperationAdopt {
        sandbox_owner_id,
        operation_id,
        sandbox_id,
        generation,
        body_hash,
        idempotency_key,
        kind,
        stdin_next_sequence,
        ..
    } = message
        && (!crate::valid_terminal_id(sandbox_owner_id)
            || operation_id.trim().is_empty()
            || operation_id.len() > 128
            || sandbox_id.trim().is_empty()
            || sandbox_id.len() > 128
            || *generation == 0
            || *generation > i32::MAX as u64
            || !crate::valid_receipt_fields(body_hash, idempotency_key, kind)
            || stdin_next_sequence.is_some_and(|next| next > 9_007_199_254_740_991))
    {
        return Err(ControlError::InvalidReceipt);
    }
    if let DaemonControlMessage::OperationReceipt {
        sandbox_owner_id,
        body_hash,
        idempotency_key,
        kind,
        result,
        error,
        ..
    } = message
        && (!crate::valid_terminal_id(sandbox_owner_id)
            || !crate::valid_receipt_fields(body_hash, idempotency_key, kind)
            || result.as_ref().is_some_and(|v| {
                !v.is_object() || v.to_string().len() > crate::RECEIPT_LIMITS.result_bytes
            })
            || error
                .as_ref()
                .is_some_and(|e| e.message.len() > crate::RECEIPT_LIMITS.error_bytes)
            || serde_json::to_vec(&DaemonControlEncoder(message))
                .map_err(|_| ControlError::Serialize)?
                .len()
                > crate::RECEIPT_LIMITS.receipt_bytes)
    {
        return Err(ControlError::InvalidReceipt);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_reasons_are_snake_case_and_pair_only_with_guest_unavailable() {
        for reason in [
            ReadinessFailureReason::AgentTimeout,
            ReadinessFailureReason::VmNotRunning,
            ReadinessFailureReason::GuestRestarts,
            ReadinessFailureReason::Architecture,
            ReadinessFailureReason::GuestUser,
            ReadinessFailureReason::GuestHome,
            ReadinessFailureReason::GuestShell,
            ReadinessFailureReason::GuestRepo,
            ReadinessFailureReason::GuestTooling,
            ReadinessFailureReason::GuestCheck,
        ] {
            let wire = ProtocolErrorReason::from(reason);
            assert_eq!(
                serde_json::to_value(wire).unwrap(),
                serde_json::json!(reason.as_str())
            );
            assert_eq!(
                serde_json::from_value::<ProtocolErrorReason>(serde_json::json!(reason.as_str()))
                    .unwrap(),
                wire
            );
            assert!(wire.fits(SandboxErrorCode::GuestUnavailable));
            assert!(!wire.fits(SandboxErrorCode::HostCapacity));
            assert!(!wire.fits(SandboxErrorCode::UnsupportedCapability));
            assert_eq!(wire.readiness(), Some(reason));
            assert_eq!(wire.capacity(), None);
            assert_eq!(wire.egress(), None);
        }
    }

    #[test]
    fn control_frames_use_camel_case_fields() {
        let fixture = include_str!("../fixtures/control_hello_daemon.json");
        let message = parse_daemon_control_for_version(fixture, "1.0").unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(
                &crate::WireCodes::CURRENT
                    .encode(&message, None)
                    .unwrap()
                    .text
            )
            .unwrap(),
            serde_json::from_str::<serde_json::Value>(fixture).unwrap()
        );
    }

    #[test]
    fn private_env_tuples_are_bounded_at_control_boundary() {
        for env in [
            vec![
                ("A".to_string(), "first".to_string()),
                ("A".into(), "second".into()),
            ],
            vec![("A".into(), "界".repeat(1366))],
            vec![("A".repeat(129), "private-canary".into())],
        ] {
            let raw = serde_json::json!({"sandboxOwnerId":"owner", "type":"operation.dispatch", "sandboxOwnerId":"owner", "operationId":"op-env", "sandboxId":"sbx", "idempotencyKey":"env", "kind":"command.run", "generation":1, "attempt":1, "argv":["true"], "env":env}).to_string();
            let error = parse_server_control(&raw).unwrap_err();
            assert!(matches!(error, ControlError::InvalidEnvironment));
            assert!(!error.to_string().contains("private-canary"));
        }
    }

    #[test]
    fn parses_server_dispatch() {
        let parsed = parse_server_control(
            r#"{"type":"operation.dispatch", "sandboxOwnerId":"owner","operationId":"op-1","sandboxId":"sbx-1","idempotencyKey":"key-1","kind":"sandbox.create","generation":1,"attempt":1}"#,
        )
        .expect("parse");
        match parsed {
            ServerControlMessage::OperationDispatch(dispatch) => {
                assert_eq!(dispatch.operation_id, "op-1");
                assert_eq!(dispatch.sandbox_id, "sbx-1");
                assert_eq!(dispatch.idempotency_key, "key-1");
                assert_eq!(dispatch.kind, "sandbox.create");
                assert_eq!(dispatch.generation, 1);
                assert_eq!(dispatch.attempt, 1);
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[test]
    fn parses_file_and_run_dispatch_fields() {
        let parsed = parse_server_control(
            r#"{"type":"operation.dispatch", "sandboxOwnerId":"owner","operationId":"op-2","sandboxId":"sbx-1","idempotencyKey":"key-2","kind":"file.put","generation":1,"attempt":1,"path":"/root/a.bin","cwd":"/root","timeoutMs":5000}"#,
        )
        .expect("parse");
        match parsed {
            ServerControlMessage::OperationDispatch(dispatch) => {
                assert_eq!(dispatch.kind, "file.put");
                assert_eq!(dispatch.path.as_deref(), Some("/root/a.bin"));
                assert_eq!(dispatch.cwd.as_deref(), Some("/root"));
                assert_eq!(dispatch.timeout_ms, Some(5000));
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[test]
    fn parses_extended_dispatch_fields() {
        let parsed = parse_server_control(
            r#"{"type":"operation.dispatch", "sandboxOwnerId":"owner","operationId":"op-3","sandboxId":"sbx-1","idempotencyKey":"key-3","kind":"file.list","generation":1,"attempt":1,"path":"/root","destPath":"/root/b","recursive":true,"maxDepth":2,"env":[["FOO","bar"]]}"#,
        )
        .expect("parse");
        match parsed {
            ServerControlMessage::OperationDispatch(dispatch) => {
                assert_eq!(dispatch.kind, "file.list");
                assert_eq!(dispatch.dest_path.as_deref(), Some("/root/b"));
                assert_eq!(dispatch.recursive, Some(true));
                assert_eq!(dispatch.max_depth, Some(2));
                assert_eq!(
                    dispatch.env.as_deref(),
                    Some([("FOO".to_string(), "bar".to_string())].as_slice())
                );
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[test]
    fn parses_egress_policy_on_launch_dispatch() {
        let parsed = parse_server_control(
            r#"{"type":"operation.dispatch", "sandboxOwnerId":"owner","operationId":"op-4","sandboxId":"sbx-1","idempotencyKey":"key-4","kind":"sandbox.create","generation":1,"attempt":1,"egressPolicy":{"domains":["example.com"],"cidrs":["128.66.0.0/24"]},"egressPolicyHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
        )
        .expect("parse");
        match parsed {
            ServerControlMessage::OperationDispatch(dispatch) => {
                let policy = dispatch.egress_policy.expect("egress policy");
                assert_eq!(policy.domains, vec!["example.com".to_string()]);
                assert_eq!(policy.cidrs, vec!["128.66.0.0/24".to_string()]);
                assert_eq!(
                    dispatch.egress_policy_hash.as_deref(),
                    Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                );
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[test]
    fn dispatch_rejects_unknown_fields() {
        let err = parse_server_control(
            r#"{"type":"operation.dispatch", "sandboxOwnerId":"owner","operationId":"op-1","sandboxId":"sbx-1","idempotencyKey":"key-1","kind":"sandbox.create","generation":1,"attempt":1,"explode":true}"#,
        )
        .expect_err("unknown field");
        assert!(matches!(err, ControlError::Parse));
    }

    #[test]
    fn guest_privilege_fields_are_true_only_and_absent_stays_absent() {
        let base = r#"{"type":"operation.dispatch", "sandboxOwnerId":"owner","operationId":"op-1","sandboxId":"sbx-1","idempotencyKey":"key-1","kind":"sandbox.create","generation":1,"attempt":1"#;
        let both = format!(r#"{base},"guestSudo":true,"guestRoot":true}}"#);
        match parse_server_control(&both).expect("parse") {
            ServerControlMessage::OperationDispatch(d) => {
                assert_eq!((d.guest_sudo, d.guest_root), (Some(true), Some(true)));
                let wire = serde_json::to_value(&*d).unwrap();
                assert_eq!(wire["guestSudo"], true);
                assert_eq!(wire["guestRoot"], true);
            }
            other => panic!("unexpected message: {other:?}"),
        }
        match parse_server_control(&format!("{base}}}")).expect("parse") {
            ServerControlMessage::OperationDispatch(d) => {
                let wire = serde_json::to_value(&*d).unwrap();
                assert!(wire.get("guestSudo").is_none() && wire.get("guestRoot").is_none());
            }
            other => panic!("unexpected message: {other:?}"),
        }
        for bad in [
            r#","guestSudo":false}"#,
            r#","guestRoot":false}"#,
            r#","guestRoot":null}"#,
            r#","guestSudoName":"user"}"#,
        ] {
            assert!(
                parse_server_control(&format!("{base}{bad}")).is_err(),
                "{bad}"
            );
        }
        for reason in [
            ReadinessFailureReason::GuestSudoUnavailable,
            ReadinessFailureReason::GuestRootGranted,
        ] {
            assert_eq!(
                serde_json::to_value(reason).unwrap(),
                serde_json::Value::from(reason.as_str())
            );
        }
        assert_eq!(
            serde_json::to_value(crate::EgressRefusalReason::GuestSudoNotPermitted).unwrap(),
            "guest_sudo_not_permitted"
        );
        assert_eq!(
            serde_json::to_value(crate::capacity_v11::CapacityReason::SandboxReceipts).unwrap(),
            "sandbox_receipts"
        );
    }
}

#[cfg(test)]
mod vm_size_tests {
    use super::*;
    #[test]
    fn launch_requires_exact_binding_and_current_version() {
        let allocation = serde_json::json!({"cpuCount":1,"memoryMiB":1024,"diskGiB":32,"storagePoolName":"default","storageMarker":"storage_1","chargedMemoryMiB":1280,"chargedVcpu":1,"rootChargeGiB":33});
        let value = serde_json::json!({"sandboxOwnerId":"owner", "type":"operation.dispatch", "sandboxOwnerId":"owner","operationId":"op","sandboxId":"sbx","idempotencyKey":"key","kind":"sandbox.create","generation":1,"attempt":1,"cpuCount":1,"memoryMiB":1024,"allocation":allocation});
        let dispatch = parse_server_control_for_version(&value.to_string(), "1.0").unwrap();
        assert!(encode_server_control_for_version(&dispatch, "1.0").is_ok());
        for other in ["0.9", "0.8", "1.1", "2.0"] {
            assert!(parse_server_control_for_version(&value.to_string(), other).is_err());
        }
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove("allocation");
        assert!(parse_server_control_for_version(&missing.to_string(), "1.0").is_err());
        let mut mismatch = value;
        mismatch["cpuCount"] = serde_json::json!(2);
        assert!(parse_server_control_for_version(&mismatch.to_string(), "1.0").is_err());
    }
}

#[cfg(test)]
mod allocation_attestation_tests {
    use super::*;
    #[derive(Deserialize)]
    struct Case {
        name: String,
        kind: String,
        version: String,
        frame: serde_json::Value,
        valid: bool,
    }
    #[test]
    fn targeted_allocation_wire_ts_rust_parity() {
        let cases: Vec<Case> = serde_json::from_str(include_str!(
            "../fixtures/allocation_attestation_wire_cases.json"
        ))
        .unwrap();
        for case in cases {
            let raw = case.frame.to_string();
            let accepted = if case.kind == "server" {
                parse_server_control_for_version(&raw, &case.version).is_ok()
            } else {
                parse_daemon_control_for_version(&raw, &case.version).is_ok()
            };
            assert_eq!(accepted, case.valid, "{}", case.name);
            if accepted {
                if case.kind == "server" {
                    let frame = parse_server_control_for_version(&raw, &case.version).unwrap();
                    assert!(encode_server_control_for_version(&frame, &case.version).is_ok());
                } else {
                    let frame = parse_daemon_control_for_version(&raw, &case.version).unwrap();
                    assert!(
                        crate::WireCodes::negotiated(&case.version)
                            .encode(&frame, None)
                            .is_ok()
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod capacity_reason_tests {
    use super::*;
    #[test]
    fn wire_capacity_reason_is_bounded_and_code_bound() {
        let base = serde_json::json!({"type":"operation.result","id":"result","operationId":"op","sandboxId":"sbx","generation":1,"attempt":1,"state":"failed","error":{"code":"host_capacity","message":"Capacity","reason":"disk"}});
        let message = parse_daemon_control(&base.to_string()).unwrap();
        assert!(encode_daemon_control(&message).is_ok());
        for (code, reason) in [("timeout", "disk"), ("host_capacity", "private/path")] {
            let mut bad = base.clone();
            bad["error"]["code"] = code.into();
            bad["error"]["reason"] = reason.into();
            assert!(parse_daemon_control(&bad.to_string()).is_err());
        }
    }
}

/// Final policy controls pinned before T1 activation; raising has no lowering
/// boolean and never represents a durable offline request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all_fields = "camelCase", deny_unknown_fields)]
pub enum HostTerminalPolicyControlV11 {
    #[serde(rename = "host.terminal-policy")]
    Report(crate::HostTerminalPolicyV11),
    #[serde(rename = "host.terminal-policy.raise")]
    Raise {
        connection_epoch: u32,
        request_id: String,
    },
}
impl HostTerminalPolicyControlV11 {
    pub fn is_valid(&self) -> bool {
        match self {
            Self::Report(policy) => policy.is_valid(),
            Self::Raise {
                connection_epoch,
                request_id,
            } => {
                *connection_epoch > 0
                    && *connection_epoch <= i32::MAX as u32
                    && valid_terminal_id(request_id)
            }
        }
    }
}

fn server_control_limit(message: &ServerControlMessage) -> usize {
    if matches!(
        message,
        ServerControlMessage::HostFileRequest(_)
            | ServerControlMessage::HostExecStdin(_)
            | ServerControlMessage::HostExecStart(_)
    ) {
        crate::HOST_CONTROL_MAX_BYTES
    } else {
        json_control_max_bytes()
    }
}
fn daemon_control_limit(message: &DaemonControlMessage) -> usize {
    if matches!(
        message,
        DaemonControlMessage::HostFileResult(_) | DaemonControlMessage::HostExecStatus(_)
    ) {
        crate::HOST_CONTROL_MAX_BYTES
    } else {
        json_control_max_bytes()
    }
}
