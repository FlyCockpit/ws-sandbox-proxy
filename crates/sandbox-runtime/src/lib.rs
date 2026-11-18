//! Host-side sandbox execution runtimes (`FakeRuntime` for tests, `IncusKvmRuntime` on
//! Linux when `WSSP_RUNTIME` is not `fake`). `UnsupportedRuntime` is a test-only
//! adapter; production does not select it on any platform.

mod before_issue;
mod teardown_hook;
pub use teardown_hook::{
    NetworkCreatedHook, NetworkRemovedHook, NetworkTeardownHook, TunnelPortsUpdate,
    set_network_created_hook, set_network_removed_hook, set_network_teardown_hook,
};
mod capture;
/// Shared test-only child ownership (one module for the whole crate).
#[cfg(test)]
#[path = "../tests/support/managed_child.rs"]
mod managed_child;
pub use capture::{
    CAPTURE_SCRUB_MANIFEST_JSON, CREDENTIAL_SCRUB_SEPARATOR, CaptureOutcome, CapturePhase,
    CaptureRequest, FREEZE_HELPER, SCRUB_HELPER, ScrubManifest, capture_names,
    credential_scrub_targets, scrub_manifest, scrub_paths,
};
mod credentials;
pub use credentials::{
    CREDENTIAL_HELPER, CredentialBytes, CredentialGuest, CredentialPackOutcome,
    CredentialPackRequest, CredentialPathSet, CredentialQuiesceOutcome, CredentialRestoreFile,
    CredentialRestoreOutcome, CredentialRestoreRequest, CredentialScrubOutcome,
    CredentialScrubRequest, validate_home_relative,
};
mod build_copy;
pub use build_copy::{BUILD_COPY_HELPER, build_copy_argv};
mod effect;
pub mod egress;
mod error;
#[cfg(all(test, target_os = "linux"))]
mod evidence_boundary_tests;
pub mod guard_probe;
pub use effect::{
    AllocationKind, Completed, EffectError, EffectOutcome, allocation_refusal_for_runtime,
    allocation_refusal_state,
};
mod fake;
mod files;
pub use files::{FILE_CHUNK_BYTES, FILE_MAX_BYTES, FileContent, FileStaging};
mod metadata;
pub use metadata::{DirectoryContinuation, DirectoryKind, canonical_metadata_path};
pub use metadata::{HOST_RESULT_MAX_BYTES, HOST_RESULT_WRAPPER_BYTES};
pub use sandbox_protocol::results::EntryInfo;
pub mod guard;
mod host_child;
mod host_pty;
pub use host_child::{
    Environment as HostChildEnvironment, agent_command as host_agent_command,
    command as host_child_command,
};
pub use host_pty::{HostPtyOpener, LocalHostPtyOpener};
mod image;
mod image_validate;
pub use image_validate::{
    ImageRefusal, SPLIT_VIRTUAL_SIZE_MAX, validate_qcow2_header, validate_split_image,
    validate_unified_image,
};
mod offload;
pub use offload::{
    IMAGE_IO_TIMEOUT, OFFLOAD_ALIAS_PREFIX, OFFLOAD_OWNER_TAG_LEN, OffloadAlias, PublishedDisk,
    offload_alias, offload_alias_owned_by, parse_cloud_init_instance_id,
    parse_instance_operation_running, parse_last_used, parse_offload_aliases, parse_root_usage,
    validate_offload_alias,
};
mod resources;
pub use resources::HostResources;
mod storage;
pub use storage::{
    GIB_BYTES, PhysicalUsage, RootAbsenceProof, RootDisk, RootVolume, STORAGE_MARKER_VOLUME,
    StorageDriver, StoragePoolIdentity, StoragePoolObservation, StorageResources,
    StorageRootCensus,
};
mod output;
mod pty;
pub use output::{CommandOutput, OutputChunk, StartBinding};
pub use pty::{
    OpenPtyRequest, PTY_DEFAULT_SESSION, PTY_EXIT_DRAIN_GRACE, PTY_INPUT_MAX_BYTES,
    PTY_INPUT_QUEUE_CHUNKS, PTY_MAX_COLS, PTY_MAX_ROWS, PTY_MAX_SESSION, PTY_MIN_DIMENSION,
    PTY_OUTPUT_CHUNK_BYTES, PTY_OUTPUT_QUEUE_CHUNKS, PtyCloseIntent, PtyEvent, PtyOpenFailure,
    PtySession, PtySize, PtyTermination, validate_session_id,
};
mod protected;
pub use protected::is_protected_guest_address;
mod reconcile;
mod refused_names;
pub use refused_names::{hint_query_name, refused_query_name};
mod r#trait;
mod unsupported;
pub use reconcile::reconcile_effect;

#[cfg(target_os = "linux")]
mod incus;

pub use error::{NotRunningDetail, RuntimeError};
pub use fake::{
    FAKE_BOOT_ID, FakeCommandScope, FakeGuestIo, FakePolicyDrift, FakePtyControl, FakePublishCrash,
    FakeRuntime, FakeUidRoots, raw_upstream_identity,
};
pub use image::{
    MALICIOUS_INCUS_IMAGE_REFS, ResolvedHostImage, is_incus_fingerprint, is_incus_image_ref,
    normalize_incus_fingerprint, require_launch_fingerprint, require_restore_launch_fingerprint,
};
#[cfg(target_os = "linux")]
pub use r#trait::sandbox_id_from_instance_name;
pub use r#trait::{
    BuildStep, CommandBirth, CommandDescription, CommandGroupGone, CommandRecord, CommandStart,
    CommandStream, CommandStreamChunk, ConfiguredSize, CreateSandboxRequest, CreateSandboxResponse,
    DnsRefreshReport, EnforcementLossIntent, EnforcementLossLifecycle, EnforcementLossStage,
    ForkSandboxRequest, ForkSandboxResponse, GuestIdentity, GuestLinger, GuestPathKind,
    GuestPrivilege, GuestProcess, INCUS_INSTANCE_NAME_PREFIX, KillSandboxRequest,
    KillSandboxResponse, ListDirRequest, ListDirResponse, ListProcessesRequest,
    ListProcessesResponse, MAX_REPORTED_DENIED_GRANT_BYTES, MAX_REPORTED_DENIED_GRANTS,
    MkdirRequest, MkdirResponse, MovePathRequest, ProbeSandboxRequest, ProbeSandboxResponse,
    ProcessSignal, QemuIdentity, RETIRE_DEADLINE_SLACK, ReadFileRequest, ReadFileResponse,
    ReadinessMode, ReconnectSandboxRequest, ReconnectSandboxResponse, RecoverFilePutRequest,
    RemovePathRequest, RemovePathResponse, RestoreLaunch, RetireCommandRequest, RetireMode,
    RetireObservation, RunCommandRequest, RunCommandResponse, RuntimeInventoryEntry, RuntimePermit,
    SandboxLiveProbeState, SandboxRecord, SandboxRuntime, SignalOutcome, SignalProcessRequest,
    SignalTarget, SnapshotRequest, SnapshotResponse, StatPathRequest, StopSandboxRequest,
    StopSandboxResponse, WriteFileRequest, WriteFileResponse, WriteStdinRequest,
    bounded_denied_grants, default_incus_instance_name, resolve_managed_instance_name,
    validate_managed_instance_name,
};
pub use unsupported::UnsupportedRuntime;

#[cfg(target_os = "linux")]
pub use incus::{
    BindingIdentity, BoundInstance, DnsRefreshOutcome, DnsTransport, ExecSupervisor,
    FakeDnsOutcome, FakeDnsRecord, FakeDnsTransport, HostInstance, IncusClient, IncusCommandOutput,
    IncusConfig, IncusKvmRuntime, ListedInstance, UdpDnsTransport, host_dns_servers,
    sandbox_network_names,
};
#[cfg(target_os = "linux")]
pub use incus::{
    DaemonIdentity, LEASE_PROFILE_PREFIX, LEASE_RENEW_EVERY, LEASE_TTL_SECS, LeaseEvent,
    LeaseFencedProbe, LeaseHealth, LeaseHolder, LeaseTiming, ServerLease, ServerLeaseError,
};

/// Host runtime backend selected by `wssp host run`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostRuntimeKind {
    Fake,
    #[cfg(target_os = "linux")]
    IncusKvm,
}

/// Select the compile-time default runtime for the current target.
pub fn default_runtime() -> Result<Box<dyn SandboxRuntime>, RuntimeError> {
    default_runtime_for(HostRuntimeKind::default_for_target())
}

pub fn build_runtime(kind: HostRuntimeKind) -> Result<Box<dyn SandboxRuntime>, RuntimeError> {
    match kind {
        HostRuntimeKind::Fake => Ok(Box::new(FakeRuntime::new())),
        #[cfg(target_os = "linux")]
        HostRuntimeKind::IncusKvm => Ok(Box::new(IncusKvmRuntime::new(IncusConfig::from_env())?)),
    }
}

pub fn default_runtime_for(kind: HostRuntimeKind) -> Result<Box<dyn SandboxRuntime>, RuntimeError> {
    build_runtime(kind)
}

impl HostRuntimeKind {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "fake" => Some(Self::Fake),
            "incus" | "incus-kvm" | "incus_kvm" => {
                #[cfg(target_os = "linux")]
                {
                    Some(Self::IncusKvm)
                }
                #[cfg(not(target_os = "linux"))]
                {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn default_for_target() -> Self {
        #[cfg(target_os = "linux")]
        {
            match std::env::var("WSSP_RUNTIME").as_deref() {
                Ok("fake") => Self::Fake,
                _ => Self::IncusKvm,
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            Self::Fake
        }
    }

    pub fn protocol_runtime_kind(self) -> sandbox_protocol::RuntimeKind {
        match self {
            Self::Fake => sandbox_protocol::RuntimeKind::Fake,
            #[cfg(target_os = "linux")]
            Self::IncusKvm => sandbox_protocol::RuntimeKind::IncusKvm,
        }
    }
}
