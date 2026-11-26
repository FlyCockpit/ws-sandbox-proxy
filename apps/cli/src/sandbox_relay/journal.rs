//! Private atomic host receipts. Intent is fsync/renamed before any external effect.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
#[cfg(unix)]
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use ring::digest::{SHA256, digest};
use sandbox_protocol::{OperationDispatch, OperationState, SandboxErrorCode};
use serde::{Deserialize, Serialize};

mod configs;
mod key;
pub mod storage;
pub(super) use configs::ConfigInstallIo;
mod lease_record;
mod leases;
mod retire;
pub use lease_record::{LeaseGuest, LeaseRecord};
pub(super) use leases::StaleEnforcementLossAuthority;
pub use leases::{LEASE_CEILING_SKEW_MS, LeaseCeilingExceeded, lease_within_ceiling};
pub(super) use retire::{COMMAND_STOP_UNPROVEN_EXT, CommandRetirement, RetirePacing, RetireSettle};
pub const JOURNAL_VERSION: u32 = 1;

// Wire counterpart of the API's CANCELLABLE_OPERATION_KINDS; protocol.test.ts
// checks parity through OPERATION_DISPATCH_KIND. Unknown kinds fail closed.
pub(super) const CANCELLABLE_DISPATCH_KINDS: &[&str] = &[
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
];

/// The most leases with an unfinished expiry the journal admits, and the
/// most expiry actions the expiry worker runs at once.
pub(super) const MAX_ACTIONS: usize = 64;

pub fn confirmed_release(
    kind: &str,
    state: OperationState,
    result: Option<&serde_json::Value>,
) -> bool {
    state == OperationState::Succeeded
        && matches!(
            (
                kind,
                result.and_then(|v| v.get("state")).and_then(|v| v.as_str())
            ),
            ("sandbox.stop", Some("stopped" | "absent")) | ("sandbox.kill", Some("deleted"))
        )
}

pub(super) fn guest_from_dispatch(dispatch: &OperationDispatch) -> sandbox_runtime::GuestIdentity {
    sandbox_runtime::GuestIdentity {
        guest_uid: dispatch.guest_uid.unwrap_or(1000),
        guest_gid: dispatch.guest_gid.unwrap_or(1000),
        guest_home: dispatch
            .guest_home
            .clone()
            .unwrap_or_else(|| "/home/user".to_string()),
        guest_shell: dispatch
            .guest_shell
            .clone()
            .unwrap_or_else(|| "/bin/bash".to_string()),
    }
}

/// Bounded extension fields preserved by every record rewrite.
pub type JournalExt = BTreeMap<String, serde_json::Value>;
const EXT_MAX_KEYS: usize = 16;
const EXT_KEY_MAX_BYTES: usize = 64;
const EXT_MAX_BYTES: usize = 4096;
const MAX_RECEIPTS: usize = 4096;
const CREATOR_MAX_RECEIPTS: usize = MAX_RECEIPTS - 1;
const TEARDOWN_HEADROOM: usize = 64;
const MAX_COMPLETED_RECEIPTS: usize = 64;
use sandbox_protocol::{
    RECEIPT_LIMITS, ReceiptConfirmation, canonical_body_hash, valid_receipt_fields,
};

#[cfg(test)]
thread_local! {
    /// Test pause point in [`HostJournal::settle_not_issued`]: after the
    /// expiry decided which attempt to settle, before the journal is locked.
    pub(super) static SETTLE_PAUSE: std::cell::RefCell<Option<Box<dyn Fn()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Why the host itself cancelled an attempt, journaled as the receipt's
/// `ext.cancelReason`. An unknown value reads as no reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelReason {
    /// Carried across a relay outage past the node's `max_carry` (D2): a
    /// proven stop settles FAILED `host_disconnect_expired`.
    CarryExpired,
}
impl CancelReason {
    pub const EXT_KEY: &'static str = "cancelReason";
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CarryExpired => "carry_expired",
        }
    }
    /// The reason journaled on this exact receipt, if any.
    pub fn of(receipt: &HostReceipt) -> Option<Self> {
        match receipt.ext.get(Self::EXT_KEY)?.as_str()? {
            "carry_expired" => Some(Self::CarryExpired),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptPhase {
    Intent,
    Effect,
    Result,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashPoint {
    AfterRetainedRoot,
    BeforeConfigPersist,
    BeforeConfigFileSync,
    BeforeConfigDirectorySync,
    BeforePrunedReceiptDirectorySync,
    AfterConfigPersist,
    AfterDigestPrune,
    BeforeConfigUnlink,
    AfterConfigUnlink,
    BeforeExpiry,
    BeforeExpiryComplete,
    BeforeLease,
    AfterLeaseDecision,
    AfterIntent,
    AfterEffect,
    BeforeResult,
    AfterResult,
    BeforeCancel,
    AfterCancel,
    AfterCleanupWatermark,
    AfterEvictedLease,
    AfterEvictedWatermark,
    BeforeReceiptDelete,
    AfterReceiptDelete,
    AfterReceiptDirectorySync,
}

pub use sandbox_protocol::TransportBindingV11;

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostReceipt {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capacity_reason: Option<sandbox_protocol::capacity_v11::CapacityReason>,
    /// Typed egress refusal (`unsupported_capability` only), replayed with
    /// the receipt so a reconnect reports the same reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_refusal: Option<sandbox_protocol::EgressRefusalReason>,
    /// The failed readiness check (`guest_unavailable` only), replayed with
    /// the receipt so the server records the same reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness_reason: Option<sandbox_protocol::ReadinessFailureReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allocation: Option<sandbox_protocol::capacity_v11::PinnedAllocationV11>,
    /// Immutable launch allocation, durable before any runtime Effect.
    pub vm_size: sandbox_protocol::VmSize,
    pub lease: Option<LeaseRecord>,
    pub version: u32,
    pub server: String,
    pub host_owner_id: String,
    pub sandbox_owner_id: String,
    pub host_id: String,
    pub sandbox_id: String,
    pub generation: u64,
    pub operation_id: String,
    pub attempt: u64,
    pub kind: String,
    pub template_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_hash: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub digest_pruned: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_config: Option<sandbox_protocol::PrivateConfigRef>,
    /// Original server request MAC for the control-plane receipt/confirmation
    /// fence. The daemon request_hash and body_hash use its derived host key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_request_hash: Option<String>,
    // Field encodings are stable within a journal version; other versions are refused at open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest_scheme: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest_key_id: Option<String>,
    pub idempotency_key: String,
    pub phase: ReceiptPhase,
    pub state: OperationState,
    pub cancel_requested: bool,
    pub result: Option<serde_json::Value>,
    /// Open code: a newer daemon's `Other` is kept and replayed verbatim.
    pub error_code: Option<sandbox_protocol::WireErrorCode>,
    pub error_message: Option<String>,
    pub written_at_unix_ms: u64,
    /// `file.put` only: what crash recovery needs to settle the attempt from
    /// guest evidence (the guest staging name derives from the attempt).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_put: Option<FilePutIntent>,
    /// Fixed pre-issue recovery deadline; never refreshed by result/replay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_deadline_unix_ms: Option<u64>,
    /// A launch's journaled launch mode (`new_root`
    /// for a restore reconnect), so restart recovery and allocation
    /// attestation resolve a restore with create proofs. Omitted while
    /// absent so other receipts keep their checksum.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch_mode: Option<sandbox_protocol::LaunchMode>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub ext: JournalExt,
}

impl HostReceipt {
    /// [`sandbox_runtime::AllocationKind`] of this receipt (restore → create).
    pub fn allocation_kind(&self) -> Option<sandbox_runtime::AllocationKind> {
        sandbox_runtime::AllocationKind::from_launch(&self.kind, self.launch_mode)
    }
}

// Nonlaunch operations retain this explicit, unused VM size.
pub(super) fn default_vm_size() -> sandbox_protocol::VmSize {
    sandbox_protocol::VmSize {
        cpu_count: 1,
        memory_mi_b: 1024,
    }
}

impl std::fmt::Debug for HostReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostReceipt")
            .field("operation_id", &self.operation_id)
            .field("phase", &self.phase)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilePutIntent {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub incus_name: Option<String>,
    pub guest_uid: u32,
    pub guest_gid: u32,
    pub guest_home: String,
    pub guest_shell: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub ext: JournalExt,
}

/// The checksum covers the exact receipt bytes stored on disk.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalEnvelope {
    receipt: Box<serde_json::value::RawValue>,
    checksum: String,
}

/// Survives confirmation of the cleanup receipt. One monotonic entry per
/// sandbox, bound to the same authenticated host/owner/server as its receipts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CleanupWatermark {
    version: u32,
    binding: TransportBindingV11,
    sandbox_owner_id: String,
    sandbox_id: String,
    generation: u64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    instance_absent: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    ext: JournalExt,
}

/// Checksummed like [`JournalEnvelope`] over the exact stored bytes.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CleanupEnvelope {
    watermark: Box<serde_json::value::RawValue>,
    checksum: String,
}

/// Decode a record only when its exact stored bytes match the checksum.
fn checked_record<T: serde::de::DeserializeOwned>(
    raw: &serde_json::value::RawValue,
    checksum: &str,
) -> Result<Option<T>> {
    let record: T = serde_json::from_str(raw.get())?;
    Ok((checksum == sha256_hex(raw.get().as_bytes())).then_some(record))
}

fn checksummed_raw<T: Serialize>(record: &T) -> Result<(Box<serde_json::value::RawValue>, String)> {
    let text = serde_json::to_string(record)?;
    let checksum = sha256_hex(text.as_bytes());
    Ok((serde_json::value::RawValue::from_string(text)?, checksum))
}

fn receipt_envelope_bytes(receipt: &HostReceipt) -> Result<Vec<u8>> {
    let (receipt, checksum) = checksummed_raw(receipt).context("serialize receipt")?;
    Ok(serde_json::to_vec(&JournalEnvelope { receipt, checksum })?)
}

fn valid_ext(ext: &JournalExt) -> bool {
    ext.len() <= EXT_MAX_KEYS
        && ext.keys().all(|key| {
            key.len() <= EXT_KEY_MAX_BYTES
                && key.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
                && key.bytes().all(|b| b.is_ascii_alphanumeric())
        })
        && serde_json::to_vec(ext).is_ok_and(|bytes| bytes.len() <= EXT_MAX_BYTES)
}

#[derive(Debug)]
struct JournalState {
    storage: storage::StorageLedger,
    configs: HashMap<String, configs::RetainedConfig>,
    lease_workers: HashMap<String, usize>,
    leases: HashMap<String, LeaseRecord>,
    receipts: HashMap<String, HostReceipt>,
    cleanups: HashMap<String, CleanupWatermark>,
    // Exact confirmations whose unlink/fsync is in progress in this process.
    confirmed_receipts: HashSet<String>,
    /// The pending set of `retireCommand` confirmations (bounded,
    /// in memory: a lost one is re-requested next session). Each entry keeps
    /// the session that admitted it; an entry in flight keeps its slot.
    retirements: Vec<retire::RetireEntry>,
    /// No retry starts before this instant (one per paced
    /// interval across the host's sessions).
    retry_paced_until: Option<std::time::Instant>,
    /// This session's `hello.ok` answered `commandRetire`.
    command_retire: bool,
    /// Bumped at every negotiation change (each `hello` and
    /// `hello.ok`); a proof deletes a receipt only under the token it was
    /// queued with, so no proof outlives its session's negotiation.
    retire_session: u64,
}

impl JournalState {
    fn validate_workload_owners(&self) -> Result<()> {
        let mut owners = HashMap::<&str, &str>::new();
        let entries = self
            .receipts
            .values()
            .map(|r| (r.sandbox_id.as_str(), r.sandbox_owner_id.as_str()))
            .chain(
                self.leases
                    .values()
                    .map(|r| (r.sandbox_id.as_str(), r.sandbox_owner_id.as_str())),
            )
            .chain(
                self.cleanups
                    .values()
                    .map(|r| (r.sandbox_id.as_str(), r.sandbox_owner_id.as_str())),
            )
            .chain(
                self.storage
                    .roots
                    .iter()
                    .map(|(id, r)| (id.as_str(), r.sandbox_owner_id.as_str())),
            )
            .chain(
                self.configs
                    .iter()
                    .map(|(id, r)| (id.as_str(), r.sandbox_owner())),
            );
        for (id, owner) in entries {
            anyhow::ensure!(
                sandbox_protocol::valid_terminal_id(owner),
                "invalid workload owner"
            );
            if let Some(previous) = owners.insert(id, owner) {
                anyhow::ensure!(
                    previous == owner,
                    "journal workload identity differs; preserve original evidence"
                );
            }
        }
        Ok(())
    }
    fn sandbox_owner(&self, id: &str) -> Option<&str> {
        self.leases
            .get(id)
            .map(|r| r.sandbox_owner_id.as_str())
            .or_else(|| {
                self.storage
                    .roots
                    .get(id)
                    .map(|r| r.sandbox_owner_id.as_str())
            })
            .or_else(|| self.cleanups.get(id).map(|r| r.sandbox_owner_id.as_str()))
            .or_else(|| self.configs.get(id).map(|r| r.sandbox_owner()))
            .or_else(|| {
                self.receipts
                    .values()
                    .find(|r| r.sandbox_id == id)
                    .map(|r| r.sandbox_owner_id.as_str())
            })
    }
}

#[derive(Debug)]
pub struct HostJournal {
    storage_path: PathBuf,
    instance_id: String,
    pub(super) clock: std::sync::Arc<super::clock::LeaseClock>,
    configs_dir: PathBuf,
    leases_dir: PathBuf,
    receipts_dir: PathBuf,
    cleanups_dir: PathBuf,
    _lock: File,
    /// Journal-wide IO latch: every durable write goes through it.
    pub(super) io: IoLatch,
    state: Mutex<JournalState>,
    key: Mutex<Option<key::MemoryJournalKey>>,
    crash: Mutex<Option<CrashPoint>>,
    /// Host lease ceiling (`None` = unlimited) checked when a dispatched lease
    /// will be stored. 24 hours until the daemon sets the configured value.
    lease_ceiling: Mutex<Option<u64>>,
    /// `max_concurrent_commands` of this daemon: the per-sandbox receipt cap
    /// is `max(SANDBOX_COMMAND_RECEIPTS_MIN, this)` (DG-10).
    max_concurrent_commands: std::sync::atomic::AtomicUsize,
}

/// The per-sandbox floor of retained non-terminal `command.run` receipts
/// (DG-10, I12): one sandbox, however hostile, never holds more than
/// `max(64, max_concurrent_commands)` of this host's journal.
pub(super) const SANDBOX_COMMAND_RECEIPTS_MIN: usize = 64;

impl HostJournal {
    /// The daemon's command concurrency (`--max-concurrent-commands`); the
    /// per-sandbox receipt cap never drops below it.
    pub fn set_max_concurrent_commands(&self, max: u32) {
        self.max_concurrent_commands.store(
            usize::try_from(max).unwrap_or(usize::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    fn sandbox_command_receipts_max(&self) -> usize {
        SANDBOX_COMMAND_RECEIPTS_MIN.max(
            self.max_concurrent_commands
                .load(std::sync::atomic::Ordering::Relaxed),
        )
    }

    /// The journal's private state directory (holds the lock and records).
    pub(super) fn state_dir(&self) -> Option<&Path> {
        self.storage_path.parent()
    }
    /// Durable write inside the journal directory (fsync file and directory).
    pub(super) fn persist_marker(&self, name: &str, bytes: &[u8]) -> Result<()> {
        let dir = self
            .state_dir()
            .ok_or_else(|| anyhow::anyhow!("journal directory missing"))?;
        persist_bytes(&self.io, dir, &dir.join(name), bytes)
    }
    /// Durably removes a marker written by [`Self::persist_marker`] (absent
    /// is fine). Unlink and directory fsync run through the journal IO
    /// latch: a failure closes admission like any journal write.
    pub(super) fn remove_marker(&self, name: &str) -> Result<()> {
        let dir = self
            .state_dir()
            .ok_or_else(|| anyhow::anyhow!("journal directory missing"))?;
        remove_durably(&self.io, &dir.join(name), true)?;
        sync_dir(&self.io, dir)
    }
    pub fn sandbox_owner(&self, sandbox_id: &str) -> Option<String> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .sandbox_owner(sandbox_id)
            .map(str::to_owned)
    }
    /// Refuse before any body MAC on a missing/replaced key. Existing keyed
    /// history cannot be downgraded by changing the incoming kind or scheme.
    pub fn prepare_dispatch(
        &self,
        binding: &TransportBindingV11,
        dispatch: &OperationDispatch,
    ) -> std::result::Result<HostReceipt, SandboxErrorCode> {
        self.prepare_dispatch_with(binding, dispatch, |key, domain, bytes| {
            key.mac(domain, bytes)
        })
    }

    fn prepare_dispatch_with(
        &self,
        binding: &TransportBindingV11,
        dispatch: &OperationDispatch,
        mut mac: impl FnMut(&key::MemoryJournalKey, &str, &str) -> String,
    ) -> std::result::Result<HostReceipt, SandboxErrorCode> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if !binding.is_valid()
            || !sandbox_protocol::valid_terminal_id(&dispatch.sandbox_owner_id)
            || state
                .sandbox_owner(&dispatch.sandbox_id)
                .is_some_and(|owner| owner != dispatch.sandbox_owner_id)
        {
            return Err(SandboxErrorCode::ProtocolError);
        }
        let existing = state.receipts.get(&dispatch.operation_id).cloned();
        let key = self.key.lock().unwrap_or_else(|err| err.into_inner());
        if let Some(old) = &existing {
            if old.digest_pruned {
                return Err(SandboxErrorCode::ReceiptDigestPruned);
            }
            if old.digest_scheme.as_deref() != Some("hmac-sha256-v1")
                && (dispatch.digest_scheme.as_deref() == Some("hmac-sha256-v1")
                    || dispatch.env.as_ref().is_some_and(|env| !env.is_empty()))
            {
                return Err(SandboxErrorCode::DigestKeyChanged);
            }
            if old.digest_scheme.as_deref() == Some("hmac-sha256-v1") {
                let installed = key.as_ref().ok_or(SandboxErrorCode::DigestKeyUnavailable)?;
                if old.digest_key_id.as_ref() != Some(&installed.key_id) {
                    return Err(SandboxErrorCode::DigestKeyChanged);
                }
            }
            if !old.binds(binding) || old.kind != dispatch.kind {
                return Err(SandboxErrorCode::IdempotencyConflict);
            }
        }
        if matches!(
            dispatch.kind.as_str(),
            "sandbox.create" | "sandbox.reconnect"
        ) && dispatch.private_config.is_none()
            && (state.configs.contains_key(&dispatch.sandbox_id)
                || state
                    .leases
                    .get(&dispatch.sandbox_id)
                    .is_some_and(|lease| lease.private_config.is_some()))
        {
            return Err(SandboxErrorCode::ProtocolError);
        }
        if dispatch
            .body_hash
            .as_deref()
            .is_none_or(|hash| !canonical_body_hash(hash))
        {
            return Err(SandboxErrorCode::ProtocolError);
        }
        let cleanup = sandbox_protocol::KEY_FREE_CLEANUP_KINDS.contains(&dispatch.kind.as_str());
        let env_bearing = dispatch.env.as_ref().is_some_and(|env| !env.is_empty())
            || dispatch.private_config.is_some();
        let keyed = dispatch.digest_scheme.as_deref() == Some("hmac-sha256-v1") || env_bearing;
        let mut host_request_hash = None;
        let (hash, scheme, key_id) = if cleanup {
            if dispatch.digest_scheme.as_deref() != Some("sha256-env-free-v1")
                || dispatch.env.is_some()
                || dispatch.argv.is_some()
                || dispatch.script.is_some()
                || dispatch.cwd.is_some()
                || dispatch.path.is_some()
                || dispatch.dest_path.is_some()
                || dispatch.stdin_sequence.is_some()
                || dispatch.timeout_ms.is_some()
                || dispatch.pid.is_some()
                || dispatch.signal.is_some()
                || dispatch.file_size.is_some()
                || dispatch.file_sha256.is_some()
                || dispatch.private_config.is_some()
                || dispatch.egress_policy.is_some()
                || dispatch.egress_policy_hash.is_some()
                || dispatch.digest_key_id.is_some()
                || keyed
                || existing.as_ref().is_some_and(|r| r.digest_key_id.is_some())
            {
                return Err(SandboxErrorCode::ProtocolError);
            }
            let safe = serde_json::json!({"sandboxOwnerId":dispatch.sandbox_owner_id, "server": binding.server, "hostOwnerId": binding.host_owner_id,
                "host": binding.host_id, "sandboxId": dispatch.sandbox_id, "operationId": dispatch.operation_id,
                "kind": dispatch.kind, "generation": dispatch.generation,
                "idempotencyKey": dispatch.idempotency_key, "incusName": dispatch.incus_name,
                "templateDigest": dispatch.template_digest, "incusFingerprint": dispatch.incus_fingerprint,
                "lease": dispatch.lease, "requestHash": dispatch.body_hash });
            (
                sha256_hex(safe.to_string().as_bytes()),
                "sha256-env-free-v1",
                None,
            )
        } else if keyed {
            let installed = key.as_ref().ok_or(SandboxErrorCode::DigestKeyUnavailable)?;
            if installed.binding != *binding
                || dispatch.digest_key_id.as_ref() != Some(&installed.key_id)
                || dispatch.digest_scheme.as_deref() != Some("hmac-sha256-v1")
            {
                return Err(SandboxErrorCode::DigestKeyChanged);
            }
            if let Some(config) = &dispatch.private_config {
                configs::check_reference(
                    &self.configs_dir,
                    &state,
                    installed,
                    binding,
                    &dispatch.sandbox_id,
                    dispatch.generation,
                    config,
                )
                .map_err(|error| {
                    error
                        .downcast_ref::<SandboxErrorCode>()
                        .copied()
                        .unwrap_or(SandboxErrorCode::ProtocolError)
                })?;
            }
            host_request_hash = Some(mac(
                installed,
                "wssp-host-request-v1",
                &serde_json::json!({"sandboxOwnerId":dispatch.sandbox_owner_id, "sandboxId":dispatch.sandbox_id,
                    "generation": dispatch.generation, "requestHash":dispatch.body_hash.as_deref().ok_or(SandboxErrorCode::ProtocolError)?}).to_string(),
            ));
            (
                mac(installed, "wssp-host-dispatch-v1", &{
                    let mut canonical = dispatch.clone();
                    if let Some(env) = &mut canonical.env {
                        env.sort();
                    }
                    let mut body = serde_json::to_value(&canonical)
                        .map_err(|_| SandboxErrorCode::ProtocolError)?;
                    let fields = body
                        .as_object_mut()
                        .ok_or(SandboxErrorCode::ProtocolError)?;
                    // Retry transport metadata must not demote a known result.
                    // Operation, sandbox, generation and idempotency identities
                    // remain bound here and are fenced again by record_intent.
                    fields.remove("attempt");
                    fields.remove("stdinSequence");
                    if let Some(version) = dispatch.result_version {
                        fields.insert("resultVersion".into(), serde_json::json!(version));
                    }
                    if let Some(limit) = dispatch.limit {
                        fields.insert("limit".into(), serde_json::json!(limit));
                    }
                    if let Some(cursor) = &dispatch.continuation {
                        fields.insert("continuation".into(), serde_json::json!(cursor));
                    }
                    body.to_string()
                }),
                "hmac-sha256-v1",
                Some(installed.key_id.clone()),
            )
        } else {
            return Err(SandboxErrorCode::ProtocolError);
        };
        let mut receipt = build_intent(
            binding,
            dispatch,
            hash,
            dispatch
                .body_hash
                .clone()
                .ok_or(SandboxErrorCode::ProtocolError)?,
            Some(scheme.into()),
            key_id,
        );
        if let Some(request_hash) = host_request_hash {
            receipt.server_request_hash = receipt.request_hash;
            receipt.request_hash = Some(request_hash);
        }
        if let Some(old) = existing
            && old.body_hash != receipt.body_hash
        {
            return Err(SandboxErrorCode::IdempotencyConflict);
        }
        Ok(receipt)
    }

    pub fn clear_key(&self) {
        *self.key.lock().unwrap_or_else(|err| err.into_inner()) = None;
    }

    pub fn install_key(
        &self,
        frame: &sandbox_protocol::JournalKeyInstall,
        binding: &TransportBindingV11,
        epoch: u64,
    ) -> Result<()> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.configs.values().any(|config| !config.binds(binding)) {
            bail!("private config journal refused");
        }
        let key = key::MemoryJournalKey::install(frame, binding, epoch)?;
        *self.key.lock().unwrap_or_else(|err| err.into_inner()) = Some(key);
        Ok(())
    }

    pub fn open(dir: impl AsRef<Path>, binding: &TransportBindingV11) -> Result<Self> {
        #[cfg(unix)]
        {
            Self::open_unix(dir.as_ref(), binding)
        }
        #[cfg(not(unix))]
        {
            let _ = (dir, binding);
            bail!("durable host receipts require Unix directory fsync support");
        }
    }

    #[cfg(unix)]
    fn open_unix(dir: &Path, binding: &TransportBindingV11) -> Result<Self> {
        private_dir(dir)?;
        let receipts_dir = dir.join("receipts");
        private_dir(&receipts_dir)?;
        let lock_path = dir.join("LOCK");
        let lock = {
            use std::os::unix::fs::OpenOptionsExt;
            OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .mode(0o600)
                .open(&lock_path)
        }
        .with_context(|| format!("open journal lock {}", lock_path.display()))?;
        private_file(&lock_path)?;
        lock_exclusive(&lock)?;
        let version_path = dir.join("VERSION");
        if version_path.try_exists()? {
            private_file(&version_path)?;
            anyhow::ensure!(
                fs::metadata(&version_path)?.len() <= 16,
                "invalid journal version marker"
            );
            anyhow::ensure!(
                fs::read_to_string(&version_path)? == JOURNAL_VERSION.to_string(),
                "unsupported journal version; retire allocations using the original daemon and preserve its journal"
            );
        } else {
            anyhow::ensure!(
                !dir.join("IDENTITY").try_exists()?,
                "journal state without a version marker is unsupported; preserve it, retire its allocations with the daemon that wrote it, and use a fresh private directory"
            );
            persist_bytes(
                &IoLatch::default(),
                dir,
                &version_path,
                JOURNAL_VERSION.to_string().as_bytes(),
            )?;
        }
        // Durable, non-secret journal lineage. A fresh state directory cannot
        // certify work sent to an earlier journal under the same host token.
        let identity_path = dir.join("IDENTITY");
        let instance_id = match fs::symlink_metadata(&identity_path) {
            Ok(_) => {
                private_file(&identity_path)?;
                let id = fs::read_to_string(&identity_path)?;
                if id.len() != 32
                    || !id
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    bail!("invalid journal identity");
                }
                id
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                use ring::rand::SecureRandom;
                let mut bytes = [0u8; 16];
                ring::rand::SystemRandom::new()
                    .fill(&mut bytes)
                    .map_err(|_| anyhow::anyhow!("journal identity randomness unavailable"))?;
                let id = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
                persist_bytes(&IoLatch::default(), dir, &identity_path, id.as_bytes())?;
                id
            }
            Err(error) => return Err(error.into()),
        };
        File::open(dir)?.sync_all()?;
        let cleanups_dir = dir.join("cleanups");
        private_dir(&cleanups_dir)?;
        let cleanups = load_cleanups(&cleanups_dir)?;
        let mut receipts = load_receipts(&receipts_dir)?;
        if receipts.values().any(|r| {
            r.server != binding.server
                || r.host_id != binding.host_id
                || (!binding.host_owner_id.is_empty() && r.host_owner_id != binding.host_owner_id)
        }) || cleanups.values().any(|c| {
            c.binding.server != binding.server
                || c.binding.host_id != binding.host_id
                || (!binding.host_owner_id.is_empty()
                    && c.binding.host_owner_id != binding.host_owner_id)
        }) {
            bail!("journal belongs to a different server, owner or host");
        }
        let leases_dir = dir.join("leases");
        private_dir(&leases_dir)?;
        File::open(dir)?.sync_all()?;
        let configs_dir = dir.join("private-configs");
        private_dir(&configs_dir)?;
        File::open(dir)?.sync_all()?;
        let configs = configs::load(&configs_dir, binding)?;
        let leases = lease_record::load(&leases_dir, binding, &receipts)?;
        let io = IoLatch::default();
        prune_completed(&io, &receipts_dir, &mut receipts)?;
        let storage_path = dir.join("storage.json");
        let storage = storage::StorageLedger::load(&storage_path, binding)?;
        let state = JournalState {
            storage,
            configs,
            lease_workers: HashMap::new(),
            receipts,
            cleanups,
            leases,
            confirmed_receipts: HashSet::new(),
            retirements: Vec::new(),
            retry_paced_until: None,
            command_retire: false,
            retire_session: 0,
        };
        state.validate_workload_owners()?;
        let journal = Self {
            storage_path,
            instance_id,
            clock: std::sync::Arc::new(super::clock::LeaseClock::default()),
            configs_dir,
            leases_dir,
            receipts_dir,
            cleanups_dir,
            _lock: lock,
            io,
            state: Mutex::new(state),
            key: Mutex::new(None),
            crash: Mutex::new(None),
            lease_ceiling: Mutex::new(Some(sandbox_protocol::DEFAULT_MAX_LEASE_MS)),
            max_concurrent_commands: std::sync::atomic::AtomicUsize::new(0),
        };
        journal.recover_storage()?;
        // A crash between the watermark fsync and lease removal resumes the
        // compaction here, after storage recovery has read the release facts
        // of the records it removes (an eviction's lease).
        {
            let mut state = journal.state.lock().unwrap_or_else(|e| e.into_inner());
            leases::compact_confirmed(
                &journal.io,
                &journal.leases_dir,
                &journal.cleanups_dir,
                &mut state,
            )?;
        }
        journal.maintain()?;
        Ok(journal)
    }

    #[cfg(test)]
    pub fn inject_crash(&self, point: CrashPoint) {
        *self.crash.lock().unwrap_or_else(|err| err.into_inner()) = Some(point);
    }

    pub fn lookup(&self, operation_id: &str) -> Option<HostReceipt> {
        self.state
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .receipts
            .get(operation_id)
            .cloned()
    }

    /// WP7: terminal `kind` results written at or after `since_ms` (wall
    /// clock, as `written_at_unix_ms`) that still wait for the server's
    /// confirmation. A quiesce drains them before it restarts.
    pub(super) fn unconfirmed_results_since(&self, kind: &str, since_ms: u64) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .receipts
            .values()
            .filter(|r| {
                r.kind == kind
                    && r.is_terminal()
                    && !r.digest_pruned
                    && r.written_at_unix_ms >= since_ms
            })
            .count()
    }

    /// Sample before accept_lease/record_effect, while the exact Intent still
    /// proves this attempt unissued. Reconnect permits older generations' history
    /// (its retained disk), never history from this or a newer generation.
    pub(super) fn first_allocation_attempt(&self, d: &OperationDispatch) -> bool {
        self.lookup(&d.operation_id).is_some_and(|r| {
            r.sandbox_id == d.sandbox_id
                && r.generation == d.generation
                && r.attempt == d.attempt
                && r.kind == d.kind
                && r.idempotency_key == d.idempotency_key
                && self.first_allocation_receipt(&r)
        })
    }

    /// Read-only proof for work refused before intent admission (including a
    /// full journal). Capacity is not corruption: retained lineage is readable.
    /// Any receipt/key collision, lease or cleanup makes the lineage ambiguous.
    pub(super) fn first_unadmitted_allocation(&self, receipt: &HostReceipt) -> bool {
        let state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        let relevant =
            |generation| receipt.kind != "sandbox.reconnect" || generation >= receipt.generation;
        matches!(
            receipt.kind.as_str(),
            "sandbox.create" | "sandbox.reconnect"
        ) && receipt.attempt == 1
            && !self.io.failed()
            && !state.lease_workers.contains_key(&receipt.sandbox_id)
            && !state.receipts.contains_key(&receipt.operation_id)
            && !state.receipts.values().any(|r| {
                (r.sandbox_id == receipt.sandbox_id && relevant(r.generation))
                    || (r.idempotency_key == receipt.idempotency_key && r.same_binding(receipt))
            })
            && !state
                .leases
                .get(&receipt.sandbox_id)
                .is_some_and(|r| relevant(r.generation))
            && !state
                .cleanups
                .get(&receipt.sandbox_id)
                .is_some_and(|r| relevant(r.generation))
    }

    pub(super) fn first_allocation_receipt(&self, receipt: &HostReceipt) -> bool {
        let state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        let reconnect = receipt.kind == "sandbox.reconnect";
        let relevant = |generation| !reconnect || generation >= receipt.generation;
        matches!(
            receipt.kind.as_str(),
            "sandbox.create" | "sandbox.reconnect"
        ) && receipt.attempt == 1
            && state.receipts.get(&receipt.operation_id).is_some_and(|r| {
                r.sandbox_id == receipt.sandbox_id
                    && r.generation == receipt.generation
                    && r.attempt == 1
                    && r.idempotency_key == receipt.idempotency_key
                    && r.kind == receipt.kind
                    && r.phase == ReceiptPhase::Intent
                    && !r.digest_pruned
            })
            && !state
                .leases
                .get(&receipt.sandbox_id)
                .is_some_and(|r| relevant(r.generation))
            && !state
                .cleanups
                .get(&receipt.sandbox_id)
                .is_some_and(|r| relevant(r.generation))
            && !state.receipts.values().any(|r| {
                r.sandbox_id == receipt.sandbox_id
                    && r.operation_id != receipt.operation_id
                    && relevant(r.generation)
            })
    }

    #[cfg(test)]
    pub(super) fn seed_pruned_receipt_for_test(&self, operation_id: &str) {
        let mut state = self.state.lock().unwrap();
        let tombstone = state.receipts[operation_id].clone().into_digest_pruned();
        persist_receipt(&self.io, &self.receipts_dir, &tombstone).unwrap();
        state.receipts.insert(operation_id.into(), tombstone);
    }

    pub fn cancel_blocks(&self, operation_id: &str, generation: u64) -> bool {
        self.lookup(operation_id)
            .is_some_and(|receipt| receipt.cancel_requested && receipt.generation == generation)
    }

    pub fn maintain(&self) -> Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        prune_completed(&self.io, &self.receipts_dir, &mut state.receipts)?;
        // Replay an eviction's watermark before the config GC.
        leases::settle_absent_watermarks(&self.io, &self.cleanups_dir, &mut state)?;
        self.gc_configs_locked(&mut state)?;
        leases::compact_confirmed(&self.io, &self.leases_dir, &self.cleanups_dir, &mut state)
    }

    pub fn record_intent(&self, receipt: &HostReceipt) -> Result<Decision> {
        validate_receipt(receipt)?;
        if receipt.version != JOURNAL_VERSION {
            bail!("unsupported journal version {}", receipt.version);
        }
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        if state
            .sandbox_owner(&receipt.sandbox_id)
            .is_some_and(|owner| owner != receipt.sandbox_owner_id)
        {
            return Ok(Decision::Conflict);
        }
        prune_completed(&self.io, &self.receipts_dir, &mut state.receipts)?;
        if let Some(existing) = state.receipts.get(&receipt.operation_id) {
            if !existing.same_binding(receipt) || existing.sandbox_id != receipt.sandbox_id {
                return Ok(Decision::Conflict);
            }
            if existing.vm_size != receipt.vm_size || existing.allocation != receipt.allocation {
                return Ok(Decision::Conflict);
            }
            if existing.generation != receipt.generation {
                return Ok(Decision::Conflict);
            }
            if existing.digest_pruned {
                return Ok(Decision::Unknown(existing.clone()));
            }
            if existing.body_hash != receipt.body_hash
                || existing.kind != receipt.kind
                || existing.idempotency_key != receipt.idempotency_key
            {
                return Ok(Decision::Conflict);
            }
            match existing.phase {
                ReceiptPhase::Result => return Ok(Decision::Replay(existing.clone())),
                ReceiptPhase::Intent | ReceiptPhase::Effect => {
                    return Ok(Decision::Unknown(existing.clone()));
                }
            }
        }
        if receipt.digest_pruned {
            bail!("receipt_digest_pruned");
        }
        if content_dispatch(receipt)
            && state
                .receipts
                .values()
                .filter(|r| {
                    r.content_deadline_unix_ms
                        .is_some_and(|deadline| deadline > now_ms())
                })
                .count()
                >= sandbox_protocol::results::HOST_CONTENT_MAX_SLOTS
        {
            return Ok(Decision::Capacity);
        }
        // DG-10 (S10): one sandbox holds at most `max(64, concurrency)`
        // non-terminal `command.run` receipts, digest-pruned UNKNOWN ones
        // included (they still occupy the journal). After the replay branch
        // above, so a replay is never refused; stopping the sandbox frees them.
        if receipt.kind == "command.run"
            && state
                .receipts
                .values()
                .filter(|r| {
                    r.sandbox_id == receipt.sandbox_id
                        && r.kind == "command.run"
                        && !r.is_terminal()
                })
                .count()
                >= self.sandbox_command_receipts_max()
        {
            return Ok(Decision::SandboxReceipts);
        }
        let teardown = matches!(receipt.kind.as_str(), "sandbox.stop" | "sandbox.kill");
        // The caller has verified the workload MAC and the journal rejects a
        // different creator for retained sandbox lineage above. Count every
        // ordinary phase, including uncertain effects and pruned digests; only
        // positive settlement may free those entries. Cleanup has its own lane.
        if !teardown
            && state
                .receipts
                .values()
                .filter(|r| {
                    r.sandbox_owner_id == receipt.sandbox_owner_id
                        && !matches!(r.kind.as_str(), "sandbox.stop" | "sandbox.kill")
                })
                .count()
                >= CREATOR_MAX_RECEIPTS
        {
            return Ok(Decision::Capacity);
        }
        let limit = MAX_RECEIPTS + if teardown { TEARDOWN_HEADROOM } else { 0 };
        if state.receipts.len() >= limit {
            return Ok(Decision::Capacity);
        }
        if state
            .receipts
            .values()
            .any(|r| r.idempotency_key == receipt.idempotency_key && r.same_binding(receipt))
        {
            return Ok(Decision::Conflict);
        }
        if let Some(config) = &receipt.private_config {
            let key = self.key.lock().unwrap_or_else(|e| e.into_inner());
            let key = key
                .as_ref()
                .ok_or_else(|| anyhow::Error::msg(SandboxErrorCode::DigestKeyUnavailable))?;
            let binding = TransportBindingV11 {
                server: receipt.server.clone(),
                host_owner_id: receipt.host_owner_id.clone(),
                host_id: receipt.host_id.clone(),
            };
            configs::check_reference(
                &self.configs_dir,
                &state,
                key,
                &binding,
                &receipt.sandbox_id,
                receipt.generation,
                config,
            )?;
        }
        let mut stored = receipt.clone();
        stored.phase = ReceiptPhase::Intent;
        stored.state = OperationState::Accepted;
        stored.result = None;
        stored.written_at_unix_ms = now_ms();
        if content_dispatch(receipt) {
            stored.content_deadline_unix_ms = Some(
                stored
                    .written_at_unix_ms
                    .saturating_add(result_limits()?.mutation_content_retention_ms),
            );
        }
        self.retain_intent_locked(&mut state, &stored)?;
        self.maybe_crash(CrashPoint::AfterRetainedRoot)?;
        persist_receipt(&self.io, &self.receipts_dir, &stored)?;
        state
            .receipts
            .insert(stored.operation_id.clone(), stored.clone());
        drop(state);
        self.maybe_crash(CrashPoint::AfterIntent)?;
        Ok(Decision::Fresh)
    }

    pub fn record_effect(&self, operation_id: &str) -> Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        let Some(existing) = state.receipts.get(operation_id) else {
            bail!("effect without intent receipt {operation_id}");
        };
        if existing.digest_pruned {
            bail!("receipt_digest_pruned");
        }
        if existing.is_terminal() {
            bail!("effect after terminal result");
        }
        let mut existing = existing.clone();
        existing.phase = ReceiptPhase::Effect;
        existing.written_at_unix_ms = now_ms();
        persist_receipt(&self.io, &self.receipts_dir, &existing)?;
        state.receipts.insert(operation_id.into(), existing);
        drop(state);
        self.maybe_crash(CrashPoint::AfterEffect)?;
        Ok(())
    }

    pub fn record_result(
        &self,
        operation_id: &str,
        state: OperationState,
        result: Option<serde_json::Value>,
        error_code: Option<SandboxErrorCode>,
        error_message: Option<String>,
    ) -> Result<HostReceipt> {
        self.record_result_inner(
            operation_id,
            state,
            result,
            (error_code.map(Into::into), error_message, None),
            false,
            ResultFence::None,
        )?
        .context("result precondition")
    }

    /// An unissued recovery worker leaves its obligation pending. Refresh its
    /// queue age durably so a repeatedly refused resume yields to other VMs.
    pub fn defer_teardown(&self, operation_id: &str) -> Result<()> {
        let mut guard = self.state.lock().unwrap_or_else(|err| err.into_inner());
        let Some(existing) = guard.receipts.get(operation_id) else {
            bail!("deferral without intent receipt {operation_id}");
        };
        if existing.phase == ReceiptPhase::Result
            || existing.digest_pruned
            || !matches!(existing.kind.as_str(), "sandbox.kill" | "sandbox.stop")
        {
            return Ok(());
        }
        let mut deferred = existing.clone();
        deferred.written_at_unix_ms = now_ms().max(deferred.written_at_unix_ms.saturating_add(1));
        persist_receipt(&self.io, &self.receipts_dir, &deferred)?;
        guard.receipts.insert(operation_id.into(), deferred);
        Ok(())
    }

    pub fn record_reconciled_result(
        &self,
        operation_id: &str,
        state: OperationState,
        result: Option<serde_json::Value>,
        error_code: Option<sandbox_protocol::WireErrorCode>,
        error_message: Option<String>,
    ) -> Result<HostReceipt> {
        self.record_result_inner(
            operation_id,
            state,
            result,
            (error_code, error_message, None),
            true,
            ResultFence::None,
        )?
        .context("result precondition")
    }

    pub fn record_result_with_reason(
        &self,
        operation_id: &str,
        state: OperationState,
        result: Option<serde_json::Value>,
        failure: (
            Option<sandbox_protocol::WireErrorCode>,
            Option<String>,
            Option<sandbox_protocol::ProtocolErrorReason>,
        ),
    ) -> Result<HostReceipt> {
        self.record_result_inner(
            operation_id,
            state,
            result,
            failure,
            false,
            ResultFence::None,
        )?
        .context("result precondition")
    }

    /// A worker's or refusal's result for one exact `(generation, attempt)`:
    /// written only while the journaled receipt is still that attempt, in
    /// the same compare-and-set under the journal lock as every other result
    /// writer. `None`: the receipt moved on (a later attempt was admitted
    /// after this one was settled and confirmed), and is left untouched — a
    /// stale queued worker that wakes after a redispatch must never settle
    /// the newer attempt (fu-a, integration review).
    pub fn record_attempt_result(
        &self,
        operation_id: &str,
        (generation, attempt): (u64, u64),
        state: OperationState,
        result: Option<serde_json::Value>,
        failure: (
            Option<sandbox_protocol::WireErrorCode>,
            Option<String>,
            Option<sandbox_protocol::ProtocolErrorReason>,
        ),
    ) -> Result<Option<HostReceipt>> {
        self.record_attempt_result_ext(
            operation_id,
            (generation, attempt),
            state,
            result,
            failure,
            &[],
        )
    }

    /// [`Self::record_attempt_result`] plus `ext` keys in the same write
    /// (`commandStopUnproven` on an interim command observation).
    pub fn record_attempt_result_ext(
        &self,
        operation_id: &str,
        (generation, attempt): (u64, u64),
        state: OperationState,
        result: Option<serde_json::Value>,
        failure: (
            Option<sandbox_protocol::WireErrorCode>,
            Option<String>,
            Option<sandbox_protocol::ProtocolErrorReason>,
        ),
        ext: &[(&str, serde_json::Value)],
    ) -> Result<Option<HostReceipt>> {
        self.record_result_ext(
            operation_id,
            state,
            result,
            failure,
            false,
            ResultFence::Attempt(generation, attempt),
            ext,
        )
    }

    /// WP3: settle a carried attempt that never reached its effect gate as
    /// FAILED `host_effect_not_issued`, as ONE compare-and-set under the
    /// journal lock: only while the journaled receipt is still this exact
    /// `(generation, attempt)` in Intent. A receipt that moved on (settled,
    /// confirmed and redispatched as a later attempt, or in Effect) is left
    /// untouched. Returns whether it wrote.
    pub fn settle_not_issued(
        &self,
        operation_id: &str,
        generation: u64,
        attempt: u64,
    ) -> Result<bool> {
        #[cfg(test)]
        SETTLE_PAUSE.with(|pause| {
            if let Some(pause) = pause.borrow().as_ref() {
                pause();
            }
        });
        Ok(self
            .record_result_inner(
                operation_id,
                OperationState::Failed,
                None,
                (
                    Some(SandboxErrorCode::HostEffectNotIssued.into()),
                    None,
                    None,
                ),
                false,
                ResultFence::Intent(generation, attempt),
            )?
            .is_some())
    }

    fn record_result_inner(
        &self,
        operation_id: &str,
        state: OperationState,
        result: Option<serde_json::Value>,
        failure: (
            Option<sandbox_protocol::WireErrorCode>,
            Option<String>,
            Option<sandbox_protocol::ProtocolErrorReason>,
        ),
        reconcile: bool,
        fence: ResultFence,
    ) -> Result<Option<HostReceipt>> {
        self.record_result_ext(operation_id, state, result, failure, reconcile, fence, &[])
    }

    /// [`Self::record_result_inner`] that also adds `ext` keys (only absent
    /// ones, in the same durable write) when it writes the result.
    #[allow(clippy::too_many_arguments)]
    fn record_result_ext(
        &self,
        operation_id: &str,
        state: OperationState,
        result: Option<serde_json::Value>,
        failure: (
            Option<sandbox_protocol::WireErrorCode>,
            Option<String>,
            Option<sandbox_protocol::ProtocolErrorReason>,
        ),
        reconcile: bool,
        fence: ResultFence,
        ext: &[(&str, serde_json::Value)],
    ) -> Result<Option<HostReceipt>> {
        let (error_code, error_message, reason) = failure;
        let reason = reason.filter(|reason| {
            error_code
                .as_ref()
                .is_some_and(|code| reason.fits_wire(code))
        });
        self.maybe_crash(CrashPoint::BeforeResult)?;
        let mut guard = self.state.lock().unwrap_or_else(|err| err.into_inner());
        let Some(existing) = guard.receipts.get(operation_id) else {
            if matches!(fence, ResultFence::Intent(..)) {
                return Ok(None);
            }
            bail!("result without intent receipt {operation_id}");
        };
        match fence {
            ResultFence::None => {}
            ResultFence::Attempt(generation, attempt) => {
                if existing.generation != generation || existing.attempt != attempt {
                    return Ok(None);
                }
            }
            ResultFence::Intent(generation, attempt) => {
                if existing.generation != generation
                    || existing.attempt != attempt
                    || existing.phase != ReceiptPhase::Intent
                    || existing.digest_pruned
                {
                    return Ok(None);
                }
            }
        }
        if existing.digest_pruned {
            bail!("receipt_digest_pruned");
        }
        // The journal mutex is the completion owner. A second producer cannot
        // overwrite positive completion evidence. An UNKNOWN stdin observation
        // remains Effect and may later be resolved by the command worker.
        if existing.is_terminal() {
            return Ok(Some(existing.clone()));
        }
        if existing.state == OperationState::UnknownOutcome
            && state == OperationState::Failed
            && matches!(existing.kind.as_str(), "sandbox.kill" | "sandbox.stop")
        {
            // Preserve uncertainty, but rotate this refused recovery attempt
            // behind older obligations so it cannot monopolize RESUME_CAP.
            let mut deferred = existing.clone();
            deferred.written_at_unix_ms =
                now_ms().max(deferred.written_at_unix_ms.saturating_add(1));
            persist_receipt(&self.io, &self.receipts_dir, &deferred)?;
            guard.receipts.insert(operation_id.into(), deferred.clone());
            return Ok(Some(deferred));
        }
        let mut existing = existing.clone();
        existing.phase = if state == OperationState::UnknownOutcome {
            ReceiptPhase::Effect
        } else {
            ReceiptPhase::Result
        };
        existing.state = state;
        let previous = existing.result.clone();
        let result = merge_permanent_evidence(previous.as_ref(), result)?;
        existing.result = truncate_result(result);
        if existing
            .content_deadline_unix_ms
            .is_some_and(|deadline| deadline <= now_ms())
            && existing.result.is_none()
        {
            existing.result = previous;
        }
        if existing
            .content_deadline_unix_ms
            .is_some_and(|deadline| deadline <= now_ms())
            && let Some(result) = &mut existing.result
        {
            expire_content(result)?;
        }
        // Reconciliation without positive completion evidence cannot overwrite
        // an observed diagnostic. Arbitrate under the same journal mutex as the
        // completion owner, so a stale recovery snapshot cannot win a race.
        if !reconcile || state != OperationState::UnknownOutcome || existing.error_code.is_none() {
            existing.error_code = error_code;
            existing.capacity_reason =
                reason.and_then(sandbox_protocol::ProtocolErrorReason::capacity);
            existing.egress_refusal =
                reason.and_then(sandbox_protocol::ProtocolErrorReason::egress);
            existing.readiness_reason =
                reason.and_then(sandbox_protocol::ProtocolErrorReason::readiness);
            existing.error_message = error_message.map(|value| bounded_error(&value));
        }
        existing.written_at_unix_ms = now_ms();
        for (key, value) in ext {
            if !existing.ext.contains_key(*key) {
                existing.ext.insert((*key).to_owned(), value.clone());
            }
        }
        if !ext.is_empty() && !valid_ext(&existing.ext) {
            bail!("invalid journal ext");
        }
        // Escaping in metadata/error text also counts toward the total envelope.
        // Preserve the known outcome with a truthful marker if content no longer fits.
        if serde_json::to_vec(&existing)?.len() + 100 > RECEIPT_LIMITS.receipt_bytes {
            existing.result = existing.result.map(|value| {
                retain_result_evidence(
                    &value,
                    serde_json::json!({"truncated": true, "retainedBytes": 0}),
                )
            });
        }
        persist_receipt(&self.io, &self.receipts_dir, &existing)?;
        let stored = existing.clone();
        guard.receipts.insert(operation_id.into(), existing);
        leases::retire_cleanup(&self.io, &self.leases_dir, &mut guard, &stored)?;
        prune_completed(&self.io, &self.receipts_dir, &mut guard.receipts)?;
        drop(guard);
        if confirmed_release(&stored.kind, stored.state, stored.result.as_ref()) {
            self.release_retained(
                &stored.sandbox_id,
                stored.generation,
                stored.kind == "sandbox.kill",
            )?;
        }
        self.maybe_crash(CrashPoint::AfterResult)?;
        Ok(Some(stored))
    }

    pub fn record_cancel(&self, operation_id: &str, generation: u64, attempt: u64) -> Result<()> {
        self.record_cancel_for(operation_id, generation, attempt, None)
    }

    /// The first durable cancel wins: a later request (another reason, or
    /// none) never rewrites an already requested cancel or its reason.
    pub fn record_cancel_for(
        &self,
        operation_id: &str,
        generation: u64,
        attempt: u64,
        reason: Option<CancelReason>,
    ) -> Result<()> {
        self.maybe_crash(CrashPoint::BeforeCancel)?;
        let mut guard = self.state.lock().unwrap_or_else(|err| err.into_inner());
        let Some(existing) = guard.receipts.get(operation_id) else {
            return Ok(());
        };
        if existing.generation != generation
            || existing.attempt != attempt
            || !CANCELLABLE_DISPATCH_KINDS.contains(&existing.kind.as_str())
            || existing.cancel_requested
            || existing.is_terminal()
        {
            return Ok(());
        }
        let mut stored = existing.clone();
        stored.cancel_requested = true;
        if let Some(reason) = reason {
            stored.ext.insert(
                CancelReason::EXT_KEY.into(),
                serde_json::Value::from(reason.as_str()),
            );
        }
        persist_receipt(&self.io, &self.receipts_dir, &stored)?;
        guard.receipts.insert(operation_id.into(), stored);
        drop(guard);
        self.maybe_crash(CrashPoint::AfterCancel)?;
        Ok(())
    }

    /// Intact receipts retire only on authenticated exact-binding confirmation.
    /// Serialized with every writer; late producers cannot recreate missing intent.
    pub fn confirm(
        &self,
        binding: &TransportBindingV11,
        confirmed: &ReceiptConfirmation,
    ) -> Result<bool> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let Some(receipt) = state.receipts.get(&confirmed.operation_id) else {
            return Ok(false);
        };
        if !self.confirmation_binds(receipt, binding, confirmed) {
            return Ok(false);
        }
        // An UNKNOWN command recorded as such by the server retires
        // only on per-command proof (`retire.rs`), never by this confirmation,
        // and only when this session negotiated `commandRetire`.
        if confirmed.retire_command {
            Self::queue_retirement_locked(&mut state, confirmed);
            return Ok(false);
        }
        let receipt = &state.receipts[&confirmed.operation_id];
        // An authenticated settlement is exact-binding confirmation PLUS a
        // later cleanup generation. An ordinary ACK/confirmation never retires
        // unknown work. Persist its watermark even if cleanup inventory arrives
        // later, or its local receipt has already been confirmed/deleted.
        let settled = confirmed.cleanup_generation;
        if settled.is_some_and(|generation| generation <= receipt.generation)
            || (!receipt.is_terminal() && settled.is_none())
        {
            return Ok(false);
        }
        let released = confirmed_release(&receipt.kind, receipt.state, receipt.result.as_ref());
        let cleanup_generation = settled.or_else(|| released.then_some(receipt.generation));
        if let Some(generation) = cleanup_generation {
            let watermark = CleanupWatermark {
                version: JOURNAL_VERSION,
                binding: binding.clone(),
                sandbox_owner_id: receipt.sandbox_owner_id.clone(),
                sandbox_id: receipt.sandbox_id.clone(),
                generation,
                instance_absent: (receipt.kind == "sandbox.kill" && released)
                    || state.leases.get(&receipt.sandbox_id).is_some_and(|l| {
                        l.instance_absent && l.expiry_complete && l.generation <= generation
                    }),
                // A rewrite of the same generation keeps its `ext`; a new
                // generation starts empty.
                ext: state
                    .cleanups
                    .get(&receipt.sandbox_id)
                    .filter(|old| old.generation == generation)
                    .map(|old| old.ext.clone())
                    .unwrap_or_default(),
            };
            if state.cleanups.get(&watermark.sandbox_id).is_none_or(|old| {
                old.generation < generation
                    || (old.generation == generation
                        && !old.instance_absent
                        && watermark.instance_absent)
            }) {
                persist_cleanup(&self.io, &self.cleanups_dir, &watermark)?;
                state
                    .cleanups
                    .insert(watermark.sandbox_id.clone(), watermark);
            }
            self.maybe_crash(CrashPoint::AfterCleanupWatermark)?;
        }
        self.delete_confirmed_receipt_locked(&mut state, &confirmed.operation_id)?;
        Ok(true)
    }

    /// The exact-binding checks every confirmation shares: the receipt is
    /// intact, keyed by the current journal key, and names this binding,
    /// owner, sandbox, attempt, request MAC, idempotency key and kind.
    fn confirmation_binds(
        &self,
        receipt: &HostReceipt,
        binding: &TransportBindingV11,
        confirmed: &ReceiptConfirmation,
    ) -> bool {
        if receipt.digest_pruned {
            return false;
        }
        if receipt.digest_scheme.as_deref() == Some("hmac-sha256-v1") {
            let key = self.key.lock().unwrap_or_else(|e| e.into_inner());
            if key
                .as_ref()
                .is_none_or(|key| receipt.digest_key_id.as_ref() != Some(&key.key_id))
            {
                return false;
            }
        }
        receipt.binds(binding)
            && receipt.sandbox_owner_id == confirmed.sandbox_owner_id
            && receipt.sandbox_id == confirmed.sandbox_id
            && receipt.generation == confirmed.generation
            && receipt.attempt == confirmed.attempt
            && receipt.server_request_hash() == Some(confirmed.body_hash.as_str())
            && receipt.idempotency_key == confirmed.idempotency_key
            && receipt.kind == confirmed.kind
    }

    /// Durable receipt deletion after a confirmation (or a §10 retirement)
    /// was accepted under the journal mutex.
    fn delete_confirmed_receipt_locked(
        &self,
        state: &mut JournalState,
        operation_id: &str,
    ) -> Result<()> {
        self.maybe_crash(CrashPoint::BeforeReceiptDelete)?;
        let retry = !state.confirmed_receipts.insert(operation_id.to_owned());
        remove_durably(
            &self.io,
            &self.receipts_dir.join(receipt_file_name(operation_id)?),
            retry,
        )?;
        self.maybe_crash(CrashPoint::AfterReceiptDelete)?;
        sync_dir(&self.io, &self.receipts_dir)?;
        self.maybe_crash(CrashPoint::AfterReceiptDirectorySync)?;
        state.receipts.remove(operation_id);
        state.confirmed_receipts.remove(operation_id);
        self.gc_configs_locked(state)?;
        // The watermark is durable; settled lease records it covers are
        // reclaimed so lifetime churn cannot exhaust admission.
        leases::compact_confirmed(&self.io, &self.leases_dir, &self.cleanups_dir, state)?;
        Ok(())
    }

    /// The authenticated peer received this exact identity-only pruned report.
    /// This releases local journal space, never server capacity or outcome holds.
    pub fn acknowledge_pruned(
        &self,
        binding: &TransportBindingV11,
        epoch: u64,
        ack: &sandbox_protocol::PrunedReceiptAck,
    ) -> Result<bool> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let Some(receipt) = state.receipts.get(&ack.operation_id) else {
            return Ok(false);
        };
        if !ack.is_valid()
            || ack.connection_epoch != epoch
            || !receipt.digest_pruned
            || !receipt.binds(binding)
            || receipt.sandbox_owner_id != ack.sandbox_owner_id
            || receipt.sandbox_id != ack.sandbox_id
            || receipt.generation != ack.generation
            || receipt.attempt != ack.attempt
            || receipt.idempotency_key != ack.idempotency_key
            || receipt.kind != ack.kind
        {
            return Ok(false);
        }
        let path = self
            .receipts_dir
            .join(receipt_file_name(&ack.operation_id)?);
        let removed = (|| -> Result<()> {
            remove_durably(&self.io, &path, true)?;
            self.maybe_crash(CrashPoint::BeforePrunedReceiptDirectorySync)?;
            sync_dir(&self.io, &self.receipts_dir)?;
            Ok(())
        })();
        if removed.is_err() {
            // Keep the index entry until deletion is durable. A retry after an
            // unlink followed by a failed fsync must accept an absent file.
            // Omit paths, identities and the source error from session logs.
            tracing::warn!("pruned receipt journal IO failed; receipt retained");
            return Ok(false);
        }
        state.receipts.remove(&ack.operation_id);
        self.gc_configs_locked(&mut state)?;
        leases::compact_confirmed(&self.io, &self.leases_dir, &self.cleanups_dir, &mut state)?;
        Ok(true)
    }

    pub fn matching(&self, binding: &TransportBindingV11) -> Result<Vec<HostReceipt>> {
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        if (!state.storage.binding.host_owner_id.is_empty() && state.storage.binding != *binding)
            || state.configs.values().any(|config| !config.binds(binding))
            || state.receipts.values().any(|r| !r.binds(binding))
            || state.cleanups.values().any(|c| c.binding != *binding)
            || state.leases.values().any(|c| c.binding != *binding)
        {
            bail!("journal owner binding differs from authenticated hello");
        }
        // Reconnect must not replay content that expired while the host was
        // offline, even if the periodic maintenance tick has not run yet.
        prune_completed(&self.io, &self.receipts_dir, &mut state.receipts)?;
        Ok(state.receipts.values().cloned().collect())
    }

    pub(crate) fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// Atomic per-id journal snapshot, taken on the ordered reader BEFORE
    /// scheduling runtime IO. History lookup is O(1), independent of its size.
    /// Receipts are bounded by journal capacity; no history is serialized.
    pub(super) fn never_issued(&self, ids: &[String]) -> Vec<bool> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        ids.iter()
            .map(|id| {
                !state.storage.roots.contains_key(id)
                    && !state.leases.contains_key(id)
                    && !state.cleanups.contains_key(id)
                    && state.lease_workers.get(id).copied().unwrap_or(0) == 0
                    && !state.receipts.values().any(|r| {
                        r.sandbox_id == *id
                            && matches!(r.kind.as_str(), "sandbox.create" | "sandbox.reconnect")
                    })
            })
            .collect()
    }

    pub fn cleanup_generations(
        &self,
        binding: &TransportBindingV11,
    ) -> Result<HashMap<String, u64>> {
        let state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        if state.cleanups.values().any(|c| c.binding != *binding) {
            bail!("cleanup watermark owner binding differs from authenticated hello");
        }
        Ok(state
            .cleanups
            .iter()
            .map(|(id, c)| (id.clone(), c.generation))
            .collect())
    }

    fn maybe_crash(&self, point: CrashPoint) -> Result<()> {
        let crash = *self.crash.lock().unwrap_or_else(|err| err.into_inner());
        if crash == Some(point) {
            bail!("injected journal crash at {point:?}");
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum Decision {
    Fresh,
    Capacity,
    /// The sandbox's own retained `command.run` receipts are at their cap
    /// (`host_capacity` with reason `sandbox_receipts`).
    SandboxReceipts,
    Replay(HostReceipt),
    Unknown(HostReceipt),
    Conflict,
}

impl HostReceipt {
    /// The typed wire `reason` this receipt replays (capacity or egress).
    pub fn error_reason(&self) -> Option<sandbox_protocol::ProtocolErrorReason> {
        self.capacity_reason
            .map(sandbox_protocol::ProtocolErrorReason::from)
            .or(self
                .egress_refusal
                .map(sandbox_protocol::ProtocolErrorReason::from))
            .or(self
                .readiness_reason
                .map(sandbox_protocol::ProtocolErrorReason::from))
    }

    pub fn workload_binding(&self) -> Option<sandbox_protocol::WorkloadBindingV11> {
        let binding = sandbox_protocol::WorkloadBindingV11 {
            server: self.server.clone(),
            host_owner_id: self.host_owner_id.clone(),
            host_id: self.host_id.clone(),
            sandbox_owner_id: self.sandbox_owner_id.clone(),
            sandbox_id: self.sandbox_id.clone(),
            generation: u32::try_from(self.generation).ok()?,
        };
        binding.is_valid().then_some(binding)
    }
    #[cfg(test)]
    fn into_digest_pruned(mut self) -> Self {
        self.body_hash = None;
        self.request_hash = None;
        self.server_request_hash = None;
        self.digest_scheme = Some("digest-pruned-v1".into());
        self.digest_key_id = None;
        self.private_config = None;
        if let Some(lease) = &mut self.lease {
            lease.private_config = None;
        }
        self.digest_pruned = true;
        self.result = self.result.as_ref().map(|result| {
            retain_result_evidence(result, serde_json::json!({"outputExpired":true}))
        });
        self
    }

    pub fn server_request_hash(&self) -> Option<&str> {
        if self.digest_pruned {
            return None;
        }
        self.server_request_hash
            .as_deref()
            .or(self.request_hash.as_deref())
    }

    pub fn binds(&self, binding: &TransportBindingV11) -> bool {
        self.server == binding.server
            && self.host_owner_id == binding.host_owner_id
            && self.host_id == binding.host_id
    }

    fn same_binding(&self, other: &Self) -> bool {
        self.server == other.server
            && self.host_owner_id == other.host_owner_id
            && self.sandbox_owner_id == other.sandbox_owner_id
            && self.host_id == other.host_id
    }

    pub fn is_terminal(&self) -> bool {
        self.phase == ReceiptPhase::Result
            && matches!(
                self.state,
                OperationState::Succeeded | OperationState::Failed | OperationState::Cancelled
            )
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
fn fixture_dispatch_bytes(dispatch: &OperationDispatch) -> String {
    serde_json::to_string(dispatch).expect("serialize fixture dispatch")
}

#[cfg(test)]
pub fn intent_from_dispatch(
    journal: &HostJournal,
    binding: &TransportBindingV11,
    dispatch: &OperationDispatch,
) -> HostReceipt {
    super::test_support::install_fixture_key(journal, binding);
    let dispatch = super::test_support::current_fixture_dispatch(dispatch);
    journal
        .prepare_dispatch(binding, &dispatch)
        .expect("current fixture intent")
}

#[cfg(test)]
pub fn unrecorded_intent_from_dispatch(
    binding: &TransportBindingV11,
    dispatch: &OperationDispatch,
) -> HostReceipt {
    build_intent(
        binding,
        dispatch,
        sha256_hex(fixture_dispatch_bytes(dispatch).as_bytes()),
        dispatch.body_hash.clone().unwrap_or_else(|| "a".repeat(64)),
        Some("sha256-env-free-v1".into()),
        None,
    )
}

fn build_intent(
    binding: &TransportBindingV11,
    dispatch: &OperationDispatch,
    body_hash: String,
    request_hash: String,
    digest_scheme: Option<String>,
    digest_key_id: Option<String>,
) -> HostReceipt {
    HostReceipt {
        capacity_reason: None,
        egress_refusal: None,
        readiness_reason: None,
        allocation: dispatch.allocation.clone(),
        // Launch ingress has already validated the pair. Nonlaunch receipts
        // carry the explicit nonlaunch default size.
        vm_size: dispatch.allocation.as_ref().map_or_else(
            || sandbox_protocol::VmSize {
                cpu_count: dispatch.cpu_count.unwrap_or(1),
                memory_mi_b: dispatch.memory_mi_b.unwrap_or(1024),
            },
            |a| sandbox_protocol::VmSize {
                cpu_count: a.cpu_count,
                memory_mi_b: a.memory_mi_b,
            },
        ),
        lease: None,
        version: JOURNAL_VERSION,
        server: binding.server.clone(),
        host_owner_id: binding.host_owner_id.clone(),
        sandbox_owner_id: dispatch.sandbox_owner_id.clone(),
        host_id: binding.host_id.clone(),
        sandbox_id: dispatch.sandbox_id.clone(),
        generation: dispatch.generation,
        operation_id: dispatch.operation_id.clone(),
        attempt: dispatch.attempt,
        kind: dispatch.kind.clone(),
        template_fingerprint: dispatch
            .incus_fingerprint
            .clone()
            .or_else(|| dispatch.template_digest.clone()),
        body_hash: Some(body_hash),
        digest_pruned: false,
        private_config: dispatch.private_config.clone(),
        digest_scheme,
        digest_key_id,
        request_hash: Some(request_hash),
        server_request_hash: None,
        idempotency_key: dispatch.idempotency_key.clone(),
        phase: ReceiptPhase::Intent,
        state: OperationState::Accepted,
        cancel_requested: false,
        result: None,
        error_code: None,
        error_message: None,
        written_at_unix_ms: now_ms(),
        file_put: file_put_intent(dispatch),
        // Only a restore journals a launch mode (`new_root`); every other
        // receipt stays byte-identical.
        launch_mode: dispatch
            .restore
            .as_ref()
            .map(|_| sandbox_protocol::LaunchMode::NewRoot),
        content_deadline_unix_ms: (dispatch.result_version == Some(1)
            && matches!(
                dispatch.kind.as_str(),
                "file.stat" | "file.list" | "file.move" | "process.list"
            ))
        .then_some(0),
        ext: JournalExt::new(),
    }
}

fn file_put_intent(dispatch: &OperationDispatch) -> Option<FilePutIntent> {
    if dispatch.kind != "file.put" {
        return None;
    }
    let guest = guest_from_dispatch(dispatch);
    Some(FilePutIntent {
        path: dispatch.path.clone()?,
        size: dispatch.file_size?,
        sha256: dispatch.file_sha256.clone()?,
        incus_name: dispatch.incus_name.clone(),
        guest_uid: guest.guest_uid,
        guest_gid: guest.guest_gid,
        guest_home: guest.guest_home,
        guest_shell: guest.guest_shell,
        ext: JournalExt::new(),
    })
}

#[cfg(unix)]
fn load_receipts(dir: &Path) -> Result<HashMap<String, HostReceipt>> {
    let mut receipts = HashMap::new();
    for entry in fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(".tmp"))
        {
            private_file(&path)?;
            fs::remove_file(&path)?;
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            bail!("unexpected journal entry");
        }
        private_file(&path)?;
        if fs::metadata(&path)?.len() > RECEIPT_LIMITS.receipt_bytes as u64 {
            bail!("oversized journal receipt");
        }
        let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        let version: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("corrupt journal receipt"))?;
        if version["receipt"]["version"] != JOURNAL_VERSION {
            bail!(
                "unsupported journal version {}; retire old allocations using the original daemon and preserve its journal",
                version["receipt"]["version"]
            );
        }
        let envelope: JournalEnvelope = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("corrupt journal receipt"))?;
        let receipt: HostReceipt = checked_record(&envelope.receipt, &envelope.checksum)
            .map_err(|_| anyhow::anyhow!("corrupt journal receipt"))?
            .context("corrupt journal receipt checksum")?;
        validate_receipt(&receipt)?;
        if receipt.phase == ReceiptPhase::Result && !receipt.is_terminal() {
            bail!("invalid receipt outcome");
        }
        if receipt.version != JOURNAL_VERSION {
            bail!(
                "unsupported journal version {} in {}; retire old allocations using the original daemon and preserve its journal",
                receipt.version,
                path.display()
            );
        }
        if path.file_name().and_then(|v| v.to_str())
            != Some(&receipt_file_name(&receipt.operation_id)?)
            || receipt.server.is_empty()
            || receipt.host_owner_id.is_empty()
            || receipt.host_id.is_empty()
            || receipt.sandbox_id.is_empty()
            || receipt.result.as_ref().is_some_and(|v| {
                !v.is_object() || v.to_string().len() > RECEIPT_LIMITS.result_bytes
            })
            || receipt
                .error_message
                .as_ref()
                .is_some_and(|v| v.len() > RECEIPT_LIMITS.error_bytes)
            || receipt.generation == 0
            || receipt.attempt == 0
            || receipts.len() >= MAX_RECEIPTS + TEARDOWN_HEADROOM
        {
            bail!("invalid journal receipt");
        }
        receipts.insert(receipt.operation_id.clone(), receipt);
    }
    Ok(receipts)
}

/// WP2: the journal-wide IO latch. Every durable journal write (receipts,
/// leases, cleanup watermarks, storage, private configs, markers, and every
/// delete with its directory fsync) runs through [`IoLatch::write`]; any
/// failure latches it for the life of the process. A latched journal admits
/// no new lifecycle work ([`HostJournal::work_refusal`]), the expiry service closes
/// admission, the reconnect loop revokes carried work instead of detaching
/// it, and the host reports itself unschedulable. Only a restart, which
/// re-reads the journal from disk, clears it.
#[derive(Debug, Default)]
pub(crate) struct IoLatch {
    failed: std::sync::atomic::AtomicBool,
    /// Test hook: fail every later write, as a full or broken disk would.
    #[cfg(test)]
    inject: std::sync::atomic::AtomicBool,
}

impl IoLatch {
    /// Runs one durable write; any error latches.
    pub(super) fn write<T>(&self, write: impl FnOnce() -> Result<T>) -> Result<T> {
        #[cfg(test)]
        if self.inject.load(std::sync::atomic::Ordering::SeqCst) {
            self.trip();
            bail!("injected journal write failure");
        }
        write().inspect_err(|_| self.trip())
    }

    pub(super) fn trip(&self) {
        if !self.failed.swap(true, std::sync::atomic::Ordering::SeqCst) {
            tracing::error!(
                "host journal write failed; admission closed and carried work revoked until restart"
            );
        }
    }

    pub(crate) fn failed(&self) -> bool {
        self.failed.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Test hook: every later journal write fails (and latches).
    #[cfg(test)]
    pub(crate) fn fail_writes(&self) {
        self.inject.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

fn persist_receipt(io: &IoLatch, dir: &Path, receipt: &HostReceipt) -> Result<()> {
    validate_receipt(receipt)?;
    let name = receipt_file_name(&receipt.operation_id)?;
    let final_path = dir.join(&name);
    let bytes = receipt_envelope_bytes(receipt)?;
    if bytes.len() > RECEIPT_LIMITS.receipt_bytes {
        bail!("oversized journal receipt");
    }
    persist_bytes(io, dir, &final_path, &bytes)
}

pub(super) fn persist_bytes(
    io: &IoLatch,
    dir: &Path,
    final_path: &Path,
    bytes: &[u8],
) -> Result<()> {
    io.write(|| {
        let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
        tmp.write_all(bytes)?;
        tmp.as_file().sync_all()?;
        tmp.persist(final_path)?;
        File::open(dir)?.sync_all()?;
        Ok(())
    })
}

/// Unlinks `path` (already absent is fine when `missing_ok`); the caller
/// fsyncs its directory with [`sync_dir`].
pub(super) fn remove_durably(io: &IoLatch, path: &Path, missing_ok: bool) -> Result<()> {
    io.write(|| match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if missing_ok && error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    })
}

pub(super) fn sync_dir(io: &IoLatch, dir: &Path) -> Result<()> {
    io.write(|| Ok(File::open(dir)?.sync_all()?))
}

fn persist_cleanup(io: &IoLatch, dir: &Path, watermark: &CleanupWatermark) -> Result<()> {
    let (watermark_raw, checksum) = checksummed_raw(watermark)?;
    let bytes = serde_json::to_vec(&CleanupEnvelope {
        watermark: watermark_raw,
        checksum,
    })?;
    persist_bytes(
        io,
        dir,
        &dir.join(cleanup_file_name(&watermark.sandbox_id)),
        &bytes,
    )
}

fn cleanup_file_name(sandbox_id: &str) -> String {
    format!("{}.json", sha256_hex(sandbox_id.as_bytes()))
}

#[cfg(unix)]
fn load_cleanups(dir: &Path) -> Result<HashMap<String, CleanupWatermark>> {
    let mut cleanups = HashMap::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        private_file(&path)?;
        if path
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.starts_with(".tmp"))
        {
            fs::remove_file(path)?;
            continue;
        }
        if fs::metadata(&path)?.len() > RECEIPT_LIMITS.receipt_bytes as u64 {
            bail!("oversized cleanup watermark");
        }
        let envelope: CleanupEnvelope = serde_json::from_slice(&fs::read(&path)?)?;
        let Some(c) = checked_record::<CleanupWatermark>(&envelope.watermark, &envelope.checksum)?
        else {
            bail!("invalid cleanup watermark");
        };
        if !valid_ext(&c.ext)
            || c.version != JOURNAL_VERSION
            || c.generation == 0
            || [&c.sandbox_id, &c.binding.host_id, &c.binding.host_owner_id]
                .iter()
                .any(|s| s.is_empty() || s.len() > RECEIPT_LIMITS.identity_bytes)
            || c.binding.server.is_empty()
            || c.binding.server.len() > RECEIPT_LIMITS.server_bytes
            || path.file_name().and_then(|s| s.to_str()) != Some(&cleanup_file_name(&c.sandbox_id))
        {
            bail!("invalid cleanup watermark");
        }
        cleanups.insert(c.sandbox_id.clone(), c);
    }
    Ok(cleanups)
}

// Scalar command metadata (`exitCode`, `pid`, `outputBytes`) is completion
// evidence, not content: it must survive retention unchanged so a replayed
// receipt can still resolve the server's pending operation and its output
// watermark. A result holding only evidence keys is never pruned at all.
fn content_dispatch(receipt: &HostReceipt) -> bool {
    receipt.content_deadline_unix_ms.is_some()
}
const RESULT_EVIDENCE: &[&str] = &[
    "state",
    "endState",
    "exitCode",
    "errorCode",
    "lease",
    "pid",
    "outputBytes",
    "process",
    "birth",
    "startedAt",
];

/// Output is expendable; completion evidence is not. Shared by age/count and
/// byte-size retention, including the final envelope-size fallback.
fn retain_result_evidence(
    value: &serde_json::Value,
    mut marker: serde_json::Value,
) -> serde_json::Value {
    if value.get("version").and_then(serde_json::Value::as_u64) == Some(1) {
        return value.clone();
    }
    if let Some(fields) = marker.as_object_mut() {
        for key in RESULT_EVIDENCE {
            if let Some(evidence) = value.get(key) {
                fields.insert((*key).into(), evidence.clone());
            }
        }
    }
    marker
}

fn result_limits() -> Result<sandbox_protocol::results::ResultLimits> {
    Ok(serde_json::from_str(
        sandbox_protocol::results::RESULT_LIMITS_JSON,
    )?)
}

fn expire_content(result: &mut serde_json::Value) -> Result<()> {
    let fields = result
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("invalid typed result"))?;
    fields.insert("payload".into(), serde_json::Value::Null);
    fields.insert("continuation".into(), serde_json::Value::Null);
    fields.insert("resultExpired".into(), serde_json::json!(true));
    Ok(())
}

fn prune_completed(
    io: &IoLatch,
    dir: &Path,
    receipts: &mut HashMap<String, HostReceipt>,
) -> Result<()> {
    // Typed content cannot be count-pruned to admit another effect. Deadline
    // markers are persisted before releasing their slots, including Intent/Effect.
    let expired: Vec<String> = receipts
        .iter()
        .filter(|(_, r)| {
            r.content_deadline_unix_ms.is_some_and(|d| d <= now_ms())
                && r.result
                    .as_ref()
                    .is_none_or(|v| v.get("resultExpired") != Some(&serde_json::json!(true)))
        })
        .map(|(key, _)| key.clone())
        .collect();
    for key in expired {
        let Some(receipt) = receipts.get_mut(&key) else {
            continue;
        };
        let mut result = receipt.result.clone().unwrap_or_else(|| {
            serde_json::json!({
                "version":1,"observedAt":sandbox_protocol::results::format_timestamp_ms(now_ms()),
                "payload":null,"continuation":null,"birth":null,"failure":null
            })
        });
        expire_content(&mut result)?;
        replace_result_durably(io, dir, receipt, result)?;
    }
    let mut content: Vec<(u64, String)> = receipts
        .iter()
        .filter(|(_, r)| {
            r.content_deadline_unix_ms.is_none()
                && r.result.as_ref().is_none_or(|v| v.get("version").is_none())
        })
        .filter(|(_, r)| {
            r.result.as_ref().is_some_and(|v| {
                v.get("outputExpired").is_none()
                    && v.as_object()
                        .is_some_and(|v| v.keys().any(|k| !RESULT_EVIDENCE.contains(&k.as_str())))
            })
        })
        .map(|(key, r)| (r.written_at_unix_ms, key.clone()))
        .collect();
    content.sort_by_key(|(written_at, _)| *written_at);
    let excess = content.len().saturating_sub(MAX_COMPLETED_RECEIPTS);
    // Parsed at most once, and only when a receipt past the count cap needs it.
    let mut retention_ms = None;
    for (index, (written_at, key)) in content.into_iter().enumerate() {
        let prune = index < excess || {
            let retention = match retention_ms {
                Some(retention) => retention,
                None => *retention_ms.insert(result_limits()?.mutation_content_retention_ms),
            };
            now_ms().saturating_sub(written_at) > retention
        };
        if !prune {
            continue;
        }
        let Some(receipt) = receipts.get_mut(&key) else {
            continue;
        };
        let Some(result) = receipt
            .result
            .as_ref()
            .map(|value| retain_result_evidence(value, serde_json::json!({"outputExpired": true})))
        else {
            continue;
        };
        replace_result_durably(io, dir, receipt, result)?;
    }
    Ok(())
}

/// Persists `receipt` with `result`; on a failed write the in-memory receipt
/// keeps its previous result, exactly as if it had never been touched.
fn replace_result_durably(
    io: &IoLatch,
    dir: &Path,
    receipt: &mut HostReceipt,
    result: serde_json::Value,
) -> Result<()> {
    let previous = receipt.result.replace(result);
    if let Err(error) = persist_receipt(io, dir, receipt) {
        receipt.result = previous;
        return Err(error);
    }
    Ok(())
}

#[cfg(unix)]
fn create_durable_dir(path: &Path) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    create_durable_dir(parent)?;
    // E-16: every component created here is owner-only (0700) whatever the
    // process umask; existing ancestors keep their mode.
    let mut builder = std::fs::DirBuilder::new();
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(err) => return Err(err.into()),
    }
    File::open(parent)?.sync_all()?;
    Ok(())
}
#[cfg(unix)]
fn private_dir(path: &Path) -> Result<()> {
    create_durable_dir(path)?;
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        bail!("journal directory is a symlink");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
#[cfg(unix)]
fn private_file(path: &Path) -> Result<()> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        bail!("journal entry is not a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
#[cfg(all(unix, not(test)))]
fn lock_exclusive(lock: &File) -> Result<()> {
    lock.try_lock()
        .map_err(|err| anyhow::anyhow!("exclusive host state lock: {err}"))
}
/// A child forked on another test thread shares this process's open file
/// descriptions until it execs, so a journal a test just dropped can still be
/// flock-held for a moment by that child and an immediate reopen would see
/// `WouldBlock`. Tests retry briefly; a lock that is really held still fails.
#[cfg(all(unix, test))]
fn lock_exclusive(lock: &File) -> Result<()> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        match lock.try_lock() {
            Err(std::fs::TryLockError::WouldBlock) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            result => {
                return result.map_err(|err| anyhow::anyhow!("exclusive host state lock: {err}"));
            }
        }
    }
}

pub fn validate_receipt(receipt: &HostReceipt) -> Result<()> {
    anyhow::ensure!(
        valid_ext(&receipt.ext)
            && receipt
                .file_put
                .as_ref()
                .is_none_or(|put| valid_ext(&put.ext)),
        "invalid journal ext"
    );
    anyhow::ensure!(
        receipt.workload_binding().is_some(),
        "invalid workload binding"
    );
    if let Some(lease) = &receipt.lease {
        anyhow::ensure!(
            lease.version == JOURNAL_VERSION
                && lease.binding
                    == receipt
                        .workload_binding()
                        .context("invalid workload binding")?
                        .transport()
                && lease.sandbox_owner_id == receipt.sandbox_owner_id
                && lease.sandbox_id == receipt.sandbox_id,
            "lease workload binding differs"
        );
    }
    anyhow::ensure!(
        receipt.capacity_reason.is_none()
            || receipt
                .error_code
                .as_ref()
                .is_some_and(|code| code.is(SandboxErrorCode::HostCapacity)),
        "invalid capacity reason binding"
    );
    anyhow::ensure!(
        receipt.egress_refusal.is_none()
            || receipt
                .error_code
                .as_ref()
                .is_some_and(|code| code.is(SandboxErrorCode::UnsupportedCapability)),
        "invalid egress refusal binding"
    );
    anyhow::ensure!(
        receipt.readiness_reason.is_none()
            || receipt
                .error_code
                .as_ref()
                .is_some_and(|code| code.is(SandboxErrorCode::GuestUnavailable)),
        "invalid readiness reason binding"
    );
    if let Some(a) = &receipt.allocation {
        let _: sandbox_protocol::capacity_v11::PinnedAllocationV11 =
            serde_json::from_value(serde_json::to_value(a)?)?;
        anyhow::ensure!(
            a.cpu_count == receipt.vm_size.cpu_count
                && a.memory_mi_b == receipt.vm_size.memory_mi_b,
            "receipt size differs from pinned allocation"
        );
        storage::allocation_root(a).validate()?;
    }
    sandbox_protocol::VmSize::new(receipt.vm_size.cpu_count, receipt.vm_size.memory_mi_b)
        .context("invalid receipt VM size")?;
    if let Some(value) = receipt
        .result
        .as_ref()
        .filter(|v| v.get("version").is_some())
    {
        use sandbox_protocol::results::host::{HostOperationResult, kind_from_dispatch};
        let typed: HostOperationResult =
            serde_json::from_value(value.clone()).context("invalid typed receipt")?;
        let Some(kind) = kind_from_dispatch(&receipt.kind) else {
            bail!("invalid typed result kind");
        };
        let generation = u32::try_from(receipt.generation).context("invalid result generation")?;
        if !typed.validate(kind, &receipt.sandbox_id, generation)
            || typed.birth.as_ref().is_some_and(|b| {
                b.operation_id != receipt.operation_id || u64::from(b.attempt) != receipt.attempt
            })
        {
            bail!("invalid typed receipt");
        }
    }

    let digest_metadata_valid = match (
        receipt.digest_scheme.as_deref(),
        receipt.digest_key_id.as_deref(),
    ) {
        (Some("sha256-env-free-v1"), None) => true,
        (Some("hmac-sha256-v1"), Some(id)) => {
            id.len() == 32
                && id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }
        _ => false,
    };
    let digest_fields_valid = if receipt.digest_pruned {
        receipt.digest_scheme.as_deref() == Some("digest-pruned-v1")
            && receipt.digest_key_id.is_none()
            && receipt.body_hash.is_none()
            && receipt.request_hash.is_none()
            && receipt.server_request_hash.is_none()
            && receipt.private_config.is_none()
            && receipt
                .lease
                .as_ref()
                .is_none_or(|lease| lease.private_config.is_none())
    } else {
        digest_metadata_valid
            && receipt
                .server_request_hash
                .as_ref()
                .is_none_or(|hash| canonical_body_hash(hash))
            && (receipt.digest_scheme.as_deref() == Some("hmac-sha256-v1"))
                == receipt.server_request_hash.is_some()
            && receipt.request_hash.as_deref().is_some_and(|hash| {
                valid_receipt_fields(hash, &receipt.idempotency_key, &receipt.kind)
            })
            && receipt
                .body_hash
                .as_deref()
                .is_some_and(canonical_body_hash)
            && receipt.private_config.as_ref().is_none_or(|config| {
                config.is_valid()
                    && receipt.digest_scheme.as_deref() == Some("hmac-sha256-v1")
                    && Some(&config.binding_key_id) == receipt.digest_key_id.as_ref()
            })
    };
    if !digest_fields_valid
        || receipt.idempotency_key.is_empty()
        || receipt.idempotency_key.len() > RECEIPT_LIMITS.idempotency_key_bytes
        || !RECEIPT_LIMITS.kinds.contains(&receipt.kind)
        || [
            &receipt.host_owner_id,
            &receipt.sandbox_owner_id,
            &receipt.host_id,
            &receipt.sandbox_id,
            &receipt.operation_id,
        ]
        .iter()
        .any(|v| v.is_empty() || v.len() > RECEIPT_LIMITS.identity_bytes)
        || receipt.server.is_empty()
        || receipt.server.len() > RECEIPT_LIMITS.server_bytes
        || receipt
            .result
            .as_ref()
            .is_some_and(|v| !v.is_object() || v.to_string().len() > RECEIPT_LIMITS.result_bytes)
        || receipt
            .error_message
            .as_ref()
            .is_some_and(|v| v.len() > RECEIPT_LIMITS.error_bytes)
        || receipt.generation == 0
        || receipt.attempt == 0
        || receipt.file_put.as_ref().is_some_and(|file| {
            receipt.kind != "file.put"
                || file.path.is_empty()
                || file.path.len() > 4096
                || file.size > sandbox_runtime::FILE_MAX_BYTES
                || !canonical_body_hash(&file.sha256)
                || [&file.guest_home, &file.guest_shell]
                    .iter()
                    .any(|v| v.len() > 4096)
        })
        || serde_json::to_vec(receipt)?.len() + 100 > RECEIPT_LIMITS.receipt_bytes
    {
        bail!("invalid or oversized receipt binding");
    }
    receipt_file_name(&receipt.operation_id)?;
    Ok(())
}
fn bounded_error(value: &str) -> String {
    let mut end = value.len().min(RECEIPT_LIMITS.error_bytes);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].into()
}
fn receipt_file_name(operation_id: &str) -> Result<String> {
    let valid = !operation_id.is_empty()
        && operation_id.len() <= 128
        && operation_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !valid {
        bail!("refusing journal name for operation id `{operation_id}`");
    }
    Ok(format!("{operation_id}.json"))
}

/// Recovery can settle status but cannot erase or rebind proven command birth.
fn merge_permanent_evidence(
    previous: Option<&serde_json::Value>,
    result: Option<serde_json::Value>,
) -> Result<Option<serde_json::Value>> {
    let Some(old) =
        previous.filter(|v| v.get("version").and_then(serde_json::Value::as_u64) == Some(1))
    else {
        return Ok(result);
    };
    let Some(mut new) = result else {
        return Ok(Some(old.clone()));
    };
    let new_fields = new
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("invalid typed result"))?;
    if let Some(birth) = old.get("birth").filter(|v| !v.is_null()) {
        if let Some(next) = new_fields.get("birth").filter(|v| !v.is_null()) {
            for key in [
                "operationId",
                "sandboxId",
                "generation",
                "attempt",
                "processId",
                "pid",
                "bootId",
                "startTicks",
                "startedAt",
            ] {
                if birth.get(key) != next.get(key) {
                    bail!("conflicting command birth");
                }
            }
        }
        if let Some(payload) = new_fields.get("payload").filter(|v| !v.is_null()) {
            for key in ["sandboxId", "generation", "attempt", "processId", "pid"] {
                if birth.get(key) != payload.get("process").and_then(|v| v.get(key)) {
                    bail!("conflicting command payload");
                }
            }
            if birth.get("startedAt") != payload.get("startedAt") {
                bail!("conflicting command payload");
            }
        }
        if new_fields
            .get("birth")
            .is_none_or(serde_json::Value::is_null)
        {
            new_fields.insert("birth".into(), birth.clone());
        }
    }
    if old
        .get("payload")
        .and_then(|v| v.get("type"))
        .and_then(serde_json::Value::as_str)
        == Some("command")
        && new_fields
            .get("payload")
            .is_none_or(serde_json::Value::is_null)
        && let Some(payload) = old.get("payload")
    {
        new_fields.insert("payload".into(), payload.clone());
    }
    Ok(Some(new))
}

fn truncate_result(result: Option<serde_json::Value>) -> Option<serde_json::Value> {
    let value = result?;
    if value.get("version").is_some() {
        return Some(value);
    }
    let encoded = serde_json::to_vec(&value).unwrap_or_default();
    if encoded.len() <= RECEIPT_LIMITS.result_bytes {
        return Some(value);
    }
    Some(retain_result_evidence(
        &value,
        serde_json::json!({
            "truncated": true,
            "retainedBytes": 0,
        }),
    ))
}

/// The compare-and-set a result write applies under the journal lock.
#[derive(Debug, Clone, Copy)]
enum ResultFence {
    /// Any attempt of the operation (reconciliation, direct refusals).
    None,
    /// Only while the receipt is this exact `(generation, attempt)`.
    Attempt(u64, u64),
    /// Only while the receipt is this exact `(generation, attempt)` in
    /// Intent (WP3 carry settlement).
    Intent(u64, u64),
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(all(test, unix))]
mod tolerance_tests;

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use serde_json::json;

    fn binding() -> TransportBindingV11 {
        TransportBindingV11 {
            server: "wss://api.example".into(),
            host_owner_id: "owner-1".into(),
            host_id: "host-1".into(),
        }
    }

    pub(super) fn receipt(id: &str, attempt: u64) -> HostReceipt {
        HostReceipt {
            launch_mode: None,
            sandbox_owner_id: "owner".into(),
            capacity_reason: None,
            egress_refusal: None,
            readiness_reason: None,
            allocation: None,
            vm_size: default_vm_size(),
            lease: None,
            version: JOURNAL_VERSION,
            server: "wss://api.example".into(),
            host_owner_id: "owner-1".into(),
            host_id: "host-1".into(),
            sandbox_id: "sbx-1".into(),
            generation: 2,
            operation_id: id.into(),
            attempt,
            kind: "command.run".into(),
            template_fingerprint: None,
            body_hash: Some("a".repeat(64)),
            request_hash: Some("a".repeat(64)),
            digest_pruned: false,
            private_config: None,
            server_request_hash: None,
            digest_scheme: Some("sha256-env-free-v1".into()),
            digest_key_id: None,
            idempotency_key: id.into(),
            phase: ReceiptPhase::Intent,
            state: OperationState::Accepted,
            cancel_requested: false,
            result: None,
            error_code: None,
            error_message: None,
            written_at_unix_ms: 0,
            file_put: None,
            content_deadline_unix_ms: None,
            ext: JournalExt::new(),
        }
    }

    /// R9: the retention prune parses its limits once and works by key; a
    /// failed write leaves the in-memory receipt exactly as it was.
    #[test]
    fn prune_by_key_keeps_the_previous_result_when_the_write_fails() {
        let dir = tempfile::tempdir().unwrap();
        let mut stale = receipt("stale", 1);
        stale.result = Some(json!({"stdout": "old output"}));
        let mut receipts = HashMap::from([("stale".to_owned(), stale.clone())]);
        let missing = dir.path().join("missing");
        assert!(prune_completed(&IoLatch::default(), &missing, &mut receipts).is_err());
        assert_eq!(receipts["stale"].result, stale.result);
        prune_completed(&IoLatch::default(), dir.path(), &mut receipts).unwrap();
        let pruned = receipts["stale"].result.as_ref().unwrap();
        assert_eq!(pruned["outputExpired"], true);
        assert!(pruned.get("stdout").is_none());
    }

    #[test]
    fn multiple_creators_on_one_transport_never_rebind_uncertain_work() {
        let dir = tempfile::tempdir().unwrap();
        let transport = binding();
        let j = HostJournal::open(dir.path(), &transport).unwrap();
        for (id, owner) in [("a", "creator-a"), ("b", "creator-b")] {
            let mut r = receipt(id, 1);
            r.sandbox_id = format!("sbx-{id}");
            r.sandbox_owner_id = owner.into();
            r.idempotency_key = "same-owner-scoped-key".into();
            assert!(matches!(j.record_intent(&r).unwrap(), Decision::Fresh));
            j.record_effect(id).unwrap();
        }
        drop(j);
        let j = HostJournal::open(dir.path(), &transport).unwrap();
        let rows = j.matching(&transport).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.phase == ReceiptPhase::Effect));
        let mut forged = j.lookup("a").unwrap();
        forged.operation_id = "forged".into();
        forged.sandbox_owner_id = "creator-b".into();
        assert!(matches!(
            j.record_intent(&forged).unwrap(),
            Decision::Conflict
        ));
        assert!(j.lookup("forged").is_none());
        let wrong = TransportBindingV11 {
            host_owner_id: "other-host-owner".into(),
            ..transport.clone()
        };
        assert!(j.matching(&wrong).is_err());
        drop(j);
        assert!(HostJournal::open(dir.path(), &wrong).is_err());
        let j = HostJournal::open(dir.path(), &transport).unwrap();
        assert_eq!(j.matching(&transport).unwrap().len(), 2);
    }

    #[test]
    fn reconnect_first_attempt_evidence_rejects_ambiguous_generation_history() {
        // Read-only predicate matrix; durability/reopen is exercised by the
        // interrupted reconnect recovery test, without fsync for every row here.
        let dir = tempfile::tempdir().unwrap();
        let journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        for history in [
            "first",
            "retry",
            "effect",
            "pruned",
            "missing",
            "older-receipt",
            "same-receipt",
            "newer-receipt",
            "older-cleanup",
            "same-cleanup",
            "newer-cleanup",
        ] {
            let mut row = receipt("reconnect", if history == "retry" { 2 } else { 1 });
            row.kind = "sandbox.reconnect".into();
            {
                let mut state = journal.state.lock().unwrap();
                state.receipts.clear();
                state.cleanups.clear();
                if history != "missing" {
                    let mut stored = row.clone();
                    if history == "effect" {
                        stored.phase = ReceiptPhase::Effect;
                    }
                    if history == "pruned" {
                        stored.digest_pruned = true;
                    }
                    state.receipts.insert(row.operation_id.clone(), stored);
                }
                let generation = if history.starts_with("older") {
                    1
                } else if history.starts_with("newer") {
                    3
                } else {
                    2
                };
                if history.ends_with("receipt") {
                    let mut other = receipt("prior", 1);
                    other.generation = generation;
                    state.receipts.insert(other.operation_id.clone(), other);
                }
                if history.ends_with("cleanup") {
                    state.cleanups.insert(
                        row.sandbox_id.clone(),
                        CleanupWatermark {
                            sandbox_owner_id: "owner".into(),
                            version: JOURNAL_VERSION,
                            binding: binding(),
                            sandbox_id: row.sandbox_id.clone(),
                            generation,
                            instance_absent: false,
                            ext: JournalExt::new(),
                        },
                    );
                }
            }
            assert_eq!(
                journal.first_allocation_receipt(&row),
                matches!(history, "first" | "older-receipt" | "older-cleanup"),
                "{history}"
            );
        }
    }

    #[test]
    fn d20_zero_interrupted_intent_and_effect_never_reexecute_after_reopen() {
        for issued in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let dispatch: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner", "operationId":"zero", "sandboxId":"sbx", "kind":"command.run", "generation":1, "attempt":1, "idempotencyKey":"zero", "argv":["sleep", "600"], "timeoutMs":0, "bodyHash":"a".repeat(64)})).unwrap();
            let journal =
                crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
            let dispatch = super::super::test_support::current_fixture_dispatch(&dispatch);
            super::super::test_support::install_fixture_key(&journal, &binding());
            let receipt = journal.prepare_dispatch(&binding(), &dispatch).unwrap();
            assert!(matches!(
                journal.record_intent(&receipt).unwrap(),
                Decision::Fresh
            ));
            if issued {
                journal.record_effect("zero").unwrap();
            }
            drop(journal);
            let reopened =
                crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
            super::super::test_support::install_fixture_key(&reopened, &binding());
            let replay = reopened.prepare_dispatch(&binding(), &dispatch).unwrap();
            assert_eq!(replay.body_hash, receipt.body_hash);
            assert_eq!(replay.request_hash, receipt.request_hash);
            assert!(matches!(
                reopened.record_intent(&replay).unwrap(),
                Decision::Unknown(_)
            ));
        }
    }

    #[test]
    fn command_zero_journal_checksum_reopen_and_replay_bind_exact_timeout() {
        let base: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner", "operationId":"timer", "sandboxId":"sbx", "kind":"command.run", "generation":1, "attempt":1, "idempotencyKey":"timer", "argv":["true"]})).unwrap();
        for keyed in [true] {
            let mut hashes = std::collections::HashSet::new();
            let mut requests = std::collections::HashSet::new();
            for timeout in [None, Some(0), Some(1), Some(120_000), Some(1_800_000)] {
                let dir = tempfile::tempdir().unwrap();
                let mut dispatch = base.clone();
                dispatch.timeout_ms = timeout;
                dispatch.body_hash = Some(sha256_hex(
                    format!("canonical-intent:{timeout:?}").as_bytes(),
                ));
                let key = sandbox_protocol::JournalKeyInstall {
                    connection_epoch: 1,
                    key_version: 1,
                    key_id: "d".repeat(32),
                    key_hex: "ab".repeat(32),
                    server: binding().server,
                    host_owner_id: binding().host_owner_id,
                    host_id: binding().host_id,
                };
                if keyed {
                    dispatch.digest_scheme = Some("hmac-sha256-v1".into());
                    dispatch.digest_key_id = Some(key.key_id.clone());
                }
                let body = fixture_dispatch_bytes(&dispatch);
                assert_eq!(
                    serde_json::from_str::<serde_json::Value>(&body).unwrap()["timeoutMs"],
                    serde_json::to_value(timeout).unwrap()
                );
                let journal =
                    crate::sandbox_relay::test_support::open_journal(dir.path(), &binding())
                        .unwrap();
                if keyed {
                    journal.install_key(&key, &binding(), 1).unwrap();
                }
                let intent = journal.prepare_dispatch(&binding(), &dispatch).unwrap();
                assert!(hashes.insert(intent.body_hash.clone()));
                assert!(requests.insert(intent.request_hash.clone()));
                assert!(matches!(
                    journal.record_intent(&intent).unwrap(),
                    Decision::Fresh
                ));
                journal.record_effect("timer").unwrap();
                journal
                    .record_result(
                        "timer",
                        OperationState::Succeeded,
                        Some(json!({"exitCode":0})),
                        None,
                        None,
                    )
                    .unwrap();
                let original = journal.lookup("timer").unwrap();
                drop(journal);
                let reopened =
                    crate::sandbox_relay::test_support::open_journal(dir.path(), &binding())
                        .unwrap();
                if keyed {
                    reopened.install_key(&key, &binding(), 1).unwrap();
                }
                assert_eq!(
                    reopened.lookup("timer").unwrap().body_hash,
                    original.body_hash
                );
                assert_eq!(
                    reopened.lookup("timer").unwrap().request_hash,
                    original.request_hash
                );
                let exact = reopened.prepare_dispatch(&binding(), &dispatch);
                assert!(
                    exact.is_ok(),
                    "exact timeout must remain replayable after reopen: {exact:?}"
                );
                let exact = exact.unwrap();
                assert!(
                    matches!(reopened.record_intent(&exact).unwrap(), Decision::Replay(_)),
                    "restart never reexecutes"
                );
                for changed in [None, Some(0), Some(120_000)] {
                    if changed == timeout {
                        continue;
                    }
                    dispatch.timeout_ms = changed;
                    let changed = reopened.prepare_dispatch(&binding(), &dispatch);
                    assert!(
                        matches!(changed, Err(SandboxErrorCode::IdempotencyConflict)),
                        "changed timer must conflict after reopen: {changed:?}"
                    );
                }
                let saved = fs::read_to_string(
                    reopened
                        .receipts_dir
                        .join(receipt_file_name("timer").unwrap()),
                )
                .unwrap();
                assert!(!saved.contains("argv"), "journal stores digests only");
            }
        }
    }

    #[test]
    fn process_identity_changes_the_dispatch_digest() {
        let mut dispatch: OperationDispatch = serde_json::from_value(serde_json::json!({
            "sandboxOwnerId":"owner", "operationId":"c", "sandboxId":"sbx",
            "kind":"command.run", "generation":1, "attempt":1, "idempotencyKey":"c",
            "argv":["true"], "resultVersion":1, "processId":"proc-1",
            "bodyHash":"a".repeat(64), "digestScheme":"hmac-sha256-v1", "digestKeyId":"d".repeat(32)
        }))
        .unwrap();
        let first = fixture_dispatch_bytes(&dispatch);
        dispatch.process_id = Some("proc-2".into());
        assert_ne!(fixture_dispatch_bytes(&dispatch), first);
    }

    #[test]
    fn unknown_result_survives_every_later_pre_issue_refusal() {
        let dir = tempfile::tempdir().unwrap();
        let journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        let mut teardown = receipt("uncertain", 1);
        teardown.kind = "sandbox.kill".into();
        journal.record_intent(&teardown).unwrap();
        journal.record_effect("uncertain").unwrap();
        let unknown = journal
            .record_result(
                "uncertain",
                OperationState::UnknownOutcome,
                None,
                Some(SandboxErrorCode::UnknownOutcome),
                None,
            )
            .unwrap();
        for code in [
            SandboxErrorCode::Cancelled,
            SandboxErrorCode::StateConflict,
            SandboxErrorCode::HostCapacity,
        ] {
            for reconcile in [false, true] {
                let stored = journal
                    .record_result_inner(
                        "uncertain",
                        OperationState::Failed,
                        None,
                        (Some(code.into()), None, None),
                        reconcile,
                        ResultFence::None,
                    )
                    .unwrap()
                    .expect("written");
                assert_eq!(stored.state, OperationState::UnknownOutcome);
                assert!(stored.written_at_unix_ms > unknown.written_at_unix_ms);
            }
        }
        let settled = journal
            .record_result(
                "uncertain",
                OperationState::Succeeded,
                Some(json!({"state":"deleted"})),
                None,
                None,
            )
            .unwrap();
        assert_eq!(settled.state, OperationState::Succeeded);
        // Command workers can later prove a timeout after an interim UNKNOWN.
        // Teardown refusal arbitration must not erase that completion proof.
        journal.record_intent(&receipt("command", 1)).unwrap();
        journal
            .record_result("command", OperationState::UnknownOutcome, None, None, None)
            .unwrap();
        let timed_out = journal
            .record_result(
                "command",
                OperationState::Failed,
                None,
                Some(SandboxErrorCode::Timeout),
                None,
            )
            .unwrap();
        assert_eq!(timed_out.state, OperationState::Failed);
    }

    #[test]
    fn d2_refused_unknown_teardowns_rotate_behind_waiting_receipts_durably() {
        let dir = tempfile::tempdir().unwrap();
        let journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        for id in ["old-kill", "old-stop", "waiting"] {
            let mut pending = receipt(id, 1);
            pending.kind = if id == "old-stop" {
                "sandbox.stop"
            } else {
                "sandbox.kill"
            }
            .into();
            journal.record_intent(&pending).unwrap();
            journal
                .record_result(
                    id,
                    OperationState::UnknownOutcome,
                    None,
                    Some(SandboxErrorCode::UnknownOutcome),
                    None,
                )
                .unwrap();
        }
        // Deterministic age ordering, independent of scheduler/clock granularity.
        {
            let mut state = journal.state.lock().unwrap();
            for (index, id) in ["old-kill", "old-stop", "waiting"].into_iter().enumerate() {
                let r = state.receipts.get_mut(id).unwrap();
                r.written_at_unix_ms = index as u64;
                persist_receipt(&journal.io, &journal.receipts_dir, r).unwrap();
            }
        }
        for id in ["old-kill", "old-stop"] {
            journal
                .record_result(
                    id,
                    OperationState::Failed,
                    None,
                    Some(SandboxErrorCode::Cancelled),
                    None,
                )
                .unwrap();
        }
        drop(journal);
        let journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        let mut pending = journal.matching(&binding()).unwrap();
        pending.sort_by_key(|r| r.written_at_unix_ms);
        assert_eq!(
            pending[0].operation_id, "waiting",
            "the two refused receipts monopolize resume slots"
        );
        assert!(
            pending
                .iter()
                .all(|r| r.state == OperationState::UnknownOutcome
                    && r.phase == ReceiptPhase::Effect)
        );
    }

    #[test]
    fn d2_deferred_unissued_recovery_rotates_without_inventing_an_effect() {
        let dir = tempfile::tempdir().unwrap();
        let journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        let mut pending = receipt("intent-only", 1);
        pending.kind = "sandbox.stop".into();
        journal.record_intent(&pending).unwrap();
        let before = journal.lookup("intent-only").unwrap();
        journal.defer_teardown("intent-only").unwrap();
        drop(journal);
        let journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        let after = journal.lookup("intent-only").unwrap();
        assert!(after.written_at_unix_ms > before.written_at_unix_ms);
        assert_eq!(after.phase, ReceiptPhase::Intent);
        assert_eq!(after.state, OperationState::Accepted);
    }

    fn pruned_ack(r: &HostReceipt) -> sandbox_protocol::PrunedReceiptAck {
        sandbox_protocol::PrunedReceiptAck {
            sandbox_owner_id: r.sandbox_owner_id.clone(),
            connection_epoch: 1,
            operation_id: r.operation_id.clone(),
            sandbox_id: r.sandbox_id.clone(),
            generation: r.generation,
            attempt: r.attempt,
            idempotency_key: r.idempotency_key.clone(),
            kind: r.kind.clone(),
        }
    }

    fn assert_intent_size_immutable(pruned: bool) {
        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        let original = receipt("size-immutable", 1);
        j.record_intent(&original).unwrap();
        if pruned {
            j.seed_pruned_receipt_for_test("size-immutable");
        }
        let mut changed = original.clone();
        // Keep the digest identical: size is an independent immutable fence.
        changed.vm_size = sandbox_protocol::VmSize::new(2, 2048).unwrap();
        assert!(matches!(
            j.record_intent(&changed).unwrap(),
            Decision::Conflict
        ));
        assert_eq!(
            j.lookup("size-immutable").unwrap().vm_size,
            original.vm_size
        );
        drop(j);
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        assert!(matches!(
            j.record_intent(&changed).unwrap(),
            Decision::Conflict
        ));
        assert!(matches!(
            j.record_intent(&original).unwrap(),
            Decision::Unknown(_)
        ));
    }

    #[test]
    fn intent_size_is_immutable_with_an_intact_digest() {
        assert_intent_size_immutable(false);
    }

    #[test]
    fn intent_size_is_immutable_when_digest_is_pruned() {
        assert_intent_size_immutable(true);
    }

    #[test]
    fn tombstone_ack_requires_every_identity_fence_and_is_durable() {
        let dir = tempfile::tempdir().unwrap();
        let binding = binding();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap();
        let original = receipt("pruned", 1);
        j.record_intent(&original).unwrap();
        let ack = pruned_ack(&original);
        assert!(
            !j.acknowledge_pruned(&binding, 1, &ack).unwrap(),
            "intact receipts cannot be ACKed away"
        );
        j.seed_pruned_receipt_for_test("pruned");
        for field in [
            "operation",
            "sandbox",
            "creator",
            "generation",
            "attempt",
            "key",
            "kind",
            "epoch",
        ] {
            let mut wrong = ack.clone();
            match field {
                "operation" => wrong.operation_id = "other".into(),
                "sandbox" => wrong.sandbox_id = "other".into(),
                "creator" => wrong.sandbox_owner_id = "other".into(),
                "generation" => wrong.generation += 1,
                "attempt" => wrong.attempt += 1,
                "key" => wrong.idempotency_key = "other".into(),
                "kind" => wrong.kind = "file.list".into(),
                "epoch" => wrong.connection_epoch += 1,
                _ => unreachable!(),
            }
            assert!(
                !j.acknowledge_pruned(&binding, 1, &wrong).unwrap(),
                "{field}"
            );
        }
        for field in ["server", "owner", "host"] {
            let mut wrong = binding.clone();
            match field {
                "server" => wrong.server = "wss://other.example".into(),
                "owner" => wrong.host_owner_id = "other".into(),
                "host" => wrong.host_id = "other".into(),
                _ => unreachable!(),
            }
            assert!(!j.acknowledge_pruned(&wrong, 1, &ack).unwrap(), "{field}");
        }
        assert!(j.lookup("pruned").unwrap().digest_pruned);
        // A normal hash-bearing confirmation must still refuse this tombstone.
        assert!(
            !j.confirm(
                &binding,
                &ReceiptConfirmation {
                    sandbox_owner_id: original.sandbox_owner_id.clone(),
                    operation_id: original.operation_id,
                    sandbox_id: original.sandbox_id,
                    generation: original.generation,
                    attempt: original.attempt,
                    body_hash: original.body_hash.unwrap(),
                    idempotency_key: original.idempotency_key,
                    kind: original.kind,
                    cleanup_generation: None,
                    retire_command: false,
                }
            )
            .unwrap()
        );
        assert!(j.acknowledge_pruned(&binding, 1, &ack).unwrap());
        assert!(!j.acknowledge_pruned(&binding, 1, &ack).unwrap());
        drop(j);
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap();
        assert!(j.lookup("pruned").is_none());
    }

    #[test]
    fn pruned_ack_missing_file_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let binding = binding();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap();
        let original = receipt("missing", 1);
        j.record_intent(&original).unwrap();
        j.seed_pruned_receipt_for_test("missing");
        fs::remove_file(j.receipts_dir.join(receipt_file_name("missing").unwrap())).unwrap();
        let ack = pruned_ack(&original);
        assert!(j.acknowledge_pruned(&binding, 1, &ack).unwrap());
        assert!(j.lookup("missing").is_none());
        assert!(!j.acknowledge_pruned(&binding, 1, &ack).unwrap());
        drop(j);
        assert!(
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding)
                .unwrap()
                .lookup("missing")
                .is_none()
        );
    }

    #[test]
    fn pruned_ack_io_failure_keeps_session_and_receipt_for_retry() {
        use super::super::journal_key::KeyControl;
        use sandbox_protocol::{ServerControlMessage, encode_server_control};
        use std::net::{TcpListener, TcpStream};
        use tungstenite::{Message, WebSocket, protocol::Role, stream::MaybeTlsStream};

        for fail_sync in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let binding = binding();
            let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap();
            let original = receipt("io-failure", 1);
            j.record_intent(&original).unwrap();
            j.seed_pruned_receipt_for_test("io-failure");
            let path = j
                .receipts_dir
                .join(receipt_file_name("io-failure").unwrap());
            if fail_sync {
                j.inject_crash(CrashPoint::BeforePrunedReceiptDirectorySync);
            } else {
                // Real unlink failure, independent of permissions or root UID.
                fs::remove_file(&path).unwrap();
                fs::create_dir(&path).unwrap();
            }
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let tcp = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (peer, _) = listener.accept().unwrap();
            peer.set_read_timeout(Some(std::time::Duration::from_secs(3)))
                .unwrap();
            let mut socket =
                WebSocket::from_raw_socket(MaybeTlsStream::Plain(tcp), Role::Client, None);
            let mut peer = WebSocket::from_raw_socket(peer, Role::Server, None);
            let control = KeyControl {
                journal: &j,
                binding: &binding,
                epoch: Some(1),
                credentials: None,
            };
            let frame = encode_server_control(&ServerControlMessage::ReceiptPrunedAck(pruned_ack(
                &original,
            )))
            .unwrap();
            assert!(control.parse(&frame, &mut socket).unwrap().is_none());
            assert!(
                j.lookup("io-failure").unwrap().digest_pruned,
                "sync failure: {fail_sync}"
            );
            // The same session must still carry subsequent control traffic.
            let heartbeat = encode_server_control(&ServerControlMessage::HeartbeatPong {
                id: "still-alive".into(),
                received_at: "2026-10-27T00:00:00Z".into(),
            })
            .unwrap();
            assert!(matches!(
                control.parse(&heartbeat, &mut socket).unwrap(),
                Some(ServerControlMessage::HeartbeatPong { .. })
            ));
            socket.send(Message::Ping(vec![1].into())).unwrap();
            assert!(matches!(peer.read().unwrap(), Message::Ping(_)));
            if fail_sync {
                assert!(
                    !path.exists(),
                    "unlink succeeded before the failed durability fence"
                );
                *j.crash.lock().unwrap() = None;
            } else {
                fs::remove_dir(&path).unwrap();
            }
            // Retry handles both a failed unlink and an already unlinked file.
            assert!(
                j.acknowledge_pruned(&binding, 1, &pruned_ack(&original))
                    .unwrap()
            );
            assert!(j.lookup("io-failure").is_none());
        }
    }

    #[test]
    fn acknowledged_tombstones_reclaim_all_receipt_admission_slots() {
        let dir = crate::sandbox_relay::test_support::journal_capacity_dir();
        let binding = binding();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap();
        // A full journal reclaims each acknowledged tombstone before new work.
        {
            let mut state = j.state.lock().unwrap();
            for index in 0..MAX_RECEIPTS {
                let r = receipt(&format!("pruned-{index}"), 1).into_digest_pruned();
                persist_receipt(&j.io, &j.receipts_dir, &r).unwrap();
                state.receipts.insert(r.operation_id.clone(), r);
            }
        }
        assert!(matches!(
            j.record_intent(&receipt("fresh", 1)).unwrap(),
            Decision::Capacity
        ));
        for index in 0..MAX_RECEIPTS {
            let r = j.lookup(&format!("pruned-{index}")).unwrap();
            assert!(j.acknowledge_pruned(&binding, 1, &pruned_ack(&r)).unwrap());
        }
        assert!(matches!(
            j.record_intent(&receipt("fresh", 1)).unwrap(),
            Decision::Fresh
        ));
        drop(j);
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap();
        assert_eq!(j.matching(&binding).unwrap().len(), 1);
        assert!(j.lookup("fresh").is_some());
    }

    #[test]
    fn unsupported_version_marker_is_refused_without_converting_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let binding = binding();
        {
            let journal =
                crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap();
            let row = receipt("preserve-unsupported", 1);
            journal.record_intent(&row).unwrap();
        }
        let version_path = dir.path().join("VERSION");
        fs::write(&version_path, "2").unwrap();
        // Preserve every journal file, including uncertain intent evidence.
        let before: Vec<_> = fs::read_dir(dir.path().join("receipts"))
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                (path.clone(), fs::read(path).unwrap())
            })
            .collect();
        let error = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding)
            .unwrap_err()
            .to_string();
        assert!(error.contains("original daemon"), "{error}");
        assert_eq!(fs::read_to_string(version_path).unwrap(), "2");
        assert!(!before.is_empty());
        for (path, bytes) in before {
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
    }

    #[test]
    fn unsupported_receipt_versions_are_refused_without_rewriting_evidence() {
        for version in [0, 2, 4, 5, 6] {
            let dir = tempfile::tempdir().unwrap();
            let path;
            let mut row = receipt("unsupported", 1);
            row.version = version;
            let bytes = serde_json::to_vec(&row).unwrap();
            {
                let journal =
                    crate::sandbox_relay::test_support::open_journal(dir.path(), &binding())
                        .unwrap();
                path = journal.receipts_dir.join("unsupported.json");
                fs::write(&path, &bytes).unwrap();
            }
            let error = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding())
                .unwrap_err()
                .to_string();
            assert!(error.contains("unsupported journal version"), "{error}");
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
    }

    #[test]
    fn key_id_refusal_precedes_digest_and_same_id_mismatch_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let binding = binding();
        let journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap();
        let frame = sandbox_protocol::JournalKeyInstall {
            connection_epoch: 1,
            key_version: 1,
            key_id: "d".repeat(32),
            key_hex: "ab".repeat(32),
            server: binding.server.clone(),
            host_owner_id: binding.host_owner_id.clone(),
            host_id: binding.host_id.clone(),
        };
        let mut dispatch: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner",
            "operationId":"keyed", "sandboxId":"sbx", "kind":"command.run", "idempotencyKey":"keyed",
            "generation":1,"attempt":1,"bodyHash":"a".repeat(64),"env":[["K","private"]],
            "digestScheme":"hmac-sha256-v1","digestKeyId":"d".repeat(32) })).unwrap();
        assert_eq!(
            journal.prepare_dispatch(&binding, &dispatch).unwrap_err(),
            SandboxErrorCode::DigestKeyUnavailable
        );
        journal.install_key(&frame, &binding, 1).unwrap();
        let first = journal.prepare_dispatch(&binding, &dispatch).unwrap();
        assert_ne!(first.request_hash, dispatch.body_hash.clone());
        assert_ne!(first.request_hash, first.body_hash);
        assert_eq!(first.server_request_hash(), dispatch.body_hash.as_deref());
        journal.record_intent(&first).unwrap();
        let calls = std::cell::Cell::new(0);
        dispatch.digest_key_id = Some("e".repeat(32));
        let refusal = journal.prepare_dispatch_with(&binding, &dispatch, |_, _, _| {
            calls.set(calls.get() + 1);
            "a".repeat(64)
        });
        assert_eq!(calls.get(), 0);
        assert_eq!(refusal.unwrap_err(), SandboxErrorCode::DigestKeyChanged);
        dispatch.digest_key_id = Some("d".repeat(32));
        dispatch.env = Some(vec![("K".into(), "different".into())]);
        assert_eq!(
            journal.prepare_dispatch(&binding, &dispatch).unwrap_err(),
            SandboxErrorCode::IdempotencyConflict
        );
        journal.clear_key();
        assert_eq!(
            journal.prepare_dispatch(&binding, &dispatch).unwrap_err(),
            SandboxErrorCode::DigestKeyUnavailable
        );
        drop(journal);
        let reopened =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap();
        assert_eq!(
            reopened.prepare_dispatch(&binding, &dispatch).unwrap_err(),
            SandboxErrorCode::DigestKeyUnavailable
        );
        reopened.install_key(&frame, &binding, 1).unwrap();
        dispatch.env = Some(vec![("K".into(), "private".into())]);
        assert_eq!(
            reopened
                .prepare_dispatch(&binding, &dispatch)
                .unwrap()
                .body_hash,
            first.body_hash
        );
    }

    #[test]
    fn keyed_confirmation_uses_the_server_fence_after_matching_key_reinstall() {
        let dir = tempfile::tempdir().unwrap();
        let binding = binding();
        let journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap();
        let frame = sandbox_protocol::JournalKeyInstall {
            connection_epoch: 1,
            key_version: 1,
            key_id: "d".repeat(32),
            key_hex: "ab".repeat(32),
            server: binding.server.clone(),
            host_owner_id: binding.host_owner_id.clone(),
            host_id: binding.host_id.clone(),
        };
        journal.install_key(&frame, &binding, 1).unwrap();
        let dispatch: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner",  "operationId":"key-confirm", "sandboxId":"sbx",
            "kind":"command.run", "idempotencyKey":"key-confirm", "generation":1, "attempt":1,
            "bodyHash":"a".repeat(64), "digestScheme":"hmac-sha256-v1", "digestKeyId":"d".repeat(32), "env":[["K","private"]] })).unwrap();
        let receipt = journal.prepare_dispatch(&binding, &dispatch).unwrap();
        journal.record_intent(&receipt).unwrap();
        journal
            .record_result("key-confirm", OperationState::Succeeded, None, None, None)
            .unwrap();
        let mut confirmation = ReceiptConfirmation {
            sandbox_owner_id: dispatch.sandbox_owner_id.clone(),
            operation_id: dispatch.operation_id,
            sandbox_id: dispatch.sandbox_id,
            generation: 1,
            attempt: 1,
            body_hash: receipt.request_hash.clone().unwrap(),
            idempotency_key: dispatch.idempotency_key,
            kind: dispatch.kind,
            cleanup_generation: None,
            retire_command: false,
        };
        assert!(!journal.confirm(&binding, &confirmation).unwrap());
        confirmation.body_hash = receipt.server_request_hash().unwrap().into();
        journal.clear_key();
        assert!(!journal.confirm(&binding, &confirmation).unwrap());
        let replaced = sandbox_protocol::JournalKeyInstall {
            key_id: "e".repeat(32),
            ..frame.clone()
        };
        journal.install_key(&replaced, &binding, 1).unwrap();
        assert!(!journal.confirm(&binding, &confirmation).unwrap());
        journal.install_key(&frame, &binding, 1).unwrap();
        assert!(journal.confirm(&binding, &confirmation).unwrap());
        assert!(journal.lookup("key-confirm").is_none());
    }

    #[test]
    fn memory_key_never_enters_journal_checkpoints_or_debug() {
        let dir = tempfile::tempdir().unwrap();
        let binding = binding();
        let frame = sandbox_protocol::JournalKeyInstall {
            connection_epoch: 1,
            key_version: 1,
            key_id: "d".repeat(32),
            server: binding.server.clone(),
            host_owner_id: binding.host_owner_id.clone(),
            host_id: binding.host_id.clone(),
            key_hex: "ab".repeat(32),
        };
        let journal = std::sync::Arc::new(
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap(),
        );
        {
            let _session = super::super::journal_key::KeySession::start(journal.clone());
            journal.install_key(&frame, &binding, 1).unwrap();
            assert!(journal.key.lock().unwrap().is_some());
            assert!(!format!("{journal:?}").contains(&frame.key_hex));
            journal.record_intent(&receipt("key-proof", 1)).unwrap();
            journal.maintain().unwrap();
            fn inspect(dir: &Path, secret: &str) {
                for file in fs::read_dir(dir).unwrap() {
                    let file = file.unwrap();
                    if file.file_type().unwrap().is_dir() {
                        inspect(&file.path(), secret);
                    } else {
                        let bytes = fs::read(file.path()).unwrap();
                        assert!(!String::from_utf8_lossy(&bytes).contains(secret));
                        assert!(!bytes.windows(32).any(|window| window == [0xab; 32]));
                    }
                }
            }
            inspect(dir.path(), &frame.key_hex);
        }
        assert!(journal.key.lock().unwrap().is_none());
        drop(journal);
        let reopened =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap();
        assert!(reopened.key.lock().unwrap().is_none());
        for wrong in [
            TransportBindingV11 {
                host_id: "other-host".into(),
                ..binding.clone()
            },
            TransportBindingV11 {
                host_owner_id: "other-owner".into(),
                ..binding.clone()
            },
        ] {
            assert!(reopened.install_key(&frame, &wrong, 1).is_err());
        }
        assert!(reopened.install_key(&frame, &binding, 2).is_err());
    }

    fn temp_dir() -> PathBuf {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "wssp-journal-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).expect("dir");
        dir
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cancellation_journal_barrier_precedes_revocation_and_survives_restart() {
        use super::super::authority::HostAuthority;
        use std::sync::atomic::Ordering;
        for point in [CrashPoint::BeforeCancel, CrashPoint::AfterCancel] {
            let dir = temp_dir();
            let journal =
                crate::sandbox_relay::test_support::open_journal(&dir, &binding()).unwrap();
            let mut work = receipt("cancel-order", 1);
            work.kind = "command.run".into();
            journal.record_intent(&work).unwrap();
            let authority = HostAuthority::default();
            authority
                .accept_dispatch(
                    &work.operation_id,
                    &work.sandbox_id,
                    &work.kind,
                    work.generation,
                    work.attempt,
                )
                .unwrap();
            let cleanup_permit = authority
                .register_runtime(&work.operation_id, work.generation, work.attempt)
                .unwrap();
            let (flag, guard) = authority
                .register_exec(&work.operation_id, work.generation, work.attempt)
                .unwrap();
            drop(guard);
            journal.inject_crash(point);
            assert!(
                authority
                    .request_cancel(&journal, &work.operation_id, work.generation, work.attempt)
                    .is_err()
            );
            assert!(
                !flag.load(Ordering::Acquire),
                "revocation preceded journal success"
            );
            drop(journal);
            let journal =
                crate::sandbox_relay::test_support::open_journal(&dir, &binding()).unwrap();
            assert_eq!(
                journal.cancel_blocks(&work.operation_id, work.generation),
                point == CrashPoint::AfterCancel
            );
            authority
                .request_cancel(&journal, &work.operation_id, work.generation, work.attempt)
                .unwrap()
                .unwrap();
            assert!(flag.load(Ordering::Acquire));
            assert!(
                !cleanup_permit.is_cancelled(),
                "cancel must retain this owner's cleanup authority"
            );
            authority.shutdown();
            assert!(
                cleanup_permit.is_cancelled(),
                "shutdown still preempts cleanup"
            );
            assert!(journal.lookup(&work.operation_id).unwrap().cancel_requested);
            drop(journal);
            fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn exclusive_lock_refuses_a_second_open() {
        let dir = temp_dir();
        let first =
            crate::sandbox_relay::test_support::open_journal(&dir, &binding()).expect("open");
        assert!(
            first
                .matching(&binding())
                .expect("empty inventory")
                .is_empty()
        );
        let err =
            crate::sandbox_relay::test_support::open_journal(&dir, &binding()).expect_err("locked");
        assert!(err.to_string().contains("lock"), "{err}");
        drop(first);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn crash_after_intent_replays_unknown_and_does_not_repeat() {
        let dir = temp_dir();
        let journal =
            crate::sandbox_relay::test_support::open_journal(&dir, &binding()).expect("open");
        journal.inject_crash(CrashPoint::AfterIntent);
        let work = receipt("op-intent", 1);
        let err = journal.record_intent(&work).expect_err("crash");
        assert!(err.to_string().contains("injected"));
        drop(journal);
        let journal =
            crate::sandbox_relay::test_support::open_journal(&dir, &binding()).expect("reopen");
        match journal
            .record_intent(&receipt("op-intent", 2))
            .expect("lookup")
        {
            Decision::Unknown(existing) => {
                assert_eq!(existing.phase, ReceiptPhase::Intent);
                assert_eq!(existing.attempt, 1);
            }
            other => panic!("expected unknown, got {other:?}"),
        }
        drop(journal);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn crash_after_effect_stays_unknown() {
        let dir = temp_dir();
        let journal =
            crate::sandbox_relay::test_support::open_journal(&dir, &binding()).expect("open");
        journal
            .record_intent(&receipt("op-effect", 1))
            .expect("intent");
        journal.inject_crash(CrashPoint::AfterEffect);
        journal.record_effect("op-effect").expect_err("crash");
        drop(journal);
        let journal =
            crate::sandbox_relay::test_support::open_journal(&dir, &binding()).expect("reopen");
        match journal
            .record_intent(&receipt("op-effect", 2))
            .expect("lookup")
        {
            Decision::Unknown(existing) => assert_eq!(existing.phase, ReceiptPhase::Effect),
            other => panic!("{other:?}"),
        }
        drop(journal);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    /// WP2: a receipt write that fails latches the whole journal (not only
    /// lease writes): lifecycle admission refuses, and the latch survives
    /// until a restart re-reads the journal.
    #[test]
    fn receipt_write_failure_latches_the_journal_wide_io_flag() {
        let dir = temp_dir();
        let journal =
            crate::sandbox_relay::test_support::open_journal(&dir, &binding()).expect("open");
        journal.record_intent(&receipt("op-io", 1)).expect("intent");
        assert!(!journal.io_failed());
        assert_eq!(
            journal.work_refusal("sbx-other", 1, "command.run"),
            Some("no_lease")
        );
        journal.io.fail_writes();
        journal
            .record_effect("op-io")
            .expect_err("injected write failure");
        assert!(journal.io_failed());
        assert_eq!(
            journal.work_refusal("sbx-other", 1, "command.run"),
            Some("journal_io_failed")
        );
        // Stop/kill stay admissible: they only ever reduce effects.
        assert_eq!(journal.work_refusal("sbx-other", 1, "sandbox.stop"), None);
        drop(journal);
        let journal =
            crate::sandbox_relay::test_support::open_journal(&dir, &binding()).expect("reopen");
        assert!(!journal.io_failed(), "a restart re-reads durable state");
        drop(journal);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    /// Every writer latches, not only receipt writes: a marker write and a
    /// receipt delete (confirmation) each trip it.
    #[test]
    fn marker_and_delete_failures_latch_too() {
        let dir = temp_dir();
        let journal =
            crate::sandbox_relay::test_support::open_journal(&dir, &binding()).expect("open");
        journal.io.fail_writes();
        journal
            .persist_marker("REVOKED", b"1")
            .expect_err("marker write fails");
        assert!(journal.io_failed());
        drop(journal);
        let journal =
            crate::sandbox_relay::test_support::open_journal(&dir, &binding()).expect("reopen");
        let latch = IoLatch::default();
        assert!(remove_durably(&latch, &dir.join("receipts"), false).is_err());
        assert!(latch.failed(), "a failed unlink latches");
        let latch = IoLatch::default();
        remove_durably(&latch, &dir.join("absent.json"), true).expect("missing is fine");
        assert!(!latch.failed());
        drop(journal);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn result_replay_and_duplicate_dispatch() {
        let dir = temp_dir();
        let journal =
            crate::sandbox_relay::test_support::open_journal(&dir, &binding()).expect("open");
        journal.record_intent(&receipt("op-ok", 1)).expect("intent");
        journal.record_effect("op-ok").expect("effect");
        journal
            .record_result(
                "op-ok",
                OperationState::Succeeded,
                Some(json!({"exitCode": 0})),
                None,
                None,
            )
            .expect("result");
        match journal.record_intent(&receipt("op-ok", 2)).expect("replay") {
            Decision::Replay(existing) => {
                assert_eq!(existing.state, OperationState::Succeeded);
                assert_eq!(existing.result.unwrap()["exitCode"], 0);
            }
            other => panic!("{other:?}"),
        }
        drop(journal);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn cancel_survives_attempt_advance() {
        let dir = temp_dir();
        let journal =
            crate::sandbox_relay::test_support::open_journal(&dir, &binding()).expect("open");
        journal.record_intent(&receipt("op-c", 1)).expect("intent");
        journal.record_cancel("op-c", 2, 1).expect("cancel");
        assert!(journal.cancel_blocks("op-c", 2));
        match journal.record_intent(&receipt("op-c", 2)).expect("n+1") {
            Decision::Unknown(_) => {}
            other => panic!("{other:?}"),
        }
        drop(journal);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    /// WP3: the carry-expiry reason is journaled with the cancel, survives a
    /// reload and the Result write, and never overwrites an earlier cancel.
    #[test]
    fn carry_expired_cancel_reason_persists_across_reload() {
        let dir = tempfile::tempdir().expect("dir");
        let open = || {
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).expect("open")
        };
        let journal = open();
        journal.record_intent(&receipt("op", 1)).expect("intent");
        journal.record_intent(&receipt("user", 1)).expect("intent");
        journal
            .record_cancel_for("op", 2, 1, Some(CancelReason::CarryExpired))
            .expect("cancel");
        // A wire cancel first: a later host cancel adds no reason.
        journal.record_cancel("user", 2, 1).expect("cancel");
        journal
            .record_cancel_for("user", 2, 1, Some(CancelReason::CarryExpired))
            .expect("cancel");
        drop(journal);
        let journal = open();
        let op = journal.lookup("op").expect("op");
        assert!(op.cancel_requested);
        assert_eq!(CancelReason::of(&op), Some(CancelReason::CarryExpired));
        assert_eq!(op.ext["cancelReason"], json!("carry_expired"));
        let user = journal.lookup("user").expect("user");
        assert!(user.cancel_requested);
        assert_eq!(CancelReason::of(&user), None);
        journal
            .record_result(
                "op",
                OperationState::Failed,
                None,
                Some(SandboxErrorCode::HostDisconnectExpired),
                None,
            )
            .expect("result");
        drop(journal);
        let op = open().lookup("op").expect("op");
        assert_eq!(CancelReason::of(&op), Some(CancelReason::CarryExpired));
        assert_eq!(op.state, OperationState::Failed);
    }

    /// The not-issued settlement is one compare-and-set. At the
    /// pause point (after the expiry chose the stale attempt, before the
    /// journal is locked) the revoked attempt settles, is confirmed away and
    /// the operation is redispatched as attempt 2, which enters Effect. The
    /// stale settlement must not touch attempt 2.
    #[test]
    fn settle_not_issued_is_an_exact_intent_compare_and_set() {
        let dir = tempfile::tempdir().expect("dir");
        let journal = std::sync::Arc::new(
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).expect("open"),
        );
        journal.record_intent(&receipt("op", 1)).expect("intent");
        let raced = journal.clone();
        SETTLE_PAUSE.with(|pause| {
            *pause.borrow_mut() = Some(Box::new(move || {
                // The revoked worker settles attempt 1 ...
                raced
                    .record_result("op", OperationState::Failed, None, None, None)
                    .expect("worker result");
                // ... the server confirms it (receipt retired) and redispatches.
                let mut state = raced.state.lock().unwrap();
                state.receipts.remove("op");
                drop(state);
                assert!(matches!(
                    raced.record_intent(&receipt("op", 2)).expect("attempt 2"),
                    Decision::Fresh
                ));
                raced.record_effect("op").expect("attempt 2 effect");
            }));
        });
        assert!(!journal.settle_not_issued("op", 2, 1).expect("settle"));
        SETTLE_PAUSE.with(|pause| pause.borrow_mut().take());
        let current = journal.lookup("op").expect("attempt 2");
        assert_eq!(current.attempt, 2);
        assert_eq!(
            current.phase,
            ReceiptPhase::Effect,
            "never marked not issued"
        );
        assert_eq!(current.error_code, None);
        // Same attempt but already past Intent: untouched.
        assert!(!journal.settle_not_issued("op", 2, 2).expect("settle"));
        assert_eq!(journal.lookup("op").unwrap().phase, ReceiptPhase::Effect);
        // A confirmed-away receipt: nothing to settle, no error.
        assert!(!journal.settle_not_issued("gone", 2, 1).expect("settle"));
        // The exact Intent attempt is settled durably.
        journal
            .record_intent(&receipt("queued", 1))
            .expect("intent");
        assert!(journal.settle_not_issued("queued", 2, 1).expect("settle"));
        let settled = journal.lookup("queued").unwrap();
        assert_eq!(settled.phase, ReceiptPhase::Result);
        assert_eq!(settled.state, OperationState::Failed);
        assert!(
            settled
                .error_code
                .as_ref()
                .is_some_and(|code| code.is(SandboxErrorCode::HostEffectNotIssued))
        );
        // A later worker refusal leaves the terminal Result unchanged.
        let again = journal
            .record_result("queued", OperationState::Cancelled, None, None, None)
            .unwrap();
        assert_eq!(again.state, OperationState::Failed);
    }

    #[test]
    fn corrupt_journal_is_refused() {
        let dir = temp_dir();
        fs::create_dir_all(dir.join("receipts")).expect("receipts");
        fs::write(dir.join("receipts/op-bad.json"), b"{not-json").expect("garbage");
        let err = crate::sandbox_relay::test_support::open_journal(&dir, &binding())
            .expect_err("corrupt");
        assert!(err.to_string().contains("corrupt"), "{err}");
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn valid_json_corruption_is_also_refused() {
        let dir = tempfile::tempdir().expect("dir");
        let journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).expect("open");
        journal.record_intent(&receipt("op", 1)).expect("intent");
        drop(journal);
        let path = dir.path().join("receipts/op.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("read")).expect("json");
        value["receipt"]["generation"] = json!(100);
        fs::write(path, value.to_string()).expect("corrupt");
        assert!(
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding())
                .expect_err("refuse")
                .to_string()
                .contains("checksum")
        );
    }

    #[test]
    fn body_hash_mismatch_is_conflict() {
        let dir = temp_dir();
        let journal =
            crate::sandbox_relay::test_support::open_journal(&dir, &binding()).expect("open");
        journal.record_intent(&receipt("op-h", 1)).expect("intent");
        let mut other = receipt("op-h", 1);
        other.body_hash = Some("b".repeat(64));
        match journal.record_intent(&other).expect("conflict") {
            Decision::Conflict => {}
            other => panic!("{other:?}"),
        }
        drop(journal);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn pinned_template_readiness_metadata_cannot_change_on_replay() {
        let dir = tempfile::tempdir().expect("dir");
        let journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).expect("open");
        let wire = json!({"sandboxOwnerId":"owner",
            "operationId": "op-template", "sandboxId": "sandbox",
            "idempotencyKey": "create-template", "kind": "sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(),
            "generation": 1, "attempt": 1, "bodyHash": "a".repeat(64),
            "incusFingerprint": "a".repeat(64), "architecture": "x86_64",
            "guestUid": 1000, "guestGid": 1000,
            "guestHome": "/home/user", "guestShell": "/bin/bash"
        });
        let dispatch: OperationDispatch = serde_json::from_value(wire.clone()).expect("dispatch");
        journal
            .record_intent(&intent_from_dispatch(&journal, &binding(), &dispatch))
            .expect("intent");
        for (field, value) in [
            ("incusFingerprint", json!("b".repeat(64))),
            ("architecture", json!("aarch64")),
            ("guestUid", json!(2000)),
            ("guestGid", json!(2000)),
            ("guestHome", json!("/home/other")),
            ("guestShell", json!("/bin/sh")),
        ] {
            let mut changed = wire.clone();
            changed[field] = value;
            let changed: OperationDispatch = serde_json::from_value(changed).expect("dispatch");
            assert_eq!(
                journal
                    .prepare_dispatch(
                        &binding(),
                        &crate::sandbox_relay::test_support::current_fixture_dispatch(&changed)
                    )
                    .unwrap_err(),
                SandboxErrorCode::IdempotencyConflict,
                "changed {field} must conflict"
            );
        }
    }

    #[test]
    fn result_content_is_bounded_without_receipt_eviction() {
        let dir = temp_dir();
        let journal =
            crate::sandbox_relay::test_support::open_journal(&dir, &binding()).expect("open");
        for i in 0..(MAX_COMPLETED_RECEIPTS + 8) {
            let id = format!("op{i:04}");
            journal.record_intent(&receipt(&id, 1)).expect("intent");
            journal
                .record_result(
                    &id,
                    OperationState::Succeeded,
                    Some(json!({"stdout":"output"})),
                    None,
                    None,
                )
                .expect("result");
        }
        let remaining = journal.matching(&binding()).expect("binding");
        assert_eq!(remaining.len(), MAX_COMPLETED_RECEIPTS + 8);
        assert_eq!(
            remaining
                .iter()
                .filter(|r| r
                    .result
                    .as_ref()
                    .is_some_and(|v| v.get("outputExpired").is_none()))
                .count(),
            MAX_COMPLETED_RECEIPTS
        );
        assert!(journal.lookup("op0000").is_some());
        drop(journal);
        fs::remove_dir_all(dir).expect("cleanup");
    }
    /// C25: command completion metadata (`exitCode`, `pid`, `outputBytes`) is
    /// evidence, not content. Neither count nor age retention may replace it
    /// with `outputExpired`, or a replayed receipt can no longer resolve the
    /// server's pending operation or restore its completion watermark.
    #[test]
    fn command_completion_metadata_survives_count_and_age_pruning() {
        let command_result = || json!({"exitCode": 0, "pid": 4242, "outputBytes": 200_000});
        // Count pruning: more completed receipts than the retained maximum.
        let dir = temp_dir();
        let journal =
            crate::sandbox_relay::test_support::open_journal(&dir, &binding()).expect("open");
        journal.record_intent(&receipt("cmd", 1)).expect("intent");
        journal
            .record_result(
                "cmd",
                OperationState::Succeeded,
                Some(command_result()),
                None,
                None,
            )
            .expect("result");
        for i in 0..(MAX_COMPLETED_RECEIPTS + 8) {
            let id = format!("fill{i:04}");
            journal.record_intent(&receipt(&id, 1)).expect("intent");
            journal
                .record_result(
                    &id,
                    OperationState::Succeeded,
                    Some(json!({"stdout": "output"})),
                    None,
                    None,
                )
                .expect("result");
        }
        journal.maintain().expect("prune");
        let retained = journal.lookup("cmd").expect("receipt retained");
        assert_eq!(retained.result, Some(command_result()));
        drop(journal);
        fs::remove_dir_all(dir).expect("cleanup");
        // Age pruning: an ancient command receipt keeps its scalar metadata.
        let dir = temp_dir();
        let journal =
            crate::sandbox_relay::test_support::open_journal(&dir, &binding()).expect("open");
        journal.record_intent(&receipt("cmd", 1)).expect("intent");
        let mut stored = journal
            .record_result(
                "cmd",
                OperationState::Succeeded,
                Some(command_result()),
                None,
                None,
            )
            .expect("result");
        stored.written_at_unix_ms = 0;
        persist_receipt(&IoLatch::default(), &dir.join("receipts"), &stored).expect("old result");
        drop(journal);
        let journal =
            crate::sandbox_relay::test_support::open_journal(&dir, &binding()).expect("restart");
        journal.maintain().expect("prune");
        let retained = journal.lookup("cmd").expect("receipt retained");
        assert_eq!(retained.result, Some(command_result()));
        drop(journal);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn result_size_and_age_expire_content_without_losing_identity() {
        let dir = tempfile::tempdir().expect("dir");
        let journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).expect("open");
        journal.record_intent(&receipt("op", 1)).expect("intent");
        let mut stored = journal
            .record_result(
                "op",
                OperationState::Succeeded,
                Some(json!({"stdout": "x".repeat(RECEIPT_LIMITS.result_bytes + 1)})),
                None,
                None,
            )
            .expect("result");
        assert_eq!(
            stored.result.as_ref().expect("bounded result")["truncated"],
            true
        );
        assert_eq!(stored.result.as_ref().unwrap()["retainedBytes"], 0);
        stored.written_at_unix_ms = 0;
        persist_receipt(&IoLatch::default(), &dir.path().join("receipts"), &stored)
            .expect("old result");
        drop(journal);
        let journal = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding())
            .expect("restart");
        match journal.record_intent(&receipt("op", 2)).expect("replay") {
            Decision::Replay(stored) => assert_eq!(
                stored.result.expect("expired content")["outputExpired"],
                true
            ),
            other => panic!("identity lost: {other:?}"),
        }
    }

    #[test]
    fn result_persisted_before_crash_is_replayable_and_private() {
        let dir = tempfile::tempdir().expect("dir");
        let journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).expect("open");
        journal.record_intent(&receipt("done", 1)).expect("intent");
        journal.inject_crash(CrashPoint::AfterResult);
        journal
            .record_result(
                "done",
                OperationState::Succeeded,
                Some(json!({"exitCode": 7})),
                None,
                None,
            )
            .expect_err("crash after durable result");
        drop(journal);
        let journal = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding())
            .expect("reopen");
        assert!(matches!(
            journal
                .record_intent(&receipt("done", 2))
                .expect("duplicate"),
            Decision::Replay(_)
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(dir.path()).expect("dir").permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(dir.path().join("receipts/done.json"))
                    .expect("receipt")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn every_identity_and_body_component_is_bound() {
        let dir = tempfile::tempdir().expect("dir");
        let journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).expect("open");
        let original = receipt("op", 1);
        journal.record_intent(&original).expect("intent");
        for field in 0..8 {
            let mut other = original.clone();
            match field {
                0 => other.server = "foreign".into(),
                1 => other.host_owner_id = "foreign".into(),
                2 => other.host_id = "foreign".into(),
                3 => other.sandbox_id = "foreign".into(),
                4 => other.generation += 1,
                5 => other.kind = "file.put".into(),
                6 => other.body_hash = Some("b".repeat(64)),
                _ => other.idempotency_key = "other".into(),
            }
            assert!(matches!(
                journal.record_intent(&other).expect("lookup"),
                Decision::Conflict
            ));
        }
        let mut other = original.clone();
        other.operation_id = "other".into();
        assert!(matches!(
            journal.record_intent(&other).expect("key reuse"),
            Decision::Conflict
        ));
    }

    #[test]
    fn one_sandbox_holds_at_most_its_command_receipt_cap() {
        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        // The daemon default (`--max-concurrent-commands` below 64).
        j.set_max_concurrent_commands(16);
        let mut first = None;
        for i in 0..SANDBOX_COMMAND_RECEIPTS_MIN {
            let mut r = receipt(&format!("c{i}"), 1);
            r.idempotency_key = format!("k{i}");
            assert!(
                matches!(j.record_intent(&r).unwrap(), Decision::Fresh),
                "{i}"
            );
            first.get_or_insert(r);
        }
        let mut next = receipt("c-over", 1);
        next.idempotency_key = "k-over".into();
        assert!(matches!(
            j.record_intent(&next).unwrap(),
            Decision::SandboxReceipts
        ));
        // A replay of a retained receipt is never refused.
        assert!(matches!(
            j.record_intent(first.as_ref().unwrap()).unwrap(),
            Decision::Unknown(_)
        ));
        // Another sandbox and teardown are unaffected.
        let mut other = receipt("other", 1);
        other.sandbox_id = "sbx-2".into();
        other.idempotency_key = "k-other".into();
        assert!(matches!(j.record_intent(&other).unwrap(), Decision::Fresh));
        let mut stop = receipt("stop", 1);
        stop.kind = "sandbox.stop".into();
        stop.idempotency_key = "k-stop".into();
        assert!(!matches!(
            j.record_intent(&stop).unwrap(),
            Decision::SandboxReceipts
        ));
        // A larger command concurrency raises the cap.
        j.set_max_concurrent_commands(256);
        assert!(matches!(j.record_intent(&next).unwrap(), Decision::Fresh));
    }

    #[test]
    fn creator_receipt_flood_keeps_other_creator_and_teardown_capacity_without_eviction() {
        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        {
            let mut state = j.state.lock().unwrap();
            for i in 0..CREATOR_MAX_RECEIPTS {
                let mut r = receipt(&format!("a-{i}"), 1);
                r.phase = ReceiptPhase::Effect;
                state.receipts.insert(r.operation_id.clone(), r);
            }
        }
        assert!(matches!(
            j.record_intent(&receipt("a-overflow", 1)).unwrap(),
            Decision::Capacity
        ));
        let mut b = receipt("b-first", 1);
        b.sandbox_owner_id = "creator-b".into();
        b.sandbox_id = "b-sandbox".into();
        assert!(matches!(j.record_intent(&b).unwrap(), Decision::Fresh));
        assert!(matches!(
            j.record_intent(&receipt("a-0", 1)).unwrap(),
            Decision::Unknown(_)
        ));
        for (i, kind) in ["sandbox.stop", "sandbox.kill"].into_iter().enumerate() {
            let mut cleanup = receipt(&format!("cleanup-{i}"), 1);
            cleanup.kind = kind.into();
            assert!(matches!(
                j.record_intent(&cleanup).unwrap(),
                Decision::Fresh
            ));
        }
        assert_eq!(j.state.lock().unwrap().receipts.len(), MAX_RECEIPTS + 2);
        assert!(j.lookup("a-0").is_some());
        assert!(!j.receipts_dir.join("a-overflow.json").exists());
        // Same sandbox with a forged creator cannot consume the other allowance.
        let mut forged = receipt("forged", 1);
        forged.sandbox_owner_id = "creator-c".into();
        assert!(matches!(
            j.record_intent(&forged).unwrap(),
            Decision::Conflict
        ));
    }
    #[test]
    fn full_journal_refuses_fresh_work_but_retains_unknown_and_replay() {
        let dir = tempfile::tempdir().expect("dir");
        let journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).expect("open");
        // Exercise capacity without thousands of fsyncs: retained entries are all
        // indistinguishable for admission, regardless of their phase.
        for index in 0..MAX_RECEIPTS {
            let r = receipt(&format!("op{index}"), 1);
            journal
                .state
                .lock()
                .expect("state")
                .receipts
                .insert(r.operation_id.clone(), r);
        }
        assert!(matches!(
            journal.record_intent(&receipt("new", 1)).unwrap(),
            Decision::Capacity
        ));
        assert!(matches!(
            journal
                .record_intent(&receipt("op0", 2))
                .expect("duplicate"),
            Decision::Unknown(_)
        ));
        assert!(!dir.path().join("receipts/new.json").exists());
    }
    pub(super) fn confirmation(r: &HostReceipt) -> ReceiptConfirmation {
        ReceiptConfirmation {
            sandbox_owner_id: r.sandbox_owner_id.clone(),
            operation_id: r.operation_id.clone(),
            sandbox_id: r.sandbox_id.clone(),
            generation: r.generation,
            attempt: r.attempt,
            body_hash: r.server_request_hash().unwrap().to_owned(),
            idempotency_key: r.idempotency_key.clone(),
            kind: r.kind.clone(),
            cleanup_generation: None,
            retire_command: false,
        }
    }
    /// C31: once the server confirms cleanup at a later generation, the
    /// settled lease record is durably reclaimed — admission capacity bounds
    /// outstanding work, not lifetime creations. The cleanup watermark keeps
    /// fencing stale dispatches after the record is gone.
    /// A completed stop leaves the VM stopped on disk; its lease record is the
    /// census binding evidence and must survive confirmation compaction, or the
    /// next reconnect's census rejects the still-present instance and wedges
    /// the host. Only proven-absent instances (kill/delete) compact.
    #[test]
    fn stopped_vm_lease_survives_compaction_and_the_reconnect_census() {
        let dir = tempfile::tempdir().expect("dir");
        let binding = binding();
        let journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).expect("open");
        for (op, kind, end_state, absent) in [
            ("stop", "sandbox.stop", "stopped", false),
            ("kill", "sandbox.kill", "deleted", true),
        ] {
            let sandbox = format!("sbx-{op}");
            let create: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner",
                "operationId": format!("create-{op}"), "sandboxId": sandbox, "kind": "sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(),
                "generation": 1, "attempt": 1, "idempotencyKey": format!("create-{op}"), "bodyHash": "a".repeat(64),
                "lease": { "revision": 1, "deadlineUnixMs": now_ms() + 3_600_000, "action": "stop", "expiryPolicy": "retry-force-60s" }
            }))
            .expect("create dispatch");
            journal
                .record_intent(&intent_from_dispatch(&journal, &binding, &create))
                .expect("intent");
            journal.accept_fixture_lease(&create).expect("lease");
            journal
                .record_result(
                    &create.operation_id,
                    OperationState::Succeeded,
                    Some(json!({"state":"ready","lease":create.lease})),
                    None,
                    None,
                )
                .expect("create result");
            // Confirm the create first so its receipt no longer references the
            // lease: the stopped record then stands on its own evidence.
            let create_confirmation = confirmation(&journal.lookup(&create.operation_id).unwrap());
            assert!(
                journal
                    .confirm(&binding, &create_confirmation)
                    .expect("confirm create")
            );
            let stop: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner",
                "operationId": op, "sandboxId": sandbox, "kind": kind,
                "generation": 1, "attempt": 1, "idempotencyKey": op, "bodyHash": "b".repeat(64)
            }))
            .expect("stop dispatch");
            journal
                .record_intent(&intent_from_dispatch(&journal, &binding, &stop))
                .expect("stop intent");
            journal.record_effect(op).expect("effect");
            journal
                .record_result(
                    op,
                    OperationState::Succeeded,
                    Some(json!({"state": end_state})),
                    None,
                    None,
                )
                .expect("stop result");
            let row = journal.lease(&sandbox).expect("lease row");
            assert!(row.expired && row.expiry_complete, "{op} settles the lease");
            assert_eq!(row.instance_absent, absent, "{op} absence evidence");
            let mut confirmed = confirmation(&journal.lookup(op).unwrap());
            confirmed.cleanup_generation = Some(2);
            assert!(journal.confirm(&binding, &confirmed).expect("confirm"));
            journal.maintain().expect("maintain");
            if absent {
                assert!(
                    journal.lease(&sandbox).is_none(),
                    "proven-absent instance compacts"
                );
            } else {
                assert!(
                    journal.lease(&sandbox).is_some(),
                    "the stopped VM keeps its durable census binding"
                );
            }
        }
        drop(journal);
        // Reopen (process restart / reconnect): the stopped VM is still on
        // disk and the census must accept it — not wedge the host.
        let journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).expect("reopen");
        crate::sandbox_relay::expiry::check_inventory(
            &journal,
            &[sandbox_runtime::RuntimeInventoryEntry {
                sandbox_id: "sbx-stop".to_string(),
                state: sandbox_protocol::SandboxLifecycleState::Stopped,
                configured_size: sandbox_runtime::ConfiguredSize::Configured(
                    sandbox_protocol::VmSize::defaults().unwrap(),
                ),
            }],
        )
        .expect("census accepts the stopped VM");
    }

    /// A stop that left the VM on disk (explicit stop, or a completed Stop
    /// expiry) must still release its lease record when a later
    /// generation-fenced kill proves the instance gone — otherwise the record
    /// is retained forever. The kill only adds absence evidence; it never
    /// reopens unfinished expiry.
    #[test]
    fn stop_then_kill_releases_the_lease_record() {
        use std::sync::atomic::{AtomicU64, Ordering};
        #[derive(Debug)]
        struct Clock(AtomicU64);
        impl crate::sandbox_relay::clock::ClockSource for Clock {
            fn sample(&self) -> Result<(u64, u64)> {
                Ok((self.0.load(Ordering::SeqCst), 0))
            }
        }
        for expired_by_timer in [false, true] {
            let dir = tempfile::tempdir().expect("dir");
            let binding = binding();
            let start = now_ms();
            let clock = std::sync::Arc::new(Clock(AtomicU64::new(start)));
            let mut journal =
                crate::sandbox_relay::test_support::open_journal(dir.path(), &binding)
                    .expect("open");
            journal.clock =
                std::sync::Arc::new(crate::sandbox_relay::clock::LeaseClock::new(clock.clone()));
            let journal = journal;
            let sandbox = "sbx-stop-kill";
            let deadline = start + 100_000;
            let create: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner",
                "operationId": "create", "sandboxId": sandbox, "kind": "sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(),
                "generation": 1, "attempt": 1, "idempotencyKey": "create", "bodyHash": "a".repeat(64),
                "lease": { "revision": 1, "deadlineUnixMs": deadline, "action": "stop", "expiryPolicy": "retry-force-60s" }
            }))
            .expect("create dispatch");
            journal
                .record_intent(&intent_from_dispatch(&journal, &binding, &create))
                .expect("intent");
            journal.accept_fixture_lease(&create).expect("lease");
            journal
                .record_result(
                    "create",
                    OperationState::Succeeded,
                    Some(json!({"state":"ready","lease":create.lease})),
                    None,
                    None,
                )
                .expect("create result");
            let create_confirmation = confirmation(&journal.lookup("create").unwrap());
            assert!(
                journal
                    .confirm(&binding, &create_confirmation)
                    .expect("confirm create")
            );
            if expired_by_timer {
                // The deadline timer stops the VM; finish_expiry completes a
                // Stop expiry with the instance still present.
                clock.0.store(deadline + 1, Ordering::SeqCst);
                assert!(journal.expire_lease(sandbox, 1, 1).expect("timer expiry"));
                let row = journal.lease(sandbox).expect("lease row");
                journal.finish_expiry(&row).expect("finish stop expiry");
            } else {
                let stop: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner",
                    "operationId": "stop", "sandboxId": sandbox, "kind": "sandbox.stop", "allocation": crate::sandbox_relay::test_support::allocation(),
                    "generation": 1, "attempt": 1, "idempotencyKey": "stop", "bodyHash": "b".repeat(64)
                }))
                .expect("stop dispatch");
                journal
                    .record_intent(&intent_from_dispatch(&journal, &binding, &stop))
                    .expect("stop intent");
                journal.record_effect("stop").expect("effect");
                journal
                    .record_result(
                        "stop",
                        OperationState::Succeeded,
                        Some(json!({"state":"stopped"})),
                        None,
                        None,
                    )
                    .expect("stop result");
                let stop_confirmation = confirmation(&journal.lookup("stop").unwrap());
                assert!(
                    journal
                        .confirm(&binding, &stop_confirmation)
                        .expect("confirm stop")
                );
            }
            let settled = journal.lease(sandbox).expect("settled lease");
            assert!(settled.expired && settled.expiry_complete);
            assert!(!settled.instance_absent, "the stop left the VM on disk");
            // A repeated stop is presence evidence, never deletion evidence:
            // only a kill may mark a settled lease absent.
            let stop_again: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner",
                "operationId": "stop-again", "sandboxId": sandbox, "kind": "sandbox.stop", "allocation": crate::sandbox_relay::test_support::allocation(),
                "generation": 1, "attempt": 1, "idempotencyKey": "stop-again", "bodyHash": "d".repeat(64)
            }))
            .expect("stop-again dispatch");
            journal
                .record_intent(&intent_from_dispatch(&journal, &binding, &stop_again))
                .expect("stop-again intent");
            journal.record_effect("stop-again").expect("effect");
            journal
                .record_result(
                    "stop-again",
                    OperationState::Succeeded,
                    Some(json!({"state":"stopped"})),
                    None,
                    None,
                )
                .expect("stop-again result");
            assert!(
                !journal.lease(sandbox).expect("lease row").instance_absent,
                "a stop receipt never marks absence"
            );
            // The later kill deletes the stopped VM: absence evidence.
            let kill: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner",
                "operationId": "kill", "sandboxId": sandbox, "kind": "sandbox.kill", "allocation": crate::sandbox_relay::test_support::allocation(),
                "generation": 1, "attempt": 1, "idempotencyKey": "kill", "bodyHash": "c".repeat(64)
            }))
            .expect("kill dispatch");
            journal
                .record_intent(&intent_from_dispatch(&journal, &binding, &kill))
                .expect("kill intent");
            journal.record_effect("kill").expect("effect");
            journal
                .record_result(
                    "kill",
                    OperationState::Succeeded,
                    Some(json!({"state":"deleted"})),
                    None,
                    None,
                )
                .expect("kill result");
            let row = journal.lease(sandbox).expect("lease row after kill");
            assert!(
                row.instance_absent,
                "generation-fenced kill marks the settled lease absent"
            );
            assert!(row.expired && row.expiry_complete, "expiry undisturbed");
            let mut kill_confirmation = confirmation(&journal.lookup("kill").unwrap());
            kill_confirmation.cleanup_generation = Some(2);
            assert!(
                journal
                    .confirm(&binding, &kill_confirmation)
                    .expect("confirm kill")
            );
            journal.maintain().expect("maintain");
            assert!(
                journal.lease(sandbox).is_none(),
                "stop-then-kill compacts the record"
            );
            drop(journal);
            let journal = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding)
                .expect("reopen");
            assert!(
                journal.lease(sandbox).is_none(),
                "the compaction is durable across reopen"
            );
            crate::sandbox_relay::expiry::check_inventory(&journal, &[])
                .expect("empty census passes after release");
        }
    }

    #[test]
    fn confirmed_cleanup_compacts_settled_lease_records() {
        use std::sync::atomic::{AtomicU64, Ordering};
        #[derive(Debug)]
        struct Clock(AtomicU64);
        impl crate::sandbox_relay::clock::ClockSource for Clock {
            fn sample(&self) -> Result<(u64, u64)> {
                Ok((self.0.load(Ordering::SeqCst), 0))
            }
        }
        let dir = tempfile::tempdir().expect("dir");
        let binding = binding();
        let start = now_ms();
        let clock = std::sync::Arc::new(Clock(AtomicU64::new(start)));
        let mut journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).expect("open");
        journal.clock =
            std::sync::Arc::new(crate::sandbox_relay::clock::LeaseClock::new(clock.clone()));
        let journal = journal;
        // The lease clock never runs backwards: each cycle occupies its own
        // 200 s slice of the timeline.
        let advance = |offset: u64| clock.0.store(start + offset, Ordering::SeqCst);
        for cycle in 0..3u64 {
            let base = cycle * 200_000;
            advance(base);
            let sandbox = format!("sbx-churn-{cycle}");
            let create: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner",
                "operationId": format!("create-{cycle}"), "sandboxId": sandbox,
                "kind": "sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(), "generation": 1, "attempt": 1,
                "idempotencyKey": format!("create-{cycle}"), "bodyHash": "a".repeat(64),
                "lease": { "revision": 1, "deadlineUnixMs": start + base + 60_000, "action": "destroy", "expiryPolicy": "retry-force-60s" }
            }))
            .expect("dispatch");
            journal
                .record_intent(&intent_from_dispatch(&journal, &binding, &create))
                .expect("intent");
            journal.accept_fixture_lease(&create).expect("lease");
            journal
                .record_result(
                    &create.operation_id,
                    OperationState::Succeeded,
                    Some(json!({"state":"ready","lease":create.lease})),
                    None,
                    None,
                )
                .expect("result");
            advance(base + 61_000);
            assert!(journal.expire_lease(&sandbox, 1, 1).expect("expire"));
            // Confirming cleanup before expiry settles must not compact.
            let mut confirmed = confirmation(&journal.lookup(&create.operation_id).unwrap());
            confirmed.cleanup_generation = Some(2);
            assert!(journal.confirm(&binding, &confirmed).expect("confirm"));
            assert!(
                journal.lease(&sandbox).is_some(),
                "unsettled expiry survives compaction"
            );
            journal
                .finish_expiry(&journal.lease(&sandbox).unwrap())
                .expect("finish");
            journal.maintain().expect("maintain");
            assert!(
                journal.lease(&sandbox).is_none(),
                "settled, watermark-covered record reclaimed"
            );
            assert!(
                !dir.path()
                    .join("leases")
                    .join(cleanup_file_name(&sandbox))
                    .exists(),
                "lease checkpoint removed"
            );
            // The watermark still fences a stale dispatch for the sandbox,
            // while a newer generation is admitted again: capacity is
            // outstanding work, not lifetime creations.
            let mut stale = create.clone();
            stale.operation_id = format!("stale-{cycle}");
            stale.idempotency_key = format!("stale-{cycle}");
            assert!(
                journal
                    .record_intent(&intent_from_dispatch(&journal, &binding, &stale))
                    .is_err(),
                "deleted retained root fences stale intent before lease admission"
            );
            assert!(
                journal.accept_fixture_lease(&stale).is_err(),
                "stale generation fenced by the watermark"
            );
            assert!(journal.lease(&sandbox).is_none());
            let mut fresh = create.clone();
            fresh.operation_id = format!("fresh-{cycle}");
            fresh.idempotency_key = format!("fresh-{cycle}");
            fresh.generation = 3;
            fresh.lease = Some(sandbox_protocol::HostLease {
                revision: 1,
                deadline_unix_ms: start + base + 121_000,
                action: sandbox_protocol::LeaseAction::Destroy,
                expiry_policy: sandbox_protocol::ExpiryPolicy::RetryForce60s,
                shorten_only: false,
                from_ready_ms: None,
            });
            journal
                .record_intent(&intent_from_dispatch(&journal, &binding, &fresh))
                .expect("fresh intent");
            journal
                .accept_fixture_lease(&fresh)
                .expect("new generation admitted after compaction");
            // Tear the fresh lease down again so the next cycle starts clean.
            advance(base + 122_000);
            assert!(journal.expire_lease(&sandbox, 3, 1).expect("expire"));
            journal
                .finish_expiry(&journal.lease(&sandbox).unwrap())
                .expect("finish");
            let mut confirmed = confirmation(&journal.lookup(&fresh.operation_id).unwrap());
            confirmed.cleanup_generation = Some(4);
            assert!(journal.confirm(&binding, &confirmed).expect("confirm"));
            // With expiry already settled, confirmation alone reclaims the
            // record — no heartbeat tick required.
            assert!(
                journal.lease(&sandbox).is_none(),
                "confirmation compacts a settled lease"
            );
        }
        assert!(journal.leases().is_empty(), "no lifetime accumulation");
        drop(journal);
        // Compaction is durable across reopen.
        let journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).expect("reopen");
        assert!(journal.leases().is_empty());
        let watermarks = journal.cleanup_generations(&binding).unwrap();
        for cycle in 0..3u64 {
            assert_eq!(watermarks[&format!("sbx-churn-{cycle}")], 4);
        }
        drop(journal);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn cleanup_watermark_survives_confirmation_and_crash_before_unlink() {
        use super::super::live_admission::LiveSandboxAdmission;
        for (kind, end_state) in [
            ("sandbox.stop", "stopped"),
            ("sandbox.stop", "absent"),
            ("sandbox.kill", "deleted"),
        ] {
            for crash in [false, true] {
                let dir = tempfile::tempdir().unwrap();
                let journal =
                    crate::sandbox_relay::test_support::open_journal(dir.path(), &binding())
                        .unwrap();
                let mut old = receipt("old", 1);
                old.kind = "sandbox.create".into();
                old.generation = 1;
                journal.record_intent(&old).unwrap();
                journal.record_effect("old").unwrap();
                journal
                    .record_result("old", OperationState::UnknownOutcome, None, None, None)
                    .unwrap();
                let mut cleanup = receipt("cleanup", 1);
                cleanup.kind = kind.into();
                journal.record_intent(&cleanup).unwrap();
                journal
                    .record_result(
                        "cleanup",
                        OperationState::Succeeded,
                        Some(json!({"state":end_state})),
                        None,
                        None,
                    )
                    .unwrap();
                if crash {
                    journal.inject_crash(CrashPoint::AfterCleanupWatermark);
                }
                let confirmed = journal.confirm(&binding(), &confirmation(&cleanup));
                if crash {
                    assert!(confirmed.is_err());
                } else {
                    assert!(confirmed.unwrap());
                }
                drop(journal);
                let journal =
                    crate::sandbox_relay::test_support::open_journal(dir.path(), &binding())
                        .unwrap();
                assert_eq!(journal.lookup("cleanup").is_some(), crash);
                assert_eq!(journal.cleanup_generations(&binding()).unwrap()["sbx-1"], 2);
                assert!(journal.lookup("old").is_some());
                // A watermark suppresses old uncertainty, never current census.
                let mut slots = LiveSandboxAdmission::new(
                    1,
                    crate::sandbox_relay::live_admission::test_capacity(),
                );
                slots.rebuild(&[], &journal, &binding()).unwrap();
                assert_eq!(slots.held(), 0);
                slots
                    .rebuild(
                        &[sandbox_runtime::RuntimeInventoryEntry {
                            sandbox_id: "sbx-1".into(),
                            state: sandbox_protocol::SandboxLifecycleState::Ready,
                            configured_size: sandbox_runtime::ConfiguredSize::Configured(
                                sandbox_protocol::VmSize::defaults().unwrap(),
                            ),
                        }],
                        &journal,
                        &binding(),
                    )
                    .unwrap();
                assert_eq!(slots.held(), 1);
                let mut later = receipt("later", 1);
                later.kind = "sandbox.reconnect".into();
                later.generation = 3;
                journal.record_intent(&later).unwrap();
                journal.record_effect("later").unwrap();
                slots.rebuild(&[], &journal, &binding()).unwrap();
                assert_eq!(slots.held(), 1, "later allocation must remain reserved");
            }
        }
    }

    #[test]
    fn unknown_retirement_requires_exact_cleanup_bound_confirmation() {
        let dir = tempfile::tempdir().unwrap();
        let journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        let mut old = receipt("old", 1);
        old.kind = "sandbox.create".into();
        journal.record_intent(&old).unwrap();
        journal.record_effect("old").unwrap();
        journal
            .record_result("old", OperationState::UnknownOutcome, None, None, None)
            .unwrap();
        let mut confirmed = confirmation(&old);
        assert!(!journal.confirm(&binding(), &confirmed).unwrap());
        confirmed.cleanup_generation = Some(old.generation);
        assert!(!journal.confirm(&binding(), &confirmed).unwrap());
        confirmed.cleanup_generation = Some(old.generation + 1);
        confirmed.body_hash = "b".repeat(64);
        assert!(!journal.confirm(&binding(), &confirmed).unwrap());
        assert!(journal.cleanup_generations(&binding()).unwrap().is_empty());
        confirmed.body_hash = old.request_hash.unwrap();
        assert!(journal.confirm(&binding(), &confirmed).unwrap());
        assert!(journal.lookup("old").is_none());
        assert!(
            journal.record_effect("old").is_err(),
            "late producer cannot recreate intent"
        );
        drop(journal);
        let journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        assert_eq!(journal.cleanup_generations(&binding()).unwrap()["sbx-1"], 3);
        drop(journal);
        let mut foreign = binding();
        foreign.host_owner_id = "foreign".into();
        assert!(
            crate::sandbox_relay::test_support::open_journal(dir.path(), &foreign).is_err(),
            "watermark alone binds the journal"
        );
    }

    #[test]
    fn lifecycle_retention_preserves_evidence_by_count_age_and_size() {
        let cases: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../../../../crates/sandbox-protocol/fixtures/cleanup_retention.json"
        ))
        .unwrap();
        for mode in ["count", "age", "size", "envelope"] {
            for case in &cases {
                let dir = tempfile::tempdir().unwrap();
                let mut cleanup = receipt("cleanup", 1);
                cleanup.kind = case["kind"].as_str().unwrap().into();
                // Escaped metadata approaches the envelope bound without making
                // any individual binding field invalid.
                if mode == "envelope" {
                    cleanup.server = "\u{1}".repeat(RECEIPT_LIMITS.server_bytes);
                    cleanup.idempotency_key = "\u{1}".repeat(RECEIPT_LIMITS.idempotency_key_bytes);
                }
                let cleanup_binding = TransportBindingV11 {
                    server: cleanup.server.clone(),
                    ..binding()
                };
                let journal =
                    crate::sandbox_relay::test_support::open_journal(dir.path(), &cleanup_binding)
                        .unwrap();
                journal.record_intent(&cleanup).unwrap();
                let mut payload = case["result"].clone();
                if mode == "size" {
                    payload["stdout"] = json!("x".repeat(RECEIPT_LIMITS.result_bytes + 1));
                }
                if mode == "envelope" {
                    payload["stdout"] = json!("x".repeat(RECEIPT_LIMITS.result_bytes - 200));
                }
                let mut stored = journal
                    .record_result(
                        "cleanup",
                        OperationState::Succeeded,
                        Some(payload),
                        Some(SandboxErrorCode::Internal),
                        Some(if mode == "envelope" {
                            "\u{1}".repeat(RECEIPT_LIMITS.error_bytes)
                        } else {
                            "retained error".into()
                        }),
                    )
                    .unwrap();
                if mode == "age" || mode == "count" {
                    // Persist a deterministic older timestamp; no clock sleeps.
                    stored.written_at_unix_ms = if mode == "age" { 0 } else { now_ms() - 1000 };
                    persist_receipt(&journal.io, &journal.receipts_dir, &stored).unwrap();
                }
                drop(journal);
                let reopen_binding = TransportBindingV11 {
                    server: cleanup.server.clone(),
                    ..binding()
                };
                let journal =
                    crate::sandbox_relay::test_support::open_journal(dir.path(), &reopen_binding)
                        .unwrap();
                if mode == "count" {
                    for i in 0..MAX_COMPLETED_RECEIPTS {
                        let r = receipt(&format!("later-{i}"), 1);
                        journal.record_intent(&r).unwrap();
                        journal
                            .record_result(
                                &r.operation_id,
                                OperationState::Succeeded,
                                Some(json!({"stdout":"later"})),
                                None,
                                None,
                            )
                            .unwrap();
                    }
                }
                let retained = journal.lookup("cleanup").unwrap();
                assert_eq!(retained.state, OperationState::Succeeded);
                assert_eq!(retained.error_code, Some(SandboxErrorCode::Internal.into()));
                let mut expected = case["retained"].clone();
                if mode == "size" || mode == "envelope" {
                    expected.as_object_mut().unwrap().remove("outputExpired");
                    expected["truncated"] = json!(true);
                    expected["retainedBytes"] = json!(0);
                }
                assert_eq!(retained.result, Some(expected), "{mode}: {case}");
            }
        }
    }

    #[test]
    fn targeted_attestation_full_journal_survives_crash_reopen() {
        use crate::sandbox_relay::reconcile::inventory_census;
        let dir = crate::sandbox_relay::test_support::journal_capacity_dir();
        let journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        for i in 0..MAX_RECEIPTS {
            let mut r = receipt(&format!("pending-{i}"), 1);
            if i == CREATOR_MAX_RECEIPTS {
                r.sandbox_owner_id = "other".into();
            }
            r.kind = "sandbox.create".into();
            r.sandbox_id = format!("pending-{i:04}");
            assert!(matches!(
                journal.record_intent(&r).unwrap(),
                Decision::Fresh
            ));
        }
        let mut refused = receipt("full-refusal", 1);
        refused.kind = "sandbox.create".into();
        refused.sandbox_id = "never-issued".into();
        assert!(matches!(
            journal.record_intent(&refused).unwrap(),
            Decision::Capacity
        ));
        let identity = journal.instance_id().to_owned();
        // No settlement is manufactured from an issued/unknown receipt. A
        // crashed queued allocation is a blocker even without a lease or VM.
        drop(journal);
        let reopened =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        assert_eq!(reopened.instance_id(), identity);
        let fresh_dir = tempfile::tempdir().unwrap();
        let fresh =
            crate::sandbox_relay::test_support::open_journal(fresh_dir.path(), &binding()).unwrap();
        assert_ne!(
            fresh.instance_id(),
            identity,
            "a different session journal supplies no continuity proof"
        );
        assert_eq!(
            reopened.never_issued(&["pending-0000".into(), "never-issued".into()]),
            [false, true]
        );
        let census = inventory_census(
            &reopened,
            &sandbox_runtime::FakeRuntime::new(),
            &Default::default(),
        )
        .unwrap();
        assert!(
            census.is_empty(),
            "receipts never change the general census"
        );
        assert!(matches!(
            reopened.record_intent(&refused).unwrap(),
            Decision::Capacity
        ));
    }

    #[test]
    fn targeted_attestation_lease_without_receipt_is_not_settled() {
        let dir = tempfile::tempdir().unwrap();
        let journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        let create: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner",
            "operationId":"leased", "sandboxId":"leased", "kind":"sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(),
            "generation":1, "attempt":1, "idempotencyKey":"leased", "bodyHash":"a".repeat(64),
            "lease":{"revision":1,"deadlineUnixMs":now_ms()+3_600_000,"action":"stop","expiryPolicy":"retry-force-60s"}
        })).unwrap();
        journal
            .record_intent(&intent_from_dispatch(&journal, &binding(), &create))
            .unwrap();
        journal.accept_fixture_lease(&create).unwrap();
        journal.state.lock().unwrap().receipts.remove("leased");
        assert_eq!(
            journal.never_issued(&["leased".into(), "never".into()]),
            [false, true]
        );
    }

    #[test]
    fn targeted_attestation_history_over_65536_and_distinct_inflight_blockers() {
        use crate::sandbox_relay::reconcile::inventory_census;
        let dir = tempfile::tempdir().unwrap();
        let journal = std::sync::Arc::new(
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap(),
        );
        let watermark = CleanupWatermark {
            sandbox_owner_id: "owner".into(),
            version: JOURNAL_VERSION,
            binding: binding(),
            sandbox_id: "history".into(),
            generation: 2,
            instance_absent: true,
            ext: JournalExt::new(),
        };
        persist_cleanup(&journal.io, &journal.cleanups_dir, &watermark).unwrap();
        {
            let mut state = journal.state.lock().unwrap();
            state.cleanups.insert("history".into(), watermark.clone());
            for i in 0..65_537 {
                state
                    .cleanups
                    .insert(format!("history-{i}"), watermark.clone());
            }
            state.lease_workers.insert("inflight".into(), 1);
        }
        let mut queued = receipt("queued", 1);
        queued.kind = "sandbox.reconnect".into();
        queued.sandbox_id = "queued".into();
        journal.record_intent(&queued).unwrap();
        let ids = ["history", "inflight", "queued", "never"].map(str::to_owned);
        let snapshot = journal.never_issued(&ids);
        assert_eq!(snapshot, [false, false, false, true]);
        let j = journal.clone();
        let runtime = sandbox_runtime::FakeRuntime::new().with_inventory_hook(move |_| {
            let mut state = j.state.lock().unwrap();
            state.lease_workers.remove("inflight");
            state.receipts.remove("queued");
            Ok(())
        });
        assert!(
            inventory_census(&journal, &runtime, &Default::default())
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            snapshot,
            [false, false, false, true],
            "snapshot preceded runtime IO"
        );
        drop(runtime);
        drop(journal);
        let reopened =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        assert_eq!(
            reopened.never_issued(&["history".into(), "never".into()]),
            [false, true]
        );
    }

    #[test]
    fn confirmed_4096_frees_capacity_unconfirmed_retained_and_stop_uses_reserve() {
        let dir = crate::sandbox_relay::test_support::journal_capacity_dir();
        let journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        for i in 0..MAX_RECEIPTS {
            let mut r = receipt(&format!("confirmed-{i}"), 1);
            if i == CREATOR_MAX_RECEIPTS {
                r.sandbox_owner_id = "other".into();
                r.sandbox_id = "other-sandbox".into();
            }
            journal.record_intent(&r).unwrap();
            journal
                .record_result(&r.operation_id, OperationState::Succeeded, None, None, None)
                .unwrap();
        }
        assert!(matches!(
            journal.record_intent(&receipt("ordinary-full", 1)).unwrap(),
            Decision::Capacity
        ));
        let mut stop = receipt("stop-reserve", 1);
        stop.kind = "sandbox.stop".into();
        assert!(matches!(
            journal.record_intent(&stop).unwrap(),
            Decision::Fresh
        ));
        // Unconfirmed/unknown receipts cannot be reclaimed, even by a matching confirmation.
        assert!(!journal.confirm(&binding(), &confirmation(&stop)).unwrap());
        journal
            .record_result(
                &stop.operation_id,
                OperationState::UnknownOutcome,
                None,
                Some(SandboxErrorCode::UnknownOutcome),
                None,
            )
            .unwrap();
        assert!(!journal.confirm(&binding(), &confirmation(&stop)).unwrap());
        let first = journal.lookup("confirmed-0").unwrap();
        let mut foreign = confirmation(&first);
        foreign.body_hash = "b".repeat(64);
        assert!(!journal.confirm(&binding(), &foreign).unwrap());
        drop(journal);
        let journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        assert_eq!(
            journal.matching(&binding()).unwrap().len(),
            MAX_RECEIPTS + 1
        );
        for i in 0..MAX_RECEIPTS {
            let r = journal.lookup(&format!("confirmed-{i}")).unwrap();
            assert!(journal.confirm(&binding(), &confirmation(&r)).unwrap());
            assert!(
                journal
                    .record_result(&r.operation_id, OperationState::Failed, None, None, None)
                    .is_err(),
                "late writer must not resurrect deleted receipt"
            );
        }
        assert_eq!(journal.matching(&binding()).unwrap().len(), 1);
        assert!(matches!(
            journal.record_intent(&receipt("fresh", 1)).unwrap(),
            Decision::Fresh
        ));
        drop(journal);
        let journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        assert_eq!(journal.matching(&binding()).unwrap().len(), 2);
        assert!(journal.lookup("stop-reserve").is_some());
    }
    #[test]
    fn paired_admission_bounds_prevent_poisoned_restart() {
        let cases: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../../../../crates/sandbox-protocol/fixtures/receipt_bound_cases.json"
        ))
        .unwrap();
        for case in cases {
            let dir = tempfile::tempdir().unwrap();
            let journal =
                crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
            let mut r = receipt("bounded", 1);
            let value = case["value"].as_str().unwrap().to_string();
            match case["field"].as_str().unwrap() {
                "bodyHash" => r.request_hash = Some(value),
                "idempotencyKey" => r.idempotency_key = value,
                "kind" => r.kind = value,
                _ => unreachable!(),
            }
            assert_eq!(
                journal.record_intent(&r).is_ok(),
                case["valid"].as_bool().unwrap(),
                "{case}"
            );
            drop(journal);
            let reopened =
                crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
            assert_eq!(
                reopened.lookup("bounded").is_some(),
                case["valid"].as_bool().unwrap()
            );
        }
        let dir = tempfile::tempdir().unwrap();
        let journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        let mut r = receipt("oversized", 1);
        r.request_hash = Some("x".repeat(60 * 1024));
        assert!(journal.record_intent(&r).is_err());
        assert!(!dir.path().join("receipts/oversized.json").exists());
        // A checksummed but semantically invalid on-disk record is rejected too.
        let raw = receipt_envelope_bytes(&r).unwrap();
        fs::write(dir.path().join("receipts/oversized.json"), raw).unwrap();
        drop(journal);
        assert!(crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).is_err());
    }
    #[test]
    fn completion_owner_serializes_competing_producers_and_confirmation() {
        let dir = tempfile::tempdir().unwrap();
        let journal = std::sync::Arc::new(
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap(),
        );
        let r = receipt("race", 1);
        journal.record_intent(&r).unwrap();
        journal.record_effect("race").unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let workers: Vec<_> = [OperationState::Succeeded, OperationState::Failed]
            .into_iter()
            .map(|state| {
                let journal = journal.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    journal
                        .record_result("race", state, None, None, None)
                        .unwrap()
                        .state
                })
            })
            .collect();
        barrier.wait();
        let states: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
        assert_eq!(states[0], states[1]);
        assert!(journal.confirm(&binding(), &confirmation(&r)).unwrap());
    }
    fn typed_content(id: &str) -> HostReceipt {
        let mut r = receipt(id, 1);
        r.kind = "file.stat".into();
        r.content_deadline_unix_ms = Some(0);
        r
    }
    fn typed_stat() -> serde_json::Value {
        serde_json::json!({"version":1,"observedAt":"2026-10-27T00:00:00.000Z","payload":{"type":"file.stat","entry":{"name":"x","path":"/x","type":"file","size":1,"mode":420,"permissions":"rw-r--r--","uid":1000,"gid":1000,"owner":null,"group":null,"modifiedTime":null,"symlinkTarget":null}},"continuation":null,"birth":null,"failure":null})
    }
    #[test]
    fn typed_slots_reserve_before_effect_and_only_exact_confirmation_releases() {
        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        for i in 0..64 {
            let r = typed_content(&format!("content-{i}"));
            assert!(matches!(j.record_intent(&r).unwrap(), Decision::Fresh));
            j.record_effect(&r.operation_id).unwrap();
            j.record_result(
                &r.operation_id,
                OperationState::Succeeded,
                Some(typed_stat()),
                None,
                None,
            )
            .unwrap();
        }
        assert!(matches!(
            j.record_intent(&typed_content("sixty-fifth")).unwrap(),
            Decision::Capacity
        ));
        assert!(j.lookup("sixty-fifth").is_none());
        // Scalar/cleanup work must still admit when content is full.
        assert!(matches!(
            j.record_intent(&receipt("scalar", 1)).unwrap(),
            Decision::Fresh
        ));
        for i in 0..70 {
            let mut r = receipt(&format!("transfer-result-{i}"), 1);
            r.kind = "file.get".into();
            j.record_intent(&r).unwrap();
            j.record_result(
                &r.operation_id,
                OperationState::Succeeded,
                Some(serde_json::json!({"path":"/download", "size":70})),
                None,
                None,
            )
            .unwrap();
        }
        j.maintain().unwrap();
        drop(j);
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        for i in 0..64 {
            assert_eq!(
                j.lookup(&format!("content-{i}")).unwrap().result,
                Some(typed_stat())
            );
        }
        let original = j.lookup("content-0").unwrap();
        let mut wrong = confirmation(&original);
        wrong.attempt = 2;
        assert!(!j.confirm(&binding(), &wrong).unwrap());
        assert!(matches!(
            j.record_intent(&typed_content("sixty-fifth")).unwrap(),
            Decision::Capacity
        ));
        assert!(j.confirm(&binding(), &confirmation(&original)).unwrap());
        assert!(matches!(
            j.record_intent(&typed_content("sixty-fifth")).unwrap(),
            Decision::Fresh
        ));
    }
    #[test]
    fn typed_crash_points_never_reissue_and_expiry_is_fixed_across_reopen() {
        for crash in [
            CrashPoint::AfterIntent,
            CrashPoint::AfterEffect,
            CrashPoint::BeforeResult,
            CrashPoint::AfterResult,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let j =
                crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
            let r = typed_content("crashed");
            j.inject_crash(crash);
            let intent = j.record_intent(&r);
            if crash != CrashPoint::AfterIntent {
                intent.unwrap();
                let issue = j.record_effect("crashed");
                if crash != CrashPoint::AfterEffect {
                    issue.unwrap();
                    let saved = j.record_result(
                        "crashed",
                        OperationState::Succeeded,
                        Some(typed_stat()),
                        None,
                        None,
                    );
                    if crash == CrashPoint::BeforeResult || crash == CrashPoint::AfterResult {
                        assert!(saved.is_err());
                    }
                }
            } else {
                assert!(intent.is_err());
            }
            let deadline = j.lookup("crashed").unwrap().content_deadline_unix_ms;
            drop(j);
            let j =
                crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
            assert!(!matches!(j.record_intent(&r).unwrap(), Decision::Fresh));
            assert_eq!(
                j.lookup("crashed").unwrap().content_deadline_unix_ms,
                deadline
            );
            // Expire the fixed reservation, including an uncertain Intent.
            {
                let mut state = j.state.lock().unwrap();
                let r = state.receipts.get_mut("crashed").unwrap();
                r.content_deadline_unix_ms = Some(1);
                persist_receipt(&j.io, &j.receipts_dir, r).unwrap();
            }
            j.maintain().unwrap();
            drop(j);
            let j =
                crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
            let expired = j.lookup("crashed").unwrap();
            assert_eq!(expired.result.as_ref().unwrap()["resultExpired"], true);
            assert!(expired.result.as_ref().unwrap()["payload"].is_null());
            let late = j
                .record_result(
                    "crashed",
                    OperationState::Succeeded,
                    Some(typed_stat()),
                    None,
                    None,
                )
                .unwrap();
            assert!(late.result.unwrap()["payload"].is_null());
        }
    }
    #[test]
    fn typed_scalar_and_birth_survive_count_age_byte_and_digest_pruning() {
        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        let r = receipt("birth-evidence", 1);
        j.record_intent(&r).unwrap();
        let mut birth: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../crates/sandbox-protocol/fixtures/process_started.json"
        ))
        .unwrap();
        birth["operationId"] = serde_json::json!(r.operation_id);
        birth["sandboxId"] = serde_json::json!(r.sandbox_id);
        birth["generation"] = serde_json::json!(2);
        let body = serde_json::json!({"version":1,"observedAt":birth["observedAt"],"payload":{"type":"command","process":{"sandboxId":r.sandbox_id,"generation":2,"processId":birth["processId"],"attempt":1,"pid":birth["pid"]},"startedAt":birth["startedAt"],"exitCode":7},"birth":birth,"continuation":null,"failure":null,"outputBytes":5});
        j.record_result(
            &r.operation_id,
            OperationState::Succeeded,
            Some(body.clone()),
            None,
            None,
        )
        .unwrap();
        for i in 0..70 {
            let r = receipt(&format!("old-{i}"), 1);
            j.record_intent(&r).unwrap();
            j.record_result(
                &r.operation_id,
                OperationState::Succeeded,
                Some(serde_json::json!({"path":"/download", "size":70})),
                None,
                None,
            )
            .unwrap();
        }
        {
            let mut state = j.state.lock().unwrap();
            let r = state.receipts.get_mut("birth-evidence").unwrap();
            r.written_at_unix_ms = 1;
            persist_receipt(&j.io, &j.receipts_dir, r).unwrap();
        }
        j.maintain().unwrap();
        let r = j.lookup("birth-evidence").unwrap();
        assert_eq!(r.result, Some(body.clone()));
        assert_eq!(r.clone().into_digest_pruned().result, Some(body.clone()));
        assert_eq!(truncate_result(Some(body.clone())), Some(body.clone()));
        drop(j);
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        assert_eq!(j.lookup("birth-evidence").unwrap().result, Some(body));
    }
    #[test]
    fn typed_confirmation_crashes_leave_replayable_content_or_durable_deletion() {
        for point in [
            CrashPoint::BeforeReceiptDelete,
            CrashPoint::AfterReceiptDelete,
            CrashPoint::AfterReceiptDirectorySync,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let j =
                crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
            let r = typed_content("confirmed-content");
            j.record_intent(&r).unwrap();
            let stored = j
                .record_result(
                    &r.operation_id,
                    OperationState::Succeeded,
                    Some(typed_stat()),
                    None,
                    None,
                )
                .unwrap();
            // Lost ACK/send: reopen still supplies exactly the original page.
            drop(j);
            let j =
                crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
            assert!(matches!(j.record_intent(&r).unwrap(), Decision::Replay(_)));
            j.inject_crash(point);
            assert!(j.confirm(&binding(), &confirmation(&stored)).is_err());
            drop(j);
            let j =
                crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
            if point == CrashPoint::BeforeReceiptDelete {
                assert_eq!(j.lookup(&r.operation_id).unwrap().result, stored.result);
            } else {
                assert!(j.lookup(&r.operation_id).is_none());
            }
        }
    }
    #[test]
    fn typed_mkdir_remove_and_signal_scalars_never_consume_or_expire_content() {
        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        let process = serde_json::json!({"sandboxId":"sbx-1","generation":2,"processId":"process","attempt":1,"pid":42});
        let cases = [
            (
                "file.mkdir",
                serde_json::json!({"type":"file.mkdir","created":false}),
            ),
            (
                "file.remove",
                serde_json::json!({"type":"file.remove","removed":true}),
            ),
            (
                "process.signal",
                serde_json::json!({"type":"process.signal","process":process,"targetOperationId":"command","signal":"SIGTERM","accepted":true,"delivery":"process_group"}),
            ),
        ];
        let mut expected = Vec::new();
        for (index, (kind, payload)) in cases.into_iter().enumerate() {
            let mut r = receipt(&format!("scalar-{index}"), 1);
            r.kind = kind.into();
            j.record_intent(&r).unwrap();
            let body = serde_json::json!({"version":1,"observedAt":"2026-10-27T00:00:00.000Z","payload":payload,"continuation":null,"birth":null,"failure":null});
            let stored = j
                .record_result(
                    &r.operation_id,
                    OperationState::Succeeded,
                    Some(body.clone()),
                    None,
                    None,
                )
                .unwrap();
            assert!(stored.content_deadline_unix_ms.is_none());
            assert_eq!(
                stored.clone().into_digest_pruned().result,
                Some(body.clone())
            );
            assert_eq!(
                retain_result_evidence(&body, serde_json::json!({"truncated":true})),
                body
            );
            {
                let mut state = j.state.lock().unwrap();
                let row = state.receipts.get_mut(&r.operation_id).unwrap();
                row.written_at_unix_ms = 1;
                persist_receipt(&j.io, &j.receipts_dir, row).unwrap();
            }
            expected.push((r.operation_id, body));
        }
        j.maintain().unwrap();
        drop(j);
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        for (id, body) in expected {
            assert_eq!(j.lookup(&id).unwrap().result, Some(body));
        }
    }
    #[test]
    fn typed_recovery_preserves_birth_and_rejects_conflicting_rebinding() {
        for with_payload in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let j =
                crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
            let mut r = receipt("operation", 1);
            r.sandbox_id = "sandbox".into();
            r.generation = 1;
            j.record_intent(&r).unwrap();
            let cases: serde_json::Value = serde_json::from_str(include_str!(
                "../../../../crates/sandbox-protocol/fixtures/host_results.json"
            ))
            .unwrap();
            let body = cases
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["name"] == "command-birth")
                .unwrap()["value"]
                .clone();
            let mut body = body;
            if !with_payload {
                body["payload"] = serde_json::Value::Null;
            }
            j.record_result(
                "operation",
                OperationState::UnknownOutcome,
                Some(body.clone()),
                Some(SandboxErrorCode::UnknownOutcome),
                None,
            )
            .unwrap();
            j.record_reconciled_result(
                "operation",
                OperationState::UnknownOutcome,
                None,
                None,
                None,
            )
            .unwrap();
            assert_eq!(j.lookup("operation").unwrap().result, Some(body.clone()));
            let mut conflict = body.clone();
            conflict["birth"]["pid"] = serde_json::json!(124);
            if with_payload {
                conflict["payload"]["process"]["pid"] = serde_json::json!(124);
            }
            assert!(
                j.record_result(
                    "operation",
                    OperationState::Succeeded,
                    Some(conflict),
                    None,
                    None
                )
                .is_err()
            );
            let mut conflict = body.clone();
            conflict["birth"] = serde_json::Value::Null;
            conflict["payload"] = serde_json::json!({"type":"command","process":{"sandboxId":"sandbox","generation":1,"processId":"process","attempt":1,"pid":124},"startedAt":"2026-10-27T00:00:00.000Z","exitCode":7});
            assert!(
                j.record_result(
                    "operation",
                    OperationState::Succeeded,
                    Some(conflict),
                    None,
                    None
                )
                .is_err()
            );
            drop(j);
            let j =
                crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
            assert_eq!(j.lookup("operation").unwrap().result, Some(body));
        }
    }
    #[test]
    fn typed_journal_rejects_invalid_guest_content_before_any_receipt_write() {
        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        let r = typed_content("invalid-content");
        j.record_intent(&r).unwrap();
        for mut invalid in [typed_stat(), typed_stat(), typed_stat()]
            .into_iter()
            .enumerate()
        {
            match invalid.0 {
                0 => invalid.1["payload"] = serde_json::json!({"type":"file.mkdir","created":true}),
                1 => invalid.1["version"] = serde_json::json!(2),
                _ => invalid.1["private"] = serde_json::json!("sentinel"),
            };
            assert!(
                j.record_result(
                    &r.operation_id,
                    OperationState::Succeeded,
                    Some(invalid.1),
                    None,
                    None
                )
                .is_err()
            );
            assert_eq!(j.lookup(&r.operation_id).unwrap().result, None);
        }
        drop(j);
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        assert_eq!(
            j.lookup(&r.operation_id).unwrap().phase,
            ReceiptPhase::Intent
        );
    }
    fn receipt_message(r: HostReceipt) -> sandbox_protocol::DaemonControlMessage {
        sandbox_protocol::DaemonControlMessage::OperationReceipt {
            sandbox_owner_id: "owner".into(),
            operation_id: r.operation_id.clone(),
            sandbox_id: r.sandbox_id.clone(),
            generation: r.generation,
            attempt: r.attempt,
            body_hash: r.server_request_hash().unwrap().into(),
            idempotency_key: r.idempotency_key,
            kind: r.kind,
            state: r.state,
            result: r.result,
            error: None,
            launch_mode: None,
        }
    }
    #[test]
    fn typed_deadline_is_fixed_from_intent_through_every_write_send_replay_and_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        let r = typed_content("fixed-deadline");
        j.record_intent(&r).unwrap();
        let deadline = j.lookup(&r.operation_id).unwrap().content_deadline_unix_ms;
        assert!(deadline.is_some());
        // Distinct clock sample makes a refresh-to-now mutation observable.
        std::thread::sleep(std::time::Duration::from_millis(5));
        j.record_effect(&r.operation_id).unwrap();
        assert_eq!(
            j.lookup(&r.operation_id).unwrap().content_deadline_unix_ms,
            deadline
        );
        j.record_result(
            &r.operation_id,
            OperationState::UnknownOutcome,
            Some(typed_stat()),
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            j.lookup(&r.operation_id).unwrap().content_deadline_unix_ms,
            deadline
        );
        j.record_reconciled_result(
            &r.operation_id,
            OperationState::UnknownOutcome,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            j.lookup(&r.operation_id).unwrap().content_deadline_unix_ms,
            deadline
        );
        let done = j
            .record_result(
                &r.operation_id,
                OperationState::Succeeded,
                Some(typed_stat()),
                None,
                None,
            )
            .unwrap();
        assert_eq!(done.content_deadline_unix_ms, deadline);
        let frame = receipt_message(done);
        let encoded = sandbox_protocol::WireCodes::negotiated("1.0")
            .encode(&frame, None)
            .unwrap();
        assert!(sandbox_protocol::parse_daemon_control(&encoded.text).is_ok());
        assert_eq!(
            j.lookup(&r.operation_id).unwrap().content_deadline_unix_ms,
            deadline
        );
        assert!(matches!(j.record_intent(&r).unwrap(), Decision::Replay(_)));
        j.matching(&binding()).unwrap();
        j.maintain().unwrap();
        assert_eq!(
            j.lookup(&r.operation_id).unwrap().content_deadline_unix_ms,
            deadline
        );
        drop(j);
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        assert_eq!(
            j.lookup(&r.operation_id).unwrap().content_deadline_unix_ms,
            deadline
        );
    }
    #[test]
    fn typed_expired_intent_releases_content_capacity_without_reissuing() {
        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        for i in 0..sandbox_protocol::results::HOST_CONTENT_MAX_SLOTS {
            assert!(matches!(
                j.record_intent(&typed_content(&format!("slot-{i}")))
                    .unwrap(),
                Decision::Fresh
            ));
        }
        let extra = typed_content("extra");
        assert!(matches!(
            j.record_intent(&extra).unwrap(),
            Decision::Capacity
        ));
        {
            let mut state = j.state.lock().unwrap();
            let first = state.receipts.get_mut("slot-0").unwrap();
            first.content_deadline_unix_ms = Some(1);
            persist_receipt(&j.io, &j.receipts_dir, first).unwrap();
        }
        assert!(matches!(j.record_intent(&extra).unwrap(), Decision::Fresh));
        let first = j.lookup("slot-0").unwrap();
        assert_eq!(first.phase, ReceiptPhase::Intent);
        assert_eq!(first.result.as_ref().unwrap()["resultExpired"], true);
        assert!(matches!(
            j.record_intent(&typed_content("slot-0")).unwrap(),
            Decision::Unknown(_)
        ));
        drop(j);
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        assert_eq!(j.lookup("slot-0").unwrap().result, first.result);
    }
    #[test]
    fn typed_confirmation_retry_after_unlink_failure_releases_slot_in_same_process() {
        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        for i in 0..sandbox_protocol::results::HOST_CONTENT_MAX_SLOTS {
            j.record_intent(&typed_content(&format!("slot-{i}")))
                .unwrap();
        }
        let done = j
            .record_result(
                "slot-0",
                OperationState::Succeeded,
                Some(typed_stat()),
                None,
                None,
            )
            .unwrap();
        assert!(matches!(
            j.record_intent(&typed_content("extra")).unwrap(),
            Decision::Capacity
        ));
        j.inject_crash(CrashPoint::AfterReceiptDelete);
        assert!(j.confirm(&binding(), &confirmation(&done)).is_err());
        assert!(j.lookup("slot-0").is_some());
        *j.crash.lock().unwrap() = None;
        assert!(j.confirm(&binding(), &confirmation(&done)).unwrap());
        assert!(j.lookup("slot-0").is_none());
        assert!(matches!(
            j.record_intent(&typed_content("extra")).unwrap(),
            Decision::Fresh
        ));
    }
    #[test]
    fn typed_reconnect_inventory_prunes_expired_content_before_replay() {
        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        let r = typed_content("offline");
        j.record_intent(&r).unwrap();
        j.record_result(
            &r.operation_id,
            OperationState::Succeeded,
            Some(typed_stat()),
            None,
            None,
        )
        .unwrap();
        {
            let mut state = j.state.lock().unwrap();
            let r = state.receipts.get_mut("offline").unwrap();
            r.content_deadline_unix_ms = Some(1);
            persist_receipt(&j.io, &j.receipts_dir, r).unwrap();
        }
        // No reopen or maintain tick: this is the exact reconnect inventory API.
        let replay = j.matching(&binding()).unwrap().pop().unwrap();
        assert_eq!(replay.result.as_ref().unwrap()["resultExpired"], true);
        assert!(replay.result.as_ref().unwrap()["payload"].is_null());
        let encoded = sandbox_protocol::WireCodes::negotiated("1.0")
            .encode(&receipt_message(replay.clone()), None)
            .unwrap();
        let value: serde_json::Value = serde_json::from_str(&encoded.text).unwrap();
        assert_eq!(value["result"]["resultExpired"], true);
        drop(j);
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        assert_eq!(j.lookup("offline").unwrap().result, replay.result);
    }
    #[test]
    fn typed_max_encoded_payload_fits_persisted_receipt_and_control_frames() {
        use sandbox_protocol::results::{ResultKind, host::HostOperationResult};
        let limit = result_limits().unwrap().host_result_max_bytes;
        let dir = tempfile::tempdir().unwrap();
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        let mut r = typed_content("max-page");
        r.kind = "file.list".into();
        j.record_intent(&r).unwrap();
        let mut body = typed_stat();
        let template = body["payload"]["entry"].clone();
        let items: Vec<_> = (0..6)
            .map(|i| {
                let mut entry = template.clone();
                entry["name"] = serde_json::json!(format!("e{i}"));
                entry["path"] = serde_json::json!(format!("/d/e{i}"));
                entry["type"] = serde_json::json!("symlink");
                entry["symlinkTarget"] = serde_json::json!("");
                entry
            })
            .collect();
        body["payload"] = serde_json::json!({"type":"file.list","path":"/d","depth":1,"items":items,"nextCursor":null,"consistency":"live"});
        for i in 0..6 {
            let remaining = limit - serde_json::to_vec(&body).unwrap().len();
            body["payload"]["items"][i]["symlinkTarget"] =
                serde_json::json!("a".repeat(remaining.min(4096)));
        }
        assert_eq!(serde_json::to_vec(&body).unwrap().len(), limit);
        let typed: HostOperationResult = serde_json::from_value(body.clone()).unwrap();
        assert!(typed.validate(ResultKind::ListDir, &r.sandbox_id, r.generation as u32));
        let mut oversized = body.clone();
        let target = oversized["payload"]["items"][5]["symlinkTarget"]
            .as_str()
            .unwrap()
            .to_owned()
            + "a";
        oversized["payload"]["items"][5]["symlinkTarget"] = serde_json::json!(target);
        assert!(
            !serde_json::from_value::<HostOperationResult>(oversized.clone())
                .unwrap()
                .validate(ResultKind::ListDir, &r.sandbox_id, r.generation as u32)
        );
        assert!(
            j.record_result(
                &r.operation_id,
                OperationState::Succeeded,
                Some(oversized),
                None,
                None
            )
            .is_err()
        );
        let done = j
            .record_result(
                &r.operation_id,
                OperationState::Succeeded,
                Some(body.clone()),
                None,
                None,
            )
            .unwrap();
        assert!(receipt_envelope_bytes(&done).unwrap().len() <= RECEIPT_LIMITS.receipt_bytes);
        assert!(serde_json::to_vec(&body).unwrap().len() <= RECEIPT_LIMITS.result_bytes);
        let receipt_frame = receipt_message(done.clone());
        let live = sandbox_protocol::DaemonControlMessage::OperationResult {
            id: "result".into(),
            sandbox_id: done.sandbox_id.clone(),
            operation_id: done.operation_id.clone(),
            generation: done.generation,
            attempt: done.attempt,
            state: done.state,
            result: Some(body.clone()),
            error: None,
        };
        for frame in [live, receipt_frame] {
            let encoded = sandbox_protocol::WireCodes::negotiated("1.0")
                .encode(&frame, Some("file.list"))
                .unwrap();
            assert!(encoded.text.len() <= sandbox_protocol::json_control_max_bytes());
            assert!(sandbox_protocol::parse_daemon_control(&encoded.text).is_ok());
        }
        drop(j);
        let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding()).unwrap();
        assert_eq!(j.lookup(&r.operation_id).unwrap().result, Some(body));
    }
}

#[cfg(all(test, not(unix)))]
mod unsupported_tests {
    #[test]
    fn unsupported_durability_fails_before_creating_state() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("journal");
        let binding = super::TransportBindingV11 {
            server: "wss://example".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        };
        assert!(super::HostJournal::open(&path, &binding).is_err());
        assert!(!path.exists());
    }
}

#[cfg(test)]
mod capacity_reason_tests {
    use super::*;
    #[test]
    fn capacity_reason_survives_receipt_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let binding = TransportBindingV11 {
            server: "wss://reason.test/ws/sandbox-host".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        };
        let dispatch: OperationDispatch = serde_json::from_value(serde_json::json!({"sandboxOwnerId":"owner", "operationId":"capacity","sandboxId":"sbx","kind":"command.run","generation":1,"attempt":1,"idempotencyKey":"capacity","bodyHash":"a".repeat(64),"argv":["true"]})).unwrap();
        let journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap();
        journal
            .record_intent(&intent_from_dispatch(&journal, &binding, &dispatch))
            .unwrap();
        journal
            .record_result_with_reason(
                "capacity",
                OperationState::Failed,
                None,
                (
                    Some(SandboxErrorCode::HostCapacity.into()),
                    Some("Capacity".into()),
                    Some(sandbox_protocol::capacity_v11::CapacityReason::Disk.into()),
                ),
            )
            .unwrap();
        drop(journal);
        let journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap();
        let receipt = journal.lookup("capacity").unwrap();
        assert_eq!(
            receipt.capacity_reason,
            Some(sandbox_protocol::capacity_v11::CapacityReason::Disk)
        );
        validate_receipt(&receipt).unwrap();
    }

    #[test]
    fn egress_refusal_survives_receipt_reopen_and_binds_to_its_code() {
        use sandbox_protocol::EgressRefusalReason;
        let dir = tempfile::tempdir().unwrap();
        let binding = TransportBindingV11 {
            server: "wss://reason.test/ws/sandbox-host".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        };
        let journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap();
        for (id, code) in [
            ("egress", SandboxErrorCode::UnsupportedCapability),
            ("mismatch", SandboxErrorCode::Internal),
        ] {
            let dispatch: OperationDispatch = serde_json::from_value(serde_json::json!({"sandboxOwnerId":"owner", "operationId":id,"sandboxId":"sbx","kind":"command.run","generation":1,"attempt":1,"idempotencyKey":id,"bodyHash":"a".repeat(64),"argv":["true"]})).unwrap();
            journal
                .record_intent(&intent_from_dispatch(&journal, &binding, &dispatch))
                .unwrap();
            journal
                .record_result_with_reason(
                    id,
                    OperationState::Failed,
                    None,
                    (
                        Some(code.into()),
                        Some("refused".into()),
                        Some(EgressRefusalReason::OpenEgressNotPermitted.into()),
                    ),
                )
                .unwrap();
        }
        drop(journal);
        let journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap();
        let receipt = journal.lookup("egress").unwrap();
        assert_eq!(
            receipt.egress_refusal,
            Some(EgressRefusalReason::OpenEgressNotPermitted)
        );
        assert_eq!(
            receipt.error_reason(),
            Some(EgressRefusalReason::OpenEgressNotPermitted.into())
        );
        validate_receipt(&receipt).unwrap();
        let mismatch = journal.lookup("mismatch").unwrap();
        assert_eq!(mismatch.error_reason(), None);
    }

    #[test]
    fn readiness_reason_survives_receipt_reopen_and_binds_to_its_code() {
        use sandbox_protocol::ReadinessFailureReason;
        let dir = tempfile::tempdir().unwrap();
        let binding = TransportBindingV11 {
            server: "wss://reason.test/ws/sandbox-host".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        };
        let journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap();
        for (id, code) in [
            ("readiness", SandboxErrorCode::GuestUnavailable),
            ("mismatch", SandboxErrorCode::Internal),
        ] {
            let dispatch: OperationDispatch = serde_json::from_value(serde_json::json!({"sandboxOwnerId":"owner", "operationId":id,"sandboxId":"sbx","kind":"command.run","generation":1,"attempt":1,"idempotencyKey":id,"bodyHash":"a".repeat(64),"argv":["true"]})).unwrap();
            journal
                .record_intent(&intent_from_dispatch(&journal, &binding, &dispatch))
                .unwrap();
            journal
                .record_result_with_reason(
                    id,
                    OperationState::UnknownOutcome,
                    None,
                    (
                        Some(code.into()),
                        Some("readiness".into()),
                        Some(ReadinessFailureReason::GuestHome.into()),
                    ),
                )
                .unwrap();
        }
        drop(journal);
        let journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap();
        let receipt = journal.lookup("readiness").unwrap();
        assert_eq!(
            receipt.readiness_reason,
            Some(ReadinessFailureReason::GuestHome)
        );
        assert_eq!(
            receipt.error_reason(),
            Some(ReadinessFailureReason::GuestHome.into())
        );
        validate_receipt(&receipt).unwrap();
        let mismatch = journal.lookup("mismatch").unwrap();
        assert_eq!(mismatch.error_reason(), None);
    }
}
