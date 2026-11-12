//! Stopped-sandbox disk offload frames (additive within 1.0; offload ,
//! §8.6). Mirrors `packages/sandbox-contracts/src/image-wire.ts`;
//! `fixtures/control_disk.json` is the shared fixture.
//!
//! The server sends these frames, and the dispatch fields below, only to a
//! session whose hello advertised `diskOffload` (I10: the server deploys
//! before daemons). Every field added to an existing frame is optional and
//! omitted when absent, so a dispatch without them is byte-identical to one
//! from before this chunk. Disk images never appear in image cache frames
//! (S6): there is no disk cache origin.
//!
//! The upload grant carries the session's data key; it is redacted from
//! `Debug` and never journaled. A disk grant without encryption does not
//! parse (I13).

use serde::{Deserialize, Serialize};

use crate::image::{
    ImageEncryptionV11, ImageUploadPartUrlV11, ImageUploadedPartV11, valid_code, valid_id,
    valid_image_fingerprint, valid_size, valid_upload_part_urls, valid_uploaded_parts,
};
use crate::{RootObservation, RootState};

/// How a launch dispatch boots its root (`SandboxOperation.launchMode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchMode {
    /// A new root: every create, and a restore from a stored disk.
    NewRoot,
    /// A stopped VM is started on its retained root.
    Cold,
    /// The VM is already running.
    Warm,
}

impl LaunchMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NewRoot => "new_root",
            Self::Cold => "cold",
            Self::Warm => "warm",
        }
    }
}

/// `restore` on a `sandbox.reconnect`: boot a new root from the stored disk.
/// The dispatch's `image` (`source: fetch`) names the same fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DispatchRestoreV11 {
    pub offload_id: String,
    pub seq: u64,
    /// The worker-verified disk image fingerprint.
    pub fingerprint: String,
    /// The stored copy's `volatile.cloud-init.instance-id` (from
    /// `disk.upload.begin`), set on the restored instance so cloud-init does
    /// not re-run its first boot. Omitted when unknown.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::egress::present"
    )]
    pub cloud_init_instance_id: Option<String>,
}

/// `expectDisk` on a cold `sandbox.reconnect` (§8.1): the retained root must
/// be the one stored as offload `seq`; otherwise the daemon refuses
/// `disk_stale` without starting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DispatchExpectDiskV11 {
    pub seq: u64,
    pub fingerprint: String,
}

fn valid_seq(seq: u64) -> bool {
    seq > 0 && seq <= 9_007_199_254_740_991
}

fn valid_generation(generation: u64) -> bool {
    generation > 0 && generation <= 9_007_199_254_740_991
}

/// Dispatch-level disk rules (both encode and parse):
/// - `restore` rides only on `sandbox.reconnect`, with `launchMode:
///   new_root`, a `fetch` image of the same fingerprint, no `expectDisk`, no
///   build, and a `diskBaseFingerprint` (if any) equal to it;
/// - `launchMode` only on launches: a create is `new_root`, and a reconnect
///   is `new_root` exactly when it carries `restore`;
/// - `expectDisk` only on a cold reconnect (no `restore`);
/// - `diskBaseFingerprint` is a fingerprint (any binding dispatch).
pub(crate) fn valid_dispatch_disk_fields(d: &crate::OperationDispatch) -> bool {
    let reconnect = d.kind == "sandbox.reconnect";
    let restore_ok = d.restore.as_ref().is_none_or(|restore| {
        reconnect
            && valid_id(&restore.offload_id)
            && valid_seq(restore.seq)
            && valid_image_fingerprint(&restore.fingerprint)
            && restore
                .cloud_init_instance_id
                .as_deref()
                .is_none_or(valid_cloud_init_instance_id)
            && d.launch_mode == Some(LaunchMode::NewRoot)
            && d.expect_disk.is_none()
            && d.build.is_none()
            && d.image.as_ref().is_some_and(|image| {
                image.format == "unified"
                    && image.source == "fetch"
                    && image.fingerprint == restore.fingerprint
            })
            && d.disk_base_fingerprint
                .as_deref()
                .is_none_or(|base| base == restore.fingerprint)
    });
    let launch_ok = d.launch_mode.is_none_or(|mode| match d.kind.as_str() {
        "sandbox.create" => mode == LaunchMode::NewRoot && d.restore.is_none(),
        "sandbox.reconnect" => (mode == LaunchMode::NewRoot) == d.restore.is_some(),
        _ => false,
    });
    let expect_ok = d.expect_disk.as_ref().is_none_or(|expect| {
        reconnect
            && d.restore.is_none()
            && d.launch_mode.is_none_or(|mode| mode == LaunchMode::Cold)
            && valid_seq(expect.seq)
            && valid_image_fingerprint(&expect.fingerprint)
    });
    let base_ok = d
        .disk_base_fingerprint
        .as_deref()
        .is_none_or(valid_image_fingerprint);
    restore_ok && launch_ok && expect_ok && base_ok
}

/// Whether a dispatch carries any disk offload field (the daemon serves them
/// only once it advertises `diskOffload`).
pub fn dispatch_has_disk_fields(d: &crate::OperationDispatch) -> bool {
    d.restore.is_some()
        || d.launch_mode.is_some()
        || d.expect_disk.is_some()
        || d.disk_base_fingerprint.is_some()
}

/// A root-absence proof: the census root observation, reused (§7), which
/// must say `absent`. The server matches pool, marker and size.
fn valid_root_absence(proof: &RootObservation) -> bool {
    proof.state == RootState::Absent
        && !proof.storage_pool_name.is_empty()
        && proof.storage_pool_name.len() <= 63
        && valid_storage_marker(&proof.storage_marker)
        && crate::vm_root_charge_gi_b(proof.disk_gi_b).is_ok()
        && proof.observation_sequence <= 9_007_199_254_740_991
}

fn valid_storage_marker(marker: &str) -> bool {
    !marker.is_empty() && marker.len() <= 128
}

// ---------------------------------------------------------------- daemon → server

/// Why an offload failed on the host before or during its upload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiskOffloadFailureCode {
    /// The staging reservation did not fit after LRU eviction (F12).
    StagingFull,
    /// A daemon restart interrupted the export; retry under a new offload id.
    ExportInterrupted,
    /// Incus did not report the instance stopped.
    NotStopped,
    /// The instance is not on this host.
    InstanceMissing,
    /// The staged file no longer matches its hash at resume.
    Corrupt,
    Io,
    Timeout,
    Cancelled,
}

/// The export finished: request an upload session for it. The server
/// answers `disk.upload.grant` or `disk.offload.cancel`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiskUploadBeginV11 {
    pub sandbox_id: String,
    pub generation: u64,
    pub offload_id: String,
    pub seq: u64,
    pub fingerprint: String,
    pub size_bytes: u64,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::egress::present"
    )]
    pub unpacked_bytes: Option<u64>,
    pub format: String,
    /// The instance's `volatile.cloud-init.instance-id`, pinned at restore
    /// so cloud-init does not re-run its first boot.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::egress::present"
    )]
    pub cloud_init_instance_id: Option<String>,
}

/// Longest `cloudInitInstanceId` (Incus writes a UUID).
pub const CLOUD_INIT_INSTANCE_ID_MAX_BYTES: usize = 128;

/// A cloud-init instance id: 1–128 bytes of `[A-Za-z0-9._:-]`.
pub fn valid_cloud_init_instance_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= CLOUD_INIT_INSTANCE_ID_MAX_BYTES
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

impl DiskUploadBeginV11 {
    pub fn is_valid(&self) -> bool {
        valid_id(&self.sandbox_id)
            && valid_generation(self.generation)
            && valid_id(&self.offload_id)
            && valid_seq(self.seq)
            && valid_image_fingerprint(&self.fingerprint)
            && valid_size(self.size_bytes)
            && self.format == "unified"
            && self
                .cloud_init_instance_id
                .as_deref()
                .is_none_or(valid_cloud_init_instance_id)
    }
}

/// Uploaded parts of one disk upload session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiskUploadPartsV11 {
    pub sandbox_id: String,
    pub offload_id: String,
    pub seq: u64,
    pub session_id: String,
    pub parts: Vec<ImageUploadedPartV11>,
}

impl DiskUploadPartsV11 {
    pub fn is_valid(&self) -> bool {
        valid_disk_session(
            &self.sandbox_id,
            &self.offload_id,
            self.seq,
            &self.session_id,
        ) && valid_uploaded_parts(&self.parts)
    }
}

/// Every part of the session is uploaded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiskUploadCompleteV11 {
    pub sandbox_id: String,
    pub offload_id: String,
    pub seq: u64,
    pub session_id: String,
}

fn valid_disk_session(sandbox_id: &str, offload_id: &str, seq: u64, session_id: &str) -> bool {
    valid_id(sandbox_id) && valid_id(offload_id) && valid_seq(seq) && valid_id(session_id)
}

/// The host could not export or upload this offload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiskOffloadFailedV11 {
    pub sandbox_id: String,
    pub offload_id: String,
    pub seq: u64,
    pub code: DiskOffloadFailureCode,
}

/// The host dropped this stored offload's alias image, export and staging
/// reservation (after `disk.offload.stored`, or when it holds nothing of
/// that offload): the server counts the host's export slot free only now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiskOffloadReleasedV11 {
    pub sandbox_id: String,
    pub offload_id: String,
    pub seq: u64,
}

/// Ask to delete the local copy of a stored offload (LRU pressure or a
/// `disk.evict.suggest`). The server answers `disk.evict.grant|refused`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiskEvictRequestV11 {
    pub sandbox_id: String,
    pub offload_id: String,
    pub seq: u64,
}

/// The granted eviction deleted the VM; its root is proven absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiskEvictedV11 {
    pub sandbox_id: String,
    pub offload_id: String,
    pub grant_id: String,
    pub root_absence_proof: RootObservation,
}

impl DiskEvictedV11 {
    pub fn is_valid(&self) -> bool {
        valid_id(&self.sandbox_id)
            && valid_id(&self.offload_id)
            && valid_id(&self.grant_id)
            && valid_root_absence(&self.root_absence_proof)
    }
}

/// The answer to `disk.discard`: exactly one of a root-absence proof (the
/// copy is gone) or a refusal code (the binding differs; the server
/// re-evaluates).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiskDiscardedV11 {
    pub sandbox_id: String,
    pub copy_id: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::egress::present"
    )]
    pub root_absence_proof: Option<RootObservation>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::egress::present"
    )]
    pub code: Option<String>,
}

impl DiskDiscardedV11 {
    pub fn is_valid(&self) -> bool {
        valid_id(&self.sandbox_id)
            && valid_id(&self.copy_id)
            && match (&self.root_absence_proof, &self.code) {
                (Some(proof), None) => valid_root_absence(proof),
                (None, Some(code)) => valid_code(code),
                _ => false,
            }
    }
}

/// Most entries one `disk.offload.inventory` frame carries.
pub const DISK_OFFLOAD_INVENTORY_PAGE_MAX: usize = 256;

/// One unfinished (not yet `stored`) offload in the host's journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiskOffloadInventoryEntryV11 {
    pub sandbox_id: String,
    pub offload_id: String,
    pub seq: u64,
}

/// After reconciliation, the host reports its unfinished offloads (pages of
/// at most [`DISK_OFFLOAD_INVENTORY_PAGE_MAX`]). The server answers each
/// entry from its own row: `disk.offload.stored` while that offload of this
/// host is STORED, `disk.offload.cancel` (`released`) once it is over or
/// is not this host's; nothing while it is still in flight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiskOffloadInventoryV11 {
    pub entries: Vec<DiskOffloadInventoryEntryV11>,
}

impl DiskOffloadInventoryV11 {
    pub fn is_valid(&self) -> bool {
        let mut ids = std::collections::BTreeSet::new();
        !self.entries.is_empty()
            && self.entries.len() <= DISK_OFFLOAD_INVENTORY_PAGE_MAX
            && self.entries.iter().all(|e| {
                valid_offload_ref(&e.sandbox_id, &e.offload_id, e.seq)
                    && ids.insert(e.offload_id.as_str())
            })
    }
}

// ---------------------------------------------------------------- server → daemon

/// Export the stopped sandbox's disk (`incus publish`) and upload it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiskOffloadRequestV11 {
    pub sandbox_id: String,
    pub generation: u64,
    pub offload_id: String,
    pub seq: u64,
}

/// The stored object was verified: journal `stored`, drop the alias and
/// staging.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiskOffloadStoredV11 {
    pub sandbox_id: String,
    pub offload_id: String,
    pub seq: u64,
    pub fingerprint: String,
    pub generation: u64,
}

/// Stop this offload (supersede, refusal of a begin, or admin action); the
/// daemon deletes the alias and staging.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiskOffloadCancelV11 {
    pub sandbox_id: String,
    pub offload_id: String,
    pub seq: u64,
    pub reason: String,
}

/// Presigned part URLs for one disk upload session. Mirrors
/// `image.upload.grant`, but encryption is required (I13) and the frame is
/// keyed by the offload and its session; `transfer_id` names the session's
/// transfer for `image.job.resume` / `image.job.failed`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiskUploadGrantV11 {
    pub sandbox_id: String,
    pub offload_id: String,
    pub seq: u64,
    pub session_id: String,
    pub transfer_id: String,
    /// Ciphertext bytes per part; the last part is shorter.
    pub part_size: u64,
    pub parts: Vec<ImageUploadPartUrlV11>,
    pub expires_at_unix_ms: u64,
    pub encryption: ImageEncryptionV11,
}

impl std::fmt::Debug for DiskUploadGrantV11 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiskUploadGrantV11")
            .field("sandbox_id", &self.sandbox_id)
            .field("offload_id", &self.offload_id)
            .field("seq", &self.seq)
            .field("session_id", &self.session_id)
            .field("transfer_id", &self.transfer_id)
            .field("part_size", &self.part_size)
            .field("parts", &self.parts.len())
            .field("encryption", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl DiskUploadGrantV11 {
    pub fn is_valid(&self) -> bool {
        valid_disk_session(
            &self.sandbox_id,
            &self.offload_id,
            self.seq,
            &self.session_id,
        ) && valid_id(&self.transfer_id)
            && valid_upload_part_urls(self.part_size, &self.parts)
            && self.encryption.is_valid()
    }
}

/// Placement found no room without this stored copy's disk: ask the host to
/// request its eviction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiskEvictSuggestV11 {
    pub sandbox_id: String,
    pub offload_id: String,
    pub seq: u64,
}

/// The server's CAS held: delete the VM before `expires_at_unix_ms` (judged
/// against the relayed server time) and answer `disk.evicted`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiskEvictGrantV11 {
    pub sandbox_id: String,
    pub offload_id: String,
    pub seq: u64,
    pub grant_id: String,
    pub expires_at_unix_ms: u64,
}

/// The eviction request was refused; the local copy stays.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiskEvictRefusedV11 {
    pub sandbox_id: String,
    pub offload_id: String,
    pub seq: u64,
    pub code: String,
}

/// Delete a stale copy (§7 Discard). With the instance present it is bound
/// by sandbox id, `create_key`, base image and template tag; with it
/// absent, the orphan root is named by `storage_pool_name + storage_marker`.
/// `base_fingerprint` is the copy row's base image (a restored lineage's
/// disk image, else the template); `template_fingerprint` is the sandbox's
/// template revision (the instance's template tag).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiskDiscardV11 {
    pub sandbox_id: String,
    pub copy_id: String,
    pub create_key: String,
    pub base_fingerprint: String,
    pub template_fingerprint: String,
    pub storage_pool_name: String,
    pub storage_marker: String,
}

impl DiskDiscardV11 {
    pub fn is_valid(&self) -> bool {
        valid_id(&self.sandbox_id)
            && valid_id(&self.copy_id)
            && !self.create_key.is_empty()
            && self.create_key.len() <= crate::RECEIPT_LIMITS.idempotency_key_bytes
            && valid_image_fingerprint(&self.base_fingerprint)
            && valid_image_fingerprint(&self.template_fingerprint)
            && !self.storage_pool_name.is_empty()
            && self.storage_pool_name.len() <= 63
            && valid_storage_marker(&self.storage_marker)
    }
}

fn valid_offload_ref(sandbox_id: &str, offload_id: &str, seq: u64) -> bool {
    valid_id(sandbox_id) && valid_id(offload_id) && valid_seq(seq)
}

/// Validation of server→daemon disk frames (both encode and parse).
pub(crate) fn valid_server_disk(message: &crate::ServerControlMessage) -> bool {
    use crate::ServerControlMessage as M;
    match message {
        M::DiskOffloadRequest(r) => {
            valid_offload_ref(&r.sandbox_id, &r.offload_id, r.seq) && valid_generation(r.generation)
        }
        M::DiskOffloadStored(r) => {
            valid_offload_ref(&r.sandbox_id, &r.offload_id, r.seq)
                && valid_image_fingerprint(&r.fingerprint)
                && valid_generation(r.generation)
        }
        M::DiskOffloadCancel(r) => {
            valid_offload_ref(&r.sandbox_id, &r.offload_id, r.seq) && valid_code(&r.reason)
        }
        M::DiskUploadGrant(g) => g.is_valid(),
        M::DiskEvictSuggest(r) => valid_offload_ref(&r.sandbox_id, &r.offload_id, r.seq),
        M::DiskEvictGrant(g) => {
            valid_offload_ref(&g.sandbox_id, &g.offload_id, g.seq) && valid_id(&g.grant_id)
        }
        M::DiskEvictRefused(r) => {
            valid_offload_ref(&r.sandbox_id, &r.offload_id, r.seq) && valid_code(&r.code)
        }
        M::DiskDiscard(r) => r.is_valid(),
        _ => true,
    }
}

/// Validation of daemon→server disk frames (both encode and parse).
pub(crate) fn valid_daemon_disk(message: &crate::DaemonControlMessage) -> bool {
    use crate::DaemonControlMessage as M;
    match message {
        M::DiskUploadBegin(r) => r.is_valid(),
        M::DiskUploadParts(r) => r.is_valid(),
        M::DiskUploadComplete(r) => {
            valid_disk_session(&r.sandbox_id, &r.offload_id, r.seq, &r.session_id)
        }
        M::DiskOffloadFailed(r) => valid_offload_ref(&r.sandbox_id, &r.offload_id, r.seq),
        M::DiskEvictRequest(r) => valid_offload_ref(&r.sandbox_id, &r.offload_id, r.seq),
        M::DiskOffloadReleased(r) => valid_offload_ref(&r.sandbox_id, &r.offload_id, r.seq),
        M::DiskEvicted(r) => r.is_valid(),
        M::DiskDiscarded(r) => r.is_valid(),
        M::DiskOffloadInventory(r) => r.is_valid(),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(encryption_key: &str) -> DiskUploadGrantV11 {
        DiskUploadGrantV11 {
            sandbox_id: "sbx".into(),
            offload_id: "off".into(),
            seq: 1,
            session_id: "ses".into(),
            transfer_id: "tr".into(),
            part_size: 5,
            parts: vec![ImageUploadPartUrlV11 {
                n: 1,
                url: "https://x/?X-Amz-Signature=abc".into(),
                size_bytes: 5,
            }],
            expires_at_unix_ms: 1,
            encryption: ImageEncryptionV11 {
                scheme: crate::IMAGE_ENCRYPTION_SCHEME.into(),
                key: encryption_key.into(),
            },
        }
    }

    #[test]
    fn disk_grant_debug_never_prints_urls_or_keys() {
        let text = format!("{:?}", grant(&"K".repeat(44)));
        assert!(
            !text.contains("Signature") && !text.contains("KKKK"),
            "{text}"
        );
        let message = crate::ServerControlMessage::DiskUploadGrant(grant(&"K".repeat(44)));
        let text = format!("{message:?}");
        assert!(
            !text.contains("KKKK") && !text.contains("Signature"),
            "{text}"
        );
    }

    #[test]
    fn disk_grant_requires_valid_encryption() {
        assert!(grant(&"K".repeat(44)).is_valid());
        assert!(!grant("short").is_valid());
        let mut value = serde_json::to_value(grant(&"K".repeat(44))).unwrap();
        value.as_object_mut().unwrap().remove("encryption");
        assert!(serde_json::from_value::<DiskUploadGrantV11>(value).is_err());
    }

    #[test]
    fn an_offload_inventory_page_holds_at_most_its_cap() {
        let page = |n: usize| DiskOffloadInventoryV11 {
            entries: (0..n)
                .map(|i| DiskOffloadInventoryEntryV11 {
                    sandbox_id: format!("sbx-{i}"),
                    offload_id: format!("off-{i}"),
                    seq: 1,
                })
                .collect(),
        };
        assert!(page(DISK_OFFLOAD_INVENTORY_PAGE_MAX).is_valid());
        assert!(!page(DISK_OFFLOAD_INVENTORY_PAGE_MAX + 1).is_valid());
        assert!(!page(0).is_valid());
    }

    #[test]
    fn launch_mode_spellings() {
        for mode in [LaunchMode::NewRoot, LaunchMode::Cold, LaunchMode::Warm] {
            assert_eq!(
                serde_json::to_value(mode).unwrap(),
                serde_json::Value::String(mode.as_str().into())
            );
        }
    }
}
