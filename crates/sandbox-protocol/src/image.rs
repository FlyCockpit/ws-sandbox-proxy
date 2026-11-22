//! Template image distribution and capture frames (additive within 1.0).
//!
//! Every field added to an existing frame is optional with `#[serde(default)]`
//! and omitted when absent, so a daemon without the `image` capability and a
//! server that never sends these frames exchange byte-identical messages.
//! Grants carry presigned URLs, relay link tokens and data keys: their
//! `Debug` output is redacted and they are never journaled.

use serde::{Deserialize, Serialize};

/// Bound on census entries per `image.cache.census` page.
pub const IMAGE_CENSUS_PAGE_MAX: usize = 256;
/// Bound on image owners recorded for one cached fingerprint.
pub const IMAGE_CENSUS_OWNERS_MAX: usize = 16;
/// Bound on relay links in one grant or request.
pub const IMAGE_LINKS_MAX: usize = 16;
/// Bound on presigned upload parts per grant and completed parts per report.
pub const IMAGE_UPLOAD_PARTS_MAX: usize = 64;
/// Bound on copy-on-write storage markers advertised at admission.
pub const IMAGE_CAPTURE_MARKERS_MAX: usize = 16;
/// Bound on capture scrub paths carried by one dispatch (built-ins excluded).
pub const CAPTURE_SCRUB_PATHS_MAX: usize = 80;
/// Relay part size (fits Cloudflare's request body cap with headroom).
pub const IMAGE_RELAY_PART_BYTES: u64 = 32 * 1024 * 1024;
/// Plaintext S3 multipart part size of a transfer that has no session yet
/// (a fetch of an artifact stored before its part size was recorded). An
/// upload session sizes its own parts (`partSize` on the grant).
pub const IMAGE_S3_PART_BYTES: u64 = 64 * 1024 * 1024;
/// Longest presigned URL lifetime a grant may carry (S3's own bound).
pub const IMAGE_UPLOAD_TTL_MAX_SECONDS: u64 = 7 * 24 * 3600;
/// Plaintext bytes per AES-256-GCM record of an encrypted stored image.
pub const IMAGE_ENCRYPTION_RECORD_BYTES: u64 = 1024 * 1024;
/// GCM tag bytes appended to every encrypted record.
pub const IMAGE_ENCRYPTION_TAG_BYTES: u64 = 16;
/// Stored-object encryption scheme name.
pub const IMAGE_ENCRYPTION_SCHEME: &str = "aes256gcm-r1";
/// Largest image the protocol accepts (1 TiB).
pub const IMAGE_SIZE_MAX: u64 = 1 << 40;

/// `sha256:<64 lowercase hex>`.
pub fn valid_image_fingerprint(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn valid_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn valid_size(value: u64) -> bool {
    value > 0 && value <= IMAGE_SIZE_MAX
}

/// Ciphertext length of an `aes256gcm-r1` object for `plain` bytes.
pub fn encrypted_image_len(plain: u64) -> u64 {
    let records = plain.div_ceil(IMAGE_ENCRYPTION_RECORD_BYTES).max(1);
    plain + records * IMAGE_ENCRYPTION_TAG_BYTES
}

/// Hello capability: what this daemon's image cache can do. Omitted entirely
/// when the cache is disabled (`image_cache_gib = 0`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageCapabilitiesV11 {
    pub fetch: bool,
    pub serve: bool,
    pub publish: bool,
    pub capture: bool,
    pub accept_foreign: bool,
    pub lease_from_ready: bool,
    pub formats: Vec<String>,
    /// Template builds: this node runs build VMs (capture-capable and not
    /// `builder = false`). Omitted while false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub build: bool,
    /// Builds for other accounts (`accept_foreign_builds`). Requires `build`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub accept_foreign_builds: bool,
}

impl ImageCapabilitiesV11 {
    pub fn is_valid(&self) -> bool {
        !self.formats.is_empty()
            && self.formats.len() <= 4
            && self.formats.iter().all(|f| f == "unified")
            && (!self.build || self.capture)
            && (!self.accept_foreign_builds || self.build)
    }
}

/// `host.admission` image facts, frozen for the connection like storage caps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageAdmissionV11 {
    pub cap_bytes: u64,
    pub used_bytes: u64,
    pub foreign_used_bytes: u64,
    /// Storage pool markers that support copy-on-write snapshots (READY capture).
    pub capture_storage_markers: Vec<String>,
}

impl ImageAdmissionV11 {
    pub fn is_valid(&self) -> bool {
        self.cap_bytes <= IMAGE_SIZE_MAX * 8
            && self.used_bytes <= IMAGE_SIZE_MAX * 8
            && self.foreign_used_bytes <= self.used_bytes
            && self.capture_storage_markers.len() <= IMAGE_CAPTURE_MARKERS_MAX
            && self
                .capture_storage_markers
                .iter()
                .all(|m| !m.is_empty() && m.len() <= 128)
    }
}

/// Planned image fetch on a `sandbox.create` dispatch. Never carries a link.
///
/// Exactly one of two shapes: a `unified` image the daemon fetches through
/// the control plane (`source: "fetch"`, no `upstream`), or a community
/// base's raw `split` image the daemon downloads itself from
/// [`UPSTREAM_IMAGE_BASE_URL`] (`source: "upstream"` with `upstream`). The
/// second rides only on a bootstrap build create (see
/// [`valid_dispatch_image_fields`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DispatchImageV11 {
    /// For `split`: Incus's split-image fingerprint, the sha256 of the
    /// metadata file's bytes followed by the disk file's.
    pub fingerprint: String,
    pub size_bytes: u64,
    pub format: String,
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream: Option<DispatchUpstreamImageV11>,
}

impl DispatchImageV11 {
    pub fn is_valid(&self) -> bool {
        if !valid_image_fingerprint(&self.fingerprint) || !valid_size(self.size_bytes) {
            return false;
        }
        match (self.format.as_str(), self.source.as_str(), &self.upstream) {
            ("unified", "fetch", None) => true,
            ("split", "upstream", Some(upstream)) => {
                upstream.is_valid()
                    && upstream.meta_size.checked_add(upstream.disk_size) == Some(self.size_bytes)
            }
            _ => false,
        }
    }
}

/// The only host the daemon downloads upstream images from. Paths in
/// [`DispatchUpstreamImageV11`] are relative to it.
pub const UPSTREAM_IMAGE_BASE_URL: &str = "https://images.linuxcontainers.org/";
/// Largest upstream metadata file (`incus.tar.xz`).
pub const UPSTREAM_META_MAX_BYTES: u64 = 1 << 20;
/// Largest upstream disk file (`disk.qcow2`).
pub const UPSTREAM_DISK_MAX_BYTES: u64 = 4 << 30;
/// Bound on one upstream path.
pub const UPSTREAM_PATH_MAX_BYTES: usize = 512;
/// File name of an upstream split image's metadata.
pub const UPSTREAM_META_FILE: &str = "incus.tar.xz";
/// File name of an upstream split image's disk.
pub const UPSTREAM_DISK_FILE: &str = "disk.qcow2";

/// The two files of an upstream split VM image, pinned by the control plane
/// from the simplestreams index: paths under [`UPSTREAM_IMAGE_BASE_URL`],
/// each file's sha256 (lowercase hex) and size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DispatchUpstreamImageV11 {
    pub meta_path: String,
    pub meta_sha256: String,
    pub meta_size: u64,
    pub disk_path: String,
    pub disk_sha256: String,
    pub disk_size: u64,
}

impl DispatchUpstreamImageV11 {
    pub fn is_valid(&self) -> bool {
        valid_sha256_hex(&self.meta_sha256)
            && valid_sha256_hex(&self.disk_sha256)
            && (1..=UPSTREAM_META_MAX_BYTES).contains(&self.meta_size)
            && (1..=UPSTREAM_DISK_MAX_BYTES).contains(&self.disk_size)
            && valid_upstream_image_path(&self.meta_path)
            && valid_upstream_image_path(&self.disk_path)
            && match (
                self.meta_path.rsplit_once('/'),
                self.disk_path.rsplit_once('/'),
            ) {
                (Some((meta_dir, meta)), Some((disk_dir, disk))) => {
                    meta_dir == disk_dir && meta == UPSTREAM_META_FILE && disk == UPSTREAM_DISK_FILE
                }
                _ => false,
            }
    }
}

/// An upstream path relative to [`UPSTREAM_IMAGE_BASE_URL`]: at most
/// [`UPSTREAM_PATH_MAX_BYTES`], starting with `images/`, every segment
/// non-empty, `[A-Za-z0-9._:+-]` only, and neither `.` nor `..`.
pub fn valid_upstream_image_path(path: &str) -> bool {
    path.len() <= UPSTREAM_PATH_MAX_BYTES
        && path.starts_with("images/")
        && path.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'+' | b'-')
                })
        })
}

/// Dispatch-level image rules: a plan rides only on `sandbox.create` (or a
/// restoring `sandbox.reconnect`), and an upstream plan only on a create
/// whose build carries `bootstrap` (the community prep build VM, the only
/// place a raw upstream image boots).
pub(crate) fn valid_dispatch_image_fields(d: &crate::OperationDispatch) -> bool {
    d.image.as_ref().is_none_or(|image| {
        image.is_valid()
            && match d.kind.as_str() {
                "sandbox.create" => {
                    image.upstream.is_none() || d.build.as_ref().is_some_and(|b| b.bootstrap)
                }
                // A restore fetches its stored disk; the
                // disk rules pin the fingerprint to `restore`.
                "sandbox.reconnect" => d.restore.is_some() && image.upstream.is_none(),
                _ => false,
            }
    })
}

/// `sandbox.capture` dispatch body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DispatchCaptureV11 {
    /// Extra scrub paths (template plus request); the built-in manifest is
    /// compiled into the daemon and never sent.
    pub scrub_paths: Vec<String>,
    /// The sandbox was STOPPED at acceptance: no freeze and no snapshot.
    pub stopped: bool,
    /// The host must upload the published image to the store (S3 mode).
    pub upload: bool,
}

impl DispatchCaptureV11 {
    pub fn is_valid(&self) -> bool {
        self.scrub_paths.len() <= CAPTURE_SCRUB_PATHS_MAX
            && self.scrub_paths.iter().all(|p| valid_scrub_path(p))
    }
}

/// Scrub paths are absolute, normalized guest paths: no `..`, no empty or
/// `.` segment, `*` only inside the last segment, bounded length.
pub fn valid_scrub_path(path: &str) -> bool {
    if path.len() < 2 || path.len() > 256 || !path.starts_with('/') || path.contains('\0') {
        return false;
    }
    let segments: Vec<&str> = path[1..].split('/').collect();
    let last = segments.len() - 1;
    segments
        .iter()
        .enumerate()
        .all(|(i, s)| !s.is_empty() && *s != "." && *s != ".." && (i == last || !s.contains('*')))
}

/// Progress carried on `operation.progress` (create fetch, capture phases).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationProgressV11 {
    pub phase: ProgressPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_done: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_total: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgressPhase {
    FetchingImage,
    ImportingImage,
    Freezing,
    Snapshotting,
    Copying,
    Scrubbing,
    Publishing,
    Uploading,
    /// Disk offload (§7): `incus publish` of the stopped VM.
    ExportingDisk,
    UploadingDisk,
    /// Restore (§8): fetch and import of the stored disk.
    FetchingDisk,
    ImportingDisk,
}

impl ProgressPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FetchingImage => "fetching_image",
            Self::ImportingImage => "importing_image",
            Self::Freezing => "freezing",
            Self::Snapshotting => "snapshotting",
            Self::Copying => "copying",
            Self::Scrubbing => "scrubbing",
            Self::Publishing => "publishing",
            Self::Uploading => "uploading",
            Self::ExportingDisk => "exporting_disk",
            Self::UploadingDisk => "uploading_disk",
            Self::FetchingDisk => "fetching_disk",
            Self::ImportingDisk => "importing_disk",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageOrigin {
    Fetched,
    Captured,
    Replica,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageEvictReason {
    Lru,
    AccessLost,
    Released,
    Operator,
    Corrupt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageFailureCode {
    Corrupt,
    Rejected,
    Io,
    CacheFull,
    Timeout,
    FormatUnsupported,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ImageLinkRole {
    Source,
    Dest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageReleaseReason {
    Stored,
    Replicated,
    Gc,
    AccessLost,
    Released,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageCacheTotals {
    pub used_bytes: u64,
    pub foreign_bytes: u64,
}

impl ImageCacheTotals {
    fn is_valid(&self) -> bool {
        self.foreign_bytes <= self.used_bytes && self.used_bytes <= IMAGE_SIZE_MAX * 8
    }
}

// ---------------------------------------------------------------- daemon → server

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageFetchRequestV11 {
    pub request_id: String,
    pub operation_id: String,
    pub sandbox_id: String,
    pub generation: u64,
    pub attempt: u64,
    pub fingerprint: String,
    pub resume_offset: u64,
}

impl ImageFetchRequestV11 {
    pub fn is_valid(&self) -> bool {
        valid_id(&self.request_id)
            && valid_id(&self.operation_id)
            && valid_id(&self.sandbox_id)
            && self.generation > 0
            && valid_image_fingerprint(&self.fingerprint)
            && self.resume_offset <= IMAGE_SIZE_MAX
    }
}

/// The host now holds `fingerprint` for `image_owner_id`. `transfer_id` or
/// `operation_id` names the job that produced it (M4): the server records
/// evidence only for an owner with such a job on this host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageCachedV11 {
    pub fingerprint: String,
    pub image_owner_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transfer_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    pub compressed_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unpacked_bytes: Option<u64>,
    pub origin: ImageOrigin,
    pub totals: ImageCacheTotals,
}

impl ImageCachedV11 {
    pub fn is_valid(&self) -> bool {
        valid_image_fingerprint(&self.fingerprint)
            && valid_id(&self.image_owner_id)
            && (self.transfer_id.is_some() != self.operation_id.is_some())
            && self.transfer_id.as_deref().is_none_or(valid_id)
            && self.operation_id.as_deref().is_none_or(valid_id)
            && valid_size(self.compressed_bytes)
            && self.totals.is_valid()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageEvictedV11 {
    pub fingerprint: String,
    pub image_owner_id: String,
    pub reason: ImageEvictReason,
    pub totals: ImageCacheTotals,
}

impl ImageEvictedV11 {
    pub fn is_valid(&self) -> bool {
        valid_image_fingerprint(&self.fingerprint)
            && valid_id(&self.image_owner_id)
            && self.totals.is_valid()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageFetchFailedV11 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transfer_id: Option<String>,
    pub fingerprint: String,
    pub code: ImageFailureCode,
}

impl ImageFetchFailedV11 {
    pub fn is_valid(&self) -> bool {
        (self.request_id.is_some() || self.transfer_id.is_some())
            && self.request_id.as_deref().is_none_or(valid_id)
            && self.transfer_id.as_deref().is_none_or(valid_id)
            && valid_image_fingerprint(&self.fingerprint)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageCensusEntryV11 {
    pub fingerprint: String,
    pub owners: Vec<String>,
    pub compressed_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unpacked_bytes: Option<u64>,
    pub origin: ImageOrigin,
    pub pinned: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageCacheCensusV11 {
    pub page: u64,
    pub complete: bool,
    pub entries: Vec<ImageCensusEntryV11>,
    pub totals: ImageCacheTotals,
}

impl ImageCacheCensusV11 {
    pub fn is_valid(&self) -> bool {
        self.page <= 4096
            && self.entries.len() <= IMAGE_CENSUS_PAGE_MAX
            && self.totals.is_valid()
            && self.entries.iter().all(|e| {
                valid_image_fingerprint(&e.fingerprint)
                    && !e.owners.is_empty()
                    && e.owners.len() <= IMAGE_CENSUS_OWNERS_MAX
                    && e.owners.iter().all(|o| valid_id(o))
                    && valid_size(e.compressed_bytes)
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageLinksRequestV11 {
    pub transfer_id: String,
    pub role: ImageLinkRole,
    pub parts: Vec<u32>,
}

impl ImageLinksRequestV11 {
    pub fn is_valid(&self) -> bool {
        valid_id(&self.transfer_id)
            && !self.parts.is_empty()
            && self.parts.len() <= IMAGE_LINKS_MAX
            && self.parts.iter().all(|p| (1..=10_000).contains(p))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImagePartAckV11 {
    pub transfer_id: String,
    pub part: u32,
    pub sha256: String,
}

impl ImagePartAckV11 {
    pub fn is_valid(&self) -> bool {
        valid_id(&self.transfer_id)
            && (1..=10_000).contains(&self.part)
            && valid_sha256_hex(&self.sha256)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageUploadBeginV11 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transfer_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    /// Capture only (round-3 P2-4): the daemon's id for this upload. The
    /// first grant and any cancellation before it echo it, so concurrent
    /// captures each receive only their own frames.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Capture only (round-3 P2-2): the dispatch attempt that produced the
    /// capture. The upload is granted only while that attempt is current
    /// and is bound to it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt: Option<u64>,
    pub fingerprint: String,
    pub size_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unpacked_bytes: Option<u64>,
    pub format: String,
}

impl ImageUploadBeginV11 {
    /// A publish names its transfer; a capture names its operation, its
    /// request id and its dispatch attempt (all three, nothing else).
    pub fn is_valid(&self) -> bool {
        let capture_identity = match (&self.transfer_id, &self.operation_id) {
            (Some(_), None) => self.request_id.is_none() && self.attempt.is_none(),
            (None, Some(_)) => {
                self.request_id.as_deref().is_some_and(valid_id) && self.attempt.is_some()
            }
            _ => false,
        };
        capture_identity
            && self.transfer_id.as_deref().is_none_or(valid_id)
            && self.operation_id.as_deref().is_none_or(valid_id)
            && valid_image_fingerprint(&self.fingerprint)
            && valid_size(self.size_bytes)
            && self.format == "unified"
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageUploadedPartV11 {
    pub n: u32,
    pub etag: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageUploadPartsV11 {
    pub transfer_id: String,
    pub parts: Vec<ImageUploadedPartV11>,
}

impl ImageUploadPartsV11 {
    pub fn is_valid(&self) -> bool {
        valid_id(&self.transfer_id) && valid_uploaded_parts(&self.parts)
    }
}

/// A non-empty, bounded report of uploaded parts (template and disk uploads).
pub(crate) fn valid_uploaded_parts(parts: &[ImageUploadedPartV11]) -> bool {
    !parts.is_empty()
        && parts.len() <= IMAGE_UPLOAD_PARTS_MAX
        && parts.iter().all(|p| {
            (1..=10_000).contains(&p.n)
                && !p.etag.is_empty()
                && p.etag.len() <= 256
                && p.etag.bytes().all(|b| b.is_ascii_graphic())
        })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageTransferRefV11 {
    pub transfer_id: String,
}

/// After a relay reconnect a background job re-binds itself to the new
/// connection. It names its transfer, or (a capture upload before its first
/// grant: begin in flight or in retry backoff) the capture's operation and
/// dispatch attempt; exactly one of the two, and an operation reference only
/// as the `SOURCE` with nothing done.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageJobResumeV11 {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::egress::present"
    )]
    pub transfer_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::egress::present"
    )]
    pub operation_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::egress::present"
    )]
    pub attempt: Option<u64>,
    pub role: ImageLinkRole,
    pub bytes_done: u64,
}

impl ImageJobResumeV11 {
    /// The resume of a transfer.
    pub fn transfer(transfer_id: &str, role: ImageLinkRole, bytes_done: u64) -> Self {
        Self {
            transfer_id: Some(transfer_id.to_owned()),
            operation_id: None,
            attempt: None,
            role,
            bytes_done,
        }
    }

    /// The resume of a capture upload that has no transfer yet.
    pub fn operation(operation_id: &str, attempt: u64) -> Self {
        Self {
            transfer_id: None,
            operation_id: Some(operation_id.to_owned()),
            attempt: Some(attempt),
            role: ImageLinkRole::Source,
            bytes_done: 0,
        }
    }

    pub fn is_valid(&self) -> bool {
        valid_job_reference(&self.transfer_id, &self.operation_id, self.attempt)
            && (self.transfer_id.is_some()
                || (self.role == ImageLinkRole::Source && self.bytes_done == 0))
            && self.bytes_done <= IMAGE_SIZE_MAX
    }
}

/// Exactly one job reference: a transfer, or an operation with its attempt
/// (at most `Number.MAX_SAFE_INTEGER`).
fn valid_job_reference(
    transfer: &Option<String>,
    operation: &Option<String>,
    attempt: Option<u64>,
) -> bool {
    match (transfer, operation) {
        (Some(transfer), None) => valid_id(transfer) && attempt.is_none(),
        (None, Some(operation)) => valid_id(operation) && attempt.is_some_and(|a| a <= JS_SAFE_MAX),
        _ => false,
    }
}

/// Why a host-side upload or export ended (`image.job.failed`). The server
/// maps it to a code-shaped detail; the daemon never sends free text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageFailureCause {
    /// A bounded wait (connect excluded) ran out: request headers, response.
    Timeout,
    /// No byte moved, in either direction, for the idle bound.
    Stalled,
    /// The peer reset or closed the connection mid-request.
    Reset,
    /// The store could not be reached (DNS, refused, unreachable).
    Connect,
    Tls,
    /// The store answered with a status other than success (`httpStatus`).
    HttpStatus,
    /// A 403 at or after the grant's expiry (`httpStatus`).
    UrlExpired,
    /// Reading or sealing the staged image failed.
    LocalIo,
    /// The image could not be exported from the host image store.
    Export,
    /// No grant arrived in time after `image.upload.begin`.
    NoGrant,
    /// The server refused the job (`image.job.cancel`; its reason is `refusal`).
    Refused,
    /// A malformed or mismatched answer (grant, key, response).
    Protocol,
}

impl ImageFailureCause {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Stalled => "stalled",
            Self::Reset => "reset",
            Self::Connect => "connect",
            Self::Tls => "tls",
            Self::HttpStatus => "http_status",
            Self::UrlExpired => "url_expired",
            Self::LocalIo => "local_io",
            Self::Export => "export",
            Self::NoGrant => "no_grant",
            Self::Refused => "refused",
            Self::Protocol => "protocol",
        }
    }
}

/// A host-side image job ended. It names its transfer, or (a capture upload
/// that never got one: export failure, no grant, refused begin) its
/// operation and dispatch attempt; exactly one of the two.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageJobFailedV11 {
    // Optional fields refuse an explicit `null` (zod `.optional()`).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::egress::present"
    )]
    pub transfer_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::egress::present"
    )]
    pub operation_id: Option<String>,
    /// At most `Number.MAX_SAFE_INTEGER`, like every integer the server reads.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::egress::present"
    )]
    pub attempt: Option<u64>,
    pub code: ImageFailureCode,
    pub cause: ImageFailureCause,
    /// The store's status: present exactly for `http_status` / `url_expired`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::egress::present"
    )]
    pub http_status: Option<u16>,
    /// The part being sent when the job ended.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::egress::present"
    )]
    pub part: Option<u32>,
    /// The server's own cancel reason, echoed: present exactly for `refused`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::egress::present"
    )]
    pub refusal: Option<String>,
}

/// The largest integer a JSON number carries exactly (the server's bound).
const JS_SAFE_MAX: u64 = 9_007_199_254_740_991;

impl ImageJobFailedV11 {
    pub fn is_valid(&self) -> bool {
        let reference = valid_job_reference(&self.transfer_id, &self.operation_id, self.attempt);
        let with_status = matches!(
            self.cause,
            ImageFailureCause::HttpStatus | ImageFailureCause::UrlExpired
        );
        reference
            && self.http_status.is_some() == with_status
            && self.http_status.is_none_or(|s| (100..=599).contains(&s))
            && self.part.is_none_or(|p| (1..=10_000).contains(&p))
            && self.refusal.is_some() == (self.cause == ImageFailureCause::Refused)
            && self.refusal.as_deref().is_none_or(valid_code)
    }
}

/// The host asks for fresh presigned part URLs of its upload (its granted
/// window is used up, or the next URL is about to expire). The server
/// answers `image.upload.grant` from its lowest unrecorded part.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageUploadRenewV11 {
    pub transfer_id: String,
}

/// Upload liveness heartbeat, at most every 30 s and only while a count
/// advanced: the furthest offset reached in the stored object (`bytesSent`,
/// logical progress: a part sent again never moves it), and every body byte
/// the transport took so far, retries included (`wireBytes`, physical
/// activity, monotonic for the transfer). Either one advancing is liveness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageUploadProgressV11 {
    pub transfer_id: String,
    pub bytes_sent: u64,
    pub wire_bytes: u64,
}

/// Bound on `wireBytes`: every part of the largest stored object sent
/// `IMAGE_WIRE_ATTEMPTS_MAX` times.
pub const IMAGE_WIRE_BYTES_MAX: u64 = IMAGE_SIZE_MAX * 2 * IMAGE_WIRE_ATTEMPTS_MAX;
/// Most attempts that can send one part's body (the daemon's are fewer).
pub const IMAGE_WIRE_ATTEMPTS_MAX: u64 = 8;

impl ImageUploadProgressV11 {
    pub fn is_valid(&self) -> bool {
        valid_id(&self.transfer_id)
            && self.bytes_sent <= IMAGE_SIZE_MAX * 2
            && self.wire_bytes <= IMAGE_WIRE_BYTES_MAX
    }
}

// ---------------------------------------------------------------- server → daemon

/// One-time relay part link. The token travels only in the
/// `X-Wssp-Image-Link` header, never in a path or query.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageRelayLinkV11 {
    pub part: u32,
    pub link_id: String,
    pub token: String,
}

impl std::fmt::Debug for ImageRelayLinkV11 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImageRelayLinkV11")
            .field("part", &self.part)
            .field("link_id", &self.link_id)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl ImageRelayLinkV11 {
    fn is_valid(&self) -> bool {
        (1..=10_000).contains(&self.part)
            && valid_id(&self.link_id)
            && self.token.len() == 43
            && self
                .token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    }
}

fn valid_links(links: &[ImageRelayLinkV11]) -> bool {
    links.len() <= IMAGE_LINKS_MAX && links.iter().all(ImageRelayLinkV11::is_valid)
}

/// Per-object data key for an encrypted stored image (base64 of 32 bytes).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageEncryptionV11 {
    pub scheme: String,
    pub key: String,
}

impl std::fmt::Debug for ImageEncryptionV11 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImageEncryptionV11")
            .field("scheme", &self.scheme)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl ImageEncryptionV11 {
    pub(crate) fn is_valid(&self) -> bool {
        self.scheme == IMAGE_ENCRYPTION_SCHEME && self.key.len() == 44
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ImageTransferMode {
    S3,
    Relay,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageFetchGrantV11 {
    pub request_id: String,
    pub transfer_id: String,
    pub mode: ImageTransferMode,
    /// Plaintext image size (the fingerprinted tarball).
    pub size_bytes: u64,
    /// Relay part size, or the stored object's part size (S3).
    pub part_size: u64,
    pub expires_at_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<ImageRelayLinkV11>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<ImageEncryptionV11>,
}

impl std::fmt::Debug for ImageFetchGrantV11 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImageFetchGrantV11")
            .field("request_id", &self.request_id)
            .field("transfer_id", &self.transfer_id)
            .field("mode", &self.mode)
            .field("size_bytes", &self.size_bytes)
            .field("url", &self.url.as_ref().map(|_| "<redacted>"))
            .field("links", &self.links.as_ref().map(Vec::len))
            .field(
                "encryption",
                &self.encryption.as_ref().map(|_| "<redacted>"),
            )
            .finish_non_exhaustive()
    }
}

impl ImageFetchGrantV11 {
    pub fn is_valid(&self) -> bool {
        valid_id(&self.request_id)
            && valid_id(&self.transfer_id)
            && valid_size(self.size_bytes)
            && self.part_size > 0
            && match self.mode {
                ImageTransferMode::S3 => {
                    self.links.is_none() && self.url.as_deref().is_some_and(valid_url)
                }
                ImageTransferMode::Relay => {
                    self.url.is_none()
                        && self.encryption.is_none()
                        && self.links.as_deref().is_some_and(valid_links)
                }
            }
            && self
                .encryption
                .as_ref()
                .is_none_or(ImageEncryptionV11::is_valid)
    }
}

/// Presigned or relay URLs carry bearer material: HTTPS, or HTTP only to an
/// explicit loopback host (local development and the disposable S3 harness).
fn valid_url(value: &str) -> bool {
    if value.len() > 8192 {
        return false;
    }
    if value.starts_with("https://") {
        return true;
    }
    let Some(rest) = value.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.contains('@') {
        return false;
    }
    let host = if let Some(v6) = authority.strip_prefix('[') {
        v6.split(']').next().unwrap_or("")
    } else {
        authority.split(':').next().unwrap_or("")
    };
    host.eq_ignore_ascii_case("localhost")
        || host == "::1"
        || host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|ip| ip.is_loopback())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageFetchRefusedV11 {
    pub request_id: String,
    pub code: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageServeRequestV11 {
    pub transfer_id: String,
    pub image_owner_id: String,
    pub fingerprint: String,
    pub size_bytes: u64,
    pub part_size: u64,
    pub links: Vec<ImageRelayLinkV11>,
}

impl std::fmt::Debug for ImageServeRequestV11 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImageServeRequestV11")
            .field("transfer_id", &self.transfer_id)
            .field("fingerprint", &self.fingerprint)
            .field("links", &self.links.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImagePublishRequestV11 {
    pub transfer_id: String,
    pub image_owner_id: String,
    pub fingerprint: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageLinksGrantV11 {
    pub transfer_id: String,
    pub role: ImageLinkRole,
    pub links: Vec<ImageRelayLinkV11>,
}

impl std::fmt::Debug for ImageLinksGrantV11 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImageLinksGrantV11")
            .field("transfer_id", &self.transfer_id)
            .field("role", &self.role)
            .field("links", &self.links.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageUploadPartUrlV11 {
    pub n: u32,
    pub url: String,
    /// Exact signed Content-Length of this part.
    pub size_bytes: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageUploadGrantV11 {
    pub transfer_id: String,
    /// The capture's `image.upload.begin` request id, on the grant that
    /// answers it (round-3 P2-4). Continuations route by `transfer_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Ciphertext (or plaintext) bytes per part; the last part is shorter.
    pub part_size: u64,
    pub parts: Vec<ImageUploadPartUrlV11>,
    pub expires_at_unix_ms: u64,
    /// Lifetime of the part URLs, relative to receipt: the host judges
    /// expiry on its own monotonic clock, never against the server's.
    pub ttl_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<ImageEncryptionV11>,
}

impl std::fmt::Debug for ImageUploadGrantV11 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImageUploadGrantV11")
            .field("transfer_id", &self.transfer_id)
            .field("request_id", &self.request_id)
            .field("part_size", &self.part_size)
            .field("parts", &self.parts.len())
            .field(
                "encryption",
                &self.encryption.as_ref().map(|_| "<redacted>"),
            )
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageJobResumeResultV11 {
    /// The reference of the resume it answers (exactly one shape).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::egress::present"
    )]
    pub transfer_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::egress::present"
    )]
    pub operation_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::egress::present"
    )]
    pub attempt: Option<u64>,
    #[serde(rename = "continue")]
    pub proceed: bool,
}

impl ImageJobResumeResultV11 {
    /// The answer to a transfer's resume.
    pub fn transfer(transfer_id: &str, proceed: bool) -> Self {
        Self {
            transfer_id: Some(transfer_id.to_owned()),
            operation_id: None,
            attempt: None,
            proceed,
        }
    }

    /// The answer to a capture operation's resume.
    pub fn operation(operation_id: &str, attempt: u64, proceed: bool) -> Self {
        Self {
            transfer_id: None,
            operation_id: Some(operation_id.to_owned()),
            attempt: Some(attempt),
            proceed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageJobCancelV11 {
    pub transfer_id: String,
    pub reason: String,
    /// Set when refusing a capture's `image.upload.begin` (round-3 P2-4):
    /// only that capture's upload stops.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageReleaseV11 {
    pub fingerprint: String,
    pub image_owner_id: String,
    pub reason: ImageReleaseReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageCacheCensusAckV11 {
    pub page: u64,
}

/// Validation of server→daemon image frames (both encode and parse).
pub(crate) fn valid_server_image(message: &crate::ServerControlMessage) -> bool {
    use crate::ServerControlMessage as M;
    match message {
        M::ImageFetchGrant(g) => g.is_valid(),
        M::ImageFetchRefused(r) => valid_id(&r.request_id) && valid_code(&r.code),
        M::ImageServeRequest(r) => {
            valid_id(&r.transfer_id)
                && valid_id(&r.image_owner_id)
                && valid_image_fingerprint(&r.fingerprint)
                && valid_size(r.size_bytes)
                && r.part_size > 0
                && valid_links(&r.links)
        }
        M::ImagePublishRequest(r) => {
            valid_id(&r.transfer_id)
                && valid_id(&r.image_owner_id)
                && valid_image_fingerprint(&r.fingerprint)
        }
        M::ImageLinksGrant(g) => valid_id(&g.transfer_id) && valid_links(&g.links),
        M::ImageUploadGrant(g) => {
            valid_id(&g.transfer_id)
                && g.request_id.as_deref().is_none_or(valid_id)
                && (1..=IMAGE_UPLOAD_TTL_MAX_SECONDS).contains(&g.ttl_seconds)
                && valid_upload_part_urls(g.part_size, &g.parts)
                && g.encryption
                    .as_ref()
                    .is_none_or(ImageEncryptionV11::is_valid)
        }
        M::ImageJobResumeResult(r) => {
            valid_job_reference(&r.transfer_id, &r.operation_id, r.attempt)
        }
        M::ImageJobCancel(r) => {
            valid_id(&r.transfer_id)
                && valid_code(&r.reason)
                && r.request_id.as_deref().is_none_or(valid_id)
        }
        M::ImageRelease(r) => {
            valid_image_fingerprint(&r.fingerprint) && valid_id(&r.image_owner_id)
        }
        M::ImageCacheCensusAck(a) => a.page <= 4096,
        _ => true,
    }
}

/// Bounded presigned part URLs, each no larger than `part_size`.
pub(crate) fn valid_upload_part_urls(part_size: u64, parts: &[ImageUploadPartUrlV11]) -> bool {
    part_size > 0
        && parts.len() <= IMAGE_UPLOAD_PARTS_MAX
        && parts.iter().all(|p| {
            (1..=10_000).contains(&p.n)
                && valid_url(&p.url)
                && p.size_bytes > 0
                && p.size_bytes <= part_size
        })
}

pub(crate) fn valid_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= 64
        && code
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b == b'_' || b == b'.')
}

/// Validation of daemon→server image frames (both encode and parse).
pub(crate) fn valid_daemon_image(message: &crate::DaemonControlMessage) -> bool {
    use crate::DaemonControlMessage as M;
    match message {
        M::ImageFetchRequest(r) => r.is_valid(),
        M::ImageCached(r) => r.is_valid(),
        M::ImageEvicted(r) => r.is_valid(),
        M::ImageFetchFailed(r) => r.is_valid(),
        M::ImageCacheCensus(r) => r.is_valid(),
        M::ImageLinksRequest(r) => r.is_valid(),
        M::ImagePartAck(r) => r.is_valid(),
        M::ImageUploadBegin(r) => r.is_valid(),
        M::ImageUploadParts(r) => r.is_valid(),
        M::ImageUploadComplete(r) => valid_id(&r.transfer_id),
        M::ImageJobResume(r) => r.is_valid(),
        M::ImageJobFailed(r) => r.is_valid(),
        M::ImageUploadProgress(r) => r.is_valid(),
        M::ImageUploadRenew(r) => valid_id(&r.transfer_id),
        M::OperationProgress {
            progress: Some(p), ..
        } => {
            p.bytes_done.is_none_or(|b| b <= IMAGE_SIZE_MAX * 2)
                && p.bytes_total.is_none_or(|b| b <= IMAGE_SIZE_MAX * 2)
        }
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P2-11: node URLs are HTTPS, or HTTP only to a loopback host.
    #[test]
    fn node_urls_require_https_except_explicit_loopback() {
        for ok in [
            "https://bucket.example.com/k?X-Amz-Signature=x",
            "http://127.0.0.1:9000/b/k",
            "http://localhost:7070/k",
            "http://[::1]:9000/k",
        ] {
            assert!(valid_url(ok), "{ok}");
        }
        for bad in [
            "http://s3.example.com/k",
            "http://10.0.0.5:9000/k",
            "http://127.0.0.1.example.com/k",
            "http://user@127.0.0.1/k",
            "ftp://127.0.0.1/k",
            "http://localhost.evil.test/k",
        ] {
            assert!(!valid_url(bad), "{bad}");
        }
    }

    #[test]
    fn scrub_paths_are_normalized_absolute_and_glob_only_in_the_last_segment() {
        for ok in ["/home/user/.bash_history", "/etc/ssh/ssh_host_*", "/a"] {
            assert!(valid_scrub_path(ok), "{ok}");
        }
        for bad in [
            "", "/", "relative", "/a/../b", "/a/./b", "/a//b", "/a*/b", "/a/", "/a\0b",
        ] {
            assert!(!valid_scrub_path(bad), "{bad:?}");
        }
        assert!(!valid_scrub_path(&format!("/{}", "a".repeat(256))));
    }

    #[test]
    fn encrypted_length_adds_one_tag_per_record() {
        assert_eq!(encrypted_image_len(1), 17);
        assert_eq!(encrypted_image_len(1 << 20), (1 << 20) + 16);
        assert_eq!(encrypted_image_len((1 << 20) + 1), (1 << 20) + 1 + 32);
    }

    #[test]
    fn grant_debug_never_prints_urls_tokens_or_keys() {
        let grant = ImageFetchGrantV11 {
            request_id: "r1".into(),
            transfer_id: "t1".into(),
            mode: ImageTransferMode::S3,
            size_bytes: 10,
            part_size: 10,
            expires_at_unix_ms: 1,
            url: Some("https://bucket.example/obj?X-Amz-Signature=secretsig".into()),
            links: None,
            encryption: Some(ImageEncryptionV11 {
                scheme: IMAGE_ENCRYPTION_SCHEME.into(),
                key: "K".repeat(44),
            }),
        };
        let text = format!("{grant:?}");
        assert!(
            !text.contains("Signature") && !text.contains("KKKK"),
            "{text}"
        );
        let link = ImageRelayLinkV11 {
            part: 1,
            link_id: "l1".into(),
            token: "T".repeat(43),
        };
        assert!(!format!("{link:?}").contains("TTTT"));
        let upload = ImageUploadGrantV11 {
            transfer_id: "t".into(),
            request_id: None,
            part_size: 5,
            parts: vec![ImageUploadPartUrlV11 {
                n: 1,
                url: "https://x/?X-Amz-Signature=abc".into(),
                size_bytes: 5,
            }],
            expires_at_unix_ms: 1,
            ttl_seconds: 600,
            encryption: None,
        };
        assert!(!format!("{upload:?}").contains("Signature"));
    }
}
