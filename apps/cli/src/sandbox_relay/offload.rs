//! Stopped-sandbox disk offload on the node.
//!
//! On `disk.offload.request` the daemon publishes the stopped VM as an
//! aliased image (`wssp-off-<offloadId>`), exports it to staging, and
//! uploads it encrypted with the session key of `disk.upload.grant` through
//! the image upload part loop. `disk.offload.stored` ends the job: the
//! journal says `stored`, the alias image and staging are deleted, and the
//! daemon answers `disk.offload.released` (the server frees the host's
//! export slot only then). Every journal phase write goes through one
//! forward-only transition table ([`OffloadPhase::may_become`]).
//!
//! - **Journal.** `disk-offload.json` (0600, atomic rename,
//!   `deny_unknown_fields`) holds one entry per sandbox and never any key
//!   material. A restart resumes or fails each entry ([`OffloadService::recover`]).
//! - **Staging.** Before the publish, `min(diskGiB, usage × 1.05 + 64 MiB) × 2`
//!   is reserved against `image_cache_gib` (LRU eviction of unpinned cache
//!   images first), else `FAILED(staging_full)` and the disk stays local.
//! - **S6.** Offload images are never cache entries: they are never recorded
//!   in the cache journal, so no census, `image.cached` or `image.evicted`
//!   frame names them; they are counted as staging only.
//! - **Preemption.** A kill or reconnect of the sandbox cancels its offload
//!   and waits (bounded by `IMAGE_IO_TIMEOUT`) for an in-flight publish (F13).
//! - **Bandwidth.** `offload_upload_mbps` / `offload_fetch_mbps` pace the part
//!   loops ([`Bandwidth`]); one offload runs per host.

use anyhow::{Context, Result};
use sandbox_protocol::{
    DaemonControlMessage, DiskOffloadCancelV11, DiskOffloadFailedV11, DiskOffloadFailureCode,
    DiskOffloadInventoryEntryV11, DiskOffloadInventoryV11, DiskOffloadReleasedV11,
    DiskOffloadRequestV11, DiskOffloadStoredV11, DiskUploadBeginV11, DiskUploadCompleteV11,
    DiskUploadPartsV11, DiskUploadResumeV11, ImageFailureCode, ImageUploadPartUrlV11,
    SandboxErrorCode, ServerControlMessage,
};
use sandbox_runtime::SandboxRuntime;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::{Duration, Instant};

use super::images::{ImageError, ImageService, StagingReservation, crypto};

pub const OFFLOAD_JOURNAL_FILE: &str = "disk-offload.json";
/// Staging entries of offloads are named `offload-<offloadId>`.
const STAGING_PREFIX: &str = "offload-";
const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;
/// An upload that makes no progress (no part done, no new stored part
/// on a resume, no body byte on the wire) for this long ends
/// `Failed(Timeout)`, reported: the server's stall rule
/// (`OFFLOAD_UPLOAD_STALL_MS`) on the host's side.
const UPLOAD_GIVE_UP: Duration = Duration::from_secs(30 * 60);
/// First wait after a transient refusal (`rate_limited`,
/// `store_unavailable`, a `stale` resume answer); doubles to
/// `RESUME_BACKOFF_MAX`.
const RESUME_BACKOFF: Duration = Duration::from_secs(5);
const RESUME_BACKOFF_MAX: Duration = Duration::from_secs(60);
/// `disk.offload.cancel` reason for a refused repeated begin: not a cancel.
const UPLOAD_IN_PROGRESS: &str = "upload_in_progress";
/// `disk.offload.cancel` reason for a begin of an offload the server no
/// longer uploads.
const STALE: &str = "stale";
/// Transient `disk.offload.cancel` reasons: the job backs off and resumes
/// (or begins) again.
const RATE_LIMITED: &str = "rate_limited";
const STORE_UNAVAILABLE: &str = "store_unavailable";
/// The server refused to resume the upload: it is over for this host.
const RESUME_REFUSED: &str = "resume_refused";
/// Answers a running upload job reads itself (none of them ends it by
/// setting its cancel flag).
const JOB_ANSWERS: [&str; 4] = [STALE, RATE_LIMITED, STORE_UNAVAILABLE, RESUME_REFUSED];
/// `disk.offload.inventory` pages one session sends at most (the server's
/// `DISK_INVENTORY_PAGES_PER_SESSION`, of `DISK_INVENTORY_PAGES_PER_WINDOW`
/// per 10 minutes); a longer inventory continues on the
/// next session after the last entry reported.
const INVENTORY_PAGES_MAX: usize = 16;
/// Completion and inventory reconciliation on a live connection
/// ([`OffloadService::tick`]): a verdict lost on a stable connection (an
/// answer that never came, a frame evicted from a full outbox, an offload
/// the server's maintenance ended without telling the host) is asked again
/// this often, until local cleanup is done.
pub(super) const RECONCILE_EVERY: Duration = Duration::from_secs(600);

/// `RECONCILE_EVERY`, or a debug test daemon's shorter period
/// (`WSSP_TEST_DISK_TIMING`).
fn reconcile_every() -> Duration {
    super::test_timing::disk_test_timing().map_or(RECONCILE_EVERY, |t| t.reconcile)
}
/// A `disk.evicted` with no ack is re-sent this often (the server clears an
/// outlived grant 2 min after its 10 min lifetime).
const EVICTED_RESEND_EVERY: Duration = Duration::from_secs(60);
/// ... for this long after it was first sent. Past the grant's outlived
/// clearing a repeat can no longer be acked (e.g. the sandbox was restored
/// elsewhere meanwhile): the entry, whose VM is deleted and proven absent, is
/// forgotten (post-landing r2 #2; the server's census decides from the
/// roots this host reports).
const EVICTED_RESEND_FOR: Duration = Duration::from_secs(15 * 60);
/// A `disk.evict.request` with no answer stops blocking its sandbox (and a
/// pressure slot) after this long.
pub(super) const EVICT_ANSWER_WAIT: Duration = Duration::from_secs(600);
/// `disk.offload.cancel` reasons for a completion the server could not
/// take now (its grant budget, the store): an `uploaded` entry keeps its
/// staging and the next pass sends the completion again.
const RETRIED_COMPLETION: [&str; 2] = ["rate_limited", "store_unavailable"];

// ------------------------------------------------------------------ journal

/// Where an offload stands on this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OffloadPhase {
    /// Journaled before `incus publish`; a restart here inspects Incus.
    Exporting,
    /// The alias image is complete.
    Exported,
    /// The export is in staging with `stagedSha256`.
    Staged,
    /// `disk.upload.begin` was sent.
    Uploading,
    /// Every part is uploaded; waiting for `disk.offload.stored`.
    Uploaded,
    /// The server verified the stored object; alias and staging are gone.
    Stored,
    /// A `disk.evict.grant` is journaled (`evictGrantId`, its expiry): the
    /// VM is being deleted.
    Evicting,
    /// The VM is deleted and its root proven absent; `disk.evicted` was
    /// sent. The entry is dropped on the server's ack (T16).
    Evicted,
}

impl OffloadPhase {
    /// The stored copy is the server's: nothing local to resume or clean.
    pub fn stored(self) -> bool {
        matches!(self, Self::Stored | Self::Evicting | Self::Evicted)
    }

    fn rank(self) -> u8 {
        match self {
            Self::Exporting => 0,
            Self::Exported => 1,
            Self::Staged => 2,
            Self::Uploading => 3,
            Self::Uploaded => 4,
            Self::Stored => 5,
            Self::Evicting => 6,
            Self::Evicted => 7,
        }
    }

    /// The one transition table of a journaled offload: an
    /// entry only moves forward (`exporting → exported → staged →
    /// uploading → uploaded → stored`, any skip allowed), or rewrites its
    /// own phase. Eviction runs only from `stored` (`stored → evicting →
    /// evicted`), and its single way back is an expired grant (`evicting
    /// → stored`). Nothing ever leaves `stored` for an upload phase, so a
    /// resumed job or a late write of an upload step can never undo a
    /// stored ack.
    pub fn may_become(self, to: Self) -> bool {
        use OffloadPhase::*;
        match (self, to) {
            _ if self == to => true,
            (Stored, Evicting) | (Evicting, Evicted) | (Evicting, Stored) => true,
            (_, Evicting | Evicted) => false,
            _ => self.rank() < to.rank(),
        }
    }
}

/// What [`OffloadService::transition`] did with a journal write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Moved {
    /// Journaled.
    Applied,
    /// The journal already holds a later phase of this offload (e.g. the
    /// stored ack overtook the job): nothing written.
    Past,
    /// The journal holds no entry of this offload (forgotten, or another
    /// offload of the sandbox): nothing written.
    Gone,
}

/// One sandbox's offload. No key material, ever (§3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OffloadEntry {
    pub offload_id: String,
    pub seq: u64,
    pub generation: u64,
    pub phase: OffloadPhase,
    pub alias: String,
    /// Hex SHA-256 of the staged export (equals the fingerprint's hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub staged_sha256: Option<String>,
    /// The instance's `last_used_at` at the offload (§8.1 `expectDisk`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
    /// `volatile.cloud-init.instance-id` read at the publish; sent with
    /// `disk.upload.begin` (pinned at restore). An identifier, not a secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud_init_instance_id: Option<String>,
    /// The journaled eviction grant (phase `evicting` / `evicted`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evict_grant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evict_expires_at_unix_ms: Option<u64>,
    /// The upload session whose `disk.upload.complete` was sent (phase
    /// `uploaded`): re-sent until the offload has a verdict. An id, never a
    /// key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_session_id: Option<String>,
}

impl OffloadEntry {
    /// `sha256:<hex>` of the staged (and stored) image.
    pub fn fingerprint(&self) -> Option<String> {
        self.staged_sha256
            .as_ref()
            .map(|hex| format!("sha256:{hex}"))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OffloadJournalFile {
    version: u32,
    /// Keyed by sandbox id: one entry per sandbox.
    entries: BTreeMap<String, OffloadEntry>,
}

/// `disk-offload.json` next to the image cache journal.
#[derive(Debug)]
pub struct OffloadJournal {
    path: PathBuf,
    file: OffloadJournalFile,
}

impl OffloadJournal {
    pub fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir).with_context(|| format!("creating `{}`", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("securing `{}`", dir.display()))?;
        }
        let path = dir.join(OFFLOAD_JOURNAL_FILE);
        let file = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing `{}`", path.display()))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => OffloadJournalFile {
                version: 1,
                entries: BTreeMap::new(),
            },
            Err(error) => {
                return Err(error).with_context(|| format!("reading `{}`", path.display()));
            }
        };
        anyhow::ensure!(
            file.version == 1,
            "unsupported disk offload journal version"
        );
        Ok(Self { path, file })
    }

    /// Atomic replace (temp file 0600, fsync, rename, directory fsync).
    pub fn save(&self) -> Result<()> {
        let dir = self
            .path
            .parent()
            .context("disk offload journal has no directory")?;
        let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            tmp.as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        tmp.write_all(&serde_json::to_vec(&self.file)?)?;
        tmp.as_file().sync_all()?;
        tmp.persist(&self.path)?;
        std::fs::File::open(dir)?.sync_all()?;
        Ok(())
    }

    pub fn get(&self, sandbox_id: &str) -> Option<&OffloadEntry> {
        self.file.entries.get(sandbox_id)
    }

    pub fn entries(&self) -> impl Iterator<Item = (&String, &OffloadEntry)> {
        self.file.entries.iter()
    }

    pub fn put(&mut self, sandbox_id: &str, entry: OffloadEntry) -> Result<()> {
        self.file.entries.insert(sandbox_id.to_owned(), entry);
        self.save()
    }

    /// Remove the sandbox's entry if it is still `offload_id` and not
    /// stored (a job's or a cancel's cleanup never drops the
    /// server's stored copy).
    pub fn remove_unfinished(&mut self, sandbox_id: &str, offload_id: &str) -> Result<()> {
        if self
            .file
            .entries
            .get(sandbox_id)
            .is_some_and(|e| e.offload_id == offload_id && !e.phase.stored())
        {
            self.file.entries.remove(sandbox_id);
            self.save()?;
        }
        Ok(())
    }

    /// Remove the sandbox's entry if it is still `offload_id`.
    pub fn remove(&mut self, sandbox_id: &str, offload_id: &str) -> Result<()> {
        if self
            .file
            .entries
            .get(sandbox_id)
            .is_some_and(|e| e.offload_id == offload_id)
        {
            self.file.entries.remove(sandbox_id);
            self.save()?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------- bandwidth

/// A token bucket with a one-part burst: each paced chunk starts no earlier
/// than the previous chunk's slot at `bytes_per_sec` has ended, so the
/// average rate never exceeds the cap.
#[derive(Debug)]
pub struct Bandwidth {
    bytes_per_sec: u64,
    next: Mutex<Option<Instant>>,
}

impl Bandwidth {
    /// `None` (unlimited) for `None`.
    pub fn new(bytes_per_sec: Option<u64>) -> Option<Arc<Self>> {
        bytes_per_sec.filter(|&rate| rate > 0).map(|rate| {
            Arc::new(Self {
                bytes_per_sec: rate,
                next: Mutex::new(None),
            })
        })
    }

    /// Reserve a slot for `bytes` at `now`; returns how long to wait first.
    fn reserve_at(&self, bytes: u64, now: Instant) -> Duration {
        let mut next = self.next.lock().unwrap_or_else(|e| e.into_inner());
        let start = next.map_or(now, |at| at.max(now));
        let slot = Duration::from_secs_f64(bytes as f64 / self.bytes_per_sec as f64);
        *next = Some(start + slot);
        start.saturating_duration_since(now)
    }

    /// Wait for `bytes`' slot; false when `stop` asked to end meanwhile.
    pub fn pace(&self, bytes: u64, stop: &dyn Fn() -> bool) -> bool {
        let until = Instant::now() + self.reserve_at(bytes, Instant::now());
        while Instant::now() < until {
            if stop() {
                return false;
            }
            std::thread::sleep(
                until
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(250)),
            );
        }
        !stop()
    }
}

// ------------------------------------------------------------------ service

/// Local settings (TOML; a restart applies them).
#[derive(Debug, Clone, Default)]
pub struct OffloadSettings {
    pub upload_bytes_per_sec: Option<u64>,
    pub fetch_bytes_per_sec: Option<u64>,
    /// This daemon's host id: its offload images carry the owner tag
    /// derived from it (`offload_owner_tag`).
    pub host_id: String,
}

/// The owner tag of this daemon's offload aliases: the first
/// `OFFLOAD_OWNER_TAG_LEN` hex characters of SHA-256(host id). The image
/// store is shared by every daemon on the machine; the startup sweep
/// deletes only aliases carrying this tag.
pub fn offload_owner_tag(host_id: &str) -> String {
    let mut tag = super::journal::sha256_hex(host_id.as_bytes());
    tag.truncate(sandbox_runtime::OFFLOAD_OWNER_TAG_LEN);
    tag
}

/// What this host's journal knows about a sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalSandbox {
    /// The pinned root size (`allocation.diskGiB`).
    pub disk_gib: u32,
    /// A template-build VM (D1): never offloaded.
    pub build: bool,
}

pub type SandboxLookup = Arc<dyn Fn(&str) -> Option<LocalSandbox> + Send + Sync>;

#[derive(Debug)]
struct ActiveJob {
    offload_id: String,
    cancel: Arc<AtomicBool>,
    publishing: bool,
}

#[derive(Default)]
struct Forgets {
    pending: HashMap<String, String>,
    /// A drain thread is running (it clears this when `pending` is empty).
    draining: bool,
}

#[derive(Default)]
struct Jobs {
    active: HashMap<String, ActiveJob>,
    /// Kill/reconnect holds per sandbox: no publish starts under one.
    holds: HashMap<String, usize>,
    /// Staging held from the publish until `stored`, cancel or failure,
    /// keyed by offload id.
    reservations: HashMap<String, StagingReservation>,
    /// Stored-ack and release cleanups received but not yet finished (alias
    /// image and staging still held): a later request reserves only after
    /// them. The server frees the host's export slot only on
    /// `disk.offload.released`; this covers a cancel's cleanup.
    cleanups: usize,
}

struct Inner {
    images: ImageService,
    /// `offload_owner_tag` of this daemon's host id.
    owner_tag: String,
    runtime: Arc<dyn SandboxRuntime>,
    lookup: SandboxLookup,
    journal: Mutex<OffloadJournal>,
    jobs: Mutex<Jobs>,
    jobs_cv: Condvar,
    /// Data keys of delivered grants until their job takes them (wiped on
    /// drop; never journaled).
    keys: Mutex<HashMap<String, crypto::GrantKey>>,
    /// One offload job at a time on this host.
    slot: Mutex<()>,
    upload_limit: Option<Arc<Bandwidth>>,
    fetch_limit: Option<Arc<Bandwidth>>,
    grant_wait: Duration,
    publish_wait: Duration,
    poll: Duration,
    /// `UPLOAD_GIVE_UP` and `RESUME_BACKOFF` (shorter in tests).
    upload_timing: Mutex<(Duration, Duration)>,
    /// Eviction and discard (installed by `connect`).
    disks: std::sync::OnceLock<Arc<dyn LocalDisks>>,
    /// The server time relayed by the last `heartbeat.pong` (S11).
    server_time: Mutex<Option<(u64, Instant)>>,
    /// Sandboxes with a `disk.evict.request` awaiting its answer, since
    /// when (cleared on a new connection, expired after
    /// `EVICT_ANSWER_WAIT`).
    evict_pending: Mutex<HashMap<String, Instant>>,
    /// `disk.evicted` reports sent, by offload id, with when: re-sent
    /// until acked (a restart re-proves and re-reports instead).
    pub(super) evicted_sent: Mutex<HashMap<String, EvictedReport>>,
    /// The last completion and inventory pass (`tick`).
    last_reconcile: Mutex<Instant>,
    /// The last sandbox a truncated inventory reported: the next one
    /// continues after it.
    inventory_after: Mutex<Option<String>>,
    /// Confirmed-kill and destroying-expiry forgets not yet run, by
    /// sandbox (its stored offload id): at most one per journal entry.
    forgets: Mutex<Forgets>,
    /// Test seam: runs after a job's steps end, before it settles.
    #[cfg(test)]
    before_settle: Mutex<Option<Box<dyn Fn() + Send>>>,
}

/// A `disk.evicted` report kept for re-sending until acked.
pub(super) struct EvictedReport {
    pub(super) frame: sandbox_protocol::DiskEvictedV11,
    pub(super) first: Instant,
    pub(super) last: Instant,
}

/// The node's disk offload service (needs the image cache's staging,
/// outbox and upload loop).
#[derive(Clone)]
pub struct OffloadService {
    inner: Arc<Inner>,
}

/// Held by a kill or reconnect of the sandbox for its whole run: while
/// held, no offload of it publishes.
pub struct LifecycleHold {
    service: OffloadService,
    sandbox_id: String,
}

impl Drop for LifecycleHold {
    fn drop(&mut self) {
        let mut jobs = self.service.lock_jobs();
        if let Some(count) = jobs.holds.get_mut(&self.sandbox_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                jobs.holds.remove(&self.sandbox_id);
            }
        }
    }
}

/// Where a job starts.
enum Start {
    /// A new request: publish first.
    Publish,
    /// The alias image `fingerprint` is complete: export it.
    Export(String),
    /// The staged export `file` (`size` bytes) is verified: upload it.
    Upload(PathBuf, u64),
}

/// Why a job ended without `disk.upload.complete`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JobEnd {
    /// Cancelled by the server or preempted: cleaned up, nothing reported.
    Cancelled,
    Failed(DiskOffloadFailureCode),
    /// The server answered a resumed begin `stale`: the upload
    /// may already be verified. The entry waits `uploaded`, its staging
    /// held, for the server's verdict on a one-entry inventory.
    Unsettled,
}

fn failure_of(code: ImageFailureCode) -> JobEnd {
    match code {
        ImageFailureCode::Cancelled => JobEnd::Cancelled,
        ImageFailureCode::Timeout => JobEnd::Failed(DiskOffloadFailureCode::Timeout),
        ImageFailureCode::Corrupt => JobEnd::Failed(DiskOffloadFailureCode::Corrupt),
        _ => JobEnd::Failed(DiskOffloadFailureCode::Io),
    }
}

/// The reservation for one offload: `min(diskGiB, usage × 1.05 + 64 MiB) × 2`
/// (the Incus image plus its export copy), at most `diskGiB × 2` (F12).
pub fn staging_estimate(disk_gib: u32, root_usage: Option<u64>) -> u64 {
    let disk = u64::from(disk_gib).saturating_mul(GIB);
    let physical = root_usage.map_or(disk, |used| {
        used.saturating_add(used / 20).saturating_add(64 * MIB)
    });
    physical.min(disk).saturating_mul(2)
}

impl OffloadService {
    /// Open the journal next to the image cache and recover what a restart
    /// interrupted (in the background: recovery may wait on Incus).
    pub fn start(
        images: ImageService,
        runtime: Arc<dyn SandboxRuntime>,
        lookup: SandboxLookup,
        settings: OffloadSettings,
    ) -> Result<Self> {
        let service = Self::open(images, runtime, lookup, settings)?;
        let recovering = service.clone();
        std::thread::Builder::new()
            .name("wssp-offload-recover".into())
            .spawn(move || recovering.recover())
            .context("starting disk offload recovery")?;
        Ok(service)
    }

    fn open(
        images: ImageService,
        runtime: Arc<dyn SandboxRuntime>,
        lookup: SandboxLookup,
        settings: OffloadSettings,
    ) -> Result<Self> {
        Self::open_with(
            images,
            runtime,
            lookup,
            settings,
            (
                Duration::from_secs(300),
                sandbox_runtime::IMAGE_IO_TIMEOUT,
                Duration::from_secs(2),
            ),
        )
    }

    /// `timing`: the grant wait, the publish wait bound and the Incus poll.
    fn open_with(
        images: ImageService,
        runtime: Arc<dyn SandboxRuntime>,
        lookup: SandboxLookup,
        settings: OffloadSettings,
        timing: (Duration, Duration, Duration),
    ) -> Result<Self> {
        let journal = OffloadJournal::open(&images.state_dir())?;
        Ok(Self {
            inner: Arc::new(Inner {
                images,
                owner_tag: offload_owner_tag(&settings.host_id),
                runtime,
                lookup,
                journal: Mutex::new(journal),
                jobs: Mutex::new(Jobs::default()),
                jobs_cv: Condvar::new(),
                keys: Mutex::new(HashMap::new()),
                slot: Mutex::new(()),
                upload_limit: Bandwidth::new(settings.upload_bytes_per_sec),
                fetch_limit: Bandwidth::new(settings.fetch_bytes_per_sec),
                grant_wait: timing.0,
                publish_wait: timing.1,
                poll: timing.2,
                upload_timing: Mutex::new((UPLOAD_GIVE_UP, RESUME_BACKOFF)),
                disks: std::sync::OnceLock::new(),
                server_time: Mutex::new(None),
                evict_pending: Mutex::new(HashMap::new()),
                evicted_sent: Mutex::new(HashMap::new()),
                last_reconcile: Mutex::new(Instant::now()),
                inventory_after: Mutex::new(None),
                forgets: Mutex::new(Forgets::default()),
                #[cfg(test)]
                before_settle: Mutex::new(None),
            }),
        })
    }

    /// Tests: the no-progress deadline and the first backoff step.
    #[cfg(test)]
    pub(crate) fn set_upload_timing_for_test(&self, give_up: Duration, backoff: Duration) {
        *self
            .inner
            .upload_timing
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = (give_up, backoff);
    }

    /// The restore fetch pace (`offload_fetch_mbps`; applied by the restore
    /// fetch, offload plan C6).
    pub fn fetch_limit(&self) -> Option<Arc<Bandwidth>> {
        self.inner.fetch_limit.clone()
    }

    fn lock_jobs(&self) -> std::sync::MutexGuard<'_, Jobs> {
        self.inner.jobs.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn lock_keys(&self) -> std::sync::MutexGuard<'_, HashMap<String, crypto::GrantKey>> {
        self.inner.keys.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn lock_journal(&self) -> std::sync::MutexGuard<'_, OffloadJournal> {
        self.inner.journal.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The journaled entry of `sandbox_id`.
    pub fn entry(&self, sandbox_id: &str) -> Option<OffloadEntry> {
        self.lock_journal().get(sandbox_id).cloned()
    }

    /// The only writer of a journal entry's phase: `entry`
    /// (its phase is the target) is journaled only when the entry in the
    /// journal is the same offload and [`OffloadPhase::may_become`] allows
    /// the move, or, for a new offload's first `exporting` write, when the
    /// journal holds no entry of that offload. Check and write happen under
    /// the journal lock, so a job, the stored ack, a cancel's cleanup and
    /// the eviction can interleave in any order.
    fn transition(&self, sandbox_id: &str, entry: &OffloadEntry) -> Result<Moved, JobEnd> {
        let mut journal = self.lock_journal();
        match journal.get(sandbox_id) {
            Some(current) if current.offload_id == entry.offload_id => {
                if !current.phase.may_become(entry.phase) {
                    return Ok(Moved::Past);
                }
            }
            _ if entry.phase == OffloadPhase::Exporting => {}
            _ => return Ok(Moved::Gone),
        }
        journal.put(sandbox_id, entry.clone()).map_err(|error| {
            tracing::warn!(reason = %format!("{error:#}"), "disk offload journal save failed");
            JobEnd::Failed(DiskOffloadFailureCode::Io)
        })?;
        Ok(Moved::Applied)
    }

    /// A job step's write: anything but `Applied` ends the job (cancelled;
    /// its cleanup keeps a stored entry).
    fn job_step(&self, sandbox_id: &str, entry: &OffloadEntry) -> Result<(), JobEnd> {
        match self.transition(sandbox_id, entry)? {
            Moved::Applied => Ok(()),
            Moved::Past | Moved::Gone => Err(JobEnd::Cancelled),
        }
    }

    /// Whether the journal holds a stored phase of `offload_id`.
    fn is_stored(&self, sandbox_id: &str, offload_id: &str) -> bool {
        self.entry(sandbox_id)
            .is_some_and(|e| e.offload_id == offload_id && e.phase.stored())
    }

    fn journal_remove(&self, sandbox_id: &str, offload_id: &str) {
        if let Err(error) = self.lock_journal().remove(sandbox_id, offload_id) {
            tracing::warn!(reason = %format!("{error:#}"), "disk offload journal save failed");
        }
    }

    fn journal_remove_unfinished(&self, sandbox_id: &str, offload_id: &str) {
        if let Err(error) = self
            .lock_journal()
            .remove_unfinished(sandbox_id, offload_id)
        {
            tracing::warn!(reason = %format!("{error:#}"), "disk offload journal save failed");
        }
    }

    /// `disk.offload.released`: nothing of this offload is held
    /// here any more; the server frees the host's export slot only now.
    fn report_released(&self, sandbox_id: &str, offload_id: &str, seq: u64) {
        self.push(DaemonControlMessage::DiskOffloadReleased(
            DiskOffloadReleasedV11 {
                sandbox_id: sandbox_id.to_owned(),
                offload_id: offload_id.to_owned(),
                seq,
                report_id: None,
            },
        ));
    }

    fn push(&self, message: DaemonControlMessage) {
        self.inner.images.push_frame(message);
    }

    fn report_failed(
        &self,
        sandbox_id: &str,
        offload_id: &str,
        seq: u64,
        code: DiskOffloadFailureCode,
    ) {
        tracing::info!(sandbox_id, offload_id, code = ?code, "disk offload failed on this host");
        self.push(DaemonControlMessage::DiskOffloadFailed(
            DiskOffloadFailedV11 {
                sandbox_id: sandbox_id.to_owned(),
                offload_id: offload_id.to_owned(),
                seq,
                code,
                report_id: None,
            },
        ));
    }

    fn staging_path(&self, offload_id: &str) -> PathBuf {
        self.inner
            .images
            .staging_dir()
            .join(format!("{STAGING_PREFIX}{offload_id}"))
    }

    /// Route one server→daemon disk frame.
    pub fn handle_server(&self, frame: ServerControlMessage) {
        match frame {
            ServerControlMessage::DiskOffloadRequest(request) => {
                let service = self.clone();
                let _ = std::thread::Builder::new()
                    .name("wssp-offload".into())
                    .spawn(move || service.on_request(request));
            }
            ServerControlMessage::DiskOffloadStored(stored) => {
                // Counted before the next frame is routed: a request that
                // follows this ack reserves only once its cleanup is done.
                self.spawn_cleanup("wssp-offload-stored", move |service| {
                    service.on_stored(&stored)
                });
            }
            ServerControlMessage::DiskOffloadCancel(cancel) => self.on_cancel(&cancel),
            ServerControlMessage::DiskUploadGrant(mut grant) => {
                // The receive site (§3): the data key (a session's first
                // grant only) leaves the frame at once into a wiped buffer
                // the job takes; the frame itself travels on without it.
                let stash = stash_key(&grant.offload_id, grant.seq, &grant.session_id);
                if let Some(encryption) = grant.encryption.as_mut() {
                    let key = crypto::take_grant_key(encryption);
                    self.lock_keys().insert(stash.clone(), key);
                }
                let route = grant_key(&grant.offload_id, grant.seq);
                let offload_id = grant.offload_id.clone();
                if !self
                    .inner
                    .images
                    .deliver_to(&route, ServerControlMessage::DiskUploadGrant(grant))
                {
                    // No offload waits for it: the key is wiped now.
                    self.lock_keys().remove(&stash);
                    tracing::debug!(offload_id = %offload_id, "disk upload grant with no waiting offload");
                }
            }
            ServerControlMessage::DiskUploadResumed(resumed) => {
                let route = grant_key(&resumed.offload_id, resumed.seq);
                if !self
                    .inner
                    .images
                    .deliver_to(&route, ServerControlMessage::DiskUploadResumed(resumed))
                {
                    tracing::debug!("disk upload resume answer with no waiting offload");
                }
            }
            ServerControlMessage::DiskEvictSuggest(suggest) => {
                self.request_eviction(&suggest.sandbox_id, &suggest.offload_id, suggest.seq)
            }
            ServerControlMessage::DiskEvictRefused(refused) => self.on_evict_refused(&refused),
            ServerControlMessage::DiskEvictGrant(grant) => {
                let service = self.clone();
                let _ = std::thread::Builder::new()
                    .name("wssp-offload-evict".into())
                    .spawn(move || service.on_evict_grant(&grant));
            }
            ServerControlMessage::DiskDiscard(discard) => {
                let service = self.clone();
                let _ = std::thread::Builder::new()
                    .name("wssp-offload-discard".into())
                    .spawn(move || service.on_discard(&discard));
            }
            _ => {}
        }
    }

    /// A kill or reconnect of `sandbox_id` (§7, F13): cancel its unfinished
    /// offload and, while Incus still publishes it, wait (bounded by
    /// `IMAGE_IO_TIMEOUT` and `still_wanted`). The hold keeps any new
    /// publish of the sandbox out until dropped. A `stored` copy is kept.
    pub fn preempt(
        &self,
        sandbox_id: &str,
        still_wanted: &dyn Fn() -> bool,
    ) -> Result<LifecycleHold, ImageError> {
        let hold = {
            let mut jobs = self.lock_jobs();
            *jobs.holds.entry(sandbox_id.to_owned()).or_insert(0) += 1;
            if let Some(job) = jobs.active.get(sandbox_id) {
                job.cancel.store(true, Ordering::SeqCst);
            }
            LifecycleHold {
                service: self.clone(),
                sandbox_id: sandbox_id.to_owned(),
            }
        };
        let deadline = Instant::now() + self.inner.publish_wait;
        let mut jobs = self.lock_jobs();
        while jobs
            .active
            .get(sandbox_id)
            .is_some_and(|job| job.publishing)
        {
            if !still_wanted() {
                return Err(ImageError::new(
                    SandboxErrorCode::Cancelled,
                    "cancelled while the disk offload publish ran",
                ));
            }
            if Instant::now() >= deadline {
                return Err(ImageError::new(
                    SandboxErrorCode::Timeout,
                    "disk offload publish still running",
                ));
            }
            let (guard, _) = self
                .inner
                .jobs_cv
                .wait_timeout(jobs, Duration::from_millis(250))
                .unwrap_or_else(|e| e.into_inner());
            jobs = guard;
        }
        let idle = !jobs.active.contains_key(sandbox_id);
        drop(jobs);
        // An unfinished entry with no running job (e.g. uploaded, awaiting
        // `stored`) is superseded by the server's admission: clean it up.
        if idle
            && let Some(entry) = self.entry(sandbox_id)
            && !entry.phase.stored()
        {
            self.cleanup(sandbox_id, &entry);
        }
        Ok(hold)
    }

    fn on_request(&self, request: DiskOffloadRequestV11) {
        let sandbox_id = request.sandbox_id.as_str();
        let fail = |code| self.report_failed(sandbox_id, &request.offload_id, request.seq, code);
        // A repeated request for the offload in hand changes nothing.
        if self
            .entry(sandbox_id)
            .is_some_and(|e| e.offload_id == request.offload_id)
        {
            return;
        }
        let Some(local) = (self.inner.lookup)(sandbox_id) else {
            return fail(DiskOffloadFailureCode::InstanceMissing);
        };
        if local.build {
            // D1: a template-build VM never leaves its host.
            return fail(DiskOffloadFailureCode::Io);
        }
        let Ok(alias) = sandbox_runtime::offload_alias(&self.inner.owner_tag, &request.offload_id)
        else {
            return fail(DiskOffloadFailureCode::Io);
        };
        // A newer request supersedes an older unfinished offload here.
        if let Some(old) = self.entry(sandbox_id) {
            let cancelled = self
                .lock_jobs()
                .active
                .get(sandbox_id)
                .map(|job| job.cancel.store(true, Ordering::SeqCst))
                .is_some();
            if !cancelled {
                self.forget(sandbox_id, &old);
            }
        }
        let entry = OffloadEntry {
            offload_id: request.offload_id.clone(),
            seq: request.seq,
            generation: request.generation,
            phase: OffloadPhase::Exporting,
            alias,
            staged_sha256: None,
            last_used_at: None,
            cloud_init_instance_id: None,
            evict_grant_id: None,
            evict_expires_at_unix_ms: None,
            upload_session_id: None,
        };
        self.run_job(sandbox_id, entry, Start::Publish, Some(local.disk_gib));
    }

    /// Run one job to `disk.upload.complete`, or clean up and (unless
    /// cancelled) report `disk.offload.failed`.
    fn run_job(&self, sandbox_id: &str, entry: OffloadEntry, start: Start, disk_gib: Option<u32>) {
        let cancel = Arc::new(AtomicBool::new(false));
        {
            let mut jobs = self.lock_jobs();
            if jobs.active.contains_key(sandbox_id) {
                // The superseded job is still unwinding: wait for it.
                while jobs.active.contains_key(sandbox_id) {
                    let (guard, _) = self
                        .inner
                        .jobs_cv
                        .wait_timeout(jobs, Duration::from_millis(250))
                        .unwrap_or_else(|e| e.into_inner());
                    jobs = guard;
                }
            }
            jobs.active.insert(
                sandbox_id.to_owned(),
                ActiveJob {
                    offload_id: entry.offload_id.clone(),
                    cancel: cancel.clone(),
                    publishing: false,
                },
            );
        }
        let outcome = {
            let _slot = self.inner.slot.lock().unwrap_or_else(|e| e.into_inner());
            self.job_steps(sandbox_id, entry.clone(), start, disk_gib, &cancel)
        };
        #[cfg(test)]
        if let Some(hook) = self
            .inner
            .before_settle
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            hook();
        }
        // Clean up before the job leaves `active`: a superseding job of the
        // same sandbox starts only once this one's leftovers are gone.
        // A stored entry (the ack overtook this job) is never removed or
        // reported failed: only its leftovers go.
        let settled = match outcome {
            Ok(()) | Err(JobEnd::Unsettled) => true,
            Err(end) => {
                self.cleanup(sandbox_id, &entry);
                if let JobEnd::Failed(code) = end
                    && !self.is_stored(sandbox_id, &entry.offload_id)
                {
                    self.report_failed(sandbox_id, &entry.offload_id, entry.seq, code);
                }
                false
            }
        };
        // A terminal server answer (`released`, a cancel, the
        // stored ack, a preemption) that lands while this job is still in
        // `active` finds no waiter any more once the job's waits are over:
        // `on_cancel` only records it on the job's `cancel` flag. The flag
        // is set, and the job leaves `active`, under the jobs lock, so an
        // answer either is seen here (and its cleanup runs) or finds no job
        // and cleans up itself. A settled job never drops one.
        let mut cleaned = !settled;
        loop {
            let mut jobs = self.lock_jobs();
            let ours = jobs
                .active
                .get(sandbox_id)
                .is_some_and(|job| job.offload_id == entry.offload_id);
            if ours && !cleaned && cancel.load(Ordering::SeqCst) {
                drop(jobs);
                // Keeps a stored entry (the ack's): only leftovers go.
                self.cleanup(sandbox_id, &entry);
                cleaned = true;
                continue;
            }
            if ours {
                jobs.active.remove(sandbox_id);
            }
            break;
        }
        self.inner.jobs_cv.notify_all();
    }

    fn job_steps(
        &self,
        sandbox_id: &str,
        mut entry: OffloadEntry,
        start: Start,
        disk_gib: Option<u32>,
        cancel: &Arc<AtomicBool>,
    ) -> Result<(), JobEnd> {
        let instance = sandbox_runtime::default_incus_instance_name(sandbox_id);
        let stopped = || {
            if cancel.load(Ordering::SeqCst) {
                Err(JobEnd::Cancelled)
            } else {
                Ok(())
            }
        };
        stopped()?;
        // A stored ack or release received before this request frees its
        // staging first.
        self.wait_for_cleanups();
        // Staging first (F12): nothing is published that cannot be staged.
        let estimate = match &start {
            Start::Upload(_, size) => size.saturating_mul(2),
            _ => {
                let usage = self
                    .inner
                    .runtime
                    .instance_root_usage(&instance)
                    .unwrap_or(None);
                let disk = disk_gib.unwrap_or_else(|| {
                    sandbox_protocol::vm_size_limits()
                        .map(|limits| limits.disk_gi_b_default)
                        .unwrap_or(20)
                });
                staging_estimate(disk, usage)
            }
        };
        self.reserve(&entry.offload_id, estimate)?;
        let staged = match &start {
            Start::Upload(file, size) => Some((file.clone(), *size)),
            _ => None,
        };
        let fingerprint = match start {
            Start::Publish => {
                self.job_step(sandbox_id, &entry)?;
                entry.last_used_at = self
                    .inner
                    .runtime
                    .instance_last_used(&instance)
                    .unwrap_or_else(|error| {
                        tracing::warn!(sandbox_id, code = ?error.code, "instance last-used time unavailable");
                        None
                    });
                // [unverified] readability: an unreadable or malformed id
                // is simply not sent (restore then lets Incus pick one).
                entry.cloud_init_instance_id = self
                    .inner
                    .runtime
                    .cloud_init_instance_id(&instance)
                    .ok()
                    .flatten()
                    .filter(|id| sandbox_protocol::valid_cloud_init_instance_id(id));
                tracing::debug!(
                    sandbox_id,
                    cloud_init_instance_id = entry.cloud_init_instance_id.is_some(),
                    "disk offload instance facts read"
                );
                let fingerprint = self.publish(sandbox_id, &instance, &entry.alias, cancel)?;
                entry.phase = OffloadPhase::Exported;
                self.job_step(sandbox_id, &entry)?;
                Some(fingerprint)
            }
            Start::Export(fingerprint) => Some(fingerprint),
            Start::Upload(..) => None,
        };
        let (file, size) = match (fingerprint, staged) {
            (Some(fingerprint), _) => {
                stopped()?;
                let dir = self.staging_path(&entry.offload_id);
                let _ = std::fs::remove_dir_all(&dir);
                std::fs::create_dir_all(&dir)
                    .map_err(|_| JobEnd::Failed(DiskOffloadFailureCode::Io))?;
                if let Some(reservation) = self.lock_jobs().reservations.get_mut(&entry.offload_id)
                {
                    reservation.own(dir.clone());
                }
                let (file, size) = self
                    .inner
                    .images
                    .export_into(&fingerprint, &dir)
                    .map_err(failure_of)?;
                entry.staged_sha256 = Some(fingerprint[7..].to_owned());
                entry.phase = OffloadPhase::Staged;
                self.job_step(sandbox_id, &entry)?;
                (file, size)
            }
            (None, Some(staged)) => staged,
            (None, None) => return Err(JobEnd::Failed(DiskOffloadFailureCode::Io)),
        };
        self.upload(sandbox_id, entry, &file, size, cancel)
    }

    /// Hold the staging bytes for this offload until it ends.
    fn reserve(&self, offload_id: &str, bytes: u64) -> Result<(), JobEnd> {
        let key = format!("{STAGING_PREFIX}{offload_id}");
        let mut reservation = match self.inner.images.reserve(&key, bytes) {
            Ok(reservation) => reservation,
            Err(error) if error.code == SandboxErrorCode::ImageCacheFull => {
                return Err(JobEnd::Failed(DiskOffloadFailureCode::StagingFull));
            }
            Err(_) => return Err(JobEnd::Failed(DiskOffloadFailureCode::Io)),
        };
        let dir = self.staging_path(offload_id);
        if dir.exists() {
            reservation.own(dir);
        }
        self.lock_jobs()
            .reservations
            .insert(offload_id.to_owned(), reservation);
        Ok(())
    }

    fn publish(
        &self,
        sandbox_id: &str,
        instance: &str,
        alias: &str,
        cancel: &Arc<AtomicBool>,
    ) -> Result<String, JobEnd> {
        {
            let mut jobs = self.lock_jobs();
            if cancel.load(Ordering::SeqCst) {
                return Err(JobEnd::Cancelled);
            }
            // A kill or reconnect of the sandbox runs: refuse this offload
            // (the server retries under a new id once it is stopped again).
            if jobs.holds.contains_key(sandbox_id) {
                return Err(JobEnd::Failed(DiskOffloadFailureCode::Cancelled));
            }
            if let Some(job) = jobs.active.get_mut(sandbox_id) {
                job.publishing = true;
            }
        }
        let published = self.inner.runtime.publish_stopped_instance(instance, alias);
        {
            let mut jobs = self.lock_jobs();
            if let Some(job) = jobs.active.get_mut(sandbox_id) {
                job.publishing = false;
            }
        }
        self.inner.jobs_cv.notify_all();
        match published {
            Ok(published) => {
                if cancel.load(Ordering::SeqCst) {
                    return Err(JobEnd::Cancelled);
                }
                Ok(published.fingerprint)
            }
            Err(error) => Err(match error.code {
                SandboxErrorCode::SandboxNotFound => {
                    JobEnd::Failed(DiskOffloadFailureCode::InstanceMissing)
                }
                SandboxErrorCode::StateConflict | SandboxErrorCode::SandboxNotRunning => {
                    JobEnd::Failed(DiskOffloadFailureCode::NotStopped)
                }
                SandboxErrorCode::Timeout => JobEnd::Failed(DiskOffloadFailureCode::Timeout),
                _ => JobEnd::Failed(DiskOffloadFailureCode::Io),
            }),
        }
    }

    /// `disk.upload.begin`, then each grant's parts until every byte is up;
    /// journals `uploaded` with the completed session's id.
    fn upload(
        &self,
        sandbox_id: &str,
        mut entry: OffloadEntry,
        file: &Path,
        size: u64,
        cancel: &Arc<AtomicBool>,
    ) -> Result<(), JobEnd> {
        let fingerprint = entry
            .fingerprint()
            .ok_or(JobEnd::Failed(DiskOffloadFailureCode::Io))?;
        entry.phase = OffloadPhase::Uploading;
        self.job_step(sandbox_id, &entry)?;
        let key = grant_key(&entry.offload_id, entry.seq);
        let rx = self.inner.images.register_stamped_waiter(&key);
        let result = self.upload_with(sandbox_id, &entry, &fingerprint, file, size, cancel, &rx);
        self.inner.images.unregister_waiter(&key);
        let unsettled = match result {
            Ok(session) => {
                // Journaled with `uploaded` before the completion is sent
                // (post-landing r1 #2): every answer to it finds the entry,
                // and the completion is re-sent from it until the offload
                // has a verdict (`resend_completions`).
                entry.upload_session_id = Some(session);
                false
            }
            Err(JobEnd::Unsettled) => true,
            Err(end) => return Err(end),
        };
        // Every part is up, or the server's verdict is pending: `uploaded`.
        // A stored ack that overtook this write keeps `stored` (Past).
        entry.phase = OffloadPhase::Uploaded;
        match (self.transition(sandbox_id, &entry)?, unsettled) {
            (Moved::Applied, false) => {
                if let Some(session_id) = entry.upload_session_id.clone() {
                    self.push(DaemonControlMessage::DiskUploadComplete(
                        DiskUploadCompleteV11 {
                            sandbox_id: sandbox_id.to_owned(),
                            offload_id: entry.offload_id.clone(),
                            seq: entry.seq,
                            session_id,
                        },
                    ));
                }
                Ok(())
            }
            (_, false) => Ok(()),
            (Moved::Applied, true) => {
                // Ask for the verdict: `stored`, `released`, or (still
                // verifying) the scheduler's stored ack later.
                self.push(DaemonControlMessage::DiskOffloadInventory(
                    DiskOffloadInventoryV11 {
                        entries: vec![DiskOffloadInventoryEntryV11 {
                            sandbox_id: sandbox_id.to_owned(),
                            offload_id: entry.offload_id.clone(),
                            seq: entry.seq,
                        }],
                    },
                ));
                Err(JobEnd::Unsettled)
            }
            // The ack overtook the job (or the entry was forgotten): its
            // cleanup frees the staging and keeps a stored entry.
            (Moved::Past | Moved::Gone, true) => Err(JobEnd::Cancelled),
        }
    }

    /// The upload of one staged export: `disk.upload.begin`, then each
    /// window's parts until every part is up. Returns the session id.
    ///
    /// A session's parts are reported only on the relay connection its
    /// transfer is bound to (`bound`: the one its first grant, or its last
    /// `disk.upload.resumed`, came on; `ImageService::push_on`). After a
    /// connection change the job resumes the session explicitly on the new
    /// connection (`disk.upload.resume`) and continues from the server's
    /// stored parts (the object store's listing), never from its own memory.
    /// A refused resume ends the job `Failed(ResumeRefused)`; no progress for
    /// `UPLOAD_GIVE_UP` ends it `Failed(Timeout)`: both are reported.
    #[allow(clippy::too_many_arguments)]
    fn upload_with(
        &self,
        sandbox_id: &str,
        entry: &OffloadEntry,
        fingerprint: &str,
        path: &Path,
        size: u64,
        cancel: &Arc<AtomicBool>,
        rx: &mpsc::Receiver<super::images::Routed>,
    ) -> Result<String, JobEnd> {
        let images = &self.inner.images;
        let (give_up, backoff_base) = *self
            .inner
            .upload_timing
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut file =
            std::fs::File::open(path).map_err(|_| JobEnd::Failed(DiskOffloadFailureCode::Io))?;
        let begin = DaemonControlMessage::DiskUploadBegin(DiskUploadBeginV11 {
            sandbox_id: sandbox_id.to_owned(),
            generation: entry.generation,
            offload_id: entry.offload_id.clone(),
            seq: entry.seq,
            fingerprint: fingerprint.to_owned(),
            size_bytes: size,
            unpacked_bytes: None,
            format: "unified".into(),
            cloud_init_instance_id: entry.cloud_init_instance_id.clone(),
        });
        let stored_size = sandbox_protocol::encrypted_image_len(size);
        // The no-progress deadline: moved by a finished window, a resume
        // that finds more parts stored, and body bytes on the wire.
        let progress = std::cell::Cell::new(Instant::now());
        let expired = || progress.get().elapsed() >= give_up;
        let stopped = || cancel.load(Ordering::SeqCst);
        // The connection the frame being answered was queued for: a begin
        // (like a resume) is sent only there (`push_on`; a reconnect purges
        // it), so its grant, the one frame with the session's key, is never
        // read as another connection's answer.
        let send_begin = |waiting_on: &mut u64| {
            let on = images.connection();
            images.push_on(on, begin.clone());
            *waiting_on = on;
        };
        let mut waiting_on = 0;
        send_begin(&mut waiting_on);
        let mut session: Option<UploadSession> = None;
        // Uploaded (or, after a resume, stored) parts by number, with their
        // bytes: completion counts distinct parts, never bytes sent.
        let mut done: BTreeMap<u32, u64> = BTreeMap::new();
        let mut step = Step::Wait;
        let mut backoff = Backoff::new(backoff_base);
        // The staging is re-hashed once per entry into a resume after
        // progress (§3 nonce safety: the same key never seals other bytes).
        let mut rehashed = false;
        // Liveness for the server's stall rule (`image.upload.progress`, at
        // most every 30 s while bytes move): one per transfer, across its
        // windows, so its counts only grow.
        let mut heartbeat: Option<super::images::UploadHeartbeat> = None;
        // The transfer this job runs: its cancel is kept meanwhile.
        let mut _running: Option<super::images::RunningTransfer> = None;
        loop {
            if stopped() {
                return Err(JobEnd::Cancelled);
            }
            if expired() {
                tracing::warn!(offload_id = %entry.offload_id, "disk upload made no progress; giving up");
                return Err(JobEnd::Failed(DiskOffloadFailureCode::Timeout));
            }
            match std::mem::replace(&mut step, Step::Wait) {
                Step::Wait => {
                    let on = waiting_on;
                    let wanted = || !stopped() && !expired() && images.connection() == on;
                    let routed = wait_routed(rx, self.inner.grant_wait, &wanted, self.inner.poll);
                    if stopped() {
                        return Err(JobEnd::Cancelled);
                    }
                    let Some(routed) = routed else {
                        if expired() {
                            continue;
                        }
                        if session.is_some() {
                            // A lost grant, or the connection moved.
                            step = Step::Resume;
                        } else if images.connection() != on {
                            // The begin (or its grant) went with the old
                            // connection: begin again on the new one (a
                            // session of the old one is superseded).
                            if !self.wait_connected(&stopped, &expired) {
                                continue;
                            }
                            send_begin(&mut waiting_on);
                        } else {
                            return Err(JobEnd::Failed(DiskOffloadFailureCode::Timeout));
                        }
                        continue;
                    };
                    if routed.connection() != on {
                        // An answer to a frame of an older connection.
                        self.discard(routed.into_frame(), entry);
                        continue;
                    }
                    match routed.into_frame() {
                        ServerControlMessage::DiskUploadGrant(grant) => {
                            let held = session.as_ref().is_some_and(|s| s.id == grant.session_id);
                            let key = self.lock_keys().remove(&stash_key(
                                &entry.offload_id,
                                entry.seq,
                                &grant.session_id,
                            ));
                            if !held {
                                // I13: a new session's first grant carries its
                                // key; a disk never leaves this host
                                // unencrypted.
                                let valid = grant.encryption.as_ref().is_some_and(|e| {
                                    e.scheme == sandbox_protocol::IMAGE_ENCRYPTION_SCHEME
                                });
                                let record_key = key
                                    .filter(|_| valid)
                                    .and_then(|text| crypto::RecordKey::from_base64(&text).ok());
                                let Some(record_key) = record_key else {
                                    tracing::warn!(offload_id = %entry.offload_id, "disk upload grant refused: no valid encryption");
                                    return Err(JobEnd::Failed(DiskOffloadFailureCode::Io));
                                };
                                // A new session (the server superseded the old
                                // one) starts from byte 0 under its own key.
                                session = Some(UploadSession {
                                    id: grant.session_id.clone(),
                                    transfer: grant.transfer_id.clone(),
                                    key: record_key,
                                    bound: on,
                                });
                                done.clear();
                                rehashed = false;
                            }
                            // A key on a held session's grant is wiped unused
                            // (dropped above): the held key is never replaced.
                            step = Step::Window(grant.part_size, grant.parts);
                        }
                        ServerControlMessage::DiskOffloadCancel(c) => match c.reason.as_str() {
                            UPLOAD_IN_PROGRESS => {}
                            // A `stale` answer to the begin itself (no session
                            // yet): this offload may be past uploading on the
                            // server (review r3: an upload whose complete went
                            // out before a crash).
                            STALE if session.is_none() => return Err(JobEnd::Unsettled),
                            STALE => step = Step::Resume,
                            RATE_LIMITED | STORE_UNAVAILABLE => {
                                self.back_off(&mut backoff, &stopped, &expired);
                                if session.is_some() {
                                    step = Step::Resume;
                                } else if self.wait_connected(&stopped, &expired) {
                                    send_begin(&mut waiting_on);
                                }
                            }
                            RESUME_REFUSED => {
                                return Err(JobEnd::Failed(DiskOffloadFailureCode::ResumeRefused));
                            }
                            // The server ended the offload (its row says so).
                            _ => return Err(JobEnd::Cancelled),
                        },
                        _ => {}
                    }
                }
                Step::Window(part_size, parts) => {
                    let Some(s) = &session else {
                        return Err(JobEnd::Failed(DiskOffloadFailureCode::Io));
                    };
                    if heartbeat
                        .as_ref()
                        .is_none_or(|h| h.transfer_id() != s.transfer.as_str())
                    {
                        heartbeat = Some(images.upload_heartbeat(&s.transfer));
                        _running = Some(images.run_transfer(&s.transfer));
                    }
                    let wire =
                        std::cell::Cell::new(heartbeat.as_ref().map_or(0, |h| h.wire_bytes()));
                    let stop = || {
                        // Body bytes moving count as progress.
                        let now = heartbeat.as_ref().map_or(0, |h| h.wire_bytes());
                        if now != wire.get() {
                            wire.set(now);
                            progress.set(Instant::now());
                        }
                        stopped() || images.transfer_cancelled(&s.transfer) || expired()
                    };
                    let put = images.put_parts(
                        &mut file,
                        size,
                        part_size,
                        &parts,
                        Some(&s.key),
                        self.inner.upload_limit.as_deref(),
                        &stop,
                        heartbeat.as_ref(),
                    );
                    let uploaded = match put {
                        Ok((uploaded, _)) => uploaded,
                        Err(_) if stopped() => return Err(JobEnd::Cancelled),
                        Err(_) if expired() => continue,
                        Err(failure) if failure.http_status == Some(403) => {
                            // The window's URLs lapsed (a long reconnect):
                            // a resume answers fresh ones.
                            tracing::info!(offload_id = %entry.offload_id, "disk upload part URL refused; resuming for fresh URLs");
                            self.back_off(&mut backoff, &stopped, &expired);
                            step = Step::Resume;
                            continue;
                        }
                        Err(failure) => return Err(failure_of(failure.code)),
                    };
                    for (part, url) in uploaded.iter().zip(&parts) {
                        done.insert(part.n, url.size_bytes);
                    }
                    progress.set(Instant::now());
                    backoff.reset();
                    rehashed = false;
                    // Reported only on the connection the transfer is bound
                    // to; after a connection change the session resumes
                    // first (its listing records these parts).
                    let reported = uploaded
                        .chunks(sandbox_protocol::IMAGE_UPLOAD_PARTS_MAX)
                        .all(|chunk| {
                            images.push_on(
                                s.bound,
                                DaemonControlMessage::DiskUploadParts(DiskUploadPartsV11 {
                                    sandbox_id: sandbox_id.to_owned(),
                                    offload_id: entry.offload_id.clone(),
                                    seq: entry.seq,
                                    session_id: s.id.clone(),
                                    parts: chunk.to_vec(),
                                }),
                            )
                        });
                    let total = stored_size.div_ceil(part_size.max(1)).max(1);
                    if done.len() as u64 >= total {
                        // Every part is up: `upload` journals the session,
                        // then sends the completion (on any connection: the
                        // server authorizes it without a resume; its
                        // ListParts, not the reports, decides).
                        return Ok(s.id.clone());
                    }
                    if reported {
                        waiting_on = s.bound;
                    } else {
                        step = Step::Resume;
                    }
                }
                Step::Resume => {
                    let Some(s) = &mut session else {
                        return Err(JobEnd::Failed(DiskOffloadFailureCode::Io));
                    };
                    if !rehashed {
                        if !staged_matches(path, entry) {
                            return Err(JobEnd::Failed(DiskOffloadFailureCode::Corrupt));
                        }
                        rehashed = true;
                    }
                    if !self.wait_connected(&stopped, &expired) {
                        step = Step::Resume;
                        continue;
                    }
                    let on = images.connection();
                    let resume = DaemonControlMessage::DiskUploadResume(DiskUploadResumeV11 {
                        sandbox_id: sandbox_id.to_owned(),
                        offload_id: entry.offload_id.clone(),
                        seq: entry.seq,
                        session_id: s.id.clone(),
                        transfer_id: s.transfer.clone(),
                    });
                    if !images.push_on(on, resume) {
                        step = Step::Resume;
                        continue;
                    }
                    tracing::info!(offload_id = %entry.offload_id, "resuming the disk upload on the current relay connection");
                    waiting_on = on;
                    let answer = self.resume_answer(rx, on, entry, &stopped, &expired);
                    if stopped() {
                        return Err(JobEnd::Cancelled);
                    }
                    match answer {
                        Some(ServerControlMessage::DiskUploadResumed(r))
                            if r.session_id == s.id && r.transfer_id == s.transfer =>
                        {
                            let before = done.len();
                            // The server's stored parts (the object store's
                            // listing) replace what this host remembers.
                            done.clear();
                            for [first, last] in &r.stored {
                                for n in *first..=*last {
                                    done.insert(n, part_bytes(stored_size, r.part_size, n));
                                }
                            }
                            if done.len() > before {
                                // More stored than this host knew of: progress.
                                progress.set(Instant::now());
                                backoff.reset();
                            }
                            s.bound = on;
                            // This resume episode is over: the next one
                            // re-hashes the staging again before any part
                            // is sent again.
                            rehashed = false;
                            let total = stored_size.div_ceil(r.part_size.max(1)).max(1);
                            if done.len() as u64 >= total {
                                return Ok(s.id.clone());
                            }
                            if r.parts.is_empty() {
                                self.back_off(&mut backoff, &stopped, &expired);
                                step = Step::Resume;
                            } else {
                                step = Step::Window(r.part_size, r.parts);
                            }
                        }
                        Some(ServerControlMessage::DiskOffloadCancel(c)) => {
                            match c.reason.as_str() {
                                RESUME_REFUSED => {
                                    tracing::warn!(offload_id = %entry.offload_id, "disk upload resume refused");
                                    return Err(JobEnd::Failed(
                                        DiskOffloadFailureCode::ResumeRefused,
                                    ));
                                }
                                STALE | RATE_LIMITED | STORE_UNAVAILABLE | UPLOAD_IN_PROGRESS => {
                                    self.back_off(&mut backoff, &stopped, &expired);
                                    step = Step::Resume;
                                }
                                _ => return Err(JobEnd::Cancelled),
                            }
                        }
                        // No answer (the connection moved, or none came):
                        // resume again on the current connection.
                        _ => step = Step::Resume,
                    }
                }
            }
        }
    }

    /// The answer to a `disk.upload.resume` sent on connection `on`: the
    /// first frame that arrived on `on` (older connections' frames are
    /// dropped); `None` once `on` is no longer current or after the grant
    /// wait.
    fn resume_answer(
        &self,
        rx: &mpsc::Receiver<super::images::Routed>,
        on: u64,
        entry: &OffloadEntry,
        stopped: &dyn Fn() -> bool,
        expired: &dyn Fn() -> bool,
    ) -> Option<ServerControlMessage> {
        let images = &self.inner.images;
        let deadline = Instant::now() + self.inner.grant_wait;
        let wanted = || !stopped() && !expired() && images.connection() == on;
        loop {
            let left = deadline.checked_duration_since(Instant::now())?;
            let routed = wait_routed(rx, left, &wanted, self.inner.poll)?;
            if routed.connection() == on {
                return Some(routed.into_frame());
            }
            self.discard(routed.into_frame(), entry);
        }
    }

    /// A frame the job does not take: a grant's key (if any) is wiped.
    fn discard(&self, frame: ServerControlMessage, entry: &OffloadEntry) {
        if let ServerControlMessage::DiskUploadGrant(grant) = frame {
            self.lock_keys()
                .remove(&stash_key(&entry.offload_id, entry.seq, &grant.session_id));
        }
    }

    /// Wait until a relay connection is up; false once `stopped` or
    /// `expired`.
    fn wait_connected(&self, stopped: &dyn Fn() -> bool, expired: &dyn Fn() -> bool) -> bool {
        while !self.inner.images.is_connected() {
            if stopped() || expired() {
                return false;
            }
            std::thread::sleep(self.inner.poll.min(Duration::from_millis(250)));
        }
        !stopped() && !expired()
    }

    /// Sleep the next backoff step (cut short by `stopped` or `expired`).
    fn back_off(
        &self,
        backoff: &mut Backoff,
        stopped: &dyn Fn() -> bool,
        expired: &dyn Fn() -> bool,
    ) {
        let until = Instant::now() + backoff.next();
        while Instant::now() < until && !stopped() && !expired() {
            std::thread::sleep(self.inner.poll.min(Duration::from_millis(250)));
        }
    }

    /// `disk.offload.stored`: journal `stored` (through the transition
    /// table), stop a job of it still running, drop the alias image and the
    /// staging, then answer `disk.offload.released`. An ack for
    /// an offload this host holds nothing of (no entry, or another offload
    /// of the sandbox) is answered `released` at once.
    fn on_stored(&self, stored: &DiskOffloadStoredV11) {
        let sandbox_id = stored.sandbox_id.as_str();
        let released = || self.report_released(sandbox_id, &stored.offload_id, stored.seq);
        let Some(mut entry) = self.entry(sandbox_id) else {
            tracing::debug!(sandbox_id, "disk offload stored for no journaled offload");
            return released();
        };
        if entry.offload_id != stored.offload_id {
            return released();
        }
        if entry.seq != stored.seq
            || entry.fingerprint().as_deref() != Some(stored.fingerprint.as_str())
        {
            tracing::warn!(
                sandbox_id,
                "disk offload stored does not match the journaled offload"
            );
            return;
        }
        // A repeated ack never undoes a journaled eviction (its staging
        // went at the first ack).
        if !matches!(entry.phase, OffloadPhase::Evicting | OffloadPhase::Evicted) {
            entry.phase = OffloadPhase::Stored;
            entry.generation = stored.generation;
            match self.transition(sandbox_id, &entry) {
                Ok(Moved::Applied) => {}
                Ok(Moved::Past) => {}
                Ok(Moved::Gone) => return released(),
                Err(_) => return,
            }
        }
        // A job of this offload still running (a resumed upload) ends: its
        // cleanup keeps the stored entry.
        if let Some(job) = self.lock_jobs().active.get(sandbox_id)
            && job.offload_id == entry.offload_id
        {
            job.cancel.store(true, Ordering::SeqCst);
        }
        // The origin copy is no longer needed: drop the alias image and
        // the staging (with its reservation).
        self.delete_alias(&entry);
        self.release_staging(&entry.offload_id);
        released();
    }

    fn on_cancel(&self, cancel: &DiskOffloadCancelV11) {
        if cancel.reason == evict::EVICTED_ACK {
            return self.on_evicted_ack(cancel);
        }
        // A begin refused because this offload's session is already open
        // (a repeated begin): the upload in hand keeps running.
        if cancel.reason == UPLOAD_IN_PROGRESS {
            tracing::debug!(offload_id = %cancel.offload_id, "repeated disk upload begin refused; the open upload continues");
            return;
        }
        let sandbox_id = cancel.sandbox_id.as_str();
        // An answer to a completion: the entry is `uploaded` from before the
        // completion was sent (post-landing r1 #2), whether or not its job
        // has left `active` yet. `stale` asks the verdict; a deferral keeps
        // it for the next pass; anything else ends it below. A cancel does
        // not name the frame it answers (a `stale` may answer a parts report
        // of an older connection, r3 #2), so none of them stops the next
        // pass's completion: only a verdict (stored, released) ends it.
        if let Some(entry) = self.entry(sandbox_id)
            && entry.offload_id == cancel.offload_id
            && entry.phase == OffloadPhase::Uploaded
        {
            if cancel.reason == STALE {
                tracing::debug!(offload_id = %cancel.offload_id, "stale answer for an uploaded disk offload; asking for its verdict");
                self.push(DaemonControlMessage::DiskOffloadInventory(
                    DiskOffloadInventoryV11 {
                        entries: vec![DiskOffloadInventoryEntryV11 {
                            sandbox_id: sandbox_id.to_owned(),
                            offload_id: entry.offload_id.clone(),
                            seq: entry.seq,
                        }],
                    },
                ));
                return;
            }
            if RETRIED_COMPLETION.contains(&cancel.reason.as_str()) {
                tracing::debug!(offload_id = %cancel.offload_id, reason = %cancel.reason, "disk upload completion deferred; sent again by the next pass");
                return;
            }
        }
        let running = {
            let jobs = self.lock_jobs();
            jobs.active
                .get(sandbox_id)
                .filter(|job| job.offload_id == cancel.offload_id)
                // A `stale`, transient or `resume_refused` answer is the
                // job's to read (to its begin `stale` means "ask for the
                // verdict"; to an upload "resume"; `resume_refused` ends it
                // with a failure report), never "cancelled".
                .map(|job| {
                    if !JOB_ANSWERS.contains(&cancel.reason.as_str()) {
                        job.cancel.store(true, Ordering::SeqCst);
                    }
                })
                .is_some()
        };
        if running {
            self.inner.images.deliver_to(
                &grant_key(&cancel.offload_id, cancel.seq),
                ServerControlMessage::DiskOffloadCancel(cancel.clone()),
            );
            return;
        }
        if let Some(entry) = self.entry(sandbox_id)
            && entry.offload_id == cancel.offload_id
            && !entry.phase.stored()
        {
            let sandbox = sandbox_id.to_owned();
            self.spawn_cleanup("wssp-offload-cancel", move |service| {
                service.cleanup(&sandbox, &entry)
            });
        }
    }

    /// Run `work` (an alias, export and staging cleanup) on its own thread,
    /// counted in `Jobs::cleanups` from now until it ends (a thread that
    /// cannot start drops the work, and its count, at once).
    fn spawn_cleanup(&self, name: &str, work: impl FnOnce(&OffloadService) + Send + 'static) {
        struct Counted(OffloadService);
        impl Drop for Counted {
            fn drop(&mut self) {
                let mut jobs = self.0.lock_jobs();
                jobs.cleanups = jobs.cleanups.saturating_sub(1);
                drop(jobs);
                self.0.inner.jobs_cv.notify_all();
            }
        }
        self.lock_jobs().cleanups += 1;
        let counted = Counted(self.clone());
        let _ = std::thread::Builder::new()
            .name(name.into())
            .spawn(move || work(&counted.0));
    }

    /// Wait (bounded by the publish wait) for received stored-ack and
    /// release cleanups to free their staging before reserving.
    fn wait_for_cleanups(&self) {
        let deadline = Instant::now() + self.inner.publish_wait;
        let mut jobs = self.lock_jobs();
        while jobs.cleanups > 0 && Instant::now() < deadline {
            let (guard, _) = self
                .inner
                .jobs_cv
                .wait_timeout(jobs, Duration::from_millis(250))
                .unwrap_or_else(|e| e.into_inner());
            jobs = guard;
        }
    }

    /// `hello.ok` of a connection that negotiated disk offload: answers to
    /// an older connection's eviction requests may be lost with it (they
    /// stop blocking now), every unacked `disk.evicted` is sent again, and
    /// the completion and inventory pass runs (`begin_inventory`).
    pub fn on_connection(&self) {
        self.inner
            .evict_pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.resend_evicted(Duration::ZERO);
        *self
            .inner
            .last_reconcile
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Instant::now();
        self.begin_inventory();
    }

    /// The periodic pass on a live connection (every minute, post-landing
    /// #1): unacked `disk.evicted` reports go again, unanswered eviction
    /// requests expire, and every `RECONCILE_EVERY` the completion and
    /// inventory pass runs again, so no lost frame or answer leaves an
    /// entry, its alias or its staging waiting on a stable connection.
    pub fn tick(&self) {
        self.inner
            .evict_pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, since| since.elapsed() < EVICT_ANSWER_WAIT);
        self.resend_evicted(EVICTED_RESEND_EVERY);
        let due = {
            let mut last = self
                .inner
                .last_reconcile
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let due = last.elapsed() >= reconcile_every();
            if due {
                *last = Instant::now();
            }
            due
        };
        if due {
            self.begin_inventory();
        }
    }

    /// Tests only: the next `tick` runs the completion and inventory pass.
    #[cfg(test)]
    pub(crate) fn force_reconcile_due(&self) {
        let mut last = self
            .inner
            .last_reconcile
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(past) = Instant::now().checked_sub(RECONCILE_EVERY) {
            *last = past;
        }
    }

    /// Re-send `disk.evicted` for every `evicted` entry (the server acks a
    /// repeated report of a finished eviction again) last sent at least
    /// `every` ago and not queued. Reports of entries gone are forgotten.
    fn resend_evicted(&self, every: Duration) {
        let evicted: Vec<String> = self
            .lock_journal()
            .entries()
            .filter(|(_, e)| e.phase == OffloadPhase::Evicted)
            .map(|(_, e)| e.offload_id.clone())
            .collect();
        let (due, expired): (Vec<sandbox_protocol::DiskEvictedV11>, Vec<(String, String)>) = {
            let mut sent = self
                .inner
                .evicted_sent
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            sent.retain(|id, _| evicted.contains(id));
            // A periodic pass forgets an entry past its window (a new
            // connection first sends it once more, whatever its age).
            let expired: Vec<(String, String)> = if every.is_zero() {
                Vec::new()
            } else {
                sent.iter()
                    .filter(|(_, r)| r.first.elapsed() >= EVICTED_RESEND_FOR)
                    .map(|(id, r)| (r.frame.sandbox_id.clone(), id.clone()))
                    .collect()
            };
            for (_, id) in &expired {
                sent.remove(id);
            }
            let due = sent
                .values_mut()
                .filter(|r| every.is_zero() || r.last.elapsed() >= every)
                .map(|r| {
                    r.last = Instant::now();
                    r.frame.clone()
                })
                .collect();
            (due, expired)
        };
        for (sandbox_id, offload_id) in expired {
            tracing::info!(sandbox_id = %sandbox_id, offload_id = %offload_id, "disk eviction report never acked; the evicted entry is forgotten");
            self.journal_remove(&sandbox_id, &offload_id);
        }
        for frame in due {
            let id = frame.offload_id.clone();
            self.inner.images.purge_queued(
                |m| matches!(m, DaemonControlMessage::DiskEvicted(e) if e.offload_id == id),
            );
            self.push(DaemonControlMessage::DiskEvicted(frame));
        }
    }

    /// Re-send `disk.upload.complete` for every `uploaded` entry no job
    /// runs, whose session is journaled (post-landing #1), until its
    /// offload has a verdict. The server
    /// rebinds a session's transfer of an older connection and claims the
    /// upload (→ verifying, then the stored ack); a claimed, superseded or
    /// ended session is answered `stale`, which asks the verdict (a few
    /// frames per pass while the server verifies). A queued completion of
    /// the same offload is replaced, so at most one is queued.
    fn resend_completions(&self) {
        let running: Vec<(String, String)> = self
            .lock_jobs()
            .active
            .iter()
            .map(|(sandbox, job)| (sandbox.clone(), job.offload_id.clone()))
            .collect();
        let uploaded: Vec<(String, OffloadEntry, String)> = self
            .lock_journal()
            .entries()
            .filter(|(_, e)| e.phase == OffloadPhase::Uploaded)
            .filter_map(|(id, e)| {
                e.upload_session_id
                    .clone()
                    .map(|session| (id.clone(), e.clone(), session))
            })
            .collect();
        for (sandbox_id, entry, session_id) in uploaded {
            if running
                .iter()
                .any(|(s, o)| *s == sandbox_id && *o == entry.offload_id)
            {
                continue;
            }
            self.inner.images.purge_queued(|m| {
                matches!(m, DaemonControlMessage::DiskUploadComplete(c)
                    if c.offload_id == entry.offload_id && c.seq == entry.seq)
            });
            self.push(DaemonControlMessage::DiskUploadComplete(
                DiskUploadCompleteV11 {
                    sandbox_id,
                    offload_id: entry.offload_id.clone(),
                    seq: entry.seq,
                    session_id,
                },
            ));
        }
    }

    /// After reconciliation (and every `RECONCILE_EVERY` on a live
    /// connection): re-send the completions still owed a verdict
    /// (`resend_completions`), then report this host's unfinished
    /// offloads (`disk.offload.inventory`, pages of at most
    /// `DISK_OFFLOAD_INVENTORY_PAGE_MAX`, at most `INVENTORY_PAGES_MAX`
    /// pages). The server answers each from its row: `stored`, `released`
    /// (a `disk.offload.cancel` that drops alias, export, staging and the
    /// entry), or nothing while it is in flight. A truncated inventory
    /// continues on the next session after its last entry.
    pub fn begin_inventory(&self) {
        self.resend_completions();
        let unfinished: Vec<DiskOffloadInventoryEntryV11> = self
            .lock_journal()
            .entries()
            .filter(|(_, entry)| !entry.phase.stored())
            .map(|(sandbox_id, entry)| DiskOffloadInventoryEntryV11 {
                sandbox_id: sandbox_id.clone(),
                offload_id: entry.offload_id.clone(),
                seq: entry.seq,
            })
            .collect();
        let mut after = self
            .inner
            .inventory_after
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Sandbox-id order (the journal's), rotated to start after `after`.
        let start = after.as_deref().map_or(0, |last| {
            unfinished
                .iter()
                .position(|e| e.sandbox_id.as_str() > last)
                .unwrap_or(0)
        });
        let cap = sandbox_protocol::DISK_OFFLOAD_INVENTORY_PAGE_MAX * INVENTORY_PAGES_MAX;
        let ordered: Vec<DiskOffloadInventoryEntryV11> = unfinished[start..]
            .iter()
            .chain(&unfinished[..start])
            .take(cap)
            .cloned()
            .collect();
        *after = (unfinished.len() > cap)
            .then(|| ordered.last().map(|e| e.sandbox_id.clone()))
            .flatten();
        drop(after);
        // Every inventory page still queued (an older connection's, r5 #1)
        // goes: this run lists every unfinished entry afresh.
        self.inner
            .images
            .purge_queued(|m| matches!(m, DaemonControlMessage::DiskOffloadInventory(_)));
        for page in ordered.chunks(sandbox_protocol::DISK_OFFLOAD_INVENTORY_PAGE_MAX) {
            self.push(DaemonControlMessage::DiskOffloadInventory(
                DiskOffloadInventoryV11 {
                    entries: page.to_vec(),
                },
            ));
        }
    }

    /// A restore accepted on this host drops the
    /// sandbox's journal entry (and any alias or staging it still names),
    /// so a later offload never finds a stale `stored` entry.
    pub fn forget_on_restore(&self, sandbox_id: &str) {
        if let Some(entry) = self.entry(sandbox_id) {
            self.forget(sandbox_id, &entry);
        }
    }

    /// A confirmed kill deleted the root a `stored` entry vouches for: drop
    /// that entry (it names no alias or staging any more), or the journal
    /// would keep every destroyed sandbox's copy forever (the inventory
    /// reports only unfinished entries). An unfinished entry belongs to the
    /// preempted job; an evicting one to the eviction and its server ack.
    ///
    /// This only enqueues (an in-memory journal read). The
    /// forget itself lists Incus aliases, so it runs on a drain thread,
    /// never on the caller's loop (the expiry loop owns other leases'
    /// deadlines). The queue holds at most one item per stored entry; a
    /// queued forget lost to a crash is redone by the startup recovery
    /// (a stored entry whose VM is gone).
    pub fn forget_on_kill(&self, sandbox_id: &str) {
        let Some(entry) = self
            .entry(sandbox_id)
            .filter(|entry| entry.phase == OffloadPhase::Stored)
        else {
            return;
        };
        let mut forgets = self.lock_forgets();
        forgets
            .pending
            .insert(sandbox_id.to_owned(), entry.offload_id);
        if forgets.draining {
            return;
        }
        forgets.draining = true;
        drop(forgets);
        let service = self.clone();
        if let Err(error) = std::thread::Builder::new()
            .name("wssp-offload-forget".into())
            .spawn(move || service.drain_forgets())
        {
            // The next kill retries the drain; a restart's recovery
            // forgets what is still queued.
            self.lock_forgets().draining = false;
            tracing::warn!(reason = %error, "disk offload forget could not start");
        }
    }

    fn lock_forgets(&self) -> std::sync::MutexGuard<'_, Forgets> {
        self.inner.forgets.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Run queued forgets until none is left. Each drops the entry only if
    /// the journal still holds that stored offload.
    fn drain_forgets(&self) {
        loop {
            let next = {
                let mut forgets = self.lock_forgets();
                let Some(sandbox_id) = forgets.pending.keys().next().cloned() else {
                    forgets.draining = false;
                    return;
                };
                forgets.pending.remove_entry(&sandbox_id)
            };
            let Some((sandbox_id, offload_id)) = next else {
                continue;
            };
            if let Some(entry) = self.entry(&sandbox_id)
                && entry.offload_id == offload_id
                && entry.phase == OffloadPhase::Stored
            {
                self.forget(&sandbox_id, &entry);
            }
        }
    }

    /// Delete the entry's alias image and its staging, and the entry unless
    /// the journal holds it stored by then (a job's, a cancel's
    /// or a preemption's cleanup never drops the server's stored copy).
    fn cleanup(&self, sandbox_id: &str, entry: &OffloadEntry) {
        self.delete_alias(entry);
        self.release_staging(&entry.offload_id);
        self.journal_remove_unfinished(sandbox_id, &entry.offload_id);
    }

    /// Delete the entry's alias image, its staging, and the entry in any
    /// phase (a restore, a confirmed kill or a superseding request).
    fn forget(&self, sandbox_id: &str, entry: &OffloadEntry) {
        self.delete_alias(entry);
        self.release_staging(&entry.offload_id);
        self.journal_remove(sandbox_id, &entry.offload_id);
    }

    fn delete_alias(&self, entry: &OffloadEntry) {
        match self.inner.runtime.offload_aliases() {
            Ok(aliases) => {
                for alias in aliases.iter().filter(|a| a.alias == entry.alias) {
                    if let Err(error) = self.inner.runtime.delete_image(&alias.fingerprint) {
                        tracing::warn!(alias = %alias.alias, code = ?error.code, "offload image delete failed; the startup sweep retries");
                    }
                }
            }
            Err(error) => {
                tracing::warn!(code = ?error.code, "offload aliases unreadable; the startup sweep retries");
            }
        }
    }

    fn release_staging(&self, offload_id: &str) {
        let reservation = self.lock_jobs().reservations.remove(offload_id);
        drop(reservation);
        let _ = std::fs::remove_dir_all(self.staging_path(offload_id));
    }

    /// Startup sweep and resume (§7 Journal): remove this daemon's
    /// `wssp-off-<ownerTag>-*` aliases and offload staging no entry names;
    /// resume or fail each entry. The image store is shared by every daemon
    /// on the machine: another daemon's alias, or an unmarked one from
    /// before the owner tag, is never deleted here (only logged).
    pub fn recover(&self) {
        let aliases = match self.inner.runtime.offload_aliases() {
            Ok(aliases) => aliases,
            Err(error) => {
                // Never act on an unreadable inventory.
                tracing::warn!(code = ?error.code, "offload aliases unreadable; startup sweep skipped");
                return;
            }
        };
        let entries: Vec<(String, OffloadEntry)> = self
            .lock_journal()
            .entries()
            .map(|(sandbox, entry)| (sandbox.clone(), entry.clone()))
            .collect();
        for alias in &aliases {
            let named = entries
                .iter()
                .any(|(_, e)| e.alias == alias.alias && !e.phase.stored());
            if named {
                continue;
            }
            if !sandbox_runtime::offload_alias_owned_by(&alias.alias, &self.inner.owner_tag) {
                tracing::info!(alias = %alias.alias, "offload image of another daemon (or unmarked) kept");
                continue;
            }
            if let Err(error) = self.inner.runtime.delete_image(&alias.fingerprint) {
                tracing::warn!(alias = %alias.alias, code = ?error.code, "stale offload image delete failed");
            }
        }
        // A restore fetch a kill or a restart interrupted (§7).
        self.inner.images.sweep_restore_parts();
        if let Ok(dir) = std::fs::read_dir(self.inner.images.staging_dir()) {
            for item in dir.flatten() {
                let name = item.file_name().to_string_lossy().into_owned();
                let Some(id) = name.strip_prefix(STAGING_PREFIX) else {
                    continue;
                };
                let live = entries.iter().any(|(_, e)| {
                    e.offload_id == id && !e.phase.stored() && e.phase != OffloadPhase::Exporting
                });
                if !live {
                    let _ = std::fs::remove_dir_all(item.path());
                }
            }
        }
        for (sandbox_id, entry) in entries {
            self.recover_entry(&sandbox_id, entry, &aliases);
        }
    }

    fn recover_entry(
        &self,
        sandbox_id: &str,
        entry: OffloadEntry,
        aliases: &[sandbox_runtime::OffloadAlias],
    ) {
        let disk_gib = (self.inner.lookup)(sandbox_id).map(|local| local.disk_gib);
        let alias_of = |aliases: &[sandbox_runtime::OffloadAlias]| {
            aliases
                .iter()
                .find(|a| a.alias == entry.alias)
                .map(|a| a.fingerprint.clone())
        };
        match entry.phase {
            OffloadPhase::Stored => {
                // A crash after a confirmed kill or a destroying
                // expiry persisted completion, before its (queued) forget
                // ran, leaves a stored entry for a removed root. With no
                // live lease and the VM proven absent, forget it now (the
                // inventory never reports stored entries). A lookup or an
                // unreadable runtime keeps it.
                if disk_gib.is_none()
                    && matches!(self.inner.runtime.sandbox_exists(sandbox_id), Ok(false))
                {
                    tracing::info!(sandbox_id, "stored disk offload of an absent VM forgotten");
                    self.forget(sandbox_id, &entry);
                }
            }
            OffloadPhase::Evicting | OffloadPhase::Evicted => {
                self.recover_eviction(sandbox_id, entry)
            }
            OffloadPhase::Exporting | OffloadPhase::Exported => {
                let mut aliases = aliases.to_vec();
                if entry.phase == OffloadPhase::Exporting {
                    // R13: let a publish Incus still runs settle first.
                    let instance = sandbox_runtime::default_incus_instance_name(sandbox_id);
                    let deadline = Instant::now() + self.inner.publish_wait;
                    while Instant::now() < deadline
                        && self
                            .inner
                            .runtime
                            .instance_operation_running(&instance)
                            .unwrap_or(false)
                    {
                        std::thread::sleep(self.inner.poll);
                    }
                    match self.inner.runtime.offload_aliases() {
                        Ok(fresh) => aliases = fresh,
                        Err(_) => return,
                    }
                }
                match alias_of(&aliases) {
                    Some(fingerprint) => {
                        let mut entry = entry;
                        entry.phase = OffloadPhase::Exported;
                        self.run_job(sandbox_id, entry, Start::Export(fingerprint), disk_gib);
                    }
                    None => {
                        // Interrupted mid-export: retry under a new id.
                        self.cleanup(sandbox_id, &entry);
                        self.report_failed(
                            sandbox_id,
                            &entry.offload_id,
                            entry.seq,
                            DiskOffloadFailureCode::ExportInterrupted,
                        );
                    }
                }
            }
            OffloadPhase::Staged | OffloadPhase::Uploading => {
                match staged_file(&self.staging_path(&entry.offload_id)) {
                    Some((file, size)) if staged_matches(&file, &entry) => {
                        self.run_job(sandbox_id, entry, Start::Upload(file, size), disk_gib);
                    }
                    _ => {
                        // The staged bytes are gone or changed: never resend
                        // different bytes; retry under a new id.
                        self.cleanup(sandbox_id, &entry);
                        self.report_failed(
                            sandbox_id,
                            &entry.offload_id,
                            entry.seq,
                            DiskOffloadFailureCode::Corrupt,
                        );
                    }
                }
            }
            OffloadPhase::Uploaded => {
                // Waiting for `stored`: hold the staging charge again.
                if let Some((_, size)) = staged_file(&self.staging_path(&entry.offload_id)) {
                    let _ = self.reserve(&entry.offload_id, size.saturating_mul(2));
                }
            }
        }
    }
}

fn grant_key(offload_id: &str, seq: u64) -> String {
    format!("disk-grant:{offload_id}:{seq}")
}

fn stash_key(offload_id: &str, seq: u64, session_id: &str) -> String {
    format!("{offload_id}:{seq}:{session_id}")
}

/// The one file in an offload's staging directory, with its size.
fn staged_file(dir: &Path) -> Option<(PathBuf, u64)> {
    let mut files = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file());
    let file = files.next()?;
    if files.next().is_some() {
        return None;
    }
    let size = std::fs::metadata(&file).ok()?.len();
    Some((file, size))
}

/// Re-hash the staged file against the journaled `stagedSha256`.
fn staged_matches(path: &Path, entry: &OffloadEntry) -> bool {
    let Some(expected) = entry.staged_sha256.as_deref() else {
        return false;
    };
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        match std::io::Read::read(&mut file, &mut buffer) {
            Ok(0) => break,
            Ok(n) => context.update(&buffer[..n]),
            Err(_) => return false,
        }
    }
    let digest: String = context
        .finish()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    digest == expected
}

/// The open upload session a job holds.
struct UploadSession {
    id: String,
    transfer: String,
    /// The session's data key (from its first grant; memory only, wiped on
    /// drop, never journaled).
    key: crypto::RecordKey,
    /// The relay connection the session's transfer is bound to: its parts
    /// are reported only there.
    bound: u64,
}

/// What an upload job does next.
enum Step {
    /// Wait for a grant (the begin's or the next window's).
    Wait,
    /// Upload these parts (`part_size` ciphertext bytes each, the last
    /// shorter).
    Window(u64, Vec<ImageUploadPartUrlV11>),
    /// Resume the held session on the current connection.
    Resume,
}

/// Doubling waits after transient refusals, from `base` to
/// `RESUME_BACKOFF_MAX`.
struct Backoff {
    base: Duration,
    next: Duration,
}

impl Backoff {
    fn new(base: Duration) -> Self {
        Self { base, next: base }
    }

    fn next(&mut self) -> Duration {
        let wait = self.next;
        self.next = (self.next * 2).min(RESUME_BACKOFF_MAX.max(self.base));
        wait
    }

    fn reset(&mut self) {
        self.next = self.base;
    }
}

/// Ciphertext bytes of part `n` (1-based) of a `total`-byte object.
fn part_bytes(total: u64, part_size: u64, n: u32) -> u64 {
    let start = u64::from(n.saturating_sub(1)).saturating_mul(part_size);
    total.saturating_sub(start).min(part_size)
}

/// Wait for one routed frame; `None` on timeout, or once `wanted` turns
/// false (frames already routed come first).
fn wait_routed(
    rx: &mpsc::Receiver<super::images::Routed>,
    timeout: Duration,
    wanted: &dyn Fn() -> bool,
    poll: Duration,
) -> Option<super::images::Routed> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match rx.recv_timeout(poll.min(Duration::from_millis(250))) {
            Ok(frame) => return Some(frame),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if !wanted() {
                    return None;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => return None,
        }
    }
    None
}

#[path = "offload_evict.rs"]
mod evict;
pub use evict::{JournalDisks, LocalDisks};

#[cfg(test)]
#[path = "offload_tests.rs"]
mod tests;
