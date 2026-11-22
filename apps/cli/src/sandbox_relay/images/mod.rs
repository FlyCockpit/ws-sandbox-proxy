//! Managed template image cache (docs/guide/hosts.md#image-cache).
//!
//! Process-scoped like the relay supervisor: fetches inside a create, peer
//! serves, S3 publishes and capture uploads keep running across a relay drop;
//! a create's fetch only proceeds while its operation is still wanted, and the
//! server re-checks authority on every grant. Frames to the server queue in a
//! bounded outbox the connect loop drains; replies route back by request or
//! transfer id. Grants (URLs, link tokens, data keys) are never journaled or
//! logged, and HTTP errors are mapped to codes, never displayed (they can
//! carry a presigned URL).

pub mod crypto;
mod failure;
pub mod journal;

use anyhow::Result;
use sandbox_protocol::{
    DaemonControlMessage, ImageAdmissionV11, ImageCacheCensusV11, ImageCachedV11,
    ImageCapabilitiesV11, ImageCensusEntryV11, ImageEvictReason, ImageEvictedV11,
    ImageFailureCause, ImageFailureCode, ImageFetchFailedV11, ImageFetchRequestV11, ImageLinkRole,
    ImageLinksRequestV11, ImagePartAckV11, ImageRelayLinkV11, ImageReleaseReason,
    ImageTransferMode, ImageTransferRefV11, ImageUploadBeginV11, ImageUploadPartsV11,
    ImageUploadedPartV11, OperationDispatch, OperationProgressV11, OperationState, ProgressPhase,
    SandboxErrorCode, ServerControlMessage,
};
use sandbox_runtime::SandboxRuntime;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read as _, Seek as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(crate) use failure::{UploadEnd, UploadFailure};
use journal::{CacheEntry, CacheJournal, Origin};

const OUTBOX_MAX: usize = 512;
pub const PRUNE_REQUEST_FILE: &str = "prune-request.json";
pub const PRUNE_RESULT_FILE: &str = "prune-result.json";
pub const LIST_REQUEST_FILE: &str = "list-request.json";
pub const LIST_RESULT_FILE: &str = "list-result.json";
const GRANT_WAIT: Duration = Duration::from_secs(60);
const FETCH_ATTEMPTS: usize = 5;
const PROGRESS_EVERY: u64 = 32 * 1024 * 1024;
/// Agent-wide bound on sending request headers and on awaiting response
/// headers for every image-cache HTTP call. It must exceed the server's relay
/// part wait (`PART_WAIT_MS`, 60 s, in
/// `apps/server/src/sandbox-image-relay/routes.ts`): a relay GET holds its
/// response headers until the part is spooled, and an equal bound would race
/// the server's own wait.
pub const HTTP_HEADERS_TIMEOUT: Duration = Duration::from_secs(90);
/// Agent-wide per-I/O idle bound: a transfer (notably the streaming storage
/// fetch and the image-store part upload, which have no total budget) fails
/// (`stalled`) once no byte moves, in either direction, for this long. A slow
/// transfer that keeps moving never fails for slowness.
pub const HTTP_IDLE: Duration = Duration::from_secs(120);
/// Wait for an image-store part PUT's response after its body: the last
/// writes only fill the kernel send buffer, and draining it on a slow uplink
/// (45 KB/s) takes longer than `HTTP_HEADERS_TIMEOUT`.
const PUT_RESPONSE_WAIT: Duration = Duration::from_secs(300);
/// How long an upload waits for the server's next grant (or refusal).
const UPLOAD_GRANT_WAIT: Duration = Duration::from_secs(300);
/// At most one `image.upload.progress` heartbeat per upload this often, and
/// only while bytes moved.
const UPLOAD_HEARTBEAT_EVERY: Duration = Duration::from_secs(30);
/// Floor of the relay upload budget for one part.
const RELAY_PART_SEND_MIN: Duration = Duration::from_secs(120);
/// Lowest sustained upload rate a relay part must keep (64 KiB/s); a slower
/// link fails the part rather than holding the transfer indefinitely.
const RELAY_PART_SEND_FLOOR_BYTES_PER_SEC: u64 = 64 * 1024;

/// Total send budget for one relay part of `part_len` bytes: the larger of
/// `RELAY_PART_SEND_MIN` and the time the part takes at the floor rate.
/// A relay part keeps this total budget on top of the idle bound, scaled so
/// slow links still finish. Downloads need none: the idle bound already fails
/// a stalled part.
fn relay_part_send_budget(part_len: usize) -> Duration {
    let len = u64::try_from(part_len).unwrap_or(u64::MAX);
    let at_floor = Duration::from_secs(len.div_ceil(RELAY_PART_SEND_FLOOR_BYTES_PER_SEC));
    at_floor.max(RELAY_PART_SEND_MIN)
}

/// Local settings (TOML only; a restart applies them).
#[derive(Debug, Clone)]
pub struct ImageSettings {
    pub size: crate::config::ImageCacheSize,
    pub accept_foreign: bool,
    pub foreign_grace: Duration,
    /// Template builds (`builder`, default on with capture).
    pub builder: bool,
    /// Builds for other accounts (`accept_foreign_builds`); needs `builder`.
    pub accept_foreign_builds: bool,
}

/// A host-plane failure as the typed code the server understands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageError {
    pub code: SandboxErrorCode,
    pub message: &'static str,
    /// Typed wire reason, when the refusal has one (a guard outage).
    pub reason: Option<sandbox_protocol::ProtocolErrorReason>,
}

impl ImageError {
    pub(crate) const fn new(code: SandboxErrorCode, message: &'static str) -> Self {
        Self {
            code,
            message,
            reason: None,
        }
    }

    /// The runtime's typed guard refusal of an import (the node's guard
    /// outage, e.g. another wssp daemon on this Incus server), kept as is so
    /// the server maps it like any guard outage.
    fn guard_refusal(error: &sandbox_runtime::RuntimeError) -> Option<Self> {
        let guard = sandbox_protocol::ProtocolErrorReason::from(
            sandbox_protocol::EgressRefusalReason::EgressGuardUnavailable,
        );
        (error.wire_reason() == Some(guard)).then_some(Self {
            code: error.code,
            message: "another wssp daemon drives this Incus server; no VM may start here",
            reason: Some(guard),
        })
    }

    /// One wssp daemon per Incus server: while another daemon's marker is
    /// live, the refusal is the node's guard outage (code and typed reason),
    /// so the server reports and retries it like one.
    fn shared_incus_server(runtime: &dyn SandboxRuntime) -> Result<(), Self> {
        let Some(probe) = runtime.egress_guard_probe() else {
            return Ok(());
        };
        sandbox_runtime::guard_probe::refuse_shared_incus_server(probe.as_ref()).map_err(|err| {
            Self {
                code: err.code,
                message: "another wssp daemon drives this Incus server; no VM may start here",
                reason: err.wire_reason(),
            }
        })
    }
}

struct Inner {
    runtime: Arc<dyn SandboxRuntime>,
    settings: ImageSettings,
    /// Cache budget: fixed, or auto from the storage pool seen at connect.
    cap: AtomicU64,
    /// Storage markers of copy-on-write pools (READY capture).
    capture_markers: Mutex<Vec<String>>,
    staging: PathBuf,
    journal: Mutex<CacheJournal>,
    outbox: Mutex<VecDeque<DaemonControlMessage>>,
    waiters: Mutex<HashMap<String, mpsc::Sender<ServerControlMessage>>>,
    inflight: Mutex<HashSet<String>>,
    inflight_cv: Condvar,
    in_use: Mutex<HashMap<String, usize>>,
    http: ureq::Agent,
    relay_base: String,
    host_secret: String,
    host_owner: Mutex<Option<String>>,
    census: Mutex<CensusState>,
    cancelled: Mutex<HashSet<String>>,
    seq: AtomicU64,
    /// Staging bytes reserved before any write (P1-4), keyed by the staging
    /// entry name they cover (`<hex>.part`, `export-<hex>`).
    reserved: Mutex<HashMap<String, u64>>,
    /// Serializes admission (eviction + reservation) so two jobs cannot both
    /// claim the last headroom.
    admission: Mutex<()>,
    /// One background inventory reconcile at a time.
    reconciling: std::sync::atomic::AtomicBool,
    /// Community bases: the agent for upstream split images, webpki roots
    /// only and no redirects (`None`: no TLS config, upstream refused).
    upstream_http: Option<ureq::Agent>,
    /// Tests only: a loopback base URL and agent instead of the fixed host.
    #[cfg(test)]
    upstream_override: Mutex<Option<(String, ureq::Agent)>>,
    /// Tests only: the total budget of one upstream fetch.
    #[cfg(test)]
    upstream_budget_override: Mutex<Option<Duration>>,
    /// Tests only: the upload heartbeat interval.
    #[cfg(test)]
    heartbeat_override: Mutex<Option<Duration>>,
    /// Tests only: how long an upload waits for each grant.
    #[cfg(test)]
    grant_wait_override: Mutex<Option<Duration>>,
    /// Tests only: upload jobs that have returned (frames all pushed).
    #[cfg(test)]
    uploads_finished: AtomicU64,
}

/// The agent config for upstream image downloads: never a redirect (the
/// pinned host serves the bytes itself), status codes as values, and the
/// image cache's header bounds.
pub(super) fn upstream_agent_config() -> ureq::config::Config {
    ureq::Agent::config_builder()
        .max_redirects(0)
        .http_status_as_error(false)
        .timeout_connect(Some(Duration::from_secs(30)))
        .timeout_send_request(Some(HTTP_HEADERS_TIMEOUT))
        .timeout_recv_response(Some(HTTP_HEADERS_TIMEOUT))
        .build()
}

/// Staging entries of one upstream split image: distinct from each other
/// and from a unified fetch's `<hex>.part`, so each file has its own
/// reservation and resume.
pub(super) fn upstream_staging_keys(fp: &str) -> (String, String) {
    let hex = fp.strip_prefix("sha256:").unwrap_or(fp);
    (format!("{hex}.meta.part"), format!("{hex}.disk.part"))
}

/// One pinned upstream file.
struct UpstreamFile<'a> {
    path: &'a str,
    sha256: &'a str,
    size: u64,
    staging: PathBuf,
    /// Bytes of the image before this file (progress offset).
    before: u64,
    /// The whole image's bytes (progress total).
    total: u64,
}

/// One census run: pages not sent yet, and since when a sent page awaits its
/// ACK (`None` once the complete page is acknowledged).
#[derive(Default)]
struct CensusState {
    pages: VecDeque<DaemonControlMessage>,
    awaiting_since: Option<Instant>,
}

/// A census whose ACK never came (a lost frame) stops blocking periodic ones.
const CENSUS_STALE: Duration = Duration::from_secs(600);

/// Abandoned staging (an interrupted download or export) is removed after this.
const STAGING_TTL: Duration = Duration::from_secs(24 * 3600);

/// Staging name prefix of a restore's disk fetch (`restore-<hex>.part`),
/// distinct from a create's resumable `<hex>.part`: a fetch the restore's
/// kill or a restart interrupted is removed by the startup sweep
/// (`sweep_restore_parts`) instead of lingering until a next fetch.
const RESTORE_PART_PREFIX: &str = "restore-";

/// Bytes held against the cache cap for one staging entry until dropped.
/// Each job reserves its own uniquely named entry (round-2 P2-5); an entry
/// the reservation owns (`owned`) is removed before the charge is released,
/// so staging is never under-counted and no job removes another's files.
pub struct StagingReservation {
    service: ImageService,
    key: String,
    owned: Option<PathBuf>,
}

impl StagingReservation {
    /// The reservation owns `path` from now on: dropping it removes the
    /// path before the charge is released.
    pub(crate) fn own(&mut self, path: PathBuf) {
        self.owned = Some(path);
    }
}

impl Drop for StagingReservation {
    fn drop(&mut self) {
        if let Some(path) = self.owned.take() {
            let _ = std::fs::remove_dir_all(&path);
        }
        self.service
            .inner
            .reserved
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.key);
    }
}

#[derive(Clone)]
pub struct ImageService {
    inner: Arc<Inner>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn sha256_file(path: &Path) -> std::io::Result<(String, u64)> {
    let mut file = std::fs::File::open(path)?;
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buffer = vec![0u8; 1 << 20];
    let mut size = 0u64;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        ctx.update(&buffer[..n]);
        size += n as u64;
    }
    Ok((hex(ctx.finish().as_ref()), size))
}

/// Hex sha256 of `meta` followed by `disk`: an Incus split image's
/// fingerprint.
fn combined_sha256(meta: &Path, disk: &Path) -> std::io::Result<String> {
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buffer = vec![0u8; 1 << 20];
    for path in [meta, disk] {
        let mut file = std::fs::File::open(path)?;
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            context.update(&buffer[..n]);
        }
    }
    Ok(hex(context.finish().as_ref()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref())
}

impl ImageService {
    /// `None` when the cache is disabled (`image_cache_gib = 0`): such a
    /// daemon omits the capability, so its hello matches a pre-image daemon.
    pub fn start(
        runtime: Arc<dyn SandboxRuntime>,
        state_dir: &Path,
        settings: ImageSettings,
        http: ureq::Agent,
        server_url: &str,
        host_secret: &str,
    ) -> Result<Option<Self>> {
        if settings.size == crate::config::ImageCacheSize::Gib(0) {
            return Ok(None);
        }
        let initial = settings.size.bytes_for(0);
        let dir = state_dir.join("images");
        let journal = CacheJournal::open(&dir)?;
        let staging = dir.join("staging");
        std::fs::create_dir_all(&staging)?;
        let base = url::Url::parse(server_url)?;
        let relay_base = base.join("/host/image-relay/v1/parts/")?.to_string();
        Ok(Some(Self {
            inner: Arc::new(Inner {
                runtime,
                settings,
                cap: AtomicU64::new(initial),
                capture_markers: Mutex::new(Vec::new()),
                staging,
                journal: Mutex::new(journal),
                outbox: Mutex::new(VecDeque::new()),
                waiters: Mutex::new(HashMap::new()),
                inflight: Mutex::new(HashSet::new()),
                inflight_cv: Condvar::new(),
                in_use: Mutex::new(HashMap::new()),
                http,
                relay_base,
                host_secret: host_secret.to_owned(),
                host_owner: Mutex::new(None),
                census: Mutex::new(CensusState::default()),
                cancelled: Mutex::new(HashSet::new()),
                seq: AtomicU64::new(0),
                reserved: Mutex::new(HashMap::new()),
                admission: Mutex::new(()),
                reconciling: std::sync::atomic::AtomicBool::new(false),
                upstream_http: super::credentials::proxy::upstream::webpki_client_config().map(
                    |tls| {
                        crate::tls::Trust::http_agent_from(
                            Some(Arc::new(tls)),
                            upstream_agent_config(),
                            HTTP_IDLE,
                        )
                    },
                ),
                #[cfg(test)]
                upstream_override: Mutex::new(None),
                #[cfg(test)]
                upstream_budget_override: Mutex::new(None),
                #[cfg(test)]
                heartbeat_override: Mutex::new(None),
                #[cfg(test)]
                grant_wait_override: Mutex::new(None),
                #[cfg(test)]
                uploads_finished: AtomicU64::new(0),
            }),
        }))
    }

    /// Tests only: download upstream images from `base` with `agent`.
    #[cfg(test)]
    pub(crate) fn set_upstream_for_test(&self, base: &str, agent: ureq::Agent) {
        *self
            .inner
            .upstream_override
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some((base.to_owned(), agent));
    }

    /// Tests only: bound every upstream fetch by `budget` in total.
    #[cfg(test)]
    pub(crate) fn set_upstream_budget_for_test(&self, budget: Duration) {
        *self
            .inner
            .upstream_budget_override
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(budget);
    }

    /// Tests only: send upload heartbeats this often.
    #[cfg(test)]
    pub(crate) fn set_heartbeat_for_test(&self, every: Duration) {
        *self
            .inner
            .heartbeat_override
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(every);
    }

    /// Tests only: wait at most `wait` for each upload grant.
    #[cfg(test)]
    pub(crate) fn set_grant_wait_for_test(&self, wait: Duration) {
        *self
            .inner
            .grant_wait_override
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(wait);
    }

    /// Tests only: how many upload jobs have returned.
    #[cfg(test)]
    pub(crate) fn uploads_finished(&self) -> u64 {
        self.inner.uploads_finished.load(Ordering::SeqCst)
    }

    /// How long an upload waits for each grant.
    fn grant_wait(&self) -> Duration {
        #[cfg(test)]
        if let Some(wait) = *self
            .inner
            .grant_wait_override
            .lock()
            .unwrap_or_else(|e| e.into_inner())
        {
            return wait;
        }
        UPLOAD_GRANT_WAIT
    }

    /// The heartbeat of one upload of `transfer`.
    fn heartbeat(&self, transfer: &str) -> UploadHeartbeat<'_> {
        #[allow(unused_mut)]
        let mut every = UPLOAD_HEARTBEAT_EVERY;
        #[cfg(test)]
        if let Some(test) = *self
            .inner
            .heartbeat_override
            .lock()
            .unwrap_or_else(|e| e.into_inner())
        {
            every = test;
        }
        UploadHeartbeat {
            service: self,
            transfer_id: transfer.to_owned(),
            every,
            reached: std::cell::Cell::new(0),
            reported: std::cell::Cell::new((Instant::now(), 0)),
        }
    }

    /// The total budget of one upstream fetch (both files).
    fn upstream_budget(&self, total: u64) -> Duration {
        #[cfg(test)]
        if let Some(budget) = *self
            .inner
            .upstream_budget_override
            .lock()
            .unwrap_or_else(|e| e.into_inner())
        {
            return budget;
        }
        Duration::from_secs(600).max(Duration::from_secs(total / (1 << 20)))
    }

    /// The upstream base URL and agent: the fixed host in production.
    fn upstream_client(&self) -> Option<(String, ureq::Agent)> {
        #[cfg(test)]
        if let Some(client) = self
            .inner
            .upstream_override
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return Some(client);
        }
        self.inner
            .upstream_http
            .clone()
            .map(|agent| (sandbox_protocol::UPSTREAM_IMAGE_BASE_URL.to_owned(), agent))
    }

    pub fn capabilities(&self) -> ImageCapabilitiesV11 {
        ImageCapabilitiesV11 {
            fetch: true,
            serve: true,
            publish: true,
            capture: true,
            accept_foreign: self.inner.settings.accept_foreign,
            lease_from_ready: true,
            formats: vec!["unified".into()],
            build: self.builds_enabled(),
            accept_foreign_builds: self.builds_enabled()
                && self.inner.settings.accept_foreign_builds,
        }
    }

    /// This node runs template-build VMs (D1: the only place guest root
    /// runs). Capture is always on while the cache exists.
    pub fn builds_enabled(&self) -> bool {
        self.inner.settings.builder
    }

    pub fn admission(&self) -> ImageAdmissionV11 {
        let owner = self.host_owner();
        let journal = self.lock_journal();
        let totals = journal.totals(owner.as_deref());
        ImageAdmissionV11 {
            cap_bytes: self.cap(),
            used_bytes: totals.used_bytes,
            foreign_used_bytes: totals.foreign_bytes,
            capture_storage_markers: self
                .inner
                .capture_markers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .take(sandbox_protocol::IMAGE_CAPTURE_MARKERS_MAX)
                .cloned()
                .collect(),
        }
    }

    pub fn cap(&self) -> u64 {
        self.inner.cap.load(Ordering::Relaxed)
    }

    /// At connect: the auto budget follows the largest configured pool, and
    /// btrfs/ZFS/LVM pools are advertised as copy-on-write (READY capture).
    pub fn configure_pools(
        &self,
        runtime: &dyn SandboxRuntime,
        pools: &[sandbox_protocol::capacity_v11::StoragePoolV11],
    ) {
        let total = pools
            .iter()
            .filter_map(|p| p.derivation_total_bytes.or(p.total_bytes))
            .max()
            .unwrap_or(0);
        self.inner
            .cap
            .store(self.inner.settings.size.bytes_for(total), Ordering::Relaxed);
        let markers: Vec<String> = pools
            .iter()
            .filter(|p| {
                runtime
                    .observe_storage_pool(&sandbox_runtime::StoragePoolIdentity {
                        name: p.name.clone(),
                        storage_id: p.marker.clone(),
                    })
                    .is_ok_and(|o| !matches!(o.driver, sandbox_runtime::StorageDriver::Dir))
            })
            .map(|p| p.marker.clone())
            .collect();
        *self
            .inner
            .capture_markers
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = markers;
    }

    fn lock_journal(&self) -> std::sync::MutexGuard<'_, CacheJournal> {
        self.inner.journal.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn host_owner(&self) -> Option<String> {
        self.inner
            .host_owner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// `hello.ok`: the host owner decides which cached bytes are foreign.
    pub fn on_registered(&self, host_owner_id: &str) {
        *self
            .inner
            .host_owner
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(host_owner_id.to_owned());
    }

    fn push(&self, message: DaemonControlMessage) {
        let mut outbox = self.inner.outbox.lock().unwrap_or_else(|e| e.into_inner());
        if outbox.len() >= OUTBOX_MAX {
            // Progress is advisory; drop the oldest one first.
            if let Some(index) = outbox
                .iter()
                .position(|m| matches!(m, DaemonControlMessage::OperationProgress { .. }))
            {
                outbox.remove(index);
            } else {
                outbox.pop_front();
            }
        }
        outbox.push_back(message);
    }

    /// Frames for the connect loop to send (bounded per call).
    pub fn drain(&self) -> Vec<DaemonControlMessage> {
        let mut outbox = self.inner.outbox.lock().unwrap_or_else(|e| e.into_inner());
        let n = outbox.len().min(32);
        outbox.drain(..n).collect()
    }

    /// After `reconcile.complete`: queue the bounded census pages; the first
    /// goes now, each later page on the previous page's ACK. A new connection
    /// always starts afresh (the old one's ACKs can never arrive).
    pub fn begin_census(&self) {
        let pages = self.census_pages();
        let mut census = self.inner.census.lock().unwrap_or_else(|e| e.into_inner());
        census.pages = pages;
        census.awaiting_since = None;
        if let Some(first) = census.pages.pop_front() {
            census.awaiting_since = Some(Instant::now());
            drop(census);
            self.push(first);
        }
    }

    /// A periodic census on a live connection, so the server's view converges
    /// without a reconnect; false (nothing sent) while one is in flight, since
    /// interleaved pages would merge two runs on the server.
    pub fn begin_periodic_census(&self) -> bool {
        {
            let census = self.inner.census.lock().unwrap_or_else(|e| e.into_inner());
            if census
                .awaiting_since
                .is_some_and(|since| since.elapsed() < CENSUS_STALE)
            {
                return false;
            }
        }
        self.begin_census();
        true
    }

    fn census_pages(&self) -> VecDeque<DaemonControlMessage> {
        let owner = self.host_owner();
        {
            let journal = self.lock_journal();
            let totals = journal.totals(owner.as_deref());
            let entries: Vec<ImageCensusEntryV11> = journal
                .file
                .entries
                .values()
                .filter(|e| e.compressed_bytes > 0 && !e.owners.is_empty())
                .map(|e| ImageCensusEntryV11 {
                    fingerprint: e.fingerprint.clone(),
                    owners: e
                        .owners
                        .iter()
                        .take(sandbox_protocol::IMAGE_CENSUS_OWNERS_MAX)
                        .cloned()
                        .collect(),
                    compressed_bytes: e.compressed_bytes,
                    unpacked_bytes: e.unpacked_bytes,
                    origin: e.origin.into(),
                    pinned: e.pinned,
                })
                .collect();
            let chunks: Vec<Vec<ImageCensusEntryV11>> = if entries.is_empty() {
                vec![Vec::new()]
            } else {
                entries
                    .chunks(sandbox_protocol::IMAGE_CENSUS_PAGE_MAX)
                    .map(<[_]>::to_vec)
                    .collect()
            };
            let last = chunks.len() - 1;
            chunks
                .into_iter()
                .enumerate()
                .map(|(page, entries)| {
                    DaemonControlMessage::ImageCacheCensus(ImageCacheCensusV11 {
                        page: page as u64,
                        complete: page == last,
                        entries,
                        totals: totals.clone(),
                    })
                })
                .collect::<VecDeque<_>>()
        }
    }

    fn next_id(&self, prefix: &str) -> String {
        format!(
            "{prefix}-{}-{}",
            now_ms(),
            self.inner.seq.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn register(&self, key: &str) -> mpsc::Receiver<ServerControlMessage> {
        let (tx, rx) = mpsc::channel();
        self.inner
            .waiters
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key.to_owned(), tx);
        rx
    }

    fn unregister(&self, key: &str) {
        self.inner
            .waiters
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key);
    }

    fn deliver(&self, key: &str, frame: ServerControlMessage) -> bool {
        let waiters = self.inner.waiters.lock().unwrap_or_else(|e| e.into_inner());
        waiters.get(key).is_some_and(|tx| tx.send(frame).is_ok())
    }

    /// Route one server→daemon image frame.
    pub fn handle_server(&self, frame: ServerControlMessage) {
        match frame {
            ServerControlMessage::ImageFetchGrant(ref g) => {
                let key = g.request_id.clone();
                self.deliver(&key, frame);
            }
            ServerControlMessage::ImageFetchRefused(ref r) => {
                let key = r.request_id.clone();
                self.deliver(&key, frame);
            }
            ServerControlMessage::ImageLinksGrant(ref g) => {
                let key = format!("links:{}:{:?}", g.transfer_id, g.role);
                self.deliver(&key, frame);
            }
            ServerControlMessage::ImageUploadGrant(ref g) => {
                // A capture's first grant answers its begin by request id
                // (round-3 P2-4); every other grant names a known transfer.
                // Nothing is ever routed to an arbitrary waiter.
                let key = match &g.request_id {
                    Some(request) => format!("upload-req:{request}"),
                    None => format!("upload:{}", g.transfer_id),
                };
                self.deliver(&key, frame);
            }
            ServerControlMessage::ImageJobCancel(ref c) => {
                if let Some(request) = &c.request_id {
                    // A refused capture begin: only that capture stops.
                    self.deliver(&format!("upload-req:{request}"), frame);
                    return;
                }
                self.inner
                    .cancelled
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(c.transfer_id.clone());
                // Waiters keyed by exactly this transfer (`upload:`, `links:`,
                // `resume:`), never by a substring of another id.
                let keys: Vec<String> = self
                    .inner
                    .waiters
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .keys()
                    .filter(|k| k.split(':').nth(1) == Some(c.transfer_id.as_str()))
                    .cloned()
                    .collect();
                for key in keys {
                    self.deliver(&key, frame.clone());
                }
            }
            ServerControlMessage::ImageJobResumeResult(ref r) => {
                let key = format!("resume:{}", r.transfer_id);
                self.deliver(&key, frame);
            }
            ServerControlMessage::ImageServeRequest(request) => {
                let service = self.clone();
                std::thread::spawn(move || service.serve(request));
            }
            ServerControlMessage::ImagePublishRequest(request) => {
                let service = self.clone();
                std::thread::spawn(move || {
                    service.upload(
                        &request.fingerprint,
                        &request.image_owner_id,
                        UploadJob::Publish(request.transfer_id),
                    )
                });
            }
            ServerControlMessage::ImageRelease(release) => self.release(
                &release.fingerprint,
                &release.image_owner_id,
                release.reason,
            ),
            ServerControlMessage::ImageCacheCensusAck(_) => {
                let next = {
                    let mut census = self.inner.census.lock().unwrap_or_else(|e| e.into_inner());
                    let next = census.pages.pop_front();
                    census.awaiting_since = next.as_ref().map(|_| Instant::now());
                    next
                };
                if let Some(page) = next {
                    self.push(page);
                }
            }
            _ => {}
        }
    }

    fn totals(&self) -> sandbox_protocol::ImageCacheTotals {
        let owner = self.host_owner();
        let mut totals = self.lock_journal().totals(owner.as_deref());
        // Staging (reserved or abandoned) occupies the cache budget too.
        totals.used_bytes = totals.used_bytes.saturating_add(self.staging_bytes());
        totals
    }

    /// Reserved staging bytes plus the on-disk size of staging entries no
    /// reservation covers (abandoned `.part` files and exports).
    fn staging_bytes(&self) -> u64 {
        let reserved = self
            .inner
            .reserved
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let mut total: u64 = reserved.values().sum();
        if let Ok(entries) = std::fs::read_dir(&self.inner.staging) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if !reserved.contains_key(&name) {
                    total = total.saturating_add(dir_bytes(&entry.path()));
                }
            }
        }
        total
    }

    /// Everything charged to the cache cap: managed images and staging.
    #[cfg(test)]
    fn charged_bytes(&self) -> u64 {
        self.lock_journal()
            .used_bytes()
            .saturating_add(self.staging_bytes())
    }

    /// Reserve `bytes` of staging for `key` (the staging entry name), evicting
    /// LRU images first; `image_cache_full` when it cannot fit (P1-4). A key
    /// is held by one job at a time: a second reservation of a held key is
    /// refused instead of overwriting the first job's charge (round-2 P2-5).
    pub fn reserve(&self, key: &str, bytes: u64) -> Result<StagingReservation, ImageError> {
        let _admission = self
            .inner
            .admission
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if self
            .inner
            .reserved
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(key)
        {
            return Err(ImageError::new(
                SandboxErrorCode::Transport,
                "image staging entry busy",
            ));
        }
        self.make_room_locked(bytes)?;
        self.inner
            .reserved
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key.to_owned(), bytes);
        Ok(StagingReservation {
            service: self.clone(),
            key: key.to_owned(),
            owned: None,
        })
    }

    /// Startup sweep: remove every restore fetch
    /// (`restore-<hex>.part`) no job holds. Taken under the reservation
    /// admission lock, so a fetch reserving its entry now is never removed.
    pub fn sweep_restore_parts(&self) -> usize {
        let _admission = self
            .inner
            .admission
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let reserved: HashSet<String> = self
            .inner
            .reserved
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .cloned()
            .collect();
        let Ok(entries) = std::fs::read_dir(&self.inner.staging) else {
            return 0;
        };
        let mut removed = 0;
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(RESTORE_PART_PREFIX)
                && name.ends_with(".part")
                && !reserved.contains(&name)
                && entry.file_type().is_ok_and(|t| t.is_file())
                && std::fs::remove_file(entry.path()).is_ok()
            {
                removed += 1;
            }
        }
        removed
    }

    /// Remove staging entries no job holds and older than `STAGING_TTL`.
    pub fn sweep_staging(&self) -> usize {
        self.sweep_staging_older_than(STAGING_TTL)
    }

    fn sweep_staging_older_than(&self, ttl: Duration) -> usize {
        let reserved: HashSet<String> = self
            .inner
            .reserved
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .cloned()
            .collect();
        let mut removed = 0;
        let Ok(entries) = std::fs::read_dir(&self.inner.staging) else {
            return 0;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if reserved.contains(&name) {
                continue;
            }
            let old = entry
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age >= ttl);
            if old {
                let path = entry.path();
                let gone = if path.is_dir() {
                    std::fs::remove_dir_all(&path)
                } else {
                    std::fs::remove_file(&path)
                };
                if gone.is_ok() {
                    removed += 1;
                }
            }
        }
        removed
    }

    fn progress(
        &self,
        d: &OperationDispatch,
        phase: ProgressPhase,
        done: Option<u64>,
        total: Option<u64>,
    ) {
        self.push(DaemonControlMessage::OperationProgress {
            id: self.next_id("progress"),
            operation_id: d.operation_id.clone(),
            sandbox_id: d.sandbox_id.clone(),
            generation: d.generation,
            attempt: d.attempt,
            state: OperationState::Running,
            progress: Some(OperationProgressV11 {
                phase,
                bytes_done: done,
                bytes_total: total,
            }),
        });
    }

    fn mark_in_use(&self, fingerprint: &str, delta: isize) {
        let mut in_use = self.inner.in_use.lock().unwrap_or_else(|e| e.into_inner());
        let count = in_use.entry(fingerprint.to_owned()).or_insert(0);
        *count = count.saturating_add_signed(delta);
        if *count == 0 {
            in_use.remove(fingerprint);
        }
    }

    fn is_in_use(&self, fingerprint: &str) -> bool {
        self.inner
            .in_use
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(fingerprint)
    }

    /// LRU eviction until `needed` more bytes fit. Never evicts an image in
    /// use, origin-pinned, aliased, or the base image of any instance.
    pub fn make_room(&self, needed: u64) -> Result<(), ImageError> {
        let _admission = self
            .inner
            .admission
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        self.make_room_locked(needed)
    }

    fn make_room_locked(&self, needed: u64) -> Result<(), ImageError> {
        let cap = self.cap();
        loop {
            let staging = self.staging_bytes();
            let (used, victim) = {
                let journal = self.lock_journal();
                let mut candidates: Vec<&CacheEntry> = journal
                    .file
                    .entries
                    .values()
                    .filter(|e| !e.pinned && !self.is_in_use(&e.fingerprint))
                    .collect();
                candidates.sort_by_key(|e| e.last_used_unix_ms);
                (
                    journal.used_bytes().saturating_add(staging),
                    candidates.first().map(|e| e.fingerprint.clone()),
                )
            };
            if used.saturating_add(needed) <= cap {
                return Ok(());
            }
            let Some(victim) = victim else {
                return Err(ImageError::new(
                    SandboxErrorCode::ImageCacheFull,
                    "image cache full",
                ));
            };
            if !self.evict(&victim, ImageEvictReason::Lru) {
                return Err(ImageError::new(
                    SandboxErrorCode::ImageCacheFull,
                    "image cache full",
                ));
            }
        }
    }

    /// Delete one managed image and report it; false when it must stay.
    fn evict(&self, fingerprint: &str, reason: ImageEvictReason) -> bool {
        if self.is_in_use(fingerprint)
            || self
                .inner
                .runtime
                .image_protected(fingerprint)
                .unwrap_or(true)
        {
            // Protected now (aliased or a base image): stop managing it.
            if !self.is_in_use(fingerprint) {
                let mut journal = self.lock_journal();
                journal.file.entries.remove(fingerprint);
                journal.save_or_warn();
            }
            return false;
        }
        if self.inner.runtime.delete_image(fingerprint).is_err() {
            return false;
        }
        let owners = {
            let mut journal = self.lock_journal();
            let owners = journal
                .file
                .entries
                .remove(fingerprint)
                .map(|e| e.owners)
                .unwrap_or_default();
            journal.save_or_warn();
            owners
        };
        let totals = self.totals();
        for owner in owners {
            self.push(DaemonControlMessage::ImageEvicted(ImageEvictedV11 {
                fingerprint: fingerprint.to_owned(),
                image_owner_id: owner,
                reason,
                totals: totals.clone(),
            }));
        }
        true
    }

    fn release(&self, fingerprint: &str, owner: &str, reason: ImageReleaseReason) {
        let evict = {
            let mut journal = self.lock_journal();
            let Some(entry) = journal.file.entries.get_mut(fingerprint) else {
                return;
            };
            match reason {
                ImageReleaseReason::Stored
                | ImageReleaseReason::Replicated
                | ImageReleaseReason::Gc => {
                    entry.pinned = false;
                }
                ImageReleaseReason::AccessLost | ImageReleaseReason::Released => {
                    entry.owners.remove(owner);
                }
            }
            let evict = entry.owners.is_empty()
                || (reason == ImageReleaseReason::Gc && entry.origin == Origin::Captured);
            journal.save_or_warn();
            evict
        };
        if evict {
            let why = if reason == ImageReleaseReason::AccessLost {
                ImageEvictReason::AccessLost
            } else {
                ImageEvictReason::Released
            };
            self.evict(fingerprint, why);
        }
    }

    /// Operator prune: every unpinned, unused managed image (or a dry run).
    pub fn prune(&self, dry_run: bool) -> Vec<String> {
        let candidates: Vec<String> = self
            .lock_journal()
            .file
            .entries
            .values()
            .filter(|e| !e.pinned && !self.is_in_use(&e.fingerprint))
            .map(|e| e.fingerprint.clone())
            .collect();
        if dry_run {
            return candidates;
        }
        candidates
            .into_iter()
            .filter(|fp| self.evict(fp, ImageEvictReason::Operator))
            .collect()
    }

    /// Foreign grace and access policy: evict foreign images idle past the grace.
    pub fn sweep_foreign(&self) {
        let owner = self.host_owner();
        let grace = self.inner.settings.foreign_grace.as_millis() as u64;
        let now = now_ms();
        let due: Vec<String> = self
            .lock_journal()
            .file
            .entries
            .values()
            .filter(|e| {
                owner.as_ref().is_some_and(|o| !e.owners.contains(o))
                    && !e.pinned
                    && !self.is_in_use(&e.fingerprint)
                    && e.idle_since_unix_ms
                        .is_some_and(|idle| now.saturating_sub(idle) >= grace)
            })
            .map(|e| e.fingerprint.clone())
            .collect();
        for fp in due {
            self.evict(&fp, ImageEvictReason::Released);
        }
    }

    #[cfg(test)]
    pub(crate) fn record_for_test(
        &self,
        fingerprint: &str,
        owner: &str,
        bytes: u64,
        origin: Origin,
        pinned: bool,
    ) {
        self.record(fingerprint, owner, bytes, origin, pinned);
    }

    fn record(&self, fingerprint: &str, owner: &str, bytes: u64, origin: Origin, pinned: bool) {
        let mut journal = self.lock_journal();
        let entry = journal
            .file
            .entries
            .entry(fingerprint.to_owned())
            .or_insert_with(|| CacheEntry {
                fingerprint: fingerprint.to_owned(),
                owners: Default::default(),
                compressed_bytes: bytes,
                unpacked_bytes: None,
                origin,
                pinned,
                last_used_unix_ms: now_ms(),
                idle_since_unix_ms: None,
            });
        entry.owners.insert(owner.to_owned());
        entry.compressed_bytes = bytes;
        entry.pinned |= pinned;
        entry.last_used_unix_ms = now_ms();
        entry.idle_since_unix_ms = None;
        journal.save_or_warn();
    }

    fn touch_idle(&self, fingerprint: &str) {
        let mut journal = self.lock_journal();
        if let Some(entry) = journal.file.entries.get_mut(fingerprint) {
            entry.last_used_unix_ms = now_ms();
            entry.idle_since_unix_ms = Some(now_ms());
            journal.save_or_warn();
        }
    }

    /// A create's planned fetch, inside the Intent phase (before any lease
    /// or Effect record). Single-flight per fingerprint; resumable `.part`.
    pub fn ensure_image(
        &self,
        d: &OperationDispatch,
        still_wanted: &dyn Fn() -> bool,
    ) -> Result<(), ImageError> {
        let Some(plan) = d.image.as_ref() else {
            return Ok(());
        };
        let fp = plan.fingerprint.clone();
        self.mark_in_use(&fp, 1);
        let result = self.ensure_inner(d, plan, None, still_wanted);
        self.mark_in_use(&fp, -1);
        self.touch_idle(&fp);
        result
    }

    /// A restore's stored disk image, fetched in the
    /// Intent phase like a create's planned image (resumable `.part`, the
    /// foreign gate, mandatory pre-import validation, the imported
    /// fingerprint compared), paced by `pace` (`offload_fetch_mbps`). The
    /// image goes to staging and Incus only: never a cache entry and never
    /// an `image.cached` frame. The caller deletes it right after init.
    pub fn ensure_restore_image(
        &self,
        d: &OperationDispatch,
        pace: &dyn Fn(u64) -> bool,
        still_wanted: &dyn Fn() -> bool,
    ) -> Result<(), ImageError> {
        let (Some(restore), Some(plan)) = (d.restore.as_ref(), d.image.as_ref()) else {
            return Err(ImageError::new(
                SandboxErrorCode::ProtocolError,
                "restore image missing",
            ));
        };
        // Ingress validated this; a restore never fetches anything else.
        if plan.fingerprint != restore.fingerprint || plan.upstream.is_some() {
            return Err(ImageError::new(
                SandboxErrorCode::ProtocolError,
                "restore image differs",
            ));
        }
        self.ensure_inner(d, plan, Some(pace), still_wanted)
    }

    fn ensure_inner(
        &self,
        d: &OperationDispatch,
        plan: &sandbox_protocol::DispatchImageV11,
        restore_pace: Option<&dyn Fn(u64) -> bool>,
        still_wanted: &dyn Fn() -> bool,
    ) -> Result<(), ImageError> {
        let fp = plan.fingerprint.as_str();
        // One wssp daemon per Incus server: while another daemon's marker is
        // live, no work downloads, reserves, evicts or imports into the
        // shared store. Checked again after every wake below.
        ImageError::shared_incus_server(self.inner.runtime.as_ref())?;
        // Single flight: wait for another fetch of the same image.
        {
            let mut inflight = self
                .inner
                .inflight
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            while inflight.contains(fp) {
                let (guard, _) = self
                    .inner
                    .inflight_cv
                    .wait_timeout(inflight, Duration::from_secs(1))
                    .unwrap_or_else(|e| e.into_inner());
                inflight = guard;
                if !still_wanted() {
                    return Err(ImageError::new(
                        SandboxErrorCode::Cancelled,
                        "create no longer wanted",
                    ));
                }
                // The daemon may have degraded while this fetch waited.
                ImageError::shared_incus_server(self.inner.runtime.as_ref())?;
            }
            inflight.insert(fp.to_owned());
        }
        let result = match &plan.upstream {
            Some(upstream) => self.fetch_upstream_and_import(d, fp, upstream, still_wanted),
            None => self.fetch_and_import(d, fp, plan.size_bytes, restore_pace, still_wanted),
        };
        self.inner
            .inflight
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(fp);
        self.inner.inflight_cv.notify_all();
        result
    }

    /// `restore_pace` is `Some` only for a restore's disk image (S6): paced,
    /// and never recorded as a cache entry.
    fn fetch_and_import(
        &self,
        d: &OperationDispatch,
        fp: &str,
        size: u64,
        restore_pace: Option<&dyn Fn(u64) -> bool>,
        still_wanted: &dyn Fn() -> bool,
    ) -> Result<(), ImageError> {
        if self.inner.runtime.resolve_image_ref(fp).is_ok() {
            // Present (an operator copy or one another daemon on this daemon
            // imported): use it, never manage what this daemon did not import.
            return Ok(());
        }
        self.foreign_gate(d, fp)?;
        // The download's bytes are reserved before the first write (P1-4).
        let part_name = if restore_pace.is_some() {
            format!("{RESTORE_PART_PREFIX}{}.part", &fp[7..])
        } else {
            format!("{}.part", &fp[7..])
        };
        let _reservation = self.reserve(&part_name, size)?;
        let part = self.inner.staging.join(&part_name);
        let deadline =
            Instant::now() + Duration::from_secs(600).max(Duration::from_secs(size / (1 << 20)));
        let mut last_error =
            ImageError::new(SandboxErrorCode::ImageUnavailable, "image unavailable");
        for _ in 0..FETCH_ATTEMPTS {
            if !still_wanted() {
                return Err(ImageError::new(
                    SandboxErrorCode::Cancelled,
                    "create no longer wanted",
                ));
            }
            if Instant::now() >= deadline {
                return Err(ImageError::new(
                    SandboxErrorCode::ImageFetchTimeout,
                    "image fetch timed out",
                ));
            }
            match self.fetch_once(d, fp, size, &part, restore_pace, still_wanted) {
                Ok(()) => break,
                Err(error) if error.code == SandboxErrorCode::Transport => last_error = error,
                Err(error) => {
                    if error.code == SandboxErrorCode::ImageCorrupt {
                        let _ = std::fs::remove_file(&part);
                    }
                    return Err(error);
                }
            }
        }
        let (digest, written) = sha256_file(&part).map_err(|_| {
            ImageError::new(SandboxErrorCode::Transport, "image staging unreadable")
        })?;
        if written != size || format!("sha256:{digest}") != fp {
            if written >= size {
                let _ = std::fs::remove_file(&part);
                return Err(ImageError::new(
                    SandboxErrorCode::ImageCorrupt,
                    "image hash mismatch",
                ));
            }
            return Err(last_error);
        }
        self.progress(d, ProgressPhase::ImportingImage, Some(size), Some(size));
        let imported = match self.inner.runtime.import_image(&part) {
            Ok(imported) => imported,
            // Two daemons on one daemon raced: the image now exists; leave it unmanaged.
            Err(_) if self.inner.runtime.resolve_image_ref(fp).is_ok() => {
                let _ = std::fs::remove_file(&part);
                return Ok(());
            }
            Err(error) => {
                let _ = std::fs::remove_file(&part);
                if let Some(refusal) = ImageError::guard_refusal(&error) {
                    return Err(refusal);
                }
                // Pre-import validation refusals carry a fixed reason token.
                if error.code == SandboxErrorCode::ImageRejected {
                    tracing::warn!(
                        operation_id = %d.operation_id,
                        fingerprint = fp,
                        reason = %error.message,
                        "host refused image import"
                    );
                }
                return Err(ImageError::new(
                    SandboxErrorCode::ImageRejected,
                    "image import refused",
                ));
            }
        };
        let _ = std::fs::remove_file(&part);
        let resolved = self.inner.runtime.resolve_image_ref(&imported);
        let arch_ok = resolved.as_ref().is_ok_and(|image| {
            image.fingerprint == fp
                && d.architecture
                    .as_deref()
                    .is_none_or(|arch| arch == image.architecture)
        });
        if imported != fp || !arch_ok {
            let _ = self.inner.runtime.delete_image(&imported);
            return Err(ImageError::new(
                SandboxErrorCode::ImageRejected,
                "imported image rejected",
            ));
        }
        if restore_pace.is_some() {
            // S6: a restore's disk image is never a cache entry.
            return Ok(());
        }
        self.record(fp, &d.sandbox_owner_id, size, Origin::Fetched, false);
        self.push(DaemonControlMessage::ImageCached(ImageCachedV11 {
            fingerprint: fp.to_owned(),
            image_owner_id: d.sandbox_owner_id.clone(),
            transfer_id: None,
            operation_id: Some(d.operation_id.clone()),
            compressed_bytes: size,
            unpacked_bytes: None,
            origin: sandbox_protocol::ImageOrigin::Fetched,
            totals: self.totals(),
        }));
        Ok(())
    }

    /// B3: `accept_foreign_images = false` is enforced here too, whatever
    /// the server planned: never fetch or import another account's image.
    fn foreign_gate(&self, d: &OperationDispatch, fp: &str) -> Result<(), ImageError> {
        if !self.inner.settings.accept_foreign
            && self.host_owner().as_deref() != Some(d.sandbox_owner_id.as_str())
        {
            tracing::warn!(
                operation_id = %d.operation_id,
                fingerprint = fp,
                reason = "foreign_image_not_accepted",
                "host refused image fetch"
            );
            return Err(ImageError::new(
                SandboxErrorCode::ImageRejected,
                "foreign images are not accepted on this host",
            ));
        }
        Ok(())
    }

    /// Community bases (D-B, I3): download a raw upstream split image from
    /// the fixed host, verify each file's size and sha256 and the combined
    /// fingerprint, validate both files, import them into this daemon's
    /// Incus project and compare the imported fingerprint. Single flight per
    /// fingerprint (the caller), the foreign gate, one reservation and one
    /// resumable staging entry per file. Failures: upstream 404/410 (or a
    /// redirect) is `image_unavailable`; a size or hash mismatch is
    /// `image_corrupt`; a validation or post-import refusal is
    /// `image_rejected`.
    fn fetch_upstream_and_import(
        &self,
        d: &OperationDispatch,
        fp: &str,
        plan: &sandbox_protocol::DispatchUpstreamImageV11,
        still_wanted: &dyn Fn() -> bool,
    ) -> Result<(), ImageError> {
        if self.inner.runtime.resolve_image_ref(fp).is_ok() {
            return Ok(());
        }
        self.foreign_gate(d, fp)?;
        let Some((base, http)) = self.upstream_client() else {
            return Err(ImageError::new(
                SandboxErrorCode::Transport,
                "upstream image TLS unavailable",
            ));
        };
        let (meta_key, disk_key) = upstream_staging_keys(fp);
        let _meta_reservation = self.reserve(&meta_key, plan.meta_size)?;
        let _disk_reservation = self.reserve(&disk_key, plan.disk_size)?;
        let total = plan.meta_size.saturating_add(plan.disk_size);
        let deadline = Instant::now() + self.upstream_budget(total);
        let files = [
            UpstreamFile {
                path: &plan.meta_path,
                sha256: &plan.meta_sha256,
                size: plan.meta_size,
                staging: self.inner.staging.join(&meta_key),
                before: 0,
                total,
            },
            UpstreamFile {
                path: &plan.disk_path,
                sha256: &plan.disk_sha256,
                size: plan.disk_size,
                staging: self.inner.staging.join(&disk_key),
                before: plan.meta_size,
                total,
            },
        ];
        let remove_both = || {
            for file in &files {
                let _ = std::fs::remove_file(&file.staging);
            }
        };
        for file in &files {
            self.fetch_upstream_file(d, &http, &base, file, deadline, still_wanted)?;
        }
        let (meta, disk) = (&files[0].staging, &files[1].staging);
        if combined_sha256(meta, disk)
            .map_err(|_| ImageError::new(SandboxErrorCode::Transport, "image staging unreadable"))?
            != fp[7..]
        {
            remove_both();
            return Err(ImageError::new(
                SandboxErrorCode::ImageCorrupt,
                "image hash mismatch",
            ));
        }
        if let Err(refusal) = sandbox_runtime::validate_split_image(
            meta,
            disk,
            sandbox_runtime::SPLIT_VIRTUAL_SIZE_MAX,
        ) {
            remove_both();
            tracing::warn!(
                operation_id = %d.operation_id,
                fingerprint = fp,
                reason = refusal.0,
                "host refused image import"
            );
            return Err(ImageError::new(
                SandboxErrorCode::ImageRejected,
                "image import refused",
            ));
        }
        self.progress(d, ProgressPhase::ImportingImage, Some(total), Some(total));
        let imported = self.inner.runtime.import_split_image(meta, disk, fp);
        remove_both();
        let imported = match imported {
            Ok(imported) => imported,
            Err(error) => {
                // A guard refusal stays typed, whatever the store holds.
                if let Some(refusal) = ImageError::guard_refusal(&error) {
                    return Err(refusal);
                }
                // Two daemons on one Incus raced: the image now exists; unmanaged.
                if self.inner.runtime.resolve_image_ref(fp).is_ok() {
                    return Ok(());
                }
                tracing::warn!(
                    operation_id = %d.operation_id,
                    fingerprint = fp,
                    reason = %error.message,
                    "host refused image import"
                );
                return Err(ImageError::new(
                    SandboxErrorCode::ImageRejected,
                    "image import refused",
                ));
            }
        };
        let arch_ok = self
            .inner
            .runtime
            .resolve_image_ref(&imported)
            .is_ok_and(|image| {
                image.fingerprint == fp
                    && d.architecture
                        .as_deref()
                        .is_none_or(|arch| arch == image.architecture)
            });
        if imported != fp || !arch_ok {
            let _ = self.inner.runtime.delete_image(&imported);
            return Err(ImageError::new(
                SandboxErrorCode::ImageRejected,
                "imported image rejected",
            ));
        }
        self.record(fp, &d.sandbox_owner_id, total, Origin::Fetched, false);
        self.push(DaemonControlMessage::ImageCached(ImageCachedV11 {
            fingerprint: fp.to_owned(),
            image_owner_id: d.sandbox_owner_id.clone(),
            transfer_id: None,
            operation_id: Some(d.operation_id.clone()),
            compressed_bytes: total,
            unpacked_bytes: None,
            origin: sandbox_protocol::ImageOrigin::Fetched,
            totals: self.totals(),
        }));
        Ok(())
    }

    /// One upstream file into its staging entry, resumed with `Range` and
    /// retried on transport errors; then its size and sha256.
    fn fetch_upstream_file(
        &self,
        d: &OperationDispatch,
        http: &ureq::Agent,
        base: &str,
        file: &UpstreamFile<'_>,
        deadline: Instant,
        still_wanted: &dyn Fn() -> bool,
    ) -> Result<(), ImageError> {
        let mut last_error = ImageError::new(SandboxErrorCode::Transport, "image download failed");
        for _ in 0..FETCH_ATTEMPTS {
            if !still_wanted() {
                return Err(ImageError::new(
                    SandboxErrorCode::Cancelled,
                    "create no longer wanted",
                ));
            }
            if Instant::now() >= deadline {
                return Err(ImageError::new(
                    SandboxErrorCode::ImageFetchTimeout,
                    "image fetch timed out",
                ));
            }
            match self.upstream_get_once(d, http, base, file, deadline, still_wanted) {
                Ok(()) => break,
                Err(error) if error.code == SandboxErrorCode::Transport => last_error = error,
                Err(error) => {
                    if error.code == SandboxErrorCode::ImageCorrupt {
                        let _ = std::fs::remove_file(&file.staging);
                    }
                    return Err(error);
                }
            }
        }
        let (digest, written) = sha256_file(&file.staging).map_err(|_| {
            ImageError::new(SandboxErrorCode::Transport, "image staging unreadable")
        })?;
        if written != file.size || digest != file.sha256 {
            if written >= file.size {
                let _ = std::fs::remove_file(&file.staging);
                return Err(ImageError::new(
                    SandboxErrorCode::ImageCorrupt,
                    "image hash mismatch",
                ));
            }
            return Err(last_error);
        }
        Ok(())
    }

    /// One GET of an upstream file from where its staging entry ends: a
    /// `206` from exactly that offset appends; a `200` (the server ignored
    /// the range) restarts the file from byte 0. Never more than the pinned
    /// size is written.
    fn upstream_get_once(
        &self,
        d: &OperationDispatch,
        http: &ureq::Agent,
        base: &str,
        file: &UpstreamFile<'_>,
        deadline: Instant,
        still_wanted: &dyn Fn() -> bool,
    ) -> Result<(), ImageError> {
        let timed_out =
            || ImageError::new(SandboxErrorCode::ImageFetchTimeout, "image fetch timed out");
        let staging_error =
            || ImageError::new(SandboxErrorCode::Transport, "image staging unavailable");
        let mut part = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&file.staging)
            .map_err(|_| staging_error())?;
        let mut have = part
            .metadata()
            .map(|m| m.len())
            .map_err(|_| staging_error())?;
        if have > file.size {
            part.set_len(0).map_err(|_| staging_error())?;
            have = 0;
        }
        if have == file.size {
            return Ok(());
        }
        // The fetch's remaining total budget bounds this whole GET, body
        // included: a trickling upstream that never trips the idle timeout
        // cannot hold the cache reservation and the per-fingerprint lock
        // past it.
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(timed_out());
        }
        let mut request = http
            .get(format!("{base}{}", file.path))
            .config()
            .timeout_global(Some(remaining))
            .build();
        if have > 0 {
            request = request.header("Range", format!("bytes={have}-"));
        }
        let mut response = request.call().map_err(|_| {
            if Instant::now() >= deadline {
                timed_out()
            } else {
                ImageError::new(SandboxErrorCode::Transport, "image download failed")
            }
        })?;
        let status = response.status().as_u16();
        let resume = match status {
            200 => 0,
            206 if have > 0
                && response
                    .headers()
                    .get("content-range")
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|range| {
                        range.starts_with(&format!("bytes {have}-"))
                            && range.ends_with(&format!("/{}", file.size))
                    }) =>
            {
                have
            }
            // A range from anywhere else: start over on the next attempt.
            206 => {
                part.set_len(0).map_err(|_| staging_error())?;
                return Err(ImageError::new(
                    SandboxErrorCode::Transport,
                    "upstream range mismatch",
                ));
            }
            404 | 410 => {
                return Err(ImageError::new(
                    SandboxErrorCode::ImageUnavailable,
                    "upstream image gone",
                ));
            }
            300..=399 => {
                return Err(ImageError::new(
                    SandboxErrorCode::ImageUnavailable,
                    "upstream redirect refused",
                ));
            }
            _ => {
                return Err(ImageError::new(
                    SandboxErrorCode::Transport,
                    "image download refused",
                ));
            }
        };
        part.set_len(resume)
            .and_then(|_| part.seek(std::io::SeekFrom::Start(resume)).map(|_| ()))
            .map_err(|_| staging_error())?;
        let mut reader = response.body_mut().as_reader();
        let mut done = resume;
        let mut next_report = done + PROGRESS_EVERY;
        let mut buffer = vec![0u8; 1 << 20];
        while done < file.size {
            if !still_wanted() {
                return Err(ImageError::new(
                    SandboxErrorCode::Cancelled,
                    "create no longer wanted",
                ));
            }
            if Instant::now() >= deadline {
                return Err(timed_out());
            }
            let want = (file.size - done).min(buffer.len() as u64) as usize;
            let n = match reader.read(&mut buffer[..want]) {
                Ok(0) => {
                    return Err(ImageError::new(
                        SandboxErrorCode::Transport,
                        "image download truncated",
                    ));
                }
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) if Instant::now() >= deadline => return Err(timed_out()),
                Err(_) => {
                    return Err(ImageError::new(
                        SandboxErrorCode::Transport,
                        "image download failed",
                    ));
                }
            };
            part.write_all(&buffer[..n]).map_err(|_| {
                ImageError::new(SandboxErrorCode::Transport, "image staging write failed")
            })?;
            done += n as u64;
            if done >= next_report {
                self.progress(
                    d,
                    ProgressPhase::FetchingImage,
                    Some(file.before + done),
                    Some(file.total),
                );
                next_report = done + PROGRESS_EVERY;
            }
        }
        // More than the pinned size is a different file.
        let mut extra = [0u8; 1];
        if matches!(reader.read(&mut extra), Ok(n) if n > 0) {
            return Err(ImageError::new(
                SandboxErrorCode::ImageCorrupt,
                "upstream file longer than pinned",
            ));
        }
        part.sync_all().map_err(|_| {
            ImageError::new(SandboxErrorCode::Transport, "image staging sync failed")
        })?;
        Ok(())
    }

    fn fetch_once(
        &self,
        d: &OperationDispatch,
        fp: &str,
        size: u64,
        part: &Path,
        pace: Option<&dyn Fn(u64) -> bool>,
        still_wanted: &dyn Fn() -> bool,
    ) -> Result<(), ImageError> {
        let have = std::fs::metadata(part)
            .map(|m| m.len())
            .unwrap_or(0)
            .min(size);
        let request_id = self.next_id("fetch");
        let rx = self.register(&request_id);
        self.push(DaemonControlMessage::ImageFetchRequest(
            ImageFetchRequestV11 {
                request_id: request_id.clone(),
                operation_id: d.operation_id.clone(),
                sandbox_id: d.sandbox_id.clone(),
                generation: d.generation,
                attempt: d.attempt,
                fingerprint: fp.to_owned(),
                resume_offset: have,
            },
        ));
        let grant = wait_for(&rx, GRANT_WAIT, still_wanted);
        self.unregister(&request_id);
        match grant {
            Some(ServerControlMessage::ImageFetchGrant(mut grant)) => {
                // The data key leaves the frame at once (wiped on drop).
                let key = grant.encryption.as_mut().map(crypto::take_grant_key);
                let result = match grant.mode {
                    ImageTransferMode::S3 => self.fetch_s3(
                        d,
                        &grant,
                        key.as_deref().map(String::as_str),
                        part,
                        pace,
                        still_wanted,
                    ),
                    ImageTransferMode::Relay => {
                        self.fetch_relay(d, &grant, part, pace, still_wanted)
                    }
                };
                // Round-2 P2-9: a grant this attempt gives up on is ended
                // before any retry, so the next request is not refused as
                // `in_progress` against the transfer it abandoned. Frames on
                // the control lane are handled in order.
                if let Err(error) = &result {
                    self.push(DaemonControlMessage::ImageFetchFailed(
                        ImageFetchFailedV11 {
                            request_id: None,
                            transfer_id: Some(grant.transfer_id.clone()),
                            fingerprint: fp.to_owned(),
                            code: fetch_failure_code(error.code),
                        },
                    ));
                }
                result
            }
            Some(ServerControlMessage::ImageFetchRefused(_)) => Err(ImageError::new(
                SandboxErrorCode::ImageUnavailable,
                "image fetch refused",
            )),
            _ => Err(ImageError::new(
                SandboxErrorCode::Transport,
                "no image fetch grant",
            )),
        }
    }

    fn open_part(part: &Path, size: u64, align: u64) -> Result<(std::fs::File, u64), ImageError> {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(part)
            .map_err(|_| {
                ImageError::new(SandboxErrorCode::Transport, "image staging unavailable")
            })?;
        let len = file.metadata().map(|m| m.len()).map_err(|_| {
            ImageError::new(SandboxErrorCode::Transport, "image staging unavailable")
        })?;
        let resume = (len.min(size) / align) * align;
        file.set_len(resume)
            .and_then(|_| file.seek(std::io::SeekFrom::Start(resume)).map(|_| ()))
            .map_err(|_| {
                ImageError::new(SandboxErrorCode::Transport, "image staging unavailable")
            })?;
        Ok((file, resume))
    }

    fn fetch_s3(
        &self,
        d: &OperationDispatch,
        grant: &sandbox_protocol::ImageFetchGrantV11,
        key: Option<&str>,
        part: &Path,
        pace: Option<&dyn Fn(u64) -> bool>,
        still_wanted: &dyn Fn() -> bool,
    ) -> Result<(), ImageError> {
        let url = grant
            .url
            .as_deref()
            .ok_or_else(|| ImageError::new(SandboxErrorCode::ProtocolError, "grant has no URL"))?;
        let key = match key {
            Some(text) => Some(crypto::RecordKey::from_base64(text).map_err(|_| {
                ImageError::new(SandboxErrorCode::ProtocolError, "invalid image key")
            })?),
            None => None,
        };
        let size = grant.size_bytes;
        let align = if key.is_some() {
            crypto::RECORD as u64
        } else {
            1
        };
        let (mut file, resume) = Self::open_part(part, size, align)?;
        let remote_offset = if key.is_some() {
            resume / crypto::RECORD as u64 * crypto::SEALED_RECORD as u64
        } else {
            resume
        };
        let mut request = self.inner.http.get(url);
        if remote_offset > 0 {
            request = request.header("Range", format!("bytes={remote_offset}-"));
        }
        let mut response = request
            .call()
            .map_err(|_| ImageError::new(SandboxErrorCode::Transport, "image download failed"))?;
        let status = response.status().as_u16();
        if status != 200 && status != 206 {
            return Err(ImageError::new(
                SandboxErrorCode::Transport,
                "image download refused",
            ));
        }
        let mut reader = response.body_mut().as_reader();
        let mut done = resume;
        let mut next_report = done + PROGRESS_EVERY;
        let mut index = resume / crypto::RECORD as u64;
        let records = crypto::record_count(size);
        let chunk = if key.is_some() {
            crypto::SEALED_RECORD
        } else {
            1 << 20
        };
        let mut buffer = vec![0u8; chunk];
        while done < size {
            if !still_wanted() {
                return Err(ImageError::new(
                    SandboxErrorCode::Cancelled,
                    "create no longer wanted",
                ));
            }
            let want = match &key {
                Some(_) => {
                    let plain = (size - done).min(crypto::RECORD as u64) as usize;
                    plain + sandbox_protocol::IMAGE_ENCRYPTION_TAG_BYTES as usize
                }
                None => (size - done).min(chunk as u64) as usize,
            };
            read_exact_or_transport(&mut reader, &mut buffer[..want])?;
            if pace.is_some_and(|pace| !pace(want as u64)) {
                return Err(ImageError::new(
                    SandboxErrorCode::Cancelled,
                    "create no longer wanted",
                ));
            }
            let plain = match &key {
                Some(key) => key
                    .open(index, index + 1 == records, &buffer[..want])
                    .map_err(|_| {
                        ImageError::new(
                            SandboxErrorCode::ImageCorrupt,
                            "image record failed authentication",
                        )
                    })?,
                None => buffer[..want].to_vec(),
            };
            index += 1;
            file.write_all(&plain).map_err(|_| {
                ImageError::new(SandboxErrorCode::Transport, "image staging write failed")
            })?;
            done += plain.len() as u64;
            if done >= next_report {
                self.progress(d, ProgressPhase::FetchingImage, Some(done), Some(size));
                next_report = done + PROGRESS_EVERY;
            }
        }
        file.sync_all().map_err(|_| {
            ImageError::new(SandboxErrorCode::Transport, "image staging sync failed")
        })?;
        Ok(())
    }

    fn relay_get(&self, link: &ImageRelayLinkV11) -> Result<(Vec<u8>, Option<String>), ImageError> {
        let url = format!("{}{}", self.inner.relay_base, link.link_id);
        let mut response = self
            .inner
            .http
            .get(&url)
            .header(
                "Authorization",
                format!("Bearer {}", self.inner.host_secret),
            )
            .header("X-Wssp-Image-Link", &link.token)
            .header("Accept-Encoding", "identity")
            .call()
            .map_err(|_| ImageError::new(SandboxErrorCode::Transport, "relay download failed"))?;
        if response.status().as_u16() != 200 {
            return Err(ImageError::new(
                SandboxErrorCode::Transport,
                "relay part not served",
            ));
        }
        let sha = response
            .headers()
            .get("x-wssp-part-sha256")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let bytes = response
            .body_mut()
            .with_config()
            .limit(sandbox_protocol::IMAGE_RELAY_PART_BYTES + 1)
            .read_to_vec()
            .map_err(|_| ImageError::new(SandboxErrorCode::Transport, "relay download failed"))?;
        Ok((bytes, sha))
    }

    fn relay_put(&self, link: &ImageRelayLinkV11, bytes: Vec<u8>) -> Result<(), UploadFailure> {
        let url = format!("{}{}", self.inner.relay_base, link.link_id);
        let response = self
            .inner
            .http
            .put(&url)
            .header(
                "Authorization",
                format!("Bearer {}", self.inner.host_secret),
            )
            .header("X-Wssp-Image-Link", &link.token)
            .header("Content-Type", "application/octet-stream")
            .config()
            .timeout_send_body(Some(relay_part_send_budget(bytes.len())))
            .build()
            .send(&bytes[..])
            .map_err(|e| UploadFailure::transport(&e).at_part(link.part))?;
        let status = response.status().as_u16();
        if status != 204 {
            return Err(UploadFailure::status(status, None, 0).at_part(link.part));
        }
        Ok(())
    }

    fn more_links(
        &self,
        transfer: &str,
        role: ImageLinkRole,
        parts: Vec<u32>,
        still_wanted: &dyn Fn() -> bool,
    ) -> Option<Vec<ImageRelayLinkV11>> {
        let key = format!("links:{transfer}:{role:?}");
        let rx = self.register(&key);
        self.push(DaemonControlMessage::ImageLinksRequest(
            ImageLinksRequestV11 {
                transfer_id: transfer.to_owned(),
                role,
                parts,
            },
        ));
        let answer = wait_for(&rx, GRANT_WAIT, still_wanted);
        self.unregister(&key);
        match answer {
            Some(ServerControlMessage::ImageLinksGrant(grant)) => Some(grant.links),
            _ => None,
        }
    }

    fn fetch_relay(
        &self,
        d: &OperationDispatch,
        grant: &sandbox_protocol::ImageFetchGrantV11,
        part: &Path,
        pace: Option<&dyn Fn(u64) -> bool>,
        still_wanted: &dyn Fn() -> bool,
    ) -> Result<(), ImageError> {
        let size = grant.size_bytes;
        let part_size = grant.part_size;
        let part_count = |count: u64| {
            u32::try_from(count).map_err(|_| {
                ImageError::new(
                    SandboxErrorCode::ProtocolError,
                    "image part count exceeds the relay part range",
                )
            })
        };
        let total_parts = part_count(size.div_ceil(part_size).max(1))?;
        let (mut file, resume) = Self::open_part(part, size, part_size)?;
        let mut next = part_count(resume / part_size + 1)?;
        let mut links: VecDeque<ImageRelayLinkV11> = grant
            .links
            .clone()
            .unwrap_or_default()
            .into_iter()
            .collect();
        while next <= total_parts {
            if !still_wanted() {
                return Err(ImageError::new(
                    SandboxErrorCode::Cancelled,
                    "create no longer wanted",
                ));
            }
            let link = match links.iter().position(|l| l.part == next) {
                Some(i) => links.remove(i),
                None => None,
            };
            let link = match link {
                Some(link) => link,
                None => {
                    let wanted: Vec<u32> = (next..=total_parts.min(next + 3)).collect();
                    links = self
                        .more_links(
                            &grant.transfer_id,
                            ImageLinkRole::Dest,
                            wanted,
                            still_wanted,
                        )
                        .ok_or_else(|| {
                            ImageError::new(SandboxErrorCode::Transport, "no relay links")
                        })?
                        .into();
                    continue;
                }
            };
            let (bytes, served_sha) = self.relay_get(&link)?;
            if pace.is_some_and(|pace| !pace(bytes.len() as u64)) {
                return Err(ImageError::new(
                    SandboxErrorCode::Cancelled,
                    "create no longer wanted",
                ));
            }
            let expected = (size - u64::from(next - 1) * part_size).min(part_size);
            let sha = sha256_hex(&bytes);
            if bytes.len() as u64 != expected || served_sha.as_deref().is_some_and(|s| s != sha) {
                return Err(ImageError::new(
                    SandboxErrorCode::Transport,
                    "relay part damaged",
                ));
            }
            file.write_all(&bytes)
                .and_then(|_| file.sync_data())
                .map_err(|_| {
                    ImageError::new(SandboxErrorCode::Transport, "image staging write failed")
                })?;
            self.push(DaemonControlMessage::ImagePartAck(ImagePartAckV11 {
                transfer_id: grant.transfer_id.clone(),
                part: next,
                sha256: sha,
            }));
            let done = u64::from(next) * part_size;
            self.progress(
                d,
                ProgressPhase::FetchingImage,
                Some(done.min(size)),
                Some(size),
            );
            next += 1;
        }
        Ok(())
    }

    /// Export a managed or operator image to staging; exactly one file whose
    /// SHA-256 equals the fingerprint (a unified image), else `format_unsupported`.
    fn export_unified(
        &self,
        fingerprint: &str,
    ) -> Result<(PathBuf, u64, StagingReservation), ImageFailureCode> {
        // One directory and one reservation per export job (round-2 P2-5):
        // concurrent exports of one image never share a charge or a path.
        let name = format!("export-{}-{}", &fingerprint[7..], self.next_id("job"));
        let dir = self.inner.staging.join(&name);
        // An export is a full copy of the image: reserve it first (P1-4).
        let estimate = self
            .lock_journal()
            .file
            .entries
            .get(fingerprint)
            .map(|e| e.compressed_bytes)
            .or_else(|| {
                self.inner
                    .runtime
                    .resolve_image_ref(fingerprint)
                    .ok()
                    .and_then(|image| image.size_bytes)
            })
            .unwrap_or(0);
        let mut reservation = self
            .reserve(&name, estimate)
            .map_err(|_| ImageFailureCode::Io)?;
        std::fs::create_dir(&dir).map_err(|_| ImageFailureCode::Io)?;
        reservation.owned = Some(dir.clone());
        let (file, size) = self.export_into(fingerprint, &dir)?;
        Ok((file, size, reservation))
    }

    /// Export `fingerprint` into the existing directory `dir`: exactly one
    /// file whose SHA-256 equals the fingerprint (a unified image), else
    /// `format_unsupported`. The caller reserved the bytes.
    pub(crate) fn export_into(
        &self,
        fingerprint: &str,
        dir: &Path,
    ) -> Result<(PathBuf, u64), ImageFailureCode> {
        let files = self
            .inner
            .runtime
            .export_image(fingerprint, dir)
            .map_err(|_| ImageFailureCode::Io)?;
        let [file] = files.as_slice() else {
            return Err(ImageFailureCode::FormatUnsupported);
        };
        let (digest, size) = sha256_file(file).map_err(|_| ImageFailureCode::Io)?;
        if format!("sha256:{digest}") != fingerprint {
            return Err(ImageFailureCode::FormatUnsupported);
        }
        Ok((file.clone(), size))
    }

    fn cancelled(&self, transfer: &str) -> bool {
        self.inner
            .cancelled
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(transfer)
    }

    /// Peer source: upload relay parts as links arrive (the server only
    /// grants within the destination's ACK window).
    fn serve(&self, request: sandbox_protocol::ImageServeRequestV11) {
        let transfer = request.transfer_id.clone();
        let fail = |failure: UploadFailure| {
            failure.log("image serve ended", Some(&transfer));
            if let Some(frame) = failure.frame(Some(&transfer), None) {
                self.push(DaemonControlMessage::ImageJobFailed(frame));
            }
        };
        self.mark_in_use(&request.fingerprint, 1);
        let exported = self.export_unified(&request.fingerprint);
        let (path, size, _reservation) = match exported {
            Ok(found) => found,
            Err(code) => {
                self.mark_in_use(&request.fingerprint, -1);
                return fail(UploadFailure::new(code, ImageFailureCause::Export));
            }
        };
        let part_size = request.part_size;
        let mut links: VecDeque<ImageRelayLinkV11> = request.links.into_iter().collect();
        let mut next = links.iter().map(|l| l.part).min().unwrap_or(1);
        let keep_going = || !self.cancelled(&transfer);
        let no_grant = || UploadFailure::new(ImageFailureCode::Timeout, ImageFailureCause::NoGrant);
        let outcome = (|| -> Result<(), UploadFailure> {
            // A count past u32 cannot be addressed by relay parts: fail rather
            // than serve a truncated range and report success.
            let total = u32::try_from(size.div_ceil(part_size).max(1)).map_err(|_| {
                UploadFailure::new(ImageFailureCode::Io, ImageFailureCause::Protocol)
            })?;
            let mut file =
                std::fs::File::open(&path).map_err(|e| UploadFailure::local_io(e.kind()))?;
            let mut idle = 0;
            while next <= total {
                if self.cancelled(&transfer) {
                    return Err(UploadFailure::refused("cancelled"));
                }
                let Some(i) = links.iter().position(|l| l.part == next) else {
                    let wanted: Vec<u32> = (next..=total.min(next + 3)).collect();
                    let granted = self
                        .more_links(&transfer, ImageLinkRole::Source, wanted, &keep_going)
                        .ok_or_else(no_grant)?;
                    if granted.is_empty() {
                        idle += 1;
                        if idle > 600 {
                            return Err(no_grant());
                        }
                        std::thread::sleep(Duration::from_millis(500));
                    } else {
                        idle = 0;
                    }
                    links.extend(granted);
                    continue;
                };
                let Some(link) = links.remove(i) else {
                    continue;
                };
                let len = (size - u64::from(next - 1) * part_size).min(part_size) as usize;
                let mut bytes = vec![0u8; len];
                file.seek(std::io::SeekFrom::Start(u64::from(next - 1) * part_size))
                    .and_then(|_| file.read_exact(&mut bytes))
                    .map_err(|e| UploadFailure::local_io(e.kind()).at_part(next))?;
                let mut tries = 0;
                loop {
                    match self.relay_put(&link, bytes.clone()) {
                        Ok(()) => break,
                        Err(_) if tries < 2 => {
                            tries += 1;
                            std::thread::sleep(Duration::from_secs(1));
                        }
                        Err(failure) => return Err(failure),
                    }
                }
                next += 1;
            }
            Ok(())
        })();
        // The export directory goes with its reservation (`_reservation`).
        self.mark_in_use(&request.fingerprint, -1);
        // A server cancel is the server's own end: nothing to report.
        if let Err(failure) = outcome
            && failure.code != ImageFailureCode::Cancelled
        {
            fail(failure);
        }
    }

    /// Multipart upload to the image store: a publish job (`transfer`) or a
    /// capture (`operation`). Encrypts records when the grant carries a key.
    /// Every end other than success is reported (`image.job.failed`, by
    /// transfer, else by the capture's operation and attempt) unless the
    /// server said another upload stores the image.
    pub fn upload(&self, fingerprint: &str, owner: &str, job: UploadJob) {
        let (transfer, capture) = match job {
            UploadJob::Publish(transfer) => (Some(transfer), None),
            UploadJob::Capture {
                operation_id,
                attempt,
            } => (None, Some((operation_id, attempt))),
        };
        let _ = owner;
        self.mark_in_use(fingerprint, 1);
        let mut transfer_id = transfer.clone();
        let mut waiters = Vec::new();
        let outcome = self.upload_job(
            fingerprint,
            transfer.as_deref(),
            capture.as_ref(),
            &mut transfer_id,
            &mut waiters,
        );
        for key in waiters {
            self.unregister(&key);
        }
        // The export directory went with its reservation (inside the job).
        self.mark_in_use(fingerprint, -1);
        if let Err(UploadEnd::Failed(failure)) = outcome {
            failure.log("image upload ended", transfer_id.as_deref());
            let capture = capture
                .as_ref()
                .map(|(op, attempt)| (op.as_str(), *attempt));
            if let Some(frame) = failure.frame(transfer_id.as_deref(), capture) {
                self.push(DaemonControlMessage::ImageJobFailed(frame));
            }
        }
        #[cfg(test)]
        self.inner.uploads_finished.fetch_add(1, Ordering::SeqCst);
    }

    /// One upload: export, begin, then each grant's parts. `transfer_id`
    /// holds the transfer once known; `waiters` collects the keys to drop.
    fn upload_job(
        &self,
        fingerprint: &str,
        transfer: Option<&str>,
        capture: Option<&(String, u64)>,
        transfer_id: &mut Option<String>,
        waiters: &mut Vec<String>,
    ) -> Result<(), UploadEnd> {
        let (path, size, _reservation) = self
            .export_unified(fingerprint)
            .map_err(|code| UploadFailure::new(code, ImageFailureCause::Export))?;
        let protocol =
            || UploadFailure::new(ImageFailureCode::Rejected, ImageFailureCause::Protocol);
        // A capture waits under its own request id until the server names
        // the transfer in the grant that echoes it (round-3 P2-4).
        let request_id = capture.map(|_| self.next_id("upload"));
        let key = match (transfer, &request_id) {
            (Some(t), _) => format!("upload:{t}"),
            (None, Some(request)) => format!("upload-req:{request}"),
            (None, None) => return Err(UploadEnd::Silent),
        };
        let mut rx = self.register(&key);
        waiters.push(key);
        self.push(DaemonControlMessage::ImageUploadBegin(
            ImageUploadBeginV11 {
                transfer_id: transfer.map(str::to_owned),
                operation_id: capture.map(|(op, _)| op.clone()),
                request_id: request_id.clone(),
                attempt: capture.map(|(_, attempt)| *attempt),
                fingerprint: fingerprint.to_owned(),
                size_bytes: size,
                unpacked_bytes: None,
                format: "unified".into(),
            },
        ));
        let always = || true;
        let mut file = std::fs::File::open(&path).map_err(|e| UploadFailure::local_io(e.kind()))?;
        let mut record_key: Option<crypto::RecordKey> = None;
        let mut heartbeat = transfer.map(|t| self.heartbeat(t));
        let mut sent_total = 0u64;
        loop {
            let mut grant = match wait_for(&rx, self.grant_wait(), &always) {
                Some(ServerControlMessage::ImageUploadGrant(grant)) => grant,
                Some(ServerControlMessage::ImageJobCancel(cancel)) => {
                    return Err(UploadEnd::cancelled(&cancel.reason));
                }
                _ => {
                    return Err(UploadFailure::new(
                        ImageFailureCode::Timeout,
                        ImageFailureCause::NoGrant,
                    )
                    .into());
                }
            };
            if transfer_id.is_none() {
                if grant.request_id != request_id {
                    return Err(protocol().into());
                }
                // Capture: re-key the waiter by the transfer the server opened.
                let key = format!("upload:{}", grant.transfer_id);
                rx = self.register(&key);
                waiters.push(key);
                *transfer_id = Some(grant.transfer_id.clone());
                heartbeat = Some(self.heartbeat(&grant.transfer_id));
            }
            let tid = transfer_id.clone().ok_or_else(protocol)?;
            if let Some(e) = grant.encryption.as_mut() {
                // The data key leaves the frame at once (wiped on drop).
                let text = crypto::take_grant_key(e);
                record_key = Some(crypto::RecordKey::from_base64(&text).map_err(|_| protocol())?);
            }
            let stop = || self.cancelled(&tid);
            let (reported, sent) = self
                .put_parts(
                    &mut file,
                    size,
                    grant.part_size,
                    &grant.parts,
                    record_key.as_ref(),
                    None,
                    &stop,
                    heartbeat.as_ref(),
                )
                .map_err(|failure| {
                    if failure.code == ImageFailureCode::Cancelled {
                        // The server cancelled the transfer: its reason is
                        // waiting on this transfer's receiver.
                        let reason = rx.try_iter().find_map(|frame| match frame {
                            ServerControlMessage::ImageJobCancel(cancel) => Some(cancel.reason),
                            _ => None,
                        });
                        return UploadEnd::cancelled(reason.as_deref().unwrap_or("cancelled"));
                    }
                    let failure = match failure.http_status {
                        Some(403) => UploadFailure {
                            part: failure.part,
                            ..UploadFailure::status(403, Some(grant.expires_at_unix_ms), now_ms())
                        },
                        _ => failure,
                    };
                    failure.into()
                })?;
            sent_total += sent;
            let stored_size = if record_key.is_some() {
                sandbox_protocol::encrypted_image_len(size)
            } else {
                size
            };
            for chunk in reported.chunks(sandbox_protocol::IMAGE_UPLOAD_PARTS_MAX) {
                self.push(DaemonControlMessage::ImageUploadParts(
                    ImageUploadPartsV11 {
                        transfer_id: tid.clone(),
                        parts: chunk.to_vec(),
                    },
                ));
            }
            if sent_total >= stored_size {
                self.push(DaemonControlMessage::ImageUploadComplete(
                    ImageTransferRefV11 { transfer_id: tid },
                ));
                return Ok(());
            }
        }
    }

    /// The image-store part loop shared by template uploads and disk
    /// offloads: read each granted part (whole sealed
    /// records when keyed), pace it through `limit`, PUT it to its presigned
    /// URL and collect its ETag. `stop` is checked before every part (kill
    /// and reconnect preempt a disk upload); a stop ends with code
    /// `Cancelled`. Bytes are counted through the request body into
    /// `heartbeat`. Returns the parts and the bytes sent.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn put_parts(
        &self,
        file: &mut std::fs::File,
        size: u64,
        part_size: u64,
        parts: &[sandbox_protocol::ImageUploadPartUrlV11],
        key: Option<&crypto::RecordKey>,
        limit: Option<&super::offload::Bandwidth>,
        stop: &dyn Fn() -> bool,
        heartbeat: Option<&UploadHeartbeat<'_>>,
    ) -> Result<(Vec<ImageUploadedPartV11>, u64), UploadFailure> {
        let mut reported = Vec::new();
        let mut sent = 0u64;
        for part in parts {
            if stop() {
                return Err(UploadFailure::refused("cancelled"));
            }
            let result = self.put_part(file, size, part_size, part, key, limit, stop, heartbeat);
            match result {
                Ok(etag) => {
                    sent += part.size_bytes;
                    reported.push(ImageUploadedPartV11 { n: part.n, etag });
                }
                Err(failure) => {
                    let failure = failure.at_part(part.n);
                    if failure.code != ImageFailureCode::Cancelled {
                        failure.log(
                            "image store part upload failed",
                            heartbeat.map(|h| h.transfer_id.as_str()),
                        );
                    }
                    return Err(failure);
                }
            }
        }
        Ok((reported, sent))
    }

    /// PUT one part; its ETag.
    #[allow(clippy::too_many_arguments)]
    fn put_part(
        &self,
        file: &mut std::fs::File,
        size: u64,
        part_size: u64,
        part: &sandbox_protocol::ImageUploadPartUrlV11,
        key: Option<&crypto::RecordKey>,
        limit: Option<&super::offload::Bandwidth>,
        stop: &dyn Fn() -> bool,
        heartbeat: Option<&UploadHeartbeat<'_>>,
    ) -> Result<String, UploadFailure> {
        let body = read_stored_part(file, size, part_size, part.n, key)
            .map_err(|e| UploadFailure::local_io(e.kind()))?;
        if body.len() as u64 != part.size_bytes {
            return Err(UploadFailure::new(
                ImageFailureCode::Rejected,
                ImageFailureCause::Protocol,
            ));
        }
        if let Some(limit) = limit
            && !limit.pace(body.len() as u64, stop)
        {
            return Err(UploadFailure::refused("cancelled"));
        }
        let mut reader = CountingBody {
            bytes: &body,
            pos: 0,
            // Where this part starts in the stored object.
            base: u64::from(part.n - 1).saturating_mul(part_size),
            heartbeat,
        };
        let response = self
            .inner
            .http
            .put(&part.url)
            .header("Content-Type", "application/octet-stream")
            .header("Content-Length", body.len().to_string())
            .config()
            .timeout_recv_response(Some(PUT_RESPONSE_WAIT))
            .build()
            .send(ureq::SendBody::from_reader(&mut reader))
            .map_err(|e| UploadFailure::transport(&e))?;
        let status = response.status().as_u16();
        if status != 200 {
            return Err(UploadFailure::status(status, None, 0));
        }
        response
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .ok_or_else(|| UploadFailure::new(ImageFailureCode::Io, ImageFailureCause::Protocol))
    }

    /// Queue a frame for the server (disk offload frames share the image
    /// outbox: both are sent only after reconciliation).
    pub(crate) fn push_frame(&self, message: DaemonControlMessage) {
        self.push(message);
    }

    /// Route frames keyed `key` to the returned receiver (see `deliver`).
    pub(crate) fn register_waiter(&self, key: &str) -> mpsc::Receiver<ServerControlMessage> {
        self.register(key)
    }

    pub(crate) fn unregister_waiter(&self, key: &str) {
        self.unregister(key);
    }

    /// Hand `frame` to the waiter keyed `key`; false when none waits.
    pub(crate) fn deliver_to(&self, key: &str, frame: ServerControlMessage) -> bool {
        self.deliver(key, frame)
    }

    /// The staging directory (charged to the cache budget).
    pub(crate) fn staging_dir(&self) -> &Path {
        &self.inner.staging
    }

    /// The image cache's journal directory (`<state>/images`).
    pub(crate) fn state_dir(&self) -> PathBuf {
        self.journal_dir()
    }

    /// Whether the server cancelled this transfer (`image.job.cancel`).
    pub(crate) fn transfer_cancelled(&self, transfer: &str) -> bool {
        self.cancelled(transfer)
    }

    /// Capture recorded as an origin-pinned managed image; S3 uploads it.
    /// The new image is admitted against the cap like any other (P1-4):
    /// LRU images are evicted to fit it, and when even that cannot make room
    /// the published image is deleted and the capture fails.
    pub fn captured(
        &self,
        d: &OperationDispatch,
        fingerprint: &str,
        size: u64,
        upload: bool,
    ) -> Result<(), ImageError> {
        if let Err(error) = self.make_room(size) {
            let _ = self.inner.runtime.delete_image(fingerprint);
            return Err(error);
        }
        self.record(
            fingerprint,
            &d.sandbox_owner_id,
            size,
            Origin::Captured,
            true,
        );
        self.push(DaemonControlMessage::ImageCached(ImageCachedV11 {
            fingerprint: fingerprint.to_owned(),
            image_owner_id: d.sandbox_owner_id.clone(),
            transfer_id: None,
            operation_id: Some(d.operation_id.clone()),
            compressed_bytes: size.max(1),
            unpacked_bytes: None,
            origin: sandbox_protocol::ImageOrigin::Captured,
            totals: self.totals(),
        }));
        if upload {
            let service = self.clone();
            let fp = fingerprint.to_owned();
            let owner = d.sandbox_owner_id.clone();
            let job = UploadJob::Capture {
                operation_id: d.operation_id.clone(),
                attempt: d.attempt,
            };
            std::thread::spawn(move || service.upload(&fp, &owner, job));
        }
        Ok(())
    }

    /// Capture progress phases, as `operation.progress` frames.
    pub fn capture_progress(&self, d: &OperationDispatch, phase: sandbox_runtime::CapturePhase) {
        let phase = match phase {
            sandbox_runtime::CapturePhase::Freezing => ProgressPhase::Freezing,
            sandbox_runtime::CapturePhase::Snapshotting => ProgressPhase::Snapshotting,
            sandbox_runtime::CapturePhase::Copying => ProgressPhase::Copying,
            sandbox_runtime::CapturePhase::Scrubbing => ProgressPhase::Scrubbing,
            sandbox_runtime::CapturePhase::Publishing => ProgressPhase::Publishing,
        };
        self.progress(d, phase, None, None);
    }

    /// `wssp host images prune`: the CLI drops a request file next to the cache
    /// journal; the running daemon (the journal's only writer) applies it and
    /// writes the result. Checked every few seconds by the connect loop.
    pub fn poll_prune_request(&self) {
        let dir = self
            .inner
            .staging
            .parent()
            .unwrap_or(&self.inner.staging)
            .to_path_buf();
        let request = dir.join(PRUNE_REQUEST_FILE);
        let Ok(bytes) = std::fs::read(&request) else {
            return;
        };
        let _ = std::fs::remove_file(&request);
        let dry_run = serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|v| v.get("dryRun").and_then(serde_json::Value::as_bool))
            .unwrap_or(true);
        let pruned = self.prune(dry_run);
        let result = serde_json::json!({ "dryRun": dry_run, "fingerprints": pruned });
        let _ = std::fs::write(dir.join(PRUNE_RESULT_FILE), result.to_string());
    }

    /// Out-of-band deletions (`incus image delete`): drop the journal entries
    /// of managed images the host image store no longer has, and report each
    /// (`image.evicted`, reason `operator`) so the server forgets the copy.
    /// `None` when the inventory could not be read: an error is never
    /// evidence of absence, so nothing is dropped. A run that dropped
    /// entries also refreshes the census.
    pub fn reconcile_inventory(&self) -> Option<usize> {
        // Snapshot before the read: an entry recorded after it (a fetch or
        // capture that just landed) is never judged by an older inventory.
        let snapshot = self.inventory_candidates();
        if snapshot.is_empty() {
            return Some(0);
        }
        let present = match self.inner.runtime.list_image_fingerprints() {
            Ok(present) => present,
            Err(error) => {
                tracing::warn!(code = ?error.code, "image inventory unavailable; reconcile skipped");
                return None;
            }
        };
        let dropped = self.reconcile_with(snapshot, present);
        if dropped > 0 {
            self.begin_periodic_census();
        }
        Some(dropped)
    }

    /// The periodic reconcile, off the connect loop (it waits on Incus);
    /// skipped while the previous one still runs.
    pub fn spawn_reconcile(&self) {
        if self.inner.reconciling.swap(true, Ordering::SeqCst) {
            return;
        }
        let service = self.clone();
        let spawned = std::thread::Builder::new()
            .name("wssp-image-reconcile".into())
            .spawn(move || {
                service.reconcile_inventory();
                service.inner.reconciling.store(false, Ordering::SeqCst);
            });
        if spawned.is_err() {
            self.inner.reconciling.store(false, Ordering::SeqCst);
        }
    }

    fn inventory_candidates(&self) -> Vec<CacheEntry> {
        self.lock_journal().file.entries.values().cloned().collect()
    }

    /// Drop each snapshot entry absent from `present`, only while it is still
    /// exactly the entry that was snapshotted (no record or use since) and no
    /// fetch, import, serve or upload holds its fingerprint.
    fn reconcile_with(
        &self,
        snapshot: Vec<CacheEntry>,
        present: std::collections::BTreeSet<String>,
    ) -> usize {
        let gone: Vec<CacheEntry> = snapshot
            .into_iter()
            .filter(|e| !present.contains(&e.fingerprint))
            .collect();
        if gone.is_empty() {
            return 0;
        }
        let dropped: Vec<CacheEntry> = {
            let mut journal = self.lock_journal();
            let inflight = self
                .inner
                .inflight
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            let dropped: Vec<CacheEntry> = gone
                .into_iter()
                .filter(|e| {
                    journal.file.entries.get(&e.fingerprint) == Some(e)
                        && !self.is_in_use(&e.fingerprint)
                        && !inflight.contains(&e.fingerprint)
                })
                .collect();
            for entry in &dropped {
                journal.file.entries.remove(&entry.fingerprint);
            }
            if !dropped.is_empty() {
                journal.save_or_warn();
            }
            dropped
        };
        let totals = self.totals();
        for entry in &dropped {
            tracing::info!(
                fingerprint = %entry.fingerprint,
                "managed image deleted out of band; journal entry dropped"
            );
            for owner in &entry.owners {
                self.push(DaemonControlMessage::ImageEvicted(ImageEvictedV11 {
                    fingerprint: entry.fingerprint.clone(),
                    image_owner_id: owner.clone(),
                    reason: ImageEvictReason::Operator,
                    totals: totals.clone(),
                }));
            }
        }
        dropped.len()
    }

    /// `wssp host images list`: like prune, the CLI drops a request file and the
    /// running daemon (the journal's only writer) reconciles the journal with
    /// the host image store before the CLI reads it.
    pub fn poll_list_request(&self) {
        let dir = self.journal_dir();
        let request = dir.join(LIST_REQUEST_FILE);
        if std::fs::remove_file(&request).is_err() {
            return;
        }
        // Off the connect loop: the inventory read waits on Incus.
        let service = self.clone();
        let _ = std::thread::Builder::new()
            .name("wssp-image-list".into())
            .spawn(move || {
                let dropped = service.reconcile_inventory();
                let result = serde_json::json!({
                    "reconciled": dropped.is_some(),
                    "dropped": dropped.unwrap_or(0),
                });
                // Renamed into place: the CLI never reads a partial answer.
                let tmp = dir.join(format!("{LIST_RESULT_FILE}.tmp"));
                if std::fs::write(&tmp, result.to_string()).is_ok() {
                    let _ = std::fs::rename(&tmp, dir.join(LIST_RESULT_FILE));
                }
            });
    }

    fn journal_dir(&self) -> PathBuf {
        self.inner
            .staging
            .parent()
            .unwrap_or(&self.inner.staging)
            .to_path_buf()
    }

    /// `wssp host images list` rows.
    pub fn entries(&self) -> Vec<CacheEntry> {
        self.lock_journal().file.entries.values().cloned().collect()
    }
}

/// What an image-store upload is for: an owner-backfill publish of a known
/// transfer, or a capture's upload bound to its originating dispatch attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadJob {
    Publish(String),
    Capture { operation_id: String, attempt: u64 },
}

/// Liveness of one upload: the byte offset reached in the stored object
/// (monotonic within the transfer: a part sent again never moves it back),
/// counted through the request bodies and sent as `image.upload.progress` at
/// most every `every` and only when it advanced.
pub(crate) struct UploadHeartbeat<'a> {
    service: &'a ImageService,
    transfer_id: String,
    every: Duration,
    reached: std::cell::Cell<u64>,
    /// When the last heartbeat went, and the offset it carried.
    reported: std::cell::Cell<(Instant, u64)>,
}

impl UploadHeartbeat<'_> {
    fn reach(&self, offset: u64) {
        let reached = self.reached.get().max(offset);
        self.reached.set(reached);
        let (at, last) = self.reported.get();
        if reached > last && at.elapsed() >= self.every {
            self.reported.set((Instant::now(), reached));
            self.service.push(DaemonControlMessage::ImageUploadProgress(
                sandbox_protocol::ImageUploadProgressV11 {
                    transfer_id: self.transfer_id.clone(),
                    bytes_sent: reached,
                },
            ));
        }
    }
}

/// A part body that reports the stored-object offset the transport has
/// taken from it.
struct CountingBody<'a, 'h> {
    bytes: &'a [u8],
    pos: usize,
    base: u64,
    heartbeat: Option<&'a UploadHeartbeat<'h>>,
}

impl std::io::Read for CountingBody<'_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let rest = self.bytes.get(self.pos..).unwrap_or_default();
        let n = rest.len().min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        self.pos += n;
        if let Some(heartbeat) = self.heartbeat
            && n > 0
        {
            heartbeat.reach(self.base.saturating_add(self.pos as u64));
        }
        Ok(n)
    }
}

/// On-disk bytes of a staging file or directory (one level of files).
fn dir_bytes(path: &Path) -> u64 {
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_dir() => std::fs::read_dir(path)
            .map(|entries| {
                entries
                    .flatten()
                    .filter_map(|e| e.metadata().ok())
                    .filter(|m| m.is_file())
                    .map(|m| m.len())
                    .sum()
            })
            .unwrap_or(0),
        Ok(meta) => meta.len(),
        Err(_) => 0,
    }
}

/// The `image.fetch.failed` code for an abandoned fetch grant.
fn fetch_failure_code(code: SandboxErrorCode) -> ImageFailureCode {
    match code {
        SandboxErrorCode::Cancelled => ImageFailureCode::Cancelled,
        SandboxErrorCode::ImageCorrupt => ImageFailureCode::Corrupt,
        SandboxErrorCode::ImageFetchTimeout => ImageFailureCode::Timeout,
        _ => ImageFailureCode::Io,
    }
}

fn read_exact_or_transport(
    reader: &mut impl std::io::Read,
    buffer: &mut [u8],
) -> Result<(), ImageError> {
    reader
        .read_exact(buffer)
        .map_err(|_| ImageError::new(SandboxErrorCode::Transport, "image download interrupted"))
}

/// Bytes of stored part `n` (1-based): plaintext, or whole sealed records.
fn read_stored_part(
    file: &mut std::fs::File,
    plain_size: u64,
    part_size: u64,
    n: u32,
    key: Option<&crypto::RecordKey>,
) -> std::io::Result<Vec<u8>> {
    let start = u64::from(n - 1) * part_size;
    match key {
        None => {
            let len = plain_size.saturating_sub(start).min(part_size) as usize;
            let mut bytes = vec![0u8; len];
            file.seek(std::io::SeekFrom::Start(start))?;
            file.read_exact(&mut bytes)?;
            Ok(bytes)
        }
        Some(key) => {
            let per_part = part_size / crypto::SEALED_RECORD as u64;
            let first = u64::from(n - 1) * per_part;
            let records = crypto::record_count(plain_size);
            let mut out = Vec::with_capacity(part_size as usize);
            for index in first..(first + per_part).min(records) {
                let offset = index * crypto::RECORD as u64;
                let len = plain_size.saturating_sub(offset).min(crypto::RECORD as u64) as usize;
                let mut plain = vec![0u8; len];
                file.seek(std::io::SeekFrom::Start(offset))?;
                file.read_exact(&mut plain)?;
                out.extend(
                    key.seal(index, index + 1 == records, &plain)
                        .map_err(|_| std::io::Error::other("seal failed"))?,
                );
            }
            Ok(out)
        }
    }
}

fn wait_for(
    rx: &mpsc::Receiver<ServerControlMessage>,
    timeout: Duration,
    still_wanted: &dyn Fn() -> bool,
) -> Option<ServerControlMessage> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(frame) => return Some(frame),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if !still_wanted() {
                    return None;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => return None,
        }
    }
    None
}

#[cfg(test)]
mod tests;
