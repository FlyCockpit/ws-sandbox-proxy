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
/// Frames one `take_batch` takes for a socket write.
const BATCH_MAX: usize = 32;
/// Admission bound of the protected backlog (r5 #3): a new upload job
/// starts only while the queued protected frames (`protected_frame`: resumes
/// and terminal upload frames, never evicted) plus two per live job (its
/// resume and its terminal frame, still to come) stay below this. So
/// protected frames stay below it, plus at most one failed batch's replay;
/// the assert keeps that within half the outbox, leaving the rest to begins,
/// census and inventory pages and other traffic.
const PROTECTED_MAX: usize = OUTBOX_MAX / 4;
const _: () = assert!(PROTECTED_MAX + BATCH_MAX <= OUTBOX_MAX / 2);
/// Reports kept until the server's `report.ack` (`PendingReport`), both
/// kinds together; the oldest goes beyond this (the server's stall and
/// expiry rules are the backstop). Each may bring its job's resume, and
/// admission reserves both (`admits`).
const REPORTS_MAX: usize = 32;
const _: () = assert!(2 * REPORTS_MAX + OFFLOAD_PROTECTED < PROTECTED_MAX);
/// A report is forgotten this long after it was made, acked or not.
const REPORT_MAX_AGE: Duration = Duration::from_secs(3600);
/// On a live connection a report sent this long ago and not acked yet is
/// sent again (its handler may have failed; the server acks only a handled
/// one).
const REPORT_RESEND_EVERY: Duration = Duration::from_secs(120);
/// Cancels kept at most (`Inner::cancelled`).
const CANCELLED_MAX: usize = 1024;
/// Acknowledged report transfers remembered (`Inner::acked_transfers`).
const ACKED_TRANSFERS_MAX: usize = 256;
/// Protected frames the disk offload slot may queue without admission
/// (post-landing #3): its job's one `image.job.resume` (deduplicated per
/// transfer), one `disk.offload.failed` and one `disk.offload.released`
/// (the server sends a host one export at a time, and holds its slot until
/// the release). Reserved in every admission.
const OFFLOAD_PROTECTED: usize = 3;
/// How long a new upload job waits for the protected backlog to drain
/// before it ends without starting (no frame: the server's own stall and
/// deadline rules end it).
const UPLOAD_ADMISSION_WAIT: Duration = Duration::from_secs(30 * 60);
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
/// The longest wait for an image-store part PUT's response after its body:
/// the last writes only fill the kernel send buffer, and draining it on a
/// slow uplink (45 KB/s) takes longer than `HTTP_HEADERS_TIMEOUT`. Each
/// attempt waits only as long as its body can still be draining
/// (`put_response_wait`, post-landing #5), so a store that took the body
/// and never answers costs about `HTTP_IDLE` per attempt on a fast link.
const PUT_RESPONSE_WAIT: Duration = Duration::from_secs(300);
/// Send buffer a part body may still sit in once written (Linux autotuned
/// `tcp_wmem` reaches 4 MiB; doubled for its accounting and any proxy hop).
const SEND_BUFFER_ASSUMED: u64 = 8 << 20;
/// The slow-uplink design rate (bytes/s) assumed while no rate was measured.
const SLOW_UPLINK_BYTES_PER_SEC: u64 = 45_000;

/// How long one part attempt waits for the store's response after its
/// body: the time the unsent rest (at most `SEND_BUFFER_ASSUMED` of the
/// body) needs at `rate` (the measured upload rate, else the slow-uplink
/// design rate), plus `idle` (`HTTP_IDLE`: the store then has that long to
/// answer), at most `PUT_RESPONSE_WAIT`.
pub(crate) fn put_response_wait(body: u64, rate: Option<u64>, idle: Duration) -> Duration {
    let rate = rate.unwrap_or(SLOW_UPLINK_BYTES_PER_SEC).max(1);
    let draining = Duration::from_secs_f64(body.min(SEND_BUFFER_ASSUMED) as f64 / rate as f64);
    idle.saturating_add(draining)
        .min(PUT_RESPONSE_WAIT.max(idle))
}
/// How long an upload waits for the server's next grant (or refusal).
const UPLOAD_GRANT_WAIT: Duration = Duration::from_secs(300);
/// At most one `image.upload.progress` heartbeat per upload this often, and
/// only while bytes moved.
const UPLOAD_HEARTBEAT_EVERY: Duration = Duration::from_secs(30);
/// Attempts of one image-store part before its failure ends the upload.
const PART_ATTEMPTS: u32 = 4;
/// Uploaded parts reported (`image.upload.parts`) at least this often.
const FLUSH_PARTS: usize = 16;
/// Begin refusals the host retries (`UploadTimings::begin_retry`): the
/// store or the host's grant budget is briefly unavailable, or GC is still
/// deleting an earlier copy of the image.
const BEGIN_RETRY_REASONS: [&str; 3] = ["rate_limited", "artifact_deleting", "store_unavailable"];

/// The upload retry and renew timings (tests shorten them).
#[derive(Debug, Clone, Copy)]
pub(crate) struct UploadTimings {
    /// Pause before part attempts 2, 3 and 4 (plus up to 25 % jitter).
    pub(crate) part_retry: [Duration; 3],
    /// Pause before each re-sent begin after a transient refusal; the
    /// refusal is reported once these are used up or `begin_budget` ran out.
    pub(crate) begin_retry: [Duration; 4],
    /// The retry allowance, starting at the first transient begin refusal
    /// (whatever the first wait had spent): one deadline that every later
    /// begin wait, resume and pause spends; a pause that does not fit in
    /// what is left ends the retries.
    pub(crate) begin_budget: Duration,
    /// How long each renew waits for its grant before it is sent again (the
    /// last repeats until the grant wait is over).
    pub(crate) renew_retry: [Duration; 4],
    /// A URL with less lifetime left than this is renewed before its part.
    pub(crate) url_margin: Duration,
    /// Uploaded parts are reported at least this often.
    pub(crate) flush_every: Duration,
    /// After a part body has drained, how long its response is awaited
    /// (`put_response_wait`).
    pub(crate) response_idle: Duration,
}

impl UploadTimings {
    const PRODUCTION: Self = Self {
        part_retry: [
            Duration::from_secs(2),
            Duration::from_secs(8),
            Duration::from_secs(30),
        ],
        begin_retry: [
            Duration::from_secs(5),
            Duration::from_secs(15),
            Duration::from_secs(30),
            Duration::from_secs(60),
        ],
        begin_budget: Duration::from_secs(180),
        renew_retry: [
            Duration::from_secs(5),
            Duration::from_secs(15),
            Duration::from_secs(30),
            Duration::from_secs(60),
        ],
        url_margin: Duration::from_secs(60),
        flush_every: Duration::from_secs(30),
        response_idle: HTTP_IDLE,
    };
}

/// `base` plus up to 25 % jitter, so hosts that failed together do not
/// retry in lockstep.
fn jittered(base: Duration) -> Duration {
    use ring::rand::SecureRandom;
    let mut byte = [0u8; 2];
    let fraction = match ring::rand::SystemRandom::new().fill(&mut byte) {
        Ok(()) => f64::from(u16::from_le_bytes(byte)) / f64::from(u16::MAX),
        Err(_) => 0.0,
    };
    base.mul_f64(1.0 + fraction / 4.0)
}

/// Connected time a renew waits for a usable grant in all (`no_grant`
/// after). With `PUT_RESPONSE_WAIT` and one heartbeat interval it stays
/// inside the server's 10 min stall window (I5: a moving upload is never
/// failed for silence the host imposed on itself).
const UPLOAD_RENEW_WAIT: Duration = Duration::from_secs(180);

/// The server's stall window (`upload_stalled` after no heartbeat advanced
/// for it; `packages/api/src/sandbox/image-store/captures.ts`).
const SERVER_STALL_WINDOW: Duration = Duration::from_secs(600);

/// The longest stretch a moving upload can go without a heartbeat, in
/// connected time: the last heartbeat interval of a body (30 s), its
/// response wait (300 s), then the longer of a retry pause (30 s + 25 %
/// jitter = 37.5 s) and a renew (180 s). 30 + 300 + 180 = 510 s < 600 s.
/// While a body is sent, `wireBytes` advances as the socket takes each
/// chunk of at most 16 KiB (`crate::tls::counting_transmits`, below ureq's
/// 128 KiB body buffer), so a slow drain of one buffered write is still
/// "moving" and heartbeats every 30 s, down to the liveness floor
/// (`UPLOAD_LIVENESS_FLOOR`); the idle bound fails a write that moves
/// nothing.
/// Every attempt re-sends its body, which advances `wireBytes` and so sends
/// a heartbeat: four attempts never add up, the stretch is per attempt. A
/// renew is one wait with one budget (W3): the resume a reconnect needs, its
/// pauses and re-sends all spend those 180 s; between parts a reconnect is
/// resumed only inside the renew that follows it, so no wait adds to it.
const fn longest_silence() -> Duration {
    let pause = Duration::from_millis(30_000 * 5 / 4);
    let after = if UPLOAD_RENEW_WAIT.as_millis() > pause.as_millis() {
        UPLOAD_RENEW_WAIT
    } else {
        pause
    };
    UPLOAD_HEARTBEAT_EVERY
        .saturating_add(PUT_RESPONSE_WAIT)
        .saturating_add(after)
}

const _: () = assert!(longest_silence().as_millis() < SERVER_STALL_WINDOW.as_millis());

/// The liveness floor of an upload body, in bytes per second (r4 #4).
/// Liveness is counted per socket chunk (`crate::tls::TRANSMIT_CHUNK`,
/// 16 KiB), once the whole chunk was taken, not per short socket write. So
/// a body counts as moving only while it sustains at least one chunk per
/// server stall window: 16 KiB per 10 min is about 27 B/s, about 29 B/s
/// when the 30 s heartbeat interval falls inside the window. Anything
/// slower is reported `upload_stalled` by the server; it could never finish
/// a part (16 MiB at 30 B/s is over six days, past the 24 h store
/// deadline) anyway. The assert ties the chunk size, the stall window and
/// the heartbeat interval to this documented floor: growing the chunk or
/// shrinking the window fails the build until the floor (and
/// docs/operations/templates.md, docs/guide/hosts.md) say so.
const UPLOAD_LIVENESS_FLOOR: u64 = 30;

const _: () = {
    let chunk = crate::tls::TRANSMIT_CHUNK as u64;
    let window = SERVER_STALL_WINDOW.as_secs() - UPLOAD_HEARTBEAT_EVERY.as_secs();
    assert!(chunk.div_ceil(window) <= UPLOAD_LIVENESS_FLOOR);
};

/// The pieces of one upload job its parts loop needs.
struct UploadJobRun<'a> {
    /// Its number in the resume registry.
    number: u64,
    fingerprint: &'a str,
    transfer: Option<&'a str>,
    capture: Option<&'a (String, u64)>,
    /// Stored bytes of the parts reported (shared with the registry).
    reported: Arc<AtomicU64>,
}

/// Sleep `wait`, waking early (false) once `stop` holds.
fn pause(wait: Duration, stop: &dyn Fn() -> bool) -> bool {
    let until = Instant::now() + wait;
    loop {
        if stop() {
            return false;
        }
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return true;
        }
        std::thread::sleep(left.min(Duration::from_millis(100)));
    }
}

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

/// Tests only: the virtual upload clock. It stands still at `base +
/// offset`: only upload pauses (recorded) and the test
/// (`advance_test_clock`) move it, so every upload deadline is
/// deterministic.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct TestClock {
    base: Instant,
    offset: Duration,
    pauses: Vec<Duration>,
    jitter: f64,
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
        sandbox_runtime::guard::probe::refuse_shared_incus_server(probe.as_ref()).map_err(|err| {
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
    /// Terminal reports kept until the server acknowledges them
    /// (`report.ack`), oldest first; see `PendingReport`. Lock order: the
    /// resume registry, then this, then the outbox.
    reports: Mutex<VecDeque<PendingReport>>,
    waiters: Mutex<HashMap<String, Waiter>>,
    inflight: Mutex<HashSet<String>>,
    inflight_cv: Condvar,
    in_use: Mutex<HashMap<String, usize>>,
    http: ureq::Agent,
    relay_base: String,
    host_secret: String,
    host_owner: Mutex<Option<String>>,
    census: Mutex<CensusState>,
    /// Transfers the server cancelled (`image.job.cancel`). A job removes
    /// its own when it ends; a cancel of a job that already ended here
    /// (its report kept, or acked recently: `acked_transfers`) is not
    /// recorded, so entries do not accumulate; cancels no job consumes
    /// (e.g. after a successful serve) are bounded by `CANCELLED_MAX`,
    /// oldest first. A cancel of a transfer a job runs (`running`) is never
    /// the one dropped (land round 1): those are bounded by admission. Lock
    /// order: this, then `running`.
    cancelled: Mutex<VecDeque<String>>,
    /// Transfers a job of this service runs now (serve, template upload once
    /// granted, disk offload upload), with how many jobs hold each.
    running: Mutex<HashMap<String, usize>>,
    /// Transfers whose terminal report the server acknowledged lately
    /// (bounded, oldest first): a delayed answer to a repeat of it (a stale
    /// cancel) is not recorded as a cancel.
    acked_transfers: Mutex<VecDeque<String>>,
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
    /// Tests only: shorter upload retry and renew timings.
    #[cfg(test)]
    timings_override: Mutex<Option<UploadTimings>>,
    /// Tests only: a virtual clock for upload pauses (recorded, not slept).
    #[cfg(test)]
    test_clock: Mutex<Option<TestClock>>,
    /// Tests only: an upload's export says it started on the sender, then
    /// waits for one message on the receiver.
    #[cfg(test)]
    export_gate: Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>,
    /// Registered relay connections (`hello.ok`) so far, the generation of
    /// the current one: an upload that sees it move resumes on the new one.
    connections: AtomicU64,
    /// Whether a relay connection is up (`hello.ok` .. its end): upload
    /// waits do not run down while it is not.
    connected: std::sync::atomic::AtomicBool,
    /// Every template upload job from its start until its terminal frame
    /// left the outbox (`ResumeEntry`), by job number: each gets an
    /// `image.job.resume` ahead of its frames on every new connection.
    resumable: Mutex<HashMap<u64, ResumeEntry>>,
    /// Peer serve jobs running (`serve`): each may still queue one
    /// protected `image.job.failed` (post-landing #3).
    serving: std::sync::atomic::AtomicUsize,
    /// The two latest measured part-body send rates (bytes/s), of bodies at
    /// least `SEND_BUFFER_ASSUMED` long; the slower one sizes response waits.
    upload_rates: Mutex<[Option<u64>; 2]>,
}

/// How a server frame reaches the job waiting for it.
enum Waiter {
    Plain(mpsc::Sender<ServerControlMessage>),
    /// Upload jobs: the frame with when and on which connection it arrived.
    Stamped(mpsc::Sender<Routed>),
}

/// A server frame as routed to an upload job: the instant it was routed
/// (a grant's URLs lapse `ttlSeconds` after it) and the relay connection
/// generation it arrived on (a resume answer counts only for the current
/// connection; a grant from an older one needs its transfer resumed).
#[derive(Debug)]
pub(crate) struct Routed {
    frame: ServerControlMessage,
    at: Instant,
    connection: u64,
}

impl Routed {
    /// The relay connection generation the frame arrived on.
    pub(crate) fn connection(&self) -> u64 {
        self.connection
    }

    pub(crate) fn into_frame(self) -> ServerControlMessage {
        self.frame
    }
}

/// What an upload job's frames name.
#[derive(Debug, Clone, PartialEq, Eq)]
enum JobRef {
    Transfer(String),
    /// A capture upload before its first grant.
    Operation(String, u64),
}

impl JobRef {
    fn resume(&self, bytes_done: u64) -> DaemonControlMessage {
        DaemonControlMessage::ImageJobResume(match self {
            Self::Transfer(transfer) => sandbox_protocol::ImageJobResumeV11::transfer(
                transfer,
                ImageLinkRole::Source,
                bytes_done.min(sandbox_protocol::IMAGE_SIZE_MAX),
            ),
            Self::Operation(operation, attempt) => {
                sandbox_protocol::ImageJobResumeV11::operation(operation, *attempt)
            }
        })
    }

    /// The job a resume, its answer or a terminal frame names.
    fn of(
        transfer: Option<&String>,
        operation: Option<&String>,
        attempt: Option<u64>,
    ) -> Option<Self> {
        match (transfer, operation, attempt) {
            (Some(transfer), None, None) => Some(Self::Transfer(transfer.clone())),
            (None, Some(operation), Some(attempt)) => {
                Some(Self::Operation(operation.clone(), attempt))
            }
            _ => None,
        }
    }

    /// The job a terminal upload frame (`image.job.failed`,
    /// `image.upload.complete`) ends.
    fn ended_by(message: &DaemonControlMessage) -> Option<Self> {
        match message {
            DaemonControlMessage::ImageJobFailed(f) => {
                Self::of(f.transfer_id.as_ref(), f.operation_id.as_ref(), f.attempt)
            }
            DaemonControlMessage::ImageUploadComplete(c) => {
                Some(Self::Transfer(c.transfer_id.clone()))
            }
            _ => None,
        }
    }

    /// A frame `push` never evicts: a resume, a terminal upload frame, or
    /// a disk offload's failure or release report (nothing else would end
    /// the server's attempt before its transfer expires, or free the host's
    /// export slot before its 10-minute backstop).
    fn protected_frame(message: &DaemonControlMessage) -> bool {
        Self::resumed_by(message).is_some()
            || Self::ended_by(message).is_some()
            || matches!(
                message,
                DaemonControlMessage::DiskOffloadFailed(_)
                    | DaemonControlMessage::DiskOffloadReleased(_)
            )
    }

    /// A queued frame of this job that only matters while the job is in
    /// the resume registry: its resume or its terminal frame.
    fn names(&self, message: &DaemonControlMessage) -> bool {
        Self::resumed_by(message).as_ref() == Some(self)
            || Self::ended_by(message).as_ref() == Some(self)
    }

    fn resumed_by(message: &DaemonControlMessage) -> Option<Self> {
        match message {
            DaemonControlMessage::ImageJobResume(r) => {
                Self::of(r.transfer_id.as_ref(), r.operation_id.as_ref(), r.attempt)
            }
            _ => None,
        }
    }

    /// The waiter key of this job's resume answers.
    fn resume_key(&self) -> String {
        match self {
            Self::Transfer(transfer) => format!("resume:{transfer}"),
            Self::Operation(operation, attempt) => format!("resume-op:{operation}#{attempt}"),
        }
    }
}

/// One upload job in the resume registry. Invariant (V1): from the job's
/// start until its terminal frame was drained to a connection, every new
/// relay connection carries this job's `image.job.resume` before any other
/// frame of the job, so nothing the job sends is refused as stale.
#[derive(Debug)]
struct ResumeEntry {
    reference: JobRef,
    /// Stored bytes of the parts reported (the resume's `bytesDone`).
    reported: Arc<AtomicU64>,
    /// The request id of a capture begin in flight.
    begin: Option<String>,
    /// That begin had already left the outbox when a new connection came:
    /// its answer may be lost with the old one, so it is sent again.
    begin_lost: bool,
    /// The job has ended and its terminal frame (a `PendingReport` of this
    /// job) is kept: the entry goes once the server acknowledges that report
    /// (`report.ack`), when it answers a resume of the job `continue: false`
    /// (the job is gone there), or with the report (age or count bound).
    terminal: bool,
}

/// A terminal report (`disk.offload.failed`, `disk.offload.released`,
/// `image.job.failed`, `image.upload.complete`) kept from its push until the
/// server acknowledges its `reportId` (`report.ack`: handled, or proven to
/// have nothing left to end). A frame written and flushed to a socket the
/// server then discards on close is so sent again: on every new connection
/// (behind its job's `image.job.resume`, which the resume registry queues
/// first) and on a live connection every `REPORT_RESEND_EVERY`. Bounded:
/// `REPORTS_MAX` (oldest goes) and `REPORT_MAX_AGE`.
#[derive(Debug, Clone)]
struct PendingReport {
    id: String,
    frame: DaemonControlMessage,
    /// The upload job (resume registry number) this report ends: re-sent
    /// behind that job's resume, and the job's entry goes with it.
    job: Option<u64>,
    created: Instant,
    /// When a socket last wrote and flushed it.
    last_sent: Option<Instant>,
}

/// Before one more frame is queued: at `OUTBOX_MAX`, evict one advisory
/// frame (operation progress, then an upload heartbeat), else the oldest
/// unprotected one. Every queueing path goes through it (`push`, and the
/// re-queues of resumes and kept reports), so the outbox stays bounded.
fn make_room(outbox: &mut VecDeque<DaemonControlMessage>) {
    if outbox.len() < OUTBOX_MAX {
        return;
    }
    let victim = outbox
        .iter()
        .position(|m| matches!(m, DaemonControlMessage::OperationProgress { .. }))
        .or_else(|| {
            outbox
                .iter()
                .position(|m| matches!(m, DaemonControlMessage::ImageUploadProgress(_)))
        })
        .or_else(|| outbox.iter().position(|m| !JobRef::protected_frame(m)));
    if let Some(index) = victim {
        outbox.remove(index);
    }
}

/// The report id a frame carries.
fn report_id(message: &DaemonControlMessage) -> Option<&str> {
    use DaemonControlMessage as M;
    match message {
        M::DiskOffloadFailed(r) => r.report_id.as_deref(),
        M::DiskOffloadReleased(r) => r.report_id.as_deref(),
        M::ImageJobFailed(r) => r.report_id.as_deref(),
        M::ImageUploadComplete(r) => r.report_id.as_deref(),
        _ => None,
    }
}

/// The report-id slot of a terminal report frame (`None`: not a report).
fn report_slot(message: &mut DaemonControlMessage) -> Option<&mut Option<String>> {
    use DaemonControlMessage as M;
    match message {
        M::DiskOffloadFailed(r) => Some(&mut r.report_id),
        M::DiskOffloadReleased(r) => Some(&mut r.report_id),
        M::ImageJobFailed(r) => Some(&mut r.report_id),
        M::ImageUploadComplete(r) => Some(&mut r.report_id),
        _ => None,
    }
}

/// The wire type of a report frame, for logs.
fn report_kind(message: &DaemonControlMessage) -> &'static str {
    use DaemonControlMessage as M;
    match message {
        M::DiskOffloadFailed(_) => "disk.offload.failed",
        M::DiskOffloadReleased(_) => "disk.offload.released",
        M::ImageJobFailed(_) => "image.job.failed",
        M::ImageUploadComplete(_) => "image.upload.complete",
        _ => "other",
    }
}

/// A fresh report id: 128 random bits, lowercase hex.
fn new_report_id() -> String {
    use ring::rand::SecureRandom;
    let mut bytes = [0u8; 16];
    if ring::rand::SystemRandom::new().fill(&mut bytes).is_err() {
        // No system randomness: unique within this process is enough (ids
        // only need to tell this daemon's reports apart).
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        bytes[..8].copy_from_slice(&nanos.to_be_bytes());
        bytes[8..].copy_from_slice(&n.to_be_bytes());
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// How an upload wait ended.
enum Waited {
    Frame(Box<Routed>),
    /// The relay connection changed: the caller resumes, then decides.
    Reconnected,
    Timeout,
}

/// Bound on one upload wait in wall time, relay outages included (the
/// waits themselves count connected time only). Past the server's 10 min
/// stall window: by then the server has ended a running upload itself.
const UPLOAD_OUTAGE_MAX: Duration = Duration::from_secs(30 * 60);

/// What one upload wait may still spend (W3): `left` connected time (a
/// relay outage does not count, FB-B4), never past the absolute `until`
/// (upload clock, at most `UPLOAD_OUTAGE_MAX` from its start), charged up
/// to `last`. Each wait (a begin with its retries, a renew) gets one from its
/// caller; a wait inside it (a resume) spends that same budget, clipped to
/// its own bound (`within` / `settle`), so no nested wait extends its
/// caller's deadline.
#[derive(Debug, Clone, Copy)]
struct Budget {
    left: Duration,
    until: Instant,
    last: Instant,
    /// Connected time charged since this budget was made (uncapped).
    spent: Duration,
}

impl Budget {
    fn new(now: Instant, left: Duration, until: Instant) -> Self {
        Self {
            left,
            until: until.min(now + UPLOAD_OUTAGE_MAX),
            last: now,
            spent: Duration::ZERO,
        }
    }

    /// Charge the time since `last` (connected time only).
    fn charge(&mut self, now: Instant, connected: bool) {
        if connected {
            let elapsed = now.saturating_duration_since(self.last);
            self.left = self.left.saturating_sub(elapsed);
            self.spent += elapsed;
        }
        self.last = self.last.max(now);
    }

    fn spent(&self, now: Instant) -> bool {
        self.left.is_zero() || now >= self.until
    }

    /// A wait inside this one with at most `own` connected time of its own.
    fn within(&self, own: Duration) -> Self {
        Self {
            left: self.left.min(own),
            spent: Duration::ZERO,
            ..*self
        }
    }

    /// Charge this budget with all the time `inner` (from `within`) was
    /// charged, also past its own bound.
    fn settle(&mut self, inner: &Self) {
        self.left = self.left.saturating_sub(inner.spent);
        self.spent += inner.spent;
        self.last = self.last.max(inner.last);
    }
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

/// Image frames taken from the outbox for one socket write
/// (`ImageService::take_batch`). Sent means written and flushed: `sent`
/// stamps the terminal reports it carries (kept until acknowledged);
/// dropped without
/// `sent` (a write or the flush failed), only the frames
/// `replayed_after_failed_write` allows go back to the front of the outbox,
/// in order; every other frame is dropped, as any frame of a failed write
/// was before.
pub struct ImageBatch {
    inner: Arc<Inner>,
    frames: Vec<DaemonControlMessage>,
    sent: bool,
}

impl ImageBatch {
    /// The frames to write, in order.
    pub fn frames(&self) -> &[DaemonControlMessage] {
        &self.frames
    }

    /// The socket wrote and flushed every frame. A terminal report stays
    /// kept (and its job in the resume registry) until the server's
    /// `report.ack`: the server may still discard it with the connection.
    pub fn sent(mut self) {
        self.sent = true;
        let ids: Vec<&str> = self.frames.iter().filter_map(report_id).collect();
        if !ids.is_empty() {
            let now = ImageService {
                inner: self.inner.clone(),
            }
            .now();
            for report in self
                .inner
                .reports
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter_mut()
                .filter(|r| ids.contains(&r.id.as_str()))
            {
                report.last_sent = Some(now);
            }
        }
    }
}

impl Drop for ImageBatch {
    fn drop(&mut self) {
        if self.sent {
            return;
        }
        let mut outbox = self.inner.outbox.lock().unwrap_or_else(|e| e.into_inner());
        for unsent in std::mem::take(&mut self.frames)
            .into_iter()
            .rev()
            .filter(replayed_after_failed_write)
        {
            // A report already queued again (`resend_reports`) goes once.
            if let Some(id) = report_id(&unsent)
                && outbox.iter().any(|m| report_id(m) == Some(id))
            {
                continue;
            }
            make_room(&mut outbox);
            outbox.push_front(unsent);
        }
    }
}

/// Whether a frame of a batch whose write or flush failed is sent again on
/// the next connection (after the jobs' resumes). A frame of such a batch
/// may or may not have reached the server, so only frames the server takes
/// idempotently, and that carry upload progress or a job's terminal cause,
/// are replayed. Exhaustive on purpose (no wildcard arm): a new variant
/// must decide here.
fn replayed_after_failed_write(message: &DaemonControlMessage) -> bool {
    use DaemonControlMessage as M;
    match message {
        // Template upload progress and terminal frames: repeated parts
        // reports and heartbeats are idempotent, a repeated terminal frame
        // ends only a still-open attempt; the job stays in the resume
        // registry until its terminal report is acknowledged (and the next
        // connection queues each kept report once).
        M::ImageJobFailed(_)
        | M::ImageUploadComplete(_)
        | M::ImageUploadParts(_)
        | M::ImageUploadProgress(_) => true,
        // The resume registry queues every live job's resume afresh on the
        // next `hello.ok`; a disk offload re-sends its own.
        M::ImageJobResume(_) => false,
        // A delivered begin already made its session (a replay would be
        // refused `stale_transfer` / supersede it, r4 #1); a lost capture
        // begin is re-sent once its job is resumed (`begin_lost`).
        M::ImageUploadBegin(_) => false,
        // A renew is re-sent by its wait; links and fetches by their jobs.
        M::ImageUploadRenew(_)
        | M::ImageLinksRequest(_)
        | M::ImageFetchRequest(_)
        | M::ImagePartAck(_) => false,
        // Census and disk inventory restart on every connection; a stale
        // page would be taken as another run's (r4 #2).
        M::ImageCacheCensus(_) | M::DiskOffloadInventory(_) => false,
        // Cache reports are re-derived by the next census.
        M::ImageCached(_) | M::ImageEvicted(_) | M::ImageFetchFailed(_) => false,
        // Disk offload reports the server takes idempotently (post-landing
        // #1): a completion (rebound to the new connection; a repeated one
        // is answered `stale`, which keeps the uploaded entry and asks the
        // verdict), a failure (ends only a still-uploadable attempt), a
        // release (recorded once) and an eviction report (a repeated one is
        // acked again).
        M::DiskUploadComplete(_)
        | M::DiskOffloadFailed(_)
        | M::DiskOffloadReleased(_)
        | M::DiskEvicted(_) => true,
        // The upload job re-begins or resumes itself on the next connection
        // (`disk.upload.resume` belongs to the connection it was sent on); a
        // lost eviction request stops blocking after `EVICT_ANSWER_WAIT` (or
        // the next connection); a discard is asked again by the server.
        M::DiskUploadBegin(_)
        | M::DiskUploadParts(_)
        | M::DiskUploadResume(_)
        | M::DiskEvictRequest(_)
        | M::DiskDiscarded(_) => false,
        // Advisory.
        M::OperationProgress { .. } => false,
        // Not image frames: never queued in the image outbox.
        M::AllocationAttestResult { .. }
        | M::AvailabilityResult { .. }
        | M::ChannelAck { .. }
        | M::ChannelEof { .. }
        | M::ChannelError { .. }
        | M::ChannelExit { .. }
        | M::ChannelReady { .. }
        | M::CredentialBundleRequest { .. }
        | M::CredentialCaptureBegin { .. }
        | M::CredentialCaptureChunk { .. }
        | M::CredentialCensus { .. }
        | M::CredentialInstalled { .. }
        | M::CredentialQuarantineDiscarded { .. }
        | M::CredentialReturnKeyAck { .. }
        | M::CredentialScrubbed { .. }
        | M::CredentialSpecRequest { .. }
        | M::DispatchAuditRequest { .. }
        | M::DispatchAuditResult { .. }
        | M::EgressRefused { .. }
        | M::FileChunkAck { .. }
        | M::Heartbeat { .. }
        | M::Hello { .. }
        | M::HostAdmission { .. }
        | M::HostAgentPolicy { .. }
        | M::HostEgressState { .. }
        | M::HostExecRejected { .. }
        | M::HostExecStarted { .. }
        | M::HostExecStatus { .. }
        | M::HostExecStdinResult { .. }
        | M::HostFileResult { .. }
        | M::HostLeasePolicy { .. }
        | M::HostPolicyLowerResult { .. }
        | M::HostQuiesce { .. }
        | M::HostTerminalPolicy { .. }
        | M::ImageVerifyResult { .. }
        | M::InventoryUpdate { .. }
        | M::JournalKeyAck { .. }
        | M::OperationAdopt { .. }
        | M::OperationReceipt { .. }
        | M::OperationReceiptPruned { .. }
        | M::OperationResult { .. }
        | M::PrivateConfigAck { .. }
        | M::PrivateConfigRefused { .. }
        | M::ProcessStarted { .. }
        | M::ReconcileComplete { .. }
        | M::SandboxExpiryStatus { .. }
        | M::SandboxInventory { .. }
        | M::SandboxProbeResult { .. }
        | M::TerminalAck { .. }
        | M::TerminalExit { .. }
        | M::TerminalReady { .. }
        | M::TunnelPortsStatus { .. }
        | M::TunnelStatus { .. } => false,
    }
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
                reports: Mutex::new(VecDeque::new()),
                waiters: Mutex::new(HashMap::new()),
                inflight: Mutex::new(HashSet::new()),
                inflight_cv: Condvar::new(),
                in_use: Mutex::new(HashMap::new()),
                http,
                relay_base,
                host_secret: host_secret.to_owned(),
                host_owner: Mutex::new(None),
                census: Mutex::new(CensusState::default()),
                cancelled: Mutex::new(VecDeque::new()),
                acked_transfers: Mutex::new(VecDeque::new()),
                running: Mutex::new(HashMap::new()),
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
                #[cfg(test)]
                timings_override: Mutex::new(None),
                #[cfg(test)]
                test_clock: Mutex::new(None),
                #[cfg(test)]
                export_gate: Mutex::new(None),
                connections: AtomicU64::new(0),
                connected: std::sync::atomic::AtomicBool::new(false),
                resumable: Mutex::new(HashMap::new()),
                serving: std::sync::atomic::AtomicUsize::new(0),
                upload_rates: Mutex::new([None, None]),
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

    /// Tests only: upload retry and renew timings.
    #[cfg(test)]
    pub(crate) fn set_upload_timings_for_test(&self, timings: UploadTimings) {
        *self
            .inner
            .timings_override
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(timings);
    }

    /// Tests only: uploads run on a virtual clock that stands still
    /// (`TestClock`): pauses are recorded, not slept, and move it; jitter is
    /// the fixed `jitter` fraction.
    #[cfg(test)]
    pub(crate) fn set_test_clock(&self, jitter: f64) {
        *self
            .inner
            .test_clock
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(TestClock {
            base: Instant::now(),
            offset: Duration::ZERO,
            pauses: Vec::new(),
            jitter,
        });
    }

    /// Tests only: move the virtual upload clock by `by`.
    #[cfg(test)]
    pub(crate) fn advance_test_clock(&self, by: Duration) {
        if let Some(clock) = self
            .inner
            .test_clock
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_mut()
        {
            clock.offset += by;
        }
    }

    /// Tests only: the next upload export says on the returned receiver
    /// that it started, then waits for one message on the returned sender
    /// (or its drop).
    #[cfg(test)]
    pub(crate) fn hold_exports_for_test(&self) -> (mpsc::Sender<()>, mpsc::Receiver<()>) {
        let (release, held) = mpsc::channel();
        let (entered, started) = mpsc::channel();
        *self
            .inner
            .export_gate
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some((entered, held));
        (release, started)
    }

    /// Tests only: the pauses recorded by the virtual clock.
    #[cfg(test)]
    pub(crate) fn test_pauses(&self) -> Vec<Duration> {
        self.inner
            .test_clock
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|c| c.pauses.clone())
            .unwrap_or_default()
    }

    /// The upload clock (virtual in tests that ask for it).
    fn now(&self) -> Instant {
        #[cfg(test)]
        if let Some(clock) = self
            .inner
            .test_clock
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            return clock.base + clock.offset;
        }
        Instant::now()
    }

    /// An upload pause of `wait` (see `pause`).
    fn pause(&self, wait: Duration, stop: &dyn Fn() -> bool) -> bool {
        #[cfg(test)]
        if let Some(clock) = self
            .inner
            .test_clock
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_mut()
        {
            clock.pauses.push(wait);
            clock.offset += wait;
            return !stop();
        }
        pause(wait, stop)
    }

    /// `base` with the upload jitter (see `jittered`).
    fn jittered(&self, base: Duration) -> Duration {
        #[cfg(test)]
        if let Some(clock) = self
            .inner
            .test_clock
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            return base.mul_f64(1.0 + clock.jitter / 4.0);
        }
        jittered(base)
    }

    /// The upload retry and renew timings.
    fn timings(&self) -> UploadTimings {
        #[cfg(test)]
        if let Some(timings) = *self
            .inner
            .timings_override
            .lock()
            .unwrap_or_else(|e| e.into_inner())
        {
            return timings;
        }
        UploadTimings::PRODUCTION
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
    fn heartbeat(&self, transfer: &str) -> UploadHeartbeat {
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
            transfer_id: transfer.to_owned(),
            state: std::rc::Rc::new(HeartbeatState {
                service: self.clone(),
                transfer_id: transfer.to_owned(),
                every,
                reached: std::cell::Cell::new(0),
                wire: std::cell::Cell::new(0),
                reported: std::cell::Cell::new((self.now(), 0, 0)),
            }),
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
    /// Every upload job in the resume registry gets its `image.job.resume`
    /// at the front of the outbox (an older queued resume of it replaced),
    /// so the new connection rebinds the job before any of its frames
    /// (queued or later) reach the server. A capture begin in flight that
    /// already left the outbox is marked lost (sent again once resumed).
    pub fn on_registered(&self, host_owner_id: &str) {
        *self
            .inner
            .host_owner
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(host_owner_id.to_owned());
        let mut resumable = self
            .inner
            .resumable
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        self.next_connection(&mut resumable);
    }

    /// A new relay connection, under the resume registry's lock (see
    /// `on_registered`).
    fn next_connection(&self, resumable: &mut HashMap<u64, ResumeEntry>) {
        self.inner.connections.fetch_add(1, Ordering::SeqCst);
        self.inner.connected.store(true, Ordering::SeqCst);
        let mut reports = self.inner.reports.lock().unwrap_or_else(|e| e.into_inner());
        let gone = self.prune_reports(&mut reports);
        let retired = Self::retire_unreported(resumable, &reports);
        let mut outbox = self.inner.outbox.lock().unwrap_or_else(|e| e.into_inner());
        // Frames of forgotten reports and retired jobs go unsent.
        outbox.retain(|m| !Self::forgotten(m, &gone, &retired));
        // Every kept report goes again on this connection (the old one may
        // have discarded it unhandled): its queued copies go first, then it
        // is queued once behind the resumes below, oldest first.
        outbox.retain(|m| report_id(m).is_none_or(|id| !reports.iter().any(|r| r.id == id)));
        for report in reports.iter() {
            make_room(&mut outbox);
            outbox.push_back(report.frame.clone());
        }
        drop(reports);
        // Disk upload parts reports queued for an older connection's
        // transfer (r5 #2) would reach this one unbound and be answered
        // `stale`: they go, and the offload's own resume / regrant decides.
        // A queued completion stays: the server rebinds its session's
        // transfer to this connection (post-landing #1).
        // So do queued disk upload begins and resumes: each belongs to the
        // connection it was queued for (its answer is read only from there),
        // and the offload begins or resumes again on this one.
        outbox.retain(|m| {
            !matches!(
                m,
                DaemonControlMessage::DiskUploadParts(_)
                    | DaemonControlMessage::DiskUploadBegin(_)
                    | DaemonControlMessage::DiskUploadResume(_)
            )
        });
        for entry in resumable.values_mut() {
            if let Some(request) = &entry.begin {
                entry.begin_lost = !outbox.iter().any(|m| {
                    matches!(m, DaemonControlMessage::ImageUploadBegin(b)
                        if b.request_id.as_deref() == Some(request.as_str()))
                });
            }
            outbox.retain(|m| JobRef::resumed_by(m).as_ref() != Some(&entry.reference));
            make_room(&mut outbox);
            outbox.push_front(
                entry
                    .reference
                    .resume(entry.reported.load(Ordering::SeqCst)),
            );
        }
    }

    /// Keep a new report (see `PendingReport`), within `REPORT_MAX_AGE` and
    /// `REPORTS_MAX` (the oldest go, with their queued copies; a job whose
    /// report went retires at the next connection or live re-send). Never
    /// takes the resume registry's lock (callers may hold it).
    fn keep_report(&self, report: PendingReport) {
        let mut reports = self.inner.reports.lock().unwrap_or_else(|e| e.into_inner());
        reports.push_back(report);
        let gone = self.prune_reports(&mut reports);
        drop(reports);
        if !gone.is_empty() {
            self.purge_queued(|m| report_id(m).is_some_and(|id| gone.iter().any(|g| g == id)));
        }
    }

    /// Drop reports past `REPORT_MAX_AGE` and the oldest beyond
    /// `REPORTS_MAX`; returns their ids.
    fn prune_reports(&self, reports: &mut VecDeque<PendingReport>) -> Vec<String> {
        let now = self.now();
        let mut gone = Vec::new();
        reports.retain(|r| {
            let keep = now.saturating_duration_since(r.created) < REPORT_MAX_AGE;
            if !keep {
                tracing::warn!(
                    kind = report_kind(&r.frame),
                    "terminal report never acknowledged within an hour; forgotten"
                );
                gone.push(r.id.clone());
            }
            keep
        });
        while reports.len() > REPORTS_MAX {
            if let Some(r) = reports.pop_front() {
                tracing::warn!(
                    kind = report_kind(&r.frame),
                    "too many unacknowledged terminal reports; the oldest is forgotten"
                );
                gone.push(r.id);
            }
        }
        gone
    }

    /// Ended jobs whose report is no longer kept leave the registry; their
    /// references (the caller purges their queued resumes and frames).
    fn retire_unreported(
        resumable: &mut HashMap<u64, ResumeEntry>,
        reports: &VecDeque<PendingReport>,
    ) -> Vec<JobRef> {
        let retired: Vec<u64> = resumable
            .iter()
            .filter(|(number, e)| e.terminal && !reports.iter().any(|r| r.job == Some(**number)))
            .map(|(number, _)| *number)
            .collect();
        retired
            .iter()
            .filter_map(|number| resumable.remove(number))
            .map(|e| e.reference)
            .collect()
    }

    /// Whether a queued frame belongs to a forgotten report or a retired
    /// job (`prune_reports`, `retire_unreported`): it goes unsent.
    fn forgotten(message: &DaemonControlMessage, gone: &[String], retired: &[JobRef]) -> bool {
        report_id(message).is_some_and(|id| gone.iter().any(|g| g == id))
            || retired.iter().any(|job| job.names(message))
    }

    /// `report.ack`: the server handled this report; it is no longer kept,
    /// its queued copies go, and its job (if any) leaves the registry with
    /// its queued resume. An unknown id changes nothing.
    fn acknowledge(&self, id: &str) {
        let mut resumable = self
            .inner
            .resumable
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut reports = self.inner.reports.lock().unwrap_or_else(|e| e.into_inner());
        let Some(index) = reports.iter().position(|r| r.id == id) else {
            return;
        };
        let report = reports.remove(index);
        drop(reports);
        if let Some(transfer) = report.as_ref().and_then(|r| match &r.frame {
            DaemonControlMessage::ImageUploadComplete(c) => Some(c.transfer_id.clone()),
            DaemonControlMessage::ImageJobFailed(f) => f.transfer_id.clone(),
            _ => None,
        }) {
            let mut acked = self
                .inner
                .acked_transfers
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            acked.push_back(transfer);
            while acked.len() > ACKED_TRANSFERS_MAX {
                acked.pop_front();
            }
        }
        let job = report
            .and_then(|r| r.job)
            .and_then(|number| resumable.remove(&number));
        self.purge_queued(|m| {
            report_id(m) == Some(id) || job.as_ref().is_some_and(|e| e.reference.names(m))
        });
    }

    /// On a live connection (the connect loop's image sweep): a kept report
    /// sent at least `REPORT_RESEND_EVERY` ago and not queued now is queued
    /// again, a job's behind its resume (a repeat is handled idempotently;
    /// the server acknowledges only a handled report). Also applies the
    /// age and count bounds.
    pub fn resend_reports(&self) {
        let mut resumable = self
            .inner
            .resumable
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut reports = self.inner.reports.lock().unwrap_or_else(|e| e.into_inner());
        let gone = self.prune_reports(&mut reports);
        let retired = Self::retire_unreported(&mut resumable, &reports);
        let now = self.now();
        let mut outbox = self.inner.outbox.lock().unwrap_or_else(|e| e.into_inner());
        outbox.retain(|m| !Self::forgotten(m, &gone, &retired));
        for report in reports.iter_mut() {
            let due = report
                .last_sent
                .is_some_and(|at| now.saturating_duration_since(at) >= REPORT_RESEND_EVERY);
            if !due
                || outbox
                    .iter()
                    .any(|m| report_id(m) == Some(report.id.as_str()))
            {
                continue;
            }
            if let Some(entry) = report.job.and_then(|n| resumable.get(&n)) {
                outbox.retain(|m| JobRef::resumed_by(m).as_ref() != Some(&entry.reference));
                make_room(&mut outbox);
                outbox.push_back(
                    entry
                        .reference
                        .resume(entry.reported.load(Ordering::SeqCst)),
                );
            }
            make_room(&mut outbox);
            outbox.push_back(report.frame.clone());
            // Due again only once this copy is flushed and ages.
            report.last_sent = None;
        }
    }

    /// Whether a kept report names `transfer` (its job has ended here).
    fn reported_transfer(&self, transfer: &str) -> bool {
        self.inner
            .reports
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|r| match &r.frame {
                DaemonControlMessage::ImageUploadComplete(c) => c.transfer_id == transfer,
                DaemonControlMessage::ImageJobFailed(f) => {
                    f.transfer_id.as_deref() == Some(transfer)
                }
                _ => false,
            })
    }

    /// Tests only: the ids of the kept reports, oldest first.
    #[cfg(test)]
    pub(crate) fn kept_reports(&self) -> Vec<String> {
        self.inner
            .reports
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|r| r.id.clone())
            .collect()
    }

    /// Tests only: the queued frames, left queued.
    #[cfg(test)]
    pub(crate) fn queued(&self) -> Vec<DaemonControlMessage> {
        self.inner
            .outbox
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .cloned()
            .collect()
    }

    /// Tests only: upload jobs in the resume registry.
    #[cfg(test)]
    pub(crate) fn resumable_jobs(&self) -> usize {
        self.inner
            .resumable
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// The relay connection ended: upload waits stop counting until the
    /// next `hello.ok`.
    pub fn on_disconnect(&self) {
        self.inner.connected.store(false, Ordering::SeqCst);
    }

    /// Queue `message`. The outbox is bounded (`OUTBOX_MAX`): advisory
    /// frames go first (operation progress, then upload heartbeats), then
    /// the oldest frame that is neither a resume nor a terminal upload frame
    /// (`image.job.failed`, `image.upload.complete`). Those are never
    /// evicted (V1: a job's cause and its rebind must reach the server);
    /// they leave when flushed or when their job is retired otherwise, and
    /// new upload jobs wait while they are backlogged (`PROTECTED_MAX`), so
    /// they hold less than half of `OUTBOX_MAX`.
    fn push(&self, mut message: DaemonControlMessage) {
        // A terminal report without an id is new: it is kept until acked.
        // (A job's report comes with its id from `finish_job`, re-sent ones
        // with theirs.)
        if let Some(slot) = report_slot(&mut message)
            && slot.is_none()
        {
            let id = new_report_id();
            *slot = Some(id.clone());
            self.keep_report(PendingReport {
                id,
                frame: message.clone(),
                job: None,
                created: self.now(),
                last_sent: None,
            });
        }
        let mut outbox = self.inner.outbox.lock().unwrap_or_else(|e| e.into_inner());
        make_room(&mut outbox);
        outbox.push_back(message);
    }

    /// Take the next queued frames (bounded per call) for one socket write
    /// (W1, a#1): the connect loop writes each, flushes the socket, then
    /// calls `ImageBatch::sent`. Only then does a frame count as sent (a
    /// terminal report stays kept until the server acknowledges it,
    /// `PendingReport`). Of a
    /// batch dropped unsent (a write or the flush failed), the upload
    /// progress and terminal frames (`replayed_after_failed_write`) go back
    /// to the front of the outbox in order (the next connection's resumes
    /// still go ahead of them); every other frame is dropped.
    pub fn take_batch(&self) -> ImageBatch {
        let frames = {
            let mut outbox = self.inner.outbox.lock().unwrap_or_else(|e| e.into_inner());
            let n = outbox.len().min(BATCH_MAX);
            outbox.drain(..n).collect()
        };
        ImageBatch {
            inner: self.inner.clone(),
            frames,
            sent: false,
        }
    }

    /// Tests only: the next queued frames, as a socket that writes and
    /// flushes them all would take them (`take_batch`).
    #[cfg(test)]
    pub(crate) fn drain(&self) -> Vec<DaemonControlMessage> {
        let batch = self.take_batch();
        let sent = batch.frames().to_vec();
        batch.sent();
        sent
    }

    /// After `reconcile.complete`: queue the bounded census pages; the first
    /// goes now, each later page on the previous page's ACK. A new connection
    /// always starts afresh (the old one's ACKs can never arrive).
    /// Every census page still queued (an older run's, or an older
    /// connection's, r5 #1) goes first: the server takes a page as the
    /// current run's, so only this run's pages may follow.
    pub fn begin_census(&self) {
        let pages = self.census_pages();
        let mut census = self.inner.census.lock().unwrap_or_else(|e| e.into_inner());
        self.purge_queued(|m| matches!(m, DaemonControlMessage::ImageCacheCensus(_)));
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
            .insert(key.to_owned(), Waiter::Plain(tx));
        rx
    }

    /// One receiver of stamped frames for every key in `keys`.
    fn register_stamped(&self, keys: &[String]) -> mpsc::Receiver<Routed> {
        let (tx, rx) = mpsc::channel();
        let mut waiters = self.inner.waiters.lock().unwrap_or_else(|e| e.into_inner());
        for key in keys {
            waiters.insert(key.clone(), Waiter::Stamped(tx.clone()));
        }
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
        match waiters.get(key) {
            Some(Waiter::Plain(tx)) => tx.send(frame).is_ok(),
            Some(Waiter::Stamped(tx)) => tx
                .send(Routed {
                    frame,
                    at: self.now(),
                    connection: self.inner.connections.load(Ordering::SeqCst),
                })
                .is_ok(),
            None => false,
        }
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
                // A cancel of a job that already ended here (e.g. a repeated
                // completion answered stale, even after its ack) is not
                // recorded: nothing runs to stop.
                let acked = self
                    .inner
                    .acked_transfers
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .contains(&c.transfer_id);
                if !acked && !self.reported_transfer(&c.transfer_id) {
                    let mut cancelled = self
                        .inner
                        .cancelled
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    if !cancelled.contains(&c.transfer_id) {
                        cancelled.push_back(c.transfer_id.clone());
                        // Over the cap the oldest cancel no running job
                        // holds goes (a running job's cancel stays until the
                        // job ends, however many others arrive meanwhile).
                        let running = self.inner.running.lock().unwrap_or_else(|e| e.into_inner());
                        while cancelled.len() > CANCELLED_MAX {
                            let Some(oldest) =
                                cancelled.iter().position(|t| !running.contains_key(t))
                            else {
                                break;
                            };
                            cancelled.remove(oldest);
                        }
                    }
                }
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
                let Some(job) =
                    JobRef::of(r.transfer_id.as_ref(), r.operation_id.as_ref(), r.attempt)
                else {
                    return;
                };
                // An ended job's kept report is not retired by a
                // `continue: false` answer: the server also refuses a resume
                // it could not fence right now (round 1 L1 #1), while the
                // upload is still open. Only the report's own `report.ack`
                // (handled, or nothing left to end) or its bounds retire it.
                self.deliver(&job.resume_key(), frame);
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
            ServerControlMessage::ReportAck(ack) => self.acknowledge(&ack.report_id),
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
            return Err(UploadFailure::status(status, false).at_part(link.part));
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
        #[cfg(test)]
        if let Some(gate) = self
            .inner
            .export_gate
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            let (entered, held) = gate;
            let _ = entered.send(());
            let _ = held.recv();
        }
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

    /// A job of `transfer` ended: its cancel goes.
    fn forget_cancel(&self, transfer: &str) {
        self.inner
            .cancelled
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|t| t != transfer);
    }

    /// A job runs `transfer` from now until the returned guard drops: its
    /// cancel is never the one the `CANCELLED_MAX` cap drops.
    pub(crate) fn run_transfer(&self, transfer: &str) -> RunningTransfer {
        *self
            .inner
            .running
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(transfer.to_owned())
            .or_insert(0) += 1;
        RunningTransfer(self.inner.clone(), transfer.to_owned())
    }

    fn cancelled(&self, transfer: &str) -> bool {
        self.inner
            .cancelled
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|t| t == transfer)
    }

    /// Peer source: upload relay parts as links arrive (the server only
    /// grants within the destination's ACK window).
    fn serve(&self, request: sandbox_protocol::ImageServeRequestV11) {
        let transfer = request.transfer_id.clone();
        // Admission (post-landing #3): a serve may queue one protected
        // failure report, so it reserves one. Over capacity it ends
        // unstarted with no frame (that frame would itself be unreserved):
        // the server's link window and transfer rules end the copy.
        struct Serving(Arc<Inner>, String);
        impl Drop for Serving {
            fn drop(&mut self) {
                self.0.serving.fetch_sub(1, Ordering::SeqCst);
                // Its cancel, if any, was for this serve, which has ended.
                self.0
                    .cancelled
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .retain(|t| *t != self.1);
            }
        }
        let _serving = {
            let resumable = self
                .inner
                .resumable
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if !self.admits(&resumable, 1) {
                tracing::warn!(transfer = %transfer, "image serve not started: the relay outbox stayed backlogged");
                return;
            }
            self.inner.serving.fetch_add(1, Ordering::SeqCst);
            Serving(self.inner.clone(), transfer.clone())
        };
        // Its cancel is kept while it runs (dropped before `_serving`, which
        // then removes that cancel).
        let _running = self.run_transfer(&transfer);
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
    /// server said another upload stores the image. The job is in the resume
    /// registry from its start until its terminal frame (that report, or
    /// `image.upload.complete`) left the outbox (V1).
    pub fn upload(&self, fingerprint: &str, owner: &str, job: UploadJob) {
        let (transfer, capture, reference) = match job {
            UploadJob::Publish(transfer) => {
                let reference = JobRef::Transfer(transfer.clone());
                (Some(transfer), None, reference)
            }
            UploadJob::Capture {
                operation_id,
                attempt,
            } => {
                let reference = JobRef::Operation(operation_id.clone(), attempt);
                (None, Some((operation_id, attempt)), reference)
            }
        };
        let _ = owner;
        self.mark_in_use(fingerprint, 1);
        let reported = Arc::new(AtomicU64::new(0));
        // Its resume answers have a waiter before the job is visible to a
        // reconnect (W4): an answer that comes while it exports is kept.
        let start_key = reference.resume_key();
        let start_rx = self.register_stamped(std::slice::from_ref(&start_key));
        let mut waiters = vec![start_key];
        // Registered under the lock `on_registered` takes: the job starts
        // bound to the connection counted here, and every later one queues
        // its resume. It waits while the protected backlog is full
        // (`admits_upload`); past `UPLOAD_ADMISSION_WAIT` it ends unstarted.
        let admission = Instant::now() + UPLOAD_ADMISSION_WAIT;
        let admitted = loop {
            let resumable = self
                .inner
                .resumable
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if self.admits_upload(&resumable) {
                break Some(resumable);
            }
            drop(resumable);
            if Instant::now() >= admission {
                break None;
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        let Some(mut resumable) = admitted else {
            tracing::warn!(
                fingerprint,
                "image upload not started: the relay outbox stayed backlogged"
            );
            for key in waiters {
                self.unregister(&key);
            }
            self.mark_in_use(fingerprint, -1);
            return;
        };
        let (number, connection) = {
            let number = self.inner.seq.fetch_add(1, Ordering::Relaxed);
            resumable.insert(
                number,
                ResumeEntry {
                    reference,
                    reported: reported.clone(),
                    begin: None,
                    begin_lost: false,
                    terminal: false,
                },
            );
            (number, self.inner.connections.load(Ordering::SeqCst))
        };
        drop(resumable);
        let mut transfer_id = transfer.clone();
        let outcome = self.upload_job(
            UploadJobRun {
                number,
                fingerprint,
                transfer: transfer.as_deref(),
                capture: capture.as_ref(),
                reported,
            },
            connection,
            start_rx,
            &mut transfer_id,
            &mut waiters,
        );
        for key in waiters {
            self.unregister(&key);
        }
        // The export directory went with its reservation (inside the job).
        self.mark_in_use(fingerprint, -1);
        let terminal = match outcome {
            Ok(()) => transfer_id.as_ref().map(|transfer| {
                DaemonControlMessage::ImageUploadComplete(ImageTransferRefV11 {
                    transfer_id: transfer.clone(),
                    report_id: None,
                })
            }),
            Err(UploadEnd::Failed(failure)) => {
                failure.log("image upload ended", transfer_id.as_deref());
                let capture = capture
                    .as_ref()
                    .map(|(op, attempt)| (op.as_str(), *attempt));
                failure
                    .frame(transfer_id.as_deref(), capture)
                    .map(DaemonControlMessage::ImageJobFailed)
            }
            Err(UploadEnd::Silent) => None,
        };
        self.finish_job(number, terminal);
        // Its cancel, if any, was for this job, which has ended.
        if let Some(transfer) = &transfer_id {
            self.forget_cancel(transfer);
        }
        #[cfg(test)]
        self.inner.uploads_finished.fetch_add(1, Ordering::SeqCst);
    }

    /// Queue a job's terminal frame, kept as a report of the job: the job
    /// stays in the resume registry until the server acknowledges it (every
    /// connection carries the job's resume first). Without one the job
    /// leaves now.
    fn finish_job(&self, number: u64, terminal: Option<DaemonControlMessage>) {
        let mut resumable = self
            .inner
            .resumable
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match terminal {
            Some(mut frame) => {
                let id = new_report_id();
                if let Some(slot) = report_slot(&mut frame) {
                    *slot = Some(id.clone());
                }
                let job = match resumable.get_mut(&number) {
                    Some(entry) => {
                        entry.terminal = true;
                        entry.begin = None;
                        Some(number)
                    }
                    None => None,
                };
                self.keep_report(PendingReport {
                    id,
                    frame: frame.clone(),
                    job,
                    created: self.now(),
                    last_sent: None,
                });
                self.push(frame);
            }
            None => {
                // Retired without a terminal frame: its queued resume goes.
                if let Some(entry) = resumable.remove(&number) {
                    self.purge_queued(|m| entry.reference.names(m));
                }
            }
        }
    }

    /// Drop every queued frame `unwanted` matches. Lock order: the resume
    /// registry (when held) before the outbox.
    pub(crate) fn purge_queued(&self, unwanted: impl Fn(&DaemonControlMessage) -> bool) {
        self.inner
            .outbox
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|m| !unwanted(m));
    }

    /// Whether a job that may queue `needs` more protected frames may start
    /// now (r5 #3, post-landing #3): the queued protected frames plus
    /// every reservation (two per live upload job, its resume and its
    /// terminal frame; one per running serve job; `OFFLOAD_PROTECTED` for
    /// the disk offload slot) plus `needs` stay within `PROTECTED_MAX`.
    /// Called under the resume registry's lock, which upload jobs then
    /// insert themselves under (serve jobs count themselves under it too).
    fn admits(&self, resumable: &HashMap<u64, ResumeEntry>, needs: usize) -> bool {
        let live = resumable.values().filter(|e| !e.terminal).count();
        let reports = self.inner.reports.lock().unwrap_or_else(|e| e.into_inner());
        let outbox = self.inner.outbox.lock().unwrap_or_else(|e| e.into_inner());
        let queued = outbox.iter().filter(|m| JobRef::protected_frame(m)).count();
        // Kept reports not queued now may come back (a reconnect, a live
        // re-send): one frame each, plus its job's resume.
        let kept: usize = reports
            .iter()
            .filter(|r| !outbox.iter().any(|m| report_id(m) == Some(r.id.as_str())))
            .map(|r| if r.job.is_some() { 2 } else { 1 })
            .sum();
        drop(outbox);
        drop(reports);
        queued
            + kept
            + 2 * live
            + self.inner.serving.load(Ordering::SeqCst)
            + OFFLOAD_PROTECTED
            + needs
            <= PROTECTED_MAX
    }

    fn admits_upload(&self, resumable: &HashMap<u64, ResumeEntry>) -> bool {
        self.admits(resumable, 2)
    }

    /// Record (or clear) the capture begin in flight of job `number`.
    fn set_begin(&self, number: u64, request: Option<String>) {
        if let Some(entry) = self
            .inner
            .resumable
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(&number)
        {
            entry.begin = request;
            entry.begin_lost = false;
        }
    }

    /// Whether job `number`'s begin in flight was lost with a connection.
    fn take_begin_lost(&self, number: u64) -> bool {
        self.inner
            .resumable
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(&number)
            .is_some_and(|entry| std::mem::take(&mut entry.begin_lost))
    }

    /// Wait on an upload job's receiver within `budget` (charged before
    /// every return). A connection generation other than `connection` ends
    /// the wait `Reconnected` (frames already routed come first); `stop`
    /// ends it `Timeout`.
    fn wait_upload(
        &self,
        rx: &mpsc::Receiver<Routed>,
        budget: &mut Budget,
        connection: u64,
        stop: &dyn Fn() -> bool,
    ) -> Waited {
        loop {
            let now = self.now();
            budget.charge(now, self.inner.connected.load(Ordering::SeqCst));
            match rx.try_recv() {
                Ok(routed) => return Waited::Frame(Box::new(routed)),
                Err(mpsc::TryRecvError::Disconnected) => return Waited::Timeout,
                Err(mpsc::TryRecvError::Empty) => {}
            }
            if self.inner.connections.load(Ordering::SeqCst) != connection {
                return Waited::Reconnected;
            }
            if budget.spent(now) || stop() {
                return Waited::Timeout;
            }
            let slice = budget
                .left
                .min(budget.until.saturating_duration_since(now))
                .min(Duration::from_millis(100));
            match rx.recv_timeout(slice) {
                Ok(routed) => {
                    budget.charge(self.now(), self.inner.connected.load(Ordering::SeqCst));
                    return Waited::Frame(Box::new(routed));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => return Waited::Timeout,
            }
        }
    }

    /// When the relay connection is no longer `connection`: wait for the
    /// answer to this job's resume on the current connection
    /// (`on_registered` queued it ahead of the job's frames). Answers to an
    /// older connection are ignored, and a newer reconnect waits for the
    /// newer answer (FB-B3). The wait spends the caller's `budget` (clipped
    /// to the grant wait; one deadline across every reconnect) and, when it
    /// runs out, ends with the caller's `timeout`. True when the job was
    /// resumed (bound to the current connection now); `continue: false`
    /// ends it `refused` with `refusal`, a cancel with its reason.
    fn await_resume(
        &self,
        rx: &mpsc::Receiver<Routed>,
        connection: &mut u64,
        refusal: &str,
        budget: &mut Budget,
        timeout: &dyn Fn() -> UploadEnd,
        stop: &dyn Fn() -> bool,
    ) -> Result<bool, UploadEnd> {
        let mut own = budget.within(self.grant_wait());
        let mut resumed = false;
        let outcome = loop {
            let now = self.inner.connections.load(Ordering::SeqCst);
            if now == *connection {
                break Ok(resumed);
            }
            match self.wait_upload(rx, &mut own, now, stop) {
                Waited::Reconnected => {}
                Waited::Frame(routed) => match routed.frame {
                    ServerControlMessage::ImageJobResumeResult(_) if routed.connection != now => {}
                    ServerControlMessage::ImageJobResumeResult(answer) if answer.proceed => {
                        *connection = now;
                        resumed = true;
                    }
                    ServerControlMessage::ImageJobResumeResult(_) => {
                        break Err(UploadFailure::refused(refusal).into());
                    }
                    ServerControlMessage::ImageJobCancel(cancel) => {
                        break Err(UploadEnd::cancelled(&cancel.reason));
                    }
                    _ => {}
                },
                Waited::Timeout => break Err(timeout()),
            }
        };
        budget.settle(&own);
        outcome
    }

    /// `image.upload.begin` until the server grants it. A capture's begin is
    /// re-sent after a transient refusal (`BEGIN_RETRY_REASONS`,
    /// `UploadTimings::begin_retry`); a publish begin never is (W5: its
    /// transfer ends with the refusal and server backfill retries it). The
    /// whole begin is one wait (`Budget`): the grant wait of connected time
    /// until the first transient refusal, then a fresh `begin_budget` from
    /// that refusal, which every later wait, resume and pause spends; when
    /// it runs out the capture
    /// is reported `refused` with the last reason. A capture waits under a
    /// fresh request id per begin until the grant that echoes it names the
    /// transfer (round-3 P2-4). A relay reconnect first resumes the job (its
    /// operation, or a publish's transfer); a capture begin that had already
    /// left the outbox is sent again. Returns the first grant as routed.
    fn begin_upload(
        &self,
        job: &UploadJobRun<'_>,
        size: u64,
        waiters: &mut Vec<String>,
        connection: &mut u64,
        resume_rx: &mpsc::Receiver<Routed>,
    ) -> Result<Routed, UploadEnd> {
        let never = || false;
        let timings = self.timings();
        let mut steps = timings.begin_retry.into_iter();
        // From the first transient refusal: the last reason.
        let mut retrying: Option<String> = None;
        let refusal = if job.capture.is_some() {
            "stale_capture"
        } else {
            "stale_transfer"
        };
        let refused_now = |retrying: &Option<String>| -> UploadEnd {
            match retrying {
                Some(reason) => UploadFailure::refused(reason).into(),
                None => {
                    UploadFailure::new(ImageFailureCode::Timeout, ImageFailureCause::NoGrant).into()
                }
            }
        };
        let start = self.now();
        let mut budget = Budget::new(start, self.grant_wait(), start + UPLOAD_OUTAGE_MAX);
        'begin: loop {
            self.await_resume(
                resume_rx,
                connection,
                refusal,
                &mut budget,
                &|| refused_now(&retrying),
                &never,
            )?;
            let request_id = job.capture.map(|_| self.next_id("upload"));
            let keys = match (job.transfer, &request_id) {
                (Some(t), _) => vec![format!("upload:{t}")],
                (None, Some(request)) => vec![format!("upload-req:{request}")],
                (None, None) => return Err(UploadEnd::Silent),
            };
            let rx = self.register_stamped(&keys);
            waiters.extend(keys.iter().cloned());
            self.set_begin(job.number, request_id.clone());
            self.push(DaemonControlMessage::ImageUploadBegin(
                ImageUploadBeginV11 {
                    transfer_id: job.transfer.map(str::to_owned),
                    operation_id: job.capture.map(|(op, _)| op.clone()),
                    request_id: request_id.clone(),
                    attempt: job.capture.map(|(_, attempt)| *attempt),
                    fingerprint: job.fingerprint.to_owned(),
                    size_bytes: size,
                    unpacked_bytes: None,
                    format: "unified".into(),
                },
            ));
            loop {
                match self.wait_upload(&rx, &mut budget, *connection, &never) {
                    Waited::Frame(routed) => match *routed {
                        Routed {
                            frame: ServerControlMessage::ImageUploadGrant(grant),
                            at,
                            connection: on,
                        } => {
                            if job.transfer.is_none() && grant.request_id != request_id {
                                return Err(UploadFailure::new(
                                    ImageFailureCode::Rejected,
                                    ImageFailureCause::Protocol,
                                )
                                .into());
                            }
                            self.set_begin(job.number, None);
                            return Ok(Routed {
                                frame: ServerControlMessage::ImageUploadGrant(grant),
                                at,
                                connection: on,
                            });
                        }
                        Routed {
                            frame: ServerControlMessage::ImageJobCancel(cancel),
                            ..
                        } => {
                            self.set_begin(job.number, None);
                            if job.capture.is_none()
                                || !BEGIN_RETRY_REASONS.contains(&cancel.reason.as_str())
                            {
                                return Err(UploadEnd::cancelled(&cancel.reason));
                            }
                            // The retry allowance starts at the first
                            // transient refusal (b#3): `begin_budget` from
                            // now, whatever the first wait spent; later waits,
                            // resumes and pauses all spend it.
                            if retrying.is_none() {
                                let now = self.now();
                                budget = Budget::new(
                                    now,
                                    timings.begin_budget,
                                    now + timings.begin_budget,
                                );
                            }
                            retrying = Some(cancel.reason.clone());
                            // A pause that does not fit in what is left of the
                            // budget ends the retries now.
                            let left = budget.until.saturating_duration_since(self.now());
                            let Some(wait) = steps
                                .next()
                                .map(|step| self.jittered(step))
                                .filter(|w| *w <= left)
                            else {
                                return Err(refused_now(&retrying));
                            };
                            tracing::info!(
                                refusal = cancel.reason.as_str(),
                                "image upload begin refused for now; retrying"
                            );
                            for key in &keys {
                                self.unregister(key);
                            }
                            self.pause(wait, &never);
                            continue 'begin;
                        }
                        _ => {}
                    },
                    Waited::Reconnected => {
                        self.await_resume(
                            resume_rx,
                            connection,
                            refusal,
                            &mut budget,
                            &|| refused_now(&retrying),
                            &never,
                        )?;
                        if job.capture.is_some() && self.take_begin_lost(job.number) {
                            // Its answer went with the old connection.
                            for key in &keys {
                                self.unregister(key);
                            }
                            continue 'begin;
                        }
                    }
                    Waited::Timeout => return Err(refused_now(&retrying)),
                }
            }
        }
    }

    /// One upload: export, begin, then every part in order. Part URLs are
    /// pulled (`image.upload.renew`) when the granted window is used up or
    /// the next URL is about to expire; uploaded parts are reported every
    /// `FLUSH_PARTS`, every `flush_every` and before each renew. A relay
    /// reconnect resumes the job on the new connection first. `transfer_id`
    /// holds the transfer once known; `waiters` collects the keys to drop.
    /// The terminal frame is the caller's (`finish_job`).
    fn upload_job(
        &self,
        job: UploadJobRun<'_>,
        mut connection: u64,
        start_rx: mpsc::Receiver<Routed>,
        transfer_id: &mut Option<String>,
        waiters: &mut Vec<String>,
    ) -> Result<(), UploadEnd> {
        let (path, size, _reservation) = self
            .export_unified(job.fingerprint)
            .map_err(|code| UploadFailure::new(code, ImageFailureCause::Export))?;
        let protocol =
            || UploadFailure::new(ImageFailureCode::Rejected, ImageFailureCause::Protocol);
        let mut file = std::fs::File::open(&path).map_err(|e| UploadFailure::local_io(e.kind()))?;
        let routed = self.begin_upload(&job, size, waiters, &mut connection, &start_rx)?;
        let Routed {
            frame: ServerControlMessage::ImageUploadGrant(mut grant),
            at: granted_at,
            connection: granted_on,
        } = routed
        else {
            return Err(protocol().into());
        };
        let tid = grant.transfer_id.clone();
        if job.transfer.is_some_and(|t| t != tid) {
            return Err(protocol().into());
        }
        *transfer_id = Some(tid.clone());
        // Its cancel is kept while this job runs (`run_transfer`).
        let _running = self.run_transfer(&tid);
        // Grants, refusals and cancels of the transfer (a capture re-keys
        // its waiter from the begin's request id); resume answers.
        let key = format!("upload:{tid}");
        let rx = self.register_stamped(std::slice::from_ref(&key));
        waiters.push(key);
        let resume_rx = if job.capture.is_some() {
            let resume_key = format!("resume:{tid}");
            let rx = self.register_stamped(std::slice::from_ref(&resume_key));
            waiters.push(resume_key);
            rx
        } else {
            start_rx
        };
        let mut record_key: Option<crypto::RecordKey> = None;
        if let Some(e) = grant.encryption.as_mut() {
            // The data key leaves the frame at once (wiped on drop).
            let text = crypto::take_grant_key(e);
            record_key = Some(crypto::RecordKey::from_base64(&text).map_err(|_| protocol())?);
        }
        let stored_size = if record_key.is_some() {
            sandbox_protocol::encrypted_image_len(size)
        } else {
            size
        };
        let part_size = grant.part_size;
        let total = u32::try_from(stored_size.div_ceil(part_size.max(1)).max(1))
            .ok()
            .filter(|n| *n <= 10_000)
            .ok_or_else(protocol)?;
        // The job now names its transfer. The grant's transfer is bound to
        // the connection the grant came on: when a reconnect came since
        // (life#3), its resume is queued now, under the lock
        // `on_registered` takes, and the run waits for the answer.
        {
            let mut resumable = self
                .inner
                .resumable
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let reference = JobRef::Transfer(tid.clone());
            if let Some(entry) = resumable.get_mut(&job.number) {
                entry.reference = reference.clone();
                entry.begin = None;
            }
            if granted_on != self.inner.connections.load(Ordering::SeqCst) {
                let mut outbox = self.inner.outbox.lock().unwrap_or_else(|e| e.into_inner());
                outbox.retain(|m| JobRef::resumed_by(m).as_ref() != Some(&reference));
                make_room(&mut outbox);
                outbox.push_front(reference.resume(0));
            }
        }
        let heartbeat = self.heartbeat(&tid);
        let mut run = UploadRun {
            service: self,
            tid: tid.clone(),
            rx,
            resume_rx,
            timings: self.timings(),
            part_size,
            stored_size,
            window: std::collections::BTreeMap::new(),
            expiry: self.now(),
            margin: Duration::ZERO,
            done: std::collections::BTreeMap::new(),
            pending: Vec::new(),
            reported_parts: HashSet::new(),
            counted: HashSet::new(),
            reported: job.reported.clone(),
            last_flush: Instant::now(),
            connection: granted_on,
        };
        run.take_grant(grant, granted_at)?;
        let stop = || self.cancelled(&tid);
        let mut next = 1u32;
        loop {
            if self.cancelled(&tid) {
                return Err(run.cancel_end());
            }
            while run.done.contains_key(&next) {
                next += 1;
            }
            if next > total {
                run.flush();
                return Ok(());
            }
            // A reconnect is resumed inside the renew it needs anyway (the
            // window is dropped on resume): one wait, one deadline (W3).
            let url = if run.reconnected() {
                None
            } else {
                run.url(next)
            };
            let Some((url, expiry)) = url else {
                run.renew(next)?;
                continue;
            };
            let etag = self
                .put_part_retrying(
                    &mut file,
                    size,
                    part_size,
                    &url,
                    Some(expiry),
                    record_key.as_ref(),
                    None,
                    &stop,
                    Some(&heartbeat),
                    &mut |n| {
                        run.renew(n)?;
                        Ok(run.url(n))
                    },
                )
                .map_err(|end| match end {
                    // The server cancelled the transfer: its reason is
                    // waiting on this transfer's receiver.
                    UploadEnd::Failed(f) if f.code == ImageFailureCode::Cancelled => {
                        run.cancel_end()
                    }
                    end => end,
                })?;
            run.window.remove(&next);
            run.done.insert(next, etag.clone());
            run.pending.push(ImageUploadedPartV11 { n: next, etag });
            if run.pending.len() >= FLUSH_PARTS
                || run.last_flush.elapsed() >= run.timings.flush_every
            {
                run.flush();
            }
        }
    }

    /// The image-store part loop shared by template uploads and disk
    /// offloads: read each granted part (whole sealed
    /// records when keyed), pace it through `limit`, PUT it to its presigned
    /// URL (retried, `put_part_retrying`; a 403 is final here, there is no
    /// renew) and collect its ETag. `stop` is checked before every part
    /// (kill and reconnect preempt a disk upload); a stop ends with code
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
        heartbeat: Option<&UploadHeartbeat>,
    ) -> Result<(Vec<ImageUploadedPartV11>, u64), UploadFailure> {
        let mut reported = Vec::new();
        let mut sent = 0u64;
        for part in parts {
            if stop() {
                return Err(UploadFailure::refused("cancelled"));
            }
            let etag = self
                .put_part_retrying(
                    file,
                    size,
                    part_size,
                    part,
                    None,
                    key,
                    limit,
                    stop,
                    heartbeat,
                    &mut |_| Ok(None),
                )
                .map_err(|end| match end {
                    UploadEnd::Failed(failure) => failure,
                    UploadEnd::Silent => UploadFailure::refused("cancelled"),
                })?;
            sent += part.size_bytes;
            reported.push(ImageUploadedPartV11 { n: part.n, etag });
        }
        Ok((reported, sent))
    }

    /// PUT one part, retried inside the upload: up to `PART_ATTEMPTS`
    /// attempts for a transient failure (`UploadFailure::retryable`), paced
    /// by `UploadTimings::part_retry` with jitter; a 403 gets one fresh URL
    /// from `renew` (`None`: no renew, the 403 is final) and one more try.
    /// Every retry is one sanitized warn line; the final failure another.
    /// `expiry` is when `part`'s URL lapses on this host's clock (a 403
    /// after it is `url_expired`). Its ETag.
    #[allow(clippy::too_many_arguments)]
    fn put_part_retrying(
        &self,
        file: &mut std::fs::File,
        size: u64,
        part_size: u64,
        part: &sandbox_protocol::ImageUploadPartUrlV11,
        expiry: Option<Instant>,
        key: Option<&crypto::RecordKey>,
        limit: Option<&super::offload::Bandwidth>,
        stop: &dyn Fn() -> bool,
        heartbeat: Option<&UploadHeartbeat>,
        renew: &mut dyn FnMut(
            u32,
        ) -> Result<
            Option<(sandbox_protocol::ImageUploadPartUrlV11, Instant)>,
            UploadEnd,
        >,
    ) -> Result<String, UploadEnd> {
        let transfer = heartbeat.map(|h| h.transfer_id.as_str());
        let delays = self.timings().part_retry;
        let mut url = part.clone();
        let mut expiry = expiry;
        let mut renewed = false;
        let mut attempt = 1u32;
        loop {
            let failure =
                match self.put_part(file, size, part_size, &url, key, limit, stop, heartbeat) {
                    Ok(etag) => return Ok(etag),
                    Err(failure) => failure.at_part(part.n).at_attempt(attempt),
                };
            if failure.code == ImageFailureCode::Cancelled {
                return Err(failure.into());
            }
            if failure.http_status == Some(403) && !renewed && attempt < PART_ATTEMPTS {
                renewed = true;
                if let Some((fresh, lapses)) = renew(part.n)? {
                    failure.log("image store part upload retrying", transfer);
                    url = fresh;
                    expiry = Some(lapses);
                    attempt += 1;
                    continue;
                }
            }
            let failure = match failure.http_status {
                Some(403) => UploadFailure {
                    part: failure.part,
                    attempt: failure.attempt,
                    ..UploadFailure::status(403, expiry.is_some_and(|at| self.now() >= at))
                },
                _ => failure,
            };
            if failure.retryable() && attempt < PART_ATTEMPTS {
                failure.log("image store part upload retrying", transfer);
                let wait = delays[(attempt - 1) as usize];
                if !self.pause(self.jittered(wait), stop) {
                    return Err(UploadFailure::refused("cancelled").into());
                }
                attempt += 1;
                continue;
            }
            failure.log("image store part upload failed", transfer);
            return Err(failure.into());
        }
    }

    /// The slower of the two latest measured upload rates.
    fn upload_rate(&self) -> Option<u64> {
        let rates = *self
            .inner
            .upload_rates
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        rates.into_iter().flatten().min()
    }

    fn note_upload_rate(&self, rate: u64) {
        let mut rates = self
            .inner
            .upload_rates
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *rates = [Some(rate.max(1)), rates[0]];
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
        heartbeat: Option<&UploadHeartbeat>,
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
            done_at: None,
            stop,
        };
        let wait = put_response_wait(
            body.len() as u64,
            self.upload_rate(),
            self.timings().response_idle,
        );
        let started = Instant::now();
        let mut send = || {
            self.inner
                .http
                .put(&part.url)
                .header("Content-Type", "application/octet-stream")
                .header("Content-Length", body.len().to_string())
                .config()
                .timeout_recv_response(Some(wait))
                .build()
                .send(ureq::SendBody::from_reader(&mut reader))
        };
        let sent = match heartbeat {
            Some(heartbeat) => heartbeat.sending(send),
            None => send(),
        };
        // The body was read to its end (all but its last buffer is in the
        // kernel): a long one measures the uplink, answered or not.
        if let Some(done) = reader.done_at
            && body.len() as u64 >= SEND_BUFFER_ASSUMED
        {
            let secs = done.saturating_duration_since(started).as_secs_f64();
            if secs > 0.0 {
                self.note_upload_rate((body.len() as f64 / secs) as u64);
            }
        }
        // A cancel while the body was still going out ends the PUT at the
        // next buffer (the reader refuses it), not when the part is done.
        if sent.is_err() && stop() {
            return Err(UploadFailure::refused("cancelled"));
        }
        let response = sent.map_err(|e| UploadFailure::transport(&e))?;
        let status = response.status().as_u16();
        if status != 200 {
            return Err(UploadFailure::status(status, false));
        }
        response
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .ok_or_else(|| UploadFailure::new(ImageFailureCode::Io, ImageFailureCause::Protocol))
    }

    /// The heartbeat of a disk offload upload of `transfer` (see
    /// `put_parts`).
    pub(crate) fn upload_heartbeat(&self, transfer: &str) -> UploadHeartbeat {
        self.heartbeat(transfer)
    }

    /// Queue a frame for the server (disk offload frames share the image
    /// outbox: both are sent only after reconciliation).
    pub(crate) fn push_frame(&self, message: DaemonControlMessage) {
        self.push(message);
    }

    /// Route frames keyed `key` to the returned receiver, each stamped with
    /// the relay connection it arrived on (see `deliver`).
    pub(crate) fn register_stamped_waiter(&self, key: &str) -> mpsc::Receiver<Routed> {
        self.register_stamped(&[key.to_owned()])
    }

    /// The current relay connection's generation (`hello.ok` count).
    pub(crate) fn connection(&self) -> u64 {
        self.inner.connections.load(Ordering::SeqCst)
    }

    /// Whether a relay connection is up (`hello.ok` .. its end).
    pub(crate) fn is_connected(&self) -> bool {
        self.inner.connected.load(Ordering::SeqCst)
    }

    /// Queue `message` for relay connection `connection` only: false (not
    /// queued) once another connection registered. Checked under the resume
    /// registry's lock, which `next_connection` holds while it moves to a new
    /// connection and purges the frames that belonged to the old one, so a
    /// frame queued here is either purged with its connection or sent on it.
    pub(crate) fn push_on(&self, connection: u64, message: DaemonControlMessage) -> bool {
        let _registry = self
            .inner
            .resumable
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if self.inner.connections.load(Ordering::SeqCst) != connection {
            return false;
        }
        self.push(message);
        true
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

/// Liveness of one upload (I5): the byte offset reached in the stored
/// object (logical progress, monotonic within the transfer: a part sent
/// again never moves it back; counted as the request body is read) and
/// every byte the socket took for its requests, retries included (physical
/// activity, `wireBytes`; counted below ureq's body buffer, as each chunk
/// leaves for the socket, `sending`). Both are sent as
/// `image.upload.progress` at most every `every` (upload clock) and only
/// when either advanced.
pub(crate) struct UploadHeartbeat {
    transfer_id: String,
    state: std::rc::Rc<HeartbeatState>,
}

/// The counters of one `UploadHeartbeat`, shared with its transport hook.
struct HeartbeatState {
    service: ImageService,
    transfer_id: String,
    every: Duration,
    reached: std::cell::Cell<u64>,
    wire: std::cell::Cell<u64>,
    /// When the last heartbeat went, and the offset and wire count it carried.
    reported: std::cell::Cell<(Instant, u64, u64)>,
}

impl UploadHeartbeat {
    /// The transfer this heartbeat reports.
    pub(crate) fn transfer_id(&self) -> &str {
        &self.transfer_id
    }

    /// Body bytes that went on the wire so far (any part, any window).
    pub(crate) fn wire_bytes(&self) -> u64 {
        self.state.wire.get()
    }

    /// The body reached stored `offset`, after `moved` more bytes went out.
    fn reach(&self, offset: u64, moved: u64) {
        self.state.reach(offset, moved);
    }

    /// Run `send` (one part's request on this thread) with every chunk of
    /// bytes the socket takes counted as wire progress (b#1: a slow drain of
    /// a buffered write keeps heartbeats flowing).
    fn sending<R>(&self, send: impl FnOnce() -> R) -> R {
        let state = self.state.clone();
        crate::tls::counting_transmits(std::rc::Rc::new(move |n| state.reach(0, n)), send)
    }
}

impl HeartbeatState {
    fn reach(&self, offset: u64, moved: u64) {
        let reached = self.reached.get().max(offset);
        self.reached.set(reached);
        let wire = self
            .wire
            .get()
            .saturating_add(moved)
            .min(sandbox_protocol::IMAGE_WIRE_BYTES_MAX);
        self.wire.set(wire);
        let (at, last, last_wire) = self.reported.get();
        let now = self.service.now();
        if (reached > last || wire > last_wire) && now.saturating_duration_since(at) >= self.every {
            self.reported.set((now, reached, wire));
            self.service.push(DaemonControlMessage::ImageUploadProgress(
                sandbox_protocol::ImageUploadProgressV11 {
                    transfer_id: self.transfer_id.clone(),
                    bytes_sent: reached,
                    wire_bytes: wire,
                },
            ));
        }
    }
}

/// The state of one running template upload between its parts: the
/// granted URL window, the parts uploaded and those not yet reported.
struct UploadRun<'a> {
    service: &'a ImageService,
    tid: String,
    rx: mpsc::Receiver<Routed>,
    resume_rx: mpsc::Receiver<Routed>,
    timings: UploadTimings,
    part_size: u64,
    stored_size: u64,
    /// Granted part URLs not used yet, and when they lapse (host clock).
    window: std::collections::BTreeMap<u32, sandbox_protocol::ImageUploadPartUrlV11>,
    expiry: Instant,
    /// Renew a URL with less lifetime left than this (`url_margin`, at most
    /// half the grant's TTL, so a short TTL never renews in a loop).
    margin: Duration,
    /// Every part uploaded, with its ETag.
    done: std::collections::BTreeMap<u32, String>,
    /// Uploaded parts not reported yet.
    pending: Vec<ImageUploadedPartV11>,
    /// Parts reported and not named by a later grant (no re-report owed).
    reported_parts: HashSet<u32>,
    /// Parts whose bytes `reported` counts: each once, however often its
    /// ETag is reported again.
    counted: HashSet<u32>,
    /// Stored bytes of the distinct parts reported (the resume's `bytesDone`).
    reported: Arc<AtomicU64>,
    last_flush: Instant,
    /// The relay connection this upload is bound to.
    connection: u64,
}

impl UploadRun<'_> {
    fn protocol() -> UploadEnd {
        UploadFailure::new(ImageFailureCode::Rejected, ImageFailureCause::Protocol).into()
    }

    /// Take a grant's URLs (the window it names, lapsing `ttlSeconds` after
    /// `at`, when it was routed). A part it names that this host already
    /// uploaded was not recorded by the server (its report was dropped):
    /// reported again.
    fn take_grant(
        &mut self,
        grant: sandbox_protocol::ImageUploadGrantV11,
        at: Instant,
    ) -> Result<(), UploadEnd> {
        if grant.transfer_id != self.tid || grant.part_size != self.part_size {
            return Err(Self::protocol());
        }
        let ttl = Duration::from_secs(grant.ttl_seconds);
        self.expiry = at + ttl;
        self.margin = self.timings.url_margin.min(ttl / 2);
        self.window.clear();
        for part in grant.parts {
            match self.done.get(&part.n) {
                Some(etag) => {
                    self.reported_parts.remove(&part.n);
                    if !self.pending.iter().any(|p| p.n == part.n) {
                        self.pending.push(ImageUploadedPartV11 {
                            n: part.n,
                            etag: etag.clone(),
                        });
                    }
                }
                None => {
                    self.window.insert(part.n, part);
                }
            }
        }
        Ok(())
    }

    /// Part `n`'s URL and its lapse, while it has more than `url_margin` left.
    fn url(&self, n: u32) -> Option<(sandbox_protocol::ImageUploadPartUrlV11, Instant)> {
        let left = self.expiry.saturating_duration_since(self.service.now());
        (left >= self.margin)
            .then(|| self.window.get(&n).cloned())
            .flatten()
            .map(|url| (url, self.expiry))
    }

    /// Report the uploaded parts not reported yet.
    fn flush(&mut self) {
        self.last_flush = Instant::now();
        if self.pending.is_empty() {
            return;
        }
        let pending = std::mem::take(&mut self.pending);
        for part in &pending {
            self.reported_parts.insert(part.n);
            if self.counted.insert(part.n) {
                let start = u64::from(part.n - 1).saturating_mul(self.part_size);
                let len = self.stored_size.saturating_sub(start).min(self.part_size);
                self.reported.fetch_add(len, Ordering::SeqCst);
            }
        }
        for chunk in pending.chunks(sandbox_protocol::IMAGE_UPLOAD_PARTS_MAX) {
            self.service.push(DaemonControlMessage::ImageUploadParts(
                ImageUploadPartsV11 {
                    transfer_id: self.tid.clone(),
                    parts: chunk.to_vec(),
                },
            ));
        }
    }

    /// The end a server cancel of this transfer means (its reason is on the
    /// transfer's receivers).
    fn cancel_end(&self) -> UploadEnd {
        let reason = self
            .rx
            .try_iter()
            .chain(self.resume_rx.try_iter())
            .find_map(|routed| match routed.frame {
                ServerControlMessage::ImageJobCancel(cancel) => Some(cancel.reason),
                _ => None,
            });
        UploadEnd::cancelled(reason.as_deref().unwrap_or("cancelled"))
    }

    /// Whether the relay connection moved since this upload was bound.
    fn reconnected(&self) -> bool {
        self.service.inner.connections.load(Ordering::SeqCst) != self.connection
    }

    /// Inside a renew: a server cancel ends the upload; a new relay
    /// connection resumes it there first, within the renew's `budget`.
    fn check(&mut self, budget: &mut Budget) -> Result<(), UploadEnd> {
        if self.service.cancelled(&self.tid) {
            return Err(self.cancel_end());
        }
        self.resume_if_reconnected(budget)
    }

    /// After a reconnect, wait for the answer to the transfer's resume on
    /// the current connection (`await_resume`, spending `budget`; `no_grant`
    /// when it runs out). Continue → the old window is dropped (the renew
    /// that follows starts from the server's lowest unrecorded part, which
    /// also re-reports parts whose report the old connection lost); anything
    /// else ends the upload.
    fn resume_if_reconnected(&mut self, budget: &mut Budget) -> Result<(), UploadEnd> {
        let service = self.service;
        let tid = self.tid.clone();
        let stop = || service.cancelled(&tid);
        match service.await_resume(
            &self.resume_rx,
            &mut self.connection,
            "stale_transfer",
            budget,
            &no_grant,
            &stop,
        ) {
            Ok(true) => {
                tracing::info!(transfer = self.tid.as_str(), "image upload resumed");
                self.window.clear();
                Ok(())
            }
            Ok(false) => Ok(()),
            Err(_) if service.cancelled(&self.tid) => Err(self.cancel_end()),
            Err(end) => Err(end),
        }
    }

    /// Fresh URLs up to a usable one for part `want`: resume after a
    /// reconnect, report the pending parts, then `image.upload.renew`,
    /// re-sent per `renew_retry` while no grant answers (a renew over the
    /// server's budget gets no reply), after a reconnect, and while a grant
    /// names only parts already held (re-reported; a pause before the next
    /// renew when nothing new was owed or the second such grant in a row
    /// came, FB-B7). Grants routed before this renew's first send (dropped
    /// from the receiver before it is queued, V2/W4) or already lapsed are
    /// never used. The whole renew, its resume waits and pauses included, is
    /// one wait (`Budget`): `UPLOAD_RENEW_WAIT` of connected time, then
    /// `no_grant`.
    fn renew(&mut self, want: u32) -> Result<(), UploadEnd> {
        let service = self.service;
        let start = service.now();
        let mut budget = Budget::new(
            start,
            service.grant_wait().min(UPLOAD_RENEW_WAIT),
            start + UPLOAD_OUTAGE_MAX,
        );
        let last = self.timings.renew_retry[self.timings.renew_retry.len() - 1];
        let mut steps = self
            .timings
            .renew_retry
            .into_iter()
            .chain(std::iter::repeat(last));
        let mut idle_grants = 0u32;
        // Anything routed so far answers an earlier request: no grant of it
        // is used (a cancel still ends the upload).
        for routed in self.rx.try_iter() {
            if let ServerControlMessage::ImageJobCancel(cancel) = routed.frame {
                return Err(UploadEnd::cancelled(&cancel.reason));
            }
        }
        let tid = self.tid.clone();
        let stop = || service.cancelled(&tid);
        loop {
            // A pause above is spent time of this renew.
            budget.charge(
                service.now(),
                service.inner.connected.load(Ordering::SeqCst),
            );
            self.check(&mut budget)?;
            self.flush();
            if budget.spent(service.now()) {
                return Err(no_grant());
            }
            self.service.push(DaemonControlMessage::ImageUploadRenew(
                sandbox_protocol::ImageUploadRenewV11 {
                    transfer_id: self.tid.clone(),
                },
            ));
            let step = steps.next().unwrap_or(last).min(budget.left);
            let mut attempt = budget.within(step);
            let outcome = loop {
                match service.wait_upload(&self.rx, &mut attempt, self.connection, &stop) {
                    Waited::Frame(routed) => match *routed {
                        Routed {
                            frame: ServerControlMessage::ImageUploadGrant(grant),
                            at,
                            ..
                        } => {
                            if at + Duration::from_secs(grant.ttl_seconds) <= service.now() {
                                continue;
                            }
                            let pending = self.pending.len();
                            self.take_grant(grant, at)?;
                            if self.url(want).is_some() {
                                break Some(Ok(()));
                            }
                            idle_grants += 1;
                            // The pause is the rest of this step: the wait
                            // for this grant was charged above, and it never
                            // runs past what is left of the renew's connected
                            // or absolute budget (a#2/b#2).
                            let rest = attempt
                                .left
                                .min(attempt.until.saturating_duration_since(service.now()));
                            if (self.pending.len() == pending || idle_grants >= 2)
                                && !service.pause(rest, &stop)
                            {
                                break Some(Err(self.cancel_end()));
                            }
                            break None;
                        }
                        Routed {
                            frame: ServerControlMessage::ImageJobCancel(cancel),
                            ..
                        } => break Some(Err(UploadEnd::cancelled(&cancel.reason))),
                        _ => {}
                    },
                    Waited::Reconnected => break None,
                    Waited::Timeout if stop() => break Some(Err(self.cancel_end())),
                    Waited::Timeout => break None,
                }
            };
            budget.settle(&attempt);
            if let Some(outcome) = outcome {
                return outcome;
            }
        }
    }
}

/// An upload that waited out its grant or renew wait (`no_grant`).
fn no_grant() -> UploadEnd {
    UploadFailure::new(ImageFailureCode::Timeout, ImageFailureCause::NoGrant).into()
}

/// A transfer a job runs (`ImageService::run_transfer`), until dropped.
pub(crate) struct RunningTransfer(Arc<Inner>, String);

impl Drop for RunningTransfer {
    fn drop(&mut self) {
        let mut running = self.0.running.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = running.get_mut(&self.1) {
            *count -= 1;
            if *count == 0 {
                running.remove(&self.1);
            }
        }
    }
}

/// A part body that reports the stored-object offset ureq has read from it
/// (logical progress; the bytes on the wire are counted as the socket takes
/// them, `UploadHeartbeat::sending`).
struct CountingBody<'a> {
    bytes: &'a [u8],
    pos: usize,
    base: u64,
    heartbeat: Option<&'a UploadHeartbeat>,
    /// When the last byte was read (the send rate's end).
    done_at: Option<Instant>,
    /// The job was cancelled: the next read fails, ending the PUT (a slow
    /// part does not hold its job, staging and slot until it is sent).
    stop: &'a dyn Fn() -> bool,
}

impl std::io::Read for CountingBody<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if (self.stop)() {
            return Err(std::io::Error::other("upload cancelled"));
        }
        let rest = self.bytes.get(self.pos..).unwrap_or_default();
        let n = rest.len().min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        self.pos += n;
        if n > 0 && self.pos == self.bytes.len() {
            self.done_at = Some(Instant::now());
        }
        if let Some(heartbeat) = self.heartbeat
            && n > 0
        {
            heartbeat.reach(self.base.saturating_add(self.pos as u64), 0);
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
