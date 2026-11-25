//! One wssp daemon per Incus server (owner decision 2026-11-07).
//!
//! Two daemons on one Incus server share its image store and network
//! namespace, so image fingerprints and the `wsn-<id>` bridge names collide.
//! This module catches that misconfiguration and refuses it safely. It is a
//! detector, not a fencing lock: Incus offers no compare-and-swap on an
//! update through its CLI, so no daemon can ever be forcibly superseded, and
//! none is.
//!
//! Each daemon keeps one marker: a profile
//! `wssp-daemon-lease-<generation>-<nonce>` in the `default` project, so it
//! is scoped to the Incus server whatever Unix user, state directory or
//! control-plane URL each daemon uses. The generation orders markers; the
//! random nonce makes every name unique for all time, so a delete by name
//! (even a late one from a paused daemon) only ever hits the exact object
//! it was meant for. Its `user.wssp.lease.*` keys hold the daemon's
//! identity, a random claim id and a wall-clock expiry. A marker is LIVE
//! while its expiry is in the future. Markers are only ever created and
//! deleted, never rewritten: Incus has no compare-and-swap on an update. A
//! graceful stop deletes the daemon's markers (released).
//!
//! Startup ([`ServerLease::acquire`]): a daemon starts only when no other
//! daemon's marker is live. It then creates generation `max + 1` and
//! confirms on two fresh reads `settle` apart: any other live marker means
//! back off, except that among daemons starting together (markers of the
//! same generation) the lowest nonce stays and every other backs off, so of
//! simultaneous starts one wins. A start that loses holds nothing yet and
//! deletes its marker. The outcome of a failed create is read back from
//! Incus by exact name and claim id, never from message text.
//!
//! Running ([`ServerLease::renew_once`]): every `renew_every` the daemon
//! creates a NEW marker (next generation, fresh expiry), publishes its
//! verdict, and only then deletes its own older ones, at most
//! `CLEANUP_DELETES` per renewal within a quarter lease; it never rewrites
//! a marker. A daemon resuming after a pause thus
//! always appears under a fresh name the other daemon reads next, and a
//! delete from another daemon's stale read can only ever hit an old
//! generation. Admission follows EVERY read, whether or not the daemon's own
//! write succeeded: any other live marker is a conflict. A daemon that can
//! read but not write, with no other live marker, stays admitted and warns
//! (the startup rule for a client that may not write profiles). A failed
//! read keeps the previous verdict. A conflict does not stop the daemon
//! (that would strand its VMs and stop lease expiry): it degrades like an
//! unhealthy egress guard. Through [`LeaseFencedProbe`] no VM starts of any
//! kind (create, cold reconnect, restore) and no image import or capture
//! while it stands; running VMs, expiry, journals, commands, files,
//! terminals, stop and destroy carry on, and it recovers once the conflict
//! clears. Another daemon's marker is removed only after it has been
//! expired for `DEAD_MARGIN_LEASES` leases, re-read just before the delete.
//!
//! The same daemon restarting takes its old marker over at once: the
//! identity is a hash of `/etc/machine-id`, host id and state directory, and
//! on one machine the journal flock on that state directory proves the old
//! process is gone. Another machine (or a host without a machine id) waits
//! for the expiry like anyone else.
//!
//! A client that may not read or create profiles in `default` (restricted
//! certificate, `incus-user`) gets [`ServerLeaseError::Forbidden`], decided
//! from the HTTP status; the daemon then runs unguarded with a warning. Any
//! other failure at startup fails closed and the service manager retries.
//!
//! Expiry compares wall clocks: daemons on different machines that share one
//! remote Incus server need synchronized clocks.

use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use sandbox_protocol::SandboxErrorCode;

use super::client::{
    IncusClient, QueryEnvelope, parse_query_envelope, percent_encode, random_nonce,
};
use crate::RuntimeError;
use crate::guard::probe::{GuardExpectations, GuardProbe, GuardStatus, INCUS_SERVER_SHARED_REASON};

/// Profile-name prefix of a daemon marker (`default` project).
pub const LEASE_PROFILE_PREFIX: &str = "wssp-daemon-lease-";
/// How long a marker stays live without renewal.
pub const LEASE_TTL_SECS: u64 = 60;
/// How often a daemon renews its marker.
pub const LEASE_RENEW_EVERY: Duration = Duration::from_secs(15);

const KEY_IDENTITY: &str = "user.wssp.lease.identity";
const KEY_CLAIM: &str = "user.wssp.lease.claim";
const KEY_HOST_ID: &str = "user.wssp.lease.host_id";
const KEY_LABEL: &str = "user.wssp.lease.label";
const KEY_MACHINE: &str = "user.wssp.lease.machine";
const KEY_PID: &str = "user.wssp.lease.pid";
const KEY_RENEWED_AT: &str = "user.wssp.lease.renewed_at";
const KEY_EXPIRES_AT: &str = "user.wssp.lease.expires_at";
const DESCRIPTION: &str =
    "wssp daemon marker: one wssp daemon per Incus server; managed by wssp, never attach";
/// Each marker call's own bound; startup never hangs on a stalled Incus.
const CALL_TIMEOUT: Duration = Duration::from_secs(15);
/// Claim rounds before contention is reported (each lost race re-reads).
const CLAIM_ROUNDS: usize = 4;
/// Another daemon's marker is removed only once it has been expired (or
/// released) for this many leases, so a renewal in flight when it was read
/// can never be deleted from a stale snapshot.
const DEAD_MARGIN_LEASES: u64 = 5;
/// Evidence of another daemon's live marker keeps a daemon degraded until
/// no read has shown one for this many leases.
const PEER_MEMORY_LEASES: u64 = 2;
/// At most this many marker deletes per renewal (cleanup never delays it).
const CLEANUP_DELETES: usize = 2;
/// Warn once this many of a daemon's own superseded markers remain.
const STALE_OWN_WARN: usize = 3;

/// The cleanup allowance of one renewal or start: a delete count and a
/// time bound (a quarter lease), so a slow or failing Incus can never push
/// the next renewal past the marker's expiry.
struct CleanupBudget {
    deletes: usize,
    deadline: std::time::Instant,
}

impl CleanupBudget {
    fn new(timing: &LeaseTiming) -> Self {
        Self {
            deletes: CLEANUP_DELETES,
            deadline: std::time::Instant::now() + Duration::from_secs(timing.ttl_secs / 4),
        }
    }
    fn allows(&self) -> bool {
        self.deletes > 0 && std::time::Instant::now() < self.deadline
    }
    fn take(&mut self) -> bool {
        if !self.allows() {
            return false;
        }
        self.deletes -= 1;
        true
    }
}

/// A displayed holder field is bounded and free of control characters.
const DISPLAY_MAX: usize = 80;

/// Who this daemon is. `machine_id`, `host_id` and `state_dir` decide
/// whether a marker is this daemon's own (a restart takes it over at once);
/// `label`, `machine` and `pid` only help an operator find the other daemon.
/// Never a credential. `machine_id` is only ever hashed, never stored or
/// displayed.
#[derive(Clone, PartialEq, Eq)]
pub struct DaemonIdentity {
    pub machine_id: String,
    pub host_id: String,
    pub label: String,
    pub state_dir: String,
    pub machine: String,
    pub pid: u32,
}

impl std::fmt::Debug for DaemonIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaemonIdentity")
            .field("host_id", &self.host_id)
            .field("label", &self.label)
            .field("state_dir", &self.state_dir)
            .field("machine", &self.machine)
            .field("pid", &self.pid)
            .finish_non_exhaustive()
    }
}

impl DaemonIdentity {
    /// The same-daemon key. Without a machine id there is no proof that a
    /// marker came from this machine, so the key is unique to this process
    /// and never matches an old marker.
    fn key(&self) -> Result<String, ServerLeaseError> {
        if self.machine_id.is_empty() {
            return random_nonce().map_err(|err| unavailable("cannot draw an identity", err));
        }
        let mut input = self.machine_id.as_bytes().to_vec();
        for part in [&self.host_id, &self.state_dir] {
            input.push(0);
            input.extend_from_slice(part.as_bytes());
        }
        let digest = ring::digest::digest(&ring::digest::SHA256, &input);
        Ok(digest.as_ref()[..16]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect())
    }

    /// The local machine's hostname, or `unknown`.
    pub fn local_machine() -> String {
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .map(|name| name.trim().to_string())
            .ok()
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "unknown".to_string())
    }

    /// This machine's `/etc/machine-id` (or the D-Bus copy), or empty.
    pub fn local_machine_id() -> String {
        ["/etc/machine-id", "/var/lib/dbus/machine-id"]
            .iter()
            .find_map(|path| {
                std::fs::read_to_string(path)
                    .ok()
                    .map(|id| id.trim().to_string())
                    .filter(|id| !id.is_empty())
            })
            .unwrap_or_default()
    }
}

/// Wall clock in unix seconds; tests inject their own.
pub type LeaseClock = Arc<dyn Fn() -> u64 + Send + Sync>;

#[derive(Clone)]
pub struct LeaseTiming {
    pub ttl_secs: u64,
    pub renew_every: Duration,
    /// Pause between a start's two confirming reads.
    pub settle: Duration,
    pub now: LeaseClock,
}

impl Default for LeaseTiming {
    fn default() -> Self {
        Self {
            ttl_secs: LEASE_TTL_SECS,
            renew_every: LEASE_RENEW_EVERY,
            settle: Duration::from_secs(2),
            now: Arc::new(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            }),
        }
    }
}

/// The daemon behind a marker, as far as its record tells.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseHolder {
    pub host_id: String,
    pub label: String,
    pub machine: String,
    pub pid: String,
}

impl std::fmt::Display for LeaseHolder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "host `{}` (label `{}`, pid {} on `{}`)",
            display(&self.host_id),
            display(&self.label),
            display(&self.pid),
            display(&self.machine)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerLeaseError {
    /// Another daemon's marker on this Incus server is live.
    Held {
        holder: Box<LeaseHolder>,
        retry_after_secs: u64,
        profile: String,
    },
    /// This Incus client may not read or create profiles in `default`
    /// (HTTP 401/403): the guard is unavailable to it, not failed.
    Forbidden { detail: String },
    /// The newest marker holds the highest possible generation (u64::MAX),
    /// which no daemon writes: no new marker can be created until it is
    /// verified and deleted.
    GenerationExhausted { profile: String },
    /// The markers could not be read or written (Incus down, unrelenting
    /// contention). The daemon does not start unguarded.
    Unavailable { detail: String },
}

impl std::fmt::Display for ServerLeaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Held {
                holder,
                retry_after_secs,
                profile,
            } => write!(
                f,
                "another wssp daemon already drives this Incus server: {holder}. One wssp \
                 daemon per Incus server is supported: image fingerprints and sandbox bridge \
                 names would collide. Stop the other daemon (for example `systemctl --user stop \
                 wssp-host` as the user that runs it), or, if it crashed, wait {retry_after_secs}s \
                 for its marker (Incus profile `{profile}` in project `default`) to expire, then \
                 start this daemon again"
            ),
            Self::GenerationExhausted { profile } => write!(
                f,
                "Incus profile `{profile}` in project `default` holds the highest possible \
                 marker generation, so no wssp daemon can claim this Incus server; no daemon \
                 writes such a marker. Inspect it and delete it if it names no daemon you run \
                 (docs/guide/hosts.md, \"Trust boundary and bogus markers\")"
            ),
            Self::Forbidden { detail } => write!(
                f,
                "this Incus client may not manage profiles in project `default` ({detail}), so \
                 the one-daemon-per-Incus-server guard is unavailable to it"
            ),
            Self::Unavailable { detail } => write!(
                f,
                "cannot verify that this is the only wssp daemon on this Incus server, so it \
                 will not start: {detail}. Check that Incus is running and reachable"
            ),
        }
    }
}

impl std::error::Error for ServerLeaseError {}

/// One renewal's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseHealth {
    /// No other daemon's marker is live.
    Sole,
    /// Another daemon's marker is live (description of it): new sandboxes
    /// are refused until it clears.
    Conflict(String),
}

/// One renewal: the verdict from the latest read, and what went wrong
/// writing this daemon's own marker, if anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Renewal {
    pub health: LeaseHealth,
    pub problem: Option<String>,
}

/// Renewal-thread notifications (the runtime crate does not log).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseEvent {
    /// Every renewal that finds another live marker.
    Conflict(String),
    /// The first sole renewal after a conflict.
    Cleared,
    RenewFailed(String),
}

#[derive(Debug, Clone)]
struct LeaseRecord {
    generation: u64,
    /// The per-marker random part of the name: names are never reused, so
    /// a delete by name only ever hits the exact object it was meant for.
    nonce: String,
    name: String,
    identity: String,
    claim: String,
    expires_at: u64,
    holder: LeaseHolder,
}

impl LeaseRecord {
    fn from_profile(profile: &serde_json::Value) -> Option<Self> {
        let name = profile.get("name")?.as_str()?;
        let (generation, nonce) = parse_marker_name(name)?;
        let config = profile.get("config").and_then(serde_json::Value::as_object);
        let get = |key: &str| {
            config
                .and_then(|config| config.get(key))
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        Some(Self {
            generation,
            nonce,
            name: name.to_string(),
            identity: get(KEY_IDENTITY),
            claim: get(KEY_CLAIM),
            // Missing or malformed: already expired (no live daemon writes it).
            expires_at: get(KEY_EXPIRES_AT).parse().unwrap_or(0),
            holder: LeaseHolder {
                host_id: get(KEY_HOST_ID),
                label: get(KEY_LABEL),
                machine: get(KEY_MACHINE),
                pid: get(KEY_PID),
            },
        })
    }

    fn live(&self, now: u64) -> bool {
        self.expires_at > now
    }
}

/// Length of the per-marker nonce in a marker name (lowercase hex).
const NAME_NONCE_LEN: usize = 16;

/// `wssp-daemon-lease-<generation>-<nonce>`: the generation without leading
/// zeros, the nonce exactly `NAME_NONCE_LEN` lowercase hex digits. Anything
/// else is not a marker.
fn parse_marker_name(name: &str) -> Option<(u64, String)> {
    let rest = name.strip_prefix(LEASE_PROFILE_PREFIX)?;
    let (generation, nonce) = rest.split_once('-')?;
    if generation.is_empty() || !generation.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let parsed = generation.parse::<u64>().ok()?;
    if parsed.to_string() != generation
        || nonce.len() != NAME_NONCE_LEN
        || !nonce
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    Some((parsed, nonce.to_string()))
}

fn marker_name(generation: u64, nonce: &str) -> String {
    format!("{LEASE_PROFILE_PREFIX}{generation}-{nonce}")
}

/// The newest live marker that is not this daemon's (`claim`) and not this
/// daemon's own predecessor (`identity`).
fn live_other<'a>(
    records: &'a [LeaseRecord],
    claim: &str,
    identity: &str,
    now: u64,
) -> Option<&'a LeaseRecord> {
    records
        .iter()
        .filter(|r| r.claim != claim && r.identity != identity && r.live(now))
        .max_by_key(|r| r.expires_at)
}

fn peer_description(other: &LeaseRecord) -> String {
    format!(
        "{} also drives this Incus server (marker `{}`)",
        other.holder, other.name
    )
}

fn display(value: &str) -> String {
    let clean: String = value
        .chars()
        .filter(|c| !c.is_control() && *c != '`')
        .take(DISPLAY_MAX)
        .collect();
    if clean.is_empty() {
        "unknown".to_string()
    } else {
        clean
    }
}

fn profile_url(name: &str) -> String {
    format!("/1.0/profiles/{}?project=default", percent_encode(name))
}

fn unavailable(action: &str, err: impl std::fmt::Display) -> ServerLeaseError {
    ServerLeaseError::Unavailable {
        detail: format!("{action}: {err}"),
    }
}

fn forbidden_status(code: u64) -> bool {
    matches!(code, 401 | 403)
}

struct LeaseState {
    stop: bool,
    released: bool,
    conflict: Option<String>,
    /// The latest read (by its ISSUE time) that showed another daemon's
    /// live marker, and which one: evidence stays for `PEER_MEMORY_LEASES`.
    peer_seen: Option<(u64, String)>,
}

struct Shared {
    client: IncusClient,
    identity: DaemonIdentity,
    identity_key: String,
    claim: String,
    /// This daemon's current marker (a removed one is recreated).
    name: Mutex<String>,
    timing: LeaseTiming,
    state: Mutex<LeaseState>,
    wake: Condvar,
}

/// A daemon's marker. Dropping it (or [`ServerLease::release`]) stops
/// renewal and marks the marker released.
pub struct ServerLease {
    shared: Arc<Shared>,
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl IncusClient {
    fn lease_call(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<QueryEnvelope, RuntimeError> {
        let mut args = vec!["query", "--raw", "-X", method];
        if let Some(body) = body {
            args.extend(["-d", body]);
        }
        args.push(path);
        let out = self.run_bounded(&args, false, CALL_TIMEOUT)?;
        Ok(match parse_query_envelope(&out) {
            QueryEnvelope::Unparseable if out.exit_code == 0 => {
                QueryEnvelope::Sync(serde_json::Value::Null)
            }
            QueryEnvelope::Unparseable => QueryEnvelope::Error((
                0,
                format!(
                    "incus exited {}: {}",
                    out.exit_code,
                    out.stderr.trim().chars().take(300).collect::<String>()
                ),
            )),
            parsed => parsed,
        })
    }

    /// Every marker, lowest generation first. A 401/403 is `Forbidden`.
    fn lease_records(&self) -> Result<Vec<LeaseRecord>, ServerLeaseError> {
        let profiles = self
            .query_raw_timed("/1.0/profiles?project=default&recursion=1", CALL_TIMEOUT)
            .map_err(|err| {
                // `api_status_error` maps exactly HTTP 401/403 to AccessDenied.
                if err.code == SandboxErrorCode::AccessDenied {
                    ServerLeaseError::Forbidden {
                        detail: err.message,
                    }
                } else {
                    unavailable("cannot list Incus profiles", err)
                }
            })?;
        let profiles = profiles
            .as_array()
            .ok_or_else(|| unavailable("cannot list Incus profiles", "the answer is not a list"))?;
        let mut records: Vec<LeaseRecord> = profiles
            .iter()
            .filter_map(LeaseRecord::from_profile)
            .collect();
        records.sort_by(|a, b| (a.generation, &a.nonce).cmp(&(b.generation, &b.nonce)));
        Ok(records)
    }

    fn delete_lease_profile(&self, name: &str) {
        // Best effort: a leftover dead marker never decides anything.
        let _ = self.lease_call("DELETE", &profile_url(name), None);
    }
}

fn marker_body(
    name: &str,
    identity: &DaemonIdentity,
    identity_key: &str,
    claim: &str,
    timing: &LeaseTiming,
) -> String {
    let mut config = lease_times((timing.now)(), timing.ttl_secs);
    for (key, value) in [
        (KEY_IDENTITY, identity_key.to_string()),
        (KEY_CLAIM, claim.to_string()),
        (KEY_HOST_ID, identity.host_id.clone()),
        (KEY_LABEL, identity.label.clone()),
        (KEY_MACHINE, identity.machine.clone()),
        (KEY_PID, identity.pid.to_string()),
    ] {
        config.insert(key.to_string(), value.into());
    }
    serde_json::json!({
        "name": name,
        "description": DESCRIPTION,
        "config": config,
        "devices": {},
    })
    .to_string()
}

enum Created {
    Mine(String),
    LostRace,
}

/// Create generation `max + 1` under a never-reused name, carrying `claim`.
/// A failed create is settled from Incus itself: that exact name carries our
/// claim (it was created), another claim (never adopted), or does not exist
/// (a real failure).
fn create_marker(
    client: &IncusClient,
    records: &[LeaseRecord],
    identity: &DaemonIdentity,
    identity_key: &str,
    claim: &str,
    timing: &LeaseTiming,
) -> Result<Created, ServerLeaseError> {
    // Never saturate: at the maximum the "next" name would be the existing
    // marker's, and a failed create would then read back as our own.
    let generation = match records.last() {
        None => 1,
        Some(record) => record.generation.checked_add(1).ok_or_else(|| {
            ServerLeaseError::GenerationExhausted {
                profile: record.name.clone(),
            }
        })?,
    };
    let nonce = random_nonce().map_err(|err| unavailable("cannot draw a marker name", err))?;
    let name = marker_name(generation, &nonce[..NAME_NONCE_LEN]);
    let body = marker_body(&name, identity, identity_key, claim, timing);
    let created = client.lease_call("POST", "/1.0/profiles?project=default", Some(&body));
    if matches!(created, Ok(QueryEnvelope::Sync(_))) {
        return Ok(Created::Mine(name));
    }
    if let Ok(QueryEnvelope::Error((code, message))) = &created
        && forbidden_status(*code)
    {
        return Err(ServerLeaseError::Forbidden {
            detail: format!("HTTP {code}: {message}"),
        });
    }
    // Adopt only the exact name this call created, carrying our claim id:
    // a profile under that name with any other claim is someone else's.
    let after = client.lease_records()?;
    match after.iter().find(|record| record.name == name) {
        Some(record) if record.claim == claim => Ok(Created::Mine(name)),
        Some(_) => Ok(Created::LostRace),
        None => Err(unavailable(
            "cannot create the marker profile",
            match created {
                Ok(QueryEnvelope::Error((code, message))) => format!("HTTP {code}: {message}"),
                Err(err) => err.to_string(),
                Ok(_) => "unexpected answer".to_string(),
            },
        )),
    }
}

impl ServerLease {
    /// Start as this Incus server's only daemon, or say who already is.
    /// Never supersedes another daemon's live marker.
    pub fn acquire(
        client: &IncusClient,
        identity: &DaemonIdentity,
        timing: LeaseTiming,
    ) -> Result<Self, ServerLeaseError> {
        let claim = random_nonce().map_err(|err| unavailable("cannot draw a claim id", err))?;
        let identity_key = identity.key()?;
        let started = (timing.now)();
        let held = |other: &LeaseRecord, now: u64| ServerLeaseError::Held {
            holder: Box::new(other.holder.clone()),
            retry_after_secs: other.expires_at.saturating_sub(now),
            profile: other.name.clone(),
        };
        for _ in 0..CLAIM_ROUNDS {
            // Judged at the read's issue time, never at its return.
            let issued = (timing.now)();
            let records = client.lease_records()?;
            if let Some(other) = live_other(&records, &claim, &identity_key, issued) {
                return Err(held(other, (timing.now)()));
            }
            let name =
                match create_marker(client, &records, identity, &identity_key, &claim, &timing)? {
                    Created::Mine(name) => name,
                    Created::LostRace => continue,
                };
            let lease = Self {
                shared: Arc::new(Shared {
                    client: client.clone(),
                    identity: identity.clone(),
                    identity_key: identity_key.clone(),
                    claim: claim.clone(),
                    name: Mutex::new(name),
                    timing: timing.clone(),
                    state: Mutex::new(LeaseState {
                        stop: false,
                        released: false,
                        conflict: None,
                        peer_seen: None,
                    }),
                    wake: Condvar::new(),
                }),
                worker: Mutex::new(None),
            };
            // Confirm on fresh reads, twice, `settle` apart. Names are unique,
            // so daemons starting together each create a marker of the same
            // generation; of those the lowest nonce stays and every other
            // backs off. Any other live marker (a running daemon, or one that
            // renewed a marker we read as expired) means back off. Holding
            // nothing yet, backing off is safe: dropping `lease` deletes our
            // marker.
            let (generation, nonce) = parse_marker_name(&lease.profile_name())
                .ok_or_else(|| unavailable("cannot confirm the marker", "unparsable name"))?;
            let mut records = Vec::new();
            for confirm in 0..2 {
                if confirm == 1 {
                    std::thread::sleep(timing.settle);
                }
                // Each read is judged at its issue time, and each one
                // counts: evidence from the first is never replaced by the
                // second.
                let issued = (timing.now)();
                records = client.lease_records()?;
                let blocking = records.iter().filter(|r| {
                    r.claim != claim
                        && r.identity != identity_key
                        && r.live(issued)
                        && (r.generation != generation || r.nonce < nonce)
                });
                if let Some(other) = blocking.max_by_key(|r| r.expires_at) {
                    return Err(held(other, (timing.now)()));
                }
            }
            let now = (timing.now)();
            // A start slower than a quarter lease begins unconfirmed
            // (degraded) until its first fast renewal.
            let took = now.saturating_sub(started);
            if took > timing.ttl_secs / 4 {
                lease.shared.state().conflict = Some(format!(
                    "this daemon's start took {took}s, more than a quarter lease, so its claim on \
                     this Incus server is unconfirmed"
                ));
            }
            lease
                .shared
                .remove_dead_markers(&records, now, &mut CleanupBudget::new(&timing));
            return Ok(lease);
        }
        Err(unavailable(
            "marker contention",
            format!("{CLAIM_ROUNDS} claim rounds lost to other daemons"),
        ))
    }

    pub fn profile_name(&self) -> String {
        self.shared.name().clone()
    }

    /// The identity this marker was claimed for.
    pub fn identity(&self) -> &DaemonIdentity {
        &self.shared.identity
    }

    /// The live conflict the last renewal saw, if any.
    pub fn conflict(&self) -> Option<String> {
        self.shared.state().conflict.clone()
    }

    /// One renewal: renew this daemon's live marker in place, or claim a
    /// new one when it is missing or expired, and report whether another
    /// daemon's marker is live. `Err`: the markers could not be read, and
    /// the previous verdict stands.
    pub fn renew_once(&self) -> Result<Renewal, String> {
        self.shared.renew_once()
    }

    /// A guard probe that reports `incus_server_shared` while a conflict
    /// stands, so every admission path refuses new sandboxes the way an
    /// unhealthy egress guard does. Everything else is `inner`'s.
    pub fn fence_probe(&self, inner: Arc<dyn GuardProbe>) -> LeaseFencedProbe {
        LeaseFencedProbe {
            inner,
            shared: self.shared.clone(),
        }
    }

    /// Renew every `renew_every` on a background thread until released.
    pub fn spawn_renewal(
        &self,
        on_event: Arc<dyn Fn(LeaseEvent) + Send + Sync>,
    ) -> std::io::Result<()> {
        let shared = self.shared.clone();
        let handle = std::thread::Builder::new()
            .name("wssp-incus-lease".into())
            .spawn(move || {
                loop {
                    {
                        let state = shared.state();
                        let (state, _) = shared
                            .wake
                            .wait_timeout_while(state, shared.timing.renew_every, |s| !s.stop)
                            .unwrap_or_else(|poison| poison.into_inner());
                        if state.stop {
                            break;
                        }
                    }
                    let before = shared.state().conflict.is_some();
                    match shared.renew_once() {
                        Ok(renewal) => {
                            if let Some(problem) = renewal.problem {
                                on_event(LeaseEvent::RenewFailed(problem));
                            }
                            match renewal.health {
                                LeaseHealth::Sole if before => on_event(LeaseEvent::Cleared),
                                LeaseHealth::Sole => {}
                                LeaseHealth::Conflict(other) => {
                                    on_event(LeaseEvent::Conflict(other));
                                }
                            }
                        }
                        Err(detail) => on_event(LeaseEvent::RenewFailed(detail)),
                    }
                }
            })?;
        *self
            .worker
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = Some(handle);
        Ok(())
    }

    /// Stop renewing and mark this daemon's marker released.
    pub fn release(&self) {
        {
            let mut state = self.shared.state();
            state.stop = true;
            self.shared.wake.notify_all();
        }
        let worker = self
            .worker
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .take();
        if let Some(worker) = worker {
            let _ = worker.join();
        }
        self.shared.mark_released();
    }
}

impl Drop for ServerLease {
    fn drop(&mut self) {
        self.release();
    }
}

impl Shared {
    fn state(&self) -> std::sync::MutexGuard<'_, LeaseState> {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn name(&self) -> std::sync::MutexGuard<'_, String> {
        self.name
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn renew_once(&self) -> Result<Renewal, String> {
        // Every read is judged at the time it was ISSUED: a marker live then
        // was live while the read was in flight, however slow Incus is.
        let first_issued = (self.timing.now)();
        // A failed read gives no new evidence: the previous verdict stands.
        let records = self.client.lease_records().map_err(|err| err.to_string())?;
        // Publish a conflict the moment any read shows a live peer, before
        // this renewal's write or any further call; the verdict below then
        // re-evaluates with the later read.
        if let Some(other) = live_other(&records, &self.claim, &self.identity_key, first_issued) {
            let other = peer_description(other);
            let mut state = self.state();
            state.peer_seen = Some((first_issued, other.clone()));
            state.conflict = Some(other);
        }
        let mut problem = None;
        let mut exhausted = None;
        // Never rewrite a marker (Incus has no compare-and-swap on update):
        // every renewal creates a NEW generation, the one write Incus
        // serializes, then removes this daemon's older ones. A daemon that
        // resumes after a pause therefore always appears under a fresh name
        // the other daemon reads next, and a delete from another daemon's
        // stale read can only ever hit an old generation.
        let claimed = match create_marker(
            &self.client,
            &records,
            &self.identity,
            &self.identity_key,
            &self.claim,
            &self.timing,
        ) {
            Ok(Created::Mine(name)) => {
                *self.name() = name;
                true
            }
            Ok(Created::LostRace) => {
                problem = Some("marker renewal raced another daemon's write".into());
                false
            }
            Err(err @ ServerLeaseError::GenerationExhausted { .. }) => {
                exhausted = Some(err.to_string());
                problem = Some(err.to_string());
                false
            }
            Err(err) => {
                problem = Some(err.to_string());
                false
            }
        };
        // A read plus write slower than a quarter lease leaves this
        // daemon's own claim unconfirmed: degraded until a faster round.
        let round_trip = (self.timing.now)().saturating_sub(first_issued);
        let slow = round_trip > self.timing.ttl_secs / 4;
        if slow {
            problem.get_or_insert(format!(
                "a marker renewal took {round_trip}s (more than a quarter lease); this daemon's \
                 claim is unconfirmed until a faster renewal"
            ));
        }
        let second_issued = (self.timing.now)();
        let fresh = self.client.lease_records();
        // Both reads are evidence: a peer live at either read's issue time.
        let mut evidence = live_other(&records, &self.claim, &self.identity_key, first_issued)
            .map(|other| (first_issued, other.clone()));
        let records = match fresh {
            Ok(fresh) => {
                if let Some(other) =
                    live_other(&fresh, &self.claim, &self.identity_key, second_issued)
                {
                    evidence = Some((second_issued, other.clone()));
                }
                fresh
            }
            Err(err) => {
                problem.get_or_insert(err.to_string());
                records
            }
        };
        // Admission follows every read, whether or not this daemon's own
        // write succeeded, and evidence of another live marker is sticky:
        // degraded until no read has shown one for `PEER_MEMORY_LEASES`
        // leases. It is published BEFORE any cleanup, so no delete can delay
        // it.
        let now = (self.timing.now)();
        let peer = {
            let mut state = self.state();
            if let Some((issued, other)) = evidence {
                state.peer_seen = Some((issued, peer_description(&other)));
            }
            let memory = self.timing.ttl_secs.saturating_mul(PEER_MEMORY_LEASES);
            match &state.peer_seen {
                Some((seen, other)) if now < seen.saturating_add(memory) => Some(other.clone()),
                _ => {
                    state.peer_seen = None;
                    None
                }
            }
        };
        let health = match (exhausted, peer) {
            // No daemon can keep a marker past it: degrade until it is gone.
            (Some(exhausted), _) => LeaseHealth::Conflict(exhausted),
            (None, Some(other)) => LeaseHealth::Conflict(other),
            (None, None) if slow => LeaseHealth::Conflict(format!(
                "this daemon's marker renewal took {round_trip}s, more than a quarter lease, so \
                 its claim on this Incus server is unconfirmed"
            )),
            // No other live marker: admitted, even when this daemon could
            // not write its own (reported as `problem`), like a start whose
            // client may not write profiles.
            (None, None) => LeaseHealth::Sole,
        };
        self.state().conflict = match &health {
            LeaseHealth::Sole => None,
            LeaseHealth::Conflict(other) => Some(other.clone()),
        };
        // Bounded cleanup after the verdict: at most `CLEANUP_DELETES`
        // deletes within `CLEANUP_BUDGET` of this renewal, own superseded
        // markers first (even in a conflict: they are ours, and the newest
        // stays for the other daemon to see), then dead markers of others.
        if claimed {
            let mut budget = CleanupBudget::new(&self.timing);
            let current = self.name().clone();
            let stale: Vec<&LeaseRecord> = records
                .iter()
                .filter(|record| record.claim == self.claim && record.name != current)
                .collect();
            let mut left = stale.len();
            for record in stale {
                if !budget.take() {
                    break;
                }
                self.client.delete_lease_profile(&record.name);
                left -= 1;
            }
            if left >= STALE_OWN_WARN {
                problem.get_or_insert(format!(
                    "{left} superseded markers of this daemon await removal (deletes are failing \
                     or slow)"
                ));
            }
            if matches!(health, LeaseHealth::Sole) {
                self.remove_dead_markers(&records, now, &mut budget);
            }
        }
        Ok(Renewal { health, problem })
    }

    /// Remove this daemon's own superseded markers and its predecessor's,
    /// and other daemons' markers that have been expired (or released) for
    /// at least `DEAD_MARGIN_LEASES` leases, re-read just before each
    /// delete. Never a live marker of another daemon, even from a stale
    /// snapshot.
    fn remove_dead_markers(&self, records: &[LeaseRecord], now: u64, budget: &mut CleanupBudget) {
        let margin = self.timing.ttl_secs.saturating_mul(DEAD_MARGIN_LEASES);
        let current = self.name().clone();
        let dead = |record: &LeaseRecord, now: u64| {
            record.name != current
                && (record.claim == self.claim
                    || record.identity == self.identity_key
                    || record.expires_at.saturating_add(margin) <= now)
        };
        if !records.iter().any(|record| dead(record, now)) || !budget.allows() {
            return;
        }
        let Ok(fresh) = self.client.lease_records() else {
            return;
        };
        let now = (self.timing.now)();
        for record in records.iter().filter(|record| dead(record, now)) {
            let unchanged = fresh.iter().any(|current| {
                current.name == record.name
                    && current.claim == record.claim
                    && current.expires_at == record.expires_at
                    && dead(current, now)
            });
            if unchanged {
                if !budget.take() {
                    return;
                }
                self.client.delete_lease_profile(&record.name);
            }
        }
    }

    fn mark_released(&self) {
        {
            let mut state = self.state();
            if state.released {
                return;
            }
            state.released = true;
            state.stop = true;
        }
        // Released by removal: never a rewrite. Names are never reused, so
        // these deletes can only hit this daemon's own markers.
        let Ok(records) = self.client.lease_records() else {
            return;
        };
        for record in records.iter().filter(|record| record.claim == self.claim) {
            self.client.delete_lease_profile(&record.name);
        }
    }
}

/// The node's guard probe, refusing new sandboxes while the Incus server is
/// shared. See [`ServerLease::fence_probe`].
pub struct LeaseFencedProbe {
    inner: Arc<dyn GuardProbe>,
    shared: Arc<Shared>,
}

impl std::fmt::Debug for LeaseFencedProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeaseFencedProbe")
            .field("conflict", &self.shared.state().conflict)
            .finish_non_exhaustive()
    }
}

impl GuardProbe for LeaseFencedProbe {
    fn status(&self) -> Result<GuardStatus, RuntimeError> {
        let mut status = self.inner.status()?;
        if self.shared.state().conflict.is_some() {
            status.ok = false;
            status
                .reasons
                .insert(0, INCUS_SERVER_SHARED_REASON.to_string());
        }
        Ok(status)
    }
    fn expectations(&self) -> Result<GuardExpectations, RuntimeError> {
        self.inner.expectations()
    }
    fn shared_incus_server(&self) -> Option<String> {
        self.shared.state().conflict.clone()
    }
    fn will_attest(&self, bridge: &str, gateway: std::net::Ipv4Addr) {
        self.inner.will_attest(bridge, gateway);
    }
    fn push_deployment(
        &self,
        configured: bool,
        entries: Vec<String>,
    ) -> Result<String, RuntimeError> {
        self.inner.push_deployment(configured, entries)
    }
    fn egress_ceiling(&self) -> Result<crate::guard::ceiling::EgressCeiling, RuntimeError> {
        // Running sandboxes keep their host sockets (credential proxy).
        self.inner.egress_ceiling()
    }
    fn domain_blocklist(&self) -> Result<crate::egress::DomainBlocklist, RuntimeError> {
        self.inner.domain_blocklist()
    }
}

fn lease_times(now: u64, ttl: u64) -> serde_json::Map<String, serde_json::Value> {
    let mut config = serde_json::Map::new();
    config.insert(KEY_RENEWED_AT.to_string(), now.to_string().into());
    config.insert(
        KEY_EXPIRES_AT.to_string(),
        now.saturating_add(ttl).to_string().into(),
    );
    config
}

#[cfg(test)]
#[path = "server_lease_shim_tests.rs"]
mod tests;
