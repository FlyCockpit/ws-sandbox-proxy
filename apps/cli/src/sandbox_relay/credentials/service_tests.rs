//! Daemon tests over FakeRuntime and a scripted server:
//! install-before-READY, install failures, recovery success / failure /
//! install failure after recovery, residue scrub-then-inject, spec transfer
//! failing before any guest effect, and the lane e2e: create with a login →
//! spec fetch → bundle install → READY, then a daemon restart → census →
//! env restore, with a sentinel check that no plaintext is at rest.

#![allow(deprecated)] // ring's fixed test RNG loads a fixed X25519 scalar.

use super::*;
use crate::sandbox_relay::credentials::seal::{ReturnPublicKey, testing};
use crate::sandbox_relay::credentials::transfer::{definition_for, digest_bytes};
use login_definition::{Bundle, BundleEnv, BundleFile, BundleFileKind, encode_bundle};
use sandbox_protocol::{
    CredentialBundleBeginV11, CredentialBundleChunkV11, CredentialBundleRefusedV11,
    CredentialCaptureAckV11, CredentialCensusAckV11, CredentialLeaseKind, CredentialReturnKeyV11,
    CredentialRotates, CredentialSpecChunkV11, SpecFilesV11, SpecResidueV11,
};
use sandbox_runtime::FakeRuntime;
use std::sync::atomic::AtomicBool;
use std::thread::JoinHandle;

const SANDBOX: &str = "sbx-1";
const OWNER: &str = "owner-1";
const FILE: &str = ".config/tool/hosts.yml";
/// The credential value: must never be at rest, in a frame's Debug or a log.
const SENTINEL: &[u8] = b"SENTINEL-CREDENTIAL-VALUE-c8a1";
const FILE_SENTINEL: &[u8] = b"token: SENTINEL-FILE-c8a1";

struct Key {
    private: [u8; 32],
    public: ReturnPublicKey,
}

impl Key {
    fn new(seed: u8) -> Self {
        let private = [seed; 32];
        let rng = ring::test::rand::FixedSliceRandom { bytes: &private };
        let key =
            ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::X25519, &rng).unwrap();
        let bytes: [u8; 32] = key
            .compute_public_key()
            .unwrap()
            .as_ref()
            .try_into()
            .unwrap();
        Self {
            private,
            public: ReturnPublicKey::from_bytes(bytes).unwrap(),
        }
    }
    fn frame(&self) -> CredentialReturnKeyV11 {
        CredentialReturnKeyV11 {
            kid_r: self.public.kid_r().to_owned(),
            epoch: 1,
            public_key: self.public.to_base64url(),
            server_origin: "https://wssp.example.com".into(),
        }
    }
}

fn lease(id: &str, action: SpecLeaseAction, binding: Option<&str>) -> SpecLeaseV11 {
    SpecLeaseV11 {
        lease_id: id.into(),
        binding_id: binding.map(str::to_owned),
        credential_id: format!("cred-{id}"),
        instance_id: "inst-1".into(),
        definition_digest: "ab".repeat(32),
        max_bytes: 4096,
        delivery: CredentialDelivery::Guest,
        exclusive: true,
        copy_back: true,
        rotates: CredentialRotates::Unknown,
        kind: CredentialLeaseKind::Workload,
        action,
        files: SpecFilesV11 {
            required: vec![".config/tool".into()],
            optional: vec![],
            exclude: vec![],
        },
        env: vec!["TOOL_TOKEN".into()],
        proxy: vec![],
        checkpoint_interval_min: None,
    }
}

fn residue(id: &str, binding: &str, lease: &str, action: SpecResidueAction) -> SpecResidueV11 {
    SpecResidueV11 {
        residue_id: id.into(),
        binding_id: binding.into(),
        lease_id: lease.into(),
        action,
        paths: vec![".config/tool".into()],
    }
}

fn spec(leases: Vec<SpecLeaseV11>, residue: Vec<SpecResidueV11>) -> CredentialSpecV11 {
    CredentialSpecV11 {
        version: 1,
        sandbox_id: SANDBOX.into(),
        sandbox_owner_id: OWNER.into(),
        host_owner_id: OWNER.into(),
        leases,
        residue,
    }
}

fn reference(bytes: &[u8]) -> CredentialSpecRefV11 {
    CredentialSpecRefV11 {
        digest: crate::sandbox_relay::credentials::seal::sha256_hex(bytes),
        bytes: bytes.len() as u64,
    }
}

fn target(spec_bytes: &[u8]) -> LaunchTarget {
    LaunchTarget {
        operation_id: "op-create-1".into(),
        guest: CredentialGuest {
            sandbox_id: SANDBOX.into(),
            uid: 1000,
            gid: 1000,
            home: "/home/user".into(),
        },
        spec_digest: crate::sandbox_relay::credentials::seal::sha256_hex(spec_bytes),
    }
}

/// The server's bundle for a lease (files only on install).
fn bundle_bytes(lease: &SpecLeaseV11, files: bool) -> Vec<u8> {
    let def = definition_for(lease).unwrap();
    let files = files && !lease.files.is_empty();
    // The lease's first declared directory holds `hosts.yml` (FILE for the
    // default lease).
    let dir = lease.files.required.first().cloned().unwrap_or_default();
    let file = format!("{dir}/hosts.yml");
    let bundle = Bundle {
        definition_digest: digest_bytes(&lease.definition_digest).unwrap(),
        files: if files {
            vec![
                BundleFile {
                    kind: BundleFileKind::Dir,
                    path: &dir,
                    mode: 0o700,
                    data: b"",
                },
                BundleFile {
                    kind: BundleFileKind::File,
                    path: &file,
                    mode: 0o600,
                    data: FILE_SENTINEL,
                },
            ]
        } else {
            vec![]
        },
        env: vec![BundleEnv {
            name: &lease.env[0],
            value: SENTINEL,
        }],
    };
    encode_bundle(&bundle, &def).unwrap().as_bytes().to_vec()
}

/// A scripted capture answer.
type Ack = (CaptureAckOutcome, Option<CaptureAckReason>);

#[derive(Clone)]
struct Script {
    spec: Vec<u8>,
    /// Lease entries the server grants bundles for (by lease id).
    leases: Vec<SpecLeaseV11>,
    refuse_bundles: bool,
    ack: CaptureAckOutcome,
    ack_reason: Option<CaptureAckReason>,
    /// Per-binding answer overriding `ack`; `None` = never answer (offline).
    binding_acks: Arc<Mutex<BTreeMap<String, Option<Ack>>>>,
    /// Refusal codes answered, in order, to the next restore requests
    /// (`restore_env` / `proxy`) before any is granted.
    restore_refusals: Arc<Mutex<VecDeque<&'static str>>>,
}

impl Script {
    fn new(spec: &CredentialSpecV11) -> Self {
        Self {
            spec: serde_json::json!(spec).to_string().into_bytes(),
            leases: spec.leases.clone(),
            refuse_bundles: false,
            ack: CaptureAckOutcome::Committed,
            ack_reason: None,
            binding_acks: Arc::default(),
            restore_refusals: Arc::default(),
        }
    }
}

/// A scripted control plane: drains the daemon's credential frames in order,
/// logs them, and answers like `credential-handlers.ts` would.
struct FakeServer {
    log: Arc<Mutex<Vec<DaemonControlMessage>>>,
    envelopes: Arc<Mutex<Vec<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl FakeServer {
    fn start(service: &CredentialService, script: Script) -> Self {
        let log = Arc::new(Mutex::new(Vec::new()));
        let envelopes = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (l, e, s, service) = (
            log.clone(),
            envelopes.clone(),
            stop.clone(),
            service.clone(),
        );
        let handle = std::thread::spawn(move || {
            let mut capture: Option<(String, String, u32, Vec<u8>)> = None;
            while !s.load(Ordering::SeqCst) {
                for message in service.drain() {
                    lock(&l).push(message.clone());
                    respond(&service, &script, &e, &mut capture, message);
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        });
        Self {
            log,
            envelopes,
            stop,
            handle: Some(handle),
        }
    }

    fn frames(&self) -> Vec<DaemonControlMessage> {
        lock(&self.log).clone()
    }

    fn kinds(&self) -> Vec<&'static str> {
        self.frames()
            .iter()
            .map(|m| match m {
                DaemonControlMessage::CredentialSpecRequest(_) => "spec.request",
                DaemonControlMessage::CredentialBundleRequest(_) => "bundle.request",
                DaemonControlMessage::CredentialCaptureBegin(_) => "capture.begin",
                DaemonControlMessage::CredentialCaptureChunk(_) => "capture.chunk",
                DaemonControlMessage::CredentialInstalled(_) => "installed",
                DaemonControlMessage::CredentialScrubbed(_) => "scrubbed",
                DaemonControlMessage::CredentialReturnKeyAck(_) => "return.key.ack",
                DaemonControlMessage::CredentialCensus(_) => "census",
                DaemonControlMessage::CredentialQuarantineDiscarded(_) => "quarantine.discarded",
                _ => "other",
            })
            .collect()
    }
}

impl Drop for FakeServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn respond(
    service: &CredentialService,
    script: &Script,
    envelopes: &Mutex<Vec<Vec<u8>>>,
    capture: &mut Option<(String, String, u32, Vec<u8>)>,
    message: DaemonControlMessage,
) {
    match message {
        DaemonControlMessage::CredentialSpecRequest(request) => {
            for (seq, chunk) in script.spec.chunks(CREDENTIAL_CHUNK_RAW_BYTES).enumerate() {
                service.handle_server(ServerControlMessage::CredentialSpecChunk(
                    CredentialSpecChunkV11 {
                        operation_id: request.operation_id.clone(),
                        seq: seq as u32,
                        data: encode_chunk_data(chunk),
                    },
                ));
            }
        }
        DaemonControlMessage::CredentialBundleRequest(request) => {
            if request.reason != BundleRequestReason::Install
                && let Some(code) = lock(&script.restore_refusals).pop_front()
            {
                service.handle_server(ServerControlMessage::CredentialBundleRefused(
                    CredentialBundleRefusedV11 {
                        request_id: request.request_id,
                        code: code.into(),
                    },
                ));
                return;
            }
            let lease = script
                .leases
                .iter()
                .find(|l| l.lease_id == request.lease_id);
            let Some(lease) = lease.filter(|_| !script.refuse_bundles) else {
                service.handle_server(ServerControlMessage::CredentialBundleRefused(
                    CredentialBundleRefusedV11 {
                        request_id: request.request_id,
                        code: "stale".into(),
                    },
                ));
                return;
            };
            let install = request.reason == BundleRequestReason::Install;
            let bytes = bundle_bytes(lease, install);
            let chunks: Vec<&[u8]> = bytes.chunks(CREDENTIAL_CHUNK_RAW_BYTES).collect();
            service.handle_server(ServerControlMessage::CredentialBundleBegin(
                CredentialBundleBeginV11 {
                    request_id: request.request_id.clone(),
                    binding_id: request
                        .binding_id
                        .clone()
                        .unwrap_or_else(|| format!("bind-{}", request.lease_id)),
                    storage_seq: 1,
                    file_count: if install && !lease.files.is_empty() {
                        2
                    } else {
                        0
                    },
                    env_count: 1,
                    bundle_len: bytes.len() as u64,
                    chunk_count: chunks.len() as u32,
                },
            ));
            for (seq, chunk) in chunks.into_iter().enumerate() {
                service.handle_server(ServerControlMessage::CredentialBundleChunk(
                    CredentialBundleChunkV11 {
                        request_id: request.request_id.clone(),
                        seq: seq as u32,
                        data: encode_chunk_data(chunk),
                    },
                ));
            }
        }
        DaemonControlMessage::CredentialCaptureBegin(begin) => {
            *capture = Some((
                begin.capture_id,
                begin.binding_id,
                begin.chunk_count,
                Vec::new(),
            ));
        }
        DaemonControlMessage::CredentialCaptureChunk(chunk) => {
            let Some((id, binding, count, bytes)) = capture.as_mut() else {
                return;
            };
            let mut raw = vec![0u8; sandbox_protocol::chunk_data_len(&chunk.data).unwrap()];
            sandbox_protocol::decode_chunk_data_into(&chunk.data, &mut raw).unwrap();
            bytes.extend_from_slice(&raw);
            if chunk.seq + 1 == *count {
                lock(envelopes).push(std::mem::take(bytes));
                let capture_id = id.clone();
                let answer = lock(&script.binding_acks)
                    .get(binding.as_str())
                    .cloned()
                    .unwrap_or(Some((script.ack, script.ack_reason)));
                *capture = None;
                let Some((outcome, reason)) = answer else {
                    return;
                };
                service.handle_server(ServerControlMessage::CredentialCaptureAck(
                    CredentialCaptureAckV11 {
                        capture_id,
                        outcome,
                        reason,
                    },
                ));
            }
        }
        DaemonControlMessage::CredentialCensus(page) => {
            service.handle_server(ServerControlMessage::CredentialCensusAck(
                CredentialCensusAckV11 { page: page.page },
            ));
        }
        _ => {}
    }
}

fn service(dir: &Path) -> CredentialService {
    let service = CredentialService::start(dir, "host-1").unwrap();
    service.on_registered(OWNER);
    service
}

fn always() -> bool {
    true
}

fn every_file_under(dir: &Path) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for item in std::fs::read_dir(dir).unwrap() {
        let path = item.unwrap().path();
        if path.is_dir() {
            out.extend(every_file_under(&path));
        } else {
            out.push(std::fs::read(path).unwrap());
        }
    }
    out
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn assert_nothing_at_rest(dir: &Path) {
    for bytes in every_file_under(dir) {
        assert!(!contains(&bytes, SENTINEL), "env value at rest");
        assert!(!contains(&bytes, FILE_SENTINEL), "file value at rest");
    }
}

fn assert_frames_redacted(frames: &[DaemonControlMessage]) {
    let text = format!("{frames:?}");
    assert!(!contains(text.as_bytes(), SENTINEL));
    assert!(!contains(text.as_bytes(), FILE_SENTINEL));
}

fn guest_calls(fake: &FakeRuntime) -> Vec<String> {
    fake.credential_calls()
        .into_iter()
        .map(|(op, _)| op)
        .collect()
}

/// End-to-end lane: create with a login → spec fetch → bundle install →
/// `installed` on the wire before READY; then a daemon restart → census →
/// `restore_env` → env back in memory. No plaintext is ever at rest, and no
/// frame's Debug carries a value.
#[test]
fn create_installs_before_ready_and_restart_restores_env() {
    let dir = tempfile::tempdir().unwrap();
    let fake = FakeRuntime::default();
    let s = spec(
        vec![lease("lease-1", SpecLeaseAction::Inject, None)],
        vec![],
    );
    let script = Script::new(&s);
    let bytes = script.spec.clone();

    let daemon = service(dir.path());
    let server = FakeServer::start(&daemon, script.clone());
    // Pre-effect: spec transfer verified (length, digest, parser).
    let fetched = daemon
        .fetch_spec("op-create-1", &reference(&bytes), &always)
        .unwrap();
    assert_eq!(fetched, s);
    assert!(guest_calls(&fake).is_empty(), "spec fetch touches no guest");

    // Post-readiness, before READY.
    let receipt = daemon
        .launch(&fake, &target(&bytes), &fetched, &always)
        .unwrap();
    // `launch` returns only after `installed` was handed to the socket, so
    // the create's READY result follows it on the wire.
    assert_eq!(
        server.kinds(),
        vec!["spec.request", "bundle.request", "installed"]
    );
    let frames = server.frames();
    let DaemonControlMessage::CredentialBundleRequest(request) = &frames[1] else {
        panic!("bundle request expected");
    };
    assert_eq!(request.reason, BundleRequestReason::Install);
    assert_eq!(request.operation_id.as_deref(), Some("op-create-1"));
    assert_eq!(request.binding_id, None);
    let DaemonControlMessage::CredentialInstalled(installed) = &frames[2] else {
        panic!("installed expected");
    };
    assert_eq!(
        (
            installed.binding_id.as_str(),
            installed.storage_seq,
            installed.file_count,
            installed.env_count
        ),
        ("bind-lease-1", 1, 2, 1)
    );
    // The READY receipt repeats the report: a frame handed to a socket that
    // broke is lost, the journaled receipt replays.
    assert_eq!(receipt, vec![installed.clone()]);
    assert_eq!(
        fake.guest_file(SANDBOX, FILE).as_deref(),
        Some(FILE_SENTINEL)
    );
    assert_eq!(
        daemon.env_for(SANDBOX, Duration::ZERO).unwrap(),
        vec![(
            "TOOL_TOKEN".to_owned(),
            String::from_utf8(SENTINEL.to_vec()).unwrap()
        )]
    );
    {
        let journal = daemon.store().journal();
        let binding = journal.binding("bind-lease-1").unwrap();
        assert_eq!(binding.phase, BindingPhase::Active);
        assert_eq!(binding.installed_seq, Some(1));
        assert!(binding.install_intent.is_some());
        assert_eq!(binding.spec.as_ref().unwrap().lease_id, "lease-1");
    }
    assert_frames_redacted(&frames);
    assert_nothing_at_rest(dir.path());
    drop(server);
    drop(daemon);

    // Daemon restart: env is memory-only, so it is pending until restored.
    let daemon = service(dir.path());
    assert_eq!(
        daemon.env_for(SANDBOX, Duration::from_millis(20)),
        Err(EnvPending)
    );
    let server = FakeServer::start(&daemon, script);
    daemon.begin_census();
    // `command.run` waits ≤ 10 s for the restore that follows the census.
    let env = daemon.env_for(SANDBOX, ENV_WAIT).unwrap();
    assert_eq!(env.len(), 1);
    assert_eq!(env[0].1.as_bytes(), SENTINEL);
    let frames = server.frames();
    assert_eq!(server.kinds()[..2], ["census", "bundle.request"]);
    let DaemonControlMessage::CredentialCensus(census) = &frames[0] else {
        panic!("census expected");
    };
    assert!(census.complete);
    assert_eq!(census.entries[0].binding_id, "bind-lease-1");
    let DaemonControlMessage::CredentialBundleRequest(restore) = &frames[1] else {
        panic!("restore request expected");
    };
    assert_eq!(restore.reason, BundleRequestReason::RestoreEnv);
    assert_eq!(restore.binding_id.as_deref(), Some("bind-lease-1"));
    assert_eq!(restore.operation_id, None);
    // A restore never rewrites guest files: only the create's restore ran.
    assert_eq!(
        guest_calls(&fake)
            .iter()
            .filter(|op| *op == "restore")
            .count(),
        1
    );
    assert_frames_redacted(&frames);
    assert_nothing_at_rest(dir.path());
}

/// Installs one lease, then restarts the daemon over the same state dir
/// with `refusals` scripted for the restore requests that follow the census.
fn restart_with_restore_refusals(
    dir: &Path,
    refusals: &[&'static str],
) -> (CredentialService, FakeServer) {
    let fake = FakeRuntime::default();
    let s = spec(
        vec![lease("lease-1", SpecLeaseAction::Inject, None)],
        vec![],
    );
    let script = Script::new(&s);
    let bytes = script.spec.clone();
    {
        let daemon = service(dir);
        let _server = FakeServer::start(&daemon, script.clone());
        daemon.launch(&fake, &target(&bytes), &s, &always).unwrap();
    }
    lock(&script.restore_refusals).extend(refusals.iter().copied());
    let daemon = service(dir);
    let server = FakeServer::start(&daemon, script);
    daemon.begin_census();
    (daemon, server)
}

fn restore_requests(server: &FakeServer) -> usize {
    server
        .frames()
        .iter()
        .filter(|m| {
            matches!(m, DaemonControlMessage::CredentialBundleRequest(r)
                if r.reason == BundleRequestReason::RestoreEnv)
        })
        .count()
}

/// Transient refusals (`busy`, vault `unavailable`, `internal`)
/// keep the env pending and are retried with backoff until the restore
/// succeeds; the env is never silently dropped.
#[test]
fn final_3_transient_restore_refusals_stay_pending_and_retry() {
    let dir = tempfile::tempdir().unwrap();
    let (daemon, server) =
        restart_with_restore_refusals(dir.path(), &["busy", "unavailable", "internal"]);
    let env = daemon.env_for(SANDBOX, ENV_WAIT).unwrap();
    assert_eq!(env.len(), 1, "restored after the transient refusals");
    assert_eq!(env[0].1.as_bytes(), SENTINEL);
    assert_eq!(restore_requests(&server), 4);
    assert_nothing_at_rest(dir.path());
}

/// An authoritative refusal settles the restore without env at
/// once, with no retry.
#[test]
fn final_3_authoritative_restore_refusal_settles_without_env() {
    let dir = tempfile::tempdir().unwrap();
    let (daemon, server) = restart_with_restore_refusals(dir.path(), &["stale"]);
    assert!(daemon.env_for(SANDBOX, ENV_WAIT).unwrap().is_empty());
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(restore_requests(&server), 1);
}

#[test]
fn refused_bundle_fails_the_install_and_reports_nothing_installed() {
    let dir = tempfile::tempdir().unwrap();
    let fake = FakeRuntime::default();
    let s = spec(
        vec![lease("lease-1", SpecLeaseAction::Inject, None)],
        vec![],
    );
    let mut script = Script::new(&s);
    script.refuse_bundles = true;
    let bytes = script.spec.clone();
    let daemon = service(dir.path());
    let _server = FakeServer::start(&daemon, script);
    assert_eq!(
        daemon.launch(&fake, &target(&bytes), &s, &always),
        Err(LaunchFailure::Install)
    );
    assert!(guest_calls(&fake).is_empty());
    assert!(daemon.env_for(SANDBOX, Duration::ZERO).unwrap().is_empty());
    assert!(daemon.store().journal().state().bindings.is_empty());
}

#[test]
fn restore_error_fails_the_install_without_reporting_it() {
    let dir = tempfile::tempdir().unwrap();
    let fake = FakeRuntime::default();
    fake.fail_credential_op("restore", 1);
    let s = spec(
        vec![lease("lease-1", SpecLeaseAction::Inject, None)],
        vec![],
    );
    let script = Script::new(&s);
    let bytes = script.spec.clone();
    let daemon = service(dir.path());
    let server = FakeServer::start(&daemon, script);
    assert_eq!(
        daemon.launch(&fake, &target(&bytes), &s, &always),
        Err(LaunchFailure::Install)
    );
    assert!(!server.kinds().contains(&"installed"));
    // The intent was durable before the guest write: the disk may hold the
    // binding's files, and the server's residue row covers it.
    let journal = daemon.store().journal();
    let binding = journal.binding("bind-lease-1").unwrap();
    assert!(binding.install_intent.is_some());
    assert_eq!(binding.installed_seq, None);
    drop(journal);
    assert!(daemon.env_for(SANDBOX, Duration::ZERO).unwrap().is_empty());
}

#[test]
fn spec_mismatch_or_short_stream_fails_before_any_guest_effect() {
    let dir = tempfile::tempdir().unwrap();
    let s = spec(
        vec![lease("lease-1", SpecLeaseAction::Inject, None)],
        vec![],
    );
    let script = Script::new(&s);
    let bytes = script.spec.clone();
    let daemon = service(dir.path());
    let _server = FakeServer::start(&daemon, script);
    let mut wrong = reference(&bytes);
    wrong.digest = "0".repeat(64);
    assert_eq!(
        daemon.fetch_spec("op-1", &wrong, &always),
        Err(LaunchFailure::SpecInvalid)
    );
    let mut long = reference(&bytes);
    long.bytes += 1;
    // The stream ends one byte short of the reference: refused, not truncated.
    let started = Instant::now();
    let cancel_after = move || started.elapsed() < Duration::from_millis(300);
    assert!(daemon.fetch_spec("op-2", &long, &cancel_after).is_err());
    // A spec naming another sandbox or host owner is refused at launch.
    let fake = FakeRuntime::default();
    let mut other = s.clone();
    other.host_owner_id = "someone-else".into();
    assert_eq!(
        daemon.launch(&fake, &target(&bytes), &other, &always),
        Err(LaunchFailure::SpecInvalid)
    );
    assert!(guest_calls(&fake).is_empty());
}

/// Residue of a closed binding is scrubbed and verified before any
/// injection: the `scrubbed{verifiedAbsent}` frame precedes the bundle
/// request, and the guest scrub precedes the restore.
#[test]
fn residue_scrub_precedes_any_injection() {
    let dir = tempfile::tempdir().unwrap();
    let fake = FakeRuntime::default();
    fake.set_guest_file(SANDBOX, FILE, b"token: old-instance-A");
    let s = spec(
        vec![lease("lease-b", SpecLeaseAction::Inject, None)],
        vec![residue(
            "res-a",
            "bind-a",
            "lease-a",
            SpecResidueAction::Scrub,
        )],
    );
    let script = Script::new(&s);
    let bytes = script.spec.clone();
    let daemon = service(dir.path());
    let server = FakeServer::start(&daemon, script);
    daemon.launch(&fake, &target(&bytes), &s, &always).unwrap();
    assert_eq!(
        server.kinds(),
        vec!["scrubbed", "bundle.request", "installed"]
    );
    let DaemonControlMessage::CredentialScrubbed(scrubbed) = &server.frames()[0] else {
        panic!("scrubbed expected");
    };
    assert_eq!(scrubbed.binding_ids, vec!["bind-a".to_owned()]);
    assert!(scrubbed.verified_absent);
    assert_eq!(guest_calls(&fake), vec!["scrub", "restore"]);
    // Instance B's value replaced A's residue.
    assert_eq!(
        fake.guest_file(SANDBOX, FILE).as_deref(),
        Some(FILE_SENTINEL)
    );
}

#[test]
fn scrub_failure_never_starts_injection() {
    let dir = tempfile::tempdir().unwrap();
    let fake = FakeRuntime::default();
    fake.set_guest_file(SANDBOX, FILE, b"token: old-instance-A");
    fake.fail_credential_op("scrub", 1);
    let s = spec(
        vec![lease("lease-b", SpecLeaseAction::Inject, None)],
        vec![residue(
            "res-a",
            "bind-a",
            "lease-a",
            SpecResidueAction::Scrub,
        )],
    );
    let script = Script::new(&s);
    let bytes = script.spec.clone();
    let daemon = service(dir.path());
    let server = FakeServer::start(&daemon, script);
    assert_eq!(
        daemon.launch(&fake, &target(&bytes), &s, &always),
        Err(LaunchFailure::Scrub)
    );
    assert!(!server.kinds().contains(&"bundle.request"));
    assert!(!guest_calls(&fake).contains(&"restore".to_owned()));
}

fn recovery_spec() -> CredentialSpecV11 {
    spec(
        vec![lease("lease-1", SpecLeaseAction::Recover, Some("rbind-1"))],
        vec![residue(
            "res-1",
            "bind-old",
            "lease-1",
            SpecResidueAction::Recover,
        )],
    )
}

fn keyed_service(dir: &Path, key: &Key) -> CredentialService {
    let daemon = service(dir);
    let ack = daemon.store().install_return_key(&key.frame()).unwrap();
    assert_eq!(ack.refused, None);
    daemon
}

/// RECOVERING → INSTALLING: the dirty disk's files are packed under the
/// RECOVER binding (kind `recovery`, residue id in the AAD), uploaded, and
/// only after the outcome scrubbed; then the lease is re-injected.
#[test]
fn recovery_recaptures_then_scrubs_then_reinjects() {
    let dir = tempfile::tempdir().unwrap();
    let key = Key::new(9);
    let fake = FakeRuntime::default();
    fake.set_guest_file(SANDBOX, FILE, b"token: rotated-on-the-dirty-disk");
    let s = recovery_spec();
    let script = Script::new(&s);
    let bytes = script.spec.clone();
    let daemon = keyed_service(dir.path(), &key);
    let server = FakeServer::start(&daemon, script);
    daemon.launch(&fake, &target(&bytes), &s, &always).unwrap();

    let kinds = server.kinds();
    let begin = kinds.iter().position(|k| *k == "capture.begin").unwrap();
    let scrubbed = kinds.iter().position(|k| *k == "scrubbed").unwrap();
    let request = kinds.iter().position(|k| *k == "bundle.request").unwrap();
    assert!(begin < scrubbed && scrubbed < request);
    assert_eq!(kinds.last(), Some(&"installed"));
    assert_eq!(guest_calls(&fake), vec!["pack", "scrub", "restore"]);
    let frames = server.frames();
    let DaemonControlMessage::CredentialCaptureBegin(capture) = &frames[begin] else {
        panic!("capture begin expected");
    };
    assert_eq!(capture.kind, CaptureKind::Recovery);
    assert_eq!(capture.binding_id, "rbind-1");
    let DaemonControlMessage::CredentialScrubbed(s1) = &frames[scrubbed] else {
        panic!("scrubbed expected");
    };
    // The residue's own (superseded) binding is the one cleared.
    assert_eq!(s1.binding_ids, vec!["bind-old".to_owned()]);
    // The envelope opens to the rotated bytes, bound to the residue row.
    let envelope = lock(&server.envelopes)[0].clone();
    let parsed = crate::sandbox_relay::credentials::envelope::parse(envelope).unwrap();
    assert_eq!(parsed.header.aad.residue_id, "res-1");
    assert_eq!(parsed.header.aad.kind, "recovery");
    let opened = testing::open(&key.private, &key.public, parsed.seal(), &parsed.header.aad)
        .unwrap()
        .expose()
        .to_vec();
    assert!(contains(&opened, b"rotated-on-the-dirty-disk"));
    // The resolved envelope left the outbox; the RECOVER binding is closed.
    assert_eq!(daemon.store().outbox().pending().count(), 0);
    let journal = daemon.store().journal();
    assert!(journal.binding("rbind-1").is_none());
    assert_eq!(
        journal.binding("bind-lease-1").unwrap().phase,
        BindingPhase::Active
    );
    drop(journal);
    assert_eq!(
        fake.guest_file(SANDBOX, FILE).as_deref(),
        Some(FILE_SENTINEL)
    );
    assert_frames_redacted(&frames);
    assert_nothing_at_rest(dir.path());
}

/// Recovery failure (REJECTED): no scrub, no injection; the residue stays
/// on the disk for the next start (the caller stops the VM).
#[test]
fn rejected_recovery_never_scrubs() {
    let dir = tempfile::tempdir().unwrap();
    let key = Key::new(9);
    let fake = FakeRuntime::default();
    fake.set_guest_file(SANDBOX, FILE, b"token: rotated-on-the-dirty-disk");
    let s = recovery_spec();
    let mut script = Script::new(&s);
    script.ack = CaptureAckOutcome::Rejected;
    script.ack_reason = Some(CaptureAckReason::BindingClosed);
    let bytes = script.spec.clone();
    let daemon = keyed_service(dir.path(), &key);
    let server = FakeServer::start(&daemon, script);
    assert_eq!(
        daemon.launch(&fake, &target(&bytes), &s, &always),
        Err(LaunchFailure::Recovery)
    );
    assert_eq!(guest_calls(&fake), vec!["pack"]);
    assert!(!server.kinds().contains(&"scrubbed"));
    assert!(!server.kinds().contains(&"bundle.request"));
    assert!(fake.guest_file(SANDBOX, FILE).is_some());
    // The REJECTED envelope is quarantined, never pending.
    assert_eq!(daemon.store().outbox().quarantined().count(), 1);
}

/// Recovery without a return key (or a pack error) fails before any scrub.
#[test]
fn recovery_without_a_return_key_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let fake = FakeRuntime::default();
    fake.set_guest_file(SANDBOX, FILE, b"token: rotated-on-the-dirty-disk");
    let s = recovery_spec();
    let script = Script::new(&s);
    let bytes = script.spec.clone();
    let daemon = service(dir.path());
    let server = FakeServer::start(&daemon, script);
    assert_eq!(
        daemon.launch(&fake, &target(&bytes), &s, &always),
        Err(LaunchFailure::Recovery)
    );
    assert!(server.frames().is_empty());
    assert!(fake.guest_file(SANDBOX, FILE).is_some());
}

/// Install failure after a committed recovery: the value is preserved
/// server-side; the residue was already scrubbed and reported.
#[test]
fn install_failure_after_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let key = Key::new(9);
    let fake = FakeRuntime::default();
    fake.set_guest_file(SANDBOX, FILE, b"token: rotated-on-the-dirty-disk");
    let s = recovery_spec();
    let mut script = Script::new(&s);
    script.refuse_bundles = true;
    let bytes = script.spec.clone();
    let daemon = keyed_service(dir.path(), &key);
    let server = FakeServer::start(&daemon, script);
    assert_eq!(
        daemon.launch(&fake, &target(&bytes), &s, &always),
        Err(LaunchFailure::Install)
    );
    let kinds = server.kinds();
    assert!(kinds.contains(&"scrubbed"));
    assert!(kinds.contains(&"bundle.request"));
    assert!(!kinds.contains(&"installed"));
    assert_eq!(guest_calls(&fake), vec!["pack", "scrub"]);
}

#[test]
fn cancellation_abandons_the_bundle_wait() {
    let dir = tempfile::tempdir().unwrap();
    let fake = FakeRuntime::default();
    let s = spec(
        vec![lease("lease-1", SpecLeaseAction::Inject, None)],
        vec![],
    );
    let bytes = serde_json::json!(&s).to_string().into_bytes();
    let daemon = service(dir.path());
    // No server answers: a revoked/cancelled create stops waiting at once.
    let started = Instant::now();
    let wanted = move || started.elapsed() < Duration::from_millis(200);
    assert_eq!(
        daemon.launch(&fake, &target(&bytes), &s, &wanted),
        Err(LaunchFailure::Cancelled)
    );
    assert!(started.elapsed() < BUNDLE_WAIT);
}

#[test]
fn revoke_drops_the_lease_env() {
    let dir = tempfile::tempdir().unwrap();
    let fake = FakeRuntime::default();
    let s = spec(
        vec![lease("lease-1", SpecLeaseAction::Inject, None)],
        vec![],
    );
    let script = Script::new(&s);
    let bytes = script.spec.clone();
    let daemon = service(dir.path());
    let _server = FakeServer::start(&daemon, script);
    daemon.launch(&fake, &target(&bytes), &s, &always).unwrap();
    assert_eq!(daemon.env_for(SANDBOX, Duration::ZERO).unwrap().len(), 1);
    daemon.handle_server(ServerControlMessage::CredentialRevoke(
        sandbox_protocol::CredentialRevokeV11 {
            lease_id: "lease-1".into(),
            reason: "freed".into(),
        },
    ));
    assert!(daemon.env_for(SANDBOX, Duration::ZERO).unwrap().is_empty());
}

/// Proxy mode lane: create with a proxied login → the value goes to the
/// host proxy, the guest env holds only the base URL and the placeholder; a
/// guest request through the base URL reaches the upstream with the header;
/// a daemon restart keeps the journaled handle (503 until the `proxy`
/// restore, then 200 at the same URL); revoke → 403; nothing at rest.
#[test]
fn proxied_login_keeps_the_value_on_the_host() {
    use crate::sandbox_relay::credentials::proxy::testing::{
        Mode, PlainConnector, TestUpstream, contains as has, exchange, settings,
    };
    let dir = tempfile::tempdir().unwrap();
    let fake = FakeRuntime::default();
    let mut entry = lease("lease-1", SpecLeaseAction::Inject, None);
    entry.delivery = CredentialDelivery::Proxy;
    entry.copy_back = false;
    entry.files = SpecFilesV11::default();
    entry.proxy = vec![sandbox_protocol::SpecProxyV11 {
        name: "TOOL_TOKEN".into(),
        upstream: "https://api.example.test/v1".into(),
        header: "Authorization".into(),
        format: "Bearer {value}".into(),
        base_url_env: "TOOL_BASE_URL".into(),
        placeholder_env: Some("TOOL_TOKEN".into()),
    }];
    let s = spec(vec![entry], vec![]);
    let script = Script::new(&s);
    let bytes = script.spec.clone();
    let upstream = TestUpstream::start(Mode::Fixed);
    let connector = Arc::new(PlainConnector::default());
    connector.route("api.example.test", upstream.addr);

    let daemon = service(dir.path());
    // Without the proxy the capability is off and a proxied install fails.
    assert!(!daemon.capabilities().proxy);
    daemon.enable_proxy(settings(connector.clone()));
    assert!(daemon.capabilities().proxy);
    let server = FakeServer::start(&daemon, script.clone());
    daemon.launch(&fake, &target(&bytes), &s, &always).unwrap();
    assert_eq!(server.kinds(), vec!["bundle.request", "installed"]);
    assert!(
        guest_calls(&fake).is_empty(),
        "nothing written to the guest"
    );

    let env = daemon.env_for(SANDBOX, Duration::ZERO).unwrap();
    assert_eq!(env.len(), 2);
    for (_, value) in &env {
        assert!(
            !has(value.as_bytes(), SENTINEL),
            "the value reached the guest env"
        );
    }
    let base = env
        .iter()
        .find(|(name, _)| name == "TOOL_BASE_URL")
        .map(|(_, v)| v.clone())
        .unwrap();
    assert!(env.contains(&("TOOL_TOKEN".into(), "wssp-credential-proxy".into())));
    let hub = daemon.proxy_hub().unwrap();
    let addr = hub.listen_addr(SANDBOX).unwrap();
    let path = base
        .strip_prefix(&format!("http://{addr}"))
        .unwrap()
        .to_owned();
    let get = format!("GET {path}/models HTTP/1.1\r\nHost: gw\r\n\r\n").into_bytes();
    let (code, guest) = exchange(addr, &get);
    assert_eq!(code, 200);
    assert!(!has(&guest, SENTINEL));
    let mut expected = b"Authorization: Bearer ".to_vec();
    expected.extend_from_slice(SENTINEL);
    assert!(has(&upstream.received(), &expected));
    assert!(has(
        &upstream.received(),
        b"GET /v1/models HTTP/1.1\r\nHost: api.example.test\r\n"
    ));
    assert_frames_redacted(&server.frames());
    assert_nothing_at_rest(dir.path());
    drop(server);
    drop(hub);
    drop(daemon);

    // Daemon restart: the journaled handle answers 503 until the restore.
    let daemon = service(dir.path());
    daemon.enable_proxy(settings(connector));
    let addr = daemon.proxy_hub().unwrap().listen_addr(SANDBOX).unwrap();
    let get = format!("GET {path}/models HTTP/1.1\r\nHost: gw\r\n\r\n").into_bytes();
    assert_eq!(exchange(addr, &get).0, 503);
    let server = FakeServer::start(&daemon, script);
    daemon.begin_census();
    let env = daemon.env_for(SANDBOX, ENV_WAIT).unwrap();
    assert_eq!(
        env.iter()
            .find(|(n, _)| n == "TOOL_BASE_URL")
            .map(|(_, v)| v.clone()),
        Some(format!("http://{addr}{path}"))
    );
    let restore = server
        .frames()
        .into_iter()
        .find_map(|f| match f {
            DaemonControlMessage::CredentialBundleRequest(r) => Some(r),
            _ => None,
        })
        .unwrap();
    assert_eq!(restore.reason, BundleRequestReason::Proxy);
    assert_eq!(exchange(addr, &get).0, 200);

    // Revoke (the last proxy login freed): 403, and the listener stays for
    // the sandbox's life, never connection refused.
    daemon.handle_server(ServerControlMessage::CredentialRevoke(
        sandbox_protocol::CredentialRevokeV11 {
            lease_id: "lease-1".into(),
            reason: "freed".into(),
        },
    ));
    assert!(daemon.env_for(SANDBOX, Duration::ZERO).unwrap().is_empty());
    assert_eq!(daemon.proxy_hub().unwrap().handle_count(SANDBOX), 0);
    assert_eq!(daemon.proxy_hub().unwrap().listen_addr(SANDBOX), Some(addr));
    assert_eq!(exchange(addr, &get).0, 403);
    assert_frames_redacted(&server.frames());
    assert_nothing_at_rest(dir.path());
}

/// Teardown (stop, kill, expiry) drops the sandbox's proxy at once.
#[test]
fn forgetting_a_sandbox_stops_its_proxy() {
    use crate::sandbox_relay::credentials::proxy::testing::{PlainConnector, settings};
    let dir = tempfile::tempdir().unwrap();
    let daemon = service(dir.path());
    daemon.enable_proxy(settings(Arc::new(PlainConnector::default())));
    let mut entry = lease("lease-1", SpecLeaseAction::Inject, None);
    entry.delivery = CredentialDelivery::Proxy;
    entry.copy_back = false;
    entry.files = SpecFilesV11::default();
    entry.proxy = vec![sandbox_protocol::SpecProxyV11 {
        name: "TOOL_TOKEN".into(),
        upstream: "https://api.example.test".into(),
        header: "X-Api-Key".into(),
        format: "{value}".into(),
        base_url_env: "TOOL_BASE_URL".into(),
        placeholder_env: None,
    }];
    let hub = daemon.proxy_hub().unwrap();
    let handles = crate::sandbox_relay::credentials::proxy::new_handles(1).unwrap();
    let values = vec![(
        "TOOL_TOKEN".to_owned(),
        crate::sandbox_relay::credentials::SecretBytes::copy_from(SENTINEL),
    )];
    hub.install(SANDBOX, &entry, "bind-1", &handles, Some(&values))
        .unwrap();
    assert_eq!(hub.handle_count(SANDBOX), 1);
    daemon.forget_sandbox_env(SANDBOX);
    assert_eq!(hub.handle_count(SANDBOX), 0);
    assert!(hub.listen_addr(SANDBOX).is_none());
}

#[path = "teardown_tests.rs"]
mod teardown;

#[path = "live_tests.rs"]
mod live;

#[path = "checkpoint_tests.rs"]
mod checkpoint;

#[test]
fn capabilities_advertise_files_env_checkpoints_and_the_slot_epoch() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = service(dir.path());
    let caps = daemon.capabilities();
    assert!(caps.is_valid());
    assert!(caps.files && caps.env && caps.sealed_return && caps.spec_transfer);
    assert!(caps.checkpoint && !caps.proxy);
    assert_eq!(caps.return_key_epoch, 0);
    let key = Key::new(3);
    let _server = FakeServer::start(&daemon, Script::new(&spec(vec![], vec![])));
    daemon.handle_server(ServerControlMessage::CredentialReturnKey(key.frame()));
    assert_eq!(daemon.capabilities().return_key_epoch, 1);
}

/// A template capture is refused while login files are in
/// motion on this host (an open teardown attempt, a binding installing or
/// tearing down, a held guest slot), and its login scrub list is the
/// capture spec's residue paths unioned with every path the journal records
/// for a binding of the sandbox.
#[test]
fn template_capture_is_refused_while_logins_move_and_scrubs_spec_and_journal_paths() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = service(dir.path());
    assert!(!daemon.capture_refused(SANDBOX));

    let mut entry = lease("lease-1", SpecLeaseAction::Inject, None);
    entry.files.optional = vec![".netrc".into()];
    daemon
        .store()
        .journal()
        .record_binding(BindingRecord {
            binding_id: "bind-1".into(),
            lease_id: "lease-1".into(),
            sandbox_id: SANDBOX.into(),
            credential_id: "cred-lease-1".into(),
            instance_id: "inst-1".into(),
            spec_digest: "a".repeat(64),
            copy_back: true,
            exclusive: true,
            purpose: BindingPurpose::Install,
            install_intent: None,
            installed_seq: None,
            phase: BindingPhase::Installing,
            teardown: None,
            scrubbed_verified: false,
            spec: Some(entry),
            proxy_handles: Vec::new(),
        })
        .unwrap();
    // Installing: the files are being written.
    assert!(daemon.capture_refused(SANDBOX));
    assert!(!daemon.capture_refused("sbx-other"));
    daemon
        .store()
        .journal()
        .set_phase("bind-1", BindingPhase::Active)
        .unwrap();
    assert!(!daemon.capture_refused(SANDBOX));

    // An open teardown attempt (a stop's capture in flight).
    daemon
        .store()
        .journal()
        .open_or_join_teardown(SANDBOX, "op-stop")
        .unwrap();
    assert!(daemon.capture_refused(SANDBOX));
    daemon
        .store()
        .journal()
        .settle_teardown(SANDBOX, false)
        .unwrap();
    assert!(!daemon.capture_refused(SANDBOX));

    // Any holder of the guest slot (install, checkpoint, teardown).
    let coord = daemon.slot(SANDBOX);
    let permit = Arc::new(sandbox_runtime::RuntimePermit::with_timeout(
        Duration::from_secs(5),
    ));
    let guard = coord
        .slot
        .try_acquire(SlotUser::Checkpoint, &permit)
        .unwrap();
    assert!(daemon.capture_refused(SANDBOX));
    drop(guard);
    assert!(!daemon.capture_refused(SANDBOX));

    // Spec residue ∪ journal binding paths, deduplicated, never filtered here.
    let mut stale = residue("res-0", "bind-0", "lease-0", SpecResidueAction::Scrub);
    stale.paths = vec![".config/tool".into(), ".aws/credentials".into()];
    let capture_spec = spec(vec![], vec![stale]);
    assert_eq!(
        daemon.capture_scrub_paths(SANDBOX, Some(&capture_spec)),
        [".aws/credentials", ".config/tool", ".netrc"]
    );
    assert_eq!(
        daemon.capture_scrub_paths(SANDBOX, None),
        [".config/tool", ".netrc"]
    );
    assert!(daemon.capture_scrub_paths("sbx-other", None).is_empty());
}

#[test]
fn duplicate_waiters_receive_the_same_ack_and_drop_only_their_registration() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = service(dir.path());
    let first = daemon.wait_for("ack:cap-1".into());
    let second = daemon.wait_for("ack:cap-1".into());
    drop(first);
    let third = daemon.wait_for("ack:cap-1".into());
    let ack = CredentialCaptureAckV11 {
        capture_id: "cap-1".into(),
        outcome: CaptureAckOutcome::Deferred,
        reason: None,
    };
    daemon.deliver(
        "ack:cap-1",
        ServerControlMessage::CredentialCaptureAck(ack.clone()),
    );
    for waiter in [&second, &third] {
        assert!(matches!(
            waiter.next(Instant::now() + Duration::from_secs(1), &always),
            Ok(ServerControlMessage::CredentialCaptureAck(received)) if received == ack
        ));
    }
    drop(second);
    assert_eq!(lock(&daemon.inner.waiters)["ack:cap-1"].len(), 1);
    drop(third);
    assert!(lock(&daemon.inner.waiters).is_empty());
}

#[test]
fn concurrent_capture_uploads_keep_streams_together_and_notify_duplicate_uploaders() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = keyed_service(dir.path(), &Key::new(19));
    let make_entry = |id: &str| {
        daemon
            .store()
            .seal_capture_with(
                &CaptureContext {
                    host_owner_id: OWNER.into(),
                    host_id: "host-1".into(),
                    sandbox_owner_id: OWNER.into(),
                    sandbox_id: SANDBOX.into(),
                    lease_id: format!("lease-{id}"),
                    binding_id: format!("bind-{id}"),
                    instance_id: "inst-1".into(),
                    credential_id: format!("cred-{id}"),
                    capture_id: id.into(),
                    kind: CaptureKind::Stop,
                    residue_id: String::new(),
                },
                now_ms(),
                || {
                    Ok(super::super::SecretBytes::copy_from(&vec![
                        42;
                        CREDENTIAL_CHUNK_RAW_BYTES
                            * 20
                    ]))
                },
            )
            .unwrap()
    };
    let first = make_entry("cap-1");
    let second = make_entry("cap-2");
    let barrier = Arc::new(std::sync::Barrier::new(4));
    // Holding the queue lets all uploaders register before publication starts.
    let queued = lock(&daemon.inner.frames);
    let workers: Vec<_> = [first.clone(), first, second]
        .into_iter()
        .map(|entry| {
            let daemon = daemon.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                daemon.upload_within(&entry, Duration::from_secs(5), &always)
            })
        })
        .collect();
    barrier.wait();
    wait_until(|| {
        lock(&daemon.inner.waiters)
            .values()
            .map(HashMap::len)
            .sum::<usize>()
            == 3
    });
    drop(queued);
    let mut current: Option<(String, u32, u32)> = None;
    let mut completed = 0;
    let mut capture_ids = BTreeSet::new();
    let deadline = Instant::now() + Duration::from_secs(3);
    while completed < 3 && Instant::now() < deadline {
        for frame in daemon.drain() {
            match frame {
                DaemonControlMessage::CredentialCaptureBegin(begin) => {
                    assert!(current.is_none(), "capture streams interleaved");
                    capture_ids.insert(begin.capture_id.clone());
                    current = Some((begin.capture_id, begin.chunk_count, 0));
                }
                DaemonControlMessage::CredentialCaptureChunk(chunk) => {
                    let (id, count, seq) = current.as_mut().expect("begin before chunks");
                    assert_eq!(chunk.capture_id, *id);
                    assert_eq!(chunk.seq, *seq);
                    *seq += 1;
                    if seq == count {
                        completed += 1;
                        current = None;
                    }
                }
                _ => {}
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(completed, 3);
    // Exactly one server ack per capture must wake every duplicate uploader.
    for capture_id in capture_ids {
        daemon.handle_server(ServerControlMessage::CredentialCaptureAck(
            CredentialCaptureAckV11 {
                capture_id,
                outcome: CaptureAckOutcome::Deferred,
                reason: None,
            },
        ));
    }
    for worker in workers {
        assert!(
            matches!(worker.join().unwrap(), Ok(Some(ack)) if ack.outcome == CaptureAckOutcome::Deferred)
        );
    }
    assert!(lock(&daemon.inner.waiters).is_empty());
}

fn wait_until(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !condition() {
        assert!(Instant::now() < deadline, "condition did not become true");
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn pending_restore(dir: &Path) -> (CredentialService, Script) {
    let s = spec(
        vec![lease("lease-1", SpecLeaseAction::Inject, None)],
        vec![],
    );
    let script = Script::new(&s);
    let daemon = service(dir);
    daemon
        .record(
            &target(&script.spec),
            &s.leases[0],
            "bind-lease-1",
            BindingPurpose::Install,
        )
        .unwrap();
    daemon
        .store()
        .journal()
        .set_phase("bind-lease-1", BindingPhase::Active)
        .unwrap();
    drop(daemon);
    (service(dir), script)
}

fn acknowledge_census(daemon: &CredentialService) {
    let mut complete = false;
    for frame in daemon.drain() {
        if let DaemonControlMessage::CredentialCensus(page) = frame {
            complete |= page.complete;
            daemon.handle_server(ServerControlMessage::CredentialCensusAck(
                CredentialCensusAckV11 { page: page.page },
            ));
        }
    }
    assert!(complete);
}

fn next_restore_request(daemon: &CredentialService) -> CredentialBundleRequestV11 {
    let mut request = None;
    wait_until(|| {
        for frame in daemon.drain() {
            if let DaemonControlMessage::CredentialBundleRequest(found) = frame {
                request = Some(found);
            }
        }
        request.is_some()
    });
    request.unwrap()
}

#[test]
fn disconnect_cancels_detached_restore_wait_and_next_census_restarts_it() {
    let dir = tempfile::tempdir().unwrap();
    let (daemon, script) = pending_restore(dir.path());
    daemon.begin_census();
    acknowledge_census(&daemon);
    next_restore_request(&daemon); // Server stays silent: worker is in a bundle wait.
    daemon.on_disconnect();
    wait_until(|| !lock(&daemon.inner.restore_work).running);
    assert!(lock(&daemon.inner.waiters).is_empty());
    assert!(
        daemon.drain().is_empty(),
        "disconnected worker queued another request"
    );
    assert!(daemon.env_for(SANDBOX, Duration::ZERO).is_err());
    let _server = FakeServer::start(&daemon, script);
    daemon.begin_census();
    assert_eq!(
        daemon
            .env_for(SANDBOX, Duration::from_secs(3))
            .unwrap()
            .len(),
        1
    );
    wait_until(|| !lock(&daemon.inner.restore_work).running);
}

#[test]
fn new_census_kicks_a_cancelled_restore_that_has_not_finished_exiting() {
    let dir = tempfile::tempdir().unwrap();
    let (daemon, script) = pending_restore(dir.path());
    daemon.begin_census();
    acknowledge_census(&daemon);
    next_restore_request(&daemon);
    // The old waiter cannot finish dropping until this lock is released.
    let registrations = lock(&daemon.inner.waiters);
    daemon.begin_census();
    acknowledge_census(&daemon);
    let epoch = daemon.inner.session_epoch.load(Ordering::SeqCst);
    wait_until(|| lock(&daemon.inner.restore_work).kick == Some(epoch));
    drop(registrations);
    let _server = FakeServer::start(&daemon, script);
    assert_eq!(
        daemon
            .env_for(SANDBOX, Duration::from_secs(3))
            .unwrap()
            .len(),
        1
    );
    wait_until(|| !lock(&daemon.inner.restore_work).running);
    assert!(lock(&daemon.inner.waiters).is_empty());
}

#[test]
fn disconnect_cancels_transient_restore_retry_backoff() {
    let dir = tempfile::tempdir().unwrap();
    let (daemon, _) = pending_restore(dir.path());
    daemon.begin_census();
    acknowledge_census(&daemon);
    let request = next_restore_request(&daemon);
    // Hold kick bookkeeping until the waiter is gone, to stop the worker
    // before it can leave the transient-refusal backoff.
    let work = lock(&daemon.inner.restore_work);
    daemon.handle_server(ServerControlMessage::CredentialBundleRefused(
        CredentialBundleRefusedV11 {
            request_id: request.request_id,
            code: "busy".into(),
        },
    ));
    wait_until(|| lock(&daemon.inner.waiters).is_empty());
    daemon.on_disconnect();
    drop(work);
    wait_until(|| !lock(&daemon.inner.restore_work).running);
    assert!(daemon.drain().is_empty());
    assert!(daemon.env_for(SANDBOX, Duration::ZERO).is_err());
}

/// How the scripted relay connection breaks: the first `times` requests of
/// `kind` are each handed to the socket and lost with it (optionally after a
/// partial answer: a bundle `begin` with no chunks), the session ends at
/// once, and the next session drains frames only `reconnect_after` later.
#[derive(Clone, Copy)]
struct Loss {
    kind: &'static str,
    partial: bool,
    reconnect_after: Duration,
    times: usize,
}

fn request_kind(message: &DaemonControlMessage) -> &'static str {
    match message {
        DaemonControlMessage::CredentialSpecRequest(_) => "spec.request",
        DaemonControlMessage::CredentialBundleRequest(_) => "bundle.request",
        _ => "other",
    }
}

impl FakeServer {
    /// [`Self::start`] over a connection that breaks once as `loss` says.
    fn start_lossy(service: &CredentialService, script: Script, loss: Loss) -> Self {
        let log = Arc::new(Mutex::new(Vec::new()));
        let envelopes = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (l, e, s, service) = (
            log.clone(),
            envelopes.clone(),
            stop.clone(),
            service.clone(),
        );
        let handle = std::thread::spawn(move || {
            let mut capture = None;
            let mut lost = 0;
            while !s.load(Ordering::SeqCst) {
                'batch: for message in service.drain() {
                    lock(&l).push(message.clone());
                    if lost < loss.times && request_kind(&message) == loss.kind {
                        lost += 1;
                        if loss.partial
                            && let DaemonControlMessage::CredentialBundleRequest(request) = &message
                        {
                            let lease = script
                                .leases
                                .iter()
                                .find(|l| l.lease_id == request.lease_id)
                                .unwrap();
                            let bytes = bundle_bytes(lease, true);
                            service.handle_server(ServerControlMessage::CredentialBundleBegin(
                                CredentialBundleBeginV11 {
                                    request_id: request.request_id.clone(),
                                    binding_id: format!("bind-{}", request.lease_id),
                                    storage_seq: 1,
                                    file_count: 2,
                                    env_count: 1,
                                    bundle_len: bytes.len() as u64,
                                    chunk_count: bytes.len().div_ceil(CREDENTIAL_CHUNK_RAW_BYTES)
                                        as u32,
                                },
                            ));
                        }
                        // The socket broke: the rest of this batch died with it.
                        service.on_disconnect();
                        std::thread::sleep(loss.reconnect_after);
                        break 'batch;
                    }
                    respond(&service, &script, &e, &mut capture, message);
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        });
        Self {
            log,
            envelopes,
            stop,
            handle: Some(handle),
        }
    }

    fn bundle_requests(&self) -> Vec<CredentialBundleRequestV11> {
        self.frames()
            .into_iter()
            .filter_map(|m| match m {
                DaemonControlMessage::CredentialBundleRequest(r) => Some(r),
                _ => None,
            })
            .collect()
    }
}

fn one_lease_launch() -> (CredentialSpecV11, Script, Vec<u8>) {
    let s = spec(
        vec![lease("lease-1", SpecLeaseAction::Inject, None)],
        vec![],
    );
    let script = Script::new(&s);
    let bytes = script.spec.clone();
    (s, script, bytes)
}

/// The bundle request went out on a socket that broke before any answer:
/// the same request (same id) is re-sent on the next session, the login
/// installs once and the launch reports it once.
#[test]
fn bundle_request_lost_with_its_socket_is_re_sent_on_the_next_session() {
    for partial in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let fake = FakeRuntime::default();
        let (s, script, bytes) = one_lease_launch();
        let daemon = service(dir.path());
        let server = FakeServer::start_lossy(
            &daemon,
            script,
            Loss {
                kind: "bundle.request",
                partial,
                reconnect_after: Duration::from_millis(300),
                times: 1,
            },
        );
        let receipt = daemon.launch(&fake, &target(&bytes), &s, &always).unwrap();
        let requests = server.bundle_requests();
        assert_eq!(requests.len(), 2, "partial={partial}");
        assert_eq!(requests[0].request_id, requests[1].request_id);
        assert_eq!(requests[0].operation_id, requests[1].operation_id);
        assert_eq!(
            server.kinds(),
            vec!["bundle.request", "bundle.request", "installed"]
        );
        assert_eq!(receipt.len(), 1);
        assert_eq!(receipt[0].binding_id, "bind-lease-1");
        assert_eq!(
            guest_calls(&fake)
                .iter()
                .filter(|op| *op == "restore")
                .count(),
            1,
            "installed once"
        );
        assert_eq!(
            daemon.env_for(SANDBOX, Duration::ZERO).unwrap()[0]
                .1
                .as_bytes(),
            SENTINEL
        );
        assert_frames_redacted(&server.frames());
        assert_nothing_at_rest(dir.path());
    }
}

/// A request still queued when the session ended was never on the dead
/// socket: it goes out on the next session once, not twice.
#[test]
fn bundle_request_still_queued_at_a_disconnect_is_not_duplicated() {
    let dir = tempfile::tempdir().unwrap();
    let fake = FakeRuntime::default();
    let (s, script, bytes) = one_lease_launch();
    let daemon = service(dir.path());
    let launcher = {
        let daemon = daemon.clone();
        let (fake, s, bytes) = (fake.clone(), s.clone(), bytes.clone());
        std::thread::spawn(move || daemon.launch(&fake, &target(&bytes), &s, &always))
    };
    wait_until(|| !lock(&daemon.inner.frames).queue.is_empty());
    daemon.on_disconnect();
    std::thread::sleep(Duration::from_millis(250));
    let server = FakeServer::start(&daemon, script);
    assert_eq!(launcher.join().unwrap().unwrap().len(), 1);
    assert_eq!(server.kinds(), vec!["bundle.request", "installed"]);
}

/// The first send's deadline bounds every attempt: a reconnect after it
/// does not extend the wait, and the launch fails `credential_install_failed`.
#[test]
fn bundle_request_lost_and_reconnected_after_the_deadline_fails_the_install() {
    let dir = tempfile::tempdir().unwrap();
    let fake = FakeRuntime::default();
    let (s, script, bytes) = one_lease_launch();
    let wait = Duration::from_millis(800);
    let daemon = CredentialService::start_with_bundle_wait(dir.path(), "host-1", wait).unwrap();
    daemon.on_registered(OWNER);
    let server = FakeServer::start_lossy(
        &daemon,
        script,
        Loss {
            kind: "bundle.request",
            partial: false,
            reconnect_after: wait * 3,
            times: 1,
        },
    );
    let started = Instant::now();
    assert_eq!(
        daemon.launch(&fake, &target(&bytes), &s, &always),
        Err(LaunchFailure::Install)
    );
    assert!(started.elapsed() < wait * 2, "deadline not extended");
    assert!(!guest_calls(&fake).iter().any(|op| op == "restore"));
    assert_eq!(daemon.env_for(SANDBOX, Duration::ZERO), Ok(vec![]));
    // The re-send queued while disconnected was retired with its wait: the
    // next session never carries a request nobody awaits.
    wait_until(|| lock(&daemon.inner.frames).queue.is_empty());
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(server.bundle_requests().len(), 1);
    assert_eq!(
        lock(&daemon.inner.frames).drained,
        2,
        "retired, still counted"
    );
}

/// Spec requests follow the same rule: lost with the socket → re-sent, and
/// the stream is assembled from the new session's chunks only.
#[test]
fn spec_request_lost_with_its_socket_is_re_sent_on_the_next_session() {
    let dir = tempfile::tempdir().unwrap();
    let (s, script, bytes) = one_lease_launch();
    let daemon = service(dir.path());
    let server = FakeServer::start_lossy(
        &daemon,
        script,
        Loss {
            kind: "spec.request",
            partial: false,
            reconnect_after: Duration::from_millis(300),
            times: 1,
        },
    );
    let fetched = daemon
        .fetch_spec("op-create-1", &reference(&bytes), &always)
        .unwrap();
    assert_eq!(fetched, s);
    assert_eq!(server.kinds(), vec!["spec.request", "spec.request"]);
}

/// A connection that keeps breaking: the request is re-sent at most
/// `MAX_REREQUESTS` times, then the wait runs out at the first deadline.
#[test]
fn bundle_re_requests_are_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let fake = FakeRuntime::default();
    let (s, script, bytes) = one_lease_launch();
    let wait = Duration::from_secs(3);
    let daemon = CredentialService::start_with_bundle_wait(dir.path(), "host-1", wait).unwrap();
    daemon.on_registered(OWNER);
    let server = FakeServer::start_lossy(
        &daemon,
        script,
        Loss {
            kind: "bundle.request",
            partial: false,
            reconnect_after: Duration::from_millis(50),
            times: usize::MAX,
        },
    );
    let started = Instant::now();
    assert_eq!(
        daemon.launch(&fake, &target(&bytes), &s, &always),
        Err(LaunchFailure::Install)
    );
    assert!(started.elapsed() < wait * 2, "one deadline");
    let requests = server.bundle_requests();
    assert_eq!(requests.len(), 1 + MAX_REREQUESTS as usize);
    assert!(
        requests
            .iter()
            .all(|r| r.request_id == requests[0].request_id)
    );
    assert!(!guest_calls(&fake).iter().any(|op| op == "restore"));
}
