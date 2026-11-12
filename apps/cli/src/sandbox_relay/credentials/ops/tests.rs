//! Daemon-level credential tests over FakeRuntime: install → capture →
//! ack → quarantine, the key-transition barrier, outbox limits and the
//! no-plaintext-at-rest sentinel.

#![allow(deprecated)] // ring's fixed test RNG loads a fixed X25519 scalar.

use super::*;
use crate::sandbox_relay::credentials::envelope;
use crate::sandbox_relay::credentials::journal::{BindingPhase, BindingPurpose, BindingRecord};
use crate::sandbox_relay::credentials::outbox::{LEASE_MAX_UNRESOLVED, QUARANTINE_MAX_ENVELOPES};
use crate::sandbox_relay::credentials::seal::{ReturnPublicKey, testing};
use crate::sandbox_relay::credentials::store::AckEffect;
use crate::sandbox_relay::credentials::transfer::BundleReceiver;
use login_definition::{Bundle, BundleEnv, BundleFile, encode_bundle};
use sandbox_protocol::{
    CREDENTIAL_CHUNK_RAW_BYTES, CaptureAckOutcome, CaptureAckReason, CaptureKind,
    CredentialBundleBeginV11, CredentialCaptureAckV11, CredentialDelivery, CredentialLeaseKind,
    CredentialReturnKeyV11, CredentialRotates, ReturnKeyRefusal, SpecFilesV11, SpecLeaseAction,
    encode_chunk_data,
};
use sandbox_runtime::FakeRuntime;
use std::sync::Arc;

const SANDBOX: &str = "sbx-1";
const FILE: &str = ".config/tool/hosts.yml";
const SENTINEL: &[u8] = b"SENTINEL-CREDENTIAL-VALUE-7f3a";

struct Key {
    private: [u8; 32],
    public: ReturnPublicKey,
    epoch: u64,
}

impl Key {
    fn new(seed: u8, epoch: u64) -> Self {
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
            epoch,
        }
    }
    fn frame(&self) -> CredentialReturnKeyV11 {
        CredentialReturnKeyV11 {
            kid_r: self.public.kid_r().to_owned(),
            epoch: self.epoch,
            public_key: self.public.to_base64url(),
            server_origin: "https://wssp.example.com".into(),
        }
    }
}

fn lease(id: &str) -> SpecLeaseV11 {
    SpecLeaseV11 {
        lease_id: id.into(),
        binding_id: None,
        credential_id: "cred-1".into(),
        instance_id: "inst-1".into(),
        definition_digest: "ab".repeat(32),
        max_bytes: 4096,
        delivery: CredentialDelivery::Guest,
        exclusive: true,
        copy_back: true,
        rotates: CredentialRotates::Unknown,
        kind: CredentialLeaseKind::Workload,
        action: SpecLeaseAction::Inject,
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

fn guest() -> CredentialGuest {
    CredentialGuest {
        sandbox_id: SANDBOX.into(),
        uid: 1000,
        gid: 1000,
        home: "/home/user".into(),
    }
}

fn binding(id: &str, lease: &str) -> BindingRecord {
    BindingRecord {
        binding_id: id.into(),
        lease_id: lease.into(),
        sandbox_id: SANDBOX.into(),
        credential_id: "cred-1".into(),
        instance_id: "inst-1".into(),
        spec_digest: "cd".repeat(32),
        copy_back: true,
        exclusive: true,
        purpose: BindingPurpose::Install,
        install_intent: None,
        installed_seq: None,
        phase: BindingPhase::Installing,
        teardown: None,
        scrubbed_verified: false,
        spec: None,
        proxy_handles: Vec::new(),
    }
}

fn ctx(lease: &str, binding: &str, capture: &str, kind: CaptureKind) -> CaptureContext {
    CaptureContext {
        host_owner_id: "owner-1".into(),
        host_id: "host-1".into(),
        sandbox_owner_id: "owner-1".into(),
        sandbox_id: SANDBOX.into(),
        lease_id: lease.into(),
        binding_id: binding.into(),
        instance_id: "inst-1".into(),
        credential_id: "cred-1".into(),
        capture_id: capture.into(),
        kind,
        residue_id: String::new(),
    }
}

/// Server side of an install: the bundle bytes streamed in chunks.
fn receive(lease: &SpecLeaseV11, binding_id: &str, token: &[u8]) -> ReceivedBundle {
    let def = definition_for(lease).unwrap();
    let bundle = Bundle {
        definition_digest: digest_bytes(&lease.definition_digest).unwrap(),
        files: vec![
            BundleFile {
                kind: BundleFileKind::Dir,
                path: ".config/tool",
                mode: 0o700,
                data: b"",
            },
            BundleFile {
                kind: BundleFileKind::File,
                path: FILE,
                mode: 0o600,
                data: token,
            },
        ],
        env: vec![BundleEnv {
            name: "TOOL_TOKEN",
            value: SENTINEL,
        }],
    };
    let bytes = encode_bundle(&bundle, &def).unwrap();
    let chunks: Vec<String> = bytes
        .as_bytes()
        .chunks(CREDENTIAL_CHUNK_RAW_BYTES)
        .map(encode_chunk_data)
        .collect();
    let mut rx = BundleReceiver::new(CredentialBundleBeginV11 {
        request_id: "req-1".into(),
        binding_id: binding_id.into(),
        storage_seq: 1,
        file_count: 2,
        env_count: 1,
        bundle_len: bytes.len() as u64,
        chunk_count: chunks.len() as u32,
    })
    .unwrap();
    for (i, c) in chunks.iter().enumerate() {
        rx.push(i as u32, c).unwrap();
    }
    rx.finish(lease, false).unwrap()
}

fn store(dir: &std::path::Path, key: &Key) -> CredentialStore {
    let store = CredentialStore::open(dir).unwrap();
    let ack = store.install_return_key(&key.frame()).unwrap();
    assert_eq!(ack.refused, None);
    store
}

fn open_envelope(key: &Key, entry: &OutboxEntry, store: &CredentialStore) -> Vec<u8> {
    let env = store.outbox().read(&entry.capture_id).unwrap();
    testing::open(&key.private, &key.public, env.seal(), &env.header.aad)
        .unwrap()
        .expose()
        .to_vec()
}

fn every_file_under(dir: &std::path::Path) -> Vec<Vec<u8>> {
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

/// install → guest rotates the file → capture → REJECTED → quarantine:
/// absent from census `pending` and from the per-lease count, present in
/// `quarantined`; `quarantine.discard` deletes it. No plaintext at rest.
#[test]
fn install_capture_reject_quarantine_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let key = Key::new(7, 1);
    let store = store(dir.path(), &key);
    let fake = FakeRuntime::default();
    let lease = lease("lease-1");
    store
        .journal()
        .record_binding(binding("bind-1", "lease-1"))
        .unwrap();

    let received = receive(&lease, "bind-1", b"token: v1");
    let (installed, env) =
        install_bundle(&store, &fake, &guest(), &lease, "req-1", &received).unwrap();
    assert_eq!((installed.file_count, installed.env_count), (2, 1));
    assert_eq!(
        fake.guest_file(SANDBOX, FILE).as_deref(),
        Some(&b"token: v1"[..])
    );
    assert_eq!(env.values[0].1.expose(), SENTINEL);
    assert_eq!(
        store.journal().binding("bind-1").unwrap().phase,
        BindingPhase::Active
    );
    assert_eq!(
        store.journal().binding("bind-1").unwrap().installed_seq,
        Some(1)
    );

    // The guest CLI rotates its token; a stop captures the new bytes.
    fake.set_guest_file(SANDBOX, FILE, b"token: v2-rotated");
    let entry = capture_binding(
        &store,
        &fake,
        &guest(),
        &lease,
        &ctx("lease-1", "bind-1", "cap-1", CaptureKind::Stop),
        1,
    )
    .unwrap();
    assert_eq!(entry.capture_seq, 1);
    assert_eq!(entry.kid_r, key.public.kid_r());
    let opened = open_envelope(&key, &entry, &store);
    assert!(contains(&opened, b"token: v2-rotated"));
    assert!(!contains(&opened, SENTINEL), "captures carry files only");

    let census = store.census().unwrap();
    assert_eq!(census.len(), 1);
    assert_eq!(census[0].entries[0].pending.len(), 1);
    assert!(census[0].quarantined.is_empty());

    // Nothing at rest holds plaintext: journal and outbox are sentinel-free.
    for bytes in every_file_under(dir.path()) {
        assert!(!contains(&bytes, SENTINEL));
        assert!(!contains(&bytes, b"token: v2-rotated"));
    }

    let rejected = CredentialCaptureAckV11 {
        capture_id: "cap-1".into(),
        outcome: CaptureAckOutcome::Rejected,
        reason: Some(CaptureAckReason::BindingClosed),
    };
    assert_eq!(
        store.apply_capture_ack(&rejected).unwrap(),
        AckEffect::Rejected { quarantined: true }
    );
    // Replayed ack is idempotent.
    assert_eq!(
        store.apply_capture_ack(&rejected).unwrap(),
        AckEffect::Rejected { quarantined: true }
    );
    assert!(
        dir.path()
            .join("credentials/outbox/rejected/cap-1.wsco")
            .exists()
    );
    assert_eq!(store.outbox().pending_for_lease("lease-1"), 0);
    let census = store.census().unwrap();
    assert!(census[0].entries[0].pending.is_empty());
    assert_eq!(census[0].quarantined.len(), 1);
    assert_eq!(census[0].quarantined[0].capture_id, "cap-1");
    // The guest files were never scrubbed by a REJECTED outcome.
    assert!(fake.guest_file(SANDBOX, FILE).is_some());

    // A reopened store (daemon restart) still knows the quarantine.
    drop(store);
    let store = CredentialStore::open(dir.path()).unwrap();
    assert_eq!(store.census().unwrap()[0].quarantined.len(), 1);
    assert_eq!(
        store
            .discard_quarantined(&["cap-1".into(), "nope".into()])
            .unwrap(),
        vec!["cap-1".to_owned()]
    );
    assert!(store.census().unwrap()[0].quarantined.is_empty());
    assert!(
        !dir.path()
            .join("credentials/outbox/rejected/cap-1.wsco")
            .exists()
    );
}

#[test]
fn committed_and_deferred_acks_follow_the_scrub_rules() {
    let dir = tempfile::tempdir().unwrap();
    let k1 = Key::new(7, 1);
    let store = store(dir.path(), &k1);
    let fake = FakeRuntime::default();
    let lease = lease("lease-1");
    fake.set_guest_file(SANDBOX, FILE, b"token: v1");
    let c = |id: &str| {
        capture_binding(
            &store,
            &fake,
            &guest(),
            &lease,
            &ctx("lease-1", "bind-1", id, CaptureKind::Stop),
            1,
        )
        .unwrap()
    };
    c("cap-1");
    c("cap-2");
    let ack = |id: &str, outcome| CredentialCaptureAckV11 {
        capture_id: id.into(),
        outcome,
        reason: None,
    };
    assert_eq!(
        store
            .apply_capture_ack(&ack("cap-1", CaptureAckOutcome::Deferred))
            .unwrap(),
        AckEffect::Deferred {
            scrub_allowed: true
        }
    );
    // After a newer key, an envelope under the old kid no longer permits scrub.
    store.install_return_key(&Key::new(9, 2).frame()).unwrap();
    assert_eq!(
        store
            .apply_capture_ack(&ack("cap-1", CaptureAckOutcome::Deferred))
            .unwrap(),
        AckEffect::Deferred {
            scrub_allowed: false
        }
    );
    assert_eq!(
        store
            .apply_capture_ack(&ack("cap-2", CaptureAckOutcome::Committed))
            .unwrap(),
        AckEffect::Resolved {
            scrub_allowed: true
        }
    );
    assert_eq!(store.outbox().pending().count(), 1);
    // Scrub of the binding's paths verifies absence.
    assert!(scrub_paths(&fake, &guest(), included_paths(&lease)).unwrap());
    assert!(fake.guest_file(SANDBOX, FILE).is_none());
}

/// ≤ 8 unresolved per lease (quarantined excluded); checkpoints coalesce.
#[test]
fn per_lease_limit_excludes_quarantine_and_checkpoints_coalesce() {
    let dir = tempfile::tempdir().unwrap();
    let key = Key::new(7, 1);
    let store = store(dir.path(), &key);
    let fake = FakeRuntime::default();
    let lease = lease("lease-1");
    fake.set_guest_file(SANDBOX, FILE, b"token");
    let capture = |id: &str, kind| {
        capture_binding(
            &store,
            &fake,
            &guest(),
            &lease,
            &ctx("lease-1", "bind-1", id, kind),
            1,
        )
    };
    for i in 0..3 {
        capture(&format!("ckpt-{i}"), CaptureKind::Checkpoint).unwrap();
    }
    // Newest pending checkpoint per lease only.
    let pending: Vec<String> = store
        .outbox()
        .pending()
        .map(|e| e.capture_id.clone())
        .collect();
    assert_eq!(pending, vec!["ckpt-2".to_owned()]);
    for i in 0..LEASE_MAX_UNRESOLVED - 1 {
        capture(&format!("stop-{i}"), CaptureKind::Stop).unwrap();
    }
    assert_eq!(
        store.outbox().pending_for_lease("lease-1"),
        LEASE_MAX_UNRESOLVED
    );
    let err = capture("stop-9th", CaptureKind::Stop).unwrap_err();
    assert!(err.to_string().contains("maximum number"), "{err}");
    // Quarantining one frees a slot: quarantine is not counted.
    store
        .apply_capture_ack(&CredentialCaptureAckV11 {
            capture_id: "stop-0".into(),
            outcome: CaptureAckOutcome::Rejected,
            reason: Some(CaptureAckReason::DecryptFailed),
        })
        .unwrap();
    capture("stop-9th", CaptureKind::Stop).unwrap();
    // Sequences are never reused, even for failed attempts.
    let seqs: Vec<u64> = store.outbox().pending().map(|e| e.capture_seq).collect();
    let mut sorted = seqs.clone();
    sorted.dedup();
    assert_eq!(seqs.len(), sorted.len());
}

/// Quarantine full → the rejected envelope stays unresolved (fail closed),
/// an alert is raised, and the census still lists it as pending.
#[test]
fn full_quarantine_holds_the_envelope_unresolved_and_alerts() {
    let dir = tempfile::tempdir().unwrap();
    let key = Key::new(7, 1);
    let store = store(dir.path(), &key);
    let fake = FakeRuntime::default();
    fake.set_guest_file(SANDBOX, FILE, b"token");
    let reject = |id: &str| CredentialCaptureAckV11 {
        capture_id: id.into(),
        outcome: CaptureAckOutcome::Rejected,
        reason: Some(CaptureAckReason::ContextMismatch),
    };
    for i in 0..QUARANTINE_MAX_ENVELOPES {
        let lease = lease(&format!("lease-{i}"));
        let id = format!("cap-{i}");
        capture_binding(
            &store,
            &fake,
            &guest(),
            &lease,
            &ctx(
                &lease.lease_id,
                &format!("bind-{i}"),
                &id,
                CaptureKind::Stop,
            ),
            1,
        )
        .unwrap();
        assert_eq!(
            store.apply_capture_ack(&reject(&id)).unwrap(),
            AckEffect::Rejected { quarantined: true }
        );
    }
    let lease = lease("lease-x");
    capture_binding(
        &store,
        &fake,
        &guest(),
        &lease,
        &ctx("lease-x", "bind-x", "cap-x", CaptureKind::Stop),
        1,
    )
    .unwrap();
    assert_eq!(
        store.apply_capture_ack(&reject("cap-x")).unwrap(),
        AckEffect::Rejected { quarantined: false }
    );
    assert_eq!(store.take_alerts().len(), 1);
    let census = store.census().unwrap();
    assert_eq!(census[0].quarantined.len(), QUARANTINE_MAX_ENVELOPES);
    let pending: Vec<_> = census
        .iter()
        .flat_map(|p| p.entries.iter())
        .flat_map(|e| e.pending.iter())
        .map(|p| p.capture_id.as_str())
        .collect();
    assert_eq!(pending, vec!["cap-x"]);
}

/// Key-transition barrier: a seal in flight finishes durable under the old
/// kid before the switch; a delayed R1 after R2 is refused (stale) and the
/// next seal uses R2; same-epoch substitution is refused.
#[test]
fn key_barrier_waits_for_in_flight_seals_and_refuses_old_keys() {
    let dir = tempfile::tempdir().unwrap();
    let r1 = Key::new(7, 1);
    let store = Arc::new(store(dir.path(), &r1));
    let fake = FakeRuntime::default();
    fake.set_guest_file(SANDBOX, FILE, b"token");
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    let go_rx = std::sync::Mutex::new(go_rx);
    *store.before_durable.lock().unwrap() = Some(Box::new(move || {
        let _ = entered_tx.send(());
        let _ = go_rx.lock().unwrap().recv();
    }));
    let s2 = Arc::clone(&store);
    let fake2 = fake.clone();
    let sealer = std::thread::spawn(move || {
        capture_binding(
            &s2,
            &fake2,
            &guest(),
            &lease("lease-1"),
            &ctx("lease-1", "bind-1", "cap-old", CaptureKind::Stop),
            1,
        )
        .unwrap()
    });
    entered_rx.recv().unwrap();
    let r2 = Key::new(9, 2);
    let s3 = Arc::clone(&store);
    let frame = r2.frame();
    let switcher = std::thread::spawn(move || s3.install_return_key(&frame).unwrap());
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert!(
        !switcher.is_finished(),
        "the switch waits for the in-flight seal"
    );
    go_tx.send(()).unwrap();
    let old = sealer.join().unwrap();
    let ack = switcher.join().unwrap();
    *store.before_durable.lock().unwrap() = None;
    assert_eq!(old.kid_r, r1.public.kid_r());
    assert_eq!(ack.refused, None);
    assert_eq!(ack.current_epoch, 2);
    assert_eq!(ack.retired_kids, vec![r1.public.kid_r().to_owned()]);
    assert_eq!(ack.pending_under_retired, 1);
    // The census after the ack lists the old-kid envelope under its kid.
    let census = store.census().unwrap();
    assert_eq!(census[0].key_epoch, 2);
    let listed = &census[0].entries[0].pending[0];
    assert_eq!(listed.kid_r, r1.public.kid_r());

    // Delayed R1 after R2: stale, slot unchanged; the next seal uses R2.
    let stale = store.install_return_key(&r1.frame()).unwrap();
    assert_eq!(stale.refused, Some(ReturnKeyRefusal::Stale));
    assert_eq!(stale.current_epoch, 2);
    let next = capture_binding(
        &store,
        &fake,
        &guest(),
        &lease("lease-1"),
        &ctx("lease-1", "bind-1", "cap-new", CaptureKind::Stop),
        1,
    )
    .unwrap();
    assert_eq!(next.kid_r, r2.public.kid_r());
    assert!(!open_envelope(&r2, &next, &store).is_empty());
    // Same epoch, different key: substitution refused + alert.
    let mut sub = Key::new(11, 2).frame();
    sub.epoch = 2;
    let refused = store.install_return_key(&sub).unwrap();
    assert_eq!(refused.refused, Some(ReturnKeyRefusal::Substitution));
    assert_eq!(store.take_alerts().len(), 1);
    // Re-ack of the current key is idempotent.
    assert_eq!(store.install_return_key(&r2.frame()).unwrap().refused, None);
}

#[test]
fn no_key_or_failing_pack_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let store = CredentialStore::open(dir.path()).unwrap();
    let fake = FakeRuntime::default();
    fake.set_guest_file(SANDBOX, FILE, b"token");
    let lease = lease("lease-1");
    let c = || {
        capture_binding(
            &store,
            &fake,
            &guest(),
            &lease,
            &ctx("lease-1", "bind-1", "cap-1", CaptureKind::Stop),
            1,
        )
    };
    assert!(c().is_err(), "no acked return key");
    store.install_return_key(&Key::new(7, 1).frame()).unwrap();
    fake.fail_credential_op("pack", 1);
    assert!(c().is_err());
    assert_eq!(store.outbox().pending().count(), 0);
    let entry = c().unwrap();
    // Envelope on disk self-verifies and matches its digest.
    let env =
        envelope::parse(std::fs::read(dir.path().join("credentials/outbox/cap-1.wsco")).unwrap())
            .unwrap();
    assert_eq!(env.digest_hex(), entry.digest_hex);
}
