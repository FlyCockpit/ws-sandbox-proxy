//! Checkpoint tests over FakeRuntime and the scripted server:
//! a checkpoint is sealed only after its interval and only when the packed bytes changed, never scrubs,
//! coalesces to the newest pending checkpoint per lease, never waits for the
//! slot (a busy slot retries on the next tick), skips bindings with a
//! teardown record or an open teardown attempt, and skips revoked leases.

use super::*;
use std::sync::Arc;

const ROTATED: &[u8] = b"token: CHECKPOINT-ROTATED-c11";
const ROTATED_AGAIN: &[u8] = b"token: CHECKPOINT-ROTATED-AGAIN-c11";
const MINUTE: Duration = Duration::from_secs(60);

struct Setup {
    dir: tempfile::TempDir,
    fake: FakeRuntime,
    key: Key,
    daemon: CredentialService,
    server: FakeServer,
    script: Script,
    t0: Instant,
}

fn checkpointed(id: &str, interval: Option<u32>) -> SpecLeaseV11 {
    let mut l = lease(id, SpecLeaseAction::Inject, None);
    l.checkpoint_interval_min = interval;
    l
}

impl Setup {
    fn new(leases: Vec<SpecLeaseV11>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key = Key::new(11);
        let fake = FakeRuntime::default();
        let s = spec(leases, vec![]);
        let script = Script::new(&s);
        let bytes = script.spec.clone();
        let daemon = keyed_service(dir.path(), &key);
        let server = FakeServer::start(&daemon, script.clone());
        daemon.launch(&fake, &target(&bytes), &s, &always).unwrap();
        Self {
            dir,
            fake,
            key,
            daemon,
            server,
            script,
            t0: Instant::now(),
        }
    }

    fn tick(&self, after: Duration) -> Vec<CheckpointOutcome> {
        self.daemon
            .run_due_checkpoints(&self.fake, self.t0 + after, &|sandbox_id| {
                (sandbox_id == SANDBOX).then(|| CheckpointTarget {
                    guest: target(b"").guest,
                    sandbox_owner_id: OWNER.into(),
                })
            })
    }

    /// Opened checkpoint envelopes the server received: (captureSeq, kind, plaintext).
    fn opened(&self) -> Vec<(u64, String, Vec<u8>)> {
        lock(&self.server.envelopes)
            .iter()
            .map(|bytes| {
                let parsed =
                    crate::sandbox_relay::credentials::envelope::parse(bytes.clone()).unwrap();
                let plain = testing::open(
                    &self.key.private,
                    &self.key.public,
                    parsed.seal(),
                    &parsed.header.aad,
                )
                .unwrap()
                .expose()
                .to_vec();
                (parsed.header.aad.capture_seq, parsed.header.aad.kind, plain)
            })
            .collect()
    }

    fn pending(&self) -> usize {
        self.daemon.store().outbox().pending().count()
    }

    fn calls(&self) -> Vec<String> {
        guest_calls(&self.fake)
    }
}

fn until(mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !f() {
        assert!(Instant::now() < deadline, "condition not reached");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn sealed(outcome: &CheckpointOutcome) -> String {
    match outcome {
        CheckpointOutcome::Sealed { capture_id, .. } => capture_id.clone(),
        other => panic!("expected Sealed, got {other:?}"),
    }
}

/// Interval, then pack without quiesce → seal → upload → COMMITTED; the
/// guest file stays (never scrubs); unchanged bytes seal nothing; changed
/// bytes seal again with a higher capture sequence.
#[test]
fn checkpoint_seals_changed_bytes_after_the_interval_and_never_scrubs() {
    let s = Setup::new(vec![checkpointed("lease-1", Some(5))]);
    s.fake.set_guest_file(SANDBOX, FILE, ROTATED);
    let launch_calls = s.calls().len();
    // First sight schedules one interval out; nothing is due yet.
    assert!(s.tick(Duration::ZERO).is_empty());
    assert!(s.tick(4 * MINUTE).is_empty());
    assert_eq!(s.calls().len(), launch_calls, "no guest call before due");

    let first = s.tick(5 * MINUTE);
    assert_eq!(first.len(), 1);
    sealed(&first[0]);
    assert_eq!(
        s.calls()[launch_calls..],
        ["pack".to_owned()],
        "no quiesce, no scrub"
    );
    until(|| s.pending() == 0);
    assert_eq!(s.fake.guest_file(SANDBOX, FILE).as_deref(), Some(ROTATED));

    // Same bytes one interval later: hashed in memory, nothing sealed.
    let second = s.tick(10 * MINUTE);
    assert_eq!(
        second,
        vec![CheckpointOutcome::Unchanged {
            binding_id: "bind-lease-1".into()
        }]
    );
    // The guest rotates again: sealed with the next capture sequence.
    s.fake.set_guest_file(SANDBOX, FILE, ROTATED_AGAIN);
    sealed(&s.tick(15 * MINUTE)[0]);
    until(|| s.pending() == 0);
    let opened = s.opened();
    assert_eq!(opened.len(), 2);
    assert!(opened.iter().all(|(_, kind, _)| kind == "checkpoint"));
    assert!(opened[1].0 > opened[0].0);
    assert!(contains(&opened[0].2, ROTATED));
    assert!(contains(&opened[1].2, ROTATED_AGAIN));
    // The binding is still ACTIVE with no teardown record.
    let journal = s.daemon.store().journal();
    let binding = journal.binding("bind-lease-1").unwrap();
    assert_eq!(binding.phase, BindingPhase::Active);
    assert!(binding.teardown.is_none());
    drop(journal);
    assert_nothing_at_rest(s.dir.path());
    for bytes in every_file_under(s.dir.path()) {
        assert!(!contains(&bytes, ROTATED) && !contains(&bytes, ROTATED_AGAIN));
    }
    assert_frames_redacted(&s.server.frames());
}

/// Offline (no outcome): a newer checkpoint replaces the lease's pending one.
#[test]
fn offline_checkpoints_coalesce_to_the_newest_per_lease() {
    let s = Setup::new(vec![checkpointed("lease-1", Some(5))]);
    lock(&s.script.binding_acks).insert("bind-lease-1".into(), None);
    s.fake.set_guest_file(SANDBOX, FILE, ROTATED);
    s.tick(Duration::ZERO);
    let a = sealed(&s.tick(5 * MINUTE)[0]);
    s.fake.set_guest_file(SANDBOX, FILE, ROTATED_AGAIN);
    let b = sealed(&s.tick(10 * MINUTE)[0]);
    let outbox = s.daemon.store().outbox();
    let pending: Vec<String> = outbox.pending().map(|e| e.capture_id.clone()).collect();
    assert_eq!(pending, vec![b.clone()]);
    assert_ne!(a, b);
}

/// The slot is never waited for: busy → skipped and retried on the next
/// tick, not one interval later.
#[test]
fn a_busy_slot_skips_and_retries_on_the_next_tick() {
    let s = Setup::new(vec![checkpointed("lease-1", Some(5))]);
    s.fake.set_guest_file(SANDBOX, FILE, ROTATED);
    s.tick(Duration::ZERO);
    let coord = s.daemon.slot(SANDBOX);
    let holder = Arc::new(sandbox_runtime::RuntimePermit::with_timeout(MINUTE));
    let guard = coord.slot.try_acquire(SlotUser::Attach, &holder).unwrap();
    let started = Instant::now();
    assert_eq!(
        s.tick(5 * MINUTE),
        vec![CheckpointOutcome::Skipped {
            binding_id: "bind-lease-1".into(),
            reason: "slot_busy"
        }]
    );
    assert!(started.elapsed() < Duration::from_secs(1), "never waits");
    drop(guard);
    // Thirty seconds later (the next tick), not a full interval.
    sealed(&s.tick(5 * MINUTE + Duration::from_secs(30))[0]);
}

/// A teardown wins: an open attempt or a binding teardown record skips the
/// checkpoint without touching the guest.
#[test]
fn bindings_in_teardown_are_skipped() {
    let s = Setup::new(vec![checkpointed("lease-1", Some(5))]);
    s.fake.set_guest_file(SANDBOX, FILE, ROTATED);
    s.tick(Duration::ZERO);
    let calls = s.calls().len();
    s.daemon
        .store()
        .journal()
        .open_or_join_teardown(SANDBOX, "stop-1")
        .unwrap();
    assert_eq!(
        s.tick(5 * MINUTE),
        vec![CheckpointOutcome::Skipped {
            binding_id: "bind-lease-1".into(),
            reason: "teardown"
        }]
    );
    s.daemon
        .store()
        .journal()
        .reserve_teardown_capture("bind-lease-1", "att-x")
        .unwrap();
    // A binding with a teardown record is not checkpointable at all.
    assert!(s.tick(10 * MINUTE).is_empty());
    assert_eq!(s.calls().len(), calls, "no guest call");
    assert_eq!(s.pending(), 0);
}

/// No interval (copy-back off, shareable, or not set) → never; a revoked
/// lease → skipped.
#[test]
fn no_interval_never_checkpoints_and_revoked_leases_are_skipped() {
    let mut shareable = checkpointed("lease-2", Some(5));
    shareable.exclusive = false;
    shareable.files.required = vec![".config/other".into()];
    let s = Setup::new(vec![checkpointed("lease-1", None), shareable]);
    s.tick(Duration::ZERO);
    assert!(s.tick(300 * MINUTE).is_empty());

    let s = Setup::new(vec![checkpointed("lease-1", Some(5))]);
    s.fake.set_guest_file(SANDBOX, FILE, ROTATED);
    s.tick(Duration::ZERO);
    s.daemon
        .handle_server(ServerControlMessage::CredentialRevoke(
            sandbox_protocol::CredentialRevokeV11 {
                lease_id: "lease-1".into(),
                reason: "force_released".into(),
            },
        ));
    assert_eq!(
        s.tick(5 * MINUTE),
        vec![CheckpointOutcome::Skipped {
            binding_id: "bind-lease-1".into(),
            reason: "revoked"
        }]
    );
    assert_eq!(s.pending(), 0);
}

/// The timer thread runs ticks until dropped.
#[test]
fn the_timer_runs_until_dropped() {
    let s = Setup::new(vec![checkpointed("lease-1", Some(5))]);
    let runtime: Arc<dyn SandboxRuntime> = Arc::new(s.fake.clone());
    let timer =
        s.daemon
            .start_checkpoints(runtime, Arc::new(|_: &str| None), Duration::from_millis(10));
    std::thread::sleep(Duration::from_millis(50));
    drop(timer);
    // First sight only scheduled it; nothing was due within the interval.
    assert_eq!(s.pending(), 0);
}
