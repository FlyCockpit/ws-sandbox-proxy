//! Daemon teardown tests over FakeRuntime and the scripted server: capture
//! by default on stop/kill/expiry, `skip`, pre-checks touching no process, the refused user stop (abort + owed re-bind in one
//! journal write, replayed idempotently across a crash), rearm with a fresh
//! capture, teardown joining (local expiry + server expiry STOP; kill during
//! stop; expiry never waiting for the slot), the scheduler rules (revoked
//! free recorded and joined; revoked attach abandons its bundle wait), the
//! outcome matrix for system stops, offline expiry within budget, and the
//! lock-free enforcement loss. Every lane test ends with a sentinel check
//! that no plaintext is at rest.

use super::*;
use crate::sandbox_relay::credentials::journal::AttemptState;
use sandbox_protocol::{TeardownCaptureV11, TeardownScrubV11};
use std::sync::atomic::AtomicUsize;

const ROTATED: &[u8] = b"token: ROTATED-BY-THE-GUEST-c8b";

struct Setup {
    dir: tempfile::TempDir,
    fake: FakeRuntime,
    key: Key,
    daemon: CredentialService,
    server: FakeServer,
    script: Script,
    /// Guest calls and frames made by the launch.
    calls_before: usize,
    frames_before: usize,
}

impl Setup {
    fn new(leases: Vec<SpecLeaseV11>, keyed: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key = Key::new(9);
        let fake = FakeRuntime::default();
        let s = spec(leases, vec![]);
        let script = Script::new(&s);
        let bytes = script.spec.clone();
        let daemon = if keyed {
            keyed_service(dir.path(), &key)
        } else {
            service(dir.path())
        };
        let server = FakeServer::start(&daemon, script.clone());
        daemon.launch(&fake, &target(&bytes), &s, &always).unwrap();
        let calls_before = guest_calls(&fake).len();
        let frames_before = server.frames().len();
        Self {
            dir,
            fake,
            key,
            daemon,
            server,
            script,
            calls_before,
            frames_before,
        }
    }

    fn calls(&self) -> Vec<String> {
        guest_calls(&self.fake)[self.calls_before..].to_vec()
    }

    fn kinds(&self) -> Vec<&'static str> {
        self.server.kinds()[self.frames_before..].to_vec()
    }

    fn ack(&self, binding: &str, answer: Option<Ack>) {
        lock(&self.script.binding_acks).insert(binding.to_owned(), answer);
    }

    /// Opens every envelope the server received for `binding`, in order:
    /// (captureId, captureSeq, kind, plaintext).
    fn opened(&self, binding: &str) -> Vec<(String, u64, String, Vec<u8>)> {
        lock(&self.server.envelopes)
            .iter()
            .filter_map(|bytes| {
                let parsed =
                    crate::sandbox_relay::credentials::envelope::parse(bytes.clone()).unwrap();
                let aad = parsed.header.aad.clone();
                (aad.binding_id == binding).then(|| {
                    let plain = testing::open(
                        &self.key.private,
                        &self.key.public,
                        parsed.seal(),
                        &parsed.header.aad,
                    )
                    .unwrap()
                    .expose()
                    .to_vec();
                    (aad.capture_id, aad.capture_seq, aad.kind, plain)
                })
            })
            .collect()
    }

    fn assert_nothing_at_rest(&self) {
        assert_nothing_at_rest(self.dir.path());
        for bytes in every_file_under(self.dir.path()) {
            assert!(!contains(&bytes, ROTATED), "rotated value at rest");
        }
        assert_frames_redacted(&self.server.frames());
    }
}

fn lease_b() -> SpecLeaseV11 {
    let mut l = lease("lease-b", SpecLeaseAction::Inject, None);
    l.files.required = vec![".config/other".into()];
    l
}

fn request(op: &str, path: TeardownPath, system: bool) -> TeardownRequest {
    TeardownRequest {
        operation_id: op.into(),
        guest: target(b"").guest,
        sandbox_owner_id: OWNER.into(),
        host_owner_id: None,
        path,
        system,
        skip: false,
        spec_unverified: false,
        generation: 2,
        budget: Duration::from_secs(10),
    }
}

fn no_rebind(_: u64) -> anyhow::Result<()> {
    panic!("a proceeding teardown never re-binds")
}

fn proceed(verdict: TeardownVerdict) -> Vec<sandbox_protocol::CredentialTeardownOutcomeV11> {
    match verdict {
        TeardownVerdict::Proceed(outcomes) => outcomes,
        other => panic!("expected Proceed, got {other:?}"),
    }
}

fn capture_id(outcome: &sandbox_protocol::CredentialTeardownOutcomeV11) -> String {
    match &outcome.capture {
        TeardownCaptureV11::Acked { capture_id, .. }
        | TeardownCaptureV11::Durable { capture_id } => capture_id.clone(),
        other => panic!("no capture id in {other:?}"),
    }
}

fn until(mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !f() {
        assert!(Instant::now() < deadline, "condition not reached");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Lane e2e: create with a login → guest rotates its token → user stop →
/// pre-checks → quiesce → pack → seal → upload → COMMITTED → scrub →
/// `credential.scrubbed` → env dropped; the envelope carries the rotated
/// bytes; settlement forgets the binding. No plaintext at rest.
#[test]
fn stop_captures_the_rotated_token_commits_scrubs_and_settles() {
    let s = Setup::new(vec![lease("lease-1", SpecLeaseAction::Inject, None)], true);
    s.fake.set_guest_file(SANDBOX, FILE, ROTATED);
    let outcomes = proceed(s.daemon.teardown(
        &s.fake,
        &request("stop-1", TeardownPath::Stop, false),
        None,
        &always,
        &no_rebind,
    ));
    assert_eq!(s.calls(), vec!["probe", "quiesce", "pack", "scrub"]);
    let kinds = s.kinds();
    assert_eq!(kinds.first(), Some(&"capture.begin"));
    assert_eq!(kinds.last(), Some(&"scrubbed"));
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].binding_id, "bind-lease-1");
    assert_eq!(outcomes[0].lease_id.as_deref(), Some("lease-1"));
    assert!(matches!(
        outcomes[0].capture,
        TeardownCaptureV11::Acked {
            outcome: CaptureAckOutcome::Committed,
            ..
        }
    ));
    assert_eq!(outcomes[0].scrub, TeardownScrubV11::Verified);
    assert!(sandbox_protocol::valid_teardown_outcomes(&outcomes));
    let opened = s.opened("bind-lease-1");
    assert_eq!(opened.len(), 1);
    assert_eq!(opened[0].0, capture_id(&outcomes[0]));
    assert_eq!(opened[0].2, "stop");
    assert!(contains(&opened[0].3, ROTATED));
    assert!(s.fake.guest_file(SANDBOX, FILE).is_none(), "scrubbed");
    assert!(
        s.daemon
            .env_for(SANDBOX, Duration::ZERO)
            .unwrap()
            .is_empty()
    );
    assert_eq!(s.daemon.store().outbox().pending().count(), 0);
    // The VM stopped: the attempt is done and the scrubbed binding
    // forgotten; with no binding left, lifecycle GC collects the done
    // attempt's sandbox record too.
    s.daemon.settle_teardown(SANDBOX, false);
    let journal = s.daemon.store().journal();
    assert!(journal.binding("bind-lease-1").is_none());
    assert!(journal.teardown_attempt(SANDBOX).is_none());
    drop(journal);
    s.assert_nothing_at_rest();
}

/// Kill: same capture, no scrub (the disk is destroyed).
#[test]
fn kill_captures_without_scrubbing() {
    let s = Setup::new(vec![lease("lease-1", SpecLeaseAction::Inject, None)], true);
    s.fake.set_guest_file(SANDBOX, FILE, ROTATED);
    let outcomes = proceed(s.daemon.teardown(
        &s.fake,
        &request("kill-1", TeardownPath::Kill, false),
        None,
        &always,
        &no_rebind,
    ));
    assert_eq!(s.calls(), vec!["probe", "quiesce", "pack"]);
    assert!(!s.kinds().contains(&"scrubbed"));
    assert_eq!(outcomes[0].scrub, TeardownScrubV11::NotRun);
    assert_eq!(s.opened("bind-lease-1")[0].2, "kill");
    s.daemon.settle_teardown(SANDBOX, true);
    assert!(s.daemon.store().journal().binding("bind-lease-1").is_none());
    s.assert_nothing_at_rest();
}

/// `credentialCapture: "skip"`: nothing captured; a stop still scrubs.
#[test]
fn skip_captures_nothing_and_still_scrubs_on_stop() {
    let s = Setup::new(vec![lease("lease-1", SpecLeaseAction::Inject, None)], true);
    let mut req = request("stop-skip", TeardownPath::Stop, false);
    req.skip = true;
    let outcomes = proceed(s.daemon.teardown(&s.fake, &req, None, &always, &no_rebind));
    assert_eq!(s.calls(), vec!["scrub"]);
    assert_eq!(outcomes[0].capture, TeardownCaptureV11::None);
    assert_eq!(outcomes[0].scrub, TeardownScrubV11::Verified);
    assert!(lock(&s.server.envelopes).is_empty());
}

/// N11: a pre-check failure refuses the user stop with no guest process
/// touched (no quiesce, pack or scrub); the env stays for the running VM.
#[test]
fn precheck_failure_refuses_the_user_stop_without_touching_a_process() {
    // (a) no acked return key; (b) helper missing; (c) spec unverified.
    for case in ["no-key", "no-helper", "spec"] {
        let s = Setup::new(
            vec![lease("lease-1", SpecLeaseAction::Inject, None)],
            case != "no-key",
        );
        if case == "no-helper" {
            s.fake.set_credential_helper_present(false);
        }
        let mut req = request("stop-1", TeardownPath::Stop, false);
        req.spec_unverified = case == "spec";
        let rebinds = Mutex::new(Vec::new());
        let verdict = s.daemon.teardown(&s.fake, &req, None, &always, &|g| {
            lock(&rebinds).push(g);
            Ok(())
        });
        let TeardownVerdict::Refused(outcomes) = verdict else {
            panic!("{case}: expected a refusal, got {verdict:?}");
        };
        assert!(matches!(
            outcomes[0].capture,
            TeardownCaptureV11::Failed { .. }
        ));
        let calls = s.calls();
        assert!(
            calls.iter().all(|op| op == "probe"),
            "{case}: guest touched: {calls:?}"
        );
        assert!(s.kinds().is_empty(), "{case}: no frame sent");
        assert_eq!(*lock(&rebinds), vec![2], "{case}");
        assert_eq!(s.daemon.env_for(SANDBOX, Duration::ZERO).unwrap().len(), 1);
        assert!(s.fake.guest_file(SANDBOX, FILE).is_some());
    }
}

/// Failed user stop (REJECTED): the abort and the owed re-bind are one
/// journal write, the lease journal is re-bound before the refusal is
/// returned (so before the FAILED receipt), and a crash between the two
/// replays idempotently: restart → owed re-bind applied → the same
/// operation answers the same refusal without touching the guest.
#[test]
fn refused_user_stop_rebinds_atomically_and_replays_after_a_crash() {
    let s = Setup::new(vec![lease("lease-1", SpecLeaseAction::Inject, None)], true);
    s.ack(
        "bind-lease-1",
        Some((
            CaptureAckOutcome::Rejected,
            Some(CaptureAckReason::ContextMismatch),
        )),
    );
    // The process "crashes" right after the credential journal write: the
    // lease-journal re-bind never happens.
    let verdict = s.daemon.teardown(
        &s.fake,
        &request("stop-1", TeardownPath::Stop, false),
        None,
        &always,
        &|_| anyhow::bail!("crash before the lease-journal re-bind"),
    );
    assert_eq!(verdict, TeardownVerdict::Uncertain);
    {
        let journal = s.daemon.store().journal();
        let attempt = journal.teardown_attempt(SANDBOX).unwrap();
        // One write carried both: the abort and the owed re-bind.
        assert_eq!(attempt.state, AttemptState::Aborted);
        assert_eq!(
            attempt.rebind.map(|r| (r.generation, r.applied)),
            Some((2, false))
        );
        assert!(journal.binding("bind-lease-1").unwrap().teardown.is_none());
    }
    // The REJECTED envelope is quarantined; nothing was scrubbed.
    assert_eq!(s.daemon.store().outbox().quarantined().count(), 1);
    assert!(s.fake.guest_file(SANDBOX, FILE).is_some());
    let calls_at_crash = guest_calls(&s.fake).len();
    let Setup {
        dir,
        fake,
        daemon,
        server,
        ..
    } = s;
    drop(server);
    drop(daemon);

    // Restart: the owed re-bind is applied before any admission.
    let daemon = keyed_service(dir.path(), &Key::new(9));
    let applied = Mutex::new(Vec::new());
    assert!(daemon.replay_rebinds(&|id, g| {
        lock(&applied).push((id.to_owned(), g));
        Ok(())
    }));
    assert_eq!(*lock(&applied), vec![(SANDBOX.to_owned(), 2)]);
    assert!(daemon.store().journal().pending_rebinds().is_empty());
    // The resumed stop answers the same refusal, idempotently.
    let rebinds = Mutex::new(Vec::new());
    for _ in 0..2 {
        let verdict = daemon.teardown(
            &fake,
            &request("stop-1", TeardownPath::Stop, false),
            None,
            &always,
            &|g| {
                lock(&rebinds).push(g);
                Ok(())
            },
        );
        assert!(
            matches!(verdict, TeardownVerdict::Refused(_)),
            "{verdict:?}"
        );
    }
    assert_eq!(
        guest_calls(&fake).len(),
        calls_at_crash,
        "replay touches no guest"
    );
    assert!(lock(&rebinds).is_empty(), "already applied: nothing owed");
    assert_nothing_at_rest(dir.path());
}

/// Rearm: A commits → B is REJECTED → the user stop is refused
/// and its attempt aborted in the same write as the re-bind; the guest
/// rewrites A; the next stop opens a new attempt and captures A again (new
/// captureId, higher captureSeq) carrying the new bytes, instead of joining.
#[test]
fn rearm_after_a_refused_stop_captures_the_live_files_again() {
    let s = Setup::new(
        vec![lease("lease-1", SpecLeaseAction::Inject, None), lease_b()],
        true,
    );
    s.fake.set_guest_file(SANDBOX, FILE, b"token: A-first");
    s.ack(
        "bind-lease-b",
        Some((
            CaptureAckOutcome::Rejected,
            Some(CaptureAckReason::BindingClosed),
        )),
    );
    let rebinds = Mutex::new(Vec::new());
    let rebind = |g| {
        lock(&rebinds).push(g);
        Ok(())
    };
    let first = s.daemon.teardown(
        &s.fake,
        &request("stop-1", TeardownPath::Stop, false),
        None,
        &always,
        &rebind,
    );
    let TeardownVerdict::Refused(outcomes) = first else {
        panic!("expected a refusal, got {first:?}");
    };
    let a = outcomes
        .iter()
        .find(|o| o.binding_id == "bind-lease-1")
        .unwrap();
    assert!(matches!(
        a.capture,
        TeardownCaptureV11::Acked {
            outcome: CaptureAckOutcome::Committed,
            ..
        }
    ));
    let first_a = capture_id(a);
    assert_eq!(*lock(&rebinds), vec![2]);
    assert!(!s.kinds().contains(&"scrubbed"), "a refusal never scrubs");
    let first_attempt = s
        .daemon
        .store()
        .journal()
        .teardown_attempt(SANDBOX)
        .unwrap()
        .clone();
    assert_eq!(first_attempt.state, AttemptState::Aborted);
    assert_eq!(first_attempt.rebind.map(|r| r.applied), Some(true));

    // Guest work resumed and rewrote A; B now commits.
    s.fake.set_guest_file(SANDBOX, FILE, b"token: A-second");
    s.ack("bind-lease-b", Some((CaptureAckOutcome::Committed, None)));
    let mut second_req = request("stop-2", TeardownPath::Stop, false);
    second_req.generation = 3;
    let outcomes = proceed(
        s.daemon
            .teardown(&s.fake, &second_req, None, &always, &rebind),
    );
    let attempt = s
        .daemon
        .store()
        .journal()
        .teardown_attempt(SANDBOX)
        .unwrap()
        .clone();
    assert_ne!(attempt.attempt_id, first_attempt.attempt_id, "never joined");
    let a = outcomes
        .iter()
        .find(|o| o.binding_id == "bind-lease-1")
        .unwrap();
    assert_ne!(capture_id(a), first_a, "fresh capture id");
    let opened = s.opened("bind-lease-1");
    assert_eq!(opened.len(), 2);
    assert!(opened[1].1 > opened[0].1, "higher captureSeq");
    assert!(contains(&opened[0].3, b"A-first"));
    assert!(contains(&opened[1].3, b"A-second"));
    assert!(
        outcomes
            .iter()
            .all(|o| o.scrub == TeardownScrubV11::Verified)
    );
    assert_eq!(*lock(&rebinds), vec![2]);
    s.assert_nothing_at_rest();
}

/// Teardown joining: local expiry and the server's expiry STOP at the same
/// deadline make ONE capture and both report the same captureId; whichever
/// starts second joins without taking (or preempting) the guest slot —
/// including expiry joining a user stop that holds the slot.
#[test]
fn concurrent_teardowns_join_one_capture_without_preempting_the_runner() {
    let expiry = TeardownPath::Expiry { destroy: false };
    for (first, second) in [
        (
            ("local-expiry:1:1", expiry, true),
            ("expiry-stop", TeardownPath::Stop, true),
        ),
        (
            ("stop-1", TeardownPath::Stop, false),
            ("local-expiry:1:1", expiry, true),
        ),
    ] {
        let s = Setup::new(vec![lease("lease-1", SpecLeaseAction::Inject, None)], true);
        s.fake.set_guest_file(SANDBOX, FILE, ROTATED);
        s.fake.hold_credential_op("pack");
        let run = |(op, path, system): (&'static str, TeardownPath, bool)| {
            let daemon = s.daemon.clone();
            let fake = s.fake.clone();
            std::thread::spawn(move || {
                daemon.teardown(&fake, &request(op, path, system), None, &always, &no_rebind)
            })
        };
        let a = run(first);
        until(|| guest_calls(&s.fake).contains(&"pack".to_owned()));
        let b = run(second);
        std::thread::sleep(Duration::from_millis(150));
        assert!(!b.is_finished(), "the joiner waits for the runner");
        s.fake.release_credential_op("pack");
        let a = proceed(a.join().unwrap());
        let b = proceed(b.join().unwrap());
        assert_eq!(a, b, "both receipts report the same outcomes");
        assert!(matches!(
            a[0].capture,
            TeardownCaptureV11::Acked {
                outcome: CaptureAckOutcome::Committed,
                ..
            }
        ));
        assert_eq!(
            s.calls().iter().filter(|op| *op == "pack").count(),
            1,
            "one capture per binding per attempt"
        );
        assert_eq!(s.opened("bind-lease-1").len(), 1);
        s.assert_nothing_at_rest();
    }
}

/// A kill superseding a stop that already captured joins its attempt: the
/// same captureId, no second pack.
#[test]
fn kill_during_stop_joins_the_open_attempt() {
    let s = Setup::new(vec![lease("lease-1", SpecLeaseAction::Inject, None)], true);
    let stop = proceed(s.daemon.teardown(
        &s.fake,
        &request("stop-1", TeardownPath::Stop, false),
        None,
        &always,
        &no_rebind,
    ));
    // The VM stop never completed (superseded): no settlement.
    let kill = proceed(s.daemon.teardown(
        &s.fake,
        &request("kill-1", TeardownPath::Kill, false),
        None,
        &always,
        &no_rebind,
    ));
    assert_eq!(capture_id(&stop[0]), capture_id(&kill[0]));
    assert_eq!(s.calls().iter().filter(|op| *op == "pack").count(), 1);
    let attempt = s
        .daemon
        .store()
        .journal()
        .teardown_attempt(SANDBOX)
        .unwrap()
        .clone();
    assert_eq!(
        attempt.op_ids,
        vec!["stop-1".to_owned(), "kill-1".to_owned()]
    );
    // After a restart (no runner in memory) a joiner still reuses the
    // recorded capture: no pack, the same captureId from the journal.
    let Setup {
        dir,
        fake,
        server,
        daemon,
        ..
    } = s;
    drop(server);
    drop(daemon);
    let daemon = keyed_service(dir.path(), &Key::new(9));
    let calls = guest_calls(&fake).len();
    let again = proceed(daemon.teardown(
        &fake,
        &request("kill-2", TeardownPath::Kill, false),
        None,
        &always,
        &no_rebind,
    ));
    assert_eq!(capture_id(&again[0]), capture_id(&stop[0]));
    assert!(!guest_calls(&fake)[calls..].contains(&"pack".to_owned()));
}

/// Scheduler: a free revoked after sealing records its binding
/// teardown under the open attempt; the superseding stop joins it and
/// uploads that envelope instead of packing again.
#[test]
fn revoked_free_records_its_capture_and_the_superseding_stop_joins_it() {
    let s = Setup::new(vec![lease("lease-1", SpecLeaseAction::Inject, None)], true);
    s.fake.set_guest_file(SANDBOX, FILE, ROTATED);
    let checks = AtomicUsize::new(0);
    // Wanted until the seal is durable, revoked right after.
    let wanted = || checks.fetch_add(1, Ordering::SeqCst) == 0;
    let free = s.daemon.capture_for_free(
        &s.fake,
        &target(b"").guest,
        OWNER,
        "free-1",
        "bind-lease-1",
        &wanted,
    );
    let FreeCapture::RevokedRecorded(entry) = free else {
        panic!("expected a recorded revoked free, got {free:?}");
    };
    assert_eq!(s.calls(), vec!["pack"], "a free never quiesces");
    let outcomes = proceed(s.daemon.teardown(
        &s.fake,
        &request("stop-1", TeardownPath::Stop, false),
        None,
        &always,
        &no_rebind,
    ));
    assert_eq!(capture_id(&outcomes[0]), entry.capture_id);
    assert_eq!(s.calls(), vec!["pack", "scrub"], "no second capture");
    let opened = s.opened("bind-lease-1");
    assert_eq!(opened.len(), 1);
    assert_eq!(opened[0].2, "free");
    s.assert_nothing_at_rest();
}

/// Scheduler: an attach/install revoked through the sandbox slot
/// abandons its 60 s bundle wait at once.
#[test]
fn revoked_install_abandons_the_bundle_wait_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let fake = FakeRuntime::default();
    let s = spec(
        vec![lease("lease-1", SpecLeaseAction::Inject, None)],
        vec![],
    );
    let bytes = serde_json::json!(&s).to_string().into_bytes();
    let daemon = service(dir.path());
    // No server answers the bundle request.
    let slot = daemon.slot(SANDBOX);
    let revoker = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        slot.slot.revoke();
    });
    let started = Instant::now();
    assert_eq!(
        daemon.launch(&fake, &target(&bytes), &s, &always),
        Err(LaunchFailure::Cancelled)
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    revoker.join().unwrap();
}

/// outcome matrix, system stop: REJECTED never scrubs, quarantines the
/// envelope and leaves the binding recovery-required (kept at settlement);
/// a system stop is never refused.
#[test]
fn system_stop_with_a_rejected_capture_stops_without_scrubbing() {
    let s = Setup::new(vec![lease("lease-1", SpecLeaseAction::Inject, None)], true);
    s.ack(
        "bind-lease-1",
        Some((
            CaptureAckOutcome::Rejected,
            Some(CaptureAckReason::DecryptFailed),
        )),
    );
    let mut req = request("access-stop", TeardownPath::Stop, true);
    req.generation = 5;
    let outcomes = proceed(s.daemon.teardown(&s.fake, &req, None, &always, &no_rebind));
    assert!(matches!(
        outcomes[0].capture,
        TeardownCaptureV11::Acked {
            outcome: CaptureAckOutcome::Rejected,
            ..
        }
    ));
    assert_eq!(outcomes[0].scrub, TeardownScrubV11::NotRun);
    assert!(!s.calls().contains(&"scrub".to_owned()));
    assert!(s.fake.guest_file(SANDBOX, FILE).is_some());
    assert_eq!(s.daemon.store().outbox().quarantined().count(), 1);
    assert_eq!(s.daemon.store().outbox().pending().count(), 0);
    s.daemon.settle_teardown(SANDBOX, false);
    assert_eq!(
        s.daemon
            .store()
            .journal()
            .binding("bind-lease-1")
            .unwrap()
            .phase,
        BindingPhase::RecoveryRequired
    );
}

/// Offline expiry: no outcome arrives; the credential phase ends
/// within its budget with a self-verified durable envelope under the newest
/// key (scrub allowed), and only the sealed envelope is at rest.
#[test]
fn offline_expiry_seals_durable_scrubs_and_stays_within_budget() {
    let s = Setup::new(vec![lease("lease-1", SpecLeaseAction::Inject, None)], true);
    s.fake.set_guest_file(SANDBOX, FILE, ROTATED);
    s.ack("bind-lease-1", None);
    let mut req = request(
        "local-expiry:1:1",
        TeardownPath::Expiry { destroy: false },
        true,
    );
    req.budget = Duration::from_millis(1500);
    let started = Instant::now();
    let outcomes = proceed(s.daemon.teardown(&s.fake, &req, None, &always, &no_rebind));
    assert!(
        started.elapsed() < Duration::from_millis(2500),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(
        outcomes[0].capture,
        TeardownCaptureV11::Durable {
            capture_id: capture_id(&outcomes[0])
        }
    );
    assert_eq!(outcomes[0].scrub, TeardownScrubV11::Verified);
    assert_eq!(s.opened("bind-lease-1")[0].2, "expiry");
    // The census lists the unresolved envelope for the server to drain.
    let census = s.daemon.store().census().unwrap();
    assert_eq!(census[0].entries[0].pending.len(), 1);
    // Destroy-on-expiry captures but never scrubs.
    let d = Setup::new(vec![lease("lease-1", SpecLeaseAction::Inject, None)], true);
    let outcomes = proceed(d.daemon.teardown(
        &d.fake,
        &request(
            "local-expiry:1:1",
            TeardownPath::Expiry { destroy: true },
            true,
        ),
        None,
        &always,
        &no_rebind,
    ));
    assert_eq!(outcomes[0].scrub, TeardownScrubV11::NotRun);
    assert_eq!(d.calls(), vec!["probe", "quiesce", "pack"]);
    s.assert_nothing_at_rest();
}

/// Enforcement loss completes while the slot state lock is held by a
/// stalled hook; bindings become recovery-required and the env is dropped.
#[test]
fn enforcement_loss_completes_with_the_slot_lock_stalled() {
    let s = Setup::new(vec![lease("lease-1", SpecLeaseAction::Inject, None)], true);
    let coord = s.daemon.slot(SANDBOX);
    let stalled = coord.slot.stall_state();
    let daemon = s.daemon.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        daemon.enforcement_loss(SANDBOX);
        let _ = tx.send(());
    });
    rx.recv_timeout(Duration::from_secs(2))
        .expect("enforcement loss must not wait on the slot lock");
    drop(stalled);
    assert!(coord.slot.is_revoked());
    assert_eq!(
        s.daemon
            .store()
            .journal()
            .binding("bind-lease-1")
            .unwrap()
            .phase,
        BindingPhase::RecoveryRequired
    );
    assert!(
        s.daemon
            .env_for(SANDBOX, Duration::ZERO)
            .unwrap()
            .is_empty()
    );
    // A later system teardown neither captures nor scrubs that binding.
    let outcomes = proceed(s.daemon.teardown(
        &s.fake,
        &request(
            "local-expiry:1:1",
            TeardownPath::Expiry { destroy: false },
            true,
        ),
        None,
        &always,
        &no_rebind,
    ));
    assert_eq!(outcomes[0].capture, TeardownCaptureV11::None);
    assert_eq!(outcomes[0].scrub, TeardownScrubV11::NotRun);
    assert!(s.calls().is_empty());
}

/// A sandbox without credential state is untouched.
#[test]
fn a_sandbox_without_credentials_needs_no_teardown() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = service(dir.path());
    let fake = FakeRuntime::default();
    assert_eq!(
        daemon.teardown(
            &fake,
            &request("stop-1", TeardownPath::Stop, false),
            None,
            &always,
            &no_rebind,
        ),
        TeardownVerdict::NoCredentials
    );
    assert!(guest_calls(&fake).is_empty());
    assert!(daemon.store().journal().teardown_attempt(SANDBOX).is_none());
}

/// A proxy-enabled sandbox whose last proxy login was freed keeps
/// its listener (403 for the freed handle) until its stop/kill, which has no
/// credential state left to tear down and still closes the listener.
#[test]
fn a_stop_after_the_last_proxy_free_closes_the_listener() {
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
    daemon.revoke_lease("lease-1");
    let addr = hub
        .listen_addr(SANDBOX)
        .expect("the listener outlives the free");
    let get = format!("GET /c/{}/x HTTP/1.1\r\nHost: gw\r\n\r\n", handles[0]).into_bytes();
    assert_eq!(
        crate::sandbox_relay::credentials::proxy::testing::exchange(addr, &get).0,
        403
    );
    let fake = FakeRuntime::default();
    assert_eq!(
        daemon.teardown(
            &fake,
            &request("stop-1", TeardownPath::Stop, false),
            None,
            &always,
            &no_rebind,
        ),
        TeardownVerdict::NoCredentials
    );
    assert!(
        hub.listen_addr(SANDBOX).is_none(),
        "the stop closed the listener"
    );
}

/// Capture eligibility matches the server's
/// (`definitionCapturesFiles`): only a lease that declares a path to install
/// (required or optional) is captured. An env-only lease and one declaring
/// only `exclude` paths have nothing to capture; the server releases them
/// without waiting for a capture.
#[test]
fn final_2_only_leases_declaring_paths_are_captured() {
    use crate::sandbox_relay::credentials::journal::{BindingPhase, BindingPurpose, BindingRecord};
    use crate::sandbox_relay::credentials::service::teardown::capturable;
    let binding = |files: SpecFilesV11| {
        let mut spec = lease("lease-1", SpecLeaseAction::Inject, Some("bind-1"));
        spec.files = files;
        BindingRecord {
            binding_id: "bind-1".into(),
            lease_id: "lease-1".into(),
            sandbox_id: SANDBOX.into(),
            credential_id: spec.credential_id.clone(),
            instance_id: spec.instance_id.clone(),
            spec_digest: "ab".repeat(32),
            copy_back: true,
            exclusive: true,
            purpose: BindingPurpose::Install,
            install_intent: None,
            installed_seq: Some(1),
            phase: BindingPhase::Active,
            teardown: None,
            scrubbed_verified: false,
            spec: Some(spec),
            proxy_handles: vec![],
        }
    };
    let paths = |required: &[&str], optional: &[&str], exclude: &[&str]| SpecFilesV11 {
        required: required.iter().map(|p| (*p).to_owned()).collect(),
        optional: optional.iter().map(|p| (*p).to_owned()).collect(),
        exclude: exclude.iter().map(|p| (*p).to_owned()).collect(),
    };
    assert!(capturable(&binding(paths(&[".config/tool"], &[], &[]))));
    assert!(capturable(&binding(paths(&[], &[".config/tool"], &[]))));
    assert!(!capturable(&binding(paths(&[], &[], &[]))), "env-only");
    assert!(
        !capturable(&binding(paths(&[], &[], &[".config/tool/cache"]))),
        "exclude-only declares nothing to capture"
    );
}
