//! Live attach / free tests over FakeRuntime and the scripted server:
//! env present after a live attach and gone after its free,
//! the free's capture (pack without quiesce, no quiesce ever) → COMMITTED →
//! scrub, `skip`, a REJECTED free that revokes env but never scrubs, a pack
//! error that scrubs anyway, an attach failure that keeps a sibling's env,
//! and a sentinel check that no plaintext is ever at rest.

use super::*;
use sandbox_protocol::{TeardownCaptureV11, TeardownScrubV11};

const ROTATED: &[u8] = b"token: ROTATED-BEFORE-FREE-c10";

struct Live {
    dir: tempfile::TempDir,
    fake: FakeRuntime,
    key: Key,
    daemon: CredentialService,
    server: FakeServer,
    script: Script,
}

impl Live {
    /// A running sandbox with no login, then a live attach of `lease-1`.
    fn attached() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key = Key::new(7);
        let fake = FakeRuntime::default();
        let attach = attach_spec();
        let script = Script::new(&attach);
        let daemon = keyed_service(dir.path(), &key);
        let server = FakeServer::start(&daemon, script.clone());
        assert!(daemon.env_for(SANDBOX, Duration::ZERO).unwrap().is_empty());
        let receipt = daemon
            .attach(&fake, &target(&script.spec), &attach, &always)
            .unwrap();
        // The attach receipt repeats the `installed` report.
        assert_eq!(
            receipt
                .iter()
                .map(|r| r.lease_id.as_str())
                .collect::<Vec<_>>(),
            vec!["lease-1"]
        );
        Self {
            dir,
            fake,
            key,
            daemon,
            server,
            script,
        }
    }

    fn free(&self, skip: bool) -> Vec<sandbox_protocol::CredentialTeardownOutcomeV11> {
        self.daemon
            .free(
                &self.fake,
                &target(b"").guest,
                OWNER,
                "op-free-1",
                &free_spec(skip),
                &always,
            )
            .unwrap()
    }

    fn opened(&self) -> Vec<Vec<u8>> {
        lock(&self.server.envelopes)
            .iter()
            .map(|bytes| {
                let parsed =
                    crate::sandbox_relay::credentials::envelope::parse(bytes.clone()).unwrap();
                testing::open(
                    &self.key.private,
                    &self.key.public,
                    parsed.seal(),
                    &parsed.header.aad,
                )
                .unwrap()
                .expose()
                .to_vec()
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

fn attach_spec() -> CredentialSpecV11 {
    spec(
        vec![lease("lease-1", SpecLeaseAction::Inject, None)],
        vec![],
    )
}

fn free_spec(skip: bool) -> CredentialSpecV11 {
    let action = if skip {
        SpecLeaseAction::ScrubOnly
    } else {
        SpecLeaseAction::None
    };
    spec(vec![lease("lease-1", action, Some("bind-lease-1"))], vec![])
}

fn token(daemon: &CredentialService) -> Option<String> {
    daemon
        .env_for(SANDBOX, Duration::ZERO)
        .unwrap()
        .into_iter()
        .find(|(name, _)| name == "TOOL_TOKEN")
        .map(|(_, value)| value)
}

/// Lane e2e: live attach → env and files present (new commands and
/// terminals see them) → the guest rotates the file → free → pack (no
/// quiesce) → seal → upload → COMMITTED → env revoked → scrub → binding
/// forgotten. The envelope carries the rotated bytes; nothing is at rest.
#[test]
fn live_attach_installs_env_and_free_captures_revokes_and_scrubs() {
    let s = Live::attached();
    assert_eq!(
        token(&s.daemon).as_deref().map(str::as_bytes),
        Some(SENTINEL)
    );
    assert_eq!(
        s.daemon.installed_env_leases(SANDBOX),
        BTreeSet::from(["lease-1".to_owned()])
    );
    assert_eq!(
        s.fake.guest_file(SANDBOX, FILE).as_deref(),
        Some(FILE_SENTINEL)
    );
    // drain() wakes the attach worker before the fake server appends to its
    // observation log. Wait for that observation before asserting its order.
    wait_until(|| s.server.kinds().len() >= 2);
    assert_eq!(s.server.kinds(), vec!["bundle.request", "installed"]);
    assert_eq!(
        s.daemon
            .store()
            .journal()
            .binding("bind-lease-1")
            .unwrap()
            .phase,
        BindingPhase::Active
    );

    s.fake.set_guest_file(SANDBOX, FILE, ROTATED);
    let calls_before = guest_calls(&s.fake).len();
    let outcomes = s.free(false);
    assert_eq!(
        guest_calls(&s.fake)[calls_before..].to_vec(),
        vec!["pack", "scrub"],
        "a free never quiesces"
    );
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].lease_id.as_deref(), Some("lease-1"));
    assert_eq!(outcomes[0].binding_id, "bind-lease-1");
    assert!(matches!(
        outcomes[0].capture,
        TeardownCaptureV11::Acked {
            outcome: CaptureAckOutcome::Committed,
            ..
        }
    ));
    assert_eq!(outcomes[0].scrub, TeardownScrubV11::Verified);
    assert!(sandbox_protocol::valid_teardown_outcomes(&outcomes));
    // Env gone at once; files gone; the settled binding is forgotten.
    assert_eq!(token(&s.daemon), None);
    assert!(s.daemon.installed_env_leases(SANDBOX).is_empty());
    assert!(s.fake.guest_file(SANDBOX, FILE).is_none());
    assert!(s.daemon.store().journal().binding("bind-lease-1").is_none());
    assert_eq!(s.daemon.store().outbox().pending().count(), 0);
    let kinds = s.server.kinds();
    assert_eq!(kinds.last(), Some(&"scrubbed"));
    let opened = s.opened();
    assert_eq!(opened.len(), 1);
    assert!(contains(&opened[0], ROTATED));
    s.assert_nothing_at_rest();
}

/// `credentialCapture: "skip"`: no capture, env revoked, files scrubbed.
#[test]
fn skip_free_scrubs_without_capturing() {
    let s = Live::attached();
    let calls_before = guest_calls(&s.fake).len();
    let outcomes = s.free(true);
    assert_eq!(guest_calls(&s.fake)[calls_before..].to_vec(), vec!["scrub"]);
    assert_eq!(outcomes[0].capture, TeardownCaptureV11::None);
    assert_eq!(outcomes[0].scrub, TeardownScrubV11::Verified);
    assert!(lock(&s.server.envelopes).is_empty());
    assert_eq!(token(&s.daemon), None);
    s.assert_nothing_at_rest();
}

/// Free, REJECTED: env revoked at once, never a scrub; the binding
/// stays capturable so the next teardown captures the live files again.
#[test]
fn rejected_free_revokes_env_but_never_scrubs() {
    let s = Live::attached();
    lock(&s.script.binding_acks).insert(
        "bind-lease-1".into(),
        Some((
            CaptureAckOutcome::Rejected,
            Some(CaptureAckReason::ContextMismatch),
        )),
    );
    let outcomes = s.free(false);
    assert!(matches!(
        outcomes[0].capture,
        TeardownCaptureV11::Acked {
            outcome: CaptureAckOutcome::Rejected,
            ..
        }
    ));
    assert_eq!(outcomes[0].scrub, TeardownScrubV11::NotRun);
    assert_eq!(token(&s.daemon), None, "env revoked even when rejected");
    assert_eq!(
        s.fake.guest_file(SANDBOX, FILE).as_deref(),
        Some(FILE_SENTINEL),
        "REJECTED never scrubs"
    );
    let journal = s.daemon.store().journal();
    assert_eq!(
        journal.binding("bind-lease-1").unwrap().phase,
        BindingPhase::Active
    );
    drop(journal);
    s.assert_nothing_at_rest();
}

/// Free, pack error: the owner chose removal — revoke and scrub anyway.
#[test]
fn pack_error_on_free_still_revokes_and_scrubs() {
    let s = Live::attached();
    s.fake.fail_credential_op("pack", 1);
    let outcomes = s.free(false);
    assert!(matches!(
        outcomes[0].capture,
        TeardownCaptureV11::Failed { .. }
    ));
    assert_eq!(outcomes[0].scrub, TeardownScrubV11::Verified);
    assert_eq!(token(&s.daemon), None);
    assert!(s.fake.guest_file(SANDBOX, FILE).is_none());
    s.assert_nothing_at_rest();
}

/// Offline (no outcome): the envelope is durable under the current key, so
/// the free scrubs, but the binding is kept non-capturable until the commit.
#[test]
fn offline_free_scrubs_a_durable_envelope_and_keeps_the_binding() {
    let s = Live::attached();
    lock(&s.script.binding_acks).insert("bind-lease-1".into(), None);
    let outcomes = s.free(false);
    assert!(matches!(
        outcomes[0].capture,
        TeardownCaptureV11::Durable { .. }
    ));
    assert_eq!(outcomes[0].scrub, TeardownScrubV11::Verified);
    assert_eq!(s.daemon.store().outbox().pending().count(), 1);
    assert_eq!(
        s.daemon
            .store()
            .journal()
            .binding("bind-lease-1")
            .unwrap()
            .phase,
        BindingPhase::Stopped
    );
    s.assert_nothing_at_rest();
}

/// A failed attach drops only its own lease's env: a sibling installed by
/// the create keeps its env.
#[test]
fn failed_attach_keeps_a_siblings_env() {
    let dir = tempfile::tempdir().unwrap();
    let fake = FakeRuntime::default();
    let create = attach_spec();
    let mut script = Script::new(&create);
    let daemon = service(dir.path());
    let server = FakeServer::start(&daemon, script.clone());
    daemon
        .launch(&fake, &target(&script.spec), &create, &always)
        .unwrap();
    drop(server);
    // The second login's bundle is refused.
    let mut second = lease("lease-2", SpecLeaseAction::Inject, None);
    second.files.required = vec![".config/other".into()];
    let attach = spec(vec![second], vec![]);
    script.refuse_bundles = true;
    let _server = FakeServer::start(&daemon, script.clone());
    assert_eq!(
        daemon.attach(&fake, &target(&script.spec), &attach, &always),
        Err(LaunchFailure::Install)
    );
    assert_eq!(
        daemon.installed_env_leases(SANDBOX),
        BTreeSet::from(["lease-1".to_owned()])
    );
    assert_eq!(token(&daemon).as_deref().map(str::as_bytes), Some(SENTINEL));
    assert_nothing_at_rest(dir.path());
}

/// Attach accepts only `inject` leases and `scrub` residue.
#[test]
fn attach_refuses_a_recovery_spec() {
    let dir = tempfile::tempdir().unwrap();
    let fake = FakeRuntime::default();
    let daemon = service(dir.path());
    let s = recovery_spec();
    assert_eq!(
        daemon.attach(&fake, &target(b""), &s, &always),
        Err(LaunchFailure::SpecInvalid)
    );
    assert!(guest_calls(&fake).is_empty());
}

/// A free whose guest slot stays busy touches nothing (retryable); the
/// lease keeps its env.
#[test]
fn busy_slot_free_touches_nothing() {
    let s = Live::attached();
    let coord = s.daemon.slot(SANDBOX);
    let permit = Arc::new(sandbox_runtime::RuntimePermit::with_timeout(
        Duration::from_secs(60),
    ));
    let _held = coord
        .slot
        .try_acquire(SlotUser::Checkpoint, &permit)
        .unwrap();
    let calls_before = guest_calls(&s.fake).len();
    let started = Instant::now();
    let refused = s.daemon.free(
        &s.fake,
        &target(b"").guest,
        OWNER,
        "op-free-busy",
        &free_spec(false),
        &always,
    );
    assert_eq!(refused, Err(FreeFailure::Busy));
    assert!(started.elapsed() >= crate::sandbox_relay::credentials::slot::ATTACH_FREE_SLOT_WAIT);
    assert_eq!(guest_calls(&s.fake).len(), calls_before);
    assert_eq!(
        token(&s.daemon).as_deref().map(str::as_bytes),
        Some(SENTINEL)
    );
}

/// Terminals: the env a shell is opened with comes with its lease ids, and a
/// freed lease is no longer installed (the terminal host closes the shell).
#[test]
fn terminal_env_carries_its_leases_until_free() {
    let s = Live::attached();
    let (env, leases) = s.daemon.env_with_leases(SANDBOX).unwrap();
    assert!(env.iter().any(|(name, _)| name == "TOOL_TOKEN"));
    assert_eq!(leases, BTreeSet::from(["lease-1".to_owned()]));
    s.free(true);
    let (env, leases) = s.daemon.env_with_leases(SANDBOX).unwrap();
    assert!(env.is_empty() && leases.is_empty());
    assert!(
        !BTreeSet::from(["lease-1".to_owned()]).is_subset(&s.daemon.installed_env_leases(SANDBOX))
    );
}

// Login finish -----------------------------------------

const LOGGED_IN: &[u8] = b"token: FRESH-LOGIN-c12";

/// A login sandbox: no attach (no bundle ever), the user logged in through
/// the terminal and the CLI wrote its files.
struct LoginSandbox {
    dir: tempfile::TempDir,
    fake: FakeRuntime,
    key: Key,
    daemon: CredentialService,
    server: FakeServer,
    script: Script,
}

fn login_lease() -> SpecLeaseV11 {
    let mut l = lease("lease-login", SpecLeaseAction::None, Some("bind-login"));
    l.kind = CredentialLeaseKind::Login;
    l.copy_back = false;
    l
}

impl LoginSandbox {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key = Key::new(11);
        let fake = FakeRuntime::default();
        let script = Script::new(&spec(vec![login_lease()], vec![]));
        let daemon = keyed_service(dir.path(), &key);
        let server = FakeServer::start(&daemon, script.clone());
        fake.set_guest_file(SANDBOX, FILE, LOGGED_IN);
        Self {
            dir,
            fake,
            key,
            daemon,
            server,
            script,
        }
    }

    fn finish(&self, op: &str) -> Vec<sandbox_protocol::CredentialTeardownOutcomeV11> {
        self.daemon
            .free(
                &self.fake,
                &target(b"").guest,
                OWNER,
                op,
                &spec(vec![login_lease()], vec![]),
                &always,
            )
            .unwrap()
    }

    /// (captureSeq, kind, plaintext) of every envelope the server received.
    fn opened(&self) -> Vec<(u64, String, Vec<u8>)> {
        lock(&self.server.envelopes)
            .iter()
            .map(|bytes| {
                let parsed =
                    crate::sandbox_relay::credentials::envelope::parse(bytes.clone()).unwrap();
                let aad = parsed.header.aad.clone();
                let plain = testing::open(
                    &self.key.private,
                    &self.key.public,
                    parsed.seal(),
                    &parsed.header.aad,
                )
                .unwrap()
                .expose()
                .to_vec();
                (aad.capture_seq, aad.kind, plain)
            })
            .collect()
    }

    fn assert_nothing_at_rest(&self) {
        for bytes in every_file_under(self.dir.path()) {
            assert!(!contains(&bytes, LOGGED_IN), "login value at rest");
        }
        let text = format!("{:?}", self.server.frames());
        assert!(!contains(text.as_bytes(), LOGGED_IN));
    }
}

/// Initial save: the LOGIN binding (granted without a bundle) is recorded
/// from the finish's spec, the guest files are packed without quiesce and
/// sealed as kind `login`, COMMITTED settles the binding — and nothing is
/// scrubbed: the server destroys the login sandbox next.
#[test]
fn login_finish_captures_kind_login_and_never_scrubs() {
    let s = LoginSandbox::new();
    assert!(s.daemon.store().journal().binding("bind-login").is_none());
    let outcomes = s.finish("op-finish-1");
    assert_eq!(
        guest_calls(&s.fake),
        vec!["pack"],
        "pack only: no quiesce, no scrub"
    );
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].lease_id.as_deref(), Some("lease-login"));
    assert_eq!(outcomes[0].binding_id, "bind-login");
    assert!(matches!(
        outcomes[0].capture,
        TeardownCaptureV11::Acked {
            outcome: CaptureAckOutcome::Committed,
            ..
        }
    ));
    assert_eq!(outcomes[0].scrub, TeardownScrubV11::NotRun);
    assert!(sandbox_protocol::valid_teardown_outcomes(&outcomes));
    let opened = s.opened();
    assert_eq!(opened.len(), 1);
    assert_eq!((opened[0].0, opened[0].1.as_str()), (1, "login"));
    assert!(contains(&opened[0].2, LOGGED_IN));
    assert_eq!(
        s.fake.guest_file(SANDBOX, FILE).as_deref(),
        Some(LOGGED_IN),
        "a login finish never scrubs"
    );
    assert!(s.daemon.store().journal().binding("bind-login").is_none());
    assert_eq!(s.daemon.store().outbox().pending().count(), 0);
    assert!(!s.server.kinds().contains(&"scrubbed"));
    s.assert_nothing_at_rest();
}

/// A login that was not saved (DISCARDED{incomplete}) keeps the LOGIN
/// binding live: the user fixes the login and finishes again, which packs
/// again under a higher `captureSeq`.
#[test]
fn unsaved_login_keeps_the_binding_for_a_retry() {
    let s = LoginSandbox::new();
    lock(&s.script.binding_acks).insert(
        "bind-login".into(),
        Some((
            CaptureAckOutcome::Discarded,
            Some(CaptureAckReason::Incomplete),
        )),
    );
    let first = s.finish("op-finish-1");
    assert!(matches!(
        first[0].capture,
        TeardownCaptureV11::Acked {
            outcome: CaptureAckOutcome::Discarded,
            ..
        }
    ));
    assert_eq!(first[0].scrub, TeardownScrubV11::NotRun);
    let binding = s
        .daemon
        .store()
        .journal()
        .binding("bind-login")
        .cloned()
        .unwrap();
    assert_eq!(binding.purpose, BindingPurpose::Login);
    assert_eq!(binding.phase, BindingPhase::Active);

    lock(&s.script.binding_acks).remove("bind-login");
    s.fake
        .set_guest_file(SANDBOX, FILE, b"token: FRESH-LOGIN-c12 retried");
    let second = s.finish("op-finish-2");
    assert!(matches!(
        second[0].capture,
        TeardownCaptureV11::Acked {
            outcome: CaptureAckOutcome::Committed,
            ..
        }
    ));
    let seqs: Vec<(u64, String)> = s
        .opened()
        .into_iter()
        .map(|(seq, kind, _)| (seq, kind))
        .collect();
    assert_eq!(seqs, vec![(1, "login".into()), (2, "login".into())]);
    assert!(s.daemon.store().journal().binding("bind-login").is_none());
    s.assert_nothing_at_rest();
}

/// Offline finish: the login envelope is durable and stays in the outbox
/// (never evicted); the binding stays recorded; nothing is scrubbed.
#[test]
fn offline_login_finish_keeps_a_durable_envelope() {
    let s = LoginSandbox::new();
    lock(&s.script.binding_acks).insert("bind-login".into(), None);
    let outcomes = s.finish("op-finish-1");
    assert!(matches!(
        outcomes[0].capture,
        TeardownCaptureV11::Durable { .. }
    ));
    assert_eq!(outcomes[0].scrub, TeardownScrubV11::NotRun);
    assert_eq!(s.daemon.store().outbox().pending().count(), 1);
    assert!(s.daemon.store().journal().binding("bind-login").is_some());
    assert_eq!(guest_calls(&s.fake), vec!["pack"]);
}

/// The teardown rule stands: a teardown (cancel / expiry / the destroy after a
/// save) never captures or scrubs a LOGIN binding.
#[test]
fn teardown_never_captures_a_login_binding() {
    let s = LoginSandbox::new();
    lock(&s.script.binding_acks).insert(
        "bind-login".into(),
        Some((
            CaptureAckOutcome::Discarded,
            Some(CaptureAckReason::Incomplete),
        )),
    );
    s.finish("op-finish-1");
    let calls_before = guest_calls(&s.fake).len();
    let envelopes_before = lock(&s.server.envelopes).len();
    let verdict = s.daemon.teardown(
        &s.fake,
        &TeardownRequest {
            operation_id: "op-kill-1".into(),
            guest: target(b"").guest,
            sandbox_owner_id: OWNER.into(),
            host_owner_id: None,
            path: TeardownPath::Kill,
            system: false,
            skip: false,
            spec_unverified: false,
            generation: 2,
            budget: Duration::from_secs(10),
        },
        None,
        &always,
        &|_| panic!("a proceeding teardown never re-binds"),
    );
    assert!(matches!(verdict, TeardownVerdict::Proceed(_)));
    assert!(
        !guest_calls(&s.fake)[calls_before..]
            .iter()
            .any(|c| c == "pack" || c == "scrub"),
        "no capture or scrub of a LOGIN binding"
    );
    assert_eq!(lock(&s.server.envelopes).len(), envelopes_before);
}

/// A login finish spec is never a `skip`, and a workload binding id cannot
/// be finished as a login (or the reverse).
#[test]
fn login_finish_refuses_skip_and_mismatched_bindings() {
    let s = LoginSandbox::new();
    let mut skip = login_lease();
    skip.action = SpecLeaseAction::ScrubOnly;
    let refused = s.daemon.free(
        &s.fake,
        &target(b"").guest,
        OWNER,
        "op-finish-1",
        &spec(vec![skip], vec![]),
        &always,
    );
    assert_eq!(refused.unwrap_err(), FreeFailure::SpecInvalid);
    // A recorded LOGIN binding freed by a workload spec.
    lock(&s.script.binding_acks).insert(
        "bind-login".into(),
        Some((
            CaptureAckOutcome::Discarded,
            Some(CaptureAckReason::Incomplete),
        )),
    );
    s.finish("op-finish-2");
    let mut workload = login_lease();
    workload.kind = CredentialLeaseKind::Workload;
    workload.copy_back = true;
    let refused = s.daemon.free(
        &s.fake,
        &target(b"").guest,
        OWNER,
        "op-free-3",
        &spec(vec![workload], vec![]),
        &always,
    );
    assert_eq!(refused.unwrap_err(), FreeFailure::SpecInvalid);
}
