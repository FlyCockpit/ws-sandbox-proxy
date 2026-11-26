//! Key refusals must preserve possible-effect history and cleanup authority.
use super::*;
use crate::sandbox_relay::test_support::FixtureRuntime;
use sandbox_protocol::{JournalKeyInstall, SandboxLifecycleState, parse_daemon_control};
use sandbox_runtime::{CreateSandboxRequest, FakeRuntime};
use std::net::{TcpListener, TcpStream};

fn binding() -> TransportBindingV11 {
    TransportBindingV11 {
        server: "wss://example.test/ws/sandbox-host".into(),
        host_owner_id: "owner".into(),
        host_id: "host".into(),
    }
}
fn key(binding: &TransportBindingV11, id: &str) -> JournalKeyInstall {
    JournalKeyInstall {
        connection_epoch: 1,
        key_version: 1,
        key_id: id.repeat(32),
        key_hex: "ab".repeat(32),
        server: binding.server.clone(),
        host_owner_id: binding.host_owner_id.clone(),
        host_id: binding.host_id.clone(),
    }
}
fn dispatch(kind: &str) -> OperationDispatch {
    let mut value = serde_json::json!({"sandboxOwnerId":"owner", "operationId":"work", "sandboxId":"sbx", "kind":kind,
        "generation":1, "attempt":1, "idempotencyKey":"work", "bodyHash":"a".repeat(64),
        "digestScheme":"hmac-sha256-v1", "digestKeyId":"d".repeat(32), "env":[["K","private-value"]],
        "lease":sandbox_protocol::HostLease::for_test()});
    if matches!(kind, "sandbox.create" | "sandbox.reconnect") {
        value["cpuCount"] = serde_json::json!(1);
        value["memoryMiB"] = serde_json::json!(1024);
    }
    serde_json::from_value(value).unwrap()
}
fn sockets() -> (
    tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<TcpStream>>,
    tungstenite::WebSocket<TcpStream>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (peer, _) = listener.accept().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    (
        tungstenite::WebSocket::from_raw_socket(
            tungstenite::stream::MaybeTlsStream::Plain(tcp),
            tungstenite::protocol::Role::Client,
            None,
        ),
        tungstenite::WebSocket::from_raw_socket(peer, tungstenite::protocol::Role::Server, None),
    )
}

#[test]
fn digest_refusal_after_receipt_keeps_slot() {
    use super::super::journal::ReceiptPhase;
    for phase in [
        ReceiptPhase::Intent,
        ReceiptPhase::Effect,
        ReceiptPhase::Result,
    ] {
        for pruned in [false, true] {
            for refusal in [
                "missing",
                "changed",
                "wrong-id",
                "mismatch",
                "invalid",
                "cleanup-downgrade",
                "same",
            ] {
                // Include create for the Effect + replacement-key capacity regression.
                for kind in ["command.run", "sandbox.create"] {
                    if refusal == "same" && !pruned {
                        continue;
                    }
                    let dir = tempfile::tempdir().unwrap();
                    let binding = binding();
                    let journal = Arc::new(
                        crate::sandbox_relay::test_support::open_journal(dir.path(), &binding)
                            .unwrap(),
                    );
                    journal
                        .install_key(&key(&binding, "d"), &binding, 1)
                        .unwrap();
                    let mut incoming = dispatch(kind);
                    journal
                        .record_fixture_intent(
                            &journal.prepare_dispatch(&binding, &incoming).unwrap(),
                        )
                        .unwrap();
                    if phase != ReceiptPhase::Intent {
                        journal.record_effect("work").unwrap();
                    }
                    if phase == ReceiptPhase::Result {
                        journal
                            .record_result("work", OperationState::Succeeded, None, None, None)
                            .unwrap();
                    }
                    if pruned {
                        journal.seed_pruned_receipt_for_test("work");
                    }
                    let prior = journal.lookup("work").unwrap();
                    match refusal {
                        "missing" => journal.clear_key(),
                        "changed" => journal
                            .install_key(&key(&binding, "e"), &binding, 1)
                            .unwrap(),
                        "wrong-id" => incoming.digest_key_id = Some("0".repeat(32)),
                        "mismatch" => {
                            incoming.env = Some(vec![("K".into(), "changed-value".into())])
                        }
                        "invalid" => incoming.idempotency_key.clear(),
                        "cleanup-downgrade" => {
                            journal.clear_key();
                            incoming.kind = "sandbox.kill".into();
                            incoming.cpu_count = None;
                            incoming.memory_mi_b = None;
                            incoming.env = None;
                            incoming.digest_scheme = Some("sha256-env-free-v1".into());
                            incoming.digest_key_id = None;
                        }
                        "same" => {}
                        _ => unreachable!(),
                    }
                    let runtime = Arc::new(FakeRuntime::new());
                    let mut authority = HostAuthority::default();
                    let relay = RelaySupervisor::start(
                        runtime.clone(),
                        journal.clone(),
                        authority.clone(),
                        None,
                    );
                    let mut admission = crate::sandbox_relay::test_support::admission(
                        1,
                        crate::sandbox_relay::live_admission::test_capacity(),
                    );
                    admission
                        .try_acquire(
                            "sbx",
                            "work",
                            1,
                            sandbox_protocol::VmSize::defaults().unwrap(),
                        )
                        .unwrap();
                    let (mut socket, mut wire) = sockets();
                    let incoming = crate::sandbox_relay::test_support::pinned_dispatch(&incoming);
                    handle_dispatch(
                        &mut socket,
                        sandbox_protocol::WireCodes::negotiated(
                            sandbox_protocol::SANDBOX_RELAY_PROTOCOL_VERSION,
                        ),
                        &mut authority,
                        &mut admission,
                        (&journal, &binding),
                        &relay,
                        &None,
                        &mut HashMap::new(),
                        &incoming,
                    )
                    .unwrap();
                    let result =
                        parse_daemon_control(wire.read().unwrap().to_text().unwrap()).unwrap();
                    assert!(
                        matches!(
                            &result,
                            DaemonControlMessage::OperationResult {
                                state: OperationState::UnknownOutcome,
                                error: Some(ProtocolErrorDetail { reason: None,
                                    code,
                                    ..
                                }),
                                ..
                            } if *code == if pruned { SandboxErrorCode::ReceiptDigestPruned } else { SandboxErrorCode::UnknownOutcome }
                        ),
                        "{phase:?}/{pruned}/{refusal}/{kind}: {result:?}"
                    );
                    assert_eq!(journal.lookup("work").unwrap(), prior);
                    assert_eq!(admission.held(), 1);
                    assert!(runtime.sandbox_inventory().unwrap().is_empty());
                    assert!(relay.poll_finished().is_empty());
                }
            }
        }
    }
}

#[test]
fn restart_cleanup_without_hmac_key() {
    for kind in ["sandbox.kill", "sandbox.stop"] {
        let dir = tempfile::tempdir().unwrap();
        let binding = binding();
        // Reopen a real journal, as a restarted host does before key install/ACK.
        {
            let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap();
            j.install_key(&key(&binding, "d"), &binding, 1).unwrap();
            j.install_config(
                &sandbox_protocol::PrivateConfigInstall {
                    sandbox_owner_id: "owner".into(),
                    refusal_token: Some("install-token".into()),
                    connection_epoch: 1,
                    server: binding.server.clone(),
                    host_owner_id: binding.host_owner_id.clone(),
                    host_id: binding.host_id.clone(),
                    sandbox_id: "sbx".into(),
                    generation: 1,
                    config: sandbox_protocol::PrivateConfigRef {
                        config_id: "config".into(),
                        binding_scheme: "hmac-sha256-v1".into(),
                        binding_key_id: "d".repeat(32),
                        binding_mac: "c".repeat(64),
                    },
                    env: vec![("K".into(), "retained-private-cleanup-sentinel".into())],
                },
                &binding,
                1,
            )
            .unwrap();
        }
        let journal = Arc::new(
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap(),
        );
        let runtime = Arc::new(FakeRuntime::new());
        runtime
            .create_fixture(&CreateSandboxRequest::for_test("sbx", "created"))
            .unwrap();
        let mut authority = HostAuthority::default();
        let relay =
            RelaySupervisor::start(runtime.clone(), journal.clone(), authority.clone(), None);
        let mut incoming = dispatch(kind);
        incoming.env = None;
        incoming.digest_scheme = Some("sha256-env-free-v1".into());
        incoming.digest_key_id = None;
        let mut admission = crate::sandbox_relay::test_support::admission(
            1,
            crate::sandbox_relay::live_admission::test_capacity(),
        );
        admission
            .try_acquire(
                "sbx",
                "created",
                1,
                sandbox_protocol::VmSize::defaults().unwrap(),
            )
            .unwrap();
        let (mut socket, mut wire) = sockets();
        let incoming = crate::sandbox_relay::test_support::pinned_dispatch(&incoming);
        handle_dispatch(
            &mut socket,
            sandbox_protocol::WireCodes::CURRENT,
            &mut authority,
            &mut admission,
            (&journal, &binding),
            &relay,
            &None,
            &mut HashMap::new(),
            &incoming,
        )
        .unwrap();
        assert!(matches!(
            parse_daemon_control(wire.read().unwrap().to_text().unwrap()).unwrap(),
            DaemonControlMessage::OperationProgress {
                state: OperationState::Accepted,
                ..
            }
        ));
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(finished) = relay.poll_finished().pop() {
                assert_eq!(finished.state, OperationState::Succeeded);
                break;
            }
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(
            runtime.query_sandbox("sbx", None, None).unwrap(),
            if kind == "sandbox.stop" {
                Some(SandboxLifecycleState::Stopped)
            } else {
                None
            }
        );
        assert_eq!(
            journal.lookup("work").unwrap().digest_scheme.as_deref(),
            Some("sha256-env-free-v1")
        );
    }
}

#[test]
fn keyed_receipt_offline_expiry_needs_no_reinstalled_key() {
    let dir = tempfile::tempdir().unwrap();
    let binding = binding();
    let runtime = Arc::new(FakeRuntime::new());
    let create = CreateSandboxRequest::for_test("sbx", "work");
    runtime.create_fixture(&create).unwrap();
    let mut incoming = dispatch("sandbox.create");
    incoming.incus_fingerprint = Some(create.template_digest.clone());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    incoming.lease = Some(sandbox_protocol::HostLease {
        deadline_unix_ms: now + 60_000,
        ..sandbox_protocol::HostLease::for_test()
    });
    {
        let journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap();
        journal
            .install_key(&key(&binding, "d"), &binding, 1)
            .unwrap();
        let incoming = crate::sandbox_relay::test_support::pinned_dispatch(&incoming);
        journal
            .record_fixture_intent(&journal.prepare_dispatch(&binding, &incoming).unwrap())
            .unwrap();
        journal.accept_fixture_lease(&incoming).unwrap();
        journal.record_effect("work").unwrap();
        journal
            .record_result(
                "work",
                OperationState::Succeeded,
                Some(json!({"state":"ready", "lease":incoming.lease})),
                None,
                None,
            )
            .unwrap();
        let lease = journal.lease("sbx").unwrap();
        assert!(journal.expire_lease_now_for_test("sbx", lease.generation, lease.lease.revision));
    }
    let journal =
        Arc::new(crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap());
    assert_eq!(
        journal.prepare_dispatch(&binding, &incoming).unwrap_err(),
        SandboxErrorCode::DigestKeyUnavailable
    );
    let _expiry = super::super::expiry::ExpiryService::start(
        runtime.clone(),
        journal.clone(),
        HostAuthority::default(),
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    while !journal.lease("sbx").unwrap().expiry_complete {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(5));
    }
    assert!(matches!(
        runtime.query_sandbox("sbx", None, None).unwrap(),
        None | Some(SandboxLifecycleState::Stopped)
    ));
    assert_eq!(
        journal.prepare_dispatch(&binding, &incoming).unwrap_err(),
        SandboxErrorCode::DigestKeyUnavailable
    );
}

#[test]
fn key_free_cleanup_scheme_has_an_exact_kind_allowlist() {
    let dir = tempfile::tempdir().unwrap();
    let binding = binding();
    let journal = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap();
    for kind in sandbox_protocol::ALLOWED_HOST_DISPATCH_KINDS
        .iter()
        .chain(sandbox_protocol::RELAY_CONTROL_DISPATCH_KINDS)
    {
        let mut incoming = dispatch(kind);
        incoming.env = None;
        incoming.digest_scheme = Some("sha256-env-free-v1".into());
        incoming.digest_key_id = None;
        assert_eq!(
            journal.prepare_dispatch(&binding, &incoming).is_ok(),
            matches!(*kind, "sandbox.kill" | "sandbox.stop"),
            "{kind}"
        );
    }
    let mut incoming = dispatch("sandbox.kill");
    incoming.digest_scheme = Some("sha256-env-free-v1".into());
    incoming.digest_key_id = None;
    assert_eq!(
        journal.prepare_dispatch(&binding, &incoming).unwrap_err(),
        SandboxErrorCode::ProtocolError
    );
}

/// Security regression: retry transport fields (attempt, stdinSequence) must
/// be excluded from the keyed dispatch MAC, as they are from the env-free body.
/// An unacknowledged DISPATCHED op from an older epoch is redispatched with attempt+1
/// (outbox-processor.ts:578); with a Result-phase receipt the host must replay
/// that known result, exactly as the env-free scheme does, not demote it.
#[test]
fn probe_keyed_redispatch_new_attempt_replays_result() {
    for (kind, keyed) in [
        ("sandbox.kill", false),
        ("sandbox.stop", false),
        ("command.run", true),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let binding = binding();
        let journal = Arc::new(
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap(),
        );
        journal
            .install_key(&key(&binding, "d"), &binding, 1)
            .unwrap();
        let mut incoming = dispatch(kind);
        incoming.lease = None;
        if kind == "command.run" {
            incoming.argv = Some(vec!["true".into()]);
        }
        if matches!(kind, "sandbox.kill" | "sandbox.stop") {
            incoming.digest_scheme = Some("sha256-env-free-v1".into());
            incoming.env = None;
            incoming.digest_key_id = None;
        } else if !keyed {
            incoming.env = None;
            incoming.digest_scheme = None;
            incoming.digest_key_id = None;
        }
        let mut incoming = crate::sandbox_relay::test_support::pinned_dispatch(&incoming);
        journal
            .record_fixture_intent(&journal.prepare_dispatch(&binding, &incoming).unwrap())
            .unwrap();
        journal.record_effect("work").unwrap();
        journal
            .record_result("work", OperationState::Succeeded, None, None, None)
            .unwrap();
        let stored = journal.lookup("work").unwrap();
        incoming.attempt = 2;
        let runtime = Arc::new(FakeRuntime::new());
        let mut authority = HostAuthority::default();
        let relay =
            RelaySupervisor::start(runtime.clone(), journal.clone(), authority.clone(), None);
        let mut admission = crate::sandbox_relay::test_support::admission(
            1,
            crate::sandbox_relay::live_admission::test_capacity(),
        );
        let (mut socket, mut wire) = sockets();
        let mut incoming = crate::sandbox_relay::test_support::pinned_dispatch(&incoming);
        handle_dispatch(
            &mut socket,
            sandbox_protocol::WireCodes::CURRENT,
            &mut authority,
            &mut admission,
            (&journal, &binding),
            &relay,
            &None,
            &mut HashMap::new(),
            &incoming,
        )
        .unwrap();
        let result = parse_daemon_control(wire.read().unwrap().to_text().unwrap()).unwrap();
        let state = match &result {
            DaemonControlMessage::OperationResult { state, .. } => *state,
            DaemonControlMessage::OperationReceipt { state, .. } => *state,
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(
            state,
            OperationState::Succeeded,
            "{kind} keyed={keyed}: attempt-only redispatch demoted a known result: {result:?}"
        );
        assert_eq!(journal.lookup("work").unwrap(), stored);
        assert!(relay.poll_finished().is_empty());
        assert!(runtime.sandbox_inventory().unwrap().is_empty());

        // C-22 still applies to a genuine mismatch, including key-free cleanup.
        // A new wire avoids confusing the replay's companion receipt with this result.
        let (mut socket, mut wire) = sockets();
        incoming.body_hash = Some("b".repeat(64));
        let incoming = crate::sandbox_relay::test_support::pinned_dispatch(&incoming);
        handle_dispatch(
            &mut socket,
            sandbox_protocol::WireCodes::CURRENT,
            &mut authority,
            &mut admission,
            (&journal, &binding),
            &relay,
            &None,
            &mut HashMap::new(),
            &incoming,
        )
        .unwrap();
        assert!(matches!(
            parse_daemon_control(wire.read().unwrap().to_text().unwrap()).unwrap(),
            DaemonControlMessage::OperationResult {
                state: OperationState::UnknownOutcome,
                ..
            }
        ));
        assert_eq!(journal.lookup("work").unwrap(), stored);
        assert!(relay.poll_finished().is_empty());
    }
}

#[test]
fn retry_digest_exclusions_preserve_receipt_identity_fences() {
    use super::super::journal::Decision;
    for (kind, keyed) in [
        ("sandbox.kill", false),
        ("sandbox.stop", false),
        ("command.run", true),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let binding = binding();
        let journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap();
        journal
            .install_key(&key(&binding, "d"), &binding, 1)
            .unwrap();
        let mut incoming = dispatch(kind);
        incoming.lease = None;
        if kind == "command.run" {
            incoming.argv = Some(vec!["true".into()]);
        }
        if !keyed {
            incoming.env = None;
            incoming.digest_scheme = Some("sha256-env-free-v1".into());
            incoming.digest_key_id = None;
        }
        let original = journal.prepare_dispatch(&binding, &incoming).unwrap();
        journal.record_fixture_intent(&original).unwrap();
        journal.record_effect("work").unwrap();
        journal
            .record_result("work", OperationState::Succeeded, None, None, None)
            .unwrap();
        let stored = journal.lookup("work").unwrap();
        for transport in ["attempt", "stdin"] {
            if transport == "stdin" && kind != "command.run" {
                continue;
            }
            let mut retry = incoming.clone();
            match transport {
                "attempt" => retry.attempt += 1,
                _ => retry.stdin_sequence = Some(99),
            }
            let receipt = journal.prepare_dispatch(&binding, &retry).unwrap();
            assert_eq!(
                receipt.body_hash, original.body_hash,
                "{kind}/{keyed}/{transport}"
            );
            assert!(
                matches!(journal.record_fixture_intent(&receipt).unwrap(), Decision::Replay(replayed) if replayed == stored)
            );
        }
        for field in [
            "operation",
            "sandbox",
            "generation",
            "idempotency",
            "request",
            "body",
        ] {
            let mut changed = incoming.clone();
            match field {
                "operation" => changed.operation_id = "other".into(),
                "sandbox" => changed.sandbox_id = "other".into(),
                "generation" => changed.generation += 1,
                "idempotency" => changed.idempotency_key = "other".into(),
                "request" => changed.body_hash = Some("b".repeat(64)),
                _ if kind == "command.run" => changed.argv = Some(vec!["false".into()]),
                _ => changed.incus_name = Some("wssp-sbx-other".into()),
            }
            match journal.prepare_dispatch(&binding, &changed) {
                Ok(receipt) => assert!(
                    matches!(
                        journal.record_fixture_intent(&receipt).unwrap(),
                        Decision::Conflict
                    ),
                    "{kind}/{keyed}/{field}"
                ),
                Err(code) => assert_eq!(
                    code,
                    SandboxErrorCode::IdempotencyConflict,
                    "{kind}/{keyed}/{field}"
                ),
            }
            assert_eq!(journal.lookup("work").unwrap(), stored);
        }
        // Another operation with its own idempotency key is fresh, never a
        // replay of the first operation, even if its body hash matches.
        let mut separate = incoming.clone();
        separate.operation_id = "separate".into();
        separate.idempotency_key = "separate".into();
        let receipt = journal.prepare_dispatch(&binding, &separate).unwrap();
        assert!(matches!(
            journal.record_fixture_intent(&receipt).unwrap(),
            Decision::Fresh
        ));
    }
}

#[test]
fn pruned_receipt_reconciliation_sends_only_safe_identity_and_cannot_confirm() {
    let dir = tempfile::tempdir().unwrap();
    let binding = binding();
    let j = crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap();
    j.install_key(&key(&binding, "d"), &binding, 1).unwrap();
    let d = dispatch("command.run");
    j.record_fixture_intent(&j.prepare_dispatch(&binding, &d).unwrap())
        .unwrap();
    let original = j.lookup("work").unwrap();
    j.seed_pruned_receipt_for_test("work");
    j.clear_key();
    let tombstone = j.lookup("work").unwrap();
    let fake = FakeRuntime::new();
    fake.fixture_root().unwrap();
    assert_eq!(
        super::super::reconcile::resolve_receipt(&j, &fake, tombstone.clone()).unwrap(),
        tombstone
    );
    let (mut socket, mut wire) = sockets();
    super::super::reconcile::send_receipt(
        &mut socket,
        sandbox_protocol::WireCodes::CURRENT,
        tombstone.clone(),
    )
    .unwrap();
    let frame = wire.read().unwrap();
    let text = frame.to_text().unwrap();
    assert!(matches!(
        parse_daemon_control(text).unwrap(),
        DaemonControlMessage::OperationReceiptPruned { .. }
    ));
    for mac in [
        original.body_hash,
        original.request_hash,
        original.server_request_hash,
    ]
    .into_iter()
    .flatten()
    {
        assert!(!text.contains(&mac));
    }
    assert!(!text.contains("bodyHash") && !text.contains("result"));
    assert!(
        !j.confirm(
            &binding,
            &sandbox_protocol::ReceiptConfirmation {
                sandbox_owner_id: d.sandbox_owner_id.clone(),
                operation_id: d.operation_id,
                sandbox_id: d.sandbox_id,
                generation: d.generation,
                attempt: d.attempt,
                body_hash: d.body_hash.unwrap(),
                idempotency_key: d.idempotency_key,
                kind: d.kind,
                cleanup_generation: Some(2),
                retire_command: false,
            }
        )
        .unwrap()
    );
    assert_eq!(j.lookup("work").unwrap(), tombstone);
    assert!(fake.sandbox_inventory().unwrap().is_empty());
}

#[test]
fn private_config_supervisor_logs_and_receipts_are_redacted() {
    const PRIVATE: &str = "private-config-supervisor-sentinel";
    const COMMAND: &str = "command-env-supervisor-sentinel";
    for format in [
        crate::logging::LogFormat::Text,
        crate::logging::LogFormat::Json,
    ] {
        let ((), logs) = crate::logging::with_subscriber(
            format,
            tracing_subscriber::EnvFilter::new("trace"),
            || {
                let dir = tempfile::tempdir().unwrap();
                let binding = binding();
                let journal = Arc::new(
                    crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap(),
                );
                let key = key(&binding, "d");
                journal.install_key(&key, &binding, 1).unwrap();
                let config = sandbox_protocol::PrivateConfigInstall {
                    sandbox_owner_id: "owner".into(),
                    refusal_token: Some("install-token".into()),
                    connection_epoch: 1,
                    server: binding.server.clone(),
                    host_owner_id: binding.host_owner_id.clone(),
                    host_id: binding.host_id.clone(),
                    sandbox_id: "sbx".into(),
                    generation: 1,
                    config: sandbox_protocol::PrivateConfigRef {
                        config_id: "config".into(),
                        binding_scheme: "hmac-sha256-v1".into(),
                        binding_key_id: key.key_id,
                        binding_mac: "c".repeat(64),
                    },
                    env: vec![("DEFAULT".into(), PRIVATE.into())],
                };
                journal.install_config(&config, &binding, 1).unwrap();
                let request = CreateSandboxRequest::for_test("sbx", "created");
                let runtime = Arc::new(FakeRuntime::new());
                runtime.create_fixture(&request).unwrap();
                let mut create = dispatch("sandbox.create");
                create.operation_id = "created".into();
                create.idempotency_key = "created".into();
                create.env = None;
                create.private_config = Some(config.config.clone());
                create.incus_fingerprint = Some(request.template_digest.clone());
                journal
                    .record_fixture_intent(&journal.prepare_dispatch(&binding, &create).unwrap())
                    .unwrap();
                journal.accept_fixture_lease(&create).unwrap();
                journal
                    .record_result(
                        "created",
                        OperationState::Succeeded,
                        Some(json!({"state":"ready","lease":create.lease})),
                        None,
                        None,
                    )
                    .unwrap();
                let mut authority = HostAuthority::default();
                let relay =
                    RelaySupervisor::start(runtime, journal.clone(), authority.clone(), None);
                let mut command = dispatch("command.run");
                command.env = Some(vec![("COMMAND".into(), COMMAND.into())]);
                command.argv = Some(vec!["true".into()]);
                command.lease = None;
                command.private_config = Some(config.config);
                command.incus_fingerprint = Some(request.template_digest);
                let (mut socket, _wire) = sockets();
                let command = crate::sandbox_relay::test_support::pinned_dispatch(&command);
                handle_dispatch(
                    &mut socket,
                    sandbox_protocol::WireCodes::CURRENT,
                    &mut authority,
                    &mut crate::sandbox_relay::test_support::admission(
                        1,
                        crate::sandbox_relay::live_admission::test_capacity(),
                    ),
                    (&journal, &binding),
                    &relay,
                    &None,
                    &mut HashMap::new(),
                    &command,
                )
                .unwrap();
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    if let Some(finished) = relay.poll_finished_consumed().pop() {
                        assert_eq!(finished.state, OperationState::Succeeded);
                        break;
                    }
                    assert!(Instant::now() < deadline);
                    thread::sleep(Duration::from_millis(2));
                }
                let receipt = journal.lookup("work").unwrap();
                let evidence = serde_json::to_string(&receipt).unwrap();
                assert!(!evidence.contains(PRIVATE) && !evidence.contains(COMMAND));
                drop(relay);
            },
        );
        let logs = String::from_utf8_lossy(&logs);
        assert!(
            logs.contains("host operation started") && logs.contains("host operation finished"),
            "{logs}"
        );
        for secret in [PRIVATE, COMMAND, &"ab".repeat(32), &"c".repeat(64)] {
            assert!(
                !logs.contains(secret),
                "private data reached automatic supervisor logs"
            );
        }
    }
}

/// Live finding B-3: a keyed create passed its effect gate just before the
/// relay dropped. Ending that session must not clear the journal key while
/// the work is carried: its lease acceptance digests the keyed dispatch.
/// Without pending work, the key is still cleared at session end.
#[test]
fn session_end_keeps_the_journal_key_for_carried_keyed_work() {
    let binding = binding();
    let dir = tempfile::tempdir().unwrap();
    let journal =
        Arc::new(crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap());
    let authority = HostAuthority::default();
    let d = dispatch("sandbox.create");
    {
        let _session = super::super::journal_key::KeySession::start_carrying(
            journal.clone(),
            authority.clone(),
        );
        journal
            .install_key(&key(&binding, "d"), &binding, 1)
            .unwrap();
        journal
            .record_fixture_intent(&journal.prepare_dispatch(&binding, &d).unwrap())
            .unwrap();
        authority
            .accept_dispatch("work", "sbx", "sandbox.create", 1, 1)
            .unwrap();
    }
    // The session ended with carried work: the keyed dispatch still digests.
    assert!(
        journal.prepare_dispatch(&binding, &d).is_ok(),
        "carried keyed work keeps its key"
    );
    // A new session with carried work does not clear it either.
    drop(super::super::journal_key::KeySession::start_carrying(
        journal.clone(),
        authority.clone(),
    ));
    assert!(journal.prepare_dispatch(&binding, &d).is_ok());
    // Once nothing is pending, session end clears it as before.
    authority.complete("work");
    drop(super::super::journal_key::KeySession::start_carrying(
        journal.clone(),
        authority,
    ));
    assert!(journal.prepare_dispatch(&binding, &d).is_err());
}
