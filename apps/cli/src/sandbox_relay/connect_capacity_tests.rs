//! Production socket, journal, authority, worker, runtime and completion paths.
use super::*;
use crate::sandbox_relay::test_support::FixtureRuntime;
use sandbox_protocol::{SandboxLifecycleState, parse_daemon_control};
use sandbox_runtime::{CreateSandboxRequest, FakeRuntime, StopSandboxRequest};
use std::net::{TcpListener, TcpStream};

struct ConnectedHost {
    wire: tungstenite::WebSocket<TcpStream>,
    daemon: Option<thread::JoinHandle<Result<()>>>,
    shutdown: ShutdownSignal,
    _dir: tempfile::TempDir,
    runtime: FakeRuntime,
}
impl ConnectedHost {
    fn start(runtime: FakeRuntime, receipt: Option<(&str, bool)>) -> Self {
        Self::start_with_journal(
            runtime,
            |journal, binding| {
                if let Some((kind, issued)) = receipt {
                    let dispatch = dispatch("interrupted", "a", kind, 1);
                    journal
                        .record_fixture_intent(&intent_from_dispatch(journal, binding, &dispatch))
                        .unwrap();
                    if issued {
                        journal.record_effect("interrupted").unwrap();
                    }
                }
            },
            false,
        )
    }
    fn start_with_journal(
        runtime: FakeRuntime,
        prepare: impl FnOnce(&HostJournal, &TransportBindingV11),
        confirm_cleanup: bool,
    ) -> Self {
        Self::start_with_live_limit(runtime, prepare, confirm_cleanup, 1)
    }
    fn start_with_live_limit(
        runtime: FakeRuntime,
        prepare: impl FnOnce(&HostJournal, &TransportBindingV11),
        confirm_cleanup: bool,
        vcpu_budget: u32,
    ) -> Self {
        Self::start_with_protocol(
            runtime,
            prepare,
            confirm_cleanup,
            vcpu_budget,
            sandbox_protocol::SANDBOX_RELAY_PROTOCOL_VERSION,
        )
    }
    fn start_with_protocol(
        runtime: FakeRuntime,
        prepare: impl FnOnce(&HostJournal, &TransportBindingV11),
        confirm_cleanup: bool,
        vcpu_budget: u32,
        version: &str,
    ) -> Self {
        runtime.fixture_root().unwrap();
        let dir = crate::sandbox_relay::test_support::journal_capacity_dir();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = ShutdownSignal::default();
        let options = ConnectOptions {
            host_terminal: None,
            server_url: format!("ws://{address}"),
            host_token: "test-only-token".into(),
            host_id: "host-1".into(),
            label: "capacity-test".into(),
            runtime: HostRuntimeKind::Fake,
            incus_project: None,
            state_dir: Some(dir.path().into()),
            heartbeat: Duration::from_secs(30),
            sandbox_memory_mib: None,
            max_sandbox_cpu_count: None,
            sandbox_vcpu_budget: Some(vcpu_budget),
            max_concurrent_commands: 16,
            shutdown: shutdown.clone(),
        };
        {
            let binding = TransportBindingV11 {
                server: format!("ws://{address}/ws/sandbox-host"),
                host_owner_id: "owner-1".into(),
                host_id: "host-1".into(),
            };
            let journal =
                crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap();
            for entry in runtime.sandbox_inventory().unwrap() {
                let id = entry.sandbox_id;
                let d = dispatch("existing", &id, "sandbox.create", 1);
                journal
                    .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &d))
                    .unwrap();
                journal.accept_fixture_lease(&d).unwrap();
                journal
                    .record_result(
                        &d.operation_id,
                        OperationState::Succeeded,
                        Some(json!({"state":"ready", "lease":d.lease})),
                        None,
                        None,
                    )
                    .unwrap();
            }
            prepare(&journal, &binding);
            // Drop and reopen from disk in run_connect, as on process restart.
        }
        let daemon_runtime = runtime.clone();
        let daemon = thread::spawn(move || {
            run_connect_with(&options, |_| Ok((Box::new(daemon_runtime), None)))
        });
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut wire = tungstenite::accept_hdr(tcp, tests::RelayHandshake).unwrap();
        wire.read().unwrap();
        crate::sandbox_relay::test_support::send_sized_hello_for_version(
            &mut wire,
            &TransportBindingV11 {
                server: format!("ws://{address}/ws/sandbox-host"),
                host_owner_id: "owner-1".into(),
                host_id: "host-1".into(),
            },
            version,
        );
        loop {
            let frame = wire.read().unwrap();
            match parse_daemon_control(frame.to_text().unwrap()).unwrap() {
                DaemonControlMessage::ReconcileComplete { .. } => break,
                DaemonControlMessage::OperationReceipt {
                    operation_id,
                    kind,
                    sandbox_id,
                    generation,
                    attempt,
                    body_hash,
                    idempotency_key,
                    ..
                } => {
                    if confirm_cleanup && kind == "sandbox.kill" {
                        wire.send(Message::Text(
                            json!({"sandboxOwnerId":"owner",
                                "type":"receipt.confirmed", "operationId":operation_id,
                                "sandboxId":sandbox_id, "generation":generation, "attempt":attempt,
                                "bodyHash":body_hash, "idempotencyKey":idempotency_key, "kind":kind,
                            })
                            .to_string()
                            .into(),
                        ))
                        .unwrap();
                    }
                    wire.send(Message::Text(
                        json!({"type":"receipt.ack", "operationId":operation_id})
                            .to_string()
                            .into(),
                    ))
                    .unwrap();
                }
                DaemonControlMessage::SandboxInventory { page, entries, .. } => {
                    wire.send(Message::Text(
                        json!({"type":"inventory.ack","page":page,"entryResults": entries.iter().map(|entry| json!({"sandboxId":entry.sandbox_id,"outcome":"converged"})).collect::<Vec<_>>()})
                            .to_string()
                            .into(),
                    ))
                    .unwrap();
                }
                // The session's TTL reports start at hello.ok (`host_reports`).
                DaemonControlMessage::Heartbeat { .. }
                | DaemonControlMessage::JournalKeyAck { .. }
                | DaemonControlMessage::HostAdmission { .. }
                | DaemonControlMessage::HostEgressState(_)
                | DaemonControlMessage::InventoryUpdate { .. } => {}
                other => panic!("unexpected startup message {other:?}"),
            }
        }
        Self {
            wire,
            daemon: Some(daemon),
            shutdown,
            _dir: dir,
            runtime,
        }
    }
    fn send_dispatch(&mut self, dispatch: &OperationDispatch) {
        let dispatch = crate::sandbox_relay::test_support::pinned_dispatch(dispatch);
        let dispatch = crate::sandbox_relay::test_support::current_fixture_dispatch(&dispatch);
        let mut value = serde_json::to_value(&dispatch).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("type".into(), json!("operation.dispatch"));
        self.wire
            .send(Message::Text(value.to_string().into()))
            .unwrap();
    }
    fn send(&mut self, dispatch: &OperationDispatch) -> OperationState {
        self.send_result(dispatch).0
    }
    fn send_result(
        &mut self,
        dispatch: &OperationDispatch,
    ) -> (OperationState, Option<SandboxErrorCode>) {
        let (state, error) = self.send_detail(dispatch);
        (state, error.and_then(|detail| detail.code.known()))
    }
    fn send_detail(
        &mut self,
        dispatch: &OperationDispatch,
    ) -> (
        OperationState,
        Option<sandbox_protocol::ProtocolErrorDetail>,
    ) {
        self.send_dispatch(dispatch);
        loop {
            let frame = self.wire.read().unwrap();
            if let DaemonControlMessage::OperationResult {
                operation_id,
                state,
                error,
                ..
            } = parse_daemon_control(frame.to_text().unwrap()).unwrap()
            {
                assert_eq!(operation_id, dispatch.operation_id);
                return (state, error);
            }
        }
    }
}
impl Drop for ConnectedHost {
    fn drop(&mut self) {
        // A failing assertion may have broken the session and started the
        // production reconnect loop. Always stop that loop before joining.
        self.shutdown.request();
        for entry in self.runtime.sandbox_inventory().unwrap() {
            let id = entry.sandbox_id;
            let _ = self
                .runtime
                .kill_fixture(&sandbox_runtime::KillSandboxRequest {
                    instance_name: sandbox_runtime::default_incus_instance_name(&id),
                    sandbox_id: id,
                    template_fingerprint: String::new(),
                    operation_id: "cleanup".into(),
                    idempotency_key: "cleanup".into(),
                });
        }
        let _ = self.wire.close(None);
        if let Some(daemon) = self.daemon.take() {
            let _ = daemon.join();
        }
    }
}
fn dispatch(id: &str, sandbox: &str, kind: &str, generation: u64) -> OperationDispatch {
    const FP: &str = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    let mut value = json!({"sandboxOwnerId":"owner", "operationId":id,"sandboxId":sandbox,"kind":kind, "lease": sandbox_protocol::HostLease { revision: generation, ..sandbox_protocol::HostLease::for_test() },
        "generation":generation,"attempt":1,"idempotencyKey":id,"bodyHash":"a".repeat(64),
        "templateDigest":FP,"incusFingerprint":FP,"architecture":"x86_64"});
    if matches!(kind, "sandbox.create" | "sandbox.reconnect") {
        value["cpuCount"] = json!(1);
        value["memoryMiB"] = json!(1024);
    }
    if matches!(
        kind,
        "sandbox.create" | "sandbox.reconnect" | "sandbox.stop" | "sandbox.kill"
    ) {
        value["allocation"] =
            serde_json::to_value(crate::sandbox_relay::test_support::allocation()).unwrap();
    }
    if sandbox_protocol::results::host::kind_from_dispatch(kind).is_some() {
        value["resultVersion"] = json!(1);
    }
    if kind == "command.run" {
        value["processId"] = json!(format!("proc-{id}"));
    }
    crate::sandbox_relay::test_support::current_fixture_dispatch(
        &serde_json::from_value(value).unwrap(),
    )
}
fn preexisting(state: SandboxLifecycleState) -> FakeRuntime {
    let fake = FakeRuntime::new();
    fake.fixture_root().unwrap();
    fake.create_fixture(&CreateSandboxRequest::for_test("a", "existing"))
        .unwrap();
    if state == SandboxLifecycleState::Stopped {
        fake.stop_sandbox(&StopSandboxRequest {
            template_fingerprint: sandbox_runtime::CreateSandboxRequest::for_test("sbx", "key")
                .template_digest,
            sandbox_id: "a".into(),
            instance_name: "wssp-sbx-a".into(),
            operation_id: "stop-existing".into(),
            idempotency_key: "stop-existing".into(),
        })
        .unwrap();
    }
    fake
}

#[test]
fn cap_one_wire_create_replay_stop_create_and_kill_reuses_slot() {
    let mut host = ConnectedHost::start(FakeRuntime::new(), None);
    for d in [
        dispatch("create-a", "a", "sandbox.create", 1),
        dispatch("create-a", "a", "sandbox.create", 1),
        dispatch("stop-a", "a", "sandbox.stop", 2),
        dispatch("create-b", "b", "sandbox.create", 1),
        dispatch("kill-b", "b", "sandbox.kill", 2),
        dispatch("reconnect-a", "a", "sandbox.reconnect", 3),
        dispatch("warm-a", "a", "sandbox.reconnect", 3),
        dispatch("replacement-a", "a", "sandbox.reconnect", 4),
        dispatch("kill-a", "a", "sandbox.kill", 5),
        dispatch("create-c", "c", "sandbox.create", 1),
    ] {
        assert_eq!(
            host.send(&d),
            OperationState::Succeeded,
            "{}",
            d.operation_id
        );
    }
}

#[test]
fn wire_fresh_create_failure_replays_and_existing_vm_refusal_keeps_capacity() {
    let mut host = ConnectedHost::start(FakeRuntime::new(), None);
    assert_eq!(
        host.send(&dispatch("original", "a", "sandbox.create", 1)),
        OperationState::Succeeded
    );
    assert_eq!(
        host.send(&dispatch("remove", "a", "sandbox.kill", 2)),
        OperationState::Succeeded
    );
    let mut stale = dispatch("stale-key", "a", "sandbox.create", 3);
    stale.idempotency_key = "original".into();
    assert_eq!(host.send(&stale), OperationState::UnknownOutcome);
    // A truly fresh, definite runtime refusal releases the new claim promptly.
    let mut bad = dispatch("bad", "refused", "sandbox.create", 1);
    bad.guest_uid = Some(0);
    assert_eq!(host.send(&bad), OperationState::Failed);
    assert_eq!(host.send(&bad), OperationState::Failed);
    assert_eq!(
        host.send(&dispatch("good", "b", "sandbox.create", 1)),
        OperationState::Succeeded
    );
    // A refusal for the same live sandbox cannot release its existing reservation.
    let refused_replacement = dispatch("bad-replacement", "b", "sandbox.create", 2);
    assert_eq!(
        host.send(&refused_replacement),
        OperationState::UnknownOutcome
    );
    assert_eq!(
        host.send(&dispatch("over-cap", "c", "sandbox.create", 1)),
        OperationState::Failed
    );
    assert_eq!(
        host.send(&dispatch("kill", "b", "sandbox.kill", 3)),
        OperationState::Succeeded
    );
    assert_eq!(
        host.send(&dispatch("after-kill", "c", "sandbox.create", 1)),
        OperationState::Succeeded
    );
}

#[test]
fn wire_create_admission_refusals_require_first_claim_and_absence() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let fail_lookup = Arc::new(AtomicBool::new(false));
    let runtime = FakeRuntime::new().with_inventory_hook({
        let fail_lookup = fail_lookup.clone();
        move |stage| {
            if stage == "exists" && fail_lookup.load(Ordering::SeqCst) {
                Err(sandbox_runtime::RuntimeError::new(
                    SandboxErrorCode::Internal,
                    "lookup unavailable",
                ))
            } else {
                Ok(())
            }
        }
    });
    let mut host = ConnectedHost::start(runtime, None);
    assert_eq!(
        host.send(&dispatch("held", "held", "sandbox.create", 1)),
        OperationState::Succeeded
    );
    assert_eq!(
        host.send(&dispatch("first", "fresh", "sandbox.create", 1)),
        OperationState::Failed
    );
    let mut retry = dispatch("retry", "retry", "sandbox.create", 1);
    retry.attempt = 2;
    assert_eq!(host.send(&retry), OperationState::UnknownOutcome);
    fail_lookup.store(true, Ordering::SeqCst);
    assert_eq!(
        host.send(&dispatch("blind", "blind", "sandbox.create", 1)),
        OperationState::UnknownOutcome
    );
    // Refusal accounting never removes the VM that exhausted capacity.
    assert!(host.runtime.sandbox_exists("held").is_err());
    fail_lookup.store(false, Ordering::SeqCst);
    assert!(host.runtime.sandbox_exists("held").unwrap());
}

// Drive both connection-thread refusal sites through the full ConnectedHost
// socket loop. A first reconnect may fail when the VM is stopped or absent;
// running VMs and inconclusive observations retain UNKNOWN. The size mismatch comes from a real, earlier live reservation
// even when the VM has since been stopped or removed outside this connection.
#[test]
fn wire_reconnect_vm_size_mismatch_requires_first_attempt_and_not_running() {
    for (observation, attempt) in [
        ("absent", 1),
        ("stopped", 1),
        ("running", 1),
        ("error", 1),
        ("absent", 2),
        ("stopped", 2),
    ] {
        let runtime = FakeRuntime::new().with_inventory_hook(move |stage| {
            if stage == "running" && observation == "error" {
                Err(sandbox_runtime::RuntimeError::new(
                    SandboxErrorCode::Internal,
                    "lookup unavailable",
                ))
            } else {
                Ok(())
            }
        });
        let mut host = ConnectedHost::start(runtime, None);
        assert_eq!(
            host.send(&dispatch("held", "a", "sandbox.create", 1)),
            OperationState::Succeeded
        );
        set_reconnect_observation(&host.runtime, observation);
        let mut reconnect = dispatch("mismatch", "a", "sandbox.reconnect", 2);
        reconnect.cpu_count = Some(2);
        reconnect.attempt = attempt;
        let (state, code) = host.send_result(&reconnect);
        assert_eq!(code, Some(SandboxErrorCode::VmSizeMismatch));
        assert_eq!(
            state,
            reconnect_refusal_expected(observation, attempt),
            "{observation}, attempt={attempt}"
        );
    }
}

#[test]
fn wire_reconnect_queue_full_requires_first_attempt_and_not_running() {
    for (observation, attempt) in [
        ("absent", 1),
        ("stopped", 1),
        ("running", 1),
        ("error", 1),
        ("absent", 2),
        ("stopped", 2),
    ] {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = std::sync::Mutex::new(release_rx);
        let runtime = preexisting(if observation == "stopped" {
            SandboxLifecycleState::Stopped
        } else {
            SandboxLifecycleState::Ready
        })
        .with_lifecycle_hook(move |stage| {
            if stage == "create" {
                entered_tx.send(()).unwrap();
                release_rx
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(20))
                    .unwrap();
            }
            Ok(())
        })
        .with_inventory_hook(move |stage| {
            if stage == "running" && observation == "error" {
                Err(sandbox_runtime::RuntimeError::new(
                    SandboxErrorCode::Internal,
                    "lookup unavailable",
                ))
            } else {
                Ok(())
            }
        });
        let mut host = ConnectedHost::start_with_live_limit(runtime, |_, _| {}, false, 2);
        if observation == "absent" {
            // Remove the VM after startup retained-root reconstruction. The
            // dispatch still carries the exact previously pinned disk identity.
            set_reconnect_observation(&host.runtime, observation);
        }
        host.send_dispatch(&dispatch("blocked-create", "blocker", "sandbox.create", 1));
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        // One active lifecycle job and the creator's fifteen nonurgent queue entries.
        // Probes share its sandbox, so no worker can drain the queue.
        for n in 0..15 {
            host.send_dispatch(&dispatch(
                &format!("queued-{n}"),
                "blocker",
                "sandbox.probe",
                1,
            ));
        }
        let mut reconnect = dispatch("overflow", "a", "sandbox.reconnect", 2);
        reconnect.attempt = attempt;
        let (state, code) = host.send_result(&reconnect);
        release_tx.send(()).unwrap();
        // Drain the parked job and its queue before closing the socket. This
        // also proves every filler was admitted, rather than refused earlier.
        // Ping wakes the socket reader between completions instead of waiting
        // for its idle read timeout on every queued probe.
        host.wire.send(Message::Ping(Vec::new().into())).unwrap();
        let mut remaining: std::collections::HashSet<_> = (0..15)
            .map(|n| format!("queued-{n}"))
            .chain(std::iter::once("blocked-create".into()))
            .collect();
        while !remaining.is_empty() {
            let frame = host.wire.read().unwrap();
            let Message::Text(text) = frame else {
                continue;
            };
            if let DaemonControlMessage::OperationResult {
                operation_id,
                error,
                ..
            } = parse_daemon_control(&text).unwrap()
            {
                assert!(
                    remaining.remove(&operation_id),
                    "unexpected result {operation_id}"
                );
                assert_ne!(
                    error.map(|detail| detail.code),
                    Some(SandboxErrorCode::HostCapacity.into())
                );
                host.wire.send(Message::Ping(Vec::new().into())).unwrap();
            }
        }
        assert_eq!(code, Some(SandboxErrorCode::HostCapacity));
        assert_eq!(
            state,
            reconnect_refusal_expected(observation, attempt),
            "{observation}, attempt={attempt}"
        );
    }
}

fn reconnect_refusal_expected(observation: &str, attempt: u64) -> OperationState {
    if attempt == 1 && matches!(observation, "absent" | "stopped") {
        OperationState::Failed
    } else {
        OperationState::UnknownOutcome
    }
}

fn set_reconnect_observation(runtime: &FakeRuntime, observation: &str) {
    if observation == "stopped" {
        runtime
            .stop_sandbox(&StopSandboxRequest {
                template_fingerprint: CreateSandboxRequest::for_test("a", "seed").template_digest,
                sandbox_id: "a".into(),
                instance_name: "wssp-sbx-a".into(),
                operation_id: "external-stop".into(),
                idempotency_key: "external-stop".into(),
            })
            .unwrap();
    } else if observation == "absent" {
        runtime
            .kill_fixture(&sandbox_runtime::KillSandboxRequest {
                template_fingerprint: String::new(),
                sandbox_id: "a".into(),
                instance_name: "wssp-sbx-a".into(),
                operation_id: "external-kill".into(),
                idempotency_key: "external-kill".into(),
            })
            .unwrap();
    }
}

// Real reader -> journal-full refusal -> bounded observation lane -> wire result.
#[test]
fn journal_full_refusal_overflow_keeps_session_and_ping_alive() {
    for fill_shared_lane in [true, false] {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release = std::sync::Mutex::new(release_rx);
        let first = std::sync::atomic::AtomicBool::new(true);
        let runtime = FakeRuntime::new().with_inventory_hook(move |stage| {
            if matches!(stage, "exists" | "running")
                && first.swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                entered_tx.send(()).unwrap();
                release
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(30))
                    .unwrap();
            }
            Ok(())
        });
        // Always unblock the worker on assertion failure, including the inverse fault.
        struct ReleaseOnDrop(mpsc::Sender<()>);
        impl Drop for ReleaseOnDrop {
            fn drop(&mut self) {
                let _ = self.0.send(());
            }
        }
        let mut host = ConnectedHost::start_with_journal(
            runtime,
            |journal, binding| {
                for n in 0..4096 {
                    let mut d = dispatch(&format!("filler-{n}"), "filler", "sandbox.probe", 1);
                    if n == 4095 {
                        d.sandbox_owner_id = "other-creator".into();
                        d.sandbox_id = "other-filler".into();
                    }
                    journal
                        .record_fixture_intent(&intent_from_dispatch(journal, binding, &d))
                        .unwrap();
                    journal
                        .record_result(
                            &d.operation_id,
                            OperationState::Failed,
                            None,
                            Some(SandboxErrorCode::NotFound),
                            Some("not found".into()),
                        )
                        .unwrap();
                }
            },
            false,
        );
        let release = ReleaseOnDrop(release_tx);
        for n in 0..40 {
            let kind = if n % 2 == 0 {
                "sandbox.create"
            } else {
                "sandbox.reconnect"
            };
            host.send_dispatch(&dispatch(
                &format!("refusal-{n}"),
                &format!("sandbox-{n}"),
                kind,
                1,
            ));
            if n == 0 {
                entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();
                if fill_shared_lane {
                    // Occupy all observation queue slots with independent image
                    // work, forcing try_send itself to fail for later refusals.
                    for i in 0..16 {
                        host.wire.send(Message::Text(json!({
                        "type": "image.verify.request", "requestId": format!("image-{i}"),
                        "imageRef": "test-image", "expectedArchitecture": "x86_64"
                    }).to_string().into())).unwrap();
                    }
                }
            }
        }
        let first_overflow = if fill_shared_lane { 1 } else { 16 };
        host.wire.send(Message::Ping(vec![9].into())).unwrap();
        let mut seen = std::collections::HashSet::new();
        let mut pong = false;
        while seen.len() < 40 - first_overflow || !pong {
            let frame = host.wire.read();
            assert!(
                frame.is_ok(),
                "refusal overflow must keep the session up: {frame:?}"
            );
            match frame.unwrap() {
                Message::Pong(bytes) => {
                    assert_eq!(bytes.as_ref(), &[9]);
                    pong = true;
                }
                Message::Text(text) => {
                    if let DaemonControlMessage::OperationResult {
                        operation_id,
                        sandbox_id,
                        generation,
                        attempt,
                        state,
                        error,
                        ..
                    } = parse_daemon_control(&text).unwrap()
                    {
                        let n: usize = operation_id
                            .strip_prefix("refusal-")
                            .unwrap()
                            .parse()
                            .unwrap();
                        assert!(
                            n >= first_overflow,
                            "queued refusal completed while observation blocked"
                        );
                        assert_eq!(sandbox_id, format!("sandbox-{n}"));
                        assert_eq!((generation, attempt), (1, 1));
                        assert_eq!(state, OperationState::UnknownOutcome);
                        assert_eq!(error.unwrap().code, SandboxErrorCode::HostCapacity);
                        assert!(seen.insert(operation_id), "duplicate refusal result");
                    }
                }
                other => panic!("session lost during refusal overflow: {other:?}"),
            }
        }
        drop(release);
        host.wire.send(Message::Ping(Vec::new().into())).unwrap();
        while seen.len() < 40 {
            if let Message::Text(text) = host.wire.read().unwrap()
                && let DaemonControlMessage::OperationResult {
                    operation_id,
                    state,
                    error,
                    ..
                } = parse_daemon_control(&text).unwrap()
            {
                assert_eq!(state, OperationState::Failed);
                assert_eq!(error.unwrap().code, SandboxErrorCode::HostCapacity);
                assert!(seen.insert(operation_id), "duplicate refusal result");
            }
        }
        assert!(!host.daemon.as_ref().unwrap().is_finished());
    }
}

#[test]
fn create_refusal_existence_lookup_never_blocks_socket_control() {
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let release = std::sync::Mutex::new(release_rx);
    let runtime = FakeRuntime::new().with_inventory_hook(move |stage| {
        if stage == "exists" {
            entered_tx.send(()).unwrap();
            release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
        }
        Ok(())
    });
    let mut host = ConnectedHost::start(runtime, None);
    assert_eq!(
        host.send(&dispatch("held", "held", "sandbox.create", 1)),
        OperationState::Succeeded
    );
    let mut value =
        serde_json::to_value(dispatch("cap-ping", "fresh", "sandbox.create", 1)).unwrap();
    value.as_object_mut().unwrap().insert(
        "type".into(),
        serde_json::Value::String("operation.dispatch".into()),
    );
    host.wire
        .send(Message::Text(value.to_string().into()))
        .unwrap();
    entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    host.wire
        .get_mut()
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    host.wire.send(Message::Ping(vec![7].into())).unwrap();
    loop {
        if let Message::Pong(bytes) = host.wire.read().unwrap() {
            assert_eq!(bytes.as_ref(), &[7]);
            break;
        }
    }
    release_tx.send(()).unwrap();
    loop {
        let frame = host.wire.read().unwrap();
        if let Ok(text) = frame.to_text()
            && let DaemonControlMessage::OperationResult {
                operation_id,
                state,
                ..
            } = parse_daemon_control(text).unwrap()
            && operation_id == "cap-ping"
        {
            assert_eq!(state, OperationState::Failed);
            break;
        }
    }
}

#[test]
fn startup_census_and_durable_effects_enforce_cap_before_dispatch() {
    for (runtime, receipt, allowed) in [
        (FakeRuntime::new(), None, true),
        (preexisting(SandboxLifecycleState::Ready), None, false),
        (preexisting(SandboxLifecycleState::Stopped), None, true),
        (FakeRuntime::new(), Some(("sandbox.create", true)), false),
        (FakeRuntime::new(), Some(("sandbox.reconnect", true)), false),
        (FakeRuntime::new(), Some(("sandbox.create", false)), true),
        (
            preexisting(SandboxLifecycleState::Stopped),
            Some(("sandbox.create", true)),
            true,
        ),
    ] {
        let mut host = ConnectedHost::start(runtime, receipt);
        assert_eq!(
            host.send(&dispatch("fresh", "b", "sandbox.create", 1)),
            if allowed {
                OperationState::Succeeded
            } else {
                OperationState::Failed
            },
            "{receipt:?}, allowed={allowed}"
        );
    }
}

#[test]
fn wire_authority_and_journal_conflict_refusals_do_not_acquire() {
    let mut host = ConnectedHost::start(FakeRuntime::new(), None);
    // Stop of absent guest still fences generation; stale create cannot acquire.
    assert_eq!(
        host.send(&dispatch("stop", "a", "sandbox.stop", 2)),
        OperationState::Succeeded
    );
    assert_eq!(
        host.send(&dispatch("stale", "a", "sandbox.create", 1)),
        OperationState::UnknownOutcome
    );
    // Changed receipt body/binding is refused before acquisition.
    assert_eq!(
        host.send(&dispatch("stop", "a", "sandbox.create", 3)),
        OperationState::UnknownOutcome
    );
    assert_eq!(
        host.send(&dispatch("good", "b", "sandbox.create", 1)),
        OperationState::Succeeded
    );
}

#[test]
fn census_failure_prevents_connection_and_dispatch() {
    let dir = tempfile::tempdir().unwrap();
    let options = ConnectOptions {
        host_terminal: None,
        server_url: "ws://127.0.0.1:1".into(),
        host_token: "test-only-token".into(),
        host_id: "host".into(),
        label: "test".into(),
        runtime: HostRuntimeKind::Fake,
        incus_project: None,
        state_dir: Some(dir.path().into()),
        heartbeat: Duration::from_secs(30),
        sandbox_memory_mib: None,
        max_sandbox_cpu_count: None,
        sandbox_vcpu_budget: Some(1),
        max_concurrent_commands: 16,
        shutdown: Default::default(),
    };
    let error = run_connect_with(&options, |_| {
        Ok((Box::new(sandbox_runtime::UnsupportedRuntime::new()), None))
    })
    .unwrap_err();
    assert!(error.to_string().contains("host startup census failed"));
}

#[test]
fn restart_after_confirmed_kill_ignores_surviving_unknown_allocation_at_cap_one() {
    for confirm_during_startup in [false, true] {
        for kind in ["sandbox.create", "sandbox.reconnect"] {
            let mut host = ConnectedHost::start_with_journal(
                FakeRuntime::new(),
                |journal, binding| {
                    let old = dispatch("old-allocation", "a", kind, 1);
                    journal
                        .record_fixture_intent(&intent_from_dispatch(journal, binding, &old))
                        .unwrap();
                    journal.record_effect(&old.operation_id).unwrap();
                    journal
                        .record_result(
                            &old.operation_id,
                            OperationState::UnknownOutcome,
                            None,
                            Some(SandboxErrorCode::UnknownOutcome),
                            None,
                        )
                        .unwrap();
                    let cleanup = dispatch("cleanup", "a", "sandbox.kill", 2);
                    let intent = intent_from_dispatch(journal, binding, &cleanup);
                    journal.record_fixture_intent(&intent).unwrap();
                    journal.record_effect(&cleanup.operation_id).unwrap();
                    journal
                        .record_result(
                            &cleanup.operation_id,
                            OperationState::Succeeded,
                            Some(json!({"state":"deleted"})),
                            None,
                            None,
                        )
                        .unwrap();
                    if !confirm_during_startup {
                        assert!(
                            journal
                                .confirm(
                                    binding,
                                    &sandbox_protocol::ReceiptConfirmation {
                                        sandbox_owner_id: cleanup.sandbox_owner_id.clone(),
                                        operation_id: cleanup.operation_id,
                                        sandbox_id: cleanup.sandbox_id,
                                        generation: cleanup.generation,
                                        attempt: cleanup.attempt,
                                        body_hash: cleanup.body_hash.unwrap(),
                                        idempotency_key: cleanup.idempotency_key,
                                        kind: cleanup.kind,
                                        cleanup_generation: None,
                                        retire_command: false,
                                    }
                                )
                                .unwrap()
                        );
                        assert!(journal.lookup("cleanup").is_none());
                    }
                    assert!(journal.lookup("old-allocation").is_some());
                },
                confirm_during_startup,
            );
            assert_eq!(
                host.send(&dispatch("fresh", "b", "sandbox.create", 1)),
                OperationState::Succeeded,
                "{kind}, startup confirmation={confirm_during_startup}"
            );
        }
    }
}

/// 4b.3 + B2-C-1/B2-K-1: an ordinary-pool overflow on a pre-10.5 (10.0)
/// session is a definite FAILED `host_capacity` result, the existing legacy
/// code and never a teardown-grade one; the session and other work continue.
#[test]
fn ordinary_pool_overflow_is_host_capacity_and_keeps_the_session_open() {
    let held = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let entered = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (gate, seen) = (held.clone(), entered.clone());
    let runtime = preexisting(SandboxLifecycleState::Ready).with_guest_io_hook(
        move |io: &sandbox_runtime::FakeGuestIo<'_>| {
            if io.operation_id == "a-0" {
                seen.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            let deadline = Instant::now() + Duration::from_secs(20);
            while io.operation_id == "a-0"
                && gate.load(std::sync::atomic::Ordering::SeqCst)
                && Instant::now() < deadline
                && !io
                    .permit
                    .is_some_and(sandbox_runtime::RuntimePermit::is_cancelled)
            {
                thread::sleep(Duration::from_millis(5));
            }
            Ok(())
        },
    );
    let mut host = ConnectedHost::start(runtime, None);
    let mut results = HashMap::new();
    let read_until = |host: &mut ConnectedHost, id: &str, results: &mut HashMap<String, String>| {
        while !results.contains_key(id) {
            let frame = host.wire.read().unwrap();
            let text = frame.to_text().unwrap().to_string();
            if let DaemonControlMessage::OperationResult { operation_id, .. } =
                parse_daemon_control(&text).unwrap()
            {
                results.insert(operation_id, text);
            }
        }
    };
    // a-0 holds A's single active slot; a-1..a-4 fill A's four queued
    // slots; a-5 overflows A's admission.
    for n in 0..=5 {
        let mut d = dispatch(&format!("a-{n}"), "a", "file.stat", 1);
        d.path = Some("/file".into());
        let mut value = serde_json::to_value(&d).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("type".into(), json!("operation.dispatch"));
        host.wire
            .send(Message::Text(value.to_string().into()))
            .unwrap();
        if n == 0 {
            // a-0 leaves the queue (it is in guest IO) before the others.
            let deadline = Instant::now() + Duration::from_secs(5);
            while !entered.load(std::sync::atomic::Ordering::SeqCst) {
                assert!(Instant::now() < deadline, "a-0 never reached guest IO");
                thread::sleep(Duration::from_millis(2));
            }
        }
    }
    read_until(&mut host, "a-5", &mut results);
    let overflow: serde_json::Value = serde_json::from_str(&results["a-5"]).unwrap();
    assert_eq!(overflow["state"], json!("failed"), "{overflow}");
    assert_eq!(
        overflow["error"]["code"],
        json!("host_capacity"),
        "{overflow}"
    );
    for n in 0..=4 {
        assert!(
            !results.contains_key(&format!("a-{n}")),
            "a-{n} is still admitted"
        );
    }
    held.store(false, std::sync::atomic::Ordering::SeqCst);
    for n in 0..=4 {
        read_until(&mut host, &format!("a-{n}"), &mut results);
        let value: serde_json::Value = serde_json::from_str(&results[&format!("a-{n}")]).unwrap();
        assert_ne!(value["error"]["code"], json!("host_capacity"), "{value}");
    }
    // The same session still serves new work.
    let mut stat = dispatch("after", "a", "file.stat", 1);
    stat.path = Some("/file".into());
    let state = host.send(&stat);
    assert!(
        matches!(state, OperationState::Succeeded | OperationState::Failed),
        "{state:?}"
    );
}

/// Exercise reservation at production dispatch acceptance and its ownership
/// across the final upload ACK, rather than only calling the scheduler seam.
#[test]
fn upload_capacity_is_decided_before_bytes_and_held_until_final_submission() {
    let _staging = crate::sandbox_relay::test_support::staging_quota();
    for accept_upload in [false, true] {
        let held = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let entered = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (gate, seen) = (held.clone(), entered.clone());
        let runtime = preexisting(SandboxLifecycleState::Ready).with_guest_io_hook(move |io| {
            if io.operation_id == "held" {
                seen.store(true, std::sync::atomic::Ordering::SeqCst);
                let deadline = Instant::now() + Duration::from_secs(20);
                while gate.load(std::sync::atomic::Ordering::SeqCst)
                    && Instant::now() < deadline
                    && !io
                        .permit
                        .is_some_and(sandbox_runtime::RuntimePermit::is_cancelled)
                {
                    thread::sleep(Duration::from_millis(2));
                }
            }
            Ok(())
        });
        let mut host = ConnectedHost::start(runtime, None);
        let send = |host: &mut ConnectedHost, d: &OperationDispatch| {
            let mut value = serde_json::to_value(d).unwrap();
            value["type"] = json!("operation.dispatch");
            host.wire
                .send(Message::Text(value.to_string().into()))
                .unwrap();
        };
        let read_result = |host: &mut ConnectedHost, id: &str| {
            loop {
                let frame = host.wire.read().unwrap();
                if let DaemonControlMessage::OperationResult {
                    operation_id,
                    state,
                    error,
                    ..
                } = parse_daemon_control(frame.to_text().unwrap()).unwrap()
                    && operation_id == id
                {
                    break (state, error);
                }
            }
        };
        let mut stat = dispatch("held", "a", "file.stat", 1);
        stat.path = Some("/file".into());
        send(&mut host, &stat);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !entered.load(std::sync::atomic::Ordering::SeqCst) {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(2));
        }
        let mut put = dispatch("upload", "a", "file.put", 1);
        put.path = Some("/file".into());
        put.file_size = Some(4);
        put.file_sha256 = Some(crate::sandbox_relay::journal::sha256_hex(b"data"));
        if accept_upload {
            send(&mut host, &put);
        }
        for n in 0..4 {
            stat.operation_id = format!("queued-{n}");
            stat.idempotency_key = stat.operation_id.clone();
            send(&mut host, &stat);
        }
        if !accept_upload {
            send(&mut host, &put);
            let (state, error) = read_result(&mut host, "upload");
            held.store(false, std::sync::atomic::Ordering::SeqCst);
            assert_eq!(state, OperationState::Failed);
            assert_eq!(
                error.unwrap().code,
                SandboxErrorCode::HostCapacity,
                "must refuse without receiving bytes"
            );
        } else {
            // The upload already owns one of the four slots, so only three
            // stats fit, even before any upload bytes have arrived.
            let (state, error) = read_result(&mut host, "queued-3");
            assert_eq!(state, OperationState::Failed);
            assert_eq!(error.unwrap().code, SandboxErrorCode::HostCapacity);
            let metadata: StreamBinaryMetadata = serde_json::from_value(json!({
                "type":"stream.end", "streamId":"upload", "operationId":"upload", "generation":1, "attempt":1,
                "sequence":0, "offset":0, "final":true, "flags":{"fileUpload":true}
            }))
            .unwrap();
            let bytes = sandbox_protocol::encode_binary_frame(&metadata, b"data").unwrap();
            host.wire.send(Message::Binary(bytes.into())).unwrap();
            loop {
                let frame = host.wire.read().unwrap();
                if let DaemonControlMessage::FileChunkAck {
                    operation_id,
                    offset,
                    ..
                } = parse_daemon_control(frame.to_text().unwrap()).unwrap()
                {
                    assert_eq!(operation_id, "upload");
                    assert_eq!(offset, 4);
                    break;
                }
            }
            held.store(false, std::sync::atomic::Ordering::SeqCst);
            let (state, error) = read_result(&mut host, "upload");
            assert_eq!(state, OperationState::Succeeded, "{error:?}");
            assert!(error.is_none());
        }
    }
}

#[test]
fn receipt_replay_precedes_capacity_after_its_slot_is_reused() {
    // A durable result with no live instance still replays while another
    // sandbox owns all local capacity. No newer authority generation is forged.
    for max_slots in [1, 4] {
        let dir = tempfile::tempdir().unwrap();
        let binding = TransportBindingV11 {
            server: "wss://replay.test".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        };
        let journal = Arc::new(
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap(),
        );
        let accepted = dispatch("create-a", "a", "sandbox.create", 1);
        journal
            .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &accepted))
            .unwrap();
        journal
            .record_result(
                "create-a",
                OperationState::Succeeded,
                Some(json!({"state":"ready"})),
                None,
                None,
            )
            .unwrap();
        let mut slots = LiveSandboxAdmission::new(
            max_slots,
            sandbox_protocol::VmCapacity::new(1536, 4).unwrap(),
        );
        slots
            .try_acquire(
                "b",
                "current",
                1,
                sandbox_protocol::VmSize::defaults().unwrap(),
            )
            .unwrap();
        slots.finish_allocation("b", "current", OperationState::Succeeded);
        let runtime = Arc::new(FakeRuntime::new());
        let mut authority = HostAuthority::default();
        let relay =
            RelaySupervisor::start(runtime.clone(), journal.clone(), authority.clone(), None);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut socket = tungstenite::WebSocket::from_raw_socket(
            tungstenite::stream::MaybeTlsStream::Plain(tcp),
            tungstenite::protocol::Role::Client,
            None,
        );
        let mut wire = tungstenite::WebSocket::from_raw_socket(
            peer,
            tungstenite::protocol::Role::Server,
            None,
        );
        handle_dispatch(
            &mut socket,
            WireCodes::negotiated(sandbox_protocol::SANDBOX_RELAY_PROTOCOL_VERSION),
            &mut authority,
            &mut slots,
            (&journal, &binding),
            &relay,
            &None,
            &mut HashMap::new(),
            &accepted,
        )
        .unwrap();
        let value: serde_json::Value =
            serde_json::from_str(wire.read().unwrap().to_text().unwrap()).unwrap();
        assert_eq!(value["state"], "succeeded");
        assert_eq!(slots.held(), 1);
        assert_eq!(slots.sandbox_ids(), vec!["b"]);
        assert!(runtime.sandbox_inventory().unwrap().is_empty());
    }
}

#[test]
fn targeted_attestation_orders_dispatch_intent_before_snapshot_and_preserves_socket_control() {
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let release = std::sync::Mutex::new(release_rx);
    let lookups = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = lookups.clone();
    let runtime = FakeRuntime::new()
        .with_inventory_hook(move |stage| {
            if stage == "exists" {
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            Ok(())
        })
        .with_lifecycle_hook(move |stage| {
            if stage == "create" {
                entered_tx.send(()).unwrap();
                release
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap();
            }
            Ok(())
        });
    let mut host = ConnectedHost::start_with_protocol(runtime, |_, _| {}, false, 1, "1.0");
    host.send_dispatch(&dispatch("busy", "busy", "sandbox.create", 1));
    entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    // VM does not yet exist. The preceding dispatch's intent and lease must
    // already be visible to the ordered reader handling this request.
    host.wire
        .send(Message::Text(
            json!({"type":"allocation.attest.request", "connectionEpoch":1,
        "barrier":2, "sandboxIds":["busy","never"], "allocations": [{"sandboxOwnerId":"owner","sandboxId":"busy","allocation":crate::sandbox_relay::test_support::allocation()},{"sandboxOwnerId":"owner","sandboxId":"never","allocation":crate::sandbox_relay::test_support::allocation()}]})
            .to_string()
            .into(),
        ))
        .unwrap();
    loop {
        let frame = host.wire.read().unwrap();
        if let DaemonControlMessage::AllocationAttestResult {
            connection_epoch,
            barrier,
            entries,
            ..
        } = parse_daemon_control(frame.to_text().unwrap()).unwrap()
        {
            assert_eq!((connection_epoch, barrier), (1, 2));
            assert_eq!(
                entries
                    .iter()
                    .map(|e| e.settled_never_issued)
                    .collect::<Vec<_>>(),
                [false, true]
            );
            break;
        }
    }
    // Only "never" needs runtime IO: the preceding journal snapshot already
    // vetoed "busy". The unrelated control frame still stays responsive.
    assert_eq!(lookups.load(std::sync::atomic::Ordering::SeqCst), 1);
    host.wire.send(Message::Ping(vec![7].into())).unwrap();
    loop {
        if let Message::Pong(bytes) = host.wire.read().unwrap() {
            assert_eq!(bytes.as_ref(), &[7]);
            break;
        }
    }
    release_tx.send(()).unwrap();
    loop {
        let frame = host.wire.read().unwrap();
        if let DaemonControlMessage::OperationResult {
            operation_id,
            state,
            ..
        } = parse_daemon_control(frame.to_text().unwrap()).unwrap()
        {
            assert_eq!(operation_id, "busy");
            assert_eq!(state, OperationState::Succeeded);
            break;
        }
    }
}

#[test]
fn targeted_attestation_checks_runtime_presence_per_id() {
    let mut host =
        ConnectedHost::start_with_protocol(FakeRuntime::new(), |_, _| {}, false, 1, "1.0");
    // A VM with no journal record is still a per-id blocker.
    host.runtime
        .create_fixture(&CreateSandboxRequest::for_test("present", "untracked"))
        .unwrap();
    host.wire
        .send(Message::Text(
            json!({"type":"allocation.attest.request", "connectionEpoch":1,
        "barrier":1, "sandboxIds":["never","present"], "allocations": [{"sandboxOwnerId":"owner","sandboxId":"never","allocation":crate::sandbox_relay::test_support::allocation()},{"sandboxOwnerId":"owner","sandboxId":"present","allocation":crate::sandbox_relay::test_support::allocation()}]})
            .to_string()
            .into(),
        ))
        .unwrap();
    loop {
        let frame = host.wire.read().unwrap();
        if let DaemonControlMessage::AllocationAttestResult { entries, .. } =
            parse_daemon_control(frame.to_text().unwrap()).unwrap()
        {
            assert_eq!(
                entries
                    .iter()
                    .map(|e| e.settled_never_issued)
                    .collect::<Vec<_>>(),
                [true, false]
            );
            break;
        }
    }
}

#[test]
fn targeted_attestation_runtime_error_never_proves_absence() {
    let runtime = FakeRuntime::new().with_inventory_hook(|stage| {
        if stage == "exists" {
            return Err(sandbox_runtime::RuntimeError::new(
                SandboxErrorCode::Internal,
                "lookup unavailable",
            ));
        }
        Ok(())
    });
    let mut host = ConnectedHost::start_with_protocol(runtime, |_, _| {}, false, 1, "1.0");
    host.wire
        .send(Message::Text(
            json!({"type":"allocation.attest.request", "connectionEpoch":1,
        "barrier":1, "sandboxIds":["never"], "allocations": [{"sandboxOwnerId":"owner","sandboxId":"never","allocation":crate::sandbox_relay::test_support::allocation()}]})
            .to_string()
            .into(),
        ))
        .unwrap();
    loop {
        let frame = host.wire.read().unwrap();
        if let DaemonControlMessage::AllocationAttestResult { entries, .. } =
            parse_daemon_control(frame.to_text().unwrap()).unwrap()
        {
            assert!(!entries[0].settled_never_issued);
            break;
        }
    }
}

/// Lane e2e (no root): the production daemon loop against a fake guard on a
/// Unix socket. The daemon renews the guard lease with `host.egress-state`,
/// pushes `configured:false` to each new guard instance, and a create is
/// refused while the guard is unhealthy and admitted once it is healthy.
#[cfg(unix)]
#[test]
fn daemon_heartbeat_repush_and_create_follow_the_guard_socket() {
    use crate::sandbox_relay::test_support::FakeGuardServer;
    fn next_state(
        host: &mut ConnectedHost,
        want: impl Fn(&sandbox_protocol::HostEgressStateV11) -> bool,
    ) -> sandbox_protocol::HostEgressStateV11 {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            // The renewal period (5 s) equals the socket read timeout.
            let frame = match host.wire.read() {
                Ok(frame) => frame,
                Err(tungstenite::Error::Io(err))
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(err) => panic!("relay read: {err}"),
            };
            let Ok(text) = frame.to_text() else { continue };
            if let DaemonControlMessage::HostEgressState(state) =
                parse_daemon_control(text).unwrap()
            {
                assert!(state.is_valid(), "{state:?}");
                if want(&state) {
                    return state;
                }
            }
        }
        panic!("no matching host.egress-state");
    }
    fn send_blocklist(host: &mut ConnectedHost, entries: &[&str]) {
        let entries: Vec<String> = entries.iter().map(|e| e.to_string()).collect();
        let frame = sandbox_protocol::ServerControlMessage::EgressBlocklist(
            sandbox_protocol::EgressBlocklistV11 {
                configured: !entries.is_empty(),
                digest: crate::sandbox_relay::egress_state::blocklist_digest(&entries),
                entries,
                invalid: false,
            },
        );
        let text = sandbox_protocol::encode_server_control(&frame).unwrap();
        host.wire.send(Message::Text(text.into())).unwrap();
    }
    let guard = FakeGuardServer::start();
    let mut runtime = FakeRuntime::new();
    runtime.set_guard_probe(guard.probe());
    let mut host = ConnectedHost::start(runtime, None);
    // What the server sends after hello.ok (no deployment list configured).
    send_blocklist(&mut host, &[]);

    let first = next_state(&mut host, |s| s.guard_ok);
    assert_eq!(
        first.guard_instance_id.as_deref(),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
    assert!(first.guard_generation.unwrap() >= 1);
    assert!(!first.allow_open_for_others, "consent not asked: off");
    // Lease renewal: the same state again, with a higher sequence.
    let renewed = next_state(&mut host, |s| s.sequence > first.sequence);
    assert!(renewed.guard_ok);
    assert_eq!(renewed.connection_epoch, first.connection_epoch);

    // Guard restart: re-pushed to the new instance, reported at once.
    guard.restart_as("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    let restarted = next_state(&mut host, |s| {
        s.guard_ok && s.guard_instance_id.as_deref() == Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    });
    assert!(restarted.sequence > renewed.sequence);
    let pushes = guard.pushes();
    assert!(
        pushes.iter().all(|(_, configured)| !configured),
        "the server said configured:false: {pushes:?}"
    );
    assert!(pushes.iter().any(|(i, _)| i.starts_with('a')));
    assert!(pushes.iter().any(|(i, _)| i.starts_with('b')));

    // A changed server list is pushed to the current instance.
    send_blocklist(&mut host, &["203.0.113.0/24", "bad.example"]);
    let deadline = Instant::now() + Duration::from_secs(20);
    while !guard
        .pushes()
        .iter()
        .any(|(i, configured)| i.starts_with('b') && *configured)
    {
        assert!(Instant::now() < deadline, "configured list never pushed");
        thread::sleep(Duration::from_millis(50));
    }
    next_state(&mut host, |s| s.guard_ok);

    // Unhealthy guard: the lease is not renewed and a create is refused.
    guard.set_healthy(false);
    let down = next_state(&mut host, |s| !s.guard_ok);
    assert_eq!(down.guard_reason.as_deref(), Some("guard_not_ok"));
    let (state, error) = host.send_detail(&dispatch("refused", "a", "sandbox.create", 1));
    assert_eq!(state, OperationState::Failed);
    let error = error.unwrap();
    assert_eq!(error.code, SandboxErrorCode::UnsupportedCapability);
    // Typed refusal on the wire (the server maps it to egress_guard_unavailable).
    assert_eq!(
        error.reason,
        Some(sandbox_protocol::EgressRefusalReason::EgressGuardUnavailable.into())
    );

    guard.set_healthy(true);
    next_state(&mut host, |s| s.guard_ok);
    assert_eq!(
        host.send(&dispatch("admitted", "b", "sandbox.create", 1)),
        OperationState::Succeeded
    );
}
