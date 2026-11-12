//! Real sockets exercise the service lifetime, including terminal auth failures.
use super::super::clock::{ClockSource, LeaseClock};
use super::*;
use crate::sandbox_relay::test_support::FixtureRuntime;
use sandbox_protocol::{LeaseAction, SandboxLifecycleState};
use sandbox_runtime::{CreateSandboxRequest, FakeRuntime};
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

#[derive(Debug)]
struct Clock {
    wall: u64,
    elapsed: AtomicU64,
}
impl ClockSource for Clock {
    fn sample(&self) -> Result<(u64, u64)> {
        Ok((self.wall, self.elapsed.load(Ordering::SeqCst)))
    }
}
fn setup(
    listener: &TcpListener,
    dir: &std::path::Path,
    fake: &FakeRuntime,
    action: LeaseAction,
) -> (ConnectOptions, Arc<Clock>, Arc<LeaseClock>) {
    let address = listener.local_addr().unwrap();
    let opts = ConnectOptions {
        host_terminal: None,
        server_url: format!("ws://{address}"),
        host_token: "test-only-token".into(),
        host_id: "host-1".into(),
        label: "expiry".into(),
        runtime: HostRuntimeKind::Fake,
        incus_project: None,
        state_dir: Some(dir.into()),
        heartbeat: Duration::from_secs(5),
        sandbox_memory_mib: None,
        max_sandbox_cpu_count: None,
        sandbox_vcpu_budget: Some(4),
        max_concurrent_commands: 16,
        shutdown: Default::default(),
    };
    let binding = TransportBindingV11 {
        server: format!("ws://{address}/ws/sandbox-host"),
        host_owner_id: "owner-1".into(),
        host_id: opts.host_id.clone(),
    };
    let source = Arc::new(Clock {
        wall: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        elapsed: AtomicU64::new(0),
    });
    let clock = Arc::new(LeaseClock::new(source.clone()));
    seed(
        dir,
        &binding,
        &clock,
        fake,
        "sbx",
        source.wall + 1000,
        action,
    );
    (opts, source, clock)
}
pub(super) fn seed(
    dir: &std::path::Path,
    binding: &TransportBindingV11,
    clock: &Arc<LeaseClock>,
    fake: &FakeRuntime,
    id: &str,
    deadline: u64,
    action: LeaseAction,
) {
    let mut j = crate::sandbox_relay::test_support::open_ready_journal(dir, binding).unwrap();
    j.clock = clock.clone();
    let op = format!("create-{id}");
    let d:OperationDispatch=serde_json::from_value(json!({"sandboxOwnerId":"owner", "operationId":op,"sandboxId":id,"kind":"sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(),"generation":1,"attempt":1,"idempotencyKey":op,"bodyHash":"a".repeat(64),"lease":{"revision":1,"deadlineUnixMs":deadline,"action":action,"expiryPolicy":"retry-force-60s"}})).unwrap();
    j.record_fixture_intent(&intent_from_dispatch(&j, binding, &d))
        .unwrap();
    j.accept_fixture_lease(&d).unwrap();
    let mut req = CreateSandboxRequest::for_test(id, &op);
    // The journal's lease runs on the test clock (deadline = the wall sample
    // taken in `setup()` + 1 s); the fake validates against the REAL wall
    // clock, so a runner taking >1 s to open and seed the journal failed the
    // seed itself. Seed the VM under the dispatch's lease with the fixture's
    // far deadline; the journal keeps the 1 s test-clock lease.
    req.lease = sandbox_protocol::HostLease {
        deadline_unix_ms: sandbox_protocol::HostLease::for_test().deadline_unix_ms,
        ..d.lease.clone().unwrap()
    };
    fake.create_fixture(&req).unwrap();
    j.record_result(
        &op,
        OperationState::Succeeded,
        Some(json!({"state":"ready","lease":d.lease})),
        None,
        None,
    )
    .unwrap();
}
#[test]
fn expiry_survives_disconnect_and_terminal_credential_rejection() {
    for status in [0, 4003, 401, 403] {
        let dir = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let fake = FakeRuntime::new();
        fake.fixture_root().unwrap();
        let (opts, source, clock) = setup(&listener, dir.path(), &fake, LeaseAction::Stop);
        let shutdown = opts.shutdown.clone();
        let runtime = fake.clone();
        let client = thread::spawn(move || {
            run_connect_service(&opts, |_| Ok((Box::new(runtime), None)), clock)
        });
        let (mut tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        if matches!(status, 401 | 403) {
            let mut request = [0u8; 4096];
            assert!(tcp.read(&mut request).unwrap() > 0);
            write!(
                tcp,
                "HTTP/1.1 {status} Denied\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
            )
            .unwrap();
        } else {
            let mut wire = tungstenite::accept_hdr(tcp, tests::RelayHandshake).unwrap();
            wire.read().unwrap();
            wire.close(Some(tungstenite::protocol::CloseFrame {
                code: if status == 4003 {
                    tungstenite::protocol::frame::coding::CloseCode::Library(4003)
                } else {
                    tungstenite::protocol::frame::coding::CloseCode::Normal
                },
                reason: "test".into(),
            }))
            .unwrap();
        }
        // No activity from the server is required to trigger cleanup.
        assert_eq!(
            fake.query_sandbox("sbx", None, None).unwrap(),
            Some(SandboxLifecycleState::Ready)
        );
        assert!(
            !client.is_finished(),
            "relay teardown killed the local lease owner"
        );
        source.elapsed.store(1001, Ordering::SeqCst);
        let deadline = Instant::now() + Duration::from_secs(3);
        if status == 0 {
            // A server close never ends the daemon (P0-1): the lease is
            // enforced while it reconnects; only a local shutdown ends it.
            while fake.query_sandbox("sbx", None, None).unwrap()
                != Some(SandboxLifecycleState::Stopped)
            {
                assert!(Instant::now() < deadline, "offline expiry did not settle");
                thread::sleep(Duration::from_millis(5));
            }
            assert!(!client.is_finished(), "a 1000 close ended the daemon");
            shutdown.request();
        }
        while !client.is_finished() {
            assert!(Instant::now() < deadline, "offline expiry did not settle");
            thread::sleep(Duration::from_millis(5));
        }
        let result = client.join().unwrap();
        if status != 0 {
            assert_eq!(
                crate::exit::code_for(&result.unwrap_err()),
                ExitCode::CredentialInactive
            );
        } else {
            result.unwrap();
        }
        assert_eq!(
            fake.query_sandbox("sbx", None, None).unwrap(),
            Some(SandboxLifecycleState::Stopped)
        );
    }
}
#[test]
fn expiry_restart_does_not_connect_or_announce_ready_until_cleanup_is_confirmed() {
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let release = Mutex::new(release_rx);
    let fake = FakeRuntime::new().with_lifecycle_hook(move |s| {
        if s == "stop" {
            entered_tx.send(()).unwrap();
            release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(3))
                .unwrap();
        }
        Ok(())
    });
    fake.fixture_root().unwrap();
    let (opts, source, clock) = setup(&listener, dir.path(), &fake, LeaseAction::Destroy);
    source.elapsed.store(1001, Ordering::SeqCst);
    let runtime = fake.clone();
    let shutdown = opts.shutdown.clone();
    let client =
        thread::spawn(move || run_connect_service(&opts, |_| Ok((Box::new(runtime), None)), clock));
    entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(
        matches!(listener.accept(),Err(e) if e.kind()==ErrorKind::WouldBlock),
        "host connected before overdue cleanup"
    );
    release_tx.send(()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let tcp = loop {
        match listener.accept() {
            Ok((tcp, _)) => break tcp,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline);
                thread::sleep(Duration::from_millis(5));
            }
            Err(e) => panic!("{e}"),
        }
    };
    tcp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut wire = tungstenite::accept_hdr(tcp, tests::RelayHandshake).unwrap();
    wire.read().unwrap();
    assert!(fake.query_sandbox("sbx", None, None).unwrap().is_none());
    shutdown.request();
    client.join().unwrap().unwrap();
}

#[test]
fn expiry_closes_upload_download_and_stdin_before_timer_cleanup() {
    let _staging = crate::sandbox_relay::test_support::staging_quota();
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let fake = FakeRuntime::new();
    fake.fixture_root().unwrap();
    let (opts, source, clock) = setup(&listener, dir.path(), &fake, LeaseAction::Stop);
    let binding = TransportBindingV11 {
        server: format!("{}/ws/sandbox-host", opts.server_url),
        host_owner_id: "owner-1".into(),
        host_id: "host-1".into(),
    };
    let mut journal =
        crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding).unwrap();
    journal.clock = clock;
    let j = Arc::new(journal);
    let authority = HostAuthority::with_journal(j.clone());
    let mut puts = HashMap::new();
    let mut downloads = Downloads::new();
    for (id, kind) in [
        ("put", "file.put"),
        ("get", "file.get"),
        ("stdin", "command.run"),
    ] {
        let d:OperationDispatch=serde_json::from_value(json!({"sandboxOwnerId":"owner", "operationId":id,"sandboxId":"sbx","kind":kind,"generation":1,"attempt":1,"idempotencyKey":id,"bodyHash":"a".repeat(64)})).unwrap();
        j.record_fixture_intent(&intent_from_dispatch(&j, &binding, &d))
            .unwrap();
        authority.accept_dispatch(id, "sbx", kind, 1, 1).unwrap();
        if id == "put" {
            puts.insert(
                id.into(),
                PendingFilePut {
                    reservation: crate::sandbox_relay::supervisor::UploadReservation::for_test(
                        "sbx-1", "owner",
                    ),
                    dispatch: d,
                    instance_name: "wssp-sbx-sbx".into(),
                    spool: sandbox_runtime::FileStaging::new(4).unwrap(),
                    next: 0,
                    last: None,
                    started: Instant::now(),
                    touched: Instant::now(),
                },
            );
        }
    }
    downloads.insert(
        "get".into(),
        (
            FinishedOp {
                operation_id: "get".into(),
                sandbox_id: "sbx".into(),
                generation: 1,
                attempt: 1,
                state: OperationState::Succeeded,
                payload: None,
                error: None,
                download: None,
                interim: false,
                readiness_detail: None,
                owner: None,
            },
            super::super::files::DownloadWindow::new(
                sandbox_runtime::FileContent::from_bytes(b"test").unwrap(),
            ),
        ),
    );
    assert!(
        settle_transfers(Instant::now(), &mut puts, &mut downloads, &authority, &j)
            .unwrap()
            .is_empty()
    );
    assert_eq!((puts.len(), downloads.len()), (1, 1));
    source.elapsed.store(1001, Ordering::SeqCst);
    assert!(
        settle_transfers(Instant::now(), &mut puts, &mut downloads, &authority, &j)
            .unwrap()
            .is_empty()
    );
    assert!(puts.is_empty() && downloads.is_empty());
    assert_eq!(
        j.lookup("put").unwrap().error_code,
        Some(SandboxErrorCode::Cancelled.into())
    );
    #[cfg(target_os = "linux")]
    assert!(
        authority
            .accept_stdin("stdin", 1, 1, 0, b"late".to_vec(), false)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        fake.query_sandbox("sbx", None, None).unwrap(),
        Some(SandboxLifecycleState::Ready)
    );
    let expiry =
        super::super::expiry::ExpiryService::start(Arc::new(fake.clone()), j.clone(), authority);
    expiry.reconcile().unwrap();
    assert_eq!(
        fake.query_sandbox("sbx", None, None).unwrap(),
        Some(SandboxLifecycleState::Stopped)
    );
}

fn accept_registered(
    listener: &TcpListener,
) -> (
    tungstenite::WebSocket<std::net::TcpStream>,
    Vec<sandbox_protocol::InventoryEntry>,
) {
    let (tcp, _) = listener.accept().unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut wire = tungstenite::accept_hdr(tcp, tests::RelayHandshake).unwrap();
    wire.read().unwrap();
    crate::sandbox_relay::test_support::send_sized_hello(
        &mut wire,
        &TransportBindingV11 {
            server: format!("ws://{}/ws/sandbox-host", listener.local_addr().unwrap()),
            host_owner_id: "owner-1".into(),
            host_id: "host-1".into(),
        },
    );
    let census = crate::sandbox_relay::test_support::ack_reconciliation(&mut wire);
    (wire, census)
}
fn failing_stop(fail: &Arc<std::sync::atomic::AtomicBool>, fake: FakeRuntime) -> FakeRuntime {
    let flag = fail.clone();
    fake.with_lifecycle_hook(move |s| {
        if s == "stop" && flag.load(Ordering::SeqCst) {
            return Err(sandbox_runtime::RuntimeError::new(
                SandboxErrorCode::UnknownOutcome,
                "injected stop failure",
            ));
        }
        Ok(())
    })
}
fn until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !done() {
        assert!(Instant::now() < deadline, "{what}");
        thread::sleep(Duration::from_millis(5));
    }
}
fn create(wire: &mut tungstenite::WebSocket<std::net::TcpStream>, id: &str, sandbox: &str) {
    const FP: &str = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    wire.send(Message::Text(
        json!({"sandboxOwnerId":"owner", "type":"operation.dispatch", "digestScheme":"hmac-sha256-v1", "digestKeyId":"d".repeat(32),"operationId":id,"sandboxId":sandbox,"kind":"sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(), "cpuCount":1, "memoryMiB":1024,
            "lease":sandbox_protocol::HostLease::for_test(),"generation":1,"attempt":1,"idempotencyKey":id,
            "bodyHash":"a".repeat(64),"templateDigest":FP,"incusFingerprint":FP,"architecture":"x86_64"})
        .to_string()
        .into(),
    ))
    .unwrap();
}
/// Reads until the result of `id`, keeping every expiry status frame seen.
fn result_of(
    wire: &mut tungstenite::WebSocket<std::net::TcpStream>,
    id: &str,
    statuses: &mut Vec<sandbox_protocol::InventoryEntry>,
) -> OperationState {
    loop {
        let frame = wire.read().unwrap();
        let Ok(text) = frame.to_text() else { continue };
        match sandbox_protocol::parse_daemon_control(text).unwrap() {
            DaemonControlMessage::OperationResult {
                operation_id,
                state,
                ..
            } if operation_id == id => return state,
            DaemonControlMessage::SandboxExpiryStatus { entries, .. } => statuses.extend(entries),
            _ => {}
        }
    }
}

#[test]
fn expiry_recovered_after_the_census_is_reported_and_frees_host_capacity_without_reconnect() {
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let fail = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let fake = failing_stop(&fail, FakeRuntime::new());
    let (mut opts, source, clock) = setup(&listener, dir.path(), &fake, LeaseAction::Stop);
    opts.sandbox_vcpu_budget = Some(1);
    // The recovery lands between the census acknowledgement and this heartbeat.
    opts.heartbeat = Duration::from_secs(15);
    source.elapsed.store(1001, Ordering::SeqCst);
    let runtime = fake.clone();
    let shutdown = opts.shutdown.clone();
    let client =
        thread::spawn(move || run_connect_service(&opts, |_| Ok((Box::new(runtime), None)), clock));
    let (mut wire, census) = accept_registered(&listener);
    let started = Instant::now();
    let lease = census[0].lease.clone().unwrap();
    assert!(lease.expiry_failure.is_some() && !lease.expiry_complete);
    let mut statuses = Vec::new();
    create(&mut wire, "while-failing", "other");
    assert_eq!(
        result_of(&mut wire, "while-failing", &mut statuses),
        OperationState::Failed,
        "an unconfirmed expiry keeps its reservation"
    );
    fail.store(false, Ordering::SeqCst);
    until("local expiry did not recover", || {
        fake.query_sandbox("sbx", None, None).unwrap() == Some(SandboxLifecycleState::Stopped)
    });
    // The journal checkpoint follows the runtime stop; poll admission until freed.
    let mut attempt = 0;
    loop {
        attempt += 1;
        let id = format!("replacement-{attempt}");
        create(&mut wire, &id, "other");
        if result_of(&mut wire, &id, &mut statuses) == OperationState::Succeeded {
            break;
        }
        assert!(
            attempt < 50,
            "recovered expiry never released host capacity"
        );
        thread::sleep(Duration::from_millis(20));
    }
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "recovery must precede the first heartbeat: elapsed={:?}, statuses={}, attempts={attempt}",
        started.elapsed(),
        statuses.len()
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while !statuses
        .iter()
        .any(|e| e.lease.as_ref().is_some_and(|l| l.expiry_complete))
    {
        assert!(Instant::now() < deadline, "recovery was never reported");
        let frame = wire.read().unwrap();
        let Ok(text) = frame.to_text() else { continue };
        if let DaemonControlMessage::SandboxExpiryStatus { entries, .. } =
            sandbox_protocol::parse_daemon_control(text).unwrap()
        {
            statuses.extend(entries);
        }
    }
    let entry = statuses
        .iter()
        .find(|e| e.lease.as_ref().is_some_and(|l| l.expiry_complete))
        .unwrap();
    let lease = entry.lease.as_ref().unwrap();
    assert_eq!(
        (entry.sandbox_id.as_str(), entry.state),
        ("sbx", SandboxLifecycleState::Stopped)
    );
    assert!(lease.expiry_complete && lease.expiry_failure.is_none());
    fake.kill_fixture(&sandbox_runtime::KillSandboxRequest {
        instance_name: "wssp-sbx-other".into(),
        sandbox_id: "other".into(),
        template_fingerprint: String::new(),
        operation_id: "cleanup".into(),
        idempotency_key: "cleanup".into(),
    })
    .unwrap();
    shutdown.request();
    client.join().unwrap().unwrap();
}

#[test]
fn slow_expiry_inventory_never_blocks_heartbeats_or_cancellation() {
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let fail = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let slow = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let release = Mutex::new(release_rx);
    let gate = slow.clone();
    let fake = failing_stop(
        &fail,
        FakeRuntime::with_command_delay(Duration::from_secs(10)),
    )
    .with_query_hook(move |_| {
        if gate.swap(false, Ordering::SeqCst) {
            entered_tx.send(()).unwrap();
            // Stands in for an Incus call stalled up to its host-call timeout.
            let _ = release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(20));
        }
        Ok(())
    });
    let (mut opts, source, clock) = setup(&listener, dir.path(), &fake, LeaseAction::Stop);
    let binding = TransportBindingV11 {
        server: format!("{}/ws/sandbox-host", opts.server_url),
        host_owner_id: "owner-1".into(),
        host_id: "host-1".into(),
    };
    seed(
        dir.path(),
        &binding,
        &clock,
        &fake,
        "ok",
        source.wall + 3_600_000,
        LeaseAction::Stop,
    );
    opts.heartbeat = Duration::from_millis(100);
    source.elapsed.store(1001, Ordering::SeqCst);
    let runtime = fake.clone();
    let shutdown = opts.shutdown.clone();
    let client =
        thread::spawn(move || run_connect_service(&opts, |_| Ok((Box::new(runtime), None)), clock));
    let (mut wire, census) = accept_registered(&listener);
    assert!(
        census
            .iter()
            .any(|e| e.sandbox_id == "sbx" && e.lease.as_ref().unwrap().expiry_failure.is_some())
    );
    // Heartbeats start only once registration (and its admission rebuild,
    // which reads the inventory) has finished.
    while !matches!(
        sandbox_protocol::parse_daemon_control(wire.read().unwrap().to_text().unwrap()).unwrap(),
        DaemonControlMessage::Heartbeat { .. }
    ) {}
    // The next failed retry changes the published attempt count, which makes
    // an expiry status observation due on a heartbeat tick.
    slow.store(true, Ordering::SeqCst);
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let blocked = Instant::now();
    wire.send(Message::Text(json!({"sandboxOwnerId":"owner", "type":"operation.dispatch", "digestScheme":"hmac-sha256-v1", "digestKeyId":"d".repeat(32),"operationId":"run","sandboxId":"ok","kind":"command.run", "resultVersion":1, "processId":"proc-run","incusFingerprint":CreateSandboxRequest::for_test("ok","create-ok").template_digest,"generation":1,"attempt":1,"idempotencyKey":"run","bodyHash":"a".repeat(64),"argv":["true"]}).to_string().into())).unwrap();
    let mut storage_fresh = false;
    let mut pending_cancel = None;
    let mut heartbeats = 0;
    let mut last_beat = Instant::now();
    loop {
        match wire.read().unwrap() {
            Message::Text(text) => match sandbox_protocol::parse_daemon_control(&text).unwrap() {
                DaemonControlMessage::Heartbeat { .. } => {
                    assert!(
                        last_beat.elapsed() < Duration::from_secs(1),
                        "heartbeat stalled behind runtime inventory"
                    );
                    last_beat = Instant::now();
                    heartbeats += 1;
                }
                DaemonControlMessage::OperationResult {
                    operation_id,
                    state,
                    ..
                } => {
                    assert_eq!(
                        (operation_id.as_str(), state),
                        ("run", OperationState::UnknownOutcome)
                    );
                    break;
                }
                DaemonControlMessage::InventoryUpdate {
                    observation_sequence,
                    storage_pools,
                    ..
                } => {
                    assert!(observation_sequence > 0);
                    assert!(storage_pools.iter().all(
                        |p| p.health == sandbox_protocol::capacity_v11::StorageHealth::Healthy
                    ));
                    storage_fresh = true;
                    if let Some(cancel) = pending_cancel.take() {
                        wire.send(Message::Text(cancel)).unwrap();
                    }
                }
                DaemonControlMessage::SandboxExpiryStatus { .. } => {
                    panic!("status published before the blocked inventory returned")
                }
                _ => {}
            },
            Message::Binary(data) => {
                let (metadata, _) = sandbox_protocol::parse_binary_frame(&data).unwrap();
                wire.send(crate::sandbox_relay::test_support::command_output_ack(
                    &data,
                ))
                .unwrap();
                let cancel = json!({"type":"operation.cancel","operationId":metadata.operation_id,"generation":metadata.generation,"attempt":metadata.attempt,"reason":"cancelled"}).to_string().into();
                if storage_fresh {
                    wire.send(Message::Text(cancel)).unwrap();
                } else {
                    pending_cancel = Some(cancel);
                }
            }
            _ => {}
        }
    }
    assert!(
        storage_fresh && heartbeats >= 3 && blocked.elapsed() < Duration::from_secs(9),
        "storage health, heartbeats and cancellation must progress during blocked lifecycle observation"
    );
    release_tx.send(()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        assert!(
            Instant::now() < deadline,
            "status never published after the inventory returned"
        );
        let frame = wire.read().unwrap();
        let Ok(text) = frame.to_text() else { continue };
        if let DaemonControlMessage::SandboxExpiryStatus { entries, .. } =
            sandbox_protocol::parse_daemon_control(text).unwrap()
        {
            assert!(entries.iter().any(|e| e.sandbox_id == "sbx"));
            break;
        }
    }
    fail.store(false, Ordering::SeqCst);
    fake.stop_sandbox(&sandbox_runtime::StopSandboxRequest {
        sandbox_id: "ok".into(),
        instance_name: "wssp-sbx-ok".into(),
        operation_id: "cleanup".into(),
        idempotency_key: "cleanup".into(),
        template_fingerprint: String::new(),
    })
    .unwrap();
    shutdown.request();
    client.join().unwrap().unwrap();
}

#[test]
fn connected_first_attempt_expiry_success_is_published_without_a_failure() {
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let fake = FakeRuntime::new();
    fake.fixture_root().unwrap();
    let (mut opts, source, clock) = setup(&listener, dir.path(), &fake, LeaseAction::Stop);
    opts.heartbeat = Duration::from_millis(100);
    // The deadline passes only after registration: nothing to reconcile, so the
    // census shows a live lease and no failure map change ever happens.
    let runtime = fake.clone();
    let shutdown = opts.shutdown.clone();
    let client =
        thread::spawn(move || run_connect_service(&opts, |_| Ok((Box::new(runtime), None)), clock));
    let (mut wire, census) = accept_registered(&listener);
    let lease = census[0].lease.clone().unwrap();
    assert!(!lease.expired && !lease.expiry_complete && lease.expiry_failure.is_none());
    source.elapsed.store(1001, Ordering::SeqCst);
    until("local expiry did not stop the sandbox", || {
        fake.query_sandbox("sbx", None, None).unwrap() == Some(SandboxLifecycleState::Stopped)
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        assert!(
            Instant::now() < deadline,
            "first-attempt expiry success was never published"
        );
        let frame = wire.read().unwrap();
        let Ok(text) = frame.to_text() else { continue };
        if let DaemonControlMessage::SandboxExpiryStatus { entries, .. } =
            sandbox_protocol::parse_daemon_control(text).unwrap()
        {
            let entry = entries
                .iter()
                .find(|e| e.sandbox_id == "sbx")
                .expect("sbx status");
            let lease = entry.lease.as_ref().unwrap();
            assert_eq!(entry.state, SandboxLifecycleState::Stopped);
            assert!(
                lease.expired
                    && lease.expiry_complete
                    && lease.timer_expired
                    && lease.expiry_failure.is_none()
            );
            break;
        }
    }
    shutdown.request();
    client.join().unwrap().unwrap();
}

#[test]
fn shortened_and_extended_leases_survive_terminal_auth_failure_with_monotonic_enforcement() {
    for duration in [500, 2000] {
        let dir = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let fake = FakeRuntime::new();
        fake.fixture_root().unwrap();
        let (opts, source, clock) = setup(&listener, dir.path(), &fake, LeaseAction::Stop);
        let binding = TransportBindingV11 {
            server: format!("ws://{}/ws/sandbox-host", listener.local_addr().unwrap()),
            host_owner_id: "owner-1".into(),
            host_id: "host-1".into(),
        };
        let mut journal =
            crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding).unwrap();
        journal.clock = clock.clone();
        let renew: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner",
            "operationId":"renew", "sandboxId":"sbx", "kind":"sandbox.lease.renew",
            "generation":1, "attempt":1, "idempotencyKey":"renew", "bodyHash":"b".repeat(64),
            "lease":{"revision":2,"deadlineUnixMs":source.wall + duration,"action":"stop","expiryPolicy":"retry-force-60s"}
        })).unwrap();
        journal
            .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &renew))
            .unwrap();
        journal.accept_fixture_lease(&renew).unwrap();
        journal
            .record_result(
                "renew",
                OperationState::Succeeded,
                Some(json!({"lease":renew.lease})),
                None,
                None,
            )
            .unwrap();
        drop(journal);
        let runtime = fake.clone();
        let journal_dir = dir.path().to_owned();
        let client = thread::spawn(move || {
            run_connect_service(&opts, |_| Ok((Box::new(runtime), None)), clock)
        });
        let (mut tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut request = [0u8; 4096];
        assert!(tcp.read(&mut request).unwrap() > 0);
        write!(
            tcp,
            "HTTP/1.1 401 Denied\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
        )
        .unwrap();

        if duration == 2000 {
            source.elapsed.store(1001, Ordering::SeqCst);
            // Observe a persisted timer poll past the OLD deadline; this is
            // evidence of keeping the extension, not an immediate-state race.
            let until = Instant::now() + Duration::from_secs(3);
            loop {
                assert!(
                    !client.is_finished(),
                    "old deadline ended an extended lease"
                );
                let observed = std::fs::read_dir(journal_dir.join("leases"))
                    .unwrap()
                    .filter_map(|entry| {
                        let path = entry.ok()?.path();
                        if path.extension()?.to_str()? != "json" {
                            return None;
                        }
                        let bytes = std::fs::read(path).ok()?;
                        let envelope: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
                        envelope.get("record")?.get("observedUnixMs")?.as_u64()
                    })
                    .max();
                if observed.is_some_and(|time| time >= source.wall + 1000) {
                    break;
                }
                assert!(
                    Instant::now() < until,
                    "timer did not checkpoint the extension"
                );
                thread::sleep(Duration::from_millis(5));
            }
            assert_eq!(
                fake.query_sandbox("sbx", None, None).unwrap(),
                Some(SandboxLifecycleState::Ready)
            );
        }
        source.elapsed.store(duration + 1, Ordering::SeqCst);
        let until = Instant::now() + Duration::from_secs(3);
        while !client.is_finished() {
            assert!(
                Instant::now() < until,
                "updated offline deadline did not settle"
            );
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            crate::exit::code_for(&client.join().unwrap().unwrap_err()),
            ExitCode::CredentialInactive
        );
        assert_eq!(
            fake.query_sandbox("sbx", None, None).unwrap(),
            Some(SandboxLifecycleState::Stopped)
        );
    }
}

/// D-20: the real durable expiry service, fake VM/runtime and logical lease clock.
#[test]
fn d20_command_lease_renew_shorten_expiry_offline_revoke_matrix() {
    use sandbox_runtime::{CommandOutput, RunCommandRequest};
    for timeout in [0, 1_800_000] {
        for ending in ["expiry", "shorten", "renew", "offline", "revoke"] {
            let dir = tempfile::tempdir().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let (ready, started) = mpsc::channel();
            let command_origin = Instant::now();
            let command_clock = Arc::new(Mutex::new(command_origin));
            let positive_renewal = timeout > 0 && ending == "renew";
            let fake = FakeRuntime::with_command_delay(Duration::from_secs(600))
                .with_command_clock(command_clock.clone())
                .with_lifecycle_hook(move |stage| {
                    if stage == "command-output" {
                        let _ = ready.send(());
                    }
                    Ok(())
                });
            fake.fixture_root().unwrap();
            let (opts, source, clock) = setup(&listener, dir.path(), &fake, LeaseAction::Stop);
            let binding = TransportBindingV11 {
                server: format!("ws://{}/ws/sandbox-host", listener.local_addr().unwrap()),
                host_owner_id: "owner-1".into(),
                host_id: opts.host_id,
            };
            let mut journal =
                crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
                    .unwrap();
            journal.clock = clock;
            let journal = Arc::new(journal);
            let renew = |revision: u64, duration: u64| {
                let dispatch: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner",
                    "operationId":format!("lease-{revision}"), "sandboxId":"sbx", "kind":"sandbox.lease.renew", "generation":1, "attempt":1,
                    "idempotencyKey":format!("lease-{revision}"), "bodyHash":"b".repeat(64),
                    "lease":{"revision":revision, "deadlineUnixMs":source.wall + duration, "action":"stop", "expiryPolicy":"retry-force-60s"}
                })).unwrap();
                journal
                    .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &dispatch))
                    .unwrap();
                journal.accept_fixture_lease(&dispatch).unwrap();
                journal
                    .record_result(
                        &dispatch.operation_id,
                        OperationState::Succeeded,
                        Some(json!({"lease":dispatch.lease})),
                        None,
                        None,
                    )
                    .unwrap();
            };
            renew(2, 300_000);
            let authority = HostAuthority::with_journal(journal.clone());
            authority
                .accept_dispatch("timer", "sbx", "command.run", 1, 1)
                .unwrap();
            let permit = authority.register_runtime("timer", 1, 1).unwrap();
            let runtime = fake.with_cancellation(permit.clone());
            let expiry = super::super::expiry::ExpiryService::start(
                Arc::new(fake.clone()),
                journal.clone(),
                authority.clone(),
            );
            let (done, result) = mpsc::channel();
            let worker = thread::spawn(move || {
                done.send(runtime.run_command_stream(
                    &RunCommandRequest {
                        template_fingerprint:
                            CreateSandboxRequest::for_test("sbx", "create-sbx").template_digest,
                        sandbox_id: "sbx".into(),
                        instance_name: "wssp-sbx-sbx".into(),
                        operation_id: "timer".into(),
                        idempotency_key: "timer".into(),
                        generation: 1,
                        attempt: 1,
                        argv: vec!["sleep".into(), "600".into()],
                        script: None,
                        cwd: None,
                        timeout_ms: Some(if positive_renewal { 200_000 } else { timeout }),
                        env: vec![],
                        stdin: None,
                        guest: Default::default(),
                        build_step: None,
                    },
                    &CommandOutput::default(),
                ))
                .unwrap();
            });
            started.recv_timeout(Duration::from_secs(2)).unwrap();
            *command_clock.lock().unwrap() = command_origin + Duration::from_secs(121);
            source.elapsed.store(121_000, Ordering::SeqCst);
            expiry.reconcile().unwrap();
            assert!(
                !permit.is_cancelled(),
                "neither mode loses authority at 120s"
            );
            assert!(result.try_recv().is_err());
            let deadline = match ending {
                "renew" => {
                    renew(3, 600_000);
                    600_001
                }
                "shorten" => {
                    renew(3, 122_000);
                    122_001
                }
                "offline" | "revoke" => {
                    authority.shutdown();
                    300_001
                }
                _ => 300_001,
            };
            if positive_renewal {
                // Renewal was durably accepted at +121s. The command must end
                // at +200s, not +321s; the renewed lease is still live.
                assert_eq!(journal.lease("sbx").unwrap().lease.revision, 3);
                *command_clock.lock().unwrap() = command_origin + Duration::from_millis(199_999);
                source.elapsed.store(199_999, Ordering::SeqCst);
                expiry.reconcile().unwrap();
                assert!(result.recv_timeout(Duration::from_millis(50)).is_err());
                *command_clock.lock().unwrap() = command_origin + Duration::from_secs(200);
                source.elapsed.store(200_000, Ordering::SeqCst);
                expiry.reconcile().unwrap();
                let outcome = result.recv_timeout(Duration::from_secs(2)).ok();
                let fired = outcome.is_some();
                if !fired {
                    authority.shutdown();
                }
                worker.join().unwrap();
                assert!(
                    fired,
                    "renewal must not restart the positive timer: original +200s deadline"
                );
                assert_eq!(
                    outcome.unwrap().unwrap_err().code,
                    SandboxErrorCode::Timeout
                );
                assert!(
                    !permit.is_cancelled(),
                    "renewed lease still grants authority"
                );
                assert_eq!(
                    fake.query_sandbox("sbx", None, None).unwrap(),
                    Some(SandboxLifecycleState::Ready)
                );
                continue;
            }
            if ending == "renew" {
                source.elapsed.store(300_001, Ordering::SeqCst);
                expiry.reconcile().unwrap();
                assert!(
                    !permit.is_cancelled(),
                    "the accepted renewal survives the old lease deadline"
                );
            }
            source.elapsed.store(deadline, Ordering::SeqCst);
            expiry.reconcile().unwrap();
            until(
                "durable lease expiry did not revoke command authority",
                || permit.is_cancelled(),
            );
            let outcome = result.recv_timeout(Duration::from_secs(3)).unwrap();
            worker.join().unwrap();
            assert_eq!(outcome.unwrap_err().code, SandboxErrorCode::UnknownOutcome);
            assert_eq!(
                fake.query_sandbox("sbx", None, None).unwrap(),
                Some(SandboxLifecycleState::Stopped)
            );
            assert!(journal.lease("sbx").unwrap().expiry_complete);
        }
    }
}
