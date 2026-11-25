//! Real sockets: in-flight work survives a relay transport loss and is
//! adopted on reconnect, while server verdicts, credential failures and
//! shutdown still revoke it at once.
use super::*;
use sandbox_protocol::parse_daemon_control;
use std::net::{TcpListener, TcpStream};

type Wire = tungstenite::WebSocket<TcpStream>;

fn options(listener: &TcpListener, dir: &std::path::Path, heartbeat: Duration) -> ConnectOptions {
    let address = listener.local_addr().expect("address");
    ConnectOptions {
        host_terminal: None,
        server_url: format!("ws://{address}"),
        host_token: "test-only-token".into(),
        host_id: "host".into(),
        label: "test".into(),
        runtime: HostRuntimeKind::Fake,
        incus_project: None,
        state_dir: Some(dir.into()),
        heartbeat,
        sandbox_memory_mib: None,
        max_sandbox_cpu_count: None,
        sandbox_vcpu_budget: Some(4),
        max_concurrent_commands: 16,
        shutdown: Default::default(),
    }
}

/// A running sandbox `sbx` whose create already succeeded.
fn seed(listener: &TcpListener, dir: &std::path::Path, fake: &sandbox_runtime::FakeRuntime) {
    let address = listener.local_addr().expect("address");
    fake.create_fixture(&sandbox_runtime::CreateSandboxRequest::for_test(
        "sbx", "create",
    ))
    .unwrap();
    let binding = TransportBindingV11 {
        server: format!("ws://{address}/ws/sandbox-host"),
        host_owner_id: "owner-1".into(),
        host_id: "host".into(),
    };
    let journal = crate::sandbox_relay::test_support::open_journal(dir, &binding).unwrap();
    let d: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner", "operationId":"create", "sandboxId":"sbx", "kind":"sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(), "cpuCount": 1, "memoryMiB": 1024, "generation":1, "attempt":1, "idempotencyKey":"create", "bodyHash":"a".repeat(64), "lease":sandbox_protocol::HostLease::for_test()})).unwrap();
    journal
        .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &d))
        .unwrap();
    journal.accept_fixture_lease(&d).unwrap();
    journal
        .record_result(
            "create",
            OperationState::Succeeded,
            Some(json!({"state":"ready","lease":d.lease})),
            None,
            None,
        )
        .unwrap();
}

fn accept_tcp(listener: &TcpListener) -> TcpStream {
    listener.set_nonblocking(true).expect("nonblocking");
    let deadline = Instant::now() + Duration::from_secs(20);
    let tcp = loop {
        match listener.accept() {
            Ok((tcp, _)) => break tcp,
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "the daemon never (re)connected");
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("accept: {error}"),
        }
    };
    tcp.set_nonblocking(false).expect("blocking");
    tcp
}

fn accept(listener: &TcpListener) -> Wire {
    let tcp = accept_tcp(listener);
    tcp.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    tungstenite::accept_hdr(tcp, super::tests::RelayHandshake).expect("handshake")
}

fn send(wire: &mut Wire, mut value: serde_json::Value) {
    if value["type"] == "operation.dispatch" && value.get("digestScheme").is_none() {
        if value["kind"]
            .as_str()
            .is_some_and(|kind| sandbox_protocol::KEY_FREE_CLEANUP_KINDS.contains(&kind))
        {
            value["digestScheme"] = json!("sha256-env-free-v1");
        } else {
            value["digestScheme"] = json!("hmac-sha256-v1");
            value["digestKeyId"] = json!("d".repeat(32));
        }
    }
    let epoch = if value["type"] == "hello.ok" {
        value["connectionEpoch"].as_u64()
    } else {
        None
    };
    wire.send(Message::Text(value.to_string().into()))
        .expect("send");
    if let Some(epoch) = epoch {
        let address = wire.get_ref().local_addr().unwrap();
        let install = json!({"type":"journal.key.install", "connectionEpoch":epoch, "keyVersion":1, "keyId":"d".repeat(32), "keyHex":"ab".repeat(32), "server":format!("ws://{address}/ws/sandbox-host"), "hostOwnerId":"owner-1", "hostId":"host"});
        wire.send(Message::Text(install.to_string().into()))
            .expect("install fixture key");
    }
}

/// Reads `hello` and answers `hello.ok` for `epoch`.
fn register(wire: &mut Wire, epoch: u64) {
    register_judged(wire, epoch);
}

/// Answers hello with the complete current protocol capabilities.
fn register_judged(wire: &mut Wire, epoch: u64) {
    loop {
        if let Message::Text(text) = wire.read().expect("hello")
            && matches!(
                parse_daemon_control(&text).expect("control"),
                DaemonControlMessage::Hello { .. }
            )
        {
            break;
        }
    }
    let mut ok: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../crates/sandbox-protocol/fixtures/control_hello_ok_server.json"
    ))
    .unwrap();
    ok["connectionEpoch"] = json!(epoch);
    send(wire, ok);
}

#[derive(Default, Debug)]
struct Reconciled {
    /// `(operation id, phase, stdin next)` in arrival order.
    adopted: Vec<(String, sandbox_protocol::AdoptPhase, Option<u64>)>,
    /// Receipts seen, with their state.
    receipts: Vec<(String, OperationState)>,
    /// Dispatch-audit verdicts received.
    audit: Vec<sandbox_protocol::DispatchAuditVerdict>,
    /// `host.egress-state` frames: `(adoption frames seen before it, epoch)`.
    egress: Vec<(usize, u32)>,
}

/// The server side of reconciliation that also answers adoption. Asserts
/// every adoption precedes the census. Ends at the initial policy report.
fn reconcile(wire: &mut Wire, answer: impl FnMut(&str) -> bool) -> Reconciled {
    reconcile_auditing(wire, answer, |_| serde_json::Value::Array(Vec::new()))
}

/// [`reconcile`], also answering dispatch-audit requests with `audit(page)`.
fn reconcile_auditing(
    wire: &mut Wire,
    mut answer: impl FnMut(&str) -> bool,
    mut audit: impl FnMut(u64) -> serde_json::Value,
) -> Reconciled {
    let mut seen = Reconciled::default();
    let mut census = false;
    let mut complete = false;
    loop {
        let Message::Text(text) = wire.read().expect("reconciliation frame") else {
            continue;
        };
        match parse_daemon_control(&text).expect("control") {
            DaemonControlMessage::OperationAdopt {
                operation_id,
                generation,
                attempt,
                phase,
                stdin_next_sequence,
                ..
            } => {
                assert!(!census, "adoption must precede the census");
                let adopted = answer(&operation_id);
                send(
                    wire,
                    json!({"type":"operation.adopt.result","operationId":operation_id,
                        "generation":generation,"attempt":attempt,"adopted":adopted}),
                );
                seen.adopted
                    .push((operation_id, phase, stdin_next_sequence));
            }
            DaemonControlMessage::OperationReceipt {
                operation_id,
                state,
                ..
            } => {
                send(
                    wire,
                    json!({"type":"receipt.ack","operationId":operation_id}),
                );
                seen.receipts.push((operation_id, state));
            }
            DaemonControlMessage::DispatchAuditRequest { page } => {
                assert!(!census, "the audit precedes the census");
                let entries = audit(page);
                send(
                    wire,
                    json!({"type":"dispatch.audit.page","page":page,"complete":true,"entries":entries}),
                );
            }
            DaemonControlMessage::DispatchAuditResult { entries, .. } => {
                seen.audit.extend(entries);
            }
            DaemonControlMessage::SandboxInventory { page, entries, .. } => {
                census = true;
                send(
                    wire,
                    json!({"type":"inventory.ack","page":page,"entryResults": entries.iter().map(|entry| json!({"sandboxId":entry.sandbox_id,"outcome":"converged"})).collect::<Vec<_>>()}),
                );
            }
            DaemonControlMessage::HostEgressState(state) => {
                seen.egress
                    .push((seen.adopted.len(), state.connection_epoch));
            }
            DaemonControlMessage::ReconcileComplete { .. } => complete = true,
            DaemonControlMessage::HostTerminalPolicy(_) if complete => return seen,
            DaemonControlMessage::Heartbeat { id, .. } => pong(wire, &id),
            _ => {}
        }
    }
}

fn pong(wire: &mut Wire, id: &str) {
    send(
        wire,
        json!({"type":"heartbeat.pong","id":id,"receivedAt":"2026-01-01T00:00:00Z"}),
    );
}

fn command(id: &str) -> serde_json::Value {
    json!({"sandboxOwnerId":"owner", "type":"operation.dispatch", "operationId":id,
        "sandboxId":"sbx", "kind":"command.run", "resultVersion":1, "processId":format!("proc-{id}"),
        "incusFingerprint":sandbox_runtime::CreateSandboxRequest::for_test("sbx", "key").template_digest,
        "generation":1, "attempt":1, "idempotencyKey":id, "bodyHash":"a".repeat(64), "argv":["true"]})
}

/// Reads until the predicate accepts a control frame (answering heartbeats).
fn until(
    wire: &mut Wire,
    mut stop: impl FnMut(&DaemonControlMessage) -> bool,
) -> DaemonControlMessage {
    loop {
        let Message::Text(text) = wire.read().expect("frame") else {
            continue;
        };
        let message = parse_daemon_control(&text).expect("control");
        if let DaemonControlMessage::Heartbeat { id, .. } = &message {
            pong(wire, id);
        }
        if stop(&message) {
            return message;
        }
    }
}

fn result_of(message: &DaemonControlMessage, id: &str) -> Option<OperationState> {
    match message {
        DaemonControlMessage::OperationResult {
            operation_id,
            state,
            ..
        } if operation_id == id => Some(*state),
        _ => None,
    }
}

fn accepted(message: &DaemonControlMessage, id: &str) -> bool {
    matches!(message, DaemonControlMessage::OperationProgress { operation_id, .. } if operation_id == id)
}

/// Close the TCP connection without a WebSocket close while the daemon's
/// bytes are still unread: Linux answers with a reset.
fn reset(wire: Wire) {
    thread::sleep(Duration::from_millis(150));
    drop(wire);
}

/// End a test's daemon: an operator shutdown never waits for leases.
fn finish(daemon: thread::JoinHandle<Result<()>>, shutdown: ShutdownSignal) {
    shutdown.request();
    daemon.join().expect("join").expect("connect");
}

fn spawn_daemon(
    options: ConnectOptions,
    fake: sandbox_runtime::FakeRuntime,
    timing: Option<(Duration, Duration)>,
) -> thread::JoinHandle<Result<()>> {
    thread::spawn(move || {
        if let Some(timing) = timing {
            RELAY_TIMING_OVERRIDE.with(|cell| cell.set(Some(timing)));
        }
        let result = run_connect_with(&options, |_| Ok((Box::new(fake), None)));
        if let Err(error) = &result {
            eprintln!("daemon ended: {error:#}");
        }
        result
    })
}

/// Test 1 + 6: a command in Effect survives a transport reset. Exactly one
/// adoption frame goes out before the census, its result arrives on the new
/// epoch, nothing is UNKNOWN. A staged upload still receiving chunks is not
/// carried: reconciliation settles it as an interrupted, unissued upload.
#[test]
fn carried_command_survives_a_reset_and_is_adopted_before_the_census() {
    let dir = tempfile::tempdir().expect("dir");
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let fake = sandbox_runtime::FakeRuntime::with_command_delay(Duration::from_millis(1500));
    seed(&listener, dir.path(), &fake);
    let options = options(&listener, dir.path(), Duration::from_secs(5));
    let shutdown = options.shutdown.clone();
    let daemon = spawn_daemon(options, fake.clone(), None);

    let mut wire = accept(&listener);
    register(&mut wire, 1);
    crate::sandbox_relay::test_support::ack_registration(&mut wire);
    send(&mut wire, command("cmd"));
    until(&mut wire, |m| accepted(m, "cmd"));
    send(
        &mut wire,
        json!({"sandboxOwnerId":"owner", "type":"operation.dispatch", "operationId":"put",
            "sandboxId":"sbx", "kind":"file.put", "path":"/home/x", "fileSize":3,
            "fileSha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "incusFingerprint":sandbox_runtime::CreateSandboxRequest::for_test("sbx", "key").template_digest,
            "generation":1, "attempt":1, "idempotencyKey":"put", "bodyHash":"a".repeat(64)}),
    );
    until(&mut wire, |m| accepted(m, "put"));
    reset(wire);

    let mut wire = accept(&listener);
    register(&mut wire, 2);
    let seen = reconcile(&mut wire, |_| true);
    assert_eq!(seen.adopted.len(), 1, "{seen:?}");
    let (id, phase, stdin) = &seen.adopted[0];
    assert_eq!(id, "cmd");
    assert_eq!(*phase, sandbox_protocol::AdoptPhase::Effect);
    // A command with open stdin is carried (B1), reporting its next sequence.
    #[cfg(target_os = "linux")]
    assert_eq!(*stdin, Some(0));
    #[cfg(not(target_os = "linux"))]
    let _ = stdin;
    assert!(
        seen.receipts
            .iter()
            .any(|(id, state)| id == "put" && *state == OperationState::Failed),
        "an interrupted upload is settled, never adopted: {seen:?}"
    );
    assert!(!seen.receipts.iter().any(|(id, _)| id == "cmd"));
    let done = until(&mut wire, |m| result_of(m, "cmd").is_some());
    assert_eq!(result_of(&done, "cmd"), Some(OperationState::Succeeded));
    finish(daemon, shutdown);
    drop(wire);
}

/// Two commands on a one-slot host: `cmd1` runs (Effect) and finishes while
/// the relay is down; `cmd2` was queued (Intent) and gets the free slot while
/// detached. Returns the reconnected wire after the server's adoption answers.
fn queued_behind_a_drop(
    answer: impl FnMut(&str) -> bool,
    grace: Option<Duration>,
    command_delay: Duration,
    reconnect_after: Duration,
) -> (
    tempfile::TempDir,
    Wire,
    Reconciled,
    thread::JoinHandle<Result<()>>,
    ShutdownSignal,
) {
    let dir = tempfile::tempdir().expect("dir");
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let fake = sandbox_runtime::FakeRuntime::with_command_delay(command_delay);
    seed(&listener, dir.path(), &fake);
    let mut options = options(&listener, dir.path(), Duration::from_secs(5));
    options.max_concurrent_commands = 1;
    let shutdown = options.shutdown.clone();
    let daemon = spawn_daemon(
        options,
        fake,
        grace.map(|grace| (grace, Duration::from_secs(30))),
    );
    let mut wire = accept(&listener);
    register(&mut wire, 1);
    crate::sandbox_relay::test_support::ack_registration(&mut wire);
    send(&mut wire, command("cmd1"));
    until(&mut wire, |m| accepted(m, "cmd1"));
    send(&mut wire, command("cmd2"));
    until(&mut wire, |m| accepted(m, "cmd2"));
    reset(wire);
    thread::sleep(reconnect_after);
    let mut wire = accept(&listener);
    register(&mut wire, 2);
    let seen = reconcile(&mut wire, answer);
    (dir, wire, seen, daemon, shutdown)
}

/// Test 2 (P10): a queued (Intent) command never starts while detached,
/// even with a free slot, and runs after adoption; the finished Effect
/// command's output still drains through adoption.
#[test]
fn queued_intent_work_waits_while_detached_and_runs_after_adoption() {
    let (_dir, mut wire, seen, daemon, shutdown) = queued_behind_a_drop(
        |_| true,
        None,
        Duration::from_millis(1200),
        Duration::from_millis(2500),
    );
    let phases: Vec<_> = seen
        .adopted
        .iter()
        .map(|(id, phase, _)| (id.as_str(), *phase))
        .collect();
    assert_eq!(
        phases,
        [
            ("cmd1", sandbox_protocol::AdoptPhase::Effect),
            ("cmd2", sandbox_protocol::AdoptPhase::Intent)
        ],
        "{seen:?}"
    );
    let mut pending = vec!["cmd1", "cmd2"];
    while !pending.is_empty() {
        let message = until(&mut wire, |m| {
            pending.iter().any(|id| result_of(m, id).is_some())
        });
        let DaemonControlMessage::OperationResult {
            operation_id,
            state,
            ..
        } = message
        else {
            unreachable!()
        };
        assert_eq!(state, OperationState::Succeeded, "{operation_id}");
        pending.retain(|id| *id != operation_id);
    }
    finish(daemon, shutdown);
    drop(wire);
}

/// Test 3 (P9): a refused adoption is revoked at once, and its definite
/// Result is settled by an exact receipt in the SAME session.
#[test]
fn refused_adoption_is_revoked_and_settled_by_a_receipt_in_the_same_session() {
    let (_dir, mut wire, seen, daemon, shutdown) = queued_behind_a_drop(
        |id| id != "cmd2",
        None,
        Duration::from_millis(1200),
        Duration::from_millis(2500),
    );
    assert_eq!(seen.adopted.len(), 2, "{seen:?}");
    let settled = seen
        .receipts
        .iter()
        .find(|(id, _)| id == "cmd2")
        .map(|(_, state)| *state)
        .unwrap_or_else(|| {
            match until(&mut wire, |m| {
                matches!(m, DaemonControlMessage::OperationReceipt { operation_id, .. } if operation_id == "cmd2")
                    || result_of(m, "cmd2").is_some()
            }) {
                DaemonControlMessage::OperationReceipt { state, .. } => state,
                other => panic!("a refused adoption must not publish a result: {other:?}"),
            }
        });
    assert!(
        matches!(settled, OperationState::Failed | OperationState::Cancelled),
        "never issued: {settled:?}"
    );
    finish(daemon, shutdown);
    drop(wire);
}

/// Test 5: `protocol.error` is a server verdict: carried work is revoked at
/// once, no adoption frame follows, and the reconnect reports the receipt.
#[test]
fn protocol_error_revokes_in_flight_work_without_adoption() {
    let dir = tempfile::tempdir().expect("dir");
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let fake = sandbox_runtime::FakeRuntime::with_command_delay(Duration::from_secs(20));
    seed(&listener, dir.path(), &fake);
    let options = options(&listener, dir.path(), Duration::from_secs(5));
    let shutdown = options.shutdown.clone();
    let daemon = spawn_daemon(options, fake, None);
    let mut wire = accept(&listener);
    register(&mut wire, 1);
    crate::sandbox_relay::test_support::ack_registration(&mut wire);
    send(&mut wire, command("cmd"));
    until(&mut wire, |m| accepted(m, "cmd"));
    let started = Instant::now();
    send(
        &mut wire,
        json!({"type":"protocol.error","failure":"protocol_error","message":"Host connection replaced"}),
    );
    let mut wire = accept(&listener);
    register(&mut wire, 2);
    let seen = reconcile(&mut wire, |_| true);
    assert!(seen.adopted.is_empty(), "{seen:?}");
    assert!(
        seen.receipts
            .iter()
            .any(|(id, state)| id == "cmd" && *state != OperationState::Succeeded),
        "{seen:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(15));
    finish(daemon, shutdown);
    drop(wire);
}

/// P0-1: a server close with `code` (None = no code) while a command runs.
/// The daemon never exits: it reconnects, the command is adopted on the new
/// epoch and succeeds. Returns how long the reconnect took.
fn server_close_keeps_carried_work(code: Option<u16>, reason: &str) -> Duration {
    let dir = tempfile::tempdir().expect("dir");
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let fake = sandbox_runtime::FakeRuntime::with_command_delay(Duration::from_millis(1500));
    seed(&listener, dir.path(), &fake);
    let options = options(&listener, dir.path(), Duration::from_secs(5));
    let shutdown = options.shutdown.clone();
    let daemon = spawn_daemon(options, fake, None);
    let mut wire = accept(&listener);
    register(&mut wire, 1);
    crate::sandbox_relay::test_support::ack_registration(&mut wire);
    send(&mut wire, command("cmd"));
    until(&mut wire, |m| accepted(m, "cmd"));
    let closed = Instant::now();
    wire.close(code.map(|code| tungstenite::protocol::CloseFrame {
        code: tungstenite::protocol::frame::coding::CloseCode::from(code),
        reason: reason.to_owned().into(),
    }))
    .expect("close");
    let mut wire = accept(&listener);
    let reconnected = closed.elapsed();
    assert!(
        !daemon.is_finished(),
        "{code:?}: a server close never ends the daemon"
    );
    register(&mut wire, 2);
    let seen = reconcile(&mut wire, |_| true);
    assert_eq!(seen.adopted.len(), 1, "{code:?}: {seen:?}");
    assert_eq!(seen.adopted[0].0, "cmd");
    assert!(!seen.receipts.iter().any(|(id, _)| id == "cmd"), "{seen:?}");
    let done = until(&mut wire, |m| result_of(m, "cmd").is_some());
    assert_eq!(
        result_of(&done, "cmd"),
        Some(OperationState::Succeeded),
        "{code:?}"
    );
    finish(daemon, shutdown);
    drop(wire);
    reconnected
}

#[test]
fn p0_1_close_1000_reconnects_and_adopts() {
    let took = server_close_keeps_carried_work(Some(1000), "bye");
    assert!(took < Duration::from_secs(5), "{took:?}");
}

#[test]
fn p0_1_close_without_code_reconnects_and_adopts() {
    server_close_keeps_carried_work(None, "");
}

#[test]
fn p0_1_close_1001_reconnects_and_adopts() {
    server_close_keeps_carried_work(Some(1001), "session_removed");
}

/// WP2: close 1002 is a server verdict on the session: the daemon still
/// reconnects (P0-1), but carried work is revoked, never adopted.
#[test]
fn wp2_close_1002_reconnects_but_revokes_carried_work() {
    let dir = tempfile::tempdir().expect("dir");
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let fake = sandbox_runtime::FakeRuntime::with_command_delay(Duration::from_secs(20));
    seed(&listener, dir.path(), &fake);
    let options = options(&listener, dir.path(), Duration::from_secs(5));
    let shutdown = options.shutdown.clone();
    let daemon = spawn_daemon(options, fake, None);
    let mut wire = accept(&listener);
    register(&mut wire, 1);
    crate::sandbox_relay::test_support::ack_registration(&mut wire);
    send(&mut wire, command("cmd"));
    until(&mut wire, |m| accepted(m, "cmd"));
    wire.close(Some(tungstenite::protocol::CloseFrame {
        code: tungstenite::protocol::frame::coding::CloseCode::from(1002),
        reason: "protocol_error".into(),
    }))
    .expect("close");
    let mut wire = accept(&listener);
    assert!(!daemon.is_finished(), "1002 never ends the daemon");
    register(&mut wire, 2);
    let seen = reconcile(&mut wire, |_| true);
    assert!(seen.adopted.is_empty(), "{seen:?}");
    assert!(
        seen.receipts
            .iter()
            .any(|(id, state)| id == "cmd" && *state != OperationState::Succeeded),
        "{seen:?}"
    );
    finish(daemon, shutdown);
    drop(wire);
}

#[test]
fn a_refused_hello_is_a_terminal_verdict() {
    let error = protocol_error_end(
        false,
        SandboxErrorCode::ProtocolError,
        "Invalid sandbox relay control frame.",
    );
    assert!(error.downcast_ref::<ServerVerdict>().is_some());
    assert!(error.downcast_ref::<TerminalHelloRefusal>().is_some());
    assert!(error.downcast_ref::<RetryableSession>().is_none());
    assert_eq!(session_end(&error, false, false), SessionEnd::Revoke);
}

/// WP2: a failed receipt write latches the journal-wide IO flag. The next
/// session end revokes carried work (even a plain transport reset, which
/// otherwise detaches), and the host reports itself unschedulable.
#[test]
fn wp2_a_receipt_write_failure_revokes_carried_work_on_the_next_drop() {
    let dir = tempfile::tempdir().expect("dir");
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let fake = sandbox_runtime::FakeRuntime::with_command_delay(Duration::from_secs(20));
    seed(&listener, dir.path(), &fake);
    let options = options(&listener, dir.path(), Duration::from_secs(5));
    let shutdown = options.shutdown.clone();
    let daemon = spawn_daemon(options, fake, None);
    let mut wire = accept(&listener);
    register(&mut wire, 1);
    crate::sandbox_relay::test_support::ack_registration(&mut wire);
    send(&mut wire, command("cmd"));
    until(&mut wire, |m| accepted(m, "cmd"));
    // A directory where `cmd2`'s receipt goes: its Intent write (rename)
    // fails, as a broken or full disk would.
    std::fs::create_dir(dir.path().join("receipts").join("cmd2.json")).expect("blocker");
    send(&mut wire, command("cmd2"));
    // Whatever the daemon answers for cmd2, the next drop is a plain reset.
    thread::sleep(Duration::from_millis(500));
    reset(wire);
    let mut wire = accept(&listener);
    let hello = loop {
        if let Message::Text(text) = wire.read().expect("hello") {
            let value: serde_json::Value = serde_json::from_str(&text).unwrap();
            if value["type"] == "hello" {
                break value;
            }
        }
    };
    assert_eq!(
        hello["inventory"]["schedulable"],
        json!(false),
        "a latched host is not placed on: {hello}"
    );
    let mut ok: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../crates/sandbox-protocol/fixtures/control_hello_ok_server.json"
    ))
    .unwrap();
    ok["connectionEpoch"] = json!(2);
    send(&mut wire, ok);
    let seen = reconcile(&mut wire, |_| true);
    assert!(
        seen.adopted.is_empty(),
        "a latched journal never carries work across a drop: {seen:?}"
    );
    finish(daemon, shutdown);
    drop(wire);
}

#[test]
fn p0_1_close_1008_reconnects_and_adopts() {
    server_close_keeps_carried_work(Some(1008), "receive_queue_limit");
}

#[test]
fn p0_1_close_1011_reconnects_and_adopts() {
    server_close_keeps_carried_work(Some(1011), "internal_error");
}

#[test]
fn p0_1_close_1013_reconnects_after_a_longer_backoff_and_adopts() {
    let took = server_close_keeps_carried_work(Some(1013), "host_socket_limit");
    // Jitter keeps the busy floor within [2.5 s, 5 s].
    assert!(took >= Duration::from_millis(2400), "{took:?}");
}

#[test]
fn p0_1_unknown_close_code_reconnects_and_adopts() {
    server_close_keeps_carried_work(Some(4999), "whatever");
}

/// P0-1: an abnormal end (TCP reset, no close frame: 1006 at the peer).
#[test]
fn p0_1_abnormal_close_reconnects_and_adopts() {
    let dir = tempfile::tempdir().expect("dir");
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let fake = sandbox_runtime::FakeRuntime::with_command_delay(Duration::from_millis(1500));
    seed(&listener, dir.path(), &fake);
    let options = options(&listener, dir.path(), Duration::from_secs(5));
    let shutdown = options.shutdown.clone();
    let daemon = spawn_daemon(options, fake, None);
    let mut wire = accept(&listener);
    register(&mut wire, 1);
    crate::sandbox_relay::test_support::ack_registration(&mut wire);
    send(&mut wire, command("cmd"));
    until(&mut wire, |m| accepted(m, "cmd"));
    wire.get_mut()
        .shutdown(std::net::Shutdown::Both)
        .expect("shutdown");
    drop(wire);
    let mut wire = accept(&listener);
    register(&mut wire, 2);
    let seen = reconcile(&mut wire, |_| true);
    assert_eq!(seen.adopted.len(), 1, "{seen:?}");
    let done = until(&mut wire, |m| result_of(m, "cmd").is_some());
    assert_eq!(result_of(&done, "cmd"), Some(OperationState::Succeeded));
    finish(daemon, shutdown);
    drop(wire);
}

/// P0-1: the server's per-host socket limit refuses a reconnect with a
/// `rate_limited` protocol error, then 1013. That is no verdict on carried
/// work: the daemon keeps it detached, waits the longer busy backoff, and the
/// next reconnect adopts it.
#[test]
fn p0_1_socket_limit_refusal_keeps_carried_work_and_backs_off() {
    let dir = tempfile::tempdir().expect("dir");
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let fake = sandbox_runtime::FakeRuntime::with_command_delay(Duration::from_millis(1500));
    seed(&listener, dir.path(), &fake);
    let options = options(&listener, dir.path(), Duration::from_secs(5));
    let shutdown = options.shutdown.clone();
    let daemon = spawn_daemon(options, fake, None);
    let mut wire = accept(&listener);
    register(&mut wire, 1);
    crate::sandbox_relay::test_support::ack_registration(&mut wire);
    send(&mut wire, command("cmd"));
    until(&mut wire, |m| accepted(m, "cmd"));
    reset(wire);
    let mut refused = accept(&listener);
    send(
        &mut refused,
        json!({"type":"protocol.error","failure":"rate_limited","message":"Host connection limit reached"}),
    );
    // The daemon may already have dropped the socket on the refusal.
    let _ = refused.close(Some(tungstenite::protocol::CloseFrame {
        code: tungstenite::protocol::frame::coding::CloseCode::Again,
        reason: "host_socket_limit".into(),
    }));
    let refused_at = Instant::now();
    let mut wire = accept(&listener);
    let waited = refused_at.elapsed();
    assert!(waited >= Duration::from_millis(2400), "{waited:?}");
    register(&mut wire, 2);
    let seen = reconcile(&mut wire, |_| true);
    assert_eq!(seen.adopted.len(), 1, "{seen:?}");
    let done = until(&mut wire, |m| result_of(m, "cmd").is_some());
    assert_eq!(result_of(&done, "cmd"), Some(OperationState::Succeeded));
    finish(daemon, shutdown);
    drop(wire);
    drop(refused);
}

/// Test 5: close 4003 (credential revoked) ends the process and revokes
/// in-flight work immediately.
#[test]
fn credential_close_revokes_in_flight_work_and_exits() {
    let dir = tempfile::tempdir().expect("dir");
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let fake = sandbox_runtime::FakeRuntime::with_command_delay(Duration::from_secs(20));
    seed(&listener, dir.path(), &fake);
    let options = options(&listener, dir.path(), Duration::from_secs(5));
    let shutdown = options.shutdown.clone();
    let daemon = spawn_daemon(options, fake, None);
    let mut wire = accept(&listener);
    register(&mut wire, 1);
    crate::sandbox_relay::test_support::ack_registration(&mut wire);
    send(&mut wire, command("cmd"));
    until(&mut wire, |m| accepted(m, "cmd"));
    let started = Instant::now();
    wire.close(Some(tungstenite::protocol::CloseFrame {
        code: tungstenite::protocol::frame::coding::CloseCode::Library(4003),
        reason: "credential_inactive".into(),
    }))
    .expect("close");
    // Revoked at once: the 20 s command ends with a non-success outcome (a
    // definite Result, or UNKNOWN, which stays in phase Effect) while the
    // process still holds its journal for lease settlement.
    let state = loop {
        if let Some(receipt) = journal_receipt(dir.path(), "cmd")
            && ["unknown_outcome", "failed", "cancelled", "succeeded"]
                .contains(&receipt["state"].as_str().unwrap_or_default())
        {
            break receipt["state"].clone();
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "credential revocation did not stop the command"
        );
        thread::sleep(Duration::from_millis(20));
    };
    assert_ne!(state, json!("succeeded"));
    shutdown.request();
    let error = daemon
        .join()
        .expect("join")
        .expect_err("credential failure");
    assert_eq!(crate::exit::code_for(&error), ExitCode::CredentialInactive);
}

/// The journal's durable receipt for `id`, read without its lock.
fn journal_receipt(dir: &std::path::Path, id: &str) -> Option<serde_json::Value> {
    fn find(dir: &std::path::Path, name: &str) -> Option<std::path::PathBuf> {
        for entry in std::fs::read_dir(dir).ok()?.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(found) = find(&path, name) {
                    return Some(found);
                }
            } else if path.ends_with(name) && path.parent()?.ends_with("receipts") {
                return Some(path);
            }
        }
        None
    }
    let path = find(dir, &format!("{id}.json"))?;
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
    Some(value["receipt"].clone())
}

/// Test 5: a shutdown request while detached revokes at once (no adoption).
#[test]
fn shutdown_while_detached_revokes_and_exits() {
    let dir = tempfile::tempdir().expect("dir");
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let fake = sandbox_runtime::FakeRuntime::with_command_delay(Duration::from_secs(20));
    seed(&listener, dir.path(), &fake);
    let options = options(&listener, dir.path(), Duration::from_secs(5));
    let shutdown = options.shutdown.clone();
    let daemon = spawn_daemon(options, fake, None);
    let mut wire = accept(&listener);
    register(&mut wire, 1);
    crate::sandbox_relay::test_support::ack_registration(&mut wire);
    send(&mut wire, command("cmd"));
    until(&mut wire, |m| accepted(m, "cmd"));
    reset(wire);
    // The reconnect dials but never gets an upgrade: still detached.
    let _stalled = accept_tcp(&listener);
    let started = Instant::now();
    shutdown.request();
    daemon.join().expect("join").expect("clean shutdown");
    assert!(started.elapsed() < Duration::from_secs(15));
}

/// Test 4 (WP3): the carry window expires while an adoption request is
/// outstanding. The queued (never-started) command is revoked before its
/// turn and its definite never-issued Result still settles by receipt; the
/// running command is not touched by the window and is adopted.
#[test]
fn window_expiry_during_an_outstanding_adoption_still_settles_by_receipt() {
    let mut first = true;
    let (_dir, mut wire, seen, daemon, shutdown) = queued_behind_a_drop(
        move |_| {
            if std::mem::take(&mut first) {
                // Hold the first answer past the window.
                thread::sleep(Duration::from_millis(1500));
            }
            true
        },
        Some(Duration::from_millis(800)),
        Duration::from_secs(3),
        Duration::ZERO,
    );
    // The queued command may still get its (late) adoption frame, from the
    // snapshot taken before the window revoked it; either way it is revoked
    // and settles by receipt.
    let adopted: Vec<_> = seen.adopted.iter().map(|(id, ..)| id.as_str()).collect();
    assert_eq!(adopted.first(), Some(&"cmd1"), "{seen:?}");
    let mut cmd1 = None;
    let mut cmd2 = seen
        .receipts
        .iter()
        .find(|(id, _)| id == "cmd2")
        .map(|(_, state)| *state);
    while cmd1.is_none() || cmd2.is_none() {
        match until(&mut wire, |m| {
            result_of(m, "cmd1").is_some()
                || matches!(m, DaemonControlMessage::OperationReceipt { operation_id, .. }
                    if operation_id == "cmd2")
        }) {
            DaemonControlMessage::OperationReceipt { state, .. } => cmd2 = Some(state),
            message => cmd1 = result_of(&message, "cmd1"),
        }
    }
    assert_eq!(cmd1, Some(OperationState::Succeeded));
    assert_eq!(cmd2, Some(OperationState::Failed), "never issued");
    finish(daemon, shutdown);
    drop(wire);
}

/// Test 8 (minor 2): a half-open socket (nothing ever read, not even pongs)
/// hits the server-silence deadline; the work is carried and adopted.
#[test]
fn half_open_socket_hits_the_silence_deadline_and_work_is_adopted() {
    let dir = tempfile::tempdir().expect("dir");
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let fake = sandbox_runtime::FakeRuntime::with_command_delay(Duration::from_millis(2500));
    seed(&listener, dir.path(), &fake);
    let options = options(&listener, dir.path(), Duration::from_millis(50));
    let shutdown = options.shutdown.clone();
    let daemon = spawn_daemon(
        options,
        fake,
        Some((Duration::from_secs(60), Duration::from_millis(600))),
    );
    let mut wire = accept(&listener);
    register(&mut wire, 1);
    crate::sandbox_relay::test_support::ack_registration(&mut wire);
    send(&mut wire, command("cmd"));
    let started = Instant::now();
    // From here on the server neither reads nor writes: half-open.
    let mut wire2 = accept(&listener);
    let silent_for = started.elapsed();
    assert!(
        silent_for < Duration::from_secs(5),
        "silence deadline must end the session: {silent_for:?}"
    );
    drop(wire);
    register(&mut wire2, 2);
    let seen = reconcile(&mut wire2, |_| true);
    assert_eq!(seen.adopted.len(), 1, "{seen:?}");
    let done = until(&mut wire2, |m| result_of(m, "cmd").is_some());
    assert_eq!(result_of(&done, "cmd"), Some(OperationState::Succeeded));
    finish(daemon, shutdown);
    drop(wire2);
}

/// N2: a write blocked on a peer that never reads fails within the write
/// timeout, and the failure classifies as a lost transport.
#[test]
fn n2_blocked_send_on_a_half_open_socket_is_a_lost_transport() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let tcp = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (_peer, _) = listener.accept().unwrap();
    let mut socket = tungstenite::WebSocket::from_raw_socket(
        tungstenite::stream::MaybeTlsStream::Plain(tcp),
        tungstenite::protocol::Role::Client,
        None,
    );
    set_ws_timeouts(
        &mut socket,
        Duration::from_millis(100),
        Duration::from_millis(300),
    )
    .unwrap();
    let started = Instant::now();
    let chunk = vec![7u8; 1 << 20];
    let error = loop {
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "send never blocked"
        );
        if let Err(error) = socket.send(Message::Binary(chunk.clone().into())) {
            break error;
        }
    };
    assert!(transport_lost(&anyhow::Error::from(error)));
    // The production relay socket keeps the 30 s write bound.
    assert_eq!(RELAY_WRITE_TIMEOUT, Duration::from_secs(30));
}

/// WP2 class -> branch table: after hello.ok carried work is revoked only on
/// a server verdict (`protocol.error`, close 1002; 4003 ends the process) or
/// the journal IO latch. Transport losses, unknown closes, local protocol,
/// runtime and reconciliation failures all detach and reconnect.
#[test]
fn wp2_only_a_server_verdict_or_the_io_latch_revokes() {
    use super::super::reconcile::server_refusal;
    use tungstenite::error::ProtocolError;
    let refusal = r#"{"type":"protocol.error","failure":"protocol_error","message":"Host connection replaced."}"#;
    let cases: Vec<(&str, anyhow::Error, SessionEnd)> = vec![
        (
            "socket reset",
            anyhow::Error::from(tungstenite::Error::Io(std::io::Error::from(
                ErrorKind::ConnectionReset,
            ))),
            SessionEnd::Detach,
        ),
        (
            "write timeout",
            anyhow::Error::from(tungstenite::Error::Io(std::io::Error::from(
                ErrorKind::TimedOut,
            )))
            .context(RetryableSession),
            SessionEnd::Detach,
        ),
        (
            "closed",
            anyhow::Error::from(tungstenite::Error::ConnectionClosed),
            SessionEnd::Detach,
        ),
        (
            "reset without close",
            anyhow::Error::from(tungstenite::Error::Protocol(
                ProtocolError::ResetWithoutClosingHandshake,
            )),
            SessionEnd::Detach,
        ),
        (
            "server silence",
            anyhow::anyhow!("relay server silent for 30s").context(TransportLost),
            SessionEnd::Detach,
        ),
        (
            "ack timeout",
            anyhow::anyhow!("receipt acknowledgement timed out").context(TransportLost),
            SessionEnd::Detach,
        ),
        (
            "close 1000",
            close_during_read(Some(1000), None),
            SessionEnd::Detach,
        ),
        (
            "close none",
            close_during_read(None, None),
            SessionEnd::Detach,
        ),
        (
            "close 1001",
            close_during_read(Some(1001), None),
            SessionEnd::Detach,
        ),
        (
            "close 1008",
            close_during_read(Some(1008), Some("receive_queue_limit")),
            SessionEnd::Detach,
        ),
        (
            "close 1011",
            close_during_read(Some(1011), None),
            SessionEnd::Detach,
        ),
        (
            "close 1013",
            close_during_read(Some(1013), Some("host_socket_limit")),
            SessionEnd::Detach,
        ),
        (
            "close 4999",
            close_during_read(Some(4999), None),
            SessionEnd::Detach,
        ),
        // Local failures the daemon cannot tell from a network fault.
        (
            "local protocol violation",
            anyhow::anyhow!("dispatch before hello.ok"),
            SessionEnd::Detach,
        ),
        (
            "masked server frame",
            anyhow::Error::from(tungstenite::Error::Protocol(
                ProtocolError::MaskedFrameFromServer,
            )),
            SessionEnd::Detach,
        ),
        (
            "runtime error",
            anyhow::anyhow!("incus query failed").context(RetryableSession),
            SessionEnd::Detach,
        ),
        (
            "hello schema refused before hello.ok",
            protocol_error_end(
                false,
                SandboxErrorCode::ProtocolError,
                "Invalid sandbox relay control frame.",
            )
            .context(RetryableSession),
            SessionEnd::Revoke,
        ),
        (
            "socket limit before hello.ok",
            protocol_error_end(
                false,
                SandboxErrorCode::RateLimited,
                "Host connection limit reached",
            ),
            SessionEnd::Detach,
        ),
        (
            "unexpected reconciliation frame",
            anyhow::anyhow!("unexpected inventory response")
                .context(server_refusal(r#"{"type":"heartbeat.pong"}"#)),
            SessionEnd::Detach,
        ),
        // Server verdicts.
        (
            "close 1002",
            close_during_read(Some(1002), Some("protocol_error")),
            SessionEnd::Revoke,
        ),
        (
            "protocol.error in the dispatch loop",
            anyhow::anyhow!("relay protocol error: Host connection replaced")
                .context(ServerVerdict)
                .context(RetryableSession),
            SessionEnd::Revoke,
        ),
        (
            "unparsed frame after hello.ok",
            protocol_error_end(
                true,
                SandboxErrorCode::ProtocolError,
                "Invalid sandbox relay control frame.",
            )
            .context(RetryableSession),
            SessionEnd::Revoke,
        ),
        (
            "other hello refusal before hello.ok",
            protocol_error_end(
                false,
                SandboxErrorCode::ProtocolError,
                "Host identity does not match the websocket credential.",
            )
            .context(RetryableSession),
            SessionEnd::Revoke,
        ),
        (
            "other failure before hello.ok",
            protocol_error_end(
                false,
                SandboxErrorCode::Internal,
                "Invalid sandbox relay control frame.",
            )
            .context(RetryableSession),
            SessionEnd::Revoke,
        ),
        (
            "protocol.error during reconciliation",
            super::super::reconcile::verdict_for_test(
                refusal,
                anyhow::anyhow!("unexpected inventory response").context(server_refusal(refusal)),
            ),
            SessionEnd::Revoke,
        ),
    ];
    for (name, error, expected) in &cases {
        assert_eq!(
            session_end(error, false, false),
            *expected,
            "{name}: {error:#}"
        );
        // The journal IO latch revokes whatever ended the session.
        assert_eq!(
            session_end(error, false, true),
            SessionEnd::Revoke,
            "{name} with the latch"
        );
        // Before hello nothing is a verdict on carried work.
        assert_eq!(
            session_end(error, true, false),
            SessionEnd::Detach,
            "{name} before hello"
        );
    }
    // 4003 never reaches the reconnect branch: it is not retried.
    assert!(
        close_during_read(Some(4003), None)
            .downcast_ref::<RetryableSession>()
            .is_none()
    );
}

/// WP2 backoff timing, over a fake clock: while carrying, at most 1 s for
/// the first 60 s of the outage, then a separate counter from 1 s to the
/// 30 s cap; without carried work the session counter (250 ms doubling).
#[test]
fn wp2_carry_backoff_is_prompt_then_exponential_and_capped() {
    let mut backoff = ReconnectBackoff::default();
    let mut clock = Duration::ZERO;
    let mut waits = Vec::new();
    while clock < Duration::from_secs(10 * 60) {
        let wait = backoff.next(true, Some(clock));
        if clock < Duration::from_secs(60) {
            assert!(wait <= Duration::from_secs(1), "{wait:?} at {clock:?}");
        }
        assert!(wait <= Duration::from_secs(30), "{wait:?}");
        waits.push((clock, wait));
        clock += wait;
    }
    let after: Vec<_> = waits
        .iter()
        .filter(|(at, _)| *at >= Duration::from_secs(60))
        .map(|(_, wait)| wait.as_secs())
        .collect();
    assert_eq!(&after[..6], &[1, 2, 4, 8, 16, 30]);
    assert!(after[6..].iter().all(|&wait| wait == 30));
    // Bounded pressure: ~60 prompt attempts, then a few per minute.
    assert!(waits.len() < 90, "{} attempts in 10 min", waits.len());
    // A new outage starts prompt again; so does an outage without carries.
    assert_eq!(
        backoff.next(true, Some(Duration::ZERO)),
        Duration::from_secs(1)
    );
    assert_eq!(
        backoff.next(true, Some(Duration::from_secs(61))),
        Duration::from_secs(1)
    );
    let mut idle = ReconnectBackoff::default();
    let idle_waits: Vec<_> = (0..9).map(|_| idle.next(false, None).as_millis()).collect();
    assert_eq!(
        idle_waits,
        [250, 500, 1000, 2000, 4000, 8000, 16000, 30000, 30000]
    );
    idle.stable_session();
    assert_eq!(idle.next(false, None), Duration::from_millis(250));
}

/// Review #4: only network/runtime-observation failures before hello keep
/// carried work detached. A storage-ledger persistence failure during
/// preparation is a journal failure: it is never classified as pre-hello
/// transport loss, so the reconnect loop revokes.
#[test]
fn prepare_classifies_storage_ledger_failure_as_revoke_and_dial_failure_as_transport() {
    use std::os::unix::fs::PermissionsExt;
    let run = |read_only: bool| -> (bool, String) {
        let dir = tempfile::tempdir().expect("dir");
        // Nothing listens here: dialing fails (a network failure).
        let closed = TcpListener::bind("127.0.0.1:0").expect("listen");
        let address = closed.local_addr().unwrap();
        drop(closed);
        let mut options = options(
            &TcpListener::bind("127.0.0.1:0").unwrap(),
            dir.path(),
            Duration::from_secs(5),
        );
        options.server_url = format!("ws://{address}");
        let binding = TransportBindingV11 {
            server: format!("ws://{address}/ws/sandbox-host"),
            host_owner_id: "owner-1".into(),
            host_id: "host".into(),
        };
        let journal = Arc::new(HostJournal::open(dir.path(), &binding).unwrap());
        let runtime: Arc<dyn SandboxRuntime> = Arc::new(sandbox_runtime::FakeRuntime::new());
        let authority = HostAuthority::with_journal(journal.clone());
        let expiry = super::super::expiry::ExpiryService::start(
            runtime.clone(),
            journal.clone(),
            authority.clone(),
        );
        let relay = RelaySupervisor::start(
            runtime.clone(),
            journal.clone(),
            authority.clone(),
            #[cfg(target_os = "linux")]
            None,
        );
        if read_only {
            // A retained root whose VM is absent: reconstruction must persist
            // its release to the storage ledger, and that write fails.
            let pool = crate::storage_capacity::connect_pools(
                runtime.as_ref(),
                &crate::config::Config::default(),
                &journal,
            )
            .unwrap()
            .remove(0);
            let mut d: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner",
                "operationId":"sbx","sandboxId":"sbx","kind":"sandbox.create","generation":1,
                "attempt":1,"idempotencyKey":"sbx","bodyHash":"a".repeat(64)}))
            .unwrap();
            d.allocation = Some(sandbox_protocol::capacity_v11::PinnedAllocationV11 {
                cpu_count: 1,
                memory_mi_b: 512,
                disk_gi_b: 32,
                storage_pool_name: pool.name.clone(),
                storage_marker: pool.marker.clone(),
                charged_memory_mi_b: sandbox_protocol::vm_live_memory_charge_mi_b(512).unwrap(),
                charged_vcpu: 1,
                root_charge_gi_b: sandbox_protocol::vm_root_charge_gi_b(32).unwrap(),
            });
            journal
                .record_intent(&intent_from_dispatch(&journal, &binding, &d))
                .unwrap();
            assert!(journal.retained_roots()["sbx"].live);
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        }
        let request = crate::auth::relay_url(&options.server_url)
            .unwrap()
            .as_str()
            .into_client_request()
            .unwrap();
        let mut pre_hello = false;
        let error = match relay_session_prepare(
            None,
            &options,
            request,
            &runtime,
            &journal,
            &authority,
            &expiry,
            &relay,
            true,
            &crate::config::Config::default(),
            &mut HostObservations::default(),
            &mut pre_hello,
            &Default::default(),
        ) {
            Ok(_) => panic!("preparation must fail"),
            Err(error) => error,
        };
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        drop(relay);
        drop(expiry);
        (pre_hello, format!("{error:#}"))
    };
    let (pre_hello, error) = run(true);
    assert!(
        !pre_hello,
        "a journal/storage write failure must revoke: {error}"
    );
    assert!(!error.contains("websocket connect failed"), "{error}");
    let (pre_hello, error) = run(false);
    assert!(pre_hello, "a dial failure is a transport loss: {error}");
    assert!(error.contains("websocket connect failed"), "{error}");
}

/// Review #1 + live finding B-2: received work is owned before the first
/// fallible send. When the acceptance send fails, the attempt is already a
/// queued job: the transport loss carries it (to be adopted), never strands
/// an ownerless entry and never settles it as cancelled.
#[test]
fn a_failed_acceptance_send_still_carries_the_received_work() {
    let dir = tempfile::tempdir().expect("dir");
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let fake = sandbox_runtime::FakeRuntime::new();
    seed(&listener, dir.path(), &fake);
    let address = listener.local_addr().unwrap();
    let binding = TransportBindingV11 {
        server: format!("ws://{address}/ws/sandbox-host"),
        host_owner_id: "owner-1".into(),
        host_id: "host".into(),
    };
    let journal =
        Arc::new(crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap());
    let mut authority = HostAuthority::with_journal(journal.clone());
    authority.attach(1);
    let relay = RelaySupervisor::start(
        Arc::new(fake),
        journal.clone(),
        authority.clone(),
        #[cfg(target_os = "linux")]
        None,
    );
    let tcp = TcpStream::connect(address).unwrap();
    let _peer = listener.accept().unwrap();
    let mut socket = tungstenite::WebSocket::from_raw_socket(
        tungstenite::stream::MaybeTlsStream::Plain(tcp),
        tungstenite::protocol::Role::Client,
        None,
    );
    // Every later send fails: the acceptance frame cannot go out.
    socket.close(None).unwrap();
    let mut admission = crate::sandbox_relay::test_support::admission(
        4,
        crate::sandbox_relay::live_admission::test_capacity(),
    );
    let mut frame = command("cmd");
    frame.as_object_mut().unwrap().remove("type");
    let dispatch: OperationDispatch = serde_json::from_value(frame).unwrap();
    let dispatch = crate::sandbox_relay::test_support::current_fixture_dispatch(&dispatch);
    crate::sandbox_relay::test_support::install_fixture_key(&journal, &binding);
    let error = handle_dispatch(
        &mut socket,
        WireCodes::CURRENT,
        &mut authority,
        &mut admission,
        (&journal, &binding),
        &relay,
        &None,
        &mut HashMap::new(),
        &dispatch,
    )
    .expect_err("the acceptance send fails");
    assert!(transport_lost(&error), "{error:#}");
    authority.detach(Instant::now());
    // Ownership was taken before the send: queued (Intent, at the gate) or
    // already running when the drop came, it is carried either way.
    assert!(authority.owned("cmd", 1, 1), "received work has an owner");
    assert_eq!(authority.carried().len(), 1);
    let receipt = journal.lookup("cmd").unwrap();
    assert_ne!(receipt.error_code, Some(SandboxErrorCode::Cancelled.into()));
}

/// Round 2 #1: a command completes immediately before the drop while its
/// output is still unacknowledged. It is adopted (not settled by a bare
/// receipt), and after reconnect its output is delivered in full with the
/// result.
#[test]
fn completion_just_before_a_drop_still_delivers_all_output_after_reconnect() {
    let dir = tempfile::tempdir().expect("dir");
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let fake = sandbox_runtime::FakeRuntime::new();
    seed(&listener, dir.path(), &fake);
    let options = options(&listener, dir.path(), Duration::from_secs(5));
    let shutdown = options.shutdown.clone();
    let daemon = spawn_daemon(options, fake, None);
    let mut wire = accept(&listener);
    register(&mut wire, 1);
    crate::sandbox_relay::test_support::ack_registration(&mut wire);
    send(&mut wire, command("cmd"));
    // Output is published but never acknowledged: the window stays open and
    // the completion waits behind it. Drop at the first output frame.
    loop {
        if let Message::Binary(_) = wire.read().expect("frame") {
            break;
        }
    }
    drop(wire);
    let mut wire = accept(&listener);
    register(&mut wire, 2);
    let seen = reconcile(&mut wire, |_| true);
    assert_eq!(
        seen.adopted
            .iter()
            .map(|(id, phase, _)| (id.as_str(), *phase))
            .collect::<Vec<_>>(),
        [("cmd", sandbox_protocol::AdoptPhase::Effect)],
        "{seen:?}"
    );
    assert!(!seen.receipts.iter().any(|(id, _)| id == "cmd"), "{seen:?}");
    let mut bytes = std::collections::BTreeMap::new();
    let result = loop {
        match wire.read().expect("frame") {
            Message::Binary(data) => {
                let (metadata, body) = sandbox_protocol::parse_binary_frame(&data).unwrap();
                if metadata.operation_id == "cmd" {
                    bytes.insert(metadata.offset.unwrap_or(0), body.len() as u64);
                    send(
                        &mut wire,
                        json!({"type":"command.output.ack","operationId":"cmd","generation":1,
                            "attempt":1,"sequence":metadata.sequence,
                            "offset":metadata.offset.unwrap_or(0) + body.len() as u64}),
                    );
                }
            }
            Message::Text(text) => {
                let message = parse_daemon_control(&text).unwrap();
                if let DaemonControlMessage::Heartbeat { id, .. } = &message {
                    pong(&mut wire, id);
                }
                if let DaemonControlMessage::OperationResult {
                    operation_id,
                    state,
                    result,
                    ..
                } = message
                    && operation_id == "cmd"
                {
                    break (state, result);
                }
            }
            _ => {}
        }
    };
    assert_eq!(result.0, OperationState::Succeeded);
    let total = result
        .1
        .as_ref()
        .and_then(|r| r["outputBytes"].as_u64())
        .unwrap();
    assert!(total > 0);
    let mut covered = 0;
    for (offset, len) in &bytes {
        assert!(*offset <= covered, "no gap at {offset}");
        covered = covered.max(offset + len);
    }
    assert_eq!(covered, total, "every output byte reached the new session");
    finish(daemon, shutdown);
    drop(wire);
}

fn finished(
    id: &str,
    state: OperationState,
    owner: Option<super::super::authority::OwnershipToken>,
) -> FinishedOp {
    FinishedOp {
        operation_id: id.into(),
        sandbox_id: "sbx".into(),
        generation: 1,
        attempt: 1,
        state,
        payload: None,
        error: None,
        download: None,
        interim: false,
        owner,
        readiness_detail: None,
    }
}

fn socket_pair() -> (
    tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<TcpStream>>,
    Wire,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (peer, _) = listener.accept().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    (
        tungstenite::WebSocket::from_raw_socket(
            tungstenite::stream::MaybeTlsStream::Plain(tcp),
            tungstenite::protocol::Role::Client,
            None,
        ),
        tungstenite::WebSocket::from_raw_socket(peer, tungstenite::protocol::Role::Server, None),
    )
}

fn relay_parts() -> (
    tempfile::TempDir,
    Arc<HostJournal>,
    HostAuthority,
    RelaySupervisor,
) {
    let dir = tempfile::tempdir().unwrap();
    let binding = TransportBindingV11 {
        server: "ws://example/ws/sandbox-host".into(),
        host_owner_id: "owner-1".into(),
        host_id: "host".into(),
    };
    let journal =
        Arc::new(crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap());
    // No journal fence: these tests drive the publication path directly.
    let authority = HostAuthority::default();
    let relay = RelaySupervisor::start(
        Arc::new(sandbox_runtime::FakeRuntime::new()),
        journal.clone(),
        authority.clone(),
        #[cfg(target_os = "linux")]
        None,
    );
    (dir, journal, authority, relay)
}

/// Review round 3 #1: the socket fails in the middle of a published batch.
/// The failed completion's ownership goes with it (receipt recovery settles
/// it); every untouched completion keeps its token and goes back to the
/// supervisor, so no ownerless entry is ever carried or adopted.
#[test]
fn a_socket_error_mid_batch_requeues_owned_completions_and_never_strands_ownership() {
    let (_dir, journal, authority, relay) = relay_parts();
    authority.attach(1);
    for id in ["first", "second"] {
        authority
            .accept_dispatch(id, "sbx", "command.run", 1, 1)
            .unwrap();
        let token = authority.take_ownership(id, 1, 1).unwrap();
        relay
            .finished_sender()
            .send(finished(id, OperationState::UnknownOutcome, Some(token)))
            .unwrap();
    }
    let (mut socket, _peer) = socket_pair();
    socket.close(None).unwrap(); // every send now fails
    let mut admission = crate::sandbox_relay::test_support::admission(
        4,
        crate::sandbox_relay::live_admission::test_capacity(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let error = loop {
        match drain_finished(
            &mut socket,
            WireCodes::CURRENT,
            &authority,
            &mut admission,
            &relay,
            &journal,
            &mut HashMap::new(),
            None,
        ) {
            Err(error) => break error,
            Ok(()) => {
                assert!(Instant::now() < deadline, "completions never drained");
                thread::sleep(Duration::from_millis(5));
            }
        }
    };
    assert!(transport_lost(&error), "{error:#}");
    // The failed item released its token; the untouched one kept it.
    let owned: Vec<_> = ["first", "second"]
        .into_iter()
        .filter(|id| authority.owned(id, 1, 1))
        .collect();
    assert_eq!(
        owned.len(),
        1,
        "exactly the requeued completion stays owned"
    );
    assert_eq!(
        authority.detach(Instant::now()),
        1,
        "only owned work is carried"
    );
    let carried = authority.carried();
    assert_eq!(carried.len(), 1);
    let requeued = carried[0].0.clone();
    assert_eq!(owned, [requeued.as_str()]);
    // After adoption the requeued completion still publishes.
    authority.attach(2);
    assert!(authority.adopt(&requeued, 1, 1, 2));
    let mut items = relay.poll_finished();
    assert_eq!(items.len(), 1);
    let item = items.pop().unwrap();
    assert_eq!(item.operation_id, requeued);
    assert!(item.owner.is_some(), "its token travelled with it");
    drop(item);
    assert!(!authority.owned(&requeued, 1, 1), "released once consumed");
}

/// Review round 3 #2: a stdin-failure observation (UNKNOWN, non-interim,
/// no token) is published while the command worker still owns the attempt
/// (e.g. cancellation cleanup). Publishing it never releases the worker's
/// ownership, so a drop carries the attempt and keeps its cleanup permit.
#[test]
fn a_stdin_failure_observation_never_releases_a_live_workers_ownership() {
    let (_dir, journal, authority, relay) = relay_parts();
    authority.attach(1);
    authority
        .accept_dispatch("cmd", "sbx", "command.run", 1, 1)
        .unwrap();
    // The live worker: its token and its cleanup permit.
    let worker = authority.take_ownership("cmd", 1, 1).unwrap();
    let permit = authority.register_runtime("cmd", 1, 1).unwrap();
    // fail_stdin's observation carries no token.
    relay
        .finished_sender()
        .send(finished("cmd", OperationState::UnknownOutcome, None))
        .unwrap();
    let (mut socket, mut peer) = socket_pair();
    let mut admission = crate::sandbox_relay::test_support::admission(
        4,
        crate::sandbox_relay::live_admission::test_capacity(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        drain_finished(
            &mut socket,
            WireCodes::CURRENT,
            &authority,
            &mut admission,
            &relay,
            &journal,
            &mut HashMap::new(),
            None,
        )
        .unwrap();
        if let Ok(Message::Text(text)) = {
            peer.get_mut().set_nonblocking(true).unwrap();
            let read = peer.read();
            peer.get_mut().set_nonblocking(false).unwrap();
            read
        } && let DaemonControlMessage::OperationResult { operation_id, .. } =
            parse_daemon_control(&text).unwrap()
        {
            assert_eq!(operation_id, "cmd");
            break;
        }
        assert!(Instant::now() < deadline, "observation never published");
        thread::sleep(Duration::from_millis(5));
    }
    assert!(authority.owned("cmd", 1, 1), "the worker still owns it");
    assert_eq!(
        authority.detach(Instant::now()),
        1,
        "carried, not forgotten"
    );
    assert!(!permit.is_cancelled(), "cleanup permit survives the drop");
    drop(worker);
}

/// Live finding B-1: a dispatch died with the transport (sent to the old
/// socket, never read). On reconnect the daemon audits the server's
/// unacknowledged attempts before the census and gives a positive
/// never-received verdict only for an epoch it attached and an operation its
/// journal never recorded; anything it knows, or an epoch it never owned,
/// stays `received` (today's reconciliation).
#[test]
fn reconnect_audit_proves_lost_dispatches_never_received() {
    let dir = tempfile::tempdir().expect("dir");
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let fake = sandbox_runtime::FakeRuntime::with_command_delay(Duration::from_millis(800));
    seed(&listener, dir.path(), &fake);
    let options = options(&listener, dir.path(), Duration::from_secs(5));
    let shutdown = options.shutdown.clone();
    let daemon = spawn_daemon(options, fake, None);
    let mut wire = accept(&listener);
    register(&mut wire, 1);
    crate::sandbox_relay::test_support::ack_registration(&mut wire);
    send(&mut wire, command("known"));
    until(&mut wire, |m| accepted(m, "known"));
    // The RST pattern: the frame for "lost" is written while the daemon's
    // bytes are unread, then the connection is reset. It never arrives.
    let _ = wire.send(Message::Text(command("lost").to_string().into()));
    reset(wire);
    let mut wire = accept(&listener);
    register(&mut wire, 2);
    let entry = |id: &str, epoch: u64| {
        json!({"sandboxOwnerId":"owner","operationId":id,"sandboxId":"sbx","generation":1,
            "attempt":1,"connectionEpoch":epoch,"idempotencyKey":id,"kind":"command.run"})
    };
    let seen = reconcile_auditing(
        &mut wire,
        |_| true,
        |page| {
            assert_eq!(page, 0);
            json!([entry("lost", 1), entry("known", 1), entry("foreign", 7)])
        },
    );
    let verdict = |id: &str| {
        seen.audit
            .iter()
            .find(|v| v.operation_id == id)
            .map(|v| v.received)
    };
    // Either the frame died in transit (proved never received) or, if the
    // kernel delivered it before the reset, the daemon journaled it.
    let lost_journaled = journal_receipt(dir.path(), "lost").is_some();
    assert_eq!(verdict("lost"), Some(lost_journaled), "{seen:?}");
    assert_eq!(verdict("known"), Some(true), "journaled work was received");
    assert_eq!(
        verdict("foreign"),
        Some(true),
        "an epoch this process never owned"
    );
    finish(daemon, shutdown);
    drop(wire);
}

/// The first session of a process owns no older epoch: no audit is sent.
#[test]
fn a_first_session_sends_no_dispatch_audit() {
    let dir = tempfile::tempdir().expect("dir");
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let fake = sandbox_runtime::FakeRuntime::new();
    seed(&listener, dir.path(), &fake);
    let options = options(&listener, dir.path(), Duration::from_secs(5));
    let shutdown = options.shutdown.clone();
    let daemon = spawn_daemon(options, fake, None);
    let mut wire = accept(&listener);
    register(&mut wire, 1);
    let seen = reconcile_auditing(
        &mut wire,
        |_| true,
        |_| panic!("no audit on a first session"),
    );
    assert!(seen.audit.is_empty());
    finish(daemon, shutdown);
    drop(wire);
}

/// Live finding R-1: a create holds its sandbox's runtime lock across the
/// drop (as an Incus create does through its boot). The reconnect census
/// must never wait on that lock: it skips the carried sandbox, so the daemon
/// reconnects promptly (well inside the grace) and adopts the create, which
/// then finishes normally.
#[test]
fn reconnect_census_never_waits_on_a_carried_creates_sandbox_lock() {
    let dir = tempfile::tempdir().expect("dir");
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    // The sandbox lock and the create's hold on it.
    let sandbox_lock = Arc::new(std::sync::Mutex::new(()));
    let (entered_tx, entered_rx) = mpsc::channel::<()>();
    let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let release = released.clone();
    let waited = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // Seeding `sbx` runs the same "create" stage; only the dispatched create
    // may take the lock, or `entered` fires (and the hook blocks for its full
    // deadline) before the daemon even starts, and the drop can race ahead of
    // the create it is meant to carry.
    let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let fake = {
        let armed = armed.clone();
        let create_lock = sandbox_lock.clone();
        let census_lock = sandbox_lock.clone();
        let waited = waited.clone();
        sandbox_runtime::FakeRuntime::new()
            .with_lifecycle_hook(move |stage| {
                if stage == "create" && armed.load(std::sync::atomic::Ordering::SeqCst) {
                    let _held = create_lock.lock().unwrap();
                    let _ = entered_tx.send(());
                    let deadline = Instant::now() + Duration::from_secs(30);
                    while !release.load(std::sync::atomic::Ordering::SeqCst)
                        && Instant::now() < deadline
                    {
                        thread::sleep(Duration::from_millis(5));
                    }
                }
                Ok(())
            })
            .with_inventory_hook(move |stage| {
                // A census that would verify every running VM takes every
                // sandbox lock; one told to skip "fresh" never touches it.
                if stage.starts_with("inventory")
                    && !stage
                        .strip_prefix("inventory-skipping:")
                        .is_some_and(|busy| busy.split(',').any(|id| id == "fresh"))
                    && census_lock.try_lock().is_err()
                {
                    waited.store(true, std::sync::atomic::Ordering::SeqCst);
                    drop(census_lock.lock());
                }
                Ok(())
            })
    };
    seed(&listener, dir.path(), &fake);
    armed.store(true, std::sync::atomic::Ordering::SeqCst);
    let options = options(&listener, dir.path(), Duration::from_secs(5));
    let shutdown = options.shutdown.clone();
    let daemon = spawn_daemon(options, fake, None);
    let mut wire = accept(&listener);
    register(&mut wire, 1);
    crate::sandbox_relay::test_support::ack_registration(&mut wire);
    let create: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner",
        "operationId":"fresh-create","sandboxId":"fresh","kind":"sandbox.create","generation":1,
        "attempt":1,"idempotencyKey":"fresh-create","bodyHash":"a".repeat(64),
        "lease":sandbox_protocol::HostLease::for_test(),"cpuCount":1,"memoryMiB":1024,
        "allocation":crate::sandbox_relay::test_support::allocation(),
        "templateDigest":sandbox_runtime::CreateSandboxRequest::for_test("fresh","k").template_digest,
        "incusFingerprint":sandbox_runtime::CreateSandboxRequest::for_test("fresh","k").template_digest,
        "architecture":"x86_64"}))
    .unwrap();
    let mut frame =
        serde_json::to_value(crate::sandbox_relay::test_support::pinned_dispatch(&create)).unwrap();
    frame["type"] = json!("operation.dispatch");
    send(&mut wire, frame);
    entered_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the create holds its sandbox lock");
    let dropped = Instant::now();
    reset(wire);
    let mut wire = accept(&listener);
    let gap = dropped.elapsed();
    assert!(
        gap < Duration::from_secs(5),
        "reconnect waited on the carried create's lock: {gap:?}"
    );
    register(&mut wire, 2);
    let seen = reconcile(&mut wire, |_| true);
    assert!(
        seen.adopted.iter().any(|(id, _, _)| id == "fresh-create"),
        "{seen:?}"
    );
    assert!(
        !waited.load(std::sync::atomic::Ordering::SeqCst),
        "no census waited on the busy sandbox"
    );
    released.store(true, std::sync::atomic::Ordering::SeqCst);
    let done = until(&mut wire, |m| result_of(m, "fresh-create").is_some());
    assert_eq!(
        result_of(&done, "fresh-create"),
        Some(OperationState::Succeeded)
    );
    finish(daemon, shutdown);
    drop(wire);
}

/// Live finding R2-1: the drop lands right after the command started and its
/// `process.started` went out on the dying transport (here: the old server
/// side reads it and loses it). After adoption the daemon publishes the same
/// birth again on the new epoch, so the server learns the pid promptly
/// instead of only at exit.
#[test]
fn adoption_republishes_process_start_evidence_lost_with_the_old_transport() {
    let dir = tempfile::tempdir().expect("dir");
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let fake = sandbox_runtime::FakeRuntime::with_command_delay(Duration::from_secs(4));
    seed(&listener, dir.path(), &fake);
    let options = options(&listener, dir.path(), Duration::from_secs(5));
    let shutdown = options.shutdown.clone();
    let daemon = spawn_daemon(options, fake, None);
    let mut wire = accept(&listener);
    register(&mut wire, 1);
    crate::sandbox_relay::test_support::ack_registration(&mut wire);
    let mut frame = command("cmd");
    frame["processId"] = json!("proc-1");
    frame["resultVersion"] = json!(1);
    send(&mut wire, frame);
    let lost = match until(&mut wire, |m| {
        matches!(m, DaemonControlMessage::ProcessStarted { .. })
    }) {
        DaemonControlMessage::ProcessStarted { pid, boot_id, .. } => (pid, boot_id),
        _ => unreachable!(),
    };
    // That frame never reached the server: the transport dies now.
    reset(wire);
    let mut wire = accept(&listener);
    register(&mut wire, 2);
    let seen = reconcile(&mut wire, |_| true);
    assert!(
        seen.adopted.iter().any(|(id, _, _)| id == "cmd"),
        "{seen:?}"
    );
    let started = Instant::now();
    match until(&mut wire, |m| {
        matches!(m, DaemonControlMessage::ProcessStarted { operation_id, .. } if operation_id == "cmd")
            || result_of(m, "cmd").is_some()
    }) {
        DaemonControlMessage::ProcessStarted {
            pid,
            boot_id,
            process_id,
            attempt,
            ..
        } => {
            assert_eq!((pid, boot_id), lost, "the same birth, republished");
            assert_eq!((process_id.as_str(), attempt), ("proc-1", 1));
        }
        other => panic!("the result came before the process identity: {other:?}"),
    }
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "promptly after adoption"
    );
    finish(daemon, shutdown);
    drop(wire);
}

/// E3B-01: a short build step looks up seven blocked names; the first three
/// already left in a hint frame, so the rate limit holds the last four.
/// They must reach the server before the step's operation result (the
/// server attributes a hint to the step running when it arrives); they used
/// to leave after it, landing on the next step or nowhere.
#[test]
fn late_refused_names_reach_the_server_before_their_steps_result() {
    let (_dir, journal, authority, relay) = relay_parts();
    authority.attach(1);
    let runtime = sandbox_runtime::FakeRuntime::new().with_refused_dns_hints();
    let mut reporter = super::super::egress_hints::RefusedNameReporter::default();
    for name in ["a.example", "b.example", "c.example"] {
        reporter.observe("sbx", name);
    }
    assert_eq!(reporter.drain(Instant::now()).len(), 1, "the early frame");
    // Late in the step: recorded by the stub before the guest saw the answers.
    for name in ["d.example", "e.example", "f.example", "g.example"] {
        runtime.push_refused_dns_name("sbx", name);
    }
    authority
        .accept_dispatch("step", "sbx", "command.run", 1, 1)
        .unwrap();
    let token = authority.take_ownership("step", 1, 1).unwrap();
    relay
        .finished_sender()
        .send(finished("step", OperationState::Succeeded, Some(token)))
        .unwrap();
    let (mut socket, mut peer) = socket_pair();
    let mut admission = crate::sandbox_relay::test_support::admission(
        4,
        crate::sandbox_relay::live_admission::test_capacity(),
    );
    let mut hinted = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        drain_finished(
            &mut socket,
            WireCodes::CURRENT,
            &authority,
            &mut admission,
            &relay,
            &journal,
            &mut HashMap::new(),
            Some(StepEndHints {
                runtime: &runtime,
                reporter: &mut reporter,
            }),
        )
        .unwrap();
        peer.get_mut().set_nonblocking(true).unwrap();
        let mut result = false;
        while let Ok(Message::Text(text)) = peer.read() {
            match parse_daemon_control(&text).unwrap() {
                DaemonControlMessage::EgressRefused(report) => {
                    assert_eq!(report.sandbox_id, "sbx");
                    hinted.extend(report.names);
                }
                DaemonControlMessage::OperationResult { operation_id, .. } => {
                    assert_eq!(operation_id, "step");
                    result = true;
                }
                other => panic!("unexpected frame {other:?}"),
            }
        }
        peer.get_mut().set_nonblocking(false).unwrap();
        if result {
            break;
        }
        assert!(Instant::now() < deadline, "the step never completed");
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        hinted,
        ["d.example", "e.example", "f.example", "g.example"],
        "every late name precedes the step's result"
    );
}

/// A `sandbox.create` dispatch for `sandbox` (operation `id`).
fn create_dispatch(id: &str, sandbox: &str) -> serde_json::Value {
    let create: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner",
        "operationId":id,"sandboxId":sandbox,"kind":"sandbox.create","generation":1,
        "attempt":1,"idempotencyKey":id,"bodyHash":"a".repeat(64),
        "lease":sandbox_protocol::HostLease::for_test(),"cpuCount":1,"memoryMiB":1024,
        "allocation":crate::sandbox_relay::test_support::allocation(),
        "templateDigest":sandbox_runtime::CreateSandboxRequest::for_test(sandbox,"k").template_digest,
        "incusFingerprint":sandbox_runtime::CreateSandboxRequest::for_test(sandbox,"k").template_digest,
        "architecture":"x86_64"}))
    .unwrap();
    let mut frame =
        serde_json::to_value(crate::sandbox_relay::test_support::pinned_dispatch(&create)).unwrap();
    frame["type"] = json!("operation.dispatch");
    frame
}

/// Fixed wall time, test-controlled monotonic time: the daemon's host-report
/// cadence advances only when the test says so.
#[derive(Debug)]
struct SteppedClock {
    wall: u64,
    elapsed: std::sync::atomic::AtomicU64,
}
impl crate::sandbox_relay::clock::ClockSource for SteppedClock {
    fn sample(&self) -> Result<(u64, u64)> {
        Ok((
            self.wall,
            self.elapsed.load(std::sync::atomic::Ordering::SeqCst),
        ))
    }
}
impl SteppedClock {
    fn advance(&self, by: Duration) {
        self.elapsed.fetch_add(
            u64::try_from(by.as_millis()).unwrap(),
            std::sync::atomic::Ordering::SeqCst,
        );
    }
}

/// A reconnect carrying `create-a` (Effect, held by the runtime until
/// `release`) and `create-b` (Intent: queued behind it on the one lifecycle
/// slot, as a create still fetching its image is). Returns the new session's
/// wire right after `hello.ok` for epoch 2.
struct CarriedCreates {
    _dir: tempfile::TempDir,
    wire: Wire,
    daemon: thread::JoinHandle<Result<()>>,
    shutdown: ShutdownSignal,
    release: Arc<std::sync::atomic::AtomicBool>,
    clock: Arc<SteppedClock>,
    fake: sandbox_runtime::FakeRuntime,
    /// Armed: the reconnect census blocks in its runtime inventory, signals
    /// `census_entered`, and waits for `census_release`.
    census_armed: Arc<std::sync::atomic::AtomicBool>,
    census_entered: mpsc::Receiver<()>,
    census_release: Arc<std::sync::atomic::AtomicBool>,
}
fn carried_creates() -> CarriedCreates {
    let dir = tempfile::tempdir().expect("dir");
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let (entered_tx, entered_rx) = mpsc::channel::<()>();
    let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // Only the first dispatched create blocks (in Effect); seeding runs the
    // same stage, so the hook is armed after it.
    let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let census_armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let census_release = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (census_tx, census_entered) = mpsc::channel::<()>();
    let fake = {
        let armed = armed.clone();
        let release = release.clone();
        let (census_armed, census_release) = (census_armed.clone(), census_release.clone());
        sandbox_runtime::FakeRuntime::new()
            .with_inventory_hook(move |stage| {
                // The reconnect census skips the carried creates.
                if stage.starts_with("inventory-skipping:")
                    && census_armed.swap(false, std::sync::atomic::Ordering::SeqCst)
                {
                    let _ = census_tx.send(());
                    let deadline = Instant::now() + Duration::from_secs(30);
                    while !census_release.load(std::sync::atomic::Ordering::SeqCst)
                        && Instant::now() < deadline
                    {
                        thread::sleep(Duration::from_millis(5));
                    }
                }
                Ok(())
            })
            .with_lifecycle_hook(move |stage| {
                if stage == "create" && armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
                    let _ = entered_tx.send(());
                    let deadline = Instant::now() + Duration::from_secs(30);
                    while !release.load(std::sync::atomic::Ordering::SeqCst)
                        && Instant::now() < deadline
                    {
                        thread::sleep(Duration::from_millis(5));
                    }
                }
                Ok(())
            })
    };
    seed(&listener, dir.path(), &fake);
    armed.store(true, std::sync::atomic::Ordering::SeqCst);
    let clock = Arc::new(SteppedClock {
        wall: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        elapsed: std::sync::atomic::AtomicU64::new(0),
    });
    // One lifecycle slot: `create-b` stays queued (Intent) behind `create-a`.
    let mut options = options(&listener, dir.path(), Duration::from_secs(5));
    options.max_concurrent_commands = 1;
    let shutdown = options.shutdown.clone();
    let daemon = {
        let fake = fake.clone();
        let clock = Arc::new(crate::sandbox_relay::clock::LeaseClock::new(clock.clone()));
        thread::spawn(move || {
            REPORT_CLOCK_OVERRIDE.with(|cell| *cell.borrow_mut() = Some(clock));
            let result = run_connect_with(&options, |_| Ok((Box::new(fake), None)));
            if let Err(error) = &result {
                eprintln!("daemon ended: {error:#}");
            }
            result
        })
    };
    let mut wire = accept(&listener);
    register(&mut wire, 1);
    crate::sandbox_relay::test_support::ack_registration(&mut wire);
    send(&mut wire, create_dispatch("create-a", "a"));
    entered_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("create-a holds the lifecycle slot in Effect");
    send(&mut wire, create_dispatch("create-b", "b"));
    until(&mut wire, |m| accepted(m, "create-b"));
    reset(wire);
    let mut wire = accept(&listener);
    register_judged(&mut wire, 2);
    CarriedCreates {
        _dir: dir,
        wire,
        daemon,
        shutdown,
        release,
        clock,
        fake,
        census_armed,
        census_entered,
        census_release,
    }
}

/// The fake server's model of the TTL gates an Intent create's adoption
/// re-runs (`intentReclaimGates`): a guard-lease renewal and a storage
/// observation of this epoch received within the TTL. Time only moves when
/// the test advances the clock, so "within the TTL" is "since the last
/// advance". Only a healthy guard verdict (with the identity the wire
/// requires of it) renews the lease; an unhealthy one ends it, as on the
/// server.
#[derive(Default, Debug)]
struct TtlGates {
    egress_fresh: bool,
    egress_healthy: bool,
    storage_fresh: bool,
    storage_healthy: bool,
    /// Last sequences seen: the server ignores a repeated or older one.
    egress_sequence: u64,
    storage_sequence: u64,
}
impl TtlGates {
    fn observe(&mut self, message: &DaemonControlMessage) {
        match message {
            DaemonControlMessage::HostEgressState(state) if state.connection_epoch == 2 => {
                assert!(state.sequence > self.egress_sequence, "{state:?}");
                assert!(state.is_valid(), "{state:?}");
                self.egress_sequence = state.sequence;
                self.egress_fresh = true;
                self.egress_healthy = state.guard_ok
                    && state.guard_instance_id.is_some()
                    && state.guard_generation.is_some();
            }
            DaemonControlMessage::InventoryUpdate {
                connection_epoch: 2,
                storage_pools,
                observation_sequence,
                ..
            } => {
                assert!(*observation_sequence > self.storage_sequence);
                self.storage_sequence = *observation_sequence;
                self.storage_fresh = true;
                self.storage_healthy = storage_pools
                    .iter()
                    .all(|p| p.health == sandbox_protocol::capacity_v11::StorageHealth::Healthy);
            }
            _ => {}
        }
    }
    fn expire(&mut self) {
        self.egress_fresh = false;
        self.storage_fresh = false;
    }
    fn admit(&self) -> bool {
        self.egress_fresh && self.egress_healthy && self.storage_fresh && self.storage_healthy
    }
    /// The server's judgement of one census entry: stopped/absent root
    /// evidence older than the pool's observation is stale; current evidence
    /// passes the retained-storage gate only on fresh, healthy health.
    fn judge(
        &self,
        entry: &sandbox_protocol::InventoryEntry,
    ) -> sandbox_protocol::CensusEntryOutcome {
        use sandbox_protocol::CensusEntryOutcome as O;
        let Some(root) = &entry.root else {
            return O::NotConverged;
        };
        if !matches!(
            entry.state,
            sandbox_protocol::SandboxLifecycleState::Stopped
                | sandbox_protocol::SandboxLifecycleState::Absent
        ) {
            return O::NotConverged;
        }
        assert!(
            root.observation_sequence <= self.storage_sequence,
            "root evidence from an observation the server never received: {entry:?}"
        );
        if root.observation_sequence < self.storage_sequence {
            O::StaleStorage
        } else if !self.storage_healthy {
            O::NotConverged
        } else if !self.storage_fresh {
            O::StaleStorage
        } else {
            O::Converged
        }
    }
}

/// What [`reconcile_outlasting_ttls`] saw.
#[derive(Debug)]
struct OutlastedReconcile {
    /// The TTL-gate model's answer to `create-b`'s Intent adoption.
    intent_adopted: bool,
    /// Census entries the model converged.
    converged: Vec<String>,
    /// Census entries the model refused for stale storage.
    stale: Vec<String>,
    /// Storage observations published between the census start (after the
    /// dispatch audit) and `reconcile.complete`.
    census_storage_updates: u64,
}

/// More than both 15 s TTLs pass; returns once the daemon renewed both
/// reports on its own cadence (the model saw fresh ones).
fn outlast_ttls(c: &mut CarriedCreates, gates: &mut TtlGates) {
    c.clock.advance(Duration::from_secs(20));
    gates.expire();
    while !(gates.egress_fresh && gates.storage_fresh) {
        let next = until(&mut c.wire, |m| {
            matches!(
                m,
                DaemonControlMessage::HostEgressState(_)
                    | DaemonControlMessage::InventoryUpdate { .. }
            )
        });
        gates.observe(&next);
    }
}

/// Plays reconciliation for [`carried_creates`]. On `create-a`'s (Effect)
/// adoption it runs `stall` and outlasts the TTLs. `create-b`'s (Intent)
/// adoption is answered by the TTL-gate model. With `long_census`, the
/// census (after the dispatch audit) then outlasts the TTLs too, blocked in
/// its runtime inventory. Each page is judged by the model as the server
/// judges it on arrival (answered per entry when negotiated).
fn reconcile_outlasting_ttls(
    c: &mut CarriedCreates,
    stall: impl FnOnce(&CarriedCreates),
    long_census: bool,
) -> OutlastedReconcile {
    let mut gates = TtlGates::default();
    let mut stall = Some(stall);
    let mut intent_answer = None;
    let (mut converged, mut stale) = (Vec::new(), Vec::new());
    let mut census_started_at = None;
    let mut census_storage_updates = 0;
    let mut complete = false;
    let mut census_pending = false;
    loop {
        let Message::Text(text) = c.wire.read().expect("reconciliation frame") else {
            continue;
        };
        let message = parse_daemon_control(&text).expect("control");
        gates.observe(&message);
        if census_pending
            && !matches!(
                message,
                DaemonControlMessage::OperationReceipt { .. }
                    | DaemonControlMessage::DispatchAuditResult { .. }
            )
        {
            census_pending = false;
            c.census_entered
                .recv_timeout(Duration::from_secs(10))
                .expect("the census started");
            outlast_ttls(c, &mut gates);
            c.census_release
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        match message {
            DaemonControlMessage::OperationAdopt {
                operation_id,
                generation,
                attempt,
                phase,
                ..
            } => {
                let adopted = if phase == sandbox_protocol::AdoptPhase::Effect {
                    if let Some(stall) = stall.take() {
                        stall(c);
                        outlast_ttls(c, &mut gates);
                    }
                    true
                } else {
                    assert_eq!(operation_id, "create-b");
                    let admit = gates.admit();
                    intent_answer = Some(admit);
                    admit
                };
                send(
                    &mut c.wire,
                    json!({"type":"operation.adopt.result","operationId":operation_id,
                        "generation":generation,"attempt":attempt,"adopted":adopted}),
                );
            }
            DaemonControlMessage::OperationReceipt { operation_id, .. } => send(
                &mut c.wire,
                json!({"type":"receipt.ack","operationId":operation_id}),
            ),
            DaemonControlMessage::DispatchAuditRequest { page } => {
                // The census follows the audit; earlier reconciliation
                // inventories (startup query, expiry pass) are not stalled.
                c.census_armed
                    .store(long_census, std::sync::atomic::Ordering::SeqCst);
                census_started_at = Some(gates.storage_sequence);
                send(
                    &mut c.wire,
                    json!({"type":"dispatch.audit.page","page":page,"complete":true,"entries":[]}),
                );
                // WP2 item 6: receipt replay now follows the audit; the
                // census begins after it (acknowledged below).
                census_pending = long_census;
            }
            DaemonControlMessage::SandboxInventory { page, entries, .. } => {
                let results: Vec<_> = entries
                    .iter()
                    .map(|e| (e.sandbox_id.clone(), gates.judge(e)))
                    .collect();
                for (id, outcome) in &results {
                    match outcome {
                        sandbox_protocol::CensusEntryOutcome::Converged => {
                            converged.push(id.clone())
                        }
                        sandbox_protocol::CensusEntryOutcome::StaleStorage => {
                            stale.push(id.clone())
                        }
                        sandbox_protocol::CensusEntryOutcome::NotConverged
                        | sandbox_protocol::CensusEntryOutcome::Superseded => {}
                    }
                }
                let mut ack = json!({"type":"inventory.ack","page":page,"entryResults": entries.iter().map(|entry| json!({"sandboxId":entry.sandbox_id,"outcome":"converged"})).collect::<Vec<_>>()});
                ack["entryResults"] = json!(
                    results
                        .iter()
                        .map(|(id, outcome)| json!({"sandboxId": id, "outcome": outcome}))
                        .collect::<Vec<_>>()
                );
                send(&mut c.wire, ack);
            }
            DaemonControlMessage::ReconcileComplete { .. } => {
                census_storage_updates =
                    gates.storage_sequence - census_started_at.expect("audit before census");
                complete = true;
            }
            DaemonControlMessage::HostTerminalPolicy(_) if complete => {
                return OutlastedReconcile {
                    intent_adopted: intent_answer.expect("create-b was offered for adoption"),
                    converged,
                    stale,
                    census_storage_updates,
                };
            }
            DaemonControlMessage::Heartbeat { id, .. } => pong(&mut c.wire, &id),
            _ => {}
        }
    }
}

/// WP2 item 6 (Codex WP2 r1 #5): carried work is offered for adoption
/// before any unrelated receipt is replayed, so stalled receipt resolutions
/// can never eat the carry grace of healthy carried work. Here the seeded
/// sandbox's journaled create receipt (`create`) is replayed on the
/// reconnect after both carried creates were offered.
#[test]
fn wp2_carried_work_is_adopted_before_receipt_replay() {
    let mut c = carried_creates();
    let mut order = Vec::new();
    loop {
        let Message::Text(text) = c.wire.read().expect("reconciliation frame") else {
            continue;
        };
        match parse_daemon_control(&text).expect("control") {
            DaemonControlMessage::OperationAdopt {
                operation_id,
                generation,
                attempt,
                ..
            } => {
                order.push(format!("adopt:{operation_id}"));
                send(
                    &mut c.wire,
                    json!({"type":"operation.adopt.result","operationId":operation_id,
                        "generation":generation,"attempt":attempt,"adopted":true}),
                );
            }
            DaemonControlMessage::OperationReceipt { operation_id, .. } => {
                order.push(format!("receipt:{operation_id}"));
                send(
                    &mut c.wire,
                    json!({"type":"receipt.ack","operationId":operation_id}),
                );
            }
            DaemonControlMessage::DispatchAuditRequest { page } => send(
                &mut c.wire,
                json!({"type":"dispatch.audit.page","page":page,"complete":true,"entries":[]}),
            ),
            DaemonControlMessage::SandboxInventory { page, entries, .. } => {
                let results: Vec<_> = entries
                    .iter()
                    .map(|e| json!({"sandboxId": e.sandbox_id, "outcome": "converged"}))
                    .collect();
                send(
                    &mut c.wire,
                    json!({"type":"inventory.ack","page":page,"entryResults":results}),
                );
            }
            DaemonControlMessage::ReconcileComplete { .. } => break,
            DaemonControlMessage::Heartbeat { id, .. } => pong(&mut c.wire, &id),
            _ => {}
        }
    }
    let first_receipt = order
        .iter()
        .position(|frame| frame == "receipt:create")
        .unwrap_or_else(|| panic!("the seeded receipt is replayed: {order:?}"));
    let adopted: Vec<_> = order
        .iter()
        .enumerate()
        .filter(|(_, frame)| frame.starts_with("adopt:"))
        .map(|(index, _)| index)
        .collect();
    assert_eq!(adopted.len(), 2, "{order:?}");
    assert!(
        adopted.iter().all(|index| *index < first_receipt),
        "{order:?}"
    );
    c.release.store(true, std::sync::atomic::Ordering::SeqCst);
    finish(c.daemon, c.shutdown);
    drop(c.wire);
}

/// Production 2026-11-05: a create still in its Intent phase (there: the
/// template image download) when the relay dropped was refused adoption on
/// reconnect and settled UNKNOWN. The server re-runs the create's TTL gates
/// (egress-guard lease, storage health) for an Intent adoption; a hello resets
/// both, and the daemon renewed them only from the dispatch loop, after
/// reconciliation. Now the session renews them on its own cadence from
/// `hello.ok`, through reconciliation: even a reconnect that outlasts both
/// TTLs adopts the Intent create, which then completes.
#[test]
fn an_intent_create_is_adopted_after_a_reconnect_that_outlasts_the_report_ttls() {
    let mut c = carried_creates();
    assert!(
        reconcile_outlasting_ttls(&mut c, |_| {}, false).intent_adopted,
        "the Intent create's TTL gates were stale at adoption"
    );
    c.release.store(true, std::sync::atomic::Ordering::SeqCst);
    let mut pending = vec!["create-a", "create-b"];
    while !pending.is_empty() {
        let message = until(&mut c.wire, |m| {
            pending.iter().any(|id| result_of(m, id).is_some())
        });
        let DaemonControlMessage::OperationResult {
            operation_id,
            state,
            ..
        } = message
        else {
            unreachable!()
        };
        assert_eq!(state, OperationState::Succeeded, "{operation_id}");
        pending.retain(|id| *id != operation_id);
    }
    finish(c.daemon, c.shutdown);
    drop(c.wire);
}

/// The renewals carry the live verdict: storage that goes unavailable during
/// reconciliation is reported as such before the Intent create's adoption,
/// which is then refused; the create never runs (it settles by receipt).
#[test]
fn storage_going_unhealthy_mid_reconcile_refuses_the_intent_create_adoption() {
    let mut c = carried_creates();
    assert!(
        !reconcile_outlasting_ttls(
            &mut c,
            |c| c.fake.set_storage_pool_available("default", false),
            false
        )
        .intent_adopted,
        "an Intent create was adopted on unavailable storage"
    );
    c.release.store(true, std::sync::atomic::Ordering::SeqCst);
    // Never issued: its worker settles it durably (a non-success Result,
    // reported by receipt), and no success is ever published.
    let started = Instant::now();
    let state = loop {
        if let Some(receipt) = journal_receipt(c._dir.path(), "create-b")
            && ["unknown_outcome", "failed", "cancelled", "succeeded"]
                .contains(&receipt["state"].as_str().unwrap_or_default())
        {
            break receipt["state"].clone();
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the refused create never settled"
        );
        thread::sleep(Duration::from_millis(20));
    };
    assert_ne!(state, json!("succeeded"), "a refused create ran");
    finish(c.daemon, c.shutdown);
    drop(c.wire);
}

fn stop_sbx_while_detached(c: &CarriedCreates) {
    c.fake
        .stop_sandbox(&sandbox_runtime::StopSandboxRequest {
            sandbox_id: "sbx".into(),
            instance_name: "wssp-sbx-sbx".into(),
            operation_id: "stopped-while-detached".into(),
            idempotency_key: "stopped-while-detached".into(),
            template_fingerprint: String::new(),
        })
        .unwrap();
}

/// A reconnect census that outlasts the storage TTL (blocked in its runtime
/// inventory past `STORAGE_HEALTH_STALE_MS`) against a server that judges
/// each entry: storage keeps renewing through the census, each page's roots
/// are observed and stamped right before it is sent, so the stopped root
/// converges, and the Intent create was still adopted.
#[test]
fn a_census_that_outlasts_the_storage_ttl_still_converges_stopped_roots() {
    let mut c = carried_creates();
    stop_sbx_while_detached(&c);
    let seen = reconcile_outlasting_ttls(&mut c, |_| {}, true);
    assert!(seen.intent_adopted, "{seen:?}");
    assert!(seen.converged.iter().any(|id| id == "sbx"), "{seen:?}");
    assert!(seen.stale.is_empty(), "{seen:?}");
    assert!(seen.census_storage_updates >= 1, "{seen:?}");
    c.release.store(true, std::sync::atomic::Ordering::SeqCst);
    finish(c.daemon, c.shutdown);
    drop(c.wire);
}

/// The model honors the renewal's verdict: a guard that turns unhealthy
/// while the reconnect outlasts the lease renews it as unhealthy, and the
/// Intent create's adoption is refused exactly as the server's guard gate
/// refuses it.
#[test]
fn an_unhealthy_guard_renewal_refuses_the_intent_create_adoption() {
    let mut c = carried_creates();
    let seen = reconcile_outlasting_ttls(
        &mut c,
        |c| {
            c.fake.guard().set_healthy(false);
            // The guard monitor polls every second (real time).
            thread::sleep(super::super::egress_state::GUARD_POLL_INTERVAL * 3);
        },
        false,
    );
    assert!(!seen.intent_adopted, "{seen:?}");
    c.release.store(true, std::sync::atomic::Ordering::SeqCst);
    finish(c.daemon, c.shutdown);
    drop(c.wire);
}

/// WP3 carry tests drive the debug timing knob, which release builds lack.
#[cfg(debug_assertions)]
mod carry {
    use super::*;

    /// WP3: a daemon whose carry policy comes from the debug timing knob
    /// (`WSSP_TEST_RELAY_TIMING` fields `intent_window,max_carry`).
    fn spawn_carry_daemon(
        options: ConnectOptions,
        fake: sandbox_runtime::FakeRuntime,
        knob: &str,
    ) -> thread::JoinHandle<Result<()>> {
        let timing =
            crate::sandbox_relay::test_timing::parse_relay_test_timing(knob).expect("knob");
        let policy =
            crate::sandbox_relay::carry::CarryPolicy::default().with_test_timing(Some(timing));
        thread::spawn(move || {
            crate::sandbox_relay::carry::CARRY_POLICY_OVERRIDE.with(|cell| cell.set(Some(policy)));
            let result = run_connect_with(&options, |_| Ok((Box::new(fake), None)));
            if let Err(error) = &result {
                eprintln!("daemon ended: {error:#}");
            }
            result
        })
    }

    /// One running command `cmd` (in Effect) across an outage of `outage`;
    /// returns its settled state and error code, whether it was published on
    /// the new epoch or settled by receipt during reconciliation.
    fn command_across_an_outage(
        fake: sandbox_runtime::FakeRuntime,
        knob: &str,
        dispatch: serde_json::Value,
        outage: Duration,
    ) -> (OperationState, Option<sandbox_protocol::WireErrorCode>) {
        let dir = tempfile::tempdir().expect("dir");
        let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
        seed(&listener, dir.path(), &fake);
        let options = options(&listener, dir.path(), Duration::from_secs(5));
        let shutdown = options.shutdown.clone();
        let daemon = spawn_carry_daemon(options, fake, knob);
        let mut wire = accept(&listener);
        register(&mut wire, 1);
        crate::sandbox_relay::test_support::ack_registration(&mut wire);
        send(&mut wire, dispatch);
        until(&mut wire, |m| accepted(m, "cmd"));
        reset(wire);
        thread::sleep(outage);
        let mut wire = accept(&listener);
        register(&mut wire, 2);
        let settled = settle_after_reconnect(&mut wire);
        finish(daemon, shutdown);
        drop(wire);
        settled
    }

    /// Server side of a reconnect that adopts everything, until `cmd` settles
    /// (published on the new epoch, or by receipt) and reconciliation completed.
    fn settle_after_reconnect(
        wire: &mut Wire,
    ) -> (OperationState, Option<sandbox_protocol::WireErrorCode>) {
        settle_after_reconnect_stalling(wire, Duration::ZERO)
    }

    /// [`settle_after_reconnect`], holding the first census acknowledgement
    /// for `stall` (adopted work stays unregistered meanwhile).
    fn settle_after_reconnect_stalling(
        wire: &mut Wire,
        mut stall: Duration,
    ) -> (OperationState, Option<sandbox_protocol::WireErrorCode>) {
        let mut settled = None;
        let mut census = false;
        let mut complete = false;
        loop {
            let Message::Text(text) = wire.read().expect("frame") else {
                continue;
            };
            match parse_daemon_control(&text).expect("control") {
                DaemonControlMessage::OperationAdopt {
                    operation_id,
                    generation,
                    attempt,
                    ..
                } => {
                    assert!(!census, "adoption must precede the census");
                    send(
                        wire,
                        json!({"type":"operation.adopt.result","operationId":operation_id,
                        "generation":generation,"attempt":attempt,"adopted":true}),
                    );
                }
                DaemonControlMessage::OperationReceipt {
                    operation_id,
                    state,
                    error,
                    ..
                } => {
                    send(
                        wire,
                        json!({"type":"receipt.ack","operationId":operation_id}),
                    );
                    if operation_id == "cmd" && state != OperationState::UnknownOutcome {
                        settled = Some((state, error.map(|e| e.code)));
                    }
                }
                DaemonControlMessage::OperationResult {
                    operation_id,
                    state,
                    error,
                    ..
                } if operation_id == "cmd" => {
                    settled = Some((state, error.map(|e| e.code)));
                }
                DaemonControlMessage::SandboxInventory { page, entries, .. } => {
                    census = true;
                    thread::sleep(std::mem::take(&mut stall));
                    send(
                        wire,
                        json!({"type":"inventory.ack","page":page,"entryResults": entries.iter().map(|entry| json!({"sandboxId":entry.sandbox_id,"outcome":"converged"})).collect::<Vec<_>>()}),
                    );
                }
                DaemonControlMessage::DispatchAuditRequest { page } => send(
                    wire,
                    json!({"type":"dispatch.audit.page","page":page,"complete":true,"entries":[]}),
                ),
                DaemonControlMessage::ReconcileComplete { .. } => complete = true,
                DaemonControlMessage::Heartbeat { id, .. } => pong(wire, &id),
                _ => {}
            }
            if complete && let Some(settled) = settled.clone() {
                return settled;
            }
        }
    }

    /// Server side of a reconnect that adopts every carried attempt, then drops
    /// the transport at the first census page (before registration completes).
    fn adopt_then_drop_at_census(mut wire: Wire) {
        loop {
            let Message::Text(text) = wire.read().expect("frame") else {
                continue;
            };
            match parse_daemon_control(&text).expect("control") {
                DaemonControlMessage::OperationAdopt {
                    operation_id,
                    generation,
                    attempt,
                    ..
                } => send(
                    &mut wire,
                    json!({"type":"operation.adopt.result","operationId":operation_id,
                    "generation":generation,"attempt":attempt,"adopted":true}),
                ),
                DaemonControlMessage::OperationReceipt { operation_id, .. } => send(
                    &mut wire,
                    json!({"type":"receipt.ack","operationId":operation_id}),
                ),
                DaemonControlMessage::DispatchAuditRequest { page } => send(
                    &mut wire,
                    json!({"type":"dispatch.audit.page","page":page,"complete":true,"entries":[]}),
                ),
                DaemonControlMessage::SandboxInventory { .. } => return reset(wire),
                DaemonControlMessage::Heartbeat { id, .. } => pong(&mut wire, &id),
                _ => {}
            }
        }
    }

    fn timed_command(timeout_ms: u64) -> serde_json::Value {
        let mut dispatch = command("cmd");
        dispatch["timeoutMs"] = json!(timeout_ms);
        dispatch
    }

    /// C12 (D1): an outage longer than the old fixed 60 s grace (scaled: past
    /// the 300 ms carry window) but within the command's own timeout no longer
    /// ends a running command: it is adopted and SUCCEEDS.
    #[test]
    fn c12_an_outage_past_the_window_within_the_command_timeout_succeeds() {
        let (state, code) = command_across_an_outage(
            sandbox_runtime::FakeRuntime::with_command_delay(Duration::from_millis(2500)),
            ",300ms,30s,,",
            timed_command(60_000),
            Duration::from_millis(1200),
        );
        assert_eq!(state, OperationState::Succeeded, "{code:?}");
    }

    /// C13 (D2): an outage past `max_carry` stops the running command through
    /// the cancel proof path; a proven stop settles FAILED
    /// `host_disconnect_expired`.
    #[test]
    fn c13_an_outage_past_max_carry_settles_host_disconnect_expired() {
        let (state, code) = command_across_an_outage(
            sandbox_runtime::FakeRuntime::with_command_delay(Duration::from_secs(30))
                .with_proven_command_cancel(),
            ",300ms,1s,,",
            timed_command(60_000),
            Duration::from_millis(2500),
        );
        assert_eq!(state, OperationState::Failed);
        assert!(
            code.as_ref()
                .is_some_and(|code| code.is(SandboxErrorCode::HostDisconnectExpired)),
            "{code:?}"
        );
    }

    /// D2: without proof of the stop the cap never claims an outcome.
    #[test]
    fn c13_an_unproven_stop_at_max_carry_stays_unknown() {
        let dir = tempfile::tempdir().expect("dir");
        let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
        let fake = sandbox_runtime::FakeRuntime::with_command_delay(Duration::from_secs(30));
        seed(&listener, dir.path(), &fake);
        let options = options(&listener, dir.path(), Duration::from_secs(5));
        let shutdown = options.shutdown.clone();
        let daemon = spawn_carry_daemon(options, fake, ",300ms,1s,,");
        let mut wire = accept(&listener);
        register(&mut wire, 1);
        crate::sandbox_relay::test_support::ack_registration(&mut wire);
        send(&mut wire, timed_command(60_000));
        until(&mut wire, |m| accepted(m, "cmd"));
        reset(wire);
        thread::sleep(Duration::from_millis(2500));
        let mut wire = accept(&listener);
        register(&mut wire, 2);
        let seen = reconcile(&mut wire, |_| true);
        let state = seen
            .receipts
            .iter()
            .find(|(id, _)| id == "cmd")
            .map(|(_, state)| *state)
            .unwrap_or_else(|| {
                let done = until(&mut wire, |m| result_of(m, "cmd").is_some());
                result_of(&done, "cmd").expect("result")
            });
        assert_eq!(state, OperationState::UnknownOutcome);
        finish(daemon, shutdown);
        drop(wire);
    }

    /// C13 (D3): an outage past the command's own timeout ends it with its
    /// natural `timeout`, not the carry code.
    #[test]
    fn c13_an_outage_past_the_command_timeout_keeps_timeout() {
        let (state, code) = command_across_an_outage(
            sandbox_runtime::FakeRuntime::with_command_delay(Duration::from_secs(30))
                .with_proven_command_cancel(),
            ",300ms,30s,,",
            timed_command(800),
            Duration::from_millis(2000),
        );
        assert_eq!(state, OperationState::Failed);
        assert!(
            code.as_ref()
                .is_some_and(|code| code.is(SandboxErrorCode::Timeout)),
            "{code:?}"
        );
    }

    /// A reconnect that adopts the command but drops during the
    /// census is the same outage. Repeating that never restarts the carry clock:
    /// the command is still stopped at `max_carry` from the first drop.
    #[test]
    fn c13_adopt_then_drop_during_census_never_restarts_max_carry() {
        let dir = tempfile::tempdir().expect("dir");
        let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
        let fake = sandbox_runtime::FakeRuntime::with_command_delay(Duration::from_secs(60))
            .with_proven_command_cancel();
        seed(&listener, dir.path(), &fake);
        let options = options(&listener, dir.path(), Duration::from_secs(5));
        let shutdown = options.shutdown.clone();
        // Each flap cycle (reconnect wait <= 1 s plus reconciliation) is shorter
        // than the 3 s cap, so a clock restarted by adoption would never fire.
        let daemon = spawn_carry_daemon(options, fake, ",300ms,3s,,");
        let mut wire = accept(&listener);
        register(&mut wire, 1);
        crate::sandbox_relay::test_support::ack_registration(&mut wire);
        send(&mut wire, timed_command(0));
        until(&mut wire, |m| accepted(m, "cmd"));
        let first_drop = Instant::now();
        reset(wire);
        let mut epoch = 2;
        while first_drop.elapsed() < Duration::from_millis(4500) {
            let mut wire = accept(&listener);
            register(&mut wire, epoch);
            epoch += 1;
            adopt_then_drop_at_census(wire);
        }
        let mut wire = accept(&listener);
        register(&mut wire, epoch);
        let (state, code) = settle_after_reconnect(&mut wire);
        assert_eq!(state, OperationState::Failed, "{code:?}");
        assert!(
            code.as_ref()
                .is_some_and(|code| code.is(SandboxErrorCode::HostDisconnectExpired)),
            "{code:?}"
        );
        finish(daemon, shutdown);
        drop(wire);
    }

    /// A queued command revoked by the carry window while every
    /// lane is busy is journaled FAILED `host_effect_not_issued` at once, so a
    /// reconnect before its worker runs settles it as never issued, not UNKNOWN.
    #[test]
    fn window_revoked_queued_work_settles_not_issued_before_its_worker_runs() {
        let (dir, mut wire, seen, daemon, shutdown) = queued_behind_a_drop(
            |_| true,
            Some(Duration::from_millis(300)),
            Duration::from_secs(20),
            Duration::from_millis(1500),
        );
        let adopted: Vec<_> = seen.adopted.iter().map(|(id, ..)| id.as_str()).collect();
        assert_eq!(adopted, ["cmd1"], "the running command is still carried");
        let cmd2 = seen
            .receipts
            .iter()
            .find(|(id, _)| id == "cmd2")
            .map(|(_, state)| *state)
            .unwrap_or_else(|| {
                match until(&mut wire, |m| {
                    matches!(m, DaemonControlMessage::OperationReceipt { operation_id, .. }
                    if operation_id == "cmd2")
                }) {
                    DaemonControlMessage::OperationReceipt { state, .. } => state,
                    _ => unreachable!(),
                }
            });
        assert_eq!(cmd2, OperationState::Failed, "{seen:?}");
        let receipt = journal_receipt(dir.path(), "cmd2").expect("cmd2 receipt");
        assert_eq!(
            receipt["errorCode"],
            json!("host_effect_not_issued"),
            "{receipt}"
        );
        finish(daemon, shutdown);
        drop(wire);
    }

    /// fu-a (integration review P2a): the stale queued worker of an attempt
    /// the carry window settled not-issued wakes only after the server
    /// confirmed that settlement and redispatched the operation as attempt
    /// 2. Its refusal must not overwrite attempt 2's receipt (the write is
    /// fenced on generation and attempt): attempt 2 runs and succeeds.
    #[test]
    fn a_stale_settled_worker_never_overwrites_the_redispatched_attempt() {
        let (dir, mut wire, seen, daemon, shutdown) = queued_behind_a_drop(
            |_| true,
            Some(Duration::from_millis(300)),
            Duration::from_secs(3),
            Duration::from_millis(1000),
        );
        if !seen.receipts.iter().any(|(id, _)| id == "cmd2") {
            until(&mut wire, |m| {
                matches!(m, DaemonControlMessage::OperationReceipt { operation_id, .. }
                    if operation_id == "cmd2")
            });
        }
        let settled = journal_receipt(dir.path(), "cmd2").expect("cmd2 receipt");
        assert_eq!(settled["errorCode"], json!("host_effect_not_issued"));
        // The server confirms the settlement and redispatches as attempt 2,
        // while attempt 1's job is still queued behind the running cmd1.
        send(
            &mut wire,
            json!({"sandboxOwnerId":"owner", "type":"receipt.confirmed", "operationId":"cmd2",
                "sandboxId":"sbx", "generation":1, "attempt":1, "bodyHash":"a".repeat(64),
                "idempotencyKey":"cmd2", "kind":"command.run"}),
        );
        let confirmed = Instant::now();
        while journal_receipt(dir.path(), "cmd2").is_some() {
            assert!(
                confirmed.elapsed() < Duration::from_secs(5),
                "the confirmation retires the settled receipt"
            );
            thread::sleep(Duration::from_millis(20));
        }
        let mut redispatch = command("cmd2");
        redispatch["attempt"] = json!(2);
        send(&mut wire, redispatch);
        let deadline = Instant::now() + Duration::from_secs(30);
        let (attempt, state) = loop {
            assert!(Instant::now() < deadline, "no result for attempt 2");
            let Message::Text(text) = wire.read().expect("frame") else {
                continue;
            };
            match parse_daemon_control(&text).expect("control") {
                DaemonControlMessage::Heartbeat { id, .. } => pong(&mut wire, &id),
                DaemonControlMessage::OperationResult {
                    operation_id,
                    attempt,
                    state,
                    ..
                } if operation_id == "cmd2" => break (attempt, state),
                _ => {}
            }
        };
        assert_eq!(
            (attempt, state),
            (2, OperationState::Succeeded),
            "attempt 2 ran"
        );
        let receipt = journal_receipt(dir.path(), "cmd2").expect("attempt 2 receipt");
        assert_eq!(receipt["attempt"], json!(2), "{receipt}");
        assert_eq!(receipt["state"], json!("succeeded"), "{receipt}");
        finish(daemon, shutdown);
        drop(wire);
    }

    /// The server adopts the running command, then the census
    /// stalls past `max_carry` (counted from the first drop) before the session
    /// registers. The adopted command is still stopped at the cap.
    #[test]
    fn c13_a_census_stalled_past_max_carry_still_stops_the_adopted_command() {
        let dir = tempfile::tempdir().expect("dir");
        let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
        let fake = sandbox_runtime::FakeRuntime::with_command_delay(Duration::from_secs(60))
            .with_proven_command_cancel();
        seed(&listener, dir.path(), &fake);
        let options = options(&listener, dir.path(), Duration::from_secs(5));
        let shutdown = options.shutdown.clone();
        let daemon = spawn_carry_daemon(options, fake, ",300ms,2s,,");
        let mut wire = accept(&listener);
        register(&mut wire, 1);
        crate::sandbox_relay::test_support::ack_registration(&mut wire);
        send(&mut wire, timed_command(600_000));
        until(&mut wire, |m| accepted(m, "cmd"));
        reset(wire);
        let mut wire = accept(&listener);
        register(&mut wire, 2);
        let (state, code) = settle_after_reconnect_stalling(&mut wire, Duration::from_secs(4));
        assert_eq!(state, OperationState::Failed, "{code:?}");
        assert!(
            code.as_ref()
                .is_some_and(|code| code.is(SandboxErrorCode::HostDisconnectExpired)),
            "{code:?}"
        );
        finish(daemon, shutdown);
        drop(wire);
    }
}

/// WP2 item 4 / D11: an unresolved create whose runtime query stalls is
/// deferred, never fatal. The session reconciles on (the census skips its
/// sandbox), `reconcile.complete` names it in `pendingReceipts` so the server
/// publishes no interim unknown outcome, and once the query finishes the
/// dispatch loop delivers its receipt, which the server confirms, in the
/// same session.
#[test]
fn wp2_a_stalled_receipt_query_is_deferred_and_delivered_in_the_same_session() {
    use std::sync::{Mutex, mpsc};
    let dir = tempfile::tempdir().expect("dir");
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let (release, gate) = mpsc::channel::<()>();
    let gate = Arc::new(Mutex::new(Some(gate)));
    let stages = Arc::new(Mutex::new(Vec::<String>::new()));
    let fake = {
        let (gate, stages) = (gate.clone(), stages.clone());
        sandbox_runtime::FakeRuntime::new()
            .with_query_hook(move |sandbox_id| {
                if sandbox_id == "stall"
                    && let Some(gate) = gate.lock().unwrap().take()
                {
                    let _ = gate.recv();
                }
                Ok(())
            })
            .with_inventory_hook(move |stage| {
                stages.lock().unwrap().push(stage.to_owned());
                Ok(())
            })
    };
    seed(&listener, dir.path(), &fake);
    fake.create_fixture(&sandbox_runtime::CreateSandboxRequest::for_test(
        "stall",
        "stalled-create",
    ))
    .unwrap();
    // An interrupted create of `stall` (its VM exists): Effect with a durable
    // lease, so the reconnect resolves it from a runtime query.
    {
        let binding = TransportBindingV11 {
            server: format!("ws://{}/ws/sandbox-host", listener.local_addr().unwrap()),
            host_owner_id: "owner-1".into(),
            host_id: "host".into(),
        };
        let journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap();
        let d: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner",
            "operationId":"stalled-create", "sandboxId":"stall", "kind":"sandbox.create",
            "allocation": crate::sandbox_relay::test_support::allocation(), "cpuCount": 1,
            "memoryMiB": 1024, "generation":1, "attempt":1, "idempotencyKey":"stalled-create",
            "incusFingerprint":sandbox_runtime::CreateSandboxRequest::for_test("stall", "stalled-create").template_digest,
            "bodyHash":"a".repeat(64), "lease":sandbox_protocol::HostLease::for_test()}))
        .unwrap();
        journal
            .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &d))
            .unwrap();
        journal.accept_fixture_lease(&d).unwrap();
        journal.record_effect("stalled-create").unwrap();
    }
    let options = options(&listener, dir.path(), Duration::from_secs(5));
    let shutdown = options.shutdown.clone();
    let daemon = thread::spawn(move || {
        RESOLUTION_WAIT_OVERRIDE.with(|cell| cell.set(Some(Duration::from_millis(300))));
        run_connect_with(&options, |_| Ok((Box::new(fake), None)))
    });

    let mut wire = accept(&listener);
    loop {
        if let Message::Text(text) = wire.read().expect("hello")
            && matches!(
                parse_daemon_control(&text).expect("control"),
                DaemonControlMessage::Hello { .. }
            )
        {
            break;
        }
    }
    let mut ok: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../crates/sandbox-protocol/fixtures/control_hello_ok_server.json"
    ))
    .unwrap();
    ok["connectionEpoch"] = json!(1);
    ok["capabilities"]["pendingReceipts"] = json!(true);
    send(&mut wire, ok);
    let started = Instant::now();
    let mut receipts = Vec::new();
    let pending = loop {
        let Message::Text(text) = wire.read().expect("reconciliation frame") else {
            continue;
        };
        match parse_daemon_control(&text).expect("control") {
            DaemonControlMessage::OperationReceipt { operation_id, .. } => {
                send(
                    &mut wire,
                    json!({"type":"receipt.ack","operationId":operation_id}),
                );
                receipts.push(operation_id);
            }
            DaemonControlMessage::SandboxInventory { page, entries, .. } => {
                send(
                    &mut wire,
                    json!({"type":"inventory.ack","page":page,"entryResults": entries.iter().map(|entry| json!({"sandboxId":entry.sandbox_id,"outcome":"converged"})).collect::<Vec<_>>()}),
                );
            }
            DaemonControlMessage::Heartbeat { id, .. } => pong(&mut wire, &id),
            DaemonControlMessage::ReconcileComplete { pending_receipts } => {
                break pending_receipts;
            }
            _ => {}
        }
    };
    assert_eq!(
        pending,
        Some(vec!["stalled-create".to_owned()]),
        "the deferred create is named, so the server settles nothing yet"
    );
    assert!(
        !receipts.contains(&"stalled-create".to_owned()),
        "no receipt for a still-resolving create: {receipts:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "reconciliation went on after the wait"
    );
    assert!(
        stages
            .lock()
            .unwrap()
            .iter()
            .any(|stage| stage.starts_with("inventory-skipping:") && stage.contains("stall")),
        "the census never waits on the resolving sandbox: {:?}",
        stages.lock().unwrap()
    );
    assert!(
        !daemon.is_finished(),
        "a stalled query never ends the session"
    );
    // The query finishes: the receipt arrives on this session and the
    // server confirms it, which clears it from the journal.
    release.send(()).unwrap();
    let delivered = until(
        &mut wire,
        |m| matches!(m, DaemonControlMessage::OperationReceipt { operation_id, .. } if operation_id == "stalled-create"),
    );
    let DaemonControlMessage::OperationReceipt {
        sandbox_owner_id,
        operation_id,
        sandbox_id,
        generation,
        attempt,
        body_hash,
        idempotency_key,
        kind,
        state,
        ..
    } = delivered
    else {
        unreachable!()
    };
    assert_eq!(
        state,
        OperationState::Succeeded,
        "resolved from the runtime"
    );
    send(
        &mut wire,
        json!({"sandboxOwnerId":sandbox_owner_id, "type":"receipt.confirmed",
            "operationId":operation_id, "sandboxId":sandbox_id, "generation":generation,
            "attempt":attempt, "bodyHash":body_hash, "idempotencyKey":idempotency_key,
            "kind":kind}),
    );
    send(
        &mut wire,
        json!({"type":"receipt.ack","operationId":"stalled-create"}),
    );
    let confirmed = Instant::now();
    while journal_receipt(dir.path(), "stalled-create").is_some() {
        assert!(
            confirmed.elapsed() < Duration::from_secs(10),
            "the confirmation clears the delivered receipt"
        );
        // Keep the session served (heartbeats) while the daemon applies it.
        let _ = until(&mut wire, |m| {
            matches!(m, DaemonControlMessage::Heartbeat { .. })
                || matches!(m, DaemonControlMessage::HostTerminalPolicy(_))
                || matches!(m, DaemonControlMessage::HostEgressState(_))
        });
    }
    assert!(!daemon.is_finished(), "delivered within the same session");
    finish(daemon, shutdown);
    drop(wire);
}

/// WP2 section 9 end to end (Codex review-integ3 #1 and #2): with
/// `expiryStatusResults` negotiated, a census entry the server refused for
/// stale storage (here a plain running sandbox with an unexpired lease, no
/// expiry arm) is offered again on the connected channel under the next
/// storage observation. A connected offer refused for stale storage is
/// offered again only under a newer observation; once judged converged it
/// is never sent again (no busy loop).
#[test]
fn wp2_refused_evidence_is_reoffered_under_newer_observations_until_converged() {
    let dir = tempfile::tempdir().expect("dir");
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let fake = sandbox_runtime::FakeRuntime::new();
    seed(&listener, dir.path(), &fake);
    let clock = Arc::new(SteppedClock {
        wall: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        elapsed: std::sync::atomic::AtomicU64::new(0),
    });
    let options = options(&listener, dir.path(), Duration::from_secs(1));
    let shutdown = options.shutdown.clone();
    let daemon = {
        let clock = Arc::new(crate::sandbox_relay::clock::LeaseClock::new(clock.clone()));
        thread::spawn(move || {
            REPORT_CLOCK_OVERRIDE.with(|cell| *cell.borrow_mut() = Some(clock));
            // Offered by this release; pinned so the test never depends on it.
            run_connect_with(&options, |_| Ok((Box::new(fake), None)))
        })
    };
    let mut wire = accept(&listener);
    loop {
        if let Message::Text(text) = wire.read().expect("hello")
            && matches!(
                parse_daemon_control(&text).expect("control"),
                DaemonControlMessage::Hello { .. }
            )
        {
            assert!(text.contains("\"expiryStatusResults\":true"), "opted in");
            assert!(text.contains("\"observationFence\":true"), "with its fence");
            break;
        }
    }
    let mut ok: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../crates/sandbox-protocol/fixtures/control_hello_ok_server.json"
    ))
    .unwrap();
    ok["connectionEpoch"] = json!(1);
    ok["capabilities"]["censusEntryResults"] = json!(true);
    ok["capabilities"]["expiryStatusResults"] = json!(true);
    ok["capabilities"]["observationFence"] = json!(true);
    send(&mut wire, ok);
    // Storage sequence of the last `inventory.update` seen.
    let mut sequence = 0u64;
    let note = |message: &DaemonControlMessage, sequence: &mut u64| {
        if let DaemonControlMessage::InventoryUpdate {
            observation_sequence,
            ..
        } = message
        {
            *sequence = (*sequence).max(*observation_sequence);
        }
    };
    loop {
        let Message::Text(text) = wire.read().expect("reconciliation frame") else {
            continue;
        };
        let message = parse_daemon_control(&text).expect("control");
        note(&message, &mut sequence);
        match message {
            DaemonControlMessage::OperationReceipt { operation_id, .. } => send(
                &mut wire,
                json!({"type":"receipt.ack","operationId":operation_id}),
            ),
            DaemonControlMessage::SandboxInventory { page, entries, .. } => {
                assert!(entries.iter().any(|e| e.sandbox_id == "sbx"));
                let results: Vec<_> = entries
                    .iter()
                    .map(|e| {
                        json!({"sandboxId":e.sandbox_id, "outcome":
                            if e.sandbox_id == "sbx" { "stale_storage" } else { "converged" }})
                    })
                    .collect();
                send(
                    &mut wire,
                    json!({"type":"inventory.ack","page":page,"entryResults":results}),
                );
            }
            DaemonControlMessage::Heartbeat { id, .. } => pong(&mut wire, &id),
            DaemonControlMessage::ReconcileComplete { .. } => break,
            _ => {}
        }
    }
    // Reads (stepping the report clock) until an expiry-status batch arrives
    // or `updates` storage reports went by without one.
    let next_offer = |wire: &mut Wire, sequence: &mut u64, updates: usize| {
        let mut seen = 0;
        let started = Instant::now();
        loop {
            assert!(started.elapsed() < Duration::from_secs(30), "stalled");
            clock.advance(Duration::from_millis(500));
            let message = loop {
                assert!(started.elapsed() < Duration::from_secs(30), "stalled");
                let Message::Text(text) = wire.read().expect("frame") else {
                    continue;
                };
                let message = parse_daemon_control(&text).expect("control");
                match &message {
                    DaemonControlMessage::Heartbeat { id, .. } => {
                        pong(wire, id);
                        clock.advance(Duration::from_secs(6));
                    }
                    DaemonControlMessage::InventoryUpdate { .. }
                    | DaemonControlMessage::SandboxExpiryStatus { .. } => break message,
                    _ => {}
                }
            };
            let before = *sequence;
            note(&message, sequence);
            match message {
                DaemonControlMessage::SandboxExpiryStatus {
                    entries,
                    batch,
                    observation,
                } => {
                    // One observation per offer here (a single entry).
                    assert_eq!(observation, batch, "observation numbered with its offer");
                    return Some((batch.expect("negotiated batch"), entries, before));
                }
                _ => {
                    seen += 1;
                    if seen >= updates {
                        return None;
                    }
                }
            }
        }
    };
    // #2: the stale census entry comes back under a newer observation.
    let judged_at = sequence;
    let (batch, entries, offered_at) =
        next_offer(&mut wire, &mut sequence, 10).expect("the stale census entry is re-offered");
    assert_eq!(batch, 1);
    assert_eq!(
        entries
            .iter()
            .map(|e| e.sandbox_id.as_str())
            .collect::<Vec<_>>(),
        ["sbx"]
    );
    assert!(
        !entries[0].lease.as_ref().unwrap().expired,
        "an entry without an expiry arm"
    );
    assert!(offered_at > judged_at, "only under a newer observation");
    // #1: refused again for stale storage: offered again, once per newer
    // observation.
    send(
        &mut wire,
        json!({"type":"sandbox.expiry_status.ack","batch":1,
            "entryResults":[{"sandboxId":"sbx","outcome":"stale_storage"}]}),
    );
    let refused_at = sequence;
    let (batch, entries, offered_at) =
        next_offer(&mut wire, &mut sequence, 10).expect("re-offered after a stale refusal");
    assert_eq!(batch, 2);
    assert_eq!(entries[0].sandbox_id, "sbx");
    assert!(offered_at > refused_at, "keyed by observation sequence");
    send(
        &mut wire,
        json!({"type":"sandbox.expiry_status.ack","batch":2,
            "entryResults":[{"sandboxId":"sbx","outcome":"converged"}]}),
    );
    // Converged: never offered again, however many observations follow.
    assert!(
        next_offer(&mut wire, &mut sequence, 4).is_none(),
        "converged evidence is never re-sent"
    );
    assert!(!daemon.is_finished());
    finish(daemon, shutdown);
    drop(wire);
}

/// WP2 follow-up: this release offers `expiryStatusResults` together with
/// `observationFence`, and uses the judged path only when the server answers
/// both. A server that answers `expiryStatusResults` alone (it judges
/// unfenced: Codex WP2 r3 P1), or an answer to an offer never made, keeps
/// the older path (no batch), which judges only expired arms.

#[test]
fn a_command_finishing_during_the_quiesce_drain_delivers_its_output_and_result_first() {
    let dir = tempfile::tempdir().expect("dir");
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let fake = sandbox_runtime::FakeRuntime::with_command_delay(Duration::from_millis(1500));
    seed(&listener, dir.path(), &fake);
    let options = options(&listener, dir.path(), Duration::from_secs(5));
    let shutdown = options.shutdown.clone();
    // As the SIGUSR1 handler registration does.
    shutdown.quiesce().enable();
    let daemon = spawn_daemon(options, fake, None);
    let mut wire = accept(&listener);
    loop {
        if let Message::Text(text) = wire.read().expect("hello")
            && matches!(
                parse_daemon_control(&text).expect("control"),
                DaemonControlMessage::Hello { .. }
            )
        {
            break;
        }
    }
    let mut ok: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../crates/sandbox-protocol/fixtures/control_hello_ok_server.json"
    ))
    .unwrap();
    ok["connectionEpoch"] = json!(1);
    ok["capabilities"]["quiesce"] = json!(true);
    send(&mut wire, ok);
    crate::sandbox_relay::test_support::ack_registration(&mut wire);
    send(&mut wire, command("cmd"));
    let dispatched = Instant::now();
    until(&mut wire, |m| accepted(m, "cmd"));
    // `wssp host daemon quiesce`.
    assert!(shutdown.quiesce().request());
    // Output is acknowledged only after the command exited (1.5 s) and the
    // old drain had already judged "nothing running" (ack + 1 s settle,
    // 250 ms polls): the completion waits behind its output drain.
    let ack_after = dispatched + Duration::from_millis(2200);
    let mut bytes = std::collections::BTreeMap::new();
    let (state, result) = loop {
        let frame = wire
            .read()
            .expect("the daemon stays until the result is published");
        match frame {
            Message::Binary(data) => {
                let (metadata, body) = sandbox_protocol::parse_binary_frame(&data).unwrap();
                if metadata.operation_id == "cmd" {
                    bytes.insert(metadata.offset.unwrap_or(0), body.len() as u64);
                    if Instant::now() >= ack_after {
                        send(
                            &mut wire,
                            json!({"type":"command.output.ack","operationId":"cmd",
                                "generation":1,"attempt":1,"sequence":metadata.sequence,
                                "offset":metadata.offset.unwrap_or(0) + body.len() as u64}),
                        );
                    }
                }
            }
            Message::Text(text) => match parse_daemon_control(&text).unwrap() {
                DaemonControlMessage::Heartbeat { id, .. } => pong(&mut wire, &id),
                DaemonControlMessage::HostQuiesce(quiesce) => send(
                    &mut wire,
                    json!({"type":"host.quiesce.ack","sequence":quiesce.sequence}),
                ),
                DaemonControlMessage::OperationResult {
                    operation_id,
                    state,
                    result,
                    ..
                } if operation_id == "cmd" => break (state, result),
                _ => {}
            },
            Message::Close(_) => panic!("the daemon closed before publishing the result"),
            _ => {}
        }
    };
    assert_eq!(state, OperationState::Succeeded);
    let total = result
        .as_ref()
        .and_then(|r| r["outputBytes"].as_u64())
        .unwrap();
    assert!(total > 0);
    let mut covered = 0;
    for (offset, len) in &bytes {
        assert!(*offset <= covered, "no gap at {offset}");
        covered = covered.max(offset + len);
    }
    assert_eq!(covered, total, "every output byte was delivered");
    let DaemonControlMessage::OperationReceipt {
        sandbox_owner_id,
        operation_id,
        sandbox_id,
        generation,
        attempt,
        body_hash,
        idempotency_key,
        kind,
        ..
    } = until(
        &mut wire,
        |m| matches!(m, DaemonControlMessage::OperationReceipt { operation_id, .. } if operation_id == "cmd"),
    )
    else {
        unreachable!()
    };
    // Published but unconfirmed: the daemon keeps the session (well past a
    // settle and a poll) until the server confirms the result.
    let held = Instant::now() + Duration::from_millis(1500);
    wire.get_mut()
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    while Instant::now() < held {
        match wire.read() {
            Ok(Message::Close(_)) => panic!("the daemon left before the confirmation"),
            Ok(Message::Text(text)) => {
                if let Ok(DaemonControlMessage::Heartbeat { id, .. }) = parse_daemon_control(&text)
                {
                    pong(&mut wire, &id);
                }
            }
            Ok(_) => {}
            Err(tungstenite::Error::Io(error))
                if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(error) => panic!("the daemon left before the confirmation: {error}"),
        }
    }
    assert!(!daemon.is_finished(), "still draining the confirmation");
    wire.get_mut()
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    send(
        &mut wire,
        json!({"sandboxOwnerId":sandbox_owner_id, "type":"receipt.confirmed",
            "operationId":operation_id, "sandboxId":sandbox_id, "generation":generation,
            "attempt":attempt, "bodyHash":body_hash, "idempotencyKey":idempotency_key,
            "kind":kind}),
    );
    // Drained: the daemon restarts (a normal close, exit 0).
    loop {
        match wire.read() {
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(Message::Text(text)) => {
                if let Ok(DaemonControlMessage::Heartbeat { id, .. }) = parse_daemon_control(&text)
                {
                    pong(&mut wire, &id);
                }
            }
            Ok(_) => {}
        }
    }
    daemon
        .join()
        .expect("join")
        .expect("a quiesced daemon exits cleanly");
    assert!(
        shutdown.requested(),
        "the drain ended in the normal shutdown"
    );
}

/// fu-a: a daemon whose `cmd` (0.5 s) finished, its output and result
/// still unpublished (output ACKs held back), when the shutdown signal
/// arrives. Returns the wire, the daemon, its shutdown handle, the output
/// frames seen so far `(offset → (len, sequence))` and the runtime (shared
/// state).
#[allow(clippy::type_complexity)]
fn finished_before_shutdown() -> (
    tempfile::TempDir,
    Wire,
    thread::JoinHandle<Result<()>>,
    ShutdownSignal,
    std::collections::BTreeMap<u64, (u64, u64)>,
    sandbox_runtime::FakeRuntime,
) {
    let dir = tempfile::tempdir().expect("dir");
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let fake = sandbox_runtime::FakeRuntime::with_command_delay(Duration::from_millis(500));
    seed(&listener, dir.path(), &fake);
    let options = options(&listener, dir.path(), Duration::from_secs(5));
    let shutdown = options.shutdown.clone();
    let daemon = spawn_daemon(options, fake.clone(), None);
    let mut wire = accept(&listener);
    register(&mut wire, 1);
    crate::sandbox_relay::test_support::ack_registration(&mut wire);
    send(&mut wire, command("cmd"));
    let dispatched = Instant::now();
    let mut bytes = std::collections::BTreeMap::new();
    // fu-d3: read (never ACK) until the command has exited (its result is
    // journaled) and its output was seen: an explicit condition, not a
    // wall-clock guess that a loaded machine can miss.
    wire.get_mut()
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let finished = || {
        journal_receipt(dir.path(), "cmd")
            .is_some_and(|receipt| receipt["state"].as_str() == Some("succeeded"))
    };
    while bytes.is_empty() || !finished() {
        assert!(
            dispatched.elapsed() < Duration::from_secs(30),
            "the command never finished"
        );
        match wire.read() {
            Ok(Message::Binary(data)) => {
                let (metadata, body) = sandbox_protocol::parse_binary_frame(&data).unwrap();
                bytes.insert(
                    metadata.offset.unwrap_or(0),
                    (body.len() as u64, metadata.sequence),
                );
            }
            Ok(Message::Text(text)) => match parse_daemon_control(&text).unwrap() {
                DaemonControlMessage::Heartbeat { id, .. } => pong(&mut wire, &id),
                DaemonControlMessage::OperationResult { operation_id, .. } => {
                    panic!("{operation_id} published behind unacknowledged output")
                }
                _ => {}
            },
            Ok(_) => {}
            Err(tungstenite::Error::Io(error))
                if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(error) => panic!("read: {error}"),
        }
    }
    wire.get_mut()
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    shutdown.request();
    (dir, wire, daemon, shutdown, bytes, fake)
}

/// fu-a: SIGTERM (every upgrade and `systemctl restart`) right after a
/// command finished, its output ACKs held back. The shutdown flush keeps the
/// session open: the output arrives intact, the result is published and
/// confirmed, then the socket closes normally. Before, the close came at
/// once and the next daemon's bare receipt settled it without stdout.
#[test]
fn a_command_finished_just_before_shutdown_delivers_its_output_and_result_first() {
    let (dir, mut wire, daemon, _shutdown, mut bytes, _fake) = finished_before_shutdown();
    // fu-d3: the flush is acknowledged at once from what was already
    // delivered, not from a resend (whose backoff may reach 2 s and, on a
    // loaded machine, land past the flush): every further step (more
    // output, the result, its receipt) follows the ACKs without a timer.
    let mut acked = 0;
    for (offset, (len, sequence)) in &bytes {
        if *offset > acked {
            break;
        }
        acked = acked.max(offset + len);
        send(
            &mut wire,
            json!({"type":"command.output.ack","operationId":"cmd","generation":1,
                "attempt":1,"sequence":sequence,"offset":offset + len}),
        );
    }
    let mut confirmed = false;
    let mut result = None;
    loop {
        match wire.read() {
            Ok(Message::Binary(data)) => {
                let (metadata, body) = sandbox_protocol::parse_binary_frame(&data).unwrap();
                bytes.insert(
                    metadata.offset.unwrap_or(0),
                    (body.len() as u64, metadata.sequence),
                );
                send(
                    &mut wire,
                    json!({"type":"command.output.ack","operationId":"cmd","generation":1,
                        "attempt":1,"sequence":metadata.sequence,
                        "offset":metadata.offset.unwrap_or(0) + body.len() as u64}),
                );
            }
            Ok(Message::Text(text)) => match parse_daemon_control(&text).unwrap() {
                DaemonControlMessage::Heartbeat { id, .. } => pong(&mut wire, &id),
                DaemonControlMessage::OperationResult {
                    operation_id,
                    state,
                    result: payload,
                    ..
                } if operation_id == "cmd" => result = Some((state, payload)),
                DaemonControlMessage::OperationReceipt {
                    sandbox_owner_id,
                    operation_id,
                    sandbox_id,
                    generation,
                    attempt,
                    body_hash,
                    idempotency_key,
                    kind,
                    ..
                } if operation_id == "cmd" => {
                    assert!(result.is_some(), "the result precedes its receipt");
                    send(
                        &mut wire,
                        json!({"sandboxOwnerId":sandbox_owner_id, "type":"receipt.confirmed",
                            "operationId":operation_id, "sandboxId":sandbox_id,
                            "generation":generation, "attempt":attempt, "bodyHash":body_hash,
                            "idempotencyKey":idempotency_key, "kind":kind}),
                    );
                    confirmed = true;
                }
                _ => {}
            },
            Ok(Message::Close(frame)) => {
                assert_eq!(
                    frame.map(|f| u16::from(f.code)),
                    Some(1000),
                    "a normal close"
                );
                break;
            }
            Ok(_) => {}
            Err(error) => panic!("the daemon left without a close: {error}"),
        }
    }
    assert!(
        confirmed,
        "the daemon closed before its result was confirmed"
    );
    let (state, payload) = result.expect("result published before the close");
    assert_eq!(state, OperationState::Succeeded);
    let total = payload
        .as_ref()
        .and_then(|r| r["outputBytes"].as_u64())
        .unwrap();
    let mut covered = 0;
    for (offset, (len, _)) in &bytes {
        assert!(*offset <= covered, "no gap at {offset}");
        covered = covered.max(offset + len);
    }
    assert_eq!(covered, total, "every output byte was delivered");
    daemon.join().expect("join").expect("a clean shutdown");
    // Confirmed: nothing is left for the next daemon to replay.
    assert!(journal_receipt(dir.path(), "cmd").is_none());
}

/// fu-a: the shutdown flush is bounded. A server that never ACKs or
/// confirms gets the normal close after SHUTDOWN_FLUSH, and the journaled
/// result stays for the next daemon's receipt replay.
#[test]
fn a_hung_server_cannot_hold_the_shutdown_flush_past_its_bound() {
    let (dir, mut wire, daemon, _shutdown, _bytes, _fake) = finished_before_shutdown();
    let requested = Instant::now();
    loop {
        match wire.read() {
            Ok(Message::Close(frame)) => {
                assert_eq!(frame.map(|f| u16::from(f.code)), Some(1000));
                break;
            }
            Ok(_) => {}
            Err(error) => panic!("the daemon left without a close: {error}"),
        }
    }
    daemon.join().expect("join").expect("a clean shutdown");
    let elapsed = requested.elapsed();
    assert!(
        elapsed >= SHUTDOWN_FLUSH - Duration::from_millis(500),
        "it waited for the pending result: {elapsed:?}"
    );
    assert!(
        elapsed < SHUTDOWN_FLUSH + Duration::from_secs(3),
        "bounded by the flush: {elapsed:?}"
    );
    assert!(
        journal_receipt(dir.path(), "cmd").is_some(),
        "the unconfirmed result stays journaled"
    );
}

/// fu-a: with nothing pending the shutdown closes at once (no flush).
#[test]
fn a_shutdown_with_nothing_pending_closes_at_once() {
    let dir = tempfile::tempdir().expect("dir");
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let fake = sandbox_runtime::FakeRuntime::new();
    seed(&listener, dir.path(), &fake);
    let options = options(&listener, dir.path(), Duration::from_secs(5));
    let shutdown = options.shutdown.clone();
    let daemon = spawn_daemon(options, fake, None);
    let mut wire = accept(&listener);
    register(&mut wire, 1);
    crate::sandbox_relay::test_support::ack_registration(&mut wire);
    let requested = Instant::now();
    shutdown.request();
    while !matches!(wire.read(), Ok(Message::Close(_)) | Err(_)) {}
    daemon.join().expect("join").expect("a clean shutdown");
    assert!(
        requested.elapsed() < Duration::from_secs(2),
        "{:?}",
        requested.elapsed()
    );
}

/// fu-a: a close 4003 that arrives during the shutdown flush keeps its
/// meaning: the process ends with the credential failure, and a revocation
/// verdict is latched durably.
#[test]
fn a_credential_close_during_the_shutdown_flush_is_still_a_revocation() {
    let (dir, mut wire, daemon, _shutdown, _bytes, fake) = finished_before_shutdown();
    wire.close(Some(tungstenite::protocol::CloseFrame {
        code: tungstenite::protocol::frame::coding::CloseCode::Library(4003),
        reason: "credential_revoked".into(),
    }))
    .expect("close");
    while wire.read().is_ok() {}
    let error = daemon
        .join()
        .expect("join")
        .expect_err("credential failure");
    assert_eq!(crate::exit::code_for(&error), ExitCode::CredentialInactive);
    assert!(super::super::revocation::is_authority_revocation(&error));
    fn find(dir: &std::path::Path) -> bool {
        std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .any(|entry| {
                let path = entry.path();
                path.ends_with("AUTHORITY-REVOKED") || (path.is_dir() && find(&path))
            })
    }
    assert!(
        find(dir.path()),
        "the revocation is latched for the next start"
    );
    // The earlier shutdown request does not cancel the stop.
    let sbx = sandbox_runtime::SandboxRuntime::sandbox_inventory(&fake)
        .unwrap()
        .into_iter()
        .find(|entry| entry.sandbox_id == "sbx")
        .map(|entry| entry.state);
    assert!(
        matches!(
            sbx,
            None | Some(
                sandbox_protocol::SandboxLifecycleState::Stopped
                    | sandbox_protocol::SandboxLifecycleState::Absent
            )
        ),
        "the revoked guest is stopped: {sbx:?}"
    );
}

/// A peer that trickles an incomplete frame during the
/// shutdown flush cannot hold the socket past the flush bound.
#[test]
fn a_trickled_frame_cannot_hold_the_shutdown_flush_past_its_bound() {
    use std::io::Write as _;
    let (_dir, mut wire, daemon, _shutdown, _bytes, _fake) = finished_before_shutdown();
    let requested = Instant::now();
    // The flush is active: the daemon keeps resending its unacknowledged
    // output (never acknowledged here).
    wire.get_mut()
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    while requested.elapsed() < Duration::from_millis(500) {
        let _ = wire.read();
    }
    // A text frame announcing 1000 bytes, then one byte every 50 ms (each
    // well inside the daemon's per-read timeout).
    wire.get_mut().write_all(&[0x81, 126, 0x03, 0xe8]).unwrap();
    while !daemon.is_finished() && requested.elapsed() < Duration::from_secs(20) {
        if wire.get_mut().write_all(b" ").is_err() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    while !daemon.is_finished() {
        assert!(Instant::now() < deadline, "the daemon never exited");
        thread::sleep(Duration::from_millis(20));
    }
    let elapsed = requested.elapsed();
    daemon.join().expect("join").expect("a clean shutdown");
    assert!(
        elapsed < SHUTDOWN_FLUSH + Duration::from_secs(3),
        "bounded by the flush: {elapsed:?}"
    );
}

/// fu-d3: a frame already trickling when the shutdown request lands keeps
/// the session loop inside one `read`, so the loop never observes the
/// request; the request itself arms the IO bound, so the daemon still exits
/// within the flush bound instead of the 60 s outer one.
#[test]
fn a_frame_trickling_before_the_shutdown_request_is_still_bounded_by_the_flush() {
    use std::io::Write as _;
    let dir = tempfile::tempdir().expect("dir");
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let fake = sandbox_runtime::FakeRuntime::new();
    seed(&listener, dir.path(), &fake);
    let options = options(&listener, dir.path(), Duration::from_secs(5));
    let shutdown = options.shutdown.clone();
    let daemon = spawn_daemon(options, fake, None);
    let mut wire = accept(&listener);
    register(&mut wire, 1);
    crate::sandbox_relay::test_support::ack_registration(&mut wire);
    // A text frame announcing 1000 bytes, then one byte every 50 ms (each
    // well inside the daemon's per-read timeout), started before the
    // request and kept up until the daemon leaves.
    wire.get_mut().write_all(&[0x81, 126, 0x03, 0xe8]).unwrap();
    let trickling = Instant::now();
    let mut requested = None;
    while !daemon.is_finished() && trickling.elapsed() < Duration::from_secs(30) {
        if requested.is_none() && trickling.elapsed() >= Duration::from_millis(500) {
            shutdown.request();
            requested = Some(Instant::now());
        }
        if wire.get_mut().write_all(b" ").is_err() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let requested = requested.expect("the request landed mid-frame");
    let deadline = Instant::now() + Duration::from_secs(30);
    while !daemon.is_finished() {
        assert!(Instant::now() < deadline, "the daemon never exited");
        thread::sleep(Duration::from_millis(20));
    }
    let elapsed = requested.elapsed();
    daemon.join().expect("join").expect("a clean shutdown");
    assert!(
        elapsed < SHUTDOWN_FLUSH + Duration::from_secs(3),
        "bounded by the flush, not the outer deadline: {elapsed:?}"
    );
}

/// A key install (parsed with side effects: install and
/// ack) during the shutdown flush is not admitted.
#[test]
fn the_shutdown_flush_admits_no_key_or_config_install() {
    let (_dir, mut wire, daemon, _shutdown, _bytes, _fake) = finished_before_shutdown();
    let address = wire.get_ref().local_addr().unwrap();
    // Let the flush begin (the daemon resends its unacknowledged output).
    let requested = Instant::now();
    wire.get_mut()
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    while requested.elapsed() < Duration::from_millis(500) {
        let _ = wire.read();
    }
    wire.get_mut()
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    send(
        &mut wire,
        json!({"type":"journal.key.install", "connectionEpoch":1, "keyVersion":1,
            "keyId":"d".repeat(32), "keyHex":"ab".repeat(32),
            "server":format!("ws://{address}/ws/sandbox-host"),
            "hostOwnerId":"owner-1", "hostId":"host"}),
    );
    loop {
        match wire.read() {
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(Message::Text(text)) => {
                let message = parse_daemon_control(&text).unwrap();
                assert!(
                    !matches!(message, DaemonControlMessage::JournalKeyAck { .. }),
                    "a key install was acted on during the flush"
                );
            }
            Ok(_) => {}
        }
    }
    daemon.join().expect("join").expect("a clean shutdown");
}

/// A sandbox on an unlimited lease holds an UNKNOWN `command.run`
/// receipt that journaled its bound birth in the VM's current boot (its
/// daemon lost the attempt). The server answers each replay with
/// `receipt.confirmed` `retireCommand`.
/// - Without `commandRetire` in `hello.ok` the field is ignored.
/// - While the VM runs in the same boot there is no sound proof: the receipt
///   stays and nothing is signalled.
/// - Once the VM is stopped (out of band here, never by the daemon or the
///   server), the next replay retires it and the session after replays
///   nothing. The daemon never stops, kills or signals anything itself.
#[test]
fn an_unknown_command_receipt_retires_only_on_a_sound_proof_never_a_stop() {
    let dir = tempfile::tempdir().expect("dir");
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let fake = sandbox_runtime::FakeRuntime::new();
    let address = listener.local_addr().expect("address");
    fake.create_fixture(&sandbox_runtime::CreateSandboxRequest::for_test(
        "sbx", "create",
    ))
    .unwrap();
    let binding = TransportBindingV11 {
        server: format!("ws://{address}/ws/sandbox-host"),
        host_owner_id: "owner-1".into(),
        host_id: "host".into(),
    };
    {
        let journal =
            crate::sandbox_relay::test_support::open_journal(dir.path(), &binding).unwrap();
        journal.set_lease_ceiling(None);
        let mut lease = sandbox_protocol::HostLease::for_test();
        lease.deadline_unix_ms = sandbox_protocol::LEASE_UNLIMITED_DEADLINE_MS;
        let create: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner", "operationId":"create", "sandboxId":"sbx", "kind":"sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(), "cpuCount": 1, "memoryMiB": 1024, "generation":1, "attempt":1, "idempotencyKey":"create", "bodyHash":"a".repeat(64), "lease":lease})).unwrap();
        journal
            .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &create))
            .unwrap();
        journal.accept_fixture_lease(&create).unwrap();
        journal
            .record_result(
                "create",
                OperationState::Succeeded,
                Some(json!({"state":"ready","lease":create.lease})),
                None,
                None,
            )
            .unwrap();
        let mut dispatch = command("cmd");
        dispatch.as_object_mut().unwrap().remove("type");
        let dispatch: OperationDispatch = serde_json::from_value(dispatch).unwrap();
        journal
            .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &dispatch))
            .unwrap();
        journal.record_effect("cmd").unwrap();
        let mut birth: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../crates/sandbox-protocol/fixtures/process_started.json"
        ))
        .unwrap();
        birth["operationId"] = json!("cmd");
        birth["sandboxId"] = json!("sbx");
        birth["processId"] = json!("proc-cmd");
        birth["bootId"] = json!(sandbox_runtime::FAKE_BOOT_ID);
        journal
            .record_result(
                "cmd",
                OperationState::UnknownOutcome,
                Some(
                    json!({"version":1,"observedAt":birth["observedAt"],"payload":null,
                    "continuation":null,"birth":birth,
                    "failure":{"resource":"command","effect":"unknown"}}),
                ),
                Some(SandboxErrorCode::UnknownOutcome),
                None,
            )
            .unwrap();
    }
    let options = options(&listener, dir.path(), Duration::from_secs(5));
    let shutdown = options.shutdown.clone();
    let daemon = spawn_daemon(options, fake.clone(), None);
    let retire = json!({"sandboxOwnerId":"owner", "type":"receipt.confirmed", "operationId":"cmd",
        "sandboxId":"sbx", "generation":1, "attempt":1, "bodyHash":"a".repeat(64),
        "idempotencyKey":"cmd", "kind":"command.run", "retireCommand":true});
    // Reconcile the unknown receipt with the complete current capabilities.
    let session = |epoch: u64| {
        let mut wire = accept(&listener);
        let hello = loop {
            if let Message::Text(text) = wire.read().expect("hello")
                && text.contains("\"type\":\"hello\"")
            {
                break text.to_string();
            }
        };
        assert!(
            hello.contains("\"commandRetire\":true"),
            "the daemon offers it"
        );
        let mut ok: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../crates/sandbox-protocol/fixtures/control_hello_ok_server.json"
        ))
        .unwrap();
        ok["connectionEpoch"] = json!(epoch);
        send(&mut wire, ok);
        let seen = reconcile(&mut wire, |_| true);
        (wire, seen)
    };
    // Reads (answering heartbeats) until `done` or the deadline.
    let pump = |wire: &mut Wire, limit: Duration, done: &dyn Fn() -> bool| {
        let deadline = Instant::now() + limit;
        while !done() && Instant::now() < deadline {
            if let Ok(Message::Text(text)) = wire.read()
                && let Ok(DaemonControlMessage::Heartbeat { id, .. }) = parse_daemon_control(&text)
            {
                pong(wire, &id);
            }
        }
        done()
    };
    let replayed = |seen: &Reconciled| {
        seen.receipts
            .iter()
            .any(|(id, state)| id == "cmd" && *state == OperationState::UnknownOutcome)
    };

    // A running VM in the birth's boot supplies no sound retirement proof.
    let (mut wire, seen) = session(1);
    assert!(replayed(&seen), "{seen:?}");
    send(&mut wire, retire.clone());
    assert!(pump(&mut wire, Duration::from_secs(10), &|| fake
        .retire_attempts()
        == 1));
    assert!(fake.retired_command_groups().is_empty());
    assert!(
        journal_receipt(dir.path(), "cmd").is_some(),
        "the receipt stays"
    );
    assert_eq!(
        fake.lifecycle_state("sbx"),
        Some(sandbox_protocol::SandboxLifecycleState::Ready),
        "nothing stopped the sandbox"
    );
    reset(wire);

    // 3. The VM is stopped: the next replay retires the receipt.
    sandbox_runtime::SandboxRuntime::stop_sandbox(
        &fake,
        &sandbox_runtime::StopSandboxRequest {
            sandbox_id: "sbx".into(),
            instance_name: "wssp-sbx-sbx".into(),
            operation_id: "out-of-band".into(),
            idempotency_key: "out-of-band".into(),
            template_fingerprint: String::new(),
        },
    )
    .unwrap();
    let (mut wire, seen) = session(2);
    assert!(replayed(&seen), "{seen:?}");
    send(&mut wire, retire.clone());
    assert!(
        pump(&mut wire, Duration::from_secs(10), &|| journal_receipt(
            dir.path(),
            "cmd"
        )
        .is_none()),
        "a stopped VM proves the UNKNOWN command gone"
    );
    let retired = fake.retired_command_groups();
    assert_eq!(retired.len(), 1, "{retired:?}");
    assert_eq!(
        (
            retired[0].0.as_str(),
            retired[0].1.pid,
            retired[0].1.start_ticks
        ),
        ("cmd", 123, 123456)
    );
    reset(wire);
    let (wire, seen) = session(3);
    assert!(seen.receipts.iter().all(|(id, _)| id != "cmd"), "{seen:?}");
    finish(daemon, shutdown);
    drop(wire);
}

/// One UNKNOWN `command.run` receipt of the
/// running-VM retirement fixture, journaled as its daemon would have.
#[derive(Clone, Copy, Default)]
struct RetireSpec {
    op: &'static str,
    /// The journaled start's budget (decision 2); `None`: no start.
    start: Option<u64>,
    /// The result also carries the bound birth.
    result_birth: bool,
    cancel: bool,
    stop_unproven: bool,
    /// The daemon died mid-run: the receipt is still in Effect.
    effect_only: bool,
}

/// Fast in-session pacing for the daemon thread.
const FAST_RETIRE: crate::sandbox_relay::journal::RetirePacing =
    crate::sandbox_relay::journal::RetirePacing {
        retry_interval: Duration::from_millis(50),
        jitter: Duration::ZERO,
        backoff_base: Duration::from_millis(100),
        backoff_cap: Duration::from_millis(400),
        not_due_pad: Duration::ZERO,
        queue_full: Duration::from_millis(10),
        park_recheck: Duration::ZERO,
    };

fn retire_birth(op: &str) -> serde_json::Value {
    let mut birth: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../crates/sandbox-protocol/fixtures/process_started.json"
    ))
    .unwrap();
    birth["operationId"] = json!(op);
    birth["sandboxId"] = json!("sbx");
    birth["processId"] = json!(format!("proc-{op}"));
    birth["bootId"] = json!(sandbox_runtime::FAKE_BOOT_ID);
    birth
}

/// A running sandbox `sbx` on an unlimited lease holding `specs`.
fn retire_fixture(
    listener: &TcpListener,
    dir: &std::path::Path,
    fake: &sandbox_runtime::FakeRuntime,
    specs: &[RetireSpec],
) {
    fake.create_fixture(&sandbox_runtime::CreateSandboxRequest::for_test(
        "sbx", "create",
    ))
    .unwrap();
    let binding = TransportBindingV11 {
        server: format!("ws://{}/ws/sandbox-host", listener.local_addr().unwrap()),
        host_owner_id: "owner-1".into(),
        host_id: "host".into(),
    };
    let journal = crate::sandbox_relay::test_support::open_journal(dir, &binding).unwrap();
    journal.set_lease_ceiling(None);
    let mut lease = sandbox_protocol::HostLease::for_test();
    lease.deadline_unix_ms = sandbox_protocol::LEASE_UNLIMITED_DEADLINE_MS;
    let create: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner", "operationId":"create", "sandboxId":"sbx", "kind":"sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(), "cpuCount": 1, "memoryMiB": 1024, "generation":1, "attempt":1, "idempotencyKey":"create", "bodyHash":"a".repeat(64), "lease":lease})).unwrap();
    journal
        .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &create))
        .unwrap();
    journal.accept_fixture_lease(&create).unwrap();
    journal
        .record_result(
            "create",
            OperationState::Succeeded,
            Some(json!({"state":"ready","lease":create.lease})),
            None,
            None,
        )
        .unwrap();
    for spec in specs {
        let mut dispatch = command(spec.op);
        dispatch.as_object_mut().unwrap().remove("type");
        let dispatch: OperationDispatch = serde_json::from_value(dispatch).unwrap();
        journal
            .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &dispatch))
            .unwrap();
        journal.record_effect(spec.op).unwrap();
        let birth = retire_birth(spec.op);
        if let Some(budget) = spec.start {
            assert!(
                journal
                    .record_command_start(spec.op, (1, 1), birth.clone(), 1000, budget, None)
                    .unwrap()
            );
        }
        if spec.cancel {
            journal.record_cancel(spec.op, 1, 1).unwrap();
        }
        if spec.effect_only {
            continue;
        }
        let ext = if spec.stop_unproven {
            vec![(
                crate::sandbox_relay::journal::COMMAND_STOP_UNPROVEN_EXT,
                json!(true),
            )]
        } else {
            Vec::new()
        };
        let body = json!({"version":1,"observedAt":birth["observedAt"],"payload":null,
            "continuation":null,"birth":spec.result_birth.then_some(&birth),
            "failure":{"resource":"command","effect":"unknown"}});
        journal
            .record_attempt_result_ext(
                spec.op,
                (1, 1),
                OperationState::UnknownOutcome,
                Some(body),
                (Some(SandboxErrorCode::UnknownOutcome.into()), None, None),
                &ext,
            )
            .unwrap()
            .unwrap();
    }
}

fn spawn_retire_daemon(
    options: ConnectOptions,
    fake: sandbox_runtime::FakeRuntime,
) -> thread::JoinHandle<Result<()>> {
    thread::spawn(move || {
        crate::sandbox_relay::command_retire::PACING_OVERRIDE
            .with(|cell| cell.set(Some(FAST_RETIRE)));
        let result = run_connect_with(&options, |_| Ok((Box::new(fake), None)));
        if let Err(error) = &result {
            eprintln!("daemon ended: {error:#}");
        }
        result
    })
}

/// Answers `hello` for `epoch` negotiating `commandRetire`, then reconciles.
fn retire_session(listener: &TcpListener, epoch: u64) -> (Wire, Reconciled) {
    let mut wire = accept(listener);
    loop {
        if let Message::Text(text) = wire.read().expect("hello")
            && text.contains("\"type\":\"hello\"")
        {
            break;
        }
    }
    let mut ok: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../crates/sandbox-protocol/fixtures/control_hello_ok_server.json"
    ))
    .unwrap();
    ok["connectionEpoch"] = json!(epoch);
    ok["capabilities"]["commandRetire"] = json!(true);
    send(&mut wire, ok);
    let seen = reconcile(&mut wire, |_| true);
    (wire, seen)
}

fn request_retire(wire: &mut Wire, op: &str) {
    send(
        wire,
        json!({"sandboxOwnerId":"owner", "type":"receipt.confirmed", "operationId":op,
            "sandboxId":"sbx", "generation":1, "attempt":1, "bodyHash":"a".repeat(64),
            "idempotencyKey":op, "kind":"command.run", "retireCommand":true}),
    );
}

/// Reads (answering heartbeats) until `done` or `limit`; returns `done()`.
fn pump_until(wire: &mut Wire, limit: Duration, done: &dyn Fn() -> bool) -> bool {
    let deadline = Instant::now() + limit;
    while !done() && Instant::now() < deadline {
        if let Ok(Message::Text(text)) = wire.read()
            && let Ok(DaemonControlMessage::Heartbeat { id, .. }) = parse_daemon_control(&text)
        {
            pong(wire, &id);
        }
    }
    done()
}

/// One negotiated session: every `specs` receipt replayed and requested.
fn retire_case(
    specs: &[RetireSpec],
    setup: impl FnOnce(&sandbox_runtime::FakeRuntime),
) -> (
    tempfile::TempDir,
    TcpListener,
    sandbox_runtime::FakeRuntime,
    thread::JoinHandle<Result<()>>,
    ShutdownSignal,
    Wire,
) {
    let dir = tempfile::tempdir().expect("dir");
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let fake = sandbox_runtime::FakeRuntime::new();
    retire_fixture(&listener, dir.path(), &fake, specs);
    setup(&fake);
    let options = options(&listener, dir.path(), Duration::from_secs(5));
    let shutdown = options.shutdown.clone();
    let daemon = spawn_retire_daemon(options, fake.clone());
    let (mut wire, seen) = retire_session(&listener, 1);
    for spec in specs {
        assert!(
            seen.receipts
                .iter()
                .any(|(id, state)| id == spec.op && *state == OperationState::UnknownOutcome),
            "{seen:?}"
        );
        request_retire(&mut wire, spec.op);
    }
    (dir, listener, fake, daemon, shutdown, wire)
}

/// Adoption 1 + 16: empty scopes retire in one session without a kill, and
/// twelve requests at one `hello.ok` are all served (none dropped).
#[test]
fn running_vm_empty_scopes_retire_without_a_kill_and_none_are_dropped() {
    const OPS: [&str; 12] = [
        "c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8", "c9", "c10", "c11",
    ];
    let specs: Vec<_> = OPS
        .iter()
        .map(|op| RetireSpec {
            op,
            start: Some(0),
            result_birth: true,
            ..RetireSpec::default()
        })
        .collect();
    let (dir, _listener, fake, daemon, shutdown, mut wire) = retire_case(&specs, |fake| {
        for op in OPS {
            fake.set_command_scope(op, sandbox_runtime::FakeCommandScope::Empty);
        }
    });
    assert!(pump_until(&mut wire, Duration::from_secs(20), &|| OPS
        .iter()
        .all(|op| journal_receipt(dir.path(), op).is_none())));
    assert!(fake.retire_kills().is_empty());
    assert_eq!(fake.retired_command_groups().len(), OPS.len());
    assert_eq!(
        fake.lifecycle_state("sbx"),
        Some(sandbox_protocol::SandboxLifecycleState::Ready),
        "nothing stopped the sandbox"
    );
    finish(daemon, shutdown);
}

/// Adoption 2: a populated, not-yet-due command stays; once its guest
/// clock passes budget + 20 s an in-session retry kills it once and
/// retires it, with no reconnect.
#[test]
fn a_not_yet_due_command_is_killed_by_an_in_session_retry() {
    let spec = RetireSpec {
        op: "cmd",
        start: Some(1000),
        result_birth: true,
        ..RetireSpec::default()
    };
    let (dir, _listener, fake, daemon, shutdown, mut wire) = retire_case(&[spec], |fake| {
        fake.set_command_scope(
            "cmd",
            sandbox_runtime::FakeCommandScope::Populated { killable: true },
        );
        fake.set_command_scope_active_for("cmd", Duration::from_millis(21_000 - 400));
    });
    assert!(pump_until(&mut wire, Duration::from_secs(10), &|| fake
        .retire_attempts()
        >= 1));
    assert!(
        journal_receipt(dir.path(), "cmd").is_some(),
        "kept, not due"
    );
    assert!(fake.retire_kills().is_empty());
    fake.set_command_scope_active_for("cmd", Duration::from_secs(30));
    assert!(pump_until(&mut wire, Duration::from_secs(10), &|| {
        journal_receipt(dir.path(), "cmd").is_none()
    }));
    assert_eq!(
        fake.retire_kills(),
        [("cmd".to_string(), sandbox_runtime::RetireMode::KillDeadline)]
    );
    finish(daemon, shutdown);
}

/// Adoption 3 + 6: a command without a budget is never signalled; it is
/// re-observed with a capped backoff and retired once it exits by itself.
#[test]
fn an_unbudgeted_command_is_never_killed_and_retires_after_it_exits() {
    let spec = RetireSpec {
        op: "cmd",
        start: Some(0),
        result_birth: true,
        ..RetireSpec::default()
    };
    let (dir, _listener, fake, daemon, shutdown, mut wire) = retire_case(&[spec], |fake| {
        fake.set_command_scope(
            "cmd",
            sandbox_runtime::FakeCommandScope::Populated { killable: true },
        );
    });
    assert!(pump_until(&mut wire, Duration::from_secs(10), &|| fake
        .retire_attempts()
        >= 4));
    assert!(fake.retire_kills().is_empty());
    assert!(journal_receipt(dir.path(), "cmd").is_some());
    fake.set_command_scope("cmd", sandbox_runtime::FakeCommandScope::Empty);
    assert!(pump_until(&mut wire, Duration::from_secs(10), &|| {
        journal_receipt(dir.path(), "cmd").is_none()
    }));
    assert!(fake.retire_kills().is_empty(), "never signalled");
    finish(daemon, shutdown);
}

/// Adoption 4 + 5: a requested cancel, or an interim stop still unproven,
/// makes the command due: exactly one whole-scope kill, then retirement.
#[test]
fn a_cancelled_or_unproven_stop_command_gets_one_kill_then_retires() {
    for (cancel, stop_unproven) in [(true, false), (false, true)] {
        let spec = RetireSpec {
            op: "cmd",
            start: Some(0),
            result_birth: true,
            cancel,
            stop_unproven,
            ..RetireSpec::default()
        };
        let (dir, _listener, fake, daemon, shutdown, mut wire) = retire_case(&[spec], |fake| {
            fake.set_command_scope(
                "cmd",
                sandbox_runtime::FakeCommandScope::Populated { killable: true },
            );
        });
        assert!(pump_until(&mut wire, Duration::from_secs(10), &|| {
            journal_receipt(dir.path(), "cmd").is_none()
        }));
        assert_eq!(
            fake.retire_kills(),
            [("cmd".to_string(), sandbox_runtime::RetireMode::KillCancel)],
            "cancel {cancel}"
        );
        finish(daemon, shutdown);
    }
}

/// Adoption 10, 11, 18: a populated guest-uid root, a kernel without
/// `cgroup.kill`, or an unscoped launch in this boot keeps the receipt
/// (one attempt, no retry, no reconnect needed).
#[test]
fn uid_roots_missing_kill_support_or_an_unscoped_boot_keep_the_receipt() {
    for case in ["uid_populated", "kill_unsupported", "unscoped"] {
        let spec = RetireSpec {
            op: "cmd",
            start: Some(0),
            result_birth: true,
            cancel: case == "kill_unsupported",
            ..RetireSpec::default()
        };
        let (dir, _listener, fake, daemon, shutdown, mut wire) =
            retire_case(&[spec], |fake| match case {
                "uid_populated" => {
                    fake.set_command_scope("cmd", sandbox_runtime::FakeCommandScope::Empty);
                    fake.set_uid_roots(sandbox_runtime::FakeUidRoots::OnePopulated);
                }
                "kill_unsupported" => {
                    fake.set_command_scope(
                        "cmd",
                        sandbox_runtime::FakeCommandScope::Populated { killable: true },
                    );
                    fake.set_scope_kill_unsupported(true);
                }
                _ => fake.set_unscoped_marker(true),
            });
        assert!(pump_until(&mut wire, Duration::from_secs(10), &|| fake
            .retire_attempts()
            >= 1));
        assert!(!pump_until(&mut wire, Duration::from_millis(800), &|| fake
            .retire_attempts()
            > 1));
        assert!(journal_receipt(dir.path(), "cmd").is_some(), "{case}");
        assert!(fake.retire_kills().is_empty(), "{case}");
        finish(daemon, shutdown);
    }
}

/// Adoption 14 (decision 2): the daemon died mid-run; reconciliation
/// settles the receipt UNKNOWN keeping its journaled start, and the
/// running VM's empty scope retires it.
#[test]
fn a_receipt_from_a_mid_run_restart_retires_after_reconcile() {
    let spec = RetireSpec {
        op: "cmd",
        start: Some(0),
        effect_only: true,
        ..RetireSpec::default()
    };
    let (dir, _listener, fake, daemon, shutdown, mut wire) = retire_case(&[spec], |fake| {
        fake.set_command_scope("cmd", sandbox_runtime::FakeCommandScope::Empty);
    });
    assert!(pump_until(&mut wire, Duration::from_secs(10), &|| {
        journal_receipt(dir.path(), "cmd").is_none()
    }));
    assert_eq!(fake.retired_command_groups().len(), 1);
    finish(daemon, shutdown);
}

/// Blocks the `n`th `retire` lifecycle stage until released.
#[derive(Clone, Default)]
struct RetireGate(Arc<(std::sync::Mutex<GateState>, std::sync::Condvar)>);
/// (retire stages seen, blocked, released).
type GateState = (usize, bool, bool);
impl RetireGate {
    fn hook(
        &self,
        block_at: usize,
    ) -> impl Fn(&str) -> Result<(), sandbox_runtime::RuntimeError> + Send + Sync + 'static {
        let gate = self.0.clone();
        move |stage| {
            if stage == "retire" {
                let (lock, cvar) = &*gate;
                let mut state = lock.lock().unwrap();
                state.0 += 1;
                if state.0 == block_at {
                    state.1 = true;
                    cvar.notify_all();
                    while !state.2 {
                        state = cvar.wait(state).unwrap();
                    }
                }
            }
            Ok(())
        }
    }
    fn blocked(&self) -> bool {
        self.0.0.lock().unwrap().1
    }
    fn release(&self) {
        let (lock, cvar) = &*self.0;
        lock.lock().unwrap().2 = true;
        cvar.notify_all();
    }
}

/// U1 (a) + (b): a not-yet-due retry is on the worker when its session ends.
/// It never re-defers into the next session: that session neither kills nor
/// deletes until it confirms itself. (b) Its own confirmation, sent while
/// the stale attempt still runs, is not lost to deduplication and retires
/// the receipt once its own proof passes.
#[test]
fn a_retry_in_flight_across_a_session_change_is_never_re_admitted() {
    for confirm_while_blocked in [false, true] {
        let dir = tempfile::tempdir().expect("dir");
        let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
        let gate = RetireGate::default();
        let fake = sandbox_runtime::FakeRuntime::new();
        let spec = RetireSpec {
            op: "cmd",
            start: Some(1000),
            result_birth: true,
            ..RetireSpec::default()
        };
        retire_fixture(&listener, dir.path(), &fake, &[spec]);
        fake.set_command_scope(
            "cmd",
            sandbox_runtime::FakeCommandScope::Populated { killable: true },
        );
        // Not due by 300 ms: the first attempt re-defers, the second blocks.
        fake.set_command_scope_active_for("cmd", Duration::from_millis(21_000 - 300));
        let options = options(&listener, dir.path(), Duration::from_secs(5));
        let shutdown = options.shutdown.clone();
        let daemon = spawn_retire_daemon(options, fake.clone().with_lifecycle_hook(gate.hook(2)));
        let (mut wire, _) = retire_session(&listener, 1);
        request_retire(&mut wire, "cmd");
        assert!(pump_until(&mut wire, Duration::from_secs(10), &|| gate.blocked()));
        // Session A ends while its retry is on the worker; B negotiates.
        reset(wire);
        let (mut wire, seen) = retire_session(&listener, 2);
        assert!(seen.receipts.iter().any(|(id, _)| id == "cmd"));
        if confirm_while_blocked {
            request_retire(&mut wire, "cmd");
        }
        // The stale attempt returns `not_due` (R9 lets an attempt already
        // on the worker finish); only then does the command become due.
        gate.release();
        pump_until(&mut wire, Duration::from_millis(500), &|| false);
        fake.set_command_scope_active_for("cmd", Duration::from_secs(30));
        if confirm_while_blocked {
            assert!(pump_until(&mut wire, Duration::from_secs(10), &|| {
                journal_receipt(dir.path(), "cmd").is_none()
            }));
            assert_eq!(fake.retire_kills().len(), 1);
        } else {
            assert!(!pump_until(
                &mut wire,
                Duration::from_millis(1500),
                &|| fake.retire_attempts() > 2 || !fake.retire_kills().is_empty()
            ));
            assert!(
                journal_receipt(dir.path(), "cmd").is_some(),
                "no delete in B"
            );
            // B's own request retires it.
            request_retire(&mut wire, "cmd");
            assert!(pump_until(&mut wire, Duration::from_secs(10), &|| {
                journal_receipt(dir.path(), "cmd").is_none()
            }));
            assert_eq!(fake.retire_kills().len(), 1);
        }
        finish(daemon, shutdown);
    }
}

#[test]
fn upgrade_rate_limits_retry_with_bounded_server_hints_or_exponential_backoff() {
    for reconnect in [false, true] {
        for (header, expected) in [
            (Some("120"), Some(120)),
            (Some("999999"), Some(300)),
            (Some("invalid"), None),
            (Some("0"), Some(0)),
            (None, None),
        ] {
            let mut response = tungstenite::http::Response::builder().status(429);
            if let Some(value) = header {
                response = response.header("Retry-After", value);
            }
            let error = relay_dial_error(
                tungstenite::Error::Http(Box::new(response.body(None).unwrap())),
                "https://localhost",
                reconnect,
            );
            assert!(error.downcast_ref::<RetryableSession>().is_some());
            assert!(error.downcast_ref::<ServerVerdict>().is_none());
            assert_eq!(
                error
                    .downcast_ref::<RetryAfter>()
                    .map(|hint| hint.0.as_secs()),
                expected
            );
            let mut backoff = ReconnectBackoff::default();
            for base in [250, 500, 1000, 2000] {
                let wait = reconnect_wait(backoff.next(false, None), &error);
                assert!(wait >= Duration::from_millis(base / 2));
                assert!(wait <= Duration::from_secs(300));
                if let Some(seconds) = expected {
                    assert!(wait >= Duration::from_secs(seconds));
                } else {
                    assert!(wait <= Duration::from_millis(base));
                }
            }
        }
    }
}

#[test]
fn first_connect_retries_a_503_only_when_it_names_a_retry_time() {
    let dial = |retry_after: Option<&str>| {
        let mut response = tungstenite::http::Response::builder().status(503);
        if let Some(value) = retry_after {
            response = response.header("Retry-After", value);
        }
        relay_dial_error(
            tungstenite::Error::Http(Box::new(response.body(None).unwrap())),
            "https://localhost",
            false,
        )
    };
    let hinted = dial(Some("5"));
    assert!(hinted.downcast_ref::<RetryableSession>().is_some());
    assert_eq!(
        hinted
            .downcast_ref::<RetryAfter>()
            .map(|hint| hint.0.as_secs()),
        Some(5)
    );
    for bare in [dial(None), dial(Some("invalid"))] {
        assert!(bare.downcast_ref::<RetryableSession>().is_none());
        assert!(format!("{bare:#}").contains("503"));
    }
}

#[test]
fn refused_hello_exits_without_a_second_connection_and_always_offers_the_full_set() {
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let fake = sandbox_runtime::FakeRuntime::new();
    fake.fixture_root().unwrap();
    let options = options(&listener, dir.path(), Duration::from_secs(1));
    let shutdown = options.shutdown.clone();
    let daemon = spawn_daemon(options, fake, None);
    let mut wire = accept(&listener);
    let hello = until(&mut wire, |frame| {
        matches!(frame, DaemonControlMessage::Hello { .. })
    });
    let DaemonControlMessage::Hello {
        daemon: hello_daemon,
        ..
    } = hello
    else {
        panic!("expected hello")
    };
    let capabilities = serde_json::to_value(hello_daemon.capabilities).unwrap();
    for name in [
        "commandRetire",
        "censusEntryResults",
        "pendingReceipts",
        "expiryStatusResults",
        "observationFence",
    ] {
        assert_eq!(capabilities[name], json!(true), "{name}");
    }
    send(
        &mut wire,
        json!({"type":"protocol.error", "failure":"protocol_error", "message":"Invalid sandbox relay control frame."}),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while !daemon.is_finished() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    let finished = daemon.is_finished();
    if !finished {
        shutdown.request();
    }
    let error = daemon.join().unwrap().unwrap_err();
    assert!(finished, "the refused hello must end the daemon");
    assert!(error.downcast_ref::<TerminalHelloRefusal>().is_some());
    listener.set_nonblocking(true).unwrap();
    assert!(matches!(listener.accept(), Err(error) if error.kind() == ErrorKind::WouldBlock));
}

/// A draining server closes the session (1001) and answers every redial with
/// 503 + `Retry-After: 1` until it exits. The daemon waits out each refusal and
/// registers exactly once, with the next process: one drop per restart.
#[test]
fn a_draining_server_defers_the_reconnect_to_the_next_process() {
    use std::io::{Read, Write};
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let fake = sandbox_runtime::FakeRuntime::new();
    fake.fixture_root().unwrap();
    let options = options(&listener, dir.path(), Duration::from_secs(5));
    let shutdown = options.shutdown.clone();
    let daemon = spawn_daemon(options, fake, None);
    let mut wire = accept(&listener);
    register(&mut wire, 1);
    crate::sandbox_relay::test_support::ack_registration(&mut wire);
    wire.close(Some(tungstenite::protocol::CloseFrame {
        code: tungstenite::protocol::frame::coding::CloseCode::Away,
        reason: "session_removed".into(),
    }))
    .unwrap();
    let mut refused_at: Option<Instant> = None;
    for _ in 0..3 {
        let mut tcp = accept_tcp(&listener);
        if let Some(at) = refused_at {
            assert!(at.elapsed() >= Duration::from_secs(1), "{:?}", at.elapsed());
        }
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            tcp.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
            assert!(request.len() < 8192);
        }
        // Stamped before the reply, so the daemon's wait cannot start earlier.
        refused_at = Some(Instant::now());
        tcp.write_all(b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
        drop(tcp);
    }
    drop(wire);
    // The next process: one registration, and the daemon dials no further.
    let mut wire = accept(&listener);
    let waited = refused_at.unwrap().elapsed();
    assert!(waited >= Duration::from_secs(1), "{waited:?}");
    // Generous for a loaded machine; the wait itself is bounded
    // deterministically in `a_draining_servers_retry_after_keeps_redials_prompt`.
    assert!(
        waited < Duration::from_secs(15),
        "no long stall: {waited:?}"
    );
    register(&mut wire, 2);
    crate::sandbox_relay::test_support::ack_registration(&mut wire);
    thread::sleep(Duration::from_millis(1500));
    listener.set_nonblocking(true).unwrap();
    assert!(matches!(listener.accept(), Err(error) if error.kind() == ErrorKind::WouldBlock));
    assert!(!daemon.is_finished());
    finish(daemon, shutdown);
    drop(wire);
}

/// The waits behind that socket test: a draining server's 503 + `Retry-After: 1`
/// is a floor of 1 s, and the redials stay prompt (no long stall) while the
/// old process drains and the next one starts.
#[test]
fn a_draining_servers_retry_after_keeps_redials_prompt() {
    let response = tungstenite::http::Response::builder()
        .status(503)
        .header("Retry-After", "1")
        .body(None)
        .unwrap();
    let error = relay_dial_error(
        tungstenite::Error::Http(Box::new(response)),
        "https://localhost",
        true,
    );
    assert!(error.downcast_ref::<RetryableSession>().is_some());
    assert!(error.downcast_ref::<ServerVerdict>().is_none());
    let mut backoff = ReconnectBackoff::default();
    for ceiling in [1000, 1000, 1000, 2000, 4000] {
        let wait = reconnect_wait(backoff.next(false, None), &error);
        assert!(wait >= Duration::from_secs(1), "{wait:?}");
        assert!(wait <= Duration::from_millis(ceiling), "{wait:?}");
    }
}

#[test]
fn an_initial_rate_limited_upgrade_retries_after_the_server_delay() {
    use std::io::{Read, Write};
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let fake = sandbox_runtime::FakeRuntime::new();
    fake.fixture_root().unwrap();
    let options = options(&listener, dir.path(), Duration::from_secs(1));
    let daemon = spawn_daemon(options, fake, None);
    let mut tcp = accept_tcp(&listener);
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        tcp.read_exact(&mut byte).unwrap();
        request.push(byte[0]);
        assert!(request.len() < 8192);
    }
    let limited_at = Instant::now();
    tcp.write_all(b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
    drop(tcp);
    let mut wire = accept(&listener);
    assert!(limited_at.elapsed() >= Duration::from_secs(1));
    until(&mut wire, |frame| {
        matches!(frame, DaemonControlMessage::Hello { .. })
    });
    send(
        &mut wire,
        json!({"type":"protocol.error", "failure":"protocol_error", "message":"Invalid sandbox relay control frame."}),
    );
    let error = daemon.join().unwrap().unwrap_err();
    assert!(error.downcast_ref::<TerminalHelloRefusal>().is_some());
}
