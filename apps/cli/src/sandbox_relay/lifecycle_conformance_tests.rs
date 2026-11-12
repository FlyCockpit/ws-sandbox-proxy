//! C57 lifecycle fault matrix against the REAL daemon: the production connect
//! loop, journal, reconcile and supervisor over a shared `FakeRuntime`, with a
//! scripted control plane on a loopback socket. Each host-side row of
//! `crates/sandbox-protocol/fixtures/lifecycle_fault_matrix.json` is a host
//! process that died at that boundary: the durable journal and the runtime are
//! left exactly as that death leaves them, then a fresh daemon process (a new
//! `run_connect_with` on the same state directory) reconnects. The TypeScript
//! suite (`apps/server/src/sandbox-relay/lifecycle-conformance.pg.test.ts`)
//! drives its host double from the same rows, so the two halves cannot drift.
use super::*;
use crate::sandbox_relay::test_support::FixtureRuntime;
use sandbox_protocol::parse_daemon_control;
use sandbox_runtime::{CreateSandboxRequest, FakeRuntime, GuestIdentity, RunCommandRequest};
use std::net::TcpListener;

const MATRIX: &str =
    include_str!("../../../../crates/sandbox-protocol/fixtures/lifecycle_fault_matrix.json");

fn fingerprint() -> String {
    CreateSandboxRequest::for_test("sbx", "key").template_digest
}

fn dispatch(id: &str, kind: &str, attempt: u64) -> OperationDispatch {
    let mut value = json!({"sandboxOwnerId":"owner",
        "operationId": id, "sandboxId": "sbx", "kind": kind, "generation": 1,
        "attempt": attempt, "idempotencyKey": id, "bodyHash": "a".repeat(64),
        "templateDigest": fingerprint(), "incusFingerprint": fingerprint(),
        "architecture": "x86_64",
    });
    if kind == "sandbox.create" {
        value["cpuCount"] = json!(1);
        value["memoryMiB"] = json!(1024);
        value["lease"] = json!(sandbox_protocol::HostLease::for_test());
    } else {
        value["argv"] = json!(["true"]);
        value["resultVersion"] = json!(1);
        value["processId"] = json!(format!("proc-{id}"));
    }
    if matches!(
        kind,
        "sandbox.create" | "sandbox.reconnect" | "sandbox.stop" | "sandbox.kill"
    ) {
        value["allocation"] =
            serde_json::to_value(crate::sandbox_relay::test_support::allocation()).unwrap();
    }
    crate::sandbox_relay::test_support::current_fixture_dispatch(
        &serde_json::from_value(value).expect("dispatch"),
    )
}

/// The runtime request a dispatch of operation `op` becomes.
fn command_request() -> RunCommandRequest {
    RunCommandRequest {
        template_fingerprint: fingerprint(),
        generation: 1,
        attempt: 1,
        sandbox_id: "sbx".into(),
        instance_name: sandbox_runtime::default_incus_instance_name("sbx"),
        operation_id: "op".into(),
        idempotency_key: "op".into(),
        argv: vec!["true".into()],
        script: None,
        cwd: None,
        timeout_ms: None,
        env: Vec::new(),
        stdin: None,
        guest: GuestIdentity::default(),
        build_step: None,
    }
}

/// Command effects of `op` counted from the runtime itself, not inferred from
/// the wire. FakeRuntime records every executed command by operation id and
/// refuses a second one, so a probe run is refused exactly when the command
/// already ran (at most once). Destructive: call it last.
fn command_effects(runtime: &FakeRuntime) -> u64 {
    match runtime.run_command(&command_request()) {
        Ok(_) => 0,
        Err(error) if error.code == SandboxErrorCode::IdempotencyConflict => 1,
        Err(error) => panic!("command probe failed: {}", error.message),
    }
}

/// What the scripted server saw while the restarted daemon reconnected.
struct Restarted {
    wire: tungstenite::WebSocket<std::net::TcpStream>,
    daemon: Option<thread::JoinHandle<Result<()>>>,
    runtime: FakeRuntime,
    receipts: Vec<(String, OperationState, Option<SandboxErrorCode>)>,
    shutdown: ShutdownSignal,
}

impl Restarted {
    /// The redelivered dispatch (a server retry of the same binding): its
    /// result, and how many stream or `accepted` frames (a fresh admission into
    /// the effect path) the daemon emitted before it.
    fn redeliver(&mut self, dispatch: &OperationDispatch) -> (OperationState, usize) {
        let mut value = serde_json::to_value(dispatch).expect("value");
        value["type"] = json!("operation.dispatch");
        self.wire
            .send(Message::Text(value.to_string().into()))
            .expect("redeliver");
        let mut streamed = 0;
        loop {
            match self.wire.read().expect("frame") {
                Message::Binary(_) => streamed += 1,
                Message::Text(text) => match parse_daemon_control(&text).expect("control") {
                    DaemonControlMessage::OperationResult {
                        operation_id,
                        state,
                        ..
                    } if operation_id == dispatch.operation_id => return (state, streamed),
                    DaemonControlMessage::OperationProgress { operation_id, .. }
                        if operation_id == dispatch.operation_id =>
                    {
                        streamed += 1
                    }
                    _ => {}
                },
                _ => {}
            }
        }
    }
}

impl Drop for Restarted {
    fn drop(&mut self) {
        // A server close never ends the daemon (P0-1): stop it locally.
        self.shutdown.request();
        for entry in self.runtime.sandbox_inventory().unwrap_or_default() {
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

/// Leaves the journal and runtime as a host that died at `journal`/`effect`
/// left them, then starts a fresh daemon process on that state.
fn die_and_restart(kind: &str, journal_phase: Option<&str>, effect: bool) -> Restarted {
    let dir = tempfile::tempdir().expect("dir");
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let address = listener.local_addr().expect("address");
    let runtime = FakeRuntime::new();
    runtime.fixture_root().unwrap();
    let binding = TransportBindingV11 {
        server: format!("ws://{address}/ws/sandbox-host"),
        host_owner_id: "owner-1".into(),
        host_id: "host-1".into(),
    };
    {
        let journal = crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
            .expect("journal");
        if kind == "command.run" {
            // The command runs in an existing VM whose create committed earlier.
            runtime
                .create_fixture(&CreateSandboxRequest::for_test("sbx", "existing"))
                .expect("vm");
            let create = dispatch("existing", "sandbox.create", 1);
            journal
                .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &create))
                .expect("intent");
            journal.accept_fixture_lease(&create).expect("lease");
            journal
                .record_result(
                    "existing",
                    OperationState::Succeeded,
                    Some(json!({"state": "ready", "lease": create.lease})),
                    None,
                    None,
                )
                .expect("result");
        }
        let work = dispatch("op", kind, 1);
        if let Some(phase) = journal_phase {
            journal
                .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &work))
                .expect("intent");
            // The Intent row models death before a lease checkpoint. C-26
            // tests separately cover ambiguous retained-lease Intent recovery.
            if kind == "sandbox.create" && phase != "intent" {
                journal.accept_fixture_lease(&work).expect("lease");
            }
            if phase != "intent" {
                journal.record_effect("op").expect("effect");
            }
        }
        if effect {
            if kind == "sandbox.create" {
                runtime
                    .create_fixture(&CreateSandboxRequest::for_test("sbx", "op"))
                    .expect("vm");
            } else {
                runtime.run_command(&command_request()).expect("command");
            }
        }
        if matches!(journal_phase, Some("result" | "delivered")) {
            let result = if kind == "sandbox.create" {
                json!({"state": "ready", "lease": work.lease})
            } else {
                json!({"exitCode": 0, "outputBytes": 8})
            };
            journal
                .record_result("op", OperationState::Succeeded, Some(result), None, None)
                .expect("result");
        }
        // Dropped here: reopened from disk by the new process below.
    }
    let options = ConnectOptions {
        host_terminal: None,
        server_url: format!("ws://{address}"),
        host_token: "test-only-token".into(),
        host_id: "host-1".into(),
        label: "c57-conformance".into(),
        runtime: HostRuntimeKind::Fake,
        incus_project: None,
        state_dir: Some(dir.path().into()),
        heartbeat: Duration::from_secs(30),
        sandbox_memory_mib: None,
        max_sandbox_cpu_count: None,
        sandbox_vcpu_budget: Some(4),
        max_concurrent_commands: 16,
        shutdown: Default::default(),
    };
    let daemon_runtime = runtime.clone();
    let shutdown = options.shutdown.clone();
    let daemon = thread::spawn(move || {
        let _dir = dir;
        run_connect_with(&options, |_| Ok((Box::new(daemon_runtime), None)))
    });
    let (tcp, _) = listener.accept().expect("accept");
    tcp.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let mut wire = tungstenite::accept_hdr(tcp, tests::RelayHandshake).expect("handshake");
    wire.read().expect("hello");
    crate::sandbox_relay::test_support::send_sized_hello(&mut wire, &binding);
    let mut receipts = Vec::new();
    loop {
        let frame = wire.read().expect("reconciliation frame");
        let Ok(text) = frame.to_text() else { continue };
        match parse_daemon_control(text).expect("control") {
            DaemonControlMessage::OperationReceipt {
                operation_id,
                state,
                error,
                ..
            } => {
                receipts.push((
                    operation_id.clone(),
                    state,
                    error.and_then(|e| e.code.known()),
                ));
                wire.send(Message::Text(
                    json!({"type": "receipt.ack", "operationId": operation_id})
                        .to_string()
                        .into(),
                ))
                .expect("receipt ack");
            }
            DaemonControlMessage::SandboxInventory { page, entries, .. } => {
                wire.send(Message::Text(
                    json!({"type": "inventory.ack", "page": page, "entryResults": entries.iter().map(|entry| json!({"sandboxId":entry.sandbox_id,"outcome":"converged"})).collect::<Vec<_>>()})
                        .to_string()
                        .into(),
                ))
                .expect("inventory ack");
            }
            DaemonControlMessage::ReconcileComplete { .. } => break,
            _ => {}
        }
    }
    Restarted {
        wire,
        daemon: Some(daemon),
        runtime,
        receipts,
        shutdown,
    }
}

fn wire_state(value: &str) -> OperationState {
    serde_json::from_value(json!(value)).expect("state")
}
fn wire_code(value: &serde_json::Value) -> Option<SandboxErrorCode> {
    (!value.is_null()).then(|| serde_json::from_value(value.clone()).expect("code"))
}

#[test]
fn shared_fault_matrix_rows_hold_for_the_real_daemon_after_a_restart() {
    let matrix: serde_json::Value = serde_json::from_str(MATRIX).expect("matrix");
    let cells = matrix["cells"].as_array().expect("cells");
    let mut checked = 0;
    for cell in cells {
        // Commit-boundary rows are server-side (the HTTP mutation); the host is untouched.
        let Some(host) = cell["host"].as_object() else {
            continue;
        };
        let journal_phase = host["journal"].as_str();
        let effect = host["effect"].as_bool().expect("effect");
        for kind in ["sandbox.create", "command.run"] {
            let id = cell["id"].as_str().expect("id");
            let expected = &cell["expect"][kind];
            let mut restarted = die_and_restart(kind, journal_phase, effect);
            let receipt = restarted
                .receipts
                .iter()
                .find(|(operation, ..)| operation == "op")
                .cloned();
            if expected["receipt"].is_null() {
                assert!(
                    receipt.is_none(),
                    "{id} {kind}: unexpected receipt {receipt:?}"
                );
            } else {
                let (_, state, code) = receipt.unwrap_or_else(|| panic!("{id} {kind}: no receipt"));
                assert_eq!(
                    (state, code),
                    (
                        wire_state(expected["receipt"]["state"].as_str().expect("state")),
                        wire_code(&expected["receipt"]["errorCode"]),
                    ),
                    "{id} {kind}: restart receipt"
                );
            }
            let effects = expected["effects"].as_u64().expect("effects");
            if kind == "sandbox.create" {
                let vms = restarted.runtime.sandbox_inventory().expect("inventory");
                assert_eq!(vms.len() as u64, effects, "{id} {kind}: VMs after restart");
            }
            if journal_phase.is_some() {
                // The server's retry of the same binding: answered from the
                // journal with the receipt's outcome, never a second effect.
                let (state, streamed) = restarted.redeliver(&dispatch("op", kind, 2));
                assert_eq!(
                    state,
                    wire_state(expected["receipt"]["state"].as_str().expect("state")),
                    "{id} {kind}: redelivered dispatch outcome"
                );
                assert_eq!(
                    streamed, 0,
                    "{id} {kind}: a redelivery re-entered the effect path"
                );
                if kind == "sandbox.create" {
                    let vms = restarted.runtime.sandbox_inventory().expect("inventory");
                    assert_eq!(
                        vms.len() as u64,
                        effects,
                        "{id} {kind}: redelivery made a VM"
                    );
                }
            }
            if kind == "command.run" {
                assert_eq!(
                    command_effects(&restarted.runtime),
                    effects,
                    "{id} {kind}: command effects in the runtime"
                );
            }
            checked += 1;
        }
    }
    // Six host-side rows × two kinds; a dropped row cannot pass silently.
    assert_eq!(checked, 12);
}
