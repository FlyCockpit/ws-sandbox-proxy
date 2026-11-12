//! B1: a STOPPED capture driven through the real dispatch path
//! (`handle_dispatch` -> journal-backed `HostAuthority` -> supervisor) after a
//! real stop. Stop moves the sandbox generation forward without carrying a
//! lease, so the capture runs under the host's own confirmed stop, never
//! under the (older, possibly retired) lease.
use super::*;
use sandbox_protocol::{HostLease, LeaseAction};
use std::net::{TcpListener, TcpStream};

type Socket = tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<TcpStream>>;
type Wire = tungstenite::WebSocket<TcpStream>;

struct Rig {
    _dir: tempfile::TempDir,
    binding: TransportBindingV11,
    journal: Arc<HostJournal>,
    authority: HostAuthority,
    fake: Arc<sandbox_runtime::FakeRuntime>,
    relay: RelaySupervisor,
    socket: Socket,
    /// Server end of the socket, kept open so dispatch replies can be sent.
    _wire: Wire,
}

fn lease(action: LeaseAction) -> HostLease {
    HostLease {
        action,
        ..HostLease::for_test()
    }
}

/// A READY sandbox `sbx` at generation 1 whose create (and lease) succeeded.
fn rig(action: LeaseAction) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let binding = TransportBindingV11 {
        server: "wss://capture.test".into(),
        host_owner_id: "owner".into(),
        host_id: "host".into(),
    };
    let journal = Arc::new(
        crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding).unwrap(),
    );
    let fake = Arc::new(sandbox_runtime::FakeRuntime::new());
    fake.create_fixture(&sandbox_runtime::CreateSandboxRequest::for_test(
        "sbx", "create",
    ))
    .unwrap();
    let create: OperationDispatch = serde_json::from_value(json!({
        "sandboxOwnerId":"owner", "operationId":"create", "sandboxId":"sbx",
        "kind":"sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(),
        "cpuCount": 1, "memoryMiB": 1024, "generation":1, "attempt":1,
        "idempotencyKey":"create", "bodyHash":"a".repeat(64), "lease": lease(action)}))
    .unwrap();
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
    let authority = HostAuthority::with_journal(journal.clone());
    let relay = RelaySupervisor::start(
        fake.clone(),
        journal.clone(),
        authority.clone(),
        #[cfg(target_os = "linux")]
        None,
    );
    let images = super::super::images::ImageService::start(
        fake.clone(),
        dir.path(),
        super::super::images::ImageSettings {
            size: crate::config::ImageCacheSize::Gib(1),
            accept_foreign: false,
            foreign_grace: Duration::from_secs(600),
            builder: true,
            accept_foreign_builds: false,
        },
        ureq::Agent::config_builder().build().into(),
        "http://127.0.0.1:9",
        "wssp_host_test-secret",
    )
    .unwrap()
    .unwrap();
    images.on_registered("owner");
    relay.install_images(images);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (peer, _) = listener.accept().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let socket = tungstenite::WebSocket::from_raw_socket(
        tungstenite::stream::MaybeTlsStream::Plain(tcp),
        tungstenite::protocol::Role::Client,
        None,
    );
    let wire =
        tungstenite::WebSocket::from_raw_socket(peer, tungstenite::protocol::Role::Server, None);
    Rig {
        _dir: dir,
        binding,
        journal,
        authority,
        fake,
        relay,
        socket,
        _wire: wire,
    }
}

impl Rig {
    /// Dispatch through `handle_dispatch` and return the terminal state and
    /// error code, whether the host refused before issue (a receipt on the
    /// wire) or a worker finished it.
    fn run(&mut self, d: &OperationDispatch) -> (OperationState, Option<SandboxErrorCode>) {
        let d = crate::sandbox_relay::test_support::pinned_dispatch(d);
        handle_dispatch(
            &mut self.socket,
            sandbox_protocol::WireCodes::CURRENT,
            &mut self.authority,
            &mut crate::sandbox_relay::test_support::admission(
                64,
                crate::sandbox_relay::live_admission::test_capacity(),
            ),
            (&self.journal, &self.binding),
            &self.relay,
            &None,
            &mut HashMap::new(),
            &d,
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(finished) = self.relay.poll_finished().pop() {
                return (finished.state, finished.error.and_then(|e| e.code.known()));
            }
            let receipt = self.journal.lookup(&d.operation_id).unwrap();
            if receipt.phase == super::super::journal::ReceiptPhase::Result
                && receipt.state != OperationState::Accepted
                && receipt.state != OperationState::Running
            {
                // Refused before issue: the receipt is final, no worker ran.
                if self.authority.pending(&d.operation_id).is_none() {
                    return (
                        receipt.state,
                        receipt.error_code.and_then(|code| code.known()),
                    );
                }
            }
            assert!(Instant::now() < deadline, "{} never finished", d.kind);
            thread::sleep(Duration::from_millis(2));
        }
    }
}

fn stop(generation: u64) -> OperationDispatch {
    serde_json::from_value(json!({
        "sandboxOwnerId":"owner", "operationId": format!("stop-{generation}"), "sandboxId":"sbx",
        "kind":"sandbox.stop", "generation": generation, "attempt":1,
        "idempotencyKey": format!("stop-{generation}"), "bodyHash":"a".repeat(64),
        "incusName":"wssp-sbx-sbx"}))
    .unwrap()
}

fn capture(id: &str, generation: u64, stopped: bool) -> OperationDispatch {
    serde_json::from_value(json!({
        "sandboxOwnerId":"owner", "operationId": id, "sandboxId":"sbx",
        "kind":"sandbox.capture", "generation": generation, "attempt":1,
        "idempotencyKey": id, "bodyHash":"a".repeat(64), "incusName":"wssp-sbx-sbx",
        "capture": {"scrubPaths": [], "stopped": stopped, "upload": false}}))
    .unwrap()
}

#[test]
fn stopped_capture_runs_under_the_confirmed_stop_for_both_lease_actions() {
    for action in [LeaseAction::Stop, LeaseAction::Destroy] {
        let mut rig = rig(action);
        // The server stops at generation 2 (no lease on stop dispatches).
        assert_eq!(
            rig.run(&stop(2)),
            (OperationState::Succeeded, None),
            "{action:?}"
        );
        assert_eq!(
            rig.fake.query_sandbox("sbx", None, None).unwrap(),
            Some(sandbox_protocol::SandboxLifecycleState::Stopped)
        );
        assert_eq!(
            rig.run(&capture("cap", 2, true)),
            (OperationState::Succeeded, None),
            "{action:?}: a STOPPED capture at the stop's generation must run"
        );
        // An older generation never gains the stop's authority.
        assert_eq!(
            rig.run(&capture("stale", 1, true)).0,
            OperationState::Failed,
            "{action:?}"
        );
    }
}

#[test]
fn stopped_capture_is_refused_without_host_stop_evidence() {
    // READY at generation 1, then a dispatch claiming STOPPED at a newer
    // generation the host never stopped at: no confirmed stop, no authority.
    let mut rig = rig(LeaseAction::Destroy);
    let (state, code) = rig.run(&capture("cap", 2, true));
    assert_eq!(state, OperationState::Failed);
    assert_eq!(code, Some(SandboxErrorCode::ProtocolError));
    // READY capture keeps the live-lease rule (exact generation).
    assert_eq!(
        rig.run(&capture("ready", 1, false)),
        (OperationState::Succeeded, None)
    );
}

#[test]
fn stopped_capture_is_refused_while_the_instance_may_be_running() {
    // A confirmed stop is the authority; the runtime still has to agree the
    // instance is not running before its root is copied without a freeze.
    // The journal holds a confirmed stop at generation 2 while the fake
    // instance is still running (for example restarted outside wssp).
    let mut rig = rig(LeaseAction::Stop);
    let stop = crate::sandbox_relay::test_support::pinned_dispatch(&stop(2));
    rig.journal
        .record_fixture_intent(&intent_from_dispatch(&rig.journal, &rig.binding, &stop))
        .unwrap();
    rig.journal
        .record_result(
            &stop.operation_id,
            OperationState::Succeeded,
            Some(json!({"state":"stopped"})),
            None,
            None,
        )
        .unwrap();
    assert_eq!(
        rig.fake.query_sandbox("sbx", None, None).unwrap(),
        Some(sandbox_protocol::SandboxLifecycleState::Ready)
    );
    let (state, code) = rig.run(&capture("cap", 2, true));
    assert_eq!(state, OperationState::Failed);
    assert_eq!(code, Some(SandboxErrorCode::CaptureFailed));
}
