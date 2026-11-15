//! Relay regression with FakeRuntime; no Incus process is launched.
use super::connect::*;
use sandbox_protocol::*;
use std::time::Duration;
use tungstenite::Message;
fn next(wire: &mut tungstenite::WebSocket<std::net::TcpStream>) -> DaemonControlMessage {
    loop {
        if let Message::Text(text) = wire.read().unwrap() {
            return parse_daemon_control(&text).unwrap();
        }
    }
}
fn send(wire: &mut tungstenite::WebSocket<std::net::TcpStream>, frame: serde_json::Value) {
    wire.send(Message::Text(frame.to_string().into())).unwrap();
}
#[test]
fn host_requests_are_epoch_fenced_owned_and_lowering_reports_before_ack() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = crate::config::Config::default();
    config.set_agent_host_commands(true).unwrap();
    std::fs::write(
        dir.path().join("config.toml"),
        toml::to_string(&config).unwrap(),
    )
    .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let shutdown = ShutdownSignal::default();
    let options = ConnectOptions {
        host_terminal: None,
        server_url: format!("ws://{address}"),
        host_token: "fixture-daemon".into(),
        host_id: "host".into(),
        label: "test".into(),
        runtime: sandbox_runtime::HostRuntimeKind::Fake,
        incus_project: None,
        state_dir: Some(dir.path().into()),
        heartbeat: Duration::from_secs(1),
        sandbox_memory_mib: None,
        max_sandbox_cpu_count: None,
        sandbox_vcpu_budget: Some(4),
        max_concurrent_commands: 16,
        shutdown: shutdown.clone(),
    };
    let client = std::thread::spawn(move || {
        super::test_support::run_fixture_connect(&options)
            .unwrap_or_else(|error| panic!("fixture daemon failed: {error:#}"))
    });
    let (tcp, _) = listener.accept().unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut wire = tungstenite::accept_hdr(tcp, RelayHandshake).unwrap();
    let DaemonControlMessage::Hello { daemon, .. } = next(&mut wire) else {
        panic!()
    };
    assert!(daemon.capabilities.host_commands);
    let binding = TransportBindingV11 {
        server: format!("ws://{address}/ws/sandbox-host"),
        host_owner_id: "owner-1".into(),
        host_id: "host".into(),
    };
    super::test_support::send_sized_hello(&mut wire, &binding);
    super::test_support::ack_reconciliation_with_policy(&mut wire);
    let policy = loop {
        if let DaemonControlMessage::HostAgentPolicy(p) = next(&mut wire) {
            break p;
        }
    };
    assert!(policy.host_commands);
    let start = serde_json::json!({"type":"host.exec.start","connectionEpoch":1,"requestId":"start","commandId":"abcdefghijklmnopqrstuv","ownerId":"other-owner","agentPolicyRevision":policy.agent_policy_revision,"argv":["/bin/sleep","30"],"timeoutMs":30000,"stdin":false});
    send(&mut wire, start.clone());
    loop {
        if let DaemonControlMessage::HostExecRejected(r) = next(&mut wire) {
            assert_eq!(r.reason, HostExecRejectReason::OwnerMismatch);
            break;
        }
    }
    let mut stale = start.clone();
    stale["ownerId"] = serde_json::json!("owner-1");
    stale["connectionEpoch"] = serde_json::json!(2);
    send(&mut wire, stale);
    loop {
        match next(&mut wire) {
            DaemonControlMessage::Heartbeat { .. } => break,
            DaemonControlMessage::HostExecStarted(_) => panic!("wrong-epoch command started"),
            _ => {}
        }
    }
    let mut valid = start;
    valid["ownerId"] = serde_json::json!("owner-1");
    send(&mut wire, valid);
    loop {
        if let DaemonControlMessage::HostExecStarted(_) = next(&mut wire) {
            break;
        }
    }
    send(
        &mut wire,
        serde_json::json!({"type":"host.policy.lower","connectionEpoch":1,"requestId":"lower","target":"hostCommands"}),
    );
    let mut reported = false;
    loop {
        match next(&mut wire) {
            DaemonControlMessage::HostAgentPolicy(p) => {
                assert!(!p.host_commands);
                assert!(p.agent_policy_revision > policy.agent_policy_revision);
                reported = true;
            }
            DaemonControlMessage::HostPolicyLowerResult(r) => {
                assert!(reported, "ACK must follow the persisted policy report");
                assert!(r.ok);
                break;
            }
            _ => {}
        }
    }
    assert!(
        !crate::config::Config::read(&dir.path().join("config.toml"))
            .unwrap()
            .allow_agent_host_commands
    );
    shutdown.request();
    while wire.read().is_ok_and(|f| !matches!(f, Message::Close(_))) {}
    client.join().unwrap();
}

struct RelayHandshake;
impl tungstenite::handshake::server::Callback for RelayHandshake {
    fn on_request(
        self,
        _: &tungstenite::handshake::server::Request,
        mut response: tungstenite::handshake::server::Response,
    ) -> std::result::Result<
        tungstenite::handshake::server::Response,
        tungstenite::handshake::server::ErrorResponse,
    > {
        response.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            SANDBOX_RELAY_SUBPROTOCOL.parse().unwrap(),
        );
        Ok(response)
    }
}
