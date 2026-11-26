//! C55 (C52-TB-3): OS shutdown signals against the real `wssp host run`
//! binary (fake runtime, loopback relay fixture; no Incus, no stdin).
#![cfg(unix)]

use std::net::{TcpListener, TcpStream};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::Stdio;
#[path = "../../../crates/sandbox-runtime/tests/support/managed_child.rs"]
mod managed_child;
use managed_child::ManagedChild;
use std::thread;
use std::time::{Duration, Instant};

use sandbox_protocol::{DaemonControlMessage, SANDBOX_RELAY_SUBPROTOCOL, parse_daemon_control};
use tungstenite::Message;
use tungstenite::handshake::server::{Callback, ErrorResponse, Request, Response};
use tungstenite::protocol::frame::coding::CloseCode;

const SIGINT: i32 = 2;
const SIGTERM: i32 = 15;

struct RelayHandshake;
impl Callback for RelayHandshake {
    fn on_request(self, _: &Request, mut response: Response) -> Result<Response, ErrorResponse> {
        response.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            SANDBOX_RELAY_SUBPROTOCOL.parse().expect("header"),
        );
        Ok(response)
    }
}

/// Starts `wssp host run` as its own process-group leader, so a test can
/// signal the whole group the way a terminal's Ctrl-C does.
fn spawn_daemon(listener: &TcpListener, temp: &tempfile::TempDir) -> ManagedChild {
    spawn_daemon_via(&[], listener, temp)
}

/// `spawn_daemon`, with `wrapper` (a program and its arguments) exec'ing the
/// daemon binary, e.g. `unshare … --fork` to make it a PID namespace's init.
fn spawn_daemon_via(
    wrapper: &[&str],
    listener: &TcpListener,
    temp: &tempfile::TempDir,
) -> ManagedChild {
    ManagedChild::spawn(&mut daemon_command(wrapper, listener, temp)).expect("spawn wssp host run")
}

/// The `wssp host run` command `spawn_daemon_via` runs, for callers that add
/// environment before spawning.
fn daemon_command(
    wrapper: &[&str],
    listener: &TcpListener,
    temp: &tempfile::TempDir,
) -> std::process::Command {
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let daemon = env!("CARGO_BIN_EXE_wssp");
    let (program, prefix) = match wrapper.split_first() {
        Some((program, rest)) => (*program, [rest, &[daemon]].concat()),
        None => (daemon, Vec::new()),
    };
    let mut command = std::process::Command::new(program);
    command
        .args(prefix)
        .args([
            "host",
            "run",
            "--server",
            &origin,
            "--host-id",
            "host-1",
            "--host-token-env",
            "WSSP_SIGNAL_TEST_TOKEN",
            "--runtime",
            "fake",
        ])
        .env(
            "WSSP_SIGNAL_TEST_TOKEN",
            format!("wssp_host_{}", "S".repeat(43)),
        )
        .env("WSSP_CONFIG_DIR", temp.path().join("config"))
        .env("WSSP_DATA_DIR", temp.path().join("data"))
        .env_remove("WSSP_LOG")
        .env_remove("RUST_LOG")
        .env_remove("WSSP_RUNTIME")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    command
}

fn accept(listener: &TcpListener, daemon: &mut ManagedChild) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok((tcp, _)) = listener.accept() {
            tcp.set_nonblocking(false).unwrap();
            tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            return tcp;
        }
        assert!(
            daemon.try_wait().unwrap().is_none(),
            "daemon exited before connecting"
        );
        assert!(Instant::now() < deadline, "daemon never connected");
        thread::sleep(Duration::from_millis(10));
    }
}

fn signal(target: &str, signal: &str) {
    let status = std::process::Command::new("kill")
        .args([signal, "--", target])
        .status()
        .expect("spawn kill");
    assert!(status.success(), "kill {signal} {target}: {status}");
}

fn wait_for_exit(daemon: &mut ManagedChild, within: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + within;
    loop {
        if let Some(status) = daemon.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = daemon.kill();
            let _ = daemon.wait();
            panic!("daemon did not exit within {within:?}");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// Plays the server through hello and the post-hello census, so the daemon is
/// in its relay loop when the test signals it.
fn establish(tcp: TcpStream) -> tungstenite::WebSocket<TcpStream> {
    let mut wire = tungstenite::accept_hdr(tcp, RelayHandshake).expect("relay handshake");
    let _hello = wire.read().expect("hello");
    let ack: serde_json::Value = serde_json::from_str(include_str!(
        "../../../crates/sandbox-protocol/fixtures/control_hello_ok_server.json"
    ))
    .unwrap();
    wire.send(Message::Text(ack.to_string().into())).unwrap();
    loop {
        let frame = wire.read().expect("reconciliation frame");
        let Ok(text) = frame.to_text() else { continue };
        match parse_daemon_control(text).expect("parse") {
            DaemonControlMessage::SandboxInventory { page, entries, .. } => wire
                .send(Message::Text(
                    serde_json::json!({"type":"inventory.ack", "page":page,
                        "entryResults": entries.iter().map(|entry| serde_json::json!({
                            "sandboxId":entry.sandbox_id,"outcome":"converged"
                        })).collect::<Vec<_>>()})
                    .to_string()
                    .into(),
                ))
                .unwrap(),
            DaemonControlMessage::OperationReceipt { operation_id, .. } => wire
                .send(Message::Text(
                    serde_json::json!({"type": "receipt.ack", "operationId": operation_id})
                        .to_string()
                        .into(),
                ))
                .unwrap(),
            DaemonControlMessage::ReconcileComplete { .. } => return wire,
            _ => {}
        }
    }
}

/// SIGTERM (a service manager) and SIGINT to the whole process group (a
/// terminal's Ctrl-C) each end a live relay session gracefully: a normal
/// close reaches the server, and the process then dies FROM that signal, so
/// its parent sees death by signal rather than an exit status.
#[test]
fn c55_shutdown_signal_closes_the_relay_normally_then_dies_by_that_signal() {
    for (sent, to_group, expected) in [("-TERM", false, SIGTERM), ("-INT", true, SIGINT)] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let temp = tempfile::tempdir().unwrap();
        let mut daemon = spawn_daemon(&listener, &temp);
        let tcp = accept(&listener, &mut daemon);
        let mut wire = establish(tcp);
        let pid = daemon.id().to_string();
        let target = if to_group { format!("-{pid}") } else { pid };
        signal(&target, sent);
        let close = loop {
            match wire.read() {
                Ok(Message::Close(frame)) => break frame,
                Ok(_) => continue,
                Err(error) => panic!("{sent}: no normal close before the socket ended: {error}"),
            }
        };
        let close = close.expect("close frame");
        assert_eq!(close.code, CloseCode::Normal, "{sent}");
        assert_eq!(close.reason.as_str(), "daemon shutdown", "{sent}");
        let status = wait_for_exit(&mut daemon, Duration::from_secs(30));
        assert_eq!(status.signal(), Some(expected), "{sent}: {status:?}");
        // No reconnect follows the shutdown.
        thread::sleep(Duration::from_millis(300));
        assert!(
            listener.accept().is_err(),
            "{sent}: a shutdown daemon never reconnects"
        );
    }
}

/// C55-L11: a server that accepts the TCP connection but never answers the
/// WebSocket upgrade cannot hold the daemon. One SIGTERM ends the stalled
/// handshake and the daemon dies from that signal promptly, well inside the
/// 60 s forced-shutdown bound.
#[test]
fn c55_l11_a_shutdown_signal_ends_a_stalled_relay_handshake() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let temp = tempfile::tempdir().unwrap();
    let mut daemon = spawn_daemon(&listener, &temp);
    // Accepted but never answered: the upgrade stalls.
    let _stalled = accept(&listener, &mut daemon);
    let sent = Instant::now();
    signal(&daemon.id().to_string(), "-TERM");
    let status = wait_for_exit(&mut daemon, Duration::from_secs(5));
    assert_eq!(status.signal(), Some(SIGTERM), "{status:?}");
    assert!(
        sent.elapsed() < Duration::from_secs(3),
        "{:?}",
        sent.elapsed()
    );
}

/// The first signal only requests the graceful shutdown: while that shutdown
/// is held (a debug-build barrier stands in for a slow graceful path) the
/// daemon keeps running. A second signal (here Ctrl-C to the group) ends it
/// at once, by that signal.
#[test]
fn c55_a_second_signal_during_shutdown_exits_at_once_by_that_signal() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let temp = tempfile::tempdir().unwrap();
    let mut daemon = ManagedChild::spawn(daemon_command(&[], &listener, &temp).env(
        "WSSP_TEST_BARRIER_GRACEFUL_SHUTDOWN",
        temp.path().join("never-released"),
    ))
    .expect("spawn wssp host run");
    // Accepted but never answered: the daemon is mid-handshake.
    let _stalled = accept(&listener, &mut daemon);
    let pid = daemon.id().to_string();
    signal(&pid, "-TERM");
    thread::sleep(Duration::from_millis(500));
    assert!(
        daemon.try_wait().unwrap().is_none(),
        "the first signal only requests a graceful shutdown"
    );
    let sent = Instant::now();
    signal(&format!("-{pid}"), "-INT");
    let status = wait_for_exit(&mut daemon, Duration::from_secs(5));
    assert_eq!(status.signal(), Some(SIGINT), "{status:?}");
    assert!(sent.elapsed() < Duration::from_secs(5));
}

/// An unprivileged user + PID namespace in which the forked command is init.
const PID1_WRAPPER: [&str; 6] = [
    "unshare",
    "--user",
    "--map-root-user",
    "--pid",
    "--fork",
    "--kill-child",
];

/// The host pid of the single child `unshare --fork` started (the daemon).
fn namespace_init_pid(unshare_pid: u32) -> u32 {
    let children = format!("/proc/{unshare_pid}/task/{unshare_pid}/children");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let text = std::fs::read_to_string(&children).unwrap_or_default();
        if let Some(pid) = text.split_whitespace().next() {
            return pid.parse().unwrap();
        }
        assert!(Instant::now() < deadline, "unshare never forked the daemon");
        thread::sleep(Duration::from_millis(10));
    }
}

/// C55-R2-1: as a PID namespace's init (a container's PID 1) the daemon still
/// closes the relay normally on SIGTERM / SIGINT, then exits with 128+signal.
/// The kernel drops a default-action signal that init sends itself, so
/// re-raising it would fall through to an abort instead of that exit status.
/// Skips (with a message) where unprivileged user namespaces are unavailable.
#[test]
fn c55_as_pid1_a_shutdown_signal_closes_normally_then_exits_128_plus_signal() {
    let probe = std::process::Command::new(PID1_WRAPPER[0])
        .args(&PID1_WRAPPER[1..])
        .arg("true")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !probe.as_ref().is_ok_and(|status| status.success()) {
        eprintln!(
            "SKIPPED c55 PID 1 signal test: `{}` is unavailable here ({probe:?})",
            PID1_WRAPPER.join(" ")
        );
        return;
    }
    for (sent, expected) in [("-TERM", SIGTERM), ("-INT", SIGINT)] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let temp = tempfile::tempdir().unwrap();
        let mut daemon = spawn_daemon_via(&PID1_WRAPPER, &listener, &temp);
        let tcp = accept(&listener, &mut daemon);
        let mut wire = establish(tcp);
        let init = namespace_init_pid(daemon.id());
        // The daemon really is PID 1 in its namespace (last NSpid entry).
        let status = std::fs::read_to_string(format!("/proc/{init}/status")).unwrap();
        let nspid = status
            .lines()
            .find(|line| line.starts_with("NSpid:"))
            .unwrap_or_default();
        assert_eq!(
            nspid.split_whitespace().last(),
            Some("1"),
            "{sent}: {nspid:?}"
        );
        signal(&init.to_string(), sent);
        let close = loop {
            match wire.read() {
                Ok(Message::Close(frame)) => break frame,
                Ok(_) => continue,
                Err(error) => panic!("{sent}: no normal close before the socket ended: {error}"),
            }
        };
        let close = close.expect("close frame");
        assert_eq!(close.code, CloseCode::Normal, "{sent}");
        assert_eq!(close.reason.as_str(), "daemon shutdown", "{sent}");
        // `unshare --fork` mirrors its child: an exit status stays an exit
        // status, a death by signal becomes unshare's own death by signal.
        let status = wait_for_exit(&mut daemon, Duration::from_secs(30));
        assert_eq!(
            status.code(),
            Some(128 + expected),
            "{sent}: PID 1 must exit 128+signal: {status:?}"
        );
    }
}

#[test]
fn journal_key_sentinel_never_reaches_actual_cli_stderr() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let temp = tempfile::tempdir().unwrap();
    let mut command = daemon_command(&[], &listener, &temp);
    command.stderr(Stdio::piped());
    let mut daemon = ManagedChild::spawn(&mut command).unwrap();
    let mut wire = tungstenite::accept_hdr(accept(&listener, &mut daemon), RelayHandshake).unwrap();
    let _host_hello: serde_json::Value =
        serde_json::from_str(wire.read().unwrap().to_text().unwrap()).unwrap();
    let mut hello: serde_json::Value = serde_json::from_str(include_str!(
        "../../../crates/sandbox-protocol/fixtures/control_hello_ok_server.json"
    ))
    .unwrap();
    hello["protocolVersion"] = serde_json::json!("1.0");
    hello["capabilities"]["protocolVersion"] = serde_json::json!("1.0");
    hello["supportedProtocolVersions"] = serde_json::json!(["1.0"]);
    hello["connectionEpoch"] = serde_json::json!(1);
    wire.send(Message::Text(hello.to_string().into())).unwrap();
    let sentinel = "ab".repeat(32);
    let mut install = serde_json::json!({"type":"journal.key.install", "connectionEpoch":1,
        "keyVersion":1,"keyId":"d".repeat(32),"keyHex":sentinel,
        "server":format!("ws://{}/ws/sandbox-host", listener.local_addr().unwrap()),
        "hostOwnerId":hello["hostOwnerId"], "hostId":"host-1"});
    wire.send(Message::Text(install.to_string().into()))
        .unwrap();
    let mut acknowledged = false;
    loop {
        let frame = wire.read().unwrap();
        let Ok(text) = frame.to_text() else { continue };
        match parse_daemon_control(text).unwrap() {
            DaemonControlMessage::JournalKeyAck { .. } => acknowledged = true,
            DaemonControlMessage::SandboxInventory { page, entries, .. } => {
                wire.send(Message::Text(
                    serde_json::json!({"type":"inventory.ack", "page":page,
                        "entryResults": entries.iter().map(|entry| serde_json::json!({
                            "sandboxId":entry.sandbox_id,"outcome":"converged"
                        })).collect::<Vec<_>>()})
                    .to_string()
                    .into(),
                ))
                .unwrap();
            }
            DaemonControlMessage::ReconcileComplete { .. } => {
                assert!(acknowledged);
                break;
            }
            _ => {}
        }
    }
    // Cover both successful install logging and the constant refusal path.
    install["hostOwnerId"] = serde_json::json!("wrong-owner");
    wire.send(Message::Text(install.to_string().into()))
        .unwrap();
    // A refused install keeps this socket alive. A subsequent env dispatch
    // proves it was processed and also clears the previously installed key.
    assert_env_dispatch_refused(&mut wire);
    wire.close(Some(tungstenite::protocol::CloseFrame {
        code: CloseCode::Library(4003),
        reason: "test done".into(),
    }))
    .unwrap();
    wait_for_exit(&mut daemon, Duration::from_secs(20));
    let output = daemon.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains(&sentinel));
    assert!(stderr.contains("invalid journal key binding"));
}

/// Security regression: the server derives the install binding from
/// BETTER_AUTH_URL, the daemon from its own --server URL. An alias of the same
/// server (localhost vs 127.0.0.1) must not stop the session from
/// reconciling: cleanup (sandbox.kill/stop) is supposed to work without a key.
#[test]
fn probe_server_alias_key_install_still_reconciles() {
    key_install_still_reconciles("alias");
}

#[test]
fn missing_or_invalid_key_install_still_reconciles() {
    for variant in ["missing", "invalid", "epoch", "owner", "host"] {
        key_install_still_reconciles(variant);
    }
}

fn key_install_still_reconciles(variant: &str) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let temp = tempfile::tempdir().unwrap();
    let mut command = daemon_command(&[], &listener, &temp);
    command.stderr(Stdio::piped());
    let mut daemon = ManagedChild::spawn(&mut command).unwrap();
    let mut wire = tungstenite::accept_hdr(accept(&listener, &mut daemon), RelayHandshake).unwrap();
    let _host_hello: serde_json::Value =
        serde_json::from_str(wire.read().unwrap().to_text().unwrap()).unwrap();
    let mut hello: serde_json::Value = serde_json::from_str(include_str!(
        "../../../crates/sandbox-protocol/fixtures/control_hello_ok_server.json"
    ))
    .unwrap();
    hello["protocolVersion"] = serde_json::json!("1.0");
    hello["capabilities"]["protocolVersion"] = serde_json::json!("1.0");
    hello["supportedProtocolVersions"] = serde_json::json!(["1.0"]);
    hello["connectionEpoch"] = serde_json::json!(1);
    wire.send(Message::Text(hello.to_string().into())).unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut install = serde_json::json!({"type":"journal.key.install", "connectionEpoch":1,
        "keyVersion":1,"keyId":"d".repeat(32),"keyHex":"ab".repeat(32),
        // Same server, reached through its BETTER_AUTH_URL alias.
        "server":format!("ws://localhost:{port}/ws/sandbox-host"),
        "hostOwnerId":hello["hostOwnerId"], "hostId":"host-1"});
    if variant != "alias" {
        install["server"] = serde_json::json!(format!(
            "ws://{}/ws/sandbox-host",
            listener.local_addr().unwrap()
        ));
    }
    match variant {
        "invalid" => install["keyHex"] = serde_json::json!("invalid"),
        "epoch" => install["connectionEpoch"] = serde_json::json!(2),
        "owner" => install["hostOwnerId"] = serde_json::json!("wrong-owner"),
        "host" => install["hostId"] = serde_json::json!("wrong-host"),
        _ => {}
    }
    if variant != "missing" {
        wire.send(Message::Text(install.to_string().into()))
            .unwrap();
    }
    let mut reconciled = false;
    let mut acknowledged = false;
    while let Ok(frame) = wire.read() {
        let Ok(text) = frame.to_text() else { continue };
        let Ok(message) = parse_daemon_control(text) else {
            continue;
        };
        match message {
            DaemonControlMessage::JournalKeyAck { .. } => acknowledged = true,
            DaemonControlMessage::SandboxInventory { page, entries, .. } => {
                wire.send(Message::Text(
                    serde_json::json!({"type":"inventory.ack", "page":page,
                        "entryResults": entries.iter().map(|entry| serde_json::json!({
                            "sandboxId":entry.sandbox_id,"outcome":"converged"
                        })).collect::<Vec<_>>()})
                    .to_string()
                    .into(),
                ))
                .unwrap();
            }
            DaemonControlMessage::ReconcileComplete { .. } => {
                reconciled = true;
                break;
            }
            _ => {}
        }
    }
    assert!(!acknowledged, "mismatched install must not be acknowledged");
    if reconciled {
        assert_env_dispatch_refused(&mut wire);
        // Key-free cleanup still reaches the runtime on the same connection.
        for (kind, id) in [("sandbox.kill", "kill"), ("sandbox.stop", "stop")] {
            let dispatch = serde_json::json!({"sandboxOwnerId":"owner", "type":"operation.dispatch", "operationId":id,
                "sandboxId":id, "kind":kind,"allocation":{"cpuCount":1,"memoryMiB":1024,"diskGiB":32,"storagePoolName":_host_hello["storagePools"][0]["name"],"storageMarker":_host_hello["storagePools"][0]["marker"],"chargedMemoryMiB":1280,"chargedVcpu":1,"rootChargeGiB":33}, "generation":1, "attempt":1,
                "idempotencyKey":id, "bodyHash":"a".repeat(64),
                "digestScheme":"sha256-env-free-v1"});
            wire.send(Message::Text(dispatch.to_string().into()))
                .unwrap();
            loop {
                let frame = wire.read().unwrap();
                let Ok(text) = frame.to_text() else { continue };
                match parse_daemon_control(text).unwrap() {
                    DaemonControlMessage::JournalKeyAck { .. } => panic!("unexpected key ACK"),
                    DaemonControlMessage::OperationProgress {
                        operation_id,
                        state,
                        ..
                    } if operation_id == id => {
                        assert_eq!(state, sandbox_protocol::OperationState::Accepted);
                        break;
                    }
                    DaemonControlMessage::OperationResult { operation_id, .. }
                        if operation_id == id =>
                    {
                        panic!("cleanup refused before acceptance: {text}");
                    }
                    _ => {}
                }
            }
        }
    }
    let _ = daemon.kill();
    let output = daemon.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        reconciled,
        "session never reconciled after a server-alias key install; stderr: {stderr}"
    );
}

/// No ACK may slip through before the pre-effect env refusal on this socket.
fn assert_env_dispatch_refused(wire: &mut tungstenite::WebSocket<TcpStream>) {
    let dispatch = serde_json::json!({"sandboxOwnerId":"owner", "type":"operation.dispatch", "operationId":"env-work",
        "sandboxId":"sbx", "kind":"command.run", "resultVersion":1, "processId":"proc-env-work", "generation":1, "attempt":1,
        "idempotencyKey":"env-work", "bodyHash":"a".repeat(64), "argv":["true"],
        "env":[["K","test-value"]], "digestScheme":"hmac-sha256-v1", "digestKeyId":"d".repeat(32)});
    wire.send(Message::Text(dispatch.to_string().into()))
        .unwrap();
    loop {
        let frame = wire.read().unwrap();
        let Ok(text) = frame.to_text() else { continue };
        match parse_daemon_control(text).unwrap() {
            DaemonControlMessage::JournalKeyAck { .. } => panic!("unexpected key ACK"),
            DaemonControlMessage::OperationProgress { .. } => {
                panic!("env work must not be accepted")
            }
            DaemonControlMessage::OperationResult {
                operation_id,
                state,
                error,
                ..
            } => {
                assert_eq!(operation_id, "env-work");
                assert_eq!(state, sandbox_protocol::OperationState::Failed);
                assert_eq!(
                    error.unwrap().code,
                    sandbox_protocol::SandboxErrorCode::DigestKeyUnavailable
                );
                break;
            }
            _ => {}
        }
    }
}

#[test]
fn private_config_sentinel_never_reaches_actual_cli_stderr() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let temp = tempfile::tempdir().unwrap();
    let mut command = daemon_command(&[], &listener, &temp);
    command.stderr(Stdio::piped());
    let mut daemon = ManagedChild::spawn(&mut command).unwrap();
    let mut wire = tungstenite::accept_hdr(accept(&listener, &mut daemon), RelayHandshake).unwrap();
    let _host_hello: serde_json::Value =
        serde_json::from_str(wire.read().unwrap().to_text().unwrap()).unwrap();
    let mut hello: serde_json::Value = serde_json::from_str(include_str!(
        "../../../crates/sandbox-protocol/fixtures/control_hello_ok_server.json"
    ))
    .unwrap();
    hello["protocolVersion"] = serde_json::json!("1.0");
    hello["capabilities"]["protocolVersion"] = serde_json::json!("1.0");
    hello["supportedProtocolVersions"] = serde_json::json!(["1.0"]);
    hello["connectionEpoch"] = serde_json::json!(1);
    wire.send(Message::Text(hello.to_string().into())).unwrap();
    let sentinel = "ab".repeat(32);
    let install = serde_json::json!({"type":"journal.key.install", "connectionEpoch":1,
        "keyVersion":1,"keyId":"d".repeat(32),"keyHex":sentinel,
        "server":format!("ws://{}/ws/sandbox-host", listener.local_addr().unwrap()),
        "hostOwnerId":hello["hostOwnerId"], "hostId":"host-1"});
    wire.send(Message::Text(install.to_string().into()))
        .unwrap();
    let mut acknowledged = false;
    loop {
        let frame = wire.read().unwrap();
        let Ok(text) = frame.to_text() else { continue };
        match parse_daemon_control(text).unwrap() {
            DaemonControlMessage::JournalKeyAck { .. } => acknowledged = true,
            DaemonControlMessage::SandboxInventory { page, entries, .. } => {
                wire.send(Message::Text(
                    serde_json::json!({"type":"inventory.ack", "page":page,
                        "entryResults": entries.iter().map(|entry| serde_json::json!({
                            "sandboxId":entry.sandbox_id,"outcome":"converged"
                        })).collect::<Vec<_>>()})
                    .to_string()
                    .into(),
                ))
                .unwrap();
            }
            DaemonControlMessage::ReconcileComplete { .. } => {
                assert!(acknowledged);
                break;
            }
            _ => {}
        }
    }
    let private_sentinel = "private-config-cli-stderr-sentinel";
    let mut config = serde_json::json!({"type":"private.config.install", "sandboxOwnerId":"owner", "connectionEpoch":1,
        "refusalToken":"config-install",
        "server":format!("ws://{}/ws/sandbox-host", listener.local_addr().unwrap()),
        "hostOwnerId":hello["hostOwnerId"], "hostId":"host-1", "sandboxId":"sbx", "generation":1,
        "config":{"configId":"config", "bindingScheme":"hmac-sha256-v1", "bindingKeyId":"d".repeat(32), "bindingMac":"c".repeat(64)},
        "env":[["K",private_sentinel]]});
    wire.send(Message::Text(config.to_string().into())).unwrap();
    loop {
        let frame = wire.read().unwrap();
        let Ok(text) = frame.to_text() else { continue };
        if let DaemonControlMessage::PrivateConfigAck(ack) = parse_daemon_control(text).unwrap() {
            assert_eq!(ack.config.binding_mac, "c".repeat(64));
            assert!(!text.contains("checksum"));
            break;
        }
    }
    // A malformed private frame gets no ACK, and a following valid reinstall
    // proves this same socket remains usable. Distinct IDs expose an extra ACK.
    config["config"]["configId"] = serde_json::json!("malformed-config");
    config["env"][0][1] = serde_json::json!({"malformed":private_sentinel});
    wire.send(Message::Text(config.to_string().into())).unwrap();
    config["config"]["configId"] = serde_json::json!("config");
    config["env"][0][1] = serde_json::json!(private_sentinel);
    wire.send(Message::Text(config.to_string().into())).unwrap();
    loop {
        let frame = wire
            .read()
            .expect("same connection survives malformed config");
        let Ok(text) = frame.to_text() else { continue };
        if let DaemonControlMessage::PrivateConfigAck(ack) = parse_daemon_control(text).unwrap() {
            assert_eq!(ack.config.config_id, "config", "malformed config was ACKed");
            break;
        }
    }
    wire.close(Some(tungstenite::protocol::CloseFrame {
        code: CloseCode::Library(4003),
        reason: "test done".into(),
    }))
    .unwrap();
    wait_for_exit(&mut daemon, Duration::from_secs(20));
    let output = daemon.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains(&sentinel));
    assert!(!stderr.contains(private_sentinel));
    assert_eq!(
        stderr
            .matches("invalid private config binding or install; config refused")
            .count(),
        1
    );
}

#[test]
fn invalid_private_config_install_still_reconciles_and_cleans_up() {
    for variant in [
        "alias",
        "missing-key",
        "unnegotiated",
        "epoch",
        "owner",
        "host",
        "key",
        "invalid",
        "malformed",
        "unknown-field",
        "size",
        "io",
    ] {
        private_config_install_still_reconciles(variant);
    }
}

fn private_config_install_still_reconciles(variant: &str) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let temp = tempfile::tempdir().unwrap();
    let mut command = daemon_command(&[], &listener, &temp);
    command.stderr(Stdio::piped());
    let mut daemon = ManagedChild::spawn(&mut command).unwrap();
    let mut wire = tungstenite::accept_hdr(accept(&listener, &mut daemon), RelayHandshake).unwrap();
    let _host_hello: serde_json::Value =
        serde_json::from_str(wire.read().unwrap().to_text().unwrap()).unwrap();
    let mut hello: serde_json::Value = serde_json::from_str(include_str!(
        "../../../crates/sandbox-protocol/fixtures/control_hello_ok_server.json"
    ))
    .unwrap();
    hello["protocolVersion"] = serde_json::json!("1.0");
    hello["capabilities"]["protocolVersion"] = serde_json::json!("1.0");
    hello["supportedProtocolVersions"] = serde_json::json!(["1.0"]);
    hello["connectionEpoch"] = serde_json::json!(1);
    let key = serde_json::json!({"type":"journal.key.install", "connectionEpoch":1,
        "keyVersion":1, "keyId":"d".repeat(32), "keyHex":"ab".repeat(32),
        "server":format!("ws://{}/ws/sandbox-host", listener.local_addr().unwrap()),
        "hostOwnerId":hello["hostOwnerId"], "hostId":"host-1"});
    let valid = serde_json::json!({"type":"private.config.install", "sandboxOwnerId":"owner", "connectionEpoch":1,
        "refusalToken":"config-install",
        "server":key["server"], "hostOwnerId":hello["hostOwnerId"], "hostId":"host-1",
        "sandboxId":"sbx", "generation":1,
        "config":{"configId":"config-good", "bindingScheme":"hmac-sha256-v1",
            "bindingKeyId":"d".repeat(32), "bindingMac":"c".repeat(64)},
        "env":[["K","private-config-f1-sentinel"]]});
    // A destination directory forces a real rename/persist error after temp
    // creation/write/fsync, independent of root privileges or chmod behavior.
    let configs_dir = temp
        .path()
        .join("data/relay")
        .join(wssp::sandbox_relay::journal::sha256_hex(b"host-1"))
        .join("private-configs");
    let blocker = configs_dir.join(format!(
        "{}.json",
        wssp::sandbox_relay::journal::sha256_hex(b"sbx")
    ));
    if variant == "io" {
        std::fs::create_dir(&blocker).unwrap();
    }
    let mut invalid = valid.clone();
    invalid["config"]["configId"] = serde_json::json!("config-refused");
    match variant {
        "alias" => {
            invalid["server"] = serde_json::json!(format!(
                "ws://localhost:{}/ws/sandbox-host",
                listener.local_addr().unwrap().port()
            ))
        }
        "epoch" => invalid["connectionEpoch"] = serde_json::json!(2),
        "owner" => invalid["hostOwnerId"] = serde_json::json!("wrong-owner"),
        "host" => invalid["hostId"] = serde_json::json!("wrong-host"),
        "key" => invalid["config"]["bindingKeyId"] = serde_json::json!("e".repeat(32)),
        "invalid" => invalid["generation"] = serde_json::json!(0),
        "malformed" => {
            invalid["env"][0][1] = serde_json::json!({"bad":"private-config-f1-sentinel"})
        }
        "unknown-field" => invalid["unknown"] = serde_json::json!("private-config-f1-sentinel"),
        "size" => invalid["env"][0][1] = serde_json::json!("x".repeat(4097)),
        _ => {}
    }
    if variant == "unnegotiated" {
        wire.send(Message::Text(invalid.to_string().into()))
            .unwrap();
    }
    wire.send(Message::Text(hello.to_string().into())).unwrap();
    let needs_key = !matches!(variant, "missing-key" | "unnegotiated");
    if needs_key {
        wire.send(Message::Text(key.to_string().into())).unwrap();
    }
    if variant != "unnegotiated" {
        // Queue before inventory ACK: the shared handler must also refuse
        // private installs while reconciliation is waiting for the server.
        wire.send(Message::Text(invalid.to_string().into()))
            .unwrap();
    }
    let mut key_acks = 0;
    loop {
        let frame = wire.read().unwrap_or_else(|error| {
            panic!("{variant}: session ended before reconciliation: {error}")
        });
        let Ok(text) = frame.to_text() else { continue };
        match parse_daemon_control(text).unwrap() {
            DaemonControlMessage::PrivateConfigAck(_) => {
                panic!("{variant}: refused config was ACKed")
            }
            DaemonControlMessage::JournalKeyAck { .. } => key_acks += 1,
            DaemonControlMessage::SandboxInventory { page, entries, .. } => wire
                .send(Message::Text(
                    serde_json::json!({"type":"inventory.ack", "page":page,
                        "entryResults": entries.iter().map(|entry| serde_json::json!({
                            "sandboxId":entry.sandbox_id,"outcome":"converged"
                        })).collect::<Vec<_>>()})
                    .to_string()
                    .into(),
                ))
                .unwrap(),
            DaemonControlMessage::ReconcileComplete { .. } => break,
            _ => {}
        }
    }
    assert_eq!(key_acks, usize::from(needs_key), "{variant}");
    if variant == "io" {
        // First refusal happened while reconciling; the next ones are handled
        // in the ordinary dispatch loop. A following cleanup is the barrier.
        for _ in 0..8 {
            wire.send(Message::Text(invalid.to_string().into()))
                .unwrap();
        }
    }
    if !needs_key {
        assert_env_dispatch_refused(&mut wire);
    }
    for (kind, id) in [("sandbox.kill", "kill"), ("sandbox.stop", "stop")] {
        let dispatch = serde_json::json!({"sandboxOwnerId":"owner", "type":"operation.dispatch", "operationId":id,
            "sandboxId":id, "kind":kind,"allocation":{"cpuCount":1,"memoryMiB":1024,"diskGiB":32,"storagePoolName":_host_hello["storagePools"][0]["name"],"storageMarker":_host_hello["storagePools"][0]["marker"],"chargedMemoryMiB":1280,"chargedVcpu":1,"rootChargeGiB":33}, "generation":1, "attempt":1,
            "idempotencyKey":id, "bodyHash":"a".repeat(64), "digestScheme":"sha256-env-free-v1"});
        wire.send(Message::Text(dispatch.to_string().into()))
            .unwrap();
        let mut accepted = false;
        loop {
            let frame = wire.read().expect("same connection permits cleanup");
            let Ok(text) = frame.to_text() else { continue };
            match parse_daemon_control(text).unwrap() {
                DaemonControlMessage::PrivateConfigAck(_) => {
                    panic!("{variant}: refused config was ACKed")
                }
                DaemonControlMessage::OperationProgress {
                    operation_id,
                    state,
                    ..
                } if operation_id == id => {
                    assert_eq!(state, sandbox_protocol::OperationState::Accepted);
                    accepted = true;
                    if variant != "io" {
                        break;
                    }
                }
                DaemonControlMessage::OperationResult {
                    operation_id,
                    state,
                    result,
                    ..
                } if operation_id == id => {
                    if variant == "io" {
                        // WP2: a failed config write latches the journal-wide
                        // IO flag, which closes admission (cleanup included)
                        // until a restart re-reads the journal.
                        assert!(!accepted, "{variant}: a latched journal admitted {kind}");
                        assert_eq!(state, sandbox_protocol::OperationState::Failed, "{text}");
                        break;
                    }
                    assert!(
                        accepted,
                        "{variant}: cleanup refused before acceptance: {text}"
                    );
                    assert_eq!(state, sandbox_protocol::OperationState::Succeeded, "{text}");
                    assert_eq!(
                        result.unwrap()["state"],
                        if kind == "sandbox.kill" {
                            "deleted"
                        } else {
                            "absent"
                        }
                    );
                    break;
                }
                _ => {}
            }
        }
    }
    if variant == "io" {
        assert_eq!(
            std::fs::read_dir(&configs_dir).unwrap().count(),
            1,
            "no failed-install temp files remain"
        );
        std::fs::remove_dir(&blocker).unwrap();
    }
    // A valid install for the same sandbox with a different config ID can
    // succeed only if the refused install left no retained config behind.
    if !needs_key {
        wire.send(Message::Text(key.to_string().into())).unwrap();
    }
    wire.send(Message::Text(valid.to_string().into())).unwrap();
    loop {
        let frame = wire.read().expect("same connection permits valid config");
        let Ok(text) = frame.to_text() else { continue };
        if let DaemonControlMessage::PrivateConfigAck(ack) = parse_daemon_control(text).unwrap() {
            assert_eq!(ack.config.config_id, "config-good", "{variant}");
            break;
        }
    }
    wire.close(Some(tungstenite::protocol::CloseFrame {
        code: CloseCode::Library(4003),
        reason: "test done".into(),
    }))
    .unwrap();
    wait_for_exit(&mut daemon, Duration::from_secs(20));
    let output = daemon.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("private-config-f1-sentinel"));
    assert!(!stderr.contains(&"ab".repeat(32)));
    assert_eq!(
        stderr
            .matches(if variant == "io" {
                "private config journal IO failed; config refused"
            } else {
                "invalid private config binding or install; config refused"
            })
            .count(),
        if variant == "io" { 9 } else { 1 },
        "{variant}: {stderr}"
    );
    assert_eq!(
        stderr.contains("host journal write failed"),
        variant == "io",
        "{variant}: the journal IO latch is logged once it trips: {stderr}"
    );
    assert!(!stderr.contains(&configs_dir.to_string_lossy().to_string()));
}
