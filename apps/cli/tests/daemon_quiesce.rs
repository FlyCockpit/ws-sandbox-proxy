//! WP7 graceful quiesce against the real binaries: `wssp connect` (fake
//! runtime, loopback relay fixture; no Incus) and `wssp daemon quiesce`.
#![cfg(target_os = "linux")]

use std::net::{TcpListener, TcpStream};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
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

fn wssp(temp: &tempfile::TempDir) -> std::process::Command {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_wssp"));
    command
        .env("WSSP_CONFIG_DIR", temp.path().join("config"))
        .env("WSSP_DATA_DIR", temp.path().join("data"))
        .env_remove("WSSP_LOG")
        .env_remove("RUST_LOG")
        .env_remove("WSSP_RUNTIME")
        .env_remove("WSSP_TEST_RELAY_TIMING")
        .env_remove("MAINPID")
        .stdin(Stdio::null());
    command
}

fn spawn_daemon(listener: &TcpListener, temp: &tempfile::TempDir) -> ManagedChild {
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let mut command = wssp(temp);
    command
        .args([
            "connect",
            "--server",
            &origin,
            "--host-id",
            "host-1",
            "--host-token-env",
            "WSSP_QUIESCE_TEST_TOKEN",
            "--runtime",
            "fake",
        ])
        .env(
            "WSSP_QUIESCE_TEST_TOKEN",
            format!("wssp_host_{}", "Q".repeat(43)),
        )
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    ManagedChild::spawn(&mut command).expect("spawn wssp connect")
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

/// Plays the server through hello (answering with `quiesce` negotiated) and
/// the post-hello census. Returns the socket and the daemon's hello.
fn establish(
    listener: &TcpListener,
    daemon: &mut ManagedChild,
    epoch: u64,
) -> (tungstenite::WebSocket<TcpStream>, serde_json::Value) {
    let tcp = accept(listener, daemon);
    let mut wire = tungstenite::accept_hdr(tcp, RelayHandshake).expect("relay handshake");
    let hello: serde_json::Value =
        serde_json::from_str(wire.read().expect("hello").to_text().unwrap()).unwrap();
    let mut ack: serde_json::Value = serde_json::from_str(include_str!(
        "../../../crates/sandbox-protocol/fixtures/control_hello_ok_server.json"
    ))
    .unwrap();
    ack["capabilities"]["quiesce"] = serde_json::json!(true);
    ack["connectionEpoch"] = serde_json::json!(epoch);
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
            // A reconnect audits the server's dispatches first.
            DaemonControlMessage::DispatchAuditRequest { page } => wire
                .send(Message::Text(
                    serde_json::json!({"type": "dispatch.audit.page", "page": page,
                        "complete": true, "entries": []})
                    .to_string()
                    .into(),
                ))
                .unwrap(),
            DaemonControlMessage::ReconcileComplete { .. } => return (wire, hello),
            _ => {}
        }
    }
}

/// The running daemon's control file, once written.
fn control_file(temp: &tempfile::TempDir) -> PathBuf {
    let relay = temp.path().join("data").join("relay");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(path) = std::fs::read_dir(&relay).ok().and_then(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path().join("daemon.json"))
                .find(|path| path.exists())
        }) {
            return path;
        }
        assert!(Instant::now() < deadline, "no control file");
        thread::sleep(Duration::from_millis(10));
    }
}

/// Reads frames until `host.quiesce`; returns its `connectionEpoch`.
fn read_host_quiesce(wire: &mut tungstenite::WebSocket<TcpStream>) -> u64 {
    loop {
        let frame = wire.read().expect("host.quiesce");
        let Ok(text) = frame.to_text() else { continue };
        let value: serde_json::Value = serde_json::from_str(text).unwrap();
        if value["type"] == "host.quiesce" {
            assert_eq!(value["sequence"], 1);
            return value["connectionEpoch"].as_u64().unwrap();
        }
    }
}

fn read_close(wire: &mut tungstenite::WebSocket<TcpStream>) -> Vec<String> {
    let mut types = Vec::new();
    loop {
        match wire.read() {
            Ok(Message::Close(frame)) => {
                let frame = frame.expect("close frame");
                assert_eq!(frame.code, CloseCode::Normal);
                assert_eq!(frame.reason.as_str(), "daemon shutdown");
                return types;
            }
            Ok(Message::Text(text)) => {
                let value: serde_json::Value = serde_json::from_str(&text).unwrap();
                types.push(value["type"].as_str().unwrap_or_default().to_owned());
            }
            Ok(_) => {}
            Err(error) => panic!("no normal close before the socket ended: {error}"),
        }
    }
}

fn quiesce_command(
    temp: &tempfile::TempDir,
    pid: Option<u32>,
    main_pid: Option<u32>,
) -> std::process::Output {
    let mut command = wssp(temp);
    command.args(["daemon", "quiesce"]);
    if let Some(pid) = pid {
        command.args(["--pid", &pid.to_string()]);
    }
    if let Some(main_pid) = main_pid {
        command.env("MAINPID", main_pid.to_string());
    }
    command.output().expect("run wssp daemon quiesce")
}

/// The full path: `wssp daemon quiesce` signals the verified daemon; it
/// sends `host.quiesce`; the connection drops before any ack; the reconnect
/// hello carries `quiescing: true` and its registration counts as the ack;
/// with no command running the daemon closes normally, exits 0 and removes
/// its control file.
#[test]
fn wp7_quiesce_survives_a_reconnect_and_exits_zero() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let temp = tempfile::tempdir().unwrap();
    let mut daemon = spawn_daemon(&listener, &temp);
    let (mut wire, hello) = establish(&listener, &mut daemon, 1);
    assert_eq!(hello["daemon"]["capabilities"]["quiesce"], true);
    assert!(hello.get("quiescing").is_none(), "{hello}");
    let control = control_file(&temp);
    let output = quiesce_command(&temp, Some(daemon.id()), None);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(read_host_quiesce(&mut wire), 1);
    // The server goes away before acknowledging.
    drop(wire);
    let (mut wire, hello) = establish(&listener, &mut daemon, 2);
    assert_eq!(hello["quiescing"], true, "{hello}");
    let frames = read_close(&mut wire);
    assert!(
        !frames.iter().any(|t| t == "host.quiesce"),
        "the quiescing hello was the ack: {frames:?}"
    );
    let status = wait_for_exit(&mut daemon, Duration::from_secs(30));
    assert_eq!(status.code(), Some(0), "{status:?}");
    assert!(!control.exists(), "the control file goes at exit");
}

/// SIGUSR1 never takes the first-signal slot: a SIGTERM during the quiesce
/// still ends the daemon gracefully, by SIGTERM.
#[test]
fn wp7_sigterm_still_works_while_quiescing() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let temp = tempfile::tempdir().unwrap();
    let mut daemon = spawn_daemon(&listener, &temp);
    let (mut wire, _) = establish(&listener, &mut daemon, 1);
    control_file(&temp);
    signal(daemon.id(), "-USR1");
    read_host_quiesce(&mut wire);
    thread::sleep(Duration::from_millis(200));
    assert!(
        daemon.try_wait().unwrap().is_none(),
        "no ack yet: still quiescing"
    );
    signal(daemon.id(), "-TERM");
    read_close(&mut wire);
    let status = wait_for_exit(&mut daemon, Duration::from_secs(30));
    assert_eq!(status.signal(), Some(SIGTERM), "{status:?}");
}

fn signal(pid: u32, signal: &str) {
    let status = std::process::Command::new("kill")
        .args([signal, "--", &pid.to_string()])
        .status()
        .expect("spawn kill");
    assert!(status.success(), "kill {signal} {pid}: {status}");
}

fn sleeper() -> ManagedChild {
    ManagedChild::spawn(
        std::process::Command::new("sleep")
            .arg("60")
            .stdin(Stdio::null())
            .process_group(0),
    )
    .expect("spawn sleep")
}

/// An older daemon (no control file) under systemd restarts with SIGTERM;
/// a manual run never signals a process it cannot verify, and without
/// `$MAINPID` or `--pid` it refuses.
#[test]
fn wp7_unverified_targets_get_sigterm_only_from_systemd() {
    let temp = tempfile::tempdir().unwrap();
    let mut old = sleeper();
    let manual = quiesce_command(&temp, Some(old.id()), None);
    assert!(!manual.status.success(), "{manual:?}");
    assert!(
        String::from_utf8_lossy(&manual.stderr).contains("nothing sent"),
        "{manual:?}"
    );
    let missing = quiesce_command(&temp, None, None);
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("MAINPID"));
    thread::sleep(Duration::from_millis(100));
    assert!(old.try_wait().unwrap().is_none(), "nothing was signalled");

    let managed = quiesce_command(&temp, None, Some(old.id()));
    assert!(managed.status.success(), "{managed:?}");
    let status = wait_for_exit(&mut old, Duration::from_secs(10));
    assert_eq!(status.signal(), Some(SIGTERM), "{status:?}");
}

/// A control file that is a symlink is never followed: under systemd the
/// daemon restarts with SIGTERM rather than SIGUSR1.
#[test]
fn wp7_a_symlinked_control_file_is_refused() {
    let temp = tempfile::tempdir().unwrap();
    let mut target = sleeper();
    let dir = temp.path().join("data").join("relay").join("host");
    std::fs::create_dir_all(&dir).unwrap();
    let real = temp.path().join("forged.json");
    let start = std::fs::read_to_string(format!("/proc/{}/stat", target.id())).unwrap();
    let start_time = start[start.rfind(')').unwrap() + 1..]
        .split_whitespace()
        .nth(19)
        .unwrap()
        .to_owned();
    std::fs::write(
        &real,
        format!(
            r#"{{"pid":{},"startTime":{start_time},"version":"0","features":["quiesce"]}}"#,
            target.id()
        ),
    )
    .unwrap();
    set_private(&real);
    std::os::unix::fs::symlink(&real, dir.join("daemon.json")).unwrap();
    let output = quiesce_command(&temp, None, Some(target.id()));
    assert!(output.status.success(), "{output:?}");
    // SIGUSR1's default action would also kill `sleep`; SIGTERM proves the
    // fallback was chosen.
    let status = wait_for_exit(&mut target, Duration::from_secs(10));
    assert_eq!(status.signal(), Some(SIGTERM), "{status:?}");
}

fn set_private(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}
