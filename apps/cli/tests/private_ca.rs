//! Real CLI processes and loopback TLS: no external services or live runtimes.
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};
use std::thread;
use std::time::{Duration, Instant};

use assert_cmd::Command;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

#[path = "../test-support/certificates.rs"]
mod certificates;
static CERTIFICATES: LazyLock<certificates::Certificates> = LazyLock::new(certificates::generate);

fn fixture(name: &str) -> PathBuf {
    assert_eq!(name, "ca.pem");
    static CA_DIR: LazyLock<tempfile::TempDir> = LazyLock::new(|| {
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path().join("ca.pem");
        std::fs::write(&ca, &CERTIFICATES.ca_pem).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::set_permissions(ca, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        dir
    });
    CA_DIR.path().join(name)
}

fn cli(dir: &Path) -> Command {
    let mut cmd = Command::cargo_bin("wssp").unwrap();
    cmd.env("WSSP_CONFIG_DIR", dir.join("config"))
        .env("WSSP_DATA_DIR", dir.join("data"))
        .env(
            "WSSP_TLS_TEST_TOKEN",
            format!("wssp_host_{}", "a".repeat(43)),
        )
        .env_remove("WSSP_CA_FILE")
        .env_remove("WSSP_LOG")
        .env_remove("RUST_LOG")
        // Do not let the machine's proxy settings redirect local TLS tests.
        .env_remove("HTTPS_PROXY")
        .env_remove("https_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy")
        .env("NO_PROXY", "localhost,127.0.0.1")
        .timeout(Duration::from_secs(12));
    cmd
}

fn accept(listener: &TcpListener) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                return stream;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "CLI did not dial the TLS test server"
                );
                thread::sleep(Duration::from_millis(10));
            }
            Err(e) => panic!("accept: {e}"),
        }
    }
}

fn tls(listener: &TcpListener) -> rustls::StreamOwned<rustls::ServerConnection, TcpStream> {
    let cert = CertificateDer::from(CERTIFICATES.leaf.clone());
    let key = PrivatePkcs8KeyDer::from(CERTIFICATES.leaf_key.clone()).into();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)
    .unwrap();
    rustls::StreamOwned::new(
        rustls::ServerConnection::new(Arc::new(config)).unwrap(),
        accept(listener),
    )
}

struct RelayHandshake;
impl tungstenite::handshake::server::Callback for RelayHandshake {
    fn on_request(
        self,
        _: &tungstenite::handshake::server::Request,
        mut response: tungstenite::handshake::server::Response,
    ) -> Result<
        tungstenite::handshake::server::Response,
        tungstenite::handshake::server::ErrorResponse,
    > {
        response.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            sandbox_protocol::SANDBOX_RELAY_SUBPROTOCOL.parse().unwrap(),
        );
        Ok(response)
    }
}

fn websocket(listener: &TcpListener) -> bool {
    let Ok(mut socket) = tungstenite::accept_hdr(tls(listener), RelayHandshake) else {
        return false;
    };
    let hello = socket.read().unwrap();
    assert!(hello.to_text().unwrap().contains("\"type\":\"hello\""));
    // 4003 is the only server close that ends the daemon (any other close
    // reconnects): no reconnect or guest work. The process exits with code 4.
    socket
        .close(Some(tungstenite::protocol::CloseFrame {
            code: tungstenite::protocol::frame::coding::CloseCode::Library(4003),
            reason: "credential_inactive".into(),
        }))
        .unwrap();
    let _ = socket.read();
    true
}

#[test]
fn private_ca_wss_handshake_requires_ca_file_and_checks_hostname() {
    for (selection, host, succeeds) in [
        ("flag", "localhost", true),
        ("env", "localhost", true),
        ("config", "localhost", true),
        ("none", "localhost", false),
        ("flag", "127.0.0.1", true),
        ("flag", "127.0.0.2", false),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let bind = if host == "127.0.0.2" {
            "127.0.0.2:0"
        } else {
            "127.0.0.1:0"
        };
        let listener = TcpListener::bind(bind).unwrap();
        let origin = format!("https://{host}:{}", listener.local_addr().unwrap().port());
        let server = thread::spawn(move || websocket(&listener));
        let mut cmd = cli(dir.path());
        if selection == "config" {
            cli(dir.path())
                .args(["config", "set-ca-file"])
                .arg(fixture("ca.pem"))
                .assert()
                .success();
        }
        cmd.args([
            "connect",
            "--runtime",
            "fake",
            "--server",
            &origin,
            "--host-token-env",
            "WSSP_TLS_TEST_TOKEN",
            "--host-id",
            "tls-host",
        ]);
        match selection {
            "flag" => {
                cmd.arg("--ca-file").arg(fixture("ca.pem"));
            }
            "env" => {
                cmd.env("WSSP_CA_FILE", fixture("ca.pem"));
            }
            _ => {}
        }
        if succeeds {
            // The handshake succeeded; the test server then ended the session.
            cmd.assert().code(4);
        } else {
            cmd.assert()
                .failure()
                .stderr(predicates::str::contains(&origin))
                .stderr(predicates::str::contains("certificate is not trusted"))
                .stderr(predicates::str::contains("--ca-file <path>"))
                .stderr(predicates::str::contains("WSSP_CA_FILE"));
        }
        assert_eq!(server.join().unwrap(), succeeds, "{selection}/{host}");
    }
}

fn http_request(listener: &TcpListener, response: &str) -> Option<String> {
    let mut stream = tls(listener);
    let mut bytes = Vec::new();
    let mut byte = [0];
    while !bytes.ends_with(b"\r\n\r\n") {
        if stream.read_exact(&mut byte).is_err() {
            return None;
        }
        bytes.push(byte[0]);
        assert!(bytes.len() < 16 * 1024);
    }
    let headers = String::from_utf8(bytes).unwrap();
    let length: usize = headers
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().unwrap())
        })
        .unwrap_or(0);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).unwrap();
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
        response.len()
    );
    stream.write_all(response.as_bytes()).unwrap();
    stream.flush().unwrap();
    Some(headers)
}

#[test]
fn private_ca_https_login_start_exchange_and_persisted_restart() {
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let server = thread::spawn(move || {
        let start = serde_json::json!({"device_code":"test-code", "user_code":"TEST", "verification_uri":"https://localhost/device", "expires_in":60, "interval":1}).to_string();
        assert!(
            http_request(&listener, &start)
                .unwrap()
                .starts_with("POST /api/auth/device/code ")
        );
        let exchange = serde_json::json!({"json":{"credentialId":"credential-tls", "userId":"owner-tls", "hostId":"tls-host", "secret":format!("wssp_device_{}", "a".repeat(43))}}).to_string();
        assert!(
            http_request(&listener, &exchange)
                .unwrap()
                .starts_with("POST /rpc/hostCredentials/exchangeDeviceCode ")
        );
        assert!(websocket(&listener));
    });
    cli(dir.path())
        .args([
            "login",
            "--slug",
            "tls-host",
            "--server",
            &origin,
            "--ca-file",
        ])
        .arg(fixture("ca.pem"))
        .assert()
        .success();
    let output = cli(dir.path())
        .args(["config", "show", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let saved: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(
        saved["caFile"],
        fixture("ca.pem").canonicalize().unwrap().to_str().unwrap()
    );
    // A separate process has neither --server nor --ca-file nor WSSP_CA_FILE.
    cli(dir.path())
        .args(["connect", "--runtime", "fake"])
        .assert()
        // The handshake succeeded; the test server then ended the session.
        .code(4);
    server.join().unwrap();
}

#[test]
fn private_ca_https_drain_and_undrain_require_extra_trust() {
    for command in ["drain", "undrain"] {
        for with_ca in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let origin = format!(
                "https://localhost:{}",
                listener.local_addr().unwrap().port()
            );
            let server = thread::spawn(move || {
                let response = serde_json::json!({"id":"tls-host", "draining":command == "drain", "liveSandboxCount":0, "drained":command == "drain", "offload":false}).to_string();
                let request = http_request(&listener, &response);
                if let Some(headers) = &request {
                    assert!(headers.starts_with("POST /api/sandbox-host/drain "));
                }
                request.is_some()
            });
            let mut cmd = cli(dir.path());
            cmd.args([
                command,
                "--server",
                &origin,
                "--host-token-env",
                "WSSP_TLS_TEST_TOKEN",
                "--host-id",
                "tls-host",
            ]);
            if with_ca {
                cmd.arg("--ca-file")
                    .arg(fixture("ca.pem"))
                    .assert()
                    .success();
            } else {
                cmd.assert()
                    .failure()
                    .stderr(predicates::str::contains(&origin))
                    .stderr(predicates::str::contains("certificate is not trusted"))
                    .stderr(predicates::str::contains("--ca-file <path>"))
                    .stderr(predicates::str::contains("WSSP_CA_FILE"));
            }
            assert_eq!(server.join().unwrap(), with_ca);
        }
    }
}

#[test]
fn every_dialing_command_fails_closed_on_invalid_ca_selection() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.pem");
    for args in [
        vec!["connect", "--runtime", "fake"],
        vec!["login", "--slug", "tls-host"],
        vec!["drain"],
        vec!["undrain"],
    ] {
        cli(dir.path())
            .args(&args)
            .arg("--ca-file")
            .arg(&missing)
            .assert()
            .failure()
            .stderr(predicates::str::contains("cannot read CA file"));
        cli(dir.path())
            .args(&args)
            .env("WSSP_CA_FILE", &missing)
            .assert()
            .failure()
            .stderr(predicates::str::contains("cannot read CA file"));
    }
    // An explicit flag overrides a broken environment selection.
    cli(dir.path())
        .args(["drain", "--ca-file"])
        .arg(fixture("ca.pem"))
        .env("WSSP_CA_FILE", &missing)
        .assert()
        .failure()
        .stderr(predicates::str::contains("server URL is not configured"));
}

#[test]
fn environment_ca_on_login_is_not_persisted() {
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let server = thread::spawn(move || {
        let start = serde_json::json!({"device_code":"test-code", "user_code":"TEST", "verification_uri":"https://localhost/device", "expires_in":60, "interval":1}).to_string();
        assert!(http_request(&listener, &start).is_some());
        let exchange = serde_json::json!({"json":{"credentialId":"credential-tls", "userId":"owner-tls", "hostId":"tls-host", "secret":format!("wssp_device_{}", "a".repeat(43))}}).to_string();
        assert!(http_request(&listener, &exchange).is_some());
    });
    cli(dir.path())
        .args(["login", "--slug", "tls-host", "--server", &origin])
        .env("WSSP_CA_FILE", fixture("ca.pem"))
        .assert()
        .success();
    server.join().unwrap();
    let output = cli(dir.path())
        .args(["config", "show", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let saved: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert!(saved["caFile"].is_null());
}

#[test]
fn e47_login_missing_ca_names_server_and_trust_options() {
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let server = thread::spawn(move || http_request(&listener, "{}").is_some());
    cli(dir.path())
        .args(["login", "--slug", "tls-host", "--server", &origin])
        .assert()
        .failure()
        .stderr(predicates::str::contains(&origin))
        .stderr(predicates::str::contains("certificate is not trusted"))
        .stderr(predicates::str::contains("--ca-file <path>"))
        .stderr(predicates::str::contains("WSSP_CA_FILE"));
    assert!(!server.join().unwrap());
}
