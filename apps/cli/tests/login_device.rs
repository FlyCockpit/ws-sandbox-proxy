//! Real binary, closed stdin, loopback-only probes adapted from C20 review.
use serde_json::{Value, json};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

const ISSUE: &str = "/api/auth/device/code";
const EXCHANGE: &str = "/rpc/hostCredentials/exchangeDeviceCode";
fn secret() -> String {
    format!("wssp_device_{}", "A".repeat(43))
}
fn host_secret() -> String {
    format!("wssp_host_{}", "B".repeat(43))
}
fn issued(expiry: u64, interval: u64) -> Value {
    json!({"device_code":"test-code", "user_code":"TEST-CODE", "verification_uri":"https://web.example.test/en-US/device", "expires_in":expiry,"interval":interval})
}
fn success() -> Value {
    json!({"json":{"credentialId":"credential-1","userId":"user-1","hostId":"host-1","secret":secret()}})
}
fn error(code: &str, tag: Option<&str>) -> Value {
    let mut data = json!({"retryAfterSeconds":1});
    if let Some(tag) = tag {
        data["deviceFlowError"] = tag.into();
    }
    json!({"json":{"code":code,"message":"fixture rejection","data":data}})
}
#[derive(Clone)]
struct Reply {
    status: u16,
    body: String,
    location: Option<String>,
    stall: Option<&'static str>,
}
fn reply(status: u16, body: Value) -> Reply {
    Reply {
        status,
        body: body.to_string(),
        location: None,
        stall: None,
    }
}
struct Server {
    url: String,
    requests: Arc<Mutex<Vec<(String, Instant)>>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}
impl Server {
    fn new(handler: impl Fn(usize, &str) -> Reply + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let capture = requests.clone();
        let done = stop.clone();
        let handle = thread::spawn(move || {
            while !done.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => panic!("accept: {e}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let request = read_request(&mut stream);
                let index = {
                    let mut guard = capture.lock().unwrap();
                    let index = guard.len();
                    guard.push((request.clone(), Instant::now()));
                    index
                };
                let response = handler(index, &request);
                if response.stall != Some("headers") {
                    let location = response
                        .location
                        .map(|url| format!("Location: {url}\r\n"))
                        .unwrap_or_default();
                    let header = format!(
                        "HTTP/1.1 {} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{location}Connection: close\r\n\r\n",
                        response.status,
                        response.body.len()
                    );
                    let _ = stream.write_all(header.as_bytes());
                    if response.stall.is_none() {
                        let _ = stream.write_all(response.body.as_bytes());
                    }
                }
                if response.stall.is_some() {
                    while !done.load(Ordering::SeqCst) {
                        thread::sleep(Duration::from_millis(5));
                    }
                }
            }
        });
        Self {
            url,
            requests,
            stop,
            handle: Some(handle),
        }
    }
    fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let joined = self.handle.take().unwrap().join();
        if !thread::panicking() {
            joined.unwrap();
        }
    }
}
fn read_request(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    loop {
        let mut buffer = [0; 4096];
        let n = stream.read(&mut buffer).unwrap_or(0);
        if n == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..n]);
        if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            let length = String::from_utf8_lossy(&bytes[..end])
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            if bytes.len() >= end + 4 + length {
                break;
            }
        }
    }
    String::from_utf8(bytes).unwrap()
}
fn command(root: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_wssp"));
    cmd.args(args)
        .env("WSSP_CONFIG_DIR", root.join("config"))
        .env("WSSP_DATA_DIR", root.join("data"))
        // Never the machine's own egress guard: an empty stand-in for `/`.
        .env("WSSP_TEST_GUARD_ROOT", root.join("guard-root"))
        .env_remove("WSSP_LOG")
        .env_remove("RUST_LOG")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy")
        .env_remove("HTTP_PROXY")
        .env_remove("http_proxy")
        .env_remove("HTTPS_PROXY")
        .env_remove("https_proxy")
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}
#[path = "../../../crates/sandbox-runtime/tests/support/managed_child.rs"]
mod managed_child;
use managed_child::ManagedChild;

fn run(mut cmd: Command) -> Output {
    let mut child: ManagedChild = ManagedChild::spawn(&mut cmd).unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let stdout = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).unwrap();
        bytes
    });
    let stderr = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).unwrap();
        bytes
    });
    let deadline = Instant::now() + Duration::from_secs(18);
    let mut expired = false;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            expired = true;
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let output = Output {
        status: child.wait().unwrap(),
        stdout: stdout.join().unwrap(),
        stderr: stderr.join().unwrap(),
    };
    assert!(
        !expired,
        "CLI exceeded test deadline: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn login(root: &Path, server: &Server) -> Output {
    run(command(
        root,
        &["-vv", "login", "--slug", "desk-01", "--server", &server.url],
    ))
}
fn assert_clean_output(out: &Output) {
    for bytes in [&out.stdout, &out.stderr] {
        let text = String::from_utf8_lossy(bytes);
        assert!(
            !text.contains(&"A".repeat(20)),
            "secret suffix leaked across log records"
        );
        assert!(!text.contains("4141 4141"), "hex-encoded secret leaked");
        for fixture in [
            secret(),
            host_secret(),
            format!("wssp_sdk_{}", "C".repeat(43)),
        ] {
            assert!(!text.contains(&fixture), "credential leaked");
        }
    }
}
fn state(root: &Path) -> Value {
    serde_json::from_slice(&fs::read(root.join("data/device-auth.json")).unwrap()).unwrap()
}

#[cfg(unix)]
#[test]
fn closed_stdin_login_pending_then_success_logout_and_source_switch() {
    let server = Server::new(|i, request| match i {
        0 => {
            assert!(request.starts_with(&format!("POST {ISSUE}")));
            assert!(request.contains("host-slug:desk-01"));
            reply(200, issued(30, 1))
        }
        1 => {
            assert!(request.starts_with(&format!("POST {EXCHANGE}")));
            assert!(request.contains("x-csrf-token: orpc"));
            let body: Value =
                serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
            assert_eq!(
                body,
                json!({"json":{"deviceCode":"test-code","hostSlug":"desk-01"}})
            );
            reply(400, error("BAD_REQUEST", Some("authorization_pending")))
        }
        2 => reply(200, success()),
        _ => reply(401, error("UNAUTHORIZED", None)),
    });
    let root = tempfile::tempdir().unwrap();
    let mut token = command(root.path(), &["token", "login", "WSSP_TEST_HOST_TOKEN"]);
    token.env("WSSP_TEST_HOST_TOKEN", host_secret());
    assert!(run(token).status.success());
    let out = login(root.path(), &server);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_clean_output(&out);
    assert!(String::from_utf8_lossy(&out.stdout).contains("https://web.example.test"));
    let stored = state(root.path());
    assert_eq!(stored["origin"], format!("{}/", server.url));
    assert_eq!(stored["hostId"], "host-1");
    let config = fs::read_to_string(root.path().join("config/config.toml")).unwrap();
    assert!(!config.contains("host_token_env"));
    assert!(!config.contains(&secret()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(root.path().join("data"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(root.path().join("data/device-auth.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let connect = run(command(
        root.path(),
        &["-vv", "connect", "--runtime", "fake"],
    ));
    assert!(!connect.status.success());
    assert_clean_output(&connect);
    let requests = server.requests.lock().unwrap();
    assert_eq!(requests.len(), 4);
    assert!(requests[3].0.contains(&format!("Bearer {}", secret())));
    drop(requests);
    for _ in 0..2 {
        let out = run(command(root.path(), &["logout", "--json"]));
        assert!(out.status.success());
        assert_clean_output(&out);
    }
    assert!(!root.path().join("data/device-auth.json").exists());
    let connect = run(command(root.path(), &["connect", "--runtime", "fake"]));
    assert!(!connect.status.success());
    assert_eq!(server.count(), 4);
}

#[test]
fn login_node_setup_sets_consent_by_flag_never_prompts_without_a_tty_and_hints_the_guard() {
    let server = || {
        Server::new(|i, _| match i {
            0 => reply(200, issued(30, 1)),
            1 => reply(200, success()),
            _ => reply(401, error("UNAUTHORIZED", None)),
        })
    };
    // No flag, no TTY (stdin is /dev/null): no prompt, consent stays unset.
    let root = tempfile::tempdir().unwrap();
    let fixture = server();
    let out = run(command(
        root.path(),
        &[
            "login",
            "--slug",
            "desk-01",
            "--server",
            &fixture.url,
            "--json",
        ],
    ));
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("[y/N]"));
    let done: Value = serde_json::from_str(stdout.lines().last().unwrap()).unwrap();
    assert!(done["openEgressForOthers"].is_null());
    assert_eq!(done["guard"]["installed"], false);
    assert_eq!(done["guard"]["ok"], false);
    assert_eq!(done["guard"]["reason"], "guard_unreachable");
    let install = done["guardInstallCommand"].as_str().unwrap();
    assert!(install.starts_with("sudo ") && install.contains(" guard install --daemon-user "));
    let config = fs::read_to_string(root.path().join("config/config.toml")).unwrap_or_default();
    assert!(!config.contains("allow_open_egress_for_others"));

    // The flag persists the answer; text output prints the install command.
    let root = tempfile::tempdir().unwrap();
    let fixture = server();
    let out = run(command(
        root.path(),
        &[
            "login",
            "--slug",
            "desk-01",
            "--server",
            &fixture.url,
            "--open-egress-for-others",
            "on",
        ],
    ));
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("open internet for other users' sandboxes: on"),
        "{stdout}"
    );
    assert!(stdout.contains(" guard install --daemon-user "), "{stdout}");
    let config = fs::read_to_string(root.path().join("config/config.toml")).unwrap();
    assert!(
        config.contains("allow_open_egress_for_others = true"),
        "{config}"
    );
    assert_clean_output(&out);
}

#[test]
fn every_contract_row_runs_over_http_and_unlisted_rows_stop_after_one_exchange() {
    let cases = [
        (400, "BAD_REQUEST", Some("authorization_pending"), true),
        (400, "BAD_REQUEST", Some("slow_down"), true),
        (400, "BAD_REQUEST", Some("expired_token"), false),
        (400, "BAD_REQUEST", None, false),
        (403, "FORBIDDEN", Some("access_denied"), false),
        (403, "FORBIDDEN", None, false),
        (404, "NOT_FOUND", None, false),
        (409, "CONFLICT", None, false),
        (429, "TOO_MANY_REQUESTS", None, true),
        (
            503,
            "SERVICE_UNAVAILABLE",
            Some("authorization_pending"),
            true,
        ),
        (401, "UNAUTHORIZED", Some("authorization_pending"), false),
        (
            500,
            "INTERNAL_SERVER_ERROR",
            Some("authorization_pending"),
            false,
        ),
        (400, "FORBIDDEN", Some("authorization_pending"), false),
        (429, "TOO_MANY_REQUESTS", Some("access_denied"), false),
        (503, "SERVICE_UNAVAILABLE", None, false),
    ];
    for (status, code, tag, retries) in cases {
        let server = Server::new(move |i, _| match i {
            0 => reply(200, issued(30, 1)),
            1 => reply(status, error(code, tag)),
            _ => reply(200, success()),
        });
        let root = tempfile::tempdir().unwrap();
        let out = login(root.path(), &server);
        assert_eq!(
            out.status.success(),
            retries,
            "{status}/{code}/{tag:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(server.count(), if retries { 3 } else { 2 });
        assert_clean_output(&out);
        let requests = server.requests.lock().unwrap();
        if retries {
            assert!(
                requests[2].1.duration_since(requests[1].1)
                    >= Duration::from_secs(if tag == Some("slow_down") { 6 } else { 1 })
            );
        }
    }
}

#[test]
fn malformed_success_and_invalid_rate_limits_never_publish() {
    let mut missing = success();
    missing["json"]
        .as_object_mut()
        .unwrap()
        .remove("credentialId");
    let mut wrong_secret = success();
    wrong_secret["json"]["secret"] = host_secret().into();
    for (status, body) in [
        (201, success()),
        (200, success()["json"].clone()),
        (200, missing),
        (200, wrong_secret),
        (429, json!({"json":{"code":"TOO_MANY_REQUESTS"}})),
        (
            429,
            json!({"json":{"code":"TOO_MANY_REQUESTS","data":{"retryAfterSeconds":0}}}),
        ),
    ] {
        let server = Server::new(move |i, _| {
            if i == 0 {
                reply(200, issued(u64::MAX, 1))
            } else {
                reply(status, body.clone())
            }
        });
        let root = tempfile::tempdir().unwrap();
        let out = login(root.path(), &server);
        assert!(!out.status.success());
        assert_eq!(server.count(), 2);
        assert!(!root.path().join("data/device-auth.json").exists());
        assert_clean_output(&out);
    }
}

#[test]
fn expiry_clips_huge_sleep_and_stalled_headers_and_body() {
    for stall in [None, Some("headers"), Some("body")] {
        let server = Server::new(move |i, _| {
            if i == 0 {
                reply(200, issued(2, if stall.is_none() { u64::MAX } else { 1 }))
            } else {
                let mut r = reply(200, success());
                r.stall = stall;
                r
            }
        });
        let root = tempfile::tempdir().unwrap();
        let now = Instant::now();
        let out = login(root.path(), &server);
        assert!(!out.status.success());
        assert!(now.elapsed() < Duration::from_secs(4));
        assert_eq!(server.count(), if stall.is_none() { 1 } else { 2 });
        assert!(!root.path().join("data/device-auth.json").exists());
    }
}

#[test]
fn issuance_has_a_network_timeout() {
    let server = Server::new(|_, _| {
        let mut r = reply(200, issued(30, 1));
        r.stall = Some("headers");
        r
    });
    let root = tempfile::tempdir().unwrap();
    let now = Instant::now();
    let out = login(root.path(), &server);
    assert!(!out.status.success());
    assert!(now.elapsed() < Duration::from_secs(12));
    assert_eq!(server.count(), 1);
}

#[test]
fn all_diagnostics_and_remote_messages_redact_credentials_at_vv() {
    for json_mode in [false, true] {
        for issuance in [false, true] {
            let server = Server::new(move |i, _| {
                if i == 0 && !issuance {
                    reply(200, issued(10, 1))
                } else {
                    reply(
                        403,
                        json!({"json":{"code":"FORBIDDEN","message":format!("{} {} {} {}",secret(),host_secret(),format_args!("wssp_sdk_{}","C".repeat(43)),"x".repeat(4000))}}),
                    )
                }
            });
            let root = tempfile::tempdir().unwrap();
            let mut cmd = command(
                root.path(),
                &["-vv", "login", "--slug", "desk-01", "--server", &server.url],
            );
            if json_mode {
                cmd.arg("--json");
            }
            let out = run(cmd);
            assert!(!out.status.success());
            assert_clean_output(&out);
            assert!(
                String::from_utf8_lossy(&out.stderr)
                    .lines()
                    .last()
                    .unwrap()
                    .len()
                    < 750
            );
            assert!(String::from_utf8_lossy(&out.stderr).contains("REDACTED"));
        }
    }
    let root = tempfile::tempdir().unwrap();
    let out = run(command(root.path(), &["-vv", &secret()]));
    assert!(!out.status.success());
    assert_clean_output(&out);
    let mut cmd = command(root.path(), &["-vv", "config", "path"]);
    cmd.env("WSSP_LOG", format!("{}=nonsense", secret()));
    let out = run(cmd);
    assert_clean_output(&out);
}

#[test]
fn required_slug_server_env_namespace_and_camel_case_config() {
    let root = tempfile::tempdir().unwrap();
    assert!(
        !run(command(root.path(), &["login", "--slug", "desk-01"]))
            .status
            .success()
    );
    assert!(
        run(command(
            root.path(),
            &["config", "set-server", "https://example.test"]
        ))
        .status
        .success()
    );
    assert!(
        run(command(root.path(), &["config", "set-slug", "desk-01"]))
            .status
            .success()
    );
    let out = run(command(root.path(), &["login"]));
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--slug"));
    let out = run(command(root.path(), &["config", "show", "--json"]));
    let body: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(body["serverUrl"], "https://example.test/");
    assert_eq!(body["hostSlug"], "desk-01");
    assert!(body.get("server_url").is_none());
    for env in ["AWS_SECRET_ACCESS_KEY", "PATH", "WSSP_", "WSSP_lower"] {
        let mut cmd = command(root.path(), &["token", "login", env]);
        cmd.env(env, host_secret());
        assert!(!run(cmd).status.success());
    }
    let mut cmd = command(root.path(), &["token", "login", "WSSP_TOKEN"]);
    cmd.env("WSSP_TOKEN", host_secret());
    assert!(run(cmd).status.success());
    let out = run(command(root.path(), &["logout", "--json"]));
    assert!(out.status.success());
    let body: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(body["removedTokenEnv"], true);
    assert!(
        !fs::read_to_string(root.path().join("config/config.toml"))
            .unwrap()
            .contains("host_token_env")
    );
}

#[test]
fn malicious_urls_fail_before_dialing_and_port_or_downgrade_mismatch_is_terminal() {
    for url in [
        "http://192.0.2.1",
        "ws://example.test",
        "http://localhost.evil",
        "https://user:pass@example.test",
        "file:///tmp/a",
    ] {
        let root = tempfile::tempdir().unwrap();
        for args in [
            vec!["config", "set-server", url],
            vec!["login", "--slug", "desk-01", "--server", url],
            vec![
                "connect",
                "--runtime",
                "fake",
                "--server",
                url,
                "--host-token-env",
                "WSSP_TOKEN",
                "--host-id",
                "host-1",
            ],
        ] {
            let mut cmd = command(root.path(), &args);
            cmd.env("WSSP_TOKEN", host_secret());
            assert!(!run(cmd).status.success(), "{url}");
        }
    }
    let issuing = Server::new(|i, _| {
        if i == 0 {
            reply(200, issued(10, 1))
        } else {
            reply(200, success())
        }
    });
    let target = Server::new(|_, _| reply(401, json!({})));
    let root = tempfile::tempdir().unwrap();
    assert!(login(root.path(), &issuing).status.success());
    let out = run(command(
        root.path(),
        &["connect", "--runtime", "fake", "--server", &target.url],
    ));
    assert!(!out.status.success());
    assert_eq!(target.count(), 0);
    let mut stored = state(root.path());
    stored["origin"] = "https://127.0.0.1/".into();
    fs::write(
        root.path().join("data/device-auth.json"),
        stored.to_string(),
    )
    .unwrap();
    let out = run(command(
        root.path(),
        &["connect", "--runtime", "fake", "--server", &target.url],
    ));
    assert!(!out.status.success());
    assert_eq!(target.count(), 0);
}

#[test]
fn http_and_websocket_redirects_never_forward_requests_or_credentials() {
    for websocket in [false, true] {
        if websocket && !cfg!(unix) {
            continue;
        }
        for device in [false, true] {
            let target = Server::new(|_, _| reply(401, json!({})));
            let location = if websocket {
                target.url.replace("http:", "ws:")
            } else {
                target.url.clone()
            };
            let server = Server::new(move |i, _| {
                if device && i < 2 {
                    return if i == 0 {
                        reply(200, issued(10, 1))
                    } else {
                        reply(200, success())
                    };
                }
                Reply {
                    status: 302,
                    body: "{}".into(),
                    location: Some(location.clone()),
                    stall: None,
                }
            });
            let root = tempfile::tempdir().unwrap();
            if device {
                assert!(login(root.path(), &server).status.success());
            }
            let out = if websocket {
                let mut args = vec![
                    "-vv",
                    "connect",
                    "--runtime",
                    "fake",
                    "--server",
                    &server.url,
                ];
                if !device {
                    args.extend(["--host-token-env", "WSSP_TOKEN", "--host-id", "host-1"]);
                }
                let mut cmd = command(root.path(), &args);
                cmd.env("WSSP_TOKEN", host_secret());
                run(cmd)
            } else {
                login(root.path(), &server)
            };
            assert!(!out.status.success());
            assert_clean_output(&out);
            assert_eq!(target.count(), 0);
            assert_eq!(server.count(), if device { 3 } else { 1 });
        }
    }
}

#[cfg(unix)]
#[test]
fn broad_mode_credential_is_rejected_on_reentry() {
    use std::os::unix::fs::PermissionsExt;
    let server = Server::new(|i, _| {
        if i == 0 {
            reply(200, issued(10, 1))
        } else {
            reply(200, success())
        }
    });
    let root = tempfile::tempdir().unwrap();
    assert!(login(root.path(), &server).status.success());
    fs::set_permissions(
        root.path().join("data/device-auth.json"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let out = run(command(root.path(), &["connect", "--runtime", "fake"]));
    assert!(!out.status.success());
    assert_eq!(server.count(), 2);
    assert!(String::from_utf8_lossy(&out.stderr).contains("owner-only"));
}

#[test]
fn stale_login_cannot_publish_or_exchange_after_newer_login_or_logout() {
    for logout in [false, true] {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let old = Server::new(move |i, _| {
            if i == 0 {
                ready_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                reply(200, issued(15, 1))
            } else {
                reply(200, success())
            }
        });
        let new = Server::new(|i, _| {
            if i == 0 {
                reply(200, issued(10, 1))
            } else {
                reply(200, success())
            }
        });
        let root = tempfile::tempdir().unwrap();
        let mut first = ManagedChild::spawn(&mut command(
            root.path(),
            &["login", "--slug", "old-host", "--server", &old.url],
        ))
        .unwrap();
        ready_rx.recv_timeout(Duration::from_secs(4)).unwrap();
        if logout {
            assert!(run(command(root.path(), &["logout"])).status.success());
        } else {
            assert!(login(root.path(), &new).status.success());
        }
        release_tx.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(4);
        while first.try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(10));
        }
        let out = first.wait_with_output().unwrap();
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("superseded"));
        assert_eq!(old.count(), 1);
        if logout {
            assert!(!root.path().join("data/device-auth.json").exists());
        } else {
            assert_eq!(state(root.path())["origin"], format!("{}/", new.url));
        }
    }
}

#[cfg(unix)]
#[test]
fn published_credential_survives_config_failure_and_connects_without_config() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("config/config.toml");
    let server = Server::new(move |i, _| match i {
        0 => reply(200, issued(10, 1)),
        1 => {
            fs::create_dir_all(&config).unwrap();
            reply(200, success())
        }
        _ => reply(401, json!({})),
    });
    let out = login(root.path(), &server);
    assert!(!out.status.success());
    assert_eq!(state(root.path())["hostId"], "host-1");
    let mut show = command(root.path(), &["config", "show", "--json"]);
    show.env("WSSP_RUNTIME", "fake");
    let shown = run(show);
    assert!(shown.status.success());
    let config: Value = serde_json::from_slice(&shown.stdout).unwrap();
    assert!(config["hostTokenEnv"].is_null());
    assert_eq!(config["serverUrl"], format!("{}/", server.url));
    let mut show = command(root.path(), &["config", "show"]);
    show.env("WSSP_RUNTIME", "fake");
    let shown = run(show);
    assert!(shown.status.success());
    let config: toml::Value = toml::from_str(std::str::from_utf8(&shown.stdout).unwrap()).unwrap();
    assert!(config.get("host_token_env").is_none());
    assert!(!String::from_utf8_lossy(&shown.stdout).contains(&secret()));
    let out = run(command(root.path(), &["connect", "--runtime", "fake"]));
    assert!(!out.status.success());
    assert_eq!(server.count(), 3);
    assert!(server.requests.lock().unwrap()[2].0.contains(&secret()));
    assert_clean_output(&out);
}

#[cfg(target_os = "linux")]
fn fault_library(root: &Path) -> std::path::PathBuf {
    let library = root.join("auth-fault.so");
    let result = Command::new("cc")
        .args(["-shared", "-fPIC", "-Wall", "-Werror"])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/auth-fault.c"
        ))
        .args(["-o"])
        .arg(&library)
        .arg("-ldl")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    library
}
#[cfg(target_os = "linux")]
fn inject(cmd: &mut Command, root: &Path, library: &Path, mode: &str, config: bool) {
    cmd.env("LD_PRELOAD", library)
        .env("WSSP_TEST_AUTH_FAULT", mode)
        .env(
            "WSSP_TEST_FAULT_TARGET",
            root.join(if config {
                "config/config.toml"
            } else {
                "data/device-auth.json"
            }),
        )
        .env(
            "WSSP_TEST_FAULT_DIR",
            root.join(if config { "config" } else { "data" }),
        )
        .env("WSSP_TEST_FAULT_ARMED", root.join("armed"))
        .env("WSSP_TEST_FAULT_HIT", root.join("hit"));
}
#[cfg(target_os = "linux")]
fn temps(root: &Path) -> Vec<std::path::PathBuf> {
    ["data", "config"]
        .iter()
        .flat_map(|dir| fs::read_dir(root.join(dir)).into_iter().flatten())
        .filter_map(|entry| {
            let entry = entry.unwrap();
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".wssp-staging-")
                .then(|| entry.path())
        })
        .collect()
}

#[cfg(target_os = "linux")]
#[test]
fn syscall_failure_at_every_publish_step_is_atomic_and_recoverable() {
    let build = tempfile::tempdir().unwrap();
    let library = fault_library(build.path());
    for config in [false, true] {
        for mode in [
            "create",
            "permissions",
            "write",
            "file-sync",
            "rename",
            "dir-sync",
        ] {
            let root = tempfile::tempdir().unwrap();
            let arm = root.path().join("armed");
            let server = Server::new(move |i, _| {
                if i == 0 {
                    reply(200, issued(10, 1))
                } else {
                    fs::write(&arm, "").unwrap();
                    reply(200, success())
                }
            });
            let mut cmd = command(
                root.path(),
                &["login", "--slug", "desk-01", "--server", &server.url],
            );
            inject(&mut cmd, root.path(), &library, mode, config);
            let out = run(cmd);
            assert!(!out.status.success(), "{config}/{mode}");
            assert!(
                root.path().join("hit").exists(),
                "fault not reached: {config}/{mode}"
            );
            if mode == "rename" {
                let obstruction = root.path().join(if config {
                    "config/config.toml"
                } else {
                    "data/device-auth.json"
                });
                assert!(obstruction.is_dir());
                fs::remove_dir(obstruction).unwrap();
            }
            assert!(temps(root.path()).is_empty());
            assert_clean_output(&out);
            if config {
                if !matches!(mode, "create" | "permissions") {
                    assert!(
                        root.path().join("data/device-auth.json").exists(),
                        "credential missing for config-side fault: {mode}"
                    );
                    assert_eq!(state(root.path())["secret"], secret());
                }
            } else if mode == "dir-sync" {
                assert!(root.path().join("data/device-auth.json").exists());
                assert_eq!(state(root.path())["secret"], secret());
            } else {
                assert!(
                    !root.path().join("data/device-auth.json").exists(),
                    "credential leaked for data-side fault: {mode}"
                );
            }
            let out = run(command(root.path(), &["logout"]));
            assert!(out.status.success());
            assert!(!root.path().join("data/device-auth.json").exists());
            assert!(temps(root.path()).is_empty());
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn crash_restart_sweeps_secrets_and_cleanup_waits_for_live_publisher_lock() {
    let build = tempfile::tempdir().unwrap();
    let library = fault_library(build.path());
    for mode in ["crash-partial", "crash-synced"] {
        let root = tempfile::tempdir().unwrap();
        let arm = root.path().join("armed");
        let server = Server::new(move |i, _| {
            if i == 0 {
                reply(200, issued(10, 1))
            } else {
                fs::write(&arm, "").unwrap();
                reply(200, success())
            }
        });
        let mut cmd = command(
            root.path(),
            &["login", "--slug", "desk-01", "--server", &server.url],
        );
        inject(&mut cmd, root.path(), &library, mode, false);
        let mut child: ManagedChild = ManagedChild::spawn(&mut cmd).unwrap();
        let deadline = Instant::now() + Duration::from_secs(6);
        while !root.path().join("hit").exists() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(temps(root.path()).len(), 1);
        let mut startup =
            ManagedChild::spawn(&mut command(root.path(), &["config", "path"])).unwrap();
        thread::sleep(Duration::from_millis(150));
        assert!(startup.try_wait().unwrap().is_none());
        assert_eq!(
            temps(root.path()).len(),
            1,
            "live temp must remain under lock"
        );
        child.kill().unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(!out.status.success());
        let deadline = Instant::now() + Duration::from_secs(3);
        while startup.try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(10));
        }
        assert!(startup.wait_with_output().unwrap().status.success());
        assert!(temps(root.path()).is_empty());
        assert!(run(command(root.path(), &["logout"])).status.success());
        assert!(!root.path().join("data/device-auth.json").exists());
    }
}

#[test]
fn exchange_redirect_and_huge_retry_after_stop_at_deadline() {
    for redirect in [false, true] {
        let target = Server::new(|_, _| reply(200, success()));
        let location = target.url.clone();
        let server = Server::new(move |i, _| {
            if i == 0 {
                reply(200, issued(2, 1))
            } else if redirect {
                Reply {
                    status: 302,
                    body: "{}".into(),
                    location: Some(location.clone()),
                    stall: None,
                }
            } else {
                reply(
                    429,
                    json!({"json":{"code":"TOO_MANY_REQUESTS","data":{"retryAfterSeconds":u64::MAX}}}),
                )
            }
        });
        let root = tempfile::tempdir().unwrap();
        let now = Instant::now();
        let out = login(root.path(), &server);
        assert!(!out.status.success());
        assert!(now.elapsed() < Duration::from_secs(4));
        assert_eq!(server.count(), 2);
        assert!(!root.path().join("data/device-auth.json").exists());
    }
}

#[cfg(unix)]
#[test]
fn explicit_token_override_and_same_origin_websocket_redirect_are_bounded() {
    let own = Arc::new(Mutex::new(String::new()));
    let location = own.clone();
    let server = Server::new(move |i, _| {
        if i == 0 {
            reply(200, issued(10, 1))
        } else if i == 1 {
            reply(200, success())
        } else {
            Reply {
                status: 302,
                body: "{}".into(),
                location: Some(location.lock().unwrap().clone()),
                stall: None,
            }
        }
    });
    *own.lock().unwrap() = server.url.replace("http:", "ws:");
    let root = tempfile::tempdir().unwrap();
    assert!(login(root.path(), &server).status.success());
    let mut cmd = command(
        root.path(),
        &[
            "-vv",
            "connect",
            "--runtime",
            "fake",
            "--host-token-env",
            "WSSP_OVERRIDE",
            "--host-id",
            "host-override",
        ],
    );
    cmd.env("WSSP_OVERRIDE", host_secret());
    let out = run(cmd);
    assert!(!out.status.success());
    assert_eq!(server.count(), 3);
    assert!(
        server.requests.lock().unwrap()[2]
            .0
            .contains(&host_secret())
    );
    assert_clean_output(&out);
    let out = run(command(
        root.path(),
        &[
            "connect",
            "--runtime",
            "fake",
            "--host-token-env",
            "WSSP_MISSING",
            "--host-id",
            "host-override",
        ],
    ));
    assert!(!out.status.success());
    assert_eq!(server.count(), 3);
}

#[cfg(target_os = "linux")]
#[test]
fn failed_config_publish_does_not_resurrect_a_previous_token_binding() {
    let root = tempfile::tempdir().unwrap();
    let library = fault_library(root.path());
    let mut token = command(root.path(), &["token", "login", "WSSP_TOKEN"]);
    token.env("WSSP_TOKEN", host_secret());
    assert!(run(token).status.success());
    let arm = root.path().join("armed");
    let server = Server::new(move |i, _| {
        if i == 0 {
            reply(200, issued(10, 1))
        } else {
            fs::write(&arm, "").unwrap();
            reply(200, success())
        }
    });
    let mut cmd = command(
        root.path(),
        &["login", "--slug", "desk-01", "--server", &server.url],
    );
    inject(&mut cmd, root.path(), &library, "write", true);
    assert!(!run(cmd).status.success());
    assert!(root.path().join("hit").exists());
    assert!(
        fs::read_to_string(root.path().join("config/config.toml"))
            .unwrap()
            .contains("WSSP_TOKEN")
    );
    let mut show = command(root.path(), &["config", "show", "--json"]);
    show.env("WSSP_RUNTIME", "fake");
    let shown = run(show);
    assert!(shown.status.success());
    let config: Value = serde_json::from_slice(&shown.stdout).unwrap();
    assert!(config["hostTokenEnv"].is_null());
    assert_eq!(config["serverUrl"], format!("{}/", server.url));
    let mut show = command(root.path(), &["config", "show"]);
    show.env("WSSP_RUNTIME", "fake");
    let shown = run(show);
    assert!(shown.status.success());
    let config: toml::Value = toml::from_str(std::str::from_utf8(&shown.stdout).unwrap()).unwrap();
    assert!(config.get("host_token_env").is_none());
    assert!(!String::from_utf8_lossy(&shown.stdout).contains(&secret()));
    let out = run(command(root.path(), &["connect", "--runtime", "fake"]));
    assert!(!out.status.success());
    assert_eq!(server.count(), 3);
    assert!(server.requests.lock().unwrap()[2].0.contains(&secret()));
    assert!(run(command(root.path(), &["logout"])).status.success());
}

#[test]
fn json_reports_issuance_interval_without_artificial_cap() {
    let server = Server::new(|_, _| reply(200, issued(1, u64::MAX)));
    let root = tempfile::tempdir().unwrap();
    let now = Instant::now();
    let out = run(command(
        root.path(),
        &[
            "login",
            "--json",
            "--slug",
            "desk-01",
            "--server",
            &server.url,
        ],
    ));
    assert!(!out.status.success());
    assert!(now.elapsed() < Duration::from_secs(3));
    assert_eq!(server.count(), 1);
    let json: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["interval"].as_u64(), Some(u64::MAX));
    assert_eq!(json["expiresIn"], 1);
}

#[test]
fn verification_uri_complete_is_absent_when_server_omits_it() {
    let server = Server::new(|i, _| {
        if i == 0 {
            reply(
                200,
                json!({
                    "device_code":"test-code",
                    "user_code":"TEST-CODE",
                    "verification_uri":"https://web.example.test/en-US/device",
                    "expires_in":2,
                    "interval":1
                }),
            )
        } else {
            reply(400, error("BAD_REQUEST", Some("authorization_pending")))
        }
    });
    let root = tempfile::tempdir().unwrap();
    let out = run(command(
        root.path(),
        &[
            "login",
            "--json",
            "--slug",
            "desk-01",
            "--server",
            &server.url,
        ],
    ));
    assert!(!out.status.success());
    let json: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(json.get("verificationUriComplete").is_none());
    assert_eq!(
        json["verificationUri"],
        "https://web.example.test/en-US/device"
    );
}

#[test]
fn rate_limit_retry_floor_is_not_truncated() {
    let server = Server::new(|i, _| match i {
        0 => reply(200, issued(180, 1)),
        1 => reply(
            429,
            json!({"json":{"code":"TOO_MANY_REQUESTS","data":{"retryAfterSeconds":120}}}),
        ),
        _ => reply(200, success()),
    });
    let root = tempfile::tempdir().unwrap();
    let sleep_log = root.path().join("sleep.log");
    let mut cmd = command(
        root.path(),
        &["login", "--slug", "desk-01", "--server", &server.url],
    );
    cmd.env("WSSP_TEST_RECORD_SLEEP", &sleep_log);
    let out = run(cmd);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let sleeps: Vec<u64> = fs::read_to_string(&sleep_log)
        .unwrap()
        .lines()
        .map(|line| line.parse().unwrap())
        .collect();
    assert!(sleeps.iter().any(|seconds| *seconds >= 120));
}

#[test]
fn login_publish_rejects_stale_server_after_config_set_server() {
    let root = tempfile::tempdir().unwrap();
    let allow_success = Arc::new(Mutex::new(false));
    let allow_success_flag = allow_success.clone();
    let old = Server::new(move |i, _| match i {
        0 => reply(200, issued(30, 1)),
        _ if *allow_success_flag.lock().unwrap() => reply(200, success()),
        _ => reply(400, error("BAD_REQUEST", Some("authorization_pending"))),
    });
    let new = Server::new(|i, _| match i {
        0 => reply(200, issued(30, 1)),
        _ => reply(200, success()),
    });
    let mut login_cmd = command(
        root.path(),
        &["login", "--slug", "desk-01", "--server", &old.url],
    );
    let child: ManagedChild = ManagedChild::spawn(&mut login_cmd).unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
    while old.count() < 2 {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        run({
            let mut cmd = command(root.path(), &["config", "set-server", &new.url]);
            cmd.env("WSSP_DATA_DIR", root.path().join("data"))
                .env("WSSP_CONFIG_DIR", root.path().join("config"));
            cmd
        })
        .status
        .success()
    );
    *allow_success.lock().unwrap() = true;
    let out = child.wait_with_output().unwrap();
    assert!(!out.status.success());
    assert!(!root.path().join("data/device-auth.json").exists());
    let config = fs::read_to_string(root.path().join("config/config.toml")).unwrap();
    assert!(config.contains(&new.url));
    assert_eq!(new.count(), 0);
}

#[cfg(target_os = "linux")]
#[test]
fn shared_config_dir_does_not_let_peer_sweep_live_config_temp() {
    let root = tempfile::tempdir().unwrap();
    let shared_config = root.path().join("shared-config");
    let data_a = root.path().join("data-a");
    let data_b = root.path().join("data-b");
    fs::create_dir_all(&shared_config).unwrap();
    fs::create_dir_all(&data_a).unwrap();
    fs::create_dir_all(&data_b).unwrap();
    let arm = root.path().join("armed");
    let arm_signal = arm.clone();
    let server = Server::new(move |i, _| {
        if i == 0 {
            reply(200, issued(10, 1))
        } else {
            fs::write(&arm_signal, "").unwrap();
            reply(200, success())
        }
    });
    let build = tempfile::tempdir().unwrap();
    let library = fault_library(build.path());
    let mut publisher = command(
        root.path(),
        &["login", "--slug", "desk-01", "--server", &server.url],
    );
    publisher
        .env("WSSP_DATA_DIR", &data_a)
        .env("WSSP_CONFIG_DIR", &shared_config);
    inject(&mut publisher, root.path(), &library, "crash-synced", true);
    publisher.env("WSSP_TEST_FAULT_DIR", &shared_config);
    publisher.env("WSSP_TEST_FAULT_TARGET", shared_config.join("config.toml"));
    let mut child: ManagedChild = ManagedChild::spawn(&mut publisher).unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
    // The HTTP reply arms injection; only the syscall marker proves staging is durable.
    while !root.path().join("hit").exists() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        fs::read_dir(&shared_config)
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".wssp-staging-")
            })
            .count(),
        1
    );
    let mut peer = ManagedChild::spawn(
        command(root.path(), &["config", "path"])
            .env("WSSP_DATA_DIR", &data_b)
            .env("WSSP_CONFIG_DIR", &shared_config),
    )
    .unwrap();
    thread::sleep(Duration::from_millis(150));
    assert!(peer.try_wait().unwrap().is_none());
    assert_eq!(
        fs::read_dir(&shared_config)
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".wssp-staging-")
            })
            .count(),
        1
    );
    child.kill().unwrap();
    let _ = child.wait_with_output();
    let _ = peer.wait_with_output();
}

#[test]
fn logout_clears_device_credential_when_config_is_unreadable() {
    let server = Server::new(|i, _| match i {
        0 => reply(200, issued(10, 1)),
        _ => reply(200, success()),
    });
    let root = tempfile::tempdir().unwrap();
    assert!(login(root.path(), &server).status.success());
    fs::remove_file(root.path().join("config/config.toml")).unwrap();
    fs::create_dir(root.path().join("config/config.toml")).unwrap();
    let out = run(command(root.path(), &["logout", "--json"]));
    assert!(out.status.success());
    assert!(!root.path().join("data/device-auth.json").exists());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("warning:"));
    let connect = run(command(root.path(), &["connect", "--runtime", "fake"]));
    assert!(!connect.status.success());
    assert_eq!(server.count(), 2);
}

#[test]
fn startup_finishes_logout_intent_without_parseable_config() {
    let server = Server::new(|i, _| match i {
        0 => reply(200, issued(10, 1)),
        _ => reply(200, success()),
    });
    let root = tempfile::tempdir().unwrap();
    assert!(login(root.path(), &server).status.success());
    fs::write(root.path().join("config/config.toml"), "host_token_env = [").unwrap();
    fs::write(
        root.path().join("data/auth-intent.json"),
        r#"{"generation":"deadbeef","operation":"logout"}"#,
    )
    .unwrap();
    let connect = run(command(root.path(), &["connect", "--runtime", "fake"]));
    assert!(!connect.status.success());
    assert!(!root.path().join("data/device-auth.json").exists());
    assert_eq!(server.count(), 2);
}

#[test]
fn loopback_login_ignores_environment_proxy_settings() {
    let connects = Arc::new(Mutex::new(0usize));
    let proxy_connects = connects.clone();
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let proxy_stop = Arc::new(AtomicBool::new(false));
    let proxy_done = proxy_stop.clone();
    let proxy_handle = thread::spawn(move || {
        proxy.set_nonblocking(true).unwrap();
        while !proxy_done.load(Ordering::SeqCst) {
            if let Ok((mut stream, _)) = proxy.accept() {
                let mut buffer = [0_u8; 4096];
                let n = stream.read(&mut buffer).unwrap_or(0);
                if n > 0 && buffer.starts_with(b"CONNECT") {
                    *proxy_connects.lock().unwrap() += 1;
                    let _ = stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
                }
            } else {
                thread::sleep(Duration::from_millis(5));
            }
        }
    });
    let server = Server::new(|i, _| match i {
        0 => reply(200, issued(10, 1)),
        _ => reply(200, success()),
    });
    let root = tempfile::tempdir().unwrap();
    let proxy_url = format!("http://{proxy_addr}");
    let mut cmd = command(
        root.path(),
        &["login", "--slug", "desk-01", "--server", &server.url],
    );
    cmd.env("ALL_PROXY", &proxy_url)
        .env("HTTP_PROXY", &proxy_url)
        .env("HTTPS_PROXY", &proxy_url);
    let out = run(cmd);
    proxy_stop.store(true, Ordering::SeqCst);
    proxy_handle.join().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(*connects.lock().unwrap(), 0);
    assert_eq!(server.count(), 2);
}

#[cfg(target_os = "linux")]
#[test]
fn creating_state_directories_fsyncs_new_parent_entries() {
    let root = tempfile::tempdir().unwrap();
    let parent = root.path().join("nested");
    let data = parent.join("data");
    let config = parent.join("config");
    let mut cmd = command(root.path(), &["config", "path"]);
    cmd.env("WSSP_DATA_DIR", &data)
        .env("WSSP_CONFIG_DIR", &config)
        .env("WSSP_TEST_RECORD_PARENT_SYNC", &parent);
    assert!(run(cmd).status.success());
    assert!(parent.join(".wssp-parent-sync-recorded").exists());
}

#[test]
fn config_generation_marker_survives_store_reopen() {
    let root = tempfile::tempdir().unwrap();
    assert!(
        run(command(
            root.path(),
            &["config", "set-server", "https://example.test/"]
        ))
        .status
        .success()
    );
    let marker = root.path().join("config").join(".wssp-config-generation");
    assert!(marker.exists());
    assert!(
        run(command(root.path(), &["config", "path"]))
            .status
            .success()
    );
    assert!(
        marker.exists(),
        "sweep on store reopen must not delete the config generation marker"
    );
    let generation: u64 = fs::read_to_string(&marker).unwrap().trim().parse().unwrap();
    assert!(generation >= 1);
}

#[test]
fn login_publish_rejects_config_init_during_pending_login() {
    let root = tempfile::tempdir().unwrap();
    assert!(
        run(command(
            root.path(),
            &["config", "set-server", "https://old.example.test/"]
        ))
        .status
        .success()
    );
    let allow_success = Arc::new(Mutex::new(false));
    let allow_success_flag = allow_success.clone();
    let server = Server::new(move |i, _| match i {
        0 => reply(200, issued(30, 1)),
        _ if *allow_success_flag.lock().unwrap() => reply(200, success()),
        _ => reply(400, error("BAD_REQUEST", Some("authorization_pending"))),
    });
    let mut login_cmd = command(
        root.path(),
        &["login", "--slug", "desk-01", "--server", &server.url],
    );
    let child: ManagedChild = ManagedChild::spawn(&mut login_cmd).unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
    while server.count() < 2 {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
    fs::remove_file(root.path().join("config/config.toml")).unwrap();
    assert!(
        run(command(root.path(), &["config", "init"]))
            .status
            .success(),
        "config init must recreate the file and bump generation"
    );
    *allow_success.lock().unwrap() = true;
    let out = child.wait_with_output().unwrap();
    assert!(!out.status.success());
    assert!(!root.path().join("data/device-auth.json").exists());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("configured server changed during login"));
}

#[test]
fn rate_limit_honored_retry_is_sent_before_expiry() {
    let exchanges = Arc::new(Mutex::new(0usize));
    let exchanges_flag = exchanges.clone();
    let server = Server::new(move |i, _| {
        if i == 0 {
            reply(200, issued(20, 1))
        } else {
            let n = {
                let mut guard = exchanges_flag.lock().unwrap();
                *guard += 1;
                *guard
            };
            if n == 1 {
                reply(
                    429,
                    json!({"json":{"code":"TOO_MANY_REQUESTS","data":{"retryAfterSeconds":12}}}),
                )
            } else {
                reply(200, success())
            }
        }
    });
    let root = tempfile::tempdir().unwrap();
    let started = Instant::now();
    let out = run(command(
        root.path(),
        &["login", "--slug", "desk-01", "--server", &server.url],
    ));
    let elapsed = started.elapsed();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        *exchanges.lock().unwrap(),
        2,
        "second exchange must run after 429"
    );
    assert!(
        elapsed >= Duration::from_secs(11),
        "must sleep the 429 floor before the retry"
    );
    assert!(
        elapsed < Duration::from_secs(20),
        "retry must complete before device-code expiry"
    );
}

#[test]
fn rate_limit_floor_beyond_remaining_expires_without_extra_sleep() {
    let server = Server::new(|i, _| match i {
        0 => reply(200, issued(5, 1)),
        1 => reply(
            429,
            json!({"json":{"code":"TOO_MANY_REQUESTS","data":{"retryAfterSeconds":10}}}),
        ),
        _ => reply(200, success()),
    });
    let root = tempfile::tempdir().unwrap();
    let sleep_log = root.path().join("sleep.log");
    let started = Instant::now();
    let mut cmd = command(
        root.path(),
        &["login", "--slug", "desk-01", "--server", &server.url],
    );
    cmd.env("WSSP_TEST_RECORD_SLEEP", &sleep_log);
    let out = run(cmd);
    assert!(
        !out.status.success(),
        "expected terminal expiry, got success"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("expired"));
    assert_eq!(server.count(), 2);
    let sleeps = fs::read_to_string(&sleep_log).unwrap_or_default();
    assert!(
        sleeps.lines().all(|line| line.parse::<u64>().unwrap() <= 5),
        "must not sleep the oversized 429 floor: {sleeps}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "must fail promptly without waiting the impossible floor"
    );
}

#[test]
fn rate_limit_floor_applies_once_then_interval_resumes_while_slow_down_persists() {
    let server = Server::new(|i, _| match i {
        0 => reply(200, issued(120, 1)),
        1 => reply(400, error("BAD_REQUEST", Some("slow_down"))),
        2 => reply(
            429,
            json!({"json":{"code":"TOO_MANY_REQUESTS","data":{"retryAfterSeconds":3}}}),
        ),
        _ => reply(200, success()),
    });
    let root = tempfile::tempdir().unwrap();
    let sleep_log = root.path().join("sleep.log");
    let mut cmd = command(
        root.path(),
        &["login", "--slug", "desk-01", "--server", &server.url],
    );
    cmd.env("WSSP_TEST_RECORD_SLEEP", &sleep_log);
    let out = run(cmd);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let sleeps: Vec<u64> = fs::read_to_string(&sleep_log)
        .unwrap()
        .lines()
        .map(|line| line.parse().unwrap())
        .collect();
    assert!(sleeps.len() >= 3);
    assert_eq!(sleeps[0], 1);
    assert_eq!(sleeps[1], 6, "slow_down adds five seconds permanently");
    assert_eq!(
        sleeps[2], 6,
        "after a 429 the next wait returns to the slow_down interval, not retryAfterSeconds alone"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn logout_json_reports_token_binding_when_config_cleanup_fails() {
    let server = Server::new(|i, _| match i {
        0 => reply(200, issued(10, 1)),
        _ => reply(200, success()),
    });
    let root = tempfile::tempdir().unwrap();
    assert!(login(root.path(), &server).status.success());
    let mut cmd = command(root.path(), &["token", "login", "WSSP_TOKEN"]);
    cmd.env("WSSP_TOKEN", host_secret());
    assert!(run(cmd).status.success());
    let build = tempfile::tempdir().unwrap();
    let library = fault_library(build.path());
    let mut logout = command(root.path(), &["logout", "--json"]);
    inject(&mut logout, root.path(), &library, "write", true);
    logout.env("WSSP_TEST_FAULT_DIR", root.path().join("config"));
    logout.env(
        "WSSP_TEST_FAULT_TARGET",
        root.path().join("config/config.toml"),
    );
    fs::write(root.path().join("armed"), "").unwrap();
    let out = run(logout);
    assert!(out.status.success());
    let body: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(body["removedDeviceCredential"], true);
    assert_eq!(body["removedTokenEnv"], false);
    assert!(
        fs::read_to_string(root.path().join("config/config.toml"))
            .unwrap()
            .contains("host_token_env")
    );
}
