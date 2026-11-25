//! User side of the CLI (`wssp login|logout|whoami|sandbox|template`) against a
//! loopback stub of the control plane. Real binary, closed stdin.
#![cfg(unix)]

use serde_json::{Value, json};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

#[path = "../test-support/certificates.rs"]
#[allow(dead_code)] // Only the CA PEM is used here.
mod certificates;

#[path = "../../../crates/sandbox-runtime/tests/support/managed_child.rs"]
mod managed_child;
use managed_child::ManagedChild;

const ISSUE: &str = "/api/auth/device/code";
const EXCHANGE: &str = "/rpc/userLogins/exchangeDeviceCode";

fn sdk_key(fill: char) -> String {
    format!("wssp_sdk_{}", fill.to_string().repeat(43))
}

#[derive(Clone, Debug)]
struct Request {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap()
    }
    fn is(&self, method: &str, path: &str) -> bool {
        self.method == method && self.target.split('?').next() == Some(path)
    }
}

struct Reply {
    status: u16,
    body: String,
    headers: Vec<(String, String)>,
}

fn reply(status: u16, body: Value) -> Reply {
    Reply {
        status,
        body: body.to_string(),
        headers: Vec::new(),
    }
}

fn api_error(status: u16, code: &str, message: &str, data: Option<Value>) -> Reply {
    let mut error = json!({"code": code, "message": message, "requestId": "00000000-0000-4000-8000-000000000000"});
    if let Some(data) = data {
        error["data"] = data;
    }
    reply(status, json!({ "error": error }))
}

struct Server {
    url: String,
    requests: Arc<Mutex<Vec<Request>>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Server {
    fn new(handler: impl Fn(usize, &Request) -> Reply + Send + 'static) -> Self {
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
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let Some(request) = read_request(&mut stream) else {
                    continue;
                };
                let index = {
                    let mut guard = capture.lock().unwrap();
                    guard.push(request.clone());
                    guard.len() - 1
                };
                let response = handler(index, &request);
                let extra: String = response
                    .headers
                    .iter()
                    .map(|(k, v)| format!("{k}: {v}\r\n"))
                    .collect();
                let header = format!(
                    "HTTP/1.1 {} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n",
                    response.status,
                    response.body.len()
                );
                let _ = stream.write_all(header.as_bytes());
                let _ = stream.write_all(response.body.as_bytes());
            }
        });
        Self {
            url,
            requests,
            stop,
            handle: Some(handle),
        }
    }

    fn requests(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
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

fn read_request(stream: &mut TcpStream) -> Option<Request> {
    let mut bytes = Vec::new();
    let end = loop {
        let mut buffer = [0; 4096];
        let n = stream.read(&mut buffer).unwrap_or(0);
        if n == 0 {
            return None;
        }
        bytes.extend_from_slice(&buffer[..n]);
        if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            break end;
        }
    };
    let head = String::from_utf8_lossy(&bytes[..end]).into_owned();
    let mut lines = head.lines();
    let mut start = lines.next()?.split_whitespace();
    let method = start.next()?.to_owned();
    let target = start.next()?.to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| {
            let (k, v) = line.split_once(':')?;
            Some((k.trim().to_owned(), v.trim().to_owned()))
        })
        .collect();
    let length = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .map_or(0, |(_, v)| v.parse::<usize>().unwrap());
    while bytes.len() < end + 4 + length {
        let mut buffer = [0; 4096];
        let n = stream.read(&mut buffer).unwrap_or(0);
        if n == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..n]);
    }
    Some(Request {
        method,
        target,
        headers,
        body: String::from_utf8_lossy(&bytes[end + 4..]).into_owned(),
    })
}

fn command(root: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_wssp"));
    cmd.args(args)
        .env("WSSP_CONFIG_DIR", root.join("config"))
        .env("WSSP_DATA_DIR", root.join("data"))
        .env("WSSP_TEST_GUARD_ROOT", root.join("guard-root"))
        .env("WSSP_TEST_RECORD_SLEEP", root.join("sleeps"))
        .env_remove("WSSP_USER_DIR")
        .env_remove("WSSP_API_KEY")
        .env_remove("WSSP_SERVER")
        .env_remove("WSSP_CA_FILE")
        .env_remove("WSSP_LOG")
        .env_remove("RUST_LOG")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for proxy in [
        "ALL_PROXY",
        "all_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        cmd.env_remove(proxy);
    }
    cmd
}

fn run(cmd: Command) -> Output {
    run_with(cmd, false)
}

/// Run to the end; with `close_stdout` the reader of stdout is gone before
/// the CLI writes (`wssp … | head` after `head` exited).
fn run_with(mut cmd: Command, close_stdout: bool) -> Output {
    let mut child: ManagedChild = ManagedChild::spawn(&mut cmd).unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let stdout = (!close_stdout).then_some(stdout);
    let stdout = thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(mut stdout) = stdout {
            stdout.read_to_end(&mut bytes).unwrap();
        }
        bytes
    });
    let stderr = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).unwrap();
        bytes
    });
    let deadline = Instant::now() + Duration::from_secs(30);
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

fn wssp(root: &Path, args: &[&str]) -> Output {
    run(command(root, args))
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn issued(expiry: u64, interval: u64) -> Value {
    json!({"device_code":"user-code-1","user_code":"USER-CODE","verification_uri":"https://web.example.test/en-US/device","verification_uri_complete":"https://web.example.test/en-US/device?user_code=USER-CODE","expires_in":expiry,"interval":interval})
}

fn minted(secret: &str) -> Value {
    json!({"json":{"keyId":"key-1","secret":secret,"name":"laptop","userId":"user-1","email":"person@example.test","scopes":["sandboxes:read","sandboxes:create"],"poolMode":"SELECTED","poolIds":["pool-1"],"ownSandboxesOnly":true,"expiresAt":"2026-12-18T00:00:00.000Z","maxLiveSandboxes":3}})
}

fn flow_error(status: u16, code: &str, tag: &str) -> Reply {
    reply(
        status,
        json!({"json":{"code":code,"message":"fixture","data":{"deviceFlowError":tag}}}),
    )
}

/// Write a saved login for `server` directly (the file `wssp login` writes).
fn save_login(root: &Path, server: &str, secret: &str) {
    let dir = root.join("data/user");
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    write_login(&dir, server, secret, "key-1");
}

fn write_login(dir: &Path, server: &str, secret: &str, key_id: &str) {
    let origin = format!("{server}/");
    let login = json!({"origin":origin,"keyId":key_id,"name":"laptop","secret":secret,"scopes":["sandboxes:read"],"poolMode":"ALL_USABLE","poolIds":[],"ownSandboxesOnly":false,"expiresAt":null,"maxLiveSandboxes":null,"userEmail":"person@example.test","createdAt":"2026-11-18T00:00:00Z"});
    let staged = dir.join("login.json.fixture");
    fs::write(&staged, login.to_string()).unwrap();
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(&staged, dir.join("login.json")).unwrap();
}

fn login_file(root: &Path) -> std::path::PathBuf {
    root.join("data/user/login.json")
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn sleeps(root: &Path) -> Vec<u64> {
    fs::read_to_string(root.join("sleeps"))
        .unwrap_or_default()
        .lines()
        .map(|l| l.parse().unwrap())
        .collect()
}

fn assert_no_secret(out: &Output, secret: &str) {
    for bytes in [&out.stdout, &out.stderr] {
        assert!(!text(bytes).contains(secret), "credential leaked");
    }
}

#[test]
fn login_pending_then_success_saves_a_private_login_beside_an_untouched_host_enrollment() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    // An enrolled host in the same config and data directories.
    fs::create_dir_all(root.join("data")).unwrap();
    fs::create_dir_all(root.join("config")).unwrap();
    let device = root.join("data/device-auth.json");
    fs::write(&device, b"{\"fixture\":\"host credential\"}").unwrap();
    let config = root.join("config/config.toml");
    fs::write(&config, "server_url = \"https://other.example.test\"\n").unwrap();
    let secret = sdk_key('C');
    let minted_secret = secret.clone();
    let server = Server::new(move |i, request| match i {
        0 => {
            assert!(request.is("POST", ISSUE), "{request:?}");
            let body = request.json();
            assert_eq!(body["client_id"], "wssp");
            assert_eq!(body["scope"], "user-login");
            reply(200, issued(600, 2))
        }
        1 => {
            assert!(request.is("POST", EXCHANGE), "{request:?}");
            assert_eq!(request.json(), json!({"json":{"deviceCode":"user-code-1"}}));
            flow_error(400, "BAD_REQUEST", "authorization_pending")
        }
        2 => reply(200, minted(&minted_secret)),
        3 => {
            // One lookup with the key just minted, for the pool slugs.
            assert!(request.is("GET", "/v1/key"), "{request:?}");
            assert_eq!(
                request.header("authorization"),
                Some(format!("Bearer {minted_secret}").as_str())
            );
            reply(200, selected_key_info())
        }
        _ => panic!("unexpected request {request:?}"),
    });
    let out = wssp(root, &["login", "--server", &server.url]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    for expected in [
        "user code: USER-CODE",
        "https://web.example.test/en-US/device?user_code=USER-CODE",
        "user: person@example.test",
        "login: laptop (key-1)",
        "access: write",
        "pools: team-pool",
        "sandboxes: only those this login creates",
        "live sandbox limit: 3",
        "expires: 2026-12-18T00:00:00.000Z",
    ] {
        assert!(stdout.contains(expected), "{expected}: {stdout}");
    }
    assert!(
        text(&out.stderr).contains("this machine is an enrolled wssp host"),
        "{}",
        text(&out.stderr)
    );
    assert_no_secret(&out, &secret);
    assert_eq!(sleeps(root), [2, 2]);
    let saved: Value = serde_json::from_slice(&fs::read(login_file(root)).unwrap()).unwrap();
    assert_eq!(saved["secret"], secret);
    assert_eq!(saved["origin"], format!("{}/", server.url));
    assert_eq!(saved["userEmail"], "person@example.test");
    assert_eq!(saved["maxLiveSandboxes"], 3);
    assert_eq!(mode(&login_file(root)), 0o600);
    assert_eq!(mode(&root.join("data/user")), 0o700);
    // The host enrollment is untouched.
    assert_eq!(
        fs::read(&device).unwrap(),
        b"{\"fixture\":\"host credential\"}"
    );
    assert_eq!(
        fs::read_to_string(&config).unwrap(),
        "server_url = \"https://other.example.test\"\n"
    );
    assert!(!root.join("data/auth-intent.json").exists());
}

#[test]
fn login_json_reports_start_and_grant_and_slow_down_adds_five_seconds() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let secret = sdk_key('D');
    let minted_secret = secret.clone();
    let server = Server::new(move |i, _| match i {
        0 => reply(200, issued(600, 1)),
        1 => flow_error(400, "BAD_REQUEST", "slow_down"),
        _ => reply(200, minted(&minted_secret)),
    });
    let out = wssp(root, &["login", "--server", &server.url, "--json"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let lines: Vec<Value> = text(&out.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["userCode"], "USER-CODE");
    assert_eq!(lines[1]["keyId"], "key-1");
    assert_eq!(lines[1]["access"], "write");
    assert!(lines[1].get("secret").is_none());
    assert_eq!(sleeps(root), [1, 6]);
    assert!(!text(&out.stderr).contains("enrolled wssp host"));
    // JSON mode makes no key lookup: start, slow_down, grant.
    assert_eq!(server.requests().len(), 3);
}

#[test]
fn login_shows_saved_pool_ids_when_the_key_lookup_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let secret = sdk_key('L');
    let minted_secret = secret.clone();
    let server = Server::new(move |i, request| match i {
        0 => reply(200, issued(600, 1)),
        1 => reply(200, minted(&minted_secret)),
        2 => {
            assert!(request.is("GET", "/v1/key"), "{request:?}");
            api_error(500, "internal", "fixture", None)
        }
        _ => panic!("unexpected request {request:?}"),
    });
    let out = wssp(root, &["login", "--server", &server.url]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(stdout.contains("logged in"), "{stdout}");
    assert!(stdout.contains("pools: pool-1"), "{stdout}");
    assert_no_secret(&out, &secret);
    // A single attempt: no retry of the lookup.
    assert_eq!(server.requests().len(), 3);
    assert!(login_file(root).exists());
}

#[test]
fn login_denied_expired_and_wrong_prefix_save_nothing() {
    for (case, last) in [
        ("denied", flow_error(403, "FORBIDDEN", "access_denied")),
        ("expired", flow_error(400, "BAD_REQUEST", "expired_token")),
        (
            "device secret",
            reply(200, minted(&format!("wssp_device_{}", "E".repeat(43)))),
        ),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let last = Mutex::new(Some(last));
        let server = Server::new(move |i, _| match i {
            0 => reply(200, issued(600, 1)),
            _ => last.lock().unwrap().take().unwrap(),
        });
        let out = wssp(root, &["login", "--server", &server.url]);
        assert_eq!(out.status.code(), Some(1), "{case}: {}", text(&out.stderr));
        let stderr = text(&out.stderr);
        match case {
            "denied" => assert!(stderr.contains("device authorization denied"), "{stderr}"),
            "expired" => assert!(stderr.contains("device authorization expired"), "{stderr}"),
            _ => assert!(stderr.contains("not a `wssp_sdk_` key"), "{stderr}"),
        }
        assert!(!login_file(root).exists(), "{case}");
    }
}

#[test]
fn login_without_server_is_a_usage_error_before_any_request() {
    let tmp = tempfile::tempdir().unwrap();
    let out = wssp(tmp.path(), &["login"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("--server"));
}

#[test]
fn logout_revokes_then_removes_and_local_skips_the_server() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let secret = sdk_key('F');
    let server = Server::new(|_, request| {
        assert!(request.is("DELETE", "/v1/key"), "{request:?}");
        reply(200, json!({"id":"key-1","revoked":true}))
    });
    save_login(root, &server.url, &secret);
    let out = wssp(root, &["logout", "--json"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].header("authorization"),
        Some(format!("Bearer {secret}").as_str())
    );
    let body: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(body["serverRevocation"], "revoked");
    assert!(!login_file(root).exists());
    // Logged out: exit 7, no request.
    let out = wssp(root, &["logout"]);
    assert_eq!(out.status.code(), Some(7));
    assert!(text(&out.stderr).contains("not logged in; run `wssp login --server <url>`"));
    // --local: no request at all.
    save_login(root, &server.url, &secret);
    let out = wssp(root, &["logout", "--local"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(server.requests().len(), 1);
    assert!(!login_file(root).exists());
}

#[test]
fn logout_treats_401_as_already_revoked_but_keeps_the_login_on_other_failures() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let server = Server::new(|i, _| match i {
        0 => api_error(503, "SERVICE_UNAVAILABLE", "busy", None),
        _ => api_error(
            401,
            "UNAUTHORIZED",
            "A valid SDK bearer key is required.",
            None,
        ),
    });
    save_login(root, &server.url, &sdk_key('G'));
    let out = wssp(root, &["logout"]);
    assert_eq!(out.status.code(), Some(11), "{}", text(&out.stderr));
    assert!(login_file(root).exists());
    let out = wssp(root, &["logout"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("no longer accepted"));
    assert!(!login_file(root).exists());
}

fn selected_key_info() -> Value {
    json!({"id":"key-1","name":"laptop","origin":"cliLogin","scopes":["sandboxes:read","sandboxes:create"],"resourceMode":"allOwned","poolMode":"selected","pools":[{"id":"pool-1","slug":"team-pool","label":"Team pool"}],"ownSandboxesOnly":true,"expiresAt":"2026-12-18T00:00:00.000Z","maxLiveSandboxes":3,"liveSandboxes":0})
}

fn key_info() -> Value {
    json!({"id":"key-1","name":"laptop","origin":"cliLogin","scopes":["sandboxes:read"],"resourceMode":"allOwned","poolMode":"allUsable","pools":[],"ownSandboxesOnly":false,"expiresAt":"2026-12-18T00:00:00.000Z","maxLiveSandboxes":2,"liveSandboxes":1})
}

#[test]
fn whoami_reads_the_key_and_offline_makes_no_request() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let server = Server::new(|_, request| {
        assert!(request.is("GET", "/v1/key"), "{request:?}");
        reply(200, key_info())
    });
    let secret = sdk_key('H');
    save_login(root, &server.url, &secret);
    let out = wssp(root, &["whoami"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(stdout.contains("live sandboxes: 1 (limit 2)"), "{stdout}");
    assert!(
        stdout.contains("key expires: 2026-12-18T00:00:00.000Z"),
        "{stdout}"
    );
    let out = wssp(root, &["whoami", "--offline", "--json"]);
    assert!(out.status.success());
    let body: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(body["source"], "file");
    assert_eq!(body["login"]["keyId"], "key-1");
    assert!(body.get("key").is_none());
    assert_eq!(server.requests().len(), 1);
    assert_no_secret(&out, &secret);
}

#[test]
fn json_errors_keep_stderr_to_one_line_with_a_saved_ca_file() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let server = Server::new(|_, _| {
        api_error(
            401,
            "UNAUTHORIZED",
            "A valid SDK bearer key is required.",
            None,
        )
    });
    save_login(root, &server.url, &sdk_key('C'));
    let ca_dir = root.join("ca");
    fs::create_dir(&ca_dir).unwrap();
    fs::set_permissions(&ca_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let ca = ca_dir.join("ca.pem");
    fs::write(&ca, certificates::generate().ca_pem).unwrap();
    fs::set_permissions(&ca, fs::Permissions::from_mode(0o600)).unwrap();
    let mut login: Value = serde_json::from_slice(&fs::read(login_file(root)).unwrap()).unwrap();
    login["caFile"] = json!(ca);
    let staged = root.join("data/user/login.json.fixture");
    fs::write(&staged, login.to_string()).unwrap();
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(&staged, login_file(root)).unwrap();
    // The saved CA file is loaded (`-v` says so; user commands log only
    // errors by default) …
    let out = wssp(root, &["whoami"]);
    assert_eq!(out.status.code(), Some(7), "{}", text(&out.stderr));
    assert!(
        !text(&out.stderr).contains("loaded extra CA certificates"),
        "{}",
        text(&out.stderr)
    );
    let out = wssp(root, &["-v", "whoami"]);
    assert_eq!(out.status.code(), Some(7), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("loaded extra CA certificates"),
        "{}",
        text(&out.stderr)
    );
    // … but `--json` keeps stderr to the single error line.
    for args in [vec!["whoami", "--json"], vec!["sandbox", "list", "--json"]] {
        let out = wssp(root, &args);
        assert_eq!(out.status.code(), Some(7), "{}", text(&out.stderr));
        assert!(out.stdout.is_empty());
        let stderr = text(&out.stderr);
        assert_eq!(stderr.lines().count(), 1, "{stderr}");
        let line: Value = serde_json::from_str(stderr.trim()).unwrap();
        assert_eq!(line["error"]["code"], "UNAUTHORIZED");
    }
}

#[test]
fn env_credential_wins_over_the_saved_login_and_needs_both_variables() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let file_server = Server::new(|_, request| panic!("file login used: {request:?}"));
    save_login(root, &file_server.url, &sdk_key('I'));
    let env_secret = sdk_key('J');
    let env_server = Server::new(|_, _| reply(200, key_info()));
    let mut cmd = command(root, &["whoami", "--json"]);
    cmd.env("WSSP_API_KEY", &env_secret)
        .env("WSSP_SERVER", &env_server.url);
    let out = run(cmd);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let body: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(body["source"], "env");
    let requests = env_server.requests();
    assert_eq!(
        requests[0].header("authorization"),
        Some(format!("Bearer {env_secret}").as_str())
    );
    for (name, value) in [
        ("WSSP_API_KEY", env_secret.as_str()),
        ("WSSP_SERVER", "http://127.0.0.1:1"),
    ] {
        let mut cmd = command(root, &["sandbox", "list"]);
        cmd.env(name, value);
        let out = run(cmd);
        assert_eq!(out.status.code(), Some(2), "{name}");
        assert!(text(&out.stderr).contains("must be set together"));
    }
    let mut cmd = command(root, &["sandbox", "list"]);
    cmd.env("WSSP_API_KEY", "wssp_sdk_short")
        .env("WSSP_SERVER", &env_server.url);
    let out = run(cmd);
    assert_eq!(out.status.code(), Some(2));
    assert!(!text(&out.stderr).contains("wssp_sdk_short"));
}

#[test]
fn user_commands_without_a_login_exit_7_before_any_network_or_state() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    for args in [
        vec!["sandbox", "list"],
        vec!["sandbox", "get", "sbx-1"],
        vec!["sandbox", "exec", "sbx-1", "--", "true"],
        vec!["sandbox", "files", "read", "sbx-1", "/etc/hostname"],
        vec!["sandbox", "ports", "get", "sbx-1"],
        vec!["template", "list"],
        vec!["whoami"],
        vec!["logout"],
    ] {
        let out = wssp(root, &args);
        assert_eq!(out.status.code(), Some(7), "{args:?}");
        assert!(
            text(&out.stderr).contains("not logged in; run `wssp login --server <url>`"),
            "{args:?}"
        );
        assert!(out.stdout.is_empty());
    }
    assert!(!root.join("data").exists());
    assert!(!root.join("config").exists());
}

/// One logged-in request answered by `answer`; returns the output.
fn against(answer: Reply, args: &[&str]) -> Output {
    let tmp = tempfile::tempdir().unwrap();
    let answer = Mutex::new(Some(answer));
    let server = Server::new(move |_, _| {
        answer
            .lock()
            .unwrap()
            .take()
            .unwrap_or_else(|| api_error(500, "INTERNAL_SERVER_ERROR", "repeat", None))
    });
    save_login(tmp.path(), &server.url, &sdk_key('K'));
    wssp(tmp.path(), args)
}

#[test]
fn api_errors_map_to_exit_codes_with_the_server_code_in_the_message() {
    for (answer, args, code, needle) in [
        (
            api_error(
                401,
                "UNAUTHORIZED",
                "A valid SDK bearer key is required.",
                None,
            ),
            vec!["sandbox", "get", "sbx-1"],
            7,
            "`UNAUTHORIZED`: A valid SDK bearer key is required.",
        ),
        (
            api_error(
                403,
                "FORBIDDEN",
                "This key cannot perform this action.",
                None,
            ),
            vec!["sandbox", "list"],
            8,
            "`FORBIDDEN`",
        ),
        (
            api_error(
                409,
                "sandbox.key_limit_reached",
                "This key's live sandbox limit is reached.",
                Some(json!({"maxLiveSandboxes":1,"liveSandboxes":1})),
            ),
            vec![
                "sandbox",
                "create",
                "--template",
                "ubuntu",
                "--pool",
                "pool-1",
            ],
            9,
            "`sandbox.key_limit_reached`: This key's live sandbox limit is reached.",
        ),
        (
            api_error(
                409,
                "sandbox.state_conflict",
                "Sandbox state conflicts with this action.",
                None,
            ),
            vec!["sandbox", "stop", "sbx-1"],
            10,
            "`sandbox.state_conflict`",
        ),
        (
            api_error(
                503,
                "SERVICE_UNAVAILABLE",
                "Service temporarily unavailable.",
                None,
            ),
            vec!["template", "list"],
            11,
            "`SERVICE_UNAVAILABLE`",
        ),
        (
            api_error(404, "sandbox.not_found", "Sandbox not found.", None),
            vec!["sandbox", "get", "sbx-1"],
            3,
            "`sandbox.not_found`",
        ),
        (
            api_error(400, "BAD_REQUEST", "Invalid request.", None),
            vec!["sandbox", "list", "--state", "NOPE"],
            2,
            "`BAD_REQUEST`",
        ),
    ] {
        let out = against(answer, &args);
        assert_eq!(
            out.status.code(),
            Some(code),
            "{args:?}: {}",
            text(&out.stderr)
        );
        assert!(text(&out.stderr).contains(needle), "{}", text(&out.stderr));
        assert!(out.stdout.is_empty());
    }
}

#[test]
fn json_errors_are_one_line_on_stderr_with_stdout_empty() {
    let out = against(
        api_error(
            409,
            "sandbox.key_limit_reached",
            "This key's live sandbox limit is reached.",
            Some(json!({"maxLiveSandboxes":1,"liveSandboxes":1})),
        ),
        &[
            "sandbox",
            "create",
            "--template",
            "ubuntu",
            "--host",
            "host-1",
            "--json",
        ],
    );
    assert_eq!(out.status.code(), Some(9));
    assert!(out.stdout.is_empty());
    let stderr = text(&out.stderr);
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    let line: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(line["error"]["code"], "sandbox.key_limit_reached");
    assert_eq!(line["error"]["status"], 409);
    assert_eq!(line["error"]["data"]["maxLiveSandboxes"], 1);
    assert!(
        line["error"]["message"]
            .as_str()
            .unwrap()
            .contains("This key's live sandbox limit is reached.")
    );
    // A local failure has a stable code and no status.
    let tmp = tempfile::tempdir().unwrap();
    let out = wssp(tmp.path(), &["sandbox", "list", "--json"]);
    assert_eq!(out.status.code(), Some(7));
    let line: Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(line["error"]["code"], "not_logged_in");
    assert_eq!(line["error"]["status"], Value::Null);
}

fn b64(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(TABLE[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn output_page(chunks: &[(&str, &[u8])], exit_code: Option<i64>, complete: bool) -> Value {
    output_page_at(0, chunks, exit_code, complete)
}

/// A page whose first chunk starts at aggregate offset `start`.
fn output_page_at(
    start: usize,
    chunks: &[(&str, &[u8])],
    exit_code: Option<i64>,
    complete: bool,
) -> Value {
    let mut offset = start;
    let chunks: Vec<Value> = chunks
        .iter()
        .map(|(stream, bytes)| {
            let chunk = json!({"stream": stream, "offset": offset, "data": b64(bytes)});
            offset += bytes.len();
            chunk
        })
        .collect();
    json!({"operationId":"op-1","state": if complete { "SUCCEEDED" } else { "RUNNING" },"exitCode":exit_code,"attempt":1,"reset":false,"offset":start,"chunks":chunks,"gaps":[],"nextCursor":"c1","hasMore":false,"receivedBytes":offset,"totalBytes":offset,"retainedBytes":offset,"truncated":false,"complete":complete,"expiresAt":null})
}

fn exec_server(final_page: Value, operation: Option<Value>) -> (Server, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let server = Server::new(move |_, request| {
        if request.is("POST", "/v1/sandboxes/sbx-1/commands") {
            assert!(request.header("idempotency-key").is_some());
            assert_eq!(request.json()["argv"], json!(["sh", "-c", "echo hello"]));
            return reply(
                202,
                json!({"operationId":"op-1","state":"QUEUED","location":"/v1/operations/op-1"}),
            );
        }
        if request.is("GET", "/v1/operations/op-1/output") {
            if request.target.contains("cursor=c1") {
                return reply(200, final_page.clone());
            }
            assert!(request.target.contains("waitMs="), "{}", request.target);
            return reply(200, output_page(&[("stdout", b"hello\n")], None, false));
        }
        if request.is("GET", "/v1/operations/op-1") {
            return reply(200, operation.clone().unwrap());
        }
        panic!("unexpected request {request:?}");
    });
    save_login(tmp.path(), &server.url, &sdk_key('L'));
    (server, tmp)
}

#[test]
fn exec_streams_output_and_exits_with_the_guest_exit_code() {
    let last = output_page_at(6, &[("stderr", b"oops\n")], Some(3), true);
    let (_server, tmp) = exec_server(last, None);
    let out = wssp(
        tmp.path(),
        &["sandbox", "exec", "sbx-1", "--", "sh", "-c", "echo hello"],
    );
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "hello\n");
    assert!(text(&out.stderr).contains("oops"));
    assert!(!text(&out.stderr).contains("error:"));
}

#[test]
fn exec_json_collects_and_still_exits_with_the_guest_code() {
    let (_server, tmp) = exec_server(
        output_page_at(6, &[("stdout", b"bye\n")], Some(0), true),
        None,
    );
    let out = wssp(
        tmp.path(),
        &[
            "sandbox",
            "exec",
            "sbx-1",
            "--json",
            "--",
            "sh",
            "-c",
            "echo hello",
        ],
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    let body: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(body["operationId"], "op-1");
    assert_eq!(body["exitCode"], 0);
    assert_eq!(body["stdout"], "hello\nbye\n");
    assert_eq!(body["truncated"], false);
}

#[test]
fn exec_without_an_exit_code_or_with_a_refusal_exits_125() {
    let failed = json!({"id":"op-1","sandboxId":"sbx-1","kind":"RUN_COMMAND","state":"FAILED","outcome":"failed","generation":1,"leaseIntent":null,"failure":null,"errorCode":"command_timeout","createdAt":"2026-11-18T00:00:00.000Z","updatedAt":"2026-11-18T00:00:00.000Z","dispatchedAt":null,"completedAt":null});
    let mut last = output_page(&[], None, true);
    last["state"] = json!("FAILED");
    let (_server, tmp) = exec_server(last, Some(failed));
    let out = wssp(
        tmp.path(),
        &["sandbox", "exec", "sbx-1", "--", "sh", "-c", "echo hello"],
    );
    assert_eq!(out.status.code(), Some(125), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("`command_timeout`"),
        "{}",
        text(&out.stderr)
    );
    // A refused start is wssp-side too: 125, with the server's code.
    let out = against(
        api_error(
            403,
            "FORBIDDEN",
            "This key cannot perform this action.",
            None,
        ),
        &["sandbox", "exec", "sbx-1", "--json", "--", "true"],
    );
    assert_eq!(out.status.code(), Some(125));
    let line: Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(line["error"]["code"], "FORBIDDEN");
    assert_eq!(line["error"]["status"], 403);
}

#[test]
fn exec_detach_prints_the_operation_id() {
    let (server, tmp) = exec_server(json!({}), None);
    let out = wssp(
        tmp.path(),
        &[
            "sandbox",
            "exec",
            "sbx-1",
            "--detach",
            "--",
            "sh",
            "-c",
            "echo hello",
        ],
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "op-1\n");
    assert_eq!(server.requests().len(), 1);
}

fn exec_args() -> Vec<&'static str> {
    vec!["sandbox", "exec", "sbx-1", "--", "sh", "-c", "echo hello"]
}

fn exec_json_args() -> Vec<&'static str> {
    vec![
        "sandbox",
        "exec",
        "sbx-1",
        "--json",
        "--",
        "sh",
        "-c",
        "echo hello",
    ]
}

#[test]
fn exec_and_logs_into_a_closed_stdout_exit_141_and_exec_cancels() {
    let tmp = tempfile::tempdir().unwrap();
    let pages = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let server = Server::new(move |_, request| {
        if request.is("POST", "/v1/sandboxes/sbx-1/commands") {
            return reply(
                202,
                json!({"operationId":"op-1","state":"QUEUED","location":"/v1/operations/op-1"}),
            );
        }
        if request.is("GET", "/v1/operations/op-1/output") {
            // A command that keeps printing and never completes.
            let n = pages.fetch_add(1, Ordering::SeqCst);
            return reply(
                200,
                output_page_at(n * 6, &[("stdout", b"chunk\n")], None, false),
            );
        }
        if request.is("POST", "/v1/operations/op-1/cancel") {
            assert!(request.header("idempotency-key").is_some());
            return reply(
                202,
                json!({"operationId":"op-2","state":"QUEUED","location":"/v1/operations/op-2"}),
            );
        }
        panic!("unexpected request {request:?}");
    });
    save_login(tmp.path(), &server.url, &sdk_key('M'));
    let out = run_with(command(tmp.path(), &exec_args()), true);
    assert_eq!(out.status.code(), Some(141), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("cancellation of operation `op-1` was requested"),
        "{}",
        text(&out.stderr)
    );
    let cancels = |server: &Server| {
        server
            .requests()
            .iter()
            .filter(|r| r.is("POST", "/v1/operations/op-1/cancel"))
            .count()
    };
    assert_eq!(cancels(&server), 1);
    // `logs --follow` stops following (it never cancels).
    let out = run_with(
        command(tmp.path(), &["sandbox", "logs", "op-1", "--follow"]),
        true,
    );
    assert_eq!(out.status.code(), Some(141), "{}", text(&out.stderr));
    assert_eq!(cancels(&server), 1);
}

#[test]
fn exec_json_capture_is_bounded_and_marked_truncated() {
    let big: Vec<u8> = (0..1_200_000_u32).map(|i| b'a' + (i % 26) as u8).collect();
    let last = output_page_at(6, &[("stdout", &big)], Some(0), true);
    let (_server, tmp) = exec_server(last, None);
    let out = wssp(tmp.path(), &exec_json_args());
    assert!(out.status.success(), "{}", text(&out.stderr));
    let body: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(body["truncated"], true);
    let stdout = body["stdout"].as_str().unwrap();
    // The first 256 KiB and the last 768 KiB.
    assert_eq!(stdout.len(), 1024 * 1024);
    assert!(stdout.starts_with("hello\nabc"));
    assert!(stdout.ends_with(std::str::from_utf8(&big[big.len() - 64..]).unwrap()));
}

#[test]
fn exec_passes_the_exit_code_through_only_for_a_succeeded_command() {
    // FAILED with an exit code: wssp-side, 125.
    let failed = json!({"id":"op-1","sandboxId":"sbx-1","kind":"RUN_COMMAND","state":"FAILED","outcome":"failed","generation":1,"leaseIntent":null,"failure":null,"errorCode":"command_failed","createdAt":"2026-11-18T00:00:00.000Z","updatedAt":"2026-11-18T00:00:00.000Z","dispatchedAt":null,"completedAt":null});
    let mut last = output_page_at(6, &[], Some(3), true);
    last["state"] = json!("FAILED");
    let (_server, tmp) = exec_server(last, Some(failed));
    let out = wssp(tmp.path(), &exec_args());
    assert_eq!(out.status.code(), Some(125), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("`command_failed`"));
    // An exit code outside 0–255 is never wrapped (256 would become 0).
    let (_server, tmp) = exec_server(output_page_at(6, &[], Some(256), true), None);
    let out = wssp(tmp.path(), &exec_args());
    assert_eq!(out.status.code(), Some(125), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("outside 0–255"));
}

#[test]
fn exec_json_restarts_on_a_new_attempt_and_never_repeats_delivered_bytes() {
    let mut last = output_page(&[("stdout", b"new\n")], Some(0), true);
    last["attempt"] = json!(2);
    last["reset"] = json!(true);
    let (_server, tmp) = exec_server(last, None);
    let out = wssp(tmp.path(), &exec_json_args());
    assert!(out.status.success(), "{}", text(&out.stderr));
    let body: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(body["stdout"], "new\n");
    // `--json` keeps stderr free of notes: the restart is a field.
    assert_eq!(body["restarts"], 1);
    assert!(out.stderr.is_empty(), "{}", text(&out.stderr));
    // A page reaching back over delivered bytes adds only the new suffix.
    let last = output_page(&[("stdout", b"hello\nbye\n")], Some(0), true);
    let (_server, tmp) = exec_server(last, None);
    let out = wssp(tmp.path(), &exec_json_args());
    let body: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(body["stdout"], "hello\nbye\n");
}

#[test]
fn exec_json_records_gaps_in_the_result_and_writes_nothing_to_stderr() {
    let mut last = output_page_at(16, &[("stdout", b"tail\n")], Some(0), true);
    last["gaps"] = json!([{"start": 6, "end": 16}]);
    let (_server, tmp) = exec_server(last.clone(), None);
    let out = wssp(tmp.path(), &exec_json_args());
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(out.stderr.is_empty(), "{}", text(&out.stderr));
    let body: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(body["stdout"], "hello\ntail\n");
    assert_eq!(body["gaps"], json!([{"start": 6, "end": 16}]));
    assert_eq!(body["gapsOmitted"], 0);
    assert_eq!(body["restarts"], 0);
    // Streaming notes the same gap on stderr.
    let (_server, tmp) = exec_server(last, None);
    let out = wssp(tmp.path(), &exec_args());
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("10 bytes of output were not retained (bytes 6–16)"),
        "{}",
        text(&out.stderr)
    );
}

/// Run `cmd`, send it SIGINT once `ready` holds, and collect its output.
fn run_interrupted(mut cmd: Command, ready: impl Fn() -> bool) -> (Output, Duration) {
    let child = ManagedChild::spawn(&mut cmd).unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while !ready() {
        assert!(Instant::now() < deadline, "the CLI never got ready");
        thread::sleep(Duration::from_millis(10));
    }
    // Let the CLI reach its retry wait.
    thread::sleep(Duration::from_millis(200));
    let interrupted = Instant::now();
    assert!(
        Command::new("kill")
            .args(["-INT", &child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let out = child.wait_with_output().unwrap();
    (out, interrupted.elapsed())
}

#[test]
fn exec_interrupted_while_starting_sends_no_new_start_and_exits_130() {
    for (status, ambiguous) in [(503, true), (429, false)] {
        let tmp = tempfile::tempdir().unwrap();
        let server = Server::new(move |_, request| {
            assert!(
                request.is("POST", "/v1/sandboxes/sbx-1/commands"),
                "{request:?}"
            );
            let mut answer = api_error(status, "BUSY", "busy", None);
            answer.headers.push(("Retry-After".into(), "5".into()));
            answer
        });
        save_login(tmp.path(), &server.url, &sdk_key('S'));
        let (out, elapsed) = run_interrupted(command(tmp.path(), &exec_args()), || {
            !server.requests().is_empty()
        });
        let stderr = text(&out.stderr);
        assert_eq!(out.status.code(), Some(130), "{stderr}");
        assert!(elapsed < Duration::from_secs(4), "{elapsed:?}");
        let requests = server.requests();
        assert_eq!(requests.len(), 1, "a start was sent after the interrupt");
        let key = requests[0].header("idempotency-key").unwrap();
        if ambiguous {
            assert!(stderr.contains(key), "{stderr}");
            assert!(stderr.contains("may have been accepted"), "{stderr}");
            assert!(stderr.contains("wssp sandbox ps sbx-1"), "{stderr}");
        } else {
            assert!(!stderr.contains(key), "{stderr}");
            assert!(
                stderr.contains("before the command was started"),
                "{stderr}"
            );
        }
    }
}

#[test]
fn exec_client_setup_failures_exit_125_and_input_errors_keep_their_codes() {
    let tmp = tempfile::tempdir().unwrap();
    let server = Server::new(|_, request| panic!("unexpected request {request:?}"));
    save_login(tmp.path(), &server.url, &sdk_key('T'));
    let mut cmd = command(tmp.path(), &exec_json_args());
    cmd.env("WSSP_CA_FILE", tmp.path().join("missing-ca.pem"));
    let out = run(cmd);
    assert_eq!(out.status.code(), Some(125), "{}", text(&out.stderr));
    let line: Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(line["error"]["code"], "exec_failed");
    // An invalid sandbox id stays a usage error.
    let out = wssp(tmp.path(), &["sandbox", "exec", "bad/id", "--", "true"]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert!(server.requests().is_empty());
}

#[test]
fn exec_credential_loading_failures_exit_125_but_no_login_stays_7() {
    let tmp = tempfile::tempdir().unwrap();
    // No login at all: 7.
    let out = wssp(tmp.path(), &exec_json_args());
    assert_eq!(out.status.code(), Some(7), "{}", text(&out.stderr));
    // A malformed login file: wssp-side, 125.
    let dir = tmp.path().join("data/user");
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(dir.join("login.json"), "{not json").unwrap();
    fs::set_permissions(dir.join("login.json"), fs::Permissions::from_mode(0o600)).unwrap();
    let out = wssp(tmp.path(), &exec_json_args());
    assert_eq!(out.status.code(), Some(125), "{}", text(&out.stderr));
    let line: Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(line["error"]["code"], "exec_failed");
    // An unreadable login file: 125.
    fs::set_permissions(dir.join("login.json"), fs::Permissions::from_mode(0o000)).unwrap();
    if fs::read(dir.join("login.json")).is_err() {
        let out = wssp(tmp.path(), &exec_args());
        assert_eq!(out.status.code(), Some(125), "{}", text(&out.stderr));
    }
    // An invalid env credential: 125 (other user commands keep 2).
    let other = tempfile::tempdir().unwrap();
    let mut cmd = command(other.path(), &exec_args());
    cmd.env("WSSP_API_KEY", "not-a-key")
        .env("WSSP_SERVER", "https://wssp.example.test");
    let out = run(cmd);
    assert_eq!(out.status.code(), Some(125), "{}", text(&out.stderr));
    let mut cmd = command(other.path(), &["sandbox", "list"]);
    cmd.env("WSSP_API_KEY", "not-a-key")
        .env("WSSP_SERVER", "https://wssp.example.test");
    assert_eq!(run(cmd).status.code(), Some(2));
}

#[test]
fn server_requested_retry_delays_are_never_shortened() {
    let tmp = tempfile::tempdir().unwrap();
    let server = Server::new(|_, _| {
        let mut answer = api_error(503, "SERVICE_UNAVAILABLE", "busy", None);
        answer.headers.push(("Retry-After".into(), "300".into()));
        answer
    });
    save_login(tmp.path(), &server.url, &sdk_key('U'));
    let started = Instant::now();
    let out = wssp(tmp.path(), &["sandbox", "stop", "sbx-1"]);
    // 300 s does not fit the retry deadline: the answer is returned at once.
    assert_eq!(out.status.code(), Some(11), "{}", text(&out.stderr));
    assert_eq!(server.requests().len(), 1);
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[test]
fn start_sends_the_lease_only_when_timeout_is_given() {
    let tmp = tempfile::tempdir().unwrap();
    let server = Server::new(|_, request| {
        assert!(
            request.is("POST", "/v1/sandboxes/sbx-1/reconnect"),
            "{}",
            request.target
        );
        reply(
            202,
            json!({"operationId":"op-1","state":"QUEUED","location":"/v1/operations/op-1"}),
        )
    });
    save_login(tmp.path(), &server.url, &sdk_key('T'));
    let out = wssp(
        tmp.path(),
        &["sandbox", "start", "sbx-1", "--timeout", "2h"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("start accepted (operation op-1, QUEUED)"));
    let out = wssp(tmp.path(), &["sandbox", "start", "sbx-1"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let out = wssp(tmp.path(), &["sandbox", "start", "sbx-1", "--timeout", "0"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let bodies: Vec<Value> = server.requests().iter().map(Request::json).collect();
    assert_eq!(
        bodies,
        vec![
            json!({"mode": "cold", "timeoutMs": 7_200_000}),
            json!({"mode": "cold"}),
            json!({"mode": "cold", "timeoutMs": 0}),
        ]
    );
    let out = wssp(
        tmp.path(),
        &["sandbox", "start", "sbx-1", "--timeout", "5x"],
    );
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(server.requests().len(), 3);
}

fn template_row(id: &str) -> Value {
    json!({"id": id, "slug": id, "label": id, "archivedAt": null, "createdAt": "2026-11-18T00:00:00.000Z"})
}

#[test]
fn template_get_pages_until_found_and_stops_with_its_own_error_at_the_cap() {
    let tmp = tempfile::tempdir().unwrap();
    let server = Server::new(|_, request| {
        if request.is("GET", "/v1/templates/tpl-far/revisions")
            || request.is("GET", "/v1/templates/tpl-never/revisions")
        {
            return reply(200, json!({"items": [], "nextCursor": null}));
        }
        assert!(request.is("GET", "/v1/templates"), "{request:?}");
        let page: usize = request
            .target
            .split("cursor=p")
            .nth(1)
            .map_or(0, |n| n.parse().unwrap());
        let mut items = vec![template_row(&format!("tpl-{page}"))];
        if page == 14 {
            items.push(template_row("tpl-far"));
        }
        reply(
            200,
            json!({"items": items, "nextCursor": format!("p{}", page + 1)}),
        )
    });
    save_login(tmp.path(), &server.url, &sdk_key('V'));
    let out = wssp(tmp.path(), &["template", "get", "tpl-far", "--json"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let body: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(body["template"]["id"], "tpl-far");
    // Never found in an endless list: a distinct error, not a not-found.
    let out = wssp(tmp.path(), &["template", "get", "tpl-never"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("searched 101 templates without finding template `tpl-never`"),
        "{}",
        text(&out.stderr)
    );
    // The list ending without it is a plain not-found.
    let end = Server::new(|_, request| {
        if request.is("GET", "/v1/templates/tpl-gone/revisions") {
            return reply(200, json!({"items": [], "nextCursor": null}));
        }
        reply(
            200,
            json!({"items": [template_row("tpl-a")], "nextCursor": null}),
        )
    });
    let tmp = tempfile::tempdir().unwrap();
    save_login(tmp.path(), &end.url, &sdk_key('W'));
    let out = wssp(tmp.path(), &["template", "get", "tpl-gone"]);
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
}

#[test]
fn files_write_refuses_a_reservation_with_another_chunk_size() {
    let tmp = tempfile::tempdir().unwrap();
    const TRANSFER: &str = "00000000-0000-4000-8000-000000000002";
    let server = Server::new(|_, request| {
        if request.is("POST", "/v1/transfers") {
            return reply(
                201,
                json!({"id":TRANSFER,"chunkBytes":4096,"receivedBytes":0}),
            );
        }
        if request.is("DELETE", &format!("/v1/transfers/{TRANSFER}")) {
            return reply(200, json!({}));
        }
        panic!("unexpected request {request:?}");
    });
    save_login(tmp.path(), &server.url, &sdk_key('X'));
    let source = tmp.path().join("in.txt");
    fs::write(&source, b"some bytes").unwrap();
    let out = wssp(
        tmp.path(),
        &[
            "sandbox",
            "files",
            "write",
            "sbx-1",
            "/home/user/in.txt",
            "--from",
            source.to_str().unwrap(),
        ],
    );
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("chunk size 4096"),
        "{}",
        text(&out.stderr)
    );
    let requests = server.requests();
    assert!(!requests.iter().any(|r| r.method == "PUT"));
    assert!(requests.iter().any(|r| r.method == "DELETE"));
}

#[test]
fn user_dir_override_never_overlaps_host_dirs_and_is_never_chmodded() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let server = Server::new(|_, request| panic!("unexpected request {request:?}"));
    for dir in [
        root.join("data"),
        root.join("config/nested"),
        root.to_path_buf(),
        root.join("data/user/../other"),
    ] {
        let mut cmd = command(root, &["login", "--server", &server.url]);
        cmd.env("WSSP_USER_DIR", &dir);
        let out = run(cmd);
        assert_eq!(out.status.code(), Some(2), "{dir:?}: {}", text(&out.stderr));
        assert!(text(&out.stderr).contains("overlaps the host"), "{dir:?}");
    }
    assert!(server.requests().is_empty());
    // An existing override is used as it is: refused while group or other
    // writable, never chmodded.
    let other = tempfile::tempdir().unwrap();
    let shared = other.path().join("shared");
    fs::create_dir(&shared).unwrap();
    write_login(&shared, &server.url, &sdk_key('N'), "key-1");
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
    let whoami = |dir: &Path| {
        let mut cmd = command(root, &["whoami", "--offline"]);
        cmd.env("WSSP_USER_DIR", dir);
        run(cmd)
    };
    let out = whoami(&shared);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("writable by group or others"));
    assert_eq!(mode(&shared), 0o777);
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o750)).unwrap();
    let out = whoami(&shared);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(mode(&shared), 0o750);
    // Publishing a new login into the existing 0750 override keeps its mode.
    let secret = sdk_key('Y');
    let minted_secret = secret.clone();
    let issuer = Server::new(move |i, _| match i {
        0 => reply(200, issued(600, 1)),
        _ => reply(200, minted(&minted_secret)),
    });
    let mut cmd = command(root, &["login", "--server", &issuer.url]);
    cmd.env("WSSP_USER_DIR", &shared);
    let out = run(cmd);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(mode(&shared), 0o750);
    assert_eq!(mode(&shared.join("login.json")), 0o600);
    let saved: Value =
        serde_json::from_slice(&fs::read(shared.join("login.json")).unwrap()).unwrap();
    assert_eq!(saved["secret"], secret);
    // The default location given explicitly is not an overlap.
    save_login(root, &server.url, &sdk_key('N'));
    let out = whoami(&root.join("data/user"));
    assert!(out.status.success(), "{}", text(&out.stderr));
}

#[test]
fn user_dir_override_resolves_symlinks_before_parent_components() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let child = root.join("data/child");
    fs::create_dir_all(&child).unwrap();
    let safe = tempfile::tempdir().unwrap();
    let link = safe.path().join("link");
    std::os::unix::fs::symlink(&child, &link).unwrap();
    // `link/..` is `<data>`, not the directory holding the link.
    let dir = link.join("..");
    for args in [vec!["whoami", "--offline"], vec!["logout"]] {
        let mut cmd = command(root, &args);
        cmd.env("WSSP_USER_DIR", &dir);
        let out = run(cmd);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{args:?}: {}",
            text(&out.stderr)
        );
        assert!(
            text(&out.stderr).contains("overlaps the host data"),
            "{}",
            text(&out.stderr)
        );
    }
    assert!(!root.join("data/login.lock").exists());
    assert!(!safe.path().join("login.lock").exists());
}

#[test]
fn a_symlinked_default_user_dir_is_refused_and_never_sweeps_host_staging_files() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let server = Server::new(|_, request| panic!("unexpected request {request:?}"));
    let data = root.join("data");
    fs::create_dir_all(&data).unwrap();
    // An abandoned host staging file the host store's own sweep owns.
    let staging = data.join(format!(".wssp-staging-{}.tmp", "ab".repeat(16)));
    fs::write(&staging, b"host staging").unwrap();
    std::os::unix::fs::symlink(".", data.join("user")).unwrap();
    for given in [None, Some(data.clone()), Some(data.join("user"))] {
        for args in [
            vec!["whoami", "--offline"],
            vec!["logout", "--local"],
            vec!["login", "--server", server.url.as_str()],
        ] {
            let mut cmd = command(root, &args);
            if let Some(dir) = &given {
                cmd.env("WSSP_USER_DIR", dir);
            }
            let out = run(cmd);
            assert_eq!(
                out.status.code(),
                Some(2),
                "{given:?} {args:?}: {}",
                text(&out.stderr)
            );
            assert!(
                text(&out.stderr).contains("overlaps the host data"),
                "{}",
                text(&out.stderr)
            );
        }
    }
    assert!(server.requests().is_empty());
    assert_eq!(fs::read(&staging).unwrap(), b"host staging");
    assert!(!data.join("login.lock").exists());
    // A plain default directory works and the user sweep still leaves host
    // staging names alone.
    fs::remove_file(data.join("user")).unwrap();
    save_login(root, &server.url, &sdk_key('P'));
    let foreign = data
        .join("user")
        .join(format!(".wssp-staging-{}.tmp", "cd".repeat(16)));
    fs::write(&foreign, b"not the user store's").unwrap();
    let out = wssp(root, &["whoami", "--offline"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("laptop"),
        "{}",
        text(&out.stdout)
    );
    assert!(foreign.exists());
    assert_eq!(fs::read(&staging).unwrap(), b"host staging");
}

#[test]
fn exec_interrupted_while_its_output_is_blocked_cancels_and_exits_130() {
    let tmp = tempfile::tempdir().unwrap();
    let pages = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let served = pages.clone();
    let chunk = vec![b'x'; 64 * 1024];
    let server = Server::new(move |_, request| {
        if request.is("POST", "/v1/sandboxes/sbx-1/commands") {
            return reply(
                202,
                json!({"operationId":"op-1","state":"QUEUED","location":"/v1/operations/op-1"}),
            );
        }
        if request.is("GET", "/v1/operations/op-1/output") {
            // A command that keeps printing a lot and never completes.
            let n = served.fetch_add(1, Ordering::SeqCst);
            return reply(
                200,
                output_page_at(n * chunk.len(), &[("stdout", &chunk)], None, false),
            );
        }
        if request.is("POST", "/v1/operations/op-1/cancel") {
            return reply(
                202,
                json!({"operationId":"op-2","state":"QUEUED","location":"/v1/operations/op-2"}),
            );
        }
        panic!("unexpected request {request:?}");
    });
    save_login(tmp.path(), &server.url, &sdk_key('B'));
    let mut cmd = command(tmp.path(), &exec_args());
    let mut child = ManagedChild::spawn(&mut cmd).unwrap();
    // stdout is a pipe nobody reads: the writer blocks once it is full.
    let unread = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let stderr = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).unwrap();
        bytes
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    // More pages than the pipe buffer and the event queue hold.
    while pages.load(Ordering::SeqCst) < 4 {
        assert!(Instant::now() < deadline, "the CLI never streamed");
        thread::sleep(Duration::from_millis(10));
    }
    thread::sleep(Duration::from_millis(300));
    assert!(child.try_wait().unwrap().is_none(), "the CLI exited early");
    let interrupted = Instant::now();
    assert!(
        Command::new("kill")
            .args(["-INT", &child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(
            interrupted.elapsed() < Duration::from_secs(8),
            "Ctrl-C did not end a CLI blocked on its output"
        );
        thread::sleep(Duration::from_millis(10));
    };
    drop(unread);
    let stderr = text(&stderr.join().unwrap());
    assert_eq!(status.code(), Some(130), "{stderr}");
    assert!(
        stderr.contains("cancellation of operation `op-1` was requested"),
        "{stderr}"
    );
    let cancels = server
        .requests()
        .iter()
        .filter(|r| r.is("POST", "/v1/operations/op-1/cancel"))
        .count();
    assert_eq!(cancels, 1);
}

#[test]
fn login_json_on_an_enrolled_host_keeps_a_failure_to_one_json_line() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::create_dir_all(root.join("data")).unwrap();
    fs::write(root.join("data/device-auth.json"), b"{}").unwrap();
    let server = Server::new(|_, request| panic!("unexpected request {request:?}"));
    let missing = root.join("missing-ca.pem");
    let out = wssp(
        root,
        &[
            "login",
            "--server",
            &server.url,
            "--ca-file",
            missing.to_str().unwrap(),
            "--json",
        ],
    );
    assert!(!out.status.success());
    assert!(out.stdout.is_empty(), "{}", text(&out.stdout));
    let stderr = text(&out.stderr);
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    let line: Value = serde_json::from_str(stderr.trim_end()).unwrap();
    assert!(line["error"]["code"].is_string(), "{line}");
    assert!(!stderr.contains("enrolled wssp host"), "{stderr}");
    assert!(server.requests().is_empty());
    // A success carries the warning in the JSON object, not on stderr.
    let secret = sdk_key('W');
    let minted_secret = secret.clone();
    let issuer = Server::new(move |i, _| match i {
        0 => reply(200, issued(600, 1)),
        _ => reply(200, minted(&minted_secret)),
    });
    let out = wssp(root, &["login", "--server", &issuer.url, "--json"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(out.stderr.is_empty(), "{}", text(&out.stderr));
    let last: Value = serde_json::from_str(text(&out.stdout).lines().last().unwrap()).unwrap();
    let warnings = last["warnings"].as_array().unwrap();
    assert_eq!(warnings.len(), 1, "{last}");
    assert!(
        warnings[0]
            .as_str()
            .unwrap()
            .contains("this machine is an enrolled wssp host"),
        "{last}"
    );
    assert_no_secret(&out, &secret);
}

#[test]
fn logout_does_not_hold_the_login_lock_across_revocation() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let release = Arc::new(AtomicBool::new(false));
    let released = release.clone();
    let server = Server::new(move |_, request| {
        assert!(request.is("DELETE", "/v1/key"), "{request:?}");
        let deadline = Instant::now() + Duration::from_secs(25);
        while !released.load(Ordering::SeqCst) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        reply(200, json!({"id":"key-1","revoked":true}))
    });
    save_login(&root, &server.url, &sdk_key('O'));
    let logout_root = root.clone();
    let logout = thread::spawn(move || wssp(&logout_root, &["logout", "--json"]));
    let deadline = Instant::now() + Duration::from_secs(20);
    while server.requests().is_empty() {
        assert!(Instant::now() < deadline, "logout never revoked");
        thread::sleep(Duration::from_millis(10));
    }
    // The revocation is in flight: another user command still reads the login.
    let out = wssp(&root, &["whoami", "--offline", "--json"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(!logout.is_finished(), "the revocation was not held");
    // A login saved meanwhile is a different key: logout keeps it.
    write_login(&root.join("data/user"), &server.url, &sdk_key('P'), "key-2");
    release.store(true, Ordering::SeqCst);
    let out = logout.join().unwrap();
    assert!(out.status.success(), "{}", text(&out.stderr));
    let body: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(body["serverRevocation"], "revoked");
    assert_eq!(body["removed"], false);
    let saved: Value = serde_json::from_slice(&fs::read(login_file(&root)).unwrap()).unwrap();
    assert_eq!(saved["keyId"], "key-2");
}

#[test]
fn a_tls_failure_is_not_retried() {
    let tmp = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let (count, done) = (accepted.clone(), stop.clone());
    // Answers the TLS client hello with plain HTTP: a TLS failure, not a
    // dropped connection.
    let handle = thread::spawn(move || {
        while !done.load(Ordering::SeqCst) {
            let mut stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(_) => {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
            };
            count.fetch_add(1, Ordering::SeqCst);
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut buffer = [0; 4096];
            let _ = stream.read(&mut buffer);
            let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
            while matches!(stream.read(&mut buffer), Ok(n) if n > 0) {}
        }
    });
    save_login(
        tmp.path(),
        &format!("https://127.0.0.1:{port}"),
        &sdk_key('Q'),
    );
    let started = Instant::now();
    let out = wssp(tmp.path(), &["sandbox", "stop", "sbx-1"]);
    let elapsed = started.elapsed();
    stop.store(true, Ordering::SeqCst);
    handle.join().unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert_eq!(accepted.load(Ordering::SeqCst), 1, "retried");
    assert!(elapsed < Duration::from_secs(15), "{elapsed:?}");
}

/// `cmd` run under `sh` with `umask` set first.
fn under_umask(cmd: &Command, mask: &str) -> Command {
    let mut wrapped = Command::new("sh");
    wrapped
        .arg("-c")
        .arg(format!("umask {mask} && exec \"$0\" \"$@\""))
        .arg(cmd.get_program())
        .args(cmd.get_args());
    for (name, value) in cmd.get_envs() {
        match value {
            Some(value) => wrapped.env(name, value),
            None => wrapped.env_remove(name),
        };
    }
    wrapped
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    wrapped
}

#[test]
fn files_read_output_never_widens_an_existing_file_and_new_files_follow_the_umask() {
    const CONTENT: &str = "downloaded\n";
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let server = Server::new(|_, request| {
        if request.is("POST", "/v1/sandboxes/sbx-1/files/download") {
            reply(
                202,
                json!({"operationId":"op-1","state":"QUEUED","location":"/v1/operations/op-1"}),
            )
        } else if request.is("GET", "/v1/operations/op-1") {
            reply(
                200,
                json!({"id":"op-1","state":"SUCCEEDED","outcome":"succeeded"}),
            )
        } else if request.is("GET", "/v1/operations/op-1/content") {
            let sha = ring::digest::digest(&ring::digest::SHA256, CONTENT.as_bytes());
            let etag = sha
                .as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            Reply {
                status: 200,
                body: CONTENT.to_owned(),
                headers: vec![("ETag".into(), format!("\"{etag}\""))],
            }
        } else {
            panic!("unexpected request {request:?}")
        }
    });
    save_login(root, &server.url, &sdk_key('R'));
    let read = |target: &Path, mask: &str| {
        let target = target.to_str().unwrap();
        let cmd = command(
            root,
            &[
                "sandbox", "files", "read", "sbx-1", "/etc/x", "--output", target,
            ],
        );
        run(under_umask(&cmd, mask))
    };
    // Overwriting an existing 0600 file keeps 0600, even under umask 022.
    let secret = root.join("secret");
    fs::write(&secret, "old").unwrap();
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
    let out = read(&secret, "022");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(fs::read_to_string(&secret).unwrap(), CONTENT);
    assert_eq!(mode(&secret), 0o600);
    // A new file is 0666 less the umask.
    for (mask, expected) in [("022", 0o644), ("077", 0o600), ("027", 0o640)] {
        let fresh = root.join(format!("fresh-{mask}"));
        let out = read(&fresh, mask);
        assert!(out.status.success(), "{}", text(&out.stderr));
        assert_eq!(fs::read_to_string(&fresh).unwrap(), CONTENT);
        assert_eq!(mode(&fresh), expected, "umask {mask}");
    }
}

#[test]
fn files_write_spools_a_fifo_like_stdin() {
    let tmp = tempfile::tempdir().unwrap();
    let fifo = tmp.path().join("pipe");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    const TRANSFER: &str = "00000000-0000-4000-8000-000000000001";
    let server = Server::new(|_, request| {
        if request.is("POST", "/v1/transfers") {
            assert_eq!(request.json()["totalBytes"], 10, "{request:?}");
            return reply(
                201,
                json!({"id":TRANSFER,"chunkBytes":1_048_576,"receivedBytes":0}),
            );
        }
        if request.is("PUT", &format!("/v1/transfers/{TRANSFER}")) {
            assert_eq!(request.body, "fifo bytes");
            return reply(200, json!({"receivedBytes":10}));
        }
        if request.is("POST", &format!("/v1/transfers/{TRANSFER}/commit")) {
            return reply(
                202,
                json!({"operationId":"op-9","state":"QUEUED","location":"/v1/operations/op-9"}),
            );
        }
        if request.is("GET", "/v1/operations/op-9") {
            return reply(
                200,
                json!({"id":"op-9","state":"SUCCEEDED","outcome":"succeeded"}),
            );
        }
        panic!("unexpected request {request:?}");
    });
    save_login(tmp.path(), &server.url, &sdk_key('R'));
    let writer_fifo = fifo.clone();
    let writer = thread::spawn(move || {
        fs::OpenOptions::new()
            .write(true)
            .open(writer_fifo)
            .unwrap()
            .write_all(b"fifo bytes")
            .unwrap();
    });
    let out = wssp(
        tmp.path(),
        &[
            "sandbox",
            "files",
            "write",
            "sbx-1",
            "/home/user/in.txt",
            "--from",
            fifo.to_str().unwrap(),
            "--json",
        ],
    );
    writer.join().unwrap();
    assert!(out.status.success(), "{}", text(&out.stderr));
    let body: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(body["bytes"], 10);
}

fn help(root: &Path, args: &[&str]) -> String {
    let out = wssp(root, args);
    assert!(out.status.success());
    text(&out.stdout)
}

fn top_level_commands(help: &str) -> Vec<String> {
    help.split("Commands:\n")
        .nth(1)
        .unwrap_or("")
        .lines()
        .take_while(|line| !line.trim().is_empty())
        .filter(|line| line.starts_with("  ") && !line.starts_with("   "))
        .filter_map(|line| line.split_whitespace().next().map(str::to_owned))
        .collect()
}

#[test]
fn help_lists_user_commands_first_whether_or_not_this_is_a_host() {
    let plain = tempfile::tempdir().unwrap();
    let host = tempfile::tempdir().unwrap();
    fs::create_dir_all(host.path().join("data")).unwrap();
    fs::write(host.path().join("data/device-auth.json"), "{}").unwrap();
    let mut order = vec!["login", "logout", "whoami", "sandbox", "template"];
    if cfg!(feature = "ssh") {
        order.extend(["ssh", "ssh-config"]);
    }
    order.extend(["host", "completions", "help"]);
    for root in [plain.path(), host.path()] {
        let top = help(root, &["--help"]);
        assert_eq!(top_level_commands(&top), order, "{top}");
        let sandbox = help(root, &["sandbox", "--help"]);
        for sub in [
            "create", "list", "get", "exec", "ps", "logs", "stop", "start", "destroy", "files",
            "ports",
        ] {
            assert!(
                top_level_commands(&sandbox).contains(&sub.to_owned()),
                "{sub}"
            );
        }
        let template = help(root, &["template", "--help"]);
        assert_eq!(top_level_commands(&template), ["list", "get", "help"]);
    }
    let not_enrolled = help(plain.path(), &["--help"]);
    assert!(not_enrolled.contains("not enrolled here"));
    let enrolled = help(host.path(), &["--help"]);
    assert!(!enrolled.contains("not enrolled here"));
}

#[test]
fn completions_include_the_user_commands() {
    let tmp = tempfile::tempdir().unwrap();
    let bash = help(tmp.path(), &["completions", "bash"]);
    for path in [
        "wssp__subcmd__login",
        "wssp__subcmd__logout",
        "wssp__subcmd__whoami",
        "wssp__subcmd__sandbox__subcmd__exec",
        "wssp__subcmd__sandbox__subcmd__files__subcmd__write",
        "wssp__subcmd__sandbox__subcmd__ports__subcmd__link",
        "wssp__subcmd__template__subcmd__get",
    ] {
        assert!(bash.contains(path), "{path}");
    }
    let zsh = help(tmp.path(), &["completions", "zsh"]);
    assert!(zsh.contains("whoami") && zsh.contains("sandbox"));
}

#[test]
fn a_symlinked_user_lock_or_login_file_is_refused_and_the_host_lock_is_untouched() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let server = Server::new(|_, request| panic!("unexpected request {request:?}"));
    save_login(root, &server.url, &sdk_key('L'));
    let host_lock = root.join("data/auth.lock");
    fs::write(&host_lock, b"host lock").unwrap();
    fs::set_permissions(&host_lock, fs::Permissions::from_mode(0o640)).unwrap();
    let lock = root.join("data/user/login.lock");
    std::os::unix::fs::symlink("../auth.lock", &lock).unwrap();
    for args in [vec!["whoami", "--offline"], vec!["logout", "--local"]] {
        let out = wssp(root, &args);
        assert_eq!(
            out.status.code(),
            Some(1),
            "{args:?}: {}",
            text(&out.stderr)
        );
        assert!(
            text(&out.stderr).contains("symlink"),
            "{}",
            text(&out.stderr)
        );
        // While another process holds the host lock it must stay lockable.
        let held = fs::File::open(&host_lock).unwrap();
        held.try_lock().unwrap();
        drop(held);
    }
    assert_eq!(fs::read(&host_lock).unwrap(), b"host lock");
    assert_eq!(mode(&host_lock), 0o640);
    assert!(login_file(root).exists());
    // A symlinked login file is never followed either.
    fs::remove_file(&lock).unwrap();
    let elsewhere = root.join("elsewhere.json");
    fs::rename(login_file(root), &elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, login_file(root)).unwrap();
    let out = wssp(root, &["whoami", "--offline"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("symlink"),
        "{}",
        text(&out.stderr)
    );
    assert!(server.requests().is_empty());
}

#[test]
fn a_hard_linked_user_lock_is_refused_and_the_host_lock_is_untouched() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let server = Server::new(|_, request| panic!("unexpected request {request:?}"));
    save_login(root, &server.url, &sdk_key('H'));
    let host_lock = root.join("data/auth.lock");
    fs::write(&host_lock, b"host lock").unwrap();
    let lock = root.join("data/user/login.lock");
    let _ = fs::remove_file(&lock);
    fs::hard_link(&host_lock, &lock).unwrap();
    let out = wssp(root, &["whoami", "--offline"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("hard links"),
        "{}",
        text(&out.stderr)
    );
    let held = fs::File::open(&host_lock).unwrap();
    held.try_lock().unwrap();
    drop(held);
    assert_eq!(fs::read(&host_lock).unwrap(), b"host lock");
    assert!(server.requests().is_empty());
}

#[test]
fn a_default_user_dir_symlinked_outside_the_data_dir_is_refused_and_never_chmodded() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let server = Server::new(|_, request| panic!("unexpected request {request:?}"));
    let outside = root.join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o755)).unwrap();
    write_login(&outside, &server.url, &sdk_key('O'), "key-1");
    fs::create_dir_all(root.join("data")).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("data/user")).unwrap();
    for args in [
        vec!["whoami", "--offline"],
        vec!["logout", "--local"],
        vec!["login", "--server", server.url.as_str()],
    ] {
        let out = wssp(root, &args);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{args:?}: {}",
            text(&out.stderr)
        );
        assert!(
            text(&out.stderr).contains("must be a real directory"),
            "{}",
            text(&out.stderr)
        );
    }
    assert_eq!(mode(&outside), 0o755);
    assert!(!outside.join("login.lock").exists());
    assert!(outside.join("login.json").exists());
    assert!(server.requests().is_empty());
}

#[test]
fn list_next_page_hints_repeat_every_bound_option() {
    let tmp = tempfile::tempdir().unwrap();
    let server = Server::new(|_, request| {
        assert!(request.is("GET", "/v1/sandboxes"), "{request:?}");
        reply(200, json!({"items":[],"nextCursor":"c 1'x"}))
    });
    save_login(tmp.path(), &server.url, &sdk_key('N'));
    let out = wssp(
        tmp.path(),
        &["sandbox", "list", "--state", "stopped", "--limit", "5"],
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains(
            "next page: wssp sandbox list --state STOPPED --limit 5 --cursor 'c 1'\\''x'"
        ),
        "{}",
        text(&out.stdout)
    );
}

#[test]
fn json_usage_errors_of_user_commands_are_one_json_line_and_exit_2() {
    let tmp = tempfile::tempdir().unwrap();
    let out = wssp(tmp.path(), &["sandbox", "list", "--json", "--limit", "0"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    let stderr = text(&out.stderr);
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    let line: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(line["error"]["code"], "usage");
    assert_eq!(line["error"]["status"], Value::Null);
    assert!(
        line["error"]["message"]
            .as_str()
            .unwrap()
            .contains("--limit"),
        "{stderr}"
    );
    // Without `--json`, clap's own text; `--help` stays help on stdout.
    let out = wssp(tmp.path(), &["sandbox", "list", "--limit", "0"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        text(&out.stderr).starts_with("error: "),
        "{}",
        text(&out.stderr)
    );
    let out = wssp(tmp.path(), &["sandbox", "list", "--json", "--help"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(text(&out.stdout).contains("Usage"), "{}", text(&out.stdout));
    assert!(out.stderr.is_empty());
}
