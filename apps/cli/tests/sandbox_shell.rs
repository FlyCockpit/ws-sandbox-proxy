//! `wssp sandbox shell` against an in-process fake of the connect plane
//! (`GET /v1/sandboxes/{id}/connect`, `wssp.connect.v1`): a tungstenite
//! server on loopback that plays the server side of the client wire with the
//! CLI's own codecs. Real binary; children go through `ManagedChild`.
#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tungstenite::{Message, WebSocket};
use wssp::connect_client::wire::{
    self, ClientControl, DataMetadata, DataStream, ExitFrames, Intent, Kind, Limits, PerKind,
    PtySize, ServerControl, StdinStream,
};

#[path = "../../../crates/sandbox-runtime/tests/support/managed_child.rs"]
mod managed_child;
use managed_child::ManagedChild;

const SECRET: &str = "wssp_sdk_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// The head of one request the fake received.
#[derive(Clone, Debug)]
struct Head {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
}

impl Head {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    fn upgrade(&self) -> bool {
        self.header("upgrade")
            .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
    }
}

type Ws = WebSocket<TcpStream>;
type Session = Box<dyn FnOnce(&mut Peer) + Send>;

/// What the fake does with one request.
enum Action {
    /// Answer HTTP `status` with this JSON body (before any upgrade).
    Reply(u16, Value),
    /// The same, with the head and the body in two writes 300 ms apart.
    SplitReply(u16, Value),
    /// Refuse the way the server's Node adapter does: an empty body, the
    /// status and these headers only.
    Bare(u16, Vec<(&'static str, String)>),
    /// Accept the upgrade and run the session.
    Accept(Session),
}

struct Fake {
    url: String,
    heads: Arc<Mutex<Vec<Head>>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

fn parse_head(bytes: &[u8]) -> Head {
    let text = String::from_utf8_lossy(bytes);
    let mut lines = text.split("\r\n");
    let mut start = lines.next().unwrap().split_whitespace();
    let method = start.next().unwrap().to_owned();
    let target = start.next().unwrap().to_owned();
    let headers = lines
        .filter_map(|line| {
            let (k, v) = line.split_once(':')?;
            Some((k.trim().to_owned(), v.trim().to_owned()))
        })
        .collect();
    Head {
        method,
        target,
        headers,
    }
}

/// Peek until the head is complete without consuming it.
fn peek_head(stream: &TcpStream) -> Option<Head> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buffer = vec![0; 16 * 1024];
    loop {
        let n = stream.peek(&mut buffer).ok()?;
        if n == 0 {
            return None;
        }
        if let Some(end) = buffer[..n].windows(4).position(|w| w == b"\r\n\r\n") {
            return Some(parse_head(&buffer[..end]));
        }
        if Instant::now() > deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn reply(mut stream: TcpStream, status: u16, body: &Value, split: bool) {
    let mut head = [0; 16 * 1024];
    let _ = stream.read(&mut head);
    let body = body.to_string();
    let response = format!(
        "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    if split {
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
        thread::sleep(Duration::from_millis(300));
        let _ = stream.write_all(body.as_bytes());
    } else {
        let _ = stream.write_all(format!("{response}{body}").as_bytes());
    }
}

fn bare_reply(mut stream: TcpStream, status: u16, headers: &[(&str, String)]) {
    let mut head = [0; 16 * 1024];
    let _ = stream.read(&mut head);
    let extra: String = headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}\r\n"))
        .collect();
    let _ = stream.write_all(
        format!(
            "HTTP/1.1 {status} Fixture\r\nConnection: close\r\nContent-Length: 0\r\n{extra}\r\n"
        )
        .as_bytes(),
    );
}

#[allow(clippy::result_large_err)] // tungstenite's callback signature
fn accept_subprotocol(_: &Request, mut response: Response) -> Result<Response, ErrorResponse> {
    response
        .headers_mut()
        .insert("Sec-WebSocket-Protocol", wire::SUBPROTOCOL.parse().unwrap());
    Ok(response)
}

impl Fake {
    fn new(handler: impl Fn(&Head) -> Action + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let heads = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (seen, done) = (heads.clone(), stop.clone());
        let handle = thread::spawn(move || {
            while !done.load(Ordering::SeqCst) {
                let stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => panic!("accept: {e}"),
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(15)))
                    .unwrap();
                let Some(head) = peek_head(&stream) else {
                    continue;
                };
                seen.lock().unwrap().push(head.clone());
                match handler(&head) {
                    Action::Reply(status, body) => reply(stream, status, &body, false),
                    Action::SplitReply(status, body) => reply(stream, status, &body, true),
                    Action::Bare(status, headers) => bare_reply(stream, status, &headers),
                    Action::Accept(session) => {
                        assert!(head.upgrade(), "an accepted request is an upgrade");
                        let ws = tungstenite::accept_hdr(stream, accept_subprotocol).unwrap();
                        let mut peer = Peer {
                            ws,
                            log: Vec::new(),
                        };
                        session(&mut peer);
                    }
                }
            }
        });
        Self {
            url,
            heads,
            stop,
            handle: Some(handle),
        }
    }

    fn heads(&self) -> Vec<Head> {
        self.heads.lock().unwrap().clone()
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let joined = self.handle.take().unwrap().join();
        if !thread::panicking() {
            joined.unwrap();
        }
    }
}

/// What the CLI sent.
#[derive(Debug, Clone, PartialEq)]
enum In {
    Control(ClientControl),
    Data(DataMetadata, Vec<u8>),
    Closed,
}

/// The server end of one session.
struct Peer {
    ws: Ws,
    log: Vec<In>,
}

fn limits() -> Limits {
    Limits {
        max_channels: 32,
        max_pty_channels: 8,
        opens_per_minute: 120,
        window_frames: PerKind { pty: 8, exec: 32 },
        data_max_bytes: PerKind {
            pty: 16384,
            exec: 32768,
        },
        ack_stall_ms: 60_000,
        ping_interval_ms: 20_000,
        idle_timeout_ms: 60_000,
        open_timeout_ms: 30_000,
        unacked_input_bytes: 4 * 1024 * 1024,
    }
}

impl Peer {
    fn send(&mut self, frame: &ServerControl) {
        self.ws
            .send(Message::text(wire::encode_control(frame).unwrap()))
            .unwrap();
    }

    fn hello(&mut self, sandbox: &str) {
        self.hello_with(sandbox, limits());
    }

    fn hello_with(&mut self, sandbox: &str, limits: Limits) {
        self.send(&ServerControl::Hello {
            connection_id: "c1".into(),
            sandbox_id: sandbox.into(),
            limits,
        });
    }

    /// `ready` for an exec channel, then wait for the CLI's stdin eof (its
    /// stdin is closed), which it sends only once it handled the `ready`.
    fn ready_exec(&mut self) {
        self.send(&ServerControl::Ready {
            channel: 1,
            pty: None,
        });
        self.expect("stdin eof", |f| {
            matches!(f, In::Control(ClientControl::Eof { .. }))
        });
    }

    /// The channel's exit after a close this client asked for.
    fn exit_client(&mut self) {
        self.send(&ServerControl::Exit {
            channel: 1,
            exit_code: None,
            signal: None,
            intent: Some(Intent::Client),
            error: None,
            frames: ExitFrames {
                stdout: 0,
                stderr: 0,
            },
        });
    }

    fn data(&mut self, channel: u32, stream: DataStream, seq: u64, body: &[u8]) {
        let frame = wire::encode_data(&DataMetadata::new(channel, stream, seq), body).unwrap();
        self.ws.send(Message::binary(frame)).unwrap();
    }

    /// Several data frames in one write, so they arrive in one read.
    fn burst(
        &mut self,
        channel: u32,
        stream: DataStream,
        seqs: std::ops::RangeInclusive<u64>,
        body: &[u8],
    ) {
        for seq in seqs {
            let frame = wire::encode_data(&DataMetadata::new(channel, stream, seq), body).unwrap();
            self.ws.write(Message::binary(frame)).unwrap();
        }
        self.ws.flush().unwrap();
    }

    fn recv(&mut self) -> In {
        loop {
            let message = match self.ws.read() {
                Ok(message) => message,
                Err(_) => return In::Closed,
            };
            let frame = match message {
                Message::Text(text) => In::Control(
                    wire::parse_client_control(text.as_str())
                        .unwrap_or_else(|| panic!("invalid client frame {text}")),
                ),
                Message::Binary(bytes) => {
                    let (metadata, body) = wire::parse_data(&bytes).expect("valid data frame");
                    In::Data(metadata, body.to_vec())
                }
                Message::Close(_) => In::Closed,
                _ => continue,
            };
            self.log.push(frame.clone());
            return frame;
        }
    }

    /// Read until `want` matches (earlier frames stay in the log).
    fn expect(&mut self, what: &str, want: impl Fn(&In) -> bool) -> In {
        loop {
            let frame = self.recv();
            if want(&frame) {
                return frame;
            }
            assert_ne!(
                frame,
                In::Closed,
                "closed while waiting for {what}: {:?}",
                self.log
            );
        }
    }

    fn open(&mut self) -> ClientControl {
        match self.expect("open", |f| {
            matches!(f, In::Control(ClientControl::Open { .. }))
        }) {
            In::Control(open) => open,
            _ => unreachable!(),
        }
    }

    /// The first frame already read that matches `want`, else read until one
    /// arrives. An earlier `expect` may have read past it: the CLI may send a
    /// resize before the ack it owes for output it just wrote to the terminal.
    fn seen_or_expect(&mut self, what: &str, want: impl Fn(&In) -> bool) -> In {
        if let Some(seen) = self.log.iter().find(|frame| want(frame)) {
            return seen.clone();
        }
        self.expect(what, want)
    }

    fn acked(&mut self, stream: wire::OutputStream, seq: u64) {
        self.expect("ack", |f| {
            *f == In::Control(ClientControl::Ack {
                channel: 1,
                stream,
                seq,
            })
        });
    }

    fn exit(&mut self, code: Option<i32>, signal: Option<u8>, stdout: u64, stderr: u64) {
        self.send(&ServerControl::Exit {
            channel: 1,
            exit_code: code,
            signal,
            intent: None,
            error: None,
            frames: ExitFrames { stdout, stderr },
        });
    }

    /// Wait for the CLI to hang up.
    fn drain(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.recv() != In::Closed {
            assert!(Instant::now() < deadline, "the CLI never closed");
        }
    }
}

fn command(root: &Path, server: &str, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_wssp"));
    cmd.args(args)
        .env("WSSP_CONFIG_DIR", root.join("config"))
        .env("WSSP_DATA_DIR", root.join("data"))
        .env("WSSP_API_KEY", SECRET)
        .env("WSSP_SERVER", server)
        .env_remove("WSSP_USER_DIR")
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

/// Run to the end, feeding `stdin` (then closing it) when given.
fn run(mut cmd: Command, stdin: Option<&[u8]>) -> Output {
    if stdin.is_some() {
        cmd.stdin(Stdio::piped());
    }
    let mut child = ManagedChild::spawn(&mut cmd).unwrap();
    if let Some(bytes) = stdin {
        let mut pipe = child.stdin.take().unwrap();
        pipe.write_all(bytes).unwrap();
    }
    let output_deadline = Instant::now() + Duration::from_secs(30);
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let out = thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout.read_to_end(&mut bytes);
        bytes
    });
    let err = thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stderr.read_to_end(&mut bytes);
        bytes
    });
    while child.try_wait().unwrap().is_none() {
        assert!(
            Instant::now() < output_deadline,
            "the CLI exceeded the test deadline"
        );
        thread::sleep(Duration::from_millis(10));
    }
    Output {
        status: child.wait().unwrap(),
        stdout: out.join().unwrap(),
        stderr: err.join().unwrap(),
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn connect_target(id: &str) -> String {
    format!("/v1/sandboxes/{id}/connect")
}

fn error_body(code: &str, message: &str) -> Value {
    json!({"error": {"code": code, "message": message, "requestId": "00000000-0000-4000-8000-000000000000"}})
}

#[test]
fn exec_channel_streams_output_and_passes_the_exit_code_through() {
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(|head| {
        assert_eq!(head.target, connect_target("sbx_1"));
        Action::Accept(Box::new(|peer: &mut Peer| {
            peer.hello("sbx_1");
            let open = peer.open();
            assert_eq!(
                open,
                ClientControl::Open {
                    channel: 1,
                    kind: Kind::Exec,
                    argv: Some(vec!["echo".into(), "two words".into(), String::new()]),
                    login: None,
                    cwd: Some("/tmp".into()),
                    env: Some([("LANG".to_owned(), "C.UTF-8".to_owned())].into()),
                    pty: None,
                    port: None,
                    path: None,
                }
            );
            peer.send(&ServerControl::Ready {
                channel: 1,
                pty: None,
            });
            // A closed stdin is an immediate eof after zero frames.
            peer.expect("stdin eof", |f| {
                *f == In::Control(ClientControl::Eof {
                    channel: 1,
                    stream: StdinStream::Stdin,
                    frames: 0,
                })
            });
            peer.data(1, DataStream::Stdout, 0, b"two words\n");
            peer.data(1, DataStream::Stderr, 0, b"warn\n");
            peer.data(1, DataStream::Stdout, 1, b"more\n");
            peer.acked(wire::OutputStream::Stdout, 1);
            peer.send(&ServerControl::Eof {
                channel: 1,
                stream: wire::OutputStream::Stdout,
                frames: 2,
            });
            peer.exit(Some(7), None, 2, 1);
            peer.drain();
            assert!(
                peer.log.contains(&In::Control(ClientControl::Ack {
                    channel: 1,
                    stream: wire::OutputStream::Stderr,
                    seq: 0
                })),
                "every delivered frame is acknowledged: {:?}",
                peer.log
            );
        }))
    });
    let output = run(
        command(
            root.path(),
            &fake.url,
            &[
                "sandbox",
                "shell",
                "sbx_1",
                "--cwd",
                "/tmp",
                "--env",
                "LANG=C.UTF-8",
                "--",
                "echo",
                "two words",
                "",
            ],
        ),
        None,
    );
    assert_eq!(output.status.code(), Some(7), "{}", text(&output.stderr));
    assert_eq!(text(&output.stdout), "two words\nmore\n");
    assert_eq!(text(&output.stderr), "warn\n");
    let heads = fake.heads();
    assert_eq!(heads.len(), 1);
    let head = &heads[0];
    assert_eq!(head.method, "GET");
    assert_eq!(
        head.header("authorization"),
        Some(format!("Bearer {SECRET}").as_str())
    );
    assert_eq!(
        head.header("sec-websocket-protocol"),
        Some(wire::SUBPROTOCOL)
    );
    assert!(head.header("origin").is_none(), "no Origin");
    assert!(head.header("cookie").is_none(), "no Cookie");
    assert!(!head.target.contains('?'), "nothing in the query");
}

#[test]
fn piped_stdin_travels_with_its_eof_and_a_signal_death_exits_128_plus_n() {
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(|_| {
        Action::Accept(Box::new(|peer: &mut Peer| {
            peer.hello("sbx_1");
            let ClientControl::Open {
                kind, login, argv, ..
            } = peer.open()
            else {
                unreachable!()
            };
            // No command: the guest's login shell, reading stdin.
            assert_eq!((kind, login, argv), (Kind::Exec, Some(true), None));
            peer.send(&ServerControl::Ready {
                channel: 1,
                pty: None,
            });
            let mut input = Vec::new();
            let mut frames = 0;
            loop {
                match peer.recv() {
                    In::Data(metadata, body) => {
                        assert_eq!(metadata, DataMetadata::new(1, DataStream::Stdin, frames));
                        input.extend(body);
                        peer.send(&ServerControl::Ack {
                            channel: 1,
                            stream: StdinStream::Stdin,
                            seq: frames,
                        });
                        frames += 1;
                    }
                    In::Control(ClientControl::Eof { frames: n, .. }) => {
                        assert_eq!(n, frames);
                        break;
                    }
                    other => panic!("unexpected {other:?}"),
                }
            }
            assert_eq!(input.len(), 100_000);
            assert!(frames >= 4, "stdin is cut into frames of at most 32 KiB");
            peer.data(1, DataStream::Stdout, 0, b"done\n");
            peer.acked(wire::OutputStream::Stdout, 0);
            peer.exit(None, Some(15), 1, 0);
            peer.drain();
        }))
    });
    let input = vec![b'x'; 100_000];
    let output = run(
        command(root.path(), &fake.url, &["sandbox", "shell", "sbx_1"]),
        Some(&input),
    );
    assert_eq!(output.status.code(), Some(143), "{}", text(&output.stderr));
    assert_eq!(text(&output.stdout), "done\n");
    assert_eq!(text(&output.stderr), "");
}

#[test]
fn upgrade_refusals_keep_their_v1_exit_codes() {
    for (status, code, expected) in [
        (401, "UNAUTHORIZED", 7),
        (403, "FORBIDDEN", 8),
        (409, "sandbox.state_conflict", 10),
        (409, "sandbox.host_unavailable", 11),
        (429, "TOO_MANY_REQUESTS", 11),
        (503, "SERVICE_UNAVAILABLE", 11),
        (400, "UNSUPPORTED_CAPABILITY", 2),
    ] {
        let root = tempfile::tempdir().unwrap();
        let fake = Fake::new(move |_| Action::Reply(status, error_body(code, "refused")));
        let output = run(
            command(
                root.path(),
                &fake.url,
                &["sandbox", "shell", "sbx_1", "--", "true"],
            ),
            None,
        );
        assert_eq!(
            output.status.code(),
            Some(expected),
            "{status} {code}: {}",
            text(&output.stderr)
        );
        assert!(
            text(&output.stderr).contains(code),
            "{}",
            text(&output.stderr)
        );
        assert!(output.stdout.is_empty());
        // No retry, no list, no second upgrade (a stopped sandbox's state is
        // read once, for its message).
        let heads = fake.heads();
        assert_eq!(
            heads.iter().filter(|h| h.upgrade()).count(),
            1,
            "{status} {code}"
        );
        assert!(
            heads
                .iter()
                .all(|h| h.upgrade() || h.target == "/v1/sandboxes/sbx_1"),
            "{status} {code}"
        );
    }
}

/// The headers of a refused upgrade as the server sends them.
fn refusal_headers(code: &str, reason: Option<&str>) -> Vec<(&'static str, String)> {
    let mut headers = vec![("X-Wssp-Error-Code", code.to_owned())];
    if let Some(reason) = reason {
        headers.push(("X-Wssp-Error-Reason", reason.to_owned()));
    }
    headers
}

#[test]
fn bodyless_refusals_name_the_cause_and_the_fix() {
    // (status, code, reason, extra header, the sandbox GET's answer, exit, message)
    type Case = (
        u16,
        &'static str,
        Option<&'static str>,
        Option<(&'static str, &'static str)>,
        Option<(u16, Value)>,
        i32,
        &'static str,
    );
    let cases: Vec<Case> = vec![
        (
            409,
            "sandbox.state_conflict",
            None,
            None,
            Some((200, json!({"id": "sbx_1", "state": "STOPPED"}))),
            10,
            "error: sandbox `sbx_1` is stopped; start it with `wssp sandbox start sbx_1 --wait` (it keeps its lease; `--timeout <dur>` sets a new one)",
        ),
        (
            409,
            "sandbox.state_conflict",
            None,
            None,
            Some((200, json!({"id": "sbx_1", "state": "OFFLOADED"}))),
            10,
            "error: sandbox `sbx_1` is stopped and its disk is offloaded; start it with `wssp sandbox start sbx_1 --wait` (it keeps its lease; `--timeout <dur>` sets a new one)",
        ),
        (
            409,
            "sandbox.state_conflict",
            None,
            None,
            Some((200, json!({"id": "sbx_1", "state": "STOPPING"}))),
            10,
            "error: sandbox `sbx_1` is stopping; once it is stopped, start it with `wssp sandbox start sbx_1 --wait` (it keeps its lease; `--timeout <dur>` sets a new one)",
        ),
        (
            409,
            "sandbox.state_conflict",
            None,
            None,
            Some((200, json!({"id": "sbx_1", "state": "PROVISIONING"}))),
            10,
            "error: sandbox `sbx_1` is still starting (`PROVISIONING`); connect again once `wssp sandbox get sbx_1` shows `READY`",
        ),
        (
            409,
            "sandbox.state_conflict",
            None,
            None,
            Some((200, json!({"id": "sbx_1", "state": "HOST_LOST"}))),
            10,
            "error: sandbox `sbx_1` cannot be connected to right now (`HOST_LOST`); `wssp sandbox get sbx_1` shows its state",
        ),
        (
            409,
            "sandbox.state_conflict",
            None,
            None,
            Some((200, json!({"id": "sbx_1", "state": "READY"}))),
            10,
            "error: sandbox `sbx_1` cannot be connected to right now (its lease may have ended, or its host or access is changing); `wssp sandbox get sbx_1` shows its state",
        ),
        (
            409,
            "sandbox.state_conflict",
            None,
            None,
            Some((500, json!({}))),
            10,
            "error: sandbox `sbx_1` cannot be connected to right now (it may be stopped or starting, its lease may have ended, or its host or access is changing); `wssp sandbox get sbx_1` shows its state, and `wssp sandbox start sbx_1 --wait` starts a stopped one",
        ),
        (
            409,
            "sandbox.host_unavailable",
            None,
            None,
            None,
            11,
            "error: the sandbox's host is not connected to the server; try again once it is back",
        ),
        (
            409,
            "sandbox.managed",
            None,
            None,
            None,
            10,
            "error: sandbox `sbx_1` is a build, verify or CLI-login sandbox, which has no shell, port-forward or ssh access",
        ),
        (
            400,
            "UNSUPPORTED_CAPABILITY",
            Some("connect_sandbox_unsupported"),
            None,
            None,
            2,
            "error: sandbox `sbx_1` is a build, verify or CLI-login sandbox, which has no shell, port-forward or ssh access",
        ),
        (
            400,
            "UNSUPPORTED_CAPABILITY",
            Some("connect_host_outdated"),
            None,
            None,
            2,
            "error: the sandbox's node runs a daemon without shell, port-forward and ssh support; its owner has to update it",
        ),
        (
            401,
            "UNAUTHORIZED",
            None,
            None,
            None,
            7,
            "error: the server refused `WSSP_API_KEY` (revoked, expired or unknown); set a valid key, or unset `WSSP_API_KEY` and `WSSP_SERVER` to use the saved login",
        ),
        (
            429,
            "TOO_MANY_REQUESTS",
            None,
            Some(("Retry-After", "7")),
            None,
            11,
            "error: too many connections or connection attempts; try again in 7 s",
        ),
        (
            503,
            "SERVICE_UNAVAILABLE",
            None,
            None,
            None,
            11,
            "error: the server is busy or shutting down; try again shortly",
        ),
        (
            404,
            "NOT_FOUND",
            None,
            None,
            None,
            3,
            "error: no sandbox `sbx_1` among yours (give its id, or the name of a live sandbox); `wssp sandbox list` shows them",
        ),
    ];
    for (status, code, reason, extra, sandbox, expected, message) in cases {
        let root = tempfile::tempdir().unwrap();
        let fake = Fake::new(move |head| {
            if head.upgrade() {
                let mut headers = refusal_headers(code, reason);
                if let Some((name, value)) = extra {
                    headers.push((name, value.to_owned()));
                }
                return Action::Bare(status, headers);
            }
            if head.target.starts_with("/v1/sandboxes?") {
                return Action::Reply(200, json!({"items": [], "nextCursor": null}));
            }
            assert_eq!(head.target, "/v1/sandboxes/sbx_1", "{code}");
            let (status, body) = sandbox.clone().expect("no sandbox read expected");
            Action::Reply(status, body)
        });
        let output = run(
            command(
                root.path(),
                &fake.url,
                &["sandbox", "shell", "sbx_1", "--", "true"],
            ),
            None,
        );
        let stderr = text(&output.stderr);
        assert_eq!(output.status.code(), Some(expected), "{code}: {stderr}");
        assert!(stderr.starts_with(message), "{code}: {stderr}");
        // The catalog code stays visible after the explanation.
        assert!(stderr.contains(&format!("`{code}`")), "{code}: {stderr}");
        assert!(output.stdout.is_empty());
    }
}

/// A saved login with these scopes, for the fake at `url`.
fn save_login(root: &std::path::Path, url: &str, scopes: &[&str]) {
    use std::os::unix::fs::PermissionsExt;
    let dir = root.join("data/user");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let login = json!({"origin": format!("{url}/"),"keyId":"key-1","name":"laptop","secret":SECRET,"scopes":scopes,"poolMode":"ALL_USABLE","poolIds":[],"ownSandboxesOnly":false,"expiresAt":null,"maxLiveSandboxes":null,"userEmail":"person@example.test","createdAt":"2026-11-18T00:00:00Z"});
    std::fs::write(dir.join("login.json"), login.to_string()).unwrap();
    std::fs::set_permissions(
        dir.join("login.json"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
}

#[test]
fn a_forbidden_connect_names_a_missing_host_only_when_the_scope_is_known() {
    // The server refuses a sandbox without a host (offloaded, waiting for
    // capacity) at authorization, with 403, like a missing scope. Only a saved
    // login known to hold `sandboxes:connect` turns that into the state line
    // (exit 10); an env key's scopes are unknown, so it keeps exit 8.
    const ENV_SCOPE: &str =
        "error: the key may lack the `sandboxes:connect` scope or access to this sandbox";
    let cases: [(bool, &str, Option<&str>, i32, &str); 7] = [
        (
            true,
            "OFFLOADED",
            None,
            10,
            "error: sandbox `sbx_1` is stopped and its disk is offloaded; start it with `wssp sandbox start sbx_1 --wait` (it keeps its lease; `--timeout <dur>` sets a new one)",
        ),
        (
            true,
            "WAITING_FOR_CAPACITY",
            None,
            10,
            "error: sandbox `sbx_1` is still starting (`WAITING_FOR_CAPACITY`); connect again once `wssp sandbox get sbx_1` shows `READY`",
        ),
        (
            true,
            "STOPPED",
            Some("host-1"),
            8,
            "error: the server refused access to sandbox `sbx_1` although this login can open shells; `wssp sandbox get sbx_1` shows its state",
        ),
        (false, "OFFLOADED", None, 8, ENV_SCOPE),
        // A read-only env key and a stopped sandbox that has a host: the scope.
        (false, "STOPPED", Some("host-1"), 8, ENV_SCOPE),
        (false, "READY", Some("host-1"), 8, ENV_SCOPE),
        (
            true,
            "READY",
            Some("host-1"),
            8,
            "error: the server refused access to sandbox `sbx_1` although this login can open shells",
        ),
    ];
    for (saved, state, host, expected, message) in cases {
        let root = tempfile::tempdir().unwrap();
        let fake = Fake::new(move |head| {
            if head.upgrade() {
                return Action::Bare(403, refusal_headers("FORBIDDEN", None));
            }
            assert_eq!(head.target, "/v1/sandboxes/sbx_1");
            Action::Reply(200, json!({"id": "sbx_1", "state": state, "hostId": host}))
        });
        let mut cmd = command(
            root.path(),
            &fake.url,
            &["sandbox", "shell", "sbx_1", "--", "true"],
        );
        if saved {
            save_login(
                root.path(),
                &fake.url,
                &["sandboxes:read", "sandboxes:create", "sandboxes:connect"],
            );
            cmd.env_remove("WSSP_API_KEY").env_remove("WSSP_SERVER");
        }
        let output = run(cmd, None);
        let stderr = text(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(expected),
            "{saved} {state}: {stderr}"
        );
        assert!(stderr.starts_with(message), "{saved} {state}: {stderr}");
        assert!(stderr.contains("`FORBIDDEN`"), "{saved} {state}: {stderr}");
        if !saved && host.is_none() {
            assert!(
                stderr.contains("also, sandbox `sbx_1` has no host right now (`OFFLOADED`)"),
                "{stderr}"
            );
        }
    }
}

#[test]
fn a_stopped_sandbox_given_by_name_is_named_and_started_by_id() {
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(|head| {
        if head.upgrade() && head.target == connect_target("web") {
            return Action::Bare(404, refusal_headers("NOT_FOUND", None));
        }
        if head.upgrade() {
            assert_eq!(head.target, connect_target("sbx_9"));
            return Action::Bare(409, refusal_headers("sandbox.state_conflict", None));
        }
        if head.target.starts_with("/v1/sandboxes?") {
            return Action::Reply(
                200,
                json!({"items": [{"id": "sbx_9", "name": "web", "state": "STOPPED"}], "nextCursor": null}),
            );
        }
        assert_eq!(head.target, "/v1/sandboxes/sbx_9");
        Action::Reply(
            200,
            json!({"id": "sbx_9", "name": "web", "state": "STOPPED"}),
        )
    });
    let output = run(
        command(
            root.path(),
            &fake.url,
            &["sandbox", "shell", "web", "--", "true"],
        ),
        None,
    );
    assert_eq!(output.status.code(), Some(10), "{}", text(&output.stderr));
    assert!(
        text(&output.stderr).starts_with(
            "error: sandbox `web` is stopped; start it with `wssp sandbox start sbx_9 --wait` (it keeps its lease; `--timeout <dur>` sets a new one)"
        ),
        "{}",
        text(&output.stderr)
    );
}

#[test]
fn a_refusal_body_after_its_head_still_counts() {
    // Head and body arrive in separate packets: the body is read to its
    // Content-Length, so the code (and its exit 11) survives.
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(|_| {
        Action::SplitReply(
            409,
            error_body("sandbox.host_unavailable", "The host is not connected."),
        )
    });
    let output = run(
        command(
            root.path(),
            &fake.url,
            &["sandbox", "shell", "sbx_1", "--", "true"],
        ),
        None,
    );
    assert_eq!(output.status.code(), Some(11), "{}", text(&output.stderr));
    assert!(
        text(&output.stderr).contains("sandbox.host_unavailable"),
        "{}",
        text(&output.stderr)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn a_signal_before_ready_closes_the_pending_channel() {
    for (signal, status) in [
        (rustix::process::Signal::TERM, 143),
        (rustix::process::Signal::HUP, 129),
    ] {
        let root = tempfile::tempdir().unwrap();
        let (opened_tx, opened) = std::sync::mpsc::channel::<()>();
        let opened_tx = Mutex::new(Some(opened_tx));
        let fake = Fake::new(move |_| {
            let opened_tx = opened_tx.lock().unwrap().take().unwrap();
            Action::Accept(Box::new(move |peer: &mut Peer| {
                peer.hello("sbx_1");
                peer.open();
                // `ready` is held back: the guest is still starting.
                opened_tx.send(()).unwrap();
                peer.expect("close", |f| {
                    *f == In::Control(ClientControl::Close { channel: 1 })
                });
                assert!(
                    !peer
                        .log
                        .iter()
                        .any(|f| matches!(f, In::Control(ClientControl::Signal { .. }))),
                    "no signal before ready: {:?}",
                    peer.log
                );
                peer.send(&ServerControl::Exit {
                    channel: 1,
                    exit_code: None,
                    signal: None,
                    intent: Some(Intent::Client),
                    error: None,
                    frames: ExitFrames {
                        stdout: 0,
                        stderr: 0,
                    },
                });
                peer.drain();
            }))
        });
        let mut cmd = command(
            root.path(),
            &fake.url,
            &["sandbox", "shell", "sbx_1", "--", "sleep", "100"],
        );
        let mut child = ManagedChild::spawn(&mut cmd).unwrap();
        let mut stderr = child.stderr.take().unwrap();
        let errors = thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = stderr.read_to_end(&mut bytes);
            bytes
        });
        opened.recv_timeout(Duration::from_secs(15)).unwrap();
        rustix::process::kill_process(
            rustix::process::Pid::from_raw(child.id() as i32).unwrap(),
            signal,
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        let exit = loop {
            if let Some(exit) = child.try_wait().unwrap() {
                break exit;
            }
            assert!(Instant::now() < deadline, "the CLI never exited");
            thread::sleep(Duration::from_millis(10));
        };
        let errors = text(&errors.join().unwrap());
        assert_eq!(exit.code(), Some(status), "{signal:?}: {errors}");
    }
}

#[test]
fn an_unread_stdout_cannot_hold_the_cli_after_the_session_ended() {
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(|_| {
        Action::Accept(Box::new(|peer: &mut Peer| {
            peer.hello("sbx_1");
            peer.open();
            peer.send(&ServerControl::Ready {
                channel: 1,
                pty: None,
            });
            // A one-byte first frame fits any pipe: its ack proves the
            // writer runs, whatever the pipe's capacity.
            peer.data(1, DataStream::Stdout, 0, b"y");
            peer.acked(wire::OutputStream::Stdout, 0);
            // Then 16 x 32000 B: far more than a pipe holds.
            let chunk = vec![b'y'; 32_000];
            for seq in 1..=16 {
                peer.data(1, DataStream::Stdout, seq, &chunk);
            }
            // Give the CLI time to hand the writer the rest (an `end` read
            // in the same poll drops them).
            thread::sleep(Duration::from_millis(300));
            peer.send(&ServerControl::End {
                intent: Intent::Revoked,
                error: None,
            });
            let _ = peer.ws.close(None);
            peer.drain();
        }))
    });
    let mut cmd = command(
        root.path(),
        &fake.url,
        &["sandbox", "shell", "sbx_1", "--", "cat", "big"],
    );
    let started = Instant::now();
    let mut child = ManagedChild::spawn(&mut cmd).unwrap();
    // Held open and never read.
    let stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let errors = thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stderr.read_to_end(&mut bytes);
        bytes
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    let exit = loop {
        if let Some(exit) = child.try_wait().unwrap() {
            break exit;
        }
        assert!(
            Instant::now() < deadline,
            "the CLI hung on its unread stdout"
        );
        thread::sleep(Duration::from_millis(10));
    };
    let elapsed = started.elapsed();
    drop(stdout);
    let errors = text(&errors.join().unwrap());
    assert_eq!(exit.code(), Some(125), "{errors}");
    // The error line could never be written: none is attempted.
    assert_eq!(errors, "", "no error line on a stuck writer");
    assert!(
        elapsed >= Duration::from_secs(2),
        "the writer got its settle time"
    );
}

#[test]
fn an_unread_stderr_cannot_hold_a_notice_or_the_revocation() {
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(|_| {
        Action::Accept(Box::new(|peer: &mut Peer| {
            peer.hello("sbx_1");
            peer.open();
            peer.send(&ServerControl::Ready {
                channel: 1,
                pty: None,
            });
            // A one-byte first frame fits any pipe: its ack proves the
            // writer runs, whatever the pipe's capacity.
            peer.data(1, DataStream::Stderr, 0, b"e");
            peer.acked(wire::OutputStream::Stderr, 0);
            // Then 16 x 32000 B of guest stderr: far more than a pipe holds,
            // so the writer blocks on the full pipe, holding stderr.
            let chunk = vec![b'e'; 32_000];
            for seq in 1..=16 {
                peer.data(1, DataStream::Stderr, seq, &chunk);
            }
            thread::sleep(Duration::from_millis(300));
            // A notice the CLI prints on its stderr, then the revocation:
            // the connection thread must still see the `end`.
            peer.send(&ServerControl::Error {
                channel: 1,
                code: wire::Notice::UnsupportedSignal,
            });
            thread::sleep(Duration::from_millis(300));
            peer.send(&ServerControl::End {
                intent: Intent::Revoked,
                error: None,
            });
            let _ = peer.ws.close(None);
            peer.drain();
        }))
    });
    let mut cmd = command(
        root.path(),
        &fake.url,
        &["sandbox", "shell", "sbx_1", "--", "cat", "big"],
    );
    let started = Instant::now();
    let mut child = ManagedChild::spawn(&mut cmd).unwrap();
    let mut stdout = child.stdout.take().unwrap();
    // Held open and never read.
    let stderr = child.stderr.take().unwrap();
    let output = thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout.read_to_end(&mut bytes);
        bytes
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    let exit = loop {
        if let Some(exit) = child.try_wait().unwrap() {
            break exit;
        }
        assert!(
            Instant::now() < deadline,
            "the CLI hung on its unread stderr"
        );
        thread::sleep(Duration::from_millis(10));
    };
    let elapsed = started.elapsed();
    drop(stderr);
    assert_eq!(output.join().unwrap(), b"", "nothing on stdout");
    assert_eq!(exit.code(), Some(125));
    assert!(
        elapsed >= Duration::from_secs(2),
        "the writer got its settle time"
    );
}

/// A pipe for the CLI's stderr whose capacity the test establishes itself:
/// `F_SETPIPE_SZ` asks for `want` bytes (refused above the per-user pipe
/// limit, which may also have left a new pipe smaller than the 64 KiB
/// default), and `F_GETPIPE_SZ` reads back the capacity the kernel gave.
/// Returns the read end, the write end (for the child) and the capacity.
#[cfg(target_os = "linux")]
fn sized_pipe(want: usize) -> (std::fs::File, std::os::fd::OwnedFd, usize) {
    use rustix::pipe::{PipeFlags, fcntl_getpipe_size, fcntl_setpipe_size, pipe_with};
    // Close-on-exec, so no CLI another test spawns meanwhile inherits it.
    let (read, write) = pipe_with(PipeFlags::CLOEXEC).unwrap();
    let _ = fcntl_setpipe_size(&write, want);
    let capacity = fcntl_getpipe_size(&write).unwrap();
    (std::fs::File::from(read), write, capacity)
}

/// What a CLI run against a stderr filled exactly produced.
#[cfg(target_os = "linux")]
struct FullStderr {
    exit: std::process::ExitStatus,
    elapsed: Duration,
    stderr: Vec<u8>,
    capacity: usize,
}

/// Run `sandbox shell` with its stderr on a pipe held open and never read
/// until it exited; the fake fills that pipe exactly with guest stderr
/// (every frame written and acknowledged, nothing pending), then ends the
/// session: with `end{revoked}`, or, when `close_stdout`, with one guest
/// stdout frame to a stdout whose reader already closed it, so its write
/// fails with a broken pipe and stops the writer.
#[cfg(target_os = "linux")]
fn on_a_full_stderr(json_mode: bool, close_stdout: bool) -> FullStderr {
    let (mut stderr, stderr_write, capacity) = sized_pipe(64 * 1024);
    // Frames of at most the exec frame limit, at most a window of them.
    let frame = capacity.min(32_768);
    assert_eq!(capacity % frame, 0, "capacity {capacity}");
    let frames = (capacity / frame) as u64;
    assert!(frames <= 32, "capacity {capacity}");
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(move |_| {
        Action::Accept(Box::new(move |peer: &mut Peer| {
            peer.hello("sbx_1");
            peer.open();
            peer.send(&ServerControl::Ready {
                channel: 1,
                pty: None,
            });
            let chunk = vec![b'e'; frame];
            for seq in 0..frames {
                peer.data(1, DataStream::Stderr, seq, &chunk);
            }
            peer.acked(wire::OutputStream::Stderr, frames - 1);
            thread::sleep(Duration::from_millis(100));
            if close_stdout {
                peer.data(1, DataStream::Stdout, 0, b"late\n");
                peer.expect("the close of the channel", |f| {
                    *f == In::Control(ClientControl::Close { channel: 1 })
                });
            } else {
                peer.send(&ServerControl::End {
                    intent: Intent::Revoked,
                    error: None,
                });
                let _ = peer.ws.close(None);
            }
            peer.drain();
        }))
    });
    let mut args = vec!["sandbox", "shell", "sbx_1", "--", "cat", "big"];
    if json_mode {
        args.insert(3, "--json");
    }
    let mut cmd = command(root.path(), &fake.url, &args);
    cmd.stderr(Stdio::from(stderr_write));
    let started = Instant::now();
    let mut child = ManagedChild::spawn(&mut cmd).unwrap();
    // The test's copy of the write end goes with the command.
    drop(cmd);
    let mut stdout = child.stdout.take().unwrap();
    let output = if close_stdout {
        drop(stdout);
        None
    } else {
        Some(thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = stdout.read_to_end(&mut bytes);
            bytes
        }))
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    let exit = loop {
        if let Some(exit) = child.try_wait().unwrap() {
            break exit;
        }
        assert!(
            Instant::now() < deadline,
            "the CLI hung on its full stderr (json: {json_mode}, stdout closed: {close_stdout})"
        );
        thread::sleep(Duration::from_millis(10));
    };
    let elapsed = started.elapsed();
    let mut errors = Vec::new();
    stderr.read_to_end(&mut errors).unwrap();
    if let Some(output) = output {
        assert_eq!(output.join().unwrap(), b"", "nothing on stdout");
    }
    FullStderr {
        exit,
        elapsed,
        stderr: errors,
        capacity,
    }
}

#[cfg(target_os = "linux")]
#[test]
fn a_full_stderr_cannot_hold_the_final_error_line() {
    for json_mode in [false, true] {
        let run = on_a_full_stderr(json_mode, false);
        assert_eq!(run.exit.code(), Some(125), "json: {json_mode}");
        // All the guest stderr, and the error line could not be written.
        assert_eq!(run.stderr.len(), run.capacity, "json: {json_mode}");
        assert!(run.stderr.iter().all(|byte| *byte == b'e'));
        assert!(
            run.elapsed >= Duration::from_secs(2),
            "the error line got its settle time"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn a_full_stderr_cannot_hold_the_error_line_of_a_stopped_writer() {
    // The closed stdout stops the writer; its broken-pipe error line cannot
    // be written to the full stderr either, and the exit stays 141.
    for json_mode in [false, true] {
        let run = on_a_full_stderr(json_mode, true);
        assert_eq!(run.exit.code(), Some(141), "json: {json_mode}");
        assert_eq!(run.stderr.len(), run.capacity, "json: {json_mode}");
        assert!(run.stderr.iter().all(|byte| *byte == b'e'));
        assert!(
            run.elapsed >= Duration::from_secs(2),
            "the error line got its settle time"
        );
    }
}

#[test]
fn a_stdout_closed_early_exits_141_while_frames_keep_arriving() {
    // The writer fails on the first frame of a burst while the connection
    // thread may still be handing it the rest: either way the closed
    // stdout is what ends the session. Several rounds widen the race.
    for round in 0..5 {
        let root = tempfile::tempdir().unwrap();
        let reader_closed = Arc::new(AtomicBool::new(false));
        let closed = reader_closed.clone();
        let fake = Fake::new(move |_| {
            let closed = closed.clone();
            Action::Accept(Box::new(move |peer: &mut Peer| {
                peer.hello("sbx_1");
                peer.open();
                peer.send(&ServerControl::Ready {
                    channel: 1,
                    pty: None,
                });
                peer.data(1, DataStream::Stdout, 0, b"first\n");
                peer.acked(wire::OutputStream::Stdout, 0);
                let deadline = Instant::now() + Duration::from_secs(10);
                while !closed.load(Ordering::SeqCst) {
                    assert!(Instant::now() < deadline, "the reader never closed");
                    thread::sleep(Duration::from_millis(1));
                }
                // A full window of frames in one write: the CLI reads them
                // in one batch.
                peer.burst(1, DataStream::Stdout, 1..=32, &[b'z'; 512]);
                peer.drain();
            }))
        });
        let mut cmd = command(
            root.path(),
            &fake.url,
            &["sandbox", "shell", "sbx_1", "--", "cat", "big"],
        );
        let mut child = ManagedChild::spawn(&mut cmd).unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();
        let errors = thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = stderr.read_to_end(&mut bytes);
            bytes
        });
        let mut first = [0_u8; 6];
        stdout.read_exact(&mut first).unwrap();
        assert_eq!(&first, b"first\n");
        drop(stdout);
        reader_closed.store(true, Ordering::SeqCst);
        let deadline = Instant::now() + Duration::from_secs(10);
        let exit = loop {
            if let Some(exit) = child.try_wait().unwrap() {
                break exit;
            }
            assert!(
                Instant::now() < deadline,
                "the CLI did not end (round {round})"
            );
            thread::sleep(Duration::from_millis(10));
        };
        let errors = text(&errors.join().unwrap());
        assert_eq!(exit.code(), Some(141), "round {round}: {errors}");
        assert!(errors.contains("broken pipe"), "round {round}: {errors}");
    }
}

#[test]
fn json_refusals_are_one_error_line() {
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(|_| {
        Action::Reply(
            409,
            error_body("sandbox.state_conflict", "The sandbox is not running."),
        )
    });
    let output = run(
        command(
            root.path(),
            &fake.url,
            &["sandbox", "shell", "sbx_1", "--json"],
        ),
        None,
    );
    assert_eq!(output.status.code(), Some(10));
    let stderr = text(&output.stderr);
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    let line: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(line["error"]["code"], "sandbox.state_conflict");
    assert_eq!(line["error"]["status"], 409);
}

#[test]
fn a_login_without_the_connect_scope_is_told_to_log_in_again() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(|_| Action::Reply(403, error_body("FORBIDDEN", "Insufficient scope.")));
    let dir = root.path().join("data/user");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let login = json!({"origin": format!("{}/", fake.url),"keyId":"key-1","name":"laptop","secret":SECRET,"scopes":["sandboxes:read","sandboxes:create"],"poolMode":"ALL_USABLE","poolIds":[],"ownSandboxesOnly":false,"expiresAt":null,"maxLiveSandboxes":null,"userEmail":"person@example.test","createdAt":"2026-11-18T00:00:00Z"});
    std::fs::write(dir.join("login.json"), login.to_string()).unwrap();
    std::fs::set_permissions(
        dir.join("login.json"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let mut cmd = command(root.path(), &fake.url, &["sandbox", "shell", "sbx_1"]);
    cmd.env_remove("WSSP_API_KEY").env_remove("WSSP_SERVER");
    let output = run(cmd, None);
    assert_eq!(output.status.code(), Some(8));
    assert!(
        text(&output.stderr).contains("log in again (`wssp login`) to get shell access"),
        "{}",
        text(&output.stderr)
    );
}

#[test]
fn a_revoked_saved_login_is_told_to_log_in_again() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(|_| Action::Bare(401, refusal_headers("UNAUTHORIZED", None)));
    let dir = root.path().join("data/user");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let login = json!({"origin": format!("{}/", fake.url),"keyId":"key-1","name":"laptop","secret":SECRET,"scopes":["sandboxes:read","sandboxes:create","sandboxes:connect"],"poolMode":"ALL_USABLE","poolIds":[],"ownSandboxesOnly":false,"expiresAt":null,"maxLiveSandboxes":null,"userEmail":"person@example.test","createdAt":"2026-11-18T00:00:00Z"});
    std::fs::write(dir.join("login.json"), login.to_string()).unwrap();
    std::fs::set_permissions(
        dir.join("login.json"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let mut cmd = command(
        root.path(),
        &fake.url,
        &["sandbox", "shell", "sbx_1", "--", "true"],
    );
    cmd.env_remove("WSSP_API_KEY").env_remove("WSSP_SERVER");
    let output = run(cmd, None);
    assert_eq!(output.status.code(), Some(7), "{}", text(&output.stderr));
    assert!(
        text(&output.stderr).starts_with(
            "error: the server refused this login (revoked or expired); log in again (`wssp login`)"
        ),
        "{}",
        text(&output.stderr)
    );
}

#[test]
fn a_name_is_resolved_through_the_sandbox_list() {
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(|head| {
        if head.target == connect_target("my-box") {
            return Action::Reply(404, error_body("NOT_FOUND", "Sandbox not found."));
        }
        if head.target.starts_with("/v1/sandboxes?") {
            assert!(!head.upgrade());
            assert!(head.target.contains("limit=100"));
            return Action::Reply(
                200,
                json!({"items": [{"id": "sbx_other", "name": "other"}, {"id": "sbx_9", "name": "my-box"}], "nextCursor": null}),
            );
        }
        assert_eq!(head.target, connect_target("sbx_9"));
        Action::Accept(Box::new(|peer: &mut Peer| {
            peer.hello("sbx_9");
            peer.open();
            peer.send(&ServerControl::Ready {
                channel: 1,
                pty: None,
            });
            peer.exit(Some(0), None, 0, 0);
            peer.drain();
        }))
    });
    let output = run(
        command(
            root.path(),
            &fake.url,
            &["sandbox", "shell", "my-box", "--", "true"],
        ),
        None,
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert_eq!(fake.heads().len(), 3);
}

#[test]
fn an_unknown_name_stays_not_found() {
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(|head| {
        if head.target.starts_with("/v1/sandboxes?") {
            return Action::Reply(200, json!({"items": [], "nextCursor": null}));
        }
        Action::Reply(404, error_body("NOT_FOUND", "Sandbox not found."))
    });
    let output = run(
        command(
            root.path(),
            &fake.url,
            &["sandbox", "shell", "nope", "--", "true"],
        ),
        None,
    );
    assert_eq!(output.status.code(), Some(3), "{}", text(&output.stderr));
}

#[test]
fn end_revoked_mid_session_names_the_intent_and_exits_125() {
    for json_mode in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let fake = Fake::new(|_| {
            Action::Accept(Box::new(|peer: &mut Peer| {
                peer.hello("sbx_1");
                peer.open();
                peer.send(&ServerControl::Ready {
                    channel: 1,
                    pty: None,
                });
                peer.data(1, DataStream::Stdout, 0, b"partial\n");
                peer.acked(wire::OutputStream::Stdout, 0);
                peer.send(&ServerControl::End {
                    intent: Intent::Revoked,
                    error: None,
                });
                let _ = peer.ws.close(Some(tungstenite::protocol::CloseFrame {
                    code: wire::CLOSE_CODE.into(),
                    reason: "end".into(),
                }));
                peer.drain();
            }))
        });
        let mut args = vec!["sandbox", "shell", "sbx_1", "--", "sleep", "100"];
        if json_mode {
            args.insert(3, "--json");
        }
        let output = run(command(root.path(), &fake.url, &args), None);
        assert_eq!(output.status.code(), Some(125), "{}", text(&output.stderr));
        assert_eq!(text(&output.stdout), "partial\n");
        let stderr = text(&output.stderr);
        assert_eq!(stderr.lines().count(), 1, "one line: {stderr}");
        if json_mode {
            let line: Value = serde_json::from_str(stderr.trim()).unwrap();
            assert_eq!(line["error"]["code"], "connect.revoked");
            assert_eq!(line["error"]["data"]["intent"], "revoked");
        } else {
            assert!(stderr.contains("`revoked`"), "{stderr}");
        }
    }
}

#[test]
fn a_kill_close_of_the_channel_exits_125_and_a_lost_socket_too() {
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(|_| {
        Action::Accept(Box::new(|peer: &mut Peer| {
            peer.hello("sbx_1");
            peer.open();
            peer.send(&ServerControl::Ready {
                channel: 1,
                pty: None,
            });
            peer.send(&ServerControl::Exit {
                channel: 1,
                exit_code: None,
                signal: Some(9),
                intent: Some(Intent::SandboxStopped),
                error: None,
                frames: ExitFrames {
                    stdout: 0,
                    stderr: 0,
                },
            });
            peer.drain();
        }))
    });
    let output = run(
        command(
            root.path(),
            &fake.url,
            &["sandbox", "shell", "sbx_1", "--", "sleep", "9"],
        ),
        None,
    );
    assert_eq!(output.status.code(), Some(125));
    assert!(
        text(&output.stderr).contains("`sandbox_stopped`"),
        "{}",
        text(&output.stderr)
    );

    let fake = Fake::new(|_| {
        Action::Accept(Box::new(|peer: &mut Peer| {
            peer.hello("sbx_1");
            peer.open();
            // Gone without an end frame.
        }))
    });
    let output = run(
        command(
            root.path(),
            &fake.url,
            &["sandbox", "shell", "sbx_1", "--", "sleep", "9"],
        ),
        None,
    );
    assert_eq!(output.status.code(), Some(125));
    // A drop (a proxy or Cloudflare edge restart) says how to get a new session.
    let stderr = text(&output.stderr);
    assert!(
        stderr.contains("the connection to the server was lost")
            && stderr.contains("run the command again to start a new one"),
        "{stderr}"
    );
}

#[test]
fn a_protocol_violation_by_the_server_ends_the_session() {
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(|_| {
        Action::Accept(Box::new(|peer: &mut Peer| {
            peer.hello("sbx_1");
            peer.open();
            peer.send(&ServerControl::Ready {
                channel: 1,
                pty: None,
            });
            // A sequence gap.
            peer.data(1, DataStream::Stdout, 3, b"x");
            peer.drain();
        }))
    });
    let output = run(
        command(
            root.path(),
            &fake.url,
            &["sandbox", "shell", "sbx_1", "--", "true"],
        ),
        None,
    );
    assert_eq!(output.status.code(), Some(125));
    assert!(
        text(&output.stderr).contains("protocol"),
        "{}",
        text(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "nothing of a broken frame is delivered"
    );
}

#[test]
fn a_refused_open_maps_host_capacity_to_retryable() {
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(|_| {
        Action::Accept(Box::new(|peer: &mut Peer| {
            peer.hello("sbx_1");
            peer.open();
            peer.send(&ServerControl::Exit {
                channel: 1,
                exit_code: None,
                signal: None,
                intent: None,
                error: Some(wire::WireError {
                    code: "host_capacity".into(),
                    message: "channel capacity reached".into(),
                }),
                frames: ExitFrames {
                    stdout: 0,
                    stderr: 0,
                },
            });
            peer.drain();
        }))
    });
    let output = run(
        command(
            root.path(),
            &fake.url,
            &["sandbox", "shell", "sbx_1", "--", "true"],
        ),
        None,
    );
    assert_eq!(output.status.code(), Some(11), "{}", text(&output.stderr));
}

#[test]
fn usage_errors_are_local() {
    let root = tempfile::tempdir().unwrap();
    for args in [
        vec!["sandbox", "shell", "sbx_1", "--env", "PATH=/bin"],
        vec!["sandbox", "shell", "sbx_1", "--cwd", "relative"],
        vec!["sandbox", "shell", "../x"],
    ] {
        // No server at all: nothing may be dialled.
        let output = run(command(root.path(), "http://127.0.0.1:9", &args), None);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            text(&output.stderr)
        );
    }
    let mut cmd = command(
        root.path(),
        "http://127.0.0.1:9",
        &["sandbox", "shell", "sbx_1"],
    );
    cmd.env_remove("WSSP_API_KEY").env_remove("WSSP_SERVER");
    assert_eq!(run(cmd, None).status.code(), Some(7));
}

/// A pty pair for the CLI's stdin and stdout.
#[cfg(target_os = "linux")]
mod pty {
    use std::fs::File;
    use std::os::fd::OwnedFd;

    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
    use rustix::termios::{self, Winsize};

    pub struct Pair {
        pub master: File,
        pub slave: File,
    }

    pub fn open(rows: u16, cols: u16) -> Pair {
        let master: OwnedFd = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
        grantpt(&master).unwrap();
        unlockpt(&master).unwrap();
        let name = ptsname(&master, Vec::new()).unwrap();
        let slave = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(name.to_str().unwrap())
            .unwrap();
        let master = File::from(master);
        resize(&master, rows, cols);
        Pair { master, slave }
    }

    pub fn resize(master: &File, rows: u16, cols: u16) {
        termios::tcsetwinsize(
            master,
            Winsize {
                ws_row: rows,
                ws_col: cols,
                ws_xpixel: 0,
                ws_ypixel: 0,
            },
        )
        .unwrap();
    }

    pub fn canonical(slave: &File) -> bool {
        termios::tcgetattr(slave)
            .unwrap()
            .local_modes
            .contains(termios::LocalModes::ICANON)
    }
}

#[cfg(target_os = "linux")]
#[test]
fn pty_shell_is_raw_echoes_resizes_and_restores_the_terminal() {
    use std::sync::mpsc;

    let root = tempfile::tempdir().unwrap();
    let pair = pty::open(30, 100);
    assert!(pty::canonical(&pair.slave));
    // The test drives the session from here through these channels.
    let (to_test, from_peer) = mpsc::channel::<In>();
    let (to_peer, from_test) = mpsc::channel::<&'static str>();
    let from_test = Mutex::new(Some(from_test));
    let to_test = Mutex::new(Some(to_test));
    let fake = Fake::new(move |_| {
        let from_test = from_test.lock().unwrap().take().unwrap();
        let to_test = to_test.lock().unwrap().take().unwrap();
        Action::Accept(Box::new(move |peer: &mut Peer| {
            peer.hello("sbx_1");
            let open = peer.open();
            to_test.send(In::Control(open)).unwrap();
            // `ready` only once the test saw the terminal still cooked.
            assert_eq!(
                from_test.recv_timeout(Duration::from_secs(15)).unwrap(),
                "cooked"
            );
            peer.send(&ServerControl::Ready {
                channel: 1,
                pty: Some(PtySize {
                    rows: 30,
                    cols: 100,
                }),
            });
            // The typed byte arrives at once (raw mode), echoed back.
            let typed = peer.expect("stdin", |f| matches!(f, In::Data(..)));
            to_test.send(typed).unwrap();
            peer.data(1, DataStream::Stdout, 0, b"echo:x\r\n");
            peer.acked(wire::OutputStream::Stdout, 0);
            assert_eq!(from_test.recv().unwrap(), "resized");
            let resize = peer.seen_or_expect("resize", |f| {
                matches!(f, In::Control(ClientControl::Resize { .. }))
            });
            to_test.send(resize).unwrap();
            peer.exit(Some(3), None, 1, 0);
            peer.drain();
        }))
    });
    let mut cmd = command(root.path(), &fake.url, &["sandbox", "shell", "sbx_1"]);
    cmd.env("TERM", "vt100")
        .stdin(pair.slave.try_clone().unwrap())
        .stdout(pair.slave.try_clone().unwrap());
    let mut child = ManagedChild::spawn(&mut cmd).unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let screen = Arc::new(Mutex::new(Vec::new()));
    let mut master_reader = pair.master.try_clone().unwrap();
    let captured = screen.clone();
    thread::spawn(move || {
        let mut buffer = [0; 1024];
        while let Ok(n) = master_reader.read(&mut buffer) {
            if n == 0 {
                break;
            }
            captured.lock().unwrap().extend_from_slice(&buffer[..n]);
        }
    });
    let wait = Duration::from_secs(15);
    let stderr_text = Arc::new(Mutex::new(Vec::new()));
    let sink = stderr_text.clone();
    thread::spawn(move || {
        let mut buffer = [0; 1024];
        while let Ok(n) = stderr.read(&mut buffer) {
            if n == 0 {
                break;
            }
            sink.lock().unwrap().extend_from_slice(&buffer[..n]);
        }
    });
    let next = |what: &str| -> In {
        from_peer.recv_timeout(wait).unwrap_or_else(|_| {
            thread::sleep(Duration::from_millis(500));
            panic!(
                "no {what} from the fake; CLI stderr: {}",
                text(&stderr_text.lock().unwrap())
            )
        })
    };
    let open = next("open");
    assert_eq!(
        open,
        In::Control(ClientControl::Open {
            channel: 1,
            kind: Kind::Pty,
            argv: None,
            login: Some(true),
            cwd: None,
            env: None,
            pty: Some(wire::PtyParams {
                rows: 30,
                cols: 100,
                term: "vt100".into()
            }),
            port: None,
            path: None,
        })
    );
    // The open went out, `ready` has not come: the terminal stays cooked
    // (a Ctrl-C can still cancel a pending open). Some time for a CLI that
    // would go raw early to do so.
    thread::sleep(Duration::from_millis(300));
    assert!(
        pty::canonical(&pair.slave),
        "the terminal went raw before ready"
    );
    to_peer.send("cooked").unwrap();
    let deadline = Instant::now() + wait;
    while pty::canonical(&pair.slave) {
        assert!(Instant::now() < deadline, "the terminal never went raw");
        thread::sleep(Duration::from_millis(10));
    }
    // No newline: a cooked terminal would hold this byte back.
    (&pair.master).write_all(b"x").unwrap();
    let typed = next("stdin");
    assert_eq!(
        typed,
        In::Data(DataMetadata::new(1, DataStream::Stdin, 0), b"x".to_vec())
    );
    let deadline = Instant::now() + wait;
    while !text(&screen.lock().unwrap()).contains("echo:x") {
        assert!(
            Instant::now() < deadline,
            "the output never reached the terminal"
        );
        thread::sleep(Duration::from_millis(10));
    }
    pty::resize(&pair.master, 40, 120);
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(child.id() as i32).unwrap(),
        rustix::process::Signal::WINCH,
    )
    .unwrap();
    to_peer.send("resized").unwrap();
    let resize = next("resize");
    assert_eq!(
        resize,
        In::Control(ClientControl::Resize {
            channel: 1,
            rows: 40,
            cols: 120
        })
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "the CLI never exited");
        thread::sleep(Duration::from_millis(10));
    };
    thread::sleep(Duration::from_millis(100));
    let errors = text(&stderr_text.lock().unwrap());
    assert_eq!(status.code(), Some(3), "{errors}");
    assert!(
        pty::canonical(&pair.slave),
        "the terminal settings were restored"
    );
    drop(fake);
}

#[cfg(target_os = "linux")]
#[test]
fn sigquit_in_a_pty_session_closes_the_channel_and_restores_the_terminal() {
    use std::sync::mpsc;

    let root = tempfile::tempdir().unwrap();
    let pair = pty::open(30, 100);
    assert!(pty::canonical(&pair.slave));
    let (ready_tx, ready) = mpsc::channel::<()>();
    let ready_tx = Mutex::new(Some(ready_tx));
    let fake = Fake::new(move |_| {
        let ready_tx = ready_tx.lock().unwrap().take().unwrap();
        Action::Accept(Box::new(move |peer: &mut Peer| {
            peer.hello("sbx_1");
            peer.open();
            peer.send(&ServerControl::Ready {
                channel: 1,
                pty: Some(PtySize {
                    rows: 30,
                    cols: 100,
                }),
            });
            ready_tx.send(()).unwrap();
            peer.expect("close", |f| {
                *f == In::Control(ClientControl::Close { channel: 1 })
            });
            assert!(
                !peer
                    .log
                    .iter()
                    .any(|f| matches!(f, In::Control(ClientControl::Signal { .. }))),
                "SIGQUIT is never forwarded: {:?}",
                peer.log
            );
            peer.send(&ServerControl::Exit {
                channel: 1,
                exit_code: None,
                signal: None,
                intent: Some(Intent::Client),
                error: None,
                frames: ExitFrames {
                    stdout: 0,
                    stderr: 0,
                },
            });
            peer.drain();
        }))
    });
    let mut cmd = command(root.path(), &fake.url, &["sandbox", "shell", "sbx_1"]);
    cmd.env("TERM", "vt100")
        .stdin(pair.slave.try_clone().unwrap())
        .stdout(pair.slave.try_clone().unwrap());
    let mut child = ManagedChild::spawn(&mut cmd).unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let errors = thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stderr.read_to_end(&mut bytes);
        bytes
    });
    let mut master_reader = pair.master.try_clone().unwrap();
    thread::spawn(move || {
        let mut buffer = [0; 1024];
        while matches!(master_reader.read(&mut buffer), Ok(n) if n > 0) {}
    });
    ready.recv_timeout(Duration::from_secs(15)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    while pty::canonical(&pair.slave) {
        assert!(Instant::now() < deadline, "the terminal never went raw");
        thread::sleep(Duration::from_millis(10));
    }
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(child.id() as i32).unwrap(),
        rustix::process::Signal::QUIT,
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "the CLI never exited");
        thread::sleep(Duration::from_millis(10));
    };
    let errors = text(&errors.join().unwrap());
    assert_eq!(status.code(), Some(131), "{errors}");
    assert!(
        pty::canonical(&pair.slave),
        "the terminal settings were restored"
    );
    drop(fake);
}

/// Wait for the child's exit, failing after `limit`.
fn wait_exit(child: &mut ManagedChild, limit: Duration, what: &str) -> std::process::ExitStatus {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(exit) = child.try_wait().unwrap() {
            return exit;
        }
        assert!(Instant::now() < deadline, "{what}");
        thread::sleep(Duration::from_millis(10));
    }
}

/// Collect a pipe to its end on a thread of its own.
fn collect(mut pipe: impl Read + Send + 'static) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = pipe.read_to_end(&mut bytes);
        bytes
    })
}

#[cfg(target_os = "linux")]
fn kill(child: &ManagedChild, signal: rustix::process::Signal) {
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(child.id() as i32).unwrap(),
        signal,
    )
    .unwrap();
}

/// Limits whose silence limit, `max(3 × ping, idle)`, is 1 s.
fn quick_liveness() -> Limits {
    Limits {
        ping_interval_ms: 200,
        idle_timeout_ms: 1_000,
        ..limits()
    }
}

#[test]
fn a_silent_server_ends_the_session_as_lost() {
    // The socket stays open but nothing arrives, not even a ping: past the
    // silence limit the connection is lost (exit 125, `connect.lost`).
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(|_| {
        Action::Accept(Box::new(|peer: &mut Peer| {
            peer.hello_with("sbx_1", quick_liveness());
            peer.open();
            peer.ready_exec();
            // Silent from here; only read until the CLI hangs up.
            peer.drain();
        }))
    });
    let mut cmd = command(
        root.path(),
        &fake.url,
        &["sandbox", "shell", "sbx_1", "--", "sleep", "100"],
    );
    let started = Instant::now();
    let mut child = ManagedChild::spawn(&mut cmd).unwrap();
    let output = collect(child.stdout.take().unwrap());
    let errors = collect(child.stderr.take().unwrap());
    let exit = wait_exit(
        &mut child,
        Duration::from_secs(15),
        "the CLI never noticed the silent server",
    );
    let elapsed = started.elapsed();
    let errors = text(&errors.join().unwrap());
    assert_eq!(exit.code(), Some(125), "{errors}");
    assert_eq!(errors.lines().count(), 1, "one line: {errors}");
    assert!(
        errors.contains("lost") && errors.contains("the server sent nothing for 1 s"),
        "{errors}"
    );
    assert_eq!(output.join().unwrap(), b"");
    assert!(
        elapsed >= Duration::from_secs(1),
        "not before the limit: {elapsed:?}"
    );
}

#[test]
fn server_pings_keep_a_quiet_session_alive() {
    // The same 1 s silence limit; nothing but pings for 3 s.
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(|_| {
        Action::Accept(Box::new(|peer: &mut Peer| {
            peer.hello_with("sbx_1", quick_liveness());
            peer.open();
            peer.ready_exec();
            let quiet = Instant::now();
            while quiet.elapsed() < Duration::from_secs(3) {
                peer.ws.send(Message::Ping(Vec::new().into())).unwrap();
                thread::sleep(Duration::from_millis(100));
            }
            peer.data(1, DataStream::Stdout, 0, b"still here\n");
            peer.acked(wire::OutputStream::Stdout, 0);
            peer.exit(Some(0), None, 1, 0);
            peer.drain();
        }))
    });
    let started = Instant::now();
    let output = run(
        command(
            root.path(),
            &fake.url,
            &["sandbox", "shell", "sbx_1", "--", "sleep", "3"],
        ),
        None,
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert_eq!(text(&output.stdout), "still here\n");
    assert_eq!(text(&output.stderr), "");
    assert!(started.elapsed() >= Duration::from_secs(3));
}

#[test]
fn a_stalled_socket_ends_without_a_closing_handshake() {
    // The fake never reads while the CLI sends stdin from /dev/zero with
    // practically unlimited credit: the socket buffers fill and a write
    // stalls for 30 s. That ends the session (125); the closing handshake
    // on the stalled socket is skipped, so the CLI does not wait for the
    // write timeout again. The stall itself takes 30 to 60 s (a blocked
    // write that copied some bytes before it blocked returns them after
    // 30 s, and only the next one fails); attempting the closing handshake
    // would add three more timed-out writes, at least 150 s in all.
    let root = tempfile::tempdir().unwrap();
    let (done_tx, done) = std::sync::mpsc::channel::<()>();
    let done = Mutex::new(Some(done));
    let fake = Fake::new(move |_| {
        let done = done.lock().unwrap().take().unwrap();
        Action::Accept(Box::new(move |peer: &mut Peer| {
            peer.hello_with(
                "sbx_1",
                Limits {
                    window_frames: PerKind {
                        pty: 8,
                        exec: 1 << 30,
                    },
                    unacked_input_bytes: 1 << 50,
                    ..limits()
                },
            );
            peer.open();
            peer.send(&ServerControl::Ready {
                channel: 1,
                pty: None,
            });
            // Never read again until the CLI exited.
            let _ = done.recv_timeout(Duration::from_secs(200));
        }))
    });
    let mut cmd = command(
        root.path(),
        &fake.url,
        &["sandbox", "shell", "sbx_1", "--", "cat"],
    );
    cmd.stdin(std::fs::File::open("/dev/zero").unwrap());
    let started = Instant::now();
    let mut child = ManagedChild::spawn(&mut cmd).unwrap();
    let output = collect(child.stdout.take().unwrap());
    let errors = collect(child.stderr.take().unwrap());
    let exit = wait_exit(
        &mut child,
        Duration::from_secs(100),
        "the CLI kept waiting on its stalled socket",
    );
    let elapsed = started.elapsed();
    done_tx.send(()).unwrap();
    let errors = text(&errors.join().unwrap());
    assert_eq!(exit.code(), Some(125), "{errors}");
    assert!(errors.contains("no progress for 30 s"), "{errors}");
    assert_eq!(output.join().unwrap(), b"");
    assert!(elapsed >= Duration::from_secs(30), "{elapsed:?}");
    drop(fake);
}

#[cfg(target_os = "linux")]
#[test]
fn sigint_is_forwarded_after_ready_and_a_second_one_closes_with_130() {
    use std::sync::mpsc;
    let root = tempfile::tempdir().unwrap();
    let (to_test, from_peer) = mpsc::channel::<&'static str>();
    let to_test = Mutex::new(Some(to_test));
    let fake = Fake::new(move |_| {
        let to_test = to_test.lock().unwrap().take().unwrap();
        Action::Accept(Box::new(move |peer: &mut Peer| {
            peer.hello("sbx_1");
            peer.open();
            peer.ready_exec();
            to_test.send("ready").unwrap();
            peer.expect("the forwarded INT", |f| {
                *f == In::Control(ClientControl::Signal {
                    channel: 1,
                    signal: wire::Signal::Int,
                })
            });
            to_test.send("forwarded").unwrap();
            // Every later INT within 2 s of the previous one closes; one
            // that came later is forwarded again (skipped here).
            peer.expect("close", |f| {
                *f == In::Control(ClientControl::Close { channel: 1 })
            });
            to_test.send("closed").unwrap();
            peer.exit_client();
            peer.drain();
        }))
    });
    let mut cmd = command(
        root.path(),
        &fake.url,
        &["sandbox", "shell", "sbx_1", "--", "sleep", "100"],
    );
    let mut child = ManagedChild::spawn(&mut cmd).unwrap();
    let errors = collect(child.stderr.take().unwrap());
    let wait = Duration::from_secs(15);
    assert_eq!(from_peer.recv_timeout(wait).unwrap(), "ready");
    kill(&child, rustix::process::Signal::INT);
    assert_eq!(from_peer.recv_timeout(wait).unwrap(), "forwarded");
    // The second Ctrl-C, repeated so that slow scheduling cannot push every
    // one past the 2 s window.
    let deadline = Instant::now() + wait;
    loop {
        kill(&child, rustix::process::Signal::INT);
        if from_peer.recv_timeout(Duration::from_millis(300)).is_ok() {
            break;
        }
        assert!(Instant::now() < deadline, "the second Ctrl-C never closed");
    }
    let exit = wait_exit(&mut child, wait, "the CLI never exited");
    let errors = text(&errors.join().unwrap());
    assert_eq!(exit.code(), Some(130), "{errors}");
    assert_eq!(errors, "");
}

#[cfg(target_os = "linux")]
#[test]
fn term_and_hup_are_forwarded_once_and_a_second_one_closes() {
    use std::sync::mpsc;
    for (signal, remote, status) in [
        (rustix::process::Signal::TERM, wire::Signal::Term, 143),
        (rustix::process::Signal::HUP, wire::Signal::Hup, 129),
    ] {
        let root = tempfile::tempdir().unwrap();
        let (to_test, from_peer) = mpsc::channel::<&'static str>();
        let to_test = Mutex::new(Some(to_test));
        let fake = Fake::new(move |_| {
            let to_test = to_test.lock().unwrap().take().unwrap();
            Action::Accept(Box::new(move |peer: &mut Peer| {
                peer.hello("sbx_1");
                peer.open();
                peer.ready_exec();
                to_test.send("ready").unwrap();
                peer.expect("the forwarded signal", |f| {
                    *f == In::Control(ClientControl::Signal {
                        channel: 1,
                        signal: remote,
                    })
                });
                to_test.send("forwarded").unwrap();
                peer.expect("close", |f| {
                    *f == In::Control(ClientControl::Close { channel: 1 })
                });
                let signals = peer
                    .log
                    .iter()
                    .filter(|f| matches!(f, In::Control(ClientControl::Signal { .. })))
                    .count();
                assert_eq!(signals, 1, "forwarded once: {:?}", peer.log);
                peer.exit_client();
                peer.drain();
            }))
        });
        let mut cmd = command(
            root.path(),
            &fake.url,
            &["sandbox", "shell", "sbx_1", "--", "sleep", "100"],
        );
        let mut child = ManagedChild::spawn(&mut cmd).unwrap();
        let errors = collect(child.stderr.take().unwrap());
        let wait = Duration::from_secs(15);
        assert_eq!(from_peer.recv_timeout(wait).unwrap(), "ready");
        kill(&child, signal);
        assert_eq!(from_peer.recv_timeout(wait).unwrap(), "forwarded");
        kill(&child, signal);
        let exit = wait_exit(&mut child, wait, "the second signal never ended the CLI");
        let errors = text(&errors.join().unwrap());
        assert_eq!(exit.code(), Some(status), "{signal:?}: {errors}");
        assert_eq!(errors, "", "{signal:?}");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn a_close_the_server_never_answers_ends_after_the_close_wait() {
    use std::sync::mpsc;
    let root = tempfile::tempdir().unwrap();
    let (opened_tx, opened) = mpsc::channel::<()>();
    let opened_tx = Mutex::new(Some(opened_tx));
    let fake = Fake::new(move |_| {
        let opened_tx = opened_tx.lock().unwrap().take().unwrap();
        Action::Accept(Box::new(move |peer: &mut Peer| {
            peer.hello("sbx_1");
            peer.open();
            opened_tx.send(()).unwrap();
            peer.expect("close", |f| {
                *f == In::Control(ClientControl::Close { channel: 1 })
            });
            // No exit for the close: the CLI gives up after its 2 s wait.
            peer.drain();
        }))
    });
    let mut cmd = command(
        root.path(),
        &fake.url,
        &["sandbox", "shell", "sbx_1", "--", "sleep", "100"],
    );
    let mut child = ManagedChild::spawn(&mut cmd).unwrap();
    let errors = collect(child.stderr.take().unwrap());
    opened.recv_timeout(Duration::from_secs(15)).unwrap();
    let signalled = Instant::now();
    kill(&child, rustix::process::Signal::TERM);
    let exit = wait_exit(
        &mut child,
        Duration::from_secs(15),
        "the CLI kept waiting for the exit of its close",
    );
    let elapsed = signalled.elapsed();
    let errors = text(&errors.join().unwrap());
    assert_eq!(exit.code(), Some(143), "{errors}");
    assert!(
        elapsed >= Duration::from_secs(2),
        "the close got its wait: {elapsed:?}"
    );
}
