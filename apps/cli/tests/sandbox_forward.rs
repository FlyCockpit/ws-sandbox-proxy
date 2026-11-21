//! `wssp sandbox forward` against an in-process fake of the connect plane
//! (`wssp.connect.v1`): a tungstenite server on loopback that plays the
//! server side with the CLI's own codecs (the fake of `sandbox_shell.rs`,
//! reduced to one upgrade, plus a scripted relay session). Real binary;
//! children go through `ManagedChild`; local clients are real sockets.
#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tungstenite::{Message, WebSocket};
use wssp::connect_client::wire::{
    self, ClientControl, DataMetadata, DataStream, ExitFrames, Intent, Kind, Limits, PerKind,
    ServerControl, StdinStream, WireError,
};

#[path = "../../../crates/sandbox-runtime/tests/support/managed_child.rs"]
mod managed_child;
use managed_child::ManagedChild;

const SECRET: &str = "wssp_sdk_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

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

/// How the fake's relay session behaves.
#[derive(Clone)]
struct Script {
    limits: Limits,
    /// Answer `ready` to opens (otherwise they wait).
    ready: bool,
    /// Echo stdin back as stdout; a stdin eof gets the stdout eof and a
    /// natural exit (the guest service closes too).
    echo: bool,
    /// Every open exits with this error instead of `ready`.
    refuse: Option<WireError>,
    /// On `ready`: send these bytes, then the stdout eof (the guest service
    /// shut its write side) and keep reading stdin.
    greet_and_shut: Option<Vec<u8>>,
    /// The first stdin frame of a channel is answered by an exit without
    /// any stdout eof (a reset).
    reset_on_input: bool,
    /// Never answer a `close`: as if every close raced the channel's own
    /// natural end (the server ignores a close of a channel it ended).
    ignore_close: bool,
    /// Never acknowledge stdin (a guest service that reads nothing), so the
    /// CLI's stdin credit runs out. The test may still send acks itself.
    hold_stdin_acks: bool,
    /// The first this many opens exit `rate_limited` instead of `ready`.
    rate_limit_first: usize,
}

impl Default for Script {
    fn default() -> Self {
        Self {
            limits: limits(),
            ready: true,
            echo: true,
            refuse: None,
            greet_and_shut: None,
            reset_on_input: false,
            ignore_close: false,
            hold_stdin_acks: false,
            rate_limit_first: 0,
        }
    }
}

/// What the CLI sent, as the fake saw it.
#[derive(Debug, Clone, PartialEq)]
enum In {
    Control(ClientControl),
    Data(DataMetadata, Vec<u8>),
    /// The CLI answered a ping: it read everything sent before it.
    Pong,
}

/// The test's orders to the running session.
enum Cmd {
    Send(ServerControl),
    End(Intent),
    /// The guest end: these stdout bytes, then a natural exit 1 without a
    /// stdout eof (the guest service reset the connection).
    Finish(u32, Vec<u8>),
    /// Stream this many stdout frames of these bytes, keeping the channel's
    /// window full: more as the CLI acknowledges (a guest service sending
    /// more than any socket buffer holds).
    Stream(u32, u64, Vec<u8>),
    /// Stop streaming and end with a natural exit 1 without an eof.
    Exit(u32),
    /// A WebSocket ping; its pong proves the CLI read what came before.
    Ping,
}

struct Fake {
    url: String,
    upgrades: Arc<Mutex<usize>>,
    log: Arc<Mutex<Vec<In>>>,
    /// stdout frames sent per channel.
    sent: Arc<Mutex<BTreeMap<u32, u64>>>,
    orders: mpsc::Sender<Cmd>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

#[allow(clippy::result_large_err)] // tungstenite's callback signature
fn accept_subprotocol(_: &Request, mut response: Response) -> Result<Response, ErrorResponse> {
    response
        .headers_mut()
        .insert("Sec-WebSocket-Protocol", wire::SUBPROTOCOL.parse().unwrap());
    Ok(response)
}

/// One relay channel as the fake guest sees it.
#[derive(Default)]
struct Chan {
    out_seq: u64,
    stdin: Vec<u8>,
    done: bool,
    /// stdout frames the CLI acknowledged (its highest seq + 1).
    out_acked: u64,
    /// [`Cmd::Stream`]: frames still to send, and their body.
    stream_left: u64,
    stream_body: Vec<u8>,
}

struct Session {
    ws: WebSocket<TcpStream>,
    script: Script,
    log: Arc<Mutex<Vec<In>>>,
    sent: Arc<Mutex<BTreeMap<u32, u64>>>,
    channels: BTreeMap<u32, Chan>,
    opens: usize,
}

impl Session {
    fn send(&mut self, frame: &ServerControl) {
        let _ = self
            .ws
            .send(Message::text(wire::encode_control(frame).unwrap()));
    }

    fn data(&mut self, channel: u32, seq: u64, body: &[u8]) {
        let frame =
            wire::encode_data(&DataMetadata::new(channel, DataStream::Stdout, seq), body).unwrap();
        let _ = self.ws.send(Message::binary(frame));
        let mut sent = self.sent.lock().unwrap();
        let count = sent.entry(channel).or_default();
        *count = (*count).max(seq + 1);
    }

    /// [`Cmd::Stream`]: fill the channel's output window.
    fn refill(&mut self, channel: u32) {
        let window = self.script.limits.window_frames.exec;
        loop {
            let Some(chan) = self.channels.get_mut(&channel) else {
                return;
            };
            if chan.done || chan.stream_left == 0 || chan.out_seq - chan.out_acked >= window {
                return;
            }
            chan.stream_left -= 1;
            chan.out_seq += 1;
            let (seq, body) = (chan.out_seq - 1, chan.stream_body.clone());
            self.data(channel, seq, &body);
        }
    }

    fn stdout(&mut self, channel: u32, body: &[u8]) {
        for chunk in body.chunks(32 * 1024) {
            let seq = {
                let chan = self.channels.entry(channel).or_default();
                chan.out_seq += 1;
                chan.out_seq - 1
            };
            self.data(channel, seq, chunk);
        }
    }

    fn eof(&mut self, channel: u32) {
        let frames = self.channels.entry(channel).or_default().out_seq;
        self.send(&ServerControl::Eof {
            channel,
            stream: wire::OutputStream::Stdout,
            frames,
        });
    }

    fn exit(&mut self, channel: u32, code: Option<i32>, intent: Option<Intent>) {
        let chan = self.channels.entry(channel).or_default();
        if chan.done {
            return;
        }
        chan.done = true;
        let stdout = chan.out_seq;
        self.send(&ServerControl::Exit {
            channel,
            exit_code: code,
            signal: None,
            intent,
            error: None,
            frames: ExitFrames { stdout, stderr: 0 },
        });
    }

    fn on_frame(&mut self, frame: In) {
        self.log.lock().unwrap().push(frame.clone());
        match frame {
            In::Control(ClientControl::Open { channel, kind, .. }) => {
                assert_eq!(kind, Kind::Tcp);
                self.channels.insert(channel, Chan::default());
                self.opens += 1;
                let rate_limited =
                    (self.opens <= self.script.rate_limit_first).then(|| WireError {
                        code: "rate_limited".into(),
                        message: "channel open rate exceeded for this connection".into(),
                    });
                if let Some(error) = rate_limited.or_else(|| self.script.refuse.clone()) {
                    self.channels.entry(channel).or_default().done = true;
                    self.send(&ServerControl::Exit {
                        channel,
                        exit_code: None,
                        signal: None,
                        intent: None,
                        error: Some(error),
                        frames: ExitFrames {
                            stdout: 0,
                            stderr: 0,
                        },
                    });
                    return;
                }
                if self.script.ready {
                    self.send(&ServerControl::Ready { channel, pty: None });
                    if let Some(greeting) = self.script.greet_and_shut.clone() {
                        self.stdout(channel, &greeting);
                        self.eof(channel);
                    }
                }
            }
            In::Data(metadata, body) => {
                let channel = metadata.channel;
                if !self.script.hold_stdin_acks {
                    self.send(&ServerControl::Ack {
                        channel,
                        stream: StdinStream::Stdin,
                        seq: metadata.seq,
                    });
                }
                if self.script.reset_on_input {
                    self.exit(channel, Some(1), None);
                    return;
                }
                self.channels
                    .entry(channel)
                    .or_default()
                    .stdin
                    .extend_from_slice(&body);
                if self.script.echo && self.script.greet_and_shut.is_none() {
                    self.stdout(channel, &body);
                }
            }
            In::Control(ClientControl::Eof { channel, .. }) => {
                if self.script.echo || self.script.greet_and_shut.is_some() {
                    if self.script.greet_and_shut.is_none() {
                        self.eof(channel);
                    }
                    self.exit(channel, Some(0), None);
                }
            }
            In::Control(ClientControl::Close { channel }) => {
                if self.script.ignore_close {
                    return;
                }
                self.exit(channel, None, Some(Intent::Client));
            }
            In::Control(ClientControl::Ack {
                channel,
                stream: wire::OutputStream::Stdout,
                seq,
            }) => {
                if let Some(chan) = self.channels.get_mut(&channel) {
                    chan.out_acked = chan.out_acked.max(seq + 1);
                }
                self.refill(channel);
            }
            In::Control(_) | In::Pong => {}
        }
    }

    /// Serve until the CLI hangs up (or the test stops the fake).
    fn run(&mut self, orders: &mpsc::Receiver<Cmd>, stop: &AtomicBool) {
        let _ = self
            .ws
            .get_mut()
            .set_read_timeout(Some(Duration::from_millis(10)));
        loop {
            if stop.load(Ordering::SeqCst) {
                return;
            }
            while let Ok(order) = orders.try_recv() {
                match order {
                    Cmd::Send(frame) => self.send(&frame),
                    Cmd::Finish(channel, body) => {
                        self.stdout(channel, &body);
                        self.exit(channel, Some(1), None);
                    }
                    Cmd::Stream(channel, frames, body) => {
                        let chan = self.channels.entry(channel).or_default();
                        chan.stream_left = frames;
                        chan.stream_body = body;
                        self.refill(channel);
                    }
                    Cmd::Exit(channel) => {
                        self.channels.entry(channel).or_default().stream_left = 0;
                        self.exit(channel, Some(1), None);
                    }
                    Cmd::Ping => {
                        let _ = self.ws.send(Message::Ping(b"order".to_vec().into()));
                    }
                    Cmd::End(intent) => {
                        self.send(&ServerControl::End {
                            intent,
                            error: None,
                        });
                        let _ = self.ws.close(Some(tungstenite::protocol::CloseFrame {
                            code: wire::CLOSE_CODE.into(),
                            reason: "end".into(),
                        }));
                    }
                }
            }
            match self.ws.read() {
                Ok(Message::Text(text)) => {
                    let frame = wire::parse_client_control(text.as_str())
                        .unwrap_or_else(|| panic!("invalid client frame {text}"));
                    self.on_frame(In::Control(frame));
                }
                Ok(Message::Binary(bytes)) => {
                    let (metadata, body) = wire::parse_data(&bytes).expect("valid data frame");
                    self.on_frame(In::Data(metadata, body.to_vec()));
                }
                Ok(Message::Close(_)) => return,
                Ok(Message::Pong(_)) => self.on_frame(In::Pong),
                Ok(_) => {}
                Err(tungstenite::Error::Io(error))
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(_) => return,
            }
        }
    }
}

impl Fake {
    fn new(script: Script) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let upgrades = Arc::new(Mutex::new(0));
        let log = Arc::new(Mutex::new(Vec::new()));
        let sent = Arc::new(Mutex::new(BTreeMap::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (orders, orders_rx) = mpsc::channel();
        let (count, seen, done) = (upgrades.clone(), log.clone(), stop.clone());
        let sent_by_session = sent.clone();
        let handle = thread::spawn(move || {
            while !done.load(Ordering::SeqCst) {
                let stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => panic!("accept: {e}"),
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(15)))
                    .unwrap();
                let Ok(ws) = tungstenite::accept_hdr(stream, accept_subprotocol) else {
                    continue;
                };
                *count.lock().unwrap() += 1;
                let mut session = Session {
                    ws,
                    script: script.clone(),
                    log: seen.clone(),
                    sent: sent_by_session.clone(),
                    channels: BTreeMap::new(),
                    opens: 0,
                };
                session.send(&ServerControl::Hello {
                    connection_id: "c1".into(),
                    sandbox_id: "sbx_1".into(),
                    limits: script.limits,
                });
                session.run(&orders_rx, &done);
            }
        });
        Self {
            url,
            upgrades,
            log,
            sent,
            orders,
            stop,
            handle: Some(handle),
        }
    }

    fn log(&self) -> Vec<In> {
        self.log.lock().unwrap().clone()
    }

    fn opens(&self) -> Vec<ClientControl> {
        self.log()
            .into_iter()
            .filter_map(|frame| match frame {
                In::Control(open @ ClientControl::Open { .. }) => Some(open),
                _ => None,
            })
            .collect()
    }

    fn count(&self, want: impl Fn(&In) -> bool) -> usize {
        self.log().iter().filter(|frame| want(frame)).count()
    }

    /// Wait until the log satisfies `want`.
    fn wait(&self, what: &str, want: impl Fn(&[In]) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(15);
        while !want(&self.log()) {
            assert!(
                Instant::now() < deadline,
                "the fake never saw {what}: {:?}",
                self.log()
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn order(&self, cmd: Cmd) {
        self.orders.send(cmd).unwrap();
    }

    /// stdout frames sent on `channel`.
    fn sent(&self, channel: u32) -> u64 {
        self.sent
            .lock()
            .unwrap()
            .get(&channel)
            .copied()
            .unwrap_or(0)
    }

    /// Wait until a [`Cmd::Stream`] on `channel` is held by a local reader
    /// that reads nothing: a full window unacknowledged and no ack for
    /// 500 ms. Returns the frames sent. Holds for any socket buffer smaller
    /// than the stream, however the host tunes it.
    fn wait_stalled(&self, channel: u32) -> u64 {
        let window = limits().window_frames.exec;
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut last = (u64::MAX, None);
        let mut since = Instant::now();
        loop {
            let now = (self.sent(channel), last_ack(&self.log(), channel));
            if now != last {
                last = now;
                since = Instant::now();
            }
            let unacked = now.0 - now.1.map_or(0, |seq| seq + 1);
            if unacked == window && since.elapsed() >= Duration::from_millis(500) {
                return now.0;
            }
            assert!(
                Instant::now() < deadline,
                "the stream never stalled: {now:?}"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// Order a ping and wait for the CLI's pong: everything ordered before
    /// it has been read by the CLI.
    fn sync(&self) {
        let pongs = self.count(|frame| *frame == In::Pong);
        self.order(Cmd::Ping);
        self.wait("the pong", |log| {
            log.iter().filter(|frame| **frame == In::Pong).count() > pongs
        });
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

/// A running forward: its child, its stdout lines and its stderr.
struct Forward {
    child: ManagedChild,
    lines: mpsc::Receiver<String>,
    stderr: thread::JoinHandle<Vec<u8>>,
}

impl Forward {
    fn spawn(root: &Path, fake: &Fake, extra: &[&str]) -> Self {
        let mut args = vec!["sandbox", "forward", "sbx_1"];
        args.extend_from_slice(extra);
        let mut child = ManagedChild::spawn(&mut command(root, &fake.url, &args)).unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sender, lines) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { return };
                if sender.send(line).is_err() {
                    return;
                }
            }
        });
        let mut stderr = child.stderr.take().unwrap();
        let stderr = thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = stderr.read_to_end(&mut bytes);
            bytes
        });
        Self {
            child,
            lines,
            stderr,
        }
    }

    /// The next stdout line.
    fn line(&self) -> String {
        self.lines
            .recv_timeout(Duration::from_secs(15))
            .expect("the forward printed no listening line")
    }

    /// The local address of the next `Forwarding <addr> -> …` line.
    fn address(&self) -> String {
        let line = self.line();
        let rest = line
            .strip_prefix("Forwarding ")
            .unwrap_or_else(|| panic!("unexpected line {line:?}"));
        rest.split(" -> ").next().unwrap().to_owned()
    }

    fn signal(&self, signal: rustix::process::Signal) {
        rustix::process::kill_process(
            rustix::process::Pid::from_raw(self.child.id() as i32).unwrap(),
            signal,
        )
        .unwrap();
    }

    /// Wait for the exit; its code and stderr.
    fn finish(mut self, limit: Duration) -> (Option<i32>, String) {
        let deadline = Instant::now() + limit;
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "the forward did not exit in time"
            );
            thread::sleep(Duration::from_millis(10));
        };
        let stderr = String::from_utf8_lossy(&self.stderr.join().unwrap()).into_owned();
        (status.code(), stderr)
    }
}

fn connect(address: &str) -> TcpStream {
    let stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    stream
}

/// A client with a tiny receive buffer (set before the connect, so the
/// window it advertises stays small): the forward's output queues in the
/// CLI's own send buffer.
fn connect_small_receive_buffer(address: &str) -> TcpStream {
    use rustix::net::{AddressFamily, SocketType, connect, socket, sockopt};
    let address: std::net::SocketAddr = address.parse().unwrap();
    let fd = socket(AddressFamily::INET, SocketType::STREAM, None).unwrap();
    sockopt::set_socket_recv_buffer_size(&fd, 4096).unwrap();
    connect(&fd, &address).unwrap();
    let stream = TcpStream::from(fd);
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    stream
}

/// Read to the end: the bytes and how the stream ended.
fn read_all(stream: &mut impl Read) -> (Vec<u8>, Option<ErrorKind>) {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => return (bytes, None),
            Ok(n) => bytes.extend_from_slice(&buffer[..n]),
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return (bytes, Some(error.kind())),
        }
    }
}

/// Close with a reset (`SO_LINGER` 0): the peer sees RST.
fn reset(stream: TcpStream) {
    rustix::net::sockopt::set_socket_linger(&stream, Some(Duration::ZERO)).unwrap();
    drop(stream);
}

/// Wait up to `limit` for a pending socket error on `stream` (the peer's
/// RST): `Some` once one is pending. Read without consuming data, so it
/// also works after the stream already read a clean EOF.
fn socket_error_within(stream: &TcpStream, limit: Duration) -> Option<rustix::io::Errno> {
    let deadline = Instant::now() + limit;
    loop {
        match rustix::net::sockopt::socket_error(stream).unwrap() {
            Err(errno) => return Some(errno),
            Ok(()) if Instant::now() >= deadline => return None,
            Ok(()) => thread::sleep(Duration::from_millis(5)),
        }
    }
}

/// The highest output `seq` the CLI acknowledged on `channel`.
fn last_ack(log: &[In], channel: u32) -> Option<u64> {
    log.iter()
        .filter_map(|f| match f {
            In::Control(ClientControl::Ack {
                channel: c, seq, ..
            }) if *c == channel => Some(*seq),
            _ => None,
        })
        .max()
}

fn payload(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

#[test]
fn one_connection_round_trips_with_half_close_and_ctrl_c_exits_130() {
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(Script::default());
    let forward = Forward::spawn(root.path(), &fake, &["5432:0"]);
    let address = forward.address();
    assert!(address.starts_with("127.0.0.1:"), "{address}");
    let mut client = connect(&address);
    client.write_all(b"ping").unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let (bytes, end) = read_all(&mut client);
    assert_eq!(bytes, b"ping");
    assert_eq!(end, None, "a clean end both ways is a normal close");
    assert_eq!(
        fake.opens(),
        vec![ClientControl::Open {
            channel: 1,
            kind: Kind::Tcp,
            argv: None,
            login: None,
            cwd: None,
            env: None,
            pty: None,
            port: Some(5432),
            path: None,
        }]
    );
    // The local half-close travelled as the channel's stdin eof.
    assert_eq!(
        fake.count(|f| matches!(f, In::Control(ClientControl::Eof { channel: 1, .. }))),
        1
    );
    forward.signal(rustix::process::Signal::INT);
    let (code, stderr) = forward.finish(Duration::from_secs(10));
    assert_eq!(code, Some(130), "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
}

#[test]
fn many_connections_share_one_websocket_concurrently() {
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(Script::default());
    let forward = Forward::spawn(root.path(), &fake, &["8080:0"]);
    let address = forward.address();
    // Open every connection first, so all are live at the same time.
    let mut clients: Vec<TcpStream> = (0..6).map(|_| connect(&address)).collect();
    fake.wait("six opens", |log| {
        log.iter()
            .filter(|f| matches!(f, In::Control(ClientControl::Open { .. })))
            .count()
            == 6
    });
    let readers: Vec<_> = clients
        .iter_mut()
        .enumerate()
        .map(|(i, client)| {
            let mut reader = client.try_clone().unwrap();
            let body = payload(200_000 + i * 1000, i as u8);
            let mut writer = client.try_clone().unwrap();
            let sent = body.clone();
            let write = thread::spawn(move || {
                writer.write_all(&sent).unwrap();
                writer.shutdown(Shutdown::Write).unwrap();
            });
            let read = thread::spawn(move || read_all(&mut reader));
            (body, write, read)
        })
        .collect();
    for (body, write, read) in readers {
        write.join().unwrap();
        let (bytes, end) = read.join().unwrap();
        assert_eq!(end, None);
        assert!(bytes == body, "a connection's bytes were mixed up or lost");
    }
    assert_eq!(*fake.upgrades.lock().unwrap(), 1, "one WebSocket for all");
    let channels: std::collections::BTreeSet<u32> = fake
        .opens()
        .iter()
        .map(|open| match open {
            ClientControl::Open { channel, .. } => *channel,
            _ => unreachable!(),
        })
        .collect();
    assert_eq!(channels.len(), 6, "one channel per connection");
    forward.signal(rustix::process::Signal::TERM);
    let (code, stderr) = forward.finish(Duration::from_secs(10));
    assert_eq!(code, Some(143), "{stderr}");
}

#[test]
fn a_guest_half_close_keeps_the_local_upload_open() {
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(Script {
        greet_and_shut: Some(b"hello\n".to_vec()),
        ..Script::default()
    });
    let forward = Forward::spawn(root.path(), &fake, &["25:0"]);
    let mut client = connect(&forward.address());
    // The guest service said hello and shut its write side: local EOF.
    let mut greeting = Vec::new();
    let mut reader = client.try_clone().unwrap();
    let (bytes, end) = read_all(&mut reader);
    greeting.extend(bytes);
    assert_eq!(greeting, b"hello\n");
    assert_eq!(end, None);
    // The other direction is still open: more input reaches the guest.
    client.write_all(b"late data").unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    fake.wait("the late upload and its eof", |log| {
        let data: Vec<u8> = log
            .iter()
            .filter_map(|f| match f {
                In::Data(_, body) => Some(body.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        data == b"late data"
            && log
                .iter()
                .any(|f| matches!(f, In::Control(ClientControl::Eof { .. })))
    });
    forward.signal(rustix::process::Signal::INT);
    assert_eq!(forward.finish(Duration::from_secs(10)).0, Some(130));
}

#[test]
fn a_channel_that_ends_without_its_eof_resets_the_local_socket() {
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(Script {
        reset_on_input: true,
        ..Script::default()
    });
    let forward = Forward::spawn(root.path(), &fake, &["6379:0"]);
    let mut client = connect(&forward.address());
    client.write_all(b"PING\r\n").unwrap();
    let (bytes, end) = read_all(&mut client);
    assert!(bytes.is_empty());
    assert_eq!(
        end,
        Some(ErrorKind::ConnectionReset),
        "a reset, not a clean EOF"
    );
    forward.signal(rustix::process::Signal::INT);
    assert_eq!(forward.finish(Duration::from_secs(10)).0, Some(130));
}

#[test]
fn refused_guest_connections_reset_and_log_at_most_once_a_second() {
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(Script {
        refuse: Some(WireError {
            code: "connection_refused".into(),
            message: "nothing in the sandbox accepted the connection".into(),
        }),
        ..Script::default()
    });
    let forward = Forward::spawn(root.path(), &fake, &["5433:0"]);
    let address = forward.address();
    let started = Instant::now();
    for _ in 0..6 {
        let mut client = connect(&address);
        let (bytes, end) = read_all(&mut client);
        assert!(bytes.is_empty());
        assert_eq!(end, Some(ErrorKind::ConnectionReset));
    }
    let elapsed = started.elapsed();
    forward.signal(rustix::process::Signal::INT);
    let (code, stderr) = forward.finish(Duration::from_secs(10));
    assert_eq!(code, Some(130), "{stderr}");
    let refusals = stderr
        .lines()
        .filter(|line| line.contains("sandbox port 5433 refused a connection"))
        .count();
    assert!(refusals >= 1, "{stderr}");
    let bound = 1 + elapsed.as_secs() as usize;
    assert!(
        refusals <= bound,
        "{refusals} lines in {elapsed:?}: {stderr}"
    );
    assert!(stderr.contains("`connection_refused`"), "{stderr}");
}

#[test]
fn ctrl_c_closes_every_channel_and_stops_listening() {
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(Script {
        echo: false,
        ..Script::default()
    });
    let forward = Forward::spawn(root.path(), &fake, &["3000:0"]);
    let address = forward.address();
    let mut clients: Vec<TcpStream> = (0..3).map(|_| connect(&address)).collect();
    fake.wait("three opens", |log| {
        log.iter()
            .filter(|f| matches!(f, In::Control(ClientControl::Open { .. })))
            .count()
            == 3
    });
    // Ready reached the CLI once a first byte travels.
    for client in &mut clients {
        client.write_all(b"x").unwrap();
    }
    fake.wait("three stdin frames", |log| {
        log.iter().filter(|f| matches!(f, In::Data(..))).count() == 3
    });
    forward.signal(rustix::process::Signal::INT);
    let (code, stderr) = forward.finish(Duration::from_secs(10));
    assert_eq!(code, Some(130), "{stderr}");
    for channel in 1..=3 {
        assert_eq!(
            fake.count(|f| *f == In::Control(ClientControl::Close { channel })),
            1,
            "channel {channel} closed once"
        );
    }
    for client in &mut clients {
        let (_, end) = read_all(client);
        assert_eq!(end, Some(ErrorKind::ConnectionReset));
    }
    assert!(TcpStream::connect(&address).is_err(), "no longer listening");
}

#[test]
fn a_revoked_login_resets_every_local_socket_and_exits_125() {
    for json in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let fake = Fake::new(Script::default());
        let mut extra = vec!["9000:0"];
        if json {
            extra.push("--json");
        }
        let forward = Forward::spawn(root.path(), &fake, &extra);
        let address = if json {
            let line: Value = serde_json::from_str(&forward.line()).unwrap();
            assert_eq!(line["guestPort"], 9000);
            line["local"].as_str().unwrap().to_owned()
        } else {
            forward.address()
        };
        let mut a = connect(&address);
        let mut b = connect(&address);
        a.write_all(b"1").unwrap();
        b.write_all(b"2").unwrap();
        let mut one = [0_u8; 1];
        a.read_exact(&mut one).unwrap();
        b.read_exact(&mut one).unwrap();
        fake.order(Cmd::End(Intent::Revoked));
        let (code, stderr) = forward.finish(Duration::from_secs(10));
        assert_eq!(code, Some(125), "{stderr}");
        for client in [&mut a, &mut b] {
            let (_, end) = read_all(client);
            assert_eq!(end, Some(ErrorKind::ConnectionReset));
        }
        assert_eq!(stderr.lines().count(), 1, "{stderr}");
        if json {
            let line: Value = serde_json::from_str(stderr.trim()).unwrap();
            assert_eq!(line["error"]["code"], "connect.revoked");
        } else {
            assert!(stderr.contains("`revoked`"), "{stderr}");
        }
    }
}

#[test]
fn a_slow_local_reader_holds_the_credit_instead_of_buffering() {
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(Script {
        echo: false,
        ..Script::default()
    });
    let path = root.path().join("fwd.sock");
    let forward = Forward::spawn(
        root.path(),
        &fake,
        &["5432", "--unix", path.to_str().unwrap()],
    );
    assert_eq!(forward.address(), path.display().to_string());
    let mut client = UnixStream::connect(&path).unwrap();
    client.write_all(b"go").unwrap();
    fake.wait("the first stdin frame", |log| {
        log.iter().any(|f| matches!(f, In::Data(..)))
    });
    // 32 MiB, more than any socket buffer, which the client does not read:
    // the acks stop with a full window outstanding.
    let frame = payload(32 * 1024, 7);
    let total = 1024;
    fake.order(Cmd::Stream(1, total, frame.clone()));
    let sent = fake.wait_stalled(1);
    assert!(
        sent < total,
        "every frame was delivered while the reader read nothing"
    );
    // The reader catches up: everything arrives and is acknowledged.
    client
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let mut got = vec![0_u8; total as usize * frame.len()];
    client.read_exact(&mut got).unwrap();
    assert!(
        got.chunks(frame.len())
            .all(|chunk| chunk == frame.as_slice())
    );
    fake.wait("the last ack", |log| last_ack(log, 1) == Some(total - 1));
    forward.signal(rustix::process::Signal::INT);
    assert_eq!(forward.finish(Duration::from_secs(10)).0, Some(130));
    assert!(!path.exists(), "the socket file is removed at the end");
}

#[test]
fn the_backlog_beyond_the_channel_cap_is_bounded() {
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(Script {
        limits: Limits {
            max_channels: 1,
            ..limits()
        },
        ready: false,
        ..Script::default()
    });
    let forward = Forward::spawn(root.path(), &fake, &["80:0"]);
    let address = forward.address();
    // One channel, then 32 waiting.
    let mut held: Vec<TcpStream> = Vec::new();
    held.push(connect(&address));
    fake.wait("the first open", |log| {
        log.iter()
            .any(|f| matches!(f, In::Control(ClientControl::Open { .. })))
    });
    for _ in 0..32 {
        held.push(connect(&address));
    }
    // Beyond the backlog: refused at once.
    thread::sleep(Duration::from_millis(300));
    let mut extra = connect(&address);
    let (_, end) = read_all(&mut extra);
    assert_eq!(end, Some(ErrorKind::ConnectionReset));
    assert_eq!(fake.opens().len(), 1, "only the cap's channel opened");
    // The waiting ones are still connected.
    held[32]
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut probe = [0_u8; 1];
    assert!(matches!(
        held[32].read(&mut probe),
        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
    ));
    // The channel ends: the next waiting connection gets it.
    fake.order(Cmd::Send(ServerControl::Exit {
        channel: 1,
        exit_code: None,
        signal: None,
        intent: None,
        error: Some(WireError {
            code: "connection_refused".into(),
            message: "nothing in the sandbox accepted the connection".into(),
        }),
        frames: ExitFrames {
            stdout: 0,
            stderr: 0,
        },
    }));
    fake.wait("the second open", |log| {
        log.iter()
            .filter(|f| matches!(f, In::Control(ClientControl::Open { .. })))
            .count()
            == 2
    });
    forward.signal(rustix::process::Signal::INT);
    let (code, stderr) = forward.finish(Duration::from_secs(10));
    assert_eq!(code, Some(130), "{stderr}");
    assert!(stderr.contains("too many connections waiting"), "{stderr}");
}

#[test]
fn a_node_without_relays_ends_the_forward() {
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(Script {
        refuse: Some(WireError {
            code: "unsupported_capability".into(),
            message: "the sandbox's node cannot open tcp channels; update its daemon".into(),
        }),
        ..Script::default()
    });
    let forward = Forward::spawn(root.path(), &fake, &["22:0"]);
    let mut client = connect(&forward.address());
    let (_, end) = read_all(&mut client);
    assert_eq!(end, Some(ErrorKind::ConnectionReset));
    let (code, stderr) = forward.finish(Duration::from_secs(10));
    assert_eq!(code, Some(125), "{stderr}");
    assert!(stderr.contains("cannot forward ports"), "{stderr}");
    assert!(stderr.contains("update its daemon"), "{stderr}");
}

#[test]
fn a_non_loopback_address_warns() {
    let root = tempfile::tempdir().unwrap();
    // No upgrade happens: the warning comes with the bind.
    let mut cmd = command(
        root.path(),
        "http://127.0.0.1:9",
        &["sandbox", "forward", "sbx_1", "1:0", "--address", "0.0.0.0"],
    );
    let output = ManagedChild::spawn(&mut cmd)
        .unwrap()
        .wait_with_output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("anyone who can reach that address"),
        "{stderr}"
    );
}

#[test]
fn usage_errors_need_no_network() {
    let root = tempfile::tempdir().unwrap();
    let sock = root.path().join("x.sock");
    let sock = sock.to_str().unwrap();
    for args in [
        vec!["sandbox", "forward", "sbx_1", "0"],
        vec!["sandbox", "forward", "sbx_1", "65536"],
        vec!["sandbox", "forward", "sbx_1", "80:x"],
        vec!["sandbox", "forward", "sbx_1"],
        vec!["sandbox", "forward", "sbx_1", "80", "81", "--unix", sock],
        vec!["sandbox", "forward", "sbx_1", "80:8080", "--unix", sock],
        vec![
            "sandbox",
            "forward",
            "sbx_1",
            "80",
            "--unix",
            sock,
            "--address",
            "127.0.0.1",
        ],
        vec![
            "sandbox",
            "forward",
            "sbx_1",
            "80",
            "--address",
            "localhost",
        ],
        vec!["sandbox", "forward", "../x", "80"],
    ] {
        let output = ManagedChild::spawn(&mut command(root.path(), "http://127.0.0.1:9", &args))
            .unwrap()
            .wait_with_output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert!(!Path::new(sock).exists());
}

#[test]
fn local_resets_racing_a_natural_end_never_consume_channel_slots() {
    // Review round 1: DATA and a natural exit arrive while (or after) the
    // local client resets. The exit was held for output that can no longer
    // be delivered and the server ignores the close, so without a discard
    // every such connection kept its slot; 32 of them stopped the forward.
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(Script {
        ignore_close: true,
        ..Script::default()
    });
    let forward = Forward::spawn(root.path(), &fake, &["7000:0"]);
    let address = forward.address();
    for channel in 1..=40_u32 {
        let client = connect(&address);
        fake.wait("the open", |log| {
            log.iter().any(|f| {
                matches!(f, In::Control(ClientControl::Open { channel: c, .. }) if *c == channel)
            })
        });
        reset(client);
        // Two output frames, then the natural exit (no eof: a reset).
        fake.order(Cmd::Finish(channel, payload(40_000, channel as u8)));
        // The discarded frames are still acknowledged (no 60 s stall).
        fake.wait("the ack of the discarded output", |log| {
            last_ack(log, channel) == Some(1)
        });
    }
    // Every slot came back: a further connection still round-trips.
    let mut client = connect(&address);
    client.write_all(b"still here").unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let (bytes, end) = read_all(&mut client);
    assert_eq!(bytes, b"still here");
    assert_eq!(end, None);
    assert_eq!(fake.opens().len(), 41);
    forward.signal(rustix::process::Signal::INT);
    let (code, stderr) = forward.finish(Duration::from_secs(10));
    assert_eq!(code, Some(130), "{stderr}");
}

#[test]
fn ctrl_c_releases_an_exit_held_for_output_the_local_side_never_read() {
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(Script {
        echo: false,
        ignore_close: true,
        ..Script::default()
    });
    let path = root.path().join("fwd.sock");
    let forward = Forward::spawn(
        root.path(),
        &fake,
        &["5432", "--unix", path.to_str().unwrap()],
    );
    assert_eq!(forward.address(), path.display().to_string());
    let client = UnixStream::connect(&path).unwrap();
    (&client).write_all(b"go").unwrap();
    fake.wait("the first stdin frame", |log| {
        log.iter().any(|f| matches!(f, In::Data(..)))
    });
    // Output the local client never reads, then the natural exit: the exit
    // is held for a window of frames still waiting for the local socket.
    fake.order(Cmd::Stream(1, 1024, payload(32 * 1024, 3)));
    let sent = fake.wait_stalled(1);
    fake.order(Cmd::Exit(1));
    fake.sync();
    forward.signal(rustix::process::Signal::INT);
    let (code, stderr) = forward.finish(Duration::from_secs(10));
    assert_eq!(code, Some(130), "{stderr}");
    // The teardown discarded and acknowledged the rest, which released the
    // exit: the server had ended the channel, so no close was sent for it.
    assert_eq!(last_ack(&fake.log(), 1), Some(sent - 1));
    assert_eq!(
        fake.count(|f| matches!(f, In::Control(ClientControl::Close { channel: 1 }))),
        0,
        "a close for a channel whose exit had come"
    );
    drop(client);
}

#[test]
fn a_local_reset_while_an_exit_waits_for_unread_output_frees_the_slot() {
    // The exit is already held when the local write fails (the abort must
    // release it); one channel slot, so the next connection proves it.
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(Script {
        limits: Limits {
            max_channels: 1,
            ..limits()
        },
        echo: false,
        ignore_close: true,
        ..Script::default()
    });
    let path = root.path().join("fwd.sock");
    let forward = Forward::spawn(
        root.path(),
        &fake,
        &["5432", "--unix", path.to_str().unwrap()],
    );
    assert_eq!(forward.address(), path.display().to_string());
    let mut first = UnixStream::connect(&path).unwrap();
    first.write_all(b"go").unwrap();
    fake.wait("the first stdin frame", |log| {
        log.iter().any(|f| matches!(f, In::Data(..)))
    });
    fake.order(Cmd::Stream(1, 1024, payload(32 * 1024, 5)));
    let sent = fake.wait_stalled(1);
    fake.order(Cmd::Exit(1));
    fake.sync();
    let second = UnixStream::connect(&path).unwrap();
    drop(first);
    fake.wait("the second connection's open", |log| {
        log.iter()
            .filter(|f| matches!(f, In::Control(ClientControl::Open { .. })))
            .count()
            == 2
    });
    assert_eq!(last_ack(&fake.log(), 1), Some(sent - 1));
    forward.signal(rustix::process::Signal::INT);
    assert_eq!(forward.finish(Duration::from_secs(10)).0, Some(130));
    drop(second);
}

#[test]
fn a_local_reset_with_the_stdin_credit_exhausted_frees_the_slot() {
    // The guest service reads nothing (no stdin acks) and sends nothing: the
    // CLI stops reading the local socket once its credit is gone, so only a
    // check independent of reads can see the client's RST.
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(Script {
        limits: Limits {
            max_channels: 1,
            ..limits()
        },
        echo: false,
        hold_stdin_acks: true,
        ..Script::default()
    });
    let forward = Forward::spawn(root.path(), &fake, &["5432:0"]);
    let address = forward.address();
    let mut first = connect(&address);
    first
        .set_write_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let chunk = payload(64 * 1024, 9);
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(5) {
        if first.write(&chunk).is_err() {
            break;
        }
    }
    let window = limits().window_frames.exec as usize;
    let stdin_frames = |log: &[In]| log.iter().filter(|f| matches!(f, In::Data(..))).count();
    fake.wait("a full stdin window", |log| stdin_frames(log) >= window);
    thread::sleep(Duration::from_millis(300));
    assert_eq!(
        stdin_frames(&fake.log()),
        window,
        "the credit is exhausted, nothing more is read"
    );
    reset(first);
    fake.wait("the close of the reset connection", |log| {
        log.iter()
            .any(|f| matches!(f, In::Control(ClientControl::Close { channel: 1 })))
    });
    // The slot came back: a second connection gets its channel.
    let mut second = connect(&address);
    second.write_all(b"next").unwrap();
    fake.wait("the second connection's open", |log| {
        log.iter()
            .filter(|f| matches!(f, In::Control(ClientControl::Open { .. })))
            .count()
            == 2
    });
    forward.signal(rustix::process::Signal::INT);
    assert_eq!(forward.finish(Duration::from_secs(10)).0, Some(130));
}

#[test]
fn a_local_reset_after_a_local_half_close_frees_the_slot() {
    // After the local EOF nothing is read any more and no output is due:
    // the RST that follows must still close the channel.
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(Script {
        limits: Limits {
            max_channels: 1,
            ..limits()
        },
        echo: false,
        ..Script::default()
    });
    let forward = Forward::spawn(root.path(), &fake, &["5432:0"]);
    let address = forward.address();
    let first = connect(&address);
    first.shutdown(Shutdown::Write).unwrap();
    fake.wait("the stdin eof", |log| {
        log.iter()
            .any(|f| matches!(f, In::Control(ClientControl::Eof { channel: 1, .. })))
    });
    thread::sleep(Duration::from_millis(200));
    assert_eq!(
        fake.count(|f| matches!(f, In::Control(ClientControl::Close { .. }))),
        0,
        "a half-close is not a reset"
    );
    reset(first);
    fake.wait("the close of the reset connection", |log| {
        log.iter()
            .any(|f| matches!(f, In::Control(ClientControl::Close { channel: 1 })))
    });
    let _second = connect(&address);
    fake.wait("the second connection's open", |log| {
        log.iter()
            .filter(|f| matches!(f, In::Control(ClientControl::Open { .. })))
            .count()
            == 2
    });
    forward.signal(rustix::process::Signal::INT);
    assert_eq!(forward.finish(Duration::from_secs(10)).0, Some(130));
}

#[test]
fn a_guest_reset_after_its_half_close_resets_the_local_socket() {
    // The guest service greets, shuts its write side, then resets on the
    // next upload (exit 1 after the stdout eof): the local socket, which
    // already read a clean EOF, is reset, not closed normally.
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(Script {
        greet_and_shut: Some(b"220 ready\r\n".to_vec()),
        reset_on_input: true,
        ..Script::default()
    });
    let forward = Forward::spawn(root.path(), &fake, &["25:0"]);
    let mut client = connect(&forward.address());
    let (greeting, end) = read_all(&mut client);
    assert_eq!((greeting.as_slice(), end), (&b"220 ready\r\n"[..], None));
    assert_eq!(
        socket_error_within(&client, Duration::from_millis(200)),
        None
    );
    client.write_all(b"MAIL FROM:<a@b>\r\n").unwrap();
    let error = socket_error_within(&client, Duration::from_secs(10));
    assert!(
        matches!(
            error,
            Some(rustix::io::Errno::CONNRESET | rustix::io::Errno::PIPE)
        ),
        "the failed upload is a reset: {error:?}"
    );
    forward.signal(rustix::process::Signal::INT);
    assert_eq!(forward.finish(Duration::from_secs(10)).0, Some(130));
}

#[test]
fn a_clean_relay_end_closes_the_local_socket_without_a_reset() {
    // The contrast: exit 0 after the stdout eof is the one clean end. The
    // client's tiny receive buffer keeps most of a 1 MiB reply in the CLI's
    // send queue when the channel ends, where a reset (`SO_LINGER` 0) would
    // discard it: only a normal close delivers every byte, then the EOF.
    let root = tempfile::tempdir().unwrap();
    let reply = payload(1024 * 1024, 11);
    let fake = Fake::new(Script {
        greet_and_shut: Some(reply.clone()),
        ..Script::default()
    });
    let forward = Forward::spawn(root.path(), &fake, &["5432:0"]);
    let mut client = connect_small_receive_buffer(&forward.address());
    client.shutdown(Shutdown::Write).unwrap();
    // A slow reader: the channel's exit (released once every frame was
    // handed to the local socket) comes while much is still queued.
    let mut got = Vec::new();
    let mut buffer = [0_u8; 4096];
    let end = loop {
        match client.read(&mut buffer) {
            Ok(0) => break None,
            Ok(n) => {
                got.extend_from_slice(&buffer[..n]);
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => break Some(error.kind()),
        }
    };
    assert_eq!(end, None, "a clean end is a FIN, never an RST");
    assert_eq!(got.len(), reply.len());
    assert!(got == reply, "every byte, in order");
    assert_eq!(
        socket_error_within(&client, Duration::from_millis(200)),
        None
    );
    fake.wait("the ack of every frame", |log| last_ack(log, 1) == Some(31));
    forward.signal(rustix::process::Signal::INT);
    assert_eq!(forward.finish(Duration::from_secs(10)).0, Some(130));
}

/// Bytes of stdin the fake received on `channel`, and its highest seq.
fn stdin_of(log: &[In], channel: u32) -> (usize, Option<u64>) {
    log.iter()
        .fold((0, None), |(bytes, seq), frame| match frame {
            In::Data(metadata, body) if metadata.channel == channel => {
                (bytes + body.len(), Some(metadata.seq))
            }
            _ => (bytes, seq),
        })
}

#[test]
fn stalled_uploads_never_starve_a_later_connection() {
    // Review round 3 and audit M1: four uploads whose guest services read
    // nothing fill the connection's 4 MiB stdin budget. A fifth connection
    // still sends its first frame at once (every channel slot keeps one
    // frame of the budget), and credit returned a little at a time to the
    // uploaders reaches it too (the input cursor rotates), so its whole
    // request arrives while the uploads go on.
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(Script {
        echo: false,
        hold_stdin_acks: true,
        ..Script::default()
    });
    let forward = Forward::spawn(root.path(), &fake, &["5432:0"]);
    let address = forward.address();
    let mut uploaders = Vec::new();
    for _ in 0..4 {
        let client = connect(&address);
        let mut writer = client.try_clone().unwrap();
        writer
            .set_write_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        thread::spawn(move || {
            let chunk = payload(64 * 1024, 1);
            while writer.write_all(&chunk).is_ok() {}
        });
        uploaders.push(client);
    }
    let total = |log: &[In]| -> usize { (1..=4).map(|channel| stdin_of(log, channel).0).sum() };
    // 128 frames of budget, 32 reserved for the slots: at most 100 frames.
    fake.wait("the uploads to fill the budget", |log| {
        total(log) >= 96 * 32 * 1024
    });
    thread::sleep(Duration::from_millis(200));
    let held = total(&fake.log());
    assert!(held <= 4 * 1024 * 1024, "{held}");
    let request = payload(8 * 32 * 1024, 5);
    let mut late = connect(&address);
    late.write_all(&request).unwrap();
    late.shutdown(Shutdown::Write).unwrap();
    fake.wait("the fifth connection's first frame", |log| {
        stdin_of(log, 5).0 > 0
    });
    // Credit back to one uploader at a time, four frames per step.
    let mut acked = [0_u64; 5];
    let mut steps = 0;
    loop {
        let log = fake.log();
        if stdin_of(&log, 5).0 == request.len()
            && log
                .iter()
                .any(|f| matches!(f, In::Control(ClientControl::Eof { channel: 5, .. })))
        {
            break;
        }
        steps += 1;
        assert!(
            steps < 400,
            "the fifth connection starved: {} of {} bytes",
            stdin_of(&log, 5).0,
            request.len()
        );
        let channel = 1 + (steps % 4) as u32;
        if let (_, Some(seq)) = stdin_of(&log, channel) {
            let next = (acked[channel as usize] + 4).min(seq + 1);
            if next > acked[channel as usize] {
                acked[channel as usize] = next;
                fake.order(Cmd::Send(ServerControl::Ack {
                    channel,
                    stream: StdinStream::Stdin,
                    seq: next - 1,
                }));
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert!(total(&fake.log()) > held, "the uploads went on too");
    forward.signal(rustix::process::Signal::INT);
    assert_eq!(forward.finish(Duration::from_secs(10)).0, Some(130));
    drop(uploaders);
}

#[test]
fn a_local_eof_travels_without_stdin_credit() {
    // A one-frame stdin window the guest never acknowledges: after the
    // request the channel has no credit, and the local half-close must
    // still reach the guest (an eof costs no credit).
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(Script {
        limits: Limits {
            window_frames: PerKind { pty: 8, exec: 1 },
            ..limits()
        },
        echo: false,
        hold_stdin_acks: true,
        ..Script::default()
    });
    let forward = Forward::spawn(root.path(), &fake, &["5432:0"]);
    let client = connect(&forward.address());
    (&client).write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    fake.wait("the request", |log| stdin_of(log, 1).0 > 0);
    client.shutdown(Shutdown::Write).unwrap();
    fake.wait("the stdin eof", |log| {
        log.iter()
            .any(|f| matches!(f, In::Control(ClientControl::Eof { channel: 1, .. })))
    });
    assert_eq!(stdin_of(&fake.log(), 1).0, 18, "the eof after every byte");
    forward.signal(rustix::process::Signal::INT);
    assert_eq!(forward.finish(Duration::from_secs(10)).0, Some(130));
}

#[test]
fn ctrl_c_while_connecting_leaves_no_unix_socket_behind() {
    // A server that accepts the TCP connection and never answers the
    // upgrade: the forward is still dialling when the signal comes.
    let root = tempfile::tempdir().unwrap();
    let silent = TcpListener::bind("127.0.0.1:0").unwrap();
    let server = format!("http://{}", silent.local_addr().unwrap());
    let dir = root.path().join("sockets");
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("fwd.sock");
    let mut child = ManagedChild::spawn(&mut command(
        root.path(),
        &server,
        &[
            "sandbox",
            "forward",
            "sbx_1",
            "5432",
            "--unix",
            path.to_str().unwrap(),
        ],
    ))
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    while !path.exists() {
        assert!(Instant::now() < deadline, "the listener was never bound");
        thread::sleep(Duration::from_millis(5));
    }
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(child.id() as i32).unwrap(),
        rustix::process::Signal::INT,
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "the forward did not exit");
        thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(status.code(), Some(130));
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        0,
        "neither the socket nor a staging directory is left"
    );
    drop(silent);
}

#[test]
fn a_rate_limited_open_waits_and_is_retried_once() {
    // The client's and the server's open-rate windows can disagree at the
    // limit: one `rate_limited` refusal re-queues the connection.
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(Script {
        rate_limit_first: 1,
        ..Script::default()
    });
    let forward = Forward::spawn(root.path(), &fake, &["5432:0"]);
    let address = forward.address();
    let mut client = connect(&address);
    client.write_all(b"ping").unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let (bytes, end) = read_all(&mut client);
    assert_eq!((bytes.as_slice(), end), (&b"ping"[..], None));
    assert_eq!(fake.opens().len(), 2);
    forward.signal(rustix::process::Signal::INT);
    let (code, stderr) = forward.finish(Duration::from_secs(10));
    assert_eq!(code, Some(130), "{stderr}");
    assert!(stderr.is_empty(), "a retried open is no refusal: {stderr}");

    // Refused twice: the second refusal resets it.
    let fake = Fake::new(Script {
        rate_limit_first: 2,
        ..Script::default()
    });
    let forward = Forward::spawn(root.path(), &fake, &["5432:0"]);
    let mut client = connect(&forward.address());
    let (_, end) = read_all(&mut client);
    assert_eq!(end, Some(ErrorKind::ConnectionReset));
    assert_eq!(fake.opens().len(), 2);
    forward.signal(rustix::process::Signal::INT);
    let (code, stderr) = forward.finish(Duration::from_secs(10));
    assert_eq!(code, Some(130), "{stderr}");
    assert!(stderr.contains("`rate_limited`"), "{stderr}");
}

#[test]
fn a_waiting_connection_that_resets_never_costs_an_open() {
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(Script {
        limits: Limits {
            max_channels: 1,
            ..limits()
        },
        ready: false,
        echo: false,
        ..Script::default()
    });
    let forward = Forward::spawn(root.path(), &fake, &["80:0"]);
    let address = forward.address();
    let _first = connect(&address);
    fake.wait("the first open", |log| {
        log.iter()
            .any(|f| matches!(f, In::Control(ClientControl::Open { .. })))
    });
    // Two wait for the slot; the first of them resets while waiting.
    let gone = connect(&address);
    thread::sleep(Duration::from_millis(100));
    let live = connect(&address);
    thread::sleep(Duration::from_millis(100));
    reset(gone);
    thread::sleep(Duration::from_millis(200));
    // The slot comes back: the live one gets channel 2.
    fake.order(Cmd::Send(ServerControl::Exit {
        channel: 1,
        exit_code: None,
        signal: None,
        intent: None,
        error: Some(WireError {
            code: "connection_refused".into(),
            message: "nothing in the sandbox accepted the connection".into(),
        }),
        frames: ExitFrames {
            stdout: 0,
            stderr: 0,
        },
    }));
    fake.wait("the second open", |log| {
        log.iter()
            .any(|f| matches!(f, In::Control(ClientControl::Open { channel: 2, .. })))
    });
    fake.order(Cmd::Send(ServerControl::Ready {
        channel: 2,
        pty: None,
    }));
    (&live).write_all(b"x").unwrap();
    fake.wait("the live connection's byte", |log| stdin_of(log, 2).0 == 1);
    assert_eq!(fake.opens().len(), 2, "no open for the reset one");
    assert_eq!(
        fake.count(|f| matches!(f, In::Control(ClientControl::Close { .. }))),
        0
    );
    forward.signal(rustix::process::Signal::INT);
    assert_eq!(forward.finish(Duration::from_secs(10)).0, Some(130));
}

#[test]
fn a_failure_after_ready_is_not_logged_as_a_refusal() {
    let root = tempfile::tempdir().unwrap();
    let fake = Fake::new(Script {
        echo: false,
        ..Script::default()
    });
    let forward = Forward::spawn(root.path(), &fake, &["6000:0"]);
    let mut client = connect(&forward.address());
    client.write_all(b"x").unwrap();
    fake.wait("the first stdin frame", |log| stdin_of(log, 1).0 == 1);
    fake.order(Cmd::Send(ServerControl::Exit {
        channel: 1,
        exit_code: None,
        signal: None,
        intent: None,
        error: Some(WireError {
            code: "internal".into(),
            message: "channel relay failed".into(),
        }),
        frames: ExitFrames {
            stdout: 0,
            stderr: 0,
        },
    }));
    let (_, end) = read_all(&mut client);
    assert_eq!(end, Some(ErrorKind::ConnectionReset));
    forward.signal(rustix::process::Signal::INT);
    let (code, stderr) = forward.finish(Duration::from_secs(10));
    assert_eq!(code, Some(130), "{stderr}");
    assert!(
        stderr.contains("a connection to sandbox port 6000 failed (`internal`"),
        "{stderr}"
    );
    assert!(!stderr.contains("refused"), "{stderr}");
}
