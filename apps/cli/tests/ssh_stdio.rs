//! `wssp ssh --stdio` and `wssp ssh-config` against the real OpenSSH client
//! (`ssh`, `scp`, `sftp`, `rsync`) and an in-process fake of the connect
//! plane (`wssp.connect.v1`) that runs each channel as a local process or
//! a local socket, the way a node runs it in the guest: `exec` and `pty`
//! channels run their argv (or `/bin/sh` for a shell) with `SHELL=/bin/sh`
//! in a scratch "guest home", with real stdin credit (a frame is
//! acknowledged once written to the process) and the client's output credit
//! honoured (like a node, it reads a process's or socket's output only while
//! the channel has credit, so a client that does not acknowledge output
//! stops the guest's writes); `tcp` and `unix` channels connect to local
//! listeners.
//!
//! Every test skips (printing why) when a client tool it needs is missing,
//! unless `WSSP_REQUIRE_SSH_TOOLS=1` (set in CI), where it fails.
#![cfg(all(target_os = "linux", feature = "ssh"))]

use std::collections::{BTreeMap, VecDeque};
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tungstenite::{Message, WebSocket};
use wssp::connect_client::wire::{
    self, ClientControl, DataMetadata, DataStream, ExitFrames, Intent, Kind, Limits, OutputStream,
    PerKind, ServerControl, StdinStream, WireError,
};

#[path = "../../../crates/sandbox-runtime/tests/support/managed_child.rs"]
mod managed_child;
use managed_child::ManagedChild;

#[path = "support/latency.rs"]
mod latency;

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

fn have(program: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {program}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn tools_required() -> bool {
    std::env::var_os("WSSP_REQUIRE_SSH_TOOLS").is_some_and(|value| value == "1")
}

/// Skip (with a line saying why) when a client tool is missing; fail
/// instead under `WSSP_REQUIRE_SSH_TOOLS=1`.
macro_rules! require {
    ($($program:expr),+) => {
        for program in [$($program),+] {
            if !have(program) {
                assert!(
                    !tools_required(),
                    "`{program}` is required (WSSP_REQUIRE_SSH_TOOLS=1)"
                );
                eprintln!("skipped: `{program}` is not installed");
                return;
            }
        }
    };
}

// ------------------------------------------------------------ the fake

/// Shared switches of the fake.
#[derive(Default)]
struct Knobs {
    /// Hold stdin: neither write it to the process nor acknowledge it.
    hold_stdin: AtomicBool,
    /// Hold only the stdin of `tcp` channels to this guest port (0: none).
    hold_port: std::sync::atomic::AtomicU16,
    /// stdin frames held so far, and their bytes.
    held_frames: AtomicUsize,
    held_bytes: AtomicUsize,
    /// Channels whose output waits for the client's acks (a full window).
    out_full: AtomicUsize,
    /// Close the `tcp` channels to this guest port with `backpressure`
    /// (0: none), as a server does with a client that stopped acking.
    close_port: std::sync::atomic::AtomicU16,
    /// Answer opens this much later (ms).
    ready_delay_ms: std::sync::atomic::AtomicU64,
    /// Report a process's exit this much after it exited (ms), so its eofs
    /// reach the client first.
    exit_delay_ms: std::sync::atomic::AtomicU64,
}

impl Knobs {
    fn holds(&self, port: Option<u16>) -> bool {
        self.hold_stdin.load(Ordering::SeqCst)
            || port.is_some_and(|port| self.hold_port.load(Ordering::SeqCst) == port)
    }
}

enum Ev {
    Out(u32, OutputStream, Vec<u8>),
    OutEof(u32, OutputStream),
    Exited(u32, Option<i32>, Option<u8>),
    Written(u32, u64),
}

enum StdinMsg {
    Data(u64, Vec<u8>),
    Eof,
}

enum Queued {
    Data(OutputStream, Vec<u8>),
    Eof(OutputStream),
}

struct GuestChan {
    kind: Kind,
    stdin: Option<mpsc::Sender<StdinMsg>>,
    /// The process group to signal (process channels).
    pid: Option<u32>,
    queue: VecDeque<Queued>,
    sent: [u64; 2],
    acked: [u64; 2],
    /// Output streams still open.
    open_streams: usize,
    exited: Option<(Option<i32>, Option<u8>)>,
    /// A relay's stdin eof arrived.
    input_closed: bool,
    held: Vec<(u64, Vec<u8>)>,
    /// The guest port of a `tcp` channel.
    port: Option<u16>,
    credit: Arc<OutCredit>,
    done: bool,
}

/// What the CLI sent (control frames only).
type Log = Arc<Mutex<Vec<ClientControl>>>;

struct Session {
    ws: WebSocket<TcpStream>,
    guest: PathBuf,
    knobs: Arc<Knobs>,
    log: Log,
    events: mpsc::Sender<Ev>,
    channels: BTreeMap<u32, GuestChan>,
}

fn data_max(kind: Kind) -> usize {
    if kind == Kind::Pty { 16384 } else { 32768 }
}

fn window(kind: Kind) -> u64 {
    if kind == Kind::Pty { 8 } else { 32 }
}

/// The output frames a channel read from its guest and the client has not
/// acknowledged yet: at most one window, so the guest's writes block beyond.
#[derive(Default)]
struct OutCredit {
    /// (outstanding frames, channel done)
    state: Mutex<(u64, bool)>,
    changed: std::sync::Condvar,
}

impl OutCredit {
    /// Wait for room for one more frame; `false` once the channel is done.
    fn take(&self, window: u64) -> bool {
        let mut state = self.state.lock().unwrap();
        while state.0 >= window && !state.1 {
            state = self.changed.wait(state).unwrap();
        }
        state.0 += 1;
        !state.1
    }

    fn give(&self, frames: u64) {
        let mut state = self.state.lock().unwrap();
        state.0 = state.0.saturating_sub(frames);
        self.changed.notify_all();
    }

    fn finish(&self) {
        self.state.lock().unwrap().1 = true;
        self.changed.notify_all();
    }
}

/// Read `reader` in frame-sized chunks onto the session's events, within
/// the channel's output credit.
fn pump_out(
    mut reader: impl Read + Send + 'static,
    channel: u32,
    stream: OutputStream,
    kind: Kind,
    credit: Arc<OutCredit>,
    events: mpsc::Sender<Ev>,
) {
    thread::spawn(move || {
        let mut buffer = vec![0_u8; data_max(kind)];
        loop {
            if !credit.take(window(kind)) {
                return;
            }
            match reader.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if events
                        .send(Ev::Out(channel, stream, buffer[..n].to_vec()))
                        .is_err()
                    {
                        return;
                    }
                }
            }
        }
        let _ = events.send(Ev::OutEof(channel, stream));
    });
}

/// Write stdin frames in order and report each one written.
fn pump_in(
    mut writer: impl Write + Send + 'static,
    channel: u32,
    events: mpsc::Sender<Ev>,
    shutdown: impl FnOnce(&mut dyn Write) + Send + 'static,
) -> mpsc::Sender<StdinMsg> {
    let (sender, receiver) = mpsc::channel::<StdinMsg>();
    thread::spawn(move || {
        for message in receiver {
            match message {
                StdinMsg::Data(seq, bytes) => {
                    if writer
                        .write_all(&bytes)
                        .and_then(|()| writer.flush())
                        .is_err()
                    {
                        // A closed pipe still consumes (as a node would drop).
                    }
                    if events.send(Ev::Written(channel, seq)).is_err() {
                        return;
                    }
                }
                StdinMsg::Eof => {
                    shutdown(&mut writer);
                    return;
                }
            }
        }
    });
    sender
}

impl Session {
    fn send(&mut self, frame: &ServerControl) {
        let _ = self
            .ws
            .send(Message::text(wire::encode_control(frame).unwrap()));
    }

    fn refuse(&mut self, channel: u32, code: &str) {
        self.send(&ServerControl::Exit {
            channel,
            exit_code: None,
            signal: None,
            intent: None,
            error: Some(WireError {
                code: code.into(),
                message: format!("fake refused: {code}"),
            }),
            frames: ExitFrames {
                stdout: 0,
                stderr: 0,
            },
        });
    }

    fn open(&mut self, frame: &ClientControl) {
        let ClientControl::Open {
            channel,
            kind,
            argv,
            login,
            env,
            pty,
            port,
            path,
            ..
        } = frame.clone()
        else {
            return;
        };
        let events = self.events.clone();
        let mut chan = GuestChan {
            kind,
            stdin: None,
            pid: None,
            queue: VecDeque::new(),
            sent: [0; 2],
            acked: [0; 2],
            open_streams: 2,
            exited: None,
            input_closed: false,
            held: Vec::new(),
            port: if kind == Kind::Tcp { port } else { None },
            credit: Arc::new(OutCredit::default()),
            done: false,
        };
        match kind {
            Kind::Pty | Kind::Exec => {
                // A guest process starts with every signal at its default,
                // as in a fresh VM: the test process may have inherited
                // ignored ones (a background job of a non-interactive
                // shell ignores SIGINT and SIGQUIT, `nohup` SIGHUP), and
                // an ignored disposition survives `exec`, so a forwarded
                // signal would not end the guest command. `env
                // --default-signal` resets them without `unsafe`.
                let mut command = Command::new("env");
                command.arg("--default-signal");
                match &argv {
                    Some(argv) => {
                        command.args(argv);
                    }
                    None => {
                        command.arg("/bin/sh");
                        if login == Some(true) {
                            command.arg("-l");
                        }
                    }
                }
                command
                    .current_dir(&self.guest)
                    .env_clear()
                    .env("PATH", std::env::var_os("PATH").unwrap_or_default())
                    .env("HOME", &self.guest)
                    .env("SHELL", "/bin/sh")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                if let Some(pty) = &pty {
                    command.env("TERM", &pty.term);
                }
                for (name, value) in env.unwrap_or_default() {
                    command.env(name, value);
                }
                let mut child = match ManagedChild::spawn(&mut command) {
                    Ok(child) => child,
                    Err(_) => {
                        self.refuse(channel, "guest_operation_failed");
                        return;
                    }
                };
                chan.pid = Some(child.id());
                // A pty has one output stream: stderr joins stdout.
                let err_stream = if kind == Kind::Pty {
                    OutputStream::Stdout
                } else {
                    OutputStream::Stderr
                };
                pump_out(
                    child.stdout.take().unwrap(),
                    channel,
                    OutputStream::Stdout,
                    kind,
                    chan.credit.clone(),
                    events.clone(),
                );
                pump_out(
                    child.stderr.take().unwrap(),
                    channel,
                    err_stream,
                    kind,
                    chan.credit.clone(),
                    events.clone(),
                );
                let stdin = child.stdin.take().unwrap();
                chan.stdin = Some(pump_in(stdin, channel, events.clone(), |_| {}));
                let waiter = events.clone();
                let exit_delay = self.knobs.exit_delay_ms.load(Ordering::SeqCst);
                thread::spawn(move || {
                    use std::os::unix::process::ExitStatusExt;
                    let status = child.wait().unwrap();
                    thread::sleep(Duration::from_millis(exit_delay));
                    let signal = status.signal().map(|s| s as u8);
                    let _ = waiter.send(Ev::Exited(channel, status.code(), signal));
                    drop(child);
                });
            }
            Kind::Tcp | Kind::Unix => {
                let (reader, writer): (Box<dyn Read + Send>, Box<dyn Write + Send>) =
                    match (port, path) {
                        (Some(port), None) => match TcpStream::connect(("127.0.0.1", port)) {
                            Ok(stream) => (
                                Box::new(stream.try_clone().unwrap()),
                                Box::new(TcpHalf(stream)),
                            ),
                            Err(_) => {
                                self.refuse(channel, "connection_refused");
                                return;
                            }
                        },
                        (None, Some(path)) => match UnixStream::connect(&path) {
                            Ok(stream) => (
                                Box::new(stream.try_clone().unwrap()),
                                Box::new(UnixHalf(stream)),
                            ),
                            Err(_) => {
                                self.refuse(channel, "connection_refused");
                                return;
                            }
                        },
                        _ => panic!("relay open without its target"),
                    };
                chan.open_streams = 1;
                pump_out(
                    reader,
                    channel,
                    OutputStream::Stdout,
                    kind,
                    chan.credit.clone(),
                    events.clone(),
                );
                chan.stdin = Some(pump_in(writer, channel, events, |writer| {
                    writer.flush().ok();
                    let _ = writer.write(&[]);
                }));
            }
        }
        self.channels.insert(channel, chan);
        let delay = self.knobs.ready_delay_ms.load(Ordering::SeqCst);
        if delay > 0 {
            thread::sleep(Duration::from_millis(delay));
        }
        self.send(&ServerControl::Ready {
            channel,
            pty: pty.map(|pty| wire::PtySize {
                rows: pty.rows,
                cols: pty.cols,
            }),
        });
    }

    fn on_control(&mut self, frame: ClientControl) {
        self.log.lock().unwrap().push(frame.clone());
        match frame {
            open @ ClientControl::Open { .. } => self.open(&open),
            ClientControl::Ack {
                channel,
                stream,
                seq,
            } => {
                if let Some(chan) = self.channels.get_mut(&channel) {
                    let before = chan.acked[stream.index()];
                    chan.acked[stream.index()] = seq + 1;
                    chan.credit.give((seq + 1).saturating_sub(before));
                }
            }
            ClientControl::Eof { channel, .. } => {
                if let Some(chan) = self.channels.get_mut(&channel) {
                    chan.input_closed = true;
                    if let Some(stdin) = chan.stdin.take() {
                        let _ = stdin.send(StdinMsg::Eof);
                    }
                }
            }
            ClientControl::Signal { channel, signal } => {
                if let Some(pid) = self.channels.get(&channel).and_then(|chan| chan.pid) {
                    let signal = match signal {
                        wire::Signal::Int => rustix::process::Signal::INT,
                        wire::Signal::Term => rustix::process::Signal::TERM,
                        wire::Signal::Hup => rustix::process::Signal::HUP,
                        wire::Signal::Kill => rustix::process::Signal::KILL,
                    };
                    let _ = rustix::process::kill_process_group(
                        rustix::process::Pid::from_raw(pid as i32).unwrap(),
                        signal,
                    );
                }
            }
            ClientControl::Close { channel } => self.close(channel, Intent::Client),
            ClientControl::Resize { .. } => {}
        }
    }

    fn close(&mut self, channel: u32, intent: Intent) {
        let Some(chan) = self.channels.get_mut(&channel) else {
            return;
        };
        if chan.done {
            return;
        }
        chan.done = true;
        chan.credit.finish();
        chan.stdin = None;
        if let Some(pid) = chan.pid {
            let _ = rustix::process::kill_process_group(
                rustix::process::Pid::from_raw(pid as i32).unwrap(),
                rustix::process::Signal::KILL,
            );
        }
        let frames = ExitFrames {
            stdout: chan.sent[0],
            stderr: chan.sent[1],
        };
        self.send(&ServerControl::Exit {
            channel,
            exit_code: None,
            signal: None,
            intent: Some(intent),
            error: None,
            frames,
        });
    }

    fn on_data(&mut self, metadata: DataMetadata, body: Vec<u8>) {
        let Some(chan) = self.channels.get_mut(&metadata.channel) else {
            return;
        };
        if self.knobs.holds(chan.port) || !chan.held.is_empty() {
            self.knobs
                .held_bytes
                .fetch_add(body.len(), Ordering::SeqCst);
            chan.held.push((metadata.seq, body));
            self.knobs.held_frames.fetch_add(1, Ordering::SeqCst);
            return;
        }
        if let Some(stdin) = &chan.stdin {
            let _ = stdin.send(StdinMsg::Data(metadata.seq, body));
        }
    }

    fn on_event(&mut self, event: Ev) {
        match event {
            Ev::Out(channel, stream, bytes) => {
                if let Some(chan) = self.channels.get_mut(&channel) {
                    chan.queue.push_back(Queued::Data(stream, bytes));
                }
            }
            Ev::OutEof(channel, stream) => {
                if let Some(chan) = self.channels.get_mut(&channel) {
                    chan.open_streams -= 1;
                    match chan.kind {
                        Kind::Exec => chan.queue.push_back(Queued::Eof(stream)),
                        Kind::Tcp | Kind::Unix => {
                            chan.queue.push_back(Queued::Eof(OutputStream::Stdout))
                        }
                        Kind::Pty => {}
                    }
                }
            }
            Ev::Exited(channel, code, signal) => {
                if let Some(chan) = self.channels.get_mut(&channel) {
                    chan.exited = Some((code, signal));
                }
            }
            Ev::Written(channel, seq) => self.send(&ServerControl::Ack {
                channel,
                stream: StdinStream::Stdin,
                seq,
            }),
        }
    }

    /// Release held stdin once the knob lets go.
    fn release_held(&mut self) {
        for chan in self.channels.values_mut() {
            if self.knobs.holds(chan.port) {
                continue;
            }
            for (seq, body) in chan.held.drain(..) {
                if let Some(stdin) = &chan.stdin {
                    let _ = stdin.send(StdinMsg::Data(seq, body));
                }
            }
        }
    }

    /// Send queued output within the client's credit, then exits.
    fn flush_output(&mut self) {
        let mut frames = Vec::new();
        let mut full = 0;
        for (&channel, chan) in self.channels.iter_mut() {
            if chan.done {
                continue;
            }
            // Every credit unit taken and none acknowledged back (a pump
            // blocked in its read holds one, so this counts reservations).
            if chan.credit.state.lock().unwrap().0 >= window(chan.kind) {
                full += 1;
            }
            while let Some(front) = chan.queue.front() {
                match front {
                    Queued::Data(stream, _) => {
                        let unacked =
                            (chan.sent[0] - chan.acked[0]) + (chan.sent[1] - chan.acked[1]);
                        if unacked >= window(chan.kind) {
                            break;
                        }
                        let index = stream.index();
                        let Some(Queued::Data(stream, bytes)) = chan.queue.pop_front() else {
                            unreachable!()
                        };
                        let metadata =
                            DataMetadata::new(channel, DataStream::from(stream), chan.sent[index]);
                        chan.sent[index] += 1;
                        frames.push(Message::binary(
                            wire::encode_data(&metadata, &bytes).unwrap(),
                        ));
                    }
                    Queued::Eof(stream) => {
                        let stream = *stream;
                        chan.queue.pop_front();
                        frames.push(Message::text(
                            wire::encode_control(&ServerControl::Eof {
                                channel,
                                stream,
                                frames: chan.sent[stream.index()],
                            })
                            .unwrap(),
                        ));
                    }
                }
            }
            let finished = chan.queue.is_empty()
                && chan.open_streams == 0
                && match chan.kind {
                    Kind::Pty | Kind::Exec => chan.exited.is_some(),
                    Kind::Tcp | Kind::Unix => chan.input_closed,
                };
            if finished {
                chan.done = true;
                let (code, signal) = chan.exited.unwrap_or((Some(0), None));
                frames.push(Message::text(
                    wire::encode_control(&ServerControl::Exit {
                        channel,
                        exit_code: if signal.is_some() { None } else { code },
                        signal,
                        intent: None,
                        error: None,
                        frames: ExitFrames {
                            stdout: chan.sent[0],
                            stderr: chan.sent[1],
                        },
                    })
                    .unwrap(),
                ));
            }
        }
        self.knobs.out_full.store(full, Ordering::SeqCst);
        for frame in frames {
            let _ = self.ws.send(frame);
        }
    }

    fn kill_all(&mut self) {
        for chan in self.channels.values() {
            chan.credit.finish();
            if let Some(pid) = chan.pid {
                let _ = rustix::process::kill_process_group(
                    rustix::process::Pid::from_raw(pid as i32).unwrap(),
                    rustix::process::Signal::KILL,
                );
            }
        }
    }

    fn run(
        &mut self,
        events: &mpsc::Receiver<Ev>,
        orders: &mpsc::Receiver<Intent>,
        stop: &AtomicBool,
    ) {
        let _ = self
            .ws
            .get_mut()
            .set_read_timeout(Some(Duration::from_millis(2)));
        loop {
            if stop.load(Ordering::SeqCst) {
                break;
            }
            if let Ok(intent) = orders.try_recv() {
                let live: Vec<u32> = self.channels.keys().copied().collect();
                for channel in live {
                    self.close(channel, intent);
                }
                self.send(&ServerControl::End {
                    intent,
                    error: None,
                });
                let _ = self.ws.close(Some(tungstenite::protocol::CloseFrame {
                    code: wire::CLOSE_CODE.into(),
                    reason: "end".into(),
                }));
                let _ = self.ws.flush();
                break;
            }
            while let Ok(event) = events.try_recv() {
                self.on_event(event);
            }
            let close = self.knobs.close_port.load(Ordering::SeqCst);
            if close != 0 {
                let doomed: Vec<u32> = self
                    .channels
                    .iter()
                    .filter(|(_, chan)| chan.port == Some(close) && !chan.done)
                    .map(|(&channel, _)| channel)
                    .collect();
                for channel in doomed {
                    self.close(channel, Intent::Backpressure);
                }
            }
            self.release_held();
            self.flush_output();
            match self.ws.read() {
                Ok(Message::Text(text)) => {
                    let frame = wire::parse_client_control(text.as_str())
                        .unwrap_or_else(|| panic!("invalid client frame {text}"));
                    self.on_control(frame);
                }
                Ok(Message::Binary(bytes)) => {
                    let (metadata, body) = wire::parse_data(&bytes).expect("valid data frame");
                    self.on_data(metadata, body.to_vec());
                }
                Ok(Message::Close(_)) => break,
                Ok(_) => {}
                Err(tungstenite::Error::Io(error))
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(_) => break,
            }
        }
        self.kill_all();
    }
}

/// A TCP write half whose "shutdown" is a write shutdown.
struct TcpHalf(TcpStream);

impl Write for TcpHalf {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.is_empty() {
            let _ = self.0.shutdown(std::net::Shutdown::Write);
            return Ok(0);
        }
        self.0.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

struct UnixHalf(UnixStream);

impl Write for UnixHalf {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.is_empty() {
            let _ = self.0.shutdown(std::net::Shutdown::Write);
            return Ok(0);
        }
        self.0.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

#[allow(clippy::result_large_err)] // tungstenite's callback signature
fn accept_subprotocol(_: &Request, mut response: Response) -> Result<Response, ErrorResponse> {
    response
        .headers_mut()
        .insert("Sec-WebSocket-Protocol", wire::SUBPROTOCOL.parse().unwrap());
    Ok(response)
}

struct Fake {
    url: String,
    upgrades: Arc<AtomicUsize>,
    log: Log,
    knobs: Arc<Knobs>,
    orders: Arc<Mutex<Vec<mpsc::Sender<Intent>>>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Fake {
    fn new(guest: &Path) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let upgrades = Arc::new(AtomicUsize::new(0));
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let knobs = Arc::new(Knobs::default());
        let orders: Arc<Mutex<Vec<mpsc::Sender<Intent>>>> = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let guest = guest.to_path_buf();
        let handle = {
            let (upgrades, log, knobs, orders, stop) = (
                upgrades.clone(),
                log.clone(),
                knobs.clone(),
                orders.clone(),
                stop.clone(),
            );
            thread::spawn(move || {
                let mut sessions = Vec::new();
                while !stop.load(Ordering::SeqCst) {
                    let stream = match listener.accept() {
                        Ok((stream, _)) => stream,
                        Err(error) if error.kind() == ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                            continue;
                        }
                        Err(error) => panic!("accept: {error}"),
                    };
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(15)))
                        .unwrap();
                    let Ok(ws) = tungstenite::accept_hdr(stream, accept_subprotocol) else {
                        continue;
                    };
                    upgrades.fetch_add(1, Ordering::SeqCst);
                    let (order, order_rx) = mpsc::channel();
                    orders.lock().unwrap().push(order);
                    let (events, events_rx) = mpsc::channel();
                    let mut session = Session {
                        ws,
                        guest: guest.clone(),
                        knobs: knobs.clone(),
                        log: log.clone(),
                        events,
                        channels: BTreeMap::new(),
                    };
                    let stop = stop.clone();
                    sessions.push(thread::spawn(move || {
                        session.send(&ServerControl::Hello {
                            connection_id: "c1".into(),
                            sandbox_id: "sbx_1".into(),
                            limits: limits(),
                        });
                        session.run(&events_rx, &order_rx, &stop);
                    }));
                }
                for session in sessions {
                    let _ = session.join();
                }
            })
        };
        Self {
            url,
            upgrades,
            log,
            knobs,
            orders,
            stop,
            handle: Some(handle),
        }
    }

    fn opens(&self) -> Vec<ClientControl> {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter(|frame| matches!(frame, ClientControl::Open { .. }))
            .cloned()
            .collect()
    }

    fn end_all(&self, intent: Intent) {
        for order in self.orders.lock().unwrap().iter() {
            let _ = order.send(intent);
        }
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

// ------------------------------------------------------------ the client side

/// A scratch world: the fake, a guest home, and the generated ssh config.
struct World {
    root: tempfile::TempDir,
    fake: Fake,
    config: PathBuf,
    /// The server URL the client uses: the fake's, or a latency proxy's.
    server: String,
    _latency: Option<latency::Latency>,
}

fn wssp_env(command: &mut Command, root: &Path, server: &str) {
    command
        .env("HOME", root.join("home"))
        .env("WSSP_CONFIG_DIR", root.join("config"))
        .env("WSSP_DATA_DIR", root.join("data"))
        .env("WSSP_API_KEY", SECRET)
        .env("WSSP_SERVER", server)
        .env_remove("WSSP_USER_DIR")
        .env_remove("WSSP_CA_FILE")
        .env_remove("WSSP_LOG")
        .env_remove("RUST_LOG")
        .env_remove("SSH_AUTH_SOCK");
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
        command.env_remove(proxy);
    }
}

impl World {
    fn new() -> Self {
        Self::with_latency(None)
    }

    /// A world whose client reaches the fake through a path that adds
    /// `one_way` in each direction.
    fn with_latency(one_way: Option<Duration>) -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("home")).unwrap();
        std::fs::create_dir_all(root.path().join("guest")).unwrap();
        let fake = Fake::new(&root.path().join("guest"));
        let latency = one_way.map(|one_way| {
            latency::Latency::start(fake.url.strip_prefix("http://").unwrap(), one_way)
        });
        let server = latency.as_ref().map_or_else(
            || fake.url.clone(),
            |proxy| format!("http://{}", proxy.address),
        );
        // The generated block, as `--install` writes it (`--install` itself
        // refuses a `$HOME` that is not the account's home, which ssh reads;
        // `tests/ssh_config.rs` covers it).
        let mut print = Command::new(env!("CARGO_BIN_EXE_wssp"));
        print.args(["ssh-config", "--json"]);
        wssp_env(&mut print, root.path(), &server);
        let output = print.output().unwrap();
        assert!(
            output.status.success(),
            "ssh-config failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let config = root.path().join("home/.ssh/config.d/wssp");
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        std::fs::write(&config, report["config"].as_str().unwrap()).unwrap();
        Self {
            root,
            fake,
            config,
            server,
            _latency: latency,
        }
    }

    fn guest(&self) -> PathBuf {
        self.root.path().join("guest")
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }

    /// The endpoint's test notes (debug builds): a channel's SSH window used
    /// up or granted again (`exhausted <n>`/`granted <n>`), a writer waiting
    /// for the client's window (`blocked`/`unblocked`).
    fn note_log(&self) -> PathBuf {
        self.root.path().join("notes.log")
    }

    /// The last of the endpoint's `on`/`off` notes is `on`.
    fn last_note_is(&self, on: &str, off: &str) -> bool {
        std::fs::read_to_string(self.note_log())
            .is_ok_and(|log| log.lines().rev().find(|line| *line == on || *line == off) == Some(on))
    }

    /// The SSH window of the endpoint's channel `local` is used up right now.
    fn window_exhausted(&self, local: u64) -> bool {
        self.last_note_is(&format!("exhausted {local}"), &format!("granted {local}"))
    }

    /// The endpoint's channels whose SSH window was used up at some point.
    fn exhausted_channels(&self) -> Vec<u64> {
        let log = std::fs::read_to_string(self.note_log()).unwrap_or_default();
        let mut found: Vec<u64> = log
            .lines()
            .filter_map(|line| line.strip_prefix("exhausted ")?.parse().ok())
            .collect();
        found.dedup();
        found
    }

    /// A channel write of the endpoint waits for the client's window.
    fn writer_blocked(&self) -> bool {
        self.last_note_is("blocked", "unblocked")
    }

    /// A client tool (`ssh`, `scp`, `sftp`) with the generated config.
    fn tool(&self, program: &str) -> Command {
        let mut command = Command::new(program);
        wssp_env(&mut command, self.root.path(), &self.server);
        command.env("WSSP_TEST_SSH_NOTE_LOG", self.note_log());
        command
            .arg("-F")
            .arg(&self.config)
            .args(["-o", "BatchMode=yes"])
            // ring-accelerated in a debug build of russh.
            .args(["-o", "Ciphers=aes256-gcm@openssh.com"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    fn ssh(&self) -> Command {
        self.tool("ssh")
    }

    /// The `-e` of rsync: ssh with the same options.
    fn rsync_shell(&self) -> String {
        format!(
            "ssh -F {} -o BatchMode=yes -o LogLevel=ERROR -o Ciphers=aes256-gcm@openssh.com",
            self.config.display()
        )
    }

    fn rsync(&self) -> Command {
        let mut command = Command::new("rsync");
        wssp_env(&mut command, self.root.path(), &self.server);
        command.env("WSSP_TEST_SSH_NOTE_LOG", self.note_log());
        command
            .arg("-e")
            .arg(self.rsync_shell())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }
}

/// Run to completion within `limit` (killed beyond it).
fn run(mut command: Command, stdin: Option<Vec<u8>>, limit: Duration) -> std::process::Output {
    if stdin.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = ManagedChild::spawn(&mut command).unwrap();
    if let Some(bytes) = stdin {
        let mut pipe = child.stdin.take().unwrap();
        thread::spawn(move || {
            let _ = pipe.write_all(&bytes);
        });
    }
    let (done, finished) = mpsc::channel();
    let pid = child.id();
    let watchdog = thread::spawn(move || {
        if finished.recv_timeout(limit).is_err() {
            let _ = rustix::process::kill_process_group(
                rustix::process::Pid::from_raw(pid as i32).unwrap(),
                rustix::process::Signal::KILL,
            );
        }
    });
    let output = child.wait_with_output().unwrap();
    let _ = done.send(());
    watchdog.join().unwrap();
    output
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn payload(n: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..n)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

const LIMIT: Duration = Duration::from_secs(60);

/// Wait (polling) until `ready`, failing with `what` after `limit`.
fn wait_until(limit: Duration, what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + limit;
    while !ready() {
        assert!(Instant::now() < deadline, "{what} (after {limit:?})");
        thread::sleep(Duration::from_millis(10));
    }
}

/// Join `handle` within `limit` (a hung worker fails the test instead of
/// hanging it; the caller kills what the worker waits on first).
fn join_within<T: Send + 'static>(handle: thread::JoinHandle<T>, limit: Duration, what: &str) -> T {
    let (done, finished) = mpsc::channel();
    thread::spawn(move || {
        let _ = done.send(handle.join());
    });
    match finished.recv_timeout(limit) {
        Ok(Ok(value)) => value,
        Ok(Err(panic)) => std::panic::resume_unwind(panic),
        Err(_) => panic!("{what} did not finish within {limit:?}"),
    }
}

/// Wait for `child` to exit within `limit`; returns when it did.
fn exit_within(child: &mut ManagedChild, limit: Duration, what: &str) -> std::process::ExitStatus {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "{what} still running after {limit:?}"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

/// Whether process `pid` is gone (or a zombie).
fn gone(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).map_or(true, |stat| {
        stat.rsplit_once(") ")
            .is_some_and(|(_, rest)| rest.starts_with('Z') || rest.starts_with('X'))
    })
}

/// The `wssp ssh --stdio` process under an ssh client.
fn endpoint_of(ssh_pid: u32) -> u32 {
    let mut found = None;
    wait_until(Duration::from_secs(20), "no endpoint process", || {
        found = descendants(ssh_pid).into_iter().find(|pid| {
            std::fs::read_to_string(format!("/proc/{pid}/cmdline"))
                .is_ok_and(|cmdline| cmdline.contains("--stdio"))
                && std::fs::read_link(format!("/proc/{pid}/exe"))
                    .is_ok_and(|exe| exe.ends_with("wssp"))
        });
        found.is_some()
    });
    found.unwrap_or_default()
}

/// Whether a process running exactly `argv` has the guest `dir` as its cwd
/// (the fake starts every guest command there).
fn guest_program_running(dir: &Path, argv: &[&str]) -> bool {
    let dir = std::fs::canonicalize(dir).unwrap();
    let want: Vec<u8> = argv
        .iter()
        .flat_map(|arg| [arg.as_bytes(), b"\0"].concat())
        .collect();
    std::fs::read_dir("/proc").is_ok_and(|entries| {
        entries.flatten().any(|entry| {
            let pid = entry.path();
            std::fs::read(pid.join("cmdline")).is_ok_and(|cmdline| cmdline == want)
                && std::fs::read_link(pid.join("cwd")).is_ok_and(|cwd| cwd == dir)
        })
    })
}

/// The channel of the `tcp` open to `port` the fake saw.
fn channel_to(fake: &Fake, port: u16) -> Option<u32> {
    fake.opens().into_iter().find_map(|open| match open {
        ClientControl::Open {
            channel,
            kind: Kind::Tcp,
            port: Some(p),
            ..
        } if p == port => Some(channel),
        _ => None,
    })
}

/// Whether the client closed `channel` (a reset for a relay).
fn client_closed(fake: &Fake, channel: u32) -> bool {
    fake.log
        .lock()
        .unwrap()
        .iter()
        .any(|frame| matches!(frame, ClientControl::Close { channel: c } if *c == channel))
}

/// Distinct free loopback ports (all bound at once, then released).
fn free_ports(n: usize) -> Vec<u16> {
    let listeners: Vec<TcpListener> = (0..n)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    listeners
        .iter()
        .map(|listener| listener.local_addr().unwrap().port())
        .collect()
}

/// ssh's stderr, collected as it comes.
struct Collected(Arc<Mutex<String>>);

impl Collected {
    fn start(child: &mut ManagedChild) -> Self {
        let mut stderr = child.stderr.take().unwrap();
        let text = Arc::new(Mutex::new(String::new()));
        let sink = text.clone();
        thread::spawn(move || {
            let mut buffer = [0_u8; 4096];
            while let Ok(n) = stderr.read(&mut buffer) {
                if n == 0 {
                    break;
                }
                sink.lock()
                    .unwrap()
                    .push_str(&String::from_utf8_lossy(&buffer[..n]));
            }
        });
        Self(text)
    }

    /// ssh's stdout, collected the same way.
    fn start_stdout(child: &mut ManagedChild) -> Self {
        let mut stdout = child.stdout.take().unwrap();
        let text = Arc::new(Mutex::new(String::new()));
        let sink = text.clone();
        thread::spawn(move || {
            let mut buffer = [0_u8; 4096];
            while let Ok(n) = stdout.read(&mut buffer) {
                if n == 0 {
                    break;
                }
                sink.lock()
                    .unwrap()
                    .push_str(&String::from_utf8_lossy(&buffer[..n]));
            }
        });
        Self(text)
    }

    fn text(&self) -> String {
        self.0.lock().unwrap().clone()
    }
}

/// An ssh client with forwards on fresh local ports (`-v`,
/// `ExitOnForwardFailure=yes`), retried with new ports when one was taken
/// meanwhile; returned once ssh listens on every port. `args` gets the
/// ports and returns ssh's arguments (forwards and the destination).
fn forwarding(
    world: &World,
    n: usize,
    env: &[(&str, &str)],
    args: impl Fn(&[u16]) -> Vec<String>,
) -> (ManagedChild, Collected, Vec<u16>) {
    for _ in 0..5 {
        let ports = free_ports(n);
        let mut ssh = world.ssh();
        for (name, value) in env {
            ssh.env(name, value);
        }
        ssh.args(["-v", "-o", "ExitOnForwardFailure=yes"])
            .args(args(&ports))
            .stdin(Stdio::piped());
        let mut child = ManagedChild::spawn(&mut ssh).unwrap();
        let stderr = Collected::start(&mut child);
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let text = stderr.text();
            if ports.iter().all(|port| {
                text.contains(&format!(
                    "Local forwarding listening on 127.0.0.1 port {port}."
                ))
            }) {
                return (child, stderr, ports);
            }
            if child.try_wait().unwrap().is_some() {
                assert!(text.contains("Address already in use"), "ssh ended: {text}");
                break;
            }
            assert!(Instant::now() < deadline, "ssh never listened: {text}");
            thread::sleep(Duration::from_millis(10));
        }
    }
    panic!("no free ports after five tries");
}

fn connect_to(port: u16) -> TcpStream {
    let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    stream
}

/// A refusal is an actual close or reset of the local connection, never a
/// read timeout and never data.
fn assert_refused(mut stream: TcpStream) {
    let mut back = Vec::new();
    match stream.read_to_end(&mut back) {
        Ok(0) => {}
        Ok(n) => panic!("{n} bytes from a refused forward"),
        Err(error) => assert_eq!(error.kind(), ErrorKind::ConnectionReset, "{error}"),
    }
}

/// The blocking syscall of a thread of `pid` (from `/proc/<pid>/task/*/syscall`).
fn blocked_in(pid: u32, syscall: &str, fd: &str) -> bool {
    let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
        return false;
    };
    tasks.flatten().any(|task| {
        std::fs::read_to_string(task.path().join("syscall")).is_ok_and(|line| {
            let mut fields = line.split_whitespace();
            fields.next() == Some(syscall) && fields.next() == Some(fd)
        })
    })
}

#[cfg(target_arch = "x86_64")]
const WRITE_SYSCALL: &str = "1";
#[cfg(target_arch = "aarch64")]
const WRITE_SYSCALL: &str = "64";

fn signal(pid: u32, signal: rustix::process::Signal) {
    let _ =
        rustix::process::kill_process(rustix::process::Pid::from_raw(pid as i32).unwrap(), signal);
}

/// The endpoint binary, as the generated ProxyCommand names it.
fn wssp_exe() -> PathBuf {
    std::fs::canonicalize(env!("CARGO_BIN_EXE_wssp")).unwrap()
}

// ------------------------------------------------------------ tests

#[test]
fn exec_runs_the_guest_shell_and_returns_its_status() {
    require!("ssh");
    let world = World::new();
    let mut ssh = world.ssh();
    ssh.args(["sbx_1.wssp", "echo \"hi $0\"; echo err >&2; exit 42"]);
    let output = run(ssh, None, LIMIT);
    assert_eq!(output.status.code(), Some(42), "{}", text(&output.stderr));
    assert_eq!(text(&output.stdout), "hi /bin/sh\n");
    assert_eq!(text(&output.stderr), "err\n");
    let opens = world.fake.opens();
    let ClientControl::Open {
        kind, argv, login, ..
    } = &opens[0]
    else {
        unreachable!()
    };
    assert_eq!(*kind, Kind::Exec);
    assert_eq!(*login, Some(false));
    assert_eq!(
        argv.as_ref().unwrap()[4],
        "echo \"hi $0\"; echo err >&2; exit 42"
    );
}

#[test]
fn a_shell_without_a_terminal_reads_its_commands_from_stdin() {
    require!("ssh");
    let world = World::new();
    let mut ssh = world.ssh();
    ssh.args(["-T", "sbx_1.wssp"]);
    let output = run(ssh, Some(b"echo plain\nexit 3\n".to_vec()), LIMIT);
    assert_eq!(output.status.code(), Some(3), "{}", text(&output.stderr));
    assert_eq!(text(&output.stdout), "plain\n");
    let ClientControl::Open {
        kind, argv, login, ..
    } = &world.fake.opens()[0]
    else {
        unreachable!()
    };
    assert_eq!(
        (*kind, argv.is_none(), *login),
        (Kind::Exec, true, Some(true))
    );
}

#[test]
fn a_terminal_session_carries_term_and_the_exit_status() {
    require!("ssh");
    let world = World::new();
    let mut ssh = world.ssh();
    ssh.env("TERM", "xterm-test").args(["-tt", "sbx_1.wssp"]);
    let output = run(ssh, Some(b"echo \"T=$TERM\"\nexit 7\n".to_vec()), LIMIT);
    assert_eq!(output.status.code(), Some(7), "{}", text(&output.stderr));
    assert!(
        text(&output.stdout).contains("T=xterm-test"),
        "{}",
        text(&output.stdout)
    );
    let ClientControl::Open {
        kind,
        pty,
        login,
        argv,
        ..
    } = &world.fake.opens()[0]
    else {
        unreachable!()
    };
    assert_eq!(*kind, Kind::Pty);
    assert_eq!(pty.as_ref().unwrap().term, "xterm-test");
    assert_eq!((*login, argv.is_none()), (Some(true), true));
}

#[test]
fn only_locale_env_travels() {
    require!("ssh");
    let world = World::new();
    let mut ssh = world.ssh();
    ssh.args([
        "-o",
        "SetEnv=LANG=C.UTF-8 LC_TIME=C FOO=bar LD_PRELOAD=/x",
        "sbx_1.wssp",
        "echo \"$LANG|$LC_TIME|${FOO:-unset}|${LD_PRELOAD:-unset}\"",
    ]);
    let output = run(ssh, None, LIMIT);
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert_eq!(text(&output.stdout), "C.UTF-8|C|unset|unset\n");
}

#[test]
fn a_death_by_signal_is_an_exit_signal() {
    require!("ssh");
    let world = World::new();
    let mut ssh = world.ssh();
    ssh.args(["-v", "sbx_1.wssp", "kill -TERM $$"]);
    let output = run(ssh, None, LIMIT);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(255), "{stderr}");
    assert!(stderr.contains("rtype exit-signal"), "{stderr}");
    assert!(!stderr.contains("rtype exit-status"), "{stderr}");
}

#[test]
fn binary_data_and_half_close_pass_unchanged() {
    require!("ssh");
    let world = World::new();
    let mut bytes: Vec<u8> = (0..=255).cycle().take(256 * 1024).collect();
    bytes.extend(payload(3 * 1024 * 1024, 5));
    let mut ssh = world.ssh();
    ssh.args(["sbx_1.wssp", "cat; printf done"]);
    let output = run(ssh, Some(bytes.clone()), LIMIT);
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert_eq!(output.stdout.len(), bytes.len() + 4);
    assert!(
        output.stdout[..bytes.len()] == bytes[..],
        "the bytes changed"
    );
    assert_eq!(&output.stdout[bytes.len()..], b"done");
}

#[test]
fn scp_in_both_modes_and_sftp_move_files() {
    require!("ssh", "scp", "sftp");
    if !Path::new("/usr/lib/openssh/sftp-server").exists() {
        assert!(
            !tools_required(),
            "/usr/lib/openssh/sftp-server is required"
        );
        eprintln!("skipped: no /usr/lib/openssh/sftp-server to stand in for the guest's");
        return;
    }
    let world = World::new();
    let source = world.path("source.bin");
    let bytes = payload(2 * 1024 * 1024 + 17, 9);
    std::fs::write(&source, &bytes).unwrap();
    let guest = world.guest();
    // OpenSSH's default (sftp) mode, then the legacy protocol: up, then down.
    for (mode, name) in [(None, "sftp-mode.bin"), (Some("-O"), "legacy.bin")] {
        let mut scp = world.tool("scp");
        if let Some(mode) = mode {
            scp.arg(mode);
        }
        scp.arg(&source)
            .arg(format!("sbx_1.wssp:{}", guest.join(name).display()));
        let output = run(scp, None, LIMIT);
        assert!(
            output.status.success(),
            "{mode:?} up: {}",
            text(&output.stderr)
        );
        assert!(
            std::fs::read(guest.join(name)).unwrap() == bytes,
            "{mode:?} up"
        );
        let back = world.path(&format!("down-{name}"));
        let mut scp = world.tool("scp");
        if let Some(mode) = mode {
            scp.arg(mode);
        }
        scp.arg(format!("sbx_1.wssp:{}", guest.join(name).display()))
            .arg(&back);
        let output = run(scp, None, LIMIT);
        assert!(
            output.status.success(),
            "{mode:?} down: {}",
            text(&output.stderr)
        );
        assert!(std::fs::read(&back).unwrap() == bytes, "{mode:?} down");
    }
    // sftp: an explicit put, a listing and a get.
    let batch = world.path("batch");
    std::fs::write(
        &batch,
        format!(
            "put {} {}\nls {}\nget {} {}\n",
            source.display(),
            guest.join("put.bin").display(),
            guest.display(),
            guest.join("put.bin").display(),
            world.path("back.bin").display()
        ),
    )
    .unwrap();
    let mut sftp = world.tool("sftp");
    sftp.arg("-b").arg(&batch).arg("sbx_1.wssp");
    let output = run(sftp, None, LIMIT);
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert!(text(&output.stdout).contains("legacy.bin"));
    assert!(
        std::fs::read(guest.join("put.bin")).unwrap() == bytes,
        "sftp put"
    );
    assert!(
        std::fs::read(world.path("back.bin")).unwrap() == bytes,
        "sftp get"
    );
    let subsystems = world
        .fake
        .opens()
        .iter()
        .filter(|open| matches!(open, ClientControl::Open { argv: Some(argv), .. } if argv[3] == "wssp-sftp"))
        .count();
    // scp's sftp mode up and down, and the sftp session.
    assert_eq!(subsystems, 3);
}

/// The rsync transfer, both ways (MiB).
const RSYNC_MIB: usize = 160;

#[test]
fn rsync_moves_a_sizeable_file_both_ways() {
    require!("ssh", "rsync");
    let world = World::new();
    let source = world.path("big.bin");
    // Plan §13 asks for 256 MiB: in a debug build that took 40 s here,
    // 160 MiB about 28 s, so the test moves the largest size that stays
    // within its ~30 s budget.
    let bytes = payload(RSYNC_MIB * 1024 * 1024, 77);
    std::fs::write(&source, &bytes).unwrap();
    let guest = world.guest().join("big.bin");
    let mut rsync = world.rsync();
    rsync
        .arg("--checksum")
        .arg(&source)
        .arg(format!("sbx_1.wssp:{}", guest.display()));
    let output = run(rsync, None, Duration::from_secs(180));
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert!(std::fs::read(&guest).unwrap() == bytes, "upload changed");
    let mut rsync = world.rsync();
    rsync
        .arg("--checksum")
        .arg(format!("sbx_1.wssp:{}", guest.display()))
        .arg(world.path("back.bin"));
    let output = run(rsync, None, Duration::from_secs(180));
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert!(
        std::fs::read(world.path("back.bin")).unwrap() == bytes,
        "download changed"
    );
}

/// Over a path with 15 ms each way, a channel moves its data at the pace
/// of its window (1 MiB of stdin or output credit per round trip), both
/// ways: the endpoint's connection thread must not add a wait of its own
/// per turn (it once waited a whole poll slice per turn for input that no
/// frame announces, and again after the frames that woke it). Each transfer
/// is timed inside its own connection, from its first byte to its end (the
/// upload in the guest by `/proc/uptime`, the download at the client by a
/// monotonic clock), so the connection's setup never counts. In a debug build: about 37 ms per MiB both ways (up
/// to 67 up next to this file's other tests); 141-182 up and 67-92 down
/// with those waits. The upload limit sits between; the download limit
/// only catches a gross regression. A busy machine only adds time (the
/// other tests of this file run at once), so the best of up to three
/// attempts counts; the waits it guards against are there every time.
#[test]
fn a_transfer_runs_at_the_pace_of_its_window() {
    require!("ssh");
    const MIB: usize = 16;
    const ONE_WAY: Duration = Duration::from_millis(15);
    const UP_LIMIT_MS_PER_MIB: f64 = 110.0;
    const DOWN_LIMIT_MS_PER_MIB: f64 = 70.0;
    const ATTEMPTS: usize = 3;
    let world = World::with_latency(Some(ONE_WAY));
    let source = world.path("up.bin");
    let bytes = payload(MIB * 1024 * 1024, 5);
    std::fs::write(&source, &bytes).unwrap();
    let guest = world.guest();
    let per_mib = |secs: f64| secs * 1000.0 / MIB as f64;
    let (mut best_up, mut best_down) = (f64::MAX, f64::MAX);
    for attempt in 1..=ATTEMPTS {
        // The guest stamps the arrival of the first byte and of the end
        // (`/proc/uptime`: a clock nobody sets, 10 ms steps).
        let mut up = world.ssh();
        up.args([
            "sbx_1.wssp",
            "dd bs=1 count=1 status=none > up.bin && cat /proc/uptime > up.start && \
             cat >> up.bin && cat /proc/uptime > up.end",
        ])
        .stdin(std::fs::File::open(&source).unwrap());
        let output = run(up, None, Duration::from_secs(300));
        assert!(output.status.success(), "upload: {}", text(&output.stderr));
        assert!(
            std::fs::read(guest.join("up.bin")).unwrap() == bytes,
            "upload changed"
        );
        let stamp = |name: &str| -> f64 {
            let text = std::fs::read_to_string(guest.join(name)).unwrap();
            text.split_whitespace()
                .next()
                .unwrap()
                .parse::<f64>()
                .unwrap()
        };
        let up = per_mib(stamp("up.end") - stamp("up.start"));
        // The client times its first byte and the end of the stream; the
        // read runs on its own thread so a hung download still fails in
        // time (its process group is killed).
        let mut down = world.ssh();
        down.args(["sbx_1.wssp", "cat up.bin"]);
        let mut child = ManagedChild::spawn(&mut down).unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let (done, finished) = mpsc::channel();
        thread::spawn(move || {
            let mut got = Vec::new();
            let mut buffer = vec![0_u8; 64 * 1024];
            let mut first = None;
            loop {
                match stdout.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        first.get_or_insert_with(Instant::now);
                        got.extend_from_slice(&buffer[..n]);
                    }
                }
            }
            let _ = done.send((first.map(|at| at.elapsed()), got));
        });
        let Ok((elapsed, got)) = finished.recv_timeout(Duration::from_secs(300)) else {
            let _ = rustix::process::kill_process_group(
                rustix::process::Pid::from_raw(child.id() as i32).unwrap(),
                rustix::process::Signal::KILL,
            );
            panic!("the download did not end within 300 s");
        };
        let down = per_mib(elapsed.expect("no download").as_secs_f64());
        assert!(exit_within(&mut child, LIMIT, "the download").success());
        assert!(got == bytes, "download changed");
        eprintln!("attempt {attempt}: up {up:.0} ms/MiB, down {down:.0} ms/MiB");
        best_up = best_up.min(up);
        best_down = best_down.min(down);
        if best_up < UP_LIMIT_MS_PER_MIB && best_down < DOWN_LIMIT_MS_PER_MIB {
            return;
        }
    }
    panic!(
        "best of {ATTEMPTS}: upload {best_up:.0}, download {best_down:.0} ms per MiB over a 30 ms \
         round trip (limits {UP_LIMIT_MS_PER_MIB} and {DOWN_LIMIT_MS_PER_MIB})"
    );
}

/// An echo service on loopback standing in for a guest service.
fn echo_service() -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        for stream in listener.incoming().take(4) {
            let Ok(mut stream) = stream else { return };
            thread::spawn(move || {
                let mut buffer = [0_u8; 16384];
                loop {
                    match stream.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buffer[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
                let _ = stream.shutdown(std::net::Shutdown::Write);
            });
        }
    });
    (port, handle)
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn round_trip(stream: &mut TcpStream, bytes: &[u8]) -> Vec<u8> {
    let mut writer = stream.try_clone().unwrap();
    let bytes = bytes.to_vec();
    let sender = thread::spawn(move || {
        writer.write_all(&bytes).unwrap();
        writer.shutdown(std::net::Shutdown::Write).unwrap();
    });
    let mut back = Vec::new();
    stream.read_to_end(&mut back).unwrap();
    sender.join().unwrap();
    back
}

#[test]
fn local_and_dynamic_forwards_reach_only_the_guest_loopback() {
    require!("ssh");
    let world = World::new();
    let (guest_port, _service) = echo_service();
    let (session, _stderr, ports) = forwarding(&world, 3, &[], |ports| {
        vec![
            "-N".into(),
            "-L".into(),
            format!("127.0.0.1:{}:localhost:{guest_port}", ports[0]),
            "-L".into(),
            format!("127.0.0.1:{}:10.1.2.3:{guest_port}", ports[1]),
            "-D".into(),
            format!("127.0.0.1:{}", ports[2]),
            "sbx_1.wssp".into(),
        ]
    });
    // -L: bytes both ways and the half-close.
    let mut stream = connect_to(ports[0]);
    let bytes = payload(600 * 1024, 3);
    assert!(round_trip(&mut stream, &bytes) == bytes);
    // -D: a SOCKS5 CONNECT to localhost:<guest_port>.
    let mut stream = connect_to(ports[2]);
    stream.write_all(&[5, 1, 0]).unwrap();
    let mut reply = [0_u8; 2];
    stream.read_exact(&mut reply).unwrap();
    assert_eq!(reply, [5, 0]);
    let mut request = vec![5, 1, 0, 3, 9];
    request.extend_from_slice(b"localhost");
    request.extend_from_slice(&guest_port.to_be_bytes());
    stream.write_all(&request).unwrap();
    let mut reply = [0_u8; 10];
    stream.read_exact(&mut reply).unwrap();
    assert_eq!(reply[1], 0, "socks connect refused");
    assert_eq!(round_trip(&mut stream, b"through socks"), b"through socks");
    // A forward to anything but the guest's loopback never opens a channel:
    // the local connection is closed (never a timeout, never data).
    assert_refused(connect_to(ports[1]));
    let relays: Vec<_> = world
        .fake
        .opens()
        .into_iter()
        .filter(|open| {
            matches!(
                open,
                ClientControl::Open {
                    kind: Kind::Tcp,
                    ..
                }
            )
        })
        .collect();
    assert_eq!(relays.len(), 2, "{relays:?}");
    for open in relays {
        let ClientControl::Open { port, .. } = open else {
            unreachable!()
        };
        assert_eq!(port, Some(guest_port));
    }
    drop(session);
}

#[test]
fn a_unix_socket_forward_reaches_the_guest_path() {
    require!("ssh");
    let world = World::new();
    let socket = world.guest().join("app.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let service = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).unwrap();
        request.reverse();
        stream.write_all(&request).unwrap();
    });
    let (session, _stderr, ports) = forwarding(&world, 1, &[], |ports| {
        vec![
            "-N".into(),
            "-L".into(),
            format!("127.0.0.1:{}:{}", ports[0], socket.display()),
            "sbx_1.wssp".into(),
        ]
    });
    let mut stream = connect_to(ports[0]);
    assert_eq!(round_trip(&mut stream, b"abc"), b"cba");
    join_within(service, LIMIT, "the guest service");
    drop(session);
}

#[test]
fn control_master_sessions_share_one_connection() {
    require!("ssh");
    let world = World::new();
    let control = world.path("cm");
    let mut master = world.ssh();
    master
        .args(["-o", "ControlMaster=yes", "-o"])
        .arg(format!("ControlPath={}", control.display()))
        .args(["-N", "sbx_1.wssp"]);
    let master = ManagedChild::spawn(&mut master).unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while !control.exists() {
        assert!(Instant::now() < deadline, "the master never listened");
        thread::sleep(Duration::from_millis(50));
    }
    for word in ["one", "two"] {
        let mut ssh = world.ssh();
        ssh.arg("-o")
            .arg(format!("ControlPath={}", control.display()))
            .args(["sbx_1.wssp", &format!("echo {word}")]);
        let output = run(ssh, None, LIMIT);
        assert!(output.status.success(), "{}", text(&output.stderr));
        assert_eq!(text(&output.stdout), format!("{word}\n"));
    }
    assert_eq!(world.fake.upgrades.load(Ordering::SeqCst), 1);
    let mut exit = world.ssh();
    exit.arg("-o")
        .arg(format!("ControlPath={}", control.display()))
        .args(["-O", "exit", "sbx_1.wssp"]);
    let _ = run(exit, None, LIMIT);
    drop(master);
}

#[test]
fn remote_forwards_and_agent_forwarding_are_refused() {
    require!("ssh");
    let world = World::new();
    let mut ssh = world.ssh();
    ssh.args([
        "-o",
        "ExitOnForwardFailure=yes",
        "-R",
        &format!("127.0.0.1:{}:localhost:22", free_port()),
        "sbx_1.wssp",
        "sleep 30",
    ]);
    let started = Instant::now();
    let output = run(ssh, None, LIMIT);
    assert_eq!(output.status.code(), Some(255));
    assert!(
        text(&output.stderr).contains("remote port forwarding failed"),
        "{}",
        text(&output.stderr)
    );
    assert!(started.elapsed() < Duration::from_secs(20));
    // Agent forwarding: requested, refused, and the guest sees no agent.
    let agent_dir = world.path("agent");
    std::fs::create_dir(&agent_dir).unwrap();
    let agent_socket = agent_dir.join("agent.sock");
    let _agent = UnixListener::bind(&agent_socket).unwrap();
    let mut ssh = world.ssh();
    ssh.env("SSH_AUTH_SOCK", &agent_socket).args([
        "-A",
        "-v",
        "sbx_1.wssp",
        "echo \"agent=${SSH_AUTH_SOCK:-none}\"",
    ]);
    let output = run(ssh, None, LIMIT);
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert_eq!(text(&output.stdout), "agent=none\n");
    assert!(
        text(&output.stderr).contains("Requesting authentication agent forwarding"),
        "{}",
        text(&output.stderr)
    );
}

#[test]
fn a_revoked_login_ends_the_session_and_ssh_exits_255() {
    require!("ssh");
    let world = World::new();
    let mut ssh = world.ssh();
    ssh.args(["sbx_1.wssp", "sleep 30"]);
    let mut session = ManagedChild::spawn(&mut ssh).unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while world.fake.opens().is_empty() {
        assert!(Instant::now() < deadline, "the session never opened");
        thread::sleep(Duration::from_millis(20));
    }
    let ended = Instant::now();
    world.fake.end_all(Intent::Revoked);
    let status = exit_within(
        &mut session,
        Duration::from_secs(5),
        "ssh after the revocation",
    );
    // Taken before collecting stderr, which is not part of the bound.
    let took = ended.elapsed();
    let mut stderr = String::new();
    session
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert_eq!(status.code(), Some(255), "{stderr}");
    assert!(stderr.contains("`revoked`"), "{stderr}");
    assert!(took < Duration::from_secs(2), "{took:?}");
}

/// A guest that stops reading holds the ssh client's input instead of this
/// process buffering it: with stdin held at the fake, once the channel's SSH
/// window is used up (synchronised on the endpoint's note and on bytes held
/// at the fake), the client has managed only a bounded amount; released,
/// everything arrives.
#[test]
fn a_guest_that_stops_reading_holds_the_clients_input() {
    require!("ssh");
    let world = World::new();
    world.fake.knobs.hold_stdin.store(true, Ordering::SeqCst);
    let mut ssh = world.ssh();
    let sink = world.guest().join("sink.bin");
    ssh.args(["sbx_1.wssp", &format!("cat > {}", sink.display())])
        .stdin(Stdio::piped());
    let mut session = ManagedChild::spawn(&mut ssh).unwrap();
    let mut pipe = session.stdin.take().unwrap();
    let written = Arc::new(AtomicUsize::new(0));
    let total = 64 * 1024 * 1024;
    let writer = {
        let written = written.clone();
        thread::spawn(move || {
            let chunk = payload(64 * 1024, 1);
            while written.load(Ordering::SeqCst) < total {
                if pipe.write_all(&chunk).is_err() {
                    return;
                }
                written.fetch_add(chunk.len(), Ordering::SeqCst);
            }
        })
    };
    wait_until(
        Duration::from_secs(30),
        "the channel's window was never used up",
        || {
            world.fake.knobs.held_frames.load(Ordering::SeqCst) >= 32
                && world
                    .exhausted_channels()
                    .into_iter()
                    .any(|local| world.window_exhausted(local))
        },
    );
    // The client keeps writing: give it time to push more than the bound if
    // anything here buffered without limit (the bound is several times what
    // the two windows and ssh's buffers hold).
    thread::sleep(Duration::from_secs(2));
    let held = world.fake.knobs.held_bytes.load(Ordering::SeqCst);
    let admitted = written.load(Ordering::SeqCst);
    // At most one window at the fake; the client got no further than its
    // SSH window here, one window at the fake and what ssh and the pipes
    // buffer.
    assert!(
        held > 0 && held <= 1024 * 1024,
        "{held} bytes held at the fake"
    );
    assert!(
        admitted < 16 * 1024 * 1024,
        "{admitted} bytes went in while the guest read nothing"
    );
    world.fake.knobs.hold_stdin.store(false, Ordering::SeqCst);
    join_within(writer, Duration::from_secs(120), "the upload");
    let status = exit_within(&mut session, Duration::from_secs(120), "the upload's ssh");
    assert!(status.success());
    assert_eq!(std::fs::metadata(&sink).unwrap().len(), total as u64);
}

/// A guest command that writes its output while it reads its input (`cat`)
/// finishes however fast the client sends: a channel's window holds only
/// its own input, never the output the guest needs to drain before it reads
/// more (the fake, like a node, reads a process's output only within the
/// client's credit).
#[test]
fn a_command_that_streams_its_input_back_finishes() {
    require!("ssh");
    let world = World::new();
    let bytes = payload(32 * 1024 * 1024, 11);
    let mut ssh = world.ssh();
    ssh.args(["sbx_1.wssp", "cat"]);
    let output = run(ssh, Some(bytes.clone()), Duration::from_secs(120));
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert_eq!(output.stdout.len(), bytes.len());
    assert!(output.stdout == bytes, "the bytes changed");
}

/// A guest service that records what it reads until the client's eof (the
/// fake holds what is sent to it while `hold_port` names it).
fn recording_service() -> (u16, thread::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut read = Vec::new();
        let _ = stream.read_to_end(&mut read);
        read
    });
    (port, handle)
}

/// An echo service that serves every connection until its client closes.
fn endless_echo_service() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            thread::spawn(move || {
                let mut buffer = [0_u8; 16384];
                while let Ok(n) = stream.read(&mut buffer) {
                    if n == 0 || stream.write_all(&buffer[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

/// Send `bytes` and read as many back on a connection that stays open.
fn echo_round(stream: &mut TcpStream, bytes: &[u8]) -> Vec<u8> {
    let mut writer = stream.try_clone().unwrap();
    let sent = bytes.to_vec();
    let sender = thread::spawn(move || writer.write_all(&sent).unwrap());
    let mut back = vec![0_u8; bytes.len()];
    stream.read_exact(&mut back).unwrap();
    join_within(sender, LIMIT, "the echo sender");
    back
}

/// Invariants 2 and 3: a `-L` forward whose guest stops reading while its
/// client keeps sending stops only that client, at the forward's own SSH
/// window. The terminal and another forward of the same ssh connection keep
/// flowing for longer than any former stall bound (16 s of traffic), the
/// jammed forward is never reset and its window stays used up, and once its
/// guest reads again every byte its client sent arrives in order.
#[test]
fn a_jammed_forward_stops_only_its_own_client() {
    require!("ssh");
    let world = World::new();
    let (stuck_port, recorded) = recording_service();
    let echo_port = endless_echo_service();
    world
        .fake
        .knobs
        .hold_port
        .store(stuck_port, Ordering::SeqCst);
    let (mut session, _stderr, ports) = forwarding(&world, 2, &[], |ports| {
        vec![
            "-tt".into(),
            "-L".into(),
            format!("127.0.0.1:{}:localhost:{stuck_port}", ports[0]),
            "-L".into(),
            format!("127.0.0.1:{}:localhost:{echo_port}", ports[1]),
            "sbx_1.wssp".into(),
        ]
    });
    let mut terminal = session.stdin.take().unwrap();
    let output = Collected::start_stdout(&mut session);
    let jam = Jam::start(&world, ports[0]);
    let held_frames = world.fake.knobs.held_frames.load(Ordering::SeqCst);
    let mut echo = connect_to(ports[1]);
    let started = Instant::now();
    let mut round = 0_u64;
    while started.elapsed() < Duration::from_secs(16) {
        round += 1;
        let bytes = payload(1024 * 1024, 200 + round);
        assert!(
            echo_round(&mut echo, &bytes) == bytes,
            "round {round}: the other forward changed bytes"
        );
        let mark = format!("tick-{round}-done");
        writeln!(terminal, "echo tick-{round}-'done'").unwrap();
        wait_until(LIMIT, "the terminal stopped answering", || {
            output.text().contains(&mark)
        });
        assert!(
            world.window_exhausted(jam.local),
            "round {round}: the jammed window moved"
        );
    }
    assert!(round >= 2, "{round} rounds");
    assert_eq!(
        world.fake.knobs.held_frames.load(Ordering::SeqCst),
        held_frames
    );
    let stuck_channel = channel_to(&world.fake, stuck_port).expect("the stuck forward opened");
    assert!(
        !client_closed(&world.fake, stuck_channel),
        "the jammed forward was reset"
    );
    // The stuck guest reads again: everything its client sent arrives.
    world.fake.knobs.hold_port.store(0, Ordering::SeqCst);
    let sent = jam.finish();
    let read = join_within(recorded, LIMIT, "the recording service");
    assert_eq!(read.len(), sent, "the jammed forward lost bytes");
    assert!(
        read.chunks(JAM_CHUNK)
            .all(|block| block == &jam_chunk()[..block.len()]),
        "the jammed forward's bytes changed"
    );
    // ssh waits for its forwarded connections before it exits.
    drop(echo);
    writeln!(terminal, "exit 0").unwrap();
    let status = exit_within(&mut session, LIMIT, "ssh");
    assert!(status.success(), "{}", output.text());
}

/// A guest service that writes `bytes` once `go` fires, then closes.
fn talking_service(bytes: Vec<u8>) -> (u16, mpsc::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (go, start) = mpsc::channel();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        if start.recv().is_ok() {
            let _ = stream.write_all(&bytes);
        }
        let _ = stream.shutdown(std::net::Shutdown::Both);
    });
    (port, go)
}

/// A forward whose guest stops reading while the client keeps sending uses
/// up its SSH window (observed directly); the output of another channel
/// keeps reaching the client meanwhile, and the jammed window stays used
/// up.
#[test]
fn a_jammed_forward_does_not_hold_another_channels_output() {
    require!("ssh");
    let world = World::new();
    let (stuck_port, _recorded) = recording_service();
    let reply = payload(512 * 1024, 31);
    let (talk_port, go) = talking_service(reply.clone());
    world
        .fake
        .knobs
        .hold_port
        .store(stuck_port, Ordering::SeqCst);
    let (_session, _stderr, ports) = forwarding(&world, 2, &[], |ports| {
        vec![
            "-N".into(),
            "-L".into(),
            format!("127.0.0.1:{}:localhost:{stuck_port}", ports[0]),
            "-L".into(),
            format!("127.0.0.1:{}:localhost:{talk_port}", ports[1]),
            "sbx_1.wssp".into(),
        ]
    });
    // The talking forward opens first (an open is input too).
    let mut talk = connect_to(ports[1]);
    wait_until(
        Duration::from_secs(30),
        "the talking forward never opened",
        || channel_to(&world.fake, talk_port).is_some(),
    );
    let jam = Jam::start(&world, ports[0]);
    // Only now the other guest talks: all of it reaches the client while
    // the jammed window stays used up.
    go.send(()).unwrap();
    let mut back = Vec::new();
    talk.read_to_end(&mut back).unwrap();
    assert_eq!(back.len(), reply.len());
    assert!(back == reply, "the talking forward's bytes changed");
    assert!(world.window_exhausted(jam.local), "the jammed window moved");
}

/// The ProxyCommand process holds exactly one socket, the WebSocket to the
/// server, and listens on nothing.
#[test]
fn the_endpoint_never_binds_or_listens_on_a_socket() {
    require!("ssh");
    let world = World::new();
    let mut ssh = world.ssh();
    ssh.args(["sbx_1.wssp", "sleep 20"]);
    let session = ManagedChild::spawn(&mut ssh).unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while world.fake.opens().is_empty() {
        assert!(Instant::now() < deadline, "the session never opened");
        thread::sleep(Duration::from_millis(20));
    }
    // The ProxyCommand: the `wssp` child of the ssh process (through `sh`
    // when ssh runs it with a shell).
    let ssh_pid = session.id();
    let endpoint = descendants(ssh_pid)
        .into_iter()
        .find(|pid| {
            std::fs::read_to_string(format!("/proc/{pid}/cmdline"))
                .is_ok_and(|cmdline| cmdline.contains("--stdio"))
                && std::fs::read_link(format!("/proc/{pid}/exe"))
                    .is_ok_and(|exe| exe.ends_with("wssp"))
        })
        .expect("no endpoint process");
    let mut sockets: Vec<String> = std::fs::read_dir(format!("/proc/{endpoint}/fd"))
        .unwrap()
        .filter_map(|entry| std::fs::read_link(entry.unwrap().path()).ok())
        .map(|target| target.display().to_string())
        .filter(|target| target.starts_with("socket:["))
        .map(|target| target["socket:[".len()..target.len() - 1].to_owned())
        .collect();
    // The connection keeps a second handle of its one socket (timeouts).
    sockets.sort();
    sockets.dedup();
    assert_eq!(sockets.len(), 1, "{sockets:?}");
    let table =
        |name: &str| std::fs::read_to_string(format!("/proc/{endpoint}/net/{name}")).unwrap();
    // TCP: the one socket is an established connection to the fake.
    let fake_port = world
        .fake
        .url
        .rsplit(':')
        .next()
        .unwrap()
        .parse::<u16>()
        .unwrap();
    let mut found = false;
    for name in ["tcp", "tcp6"] {
        for line in table(name).lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.get(9) == Some(&sockets[0].as_str()) {
                assert_eq!(fields[3], "01", "not established: {line}");
                let remote_port =
                    u16::from_str_radix(fields[2].rsplit(':').next().unwrap(), 16).unwrap();
                assert_eq!(remote_port, fake_port);
                found = true;
            }
        }
    }
    assert!(found, "the socket is not the TCP connection to the server");
    for name in ["udp", "udp6", "raw", "unix"] {
        for line in table(name).lines().skip(1) {
            assert!(
                !line.split_whitespace().any(|field| field == sockets[0]),
                "{name}: {line}"
            );
        }
    }
    drop(session);
}

fn descendants(pid: u32) -> Vec<u32> {
    let mut found = Vec::new();
    let mut frontier = vec![pid];
    while let Some(parent) = frontier.pop() {
        for entry in std::fs::read_dir("/proc").unwrap().flatten() {
            let Ok(child) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let Ok(stat) = std::fs::read_to_string(format!("/proc/{child}/stat")) else {
                continue;
            };
            let Some(rest) = stat.rsplit_once(") ").map(|(_, rest)| rest.to_owned()) else {
                continue;
            };
            let ppid = rest
                .split_whitespace()
                .nth(1)
                .and_then(|p| p.parse::<u32>().ok());
            if ppid == Some(parent) {
                found.push(child);
                frontier.push(child);
            }
        }
    }
    found
}

#[test]
fn wssp_ssh_runs_the_system_ssh_with_the_generated_options() {
    require!("ssh");
    let world = World::new();
    let mut command = Command::new(env!("CARGO_BIN_EXE_wssp"));
    wssp_env(&mut command, world.root.path(), &world.fake.url);
    command
        .args([
            "ssh",
            "sbx_1",
            "--",
            "-o",
            "BatchMode=yes",
            "echo via-wssp-ssh",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = run(command, None, LIMIT);
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert_eq!(text(&output.stdout), "via-wssp-ssh\n");
    // Its exact argv: `tests/ssh_config.rs`.
    // No ssh on PATH: a clear error.
    let mut command = Command::new(env!("CARGO_BIN_EXE_wssp"));
    wssp_env(&mut command, world.root.path(), &world.fake.url);
    command
        .env("PATH", world.path("empty"))
        .args(["ssh", "sbx_1"]);
    let output = command.output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output.stderr).contains("no `ssh` on `PATH`"));
}

// ------------------------------------------------------------ a russh client

/// A russh client speaking to `wssp ssh --stdio` directly over its stdio, for
/// the request-level checks OpenSSH does not expose (refusal replies, resizes
/// before `ready`, signals, a disconnect that keeps the pipe open).
mod direct {
    use super::*;
    use russh::client::{self, Handle};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    pub struct Accept;

    impl client::Handler for Accept {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            _key: &russh::keys::PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    pub struct Direct {
        pub child: ManagedChild,
        pub runtime: tokio::runtime::Runtime,
        pub handle: Handle<Accept>,
        /// The endpoint's stdin, kept open whatever the client does.
        pub _stdin: Arc<Mutex<Option<std::process::ChildStdin>>>,
    }

    /// Spawn the endpoint for `sbx_1.wssp` and log in.
    pub fn connect(world: &World, env: &[(&str, &str)]) -> Direct {
        let mut command = Command::new(env!("CARGO_BIN_EXE_wssp"));
        wssp_env(&mut command, world.root.path(), &world.fake.url);
        command.env("WSSP_TEST_SSH_NOTE_LOG", world.note_log());
        for (name, value) in env {
            command.env(name, value);
        }
        command
            .args(["ssh", "--stdio", "sbx_1.wssp"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = ManagedChild::spawn(&mut command).unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let stdin = Arc::new(Mutex::new(child.stdin.take()));
        let (client_io, bridge_io) = tokio::io::duplex(1 << 20);
        let (mut from_client, mut to_client) = tokio::io::split(bridge_io);
        // Endpoint stdout → client. Once the client is gone, keep reading
        // (and dropping) so the endpoint never sees a broken pipe.
        thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            let mut buffer = vec![0_u8; 64 * 1024];
            let mut open = true;
            while let Ok(n) = stdout.read(&mut buffer) {
                if n == 0 {
                    break;
                }
                if open {
                    open = runtime.block_on(to_client.write_all(&buffer[..n])).is_ok();
                }
            }
        });
        // Client → endpoint stdin; the pipe stays open after the client ends.
        let keep = stdin.clone();
        thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            let mut buffer = vec![0_u8; 64 * 1024];
            loop {
                let n = runtime.block_on(from_client.read(&mut buffer)).unwrap_or(0);
                if n == 0 {
                    return;
                }
                let mut stdin = keep.lock().unwrap();
                let Some(pipe) = stdin.as_mut() else { return };
                if pipe.write_all(&buffer[..n]).is_err() {
                    return;
                }
            }
        });
        // Worker threads drive the client's session task between the
        // test's steps (a current-thread runtime would only run it inside
        // `block_on`).
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_time()
            .build()
            .unwrap();
        let handle = runtime.block_on(login(client_io));
        Direct {
            child,
            runtime,
            handle,
            _stdin: stdin,
        }
    }

    /// The SSH handshake and a `none` login (the endpoint accepts it).
    async fn login(io: tokio::io::DuplexStream) -> Handle<Accept> {
        let mut handle = client::connect_stream(Arc::new(client::Config::default()), io, Accept)
            .await
            .expect("ssh handshake");
        let auth = handle.authenticate_none("anyone").await.unwrap();
        assert!(auth.success(), "{auth:?}");
        handle
    }

    /// Wait for the window adjust that brings `channel`'s send window to
    /// `size` (none other may come first).
    pub async fn window_reaches(channel: &mut russh::Channel<client::Msg>, size: u32) {
        loop {
            match tokio::time::timeout(Duration::from_secs(30), channel.wait()).await {
                Ok(Some(russh::ChannelMsg::WindowAdjusted { new_size })) => {
                    assert_eq!(new_size, size, "the channel's window");
                    return;
                }
                Ok(Some(_)) => {}
                Ok(None) => panic!("the channel ended"),
                Err(_) => panic!("no window adjust to {size} within 30 s"),
            }
        }
    }

    /// The next message of `channel` that is not window bookkeeping.
    pub async fn next(channel: &mut russh::Channel<client::Msg>) -> russh::ChannelMsg {
        loop {
            match tokio::time::timeout(Duration::from_secs(30), channel.wait()).await {
                Ok(Some(russh::ChannelMsg::WindowAdjusted { .. })) => {}
                Ok(Some(message)) => return message,
                Ok(None) => panic!("the channel ended"),
                Err(_) => panic!("no message within 30 s"),
            }
        }
    }
}

// ------------------------------------------------------------ a raw SSH client

/// A minimal SSH client for messages no real client sends (a stray open
/// reply, a channel with a window of 0): curve25519-sha256,
/// chacha20-poly1305@openssh.com, no compression, no `ext-info-c` and no
/// strict kex (sequence numbers run on from the cleartext packets), the
/// server's host key signature unchecked (as `direct::Accept`). It speaks
/// to the endpoint over its stdin and stdout.
///
/// Out of scope: a WINDOW_ADJUST past 2^32 - 1 (russh and the write half
/// saturate separately; a protocol violation only the client suffers).
mod raw {
    use super::*;
    use ring::aead::chacha20_poly1305_openssh::{KEY_LEN, OpeningKey, SealingKey, TAG_LEN};
    use ring::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, X25519};
    use ring::digest::{Context, SHA256};
    use ring::rand::SystemRandom;

    pub const DISCONNECT: u8 = 1;
    const IGNORE: u8 = 2;
    const DEBUG: u8 = 4;
    const KEXINIT: u8 = 20;
    const NEWKEYS: u8 = 21;
    const GLOBAL_REQUEST: u8 = 80;
    pub const OPEN: u8 = 90;
    pub const OPEN_CONFIRMATION: u8 = 91;
    pub const OPEN_FAILURE: u8 = 92;
    pub const WINDOW_ADJUST: u8 = 93;
    pub const DATA: u8 = 94;
    pub const EXTENDED_DATA: u8 = 95;
    pub const EOF: u8 = 96;
    pub const CLOSE: u8 = 97;
    pub const REQUEST: u8 = 98;
    pub const SUCCESS: u8 = 99;
    pub const FAILURE: u8 = 100;

    /// An SSH message under construction.
    #[derive(Default)]
    pub struct Msg(pub Vec<u8>);

    impl Msg {
        pub fn new(kind: u8) -> Self {
            Self(vec![kind])
        }
        pub fn u8(mut self, v: u8) -> Self {
            self.0.push(v);
            self
        }
        pub fn u32(mut self, v: u32) -> Self {
            self.0.extend_from_slice(&v.to_be_bytes());
            self
        }
        pub fn bytes(mut self, v: &[u8]) -> Self {
            self = self.u32(v.len() as u32);
            self.0.extend_from_slice(v);
            self
        }
        pub fn str(self, v: &str) -> Self {
            self.bytes(v.as_bytes())
        }
        /// A positive mpint from big-endian bytes.
        fn mpint(self, v: &[u8]) -> Self {
            let v = &v[v.iter().take_while(|b| **b == 0).count()..];
            if v.first().is_some_and(|b| b & 0x80 != 0) {
                self.bytes(&[&[0][..], v].concat())
            } else {
                self.bytes(v)
            }
        }
    }

    /// Reads the fields of a received message.
    pub struct Fields<'a>(pub &'a [u8]);

    impl<'a> Fields<'a> {
        pub fn u8(&mut self) -> u8 {
            let (v, rest) = self.0.split_first().expect("a byte");
            self.0 = rest;
            *v
        }
        pub fn u32(&mut self) -> u32 {
            let (v, rest) = self.0.split_at(4);
            self.0 = rest;
            u32::from_be_bytes(v.try_into().unwrap())
        }
        pub fn bytes(&mut self) -> &'a [u8] {
            let n = self.u32() as usize;
            let (v, rest) = self.0.split_at(n);
            self.0 = rest;
            v
        }
    }

    pub struct Raw {
        pub child: ManagedChild,
        stdin: std::process::ChildStdin,
        /// The endpoint's stdout, as it arrives (`None`: it ended).
        out: mpsc::Receiver<Option<Vec<u8>>>,
        buffer: VecDeque<u8>,
        ended: bool,
        seq_out: u32,
        seq_in: u32,
        seal: Option<SealingKey>,
        open: Option<OpeningKey>,
    }

    fn sha256(parts: &[&[u8]]) -> Vec<u8> {
        let mut context = Context::new(&SHA256);
        for part in parts {
            context.update(part);
        }
        context.finish().as_ref().to_vec()
    }

    /// RFC 4253 7.2: a 64-byte key for `letter`.
    fn derive(k: &[u8], h: &[u8], letter: u8, session_id: &[u8]) -> [u8; KEY_LEN] {
        let k1 = sha256(&[k, h, &[letter], session_id]);
        let k2 = sha256(&[k, h, &k1]);
        [k1, k2].concat().try_into().unwrap()
    }

    impl Raw {
        /// Spawn the endpoint for `sbx_1.wssp`, exchange keys and log in.
        pub fn connect(world: &World) -> Raw {
            let mut command = Command::new(env!("CARGO_BIN_EXE_wssp"));
            wssp_env(&mut command, world.root.path(), &world.fake.url);
            command.env("WSSP_TEST_SSH_NOTE_LOG", world.note_log());
            command
                .args(["ssh", "--stdio", "sbx_1.wssp"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null());
            let mut child = ManagedChild::spawn(&mut command).unwrap();
            let mut stdout = child.stdout.take().unwrap();
            let stdin = child.stdin.take().unwrap();
            let (send, out) = mpsc::channel();
            thread::spawn(move || {
                let mut buffer = vec![0_u8; 64 * 1024];
                loop {
                    match stdout.read(&mut buffer) {
                        Ok(0) | Err(_) => {
                            let _ = send.send(None);
                            return;
                        }
                        Ok(n) => {
                            if send.send(Some(buffer[..n].to_vec())).is_err() {
                                return;
                            }
                        }
                    }
                }
            });
            let mut raw = Raw {
                child,
                stdin,
                out,
                buffer: VecDeque::new(),
                ended: false,
                seq_out: 0,
                seq_in: 0,
                seal: None,
                open: None,
            };
            raw.handshake();
            raw
        }

        /// Wait until `n` bytes are buffered, at the latest until
        /// `deadline`; `false` once the endpoint's stdout ended.
        fn fill(&mut self, n: usize, deadline: Instant) -> bool {
            while self.buffer.len() < n {
                if self.ended {
                    return false;
                }
                let left = deadline.saturating_duration_since(Instant::now());
                match self.out.recv_timeout(left) {
                    Ok(Some(bytes)) => self.buffer.extend(bytes),
                    Ok(None) | Err(mpsc::RecvTimeoutError::Disconnected) => self.ended = true,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        panic!("the endpoint sent nothing more by the deadline")
                    }
                }
            }
            true
        }

        fn take(&mut self, n: usize) -> Vec<u8> {
            self.buffer.drain(..n).collect()
        }

        fn write(&mut self, bytes: &[u8]) {
            self.stdin.write_all(bytes).unwrap();
            self.stdin.flush().unwrap();
        }

        /// Send one message.
        pub fn send(&mut self, msg: Msg) {
            let payload = msg.0;
            // Cleartext packets align with the length field, chacha's without.
            let aligned = if self.seal.is_some() { 1 } else { 5 };
            let mut padding = 8 - (aligned + payload.len()) % 8;
            if padding < 4 {
                padding += 8;
            }
            let length = 1 + payload.len() + padding;
            let mut packet = Vec::with_capacity(4 + length + TAG_LEN);
            packet.extend_from_slice(&(length as u32).to_be_bytes());
            packet.push(padding as u8);
            packet.extend_from_slice(&payload);
            packet.extend(std::iter::repeat_n(0, padding));
            if let Some(seal) = &self.seal {
                let mut tag = [0; TAG_LEN];
                seal.seal_in_place(self.seq_out, &mut packet, &mut tag);
                packet.extend_from_slice(&tag);
            }
            self.seq_out = self.seq_out.wrapping_add(1);
            self.write(&packet);
        }

        /// The next message, by `deadline`; `None` once the endpoint's
        /// stdout ended.
        pub fn recv_until(&mut self, deadline: Instant) -> Option<Vec<u8>> {
            if !self.fill(4, deadline) {
                return None;
            }
            let head: [u8; 4] = self.take(4).try_into().unwrap();
            let seq = self.seq_in;
            self.seq_in = self.seq_in.wrapping_add(1);
            let (length, mut body) = match &self.open {
                None => (u32::from_be_bytes(head) as usize, Vec::new()),
                Some(open) => {
                    let length = u32::from_be_bytes(open.decrypt_packet_length(seq, head)) as usize;
                    (length, head.to_vec())
                }
            };
            let tag_len = if self.open.is_some() { TAG_LEN } else { 0 };
            assert!(self.fill(length + tag_len, deadline), "a cut packet");
            body.extend(self.take(length));
            let tag = self.take(tag_len);
            let plain = match &self.open {
                None => body,
                Some(open) => {
                    let tag: [u8; TAG_LEN] = tag.try_into().unwrap();
                    open.open_in_place(seq, &mut body, &tag)
                        .expect("a packet that authenticates")
                        .to_vec()
                }
            };
            let padding = plain[0] as usize;
            Some(plain[1..plain.len() - padding].to_vec())
        }

        /// The next message that is not transport chatter or a window
        /// adjust, by `deadline`; `None` once the endpoint's stdout ended.
        pub fn next_until(&mut self, deadline: Instant) -> Option<Vec<u8>> {
            loop {
                let msg = self.recv_until(deadline)?;
                if ![IGNORE, DEBUG, GLOBAL_REQUEST, WINDOW_ADJUST].contains(&msg[0]) {
                    return Some(msg);
                }
            }
        }

        pub fn next(&mut self) -> Vec<u8> {
            self.next_until(Instant::now() + Duration::from_secs(10))
                .expect("the endpoint ended the session")
        }

        fn kexinit() -> Msg {
            let mut cookie = [0_u8; 16];
            ring::rand::SecureRandom::fill(&SystemRandom::new(), &mut cookie).unwrap();
            let mut msg = Msg::new(KEXINIT);
            msg.0.extend_from_slice(&cookie);
            msg.str("curve25519-sha256")
                .str("ssh-ed25519")
                .str("chacha20-poly1305@openssh.com")
                .str("chacha20-poly1305@openssh.com")
                .str("hmac-sha2-256-etm@openssh.com")
                .str("hmac-sha2-256-etm@openssh.com")
                .str("none")
                .str("none")
                .str("")
                .str("")
                .u8(0)
                .u32(0)
        }

        fn handshake(&mut self) {
            let deadline = Instant::now() + Duration::from_secs(20);
            let v_c = b"SSH-2.0-wssp_raw_test";
            self.write(&[&v_c[..], b"\r\n"].concat());
            let v_s = loop {
                let mut line = Vec::new();
                loop {
                    assert!(self.fill(1, deadline), "no version line");
                    let byte = self.take(1)[0];
                    line.push(byte);
                    if byte == b'\n' {
                        break;
                    }
                }
                if line.starts_with(b"SSH-") {
                    let end = line.len() - if line.ends_with(b"\r\n") { 2 } else { 1 };
                    break line[..end].to_vec();
                }
            };
            let i_c = Self::kexinit().0;
            self.send(Msg(i_c.clone()));
            let i_s = self.recv_until(deadline).expect("KEXINIT");
            assert_eq!(i_s[0], KEXINIT);
            let rng = SystemRandom::new();
            let private = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
            let q_c = private.compute_public_key().unwrap().as_ref().to_vec();
            self.send(Msg::new(30).bytes(&q_c));
            let reply = self.recv_until(deadline).expect("ECDH reply");
            assert_eq!(reply[0], 31, "KEX_ECDH_REPLY");
            let mut fields = Fields(&reply[1..]);
            let k_s = fields.bytes().to_vec();
            let q_s = fields.bytes().to_vec();
            let shared =
                agreement::agree_ephemeral(private, &UnparsedPublicKey::new(&X25519, &q_s), |k| {
                    k.to_vec()
                })
                .unwrap();
            let k = Msg::default().mpint(&shared).0;
            let hashed = Msg::default()
                .bytes(v_c)
                .bytes(&v_s)
                .bytes(&i_c)
                .bytes(&i_s)
                .bytes(&k_s)
                .bytes(&q_c)
                .bytes(&q_s)
                .0;
            let h = sha256(&[&hashed, &k]);
            self.send(Msg::new(NEWKEYS));
            self.seal = Some(SealingKey::new(&derive(&k, &h, b'C', &h)));
            let newkeys = self.recv_until(deadline).expect("NEWKEYS");
            assert_eq!(newkeys, [NEWKEYS]);
            self.open = Some(OpeningKey::new(&derive(&k, &h, b'D', &h)));
            self.send(Msg::new(5).str("ssh-userauth"));
            let accept = self.next_until(deadline).expect("SERVICE_ACCEPT");
            assert_eq!(accept[0], 6, "SERVICE_ACCEPT");
            self.send(Msg::new(50).str("anyone").str("ssh-connection").str("none"));
            loop {
                match self.next_until(deadline).expect("USERAUTH_SUCCESS")[0] {
                    52 => break,
                    53 => {}
                    other => panic!("message {other} instead of USERAUTH_SUCCESS"),
                }
            }
        }

        /// Open a session channel (our id `ours`) with `window`; returns the
        /// endpoint's id for it.
        pub fn open_session(&mut self, ours: u32, window: u32) -> u32 {
            self.send(
                Msg::new(OPEN)
                    .str("session")
                    .u32(ours)
                    .u32(window)
                    .u32(32 * 1024),
            );
            let reply = self.next();
            assert_eq!(reply[0], OPEN_CONFIRMATION, "{reply:?}");
            let mut fields = Fields(&reply[1..]);
            assert_eq!(fields.u32(), ours);
            fields.u32()
        }

        /// A want-reply request on the endpoint's channel `theirs`: its
        /// reply (stderr before it is skipped).
        pub fn request(&mut self, theirs: u32, kind: &str, args: Msg) -> Vec<u8> {
            let mut msg = Msg::new(REQUEST).u32(theirs).str(kind).u8(1);
            msg.0.extend_from_slice(&args.0);
            self.send(msg);
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let reply = self.next_until(deadline).expect("a reply");
                if reply[0] != EXTENDED_DATA {
                    return reply;
                }
            }
        }

        /// Run `command` on the endpoint's channel `theirs` (our id `ours`):
        /// its stdout and exit status, in the order the endpoint keeps for a
        /// natural end (exit status, then EOF, then CLOSE; stderr anywhere).
        pub fn exec(&mut self, ours: u32, theirs: u32, command: &str) -> (Vec<u8>, u32) {
            let reply = self.request(theirs, "exec", Msg::default().str(command));
            assert_eq!(reply[0], SUCCESS, "{reply:?}");
            let (mut out, mut status, mut eof) = (Vec::new(), None, false);
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                let msg = self.next_until(deadline).expect("the command's end");
                // Stderr of any channel (a refusal's line comes on its own).
                if msg[0] == EXTENDED_DATA {
                    continue;
                }
                let mut fields = Fields(&msg[1..]);
                if msg[0] != DISCONNECT {
                    assert_eq!(fields.u32(), ours, "{msg:?}");
                }
                match msg[0] {
                    DATA => out.extend_from_slice(fields.bytes()),
                    REQUEST if fields.bytes() == b"exit-status" => {
                        fields.u8();
                        status = Some(fields.u32());
                    }
                    EOF => {
                        assert!(status.is_some(), "EOF before the exit status");
                        eof = true;
                    }
                    CLOSE => {
                        assert!(eof, "CLOSE before EOF");
                        self.send(Msg::new(CLOSE).u32(theirs));
                        return (out, status.expect("an exit status"));
                    }
                    other => panic!("message {other} on the channel"),
                }
            }
        }
    }
}

/// The endpoint's test notes so far.
fn notes(world: &World) -> String {
    std::fs::read_to_string(world.note_log()).unwrap_or_default()
}

/// A refusal on a channel whose window cannot take its stderr line (here a
/// window of 0) leaves nothing queued in russh, where it would hold back
/// every channel's output (russh sends none while any channel has output
/// queued; with 0.65.2 even past the client's close, 951bfb5): the line
/// waits for the window in the endpoint, the session's other channels keep
/// running, and the client's close is answered at once.
#[test]
fn a_refusal_the_window_cannot_take_holds_back_no_other_channel() {
    let world = World::new();
    let mut raw = raw::Raw::connect(&world);
    let theirs = raw.open_session(0, 0);
    let reply = raw.request(theirs, "subsystem", raw::Msg::default().str("nope"));
    assert_eq!(reply, raw::Msg::new(raw::FAILURE).u32(0).0);
    let other = raw.open_session(1, 1 << 20);
    assert_eq!(raw.exec(1, other, "echo fine"), (b"fine\n".to_vec(), 0));
    raw.send(raw::Msg::new(raw::CLOSE).u32(theirs));
    assert_eq!(
        raw.next(),
        raw::Msg::new(raw::CLOSE).u32(0).0,
        "the close was not answered"
    );
    wait_until(
        Duration::from_secs(10),
        "the endpoint kept the channel",
        || notes(&world).lines().any(|line| line == "forgot 1"),
    );
}

/// A request the endpoint refuses (it writes why to the channel's stderr)
/// ends the channel's chance to start: a later request on it is refused
/// too and starts nothing, so the line russh sent past the channel's write
/// half can never hold back that write half's output. Sending past its
/// window still resets it, and the endpoint forgets it (its slot comes
/// back). Other channels work.
#[test]
fn a_refused_request_ends_the_channels_chance_to_start() {
    let world = World::new();
    let mut raw = raw::Raw::connect(&world);
    let theirs = raw.open_session(0, 1 << 20);
    let reply = raw.request(theirs, "subsystem", raw::Msg::default().str("nope"));
    assert_eq!(reply, raw::Msg::new(raw::FAILURE).u32(0).0);
    // The why comes right after the failure, within the window.
    let why = raw.next();
    let mut fields = raw::Fields(&why[1..]);
    assert_eq!(
        (why[0], fields.u32(), fields.u32()),
        (raw::EXTENDED_DATA, 0, 1)
    );
    assert_eq!(
        fields.bytes(),
        b"wssp: only the sftp subsystem is available\r\n"
    );
    let reply = raw.request(theirs, "exec", raw::Msg::default().str("echo started"));
    assert_eq!(reply, raw::Msg::new(raw::FAILURE).u32(0).0);
    assert!(world.fake.opens().is_empty(), "the refused channel started");
    // 160 KiB past the 128 KiB the open granted.
    for _ in 0..5 {
        raw.send(raw::Msg::new(raw::DATA).u32(theirs).bytes(&[7; 32 * 1024]));
    }
    assert_eq!(
        raw.next(),
        raw::Msg::new(raw::CLOSE).u32(0).0,
        "the overrun channel stayed open"
    );
    raw.send(raw::Msg::new(raw::CLOSE).u32(theirs));
    wait_until(
        Duration::from_secs(10),
        "the endpoint kept the overrun channel",
        || notes(&world).lines().any(|line| line == "forgot 1"),
    );
    let other = raw.open_session(1, 1 << 20);
    assert_eq!(raw.exec(1, other, "echo fine"), (b"fine\n".to_vec(), 0));
    assert_eq!(world.fake.opens().len(), 1);
}

/// A CHANNEL_OPEN_FAILURE for a channel that is open (no reply to an open
/// of the endpoint's, which opens none) is ignored: the channel keeps
/// working on both sides (russh 0.65.4, 0e033c0; 0.65.2 dropped it from its
/// table behind the endpoint's back and then ended the session).
#[test]
fn a_stray_open_failure_for_an_open_channel_changes_nothing() {
    let world = World::new();
    let mut raw = raw::Raw::connect(&world);
    let theirs = raw.open_session(0, 1 << 20);
    raw.send(
        raw::Msg::new(raw::OPEN_FAILURE)
            .u32(theirs)
            .u32(2)
            .str("")
            .str(""),
    );
    assert_eq!(raw.exec(0, theirs, "echo fine"), (b"fine\n".to_vec(), 0));
    let other = raw.open_session(1, 1 << 20);
    assert_eq!(raw.exec(1, other, "echo again"), (b"again\n".to_vec(), 0));
}

/// A CHANNEL_OPEN_CONFIRMATION for a channel that is open would rewrite
/// its window and packet size: russh ends the session instead (0.65.4,
/// 0e033c0), and the endpoint ends cleanly with it, its guest command too.
#[test]
fn a_stray_open_confirmation_ends_the_session_cleanly() {
    let world = World::new();
    let mut raw = raw::Raw::connect(&world);
    let theirs = raw.open_session(0, 1 << 20);
    let reply = raw.request(theirs, "exec", raw::Msg::default().str("sleep 86400"));
    assert_eq!(reply, raw::Msg::new(raw::SUCCESS).u32(0).0);
    let guest = world.guest();
    wait_until(
        Duration::from_secs(20),
        "the guest command never ran",
        || guest_program_running(&guest, &["sleep", "86400"]),
    );
    let ClientControl::Open { channel, .. } = world.fake.opens()[0].clone() else {
        unreachable!()
    };
    raw.send(
        raw::Msg::new(raw::OPEN_CONFIRMATION)
            .u32(theirs)
            .u32(7)
            .u32(0)
            .u32(32 * 1024),
    );
    // One bound for the end of the session and of the endpoint.
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match raw.next_until(deadline) {
            None => break,
            Some(msg) if msg[0] == raw::DISCONNECT => break,
            Some(_) => {}
        }
    }
    exit_within(
        &mut raw.child,
        deadline.saturating_duration_since(Instant::now()),
        "the endpoint after the stray confirmation",
    );
    assert!(
        client_closed(&world.fake, channel),
        "the wssp channel stayed"
    );
}

/// A client that stops reading a forward until its window is used up and
/// then closes it (the user gives up on it): ssh sends EOF and CLOSE at
/// once (its write to the reset socket fails), the endpoint answers the
/// close at once and closes the wssp channel, and forgets the channel; the
/// connection's other forward keeps working.
#[test]
fn a_client_closing_a_jammed_forward_frees_it_on_both_sides() {
    require!("ssh");
    let world = World::new();
    let flood_port = flooding_service(256 * 1024 * 1024);
    let (echo_port, _echo) = echo_service();
    let (_session, stderr, ports) = forwarding(&world, 2, &[], |ports| {
        vec![
            "-vv".into(),
            "-N".into(),
            "-L".into(),
            format!("127.0.0.1:{}:localhost:{flood_port}", ports[0]),
            "-L".into(),
            format!("127.0.0.1:{}:localhost:{echo_port}", ports[1]),
            "sbx_1.wssp".into(),
        ]
    });
    let client = connect_to(ports[0]);
    wait_until(
        Duration::from_secs(30),
        "the forward's writer never waited for window",
        || {
            world.writer_blocked() && world.fake.knobs.out_full.load(Ordering::SeqCst) > 0 && {
                thread::sleep(Duration::from_millis(300));
                world.writer_blocked()
            }
        },
    );
    let flood_channel = channel_to(&world.fake, flood_port).expect("the forward opened");
    let text = stderr.text();
    let (closes, frees) = (
        text.matches("rcvd close").count(),
        text.matches(": free:").count(),
    );
    // Unread data in the socket's receive queue: closing it sends a reset.
    drop(client);
    wait_until(
        Duration::from_secs(10),
        "the endpoint never answered the close",
        || {
            let text = stderr.text();
            text.matches("rcvd close").count() > closes && text.matches(": free:").count() > frees
        },
    );
    wait_until(
        Duration::from_secs(10),
        "the wssp channel stayed open",
        || client_closed(&world.fake, flood_channel),
    );
    let mut echo = connect_to(ports[1]);
    let bytes = payload(256 * 1024, 77);
    assert!(
        round_trip(&mut echo, &bytes) == bytes,
        "the other forward changed bytes"
    );
    // The forward's open reaps an entry its writer retired first.
    assert!(
        notes(&world).lines().any(|line| line == "forgot 1"),
        "{}",
        notes(&world)
    );
}

// ------------------------------------------------------------ jams, aborts, ends

/// The bytes a [`Jam`] writes, over and over.
const JAM_CHUNK: usize = 64 * 1024;

fn jam_chunk() -> Vec<u8> {
    payload(JAM_CHUNK, 32)
}

/// A client that writes without end into a forward whose guest reads
/// nothing, until that forward's SSH window is used up (the fake holds the
/// channel's whole stdin window, frames counted, and the endpoint noted the
/// channel's window used up).
struct Jam {
    stream: TcpStream,
    /// The endpoint's key of the jammed channel.
    local: u64,
    stop: Arc<AtomicBool>,
    sent: Arc<AtomicUsize>,
    writer: thread::JoinHandle<()>,
}

impl Jam {
    fn start(world: &World, port: u16) -> Self {
        let before = world.exhausted_channels();
        let stream = connect_to(port);
        let stop = Arc::new(AtomicBool::new(false));
        let sent = Arc::new(AtomicUsize::new(0));
        let writer = {
            let mut stream = stream.try_clone().unwrap();
            let (stop, sent) = (stop.clone(), sent.clone());
            thread::spawn(move || {
                let chunk = jam_chunk();
                while !stop.load(Ordering::SeqCst) && stream.write_all(&chunk).is_ok() {
                    sent.fetch_add(chunk.len(), Ordering::SeqCst);
                }
            })
        };
        let mut local = None;
        wait_until(
            Duration::from_secs(30),
            "the jammed forward's window was never used up",
            || {
                local = world
                    .exhausted_channels()
                    .into_iter()
                    .find(|local| !before.contains(local) && world.window_exhausted(*local));
                local.is_some() && world.fake.knobs.held_frames.load(Ordering::SeqCst) >= 32
            },
        );
        Self {
            stream,
            local: local.unwrap_or_default(),
            stop,
            sent,
            writer,
        }
    }

    /// Stop writing (the guest must read again first) and close the
    /// client's side; the bytes sent.
    fn finish(self) -> usize {
        self.stop.store(true, Ordering::SeqCst);
        join_within(self.writer, LIMIT, "the jammed writer");
        self.stream.shutdown(std::net::Shutdown::Write).unwrap();
        self.sent.load(Ordering::SeqCst)
    }
}

/// Invariant 4: ssh dies while one of its forwards is jammed; the endpoint
/// still sees the end of its stdin and ends within its teardown bound.
#[test]
fn ssh_killed_while_a_forward_is_jammed_ends_the_endpoint_within_the_bound() {
    require!("ssh");
    let world = World::new();
    let (stuck_port, _recorded) = recording_service();
    world
        .fake
        .knobs
        .hold_port
        .store(stuck_port, Ordering::SeqCst);
    let (mut session, _stderr, ports) = forwarding(&world, 1, &[], |ports| {
        vec![
            "-N".into(),
            "-L".into(),
            format!("127.0.0.1:{}:localhost:{stuck_port}", ports[0]),
            "sbx_1.wssp".into(),
        ]
    });
    let endpoint = endpoint_of(session.id());
    let _jam = Jam::start(&world, ports[0]);
    signal(session.id(), rustix::process::Signal::KILL);
    let _ = session.wait();
    wait_until(
        Duration::from_secs(10),
        "the endpoint outlived its ssh client",
        || gone(endpoint),
    );
}

/// An ssh whose ProxyCommand pipes the endpoint's stdout through `cat`, so
/// that stopping `cat` blocks the endpoint's stdout while ssh lives. `cat`
/// runs in its own session: a stopped process left in the endpoint's
/// process group would get the kernel's orphaned-group SIGHUP once ssh is
/// gone, which would end the endpoint for the wrong reason.
///
/// ssh's own stdout is read all along, so ssh keeps granting its session
/// window and the only thing that stops the guest's output is the stopped
/// `cat`. Unread, that window (2 MiB in OpenSSH) runs out a few tens of
/// milliseconds into `yes`, after which nothing more is in flight: stopping
/// `cat` later then blocks no write, or blocks the endpoint's stdout with
/// too little behind it to fill the transport.
struct PipedProxy {
    session: ManagedChild,
    endpoint: u32,
    cat: u32,
    /// Reads ssh's stdout until ssh is gone.
    output: thread::JoinHandle<()>,
}

impl PipedProxy {
    fn spawn(world: &World, args: &[String]) -> Self {
        Self::spawn_with(world, args, Stdio::null())
    }

    /// With ssh's own stdin `stdin` (piped: the test uploads through it).
    fn spawn_with(world: &World, args: &[String], stdin: Stdio) -> Self {
        let proxy = format!(
            "ProxyCommand=\"{}\" ssh --stdio %n | setsid cat",
            wssp_exe().display()
        );
        let mut ssh = world.ssh();
        ssh.args(["-o", &proxy]).args(args).stdin(stdin);
        let mut session = ManagedChild::spawn(&mut ssh).unwrap();
        let output = {
            let mut stdout = session.stdout.take().unwrap();
            thread::spawn(move || {
                let mut chunk = vec![0_u8; 64 * 1024];
                while stdout.read(&mut chunk).is_ok_and(|n| n > 0) {}
            })
        };
        let endpoint = endpoint_of(session.id());
        let mut cat = None;
        wait_until(
            Duration::from_secs(20),
            "no cat in the ProxyCommand",
            || {
                cat = descendants(session.id()).into_iter().find(|pid| {
                    std::fs::read_to_string(format!("/proc/{pid}/comm"))
                        .is_ok_and(|comm| comm.trim() == "cat")
                });
                cat.is_some()
            },
        );
        Self {
            session,
            endpoint,
            cat: cat.unwrap_or_default(),
            output,
        }
    }

    /// Stop `cat` and wait until the endpoint's stdout write blocks.
    fn block_stdout(&self) {
        signal(self.cat, rustix::process::Signal::STOP);
        wait_until(
            Duration::from_secs(30),
            "the endpoint's stdout never blocked",
            || blocked_in(self.endpoint, WRITE_SYSCALL, "0x1"),
        );
    }

    /// Let `cat` go and wait for ssh.
    fn release(mut self) {
        signal(self.cat, rustix::process::Signal::CONT);
        signal(self.session.id(), rustix::process::Signal::TERM);
        let _ = exit_within(&mut self.session, Duration::from_secs(20), "ssh");
        join_within(self.output, LIMIT, "the reader of ssh's stdout");
    }
}

/// Invariants 1 and 4: ssh stops reading the endpoint's stdout (a stopped
/// process between them) while the guest writes, so the endpoint's stdout
/// write blocks; a revocation still ends the endpoint within its bound
/// (nothing flushes or locks the blocked stdout on the way out).
#[test]
fn a_revocation_ends_the_endpoint_while_its_stdout_is_blocked() {
    require!("ssh");
    let world = World::new();
    let proxy = PipedProxy::spawn(&world, &["sbx_1.wssp".into(), "yes".into()]);
    wait_until(Duration::from_secs(20), "the session never opened", || {
        !world.fake.opens().is_empty()
    });
    proxy.block_stdout();
    world.fake.end_all(Intent::Revoked);
    let revoked = Instant::now();
    wait_until(
        Duration::from_secs(15),
        "the endpoint hung on its blocked stdout",
        || gone(proxy.endpoint),
    );
    let took = revoked.elapsed();
    proxy.release();
    // One teardown deadline (5 s) from the revocation.
    assert!(took < Duration::from_secs(10), "{took:?}");
}

/// Invariants 4 and 5: the endpoint's stdout is blocked (russh waits for
/// that write) and its stdin closes (ssh is gone): the stdin pump still sees
/// the end, and the endpoint ends within its teardown bound instead of
/// living on behind the blocked write while the wssp connection stays
/// healthy.
#[test]
fn the_end_of_stdin_ends_the_endpoint_while_its_stdout_is_blocked() {
    require!("ssh");
    let world = World::new();
    let proxy = PipedProxy::spawn(&world, &["sbx_1.wssp".into(), "yes".into()]);
    wait_until(Duration::from_secs(20), "the session never opened", || {
        !world.fake.opens().is_empty()
    });
    proxy.block_stdout();
    // ssh holds the only writer of the endpoint's stdin.
    signal(proxy.session.id(), rustix::process::Signal::KILL);
    let closed = Instant::now();
    wait_until(
        Duration::from_secs(15),
        "the endpoint never saw the end of its stdin",
        || gone(proxy.endpoint),
    );
    let took = closed.elapsed();
    let channel = match world.fake.opens()[0] {
        ClientControl::Open { channel, .. } => channel,
        _ => unreachable!(),
    };
    proxy.release();
    // One shared deadline: TEARDOWN (5 s) from the end of stdin, not one per
    // step (2 s drain + 4 s for the channels + 5 s for the final line).
    assert!(took < Duration::from_millis(6500), "{took:?}");
    // Its channel was closed on the way out (within the deadline).
    assert!(client_closed(&world.fake, channel));
}

/// Invariants 4 and 5, behind a full read-ahead: the endpoint's stdout is
/// blocked, so russh reads none of its input, and ssh uploads to a guest
/// that reads nothing until the stdin pump's read-ahead is full and the
/// pump reads no more. ssh dies: the hang-up of stdin, behind bytes nobody
/// read, still ends the endpoint within its teardown bound, and the guest
/// channel is released.
#[test]
fn the_end_of_stdin_behind_a_full_read_ahead_ends_the_endpoint() {
    require!("ssh");
    let world = World::new();
    world.fake.knobs.hold_stdin.store(true, Ordering::SeqCst);
    let mut proxy =
        PipedProxy::spawn_with(&world, &["sbx_1.wssp".into(), "yes".into()], Stdio::piped());
    let mut upload = proxy.session.stdin.take().unwrap();
    wait_until(Duration::from_secs(20), "the session never opened", || {
        !world.fake.opens().is_empty()
    });
    proxy.block_stdout();
    // The upload starts only once russh is stuck writing `yes`'s output to
    // the full transport and so reads none of its input: an upload that
    // arrived earlier would be taken by russh up to the SSH window, which
    // the holding guest never refills, and the read-ahead would never fill.
    // The transport does fill: ssh's stdout is read, so its session window
    // outlasts everything between russh and the stopped `cat`.
    wait_until(
        Duration::from_secs(30),
        "the transport never filled",
        || world.last_note_is("transport full", "transport open"),
    );
    let writer = thread::spawn(move || {
        let chunk = payload(64 * 1024, 41);
        while upload.write_all(&chunk).is_ok() {}
    });
    wait_until(
        Duration::from_secs(30),
        "the stdin pump's read-ahead never filled",
        || world.last_note_is("read-ahead full", "read-ahead open"),
    );
    // ssh holds the only writer of the endpoint's stdin.
    signal(proxy.session.id(), rustix::process::Signal::KILL);
    let closed = Instant::now();
    wait_until(
        Duration::from_secs(15),
        "the endpoint never saw the end of its stdin behind its read-ahead",
        || gone(proxy.endpoint),
    );
    let took = closed.elapsed();
    let channel = match world.fake.opens()[0] {
        ClientControl::Open { channel, .. } => channel,
        _ => unreachable!(),
    };
    proxy.release();
    join_within(writer, LIMIT, "the upload");
    // TEARDOWN (5 s) from the hang-up.
    assert!(took < Duration::from_millis(6500), "{took:?}");
    assert!(client_closed(&world.fake, channel));
}

/// The endpoint's channel writes waiting right now: the `blocked` notes
/// since the last `unblocked` one.
fn writers_waiting(world: &World) -> usize {
    let log = std::fs::read_to_string(world.note_log()).unwrap_or_default();
    log.lines()
        .rev()
        .take_while(|line| *line != "unblocked")
        .filter(|line| *line == "blocked")
        .count()
}

/// Invariants 4 and 6: the transport stays blocked (stdout unread) past
/// `FINAL_WRITE` while one channel floods russh's session queue and another
/// ends naturally: its last messages cannot be queued, so instead of
/// leaving that channel open with nothing left to end it, the whole session
/// ends within the bound. The guest command ends only when the test says
/// so, once the transport and the session queue are seen full.
#[test]
fn a_last_message_that_cannot_be_queued_ends_the_session_within_the_bound() {
    require!("ssh");
    let world = World::new();
    let flood_port = flooding_service(256 * 1024 * 1024);
    let (talk_port, talk) = talking_service(b"probe".to_vec());
    let ports = free_ports(2);
    let go = world.path("go");
    let command = format!("while [ ! -e '{}' ]; do sleep 0.05; done", go.display());
    let proxy = PipedProxy::spawn(
        &world,
        &[
            "-o".into(),
            "ExitOnForwardFailure=yes".into(),
            "-L".into(),
            format!("127.0.0.1:{}:localhost:{flood_port}", ports[0]),
            "-L".into(),
            format!("127.0.0.1:{}:localhost:{talk_port}", ports[1]),
            "sbx_1.wssp".into(),
            command,
        ],
    );
    wait_until(Duration::from_secs(20), "the session never opened", || {
        !world.fake.opens().is_empty()
    });
    let mut flood = None;
    wait_until(
        Duration::from_secs(20),
        "the forward never listened",
        || {
            flood = TcpStream::connect(("127.0.0.1", ports[0])).ok();
            flood.is_some()
        },
    );
    let _probe = connect_to(ports[1]);
    // Both forwards open while the transport flows (an open is a message
    // too).
    wait_until(Duration::from_secs(20), "the forwards never opened", || {
        channel_to(&world.fake, flood_port).is_some()
            && channel_to(&world.fake, talk_port).is_some()
    });
    // The flood is read, so its SSH window never runs out: what stops it is
    // the transport.
    let drain = {
        let mut flood = flood.take().unwrap();
        thread::spawn(move || {
            let mut chunk = vec![0_u8; 64 * 1024];
            while flood.read(&mut chunk).is_ok_and(|n| n > 0) {}
        })
    };
    proxy.block_stdout();
    // russh's side of the transport is full (the stdout pump is held by the
    // blocked stdout), so russh drains its session queue no more...
    wait_until(
        Duration::from_secs(30),
        "the transport never filled",
        || world.last_note_is("transport full", "transport open"),
    );
    // ...and the flood waits.
    wait_until(Duration::from_secs(30), "the flood never waited", || {
        writers_waiting(&world) >= 1
    });
    // A channel with all of its SSH window waits as well: the session queue
    // is full.
    talk.send(()).unwrap();
    wait_until(
        Duration::from_secs(30),
        "the session queue never filled",
        || writers_waiting(&world) >= 2,
    );
    // Only now the guest command ends; its exit status and eof wait for the
    // session queue, then the session ends: within FINAL_WRITE + TEARDOWN.
    std::fs::write(&go, b"").unwrap();
    let ended = Instant::now();
    wait_until(
        Duration::from_secs(25),
        "the endpoint kept a channel nobody can end",
        || gone(proxy.endpoint),
    );
    let took = ended.elapsed();
    let flooding = channel_to(&world.fake, flood_port).unwrap();
    proxy.release();
    join_within(drain, LIMIT, "the flood's reader");
    // 2 s + 5 s, timer-driven.
    assert!(took < Duration::from_secs(10), "{took:?}");
    // The live channel was closed on the way out.
    assert!(client_closed(&world.fake, flooding));
}

/// The SSH client sends past a channel's window (the endpoint announces a
/// window it does not count, a debug-only hook, so the well-behaved test
/// client overruns): that channel alone is reset, without an exit status,
/// its wssp channel gets a kill close, and the connection goes on.
#[test]
fn a_client_that_sends_past_the_window_has_its_channel_reset() {
    let world = World::new();
    world.fake.knobs.hold_stdin.store(true, Ordering::SeqCst);
    let direct = direct::connect(&world, &[("WSSP_TEST_SSH_UNCOUNTED_WINDOW", "65536")]);
    let handle = &direct.handle;
    let channel = direct.runtime.block_on(async {
        let channel = handle.channel_open_session().await.unwrap();
        channel.exec(true, "cat > /dev/null").await.unwrap();
        channel
    });
    // The overrun has to find the wssp channel open: an abort that comes
    // first cancels the open itself.
    wait_until(
        Duration::from_secs(10),
        "the wssp channel never opened",
        || !world.fake.opens().is_empty(),
    );
    direct.runtime.block_on(async move {
        let (mut read, write) = channel.split();
        let writer = tokio::spawn(async move {
            let chunk = vec![5_u8; 32 * 1024];
            for _ in 0..256 {
                if write.data(&chunk[..]).await.is_err() {
                    return;
                }
            }
        });
        let mut stderr = Vec::new();
        loop {
            match tokio::time::timeout(Duration::from_secs(30), read.wait()).await {
                Ok(Some(russh::ChannelMsg::ExtendedData { data, .. })) => {
                    stderr.extend_from_slice(&data);
                }
                Ok(Some(russh::ChannelMsg::ExitStatus { exit_status })) => {
                    panic!("an exit status {exit_status} after an overrun")
                }
                Ok(Some(russh::ChannelMsg::Close) | None) => break,
                Ok(Some(_)) => {}
                Err(_) => panic!("the overrun channel was never reset"),
            }
        }
        writer.abort();
        assert!(
            String::from_utf8_lossy(&stderr).contains("more than its window"),
            "{}",
            String::from_utf8_lossy(&stderr)
        );
    });
    let ClientControl::Open { channel, .. } = world.fake.opens()[0].clone() else {
        unreachable!()
    };
    wait_until(Duration::from_secs(10), "the wssp channel stayed", || {
        client_closed(&world.fake, channel)
    });
    // Only that channel: the connection serves the next one.
    direct.runtime.block_on(async {
        let mut channel = handle.channel_open_session().await.unwrap();
        channel.exec(true, "echo fine").await.unwrap();
        let mut out = Vec::new();
        loop {
            match direct::next(&mut channel).await {
                russh::ChannelMsg::Data { data } => out.extend_from_slice(&data),
                russh::ChannelMsg::ExitStatus { exit_status } => {
                    assert_eq!(exit_status, 0);
                    break;
                }
                _ => {}
            }
        }
        assert_eq!(out, b"fine\n");
    });
}

/// Invariants 2 and 3 with a ControlMaster: while one forward of the
/// master is jammed, new sessions through the master open, run and end.
#[test]
fn a_control_master_with_a_jammed_forward_serves_new_sessions() {
    require!("ssh");
    let world = World::new();
    let control = world.path("cm");
    let (stuck_port, _recorded) = recording_service();
    world
        .fake
        .knobs
        .hold_port
        .store(stuck_port, Ordering::SeqCst);
    let (mut master, _stderr, ports) = forwarding(&world, 1, &[], |ports| {
        vec![
            "-o".into(),
            "ControlMaster=yes".into(),
            "-o".into(),
            format!("ControlPath={}", control.display()),
            "-N".into(),
            "-L".into(),
            format!("127.0.0.1:{}:localhost:{stuck_port}", ports[0]),
            "sbx_1.wssp".into(),
        ]
    });
    wait_until(Duration::from_secs(20), "the master never listened", || {
        control.exists()
    });
    let jam = Jam::start(&world, ports[0]);
    for round in 0..3 {
        let mut ssh = world.ssh();
        ssh.arg("-o")
            .arg(format!("ControlPath={}", control.display()))
            .args(["sbx_1.wssp", &format!("echo still-{round}")]);
        let output = run(ssh, None, LIMIT);
        assert!(output.status.success(), "{round}: {}", text(&output.stderr));
        assert_eq!(text(&output.stdout), format!("still-{round}\n"));
    }
    assert!(world.window_exhausted(jam.local), "the jammed window moved");
    assert_eq!(world.fake.upgrades.load(Ordering::SeqCst), 1);
    signal(master.id(), rustix::process::Signal::TERM);
    let _ = exit_within(&mut master, LIMIT, "the master");
}

/// Window grants that fall into one of ssh's frequent key re-exchanges
/// (`RekeyLimit 64K`) go out after it: none is lost or sent mid-exchange,
/// so a 16 MiB upload completes intact.
#[test]
fn window_grants_survive_frequent_rekeys() {
    require!("ssh");
    let world = World::new();
    let bytes = payload(16 * 1024 * 1024, 71);
    let sink = world.guest().join("rekeyed.bin");
    let mut ssh = world.ssh();
    ssh.args([
        "-o",
        "RekeyLimit=64K",
        "sbx_1.wssp",
        &format!("cat > {}", sink.display()),
    ]);
    let output = run(ssh, Some(bytes.clone()), Duration::from_secs(120));
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert!(std::fs::read(&sink).unwrap() == bytes, "the bytes changed");
}

/// Invariant 1: with every log event enabled and a stderr nobody reads, the
/// session neither blocks nor loses bytes (log events are held once the
/// session runs), and the endpoint ends after the client.
#[test]
fn debug_logging_into_an_unread_stderr_never_blocks_the_session() {
    require!("ssh", "mkfifo");
    let world = World::new();
    let fifo = world.path("stderr.fifo");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    // A reader that opens the pipe and never reads it.
    let holder = {
        let fifo = fifo.clone();
        thread::spawn(move || std::fs::File::open(fifo).unwrap())
    };
    let proxy = format!(
        "ProxyCommand=\"{}\" ssh --stdio %n 2>\"{}\"",
        wssp_exe().display(),
        fifo.display()
    );
    let bytes = payload(8 * 1024 * 1024, 51);
    let mut ssh = world.ssh();
    ssh.env("WSSP_LOG", "debug")
        .args(["-o", &proxy, "sbx_1.wssp", "cat"])
        .stdin(Stdio::piped());
    let mut session = ManagedChild::spawn(&mut ssh).unwrap();
    let endpoint = endpoint_of(session.id());
    let _held = join_within(holder, Duration::from_secs(20), "the fifo reader");
    wait_until(Duration::from_secs(20), "the session never opened", || {
        !world.fake.opens().is_empty()
    });
    // The session runs: fill the endpoint's stderr pipe to the brim, so any
    // log line from now on would block the thread that writes it.
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut filler = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(0o4000) // O_NONBLOCK
            .open(&fifo)
            .unwrap();
        let block = [b'x'; 4096];
        loop {
            match filler.write(&block) {
                Ok(_) => {}
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) => panic!("{error}"),
            }
        }
    }
    let mut pipe = session.stdin.take().unwrap();
    let writer = {
        let bytes = bytes.clone();
        thread::spawn(move || {
            pipe.write_all(&bytes).unwrap();
        })
    };
    let mut stdout = session.stdout.take().unwrap();
    let reader = thread::spawn(move || {
        let mut back = Vec::new();
        stdout.read_to_end(&mut back).unwrap();
        back
    });
    join_within(writer, Duration::from_secs(30), "the upload");
    let back = join_within(reader, Duration::from_secs(30), "the download");
    assert!(back == bytes, "the bytes changed");
    let status = exit_within(&mut session, Duration::from_secs(30), "ssh");
    assert!(status.success());
    wait_until(Duration::from_secs(15), "the endpoint never ended", || {
        gone(endpoint)
    });
}

/// A guest service that writes `bytes` to its client at once, then closes.
fn flooding_service(bytes: usize) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let chunk = payload(64 * 1024, 61);
        let mut left = bytes;
        while left > 0 {
            let n = left.min(chunk.len());
            if stream.write_all(&chunk[..n]).is_err() {
                return;
            }
            left -= n;
        }
    });
    port
}

/// Invariants 4 and 6: the client of a forward stops reading, so the SSH
/// window and the channel's whole output credit are used up and its writer
/// waits for window; a wssp abort (backpressure) still closes the SSH
/// channel at once, without waiting for the client to read.
#[test]
fn a_wssp_abort_closes_a_channel_whose_client_stopped_reading() {
    require!("ssh");
    let world = World::new();
    let flood_port = flooding_service(256 * 1024 * 1024);
    let (_session, stderr, ports) = forwarding(&world, 1, &[], |ports| {
        vec![
            "-vv".into(),
            "-N".into(),
            "-L".into(),
            format!("127.0.0.1:{}:localhost:{flood_port}", ports[0]),
            "sbx_1.wssp".into(),
        ]
    });
    let mut client = connect_to(ports[0]);
    // The writer waits for window, and still does a while later (the client
    // never reads, so the window stays used up), with the fake's credit full.
    wait_until(
        Duration::from_secs(30),
        "the forward's writer never waited for window",
        || {
            world.writer_blocked() && world.fake.knobs.out_full.load(Ordering::SeqCst) > 0 && {
                thread::sleep(Duration::from_millis(300));
                world.writer_blocked()
            }
        },
    );
    let before = stderr.text().matches("rcvd close").count();
    world
        .fake
        .knobs
        .close_port
        .store(flood_port, Ordering::SeqCst);
    wait_until(
        Duration::from_secs(10),
        "the aborted channel waited for its client",
        || stderr.text().matches("rcvd close").count() > before,
    );
    // The client then sees the end of a cut stream.
    let mut back = Vec::new();
    let _ = client.read_to_end(&mut back);
    assert!(back.len() < 256 * 1024 * 1024);
}

/// The natural end keeps FIFO order: a guest that writes more than the
/// client's window and then exits delivers all of it before its status,
/// however long the client waited before reading.
#[test]
fn a_natural_exit_waits_for_its_output_to_be_read() {
    require!("ssh");
    let world = World::new();
    let size = 8 * 1024 * 1024;
    let mut ssh = world.ssh();
    ssh.args(["sbx_1.wssp", &format!("head -c {size} /dev/zero; exit 3")]);
    let mut session = ManagedChild::spawn(&mut ssh).unwrap();
    wait_until(
        Duration::from_secs(30),
        "the writer never waited for window",
        || world.writer_blocked() && world.fake.knobs.out_full.load(Ordering::SeqCst) > 0,
    );
    let mut stdout = session.stdout.take().unwrap();
    let reader = thread::spawn(move || {
        let mut back = Vec::new();
        stdout.read_to_end(&mut back).unwrap();
        back
    });
    let back = join_within(reader, LIMIT, "the output");
    let status = exit_within(&mut session, LIMIT, "ssh");
    assert_eq!(back.len(), size);
    assert!(back.iter().all(|byte| *byte == 0));
    assert_eq!(status.code(), Some(3));
}

/// Invariant 5: a client that sends its disconnect but keeps the pipe open
/// (no EOF ever comes) still ends the endpoint within the drain deadline,
/// and its channels are closed.
#[test]
fn a_disconnect_that_keeps_the_pipe_open_ends_within_the_drain_deadline() {
    let world = World::new();
    let mut direct = direct::connect(&world, &[]);
    let handle = &direct.handle;
    direct.runtime.block_on(async {
        let channel = handle.channel_open_session().await.unwrap();
        channel.exec(true, "sleep 30").await.unwrap();
    });
    wait_until(Duration::from_secs(20), "the session never opened", || {
        !world.fake.opens().is_empty()
    });
    let ClientControl::Open { channel, .. } = world.fake.opens()[0].clone() else {
        unreachable!()
    };
    direct.runtime.block_on(async {
        handle
            .disconnect(russh::Disconnect::ByApplication, "bye", "en")
            .await
            .unwrap();
    });
    let disconnected = Instant::now();
    exit_within(
        &mut direct.child,
        Duration::from_secs(15),
        "the endpoint after the disconnect",
    );
    assert!(client_closed(&world.fake, channel));
    assert!(disconnected.elapsed() < Duration::from_secs(10));
}

/// Each channel's SSH window is one wssp window of its kind: 128 KiB come
/// with the open, and a command or a forward gets the rest (to 1 MiB) once
/// its kind is known, a forward only after its accept.
#[test]
fn a_command_or_a_forward_gets_one_wssp_window() {
    let world = World::new();
    let echo_port = endless_echo_service();
    let direct = direct::connect(&world, &[]);
    let handle = &direct.handle;
    direct.runtime.block_on(async {
        let mut command = handle.channel_open_session().await.unwrap();
        command.exec(true, "sleep 20").await.unwrap();
        direct::window_reaches(&mut command, 1024 * 1024).await;
        let mut forward = handle
            .channel_open_direct_tcpip("localhost", u32::from(echo_port), "127.0.0.1", 1)
            .await
            .unwrap();
        direct::window_reaches(&mut forward, 1024 * 1024).await;
    });
}

/// Invariant 7: a command's exit status reaches the client before its eof,
/// as sshd sends them, even when the sandbox reports the exit well after
/// the output's end: a client that closes a channel once both sides sent
/// eof (a ControlMaster's sessions do) never loses the status.
#[test]
fn a_commands_exit_status_comes_before_its_eof() {
    let world = World::new();
    world.fake.knobs.exit_delay_ms.store(300, Ordering::SeqCst);
    let direct = direct::connect(&world, &[]);
    let handle = &direct.handle;
    direct.runtime.block_on(async {
        let mut channel = handle.channel_open_session().await.unwrap();
        channel.exec(true, "echo out; exit 4").await.unwrap();
        channel.eof().await.unwrap();
        let mut order = Vec::new();
        loop {
            match direct::next(&mut channel).await {
                russh::ChannelMsg::Data { .. } => {
                    if order.last() != Some(&"data") {
                        order.push("data");
                    }
                }
                russh::ChannelMsg::ExitStatus { exit_status } => {
                    assert_eq!(exit_status, 4);
                    order.push("status");
                }
                russh::ChannelMsg::Eof => order.push("eof"),
                russh::ChannelMsg::Close => {
                    order.push("close");
                    break;
                }
                _ => {}
            }
        }
        assert_eq!(order, ["data", "status", "eof", "close"]);
    });
}

/// Agent, X11 and remote (tcp and streamlocal) forwarding are refused at
/// the request level: the reply is a failure.
#[test]
fn forwarding_requests_toward_the_workstation_are_refused() {
    let world = World::new();
    let direct = direct::connect(&world, &[]);
    let handle = &direct.handle;
    direct.runtime.block_on(async {
        let mut channel = handle.channel_open_session().await.unwrap();
        channel.agent_forward(true).await.unwrap();
        assert!(matches!(
            direct::next(&mut channel).await,
            russh::ChannelMsg::Failure
        ));
        channel
            .request_x11(true, false, "MIT-MAGIC-COOKIE-1", "00112233", 0)
            .await
            .unwrap();
        assert!(matches!(
            direct::next(&mut channel).await,
            russh::ChannelMsg::Failure
        ));
        assert!(handle.tcpip_forward("127.0.0.1", 0).await.is_err());
        assert!(
            handle
                .streamlocal_forward("/tmp/wssp-x.sock")
                .await
                .is_err()
        );
        // The session itself still works.
        channel.exec(true, "echo fine").await.unwrap();
        let mut out = Vec::new();
        loop {
            match direct::next(&mut channel).await {
                russh::ChannelMsg::Data { data } => out.extend_from_slice(&data),
                russh::ChannelMsg::ExitStatus { exit_status } => {
                    assert_eq!(exit_status, 0);
                    break;
                }
                _ => {}
            }
        }
        assert_eq!(out, b"fine\n");
    });
}

/// The fake's guest processes start with default signal dispositions
/// whatever this test process inherited: the signal test, re-run in a child
/// that ignores SIGHUP, SIGINT and SIGQUIT (as a background job of a
/// non-interactive shell under `nohup` does), still sees its guest command
/// end by the forwarded signal.
#[test]
fn a_guest_starts_with_default_signals_whatever_the_tests_inherited() {
    if std::env::var_os("WSSP_TEST_INHERITED_IGNORES").is_some() {
        return;
    }
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg(
            "trap '' HUP INT QUIT; exec \"$0\" --exact resizes_and_signals_reach_the_sandbox \
             --test-threads=1",
        )
        .arg(std::env::current_exe().unwrap())
        .env("WSSP_TEST_INHERITED_IGNORES", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = run(command, None, LIMIT);
    let stdout = text(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "{stdout}\n{}",
        text(&output.stderr)
    );
}

/// Terminal sizes reach the fake as `resize` frames: the latest size of
/// those sent before `ready` (coalesced), then each later one; signals of
/// an exec channel reach it as `signal` frames.
#[test]
fn resizes_and_signals_reach_the_sandbox() {
    let world = World::new();
    world.fake.knobs.ready_delay_ms.store(500, Ordering::SeqCst);
    let direct = direct::connect(&world, &[]);
    let handle = &direct.handle;
    let resizes = || -> Vec<(u32, u16, u16)> {
        world
            .fake
            .log
            .lock()
            .unwrap()
            .iter()
            .filter_map(|frame| match frame {
                ClientControl::Resize {
                    channel,
                    rows,
                    cols,
                } => Some((*channel, *rows, *cols)),
                _ => None,
            })
            .collect()
    };
    let terminal = direct.runtime.block_on(async {
        let channel = handle.channel_open_session().await.unwrap();
        channel
            .request_pty(true, "xterm", 80, 24, 0, 0, &[])
            .await
            .unwrap();
        channel.exec(true, "sleep 20").await.unwrap();
        // Before `ready` (the fake answers after 500 ms).
        for (cols, rows) in [(100, 30), (110, 31), (120, 32)] {
            channel.window_change(cols, rows, 0, 0).await.unwrap();
        }
        channel
    });
    assert!(resizes().is_empty(), "a resize before ready went out");
    wait_until(Duration::from_secs(20), "no resize after ready", || {
        resizes().last().is_some_and(|r| (r.1, r.2) == (32, 120))
    });
    let before = resizes();
    assert!(before.len() <= 3, "{before:?}");
    // After `ready` each size goes out.
    direct.runtime.block_on(async {
        terminal.window_change(130, 40, 0, 0).await.unwrap();
    });
    wait_until(
        Duration::from_secs(20),
        "no resize of the ready terminal",
        || resizes().last().is_some_and(|r| (r.1, r.2) == (40, 130)),
    );
    // A signal: sent until the channel is ready (earlier ones are dropped).
    // The guest command never ends by itself, and the first signal goes out
    // only once `sleep` is the running program: a signal while the guest's
    // shells are still starting could be absorbed by them (dash catches
    // SIGINT under `-c` and may `exec` with it pending), and a timed command
    // could end first; either way the exit would be a plain status.
    world.fake.knobs.ready_delay_ms.store(0, Ordering::SeqCst);
    let guest = world.guest();
    let mut channel = direct.runtime.block_on(async {
        let channel = handle.channel_open_session().await.unwrap();
        channel.exec(true, "exec sleep 86400").await.unwrap();
        channel
    });
    wait_until(Duration::from_secs(20), "the guest sleep never ran", || {
        guest_program_running(&guest, &["sleep", "86400"])
    });
    direct.runtime.block_on(async {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let signalled = world.fake.log.lock().unwrap().iter().any(|frame| {
                matches!(
                    frame,
                    ClientControl::Signal {
                        signal: wire::Signal::Int,
                        ..
                    }
                )
            });
            if signalled {
                break;
            }
            assert!(Instant::now() < deadline, "no signal frame");
            channel.signal(russh::Sig::INT).await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        loop {
            match direct::next(&mut channel).await {
                russh::ChannelMsg::ExitSignal { signal_name, .. } => {
                    assert!(matches!(signal_name, russh::Sig::INT), "{signal_name:?}");
                    break;
                }
                russh::ChannelMsg::ExitStatus { exit_status } => {
                    panic!("exit status {exit_status} instead of the signal")
                }
                _ => {}
            }
        }
    });
}

/// Invariant 6: channels that completed or were refused give their slot
/// back, so one ControlMaster connection keeps serving well past the 128
/// channels the endpoint holds at once.
#[test]
fn a_control_master_serves_more_than_128_completed_and_refused_channels() {
    require!("ssh");
    let world = World::new();
    let control = world.path("cm");
    let closed_port = free_port();
    let (mut master, stderr, ports) = forwarding(&world, 1, &[], |ports| {
        vec![
            "-o".into(),
            "ControlMaster=yes".into(),
            "-o".into(),
            format!("ControlPath={}", control.display()),
            "-N".into(),
            "-L".into(),
            format!("127.0.0.1:{}:localhost:{closed_port}", ports[0]),
            "sbx_1.wssp".into(),
        ]
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    while !control.exists() {
        assert!(
            Instant::now() < deadline,
            "the master never listened: {:?} {}",
            master.try_wait().unwrap(),
            stderr.text()
        );
        thread::sleep(Duration::from_millis(10));
    }
    for round in 0..70 {
        let mut ssh = world.ssh();
        ssh.arg("-o")
            .arg(format!("ControlPath={}", control.display()))
            .args(["sbx_1.wssp", "true"]);
        let output = run(ssh, None, LIMIT);
        assert!(
            output.status.success(),
            "{round}: {:?} {}",
            output.status,
            text(&output.stderr)
        );
        assert_refused(connect_to(ports[0]));
    }
    let mut ssh = world.ssh();
    ssh.arg("-o")
        .arg(format!("ControlPath={}", control.display()))
        .args(["sbx_1.wssp", "echo still"]);
    let output = run(ssh, None, LIMIT);
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert_eq!(text(&output.stdout), "still\n");
    assert_eq!(world.fake.upgrades.load(Ordering::SeqCst), 1);
    signal(master.id(), rustix::process::Signal::TERM);
    let _ = exit_within(&mut master, LIMIT, "the master");
}

/// Invariants 4 and 8: a revocation ends a ControlMaster connection that
/// carries two running sessions and a jammed forward (its window used up),
/// within a fixed bound; the master and its sessions exit and the control
/// socket is not reused.
#[test]
fn a_revocation_ends_a_busy_control_master_within_the_bound() {
    require!("ssh");
    let world = World::new();
    let control = world.path("cm");
    let (stuck_port, _recorded) = recording_service();
    world
        .fake
        .knobs
        .hold_port
        .store(stuck_port, Ordering::SeqCst);
    let (mut master, _stderr, ports) = forwarding(&world, 1, &[], |ports| {
        vec![
            "-o".into(),
            "ControlMaster=yes".into(),
            "-o".into(),
            format!("ControlPath={}", control.display()),
            "-N".into(),
            "-L".into(),
            format!("127.0.0.1:{}:localhost:{stuck_port}", ports[0]),
            "sbx_1.wssp".into(),
        ]
    });
    wait_until(Duration::from_secs(20), "the master never listened", || {
        control.exists()
    });
    let mut sessions: Vec<ManagedChild> = (0..2)
        .map(|_| {
            let mut ssh = world.ssh();
            ssh.arg("-o")
                .arg(format!("ControlPath={}", control.display()))
                .args(["sbx_1.wssp", "sleep 30"]);
            ManagedChild::spawn(&mut ssh).unwrap()
        })
        .collect();
    wait_until(Duration::from_secs(20), "the sessions never opened", || {
        world.fake.opens().len() >= 2
    });
    let _jam = Jam::start(&world, ports[0]);
    world.fake.end_all(Intent::Revoked);
    let revoked = Instant::now();
    let status = exit_within(&mut master, Duration::from_secs(10), "the master");
    for session in &mut sessions {
        exit_within(session, Duration::from_secs(10), "a session");
    }
    let took = revoked.elapsed();
    assert!(!status.success());
    assert!(took < Duration::from_secs(10), "{took:?}");
    wait_until(Duration::from_secs(10), "the control socket stayed", || {
        !control.exists()
    });
    assert_eq!(world.fake.upgrades.load(Ordering::SeqCst), 1);
}

// ------------------------------------------------------------ IDE flows

/// An echo service the guest starts itself: `python3 svc.py <port>` prints
/// `READY` once it listens.
const SERVICE: &str = r#"import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(8)
print("READY", flush=True)
while True:
    c, _ = s.accept()
    while True:
        d = c.recv(65536)
        if not d:
            break
        c.sendall(d)
    c.close()
"#;

/// Read `reader` until a line equal to `line` (bounded by the caller).
fn read_until_line(reader: &mut impl Read, line: &str) {
    let mut seen = Vec::new();
    let mut byte = [0_u8; 1];
    while !String::from_utf8_lossy(&seen).lines().any(|l| l == line) {
        assert_eq!(reader.read(&mut byte).unwrap(), 1, "ended before {line}");
        seen.push(byte[0]);
    }
}

/// VS Code Remote-SSH: `ssh -T -D <port> host bash` with a bootstrap script
/// on stdin that starts a guest service and keeps running; the client then
/// reaches the service through the same connection's SOCKS forward.
#[test]
fn a_remote_ssh_style_bootstrap_reaches_its_service_through_the_same_connection() {
    require!("ssh", "python3");
    let world = World::new();
    let guest_port = free_port();
    let (mut session, _stderr, ports) = forwarding(&world, 1, &[], |ports| {
        vec![
            "-T".into(),
            "-D".into(),
            format!("127.0.0.1:{}", ports[0]),
            "sbx_1.wssp".into(),
            "bash".into(),
        ]
    });
    let mut stdin = session.stdin.take().unwrap();
    let mut stdout = session.stdout.take().unwrap();
    let bootstrap = format!("cat > svc.py <<'EOF'\n{SERVICE}EOF\npython3 svc.py {guest_port} &\n");
    stdin.write_all(bootstrap.as_bytes()).unwrap();
    let ready = thread::spawn(move || {
        read_until_line(&mut stdout, "READY");
        stdout
    });
    let _stdout = join_within(ready, LIMIT, "the bootstrap");
    let mut stream = connect_to(ports[0]);
    stream.write_all(&[5, 1, 0]).unwrap();
    let mut reply = [0_u8; 2];
    stream.read_exact(&mut reply).unwrap();
    assert_eq!(reply, [5, 0]);
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&guest_port.to_be_bytes());
    stream.write_all(&request).unwrap();
    let mut reply = [0_u8; 10];
    stream.read_exact(&mut reply).unwrap();
    assert_eq!(reply[1], 0, "socks connect refused");
    let bytes = payload(2 * 1024 * 1024, 71);
    assert!(round_trip(&mut stream, &bytes) == bytes);
    stdin.write_all(b"kill $!; exit 0\n").unwrap();
    drop(stdin);
    let status = exit_within(&mut session, LIMIT, "the bootstrap session");
    assert!(status.success());
}

/// JetBrains Gateway: an exec, an explicit `sftp put` of a file, then a
/// `-L` forward to a service that the uploaded file runs.
#[test]
fn a_gateway_style_exec_upload_and_forward_work_in_sequence() {
    require!("ssh", "sftp", "python3");
    if !Path::new("/usr/lib/openssh/sftp-server").exists() {
        assert!(
            !tools_required(),
            "/usr/lib/openssh/sftp-server is required"
        );
        eprintln!("skipped: no /usr/lib/openssh/sftp-server to stand in for the guest's");
        return;
    }
    let world = World::new();
    let mut ssh = world.ssh();
    ssh.args(["sbx_1.wssp", "mkdir -p ide && echo made"]);
    let output = run(ssh, None, LIMIT);
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert_eq!(text(&output.stdout), "made\n");
    let local = world.path("svc.py");
    std::fs::write(&local, SERVICE).unwrap();
    let batch = world.path("batch");
    std::fs::write(
        &batch,
        format!(
            "put {} {}\n",
            local.display(),
            world.guest().join("ide/svc.py").display()
        ),
    )
    .unwrap();
    let mut sftp = world.tool("sftp");
    sftp.arg("-b").arg(&batch).arg("sbx_1.wssp");
    let output = run(sftp, None, LIMIT);
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert_eq!(
        std::fs::read_to_string(world.guest().join("ide/svc.py")).unwrap(),
        SERVICE
    );
    let guest_port = free_port();
    let (mut session, _stderr, ports) = forwarding(&world, 1, &[], |ports| {
        vec![
            "-L".into(),
            format!("127.0.0.1:{}:localhost:{guest_port}", ports[0]),
            "sbx_1.wssp".into(),
            format!("exec python3 ide/svc.py {guest_port}"),
        ]
    });
    let mut stdout = session.stdout.take().unwrap();
    let ready = thread::spawn(move || {
        read_until_line(&mut stdout, "READY");
        stdout
    });
    let _stdout = join_within(ready, LIMIT, "the uploaded service");
    let mut stream = connect_to(ports[0]);
    let bytes = payload(1024 * 1024, 72);
    assert!(round_trip(&mut stream, &bytes) == bytes);
}

/// The endpoint offers only its modern set; real OpenSSH negotiates it, and
/// a client limited to legacy algorithms is refused.
#[test]
fn only_modern_algorithms_are_offered() {
    require!("ssh");
    let world = World::new();
    let mut ssh = world.ssh();
    ssh.args(["-vv", "sbx_1.wssp", "true"]);
    let output = run(ssh, None, LIMIT);
    let stderr = text(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains("kex: host key algorithm: ssh-ed25519"),
        "{stderr}"
    );
    assert!(
        stderr.contains("kex: algorithm: mlkem768x25519-sha256")
            || stderr.contains("kex: algorithm: curve25519-sha256"),
        "{stderr}"
    );
    for legacy in [
        ["-o", "Ciphers=aes128-ctr"],
        ["-o", "KexAlgorithms=diffie-hellman-group14-sha256"],
    ] {
        let mut ssh = Command::new("ssh");
        wssp_env(&mut ssh, world.root.path(), &world.fake.url);
        ssh.arg("-F")
            .arg(&world.config)
            .args(["-o", "BatchMode=yes"])
            .args(legacy)
            .args(["sbx_1.wssp", "true"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = run(ssh, None, LIMIT);
        let stderr = text(&output.stderr);
        assert_eq!(output.status.code(), Some(255), "{legacy:?}: {stderr}");
        assert!(stderr.contains("no matching"), "{legacy:?}: {stderr}");
    }
}
