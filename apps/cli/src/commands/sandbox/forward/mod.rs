//! `wssp sandbox forward`: local ports (or one local Unix socket) forwarded
//! to ports on a sandbox's loopback over the connect plane
//! (`GET /v1/sandboxes/{id}/connect`, `src/connect_client/`).
//!
//! The CLI listens locally (default `127.0.0.1`; `<localPort>` defaults to
//! `<guestPort>`, `0` picks a free port and prints it). Every accepted local
//! connection becomes one `tcp` channel to guest `127.0.0.1:<guestPort>`
//! (the node falls back to `[::1]`), so many connections share one
//! WebSocket. There is no host on the wire: the target is always the guest's
//! own loopback. Accepted connections beyond the connection's channel cap
//! (or its open rate) wait in a backlog of 32, then are refused (reset).
//! `--address` other than loopback warns; `--unix PATH` listens on a 0600
//! Unix socket instead, which other local users cannot reach (bound in a
//! private directory next to PATH and renamed into place, never replacing a
//! file; the process umask is never touched).
//!
//! Half-close travels both ways: a local EOF sends the channel's stdin eof
//! (the node shuts the guest socket's write side), and the guest service's
//! write shutdown arrives as the stdout eof, after which the local socket's
//! write side is shut. Only exit 0 after that eof is a clean end (the local
//! socket closes normally); any other end was a reset (before or after the
//! eof), and so is the local socket (RST; a Unix socket cannot signal a
//! reset and just closes). A local reset is seen at once,
//! also while the stdin credit is exhausted or after a local half-close (a
//! pending socket error, checked every turn), and closes the channel. Output
//! is acknowledged only once written to
//! the local socket, so a slow local reader stops the guest reads instead of
//! buffering without bound. A refused guest connection resets the local one
//! and logs one line (at most one per second).
//!
//! Shared budgets: every channel slot keeps one frame of the connection's
//! stdin budget, input is read round robin, and a local EOF needs no
//! credit, so connections whose guest services stop reading never freeze
//! the others (`Mux::stdin_credit`).
//!
//! Teardown: Ctrl-C (or SIGTERM, SIGHUP, SIGQUIT) stops listening, closes
//! every channel, waits at most 2 s for their exits and exits 128 + N (130
//! for Ctrl-C); a signal while still connecting exits 128 + N at once, after
//! removing the `--unix` socket. A wssp-side end (a revoked login, a
//! stopped sandbox, a lost connection) resets every local socket, prints
//! why and exits 125.
//!
//! Threads: this one owns the connection, every local socket (non-blocking)
//! and every decision; a signal watcher and a line writer only move events
//! and text. During the session this thread writes nothing to stdout or
//! stderr itself (the line writer does, dropping lines when they back up),
//! so a stderr nobody reads can never stall the forward.

use std::collections::{BTreeMap, VecDeque};
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::Serialize;

use super::segment;
use super::shell::{Purpose, wssp_side};
use crate::connect_client::Connection;
use crate::connect_client::mux::{Event, Outcome};
use crate::connect_client::wire::{Intent, Kind, OutputStream};
use crate::exit::{CodedError, ExitCode, ProcessExit};
use crate::output;

/// Accepted connections waiting for a channel (beyond them: refused).
const BACKLOG: usize = 32;
/// Connections taken from a listener per loop turn at most.
const ACCEPTS_PER_TURN: usize = 64;
/// stdin frames one channel sends per loop turn at most (after the acks).
const STDIN_FRAMES_PER_TURN: usize = 4;
/// How long a teardown waits for the channels' exits.
const CLOSE_WAIT: Duration = Duration::from_secs(2);
/// How long the end waits for the line writer.
const WRITER_SETTLE: Duration = Duration::from_secs(2);
/// Refusal lines: at most one per this interval.
const REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(1);
/// Lines queued for the writer; more are dropped.
const MAX_QUEUED_LINES: usize = 64;
/// The open-rate window of `hello.limits.opensPerMinute`, plus a margin:
/// the server stamps an open when it receives it, later than this client
/// queued it, so an open that left this client's window can still be in
/// the server's. (A `rate_limited` refusal is retried once, see
/// `Forward::on_event`.)
const OPEN_WINDOW: Duration = Duration::from_secs(63);

#[derive(Debug, clap::Args)]
pub struct ForwardArgs {
    /// Sandbox id or name.
    pub sandbox: String,

    /// `<guestPort>[:<localPort>]` (repeatable; the local port defaults to the guest port, `0` picks a free one).
    #[arg(required = true, value_name = "PORTS", value_parser = parse_spec)]
    pub ports: Vec<Spec>,

    /// Local address to listen on (an IP address; default `127.0.0.1`; anything but loopback warns).
    #[arg(long, value_name = "ADDR", conflicts_with = "unix")]
    pub address: Option<IpAddr>,

    /// Listen on a Unix socket at PATH (mode 0600) instead of a TCP port; one guest port only.
    #[arg(long, value_name = "PATH")]
    pub unix: Option<PathBuf>,

    /// Print the listening addresses as JSON lines; report a failure as one JSON line on stderr.
    #[arg(long)]
    pub json: bool,
}

/// One `<guestPort>[:<localPort>]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Spec {
    pub guest: u16,
    /// `None`: the guest port (or the `--unix` socket).
    pub local: Option<u16>,
}

fn parse_spec(text: &str) -> Result<Spec, String> {
    let (guest, local) = match text.split_once(':') {
        Some((guest, local)) => (guest, Some(local)),
        None => (text, None),
    };
    let port = |what: &str, value: &str, min: u16| -> Result<u16, String> {
        match value.parse::<u16>() {
            Ok(port) if port >= min && value.bytes().all(|b| b.is_ascii_digit()) => Ok(port),
            _ => Err(format!(
                "`{text}`: the {what} port must be a number from {min} to 65535"
            )),
        }
    };
    Ok(Spec {
        guest: port("guest", guest, 1)?,
        local: local.map(|local| port("local", local, 0)).transpose()?,
    })
}

fn usage(message: String) -> anyhow::Error {
    anyhow::Error::msg(message).context(CodedError::new(ExitCode::Usage))
}

// ------------------------------------------------------------ listeners ----

/// A local listener (non-blocking) and the guest port its connections reach.
struct Listener {
    socket: ListenSocket,
    guest: u16,
}

enum ListenSocket {
    Tcp(TcpListener),
    Unix(UnixListener),
}

/// Where a listener listens, for the printed line.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Listening {
    local: String,
    guest_port: u16,
}

/// The Unix socket this forward created; removed when it ends (only while
/// it is still the same file).
struct UnixPath {
    path: PathBuf,
    identity: Option<(u64, u64)>,
}

impl UnixPath {
    fn remove(&self) {
        remove_if_same(&self.path, self.identity);
    }
}

/// Remove the socket at `path` only while it is still the file this
/// forward created (`identity`: its device and inode).
fn remove_if_same(path: &Path, identity: Option<(u64, u64)>) {
    use std::os::unix::fs::MetadataExt;
    let same = std::fs::symlink_metadata(path)
        .is_ok_and(|meta| Some((meta.dev(), meta.ino())) == identity);
    if same {
        let _ = std::fs::remove_file(path);
    }
}

impl Drop for UnixPath {
    fn drop(&mut self) {
        self.remove();
    }
}

/// Bind every listener before any network call (local errors cost nothing).
fn bind(args: &ForwardArgs) -> Result<(Vec<Listener>, Vec<Listening>, Option<UnixPath>)> {
    if let Some(path) = &args.unix {
        let [spec] = args.ports.as_slice() else {
            return Err(usage("`--unix` forwards exactly one guest port".to_owned()));
        };
        if spec.local.is_some() {
            return Err(usage(
                "with `--unix` give only the guest port (the socket is the local end)".to_owned(),
            ));
        }
        let (listener, created) = bind_unix(path)?;
        let listening = Listening {
            local: path.display().to_string(),
            guest_port: spec.guest,
        };
        return Ok((
            vec![Listener {
                socket: ListenSocket::Unix(listener),
                guest: spec.guest,
            }],
            vec![listening],
            Some(created),
        ));
    }
    let address = args.address.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let mut listeners = Vec::new();
    let mut listening = Vec::new();
    for spec in &args.ports {
        let local = spec.local.unwrap_or(spec.guest);
        let listener = TcpListener::bind(SocketAddr::new(address, local))
            .with_context(|| format!("listening on {} failed", SocketAddr::new(address, local)))?;
        listener
            .set_nonblocking(true)
            .context("configuring the listener")?;
        if let Err(error) = clamp_segment_size(&listener) {
            // Best effort: without it a shrinking client window can only
            // slow a connection down, never break it.
            tracing::debug!(%error, "TCP_MAXSEG on the listener refused");
        }
        let bound = listener.local_addr().context("configuring the listener")?;
        listening.push(Listening {
            local: bound.to_string(),
            guest_port: spec.guest,
        });
        listeners.push(Listener {
            socket: ListenSocket::Tcp(listener),
            guest: spec.guest,
        });
    }
    Ok((listeners, listening, None))
}

/// A Unix listener at `path`, 0600 from the moment it is reachable there,
/// never replacing an existing file. The socket is bound in a fresh private
/// (0700) directory next to `path`, restricted to 0600, then moved into
/// place with a rename that refuses an existing target. Nothing touches the
/// process-wide umask: a narrowed umask would apply to every other thread's
/// file and directory creation at the same moment.
/// The largest TCP segment of an accepted connection, both ways.
///
/// Linux sends a segment no larger than half the largest receive window
/// the peer ever offered (up to 64 KiB on loopback) and, while more data
/// waits than the peer's window, nothing shorter: when the window a local
/// client offers later shrinks below that size (its receive buffer
/// re-scaled, a reader that slowed down), the forward's queued output
/// moves only through the persist timer, one window per probe, about
/// 100-200 KB/s for the rest of the connection. A segment size no larger
/// than the smallest window a receive buffer can offer keeps every open
/// window usable (1 KiB never stalled down to the kernel's smallest
/// receive buffer; 2 KiB did). On loopback (segmentation offload) it costs
/// nothing; on a real interface it means somewhat more packets, on a path
/// the relay limits far below the link anyway.
const LOCAL_SEGMENT: u32 = 1024;

/// Accepted connections inherit the listener's `TCP_MAXSEG`.
#[cfg(target_os = "linux")]
fn clamp_segment_size(listener: &TcpListener) -> std::io::Result<()> {
    socket2::SockRef::from(listener).set_tcp_mss(LOCAL_SEGMENT)
}

#[cfg(not(target_os = "linux"))]
fn clamp_segment_size(_listener: &TcpListener) -> std::io::Result<()> {
    Ok(())
}

fn bind_unix(path: &Path) -> Result<(UnixListener, UnixPath)> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let exists = || {
        usage(format!(
            "`{}` already exists; remove it first or choose another path",
            path.display()
        ))
    };
    if std::fs::symlink_metadata(path).is_ok() {
        return Err(exists());
    }
    let failed = || format!("listening on `{}` failed", path.display());
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    // Removed with whatever it holds on every path out of here.
    let private = tempfile::Builder::new()
        .prefix(".w")
        .rand_bytes(6)
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(parent)
        .with_context(failed)?;
    // The mode asked for is narrowed by the umask: make it exactly 0700.
    std::fs::set_permissions(private.path(), std::fs::Permissions::from_mode(0o700))
        .with_context(failed)?;
    let staged = private.path().join("s");
    let listener = UnixListener::bind(&staged).with_context(failed)?;
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restricting `{}`", path.display()))?;
    // The inode, taken where nobody else can swap it.
    let identity = std::fs::symlink_metadata(&staged)
        .map(|meta| (meta.dev(), meta.ino()))
        .with_context(failed)?;
    match place_no_replace(&staged, path) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => return Err(exists()),
        Err(error) => return Err(anyhow::Error::new(error).context(failed())),
    }
    let created = UnixPath {
        path: path.to_path_buf(),
        identity: Some(identity),
    };
    drop(private);
    listener
        .set_nonblocking(true)
        .context("configuring the listener")?;
    Ok((listener, created))
}

/// Move `from` to `to` unless `to` exists (then `AlreadyExists`, and `to`
/// is untouched): `renameat2(RENAME_NOREPLACE)`, or where the file system
/// lacks it a hard link (which never replaces either) and an unlink.
fn place_no_replace(from: &Path, to: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{CWD, RenameFlags, renameat_with};
        match renameat_with(CWD, from, CWD, to, RenameFlags::NOREPLACE) {
            Ok(()) => return Ok(()),
            Err(errno)
                if errno == rustix::io::Errno::INVAL || errno == rustix::io::Errno::NOSYS => {}
            Err(errno) => return Err(errno.into()),
        }
    }
    std::fs::hard_link(from, to)?;
    let _ = std::fs::remove_file(from);
    Ok(())
}

// --------------------------------------------------------- local sockets ----

/// One accepted local connection (non-blocking).
enum Local {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl Local {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read(buffer),
            Self::Unix(stream) => stream.read(buffer),
        }
    }

    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.write(bytes),
            Self::Unix(stream) => stream.write(bytes),
        }
    }

    /// Whether the peer half-closed with nothing unread before it: a
    /// one-byte peek that reads no data, so a local EOF travels without
    /// stdin credit (an eof costs none). `Ok(false)`: data is waiting, or
    /// nothing is.
    fn peek_eof(&self) -> std::io::Result<bool> {
        use rustix::net::{RecvFlags, recv};
        let mut probe = [0_u8; 1];
        let flags = RecvFlags::PEEK | RecvFlags::DONTWAIT;
        let peeked = match self {
            Self::Tcp(stream) => recv(stream, &mut probe, flags),
            Self::Unix(stream) => recv(stream, &mut probe, flags),
        };
        match peeked {
            Ok((0, _)) => Ok(true),
            Ok(_) => Ok(false),
            Err(errno) if errno == rustix::io::Errno::AGAIN || errno == rustix::io::Errno::INTR => {
                Ok(false)
            }
            Err(errno) => Err(errno.into()),
        }
    }

    fn shutdown_write(&self) {
        let _ = match self {
            Self::Tcp(stream) => stream.shutdown(Shutdown::Write),
            Self::Unix(stream) => stream.shutdown(Shutdown::Write),
        };
    }

    /// The peer reset the connection: a pending socket error (TCP: an RST;
    /// Unix: the peer closed with input of ours unread). Read without
    /// reading or writing data, so a reset is seen while the stdin credit is
    /// exhausted, after a local half-close, and with no output to write. A
    /// half-close (`shutdown(SHUT_WR)`, a FIN) is no error.
    fn reset_by_peer(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            let error = match self {
                Self::Tcp(stream) => rustix::net::sockopt::socket_error(stream),
                Self::Unix(stream) => rustix::net::sockopt::socket_error(stream),
            };
            !matches!(error, Ok(Ok(())))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let error = match self {
                Self::Tcp(stream) => stream.take_error(),
                Self::Unix(stream) => stream.take_error(),
            };
            !matches!(error, Ok(None))
        }
    }

    /// Close with a reset (TCP: `SO_LINGER` 0, so the peer sees RST, not a
    /// clean EOF); a Unix socket just closes.
    fn reset(self) {
        #[cfg(target_os = "linux")]
        if let Self::Tcp(stream) = &self {
            let _ = rustix::net::sockopt::set_socket_linger(stream, Some(Duration::ZERO));
        }
        drop(self);
    }
}

fn accept(listener: &ListenSocket) -> std::io::Result<Local> {
    let local = match listener {
        ListenSocket::Tcp(listener) => {
            let (stream, _) = listener.accept()?;
            stream.set_nodelay(true)?;
            stream.set_nonblocking(true)?;
            Local::Tcp(stream)
        }
        ListenSocket::Unix(listener) => {
            let (stream, _) = listener.accept()?;
            stream.set_nonblocking(true)?;
            Local::Unix(stream)
        }
    };
    Ok(local)
}

fn is_would_block(error: &std::io::Error) -> bool {
    matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted)
}

// ---------------------------------------------------------------- lines ----

/// The line writer: stdout lines (the listening addresses) and stderr lines
/// (warnings, refusals, the final error), in order, from its own thread.
struct Lines {
    sender: Option<mpsc::SyncSender<(bool, String)>>,
    done: mpsc::Receiver<()>,
    queued: usize,
}

impl Lines {
    fn spawn() -> Result<Self> {
        let (sender, receiver) = mpsc::sync_channel::<(bool, String)>(MAX_QUEUED_LINES);
        let (done_tx, done) = mpsc::channel();
        std::thread::Builder::new()
            .name("wssp-forward-lines".into())
            .spawn(move || {
                for (stdout, line) in receiver {
                    let _ = if stdout {
                        output::line(&line).and_then(|()| output::flush_stdout())
                    } else {
                        output::diagnostic(&line)
                    };
                    if done_tx.send(()).is_err() {
                        return;
                    }
                }
            })
            .context("starting the line writer")?;
        Ok(Self {
            sender: Some(sender),
            done,
            queued: 0,
        })
    }

    fn settle(&mut self) {
        while self.done.try_recv().is_ok() {
            self.queued = self.queued.saturating_sub(1);
        }
    }

    /// Queue one line; dropped when the writer is backed up.
    fn send(&mut self, stdout: bool, line: String) -> bool {
        self.settle();
        let queued = self
            .sender
            .as_ref()
            .is_some_and(|sender| sender.try_send((stdout, line)).is_ok());
        if queued {
            self.queued += 1;
        }
        queued
    }

    fn out(&mut self, line: String) {
        self.send(true, line);
    }

    fn err(&mut self, line: String) {
        self.send(false, line);
    }

    /// Wait up to [`WRITER_SETTLE`] for every queued line; `false`: the
    /// writer is stuck on a stdout or stderr nobody reads.
    fn drain(&mut self) -> bool {
        let deadline = Instant::now() + WRITER_SETTLE;
        self.settle();
        while self.queued > 0 {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.done.recv_timeout(left) {
                Ok(()) => self.queued -= 1,
                Err(_) => return false,
            }
        }
        true
    }
}

// --------------------------------------------------------------- signals ----

/// What a signal before the session must clean up, and whether the
/// session has taken signals over.
#[derive(Default)]
struct Early {
    /// The `--unix` socket once bound: its path and identity.
    unix: Option<(PathBuf, Option<(u64, u64)>)>,
    session: bool,
}

/// The signal watcher, installed before anything is bound. Until the
/// session takes over ([`hand_over`]) a signal ends the process at once
/// (128 + N), after removing the `--unix` socket if one was bound: the
/// dial may take seconds, and the default action would leave the socket
/// file (and, during the bind, its staging directory) behind. A bind holds
/// the lock, so the watcher waits for it to finish and clean up first.
#[cfg(unix)]
fn spawn_signals(early: std::sync::Arc<std::sync::Mutex<Early>>) -> Result<mpsc::Receiver<i32>> {
    use signal_hook::consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
    let (sender, receiver) = mpsc::channel();
    let mut signals = signal_hook::iterator::Signals::new([SIGINT, SIGTERM, SIGHUP, SIGQUIT])
        .context("installing the signal handlers")?;
    std::thread::Builder::new()
        .name("wssp-forward-signals".into())
        .spawn(move || {
            for signal in signals.forever() {
                {
                    let state = lock(&early);
                    if !state.session {
                        if let Some((path, identity)) = &state.unix {
                            remove_if_same(path, *identity);
                        }
                        std::process::exit(128 + signal);
                    }
                }
                if sender.send(signal).is_err() {
                    return;
                }
            }
        })
        .context("starting the signal watcher")?;
    Ok(receiver)
}

fn lock(early: &std::sync::Mutex<Early>) -> std::sync::MutexGuard<'_, Early> {
    early
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// From here signals reach the session's pump (and its teardown).
fn hand_over(early: &std::sync::Mutex<Early>) {
    let mut state = lock(early);
    state.session = true;
    state.unix = None;
}

// -------------------------------------------------------------- channels ----

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// The open is sent; waiting for `ready`.
    Opening,
    Open,
    /// This client closed it (the local side failed or a teardown); the
    /// local socket is gone, the channel's exit is still due.
    Closing,
}

/// One forwarded connection.
struct Link {
    local: Option<Local>,
    guest: u16,
    phase: Phase,
    /// Output frames not yet fully written to the local socket: seq, bytes,
    /// bytes written.
    pending: VecDeque<(u64, Vec<u8>, usize)>,
    /// The local side reached EOF and the stdin eof was sent.
    local_eof: bool,
    /// The guest service shut its write side (the stdout eof was released).
    remote_eof: bool,
    /// An earlier open for this local connection was refused as
    /// `rate_limited` (it is retried once).
    retried: bool,
}

/// The session's channels and its waiting connections.
struct Forward {
    links: BTreeMap<u32, Link>,
    /// Accepted connections waiting for a channel, with their guest port
    /// and whether an open of theirs was already refused as `rate_limited`.
    waiting: VecDeque<(Local, u16, bool)>,
    /// When the recent opens were sent (`opensPerMinute`).
    opens: VecDeque<Instant>,
    /// Ended channels whose state the mux drops after the next flush.
    ended: Vec<u32>,
    /// Events an abort released (a held eof or exit), handled with the
    /// turn's other events.
    later: VecDeque<Event>,
    last_refusal_log: Option<Instant>,
    refusals_unlogged: u64,
    buffer: Vec<u8>,
    /// The next channel `read_input` serves first.
    in_cursor: u32,
    /// This turn moved bytes (local output written, local input sent):
    /// what a local socket does next announces itself with no frame, so
    /// the next poll waits only briefly ([`Connection::set_busy`]).
    moved: bool,
}

impl Forward {
    fn new(data_max: usize) -> Self {
        Self {
            links: BTreeMap::new(),
            waiting: VecDeque::new(),
            opens: VecDeque::new(),
            ended: Vec::new(),
            later: VecDeque::new(),
            last_refusal_log: None,
            refusals_unlogged: 0,
            buffer: vec![0; data_max.max(1)],
            in_cursor: 0,
            moved: false,
        }
    }

    /// One refusal line, at most one per second (the rest are counted into
    /// the next one).
    fn refusal(&mut self, lines: &mut Lines, now: Instant, text: impl FnOnce() -> String) {
        if self
            .last_refusal_log
            .is_some_and(|at| now.duration_since(at) < REFUSAL_LOG_INTERVAL)
        {
            self.refusals_unlogged += 1;
            return;
        }
        self.last_refusal_log = Some(now);
        let mut line = format!("wssp: {}", text());
        if self.refusals_unlogged > 0 {
            line.push_str(&format!(
                " ({} more since the last line)",
                self.refusals_unlogged
            ));
            self.refusals_unlogged = 0;
        }
        lines.err(line);
    }

    /// Close one channel from this side: the local socket is reset now, its
    /// output is discarded and acknowledged (also what arrives later), and
    /// the channel's exit is awaited (its slot counts until then). An exit
    /// the mux held for undelivered output is released at once (into
    /// `later`): the server already ended that channel and ignores a close.
    fn abort(&mut self, connection: &mut Connection, channel: u32) -> Result<()> {
        if let Some(link) = self.links.get_mut(&channel) {
            if link.phase == Phase::Closing {
                return Ok(());
            }
            link.phase = Phase::Closing;
            link.pending.clear();
            if let Some(local) = link.local.take() {
                local.reset();
            }
            self.later.extend(connection.abort_channel(channel)?);
        }
        Ok(())
    }

    /// Admit waiting connections while the connection's channel cap and
    /// open rate allow.
    fn admit(&mut self, connection: &mut Connection, now: Instant) -> Result<()> {
        let limits = *connection.limits();
        let max_channels = usize::try_from(limits.max_channels).unwrap_or(usize::MAX);
        let per_minute = usize::try_from(limits.opens_per_minute).unwrap_or(usize::MAX);
        while self
            .opens
            .front()
            .is_some_and(|at| now.duration_since(*at) >= OPEN_WINDOW)
        {
            self.opens.pop_front();
        }
        while !self.waiting.is_empty()
            && self.links.len() < max_channels
            && self.opens.len() < per_minute
        {
            let Some((local, guest, retried)) = self.waiting.pop_front() else {
                break;
            };
            let channel = connection.open_relay(Some(guest), None)?;
            self.opens.push_back(now);
            self.links.insert(
                channel,
                Link {
                    local: Some(local),
                    guest,
                    phase: Phase::Opening,
                    pending: VecDeque::new(),
                    local_eof: false,
                    remote_eof: false,
                    retried,
                },
            );
        }
        Ok(())
    }

    /// Act on one released event; delivered output may release more.
    fn on_event(&mut self, lines: &mut Lines, event: Event, now: Instant) -> Result<()> {
        match event {
            Event::Ready { channel, .. } => {
                if let Some(link) = self.links.get_mut(&channel)
                    && link.phase == Phase::Opening
                {
                    link.phase = Phase::Open;
                }
            }
            Event::Output {
                channel, seq, body, ..
            } => {
                if let Some(link) = self.links.get_mut(&channel)
                    && link.phase == Phase::Open
                {
                    link.pending.push_back((seq, body, 0));
                }
            }
            Event::Eof { channel, .. } => {
                // Released only after every frame before it was written.
                if let Some(link) = self.links.get_mut(&channel) {
                    link.remote_eof = true;
                    if let Some(local) = &link.local {
                        local.shutdown_write();
                    }
                }
            }
            Event::Notice { .. } => {}
            Event::Exit { channel, outcome } => {
                let Some(mut link) = self.links.remove(&channel) else {
                    return Ok(());
                };
                self.ended.push(channel);
                // Clean only when the relay says so: exit 0 after the stdout
                // eof. A reset after the eof (exit 1), an unknown end or a
                // signal is a reset, also after a graceful-looking eof.
                let graceful = outcome == Outcome::Code(0) && link.remote_eof;
                match outcome {
                    Outcome::Failed { error }
                        if error.code == "rate_limited"
                            && link.phase == Phase::Opening
                            && !link.retried
                            && link.local.is_some() =>
                    {
                        // The rate windows of this client and the server
                        // can disagree at the limit: wait again (first in
                        // line) instead of resetting, once.
                        if let Some(local) = link.local.take() {
                            self.waiting.push_front((local, link.guest, true));
                        }
                        return Ok(());
                    }
                    Outcome::Failed { error } => {
                        if error.code == "unsupported_capability" {
                            if let Some(local) = link.local.take() {
                                local.reset();
                            }
                            return Err(anyhow::anyhow!(
                                "the sandbox cannot forward ports (`{}`: {})",
                                output::remote_message(&error.code),
                                output::remote_message(&error.message)
                            )
                            .context(CodedError::new(ExitCode::ExecFailure)));
                        }
                        let guest = link.guest;
                        // A refusal only before `ready`; later the channel
                        // failed (a corrupt relay stream, a timeout).
                        let what = if link.phase == Phase::Opening {
                            format!("sandbox port {guest} refused a connection")
                        } else {
                            format!("a connection to sandbox port {guest} failed")
                        };
                        self.refusal(lines, now, || {
                            format!(
                                "{what} (`{}`: {})",
                                output::remote_message(&error.code),
                                output::remote_message(&error.message)
                            )
                        });
                    }
                    Outcome::Closed { intent, error } if intent != Intent::Client => {
                        let guest = link.guest;
                        self.refusal(lines, now, || {
                            let mut text = format!(
                                "a connection to sandbox port {guest} was closed (`{}`): {}",
                                intent.name(),
                                intent.describe()
                            );
                            if let Some(error) = &error {
                                text.push_str(&format!(
                                    " (`{}`: {})",
                                    output::remote_message(&error.code),
                                    output::remote_message(&error.message)
                                ));
                            }
                            text
                        });
                    }
                    _ => {}
                }
                if let Some(local) = link.local.take() {
                    if graceful {
                        // Both directions ended cleanly: a normal close.
                        drop(local);
                    } else {
                        local.reset();
                    }
                }
            }
        }
        Ok(())
    }

    /// Local IO of every link: output written (and reported delivered),
    /// then input read within the stdin credit.
    fn local_io(
        &mut self,
        connection: &mut Connection,
        released: &mut VecDeque<Event>,
    ) -> Result<()> {
        let channels: Vec<u32> = self.links.keys().copied().collect();
        let mut failed = Vec::new();
        for channel in &channels {
            let Some(link) = self.links.get_mut(channel) else {
                continue;
            };
            let Some(local) = &mut link.local else {
                continue;
            };
            while let Some((seq, bytes, written)) = link.pending.front_mut() {
                match local.write(&bytes[*written..]) {
                    // A socket that takes nothing: try again next turn.
                    Ok(0) => break,
                    Ok(n) => {
                        self.moved = true;
                        *written += n;
                        if *written >= bytes.len() {
                            let seq = *seq;
                            link.pending.pop_front();
                            released.extend(connection.delivered(
                                *channel,
                                OutputStream::Stdout,
                                seq,
                            ));
                        }
                    }
                    Err(error) if is_would_block(&error) => break,
                    Err(_) => {
                        failed.push(*channel);
                        break;
                    }
                }
            }
        }
        for channel in failed {
            self.abort(connection, channel)?;
        }
        Ok(())
    }

    /// Read local input into stdin frames (after the turn's acks), round
    /// robin from the input cursor: the cursor moves past a channel only
    /// when it sent a frame, so returned credit reaches every channel in
    /// turn, never only the lowest ids. A local EOF needs no credit: while
    /// a channel has none, a peek still sees the half-close and sends the
    /// eof.
    fn read_input(&mut self, connection: &mut Connection) -> Result<()> {
        let mut channels: Vec<u32> = self.links.keys().copied().collect();
        let start = channels.partition_point(|channel| *channel < self.in_cursor);
        channels.rotate_left(start);
        let mut failed = Vec::new();
        for channel in channels {
            let Some(link) = self.links.get_mut(&channel) else {
                continue;
            };
            if link.phase != Phase::Open || link.local_eof {
                continue;
            }
            let Some(local) = &mut link.local else {
                continue;
            };
            let mut served = false;
            for _ in 0..STDIN_FRAMES_PER_TURN {
                if !connection.stdin_credit(channel) {
                    if !served {
                        match local.peek_eof() {
                            Ok(true) => {
                                link.local_eof = true;
                                connection.stdin_eof(channel)?;
                            }
                            Ok(false) => {}
                            Err(_) => failed.push(channel),
                        }
                    }
                    break;
                }
                match local.read(&mut self.buffer) {
                    Ok(0) => {
                        link.local_eof = true;
                        connection.stdin_eof(channel)?;
                        break;
                    }
                    Ok(n) => {
                        connection.send_stdin(channel, &self.buffer[..n])?;
                        served = true;
                        self.moved = true;
                    }
                    Err(error) if is_would_block(&error) => break,
                    Err(_) => {
                        failed.push(channel);
                        break;
                    }
                }
            }
            if served {
                self.in_cursor = channel.saturating_add(1);
            }
        }
        for channel in failed {
            self.abort(connection, channel)?;
        }
        Ok(())
    }

    /// Abort every link whose local peer reset its connection, whether or
    /// not this turn could read or write it (exhausted stdin credit, a
    /// local half-close, no output due), and drop waiting connections that
    /// reset before they got a channel (they would cost an open each).
    fn reap_resets(&mut self, connection: &mut Connection) -> Result<()> {
        let waiting = std::mem::take(&mut self.waiting);
        for entry in waiting {
            if entry.0.reset_by_peer() {
                entry.0.reset();
            } else {
                self.waiting.push_back(entry);
            }
        }
        let reset: Vec<u32> = self
            .links
            .iter()
            .filter(|(_, link)| link.local.as_ref().is_some_and(Local::reset_by_peer))
            .map(|(channel, _)| *channel)
            .collect();
        for channel in reset {
            self.abort(connection, channel)?;
        }
        Ok(())
    }

    /// Reset everything local at once (a wssp-side end, a teardown).
    fn reset_all(&mut self) {
        for (local, ..) in self.waiting.drain(..) {
            local.reset();
        }
        for link in self.links.values_mut() {
            link.pending.clear();
            if let Some(local) = link.local.take() {
                local.reset();
            }
        }
    }
}

// -------------------------------------------------------------- command ----

pub fn forward(args: &ForwardArgs) -> Result<()> {
    output::set_json_errors(args.json);
    let target = segment(&args.sandbox)?.to_owned();
    let early = std::sync::Arc::new(std::sync::Mutex::new(Early::default()));
    let signals = spawn_signals(early.clone())?;
    let (listeners, listening, unix) = {
        let mut state = lock(&early);
        let bound = bind(args)?;
        state.unix = bound
            .2
            .as_ref()
            .map(|created| (created.path.clone(), created.identity));
        bound
    };
    if let Some(address) = args.address.filter(|address| !address.is_loopback()) {
        // Before the session: nothing else writes yet.
        let _ = output::warning(format!(
            "listening on {address}: anyone who can reach that address can connect to the sandbox"
        ));
    }
    let credential = crate::user_state::require_credential()?;
    let connection =
        super::shell::connect(&credential, &target, Purpose::Forward).map_err(wssp_side)?;
    hand_over(&early);
    session(connection, listeners, &listening, unix, &signals, args)
}

/// The listening lines, then the pump, then the bounded end.
fn session(
    mut connection: Connection,
    listeners: Vec<Listener>,
    listening: &[Listening],
    unix: Option<UnixPath>,
    signals: &mpsc::Receiver<i32>,
    args: &ForwardArgs,
) -> Result<()> {
    let mut lines = Lines::spawn()?;
    // From here the line writer owns stdout and stderr (see the module doc).
    crate::logging::hold_stderr(true);
    for item in listening {
        if args.json {
            if let Ok(line) = output::json_line(item) {
                lines.out(line);
            }
        } else {
            lines.out(format!(
                "Forwarding {} -> sandbox port {}",
                item.local, item.guest_port
            ));
        }
    }
    let data_max = connection.data_max(Kind::Tcp);
    let mut forward = Forward::new(data_max);
    let result = pump(
        &mut connection,
        &mut forward,
        listeners,
        signals,
        &mut lines,
    );
    forward.reset_all();
    // The closing handshake (bounded; skipped on a broken transport).
    connection.finish();
    // The socket file goes whatever the outcome (also before an early exit).
    drop(unix);
    let result = result.map_err(wssp_side);
    let status = match &result {
        Ok(status) => *status,
        Err(error) => crate::exit::code_for(error) as i32,
    };
    if let Err(error) = &result
        && let Some(line) = crate::commands::failure_line(error)
    {
        lines.err(line);
    }
    let drained = lines.drain();
    if !drained {
        // The writer is blocked on a stdout or stderr nobody reads: end now
        // with the status and no message (`process::exit`'s stdout cleanup
        // only try-locks, see `shell::session`).
        std::process::exit(status);
    }
    match status {
        0 => Ok(()),
        status => Err(anyhow::Error::new(ProcessExit(status))),
    }
}

/// The session: until a signal ends it (its status) or the wssp side does
/// (an error).
fn pump(
    connection: &mut Connection,
    forward: &mut Forward,
    mut listeners: Vec<Listener>,
    signals: &mpsc::Receiver<i32>,
    lines: &mut Lines,
) -> Result<i32> {
    // A teardown this client decided: its status and the wait's deadline.
    let mut closing: Option<(i32, Instant)> = None;
    loop {
        let mut released: VecDeque<Event> = connection.poll()?.into();
        forward.moved |= !released.is_empty();
        let now = Instant::now();
        while let Ok(signal) = signals.try_recv() {
            if closing.is_some() {
                // A second signal: end at once.
                return Ok(128 + signal);
            }
            closing = Some((128 + signal, now + CLOSE_WAIT));
            // Stop listening, refuse what waits, close every channel.
            listeners.clear();
            for (local, ..) in forward.waiting.drain(..) {
                local.reset();
            }
            let channels: Vec<u32> = forward.links.keys().copied().collect();
            for channel in channels {
                forward.abort(connection, channel)?;
            }
        }
        for listener in &listeners {
            for _ in 0..ACCEPTS_PER_TURN {
                match accept(&listener.socket) {
                    Ok(local) if forward.waiting.len() < BACKLOG => {
                        forward.waiting.push_back((local, listener.guest, false));
                    }
                    Ok(local) => {
                        local.reset();
                        let guest = listener.guest;
                        forward.refusal(lines, now, || {
                            format!(
                                "too many connections waiting for sandbox port {guest}; refused one"
                            )
                        });
                    }
                    Err(error) if is_would_block(&error) => break,
                    // Out of descriptors or an aborted handshake: try later.
                    Err(_) => break,
                }
            }
        }
        if closing.is_none() {
            forward.admit(connection, now)?;
        }
        loop {
            released.extend(forward.later.drain(..));
            while let Some(event) = released.pop_front() {
                forward.on_event(lines, event, now)?;
            }
            forward.local_io(connection, &mut released)?;
            released.extend(forward.later.drain(..));
            if released.is_empty() {
                break;
            }
        }
        if let Some((status, deadline)) = closing
            && (forward.links.is_empty() || now >= deadline)
        {
            return Ok(status);
        }
        // The turn's acks go first, then at most a few stdin frames each.
        connection.queue_acks()?;
        if closing.is_none() {
            forward.read_input(connection)?;
            // After the reads, so an error a read consumed is not checked
            // twice; aborts reach `on_event` through `later` next turn.
            forward.reap_resets(connection)?;
        }
        connection.flush()?;
        for channel in forward.ended.drain(..) {
            connection.forget(channel);
        }
        connection.set_busy(std::mem::take(&mut forward.moved))?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_specs_are_guest_then_local() {
        assert_eq!(
            parse_spec("5432").unwrap(),
            Spec {
                guest: 5432,
                local: None
            }
        );
        assert_eq!(
            parse_spec("5432:15432").unwrap(),
            Spec {
                guest: 5432,
                local: Some(15432)
            }
        );
        assert_eq!(parse_spec("80:0").unwrap().local, Some(0));
        for bad in [
            "0", "65536", "", ":80", "80:", "80:65536", "a", "80:x", "+80", "1:2:3",
        ] {
            assert!(parse_spec(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_unix_listener_is_private_and_never_replaces_a_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fwd.sock");
        let (listener, created) = bind_unix(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(bind_unix(&path).is_err(), "an existing path stays");
        // The socket is reachable at the path, and nothing else remains.
        std::os::unix::net::UnixStream::connect(&path).unwrap();
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        drop(listener);
        drop(created);
        assert!(!path.exists(), "the forward removes its own socket");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        std::fs::write(&path, b"not ours").unwrap();
        assert!(bind_unix(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"not ours");
    }

    #[test]
    fn a_unix_bind_never_changes_what_other_threads_create() {
        // The bind once narrowed the process umask: a directory another
        // thread created meanwhile came out 0600 (no search bit), and a bind
        // inside it failed. Binds race directory creation here.
        use std::os::unix::fs::PermissionsExt;
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let creators: Vec<_> = (0..4)
            .map(|_| {
                let stop = stop.clone();
                std::thread::spawn(move || {
                    let mut created = 0;
                    while !stop.load(std::sync::atomic::Ordering::SeqCst) || created < 50 {
                        let dir = tempfile::tempdir().unwrap();
                        let mode = std::fs::metadata(dir.path()).unwrap().permissions().mode();
                        assert_eq!(mode & 0o700, 0o700, "a directory created during a bind");
                        let file = dir.path().join("f");
                        std::fs::write(&file, b"x").unwrap();
                        let mode = std::fs::metadata(&file).unwrap().permissions().mode();
                        assert_eq!(mode & 0o600, 0o600, "a file created during a bind");
                        created += 1;
                    }
                })
            })
            .collect();
        let dir = tempfile::tempdir().unwrap();
        for i in 0..200 {
            let path = dir.path().join(format!("{i}.sock"));
            let (listener, created) = bind_unix(&path).unwrap();
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
            drop((listener, created));
        }
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        for creator in creators {
            creator.join().unwrap();
        }
        // No staging directory is left behind.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn a_unix_bind_that_loses_a_race_for_the_path_keeps_the_winner() {
        // The path appears between the existence check and the move: the
        // no-replace rename refuses, the other file stays, nothing leaks.
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("staged");
        let target = dir.path().join("target");
        std::fs::write(&staged, b"ours").unwrap();
        std::fs::write(&target, b"theirs").unwrap();
        let error = place_no_replace(&staged, &target).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&target).unwrap(), b"theirs");
        assert_eq!(std::fs::read(&staged).unwrap(), b"ours");
        let moved = dir.path().join("moved");
        place_no_replace(&staged, &moved).unwrap();
        assert!(!staged.exists());
        assert_eq!(std::fs::read(&moved).unwrap(), b"ours");
    }

    #[test]
    fn a_replaced_socket_path_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fwd.sock");
        let (_listener, created) = bind_unix(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"someone else's").unwrap();
        drop(created);
        assert_eq!(std::fs::read(&path).unwrap(), b"someone else's");
    }
}
