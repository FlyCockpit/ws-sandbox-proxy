//! The SSH endpoint of `wssp ssh --stdio`: a russh server on this process's
//! own stdin and stdout, on a current-thread tokio runtime that exists only
//! here. Nothing listens anywhere: the only peer is the ssh client that
//! spawned this process as its `ProxyCommand`.
//!
//! The endpoint authenticates nobody (`none`, any public key, any password
//! and an empty keyboard-interactive are all accepted, the user name is
//! ignored): reaching it already took the user's own ssh spawning the
//! user's own `wssp`, and every channel is authorized by the server with the
//! wssp login over TLS.
//!
//! Each SSH channel is one wssp channel ([`super::mapping`]). Output is
//! written to an SSH channel within the client's window and reported back
//! as delivered only then, so the wssp credit follows the SSH window. Input
//! has a receive window per channel that grows only as the channel's guest
//! consumes ([`super::input`], on the vendored russh's `manual_window`); the
//! handler never waits, and a channel whose guest stops reading stops only
//! its own ssh client.
//!
//! The SSH transport runs over an in-memory duplex between two pumps of
//! this process's stdin and stdout, so the end of stdin is seen whatever
//! the output does. Every end (ssh's disconnect or stdin closing, a wssp
//! end, a session that stopped taking a channel's last messages) starts one
//! absolute [`TEARDOWN`] deadline that covers the disconnect drain, the
//! connection thread and the final report together.
//!
//! Once the session runs, only this runtime writes the process's stdout (the
//! SSH transport), nothing writes its stderr (log events are held), and the
//! process ends through [`shell::final_report_by`](super::super::shell),
//! which never waits on a blocked stdout or stderr beyond the deadline.

use std::borrow::Cow;
use std::collections::VecDeque;
use std::collections::{BTreeMap, HashMap};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, mpsc};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use russh::keys::{Algorithm, PrivateKey};
use russh::server::{Auth, ChannelOpenHandle, Handle, Handler, Msg, Session};
use russh::{Channel, ChannelId, ChannelWriteHalf, MethodKind, MethodSet, Sig};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc as tokio_mpsc, watch};

use super::bridge::{self, Abort, Cmd, Grant, OpenRequest, Slot, Slots, Up};
use super::input::{Admit, Budget};
use super::mapping::{self, Finish, PtyRequest, SessionRequest};
use crate::connect_client::Connection;
use crate::connect_client::wire::{Kind, Limits, OutputStream};

/// The SSH packet size this endpoint accepts.
const MAX_PACKET: u32 = 32 * 1024;
/// A channel's SSH window at least (more than one SSH packet).
const MIN_STDIN_BYTES: usize = 64 * 1024;
/// How long a channel's last messages (eof, exit status, close) may wait
/// for russh's session queue; beyond it the whole session ends.
const FINAL_WRITE: Duration = Duration::from_secs(2);
/// From the start of the end: how long russh may keep reading (the client's
/// disconnect, the rest of its input) before the session is cut.
const DISCONNECT_DRAIN: Duration = Duration::from_secs(2);
/// From the start of the end: until when the connection thread may close
/// the channels.
const BRIDGE_DEADLINE: Duration = Duration::from_secs(4);
/// From the start of the end: when the process has exited, whatever is
/// blocked (the drain, the connection thread and the final report share it).
pub const TEARDOWN: Duration = Duration::from_secs(5);
/// What the stdin pump reads ahead of the SSH session at most.
const READ_AHEAD: usize = 256 * 1024;
/// The in-memory transport between the pumps and russh, per direction.
const TRANSPORT_BUFFER: usize = 64 * 1024;

/// The per-kind SSH window (one wssp window) and the window every channel
/// opens with, from `hello.limits`.
#[derive(Debug, Clone, Copy)]
pub struct Caps {
    pub stdin_pty: usize,
    pub stdin_bulk: usize,
    /// The window of a channel's open (a terminal's whole window); the rest
    /// of its kind's window is granted once the kind is known.
    pub initial: usize,
}

impl Caps {
    /// One wssp window per kind (`windowFrames × dataMaxBytes`).
    pub fn of(limits: &Limits) -> Self {
        let window = |kind: Kind| {
            let bytes = limits
                .window_frames
                .of(kind)
                .saturating_mul(limits.data_max_bytes.of(kind));
            usize::try_from(bytes)
                .unwrap_or(usize::MAX)
                .clamp(MIN_STDIN_BYTES, 16 * 1024 * 1024)
        };
        let pty = window(Kind::Pty);
        let bulk = window(Kind::Exec);
        Self {
            stdin_pty: pty,
            stdin_bulk: bulk,
            initial: pty.min(bulk),
        }
    }

    /// The initial window as russh takes it.
    fn initial_window(&self) -> u32 {
        u32::try_from(self.initial).unwrap_or(u32::MAX)
    }

    fn stdin(&self, kind: Kind) -> usize {
        match kind {
            Kind::Pty => self.stdin_pty,
            Kind::Exec | Kind::Tcp | Kind::Unix => self.stdin_bulk,
        }
    }
}

/// The algorithms offered: a small modern set that every OpenSSH since 8.x
/// speaks (ML-KEM/curve25519 key exchange with strict kex, the one ed25519
/// host key, AEAD ciphers, ETM MACs, no compression).
fn preferred() -> russh::Preferred {
    use russh::{cipher, compression, kex, mac};
    russh::Preferred {
        kex: Cow::Borrowed(&[
            kex::MLKEM768X25519_SHA256,
            kex::CURVE25519,
            kex::CURVE25519_PRE_RFC_8731,
            kex::EXTENSION_SUPPORT_AS_SERVER,
            kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
        ]),
        key: Cow::Borrowed(&[Algorithm::Ed25519]),
        host_key_certificates: Cow::Borrowed(&[]),
        cipher: Cow::Borrowed(&[
            cipher::CHACHA20_POLY1305,
            cipher::AES_256_GCM,
            cipher::AES_128_GCM,
        ]),
        mac: Cow::Borrowed(&[mac::HMAC_SHA512_ETM, mac::HMAC_SHA256_ETM]),
        compression: Cow::Borrowed(&[compression::NONE]),
    }
}

/// The russh configuration: the one host key, every auth method accepted,
/// windows granted by this endpoint only (`manual_window`), no timers of its
/// own (the client's `ServerAliveInterval` and the wssp connection's
/// liveness cover both ends; the teardown deadline here bounds the rest).
pub fn config(key: PrivateKey, caps: &Caps) -> russh::server::Config {
    russh::server::Config {
        server_id: russh::SshId::Standard(
            format!("SSH-2.0-wssp_{}", env!("CARGO_PKG_VERSION")).into(),
        ),
        methods: MethodSet::from(
            &[
                MethodKind::None,
                MethodKind::PublicKey,
                MethodKind::Password,
                MethodKind::KeyboardInteractive,
            ][..],
        ),
        auth_rejection_time: Duration::ZERO,
        auth_rejection_time_initial: Some(Duration::ZERO),
        keys: vec![key],
        window_size: caps
            .initial_window()
            .saturating_add(super::input::uncounted_window()),
        manual_window: true,
        maximum_packet_size: MAX_PACKET,
        inactivity_timeout: None,
        keepalive_interval: None,
        preferred: preferred(),
        ..Default::default()
    }
}

/// A channel writer's two inputs: its events in order, and an abort that
/// overtakes them.
struct Route {
    events: tokio_mpsc::UnboundedSender<Up>,
    abort: watch::Sender<Option<Abort>>,
}

type Routes = Arc<Mutex<HashMap<u64, Route>>>;
/// Channels whose writer finished: the endpoint drops their entries.
type Retired = Arc<Mutex<Vec<(ChannelId, u64)>>>;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One SSH channel.
struct SshChannel {
    local: u64,
    relay: bool,
    pty: Option<PtyRequest>,
    env: BTreeMap<String, String>,
    /// Until the channel starts (then its writer task owns it).
    write: Option<ChannelWriteHalf<Msg>>,
    /// The wssp kind, once started.
    started: Option<Kind>,
    stdin: Arc<Budget>,
    closed: watch::Sender<bool>,
    slot: Arc<Slot>,
}

/// The russh handler of the one SSH session.
pub struct Endpoint {
    commands: mpsc::Sender<Cmd>,
    routes: Routes,
    retired: Retired,
    slots: Arc<Slots>,
    caps: Caps,
    ending: Arc<Ending>,
    next_local: u64,
    channels: HashMap<ChannelId, SshChannel>,
}

impl Endpoint {
    fn new(commands: mpsc::Sender<Cmd>, routes: Routes, caps: Caps, ending: Arc<Ending>) -> Self {
        Self {
            commands,
            routes,
            retired: Arc::new(Mutex::new(Vec::new())),
            slots: Arc::new(Slots::default()),
            caps,
            ending,
            next_local: 0,
            channels: HashMap::new(),
        }
    }

    fn command(&self, command: Cmd) {
        // The connection thread is gone only when the session is ending.
        let _ = self.commands.send(command);
    }

    /// Drop the entries of channels whose writer finished (the writer sent
    /// the SSH close, or refused the open): russh tells no handler about
    /// those, and their slots must not wait for a `channel_close`.
    fn reap(&mut self) {
        let retired = std::mem::take(&mut *lock(&self.retired));
        for (id, local) in retired {
            if self
                .channels
                .get(&id)
                .is_some_and(|chan| chan.local == local)
                && let Some(chan) = self.channels.remove(&id)
            {
                chan.stdin.close();
                let _ = chan.closed.send(true);
                super::input::test_note(&format!("forgot {local}"));
            }
        }
    }

    fn register(
        &mut self,
        id: ChannelId,
        write: ChannelWriteHalf<Msg>,
        relay: bool,
        slot: Arc<Slot>,
    ) -> u64 {
        self.next_local += 1;
        let local = self.next_local;
        let (closed, _) = watch::channel(false);
        self.channels.insert(
            id,
            SshChannel {
                local,
                relay,
                pty: None,
                env: BTreeMap::new(),
                write: Some(write),
                started: None,
                // The window russh announced with the channel's open.
                stdin: Budget::new(local, self.caps.initial),
                closed,
                slot,
            },
        );
        local
    }

    /// Start the writer of a channel and open its wssp channel. The route
    /// exists before the open, so no event can miss it.
    fn launch(
        &mut self,
        id: ChannelId,
        kind: Kind,
        request: OpenRequest,
        reply: Option<ChannelOpenHandle>,
        handle: Handle,
    ) {
        let Some(channel) = self.channels.get_mut(&id) else {
            return;
        };
        let Some(write) = channel.write.take() else {
            return;
        };
        channel.started = Some(kind);
        channel.stdin.start();
        let window = self.caps.stdin(kind);
        if reply.is_none() {
            // A session channel is open already: the rest of its window now
            // (a forward's comes with its accept, from its writer).
            let add = channel.stdin.widen(window);
            if add > 0 {
                let _ = handle.grant_window(id, add);
            }
        }
        let local = channel.local;
        let (sender, events) = tokio_mpsc::unbounded_channel();
        let (abort, aborted) = watch::channel(None);
        lock(&self.routes).insert(
            local,
            Route {
                events: sender,
                abort,
            },
        );
        let writer = Writer {
            id,
            local,
            kind,
            write,
            handle,
            guard: Guard {
                closed: channel.closed.subscribe(),
                aborted,
                gone: false,
            },
            reply,
            stdin: channel.stdin.clone(),
            window,
            commands: self.commands.clone(),
            ending: self.ending.clone(),
            _slot: channel.slot.clone(),
        };
        let grant = Grant {
            handle: writer.handle.clone(),
            id,
        };
        tokio::spawn(writer.run(events, self.routes.clone(), self.retired.clone()));
        let stdin = channel.stdin.clone();
        let slot = channel.slot.clone();
        self.command(Cmd::Open {
            local,
            request,
            stdin,
            grant,
            slot,
        });
    }

    /// The client sent past a channel's window (a protocol violation; OpenSSH
    /// never does): that channel alone is reset. A started channel aborts
    /// through its writer (closed without eof or exit status) and its wssp
    /// channel gets a kill close; one not started yet (or refused) is closed
    /// here, and its entry goes with it: russh drops the channel and calls no
    /// handler for the client's answering close, so nothing would reap it.
    fn overrun(&mut self, id: ChannelId, session: &mut Session) {
        let Some(chan) = self.channels.get_mut(&id) else {
            return;
        };
        chan.stdin.close();
        if chan.started.is_some() {
            let local = chan.local;
            if let Some(route) = lock(&self.routes).get(&local) {
                route.abort.send_replace(Some(Abort::Overrun));
            }
            self.command(Cmd::Close { local });
            return;
        }
        if let Some(chan) = self.channels.remove(&id) {
            let _ = chan.closed.send(true);
            super::input::test_note(&format!("forgot {}", chan.local));
        }
        let _ = session.close(id);
    }

    fn open_relay(
        &mut self,
        channel: Channel<Msg>,
        kind: Kind,
        request: OpenRequest,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) {
        self.reap();
        let Some(slot) = self.slots.take() else {
            // Dropping the reply refuses the open.
            return;
        };
        let id = channel.id();
        let (read, write) = channel.split();
        // Input arrives through `Handler::data`; an unread channel queue
        // would stall the session loop.
        drop(read);
        self.register(id, write, true, slot);
        // Accepted only once the guest side is `ready` (else refused with
        // its reason).
        self.launch(id, kind, request, Some(reply), session.handle());
    }

    fn start(
        &mut self,
        id: ChannelId,
        request: &SessionRequest,
        session: &mut Session,
    ) -> Result<()> {
        let Some(channel) = self.channels.get(&id) else {
            return Ok(());
        };
        if channel.relay || channel.started.is_some() || channel.write.is_none() {
            session.channel_failure(id)?;
            return Ok(());
        }
        let plan = match mapping::plan(channel.pty.as_ref(), request) {
            Ok(plan) => plan,
            Err(mapping::Refusal(line)) => {
                // The channel never starts after a refusal (later requests
                // get a failure). Its line goes through the write half, so
                // within the client's window, from a task that gives up when
                // the channel ends: written past the write half, a line the
                // window cannot take would wait in russh, and while any
                // channel has output waiting there russh sends no channel's
                // output.
                if let Some(channel) = self.channels.get_mut(&id)
                    && let Some(write) = channel.write.take()
                {
                    let mut closed = channel.closed.subscribe();
                    let line = format!("{line}\r\n").into_bytes();
                    tokio::spawn(async move {
                        tokio::select! {
                            _ = write.extended_data_bytes(1, line) => {}
                            _ = closed.wait_for(|closed| *closed) => {}
                        }
                    });
                }
                session.channel_failure(id)?;
                return Ok(());
            }
        };
        session.channel_success(id)?;
        let request = OpenRequest::Process {
            kind: plan.kind,
            argv: plan.argv,
            login: plan.login,
            env: channel.env.clone(),
            pty: plan.pty,
        };
        self.launch(id, plan.kind, request, None, session.handle());
        Ok(())
    }
}

impl Handler for Endpoint {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn auth_password(&mut self, _user: &str, _password: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _key: russh::server::VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        _user: &str,
        _submethods: &str,
        _response: Option<russh::server::Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.reap();
        let Some(slot) = self.slots.take() else {
            reply
                .reject(russh::ChannelOpenFailure::ResourceShortage)
                .await;
            return Ok(());
        };
        let id = channel.id();
        let (read, write) = channel.split();
        drop(read);
        self.register(id, write, false, slot);
        reply.accept().await;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        match mapping::forward_target(host_to_connect, port_to_connect) {
            Some(port) => {
                self.open_relay(channel, Kind::Tcp, OpenRequest::Tcp(port), reply, session)
            }
            None => {
                reply
                    .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                    .await;
            }
        }
        Ok(())
    }

    async fn channel_open_direct_streamlocal(
        &mut self,
        channel: Channel<Msg>,
        socket_path: &str,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        match mapping::streamlocal_target(socket_path) {
            Some(path) => {
                self.open_relay(channel, Kind::Unix, OpenRequest::Unix(path), reply, session);
            }
            None => {
                reply
                    .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                    .await;
            }
        }
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        match self.channels.get_mut(&channel) {
            Some(chan) if !chan.relay && chan.started.is_none() => {
                chan.pty = Some(PtyRequest::new(term, col_width, row_height));
                session.channel_success(channel)?;
            }
            _ => session.channel_failure(channel)?,
        }
        Ok(())
    }

    async fn x11_request(
        &mut self,
        channel: ChannelId,
        _single_connection: bool,
        _x11_auth_protocol: &str,
        _x11_auth_cookie: &str,
        _x11_screen_number: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        match self.channels.get_mut(&channel) {
            Some(chan)
                if !chan.relay
                    && chan.started.is_none()
                    && mapping::accept_env(&chan.env, variable_name, variable_value) =>
            {
                chan.env
                    .insert(variable_name.to_owned(), variable_value.to_owned());
                session.channel_success(channel)?;
            }
            _ => session.channel_failure(channel)?,
        }
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.start(channel, &SessionRequest::Shell, session)
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.start(channel, &SessionRequest::Exec(data.to_vec()), session)
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.start(
            channel,
            &SessionRequest::Subsystem(name.to_owned()),
            session,
        )
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(chan) = self.channels.get_mut(&channel) else {
            return Ok(());
        };
        let (rows, cols) = mapping::size_of(col_width, row_height);
        match (chan.started, chan.pty.as_mut()) {
            (Some(Kind::Pty), _) => {
                // Coalesced: only the latest size waits for the connection
                // thread, which is told once.
                if chan.stdin.set_resize(rows, cols) {
                    let local = chan.local;
                    self.command(Cmd::Resize { local });
                }
            }
            (None, Some(pty)) => {
                pty.rows = rows;
                pty.cols = cols;
            }
            _ => {}
        }
        Ok(())
    }

    async fn agent_request(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // No agent forwarding: the guest never reaches the local agent.
        Ok(false)
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        signal: Sig,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(chan) = self.channels.get(&channel)
            && chan.started == Some(Kind::Exec)
            && let Some(signal) = mapping::signal_of(&signal)
            && chan.stdin.admit_signal()
        {
            self.command(Cmd::Signal {
                local: chan.local,
                signal,
            });
        }
        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        _address: &str,
        _port: &mut u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    async fn streamlocal_forward(
        &mut self,
        _socket_path: &str,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(chan) = self.channels.get(&channel) else {
            return Ok(());
        };
        // Never wait here: this runs inside russh's session loop. The
        // client sends no more than the window this channel granted
        // ([`super::input`]), so the budget holds it; an ended or unstarted
        // channel drops the bytes without a copy. The connection thread
        // takes them from the budget and grants them back once sent.
        if chan.stdin.admit(data) == Admit::Overrun {
            self.overrun(channel, session);
        }
        Ok(())
    }

    async fn extended_data(
        &mut self,
        channel: ChannelId,
        _code: u32,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // The guest has no input stream for it: counted, dropped and
        // granted back.
        if let Some(chan) = self.channels.get(&channel)
            && chan.stdin.admit_ignored(data.len()) == Admit::Overrun
        {
            self.overrun(channel, session);
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(chan) = self.channels.get(&channel)
            && chan.started.is_some()
        {
            self.command(Cmd::Eof { local: chan.local });
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.reap();
        if let Some(chan) = self.channels.remove(&channel) {
            let _ = chan.closed.send(true);
            chan.stdin.close();
            if chan.started.is_some() {
                self.command(Cmd::Close { local: chan.local });
            }
            super::input::test_note(&format!("forgot {}", chan.local));
        }
        Ok(())
    }
}

/// The writer of one channel: the wssp side's events, in order, onto the
/// SSH channel; an abort overtakes them.
struct Writer {
    id: ChannelId,
    local: u64,
    kind: Kind,
    write: ChannelWriteHalf<Msg>,
    handle: Handle,
    guard: Guard,
    /// A forward's open, answered on `ready` or refused on its exit.
    reply: Option<ChannelOpenHandle>,
    stdin: Arc<Budget>,
    /// The channel's whole SSH window (a forward's rest is granted with its
    /// accept).
    window: usize,
    commands: mpsc::Sender<Cmd>,
    ending: Arc<Ending>,
    _slot: Arc<Slot>,
}

/// What every write of a channel waits on besides the write itself.
struct Guard {
    /// The SSH client closed the channel.
    closed: watch::Receiver<bool>,
    aborted: watch::Receiver<Option<Abort>>,
    /// A write failed or the client closed: nothing more is written.
    gone: bool,
}

impl Guard {
    /// Run `send` unless the client closes the channel or the channel is
    /// aborted first.
    async fn run<F>(&mut self, send: F) -> Sent
    where
        F: std::future::Future<Output = std::result::Result<(), russh::Error>>,
    {
        if self.gone || *self.closed.borrow() {
            self.gone = true;
            return Sent::Gone;
        }
        let mut closed = self.closed.clone();
        let mut aborted = self.aborted.clone();
        tokio::pin!(send);
        // A write that cannot go at once waits for the client's window.
        let waited = match at_once(&mut send).await {
            Some(result) => return self.sent(result),
            None => {
                super::input::test_note("blocked");
                true
            }
        };
        let sent = tokio::select! {
            biased;
            abort = abort_now(&mut aborted) => Sent::Aborted(abort),
            () = closed_now(&mut closed) => Sent::Gone,
            result = &mut send => self.sent(result),
        };
        if waited {
            super::input::test_note("unblocked");
        }
        if matches!(sent, Sent::Gone) {
            self.gone = true;
        }
        sent
    }

    fn sent(&mut self, result: std::result::Result<(), russh::Error>) -> Sent {
        if result.is_ok() {
            Sent::Done
        } else {
            self.gone = true;
            Sent::Gone
        }
    }

    fn ended(&self) -> bool {
        self.gone || *self.closed.borrow()
    }
}

/// How a guarded write ended.
enum Sent {
    Done,
    /// The SSH client closed the channel (or the session is gone).
    Gone,
    Aborted(Abort),
}

async fn closed_now(closed: &mut watch::Receiver<bool>) {
    if closed.wait_for(|closed| *closed).await.is_err() {
        std::future::pending::<()>().await;
    }
}

async fn abort_now(aborted: &mut watch::Receiver<Option<Abort>>) -> Abort {
    let abort = match aborted.wait_for(Option::is_some).await {
        Ok(abort) => abort.clone(),
        Err(_) => None,
    };
    match abort {
        Some(abort) => abort,
        None => std::future::pending().await,
    }
}

/// Poll `future` once: its output if it is ready at once, else `None` (it
/// is dropped). For a best-effort line that must never wait for window.
async fn at_once<F: std::future::Future>(future: F) -> Option<F::Output> {
    tokio::select! {
        biased;
        output = future => Some(output),
        () = std::future::ready(()) => None,
    }
}

impl Writer {
    async fn run(
        mut self,
        mut events: tokio_mpsc::UnboundedReceiver<Up>,
        routes: Routes,
        retired: Retired,
    ) {
        if let Some(abort) = self.pump(&mut events).await {
            self.abort(&abort).await;
        }
        lock(&routes).remove(&self.local);
        lock(&retired).push((self.id, self.local));
    }

    /// The channel's events in order; `Some` once it is aborted.
    async fn pump(&mut self, events: &mut tokio_mpsc::UnboundedReceiver<Up>) -> Option<Abort> {
        let mut eof_sent = false;
        loop {
            let mut closed = self.guard.closed.clone();
            let mut aborted = self.guard.aborted.clone();
            let event = tokio::select! {
                biased;
                abort = abort_now(&mut aborted) => return Some(abort),
                () = closed_now(&mut closed), if self.reply.is_none() => {
                    // The client closed it: the connection thread discards
                    // its output; nothing is left to write.
                    self.guard.gone = true;
                    return None;
                }
                event = events.recv() => event?,
            };
            match event {
                Up::Ready { .. } => {
                    if let Some(reply) = self.reply.take() {
                        reply.accept().await;
                        // After the accept on the same queue, so russh knows
                        // the channel when the grant comes.
                        let add = self.stdin.widen(self.window);
                        if add > 0 {
                            let _ = self.handle.grant_window(self.id, add);
                        }
                    }
                }
                Up::Output {
                    stream, seq, body, ..
                } => {
                    let sent = match stream {
                        OutputStream::Stdout => {
                            let write = self.write.data_bytes(body);
                            self.guard.run(write).await
                        }
                        OutputStream::Stderr => {
                            let write = self.write.extended_data_bytes(1, body);
                            self.guard.run(write).await
                        }
                    };
                    if let Sent::Aborted(abort) = sent {
                        return Some(abort);
                    }
                    // Acknowledged once the SSH window took it (or the
                    // channel is gone and nobody will).
                    let _ = self.commands.send(Cmd::Delivered {
                        local: self.local,
                        stream,
                        seq,
                    });
                }
                Up::Eof { stream, .. } => {
                    // A relay's eof is its half-close and goes at once. A
                    // session's waits for the exit, after the exit status, as
                    // sshd sends them: an ssh client (a ControlMaster's
                    // sessions, for one) may close the channel once both
                    // sides sent eof, and the status would then be lost.
                    if self.kind.is_relay() && stream == OutputStream::Stdout && !eof_sent {
                        eof_sent = true;
                        let eof = bounded(&self.ending, self.write.eof());
                        if let Sent::Aborted(abort) = self.guard.run(eof).await {
                            return Some(abort);
                        }
                    }
                }
                Up::Exit { outcome, .. } => {
                    if let Some(reply) = self.reply.take() {
                        reply.reject(mapping::open_failure_of(&outcome)).await;
                        return None;
                    }
                    return self.finish(&outcome, eof_sent).await;
                }
                Up::Abort { abort, .. } => return Some(abort),
                Up::Ended(_) => {}
            }
        }
    }

    /// The natural end of a channel, after all its output: a relay's eof
    /// (unless it was reset) or a session's exit status or signal and then its
    /// eof, then the close.
    async fn finish(
        &mut self,
        outcome: &crate::connect_client::mux::Outcome,
        eof_sent: bool,
    ) -> Option<Abort> {
        // A relay that ends without its stdout eof was reset: no eof.
        if !self.kind.is_relay() {
            let sent = match mapping::finish_of(outcome) {
                Finish::Status(status) => {
                    let write = bounded(&self.ending, self.write.exit_status(status));
                    self.guard.run(write).await
                }
                Finish::Signal(number) => {
                    let signal = mapping::exit_signal_of(number);
                    let id = self.write.id();
                    let handle = self.handle.clone();
                    let send = bounded(&self.ending, async move {
                        handle
                            .exit_signal_request(id, signal, false, String::new(), String::new())
                            .await
                            .map_err(|()| russh::Error::SendError)
                    });
                    self.guard.run(send).await
                }
                // A wssp-side end goes through `abort`.
                Finish::Message(_) | Finish::Nothing => Sent::Done,
            };
            if let Sent::Aborted(abort) = sent {
                return Some(abort);
            }
            if !eof_sent {
                let eof = bounded(&self.ending, self.write.eof());
                if let Sent::Aborted(abort) = self.guard.run(eof).await {
                    return Some(abort);
                }
            }
        }
        let close = bounded(&self.ending, self.write.close());
        if let Sent::Aborted(abort) = self.guard.run(close).await {
            return Some(abort);
        }
        None
    }

    /// An abort: whatever output is queued or half-written is dropped, a
    /// forward's pending open is refused, a process channel gets one
    /// best-effort `wssp: …` line (only if the client's window takes it at
    /// once), and the channel closes without an eof or exit status, so ssh
    /// reports the end as an abort (exit 255 for a session). No step waits
    /// for window credit.
    async fn abort(&mut self, abort: &Abort) {
        if let Some(reply) = self.reply.take() {
            let failure = match abort {
                Abort::Wssp(outcome) => mapping::open_failure_of(outcome),
                Abort::Overrun => russh::ChannelOpenFailure::ConnectFailed,
            };
            reply.reject(failure).await;
            return;
        }
        if self.guard.ended() {
            return;
        }
        let line = match abort {
            Abort::Wssp(outcome) => match mapping::finish_of(outcome) {
                Finish::Message(line) => Some(line),
                _ => None,
            },
            Abort::Overrun => Some(mapping::OVERRUN_LINE.to_owned()),
        };
        if let Some(line) = line
            && !self.kind.is_relay()
        {
            if self.kind == Kind::Pty {
                let _ = at_once(
                    self.write
                        .data_bytes(format!("\r\n{line}\r\n").into_bytes()),
                )
                .await;
            } else {
                let _ = at_once(
                    self.write
                        .extended_data_bytes(1, format!("{line}\n").into_bytes()),
                )
                .await;
            }
        }
        let _ = bounded(&self.ending, self.write.close()).await;
    }
}

/// A channel's last message (no window needed) bounded by [`FINAL_WRITE`]
/// in russh's session queue. One that cannot be queued in time would leave
/// the client's channel open with nothing left to end it, so the whole
/// session ends instead ([`Ending::stuck`]), within [`TEARDOWN`].
async fn bounded<F>(ending: &Ending, send: F) -> std::result::Result<(), russh::Error>
where
    F: std::future::Future<Output = std::result::Result<(), russh::Error>>,
{
    match tokio::time::timeout(FINAL_WRITE, send).await {
        Ok(result) => result,
        Err(_) => {
            ending.stuck();
            Err(russh::Error::SendError)
        }
    }
}

/// Route the connection thread's events to the channel writers; returns
/// why the connection ended.
async fn route(mut up: tokio_mpsc::UnboundedReceiver<Up>, routes: Routes) -> anyhow::Error {
    while let Some(event) = up.recv().await {
        match event {
            Up::Ended(error) => return error,
            // An abort overtakes the channel's queued events.
            Up::Abort { local, abort } => {
                if let Some(route) = lock(&routes).get(&local) {
                    route.abort.send_replace(Some(abort));
                }
            }
            event => {
                if let Some(local) = event.local() {
                    let sender = lock(&routes).get(&local).map(|route| route.events.clone());
                    if let Some(sender) = sender {
                        let _ = sender.send(event);
                    }
                }
            }
        }
    }
    anyhow::anyhow!("the connection thread stopped")
}

/// The end of the session: the first end (ssh's disconnect or its stdin
/// closing, a wssp end, a stuck session) starts one absolute deadline,
/// [`TEARDOWN`], that every later step shares.
#[derive(Debug)]
struct Ending {
    begun: watch::Sender<Option<Instant>>,
    stuck: watch::Sender<bool>,
}

impl Ending {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            begun: watch::channel(None).0,
            stuck: watch::channel(false).0,
        })
    }

    /// The end starts now, unless it already did.
    fn begin(&self) {
        self.begun.send_if_modified(|at| {
            if at.is_some() {
                return false;
            }
            *at = Some(Instant::now());
            true
        });
    }

    /// A channel's last message could not be queued in time: the session
    /// ends now.
    fn stuck(&self) {
        self.begin();
        self.stuck.send_replace(true);
    }

    /// When the end started (now if it had not).
    fn started(&self) -> Instant {
        self.begin();
        (*self.begun.borrow()).unwrap_or_else(Instant::now)
    }

    async fn begun(&self) -> Instant {
        let mut begun = self.begun.subscribe();
        match begun.wait_for(Option::is_some).await {
            Ok(at) => (*at).unwrap_or_else(Instant::now),
            Err(_) => std::future::pending().await,
        }
    }

    async fn stuck_now(&self) {
        let mut stuck = self.stuck.subscribe();
        if stuck.wait_for(|stuck| *stuck).await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// The transport as russh sees it (one end of the in-memory duplex): its
/// shutdown (after the client's disconnect, or at the end) starts the end.
struct Watched<S> {
    inner: S,
    ending: Arc<Ending>,
    /// The last write found the transport full (for the test notes).
    full: bool,
}

impl<S: AsyncRead + Unpin> AsyncRead for Watched<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Watched<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(cx, buf);
        let full = polled.is_pending();
        if full != self.full {
            self.full = full;
            super::input::test_note(if full {
                "transport full"
            } else {
                "transport open"
            });
        }
        polled
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.ending.begin();
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// ssh's input → russh: reads stdin whatever russh is doing (up to
/// [`READ_AHEAD`] ahead of it), so the end of stdin starts the end even
/// while russh waits for a blocked stdout. While the read-ahead is full the
/// pump reads nothing, but `hangup` (the writer of stdin is gone, seen even
/// behind unread bytes) still starts the end: the end of the transport's
/// input is observed whatever the buffering.
async fn stdin_pump<R, W, H>(mut input: R, mut to_russh: W, hangup: H, ending: Arc<Ending>)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    H: std::future::Future<Output = ()>,
{
    tokio::pin!(hangup);
    let mut chunk = vec![0_u8; 32 * 1024];
    let mut ahead: VecDeque<u8> = VecDeque::new();
    let mut open = true;
    let mut hung_up = false;
    let mut full = false;
    loop {
        if !open && ahead.is_empty() {
            break;
        }
        let room = open && ahead.len() < READ_AHEAD;
        if full == room {
            full = !room;
            super::input::test_note(if full {
                "read-ahead full"
            } else {
                "read-ahead open"
            });
        }
        tokio::select! {
            read = input.read(&mut chunk), if room => match read {
                Ok(n) if n > 0 => ahead.extend(&chunk[..n]),
                // The end of ssh's input (or a read error): the end starts.
                _ => {
                    open = false;
                    ending.begin();
                }
            },
            // Reads are paused: the end of the input still starts the end.
            () = &mut hangup, if open && !room && !hung_up => {
                hung_up = true;
                ending.begin();
            },
            wrote = to_russh.write(ahead.as_slices().0), if !ahead.is_empty() => match wrote {
                Ok(n) if n > 0 => {
                    ahead.drain(..n);
                }
                // russh is gone.
                _ => return,
            },
        }
    }
    let _ = to_russh.shutdown().await;
}

/// Resolves once the writer of this process's stdin is gone (a pipe's
/// `POLLHUP`, a socket's `POLLRDHUP`), even while unread bytes are still in
/// it. A thread waits in `poll` for the hang-up alone (no `POLLIN`, so
/// readable data never wakes it); never resolves if stdin cannot be polled.
#[cfg(target_os = "linux")]
async fn stdin_hung_up() {
    let (gone, hung_up) = tokio::sync::oneshot::channel();
    let watch = std::thread::Builder::new()
        .name("wssp-ssh-stdin".into())
        .spawn(move || {
            if writer_gone(&std::io::stdin()) {
                let _ = gone.send(());
            }
        });
    if watch.is_err() || hung_up.await.is_err() {
        std::future::pending::<()>().await;
    }
}

#[cfg(not(target_os = "linux"))]
async fn stdin_hung_up() {
    std::future::pending().await
}

/// Blocks until `fd` reports its writer gone (`true`), or `false` if it
/// cannot be polled.
#[cfg(target_os = "linux")]
fn writer_gone(fd: &impl std::os::fd::AsFd) -> bool {
    use rustix::event::{PollFd, PollFlags, poll};
    loop {
        let mut fds = [PollFd::new(fd, PollFlags::RDHUP)];
        match poll(&mut fds, None) {
            Ok(_) => {
                let seen = fds[0].revents();
                if seen.intersects(PollFlags::RDHUP | PollFlags::HUP | PollFlags::ERR) {
                    return true;
                }
                // `POLLNVAL` or nothing: not a hang-up that will ever come.
                if seen.contains(PollFlags::NVAL) {
                    return false;
                }
            }
            Err(rustix::io::Errno::INTR) => {}
            Err(_) => return false,
        }
    }
}

/// russh's output → ssh. A failed write (ssh is gone) starts the end; the
/// rest of russh's output is then read and dropped, so russh never waits on
/// it.
async fn stdout_pump<R, W>(mut from_russh: R, mut output: W, ending: Arc<Ending>)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut chunk = vec![0_u8; 64 * 1024];
    let mut writable = true;
    loop {
        let n = match from_russh.read(&mut chunk).await {
            Ok(n) if n > 0 => n,
            _ => break,
        };
        if writable {
            let wrote = output.write_all(&chunk[..n]).await;
            if wrote.is_err() || output.flush().await.is_err() {
                writable = false;
                ending.begin();
            }
        }
    }
    if writable {
        let _ = output.flush().await;
    }
}

/// How the session ended.
enum End {
    /// The SSH client went away (or broke the protocol).
    Ssh,
    /// The wssp connection ended.
    Wssp(anyhow::Error),
    /// A channel's last message could not be queued ([`bounded`]).
    Stuck,
}

async fn session(
    config: russh::server::Config,
    commands: mpsc::Sender<Cmd>,
    up: tokio_mpsc::UnboundedReceiver<Up>,
    caps: Caps,
    ending: Arc<Ending>,
) -> End {
    let routes: Routes = Arc::new(Mutex::new(HashMap::new()));
    let endpoint = Endpoint::new(commands, routes.clone(), caps, ending.clone());
    let (russh_side, pump_side) = tokio::io::duplex(TRANSPORT_BUFFER);
    let (from_russh, to_russh) = tokio::io::split(pump_side);
    tokio::spawn(stdin_pump(
        tokio::io::stdin(),
        to_russh,
        stdin_hung_up(),
        ending.clone(),
    ));
    tokio::spawn(stdout_pump(from_russh, tokio::io::stdout(), ending.clone()));
    let stream = Watched {
        inner: russh_side,
        ending: ending.clone(),
        full: false,
    };
    let router = route(up, routes);
    tokio::pin!(router);
    // Once the end started, russh gets a fixed time (from that start) to
    // finish reading the client's side, whatever the healthy-session timers
    // and the output are.
    let drained = async {
        let at = ending.begun().await;
        tokio::time::sleep_until(tokio::time::Instant::from_std(at + DISCONNECT_DRAIN)).await;
    };
    tokio::pin!(drained);
    let stuck = ending.stuck_now();
    tokio::pin!(stuck);
    let running = tokio::select! {
        biased;
        error = &mut router => return End::Wssp(error),
        () = &mut stuck => return End::Stuck,
        () = &mut drained => return End::Ssh,
        running = russh::server::run_stream(Arc::new(config), stream, endpoint) => running,
    };
    let Ok(running) = running else {
        return End::Ssh;
    };
    tokio::pin!(running);
    // A protocol error of the ssh client ends the session like a
    // disconnect; ssh reports its own side.
    tokio::select! {
        biased;
        error = &mut router => End::Wssp(error),
        () = &mut stuck => End::Stuck,
        () = &mut drained => End::Ssh,
        _ = &mut running => End::Ssh,
    }
}

/// Serve SSH on stdin/stdout over `connection` until either side ends, then
/// end the process (an error is returned only before the session starts).
pub fn serve(connection: Connection, key: PrivateKey) -> Result<()> {
    let caps = Caps::of(connection.limits());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .context("starting the ssh runtime")?;
    let (commands, receiver) = mpsc::channel();
    let (up, up_receiver) = tokio_mpsc::unbounded_channel();
    // From here this runtime owns stdout (the SSH transport) and nothing
    // writes stderr: a log event is written on the thread that emits it, and
    // neither the session loop nor the connection thread may wait on a
    // stderr nobody reads. The hold lasts until the process exits.
    crate::logging::hold_stderr(true);
    let bridge = std::thread::Builder::new()
        .name("wssp-ssh-connect".into())
        .spawn(move || bridge::run(connection, receiver, up))
        .context("starting the connection thread")?;
    let ending = Ending::new();
    let end = runtime.block_on(session(
        config(key, &caps),
        commands.clone(),
        up_receiver,
        caps,
        ending.clone(),
    ));
    // One deadline from the start of the end for everything that follows.
    let started = ending.started();
    // The stdin pump may be blocked in a read, and the stdout pump in a
    // write to a client that stopped reading: never wait for either.
    runtime.shutdown_background();
    let close_channels = |deadline: Instant| {
        let _ = commands.send(Cmd::Shutdown);
        while !bridge.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
    };
    let (line, status) = match end {
        End::Ssh => {
            close_channels(started + BRIDGE_DEADLINE);
            (None, 0)
        }
        End::Stuck => {
            close_channels(started + BRIDGE_DEADLINE);
            let error = anyhow::anyhow!(
                "the ssh session took no channel message for {} s; it was ended",
                FINAL_WRITE.as_secs()
            );
            (
                crate::exit::failure_line(&error),
                crate::exit::code_for(&error) as i32,
            )
        }
        // The ssh client sees its ProxyCommand's stdio close (and exits
        // 255) as this process exits; the error line goes to its stderr.
        End::Wssp(error) => {
            let error = super::super::shell::wssp_side(error);
            (
                crate::exit::failure_line(&error),
                crate::exit::code_for(&error) as i32,
            )
        }
    };
    // A blocked tokio stdout write may hold the stdout lock: the final line
    // and the exit never wait on it past the deadline.
    super::super::shell::final_report_by(line, status, started + TEARDOWN)
}

#[cfg(test)]
mod tests {
    /// The source of the code that runs once the session started.
    fn session_sources() -> [(&'static str, &'static str); 4] {
        [
            ("server.rs", include_str!("server.rs")),
            ("bridge.rs", include_str!("bridge.rs")),
            ("input.rs", include_str!("input.rs")),
            ("mapping.rs", include_str!("mapping.rs")),
        ]
    }

    /// The non-test part of a source file.
    fn code(source: &str) -> &str {
        source
            .find("#[cfg(test)]\nmod tests")
            .map_or(source, |at| &source[..at])
    }

    /// Invariant 1: once the session runs, only the runtime's transport
    /// (`tokio::io::stdout`, in `session`) writes fd 1 and nothing writes
    /// fd 2 but the bounded final report. Nothing in the session's code
    /// prints, locks the std streams or writes through `output`.
    #[test]
    fn nothing_but_the_transport_writes_the_standard_streams() {
        let banned = [
            "println!",
            "eprintln!",
            "print!(",
            "eprint!(",
            "dbg!(",
            "std::io::stdout",
            "std::io::stderr",
            "io::stderr()",
            "flush_stdout",
            "output::line",
            "output::text",
            "output::json",
            "output::diagnostic",
            "output::bytes",
        ];
        for (name, source) in session_sources() {
            let code = code(source);
            for pattern in banned {
                assert!(!code.contains(pattern), "{name} uses `{pattern}`");
            }
            let owner = usize::from(name == "server.rs");
            assert_eq!(code.matches("io::stdout()").count(), owner, "{name}");
            assert_eq!(code.matches("tokio::io::stdout()").count(), owner, "{name}");
        }
        let server = code(include_str!("server.rs"));
        assert_eq!(server.matches("final_report_by(").count(), 1);
        assert_eq!(server.matches("tokio::io::stdin()").count(), 1);
    }

    fn current_thread() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
    }

    /// ssh's side of stdin: always more to read, never an end (the end can
    /// only come from the hang-up); counts what it handed out.
    struct Endless(std::sync::Arc<std::sync::atomic::AtomicUsize>);

    impl tokio::io::AsyncRead for Endless {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let n = buf.remaining();
            buf.put_slice(&vec![7_u8; n]);
            self.0.fetch_add(n, std::sync::atomic::Ordering::SeqCst);
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// Invariants 4 and 5: russh takes nothing (its side of the transport is
    /// never read), so the pump fills its read-ahead and stops reading; the
    /// hang-up of stdin, behind bytes nobody read, still starts the end.
    #[test]
    fn a_hang_up_behind_a_full_read_ahead_starts_the_end() {
        use std::sync::atomic::Ordering;
        current_thread().block_on(async {
            let ending = super::Ending::new();
            let read = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let (_russh, to_russh) = tokio::io::duplex(1024);
            let (hang_up, hung_up) = tokio::sync::oneshot::channel::<()>();
            let hung_up = async {
                let _ = hung_up.await;
            };
            let input = Endless(read.clone());
            let pump = tokio::spawn(super::stdin_pump(input, to_russh, hung_up, ending.clone()));
            while read.load(Ordering::SeqCst) < super::READ_AHEAD {
                tokio::task::yield_now().await;
            }
            for _ in 0..100 {
                tokio::task::yield_now().await;
            }
            // Paused: nothing more is read, and nothing ended.
            let paused = read.load(Ordering::SeqCst);
            for _ in 0..100 {
                tokio::task::yield_now().await;
            }
            assert_eq!(read.load(Ordering::SeqCst), paused, "the pump kept reading");
            assert!(paused < super::READ_AHEAD + 64 * 1024, "{paused}");
            assert!(ending.begun.borrow().is_none());
            hang_up.send(()).unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(10), ending.begun())
                .await
                .expect("the hang-up behind the full read-ahead was not seen");
            pump.abort();
        });
    }

    /// The hang-up watch sees a pipe's and a socket's writer go while unread
    /// bytes are still in them, and readable data alone never wakes it.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_writers_end_is_seen_behind_unread_bytes() {
        use std::io::Write;
        // A watch that never returns fails the test instead of hanging it.
        fn watch(fd: impl std::os::fd::AsFd + Send + 'static) -> std::sync::mpsc::Receiver<bool> {
            let (seen, watched) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = seen.send(super::writer_gone(&fd));
            });
            watched
        }
        const BOUND: std::time::Duration = std::time::Duration::from_secs(10);

        let (reader, mut writer) = std::io::pipe().unwrap();
        writer.write_all(b"unread").unwrap();
        let watched = watch(reader);
        assert!(
            watched
                .recv_timeout(std::time::Duration::from_millis(100))
                .is_err(),
            "readable data woke the watch"
        );
        drop(writer);
        assert_eq!(watched.recv_timeout(BOUND), Ok(true), "a pipe's hang-up");

        let (reader, mut writer) = std::os::unix::net::UnixStream::pair().unwrap();
        writer.write_all(b"unread").unwrap();
        let watched = watch(reader);
        writer.shutdown(std::net::Shutdown::Write).unwrap();
        assert_eq!(watched.recv_timeout(BOUND), Ok(true), "a socket's hang-up");
    }

    /// Invariant 10: no listener in the endpoint or the connection it uses
    /// (the census test of `tests/ssh_stdio.rs` checks the live process).
    #[test]
    fn nothing_here_listens_or_binds() {
        let sources = [
            ("ssh/mod.rs", include_str!("mod.rs")),
            ("ssh/config.rs", include_str!("config.rs")),
            (
                "connect_client/mod.rs",
                include_str!("../../../connect_client/mod.rs"),
            ),
            (
                "connect_client/mux.rs",
                include_str!("../../../connect_client/mux.rs"),
            ),
            (
                "connect_client/wire.rs",
                include_str!("../../../connect_client/wire.rs"),
            ),
        ];
        let banned = [
            "TcpListener",
            "UnixListener",
            "UdpSocket",
            "UnixDatagram",
            "bind(",
            "listen(",
            "run_on_address",
            "run_on_socket",
            "tokio::net",
        ];
        for (name, source) in session_sources().into_iter().chain(sources) {
            let code = code(source);
            for pattern in banned {
                assert!(!code.contains(pattern), "{name} uses `{pattern}`");
            }
        }
    }
}
