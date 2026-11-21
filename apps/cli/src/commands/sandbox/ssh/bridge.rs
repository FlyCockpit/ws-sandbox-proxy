//! The connection thread of `wssp ssh --stdio`: it owns the
//! `wssp.connect.v1` connection (tungstenite, blocking) and moves frames
//! between it and the SSH side (tokio).
//!
//! - SSH → wssp ([`Cmd`], a std channel): opens, eof, resize and signal
//!   notices, closes and delivery reports. stdin bytes do not travel here:
//!   each channel's [`Budget`] holds them and this thread takes them as it
//!   sends them.
//! - wssp → SSH ([`Up`], a tokio channel): ready, output, eof, exit, a
//!   channel's abort, and the end of the whole connection.
//!
//! Every queue is bounded by construction, not by its own size:
//! - output frames leave this thread only within the channel's credit window
//!   (at most `windowFrames` unacknowledged), and a frame is acknowledged
//!   only once the SSH side reports it [`Cmd::Delivered`], that is, once the
//!   SSH client's window took it;
//! - stdin bytes stay in the channel's [`Budget`] (never more than the
//!   channel's SSH window) and leave it only as stdin frames within the
//!   channel's credit; what left is granted back to the SSH client as window
//!   ([`Grant`]) after the flush, once per channel and turn;
//! - a channel's lifecycle (one open, eof, close) holds a [`Slot`] from its
//!   SSH open until this thread is done with it, so channel churn is capped
//!   at [`MAX_CHANNELS`] lifecycles through bridge completion; resizes
//!   coalesce in the budget and signals are capped there.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use russh::ChannelId;
use tokio::sync::mpsc::UnboundedSender;

use super::input::Budget;

use crate::connect_client::Connection;
use crate::connect_client::mux::{Event, Outcome};
use crate::connect_client::wire::{Intent, Kind, OutputStream, PtyParams, Signal};

/// stdin frames one channel sends per loop turn at most, after the acks.
const STDIN_FRAMES_PER_TURN: usize = 4;
/// Commands handled per loop turn at most, so the socket keeps its turn.
const COMMANDS_PER_TURN: usize = 256;
/// How long the end of the SSH session waits for the channels' exits.
const CLOSE_WAIT: Duration = Duration::from_secs(2);
/// SSH channel lifecycles at once at most, from the SSH open until this
/// thread is done with the channel (wssp allows 32 live channels per
/// connection; session channels that never start cost it nothing).
pub const MAX_CHANNELS: usize = 128;

/// The lifecycles in progress.
#[derive(Debug, Default)]
pub struct Slots {
    live: AtomicUsize,
}

impl Slots {
    /// A slot for one more channel, or `None` at [`MAX_CHANNELS`].
    pub fn take(self: &Arc<Self>) -> Option<Arc<Slot>> {
        if self.live.fetch_add(1, Ordering::SeqCst) >= MAX_CHANNELS {
            self.live.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(Arc::new(Slot(self.clone())))
    }

    #[cfg(test)]
    pub fn live(&self) -> usize {
        self.live.load(Ordering::SeqCst)
    }
}

/// One channel's lifecycle: the SSH side's channel entry, its writer and
/// this thread's link each hold it, and it is free once all three let go
/// (every end path drops them).
#[derive(Debug)]
pub struct Slot(Arc<Slots>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Where a channel's window grants go: its SSH channel in the session
/// (russh's unbounded priority queue, so sending never waits; a grant for a
/// channel that is gone is dropped there).
#[derive(Debug, Clone)]
pub struct Grant {
    pub handle: russh::server::Handle,
    pub id: ChannelId,
}

impl Grant {
    fn send(&self, bytes: u32) {
        // Fails only once the session is gone.
        let _ = self.handle.grant_window(self.id, bytes);
    }
}

/// What a channel opens on the wssp side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenRequest {
    Process {
        kind: Kind,
        argv: Option<Vec<String>>,
        login: bool,
        env: BTreeMap<String, String>,
        pty: Option<PtyParams>,
    },
    Tcp(u16),
    Unix(String),
}

/// SSH side → connection thread. `local` is the SSH side's channel key.
#[derive(Debug)]
pub enum Cmd {
    Open {
        local: u64,
        request: OpenRequest,
        stdin: Arc<Budget>,
        grant: Grant,
        slot: Arc<Slot>,
    },
    /// The SSH client sent its eof; it follows the queued bytes.
    Eof { local: u64 },
    /// A new size waits in the channel's budget.
    Resize { local: u64 },
    /// One signal admitted by the channel's budget.
    Signal { local: u64, signal: Signal },
    /// The SSH channel is gone: discard its output and close it (a hang-up).
    Close { local: u64 },
    /// An output frame was taken by the SSH client's window.
    Delivered {
        local: u64,
        stream: OutputStream,
        seq: u64,
    },
    /// The SSH session ended: close every channel and the connection.
    Shutdown,
}

/// Why a channel is aborted instead of ending in order.
#[derive(Debug, Clone)]
pub enum Abort {
    /// wssp closed it (backpressure, lifetime, revocation, stop, …) or its
    /// open failed.
    Wssp(Outcome),
    /// The SSH client sent past the channel's window
    /// ([`super::input::Admit::Overrun`]).
    Overrun,
}

/// Connection thread → SSH side.
#[derive(Debug)]
pub enum Up {
    Ready {
        local: u64,
    },
    Output {
        local: u64,
        stream: OutputStream,
        seq: u64,
        body: Vec<u8>,
    },
    Eof {
        local: u64,
        stream: OutputStream,
    },
    /// A natural end, after every earlier event of the channel.
    Exit {
        local: u64,
        outcome: Outcome,
    },
    /// An abort: it overtakes the channel's queued events (its writer
    /// discards them and closes the SSH channel without waiting for window).
    Abort {
        local: u64,
        abort: Abort,
    },
    /// The whole connection ended (revoked, stopped, lost, …); the SSH
    /// session ends with it.
    Ended(anyhow::Error),
}

impl Up {
    pub fn local(&self) -> Option<u64> {
        match self {
            Self::Ready { local }
            | Self::Output { local, .. }
            | Self::Eof { local, .. }
            | Self::Exit { local, .. }
            | Self::Abort { local, .. } => Some(*local),
            Self::Ended(_) => None,
        }
    }
}

/// Whether an exit aborts the channel rather than ending it in order: a
/// close decision of wssp (any but this side's own) or a failure. A natural
/// exit (a status, a signal, a relay's end) keeps its output first.
pub fn is_abort(outcome: &Outcome) -> bool {
    match outcome {
        Outcome::Closed { intent, .. } => *intent != Intent::Client,
        Outcome::Failed { .. } => true,
        Outcome::Code(_) | Outcome::Signal(_) | Outcome::Unknown => false,
    }
}

/// One channel as this thread keeps it.
struct Link {
    channel: u32,
    kind: Kind,
    ready: bool,
    /// The SSH client sent its eof; it follows the queued bytes.
    eof: bool,
    /// A size that arrived before `ready`.
    resize: Option<(u16, u16)>,
    stdin: Arc<Budget>,
    grant: Grant,
    data_max: usize,
    /// Reset here: nothing more of it goes to the SSH side.
    aborted: bool,
    _slot: Arc<Slot>,
}

/// The bridge state; [`run`] drives it.
struct Bridge {
    connection: Connection,
    commands: mpsc::Receiver<Cmd>,
    up: UnboundedSender<Up>,
    links: BTreeMap<u64, Link>,
    /// wssp channel id → local key.
    locals: BTreeMap<u32, u64>,
    /// Ended channels whose state the mux still holds (forgotten once their
    /// acks are out).
    ended: Vec<u32>,
    /// stdin round robin: the next turn starts at this local key, which
    /// moves past a channel only once it sent a frame.
    cursor: u64,
}

/// Drive the connection until the SSH side shuts down or the connection
/// ends; in the latter case the last [`Up`] is [`Up::Ended`].
pub fn run(connection: Connection, commands: mpsc::Receiver<Cmd>, up: UnboundedSender<Up>) {
    let mut bridge = Bridge {
        connection,
        commands,
        up,
        links: BTreeMap::new(),
        locals: BTreeMap::new(),
        ended: Vec::new(),
        cursor: 0,
    };
    let result = bridge.pump();
    match result {
        Ok(()) => bridge.connection.finish(),
        Err(error) => {
            for link in bridge.links.values_mut() {
                link.stdin.close();
            }
            let _ = bridge.up.send(Up::Ended(error));
        }
    }
}

impl Bridge {
    fn pump(&mut self) -> anyhow::Result<()> {
        loop {
            if self.commands_turn()? {
                return self.shutdown();
            }
            let events = self.connection.poll()?;
            for event in events {
                self.on_event(event);
            }
            self.send_stdin()?;
            self.connection.flush()?;
            // What left as stdin frames is window for the SSH client again.
            self.send_grants();
            self.forget_ended();
        }
    }

    /// Handle the queued commands; `true` on [`Cmd::Shutdown`] or when the
    /// SSH side is gone.
    fn commands_turn(&mut self) -> anyhow::Result<bool> {
        for _ in 0..COMMANDS_PER_TURN {
            let command = match self.commands.try_recv() {
                Ok(command) => command,
                Err(mpsc::TryRecvError::Empty) => return Ok(false),
                Err(mpsc::TryRecvError::Disconnected) => return Ok(true),
            };
            if self.on_command(command)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn on_command(&mut self, command: Cmd) -> anyhow::Result<bool> {
        match command {
            Cmd::Open {
                local,
                request,
                stdin,
                grant,
                slot,
            } => self.open(local, request, stdin, grant, slot)?,
            Cmd::Eof { local } => {
                if let Some(link) = self.links.get_mut(&local) {
                    link.eof = true;
                }
            }
            Cmd::Resize { local } => {
                if let Some(link) = self.links.get_mut(&local)
                    && let Some((rows, cols)) = link.stdin.take_resize()
                    && link.kind == Kind::Pty
                    && !link.aborted
                {
                    if link.ready {
                        self.connection.resize(link.channel, rows, cols)?;
                    } else {
                        link.resize = Some((rows, cols));
                    }
                }
            }
            Cmd::Signal { local, signal } => {
                if let Some(link) = self.links.get(&local) {
                    link.stdin.signal_done();
                    if link.kind == Kind::Exec && link.ready && !link.aborted {
                        self.connection.signal(link.channel, signal)?;
                    }
                }
            }
            Cmd::Close { local } => {
                if let Some(link) = self.links.get_mut(&local) {
                    let channel = link.channel;
                    link.stdin.close();
                    if !link.aborted {
                        link.aborted = true;
                        let released = self.connection.abort_channel(channel)?;
                        for event in released {
                            self.on_event(event);
                        }
                    }
                }
            }
            Cmd::Delivered { local, stream, seq } => {
                if let Some(link) = self.links.get(&local) {
                    let released = self.connection.delivered(link.channel, stream, seq);
                    for event in released {
                        self.on_event(event);
                    }
                }
            }
            Cmd::Shutdown => return Ok(true),
        }
        Ok(false)
    }

    fn open(
        &mut self,
        local: u64,
        request: OpenRequest,
        stdin: Arc<Budget>,
        grant: Grant,
        slot: Arc<Slot>,
    ) -> anyhow::Result<()> {
        if stdin.is_closed() {
            // The SSH channel went away before its open got here.
            return Ok(());
        }
        let (channel, kind) = match request {
            OpenRequest::Process {
                kind,
                argv,
                login,
                env,
                pty,
            } => {
                let env = (!env.is_empty()).then_some(env);
                let channel = self
                    .connection
                    .open(kind, argv, Some(login), None, env, pty)?;
                (channel, kind)
            }
            OpenRequest::Tcp(port) => (self.connection.open_relay(Some(port), None)?, Kind::Tcp),
            OpenRequest::Unix(path) => (self.connection.open_relay(None, Some(path))?, Kind::Unix),
        };
        self.locals.insert(channel, local);
        self.links.insert(
            local,
            Link {
                channel,
                kind,
                ready: false,
                eof: false,
                resize: None,
                stdin,
                grant,
                data_max: self.connection.data_max(kind),
                aborted: false,
                _slot: slot,
            },
        );
        Ok(())
    }

    fn send_up(&self, up: Up) {
        if self.up.send(up).is_err() {
            // The SSH side is gone; the next commands turn shuts down.
        }
    }

    fn on_event(&mut self, event: Event) {
        let channel = match &event {
            Event::Ready { channel, .. }
            | Event::Output { channel, .. }
            | Event::Eof { channel, .. }
            | Event::Exit { channel, .. }
            | Event::Notice { channel, .. } => *channel,
        };
        let Some(&local) = self.locals.get(&channel) else {
            return;
        };
        let aborted = self.links.get(&local).is_none_or(|link| link.aborted);
        let up = match event {
            Event::Ready { .. } => {
                if let Some(link) = self.links.get_mut(&local) {
                    link.ready = true;
                    if let Some((rows, cols)) = link.resize.take() {
                        let _ = self.connection.resize(channel, rows, cols);
                    }
                }
                Up::Ready { local }
            }
            Event::Output {
                stream, seq, body, ..
            } => Up::Output {
                local,
                stream,
                seq,
                body,
            },
            Event::Eof { stream, .. } => Up::Eof { local, stream },
            Event::Exit { outcome, .. } => {
                // The exit is the channel's last event: later frames for it
                // and late delivery reports are ignored. Its budget closes
                // (no more grants) before the SSH side hears of it.
                if let Some(link) = self.links.remove(&local) {
                    link.stdin.close();
                }
                self.locals.remove(&channel);
                self.ended.push(channel);
                if is_abort(&outcome) {
                    Up::Abort {
                        local,
                        abort: Abort::Wssp(outcome),
                    }
                } else {
                    Up::Exit { local, outcome }
                }
            }
            // `unsupported_signal`, `state_conflict`: nothing to show.
            Event::Notice { .. } => return,
        };
        if !aborted {
            self.send_up(up);
        }
    }

    /// Send the queued stdin of every ready channel within its credit, round
    /// robin from the cursor (it moves past a channel only once it was
    /// served, so returned credit reaches every channel in turn, never only
    /// the lowest keys); then each eof once nothing waits (an eof needs no
    /// credit).
    fn send_stdin(&mut self) -> anyhow::Result<()> {
        self.connection.queue_acks()?;
        let order: Vec<u64> = self.links.keys().copied().collect();
        let (links, connection) = (&mut self.links, &mut self.connection);
        round_robin(&order, &mut self.cursor, |local| {
            let Some(link) = links.get_mut(&local) else {
                return Ok(false);
            };
            if !link.ready || link.aborted {
                return Ok(false);
            }
            let mut sent = 0;
            while sent < STDIN_FRAMES_PER_TURN && connection.stdin_credit(link.channel) {
                let Some(bytes) = link.stdin.take(link.data_max) else {
                    break;
                };
                connection.send_stdin(link.channel, &bytes)?;
                sent += 1;
            }
            // A pty has no stdin eof (sshd keeps the terminal open).
            if link.eof && link.kind != Kind::Pty && link.stdin.is_empty() {
                connection.stdin_eof(link.channel)?;
            }
            Ok(sent > 0)
        })
    }

    /// Grant each channel's SSH client the window its sent stdin frames
    /// freed: one grant per channel and turn, never for an ended channel.
    fn send_grants(&self) {
        for link in self.links.values() {
            if link.aborted {
                continue;
            }
            if let Some(bytes) = link.stdin.take_grant() {
                link.grant.send(bytes);
            }
        }
    }

    /// Drop the mux state of ended channels: their acks were queued by the
    /// flush before this, so [`Connection::forget`] lets go of them.
    fn forget_ended(&mut self) {
        for channel in self.ended.drain(..) {
            self.connection.forget(channel);
        }
    }

    /// Close every live channel and wait (bounded) for their exits.
    fn shutdown(&mut self) -> anyhow::Result<()> {
        let live: Vec<u32> = self.links.values().map(|link| link.channel).collect();
        for link in self.links.values() {
            link.stdin.close();
        }
        for channel in &live {
            let _ = self.connection.abort_channel(*channel)?;
        }
        self.connection.flush()?;
        let deadline = Instant::now() + CLOSE_WAIT;
        while Instant::now() < deadline && live.iter().any(|c| !self.connection.is_done(*c)) {
            // Output racing the closes was discarded (and is acknowledged).
            let _ = self.connection.poll()?;
            self.connection.flush()?;
        }
        Ok(())
    }
}

/// One round of the stdin round robin over `order` (ascending keys),
/// starting at `cursor`: `serve` sends what one channel may now and says
/// whether it sent anything. The cursor moves past a channel only once it
/// was served, so a channel that had nothing (or no credit) this turn keeps
/// its place and the next turn starts with it.
fn round_robin(
    order: &[u64],
    cursor: &mut u64,
    mut serve: impl FnMut(u64) -> anyhow::Result<bool>,
) -> anyhow::Result<()> {
    let start = order.partition_point(|key| *key < *cursor);
    for &key in order[start..].iter().chain(&order[..start]) {
        if serve(key)? {
            *cursor = key.saturating_add(1);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shared credit for two frames a turn among five busy channels: each
    /// gets its share, the later keys as much as the first ones.
    #[test]
    fn a_later_channel_gets_its_share_of_the_stdin_credit() {
        let order = [3_u64, 5, 8, 13, 21];
        let mut cursor = 0;
        let mut sent: BTreeMap<u64, usize> = BTreeMap::new();
        for _ in 0..1000 {
            let mut credit = 2;
            round_robin(&order, &mut cursor, |key| {
                let mut frames = 0;
                while frames < STDIN_FRAMES_PER_TURN && credit > 0 {
                    credit -= 1;
                    frames += 1;
                }
                *sent.entry(key).or_default() += frames;
                Ok(frames > 0)
            })
            .unwrap();
        }
        // 2000 frames over five channels: 400 each, give or take a turn.
        for key in order {
            let got = sent.get(&key).copied().unwrap_or(0);
            assert!(
                (396..=404).contains(&got),
                "{key}: {got} of 2000 ({sent:?})"
            );
        }
    }

    #[test]
    fn a_slot_is_free_only_once_every_holder_let_go() {
        let slots = Arc::new(Slots::default());
        let held: Vec<_> = (0..MAX_CHANNELS).map(|_| slots.take().unwrap()).collect();
        assert!(slots.take().is_none(), "beyond the cap");
        let first = held[0].clone();
        drop(held);
        assert_eq!(slots.live(), 1, "one holder is left");
        assert!(slots.take().is_some());
        drop(first);
        assert_eq!(slots.live(), 0);
    }

    #[test]
    fn only_wssp_closes_and_failures_abort() {
        use crate::connect_client::wire::WireError;
        let error = WireError {
            code: "revoked".into(),
            message: String::new(),
        };
        for intent in [Intent::Revoked, Intent::Backpressure, Intent::Expired] {
            assert!(is_abort(&Outcome::Closed {
                intent,
                error: None
            }));
        }
        assert!(is_abort(&Outcome::Failed { error }));
        for natural in [
            Outcome::Code(0),
            Outcome::Code(1),
            Outcome::Signal(9),
            Outcome::Unknown,
            Outcome::Closed {
                intent: Intent::Client,
                error: None,
            },
        ] {
            assert!(!is_abort(&natural), "{natural:?}");
        }
    }
}
