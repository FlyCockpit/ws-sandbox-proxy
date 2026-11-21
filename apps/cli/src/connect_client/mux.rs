//! The per-connection channel state of the client wire, without IO.
//!
//! [`Mux`] checks every server frame against the channel it names (ready
//! before data, sequences from 0 without gaps, at most `windowFrames`
//! unacknowledged output frames, eof and exit watermarks) and turns it into
//! [`Event`]s in delivery order. The caller delivers each output frame (to a
//! terminal, a pipe or a socket) and reports it with [`Mux::delivered`]; the
//! mux then owes an `ack` ([`Mux::take_acks`]) and releases an `eof` or a
//! natural `exit` only once every frame up to its watermark was delivered.
//! An `exit` with an `intent` is a close decision and is released at once.
//!
//! stdin is credited the same way: at most `windowFrames` frames not yet
//! acknowledged by the server, sequences from 0, nothing before `ready`.
//! Several channels share one mux, so later commands (port forwards, the SSH
//! endpoint) reuse it unchanged.

use std::collections::BTreeMap;

use super::wire::{
    ClientControl, ExitFrames, Intent, Kind, Limits, Notice, OutputStream, PtySize, ServerControl,
    StdinStream, WireError,
};

/// How a channel ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The guest process exited with this code.
    Code(i32),
    /// The guest process died by this signal.
    Signal(u8),
    /// The guest process ended without a known status.
    Unknown,
    /// wssp closed the channel (`intent`), whatever the guest reported.
    Closed {
        intent: Intent,
        error: Option<WireError>,
    },
    /// The open failed or the channel failed without a close decision.
    Failed { error: WireError },
}

/// What the caller acts on, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Ready {
        channel: u32,
        pty: Option<PtySize>,
    },
    /// Deliver `body`, then report it with [`Mux::delivered`].
    Output {
        channel: u32,
        stream: OutputStream,
        seq: u64,
        body: Vec<u8>,
    },
    /// Every frame of `stream` was delivered; the stream is complete.
    Eof {
        channel: u32,
        stream: OutputStream,
    },
    /// The channel's last event.
    Exit {
        channel: u32,
        outcome: Outcome,
    },
    /// A non-fatal notice (`unsupported_signal`, `state_conflict`).
    Notice {
        channel: u32,
        code: Notice,
    },
}

/// A server frame that breaks the contract; the connection must end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation(pub &'static str);

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the server broke the connect protocol: {}", self.0)
    }
}

impl std::error::Error for Violation {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Opening,
    Open,
    Done,
}

#[derive(Debug)]
struct Chan {
    kind: Kind,
    state: State,
    /// Output frames received per stream (the next expected `seq`).
    received: [u64; 2],
    /// Output frames the caller delivered per stream.
    delivered: [u64; 2],
    /// Output frames acknowledged (queued as `ack`) per stream.
    acked: [u64; 2],
    /// A stream's `eof.frames`, held until delivered; `Some` after it came.
    eof: [Option<u64>; 2],
    /// Whether the eof of a stream was released to the caller.
    eof_released: [bool; 2],
    /// A natural exit held until its output is delivered.
    exit: Option<(ExitFrames, Outcome)>,
    stdin_sent: u64,
    /// stdin frames the server acknowledged (its highest `seq` + 1).
    stdin_acked: u64,
    /// Sizes of the stdin frames sent and not yet acknowledged, oldest first.
    stdin_unacked: std::collections::VecDeque<u64>,
    stdin_eof: bool,
}

impl Chan {
    fn unacked(&self) -> u64 {
        (self.received[0] - self.acked[0]) + (self.received[1] - self.acked[1])
    }
}

/// The channels of one connection.
#[derive(Debug)]
pub struct Mux {
    limits: Limits,
    last_channel: u32,
    channels: BTreeMap<u32, Chan>,
}

fn outcome_of(
    exit_code: Option<i32>,
    signal: Option<u8>,
    intent: Option<Intent>,
    error: Option<WireError>,
) -> Outcome {
    match (intent, error, exit_code, signal) {
        (Some(intent), error, _, _) => Outcome::Closed { intent, error },
        (None, Some(error), _, _) => Outcome::Failed { error },
        (None, None, Some(code), _) => Outcome::Code(code),
        (None, None, None, Some(signal)) => Outcome::Signal(signal),
        (None, None, None, None) => Outcome::Unknown,
    }
}

impl Mux {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            last_channel: 0,
            channels: BTreeMap::new(),
        }
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Largest data body this connection sends or accepts on `kind`.
    pub fn data_max(&self, kind: Kind) -> usize {
        usize::try_from(self.limits.data_max_bytes.of(kind))
            .unwrap_or(usize::MAX)
            .min(super::wire::DATA_MAX_BYTES)
    }

    fn window(&self, kind: Kind) -> u64 {
        self.limits.window_frames.of(kind)
    }

    /// Register a new channel and return its `open` frame. Ids increase
    /// from 1 and are never reused.
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        &mut self,
        kind: Kind,
        argv: Option<Vec<String>>,
        login: Option<bool>,
        cwd: Option<String>,
        env: Option<BTreeMap<String, String>>,
        pty: Option<super::wire::PtyParams>,
    ) -> anyhow::Result<(u32, ClientControl)> {
        let channel = self
            .last_channel
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("no channel ids left on this connection"))?;
        let frame = ClientControl::Open {
            channel,
            kind,
            argv,
            login,
            cwd,
            env,
            pty,
        };
        anyhow::ensure!(frame.is_valid(), "invalid channel open parameters");
        self.last_channel = channel;
        self.channels.insert(
            channel,
            Chan {
                kind,
                state: State::Opening,
                received: [0; 2],
                delivered: [0; 2],
                acked: [0; 2],
                eof: [None; 2],
                eof_released: [false; 2],
                exit: None,
                stdin_sent: 0,
                stdin_acked: 0,
                stdin_unacked: std::collections::VecDeque::new(),
                stdin_eof: false,
            },
        );
        Ok((channel, frame))
    }

    pub fn kind(&self, channel: u32) -> Option<Kind> {
        self.channels.get(&channel).map(|chan| chan.kind)
    }

    /// Whether the channel's exit was released (or it is unknown).
    pub fn is_done(&self, channel: u32) -> bool {
        self.channels
            .get(&channel)
            .is_none_or(|chan| chan.state == State::Done)
    }

    fn chan(&mut self, channel: u32) -> Result<Option<&mut Chan>, Violation> {
        match self.channels.get_mut(&channel) {
            None => Err(Violation("a frame for a channel this client never opened")),
            // Frames racing a released exit are ignored.
            Some(chan) if chan.state == State::Done => Ok(None),
            Some(chan) => Ok(Some(chan)),
        }
    }

    /// One server control frame (after `hello`).
    pub fn on_control(&mut self, frame: ServerControl) -> Result<Vec<Event>, Violation> {
        match frame {
            ServerControl::Hello { .. } => Err(Violation("a second hello")),
            ServerControl::End { .. } => Err(Violation("end is handled by the connection")),
            ServerControl::Ready { channel, pty } => {
                let Some(chan) = self.chan(channel)? else {
                    return Ok(Vec::new());
                };
                if chan.state != State::Opening {
                    return Err(Violation("a second ready"));
                }
                if (chan.kind == Kind::Pty) != pty.is_some() {
                    return Err(Violation("ready without the pty size, or with it on exec"));
                }
                chan.state = State::Open;
                Ok(vec![Event::Ready { channel, pty }])
            }
            ServerControl::Ack {
                channel,
                stream: StdinStream::Stdin,
                seq,
            } => {
                let Some(chan) = self.chan(channel)? else {
                    return Ok(Vec::new());
                };
                if seq >= chan.stdin_sent {
                    return Err(Violation("a stdin ack beyond the frames sent"));
                }
                while chan.stdin_acked <= seq {
                    chan.stdin_acked += 1;
                    chan.stdin_unacked.pop_front();
                }
                Ok(Vec::new())
            }
            ServerControl::Eof {
                channel,
                stream,
                frames,
            } => {
                let Some(chan) = self.chan(channel)? else {
                    return Ok(Vec::new());
                };
                let index = stream.index();
                if chan.state != State::Open || chan.eof[index].is_some() {
                    return Err(Violation("an eof before ready or twice"));
                }
                if frames < chan.received[index] {
                    return Err(Violation("an eof below the frames received"));
                }
                chan.eof[index] = Some(frames);
                Ok(self.release(channel))
            }
            ServerControl::Error { channel, code } => {
                let Some(_) = self.chan(channel)? else {
                    return Ok(Vec::new());
                };
                Ok(vec![Event::Notice { channel, code }])
            }
            ServerControl::Exit {
                channel,
                exit_code,
                signal,
                intent,
                error,
                frames,
            } => {
                let Some(chan) = self.chan(channel)? else {
                    return Ok(Vec::new());
                };
                if chan.exit.is_some() {
                    return Err(Violation("a second exit"));
                }
                let outcome = outcome_of(exit_code, signal, intent, error);
                if intent.is_some() || chan.state == State::Opening {
                    // A close decision (or a refused open): released at
                    // once; undelivered output may be dropped.
                    chan.state = State::Done;
                    return Ok(vec![Event::Exit { channel, outcome }]);
                }
                if frames.stdout < chan.received[0] || frames.stderr < chan.received[1] {
                    return Err(Violation("an exit below the frames received"));
                }
                for stream in [OutputStream::Stdout, OutputStream::Stderr] {
                    let index = stream.index();
                    if chan.eof[index].is_some_and(|eof| eof != frames.of(stream)) {
                        return Err(Violation("an exit that disagrees with its eof"));
                    }
                }
                chan.exit = Some((frames, outcome));
                Ok(self.release(channel))
            }
        }
    }

    /// One output data frame.
    pub fn on_data(
        &mut self,
        channel: u32,
        stream: OutputStream,
        seq: u64,
        body: &[u8],
    ) -> Result<Vec<Event>, Violation> {
        let max = |kind| self.data_max(kind);
        let window = |kind| self.window(kind);
        let (max_pty, max_exec) = (max(Kind::Pty), max(Kind::Exec));
        let (window_pty, window_exec) = (window(Kind::Pty), window(Kind::Exec));
        let Some(chan) = self.chan(channel)? else {
            return Ok(Vec::new());
        };
        let index = stream.index();
        let (max, window) = match chan.kind {
            Kind::Pty => (max_pty, window_pty),
            Kind::Exec => (max_exec, window_exec),
        };
        if chan.state != State::Open {
            return Err(Violation("output before ready"));
        }
        if chan.eof[index].is_some_and(|frames| seq >= frames)
            || chan
                .exit
                .as_ref()
                .is_some_and(|(frames, _)| seq >= frames.of(stream))
        {
            return Err(Violation("output after its eof or exit"));
        }
        if seq != chan.received[index] {
            return Err(Violation("an output sequence gap"));
        }
        if body.len() > max {
            return Err(Violation("an oversized output frame"));
        }
        if chan.unacked() >= window {
            return Err(Violation("output beyond the credit window"));
        }
        chan.received[index] += 1;
        Ok(vec![Event::Output {
            channel,
            stream,
            seq,
            body: body.to_vec(),
        }])
    }

    /// The caller delivered output frame `seq` of `stream` (frames are
    /// delivered in order). Returns the events this releases.
    pub fn delivered(&mut self, channel: u32, stream: OutputStream, seq: u64) -> Vec<Event> {
        let Some(chan) = self.channels.get_mut(&channel) else {
            return Vec::new();
        };
        let index = stream.index();
        if seq < chan.received[index] {
            chan.delivered[index] = chan.delivered[index].max(seq + 1);
        }
        if chan.state == State::Done {
            return Vec::new();
        }
        self.release(channel)
    }

    /// Release held eofs and a natural exit whose watermarks are delivered.
    fn release(&mut self, channel: u32) -> Vec<Event> {
        let mut events = Vec::new();
        let Some(chan) = self.channels.get_mut(&channel) else {
            return events;
        };
        for stream in [OutputStream::Stdout, OutputStream::Stderr] {
            let index = stream.index();
            if let Some(frames) = chan.eof[index]
                && !chan.eof_released[index]
                && chan.delivered[index] >= frames
            {
                chan.eof_released[index] = true;
                events.push(Event::Eof { channel, stream });
            }
        }
        if let Some((frames, _)) = &chan.exit
            && chan.delivered[0] >= frames.stdout
            && chan.delivered[1] >= frames.stderr
            && let Some((_, outcome)) = chan.exit.take()
        {
            chan.state = State::Done;
            events.push(Event::Exit { channel, outcome });
        }
        events
    }

    /// The `ack` frames owed for delivered output (cumulative, one per stream).
    pub fn take_acks(&mut self) -> Vec<ClientControl> {
        let mut acks = Vec::new();
        for (channel, chan) in &mut self.channels {
            for stream in [OutputStream::Stdout, OutputStream::Stderr] {
                let index = stream.index();
                if chan.delivered[index] > chan.acked[index] {
                    chan.acked[index] = chan.delivered[index];
                    // Acks after the exit are harmless and keep the server's
                    // credit exact; the server ignores them for an ended channel.
                    acks.push(ClientControl::Ack {
                        channel: *channel,
                        stream,
                        seq: chan.delivered[index] - 1,
                    });
                }
            }
        }
        acks
    }

    /// Whether one more stdin frame may be sent now: within the channel's
    /// window, and with room for a full frame in the connection's
    /// `unackedInputBytes` (every channel the client has not seen end).
    pub fn stdin_credit(&self, channel: u32) -> bool {
        self.channels.get(&channel).is_some_and(|chan| {
            chan.state == State::Open
                && !chan.stdin_eof
                && chan.stdin_sent - chan.stdin_acked < self.window(chan.kind)
                && self.unacked_input_bytes() + self.data_max(chan.kind) as u64
                    <= self.limits.unacked_input_bytes
        })
    }

    /// stdin bytes sent and not yet acknowledged, across live channels.
    fn unacked_input_bytes(&self) -> u64 {
        self.channels
            .values()
            .filter(|chan| chan.state != State::Done)
            .flat_map(|chan| chan.stdin_unacked.iter())
            .sum()
    }

    /// Take the `seq` of the next stdin frame (only with credit).
    pub fn stdin_frame(&mut self, channel: u32, len: usize) -> anyhow::Result<u64> {
        anyhow::ensure!(self.stdin_credit(channel), "no stdin credit");
        let max = self.kind(channel).map_or(0, |kind| self.data_max(kind));
        anyhow::ensure!(len > 0 && len <= max, "invalid stdin frame size");
        let chan = self
            .channels
            .get_mut(&channel)
            .ok_or_else(|| anyhow::anyhow!("unknown channel"))?;
        let seq = chan.stdin_sent;
        chan.stdin_sent += 1;
        chan.stdin_unacked.push_back(len as u64);
        Ok(seq)
    }

    /// The `eof` frame closing stdin, once (after `ready`).
    pub fn stdin_eof(&mut self, channel: u32) -> Option<ClientControl> {
        let chan = self.channels.get_mut(&channel)?;
        if chan.state != State::Open || chan.stdin_eof {
            return None;
        }
        chan.stdin_eof = true;
        Some(ClientControl::Eof {
            channel,
            stream: StdinStream::Stdin,
            frames: chan.stdin_sent,
        })
    }

    /// Whether the channel is open (after `ready`, before its exit).
    pub fn is_open(&self, channel: u32) -> bool {
        self.channels
            .get(&channel)
            .is_some_and(|chan| chan.state == State::Open)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connect_client::wire::{PerKind, PtyParams};

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
            unacked_input_bytes: 4 * 1024 * 1024,
            open_timeout_ms: 30_000,
        }
    }

    fn exec(mux: &mut Mux) -> u32 {
        let (channel, _) = mux
            .open(
                Kind::Exec,
                Some(vec!["true".into()]),
                None,
                None,
                None,
                None,
            )
            .unwrap();
        mux.on_control(ServerControl::Ready { channel, pty: None })
            .unwrap();
        channel
    }

    fn exit(channel: u32, code: Option<i32>, stdout: u64, stderr: u64) -> ServerControl {
        ServerControl::Exit {
            channel,
            exit_code: code,
            signal: None,
            intent: None,
            error: None,
            frames: ExitFrames { stdout, stderr },
        }
    }

    #[test]
    fn channel_ids_increase_from_one_and_opens_are_checked() {
        let mut mux = Mux::new(limits());
        let (a, _) = mux.open(Kind::Exec, None, None, None, None, None).unwrap();
        let pty = PtyParams {
            rows: 24,
            cols: 80,
            term: "xterm".into(),
        };
        let (b, frame) = mux
            .open(Kind::Pty, None, Some(true), None, None, Some(pty))
            .unwrap();
        assert_eq!((a, b), (1, 2));
        assert!(matches!(frame, ClientControl::Open { channel: 2, .. }));
        // A pty without its parameters is refused and burns no id.
        assert!(mux.open(Kind::Pty, None, None, None, None, None).is_err());
        assert_eq!(
            mux.open(Kind::Exec, None, None, None, None, None)
                .unwrap()
                .0,
            3
        );
    }

    #[test]
    fn natural_exit_waits_for_every_output_frame_to_be_delivered() {
        let mut mux = Mux::new(limits());
        let ch = exec(&mut mux);
        assert_eq!(
            mux.on_data(ch, OutputStream::Stdout, 0, b"a")
                .unwrap()
                .len(),
            1
        );
        mux.on_data(ch, OutputStream::Stderr, 0, b"e").unwrap();
        // The exit names 2 stdout frames: one is still in flight.
        assert!(mux.on_control(exit(ch, Some(3), 2, 1)).unwrap().is_empty());
        mux.on_data(ch, OutputStream::Stdout, 1, b"b").unwrap();
        assert!(mux.delivered(ch, OutputStream::Stdout, 0).is_empty());
        assert!(mux.delivered(ch, OutputStream::Stdout, 1).is_empty());
        assert_eq!(
            mux.delivered(ch, OutputStream::Stderr, 0),
            vec![Event::Exit {
                channel: ch,
                outcome: Outcome::Code(3)
            }]
        );
        assert!(mux.is_done(ch));
        // Acks still owed after the exit are cumulative, one per stream.
        assert_eq!(
            mux.take_acks(),
            vec![
                ClientControl::Ack {
                    channel: ch,
                    stream: OutputStream::Stdout,
                    seq: 1
                },
                ClientControl::Ack {
                    channel: ch,
                    stream: OutputStream::Stderr,
                    seq: 0
                },
            ]
        );
        assert!(mux.take_acks().is_empty());
        // Frames racing the exit are ignored.
        assert!(
            mux.on_data(ch, OutputStream::Stdout, 9, b"x")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn eof_is_released_only_after_its_frames() {
        let mut mux = Mux::new(limits());
        let ch = exec(&mut mux);
        mux.on_data(ch, OutputStream::Stdout, 0, b"a").unwrap();
        assert!(
            mux.on_control(ServerControl::Eof {
                channel: ch,
                stream: OutputStream::Stdout,
                frames: 1
            })
            .unwrap()
            .is_empty()
        );
        assert_eq!(
            mux.delivered(ch, OutputStream::Stdout, 0),
            vec![Event::Eof {
                channel: ch,
                stream: OutputStream::Stdout
            }]
        );
        // Output after the eof breaks the contract.
        assert!(mux.on_data(ch, OutputStream::Stdout, 1, b"b").is_err());
    }

    #[test]
    fn an_intent_exit_is_released_at_once() {
        let mut mux = Mux::new(limits());
        let ch = exec(&mut mux);
        mux.on_data(ch, OutputStream::Stdout, 0, b"a").unwrap();
        let events = mux
            .on_control(ServerControl::Exit {
                channel: ch,
                exit_code: None,
                signal: Some(9),
                intent: Some(Intent::Revoked),
                error: None,
                frames: ExitFrames {
                    stdout: 1,
                    stderr: 0,
                },
            })
            .unwrap();
        assert_eq!(
            events,
            vec![Event::Exit {
                channel: ch,
                outcome: Outcome::Closed {
                    intent: Intent::Revoked,
                    error: None
                }
            }]
        );
    }

    #[test]
    fn a_refused_open_exits_without_ready() {
        let mut mux = Mux::new(limits());
        let (ch, _) = mux.open(Kind::Exec, None, None, None, None, None).unwrap();
        let error = WireError {
            code: "host_capacity".into(),
            message: "full".into(),
        };
        let events = mux
            .on_control(ServerControl::Exit {
                channel: ch,
                exit_code: None,
                signal: None,
                intent: None,
                error: Some(error.clone()),
                frames: ExitFrames {
                    stdout: 0,
                    stderr: 0,
                },
            })
            .unwrap();
        assert_eq!(
            events,
            vec![Event::Exit {
                channel: ch,
                outcome: Outcome::Failed { error }
            }]
        );
    }

    #[test]
    fn output_is_checked_against_order_window_and_size() {
        let mut mux = Mux::new(limits());
        let (ch, _) = mux.open(Kind::Exec, None, None, None, None, None).unwrap();
        assert!(
            mux.on_data(ch, OutputStream::Stdout, 0, b"a").is_err(),
            "before ready"
        );
        let mut mux = Mux::new(limits());
        let ch = exec(&mut mux);
        assert!(
            mux.on_data(ch, OutputStream::Stdout, 1, b"a").is_err(),
            "gap"
        );
        assert!(
            mux.on_data(99, OutputStream::Stdout, 0, b"a").is_err(),
            "unopened"
        );
        assert!(
            mux.on_data(ch, OutputStream::Stdout, 0, &vec![0; 32769])
                .is_err()
        );
        // 32 frames across both streams fill the exec window.
        for seq in 0..16 {
            mux.on_data(ch, OutputStream::Stdout, seq, b"o").unwrap();
            mux.on_data(ch, OutputStream::Stderr, seq, b"e").unwrap();
        }
        assert!(mux.on_data(ch, OutputStream::Stdout, 16, b"o").is_err());
        let mut mux = Mux::new(limits());
        let ch = exec(&mut mux);
        for seq in 0..32 {
            mux.on_data(ch, OutputStream::Stdout, seq, b"o").unwrap();
        }
        // Delivery alone returns no credit; the queued ack does.
        mux.delivered(ch, OutputStream::Stdout, 0);
        assert!(mux.on_data(ch, OutputStream::Stdout, 32, b"o").is_err());
        let mut mux = Mux::new(limits());
        let ch = exec(&mut mux);
        for seq in 0..32 {
            mux.on_data(ch, OutputStream::Stdout, seq, b"o").unwrap();
        }
        mux.delivered(ch, OutputStream::Stdout, 0);
        assert_eq!(mux.take_acks().len(), 1);
        mux.on_data(ch, OutputStream::Stdout, 32, b"o").unwrap();
        // pty frames are bounded at 16 KiB.
        let mut mux = Mux::new(limits());
        let pty = PtyParams {
            rows: 24,
            cols: 80,
            term: "xterm".into(),
        };
        let (ch, _) = mux
            .open(Kind::Pty, None, Some(true), None, None, Some(pty))
            .unwrap();
        assert!(
            mux.on_control(ServerControl::Ready {
                channel: ch,
                pty: None
            })
            .is_err(),
            "pty ready carries the size"
        );
        mux.on_control(ServerControl::Ready {
            channel: ch,
            pty: Some(PtySize { rows: 24, cols: 80 }),
        })
        .unwrap();
        assert!(
            mux.on_data(ch, OutputStream::Stdout, 0, &vec![0; 16385])
                .is_err()
        );
    }

    #[test]
    fn stdin_credit_respects_the_connection_byte_budget() {
        let mut mux = Mux::new(limits());
        let full = 32 * 1024;
        let mut open = Vec::new();
        for _ in 0..5 {
            let (ch, _) = mux.open(Kind::Exec, None, None, None, None, None).unwrap();
            mux.on_control(ServerControl::Ready {
                channel: ch,
                pty: None,
            })
            .unwrap();
            open.push(ch);
        }
        // 4 MiB of full frames across channels: 128 frames, then no credit.
        let mut sent = 0;
        'fill: for &ch in &open {
            while mux.stdin_credit(ch) {
                mux.stdin_frame(ch, full).unwrap();
                sent += 1;
                if sent > 200 {
                    break 'fill;
                }
            }
        }
        assert_eq!(sent, 128);
        assert!(open.iter().all(|&ch| !mux.stdin_credit(ch)));
        // A server ack on one channel frees room on every channel.
        mux.on_control(ServerControl::Ack {
            channel: open[0],
            stream: StdinStream::Stdin,
            seq: 0,
        })
        .unwrap();
        assert!(mux.stdin_credit(open[4]));
    }

    #[test]
    fn stdin_credit_follows_the_window_and_server_acks() {
        let mut mux = Mux::new(limits());
        let (ch, _) = mux.open(Kind::Exec, None, None, None, None, None).unwrap();
        assert!(!mux.stdin_credit(ch), "nothing before ready");
        assert!(mux.stdin_eof(ch).is_none());
        mux.on_control(ServerControl::Ready {
            channel: ch,
            pty: None,
        })
        .unwrap();
        for expected in 0..32 {
            assert_eq!(mux.stdin_frame(ch, 1).unwrap(), expected);
        }
        assert!(!mux.stdin_credit(ch));
        assert!(
            mux.on_control(ServerControl::Ack {
                channel: ch,
                stream: StdinStream::Stdin,
                seq: 32
            })
            .is_err(),
            "an ack beyond the frames sent"
        );
        mux.on_control(ServerControl::Ack {
            channel: ch,
            stream: StdinStream::Stdin,
            seq: 1,
        })
        .unwrap();
        assert!(mux.stdin_credit(ch));
        assert_eq!(mux.stdin_frame(ch, 1).unwrap(), 32);
        assert!(mux.stdin_frame(ch, 0).is_err());
        assert!(mux.stdin_frame(ch, 32769).is_err());
        assert_eq!(
            mux.stdin_eof(ch),
            Some(ClientControl::Eof {
                channel: ch,
                stream: StdinStream::Stdin,
                frames: 33
            })
        );
        assert!(mux.stdin_eof(ch).is_none(), "once");
        assert!(!mux.stdin_credit(ch), "nothing after eof");
    }

    #[test]
    fn exit_outcomes() {
        assert_eq!(outcome_of(Some(0), None, None, None), Outcome::Code(0));
        assert_eq!(outcome_of(None, Some(15), None, None), Outcome::Signal(15));
        assert_eq!(outcome_of(None, None, None, None), Outcome::Unknown);
        assert!(matches!(
            outcome_of(None, Some(9), Some(Intent::SandboxStopped), None),
            Outcome::Closed {
                intent: Intent::SandboxStopped,
                ..
            }
        ));
    }
}
