//! Model tests of the pure tick ([`step`]): no custodian threads, no
//! runtime, no sleeps. A scripted custodian answers every order with
//! seeded delays, a scripted guest emits PROMPT/READY/output/EXIT/EOF, and
//! every snapshot is built by the test (verdicts, events, clock), so a
//! deadline or revocation can cross between any two ticks and land in the
//! same tick as any event. Each tick's frames are checked against the
//! channel contract's trace invariants; a failure names its seed.
use super::*;
use sandbox_protocol::parse_channel_frame;
use sandbox_runtime::{WriteRefused, channel_nonce, guest_frame_bytes};

const SEEDS: u64 = 3000;

/// What the seeds exercised (so a script change cannot make the test vacuous).
#[derive(Default, Debug)]
struct Coverage {
    ready: u64,
    data: u64,
    kill_verdicts_after_ready: u64,
    /// Channels whose first close order was `Finish` (a natural end).
    natural_ends: u64,
    unsettled_exits: u64,
}

thread_local! {
    static COVERAGE: std::cell::RefCell<Coverage> = std::cell::RefCell::default();
}

fn covered(f: impl FnOnce(&mut Coverage)) {
    COVERAGE.with(|c| f(&mut c.borrow_mut()));
}
const TICKS: usize = 160;
const SETTLE_TICKS: usize = 400;

struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn one_in(&mut self, n: u64) -> bool {
        self.below(n) == 0
    }
}

/// The guest's side of one channel's IO.
#[derive(Default)]
struct GuestPipes {
    out: [VecDeque<Vec<u8>>; 2],
    /// The stream ends once its queued chunks are read.
    eof: [bool; 2],
    /// Everything handed to the guest's stdin (preamble first).
    written: Vec<Vec<u8>>,
    stdin_closed: bool,
    input_ready: bool,
    /// The IO object was dropped (the cut-off).
    dropped: bool,
}

struct ScriptIo(Arc<Mutex<GuestPipes>>);

impl ScriptIo {
    fn pipes(&self) -> std::sync::MutexGuard<'_, GuestPipes> {
        self.0.lock().unwrap()
    }
}

impl ChannelIo for ScriptIo {
    fn try_read(&mut self, stream: ChannelOutput) -> ChannelRead {
        let mut pipes = self.pipes();
        let index = stream as usize;
        match pipes.out[index].pop_front() {
            Some(bytes) => ChannelRead::Data(bytes),
            None if pipes.eof[index] => ChannelRead::Eof,
            None => ChannelRead::WouldBlock,
        }
    }
    fn try_write(&mut self, bytes: Vec<u8>) -> Result<(), WriteRefused> {
        let mut pipes = self.pipes();
        if pipes.stdin_closed {
            return Err(WriteRefused {
                bytes,
                closed: true,
            });
        }
        pipes.written.push(bytes);
        Ok(())
    }
    fn close_stdin(&mut self) -> bool {
        self.pipes().stdin_closed = true;
        true
    }
    fn resize(&mut self, _size: PtySize) -> Result<(), sandbox_runtime::RuntimeError> {
        Ok(())
    }
    fn input_ready(&mut self) -> bool {
        self.pipes().input_ready
    }
}

impl Drop for ScriptIo {
    fn drop(&mut self) {
        self.pipes().dropped = true;
    }
}

/// The scripted custodian of one channel (mirrors [`Custodian`]'s answers:
/// one `Ended` per close order, updates as the end settles, nothing after
/// `Done`).
#[derive(Default)]
struct ScriptCustodian {
    /// Events not yet delivered, in order (a tick delivers a prefix).
    queue: VecDeque<Evt>,
    spawned: bool,
    open_failed: bool,
    end: Option<ChannelEnd>,
    released: bool,
    /// Answers (`Ended { answers: true }`) delivered to the owner in a
    /// snapshot (not merely queued).
    delivered: u32,
    /// Orders received.
    orders: u32,
}

/// One modelled channel: its state, the custodian's order lane and the
/// test's view of guest and wire.
struct Model {
    key: (String, String),
    kind: ChannelKind,
    orders: mpsc::Receiver<Order>,
    custodian: ScriptCustodian,
    pipes: Arc<Mutex<GuestPipes>>,
    nonce: String,
    secret: String,
    /// The guest saw its preamble and may report READY.
    preamble_seen: bool,
    guest_ready: bool,
    guest_exited: bool,
    // Wire trace.
    ready_sent: bool,
    sent: [u64; 2],
    acked: [u64; 2],
    eof_frames: [Option<u64>; 2],
    exits: Vec<(bool, ChannelExitFrames)>,
    stdin_next: u64,
    /// The tick (index) after which nothing may cross any more.
    decided_at: Option<usize>,
    removed: bool,
}

fn fence(channel: &str) -> ChannelFence {
    ChannelFence {
        host_id: "host-1".into(),
        epoch: 1,
        connection_id: "conn-1".into(),
        channel_id: channel.into(),
        target: ChannelTarget::Sandbox {
            sandbox_id: "sbx-1".into(),
            generation: 1,
        },
    }
}

fn model_chan(
    id: &str,
    kind: ChannelKind,
    creator: &str,
    now: Instant,
    lifetime: Duration,
) -> (Chan, Model) {
    let fence = fence(id);
    let nonce = channel_nonce().unwrap();
    let secret = channel_nonce().unwrap();
    let (orders_tx, orders_rx) = mpsc::sync_channel(4);
    let (signals_tx, _signals_rx) = mpsc::sync_channel(SIGNALS_IN_FLIGHT);
    let deadline = now + lifetime;
    let chan = Chan {
        filter: FrameFilter::new(&nonce, &secret),
        fence: fence.clone(),
        kind,
        phase: Phase::Opening,
        io: None,
        orders: orders_tx,
        signals: signals_tx,
        preamble: Some(b"PREAMBLE".to_vec()),
        size: (kind == ChannelKind::Pty).then(|| PtySize::new(24, 80).unwrap()),
        prompted: false,
        refused: false,
        birth: None,
        exit: None,
        out: [OutStream::default(), OutStream::default()],
        eof: [false; 2],
        eof_sent: [false; 2],
        idle_since: [None; 2],
        next_stream: 0,
        pending_in: VecDeque::new(),
        input_next: 0,
        input_acked: 0,
        acks_due: Vec::new(),
        stdin_eof: None,
        stdin_closed: false,
        violations: 0,
        credential_leases: BTreeSet::new(),
        creator: creator.into(),
        deadline,
        setup_deadline: (now + SETUP_DEADLINE).min(deadline),
        intent: None,
        error: None,
        decided: false,
        kill_ordered: false,
        outstanding: 0,
        end: None,
        exit_sent: false,
        exit_settled: false,
        gone: false,
    };
    let model = Model {
        key: key(&fence),
        kind,
        orders: orders_rx,
        custodian: ScriptCustodian::default(),
        pipes: Arc::default(),
        nonce,
        secret,
        preamble_seen: false,
        guest_ready: false,
        guest_exited: false,
        ready_sent: false,
        sent: [0; 2],
        acked: [0; 2],
        eof_frames: [None; 2],
        exits: Vec::new(),
        stdin_next: 0,
        decided_at: None,
        removed: false,
    };
    (chan, model)
}

fn random_end(rng: &mut XorShift, kill: bool) -> ChannelEnd {
    ChannelEnd {
        reaped: !rng.one_in(4),
        scope: if !kill {
            ChannelScope::Released
        } else if rng.one_in(4) {
            ChannelScope::Uncertain
        } else {
            ChannelScope::Killed
        },
    }
}

impl Model {
    /// The custodian takes its orders and settles a little (seeded).
    fn custodian_turn(&mut self, rng: &mut XorShift) {
        let c = &mut self.custodian;
        if c.released {
            return;
        }
        while let Ok(order) = self.orders.try_recv() {
            match order {
                Order::Close(how) => {
                    c.orders += 1;
                    if c.orders == 1 && how == ChannelClose::Finish {
                        covered(|c| c.natural_ends += 1);
                    }
                    let end = match c.end {
                        None if !c.spawned => NOTHING_SPAWNED,
                        None => random_end(rng, how.is_kill()),
                        Some(mut end) => {
                            if how.is_kill() && end.scope == ChannelScope::Released && c.spawned {
                                end.scope = if rng.one_in(4) {
                                    ChannelScope::Uncertain
                                } else {
                                    ChannelScope::Killed
                                };
                            }
                            end
                        }
                    };
                    c.end = Some(end);
                    c.queue.push_back(Evt::Ended { end, answers: true });
                }
                Order::Done => {
                    c.released = true;
                    return;
                }
            }
        }
        // Not yet spawned and not closed: spawn (or fail) at some point.
        if !c.spawned && !c.open_failed && c.end.is_none() && rng.one_in(3) {
            if rng.one_in(12) {
                c.open_failed = true;
                c.queue
                    .push_back(Evt::OpenFailed(SandboxErrorCode::GuestUnavailable));
                c.end = Some(NOTHING_SPAWNED);
                c.queue.push_back(Evt::Ended {
                    end: NOTHING_SPAWNED,
                    answers: false,
                });
            } else {
                c.spawned = true;
                c.queue
                    .push_back(Evt::Spawned(Box::new(ScriptIo(self.pipes.clone()))));
            }
        }
        // Reconcile: an unreaped client is reaped, an uncertain kill proven.
        if let Some(mut end) = c.end
            && !end.settled()
            && rng.one_in(3)
        {
            end.reaped = true;
            if end.scope == ChannelScope::Uncertain && rng.one_in(2) {
                end.scope = ChannelScope::Killed;
            }
            if Some(end) != c.end {
                c.end = Some(end);
                c.queue.push_back(Evt::Ended {
                    end,
                    answers: false,
                });
            }
        }
    }

    /// The scripted guest (only while its IO exists).
    fn guest_turn(&mut self, rng: &mut XorShift, live: bool) {
        let mut pipes = self.pipes.lock().unwrap();
        if pipes.dropped || !self.custodian.spawned || !live {
            return;
        }
        let frame_stream = match self.kind {
            ChannelKind::Pty => 0,
            ChannelKind::Exec => 1,
        };
        if !self.preamble_seen && pipes.written.first().is_some_and(|p| p == b"PREAMBLE") {
            self.preamble_seen = true;
        }
        if pipes.written.is_empty() && pipes.out[frame_stream].is_empty() && rng.one_in(2) {
            pipes.out[frame_stream].push_back(guest_frame_bytes(&self.nonce, "PROMPT"));
        }
        // A pty's host tty turns raw at some point; exec input is ready.
        if self.kind == ChannelKind::Exec || rng.one_in(2) {
            pipes.input_ready = true;
        }
        if self.preamble_seen && !self.guest_ready && rng.one_in(2) {
            self.guest_ready = true;
            let mut chunk = guest_frame_bytes(&self.secret, "READY 42 0b6a-ff 12345 1000");
            if rng.one_in(2) {
                chunk.extend_from_slice(b"hello");
            }
            pipes.out[frame_stream].push_back(chunk);
        }
        if !self.guest_ready || pipes.eof[0] && pipes.eof[1] {
            return;
        }
        for stream in 0..2 {
            if (self.kind == ChannelKind::Pty && stream == 1) || pipes.eof[stream] {
                continue;
            }
            for _ in 0..rng.below(4) {
                pipes.out[stream].push_back(vec![b'x'; 1 + rng.below(64) as usize]);
            }
        }
        if !self.guest_exited && rng.one_in(25) {
            self.guest_exited = true;
            let status = if rng.one_in(2) {
                "EXIT code 0"
            } else {
                "EXIT signal 15"
            };
            pipes.out[frame_stream].push_back(guest_frame_bytes(&self.secret, status));
        }
        if self.guest_exited && rng.one_in(3) {
            let stream = rng.below(2) as usize;
            pipes.eof[stream] = true;
            if self.kind == ChannelKind::Pty {
                pipes.eof = [true, true];
            }
        }
    }

    fn written(&self) -> usize {
        self.pipes.lock().unwrap().written.len()
    }
}

/// The frames of one tick, by channel id.
fn by_channel(out: &[Outgoing]) -> HashMap<String, Vec<&Outgoing>> {
    let mut map: HashMap<String, Vec<&Outgoing>> = HashMap::new();
    for frame in out {
        let channel = match frame {
            Outgoing::Binary(bytes) => {
                parse_channel_frame(bytes)
                    .unwrap()
                    .unwrap()
                    .0
                    .fence
                    .channel_id
            }
            Outgoing::Text(message) => match message.as_ref() {
                DaemonControlMessage::ChannelReady { fence, .. }
                | DaemonControlMessage::ChannelEof { fence, .. }
                | DaemonControlMessage::ChannelExit { fence, .. }
                | DaemonControlMessage::ChannelAck { fence, .. }
                | DaemonControlMessage::ChannelError { fence, .. } => fence.channel_id.clone(),
                other => panic!("not a channel frame: {other:?}"),
            },
        };
        map.entry(channel).or_default().push(frame);
    }
    map
}

/// One tick's frames of one channel against its trace.
#[allow(clippy::too_many_arguments)]
fn check_tick(
    seed: u64,
    tick: usize,
    m: &mut Model,
    frames: &[&Outgoing],
    kill_verdict: bool,
    now: Instant,
    setup_deadline: Instant,
    written_before: usize,
    written_after: usize,
) {
    let ctx = || format!("seed {seed} tick {tick} channel {}", m.key.1);
    let crossed = m.decided_at.is_some_and(|at| at < tick);
    if kill_verdict || crossed {
        assert_eq!(
            written_before,
            written_after,
            "{}: stdin or preamble handed over under a kill verdict or after the decision",
            ctx()
        );
    }
    for frame in frames {
        match frame {
            Outgoing::Binary(bytes) => {
                let (meta, _) = parse_channel_frame(bytes).unwrap().unwrap();
                let index = match meta.stream {
                    ChannelStream::Stdout => 0,
                    ChannelStream::Stderr => 1,
                    ChannelStream::Stdin => panic!("{}: stdin data from the host", ctx()),
                };
                assert!(!kill_verdict, "{}: data under a kill verdict", ctx());
                assert!(!crossed, "{}: data after the decision", ctx());
                assert!(m.ready_sent, "{}: data before READY", ctx());
                assert!(m.exits.is_empty(), "{}: data after the exit", ctx());
                assert!(
                    m.eof_frames[index].is_none(),
                    "{}: data after its eof",
                    ctx()
                );
                assert_eq!(meta.seq, m.sent[index], "{}: seq gap", ctx());
                m.sent[index] += 1;
                covered(|c| c.data += 1);
                let window = window(m.kind);
                assert!(
                    m.sent[0] + m.sent[1] - m.acked[0] - m.acked[1] <= window,
                    "{}: window exceeded",
                    ctx()
                );
            }
            Outgoing::Text(message) => match message.as_ref() {
                DaemonControlMessage::ChannelReady { .. } => {
                    assert!(!m.ready_sent, "{}: READY twice", ctx());
                    assert!(!kill_verdict, "{}: READY under a kill verdict", ctx());
                    assert!(!crossed, "{}: READY after the decision", ctx());
                    assert!(now < setup_deadline, "{}: READY past setup", ctx());
                    assert!(m.preamble_seen, "{}: READY without preamble", ctx());
                    m.ready_sent = true;
                    covered(|c| c.ready += 1);
                }
                DaemonControlMessage::ChannelEof { stream, frames, .. } => {
                    let index = match stream {
                        ChannelStream::Stdout => 0,
                        ChannelStream::Stderr => 1,
                        ChannelStream::Stdin => panic!("{}: stdin eof from the host", ctx()),
                    };
                    assert_eq!(m.kind, ChannelKind::Exec, "{}: pty eof", ctx());
                    assert!(m.eof_frames[index].is_none(), "{}: eof twice", ctx());
                    assert!(m.exits.is_empty(), "{}: eof after the exit", ctx());
                    assert_eq!(*frames, m.sent[index], "{}: eof frame count", ctx());
                    m.eof_frames[index] = Some(*frames);
                }
                DaemonControlMessage::ChannelExit {
                    reaped,
                    frames,
                    exit_code,
                    signal,
                    error,
                    ..
                } => {
                    assert_eq!(frames.stdout, m.sent[0], "{}: exit stdout count", ctx());
                    assert_eq!(frames.stderr, m.sent[1], "{}: exit stderr count", ctx());
                    if m.ready_sent && m.kind == ChannelKind::Exec && m.exits.is_empty() {
                        assert!(
                            m.eof_frames.iter().all(Option::is_some),
                            "{}: exit before both eofs",
                            ctx()
                        );
                    }
                    match m.exits.as_slice() {
                        [] => {}
                        [(false, _)] => {
                            assert!(*reaped, "{}: a second unsettled exit", ctx());
                            assert!(
                                exit_code.is_none() && signal.is_none() && error.is_none(),
                                "{}: the settled follow-up repeats the status",
                                ctx()
                            );
                        }
                        _ => panic!("{}: an exit after the settled exit", ctx()),
                    }
                    if !*reaped {
                        covered(|c| c.unsettled_exits += 1);
                    }
                    m.exits.push((*reaped, *frames));
                }
                DaemonControlMessage::ChannelAck { .. }
                | DaemonControlMessage::ChannelError { .. } => {}
                other => panic!("{}: unexpected {other:?}", ctx()),
            },
        }
    }
}

fn run_seed(seed: u64) {
    let mut rng = XorShift(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    let mut now = Instant::now();
    let mut channels: HashMap<(String, String), Chan> = HashMap::new();
    let mut models: Vec<Model> = Vec::new();
    let mut rr = 0usize;
    let mut revoked: BTreeSet<(String, String)> = BTreeSet::new();
    let count = 1 + rng.below(4);
    for n in 0..count {
        let kind = if rng.one_in(2) {
            ChannelKind::Pty
        } else {
            ChannelKind::Exec
        };
        let lifetime = Duration::from_secs(20 + rng.below(400));
        let creator = if rng.one_in(2) { "owner-a" } else { "owner-b" };
        let (chan, model) = model_chan(&format!("ch-{n}"), kind, creator, now, lifetime);
        channels.insert(model.key.clone(), chan);
        models.push(model);
    }
    for tick in 0..TICKS + SETTLE_TICKS {
        let stimulate = tick < TICKS;
        // Between two ticks: the clock moves (sometimes across a deadline),
        // authority may be lost, the client may close, ack, or send stdin.
        now += match rng.below(10) {
            0 => Duration::from_secs(1 + rng.below(45)),
            1..=3 => Duration::from_millis(rng.below(400)),
            _ => Duration::from_millis(rng.below(20)),
        };
        for m in models.iter_mut().filter(|m| !m.removed) {
            let chan = channels.get_mut(&m.key).unwrap();
            if stimulate && rng.one_in(60) {
                revoked.insert(m.key.clone());
            }
            if stimulate && rng.one_in(50) {
                chan.decide(Some(ChannelCloseIntent::Client), None, false);
            }
            // The client acks a random prefix of what it received.
            for index in 0..2 {
                if m.acked[index] < m.sent[index] && (rng.one_in(2) || !stimulate) {
                    let upto = m.acked[index] + 1 + rng.below(m.sent[index] - m.acked[index]);
                    let out = &mut chan.out[index];
                    for _ in out.acked..upto {
                        out.unacked_since.pop_front();
                    }
                    out.acked = upto;
                    m.acked[index] = upto;
                }
            }
            if stimulate
                && chan.phase == Phase::Running
                && chan.input_next - chan.input_acked < window(chan.kind)
                && rng.one_in(3)
            {
                chan.pending_in
                    .push_back((m.stdin_next, format!("in-{}", m.stdin_next).into_bytes()));
                chan.input_next += 1;
                m.stdin_next += 1;
            }
            m.custodian_turn(&mut rng);
            m.guest_turn(&mut rng, stimulate);
        }
        // The snapshot: verdicts, a random prefix of each custodian's
        // events (so events land in the same tick as any crossing), clock.
        let mut seen = HashMap::new();
        let mut verdicts = HashMap::new();
        let mut written_before = HashMap::new();
        for m in models.iter_mut().filter(|m| !m.removed) {
            let refusal = revoked
                .contains(&m.key)
                .then_some(ChannelCloseIntent::Revoked);
            let take = if stimulate {
                rng.below(m.custodian.queue.len() as u64 + 1) as usize
            } else {
                m.custodian.queue.len()
            };
            let events: Vec<Evt> = m.custodian.queue.drain(..take).collect();
            m.custodian.delivered += events
                .iter()
                .filter(|e| matches!(e, Evt::Ended { answers: true, .. }))
                .count() as u32;
            let chan = &channels[&m.key];
            verdicts.insert(
                m.key.clone(),
                (
                    refusal.is_some() || now >= chan.deadline,
                    chan.setup_deadline,
                ),
            );
            written_before.insert(m.key.clone(), m.written());
            seen.insert(
                m.key.clone(),
                Seen {
                    refusal,
                    events,
                    custodian_gone: false,
                },
            );
        }
        let mut outbox = Vec::new();
        step(&mut channels, &mut rr, Snapshot { now, seen }, &mut outbox).unwrap();
        let data_frames = outbox
            .iter()
            .filter(|o| matches!(o, Outgoing::Binary(_)))
            .count();
        assert!(
            data_frames <= TICK_DATA_FRAMES,
            "seed {seed} tick {tick}: {data_frames} data frames in one tick"
        );
        let frames = by_channel(&outbox);
        for m in models.iter_mut().filter(|m| !m.removed) {
            let (kill_verdict, setup_deadline) = verdicts[&m.key];
            let after = m.written();
            check_tick(
                seed,
                tick,
                m,
                frames.get(&m.key.1).map(Vec::as_slice).unwrap_or(&[]),
                kill_verdict,
                now,
                setup_deadline,
                written_before[&m.key],
                after,
            );
            let chan = &channels[&m.key];
            if chan.decided || matches!(chan.phase, Phase::Closing | Phase::Unsettled) {
                m.decided_at.get_or_insert(tick);
                assert!(
                    chan.io.is_none(),
                    "seed {seed} tick {tick}: IO kept after the decision"
                );
            }
            if kill_verdict && m.ready_sent && m.decided_at.is_none_or(|at| at == tick) {
                covered(|c| c.kill_verdicts_after_ready += 1);
            }
            if kill_verdict && !chan.gone {
                assert!(
                    chan.kill_ordered || chan.phase == Phase::Opening && !chan.decided,
                    "seed {seed} tick {tick} {}: a kill verdict without a kill order \
                     (phase {:?})",
                    m.key.1,
                    chan.phase
                );
            }
            if chan.gone {
                assert!(
                    m.exits.last().is_some_and(|(reaped, _)| *reaped),
                    "seed {seed} tick {tick} {}: removed without a settled exit",
                    m.key.1
                );
                assert_eq!(
                    m.custodian.orders, m.custodian.delivered,
                    "seed {seed}: removed before every close order's answer was delivered"
                );
                m.removed = true;
            }
        }
        channels.retain(|_, chan| !chan.gone);
        if models.iter().all(|m| m.removed) {
            break;
        }
    }
    for m in &models {
        assert!(
            m.removed,
            "seed {seed}: channel {} never settled (custodian orders {}, exits {:?})",
            m.key.1, m.custodian.orders, m.exits
        );
        // `Done` was the last order: the lane holds it and nothing else.
        if !m.custodian.released {
            assert!(
                matches!(m.orders.try_recv(), Ok(Order::Done)),
                "seed {seed}: channel {} removed without Done",
                m.key.1
            );
            assert!(
                m.orders.try_recv().is_err(),
                "seed {seed}: an order after Done"
            );
        }
    }
}

/// 1a.1: the pure step over thousands of seeded interleavings.
#[test]
fn the_pure_step_keeps_the_trace_invariants_over_seeded_interleavings() {
    for seed in 1..=SEEDS {
        run_seed(seed);
    }
    let coverage = COVERAGE.with(|c| std::mem::take(&mut *c.borrow_mut()));
    eprintln!("model coverage: {coverage:?}");
    assert!(coverage.ready > SEEDS, "{coverage:?}");
    assert!(coverage.data > SEEDS * 10, "{coverage:?}");
    assert!(
        coverage.kill_verdicts_after_ready > SEEDS / 4,
        "{coverage:?}"
    );
    assert!(coverage.natural_ends > SEEDS / 10, "{coverage:?}");
    assert!(coverage.unsettled_exits > SEEDS / 10, "{coverage:?}");
}
