//! Reader-owned relay window. ACKs are cumulative identities, never additive credits.
use sandbox_protocol::{StreamBinaryMetadata, StreamChunkFlags, StreamKind, encode_binary_frame};
use sandbox_runtime::{CommandOutput, CommandStream};
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use tungstenite::Bytes;
pub const WINDOW: usize = sandbox_protocol::SANDBOX_STREAM_WINDOW_CHUNKS;
/// A finished command's completion seals its output on the server, so it
/// waits while retained output is still draining. It gives up only after this
/// long without ACK progress (several capped resends: see [`ResendTimer`]).
pub const DRAIN_IDLE: Duration = Duration::from_secs(5);
/// Absolute bound on holding a completion for its output. Retained output is
/// at most `OUTPUT_HEAD + OUTPUT_TAIL` (1 MiB): this admits ~35 KiB/s.
pub const DRAIN_MAX: Duration = Duration::from_secs(30);

/// Window retransmission timer. A whole-window resend after silence starts at
/// 250 ms and doubles on every further resend without ACK progress, capped at
/// 2 s, so a slow (not lossy) server is not fed duplicate chunks that each
/// cost it a full transaction. Any ACK progress resets it.
#[derive(Debug, Default, Clone, Copy)]
pub struct ResendTimer {
    resends: u32,
}
impl ResendTimer {
    pub const BASE: Duration = Duration::from_millis(250);
    pub const CAP: Duration = Duration::from_secs(2);
    pub fn interval(&self) -> Duration {
        Self::BASE
            .saturating_mul(1u32 << self.resends.min(8))
            .min(Self::CAP)
    }
    /// Whether a resend is due `now` for frames last sent at `last`.
    pub fn due(&self, last: Instant, now: Instant) -> bool {
        now.duration_since(last) >= self.interval()
    }
    pub fn resent(&mut self) {
        self.resends = self.resends.saturating_add(1);
    }
    pub fn progressed(&mut self) {
        self.resends = 0;
    }
}
/// One windowed binary frame, encoded once when it enters the window: a resend
/// clones the shared wire buffer instead of copying and re-encoding the body.
#[derive(Clone)]
pub struct Frame {
    pub metadata: StreamBinaryMetadata,
    body_len: usize,
    encoded: Bytes,
}
impl Frame {
    pub fn encode(metadata: StreamBinaryMetadata, body: &[u8]) -> anyhow::Result<Self> {
        let encoded = Bytes::from(encode_binary_frame(&metadata, body)?);
        Ok(Self {
            metadata,
            body_len: body.len(),
            encoded,
        })
    }
    /// The exact wire bytes (`Message::Binary(frame.encoded())`).
    pub fn encoded(&self) -> Bytes {
        self.encoded.clone()
    }
    pub fn body_len(&self) -> usize {
        self.body_len
    }
    /// The body is the tail of the encoded frame.
    pub fn body(&self) -> &[u8] {
        let start = self.encoded.len().saturating_sub(self.body_len);
        self.encoded.get(start..).unwrap_or_default()
    }
}
pub struct OutputWindow {
    pub output: CommandOutput,
    frames: VecDeque<Frame>,
    sequence: u64,
    offset: u64,
    last_send: Option<Instant>,
    resend: ResendTimer,
    /// Last ACK that retired frames.
    progressed: Option<Instant>,
    /// Largest body of a new frame: the connection's negotiated output chunk
    /// size (D3b). Frames already in the window keep their size.
    chunk_bytes: usize,
}
impl OutputWindow {
    pub fn new(output: CommandOutput) -> Self {
        Self {
            output,
            frames: VecDeque::new(),
            sequence: 0,
            offset: 0,
            last_send: None,
            resend: ResendTimer::default(),
            progressed: None,
            chunk_bytes: sandbox_protocol::SANDBOX_OUTPUT_CHUNK_MIN_BYTES,
        }
    }
    /// Size new frames for the current connection's `hello.ok` (D3b).
    pub fn set_chunk_bytes(&mut self, bytes: usize) {
        self.chunk_bytes = bytes;
    }
    pub fn ack(&mut self, sequence: u64, offset: u64, now: Instant) {
        if let Some(index) = self.frames.iter().position(|f| {
            f.metadata.sequence == sequence
                && f.metadata
                    .offset
                    .is_some_and(|start| start.checked_add(f.body_len as u64) == Some(offset))
        }) {
            self.frames.drain(..=index);
            self.resend.progressed();
            self.progressed = Some(now);
        }
    }
    pub fn drained(&self) -> bool {
        self.frames.is_empty() && self.output.retained() == 0
    }
    /// Whether the completion observed `since` (held at most `until`) may
    /// publish `now`: the output drained, ACKs stopped advancing for
    /// [`DRAIN_IDLE`], or the absolute bound passed. Anything still retained
    /// then becomes a gap, exactly as an unacknowledged drain always did.
    pub fn drain_settled(&self, since: Instant, until: Instant, now: Instant) -> bool {
        let progress = self.progressed.map_or(since, |at| at.max(since));
        self.drained() || now >= until || now.saturating_duration_since(progress) >= DRAIN_IDLE
    }
    pub fn poll(
        &mut self,
        operation: &str,
        generation: u64,
        attempt: u64,
        now: Instant,
    ) -> anyhow::Result<Vec<Frame>> {
        if !self.frames.is_empty()
            && self
                .last_send
                .is_some_and(|last| self.resend.due(last, now))
        {
            self.last_send = Some(now);
            self.resend.resent();
            return Ok(self.frames.iter().cloned().collect());
        }
        let mut ready = Vec::new();
        while self.frames.len() < WINDOW {
            let Some(chunk) = self.output.pop_max(self.chunk_bytes) else {
                break;
            };
            let metadata = StreamBinaryMetadata {
                r#type: StreamKind::Chunk,
                stream_id: operation.into(),
                operation_id: operation.into(),
                generation,
                attempt,
                sequence: self.sequence,
                offset: Some(chunk.offset),
                gap_start: (chunk.offset > self.offset).then_some(self.offset),
                flags: Some(StreamChunkFlags {
                    stdout: Some(chunk.stream == CommandStream::Stdout),
                    stderr: Some(chunk.stream == CommandStream::Stderr),
                    file_upload: None,
                    file_download: None,
                    stdin: None,
                }),
                final_chunk: None,
            };
            // Encode before advancing the cursor so a failure leaves the
            // sequence/offset state consistent. The popped chunk is lost only
            // together with the session: the caller treats this error as fatal.
            let frame = Frame::encode(metadata, &chunk.bytes)?;
            self.offset = chunk.offset + chunk.bytes.len() as u64;
            self.sequence += 1;
            self.frames.push_back(frame.clone());
            ready.push(frame);
        }
        if !ready.is_empty() {
            self.last_send = Some(now);
        }
        Ok(ready)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_and_interleaved_streams_share_one_sequence_and_cursor() {
        let output = CommandOutput::default();
        let mut window = OutputWindow::new(output.clone());
        assert!(window.poll("op", 1, 1, Instant::now()).unwrap().is_empty());
        assert!(window.drained());
        output.push(CommandStream::Stdout, &[0xe2, 0x82]);
        output.push(CommandStream::Stderr, b"err");
        output.push(CommandStream::Stdout, &[0xac]);
        let frames = window.poll("op", 1, 1, Instant::now()).unwrap();
        assert_eq!(
            frames
                .iter()
                .map(|f| (f.metadata.sequence, f.metadata.offset))
                .collect::<Vec<_>>(),
            vec![(0, Some(0)), (1, Some(2)), (2, Some(5))]
        );
        assert_eq!(
            frames[1].metadata.flags.as_ref().unwrap().stderr,
            Some(true)
        );
        window.ack(2, 6, Instant::now());
        assert!(window.drained());
    }
    #[test]
    fn lost_duplicate_future_and_out_of_order_acks_never_expand_window() {
        let output = CommandOutput::default();
        output.push(CommandStream::Stdout, &[b'x'; 100_000]);
        let mut window = OutputWindow::new(output);
        let now = Instant::now();
        assert_eq!(window.poll("op", 1, 1, now).unwrap().len(), 4);
        assert!(window.poll("op", 1, 1, now).unwrap().is_empty());
        window.ack(999, 100_000, Instant::now());
        window.ack(2, 1, Instant::now());
        assert!(window.poll("op", 1, 1, now).unwrap().is_empty());
        let replay = window
            .poll("op", 1, 1, now + Duration::from_secs(1))
            .unwrap();
        assert_eq!(replay.len(), 4);
        assert_eq!(replay[0].metadata.sequence, 0);
        window.ack(2, 3 * 8192, Instant::now());
        window.ack(0, 8192, Instant::now());
        window.ack(2, 3 * 8192, Instant::now());
        assert_eq!(
            window
                .poll("op", 1, 1, now + Duration::from_secs(1))
                .unwrap()
                .len(),
            3
        );
        assert_eq!(window.frames.len(), 4);
    }
    #[test]
    fn pre_encoded_frames_match_the_direct_encode_and_resend_identically() {
        let output = CommandOutput::default();
        output.push(CommandStream::Stdout, b"hello");
        output.push(CommandStream::Stderr, b"oops");
        let mut window = OutputWindow::new(output);
        let now = Instant::now();
        let sent = window.poll("op", 3, 2, now).unwrap();
        assert_eq!(sent.len(), 2);
        let bodies: [&[u8]; 2] = [b"hello", b"oops"];
        for (frame, body) in sent.iter().zip(bodies) {
            let direct = encode_binary_frame(&frame.metadata, body).unwrap();
            assert_eq!(&frame.encoded()[..], &direct[..]);
            assert_eq!(frame.body(), body);
            assert_eq!(frame.body_len(), body.len());
        }
        let resent = window
            .poll("op", 3, 2, now + Duration::from_secs(1))
            .unwrap();
        assert_eq!(resent.len(), 2);
        for (first, again) in sent.iter().zip(&resent) {
            assert_eq!(first.encoded(), again.encoded());
        }
    }
    /// D3a: a silent window is resent after 250 ms, then 500 ms, 1 s and
    /// 2 s (cap) while no ACK advances; ACK progress restores 250 ms. Each
    /// resend is the same pre-encoded wire bytes.
    #[test]
    fn resends_back_off_without_ack_progress_and_reset_on_progress() {
        let output = CommandOutput::default();
        output.push(CommandStream::Stdout, &[b'x'; 100_000]);
        let mut window = OutputWindow::new(output);
        let t0 = Instant::now();
        let first = window.poll("op", 1, 1, t0).unwrap();
        assert_eq!(first.len(), WINDOW);
        let ms = Duration::from_millis;
        let mut last = t0;
        for gap in [250, 500, 1000, 2000, 2000, 2000] {
            assert!(
                window
                    .poll("op", 1, 1, last + ms(gap - 1))
                    .unwrap()
                    .is_empty(),
                "resent before {gap} ms"
            );
            last += ms(gap);
            let again = window.poll("op", 1, 1, last).unwrap();
            assert_eq!(again.len(), WINDOW, "no resend at {gap} ms");
            for (sent, resent) in first.iter().zip(&again) {
                assert_eq!(sent.encoded(), resent.encoded());
            }
        }
        // One retired frame is progress: the next resend is due at 250 ms again.
        window.ack(0, 8192, last);
        let fresh = window.poll("op", 1, 1, last).unwrap();
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].metadata.sequence, WINDOW as u64);
        assert!(window.poll("op", 1, 1, last + ms(249)).unwrap().is_empty());
        assert_eq!(
            window.poll("op", 1, 1, last + ms(250)).unwrap().len(),
            WINDOW
        );
        // Wrong or stale ACKs are not progress.
        window.ack(0, 8192, last + ms(300));
        window.ack(9, 9, last + ms(300));
        assert!(
            window
                .poll("op", 1, 1, last + ms(250 + 499))
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            window.poll("op", 1, 1, last + ms(750)).unwrap().len(),
            WINDOW
        );
    }

    #[test]
    fn drain_settles_on_drain_ack_idleness_or_the_absolute_bound() {
        let output = CommandOutput::default();
        output.push(CommandStream::Stdout, &[b'x'; 100_000]);
        let mut window = OutputWindow::new(output);
        let since = Instant::now();
        let until = since + DRAIN_MAX;
        window.poll("op", 1, 1, since).unwrap();
        let s = Duration::from_secs;
        // The old fixed 1 s grace no longer releases an advancing drain.
        assert!(!window.drain_settled(since, until, since + s(1)));
        // Silence for DRAIN_IDLE since the completion settles it.
        assert!(window.drain_settled(since, until, since + DRAIN_IDLE));
        // Each ACK that retires frames restarts the idle clock.
        let mut now = since;
        for _ in 0..WINDOW {
            now += s(4);
            let frame = window.frames.front().unwrap().metadata.clone();
            window.ack(frame.sequence, frame.offset.unwrap() + 8192, now);
            assert!(!window.drain_settled(since, until, now + s(4)));
        }
        assert!(window.drain_settled(since, until, now + DRAIN_IDLE));
        // A steady drain still ends at the absolute bound.
        window.poll("op", 1, 1, now).unwrap();
        window.ack(WINDOW as u64, (WINDOW as u64 + 1) * 8192, until - s(1));
        assert!(!window.drain_settled(since, until, until - s(1)));
        assert!(window.drain_settled(since, until, until));
        // A drained window settles at once.
        let empty = OutputWindow::new(CommandOutput::default());
        assert!(empty.drain_settled(since, until, since));
    }
}
