//! Pipe producers never wait for a network consumer. One aggregate byte cursor
//! covers both streams; retained bytes are the first 256 KiB and last 768 KiB.
use crate::CommandStream;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
pub const OUTPUT_HEAD: usize = 256 * 1024;
pub const OUTPUT_TAIL: usize = 768 * 1024;
pub const OUTPUT_CHUNK: usize = 8192;
#[derive(Debug, Default)]
struct Bytes {
    head: Lane,
    tail: Lane,
    head_offset: u64,
    total: u64,
    closed: bool,
}

/// Retained bytes plus their stream as run lengths. Adjacent runs always name
/// different streams: pushes merge at the back, pops and eviction only remove
/// from the front.
#[derive(Debug, Default)]
struct Lane {
    bytes: VecDeque<u8>,
    runs: VecDeque<(CommandStream, usize)>,
}

impl Lane {
    fn len(&self) -> usize {
        self.bytes.len()
    }
    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
    fn push(&mut self, stream: CommandStream, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.bytes.extend(bytes.iter().copied());
        match self.runs.back_mut() {
            Some((last, len)) if *last == stream => *len += bytes.len(),
            _ => self.runs.push_back((stream, bytes.len())),
        }
    }
    /// Drop the `count` oldest bytes.
    fn evict(&mut self, count: usize) {
        let count = count.min(self.bytes.len());
        self.bytes.drain(..count);
        let mut left = count;
        while left > 0 {
            let Some(front) = self.runs.front_mut() else {
                break;
            };
            if front.1 > left {
                front.1 -= left;
                break;
            }
            left -= front.1;
            self.runs.pop_front();
        }
    }
    /// Take up to `max` bytes of the front run (one stream).
    fn pop(&mut self, max: usize) -> Option<(CommandStream, Vec<u8>)> {
        let &(stream, run) = self.runs.front()?;
        let take = run.min(max).min(self.bytes.len());
        let mut out = Vec::with_capacity(take);
        let (a, b) = self.bytes.as_slices();
        let from_a = take.min(a.len());
        out.extend_from_slice(&a[..from_a]);
        out.extend_from_slice(&b[..take - from_a]);
        self.evict(take);
        Some((stream, out))
    }
}
#[derive(Debug, Clone, Default)]
pub struct CommandOutput(Arc<Mutex<Bytes>>, Arc<Mutex<StartSlot>>);

/// One immutable start binding per command attempt (4a). The first valid
/// record binds; an identical repeat is idempotent; a conflicting record is
/// refused and can never replace the identity.
#[derive(Debug, Default)]
struct StartSlot {
    birth: Option<crate::CommandBirth>,
    published: bool,
    sink: Option<StartSink>,
}

/// Where a bound start is journaled (decision 2). Called at most once per
/// output window, on the command's own wait loop, never under a runtime lock.
#[derive(Clone)]
struct StartSink(Arc<dyn Fn(&crate::CommandStart) + Send + Sync>);
impl std::fmt::Debug for StartSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StartSink")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartBinding {
    Bound,
    Duplicate,
    Conflict,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputChunk {
    pub stream: CommandStream,
    pub offset: u64,
    pub bytes: Vec<u8>,
}
impl CommandOutput {
    /// This window journals its bound start through `sink` (decision 2).
    #[must_use]
    pub fn with_start_sink(
        self,
        sink: impl Fn(&crate::CommandStart) + Send + Sync + 'static,
    ) -> Self {
        self.1.lock().unwrap_or_else(|e| e.into_inner()).sink = Some(StartSink(Arc::new(sink)));
        self
    }
    /// Hand the start that [`Self::bind_start`] just bound to the sink, once.
    /// A start whose birth is not the bound one is ignored.
    pub fn record_start(&self, start: &crate::CommandStart) {
        let sink = {
            let mut slot = self.1.lock().unwrap_or_else(|e| e.into_inner());
            if slot.birth.as_ref() != Some(&start.birth) {
                return;
            }
            slot.sink.take()
        };
        if let Some(sink) = sink {
            (sink.0)(start);
        }
    }
    pub fn bind_start(&self, birth: &crate::CommandBirth) -> StartBinding {
        let mut slot = self.1.lock().unwrap_or_else(|e| e.into_inner());
        match &slot.birth {
            None => {
                slot.birth = Some(birth.clone());
                StartBinding::Bound
            }
            Some(existing) if existing == birth => StartBinding::Duplicate,
            Some(_) => StartBinding::Conflict,
        }
    }
    pub fn start(&self) -> Option<crate::CommandBirth> {
        self.1
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .birth
            .clone()
    }
    /// Best-effort publication: yields the bound identity at most once.
    pub fn take_unpublished_start(&self) -> Option<crate::CommandBirth> {
        let mut slot = self.1.lock().unwrap_or_else(|e| e.into_inner());
        if slot.published {
            return None;
        }
        let birth = slot.birth.clone()?;
        slot.published = true;
        Some(birth)
    }
    pub fn push(&self, stream: CommandStream, bytes: &[u8]) {
        // Bound lock hold time even for a runtime submitting one large slice.
        for part in bytes.chunks(OUTPUT_CHUNK) {
            let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
            if state.closed {
                return;
            }
            // Absolute bytes [0, OUTPUT_HEAD) are head; the rest is tail.
            let head_room = (OUTPUT_HEAD as u64).saturating_sub(state.total);
            let split = usize::try_from(head_room).map_or(part.len(), |room| room.min(part.len()));
            let (to_head, to_tail) = part.split_at(split);
            state.head.push(stream, to_head);
            state.tail.push(stream, to_tail);
            let excess = state.tail.len().saturating_sub(OUTPUT_TAIL);
            state.tail.evict(excess);
            state.total += part.len() as u64;
        }
    }
    /// Freeze the observation boundary; late detached pipe readers still drain
    /// their OS pipes but cannot append bytes after the result watermark.
    pub fn close(&self) -> u64 {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state.closed = true;
        state.total
    }
    pub fn total(&self) -> u64 {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).total
    }
    pub fn retained(&self) -> usize {
        let s = self.0.lock().unwrap_or_else(|e| e.into_inner());
        s.head.len() + s.tail.len()
    }
    /// Next chunk of at most [`OUTPUT_CHUNK`] bytes.
    pub fn pop(&self) -> Option<OutputChunk> {
        self.pop_max(OUTPUT_CHUNK)
    }
    /// Next chunk of at most `max` bytes (at least one): one stream, from the
    /// head while it holds bytes, else from the tail (D3b negotiated size).
    pub fn pop_max(&self, max: usize) -> Option<OutputChunk> {
        let max = max.max(1);
        let mut s = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let head = !s.head.is_empty();
        let offset = if head {
            s.head_offset
        } else {
            s.total - s.tail.len() as u64
        };
        let queue = if head { &mut s.head } else { &mut s.tail };
        let (stream, bytes) = queue.pop(max)?;
        if head {
            s.head_offset += bytes.len() as u64;
        }
        Some(OutputChunk {
            stream,
            offset,
            bytes,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    /// Decision 2: the bound start reaches the sink exactly once; a start
    /// for any other birth never does.
    #[test]
    fn the_start_sink_sees_only_the_bound_start_once() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let out = CommandOutput::default().with_start_sink(move |start: &crate::CommandStart| {
            sink.lock().unwrap().push(start.clone());
        });
        let birth = crate::CommandBirth {
            pid: 42,
            boot_id: "00000000-0000-4000-8000-000000000001".into(),
            start_ticks: 7,
            started_at_ms: 1,
        };
        let start = crate::CommandStart {
            birth: birth.clone(),
            uid: 1000,
            budget_ms: 5000,
            qemu: None,
        };
        out.record_start(&start);
        assert!(seen.lock().unwrap().is_empty(), "nothing bound yet");
        assert_eq!(out.bind_start(&birth), StartBinding::Bound);
        let mut other = start.clone();
        other.birth.pid = 43;
        out.record_start(&other);
        out.record_start(&start);
        out.record_start(&start);
        assert_eq!(*seen.lock().unwrap(), [start]);
    }
    #[test]
    fn pop_max_takes_negotiated_chunks_of_one_stream_across_the_head_boundary() {
        let out = CommandOutput::default();
        out.push(CommandStream::Stdout, &vec![1; OUTPUT_HEAD + 10_000]);
        out.push(CommandStream::Stderr, &[2; 100]);
        let mut offset = 0;
        let mut sizes = Vec::new();
        while let Some(chunk) = out.pop_max(64 * 1024) {
            assert_eq!(chunk.offset, offset);
            offset += chunk.bytes.len() as u64;
            sizes.push((chunk.stream, chunk.bytes.len()));
        }
        // Four full head chunks, the tail's stdout, then the stderr run.
        assert_eq!(
            sizes,
            [
                (CommandStream::Stdout, 65_536),
                (CommandStream::Stdout, 65_536),
                (CommandStream::Stdout, 65_536),
                (CommandStream::Stdout, 65_536),
                (CommandStream::Stdout, 10_000),
                (CommandStream::Stderr, 100),
            ]
        );
        assert_eq!(offset, out.total());
        // `pop` keeps the historical 8 KiB.
        out.push(CommandStream::Stdout, &[3; 20_000]);
        assert_eq!(out.pop().unwrap().bytes.len(), OUTPUT_CHUNK);
    }
    #[test]
    fn stalled_output_retains_exact_head_tail_and_interleaved_byte_offsets() {
        let out = CommandOutput::default();
        out.push(CommandStream::Stdout, &[0xe2, 0x82]);
        out.push(CommandStream::Stderr, b"err");
        out.push(CommandStream::Stdout, &[0xac]);
        assert_eq!(out.pop().unwrap().bytes, [0xe2, 0x82]);
        assert_eq!(out.pop().unwrap().offset, 2);
        assert_eq!(out.pop().unwrap().bytes, [0xac]);
        for _ in 0..512 {
            out.push(CommandStream::Stderr, &[b'x'; OUTPUT_CHUNK]);
        }
        assert_eq!(out.retained(), OUTPUT_HEAD + OUTPUT_TAIL - 6);
        assert_eq!(out.total(), 512 * OUTPUT_CHUNK as u64 + 6);
        let mut cursor = 6;
        let mut gaps = Vec::new();
        while let Some(chunk) = out.pop() {
            if chunk.offset != cursor {
                gaps.push((cursor, chunk.offset));
            }
            cursor = chunk.offset + chunk.bytes.len() as u64;
        }
        assert_eq!(
            gaps,
            vec![(OUTPUT_HEAD as u64, out.total() - OUTPUT_TAIL as u64)]
        );
        assert_eq!(cursor, out.total());
        assert_eq!(out.retained(), 0);
        let total = out.close();
        out.push(CommandStream::Stdout, b"late");
        assert_eq!(out.total(), total);
    }

    /// The pre-R1 per-byte implementation, kept verbatim as a test oracle.
    #[derive(Debug, Default)]
    struct OldBytes {
        head: VecDeque<(CommandStream, u8)>,
        tail: VecDeque<(CommandStream, u8)>,
        head_offset: u64,
        total: u64,
        closed: bool,
    }
    #[derive(Debug, Default)]
    struct OldOutput(Mutex<OldBytes>);
    impl OldOutput {
        fn push(&self, stream: CommandStream, bytes: &[u8]) {
            for part in bytes.chunks(OUTPUT_CHUNK) {
                let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
                if state.closed {
                    return;
                }
                for &byte in part {
                    if state.total < OUTPUT_HEAD as u64 {
                        state.head.push_back((stream, byte));
                    } else {
                        if state.tail.len() == OUTPUT_TAIL {
                            state.tail.pop_front();
                        }
                        state.tail.push_back((stream, byte));
                    }
                    state.total += 1;
                }
            }
        }
        fn close(&self) -> u64 {
            let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
            state.closed = true;
            state.total
        }
        fn total(&self) -> u64 {
            self.0.lock().unwrap_or_else(|e| e.into_inner()).total
        }
        fn retained(&self) -> usize {
            let s = self.0.lock().unwrap_or_else(|e| e.into_inner());
            s.head.len() + s.tail.len()
        }
        fn pop(&self) -> Option<OutputChunk> {
            let mut s = self.0.lock().unwrap_or_else(|e| e.into_inner());
            let head = !s.head.is_empty();
            let offset = if head {
                s.head_offset
            } else {
                s.total - s.tail.len() as u64
            };
            let queue = if head { &mut s.head } else { &mut s.tail };
            let stream = queue.front()?.0;
            let mut bytes = Vec::new();
            while bytes.len() < OUTPUT_CHUNK && queue.front().is_some_and(|v| v.0 == stream) {
                if let Some((_, byte)) = queue.pop_front() {
                    bytes.push(byte);
                }
            }
            if head {
                s.head_offset += bytes.len() as u64;
            }
            Some(OutputChunk {
                stream,
                offset,
                bytes,
            })
        }
    }

    /// xorshift64*: deterministic, dependency-free.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    fn random_len(rng: &mut Rng) -> usize {
        let len = match rng.below(10) {
            0 => 0,
            1..=4 => rng.below(64),
            5..=7 => rng.below(3 * OUTPUT_CHUNK as u64),
            8 => OUTPUT_CHUNK as u64 + rng.below(3) - 1,
            _ => rng.below(OUTPUT_HEAD as u64 + OUTPUT_TAIL as u64 / 2),
        };
        usize::try_from(len).unwrap()
    }

    #[test]
    fn run_length_buffer_matches_per_byte_oracle_on_random_interleavings() {
        for seed in 1..=60u64 {
            let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
            let new = CommandOutput::default();
            let old = OldOutput::default();
            let mut counter = 0u8;
            // Every seed pushes well past head + tail (> 1 MiB).
            let target = (OUTPUT_HEAD + OUTPUT_TAIL) as u64 + rng.below(2 * 1024 * 1024);
            let mut pushed = 0u64;
            let mut closed = false;
            while pushed < target {
                match rng.below(8) {
                    0..=3 => {
                        let stream = if rng.below(2) == 0 {
                            CommandStream::Stdout
                        } else {
                            CommandStream::Stderr
                        };
                        let len = random_len(&mut rng);
                        let bytes: Vec<u8> = (0..len)
                            .map(|_| {
                                counter = counter.wrapping_add(1);
                                counter
                            })
                            .collect();
                        new.push(stream, &bytes);
                        old.push(stream, &bytes);
                        pushed += len as u64;
                    }
                    4..=6 => {
                        for _ in 0..rng.below(6) {
                            let (a, b) = (new.pop(), old.pop());
                            assert_eq!(a, b, "seed {seed}");
                        }
                    }
                    _ => {
                        // Close late in a minority of runs.
                        if !closed && pushed > target / 2 && rng.below(4) == 0 {
                            assert_eq!(new.close(), old.close(), "seed {seed}");
                            closed = true;
                        }
                    }
                }
                assert_eq!(new.total(), old.total(), "seed {seed}");
                assert_eq!(new.retained(), old.retained(), "seed {seed}");
            }
            loop {
                let (a, b) = (new.pop(), old.pop());
                assert_eq!(a, b, "seed {seed}");
                if a.is_none() {
                    break;
                }
            }
            assert_eq!(new.retained(), 0);
        }
    }

    #[test]
    fn chunk_never_crosses_head_into_tail_and_same_stream_pushes_merge() {
        let out = CommandOutput::default();
        out.push(CommandStream::Stdout, &vec![1; OUTPUT_HEAD - 3]);
        // One push straddling the head boundary, same stream.
        out.push(CommandStream::Stdout, &[2; 10]);
        let mut chunks = Vec::new();
        while let Some(chunk) = out.pop() {
            chunks.push(chunk);
        }
        let last_head = &chunks[chunks.len() - 2];
        assert_eq!(
            last_head.offset + last_head.bytes.len() as u64,
            OUTPUT_HEAD as u64
        );
        let tail = &chunks[chunks.len() - 1];
        assert_eq!(tail.offset, OUTPUT_HEAD as u64);
        assert_eq!(tail.bytes, vec![2; 7]);
        // Separate small same-stream pushes merge into one chunk.
        out.push(CommandStream::Stderr, b"ab");
        out.push(CommandStream::Stderr, b"cd");
        assert_eq!(out.pop().unwrap().bytes, b"abcd");
    }

    /// Micro benchmark: `cargo nextest run -p sandbox-runtime --run-ignored
    /// ignored-only output_throughput --no-capture` (use --release for numbers).
    #[test]
    #[ignore = "benchmark; prints timings"]
    fn output_throughput_old_vs_new() {
        const TOTAL: usize = 64 * 1024 * 1024;
        let slice = vec![b'x'; 64 * 1024];
        let start = std::time::Instant::now();
        let old = OldOutput::default();
        for i in 0..TOTAL / slice.len() {
            let stream = if i % 3 == 0 {
                CommandStream::Stderr
            } else {
                CommandStream::Stdout
            };
            old.push(stream, &slice);
            for _ in 0..4 {
                let _ = old.pop();
            }
        }
        while old.pop().is_some() {}
        let old_time = start.elapsed();
        let start = std::time::Instant::now();
        let new = CommandOutput::default();
        for i in 0..TOTAL / slice.len() {
            let stream = if i % 3 == 0 {
                CommandStream::Stderr
            } else {
                CommandStream::Stdout
            };
            new.push(stream, &slice);
            for _ in 0..4 {
                let _ = new.pop();
            }
        }
        while new.pop().is_some() {}
        let new_time = start.elapsed();
        println!("64 MiB push/pop: old {old_time:?}, new {new_time:?}");
        assert!(new_time < old_time);
    }
}
