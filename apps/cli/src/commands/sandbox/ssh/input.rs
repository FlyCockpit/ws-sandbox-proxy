//! Input flow control of `wssp ssh --stdio`: one SSH receive window per
//! channel that grows only as the channel's guest consumes.
//!
//! The endpoint runs russh with `manual_window` (the vendored patch,
//! `third_party/russh-0.65.2.patch`): a received data packet only uses up
//! its channel's window, and the window grows only through
//! `Handle::grant_window`. Each channel's [`Budget`] keeps
//! - the window the client may still use (russh does not enforce it, so the
//!   handler does: a client that sends past it gets its channel reset,
//!   [`Admit::Overrun`]);
//! - the input handed over by the SSH side and not yet sent as wssp stdin
//!   frames (never more than the window, so nothing here buffers beyond
//!   it);
//! - the bytes that left as stdin frames and are owed back to the client as
//!   window ([`Budget::take_grant`], at most one grant per channel and
//!   connection-thread turn).
//!
//! A channel's window is one wssp window of its kind (1 MiB for commands and
//! forwards, 128 KiB for a terminal): the first 128 KiB come with the
//! channel's open, the rest once its kind is known ([`Budget::widen`]).
//! So a channel whose guest stops reading stops only its own ssh client at
//! that window; every other channel keeps its own.
//!
//! Its latest terminal size and its pending signals live here too. Nothing
//! here ever waits.

use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard, PoisonError};

/// Signals of one channel waiting for the connection thread, at most.
const MAX_PENDING_SIGNALS: usize = 8;
/// Small packets share a buffer up to this size.
const COALESCE: usize = 32 * 1024;

/// A debug build appends `line` to the file named by
/// `WSSP_TEST_SSH_NOTE_LOG`: every channel window used up or granted again
/// (`exhausted <n>`/`granted <n>`, `n` the endpoint's channel key) and every
/// channel write that has to wait for the client's window
/// (`blocked`/`unblocked`), so black-box tests synchronise on the real state
/// instead of sampling throughput. Release builds compile nothing.
#[cfg(debug_assertions)]
pub fn test_note(line: &str) {
    use std::io::Write;
    let Some(path) = std::env::var_os("WSSP_TEST_SSH_NOTE_LOG") else {
        return;
    };
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|mut file| writeln!(file, "{line}"));
}

#[cfg(not(debug_assertions))]
pub fn test_note(_line: &str) {}

/// Window a debug build announces with every channel's open without
/// counting it (`WSSP_TEST_SSH_UNCOUNTED_WINDOW`, at most 1 MiB), so a test
/// client that keeps to its window overruns the count. Release builds
/// always announce exactly what they count.
#[cfg(debug_assertions)]
pub fn uncounted_window() -> u32 {
    std::env::var("WSSP_TEST_SSH_UNCOUNTED_WINDOW")
        .ok()
        .and_then(|bytes| bytes.parse::<u32>().ok())
        .map_or(0, |bytes| bytes.min(1024 * 1024))
}

#[cfg(not(debug_assertions))]
pub fn uncounted_window() -> u32 {
    0
}

/// What became of bytes the SSH client sent on a channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    /// Queued for the guest.
    Kept,
    /// Counted against the window and dropped (the channel ended, has not
    /// started, or the bytes are of no use, like a client's extended data).
    Dropped,
    /// More than the window the client had left: a protocol violation; the
    /// caller resets the channel.
    Overrun,
}

#[derive(Debug, Default)]
struct BudgetState {
    queue: VecDeque<Vec<u8>>,
    closed: bool,
    /// Its wssp channel was asked for: later bytes are kept.
    started: bool,
    /// Window granted to the client and not used yet.
    window: usize,
    /// Window granted in total (what [`Budget::widen`] tops up to).
    granted: usize,
    /// Bytes consumed (sent as stdin frames, or dropped as of no use) and
    /// not granted back yet.
    owed: usize,
    /// The latest terminal size not yet taken by the connection thread.
    resize: Option<(u16, u16)>,
    /// Signals handed over and not yet handled.
    signals: usize,
}

/// One channel's input in this process. The SSH side admits, the
/// connection thread takes and grants; nothing here ever waits.
#[derive(Debug)]
pub struct Budget {
    /// The endpoint's key of the channel (for the test notes).
    local: u64,
    state: Mutex<BudgetState>,
}

impl Budget {
    /// A channel whose open granted the client `initial` bytes of window.
    pub fn new(local: u64, initial: usize) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            local,
            state: Mutex::new(BudgetState {
                window: initial,
                granted: initial,
                ..BudgetState::default()
            }),
        })
    }

    fn lock(&self) -> MutexGuard<'_, BudgetState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// From now on bytes are kept for the guest.
    pub fn start(&self) {
        self.lock().started = true;
    }

    /// Top the channel's window up to `total` once its kind is known; the
    /// bytes the caller grants now (0 when there is nothing to add or the
    /// channel ended).
    pub fn widen(&self, total: usize) -> u32 {
        let mut state = self.lock();
        if state.closed {
            return 0;
        }
        let add = u32::try_from(total.saturating_sub(state.granted)).unwrap_or(u32::MAX);
        let add_bytes = add as usize;
        state.granted = state.granted.saturating_add(add_bytes);
        state.window = state.window.saturating_add(add_bytes);
        add
    }

    /// Count `len` received bytes against the window: `Err` past it.
    fn consume(&self, state: &mut BudgetState, len: usize) -> Result<(), ()> {
        if len > state.window {
            return Err(());
        }
        state.window -= len;
        if state.window == 0 && len > 0 {
            test_note(&format!("exhausted {}", self.local));
        }
        Ok(())
    }

    /// The SSH client sent `bytes` on the channel. Never waits: a client
    /// can send no more than its window, and the queue holds no more.
    pub fn admit(&self, bytes: &[u8]) -> Admit {
        let mut state = self.lock();
        if state.closed {
            return Admit::Dropped;
        }
        if self.consume(&mut state, bytes.len()).is_err() {
            return Admit::Overrun;
        }
        if !state.started {
            return Admit::Dropped;
        }
        if bytes.is_empty() {
            return Admit::Kept;
        }
        match state.queue.back_mut() {
            Some(back) if back.len() + bytes.len() <= COALESCE => back.extend_from_slice(bytes),
            _ => state.queue.push_back(bytes.to_vec()),
        }
        Admit::Kept
    }

    /// The SSH client sent `len` bytes the guest never gets (extended data
    /// toward the guest has no meaning): counted, dropped, and owed back at
    /// once.
    pub fn admit_ignored(&self, len: usize) -> Admit {
        let mut state = self.lock();
        if state.closed {
            return Admit::Dropped;
        }
        if self.consume(&mut state, len).is_err() {
            return Admit::Overrun;
        }
        state.owed = state.owed.saturating_add(len);
        Admit::Dropped
    }

    /// Take up to `max` bytes to send as one stdin frame now; they are owed
    /// back to the client as window.
    pub fn take(&self, max: usize) -> Option<Vec<u8>> {
        let mut state = self.lock();
        let front = state.queue.front_mut()?;
        let bytes = if front.len() <= max {
            state.queue.pop_front()?
        } else {
            let rest = front.split_off(max.max(1));
            std::mem::replace(front, rest)
        };
        state.owed = state.owed.saturating_add(bytes.len());
        Some(bytes)
    }

    /// The window to grant the client now: everything owed, at once (one
    /// grant), counted as granted before the caller sends it. `None` when
    /// nothing is owed or the channel ended (a grant after the close is
    /// never sent).
    pub fn take_grant(&self) -> Option<u32> {
        let mut state = self.lock();
        if state.closed || state.owed == 0 {
            return None;
        }
        let grant = u32::try_from(state.owed).unwrap_or(u32::MAX);
        let bytes = grant as usize;
        state.owed -= bytes;
        if state.window == 0 {
            test_note(&format!("granted {}", self.local));
        }
        state.window = state.window.saturating_add(bytes);
        Some(grant)
    }

    /// Nothing is waiting to be sent.
    pub fn is_empty(&self) -> bool {
        self.lock().queue.is_empty()
    }

    /// The channel ended: what it held is dropped, later input is dropped,
    /// and it is owed nothing.
    pub fn close(&self) {
        let mut state = self.lock();
        state.closed = true;
        state.queue.clear();
        state.owed = 0;
        state.resize = None;
    }

    pub fn is_closed(&self) -> bool {
        self.lock().closed
    }

    /// Keep the latest size; `true` when the connection thread has to be
    /// told (no size was waiting), so resizes never pile up.
    pub fn set_resize(&self, rows: u16, cols: u16) -> bool {
        let mut state = self.lock();
        if state.closed {
            return false;
        }
        state.resize.replace((rows, cols)).is_none()
    }

    pub fn take_resize(&self) -> Option<(u16, u16)> {
        self.lock().resize.take()
    }

    /// Admit one signal; `false` (drop it) beyond [`MAX_PENDING_SIGNALS`].
    pub fn admit_signal(&self) -> bool {
        let mut state = self.lock();
        if state.closed || state.signals >= MAX_PENDING_SIGNALS {
            return false;
        }
        state.signals += 1;
        true
    }

    /// The connection thread handled one signal.
    pub fn signal_done(&self) {
        let mut state = self.lock();
        state.signals = state.signals.saturating_sub(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INITIAL: usize = 128 * 1024;
    const BULK: usize = 1024 * 1024;

    fn started(initial: usize, total: usize) -> std::sync::Arc<Budget> {
        let budget = Budget::new(1, initial);
        budget.start();
        assert_eq!(budget.widen(total) as usize, total - initial);
        budget
    }

    fn fill(budget: &Budget, bytes: usize) -> Admit {
        let packet = vec![7_u8; 32 * 1024];
        let mut left = bytes;
        let mut last = Admit::Kept;
        while left > 0 {
            let n = left.min(packet.len());
            last = budget.admit(&packet[..n]);
            if last != Admit::Kept {
                return last;
            }
            left -= n;
        }
        last
    }

    fn drain(budget: &Budget, bytes: usize) {
        let mut left = bytes;
        while left > 0 {
            let taken = budget.take(left.min(32 * 1024)).expect("queued bytes");
            left -= taken.len();
        }
    }

    #[test]
    fn a_channel_takes_exactly_its_window_and_a_byte_more_is_an_overrun() {
        let budget = started(INITIAL, BULK);
        assert_eq!(fill(&budget, BULK), Admit::Kept);
        assert_eq!(budget.admit(&[1]), Admit::Overrun);
        // An empty packet is never an overrun.
        assert_eq!(budget.admit(&[]), Admit::Kept);
        // Its guest consumed 64 KiB: exactly that much may come again.
        drain(&budget, 64 * 1024);
        assert_eq!(budget.take_grant(), Some(64 * 1024));
        assert_eq!(budget.take_grant(), None, "one grant for what is owed");
        assert_eq!(fill(&budget, 64 * 1024), Admit::Kept);
        assert_eq!(budget.admit(&[1]), Admit::Overrun);
    }

    #[test]
    fn the_window_grows_only_as_bytes_leave() {
        let budget = started(INITIAL, BULK);
        assert_eq!(fill(&budget, BULK), Admit::Kept);
        assert_eq!(budget.take_grant(), None, "nothing consumed, nothing owed");
        // Three frames leave between two grants: one coalesced grant.
        drain(&budget, 3 * 32 * 1024);
        assert_eq!(budget.take_grant(), Some(3 * 32 * 1024));
        // A widen after the start adds nothing more.
        assert_eq!(budget.widen(BULK), 0);
        // A terminal's window is its open's window: nothing to widen.
        let terminal = Budget::new(2, INITIAL);
        terminal.start();
        assert_eq!(terminal.widen(INITIAL), 0);
        assert_eq!(fill(&terminal, INITIAL), Admit::Kept);
        assert_eq!(terminal.admit(&[1]), Admit::Overrun);
    }

    #[test]
    fn bytes_before_the_start_count_and_are_dropped() {
        let budget = Budget::new(1, INITIAL);
        assert_eq!(budget.admit(&[1; 100]), Admit::Dropped);
        assert!(budget.is_empty());
        budget.start();
        assert_eq!(budget.widen(BULK) as usize, BULK - INITIAL);
        assert_eq!(fill(&budget, BULK - 100), Admit::Kept);
        assert_eq!(budget.admit(&[1]), Admit::Overrun);
    }

    #[test]
    fn a_clients_extended_data_is_counted_and_owed_back_at_once() {
        let budget = started(INITIAL, BULK);
        assert_eq!(budget.admit_ignored(1000), Admit::Dropped);
        assert!(budget.is_empty());
        assert_eq!(budget.take_grant(), Some(1000));
        assert_eq!(budget.admit_ignored(BULK + 1), Admit::Overrun);
    }

    #[test]
    fn a_grant_after_the_close_is_never_sent() {
        let budget = started(INITIAL, BULK);
        assert_eq!(fill(&budget, BULK), Admit::Kept);
        drain(&budget, 32 * 1024);
        budget.close();
        assert_eq!(budget.take_grant(), None);
        assert_eq!(budget.widen(2 * BULK), 0);
        assert!(budget.take(100).is_none());
        // Later input is dropped, never an overrun of an ended channel.
        assert_eq!(budget.admit(&[1; 64]), Admit::Dropped);
        assert_eq!(budget.admit_ignored(BULK * 4), Admit::Dropped);
    }

    #[test]
    fn bytes_come_out_in_order_within_the_frame_size() {
        let budget = started(INITIAL, BULK);
        let mut sent = Vec::new();
        for n in 1..200_usize {
            let packet: Vec<u8> = (0..n).map(|i| (i + n) as u8).collect();
            sent.extend_from_slice(&packet);
            assert_eq!(budget.admit(&packet), Admit::Kept);
        }
        let mut got = Vec::new();
        while let Some(frame) = budget.take(1000) {
            assert!(!frame.is_empty() && frame.len() <= 1000);
            got.extend(frame);
        }
        assert!(got == sent);
        assert!(budget.is_empty());
        assert_eq!(budget.take_grant(), Some(sent.len() as u32));
    }

    #[test]
    fn resizes_coalesce_and_signals_are_capped() {
        let channel = started(INITIAL, BULK);
        assert!(channel.set_resize(10, 20));
        assert!(!channel.set_resize(11, 21));
        assert!(!channel.set_resize(12, 22));
        assert_eq!(channel.take_resize(), Some((12, 22)));
        assert_eq!(channel.take_resize(), None);
        assert!(channel.set_resize(13, 23));
        let admitted = (0..100).filter(|_| channel.admit_signal()).count();
        assert_eq!(admitted, MAX_PENDING_SIGNALS);
        channel.signal_done();
        assert!(channel.admit_signal());
        channel.close();
        assert!(!channel.set_resize(1, 1));
        assert!(!channel.admit_signal());
    }
}
