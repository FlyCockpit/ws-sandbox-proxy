//! FakeRuntime CLI channels (tests only drive these; no guest exists).
//!
//! The fake guest speaks the real in-band protocol: it prompts on its frame
//! stream (stderr for exec, the tty for pty), parses the preamble the IO
//! owner writes (environment and frame secret), then reports a secret-bound
//! READY and, at the end, EXIT. Default behaviour, so relay tests work
//! without scripting:
//! - `exec` is `cat`: stdin bytes come back on stdout; stdin EOF ends both
//!   streams and the process exits 0.
//! - `pty` echoes input; a `^D` byte exits 0.
//!
//! [`FakeChannelControl`] scripts everything else (output, exits, signal
//! support, uncertain kills) and observes stdin, sizes, signals and closes.
//! The IO half never blocks and never sleeps.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sandbox_protocol::SandboxErrorCode;

use crate::channel::{
    CHANNEL_EXEC_READ_BYTES, CHANNEL_PTY_READ_BYTES, ChannelBirth, ChannelClose, ChannelCustody,
    ChannelEnd, ChannelExitStatus, ChannelIo, ChannelMode, ChannelOutput, ChannelRead,
    ChannelScope, ChannelSignalOutcome, WriteRefused, guest_frame_bytes,
};
use crate::error::RuntimeError;
use crate::{ProcessSignal, PtySize};

/// Unread stdin chunks the fake keeps before a write is refused (busy).
const FAKE_STDIN_CAPACITY: usize = 32;

#[derive(Debug)]
struct State {
    pty: bool,
    nonce: String,
    argv: Option<Vec<String>>,
    login: bool,
    cwd: Option<String>,
    sizes: Vec<PtySize>,
    pid: u32,
    /// Chunks the guest wrote and the owner has not read, per stream (one
    /// write is one read, split only at the read size).
    streams: [VecDeque<Vec<u8>>; 2],
    /// The guest closed the stream (after what is queued).
    closed: [bool; 2],
    preamble: Vec<u8>,
    env: Option<Vec<(String, String)>>,
    secret: Option<String>,
    stdin: Vec<u8>,
    pending_stdin: VecDeque<Vec<u8>>,
    stdin_closed: bool,
    hold_stdin: bool,
    input_ready: bool,
    signals: Vec<ProcessSignal>,
    signal_support: bool,
    signal_delay: Duration,
    echo: bool,
    exit: Option<ChannelExitStatus>,
    closes: Vec<ChannelClose>,
    kill_uncertain: bool,
    unreaped: bool,
    /// A hangup or finish takes this long (a client slow to end).
    normal_close_delay: Duration,
    ended: Option<ChannelEnd>,
    /// `terminate` calls (after a later kill proof).
    terminations: usize,
    /// The host client exited on its own (after an unproven kill).
    client_exited: bool,
}

impl State {
    fn frame_stream(&self) -> usize {
        if self.pty { 0 } else { 1 }
    }

    fn push(&mut self, stream: usize, bytes: &[u8]) {
        if !self.closed[stream] && !bytes.is_empty() {
            self.streams[stream].push_back(bytes.to_vec());
        }
    }

    fn frame(&mut self, fields: &str) {
        let Some(secret) = self.secret.clone() else {
            return;
        };
        let stream = self.frame_stream();
        let bytes = guest_frame_bytes(&secret, fields);
        self.push(stream, &bytes);
    }

    fn exit_with(&mut self, status: ChannelExitStatus, close_streams: bool) {
        if self.exit.is_some() || self.secret.is_none() {
            return;
        }
        self.exit = Some(status);
        let fields = match status {
            ChannelExitStatus::Code(code) => format!("EXIT code {code}"),
            ChannelExitStatus::Signal(signal) => format!("EXIT signal {signal}"),
            ChannelExitStatus::Unknown => String::new(),
        };
        if !fields.is_empty() {
            self.frame(&fields);
        }
        if close_streams {
            self.closed = [true, true];
        }
    }

    /// The fake workload reads its stdin (unless held): `cat` echo, `^D` on
    /// a pty.
    fn consume(&mut self) {
        if self.hold_stdin {
            return;
        }
        while let Some(bytes) = self.pending_stdin.pop_front() {
            self.stdin.extend_from_slice(&bytes);
            if self.pty && bytes.contains(&0x04) {
                self.pending_stdin.clear();
                self.exit_with(ChannelExitStatus::Code(0), true);
                return;
            }
            if self.echo {
                self.push(0, &bytes);
            }
        }
    }

    /// A complete preamble starts the fake workload (READY).
    fn take_preamble(&mut self, bytes: &[u8]) {
        self.preamble.extend_from_slice(bytes);
        let Some((env, secret, used)) = parse_preamble(&self.preamble) else {
            return;
        };
        let rest = self.preamble.split_off(used);
        self.preamble.clear();
        self.env = Some(env);
        self.secret = Some(secret);
        let pid = self.pid;
        self.frame(&format!(
            "READY {pid} {} {} 1000",
            super::FAKE_BOOT_ID,
            u64::from(pid) * 10
        ));
        if !rest.is_empty() {
            self.pending_stdin.push_back(rest);
            self.consume();
        }
    }
}

/// A parsed preamble: env, secret, bytes used.
type Preamble = (Vec<(String, String)>, String, usize);

/// `<8 hex>:<base64 JSON>` + 32-char secret + `\n`; `None` until complete.
fn parse_preamble(bytes: &[u8]) -> Option<Preamble> {
    let header = bytes.get(..9)?;
    let length = usize::from_str_radix(std::str::from_utf8(header.get(..8)?).ok()?, 16).ok()?;
    let body = bytes.get(9..9 + length)?;
    let line = bytes.get(9 + length..9 + length + 33)?;
    let env = if length == 0 {
        Vec::new()
    } else {
        let json = decode_base64(body)?;
        let map: std::collections::BTreeMap<String, String> = serde_json::from_slice(&json).ok()?;
        map.into_iter().collect()
    };
    (line[32] == b'\n').then_some(())?;
    let secret = std::str::from_utf8(&line[..32]).ok()?.to_string();
    Some((env, secret, 9 + length + 33))
}

fn decode_base64(text: &[u8]) -> Option<Vec<u8>> {
    let value = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a') + 26,
            b'0'..=b'9' => u32::from(c - b'0') + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    };
    let mut out = Vec::new();
    for chunk in text.chunks(4) {
        let pad = chunk.iter().filter(|c| **c == b'=').count();
        let mut acc = 0u32;
        for c in chunk {
            acc = (acc << 6) | if *c == b'=' { 0 } else { value(*c)? };
        }
        let bytes = acc.to_be_bytes();
        out.extend_from_slice(&bytes[1..4 - pad]);
    }
    Some(out)
}

#[derive(Clone, Debug)]
pub struct FakeChannelControl {
    state: Arc<Mutex<State>>,
}

impl FakeChannelControl {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub fn is_pty(&self) -> bool {
        self.lock().pty
    }
    pub fn argv(&self) -> Option<Vec<String>> {
        self.lock().argv.clone()
    }
    pub fn login(&self) -> bool {
        self.lock().login
    }
    /// The environment the preamble carried (`None` before it arrived).
    pub fn env(&self) -> Option<Vec<(String, String)>> {
        self.lock().env.clone()
    }
    pub fn cwd(&self) -> Option<String> {
        self.lock().cwd.clone()
    }
    pub fn sizes(&self) -> Vec<PtySize> {
        self.lock().sizes.clone()
    }
    /// The workload started (its preamble arrived complete).
    pub fn started(&self) -> bool {
        self.lock().secret.is_some()
    }
    /// Preamble bytes received while it is incomplete.
    pub fn partial_preamble(&self) -> usize {
        self.lock().preamble.len()
    }
    /// Every stdin byte the workload consumed so far.
    pub fn stdin(&self) -> Vec<u8> {
        self.lock().stdin.clone()
    }
    pub fn stdin_closed(&self) -> bool {
        self.lock().stdin_closed
    }
    pub fn signals(&self) -> Vec<ProcessSignal> {
        self.lock().signals.clone()
    }
    pub fn closes(&self) -> Vec<ChannelClose> {
        self.lock().closes.clone()
    }
    pub fn ended(&self) -> Option<ChannelEnd> {
        self.lock().ended
    }
    /// Chunks of `stream` the owner has not read yet.
    pub fn queued(&self, stream: ChannelOutput) -> usize {
        self.lock().streams[stream as usize].len()
    }
    /// The host client exits on its own (after an unproven kill).
    pub fn exit_client(&self) {
        self.lock().client_exited = true;
    }
    /// How often the custody terminated the client after a later proof.
    pub fn terminations(&self) -> usize {
        self.lock().terminations
    }
    /// Stop echoing stdin (scripted output only).
    pub fn set_echo(&self, echo: bool) {
        self.lock().echo = echo;
    }
    /// Stop consuming stdin: queued bytes stay unread (back-pressure).
    pub fn hold_stdin(&self, hold: bool) {
        let mut state = self.lock();
        state.hold_stdin = hold;
        state.consume();
    }
    /// The host side refuses input until set (pty: the host tty is not raw).
    pub fn set_input_ready(&self, ready: bool) {
        self.lock().input_ready = ready;
    }
    pub fn set_signal_support(&self, supported: bool) {
        self.lock().signal_support = supported;
    }
    /// Each group signal blocks the custody this long.
    pub fn set_signal_delay(&self, delay: Duration) {
        self.lock().signal_delay = delay;
    }
    pub fn make_kill_uncertain(&self) {
        self.lock().kill_uncertain = true;
    }
    pub fn set_normal_close_delay(&self, delay: Duration) {
        self.lock().normal_close_delay = delay;
    }
    pub fn make_unreaped(&self) {
        self.lock().unreaped = true;
    }
    /// The fake host client is reaped from now on.
    pub fn reap(&self) {
        self.lock().unreaped = false;
    }
    /// A later scope kill succeeds.
    pub fn settle_kill(&self) {
        self.lock().kill_uncertain = false;
    }
    /// Workload output (raw: a pty's frames share the stream).
    pub fn emit(&self, stream: ChannelOutput, bytes: &[u8]) {
        self.lock().push(stream as usize, bytes);
    }
    /// Join every unread chunk of `stream` into one (one guest read that
    /// carries several frames, as a real pty read can).
    pub fn coalesce(&self, stream: ChannelOutput) {
        let mut state = self.lock();
        let queue = &mut state.streams[stream as usize];
        let joined: Vec<u8> = queue.drain(..).flatten().collect();
        if !joined.is_empty() {
            queue.push_back(joined);
        }
    }
    /// The guest closes one output stream.
    pub fn eof(&self, stream: ChannelOutput) {
        self.lock().closed[stream as usize] = true;
    }
    /// The workload exits (after every scripted output so far) and its
    /// streams end.
    pub fn exit(&self, status: ChannelExitStatus) {
        self.lock().exit_with(status, true);
    }
    /// The workload exits but a detached survivor keeps the streams open.
    pub fn exit_holding(&self, status: ChannelExitStatus) {
        self.lock().exit_with(status, false);
    }
    /// The launcher dies before the prompt: the frame stream ends (with a
    /// `REFUSED` frame when `refused`).
    pub fn fail_setup(&self, refused: bool) {
        let mut state = self.lock();
        let stream = state.frame_stream();
        if refused {
            let nonce = state.nonce.clone();
            state.streams[stream].clear();
            state.push(stream, &guest_frame_bytes(&nonce, "REFUSED scope"));
        } else {
            state.streams[stream].clear();
        }
        state.closed = [true, true];
    }
}

pub(super) struct FakeChannelIo {
    control: FakeChannelControl,
}

pub(super) struct FakeChannelCustody {
    control: FakeChannelControl,
}

pub(super) struct FakeOpen<'a> {
    pub mode: &'a ChannelMode,
    pub nonce: &'a str,
    pub argv: Option<Vec<String>>,
    pub login: bool,
    pub cwd: Option<String>,
    pub pid: u32,
    /// Fail before the prompt (`Some(true)`: the launcher refused).
    pub fail_setup: Option<bool>,
}

pub(super) fn open(open: FakeOpen<'_>) -> (FakeChannelControl, FakeChannelIo, FakeChannelCustody) {
    let (pty, sizes) = match open.mode {
        ChannelMode::Pty { size, .. } => (true, vec![*size]),
        ChannelMode::Exec => (false, Vec::new()),
    };
    let control = FakeChannelControl {
        state: Arc::new(Mutex::new(State {
            pty,
            nonce: open.nonce.to_string(),
            argv: open.argv,
            login: open.login,
            cwd: open.cwd,
            sizes,
            pid: open.pid,
            streams: [VecDeque::new(), VecDeque::new()],
            closed: [false, false],
            preamble: Vec::new(),
            env: None,
            secret: None,
            stdin: Vec::new(),
            pending_stdin: VecDeque::new(),
            stdin_closed: false,
            hold_stdin: false,
            input_ready: true,
            signals: Vec::new(),
            signal_support: true,
            signal_delay: Duration::ZERO,
            echo: true,
            exit: None,
            closes: Vec::new(),
            kill_uncertain: false,
            unreaped: false,
            normal_close_delay: Duration::ZERO,
            ended: None,
            terminations: 0,
            client_exited: false,
        })),
    };
    {
        let mut state = control.lock();
        let stream = state.frame_stream();
        let nonce = state.nonce.clone();
        state.push(stream, b"agent chatter ");
        state.push(stream, &guest_frame_bytes(&nonce, "PROMPT"));
    }
    if let Some(refused) = open.fail_setup {
        control.fail_setup(refused);
    }
    (
        control.clone(),
        FakeChannelIo {
            control: control.clone(),
        },
        FakeChannelCustody { control },
    )
}

impl ChannelIo for FakeChannelIo {
    fn try_read(&mut self, stream: ChannelOutput) -> ChannelRead {
        let mut state = self.control.lock();
        let index = stream as usize;
        if state.pty && index == 1 {
            return ChannelRead::Eof;
        }
        let max = if state.pty {
            CHANNEL_PTY_READ_BYTES
        } else {
            CHANNEL_EXEC_READ_BYTES
        };
        let queue = &mut state.streams[index];
        let Some(chunk) = queue.front_mut() else {
            return if state.closed[index] || state.ended.is_some() {
                ChannelRead::Eof
            } else {
                ChannelRead::WouldBlock
            };
        };
        if chunk.len() > max {
            let rest = chunk.split_off(max);
            let head = std::mem::replace(chunk, rest);
            return ChannelRead::Data(head);
        }
        let chunk = queue.pop_front().unwrap_or_default();
        ChannelRead::Data(chunk)
    }

    fn try_write(&mut self, bytes: Vec<u8>) -> Result<(), WriteRefused> {
        let mut state = self.control.lock();
        if state.ended.is_some() || state.exit.is_some() || state.stdin_closed {
            return Err(WriteRefused {
                bytes,
                closed: true,
            });
        }
        if state.secret.is_none() {
            state.take_preamble(&bytes);
            return Ok(());
        }
        if state.pending_stdin.len() >= FAKE_STDIN_CAPACITY {
            return Err(WriteRefused {
                bytes,
                closed: false,
            });
        }
        if !bytes.is_empty() {
            state.pending_stdin.push_back(bytes);
        }
        state.consume();
        Ok(())
    }

    fn close_stdin(&mut self) -> bool {
        let mut state = self.control.lock();
        if state.stdin_closed || state.pty {
            return true;
        }
        state.stdin_closed = true;
        state.consume();
        if state.echo && state.pending_stdin.is_empty() {
            state.exit_with(ChannelExitStatus::Code(0), true);
        }
        true
    }

    fn resize(&mut self, size: PtySize) -> Result<(), RuntimeError> {
        let mut state = self.control.lock();
        if !state.pty {
            return Err(RuntimeError::new(
                SandboxErrorCode::ProtocolError,
                "exec channels have no terminal",
            ));
        }
        state.sizes.push(size);
        Ok(())
    }

    fn input_ready(&mut self) -> bool {
        self.control.lock().input_ready
    }
}

impl ChannelCustody for FakeChannelCustody {
    fn signal(&mut self, _birth: &ChannelBirth, signal: ProcessSignal) -> ChannelSignalOutcome {
        let delay = self.control.lock().signal_delay;
        if !delay.is_zero() {
            std::thread::sleep(delay);
        }
        let mut state = self.control.lock();
        if state.pty {
            return ChannelSignalOutcome::Unsupported;
        }
        if state.ended.is_some() || state.exit.is_some() || signal.is_kill() {
            return ChannelSignalOutcome::Ended;
        }
        if !state.signal_support {
            return ChannelSignalOutcome::Unsupported;
        }
        state.signals.push(signal);
        let number = match signal {
            ProcessSignal::Sighup => 1,
            ProcessSignal::Sigint => 2,
            ProcessSignal::Sigterm => 15,
            ProcessSignal::Sigkill => 9,
        };
        state.exit_with(ChannelExitStatus::Signal(number), true);
        ChannelSignalOutcome::Delivered
    }

    fn close(&mut self, how: ChannelClose) -> ChannelEnd {
        let delay = {
            let mut state = self.control.lock();
            state.closes.push(how.clone());
            state.normal_close_delay
        };
        if !how.is_kill() && !delay.is_zero() {
            std::thread::sleep(delay);
        }
        let mut state = self.control.lock();
        let scope = match how {
            ChannelClose::Kill { .. } if state.kill_uncertain => ChannelScope::Uncertain,
            ChannelClose::Kill { .. } => ChannelScope::Killed,
            _ => ChannelScope::Released,
        };
        // An unproven kill leaves the host client (and the streams) alone.
        let end = ChannelEnd {
            reaped: !state.unreaped && scope != ChannelScope::Uncertain,
            scope,
        };
        state.ended = Some(end);
        if scope != ChannelScope::Uncertain {
            state.closed = [true, true];
        }
        end
    }

    fn terminate(&mut self) -> bool {
        let mut state = self.control.lock();
        state.terminations += 1;
        state.closed = [true, true];
        let reaped = !state.unreaped;
        if let Some(end) = &mut state.ended {
            end.reaped = reaped;
        }
        reaped
    }

    fn reap_confirmed(&mut self) -> bool {
        let mut state = self.control.lock();
        // After an unproven kill the client runs until `terminate`.
        let running = state
            .ended
            .is_some_and(|end| end.scope == ChannelScope::Uncertain)
            && state.terminations == 0
            && !state.client_exited;
        if state.unreaped || running {
            return false;
        }
        if let Some(end) = &mut state.ended {
            end.reaped = true;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preamble_round_trips_through_the_fake_guest() {
        let env = vec![("A".to_string(), "b c".to_string())];
        let secret = "0123456789abcdef0123456789abcdef";
        let bytes = crate::channel_preamble(&env, secret).unwrap();
        let (parsed, got, used) = parse_preamble(&bytes).unwrap();
        assert_eq!(parsed, env);
        assert_eq!(got, secret);
        assert_eq!(used, bytes.len());
        assert!(parse_preamble(&bytes[..bytes.len() - 1]).is_none());
    }
}
