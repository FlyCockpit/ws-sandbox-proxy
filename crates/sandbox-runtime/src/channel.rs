//! CLI channels (wssp-ssh): one guest process per channel, started inside its
//! own guest systemd scope, as the guest user, with an exact argv.
//!
//! - `pty` channels run the workload on a guest tty.
//! - `exec` channels run it with piped stdin/stdout/stderr, stdin EOF,
//!   signals and an exit status.
//! - `tcp` and `unix` channels (relay channels) run no workload: the guest
//!   helper itself, as the guest user, connects to a guest loopback port
//!   (`127.0.0.1`, then `[::1]`) or a guest Unix socket and relays one byte
//!   stream each way. Its stdout is framed ([`RelayDecoder`]), so the guest
//!   service's write shutdown travels as an EOF while the other direction
//!   stays open; stdin is raw and its EOF becomes `shutdown(SHUT_WR)`. The
//!   connection goes over `incus exec` (vsock): no guest network path, no
//!   ACL rule, no listener.
//!
//! A spawned channel has two halves with separate owners:
//!
//! - [`ChannelIo`] is the byte IO and nothing else. Every call is
//!   non-blocking: a read takes at most one chunk that is already there, a
//!   write hands over one chunk only when the previous one is written. The
//!   relay's socket thread owns it and is the only party that decides what
//!   crosses the channel and when it closes; dropping it ends the IO.
//! - [`ChannelCustody`] holds the host client process and the guest scope's
//!   kill authority. Its calls block (bounded) and decide nothing: the caller
//!   says how to close.
//!
//! Every launch goes through the guest channel helper: guest root creates the
//! scope `wssp.slice/wssp-chan-<connection>.<channel>.scope`, checks the
//! cancel tombstone inside it and drops to the guest user. The wrapper then
//! prompts (`PROMPT`, bound to the public nonce) and waits for its preamble:
//! the private environment and the frame secret, written by the IO owner
//! with [`channel_preamble`]. Its last byte is the go: before it nothing of
//! the workload runs, and a close before it leaves the helper with a
//! truncated preamble (it exits without a workload). After it the wrapper
//! reports a secret-bound `READY` birth record and the workload's `EXIT`
//! status in band. There is no unscoped fallback.
//!
//! Close modes follow sshd: a normal close hangs the session up (processes
//! that detached themselves survive); a kill close tombstones and kills the
//! whole scope and proves it gone before the channel's capacity is released.

use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use sandbox_protocol::SandboxErrorCode;

use crate::error::RuntimeError;
use crate::{GuestIdentity, ProcessSignal, PtySize};

/// Ids that name a guest scope: `[A-Za-z0-9][A-Za-z0-9_-]{0,63}`.
pub const CHANNEL_ID_MAX_BYTES: usize = 64;
/// The argv of one channel: items and total bytes.
pub const CHANNEL_ARGV_MAX_ITEMS: usize = 4096;
pub const CHANNEL_ARGV_MAX_BYTES: usize = 64 * 1024;
/// A terminal type name (`TERM`).
pub const CHANNEL_TERM_MAX_BYTES: usize = 64;
/// Longest in-band frame the guest helper writes.
pub const CHANNEL_FRAME_MAX_BYTES: usize = 512;
/// One read of an exec stream. A filtered stream (stderr) can release up to
/// one held frame prefix with it, so a read plus the filter's holdback always
/// fits one 32 KiB data frame.
pub const CHANNEL_EXEC_READ_BYTES: usize = 32 * 1024 - CHANNEL_FRAME_MAX_BYTES;
/// One read of a pty stream (16 KiB frames, filtered).
pub const CHANNEL_PTY_READ_BYTES: usize = 16 * 1024 - CHANNEL_FRAME_MAX_BYTES;
/// Chunks a stream's proxy reader may hold ahead of the IO owner. They are
/// an extension of the kernel pipe: taken only by the owner, in order, and
/// dropped unread with the IO at a close decision.
pub const CHANNEL_READ_AHEAD_CHUNKS: usize = 8;
/// How long the guest wrapper waits for its preamble after `PROMPT`.
pub const CHANNEL_PREAMBLE_BUDGET: Duration = Duration::from_secs(30);

pub fn valid_channel_id(id: &str) -> bool {
    (1..=CHANNEL_ID_MAX_BYTES).contains(&id.len())
        && id.as_bytes()[0].is_ascii_alphanumeric()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub fn valid_term(term: &str) -> bool {
    (1..=CHANNEL_TERM_MAX_BYTES).contains(&term.len())
        && term
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
}

/// A channel nonce: 32 lowercase hex characters from the OS CSPRNG.
pub fn channel_nonce() -> Result<String, RuntimeError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|_| RuntimeError::new(SandboxErrorCode::Internal, "failed to read OS CSPRNG"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn valid_nonce(nonce: &str) -> bool {
    nonce.len() == 32 && nonce.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// The guest scope unit of one channel. Ids never contain `.`, so the pair
/// is encoded unambiguously.
pub fn channel_scope_unit(connection_id: &str, channel_id: &str) -> Result<String, RuntimeError> {
    if !valid_channel_id(connection_id) || !valid_channel_id(channel_id) {
        return Err(RuntimeError::new(
            SandboxErrorCode::ProtocolError,
            "invalid channel id",
        ));
    }
    Ok(format!("wssp-chan-{connection_id}.{channel_id}.scope"))
}

/// Parse a scope unit back (registry entries); refuses every other name.
pub fn validate_channel_scope_unit(unit: &str) -> Result<(), RuntimeError> {
    let valid = unit
        .strip_prefix("wssp-chan-")
        .and_then(|rest| rest.strip_suffix(".scope"))
        .and_then(|rest| rest.split_once('.'))
        .is_some_and(|(connection, channel)| {
            valid_channel_id(connection) && valid_channel_id(channel)
        });
    if valid {
        Ok(())
    } else {
        Err(RuntimeError::new(
            SandboxErrorCode::ProtocolError,
            "invalid channel scope unit",
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelMode {
    /// A guest tty of `size`; `term` becomes the workload's `TERM`.
    Pty { size: PtySize, term: String },
    /// Piped stdin/stdout/stderr.
    Exec,
    /// A relay to guest `127.0.0.1:<port>` (then `[::1]:<port>`).
    Tcp { port: u16 },
    /// A relay to the guest Unix socket at `path` (absolute).
    Unix { path: String },
}

impl ChannelMode {
    /// A relay channel (`tcp`/`unix`): no workload, framed stdout.
    pub fn is_relay(&self) -> bool {
        matches!(self, Self::Tcp { .. } | Self::Unix { .. })
    }
}

/// Longest guest Unix socket path (`sun_path` holds 108 bytes with its NUL).
pub const CHANNEL_UNIX_PATH_MAX_BYTES: usize = 107;

/// Spawn one channel process. Like [`crate::OpenPtyRequest`] there is no
/// instance name: it derives from `sandbox_id` and is positively bound before
/// spawn. `guest` comes from the journal lease, never from the client. The
/// request carries no secret and no environment: those travel only in the
/// preamble the IO owner writes.
#[derive(Debug, Clone)]
pub struct SpawnChannelRequest {
    pub template_fingerprint: String,
    pub sandbox_id: String,
    pub connection_id: String,
    pub channel_id: String,
    pub guest: GuestIdentity,
    pub mode: ChannelMode,
    /// `None`: the guest shell (`login` makes it a login shell).
    pub argv: Option<Vec<String>>,
    pub login: bool,
    /// `None` is the guest home.
    pub cwd: Option<String>,
    /// The public nonce (`PROMPT`, `REFUSED`; visible in the guest's argv).
    pub nonce: String,
}

impl SpawnChannelRequest {
    pub fn scope_unit(&self) -> Result<String, RuntimeError> {
        channel_scope_unit(&self.connection_id, &self.channel_id)
    }

    /// Structural checks shared by every runtime.
    pub fn validate(&self) -> Result<(), RuntimeError> {
        let invalid = |what: &str| {
            RuntimeError::new(
                SandboxErrorCode::ProtocolError,
                format!("invalid channel request: {what}"),
            )
        };
        self.scope_unit()?;
        if !valid_nonce(&self.nonce) {
            return Err(invalid("nonce"));
        }
        if let Some(argv) = &self.argv {
            let bytes: usize = argv.iter().map(String::len).sum();
            if argv.is_empty()
                || argv.len() > CHANNEL_ARGV_MAX_ITEMS
                || bytes > CHANNEL_ARGV_MAX_BYTES
                || argv.iter().any(|item| item.contains('\0'))
            {
                return Err(invalid("argv"));
            }
        }
        match &self.mode {
            ChannelMode::Pty { term, .. } if !valid_term(term) => return Err(invalid("term")),
            ChannelMode::Tcp { port } if *port == 0 => return Err(invalid("port")),
            ChannelMode::Unix { path }
                if !path.starts_with('/')
                    || path.len() > CHANNEL_UNIX_PATH_MAX_BYTES
                    || path.contains('\0') =>
            {
                return Err(invalid("path"));
            }
            _ => {}
        }
        // A relay runs no workload: nothing of a process travels with it.
        if self.mode.is_relay() && (self.argv.is_some() || self.cwd.is_some() || self.login) {
            return Err(invalid("relay channels carry only their target"));
        }
        if let Some(cwd) = &self.cwd
            && (!cwd.starts_with('/') || cwd.contains('\0') || cwd.len() > 4096)
        {
            return Err(invalid("cwd"));
        }
        self.guest.validate()?;
        crate::resolve_managed_instance_name(&self.sandbox_id, None)?;
        Ok(())
    }
}

/// The preamble the IO owner writes after the guest's `PROMPT`:
/// `<8 hex>:<base64 canonical env JSON>` (length 0 without env), then the
/// 32-character frame secret and a newline. The newline is the go.
pub fn channel_preamble(env: &[(String, String)], secret: &str) -> Result<Vec<u8>, RuntimeError> {
    let invalid = || RuntimeError::new(SandboxErrorCode::ProtocolError, "channel setup failed");
    if !valid_nonce(secret) {
        return Err(invalid());
    }
    sandbox_protocol::validate_env(env)
        .map_err(|(code, _)| RuntimeError::new(code, "channel setup failed"))?;
    if env
        .iter()
        .any(|(key, _)| matches!(key.as_str(), "HOME" | "SHELL" | "TERM"))
    {
        return Err(invalid());
    }
    let body = if env.is_empty() {
        Vec::new()
    } else {
        let json = sandbox_protocol::canonical_env_json(env)
            .map_err(|(code, _)| RuntimeError::new(code, "channel setup failed"))?;
        base64(&json)
    };
    let mut out = format!("{:08x}:", body.len()).into_bytes();
    out.extend(body);
    out.extend_from_slice(secret.as_bytes());
    out.push(b'\n');
    Ok(out)
}

fn base64(bytes: &[u8]) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let a = usize::from(chunk[0]);
        let b = usize::from(chunk.get(1).copied().unwrap_or_default());
        let c = usize::from(chunk.get(2).copied().unwrap_or_default());
        out.push(ALPHABET[a >> 2]);
        out.push(ALPHABET[((a & 3) << 4) | (b >> 4)]);
        out.push(if chunk.len() > 1 {
            ALPHABET[((b & 15) << 2) | (c >> 6)]
        } else {
            b'='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[c & 63]
        } else {
            b'='
        });
    }
    out
}

/// The guest-attested start of the channel's wrapper (session and process
/// group leader of an exec channel). Signals target exactly this incarnation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelBirth {
    pub pid: u32,
    pub boot_id: String,
    pub start_ticks: u64,
    pub uid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelOutput {
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelExitStatus {
    Code(i32),
    Signal(u8),
    /// No guest-attested outcome (the wrapper died without its EXIT frame).
    Unknown,
}

/// What happened to the channel's guest scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelScope {
    /// Normal end or close: the scope keeps whatever detached itself.
    Released,
    /// A kill close proved the scope gone.
    Killed,
    /// A kill close could not prove the scope gone; capacity stays charged.
    Uncertain,
}

/// The host side of a closed channel. The exit status is not part of it: the
/// IO owner reads the guest's frames and decides it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelEnd {
    /// The host-side `incus exec` client is reaped.
    pub reaped: bool,
    pub scope: ChannelScope,
}

impl ChannelEnd {
    /// Capacity may be released.
    pub fn settled(&self) -> bool {
        self.reaped && self.scope != ChannelScope::Uncertain
    }
}

/// How the custody closes the channel (the caller decided which).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelClose {
    /// The workload already ended (its EXIT was read, or both streams ended):
    /// terminate and reap the host client.
    Finish,
    /// sshd close: hang the session up (exec: `SIGHUP` to the wrapper's
    /// process group, verified by its birth record), give it a bounded
    /// moment, then terminate and reap the host client.
    Hangup(Option<ChannelBirth>),
    /// Tombstone, kill and prove the scope gone, then terminate and reap the
    /// host client. `forget` drops the tombstone after the proof (READY was
    /// seen, so no delayed launcher can still be on its way).
    Kill { forget: bool },
}

impl ChannelClose {
    pub fn is_kill(&self) -> bool {
        matches!(self, Self::Kill { .. })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelSignalOutcome {
    Delivered,
    /// Group signals are not available in this guest; nothing was sent.
    Unsupported,
    /// The wrapper is gone.
    Ended,
}

/// Outcome of one scope in a kill batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeKill {
    Gone,
    Present,
}

/// One scope to kill (durable-registry sweep). `forget` lets the helper drop
/// the cancel tombstone after the proof (READY was seen for this scope).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelScopeRef {
    pub unit: String,
    pub forget: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KillScopesRequest {
    pub sandbox_id: String,
    pub template_fingerprint: String,
    pub guest: GuestIdentity,
    pub scopes: Vec<ChannelScopeRef>,
}

/// One non-blocking read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelRead {
    Data(Vec<u8>),
    /// Nothing to take right now.
    WouldBlock,
    /// The stream ended (repeats).
    Eof,
}

/// A refused write hands the chunk back.
#[derive(Debug, PartialEq, Eq)]
pub struct WriteRefused {
    pub bytes: Vec<u8>,
    /// Stdin is gone for good (otherwise: the previous chunk is still being
    /// written; try again later).
    pub closed: bool,
}

/// Byte IO of one channel. Every call is non-blocking; no call decides
/// anything. Dropping it ends the IO (stdin stays open until the custody
/// closed the process, so no EOF reaches the guest ahead of a kill).
pub trait ChannelIo: Send {
    /// Take one chunk of `stream` (a pty has only `Stdout`). A chunk is at
    /// most [`CHANNEL_EXEC_READ_BYTES`] / [`CHANNEL_PTY_READ_BYTES`].
    fn try_read(&mut self, stream: ChannelOutput) -> ChannelRead;
    /// Hand `bytes` (one whole chunk) to the guest's stdin. Accepted only
    /// when the previous chunk is fully written.
    fn try_write(&mut self, bytes: Vec<u8>) -> Result<(), WriteRefused>;
    /// Stdin EOF once the accepted chunks are written (exec). `false`: try
    /// again later. A pty has no half-close (returns `true`, does nothing).
    fn close_stdin(&mut self) -> bool;
    fn resize(&mut self, size: PtySize) -> Result<(), RuntimeError>;
    /// The host side is ready for input (pty: the host tty is raw, so
    /// nothing is echoed or interpreted on the way in).
    fn input_ready(&mut self) -> bool;
}

/// The process side of one channel. Calls block (bounded); none decides.
pub trait ChannelCustody: Send {
    fn signal(&mut self, birth: &ChannelBirth, signal: ProcessSignal) -> ChannelSignalOutcome;
    /// Close as told. Called once. A kill that cannot prove the scope gone
    /// leaves the host client running and stdin open (an EOF could still
    /// reach a live workload); [`ChannelCustody::terminate`] ends them after
    /// a later proof.
    fn close(&mut self, how: ChannelClose) -> ChannelEnd;
    /// End and reap the host client and release stdin (after a later scope
    /// kill proved the scope gone). Bounded; `true` once reaped.
    fn terminate(&mut self) -> bool;
    /// One non-blocking reconciliation attempt for an unreaped client.
    fn reap_confirmed(&mut self) -> bool;
}

pub struct SpawnedChannel {
    pub io: Box<dyn ChannelIo>,
    pub custody: Box<dyn ChannelCustody>,
}

impl std::fmt::Debug for SpawnedChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SpawnedChannel")
    }
}

/// A failed spawn. `custody` retains a process that was started (its kill
/// close tombstones and kills the scope).
pub struct ChannelOpenFailure {
    pub error: RuntimeError,
    pub custody: Option<Box<dyn ChannelCustody>>,
}

impl std::fmt::Debug for ChannelOpenFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelOpenFailure")
            .field("error", &self.error)
            .field("custody", &self.custody.is_some())
            .finish()
    }
}

impl From<RuntimeError> for ChannelOpenFailure {
    fn from(error: RuntimeError) -> Self {
        Self {
            error,
            custody: None,
        }
    }
}

/// Guest-reported frames, parsed from the tty (pty) or stderr (exec).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestFrame {
    /// The wrapper waits for its preamble (public nonce).
    Prompt,
    /// The launcher refused (no usable scope; public nonce).
    Refused,
    /// The workload started (secret).
    Ready(ChannelBirth),
    /// The workload ended (secret).
    Exit(ChannelExitStatus),
    /// A relay channel's helper could not connect to its target (secret,
    /// before READY). The helper exits on its own after it.
    Failed(RelayFailure),
}

/// Why a relay helper could not connect (constant labels, never guest data).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayFailure {
    /// Nothing listens there (`ECONNREFUSED`; a Unix path that does not
    /// exist).
    Refused,
    /// The guest user may not connect there (`EACCES`, `EPERM`).
    Denied,
    /// Any other failure (a timeout, not a socket, …).
    Failed,
}

const FRAME_PREFIX: &[u8] = b"\x1eWSSP_CHAN ";

/// Strips the wrapper's frames `\x1eWSSP_CHAN <nonce> ...\x1f` from a byte
/// stream, chunk-boundary safe.
///
/// - Before READY, every byte is withheld and dropped (setup chatter is never
///   workload output); only PROMPT/REFUSED (public nonce) and READY (secret)
///   count there.
/// - READY and EXIT carry the secret, which the workload never sees (it
///   travels in the preamble on the wrapper's stdin). The first READY and the
///   first EXIT latch; later frames pass through as data.
/// - A partial frame is held back at most [`CHANNEL_FRAME_MAX_BYTES`].
#[derive(Debug)]
pub struct FrameFilter {
    public: String,
    secret: String,
    held: Vec<u8>,
    prompted: bool,
    ready: bool,
    exited: bool,
}

impl FrameFilter {
    pub fn new(public: &str, secret: &str) -> Self {
        Self {
            public: public.to_string(),
            secret: secret.to_string(),
            held: Vec::new(),
            prompted: false,
            ready: false,
            exited: false,
        }
    }

    pub fn ready(&self) -> bool {
        self.ready
    }

    /// Feed bytes; returns the data bytes to forward and the frames found.
    /// The data is at most `bytes.len()` plus one held prefix (< 512 bytes).
    pub fn feed(&mut self, bytes: &[u8]) -> (Vec<u8>, Vec<GuestFrame>) {
        self.held.extend_from_slice(bytes);
        let mut data = Vec::new();
        let mut frames = Vec::new();
        loop {
            let Some(start) = self.held.iter().position(|b| *b == FRAME_PREFIX[0]) else {
                self.emit(&mut data, self.held.len());
                break;
            };
            self.emit(&mut data, start);
            // `held` now starts with \x1e.
            let candidate = &self.held[..self.held.len().min(FRAME_PREFIX.len())];
            if !FRAME_PREFIX.starts_with(candidate) {
                self.emit(&mut data, 1);
                continue;
            }
            if self.held.len() < FRAME_PREFIX.len() {
                break; // possible frame prefix: hold
            }
            match self.held.iter().position(|b| *b == 0x1f) {
                Some(end) if end < CHANNEL_FRAME_MAX_BYTES => {
                    let body = self.held[FRAME_PREFIX.len()..end].to_vec();
                    match self.accept(&body) {
                        Some(frame) => {
                            frames.push(frame);
                            self.held.drain(..=end);
                        }
                        None => self.emit(&mut data, end + 1),
                    }
                }
                Some(_) => self.emit(&mut data, 1),
                None if self.held.len() >= CHANNEL_FRAME_MAX_BYTES => self.emit(&mut data, 1),
                None => break,
            }
        }
        (data, frames)
    }

    /// End of stream: flush a held partial prefix as data (after READY).
    pub fn finish(&mut self) -> Vec<u8> {
        let mut data = Vec::new();
        let len = self.held.len();
        self.emit(&mut data, len);
        data
    }

    fn emit(&mut self, data: &mut Vec<u8>, n: usize) {
        let taken = self.held.drain(..n);
        if self.ready {
            data.extend(taken);
        }
    }

    fn accept(&mut self, body: &[u8]) -> Option<GuestFrame> {
        let text = std::str::from_utf8(body).ok()?;
        let fields: Vec<&str> = text.split(' ').collect();
        let (nonce, rest) = fields.split_first()?;
        let public = *nonce == self.public;
        let secret = *nonce == self.secret;
        match rest {
            ["PROMPT"] if public && !self.prompted && !self.ready => {
                self.prompted = true;
                Some(GuestFrame::Prompt)
            }
            ["REFUSED", _] if public && !self.ready => Some(GuestFrame::Refused),
            ["READY", pid, boot, ticks, uid] if secret && !self.ready => {
                let birth = ChannelBirth {
                    pid: pid.parse().ok().filter(|pid| *pid > 1)?,
                    boot_id: valid_boot(boot)?,
                    start_ticks: ticks.parse().ok()?,
                    uid: uid.parse().ok()?,
                };
                self.ready = true;
                Some(GuestFrame::Ready(birth))
            }
            ["FAILED", code] if secret && !self.ready && !self.exited => {
                let failure = match *code {
                    "refused" => RelayFailure::Refused,
                    "denied" => RelayFailure::Denied,
                    "failed" => RelayFailure::Failed,
                    _ => return None,
                };
                self.exited = true;
                Some(GuestFrame::Failed(failure))
            }
            ["EXIT", kind, value] if secret && self.ready && !self.exited => {
                let status = match *kind {
                    "code" => ChannelExitStatus::Code(value.parse().ok()?),
                    "signal" => ChannelExitStatus::Signal(
                        value.parse().ok().filter(|sig| (1..=64).contains(sig))?,
                    ),
                    _ => return None,
                };
                self.exited = true;
                Some(GuestFrame::Exit(status))
            }
            _ => None,
        }
    }
}

fn valid_boot(boot: &str) -> Option<String> {
    ((1..=64).contains(&boot.len()) && boot.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'))
        .then(|| boot.to_string())
}

/// The wrapper's in-band frame (also used by the fake guest and tests).
pub fn guest_frame_bytes(nonce: &str, fields: &str) -> Vec<u8> {
    format!("\x1eWSSP_CHAN {nonce} {fields}\x1f").into_bytes()
}

// ------------------------------------------------------- relay framing ----

/// Relay stdout tags: data (`D` + u32 big-endian length + bytes), the guest
/// service shut its write side (`E`), the connection failed (`R`).
const RELAY_DATA: u8 = b'D';
const RELAY_EOF: u8 = b'E';
const RELAY_RESET: u8 = b'R';
/// Largest relay data frame the helper writes (and the decoder accepts).
pub const RELAY_DATA_MAX_BYTES: usize = 64 * 1024;

/// How a relay's guest-to-client stream ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayEnd {
    /// The guest service shut its write side (after every byte before it).
    /// Not final: the connection may still fail while input flows
    /// ([`RelayEnd::Reset`] after it).
    Eof,
    /// The connection failed (or the helper died) before a clean end, or
    /// after the guest service's write shutdown.
    Reset,
    /// The stream broke the framing (a helper that is not the fixed one).
    Corrupt,
}

/// Decodes a relay channel's framed stdout, chunk-boundary safe. The data
/// out of one [`RelayDecoder::feed`] is never longer than its input, so a
/// read of at most [`CHANNEL_EXEC_READ_BYTES`] fits one data frame. After
/// the eof only a reset may follow (the connection failed while input still
/// flowed); after a reset nothing: further bytes are [`RelayEnd::Corrupt`].
#[derive(Debug, Default)]
pub struct RelayDecoder {
    /// A partial data header (at most 5 bytes).
    header: Vec<u8>,
    /// Payload bytes still due for the current data frame.
    remaining: usize,
    /// The eof tag was decoded (also when a reset followed it).
    eof: bool,
    end: Option<RelayEnd>,
}

impl RelayDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// The latest end decoded, if any ([`RelayEnd::Eof`] until a reset or a
    /// framing error follows it).
    pub fn end(&self) -> Option<RelayEnd> {
        self.end
    }

    /// The guest service's write shutdown was decoded, also when a reset
    /// followed it (in the same read or later). False once corrupt.
    pub fn eof_seen(&self) -> bool {
        self.eof && self.end != Some(RelayEnd::Corrupt)
    }

    /// Whether the stream ended cleanly so far: the eof and nothing after it.
    pub fn clean(&self) -> bool {
        self.end == Some(RelayEnd::Eof)
    }

    /// Feed stdout bytes: the payload bytes they carry, and the latest end
    /// when one arrives with them (always after that payload; an eof and a
    /// reset in the same bytes report the reset, see [`Self::eof_seen`]).
    pub fn feed(&mut self, mut bytes: &[u8]) -> (Vec<u8>, Option<RelayEnd>) {
        let mut data = Vec::new();
        if bytes.is_empty() {
            return (data, None);
        }
        if let Some(end) = self.end {
            // After the eof only a lone reset; anything else (and anything
            // after a reset): not the fixed helper.
            self.end = Some(if end == RelayEnd::Eof && bytes == [RELAY_RESET] {
                RelayEnd::Reset
            } else {
                RelayEnd::Corrupt
            });
            return (data, self.end);
        }
        while !bytes.is_empty() {
            if self.remaining > 0 {
                let take = self.remaining.min(bytes.len());
                data.extend_from_slice(&bytes[..take]);
                self.remaining -= take;
                bytes = &bytes[take..];
                continue;
            }
            if self.header.is_empty() {
                match bytes[0] {
                    RELAY_DATA => {}
                    RELAY_EOF if bytes.len() == 1 || bytes[1..] == [RELAY_RESET] => {
                        self.eof = true;
                        self.end = Some(if bytes.len() == 1 {
                            RelayEnd::Eof
                        } else {
                            RelayEnd::Reset
                        });
                        return (data, self.end);
                    }
                    RELAY_RESET if bytes.len() == 1 => {
                        self.end = Some(RelayEnd::Reset);
                        return (data, self.end);
                    }
                    // An end tag with bytes after it, or an unknown tag.
                    _ => {
                        self.end = Some(RelayEnd::Corrupt);
                        return (data, self.end);
                    }
                }
            }
            let need = 5 - self.header.len();
            let take = need.min(bytes.len());
            self.header.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.header.len() == 5 {
                let mut length = [0_u8; 4];
                length.copy_from_slice(&self.header[1..5]);
                let length = u32::from_be_bytes(length) as usize;
                self.header.clear();
                if length == 0 || length > RELAY_DATA_MAX_BYTES {
                    self.end = Some(RelayEnd::Corrupt);
                    return (data, self.end);
                }
                self.remaining = length;
            }
        }
        (data, None)
    }

    /// The stdout pipe ended: without an end frame first (the helper died,
    /// or was killed) the stream was reset.
    pub fn finish(&mut self) -> RelayEnd {
        *self.end.get_or_insert(RelayEnd::Reset)
    }
}

/// One relay data frame (the helper's encoding; for the fake guest and
/// tests).
pub fn relay_data_frame(bytes: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + bytes.len());
    frame.push(RELAY_DATA);
    frame.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    frame.extend_from_slice(bytes);
    frame
}

/// The relay end frame for `end` ([`RelayEnd::Eof`] or [`RelayEnd::Reset`]).
pub fn relay_end_frame(end: RelayEnd) -> Vec<u8> {
    match end {
        RelayEnd::Eof => vec![RELAY_EOF],
        RelayEnd::Reset | RelayEnd::Corrupt => vec![RELAY_RESET],
    }
}

// ---------------------------------------------------------- proxy IO ----

/// Message to a stdin proxy thread.
enum StdinMsg {
    Data(Vec<u8>),
    /// Stdin EOF now.
    Close,
}

/// A pty's resize hook (the master stays with the IO owner).
pub(crate) type ResizeHook = Box<dyn FnMut(PtySize) -> Result<(), RuntimeError> + Send>;

/// [`ChannelIo`] over blocking file handles, through decision-free proxy
/// threads (the PTY master from `portable_pty` cannot be made non-blocking
/// without `unsafe`, so exec and pty share this one shape).
///
/// - A reader thread reads ahead at most [`CHANNEL_READ_AHEAD_CHUNKS`]
///   chunks (the one it holds included) and then blocks, so the guest is
///   back-pressured as by a pipe. Only the owner takes chunks, in order, and
///   only when it can send each at once; a close decision drops them unread,
///   exactly like bytes still in the kernel pipe.
/// - The writer thread takes a chunk only while it is idle (rendezvous), so
///   the hand-over is the admission point (like a write into a kernel
///   pipe). After the owner drops the IO, the writer keeps stdin open until
///   `release` fires: the custody fires it once the process is closed, so no
///   EOF (or `portable_pty`'s closing EOT) reaches the guest before a kill.
pub(crate) struct ProxyIo {
    readers: [Option<mpsc::Receiver<Vec<u8>>>; 2],
    writer: Option<mpsc::SyncSender<StdinMsg>>,
    resize: Option<ResizeHook>,
    input_ready: Box<dyn FnMut() -> bool + Send>,
    release: IoRelease,
}

/// The custody's hold on the proxy threads' file handles: after the IO is
/// dropped, every proxy thread keeps its pipe or master end open until the
/// release, so the host client neither sees stdin EOF nor EPIPE on its
/// output before the custody closed the process.
pub(crate) struct IoRelease {
    holds: Vec<mpsc::Sender<()>>,
    /// The writer thread is finished: every chunk handed to it is written (or
    /// failed) and the writer itself is dropped (its destructor included).
    pub(crate) writer_done: Arc<AtomicBool>,
    pub(crate) writer: Arc<WriterProgress>,
}

/// What the stdin writer still has in hand (for draining a blocked tty).
#[derive(Default)]
pub(crate) struct WriterProgress {
    /// Chunks handed over (counted before the hand-over is attempted).
    handed: std::sync::atomic::AtomicU64,
    /// Chunks the writer finished (written or failed).
    finished: std::sync::atomic::AtomicU64,
}

impl WriterProgress {
    /// Nothing handed over is still being written.
    pub(crate) fn idle(&self) -> bool {
        self.finished.load(Ordering::Acquire) >= self.handed.load(Ordering::Acquire)
    }
}

impl IoRelease {
    /// Let every proxy thread close its handle.
    pub(crate) fn release(&mut self) {
        self.holds.clear();
    }
}

impl ProxyIo {
    pub(crate) fn new(
        input_ready: Box<dyn FnMut() -> bool + Send>,
        resize: Option<ResizeHook>,
    ) -> Self {
        Self {
            readers: [None, None],
            writer: None,
            resize,
            input_ready,
            release: IoRelease {
                holds: Vec::new(),
                writer_done: Arc::new(AtomicBool::new(true)),
                writer: Arc::default(),
            },
        }
    }

    /// The custody's release handle (taken once, after wiring).
    pub(crate) fn take_release(&mut self) -> IoRelease {
        IoRelease {
            holds: std::mem::take(&mut self.release.holds),
            writer_done: self.release.writer_done.clone(),
            writer: self.release.writer.clone(),
        }
    }

    pub(crate) fn add_reader(
        &mut self,
        stream: ChannelOutput,
        mut reader: Box<dyn Read + Send>,
        chunk: usize,
    ) -> std::io::Result<()> {
        // The queue plus the one chunk the reader holds while it waits.
        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(CHANNEL_READ_AHEAD_CHUNKS - 1);
        let (hold_tx, hold_rx) = mpsc::channel::<()>();
        std::thread::Builder::new()
            .name("wssp-chan-read".into())
            .spawn(move || {
                let mut buf = vec![0u8; chunk];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => return,
                        Ok(n) => {
                            if tx.send(buf[..n].to_vec()).is_err() {
                                break;
                            }
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(_) => return,
                    }
                }
                // The owner dropped the IO: hold the handle (unread) until the
                // custody closed the process.
                let _ = hold_rx.recv();
                drop(reader);
            })?;
        self.release.holds.push(hold_tx);
        self.readers[stream as usize] = Some(rx);
        Ok(())
    }

    pub(crate) fn set_writer(&mut self, mut writer: Box<dyn Write + Send>) -> std::io::Result<()> {
        let (tx, rx) = mpsc::sync_channel::<StdinMsg>(0);
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let done = Arc::new(AtomicBool::new(false));
        let finished = done.clone();
        self.release.writer_done = done;
        let progress = self.release.writer.clone();
        std::thread::Builder::new()
            .name("wssp-chan-write".into())
            .spawn(move || {
                loop {
                    match rx.recv() {
                        Ok(StdinMsg::Data(bytes)) => {
                            let written = writer.write_all(&bytes).and_then(|()| writer.flush());
                            progress.finished.fetch_add(1, Ordering::AcqRel);
                            if written.is_err() {
                                break;
                            }
                        }
                        Ok(StdinMsg::Close) => {
                            drop(writer);
                            finished.store(true, Ordering::Release);
                            return;
                        }
                        Err(_) => break,
                    }
                }
                // Hold stdin until the custody closed the process.
                let _ = release_rx.recv();
                drop(writer);
                finished.store(true, Ordering::Release);
            })?;
        self.writer = Some(tx);
        self.release.holds.push(release_tx);
        Ok(())
    }
}

impl ChannelIo for ProxyIo {
    fn try_read(&mut self, stream: ChannelOutput) -> ChannelRead {
        let slot = &mut self.readers[stream as usize];
        let Some(rx) = slot else {
            return ChannelRead::Eof;
        };
        match rx.try_recv() {
            Ok(bytes) => ChannelRead::Data(bytes),
            Err(mpsc::TryRecvError::Empty) => ChannelRead::WouldBlock,
            Err(mpsc::TryRecvError::Disconnected) => {
                *slot = None;
                ChannelRead::Eof
            }
        }
    }

    fn try_write(&mut self, bytes: Vec<u8>) -> Result<(), WriteRefused> {
        let Some(tx) = &self.writer else {
            return Err(WriteRefused {
                bytes,
                closed: true,
            });
        };
        // Counted before the hand-over, so a concurrent drain never sees a
        // chunk the writer holds as idle; undone when refused.
        let progress = self.release.writer.clone();
        progress.handed.fetch_add(1, Ordering::AcqRel);
        let result = tx.try_send(StdinMsg::Data(bytes));
        if result.is_err() {
            progress.handed.fetch_sub(1, Ordering::AcqRel);
        }
        match result {
            Ok(()) => Ok(()),
            Err(mpsc::TrySendError::Full(StdinMsg::Data(bytes))) => Err(WriteRefused {
                bytes,
                closed: false,
            }),
            Err(mpsc::TrySendError::Disconnected(StdinMsg::Data(bytes))) => {
                self.writer = None;
                Err(WriteRefused {
                    bytes,
                    closed: true,
                })
            }
            Err(_) => Err(WriteRefused {
                bytes: Vec::new(),
                closed: true,
            }),
        }
    }

    fn close_stdin(&mut self) -> bool {
        if self.resize.is_some() {
            // A tty has no half-close; sshd ignores EOF on pty sessions too.
            return true;
        }
        let Some(tx) = &self.writer else {
            return true;
        };
        match tx.try_send(StdinMsg::Close) {
            Ok(()) | Err(mpsc::TrySendError::Disconnected(_)) => {
                self.writer = None;
                true
            }
            Err(mpsc::TrySendError::Full(_)) => false,
        }
    }

    fn resize(&mut self, size: PtySize) -> Result<(), RuntimeError> {
        match &mut self.resize {
            Some(resize) => resize(size),
            None => Err(RuntimeError::new(
                SandboxErrorCode::ProtocolError,
                "exec channels have no terminal",
            )),
        }
    }

    fn input_ready(&mut self) -> bool {
        (self.input_ready)()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBLIC: &str = "abcdef0123456789abcdef0123456789";
    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    fn ready() -> Vec<u8> {
        guest_frame_bytes(SECRET, "READY 42 0b6a-ff 12345 1000")
    }

    fn run(filter: &mut FrameFilter, chunks: &[&[u8]]) -> (Vec<u8>, Vec<GuestFrame>) {
        let mut data = Vec::new();
        let mut frames = Vec::new();
        for chunk in chunks {
            let (d, f) = filter.feed(chunk);
            data.extend(d);
            frames.extend(f);
        }
        data.extend(filter.finish());
        (data, frames)
    }

    #[test]
    fn scope_units_round_trip_and_refuse_everything_else() {
        let unit = channel_scope_unit("conn1", "ch_2").unwrap();
        assert_eq!(unit, "wssp-chan-conn1.ch_2.scope");
        // Ids with dashes never collide: the separator is not an id byte.
        assert_ne!(
            channel_scope_unit("a-b", "c").unwrap(),
            channel_scope_unit("a", "b-c").unwrap()
        );
        validate_channel_scope_unit(&unit).unwrap();
        for bad in [
            "wssp-chan-.scope",
            "wssp-chan-a.scope",
            "wssp-chan-a-b.scope",
            "wssp-chan-a.b.c.scope",
            "wssp-chan-.b.scope",
            "wssp-cmd-a-1-1.scope",
            "wssp-chan-a.b.service",
            "wssp-chan--a.b.scope",
            "wssp-chan-a.b/../x.scope",
        ] {
            assert!(validate_channel_scope_unit(bad).is_err(), "{bad}");
        }
        assert!(channel_scope_unit(&"a".repeat(65), "b").is_err());
        assert!(channel_scope_unit("a", "-b").is_err());
    }

    #[test]
    fn pre_ready_bytes_are_dropped_and_ready_latches() {
        let mut filter = FrameFilter::new(PUBLIC, SECRET);
        let mut stream = b"agent chatter".to_vec();
        stream.extend(guest_frame_bytes(PUBLIC, "PROMPT"));
        stream.extend(ready());
        stream.extend(b"hello");
        stream.extend(guest_frame_bytes(SECRET, "READY 7 aa 1 1"));
        let (data, frames) = run(&mut filter, &[&stream]);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0], GuestFrame::Prompt);
        assert!(
            matches!(&frames[1], GuestFrame::Ready(b) if b.pid == 42 && b.start_ticks == 12345)
        );
        let mut expected = b"hello".to_vec();
        expected.extend(guest_frame_bytes(SECRET, "READY 7 aa 1 1"));
        assert_eq!(data, expected, "a second READY is data and never rebinds");
    }

    #[test]
    fn ready_and_exit_need_the_secret() {
        let mut filter = FrameFilter::new(PUBLIC, SECRET);
        let (_, frames) = filter.feed(&guest_frame_bytes(PUBLIC, "READY 42 aa 1 1000"));
        assert!(frames.is_empty(), "the public nonce never makes READY");
        let _ = filter.feed(&ready());
        let forged = guest_frame_bytes(PUBLIC, "EXIT code 0");
        let (data, frames) = filter.feed(&forged);
        assert!(frames.is_empty());
        assert_eq!(data, forged, "a public-nonce EXIT is workload data");
        let (_, frames) = filter.feed(&guest_frame_bytes(SECRET, "EXIT code 3"));
        assert_eq!(frames, vec![GuestFrame::Exit(ChannelExitStatus::Code(3))]);
    }

    #[test]
    fn frames_split_at_every_boundary_are_found() {
        let mut stream = ready();
        stream.extend(b"out\x1eput");
        stream.extend(guest_frame_bytes(SECRET, "EXIT code 143"));
        stream.extend(b"tail");
        for split in 0..stream.len() {
            let mut filter = FrameFilter::new(PUBLIC, SECRET);
            let (data, frames) = run(&mut filter, &[&stream[..split], &stream[split..]]);
            assert_eq!(data, b"out\x1eputtail", "split {split}");
            assert_eq!(frames.len(), 2, "split {split}");
            assert_eq!(frames[1], GuestFrame::Exit(ChannelExitStatus::Code(143)));
        }
    }

    #[test]
    fn foreign_nonce_and_unterminated_prefix_pass_through() {
        let mut filter = FrameFilter::new(PUBLIC, SECRET);
        let _ = filter.feed(&ready());
        let other = guest_frame_bytes("ffffffffffffffffffffffffffffffff", "EXIT code 1");
        let (data, frames) = filter.feed(&other);
        assert!(frames.is_empty());
        assert_eq!(data, other);
        let mut open = b"\x1eWSSP_CHAN ".to_vec();
        open.extend(SECRET.as_bytes());
        open.extend(b" EXIT code ");
        open.extend(vec![b'9'; CHANNEL_FRAME_MAX_BYTES]);
        let (data, frames) = run(&mut filter, &[&open]);
        assert!(frames.is_empty());
        assert_eq!(data, open, "an unterminated prefix is released as data");
    }

    #[test]
    fn filtered_output_never_exceeds_one_frame() {
        // A held prefix plus one full read still fits one data frame.
        let mut filter = FrameFilter::new(PUBLIC, SECRET);
        let _ = filter.feed(&ready());
        let mut partial = b"\x1eWSSP_CHAN ".to_vec();
        partial.extend(vec![b'x'; CHANNEL_FRAME_MAX_BYTES - partial.len() - 1]);
        let (data, _) = filter.feed(&partial);
        assert!(data.is_empty());
        let (data, _) = filter.feed(&vec![b'y'; CHANNEL_EXEC_READ_BYTES]);
        assert!(data.len() <= 32 * 1024, "{}", data.len());
        let mut filter = FrameFilter::new(PUBLIC, SECRET);
        let _ = filter.feed(&ready());
        let _ = filter.feed(&partial);
        let (data, _) = filter.feed(&vec![b'y'; CHANNEL_PTY_READ_BYTES]);
        assert!(data.len() <= 16 * 1024, "{}", data.len());
    }

    #[test]
    fn exit_and_refusal_are_parsed_only_in_their_phase() {
        let mut filter = FrameFilter::new(PUBLIC, SECRET);
        let (_, frames) = filter.feed(&guest_frame_bytes(SECRET, "EXIT signal 15"));
        assert!(frames.is_empty(), "EXIT before READY is ignored");
        let (_, frames) = filter.feed(&guest_frame_bytes(PUBLIC, "REFUSED scope"));
        assert_eq!(frames, vec![GuestFrame::Refused]);
        let _ = filter.feed(&ready());
        let (data, frames) = filter.feed(&guest_frame_bytes(PUBLIC, "REFUSED scope"));
        assert!(frames.is_empty());
        assert!(!data.is_empty(), "REFUSED after READY is data");
        let (_, frames) = filter.feed(&guest_frame_bytes(SECRET, "EXIT signal 15"));
        assert_eq!(
            frames,
            vec![GuestFrame::Exit(ChannelExitStatus::Signal(15))]
        );
    }

    #[test]
    fn relay_failures_need_the_secret_and_come_before_ready() {
        let mut filter = FrameFilter::new(PUBLIC, SECRET);
        let (_, frames) = filter.feed(&guest_frame_bytes(PUBLIC, "FAILED refused"));
        assert!(frames.is_empty(), "the public nonce never makes FAILED");
        let (_, frames) = filter.feed(&guest_frame_bytes(SECRET, "FAILED bogus"));
        assert!(frames.is_empty());
        let (_, frames) = filter.feed(&guest_frame_bytes(SECRET, "FAILED denied"));
        assert_eq!(frames, vec![GuestFrame::Failed(RelayFailure::Denied)]);
        let (_, frames) = filter.feed(&guest_frame_bytes(SECRET, "FAILED refused"));
        assert!(frames.is_empty(), "FAILED latches");
        let mut filter = FrameFilter::new(PUBLIC, SECRET);
        let _ = filter.feed(&ready());
        let (_, frames) = filter.feed(&guest_frame_bytes(SECRET, "FAILED refused"));
        assert!(frames.is_empty(), "FAILED after READY is data");
    }

    fn decode(chunks: &[&[u8]]) -> (Vec<u8>, Option<RelayEnd>) {
        let mut decoder = RelayDecoder::new();
        let mut data = Vec::new();
        let mut end = None;
        for chunk in chunks {
            let (d, e) = decoder.feed(chunk);
            data.extend(d);
            if e.is_some() {
                end = e;
            }
        }
        (data, end)
    }

    #[test]
    fn relay_frames_decode_at_every_split_and_eof_never_overtakes_data() {
        let mut stream = relay_data_frame(b"hello ");
        stream.extend(relay_data_frame(b"world"));
        stream.extend(relay_end_frame(RelayEnd::Eof));
        for split in 0..stream.len() {
            let (data, end) = decode(&[&stream[..split], &stream[split..]]);
            assert_eq!(data, b"hello world", "split {split}");
            assert_eq!(end, Some(RelayEnd::Eof), "split {split}");
        }
        // Byte by byte: the end only after the last payload byte.
        let mut decoder = RelayDecoder::new();
        let mut data = Vec::new();
        for (i, byte) in stream.iter().enumerate() {
            let (d, end) = decoder.feed(std::slice::from_ref(byte));
            data.extend(d);
            assert_eq!(end.is_some(), i + 1 == stream.len());
        }
        assert_eq!(data, b"hello world");
    }

    #[test]
    fn relay_output_is_never_longer_than_its_input() {
        let payload = vec![7_u8; RELAY_DATA_MAX_BYTES];
        let stream = relay_data_frame(&payload);
        let mut decoder = RelayDecoder::new();
        for chunk in stream.chunks(CHANNEL_EXEC_READ_BYTES) {
            let (data, end) = decoder.feed(chunk);
            assert!(data.len() <= chunk.len());
            assert!(end.is_none());
        }
    }

    #[test]
    fn broken_relay_streams_are_corrupt_or_reset() {
        assert_eq!(decode(&[b"X"]).1, Some(RelayEnd::Corrupt));
        assert_eq!(decode(&[b"D\0\0\0\0"]).1, Some(RelayEnd::Corrupt));
        let too_long = ((RELAY_DATA_MAX_BYTES + 1) as u32).to_be_bytes();
        assert_eq!(
            decode(&[b"D", &too_long]).1,
            Some(RelayEnd::Corrupt),
            "oversized frame"
        );
        assert_eq!(decode(&[b"E", b"D"]).1, Some(RelayEnd::Corrupt));
        assert_eq!(decode(&[b"ED"]).1, Some(RelayEnd::Corrupt));
        assert_eq!(decode(&[b"E", b"E"]).1, Some(RelayEnd::Corrupt));
        assert_eq!(decode(&[b"ERR"]).1, Some(RelayEnd::Corrupt));
        assert_eq!(decode(&[b"E", b"R", b"R"]).1, Some(RelayEnd::Corrupt));
        assert_eq!(decode(&[b"R", b"E"]).1, Some(RelayEnd::Corrupt));
        assert_eq!(decode(&[b"RE"]).1, Some(RelayEnd::Corrupt));
        let (data, end) = decode(&[&relay_data_frame(b"ab"), b"R"]);
        assert_eq!((data.as_slice(), end), (&b"ab"[..], Some(RelayEnd::Reset)));
        // The pipe ending mid-frame (or with no end frame) is a reset.
        let mut decoder = RelayDecoder::new();
        let _ = decoder.feed(&relay_data_frame(b"abc")[..4]);
        assert_eq!(decoder.finish(), RelayEnd::Reset);
        let mut decoder = RelayDecoder::new();
        let _ = decoder.feed(b"E");
        assert_eq!(decoder.finish(), RelayEnd::Eof);
        assert!(decoder.eof_seen() && decoder.clean());
    }

    #[test]
    fn a_reset_after_the_eof_is_a_reset_at_every_split() {
        let mut stream = relay_data_frame(b"220 ready");
        stream.extend(relay_end_frame(RelayEnd::Eof));
        stream.extend(relay_end_frame(RelayEnd::Reset));
        for split in 0..=stream.len() {
            let mut decoder = RelayDecoder::new();
            let mut data = Vec::new();
            let mut ends = Vec::new();
            for chunk in [&stream[..split], &stream[split..]] {
                let (d, end) = decoder.feed(chunk);
                data.extend(d);
                ends.extend(end);
            }
            assert_eq!(data, b"220 ready", "split {split}");
            assert_eq!(ends.last(), Some(&RelayEnd::Reset), "split {split}");
            assert!(decoder.eof_seen(), "split {split}");
            assert!(!decoder.clean(), "split {split}");
            assert_eq!(decoder.finish(), RelayEnd::Reset, "split {split}");
        }
        // A reset without an eof is no eof; a corrupt stream is neither.
        let mut decoder = RelayDecoder::new();
        let _ = decoder.feed(b"R");
        assert!(!decoder.eof_seen() && !decoder.clean());
        let mut decoder = RelayDecoder::new();
        let _ = decoder.feed(b"ED");
        assert!(!decoder.eof_seen() && !decoder.clean());
        let mut decoder = RelayDecoder::new();
        assert!(!decoder.clean(), "nothing decoded is not clean");
        assert_eq!(decoder.finish(), RelayEnd::Reset);
    }

    #[test]
    fn relay_requests_carry_only_their_target() {
        let base = SpawnChannelRequest {
            template_fingerprint: "sha256:x".into(),
            sandbox_id: "sbx-1".into(),
            connection_id: "c".into(),
            channel_id: "h".into(),
            guest: GuestIdentity {
                guest_uid: 1000,
                guest_gid: 1000,
                guest_home: "/home/user".into(),
                guest_shell: "/bin/sh".into(),
            },
            mode: ChannelMode::Tcp { port: 5432 },
            argv: None,
            login: false,
            cwd: None,
            nonce: PUBLIC.into(),
        };
        base.validate().unwrap();
        for bad in [
            SpawnChannelRequest {
                mode: ChannelMode::Tcp { port: 0 },
                ..base.clone()
            },
            SpawnChannelRequest {
                argv: Some(vec!["nc".into()]),
                ..base.clone()
            },
            SpawnChannelRequest {
                login: true,
                ..base.clone()
            },
            SpawnChannelRequest {
                cwd: Some("/".into()),
                ..base.clone()
            },
            SpawnChannelRequest {
                mode: ChannelMode::Unix {
                    path: "run/x.sock".into(),
                },
                ..base.clone()
            },
            SpawnChannelRequest {
                mode: ChannelMode::Unix {
                    path: format!("/{}", "a".repeat(CHANNEL_UNIX_PATH_MAX_BYTES)),
                },
                ..base.clone()
            },
        ] {
            assert!(bad.validate().is_err(), "{:?}", bad.mode);
        }
        SpawnChannelRequest {
            mode: ChannelMode::Unix {
                path: "/run/app.sock".into(),
            },
            ..base
        }
        .validate()
        .unwrap();
    }

    #[test]
    fn preamble_is_env_then_secret_with_the_newline_last() {
        let preamble = channel_preamble(&[], SECRET).unwrap();
        assert_eq!(preamble, format!("00000000:{SECRET}\n").into_bytes());
        let env = vec![("A".to_string(), "b".to_string())];
        let preamble = channel_preamble(&env, SECRET).unwrap();
        let text = String::from_utf8(preamble).unwrap();
        // {"A":"b"} in base64.
        assert_eq!(text, format!("0000000c:eyJBIjoiYiJ9{SECRET}\n"));
        assert!(channel_preamble(&[("HOME".into(), "/x".into())], SECRET).is_err());
        assert!(channel_preamble(&[], "short").is_err());
    }

    #[test]
    fn proxy_reader_hands_over_one_chunk_at_a_time() {
        let mut io = ProxyIo::new(Box::new(|| true), None);
        io.add_reader(
            ChannelOutput::Stdout,
            Box::new(std::io::Cursor::new(b"abc".to_vec())),
            2,
        )
        .unwrap();
        let mut got = Vec::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match io.try_read(ChannelOutput::Stdout) {
                ChannelRead::Data(bytes) => {
                    assert!(bytes.len() <= 2);
                    got.extend(bytes);
                }
                ChannelRead::WouldBlock => std::thread::sleep(Duration::from_millis(1)),
                ChannelRead::Eof => break,
            }
            assert!(std::time::Instant::now() < deadline);
        }
        assert_eq!(got, b"abc");
        assert_eq!(io.try_read(ChannelOutput::Stderr), ChannelRead::Eof);
    }

    struct Counting(Arc<std::sync::atomic::AtomicUsize>);
    impl Read for Counting {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.0.fetch_add(1, Ordering::SeqCst);
            buf[0] = b'x';
            Ok(1)
        }
    }

    #[test]
    fn proxy_read_ahead_is_exactly_the_documented_bound() {
        let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut io = ProxyIo::new(Box::new(|| true), None);
        io.add_reader(ChannelOutput::Stdout, Box::new(Counting(reads.clone())), 1)
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while reads.load(Ordering::SeqCst) < CHANNEL_READ_AHEAD_CHUNKS {
            assert!(
                std::time::Instant::now() < deadline,
                "the reader never filled up"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(
            reads.load(Ordering::SeqCst),
            CHANNEL_READ_AHEAD_CHUNKS,
            "chunks out of the pipe while the owner reads nothing"
        );
        assert!(matches!(
            io.try_read(ChannelOutput::Stdout),
            ChannelRead::Data(_)
        ));
        drop(io);
    }

    #[derive(Clone, Default)]
    struct Sink(Arc<std::sync::Mutex<(Vec<u8>, bool)>>);
    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().0.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl Drop for Sink {
        fn drop(&mut self) {
            if Arc::strong_count(&self.0) == 2 {
                self.0.lock().unwrap().1 = true;
            }
        }
    }

    #[test]
    fn proxy_stdin_stays_open_after_drop_until_released() {
        let sink = Sink::default();
        let mut io = ProxyIo::new(Box::new(|| true), None);
        io.set_writer(Box::new(sink.clone())).unwrap();
        let mut release = io.take_release();
        let mut chunk = b"hi".to_vec();
        loop {
            match io.try_write(chunk) {
                Ok(()) => break,
                Err(refused) => {
                    assert!(!refused.closed);
                    chunk = refused.bytes;
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
        drop(io);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while sink.0.lock().unwrap().0 != b"hi" {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        std::thread::sleep(Duration::from_millis(20));
        assert!(!sink.0.lock().unwrap().1, "stdin is held until the release");
        assert!(!release.writer_done.load(Ordering::Acquire));
        let done = release.writer_done.clone();
        release.release();
        while !sink.0.lock().unwrap().1 || !done.load(Ordering::Acquire) {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
