//! Guard socket protocol.
//!
//! `/run/wssp-guard/guard.sock` (0666, in the unit's `RuntimeDirectory`).
//! One request per connection: the client writes one frame, the guard
//! answers with one frame and closes. A frame is a 4-byte big-endian length
//! followed by that many bytes of UTF-8 JSON, at most 1 MiB. The whole
//! request must arrive within 2 s; at most 4 connections are served at once
//! (the 5th gets a `busy` error). Every connection is authenticated with
//! `SO_PEERCRED`: `push_deployment` is accepted only from the daemon uid in
//! `/etc/wssp/guard.toml`; `status`, `policy` and `ceiling` from any local
//! uid. `ceiling` answers the egress ceiling of the last healthy pass
//! together with the status of that same publication (`null` while the
//! guard is not healthy), so the reader can apply the lease rule to it.
//!
//! Requests (`op` tag, unknown fields refused):
//!   {"op":"status"}
//!   {"op":"policy"}
//!   {"op":"ceiling"}
//!   {"op":"push_deployment","configured":true,"entries":["203.0.113.0/24","bad.example"]}
//!   {"op":"push_deployment","configured":false}
//! Replies (`result` tag):
//!   {"result":"status","status":{…GuardStatus…}}
//!   {"result":"policy","policy":{"root":{…},"deployment":{…}}}
//!   {"result":"ceiling","status":{…GuardStatus…},"ceiling":{…}|null}
//!   {"result":"pushed","digest":"sha256:…","state":{"state":"valid",…}}
//!   {"result":"error","code":"forbidden","message":"…","line":7}

use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

use super::ceiling::EgressCeiling;
use super::sources::SourceState;
use crate::guard::probe::GuardStatus;

pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
pub const MAX_CONNECTIONS: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    // Struct variants (not unit) so `deny_unknown_fields` also refuses
    // `{"op":"status","extra":…}`.
    Status {},
    Policy {},
    Ceiling {},
    PushDeployment {
        configured: bool,
        #[serde(default)]
        entries: Vec<String>,
    },
}

impl Request {
    /// State-changing requests need the daemon uid.
    pub fn is_write(&self) -> bool {
        matches!(self, Self::PushDeployment { .. })
    }
}

/// One source in the `policy` answer: its state, and the content it
/// currently enforces (its last valid content; empty when it has none).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SourcePolicy {
    pub state: SourceState,
    /// Digest of the enforced (last valid) content, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub cidrs: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PolicyAnswer {
    pub root: SourcePolicy,
    pub deployment: SourcePolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Forbidden,
    InvalidRequest,
    InvalidSource,
    TooLarge,
    Busy,
    Timeout,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Reply {
    Status {
        status: Box<GuardStatus>,
    },
    Policy {
        policy: PolicyAnswer,
    },
    Ceiling {
        status: Box<GuardStatus>,
        ceiling: Option<EgressCeiling>,
    },
    Pushed {
        digest: String,
        state: SourceState,
    },
    Error {
        code: ErrorCode,
        message: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        line: Option<usize>,
    },
}

impl Reply {
    pub fn error(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::Error {
            code,
            message: message.into(),
            line: None,
        }
    }
}

#[derive(Debug)]
pub enum FrameError {
    TooLarge(usize),
    Timeout,
    Closed,
    Io(io::Error),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge(len) => write!(f, "frame of {len} bytes exceeds the limit"),
            Self::Timeout => f.write_str("frame not received in time"),
            Self::Closed => f.write_str("connection closed mid-frame"),
            Self::Io(err) => write!(f, "frame i/o: {err}"),
        }
    }
}

impl std::error::Error for FrameError {}

pub fn write_frame(writer: &mut impl Write, body: &[u8]) -> io::Result<()> {
    let len = u32::try_from(body.len())
        .ok()
        .filter(|len| *len as usize <= MAX_FRAME_BYTES)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
    let mut framed = Vec::with_capacity(4 + body.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(body);
    writer.write_all(&framed)?;
    writer.flush()
}

/// A stream whose per-read timeout can be narrowed to a deadline.
pub trait DeadlineRead: Read {
    fn set_read_deadline(&mut self, remaining: Duration) -> io::Result<()>;
}

#[cfg(unix)]
impl DeadlineRead for std::os::unix::net::UnixStream {
    fn set_read_deadline(&mut self, remaining: Duration) -> io::Result<()> {
        self.set_read_timeout(Some(remaining.max(Duration::from_millis(1))))
    }
}

fn read_exact_by(
    reader: &mut impl DeadlineRead,
    buf: &mut [u8],
    deadline: Instant,
) -> Result<(), FrameError> {
    let mut filled = 0;
    while filled < buf.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(FrameError::Timeout);
        }
        reader
            .set_read_deadline(remaining)
            .map_err(FrameError::Io)?;
        match reader.read(&mut buf[filled..]) {
            Ok(0) => return Err(FrameError::Closed),
            Ok(n) => filled += n,
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(FrameError::Timeout);
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(FrameError::Io(err)),
        }
    }
    Ok(())
}

/// Read one frame that must complete by `deadline` (a slow client cannot
/// hold a connection slot by trickling bytes: the deadline is total, not
/// per read). The length is checked before any body byte is read.
pub fn read_frame(
    reader: &mut impl DeadlineRead,
    max: usize,
    deadline: Instant,
) -> Result<Vec<u8>, FrameError> {
    let mut header = [0u8; 4];
    read_exact_by(reader, &mut header, deadline)?;
    let len = u32::from_be_bytes(header) as usize;
    if len > max {
        return Err(FrameError::TooLarge(len));
    }
    let mut body = vec![0u8; len];
    read_exact_by(reader, &mut body, deadline)?;
    Ok(body)
}

/// Write authority: only the configured daemon uid may change state. A peer
/// whose credentials could not be read may only read.
pub fn authorize(
    request: &Request,
    peer_uid: Option<u32>,
    daemon_uid: u32,
) -> Result<(), Box<Reply>> {
    if request.is_write() && peer_uid != Some(daemon_uid) {
        return Err(Box::new(Reply::error(
            ErrorCode::Forbidden,
            "only the daemon user may change guard policy",
        )));
    }
    Ok(())
}

/// Decode a request frame (strict: unknown ops and fields are refused).
pub fn decode_request(body: &[u8]) -> Result<Request, Box<Reply>> {
    serde_json::from_slice(body).map_err(|_| {
        Box::new(Reply::error(
            ErrorCode::InvalidRequest,
            "malformed guard request",
        ))
    })
}

/// Counts live connections; the permit releases its slot on drop.
#[derive(Debug, Clone)]
pub struct ConnectionLimiter {
    active: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    max: usize,
}

#[derive(Debug)]
pub struct ConnectionPermit(std::sync::Arc<std::sync::atomic::AtomicUsize>);

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

impl ConnectionLimiter {
    pub fn new(max: usize) -> Self {
        Self {
            active: Default::default(),
            max,
        }
    }

    pub fn try_acquire(&self) -> Option<ConnectionPermit> {
        use std::sync::atomic::Ordering;
        let mut current = self.active.load(Ordering::Acquire);
        loop {
            if current >= self.max {
                return None;
            }
            match self.active.compare_exchange(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(ConnectionPermit(self.active.clone())),
                Err(seen) => current = seen,
            }
        }
    }
}

/// Server side of one request. Implemented by the guard daemon.
pub trait Handler: Send + Sync {
    fn handle(&self, request: Request) -> Reply;
}

#[cfg(unix)]
mod server {
    use super::*;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Debug, Clone, Copy)]
    pub struct ServerConfig {
        pub daemon_uid: u32,
        pub max_connections: usize,
        pub request_timeout: Duration,
    }

    impl ServerConfig {
        pub fn new(daemon_uid: u32) -> Self {
            Self {
                daemon_uid,
                max_connections: MAX_CONNECTIONS,
                request_timeout: REQUEST_TIMEOUT,
            }
        }
    }

    fn send(stream: &mut UnixStream, reply: &Reply) {
        if let Ok(body) = serde_json::to_vec(reply) {
            let _ = stream.set_write_timeout(Some(REQUEST_TIMEOUT));
            let _ = write_frame(stream, &body);
        }
    }

    /// Serve exactly one request on an accepted connection.
    pub fn serve_connection(
        mut stream: UnixStream,
        peer_uid: Option<u32>,
        config: ServerConfig,
        handler: &dyn Handler,
    ) {
        let deadline = Instant::now() + config.request_timeout;
        let reply = match read_frame(&mut stream, MAX_FRAME_BYTES, deadline) {
            Err(FrameError::TooLarge(_)) => {
                Reply::error(ErrorCode::TooLarge, "request exceeds 1 MiB")
            }
            Err(FrameError::Timeout) => Reply::error(ErrorCode::Timeout, "request timed out"),
            Err(_) => return,
            Ok(body) => match decode_request(&body).and_then(|request| {
                authorize(&request, peer_uid, config.daemon_uid).map(|()| request)
            }) {
                Ok(request) => handler.handle(request),
                Err(reply) => *reply,
            },
        };
        send(&mut stream, &reply);
    }

    /// Accept loop: one thread per admitted connection, at most
    /// `max_connections` at once; the rest get `busy` and are closed.
    /// Returns when `stop` is set (checked between accepts; the listener
    /// should be non-blocking or woken by a connection).
    pub fn serve(
        listener: &UnixListener,
        peer_uid: &(dyn Fn(&UnixStream) -> io::Result<u32> + Sync),
        config: ServerConfig,
        handler: Arc<dyn Handler>,
        stop: &AtomicBool,
    ) -> io::Result<()> {
        let limiter = ConnectionLimiter::new(config.max_connections);
        for stream in listener.incoming() {
            if stop.load(Ordering::Acquire) {
                return Ok(());
            }
            let mut stream = match stream {
                Ok(stream) => stream,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(err),
            };
            let Some(permit) = limiter.try_acquire() else {
                send(
                    &mut stream,
                    &Reply::error(ErrorCode::Busy, "too many guard connections"),
                );
                continue;
            };
            let uid = peer_uid(&stream).ok();
            let handler = handler.clone();
            std::thread::spawn(move || {
                let _permit = permit;
                serve_connection(stream, uid, config, handler.as_ref());
            });
        }
        Ok(())
    }

    /// Client: one request, one reply, bounded by `timeout` overall.
    pub fn call(
        path: &std::path::Path,
        request: &Request,
        timeout: Duration,
    ) -> Result<Reply, String> {
        let deadline = Instant::now() + timeout;
        let mut stream = UnixStream::connect(path)
            .map_err(|err| format!("cannot connect to `{}`: {}", path.display(), err.kind()))?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|err| err.to_string())?;
        let body = serde_json::to_vec(request).map_err(|err| err.to_string())?;
        write_frame(&mut stream, &body).map_err(|err| format!("guard request: {}", err.kind()))?;
        let reply =
            read_frame(&mut stream, MAX_FRAME_BYTES, deadline).map_err(|e| e.to_string())?;
        serde_json::from_slice(&reply).map_err(|_| "malformed guard reply".to_string())
    }
}

#[cfg(unix)]
pub use server::{ServerConfig, call, serve, serve_connection};

#[cfg(test)]
#[path = "tests/protocol.rs"]
mod tests;
