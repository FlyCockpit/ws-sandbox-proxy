//! The shared client of `GET /v1/sandboxes/{id}/connect` (`wssp.connect.v1`,
//! docs/design/connect-channel-contract.md#client-wire-wsspconnectv1).
//!
//! [`Connection::connect`] upgrades with `Authorization: Bearer <login key>`
//! and `Sec-WebSocket-Protocol: wssp.connect.v1` only: no `Origin`, no
//! cookies, nothing in the query. The transport rules are the `/v1` client's
//! (`src/api.rs`): WSS, or cleartext WS only on loopback; the extra CA trust
//! of `crate::tls`; no redirects; bounded dial and handshake. A refusal
//! before the upgrade is the `/v1` error envelope and maps to the same exit
//! codes as every `/v1` answer (7 for 401, 8 for 403, 3 for 404, 10 for a
//! 409, 11 for 429/503/504), except `sandbox.host_unavailable`, which is
//! retryable (11).
//!
//! After `hello` one socket multiplexes many channels; [`mux::Mux`] keeps
//! their credit and ordering rules and the connection only moves frames.
//! The caller polls ([`Connection::poll`]) from one thread, delivers each
//! output event and reports it ([`Connection::delivered`]); acknowledgements
//! leave at the next [`Connection::flush`], so a delivered frame is never
//! held back. Pings are answered by the WebSocket layer while polling, which
//! is what keeps an idle connection alive (the server ends a connection that
//! sends nothing for 60 s). The other direction is checked too: the server
//! pings every `pingIntervalMs` whatever else it sends, so a connection that
//! brings no frame at all (no ping either) for `max(3 × pingIntervalMs,
//! idleTimeoutMs)` (60 s with the contract's values) is lost, the same as a
//! reset socket. `end{intent}`, a lost socket, a silent server and a
//! protocol violation surface as [`SessionEnded`] (exit 125, `connect.lost`
//! unless an `end` named its intent).

pub mod mux;
pub mod wire;

use std::collections::BTreeMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tungstenite::protocol::Role;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message, WebSocket};

use crate::exit::{CodedError, ExitCode};
use crate::user_state::UserCredential;
use mux::{Event, Mux, Violation};
use wire::{
    ClientControl, DataMetadata, DataStream, Intent, Kind, Limits, PtyParams, ServerControl,
    Signal, WireError,
};

/// Dial bound per address.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound of the TLS and upgrade handshake and of the wait for `hello`.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// A socket write that makes no progress this long fails the session.
const WRITE_STALL: Duration = Duration::from_secs(30);
/// Bound of the closing handshake's writes once the session is over.
const CLOSE_WRITE: Duration = Duration::from_secs(2);
/// How long one [`Connection::poll`] waits for a frame at most.
pub const POLL_SLICE: Duration = Duration::from_millis(10);
/// The wait of [`Connection::poll`] while the caller has work coming that
/// no frame announces (input its other side hands over, a delivery report
/// to acknowledge): that work then waits for at most this, not a whole
/// [`POLL_SLICE`] per turn, which capped a transfer at one turn's frames
/// per slice.
pub const BUSY_POLL_SLICE: Duration = Duration::from_millis(1);
/// How long after its last activity the caller counts as busy, so a short
/// gap in a transfer (a burst boundary, a request and its answer) does not
/// cost a whole [`POLL_SLICE`].
const BUSY_HOLD: Duration = Duration::from_millis(50);
/// Frames handled per poll before the caller gets a turn.
const POLL_BATCH: usize = 64;
/// Largest upgrade response head read.
const HEAD_MAX_BYTES: usize = 16 * 1024;
/// Most headers in an upgrade response head.
const HEAD_MAX_HEADERS: usize = 64;
/// Largest refusal body read (the rest is ignored).
const BODY_MAX_BYTES: usize = 64 * 1024;

/// Why a connection ended after the upgrade (exit 125 unless the caller
/// decides otherwise).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEnded {
    /// `end{intent}` from the server; `None` when the socket was lost or the
    /// server broke the protocol.
    pub intent: Option<Intent>,
    pub error: Option<WireError>,
    /// What this client saw when there was no `end` frame.
    pub detail: Option<String>,
}

impl std::fmt::Display for SessionEnded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.intent {
            Some(intent) => write!(
                f,
                "the session ended (`{}`): {}",
                intent.name(),
                intent.describe()
            )?,
            // A drop (a proxy or Cloudflare edge restart, a network change)
            // ends the session for good: say how to get a new one.
            None => write!(
                f,
                "the connection to the server was lost ({}); the session cannot be resumed, \
                 so run the command again to start a new one",
                self.detail
                    .as_deref()
                    .unwrap_or("closed without an end frame")
            )?,
        }
        if let Some(error) = &self.error {
            write!(
                f,
                " (`{}`: {})",
                crate::output::remote_message(&error.code),
                crate::output::remote_message(&error.message)
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for SessionEnded {}

impl SessionEnded {
    fn lost(detail: impl Into<String>) -> Self {
        Self {
            intent: None,
            error: None,
            detail: Some(detail.into()),
        }
    }

    /// The JSON error code: `connect.<intent>`, else `connect.lost`.
    pub fn code(&self) -> String {
        format!("connect.{}", self.intent.map_or("lost", Intent::name))
    }

    fn into_error(self) -> anyhow::Error {
        anyhow::Error::new(self).context(CodedError::new(ExitCode::ExecFailure))
    }
}

/// The first [`SessionEnded`] in an error chain.
pub fn session_ended_of(err: &anyhow::Error) -> Option<&SessionEnded> {
    err.chain()
        .find_map(|cause| cause.downcast_ref::<SessionEnded>())
}

type Socket = WebSocket<MaybeTlsStream<Transport>>;

/// One live `wssp.connect.v1` connection.
pub struct Connection {
    socket: Socket,
    /// Another handle of the socket, for its timeouts.
    control: TcpStream,
    mux: Mux,
    connection_id: String,
    /// When the last frame (of any kind, pings too) arrived.
    last_heard: Instant,
    /// No frame for this long and the connection is lost.
    silence_limit: Duration,
    /// The transport failed or stalled: no closing handshake is attempted.
    broken: bool,
    /// The closing handshake was attempted already.
    closed: bool,
    /// The read timeout of [`Connection::poll`] now.
    poll_wait: Duration,
    /// When the caller last reported activity ([`Connection::set_busy`]).
    last_active: Option<Instant>,
    /// The socket is in nonblocking mode (only within [`Connection::poll`]).
    nonblocking: bool,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("connection_id", &self.connection_id)
            .finish_non_exhaustive()
    }
}

/// The connect URL of `sandbox_id` on `origin` (`ws`/`wss`).
pub fn connect_url(origin: &str, sandbox_id: &str) -> Result<url::Url> {
    let mut url = crate::auth::control_plane_url(origin)?
        .join(&format!("/v1/sandboxes/{sandbox_id}/connect"))?;
    let scheme = if url.scheme() == "https" { "wss" } else { "ws" };
    url.set_scheme(scheme)
        .map_err(|_| anyhow::anyhow!("invalid connect scheme"))?;
    Ok(url)
}

/// The exit code of an upgrade refusal: the `/v1` mapping, except that a
/// disconnected host is worth retrying.
pub fn refusal_exit_code(error: &crate::api::ApiError) -> ExitCode {
    if error.code == "sandbox.host_unavailable" {
        ExitCode::Retryable
    } else {
        error.exit_code()
    }
}

/// The URL's host without IPv6 brackets.
fn url_host(url: &url::Url) -> Result<&str> {
    let host = url.host_str().context("the connect URL has no host")?;
    Ok(host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host))
}

fn dial(url: &url::Url) -> Result<TcpStream> {
    let host = url_host(url)?;
    let port = url
        .port_or_known_default()
        .context("the connect URL has no port")?;
    let mut last = None;
    for addr in (host, port)
        .to_socket_addrs()
        .with_context(|| format!("resolving `{host}`"))?
    {
        match TcpStream::connect_timeout(&addr, DIAL_TIMEOUT) {
            Ok(stream) => return Ok(stream),
            Err(error) => last = Some(error),
        }
    }
    Err(match last {
        Some(error) => anyhow::Error::new(error),
        None => anyhow::anyhow!("`{host}` has no address"),
    })
}

/// The socket under the WebSocket. While `deadline` is set (the TLS and
/// upgrade handshake and the wait for `hello`) every read and write first
/// sets the socket timeout to the time left and fails with `TimedOut` once
/// none is: rustls drives its handshake through these calls, and a socket
/// timeout alone bounds one call, not a peer that trickles bytes.
#[derive(Debug)]
struct Transport {
    tcp: TcpStream,
    deadline: Option<Instant>,
}

impl Transport {
    /// The time left until the deadline, `None` without one.
    fn left(&self) -> std::io::Result<Option<Duration>> {
        let Some(deadline) = self.deadline else {
            return Ok(None);
        };
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::Error::new(
                ErrorKind::TimedOut,
                "the handshake deadline passed",
            ));
        }
        Ok(Some(left))
    }
}

impl Read for Transport {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if let Some(left) = self.left()? {
            self.tcp.set_read_timeout(Some(left))?;
        }
        self.tcp.read(buffer)
    }
}

impl Write for Transport {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if let Some(left) = self.left()? {
            self.tcp.set_write_timeout(Some(left.min(WRITE_STALL)))?;
        }
        self.tcp.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.tcp.flush()
    }
}

/// The [`Transport`] under a stream.
fn transport(stream: &mut MaybeTlsStream<Transport>) -> Option<&mut Transport> {
    match stream {
        MaybeTlsStream::Plain(transport) => Some(transport),
        MaybeTlsStream::Rustls(stream) => Some(&mut stream.sock),
        _ => None,
    }
}

/// Bound (or, with `None`, stop bounding) every socket call by `deadline`.
fn set_deadline(socket: &mut Socket, deadline: Option<Instant>) -> Result<()> {
    let transport =
        transport(socket.get_mut()).context("the connect stream has no TCP transport")?;
    transport.deadline = deadline;
    Ok(())
}

/// Why the upgrade did not happen.
#[derive(Debug)]
enum UpgradeError {
    /// The server answered something other than 101 (head and bounded body).
    Refused(Box<tungstenite::http::Response<Option<Vec<u8>>>>),
    TimedOut,
    /// A malformed or non-conforming answer.
    Invalid(String),
    /// Transport and TLS failures.
    Io(std::io::Error),
}

impl From<std::io::Error> for UpgradeError {
    fn from(error: std::io::Error) -> Self {
        if is_timeout(&error) {
            Self::TimedOut
        } else {
            Self::Io(error)
        }
    }
}

/// One read (a signal's interruption is retried); the [`Transport`]'s
/// deadline bounds it. `Ok(0)` is the end of the stream.
fn read_by<S: Read>(stream: &mut S, buffer: &mut [u8]) -> Result<usize, UpgradeError> {
    loop {
        match stream.read(buffer) {
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            other => return Ok(other?),
        }
    }
}

/// The parsed head of a response: status, headers, head length.
struct Head {
    status: u16,
    headers: Vec<(String, Vec<u8>)>,
    length: usize,
}

impl Head {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .and_then(|(_, value)| std::str::from_utf8(value).ok())
            .map(str::trim)
    }

    /// Whether a comma-separated header carries `token` (any case).
    fn has_token(&self, name: &str, token: &str) -> bool {
        self.headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .filter_map(|(_, value)| std::str::from_utf8(value).ok())
            .flat_map(|value| value.split(','))
            .any(|item| item.trim().eq_ignore_ascii_case(token))
    }
}

/// Parse a complete head at the start of `bytes`; `None` while partial.
fn parse_head(bytes: &[u8]) -> Result<Option<Head>, UpgradeError> {
    let mut headers = [httparse::EMPTY_HEADER; HEAD_MAX_HEADERS];
    let mut response = httparse::Response::new(&mut headers);
    match response.parse(bytes) {
        Ok(httparse::Status::Partial) => Ok(None),
        Ok(httparse::Status::Complete(length)) => Ok(Some(Head {
            status: response.code.unwrap_or_default(),
            headers: response
                .headers
                .iter()
                .map(|h| (h.name.to_owned(), h.value.to_vec()))
                .collect(),
            length,
        })),
        Err(error) => Err(UpgradeError::Invalid(format!(
            "the server's answer is not valid HTTP ({error})"
        ))),
    }
}

/// Decode a chunked body as far as it is complete, at most
/// [`BODY_MAX_BYTES`]; `true` once the last chunk was seen.
fn dechunk(mut raw: &[u8], body: &mut Vec<u8>) -> bool {
    body.clear();
    loop {
        let Ok(httparse::Status::Complete((start, size))) = httparse::parse_chunk_size(raw) else {
            return false;
        };
        if size == 0 {
            return true;
        }
        let Some(chunk) = usize::try_from(size)
            .ok()
            .and_then(|size| raw.get(start..start.checked_add(size)?))
        else {
            // A chunk still arriving: keep the part that is here.
            let here = &raw[start.min(raw.len())..];
            body.extend_from_slice(&here[..here.len().min(BODY_MAX_BYTES - body.len())]);
            return false;
        };
        body.extend_from_slice(&chunk[..chunk.len().min(BODY_MAX_BYTES - body.len())]);
        if body.len() >= BODY_MAX_BYTES {
            return true;
        }
        raw = match raw.get(start + chunk.len()..) {
            Some(rest) if rest.starts_with(b"\r\n") => &rest[2..],
            _ => return false,
        };
    }
}

/// The body of a refusal: to its `Content-Length`, its last chunk, or the
/// end of the stream, at most [`BODY_MAX_BYTES`] and by the [`Transport`]'s
/// deadline. A body cut short by a failure is used as far as it arrived.
fn read_body<S: Read>(stream: &mut S, head: &Head, mut raw: Vec<u8>) -> Vec<u8> {
    let chunked = head.has_token("transfer-encoding", "chunked");
    let length = if chunked {
        None
    } else {
        head.header("content-length")
            .and_then(|value| value.parse::<usize>().ok())
    };
    let want = length.unwrap_or(usize::MAX).min(BODY_MAX_BYTES);
    // Chunk framing may add to the decoded size; bound the raw bytes too.
    let raw_max = BODY_MAX_BYTES * 2;
    let mut body = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        if chunked {
            if dechunk(&raw, &mut body) || raw.len() >= raw_max {
                return body;
            }
        } else if raw.len() >= want {
            raw.truncate(want);
            return raw;
        }
        match read_by(stream, &mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(n) => raw.extend_from_slice(&buffer[..n]),
        }
    }
    if chunked {
        dechunk(&raw, &mut body);
        body
    } else {
        raw.truncate(want);
        raw
    }
}

/// Write the upgrade request and read the answer. On 101 returns the bytes
/// read past the head (the first WebSocket frames, if any). The
/// [`Transport`]'s deadline bounds the whole exchange, TLS handshake included.
fn upgrade(
    stream: &mut MaybeTlsStream<Transport>,
    url: &url::Url,
    authorization: &tungstenite::http::HeaderValue,
) -> Result<Vec<u8>, UpgradeError> {
    let key = tungstenite::handshake::client::generate_key();
    let target = &url[url::Position::BeforePath..url::Position::AfterQuery];
    let host = &url[url::Position::BeforeHost..url::Position::AfterPort];
    // Bearer + subprotocol only: no Origin, no cookies.
    let mut request = zeroize::Zeroizing::new(
        format!(
            "GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Protocol: {}\r\nAuthorization: ",
            wire::SUBPROTOCOL
        )
        .into_bytes(),
    );
    request.extend_from_slice(authorization.as_bytes());
    request.extend_from_slice(b"\r\n\r\n");
    // A TLS stream completes its handshake within this write.
    loop {
        match stream.write_all(&request).and_then(|()| stream.flush()) {
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            other => break other?,
        }
    }
    let mut raw = Vec::new();
    let mut buffer = [0_u8; 4096];
    let head = loop {
        if let Some(head) = parse_head(&raw)? {
            break head;
        }
        if raw.len() >= HEAD_MAX_BYTES {
            return Err(UpgradeError::Invalid(
                "the server's answer head is too long".to_owned(),
            ));
        }
        let room = (HEAD_MAX_BYTES - raw.len()).min(buffer.len());
        let n = read_by(stream, &mut buffer[..room])?;
        if n == 0 {
            return Err(UpgradeError::Invalid(
                "the server closed the connection during the upgrade".to_owned(),
            ));
        }
        raw.extend_from_slice(&buffer[..n]);
    };
    let rest = raw.split_off(head.length);
    if head.status != 101 {
        let body = read_body(stream, &head, rest);
        let mut response = tungstenite::http::Response::builder().status(head.status);
        for (name, value) in &head.headers {
            if let (Ok(name), Ok(value)) = (
                tungstenite::http::HeaderName::from_bytes(name.as_bytes()),
                tungstenite::http::HeaderValue::from_bytes(value),
            ) {
                response = response.header(name, value);
            }
        }
        return Err(match response.body(Some(body)) {
            Ok(response) => UpgradeError::Refused(Box::new(response)),
            Err(_) => UpgradeError::Invalid(format!("the server answered {}", head.status)),
        });
    }
    if !head.has_token("upgrade", "websocket") || !head.has_token("connection", "upgrade") {
        return Err(UpgradeError::Invalid(
            "the server's 101 answer is not a WebSocket upgrade".to_owned(),
        ));
    }
    let accept = tungstenite::handshake::derive_accept_key(key.as_bytes());
    if head.header("sec-websocket-accept") != Some(accept.as_str()) {
        return Err(UpgradeError::Invalid(
            "the server's `Sec-WebSocket-Accept` does not match the request".to_owned(),
        ));
    }
    if head.header("sec-websocket-protocol") != Some(wire::SUBPROTOCOL) {
        return Err(UpgradeError::Invalid(format!(
            "the server did not accept the `{}` subprotocol",
            wire::SUBPROTOCOL
        )));
    }
    Ok(rest)
}

fn is_timeout(error: &std::io::Error) -> bool {
    matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

/// A socket call a signal interrupted: with a socket timeout it is never
/// restarted (SIGWINCH, SIGINT), and nothing was consumed or lost.
fn is_interrupted(error: &tungstenite::Error) -> bool {
    matches!(error, tungstenite::Error::Io(io) if io.kind() == ErrorKind::Interrupted)
}

impl Connection {
    /// Upgrade and wait for `hello`. Refusals carry their `/v1` exit code.
    pub fn connect(credential: &UserCredential, sandbox_id: &str) -> Result<Self> {
        let origin = crate::auth::canonical_control_plane_origin(&credential.origin)?;
        let url = connect_url(&origin, sandbox_id)?;
        let trust = credential.trust()?;
        let authorization =
            tungstenite::http::HeaderValue::from_str(&format!("Bearer {}", credential.secret))
                .context("the login key is not a valid header value")?;
        let tcp = dial(&url).with_context(|| format!("connecting to `{origin}` failed"))?;
        tcp.set_nodelay(true).context("configuring the socket")?;
        tcp.set_read_timeout(Some(HANDSHAKE_TIMEOUT))
            .context("configuring the socket")?;
        tcp.set_write_timeout(Some(WRITE_STALL))
            .context("configuring the socket")?;
        // Another handle of the same socket, for its timeouts.
        let control = tcp.try_clone().context("configuring the socket")?;
        // Every socket call until `hello` is bounded by the handshake deadline.
        let transport = Transport {
            tcp,
            deadline: Some(Instant::now() + HANDSHAKE_TIMEOUT),
        };
        // Cleartext only on loopback (`connect_url`); WSS uses the extra CA
        // trust, else the webpki roots.
        let mut stream = if url.scheme() == "wss" {
            let config = trust.wss_client_config()?;
            let name = rustls::pki_types::ServerName::try_from(url_host(&url)?.to_owned())
                .context("the connect host is not a valid TLS server name")?;
            let client = rustls::ClientConnection::new(config, name)
                .with_context(|| format!("connecting to `{origin}` failed"))?;
            MaybeTlsStream::Rustls(rustls::StreamOwned::new(client, transport))
        } else {
            MaybeTlsStream::Plain(transport)
        };
        let leftover = upgrade(&mut stream, &url, &authorization).map_err(|error| match error {
            UpgradeError::Refused(response) => refusal(&response),
            UpgradeError::TimedOut => {
                anyhow::anyhow!("connecting to `{origin}` failed: the handshake timed out")
            }
            UpgradeError::Invalid(why) => {
                anyhow::anyhow!("connecting to `{origin}` failed: {why}")
            }
            UpgradeError::Io(error) => crate::tls::control_plane_error(&origin, error)
                .context(format!("connecting to `{origin}` failed")),
        })?;
        let config = tungstenite::protocol::WebSocketConfig::default()
            .max_message_size(Some(wire::CONTROL_MAX_BYTES + 64))
            .max_frame_size(Some(wire::CONTROL_MAX_BYTES + 64));
        let mut socket =
            WebSocket::from_partially_read(stream, leftover, Role::Client, Some(config));
        // The first frame is `hello` (the client sends nothing before it),
        // by its own deadline.
        let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
        set_deadline(&mut socket, Some(deadline))?;
        let hello = loop {
            anyhow::ensure!(
                Instant::now() < deadline,
                "the server sent no hello in time"
            );
            match socket.read() {
                Ok(Message::Text(text)) => break wire::parse_server_control(text.as_str()),
                Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_)) => {}
                Ok(Message::Binary(_)) => break None,
                Ok(Message::Close(_)) => {
                    return Err(SessionEnded::lost("closed before hello").into_error());
                }
                Err(tungstenite::Error::Io(error)) if is_timeout(&error) => {
                    anyhow::bail!("the server sent no hello in time")
                }
                Err(error) => {
                    return Err(SessionEnded::lost(error.to_string()).into_error());
                }
            }
        };
        let (connection_id, limits) = match hello {
            Some(ServerControl::Hello {
                connection_id,
                sandbox_id: announced,
                limits,
            }) if announced == sandbox_id => (connection_id, limits),
            Some(ServerControl::End { intent, error }) => {
                return Err(SessionEnded {
                    intent: Some(intent),
                    error,
                    detail: None,
                }
                .into_error());
            }
            _ => {
                return Err(
                    SessionEnded::lost("the first frame was not a valid hello").into_error()
                );
            }
        };
        // The session's own timeouts from here on.
        set_deadline(&mut socket, None)?;
        control
            .set_read_timeout(Some(POLL_SLICE))
            .context("configuring the socket")?;
        control
            .set_write_timeout(Some(WRITE_STALL))
            .context("configuring the socket")?;
        tracing::debug!(%connection_id, "connect session open");
        Ok(Self {
            socket,
            control,
            silence_limit: silence_limit(&limits),
            mux: Mux::new(limits),
            connection_id,
            last_heard: Instant::now(),
            broken: false,
            closed: false,
            poll_wait: POLL_SLICE,
            last_active: None,
            nonblocking: false,
        })
    }

    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }

    pub fn limits(&self) -> &Limits {
        self.mux.limits()
    }

    /// Largest data body on a channel of `kind`.
    pub fn data_max(&self, kind: Kind) -> usize {
        self.mux.data_max(kind)
    }

    fn write(&mut self, message: Message) -> Result<()> {
        match self.socket.write(message) {
            // The frame is queued; the next flush writes it.
            Ok(()) => Ok(()),
            Err(error) if is_interrupted(&error) => Ok(()),
            Err(error) => Err(self.transport_error(error)),
        }
    }

    fn transport_error(&mut self, error: tungstenite::Error) -> anyhow::Error {
        self.broken = true;
        let detail = match &error {
            tungstenite::Error::Io(io) if is_timeout(io) => {
                "a write made no progress for 30 s".to_owned()
            }
            other => other.to_string(),
        };
        SessionEnded::lost(detail).into_error()
    }

    fn control(&mut self, frame: &ClientControl) -> Result<()> {
        let text = wire::encode_control(frame)?;
        self.write(Message::text(text))
    }

    /// Open a channel; its `ready` (or a refusal `exit`) arrives as an event.
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        &mut self,
        kind: Kind,
        argv: Option<Vec<String>>,
        login: Option<bool>,
        cwd: Option<String>,
        env: Option<BTreeMap<String, String>>,
        pty: Option<PtyParams>,
    ) -> Result<u32> {
        let (channel, frame) = self.mux.open(kind, argv, login, cwd, env, pty)?;
        self.control(&frame)?;
        self.flush()?;
        Ok(channel)
    }

    /// Open a relay channel to guest loopback `port` (`tcp`) or the guest
    /// Unix socket `path` (`unix`); queued until the next flush. Its `ready`
    /// (or a refusal `exit`) arrives as an event.
    pub fn open_relay(&mut self, port: Option<u16>, path: Option<String>) -> Result<u32> {
        let (channel, frame) = self.mux.open_relay(port, path)?;
        self.control(&frame)?;
        Ok(channel)
    }

    /// Whether the channel's exit was released (or it is unknown).
    pub fn is_done(&self, channel: u32) -> bool {
        self.mux.is_done(channel)
    }

    /// Drop an ended channel's state once its owed acks were queued
    /// ([`mux::Mux::forget`]).
    pub fn forget(&mut self, channel: u32) {
        self.mux.forget(channel);
    }

    /// The caller's turn moved data (`active`) or not: the next polls wait
    /// [`BUSY_POLL_SLICE`] until [`BUSY_HOLD`] after the last active turn,
    /// then [`POLL_SLICE`] again, so an idle connection wakes as rarely as
    /// before.
    pub fn set_busy(&mut self, active: bool) -> Result<()> {
        let now = Instant::now();
        if active {
            self.last_active = Some(now);
        }
        let busy = self
            .last_active
            .is_some_and(|at| now.duration_since(at) < BUSY_HOLD);
        let wait = if busy { BUSY_POLL_SLICE } else { POLL_SLICE };
        if wait != self.poll_wait {
            self.control
                .set_read_timeout(Some(wait))
                .context("configuring the socket")?;
            self.poll_wait = wait;
        }
        Ok(())
    }

    /// Wait up to [`POLL_SLICE`] (see [`Connection::set_busy`]) for frames
    /// and return their events in delivery order. Only the first read
    /// waits: once a frame arrived, the rest of the batch takes only what
    /// is already there, so the caller gets its turn as soon as the frames
    /// that woke it are handled (a wait after them delayed every ack by a
    /// whole slice).
    pub fn poll(&mut self) -> Result<Vec<Event>> {
        let result = self.poll_batch();
        let restored = self.set_blocking();
        let events = result?;
        restored.map_err(|error| {
            self.broken = true;
            anyhow::Error::new(error).context("configuring the socket")
        })?;
        Ok(events)
    }

    /// Back to blocking reads and writes (with their timeouts).
    fn set_blocking(&mut self) -> std::io::Result<()> {
        if self.nonblocking {
            self.nonblocking = false;
            self.control.set_nonblocking(false)?;
        }
        Ok(())
    }

    fn poll_batch(&mut self) -> Result<Vec<Event>> {
        let mut events = Vec::new();
        for turn in 0..POLL_BATCH {
            if turn == 1 && !self.nonblocking {
                if let Err(error) = self.control.set_nonblocking(true) {
                    self.broken = true;
                    return Err(anyhow::Error::new(error).context("configuring the socket"));
                }
                self.nonblocking = true;
            }
            let message = match self.socket.read() {
                Ok(message) => message,
                Err(tungstenite::Error::Io(error)) if is_timeout(&error) => {
                    // Nothing buffered either: frames that queued up while
                    // this thread was busy count before this check.
                    if self.last_heard.elapsed() >= self.silence_limit {
                        self.broken = true;
                        return Err(SessionEnded::lost(format!(
                            "the server sent nothing for {} s",
                            self.silence_limit.as_secs_f64().ceil()
                        ))
                        .into_error());
                    }
                    break;
                }
                Err(error) if is_interrupted(&error) => break,
                Err(error) => return Err(self.transport_error(error)),
            };
            self.last_heard = Instant::now();
            let handled = match message {
                Message::Text(text) => match wire::parse_server_control(text.as_str()) {
                    Some(ServerControl::End { intent, error }) => {
                        self.close_socket();
                        return Err(SessionEnded {
                            intent: Some(intent),
                            error,
                            detail: None,
                        }
                        .into_error());
                    }
                    Some(frame) => self.mux.on_control(frame),
                    None => Err(Violation("an invalid control frame")),
                },
                Message::Binary(bytes) => match wire::parse_data(&bytes) {
                    Some((metadata, body)) => match metadata.stream.output() {
                        Some(stream) => {
                            self.mux
                                .on_data(metadata.channel, stream, metadata.seq, body)
                        }
                        None => Err(Violation("stdin data from the server")),
                    },
                    None => Err(Violation("an invalid data frame")),
                },
                Message::Close(_) => {
                    return Err(
                        SessionEnded::lost("the server closed without an end frame").into_error()
                    );
                }
                Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => Ok(Vec::new()),
            };
            match handled {
                Ok(more) => events.extend(more),
                Err(violation) => {
                    self.close_socket();
                    return Err(SessionEnded::lost(violation.to_string()).into_error());
                }
            }
        }
        Ok(events)
    }

    /// The caller delivered output frame `seq`; returns what it releases.
    /// The ack leaves with the next [`Connection::flush`].
    pub fn delivered(&mut self, channel: u32, stream: wire::OutputStream, seq: u64) -> Vec<Event> {
        self.mux.delivered(channel, stream, seq)
    }

    pub fn stdin_credit(&self, channel: u32) -> bool {
        self.mux.stdin_credit(channel)
    }

    /// Send one stdin frame (only with [`Connection::stdin_credit`]); `body`
    /// is 1 ..= [`Connection::data_max`] bytes.
    pub fn send_stdin(&mut self, channel: u32, body: &[u8]) -> Result<()> {
        let seq = self.mux.stdin_frame(channel, body.len())?;
        let frame = wire::encode_data(&DataMetadata::new(channel, DataStream::Stdin, seq), body)?;
        self.write(Message::binary(frame))
    }

    /// Close stdin after every frame sent so far.
    pub fn stdin_eof(&mut self, channel: u32) -> Result<()> {
        match self.mux.stdin_eof(channel) {
            Some(frame) => self.control(&frame),
            None => Ok(()),
        }
    }

    /// Resize a pty channel; the size is clamped to 1–512 × 1–1024.
    pub fn resize(&mut self, channel: u32, rows: u16, cols: u16) -> Result<()> {
        let (rows, cols) = clamp_size(rows, cols);
        if !self.mux.is_open(channel) {
            return Ok(());
        }
        self.control(&ClientControl::Resize {
            channel,
            rows,
            cols,
        })
    }

    pub fn signal(&mut self, channel: u32, signal: Signal) -> Result<()> {
        if !self.mux.is_open(channel) {
            return Ok(());
        }
        self.control(&ClientControl::Signal { channel, signal })
    }

    /// A normal close (sshd semantics); the channel's `exit` follows.
    pub fn close_channel(&mut self, channel: u32) -> Result<()> {
        if self.mux.is_done(channel) {
            return Ok(());
        }
        self.control(&ClientControl::Close { channel })
    }

    /// Give a channel up from this side (its local end failed or a
    /// teardown): its output is discarded and acknowledged
    /// ([`mux::Mux::discard`]), and a `close` is sent unless that released
    /// its exit already. Returns the events released (a held eof or exit).
    pub fn abort_channel(&mut self, channel: u32) -> Result<Vec<Event>> {
        let released = self.mux.discard(channel);
        self.close_channel(channel)?;
        Ok(released)
    }

    /// Queue the owed acks (they leave with the next write or flush), so
    /// they go out before anything queued after them.
    pub fn queue_acks(&mut self) -> Result<()> {
        for ack in self.mux.take_acks() {
            self.control(&ack)?;
        }
        Ok(())
    }

    /// Send owed acks and everything written so far.
    pub fn flush(&mut self) -> Result<()> {
        self.queue_acks()?;
        loop {
            match self.socket.flush() {
                Ok(()) => return Ok(()),
                Err(error) if is_interrupted(&error) => {}
                Err(error) => return Err(self.transport_error(error)),
            }
        }
    }

    /// The closing handshake, once: owed acks, anything queued and the
    /// close frame, each write bounded by [`CLOSE_WRITE`] instead of
    /// [`WRITE_STALL`]. Skipped on a transport that failed or stalled (a
    /// failed write, a silent server): nothing would get through, and each
    /// attempt would wait for the write timeout.
    fn close_socket(&mut self) {
        if self.broken || self.closed {
            return;
        }
        self.closed = true;
        if self.set_blocking().is_err()
            || self.control.set_write_timeout(Some(CLOSE_WRITE)).is_err()
        {
            return;
        }
        let deadline = Instant::now() + CLOSE_WRITE;
        if self.queue_acks().is_err() {
            return;
        }
        // `close` queues the close frame and flushes everything queued.
        while let Err(error) = self.socket.close(None) {
            if !is_interrupted(&error) || Instant::now() >= deadline {
                return;
            }
        }
    }

    /// Close the WebSocket (best effort, see [`Connection::close_socket`]).
    pub fn finish(mut self) {
        self.close_socket();
    }
}

/// How long the server may send nothing at all before the connection is
/// lost: it pings every `pingIntervalMs` (a ping is sent whatever else
/// flows), so three missed pings, and never less than the server's own
/// `idleTimeoutMs` for a silent client.
fn silence_limit(limits: &Limits) -> Duration {
    Duration::from_millis(
        limits
            .ping_interval_ms
            .saturating_mul(3)
            .max(limits.idle_timeout_ms),
    )
}

/// Sizes outside 1–512 × 1–1024 are clamped (an unknown 0 becomes 1).
pub fn clamp_size(rows: u16, cols: u16) -> (u16, u16) {
    (
        rows.clamp(
            sandbox_protocol::TERMINAL_MIN_DIMENSION,
            sandbox_protocol::TERMINAL_MAX_ROWS,
        ),
        cols.clamp(
            sandbox_protocol::TERMINAL_MIN_DIMENSION,
            sandbox_protocol::TERMINAL_MAX_COLS,
        ),
    )
}

/// The `/v1` error of a refused upgrade, with its exit code.
fn refusal(response: &tungstenite::http::Response<Option<Vec<u8>>>) -> anyhow::Error {
    let status = response.status().as_u16();
    let retry_after = response
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok());
    let body = response
        .body()
        .as_deref()
        .map(|bytes| String::from_utf8_lossy(&bytes[..bytes.len().min(64 * 1024)]).into_owned())
        .unwrap_or_default();
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
    };
    let error = crate::api::parse_refusal(
        status,
        &body,
        retry_after,
        header("x-wssp-error-code"),
        header("x-wssp-error-reason"),
    );
    let code = refusal_exit_code(&error);
    anyhow::Error::new(error).context(CodedError::new(code))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_urls_follow_the_transport_rules() {
        assert_eq!(
            connect_url("https://wssp.example.com/", "sbx_1")
                .unwrap()
                .as_str(),
            "wss://wssp.example.com/v1/sandboxes/sbx_1/connect"
        );
        assert_eq!(
            connect_url("http://127.0.0.1:8080/", "sbx_1")
                .unwrap()
                .as_str(),
            "ws://127.0.0.1:8080/v1/sandboxes/sbx_1/connect"
        );
        assert!(connect_url("http://wssp.example.com/", "sbx_1").is_err());
    }

    #[test]
    fn refusals_map_to_the_v1_exit_codes() {
        let code = |status, code: &str| {
            refusal_exit_code(&crate::api::parse_error(
                status,
                &serde_json::json!({"error": {"code": code, "message": "m"}}).to_string(),
                None,
            ))
        };
        assert_eq!(code(401, "UNAUTHORIZED"), ExitCode::NotLoggedIn);
        assert_eq!(code(403, "FORBIDDEN"), ExitCode::Forbidden);
        assert_eq!(code(404, "NOT_FOUND"), ExitCode::NotFound);
        assert_eq!(code(409, "sandbox.state_conflict"), ExitCode::Conflict);
        assert_eq!(code(409, "sandbox.host_unavailable"), ExitCode::Retryable);
        assert_eq!(code(429, "TOO_MANY_REQUESTS"), ExitCode::Retryable);
        assert_eq!(code(503, "SERVICE_UNAVAILABLE"), ExitCode::Retryable);
        assert_eq!(code(400, "UNSUPPORTED_CAPABILITY"), ExitCode::Usage);
    }

    #[test]
    fn chunked_refusal_bodies_are_decoded_as_far_as_they_arrived() {
        let mut body = Vec::new();
        assert!(dechunk(b"4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n", &mut body));
        assert_eq!(body, b"{\"a\":1}");
        assert!(!dechunk(b"4\r\n{\"a\"\r\n3\r\n:1", &mut body));
        assert_eq!(body, b"{\"a\":1");
        assert!(!dechunk(b"", &mut body));
        assert!(body.is_empty());
    }

    #[test]
    fn response_heads_parse_only_when_complete() {
        assert!(
            parse_head(b"HTTP/1.1 409 Conflict\r\nContent-Le")
                .unwrap()
                .is_none()
        );
        let head = parse_head(
            b"HTTP/1.1 101 Switching\r\nUpgrade: WebSocket\r\nConnection: keep-alive, Upgrade\r\n\r\nrest",
        )
        .unwrap()
        .unwrap();
        assert_eq!(head.status, 101);
        assert_eq!(head.length, 79);
        assert!(head.has_token("upgrade", "websocket"));
        assert!(head.has_token("connection", "upgrade"));
        assert!(matches!(
            parse_head(b"NOT HTTP\r\n\r\n"),
            Err(UpgradeError::Invalid(_))
        ));
    }

    #[test]
    fn the_silence_limit_is_three_pings_and_at_least_the_idle_timeout() {
        let limits = |ping, idle| Limits {
            max_channels: 32,
            max_pty_channels: 8,
            opens_per_minute: 120,
            window_frames: wire::PerKind { pty: 8, exec: 32 },
            data_max_bytes: wire::PerKind {
                pty: 16384,
                exec: 32768,
            },
            ack_stall_ms: 60_000,
            ping_interval_ms: ping,
            idle_timeout_ms: idle,
            open_timeout_ms: 30_000,
            unacked_input_bytes: 4 * 1024 * 1024,
        };
        // The contract's values: 3 × 20 s = the 60 s idle timeout.
        assert_eq!(
            silence_limit(&limits(20_000, 60_000)),
            Duration::from_secs(60)
        );
        assert_eq!(
            silence_limit(&limits(30_000, 60_000)),
            Duration::from_secs(90)
        );
        assert_eq!(
            silence_limit(&limits(1_000, 60_000)),
            Duration::from_secs(60)
        );
        assert_eq!(
            silence_limit(&limits(u64::MAX / 2, 1)),
            Duration::from_millis(u64::MAX)
        );
    }

    /// A server that answers the ClientHello with a TLS record header and
    /// then trickles its body, one byte every 200 ms, never finishing the
    /// handshake: the upgrade fails by the deadline, not per socket call.
    #[test]
    fn a_trickled_tls_handshake_cannot_outlast_the_deadline() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, mpsc};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let server = std::thread::spawn({
            let stop = stop.clone();
            move || {
                let (mut peer, _) = listener.accept().unwrap();
                // A 16 KiB handshake record, its body never complete.
                let _ = peer.write_all(&[0x16, 0x03, 0x03, 0x40, 0x00]);
                while !stop.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(200));
                    if peer.write_all(&[0]).is_err() {
                        break;
                    }
                }
            }
        });
        let tcp = TcpStream::connect(address).unwrap();
        let config = crate::tls::Trust::default().wss_client_config().unwrap();
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let client = rustls::ClientConnection::new(config, name).unwrap();
        let started = Instant::now();
        let transport = Transport {
            tcp,
            deadline: Some(started + Duration::from_secs(1)),
        };
        let mut stream = MaybeTlsStream::Rustls(rustls::StreamOwned::new(client, transport));
        let url = url::Url::parse("wss://localhost/v1/sandboxes/sbx_1/connect").unwrap();
        let authorization = tungstenite::http::HeaderValue::from_static("Bearer key");
        let (done, result) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = done.send(upgrade(&mut stream, &url, &authorization));
        });
        let result = result.recv_timeout(Duration::from_secs(10));
        stop.store(true, Ordering::SeqCst);
        server.join().unwrap();
        let result = result.expect("the trickled handshake outlasted its deadline");
        assert!(matches!(result, Err(UpgradeError::TimedOut)), "{result:?}");
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_secs(1) && elapsed < Duration::from_secs(3),
            "{elapsed:?}"
        );
    }

    #[test]
    fn sizes_are_clamped() {
        assert_eq!(clamp_size(0, 0), (1, 1));
        assert_eq!(clamp_size(24, 80), (24, 80));
        assert_eq!(clamp_size(9999, 9999), (512, 1024));
    }

    #[test]
    fn session_end_messages_name_the_intent() {
        let ended = SessionEnded {
            intent: Some(Intent::Revoked),
            error: None,
            detail: None,
        };
        assert!(ended.to_string().contains("`revoked`"));
        assert_eq!(ended.code(), "connect.revoked");
        let lost = SessionEnded::lost("reset");
        assert_eq!(lost.code(), "connect.lost");
        assert_eq!(
            lost.to_string(),
            "the connection to the server was lost (reset); the session cannot be resumed, \
             so run the command again to start a new one"
        );
    }
}
