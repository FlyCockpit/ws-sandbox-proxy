//! Frame codecs of the client wire `wssp.connect.v1` (CLI ↔ server).
//!
//! The Rust mirror of `packages/sandbox-contracts/src/connect-wire.ts`:
//! JSON text control frames and binary data frames (a big-endian u32
//! metadata length, the JSON metadata `{type: "data", channel, stream, seq}`,
//! then the body). Every object is strict: an unknown field, a `null` where a
//! field is optional, or a value outside its bound is refused, exactly as the
//! TypeScript schemas refuse it (`connect-wire-fixtures.json` holds the
//! shared vectors). Both directions are modelled so the tests can play the
//! server; the CLI only encodes [`ClientControl`] and decodes
//! [`ServerControl`].

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use serde::{Deserialize, Deserializer, Serialize};

/// The one subprotocol of the connect route.
pub const SUBPROTOCOL: &str = "wssp.connect.v1";
/// The WebSocket close code after a final `end` frame.
pub const CLOSE_CODE: u16 = 4401;
/// Largest text control frame.
pub const CONTROL_MAX_BYTES: usize = 256 * 1024;
/// Largest binary metadata header.
pub const DATA_METADATA_MAX_BYTES: usize = 1024;
/// Largest data body (exec streams); pty bodies are bounded by `hello.limits`.
pub const DATA_MAX_BYTES: usize = sandbox_protocol::CHANNEL_BULK_DATA_MAX_BYTES;
/// JavaScript's largest exact integer: every sequence and count stays below it.
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// A channel kind: a guest process (`pty`, `exec`) or a relay to a guest
/// loopback TCP port (`tcp`) or guest Unix socket (`unix`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Pty,
    Exec,
    Tcp,
    Unix,
}

impl Kind {
    /// A relay: stdin and stdout only, no signals, no terminal.
    pub fn is_relay(self) -> bool {
        matches!(self, Self::Tcp | Self::Unix)
    }
}

/// A guest output stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputStream {
    Stdout,
    Stderr,
}

impl OutputStream {
    pub fn index(self) -> usize {
        match self {
            Self::Stdout => 0,
            Self::Stderr => 1,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

/// The only input stream (a literal on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StdinStream {
    Stdin,
}

/// The stream of a data frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataStream {
    Stdin,
    Stdout,
    Stderr,
}

impl DataStream {
    pub fn output(self) -> Option<OutputStream> {
        match self {
            Self::Stdin => None,
            Self::Stdout => Some(OutputStream::Stdout),
            Self::Stderr => Some(OutputStream::Stderr),
        }
    }
}

impl From<OutputStream> for DataStream {
    fn from(stream: OutputStream) -> Self {
        match stream {
            OutputStream::Stdout => Self::Stdout,
            OutputStream::Stderr => Self::Stderr,
        }
    }
}

/// The signals of exec channels (`KILL` kill-closes the channel's scope).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Signal {
    #[serde(rename = "TERM")]
    Term,
    #[serde(rename = "INT")]
    Int,
    #[serde(rename = "HUP")]
    Hup,
    #[serde(rename = "KILL")]
    Kill,
}

/// Why a channel or the whole connection was closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Intent {
    Client,
    Detached,
    Backpressure,
    Revoked,
    Superseded,
    ProtocolViolation,
    HostDisconnected,
    Expired,
    SandboxStopped,
    SandboxDestroyed,
    LifecycleUnconfirmed,
    Shutdown,
}

impl Intent {
    /// The wire name (`revoked`, `sandbox_stopped`, …).
    pub fn name(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Detached => "detached",
            Self::Backpressure => "backpressure",
            Self::Revoked => "revoked",
            Self::Superseded => "superseded",
            Self::ProtocolViolation => "protocol_violation",
            Self::HostDisconnected => "host_disconnected",
            Self::Expired => "expired",
            Self::SandboxStopped => "sandbox_stopped",
            Self::SandboxDestroyed => "sandbox_destroyed",
            Self::LifecycleUnconfirmed => "lifecycle_unconfirmed",
            Self::Shutdown => "shutdown",
        }
    }

    /// What happened, for the one line a command prints.
    pub fn describe(self) -> &'static str {
        match self {
            Self::Client => "closed by this client",
            Self::Detached => "the server stopped hearing from this client",
            Self::Backpressure => "output was not acknowledged in time",
            Self::Revoked => {
                "the login was revoked or expired, or access to the sandbox was withdrawn"
            }
            Self::Superseded => "the sandbox moved to a new generation or host",
            Self::ProtocolViolation => "a protocol error",
            Self::HostDisconnected => "the sandbox's host disconnected",
            Self::Expired => "the session or the sandbox's lease expired",
            Self::SandboxStopped => "the sandbox stopped",
            Self::SandboxDestroyed => "the sandbox was destroyed",
            Self::LifecycleUnconfirmed => "the sandbox's state could not be confirmed",
            Self::Shutdown => "the server is shutting down",
        }
    }
}

/// Non-fatal notices on a live channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Notice {
    UnsupportedSignal,
    StateConflict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PtyParams {
    pub rows: u16,
    pub cols: u16,
    pub term: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PtySize {
    pub rows: u16,
    pub cols: u16,
}

/// A stable lower-case error code and a short message (never request data).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WireError {
    pub code: String,
    pub message: String,
}

impl WireError {
    fn is_valid(&self) -> bool {
        let code = self.code.as_bytes();
        (1..=64).contains(&code.len())
            && code[0].is_ascii_lowercase()
            && code
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
            && self.message.len() <= 1024
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExitFrames {
    pub stdout: u64,
    pub stderr: u64,
}

impl ExitFrames {
    pub fn of(self, stream: OutputStream) -> u64 {
        match stream {
            OutputStream::Stdout => self.stdout,
            OutputStream::Stderr => self.stderr,
        }
    }
}

/// A per-kind value of `hello.limits`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PerKind {
    pub pty: u64,
    pub exec: u64,
}

impl PerKind {
    /// The value for `kind`: every bulk kind (all but `pty`) uses `exec`'s.
    pub fn of(self, kind: Kind) -> u64 {
        match kind {
            Kind::Pty => self.pty,
            Kind::Exec | Kind::Tcp | Kind::Unix => self.exec,
        }
    }

    fn is_valid(self) -> bool {
        self.pty > 0 && self.exec > 0
    }
}

/// The connection's limits, announced in `hello`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Limits {
    pub max_channels: u64,
    pub max_pty_channels: u64,
    pub opens_per_minute: u64,
    /// Unacknowledged data frames per channel and direction.
    pub window_frames: PerKind,
    pub data_max_bytes: PerKind,
    pub ack_stall_ms: u64,
    pub ping_interval_ms: u64,
    pub idle_timeout_ms: u64,
    pub open_timeout_ms: u64,
    /// stdin bytes not yet acknowledged by the server, across the connection.
    pub unacked_input_bytes: u64,
}

impl Limits {
    fn is_valid(&self) -> bool {
        [
            self.max_channels,
            self.max_pty_channels,
            self.opens_per_minute,
            self.ack_stall_ms,
            self.ping_interval_ms,
            self.idle_timeout_ms,
            self.open_timeout_ms,
            self.unacked_input_bytes,
        ]
        .iter()
        .all(|value| (1..=MAX_SAFE_INTEGER).contains(value))
            && self.window_frames.is_valid()
            && self.data_max_bytes.is_valid()
    }
}

/// An optional field that, when present, is never `null` (zod `.optional()`).
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(deserializer).map(Some)
}

/// Client → server control frames.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ClientControl {
    /// `argv` is structural (never a shell string); absent: the guest shell,
    /// a login shell with `login: true`. `pty` exactly for `kind: "pty"`. A
    /// relay carries exactly its target (`tcp`: `port`; `unix`: `path`) and
    /// nothing else: there is no host, the target is the guest's own.
    Open {
        channel: u32,
        kind: Kind,
        #[serde(
            default,
            deserialize_with = "present",
            skip_serializing_if = "Option::is_none"
        )]
        argv: Option<Vec<String>>,
        #[serde(
            default,
            deserialize_with = "present",
            skip_serializing_if = "Option::is_none"
        )]
        login: Option<bool>,
        #[serde(
            default,
            deserialize_with = "present",
            skip_serializing_if = "Option::is_none"
        )]
        cwd: Option<String>,
        #[serde(
            default,
            deserialize_with = "present",
            skip_serializing_if = "Option::is_none"
        )]
        env: Option<BTreeMap<String, String>>,
        #[serde(
            default,
            deserialize_with = "present",
            skip_serializing_if = "Option::is_none"
        )]
        pty: Option<PtyParams>,
        #[serde(
            default,
            deserialize_with = "present",
            skip_serializing_if = "Option::is_none"
        )]
        port: Option<u16>,
        #[serde(
            default,
            deserialize_with = "present",
            skip_serializing_if = "Option::is_none"
        )]
        path: Option<String>,
    },
    /// Cumulative output credit: the highest delivered `seq` of `stream`.
    Ack {
        channel: u32,
        stream: OutputStream,
        seq: u64,
    },
    /// stdin is complete after `frames` data frames.
    Eof {
        channel: u32,
        stream: StdinStream,
        frames: u64,
    },
    Resize {
        channel: u32,
        rows: u16,
        cols: u16,
    },
    Signal {
        channel: u32,
        signal: Signal,
    },
    /// A normal close (sshd semantics: the session hangs up).
    Close {
        channel: u32,
    },
}

impl ClientControl {
    /// The bounds the schema checks beyond the field types.
    pub fn is_valid(&self) -> bool {
        match self {
            Self::Open {
                kind,
                argv,
                login,
                cwd,
                env,
                pty,
                port,
                path,
                ..
            } => {
                if kind.is_relay() {
                    let target = match kind {
                        Kind::Tcp => port.is_some_and(|port| port > 0) && path.is_none(),
                        _ => {
                            port.is_none()
                                && path
                                    .as_deref()
                                    .is_some_and(sandbox_protocol::valid_channel_unix_path)
                        }
                    };
                    return target
                        && argv.is_none()
                        && login.is_none()
                        && cwd.is_none()
                        && env.is_none()
                        && pty.is_none();
                }
                let pty_ok = match (kind, pty) {
                    (Kind::Pty, Some(pty)) => {
                        sandbox_protocol::valid_terminal_size(pty.rows, pty.cols)
                            && sandbox_protocol::valid_channel_term(&pty.term)
                    }
                    (Kind::Exec, None) => true,
                    _ => false,
                };
                pty_ok
                    && port.is_none()
                    && path.is_none()
                    && argv
                        .as_deref()
                        .is_none_or(sandbox_protocol::valid_channel_argv)
                    && cwd
                        .as_deref()
                        .is_none_or(sandbox_protocol::valid_channel_cwd)
                    && env.as_ref().is_none_or(sandbox_protocol::valid_channel_env)
            }
            Self::Ack { seq, .. } => *seq <= MAX_SAFE_INTEGER,
            Self::Eof { frames, .. } => *frames <= MAX_SAFE_INTEGER,
            Self::Resize { rows, cols, .. } => sandbox_protocol::valid_terminal_size(*rows, *cols),
            Self::Signal { .. } | Self::Close { .. } => true,
        }
    }
}

/// Server → client control frames.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ServerControl {
    /// The first frame of every connection.
    Hello {
        connection_id: String,
        sandbox_id: String,
        limits: Limits,
    },
    Ready {
        channel: u32,
        #[serde(
            default,
            deserialize_with = "present",
            skip_serializing_if = "Option::is_none"
        )]
        pty: Option<PtySize>,
    },
    /// stdin credit: the highest `seq` the guest side consumed.
    Ack {
        channel: u32,
        stream: StdinStream,
        seq: u64,
    },
    /// `stream` ended after `frames` data frames.
    Eof {
        channel: u32,
        stream: OutputStream,
        frames: u64,
    },
    /// The channel's last frame. At most one of `exit_code` and `signal`;
    /// neither is an unknown status. `intent`: the channel was closed;
    /// `error`: why it failed.
    Exit {
        channel: u32,
        #[serde(
            default,
            deserialize_with = "present",
            skip_serializing_if = "Option::is_none"
        )]
        exit_code: Option<i32>,
        #[serde(
            default,
            deserialize_with = "present",
            skip_serializing_if = "Option::is_none"
        )]
        signal: Option<u8>,
        #[serde(
            default,
            deserialize_with = "present",
            skip_serializing_if = "Option::is_none"
        )]
        intent: Option<Intent>,
        #[serde(
            default,
            deserialize_with = "present",
            skip_serializing_if = "Option::is_none"
        )]
        error: Option<WireError>,
        frames: ExitFrames,
    },
    /// A non-fatal notice; the channel stays open.
    Error { channel: u32, code: Notice },
    /// The whole connection ends; the server then closes with 4401.
    End {
        intent: Intent,
        #[serde(
            default,
            deserialize_with = "present",
            skip_serializing_if = "Option::is_none"
        )]
        error: Option<WireError>,
    },
}

/// `[A-Za-z0-9][A-Za-z0-9_-]{0,63}`.
fn valid_connection_id(id: &str) -> bool {
    sandbox_protocol::valid_channel_id(id)
}

impl ServerControl {
    /// The bounds the schema checks beyond the field types.
    pub fn is_valid(&self) -> bool {
        match self {
            Self::Hello {
                connection_id,
                sandbox_id,
                limits,
            } => {
                valid_connection_id(connection_id)
                    && (1..=128).contains(&sandbox_id.chars().count())
                    && limits.is_valid()
            }
            Self::Ready { pty, .. } => {
                pty.is_none_or(|size| sandbox_protocol::valid_terminal_size(size.rows, size.cols))
            }
            Self::Ack { seq, .. } => *seq <= MAX_SAFE_INTEGER,
            Self::Eof { frames, .. } => *frames <= MAX_SAFE_INTEGER,
            Self::Exit {
                exit_code,
                signal,
                error,
                frames,
                ..
            } => {
                !(exit_code.is_some() && signal.is_some())
                    && signal.is_none_or(|n| (1..=64).contains(&n))
                    && error.as_ref().is_none_or(WireError::is_valid)
                    && frames.stdout <= MAX_SAFE_INTEGER
                    && frames.stderr <= MAX_SAFE_INTEGER
            }
            Self::Error { .. } => true,
            Self::End { error, .. } => error.as_ref().is_none_or(WireError::is_valid),
        }
    }
}

/// The tag of a data frame's metadata (a literal on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataTag {
    Data,
}

/// The JSON metadata of a binary data frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataMetadata {
    #[serde(rename = "type")]
    pub tag: DataTag,
    pub channel: u32,
    pub stream: DataStream,
    pub seq: u64,
}

impl DataMetadata {
    pub fn new(channel: u32, stream: DataStream, seq: u64) -> Self {
        Self {
            tag: DataTag::Data,
            channel,
            stream,
            seq,
        }
    }
}

/// The one JSON encoder of client-wire frames (typed frames of this module,
/// never relay frames).
fn json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).context("encoding a connect frame")
}

/// Encode a control frame (either direction) as WebSocket text.
pub fn encode_control<T: Serialize>(frame: &T) -> Result<String> {
    String::from_utf8(json(frame)?).context("encoding a connect frame")
}

/// Parse and check a server control frame; `None` for anything malformed.
pub fn parse_server_control(text: &str) -> Option<ServerControl> {
    if text.len() > CONTROL_MAX_BYTES {
        return None;
    }
    serde_json::from_str::<ServerControl>(text)
        .ok()
        .filter(ServerControl::is_valid)
}

/// Parse and check a client control frame; `None` for anything malformed.
pub fn parse_client_control(text: &str) -> Option<ClientControl> {
    if text.len() > CONTROL_MAX_BYTES {
        return None;
    }
    serde_json::from_str::<ClientControl>(text)
        .ok()
        .filter(ClientControl::is_valid)
}

/// Encode a data frame; the body is 1 ..= 32 KiB.
pub fn encode_data(metadata: &DataMetadata, body: &[u8]) -> Result<Vec<u8>> {
    anyhow::ensure!(
        !body.is_empty() && body.len() <= DATA_MAX_BYTES && metadata.seq <= MAX_SAFE_INTEGER,
        "connect data frame is empty or oversized"
    );
    let header = json(metadata)?;
    let length = u32::try_from(header.len()).context("connect data metadata length")?;
    let mut frame = Vec::with_capacity(4 + header.len() + body.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&header);
    frame.extend_from_slice(body);
    Ok(frame)
}

/// The strictly parsed data frame, or `None` for anything malformed (short
/// frame, oversized or invalid metadata, unknown field, empty or oversized
/// body).
pub fn parse_data(frame: &[u8]) -> Option<(DataMetadata, &[u8])> {
    let length = u32::from_be_bytes(frame.get(..4)?.try_into().ok()?);
    let length = usize::try_from(length).ok()?;
    if length > DATA_METADATA_MAX_BYTES {
        return None;
    }
    let header = frame.get(4..4 + length)?;
    let metadata: DataMetadata = serde_json::from_slice(header).ok()?;
    if metadata.seq > MAX_SAFE_INTEGER {
        return None;
    }
    let body = &frame[4 + length..];
    if body.is_empty() || body.len() > DATA_MAX_BYTES {
        return None;
    }
    Some((metadata, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const FIXTURES: &str =
        include_str!("../../../../packages/sandbox-contracts/src/connect-wire-fixtures.json");

    fn fixtures() -> Value {
        serde_json::from_str(FIXTURES).unwrap()
    }

    fn list<'a>(root: &'a Value, path: &[&str]) -> &'a Vec<Value> {
        let mut value = root;
        for key in path {
            value = &value[*key];
        }
        let list = value.as_array().unwrap();
        assert!(!list.is_empty(), "{path:?} has vectors");
        list
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn raw_frame(metadata: &Value, body: &[u8]) -> Vec<u8> {
        let header = metadata.to_string().into_bytes();
        let mut frame = (header.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&header);
        frame.extend_from_slice(body);
        frame
    }

    #[test]
    fn valid_client_vectors_decode_and_encode_identically() {
        let root = fixtures();
        for vector in list(&root, &["client", "valid"]) {
            let parsed = parse_client_control(&vector.to_string())
                .unwrap_or_else(|| panic!("client vector refused: {vector}"));
            let encoded: Value = serde_json::from_str(&encode_control(&parsed).unwrap()).unwrap();
            assert_eq!(&encoded, vector);
        }
    }

    #[test]
    fn invalid_client_vectors_are_refused() {
        let root = fixtures();
        for vector in list(&root, &["client", "invalid"]) {
            assert!(
                parse_client_control(&vector.to_string()).is_none(),
                "client vector accepted: {vector}"
            );
        }
    }

    #[test]
    fn valid_server_vectors_decode_and_encode_identically() {
        let root = fixtures();
        for vector in list(&root, &["server", "valid"]) {
            let parsed = parse_server_control(&vector.to_string())
                .unwrap_or_else(|| panic!("server vector refused: {vector}"));
            let encoded: Value = serde_json::from_str(&encode_control(&parsed).unwrap()).unwrap();
            assert_eq!(&encoded, vector);
        }
    }

    #[test]
    fn invalid_server_vectors_are_refused() {
        let root = fixtures();
        for vector in list(&root, &["server", "invalid"]) {
            assert!(
                parse_server_control(&vector.to_string()).is_none(),
                "server vector accepted: {vector}"
            );
        }
    }

    #[test]
    fn the_hello_vector_is_the_channel_limits_manifest() {
        let root = fixtures();
        let hello = list(&root, &["server", "valid"])
            .iter()
            .find(|v| v["type"] == "hello")
            .unwrap();
        let Some(ServerControl::Hello { limits, .. }) = parse_server_control(&hello.to_string())
        else {
            panic!("hello vector");
        };
        assert_eq!(
            limits.window_frames.pty,
            sandbox_protocol::CHANNEL_PTY_WINDOW_FRAMES
        );
        assert_eq!(
            limits.window_frames.exec,
            sandbox_protocol::CHANNEL_BULK_WINDOW_FRAMES
        );
        assert_eq!(
            limits.data_max_bytes.pty,
            sandbox_protocol::CHANNEL_PTY_DATA_MAX_BYTES as u64
        );
        assert_eq!(limits.data_max_bytes.exec, DATA_MAX_BYTES as u64);
        assert_eq!(
            limits.max_channels,
            sandbox_protocol::CHANNEL_MAX_CHANNELS_PER_CONNECTION as u64
        );
    }

    #[test]
    fn data_vectors_round_trip_identically() {
        let root = fixtures();
        for vector in list(&root, &["data", "valid"]) {
            let metadata: DataMetadata =
                serde_json::from_value(vector["metadata"].clone()).unwrap();
            let body = hex(vector["bodyHex"].as_str().unwrap());
            let frame = encode_data(&metadata, &body).unwrap();
            // The TypeScript encoder's key order (the schema's).
            let header = format!(
                r#"{{"type":"data","channel":{},"stream":{},"seq":{}}}"#,
                vector["metadata"]["channel"],
                vector["metadata"]["stream"],
                vector["metadata"]["seq"]
            );
            let mut expected = (header.len() as u32).to_be_bytes().to_vec();
            expected.extend_from_slice(header.as_bytes());
            expected.extend_from_slice(&body);
            assert_eq!(frame, expected);
            let (parsed, parsed_body) = parse_data(&frame).unwrap();
            assert_eq!(parsed, metadata);
            assert_eq!(parsed_body, body.as_slice());
            assert_eq!(serde_json::to_value(parsed).unwrap(), vector["metadata"]);
        }
    }

    #[test]
    fn invalid_data_metadata_is_refused() {
        let root = fixtures();
        for metadata in list(&root, &["data", "invalidMetadata"]) {
            assert!(
                parse_data(&raw_frame(metadata, &[0])).is_none(),
                "data metadata accepted: {metadata}"
            );
        }
    }

    #[test]
    fn refuses_empty_oversized_and_truncated_data_frames() {
        let metadata =
            serde_json::json!({"type": "data", "channel": 1, "stream": "stdin", "seq": 0});
        assert!(parse_data(&raw_frame(&metadata, &[])).is_none());
        assert!(parse_data(&raw_frame(&metadata, &vec![0; DATA_MAX_BYTES + 1])).is_none());
        assert!(parse_data(&raw_frame(&metadata, &vec![0; DATA_MAX_BYTES])).is_some());
        assert!(parse_data(&[0, 0, 0]).is_none());
        assert!(parse_data(&raw_frame(&metadata, &[0])[..10]).is_none());
        let mut long = (2000_u32).to_be_bytes().to_vec();
        long.extend(vec![b' '; 2001]);
        assert!(parse_data(&long).is_none());
        let meta = DataMetadata::new(1, DataStream::Stdin, 0);
        assert!(encode_data(&meta, &[]).is_err());
        assert!(encode_data(&meta, &vec![0; DATA_MAX_BYTES + 1]).is_err());
    }

    #[test]
    fn optional_fields_are_never_null() {
        for text in [
            r#"{"type":"open","channel":1,"kind":"exec","argv":null}"#,
            r#"{"type":"open","channel":1,"kind":"exec","login":null}"#,
        ] {
            assert!(parse_client_control(text).is_none(), "{text}");
        }
        for text in [
            r#"{"type":"ready","channel":1,"pty":null}"#,
            r#"{"type":"end","intent":"revoked","error":null}"#,
            r#"{"type":"exit","channel":1,"exitCode":null,"frames":{"stdout":0,"stderr":0}}"#,
        ] {
            assert!(parse_server_control(text).is_none(), "{text}");
        }
    }

    #[test]
    fn server_bounds_beyond_types_are_checked() {
        let exit = |extra: &str| {
            format!(r#"{{"type":"exit","channel":1,{extra}"frames":{{"stdout":0,"stderr":0}}}}"#)
        };
        assert!(parse_server_control(&exit(r#""signal":0,"#)).is_none());
        assert!(parse_server_control(&exit(r#""signal":65,"#)).is_none());
        assert!(parse_server_control(&exit(r#""signal":64,"#)).is_some());
        assert!(parse_server_control(&exit(r#""exitCode":2147483648,"#)).is_none());
        assert!(parse_server_control(&exit(r#""exitCode":-2147483648,"#)).is_some());
        assert!(parse_server_control(&exit(r#""error":{"code":"Bad","message":"m"},"#)).is_none());
        assert!(
            parse_server_control(
                r#"{"type":"ack","channel":1,"stream":"stdin","seq":9007199254740992}"#
            )
            .is_none()
        );
        assert!(
            parse_server_control(r#"{"type":"ready","channel":1,"pty":{"rows":513,"cols":80}}"#)
                .is_none()
        );
        let hello = |connection: &str, sandbox: &str| {
            format!(
                r#"{{"type":"hello","connectionId":"{connection}","sandboxId":"{sandbox}","limits":{{"maxChannels":32,"maxPtyChannels":8,"opensPerMinute":120,"windowFrames":{{"pty":8,"exec":32}},"dataMaxBytes":{{"pty":16384,"exec":32768}},"ackStallMs":60000,"pingIntervalMs":20000,"idleTimeoutMs":60000,"openTimeoutMs":30000,"unackedInputBytes":4194304}}}}"#
            )
        };
        assert!(parse_server_control(&hello("c1", "sbx")).is_some());
        assert!(parse_server_control(&hello("-c1", "sbx")).is_none());
        assert!(parse_server_control(&hello("c1", "")).is_none());
        assert!(parse_server_control(&hello("c1", &"s".repeat(129))).is_none());
        assert!(parse_server_control(&"x".repeat(CONTROL_MAX_BYTES + 1)).is_none());
    }
}
