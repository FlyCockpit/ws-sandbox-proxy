//! Terminal (PTY) channel on the host relay (, relay protocol 1.0).
//!
//! A terminal session is a server-minted, non-durable binding of ONE browser
//! attachment to ONE host PTY. Every frame carries the full [`TerminalFence`]
//! (session, operation, host, sandbox, generation and connection epoch); a
//! peer delivers zero bytes for a frame whose fence does not match the live
//! session it names. Data travels in binary frames ([`TerminalDataMetadata`])
//! with a per-session, per-direction sequence starting at 0. Flow control is
//! a credit window per direction, independent of the command and file
//! channels: a sender never has more than the window's frames unacknowledged.
//!
//! The bounds are shared with the TypeScript peer through
//! `packages/config/src/sandbox-terminal-limits.json` (parity-tested below).

use std::borrow::Cow;

use serde::{Deserialize, Serialize};

use crate::command_limits::json_control_max_bytes;
use crate::frame::FrameError;
use crate::ids::valid_terminal_id;

/// Terminal uses the sole supported relay version. Runtime capability and
/// session authority still gate every terminal attachment.
pub const TERMINAL_PROTOCOL_VERSION: &str = crate::version::SANDBOX_RELAY_PROTOCOL_VERSION;
/// Active (attached) sessions per sandbox on the server. A new attach
/// REPLACES the active one (the old attachment closes with 4401 `replaced`).
pub const TERMINAL_MAX_ACTIVE_SESSIONS_PER_SANDBOX: usize = 1;
/// Live PTYs per sandbox on the host: the active one plus one still closing
/// (a close can take ~12–17 s), so a replacement is not refused for capacity.
pub const TERMINAL_MAX_LIVE_SESSIONS_PER_SANDBOX: usize = 2;
/// Terminal sessions per host connection (server) and live PTYs per host
/// daemon process (host), counted until the PTY is confirmed reaped.
pub const TERMINAL_MAX_SESSIONS_PER_HOST: usize = 8;
pub const TERMINAL_RESERVED_HOST_SESSIONS: usize = 2;
pub const TERMINAL_MAX_GUEST_SESSIONS_PER_HOST: usize = 6;
pub const TERMINAL_MAX_SESSIONS_PER_GUEST_CREATOR: usize = 3;
pub const TERMINAL_RESERVED_HOST_OPENS_PER_MINUTE: usize = 2;
pub const TERMINAL_OPENS_PER_MINUTE_PER_GUEST_CREATOR: usize = 14;
pub const TERMINAL_HOST_INPUT_IDLE_MS: u64 = 600_000;
pub const TERMINAL_HOST_MAX_LIFETIME_MS: u64 = 3_600_000;
/// A guest (sandbox) PTY's lifetime from its first open
/// (`sandbox_runtime::PTY_DEFAULT_SESSION`); reattaching never extends it.
pub const TERMINAL_GUEST_MAX_LIFETIME_MS: u64 = 14_400_000;
/// WP8 (D5): how long a node keeps a lost sandbox PTY detached for
/// `terminal.resume` (`terminal_resume_grace`): default and ceiling.
pub const TERMINAL_RESUME_GRACE_DEFAULT_MS: u64 = 120_000;
pub const TERMINAL_RESUME_GRACE_MAX_MS: u64 = 600_000;
/// The shortest grace a node may advertise.
pub const TERMINAL_RESUME_GRACE_MIN_MS: u64 = 1_000;
/// Session opens per host in any rolling 60 s window (both peers).
pub const TERMINAL_OPENS_PER_MINUTE_PER_HOST: usize = 30;
/// Largest terminal data body (one PTY output chunk).
pub const TERMINAL_DATA_MAX_BYTES: usize = 16 * 1024;
/// Host→server output frames in flight per session before an ACK.
pub const TERMINAL_OUTPUT_WINDOW_FRAMES: u64 = 8;
/// Server→host input frames in flight per session before an ACK.
pub const TERMINAL_INPUT_WINDOW_FRAMES: u64 = 8;
/// Server-side queued input per session while the input window is full.
pub const TERMINAL_INPUT_QUEUE_MAX_BYTES: usize = 64 * 1024;
/// Server→browser buffered bytes before the attachment is detached with an
/// explicit backpressure error.
pub const TERMINAL_ATTACHMENT_BUFFERED_MAX_BYTES: usize = 1024 * 1024;
/// Fence/sequence violations on one session before it is closed.
pub const TERMINAL_FENCE_VIOLATION_LIMIT: u32 = 3;
/// Open must be answered (ready or exit) within this bound.
pub const TERMINAL_OPEN_TIMEOUT_MS: u64 = 30_000;
/// Recently ended session ids remembered per connection, so in-flight frames
/// for them are dropped silently instead of being audited as foreign.
pub const TERMINAL_ENDED_SESSION_TOMBSTONES: usize = 64;
/// Final WebSocket close code of a browser terminal attachment.
pub const TERMINAL_CLOSE_CODE: u16 = 4401;
/// Terminal dimensions (inclusive); mirrors the runtime's PTY bounds.
pub const TERMINAL_MIN_DIMENSION: u16 = 1;
pub const TERMINAL_MAX_ROWS: u16 = 512;
pub const TERMINAL_MAX_COLS: u16 = 1024;

/// Live relay consumers use the sole strict typed-target fence.
pub type TerminalFence = TerminalFenceV11;

pub fn valid_terminal_size(rows: u16, cols: u16) -> bool {
    (TERMINAL_MIN_DIMENSION..=TERMINAL_MAX_ROWS).contains(&rows)
        && (TERMINAL_MIN_DIMENSION..=TERMINAL_MAX_COLS).contains(&cols)
}

/// Why a terminal session ended when it did not end by the shell exiting.
/// Explicit on the wire (`terminal.close` / `terminal.exit`), so a peer can
/// tell an intentional close from a transport loss.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalCloseIntent {
    /// The attached user asked to close.
    Client,
    /// The browser attachment went away without asking.
    Detached,
    /// A newer attach for the same sandbox replaced this one.
    Replaced,
    /// The browser could not keep up: buffered output exceeded the bound.
    Backpressure,
    /// Credential, session or ownership authority ended.
    Revoked,
    /// A newer generation, stop or kill superseded the bound sandbox.
    Superseded,
    /// Repeated fence or sequence violations.
    ProtocolViolation,
    /// The host relay connection was lost or replaced.
    HostDisconnected,
    /// The session or the sandbox lease outlived its bound.
    Expired,
    /// The sandbox VM was stopped.
    SandboxStopped,
    /// The sandbox VM was destroyed.
    SandboxDestroyed,
    /// A stop or destroy was attempted but not confirmed.
    LifecycleUnconfirmed,
    /// The server or node daemon is shutting down.
    Shutdown,
}

/// Body kind of a terminal binary frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TerminalDataKind {
    #[serde(rename = "terminal.data")]
    Data,
}

/// Metadata of a binary terminal data frame. Server→host frames carry
/// input; host→server frames carry output. `sequence` is per session and
/// per direction, starting at 0, with no gaps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerminalDataMetadata {
    pub r#type: TerminalDataKind,
    pub fence: TerminalFence,
    pub sequence: u64,
}

/// Only the `type` field, borrowed from the frame unless it has escapes. A
/// missing `type` reads as empty; a `null` or non-string one fails the peek;
/// either way the frame is not a terminal frame.
#[derive(Deserialize)]
struct Peek<'a> {
    #[serde(borrow, default)]
    r#type: Cow<'a, str>,
}

pub fn encode_terminal_frame(
    metadata: &TerminalDataMetadata,
    body: &[u8],
) -> Result<Vec<u8>, FrameError> {
    if body.len() > TERMINAL_DATA_MAX_BYTES {
        return Err(FrameError::BodyTooLarge);
    }
    if body.is_empty() || !metadata.fence.is_valid() || metadata.sequence > 9_007_199_254_740_991 {
        return Err(FrameError::InvalidTerminalFrame);
    }
    crate::frame::metadata_prefixed_frame(metadata, body)
}

/// `None` when the binary frame is not a terminal frame (a command/file
/// stream frame); otherwise the strictly parsed terminal frame. A terminal
/// frame with an empty or oversized body or an invalid fence is an error.
pub fn parse_terminal_frame(
    frame: &[u8],
) -> Option<Result<(TerminalDataMetadata, Vec<u8>), FrameError>> {
    let head: [u8; 4] = frame.get(..4)?.try_into().ok()?;
    let len = u32::from_be_bytes(head) as usize;
    if len > json_control_max_bytes() {
        return None;
    }
    let meta = frame.get(4..4 + len)?;
    let peek: Peek = serde_json::from_slice(meta).ok()?;
    if peek.r#type != "terminal.data" {
        return None;
    }
    let body = &frame[4 + len..];
    Some((|| {
        if body.len() > TERMINAL_DATA_MAX_BYTES {
            return Err(FrameError::BodyTooLarge);
        }
        let metadata: TerminalDataMetadata =
            serde_json::from_slice(meta).map_err(FrameError::ParseMetadata)?;
        if body.is_empty()
            || !metadata.fence.is_valid()
            || metadata.sequence > 9_007_199_254_740_991
        {
            return Err(FrameError::InvalidTerminalFrame);
        }
        Ok((metadata, body.to_vec()))
    })())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fence() -> TerminalFence {
        TerminalFence {
            session_id: "term-1".into(),
            operation_id: "termop-1".into(),
            host_id: "host-1".into(),
            target: crate::TerminalTargetV11::Sandbox {
                sandbox_id: "sbx-1".into(),
                generation: 2,
            },
            epoch: 7,
        }
    }

    #[test]
    fn limits_match_the_shared_manifest() {
        let raw = include_str!("../../../packages/config/src/sandbox-terminal-limits.json");
        let json: serde_json::Value = serde_json::from_str(raw).unwrap();
        let n = |key: &str| json[key].as_u64().unwrap();
        assert_eq!(json["protocolVersion"], TERMINAL_PROTOCOL_VERSION);
        assert_eq!(
            n("maxActiveSessionsPerSandbox"),
            TERMINAL_MAX_ACTIVE_SESSIONS_PER_SANDBOX as u64
        );
        assert_eq!(
            n("maxLiveSessionsPerSandbox"),
            TERMINAL_MAX_LIVE_SESSIONS_PER_SANDBOX as u64
        );
        assert_eq!(
            n("maxSessionsPerHost"),
            TERMINAL_MAX_SESSIONS_PER_HOST as u64
        );
        assert_eq!(
            n("opensPerMinutePerHost"),
            TERMINAL_OPENS_PER_MINUTE_PER_HOST as u64
        );
        assert_eq!(n("dataMaxBytes"), TERMINAL_DATA_MAX_BYTES as u64);
        assert_eq!(n("outputWindowFrames"), TERMINAL_OUTPUT_WINDOW_FRAMES);
        assert_eq!(n("inputWindowFrames"), TERMINAL_INPUT_WINDOW_FRAMES);
        assert_eq!(
            n("inputQueueMaxBytes"),
            TERMINAL_INPUT_QUEUE_MAX_BYTES as u64
        );
        assert_eq!(
            n("attachmentBufferedMaxBytes"),
            TERMINAL_ATTACHMENT_BUFFERED_MAX_BYTES as u64
        );
        assert_eq!(
            n("fenceViolationLimit"),
            u64::from(TERMINAL_FENCE_VIOLATION_LIMIT)
        );
        assert_eq!(n("openTimeoutMs"), TERMINAL_OPEN_TIMEOUT_MS);
        assert_eq!(
            n("endedSessionTombstones"),
            TERMINAL_ENDED_SESSION_TOMBSTONES as u64
        );
        assert_eq!(n("closeCode"), u64::from(TERMINAL_CLOSE_CODE));
        assert_eq!(n("maxRows"), u64::from(TERMINAL_MAX_ROWS));
        assert_eq!(n("maxCols"), u64::from(TERMINAL_MAX_COLS));
        for (key, expected) in [
            (
                "reservedHostSessions",
                TERMINAL_RESERVED_HOST_SESSIONS as u64,
            ),
            (
                "maxGuestSessionsPerHost",
                TERMINAL_MAX_GUEST_SESSIONS_PER_HOST as u64,
            ),
            (
                "maxSessionsPerGuestCreator",
                TERMINAL_MAX_SESSIONS_PER_GUEST_CREATOR as u64,
            ),
            (
                "reservedHostOpensPerMinute",
                TERMINAL_RESERVED_HOST_OPENS_PER_MINUTE as u64,
            ),
            (
                "opensPerMinutePerGuestCreator",
                TERMINAL_OPENS_PER_MINUTE_PER_GUEST_CREATOR as u64,
            ),
            ("hostInputIdleMs", TERMINAL_HOST_INPUT_IDLE_MS),
            ("hostMaxLifetimeMs", TERMINAL_HOST_MAX_LIFETIME_MS),
            ("guestMaxLifetimeMs", TERMINAL_GUEST_MAX_LIFETIME_MS),
            ("resumeGraceDefaultMs", TERMINAL_RESUME_GRACE_DEFAULT_MS),
            ("resumeGraceMaxMs", TERMINAL_RESUME_GRACE_MAX_MS),
        ] {
            assert_eq!(n(key), expected, "{key}");
        }
        assert_eq!(json.as_object().unwrap().len(), 26, "unchecked limit key");
    }

    #[test]
    fn terminal_frames_round_trip_and_stream_frames_are_not_terminal() {
        let metadata = TerminalDataMetadata {
            r#type: TerminalDataKind::Data,
            fence: fence(),
            sequence: 3,
        };
        let encoded = encode_terminal_frame(&metadata, b"ls\r").unwrap();
        let (parsed, body) = parse_terminal_frame(&encoded).unwrap().unwrap();
        assert_eq!(parsed, metadata);
        assert_eq!(body, b"ls\r");
        let stream = crate::encode_binary_frame(
            &crate::StreamBinaryMetadata {
                r#type: crate::StreamKind::Chunk,
                stream_id: "s".into(),
                operation_id: "op".into(),
                generation: 1,
                attempt: 1,
                sequence: 0,
                offset: None,
                gap_start: None,
                flags: None,
                final_chunk: None,
            },
            b"x",
        )
        .unwrap();
        assert!(parse_terminal_frame(&stream).is_none());
    }

    #[test]
    fn terminal_encoding_matches_a_separately_serialized_prefix() {
        let metadata = TerminalDataMetadata {
            r#type: TerminalDataKind::Data,
            fence: fence(),
            sequence: 5,
        };
        let json = serde_json::to_vec(&metadata).unwrap();
        let mut expected = (json.len() as u32).to_be_bytes().to_vec();
        expected.extend_from_slice(&json);
        expected.extend_from_slice(b"ls\r");
        assert_eq!(encode_terminal_frame(&metadata, b"ls\r").unwrap(), expected);
    }

    #[test]
    fn the_type_peek_reads_escaped_missing_and_null_types() {
        let metadata = TerminalDataMetadata {
            r#type: TerminalDataKind::Data,
            fence: fence(),
            sequence: 0,
        };
        let frame_with = |meta: &[u8]| {
            let mut frame = (meta.len() as u32).to_be_bytes().to_vec();
            frame.extend_from_slice(meta);
            frame.push(b'x');
            frame
        };
        let json = serde_json::to_string(&metadata).unwrap();
        // An escaped type is still the terminal type.
        let escaped = json.replacen("terminal.data", "terminal\\u002edata", 1);
        assert_ne!(escaped, json);
        let (parsed, _) = parse_terminal_frame(&frame_with(escaped.as_bytes()))
            .unwrap()
            .unwrap();
        assert_eq!(parsed, metadata);
        // A missing, null or non-string type is not a terminal frame.
        assert!(parse_terminal_frame(&frame_with(br#"{"streamId":"s"}"#)).is_none());
        assert!(parse_terminal_frame(&frame_with(br#"{"type":null}"#)).is_none());
        assert!(parse_terminal_frame(&frame_with(br#"{"type":1}"#)).is_none());
    }

    #[test]
    fn oversized_empty_and_unfenced_terminal_frames_are_refused() {
        let metadata = TerminalDataMetadata {
            r#type: TerminalDataKind::Data,
            fence: fence(),
            sequence: 0,
        };
        assert!(encode_terminal_frame(&metadata, &[0; TERMINAL_DATA_MAX_BYTES + 1]).is_err());
        assert!(encode_terminal_frame(&metadata, &[]).is_err());
        let ok = encode_terminal_frame(&metadata, &[1; TERMINAL_DATA_MAX_BYTES]).unwrap();
        let mut oversized = ok.clone();
        oversized.push(0);
        assert!(parse_terminal_frame(&oversized).unwrap().is_err());
        let meta_len = u32::from_be_bytes(ok[..4].try_into().unwrap()) as usize;
        assert!(parse_terminal_frame(&ok[..4 + meta_len]).unwrap().is_err());
        for bad in [
            TerminalFence {
                session_id: "../x".into(),
                ..fence()
            },
            TerminalFence {
                target: TerminalTargetV11::Sandbox {
                    sandbox_id: "sbx-1".into(),
                    generation: 0,
                },
                ..fence()
            },
            TerminalFence {
                host_id: String::new(),
                ..fence()
            },
        ] {
            let meta = serde_json::to_vec(&TerminalDataMetadata {
                fence: bad,
                ..metadata.clone()
            })
            .unwrap();
            let mut frame = (meta.len() as u32).to_be_bytes().to_vec();
            frame.extend_from_slice(&meta);
            frame.push(b'x');
            assert!(parse_terminal_frame(&frame).unwrap().is_err());
        }
        // Unknown metadata fields are refused, not ignored.
        let mut value = serde_json::to_value(&metadata).unwrap();
        value["extra"] = serde_json::json!(1);
        let meta = serde_json::to_vec(&value).unwrap();
        let mut frame = (meta.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&meta);
        frame.push(b'x');
        assert!(parse_terminal_frame(&frame).unwrap().is_err());
    }

    #[test]
    fn sizes_and_ids_follow_the_runtime_grammar() {
        assert!(valid_terminal_size(1, 1));
        assert!(valid_terminal_size(512, 1024));
        assert!(!valid_terminal_size(0, 80));
        assert!(!valid_terminal_size(513, 80));
        assert!(!valid_terminal_size(24, 1025));
        assert!(valid_terminal_id("a-b_C9"));
        assert!(!valid_terminal_id("-a"));
        assert!(!valid_terminal_id(&"a".repeat(129)));
        assert!(!valid_terminal_id("a b"));
    }
}

/// Final integrated 1.0 target contract. No flat/default/combined variant.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum TerminalTargetV11 {
    Host {},
    Sandbox { sandbox_id: String, generation: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerminalFenceV11 {
    pub session_id: String,
    pub operation_id: String,
    pub host_id: String,
    pub epoch: u64,
    pub target: TerminalTargetV11,
}
impl TerminalFenceV11 {
    pub fn is_valid(&self) -> bool {
        [&self.session_id, &self.operation_id, &self.host_id]
            .iter()
            .all(|id| valid_terminal_id(id))
            && self.epoch > 0
            && self.epoch <= i32::MAX as u64
            && match &self.target {
                TerminalTargetV11::Host {} => true,
                TerminalTargetV11::Sandbox {
                    sandbox_id,
                    generation,
                } => {
                    valid_terminal_id(sandbox_id)
                        && *generation > 0
                        && *generation <= i32::MAX as u64
                }
            }
    }
}

/// Optional hello capability (`terminalResume`): the node keeps a sandbox PTY whose
/// relay connection was lost detached for `graceMs` and accepts
/// `terminal.resume` for it after its next `reconcile.complete`. Without this
/// runtime feature a terminal ends with its socket. The server echoes
/// `terminalResume: true` in
/// `hello.ok` only to a daemon that offered it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerminalResumeCapabilityV11 {
    pub grace_ms: u64,
}
impl TerminalResumeCapabilityV11 {
    pub fn is_valid(&self) -> bool {
        (TERMINAL_RESUME_GRACE_MIN_MS..=TERMINAL_RESUME_GRACE_MAX_MS).contains(&self.grace_ms)
    }
}

/// `terminal.resume` is valid only for a sandbox target (host-target
/// terminals are never detached), a valid size and a scalar sequence.
pub fn valid_terminal_resume(
    request_id: &str,
    fence: &TerminalFenceV11,
    next_output_seq: u64,
    rows: u16,
    cols: u16,
) -> bool {
    valid_terminal_id(request_id)
        && fence.is_valid()
        && matches!(fence.target, TerminalTargetV11::Sandbox { .. })
        && next_output_seq <= 9_007_199_254_740_991
        && valid_terminal_size(rows, cols)
}

/// Required only on host opens; never supplied as a substitute for live policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostTerminalOpenPolicyV11 {
    pub policy_revision: u64,
    pub proof_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all_fields = "camelCase", deny_unknown_fields)]
pub enum TerminalControlV11 {
    #[serde(rename = "terminal.exit")]
    Exit {
        fence: TerminalFenceV11,
        reaped: bool,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "present_terminal_field"
        )]
        request_id: Option<String>,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "present_terminal_field"
        )]
        exit_code: Option<i32>,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "present_terminal_field"
        )]
        intent: Option<TerminalCloseIntent>,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "present_terminal_field"
        )]
        error: Option<crate::ProtocolErrorDetail>,
    },
    #[serde(rename = "terminal.open")]
    Open {
        request_id: String,
        fence: TerminalFenceV11,
        rows: u16,
        cols: u16,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "present_terminal_field"
        )]
        host_policy: Option<HostTerminalOpenPolicyV11>,
        /// Guest opens only: the shell's working directory (the revision's
        /// default cwd); absent means the guest home.
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "present_terminal_field"
        )]
        cwd: Option<String>,
    },
    #[serde(rename = "terminal.ready")]
    Ready {
        request_id: String,
        fence: TerminalFenceV11,
        rows: u16,
        cols: u16,
        /// Only on the answer to `terminal.resume`: the sequence of the next
        /// output frame (>= the requested `nextOutputSeq`; greater means the
        /// detached ring lost output).
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "present_terminal_field"
        )]
        output_seq: Option<u64>,
    },
    /// WP8: reattach a detached sandbox PTY. `fence.sessionId` is the
    /// terminal id the PTY was opened with; the fence's operation id and
    /// epoch are new (this connection's). Sent only to a node that negotiated
    /// `terminalResume`, only after its `reconcile.complete`. Answered by
    /// `terminal.ready` (with `outputSeq`) or `terminal.exit`.
    #[serde(rename = "terminal.resume")]
    Resume {
        request_id: String,
        fence: TerminalFenceV11,
        next_output_seq: u64,
        rows: u16,
        cols: u16,
    },
    #[serde(rename = "terminal.resize")]
    Resize {
        request_id: String,
        fence: TerminalFenceV11,
        rows: u16,
        cols: u16,
    },
    #[serde(rename = "terminal.ack")]
    Ack {
        fence: TerminalFenceV11,
        sequence: u64,
    },
    #[serde(rename = "terminal.close")]
    Close {
        request_id: String,
        fence: TerminalFenceV11,
        intent: TerminalCloseIntent,
    },
    #[serde(rename = "terminal.data")]
    Data {
        fence: TerminalFenceV11,
        sequence: u64,
    },
}
impl TerminalControlV11 {
    pub fn is_valid(&self) -> bool {
        match self {
            Self::Exit {
                fence,
                request_id,
                error,
                ..
            } => {
                fence.is_valid()
                    && request_id.as_deref().is_none_or(valid_terminal_id)
                    && error.as_ref().is_none_or(|e| {
                        e.message.len() <= crate::RECEIPT_LIMITS.error_bytes
                            && e.reason.is_none_or(|reason| reason.fits_wire(&e.code))
                    })
            }
            Self::Open {
                request_id,
                fence,
                rows,
                cols,
                host_policy,
                cwd,
            } => {
                valid_terminal_id(request_id)
                    && fence.is_valid()
                    && valid_terminal_size(*rows, *cols)
                    && match (&fence.target, host_policy) {
                        (TerminalTargetV11::Host {}, Some(policy)) => {
                            policy.policy_revision <= 9_007_199_254_740_991 && cwd.is_none()
                        }
                        (TerminalTargetV11::Sandbox { .. }, None) => {
                            cwd.as_deref().is_none_or(crate::startup::valid_cwd)
                        }
                        _ => false,
                    }
            }
            Self::Ready {
                request_id,
                fence,
                rows,
                cols,
                output_seq,
            } => {
                valid_terminal_id(request_id)
                    && fence.is_valid()
                    && valid_terminal_size(*rows, *cols)
                    && output_seq.is_none_or(|seq| seq <= 9_007_199_254_740_991)
            }
            Self::Resume {
                request_id,
                fence,
                next_output_seq,
                rows,
                cols,
            } => valid_terminal_resume(request_id, fence, *next_output_seq, *rows, *cols),
            Self::Resize {
                request_id,
                fence,
                rows,
                cols,
            } => {
                valid_terminal_id(request_id)
                    && fence.is_valid()
                    && valid_terminal_size(*rows, *cols)
            }
            Self::Ack { fence, sequence } | Self::Data { fence, sequence } => {
                fence.is_valid() && *sequence <= 9_007_199_254_740_991
            }
            Self::Close {
                request_id, fence, ..
            } => valid_terminal_id(request_id) && fence.is_valid(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerminalDataMetadataV11 {
    pub r#type: TerminalDataKind,
    pub fence: TerminalFenceV11,
    pub sequence: u64,
}

pub fn encode_terminal_frame_v11(
    metadata: &TerminalDataMetadataV11,
    body: &[u8],
) -> Result<Vec<u8>, FrameError> {
    if body.len() > TERMINAL_DATA_MAX_BYTES {
        return Err(FrameError::BodyTooLarge);
    }
    if body.is_empty() || !metadata.fence.is_valid() || metadata.sequence > 9_007_199_254_740_991 {
        return Err(FrameError::InvalidTerminalFrame);
    }
    let meta = serde_json::to_vec(metadata).map_err(FrameError::SerializeMetadata)?;
    if meta.len() > json_control_max_bytes() {
        return Err(FrameError::MetadataTooLarge);
    }
    let len = u32::try_from(meta.len()).map_err(|_| FrameError::MetadataLengthOverflow)?;
    let mut frame = len.to_be_bytes().to_vec();
    frame.extend_from_slice(&meta);
    frame.extend_from_slice(body);
    Ok(frame)
}

pub fn parse_terminal_frame_v11(
    frame: &[u8],
) -> Result<(TerminalDataMetadataV11, Vec<u8>), FrameError> {
    let head: [u8; 4] = frame
        .get(..4)
        .and_then(|v| v.try_into().ok())
        .ok_or(FrameError::InvalidTerminalFrame)?;
    let len = u32::from_be_bytes(head) as usize;
    if len > json_control_max_bytes() {
        return Err(FrameError::MetadataTooLarge);
    }
    let meta = frame
        .get(4..4 + len)
        .ok_or(FrameError::InvalidTerminalFrame)?;
    let metadata: TerminalDataMetadataV11 =
        serde_json::from_slice(meta).map_err(FrameError::ParseMetadata)?;
    let body = &frame[4 + len..];
    // One validation path for encoding and parsing.
    encode_terminal_frame_v11(&metadata, body)?;
    Ok((metadata, body.to_vec()))
}

// An omitted optional field differs from an explicitly null field on the wire.
pub(crate) fn present_terminal_field<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}
