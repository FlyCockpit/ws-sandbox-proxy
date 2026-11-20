//! Interactive channels (`channel.*`) on the host relay, relay protocol 1.0.
//!
//! A channel is a server-minted, non-durable binding of ONE client
//! connection's request (a PTY shell or an exec) to ONE guest process in a
//! sandbox generation. Every frame carries the full [`ChannelFence`]
//! (channel, connection, host, epoch and sandbox target); a peer delivers
//! zero bytes for a frame whose fence does not match the live channel it
//! names. Data travels in binary frames ([`ChannelDataMetadata`]) with a
//! per-channel, per-stream sequence starting at 0 and a credit window per
//! stream (bulk exec and PTY windows differ). Negotiated by the optional
//! `channels` hello capability ([`ChannelsCapability`]).
//!
//! The bounds are shared with the TypeScript peer through
//! `packages/config/src/sandbox-channel-limits.json` (parity-tested below).

use std::borrow::Cow;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::command_limits::json_control_max_bytes;
use crate::frame::FrameError;
use crate::terminal::{valid_terminal_id, valid_terminal_size};

/// Largest channel data body (exec streams).
pub const CHANNEL_BULK_DATA_MAX_BYTES: usize = 32 * 1024;
/// Largest channel data body on a PTY channel (enforced by the endpoints).
pub const CHANNEL_PTY_DATA_MAX_BYTES: usize = 16 * 1024;
/// Unacknowledged frames per stream on an exec channel.
pub const CHANNEL_BULK_WINDOW_FRAMES: u64 = 32;
/// Unacknowledged frames per stream on a PTY channel.
pub const CHANNEL_PTY_WINDOW_FRAMES: u64 = 8;
pub const CHANNEL_MAX_CHANNELS_PER_HOST: usize = 96;
pub const CHANNEL_MAX_PTY_CHANNELS_PER_HOST: usize = 32;
pub const CHANNEL_MAX_CHANNELS_PER_GUEST_CREATOR: usize = 48;
pub const CHANNEL_OPENS_PER_MINUTE_PER_HOST: usize = 600;
pub const CHANNEL_OPENS_PER_MINUTE_PER_GUEST_CREATOR: usize = 300;
pub const CHANNEL_MAX_CHANNELS_PER_CONNECTION: usize = 32;
pub const CHANNEL_MAX_PTY_CHANNELS_PER_CONNECTION: usize = 8;
/// Fence/sequence violations on one channel before it is kill-closed.
pub const CHANNEL_FENCE_VIOLATION_LIMIT: u32 = 3;
pub const CHANNEL_ARGV_MAX_BYTES: usize = 65_536;
pub const CHANNEL_ARGV_MAX_ITEMS: usize = 4096;
pub const CHANNEL_ENV_MAX_ENTRIES: usize = 32;
pub const CHANNEL_ENV_VALUE_MAX_BYTES: usize = 4096;
pub const CHANNEL_TERM_MAX_BYTES: usize = 64;
pub const CHANNEL_CWD_MAX_BYTES: usize = 4096;

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Channel and connection ids: 1..=64 chars of `[A-Za-z0-9][A-Za-z0-9_-]*`,
/// stricter than terminal ids so the guest unit
/// `wssp-chan-<connectionId>-<channelId>.scope` stays short.
pub fn valid_channel_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// What a channel is bound to. Only sandbox guests; never the host.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ChannelTarget {
    Sandbox { sandbox_id: String, generation: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelFence {
    pub channel_id: String,
    pub connection_id: String,
    pub host_id: String,
    pub epoch: u64,
    pub target: ChannelTarget,
}
impl ChannelFence {
    pub fn is_valid(&self) -> bool {
        valid_channel_id(&self.channel_id)
            && valid_channel_id(&self.connection_id)
            && valid_terminal_id(&self.host_id)
            && self.epoch > 0
            && self.epoch <= i32::MAX as u64
            && match &self.target {
                ChannelTarget::Sandbox {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelKind {
    Pty,
    Exec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelStream {
    Stdin,
    Stdout,
    Stderr,
}
impl ChannelStream {
    pub fn is_output(self) -> bool {
        matches!(self, Self::Stdout | Self::Stderr)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelSignal {
    #[serde(rename = "TERM")]
    Term,
    #[serde(rename = "INT")]
    Int,
    #[serde(rename = "HUP")]
    Hup,
    #[serde(rename = "KILL")]
    Kill,
}

/// `client` is a normal close; every other intent is a kill close.
pub type ChannelCloseIntent = crate::terminal::TerminalCloseIntent;

/// Non-fatal refusal of one request on a live channel (`channel.error`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelNotice {
    UnsupportedSignal,
    StateConflict,
}

/// PTY parameters of a `channel.open` with kind `pty`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelPtyParams {
    pub rows: u16,
    pub cols: u16,
    pub term: String,
}
impl ChannelPtyParams {
    pub fn is_valid(&self) -> bool {
        valid_terminal_size(self.rows, self.cols) && valid_channel_term(&self.term)
    }
}

/// The applied PTY size in `channel.ready`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelPtySize {
    pub rows: u16,
    pub cols: u16,
}

/// Output frame counts per stream in `channel.exit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelExitFrames {
    pub stdout: u64,
    pub stderr: u64,
}

/// Optional hello capability: the channel kinds this node can open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelsCapability {
    pub kinds: Vec<ChannelKind>,
}
impl ChannelsCapability {
    pub fn is_valid(&self) -> bool {
        !self.kinds.is_empty()
            && self
                .kinds
                .iter()
                .enumerate()
                .all(|(i, kind)| !self.kinds[..i].contains(kind))
    }
}

/// `TERM`: 1..=64 bytes of `[A-Za-z0-9._+-]`.
pub fn valid_channel_term(term: &str) -> bool {
    (1..=CHANNEL_TERM_MAX_BYTES).contains(&term.len())
        && term
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
}

/// Only locale and colour hints travel as env (`TERM` rides in `pty.term`).
pub fn valid_channel_env_name(name: &str) -> bool {
    let grammar = name
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_uppercase() || b == b'_')
        && name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
    grammar
        && (name == "COLORTERM" || name == "LANG" || (name.len() > 3 && name.starts_with("LC_")))
}

pub fn valid_channel_env(env: &BTreeMap<String, String>) -> bool {
    env.len() <= CHANNEL_ENV_MAX_ENTRIES
        && env.iter().all(|(name, value)| {
            valid_channel_env_name(name)
                && value.len() <= CHANNEL_ENV_VALUE_MAX_BYTES
                && !value.contains('\0')
        })
}

pub fn valid_channel_argv(argv: &[String]) -> bool {
    !argv.is_empty()
        && argv.len() <= CHANNEL_ARGV_MAX_ITEMS
        && argv.iter().map(String::len).sum::<usize>() <= CHANNEL_ARGV_MAX_BYTES
        && argv.iter().all(|arg| !arg.contains('\0'))
}

pub fn valid_channel_cwd(cwd: &str) -> bool {
    cwd.starts_with('/') && cwd.len() <= CHANNEL_CWD_MAX_BYTES && !cwd.contains('\0')
}

/// The `channel.open` field rules, shared by parse and encode.
pub fn valid_channel_open(
    fence: &ChannelFence,
    kind: ChannelKind,
    argv: Option<&[String]>,
    cwd: Option<&str>,
    env: Option<&BTreeMap<String, String>>,
    pty: Option<&ChannelPtyParams>,
) -> bool {
    fence.is_valid()
        && match (kind, pty) {
            (ChannelKind::Pty, Some(pty)) => pty.is_valid(),
            (ChannelKind::Exec, None) => true,
            _ => false,
        }
        && argv.is_none_or(valid_channel_argv)
        && cwd.is_none_or(valid_channel_cwd)
        && env.is_none_or(valid_channel_env)
}

pub(crate) fn valid_channel_seq(seq: u64) -> bool {
    seq <= MAX_SAFE_INTEGER
}

/// The `channel.exit` field rules (receipt-level error code checks run on
/// the daemon parse path as for every other error detail).
pub fn valid_channel_exit(
    fence: &ChannelFence,
    exit_code: Option<i32>,
    signal: Option<u8>,
    error: Option<&crate::ProtocolErrorDetail>,
    frames: &ChannelExitFrames,
) -> bool {
    fence.is_valid()
        && !(exit_code.is_some() && signal.is_some())
        && signal.is_none_or(|s| (1..=64).contains(&s))
        && error.is_none_or(|e| e.message.len() <= crate::RECEIPT_LIMITS.error_bytes)
        && valid_channel_seq(frames.stdout)
        && valid_channel_seq(frames.stderr)
}

/// Body kind of a channel binary frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelDataKind {
    #[serde(rename = "channel.data")]
    Data,
}

/// Metadata of a binary channel data frame. Server→host frames carry
/// `stdin`; host→server frames carry `stdout`/`stderr` (direction is
/// enforced by the endpoints). `seq` is per channel and per stream,
/// starting at 0, with no gaps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelDataMetadata {
    pub r#type: ChannelDataKind,
    pub fence: ChannelFence,
    pub stream: ChannelStream,
    pub seq: u64,
}

#[derive(Deserialize)]
struct Peek<'a> {
    #[serde(borrow, default)]
    r#type: Cow<'a, str>,
}

fn valid_channel_frame(metadata: &ChannelDataMetadata, body: &[u8]) -> Result<(), FrameError> {
    if body.len() > CHANNEL_BULK_DATA_MAX_BYTES {
        return Err(FrameError::BodyTooLarge);
    }
    if body.is_empty() || !metadata.fence.is_valid() || !valid_channel_seq(metadata.seq) {
        return Err(FrameError::InvalidChannelFrame);
    }
    Ok(())
}

pub fn encode_channel_frame(
    metadata: &ChannelDataMetadata,
    body: &[u8],
) -> Result<Vec<u8>, FrameError> {
    valid_channel_frame(metadata, body)?;
    crate::frame::metadata_prefixed_frame(metadata, body)
}

/// `None` when the binary frame is not a channel frame (a command/file stream
/// or terminal frame); otherwise the strictly parsed channel frame. A channel
/// frame with an empty or oversized body or an invalid fence is an error.
pub fn parse_channel_frame(
    frame: &[u8],
) -> Option<Result<(ChannelDataMetadata, Vec<u8>), FrameError>> {
    let head: [u8; 4] = frame.get(..4)?.try_into().ok()?;
    let len = u32::from_be_bytes(head) as usize;
    if len > json_control_max_bytes() {
        return None;
    }
    let meta = frame.get(4..4 + len)?;
    let peek: Peek = serde_json::from_slice(meta).ok()?;
    if peek.r#type != "channel.data" {
        return None;
    }
    let body = &frame[4 + len..];
    Some((|| {
        if body.len() > CHANNEL_BULK_DATA_MAX_BYTES {
            return Err(FrameError::BodyTooLarge);
        }
        let metadata: ChannelDataMetadata =
            serde_json::from_slice(meta).map_err(FrameError::ParseMetadata)?;
        valid_channel_frame(&metadata, body)?;
        Ok((metadata, body.to_vec()))
    })())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fence() -> ChannelFence {
        ChannelFence {
            channel_id: "chan-1".into(),
            connection_id: "conn-1".into(),
            host_id: "host-1".into(),
            epoch: 7,
            target: ChannelTarget::Sandbox {
                sandbox_id: "sbx-1".into(),
                generation: 2,
            },
        }
    }

    #[test]
    fn limits_match_the_shared_manifest() {
        let raw = include_str!("../../../packages/config/src/sandbox-channel-limits.json");
        let json: serde_json::Value = serde_json::from_str(raw).unwrap();
        let n = |key: &str| json[key].as_u64().unwrap();
        for (key, expected) in [
            ("bulkDataMaxBytes", CHANNEL_BULK_DATA_MAX_BYTES as u64),
            ("ptyDataMaxBytes", CHANNEL_PTY_DATA_MAX_BYTES as u64),
            ("bulkWindowFrames", CHANNEL_BULK_WINDOW_FRAMES),
            ("ptyWindowFrames", CHANNEL_PTY_WINDOW_FRAMES),
            ("maxChannelsPerHost", CHANNEL_MAX_CHANNELS_PER_HOST as u64),
            (
                "maxPtyChannelsPerHost",
                CHANNEL_MAX_PTY_CHANNELS_PER_HOST as u64,
            ),
            (
                "maxChannelsPerGuestCreator",
                CHANNEL_MAX_CHANNELS_PER_GUEST_CREATOR as u64,
            ),
            (
                "opensPerMinutePerHost",
                CHANNEL_OPENS_PER_MINUTE_PER_HOST as u64,
            ),
            (
                "opensPerMinutePerGuestCreator",
                CHANNEL_OPENS_PER_MINUTE_PER_GUEST_CREATOR as u64,
            ),
            (
                "maxChannelsPerConnection",
                CHANNEL_MAX_CHANNELS_PER_CONNECTION as u64,
            ),
            (
                "maxPtyChannelsPerConnection",
                CHANNEL_MAX_PTY_CHANNELS_PER_CONNECTION as u64,
            ),
            (
                "fenceViolationLimit",
                u64::from(CHANNEL_FENCE_VIOLATION_LIMIT),
            ),
            ("argvMaxBytes", CHANNEL_ARGV_MAX_BYTES as u64),
            ("argvMaxItems", CHANNEL_ARGV_MAX_ITEMS as u64),
            ("envMaxEntries", CHANNEL_ENV_MAX_ENTRIES as u64),
            ("envValueMaxBytes", CHANNEL_ENV_VALUE_MAX_BYTES as u64),
            ("termMaxBytes", CHANNEL_TERM_MAX_BYTES as u64),
            ("cwdMaxBytes", CHANNEL_CWD_MAX_BYTES as u64),
        ] {
            assert_eq!(n(key), expected, "{key}");
        }
        assert_eq!(json.as_object().unwrap().len(), 18, "unchecked limit key");
    }

    #[test]
    fn channel_frames_round_trip_and_other_frames_are_not_channel_frames() {
        let metadata = ChannelDataMetadata {
            r#type: ChannelDataKind::Data,
            fence: fence(),
            stream: ChannelStream::Stdout,
            seq: 3,
        };
        let encoded = encode_channel_frame(&metadata, b"hi\n").unwrap();
        let (parsed, body) = parse_channel_frame(&encoded).unwrap().unwrap();
        assert_eq!(parsed, metadata);
        assert_eq!(body, b"hi\n");
        let terminal = crate::encode_terminal_frame(
            &crate::TerminalDataMetadata {
                r#type: crate::TerminalDataKind::Data,
                fence: crate::TerminalFence {
                    session_id: "t".into(),
                    operation_id: "o".into(),
                    host_id: "h".into(),
                    epoch: 1,
                    target: crate::TerminalTargetV11::Sandbox {
                        sandbox_id: "s".into(),
                        generation: 1,
                    },
                },
                sequence: 0,
            },
            b"x",
        )
        .unwrap();
        assert!(parse_channel_frame(&terminal).is_none());
        assert!(crate::parse_terminal_frame(&encoded).is_none());
    }

    #[test]
    fn oversized_empty_and_unfenced_channel_frames_are_refused() {
        let metadata = ChannelDataMetadata {
            r#type: ChannelDataKind::Data,
            fence: fence(),
            stream: ChannelStream::Stdin,
            seq: 0,
        };
        assert!(encode_channel_frame(&metadata, &[0; CHANNEL_BULK_DATA_MAX_BYTES + 1]).is_err());
        assert!(encode_channel_frame(&metadata, &[]).is_err());
        let ok = encode_channel_frame(&metadata, &[1; CHANNEL_BULK_DATA_MAX_BYTES]).unwrap();
        let mut oversized = ok.clone();
        oversized.push(0);
        assert!(parse_channel_frame(&oversized).unwrap().is_err());
        let frame_with = |meta: &serde_json::Value| {
            let meta = serde_json::to_vec(meta).unwrap();
            let mut frame = (meta.len() as u32).to_be_bytes().to_vec();
            frame.extend_from_slice(&meta);
            frame.push(b'x');
            frame
        };
        let value = serde_json::to_value(&metadata).unwrap();
        for (path, bad) in [
            ("channelId", serde_json::json!("a".repeat(65))),
            ("connectionId", serde_json::json!("-x")),
            ("epoch", serde_json::json!(0)),
        ] {
            let mut meta = value.clone();
            meta["fence"][path] = bad;
            assert!(parse_channel_frame(&frame_with(&meta)).unwrap().is_err());
        }
        let mut meta = value.clone();
        meta["seq"] = serde_json::json!(9_007_199_254_740_992_u64);
        assert!(parse_channel_frame(&frame_with(&meta)).unwrap().is_err());
        let mut meta = value.clone();
        meta["extra"] = serde_json::json!(1);
        assert!(parse_channel_frame(&frame_with(&meta)).unwrap().is_err());
        let mut meta = value;
        meta["fence"]["target"] = serde_json::json!({"kind": "host"});
        assert!(parse_channel_frame(&frame_with(&meta)).unwrap().is_err());
    }

    #[test]
    fn ids_env_term_and_capability_follow_the_grammar() {
        assert!(valid_channel_id(&"a".repeat(64)));
        assert!(!valid_channel_id(&"a".repeat(65)));
        assert!(!valid_channel_id("_a"));
        assert!(!valid_channel_id("a.b"));
        assert!(valid_channel_term("xterm-256color"));
        assert!(!valid_channel_term(""));
        assert!(!valid_channel_term("xterm 256"));
        assert!(!valid_channel_term(&"x".repeat(65)));
        for name in ["LANG", "COLORTERM", "LC_ALL", "LC_CTYPE"] {
            assert!(valid_channel_env_name(name), "{name}");
        }
        for name in ["TERM", "PATH", "LC_", "lang", "LD_PRELOAD", "LC_all"] {
            assert!(!valid_channel_env_name(name), "{name}");
        }
        assert!(
            ChannelsCapability {
                kinds: vec![ChannelKind::Pty, ChannelKind::Exec]
            }
            .is_valid()
        );
        assert!(!ChannelsCapability { kinds: vec![] }.is_valid());
        assert!(
            !ChannelsCapability {
                kinds: vec![ChannelKind::Pty, ChannelKind::Pty]
            }
            .is_valid()
        );
    }
}
