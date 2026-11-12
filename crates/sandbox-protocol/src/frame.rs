//! Length-prefixed JSON metadata + binary payload frames for multiplexed streams.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::command_limits::json_control_max_bytes;
pub const SANDBOX_BINARY_CHUNK_MAX_BYTES: usize = 1024 * 1024;
pub const SANDBOX_STREAM_WINDOW_CHUNKS: usize = 4;
/// Minimum command-output chunk size and the safe ceiling before hello.
pub const SANDBOX_OUTPUT_CHUNK_MIN_BYTES: usize = 8 * 1024;
/// Largest command-output chunk this daemon offers in its hello.
pub const SANDBOX_OUTPUT_CHUNK_OFFER_BYTES: usize = 64 * 1024;

/// A valid output chunk ceiling on the wire: between the minimum size and the
/// binary frame cap (both hello offer and `hello.ok` answer).
pub fn valid_output_chunk_bytes(bytes: u32) -> bool {
    (SANDBOX_OUTPUT_CHUNK_MIN_BYTES..=SANDBOX_BINARY_CHUNK_MAX_BYTES).contains(&(bytes as usize))
}

/// The output chunk size a daemon that offered `offer` uses after a
/// `hello.ok` carrying `answer`. Before hello the minimum is used; after
/// hello the required answer never exceeds the daemon offer.
pub fn negotiated_output_chunk_bytes(offer: usize, answer: Option<u32>) -> usize {
    answer.map_or(SANDBOX_OUTPUT_CHUNK_MIN_BYTES, |bytes| {
        (bytes as usize).clamp(
            SANDBOX_OUTPUT_CHUNK_MIN_BYTES,
            offer.max(SANDBOX_OUTPUT_CHUNK_MIN_BYTES),
        )
    })
}
pub const SANDBOX_LIST_MAX_DEPTH: u32 = 8;
pub const SANDBOX_LIST_MAX_ENTRIES: u32 = 2000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamKind {
    #[serde(rename = "stream.chunk")]
    Chunk,
    #[serde(rename = "stream.end")]
    End,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StreamChunkFlags {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_upload: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_download: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdin: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StreamBinaryMetadata {
    pub r#type: StreamKind,
    pub stream_id: String,
    pub operation_id: String,
    pub generation: u64,
    pub attempt: u64,
    pub sequence: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gap_start: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<StreamChunkFlags>,
    #[serde(rename = "final", skip_serializing_if = "Option::is_none")]
    pub final_chunk: Option<bool>,
}

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("binary frame is missing metadata length")]
    MissingMetadataLength,
    #[error("binary frame metadata exceeds {} bytes", json_control_max_bytes())]
    MetadataTooLarge,
    #[error("binary frame metadata length is invalid")]
    InvalidMetadataLength,
    #[error("binary body chunk exceeds {SANDBOX_BINARY_CHUNK_MAX_BYTES} bytes")]
    BodyTooLarge,
    #[error("failed to serialize frame metadata: {0}")]
    SerializeMetadata(serde_json::Error),
    #[error("failed to parse frame metadata: {0}")]
    ParseMetadata(serde_json::Error),
    #[error("metadata length does not fit in u32")]
    MetadataLengthOverflow,
    #[error("terminal frame body is empty or its fence is invalid")]
    InvalidTerminalFrame,
}

pub fn encode_binary_frame(
    metadata: &StreamBinaryMetadata,
    body: &[u8],
) -> Result<Vec<u8>, FrameError> {
    if body.len() > SANDBOX_BINARY_CHUNK_MAX_BYTES {
        return Err(FrameError::BodyTooLarge);
    }
    metadata_prefixed_frame(metadata, body)
}

/// A 4-byte big-endian metadata length, the metadata JSON (serialized
/// straight into the frame), then `body`. Same errors, in the same order, as
/// serializing the metadata to a separate buffer first.
pub(crate) fn metadata_prefixed_frame<T: serde::Serialize>(
    metadata: &T,
    body: &[u8],
) -> Result<Vec<u8>, FrameError> {
    // A typical metadata object fits the estimate; a larger one grows the
    // buffer before the body is copied in.
    const METADATA_ESTIMATE: usize = 512;
    let mut frame = Vec::with_capacity(4 + METADATA_ESTIMATE + body.len());
    frame.extend_from_slice(&[0; 4]);
    serde_json::to_writer(&mut frame, metadata).map_err(FrameError::SerializeMetadata)?;
    let metadata_len = frame.len() - 4;
    if metadata_len > json_control_max_bytes() {
        return Err(FrameError::MetadataTooLarge);
    }
    let metadata_len =
        u32::try_from(metadata_len).map_err(|_| FrameError::MetadataLengthOverflow)?;
    frame[..4].copy_from_slice(&metadata_len.to_be_bytes());
    frame.reserve_exact(body.len());
    frame.extend_from_slice(body);
    Ok(frame)
}

pub fn parse_binary_frame(frame: &[u8]) -> Result<(StreamBinaryMetadata, Vec<u8>), FrameError> {
    let (metadata, body) = parse_binary_frame_ref(frame)?;
    Ok((metadata, body.to_vec()))
}

/// Parses a binary frame without copying its body: the returned slice borrows
/// from `frame`. Same validation and errors as [`parse_binary_frame`].
pub fn parse_binary_frame_ref(frame: &[u8]) -> Result<(StreamBinaryMetadata, &[u8]), FrameError> {
    if frame.len() < 4 {
        return Err(FrameError::MissingMetadataLength);
    }
    let metadata_len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    if metadata_len > json_control_max_bytes() {
        return Err(FrameError::MetadataTooLarge);
    }
    let body_offset = 4 + metadata_len;
    if body_offset > frame.len() {
        return Err(FrameError::InvalidMetadataLength);
    }
    let body_len = frame.len() - body_offset;
    if body_len > SANDBOX_BINARY_CHUNK_MAX_BYTES {
        return Err(FrameError::BodyTooLarge);
    }
    let metadata =
        serde_json::from_slice(&frame[4..body_offset]).map_err(FrameError::ParseMetadata)?;
    Ok((metadata, &frame[body_offset..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_oversized_binary_chunks() {
        let metadata = StreamBinaryMetadata {
            r#type: StreamKind::Chunk,
            stream_id: "stream-1".to_string(),
            operation_id: "op-1".to_string(),
            generation: 1,
            attempt: 1,
            offset: None,
            gap_start: None,
            sequence: 0,
            flags: None,
            final_chunk: None,
        };
        let body = vec![0_u8; SANDBOX_BINARY_CHUNK_MAX_BYTES + 1];
        assert!(matches!(
            encode_binary_frame(&metadata, &body),
            Err(FrameError::BodyTooLarge)
        ));
    }

    #[test]
    fn round_trips_binary_frame() {
        let metadata = StreamBinaryMetadata {
            r#type: StreamKind::Chunk,
            stream_id: "stream-1".to_string(),
            operation_id: "op-1".to_string(),
            generation: 1,
            attempt: 1,
            offset: None,
            gap_start: None,
            sequence: 3,
            flags: Some(StreamChunkFlags {
                stdout: Some(true),
                stderr: None,
                file_upload: None,
                file_download: None,
                stdin: None,
            }),
            final_chunk: Some(true),
        };
        let encoded = encode_binary_frame(&metadata, b"payload").expect("encode");
        let (decoded, body) = parse_binary_frame(&encoded).expect("parse");
        assert_eq!(decoded, metadata);
        assert_eq!(body, b"payload");
        let (borrowed_meta, borrowed_body) = parse_binary_frame_ref(&encoded).expect("parse ref");
        assert_eq!(borrowed_meta, metadata);
        assert_eq!(borrowed_body, b"payload");
    }

    #[test]
    fn encoding_matches_a_separately_serialized_prefix() {
        let metadata = StreamBinaryMetadata {
            r#type: StreamKind::Chunk,
            stream_id: "s".repeat(600),
            operation_id: "op-1".to_string(),
            generation: 1,
            attempt: 2,
            offset: Some(9),
            gap_start: None,
            sequence: 3,
            flags: None,
            final_chunk: Some(false),
        };
        for body in [&b""[..], b"payload"] {
            let json = serde_json::to_vec(&metadata).unwrap();
            let mut expected = (json.len() as u32).to_be_bytes().to_vec();
            expected.extend_from_slice(&json);
            expected.extend_from_slice(body);
            assert_eq!(encode_binary_frame(&metadata, body).unwrap(), expected);
        }
    }

    #[test]
    fn borrowed_parse_rejects_like_owned_parse() {
        assert!(matches!(
            parse_binary_frame_ref(&[0, 0, 0]),
            Err(FrameError::MissingMetadataLength)
        ));
        assert!(matches!(
            parse_binary_frame_ref(&[0, 0, 0, 9, b'{']),
            Err(FrameError::InvalidMetadataLength)
        ));
        assert!(matches!(
            parse_binary_frame_ref(&[0, 0, 0, 1, b'{']),
            Err(FrameError::ParseMetadata(_))
        ));
    }
}
