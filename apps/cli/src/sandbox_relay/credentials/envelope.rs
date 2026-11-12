//! Capture envelope format v1 (docs/design/credential-vault.md § Envelope;
//! TS parser `packages/api/src/credentials/vault/envelope.ts`).
//!
//! ```text
//! "WSCO" ‖ u8 version = 1 ‖ u32be headerLen ‖ header JSON ‖ seal
//! header = {"kidR","recipientPubSha256","aad":{…},"sealedLen","sealedSha256","createdAt"}
//! envelopeDigest = SHA-256(all envelope bytes)
//! ```
//!
//! The header has exactly one accepted spelling: compact serde JSON in this
//! field order, ≤ 4 KiB. Durable writing (temp file, fsync, rename, directory
//! fsync, re-read + [`parse`]) belongs to the credential outbox.

use ring::digest;
use serde::{Deserialize, Serialize};

use super::seal::{ReturnAad, ReturnPublicKey, SEAL_OVERHEAD, SealError, sha256_hex};

pub const MAGIC: &[u8; 4] = b"WSCO";
pub const VERSION: u8 = 1;
pub const MAX_HEADER_BYTES: usize = 4096;
const PREFIX_BYTES: usize = 4 + 1 + 4;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnvelopeHeader {
    pub kid_r: String,
    pub recipient_pub_sha256: String,
    pub aad: ReturnAad,
    pub sealed_len: u64,
    pub sealed_sha256: String,
    /// Unix milliseconds at pack time; advisory only.
    pub created_at: u64,
}

#[derive(Debug)]
pub struct Envelope {
    pub header: EnvelopeHeader,
    /// The complete envelope file bytes.
    pub bytes: Vec<u8>,
    /// SHA-256 of `bytes`: the server's replay key with `captureId`.
    pub digest: [u8; 32],
}

fn digest32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(digest::digest(&digest::SHA256, bytes).as_ref());
    out
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn check_header(header: &EnvelopeHeader) -> Result<(), SealError> {
    header.aad.validate()?;
    if !is_lower_hex(&header.kid_r, 16)
        || !is_lower_hex(&header.recipient_pub_sha256, 64)
        || !header.recipient_pub_sha256.starts_with(&header.kid_r)
        || !is_lower_hex(&header.sealed_sha256, 64)
        || header.sealed_len < SEAL_OVERHEAD as u64
        || header.created_at > (1u64 << 53) - 1
    {
        return Err(SealError::Malformed);
    }
    Ok(())
}

/// Frame a seal for `recipient`. The header carries the same AAD the seal
/// was made with; the server still rebuilds it from rows and compares.
pub fn build(
    recipient: &ReturnPublicKey,
    aad: &ReturnAad,
    seal: &[u8],
    created_at_ms: u64,
) -> Result<Envelope, SealError> {
    let header = EnvelopeHeader {
        kid_r: recipient.kid_r().to_owned(),
        recipient_pub_sha256: recipient.sha256_hex(),
        aad: aad.clone(),
        sealed_len: seal.len() as u64,
        sealed_sha256: sha256_hex(seal),
        created_at: created_at_ms,
    };
    check_header(&header)?;
    let json = serde_json::to_vec(&header).map_err(|_| SealError::Malformed)?;
    if json.len() > MAX_HEADER_BYTES {
        return Err(SealError::Malformed);
    }
    let header_len = u32::try_from(json.len()).map_err(|_| SealError::Malformed)?;
    let mut bytes = Vec::with_capacity(PREFIX_BYTES + json.len() + seal.len());
    bytes.extend_from_slice(MAGIC);
    bytes.push(VERSION);
    bytes.extend_from_slice(&header_len.to_be_bytes());
    bytes.extend_from_slice(&json);
    bytes.extend_from_slice(seal);
    let digest = digest32(&bytes);
    Ok(Envelope {
        header,
        bytes,
        digest,
    })
}

/// Parse and self-verify (framing, canonical header, seal length and
/// `sealedSha256`). Used on the post-write re-read; never decrypts.
pub fn parse(bytes: Vec<u8>) -> Result<Envelope, SealError> {
    if bytes.len() < PREFIX_BYTES || &bytes[..4] != MAGIC || bytes[4] != VERSION {
        return Err(SealError::Malformed);
    }
    let header_len = u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]) as usize;
    if header_len > MAX_HEADER_BYTES || bytes.len() < PREFIX_BYTES + header_len {
        return Err(SealError::Malformed);
    }
    let json = &bytes[PREFIX_BYTES..PREFIX_BYTES + header_len];
    let header: EnvelopeHeader = serde_json::from_slice(json).map_err(|_| SealError::Malformed)?;
    check_header(&header)?;
    let canonical = serde_json::to_vec(&header).map_err(|_| SealError::Malformed)?;
    if canonical != json {
        return Err(SealError::Malformed);
    }
    let seal = &bytes[PREFIX_BYTES + header_len..];
    if seal.len() as u64 != header.sealed_len || sha256_hex(seal) != header.sealed_sha256 {
        return Err(SealError::Malformed);
    }
    let digest = digest32(&bytes);
    Ok(Envelope {
        header,
        bytes,
        digest,
    })
}

impl Envelope {
    /// The seal bytes after the header.
    pub fn seal(&self) -> &[u8] {
        let start = self.bytes.len() - self.header.sealed_len as usize;
        &self.bytes[start..]
    }

    pub fn digest_hex(&self) -> String {
        super::seal::hex(&self.digest)
    }
}
