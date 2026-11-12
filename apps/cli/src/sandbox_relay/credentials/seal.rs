//! Sealed box from a host to the control plane's return key
//! (TS opener `packages/api/src/credentials/vault/sealed-box.ts`). Spec:
//! docs/design/credential-vault.md § Sealed box
//!
//! ```text
//! seal   = eph_pub(32) ‖ nonce(12) ‖ ciphertext ‖ tag(16)
//! shared = X25519(eph, recipient_pub)              (all-zero refused)
//! key    = HKDF-SHA256(ikm = shared, salt = eph_pub ‖ recipient_pub,
//!            info = "wssp:cred-return:v1" ‖ kidR)
//! AAD    = LP list ["wssp:cred-return:v1", kidR, serverOrigin, hostOwnerId,
//!            hostId, sandboxOwnerId, sandboxId, leaseId, bindingId,
//!            instanceId, credentialId, captureSeq, captureId, kind, residueId|""]
//! LP(x)  = u32be(len(x)) ‖ UTF-8(x)
//! ```
//!
//! Each seal uses a fresh ephemeral key, so the AES key and nonce are never
//! reused. The host never opens seals; the opener here is test-only.

use ring::{aead, agreement, digest, hkdf, rand};
use serde::{Deserialize, Serialize};

pub const SEAL_LABEL: &str = "wssp:cred-return:v1";
pub const KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 12;
pub const TAG_BYTES: usize = 16;
pub const SEAL_OVERHEAD: usize = KEY_BYTES + NONCE_BYTES + TAG_BYTES;
const MAX_AAD_FIELD_BYTES: usize = 256;
const MAX_SEQ: u64 = i64::MAX as u64;

/// Data-free failure of a seal operation. Never carries key or value bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    /// A key is not in its strict encoding, or the DH result is all-zero.
    InvalidKey,
    /// `kidR` does not name the public key.
    KeyIdMismatch,
    /// An AAD field is out of bounds.
    InvalidAad,
    /// Envelope framing, header, or seal length/digest mismatch.
    Malformed,
    /// The crypto library failed (randomness, or authentication when opening).
    Crypto,
}

impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidKey => "invalid credential return key",
            Self::KeyIdMismatch => "credential return key id does not match its key",
            Self::InvalidAad => "invalid credential capture context",
            Self::Malformed => "malformed credential capture envelope",
            Self::Crypto => "credential seal operation failed",
        })
    }
}

impl std::error::Error for SealError {}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex(digest::digest(&digest::SHA256, bytes).as_ref())
}

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Unpadded base64url (RFC 4648 §5).
pub fn to_base64url(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..=chunk.len() {
            out.push(char::from(B64URL[((n >> (18 - 6 * i)) & 0x3f) as usize]));
        }
    }
    out
}

/// Strict decode of an X25519 key: 43 unpadded base64url characters that
/// re-encode to exactly the same text (no padding, no `+`/`/`, zero trailing bits).
fn key_from_base64url(text: &str) -> Result<[u8; KEY_BYTES], SealError> {
    if text.len() != 43 {
        return Err(SealError::InvalidKey);
    }
    let mut bits: u32 = 0;
    let mut count = 0u32;
    let mut out = Vec::with_capacity(33);
    for c in text.bytes() {
        let v = B64URL
            .iter()
            .position(|&a| a == c)
            .ok_or(SealError::InvalidKey)?;
        bits = (bits << 6) | v as u32;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push(((bits >> count) & 0xff) as u8);
        }
    }
    let key: [u8; KEY_BYTES] = out.try_into().map_err(|_| SealError::InvalidKey)?;
    if to_base64url(&key) != text {
        return Err(SealError::InvalidKey);
    }
    Ok(key)
}

/// p = 2^255 − 19, little-endian.
const P25519: [u8; 32] = {
    let mut p = [0xff; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    p
};

/// A canonical u-coordinate: high bit clear and below p. Low-order points are
/// refused by the all-zero shared-secret check.
fn is_canonical_x25519(key: &[u8; KEY_BYTES]) -> bool {
    for i in (0..KEY_BYTES).rev() {
        if key[i] != P25519[i] {
            return key[i] < P25519[i];
        }
    }
    false
}

/// The control plane's current return public key, as received in
/// `credential.return.key` and held in the host's key slot.
#[derive(Clone, PartialEq, Eq)]
pub struct ReturnPublicKey {
    bytes: [u8; KEY_BYTES],
    kid_r: String,
}

impl std::fmt::Debug for ReturnPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReturnPublicKey")
            .field("kid_r", &self.kid_r)
            .finish_non_exhaustive()
    }
}

impl ReturnPublicKey {
    /// Parse the transport spelling and refuse unless `kid_r` names the key
    /// (`kidR = hex(SHA-256(publicKey))[0:16]`).
    pub fn parse(public_key: &str, kid_r: &str) -> Result<Self, SealError> {
        let key = Self::from_bytes(key_from_base64url(public_key)?)?;
        if key.kid_r != kid_r {
            return Err(SealError::KeyIdMismatch);
        }
        Ok(key)
    }

    pub fn from_bytes(bytes: [u8; KEY_BYTES]) -> Result<Self, SealError> {
        if !is_canonical_x25519(&bytes) {
            return Err(SealError::InvalidKey);
        }
        let mut kid_r = sha256_hex(&bytes);
        kid_r.truncate(16);
        Ok(Self { bytes, kid_r })
    }

    pub fn kid_r(&self) -> &str {
        &self.kid_r
    }

    pub fn as_bytes(&self) -> &[u8; KEY_BYTES] {
        &self.bytes
    }

    pub fn to_base64url(&self) -> String {
        to_base64url(&self.bytes)
    }

    /// Full hex SHA-256 of the key (`recipientPubSha256` in envelope headers).
    pub fn sha256_hex(&self) -> String {
        sha256_hex(&self.bytes)
    }
}

mod seq_string {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse::<u64>().map_err(serde::de::Error::custom)
    }
}

/// Everything the seal AAD binds besides the label and kidR. Field order is the
/// AAD order and the envelope-header JSON order; every field is a JSON string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReturnAad {
    pub server_origin: String,
    pub host_owner_id: String,
    pub host_id: String,
    pub sandbox_owner_id: String,
    pub sandbox_id: String,
    pub lease_id: String,
    pub binding_id: String,
    pub instance_id: String,
    pub credential_id: String,
    /// 1 ≤ seq ≤ 2^63 − 1, a decimal string on the wire.
    #[serde(with = "seq_string")]
    pub capture_seq: u64,
    pub capture_id: String,
    /// Lowercase capture kind token (`stop`, `checkpoint`, `recovery`, `login`, …).
    pub kind: String,
    /// Empty when the capture packs no residue.
    pub residue_id: String,
}

fn valid_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_AAD_FIELD_BYTES
}

fn valid_kind(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 32
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'-')
}

impl ReturnAad {
    fn ids(&self) -> [&str; 11] {
        [
            &self.server_origin,
            &self.host_owner_id,
            &self.host_id,
            &self.sandbox_owner_id,
            &self.sandbox_id,
            &self.lease_id,
            &self.binding_id,
            &self.instance_id,
            &self.credential_id,
            &self.capture_id,
            &self.kind,
        ]
    }

    pub fn validate(&self) -> Result<(), SealError> {
        let residue_ok = self.residue_id.is_empty() || self.residue_id.len() <= MAX_AAD_FIELD_BYTES;
        if !self.ids().iter().all(|id| valid_id(id))
            || !residue_ok
            || !valid_kind(&self.kind)
            || self.capture_seq == 0
            || self.capture_seq > MAX_SEQ
        {
            return Err(SealError::InvalidAad);
        }
        Ok(())
    }

    /// The LP-encoded AAD for `kid_r` (validates every field first).
    pub fn encode(&self, kid_r: &str) -> Result<Vec<u8>, SealError> {
        self.validate()?;
        let seq = self.capture_seq.to_string();
        let fields: [&str; 15] = [
            SEAL_LABEL,
            kid_r,
            &self.server_origin,
            &self.host_owner_id,
            &self.host_id,
            &self.sandbox_owner_id,
            &self.sandbox_id,
            &self.lease_id,
            &self.binding_id,
            &self.instance_id,
            &self.credential_id,
            &seq,
            &self.capture_id,
            &self.kind,
            &self.residue_id,
        ];
        let mut out = Vec::with_capacity(fields.iter().map(|f| 4 + f.len()).sum());
        for field in fields {
            let len = u32::try_from(field.len()).map_err(|_| SealError::InvalidAad)?;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(field.as_bytes());
        }
        Ok(out)
    }
}

fn seal_key(
    shared: &[u8],
    eph_pub: &[u8],
    recipient: &ReturnPublicKey,
) -> Result<aead::LessSafeKey, SealError> {
    if shared.len() != KEY_BYTES || shared.iter().all(|b| *b == 0) {
        return Err(SealError::InvalidKey);
    }
    let mut salt = [0u8; 2 * KEY_BYTES];
    salt[..KEY_BYTES].copy_from_slice(eph_pub);
    salt[KEY_BYTES..].copy_from_slice(recipient.as_bytes());
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt).extract(shared);
    let info = [SEAL_LABEL.as_bytes(), recipient.kid_r().as_bytes()];
    let okm = prk
        .expand(&info, &aead::AES_256_GCM)
        .map_err(|_| SealError::Crypto)?;
    Ok(aead::LessSafeKey::new(aead::UnboundKey::from(okm)))
}

/// Seal `plaintext` to `recipient` with a fresh ephemeral key and nonce.
pub fn seal(
    plaintext: &[u8],
    recipient: &ReturnPublicKey,
    aad: &ReturnAad,
) -> Result<Vec<u8>, SealError> {
    seal_with_rng(&rand::SystemRandom::new(), plaintext, recipient, aad)
}

/// [`seal`] with an explicit randomness source: the ephemeral key is drawn
/// first (32 bytes), then the nonce (12). Production passes `SystemRandom`;
/// only cross-language vectors pass a fixed sequence.
pub(crate) fn seal_with_rng(
    rng: &dyn rand::SecureRandom,
    plaintext: &[u8],
    recipient: &ReturnPublicKey,
    aad: &ReturnAad,
) -> Result<Vec<u8>, SealError> {
    let aad_bytes = aad.encode(recipient.kid_r())?;
    let eph = agreement::EphemeralPrivateKey::generate(&agreement::X25519, rng)
        .map_err(|_| SealError::Crypto)?;
    let eph_pub = eph.compute_public_key().map_err(|_| SealError::Crypto)?;
    let mut nonce = [0u8; NONCE_BYTES];
    rng.fill(&mut nonce).map_err(|_| SealError::Crypto)?;
    let peer = agreement::UnparsedPublicKey::new(&agreement::X25519, recipient.as_bytes());
    // ring refuses an all-zero result itself (`Err`), mapped to InvalidKey.
    let key = agreement::agree_ephemeral(eph, &peer, |shared| {
        seal_key(shared, eph_pub.as_ref(), recipient)
    })
    .map_err(|_| SealError::InvalidKey)??;

    let mut out = Vec::with_capacity(SEAL_OVERHEAD + plaintext.len());
    out.extend_from_slice(eph_pub.as_ref());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(plaintext);
    let tag = key
        .seal_in_place_separate_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(&aad_bytes),
            &mut out[KEY_BYTES + NONCE_BYTES..],
        )
        .map_err(|_| SealError::Crypto)?;
    out.extend_from_slice(tag.as_ref());
    Ok(out)
}

#[cfg(test)]
#[allow(deprecated)] // ring's deterministic test RNGs are the only way to load a fixed scalar.
pub(crate) mod testing {
    use super::*;
    use crate::sandbox_relay::credentials::SecretBytes;

    /// Fixed (ephemeral, nonce) draws for vectors.
    pub fn seal_deterministic(
        eph: &[u8; 32],
        nonce: &[u8; 12],
        plaintext: &[u8],
        recipient: &ReturnPublicKey,
        aad: &ReturnAad,
    ) -> Result<Vec<u8>, SealError> {
        let draws: [&[u8]; 2] = [eph, nonce];
        let rng = ring::test::rand::FixedSliceSequenceRandom {
            bytes: &draws,
            current: core::cell::UnsafeCell::new(0),
        };
        seal_with_rng(&rng, plaintext, recipient, aad)
    }

    /// Test-only opener (the server opens in TS), used to open TS-made seals.
    pub fn open(
        recipient_private: &[u8; 32],
        recipient: &ReturnPublicKey,
        sealed: &[u8],
        aad: &ReturnAad,
    ) -> Result<SecretBytes, SealError> {
        if sealed.len() < SEAL_OVERHEAD {
            return Err(SealError::Malformed);
        }
        let aad_bytes = aad.encode(recipient.kid_r())?;
        let eph_pub: [u8; 32] = sealed[..KEY_BYTES]
            .try_into()
            .map_err(|_| SealError::Malformed)?;
        ReturnPublicKey::from_bytes(eph_pub)?;
        let rng = ring::test::rand::FixedSliceRandom {
            bytes: recipient_private,
        };
        let private = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)
            .map_err(|_| SealError::Crypto)?;
        let mine = private
            .compute_public_key()
            .map_err(|_| SealError::Crypto)?;
        if mine.as_ref() != recipient.as_bytes() {
            return Err(SealError::KeyIdMismatch);
        }
        let peer = agreement::UnparsedPublicKey::new(&agreement::X25519, &eph_pub);
        let key = agreement::agree_ephemeral(private, &peer, |shared| {
            seal_key(shared, &eph_pub, recipient)
        })
        .map_err(|_| SealError::InvalidKey)??;
        let nonce: [u8; NONCE_BYTES] = sealed[KEY_BYTES..KEY_BYTES + NONCE_BYTES]
            .try_into()
            .map_err(|_| SealError::Malformed)?;
        let mut body = SecretBytes::copy_from(&sealed[KEY_BYTES + NONCE_BYTES..]);
        let len = key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(&aad_bytes),
                body.expose_mut(),
            )
            .map_err(|_| SealError::Crypto)?
            .len();
        Ok(SecretBytes::copy_from(&body.expose()[..len]))
    }
}
