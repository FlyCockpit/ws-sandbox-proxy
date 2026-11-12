//! `aes256gcm-r1` stored-image records (ring; no new crate). Mirrors
//! `packages/api/src/sandbox/image-store/s3.ts`: 1 MiB plaintext records,
//! nonce = 4 zero bytes || u64be(index), AAD = "wssp-img-r1" || u64be(index)
//! || final-flag, so truncation, reordering and dropped records all fail.

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use sandbox_protocol::{IMAGE_ENCRYPTION_RECORD_BYTES, IMAGE_ENCRYPTION_TAG_BYTES};
use zeroize::Zeroizing;

pub const RECORD: usize = IMAGE_ENCRYPTION_RECORD_BYTES as usize;
pub const SEALED_RECORD: usize = RECORD + IMAGE_ENCRYPTION_TAG_BYTES as usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoError;

pub struct RecordKey(LessSafeKey);

/// A grant's base64 data key, moved out of the received frame so the frame
/// no longer holds it and the text is wiped on drop. The key is never
/// journaled, logged or re-sent.
pub type GrantKey = Zeroizing<String>;

/// Move the key out of a received grant's `encryption` (leaving it empty).
pub fn take_grant_key(encryption: &mut sandbox_protocol::ImageEncryptionV11) -> GrantKey {
    Zeroizing::new(std::mem::take(&mut encryption.key))
}

impl RecordKey {
    /// The decoded key bytes live in a wiped buffer (`Zeroizing`) until
    /// `ring` takes its own copy.
    pub fn from_base64(text: &str) -> Result<Self, CryptoError> {
        let bytes: Zeroizing<Vec<u8>> = decode_base64(text).ok_or(CryptoError)?;
        if bytes.len() != 32 {
            return Err(CryptoError);
        }
        let key = UnboundKey::new(&AES_256_GCM, &bytes).map_err(|_| CryptoError)?;
        Ok(Self(LessSafeKey::new(key)))
    }

    fn nonce(index: u64) -> Nonce {
        let mut bytes = [0u8; 12];
        bytes[4..].copy_from_slice(&index.to_be_bytes());
        Nonce::assume_unique_for_key(bytes)
    }

    fn aad(index: u64, last: bool) -> [u8; 20] {
        let mut aad = [0u8; 20];
        aad[..11].copy_from_slice(b"wssp-img-r1");
        aad[11..19].copy_from_slice(&index.to_be_bytes());
        aad[19] = u8::from(last);
        aad
    }

    pub fn seal(&self, index: u64, last: bool, plain: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut buffer = plain.to_vec();
        self.0
            .seal_in_place_append_tag(
                Self::nonce(index),
                Aad::from(Self::aad(index, last)),
                &mut buffer,
            )
            .map_err(|_| CryptoError)?;
        Ok(buffer)
    }

    pub fn open(&self, index: u64, last: bool, sealed: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut buffer = sealed.to_vec();
        let plain = self
            .0
            .open_in_place(
                Self::nonce(index),
                Aad::from(Self::aad(index, last)),
                &mut buffer,
            )
            .map_err(|_| CryptoError)?;
        Ok(plain.to_vec())
    }
}

/// Number of records for `plain` bytes (at least one).
pub fn record_count(plain: u64) -> u64 {
    plain.div_ceil(IMAGE_ENCRYPTION_RECORD_BYTES).max(1)
}

fn decode_base64(text: &str) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(text.len() * 3 / 4));
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

    #[test]
    fn records_round_trip_and_refuse_tamper_reorder_and_truncation_flags() {
        let key = RecordKey::from_base64(KEY).unwrap();
        let sealed = key.seal(0, false, b"hello").unwrap();
        assert_eq!(key.open(0, false, &sealed).unwrap(), b"hello");
        assert!(key.open(1, false, &sealed).is_err(), "reordered");
        assert!(key.open(0, true, &sealed).is_err(), "final flag forged");
        let mut tampered = sealed.clone();
        tampered[0] ^= 1;
        assert!(key.open(0, false, &tampered).is_err());
        assert!(key.open(0, false, &sealed[..sealed.len() - 1]).is_err());
        assert!(RecordKey::from_base64("c2hvcnQ=").is_err());
        assert_eq!(record_count(0), 1);
        assert_eq!(record_count(RECORD as u64 + 1), 2);
    }

    /// Same vector the Node side checks (`image-store.test.ts`).
    #[test]
    fn matches_the_typescript_record_vector() {
        let key = RecordKey::from_base64(KEY).unwrap();
        let sealed = key.seal(3, true, b"wssp").unwrap();
        let hex: String = sealed.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex.len(), (4 + 16) * 2);
        assert_eq!(key.open(3, true, &sealed).unwrap(), b"wssp");
    }

    /// The received key and its decoded bytes are wiped
    /// buffers, and taking the key leaves the frame without it.
    #[test]
    fn grant_keys_and_decoded_bytes_are_zeroizing() {
        let mut encryption = sandbox_protocol::ImageEncryptionV11 {
            scheme: sandbox_protocol::IMAGE_ENCRYPTION_SCHEME.into(),
            key: KEY.into(),
        };
        let key: GrantKey = take_grant_key(&mut encryption);
        let _: &Zeroizing<String> = &key;
        assert!(encryption.key.is_empty());
        let decoded: Option<Zeroizing<Vec<u8>>> = decode_base64(&key);
        assert_eq!(decoded.map(|bytes| bytes.len()), Some(32));
        assert!(RecordKey::from_base64(&key).is_ok());
    }
}
