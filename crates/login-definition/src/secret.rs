//! [`SecretBuf`]: the only owned allocation this crate puts credential
//! plaintext in (encoded bundles, constructed header values).
//!
//! The buffer is overwritten when dropped. It is not `Clone`, and `Debug`
//! prints only the length. It never reallocates in place: every writer sizes
//! it exactly up front, and growing past the capacity moves the bytes into a
//! fresh zeroizing buffer so no unwiped copy is left behind in a freed block.

use std::fmt;

use zeroize::Zeroizing;

pub struct SecretBuf(Zeroizing<Vec<u8>>);

impl SecretBuf {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self(Zeroizing::new(Vec::with_capacity(capacity)))
    }

    pub(crate) fn extend_from_slice(&mut self, bytes: &[u8]) {
        let needed = self.0.len() + bytes.len();
        if needed > self.0.capacity() {
            let mut grown = Zeroizing::new(Vec::with_capacity(needed));
            grown.extend_from_slice(&self.0);
            self.0 = grown;
        }
        self.0.extend_from_slice(bytes);
    }

    pub(crate) fn push(&mut self, byte: u8) {
        self.extend_from_slice(&[byte]);
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBuf(<{} bytes redacted>)", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grows_without_losing_bytes_and_redacts_debug() {
        let mut buf = SecretBuf::with_capacity(2);
        buf.extend_from_slice(b"s3");
        buf.extend_from_slice(b"cr3t");
        buf.push(b'!');
        assert_eq!(buf.as_bytes(), b"s3cr3t!");
        assert_eq!(buf.len(), 7);
        assert!(!format!("{buf:?}").contains("s3cr3t"));
    }
}
