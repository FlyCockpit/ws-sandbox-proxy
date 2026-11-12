//! `SecretBytes`: the only container for credential plaintext on the host.
//!
//! Backed by `zeroize::Zeroizing<Vec<u8>>`, so the buffer is overwritten when
//! dropped. It deliberately has no `Clone`, `Serialize`, or `Display`, and its
//! `Debug` prints only the length. Growth never leaves a stale copy behind:
//! [`SecretBytes::extend_from_slice`] moves into a fresh zeroizing buffer
//! instead of letting `Vec` reallocate (which would free the old allocation
//! without wiping it).
//!
//! Zeroing is best effort (docs/design/credential-vault.md § Memory hygiene).
//! Copies made by the kernel (pipes, page cache), by `ring` internals
//! (the X25519 shared secret), or by swap are outside its reach; `mlock` needs
//! `unsafe` here and is not used (nix exposes it only as an `unsafe fn`). The
//! daemon instead marks itself non-dumpable at start ([`harden_process`]) and
//! the docs require `LimitCORE=0` and encrypted or no swap.

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// `prctl(PR_SET_DUMPABLE, 0)`: no core dumps and no same-user ptrace or
/// `/proc/<pid>/mem` reads of the daemon (and its credential plaintext).
/// Best effort: a failure is reported to the caller, never fatal.
#[cfg(target_os = "linux")]
pub fn harden_process() -> std::io::Result<()> {
    nix::sys::prctl::set_dumpable(false).map_err(std::io::Error::from)
}

#[cfg(not(target_os = "linux"))]
pub fn harden_process() -> std::io::Result<()> {
    Ok(())
}

pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Takes ownership of `bytes`; they are wiped when this value drops.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// An empty buffer that can hold `capacity` bytes without reallocating.
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Zeroizing::new(Vec::with_capacity(capacity)))
    }

    /// `len` zero bytes, allocated once: decode chunks straight into
    /// [`SecretBytes::expose_mut`] without any reallocation.
    pub fn zeroed(len: usize) -> Self {
        Self(Zeroizing::new(vec![0u8; len]))
    }

    /// Adopts an already-zeroizing buffer (e.g. from the runtime helper).
    pub fn from_zeroizing(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }

    /// Wipes the contents now (also done on drop) and empties the buffer.
    pub fn wipe(&mut self) {
        self.0.zeroize();
    }

    /// Copies `bytes` in. The caller remains responsible for its own copy.
    pub fn copy_from(bytes: &[u8]) -> Self {
        let mut secret = Self::with_capacity(bytes.len());
        secret.0.extend_from_slice(bytes);
        secret
    }

    /// Appends without leaving an unwiped copy if the buffer must grow.
    pub fn extend_from_slice(&mut self, bytes: &[u8]) {
        let needed = self.0.len().saturating_add(bytes.len());
        if needed > self.0.capacity() {
            let mut grown = Zeroizing::new(Vec::with_capacity(needed.max(self.0.capacity() * 2)));
            grown.extend_from_slice(&self.0);
            // The old buffer is wiped when it is replaced here.
            self.0 = grown;
        }
        self.0.extend_from_slice(bytes);
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn expose_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

// Dropping a `SecretBytes` wipes it: the inner `Zeroizing` does the work.
impl ZeroizeOnDrop for SecretBytes {}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes(<redacted {} bytes>)", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_prints_contents() {
        let secret = SecretBytes::copy_from(b"test-only-token");
        let shown = format!("{secret:?} {secret:#?}");
        assert!(!shown.contains("test-only-token"));
        assert!(!shown.contains("116")); // no byte values either
        assert!(shown.contains("15 bytes"));
    }

    /// Compile-time proof that dropping wipes, plus explicit wipe semantics:
    /// `zeroize` overwrites the contents and the spare capacity, then empties.
    #[test]
    fn zeroizes_on_drop_and_on_wipe() {
        fn wipes_on_drop<T: ZeroizeOnDrop>() {}
        wipes_on_drop::<SecretBytes>();
        let mut secret = SecretBytes::copy_from(b"test-only-token");
        secret.wipe();
        assert!(secret.is_empty());
        // The same primitive on a buffer we can still observe afterwards.
        let mut probe = vec![0x41u8; 32];
        probe.as_mut_slice().zeroize();
        assert!(probe.iter().all(|b| *b == 0));
    }

    #[test]
    fn zeroed_buffers_take_chunks_without_reallocating() {
        let mut secret = SecretBytes::zeroed(6);
        let before = secret.expose().as_ptr();
        let text = sandbox_protocol::encode_chunk_data(b"abcdef");
        sandbox_protocol::decode_chunk_data_into(&text, secret.expose_mut()).unwrap();
        assert_eq!(secret.expose(), b"abcdef");
        assert_eq!(secret.expose().as_ptr(), before);
    }

    #[test]
    fn grows_without_losing_bytes() {
        let mut secret = SecretBytes::with_capacity(2);
        for chunk in [&b"ab"[..], b"cdef", b"", b"ghijklmnop"] {
            secret.extend_from_slice(chunk);
        }
        assert_eq!(secret.expose(), b"abcdefghijklmnop");
        assert_eq!(secret.len(), 16);
        assert!(!secret.is_empty());
        secret.expose_mut()[0] = b'A';
        assert_eq!(secret.expose()[0], b'A');
        assert!(SecretBytes::new(Vec::new()).is_empty());
    }
}
