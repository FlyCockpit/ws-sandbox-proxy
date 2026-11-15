//! Host side of the credential vault crypto (docs/design/credential-vault.md).
//!
//! - [`secret::SecretBytes`]: the only container for credential plaintext.
//! - [`seal`]: sealed box to the control plane's return key (ring X25519,
//!   HKDF-SHA256, AES-256-GCM) with the capture AAD.
//! - [`envelope`]: capture envelope format v1 and its digest.
//!
//! - [`journal`], [`outbox`], [`store`]: durable daemon state (teardown
//!   attempts, key slot, bindings, capture sequences, envelopes, quarantine,
//!   census) and the return-key transition barrier.
//! - [`transfer`]: spec and bundle reassembly; [`slot`]: per-sandbox guest
//!   slot; [`ops`]: install / capture / scrub over the runtime.
//! - [`proxy`]: proxy mode, the host-side HTTP proxy that injects a
//!   proxied login's header so its value never enters the guest.
//! - [`service`]: frame routing, spec fetch, the install-before-READY launch
//!   sequence, envelope upload, census and daemon-restart env restore.
//!
//! Cross-language vectors are shared with the TS opener in
//! `packages/api/src/credentials/vault/fixtures/seal-v1.json`.

pub mod envelope;
pub mod journal;
pub mod ops;
pub mod outbox;
pub mod proxy;
pub mod seal;
pub mod secret;
pub mod service;
pub mod slot;
pub mod store;
pub mod transfer;

pub(crate) use secret::masking_snapshot;
pub use secret::{SecretBytes, harden_process};

#[cfg(test)]
mod vector_tests;

/// Threat model: credential modules never stage plaintext through the
/// generic file IO paths. (The names are split so the test cannot match itself.)
#[cfg(test)]
#[test]
fn credential_modules_never_use_file_staging() {
    let banned = [concat!("File", "Staging"), concat!("file", "_io")];
    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sandbox_relay/credentials");
    let mut stack = vec![root];
    let mut scanned = 0;
    while let Some(dir) = stack.pop() {
        for item in std::fs::read_dir(dir).unwrap() {
            let path = item.unwrap().path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            for word in banned {
                assert!(!text.contains(word), "{} uses {word}", path.display());
            }
            scanned += 1;
        }
    }
    assert!(scanned >= 8);
}
