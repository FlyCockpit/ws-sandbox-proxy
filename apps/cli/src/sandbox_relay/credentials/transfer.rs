//! Chunked transfers into the daemon:
//!
//! - [`SpecAssembler`]: `credential.spec.chunk` stream for a dispatch's
//!   `credentialSpec {digest, bytes}`. Reassembled in memory, then length,
//!   SHA-256 and the shared parser; any mismatch fails the operation before
//!   any guest effect (`credential_spec_invalid`). Nothing is truncated.
//! - [`BundleReceiver`]: `credential.bundle.begin` + chunks decoded straight
//!   into one preallocated [`SecretBytes`] (never journaled, never logged),
//!   then decoded and validated against a definition rebuilt from the
//!   operation's verified spec entry.

use anyhow::{Result, bail};
use login_definition::{Bundle, LoginDefinition, decode_bundle, parse_definition};
use sandbox_protocol::{
    CREDENTIAL_CHUNK_RAW_BYTES, CredentialBundleBeginV11, CredentialSpecRefV11, CredentialSpecV11,
    SpecLeaseV11, chunk_data_len, decode_chunk_data_into, parse_credential_spec,
};

use super::SecretBytes;

/// Operation code when a spec cannot be fetched or verified.
pub const SPEC_INVALID_CODE: &str = "credential_spec_invalid";

#[derive(Debug)]
pub struct SpecAssembler {
    operation_id: String,
    expected: CredentialSpecRefV11,
    bytes: Vec<u8>,
    next_seq: u32,
}

impl SpecAssembler {
    pub fn new(operation_id: &str, expected: &CredentialSpecRefV11) -> Result<Self> {
        if !expected.is_valid() {
            bail!("{SPEC_INVALID_CODE}: invalid spec reference");
        }
        let capacity = usize::try_from(expected.bytes)?;
        Ok(Self {
            operation_id: operation_id.to_owned(),
            expected: expected.clone(),
            bytes: Vec::with_capacity(capacity),
            next_seq: 0,
        })
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Chunks arrive strictly in order; a gap, a replay or an overrun fails.
    pub fn push(&mut self, seq: u32, data: &str) -> Result<()> {
        if seq != self.next_seq {
            bail!("{SPEC_INVALID_CODE}: chunk out of order");
        }
        let len = chunk_data_len(data)
            .ok_or_else(|| anyhow::anyhow!("{SPEC_INVALID_CODE}: malformed chunk"))?;
        let at = self.bytes.len();
        if (at + len) as u64 > self.expected.bytes {
            bail!("{SPEC_INVALID_CODE}: spec longer than its reference");
        }
        // Every chunk but the last is full-size.
        if len != CREDENTIAL_CHUNK_RAW_BYTES && ((at + len) as u64) < self.expected.bytes {
            bail!("{SPEC_INVALID_CODE}: short chunk");
        }
        self.bytes.resize(at + len, 0);
        decode_chunk_data_into(data, &mut self.bytes[at..])
            .ok_or_else(|| anyhow::anyhow!("{SPEC_INVALID_CODE}: malformed chunk"))?;
        self.next_seq += 1;
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.bytes.len() as u64 == self.expected.bytes
    }

    /// Length, digest and the shared strict parser, in that order.
    pub fn finish(self) -> Result<CredentialSpecV11> {
        if !self.is_complete() {
            bail!("{SPEC_INVALID_CODE}: short spec stream");
        }
        if super::seal::sha256_hex(&self.bytes) != self.expected.digest {
            bail!("{SPEC_INVALID_CODE}: digest mismatch");
        }
        parse_credential_spec(&self.bytes).map_err(|e| anyhow::anyhow!("{SPEC_INVALID_CODE}: {e}"))
    }
}

/// A definition carrying exactly the spec entry's bundle rules (declared
/// paths, env names, `maxBytes`), so the shared bundle decoder enforces the
/// same limits the server enforced. Proxy shapes are not needed to decode.
pub fn definition_for(lease: &SpecLeaseV11) -> Result<LoginDefinition> {
    let env: Vec<serde_json::Value> = lease
        .env
        .iter()
        .map(|name| serde_json::json!({"name": name, "required": false}))
        .collect();
    let mut credentials = serde_json::json!({
        "sharing": if lease.exclusive { "exclusive" } else { "shareable" },
        "maxBytes": lease.max_bytes,
    });
    if !lease.files.is_empty() {
        credentials["files"] = serde_json::json!({
            "required": lease.files.required,
            "optional": lease.files.optional,
            "exclude": lease.files.exclude,
        });
    }
    if !env.is_empty() {
        credentials["env"] = serde_json::Value::Array(env);
    }
    let document = serde_json::json!({
        "schemaVersion": 1,
        "id": "spec-entry",
        "displayName": "spec entry",
        "login": {"command": "true", "method": "paste"},
        "credentials": credentials,
    });
    parse_definition(&document)
        .map(|parsed| parsed.definition)
        .map_err(|_| anyhow::anyhow!("credential spec entry does not form a valid definition"))
}

pub fn digest_bytes(hex: &str) -> Result<[u8; 32]> {
    if !sandbox_protocol::valid_sha256_hex(hex) {
        bail!("invalid digest");
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)?;
    }
    Ok(out)
}

/// One bundle stream for one request.
#[derive(Debug)]
pub struct BundleReceiver {
    begin: CredentialBundleBeginV11,
    secret: SecretBytes,
    filled: usize,
    next_seq: u32,
}

/// A complete, validated bundle. `secret` holds the plaintext; [`Self::view`]
/// borrows from it, so dropping this value wipes the only copy.
#[derive(Debug)]
pub struct ReceivedBundle {
    pub binding_id: String,
    pub storage_seq: u64,
    secret: SecretBytes,
    definition: LoginDefinition,
    digest: [u8; 32],
}

impl ReceivedBundle {
    pub fn view(&self) -> Result<Bundle<'_>> {
        decode_bundle(self.secret.expose(), &self.definition, &self.digest)
            .map_err(|e| anyhow::anyhow!("invalid credential bundle: {}", e.reason.as_str()))
    }
}

impl BundleReceiver {
    pub fn new(begin: CredentialBundleBeginV11) -> Result<Self> {
        if !begin.is_valid() {
            bail!("invalid credential bundle header");
        }
        let len = usize::try_from(begin.bundle_len)?;
        Ok(Self {
            secret: SecretBytes::zeroed(len),
            begin,
            filled: 0,
            next_seq: 0,
        })
    }

    pub fn request_id(&self) -> &str {
        &self.begin.request_id
    }

    pub fn push(&mut self, seq: u32, data: &str) -> Result<()> {
        if seq != self.next_seq || seq >= self.begin.chunk_count {
            bail!("credential bundle chunk out of order");
        }
        let len = chunk_data_len(data).ok_or_else(|| anyhow::anyhow!("malformed bundle chunk"))?;
        let end = self.filled + len;
        let last = seq + 1 == self.begin.chunk_count;
        if end > self.secret.len()
            || (last && end != self.secret.len())
            || (!last && len != CREDENTIAL_CHUNK_RAW_BYTES)
        {
            bail!("credential bundle chunk has the wrong size");
        }
        decode_chunk_data_into(data, &mut self.secret.expose_mut()[self.filled..end])
            .ok_or_else(|| anyhow::anyhow!("malformed bundle chunk"))?;
        self.filled = end;
        self.next_seq += 1;
        Ok(())
    }

    /// Validates the complete bundle against the spec entry: digest, every
    /// bundle rule, the announced counts, and env-only for restore variants.
    pub fn finish(self, lease: &SpecLeaseV11, restore: bool) -> Result<ReceivedBundle> {
        if self.filled != self.secret.len() {
            bail!("credential bundle stream ended early");
        }
        let definition = definition_for(lease)?;
        let digest = digest_bytes(&lease.definition_digest)?;
        let received = ReceivedBundle {
            binding_id: self.begin.binding_id.clone(),
            storage_seq: self.begin.storage_seq,
            secret: self.secret,
            definition,
            digest,
        };
        {
            let view = received.view()?;
            if view.files.len() != self.begin.file_count as usize
                || view.env.len() != self.begin.env_count as usize
            {
                bail!("credential bundle counts do not match its header");
            }
            if restore && !view.files.is_empty() {
                bail!("a restore bundle never carries files");
            }
        }
        Ok(received)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use login_definition::{BundleEnv, BundleFile, BundleFileKind, encode_bundle};
    use sandbox_protocol::{
        CredentialDelivery, CredentialLeaseKind, CredentialRotates, SpecFilesV11, SpecLeaseAction,
        encode_chunk_data,
    };

    pub(crate) fn lease() -> SpecLeaseV11 {
        SpecLeaseV11 {
            lease_id: "lease-1".into(),
            binding_id: None,
            credential_id: "cred-1".into(),
            instance_id: "inst-1".into(),
            definition_digest: "ab".repeat(32),
            max_bytes: 1024,
            delivery: CredentialDelivery::Guest,
            exclusive: true,
            copy_back: true,
            rotates: CredentialRotates::Unknown,
            kind: CredentialLeaseKind::Workload,
            action: SpecLeaseAction::Inject,
            files: SpecFilesV11 {
                required: vec![".config/tool".into()],
                optional: vec![],
                exclude: vec![],
            },
            env: vec!["TOOL_TOKEN".into()],
            proxy: vec![],
            checkpoint_interval_min: None,
        }
    }

    fn bundle_bytes(with_files: bool) -> Vec<u8> {
        let lease = lease();
        let def = definition_for(&lease).unwrap();
        let files = if with_files {
            vec![
                BundleFile {
                    kind: BundleFileKind::Dir,
                    path: ".config/tool",
                    mode: 0o700,
                    data: b"",
                },
                BundleFile {
                    kind: BundleFileKind::File,
                    path: ".config/tool/hosts.yml",
                    mode: 0o600,
                    data: b"token: test-only",
                },
            ]
        } else {
            vec![]
        };
        let bundle = Bundle {
            definition_digest: digest_bytes(&lease.definition_digest).unwrap(),
            files,
            env: vec![BundleEnv {
                name: "TOOL_TOKEN",
                value: b"test-only-env",
            }],
        };
        encode_bundle(&bundle, &def).unwrap().as_bytes().to_vec()
    }

    fn stream(bytes: &[u8], files: u32) -> (CredentialBundleBeginV11, Vec<String>) {
        let chunks: Vec<String> = bytes
            .chunks(CREDENTIAL_CHUNK_RAW_BYTES)
            .map(encode_chunk_data)
            .collect();
        (
            CredentialBundleBeginV11 {
                request_id: "req-1".into(),
                binding_id: "bind-1".into(),
                storage_seq: 3,
                file_count: files,
                env_count: 1,
                bundle_len: bytes.len() as u64,
                chunk_count: chunks.len() as u32,
            },
            chunks,
        )
    }

    #[test]
    fn bundle_receiver_validates_against_the_spec_entry() {
        let bytes = bundle_bytes(true);
        let (begin, chunks) = stream(&bytes, 2);
        let mut rx = BundleReceiver::new(begin.clone()).unwrap();
        for (i, c) in chunks.iter().enumerate() {
            rx.push(i as u32, c).unwrap();
        }
        let got = rx.finish(&lease(), false).unwrap();
        let view = got.view().unwrap();
        assert_eq!(view.files.len(), 2);
        assert_eq!(view.env[0].value, b"test-only-env");
        // Debug never prints plaintext.
        let shown = format!("{got:?}");
        assert!(!shown.contains("test-only"), "{shown}");
        // A restore must not carry files.
        let mut rx = BundleReceiver::new(begin.clone()).unwrap();
        rx.push(0, &chunks[0]).unwrap();
        assert!(rx.finish(&lease(), true).is_err());
        // Wrong announced counts.
        let mut wrong = begin.clone();
        wrong.file_count = 1;
        let mut rx = BundleReceiver::new(wrong).unwrap();
        rx.push(0, &chunks[0]).unwrap();
        assert!(rx.finish(&lease(), false).is_err());
        // A different definition digest.
        let mut other = lease();
        other.definition_digest = "cd".repeat(32);
        let mut rx = BundleReceiver::new(begin.clone()).unwrap();
        rx.push(0, &chunks[0]).unwrap();
        assert!(rx.finish(&other, false).is_err());
        // Out of order and short streams.
        let mut rx = BundleReceiver::new(begin.clone()).unwrap();
        assert!(rx.push(1, &chunks[0]).is_err());
        let rx = BundleReceiver::new(begin).unwrap();
        assert!(rx.finish(&lease(), false).is_err());
        // Restore bundles (env only) pass.
        let env_only = bundle_bytes(false);
        let (begin, chunks) = stream(&env_only, 0);
        let mut rx = BundleReceiver::new(begin).unwrap();
        rx.push(0, &chunks[0]).unwrap();
        assert!(rx.finish(&lease(), true).is_ok());
    }

    fn spec_bytes() -> Vec<u8> {
        let spec = CredentialSpecV11 {
            version: 1,
            sandbox_id: "sbx-1".into(),
            sandbox_owner_id: "owner-1".into(),
            host_owner_id: "owner-1".into(),
            leases: vec![lease()],
            residue: vec![],
        };
        let mut bytes = serde_json::to_vec(&spec).unwrap();
        // Make it span several chunks.
        bytes.resize(3 * CREDENTIAL_CHUNK_RAW_BYTES + 17, b' ');
        bytes
    }

    fn reference(bytes: &[u8]) -> CredentialSpecRefV11 {
        CredentialSpecRefV11 {
            digest: super::super::seal::sha256_hex(bytes),
            bytes: bytes.len() as u64,
        }
    }

    /// Spec transfer: digest mismatch and short stream fail before any guest
    /// effect; the max-size spec is accepted.
    #[test]
    fn spec_transfer_verifies_length_digest_and_parse() {
        let bytes = spec_bytes();
        let feed = |bytes: &[u8], r: &CredentialSpecRefV11| -> Result<CredentialSpecV11> {
            let mut a = SpecAssembler::new("op-1", r)?;
            for (i, c) in bytes.chunks(CREDENTIAL_CHUNK_RAW_BYTES).enumerate() {
                a.push(i as u32, &encode_chunk_data(c))?;
            }
            a.finish()
        };
        assert_eq!(feed(&bytes, &reference(&bytes)).unwrap().leases.len(), 1);
        let mut bad = reference(&bytes);
        bad.digest = "0".repeat(64);
        assert!(
            feed(&bytes, &bad)
                .unwrap_err()
                .to_string()
                .contains(SPEC_INVALID_CODE)
        );
        // Short stream: the reference promises more than arrives.
        let mut long = reference(&bytes);
        long.bytes += 1;
        assert!(feed(&bytes, &long).is_err());
        // A tampered byte under the right length fails the digest.
        let mut tampered = bytes.clone();
        tampered[10] ^= 1;
        assert!(feed(&tampered, &reference(&bytes)).is_err());
        // The single cap: a spec of exactly the cap parses.
        let mut max = spec_bytes();
        max.resize(sandbox_protocol::CREDENTIAL_SPEC_MAX_BYTES, b' ');
        assert!(feed(&max, &reference(&max)).is_ok());
    }
}
