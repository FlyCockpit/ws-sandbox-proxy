//! CLI-login credential frames (additive within relay 1.0).
//!
//! Every field added to an existing frame is optional and omitted when
//! absent; a host only receives credential frames after advertising the
//! `credentials` capability, and the server parses every frame strictly
//! (`deny_unknown_fields` plus `is_valid`). Server deploys first, daemons roll
//! back first.
//!
//! Frames that can carry plaintext (`credential.bundle.chunk`) or sealed
//! captures (`credential.capture.chunk`) redact their payload in `Debug`.
//! Bounds come from `packages/config/src/credential-protocol-limits.json`,
//! shared with the zod mirror in
//! `packages/sandbox-contracts/src/credential-wire.ts`; the shared fixture is
//! `crates/sandbox-protocol/fixtures/control_credentials.json`.

use serde::{Deserialize, Serialize};

pub const CREDENTIAL_PROTOCOL_LIMITS_JSON: &str =
    include_str!("../../../packages/config/src/credential-protocol-limits.json");

/// Credential ids (lease, binding, instance, request, capture, residue …).
pub const CREDENTIAL_ID_MAX_BYTES: usize = 64;
/// Raw bytes per chunk before base64url (spec, bundle and capture chunks).
pub const CREDENTIAL_CHUNK_RAW_BYTES: usize = 32 * 1024;
/// Unpadded base64url characters for a full chunk.
pub const CREDENTIAL_CHUNK_TEXT_MAX: usize = (CREDENTIAL_CHUNK_RAW_BYTES * 4).div_ceil(3);
/// Chunks in flight before an ack (capture upload windows).
pub const CREDENTIAL_CHUNK_WINDOW: usize = 8;
/// The single spec cap (R3-5): admission, the DB CHECK, transfer and both parsers.
pub const CREDENTIAL_SPEC_MAX_BYTES: usize = 1_179_648;
pub const CREDENTIAL_SPEC_CHUNKS_MAX: usize =
    CREDENTIAL_SPEC_MAX_BYTES / CREDENTIAL_CHUNK_RAW_BYTES;
pub const CREDENTIAL_SPEC_LEASES_MAX: usize = 8;
pub const CREDENTIAL_SPEC_RESIDUES_MAX: usize = 16;
pub const CREDENTIAL_SPEC_PATHS_MAX: usize = 64;
pub const CREDENTIAL_SPEC_ENV_MAX: usize = 16;
/// `628 825 + 4 194 304` (§3 exact maximum).
pub const CREDENTIAL_BUNDLE_MAX_BYTES: usize = 4_823_129;
/// Bundle v1 header: the smallest bundle.
pub const CREDENTIAL_BUNDLE_MIN_BYTES: usize = 41;
pub const CREDENTIAL_BUNDLE_CHUNKS_MAX: usize = 148;
/// Envelope prefix (9) + header (≤ 4 KiB) + largest bundle + seal overhead (60).
pub const CREDENTIAL_ENVELOPE_MAX_BYTES: usize = 9 + 4096 + CREDENTIAL_BUNDLE_MAX_BYTES + 60;
pub const CREDENTIAL_CAPTURE_CHUNKS_MAX: usize = 148;
pub const CREDENTIAL_CENSUS_ENTRIES_MAX: usize = 32;
pub const CREDENTIAL_CENSUS_PENDING_MAX: usize = 8;
pub const CREDENTIAL_CENSUS_QUARANTINED_MAX: usize = 64;
/// Encoded census page bound; pages are filled greedily under it.
pub const CREDENTIAL_CENSUS_PAGE_BYTES_MAX: usize = 48 * 1024;
pub const CREDENTIAL_CENSUS_PAGES_MAX: u32 = 1024;
pub const CREDENTIAL_SCRUBBED_BINDINGS_MAX: usize = 24;
pub const CREDENTIAL_TEARDOWN_OUTCOMES_MAX: usize = 24;
pub const CREDENTIAL_RETIRED_KIDS_MAX: usize = 16;
pub const CREDENTIAL_QUARANTINE_DISCARD_MAX: usize = 64;
/// Return-key epochs are `BigInt` in the DB and JSON numbers on the wire.
pub const CREDENTIAL_EPOCH_MAX: u64 = 9_007_199_254_740_991;

// --- scalar validators ----------------------------------------------------------

/// `[A-Za-z0-9_-]{1,64}`.
pub fn valid_credential_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= CREDENTIAL_ID_MAX_BYTES
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn valid_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// SHA-256 as 64 lowercase hex characters.
pub fn valid_sha256_hex(value: &str) -> bool {
    valid_hex(value, 64)
}

/// `kidR` = first 16 hex characters of SHA-256(public key).
pub fn valid_kid(value: &str) -> bool {
    valid_hex(value, 16)
}

fn valid_epoch(value: u64) -> bool {
    value > 0 && value <= CREDENTIAL_EPOCH_MAX
}

fn valid_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= 64
        && code
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b == b'_' || b == b'.')
}

/// HTTPS origin (HTTP only to an explicit loopback host, local development).
fn valid_origin(value: &str) -> bool {
    let rest = if let Some(rest) = value.strip_prefix("https://") {
        rest
    } else if let Some(rest) = value.strip_prefix("http://") {
        let host = rest.split(':').next().unwrap_or("");
        if !(host == "localhost" || host == "127.0.0.1" || host == "[::1]") {
            return false;
        }
        rest
    } else {
        return false;
    };
    value.len() <= 256
        && !rest.is_empty()
        && rest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'))
}

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64_value(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some(u32::from(c - b'A')),
        b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// Unpadded base64url (RFC 4648 §5) of a chunk.
pub fn encode_chunk_data(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() * 4).div_ceil(3));
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

/// Decoded length of canonical unpadded base64url text, if well formed.
pub fn chunk_data_len(text: &str) -> Option<usize> {
    let rem = text.len() % 4;
    if rem == 1 {
        return None;
    }
    Some(text.len() / 4 * 3 + rem.saturating_sub(1))
}

/// Strict unpadded base64url decode into `out` (exactly [`chunk_data_len`]
/// bytes), so a caller can decode plaintext straight into a buffer it wipes.
/// Non-canonical trailing bits are refused.
pub fn decode_chunk_data_into(text: &str, out: &mut [u8]) -> Option<()> {
    if chunk_data_len(text)? != out.len() {
        return None;
    }
    let bytes = text.as_bytes();
    let mut at = 0;
    for group in bytes.chunks(4) {
        let mut n = 0u32;
        for (i, c) in group.iter().enumerate() {
            n |= b64_value(*c)? << (18 - 6 * i);
        }
        let produced = group.len() - 1;
        let mask = match produced {
            1 => 0xffff,
            2 => 0xff,
            _ => 0,
        };
        if n & mask != 0 {
            return None;
        }
        for i in 0..produced {
            out[at] = ((n >> (16 - 8 * i)) & 0xff) as u8;
            at += 1;
        }
    }
    Some(())
}

/// Valid chunk payload text: canonical base64url of 1..=32 KiB.
pub fn valid_chunk_data(text: &str) -> bool {
    let Some(len) = chunk_data_len(text) else {
        return false;
    };
    if !(1..=CREDENTIAL_CHUNK_RAW_BYTES).contains(&len)
        || !text.bytes().all(|b| b64_value(b).is_some())
    {
        return false;
    }
    // Only the last group can carry non-canonical trailing bits.
    let tail = &text[(text.len() - 1) / 4 * 4..];
    let mut scratch = [0u8; 3];
    chunk_data_len(tail).is_some_and(|n| decode_chunk_data_into(tail, &mut scratch[..n]).is_some())
}

/// Home-relative credential path (§3): relative, no `.`/`..`/empty segments,
/// no `\`, `:`, NUL or control bytes, ≤ 255 bytes, never under `.wssp*`.
/// No segment may start with the daemon's `.wssp-cred-` staging prefix.
pub fn valid_credential_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 255
        && !path.starts_with('/')
        && !path
            .bytes()
            .any(|b| b < 0x20 || b == 0x7f || b == b'\\' || b == b':')
        && path
            .split('/')
            .all(|s| !s.is_empty() && s != "." && s != ".." && !s.starts_with(".wssp-cred-"))
        && !path
            .split('/')
            .next()
            .is_some_and(|s| s.starts_with(".wssp"))
}

/// POSIX env name, ≤ 128 bytes.
pub fn valid_env_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && (bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
}

fn unique<'a>(items: impl Iterator<Item = &'a str>) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    items.into_iter().all(|item| seen.insert(item))
}

// --- capability -----------------------------------------------------------------

/// Hello capability. Omitted entirely by daemons without credential support,
/// so their hello stays byte-identical. `returnKeyEpoch` is the host's key
/// slot epoch (0 = no key yet); a lower value than the server's current
/// epoch makes the server issue and send the current key (§4.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialCapabilitiesV11 {
    pub files: bool,
    pub env: bool,
    pub proxy: bool,
    pub sealed_return: bool,
    pub checkpoint: bool,
    pub spec_transfer: bool,
    pub max_bundle_bytes: u64,
    pub return_key_epoch: u64,
}

impl CredentialCapabilitiesV11 {
    pub fn is_valid(&self) -> bool {
        (CREDENTIAL_BUNDLE_MIN_BYTES as u64..=CREDENTIAL_BUNDLE_MAX_BYTES as u64)
            .contains(&self.max_bundle_bytes)
            && self.return_key_epoch <= CREDENTIAL_EPOCH_MAX
    }
}

// --- dispatch additions ---------------------------------------------------------

/// Reference to an operation's credential spec (§6.1): never inline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialSpecRefV11 {
    pub digest: String,
    pub bytes: u64,
}

impl CredentialSpecRefV11 {
    pub fn is_valid(&self) -> bool {
        valid_sha256_hex(&self.digest)
            && self.bytes >= 2
            && self.bytes <= CREDENTIAL_SPEC_MAX_BYTES as u64
    }
}

/// `sandbox.stop`/`sandbox.kill` capture mode; absent means capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialCaptureMode {
    Skip,
}

/// Author of a `sandbox.stop`/`sandbox.kill`. Absent is a user
/// stop/kill: a capture failure fails it `credential_capture_failed` and the
/// VM keeps running. `system` (expiry, access, readiness writers) never
/// fails: the VM stops and the lease becomes recovery-required.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialTeardownOrigin {
    System,
}

/// Dispatch kinds that may carry a `credentialSpec` reference.
pub const CREDENTIAL_SPEC_DISPATCH_KINDS: &[&str] = &[
    "sandbox.create",
    "sandbox.reconnect",
    "credential.attach",
    "credential.free",
    "sandbox.stop",
    "sandbox.kill",
    "sandbox.capture",
];

/// Dispatch kinds that may carry `credentialCapture`.
pub const CREDENTIAL_CAPTURE_DISPATCH_KINDS: &[&str] = &["sandbox.stop", "sandbox.kill"];

// --- spec content (§6.1) --------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialDelivery {
    Guest,
    Proxy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialRotates {
    Yes,
    No,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialLeaseKind {
    Workload,
    Login,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpecLeaseAction {
    Inject,
    Recover,
    ScrubOnly,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpecResidueAction {
    Recover,
    Scrub,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpecFilesV11 {
    pub required: Vec<String>,
    pub optional: Vec<String>,
    pub exclude: Vec<String>,
}

impl SpecFilesV11 {
    pub fn len(&self) -> usize {
        self.required.len() + self.optional.len() + self.exclude.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Whether the lease declares a path to install and capture (required
    /// or optional; `exclude` alone captures nothing). An env-only login
    /// declares none: its teardown and checkpoints capture nothing, and the
    /// server (`definitionCapturesFiles`) never waits for such a capture.
    pub fn includes_paths(&self) -> bool {
        !self.required.is_empty() || !self.optional.is_empty()
    }
    fn is_valid(&self) -> bool {
        self.len() <= CREDENTIAL_SPEC_PATHS_MAX
            && self
                .required
                .iter()
                .chain(&self.optional)
                .chain(&self.exclude)
                .all(|p| valid_credential_path(p))
            && unique(
                self.required
                    .iter()
                    .chain(&self.optional)
                    .chain(&self.exclude)
                    .map(String::as_str),
            )
    }
}

/// One proxied env entry (§9). Validated in full at definition write; the
/// host re-checks shape and bounds only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpecProxyV11 {
    pub name: String,
    pub upstream: String,
    pub header: String,
    pub format: String,
    pub base_url_env: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder_env: Option<String>,
}

impl SpecProxyV11 {
    fn is_valid(&self) -> bool {
        valid_env_name(&self.name)
            && self.upstream.starts_with("https://")
            && self.upstream.len() <= 512
            && !self.header.is_empty()
            && self.header.len() <= 64
            && self
                .header
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
            && self.format.len() <= 256
            && self.format.matches("{value}").count() == 1
            && valid_env_name(&self.base_url_env)
            && self.placeholder_env.as_deref().is_none_or(valid_env_name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpecLeaseV11 {
    pub lease_id: String,
    /// The open binding (absent before the install grant creates one).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_id: Option<String>,
    pub credential_id: String,
    pub instance_id: String,
    /// The verified definition's digest: the bundle header digest.
    pub definition_digest: String,
    /// The definition's `maxBytes` (decoded file content bound).
    pub max_bytes: u64,
    pub delivery: CredentialDelivery,
    pub exclusive: bool,
    pub copy_back: bool,
    pub rotates: CredentialRotates,
    pub kind: CredentialLeaseKind,
    pub action: SpecLeaseAction,
    pub files: SpecFilesV11,
    pub env: Vec<String>,
    pub proxy: Vec<SpecProxyV11>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_interval_min: Option<u32>,
}

impl SpecLeaseV11 {
    fn is_valid(&self) -> bool {
        valid_credential_id(&self.lease_id)
            && self.binding_id.as_deref().is_none_or(valid_credential_id)
            && valid_credential_id(&self.credential_id)
            && valid_credential_id(&self.instance_id)
            && valid_sha256_hex(&self.definition_digest)
            && (1..=4_194_304).contains(&self.max_bytes)
            && self.files.is_valid()
            && self.env.len() <= CREDENTIAL_SPEC_ENV_MAX
            && self.env.iter().all(|n| valid_env_name(n))
            && unique(self.env.iter().map(String::as_str))
            && self.proxy.len() <= CREDENTIAL_SPEC_ENV_MAX
            && self.proxy.iter().all(SpecProxyV11::is_valid)
            && self.checkpoint_interval_min.is_none_or(|m| (5..=240).contains(&m))
            // A proxied login has no files, proxies every env entry, never copies back.
            && match self.delivery {
                CredentialDelivery::Proxy => {
                    self.files.is_empty()
                        && !self.copy_back
                        && self.proxy.len() == self.env.len()
                        && self.proxy.iter().all(|p| self.env.contains(&p.name))
                }
                CredentialDelivery::Guest => self.proxy.is_empty(),
            }
            && (self.kind == CredentialLeaseKind::Workload || self.delivery == CredentialDelivery::Guest)
            && (!self.copy_back || self.exclusive)
            // `recover` always names the RECOVER binding.
            && (self.action != SpecLeaseAction::Recover || self.binding_id.is_some())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpecResidueV11 {
    pub residue_id: String,
    pub binding_id: String,
    pub lease_id: String,
    pub action: SpecResidueAction,
    pub paths: Vec<String>,
}

impl SpecResidueV11 {
    fn is_valid(&self) -> bool {
        valid_credential_id(&self.residue_id)
            && valid_credential_id(&self.binding_id)
            && valid_credential_id(&self.lease_id)
            && !self.paths.is_empty()
            && self.paths.len() <= CREDENTIAL_SPEC_PATHS_MAX
            && self.paths.iter().all(|p| valid_credential_path(p))
            && unique(self.paths.iter().map(String::as_str))
    }
}

/// Operation credential spec (non-secret), canonical JSON on the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialSpecV11 {
    pub version: u32,
    pub sandbox_id: String,
    pub sandbox_owner_id: String,
    pub host_owner_id: String,
    pub leases: Vec<SpecLeaseV11>,
    pub residue: Vec<SpecResidueV11>,
}

impl CredentialSpecV11 {
    pub fn is_valid(&self) -> bool {
        self.version == 1
            && crate::valid_inventory_sandbox_id(&self.sandbox_id)
            && crate::valid_terminal_id(&self.sandbox_owner_id)
            && crate::valid_terminal_id(&self.host_owner_id)
            && self.leases.len() <= CREDENTIAL_SPEC_LEASES_MAX
            && self.residue.len() <= CREDENTIAL_SPEC_RESIDUES_MAX
            && self.leases.iter().all(SpecLeaseV11::is_valid)
            && self.residue.iter().all(SpecResidueV11::is_valid)
            && unique(self.leases.iter().map(|l| l.lease_id.as_str()))
            && unique(self.leases.iter().map(|l| l.credential_id.as_str()))
            && unique(self.residue.iter().map(|r| r.residue_id.as_str()))
            && unique(self.residue.iter().map(|r| r.binding_id.as_str()))
            // A `recover` residue row is recaptured only by a RECOVERING lease
            // of this spec (its RECOVER binding supersedes the residue's).
            && self.residue.iter().all(|r| {
                r.action == SpecResidueAction::Scrub
                    || self.leases.iter().any(|l| {
                        l.lease_id == r.lease_id && l.action == SpecLeaseAction::Recover
                    })
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CredentialSpecError {
    #[error("credential spec exceeds the byte cap")]
    TooLarge,
    #[error("credential spec length or digest mismatch")]
    Mismatch,
    #[error("credential spec is malformed")]
    Malformed,
}

/// Parse reassembled spec bytes (both parsers share the single cap).
/// The caller has already checked the digest against the dispatch reference.
pub fn parse_credential_spec(bytes: &[u8]) -> Result<CredentialSpecV11, CredentialSpecError> {
    if bytes.len() > CREDENTIAL_SPEC_MAX_BYTES {
        return Err(CredentialSpecError::TooLarge);
    }
    let spec: CredentialSpecV11 =
        serde_json::from_slice(bytes).map_err(|_| CredentialSpecError::Malformed)?;
    if !spec.is_valid() {
        return Err(CredentialSpecError::Malformed);
    }
    Ok(spec)
}

// --- daemon → server -------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialSpecRequestV11 {
    pub operation_id: String,
    pub digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleRequestReason {
    Install,
    RestoreEnv,
    Proxy,
}

/// Two variants (P3-4/R3-4). `install` carries `operationId` and no
/// `bindingId` (the server creates the binding); `restore_env`/`proxy` carry
/// the open `bindingId` and no `operationId` (env and proxy values only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialBundleRequestV11 {
    pub request_id: String,
    pub sandbox_id: String,
    pub lease_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_id: Option<String>,
    pub reason: BundleRequestReason,
}

impl CredentialBundleRequestV11 {
    pub fn is_valid(&self) -> bool {
        valid_credential_id(&self.request_id)
            && crate::valid_inventory_sandbox_id(&self.sandbox_id)
            && valid_credential_id(&self.lease_id)
            && match self.reason {
                BundleRequestReason::Install => {
                    self.binding_id.is_none()
                        && self
                            .operation_id
                            .as_deref()
                            .is_some_and(crate::valid_terminal_id)
                }
                BundleRequestReason::RestoreEnv | BundleRequestReason::Proxy => {
                    self.operation_id.is_none()
                        && self.binding_id.as_deref().is_some_and(valid_credential_id)
                }
            }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureKind {
    Stop,
    Kill,
    Free,
    Expiry,
    Checkpoint,
    Recovery,
    Login,
}

impl CaptureKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::Kill => "kill",
            Self::Free => "free",
            Self::Expiry => "expiry",
            Self::Checkpoint => "checkpoint",
            Self::Recovery => "recovery",
            Self::Login => "login",
        }
    }
    /// Teardown/recovery/login envelopes are never evicted from the outbox.
    pub fn evictable(self) -> bool {
        self == Self::Checkpoint
    }
}

/// Start of a capture upload. The chunks carry the complete envelope file
/// (prefix, header JSON, seal) so the server checks `envelopeDigest` over the
/// exact bytes before parsing the header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialCaptureBeginV11 {
    pub capture_id: String,
    pub lease_id: String,
    pub binding_id: String,
    pub kid_r: String,
    pub kind: CaptureKind,
    pub envelope_digest: String,
    pub envelope_len: u64,
    pub chunk_count: u32,
}

impl CredentialCaptureBeginV11 {
    pub fn is_valid(&self) -> bool {
        valid_credential_id(&self.capture_id)
            && valid_credential_id(&self.lease_id)
            && valid_credential_id(&self.binding_id)
            && valid_kid(&self.kid_r)
            && valid_sha256_hex(&self.envelope_digest)
            && self.envelope_len > 69
            && self.envelope_len <= CREDENTIAL_ENVELOPE_MAX_BYTES as u64
            && u64::from(self.chunk_count)
                == self
                    .envelope_len
                    .div_ceil(CREDENTIAL_CHUNK_RAW_BYTES as u64)
    }
}

/// One capture chunk (sealed bytes; still never logged).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialCaptureChunkV11 {
    pub capture_id: String,
    pub seq: u32,
    pub data: String,
}

impl std::fmt::Debug for CredentialCaptureChunkV11 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialCaptureChunkV11")
            .field("capture_id", &self.capture_id)
            .field("seq", &self.seq)
            .field(
                "data",
                &format_args!("<redacted {} chars>", self.data.len()),
            )
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialInstalledV11 {
    pub lease_id: String,
    pub binding_id: String,
    pub storage_seq: u64,
    pub file_count: u32,
    pub env_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialScrubbedV11 {
    pub sandbox_id: String,
    pub binding_ids: Vec<String>,
    pub verified_absent: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReturnKeyRefusal {
    /// `epoch < slot.epoch`: ignored; `currentEpoch` is the slot's epoch.
    Stale,
    /// Same epoch, different kid or key: refused, slot unchanged, alert.
    Substitution,
}

/// `credential.return.key.ack` (§4.3 step 2d). `currentEpoch` is always the
/// slot epoch after the frame was processed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialReturnKeyAckV11 {
    pub kid_r: String,
    pub epoch: u64,
    pub current_epoch: u64,
    pub retired_kids: Vec<String>,
    pub pending_under_retired: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused: Option<ReturnKeyRefusal>,
}

impl CredentialReturnKeyAckV11 {
    pub fn is_valid(&self) -> bool {
        valid_kid(&self.kid_r)
            && valid_epoch(self.epoch)
            && valid_epoch(self.current_epoch)
            && self.retired_kids.len() <= CREDENTIAL_RETIRED_KIDS_MAX
            && self.retired_kids.iter().all(|k| valid_kid(k))
            && unique(self.retired_kids.iter().map(String::as_str))
            && match self.refused {
                None => self.current_epoch == self.epoch,
                Some(ReturnKeyRefusal::Stale) => self.epoch < self.current_epoch,
                Some(ReturnKeyRefusal::Substitution) => self.epoch == self.current_epoch,
            }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CensusPendingV11 {
    pub capture_id: String,
    pub kid_r: String,
    pub kind: CaptureKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CensusQuarantinedV11 {
    pub capture_id: String,
    pub lease_id: String,
    pub kid_r: String,
}

/// Host-side binding phase reported by the census.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CensusBindingState {
    Installing,
    Active,
    Teardown,
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CensusEntryV11 {
    pub lease_id: String,
    pub binding_id: String,
    pub sandbox_id: String,
    pub state: CensusBindingState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub teardown_attempt_id: Option<String>,
    pub scrubbed_verified: bool,
    /// Unresolved envelopes only (quarantined ones are listed separately).
    pub pending: Vec<CensusPendingV11>,
}

impl CensusEntryV11 {
    fn is_valid(&self) -> bool {
        valid_credential_id(&self.lease_id)
            && valid_credential_id(&self.binding_id)
            && crate::valid_inventory_sandbox_id(&self.sandbox_id)
            && self
                .teardown_attempt_id
                .as_deref()
                .is_none_or(valid_credential_id)
            && self.pending.len() <= CREDENTIAL_CENSUS_PENDING_MAX
            && self
                .pending
                .iter()
                .all(|p| valid_credential_id(&p.capture_id) && valid_kid(&p.kid_r))
    }
}

/// One census page. `quarantined` appears on the first page only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialCensusV11 {
    pub page: u32,
    pub complete: bool,
    pub key_epoch: u64,
    pub quarantined: Vec<CensusQuarantinedV11>,
    pub entries: Vec<CensusEntryV11>,
}

impl CredentialCensusV11 {
    pub fn is_valid(&self) -> bool {
        self.page < CREDENTIAL_CENSUS_PAGES_MAX
            && self.key_epoch <= CREDENTIAL_EPOCH_MAX
            && self.quarantined.len() <= CREDENTIAL_CENSUS_QUARANTINED_MAX
            && (self.page == 0 || self.quarantined.is_empty())
            && self.quarantined.iter().all(|q| {
                valid_credential_id(&q.capture_id)
                    && valid_credential_id(&q.lease_id)
                    && valid_kid(&q.kid_r)
            })
            && self.entries.len() <= CREDENTIAL_CENSUS_ENTRIES_MAX
            && self.entries.iter().all(CensusEntryV11::is_valid)
            && unique(self.entries.iter().map(|e| e.binding_id.as_str()))
    }
}

/// Split a host census into pages: ≤ 32 entries and ≤ 48 KiB encoded each,
/// `quarantined` on page 0 only, the last page `complete`. Entries are never
/// dropped or truncated; inputs outside the per-entry bounds are refused.
pub fn paginate_census(
    key_epoch: u64,
    quarantined: Vec<CensusQuarantinedV11>,
    entries: Vec<CensusEntryV11>,
) -> Result<Vec<CredentialCensusV11>, CredentialSpecError> {
    let encoded = |page: &CredentialCensusV11| {
        serde_json::to_vec(page)
            .map(|v| v.len() + 32) // the `{"type":"credential.census",` envelope
            .unwrap_or(usize::MAX)
    };
    let mut pages = vec![CredentialCensusV11 {
        page: 0,
        complete: false,
        key_epoch,
        quarantined,
        entries: Vec::new(),
    }];
    for entry in entries {
        let current = pages.last_mut().ok_or(CredentialSpecError::Malformed)?;
        current.entries.push(entry);
        if current.entries.len() > CREDENTIAL_CENSUS_ENTRIES_MAX
            || encoded(current) > CREDENTIAL_CENSUS_PAGE_BYTES_MAX
        {
            let entry = current
                .entries
                .pop()
                .ok_or(CredentialSpecError::Malformed)?;
            let next = CredentialCensusV11 {
                page: current.page + 1,
                complete: false,
                key_epoch,
                quarantined: Vec::new(),
                entries: vec![entry],
            };
            if encoded(&next) > CREDENTIAL_CENSUS_PAGE_BYTES_MAX {
                return Err(CredentialSpecError::TooLarge);
            }
            pages.push(next);
        }
    }
    if let Some(last) = pages.last_mut() {
        last.complete = true;
    }
    if pages.len() as u32 > CREDENTIAL_CENSUS_PAGES_MAX
        || pages
            .iter()
            .any(|p| !p.is_valid() || encoded(p) > CREDENTIAL_CENSUS_PAGE_BYTES_MAX)
    {
        return Err(CredentialSpecError::TooLarge);
    }
    Ok(pages)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialQuarantineDiscardedV11 {
    pub capture_ids: Vec<String>,
}

fn valid_capture_ids(ids: &[String]) -> bool {
    !ids.is_empty()
        && ids.len() <= CREDENTIAL_QUARANTINE_DISCARD_MAX
        && ids.iter().all(|id| valid_credential_id(id))
        && unique(ids.iter().map(String::as_str))
}

// --- server → daemon -------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialReturnKeyV11 {
    pub kid_r: String,
    pub epoch: u64,
    /// X25519 public key, 43 characters of unpadded base64url.
    pub public_key: String,
    pub server_origin: String,
}

impl CredentialReturnKeyV11 {
    pub fn is_valid(&self) -> bool {
        valid_kid(&self.kid_r)
            && valid_epoch(self.epoch)
            && self.public_key.len() == 43
            && self.public_key.bytes().all(|b| b64_value(b).is_some())
            && valid_origin(&self.server_origin)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialSpecChunkV11 {
    pub operation_id: String,
    pub seq: u32,
    pub data: String,
}

/// The server cannot serve a spec (unknown or terminal operation, digest
/// mismatch). The host fails the operation before any guest effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialSpecRefusedV11 {
    pub operation_id: String,
    pub code: String,
}

/// Start of a bundle stream. `install` returns the NEW binding; restore
/// echoes the open one with `fileCount = 0`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialBundleBeginV11 {
    pub request_id: String,
    pub binding_id: String,
    pub storage_seq: u64,
    pub file_count: u32,
    pub env_count: u32,
    pub bundle_len: u64,
    pub chunk_count: u32,
}

impl CredentialBundleBeginV11 {
    pub fn is_valid(&self) -> bool {
        valid_credential_id(&self.request_id)
            && valid_credential_id(&self.binding_id)
            && valid_epoch(self.storage_seq)
            && self.file_count <= 4096
            && self.env_count <= 16
            && (CREDENTIAL_BUNDLE_MIN_BYTES as u64..=CREDENTIAL_BUNDLE_MAX_BYTES as u64)
                .contains(&self.bundle_len)
            && u64::from(self.chunk_count)
                == self.bundle_len.div_ceil(CREDENTIAL_CHUNK_RAW_BYTES as u64)
    }
}

/// One bundle chunk: credential PLAINTEXT. Never journaled; `Debug` redacts.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialBundleChunkV11 {
    pub request_id: String,
    pub seq: u32,
    pub data: String,
}

impl std::fmt::Debug for CredentialBundleChunkV11 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialBundleChunkV11")
            .field("request_id", &self.request_id)
            .field("seq", &self.seq)
            .field(
                "data",
                &format_args!("<redacted {} chars>", self.data.len()),
            )
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialBundleRefusedV11 {
    pub request_id: String,
    pub code: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineDiscardReason {
    ForceReleased,
    OwnerDiscard,
    HostDeleted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialQuarantineDiscardV11 {
    pub capture_ids: Vec<String>,
    pub reason: QuarantineDiscardReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureAckOutcome {
    Committed,
    Unchanged,
    Discarded,
    Rejected,
    Deferred,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureAckReason {
    // DISCARDED (authorized)
    ForceReleased,
    CopyBackDisabled,
    Superseded,
    Incomplete,
    AccountDeleted,
    // REJECTED (never scrub; quarantine)
    ContextMismatch,
    DecryptFailed,
    InvalidBundle,
    UnknownKid,
    UnknownLease,
    BindingClosed,
}

impl CaptureAckReason {
    pub fn is_discard(self) -> bool {
        matches!(
            self,
            Self::ForceReleased
                | Self::CopyBackDisabled
                | Self::Superseded
                | Self::Incomplete
                | Self::AccountDeleted
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialCaptureAckV11 {
    pub capture_id: String,
    pub outcome: CaptureAckOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<CaptureAckReason>,
}

impl CredentialCaptureAckV11 {
    pub fn is_valid(&self) -> bool {
        valid_credential_id(&self.capture_id)
            && match (self.outcome, self.reason) {
                (CaptureAckOutcome::Discarded, Some(r)) => r.is_discard(),
                (CaptureAckOutcome::Rejected, Some(r)) => !r.is_discard(),
                (
                    CaptureAckOutcome::Committed
                    | CaptureAckOutcome::Unchanged
                    | CaptureAckOutcome::Deferred,
                    None,
                ) => true,
                _ => false,
            }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialRevokeV11 {
    pub lease_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialCensusAckV11 {
    pub page: u32,
}

// --- teardown receipt outcomes (§6 "Teardown receipt"; wired in C8b) -----------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum TeardownCaptureV11 {
    Acked {
        capture_id: String,
        outcome: CaptureAckOutcome,
    },
    Durable {
        capture_id: String,
    },
    None,
    Failed {
        reason: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeardownScrubV11 {
    Verified,
    NotRun,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialTeardownOutcomeV11 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
    pub binding_id: String,
    pub capture: TeardownCaptureV11,
    pub scrub: TeardownScrubV11,
}

impl CredentialTeardownOutcomeV11 {
    pub fn is_valid(&self) -> bool {
        self.lease_id.as_deref().is_none_or(valid_credential_id)
            && valid_credential_id(&self.binding_id)
            && match &self.capture {
                TeardownCaptureV11::Acked { capture_id, .. }
                | TeardownCaptureV11::Durable { capture_id } => valid_credential_id(capture_id),
                TeardownCaptureV11::None => true,
                TeardownCaptureV11::Failed { reason } => valid_code(reason),
            }
    }
}

pub fn valid_teardown_outcomes(outcomes: &[CredentialTeardownOutcomeV11]) -> bool {
    outcomes.len() <= CREDENTIAL_TEARDOWN_OUTCOMES_MAX
        && outcomes.iter().all(CredentialTeardownOutcomeV11::is_valid)
        && unique(outcomes.iter().map(|o| o.binding_id.as_str()))
}

// --- frame validation (encode and parse) ---------------------------------------

fn valid_chunk(id: &str, seq: u32, data: &str, max_chunks: usize) -> bool {
    valid_credential_id(id) && (seq as usize) < max_chunks && valid_chunk_data(data)
}

pub(crate) fn valid_daemon_credential(message: &crate::DaemonControlMessage) -> bool {
    use crate::DaemonControlMessage as M;
    match message {
        M::CredentialSpecRequest(r) => {
            crate::valid_terminal_id(&r.operation_id) && valid_sha256_hex(&r.digest)
        }
        M::CredentialBundleRequest(r) => r.is_valid(),
        M::CredentialCaptureBegin(r) => r.is_valid(),
        M::CredentialCaptureChunk(r) => {
            valid_chunk(&r.capture_id, r.seq, &r.data, CREDENTIAL_CAPTURE_CHUNKS_MAX)
        }
        M::CredentialInstalled(r) => {
            valid_credential_id(&r.lease_id)
                && valid_credential_id(&r.binding_id)
                && valid_epoch(r.storage_seq)
                && r.file_count <= 4096
                && r.env_count <= 16
        }
        M::CredentialScrubbed(r) => {
            crate::valid_inventory_sandbox_id(&r.sandbox_id)
                && !r.binding_ids.is_empty()
                && r.binding_ids.len() <= CREDENTIAL_SCRUBBED_BINDINGS_MAX
                && r.binding_ids.iter().all(|id| valid_credential_id(id))
                && unique(r.binding_ids.iter().map(String::as_str))
        }
        M::CredentialReturnKeyAck(r) => r.is_valid(),
        M::CredentialCensus(r) => r.is_valid(),
        M::CredentialQuarantineDiscarded(r) => valid_capture_ids(&r.capture_ids),
        _ => true,
    }
}

pub(crate) fn valid_server_credential(message: &crate::ServerControlMessage) -> bool {
    use crate::ServerControlMessage as M;
    match message {
        M::CredentialReturnKey(r) => r.is_valid(),
        M::CredentialSpecChunk(r) => {
            crate::valid_terminal_id(&r.operation_id)
                && (r.seq as usize) < CREDENTIAL_SPEC_CHUNKS_MAX
                && valid_chunk_data(&r.data)
        }
        M::CredentialSpecRefused(r) => {
            crate::valid_terminal_id(&r.operation_id) && valid_code(&r.code)
        }
        M::CredentialBundleBegin(r) => r.is_valid(),
        M::CredentialBundleChunk(r) => {
            valid_chunk(&r.request_id, r.seq, &r.data, CREDENTIAL_BUNDLE_CHUNKS_MAX)
        }
        M::CredentialBundleRefused(r) => valid_credential_id(&r.request_id) && valid_code(&r.code),
        M::CredentialQuarantineDiscard(r) => valid_capture_ids(&r.capture_ids),
        M::CredentialCaptureAck(r) => r.is_valid(),
        M::CredentialRevoke(r) => valid_credential_id(&r.lease_id) && valid_code(&r.reason),
        M::CredentialCensusAck(r) => r.page < CREDENTIAL_CENSUS_PAGES_MAX,
        M::OperationDispatch(d) => {
            d.credential_spec.as_ref().is_none_or(|spec| {
                spec.is_valid() && CREDENTIAL_SPEC_DISPATCH_KINDS.contains(&d.kind.as_str())
            }) && d
                .credential_capture
                .is_none_or(|_| CREDENTIAL_CAPTURE_DISPATCH_KINDS.contains(&d.kind.as_str()))
                && d.credential_teardown
                    .is_none_or(|_| CREDENTIAL_CAPTURE_DISPATCH_KINDS.contains(&d.kind.as_str()))
        }
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Limits {
        id_max_bytes: usize,
        chunk_raw_bytes: usize,
        chunk_window: usize,
        spec_max_bytes: usize,
        spec_chunks_max: usize,
        spec_leases_max: usize,
        spec_residues_max: usize,
        spec_paths_max: usize,
        spec_env_max: usize,
        bundle_max_bytes: usize,
        bundle_chunks_max: usize,
        envelope_max_bytes: usize,
        capture_chunks_max: usize,
        census_entries_max: usize,
        census_pending_max: usize,
        census_quarantined_max: usize,
        census_page_bytes_max: usize,
        census_pages_max: u32,
        scrubbed_bindings_max: usize,
        teardown_outcomes_max: usize,
        retired_kids_max: usize,
        quarantine_discard_max: usize,
        return_key_epoch_max: u64,
    }

    #[test]
    fn constants_match_the_shared_limits_file() {
        let l: Limits = serde_json::from_str(CREDENTIAL_PROTOCOL_LIMITS_JSON).unwrap();
        assert_eq!(l.id_max_bytes, CREDENTIAL_ID_MAX_BYTES);
        assert_eq!(l.chunk_raw_bytes, CREDENTIAL_CHUNK_RAW_BYTES);
        assert_eq!(l.chunk_window, CREDENTIAL_CHUNK_WINDOW);
        assert_eq!(l.spec_max_bytes, CREDENTIAL_SPEC_MAX_BYTES);
        assert_eq!(l.spec_chunks_max, CREDENTIAL_SPEC_CHUNKS_MAX);
        assert_eq!(l.spec_leases_max, CREDENTIAL_SPEC_LEASES_MAX);
        assert_eq!(l.spec_residues_max, CREDENTIAL_SPEC_RESIDUES_MAX);
        assert_eq!(l.spec_paths_max, CREDENTIAL_SPEC_PATHS_MAX);
        assert_eq!(l.spec_env_max, CREDENTIAL_SPEC_ENV_MAX);
        assert_eq!(l.bundle_max_bytes, CREDENTIAL_BUNDLE_MAX_BYTES);
        assert_eq!(l.bundle_chunks_max, CREDENTIAL_BUNDLE_CHUNKS_MAX);
        assert_eq!(l.envelope_max_bytes, CREDENTIAL_ENVELOPE_MAX_BYTES);
        assert_eq!(l.capture_chunks_max, CREDENTIAL_CAPTURE_CHUNKS_MAX);
        assert_eq!(l.census_entries_max, CREDENTIAL_CENSUS_ENTRIES_MAX);
        assert_eq!(l.census_pending_max, CREDENTIAL_CENSUS_PENDING_MAX);
        assert_eq!(l.census_quarantined_max, CREDENTIAL_CENSUS_QUARANTINED_MAX);
        assert_eq!(l.census_page_bytes_max, CREDENTIAL_CENSUS_PAGE_BYTES_MAX);
        assert_eq!(l.census_pages_max, CREDENTIAL_CENSUS_PAGES_MAX);
        assert_eq!(l.scrubbed_bindings_max, CREDENTIAL_SCRUBBED_BINDINGS_MAX);
        assert_eq!(l.teardown_outcomes_max, CREDENTIAL_TEARDOWN_OUTCOMES_MAX);
        assert_eq!(l.retired_kids_max, CREDENTIAL_RETIRED_KIDS_MAX);
        assert_eq!(l.quarantine_discard_max, CREDENTIAL_QUARANTINE_DISCARD_MAX);
        assert_eq!(l.return_key_epoch_max, CREDENTIAL_EPOCH_MAX);
        // Derived bounds are exact, not estimated.
        assert_eq!(
            CREDENTIAL_BUNDLE_CHUNKS_MAX,
            CREDENTIAL_BUNDLE_MAX_BYTES.div_ceil(CREDENTIAL_CHUNK_RAW_BYTES)
        );
        assert_eq!(
            CREDENTIAL_CAPTURE_CHUNKS_MAX,
            CREDENTIAL_ENVELOPE_MAX_BYTES.div_ceil(CREDENTIAL_CHUNK_RAW_BYTES)
        );
        assert_eq!(CREDENTIAL_SPEC_MAX_BYTES % CREDENTIAL_CHUNK_RAW_BYTES, 0);
        assert_eq!(
            CREDENTIAL_SPEC_MAX_BYTES,
            8 * 106_496 + 16 * 18_432 + 1_024 + 31_744,
            "1152 KiB covers 8 lease + 16 residue entries at their measured caps"
        );
        // A full chunk frame stays well inside the 64 KiB control bound.
        let frame = serde_json::json!({
            "type": "credential.bundle.chunk",
            "requestId": "r".repeat(64),
            "seq": 147,
            "data": "A".repeat(CREDENTIAL_CHUNK_TEXT_MAX),
        });
        assert!(frame.to_string().len() < crate::json_control_max_bytes());
    }

    #[test]
    fn chunk_codec_is_strict_and_round_trips() {
        for len in [1usize, 2, 3, 4, 31, 32, 33, CREDENTIAL_CHUNK_RAW_BYTES] {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let text = encode_chunk_data(&bytes);
            assert!(valid_chunk_data(&text), "{len}");
            let mut out = vec![0u8; chunk_data_len(&text).unwrap()];
            decode_chunk_data_into(&text, &mut out).unwrap();
            assert_eq!(out, bytes);
        }
        assert!(!valid_chunk_data(""));
        assert!(!valid_chunk_data("A")); // impossible length
        assert!(!valid_chunk_data("AB==")); // padding
        assert!(!valid_chunk_data("AB+/")); // standard alphabet
        assert!(!valid_chunk_data("AB")); // non-canonical trailing bits ("AB" ≠ "AA")
        assert!(valid_chunk_data("AA"));
        let over = encode_chunk_data(&vec![0u8; CREDENTIAL_CHUNK_RAW_BYTES + 1]);
        assert!(!valid_chunk_data(&over));
        let mut wrong = [0u8; 2];
        assert!(decode_chunk_data_into("AA", &mut wrong).is_none());
    }

    #[test]
    fn credential_paths_follow_the_definition_rules() {
        for ok in [".config/gh/hosts.yml", "a", ".aws", "dir/.wssp"] {
            assert!(valid_credential_path(ok), "{ok}");
        }
        for bad in [
            "",
            "/abs",
            "a/../b",
            "./a",
            "a//b",
            "a/",
            "a\\b",
            "a:b",
            "a\0b",
            "a\nb",
            ".wssp",
            ".wssp-journal/x",
            "auth/.wssp-cred-0123456789abcdef",
            "auth/nested/.wssp-cred-0123456789abcdef/token",
            "auth/.wssp-cred-other",
        ] {
            assert!(!valid_credential_path(bad), "{bad:?}");
        }
        assert!(valid_credential_path(&"a".repeat(255)));
        assert!(!valid_credential_path(&"a".repeat(256)));
    }

    #[test]
    fn return_key_ack_refusal_matches_epochs() {
        let ack = |epoch, current, refused| CredentialReturnKeyAckV11 {
            kid_r: "0123456789abcdef".into(),
            epoch,
            current_epoch: current,
            retired_kids: vec![],
            pending_under_retired: 0,
            refused,
        };
        assert!(ack(2, 2, None).is_valid());
        assert!(ack(1, 2, Some(ReturnKeyRefusal::Stale)).is_valid());
        assert!(ack(2, 2, Some(ReturnKeyRefusal::Substitution)).is_valid());
        assert!(!ack(1, 2, None).is_valid());
        assert!(!ack(3, 2, Some(ReturnKeyRefusal::Stale)).is_valid());
        assert!(!ack(1, 2, Some(ReturnKeyRefusal::Substitution)).is_valid());
        assert!(!ack(0, 0, None).is_valid());
    }

    #[test]
    fn capture_ack_outcome_and_reason_pair_up() {
        let ack = |outcome, reason| CredentialCaptureAckV11 {
            capture_id: "c1".into(),
            outcome,
            reason,
        };
        use CaptureAckOutcome as O;
        use CaptureAckReason as R;
        assert!(ack(O::Committed, None).is_valid());
        assert!(ack(O::Deferred, None).is_valid());
        assert!(ack(O::Discarded, Some(R::Superseded)).is_valid());
        assert!(ack(O::Rejected, Some(R::BindingClosed)).is_valid());
        assert!(!ack(O::Committed, Some(R::Superseded)).is_valid());
        assert!(!ack(O::Discarded, Some(R::DecryptFailed)).is_valid());
        assert!(!ack(O::Rejected, Some(R::Incomplete)).is_valid());
        assert!(!ack(O::Rejected, None).is_valid());
    }

    #[test]
    fn chunk_frames_redact_their_payload_in_debug() {
        let data = encode_chunk_data(b"sentinel-plaintext-value");
        let bundle = CredentialBundleChunkV11 {
            request_id: "r1".into(),
            seq: 0,
            data: data.clone(),
        };
        let capture = CredentialCaptureChunkV11 {
            capture_id: "c1".into(),
            seq: 0,
            data: data.clone(),
        };
        for shown in [format!("{bundle:?}"), format!("{capture:#?}")] {
            assert!(!shown.contains(&data), "{shown}");
            assert!(!shown.contains("sentinel"), "{shown}");
        }
    }

    fn max_entry(i: usize) -> CensusEntryV11 {
        let id = |p: &str| format!("{p}{i:0>63}")[..64].to_owned();
        CensusEntryV11 {
            lease_id: id("l"),
            binding_id: id("b"),
            sandbox_id: id("s"),
            state: CensusBindingState::Teardown,
            teardown_attempt_id: Some(id("t")),
            scrubbed_verified: false,
            pending: (0..CREDENTIAL_CENSUS_PENDING_MAX)
                .map(|p| CensusPendingV11 {
                    capture_id: id(&format!("c{p}")),
                    kid_r: "0123456789abcdef".into(),
                    kind: CaptureKind::Checkpoint,
                })
                .collect(),
        }
    }

    /// Census sizing (§6 bounds): every page of a worst-case census, the
    /// full quarantined list included, encodes within 48 KiB and nothing is
    /// dropped.
    #[test]
    fn worst_case_census_paginates_within_the_page_bound() {
        let quarantined: Vec<_> = (0..CREDENTIAL_CENSUS_QUARANTINED_MAX)
            .map(|i| CensusQuarantinedV11 {
                capture_id: format!("q{i:0>63}"),
                lease_id: format!("l{i:0>63}"),
                kid_r: "0123456789abcdef".into(),
            })
            .collect();
        let entries: Vec<_> = (0..200).map(max_entry).collect();
        let pages =
            paginate_census(CREDENTIAL_EPOCH_MAX, quarantined.clone(), entries.clone()).unwrap();
        assert!(pages.len() > 1);
        let mut seen = Vec::new();
        for (i, page) in pages.iter().enumerate() {
            assert_eq!(page.page as usize, i);
            assert_eq!(page.complete, i == pages.len() - 1);
            assert!(page.is_valid());
            let frame = serde_json::json!({"type": "credential.census"});
            let mut value = serde_json::to_value(page).unwrap();
            value["type"] = frame["type"].clone();
            let bytes = value.to_string().len();
            assert!(
                bytes <= CREDENTIAL_CENSUS_PAGE_BYTES_MAX,
                "page {i}: {bytes}"
            );
            seen.extend(page.entries.iter().cloned());
        }
        assert_eq!(pages[0].quarantined, quarantined);
        assert!(pages[1..].iter().all(|p| p.quarantined.is_empty()));
        assert_eq!(seen, entries);
        // An empty census is one complete page.
        let empty = paginate_census(0, vec![], vec![]).unwrap();
        assert_eq!(empty.len(), 1);
        assert!(empty[0].complete);
    }

    fn spec_lease(i: usize) -> SpecLeaseV11 {
        SpecLeaseV11 {
            lease_id: format!("lease{i}"),
            binding_id: None,
            credential_id: format!("cred{i}"),
            instance_id: format!("inst{i}"),
            definition_digest: "a".repeat(64),
            max_bytes: 1_048_576,
            delivery: CredentialDelivery::Guest,
            exclusive: true,
            copy_back: true,
            rotates: CredentialRotates::Unknown,
            kind: CredentialLeaseKind::Workload,
            action: SpecLeaseAction::Inject,
            files: SpecFilesV11 {
                required: vec![format!(".config/tool{i}/hosts.yml")],
                optional: vec![],
                exclude: vec![],
            },
            env: vec![],
            proxy: vec![],
            checkpoint_interval_min: Some(30),
        }
    }

    fn spec() -> CredentialSpecV11 {
        CredentialSpecV11 {
            version: 1,
            sandbox_id: "sbx-1".into(),
            sandbox_owner_id: "owner-1".into(),
            host_owner_id: "owner-1".into(),
            leases: (0..CREDENTIAL_SPEC_LEASES_MAX).map(spec_lease).collect(),
            residue: (0..CREDENTIAL_SPEC_RESIDUES_MAX)
                .map(|i| SpecResidueV11 {
                    residue_id: format!("res{i}"),
                    binding_id: format!("bind{i}"),
                    lease_id: format!("old{i}"),
                    action: SpecResidueAction::Scrub,
                    paths: vec![".config/old/hosts.yml".into()],
                })
                .collect(),
        }
    }

    /// The single cap: a spec at exactly `credentialSpecMaxBytes` parses, one
    /// byte more is refused (never truncated).
    #[test]
    fn spec_parser_enforces_the_single_cap_exactly() {
        let mut bytes = serde_json::to_vec(&spec()).unwrap();
        assert!(parse_credential_spec(&bytes).is_ok());
        bytes.resize(CREDENTIAL_SPEC_MAX_BYTES, b' ');
        assert_eq!(parse_credential_spec(&bytes).unwrap(), spec());
        bytes.push(b' ');
        assert_eq!(
            parse_credential_spec(&bytes),
            Err(CredentialSpecError::TooLarge)
        );
    }

    #[test]
    fn spec_rules_refuse_inconsistent_entries() {
        let check = |f: &dyn Fn(&mut CredentialSpecV11)| {
            let mut s = spec();
            f(&mut s);
            parse_credential_spec(&serde_json::to_vec(&s).unwrap()).is_ok()
        };
        assert!(check(&|_| {}));
        assert!(!check(&|s| s.leases.push(spec_lease(99))));
        assert!(!check(
            &|s| s.leases[0].files.required[0] = "../etc/passwd".into()
        ));
        assert!(!check(
            &|s| s.leases[1].credential_id = s.leases[0].credential_id.clone()
        ));
        assert!(!check(&|s| s.leases[0].delivery = CredentialDelivery::Proxy));
        assert!(!check(&|s| {
            s.leases[0].exclusive = false;
        }));
        assert!(!check(&|s| s.residue[0].action = SpecResidueAction::Recover));
        assert!(check(&|s| {
            s.residue[0].action = SpecResidueAction::Recover;
            s.residue[0].lease_id = "lease0".into();
            s.leases[0].action = SpecLeaseAction::Recover;
            s.leases[0].binding_id = Some("rec0".into());
        }));
        assert!(!check(&|s| s.leases[0].action = SpecLeaseAction::Recover));
        let mut value = serde_json::to_value(spec()).unwrap();
        value["leases"][0]["extra"] = serde_json::json!(1);
        assert!(parse_credential_spec(value.to_string().as_bytes()).is_err());
        // A proxied lease: env only, every entry proxied, no copy-back.
        assert!(check(&|s| {
            let l = &mut s.leases[0];
            l.delivery = CredentialDelivery::Proxy;
            l.copy_back = false;
            l.files = SpecFilesV11::default();
            l.env = vec!["API_KEY".into()];
            l.proxy = vec![SpecProxyV11 {
                name: "API_KEY".into(),
                upstream: "https://api.example.com/v1".into(),
                header: "Authorization".into(),
                format: "Bearer {value}".into(),
                base_url_env: "API_BASE_URL".into(),
                placeholder_env: None,
            }];
        }));
    }
}
