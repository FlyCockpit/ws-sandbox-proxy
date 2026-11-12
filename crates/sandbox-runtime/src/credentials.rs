//! Credential guest operations: request and outcome
//! types for pack, restore, scrub and quiesce, the fixed guest helper, and
//! the stdin/stdout framing shared by the Incus runtime and its tests.
//!
//! The helper is `python3 -I -S -B -c <CREDENTIAL_HELPER> <mode>`; every control
//! field (paths included) and the restore payload travel on stdin:
//!
//! ```text
//! stdin : u32be controlLen | control JSON | payload (restore: entry data in order)
//! stdout: u32be reportLen  | report JSON  | bundle (pack: report.bundleLen bytes)
//! ```
//!
//! Plaintext never appears in argv, errors or `Debug` output.

use login_definition::BundleFileKind;
use sandbox_protocol::SandboxErrorCode;
use zeroize::Zeroizing;

use crate::RuntimeError;

/// The fixed guest helper: the shared descriptor-relative walk and cgroup v2
/// freezer (also used by the image-cache capture scrub) plus the credential
/// modes. The shared files load no module, so the helper's first line does.
pub const CREDENTIAL_HELPER: &str = concat!(
    "import errno, os, stat, time\n",
    include_str!("incus/dirfd_walk.py"),
    include_str!("incus/guest_freeze.py"),
    include_str!("incus/credential-helper.py")
);

/// Largest control JSON the helper accepts (and the runtime sends).
pub const CREDENTIAL_CONTROL_MAX_BYTES: usize = 1 << 20;
/// Largest report JSON the runtime reads back.
pub const CREDENTIAL_REPORT_MAX_BYTES: usize = 64 * 1024;
/// Declared (definition) paths: §3 bound.
pub const CREDENTIAL_DECLARED_PATH_MAX_BYTES: usize = 255;

/// §3 home-relative path rule for declared paths: relative, no empty, `.` or
/// `..` segment, no `\`, `:`, NUL or control byte, ≤ 255 bytes, never under
/// `.wssp*`.
pub fn validate_home_relative(path: &str) -> bool {
    login_definition::paths::path_problem(path, CREDENTIAL_DECLARED_PATH_MAX_BYTES).is_none()
}

/// The guest account credential files belong to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialGuest {
    pub sandbox_id: String,
    pub uid: u32,
    pub gid: u32,
    /// Absolute guest home directory.
    pub home: String,
}

impl CredentialGuest {
    fn validate(&self) -> Result<(), RuntimeError> {
        let home_ok = self.home.starts_with('/')
            && self.home.len() <= 4096
            && !self.home.contains('\0')
            && !self.home.split('/').any(|s| s == "." || s == "..");
        if !home_ok {
            return Err(invalid("invalid credential guest home"));
        }
        Ok(())
    }
}

/// Declared credential paths, home-relative.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CredentialPathSet {
    pub required: Vec<String>,
    pub optional: Vec<String>,
    pub exclude: Vec<String>,
}

impl CredentialPathSet {
    fn validate(&self) -> Result<(), RuntimeError> {
        if self
            .required
            .iter()
            .chain(&self.optional)
            .chain(&self.exclude)
            .all(|p| validate_home_relative(p))
        {
            Ok(())
        } else {
            Err(invalid("invalid credential path"))
        }
    }

    /// Included (required ∪ optional) paths, sorted and deduplicated.
    pub fn included(&self) -> Vec<String> {
        let mut all: Vec<String> = self
            .required
            .iter()
            .chain(&self.optional)
            .cloned()
            .collect();
        all.sort();
        all.dedup();
        all
    }

    fn excluded(&self, path: &str) -> bool {
        self.exclude
            .iter()
            .any(|e| login_definition::paths::path_within(path, e))
    }
}

/// Owned plaintext from or for the guest helper. Wiped on drop; no `Clone`;
/// `Debug` prints the length only.
pub struct CredentialBytes(Zeroizing<Vec<u8>>);

impl CredentialBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn into_zeroizing(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
    pub(crate) fn from_zeroizing(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Debug for CredentialBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CredentialBytes(<redacted {} bytes>)", self.0.len())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialPackRequest {
    pub guest: CredentialGuest,
    pub paths: CredentialPathSet,
    pub definition_digest: [u8; 32],
    pub max_bytes: usize,
}

#[derive(Debug)]
pub struct CredentialPackOutcome {
    /// Bundle v1 with `envCount = 0`.
    pub bundle: CredentialBytes,
    pub file_count: u32,
    pub skipped_links: u32,
    pub skipped_special: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CredentialRestoreFile<'a> {
    pub kind: BundleFileKind,
    pub path: &'a str,
    pub mode: u16,
    /// Empty for a directory.
    pub data: &'a [u8],
}

impl std::fmt::Debug for CredentialRestoreFile<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialRestoreFile")
            .field("kind", &self.kind)
            .field("path", &self.path)
            .field("mode", &format_args!("{:o}", self.mode))
            .field(
                "data",
                &format_args!("<{} bytes redacted>", self.data.len()),
            )
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRestoreRequest<'a> {
    pub guest: CredentialGuest,
    /// Declared paths; every included path is cleared before any write.
    pub declared: CredentialPathSet,
    /// Entries in bundle order (sorted by path bytes).
    pub files: Vec<CredentialRestoreFile<'a>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRestoreOutcome {
    pub files_written: u32,
    pub dirs_created: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialScrubRequest {
    pub guest: CredentialGuest,
    /// Home-relative paths to remove (a link is unlinked, never followed).
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialScrubOutcome {
    pub verified_absent: bool,
    pub removed: u32,
    pub links_unlinked: u32,
    pub failed_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialQuiesceOutcome {
    /// Guest-uid processes sent SIGTERM.
    pub terminated: u32,
    /// Guest-uid processes sent SIGKILL (after the SIGTERM grace).
    pub killed: u32,
    /// The kill phase ran under the cgroup v2 freezer.
    pub freezer: bool,
}

fn invalid(message: &str) -> RuntimeError {
    RuntimeError::new(SandboxErrorCode::ProtocolError, message.to_owned())
}

/// Every entry lies within a declared, non-excluded path, entries are sorted
/// and unique, directories carry no data and modes are normalized.
pub(crate) fn validate_restore(request: &CredentialRestoreRequest<'_>) -> Result<(), RuntimeError> {
    request.guest.validate()?;
    request.declared.validate()?;
    let included = request.declared.included();
    let mut previous: Option<&[u8]> = None;
    if request.files.len() > login_definition::limits::BUNDLE_FILE_COUNT_MAX {
        return Err(invalid("too many credential entries"));
    }
    for file in &request.files {
        let ok = login_definition::paths::path_problem(
            file.path,
            login_definition::limits::BUNDLE_PATH_MAX_BYTES,
        )
        .is_none()
            && included
                .iter()
                .any(|d| login_definition::paths::path_within(file.path, d))
            && !request.declared.excluded(file.path)
            && previous.is_none_or(|p| p < file.path.as_bytes())
            && (file.kind == BundleFileKind::File || file.data.is_empty());
        if !ok {
            return Err(invalid("invalid credential restore entry"));
        }
        previous = Some(file.path.as_bytes());
    }
    Ok(())
}

pub(crate) fn validate_pack(request: &CredentialPackRequest) -> Result<(), RuntimeError> {
    request.guest.validate()?;
    request.paths.validate()?;
    if request.max_bytes == 0
        || request.max_bytes > login_definition::limits::MAX_BYTES_MAX as usize
        || request.paths.included().is_empty()
    {
        return Err(invalid("invalid credential pack request"));
    }
    Ok(())
}

pub(crate) fn validate_scrub(request: &CredentialScrubRequest) -> Result<(), RuntimeError> {
    request.guest.validate()?;
    if request.paths.len() > 16 * login_definition::limits::FILE_PATHS_MAX
        || !request.paths.iter().all(|p| validate_home_relative(p))
    {
        return Err(invalid("invalid credential scrub path"));
    }
    Ok(())
}

pub(crate) fn validate_guest(guest: &CredentialGuest) -> Result<(), RuntimeError> {
    guest.validate()
}

pub(crate) fn validate_quiesce(guest: &CredentialGuest) -> Result<(), RuntimeError> {
    guest.validate()?;
    if guest.uid == 0 {
        return Err(invalid("credential quiesce needs a non-root guest uid"));
    }
    Ok(())
}

/// Helper control JSON per mode (paths only; never plaintext).
pub(crate) fn pack_control(request: &CredentialPackRequest) -> serde_json::Value {
    serde_json::json!({
        "home": request.guest.home,
        "required": request.paths.required,
        "optional": request.paths.optional,
        "exclude": request.paths.exclude,
        "digest": hex(&request.definition_digest),
        "maxBytes": request.max_bytes,
    })
}

pub(crate) fn restore_control(request: &CredentialRestoreRequest<'_>) -> serde_json::Value {
    let entries: Vec<serde_json::Value> = request
        .files
        .iter()
        .map(|f| {
            serde_json::json!({
                "kind": match f.kind { BundleFileKind::File => 1, BundleFileKind::Dir => 2 },
                "path": f.path,
                "mode": login_definition::bundle::normalize_mode(f.kind, f.mode),
                "len": f.data.len(),
            })
        })
        .collect();
    serde_json::json!({
        "home": request.guest.home,
        "declared": {
            "required": request.declared.required,
            "optional": request.declared.optional,
            "exclude": request.declared.exclude,
        },
        "entries": entries,
    })
}

pub(crate) fn scrub_control(request: &CredentialScrubRequest) -> serde_json::Value {
    serde_json::json!({"home": request.guest.home, "paths": request.paths})
}

pub(crate) fn quiesce_control(guest: &CredentialGuest) -> serde_json::Value {
    serde_json::json!({"uid": guest.uid})
}

/// `u32be len | bytes` (control and report framing).
pub(crate) fn frame(bytes: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    if bytes.len() > CREDENTIAL_CONTROL_MAX_BYTES {
        return Err(invalid("credential helper control too large"));
    }
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn count(report: &serde_json::Value, key: &str) -> Result<u32, RuntimeError> {
    report
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .and_then(|v| u32::try_from(v).ok())
        .ok_or_else(helper_malformed)
}

pub(crate) fn helper_malformed() -> RuntimeError {
    RuntimeError::new(
        SandboxErrorCode::ProtocolError,
        "credential helper report is malformed",
    )
}

/// A report with `ok: false`: the first few failing paths name the problem;
/// never file bytes.
pub(crate) fn helper_failed(mode: &str, report: &serde_json::Value) -> RuntimeError {
    let first = report
        .get("errors")
        .and_then(|e| e.as_array())
        .and_then(|e| e.first())
        .map(|e| {
            format!(
                "{}: {}",
                e.get("path").and_then(|v| v.as_str()).unwrap_or(""),
                e.get("error").and_then(|v| v.as_str()).unwrap_or("")
            )
        })
        .unwrap_or_default();
    let mut message = format!("credential {mode} failed");
    if !first.is_empty() {
        message.push_str(": ");
        message.extend(first.chars().take(512));
    }
    RuntimeError::new(SandboxErrorCode::GuestOperationFailed, message)
}

/// Turn a pack report plus body into the outcome, checking the bundle header
/// against the request (digest, envCount = 0, length).
pub(crate) fn pack_outcome(
    request: &CredentialPackRequest,
    report: &serde_json::Value,
    bundle: Zeroizing<Vec<u8>>,
) -> Result<CredentialPackOutcome, RuntimeError> {
    let file_count = count(report, "fileCount")?;
    let header = login_definition::limits::BUNDLE_HEADER_BYTES;
    let ok = bundle.len() >= header
        && &bundle[..4] == login_definition::bundle::BUNDLE_MAGIC
        && bundle[4] == login_definition::bundle::BUNDLE_VERSION
        && bundle[5..37] == request.definition_digest
        && u16::from_be_bytes([bundle[37], bundle[38]]) as u32 == file_count
        && bundle[39..41] == [0, 0];
    if !ok {
        return Err(helper_malformed());
    }
    Ok(CredentialPackOutcome {
        bundle: CredentialBytes::from_zeroizing(bundle),
        file_count,
        skipped_links: count(report, "skippedLinks")?,
        skipped_special: count(report, "skippedSpecial")?,
    })
}

pub(crate) fn restore_outcome(
    report: &serde_json::Value,
) -> Result<CredentialRestoreOutcome, RuntimeError> {
    Ok(CredentialRestoreOutcome {
        files_written: count(report, "filesWritten")?,
        dirs_created: count(report, "dirsCreated")?,
    })
}

pub(crate) fn scrub_outcome(
    report: &serde_json::Value,
) -> Result<CredentialScrubOutcome, RuntimeError> {
    let verified = report
        .get("verifiedAbsent")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(helper_malformed)?;
    let failed: Vec<String> = report
        .get("failed")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .ok_or_else(helper_malformed)?;
    Ok(CredentialScrubOutcome {
        verified_absent: verified && failed.is_empty(),
        removed: count(report, "removed")?,
        links_unlinked: count(report, "linksUnlinked")?,
        failed_paths: failed.into_iter().take(256).collect(),
    })
}

pub(crate) fn quiesce_outcome(
    report: &serde_json::Value,
) -> Result<CredentialQuiesceOutcome, RuntimeError> {
    Ok(CredentialQuiesceOutcome {
        terminated: count(report, "terminated")?,
        killed: count(report, "killed")?,
        freezer: report
            .get("freezer")
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(helper_malformed)?,
    })
}

/// One packed entry (fake runtime and tests).
pub(crate) struct PackEntry {
    pub kind: BundleFileKind,
    pub path: String,
    pub mode: u16,
    pub data: Zeroizing<Vec<u8>>,
}

/// Bundle v1 (files only, envCount = 0) in path-byte order, written into one
/// exactly sized zeroizing buffer.
pub(crate) fn encode_files_bundle(
    digest: &[u8; 32],
    entries: &mut [PackEntry],
) -> Zeroizing<Vec<u8>> {
    entries.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    let size = login_definition::limits::BUNDLE_HEADER_BYTES
        + entries
            .iter()
            .map(|e| 9 + e.path.len() + e.data.len())
            .sum::<usize>();
    let mut out = Zeroizing::new(Vec::with_capacity(size));
    out.extend_from_slice(login_definition::bundle::BUNDLE_MAGIC);
    out.push(login_definition::bundle::BUNDLE_VERSION);
    out.extend_from_slice(digest);
    out.extend_from_slice(&(entries.len() as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    for e in entries.iter() {
        out.push(match e.kind {
            BundleFileKind::File => login_definition::bundle::BUNDLE_KIND_FILE,
            BundleFileKind::Dir => login_definition::bundle::BUNDLE_KIND_DIR,
        });
        out.extend_from_slice(
            &login_definition::bundle::normalize_mode(e.kind, e.mode).to_be_bytes(),
        );
        out.extend_from_slice(&(e.path.len() as u16).to_be_bytes());
        out.extend_from_slice(e.path.as_bytes());
        out.extend_from_slice(&(e.data.len() as u32).to_be_bytes());
        out.extend_from_slice(&e.data);
    }
    out
}

#[cfg(test)]
#[path = "credentials_tests.rs"]
mod tests;
