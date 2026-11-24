//! Guard policy sources with provenance.
//!
//! Two runtime sources feed `deny4` (the static protected set is compiled
//! in): the root operator list `/etc/wssp/egress-blocklist` and the
//! deployment list pushed by the daemon. `deny4 = root ∪ deployment`, so a
//! push can never remove a root entry. Each source has a state; missing,
//! unknown and invalid keep the LAST VALID content and make health false.
//! Clearing is explicit only: an existing root file with no entries, or a
//! `configured:false` push.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use super::net::{Ipv4Net, normalize};

pub const MAX_SOURCE_BYTES: usize = 1024 * 1024;
pub const MAX_CIDRS: usize = 4096;
pub const MAX_DOMAINS: usize = 2048;
/// Rendered `local=/<d>/\n` lines. The open-mode dnsmasq body (§2.2) is
/// bounded at 64 KiB; this leaves 1 KiB for its fixed header and upstreams.
pub const MAX_DOMAIN_RENDER_BYTES: usize = 63 * 1024;

/// Validated content of one source: normalized CIDRs and sorted domains.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyContent {
    pub cidrs: Vec<Ipv4Net>,
    pub domains: Vec<String>,
}

impl PolicyContent {
    pub fn is_empty(&self) -> bool {
        self.cidrs.is_empty() && self.domains.is_empty()
    }

    /// `sha256:<hex>` of the canonical JSON `{"cidrs":[…],"domains":[…]}`.
    pub fn digest(&self) -> String {
        let canonical = serde_json::json!({
            "cidrs": self.cidrs.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "domains": self.domains,
        });
        let digest = ring::digest::digest(&ring::digest::SHA256, canonical.to_string().as_bytes());
        let mut out = String::from("sha256:");
        for byte in digest.as_ref() {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }
}

/// Why a source was rejected. `line` is 1-based (an entry index for pushes).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SourceError {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    pub reason: String,
}

impl SourceError {
    fn at(line: usize, reason: impl Into<String>) -> Self {
        Self {
            line: Some(line),
            reason: reason.into(),
        }
    }
    fn whole(reason: impl Into<String>) -> Self {
        Self {
            line: None,
            reason: reason.into(),
        }
    }
}

enum Entry {
    Cidr(Ipv4Net),
    Domain(String),
}

fn parse_entry(raw: &str) -> Result<Option<Entry>, String> {
    let entry = raw.split('#').next().unwrap_or("").trim();
    if entry.is_empty() {
        return Ok(None);
    }
    if entry.split_whitespace().count() > 1 {
        return Err("one entry per line".into());
    }
    if entry.contains(':') {
        return Err("IPv6 entries are not supported".into());
    }
    if entry.contains('/') || entry.parse::<Ipv4Addr>().is_ok() {
        let net = match entry.split_once('/') {
            None => entry.parse::<Ipv4Addr>().ok().map(Ipv4Net::host),
            Some((address, prefix)) => {
                let address: Ipv4Addr = address.parse().map_err(|_| "invalid IPv4 address")?;
                if prefix.is_empty()
                    || (prefix.len() > 1 && prefix.starts_with('0'))
                    || !prefix.bytes().all(|b| b.is_ascii_digit())
                {
                    return Err("invalid prefix length".into());
                }
                let prefix: u8 = prefix.parse().map_err(|_| "invalid prefix length")?;
                if prefix > 32 {
                    return Err("invalid prefix length".into());
                }
                Some(Ipv4Net::new(address, prefix).ok_or("CIDR has host bits set")?)
            }
        };
        return net
            .map(|net| Some(Entry::Cidr(net)))
            .ok_or_else(|| "invalid IPv4 address".to_string());
    }
    let lower = entry.to_ascii_lowercase();
    let domain = lower.strip_suffix('.').unwrap_or(&lower);
    if crate::egress::valid_domain_name(domain) {
        Ok(Some(Entry::Domain(domain.to_string())))
    } else {
        Err("not an IPv4 CIDR or a domain name".into())
    }
}

fn collect<'a>(lines: impl Iterator<Item = &'a str>) -> Result<PolicyContent, SourceError> {
    let mut cidrs = Vec::new();
    let mut domains = BTreeSet::new();
    for (index, line) in lines.enumerate() {
        let number = index + 1;
        match parse_entry(line).map_err(|reason| SourceError::at(number, reason))? {
            None => {}
            Some(Entry::Cidr(net)) => {
                cidrs.push(net);
                if cidrs.len() > MAX_CIDRS {
                    return Err(SourceError::at(number, "more than 4096 CIDRs"));
                }
            }
            Some(Entry::Domain(domain)) => {
                domains.insert(domain);
                if domains.len() > MAX_DOMAINS {
                    return Err(SourceError::at(number, "more than 2048 domains"));
                }
            }
        }
    }
    let domains: Vec<String> = domains.into_iter().collect();
    if rendered_domain_bytes(&domains) > MAX_DOMAIN_RENDER_BYTES {
        return Err(SourceError::whole("rendered domain list exceeds 63 KiB"));
    }
    Ok(PolicyContent {
        cidrs: normalize(cidrs),
        domains,
    })
}

/// Parse the root file body. The whole source is rejected on the first bad
/// line (never a partial list).
pub fn parse_source(bytes: &[u8]) -> Result<PolicyContent, SourceError> {
    if bytes.len() > MAX_SOURCE_BYTES {
        return Err(SourceError::whole("source exceeds 1 MiB"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| SourceError::whole("source is not UTF-8"))?;
    collect(text.lines())
}

/// Parse a deployment push: one entry per element (same grammar as a line,
/// no embedded newlines).
pub fn parse_entries(entries: &[String]) -> Result<PolicyContent, SourceError> {
    let total: usize = entries.iter().map(|e| e.len() + 1).sum();
    if total > MAX_SOURCE_BYTES {
        return Err(SourceError::whole("source exceeds 1 MiB"));
    }
    if let Some(index) = entries.iter().position(|e| e.contains(['\n', '\r'])) {
        return Err(SourceError::at(index + 1, "entry contains a line break"));
    }
    collect(entries.iter().map(String::as_str))
}

fn rendered_domain_bytes(domains: &[String]) -> usize {
    domains.iter().map(|d| "local=//\n".len() + d.len()).sum()
}

/// One source's observable state (status `sources.<name>`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceState {
    Valid {
        digest: String,
        cidrs: usize,
        domains: usize,
    },
    /// Explicitly empty: the root file exists with no entries, or the push
    /// said `configured:false`.
    NotConfigured {
        digest: String,
    },
    Invalid {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        line: Option<usize>,
        reason: String,
    },
    Missing,
    Unknown,
}

impl SourceState {
    /// Healthy states admit sandboxes; the rest make `ok` false.
    pub fn healthy(&self) -> bool {
        matches!(self, Self::Valid { .. } | Self::NotConfigured { .. })
    }

    pub fn digest(&self) -> Option<&str> {
        match self {
            Self::Valid { digest, .. } | Self::NotConfigured { digest } => Some(digest),
            _ => None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Valid { .. } => "valid",
            Self::NotConfigured { .. } => "not_configured",
            Self::Invalid { .. } => "invalid",
            Self::Missing => "missing",
            Self::Unknown => "unknown",
        }
    }
}

/// A source: its current state and the last valid content it enforced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub state: SourceState,
    pub last_valid: Option<PolicyContent>,
}

impl Source {
    /// A freshly started guard: unknown, with whatever was persisted.
    pub fn starting(last_valid: Option<PolicyContent>) -> Self {
        Self {
            state: SourceState::Unknown,
            last_valid,
        }
    }

    /// Accept new valid content. `configured` false is the explicit clear
    /// (`not_configured`); a configured empty push is `valid` with 0 entries.
    pub fn accept(&mut self, content: PolicyContent, configured: bool) {
        let digest = content.digest();
        self.state = if !configured {
            SourceState::NotConfigured { digest }
        } else {
            SourceState::Valid {
                digest,
                cidrs: content.cidrs.len(),
                domains: content.domains.len(),
            }
        };
        self.last_valid = Some(content);
    }

    /// Root file semantics: an existing file without entries is
    /// `not_configured`; with entries it is `valid`.
    pub fn accept_root_file(&mut self, content: PolicyContent) {
        let empty = content.is_empty();
        self.accept(content, !empty);
    }

    /// Missing / invalid / unknown: the last valid content stays enforced.
    pub fn reject(&mut self, state: SourceState) {
        debug_assert!(!state.healthy());
        self.state = state;
    }

    pub fn cidrs(&self) -> &[Ipv4Net] {
        self.last_valid
            .as_ref()
            .map(|c| c.cidrs.as_slice())
            .unwrap_or(&[])
    }

    pub fn domains(&self) -> &[String] {
        self.last_valid
            .as_ref()
            .map(|c| c.domains.as_slice())
            .unwrap_or(&[])
    }
}

/// `deny4 = root ∪ deployment` (each source's last valid content).
pub fn deny4(root: &Source, deployment: &Source) -> Vec<Ipv4Net> {
    normalize(root.cidrs().iter().chain(deployment.cidrs()).copied())
}

/// The union of both domain lists must still fit the runtime's bounds
/// (2048 names, 63 KiB rendered) or the daemon could not capture it.
pub fn domain_union_fits(root: &Source, deployment: &Source) -> bool {
    let union: BTreeSet<String> = root
        .domains()
        .iter()
        .chain(deployment.domains())
        .cloned()
        .collect();
    let union: Vec<String> = union.into_iter().collect();
    union.len() <= MAX_DOMAINS && rendered_domain_bytes(&union) <= MAX_DOMAIN_RENDER_BYTES
}

/// Ownership/mode rules for the root file and its directory (§2.0.4).
pub fn check_root_owned(
    kind: &str,
    uid: u32,
    mode: u32,
    expected_uid: u32,
    type_ok: bool,
) -> Result<(), String> {
    if !type_ok {
        return Err(format!("{kind} has the wrong file type"));
    }
    if uid != expected_uid {
        return Err(format!("{kind} is not owned by root"));
    }
    if mode & 0o022 != 0 {
        return Err(format!("{kind} is group- or world-writable"));
    }
    Ok(())
}

/// Result of reading the root operator list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootRead {
    Missing,
    Content(Vec<u8>),
    Refused(String),
}

/// Read a root-owned policy file: the directory must be a real directory,
/// owned by `expected_uid` and not group/world-writable; the file is opened
/// with `O_NOFOLLOW`, must be a regular file with the same ownership rule,
/// and at most 1 MiB. Production passes `expected_uid = 0`.
#[cfg(target_os = "linux")]
pub fn read_root_file(path: &std::path::Path, expected_uid: u32) -> RootRead {
    use std::io::Read as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    let Some(dir) = path.parent() else {
        return RootRead::Refused("path has no directory".into());
    };
    match std::fs::symlink_metadata(dir) {
        Ok(meta) => {
            if let Err(reason) = check_root_owned(
                "policy directory",
                meta.uid(),
                meta.mode(),
                expected_uid,
                meta.file_type().is_dir(),
            ) {
                return RootRead::Refused(reason);
            }
        }
        Err(err) => return RootRead::Refused(format!("policy directory: {}", err.kind())),
    }
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return RootRead::Missing,
        Err(err) if err.raw_os_error() == Some(libc::ELOOP) => {
            return RootRead::Refused("policy file is a symlink".into());
        }
        Err(err) => return RootRead::Refused(format!("policy file: {}", err.kind())),
    };
    let meta = match file.metadata() {
        Ok(meta) => meta,
        Err(err) => return RootRead::Refused(format!("policy file: {}", err.kind())),
    };
    if let Err(reason) = check_root_owned(
        "policy file",
        meta.uid(),
        meta.mode(),
        expected_uid,
        meta.file_type().is_file(),
    ) {
        return RootRead::Refused(reason);
    }
    let mut bytes = Vec::new();
    match file
        .take(MAX_SOURCE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
    {
        Ok(_) => RootRead::Content(bytes),
        Err(err) => RootRead::Refused(format!("policy file: {}", err.kind())),
    }
}

/// The state a root read maps to. `Ok` carries content for `accept_root_file`.
pub fn root_state(read: RootRead) -> Result<PolicyContent, SourceState> {
    match read {
        RootRead::Missing => Err(SourceState::Missing),
        RootRead::Refused(reason) => Err(SourceState::Invalid { line: None, reason }),
        RootRead::Content(bytes) => parse_source(&bytes).map_err(|err| SourceState::Invalid {
            line: err.line,
            reason: err.reason,
        }),
    }
}

#[cfg(test)]
#[path = "sources_tests.rs"]
mod tests;
