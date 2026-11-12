//! Guest metadata validation and bounded live pages, shared by real and fake IO.
use crate::{ListDirRequest, ListDirResponse, RuntimeError};
use sandbox_protocol::SandboxErrorCode;
use sandbox_protocol::results::{EntryInfo, ResultBody};
use serde::{Deserialize, Serialize};

pub const HOST_RESULT_MAX_BYTES: usize = 24 * 1024;
/// Private envelope space; the published whole-host-result limit stays 24 KiB.
pub const HOST_RESULT_WRAPPER_BYTES: usize = 1024;
pub const DIRECTORY_LIMIT: usize = 100;
pub const DIRECTORY_DEPTH: u32 = 8;
pub const DIRECTORY_VISITS: usize = 100_000;
pub const OBSERVATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// B2-C-2: the host kill deadline exceeds the guest's own listing budget by
/// this explicit slack for `incus exec`, interpreter startup and transfer, so
/// the guest's precise `fs_listing_limit` is reachable before the kill.
pub const OBSERVATION_SLACK: std::time::Duration = std::time::Duration::from_secs(5);

/// (host kill deadline, guest listing budget) for one observation. The guest
/// budget always ends strictly before the host deadline.
pub(crate) fn observation_budgets(
    agent_timeout: std::time::Duration,
) -> (std::time::Duration, std::time::Duration) {
    let host = agent_timeout.min(OBSERVATION_TIMEOUT + OBSERVATION_SLACK);
    let guest = host
        .saturating_sub(OBSERVATION_SLACK)
        .max(host / 2)
        .min(OBSERVATION_TIMEOUT)
        .max(std::time::Duration::from_millis(1));
    (host, guest)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectoryContinuation {
    pub last_key: String,
    pub root: String,
    pub depth: u32,
    pub limit: usize,
    pub generation: u64,
    pub kind: DirectoryKind,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DirectoryKind {
    #[serde(rename = "LIST_DIR")]
    ListDir,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuestFileResult {
    pub result: ResultBody,
    pub continuation: Option<DirectoryContinuation>,
}
pub(crate) fn invalid() -> RuntimeError {
    RuntimeError::new(
        SandboxErrorCode::ProtocolError,
        "invalid guest file response",
    )
    .filesystem(sandbox_protocol::results::FailureEffect::None)
}
pub(crate) fn fs_error(code: SandboxErrorCode) -> RuntimeError {
    // Codes are the sole guest-controlled input; messages never contain paths,
    // stderr, lookup names, or framing tokens.
    #[derive(Deserialize)]
    struct CatalogEntry {
        message: String,
    }
    static CATALOG: std::sync::LazyLock<Option<std::collections::BTreeMap<String, CatalogEntry>>> =
        std::sync::LazyLock::new(|| {
            serde_json::from_str(include_str!(
                "../../../packages/config/src/sandbox-result-errors.json"
            ))
            .ok()
        });
    let message = CATALOG
        .as_ref()
        .and_then(|catalog| catalog.get(code.as_str()))
        .map(|entry| entry.message.as_str())
        .unwrap_or("Guest filesystem operation failed.");
    RuntimeError::new(code, message).filesystem(sandbox_protocol::results::FailureEffect::None)
}
/// B2-K-5: the one leading/trailing guest-path whitespace set, shared with
/// the server (`String.prototype.trim`) and the helper through
/// `packages/config/src/sandbox-path-whitespace.json`.
pub(crate) const PATH_WHITESPACE: &[char] = &[
    '\u{9}', '\u{a}', '\u{b}', '\u{c}', '\u{d}', '\u{20}', '\u{a0}', '\u{1680}', '\u{2000}',
    '\u{2001}', '\u{2002}', '\u{2003}', '\u{2004}', '\u{2005}', '\u{2006}', '\u{2007}', '\u{2008}',
    '\u{2009}', '\u{200a}', '\u{2028}', '\u{2029}', '\u{202f}', '\u{205f}', '\u{3000}', '\u{feff}',
];
pub fn canonical_metadata_path(path: &str, mutate: bool) -> Result<String, RuntimeError> {
    if !path.starts_with('/')
        || path.len() > 4096
        || path.contains('\0')
        || path.starts_with(PATH_WHITESPACE)
        || path.ends_with(PATH_WHITESPACE)
        || path.split('/').any(|p| p == "..")
    {
        return Err(RuntimeError::new(
            SandboxErrorCode::ProtocolError,
            "invalid guest metadata path",
        ));
    }
    let canonical = format!(
        "/{}",
        path.split('/')
            .filter(|p| !p.is_empty() && *p != ".")
            .collect::<Vec<_>>()
            .join("/")
    );
    if mutate && canonical == "/" {
        return Err(RuntimeError::new(
            SandboxErrorCode::PathRefused,
            "refusing guest root mutation",
        ));
    }
    Ok(canonical)
}
pub(crate) fn validate_file_path(path: &str) -> Result<(), RuntimeError> {
    canonical_metadata_path(path, true)?;
    if path.split('/').any(|p| p == ".") || path.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}') {
        return Err(RuntimeError::new(
            SandboxErrorCode::ProtocolError,
            "invalid guest transfer path",
        ));
    }
    Ok(())
}
pub(crate) fn relative_key<'a>(root: &str, path: &'a str, depth: u32) -> Option<&'a str> {
    let relative = if root == "/" {
        path.strip_prefix('/')?
    } else {
        path.strip_prefix(root)?.strip_prefix('/')?
    };
    let mut count = 0;
    if relative.split('/').all(|p| {
        count += 1;
        !p.is_empty() && p != "." && p != ".."
    }) && count <= depth
    {
        Some(relative)
    } else {
        None
    }
}
impl ListDirRequest {
    pub fn validate_page(&self) -> Result<String, RuntimeError> {
        let root = canonical_metadata_path(&self.path, false)?;
        if !(1..=DIRECTORY_DEPTH).contains(&self.depth)
            || !(1..=DIRECTORY_LIMIT).contains(&self.limit)
            || !(1..=i32::MAX as u64).contains(&self.generation)
        {
            return Err(invalid());
        }
        if let Some(cursor) = &self.continuation
            && (cursor.root != root
                || cursor.depth != self.depth
                || cursor.limit != self.limit
                || cursor.generation != self.generation
                || cursor.last_key.len() > 4096
                || cursor.last_key.contains('\0')
                || relative_key("/", &format!("/{}", cursor.last_key), self.depth).is_none())
        {
            return Err(invalid());
        }
        Ok(root)
    }
}
pub(crate) fn page_envelope(page: &ListDirResponse) -> GuestFileResult {
    GuestFileResult {
        result: ResultBody::List {
            path: page.path.clone(),
            depth: page.depth,
            items: page.items.clone(),
            next_cursor: None,
            consistency: sandbox_protocol::results::LiveConsistency::Live,
        },
        continuation: page.continuation.clone(),
    }
}
pub(crate) fn fits(value: &impl Serialize) -> bool {
    serde_json::to_vec(value)
        .is_ok_and(|v| v.len() <= HOST_RESULT_MAX_BYTES - HOST_RESULT_WRAPPER_BYTES)
}
pub(crate) fn validate_page(
    request: &ListDirRequest,
    page: &ListDirResponse,
) -> Result<(), RuntimeError> {
    let root = request.validate_page()?;
    if page.path != root
        || page.depth != request.depth
        || page.items.len() > request.limit
        || !fits(&page_envelope(page))
    {
        return Err(invalid());
    }
    let mut previous = request.continuation.as_ref().map(|c| c.last_key.as_str());
    for entry in &page.items {
        let key = relative_key(&root, &entry.path, request.depth).ok_or_else(invalid)?;
        if !entry.validate() || previous.is_some_and(|p| p >= key) {
            return Err(invalid());
        }
        previous = Some(key);
    }
    if let Some(cursor) = &page.continuation
        && (page.items.is_empty()
            || Some(cursor.last_key.as_str()) != previous
            || cursor.root != root
            || cursor.depth != request.depth
            || cursor.limit != request.limit
            || cursor.generation != request.generation)
    {
        return Err(invalid());
    }
    Ok(())
}

/// FakeRuntime uses the same O(limit) selection and byte-shortening semantics.
pub(crate) fn select_page(
    request: &ListDirRequest,
    entries: impl Iterator<Item = EntryInfo>,
) -> Result<ListDirResponse, RuntimeError> {
    let root = request.validate_page()?;
    let mut heap = std::collections::BinaryHeap::new();
    let start = std::time::Instant::now();
    for (visited, entry) in entries.enumerate() {
        if visited >= DIRECTORY_VISITS || start.elapsed() >= OBSERVATION_TIMEOUT {
            return Err(fs_error(SandboxErrorCode::FsListingLimit));
        }
        let key = relative_key(&root, &entry.path, request.depth)
            .ok_or_else(invalid)?
            .to_string();
        if !entry.validate() {
            return Err(fs_error(SandboxErrorCode::FsMetadataUnrepresentable));
        }
        if !fits(&GuestFileResult {
            result: ResultBody::Stat {
                entry: entry.clone(),
            },
            continuation: None,
        }) {
            return Err(fs_error(SandboxErrorCode::FsEntryTooLarge));
        }
        if request
            .continuation
            .as_ref()
            .is_some_and(|c| key <= c.last_key)
        {
            continue;
        }
        let candidate = PageCandidate(key, entry);
        if heap.len() < request.limit + 1 {
            heap.push(candidate);
        } else if let Some(mut largest) = heap.peek_mut()
            && candidate < *largest
        {
            *largest = candidate;
        }
    }
    let selected = heap.into_sorted_vec();
    let mut page = ListDirResponse {
        path: root.clone(),
        depth: request.depth,
        items: Vec::new(),
        continuation: None,
    };
    for (index, entry) in selected.iter().take(request.limit).enumerate() {
        page.items.push(entry.1.clone());
        page.continuation = (index + 1 < selected.len()).then(|| DirectoryContinuation {
            last_key: entry.0.clone(),
            root: root.clone(),
            depth: request.depth,
            limit: request.limit,
            generation: request.generation,
            kind: DirectoryKind::ListDir,
        });
        if !fits(&page_envelope(&page)) {
            page.items.pop();
            let last = page
                .items
                .last()
                .ok_or_else(|| fs_error(SandboxErrorCode::FsEntryTooLarge))?;
            page.continuation = Some(DirectoryContinuation {
                last_key: relative_key(&root, &last.path, request.depth)
                    .ok_or_else(invalid)?
                    .into(),
                root: root.clone(),
                depth: request.depth,
                limit: request.limit,
                generation: request.generation,
                kind: DirectoryKind::ListDir,
            });
            if !fits(&page_envelope(&page)) {
                return Err(fs_error(SandboxErrorCode::FsEntryTooLarge));
            }
            break;
        }
    }
    validate_page(request, &page)?;
    Ok(page)
}
#[derive(Eq, PartialEq)]
struct PageCandidate(String, EntryInfo);
impl Ord for PageCandidate {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}
impl PartialOrd for PageCandidate {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
