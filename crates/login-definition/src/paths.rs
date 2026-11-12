//! Home-relative credential paths (same rules as `paths.ts`).

/// `None` when `path` is acceptable, else a short reason: relative,
/// `/`-separated, no empty, `.` or `..` segment, no `\`, `:`, NUL or ASCII
/// control byte, at most `max_bytes` bytes, and the first segment never
/// starts with `.wssp` (daemon-owned state). No segment may start with
/// `.wssp-cred-` (credential restore staging).
#[must_use]
pub fn path_problem(path: &str, max_bytes: usize) -> Option<&'static str> {
    if path.is_empty() {
        return Some("path is empty");
    }
    if path.len() > max_bytes {
        return Some("path is too long");
    }
    for byte in path.bytes() {
        if byte < 0x20 || byte == 0x7f {
            return Some("path contains a control byte");
        }
        if byte == b'\\' {
            return Some("path contains a backslash");
        }
        if byte == b':' {
            return Some("path contains a colon");
        }
    }
    if path.starts_with('/') {
        return Some("path must be relative to the home directory");
    }
    for segment in path.split('/') {
        if segment.is_empty() {
            return Some("path has an empty segment");
        }
        if segment == "." || segment == ".." {
            return Some("path has a dot segment");
        }
        if segment.starts_with(".wssp-cred-") {
            return Some("credential staging paths are reserved");
        }
    }
    if path
        .split('/')
        .next()
        .is_some_and(|first| first.starts_with(".wssp"))
    {
        return Some("paths under .wssp* are reserved");
    }
    None
}

/// `path` equals `ancestor` or lies below it.
#[must_use]
pub fn path_within(path: &str, ancestor: &str) -> bool {
    path == ancestor || path_below(path, ancestor)
}

/// `path` lies strictly below `ancestor`.
#[must_use]
pub fn path_below(path: &str, ancestor: &str) -> bool {
    path.len() > ancestor.len() + 1
        && path.starts_with(ancestor)
        && path.as_bytes()[ancestor.len()] == b'/'
}

/// Two paths overlap when one equals or contains the other.
#[must_use]
pub fn paths_overlap(a: &str, b: &str) -> bool {
    path_within(a, b) || path_within(b, a)
}
