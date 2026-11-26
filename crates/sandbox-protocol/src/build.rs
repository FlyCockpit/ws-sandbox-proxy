//! Template-build dispatch fields (additive within 1.0).
//!
//! Guest root runs only inside build VMs. The wire carries
//! three optional fields, each refused outside its one dispatch kind:
//!
//! - `build` rides only on `sandbox.create`; the daemon journals its `buildId`
//!   in the sandbox record, which is immutable for the sandbox.
//! - `runAs: "root"` rides only on `command.run`.
//! - `buildCopy` rides only on `command.run`, implies root, and carries no
//!   `argv`, `script`, `env` or `runAs`: the daemon runs its own fixed helper.
//!
//! The daemon additionally refuses `runAs`/`buildCopy` unless the journaled
//! record of the target sandbox carries a build id. Every field is omitted
//! when absent, so non-build frames stay byte-identical.

use serde::{Deserialize, Serialize};

/// Bound on `buildCopy.src` entries.
pub const BUILD_COPY_SRC_MAX: usize = 64;
/// Bound on one `buildCopy.src` entry.
pub const BUILD_COPY_SRC_MAX_BYTES: usize = 1024;
/// Bound on `buildCopy.dest`.
pub const BUILD_COPY_DEST_MAX_BYTES: usize = 4096;
/// Largest `buildCopy.mode` (permission bits only).
pub const BUILD_COPY_MODE_MAX: u32 = 0o777;
/// Guest directory that holds one build's staged context.
pub const BUILD_CONTEXT_DIR: &str = "/var/tmp/wssp-build";
/// File name of the staged context inside the build's directory.
pub const BUILD_CONTEXT_FILE: &str = "context.tar";

/// Build ids share the image-plane id grammar.
pub fn valid_build_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The only guest path a build context is put to and copied from.
pub fn build_context_path(build_id: &str) -> Option<String> {
    valid_build_id(build_id).then(|| format!("{BUILD_CONTEXT_DIR}/{build_id}/{BUILD_CONTEXT_FILE}"))
}

/// The build id a context path names, when it has the exact fixed shape.
pub fn build_id_of_context_path(path: &str) -> Option<&str> {
    let rest = path.strip_prefix(BUILD_CONTEXT_DIR)?.strip_prefix('/')?;
    let id = rest.strip_suffix(BUILD_CONTEXT_FILE)?.strip_suffix('/')?;
    valid_build_id(id).then_some(id)
}

/// `sandbox.create` build binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DispatchBuildV11 {
    pub build_id: String,
    /// The community prep build VM of a raw upstream base: bootstrap
    /// readiness (no target-identity script, a boot settle instead). Omitted
    /// while false; an upstream image plan requires it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub bootstrap: bool,
}

impl DispatchBuildV11 {
    pub fn is_valid(&self) -> bool {
        valid_build_id(&self.build_id)
    }
}

/// `command.run` identity override. Only guest root exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RunAsV11 {
    Root,
}

/// Owner of copied files: guest root or the sandbox's declared guest user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BuildCopyOwnerV11 {
    Root,
    User,
}

/// `command.run` body for a recipe COPY step (Docker COPY subset).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildCopyV11 {
    /// Always `/var/tmp/wssp-build/<buildId>/context.tar`.
    pub context_path: String,
    /// Lowercase hex sha256 of the whole context file.
    pub sha256: String,
    /// Context-relative sources; `.` is the whole context.
    pub src: Vec<String>,
    /// Absolute guest destination; a trailing `/` names a directory.
    pub dest: String,
    pub owner: BuildCopyOwnerV11,
    /// Permission bits for copied files (else each member's own bits).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
}

impl BuildCopyV11 {
    pub fn is_valid(&self) -> bool {
        build_id_of_context_path(&self.context_path).is_some()
            && valid_sha256_hex(&self.sha256)
            && !self.src.is_empty()
            && self.src.len() <= BUILD_COPY_SRC_MAX
            && self.src.iter().all(|s| valid_build_copy_src(s))
            && valid_build_copy_dest(&self.dest)
            && self.mode.is_none_or(|m| m <= BUILD_COPY_MODE_MAX)
    }
}

fn valid_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn plain_text(value: &str) -> bool {
    !value.chars().any(char::is_control)
}

/// Relative, normalized context path: `.` alone, or non-empty segments that
/// are neither `.` nor `..`, with `*` only in the last segment.
pub fn valid_build_copy_src(src: &str) -> bool {
    if src == "." {
        return true;
    }
    if src.is_empty()
        || src.len() > BUILD_COPY_SRC_MAX_BYTES
        || src.starts_with('/')
        || !plain_text(src)
    {
        return false;
    }
    let segments: Vec<&str> = src.split('/').collect();
    let last = segments.len() - 1;
    segments
        .iter()
        .enumerate()
        .all(|(i, s)| !s.is_empty() && *s != "." && *s != ".." && (i == last || !s.contains('*')))
}

/// Absolute guest path without `.`/`..` or empty segments; a single
/// trailing `/` marks a directory destination. No glob characters.
pub fn valid_build_copy_dest(dest: &str) -> bool {
    if !dest.starts_with('/')
        || dest.len() > BUILD_COPY_DEST_MAX_BYTES
        || !plain_text(dest)
        || dest.contains('*')
    {
        return false;
    }
    if dest == "/" {
        return true;
    }
    let body = dest[1..].strip_suffix('/').unwrap_or(&dest[1..]);
    !body.is_empty()
        && body
            .split('/')
            .all(|s| !s.is_empty() && s != "." && s != "..")
}

/// Strict placement of the build fields on one dispatch (see module docs).
pub(crate) fn valid_dispatch_build_fields(d: &crate::OperationDispatch) -> bool {
    let create = d.kind == "sandbox.create";
    let command = d.kind == "command.run";
    d.build.as_ref().is_none_or(|b| create && b.is_valid())
        && (d.run_as.is_none() || command)
        && d.build_copy.as_ref().is_none_or(|copy| {
            command
                && copy.is_valid()
                && d.run_as.is_none()
                && d.argv.is_none()
                && d.script.is_none()
                && d.env.as_ref().is_none_or(Vec::is_empty)
        })
}
