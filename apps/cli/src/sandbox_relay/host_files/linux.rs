//! Canonical physical path + openat2(RESOLVE_BENEATH|NO_SYMLINKS).
//! All later effects use held directory descriptors, including atomic rename.
use super::super::host_mask::Masker;
use super::{Context, lock};
use rustix::fs::{self, AtFlags, Mode, OFlags, ResolveFlags};
use sandbox_protocol::*;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
const MAX_FILE: u64 = 4 * 1024 * 1024;
type Result<T> = std::result::Result<T, HostFileError>;
fn io(e: std::io::Error) -> HostFileError {
    match e.kind() {
        std::io::ErrorKind::NotFound => HostFileError::NotFound,
        std::io::ErrorKind::PermissionDenied => HostFileError::PathDenied,
        _ => HostFileError::IoError,
    }
}
fn errno(e: rustix::io::Errno) -> HostFileError {
    match e {
        rustix::io::Errno::NOENT => HostFileError::NotFound,
        rustix::io::Errno::NOTDIR => HostFileError::NotADir,
        rustix::io::Errno::LOOP
        | rustix::io::Errno::XDEV
        | rustix::io::Errno::ACCESS
        | rustix::io::Errno::PERM => HostFileError::PathDenied,
        rustix::io::Errno::EXIST => HostFileError::Exists,
        _ => HostFileError::IoError,
    }
}
fn denied(ctx: &Context<'_>, path: &Path) -> bool {
    if ctx.shared.protected.iter().any(|p| {
        path.starts_with(p)
            || p.canonicalize()
                .is_ok_and(|actual| path.starts_with(actual))
    }) {
        return true;
    }
    path.components().any(|c| {
        let v = c.as_os_str().to_string_lossy().to_ascii_lowercase();
        matches!(
            v.as_str(),
            ".ssh"
                | ".aws"
                | ".gnupg"
                | ".kube"
                | ".netrc"
                | ".npmrc"
                | ".env"
                | "auth.json"
                | "credentials"
                | "credentials.json"
                | "credentials.toml"
                | "journal.key"
                | "journal-key"
        ) || v.starts_with(".env.")
            || v.ends_with(".pem")
            || v.ends_with(".key")
    })
}
struct Resolved {
    parent: OwnedFd,
    name: std::ffi::OsString,
    physical: PathBuf,
}
fn resolve(ctx: &Context<'_>) -> Result<Resolved> {
    ctx.check()?;
    let raw = ctx.req.path();
    let expanded = if raw == "~" {
        dirs::home_dir().ok_or(HostFileError::PathDenied)?
    } else if let Some(rest) = raw.strip_prefix("~/") {
        dirs::home_dir()
            .ok_or(HostFileError::PathDenied)?
            .join(rest)
    } else {
        PathBuf::from(raw)
    };
    if !expanded.is_absolute() || raw.contains('\0') {
        return Err(HostFileError::PathDenied);
    }
    if denied(ctx, &expanded) {
        return Err(HostFileError::PathDenied);
    }
    let physical = match expanded.canonicalize() {
        Ok(path) => path,
        Err(e)
            if e.kind() == std::io::ErrorKind::NotFound
                && matches!(ctx.req, HostFileRequestV11::Write { .. }) =>
        {
            let name = expanded.file_name().ok_or(HostFileError::PathDenied)?;
            expanded
                .parent()
                .ok_or(HostFileError::PathDenied)?
                .canonicalize()
                .map_err(io)?
                .join(name)
        }
        Err(e) => return Err(io(e)),
    };
    if denied(ctx, &physical) {
        return Err(HostFileError::PathDenied);
    }
    let policy = lock(&ctx.shared.policy);
    let root = policy
        .roots
        .iter()
        .filter(|root| physical.starts_with(root))
        .max_by_key(|root| root.components().count())
        .ok_or(HostFileError::PathDenied)?;
    let slash = fs::open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(errno)?;
    let rootfd = fs::openat2(
        &slash,
        root.strip_prefix("/")
            .map_err(|_| HostFileError::PathDenied)?,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(errno)?;
    let relative = physical
        .strip_prefix(root)
        .map_err(|_| HostFileError::PathDenied)?;
    let (parent, name) = if relative.as_os_str().is_empty() {
        (rootfd, std::ffi::OsString::from("."))
    } else {
        let dir = relative
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = fs::openat2(
            &rootfd,
            dir,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(errno)?;
        (
            parent,
            relative
                .file_name()
                .ok_or(HostFileError::PathDenied)?
                .to_os_string(),
        )
    };
    Ok(Resolved {
        parent,
        name,
        physical,
    })
}
impl Resolved {
    fn check(&self, ctx: &Context<'_>) -> Result<()> {
        ctx.check()?;
        // Reject a parent renamed out of the root or into a protected tree.
        use std::os::fd::AsRawFd;
        let actual =
            std::fs::read_link(format!("/proc/self/fd/{}", self.parent.as_raw_fd())).map_err(io)?;
        let actual = if self.name == "." {
            actual
        } else {
            actual.join(&self.name)
        };
        if actual != self.physical || denied(ctx, &actual) {
            return Err(HostFileError::PathDenied);
        }
        Ok(())
    }
    fn open(&self, ctx: &Context<'_>) -> Result<File> {
        self.check(ctx)?;
        let fd = fs::openat2(
            &self.parent,
            &self.name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(errno)?;
        let file = File::from(fd);
        let meta = file.metadata().map_err(io)?;
        if !meta.is_file() {
            return Err(HostFileError::NotAFile);
        }
        // Hardlinks must not alias a credential or journal file outside the root.
        if meta.nlink() != 1 {
            return Err(HostFileError::PathDenied);
        }
        Ok(file)
    }
    fn bytes(&self, ctx: &Context<'_>) -> Result<(Vec<u8>, std::fs::Metadata)> {
        let file = self.open(ctx)?;
        let meta = file.metadata().map_err(io)?;
        if meta.len() > MAX_FILE {
            return Err(HostFileError::TooLarge);
        }
        let mut bytes = Vec::new();
        file.take(MAX_FILE + 1)
            .read_to_end(&mut bytes)
            .map_err(io)?;
        if bytes.len() as u64 > MAX_FILE {
            return Err(HostFileError::TooLarge);
        }
        if bytes.iter().take(8192).any(|b| *b == 0) || std::str::from_utf8(&bytes).is_err() {
            return Err(HostFileError::BinaryFile);
        }
        self.check(ctx)?;
        Ok((bytes, meta))
    }
}
pub(super) fn run(ctx: &Context<'_>) -> Result<HostFileValueV11> {
    let resolved = resolve(ctx)?;
    match ctx.req {
        HostFileRequestV11::Read {
            offset, max_bytes, ..
        } => {
            let (bytes, _) = resolved.bytes(ctx)?;
            let etag = ctx.etag(&bytes);
            let masked = Masker::new(&ctx.shared.secret).whole(&bytes);
            let text = String::from_utf8(masked).map_err(|_| HostFileError::BinaryFile)?;
            let offset =
                usize::try_from(offset.unwrap_or(0)).map_err(|_| HostFileError::InvalidInput)?;
            if offset > text.len() || !text.is_char_boundary(offset) {
                return Err(HostFileError::InvalidInput);
            }
            let mut end = offset
                .saturating_add(max_bytes.unwrap_or(65536))
                .min(text.len());
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            Ok(HostFileValueV11::Read(HostFileReadV11 {
                content: text[offset..end].into(),
                offset: offset as u64,
                size: text.len() as u64,
                etag,
                truncated: end < text.len(),
            }))
        }
        HostFileRequestV11::List { .. } => {
            resolved.check(ctx)?;
            let fd = fs::openat2(
                &resolved.parent,
                &resolved.name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
            )
            .map_err(errno)?;
            let mut dir = fs::Dir::read_from(&fd).map_err(errno)?;
            let mut entries = Vec::new();
            let mut truncated = false;
            while let Some(entry) = dir.read() {
                resolved.check(ctx)?;
                let entry = entry.map_err(errno)?;
                let name = entry.file_name().to_bytes();
                if name == b"." || name == b".." {
                    continue;
                }
                if entries.len() == 1000 {
                    truncated = true;
                    break;
                }
                let name = std::str::from_utf8(name).map_err(|_| HostFileError::InvalidInput)?;
                let st = fs::statat(&fd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(errno)?;
                let kind = match fs::FileType::from_raw_mode(st.st_mode) {
                    fs::FileType::RegularFile => HostFileKind::File,
                    fs::FileType::Directory => HostFileKind::Dir,
                    fs::FileType::Symlink => HostFileKind::Symlink,
                    _ => HostFileKind::Other,
                };
                entries.push(HostFileEntryV11 {
                    name: name.into(),
                    kind,
                    size: (kind == HostFileKind::File).then_some(st.st_size.max(0) as u64),
                });
            }
            entries.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(HostFileValueV11::List(HostFileListV11 {
                entries,
                truncated,
            }))
        }
        HostFileRequestV11::Write {
            content,
            expected_etag,
            create_only,
            ..
        } => {
            reject_marker(content)?;
            let old = match resolved.bytes(ctx) {
                Ok(v) => Some(v),
                Err(HostFileError::NotFound) => None,
                Err(e) => return Err(e),
            };
            if old.is_some() && create_only.unwrap_or(false) {
                return Err(HostFileError::Exists);
            }
            if let Some((bytes, _)) = &old {
                if expected_etag.as_deref() != Some(&ctx.etag(bytes)) {
                    return Err(HostFileError::Conflict);
                }
            } else if expected_etag.is_some() {
                return Err(HostFileError::Conflict);
            }
            atomic(ctx, &resolved, content.as_bytes(), old.as_ref())?;
            Ok(HostFileValueV11::Write(HostFileWriteV11 {
                etag: ctx.etag(content.as_bytes()),
                size: content.len() as u64,
                created: old.is_none(),
            }))
        }
        HostFileRequestV11::Edit {
            edits,
            expected_etag,
            ..
        } => {
            let (old, meta) = resolved.bytes(ctx)?;
            if expected_etag.as_ref().is_some_and(|e| *e != ctx.etag(&old)) {
                return Err(HostFileError::Conflict);
            }
            let current = std::str::from_utf8(&old).map_err(|_| HostFileError::BinaryFile)?;
            reject_marker(current)?;
            // Evaluate every match against the original input; overlapping edits refuse.
            let mut replacements = Vec::new();
            for edit in edits {
                reject_marker(&edit.old_text)?;
                reject_marker(&edit.new_text)?;
                if edit.old_text.is_empty() {
                    return Err(HostFileError::InvalidInput);
                }
                let start = current.find(&edit.old_text).ok_or(HostFileError::NoMatch)?;
                let next = start + current[start..].chars().next().map_or(0, char::len_utf8);
                if current[next..].contains(&edit.old_text) {
                    return Err(HostFileError::MatchCount);
                }
                replacements.push((start, start + edit.old_text.len(), edit.new_text.as_str()));
            }
            replacements.sort_by_key(|r| r.0);
            if replacements.windows(2).any(|p| p[0].1 > p[1].0) {
                return Err(HostFileError::MatchCount);
            }
            let mut result = String::new();
            let mut at = 0;
            for (start, end, new) in &replacements {
                result.push_str(&current[at..*start]);
                result.push_str(new);
                at = *end;
            }
            result.push_str(&current[at..]);
            if result.len() as u64 > MAX_FILE {
                return Err(HostFileError::TooLarge);
            }
            atomic(ctx, &resolved, result.as_bytes(), Some(&(old, meta)))?;
            Ok(HostFileValueV11::Edit(HostFileEditedV11 {
                etag: ctx.etag(result.as_bytes()),
                size: result.len() as u64,
                replacements: edits.len(),
            }))
        }
    }
}
fn reject_marker(text: &str) -> Result<()> {
    if text.contains("⟦redacted") {
        Err(HostFileError::RedactedSpan)
    } else {
        Ok(())
    }
}
fn atomic(
    ctx: &Context<'_>,
    resolved: &Resolved,
    content: &[u8],
    old: Option<&(Vec<u8>, std::fs::Metadata)>,
) -> Result<()> {
    resolved.check(ctx)?;
    let mut random = [0; 16];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut random)
        .map_err(|_| HostFileError::IoError)?;
    let name = format!(".wssp-host-write-{}", encode_chunk_data(&random));
    let fd = fs::openat(
        &resolved.parent,
        name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(errno)?;
    let result = (|| {
        let mut file = File::from(fd);
        file.write_all(content).map_err(io)?;
        let mode = old.map(|(_, meta)| meta.mode() & 0o777).unwrap_or(0o644);
        file.set_permissions(std::fs::Permissions::from_mode(mode))
            .map_err(io)?;
        file.sync_all().map_err(io)?;
        resolved.check(ctx)?;
        if let Some((bytes, meta)) = old {
            let (current, current_meta) = resolved.bytes(ctx)?;
            if current_meta.ino() != meta.ino()
                || current_meta.dev() != meta.dev()
                || current != *bytes
            {
                return Err(HostFileError::Conflict);
            }
            fs::renameat(
                &resolved.parent,
                name.as_str(),
                &resolved.parent,
                &resolved.name,
            )
            .map_err(errno)?;
        } else {
            fs::renameat_with(
                &resolved.parent,
                name.as_str(),
                &resolved.parent,
                &resolved.name,
                fs::RenameFlags::NOREPLACE,
            )
            .map_err(errno)?;
        }
        fs::fsync(&resolved.parent).map_err(errno)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::unlinkat(&resolved.parent, name.as_str(), AtFlags::empty());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::super::super::agent_policy::AgentPolicy;
    use super::super::Shared;
    use super::*;
    use serde_json::{Value, json};
    use std::sync::{Mutex, atomic::AtomicBool};
    struct Harness {
        dir: tempfile::TempDir,
        shared: Shared,
    }
    impl Harness {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().canonicalize().unwrap();
            let shared = Shared {
                policy: Mutex::new(AgentPolicy {
                    enabled: true,
                    max_ms: 600000,
                    roots: vec![root.clone()],
                    revision: 1,
                }),
                owner: "owner".into(),
                protected: vec![
                    root.join("protected"),
                    "/proc".into(),
                    "/sys".into(),
                    "/dev".into(),
                ],
                secret: zeroize::Zeroizing::new(b"fixture-daemon-value".to_vec()),
                key: [7; 32],
                serial: Mutex::new(()),
            };
            Self { dir, shared }
        }
        fn run(&self, name: &str, op: Value) -> Result<HostFileValueV11> {
            let mut req = json!({"connectionEpoch":1,"requestId":"request","ownerId":"owner","agentPolicyRevision":1,"path":self.dir.path().join(name).to_str().unwrap()});
            req.as_object_mut()
                .unwrap()
                .extend(op.as_object().unwrap().clone());
            let req: HostFileRequestV11 = serde_json::from_value(req).unwrap();
            let ctx = Context {
                shared: &self.shared,
                cancelled: &AtomicBool::new(false),
                req: &req,
            };
            ctx.check()?;
            run(&ctx)
        }
        fn write(&self, name: &str, text: &str) {
            std::fs::write(self.dir.path().join(name), text).unwrap();
        }
    }
    #[test]
    fn files_are_atomic_etag_guarded_and_edits_are_all_or_nothing() {
        let h = Harness::new();
        let created = h
            .run("file", json!({"op":"write","content":"one two"}))
            .unwrap();
        let HostFileValueV11::Write(created) = created else {
            panic!()
        };
        assert!(created.created);
        assert!(created.etag.starts_with("h:"));
        assert_eq!(created.etag.len(), 24);
        assert_eq!(
            std::fs::metadata(h.dir.path().join("file")).unwrap().mode() & 0o777,
            0o644
        );
        assert_eq!(
            h.run("file", json!({"op":"write","content":"new"}))
                .unwrap_err(),
            HostFileError::Conflict
        );
        assert_eq!(
            h.run(
                "file",
                json!({"op":"write","content":"new","createOnly":true})
            )
            .unwrap_err(),
            HostFileError::Exists
        );
        assert_eq!(
            h.run(
                "file",
                json!({"op":"write","content":"new","expectedEtag":"h:wrong"})
            )
            .unwrap_err(),
            HostFileError::Conflict
        );
        assert_eq!(h.run("file",json!({"op":"edit","edits":[{"oldText":"one","newText":"ONE"},{"oldText":"missing","newText":"x"}]})).unwrap_err(),HostFileError::NoMatch);
        assert_eq!(
            std::fs::read_to_string(h.dir.path().join("file")).unwrap(),
            "one two"
        );
        let result=h.run("file",json!({"op":"edit","expectedEtag":created.etag,"edits":[{"oldText":"one","newText":"ONE"},{"oldText":"two","newText":"TWO"}]})).unwrap();
        let HostFileValueV11::Edit(result) = result else {
            panic!()
        };
        assert_eq!(result.replacements, 2);
        assert_eq!(
            std::fs::read_to_string(h.dir.path().join("file")).unwrap(),
            "ONE TWO"
        );
        h.write("file", "aaa");
        assert_eq!(
            h.run(
                "file",
                serde_json::json!({"op":"edit","edits":[{"oldText":"aa","newText":"x"}]})
            )
            .unwrap_err(),
            HostFileError::MatchCount
        );
        h.write("file", "aa aa");
        assert_eq!(
            h.run(
                "file",
                json!({"op":"edit","edits":[{"oldText":"aa","newText":"x"}]})
            )
            .unwrap_err(),
            HostFileError::MatchCount
        );
    }
    #[test]
    fn paths_resolve_physically_and_deny_escapes_protected_trees_and_aliases() {
        use std::os::unix::fs::symlink;
        let h = Harness::new();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), "outside").unwrap();
        symlink(outside.path(), h.dir.path().join("escape")).unwrap();
        assert_eq!(
            h.run("escape/secret", json!({"op":"read"})).unwrap_err(),
            HostFileError::PathDenied
        );
        assert_eq!(
            h.run("escape/../secret", json!({"op":"read"})).unwrap_err(),
            HostFileError::NotFound
        );
        let outside_name = outside.path().file_name().unwrap().to_str().unwrap();
        assert_eq!(
            h.run(&format!("../{outside_name}/secret"), json!({"op":"read"}))
                .unwrap_err(),
            HostFileError::PathDenied
        );
        assert_eq!(
            h.run("escape/new", json!({"op":"write","content":"x"}))
                .unwrap_err(),
            HostFileError::PathDenied
        );
        std::fs::create_dir(h.dir.path().join("protected")).unwrap();
        h.write("protected/key", "protected");
        symlink(
            h.dir.path().join("protected/key"),
            h.dir.path().join("alias"),
        )
        .unwrap();
        assert_eq!(
            h.run("alias", json!({"op":"read"})).unwrap_err(),
            HostFileError::PathDenied
        );
        std::fs::hard_link(
            h.dir.path().join("protected/key"),
            h.dir.path().join("hardlink"),
        )
        .unwrap();
        assert_eq!(
            h.run("hardlink", json!({"op":"read"})).unwrap_err(),
            HostFileError::PathDenied
        );
        for name in [".env", "credentials.json", "journal.key", "private.pem"] {
            h.write(name, "sensitive");
            assert_eq!(
                h.run(name, json!({"op":"read"})).unwrap_err(),
                HostFileError::PathDenied
            );
        }
        h.write("plain", "safe");
        symlink(h.dir.path().join("plain"), h.dir.path().join("inside")).unwrap();
        assert!(h.run("inside", json!({"op":"read"})).is_ok());
        for path in ["/proc/self/environ", "/sys/kernel", "/dev/null"] {
            assert_eq!(
                h.run(path, json!({"op":"read"})).unwrap_err(),
                HostFileError::PathDenied
            );
        }
    }
    #[test]
    fn file_rejections_and_masking() {
        let h = Harness::new();
        assert_eq!(
            h.run("missing", json!({"op":"read"})).unwrap_err(),
            HostFileError::NotFound
        );
        assert_eq!(
            h.run(".", json!({"op":"read"})).unwrap_err(),
            HostFileError::NotAFile
        );
        h.write("plain", "ordinary");
        assert_eq!(
            h.run("plain", json!({"op":"list"})).unwrap_err(),
            HostFileError::NotADir
        );
        h.write("binary", "\0");
        assert_eq!(
            h.run("binary", json!({"op":"read"})).unwrap_err(),
            HostFileError::BinaryFile
        );
        std::fs::write(h.dir.path().join("invalid"), [0xff]).unwrap();
        assert_eq!(
            h.run("invalid", json!({"op":"read"})).unwrap_err(),
            HostFileError::BinaryFile
        );
        let big = File::create(h.dir.path().join("big")).unwrap();
        big.set_len(MAX_FILE + 1).unwrap();
        assert_eq!(
            h.run("big", json!({"op":"read"})).unwrap_err(),
            HostFileError::TooLarge
        );
        assert_eq!(
            h.run("new", json!({"op":"write","content":"⟦redacted⟧"}))
                .unwrap_err(),
            HostFileError::RedactedSpan
        );
        assert_eq!(
            h.run(
                "plain",
                json!({"op":"edit","edits":[{"oldText":"ordinary","newText":"⟦redacted: value⟧"}]})
            )
            .unwrap_err(),
            HostFileError::RedactedSpan
        );
        assert_eq!(
            h.run("plain", json!({"op":"read","offset":1000}))
                .unwrap_err(),
            HostFileError::InvalidInput
        );
        h.write(
            "tokens",
            "before wssp_agent_fixture-token after fixture-daemon-value",
        );
        let HostFileValueV11::Read(read) = h.run("tokens", json!({"op":"read"})).unwrap() else {
            panic!()
        };
        assert!(!read.content.contains("wssp_agent_"));
        assert!(!read.content.contains("fixture-daemon-value"));
        assert!(read.content.contains("⟦redacted⟧"));
    }
    #[test]
    fn owner_revision_roots_and_cancel_are_rechecked() {
        let h = Harness::new();
        h.write("file", "data");
        lock(&h.shared.policy).enabled = false;
        assert_eq!(
            h.run("file", json!({"op":"read"})).unwrap_err(),
            HostFileError::HostFilesOff
        );
        lock(&h.shared.policy).enabled = true;
        lock(&h.shared.policy).revision = 2;
        assert_eq!(
            h.run("file", json!({"op":"read"})).unwrap_err(),
            HostFileError::PolicyChanged
        );
        lock(&h.shared.policy).revision = 1;
        assert_eq!(
            h.run("file", json!({"op":"read","ownerId":"other"}))
                .unwrap_err(),
            HostFileError::OwnerMismatch
        );
        lock(&h.shared.policy).roots.clear();
        assert_eq!(
            h.run("file", json!({"op":"read"})).unwrap_err(),
            HostFileError::NoRoots
        );
    }
}

#[cfg(test)]
mod race_tests {
    use super::super::super::agent_policy::AgentPolicy;
    use super::super::Shared;
    use super::*;
    use std::sync::{Mutex, atomic::AtomicBool};
    #[test]
    fn a_parent_moved_or_swapped_after_resolution_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("parent")).unwrap();
        std::fs::write(dir.path().join("parent/file"), "safe").unwrap();
        let shared = Shared {
            policy: Mutex::new(AgentPolicy {
                enabled: true,
                max_ms: 1000,
                roots: vec![dir.path().canonicalize().unwrap()],
                revision: 1,
            }),
            owner: "owner".into(),
            protected: Vec::new(),
            secret: zeroize::Zeroizing::new(Vec::new()),
            key: [9; 32],
            serial: Mutex::new(()),
        };
        let req:HostFileRequestV11=serde_json::from_value(serde_json::json!({"op":"read","connectionEpoch":1,"requestId":"read","ownerId":"owner","agentPolicyRevision":1,"path":dir.path().join("parent/file").to_str().unwrap()})).unwrap();
        let ctx = Context {
            shared: &shared,
            cancelled: &AtomicBool::new(false),
            req: &req,
        };
        let resolved = resolve(&ctx).unwrap();
        std::fs::rename(dir.path().join("parent"), outside.path().join("moved")).unwrap();
        std::os::unix::fs::symlink(outside.path().join("moved"), dir.path().join("parent"))
            .unwrap();
        assert_eq!(resolved.open(&ctx).unwrap_err(), HostFileError::PathDenied);
        assert_eq!(
            io(std::io::Error::other("fixture failure")),
            HostFileError::IoError
        );
    }
}
