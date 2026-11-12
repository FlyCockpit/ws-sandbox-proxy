//! Template-build COPY (D1: guest root only inside build VMs).
//!
//! The node daemon turns a `buildCopy` dispatch into an ordinary supervised
//! `command.run` carrying [`crate::BuildStep::Copy`]; the runtime then runs
//! this fixed helper as guest root (its argv is built here, after the typed
//! body is validated, never taken from the wire). The
//! helper shares the capture scrub's descriptor-relative walk
//! (`incus/dirfd_walk.py`) and never parses anything the
//! server sends besides the validated argv below.

use sandbox_protocol::{BuildCopyOwnerV11, BuildCopyV11, SandboxErrorCode};

use crate::{GuestIdentity, RuntimeError};

/// Guest COPY helper, run as `python3 -I -B -c <this> <context> <sha256>
/// <dest> <uid> <gid> <mode|-> <src>...` as guest root. Exit 0 prints
/// `{"copied": n, "bytes": n}`; exit 2 is a refusal (unsafe member, missing
/// source, sha mismatch), exit 1 an IO failure. Nothing is written before
/// the whole archive is validated.
pub const BUILD_COPY_HELPER: &str = concat!(
    "import errno, os, stat\n",
    include_str!("incus/dirfd_walk.py"),
    include_str!("build-copy-helper.py")
);

/// Exact argv for one validated COPY step. `owner = user` resolves to the
/// sandbox's declared guest identity; `root` to uid/gid 0.
pub fn build_copy_argv(
    copy: &BuildCopyV11,
    guest: &GuestIdentity,
) -> Result<Vec<String>, RuntimeError> {
    if !copy.is_valid() {
        return Err(RuntimeError::new(
            SandboxErrorCode::ProtocolError,
            "invalid build copy",
        ));
    }
    guest.validate()?;
    let (uid, gid) = match copy.owner {
        BuildCopyOwnerV11::Root => (0, 0),
        BuildCopyOwnerV11::User => (guest.guest_uid, guest.guest_gid),
    };
    Ok(helper_argv(
        "python3",
        &copy.context_path,
        &copy.sha256,
        &copy.dest,
        (uid, gid),
        copy.mode,
        &copy.src,
    ))
}

fn helper_argv(
    python: &str,
    context: &str,
    sha256: &str,
    dest: &str,
    (uid, gid): (u32, u32),
    mode: Option<u32>,
    src: &[String],
) -> Vec<String> {
    let mut argv: Vec<String> = [python, "-I", "-B", "-c", BUILD_COPY_HELPER]
        .map(String::from)
        .into();
    argv.extend([
        context.to_string(),
        sha256.to_string(),
        dest.to_string(),
        uid.to_string(),
        gid.to_string(),
        mode.map_or_else(|| "-".to_string(), |m| m.to_string()),
    ]);
    argv.extend(src.iter().cloned());
    argv
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::process::Command;

    const PYTHON: &str = "/usr/bin/python3";

    fn scratch(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "wssp-build-copy-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Build a tar at `out` from a Python literal list of member specs:
    /// `(name, kind, payload)` with kind in reg/dir/sym/lnk/chr/fifo.
    fn make_tar(out: &Path, members: &str) -> String {
        let script = r#"
import hashlib, io, sys, tarfile
out, spec = sys.argv[1], eval(sys.argv[2])
kinds = {"reg": tarfile.REGTYPE, "dir": tarfile.DIRTYPE, "sym": tarfile.SYMTYPE,
         "lnk": tarfile.LNKTYPE, "chr": tarfile.CHRTYPE, "fifo": tarfile.FIFOTYPE}
with tarfile.open(out, "w", format=tarfile.PAX_FORMAT) as tar:
    for name, kind, payload in spec:
        info = tarfile.TarInfo(name)
        info.type = kinds[kind]
        info.mode = 0o755 if kind == "dir" else 0o640
        data = None
        if kind == "reg":
            data = payload.encode()
            info.size = len(data)
        elif kind in ("sym", "lnk"):
            info.linkname = payload
        tar.addfile(info, io.BytesIO(data) if data is not None else None)
print(hashlib.sha256(open(out, "rb").read()).hexdigest())
"#;
        let output = Command::new(PYTHON)
            .args(["-I", "-c", script])
            .arg(out)
            .arg(members)
            .output()
            .expect("python3");
        assert!(output.status.success(), "{output:?}");
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    fn ids(dir: &Path) -> (u32, u32) {
        let meta = std::fs::metadata(dir).unwrap();
        (meta.uid(), meta.gid())
    }

    fn run(
        context: &Path,
        sha: &str,
        dest: &str,
        mode: Option<u32>,
        src: &[&str],
    ) -> std::process::Output {
        let owner = ids(context.parent().unwrap());
        let src: Vec<String> = src.iter().map(|s| s.to_string()).collect();
        let argv = helper_argv(
            PYTHON,
            context.to_str().unwrap(),
            sha,
            dest,
            owner,
            mode,
            &src,
        );
        Command::new(&argv[0])
            .args(&argv[1..])
            .output()
            .expect("helper")
    }

    fn refused(output: &std::process::Output, why: &str) {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{stderr}");
        assert!(stderr.contains(why), "{stderr}");
    }

    #[test]
    fn argv_is_fixed_and_owner_resolves_from_the_declared_guest() {
        let copy = BuildCopyV11 {
            context_path: "/var/tmp/wssp-build/b-1/context.tar".into(),
            sha256: "a".repeat(64),
            src: vec!["app".into(), "*.json".into()],
            dest: "/home/user/app/".into(),
            owner: BuildCopyOwnerV11::User,
            mode: Some(0o644),
        };
        let guest = GuestIdentity::default();
        let argv = build_copy_argv(&copy, &guest).unwrap();
        assert_eq!(argv[..4], ["python3", "-I", "-B", "-c"]);
        assert_eq!(argv[4], BUILD_COPY_HELPER);
        assert_eq!(
            argv[5..],
            [
                "/var/tmp/wssp-build/b-1/context.tar".to_string(),
                "a".repeat(64),
                "/home/user/app/".into(),
                guest.guest_uid.to_string(),
                guest.guest_gid.to_string(),
                "420".into(),
                "app".into(),
                "*.json".into(),
            ]
        );
        let root = BuildCopyV11 {
            owner: BuildCopyOwnerV11::Root,
            mode: None,
            ..copy.clone()
        };
        let argv = build_copy_argv(&root, &guest).unwrap();
        assert_eq!(argv[8..11], ["0", "0", "-"]);
        // An unvalidated body never becomes argv.
        for bad in [
            BuildCopyV11 {
                src: vec!["../etc".into()],
                ..copy.clone()
            },
            BuildCopyV11 {
                context_path: "/tmp/context.tar".into(),
                ..copy.clone()
            },
            BuildCopyV11 {
                dest: "relative".into(),
                ..copy.clone()
            },
        ] {
            assert!(build_copy_argv(&bad, &guest).is_err());
        }
        let root_guest = GuestIdentity {
            guest_uid: 0,
            ..GuestIdentity::default()
        };
        assert!(build_copy_argv(&copy, &root_guest).is_err());
    }

    #[test]
    fn helper_shares_the_descriptor_relative_walk() {
        assert!(BUILD_COPY_HELPER.starts_with("import errno, os, stat\n"));
        assert!(BUILD_COPY_HELPER.contains("def open_dir(path):"));
        assert!(crate::SCRUB_HELPER.contains("def open_dir(path):"));
        assert!(BUILD_COPY_HELPER.contains("O_RDONLY | os.O_NOFOLLOW"));
        assert!(BUILD_COPY_HELPER.len() < 16 * 1024);
    }

    #[test]
    fn copies_files_and_directory_contents_with_owner_and_mode() {
        let dir = scratch("ok");
        let context = dir.join("context.tar");
        let sha = make_tar(
            &context,
            r#"[("app", "dir", ""), ("app/main.py", "reg", "print(1)"), ("app/lib", "dir", ""),
               ("app/lib/x.txt", "reg", "x"), ("app/link", "sym", "lib/x.txt"),
               ("app/hard", "lnk", "app/main.py"), ("package.json", "reg", "{}"),
               ("other.json", "reg", "[]")]"#,
        );
        let dest = dir.join("out");
        let out = run(
            &context,
            &sha,
            &format!("{}/", dest.display()),
            None,
            &["app"],
        );
        assert!(out.status.success(), "{out:?}");
        assert_eq!(
            std::fs::read_to_string(dest.join("main.py")).unwrap(),
            "print(1)"
        );
        assert_eq!(
            std::fs::read_to_string(dest.join("lib/x.txt")).unwrap(),
            "x"
        );
        assert_eq!(
            std::fs::read_link(dest.join("link")).unwrap(),
            Path::new("lib/x.txt")
        );
        assert_eq!(
            std::fs::read_to_string(dest.join("hard")).unwrap(),
            "print(1)"
        );
        let mode = std::fs::metadata(dest.join("main.py"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o640);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.contains("\"copied\": 5"), "{stdout}");
        // Glob + explicit mode into a directory destination.
        let json = dir.join("json");
        let out = run(
            &context,
            &sha,
            &format!("{}/", json.display()),
            Some(0o600),
            &["*.json"],
        );
        assert!(out.status.success(), "{out:?}");
        for name in ["package.json", "other.json"] {
            let meta = std::fs::metadata(json.join(name)).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
            assert_eq!((meta.uid(), meta.gid()), ids(&dir));
        }
        // A single file to a file destination.
        let single = dir.join("single.json");
        let out = run(
            &context,
            &sha,
            single.to_str().unwrap(),
            None,
            &["package.json"],
        );
        assert!(out.status.success(), "{out:?}");
        assert_eq!(std::fs::read_to_string(&single).unwrap(), "{}");
        // Several sources need a directory destination.
        let out = run(&context, &sha, single.to_str().unwrap(), None, &["*.json"]);
        refused(&out, "several sources");
        let out = run(&context, &sha, single.to_str().unwrap(), None, &["missing"]);
        refused(&out, "source not found");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn unsafe_members_are_refused_before_any_write() {
        for (label, spec, why) in [
            (
                "dotdot",
                r#"[("ok", "reg", "1"), ("../evil", "reg", "x")]"#,
                "escapes the context",
            ),
            (
                "nested-dotdot",
                r#"[("a/../../evil", "reg", "x")]"#,
                "escapes the context",
            ),
            (
                "absolute",
                r#"[("ok", "reg", "1"), ("/etc/evil", "reg", "x")]"#,
                "absolute member",
            ),
            (
                "device",
                r#"[("ok", "reg", "1"), ("dev", "chr", "")]"#,
                "device or special",
            ),
            (
                "fifo",
                r#"[("ok", "reg", "1"), ("pipe", "fifo", "")]"#,
                "device or special",
            ),
            (
                "sym-abs",
                r#"[("ok", "reg", "1"), ("l", "sym", "/etc/shadow")]"#,
                "symlink escapes",
            ),
            (
                "sym-up",
                r#"[("a/l", "sym", "../../x")]"#,
                "symlink escapes",
            ),
            (
                "hard-out",
                r#"[("ok", "reg", "1"), ("h", "lnk", "/etc/shadow")]"#,
                "absolute member",
            ),
            (
                "hard-missing",
                r#"[("ok", "reg", "1"), ("h", "lnk", "nope")]"#,
                "hardlink outside",
            ),
            (
                "through-link",
                r#"[("l", "sym", "sub"), ("sub", "dir", ""), ("l/f", "reg", "x")]"#,
                "crosses a non-directory",
            ),
            (
                "dup",
                r#"[("ok", "reg", "1"), ("ok", "reg", "2")]"#,
                "duplicate member",
            ),
        ] {
            let dir = scratch(label);
            let context = dir.join("context.tar");
            let sha = make_tar(&context, spec);
            let dest = dir.join("out");
            let out = run(
                &context,
                &sha,
                &format!("{}/", dest.display()),
                None,
                &["."],
            );
            refused(&out, why);
            assert!(!dest.exists(), "{label}: wrote before validation");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    #[test]
    fn sha_mismatch_and_linked_context_are_refused() {
        let dir = scratch("sha");
        let context = dir.join("context.tar");
        let sha = make_tar(&context, r#"[("ok", "reg", "1")]"#);
        let dest = dir.join("out");
        let dest_arg = format!("{}/", dest.display());
        refused(
            &run(&context, &"0".repeat(64), &dest_arg, None, &["."]),
            "sha256 mismatch",
        );
        // O_NOFOLLOW: a symlink in place of the context is never opened.
        let link = dir.join("linked.tar");
        std::os::unix::fs::symlink(&context, &link).unwrap();
        refused(
            &run(&link, &sha, &dest_arg, None, &["."]),
            "context unavailable",
        );
        // A context directory reached through a link is refused too.
        let real = dir.join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::copy(&context, real.join("context.tar")).unwrap();
        let alias = dir.join("alias");
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        refused(
            &run(&alias.join("context.tar"), &sha, &dest_arg, None, &["."]),
            "context unavailable",
        );
        assert!(!dest.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn destinations_never_follow_links() {
        let dir = scratch("dest");
        let context = dir.join("context.tar");
        let sha = make_tar(&context, r#"[("f", "reg", "new")]"#);
        let outside = dir.join("outside");
        std::fs::create_dir(&outside).unwrap();
        // A link in the destination path is refused, not followed.
        let link_dir = dir.join("linkdir");
        std::os::unix::fs::symlink(&outside, &link_dir).unwrap();
        refused(
            &run(
                &context,
                &sha,
                &format!("{}/", link_dir.display()),
                None,
                &["f"],
            ),
            "not a plain directory",
        );
        // A link at the destination name is replaced, never written through.
        let target = outside.join("victim");
        std::fs::write(&target, "keep").unwrap();
        let dest = dir.join("d");
        std::fs::create_dir(&dest).unwrap();
        std::os::unix::fs::symlink(&target, dest.join("f")).unwrap();
        let out = run(
            &context,
            &sha,
            &format!("{}/", dest.display()),
            None,
            &["f"],
        );
        assert!(out.status.success(), "{out:?}");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
        assert_eq!(std::fs::read_to_string(dest.join("f")).unwrap(), "new");
        assert!(
            !std::fs::symlink_metadata(dest.join("f"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
