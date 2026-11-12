//! Mutation fault shims run the bundled helper locally, never a live VM.
use super::managed_child::ManagedChild;
use super::{
    client::IncusClient,
    files::{Fence, HELPER, host_refusal, put_outcome},
};
use sandbox_protocol::{
    OperationState, SandboxErrorCode,
    results::{FailureEffect, ResultBody},
};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

const TOKEN_CHAR: &str = "b";
fn token() -> String {
    TOKEN_CHAR.repeat(64)
}
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "wssp-mutations-{}",
            super::client::random_nonce().unwrap()
        ));
        fs::create_dir(&dir).unwrap();
        Self(dir)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn command(mode: &str, path: &Path, options: serde_json::Value, injection: &str) -> Command {
    let source = HELPER.replace("try:\n    run()", &format!("{injection}\ntry:\n    run()"));
    let mut command = Command::new("python3");
    command.args([
        "-I",
        "-c",
        &source,
        mode,
        path.to_str().unwrap(),
        &token(),
        "0",
        &options.to_string(),
    ]);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}
fn invoke(
    mode: &str,
    path: &Path,
    options: serde_json::Value,
    injection: &str,
    go: &[u8],
) -> std::process::Output {
    let mut child = ManagedChild::spawn(&mut command(mode, path, options, injection)).unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(go).unwrap();
    drop(stdin);
    child.wait_with_output().unwrap()
}
fn result(out: std::process::Output) -> ResultBody {
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.stderr,
        format!("WSSP_STATUS {} ok\n", token()).as_bytes()
    );
    let prefix = format!("WSSP_COMMIT_READY {}\n", token());
    let payload = out.stdout.strip_prefix(prefix.as_bytes()).unwrap();
    assert!(payload.len() <= crate::metadata::HOST_RESULT_MAX_BYTES);
    let parsed: crate::metadata::GuestFileResult = serde_json::from_slice(payload).unwrap();
    assert!(parsed.continuation.is_none());
    parsed.result
}
fn failure(out: &std::process::Output) -> crate::EffectError {
    assert!(!out.status.success());
    let out = super::client::IncusCommandOutput {
        stdout: String::new(),
        stderr: String::from_utf8(out.stderr.clone()).unwrap(),
        exit_code: out.status.code().unwrap_or(-1),
    };
    super::effect_completion::helper_outcome(&token(), &out, "mutation", "sentinel-path")
        .map_err(crate::EffectError::from)
        .unwrap_err()
}

#[test]
fn all_mutations_wait_for_commit_and_mkdir_reports_the_final_syscall() {
    let dir = Scratch::new();
    let nested = dir.0.join("parent/target");
    for go in [b"".as_slice(), b"X"] {
        let out = invoke("mkdir", &nested, serde_json::json!({}), "", go);
        assert_eq!(failure(&out).failure().unwrap().effect, FailureEffect::None);
        assert!(
            !dir.0.join("parent").exists(),
            "no parent creation before commit"
        );
    }
    assert_eq!(
        result(invoke("mkdir", &nested, serde_json::json!({}), "", b"C")),
        ResultBody::Mkdir { created: true }
    );
    assert_eq!(
        result(invoke("mkdir", &nested, serde_json::json!({}), "", b"C")),
        ResultBody::Mkdir { created: false }
    );
    let race = dir.0.join("race");
    assert_eq!(
        result(invoke(
            "mkdir",
            &race,
            serde_json::json!({}),
            "original_mkdir = os.mkdir\ndef racing_mkdir(name, *args, **kw):\n    original_mkdir(name, *args, **kw)\n    raise FileExistsError(errno.EEXIST, 'external create')\nos.mkdir = racing_mkdir",
            b"C"
        )),
        ResultBody::Mkdir { created: false }
    );
    let source = dir.0.join("source");
    fs::write(&source, b"source bytes").unwrap();
    let dest = dir.0.join("dest");
    for mode in ["remove", "rename"] {
        let out = invoke(
            mode,
            &source,
            serde_json::json!({"destPath":dest,"recursive":true}),
            "",
            b"",
        );
        assert_eq!(failure(&out).code, SandboxErrorCode::Cancelled);
        assert_eq!(fs::read(&source).unwrap(), b"source bytes");
        assert!(!dest.exists());
    }
}

#[test]
fn rename_uses_exact_destination_and_links_are_never_followed() {
    use std::os::unix::fs::symlink;
    let dir = Scratch::new();
    let source = dir.0.join("source");
    fs::write(&source, b"new").unwrap();
    let dest = dir.0.join("dest");
    fs::write(&dest, b"old").unwrap();
    match result(invoke(
        "rename",
        &source,
        serde_json::json!({"destPath":dest}),
        "",
        b"C",
    )) {
        ResultBody::Rename { entry } => {
            assert!(entry.validate());
            assert_eq!(entry.path, dest.to_str().unwrap());
            assert_eq!(entry.size, 3);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(fs::read(&dest).unwrap(), b"new");
    assert!(!source.exists());
    fs::create_dir(&source).unwrap();
    let empty = dir.0.join("empty");
    fs::create_dir(&empty).unwrap();
    result(invoke(
        "rename",
        &source,
        serde_json::json!({"destPath":empty}),
        "",
        b"C",
    ));
    assert!(!source.exists());
    assert!(empty.is_dir());
    assert!(!empty.join("source").exists());
    fs::write(&source, b"file").unwrap();
    let out = invoke(
        "rename",
        &source,
        serde_json::json!({"destPath":empty}),
        "",
        b"C",
    );
    assert_eq!(failure(&out).code, SandboxErrorCode::FsIsDirectory);
    let link = dir.0.join("link");
    symlink("missing", &link).unwrap();
    let moved_link = dir.0.join("moved-link");
    match result(invoke(
        "rename",
        &link,
        serde_json::json!({"destPath":moved_link}),
        "",
        b"C",
    )) {
        ResultBody::Rename { entry } => {
            assert_eq!(entry.symlink_target.as_deref(), Some("missing"))
        }
        other => panic!("{other:?}"),
    }
    result(invoke(
        "remove",
        &moved_link,
        serde_json::json!({}),
        "",
        b"C",
    ));
    assert!(fs::symlink_metadata(&moved_link).is_err());
    symlink(&empty, &link).unwrap();
    for mode in ["mkdir", "remove", "rename"] {
        let out = invoke(
            mode,
            &link.join("child"),
            serde_json::json!({"destPath":dest}),
            "",
            b"C",
        );
        assert_eq!(failure(&out).code, SandboxErrorCode::FsSymlinkRefused);
        assert!(!empty.join("child").exists());
    }
    // Recursion unlinks a link itself, preserving its target's children.
    let tree = dir.0.join("tree");
    fs::create_dir(&tree).unwrap();
    fs::write(empty.join("keep"), b"keep").unwrap();
    symlink(&empty, tree.join("link")).unwrap();
    result(invoke(
        "remove",
        &tree,
        serde_json::json!({"recursive":true}),
        "",
        b"C",
    ));
    assert_eq!(fs::read(empty.join("keep")).unwrap(), b"keep");
}

#[test]
fn completed_errno_preserves_partial_effect_and_cross_device_never_copies() {
    let dir = Scratch::new();
    let nested = dir.0.join("new-parent/target");
    let out = invoke(
        "mkdir",
        &nested,
        serde_json::json!({}),
        "original_mkdir = os.mkdir\ndef denied_final(name, *a, **kw):\n    if name == 'target': raise PermissionError(errno.EACCES, 'sentinel-path')\n    return original_mkdir(name, *a, **kw)\nos.mkdir = denied_final",
        b"C",
    );
    let failed = failure(&out);
    assert_eq!(failed.code, SandboxErrorCode::FsPermissionDenied);
    assert_eq!(failed.state(), OperationState::Failed);
    assert_eq!(failed.failure().unwrap().effect, FailureEffect::Partial);
    assert!(dir.0.join("new-parent").is_dir());
    assert!(!nested.exists());
    let tree = dir.0.join("tree");
    fs::create_dir(&tree).unwrap();
    fs::write(tree.join("a"), b"a").unwrap();
    fs::write(tree.join("b"), b"b").unwrap();
    let nonempty = invoke("remove", &tree, serde_json::json!({}), "", b"C");
    assert_eq!(failure(&nonempty).code, SandboxErrorCode::FsNotEmpty);
    assert_eq!(
        failure(&nonempty).failure().unwrap().effect,
        FailureEffect::None
    );
    let out = invoke(
        "remove",
        &tree,
        serde_json::json!({"recursive":true}),
        "original_unlink = os.unlink\nunlinks = 0\ndef partial_unlink(*a, **kw):\n    global unlinks\n    unlinks += 1\n    if unlinks == 2: raise PermissionError(errno.EPERM, 'sentinel-stderr')\n    return original_unlink(*a, **kw)\nos.unlink = partial_unlink",
        b"C",
    );
    assert_eq!(
        failure(&out).failure().unwrap().effect,
        FailureEffect::Partial
    );
    assert_eq!(fs::read_dir(&tree).unwrap().count(), 1);
    let source = dir.0.join("source");
    let dest = dir.0.join("dest");
    fs::write(&source, b"source").unwrap();
    fs::write(&dest, b"dest").unwrap();
    let out = invoke(
        "rename",
        &source,
        serde_json::json!({"destPath":dest}),
        "def cross_device(*a, **kw): raise OSError(errno.EXDEV, 'sentinel-private')\nos.replace = cross_device",
        b"C",
    );
    assert_eq!(failure(&out).code, SandboxErrorCode::FsCrossDevice);
    assert_eq!(failure(&out).failure().unwrap().effect, FailureEffect::None);
    assert_eq!(fs::read(&source).unwrap(), b"source");
    assert_eq!(fs::read(&dest).unwrap(), b"dest");
    assert!(!format!("{:?}", failure(&out)).contains("sentinel"));
}

#[test]
fn lost_rename_completion_post_effect_metadata_and_fsync_failures_stay_unknown() {
    let dir = Scratch::new();
    for (index, injection) in [
        "def no_metadata(*a): raise FileNotFoundError(errno.ENOENT, 'sentinel-after-rename')\nentry_info = no_metadata",
        "def bad_sync(*a): raise OSError(errno.EIO, 'sentinel-fsync')\nos.fsync = bad_sync",
        "original_replace = os.replace\ndef lose_completion(*a, **kw):\n    original_replace(*a, **kw)\n    os._exit(1)\nos.replace = lose_completion",
    ].iter().enumerate() {
        let source = dir.0.join(format!("source-{index}")); let dest = dir.0.join(format!("dest-{index}"));
        fs::write(&source, b"moved").unwrap();
        let out = invoke("rename", &source, serde_json::json!({"destPath":dest}), injection, b"C");
        let unknown = failure(&out);
        assert_eq!(unknown.state(), OperationState::UnknownOutcome);
        assert_eq!(unknown.failure().unwrap().effect, FailureEffect::Unknown);
        assert!(!source.exists()); assert_eq!(fs::read(&dest).unwrap(), b"moved");
        assert!(!format!("{unknown:?}").contains("sentinel"));
    }
    let path = dir.0.join("mkdir-fsync");
    let out = invoke(
        "mkdir",
        &path,
        serde_json::json!({}),
        "def bad_sync(*a): raise OSError(errno.EIO, 'sentinel-fsync')\nos.fsync = bad_sync",
        b"C",
    );
    assert_eq!(failure(&out).state(), OperationState::UnknownOutcome);
    assert!(path.exists());
}

fn wait_for(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(path.exists(), "test barrier timed out");
}

#[test]
fn permit_revocation_before_and_after_the_shared_metadata_fence_is_safe() {
    let dir = Scratch::new();
    for mode in ["mkdir", "remove", "rename"] {
        let root = dir.0.join(mode);
        fs::create_dir(&root).unwrap();
        for after in [false, true] {
            let marker = root.join(if after { "issued" } else { "pending" });
            let gate = root.join(if after { "after-gate" } else { "before-gate" });
            let source = root.join(if after {
                "after-source"
            } else {
                "before-source"
            });
            if mode != "mkdir" {
                fs::write(&source, b"source").unwrap();
            }
            let dest = root.join(if after { "after-dest" } else { "before-dest" });
            let injection = format!(
                "original_gate = commit_gate\ndef held_gate(token):\n    {}\n    with open({marker:?}, 'w') as marker: marker.write('ready')\n    while not os.path.exists({gate:?}): time.sleep(0.005)\n    {}\ncommit_gate = held_gate",
                if after {
                    "original_gate(token)"
                } else {
                    "pass"
                },
                if after {
                    "pass"
                } else {
                    "original_gate(token)"
                },
                marker = marker.to_str().unwrap(),
                gate = gate.to_str().unwrap()
            );
            let cmd = command(
                mode,
                &source,
                serde_json::json!({"destPath":dest,"recursive":true}),
                &injection,
            );
            let permit = Arc::new(crate::RuntimePermit::default());
            let client = IncusClient {
                cancelled: Some(permit.clone()),
                agent_timeout: Duration::from_secs(15),
                ..IncusClient::new("unused", "default")
            };
            let worker = std::thread::spawn(move || {
                client.mutation_io(&client.local_test_bound(), cmd, None, &token())
            });
            wait_for(&marker);
            permit.revoke();
            fs::write(&gate, b"go").unwrap();
            let run = worker.join().unwrap().unwrap();
            let failed = put_outcome(&token(), "sentinel", &run).unwrap_err();
            if after {
                assert_eq!(run.fence, Fence::Issued);
                assert_eq!(failed.state(), OperationState::UnknownOutcome);
                assert_eq!(failed.failure().unwrap().effect, FailureEffect::Unknown);
            } else {
                assert_eq!(run.fence, Fence::Refused);
                assert_eq!(failed.state(), OperationState::Failed);
                assert_eq!(failed.failure().unwrap().effect, FailureEffect::None);
                // B2-C-1: the host refused; preemption, not guest cancellation.
                let refusal = host_refusal(&token(), &run).expect("host-authored refusal");
                assert_eq!(refusal.state(), OperationState::Failed);
                assert_eq!(refusal.code, SandboxErrorCode::UnknownOutcome);
                assert_eq!(refusal.message, "runtime work preempted");
                assert_eq!(refusal.failure().unwrap().effect, FailureEffect::None);
                if mode == "mkdir" {
                    assert!(!source.exists());
                } else {
                    assert_eq!(fs::read(&source).unwrap(), b"source");
                }
                assert!(!dest.exists());
            }
        }
    }
}

/// B2-K-3: readiness keeps `mkdir -p` follow semantics for template layout
/// (`/home -> var/home`), behind the same commit gate; user-API mkdir keeps
/// refusing the symlinked ancestor.
#[test]
fn readiness_directory_follows_a_symlinked_home_but_user_mkdir_does_not() {
    let dir = Scratch::new();
    fs::create_dir_all(dir.0.join("var/home/user")).unwrap();
    std::os::unix::fs::symlink("var/home", dir.0.join("home")).unwrap();
    let repo = dir.0.join("home/user/repo");
    let refused = invoke("mkdir", &repo, serde_json::json!({}), "", b"C");
    assert_eq!(failure(&refused).code, SandboxErrorCode::FsSymlinkRefused);
    assert!(!dir.0.join("var/home/user/repo").exists());
    let held = invoke("ensure-dir", &repo, serde_json::json!({}), "", b"");
    assert_eq!(
        failure(&held).failure().unwrap().effect,
        FailureEffect::None
    );
    assert!(
        !dir.0.join("var/home/user/repo").exists(),
        "nothing before C"
    );
    for created in [true, false] {
        assert_eq!(
            result(invoke("ensure-dir", &repo, serde_json::json!({}), "", b"C")),
            ResultBody::Mkdir { created }
        );
        assert!(dir.0.join("var/home/user/repo").is_dir());
    }
    // A template that ships $HOME/repo as a link to a directory is ready too.
    fs::create_dir(dir.0.join("var/elsewhere")).unwrap();
    let linked = dir.0.join("var/home/linked");
    fs::create_dir(&linked).unwrap();
    std::os::unix::fs::symlink("../../elsewhere", linked.join("repo")).unwrap();
    assert_eq!(
        result(invoke(
            "ensure-dir",
            &dir.0.join("home/linked/repo"),
            serde_json::json!({}),
            "",
            b"C"
        )),
        ResultBody::Mkdir { created: false }
    );
    // A non-directory still fails precisely, with no effect.
    fs::write(dir.0.join("var/home/user/file"), b"x").unwrap();
    let out = invoke(
        "ensure-dir",
        &dir.0.join("home/user/file"),
        serde_json::json!({}),
        "",
        b"C",
    );
    let error = failure(&out);
    assert_eq!(error.code, SandboxErrorCode::FsAlreadyExists);
    assert_eq!(error.failure().unwrap().effect, FailureEffect::None);
}

/// B2-T-3/B2-C-4: recursive remove handles non-UTF-8 names and depth past
/// Python's recursion limit, and kernel refusals with no effect say so.
#[test]
fn recursive_remove_is_iterative_byte_safe_and_kernel_refusals_have_no_effect() {
    use std::os::unix::ffi::OsStrExt;
    let dir = Scratch::new();
    let tree = dir.0.join("tree");
    let mut deep = tree.clone();
    // 1100 levels: deeper than Python's default recursion limit (1000).
    for _ in 0..1100 {
        deep.push("d");
    }
    fs::create_dir_all(&deep).unwrap();
    let odd = std::ffi::OsStr::from_bytes(b"bad\xff");
    fs::write(tree.join(odd), b"x").unwrap();
    fs::create_dir(tree.join("sub")).unwrap();
    fs::write(tree.join("sub").join(odd), b"x").unwrap();
    for index in 0..300 {
        fs::write(tree.join(format!("f{index}")), b"x").unwrap();
    }
    assert_eq!(
        result(invoke(
            "remove",
            &tree,
            serde_json::json!({"recursive":true}),
            "",
            b"C"
        )),
        ResultBody::Remove { removed: true }
    );
    assert!(!tree.exists());
    // rename(2) into its own subtree is EINVAL: refused, nothing changed.
    let parent = dir.0.join("parent");
    fs::create_dir_all(parent.join("child")).unwrap();
    let out = invoke(
        "rename",
        &parent,
        serde_json::json!({"destPath": parent.join("child/moved")}),
        "",
        b"C",
    );
    let refused = failure(&out);
    assert_eq!(refused.code, SandboxErrorCode::PathRefused);
    assert_eq!(refused.state(), OperationState::Failed);
    assert_eq!(refused.failure().unwrap().effect, FailureEffect::None);
    assert!(parent.join("child").is_dir());
    for (errno, code) in [
        ("EBUSY", SandboxErrorCode::PathRefused),
        ("EMLINK", SandboxErrorCode::FsNoSpace),
    ] {
        let out = invoke(
            "mkdir",
            &dir.0.join("busy"),
            serde_json::json!({}),
            &format!(
                "def refused(*a, **kw): raise OSError(errno.{errno}, 'sentinel')\nos.mkdir = refused"
            ),
            b"C",
        );
        let failed = failure(&out);
        assert_eq!(failed.code, code, "{errno}");
        assert_eq!(
            failed.failure().unwrap().effect,
            FailureEffect::None,
            "{errno}"
        );
    }
}

/// B2R2-C-3: EINVAL/EBUSY/EMLINK are a no-effect refusal only from the
/// mkdir/rmdir/unlink/rename syscall of a metadata mutation. A directory
/// fsync EINVAL (filesystems without directory fsync) keeps its previous
/// classification: before the gate, put reports unknown_outcome.
#[test]
fn kernel_refusal_errnos_are_scoped_to_the_metadata_syscalls() {
    let dir = Scratch::new();
    // remove: the unlink itself refused.
    let file = dir.0.join("busy-file");
    fs::write(&file, b"x").unwrap();
    let out = invoke(
        "remove",
        &file,
        serde_json::json!({"recursive": false}),
        "def refused_unlink(*a, **kw): raise OSError(errno.EBUSY, 'sentinel')\nos.unlink = refused_unlink",
        b"C",
    );
    let refused = failure(&out);
    assert_eq!(refused.code, SandboxErrorCode::PathRefused);
    assert_eq!(refused.failure().unwrap().effect, FailureEffect::None);
    assert!(file.exists());
    // A directory fsync EINVAL is not a syscall refusal of the mutation.
    let fsync_einval = "original_fsync = os.fsync\ndef dir_fsync(fd):\n    if stat.S_ISDIR(os.fstat(fd).st_mode): raise OSError(errno.EINVAL, 'sentinel')\n    return original_fsync(fd)\nos.fsync = dir_fsync";
    let bytes = crate::FileContent::from_bytes(b"new bytes").unwrap();
    let target = dir.0.join("put-target");
    let source = HELPER.replace(
        "try:\n    run()",
        &format!("{fsync_einval}\ntry:\n    run()"),
    );
    let mut child = ManagedChild::spawn(
        Command::new("python3")
            .args([
                "-I",
                "-c",
                &source,
                "put",
                target.to_str().unwrap(),
                &token(),
                &bytes.len().to_string(),
                bytes.digest(),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    )
    .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(b"new bytesC").unwrap();
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        String::from_utf8(out.stderr.clone()).unwrap(),
        format!("WSSP_STATUS {} unknown_outcome unknown\n", token())
    );
    assert!(!target.exists());
    // The same directory fsync EINVAL inside mkdir stays unknown too: the
    // mkdir happened, so its durability proof is what is missing.
    let made = dir.0.join("made");
    let out = invoke("mkdir", &made, serde_json::json!({}), fsync_einval, b"C");
    assert_eq!(
        String::from_utf8(out.stderr.clone()).unwrap(),
        "",
        "an issued mutation without durability proof leaves no record"
    );
    assert!(made.is_dir());
}

#[test]
fn byte_transfer_errno_is_precise_and_never_carries_guest_text() {
    let dir = Scratch::new();
    let path = dir.0.join("sentinel-target");
    fs::write(&path, b"original").unwrap();
    let bytes = crate::FileContent::from_bytes(b"new bytes").unwrap();
    for (number, code) in [
        (13, SandboxErrorCode::FsPermissionDenied),
        (1, SandboxErrorCode::FsPermissionDenied),
        (28, SandboxErrorCode::FsNoSpace),
        (122, SandboxErrorCode::FsNoSpace),
        (30, SandboxErrorCode::FsReadOnly),
        (21, SandboxErrorCode::FsIsDirectory),
        (20, SandboxErrorCode::FsNotDirectory),
        (2, SandboxErrorCode::FsNotFound),
        (40, SandboxErrorCode::FsSymlinkRefused),
        (18, SandboxErrorCode::FsCrossDevice),
        (17, SandboxErrorCode::FsAlreadyExists),
        (39, SandboxErrorCode::FsNotEmpty),
    ] {
        for mode in ["read", "put"] {
            let injection = if mode == "read" {
                format!(
                    "original_open = os.open\ndef failed_open(name, *a, **kw):\n    if name == 'sentinel-target': raise OSError({number}, 'sentinel-stderr')\n    return original_open(name, *a, **kw)\nos.open = failed_open"
                )
            } else {
                format!(
                    "def failed_replace(*a, **kw): raise OSError({number}, 'sentinel-stderr')\nos.replace = failed_replace"
                )
            };
            let source =
                HELPER.replace("try:\n    run()", &format!("{injection}\ntry:\n    run()"));
            let mut child = ManagedChild::spawn(
                Command::new("python3")
                    .args([
                        "-I",
                        "-c",
                        &source,
                        mode,
                        path.to_str().unwrap(),
                        &token(),
                        &bytes.len().to_string(),
                        bytes.digest(),
                    ])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped()),
            )
            .unwrap();
            let mut stdin = child.stdin.take().unwrap();
            if mode == "put" {
                stdin.write_all(b"new bytesC").unwrap();
            }
            drop(stdin);
            let out = child.wait_with_output().unwrap();
            let failed = failure(&out);
            assert_eq!(failed.code, code, "{mode} errno {number}");
            assert_eq!(failed.failure().unwrap().effect, FailureEffect::None);
            assert!(!format!("{failed:?} {failed}").contains("sentinel"));
            assert_eq!(fs::read(&path).unwrap(), b"original");
        }
    }
    // Real fstat, rather than a diagnostic string, distinguishes entry types.
    for (name, code) in [
        ("directory", SandboxErrorCode::FsIsDirectory),
        ("fifo", SandboxErrorCode::FsNotRegular),
    ] {
        let target = dir.0.join(name);
        if name == "directory" {
            fs::create_dir(&target).unwrap();
        } else {
            assert!(
                Command::new("mkfifo")
                    .arg(&target)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        assert_eq!(
            failure(&invoke("read", &target, serde_json::json!({}), "", b"")).code,
            code
        );
    }
    let socket = dir.0.join("socket");
    let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    assert_eq!(
        failure(&invoke("read", &socket, serde_json::json!({}), "", b"")).code,
        SandboxErrorCode::FsNotRegular
    );
}

#[test]
fn unmapped_guest_errno_is_unknown_and_never_uses_a_coarse_file_status() {
    let dir = Scratch::new();
    let target = dir.0.join("target");
    let out = invoke(
        "mkdir",
        &target,
        serde_json::json!({}),
        "def failed_mkdir(*a, **kw): raise OSError(errno.EIO, 'sentinel-io')\nos.mkdir = failed_mkdir",
        b"C",
    );
    assert_eq!(
        out.stderr,
        format!("WSSP_STATUS {} unknown_outcome unknown\n", token()).as_bytes()
    );
    let unknown = failure(&out);
    assert_eq!(unknown.state(), OperationState::UnknownOutcome);
    assert_eq!(unknown.failure().unwrap().effect, FailureEffect::Unknown);
    assert!(!target.exists());
    assert!(!format!("{unknown:?} {unknown}").contains("sentinel"));
}
