//! Regression coverage for asynchronous test child ownership.
#![cfg(unix)]
#[path = "../../../crates/sandbox-runtime/tests/support/managed_child.rs"]
mod managed_child;
use managed_child::ManagedChild;
use std::path::Path;
use std::process::Command;

fn rust_files(dir: &Path, paths: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, paths);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            paths.push(path);
        }
    }
}

#[test]
fn asynchronous_cli_children_use_the_shared_guard() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut paths = Vec::new();
    for dir in ["apps/cli/tests", "apps/cli/src", "crates"] {
        rust_files(&root.join(dir), &mut paths);
    }
    for path in paths {
        if path.ends_with("child_guard.rs") {
            continue;
        }
        let source = std::fs::read_to_string(&path).unwrap();
        let test_file = path.components().any(|part| part.as_os_str() == "tests")
            || path
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .ends_with("_tests.rs")
            || path.ends_with("test_support.rs")
            || path.ends_with("tests.rs");
        let tests = if test_file {
            source.as_str()
        } else if let Some(start) = source.find("mod tests {") {
            &source[start..]
        } else {
            continue;
        };
        let compact: String = tests.chars().filter(|c| !c.is_whitespace()).collect();
        // Pin the existing non-daemon fixtures, rather than relying on the
        // spelling of a wssp binary path (helpers/wrappers can obscure it).
        // A new zero-argument process spawn in ANY Rust test fails this gate.
        let relative = path.strip_prefix(&root).unwrap().to_str().unwrap();
        let expected = match relative {
            // Python signal-helper and exact-wrapper fixtures (4b, no wssp binary).
            "crates/sandbox-runtime/src/incus/signal_helper_tests.rs" => 2,
            // Bounded-output shell fixtures (streaming excess and exact cap), never wssp.
            "crates/sandbox-runtime/src/incus/client.rs" => 2,
            // Disposable shell/setsid fixtures exercising guest wrappers.
            "crates/sandbox-runtime/src/incus/exec.rs" => 3,
            // Python fixture processes for FIFO/file lifetime tests.
            "crates/sandbox-runtime/src/incus/files.rs" => 2,
            // Python credential-helper fixture fed over piped stdin, never wssp.
            "crates/sandbox-runtime/src/credentials_tests.rs" => 1,
            // The credential helper run against a scratch tree (staging scrub), never wssp.
            "crates/sandbox-runtime/src/incus/credentials_tests.rs" => 1,
            // gzip/zstd compressor fixtures for the image validator, never wssp.
            "crates/sandbox-runtime/src/image_validate_tests.rs" => 1,
            // sleep bystanders in process-group isolation tests.
            "crates/sandbox-runtime/src/incus/pty_shim_tests.rs" => 2,
            // Contained libtest subprocess and sleep bystander, never wssp.
            "crates/sandbox-runtime/src/incus/shim_tests.rs" => 2,
            // The guest sudo helper run locally against a temp tree, never wssp.
            "crates/sandbox-runtime/src/incus/guest_sudo_tests.rs" => 1,
            // The root-grow helper run locally against a temp tree, never wssp.
            "crates/sandbox-runtime/src/incus/root_grow_tests.rs" => 1,
            // Unprivileged loopback dnsmasq in front of the DNS stub, never wssp.
            "crates/sandbox-runtime/src/incus/dns_stub.rs" => 1,
            // A /bin/sh fake tool for the guard's process-group kill tests, never wssp.
            "apps/cli/src/commands/guard/tools.rs" => 1,
            // The single shared construction boundary under test.
            "crates/sandbox-runtime/tests/support/managed_child.rs" => 1,
            _ => 0,
        };
        assert_eq!(
            compact.matches(".spawn()").count(),
            expected,
            "asynchronous process spawn inventory changed in {relative}: use ManagedChild::spawn for CLI/daemon children"
        );
    }
}

#[test]
fn drop_kills_and_reaps_on_panic_including_the_process_group() {
    let dir = tempfile::tempdir().unwrap();
    let ready = dir.path().join("ready");
    let mut pid = 0;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut command = Command::new("sh");
        command
            .args(["-c", "sleep 60 & echo $! > \"$1\"; wait", "sh"])
            .arg(&ready);
        let child = ManagedChild::spawn(&mut command).unwrap();
        pid = child.id();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !ready.exists() {
            assert!(std::time::Instant::now() < deadline, "child never ready");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("exercise unwinding with a live child");
    }));
    assert!(result.is_err());
    // Output collection must clean descendants before joining pipe readers,
    // even when their leader exits normally. The fallback sleep bounds a
    // regression without leaking an indefinitely blocked fixture.
    let started = std::time::Instant::now();
    let output = ManagedChild::spawn(
        Command::new("sh")
            .args(["-c", "sleep 10 & printf leader"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped()),
    )
    .unwrap()
    .wait_with_output()
    .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"leader");
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    // Linux /proc absence proves the direct child was reaped, not just killed.
    #[cfg(target_os = "linux")]
    {
        assert!(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "child was not reaped"
        );
        let descendant = std::fs::read_to_string(ready).unwrap();
        let stat = format!("/proc/{}/stat", descendant.trim());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let state = std::fs::read_to_string(&stat).ok();
            // A grandchild zombie belongs to init; it cannot continue running.
            if state
                .as_ref()
                .is_none_or(|s| s.rsplit_once(") ").unwrap().1.starts_with('Z'))
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "descendant survived drop"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}
