//! Real fixed helpers against disposable scratch trees, without Incus.

use crate::credentials::CREDENTIAL_HELPER;
use std::io::Write;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "wssp-credential-residue-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(path.join("auth")).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn helper(home: &Path, mode: &str, setup: &str) -> serde_json::Value {
    let control = if mode == "restore" {
        serde_json::json!({
            "home": home, "declared": {"required": ["auth/token"]},
            "entries": [{"kind": 1, "path": "auth/token", "mode": 384, "len": 4}]
        })
    } else {
        serde_json::json!({"home": home, "paths": ["auth/token"]})
    };
    helper_control(mode, setup, control)
}

fn helper_control(mode: &str, setup: &str, control: serde_json::Value) -> serde_json::Value {
    let harness = format!(
        "import sys\nns = {{'__name__': 'helper'}}\nexec(sys.argv[1], ns)\n{setup}\n\
         sys.exit(ns['main'](['helper', sys.argv[2]]))"
    );
    let mut child = Command::new("/usr/bin/python3")
        .args(["-I", "-S", "-B", "-c", &harness, CREDENTIAL_HELPER, mode])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let data = control.to_string();
    let mut input = (data.len() as u32).to_be_bytes().to_vec();
    input.extend_from_slice(data.as_bytes());
    if mode == "restore" {
        input.extend_from_slice(b"test");
    }
    child.stdin.take().unwrap().write_all(&input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.stdout.len() >= 4,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout[4..]).unwrap();
    assert_eq!(output.status.success(), report["ok"] == true);
    report
}

#[test]
fn rename_failure_removes_credential_staging_file() {
    let dir = Scratch::new();
    let report = helper(
        &dir.0,
        "restore",
        "\
        def race(where, path):\n    \
            if where == 'rename':\n        \
                def refuse(*args, **kwargs):\n            \
                    raise OSError('injected rename failure')\n        \
                ns['os'].rename = refuse\n\
        ns['_race_window'] = race",
    );
    assert_eq!(report["ok"], false);
    assert_eq!(std::fs::read_dir(dir.0.join("auth")).unwrap().count(), 0);
}

fn crash_residue(home: &Path) {
    std::fs::write(home.join("auth/.wssp-cred-0123456789abcdef"), "staged").unwrap();
    std::fs::write(home.join("outside"), "kept").unwrap();
    std::fs::write(home.join("auth").join(staging_pattern()), "literal").unwrap();
    symlink(
        home.join("outside"),
        home.join("auth/.wssp-cred-fedcba9876543210"),
    )
    .unwrap();
    for name in [
        "notes",
        ".wssp-cred-0123456789abcdeg",
        ".wssp-cred-0123456789abcdef0",
    ] {
        std::fs::write(home.join("auth").join(name), "kept").unwrap();
    }
}

fn staging_pattern() -> String {
    format!(".wssp-cred-{}", "[0-9a-f]".repeat(16))
}

fn assert_residue_gone(home: &Path) {
    assert_eq!(
        std::fs::read(home.join("auth").join(staging_pattern())).unwrap(),
        b"literal"
    );
    assert!(!home.join("auth/.wssp-cred-0123456789abcdef").exists());
    assert!(std::fs::symlink_metadata(home.join("auth/.wssp-cred-fedcba9876543210")).is_err());
    assert_eq!(std::fs::read(home.join("outside")).unwrap(), b"kept");
    for name in [
        "notes",
        ".wssp-cred-0123456789abcdeg",
        ".wssp-cred-0123456789abcdef0",
    ] {
        assert_eq!(
            std::fs::read(home.join("auth").join(name)).unwrap(),
            b"kept"
        );
    }
}

#[test]
fn credential_scrub_removes_crash_staging_without_following_links() {
    let dir = Scratch::new();
    crash_residue(&dir.0);
    assert_eq!(helper(&dir.0, "scrub", "")["verifiedAbsent"], true);
    assert_residue_gone(&dir.0);
}

#[test]
fn credential_restore_preclear_removes_crash_staging() {
    let dir = Scratch::new();
    crash_residue(&dir.0);
    assert_eq!(helper(&dir.0, "restore", "")["ok"], true);
    assert_residue_gone(&dir.0);
    assert_eq!(std::fs::read(dir.0.join("auth/token")).unwrap(), b"test");
}

#[test]
fn credential_capture_scrubs_exact_staging_pattern_without_following_links() {
    let dir = Scratch::new();
    crash_residue(&dir.0);
    let targets =
        crate::credential_scrub_targets(dir.0.to_str().unwrap(), &["auth/token".into()]).unwrap();
    let output = Command::new("/usr/bin/python3")
        .args([
            "-I",
            "-S",
            "-B",
            "-c",
            crate::SCRUB_HELPER,
            "in-place",
            "0",
            crate::CREDENTIAL_SCRUB_SEPARATOR,
        ])
        .args(targets)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_residue_gone(&dir.0);
}

#[test]
fn credential_capture_rejects_a_declared_filename_equal_to_the_staging_pattern() {
    let dir = Scratch::new();
    let literal = format!("auth/{}", staging_pattern());
    std::fs::write(dir.0.join(&literal), "literal").unwrap();
    assert!(
        crate::credential_scrub_targets(dir.0.to_str().unwrap(), std::slice::from_ref(&literal))
            .is_err()
    );
    assert_eq!(std::fs::read(dir.0.join(literal)).unwrap(), b"literal");
}

#[test]
fn credential_helper_rejects_staging_names_at_every_depth_before_modifying_files() {
    let dir = Scratch::new();
    for path in [
        "auth/.wssp-cred-0123456789abcdef",
        "auth/nested/.wssp-cred-0123456789abcdef/token",
        "auth/.wssp-cred-other",
    ] {
        let target = dir.0.join(path);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&target, "kept").unwrap();
        for mode in ["scrub", "pack", "restore"] {
            let control = match mode {
                "scrub" => serde_json::json!({"home": dir.0, "paths": [path]}),
                "pack" => serde_json::json!({
                    "home": dir.0, "required": [path], "digest": "a".repeat(64), "maxBytes": 1024
                }),
                _ => serde_json::json!({
                    "home": dir.0, "declared": {"required": [path]},
                    "entries": [{"kind": 1, "path": path, "mode": 384, "len": 4}]
                }),
            };
            assert_eq!(
                helper_control(mode, "", control)["ok"],
                false,
                "{mode}: {path}"
            );
            assert_eq!(std::fs::read(&target).unwrap(), b"kept", "{mode}: {path}");
        }
    }
    // A valid directory declaration must not smuggle a reserved descendant
    // through pack traversal or restore bundle entries either.
    let path = "auth/.wssp-cred-0123456789abcdef";
    let pack = serde_json::json!({
        "home": dir.0, "required": ["auth"], "digest": "a".repeat(64), "maxBytes": 1024
    });
    assert_eq!(helper_control("pack", "", pack)["ok"], false);
    let restore = serde_json::json!({
        "home": dir.0, "declared": {"required": ["auth"]},
        "entries": [{"kind": 1, "path": path, "mode": 384, "len": 4}]
    });
    assert_eq!(helper_control("restore", "", restore)["ok"], false);
    assert_eq!(std::fs::read(dir.0.join(path)).unwrap(), b"kept");
}
