//! Credential guest operations over a fake `incus` that logs argv and, per
//! test, either runs the real helper locally against a scratch home (never a
//! VM) or replays a canned framed report. Quiesce is only ever canned.

use super::client::IncusClient;
use super::shim_tests::install_executable;
use crate::{
    CredentialGuest, CredentialPackRequest, CredentialPathSet, CredentialRestoreFile,
    CredentialRestoreRequest, CredentialScrubRequest,
};
use sandbox_protocol::SandboxErrorCode;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const HEX: &str = "abababababababababababababababababababababababababababababababab";
static COUNTER: AtomicU64 = AtomicU64::new(0);

struct Shim {
    dir: PathBuf,
}

impl Drop for Shim {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

impl Shim {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "wssp-cred-shim-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(dir.join("home")).expect("shim dir");
        install_executable(&dir.join("incus"), &script(&dir), 0o755);
        fs::write(dir.join("status"), "Running").unwrap();
        fs::write(dir.join("exec-mode"), "real").unwrap();
        Self { dir }
    }
    fn client(&self) -> IncusClient {
        IncusClient::new(self.dir.join("incus").to_string_lossy(), "default")
    }
    fn home(&self) -> PathBuf {
        self.dir.join("home")
    }
    fn guest(&self) -> CredentialGuest {
        CredentialGuest {
            sandbox_id: "sbx-1".into(),
            uid: 1000,
            gid: 1000,
            home: self.home().to_string_lossy().into_owned(),
        }
    }
    fn mode(&self, mode: &str) {
        fs::write(self.dir.join("exec-mode"), mode).unwrap();
    }
    /// A canned helper answer: framed `report` plus `body`, then `exit`.
    fn canned(&self, report: &serde_json::Value, body: &[u8], exit: i32) {
        let json = report.to_string();
        let mut bytes = (json.len() as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(json.as_bytes());
        bytes.extend_from_slice(body);
        fs::write(self.dir.join("canned.bin"), bytes).unwrap();
        fs::write(self.dir.join("exit"), exit.to_string()).unwrap();
        self.mode("canned");
    }
    fn exec_lines(&self) -> Vec<String> {
        fs::read_to_string(self.dir.join("incus.log"))
            .unwrap_or_default()
            .lines()
            .filter(|l| l.starts_with("exec "))
            .map(str::to_owned)
            .collect()
    }
    fn stdin(&self) -> Vec<u8> {
        fs::read(self.dir.join("stdin.bin")).unwrap_or_default()
    }
}

fn script(dir: &Path) -> String {
    format!(
        r#"#!/bin/sh
d='{dir}'
if [ "$1" = "--project" ]; then shift 2; fi
line=""; prev=""
for a in "$@"; do
  if [ "$prev" = "-c" ]; then a="<code>"; fi
  line="$line${{line:+ }}$a"; prev="$a"
done
printf '%s\n' "$line" >> "$d/incus.log"
case "$1" in
  query)
    if [ -f "$d/query.json" ]; then cat "$d/query.json"; exit 0; fi
    printf '{{"type":"sync","metadata":{{"type":"virtual-machine","status":"%s","config":{{"user.flycockpit.sandbox_id":"sbx-1","user.flycockpit.template_digest":"sha256:{HEX}","volatile.base_image":"{HEX}"}}}}}}\n' "$(cat "$d/status")"
    ;;
  exec)
    cat > "$d/stdin.bin"
    case "$(cat "$d/exec-mode")" in
      real)
        while [ "$1" != "--" ]; do shift; done
        shift 2
        exec /usr/bin/python3 "$@" < "$d/stdin.bin"
        ;;
      canned) cat "$d/canned.bin"; exit "$(cat "$d/exit")" ;;
      sleep) sleep 30 ;;
      missing) exit 127 ;;
    esac
    ;;
esac
exit 0
"#,
        dir = dir.display(),
    )
}

fn paths() -> CredentialPathSet {
    CredentialPathSet {
        required: vec![".config/tool".into()],
        optional: vec![],
        exclude: vec![],
    }
}

fn pack_request(shim: &Shim, max_bytes: usize) -> CredentialPackRequest {
    CredentialPackRequest {
        guest: shim.guest(),
        paths: paths(),
        definition_digest: [7; 32],
        max_bytes,
    }
}

#[test]
fn credential_pack_runs_the_fixed_helper_as_the_guest_with_paths_only_on_stdin() {
    let shim = Shim::new();
    fs::create_dir_all(shim.home().join(".config/tool")).unwrap();
    fs::write(shim.home().join(".config/tool/auth.json"), "token-a").unwrap();
    let outcome = shim
        .client()
        .credential_pack(&pack_request(&shim, 4096))
        .unwrap();
    assert_eq!(outcome.file_count, 2);
    assert!(outcome.bundle.as_bytes().ends_with(b"token-a"));
    let home = shim.home().display().to_string();
    assert_eq!(
        shim.exec_lines(),
        [format!(
            "exec wssp-sbx-sbx-1 -T --user 1000 --group 1000 --cwd {home} --env HOME={home} \
             -- python3 -I -S -B -c <code> pack"
        )]
    );
    let stdin = String::from_utf8_lossy(&shim.stdin()).into_owned();
    assert!(stdin.contains(".config/tool"), "paths travel on stdin");
}

#[test]
fn credential_restore_streams_the_payload_on_stdin_and_writes_through_the_helper() {
    let shim = Shim::new();
    let request = CredentialRestoreRequest {
        guest: shim.guest(),
        declared: paths(),
        files: vec![CredentialRestoreFile {
            kind: login_definition::BundleFileKind::File,
            path: ".config/tool",
            mode: 0o600,
            data: b"restored-value",
        }],
    };
    let outcome = shim.client().credential_restore(&request).unwrap();
    assert_eq!(outcome.files_written, 1);
    assert_eq!(
        fs::read(shim.home().join(".config/tool")).unwrap(),
        b"restored-value"
    );
    assert!(shim.stdin().ends_with(b"restored-value"));
    assert!(
        shim.exec_lines()
            .iter()
            .all(|l| !l.contains("restored-value") && l.ends_with("<code> restore")),
        "{:?}",
        shim.exec_lines()
    );
}

#[test]
fn credential_scrub_reports_unverified_absence_as_an_outcome() {
    let shim = Shim::new();
    let request = CredentialScrubRequest {
        guest: shim.guest(),
        paths: vec![".aws".into()],
    };
    shim.canned(
        &serde_json::json!({"ok": false, "verifiedAbsent": false, "removed": 0,
                            "linksUnlinked": 0, "failed": [".aws/x"]}),
        b"",
        1,
    );
    let outcome = shim.client().credential_scrub(&request).unwrap();
    assert!(!outcome.verified_absent);
    assert_eq!(outcome.failed_paths, [".aws/x"]);
    // A "verified" report with a failing exit is not trusted.
    shim.canned(
        &serde_json::json!({"ok": true, "verifiedAbsent": true, "removed": 0,
                            "linksUnlinked": 0, "failed": []}),
        b"",
        1,
    );
    assert!(shim.client().credential_scrub(&request).is_err());
}

#[test]
fn malformed_oversized_and_failed_helper_output_is_refused() {
    let shim = Shim::new();
    let request = pack_request(&shim, 16);
    let cap = login_definition::limits::bundle_max_encoded_bytes(16);
    let report = |len: usize| {
        serde_json::json!({"ok": true, "bundleLen": len, "fileCount": 0,
                           "skippedLinks": 0, "skippedSpecial": 0})
    };
    // Larger than the bundle bound for maxBytes: never read.
    shim.canned(&report(cap + 1), b"", 0);
    assert!(shim.client().credential_pack(&request).is_err());
    // Trailing bytes after the declared bundle.
    let mut bundle = b"WSCB\x01".to_vec();
    bundle.extend_from_slice(&[7; 32]);
    bundle.extend_from_slice(&[0, 0, 0, 0]);
    let mut trailing = bundle.clone();
    trailing.push(b'x');
    shim.canned(&report(bundle.len()), &trailing, 0);
    assert!(shim.client().credential_pack(&request).is_err());
    // The exact bundle is accepted.
    shim.canned(&report(bundle.len()), &bundle, 0);
    assert_eq!(
        shim.client().credential_pack(&request).unwrap().file_count,
        0
    );
    // A bundle with a foreign digest is refused.
    let mut foreign = bundle.clone();
    foreign[5] = 8;
    shim.canned(&report(bundle.len()), &foreign, 0);
    assert!(shim.client().credential_pack(&request).is_err());
    // A failing helper names the problem without any bytes.
    shim.canned(
        &serde_json::json!({"ok": false, "errors": [{"path": "<pack>", "error": "credential files exceed maxBytes"}]}),
        b"",
        1,
    );
    let err = shim.client().credential_pack(&request).unwrap_err();
    assert_eq!(err.code, SandboxErrorCode::GuestOperationFailed);
    assert!(err.message.contains("exceed maxBytes"), "{}", err.message);
    // A huge report length is refused.
    fs::write(shim.dir.join("canned.bin"), u32::MAX.to_be_bytes()).unwrap();
    assert!(shim.client().credential_pack(&request).is_err());
}

#[test]
fn credential_quiesce_runs_as_root_and_parses_the_report() {
    let shim = Shim::new();
    shim.canned(
        &serde_json::json!({"ok": true, "terminated": 2, "killed": 1, "freezer": true, "errors": []}),
        b"",
        0,
    );
    let outcome = shim.client().credential_quiesce(&shim.guest()).unwrap();
    assert_eq!(
        (outcome.terminated, outcome.killed, outcome.freezer),
        (2, 1, true)
    );
    assert_eq!(
        shim.exec_lines(),
        ["exec wssp-sbx-sbx-1 -T --user 0 --group 0 --cwd / -- python3 -I -S -B -c <code> quiesce"]
    );
    assert!(String::from_utf8_lossy(&shim.stdin()).contains("\"uid\":1000"));
}

#[test]
fn cancellation_kills_a_running_helper_and_missing_python_is_not_present() {
    let shim = Shim::new();
    shim.mode("sleep");
    let permit = std::sync::Arc::new(crate::RuntimePermit::default());
    let mut client = shim.client();
    client.cancelled = Some(permit.clone());
    let started = std::time::Instant::now();
    let revoker = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(200));
        permit.revoke();
    });
    let err = client
        .credential_scrub(&CredentialScrubRequest {
            guest: shim.guest(),
            paths: vec![".aws".into()],
        })
        .unwrap_err();
    revoker.join().unwrap();
    assert_eq!(err.code, SandboxErrorCode::Cancelled);
    assert!(started.elapsed() < std::time::Duration::from_secs(10));

    shim.mode("missing");
    assert!(
        !shim
            .client()
            .credential_helper_present(&shim.guest())
            .unwrap()
    );
    shim.mode("real");
    assert!(
        shim.client()
            .credential_helper_present(&shim.guest())
            .unwrap()
    );
}

#[test]
fn a_stopped_sandbox_or_an_invalid_request_never_execs() {
    let shim = Shim::new();
    fs::write(shim.dir.join("status"), "Stopped").unwrap();
    let err = shim
        .client()
        .credential_pack(&pack_request(&shim, 4096))
        .unwrap_err();
    assert_eq!(err.code, SandboxErrorCode::SandboxNotRunning);
    fs::write(shim.dir.join("status"), "Running").unwrap();
    let mut bad = pack_request(&shim, 4096);
    bad.paths.required = vec!["../etc".into()];
    assert!(shim.client().credential_pack(&bad).is_err());
    let mut root = shim.guest();
    root.uid = 0;
    assert!(shim.client().credential_quiesce(&root).is_err());
    assert!(shim.exec_lines().is_empty());
}

/// Credential install binds a restored instance through
/// the host-owned binding; a forged lineage (restored base without a valid
/// restore tag) is never written to.
#[test]
fn credential_install_binds_a_restored_instance_and_refuses_a_forged_one() {
    const DISK: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    for (tag, ok) in [
        (format!("sha256:{DISK}"), true),
        ("forged".to_string(), false),
    ] {
        let shim = Shim::new();
        fs::write(
            shim.dir.join("query.json"),
            format!(
                r#"{{"type":"sync","metadata":{{"type":"virtual-machine","status":"Running","config":{{"user.flycockpit.sandbox_id":"sbx-1","user.flycockpit.template_digest":"sha256:{HEX}","volatile.base_image":"{DISK}","user.flycockpit.restore_base":"{tag}"}}}}}}"#
            ),
        )
        .unwrap();
        let request = CredentialRestoreRequest {
            guest: shim.guest(),
            declared: paths(),
            files: vec![CredentialRestoreFile {
                kind: login_definition::BundleFileKind::File,
                path: ".config/tool",
                mode: 0o600,
                data: b"restored-value",
            }],
        };
        let outcome = shim.client().credential_restore(&request);
        assert_eq!(outcome.is_ok(), ok, "{tag}: {outcome:?}");
        if !ok {
            assert!(
                shim.exec_lines().is_empty(),
                "a forged lineage is never written"
            );
        }
    }
}
