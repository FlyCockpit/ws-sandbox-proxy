//! Credential helper (real `python3` on scratch trees, never `/` and never a
//! guest), request validation and FakeRuntime semantics.

use super::*;
use crate::{FakeRuntime, SandboxRuntime};
use std::io::Write as _;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "wssp-cred-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Run {
    code: i32,
    report: serde_json::Value,
    body: Vec<u8>,
}

/// Runs the helper as a module with `setup` (Python, `ns` in scope) applied
/// before `main`, feeding `control` then `payload` on stdin.
fn run(setup: &str, mode: &str, control: &serde_json::Value, payload: &[u8]) -> Run {
    let harness = format!(
        "import os, sys\nns = {{'__name__': 'cred_helper'}}\n\
         exec(compile(sys.argv[1], 'cred', 'exec'), ns)\n{setup}\n\
         sys.exit(ns['main'](['cred'] + sys.argv[2:]))\n"
    );
    let mut child = std::process::Command::new("/usr/bin/python3")
        .args(["-I", "-S", "-B", "-c", &harness, CREDENTIAL_HELPER, mode])
        .env_clear()
        .env("PATH", "")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("python3");
    let mut stdin = child.stdin.take().unwrap();
    let mut input = frame(control.to_string().as_bytes()).unwrap();
    input.extend_from_slice(payload);
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let out = child.wait_with_output().unwrap();
    writer.join().unwrap();
    assert!(
        out.stdout.len() >= 4,
        "no report: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let len = u32::from_be_bytes(out.stdout[..4].try_into().unwrap()) as usize;
    let report = serde_json::from_slice(&out.stdout[4..4 + len]).expect("report JSON");
    Run {
        code: out.status.code().unwrap_or(-1),
        report,
        body: out.stdout[4 + len..].to_vec(),
    }
}

fn definition(max_bytes: usize) -> (login_definition::LoginDefinition, [u8; 32]) {
    let document = serde_json::json!({
        "schemaVersion": 1,
        "id": "tool",
        "displayName": "Tool",
        "login": {"command": "tool login", "method": "paste"},
        "credentials": {
            "files": {
                "required": [".config/tool"],
                "optional": [".tool-token"],
                "exclude": [".config/tool/cache"]
            },
            "maxBytes": max_bytes
        }
    });
    let parsed = login_definition::parse_definition(&document).expect("definition");
    let digest = login_definition::definition_digest(&document).expect("digest");
    (parsed.definition, digest)
}

fn pack_control(home: &Path, digest: &[u8; 32], max_bytes: usize) -> serde_json::Value {
    serde_json::json!({
        "home": home, "required": [".config/tool"], "optional": [".tool-token"],
        "exclude": [".config/tool/cache"], "digest": hex(digest), "maxBytes": max_bytes,
    })
}

fn tool_tree(home: &Path, outside: &Path) {
    std::fs::create_dir_all(home.join(".config/tool/sub")).unwrap();
    std::fs::create_dir_all(home.join(".config/tool/cache")).unwrap();
    std::fs::create_dir_all(outside).unwrap();
    std::fs::write(outside.join("secret"), "OUTSIDE-SECRET").unwrap();
    std::fs::write(home.join(".config/tool/auth.json"), "token-a").unwrap();
    std::fs::write(home.join(".config/tool/run.sh"), "#!/bin/sh").unwrap();
    std::fs::set_permissions(
        home.join(".config/tool/run.sh"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    std::fs::write(home.join(".config/tool/sub/b"), "token-b").unwrap();
    std::fs::write(home.join(".config/tool/cache/x"), "cached").unwrap();
    std::fs::write(home.join(".tool-token"), "token-c").unwrap();
    symlink(outside.join("secret"), home.join(".config/tool/link")).unwrap();
    let status = std::process::Command::new("mkfifo")
        .arg(home.join(".config/tool/pipe"))
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn pack_round_trips_through_decode_bundle_and_never_reads_links_or_fifos() {
    let dir = Scratch::new();
    let home = dir.path().join("home");
    let outside = dir.path().join("outside");
    tool_tree(&home, &outside);
    let (def, digest) = definition(4096);
    let out = run("", "pack", &pack_control(&home, &digest, 4096), b"");
    assert_eq!(out.code, 0, "{}", out.report);
    assert_eq!(out.report["skippedLinks"], 1);
    assert_eq!(out.report["skippedSpecial"], 1);
    assert_eq!(out.report["bundleLen"], out.body.len());
    let bundle = login_definition::decode_bundle(&out.body, &def, &digest).expect("decodes");
    let got: Vec<(&str, u16, &[u8])> = bundle
        .files
        .iter()
        .map(|f| (f.path, f.mode, f.data))
        .collect();
    assert_eq!(
        got,
        [
            (".config/tool", 0o700, &b""[..]),
            (".config/tool/auth.json", 0o600, b"token-a"),
            (".config/tool/run.sh", 0o700, b"#!/bin/sh"),
            (".config/tool/sub", 0o700, b""),
            (".config/tool/sub/b", 0o600, b"token-b"),
            (".tool-token", 0o600, b"token-c"),
        ]
    );
    assert!(bundle.env.is_empty());
    assert!(
        !out.body.windows(14).any(|w| w == b"OUTSIDE-SECRET"),
        "a link target was read"
    );
    // The outcome check accepts exactly this bundle for this request.
    let request = CredentialPackRequest {
        guest: guest(&home),
        paths: paths(),
        definition_digest: digest,
        max_bytes: 4096,
    };
    let outcome =
        pack_outcome(&request, &out.report, Zeroizing::new(out.body.clone())).expect("outcome");
    assert_eq!(outcome.file_count, 6);
    let mut wrong = request.clone();
    wrong.definition_digest = [9; 32];
    assert!(pack_outcome(&wrong, &out.report, Zeroizing::new(out.body)).is_err());
}

#[test]
fn pack_fails_closed_on_every_limit_and_missing_paths_are_absent() {
    let dir = Scratch::new();
    let home = dir.path().join("home");
    tool_tree(&home, &dir.path().join("outside"));
    let (_, digest) = definition(4096);
    let over = run("", "pack", &pack_control(&home, &digest, 10), b"");
    assert_eq!(over.code, 1);
    assert_eq!(over.report["ok"], false);
    assert!(over.body.is_empty(), "no partial bundle");
    assert!(
        over.report.to_string().contains("exceed maxBytes"),
        "{}",
        over.report
    );
    let entries = run(
        "ns['MAX_ENTRIES'] = 3",
        "pack",
        &pack_control(&home, &digest, 4096),
        b"",
    );
    assert!(
        entries.report.to_string().contains("entry limit"),
        "{}",
        entries.report
    );
    assert_eq!(entries.code, 1);
    let depth = run(
        "ns['MAX_DEPTH'] = 2",
        "pack",
        &pack_control(&home, &digest, 4096),
        b"",
    );
    assert!(
        depth.report.to_string().contains("depth limit"),
        "{}",
        depth.report
    );
    let empty = dir.path().join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    let absent = run("", "pack", &pack_control(&empty, &digest, 4096), b"");
    assert_eq!(absent.code, 0, "{}", absent.report);
    assert_eq!(absent.report["fileCount"], 0);
}

#[test]
fn pack_never_follows_a_file_swapped_for_a_link_between_check_and_read() {
    let dir = Scratch::new();
    let home = dir.path().join("home");
    let outside = dir.path().join("outside");
    tool_tree(&home, &outside);
    let (_, digest) = definition(4096);
    let setup = format!(
        "def race(where, shown):\n    \
         if where == 'read' and shown.endswith('auth.json'):\n        \
         p = {h:?} + '/' + shown\n        os.unlink(p)\n        os.symlink({t:?}, p)\n\
         ns['_race_window'] = race",
        h = home.to_str().unwrap(),
        t = outside.join("secret").to_str().unwrap(),
    );
    let out = run(&setup, "pack", &pack_control(&home, &digest, 4096), b"");
    assert_eq!(out.code, 1);
    assert!(
        out.report.to_string().contains("replaced during pack"),
        "{}",
        out.report
    );
    assert!(out.body.is_empty());
}

fn restore_control_for(
    home: &Path,
    entries: &[(u8, &str, u16, &[u8])],
) -> (serde_json::Value, Vec<u8>) {
    let specs: Vec<serde_json::Value> = entries
        .iter()
        .map(|(k, p, m, d)| serde_json::json!({"kind": k, "path": p, "mode": m, "len": d.len()}))
        .collect();
    let payload = entries.iter().flat_map(|e| e.3.to_vec()).collect();
    (
        serde_json::json!({
            "home": home,
            "declared": {"required": [".config/tool"], "optional": [".tool-token"], "exclude": []},
            "entries": specs,
        }),
        payload,
    )
}

#[test]
fn restore_clears_declared_paths_then_writes_with_masked_modes() {
    let dir = Scratch::new();
    let home = dir.path().join("home");
    std::fs::create_dir_all(home.join(".config/tool")).unwrap();
    std::fs::write(home.join(".config/tool/stale"), "old").unwrap();
    std::fs::write(home.join(".tool-token"), "old-token").unwrap();
    let (control, payload) = restore_control_for(
        &home,
        &[
            (2, ".config/tool", 0o700, b""),
            (1, ".config/tool/auth.json", 0o755, b"new-a"),
            (2, ".config/tool/sub", 0o700, b""),
            (1, ".config/tool/sub/b", 0o644, b"new-b"),
        ],
    );
    let out = run("", "restore", &control, &payload);
    assert_eq!(out.code, 0, "{}", out.report);
    assert_eq!(out.report["filesWritten"], 2);
    assert!(
        !home.join(".config/tool/stale").exists(),
        "declared dir not cleared"
    );
    assert!(
        !home.join(".tool-token").exists(),
        "optional path not cleared"
    );
    let mode = |p: &str| {
        std::fs::metadata(home.join(p))
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(
        std::fs::read(home.join(".config/tool/auth.json")).unwrap(),
        b"new-a"
    );
    assert_eq!(mode(".config/tool/auth.json"), 0o700);
    assert_eq!(mode(".config/tool/sub/b"), 0o600);
    assert_eq!(mode(".config/tool/sub"), 0o700);
    let leftovers: Vec<_> = std::fs::read_dir(home.join(".config/tool"))
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with(".wssp-cred-"))
        .collect();
    assert!(leftovers.is_empty());
}

#[test]
fn restore_refuses_a_symlinked_parent_and_a_link_planted_at_the_target() {
    let dir = Scratch::new();
    let home = dir.path().join("home");
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    symlink(&outside, home.join(".config")).unwrap();
    let (control, payload) = restore_control_for(&home, &[(1, ".config/tool", 0o600, b"secret")]);
    let out = run("", "restore", &control, &payload);
    assert_eq!(out.code, 1, "{}", out.report);
    assert!(out.report.to_string().contains("parent is not a directory"));
    assert_eq!(
        std::fs::read_dir(&outside).unwrap().count(),
        0,
        "wrote through the link"
    );
    assert!(
        home.join(".config").is_symlink(),
        "the user's link is not ours"
    );

    // A link planted at the target after the clear is refused, never replaced.
    std::fs::remove_file(home.join(".config")).unwrap();
    std::fs::write(outside.join("victim"), "keep").unwrap();
    let setup = format!(
        "def race(where, shown):\n    \
         if where == 'rename':\n        os.symlink({v:?}, {h:?} + '/' + shown)\n\
         ns['_race_window'] = race",
        v = outside.join("victim").to_str().unwrap(),
        h = home.to_str().unwrap(),
    );
    let (control, payload) = restore_control_for(&home, &[(1, ".tool-token", 0o600, b"secret")]);
    let out = run(&setup, "restore", &control, &payload);
    assert_eq!(out.code, 1, "{}", out.report);
    assert!(
        out.report.to_string().contains("not a regular file"),
        "{}",
        out.report
    );
    assert_eq!(std::fs::read(outside.join("victim")).unwrap(), b"keep");
    assert!(home.join(".tool-token").is_symlink());
}

#[test]
fn restore_refuses_entries_outside_the_declared_paths() {
    let dir = Scratch::new();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let (control, payload) = restore_control_for(&home, &[(1, ".bashrc", 0o600, b"x")]);
    let out = run("", "restore", &control, &payload);
    assert_eq!(out.code, 1);
    assert!(!home.join(".bashrc").exists());
}

#[test]
fn scrub_unlinks_links_without_touching_targets_and_verifies_absence() {
    let dir = Scratch::new();
    let home = dir.path().join("home");
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(home.join(".aws/nested")).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("secret"), "keep").unwrap();
    std::fs::write(home.join(".aws/config"), "x").unwrap();
    symlink(outside.join("secret"), home.join(".aws/credentials")).unwrap();
    symlink(&outside, home.join(".aws/nested/dirlink")).unwrap();
    let control = serde_json::json!({"home": home, "paths": [".aws", ".missing"]});
    let out = run("", "scrub", &control, b"");
    assert_eq!(out.code, 0, "{}", out.report);
    assert_eq!(out.report["verifiedAbsent"], true);
    assert_eq!(out.report["linksUnlinked"], 2);
    assert!(!home.join(".aws").exists());
    assert_eq!(std::fs::read(outside.join("secret")).unwrap(), b"keep");
    let outcome = scrub_outcome(&out.report).unwrap();
    assert!(outcome.verified_absent && outcome.failed_paths.is_empty());
}

/// Records every unlink/rmdir, fsync, sync, absence check and the report
/// in order (`ns['events']`), and optionally makes `fsync` fail.
fn durability_probe(fail_fsync: bool) -> String {
    format!(
        "events = []\n\
         real = {{n: getattr(os, n) for n in ('unlink', 'rmdir', 'fsync', 'sync')}}\n\
         def rec(n):\n    \
             def f(*a, **k):\n        \
                 events.append(n)\n        \
                 if n == 'fsync' and {fail}:\n            \
                     raise OSError(5, 'Input/output error')\n        \
                 return real[n](*a, **k)\n    \
             return f\n\
         for n in real:\n    setattr(os, n, rec(n))\n\
         real_present, real_emit = ns['present'], ns['emit']\n\
         def present(*a):\n    events.append('verify')\n    return real_present(*a)\n\
         def emit(report, body=b''):\n    \
             events.append('report')\n    \
             report['events'] = events\n    \
             return real_emit(report, body)\n\
         ns['present'] = present\n\
         ns['emit'] = emit",
        fail = if fail_fsync { "True" } else { "False" },
    )
}

fn events(report: &serde_json::Value) -> Vec<String> {
    serde_json::from_value(report["events"].clone()).expect("events")
}

/// E1-B-01: a user stop is a forced power-off, which discards the guest page
/// cache. A scrub whose unlinks were never fsynced reported `verifiedAbsent`
/// from the page cache while the disk kept the token. The helper must make
/// every removal durable (parent fsync, then sync) BEFORE it verifies
/// absence, and verify before it reports: remove → fsync → sync → verify →
/// report.
#[test]
fn scrub_is_durable_before_it_verifies_and_reports() {
    let dir = Scratch::new();
    let home = dir.path().join("home");
    std::fs::create_dir_all(home.join(".fakecli")).unwrap();
    std::fs::write(home.join(".fakecli/token"), "vault-token").unwrap();
    std::fs::create_dir_all(home.join(".aws")).unwrap();
    std::fs::write(home.join(".aws/credentials"), "x").unwrap();
    let control =
        serde_json::json!({"home": home, "paths": [".fakecli/token", ".aws", ".missing"]});
    let out = run(&durability_probe(false), "scrub", &control, b"");
    assert_eq!(out.code, 0, "{}", out.report);
    assert_eq!(out.report["verifiedAbsent"], true);
    let events = events(&out.report);
    let last = |name: &str| events.iter().rposition(|e| e == name).unwrap();
    let first = |name: &str| events.iter().position(|e| e == name).unwrap();
    // One parent fsync per declared path whose parent exists, after its removal.
    assert_eq!(
        events.iter().filter(|e| *e == "fsync").count(),
        3,
        "{events:?}"
    );
    assert!(first("unlink") < first("fsync"), "{events:?}");
    assert!(
        last("unlink") < last("fsync") && last("rmdir") < last("fsync"),
        "{events:?}"
    );
    // sync after every removal and fsync, verification after the sync, the
    // report last.
    assert_eq!(
        events.iter().filter(|e| *e == "sync").count(),
        1,
        "{events:?}"
    );
    assert!(last("fsync") < first("sync"), "{events:?}");
    assert!(first("sync") < first("verify"), "{events:?}");
    assert_eq!(
        events.last().map(String::as_str),
        Some("report"),
        "{events:?}"
    );
    assert!(!home.join(".fakecli/token").exists() && !home.join(".aws").exists());
}

/// An fsync failure means the removal may not be on the disk: the scrub
/// fails closed (never `verifiedAbsent`), so nothing clears the residue.
#[test]
fn scrub_fails_closed_when_the_removal_cannot_be_made_durable() {
    let dir = Scratch::new();
    let home = dir.path().join("home");
    std::fs::create_dir_all(home.join(".fakecli")).unwrap();
    std::fs::write(home.join(".fakecli/token"), "vault-token").unwrap();
    let control = serde_json::json!({"home": home, "paths": [".fakecli/token"]});
    let out = run(&durability_probe(true), "scrub", &control, b"");
    assert_eq!(out.code, 1, "{}", out.report);
    assert_eq!(out.report["verifiedAbsent"], false);
    let outcome = scrub_outcome(&out.report).unwrap();
    assert!(!outcome.verified_absent);
    assert_eq!(outcome.failed_paths, vec![".fakecli/token".to_owned()]);
}

/// Restore clears the declared paths through the same durable scrub before
/// it writes: a stale file it removes stays removed across a power-off.
#[test]
fn restore_makes_its_clearing_scrub_durable_before_writing() {
    let dir = Scratch::new();
    let home = dir.path().join("home");
    std::fs::create_dir_all(home.join(".fakecli")).unwrap();
    std::fs::write(home.join(".fakecli/stale"), "old").unwrap();
    let control = serde_json::json!({
        "home": home,
        "declared": {"required": [".fakecli"], "optional": [], "exclude": []},
        "entries": [],
    });
    let out = run(&durability_probe(false), "restore", &control, b"");
    assert_eq!(out.code, 0, "{}", out.report);
    let events = events(&out.report);
    let sync = events.iter().position(|e| e == "sync").expect("sync");
    assert!(events[..sync].iter().any(|e| e == "fsync"), "{events:?}");
    assert!(!home.join(".fakecli/stale").exists());
}

#[test]
fn scrub_reports_a_directory_swapped_for_a_link_and_never_follows_it() {
    let dir = Scratch::new();
    let home = dir.path().join("home");
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(home.join(".kube/cache")).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("secret"), "keep").unwrap();
    let setup = format!(
        "def race(where, shown):\n    \
         if where == 'descend' and shown == '.kube/cache':\n        \
         p = {h:?} + '/' + shown\n        os.rmdir(p)\n        os.symlink({o:?}, p)\n\
         ns['_race_window'] = race",
        h = home.to_str().unwrap(),
        o = outside.to_str().unwrap(),
    );
    let control = serde_json::json!({"home": home, "paths": [".kube"]});
    let out = run(&setup, "scrub", &control, b"");
    assert_eq!(out.code, 1, "{}", out.report);
    assert_eq!(out.report["verifiedAbsent"], false);
    let outcome = scrub_outcome(&out.report).unwrap();
    assert!(!outcome.verified_absent);
    assert!(
        outcome.failed_paths.contains(&".kube/cache".to_owned()),
        "{outcome:?}"
    );
    assert_eq!(std::fs::read(outside.join("secret")).unwrap(), b"keep");
}

/// A fake cgroup v2 tree and process table for quiesce (no real cgroup or
/// process is touched). Guest uid 1000 owns 900005 (user.slice) and 900001
/// (root cgroup); root owns 900003 (a service) and 900007 (root cgroup).
/// `TERMABLE` processes exit on SIGTERM; every one dies on SIGKILL.
fn fake_quiesce(root: &Path, termable: &str) -> String {
    format!(
        r#"ROOT = {root:?}
AGENT = 900004
TREE = {{
    "/": [900001, 900007],
    "/init.scope": [900002],
    "/user.slice": [900005],
    "/system.slice": [],
    "/system.slice/incus-agent.service": [AGENT, os.getpid()],
    "/system.slice/other.service": [900003],
}}
GUEST = {{900001, 900005}}
ALIVE = {{900001, 900002, 900003, 900005, 900007}}
TERMABLE = {termable}
SIGNALS = []
for path, pids in TREE.items():
    d = ROOT + ("" if path == "/" else path)
    os.makedirs(d, exist_ok=True)
    with open(d + "/cgroup.procs", "w") as f:
        f.write("".join("%d\n" % p for p in pids))
open(ROOT + "/cgroup.controllers", "w").close()
def procs_files():
    for dirpath, _, files in os.walk(ROOT):
        if "cgroup.procs" in files:
            yield (dirpath[len(ROOT):] or "/"), dirpath + "/cgroup.procs"
def members(file):
    with open(file) as f:
        return f.read().split()
def cgroup_of(pid, tid=None):
    for path, file in procs_files():
        if str(pid) in members(file):
            return path
    raise ProcessLookupError(pid)
real_write = ns["cg_write"]
def cg_write(path, value):
    if not path.endswith("/cgroup.procs"):
        return real_write(path, value)
    for _, file in list(procs_files()):
        kept = [p for p in members(file) if p != value]
        with open(file, "w") as f:
            f.write("".join(p + "\n" for p in kept))
    kept = members(path) if os.path.exists(path) else []
    with open(path, "w") as f:
        f.write("".join(p + "\n" for p in kept + [value]))
def is_frozen(path):
    while path not in ("", "/"):
        try:
            with open(ROOT + path + "/cgroup.freeze") as f:
                if f.read().strip() == "1":
                    return True
        except OSError:
            pass
        path = path.rsplit("/", 1)[0]
    return False
def user_tasks(keep):
    return [(int(p), int(p)) for _, file in procs_files() for p in members(file)
            if int(p) not in keep]
def die(pid):
    ALIVE.discard(pid)
    for _, file in list(procs_files()):
        kept = [p for p in members(file) if p != str(pid)]
        with open(file, "w") as f:
            f.write("".join(p + "\n" for p in kept))
def send(pid, sig):
    if pid not in ALIVE:
        return False
    SIGNALS.append((pid, int(sig)))
    if int(sig) == 9 or pid in TERMABLE:
        die(pid)
    return True
ns.update(CGROUP=ROOT, QUIESCE_TERM_S=0.1, QUIESCE_KILL_S=0.3, QUIESCE_FREEZE_S=0.3,
          exempt_pids=lambda: {{os.getpid(), AGENT}}, cgroup_of=cgroup_of,
          cg_write=cg_write, is_frozen=is_frozen, user_tasks=user_tasks, send=send,
          alive=lambda pid: pid in ALIVE,
          uid_tasks=lambda uid, keep: sorted(p for p in GUEST & ALIVE if p not in keep))
import atexit
atexit.register(lambda: open(ROOT + "/signals.json", "w").write(__import__("json").dumps(SIGNALS)))
"#,
        root = root.to_str().unwrap(),
    )
}

fn signals(cg: &Path) -> Vec<(u64, u64)> {
    serde_json::from_str(&std::fs::read_to_string(cg.join("signals.json")).unwrap()).unwrap()
}

#[test]
fn quiesce_terminates_guest_processes_first_and_skips_the_freezer_when_they_exit() {
    let dir = Scratch::new();
    let cg = dir.path().join("cg");
    let out = run(
        &fake_quiesce(&cg, "{900001, 900005}"),
        "quiesce",
        &serde_json::json!({"uid": 1000}),
        b"",
    );
    assert_eq!(out.code, 0, "{}", out.report);
    let outcome = quiesce_outcome(&out.report).unwrap();
    assert_eq!(
        outcome,
        CredentialQuiesceOutcome {
            terminated: 2,
            killed: 0,
            freezer: false
        }
    );
    assert!(
        !cg.join("init.scope/cgroup.freeze").exists(),
        "nothing frozen"
    );
    assert_eq!(signals(&cg), [(900001, 15), (900005, 15)]);
}

#[test]
fn quiesce_kills_survivors_under_the_freezer_then_thaws_and_returns_held_processes() {
    let dir = Scratch::new();
    let cg = dir.path().join("cg");
    let out = run(
        &fake_quiesce(&cg, "set()"),
        "quiesce",
        &serde_json::json!({"uid": 1000}),
        b"",
    );
    assert_eq!(out.code, 0, "{}", out.report);
    assert_eq!(
        quiesce_outcome(&out.report).unwrap(),
        CredentialQuiesceOutcome {
            terminated: 2,
            killed: 2,
            freezer: true
        }
    );
    // Root processes are never signalled.
    assert!(
        signals(&cg)
            .iter()
            .all(|(pid, _)| *pid == 900001 || *pid == 900005)
    );
    // Every cgroup the freezer froze is thawed again.
    for path in ["init.scope", "user.slice", "system.slice/other.service"] {
        assert_eq!(
            std::fs::read_to_string(cg.join(path).join("cgroup.freeze")).unwrap(),
            "0",
            "{path}"
        );
    }
    let procs = |p: &Path| std::fs::read_to_string(p.join("cgroup.procs")).unwrap();
    // The root task held while frozen is back in its own cgroup and the
    // helper's holding cgroup is empty and thawed.
    assert_eq!(
        procs(&cg).split_whitespace().collect::<Vec<_>>(),
        ["900007"]
    );
    assert_eq!(
        procs(&cg.join("system.slice/other.service")).trim(),
        "900003"
    );
    let hold = std::fs::read_dir(&cg)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("wssp-hold-")
        })
        .expect("hold cgroup");
    assert_eq!(procs(&hold).trim(), "");
    assert_eq!(
        std::fs::read_to_string(hold.join("cgroup.freeze")).unwrap(),
        "0"
    );
}

#[test]
fn quiesce_without_cgroup_v2_scan_kills_and_reports_no_freezer() {
    let dir = Scratch::new();
    let cg = dir.path().join("cg");
    let setup = format!(
        "{}\nos.unlink(ROOT + '/cgroup.controllers')",
        fake_quiesce(&cg, "set()")
    );
    let out = run(&setup, "quiesce", &serde_json::json!({"uid": 1000}), b"");
    assert_eq!(out.code, 0, "{}", out.report);
    let outcome = quiesce_outcome(&out.report).unwrap();
    assert!(!outcome.freezer);
    assert_eq!(outcome.killed, 2);
    let root = run("", "quiesce", &serde_json::json!({"uid": 0}), b"");
    assert_eq!(root.code, 1, "uid 0 is refused");
}

#[test]
fn unknown_modes_and_bad_control_fail_with_a_report() {
    let out = run("", "explode", &serde_json::json!({}), b"");
    assert_eq!(out.code, 1);
    assert_eq!(out.report["ok"], false);
    let out = run(
        "",
        "scrub",
        &serde_json::json!({"home": "/", "paths": ["../etc"]}),
        b"",
    );
    assert_eq!(out.code, 1);
    assert!(
        out.report.to_string().contains("invalid paths"),
        "{}",
        out.report
    );
}

#[test]
fn shared_walk_lives_once_and_credential_scrub_never_resolves_link_targets() {
    let walk = include_str!("incus/dirfd_walk.py");
    let freeze = include_str!("incus/guest_freeze.py");
    assert!(crate::SCRUB_HELPER.contains(walk) && CREDENTIAL_HELPER.contains(walk));
    assert!(!walk.contains("import ") && !freeze.contains("import "));
    assert!(CREDENTIAL_HELPER.starts_with("import "));
    assert!(crate::SCRUB_HELPER.contains(freeze) && CREDENTIAL_HELPER.contains(freeze));
    let own = include_str!("incus/credential-helper.py");
    assert!(!own.contains("realpath") && !own.contains("readlink") && !own.contains("rmtree"));
    assert!(
        !crate::SCRUB_HELPER.contains("\"0\")"),
        "image scrub never thaws"
    );
}

#[test]
fn home_relative_rule_and_debug_redaction() {
    for ok in [".config/gh", "a", "dir with spaces/ü"] {
        assert!(validate_home_relative(ok), "{ok}");
    }
    for bad in [
        "",
        "/etc",
        "a/../b",
        "a//b",
        "./a",
        "a\\b",
        "a:b",
        "a\0b",
        ".wssp/x",
        ".wssp-cred",
    ] {
        assert!(!validate_home_relative(bad), "{bad:?}");
    }
    assert!(!validate_home_relative(&"a".repeat(256)));
    let bytes = CredentialBytes::new(b"super-secret-token".to_vec());
    let shown = format!("{bytes:?}");
    assert!(!shown.contains("super") && shown.contains("18 bytes"));
    let file = CredentialRestoreFile {
        kind: login_definition::BundleFileKind::File,
        path: "a",
        mode: 0o600,
        data: b"super-secret-token",
    };
    assert!(!format!("{file:?}").contains("super"));
}

// ---- FakeRuntime ---------------------------------------------------------

fn guest(home: &Path) -> CredentialGuest {
    CredentialGuest {
        sandbox_id: "sbx-1".into(),
        uid: 1000,
        gid: 1000,
        home: home.to_str().unwrap().into(),
    }
}

fn fake_guest() -> CredentialGuest {
    guest(Path::new("/home/user"))
}

fn paths() -> CredentialPathSet {
    CredentialPathSet {
        required: vec![".config/tool".into()],
        optional: vec![".tool-token".into()],
        exclude: vec![".config/tool/cache".into()],
    }
}

#[test]
fn fake_pack_matches_the_helper_and_decodes() {
    let fake = FakeRuntime::default();
    fake.set_guest_file("sbx-1", ".config/tool/auth.json", b"token-a");
    fake.set_guest_file("sbx-1", ".config/tool/cache/x", b"cached");
    fake.set_guest_file("sbx-1", ".config/tool-other", b"unrelated");
    fake.set_guest_symlink("sbx-1", ".config/tool/link", "/etc/shadow");
    fake.set_guest_fifo("sbx-1", ".config/tool/pipe");
    fake.set_guest_file("sbx-1", ".tool-token", b"token-c");
    let (def, digest) = definition(4096);
    let request = CredentialPackRequest {
        guest: fake_guest(),
        paths: paths(),
        definition_digest: digest,
        max_bytes: 4096,
    };
    let outcome = fake.credential_pack(&request).unwrap();
    assert_eq!((outcome.skipped_links, outcome.skipped_special), (1, 1));
    let bundle = login_definition::decode_bundle(outcome.bundle.as_bytes(), &def, &digest).unwrap();
    let got: Vec<&str> = bundle.files.iter().map(|f| f.path).collect();
    assert_eq!(
        got,
        [".config/tool", ".config/tool/auth.json", ".tool-token"]
    );
    assert_eq!(outcome.file_count, 3);
    let small = CredentialPackRequest {
        max_bytes: 3,
        ..request
    };
    assert!(
        fake.credential_pack(&small).is_err(),
        "maxBytes fails closed"
    );
}

#[test]
fn fake_restore_clears_then_writes_and_scrub_unlinks_links_only() {
    let fake = FakeRuntime::default();
    fake.set_guest_file("sbx-1", ".config/tool/stale", b"old");
    let request = CredentialRestoreRequest {
        guest: fake_guest(),
        declared: paths(),
        files: vec![
            CredentialRestoreFile {
                kind: login_definition::BundleFileKind::Dir,
                path: ".config/tool",
                mode: 0o700,
                data: b"",
            },
            CredentialRestoreFile {
                kind: login_definition::BundleFileKind::File,
                path: ".config/tool/auth.json",
                mode: 0o600,
                data: b"new",
            },
        ],
    };
    let outcome = fake.credential_restore(&request).unwrap();
    assert_eq!(outcome.files_written, 1);
    assert_eq!(fake.guest_file("sbx-1", ".config/tool/stale"), None);
    assert_eq!(
        fake.guest_file("sbx-1", ".config/tool/auth.json").unwrap(),
        b"new"
    );
    // Unsorted or undeclared entries are refused before any effect.
    let mut bad = request.clone();
    bad.files.reverse();
    assert!(fake.credential_restore(&bad).is_err());
    // A symlinked parent is refused.
    fake.set_guest_symlink("sbx-1", ".config", "/tmp");
    assert!(fake.credential_restore(&request).is_err());

    fake.set_guest_file("sbx-1", ".aws/config", b"x");
    fake.set_guest_symlink("sbx-1", ".aws/credentials", "/etc/shadow");
    let scrub = fake
        .credential_scrub(&CredentialScrubRequest {
            guest: fake_guest(),
            paths: vec![".aws".into()],
        })
        .unwrap();
    assert!(scrub.verified_absent);
    assert_eq!((scrub.removed, scrub.links_unlinked), (2, 1));
    assert!(
        fake.guest_paths("sbx-1")
            .iter()
            .all(|p| !p.starts_with(".aws"))
    );
}

#[test]
fn fake_faults_holds_and_call_log() {
    let fake = FakeRuntime::default();
    fake.fail_credential_op("quiesce", 1);
    fake.set_guest_quiesce("sbx-1", 3, 1);
    assert_eq!(
        fake.credential_quiesce(&fake_guest()).unwrap_err().code,
        sandbox_protocol::SandboxErrorCode::GuestOperationFailed
    );
    assert_eq!(
        fake.credential_quiesce(&fake_guest()).unwrap(),
        CredentialQuiesceOutcome {
            terminated: 3,
            killed: 1,
            freezer: true
        }
    );
    assert!(fake.credential_helper_present(&fake_guest()).unwrap());
    fake.set_credential_helper_present(false);
    assert!(!fake.credential_helper_present(&fake_guest()).unwrap());

    // A held scrub blocks until the scoped permit is revoked (stop/kill).
    fake.hold_credential_op("scrub");
    let permit = std::sync::Arc::new(crate::RuntimePermit::default());
    let scoped = fake.with_cancellation(permit.clone());
    let request = CredentialScrubRequest {
        guest: fake_guest(),
        paths: vec![".aws".into()],
    };
    let handle = std::thread::spawn(move || scoped.credential_scrub(&request));
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert!(!handle.is_finished(), "held op must block");
    permit.revoke();
    assert_eq!(
        handle.join().unwrap().unwrap_err().code,
        sandbox_protocol::SandboxErrorCode::Cancelled
    );
    fake.release_credential_op("scrub");
    let ops: Vec<String> = fake.credential_calls().into_iter().map(|c| c.0).collect();
    assert_eq!(ops, ["quiesce", "quiesce", "probe", "probe", "scrub"]);
}
