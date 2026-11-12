//! Retire-helper tests. The helper runs as its exact source in a
//! Python namespace; only the path constants and (except n1) `owner_of`
//! are replaced, from this `#[cfg(test)]` code. The shipped helper has no
//! test env, argv or branch (n2).
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use super::*;
use crate::r#trait::{CommandBirth, GuestIdentity, RetireMode};

const UNIT: &str = "wssp-cmd-op-1-2-3.scope";
const NONCE: &str = "0123456789abcdef0123456789abcdef";
const BOOT: &str = "12345678-1234-4234-8234-123456789abc";

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "wssp-retire-test-{}-{}",
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

/// A fake guest: `cg/` (the cgroup2 hierarchy), `mountinfo`, `run/`,
/// `boot_id` and a fake `systemctl`. Ownership is a table (relative path →
/// uid, default 0) read by the replaced `owner_of`.
struct Guest {
    dir: Scratch,
    owners: Vec<(String, u32)>,
    real_owner_of: bool,
}

impl Guest {
    /// A populated scope `wssp.slice/<UNIT>` and kernel `cgroup.kill`.
    fn new() -> Self {
        let dir = Scratch::new();
        let base = dir.path();
        let scope = base.join("cg/wssp.slice").join(UNIT);
        std::fs::create_dir_all(&scope).unwrap();
        std::fs::create_dir_all(base.join("cg/system.slice/incus-agent.service")).unwrap();
        std::fs::create_dir_all(base.join("run")).unwrap();
        std::fs::write(base.join("cg/wssp.slice/cgroup.kill"), "").unwrap();
        for (name, body) in [
            ("cgroup.events", "populated 1\nfrozen 0\n"),
            ("cgroup.procs", "4242\n"),
            ("cgroup.kill", ""),
        ] {
            std::fs::write(scope.join(name), body).unwrap();
        }
        std::fs::write(
            base.join("cg/system.slice/incus-agent.service/cgroup.events"),
            "populated 1\n",
        )
        .unwrap();
        std::fs::write(
            base.join("mountinfo"),
            format!(
                "25 1 0:22 / /sys rw - sysfs sysfs rw\n\
                 30 25 0:26 / {} rw,nosuid - tmpfs tmpfs rw\n\
                 31 25 0:27 / {} rw,nosuid - cgroup2 cgroup2 rw\n",
                base.join("cg").display(),
                base.join("cg").display()
            ),
        )
        .unwrap();
        std::fs::write(base.join("boot_id"), format!("{BOOT}\n")).unwrap();
        Self {
            dir,
            owners: Vec::new(),
            real_owner_of: false,
        }
    }
    fn base(&self) -> &Path {
        self.dir.path()
    }
    fn path(&self, relative: &str) -> PathBuf {
        self.base().join(relative)
    }
    fn scope(&self, name: &str) -> PathBuf {
        self.path(&format!("cg/wssp.slice/{UNIT}/{name}"))
    }
    fn own(mut self, relative: &str, uid: u32) -> Self {
        self.owners.push((relative.into(), uid));
        self
    }
    fn events(&self, relative: &str, populated: bool) {
        std::fs::write(
            self.path(relative).join("cgroup.events"),
            format!("populated {}\n", u8::from(populated)),
        )
        .unwrap();
    }
    fn cgroup(&self, relative: &str, populated: bool) {
        std::fs::create_dir_all(self.path(relative)).unwrap();
        self.events(relative, populated);
    }
    fn remove_scope(&self) {
        std::fs::remove_dir_all(self.path(&format!("cg/wssp.slice/{UNIT}"))).unwrap();
    }
    fn marker(&self) {
        std::fs::create_dir_all(self.path("run/wssp")).unwrap();
        std::fs::write(self.path("run/wssp/unscoped"), "").unwrap();
    }
    /// A fake `systemctl show` printing `props` (`{elapsed}` becomes the
    /// real CLOCK_MONOTONIC µs minus `elapsed_ms`), exiting `code`.
    fn systemctl(&self, props: &str, elapsed_ms: u64, code: i32) {
        let script = format!(
            "#!/usr/bin/python3 -I\nimport sys, time\n\
             assert sys.argv[1:4] == ['show', '--no-pager', \
             '--property=ActiveState,ControlGroup,ActiveEnterTimestampMonotonic'], sys.argv\n\
             assert sys.argv[4:] == ['--', '{UNIT}'], sys.argv\n\
             now = time.clock_gettime_ns(time.CLOCK_MONOTONIC) // 1000\n\
             sys.stdout.write({props:?}.replace('{{elapsed}}', str(now - {elapsed_ms} * 1000)))\n\
             sys.exit({code})\n"
        );
        let path = self.path("systemctl");
        std::fs::write(&path, script).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    fn active_for(&self, elapsed_ms: u64) {
        self.systemctl(
            &format!(
                "ActiveState=active\nControlGroup=/wssp.slice/{UNIT}\n\
                 ActiveEnterTimestampMonotonic={{elapsed}}\n"
            ),
            elapsed_ms,
            0,
        );
    }

    /// Runs the helper with `args` (after `-c`) and returns (exit, stderr).
    fn run(&self, args: &[&str]) -> (i32, String) {
        let owners: String = self
            .owners
            .iter()
            .map(|(path, uid)| format!("{path:?}: {uid}, "))
            .collect();
        let replace_owner = if self.real_owner_of {
            String::new()
        } else {
            format!(
                "OWNERS = {{{owners}}}\n\
                 real_stat = os.stat\n\
                 def owner_of(dirfd, name):\n\
                 \x20   path = name if dirfd is None else os.path.join(os.readlink('/proc/self/fd/%d' % dirfd), name)\n\
                 \x20   real_stat(path, follow_symlinks=False)\n\
                 \x20   return OWNERS.get(os.path.relpath(path, BASE), 0)\n\
                 ns['owner_of'] = owner_of\n"
            )
        };
        let harness = format!(
            "import os, sys\n\
             ns = {{'__name__': 'retire_helper'}}\n\
             exec(compile(sys.argv[1], 'retire', 'exec'), ns)\n\
             BASE = sys.argv[2]\n\
             ns.update(CGROUP=BASE + '/cg', MOUNTINFO=BASE + '/mountinfo',\n\
             \x20         RUN_DIR=BASE + '/run/wssp', BOOT_ID=BASE + '/boot_id',\n\
             \x20         SYSTEMCTL=BASE + '/systemctl')\n\
             {replace_owner}\
             sys.exit(ns['main'](['-c'] + sys.argv[3:]))\n"
        );
        let out = Command::new("/usr/bin/python3")
            .args(["-I", "-S", "-B", "-c", &harness, RETIRE_HELPER])
            .arg(self.base())
            .args(args)
            .env_clear()
            .output()
            .unwrap();
        assert!(out.stdout.is_empty(), "{out:?}");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8(out.stderr).unwrap(),
        )
    }

    /// The verdict (and remaining ms) of one helper run in `mode`.
    fn verdict(&self, mode: &str, uid: &str, budget: &str) -> String {
        let (code, stderr) = self.run(&[mode, NONCE, uid, UNIT, budget]);
        assert_eq!(code, 0, "{stderr}");
        let record = stderr
            .strip_prefix(&format!("WSSP_RETIRE {NONCE} {BOOT} "))
            .and_then(|rest| rest.strip_suffix('\n'))
            .unwrap_or_else(|| panic!("record: {stderr:?}"));
        record.to_string()
    }
    fn observe(&self) -> String {
        self.verdict("observe", "1000", "0")
    }
}

/// When `cgroup.kill` receives `1`, empties the scope like the kernel.
fn kernel_kills(guest: &Guest) -> std::thread::JoinHandle<bool> {
    let kill = guest.scope("cgroup.kill");
    let events = guest.scope("cgroup.events");
    std::thread::spawn(move || {
        for _ in 0..300 {
            if std::fs::read(&kill).is_ok_and(|bytes| bytes == b"1") {
                std::fs::write(&events, "populated 0\n").unwrap();
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    })
}

#[test]
fn argv_refusals_exit_2_without_a_record() {
    let guest = Guest::new();
    let good = ["observe", NONCE, "1000", UNIT, "0"];
    assert_eq!(guest.run(&good).0, 0);
    for (index, bad) in [
        (0, "kill"),
        (1, "nonce"),
        (1, "0123456789ABCDEF0123456789ABCDEF"),
        (2, "0"),
        (2, "01000"),
        (2, "-1"),
        (2, "4294967295"),
        (3, "wssp-cmd-op.scope"),
        (3, "../wssp-cmd-op-1-2-3.scope"),
        (4, "01"),
        (4, "-5"),
    ] {
        let mut args = good;
        args[index] = bad;
        assert_eq!(guest.run(&args), (2, String::new()), "{index}: {bad}");
    }
    assert_eq!(guest.run(&good[..4]), (2, String::new()));
    let mut extra = good.to_vec();
    extra.push("x");
    assert_eq!(guest.run(&extra), (2, String::new()));
}

#[test]
fn a_populated_scope_is_observed_and_an_empty_one_is_a_proof() {
    let guest = Guest::new();
    assert_eq!(guest.observe(), "populated");
    guest.events(&format!("cg/wssp.slice/{UNIT}"), false);
    assert_eq!(guest.observe(), "empty");
    // Observe never writes `cgroup.kill`.
    assert_eq!(std::fs::read(guest.scope("cgroup.kill")).unwrap(), b"");
}

#[test]
fn a_missing_scope_is_absent_only_without_an_unscoped_launch() {
    // Every ENOENT site: no slice, no scope, no `cgroup.events`.
    for site in ["slice", "scope", "events"] {
        let guest = Guest::new();
        match site {
            "slice" => std::fs::remove_dir_all(guest.path("cg/wssp.slice")).unwrap(),
            "scope" => guest.remove_scope(),
            _ => std::fs::remove_file(guest.scope("cgroup.events")).unwrap(),
        }
        assert_eq!(guest.observe(), "absent", "{site}");
        // A root-owned 0755 `/run/wssp` without a marker is still absent.
        std::fs::create_dir_all(guest.path("run/wssp")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            guest.path("run/wssp"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert_eq!(guest.observe(), "absent", "{site}");
        guest.marker();
        assert_eq!(guest.observe(), "unscoped", "{site}: marker");
    }
}

#[test]
fn a_bad_marker_directory_or_marker_is_unscoped() {
    let missing = |setup: &dyn Fn(&Guest)| {
        let guest = Guest::new();
        guest.remove_scope();
        setup(&guest);
        guest
    };
    use std::os::unix::fs::PermissionsExt;
    // Group- or world-writable (U5).
    for bits in [0o775, 0o757, 0o777] {
        let guest = missing(&|guest| {
            std::fs::create_dir_all(guest.path("run/wssp")).unwrap();
        });
        std::fs::set_permissions(
            guest.path("run/wssp"),
            std::fs::Permissions::from_mode(bits),
        )
        .unwrap();
        assert_eq!(guest.observe(), "unscoped", "{bits:o}");
    }
    // Not root-owned.
    let guest = missing(&|guest| std::fs::create_dir_all(guest.path("run/wssp")).unwrap())
        .own("run/wssp", 1000);
    assert_eq!(guest.observe(), "unscoped");
    // A symlink, or a file, instead of the directory.
    let guest = missing(&|guest| {
        std::fs::create_dir_all(guest.path("elsewhere")).unwrap();
        std::os::unix::fs::symlink(guest.path("elsewhere"), guest.path("run/wssp")).unwrap();
    });
    assert_eq!(guest.observe(), "unscoped");
    let guest = missing(&|guest| std::fs::write(guest.path("run/wssp"), "").unwrap());
    assert_eq!(guest.observe(), "unscoped");
    // The marker as a directory, a symlink or a uid-owned file still counts.
    let guest = missing(&|guest| {
        std::fs::create_dir_all(guest.path("run/wssp/unscoped")).unwrap();
    });
    assert_eq!(guest.observe(), "unscoped");
    let guest = missing(&|guest| {
        std::fs::create_dir_all(guest.path("run/wssp")).unwrap();
        std::os::unix::fs::symlink("/nonexistent", guest.path("run/wssp/unscoped")).unwrap();
    });
    assert_eq!(guest.observe(), "unscoped");
    let guest = missing(&|guest| guest.marker()).own("run/wssp/unscoped", 1000);
    assert_eq!(guest.observe(), "unscoped");
}

#[test]
fn non_root_hierarchy_slice_scope_or_procs_is_unsupported() {
    for path in [
        "cg".to_string(),
        "cg/wssp.slice".to_string(),
        format!("cg/wssp.slice/{UNIT}"),
        format!("cg/wssp.slice/{UNIT}/cgroup.procs"),
    ] {
        let guest = Guest::new().own(&path, 1000);
        assert_eq!(guest.observe(), "unsupported", "{path}");
        guest.events(&format!("cg/wssp.slice/{UNIT}"), false);
        assert_eq!(guest.observe(), "unsupported", "{path}: empty");
    }
}

#[test]
fn a_hierarchy_that_is_not_cgroup2_is_legacy() {
    let guest = Guest::new();
    let cg = guest.path("cg");
    std::fs::write(
        guest.path("mountinfo"),
        format!(
            "31 25 0:27 / {} rw - cgroup2 cgroup2 rw\n32 25 0:28 / {} rw - tmpfs tmpfs rw\n",
            cg.display(),
            cg.display()
        ),
    )
    .unwrap();
    assert_eq!(guest.observe(), "legacy");
    std::fs::write(guest.path("mountinfo"), "").unwrap();
    assert_eq!(guest.observe(), "legacy");
}

#[test]
fn rule_8_counts_uid_roots_after_every_proof() {
    // R1: an empty scope plus a populated uid root (a lingering
    // `user@1000.service`, or a process PID 1 moved there) is never a proof.
    let user = "cg/user.slice/user-1000.slice/user@1000.service";
    let guest = Guest::new().own(user, 1000);
    guest.cgroup(user, true);
    guest.cgroup(&format!("{user}/app.slice/x.service"), true);
    guest.events(&format!("cg/wssp.slice/{UNIT}"), false);
    assert_eq!(guest.observe(), "uid_populated");
    // Not before the proof: a running scope is still just `populated`.
    guest.events(&format!("cg/wssp.slice/{UNIT}"), true);
    assert_eq!(guest.observe(), "populated");
    // And after a kill.
    let kernel = kernel_kills(&guest);
    assert_eq!(guest.verdict("kill-cancel", "1000", "0"), "uid_populated");
    assert!(kernel.join().unwrap());
    // An unpopulated uid root is fine; a root of another uid is not counted.
    guest.events(user, false);
    assert_eq!(guest.observe(), "empty");
    let other = Guest::new().own(user, 2000);
    other.cgroup(user, true);
    other.events(&format!("cg/wssp.slice/{UNIT}"), false);
    assert_eq!(other.observe(), "empty");
    // Two uid roots are unsupported.
    let two = Guest::new()
        .own(user, 1000)
        .own("cg/system.slice/delegated.service", 1000);
    two.cgroup(user, false);
    two.cgroup("cg/system.slice/delegated.service", false);
    two.remove_scope();
    assert_eq!(two.observe(), "unsupported");
    // Pruning: a uid-owned directory inside `wssp.slice` is a root too;
    // its uid-owned children are never counted again.
    let inside = Guest::new()
        .own("cg/wssp.slice/sneaky", 1000)
        .own("cg/wssp.slice/sneaky/child", 1000);
    inside.cgroup("cg/wssp.slice/sneaky/child", false);
    inside.events("cg/wssp.slice/sneaky", true);
    inside.remove_scope();
    assert_eq!(inside.observe(), "uid_populated");
}

#[test]
fn the_walk_is_capped() {
    let guest = Guest::new();
    guest.remove_scope();
    for n in 0..4097 {
        std::fs::create_dir(guest.path(&format!("cg/system.slice/s{n}"))).unwrap();
    }
    assert_eq!(guest.observe(), "unsupported");
}

#[test]
fn kill_modes_kill_only_a_populated_scope_and_wait_for_it_to_empty() {
    let guest = Guest::new();
    let kernel = kernel_kills(&guest);
    assert_eq!(guest.verdict("kill-cancel", "1000", "0"), "killed");
    assert!(kernel.join().unwrap());
    // An empty or missing scope is never written.
    let empty = Guest::new();
    empty.events(&format!("cg/wssp.slice/{UNIT}"), false);
    assert_eq!(empty.verdict("kill-cancel", "1000", "0"), "empty");
    assert_eq!(std::fs::read(empty.scope("cgroup.kill")).unwrap(), b"");
    // A kill that never empties the scope times out (unproven).
    let stuck = Guest::new();
    assert_eq!(stuck.verdict("kill-cancel", "1000", "0"), "timeout");
    // No `cgroup.kill` in the kernel (Linux < 5.14): unsupported, no write.
    let old = Guest::new();
    std::fs::remove_file(old.path("cg/wssp.slice/cgroup.kill")).unwrap();
    assert_eq!(old.verdict("kill-cancel", "1000", "0"), "unsupported");
    assert_eq!(std::fs::read(old.scope("cgroup.kill")).unwrap(), b"");
    // The scope vanished between the read and the kill: the marker test.
    let gone = Guest::new();
    std::fs::remove_file(gone.scope("cgroup.kill")).unwrap();
    assert_eq!(gone.verdict("kill-cancel", "1000", "0"), "absent");
    gone.marker();
    assert_eq!(gone.verdict("kill-cancel", "1000", "0"), "unscoped");
}

#[test]
fn the_deadline_gate_kills_only_a_due_command() {
    // Not due: budget 10 s + 20 s slack, active for 5 s → ~25 s left.
    let guest = Guest::new();
    guest.active_for(5_000);
    let verdict = guest.verdict("kill-deadline", "1000", "10000");
    let remaining: u64 = verdict
        .strip_prefix("not_due ")
        .unwrap_or_else(|| panic!("{verdict}"))
        .parse()
        .unwrap();
    assert!((24_000..=25_000).contains(&remaining), "{remaining}");
    assert_eq!(std::fs::read(guest.scope("cgroup.kill")).unwrap(), b"");
    // Due: active for budget + slack.
    guest.active_for(30_500);
    let kernel = kernel_kills(&guest);
    assert_eq!(guest.verdict("kill-deadline", "1000", "10000"), "killed");
    assert!(kernel.join().unwrap());
    // Budget 0: never due.
    let unbounded = Guest::new();
    unbounded.active_for(10_000_000);
    assert_eq!(unbounded.verdict("kill-deadline", "1000", "0"), "populated");
    // Every gate failure keeps the command running, unsignalled.
    let cg = format!("ControlGroup=/wssp.slice/{UNIT}\n");
    for (props, code) in [
        (
            format!("ActiveState=inactive\n{cg}ActiveEnterTimestampMonotonic={{elapsed}}\n"),
            0,
        ),
        (
            format!("ActiveState=deactivating\n{cg}ActiveEnterTimestampMonotonic={{elapsed}}\n"),
            0,
        ),
        (
            format!("ActiveState=active\n{cg}ActiveEnterTimestampMonotonic=0\n"),
            0,
        ),
        (
            "ActiveState=active\nControlGroup=/system.slice/x.scope\n\
             ActiveEnterTimestampMonotonic={elapsed}\n"
                .to_string(),
            0,
        ),
        (
            format!("ActiveState=active\n{cg}ActiveEnterTimestampMonotonic={{elapsed}}\n"),
            1,
        ),
        (format!("ActiveState=active\n{cg}"), 0),
    ] {
        let guest = Guest::new();
        guest.systemctl(&props, 60_000, code);
        assert_eq!(
            guest.verdict("kill-deadline", "1000", "1000"),
            "populated",
            "{props:?} {code}"
        );
        assert_eq!(std::fs::read(guest.scope("cgroup.kill")).unwrap(), b"");
    }
    // Keys are parsed by name, not line order.
    let reordered = Guest::new();
    reordered.systemctl(
        &format!("ActiveEnterTimestampMonotonic={{elapsed}}\n{cg}ActiveState=active\n"),
        60_000,
        0,
    );
    let kernel = kernel_kills(&reordered);
    assert_eq!(reordered.verdict("kill-deadline", "1000", "1000"), "killed");
    assert!(kernel.join().unwrap());
    // A missing systemctl is a gate failure too.
    let none = Guest::new();
    assert_eq!(none.verdict("kill-deadline", "1000", "1000"), "populated");
}

/// U8: the helper's slack is exactly `HOST_SETUP_BUDGET` + 5 s, the same
/// constant the daemon documents (`RETIRE_DEADLINE_SLACK`).
#[test]
fn the_deadline_slack_tracks_the_host_setup_budget() {
    let slack = super::super::exec::HOST_SETUP_BUDGET + Duration::from_secs(5);
    assert_eq!(slack, crate::RETIRE_DEADLINE_SLACK);
    assert!(RETIRE_HELPER.contains(&format!("DEADLINE_SLACK_US = {}\n", slack.as_micros())));
}

/// The helper never reads `cgroup.procs`, never writes anything but the
/// scope's `cgroup.kill`, never writes the marker and never removes.
#[test]
fn the_helper_writes_only_the_scope_kill_file() {
    let guest = Guest::new();
    let user = "cg/user.slice/user-1000.slice/user@1000.service";
    guest.cgroup(user, false);
    std::fs::write(guest.scope("cgroup.procs"), "").unwrap();
    use std::os::unix::fs::PermissionsExt;
    // Unreadable `cgroup.procs`: reading it would fail the run.
    std::fs::set_permissions(
        guest.scope("cgroup.procs"),
        std::fs::Permissions::from_mode(0o200),
    )
    .unwrap();
    let snapshot = |guest: &Guest| {
        let mut entries = Vec::new();
        let mut stack = vec![guest.base().to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path.clone());
                    entries.push((path, None));
                } else if path.file_name() != Some(std::ffi::OsStr::new("cgroup.procs")) {
                    entries.push((path.clone(), Some(std::fs::read(&path).unwrap())));
                }
            }
        }
        entries.sort();
        entries
    };
    let before = snapshot(&guest);
    let kernel = kernel_kills(&guest);
    assert_eq!(guest.verdict("kill-cancel", "1000", "0"), "killed");
    assert!(kernel.join().unwrap());
    let after = snapshot(&guest);
    let changed: Vec<_> = before
        .iter()
        .zip(&after)
        .filter(|(a, b)| a != b)
        .map(|(a, _)| a.0.clone())
        .collect();
    assert_eq!(before.len(), after.len());
    assert_eq!(
        changed,
        [guest.scope("cgroup.events"), guest.scope("cgroup.kill")]
    );
    assert!(!guest.path("run/wssp").exists(), "never writes the marker");
    // Source: no rmdir/unlink, no pid signals, `cgroup.procs` only as an
    // ownership target.
    for banned in ["rmdir", "unlink", "os.kill", "killpg", "remove(", "pidfd"] {
        assert!(!RETIRE_HELPER.contains(banned), "{banned}");
    }
}

/// n1: with the real `owner_of`, a tree owned by the test uid is
/// `unsupported` on every proof path (absent, empty, killed).
#[test]
fn n1_release_owner_of_on_a_non_root_tree_proves_nothing() {
    for setup in ["absent", "empty", "kill"] {
        let mut guest = Guest::new();
        guest.real_owner_of = true;
        match setup {
            "absent" => guest.remove_scope(),
            "empty" => guest.events(&format!("cg/wssp.slice/{UNIT}"), false),
            _ => {}
        }
        let mode = if setup == "kill" {
            "kill-cancel"
        } else {
            "observe"
        };
        assert_eq!(guest.verdict(mode, "1000", "0"), "unsupported", "{setup}");
        assert_eq!(
            std::fs::read(guest.scope_or_empty()).unwrap_or_default(),
            b""
        );
    }
}

impl Guest {
    fn scope_or_empty(&self) -> PathBuf {
        self.scope("cgroup.kill")
    }
}

/// n2: the shipped source has no test seam beyond module constants and
/// `owner_of`: no environment, no extra argv, no test names, and
/// `ROOT_UID` stays 0.
#[test]
fn n2_the_helper_source_has_no_bypass() {
    for banned in [
        "environ",
        "getenv",
        "WSSP_",
        "TEST",
        "test",
        "fake",
        "mock",
        "sys.argv[",
    ] {
        let hits: Vec<_> = RETIRE_HELPER
            .lines()
            .filter(|line| line.contains(banned) && !line.trim_start().starts_with('#'))
            .filter(|line| !(banned == "WSSP_" && line.contains("'WSSP_RETIRE %s %s %s'")))
            .filter(|line| {
                !(banned == "WSSP_"
                    && line.trim() == "WSSP_RETIRE <nonce> <boot-id> <verdict> [<remaining-ms>]")
            })
            .collect();
        assert!(hits.is_empty(), "{banned}: {hits:?}");
    }
    assert_eq!(RETIRE_HELPER.matches("ROOT_UID = ").count(), 1);
    assert!(RETIRE_HELPER.contains("\nROOT_UID = 0\n"));
    assert_eq!(RETIRE_HELPER.matches("sys.argv").count(), 1);
    assert!(RETIRE_HELPER.contains("sys.exit(main(sys.argv))"));
    // Every ownership read goes through `owner_of`.
    assert_eq!(RETIRE_HELPER.matches(".st_uid").count(), 1);
}

fn request(mode: RetireMode, budget_ms: u64) -> crate::RetireCommandRequest {
    crate::RetireCommandRequest {
        template_fingerprint: "f".repeat(64),
        guest: GuestIdentity::default(),
        sandbox_id: "sbx-1".into(),
        instance_name: "wssp-sbx-sbx-1".into(),
        operation_id: "op-1".into(),
        birth: CommandBirth {
            pid: 42,
            boot_id: BOOT.into(),
            start_ticks: 7,
            started_at_ms: 0,
        },
        generation: 2,
        attempt: 3,
        uid: Some(1000),
        budget_ms,
        mode,
        host_proof_only: false,
        qemu: None,
    }
}

/// n3: the argv carries only the documented, host-derived fields.
#[test]
fn n3_the_helper_argv_has_only_documented_fields() {
    for (mode, arg) in [
        (RetireMode::Observe, "observe"),
        (RetireMode::KillCancel, "kill-cancel"),
        (RetireMode::KillDeadline, "kill-deadline"),
    ] {
        let argv = retire_helper_argv(&request(mode, 5000), 1000, NONCE).unwrap();
        assert_eq!(
            argv,
            [
                "python3",
                "-I",
                "-S",
                "-B",
                "-c",
                RETIRE_HELPER,
                arg,
                NONCE,
                "1000",
                UNIT,
                "5000"
            ]
        );
    }
    assert!(retire_helper_argv(&request(RetireMode::Observe, 0), 0, NONCE).is_err());
    let mut bad = request(RetireMode::Observe, 0);
    bad.operation_id = "../x".into();
    assert!(retire_helper_argv(&bad, 1000, NONCE).is_err());
}

#[test]
fn records_parse_strictly() {
    let out = |stdout: &str, stderr: &str, exit_code| IncusCommandOutput {
        stdout: stdout.into(),
        stderr: stderr.into(),
        exit_code,
    };
    let ok = |verdict: &str| out("", &format!("WSSP_RETIRE {NONCE} {BOOT} {verdict}\n"), 0);
    for (text, verdict) in [
        ("absent", RetireVerdict::Absent),
        ("empty", RetireVerdict::Empty),
        ("killed", RetireVerdict::Killed),
        ("populated", RetireVerdict::Populated),
        ("not_due 1500", RetireVerdict::NotDue(1500)),
        ("unscoped", RetireVerdict::Unscoped),
        ("legacy", RetireVerdict::Legacy),
        ("unsupported", RetireVerdict::Unsupported),
        ("uid_populated", RetireVerdict::UidPopulated),
        ("timeout", RetireVerdict::Timeout),
    ] {
        assert_eq!(
            parse_retire_record(NONCE, &ok(text)),
            Some(RetireRecord {
                boot_id: BOOT.into(),
                verdict
            }),
            "{text}"
        );
    }
    for bad in [
        out("x", &format!("WSSP_RETIRE {NONCE} {BOOT} absent\n"), 0),
        out("", &format!("WSSP_RETIRE {NONCE} {BOOT} absent\n"), 1),
        out("", &format!("WSSP_RETIRE {NONCE} {BOOT} absent"), 0),
        out("", &format!("WSSP_RETIRE {NONCE} {BOOT} absent 5\n"), 0),
        out("", &format!("WSSP_RETIRE {NONCE} {BOOT} not_due\n"), 0),
        out("", &format!("WSSP_RETIRE {NONCE} {BOOT} not_due 01\n"), 0),
        out("", &format!("WSSP_RETIRE {NONCE} {BOOT} gone\n"), 0),
        out("", &format!("WSSP_RETIRE {NONCE} not-a-boot absent\n"), 0),
        out(
            "",
            &format!("WSSP_RETIRE {} {BOOT} absent\n", "f".repeat(32)),
            0,
        ),
        out("", &format!("x\nWSSP_RETIRE {NONCE} {BOOT} absent\n"), 0),
        out(
            "",
            &format!("WSSP_RETIRE {NONCE} {BOOT} absent\nWSSP_RETIRE {NONCE} {BOOT} absent\n"),
            0,
        ),
    ] {
        assert_eq!(parse_retire_record(NONCE, &bad), None, "{bad:?}");
    }
    // The shipped helper's own record parses.
    let guest = Guest::new();
    let (code, stderr) = guest.run(&["observe", NONCE, "1000", UNIT, "0"]);
    assert_eq!(
        parse_retire_record(NONCE, &out("", &stderr, code)).map(|r| r.verdict),
        Some(RetireVerdict::Populated)
    );
}

/// The real cgroup2 tests: a private cgroup2 hierarchy in a delegated
/// systemd user scope (harness A, `capture.rs`), with `--map-auto` for a
/// mapped non-root uid (harness B). They fail with a precondition message
/// when the environment is missing; CI lists them as ignored.
mod real {
    use super::*;

    /// Runs `script` in the namespace (as mapped root, cgroup2 at
    /// /sys/fs/cgroup, a private tmpfs /run) with the helper source in
    /// `$HELPER` and the harness in `$HARNESS`.
    fn namespace(map_auto: bool, script: &str, env: &[(&str, &str)]) -> std::process::Output {
        let mut command = Command::new("systemd-run");
        command.args([
            "--user",
            "--scope",
            "--quiet",
            "-p",
            "Delegate=yes",
            "-p",
            "TasksMax=512",
            "unshare",
            "--user",
        ]);
        if map_auto {
            command.args(["--map-root-user", "--map-auto"]);
        } else {
            command.arg("--map-root-user");
        }
        command
            // No PID namespace: `unshare` execs the shell, so the delegated
            // scope holds no outside process and its root can enable `pids`.
            .args(["--mount", "--net", "--cgroup", "sh", "-c"])
            .arg(format!(
                "set -e\n\
                 mount -t tmpfs none /sys/fs/cgroup && mount -t cgroup2 none /sys/fs/cgroup || exit 97\n\
                 mount -t tmpfs none /run || exit 97\n\
                 mkdir /sys/fs/cgroup/init && echo $$ > /sys/fs/cgroup/init/cgroup.procs\n\
                 echo '+pids' > /sys/fs/cgroup/cgroup.subtree_control || exit 98\n\
                 cleanup() {{ for k in $(find /sys/fs/cgroup -mindepth 2 -name cgroup.kill \
                 ! -path '/sys/fs/cgroup/init/*'); do echo 1 > \"$k\" 2>/dev/null || true; done; }}\n\
                 trap cleanup EXIT\n\
                 {script}"
            ))
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HELPER", RETIRE_HELPER)
            .env("HARNESS", REAL_HARNESS)
            .envs(env.iter().copied())
            .stdin(std::process::Stdio::null());
        for name in ["XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        command.output().expect("systemd-run")
    }

    /// The exact helper with the real `owner_of`; only `RUN_DIR` and
    /// `BOOT_ID` stay at their shipped paths (inside the namespace).
    const REAL_HARNESS: &str = "import os, sys\n\
         ns = {'__name__': 'retire_helper'}\n\
         exec(compile(os.environ.pop('HELPER'), 'retire', 'exec'), ns)\n\
         sys.exit(ns['main'](['-c'] + sys.argv[1:]))\n";

    fn precondition(map_auto: bool) {
        let mut missing = Vec::new();
        for tool in ["systemd-run", "unshare", "setpriv", "newuidmap"] {
            if Command::new("sh")
                .args(["-c", &format!("command -v {tool}")])
                .output()
                .map_or(true, |out| !out.status.success())
            {
                missing.push(tool.to_string());
            }
        }
        if map_auto && !Path::new("/etc/subuid").exists() {
            missing.push("/etc/subuid".into());
        }
        assert!(missing.is_empty(), "precondition: missing {missing:?}");
        let probe = namespace(map_auto, "echo ok", &[]);
        assert!(
            probe.status.success() && probe.stdout == b"ok\n",
            "precondition: delegated cgroup2 user namespace unavailable ({:?}): {}",
            probe.status.code(),
            String::from_utf8_lossy(&probe.stderr)
        );
    }

    /// Prelude: the attempt's scope `wssp.slice/<UNIT>` (as root) and a
    /// `retire MODE UID BUDGET` shell function printing the verdict.
    fn prelude() -> String {
        format!(
            "S=/sys/fs/cgroup/wssp.slice/{UNIT}\n\
             mkdir -p $S\n\
             echo +pids > /sys/fs/cgroup/wssp.slice/cgroup.subtree_control\n\
             retire() {{ python3 -I -S -B -c \"$HARNESS\" \"$1\" {NONCE} \"$2\" {UNIT} \"$3\" 2>&1 \
             | sed -n 's/^WSSP_RETIRE {NONCE} [0-9a-f-]* //p'; }}\n\
             in_scope() {{ sh -c \"echo \\$\\$ > $S/cgroup.procs; exec $1\" & }}\n"
        )
    }

    fn run(map_auto: bool, body: &str, env: &[(&str, &str)]) -> String {
        precondition(map_auto);
        let out = namespace(map_auto, &format!("{}{body}", prelude()), env);
        assert!(
            out.status.success(),
            "{:?}\nstdout: {}\nstderr: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    /// (a) a fork bomb capped by `pids.max`, (b) double-fork + `setsid`
    /// descendants, killed as one scope; (e) sibling and non-command
    /// cgroups survive.
    #[test]
    #[ignore = "needs delegated cgroup2 userns; run --ignored command_scope_real"]
    fn command_scope_real_kill_takes_the_whole_scope_and_nothing_else() {
        let out = run(
            false,
            "echo 64 > $S/pids.max\n\
             in_scope \"sh -c 'while :; do sleep 100 & done'\"\n\
             in_scope \"sh -c '(setsid sh -c \\\"(sleep 100 &) ; sleep 100\\\" &) ; sleep 100'\"\n\
             mkdir /sys/fs/cgroup/wssp.slice/wssp-cmd-other-1-1.scope\n\
             sh -c 'echo $$ > /sys/fs/cgroup/wssp.slice/wssp-cmd-other-1-1.scope/cgroup.procs; exec sleep 100' &\n\
             SIB=$!\n\
             mkdir /sys/fs/cgroup/other\n\
             sh -c 'echo $$ > /sys/fs/cgroup/other/cgroup.procs; exec sleep 100' &\n\
             OTHER=$!\n\
             sleep 0.5\n\
             [ \"$(cat $S/pids.current)\" -le 64 ] || { echo pids-cap-failed; exit 1; }\n\
             grep -q '^populated 1' $S/cgroup.events\n\
             echo observe=$(retire observe 1000 0)\n\
             echo kill=$(retire kill-cancel 1000 0)\n\
             grep -q '^populated 0' $S/cgroup.events && echo scope-empty\n\
             kill -0 $SIB && echo sibling-alive\n\
             kill -0 $OTHER && echo other-alive\n\
             rmdir $S\n\
             echo after=$(retire observe 1000 0)\n\
             kill $SIB $OTHER\n",
            &[],
        );
        assert_eq!(
            out,
            "observe=populated\nkill=killed\nscope-empty\nsibling-alive\nother-alive\nafter=absent\n"
        );
    }

    /// (c) observe, then the command exits, then `absent`/`empty`.
    #[test]
    #[ignore = "needs delegated cgroup2 userns; run --ignored command_scope_real"]
    fn command_scope_real_observe_then_exit_is_a_proof() {
        let out = run(
            false,
            "in_scope 'sleep 0.5'\n\
             sleep 0.1\n\
             echo running=$(retire observe 1000 0)\n\
             wait\n\
             echo exited=$(retire observe 1000 0)\n\
             rmdir $S\n\
             echo collected=$(retire observe 1000 0)\n\
             mkdir -p /run/wssp && : > /run/wssp/unscoped\n\
             echo marker=$(retire observe 1000 0)\n",
            &[],
        );
        assert_eq!(
            out,
            "running=populated\nexited=empty\ncollected=absent\nmarker=unscoped\n"
        );
    }

    /// (d) a mapped non-root uid cannot write itself out of the scope into a
    /// sibling or the root `cgroup.procs` (EACCES; errno checked in
    /// Python), and the kill still takes it. (f) a populated cgroup root of
    /// that uid is `uid_populated`; two roots are `unsupported`. (g) that
    /// uid can neither create nor unlink in a root-owned 0755 marker dir.
    #[test]
    #[ignore = "needs delegated cgroup2 userns; run --ignored command_scope_real"]
    fn command_scope_real_mapped_uid_cannot_escape_or_touch_the_marker() {
        const ESCAPE: &str = r#"import errno, os, time
for path in ('/sys/fs/cgroup/sibling/cgroup.procs', '/sys/fs/cgroup/cgroup.procs'):
    try:
        with open(path, 'w') as procs:
            procs.write(str(os.getpid()))
        print('escaped', flush=True)
    except OSError as error:
        print(errno.errorcode[error.errno], flush=True)
time.sleep(100)
"#;
        const MARKER: &str = r#"import errno, os
for op in (lambda: os.unlink('/run/wssp/unscoped'), lambda: open('/run/wssp/x', 'w')):
    try:
        op()
        print('wrote')
    except OSError as error:
        print(errno.errorcode[error.errno])
"#;
        let out = run(
            true,
            "AS_UID='setpriv --reuid 1000 --regid 1000 --clear-groups'\n\
             mkdir /sys/fs/cgroup/sibling\n\
             sh -c \"echo \\$\\$ > $S/cgroup.procs; exec $AS_UID python3 -I -c \\\"\\$ESCAPE\\\"\" &\n\
             sleep 0.5\n\
             echo kill=$(retire kill-cancel 1000 0)\n\
             mkdir /sys/fs/cgroup/user1000\n\
             chown 1000:1000 /sys/fs/cgroup/user1000 /sys/fs/cgroup/user1000/cgroup.procs\n\
             sh -c 'echo $$ > /sys/fs/cgroup/user1000/cgroup.procs; exec sleep 100' &\n\
             ROOT=$!\n\
             sleep 0.2\n\
             echo root=$(retire observe 1000 0)\n\
             mkdir /sys/fs/cgroup/user1000b\n\
             chown 1000:1000 /sys/fs/cgroup/user1000b\n\
             echo two=$(retire observe 1000 0)\n\
             kill $ROOT\n\
             mkdir -p /run/wssp && chmod 0755 /run/wssp && : > /run/wssp/unscoped\n\
             $AS_UID python3 -I -c \"$MARKER\"\n",
            &[("ESCAPE", ESCAPE), ("MARKER", MARKER)],
        );
        assert_eq!(
            out,
            "EACCES\nEACCES\nkill=killed\nroot=uid_populated\ntwo=unsupported\nEACCES\nEACCES\n",
            "{out}"
        );
    }
}
