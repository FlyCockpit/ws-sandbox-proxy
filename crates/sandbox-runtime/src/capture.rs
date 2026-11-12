//! Snapshot-to-template request and outcome types, the shared scrub manifest
//! and the fixed guest helpers (freeze and scrub). Both helpers are fixed
//! programs: request paths reach them only as validated argv, never as code.

use serde::Deserialize;

/// `packages/config/src/template-capture-scrub.json`, shared with the
/// dashboard's "what is scrubbed" list (TS parity test).
pub const CAPTURE_SCRUB_MANIFEST_JSON: &str =
    include_str!("../../../packages/config/src/template-capture-scrub.json");

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScrubManifest {
    pub version: u32,
    pub home_relative: Vec<String>,
    pub absolute: Vec<String>,
    pub truncate: Vec<String>,
    pub homes: Vec<String>,
}

pub fn scrub_manifest() -> Result<ScrubManifest, crate::RuntimeError> {
    serde_json::from_str(CAPTURE_SCRUB_MANIFEST_JSON).map_err(|_| {
        crate::RuntimeError::new(
            sandbox_protocol::SandboxErrorCode::Internal,
            "capture scrub manifest is invalid",
        )
    })
}

/// Every path the scrub removes (built-ins for `guest_home` plus extras).
pub fn scrub_paths(
    manifest: &ScrubManifest,
    guest_home: &str,
    extra: &[String],
) -> (Vec<String>, Vec<String>) {
    let mut delete = Vec::new();
    let mut homes: Vec<String> = manifest.homes.clone();
    homes.push(guest_home.trim_end_matches('/').to_owned());
    homes.sort();
    homes.dedup();
    for home in &homes {
        for rel in &manifest.home_relative {
            delete.push(format!("{home}/{rel}"));
        }
    }
    delete.extend(manifest.absolute.iter().cloned());
    delete.extend(
        extra
            .iter()
            .filter(|p| sandbox_protocol::valid_scrub_path(p))
            .cloned(),
    );
    delete.sort();
    delete.dedup();
    (delete, manifest.truncate.clone())
}

/// Separator between the image-scrub paths and the credential paths in the
/// scrub helper's argv. Never a valid path (every path is absolute).
pub const CREDENTIAL_SCRUB_SEPARATOR: &str = "--credential";

/// The credential scrub list of a template capture:
/// home-relative login paths, resolved against `guest_home`. They are never
/// filtered: any invalid entry fails the capture, so a login file the
/// server or the host journal names can never reach a template unscrubbed.
pub fn credential_scrub_targets(
    guest_home: &str,
    rel_paths: &[String],
) -> Result<Vec<String>, crate::RuntimeError> {
    let home = guest_home.trim_end_matches('/');
    let home_ok = guest_home.starts_with('/')
        && !home.is_empty()
        && !guest_home.contains('\0')
        && !home.split('/').any(|s| s == "." || s == "..");
    if !home_ok
        || !rel_paths
            .iter()
            .all(|p| sandbox_protocol::valid_credential_path(p))
    {
        return Err(crate::RuntimeError::new(
            sandbox_protocol::SandboxErrorCode::CaptureFailed,
            "invalid credential scrub path",
        ));
    }
    let staging_pattern = format!(".wssp-cred-{}", "[0-9a-f]".repeat(16));
    let mut out = Vec::new();
    for path in rel_paths {
        // Validation reserves the staging prefix at every depth, so declared
        // filenames cannot collide with the generated staging pattern.
        out.push(format!("{home}/{path}"));
        let parent = path.rsplit_once('/').map(|(parent, _)| parent);
        let parent = parent
            .map(|p| format!("{home}/{p}"))
            .unwrap_or_else(|| home.to_owned());
        // A crashed credential restore can leave its exclusive staging file
        // beside any declared path. Match exactly eight random bytes in hex.
        out.push(format!("{parent}/{staging_pattern}"));
    }
    out.sort();
    out.dedup();
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureRequest {
    pub sandbox_id: String,
    pub operation_id: String,
    /// STOPPED at acceptance: no freeze, no snapshot; copy the root directly.
    pub stopped: bool,
    pub guest_home: String,
    pub extra_scrub_paths: Vec<String>,
    /// Home-relative login paths (the capture spec's residue ∪ the host's
    /// credential journal). Scrubbed frozen, links unlinked and never
    /// followed, absence verified; see [`credential_scrub_targets`].
    pub credential_scrub_paths: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapturePhase {
    Freezing,
    Snapshotting,
    Copying,
    Scrubbing,
    Publishing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureOutcome {
    pub fingerprint: String,
    pub size_bytes: u64,
    pub architecture: String,
    /// Scrubbed paths that were symlinks (link and target both removed).
    pub symlinked_paths: Vec<String>,
}

/// Capture VM / snapshot names for one operation (never `wssp-sbx-`, so the
/// storage census ignores them).
pub fn capture_names(operation_id: &str) -> Result<(String, String), crate::RuntimeError> {
    let short: String = operation_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(24)
        .collect::<String>()
        .to_ascii_lowercase();
    if short.is_empty() {
        return Err(crate::RuntimeError::new(
            sandbox_protocol::SandboxErrorCode::ProtocolError,
            "invalid capture operation id",
        ));
    }
    Ok((format!("wssp-cap-{short}"), format!("wssp-cap-{short}")))
}

/// Guest freeze helper, run as `python3 -I -B -c <this>` (M10): every import
/// happens before FIFREEZE; it prints `frozen`, then thaws on `thaw`, EOF or
/// after 15 s. An already-frozen `/` (EBUSY, e.g. the Incus agent froze it)
/// prints `busy` and never thaws what it did not freeze.
pub const FREEZE_HELPER: &str = r#"import errno, fcntl, os, select, sys
FIFREEZE = 0xC0045877
FITHAW = 0xC0045878
fd = os.open("/", os.O_RDONLY)
os.sync()
try:
    fcntl.ioctl(fd, FIFREEZE, 0)
except OSError as e:
    if e.errno == errno.EBUSY:
        print("busy", flush=True)
        sys.exit(0)
    print("error", flush=True)
    sys.exit(3)
print("frozen", flush=True)
try:
    ready, _, _ = select.select([sys.stdin], [], [], 15)
    if ready:
        sys.stdin.readline()
finally:
    fcntl.ioctl(fd, FITHAW, 0)
    print("thawed", flush=True)
"#;

/// Guest scrub helper, `python3 -I -S -B -c <this> <mode> <truncate-count>
/// <truncate...> <paths...> [--credential <login paths...>]`, run as root
/// inside the disposable capture VM. It is one import line (every module,
/// first) followed by
/// the shared descriptor-relative walk (`incus/dirfd_walk.py`), the shared
/// guest freezer (`incus/guest_freeze.py`) and the scrub itself; neither
/// shared file imports anything.
///
/// `freeze` mode (the only mode the runtime uses) first proves the capture
/// VM has no network device besides `lo`, then freezes every guest task with
/// the cgroup v2 freezer, PID 1 and `init.scope` included: the helper moves
/// itself (and only itself) into a dedicated cgroup, writes `1` to
/// `cgroup.freeze` of every other subtree except the path from the root to
/// the Incus agent's cgroup (the agent carries this helper's output), moves
/// any other process found in that running path (the root cgroup, the
/// agent's cgroup) into a frozen holding cgroup, and waits for `frozen 1` in
/// `cgroup.events`. A frozen task cannot run, so no signal (a `SIGCONT` from
/// PID 1 included) resumes it. The scrub, `sync` and the final verification
/// (every user task still frozen, nothing beside the helper in its cgroup,
/// every scrubbed path absent, every truncated file empty) all run frozen,
/// in that order. The helper never thaws: the runtime force-stops the VM
/// afterwards. No cgroup v2, a cgroup that cannot be created or frozen, a
/// helper that cannot be isolated, or a task that does not freeze fails the
/// capture.
///
/// Once the freeze begins the helper executes nothing from the guest:
/// no subprocess, no shell, and no import (every module is imported at start-up). It never runs `cloud-init clean`, which executes the guest's
/// `/etc/cloud/clean.d/` hooks as root outside the freeze; the manifest
/// instead removes what `cloud-init clean --logs --seed` removed
/// (`/var/lib/cloud/*`, seed included, and the cloud-init logs, rotated ones
/// too), so those paths are scrubbed and verified like any other.
/// `in-place` skips the freeze (tests only).
///
/// Traversal is descriptor-relative: every directory is opened one component
/// at a time with `O_NOFOLLOW | O_DIRECTORY` (`dir_fd`), its `fstat` must
/// match the entry seen before opening, and every unlink/rmdir re-checks the
/// entry's device, inode and type first. A replacement is reported and fails
/// the capture instead of being followed. A symlink found at a scrubbed path,
/// or anywhere below a scrubbed directory, is removed together with the
/// target it resolves to (never `rmtree`); system roots and virtual
/// filesystems are never removed through a link; cycles terminate. A link to
/// a truncate target (Ubuntu's `/var/lib/dbus/machine-id` →
/// `/etc/machine-id`) is unlinked and its target kept: every truncate target
/// ends present and empty (created 0444 when missing), so systemd generates
/// a fresh machine id on first boot. `*`
/// matches within the last segment only (dotfiles included).
///
/// Login paths after `--credential` are literal, except the fixed
/// credential restore-staging pattern, and
/// scrubbed with the credential helper's rule instead: a link at or below
/// one is unlinked and its target is never touched, and a path whose parent
/// runs through a link is skipped (no login file can be there). They are
/// scrubbed and verified absent while frozen, like every other path. Prints one JSON
/// line `{"symlinked": [...], "errors": [...], "frozen": n, "held": n}` and
/// exits 1 when anything could not be scrubbed or verified, so the capture
/// fails instead of publishing.
///
/// Residual: the helper runs on the guest image's own kernel, Incus agent
/// and `python3` interpreter (with its standard library), which stay
/// trusted. `-I -S` keeps every other guest-writable import path out: no
/// `PYTHON*` environment, no script or working directory, no user or system
/// `site-packages`, `.pth` files or `sitecustomize`. It protects against
/// concurrent guest workloads (PID 1 included), not against a guest image
/// whose kernel, agent or interpreter were themselves modified to lie.
pub const SCRUB_HELPER: &str = concat!(
    "import errno, fnmatch, json, os, stat, sys, time\n",
    include_str!("incus/dirfd_walk.py"),
    include_str!("incus/guest_freeze.py"),
    r#"PROTECTED = {"/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib32", "/lib64",
             "/libx32", "/media", "/mnt", "/opt", "/proc", "/root", "/run", "/sbin",
             "/srv", "/sys", "/tmp", "/usr", "/var"}
VIRTUAL = ("/proc/", "/sys/", "/dev/", "/run/")
linked = []
seen_targets = set()
seen_dirs = set()
# Truncate targets: kept present and emptied, never removed through a link
# (Ubuntu's /var/lib/dbus/machine-id links to /etc/machine-id).
truncated = set()
def network_detached():
    try:
        with open("/proc/self/net/dev") as f:
            lines = f.read().splitlines()[2:]
    except OSError:
        return False
    names = [line.split(":", 1)[0].strip() for line in lines if ":" in line]
    return all(name == "lo" for name in names)
def remove_at(dfd, dpath, name, follow=True):
    shown = dpath.rstrip("/") + "/" + name
    try:
        st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as e:
        fail(shown, e.strerror or "lstat")
        return
    if stat.S_ISLNK(st.st_mode):
        try:
            raw = os.readlink(name, dir_fd=dfd)
        except OSError as e:
            fail(shown, e.strerror or "readlink")
            return
        target = os.path.realpath(os.path.join(dpath, raw))
        checked_remove(dfd, name, st, shown, False)
        if not follow:
            # Credential paths: the link is unlinked, its target never touched.
            return
        linked.append(shown)
        if target in truncated:
            return
        if target in seen_targets:
            return
        seen_targets.add(target)
        if target in PROTECTED or target.startswith(VIRTUAL):
            fail(shown, "link target is protected: " + target)
            return
        remove_path(target)
    elif stat.S_ISDIR(st.st_mode):
        _race_window("descend", shown)
        try:
            cfd = os.open(name, O_DIR, dir_fd=dfd)
        except OSError as e:
            fail(shown, "replaced during scrub" if e.errno in (errno.ELOOP, errno.ENOTDIR) else (e.strerror or "open"))
            return
        try:
            cst = os.fstat(cfd)
            if not same(cst, st):
                fail(shown, "replaced during scrub")
                return
            if (cst.st_dev, cst.st_ino) in seen_dirs:
                return
            seen_dirs.add((cst.st_dev, cst.st_ino))
            with os.scandir(cfd) as it:
                children = [entry.name for entry in it]
            for child in children:
                remove_at(cfd, shown, child, follow)
        finally:
            os.close(cfd)
        checked_remove(dfd, name, st, shown, True)
    else:
        checked_remove(dfd, name, st, shown, False)
def remove_path(path):
    head, tail = os.path.split(path)
    if not tail:
        return
    parent = os.path.realpath(head)
    try:
        pfd = open_dir(parent)
    except FileNotFoundError:
        return
    except OSError as e:
        fail(path, e.strerror or "open")
        return
    try:
        remove_at(pfd, parent, tail)
    finally:
        os.close(pfd)
def expand(pattern):
    head, tail = os.path.split(pattern)
    if "*" in head:
        return []
    if "*" not in tail:
        return [pattern]
    parent = os.path.realpath(head)
    try:
        pfd = open_dir(parent)
    except OSError:
        return []
    try:
        with os.scandir(pfd) as it:
            names = sorted(entry.name for entry in it)
    finally:
        os.close(pfd)
    return [parent.rstrip("/") + "/" + n for n in names if fnmatch.fnmatchcase(n, tail)]
def present(path):
    head, tail = os.path.split(path)
    try:
        pfd = open_dir(os.path.realpath(head))
    except OSError:
        return False
    try:
        os.stat(tail, dir_fd=pfd, follow_symlinks=False)
        return True
    except OSError:
        return False
    finally:
        os.close(pfd)
def emptied(path):
    """None when `path` is an empty regular file (no link followed), else the
    problem: a truncated file must stay present (an absent /etc/machine-id is
    never regenerated, an empty one is, on first boot)."""
    head, tail = os.path.split(path)
    try:
        pfd = open_dir(os.path.realpath(head))
    except FileNotFoundError:
        return "missing after scrub"
    except OSError:
        return "not empty after scrub"
    try:
        st = os.stat(tail, dir_fd=pfd, follow_symlinks=False)
    except FileNotFoundError:
        return "missing after scrub"
    except OSError:
        return "not empty after scrub"
    finally:
        os.close(pfd)
    if stat.S_ISREG(st.st_mode) and st.st_size == 0:
        return None
    return "not empty after scrub"
def truncate_at(path):
    """Empty `path` in place, creating it (0444, as systemd ships it) when it
    is missing. Never follows a link at `path`."""
    head, tail = os.path.split(path)
    try:
        pfd = open_dir(os.path.realpath(head))
    except FileNotFoundError:
        return
    except OSError as e:
        fail(path, e.strerror or "open")
        return
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(tail, flags, 0o444, dir_fd=pfd)
        os.close(fd)
    except OSError as e:
        fail(path, e.strerror or "truncate")
    finally:
        os.close(pfd)
def scrub(paths, truncate):
    """Remove and truncate; returns every path that must stay absent."""
    seen_targets.clear()
    seen_dirs.clear()
    truncated.clear()
    truncated.update(truncate)
    truncated.update(os.path.realpath(p) for p in truncate)
    removed = []
    for pattern in paths:
        for p in expand(pattern):
            remove_path(p)
            removed.append(p)
    for p in truncate:
        truncate_at(p)
    return [p for p in removed + sorted(seen_targets)
            if p not in PROTECTED and not p.startswith(VIRTUAL)]
def cred_parent(path):
    """fd of the directory holding a credential path, opened without ever
    following a link; None when it is missing or runs through a link (no
    login file can be at the declared location then)."""
    head = os.path.dirname(path)
    try:
        return open_dir(head)
    except FileNotFoundError:
        return None
    except OSError as e:
        if e.errno in (errno.ELOOP, errno.ENOTDIR):
            return None
        fail(path, e.strerror or "open")
        return None
CRED_STAGING_PATTERN = ".wssp-cred-" + "[0-9a-f]" * 16
def cred_names(pfd, path):
    name = os.path.basename(path)
    if name != CRED_STAGING_PATTERN:
        return [name]
    with os.scandir(pfd) as it:
        return sorted(e.name for e in it if fnmatch.fnmatchcase(e.name, name))
def cred_present(path):
    pfd = cred_parent(path)
    if pfd is None:
        return False
    try:
        for name in cred_names(pfd, path):
            try:
                os.stat(name, dir_fd=pfd, follow_symlinks=False)
                return True
            except FileNotFoundError:
                pass
        return False
    except OSError:
        return False
    finally:
        os.close(pfd)
def scrub_credentials(paths):
    """Literal login paths and the exact restore-staging pattern: every link
    unlinked and never followed. Returns the paths that must stay absent."""
    seen_dirs.clear()
    for p in paths:
        pfd = cred_parent(p)
        if pfd is None:
            continue
        try:
            for name in cred_names(pfd, p):
                remove_at(pfd, os.path.dirname(p), name, False)
            # Durable before the sync and the final check.
            try:
                os.fsync(pfd)
            except OSError as e:
                fail(p, "fsync failed: %s" % (e.strerror or "fsync"))
        finally:
            os.close(pfd)
    return list(paths)
def main(argv):
    mode = argv[1]
    n = int(argv[2])
    truncate = argv[3:3 + n]
    paths = argv[3 + n:]
    credentials = []
    if "--credential" in paths:
        cut = paths.index("--credential")
        paths, credentials = paths[:cut], paths[cut + 1:]
    if mode not in ("freeze", "in-place"):
        fail("<mode>", "unknown mode")
    elif mode == "freeze":
        if not network_detached():
            fail("<network>", "a network device is attached")
        else:
            freeze_guest()
    if not errors:
        absent = scrub(paths, truncate)
        cred_absent = scrub_credentials(credentials)
        if not errors:
            # Still frozen: flush, then verify last, so nothing that ran
            # before the verification can undo what it proves. Nothing from
            # the guest is executed (no shell, no tool whose hooks, such as
            # /etc/cloud/clean.d/, are guest code): the manifest resets the
            # cloud init state through the scrub itself.
            os.sync()
            if mode == "freeze":
                for problem in frozen_problems():
                    fail("<freeze>", problem)
            for p in absent:
                if present(p):
                    fail(p, "present after scrub")
            for p in truncate:
                problem = emptied(p)
                if problem:
                    fail(p, problem)
            for p in cred_absent:
                if cred_present(p):
                    fail(p, "present after scrub")
    print(json.dumps({"symlinked": sorted(set(linked)), "errors": errors,
                      "frozen": len(frozen_roots), "held": len(held)}))
    return 1 if errors else 0
if __name__ == "__main__":
    sys.exit(main(sys.argv))
"#
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed_child::ManagedChild;

    #[test]
    fn manifest_parses_and_covers_the_scrub_requirements() {
        let manifest = scrub_manifest().expect("manifest");
        assert_eq!(manifest.version, 1);
        for required in [
            "/var/log/journal",
            "/swap.img",
            "/etc/ssh/ssh_host_*",
            // What `cloud-init clean --logs --seed` removed.
            "/var/lib/cloud/*",
            "/var/log/cloud-init.log*",
            "/var/log/cloud-init-output.log*",
            // Guest sudo: the daemon's drop-in and its temp
            // file never travel in a capture (absent guest tampering).
            "/etc/sudoers.d/wssp-guest",
            "/etc/.wssp-sudoers.tmp",
        ] {
            assert!(
                manifest.absolute.iter().any(|p| p == required),
                "{required}"
            );
        }
        let (delete, truncate) = scrub_paths(
            &manifest,
            "/home/user",
            &["/home/user/secret.txt".into(), "../etc".into()],
        );
        assert!(delete.contains(&"/home/user/.bash_history".to_owned()));
        assert!(delete.contains(&"/root/.bash_history".to_owned()));
        assert!(delete.contains(&"/home/user/secret.txt".to_owned()));
        assert!(!delete.iter().any(|p| p.contains("..")));
        assert_eq!(truncate, vec!["/etc/machine-id".to_owned()]);
        assert!(
            delete.iter().all(|p| sandbox_protocol::valid_scrub_path(p)),
            "{delete:?}"
        );
    }

    /// Runs the real helper on a scratch tree (never `/`) without the
    /// freeze (which would freeze the test host's processes); PATH is empty.
    fn run_scrub(paths: &[&std::path::Path]) -> (i32, serde_json::Value) {
        let mut command = std::process::Command::new("/usr/bin/python3");
        command
            .args(["-I", "-S", "-B", "-c", SCRUB_HELPER, "in-place", "0"])
            .args(paths)
            .env_clear()
            .env("PATH", "");
        let out = command.output().expect("python3");
        let json = serde_json::from_slice(&out.stdout).expect("helper JSON");
        (out.status.code().unwrap_or(-1), json)
    }

    /// Loads the helper as a module (`ns`), runs `setup` (Python with `ns`
    /// in scope, to replace seams), then `main` with `args`.
    fn run_helper(setup: &str, args: &[&str]) -> (i32, serde_json::Value) {
        run_helper_with_path(setup, args, "")
    }

    /// `run_helper` with `PATH` set to `path` (a scratch bin directory that
    /// plants guest binaries the helper must never execute).
    fn run_helper_with_path(setup: &str, args: &[&str], path: &str) -> (i32, serde_json::Value) {
        let harness = format!(
            "import os, sys\nns = {{'__name__': 'scrub_helper'}}\n\
             exec(compile(sys.argv[1], 'scrub', 'exec'), ns)\n{setup}\n\
             sys.exit(ns['main'](['scrub'] + sys.argv[2:]))\n"
        );
        let out = std::process::Command::new("/usr/bin/python3")
            .args(["-I", "-S", "-B", "-c", &harness, SCRUB_HELPER])
            .args(args)
            .env_clear()
            .env("PATH", path)
            .output()
            .expect("python3");
        let json = serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|_| panic!("helper JSON: {}", String::from_utf8_lossy(&out.stderr)));
        (out.status.code().unwrap_or(-1), json)
    }

    /// Replaces the helper's `_race_window` seam with `hook` (Python source
    /// defining `race(where, shown)`), so a test can change the tree at the
    /// exact point between check and act.
    fn run_scrub_raced(hook: &str, args: &[&str]) -> (i32, serde_json::Value) {
        run_helper(&format!("{hook}\nns['_race_window'] = race"), args)
    }

    /// An entry replaced between its check and its removal
    /// (a file swapped for a link to a credential, a directory swapped for a
    /// link) is detected, reported and fails the capture; the link is never
    /// followed and the credential target survives untouched.
    #[test]
    fn scrub_detects_replacement_between_check_and_act_and_fails() {
        let dir = Scratch::new();
        let home = dir.path().join("home");
        let data = dir.path().join("data");
        std::fs::create_dir_all(home.join(".aws")).unwrap();
        std::fs::create_dir_all(home.join(".kube/cache")).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(home.join(".aws/credentials"), "old").unwrap();
        std::fs::write(data.join("secret"), "credential").unwrap();
        let target = data.join("secret");
        let hook = format!(
            "done = []\ndef race(where, shown):\n    \
             if where == 'remove' and shown.endswith('/credentials') and not done:\n        \
             done.append(1)\n        os.unlink(shown)\n        os.symlink({target:?}, shown)\n    \
             if where == 'descend' and shown.endswith('/.kube/cache') and len(done) < 2:\n        \
             done.append(2)\n        os.rmdir(shown)\n        os.symlink({data:?}, shown)\n",
            target = target.to_str().unwrap(),
            data = data.to_str().unwrap(),
        );
        let aws = home.join(".aws");
        let kube = home.join(".kube");
        let (code, report) = run_scrub_raced(
            &hook,
            &[
                "in-place",
                "0",
                aws.to_str().unwrap(),
                kube.to_str().unwrap(),
            ],
        );
        assert_eq!(code, 1, "{report}");
        let errors = report["errors"].as_array().unwrap();
        let replaced: Vec<&str> = errors
            .iter()
            .filter(|e| e["error"] == "replaced during scrub")
            .filter_map(|e| e["path"].as_str())
            .collect();
        assert!(
            replaced.iter().any(|p| p.ends_with(".aws/credentials")),
            "{report}"
        );
        assert!(
            replaced.iter().any(|p| p.ends_with(".kube/cache")),
            "{report}"
        );
        assert_eq!(
            std::fs::read_to_string(data.join("secret")).unwrap(),
            "credential",
            "the swapped-in link was never followed"
        );
    }

    /// A fake cgroup v2 tree under `root` for the freeze sequence (no real
    /// cgroups touched): `cgroup.procs` moves emulate migration, and a
    /// cgroup is frozen when it or an ancestor has `cgroup.freeze` = 1,
    /// except `stuck`, which never freezes. The helper starts in the agent's
    /// `incus-agent.service` cgroup; 900001 sits in the root cgroup, 900002
    /// is PID 1's `init.scope`, 900004 is the exempt agent.
    fn fake_cgroupfs(root: &std::path::Path, stuck: &str) -> String {
        format!(
            r#"ROOT = {root:?}
STUCK = {stuck:?}
AGENT = 900004
TREE = {{
    "/": [900001],
    "/init.scope": [900002],
    "/user.slice": [],
    "/user.slice/user-1000.slice": [900005],
    "/system.slice": [],
    "/system.slice/incus-agent.service": [AGENT, os.getpid()],
    "/system.slice/other.service": [900003],
}}
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
    if path == STUCK:
        return False
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
ns.update(CGROUP=ROOT, FREEZE_DEADLINE_S=0.3, network_detached=lambda: True,
          exempt_pids=lambda: {{os.getpid(), AGENT}}, cgroup_of=cgroup_of,
          cg_write=cg_write, is_frozen=is_frozen, user_tasks=user_tasks)
"#,
            root = root.to_str().unwrap(),
        )
    }

    fn errors_of(report: &serde_json::Value) -> Vec<String> {
        report["errors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                format!(
                    "{}: {}",
                    e["path"].as_str().unwrap(),
                    e["error"].as_str().unwrap()
                )
            })
            .collect()
    }

    /// The freeze sequence. The helper isolates itself, freezes
    /// every subtree off the agent's path (PID 1's `init.scope` included),
    /// moves a process found in the running root cgroup into the frozen
    /// holding cgroup, leaves the agent running, and only then scrubs.
    #[test]
    fn freeze_isolates_the_helper_and_freezes_every_other_subtree() {
        let dir = Scratch::new();
        let cg = dir.path().join("cg");
        let secret = dir.path().join("credentials");
        std::fs::write(&secret, "secret").unwrap();
        let (code, report) = run_helper(
            &fake_cgroupfs(&cg, ""),
            &["freeze", "0", secret.to_str().unwrap()],
        );
        assert_eq!(code, 0, "{report}");
        assert!(!secret.exists());
        let freeze = |path: &str| std::fs::read_to_string(cg.join(path).join("cgroup.freeze")).ok();
        for frozen in ["init.scope", "user.slice", "system.slice/other.service"] {
            assert_eq!(freeze(frozen).as_deref(), Some("1"), "{frozen}");
        }
        // The agent's path keeps running; nothing below the root is frozen whole.
        for running in ["system.slice", "system.slice/incus-agent.service"] {
            assert_eq!(freeze(running), None, "{running}");
        }
        let procs = |path: &std::path::Path| -> Vec<String> {
            std::fs::read_to_string(path.join("cgroup.procs"))
                .unwrap()
                .split_whitespace()
                .map(str::to_owned)
                .collect()
        };
        assert_eq!(
            procs(&cg.join("system.slice/incus-agent.service")),
            ["900004"]
        );
        let named = |prefix: &str| {
            std::fs::read_dir(&cg)
                .unwrap()
                .flatten()
                .map(|e| e.path())
                .find(|p| p.file_name().unwrap().to_str().unwrap().starts_with(prefix))
                .unwrap_or_else(|| panic!("{prefix} cgroup"))
        };
        assert_eq!(procs(&named("wssp-hold-")), ["900001"]);
        assert_eq!(
            freeze(named("wssp-hold-").to_str().unwrap()).as_deref(),
            Some("1")
        );
        assert_eq!(procs(&named("wssp-scrub-")).len(), 1, "only the helper");
        assert_eq!(report["held"], 1, "{report}");
    }

    /// A subtree that never reports `frozen 1` (here PID 1's
    /// `init.scope`) fails the capture before anything is scrubbed.
    #[test]
    fn freeze_fails_closed_when_a_subtree_never_freezes() {
        let dir = Scratch::new();
        let cg = dir.path().join("cg");
        let secret = dir.path().join("credentials");
        std::fs::write(&secret, "secret").unwrap();
        let (code, report) = run_helper(
            &fake_cgroupfs(&cg, "/init.scope"),
            &["freeze", "0", secret.to_str().unwrap()],
        );
        assert_eq!(code, 1, "{report}");
        let errors = errors_of(&report);
        assert!(
            errors.contains(&"<freeze>: cgroup /init.scope did not freeze".to_owned()),
            "{errors:?}"
        );
        assert!(
            errors.contains(&"<freeze>: process 900002 is not frozen".to_owned()),
            "{errors:?}"
        );
        assert!(secret.exists(), "nothing is scrubbed without the freeze");
    }

    /// The final verification runs after the scrub and sync:
    /// a task left running beside the helper fails the capture.
    #[test]
    fn freeze_final_verification_fails_on_a_task_beside_the_helper() {
        let dir = Scratch::new();
        let cg = dir.path().join("cg");
        let secret = dir.path().join("credentials");
        std::fs::write(&secret, "secret").unwrap();
        let setup = format!(
            "{}\nreal_scrub = ns['scrub']\n\
             def scrub(paths, truncate):\n    \
                 found = real_scrub(paths, truncate)\n    \
                 with open(ns['cgdir'](ns['cg_state']['helper']) + '/cgroup.procs', 'a') as f:\n        \
                     f.write('900099\\n')\n    \
                 return found\n\
             ns['scrub'] = scrub",
            fake_cgroupfs(&cg, "")
        );
        let (code, report) = run_helper(&setup, &["freeze", "0", secret.to_str().unwrap()]);
        assert_eq!(code, 1, "{report}");
        assert!(
            errors_of(&report)
                .contains(&"<freeze>: process 900099 runs beside the scrub helper".to_owned()),
            "{report}"
        );
    }

    /// Once the freeze has begun the helper executes nothing
    /// from the guest. A planted `cloud-init` (standing in for `cloud-init
    /// clean` running guest-supplied `/etc/cloud/clean.d/` hooks as root,
    /// outside the freeze) runs its hook, which recreates the scrubbed
    /// credential; the helper must never run it, and must reset the
    /// cloud-init state itself through the scrub (and the final check).
    #[test]
    fn freeze_never_executes_guest_cloud_init_clean_hooks() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = Scratch::new();
        let cg = dir.path().join("cg");
        let aws = dir.path().join("home/.aws");
        std::fs::create_dir_all(&aws).unwrap();
        std::fs::write(aws.join("credentials"), "secret").unwrap();
        let cloud = dir.path().join("var/lib/cloud");
        std::fs::create_dir_all(cloud.join("instances/iid-1")).unwrap();
        std::fs::create_dir_all(cloud.join("seed/nocloud")).unwrap();
        std::fs::write(cloud.join("seed/nocloud/user-data"), "#cloud-config").unwrap();
        let clean_d = dir.path().join("etc/cloud/clean.d");
        std::fs::create_dir_all(&clean_d).unwrap();
        let ran = dir.path().join("hook-ran");
        let hook = clean_d.join("10-restore");
        std::fs::write(
            &hook,
            format!(
                "#!/bin/sh\n/bin/mkdir -p '{aws}'\necho secret > '{aws}/credentials'\n: > '{ran}'\n",
                aws = aws.display(),
                ran = ran.display()
            ),
        )
        .unwrap();
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let cloud_init = bin.join("cloud-init");
        std::fs::write(
            &cloud_init,
            format!(
                "#!/bin/sh\nfor hook in '{clean_d}'/*; do \"$hook\"; done\n",
                clean_d = clean_d.display()
            ),
        )
        .unwrap();
        for file in [&hook, &cloud_init] {
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let state = format!("{}/*", cloud.display());
        let (code, report) = run_helper_with_path(
            &fake_cgroupfs(&cg, ""),
            &["freeze", "0", aws.to_str().unwrap(), &state],
            bin.to_str().unwrap(),
        );
        assert!(!ran.exists(), "a guest clean.d hook ran during the scrub");
        assert!(!aws.exists(), "the hook recreated the scrubbed credential");
        assert_eq!(code, 0, "{report}");
        assert_eq!(
            std::fs::read_dir(&cloud).unwrap().count(),
            0,
            "cloud-init instance state and seed are reset"
        );
    }

    /// The final check re-verifies the truncated files too: one
    /// left non-empty fails the capture.
    #[test]
    fn final_check_fails_on_a_truncated_file_that_is_not_empty() {
        let dir = Scratch::new();
        let machine_id = dir.path().join("machine-id");
        std::fs::write(&machine_id, "0123456789abcdef").unwrap();
        let (code, report) = run_helper(
            "ns['truncate_at'] = lambda path: None",
            &["in-place", "1", machine_id.to_str().unwrap()],
        );
        assert_eq!(code, 1, "{report}");
        assert_eq!(
            errors_of(&report),
            [format!("{}: not empty after scrub", machine_id.display())]
        );
        let (code, report) = run_helper("", &["in-place", "1", machine_id.to_str().unwrap()]);
        assert_eq!(code, 0, "{report}");
        assert_eq!(std::fs::read(&machine_id).unwrap().len(), 0);
    }

    /// Ubuntu's `/var/lib/dbus/machine-id` links to
    /// `/etc/machine-id`. Scrubbing the link must not delete the truncate
    /// target: it stays present and empty (systemd regenerates an empty one
    /// on first boot, never a missing one), and a missing one is created.
    #[test]
    fn a_link_to_machine_id_is_unlinked_and_machine_id_stays_present_and_empty() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = Scratch::new();
        let etc = dir.path().join("etc");
        let dbus = dir.path().join("var/lib/dbus");
        std::fs::create_dir_all(&etc).unwrap();
        std::fs::create_dir_all(&dbus).unwrap();
        let machine_id = etc.join("machine-id");
        std::fs::write(&machine_id, "87621c89aaaaaaaaaaaaaaaaaaaaaaaa\n").unwrap();
        let link = dbus.join("machine-id");
        symlink(&machine_id, &link).unwrap();
        let (code, report) = run_helper(
            "",
            &[
                "in-place",
                "1",
                machine_id.to_str().unwrap(),
                link.to_str().unwrap(),
            ],
        );
        assert_eq!(code, 0, "{report}");
        assert!(
            std::fs::symlink_metadata(&link).is_err(),
            "the link is gone"
        );
        let meta = std::fs::symlink_metadata(&machine_id).expect("machine-id kept");
        assert!(meta.file_type().is_file());
        assert_eq!(meta.len(), 0);
        // A missing machine-id is created empty (0444), not left absent.
        std::fs::remove_file(&machine_id).unwrap();
        let (code, report) = run_helper("", &["in-place", "1", machine_id.to_str().unwrap()]);
        assert_eq!(code, 0, "{report}");
        let meta = std::fs::metadata(&machine_id).expect("machine-id created");
        assert_eq!(meta.len(), 0);
        assert_eq!(meta.permissions().mode() & 0o777, 0o444);
        // The final check refuses an absent truncate target.
        std::fs::remove_file(&machine_id).unwrap();
        let (code, report) = run_helper(
            "ns['truncate_at'] = lambda path: None",
            &["in-place", "1", machine_id.to_str().unwrap()],
        );
        assert_eq!(code, 1, "{report}");
        assert_eq!(
            errors_of(&report),
            [format!("{}: missing after scrub", machine_id.display())]
        );
    }

    /// No cgroup v2 freezer, or a helper that cannot be moved
    /// into its own cgroup, fails the capture before anything is scrubbed.
    #[test]
    fn freeze_fails_closed_without_cgroup_v2_or_isolation() {
        let dir = Scratch::new();
        let secret = dir.path().join("credentials");
        std::fs::write(&secret, "secret").unwrap();
        let empty = dir.path().join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        let (code, report) = run_helper(
            &format!(
                "ns.update(CGROUP={:?}, network_detached=lambda: True)",
                empty.to_str().unwrap()
            ),
            &["freeze", "0", secret.to_str().unwrap()],
        );
        assert_eq!(code, 1, "{report}");
        assert_eq!(
            errors_of(&report),
            ["<freeze>: cgroup v2 freezer unavailable"]
        );
        assert!(secret.exists());
        // The move into the helper's cgroup does not take effect.
        let cg = dir.path().join("cg");
        let setup = format!(
            "{}\nns['cgroup_of'] = lambda pid, tid=None: '/system.slice/incus-agent.service'",
            fake_cgroupfs(&cg, "")
        );
        let (code, report) = run_helper(&setup, &["freeze", "0", secret.to_str().unwrap()]);
        assert_eq!(code, 1, "{report}");
        assert_eq!(
            errors_of(&report),
            ["<freeze>: cannot isolate the scrub helper"]
        );
        assert!(secret.exists());
    }

    /// `unshare` in a delegated systemd user scope with a private cgroup2
    /// mount at `/sys/fs/cgroup` (exit 97 when that mount is refused).
    fn delegated_namespace(script: &str) -> std::process::Command {
        let mut command = std::process::Command::new("systemd-run");
        command
            .args([
                "--user",
                "--scope",
                "--quiet",
                "-p",
                "Delegate=yes",
                "unshare",
                "--user",
                "--map-root-user",
                "--pid",
                "--fork",
                "--kill-child",
                "--mount",
                "--mount-proc",
                "--net",
                "--cgroup",
                "sh",
                "-c",
            ])
            .arg(format!(
                "mount -t tmpfs none /sys/fs/cgroup && mount -t cgroup2 none /sys/fs/cgroup || exit 97\n{script}"
            ))
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(std::process::Stdio::null());
        // Only the user manager's address is passed through, never printed.
        for name in ["XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        command
    }

    fn delegated_freezer_available() -> bool {
        delegated_namespace(
            "mkdir /sys/fs/cgroup/probe && echo 1 > /sys/fs/cgroup/probe/cgroup.freeze \
             && grep -qx 'frozen 1' /sys/fs/cgroup/probe/cgroup.events && rmdir /sys/fs/cgroup/probe",
        )
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
    }

    /// On a real kernel freezer, PID 1
    /// keeps sending `SIGCONT` to every process, through the scrub and the
    /// window after the final check, while a writer in a service-like cgroup
    /// recreates a credential and keeps escaping into the root cgroup. The
    /// helper freezes PID 1 and the writer, scrubs, verifies, and the
    /// credential stays gone. Runs in a private user+PID+net+cgroup namespace
    /// inside a delegated systemd user scope; skipped where unavailable.
    #[test]
    fn freeze_holds_against_pid1_sigcont_and_escaping_writers() {
        if !delegated_freezer_available() {
            eprintln!("skipped: delegated cgroup v2 freezer in a user namespace unavailable");
            return;
        }
        use std::io::BufRead as _;
        let dir = Scratch::new();
        let aws = dir.path().join("home/.aws");
        std::fs::create_dir_all(&aws).unwrap();
        let writer = format!(
            "while true; do echo $$ > /sys/fs/cgroup/cgroup.procs 2>/dev/null; \
             mkdir -p '{aws}'; echo secret > '{aws}/credentials'; done",
            aws = aws.display()
        );
        // PID 1: a service-like cgroup for the writer, the helper as its own
        // child, then SIGCONT to everything, forever (it never reaps).
        let script = format!(
            "mkdir /sys/fs/cgroup/workload.service || exit 98\n\
             sh -c \"$WRITER\" &\n\
             echo $! > /sys/fs/cgroup/workload.service/cgroup.procs\n\
             sleep 0.3\n\
             /usr/bin/python3 -I -B -c \"$HELPER\" freeze 0 '{aws}' &\n\
             while :; do kill -s CONT -- -1 2>/dev/null; done",
            aws = aws.display()
        );
        let mut command = delegated_namespace(&script);
        command
            .env("WRITER", &writer)
            .env("HELPER", SCRUB_HELPER)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null());
        // Owned in its own process group: a panic still kills `unshare`,
        // and with it PID 1 and the whole namespace.
        let mut child = ManagedChild::spawn(&mut command).expect("systemd-run");
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout)
                .lines()
                .map_while(Result::ok)
            {
                if line.starts_with('{') {
                    let _ = tx.send(line);
                    return;
                }
            }
        });
        let line = rx.recv_timeout(std::time::Duration::from_secs(90));
        // Well after the helper's last check: a resumed writer would be back.
        std::thread::sleep(std::time::Duration::from_millis(700));
        let reappeared = aws.exists();
        // `unshare --fork` ignores SIGTERM: dropping the guard SIGKILLs it,
        // which kills PID 1 and the whole namespace (frozen tasks die too);
        // the scope is removed.
        drop(child);
        let line = line.expect("helper report");
        let report: serde_json::Value = serde_json::from_str(&line).expect("helper JSON");
        assert_eq!(report["errors"], serde_json::json!([]), "{report}");
        assert!(report["frozen"].as_u64().unwrap_or(0) >= 1, "{report}");
        assert!(
            report["held"].as_u64().unwrap_or(0) >= 1,
            "PID 1 held: {report}"
        );
        assert!(!reappeared, "a resumed writer recreated the scrubbed path");
    }

    /// A scratch directory removed on drop (the crate has no tempfile dep).
    struct Scratch(std::path::PathBuf);
    impl Scratch {
        fn new() -> Self {
            static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "wssp-scrub-test-{}-{}",
                std::process::id(),
                N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A link nested anywhere under a scrubbed directory has its target
    /// scrubbed too; link cycles terminate; everything removed is reported.
    #[test]
    fn scrub_follows_nested_links_to_their_targets_with_cycle_protection() {
        use std::os::unix::fs::symlink;
        let dir = Scratch::new();
        let home = dir.path().join("home");
        let data = dir.path().join("data");
        std::fs::create_dir_all(home.join(".aws/nested")).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(data.join("credentials"), "secret").unwrap();
        std::fs::write(data.join("token"), "secret").unwrap();
        std::fs::write(data.join("keep"), "public").unwrap();
        symlink(data.join("credentials"), home.join(".aws/credentials")).unwrap();
        symlink(data.join("token"), home.join(".aws/nested/token")).unwrap();
        // Cycles back to the scrubbed directory and to itself.
        symlink(home.join(".aws"), home.join(".aws/nested/loop")).unwrap();
        symlink(home.join(".aws/nested/self"), home.join(".aws/nested/self")).unwrap();
        let (code, report) = run_scrub(&[&home.join(".aws")]);
        assert_eq!(code, 0, "{report}");
        assert!(!home.join(".aws").exists());
        assert!(
            !data.join("credentials").exists(),
            "nested link target survived"
        );
        assert!(
            !data.join("token").exists(),
            "doubly nested link target survived"
        );
        assert!(data.join("keep").exists(), "unrelated file removed");
        let linked: Vec<String> = serde_json::from_value(report["symlinked"].clone()).unwrap();
        assert!(
            linked.iter().any(|p| p.ends_with(".aws/credentials")),
            "{linked:?}"
        );
        assert!(
            linked.iter().any(|p| p.ends_with("nested/token")),
            "{linked:?}"
        );
        assert_eq!(report["errors"], serde_json::json!([]));
    }

    /// A link into a system root is never followed: the capture fails
    /// (exit 1, reported) instead of deleting `/usr` or publishing silently.
    #[test]
    fn scrub_refuses_links_into_system_roots_and_fails_the_capture() {
        use std::os::unix::fs::symlink;
        let dir = Scratch::new();
        let cache = dir.path().join("cache");
        std::fs::create_dir_all(&cache).unwrap();
        symlink("/usr", cache.join("usr")).unwrap();
        symlink("/proc/self/environ", cache.join("environ")).unwrap();
        let (code, report) = run_scrub(&[&cache]);
        assert_eq!(code, 1, "{report}");
        assert!(std::path::Path::new("/usr/bin").exists());
        let errors = report["errors"].as_array().unwrap();
        assert_eq!(
            errors.len(),
            2,
            "both protected targets are reported: {report}"
        );
        assert!(
            !cache.join("usr").exists(),
            "the link itself is still removed"
        );
    }

    /// Login paths after `--credential` are
    /// removed with the credential helper's rule — a link at or below one is
    /// unlinked and its target survives; a parent that runs through a link is
    /// skipped; everything else is removed and verified absent.
    #[test]
    fn credential_paths_are_scrubbed_without_ever_following_a_link() {
        use std::os::unix::fs::symlink;
        let dir = Scratch::new();
        let home = dir.path().join("home");
        let data = dir.path().join("data");
        std::fs::create_dir_all(home.join(".config/tool/nested")).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(home.join(".config/tool/hosts.yml"), "token").unwrap();
        std::fs::write(data.join("target"), "not ours").unwrap();
        std::fs::write(data.join("nested-target"), "not ours").unwrap();
        // The declared file itself is a link, and a link sits inside the dir.
        symlink(data.join("target"), home.join(".netrc")).unwrap();
        symlink(
            data.join("nested-target"),
            home.join(".config/tool/nested/link"),
        )
        .unwrap();
        // A declared path whose parent is a link: never followed.
        std::fs::create_dir_all(data.join("aws")).unwrap();
        std::fs::write(data.join("aws/credentials"), "elsewhere").unwrap();
        symlink(data.join("aws"), home.join(".aws")).unwrap();
        let tool = home.join(".config/tool");
        let netrc = home.join(".netrc");
        let aws = home.join(".aws/credentials");
        let (code, report) = run_helper(
            "",
            &[
                "in-place",
                "0",
                CREDENTIAL_SCRUB_SEPARATOR,
                tool.to_str().unwrap(),
                netrc.to_str().unwrap(),
                aws.to_str().unwrap(),
            ],
        );
        assert_eq!(code, 0, "{report}");
        assert!(!tool.exists() && std::fs::symlink_metadata(&netrc).is_err());
        assert!(data.join("target").exists(), "a link target was removed");
        assert!(
            data.join("nested-target").exists(),
            "a nested link target was removed"
        );
        assert!(
            data.join("aws/credentials").exists(),
            "a parent link was followed"
        );
        assert!(
            home.join(".aws").exists(),
            "the parent link is not ours to remove"
        );
        // Credential links are never reported as followed.
        assert_eq!(report["symlinked"], serde_json::json!([]));
        assert_eq!(report["errors"], serde_json::json!([]));
    }

    /// The capture VM is powered off by force after the scrub, so
    /// a login file's removal must be durable before the final check:
    /// remove → parent fsync → sync → verify absent → report.
    #[test]
    fn credential_paths_are_durable_before_the_final_check() {
        let dir = Scratch::new();
        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join(".fakecli")).unwrap();
        std::fs::write(home.join(".fakecli/token"), "vault-token").unwrap();
        let token = home.join(".fakecli/token");
        let setup = "events = []\n\
             real = {n: getattr(os, n) for n in ('unlink', 'fsync', 'sync')}\n\
             def rec(n):\n    \
                 def f(*a, **k):\n        \
                     events.append(n)\n        \
                     return real[n](*a, **k)\n    \
                 return f\n\
             for n in real:\n    setattr(os, n, rec(n))\n\
             real_present = ns['cred_present']\n\
             def cred_present(p):\n    events.append('verify')\n    return real_present(p)\n\
             ns['cred_present'] = cred_present\n\
             def report(text):\n    \
                 out = ns['json'].loads(text)\n    \
                 out['events'] = events + ['report']\n    \
                 sys.stdout.write(ns['json'].dumps(out))\n\
             ns['print'] = report";
        let (code, report) = run_helper(
            setup,
            &[
                "in-place",
                "0",
                CREDENTIAL_SCRUB_SEPARATOR,
                token.to_str().unwrap(),
            ],
        );
        assert_eq!(code, 0, "{report}");
        let events: Vec<String> = serde_json::from_value(report["events"].clone()).unwrap();
        assert_eq!(
            events,
            ["unlink", "fsync", "sync", "verify", "report"],
            "{report}"
        );
        assert!(!token.exists());
    }

    /// Login paths and image paths share one run; a login path that cannot
    /// be removed fails the capture (exit 1, reported), never publishes.
    #[test]
    fn credential_paths_join_the_image_scrub_and_fail_closed() {
        let dir = Scratch::new();
        let home = dir.path().join("home");
        let cache = dir.path().join("cache");
        std::fs::create_dir_all(home.join(".config/tool")).unwrap();
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::write(home.join(".config/tool/token"), "t").unwrap();
        std::fs::write(cache.join("x"), "x").unwrap();
        let tool = home.join(".config/tool");
        let (code, report) = run_helper(
            "",
            &[
                "in-place",
                "0",
                cache.to_str().unwrap(),
                CREDENTIAL_SCRUB_SEPARATOR,
                tool.to_str().unwrap(),
            ],
        );
        assert_eq!(code, 0, "{report}");
        assert!(!cache.exists() && !tool.exists());

        // A path that stays present after the scrub fails the capture.
        std::fs::create_dir_all(&tool).unwrap();
        let hook = format!(
            "def stuck(path):\n    return path == {tool:?}\nns['cred_present'] = stuck\n\
             ns['scrub_credentials'] = lambda paths: list(paths)",
            tool = tool.to_str().unwrap(),
        );
        let (code, report) = run_helper(
            &hook,
            &[
                "in-place",
                "0",
                CREDENTIAL_SCRUB_SEPARATOR,
                tool.to_str().unwrap(),
            ],
        );
        assert_eq!(code, 1, "{report}");
        assert!(
            errors_of(&report)
                .iter()
                .any(|e| e.contains("present after scrub")),
            "{report}"
        );
    }

    #[test]
    fn credential_scrub_targets_resolve_against_home_and_never_filter() {
        assert_eq!(
            credential_scrub_targets(
                "/home/user/",
                &[".netrc".into(), ".config/tool".into(), ".netrc".into()]
            )
            .unwrap(),
            [
                "/home/user/.config/tool".to_owned(),
                format!("/home/user/.config/.wssp-cred-{}", "[0-9a-f]".repeat(16)),
                "/home/user/.netrc".to_owned(),
                format!("/home/user/.wssp-cred-{}", "[0-9a-f]".repeat(16)),
            ]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
        );
        assert!(
            credential_scrub_targets("/home/user", &[])
                .unwrap()
                .is_empty()
        );
        for bad in [
            "../etc/shadow",
            "/etc/shadow",
            ".config/../x",
            "",
            ".wssp/state",
            "auth/.wssp-cred-0123456789abcdef",
            "auth/.wssp-cred-other/token",
            "a:b",
        ] {
            let refused =
                credential_scrub_targets("/home/user", &[".netrc".into(), bad.into()]).unwrap_err();
            assert_eq!(
                refused.code,
                sandbox_protocol::SandboxErrorCode::CaptureFailed
            );
        }
        for home in ["relative", "/", "/home/../root"] {
            assert!(
                credential_scrub_targets(home, &[".netrc".into()]).is_err(),
                "{home}"
            );
        }
    }

    #[test]
    fn helpers_import_everything_before_freezing_and_never_follow_links_blindly() {
        let freeze_at = FREEZE_HELPER.find("FIFREEZE, 0").expect("freeze call");
        assert!(FREEZE_HELPER[..freeze_at].matches("import").count() == 1);
        assert!(!FREEZE_HELPER[freeze_at..].contains("import "));
        assert!(SCRUB_HELPER.contains("follow_symlinks=False"));
        assert!(SCRUB_HELPER.contains("dir_fd="));
        assert!(SCRUB_HELPER.contains("cgroup.freeze"));
        assert!(!SCRUB_HELPER.contains("FITHAW") && !SCRUB_HELPER.contains("\"0\")"));
        assert!(!SCRUB_HELPER.contains("rmtree"));
        assert!(SCRUB_HELPER.contains("O_NOFOLLOW"));
        // One import line, first; nothing executed from the guest.
        assert_eq!(SCRUB_HELPER.matches("import").count(), 1);
        assert!(SCRUB_HELPER.starts_with("import "));
        for spawn in [
            "os.system",
            "subprocess",
            "os.exec",
            "os.spawn",
            "os.popen",
            "os.fork",
            "posix_spawn",
            "cloud-init",
        ] {
            assert!(!SCRUB_HELPER.contains(spawn), "{spawn}");
        }
        assert_eq!(
            capture_names("op-ABC_123").expect("names").0,
            "wssp-cap-opabc123"
        );
        assert!(capture_names("---").is_err());
    }
}
