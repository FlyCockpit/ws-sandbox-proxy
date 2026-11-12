//! R14-F1: `incus-surface cleanup <run-id>` must REPORT failure (nonzero
//! exit, no "cleaned") when an owned resource cannot be deleted, and report
//! success only when everything owned is gone. Spawns the real binary
//! against a shim daemon with a pinned deletion failure.

#![cfg(target_os = "linux")]

mod support {
    pub mod managed_child;
}
use std::fs;
use std::process::Command;
use support::managed_child::ManagedChild;

const RUN: &str = "b2c3d4e5f6a1";

/// Installs an executable without this process ever holding a writable
/// descriptor to it: a concurrent test thread's fork would inherit one written
/// in-process, and the spawned binary's exec of the shim then fails with
/// ETXTBSY. Only the `cp` child opens the target for writing (the library
/// tests' `install_executable`).
fn install_executable(path: &std::path::Path, contents: &str) {
    let mut staged = path.as_os_str().to_owned();
    staged.push(".src");
    let staged = std::path::PathBuf::from(staged);
    fs::write(&staged, contents).unwrap();
    let status = Command::new("cp").arg(&staged).arg(path).status().unwrap();
    assert!(status.success(), "cp {staged:?} -> {path:?}: {status}");
    fs::remove_file(&staged).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn shim(dir: &std::path::Path, run: &str) -> std::path::PathBuf {
    let shim = dir.join("incus-shim.sh");
    install_executable(
        &shim,
        &format!(
            r#"#!/bin/sh
case "$*" in
  *"config get wssp-sbx-s{run}-a user.flycockpit.sandbox_id")
    n=$(cat '{dir}/probe-count-a' 2>/dev/null || echo 0); n=$((n+1)); echo $n > '{dir}/probe-count-a'
    if [ -f '{dir}/fail-after-first-probe' ] && [ "$n" -gt 1 ]; then
      echo "Error: Forbidden" >&2; exit 1; fi
    if [ -f '{dir}/vm-a' ]; then echo "s{run}-a";
    elif [ -f '{dir}/fail-probe-after-delete' ]; then echo "Error: Forbidden" >&2; exit 1;
    elif [ -f '{dir}/misleading-not-found' ]; then
      echo 'Error: cannot parse server response: field "config" not found' >&2; exit 1;
    else
      echo "Error: Failed to fetch instance \"wssp-sbx-s{run}-a\" in project \"default\": Instance not found" >&2; exit 1; fi ;;
  *"config get wssp-sbx-s{run}-p user.flycockpit.sandbox_id")
    if [ -f '{dir}/vm-p' ]; then echo "s{run}-p";
    else
      echo "Error: Failed to fetch instance \"wssp-sbx-s{run}-p\" in project \"wssp-surface-{run}\": Instance not found" >&2; exit 1; fi ;;
  "--project default delete wssp-sbx-s{run}-a --force")
    if [ -f '{dir}/fail-vm-delete' ]; then echo "Error: daemon busy" >&2; exit 1; fi
    rm -f '{dir}/vm-a' ;;
  "--project wssp-surface-{run} delete wssp-sbx-s{run}-p --force")
    if [ -f '{dir}/fail-vm-delete' ]; then echo "Error: daemon busy" >&2; exit 1; fi
    rm -f '{dir}/vm-p' ;;
  "project delete "*)
    if [ -f '{dir}/fail-project-delete' ]; then echo "Error: project is not empty" >&2; exit 1; fi
    rm -f '{dir}/proj-exists' ;;
  "project show "*)
    if [ -f '{dir}/proj-exists' ]; then exit 0; fi
    if [ -f '{dir}/fail-project-probe' ]; then
      echo "Error: Get \"http://unix.socket/1.0\": dial unix: connect: connection refused" >&2; exit 1; fi
    echo "Error: Project not found" >&2; exit 1 ;;
  *"config get "*)
    nf_name=$(printf '%s' "$*" | awk '{{print $(NF-1)}}')
    nf_proj=$(printf '%s' "$*" | awk '{{print $2}}')
    echo "Error: Failed to fetch instance \"$nf_name\" in project \"$nf_proj\": Instance not found" >&2; exit 1 ;;
  "query --raw /1.0/networks/"*|"query --raw /1.0/network-acls/"*)
    url=$3
    name=${{url##*/}}
    name=${{name%%\?*}}
    marker=$(cat '{dir}'/net-"$name" 2>/dev/null) || marker=""
    if [ -n "$marker" ]; then
      tag=${{marker%%|*}}
      proj=${{marker##*|}}
      printf '{{"type":"sync","status_code":200,"error_code":0,"metadata":{{"name":"%s","config":{{"user.wssp.sandbox_id":"%s","user.wssp.attempt":"s1","user.wssp.project":"%s"}}}}}}\n' "$name" "$tag" "$proj"
    else
      printf '{{"type":"error","status":"Not Found","status_code":404,"error_code":404,"error":"Not Found"}}\n'
    fi ;;
  *"network acl delete "*|*"network delete "*)
    if [ -f '{dir}/fail-net-delete' ]; then echo "Error: daemon busy" >&2; exit 1; fi
    if [ -f '{dir}/slow-cleanup' ]; then sleep 3; fi
    rm -f '{dir}/'net-"${{*##* }}" ;;
esac
exit 0
"#,
            dir = dir.display()
        ),
    );
    shim
}

fn run_cleanup(dir: &std::path::Path, shim: &std::path::Path) -> std::process::Output {
    run_cleanup_for(dir, shim, RUN)
}

fn run_cleanup_for(
    dir: &std::path::Path,
    shim: &std::path::Path,
    run: &str,
) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_incus-surface"))
        .args(["cleanup", run])
        .env("WSSP_INCUS_BINARY", shim)
        .env("WSSP_SURFACE_ROOT", dir.join("surfroot"))
        .current_dir(dir)
        .output()
        .expect("spawn incus-surface")
}

#[test]
fn cleanup_command_reports_failure_and_never_claims_cleaned() {
    let dir = std::env::temp_dir().join(format!("surface-cleanup-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let shim = shim(&dir, RUN);
    // An owned bridge+ACL for this run in the default project.
    let (network, acl) = sandbox_runtime::sandbox_network_names(&format!("s{RUN}-a"));
    for name in [&network, &acl] {
        fs::write(dir.join(format!("net-{name}")), format!("s{RUN}-a|default")).unwrap();
    }
    for marker in ["vm-a", "vm-p", "proj-exists"] {
        fs::write(dir.join(marker), "").unwrap();
    }

    // Transient deletion failure: the command FAILS and does not lie.
    fs::write(dir.join("fail-net-delete"), "").unwrap();
    let out = run_cleanup(&dir, &shim);
    assert_eq!(out.status.code(), Some(1), "failure must surface");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("cleaned"),
        "never reports success over an owned leftover: {stdout}"
    );
    assert!(
        dir.join(format!("net-{network}")).exists(),
        "the owned bridge remains on the daemon"
    );

    // The retained state journal lives in the run-id-keyed CANONICAL dir, so
    // a LATER `incus-surface cleanup <run-id>` process (a different pid)
    // reopens it.
    let canonical = dir.join("surfroot").join(format!("state-{RUN}"));
    assert!(canonical.exists(), "the canonical state dir is retained");
    fs::remove_file(dir.join("fail-net-delete")).unwrap();

    // VM deletion failure: the command fails even though network teardown
    // can succeed (the stopped VM may not reference the managed bridge).
    // Phase 1's VM delete succeeded, so re-create the VM first.
    fs::write(dir.join("vm-a"), "").unwrap();
    fs::write(dir.join("fail-vm-delete"), "").unwrap();
    let out = run_cleanup(&dir, &shim);
    assert_eq!(out.status.code(), Some(1), "VM deletion failure surfaces");
    assert!(!String::from_utf8_lossy(&out.stdout).contains("cleaned"));
    assert!(dir.join("vm-a").exists(), "the VM survives");
    fs::remove_file(dir.join("fail-vm-delete")).unwrap();

    // Project deletion failure AFTER everything else succeeds: still a
    // failure, still no "cleaned". (The VM-failure phase's project delete
    // succeeded, so re-create the project first.)
    fs::write(dir.join("proj-exists"), "").unwrap();
    fs::write(dir.join("fail-project-delete"), "").unwrap();
    let out = run_cleanup(&dir, &shim);
    assert_eq!(
        out.status.code(),
        Some(1),
        "project deletion failure surfaces"
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains("cleaned"));
    assert!(dir.join("proj-exists").exists(), "the project survives");
    fs::remove_file(dir.join("fail-project-delete")).unwrap();

    // Deletion fails AND the subsequent verify probe returns a
    // non-not-found error (permission denied): the probe error is not
    // absence evidence — nonzero exit, no "cleaned", VM retained.
    fs::write(dir.join("vm-a"), "").unwrap();
    let _ = fs::remove_file(dir.join("probe-count-a"));
    fs::write(dir.join("fail-vm-delete"), "").unwrap();
    fs::write(dir.join("fail-after-first-probe"), "").unwrap();
    let out = run_cleanup(&dir, &shim);
    assert_eq!(
        out.status.code(),
        Some(1),
        "a non-not-found probe error after a failed delete must fail the command"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("cleaned"));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("cannot verify"),
        "the inconclusive probe is reported: {stderr}"
    );
    assert!(dir.join("vm-a").exists());
    fs::remove_file(dir.join("fail-vm-delete")).unwrap();
    fs::remove_file(dir.join("fail-after-first-probe")).unwrap();
    fs::remove_file(dir.join("probe-count-a")).unwrap();

    // Daemon down during project show after a successful project delete:
    // inconclusive absence fails the command too.
    fs::write(dir.join("proj-exists"), "").unwrap();
    fs::write(dir.join("fail-project-probe"), "").unwrap();
    let out = run_cleanup(&dir, &shim);
    assert_eq!(
        out.status.code(),
        Some(1),
        "daemon-down project probe fails"
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains("cleaned"));
    fs::remove_file(dir.join("fail-project-probe")).unwrap();

    // Misleading diagnostics: an unrelated "not found" mention on the
    // absence verify is a FAILURE, not absence evidence.
    fs::write(dir.join("vm-a"), "").unwrap();
    fs::write(dir.join("misleading-not-found"), "").unwrap();
    let out = run_cleanup(&dir, &shim);
    assert_eq!(out.status.code(), Some(1));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("cleaned"));
    fs::remove_file(dir.join("misleading-not-found")).unwrap();

    // Recovery: everything now cleans and the command says so.
    let out = run_cleanup(&dir, &shim);
    assert_eq!(
        out.status.code(),
        Some(0),
        "final cleanup: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("cleaned"));
    assert!(!dir.join(format!("net-{network}")).exists());
    assert!(
        !canonical.exists(),
        "a successful cleanup removes the canonical state dir"
    );
    fs::remove_dir_all(&dir).unwrap();
}

/// Pid-suffixed scratch state dirs for a run id inside the surface root
/// (R20-F3).
fn scratch_dirs(dir: &std::path::Path, run: &str) -> Vec<String> {
    fs::read_dir(dir.join("surfroot"))
        .map(|entries| {
            entries
                .filter_map(std::result::Result::ok)
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|name| name.starts_with(&format!("state-{run}-")))
                .collect()
        })
        .unwrap_or_default()
}

/// R21-F1: a symlink planted at the run's predictable state-dir path (by
/// another local user while the publicly discoverable lock outlives the
/// initial cleanup's dir removal) is REFUSED — the process exits 2, the
/// planted symlink is never followed, and its target's bytes are untouched.
#[test]
fn cleanup_refuses_a_planted_symlinked_state_dir() {
    const RUN3: &str = "d4e5f6a1b2c3";
    let dir = std::env::temp_dir().join(format!("incus-surface-it3-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let shim = shim(&dir, RUN3);
    // A valid private root with a symlink planted at the state-dir path.
    let root = dir.join("surfroot");
    fs::create_dir_all(&root).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let victim = dir.join("victim.json");
    fs::write(&victim, b"precious").unwrap();
    std::os::unix::fs::symlink(&victim, root.join(format!("state-{RUN3}"))).unwrap();
    let out = run_cleanup_for(&dir, &shim, RUN3);
    assert_eq!(
        out.status.code(),
        Some(2),
        "a planted symlink state dir refuses the claim: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("refusing"),
        "the refusal names the planted path: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        fs::read(&victim).unwrap(),
        b"precious",
        "the planted symlink's target is untouched"
    );
    assert!(
        root.join(format!("state-{RUN3}"))
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink(),
        "the planted symlink was not traversed or replaced"
    );
    fs::remove_dir_all(&dir).unwrap();
}

/// R18-F2: a second `cleanup <run-id>` process is refused while a cleanup of
/// the same run id is still active (the run lock is held for the whole
/// process lifetime, across the initial state-dir removal).
#[test]
fn concurrent_cleanup_of_the_same_run_id_is_refused() {
    const RUN2: &str = "c3d4e5f6a1b2";
    let dir = std::env::temp_dir().join(format!("incus-surface-it2-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let shim = shim(&dir, RUN2);
    // Give the first claimant real work and make it slow.
    let (network, acl) = sandbox_runtime::sandbox_network_names(&format!("s{RUN2}-a"));
    for name in [&network, &acl] {
        fs::write(
            dir.join(format!("net-{name}")),
            format!("s{RUN2}-a|default"),
        )
        .unwrap();
    }
    fs::write(dir.join("vm-a"), "").unwrap();
    fs::write(dir.join("slow-cleanup"), "").unwrap();
    // R20-F3: snapshot scratch dirs so the refusal assertion is delta-based
    // (stale dirs from older binary runs must not flake this test).
    let scratch_before = scratch_dirs(&dir, RUN2);
    // First claimant: runs long enough to still hold the lock mid-flight.
    let mut first = ManagedChild::spawn(
        Command::new(env!("CARGO_BIN_EXE_incus-surface"))
            .args(["cleanup", RUN2])
            .env("WSSP_INCUS_BINARY", &shim)
            .env("WSSP_SURFACE_ROOT", dir.join("surfroot"))
            .current_dir(&dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped()),
    )
    .expect("spawn first cleanup");
    std::thread::sleep(std::time::Duration::from_millis(500));
    // Second claimant while the first is active: refused.
    let second = run_cleanup_for(&dir, &shim, RUN2);
    assert_eq!(
        second.status.code(),
        Some(2),
        "a concurrent claimant must be refused: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert!(
        String::from_utf8_lossy(&second.stderr).contains("owned by a live process"),
        "refusal names the live owner: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    // R20-F3: the refused claim abandoned no pid-suffixed scratch state dir.
    let abandoned: Vec<_> = scratch_dirs(&dir, RUN2)
        .into_iter()
        .filter(|name| !scratch_before.contains(name))
        .collect();
    assert!(
        abandoned.is_empty(),
        "abandoned scratch dirs: {abandoned:?}"
    );
    fs::remove_file(dir.join("slow-cleanup")).unwrap();
    let status = first.wait().expect("first cleanup");
    assert_eq!(
        status.code(),
        Some(0),
        "the first cleanup completes unharmed"
    );
    fs::remove_dir_all(&dir).unwrap();
}
