//! Node-only raises: fail closed when Linux cannot prove a caller's ancestry.
use anyhow::{Context, Result, bail, ensure};
use std::path::Path;

pub(crate) fn check() -> Result<()> {
    ensure!(
        ["WSSP_HOST_COMMAND", "WSSP_HOST_TERMINAL"]
            .iter()
            .all(|name| std::env::var_os(name).is_none()),
        "a host command or host terminal cannot raise host access"
    );
    #[cfg(target_os = "linux")]
    {
        let root = Path::new("/proc");
        let mut daemons = Vec::new();
        let relay = crate::paths::data_dir()?.join("relay");
        match std::fs::read_dir(relay) {
            Ok(entries) => {
                for (index, entry) in entries.enumerate() {
                    ensure!(
                        index < 1024,
                        "too many daemon state directories to verify safely"
                    );
                    let entry = entry.context("reading daemon state directories")?;
                    let path = entry
                        .path()
                        .join(crate::sandbox_relay::quiesce::CONTROL_FILE);
                    let file =
                        crate::commands::daemon::read_control(&path).map_err(anyhow::Error::msg)?;
                    if let Some(file) = file
                        && crate::sandbox_relay::quiesce::process_start_time(file.pid)
                            == Some(file.start_time)
                    {
                        daemons.push(file.pid);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).context("reading daemon state directories"),
        }
        // Also find daemons started with a nondefault state directory. Never
        // rely on a caller-controlled data-directory override for attribution.
        for pid in discover_daemons(root, rustix::process::geteuid().as_raw())? {
            daemons.push(pid);
        }
        check_in(
            root,
            std::process::id(),
            &daemons,
            rustix::process::geteuid().as_raw(),
        )
    }
    #[cfg(not(target_os = "linux"))]
    bail!("raising host access requires Linux process ancestry verification")
}

#[cfg(target_os = "linux")]
fn discover_daemons(root: &Path, own_uid: u32) -> Result<Vec<u32>> {
    let mut daemons = Vec::new();
    for entry in std::fs::read_dir(root).context("reading process table")? {
        let entry = entry.context("reading process table entry")?;
        if let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse().ok())
            && uids(&entry.path()).is_ok_and(|ids| ids == (own_uid, own_uid))
            && is_daemon(&entry.path()).unwrap_or(false)
        {
            daemons.push(pid);
        }
    }
    Ok(daemons)
}

#[cfg(target_os = "linux")]
fn is_daemon(dir: &Path) -> Result<bool> {
    if is_connect_process(dir)? {
        return Ok(true);
    }
    let exe = std::fs::read_link(dir.join("exe")).context("reading ancestor executable")?;
    let name = exe.file_name().unwrap_or_default().to_string_lossy();
    let wssp = name.strip_suffix(" (deleted)").unwrap_or(&name) == "wssp";
    let cmdline = std::fs::read(dir.join("cmdline")).context("reading ancestor command line")?;
    Ok(wssp
        && cmdline
            .split(|b| *b == 0)
            .skip(1)
            .any(|arg| arg == b"connect"))
}

// comm/cmdline remain readable for the non-dumpable daemon; exe does not.
#[cfg(target_os = "linux")]
fn is_connect_process(dir: &Path) -> Result<bool> {
    let comm = std::fs::read_to_string(dir.join("comm")).context("reading ancestor comm")?;
    if comm.trim_end() != "wssp" {
        return Ok(false);
    }
    let cmdline = std::fs::read(dir.join("cmdline")).context("reading ancestor command line")?;
    Ok(cmdline
        .split(|b| *b == 0)
        .skip(1)
        .any(|arg| arg == b"connect"))
}

/// Real and effective uid of a process, from the world-readable `status`.
#[cfg(target_os = "linux")]
fn uids(dir: &Path) -> Result<(u32, u32)> {
    let status = std::fs::read_to_string(dir.join("status")).context("reading ancestor status")?;
    let line = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .context("missing ancestor uid")?;
    let mut ids = line.split_whitespace().map(str::parse::<u32>);
    match (ids.next(), ids.next()) {
        (Some(Ok(real)), Some(Ok(effective))) => Ok((real, effective)),
        _ => bail!("invalid ancestor uid"),
    }
}

/// The per-user service manager (`systemd --user`) is non-dumpable, so its
/// `exe` and `environ` cannot be read even by its own user. Accept exactly that
/// shape: command name `systemd` and a direct child of pid 1. Host-command
/// orphans stay under their per-command subreaper supervisor until cleanup;
/// the daemon's own pid is checked first.
#[cfg(target_os = "linux")]
fn is_user_manager(dir: &Path, parent: u32) -> bool {
    parent == 1
        && std::fs::read_to_string(dir.join("comm")).is_ok_and(|comm| comm.trim_end() == "systemd")
}

#[cfg(target_os = "linux")]
fn parent_of(dir: &Path) -> Result<u32> {
    let stat = std::fs::read_to_string(dir.join("stat")).context("reading ancestor stat")?;
    let tail = stat.rsplit_once(')').context("invalid ancestor stat")?.1;
    let parent = tail
        .split_whitespace()
        .nth(1)
        .context("missing parent pid")?
        .parse()?;
    ensure!(parent > 0, "unverifiable process ancestry");
    Ok(parent)
}

#[cfg(target_os = "linux")]
fn check_in(root: &Path, mut pid: u32, daemons: &[u32], own_uid: u32) -> Result<()> {
    let cgroup = std::fs::read(root.join(pid.to_string()).join("cgroup"))
        .context("reading caller cgroup")?;
    for daemon in daemons {
        let other = std::fs::read(root.join(daemon.to_string()).join("cgroup"))
            .context("reading daemon cgroup")?;
        ensure!(
            cgroup != other,
            "the daemon cgroup cannot raise host access"
        );
    }
    let mut visited = std::collections::HashSet::new();
    while pid > 1 && visited.len() < 256 {
        ensure!(visited.insert(pid), "cyclic process ancestry");
        ensure!(
            !daemons.contains(&pid),
            "a daemon descendant cannot raise host access"
        );
        let dir = root.join(pid.to_string());
        let parent = parent_of(&dir)?;
        let (real, effective) = uids(&dir)?;
        // Host commands and host terminals run as the daemon's uid, which owns
        // this config. An ancestor running entirely as another user (sshd,
        // login, sudo, pid 1's children) can be neither; its exe and environ
        // are unreadable to us anyway.
        if real != own_uid && effective != own_uid {
            pid = parent;
            continue;
        }
        ensure!(
            !is_connect_process(&dir)?,
            "a daemon descendant cannot raise host access"
        );
        let exe_readable = std::fs::read_link(dir.join("exe")).is_ok();
        if !exe_readable && is_user_manager(&dir, parent) {
            pid = parent;
            continue;
        }
        if !exe_readable
            && real == own_uid
            && effective == own_uid
            && parent > 1
            && std::fs::read_to_string(dir.join("comm"))?.trim_end() != "wssp"
        {
            let (parent_real, parent_effective) = uids(&root.join(parent.to_string()))?;
            if parent_real != own_uid && parent_effective != own_uid {
                // OpenSSH's same-uid, non-dumpable login-session process.
                // The chain above belongs to another user; stop here.
                return Ok(());
            }
        }
        ensure!(
            !is_daemon(&dir)?,
            "a daemon descendant cannot raise host access"
        );
        let env = std::fs::read(dir.join("environ")).context("reading ancestor environment")?;
        ensure!(
            !env.split(|b| *b == 0)
                .any(|v| v.starts_with(b"WSSP_HOST_COMMAND=")
                    || v.starts_with(b"WSSP_HOST_TERMINAL=")),
            "a host child descendant cannot raise host access"
        );
        pid = parent;
    }
    if pid != 1 {
        bail!("process ancestry does not reach pid 1");
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    fn process(root: &Path, pid: u32, parent: u32, exe: &str, argv: &[u8], env: &[u8]) {
        use std::os::unix::fs::symlink;
        let dir = root.join(pid.to_string());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("stat"),
            format!("{pid} (a ) tricky ( name) S {parent} 0 0"),
        )
        .unwrap();
        symlink(exe, dir.join("exe")).unwrap();
        std::fs::write(dir.join("cmdline"), argv).unwrap();
        std::fs::write(dir.join("environ"), env).unwrap();
        std::fs::write(dir.join("cgroup"), "0::/person\n").unwrap();
        std::fs::write(
            dir.join("status"),
            "Name:\tx\nUid:\t1000\t1000\t1000\t1000\n",
        )
        .unwrap();
        std::fs::write(dir.join("comm"), "x\n").unwrap();
    }
    const UID: u32 = 1000;
    fn foreign(root: &Path, pid: u32) {
        let dir = root.join(pid.to_string());
        std::fs::write(dir.join("status"), "Name:\tx\nUid:\t0\t0\t0\t0\n").unwrap();
        std::fs::remove_file(dir.join("exe")).unwrap();
        std::fs::remove_file(dir.join("environ")).unwrap();
    }
    fn unreadable(root: &Path, pid: u32, comm: &str) {
        let dir = root.join(pid.to_string());
        std::fs::remove_file(dir.join("exe")).unwrap();
        std::fs::remove_file(dir.join("environ")).unwrap();
        std::fs::write(dir.join("comm"), format!("{comm}\n")).unwrap();
    }
    #[test]
    fn foreign_uid_ancestors_and_the_user_manager_do_not_block_a_login_session() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // wssp config <- bash <- sshd (root) <- pid 1
        process(root, 40, 30, "/bin/wssp", b"wssp\0config\0", b"");
        process(root, 30, 20, "/bin/bash", b"bash\0", b"");
        process(root, 20, 1, "/usr/sbin/sshd", b"sshd\0", b"");
        foreign(root, 20);
        assert!(check_in(root, 40, &[], UID).is_ok());
        // wssp config <- bash <- systemd --user (non-dumpable, same uid) <- pid 1
        std::fs::remove_dir_all(root.join("20")).unwrap();
        process(
            root,
            20,
            1,
            "/usr/lib/systemd/systemd",
            b"systemd\0--user\0",
            b"",
        );
        unreadable(root, 20, "systemd");
        assert!(check_in(root, 40, &[], UID).is_ok());
        // A same-uid unreadable ancestor that is not the user manager fails closed,
        // as does one named systemd that is not a direct child of pid 1.
        std::fs::write(root.join("20/comm"), "sh\n").unwrap();
        assert!(check_in(root, 40, &[], UID).is_err());
        std::fs::write(root.join("20/comm"), "systemd\n").unwrap();
        std::fs::write(root.join("20/stat"), "20 (systemd) S 10 0 0").unwrap();
        process(root, 10, 1, "/bin/sh", b"sh\0", b"");
        assert!(check_in(root, 40, &[], UID).is_err());
        // The daemon is non-dumpable too: its listed pid refuses before any read.
        std::fs::write(root.join("20/stat"), "20 (wssp) S 1 0 0").unwrap();
        std::fs::write(root.join("20/comm"), "wssp\n").unwrap();
        assert!(check_in(root, 40, &[20], UID).is_err());
        assert!(check_in(root, 40, &[], UID).is_err());
    }
    #[test]
    fn unreadable_login_session_requires_a_foreign_parent_and_never_accepts_wssp() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        process(root, 40, 30, "/bin/wssp", b"wssp\0config\0", b"");
        process(
            root,
            30,
            20,
            "/usr/sbin/sshd-session",
            b"sshd-session: user@pts/0\0",
            b"",
        );
        process(root, 20, 10, "/usr/sbin/sshd", b"sshd\0", b"");
        foreign(root, 20);
        unreadable(root, 30, "sshd-session");
        std::fs::remove_file(root.join("30/cmdline")).unwrap();
        // The foreign chain above the login boundary need not be readable.
        assert!(check_in(root, 40, &[], UID).is_ok());
        std::fs::write(root.join("30/comm"), "wssp\n").unwrap();
        assert!(check_in(root, 40, &[], UID).is_err());
        std::fs::write(root.join("30/comm"), "sshd-session\n").unwrap();
        assert!(check_in(root, 40, &[30], UID).is_err());
        std::fs::write(root.join("30/stat"), "30 (sshd-session) S 1").unwrap();
        assert!(check_in(root, 40, &[], UID).is_err());
    }
    #[test]
    fn discovers_non_dumpable_daemons_without_control_files_and_refuses_ancestors() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        process(root, 40, 30, "/bin/wssp", b"wssp\0config\0", b"");
        process(root, 30, 1, "/bin/sh", b"sh\0", b"");
        process(root, 20, 1, "/bin/wssp", b"renamed\0connect\0", b"");
        unreadable(root, 20, "wssp");
        assert_eq!(discover_daemons(root, UID).unwrap(), vec![20]);
        assert!(check_in(root, 40, &discover_daemons(root, UID).unwrap(), UID).is_err());
        std::fs::write(root.join("20/cgroup"), "0::/daemon\n").unwrap();
        assert!(check_in(root, 40, &discover_daemons(root, UID).unwrap(), UID).is_ok());
        std::fs::write(root.join("30/stat"), "30 (sh) S 20").unwrap();
        assert!(check_in(root, 40, &[], UID).is_err());
        foreign_status(root, 20);
        assert!(discover_daemons(root, UID).unwrap().is_empty());
    }
    fn foreign_status(root: &Path, pid: u32) {
        std::fs::write(
            root.join(pid.to_string()).join("status"),
            "Uid:\t0\t0\t0\t0\n",
        )
        .unwrap();
    }
    #[test]
    fn host_ancestry_survives_cleared_markers_and_forged_argv() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        process(root, 40, 30, "/bin/wssp", b"wssp\0config\0", b"");
        process(root, 30, 20, "/usr/bin/script", b"script\0", b"");
        process(root, 20, 1, "/bin/wssp", b"renamed\0connect\0", b"");
        assert!(check_in(root, 40, &[], UID).is_err());
        std::fs::remove_file(root.join("20/exe")).unwrap();
        std::os::unix::fs::symlink("/bin/sh", root.join("20/exe")).unwrap();
        assert!(
            check_in(root, 40, &[], UID).is_ok(),
            "argv alone is not a daemon"
        );
        for marker in ["WSSP_HOST_COMMAND=", "WSSP_HOST_TERMINAL=1"] {
            std::fs::write(root.join("30/environ"), marker).unwrap();
            assert!(check_in(root, 40, &[], UID).is_err());
        }
    }
    #[test]
    fn host_ancestry_fails_closed_on_missing_data_cycles_and_daemon_cgroup() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        process(root, 40, 30, "/bin/wssp", b"wssp\0config\0", b"");
        assert!(check_in(root, 40, &[], UID).is_err());
        process(root, 30, 1, "/bin/sh", b"sh\0", b"");
        assert!(check_in(root, 40, &[], UID).is_ok());
        process(root, 20, 1, "/bin/wssp", b"wssp\0connect\0", b"");
        assert!(check_in(root, 40, &[20], UID).is_err());
        std::fs::write(root.join("20/cgroup"), "0::/daemon\n").unwrap();
        assert!(check_in(root, 40, &[20], UID).is_ok());
        std::fs::remove_file(root.join("20/cgroup")).unwrap();
        assert!(check_in(root, 40, &[20], UID).is_err());
        std::fs::write(root.join("30/stat"), "30 (sh) S 40").unwrap();
        assert!(check_in(root, 40, &[], UID).is_err());
        std::fs::write(root.join("30/stat"), "30 (sh) S 1").unwrap();
        std::fs::remove_file(root.join("30/environ")).unwrap();
        assert!(check_in(root, 40, &[], UID).is_err());
    }
}
