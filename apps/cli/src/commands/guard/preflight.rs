//! The guard service (`__wssp-guard`) refuses to start unless it is uid 0 with
//! `CAP_NET_ADMIN`, and `/etc/wssp` and `guard.toml` are root-owned and not
//! group/world-writable.

use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use anyhow::{Context, Result, bail};
use sandbox_runtime::guard::sources::check_root_owned;

use super::paths::Paths;

const CAP_NET_ADMIN: u32 = 12;

/// `(effective uid, effective capability mask)` from `/proc/self/status`.
pub fn parse_proc_status(text: &str) -> Option<(u32, u64)> {
    let mut euid = None;
    let mut cap_eff = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            euid = rest.split_whitespace().nth(1).and_then(|v| v.parse().ok());
        } else if let Some(rest) = line.strip_prefix("CapEff:") {
            cap_eff = u64::from_str_radix(rest.trim(), 16).ok();
        }
    }
    Some((euid?, cap_eff?))
}

pub fn process_identity() -> Result<(u32, u64)> {
    let text = std::fs::read_to_string("/proc/self/status").context("reading /proc/self/status")?;
    parse_proc_status(&text).context("unreadable /proc/self/status")
}

pub fn is_root() -> bool {
    process_identity().is_ok_and(|(euid, _)| euid == 0)
}

pub fn check_identity(euid: u32, cap_eff: u64) -> Result<()> {
    if euid != 0 {
        bail!("the egress guard service must run as root (the `wssp-guard` system service)");
    }
    if cap_eff & (1 << CAP_NET_ADMIN) == 0 {
        bail!("the egress guard service needs `CAP_NET_ADMIN`");
    }
    Ok(())
}

pub fn check_root_path(path: &Path, dir: bool) -> Result<()> {
    let meta = std::fs::symlink_metadata(path).with_context(|| {
        format!(
            "`{}` is missing: run `sudo wssp host guard install --daemon-user <user>`",
            path.display()
        )
    })?;
    let type_ok = if dir {
        meta.file_type().is_dir()
    } else {
        meta.file_type().is_file()
    };
    check_root_owned(
        &format!("`{}`", path.display()),
        meta.uid(),
        meta.mode(),
        0,
        type_ok,
    )
    .map_err(anyhow::Error::msg)
}

pub fn check_service(paths: &Paths) -> Result<()> {
    let (euid, cap_eff) = process_identity()?;
    check_identity(euid, cap_eff)?;
    check_root_path(&paths.config_dir(), true)?;
    check_root_path(&paths.config(), false)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_rules() {
        let status = "Name:\twssp\nUid:\t1000\t0\t0\t0\nCapEff:\t0000000000001000\n";
        assert_eq!(parse_proc_status(status), Some((0, 0x1000)));
        assert!(check_identity(0, 1 << CAP_NET_ADMIN).is_ok());
        assert!(check_identity(1000, 1 << CAP_NET_ADMIN).is_err());
        assert!(check_identity(0, 0).is_err());
        assert!(check_identity(0, !(1 << CAP_NET_ADMIN)).is_err());
        assert_eq!(parse_proc_status("Uid:\t0\n"), None);
    }

    #[test]
    fn service_refuses_without_root_or_with_user_owned_config() {
        // Tests never run as root: the identity check refuses first.
        if !is_root() {
            assert!(check_service(&Paths::system()).is_err());
        }
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("guard.toml");
        std::fs::write(&file, "daemon_user = \"x\"\ndaemon_uid = 1000\n").unwrap();
        // Owned by the test user, not root.
        assert!(check_root_path(&file, false).is_err());
        assert!(check_root_path(dir.path(), true).is_err());
        assert!(check_root_path(&dir.path().join("absent"), false).is_err());
    }
}
