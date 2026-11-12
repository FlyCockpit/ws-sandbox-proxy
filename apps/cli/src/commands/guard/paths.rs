//! Guard file locations, optionally under a test root (`--root-prefix`).

use std::path::{Path, PathBuf};

use sandbox_runtime::guard;

/// Debug-build-only stand-in for `/` (tests and the cancel-wire harness).
#[cfg(debug_assertions)]
fn test_guard_root() -> Option<std::ffi::OsString> {
    std::env::var_os("WSSP_TEST_GUARD_ROOT")
}

/// Release builds never read the environment for guard paths.
#[cfg(not(debug_assertions))]
const fn test_guard_root() -> Option<std::ffi::OsString> {
    None
}

#[derive(Debug, Clone)]
pub struct Paths {
    root: PathBuf,
}

impl Paths {
    pub fn system() -> Self {
        Self::under(Path::new("/"))
    }

    /// The paths this node's daemon and `wssp guard status` use: the system
    /// paths. Debug builds only honour `WSSP_TEST_GUARD_ROOT` (a directory
    /// standing in for `/`) so tests never see the machine's guard; release
    /// builds do not compile the override at all.
    pub fn local() -> Self {
        match test_guard_root() {
            Some(root) => Self::under(Path::new(&root)),
            None => Self::system(),
        }
    }

    pub fn under(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
        }
    }

    /// `/`, or the `--root-prefix` test root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn join(&self, absolute: &str) -> PathBuf {
        self.root.join(absolute.trim_start_matches('/'))
    }

    pub fn config_dir(&self) -> PathBuf {
        self.join(guard::CONFIG_DIR)
    }
    pub fn config(&self) -> PathBuf {
        self.join(guard::CONFIG_PATH)
    }
    pub fn root_blocklist(&self) -> PathBuf {
        self.join(guard::ROOT_BLOCKLIST_PATH)
    }
    pub fn socket(&self) -> PathBuf {
        self.join(guard::SOCKET_PATH)
    }
    pub fn status_file(&self) -> PathBuf {
        self.join(guard::STATUS_PATH)
    }
    pub fn state_dir(&self) -> PathBuf {
        self.join(guard::STATE_DIR)
    }
    /// Links the quarantine fence took down (restored on recovery).
    pub fn fenced(&self) -> PathBuf {
        self.state_dir().join("fenced.json")
    }
    pub fn root_source(&self) -> PathBuf {
        self.state_dir().join("sources/root.json")
    }
    pub fn deployment_source(&self) -> PathBuf {
        self.state_dir().join("sources/deployment.json")
    }
    pub fn install_dir(&self) -> PathBuf {
        self.join(guard::INSTALL_DIR)
    }
    pub fn binary(&self) -> PathBuf {
        self.join(guard::INSTALLED_BINARY)
    }
    pub fn unit(&self) -> PathBuf {
        self.join(guard::UNIT_PATH)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The production socket is the fixed system path.
    #[test]
    fn system_guard_socket_is_fixed() {
        assert_eq!(
            Paths::system().socket(),
            Path::new("/run/wssp-guard/guard.sock")
        );
    }

    /// Release builds compile no override: whatever the environment holds,
    /// the daemon asks the system guard (`cargo test --release`).
    #[cfg(not(debug_assertions))]
    #[test]
    fn release_build_ignores_the_test_guard_root() {
        assert!(test_guard_root().is_none());
        assert_eq!(
            Paths::local().socket(),
            Path::new("/run/wssp-guard/guard.sock")
        );
    }
}
