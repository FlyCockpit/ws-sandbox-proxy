//! Filesystem locations.
//!
//! Resolves the per-user config/data directories in a cross-platform way
//! via the `dirs` crate:
//!
//!   | Dir    | Linux                     | macOS                              | Windows                       |
//!   |--------|---------------------------|------------------------------------|-------------------------------|
//!   | config | ~/.config/wssp            | ~/Library/Application Support/wssp | %APPDATA%\wssp                |
//!   | data   | ~/.local/share/wssp       | ~/Library/Application Support/wssp | %LOCALAPPDATA%\wssp (user-private) |
//!
//! On Windows, `dirs::data_local_dir()` uses LocalAppData. Its user profile
//! directory inherits user-only ACLs; we do not install an explicit DACL.
//! Overrides must provide equivalent permissions. File buffers are flushed
//! before rename; on Windows the parent directory is opened with backup semantics
//! and flushed after rename (see `state::sync_directory`). Native Windows
//! durability is covered by CI state tests.
//!
//! Any of these can be overridden with the `WSSP_CONFIG_DIR` / `WSSP_DATA_DIR`
//! environment variables — useful for tests and for users who want everything
//! in one place.

use std::path::PathBuf;

use anyhow::{Context, Result};

/// Application directory name. Product identity; no old-name fallback.
const APP: &str = "wssp";

/// Override for [`config_dir`].
pub const CONFIG_DIR_ENV: &str = "WSSP_CONFIG_DIR";

/// Override for [`data_dir`].
pub const DATA_DIR_ENV: &str = "WSSP_DATA_DIR";

/// The directory holding the user's editable configuration file.
pub fn config_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os(CONFIG_DIR_ENV) {
        return Ok(PathBuf::from(dir));
    }
    let base = dirs::config_dir().context("could not determine the user config directory")?;
    Ok(base.join(APP))
}

/// The directory for application-managed data (databases, caches, state).
pub fn data_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os(DATA_DIR_ENV) {
        return Ok(PathBuf::from(dir));
    }
    #[cfg(windows)]
    let base = dirs::data_local_dir().context("could not determine local app data")?;
    #[cfg(not(windows))]
    let base = dirs::data_dir().context("could not determine the user data directory")?;
    Ok(base.join(APP))
}

/// Full path to the config file (`config.toml` inside [`config_dir`]).
pub fn config_file() -> Result<PathBuf> {
    Ok(config_dir()?.join("config.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_directory_and_env_names() {
        assert_eq!(APP, "wssp");
        assert_eq!(CONFIG_DIR_ENV, "WSSP_CONFIG_DIR");
        assert_eq!(DATA_DIR_ENV, "WSSP_DATA_DIR");
    }
}
