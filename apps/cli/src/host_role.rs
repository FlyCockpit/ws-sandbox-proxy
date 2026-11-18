//! Whether this machine is an enrolled host, from local state only.
//!
//! Used to shape `--help` and to fail fast on host commands that need an
//! enrollment. It takes no locks and makes no network call. Anything it
//! cannot read with certainty counts as enrolled: help is never hidden and no
//! command is refused because of an unreadable file.

use std::path::Path;

/// The local host role of this machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostRole {
    /// A host device credential exists, or `config.toml` selects a host token
    /// environment variable (or local state could not be read).
    Enrolled,
    /// Neither a device credential nor a host token selection.
    NotEnrolled,
}

impl HostRole {
    /// Detect the role from the resolved data and config directories.
    pub fn detect() -> Self {
        match (crate::paths::data_dir(), crate::paths::config_file()) {
            (Ok(data), Ok(config)) => Self::detect_at(&data, &config),
            _ => Self::Enrolled,
        }
    }

    pub(crate) fn detect_at(data_dir: &Path, config_file: &Path) -> Self {
        match std::fs::symlink_metadata(data_dir.join(crate::state::DEVICE_CREDENTIAL_FILE)) {
            Ok(_) => return Self::Enrolled,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Self::Enrolled,
        }
        match std::fs::symlink_metadata(config_file) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Self::NotEnrolled;
            }
            Err(_) => return Self::Enrolled,
            Ok(_) => {}
        }
        match crate::config::Config::read(config_file) {
            Ok(config) if config.host_token_env.is_none() => Self::NotEnrolled,
            _ => Self::Enrolled,
        }
    }

    pub fn is_enrolled(self) -> bool {
        self == Self::Enrolled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_from_credential_file_or_token_env_and_fails_towards_enrolled() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        let config = dir.path().join("config/config.toml");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        assert_eq!(HostRole::detect_at(&data, &config), HostRole::NotEnrolled);
        std::fs::write(&config, "server_url = \"https://example.com\"\n").unwrap();
        assert_eq!(HostRole::detect_at(&data, &config), HostRole::NotEnrolled);
        std::fs::write(&config, "host_token_env = \"WSSP_HOST_TOKEN\"\n").unwrap();
        assert_eq!(HostRole::detect_at(&data, &config), HostRole::Enrolled);
        std::fs::write(&config, "not = [valid toml").unwrap();
        assert_eq!(HostRole::detect_at(&data, &config), HostRole::Enrolled);
        std::fs::remove_file(&config).unwrap();
        // Even a dangling symlink counts: the credential path is occupied.
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            dir.path().join("missing"),
            data.join(crate::state::DEVICE_CREDENTIAL_FILE),
        )
        .unwrap();
        #[cfg(not(unix))]
        std::fs::write(data.join(crate::state::DEVICE_CREDENTIAL_FILE), "{}").unwrap();
        assert_eq!(HostRole::detect_at(&data, &config), HostRole::Enrolled);
    }
}
