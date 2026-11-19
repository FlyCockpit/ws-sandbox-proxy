//! Environment policies for host children. Construct scrubbed builders before
//! adding arguments, fixed locale, stdio or process-group settings.
use std::ffi::OsStr;
use std::process::Command;

/// Only the Incus client may inherit host client configuration.
#[derive(Clone, Copy)]
pub enum Environment {
    Incus,
    PathOnly,
}

const INCUS_CLIENT_ENV: &[&str] = &["PATH", "HOME", "INCUS_DIR", "INCUS_SOCKET", "INCUS_CONF"];
const PATH_ENV: &[&str] = &["PATH"];
#[cfg(target_os = "linux")]
pub(crate) const PTY_TERM: &str = "xterm-256color";

fn inherited(policy: Environment) -> impl Iterator<Item = (&'static str, std::ffi::OsString)> {
    let keys = match policy {
        Environment::Incus => INCUS_CLIENT_ENV,
        Environment::PathOnly => PATH_ENV,
    };
    keys.iter()
        .filter_map(|&key| std::env::var_os(key).map(|value| (key, value)))
}

/// A host child with an explicit inheritance policy. Callers may add fixed
/// constants (for example LC_ALL=C), never inherited workload or credentials.
pub fn command(program: impl AsRef<OsStr>, policy: Environment) -> Command {
    let mut command = Command::new(program);
    command.env_clear().envs(inherited(policy));
    command
}

/// PTY equivalent of the Incus policy, with a fixed terminal type.
#[cfg(target_os = "linux")]
pub(crate) fn incus_pty_command(program: impl AsRef<OsStr>) -> portable_pty::CommandBuilder {
    let mut builder = portable_pty::CommandBuilder::new(program);
    builder.env_clear();
    for (key, value) in inherited(Environment::Incus) {
        builder.env(key, value);
    }
    builder.env("TERM", PTY_TERM);
    builder
}

/// Local host shell identity comes only from NSS for the effective UID.
#[cfg(target_os = "linux")]
pub(crate) fn terminal_command() -> Result<portable_pty::CommandBuilder, crate::RuntimeError> {
    let user = nix::unistd::User::from_uid(nix::unistd::geteuid()).map_err(|_| {
        crate::RuntimeError::new(
            sandbox_protocol::SandboxErrorCode::Internal,
            "host identity lookup failed",
        )
    })?;
    let (name, home) = user
        .map(|u| (u.name, u.dir))
        .unwrap_or_else(|| (String::new(), "/".into()));
    terminal_command_for(&name, &home)
}

#[cfg(target_os = "linux")]
fn terminal_command_for(
    name: &str,
    home: &std::path::Path,
) -> Result<portable_pty::CommandBuilder, crate::RuntimeError> {
    let forbidden = |v: &str| {
        ["wssp_host_", "wssp_device_", "wssp_sdk_", "wssp_agent_"]
            .iter()
            .any(|p| v.contains(p))
    };
    let home = if home.is_absolute() && home.is_dir() {
        home
    } else {
        std::path::Path::new("/")
    };
    if forbidden(name) || forbidden(&home.to_string_lossy()) {
        return Err(crate::RuntimeError::new(
            sandbox_protocol::SandboxErrorCode::AccessDenied,
            "host identity refused",
        ));
    }
    let mut command = portable_pty::CommandBuilder::new("/bin/sh");
    command.arg("-i");
    command.env_clear();
    for (key, value) in [
        ("PATH", "/usr/local/bin:/usr/bin:/bin"),
        ("TERM", PTY_TERM),
        ("SHELL", "/bin/sh"),
        ("LANG", "C.UTF-8"),
        ("LC_ALL", "C.UTF-8"),
        ("HISTFILE", "/dev/null"),
        ("WSSP_HOST_TERMINAL", "1"),
        ("USER", name),
        ("LOGNAME", name),
    ] {
        command.env(key, value);
    }
    command.env("HOME", home);
    command.cwd(home);
    Ok(command)
}

#[cfg(all(test, target_os = "linux"))]
mod terminal_tests {
    use super::*;
    #[test]
    fn host_terminal_uses_nss_home_fixed_environment_and_no_inherited_sentinels() {
        // Inspect builders, without changing process environment or opening a shell.
        let home = std::path::Path::new("/tmp");
        let command = terminal_command_for("daemon-user", home).unwrap();
        assert_eq!(command.get_argv(), &["/bin/sh", "-i"]);
        let env: std::collections::BTreeMap<_, _> = command
            .iter_full_env_as_str()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(env.get("HOME").map(String::as_str), Some("/tmp"));
        assert_eq!(env.get("USER").map(String::as_str), Some("daemon-user"));
        assert_eq!(env.get("HISTFILE").map(String::as_str), Some("/dev/null"));
        assert_eq!(env.get("WSSP_HOST_TERMINAL").map(String::as_str), Some("1"));
        assert_eq!(env.len(), 10);
        for key in [
            "SSH_AUTH_SOCK",
            "WSSP_HOST_TOKEN",
            "INCUS_DIR",
            "DBUS_SESSION_BUS_ADDRESS",
            "LD_PRELOAD",
            "HTTP_PROXY",
        ] {
            assert!(!env.contains_key(key));
        }
        let command = terminal_command_for("daemon", std::path::Path::new("relative")).unwrap();
        assert_eq!(
            command
                .iter_full_env_as_str()
                .find(|(k, _)| *k == "HOME")
                .unwrap()
                .1,
            "/"
        );
        assert!(terminal_command_for("wssp_sdk_refused", home).is_err());
        let command = terminal_command().unwrap();
        let user = nix::unistd::User::from_uid(nix::unistd::geteuid()).unwrap();
        if let Some(user) = user {
            assert_eq!(
                command
                    .iter_full_env_as_str()
                    .find(|(k, _)| *k == "USER")
                    .unwrap()
                    .1,
                user.name
            );
        }
    }
}

/// Commands requested by an owner credential use only a minimal, scrubbed host environment.
pub fn agent_command(program: impl AsRef<OsStr>) -> Command {
    let mut command = command(program, Environment::PathOnly);
    command
        .env_clear()
        .envs(agent_environment(std::env::vars_os()));
    command.env("TERM", "dumb").env("WSSP_HOST_COMMAND", "1");
    command
}
fn agent_environment(
    values: impl IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    values
        .into_iter()
        .filter(|(key, value)| {
            let key = key.to_string_lossy();
            // Every `WSSP_` name is dropped, including the user login's CI
            // credential (`WSSP_API_KEY`, `WSSP_SERVER`): an agent's host
            // command never inherits the daemon user's login.
            !key.starts_with("WSSP_")
                && (matches!(
                    key.as_ref(),
                    "PATH" | "HOME" | "USER" | "LOGNAME" | "LANG" | "TZ"
                ) || key.starts_with("LC_"))
                && !["wssp_sdk_", "wssp_host_", "wssp_device_", "wssp_agent_"]
                    .iter()
                    .any(|p| value.to_string_lossy().contains(p))
        })
        .collect()
}
#[cfg(test)]
mod agent_tests {
    use super::*;
    #[test]
    fn host_environment_is_an_allowlist_and_drops_token_values() {
        let input = [
            ("PATH", "/bin"),
            ("HOME", "/tmp"),
            ("LANG", "wssp_agent_fake"),
            ("LC_ALL", "C"),
            ("TZ", "wssp_sdk_fake"),
            ("WSSP_HOST_TOKEN", "refused"),
            ("WSSP_API_KEY", "refused"),
            ("WSSP_SERVER", "https://wssp.example.test"),
            ("SHELL", "/bin/sh"),
            ("LD_PRELOAD", "refused"),
            ("INCUS_DIR", "refused"),
        ];
        let env = agent_environment(input.map(|(k, v)| (k.into(), v.into())));
        assert_eq!(env.len(), 3);
        assert!(
            !env.iter()
                .any(|(k, _)| k == "WSSP_API_KEY" || k == "WSSP_SERVER")
        );
        let child = agent_command("/bin/true");
        assert_eq!(
            child
                .get_envs()
                .find(|(k, _)| *k == "WSSP_HOST_COMMAND")
                .unwrap()
                .1,
            Some(OsStr::new("1"))
        );
    }
}
