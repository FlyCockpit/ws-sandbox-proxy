//! Template start/ready dispatch field (template builds ; additive in 1.0).
//!
//! A revision built from a recipe with `start` carries a start command and an
//! optional ready command. The server sends them as `startup` on
//! `sandbox.create` and `sandbox.reconnect` (and only to daemons advertising
//! `templateStartup`). After the VM boots, the daemon launches the start
//! command in the background as the guest user (never root; D1), then polls
//! the ready command until it exits 0 or `readyTimeoutMs` elapses, before it
//! reports READY. Absent everywhere else, so other frames stay byte-identical.

use serde::{Deserialize, Serialize};

/// Bound on `startup.command` and `startup.ready` (UTF-8 bytes).
pub const STARTUP_COMMAND_MAX_BYTES: usize = 4096;
/// Bound on `startup.cwd`.
pub const STARTUP_CWD_MAX_BYTES: usize = 4096;
/// Smallest and largest `startup.readyTimeoutMs`.
pub const STARTUP_READY_TIMEOUT_MIN_MS: u32 = 1_000;
pub const STARTUP_READY_TIMEOUT_MAX_MS: u32 = 600_000;
/// Ready budget when a ready command carries no explicit timeout.
pub const STARTUP_READY_TIMEOUT_DEFAULT_MS: u32 = 60_000;

/// `sandbox.create` / `sandbox.reconnect` start and ready commands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DispatchStartupV11 {
    /// Shell command launched in the background after boot.
    pub command: String,
    /// Shell command polled until it exits 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready: Option<String>,
    /// Ready budget; only with `ready`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready_timeout_ms: Option<u32>,
    /// Absolute guest working directory (the revision's default cwd).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
}

fn valid_command(value: &str) -> bool {
    !value.is_empty() && value.len() <= STARTUP_COMMAND_MAX_BYTES && !value.contains('\0')
}

pub(crate) fn valid_cwd(value: &str) -> bool {
    value.starts_with('/')
        && value.len() <= STARTUP_CWD_MAX_BYTES
        && !value.chars().any(char::is_control)
        && value.split('/').all(|segment| segment != "..")
}

impl DispatchStartupV11 {
    pub fn is_valid(&self) -> bool {
        valid_command(&self.command)
            && self.ready.as_deref().is_none_or(valid_command)
            && self.ready_timeout_ms.is_none_or(|ms| {
                self.ready.is_some()
                    && (STARTUP_READY_TIMEOUT_MIN_MS..=STARTUP_READY_TIMEOUT_MAX_MS).contains(&ms)
            })
            && self.cwd.as_deref().is_none_or(valid_cwd)
    }

    /// The effective ready budget (`None` without a ready command).
    pub fn ready_budget_ms(&self) -> Option<u32> {
        self.ready.as_ref().map(|_| {
            self.ready_timeout_ms
                .unwrap_or(STARTUP_READY_TIMEOUT_DEFAULT_MS)
        })
    }
}

/// `startup` rides only on launches and is valid.
pub(crate) fn valid_dispatch_startup(d: &crate::OperationDispatch) -> bool {
    d.startup.as_ref().is_none_or(|startup| {
        matches!(d.kind.as_str(), "sandbox.create" | "sandbox.reconnect")
            && d.build.is_none()
            && startup.is_valid()
    })
}
