//! The root-owned egress guard (see docs/guide/hosts.md#egress-guard).
//!
//! Pure, security-critical building blocks shared by the `wssp host guard`
//! service (apps/cli) and the daemon-side client ([`crate::GuardProbe`]):
//!
//! - [`ceiling`]: the egress ceiling host sockets obey (credential proxy);
//! - [`ruleset`]: the `inet wssp_guard` compiler (drops only) and the
//!   semantic readback verifier;
//! - [`routes`]: `scope4` / `uplinks` from every routing table, any length;
//! - [`path`]: the supported-packet-path checker (§2.0.1);
//! - [`sources`]: root-file and deployment policy sources with provenance;
//! - [`protocol`]: the `SO_PEERCRED`-authenticated socket protocol;
//! - [`status`]: maps source provenance onto the shared `GuardStatus`;
//! - [`client`]: the real `GuardProbe` (socket client);
//! - [`probe`]: the status format, the `GuardProbe` trait and the lease rule
//!   the daemon side evaluates.
//!
//! The guard never accepts; every chain contains only `return` and `drop`.

use std::time::Duration;

pub mod ceiling;
#[cfg(unix)]
pub mod client;
pub mod net;
pub mod path;
pub mod probe;
pub mod protocol;
pub mod routes;
pub mod ruleset;
pub mod sources;
pub mod status;

/// nftables table (family `inet`).
pub const TABLE: &str = "wssp_guard";
/// Compatibility level of the guard (ruleset shape, socket protocol and
/// status). The daemon requires at least its own build's value.
pub const GUARD_VERSION: u32 = 1;
/// Socket protocol revision carried in every status answer.
pub const PROTOCOL_VERSION: u32 = 1;

/// Sandbox bridges are `wsn-<10 hex>`; the guard matches `wsn-*`.
pub const BRIDGE_PREFIX: &str = "wsn-";

/// `raw - 10`: before conntrack (−200) and every DNAT (−100).
pub const PRE_PRIORITY: i32 = -310;
/// `filter - 300` on input and forward.
pub const INPUT_PRIORITY: i32 = -300;
pub const FORWARD_PRIORITY: i32 = -300;

/// Dead-man: `live_bridges` element timeout, renewed by every applied
/// resync (§2.0.3).
pub const LIVE_TIMEOUT: Duration = Duration::from_secs(30);
/// Health lease after the last fully successful resync (§2.0.5).
pub const LEASE: Duration = Duration::from_secs(15);
/// Full resync period (backstop to the event monitors).
pub const RESYNC_INTERVAL: Duration = Duration::from_secs(5);
/// Per child (`nft`, `ip`, `tc`, `conntrack`) timeout.
pub const CHILD_TIMEOUT: Duration = Duration::from_secs(5);

/// Installed paths (§2.0.4, §2.0.6).
pub const CONFIG_DIR: &str = "/etc/wssp";
pub const CONFIG_PATH: &str = "/etc/wssp/guard.toml";
pub const ROOT_BLOCKLIST_PATH: &str = "/etc/wssp/egress-blocklist";
pub const RUNTIME_DIR: &str = "/run/wssp-guard";
pub const SOCKET_PATH: &str = "/run/wssp-guard/guard.sock";
pub const STATUS_PATH: &str = "/run/wssp-guard/status.json";
pub const STATE_DIR: &str = "/var/lib/wssp-guard";
pub const INSTALL_DIR: &str = "/usr/local/lib/wssp";
pub const INSTALLED_BINARY: &str = "/usr/local/lib/wssp/wssp-guard";
pub const UNIT_NAME: &str = "wssp-guard.service";
pub const UNIT_PATH: &str = "/etc/systemd/system/wssp-guard.service";

/// NSS lookup of a user's uid (`wssp host guard install --daemon-user`).
#[cfg(target_os = "linux")]
pub fn lookup_user_uid(name: &str) -> std::io::Result<Option<u32>> {
    nix::unistd::User::from_name(name)
        .map(|user| user.map(|user| user.uid.as_raw()))
        .map_err(|errno| std::io::Error::from_raw_os_error(errno as i32))
}
