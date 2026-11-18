//! User configuration.
//!
//! The config file is TOML (comments allowed, friendly to hand-editing) and
//! lives at [`crate::paths::config_file`]. Loading is tolerant: a missing file
//! yields [`Config::default`], so a fresh install Just Works.
//!
//! Add a field: give it a `#[serde(default)]` (or make the whole struct default
//! via `#[serde(default)]` as below) so old config files keep parsing.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub allow_host_terminal: bool,
    pub allow_agent_host_commands: bool,
    pub host_command_max_ms: u64,
    pub host_file_roots: Vec<PathBuf>,
    pub agent_policy_revision: u64,
    pub agent_policy_enable_revision: u64,
    #[serde(default = "required_totp")]
    pub host_terminal_require_totp: bool,
    pub host_terminal_policy_revision: u64,
    /// Only the explicit local enable setter advances this unlatch witness.
    pub host_terminal_enable_revision: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox_vcpu_budget: Option<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub storage_pools: Vec<StoragePoolConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox_memory_mib: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_sandbox_cpu_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_slug: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_token_env: Option<String>,
    /// Host lease ceiling: the longest sandbox lifetime this machine accepts
    /// (`"6h"`, `"90m"`, `"7d"`, or `"unlimited"`). Default 24 hours. The
    /// running daemon reloads it and reports it; the server never raises it.
    #[serde(default, skip_serializing_if = "MaxLease::is_default")]
    pub max_lease: MaxLease,
    /// How long work that never started (queued or waiting before its first
    /// effect) is carried across a relay outage: `"10m"` (default), 1m..24h,
    /// never past the sandbox lease or `max_carry`. A restart applies it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carry_intent_window: Option<CarryIntentWindow>,
    /// The longest a running command is carried across a relay outage before
    /// the node stops it (`host_disconnect_expired`): `"24h"` (default),
    /// 10m..24d. A restart applies it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_carry: Option<MaxCarry>,
    /// Managed template image cache: `"auto"` (min(100 GiB, 15% of the
    /// storage pool)), a size in GiB (0..4096), or 0 to turn image fetch,
    /// serve and capture off. A restart applies it.
    #[serde(default, skip_serializing_if = "ImageCacheSize::is_default")]
    pub image_cache_gib: ImageCacheSize,
    /// Accept images owned by other accounts (shared pools). Off by default
    /// until the crafted-import qualification passes on this Incus version.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub accept_foreign_images: bool,
    /// How long another account's image stays after its last use (`"10m"`,
    /// `"0s"` for immediately; at most 24 hours).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub foreign_image_grace: Option<String>,
    /// Template builds: run build VMs here. Unset means on whenever capture
    /// is enabled (`image_cache_gib` is not 0); `false` opts this node out
    /// (build steps may run as guest root inside build VMs). A restart
    /// applies it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builder: Option<bool>,
    /// Run builds for other accounts (shared pools). Off by default; also
    /// needs `accept_foreign_images`. A restart applies it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub accept_foreign_builds: bool,
    /// CLI-logins proxy mode: the TCP port the credential proxy listens on,
    /// on each proxy-enabled sandbox's bridge gateway. Default 48080.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_proxy_port: Option<u16>,
    /// Let sandboxes from other users' pools reach the open internet from
    /// this machine. `None` means "not asked yet" and reads as off; your own
    /// sandboxes are never affected. A running daemon reloads it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_open_egress_for_others: Option<bool>,
    /// Let sandboxes from other users' pools have `sudo` (root inside their
    /// own VM) on this machine. `None` reads as on (the default); your own
    /// sandboxes are never affected. A running daemon reloads it; it applies
    /// to the next create or cold reconnect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_guest_sudo_for_others: Option<bool>,
    /// Reject outbound SMTP (tcp/25) from sandboxes. Default on. Applies to
    /// sandboxes created afterwards.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub egress_block_smtp: bool,
    /// Reject DNS (53/853) to resolvers other than the sandbox gateway.
    /// Default off. Applies to sandboxes created afterwards.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub egress_block_external_dns: bool,
    /// Upstream resolvers for open-mode sandboxes (at most 4 unicast IPv4);
    /// empty uses the host resolvers. Applies to sandboxes created afterwards.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_dns_upstreams"
    )]
    pub egress_dns_upstreams: Vec<std::net::Ipv4Addr>,
    /// Graceful restart (`wssp daemon quiesce`, the service's reload): how
    /// long the daemon waits for running commands before it restarts
    /// (`"10m"`, `"90s"`, `"1h"`; at most 24 hours). Default 10 minutes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quiesce_max: Option<String>,
    /// How long a sandbox terminal whose relay connection was lost stays
    /// open for the browser to reattach (`"120s"`, `"5m"`). Default 2
    /// minutes, clamped to 1 s ..= 10 minutes. A restart applies it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_resume_grace: Option<String>,
    /// Stopped-sandbox disk offload: the upload rate cap in megabits per
    /// second (1 Mbps = 125 000 bytes/s); 0 or unset is unlimited. A restart
    /// applies it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offload_upload_mbps: Option<u32>,
    /// Restore of an offloaded disk: the fetch rate cap in megabits per
    /// second; 0 or unset is unlimited. A restart applies it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offload_fetch_mbps: Option<u32>,
    /// Preview tunnels: the pinned `tunnel` client this node runs outside
    /// the guests (set by `wssp tunnel install`). Absent: no tunnels here.
    /// A restart applies it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel: Option<TunnelConfig>,
}

/// `[tunnel]`: the hash-pinned client and the node owner's limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelConfig {
    /// Absolute path of the client binary.
    pub client: PathBuf,
    /// Its SHA-256 (lowercase hex); checked before every client start.
    pub client_sha256: String,
    /// Most tunnel clients at once (1..=256, default 16).
    #[serde(default = "default_max_tunnels")]
    pub max_tunnels: u32,
    /// Let sandboxes from other users' pools use tunnels on this machine
    /// (bandwidth and outbound connections). Default off.
    #[serde(default)]
    pub allow_for_others: bool,
}

fn default_max_tunnels() -> u32 {
    16
}

impl TunnelConfig {
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.client.is_absolute(),
            "`[tunnel] client` must be an absolute path"
        );
        anyhow::ensure!(
            self.client_sha256.len() == 64
                && self
                    .client_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "`[tunnel] client_sha256` must be 64 lowercase hex characters"
        );
        anyhow::ensure!(
            (1..=256).contains(&self.max_tunnels),
            "`[tunnel] max_tunnels` must be 1..=256"
        );
        Ok(())
    }
}

fn default_true() -> bool {
    true
}

/// Megabits per second to bytes per second; 0 or unset is unlimited.
fn mbps_bytes(mbps: Option<u32>) -> Option<u64> {
    mbps.filter(|&rate| rate > 0)
        .map(|rate| u64::from(rate) * 125_000)
}
fn is_true(value: &bool) -> bool {
    *value
}

/// `egress_dns_upstreams`: at most 4 unicast IPv4 addresses (the runtime's
/// own `EgressSettings` bound). An invalid list fails the whole read, which
/// the running daemon treats as an unreadable config (fail closed).
pub fn validate_dns_upstreams(upstreams: &[std::net::Ipv4Addr]) -> Result<()> {
    sandbox_runtime::egress::EgressSettings {
        dns_upstreams: upstreams.to_vec(),
        ..Default::default()
    }
    .validate()
    .map_err(|err| anyhow::anyhow!("{}", err.message))
}

fn deserialize_dns_upstreams<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<std::net::Ipv4Addr>, D::Error> {
    let upstreams = Vec::<std::net::Ipv4Addr>::deserialize(deserializer)?;
    validate_dns_upstreams(&upstreams).map_err(serde::de::Error::custom)?;
    Ok(upstreams)
}

/// Parse `--egress-dns-upstreams 1.1.1.1,9.9.9.9` (comma-separated).
pub fn parse_dns_upstreams(text: &str) -> Result<Vec<std::net::Ipv4Addr>> {
    let upstreams = text
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| {
            item.parse::<std::net::Ipv4Addr>()
                .with_context(|| format!("invalid IPv4 address `{item}`"))
        })
        .collect::<Result<Vec<_>>>()?;
    anyhow::ensure!(
        !upstreams.is_empty(),
        "give at least one IPv4 address, or use --clear"
    );
    validate_dns_upstreams(&upstreams)?;
    Ok(upstreams)
}

impl Config {
    /// Open egress for other users' sandboxes (`None`, not asked, is off).
    pub fn open_egress_for_others(&self) -> bool {
        self.allow_open_egress_for_others.unwrap_or(false)
    }
    /// Guest sudo for other users' sandboxes (`None` is the default, on).
    pub fn guest_sudo_for_others(&self) -> bool {
        self.allow_guest_sudo_for_others.unwrap_or(true)
    }
    /// The node part of `EgressSettings` (§2.1); the domain blocklist comes
    /// from the guard at materialization, never from this file.
    pub fn egress_settings(&self) -> sandbox_runtime::egress::EgressSettings {
        sandbox_runtime::egress::EgressSettings {
            block_smtp: self.egress_block_smtp,
            block_external_dns: self.egress_block_external_dns,
            dns_upstreams: self.egress_dns_upstreams.clone(),
            domain_blocklist: Default::default(),
            credential_proxy_port: None,
            refused_dns_stub_port: None,
            tunnel_ports: None,
            tunnel_revision: 0,
            tunnel_pending: None,
        }
    }

    /// The validated `[tunnel]` section; an invalid one is logged and off.
    pub(crate) fn tunnel_settings(&self) -> Option<crate::sandbox_relay::tunnel::TunnelSettings> {
        let tunnel = self.tunnel.as_ref()?;
        if let Err(error) = tunnel.validate() {
            tracing::warn!(%error, "invalid [tunnel] section; preview tunnels are off");
            return None;
        }
        Some(crate::sandbox_relay::tunnel::TunnelSettings {
            client: tunnel.client.clone(),
            client_sha256: tunnel.client_sha256.clone(),
            max_tunnels: tunnel.max_tunnels,
            allow_for_others: tunnel.allow_for_others,
        })
    }
}

/// `image_cache_gib`: automatic or a fixed GiB budget (0 disables).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ImageCacheSize {
    #[default]
    Auto,
    Gib(u32),
}

impl ImageCacheSize {
    pub fn is_default(&self) -> bool {
        *self == Self::Auto
    }
    pub fn parse(text: &str) -> Result<Self> {
        let text = text.trim();
        if text.eq_ignore_ascii_case("auto") {
            return Ok(Self::Auto);
        }
        let gib: u32 = text
            .parse()
            .with_context(|| format!("invalid image cache size `{text}`: use auto or 0..4096"))?;
        anyhow::ensure!(gib <= 4096, "image cache size must be at most 4096 GiB");
        Ok(Self::Gib(gib))
    }
    /// Cache budget in bytes for a store whose backing pool holds `total_bytes`.
    pub fn bytes_for(self, total_bytes: u64) -> u64 {
        const GIB: u64 = 1 << 30;
        match self {
            Self::Gib(gib) => u64::from(gib) * GIB,
            Self::Auto => (100 * GIB).min(total_bytes / 100 * 15),
        }
    }
}

impl std::fmt::Display for ImageCacheSize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auto => f.write_str("auto"),
            Self::Gib(gib) => write!(f, "{gib}"),
        }
    }
}

impl Serialize for ImageCacheSize {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Auto => serializer.serialize_str("auto"),
            Self::Gib(gib) => serializer.serialize_u32(*gib),
        }
    }
}

impl<'de> Deserialize<'de> for ImageCacheSize {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Text(String),
            Number(u32),
        }
        match Raw::deserialize(deserializer)? {
            Raw::Text(text) => Self::parse(&text).map_err(serde::de::Error::custom),
            Raw::Number(gib) if gib <= 4096 => Ok(Self::Gib(gib)),
            Raw::Number(_) => Err(serde::de::Error::custom(
                "image cache size must be at most 4096 GiB",
            )),
        }
    }
}

/// Parse `foreign_image_grace` or `quiesce_max` (`"10m"`, `"90s"`, `"2h"`,
/// `"0"`), at most 24 hours.
pub fn parse_grace(text: &str) -> Result<std::time::Duration> {
    let text = text.trim();
    let (number, unit) = text.split_at(
        text.find(|c: char| !c.is_ascii_digit())
            .unwrap_or(text.len()),
    );
    let value: u64 = number
        .parse()
        .with_context(|| format!("invalid duration `{text}`"))?;
    let seconds = match unit {
        "" | "s" => value,
        "m" => value.saturating_mul(60),
        "h" => value.saturating_mul(3600),
        _ => anyhow::bail!("invalid duration unit in `{text}`: use s, m or h"),
    };
    anyhow::ensure!(seconds <= 86_400, "duration `{text}` must be at most 24h");
    Ok(std::time::Duration::from_secs(seconds))
}

impl Config {
    pub fn foreign_grace(&self) -> std::time::Duration {
        self.foreign_image_grace
            .as_deref()
            .and_then(|text| parse_grace(text).ok())
            .unwrap_or(std::time::Duration::from_secs(600))
    }

    /// `quiesce_max`: the graceful restart's wait for running commands
    /// (default 10 minutes). An unparsable value keeps the default.
    pub fn quiesce_max(&self) -> std::time::Duration {
        const DEFAULT: std::time::Duration = std::time::Duration::from_secs(600);
        match self.quiesce_max.as_deref().map(parse_grace) {
            None => DEFAULT,
            Some(Ok(value)) => value,
            Some(Err(error)) => {
                tracing::warn!("ignoring `quiesce_max`: {error:#}; using 10m");
                DEFAULT
            }
        }
    }

    /// The terminal reattach grace (`terminal_resume_grace`, D5): default
    /// 120 s, clamped to 1 s ..= 10 minutes. An unparsable value keeps the
    /// default (like `foreign_image_grace`).
    pub fn terminal_resume_grace(&self) -> std::time::Duration {
        use sandbox_protocol::{
            TERMINAL_RESUME_GRACE_DEFAULT_MS, TERMINAL_RESUME_GRACE_MAX_MS,
            TERMINAL_RESUME_GRACE_MIN_MS,
        };
        let ms = self
            .terminal_resume_grace
            .as_deref()
            .and_then(|text| parse_grace(text).ok())
            .map_or(TERMINAL_RESUME_GRACE_DEFAULT_MS, |grace| {
                u64::try_from(grace.as_millis()).unwrap_or(u64::MAX)
            });
        std::time::Duration::from_millis(
            ms.clamp(TERMINAL_RESUME_GRACE_MIN_MS, TERMINAL_RESUME_GRACE_MAX_MS),
        )
    }

    /// The credential proxy port (`credential_proxy_port`, default 48080;
    /// 0 falls back to the default).
    pub fn credential_proxy_port(&self) -> u16 {
        match self.credential_proxy_port {
            Some(port) if port != 0 => port,
            _ => 48080,
        }
    }
}

fn required_totp() -> bool {
    true
}

/// A host lease ceiling: finite milliseconds (5 minutes .. 24 days) or
/// unlimited. Serialized as a duration string such as `"6h"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaxLease {
    Finite(u64),
    Unlimited,
}

impl Default for MaxLease {
    fn default() -> Self {
        Self::Finite(sandbox_protocol::DEFAULT_MAX_LEASE_MS)
    }
}

const LEASE_UNITS: [(char, u64); 3] = [('d', 86_400_000), ('h', 3_600_000), ('m', 60_000)];

impl MaxLease {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
    /// The journal and wire form: `None` means unlimited.
    pub fn ceiling_ms(self) -> Option<u64> {
        match self {
            Self::Finite(ms) => Some(ms),
            Self::Unlimited => None,
        }
    }
    pub fn parse(text: &str) -> Result<Self> {
        let text = text.trim();
        if text == "unlimited" {
            return Ok(Self::Unlimited);
        }
        let invalid = || {
            anyhow::anyhow!(
                "invalid lease ceiling: use a whole number of minutes (m), hours (h) or days (d) between 5m and 24d, or `unlimited`"
            )
        };
        let ms = parse_duration_ms(text).ok_or_else(invalid)?;
        anyhow::ensure!(
            (sandbox_protocol::LEASE_CEILING_MIN_MS..=sandbox_protocol::LEASE_CEILING_MAX_MS)
                .contains(&ms),
            invalid()
        );
        Ok(Self::Finite(ms))
    }
}

impl std::fmt::Display for MaxLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unlimited => f.write_str("unlimited"),
            Self::Finite(ms) => f.write_str(&format_duration_ms(*ms)),
        }
    }
}

/// A whole number of minutes, hours or days within `MIN_MS..=MAX_MS`,
/// written like `max_lease` (`"90m"`, `"6h"`, `"7d"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundedDuration<const MIN_MS: u64, const MAX_MS: u64, const DEFAULT_MS: u64>(u64);

/// `carry_intent_window`: 1 minute to 24 hours, default 10 minutes.
pub type CarryIntentWindow = BoundedDuration<60_000, 86_400_000, 600_000>;
/// `max_carry`: 10 minutes to 24 days, default 24 hours.
pub type MaxCarry = BoundedDuration<600_000, 2_073_600_000, 86_400_000>;

impl<const MIN_MS: u64, const MAX_MS: u64, const DEFAULT_MS: u64>
    BoundedDuration<MIN_MS, MAX_MS, DEFAULT_MS>
{
    pub fn default_value() -> Self {
        Self(DEFAULT_MS)
    }
    pub fn duration(self) -> std::time::Duration {
        std::time::Duration::from_millis(self.0)
    }
    /// `default` means "unset" (`None`); anything else must be in bounds.
    pub fn parse_setting(text: &str) -> Result<Option<Self>> {
        if text.trim() == "default" {
            return Ok(None);
        }
        Self::parse(text).map(Some)
    }
    pub fn parse(text: &str) -> Result<Self> {
        let invalid = || {
            anyhow::anyhow!(
                "invalid duration: use a whole number of minutes (m), hours (h) or days (d) between {} and {}",
                format_duration_ms(MIN_MS),
                format_duration_ms(MAX_MS)
            )
        };
        let ms = parse_duration_ms(text.trim()).ok_or_else(invalid)?;
        anyhow::ensure!((MIN_MS..=MAX_MS).contains(&ms), invalid());
        Ok(Self(ms))
    }
}

impl<const MIN_MS: u64, const MAX_MS: u64, const DEFAULT_MS: u64> std::fmt::Display
    for BoundedDuration<MIN_MS, MAX_MS, DEFAULT_MS>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format_duration_ms(self.0))
    }
}

impl<const MIN_MS: u64, const MAX_MS: u64, const DEFAULT_MS: u64> Serialize
    for BoundedDuration<MIN_MS, MAX_MS, DEFAULT_MS>
{
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de, const MIN_MS: u64, const MAX_MS: u64, const DEFAULT_MS: u64> Deserialize<'de>
    for BoundedDuration<MIN_MS, MAX_MS, DEFAULT_MS>
{
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(|_| serde::de::Error::custom("invalid duration"))
    }
}

/// `<digits><m|h|d>` in milliseconds; `None` when malformed or overflowing.
fn parse_duration_ms(text: &str) -> Option<u64> {
    let unit = text.chars().last()?;
    let scale = LEASE_UNITS
        .iter()
        .find(|(suffix, _)| *suffix == unit)
        .map(|(_, scale)| *scale)?;
    let digits = &text[..text.len() - unit.len_utf8()];
    if digits.is_empty() || digits.len() > 9 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u64>().ok()?.checked_mul(scale)
}

/// The shortest unit form; days from two days up (`24h` reads better than `1d`).
fn format_duration_ms(ms: u64) -> String {
    let (suffix, scale) = LEASE_UNITS
        .iter()
        .copied()
        .find(|(suffix, scale)| ms.is_multiple_of(*scale) && (*suffix != 'd' || ms >= 2 * scale))
        .unwrap_or(('m', 60_000));
    format!("{}{suffix}", ms / scale)
}

impl Serialize for MaxLease {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for MaxLease {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(|_| serde::de::Error::custom("invalid max_lease"))
    }
}
impl Default for Config {
    fn default() -> Self {
        Self {
            allow_host_terminal: false,
            allow_agent_host_commands: false,
            host_command_max_ms: 600_000,
            host_file_roots: Vec::new(),
            agent_policy_revision: 0,
            agent_policy_enable_revision: 0,
            host_terminal_require_totp: true,
            host_terminal_policy_revision: 0,
            host_terminal_enable_revision: 0,
            sandbox_vcpu_budget: None,
            storage_pools: Vec::new(),
            sandbox_memory_mib: None,
            max_sandbox_cpu_count: None,
            server_url: None,
            ca_file: None,
            host_slug: None,
            host_token_env: None,
            max_lease: MaxLease::default(),
            carry_intent_window: None,
            max_carry: None,
            image_cache_gib: ImageCacheSize::Auto,
            accept_foreign_images: false,
            foreign_image_grace: None,
            builder: None,
            accept_foreign_builds: false,
            credential_proxy_port: None,
            allow_open_egress_for_others: None,
            allow_guest_sudo_for_others: None,
            egress_block_smtp: true,
            egress_block_external_dns: false,
            egress_dns_upstreams: Vec::new(),
            quiesce_max: None,
            terminal_resume_grace: None,
            offload_upload_mbps: None,
            offload_fetch_mbps: None,
            tunnel: None,
        }
    }
}
impl Config {
    pub fn set_agent_host_commands(&mut self, enabled: bool) -> Result<()> {
        self.bump_agent_policy()?;
        self.allow_agent_host_commands = enabled;
        if enabled {
            self.agent_policy_enable_revision = self.agent_policy_revision;
        }
        Ok(())
    }
    pub fn set_host_command_max_ms(&mut self, ms: u64) -> Result<()> {
        anyhow::ensure!(
            sandbox_protocol::valid_host_command_max_ms(ms),
            "host command time must be 1..86400 seconds"
        );
        self.bump_agent_policy()?;
        if ms > self.host_command_max_ms {
            self.agent_policy_enable_revision = self.agent_policy_revision;
        }
        self.host_command_max_ms = ms;
        Ok(())
    }
    pub fn set_host_file_roots(&mut self, roots: &[PathBuf]) -> Result<()> {
        anyhow::ensure!(roots.len() <= 32, "at most 32 host file roots are allowed");
        let mut canonical = Vec::new();
        for root in roots {
            anyhow::ensure!(
                root.is_absolute(),
                "host file roots must be absolute directories"
            );
            let path = root
                .canonicalize()
                .map_err(|_| anyhow::anyhow!("host file root is not accessible"))?;
            anyhow::ensure!(
                path.parent().is_some() && path.is_dir(),
                "host file roots must be directories other than `/`"
            );
            if !canonical.contains(&path) {
                canonical.push(path);
            }
        }
        self.bump_agent_policy()?;
        if canonical.iter().any(|p| !self.host_file_roots.contains(p)) {
            self.agent_policy_enable_revision = self.agent_policy_revision;
        }
        self.host_file_roots = canonical;
        Ok(())
    }
    fn bump_agent_policy(&mut self) -> Result<()> {
        anyhow::ensure!(
            self.agent_policy_revision < sandbox_protocol::HOST_SAFE_INTEGER,
            "agent policy revision exhausted"
        );
        self.agent_policy_revision += 1;
        Ok(())
    }
    pub fn validate_agent_policy(&self) -> Result<()> {
        anyhow::ensure!(
            sandbox_protocol::valid_host_command_max_ms(self.host_command_max_ms),
            "invalid host command time"
        );
        anyhow::ensure!(
            self.agent_policy_revision <= sandbox_protocol::HOST_SAFE_INTEGER
                && self.agent_policy_enable_revision <= self.agent_policy_revision,
            "invalid agent policy revision"
        );
        anyhow::ensure!(
            self.host_file_roots.len() <= 32
                && self.host_file_roots.iter().all(|p| p.is_absolute()
                    && p.parent().is_some()
                    && p.canonicalize().is_ok_and(|c| c == *p && c.is_dir())),
            "invalid host file roots"
        );
        Ok(())
    }
    pub fn set_host_terminal(&mut self, enabled: bool) -> Result<()> {
        self.bump_terminal_policy()?;
        self.allow_host_terminal = enabled;
        if enabled {
            self.host_terminal_enable_revision = self.host_terminal_policy_revision;
        }
        Ok(())
    }
    pub fn set_host_terminal_totp(&mut self, required: bool) -> Result<()> {
        self.bump_terminal_policy()?;
        if !required {
            self.host_terminal_enable_revision = self.host_terminal_policy_revision;
        }
        self.host_terminal_require_totp = required;
        Ok(())
    }
    /// The lease ceiling is deliberately not part of the terminal policy tuple:
    /// changing it never bumps `host_terminal_policy_revision`.
    pub fn set_max_lease(&mut self, value: MaxLease) {
        self.max_lease = value;
    }
    /// `None` restores the default (10 minutes).
    pub fn set_carry_intent_window(&mut self, value: Option<CarryIntentWindow>) {
        self.carry_intent_window = value;
    }
    /// `None` restores the default (24 hours).
    pub fn set_max_carry(&mut self, value: Option<MaxCarry>) {
        self.max_carry = value;
    }
    /// The configured Intent-phase carry window (`carry_intent_window`).
    pub fn carry_intent_window(&self) -> std::time::Duration {
        self.carry_intent_window
            .unwrap_or_else(CarryIntentWindow::default_value)
            .duration()
    }
    /// The configured carry cap for running work (`max_carry`).
    pub fn max_carry(&self) -> std::time::Duration {
        self.max_carry
            .unwrap_or_else(MaxCarry::default_value)
            .duration()
    }
    /// `None` restores the default (on when capture is enabled).
    pub fn set_builder(&mut self, value: Option<bool>) {
        self.builder = value;
    }
    pub fn set_accept_foreign_builds(&mut self, value: bool) {
        self.accept_foreign_builds = value;
    }
    /// Whether this node runs template builds, given whether its image cache
    /// (and so capture) is enabled.
    pub fn builder_enabled(&self, capture_enabled: bool) -> bool {
        capture_enabled && self.builder != Some(false)
    }
    /// `offload_upload_mbps` as bytes per second (`None`: unlimited).
    pub fn offload_upload_bytes_per_sec(&self) -> Option<u64> {
        mbps_bytes(self.offload_upload_mbps)
    }
    /// `offload_fetch_mbps` as bytes per second (`None`: unlimited).
    pub fn offload_fetch_bytes_per_sec(&self) -> Option<u64> {
        mbps_bytes(self.offload_fetch_mbps)
    }
    fn bump_terminal_policy(&mut self) -> Result<()> {
        anyhow::ensure!(
            self.host_terminal_policy_revision < 9_007_199_254_740_991,
            "terminal policy revision exhausted"
        );
        self.host_terminal_policy_revision += 1;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoragePoolConfig {
    pub name: String,
    pub capacity_gib: u32,
    #[serde(default)]
    pub draining: bool,
}

impl Config {
    pub fn validate_storage(&self) -> Result<()> {
        let limits = sandbox_protocol::vm_size_limits()?;
        anyhow::ensure!(
            self.storage_pools.len() <= limits.storage_pool_max,
            "too many storage pools"
        );
        let mut names = std::collections::HashSet::new();
        for pool in &self.storage_pools {
            let identity = sandbox_runtime::StoragePoolIdentity {
                name: pool.name.clone(),
                storage_id: "0".repeat(32),
            };
            anyhow::ensure!(identity.validate().is_ok(), "invalid storage pool name");
            anyhow::ensure!(names.insert(&pool.name), "duplicate storage pool name");
            anyhow::ensure!(
                (1..=limits.storage_capacity_gi_b_max).contains(&pool.capacity_gib),
                "invalid storage pool capacity_gib"
            );
        }
        Ok(())
    }
}

pub fn validate_env_name(name: &str) -> Result<()> {
    let valid = name.strip_prefix("WSSP_").is_some_and(|suffix| {
        (1..=64).contains(&suffix.len())
            && suffix
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
    });
    anyhow::ensure!(
        valid,
        "host token environment name must match `^WSSP_[A-Z0-9_]{{1,64}}$`"
    );
    Ok(())
}
impl Config {
    pub(crate) fn read(path: &Path) -> Result<Self> {
        let (config, diagnostics) = Self::read_for_inspection(path)?;
        anyhow::ensure!(diagnostics.is_empty(), "{}", diagnostics.join("; "));
        Ok(config)
    }

    /// Inspect capacity values without losing valid fields or echoing TOML text.
    /// The regular loader refuses the same diagnostics for commands that act.
    pub(crate) fn read_for_inspection(path: &Path) -> Result<(Self, Vec<&'static str>)> {
        use std::io::Read;
        let text = match std::fs::File::open(path) {
            Ok(file) => {
                let mut text = String::new();
                file.take(65537)
                    .read_to_string(&mut text)
                    .context("reading bounded config file")?;
                anyhow::ensure!(text.len() <= 65536, "config file exceeds byte bound");
                text
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok((Self::default(), Vec::new()));
            }
            Err(error) => return Err(error).context("reading config file"),
        };
        // Preserve byte offsets while masking invalid capacity assignments so
        // later parser/type errors still point into the original document.
        let mut sanitized = text.clone();
        let mut diagnostics = Vec::new();
        let values: std::collections::HashMap<toml::Spanned<String>, toml::Spanned<toml::Value>> = loop {
            match toml::from_str(&sanitized) {
                Ok(value) => break value,
                Err(error) => {
                    // Numeric overflow can fail before a TOML value exists.
                    // Recognize only a capacity assignment at the error line;
                    // never include its raw value in a diagnostic.
                    let span = error.span().unwrap_or(0..0);
                    let start = sanitized[..span.start].rfind('\n').map_or(0, |p| p + 1);
                    let end = sanitized[span.start..]
                        .find('\n')
                        .map_or(sanitized.len(), |p| span.start + p);
                    let key = sanitized[start..end]
                        .split_once('=')
                        .map(|(key, _)| key.trim());
                    let diagnostic = match key {
                        Some("sandbox_memory_mib") => {
                            "invalid config file value for `sandbox_memory_mib`"
                        }
                        Some("sandbox_vcpu_budget") => {
                            "invalid config file value for `sandbox_vcpu_budget`"
                        }
                        Some("max_sandbox_cpu_count") => {
                            "invalid config file value for `max_sandbox_cpu_count`"
                        }
                        _ => return Err(config_parse_error(&text, &error, "invalid TOML")),
                    };
                    diagnostics.push(diagnostic);
                    mask_config_range(&mut sanitized, start..end);
                }
            }
        };
        for (key, diagnostic, dimension) in [
            (
                "sandbox_memory_mib",
                "invalid config file value for `sandbox_memory_mib`",
                0,
            ),
            (
                "max_sandbox_cpu_count",
                "invalid config file value for `max_sandbox_cpu_count`",
                1,
            ),
            (
                "sandbox_vcpu_budget",
                "invalid config file value for `sandbox_vcpu_budget`",
                2,
            ),
        ] {
            if let Some((field, raw)) = values.iter().find(|(field, _)| field.get_ref() == key) {
                let valid = raw
                    .get_ref()
                    .as_integer()
                    .and_then(|v| u32::try_from(v).ok())
                    .is_some_and(|v| {
                        if dimension == 0 {
                            sandbox_protocol::VmCapacity::new(v, 1).is_ok()
                        } else if dimension == 1 {
                            sandbox_protocol::VmCapacity::new(512, v).is_ok()
                        } else {
                            sandbox_protocol::vm_size_limits().is_ok_and(|l| {
                                (l.host_vcpu_budget_min..=l.host_vcpu_budget_max).contains(&v)
                            })
                        }
                    });
                if !valid {
                    diagnostics.push(diagnostic);
                    let span = raw.span();
                    let start = sanitized[..field.span().start]
                        .rfind('\n')
                        .map_or(0, |p| p + 1);
                    mask_config_range(&mut sanitized, start..span.end);
                }
            }
        }
        let mut config: Self = toml::from_str(&sanitized)
            .map_err(|error| config_parse_error(&text, &error, "invalid field type"))?;
        if config.host_terminal_policy_revision > 9_007_199_254_740_991
            || config.host_terminal_enable_revision > config.host_terminal_policy_revision
        {
            diagnostics.push("invalid host terminal policy revision");
            config.allow_host_terminal = false;
            config.host_terminal_require_totp = true;
            config.host_terminal_policy_revision = 0;
            config.host_terminal_enable_revision = 0;
        }
        if config.validate_agent_policy().is_err() {
            diagnostics.push("invalid host agent policy");
            config.allow_agent_host_commands = false;
            config.host_file_roots.clear();
            config.host_command_max_ms = 600_000;
            config.agent_policy_revision = 0;
            config.agent_policy_enable_revision = 0;
        }
        if config.validate_storage().is_err() {
            diagnostics.push("invalid storage_pools configuration");
            config.storage_pools.clear();
        }
        Ok((config, diagnostics))
    }
    pub fn load() -> Result<Self> {
        Ok(crate::state::AuthStore::open(None)?.snapshot()?.0)
    }
    pub fn update<T>(mutate: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        crate::state::AuthStore::open(None)?.update_config(mutate)
    }
    pub fn save_new(&self) -> Result<bool> {
        crate::state::AuthStore::open(None)?.init_config()
    }
}

/// Hide source snippets and values while retaining the original TOML location.
fn config_parse_error(text: &str, error: &toml::de::Error, kind: &str) -> anyhow::Error {
    if let Some(prefix) = error.span().and_then(|span| text.get(..span.start)) {
        let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
        let column = prefix.rsplit('\n').next().unwrap_or("").chars().count() + 1;
        anyhow::anyhow!("parsing config file: {kind} at line {line}, column {column}")
    } else {
        anyhow::anyhow!("parsing config file: {kind}")
    }
}

fn mask_config_range(text: &mut String, range: std::ops::Range<usize>) {
    let blank: String = text.as_bytes()[range.clone()]
        .iter()
        .map(|byte| if *byte == b'\n' { '\n' } else { ' ' })
        .collect();
    text.replace_range(range, &blank);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_capacities_preserve_all_other_fields_and_each_other() {
        for capacity in [
            "sandbox_memory_mib = 18446744073709551616\nmax_sandbox_cpu_count = 4\n",
            "sandbox_memory_mib = 2048\nmax_sandbox_cpu_count = 18446744073709551616\n",
            "sandbox_memory_mib = 18446744073709551616\nmax_sandbox_cpu_count = 18446744073709551616\n",
            "sandbox_memory_mib = [\n  123,\n  456\n]\nmax_sandbox_cpu_count = 4\n",
            "\"sandbox_memory_mib\" = \"\"\"invalid\nmultiple lines\"\"\"\nmax_sandbox_cpu_count = 4\n",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("config.toml");
            let text = format!(
                "server_url = \"https://config.example\"\nca_file = \"ca.pem\"\nhost_slug = \"retained\"\nhost_token_env = \"WSSP_TEST\"\n{capacity}"
            );
            std::fs::write(&path, &text).unwrap();
            let (config, diagnostics) = Config::read_for_inspection(&path).unwrap();
            assert_eq!(config.server_url.as_deref(), Some("https://config.example"));
            assert_eq!(config.ca_file.as_deref(), Some(Path::new("ca.pem")));
            assert_eq!(config.host_slug.as_deref(), Some("retained"));
            assert_eq!(config.host_token_env.as_deref(), Some("WSSP_TEST"));
            assert_eq!(
                config.sandbox_memory_mib,
                capacity.contains("= 2048").then_some(2048)
            );
            assert_eq!(
                config.max_sandbox_cpu_count,
                capacity.contains("= 4\n").then_some(4)
            );
            assert_eq!(
                diagnostics.len(),
                if capacity.matches("18446744073709551616").count() == 2 {
                    2
                } else {
                    1
                }
            );
            assert!(
                diagnostics
                    .iter()
                    .all(|message| !message.contains("18446744073709551616"))
            );
            assert!(Config::read(&path).is_err());
            assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
        }
    }

    #[test]
    fn max_lease_parses_formats_and_bounds() {
        for (text, ms) in [
            ("5m", Some(300_000)),
            ("90m", Some(5_400_000)),
            ("6h", Some(21_600_000)),
            ("24h", Some(86_400_000)),
            ("7d", Some(604_800_000)),
            ("24d", Some(2_073_600_000)),
            ("unlimited", None),
        ] {
            let parsed = MaxLease::parse(text).unwrap();
            assert_eq!(parsed.ceiling_ms(), ms, "{text}");
            assert_eq!(MaxLease::parse(&parsed.to_string()).unwrap(), parsed);
        }
        assert_eq!(MaxLease::parse("1440m").unwrap().to_string(), "24h");
        assert_eq!(MaxLease::parse("1d").unwrap().to_string(), "24h");
        assert_eq!(MaxLease::parse("48h").unwrap().to_string(), "2d");
        assert_eq!(MaxLease::parse("90m").unwrap().to_string(), "90m");
        for invalid in [
            "",
            "4m",
            "25d",
            "577h",
            "0h",
            "h",
            "6",
            "6s",
            "6H",
            "-1h",
            "1.5h",
            "6 h",
            "+6h",
            "99999999999999999999d",
            "Unlimited",
            "∞",
            "6hh",
        ] {
            assert!(MaxLease::parse(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn max_lease_defaults_to_24h_and_invalid_values_fail_the_read() {
        let config: Config = toml::from_str("").unwrap();
        assert_eq!(config.max_lease.ceiling_ms(), Some(86_400_000));
        assert!(!toml::to_string(&config).unwrap().contains("max_lease"));
        let mut config = Config::default();
        config.set_max_lease(MaxLease::Unlimited);
        let text = toml::to_string(&config).unwrap();
        assert!(text.contains("max_lease = \"unlimited\""), "{text}");
        assert_eq!(toml::from_str::<Config>(&text).unwrap(), config);
        assert_eq!(config.host_terminal_policy_revision, 0);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "max_lease = \"forever\"\n").unwrap();
        assert!(Config::read(&path).is_err());
        std::fs::write(&path, "max_lease = \"6h\"\n").unwrap();
        assert_eq!(
            Config::read(&path).unwrap().max_lease,
            MaxLease::Finite(21_600_000)
        );
    }

    #[test]
    fn carry_settings_parse_bound_default_and_round_trip() {
        use std::time::Duration;
        let config: Config = toml::from_str("").unwrap();
        assert_eq!(config.carry_intent_window(), Duration::from_secs(600));
        assert_eq!(config.max_carry(), Duration::from_secs(86_400));
        let text = toml::to_string(&config).unwrap();
        assert!(!text.contains("carry"), "{text}");
        for (text, ms) in [("1m", 60_000), ("10m", 600_000), ("24h", 86_400_000)] {
            let parsed = CarryIntentWindow::parse(text).unwrap();
            assert_eq!(parsed.duration(), Duration::from_millis(ms), "{text}");
            assert_eq!(
                CarryIntentWindow::parse(&parsed.to_string()).unwrap(),
                parsed
            );
        }
        for invalid in [
            "", "0m", "59s", "30s", "25h", "2d", "10", "10M", "1.5h", "default",
        ] {
            assert!(CarryIntentWindow::parse(invalid).is_err(), "{invalid}");
        }
        for (text, ms) in [
            ("10m", 600_000),
            ("24h", 86_400_000),
            ("7d", 604_800_000),
            ("24d", 2_073_600_000),
        ] {
            let parsed = MaxCarry::parse(text).unwrap();
            assert_eq!(parsed.duration(), Duration::from_millis(ms), "{text}");
            assert_eq!(MaxCarry::parse(&parsed.to_string()).unwrap(), parsed);
        }
        for invalid in ["9m", "25d", "577h", "unlimited", "0h", "-1h"] {
            assert!(MaxCarry::parse(invalid).is_err(), "{invalid}");
        }
        assert_eq!(MaxCarry::parse_setting("default").unwrap(), None);
        assert!(MaxCarry::parse_setting("1m").is_err());

        let mut config = Config::default();
        config.set_carry_intent_window(Some(CarryIntentWindow::parse("30m").unwrap()));
        config.set_max_carry(Some(MaxCarry::parse("7d").unwrap()));
        let text = toml::to_string(&config).unwrap();
        assert!(text.contains("carry_intent_window = \"30m\""), "{text}");
        assert!(text.contains("max_carry = \"7d\""), "{text}");
        assert_eq!(toml::from_str::<Config>(&text).unwrap(), config);
        assert_eq!(config.carry_intent_window(), Duration::from_secs(1800));
        assert_eq!(config.max_carry(), Duration::from_secs(7 * 86_400));
        // The setters never touch the terminal policy tuple.
        assert_eq!(config.host_terminal_policy_revision, 0);
        config.set_max_carry(None);
        assert_eq!(config.max_carry(), Duration::from_secs(86_400));

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "max_carry = \"forever\"\n").unwrap();
        assert!(Config::read(&path).is_err());
        std::fs::write(&path, "carry_intent_window = \"25h\"\n").unwrap();
        assert!(Config::read(&path).is_err());
    }

    #[test]
    fn round_trips_through_toml() {
        let cfg = Config::default();
        let text = toml::to_string_pretty(&cfg).expect("serialize");
        let back: Config = toml::from_str(&text).expect("deserialize");
        assert_eq!(cfg, back);
    }

    #[test]
    fn empty_file_is_default() {
        let cfg: Config = toml::from_str("").expect("empty toml is valid");
        assert_eq!(cfg, Config::default());
    }

    #[test]
    fn ignores_unknown_fields() {
        let cfg: Config =
            toml::from_str("greeting_name = \"Ada\"\nfuture_setting = true\n").expect("parse");
        assert_eq!(cfg, Config::default());
    }
}

#[cfg(test)]
mod storage_tests {
    use super::*;
    #[test]
    fn explicit_pool_names_count_duplicates_capacity_and_removed_identity_fields_are_closed() {
        let entry = StoragePoolConfig {
            name: "pool-a".into(),
            capacity_gib: 96,
            draining: false,
        };
        let mut config = Config {
            storage_pools: vec![entry.clone()],
            ..Config::default()
        };
        config.validate_storage().unwrap();
        config.storage_pools.push(entry.clone());
        assert!(config.validate_storage().is_err());
        for name in ["../pool", "", "pool/name", "pool name"] {
            config.storage_pools = vec![StoragePoolConfig {
                name: name.into(),
                ..entry.clone()
            }];
            assert!(config.validate_storage().is_err());
        }
        for capacity_gib in [0, 1_048_577, u32::MAX] {
            config.storage_pools = vec![StoragePoolConfig {
                capacity_gib,
                ..entry.clone()
            }];
            assert!(config.validate_storage().is_err());
        }
        config.storage_pools = (0..17)
            .map(|n| StoragePoolConfig {
                name: format!("p{n}"),
                ..entry.clone()
            })
            .collect();
        assert!(config.validate_storage().is_err());
        for field in ["identity", "required_mount", "filesystem_uuid"] {
            let text = format!("name='pool'\ncapacity_gib=96\n{field}='rejected'\n");
            assert!(toml::from_str::<StoragePoolConfig>(&text).is_err());
        }
    }
}

#[cfg(test)]
mod image_cache_config_tests {
    use super::*;

    #[test]
    fn image_cache_size_parses_auto_fixed_and_refuses_out_of_range() {
        assert_eq!(ImageCacheSize::parse("auto").unwrap(), ImageCacheSize::Auto);
        assert_eq!(ImageCacheSize::parse("0").unwrap(), ImageCacheSize::Gib(0));
        assert!(ImageCacheSize::parse("4097").is_err());
        assert!(ImageCacheSize::parse("-1").is_err());
        const GIB: u64 = 1 << 30;
        assert_eq!(ImageCacheSize::Auto.bytes_for(2000 * GIB), 100 * GIB);
        assert_eq!(ImageCacheSize::Auto.bytes_for(100 * GIB), 15 * GIB);
        assert_eq!(ImageCacheSize::Gib(7).bytes_for(1), 7 * GIB);
    }

    #[test]
    fn config_round_trips_and_defaults_refuse_foreign_images() {
        let config: Config =
            toml::from_str("image_cache_gib = 20\nforeign_image_grace = \"5m\"\n").unwrap();
        assert_eq!(config.image_cache_gib, ImageCacheSize::Gib(20));
        assert!(!config.accept_foreign_images);
        assert_eq!(config.foreign_grace(), std::time::Duration::from_secs(300));
        let text = toml::to_string(&config).unwrap();
        assert!(text.contains("image_cache_gib = 20"), "{text}");
        let auto: Config = toml::from_str("image_cache_gib = \"auto\"\n").unwrap();
        assert_eq!(auto.image_cache_gib, ImageCacheSize::Auto);
        assert!(parse_grace("25h").is_err());
        assert_eq!(parse_grace("0").unwrap(), std::time::Duration::ZERO);
        assert!(Config::default().foreign_grace() == std::time::Duration::from_secs(600));
    }

    #[test]
    fn offload_bandwidth_is_megabits_and_zero_is_unlimited() {
        let config: Config =
            toml::from_str("offload_upload_mbps = 80\noffload_fetch_mbps = 0\n").unwrap();
        assert_eq!(config.offload_upload_bytes_per_sec(), Some(10_000_000));
        assert_eq!(config.offload_fetch_bytes_per_sec(), None);
        assert_eq!(Config::default().offload_upload_bytes_per_sec(), None);
        let text = toml::to_string(&config).unwrap();
        assert!(text.contains("offload_upload_mbps = 80"), "{text}");
        assert!(
            !toml::to_string(&Config::default())
                .unwrap()
                .contains("offload_")
        );
    }

    #[test]
    fn quiesce_max_is_a_flat_key_defaulting_to_ten_minutes() {
        let minutes = std::time::Duration::from_secs(600);
        assert_eq!(Config::default().quiesce_max(), minutes);
        assert!(
            !toml::to_string(&Config::default())
                .unwrap()
                .contains("quiesce_max")
        );
        let config: Config = toml::from_str("quiesce_max = \"90s\"\n").unwrap();
        assert_eq!(config.quiesce_max(), std::time::Duration::from_secs(90));
        assert!(
            toml::to_string(&config)
                .unwrap()
                .contains("quiesce_max = \"90s\"")
        );
        // Unparsable or over 24 hours: the default, never a failed start.
        for bad in ["forever", "25h"] {
            let config: Config = toml::from_str(&format!("quiesce_max = \"{bad}\"\n")).unwrap();
            assert_eq!(config.quiesce_max(), minutes, "{bad}");
        }
    }

    #[test]
    fn builder_defaults_on_with_capture_and_foreign_builds_off() {
        let config = Config::default();
        assert!(config.builder_enabled(true));
        assert!(!config.builder_enabled(false));
        assert!(!config.accept_foreign_builds);
        assert!(!toml::to_string(&config).unwrap().contains("builder"));
        let off: Config = toml::from_str(
            "builder = false
accept_foreign_builds = true
",
        )
        .unwrap();
        assert!(!off.builder_enabled(true));
        assert!(off.accept_foreign_builds);
        let mut on = off.clone();
        on.set_builder(None);
        assert!(on.builder_enabled(true));
        let text = toml::to_string(&off).unwrap();
        assert!(text.contains("builder = false") && text.contains("accept_foreign_builds = true"));
    }

    #[test]
    fn egress_keys_default_round_trip_and_refuse_invalid_upstreams() {
        let config = Config::default();
        assert_eq!(config.allow_open_egress_for_others, None);
        assert!(!config.open_egress_for_others());
        // Guest sudo for others defaults to allow (the opposite of egress).
        assert_eq!(config.allow_guest_sudo_for_others, None);
        assert!(config.guest_sudo_for_others());
        let off: Config = toml::from_str("allow_guest_sudo_for_others = false\n").unwrap();
        assert!(!off.guest_sudo_for_others());
        assert!(toml::from_str::<Config>("allow_guest_sudo_for_others = \"no\"").is_err());
        let settings = config.egress_settings();
        assert!(settings.block_smtp && !settings.block_external_dns);
        assert!(settings.dns_upstreams.is_empty());
        // Defaults are never written.
        assert!(!toml::to_string(&config).unwrap().contains("egress"));
        let text = "allow_open_egress_for_others = true\negress_block_smtp = false\negress_block_external_dns = true\negress_dns_upstreams = [\"1.1.1.1\", \"9.9.9.9\"]\n";
        let parsed: Config = toml::from_str(text).unwrap();
        assert!(parsed.open_egress_for_others());
        let settings = parsed.egress_settings();
        assert!(!settings.block_smtp && settings.block_external_dns);
        assert_eq!(settings.dns_upstreams.len(), 2);
        assert_eq!(
            toml::from_str::<Config>(&toml::to_string(&parsed).unwrap()).unwrap(),
            parsed
        );
        for bad in [
            "egress_dns_upstreams = [\"0.0.0.0\"]",
            "egress_dns_upstreams = [\"224.0.0.1\"]",
            "egress_dns_upstreams = [\"255.255.255.255\"]",
            "egress_dns_upstreams = [\"1.1.1.1\",\"1.0.0.1\",\"8.8.8.8\",\"8.8.4.4\",\"9.9.9.9\"]",
            "egress_dns_upstreams = [\"::1\"]",
            "allow_open_egress_for_others = \"yes\"",
        ] {
            assert!(toml::from_str::<Config>(bad).is_err(), "{bad}");
        }
        assert_eq!(parse_dns_upstreams("1.1.1.1, 9.9.9.9").unwrap().len(), 2);
        assert!(parse_dns_upstreams("").is_err());
        assert!(parse_dns_upstreams("1.1.1.1,example.com").is_err());
        assert!(parse_dns_upstreams("240.0.0.1").is_err());
    }
}

#[cfg(test)]
mod terminal_resume_grace_tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn terminal_resume_grace_defaults_to_two_minutes_and_clamps_to_ten() {
        let grace = |text: Option<&str>| {
            Config {
                terminal_resume_grace: text.map(str::to_owned),
                ..Config::default()
            }
            .terminal_resume_grace()
        };
        assert_eq!(grace(None), Duration::from_secs(120));
        assert_eq!(grace(Some("5m")), Duration::from_secs(300));
        assert_eq!(grace(Some("90s")), Duration::from_secs(90));
        // Clamped, never refused: at most 10 minutes, at least 1 s.
        assert_eq!(grace(Some("1h")), Duration::from_secs(600));
        assert_eq!(grace(Some("11m")), Duration::from_secs(600));
        assert_eq!(grace(Some("0")), Duration::from_secs(1));
        // Unparsable: the default.
        assert_eq!(grace(Some("forever")), Duration::from_secs(120));
        // A flat key; absent from a default config file.
        let config: Config = toml::from_str("terminal_resume_grace = \"3m\"\n").unwrap();
        assert_eq!(config.terminal_resume_grace(), Duration::from_secs(180));
        assert!(
            !toml::to_string(&Config::default())
                .unwrap()
                .contains("terminal_resume")
        );
    }
}
