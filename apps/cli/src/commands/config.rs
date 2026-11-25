//! `wssp host config` — inspect configuration and resolved paths.
//!
//! Subcommands:
//!   - `host config path`  print the config file path (whether or not it exists)
//!   - `host config show`  print the effective config (defaults + file) as TOML
//!   - `host config init`  write a default config file if none exists

mod host_context;

use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::auth::canonical_control_plane_origin;

use crate::output;
use crate::slug::validate_host_slug;
use crate::state::{load_config, update_config};

#[derive(Debug, clap::Args)]
pub struct Args {
    /// Emit JSON instead of human-readable text.
    // `global` only because this command has subcommands: it lets the flag
    // appear on either side (`host config --json path` and `host config path --json`).
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Sub,
}

#[derive(Debug, clap::Subcommand)]
enum Sub {
    /// Allow agents to run host commands and use host file tools. The daemon user is an Incus admin: these tools can reach every sandbox on this node, including other users' sandboxes in shared pools. A credential's "own sandboxes only" setting does not limit host commands. Enabling requires local stdin and stderr TTYs, verified process ancestry outside the daemon, and typed confirmation.
    SetAgentHostCommands {
        #[arg(value_enum)]
        value: OnOff,
    },
    /// Cap each host command at 1..86400 seconds (default 600). Raising requires local confirmation.
    SetHostCommandMaxTime { seconds: u64 },
    /// Set up to 32 absolute host file roots (never `/`). Adding roots requires local confirmation.
    SetHostFileRoots {
        #[arg(required=true, num_args=1..=32)]
        paths: Vec<std::path::PathBuf>,
    },
    /// Disable host file tools by clearing their roots. Never prompts.
    ClearHostFileRoots,
    /// Enable or disable host terminals locally.
    SetHostTerminal {
        #[arg(value_enum)]
        value: OnOff,
    },
    /// Require TOTP, or permit host terminals without a fresh code.
    SetHostTerminalTotp {
        #[arg(value_enum)]
        value: TotpMode,
    },
    /// Set this host's sandbox lease ceiling: `6h`, `90m`, `7d` (5m..24d) or
    /// `unlimited`. A running daemon reloads it and reports it to the server.
    SetMaxLease { value: String },
    /// How long work that never started is carried across a relay outage:
    /// `10m` (1m..24h), or `default` (10 minutes). Never past the sandbox
    /// lease or `max_carry`. A restart of `wssp host run` applies it.
    SetCarryIntentWindow { value: String },
    /// How long a running command is carried across a relay outage before
    /// the node stops it (`host_disconnect_expired`): `24h`, `7d` (10m..24d),
    /// or `default` (24 hours). A restart of `wssp host run` applies it.
    SetMaxCarry { value: String },
    /// Run template-build VMs on this host: `on`, `off`, or `default` (on
    /// whenever the image cache is enabled). Build steps may run as guest
    /// root inside build VMs. A restart of `wssp host run` applies it.
    SetBuilder {
        #[arg(value_enum)]
        value: BuilderMode,
    },
    /// Run template builds for other accounts in shared pools (default off;
    /// also needs `accept_foreign_images`). A restart applies it.
    SetAcceptForeignBuilds {
        #[arg(value_enum)]
        value: OnOff,
    },
    /// Print the path to the config file.
    Path,
    /// Print the effective configuration (defaults merged with the file).
    Show,
    /// Create a default config file if one does not already exist.
    Init,
    /// Set the control plane server URL.
    SetServer { url: String },
    /// Save a PEM CA file for HTTPS/WSS (added to webpki roots).
    SetCaFile { path: std::path::PathBuf },
    /// Clear the saved CA file (WSSP_CA_FILE can still override it).
    ClearCaFile,
    /// Store a host slug label (`wssp host enroll` still requires an explicit `--slug`).
    SetSlug { slug: String },
    /// Let sandboxes from other users' pools reach the open internet from
    /// this machine (your own sandboxes always can). A running daemon reloads it.
    SetOpenEgressForOthers {
        #[arg(value_enum)]
        value: OnOff,
    },
    /// Let sandboxes from other users' pools use `sudo` (root inside their
    /// own VM) on this machine. Default on; your own sandboxes always can.
    /// A running daemon reloads it for the next create or cold reconnect.
    SetAllowGuestSudoForOthers {
        #[arg(value_enum)]
        value: BuilderMode,
    },
    /// Reject outbound SMTP (tcp/25) from sandboxes created afterwards.
    SetEgressBlockSmtp {
        #[arg(value_enum)]
        value: OnOff,
    },
    /// Reject DNS to resolvers other than the sandbox gateway, for
    /// sandboxes created afterwards.
    SetEgressBlockExternalDns {
        #[arg(value_enum)]
        value: OnOff,
    },
    /// Upstream resolvers for open-internet sandboxes created afterwards:
    /// up to 4 comma-separated IPv4 addresses, or `--clear` for the host
    /// resolvers.
    SetEgressDnsUpstreams {
        #[arg(
            value_name = "IP,...",
            required_unless_present = "clear",
            conflicts_with = "clear"
        )]
        upstreams: Option<String>,
        /// Use the host resolvers again.
        #[arg(long)]
        clear: bool,
    },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum OnOff {
    On,
    Off,
}
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum BuilderMode {
    On,
    Off,
    Default,
}
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum TotpMode {
    Required,
    Optional,
}

pub fn run(args: &Args) -> Result<()> {
    match &args.command {
        Sub::SetAgentHostCommands { value } => {
            if matches!(value, OnOff::On) {
                confirm_host_access_raise()?;
            }
            update_config(|cfg| cfg.set_agent_host_commands(matches!(value, OnOff::On)))?;
            set_bool(
                args.json,
                "allowAgentHostCommands",
                matches!(value, OnOff::On),
                "agent host commands",
            )?;
        }
        Sub::SetHostCommandMaxTime { seconds } => {
            let ms = seconds
                .checked_mul(1000)
                .filter(|v| sandbox_protocol::valid_host_command_max_ms(*v))
                .context("host command time must be 1..86400 seconds")?;
            let current = load_config()?;
            let confirmed = ms > current.host_command_max_ms;
            if confirmed {
                confirm_host_access_raise()?;
            }
            update_config(|cfg| {
                anyhow::ensure!(
                    confirmed || ms <= cfg.host_command_max_ms,
                    "policy changed; retry the local command"
                );
                cfg.set_host_command_max_ms(ms)
            })?;
            if args.json {
                output::json(&SetValue {
                    key: "hostCommandMaxMs",
                    value: ms.to_string(),
                })?;
            } else {
                output::line(format!("set host command time cap to {seconds} seconds"))?;
            }
        }
        Sub::SetHostFileRoots { paths } => {
            let mut proposed = load_config()?;
            proposed.set_host_file_roots(paths)?;
            let current = load_config()?;
            let confirmed = proposed
                .host_file_roots
                .iter()
                .any(|p| !current.host_file_roots.contains(p));
            if confirmed {
                confirm_host_access_raise()?;
            }
            update_config(|cfg| {
                anyhow::ensure!(
                    confirmed
                        || proposed
                            .host_file_roots
                            .iter()
                            .all(|p| cfg.host_file_roots.contains(p)),
                    "policy changed; retry the local command"
                );
                cfg.set_host_file_roots(&proposed.host_file_roots)
            })?;
            set_bool(args.json, "hostFiles", !paths.is_empty(), "host file roots")?;
        }
        Sub::ClearHostFileRoots => {
            update_config(|cfg| cfg.set_host_file_roots(&[]))?;
            set_bool(args.json, "hostFiles", false, "host file roots")?;
        }
        Sub::SetHostTerminal { value } => {
            if matches!(value, OnOff::On) {
                confirm_host_access_raise()?;
            }
            update_config(|cfg| cfg.set_host_terminal(matches!(value, OnOff::On)))?;
            if args.json {
                output::json(&SetValue {
                    key: "allowHostTerminal",
                    value: matches!(value, OnOff::On).to_string(),
                })?;
            } else {
                output::line("saved local host terminal policy")?;
            }
        }
        Sub::SetHostTerminalTotp { value } => {
            if !matches!(value, TotpMode::Required) {
                confirm_host_access_raise()?;
            }
            update_config(|cfg| cfg.set_host_terminal_totp(matches!(value, TotpMode::Required)))?;
            if args.json {
                output::json(&SetValue {
                    key: "hostTerminalRequireTotp",
                    value: matches!(value, TotpMode::Required).to_string(),
                })?;
            } else {
                output::line("saved local host terminal TOTP policy")?;
            }
        }
        Sub::SetMaxLease { value } => {
            let parsed = crate::config::MaxLease::parse(value)?;
            update_config(|cfg| {
                cfg.set_max_lease(parsed);
                Ok(())
            })?;
            if let crate::config::MaxLease::Finite(_) = parsed {
                output::warning(format!(
                    "running sandboxes with later deadlines will be shortened to at most {parsed} from now once the daemon reports the new ceiling"
                ))?;
            }
            if args.json {
                output::json(&SetValue {
                    key: "maxLease",
                    value: parsed.to_string(),
                })?;
            } else {
                output::line(format!("set host lease ceiling to `{parsed}`"))?;
            }
        }
        Sub::SetCarryIntentWindow { value } => {
            let parsed = crate::config::CarryIntentWindow::parse_setting(value)?;
            update_config(|cfg| {
                cfg.set_carry_intent_window(parsed);
                Ok(())
            })?;
            let shown = parsed.unwrap_or_else(crate::config::CarryIntentWindow::default_value);
            if args.json {
                output::json(&SetValue {
                    key: "carryIntentWindow",
                    value: shown.to_string(),
                })?;
            } else {
                output::line(format!(
                    "set the carry window for unstarted work to `{shown}`; restart `wssp host run` to apply it"
                ))?;
            }
        }
        Sub::SetMaxCarry { value } => {
            let parsed = crate::config::MaxCarry::parse_setting(value)?;
            update_config(|cfg| {
                cfg.set_max_carry(parsed);
                Ok(())
            })?;
            let shown = parsed.unwrap_or_else(crate::config::MaxCarry::default_value);
            if args.json {
                output::json(&SetValue {
                    key: "maxCarry",
                    value: shown.to_string(),
                })?;
            } else {
                output::line(format!(
                    "set the carry cap for running work to `{shown}`; restart `wssp host run` to apply it"
                ))?;
            }
        }
        Sub::SetBuilder { value } => {
            let builder = match value {
                BuilderMode::On => Some(true),
                BuilderMode::Off => Some(false),
                BuilderMode::Default => None,
            };
            update_config(|cfg| {
                cfg.set_builder(builder);
                Ok(())
            })?;
            let shown = builder.map_or_else(|| "default".to_string(), |b| b.to_string());
            if args.json {
                output::json(&SetValue {
                    key: "builder",
                    value: shown,
                })?;
            } else {
                output::line(format!(
                    "set template builder to `{shown}`; restart `wssp host run` to apply"
                ))?;
            }
        }
        Sub::SetAcceptForeignBuilds { value } => {
            let accept = matches!(value, OnOff::On);
            update_config(|cfg| {
                cfg.set_accept_foreign_builds(accept);
                Ok(())
            })?;
            if args.json {
                output::json(&SetValue {
                    key: "acceptForeignBuilds",
                    value: accept.to_string(),
                })?;
            } else {
                output::line(format!(
                    "set accept_foreign_builds to `{accept}`; restart `wssp host run` to apply"
                ))?;
            }
        }
        Sub::SetOpenEgressForOthers { value } => {
            let on = matches!(value, OnOff::On);
            update_config(|cfg| {
                cfg.allow_open_egress_for_others = Some(on);
                Ok(())
            })?;
            if !on {
                output::warning(
                    "other users' sandboxes already running with open internet keep it until they stop; they cannot be restarted on this node. Run `wssp host drain` to remove them now",
                )?;
            }
            set_bool(
                args.json,
                "openEgressForOthers",
                on,
                "open internet for other users' sandboxes",
            )?;
        }
        Sub::SetAllowGuestSudoForOthers { value } => {
            let setting = match value {
                BuilderMode::On => Some(true),
                BuilderMode::Off => Some(false),
                BuilderMode::Default => None,
            };
            update_config(|cfg| {
                cfg.allow_guest_sudo_for_others = setting;
                Ok(())
            })?;
            let on = setting.unwrap_or(true);
            if !on {
                output::warning(
                    "other users' sudo sandboxes already running keep sudo until they stop; their next cold reconnect on this node is refused (`guest_sudo_not_permitted`). New ones get no sudo",
                )?;
            }
            set_bool(
                args.json,
                "guestSudoForOthers",
                on,
                "guest sudo for other users' sandboxes",
            )?;
        }
        Sub::SetEgressBlockSmtp { value } => {
            let on = matches!(value, OnOff::On);
            update_config(|cfg| {
                cfg.egress_block_smtp = on;
                Ok(())
            })?;
            set_bool(
                args.json,
                "egressBlockSmtp",
                on,
                "SMTP blocking for new sandboxes",
            )?;
        }
        Sub::SetEgressBlockExternalDns { value } => {
            let on = matches!(value, OnOff::On);
            update_config(|cfg| {
                cfg.egress_block_external_dns = on;
                Ok(())
            })?;
            set_bool(
                args.json,
                "egressBlockExternalDns",
                on,
                "external DNS blocking for new sandboxes",
            )?;
        }
        Sub::SetEgressDnsUpstreams { upstreams, clear } => {
            let parsed = match (upstreams, clear) {
                (_, true) => Vec::new(),
                (Some(text), false) => crate::config::parse_dns_upstreams(text)?,
                (None, false) => anyhow::bail!("give the upstream addresses or `--clear`"),
            };
            update_config(|cfg| {
                cfg.egress_dns_upstreams = parsed.clone();
                Ok(())
            })?;
            let shown = parsed
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            if args.json {
                output::json(&SetValue {
                    key: "egressDnsUpstreams",
                    value: shown,
                })?;
            } else if parsed.is_empty() {
                output::line("open-internet sandboxes created from now on use the host resolvers")?;
            } else {
                output::line(format!(
                    "open-internet sandboxes created from now on resolve through `{shown}`"
                ))?;
            }
        }
        Sub::Path => {
            let path = crate::paths::config_file()?;
            if args.json {
                output::json(&ConfigPath::new(&path))?;
            } else {
                output::line(path.display())?;
            }
        }
        Sub::Show => {
            let (config, diagnostics) = crate::state::AuthStore::open(None)?.inspect_config()?;
            let kind = sandbox_runtime::HostRuntimeKind::default_for_target();
            let capacity = crate::vm_capacity::inspect_capacity(
                kind,
                crate::vm_capacity::CapacityOverrides::default(),
                &config,
                crate::vm_capacity::detect_resources(kind),
            )?;
            let pools = crate::storage_capacity::inspect(&config);
            let guard = crate::guard_report::GuardReport::local();
            if args.json {
                output::json(&ConfigJson {
                    allow_host_terminal: config.allow_host_terminal,
                    allow_agent_host_commands: config.allow_agent_host_commands,
                    host_command_max_ms: config.host_command_max_ms,
                    host_file_roots: &config.host_file_roots,
                    agent_policy_revision: config.agent_policy_revision,
                    host_terminal_require_totp: config.host_terminal_require_totp,
                    host_terminal_policy_revision: config.host_terminal_policy_revision,
                    max_lease: config.max_lease.to_string(),
                    carry_intent_window: config
                        .carry_intent_window
                        .unwrap_or_else(crate::config::CarryIntentWindow::default_value)
                        .to_string(),
                    max_carry: config
                        .max_carry
                        .unwrap_or_else(crate::config::MaxCarry::default_value)
                        .to_string(),
                    config_errors: &diagnostics,
                    sandbox_vcpu_budget: config.sandbox_vcpu_budget,
                    storage_pools: &pools,
                    sandbox_memory_mib: config.sandbox_memory_mib,
                    max_sandbox_cpu_count: config.max_sandbox_cpu_count,
                    vm_capacity: &capacity,
                    server_url: config.server_url.as_deref(),
                    ca_file: config.ca_file.as_deref(),
                    host_slug: config.host_slug.as_deref(),
                    host_token_env: config.host_token_env.as_deref(),
                    open_egress_for_others: config.allow_open_egress_for_others,
                    guest_sudo_for_others: config.guest_sudo_for_others(),
                    egress_block_smtp: config.egress_block_smtp,
                    egress_block_external_dns: config.egress_block_external_dns,
                    egress_dns_upstreams: &config.egress_dns_upstreams,
                    guard: &guard,
                })?;
            } else {
                output::text(toml::to_string_pretty(&config)?)?;
                // Resolved values are read-only comments, so pasting this output
                // into config.toml never creates overrides or diagnostic keys.
                output::line("# Runtime selection follows `wssp host run` (WSSP_RUNTIME)")?;
                output::line("# vm_capacity (read-only)")?;
                for line in toml::to_string_pretty(&capacity)?.lines() {
                    output::line(format!("# {line}"))?;
                }
                for pool in &pools {
                    for line in toml::to_string_pretty(pool)?.lines() {
                        output::line(format!("# {line}"))?;
                    }
                }
                for diagnostic in &diagnostics {
                    output::line(format!("# {diagnostic}"))?;
                }
                // Effective egress values (defaults are not written to the
                // file) and the guard's per-source state, never contents.
                output::line("# egress (read-only, effective)")?;
                output::line(format!(
                    "# allow_open_egress_for_others = {}",
                    match config.allow_open_egress_for_others {
                        Some(value) => value.to_string(),
                        None => "false (not asked yet)".into(),
                    }
                ))?;
                output::line(format!(
                    "# allow_guest_sudo_for_others = {}",
                    match config.allow_guest_sudo_for_others {
                        Some(value) => value.to_string(),
                        None => "true (default)".into(),
                    }
                ))?;
                output::line(format!(
                    "# egress_block_smtp = {}",
                    config.egress_block_smtp
                ))?;
                output::line(format!(
                    "# egress_block_external_dns = {}",
                    config.egress_block_external_dns
                ))?;
                output::line(format!(
                    "# egress_dns_upstreams = {}",
                    if config.egress_dns_upstreams.is_empty() {
                        "host resolvers".to_string()
                    } else {
                        config
                            .egress_dns_upstreams
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(",")
                    }
                ))?;
                output::line(format!(
                    "# guard = {}",
                    if guard.ok {
                        "ok".to_string()
                    } else {
                        format!("not ok ({})", guard.reason.unwrap_or("guard_not_ok"))
                    }
                ))?;
                for (name, source) in [
                    ("root blocklist", &guard.root_source),
                    ("deployment blocklist", &guard.deployment_source),
                ] {
                    if let Some(source) = source {
                        output::line(format!(
                            "# guard {name} = {}{}",
                            source.state,
                            source
                                .digest
                                .as_deref()
                                .map(|d| format!(" ({d})"))
                                .unwrap_or_default()
                        ))?;
                    }
                }
                for (name, count) in &guard.counts {
                    output::line(format!("# guard count {name} = {count}"))?;
                }
                if let Some(hint) = guard.hint() {
                    for line in hint.lines() {
                        output::line(format!("# {}", line.trim_start()))?;
                    }
                }
            }
        }
        Sub::Init => {
            let path = crate::paths::config_file()?;
            let created = crate::state::init_config().context("writing the default config file")?;

            if args.json {
                output::json(&ConfigInit::new(&path, created))?;
            } else if created {
                output::line(format!("wrote default config to `{}`", path.display()))?;
            } else {
                output::line(format!("config already exists at `{}`", path.display()))?;
            }
        }
        Sub::SetServer { url } => {
            let saved = canonical_control_plane_origin(url)?;
            update_config(|cfg| {
                cfg.server_url = Some(saved.clone());
                Ok(())
            })?;
            if args.json {
                output::json(&SetValue {
                    key: "serverUrl",
                    value: saved,
                })?;
            } else {
                output::line(format!("set server URL to `{saved}`"))?;
            }
        }
        Sub::SetCaFile { path } => {
            let trust = crate::tls::Trust::load(Some(path))?;
            let saved = trust.ca_file;
            update_config(|cfg| {
                cfg.ca_file = saved.clone();
                Ok(())
            })?;
            if args.json {
                output::json(&CaFileSelection {
                    ca_file: saved.as_deref(),
                })?;
            } else {
                output::line(format!("set CA file to `{}`", path.display()))?;
            }
        }
        Sub::ClearCaFile => {
            update_config(|cfg| {
                cfg.ca_file = None;
                Ok(())
            })?;
            if args.json {
                output::json(&CaFileSelection { ca_file: None })?;
            } else {
                output::line("cleared saved CA file")?;
            }
        }
        Sub::SetSlug { slug } => {
            validate_host_slug(slug)?;
            let saved = slug.clone();
            update_config(|cfg| {
                cfg.host_slug = Some(saved.clone());
                Ok(())
            })?;
            if args.json {
                output::json(&SetValue {
                    key: "hostSlug",
                    value: saved,
                })?;
            } else {
                output::line(format!("set host slug to `{saved}`"))?;
            }
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct ConfigPath {
    path: String,
}

impl ConfigPath {
    fn new(path: &Path) -> Self {
        Self {
            path: path.display().to_string(),
        }
    }
}

#[derive(Debug, Serialize)]
struct ConfigInit {
    path: String,
    created: bool,
}

impl ConfigInit {
    fn new(path: &Path, created: bool) -> Self {
        Self {
            path: path.display().to_string(),
            created,
        }
    }
}

#[derive(Debug, Serialize)]
struct SetValue {
    key: &'static str,
    value: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfigJson<'a> {
    allow_host_terminal: bool,
    allow_agent_host_commands: bool,
    host_command_max_ms: u64,
    host_file_roots: &'a [std::path::PathBuf],
    agent_policy_revision: u64,
    host_terminal_require_totp: bool,
    host_terminal_policy_revision: u64,
    max_lease: String,
    carry_intent_window: String,
    max_carry: String,
    sandbox_vcpu_budget: Option<u32>,
    storage_pools: &'a [crate::storage_capacity::PoolInspection],
    config_errors: &'a [&'static str],
    sandbox_memory_mib: Option<u32>,
    max_sandbox_cpu_count: Option<u32>,
    vm_capacity: &'a crate::vm_capacity::CapacityInspection,
    server_url: Option<&'a str>,
    ca_file: Option<&'a Path>,
    host_slug: Option<&'a str>,
    host_token_env: Option<&'a str>,
    /// `null` until the node owner answers (reads as off).
    open_egress_for_others: Option<bool>,
    /// Effective `allow_guest_sudo_for_others` (default on).
    guest_sudo_for_others: bool,
    egress_block_smtp: bool,
    egress_block_external_dns: bool,
    egress_dns_upstreams: &'a [std::net::Ipv4Addr],
    guard: &'a crate::guard_report::GuardReport,
}

fn set_bool(json: bool, key: &'static str, on: bool, what: &str) -> Result<()> {
    if json {
        output::json(&SetValue {
            key,
            value: on.to_string(),
        })
    } else {
        output::line(format!("set {what} {}", if on { "on" } else { "off" }))
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CaFileSelection<'a> {
    ca_file: Option<&'a Path>,
}

/// This gate is deliberately independent of JSON output and has no bypass flag.
pub(crate) fn confirm_host_access_raise() -> Result<()> {
    use std::io::{IsTerminal, Write};
    check_raise_context(
        std::io::stdin().is_terminal(),
        std::io::stderr().is_terminal(),
        std::env::var_os("WSSP_HOST_COMMAND").is_some()
            || std::env::var_os("WSSP_HOST_TERMINAL").is_some(),
    )?;
    host_context::check()?;
    let mut stderr = std::io::stderr().lock();
    writeln!(
        stderr,
        "the daemon user is an Incus admin; host access can reach every sandbox on this node, including other users' shared-pool sandboxes. own sandboxes only does not limit host commands."
    )?;
    write!(stderr, "type on to enable or raise host access: ")?;
    stderr.flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    anyhow::ensure!(answer.trim() == "on", "host access raise was not confirmed");
    Ok(())
}
fn check_raise_context(stdin_tty: bool, stderr_tty: bool, host_command: bool) -> Result<()> {
    anyhow::ensure!(!host_command, "a host command cannot raise host access");
    anyhow::ensure!(
        stdin_tty && stderr_tty,
        "raising host access requires local stdin and stderr TTYs"
    );
    Ok(())
}
#[cfg(test)]
mod host_raise_tests {
    use super::*;
    #[test]
    fn raises_need_both_ttys_and_no_marker() {
        for (stdin, stderr, marker) in [
            (false, false, false),
            (false, true, false),
            (true, false, false),
            (true, true, true),
            (false, false, true),
        ] {
            assert!(check_raise_context(stdin, stderr, marker).is_err());
        }
        assert!(check_raise_context(true, true, false).is_ok());
    }
}
