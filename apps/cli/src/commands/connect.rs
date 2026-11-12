#[cfg(not(target_os = "linux"))]
use anyhow::bail;
use anyhow::{Context, Result};
use clap::{Args, ValueEnum};

use crate::auth::resolve_connect;
use crate::sandbox_relay::connect::{ConnectOptions, ShutdownSignal, run_connect_with_config};
use sandbox_runtime::HostRuntimeKind;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ConnectRuntime {
    /// In-process fake runtime (tests, relay plumbing and local stacks without Incus).
    Fake,
    /// Incus-managed QEMU/KVM VMs via the local `incus` CLI (Linux only).
    Incus,
}

#[derive(Debug, Args)]
pub struct ConnectArgs {
    /// Initial host-terminal override; later local policy changes take precedence.
    #[arg(long, value_enum)]
    pub host_terminal: Option<crate::commands::config::OnOff>,
    #[command(flatten)]
    pub tls: crate::tls::TlsArgs,

    /// Control plane origin (defaults to configured `server_url`).
    #[arg(long)]
    pub server: Option<String>,

    /// Environment variable holding a dashboard host token (overrides saved selection).
    #[arg(long)]
    pub host_token_env: Option<String>,

    /// Sandbox host id (required with a host token; assigned automatically for device login).
    #[arg(long)]
    pub host_id: Option<String>,

    /// Human-readable label reported to the control plane.
    #[arg(long, default_value = "wssp-host")]
    pub label: String,

    /// Sandbox execution backend. Defaults to Incus on Linux, fake elsewhere (`WSSP_RUNTIME=fake` also forces fake on Linux).
    #[arg(long, value_enum, default_value_t = default_connect_runtime())]
    pub runtime: ConnectRuntime,

    /// Incus project for sandbox VMs (default: `WSSP_INCUS_PROJECT` or `wssp`;
    /// dedicated projects share `default` profiles and images; use `default` to
    /// skip auto-provisioning).
    #[arg(long)]
    pub incus_project: Option<String>,

    /// Total vCPU budget (1..8192); TOML sandbox_vcpu_budget, otherwise threads x 2.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=8192))]
    pub sandbox_vcpu_budget: Option<u32>,

    /// Optional RAM budget including per-VM host overhead in MiB (512..16777216, steps of 256).
    /// Overrides TOML sandbox_memory_mib, otherwise detected from the runtime.
    #[arg(long)]
    pub sandbox_memory_mib: Option<u32>,

    /// Optional per-VM CPU cap (1..32), independent of the number of VMs.
    /// Overrides TOML max_sandbox_cpu_count, otherwise detected from the runtime.
    #[arg(long)]
    pub max_sandbox_cpu_count: Option<u32>,

    /// Maximum concurrent commands across this host (1 to 256; default 16).
    #[arg(long, default_value_t = 16, value_parser = clap::value_parser!(u32).range(1..=256))]
    pub max_concurrent_commands: u32,
}

fn default_connect_runtime() -> ConnectRuntime {
    match HostRuntimeKind::default_for_target() {
        HostRuntimeKind::Fake => ConnectRuntime::Fake,
        #[cfg(target_os = "linux")]
        HostRuntimeKind::IncusKvm => ConnectRuntime::Incus,
    }
}

pub fn run(args: &ConnectArgs) -> Result<()> {
    // C55 (C52-TB-3): the SIGTERM/SIGINT handlers are registered FIRST,
    // before `run_connect` starts any relay, expiry or PTY thread, so no relay
    // effect can begin without them. The first signal requests the graceful
    // shutdown; a second one exits at once (`crate::shutdown`).
    let shutdown = ShutdownSignal::default();
    let signals = crate::shutdown::install(&shutdown)?;
    let runtime = match args.runtime {
        ConnectRuntime::Fake => HostRuntimeKind::Fake,
        ConnectRuntime::Incus => {
            #[cfg(target_os = "linux")]
            {
                HostRuntimeKind::IncusKvm
            }
            #[cfg(not(target_os = "linux"))]
            {
                bail!("`--runtime incus` is only supported on Linux");
            }
        }
    };

    // CLI logins: credential plaintext lives in daemon memory while
    // installing, capturing or proxying; keep it out of core dumps and
    // same-user ptrace. Best effort, before any relay thread starts.
    if let Err(err) = crate::sandbox_relay::credentials::harden_process() {
        tracing::warn!(error = %err, "could not mark the daemon non-dumpable");
    }
    let config = crate::config::Config::load()?;
    let trust = args.tls.load(&config)?;
    let resolved = resolve_connect(
        args.server.as_deref(),
        args.host_id.as_deref(),
        args.host_token_env.as_deref(),
    )?;

    let result = run_connect_with_config(
        &ConnectOptions {
            host_terminal: args
                .host_terminal
                .map(|v| matches!(v, crate::commands::config::OnOff::On)),
            server_url: resolved.server_url,
            host_token: resolved.secret,
            host_id: resolved.host_id,
            label: args.label.clone(),
            runtime,
            incus_project: args.incus_project.clone(),
            state_dir: None,
            heartbeat: std::time::Duration::from_secs(5),
            sandbox_memory_mib: args.sandbox_memory_mib,
            max_sandbox_cpu_count: args.max_sandbox_cpu_count,
            sandbox_vcpu_budget: args.sandbox_vcpu_budget,
            max_concurrent_commands: args.max_concurrent_commands,
            shutdown,
        },
        &trust,
        &config,
    );
    // Every relay thread, the expiry worker and every PTY have been joined or
    // reaped by now. A signalled daemon then dies from that same signal, so a
    // service manager sees death by SIGTERM (or SIGINT), not an exit status.
    if let Some(signal) = signals.received() {
        if let Err(error) = &result {
            tracing::warn!("sandbox relay ended with an error during shutdown: {error:#}");
        }
        crate::shutdown::terminate_by_signal(signal);
    }
    drop(signals);
    result.context("sandbox relay connect failed")
}
