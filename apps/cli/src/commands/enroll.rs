//! `wssp host enroll`: device-code enrollment (`--slug`) or a dashboard host
//! token's environment variable (`--token-env`).

use std::time::Instant;

use anyhow::Result;
use serde::Serialize;

use crate::auth::{
    DeviceFlowTiming, MAX_LOGIN_DURATION, approval_url, device_login_scope, exchange_device_code,
    poll_device_flow, remaining, start_device_authorization,
};
use crate::output;
use crate::slug::validate_host_slug;
use crate::state::{AuthStore, LoginStart};

#[derive(Debug, clap::Args)]
#[command(group(
    clap::ArgGroup::new("method").required(true).args(["slug", "token_env"])
))]
pub struct Args {
    #[command(flatten)]
    pub tls: crate::tls::TlsArgs,

    /// Sandbox host slug to enroll with the device flow (`host-slug:<slug>` scope).
    #[arg(long)]
    slug: Option<String>,

    /// Record the environment variable that holds a dashboard-minted host
    /// token instead of running the device flow (the token itself is never
    /// written to config).
    #[arg(
        long,
        value_name = "ENV",
        conflicts_with_all = ["slug", "server", "open_egress_for_others", "ca_file"]
    )]
    token_env: Option<String>,

    /// Control plane origin override (defaults to configured `server_url`).
    #[arg(long)]
    server: Option<String>,

    /// Emit JSON instead of human-readable text.
    #[arg(long)]
    json: bool,

    /// Let sandboxes from other users' pools reach the open internet from
    /// this machine. Without it, an interactive device enrollment asks once.
    #[arg(long, value_enum, value_name = "on|off")]
    open_egress_for_others: Option<crate::commands::config::OnOff>,
}

pub fn run(args: &Args) -> Result<()> {
    match (&args.token_env, &args.slug) {
        (Some(env_var), _) => enroll_token_env(args, env_var),
        (None, Some(slug)) => enroll_device(args, slug),
        (None, None) => anyhow::bail!("`wssp host enroll` needs `--slug` or `--token-env`"),
    }
}

fn enroll_token_env(args: &Args, env_var: &str) -> Result<()> {
    crate::auth::host_token_from_env(env_var)?;
    crate::state::update_config(|cfg| {
        cfg.host_token_env = Some(env_var.to_owned());
        Ok(())
    })?;
    let guard = crate::guard_report::GuardReport::local();
    if args.json {
        output::json(&TokenEnrolled {
            host_token_env: env_var,
            guard: GuardSummary::from(&guard),
            guard_install_command: (!guard.ok).then(crate::guard_report::install_command),
        })?;
    } else {
        output::line(format!(
            "recorded host token environment variable `{env_var}`"
        ))?;
        print_guard_hint(&guard)?;
        let server = args
            .server
            .clone()
            .or_else(|| crate::state::load_config().ok().and_then(|c| c.server_url));
        output::line(token_next_step(server.as_deref(), env_var))?;
    }
    Ok(())
}

const DEVICE_NEXT_STEP: &str = "next: start the daemon with `wssp host run`, or run it as a service (docs/guide/hosts.md#run-as-a-service)";

/// The run command a token enrollment needs: a host token always needs the
/// server and the host id, which the token itself does not name.
fn token_next_step(server: Option<&str>, env_var: &str) -> String {
    let server = server.map_or("<server-url>", |s| s.trim_end_matches('/'));
    format!(
        "next: start the daemon with `wssp host run --server {server} --host-id <host-id> --host-token-env {env_var}`, or run it as a service (docs/guide/hosts.md#run-as-a-service)"
    )
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TokenEnrolled<'a> {
    host_token_env: &'a str,
    guard: GuardSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    guard_install_command: Option<String>,
}

/// The egress guard line every enrollment ends with.
fn print_guard_hint(guard: &crate::guard_report::GuardReport) -> Result<()> {
    if let Some(hint) = guard.hint() {
        output::line(hint)
    } else {
        output::line("egress guard: ok")
    }
}

fn enroll_device(args: &Args, slug: &str) -> Result<()> {
    let store = AuthStore::open(None)?;
    let (config, _) = store.snapshot()?;
    let trust = args.tls.load(&config)?;
    // Environment trust is an invocation-only override, including enrollment.
    // Only an explicit flag publishes a new default; retain an existing one.
    let saved_ca_file = if args.tls.ca_file.is_some() {
        trust.ca_file.clone()
    } else {
        config.ca_file.clone()
    };
    let host_slug = slug.to_owned();
    validate_host_slug(&host_slug)?;
    let LoginStart {
        generation,
        server_url,
    } = store.begin_login(args.server.as_deref(), &host_slug)?;
    drop(store);
    let server_url = server_url.as_str();
    let login_started = Instant::now();
    let started = start_device_authorization(
        &trust,
        server_url,
        &device_login_scope(&host_slug),
        login_started + MAX_LOGIN_DURATION,
    )?;
    let approval = approval_url(&started)?;
    let timing = DeviceFlowTiming::new(&started, login_started);
    let deadline = timing.deadline;
    if args.json {
        output::json(&LoginStarted {
            host_slug: &host_slug,
            user_code: &started.user_code,
            verification_uri: Some(started.verification_uri.as_str()),
            verification_uri_complete: started.verification_uri_complete.as_deref(),
            expires_in: Some(timing.expires_in.as_secs()),
            interval: Some(timing.interval.as_secs()),
        })?;
    } else {
        output::line(format!("host slug: {host_slug}"))?;
        output::line(format!("user code: {}", started.user_code))?;
        output::line(format!("verification URI: {approval}"))?;
    }

    poll_device_flow(&timing, || {
        let store = AuthStore::open(Some(deadline))?;
        store.check_generation(&generation)?;
        let credential = exchange_device_code(
            &trust,
            server_url,
            &started.device_code,
            &host_slug,
            deadline,
        )?;
        remaining(deadline)?;
        store.publish_with_ca_file(&generation, credential, saved_ca_file.clone())?;
        Ok(())
    })?;
    if !args.json {
        output::line("device enrollment complete")?;
    }
    node_setup(args, &host_slug)
}

const OPEN_EGRESS_QUESTION: &str =
    "Allow sandboxes from other users' pools to reach the open internet from this machine? [y/N] ";

/// Node setup after enrollment (docs/guide/hosts.md#egress-guard): the open
/// egress consent, then the egress guard check. Never prompts or waits on
/// stdin without a terminal on both stdin and stdout.
fn node_setup(args: &Args, host_slug: &str) -> Result<()> {
    use std::io::IsTerminal;
    let current = crate::state::load_config()?.allow_open_egress_for_others;
    let interactive =
        !args.json && std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let answer = match (args.open_egress_for_others, current) {
        (Some(value), _) => Some(matches!(value, crate::commands::config::OnOff::On)),
        (None, None) if interactive => Some(ask_open_egress()?),
        (None, _) => None,
    };
    if let Some(value) = answer {
        crate::state::update_config(|cfg| {
            cfg.allow_open_egress_for_others = Some(value);
            Ok(())
        })?;
    }
    let consent = answer.or(current);
    if consent.is_none() && !args.json {
        output::diagnostic(
            "open internet for other users' sandboxes is off until you choose: `wssp host config set-open-egress-for-others on|off`",
        )?;
    } else if !args.json {
        output::line(format!(
            "open internet for other users' sandboxes: {}",
            if consent == Some(true) { "on" } else { "off" }
        ))?;
    }
    let guard = crate::guard_report::GuardReport::local();
    if args.json {
        output::json(&LoginComplete {
            host_slug,
            open_egress_for_others: consent,
            guard: GuardSummary::from(&guard),
            guard_install_command: (!guard.ok).then(crate::guard_report::install_command),
        })?;
    } else {
        print_guard_hint(&guard)?;
        output::line(DEVICE_NEXT_STEP)?;
    }
    Ok(())
}

fn ask_open_egress() -> Result<bool> {
    use std::io::{BufRead, Read, Write};
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(OPEN_EGRESS_QUESTION.as_bytes())?;
    stdout.flush()?;
    drop(stdout);
    // Bounded single-line read: a stray paste cannot grow without limit.
    let mut line = String::new();
    std::io::stdin().lock().take(256).read_line(&mut line)?;
    Ok(parse_yes(&line))
}

fn parse_yes(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GuardSummary {
    installed: bool,
    ok: bool,
    reason: Option<&'static str>,
}

impl From<&crate::guard_report::GuardReport> for GuardSummary {
    fn from(guard: &crate::guard_report::GuardReport) -> Self {
        Self {
            installed: guard.installed,
            ok: guard.ok,
            reason: guard.reason,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginComplete<'a> {
    host_slug: &'a str,
    /// `null`: not asked yet (reads as off).
    open_egress_for_others: Option<bool>,
    guard: GuardSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    guard_install_command: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginStarted<'a> {
    host_slug: &'a str,
    user_code: &'a str,
    verification_uri: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verification_uri_complete: Option<&'a str>,
    expires_in: Option<u64>,
    interval: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_steps_name_the_run_command_for_each_path() {
        assert!(DEVICE_NEXT_STEP.contains("`wssp host run`"));
        assert!(DEVICE_NEXT_STEP.contains("hosts.md#run-as-a-service"));
        assert_eq!(
            token_next_step(Some("https://wssp.example/"), "WSSP_HOST_TOKEN"),
            "next: start the daemon with `wssp host run --server https://wssp.example --host-id <host-id> --host-token-env WSSP_HOST_TOKEN`, or run it as a service (docs/guide/hosts.md#run-as-a-service)"
        );
        assert!(token_next_step(None, "WSSP_X").contains("--server <server-url> "));
    }

    #[test]
    fn only_an_explicit_yes_consents() {
        for yes in ["y", "Y", "yes", " YES \n"] {
            assert!(parse_yes(yes), "{yes}");
        }
        for no in ["", "\n", "n", "no", "yess", "sure"] {
            assert!(!parse_yes(no), "{no}");
        }
    }
}
