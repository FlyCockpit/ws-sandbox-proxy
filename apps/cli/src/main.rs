//! Binary entry point.
//!
//! Responsibilities, in order:
//!   1. Dispatch the internal entries (`__wssp-host-child`, `__wssp-guard`).
//!   2. Parse arguments (clap), shaping `wssp host` help by the local host role.
//!   3. Initialize logging.
//!   4. Dispatch to the chosen subcommand.
//!   5. Map any error to a process exit code and a clean stderr message.
//!
//! Keep this file small. Real work belongs in `src/commands/`.

use anyhow::Context;
use clap::{CommandFactory, FromArgMatches};

use wssp::cli::{Cli, Command};
use wssp::commands::host::{
    ABOUT_NOT_ENROLLED, NOT_ENROLLED_AFTER_HELP, NOT_ENROLLED_HOST_MESSAGE,
};
use wssp::exit::{CodedError, ExitCode};
use wssp::host_role::HostRole;
use wssp::logging::LogFormat;
use wssp::{commands, exit, logging, output};

fn main() {
    #[cfg(target_os = "linux")]
    {
        let entry = std::env::args_os().nth(1);
        if entry.as_deref() == Some(std::ffi::OsStr::new(wssp::host_process::ENTRY)) {
            std::process::exit(wssp::host_process::run());
        }
        // The root guard service: no clap, no host role, no auth store.
        if entry.as_deref() == Some(std::ffi::OsStr::new(commands::guard::ENTRY)) {
            logging::init(LogFormat::Text, 0, false);
            finish(commands::guard::run_service());
        }
    }
    let role = HostRole::detect();
    let cli = match parse(role) {
        Ok(cli) => cli,
        Err(error) => {
            let code = error.exit_code();
            let args: Vec<_> = std::env::args_os().skip(1).collect();
            if error.use_stderr() && user_json_in(&args) {
                // A user command asked for JSON: one JSON error line only.
                let rendered = error.render().to_string();
                let first = rendered.lines().next().unwrap_or_default();
                let message =
                    output::remote_message(first.strip_prefix("error: ").unwrap_or(first));
                let _ = output::json_error(ExitCode::Usage.name(), None, &message, None);
            } else if error.use_stderr() {
                let _ = output::diagnostic(error);
            } else {
                let _ = output::text(error);
            }
            std::process::exit(code);
        }
    };
    // User commands (login, sandbox, …) talk to agents and scripts: their
    // stderr carries only errors (one JSON line with `--json`) unless `-v`
    // asks for logs. Host commands keep their info-level operator logs.
    let user_command = !matches!(cli.command, Command::Host(_) | Command::Completions(_));
    logging::init(
        cli.log_format,
        cli.verbose,
        cli.quiet || (user_command && cli.verbose == 0),
    );
    finish(run(&cli, role));
}

fn finish(result: anyhow::Result<()>) -> ! {
    if let Err(err) = &result
        && let Some(status) = exit::process_exit_of(err)
    {
        let _ = output::flush_stdout();
        std::process::exit(status);
    }
    let code = match result {
        Ok(()) => ExitCode::Success,
        // A closed stdout ends a plain listing quietly; commands whose output
        // is the point (`sandbox exec`, `logs`, `files read`) carry exit 141.
        Err(err)
            if exit::is_broken_pipe(&err) && exit::code_for(&err) != ExitCode::OutputClosed =>
        {
            ExitCode::Success
        }
        Err(err) => exit::report_failure(&err),
    };

    let _ = output::flush_stdout();
    std::process::exit(code as i32);
}

/// Parse argv. On a machine that is not an enrolled host, `wssp host` help
/// lists only `enroll` unless `--all` accompanies `--help`/`-h`. Completions
/// and the generated reference use the unmodified `Cli::command()`.
fn parse(role: HostRole) -> Result<Cli, clap::Error> {
    let mut command = Cli::command();
    if !role.is_enrolled() && !help_all_requested() {
        command = command.mut_subcommand("host", |host| {
            let names: Vec<String> = host
                .get_subcommands()
                .map(|sub| sub.get_name().to_owned())
                .filter(|name| name != "enroll")
                .collect();
            let mut host = host
                .about(ABOUT_NOT_ENROLLED)
                .after_help(NOT_ENROLLED_AFTER_HELP);
            for name in names {
                host = host.mut_subcommand(name, |sub| sub.hide(true));
            }
            host
        });
    }
    let matches = command.try_get_matches()?;
    Cli::from_arg_matches(&matches)
}

fn help_all_requested() -> bool {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    help_all_in(&args)
}

/// `--all` counts only as the `host` command's own flag: after `host` and
/// before any host subcommand, so `wssp host images … --all --help` cannot
/// un-hide the host command list.
fn help_all_in(args: &[std::ffi::OsString]) -> bool {
    let Some(host) = args.iter().position(|arg| arg == "host") else {
        return false;
    };
    let mut all = false;
    let mut help = false;
    let mut rest = args[host + 1..].iter();
    while let Some(arg) = rest.next() {
        if arg == "--" || !arg.to_string_lossy().starts_with('-') {
            break;
        }
        // The only value-taking global flag: skip its separate value.
        if arg == "--log-format" {
            rest.next();
        }
        all |= arg == "--all";
        help |= arg == "--help" || arg == "-h";
    }
    all && (help || args.iter().any(|arg| arg == "--help" || arg == "-h"))
}

/// Whether argv names a user command (`login`, `logout`, `whoami`,
/// `sandbox`, `template`, `ssh-config`) as its subcommand and carries `--json` before any
/// `--` (after it the words are the guest argv of `sandbox exec`).
fn user_json_in(args: &[std::ffi::OsString]) -> bool {
    let mut rest = args.iter();
    let command = loop {
        match rest.next() {
            None => return false,
            Some(arg) if arg == "--" => return false,
            // The only value-taking global flag: skip its separate value.
            Some(arg) if arg == "--log-format" => {
                rest.next();
            }
            Some(arg) if arg.to_string_lossy().starts_with('-') => {}
            Some(arg) => break arg,
        }
    };
    if ![
        "login",
        "logout",
        "whoami",
        "sandbox",
        "template",
        "ssh-config",
    ]
    .iter()
    .any(|name| command == name)
    {
        return false;
    }
    args.iter()
        .take_while(|arg| *arg != "--")
        .any(|arg| arg == "--json")
}

/// Dispatch to the selected subcommand. Returning `Result` here keeps `main`
/// free of branching and lets every command use `?`.
fn run(cli: &Cli, role: HostRole) -> anyhow::Result<()> {
    match &cli.command {
        // User commands: the user login only, never `config.toml` or the host
        // auth store.
        Command::Login(args) => commands::login::run(args, role),
        Command::Logout(args) => commands::user_logout::run(args),
        Command::Whoami(args) => commands::whoami::run(args),
        Command::Sandbox(args) => commands::sandbox::run(args),
        Command::Template(args) => commands::template::run(args),
        #[cfg(feature = "ssh")]
        Command::Ssh(args) => commands::sandbox::ssh::ssh(args),
        #[cfg(feature = "ssh")]
        Command::SshConfig(args) => commands::sandbox::ssh::ssh_config(args),
        Command::Completions(args) => commands::completions::run(args, Cli::command()),
        Command::Host(args) => {
            // Fail fast, before any network call or auth store.
            if !role.is_enrolled() && !args.command.allowed_without_enrollment() {
                return Err(anyhow::Error::msg(NOT_ENROLLED_HOST_MESSAGE))
                    .context(CodedError::new(ExitCode::NotEnrolledHost));
            }
            if args.command.uses_auth_store() {
                drop(wssp::state::AuthStore::open(None)?);
            }
            commands::host::run(args)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{help_all_in, user_json_in};

    #[test]
    fn json_usage_errors_only_for_user_commands_with_json() {
        let json = |args: &[&str]| {
            let args: Vec<std::ffi::OsString> = args.iter().map(Into::into).collect();
            user_json_in(&args)
        };
        assert!(json(&["sandbox", "list", "--json", "--limit", "0"]));
        assert!(json(&["-v", "--log-format", "json", "whoami", "--json"]));
        assert!(json(&["login", "--json", "--bogus"]));
        assert!(!json(&["sandbox", "list", "--limit", "0"]));
        assert!(!json(&["host", "images", "--json"]));
        assert!(!json(&["--json", "help", "sandbox"]));
        assert!(!json(&["sandbox", "exec", "s", "--", "echo", "--json"]));
        assert!(!json(&["--log-format", "sandbox", "host", "--json"]));
    }

    fn requested(args: &[&str]) -> bool {
        let args: Vec<std::ffi::OsString> = args.iter().map(Into::into).collect();
        help_all_in(&args)
    }

    #[test]
    fn all_counts_only_as_the_host_flag() {
        assert!(requested(&["host", "--help", "--all"]));
        assert!(requested(&["host", "--all", "--help"]));
        assert!(requested(&["-v", "host", "--all", "-h"]));
        assert!(!requested(&["host", "--help"]));
        assert!(!requested(&["host", "images", "prune", "--all", "--help"]));
        assert!(!requested(&["host", "images", "--all", "--help"]));
        assert!(!requested(&["--all", "--help"]));
        assert!(requested(&[
            "host",
            "--log-format",
            "json",
            "--help",
            "--all"
        ]));
        assert!(requested(&["host", "--log-format=json", "--all", "--help"]));
        assert!(!requested(&[
            "host",
            "--log-format",
            "json",
            "run",
            "--all",
            "--help"
        ]));
    }
}
