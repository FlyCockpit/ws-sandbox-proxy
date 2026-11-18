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

use wssp::cli::{Cli, Command, LogFormat};
use wssp::commands::host::{
    ABOUT_NOT_ENROLLED, NOT_ENROLLED_AFTER_HELP, NOT_ENROLLED_HOST_MESSAGE,
};
use wssp::exit::{CodedError, ExitCode};
use wssp::host_role::HostRole;
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
            if error.use_stderr() {
                let _ = output::diagnostic(error);
            } else {
                let _ = output::text(error);
            }
            std::process::exit(code);
        }
    };
    logging::init(cli.log_format, cli.verbose, cli.quiet);
    finish(run(&cli, role));
}

fn finish(result: anyhow::Result<()>) -> ! {
    let code = match result {
        Ok(()) => ExitCode::Success,
        Err(err) if exit::is_broken_pipe(&err) => ExitCode::Success,
        Err(err) => {
            // Identifiers in error messages are wrapped in `backticks`, never
            // 'single quotes' — see AGENTS.md.
            let _ = output::diagnostic(format!("error: {}", exit::message_for(&err)));
            exit::code_for(&err)
        }
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

/// Dispatch to the selected subcommand. Returning `Result` here keeps `main`
/// free of branching and lets every command use `?`.
fn run(cli: &Cli, role: HostRole) -> anyhow::Result<()> {
    match &cli.command {
        Command::Completions(args) => commands::completions::run(args),
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
    use super::help_all_in;

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
