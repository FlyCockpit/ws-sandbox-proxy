//! Binary entry point.
//!
//! Responsibilities, in order:
//!   1. Parse arguments (clap).
//!   2. Initialize logging.
//!   3. Dispatch to the chosen subcommand.
//!   4. Map any error to a process exit code and a clean stderr message.
//!
//! Keep this file small. Real work belongs in `src/commands/`.

use clap::Parser;

use wssp::cli::{Cli, Command};
use wssp::exit::ExitCode;
use wssp::{commands, exit, logging, output};

fn main() {
    #[cfg(target_os = "linux")]
    if std::env::args_os().nth(1).as_deref()
        == Some(std::ffi::OsStr::new(wssp::host_process::ENTRY))
    {
        std::process::exit(wssp::host_process::run());
    }
    let cli = match Cli::try_parse() {
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

    let code = match run(&cli) {
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

/// Dispatch to the selected subcommand. Returning `Result` here keeps `main`
/// free of branching and lets every command use `?`.
fn run(cli: &Cli) -> anyhow::Result<()> {
    // The guard runs as root under `ProtectHome=yes`: it never touches the
    // daemon user's auth store.
    #[cfg(target_os = "linux")]
    if let Command::Guard(args) = &cli.command {
        return commands::guard::run(args);
    }
    drop(wssp::state::AuthStore::open(None)?);
    match &cli.command {
        Command::Config(args) => commands::config::run(args),
        Command::Completions(args) => commands::completions::run(args),
        Command::Login(args) => commands::login::run(args),
        Command::Logout(args) => commands::logout::run(args),
        Command::Token(args) => commands::token::run(args),
        Command::Drain(args) => commands::drain::run(args, true),
        Command::Undrain(args) => commands::drain::run(args, false),
        Command::Images(args) => commands::images::run(args),
        Command::Connect(args) => commands::connect::run(args),
        #[cfg(target_os = "linux")]
        Command::Daemon(args) => commands::daemon::run(args),
        #[cfg(target_os = "linux")]
        Command::Tunnel(args) => commands::tunnel::run(args),
        #[cfg(target_os = "linux")]
        Command::Guard(_) => unreachable!("handled above"),
    }
}
