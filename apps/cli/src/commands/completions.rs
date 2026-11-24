//! `wssp completions <shell>` — print a shell completion script to stdout.
//!
//! Usage examples:
//!   wssp completions bash > /etc/bash_completion.d/wssp
//!   wssp completions zsh  > ~/.zfunc/_wssp
//!   wssp completions fish > ~/.config/fish/completions/wssp.fish
//!
//! Generating from the live clap definition means completions never go stale.

use anyhow::Result;
use clap_complete::Shell;

use crate::output;

#[derive(Debug, clap::Args)]
pub struct Args {
    /// Shell to generate completions for.
    shell: Shell,
}

/// `cmd`: the top-level clap command (`Cli::command()`), passed in by `main`.
pub fn run(args: &Args, mut cmd: clap::Command) -> Result<()> {
    let bin_name = cmd.get_name().to_string();
    let mut completions = Vec::new();
    clap_complete::generate(args.shell, &mut cmd, bin_name, &mut completions);
    output::bytes(&completions)?;
    Ok(())
}
