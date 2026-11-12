//! `wssp token` commands.

use anyhow::Result;
use serde::Serialize;

use crate::config::Config;
use crate::output;

#[derive(Debug, clap::Args)]
pub struct Args {
    /// Emit JSON instead of human-readable text.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Sub,
}

#[derive(Debug, clap::Subcommand)]
enum Sub {
    /// Record the environment variable that contains a dashboard-minted host token.
    Login { env_var: String },
}

pub fn run(args: &Args) -> Result<()> {
    match &args.command {
        Sub::Login { env_var } => {
            crate::auth::host_token_from_env(env_var)?;
            Config::update(|cfg| {
                cfg.host_token_env = Some(env_var.clone());
                Ok(())
            })?;
            if args.json {
                output::json(&TokenLogin {
                    host_token_env: env_var,
                })?;
            } else {
                output::line(format!(
                    "recorded host token environment variable `{env_var}`"
                ))?;
            }
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TokenLogin<'a> {
    host_token_env: &'a str,
}
