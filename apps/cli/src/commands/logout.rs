//! `wssp host logout`.

use anyhow::Result;
use serde::Serialize;

use crate::output;
use crate::state::AuthStore;

#[derive(Debug, clap::Args)]
pub struct Args {
    /// Emit JSON instead of human-readable text.
    #[arg(long)]
    json: bool,
}

pub fn run(args: &Args) -> Result<()> {
    let outcome = AuthStore::open(None)?.logout()?;
    for warning in &outcome.warnings {
        output::warning(warning)?;
    }
    if args.json {
        output::json(&LogoutOutput {
            removed_device_credential: outcome.removed_device_credential,
            removed_token_env: outcome.removed_token_env,
        })?;
    } else if outcome.warnings.is_empty() {
        output::line("logged out")?;
    } else {
        output::line("logged out; config cleanup incomplete (see warnings)")?;
    }
    Ok(())
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LogoutOutput {
    removed_device_credential: bool,
    removed_token_env: bool,
}
