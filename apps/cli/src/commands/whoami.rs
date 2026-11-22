//! `wssp whoami`: the user login of this machine and, unless `--offline`,
//! what the server says about its key (`GET /v1/key`).

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::api::Client;
use crate::commands::login::Granted;
use crate::output;
use crate::user_state::{CredentialSource, require_credential};

#[derive(Debug, clap::Args)]
pub struct Args {
    /// Show only the saved login; make no network call.
    #[arg(long)]
    pub offline: bool,

    /// Emit JSON instead of human-readable text.
    #[arg(long)]
    pub json: bool,
}

/// `GET /v1/key` (packages/sandbox-contracts/src/keys.ts `keyInfoSchema`).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyInfo {
    pub id: String,
    pub name: String,
    pub origin: String,
    pub scopes: Vec<String>,
    pub resource_mode: String,
    pub pool_mode: String,
    pub pools: Vec<KeyPool>,
    pub own_sandboxes_only: bool,
    pub expires_at: Option<String>,
    pub max_live_sandboxes: Option<u32>,
    pub live_sandboxes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyPool {
    pub id: String,
    pub slug: String,
    pub label: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WhoAmI<'a> {
    source: CredentialSource,
    server: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    login: Option<Granted<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<KeyInfo>,
}

pub fn run(args: &Args) -> Result<()> {
    output::set_json_errors(args.json);
    let credential = require_credential()?;
    let key = if args.offline {
        None
    } else {
        Some(Client::new(&credential)?.get::<KeyInfo>("/v1/key", &[])?)
    };
    let view = WhoAmI {
        source: credential.source,
        server: &credential.origin,
        login: credential.login.as_ref().map(Granted::of),
        key,
    };
    if args.json {
        return output::json(&view);
    }
    let key_slugs: Option<Vec<String>> = view
        .key
        .as_ref()
        .filter(|key| key.pool_mode.eq_ignore_ascii_case("selected"))
        .map(|key| key.pools.iter().map(|p| p.slug.clone()).collect());
    match &view.login {
        Some(login) => login.print(key_slugs.as_deref())?,
        None => {
            output::line(format!("server: {}", view.server))?;
            output::line("login: `WSSP_API_KEY` from the environment")?;
        }
    }
    if let Some(key) = &view.key {
        output::line(format!(
            "key: {} ({}, {})",
            output::remote_message(&key.name),
            key.id,
            key.origin
        ))?;
        output::line(format!("scopes: {}", key.scopes.join(" ")))?;
        // A saved login already printed its pools (as slugs) above.
        if view.login.is_none() && key.pool_mode == "selected" {
            let pools: Vec<String> = key
                .pools
                .iter()
                .map(|p| output::remote_message(&p.slug))
                .collect();
            output::line(format!("key pools: {}", pools.join(", ")))?;
        }
        let limit = key
            .max_live_sandboxes
            .map_or_else(|| "no limit".to_owned(), |n| format!("limit {n}"));
        output::line(format!("live sandboxes: {} ({limit})", key.live_sandboxes))?;
        output::line(format!(
            "key expires: {}",
            key.expires_at.as_deref().unwrap_or("never")
        ))?;
    }
    Ok(())
}
