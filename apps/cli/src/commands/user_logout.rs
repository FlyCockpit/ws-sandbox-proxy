//! `wssp logout`: revoke this machine's user login (`DELETE /v1/key`) and
//! remove the saved `login.json`. Acts on the saved login only; a
//! `WSSP_API_KEY` in the environment is never revoked or changed.

use anyhow::{Context, Result};
use serde::Serialize;

use crate::api::{Client, Method, api_error_of};
use crate::exit::{CodedError, ExitCode};
use crate::output;
use crate::user_state::{CredentialSource, NOT_LOGGED_IN_MESSAGE, UserCredential, UserStore};

#[derive(Debug, clap::Args)]
pub struct Args {
    /// Only remove the saved login; do not revoke its key on the server.
    #[arg(long)]
    pub local: bool,

    /// Emit JSON instead of human-readable text.
    #[arg(long)]
    pub json: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LoggedOut<'a> {
    key_id: &'a str,
    server: &'a str,
    /// `revoked`, `already_invalid` (the server answered 401) or `skipped` (`--local`).
    server_revocation: &'static str,
    removed: bool,
}

pub fn run(args: &Args) -> Result<()> {
    output::set_json_errors(args.json);
    let dir = crate::user_state::user_dir()?;
    if std::fs::symlink_metadata(dir.join(crate::user_state::LOGIN_FILE))
        .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    {
        return Err(anyhow::Error::msg(NOT_LOGGED_IN_MESSAGE))
            .context(CodedError::new(ExitCode::NotLoggedIn));
    }
    // The lock is held only to read and to remove, never across the network
    // call: other user commands keep working while the server answers.
    let store = UserStore::open()?;
    let read = store.read()?;
    drop(store);
    let Some(login) = read else {
        return Err(anyhow::Error::msg(NOT_LOGGED_IN_MESSAGE))
            .context(CodedError::new(ExitCode::NotLoggedIn));
    };
    let revocation = if args.local {
        "skipped"
    } else {
        let client = Client::new(&UserCredential {
            origin: login.origin.clone(),
            secret: login.secret.clone(),
            source: CredentialSource::File,
            ca_file: login.ca_file.clone(),
            login: None,
        })?;
        match client.send::<serde_json::Value, serde_json::Value>(Method::Delete, "/v1/key", None) {
            Ok(_) => "revoked",
            Err(error) if api_error_of(&error).is_some_and(|e| e.status == 401) => {
                "already_invalid"
            }
            Err(error) => {
                return Err(error.context(
                    "revoking the login failed; nothing was removed (`wssp logout --local` removes it here only)",
                ));
            }
        }
    };
    // Remove only the login that was revoked: a `wssp login` that finished
    // meanwhile saved a different key, which stays.
    let store = UserStore::open()?;
    let current = store.read()?;
    let replaced = current
        .as_ref()
        .is_some_and(|current| current.key_id != login.key_id);
    let removed = !replaced && store.remove()?;
    drop(store);
    if replaced {
        output::warning("another `wssp login` saved a new login meanwhile; it was kept")?;
    }
    if args.json {
        output::json(&LoggedOut {
            key_id: &login.key_id,
            server: &login.origin,
            server_revocation: revocation,
            removed,
        })
    } else {
        match revocation {
            "revoked" => output::line(format!(
                "revoked login `{}` on {}",
                login.name, login.origin
            ))?,
            "already_invalid" => output::line("the server no longer accepted this login")?,
            _ => output::warning(format!(
                "the key `{}` stays valid on the server until it expires or you revoke it on the dashboard",
                login.key_id
            ))?,
        }
        output::line("logged out")
    }
}
