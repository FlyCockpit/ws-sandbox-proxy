//! `wssp login`: a user login through the device flow (scope `user-login`).
//!
//! The browser approval chooses everything the minted `/v1` key may do (name,
//! read or write access, pools, own sandboxes only, live sandbox limit,
//! expiry); this command sends only the scope. The exchange
//! (`userLogins.exchangeDeviceCode`) follows the same poll contract as host
//! enrollment (`crate::auth::poll_device_flow`).

use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::auth::{
    DeviceFlowTiming, MAX_LOGIN_DURATION, approval_url, poll_device_flow,
    start_device_authorization,
};
use crate::exit::{CodedError, ExitCode};
use crate::host_role::HostRole;
use crate::output;
use crate::user_state::{UserLogin, UserStore, validate_sdk_key};

/// The device authorization scope of a user login.
pub const USER_LOGIN_SCOPE: &str = "user-login";

/// Shown on an enrolled host: the daemon user can read this login.
pub const HOST_MACHINE_WARNING: &str = "this machine is an enrolled wssp host: host commands that agents run here (`hosts:execute`, `hosts:files`) run as this user and could read the saved login; prefer `wssp login` on a machine that is not a host, or a short expiry and read access";

#[derive(Debug, clap::Args)]
pub struct Args {
    /// Server origin, e.g. `https://wssp.example.com` (default: the origin of the current login).
    #[arg(long, value_name = "URL")]
    pub server: Option<String>,

    /// Add PEM CA certificates to webpki roots for this server (saved with the login; `WSSP_CA_FILE` overrides).
    #[arg(long, value_name = "PATH")]
    pub ca_file: Option<PathBuf>,

    /// Emit JSON instead of human-readable text.
    #[arg(long)]
    pub json: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Exchanged {
    key_id: String,
    secret: String,
    name: String,
    email: String,
    scopes: Vec<String>,
    pool_mode: String,
    pool_ids: Vec<String>,
    own_sandboxes_only: bool,
    expires_at: Option<String>,
    max_live_sandboxes: Option<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Started<'a> {
    user_code: &'a str,
    verification_uri: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    verification_uri_complete: Option<&'a str>,
    expires_in: u64,
    interval: u64,
}

/// The `--json` success object of `wssp login`.
#[derive(Serialize)]
struct LoggedIn<'a> {
    #[serde(flatten)]
    granted: Granted<'a>,
    /// What human mode prints as `warning: …` on stderr.
    warnings: Vec<String>,
}

/// What a login grants, as `wssp login` and `wssp whoami --offline` print it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Granted<'a> {
    pub server: &'a str,
    pub key_id: &'a str,
    pub name: &'a str,
    pub user_email: &'a str,
    pub access: &'static str,
    pub scopes: &'a [String],
    pub pool_mode: &'a str,
    pub pool_ids: &'a [String],
    pub own_sandboxes_only: bool,
    pub max_live_sandboxes: Option<u32>,
    pub expires_at: Option<&'a str>,
    pub created_at: &'a str,
}

impl<'a> Granted<'a> {
    pub fn of(login: &'a UserLogin) -> Self {
        Self {
            server: &login.origin,
            key_id: &login.key_id,
            name: &login.name,
            user_email: &login.user_email,
            access: login.access(),
            scopes: &login.scopes,
            pool_mode: &login.pool_mode,
            pool_ids: &login.pool_ids,
            own_sandboxes_only: login.own_sandboxes_only,
            max_live_sandboxes: login.max_live_sandboxes,
            expires_at: login.expires_at.as_deref(),
            created_at: &login.created_at,
        }
    }

    /// Human lines. `pool_slugs`: the selected pools' slugs from `GET /v1/key`
    /// when that answered; otherwise the saved pool ids are shown.
    pub fn print(&self, pool_slugs: Option<&[String]>) -> Result<()> {
        output::line(format!("server: {}", self.server))?;
        output::line(format!("user: {}", self.user_email))?;
        output::line(format!("login: {} ({})", self.name, self.key_id))?;
        output::line(format!("access: {}", self.access))?;
        let pools = pools_line(self.pool_mode, self.pool_ids, pool_slugs);
        output::line(format!("pools: {pools}"))?;
        output::line(format!(
            "sandboxes: {}",
            if self.own_sandboxes_only {
                "only those this login creates"
            } else {
                "all of yours"
            }
        ))?;
        output::line(format!(
            "live sandbox limit: {}",
            self.max_live_sandboxes
                .map_or_else(|| "none".to_owned(), |n| n.to_string())
        ))?;
        output::line(format!("expires: {}", self.expires_at.unwrap_or("never")))
    }
}

/// The `pools:` value: slugs when known, the saved ids otherwise.
fn pools_line(pool_mode: &str, pool_ids: &[String], pool_slugs: Option<&[String]>) -> String {
    if !pool_mode.eq_ignore_ascii_case("selected") {
        return "all usable pools".to_owned();
    }
    match pool_slugs {
        Some(slugs) => slugs
            .iter()
            .map(|slug| output::remote_message(slug))
            .collect::<Vec<_>>()
            .join(", "),
        None => pool_ids.join(", "),
    }
}

/// One best-effort `GET /v1/key` with the login just saved (never the
/// environment's credentials), for the pool slugs. Single attempt, short
/// timeout; any failure falls back to the saved pool ids.
fn lookup_pool_slugs(login: &UserLogin, ca_file: Option<PathBuf>) -> Option<Vec<String>> {
    if !login.pool_mode.eq_ignore_ascii_case("selected") {
        return None;
    }
    let credential = crate::user_state::UserCredential {
        origin: login.origin.clone(),
        secret: login.secret.clone(),
        source: crate::user_state::CredentialSource::File,
        login: None,
        ca_file,
    };
    let key: crate::commands::whoami::KeyInfo = crate::api::Client::new(&credential)
        .and_then(|client| {
            client.request(
                crate::api::Method::Get,
                "/v1/key",
                &[],
                crate::api::Body::None,
                None,
                std::time::Duration::from_secs(10),
            )
        })
        .ok()?;
    Some(key.pools.into_iter().map(|pool| pool.slug).collect())
}

pub fn run(args: &Args, role: HostRole) -> Result<()> {
    output::set_json_errors(args.json);
    let store = UserStore::open()?;
    let previous = store.read().ok().flatten();
    drop(store);
    let server = match (&args.server, &previous) {
        (Some(server), _) => server.clone(),
        (None, Some(login)) => login.origin.clone(),
        (None, None) => {
            return Err(anyhow::anyhow!(
                "no server: pass `--server <url>` (for example `wssp login --server https://wssp.example.com`)"
            ))
            .context(CodedError::new(ExitCode::Usage));
        }
    };
    let origin = crate::auth::canonical_control_plane_origin(&server)
        .context("invalid `--server`")
        .context(CodedError::new(ExitCode::Usage))?;
    // Human mode warns up front; `--json` reports warnings only in the
    // success object, so a failure stays one JSON error line.
    let mut warnings: Vec<String> = Vec::new();
    if role.is_enrolled() {
        if args.json {
            warnings.push(HOST_MACHINE_WARNING.to_owned());
        } else {
            output::warning(HOST_MACHINE_WARNING)?;
        }
    }
    let env_ca = std::env::var_os("WSSP_CA_FILE").map(PathBuf::from);
    // `--ca-file` is saved; an environment CA stays an invocation override;
    // without either, a re-login to the same server keeps the saved CA file.
    let kept_ca = previous
        .as_ref()
        .filter(|login| login.origin == origin)
        .and_then(|login| login.ca_file.clone());
    let selected = args.ca_file.clone().or(env_ca).or(kept_ca.clone());
    let trust = crate::tls::Trust::load(selected.as_deref())?;
    let saved_ca_file = if args.ca_file.is_some() {
        trust.ca_file.clone()
    } else {
        kept_ca
    };

    let login_started = Instant::now();
    let started = start_device_authorization(
        &trust,
        &origin,
        USER_LOGIN_SCOPE,
        login_started + MAX_LOGIN_DURATION,
    )?;
    let approval = approval_url(&started)?;
    let timing = DeviceFlowTiming::new(&started, login_started);
    if args.json {
        output::json(&Started {
            user_code: &started.user_code,
            verification_uri: &started.verification_uri,
            verification_uri_complete: started.verification_uri_complete.as_deref(),
            expires_in: timing.expires_in.as_secs(),
            interval: timing.interval.as_secs(),
        })?;
    } else {
        output::line(format!("user code: {}", started.user_code))?;
        output::line(format!("open this URL in a signed-in browser: {approval}"))?;
        output::diagnostic(
            "approve only if you started this login yourself; waiting for approval…",
        )?;
    }
    let deadline = timing.deadline;
    let exchanged: Exchanged = poll_device_flow(&timing, || {
        crate::auth::exchange(
            &trust,
            &origin,
            "/rpc/userLogins/exchangeDeviceCode",
            serde_json::json!({ "deviceCode": started.device_code }),
            "wssp login",
            deadline,
        )
    })?;
    // From here on the key exists on the server: no deadline check may drop
    // it, and a login that cannot be saved is revoked again.
    validate_sdk_key(&exchanged.secret)
        .context("the server returned a credential that is not a `wssp_sdk_` key")?;
    let key_id = exchanged.key_id.clone();
    let login = UserLogin {
        origin: origin.clone(),
        key_id: exchanged.key_id,
        name: crate::output::remote_message(&exchanged.name),
        secret: exchanged.secret,
        scopes: exchanged.scopes,
        pool_mode: exchanged.pool_mode,
        pool_ids: exchanged.pool_ids,
        own_sandboxes_only: exchanged.own_sandboxes_only,
        expires_at: exchanged.expires_at,
        max_live_sandboxes: exchanged.max_live_sandboxes,
        user_email: crate::output::remote_message(&exchanged.email),
        created_at: crate::user_state::utc_now_iso(),
        ca_file: saved_ca_file,
    };
    let saved = (|| -> Result<()> {
        anyhow::ensure!(
            !login.key_id.is_empty(),
            "the server returned a login without a key id"
        );
        UserStore::open()?.write(&login)
    })();
    if let Err(error) = saved {
        return Err(revoke_unsaved(&login, selected, &key_id, error));
    }
    let mut late = Vec::new();
    if let Some(previous) = previous.filter(|p| p.key_id != login.key_id) {
        late.push(format!(
            "replaced the previous login `{}` ({}); it stays valid until it expires or you revoke it on the dashboard's SDK keys page",
            previous.name, previous.key_id
        ));
    }
    if crate::user_state::env_credential_present() {
        late.push(format!(
            "`{}` or `{}` is set: user commands in this environment use them, not the saved login",
            crate::user_state::API_KEY_ENV,
            crate::user_state::SERVER_ENV
        ));
    }
    let granted = Granted::of(&login);
    if args.json {
        warnings.extend(late);
        output::json(&LoggedIn { granted, warnings })
    } else {
        for warning in late {
            output::warning(warning)?;
        }
        output::line("logged in")?;
        let slugs = lookup_pool_slugs(&login, selected);
        granted.print(slugs.as_deref())
    }
}

/// Best effort: revoke a minted key that could not be saved (`DELETE /v1/key`
/// with the new key itself), and report both.
fn revoke_unsaved(
    login: &UserLogin,
    ca_file: Option<PathBuf>,
    key_id: &str,
    error: anyhow::Error,
) -> anyhow::Error {
    let credential = crate::user_state::UserCredential {
        origin: login.origin.clone(),
        secret: login.secret.clone(),
        source: crate::user_state::CredentialSource::File,
        login: None,
        ca_file,
    };
    let revoked = crate::api::Client::new(&credential).and_then(|client| {
        client.send::<serde_json::Value, serde_json::Value>(
            crate::api::Method::Delete,
            "/v1/key",
            None,
        )
    });
    let label = if key_id.is_empty() {
        "the new key".to_owned()
    } else {
        format!("the new key `{}`", output::remote_message(key_id))
    };
    match revoked {
        Ok(_) => error.context(format!(
            "saving the login failed; {label} was revoked on the server"
        )),
        Err(revoke) => error.context(format!(
            "saving the login failed and revoking {label} also failed ({}); revoke it on the dashboard's SDK keys page",
            crate::exit::message_for(&revoke)
        )),
    }
}
