//! `wssp sandbox …`: the `/v1` sandbox routes (packages/sandbox-contracts/src/routes.ts)
//! with the user login (`src/user_state.rs`).
//!
//! Mutations send one idempotency key and are re-sent unchanged only while the
//! answer is transient (`Client::mutate`). Accepted operations are followed
//! with held reads (`waitMs`) of `GET /v1/operations/{id}`.

mod exec;
mod files;
mod ports;
mod shell;

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{Value, json};

use crate::api::{Client, Method, MutationReceipt, OperationError, WAIT_MS};
use crate::exit::{CodedError, ExitCode};
use crate::output;

/// How long a `--wait` (or a file or process call) follows its operation.
const OPERATION_DEADLINE: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, clap::Args)]
pub struct Args {
    #[command(subcommand)]
    pub command: SandboxCommand,
}

#[derive(Debug, clap::Subcommand)]
pub enum SandboxCommand {
    /// Create a sandbox from a template on a pool or one of your hosts.
    Create(CreateArgs),
    /// List sandboxes (newest first, one bounded page).
    List(ListArgs),
    /// Show one sandbox.
    Get(IdArgs),
    /// Run a command in a sandbox and stream its output; exits with the command's exit code.
    Exec(exec::ExecArgs),
    /// Open a shell in a sandbox, or run a command there interactively; exits with the remote status.
    Shell(shell::ShellArgs),
    /// List the commands running in a sandbox.
    Ps(exec::PsArgs),
    /// Print a command's retained output by operation id.
    Logs(exec::LogsArgs),
    /// Stop a sandbox (its disk is kept).
    Stop(LifecycleArgs),
    /// Start a stopped sandbox again (cold reconnect).
    Start(LifecycleArgs),
    /// Destroy a sandbox and its disk.
    Destroy(LifecycleArgs),
    /// Guest files: list, stat, read, write, mkdir, move and remove.
    Files(files::Args),
    /// Preview tunnel ports: show, expose, change, close and link.
    Ports(ports::Args),
}

#[derive(Debug, clap::Args)]
pub struct CreateArgs {
    /// Template selector: a template slug or id, `slug:tag`, `template/<id>` or `revision/<id>`.
    #[arg(long, value_name = "SEL")]
    pub template: String,

    /// Place the sandbox through this pool.
    #[arg(
        long,
        value_name = "ID",
        conflicts_with = "host",
        required_unless_present = "host"
    )]
    pub pool: Option<String>,

    /// Place the sandbox on this host (one of yours).
    #[arg(long, value_name = "ID")]
    pub host: Option<String>,

    /// Sandbox name (default: a generated adjective-noun name).
    #[arg(long, value_name = "N")]
    pub name: Option<String>,

    /// Lease, e.g. `30m`, `2h`, `1d` (`0`: no lease timer where policy allows it; default 5m).
    #[arg(long, value_name = "DUR", value_parser = parse_duration_ms)]
    pub timeout: Option<u64>,

    /// vCPUs (default: the template revision's).
    #[arg(long, value_name = "N")]
    pub cpu: Option<u32>,

    /// Guest memory in MiB (default: the template revision's).
    #[arg(long, value_name = "MiB")]
    pub memory: Option<u32>,

    /// Root disk in GiB (default: the template revision's).
    #[arg(long, value_name = "GiB")]
    pub disk: Option<u32>,

    /// Metadata label `key=value` (repeatable).
    #[arg(long, value_name = "K=V", value_parser = parse_key_value)]
    pub metadata: Vec<(String, String)>,

    /// Wait until the sandbox is READY (or fails).
    #[arg(long)]
    pub wait: bool,

    /// Emit JSON instead of human-readable text.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, clap::Args)]
pub struct ListArgs {
    /// Only sandboxes in this state (repeatable; default READY), e.g. `--state STOPPED`.
    #[arg(long = "state", value_name = "S")]
    pub states: Vec<String>,

    /// Page size, 1–100 (default 20).
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u16).range(1..=100))]
    pub limit: Option<u16>,

    /// Continue after a previous page (`nextCursor`).
    #[arg(long, value_name = "C")]
    pub cursor: Option<String>,

    /// Emit JSON instead of human-readable text.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, clap::Args)]
pub struct IdArgs {
    /// Sandbox id.
    pub id: String,

    /// Emit JSON instead of human-readable text.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, clap::Args)]
pub struct LifecycleArgs {
    /// Sandbox id.
    pub id: String,

    /// Wait until the operation finishes (and, for `start`, the sandbox is READY).
    #[arg(long)]
    pub wait: bool,

    /// Emit JSON instead of human-readable text.
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &Args) -> Result<()> {
    match &args.command {
        SandboxCommand::Create(args) => create(args),
        SandboxCommand::List(args) => list(args),
        SandboxCommand::Get(args) => get(args),
        SandboxCommand::Exec(args) => exec::exec(args),
        SandboxCommand::Shell(args) => shell::shell(args),
        SandboxCommand::Ps(args) => exec::ps(args),
        SandboxCommand::Logs(args) => exec::logs(args),
        SandboxCommand::Stop(args) => lifecycle(args, Lifecycle::Stop),
        SandboxCommand::Start(args) => lifecycle(args, Lifecycle::Start),
        SandboxCommand::Destroy(args) => lifecycle(args, Lifecycle::Destroy),
        SandboxCommand::Files(args) => files::run(args),
        SandboxCommand::Ports(args) => ports::run(args),
    }
}

/// The logged-in client; exit 7 before any network call without a login.
pub(crate) fn client(json: bool) -> Result<Client> {
    output::set_json_errors(json);
    Client::new(&crate::user_state::require_credential()?)
}

/// A path segment from user input: `/v1` ids are `[A-Za-z0-9_-]{1,64}`.
pub(crate) fn segment(id: &str) -> Result<&str> {
    let valid = !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if valid {
        Ok(id)
    } else {
        Err(anyhow::anyhow!(
            "invalid id `{}`",
            output::remote_message(id)
        ))
        .context(CodedError::new(ExitCode::Usage))
    }
}

/// A write to a closed stdout or stderr (`| head`) becomes exit 141; any
/// other error is returned unchanged.
pub(crate) fn output_closed(error: anyhow::Error) -> anyhow::Error {
    if crate::exit::is_broken_pipe(&error) {
        closed_output_error("the output was closed (broken pipe)".to_owned())
    } else {
        error
    }
}

/// The exit-141 error, without the I/O cause that `main` treats as success.
pub(crate) fn closed_output_error(message: String) -> anyhow::Error {
    anyhow::Error::msg(message).context(CodedError::new(ExitCode::OutputClosed))
}

/// Parse `90s`, `30m`, `2h`, `1d`, `500ms` or `0` into milliseconds.
pub fn parse_duration_ms(text: &str) -> Result<u64, String> {
    let text = text.trim();
    if text == "0" {
        return Ok(0);
    }
    let split = text
        .find(|c: char| !c.is_ascii_digit())
        .ok_or_else(|| format!("`{text}` needs a unit: ms, s, m, h or d"))?;
    let (number, unit) = text.split_at(split);
    let number: u64 = number
        .parse()
        .map_err(|_| format!("`{text}` is not a duration"))?;
    let factor = match unit {
        "ms" => 1,
        "s" => 1_000,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        _ => return Err(format!("`{text}` needs a unit: ms, s, m, h or d")),
    };
    number
        .checked_mul(factor)
        .ok_or_else(|| format!("`{text}` is too long"))
}

/// Parse `KEY=VALUE`.
pub fn parse_key_value(text: &str) -> Result<(String, String), String> {
    match text.split_once('=') {
        Some((key, value)) if !key.is_empty() => Ok((key.to_owned(), value.to_owned())),
        _ => Err(format!("expected `KEY=VALUE`, got `{text}`")),
    }
}

fn str_field<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("-")
}

/// Follow an accepted operation until it leaves `pending`; fail unless it
/// succeeded. Returns the operation.
pub(crate) fn await_operation(client: &Client, operation_id: &str) -> Result<Value> {
    let deadline = Instant::now() + OPERATION_DEADLINE;
    let path = format!("/v1/operations/{}", segment(operation_id)?);
    loop {
        let operation: Value =
            crate::api::retry_transient(deadline, || client.get_held(&path, &[], WAIT_MS))?;
        let outcome = str_field(&operation, "outcome");
        if outcome != "pending" {
            return if outcome == "succeeded" {
                Ok(operation)
            } else {
                Err(operation_failure(operation_id, &operation))
            };
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "operation `{operation_id}` is still {}; follow it with `wssp sandbox get` or rerun with a later check",
                str_field(&operation, "state")
            );
        }
    }
}

pub(crate) fn operation_failure(operation_id: &str, operation: &Value) -> anyhow::Error {
    let error = OperationError {
        operation_id: operation_id.to_owned(),
        outcome: str_field(operation, "outcome").to_owned(),
        state: str_field(operation, "state").to_owned(),
        error_code: operation
            .get("errorCode")
            .and_then(Value::as_str)
            .map(output::remote_message),
    };
    let code = error.exit_code();
    anyhow::Error::new(error).context(CodedError::new(code))
}

/// Submit a typed-result operation (file metadata, process list), follow it
/// and read its result (`GET /v1/operations/{id}/result`).
pub(crate) fn result_operation<B: Serialize>(
    client: &Client,
    path: &str,
    body: &B,
) -> Result<Value> {
    let receipt: MutationReceipt = client.mutate(Method::Post, path, body)?;
    await_operation(client, &receipt.operation_id)?;
    let result_path = format!("/v1/operations/{}/result", segment(&receipt.operation_id)?);
    let deadline = Instant::now() + Duration::from_secs(120);
    let result: Value =
        crate::api::retry_transient(deadline, || client.get_held(&result_path, &[], WAIT_MS))?;
    result
        .get("result")
        .filter(|r| !r.is_null())
        .cloned()
        .context("the operation succeeded without a result")
}

/// Wait for a sandbox to be READY; stop on a state it cannot leave.
fn wait_ready(client: &Client, sandbox_id: &str) -> Result<Value> {
    let deadline = Instant::now() + OPERATION_DEADLINE;
    let path = format!("/v1/sandboxes/{}", segment(sandbox_id)?);
    loop {
        let sandbox: Value = crate::api::retry_transient(deadline, || client.get(&path, &[]))?;
        match str_field(&sandbox, "state") {
            "READY" => return Ok(sandbox),
            state @ ("ERROR" | "DELETED" | "HOST_LOST") => {
                anyhow::bail!("sandbox `{sandbox_id}` is {state} and will not become READY")
            }
            state => {
                if Instant::now() >= deadline {
                    anyhow::bail!("sandbox `{sandbox_id}` is still {state}");
                }
                tracing::debug!(state, "waiting for the sandbox to be READY");
                std::thread::sleep(Duration::from_secs(2));
            }
        }
    }
}

fn print_sandbox(sandbox: &Value) -> Result<()> {
    for key in [
        "id",
        "name",
        "state",
        "templateId",
        "templateRevisionId",
        "hostId",
        "originPoolId",
        "endAt",
        "createdAt",
    ] {
        let value = match sandbox.get(key) {
            Some(Value::String(text)) => output::remote_message(text),
            Some(Value::Null) | None => "-".to_owned(),
            Some(other) => other.to_string(),
        };
        output::line(format!("{key}: {value}"))?;
    }
    output::line(format!(
        "size: {} vCPU, {} MiB, {} GiB",
        sandbox.get("cpuCount").unwrap_or(&Value::Null),
        sandbox.get("memoryMiB").unwrap_or(&Value::Null),
        sandbox.get("diskGiB").unwrap_or(&Value::Null)
    ))?;
    if let Some(Value::Object(metadata)) = sandbox.get("metadata") {
        for (key, value) in metadata {
            output::line(format!(
                "metadata: {}={}",
                output::remote_message(key),
                output::remote_message(value.as_str().unwrap_or_default())
            ))?;
        }
    }
    Ok(())
}

/// `POST /v1/sandboxes` (`createSandboxBodySchema`).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateBody<'a> {
    template: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pool_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sandbox_host_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timeout_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cpu_count: Option<u32>,
    #[serde(rename = "memoryMiB", skip_serializing_if = "Option::is_none")]
    memory_mi_b: Option<u32>,
    #[serde(rename = "diskGiB", skip_serializing_if = "Option::is_none")]
    disk_gi_b: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<std::collections::BTreeMap<&'a str, &'a str>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Accepted<'a> {
    operation_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    sandbox_id: Option<&'a str>,
    state: &'a str,
}

fn create(args: &CreateArgs) -> Result<()> {
    let client = client(args.json)?;
    let body = CreateBody {
        template: &args.template,
        pool_id: args.pool.as_deref(),
        sandbox_host_id: if args.pool.is_some() {
            None
        } else {
            args.host.as_deref()
        },
        name: args.name.as_deref(),
        timeout_ms: args.timeout,
        cpu_count: args.cpu,
        memory_mi_b: args.memory,
        disk_gi_b: args.disk,
        metadata: (!args.metadata.is_empty()).then(|| {
            args.metadata
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect()
        }),
    };
    anyhow::ensure!(
        body.pool_id.is_some() || body.sandbox_host_id.is_some(),
        "pass `--pool` or `--host`"
    );
    let receipt: MutationReceipt = client.mutate(Method::Post, "/v1/sandboxes", &body)?;
    if args.wait {
        let operation = await_operation(&client, &receipt.operation_id)?;
        let sandbox_id = operation
            .get("sandboxId")
            .and_then(Value::as_str)
            .context("the create operation carries no sandbox id")?;
        let sandbox = wait_ready(&client, sandbox_id)?;
        return if args.json {
            output::json(&sandbox)
        } else {
            print_sandbox(&sandbox)
        };
    }
    let path = format!("/v1/operations/{}", segment(&receipt.operation_id)?);
    let operation: Value = client.get(&path, &[])?;
    let accepted = Accepted {
        operation_id: &receipt.operation_id,
        sandbox_id: operation.get("sandboxId").and_then(Value::as_str),
        state: str_field(&operation, "state"),
    };
    if args.json {
        output::json(&accepted)
    } else {
        output::line(format!(
            "sandbox {} accepted (operation {}, {})",
            accepted.sandbox_id.unwrap_or("-"),
            accepted.operation_id,
            accepted.state
        ))
    }
}

fn list(args: &ListArgs) -> Result<()> {
    let client = client(args.json)?;
    let mut query = Vec::new();
    if !args.states.is_empty() {
        let states: Vec<String> = args.states.iter().map(|s| s.to_ascii_uppercase()).collect();
        query.push(("states", states.join(",")));
    }
    if let Some(limit) = args.limit {
        query.push(("limit", limit.to_string()));
    }
    if let Some(cursor) = &args.cursor {
        query.push(("cursor", cursor.clone()));
    }
    let page: Value = client.get("/v1/sandboxes", &query)?;
    if args.json {
        return output::json(&page);
    }
    let items = page
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if items.is_empty() {
        output::line("no sandboxes")?;
    } else {
        output::line(format!(
            "{:<26} {:<28} {:<22} {:<26} CREATED",
            "ID", "NAME", "STATE", "HOST"
        ))?;
    }
    for item in &items {
        output::line(format!(
            "{:<26} {:<28} {:<22} {:<26} {}",
            output::remote_message(str_field(item, "id")),
            output::remote_message(str_field(item, "name")),
            str_field(item, "state"),
            output::remote_message(str_field(item, "hostId")),
            str_field(item, "createdAt")
        ))?;
    }
    print_next_cursor(&page, &list_next_command(args))
}

/// `wssp sandbox list` with every option the cursor binds (all but it).
fn list_next_command(args: &ListArgs) -> String {
    let mut command = String::from("wssp sandbox list");
    for state in &args.states {
        command.push_str(" --state ");
        command.push_str(&shell_quote(&state.to_ascii_uppercase()));
    }
    if let Some(limit) = args.limit {
        command.push_str(&format!(" --limit {limit}"));
    }
    command
}

/// The next-page hint of a bounded list. `command` repeats every option the
/// cursor binds, already shell-quoted.
pub(crate) fn print_next_cursor(page: &Value, command: &str) -> Result<()> {
    if let Some(cursor) = page.get("nextCursor").and_then(Value::as_str) {
        output::line(format!(
            "next page: {command} --cursor {}",
            shell_quote(&output::remote_message(cursor))
        ))?;
    }
    Ok(())
}

/// `text` as one POSIX shell word: unchanged when only safe characters,
/// else single-quoted (`'` written as `'\''`).
pub(crate) fn shell_quote(text: &str) -> String {
    let safe = !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-./:=@%+,".contains(c));
    if safe {
        text.to_owned()
    } else {
        format!("'{}'", text.replace('\'', "'\\''"))
    }
}

fn get(args: &IdArgs) -> Result<()> {
    let client = client(args.json)?;
    let sandbox: Value = client.get(&format!("/v1/sandboxes/{}", segment(&args.id)?), &[])?;
    if args.json {
        output::json(&sandbox)
    } else {
        print_sandbox(&sandbox)
    }
}

#[derive(Clone, Copy)]
enum Lifecycle {
    Stop,
    Start,
    Destroy,
}

fn lifecycle(args: &LifecycleArgs, action: Lifecycle) -> Result<()> {
    let client = client(args.json)?;
    let id = segment(&args.id)?;
    let (method, path, body, verb) = match action {
        Lifecycle::Stop => (
            Method::Post,
            format!("/v1/sandboxes/{id}/stop"),
            json!({}),
            "stop",
        ),
        Lifecycle::Start => (
            Method::Post,
            format!("/v1/sandboxes/{id}/reconnect"),
            json!({ "mode": "cold" }),
            "start",
        ),
        Lifecycle::Destroy => (
            Method::Delete,
            format!("/v1/sandboxes/{id}"),
            json!({}),
            "destroy",
        ),
    };
    let receipt: MutationReceipt = client.mutate(method, &path, &body)?;
    if !args.wait {
        return if args.json {
            output::json(&receipt)
        } else {
            output::line(format!(
                "{verb} accepted (operation {}, {})",
                receipt.operation_id, receipt.state
            ))
        };
    }
    let operation = await_operation(&client, &receipt.operation_id)?;
    if matches!(action, Lifecycle::Start) {
        let sandbox = wait_ready(&client, id)?;
        return if args.json {
            output::json(&sandbox)
        } else {
            print_sandbox(&sandbox)
        };
    }
    if args.json {
        output::json(&operation)
    } else {
        output::line(format!(
            "{verb} succeeded (operation {})",
            receipt.operation_id
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_durations() {
        assert_eq!(parse_duration_ms("0"), Ok(0));
        assert_eq!(parse_duration_ms("500ms"), Ok(500));
        assert_eq!(parse_duration_ms("90s"), Ok(90_000));
        assert_eq!(parse_duration_ms("30m"), Ok(1_800_000));
        assert_eq!(parse_duration_ms("2h"), Ok(7_200_000));
        assert_eq!(parse_duration_ms("1d"), Ok(86_400_000));
        for bad in ["", "5", "m", "5x", "-1s", "1.5h"] {
            assert!(parse_duration_ms(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn ids_are_path_safe() {
        assert!(segment("sbx_1-a").is_ok());
        for bad in ["", "../x", "a/b", "a?b", &"a".repeat(65)] {
            assert!(segment(bad).is_err(), "{bad}");
        }
    }
}
