//! `wssp template list|get`: templates visible to the login's key
//! (`GET /v1/templates`, `GET /v1/templates/{id}/revisions`).

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;

use crate::commands::sandbox::{client, print_next_cursor, segment};
use crate::exit::{CodedError, ExitCode};
use crate::output;

/// `template get` pages through `GET /v1/templates` (100 a page) for at most
/// this many pages; past it the search stops with its own error.
const GET_MAX_PAGES: usize = 100;
const GET_PAGE_SIZE: usize = 100;

#[derive(Debug, clap::Args)]
pub struct Args {
    #[command(subcommand)]
    pub command: TemplateCommand,
}

#[derive(Debug, clap::Subcommand)]
pub enum TemplateCommand {
    /// List templates (newest first, one bounded page).
    List(ListArgs),
    /// Show one template and its revisions.
    Get(GetArgs),
}

#[derive(Debug, clap::Args)]
pub struct ListArgs {
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
pub struct GetArgs {
    /// Template id.
    pub id: String,
    /// Continue the revision list after a previous page (`revisionsNextCursor`).
    #[arg(long, value_name = "C")]
    pub cursor: Option<String>,
    /// Emit JSON instead of human-readable text.
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &Args) -> Result<()> {
    match &args.command {
        TemplateCommand::List(args) => list(args),
        TemplateCommand::Get(args) => get(args),
    }
}

fn field(value: &Value, key: &str) -> String {
    match value.get(key) {
        Some(Value::String(text)) => output::remote_message(text),
        Some(Value::Null) | None => "-".to_owned(),
        Some(other) => other.to_string(),
    }
}

fn list(args: &ListArgs) -> Result<()> {
    let client = client(args.json)?;
    let mut query = Vec::new();
    if let Some(limit) = args.limit {
        query.push(("limit", limit.to_string()));
    }
    if let Some(cursor) = &args.cursor {
        query.push(("cursor", cursor.clone()));
    }
    let page: Value = client.get("/v1/templates", &query)?;
    if args.json {
        return output::json(&page);
    }
    let items = page
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if items.is_empty() {
        output::line("no templates")?;
    } else {
        output::line(format!("{:<26} {:<32} LABEL", "ID", "SLUG"))?;
    }
    for item in &items {
        let archived = if item.get("archivedAt").is_some_and(|v| !v.is_null()) {
            " (archived)"
        } else {
            ""
        };
        output::line(format!(
            "{:<26} {:<32} {}{archived}",
            field(item, "id"),
            field(item, "slug"),
            field(item, "label")
        ))?;
    }
    let mut command = String::from("wssp template list");
    if let Some(limit) = args.limit {
        command.push_str(&format!(" --limit {limit}"));
    }
    print_next_cursor(&page, &command)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TemplateDetail {
    template: Value,
    revisions: Vec<Value>,
    revisions_next_cursor: Option<String>,
}

/// The list row of template `id`: every page until it is found or the list
/// ends (not found, exit 3), at most [`GET_MAX_PAGES`] pages (a distinct
/// error, never a false not-found).
fn find_template(client: &crate::api::Client, id: &str) -> Result<Value> {
    let mut cursor: Option<String> = None;
    let mut searched = 0_usize;
    for _ in 0..GET_MAX_PAGES {
        let mut query = vec![("limit", GET_PAGE_SIZE.to_string())];
        if let Some(cursor) = &cursor {
            query.push(("cursor", cursor.clone()));
        }
        let page: Value = client.get("/v1/templates", &query)?;
        let items = page
            .get("items")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        searched += items.len();
        if let Some(found) = items
            .iter()
            .find(|item| item.get("id").and_then(Value::as_str) == Some(id))
        {
            return Ok(found.clone());
        }
        let next = page
            .get("nextCursor")
            .and_then(Value::as_str)
            .map(str::to_owned);
        match next {
            None => {
                return Err(anyhow::anyhow!("template `{id}` not found"))
                    .context(CodedError::new(ExitCode::NotFound));
            }
            Some(next) => {
                anyhow::ensure!(
                    cursor.as_deref() != Some(next.as_str()),
                    "the template list made no progress"
                );
                cursor = Some(next);
            }
        }
    }
    anyhow::bail!(
        "searched {searched} templates without finding template `{id}` (the search stops after {GET_MAX_PAGES} pages)"
    )
}

fn get(args: &GetArgs) -> Result<()> {
    let client = client(args.json)?;
    let id = segment(&args.id)?;
    // The revisions route answers `sandbox.template_not_found` (404, exit 3)
    // for a template the key cannot see: the authoritative not-found.
    let mut query = vec![("limit", "100".to_owned())];
    if let Some(cursor) = &args.cursor {
        query.push(("cursor", cursor.clone()));
    }
    let page: Value = client.get(&format!("/v1/templates/{id}/revisions"), &query)?;
    // There is no single-template route: find the list row, page by page.
    let template = find_template(&client, id)?;
    let detail = TemplateDetail {
        template,
        revisions: page
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        revisions_next_cursor: page
            .get("nextCursor")
            .and_then(Value::as_str)
            .map(str::to_owned),
    };
    if args.json {
        return output::json(&detail);
    }
    for key in ["id", "slug", "label", "archivedAt", "createdAt"] {
        output::line(format!("{key}: {}", field(&detail.template, key)))?;
    }
    output::line(format!(
        "{:<26} {:>4} {:>5} {:>8} {:>9} {:<10} RETIRED",
        "REVISION", "#", "vCPU", "MiB", "DISK GiB", "ARCH"
    ))?;
    for revision in &detail.revisions {
        output::line(format!(
            "{:<26} {:>4} {:>5} {:>8} {:>9} {:<10} {}",
            field(revision, "id"),
            field(revision, "revision"),
            field(revision, "cpuCount"),
            field(revision, "memoryMiB"),
            field(revision, "defaultDiskGiB"),
            field(revision, "architecture"),
            field(revision, "retiredAt")
        ))?;
    }
    if let Some(cursor) = &detail.revisions_next_cursor {
        output::line(format!(
            "more revisions: wssp template get {id} --cursor {}",
            crate::commands::sandbox::shell_quote(&output::remote_message(cursor))
        ))?;
    }
    Ok(())
}
