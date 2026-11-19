//! `wssp sandbox files …`: guest file metadata operations, downloads
//! (`POST …/files/download`, then `GET /v1/operations/{id}/content`) and
//! uploads (`/v1/transfers`: reserve the length, put fixed chunks, commit the
//! SHA-256). Paths name files inside the VM only.

use std::io::{Read, Seek, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{Value, json};

use super::{await_operation, client, result_operation, segment, str_field};
use crate::api::{Client, Method, MutationReceipt, hex};
use crate::exit::{CodedError, ExitCode};
use crate::output;

#[derive(Debug, clap::Args)]
pub struct Args {
    #[command(subcommand)]
    pub command: FilesCommand,
}

#[derive(Debug, clap::Subcommand)]
pub enum FilesCommand {
    /// List a directory.
    Ls(LsArgs),
    /// Show one entry's metadata.
    Stat(PathArgs),
    /// Print a file's bytes (or save them with `--output`).
    Read(ReadArgs),
    /// Replace a file with the bytes of a local file or stdin.
    Write(WriteArgs),
    /// Create a directory.
    Mkdir(PathArgs),
    /// Move or rename an entry.
    Mv(MvArgs),
    /// Remove an entry.
    Rm(RmArgs),
}

#[derive(Debug, clap::Args)]
pub struct PathArgs {
    /// Sandbox id.
    pub id: String,
    /// Absolute guest path.
    pub path: String,
    /// Emit JSON instead of human-readable text.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, clap::Args)]
pub struct LsArgs {
    /// Sandbox id.
    pub id: String,
    /// Absolute guest directory path.
    pub path: String,
    /// Levels to list below the directory, 1–8.
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u8).range(1..=8))]
    pub depth: Option<u8>,
    /// Page size, 1–100 (default 100).
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
pub struct ReadArgs {
    /// Sandbox id.
    pub id: String,
    /// Absolute guest file path.
    pub path: String,
    /// Write the bytes to this local file instead of stdout.
    #[arg(long, short, value_name = "FILE")]
    pub output: Option<PathBuf>,
    /// With `--output`: print `{path, bytes, sha256}` as JSON.
    #[arg(long, requires = "output")]
    pub json: bool,
}

#[derive(Debug, clap::Args)]
pub struct WriteArgs {
    /// Sandbox id.
    pub id: String,
    /// Absolute guest file path.
    pub path: String,
    /// Local file to upload, or `-` for stdin.
    #[arg(long, value_name = "FILE|-")]
    pub from: String,
    /// Emit JSON instead of human-readable text.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, clap::Args)]
pub struct MvArgs {
    /// Sandbox id.
    pub id: String,
    /// Absolute guest source path.
    pub path: String,
    /// Absolute guest destination path.
    pub dest: String,
    /// Emit JSON instead of human-readable text.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, clap::Args)]
pub struct RmArgs {
    /// Sandbox id.
    pub id: String,
    /// Absolute guest path.
    pub path: String,
    /// Remove a directory and everything in it.
    #[arg(long, short)]
    pub recursive: bool,
    /// Emit JSON instead of human-readable text.
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &Args) -> Result<()> {
    match &args.command {
        FilesCommand::Ls(args) => ls(args),
        FilesCommand::Stat(args) => metadata(args, "stat"),
        FilesCommand::Read(args) => read(args),
        FilesCommand::Write(args) => write(args),
        FilesCommand::Mkdir(args) => metadata(args, "mkdir"),
        FilesCommand::Mv(args) => mv(args),
        FilesCommand::Rm(args) => rm(args),
    }
}

fn entry_line(entry: &Value) -> String {
    let kind = match str_field(entry, "type") {
        "dir" => 'd',
        "symlink" => 'l',
        "file" => '-',
        _ => '?',
    };
    let mut line = format!(
        "{kind}{} {:>12} {:<24} {}",
        str_field(entry, "permissions"),
        entry
            .get("size")
            .and_then(Value::as_u64)
            .unwrap_or_default(),
        entry
            .get("modifiedTime")
            .and_then(Value::as_str)
            .unwrap_or("-"),
        output::remote_message(str_field(entry, "path"))
    );
    if let Some(target) = entry.get("symlinkTarget").and_then(Value::as_str) {
        line.push_str(&format!(" -> {}", output::remote_message(target)));
    }
    line
}

/// `listBodySchema`.
#[derive(Serialize)]
struct ListBody<'a> {
    path: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    depth: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<&'a str>,
}

/// `removeBodySchema`.
#[derive(Serialize)]
struct RemoveBody<'a> {
    path: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    recursive: Option<bool>,
}

fn ls(args: &LsArgs) -> Result<()> {
    let client = client(args.json)?;
    let id = segment(&args.id)?;
    let body = ListBody {
        path: &args.path,
        depth: args.depth,
        limit: args.limit,
        cursor: args.cursor.as_deref(),
    };
    let result = result_operation(&client, &format!("/v1/sandboxes/{id}/files/list"), &body)?;
    if args.json {
        return output::json(&result);
    }
    for entry in result
        .get("items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        output::line(entry_line(entry))?;
    }
    let mut command = format!(
        "wssp sandbox files ls {} {}",
        super::shell_quote(&args.id),
        super::shell_quote(&args.path)
    );
    if let Some(depth) = args.depth {
        command.push_str(&format!(" --depth {depth}"));
    }
    if let Some(limit) = args.limit {
        command.push_str(&format!(" --limit {limit}"));
    }
    super::print_next_cursor(&result, &command)
}

fn metadata(args: &PathArgs, action: &str) -> Result<()> {
    let client = client(args.json)?;
    let id = segment(&args.id)?;
    let result = result_operation(
        &client,
        &format!("/v1/sandboxes/{id}/files/{action}"),
        &json!({ "path": args.path }),
    )?;
    if args.json {
        return output::json(&result);
    }
    match action {
        "stat" => output::line(entry_line(result.get("entry").unwrap_or(&Value::Null))),
        _ if result.get("created").and_then(Value::as_bool) == Some(false) => {
            output::line(format!("`{}` already exists", args.path))
        }
        _ => output::line(format!("created `{}`", args.path)),
    }
}

fn mv(args: &MvArgs) -> Result<()> {
    let client = client(args.json)?;
    let id = segment(&args.id)?;
    let result = result_operation(
        &client,
        &format!("/v1/sandboxes/{id}/files/move"),
        &json!({ "path": args.path, "destPath": args.dest }),
    )?;
    if args.json {
        return output::json(&result);
    }
    output::line(format!("moved `{}` to `{}`", args.path, args.dest))
}

fn rm(args: &RmArgs) -> Result<()> {
    let client = client(args.json)?;
    let id = segment(&args.id)?;
    let body = RemoveBody {
        path: &args.path,
        recursive: args.recursive.then_some(true),
    };
    let result = result_operation(&client, &format!("/v1/sandboxes/{id}/files/remove"), &body)?;
    if args.json {
        return output::json(&result);
    }
    output::line(format!("removed `{}`", args.path))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Saved {
    path: PathBuf,
    bytes: u64,
    sha256: String,
}

fn read(args: &ReadArgs) -> Result<()> {
    let client = client(args.json)?;
    let id = segment(&args.id)?;
    let receipt: MutationReceipt = client.mutate(
        Method::Post,
        &format!("/v1/sandboxes/{id}/files/download"),
        &json!({ "path": args.path }),
    )?;
    await_operation(&client, &receipt.operation_id)?;
    let content = format!("/v1/operations/{}/content", segment(&receipt.operation_id)?);
    let Some(target) = &args.output else {
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        // A closed stdout (`| head`) is exit 141, never a silent success.
        client
            .download(&content, &mut out)
            .map_err(super::output_closed)?;
        return out
            .flush()
            .context("flushing stdout")
            .map_err(super::output_closed);
    };
    // Write next to the target, then rename: a failed download never leaves
    // a partial file under the requested name.
    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    // Staged owner-only; published with the existing destination's
    // permission bits (never wider), or 0666 less the umask for a new file.
    #[cfg(unix)]
    let published = published_mode(target)?;
    let mut builder = tempfile::Builder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o600));
    }
    let mut temp = builder
        .tempfile_in(parent)
        .with_context(|| format!("creating a file in `{}`", parent.display()))?;
    let downloaded = client.download(&content, temp.as_file_mut())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(published))
            .context("setting the download's permissions")?;
    }
    temp.as_file().sync_all().context("flushing the download")?;
    temp.persist(target)
        .with_context(|| format!("saving `{}`", target.display()))?;
    if args.json {
        output::json(&Saved {
            path: target.clone(),
            bytes: downloaded.bytes,
            sha256: downloaded.sha256,
        })
    } else {
        output::diagnostic(format!(
            "saved {} bytes to `{}`",
            downloaded.bytes,
            target.display()
        ))
    }
}

/// The mode `files read --output` publishes `target` with: an existing
/// destination keeps its permission bits (never widened, no set-id bits);
/// a new file gets 0666 less the process umask, like a shell redirect.
#[cfg(unix)]
fn published_mode(target: &std::path::Path) -> Result<u32> {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(target) {
        Ok(meta) => Ok(meta.permissions().mode() & 0o777),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0o666 & !umask()),
        Err(error) => Err(error).with_context(|| format!("reading `{}`", target.display())),
    }
}

/// The process umask: `/proc/self/status` where it is reported (no change
/// to process state), else read by setting and restoring it.
#[cfg(unix)]
fn umask() -> u32 {
    let reported = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                let value = line.strip_prefix("Umask:")?.trim();
                u32::from_str_radix(value, 8).ok()
            })
        });
    reported.unwrap_or_else(|| {
        use rustix::fs::Mode;
        let previous = rustix::process::umask(Mode::from_raw_mode(0o077));
        rustix::process::umask(previous);
        previous.as_raw_mode() & 0o777
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Written<'a> {
    path: &'a str,
    bytes: u64,
    sha256: &'a str,
    operation_id: &'a str,
}

/// The upload source, with a known length: a regular local file, or anything
/// else (stdin as `-`, a FIFO, `/dev/stdin`, `<(cmd)`) spooled to a private
/// temporary file first.
fn source(from: &str) -> Result<std::fs::File> {
    if from == "-" {
        return spool(&mut std::io::stdin().lock(), "stdin");
    }
    let mut file = std::fs::File::open(from).with_context(|| format!("opening `{from}`"))?;
    if file
        .metadata()
        .with_context(|| format!("reading `{from}`"))?
        .is_file()
    {
        return Ok(file);
    }
    spool(&mut file, &format!("`{from}`"))
}

fn spool(reader: &mut dyn Read, label: &str) -> Result<std::fs::File> {
    let mut spool = tempfile::tempfile().context("creating the upload spool")?;
    let copied = std::io::copy(
        &mut reader.take(crate::api::TRANSFER_MAX_BYTES + 1),
        &mut spool,
    )
    .with_context(|| format!("reading {label}"))?;
    anyhow::ensure!(
        copied <= crate::api::TRANSFER_MAX_BYTES,
        "{label} exceeds the 1 GiB transfer limit"
    );
    spool.rewind()?;
    Ok(spool)
}

fn write(args: &WriteArgs) -> Result<()> {
    let client = client(args.json)?;
    let id = segment(&args.id)?;
    let mut file = source(&args.from)?;
    let total = file.metadata()?.len();
    anyhow::ensure!(
        total <= crate::api::TRANSFER_MAX_BYTES,
        "`{}` exceeds the 1 GiB transfer limit",
        args.from
    );
    let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
    }
    let sha256 = hex(digest.finish().as_ref());

    let transfer: Value = client.mutate(
        Method::Post,
        "/v1/transfers",
        &json!({ "sandboxId": id, "guestPath": args.path, "totalBytes": total }),
    )?;
    let transfer_id = transfer
        .get("id")
        .and_then(Value::as_str)
        .context("the upload reservation has no id")?
        .to_owned();
    let result = upload(&client, &transfer_id, &mut file, total, &transfer, &sha256);
    let receipt = match result {
        Ok(receipt) => receipt,
        Err(error) => {
            abort(&client, &transfer_id);
            return Err(error);
        }
    };
    await_operation(&client, &receipt.operation_id)?;
    if args.json {
        output::json(&Written {
            path: &args.path,
            bytes: total,
            sha256: &sha256,
            operation_id: &receipt.operation_id,
        })
    } else {
        output::line(format!("wrote {total} bytes to `{}`", args.path))
    }
}

fn upload(
    client: &Client,
    transfer_id: &str,
    file: &mut std::fs::File,
    total: u64,
    transfer: &Value,
    sha256: &str,
) -> Result<MutationReceipt> {
    let path = format!("/v1/transfers/{}", transfer_id_segment(transfer_id)?);
    let chunk = reservation_chunk_bytes(transfer)?;
    // A replayed reservation resumes at its durable cursor.
    let mut offset = transfer
        .get("receivedBytes")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    anyhow::ensure!(
        offset <= total && offset.is_multiple_of(chunk),
        "the upload reservation has an unusable cursor"
    );
    file.seek(std::io::SeekFrom::Start(offset))?;
    let mut buffer = vec![0_u8; usize::try_from(chunk).context("chunk size")?];
    while offset < total {
        let length = usize::try_from(chunk.min(total - offset)).context("chunk size")?;
        file.read_exact(&mut buffer[..length])
            .context("reading the upload source")?;
        client.put_chunk(&path, &buffer[..length], offset, total)?;
        offset += length as u64;
    }
    client.mutate(
        Method::Post,
        &format!("{path}/commit"),
        &json!({ "sha256": sha256 }),
    )
}

/// The contract's fixed upload chunk size (`TRANSFER_CHUNK_BYTES`,
/// packages/sandbox-contracts/src/transfers.ts: `chunkBytes` is that literal).
const TRANSFER_CHUNK_BYTES: u64 = 1024 * 1024;

/// The reservation's `chunkBytes`, checked before anything is allocated: any
/// value but [`TRANSFER_CHUNK_BYTES`] (or none) is refused.
fn reservation_chunk_bytes(transfer: &Value) -> Result<u64> {
    match transfer.get("chunkBytes").and_then(Value::as_u64) {
        Some(TRANSFER_CHUNK_BYTES) => Ok(TRANSFER_CHUNK_BYTES),
        other => Err(anyhow::anyhow!(
            "the upload reservation has chunk size {}; this client sends {TRANSFER_CHUNK_BYTES}-byte chunks only",
            other.map_or_else(|| "none".to_owned(), |n| n.to_string())
        ))
        .context(CodedError::new(ExitCode::Failure)),
    }
}

/// Transfer ids are UUIDs.
fn transfer_id_segment(id: &str) -> Result<&str> {
    anyhow::ensure!(
        id.len() == 36 && id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'),
        "the upload reservation has an invalid id"
    );
    Ok(id)
}

/// Best effort: release an uncommitted upload's spool.
fn abort(client: &Client, transfer_id: &str) {
    if let Ok(id) = transfer_id_segment(transfer_id) {
        let _ = client.send::<Value, Value>(
            Method::Delete,
            &format!("/v1/transfers/{id}"),
            Some(&json!({})),
        );
    }
}
