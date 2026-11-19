//! `wssp sandbox ports …`: the preview tunnel routes of a tunnel sandbox
//! (`/v1/sandboxes/{id}/tunnel`, docs/guide/tunnels.md).

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;

use super::{client, segment, str_field};
use crate::api::Method;
use crate::output;

#[derive(Debug, clap::Args)]
pub struct Args {
    #[command(subcommand)]
    pub command: PortsCommand,
}

#[derive(Debug, clap::Subcommand)]
pub enum PortsCommand {
    /// Show the tunnel: exposed ports, state and preview URLs.
    Get(IdArgs),
    /// Expose declared ports through the tunnel (default: every declared port).
    Expose(ExposeArgs),
    /// Change the declared ports of a tunnel sandbox.
    Set(SetArgs),
    /// Close the tunnel; every link to it stops working.
    Close(IdArgs),
    /// Mint a short-lived access link to one exposed port and print it.
    Link(LinkArgs),
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
pub struct ExposeArgs {
    /// Sandbox id.
    pub id: String,
    /// Declared ports to expose (default: all of them).
    #[arg(value_name = "PORT")]
    pub ports: Vec<u16>,
    /// Emit JSON instead of human-readable text.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, clap::Args)]
#[command(group(clap::ArgGroup::new("change").required(true).multiple(true).args(["add", "remove"])))]
pub struct SetArgs {
    /// Sandbox id.
    pub id: String,
    /// Port to declare (repeatable).
    #[arg(long, value_name = "PORT")]
    pub add: Vec<u16>,
    /// Port to stop declaring (repeatable); removing an exposed port replaces the tunnel.
    #[arg(long, value_name = "PORT")]
    pub remove: Vec<u16>,
    /// Emit JSON instead of human-readable text.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, clap::Args)]
pub struct LinkArgs {
    /// Sandbox id.
    pub id: String,
    /// The exposed port the link opens.
    pub port: u16,
    /// Seconds the link can be redeemed, 30–3600 (default 60).
    #[arg(long, value_name = "S")]
    pub ttl: Option<u32>,
    /// Let the link be opened more than once.
    #[arg(long)]
    pub multi_use: bool,
    /// Seconds the browser session it grants lasts, 60–86400 (default 3600).
    #[arg(long, value_name = "S")]
    pub session_ttl: Option<u32>,
    /// Emit JSON instead of human-readable text.
    #[arg(long)]
    pub json: bool,
}

/// `exposeTunnelBodySchema`.
#[derive(Serialize)]
struct ExposeBody<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    ports: Option<&'a [u16]>,
}

/// `updateTunnelPortsBodySchema`.
#[derive(Serialize)]
struct PortsBody<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    add: Option<&'a [u16]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remove: Option<&'a [u16]>,
}

/// `createTunnelLinkBodySchema`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LinkBody {
    port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl_seconds: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    single_use: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_ttl_seconds: Option<u32>,
}

pub fn run(args: &Args) -> Result<()> {
    match &args.command {
        PortsCommand::Get(args) => {
            let client = client(args.json)?;
            let path = format!("/v1/sandboxes/{}/tunnel", segment(&args.id)?);
            let tunnel: Value = client.get(&path, &[])?;
            print_tunnel(&tunnel, args.json)
        }
        PortsCommand::Expose(args) => {
            let client = client(args.json)?;
            let path = format!("/v1/sandboxes/{}/tunnel", segment(&args.id)?);
            let body = ExposeBody {
                ports: (!args.ports.is_empty()).then_some(args.ports.as_slice()),
            };
            let tunnel: Value = client.send(Method::Put, &path, Some(&body))?;
            print_tunnel(&tunnel, args.json)
        }
        PortsCommand::Set(args) => {
            let client = client(args.json)?;
            let path = format!("/v1/sandboxes/{}/tunnel/ports", segment(&args.id)?);
            let body = PortsBody {
                add: (!args.add.is_empty()).then_some(args.add.as_slice()),
                remove: (!args.remove.is_empty()).then_some(args.remove.as_slice()),
            };
            let ports: Value = client.send(Method::Post, &path, Some(&body))?;
            if args.json {
                return output::json(&ports);
            }
            output::line(format!(
                "declared ports: {} (revision {}, {})",
                join_ports(ports.get("ports")),
                ports.get("revision").unwrap_or(&Value::Null),
                str_field(&ports, "state")
            ))
        }
        PortsCommand::Close(args) => {
            let client = client(args.json)?;
            let path = format!("/v1/sandboxes/{}/tunnel", segment(&args.id)?);
            let tunnel: Value = client.send(Method::Delete, &path, None::<&Value>)?;
            print_tunnel(&tunnel, args.json)
        }
        PortsCommand::Link(args) => {
            let client = client(args.json)?;
            let path = format!("/v1/sandboxes/{}/tunnel/links", segment(&args.id)?);
            let body = LinkBody {
                port: args.port,
                ttl_seconds: args.ttl,
                single_use: args.multi_use.then_some(false),
                session_ttl_seconds: args.session_ttl,
            };
            let link: Value = client.send(Method::Post, &path, Some(&body))?;
            if args.json {
                return output::json(&link);
            }
            output::line(output::remote_message(str_field(&link, "url")))?;
            output::diagnostic(format!(
                "wssp: {} link, expires {}; treat it as a secret",
                if link.get("singleUse").and_then(Value::as_bool) == Some(false) {
                    "multi-use"
                } else {
                    "single-use"
                },
                str_field(&link, "expiresAt")
            ))
        }
    }
}

fn join_ports(ports: Option<&Value>) -> String {
    let ports: Vec<String> = ports
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(Value::to_string)
        .collect();
    if ports.is_empty() {
        "none".to_owned()
    } else {
        ports.join(", ")
    }
}

fn print_tunnel(tunnel: &Value, json: bool) -> Result<()> {
    if json {
        return output::json(tunnel);
    }
    output::line(format!("state: {}", str_field(tunnel, "state")))?;
    output::line(format!("ports: {}", join_ports(tunnel.get("ports"))))?;
    if let Some(error) = tunnel.get("lastError").and_then(Value::as_str) {
        output::line(format!("last error: {error}"))?;
    }
    for url in tunnel
        .get("urls")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        output::line(format!(
            "{} {}",
            url.get("port").unwrap_or(&Value::Null),
            output::remote_message(str_field(url, "url"))
        ))?;
    }
    Ok(())
}
