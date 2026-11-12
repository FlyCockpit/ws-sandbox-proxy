//! Supported packet path checker.
//!
//! Inputs: `nft -j list ruleset`, `ip -j -d link show`, `ip -j -4 addr show`
//! and `tc -j qdisc show`. Anything that could let a sandbox packet skip or
//! precede the guard is a node-level finding (health false, quarantine,
//! conntrack deletion for the sandbox subnets):
//!
//! - any flowtable, in any family, and any rule with a `flow` statement;
//! - an `ip`/`inet` base chain on prerouting/input/forward at or below the
//!   guard's priority (other than the guard's own);
//! - a `netdev` chain or an `inet` ingress chain on a sandbox bridge, one of
//!   its ports or an uplink (or bound to no named device), and any `bridge`
//!   table other than Incus's own `bridge incus`;
//! - XDP or an `ingress`/`clsact` qdisc on a sandbox bridge, a port or an
//!   uplink (a tc `mirred` or XDP redirect transmits straight to its target
//!   device, past every netfilter hook, so the guard's table cannot stop it;
//!   only the quarantine fence, which takes the sandbox links down, does).
//!
//! Separately, a host firewall that drops sandbox traffic (ufw, firewalld,
//! Docker's FORWARD policy) is reported in [`PathReport::host_firewall`]: it
//! cannot let a packet skip the guard, but it silently drops the sandboxes'
//! DHCP, DNS and forwarding, so a sandbox would boot with no network. The
//! guard reports it as unhealthy (`host_firewall_blocks_sandboxes`).
//!
//! A malformed `wsn-*` bridge (not a bridge, zero or several IPv4 addresses,
//! not a /24, gateway not `.1`, a non-`tap` port) is only excluded: it gets
//! no `live_bridges`/`gateways` entry; other bridges are unaffected.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use serde_json::Value;

use super::net::Ipv4Net;
use super::ruleset::{GatewayPair, is_sandbox_bridge, valid_ifname};
use super::{FORWARD_PRIORITY, INPUT_PRIORITY, PRE_PRIORITY, TABLE};

pub struct PathInputs<'a> {
    pub ruleset: &'a Value,
    pub links: &'a Value,
    pub addresses: &'a Value,
    pub qdiscs: &'a Value,
    pub uplinks: &'a [String],
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExcludedBridge {
    pub bridge: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathReport {
    /// Node-level unsupported-packet-path findings (`what`, without the
    /// `unsupported_packet_path:` prefix).
    pub findings: Vec<String>,
    /// Well-formed sandbox bridges: their `(bridge, .1)` pair.
    pub bridges: Vec<GatewayPair>,
    pub excluded: Vec<ExcludedBridge>,
    /// Every IPv4 network configured on any `wsn-*` interface (valid or
    /// not): the conntrack deletion scope on packet-path quarantine.
    pub sandbox_subnets: Vec<Ipv4Net>,
    /// Host firewall base chains (`family/table/chain`) that drop sandbox
    /// bridge traffic by default and admit no `wsn-*` traffic: see
    /// [`host_firewall_blocks`].
    pub host_firewall: Vec<String>,
}

/// Reason code (and `wssp guard status` prefix) for [`PathReport::host_firewall`].
pub const HOST_FIREWALL_REASON: &str = "host_firewall_blocks_sandboxes";

/// The operator's fix for [`HOST_FIREWALL_REASON`] (docs/guide/hosts.md#host-firewall-ufwfirewalld).
pub const HOST_FIREWALL_FIX: &str = "\
the host firewall drops traffic on the sandbox bridges (`wsn-*`), so sandboxes get no \
DHCP lease, DNS or internet; new sandboxes cannot start on this node. Let the guard add \
the minimal rules (it prints each one; the egress guard still enforces every block):
  sudo wssp guard install --daemon-user <user> --configure-ufw
  (or --configure-firewalld; add --credential-proxy-port <port> if you changed `credential_proxy_port`)
or add them yourself (ufw): DHCP, DNS and the login proxy in, routing both ways:
  sudo ufw allow in on wsn+ to any port 67 proto udp
  sudo ufw allow in on wsn+ to any port 53 proto udp
  sudo ufw allow in on wsn+ to any port 53 proto tcp
  sudo ufw allow in on wsn+ to any port 48080 proto tcp
  sudo ufw route allow in on wsn+
  sudo ufw route allow out on wsn+
See docs/guide/hosts.md#host-firewall-ufwfirewalld";

fn guard_priority(hook: &str) -> Option<i32> {
    match hook {
        "prerouting" => Some(PRE_PRIORITY),
        "input" => Some(INPUT_PRIORITY),
        "forward" => Some(FORWARD_PRIORITY),
        _ => None,
    }
}

fn has_flow_statement(value: &Value) -> bool {
    match value {
        Value::Object(map) => map
            .iter()
            .any(|(key, inner)| key == "flow" || has_flow_statement(inner)),
        Value::Array(items) => items.iter().any(has_flow_statement),
        _ => false,
    }
}

fn chain_devices(chain: &Value) -> Vec<String> {
    let mut devices = Vec::new();
    for key in ["dev", "devs"] {
        match chain.get(key) {
            Some(Value::String(dev)) => devices.push(dev.clone()),
            Some(Value::Array(items)) => {
                devices.extend(items.iter().filter_map(Value::as_str).map(str::to_string));
            }
            _ => {}
        }
    }
    devices
}

fn str_field<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("listing entry lacks string `{key}`"))
}

/// Run every §2.0.1 check. Errors mean the listings are malformed (the
/// caller quarantines with `classification_failed`).
pub fn check(inputs: &PathInputs<'_>) -> Result<PathReport, String> {
    let links = inputs
        .links
        .as_array()
        .ok_or("link listing is not an array")?;
    let addresses = inputs
        .addresses
        .as_array()
        .ok_or("address listing is not an array")?;
    let qdiscs = inputs
        .qdiscs
        .as_array()
        .ok_or("qdisc listing is not an array")?;
    let items = inputs.ruleset["nftables"]
        .as_array()
        .ok_or("ruleset listing has no `nftables` array")?;

    // Interfaces: sandbox bridges, their ports, uplinks.
    let mut kinds = BTreeMap::new();
    let mut ports: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut xdp = BTreeSet::new();
    for link in links {
        let name = str_field(link, "ifname")?.to_string();
        if let Some(master) = link.get("master").and_then(Value::as_str)
            && is_sandbox_bridge(master)
        {
            ports
                .entry(master.to_string())
                .or_default()
                .push(name.clone());
        }
        if link.get("xdp").is_some() {
            xdp.insert(name.clone());
        }
        let kind = link
            .pointer("/linkinfo/info_kind")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        kinds.insert(name, kind);
    }
    let bridges: Vec<&String> = kinds.keys().filter(|n| is_sandbox_bridge(n)).collect();
    let mut sensitive: BTreeSet<String> = bridges.iter().map(|n| (*n).clone()).collect();
    sensitive.extend(ports.values().flatten().cloned());
    sensitive.extend(inputs.uplinks.iter().cloned());

    let mut findings = BTreeSet::new();
    for name in &xdp {
        if sensitive.contains(name) {
            findings.insert(format!("xdp:{name}"));
        }
    }
    for qdisc in qdiscs {
        let kind = str_field(qdisc, "kind")?;
        let dev = str_field(qdisc, "dev")?.to_string();
        if matches!(kind, "ingress" | "clsact") && sensitive.contains(&dev) {
            findings.insert(format!("tc_{kind}:{dev}"));
        }
    }

    for item in items {
        let Some((kind, body)) = item.as_object().and_then(|m| m.iter().next()) else {
            return Err("ruleset item is not an object".into());
        };
        let family = body.get("family").and_then(Value::as_str).unwrap_or("");
        let table = body.get("table").and_then(Value::as_str).unwrap_or("");
        match kind.as_str() {
            "flowtable" => {
                let name = body.get("name").and_then(Value::as_str).unwrap_or("?");
                findings.insert(format!("flowtable:{family}/{table}/{name}"));
            }
            "table" => {
                let name = body.get("name").and_then(Value::as_str).unwrap_or("?");
                if family == "bridge" && name != "incus" {
                    findings.insert(format!("bridge_table:{name}"));
                }
            }
            "chain" => {
                let Some(hook) = body.get("hook").and_then(Value::as_str) else {
                    continue;
                };
                let name = body.get("name").and_then(Value::as_str).unwrap_or("?");
                let ours = family == "inet" && table == TABLE;
                if matches!(family, "ip" | "inet")
                    && !ours
                    && let Some(limit) = guard_priority(hook)
                {
                    let prio = body
                        .get("prio")
                        .and_then(Value::as_i64)
                        .ok_or_else(|| format!("base chain `{table}/{name}` has no priority"))?;
                    if prio <= i64::from(limit) {
                        findings.insert(format!("early_chain:{family}/{table}/{name}@{prio}"));
                    }
                }
                let device_hook =
                    family == "netdev" || (family == "inet" && hook == "ingress" && !ours);
                if device_hook {
                    let devices = chain_devices(body);
                    if devices.is_empty() || devices.iter().any(|d| sensitive.contains(d)) {
                        findings.insert(format!("{family}_chain:{table}/{name}/{hook}"));
                    }
                }
            }
            "rule" if has_flow_statement(&body["expr"]) => {
                let chain = body.get("chain").and_then(Value::as_str).unwrap_or("?");
                findings.insert(format!("flow_offload:{family}/{table}/{chain}"));
            }
            _ => {}
        }
    }

    // Per-bridge single-address /24 .1 invariant (m14).
    let v4 = ipv4_by_interface(addresses)?;
    let mut report = PathReport {
        findings: findings.into_iter().collect(),
        sandbox_subnets: subnets_of(&v4),
        host_firewall: host_firewall_blocks(items),
        ..PathReport::default()
    };
    for bridge in bridges {
        let addrs = v4.get(bridge).map(Vec::as_slice).unwrap_or(&[]);
        let foreign_port = ports
            .get(bridge)
            .into_iter()
            .flatten()
            .find(|port| !port.starts_with("tap"));
        let reason = if !valid_ifname(bridge) {
            Some("unsupported_name".to_string())
        } else if kinds.get(bridge).map(String::as_str) != Some("bridge") {
            Some("not_a_bridge".to_string())
        } else if addrs.is_empty() {
            Some("no_ipv4_address".to_string())
        } else if addrs.len() > 1 {
            Some("multiple_ipv4_addresses".to_string())
        } else if addrs[0].1 != 24 {
            Some("prefix_not_24".to_string())
        } else if addrs[0].0.octets()[3] != 1 {
            Some("gateway_not_dot1".to_string())
        } else {
            foreign_port.map(|port| format!("foreign_port:{port}"))
        };
        match reason {
            Some(reason) => report.excluded.push(ExcludedBridge {
                bridge: bridge.clone(),
                reason,
            }),
            None => report.bridges.push(GatewayPair {
                bridge: bridge.clone(),
                gateway: addrs[0].0,
            }),
        }
    }
    Ok(report)
}

/// Expression keys that do not make a rule conditional.
const UNCONDITIONAL_KEYS: &[&str] = &["counter", "log", "drop", "reject"];

/// An `iifname` match on a `wsn…` name or pattern (`wsn*`, `wsn-*`, a set
/// containing one): the host firewall admits sandbox bridge traffic.
fn matches_sandbox_iifname(expr: &Value) -> bool {
    let Some(matched) = expr.get("match") else {
        return false;
    };
    if matched.pointer("/left/meta/key").and_then(Value::as_str) != Some("iifname")
        || !matches!(
            matched.get("op").and_then(Value::as_str),
            None | Some("==" | "in")
        )
    {
        return false;
    }
    let names: Vec<&str> = match &matched["right"] {
        Value::String(name) => vec![name.as_str()],
        Value::Object(map) => map
            .get("set")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect(),
        _ => Vec::new(),
    };
    names.iter().any(|name| name.starts_with("wsn"))
}

/// Host firewall chains that drop sandbox traffic: an `ip`/`inet` base
/// chain on `input` or `forward`, outside Incus's own table and the
/// guard's, that drops by default (policy `drop`, or a final unconditional
/// `drop`/`reject` rule as firewalld uses) while no rule in its table admits
/// `wsn-*` traffic (an `iifname "wsn*"` match whose verdict is `accept`,
/// `jump` or `goto`, which is what `ufw allow in on wsn+`, `ufw route allow
/// in on wsn+`, a firewalld trusted zone or a `DOCKER-USER` accept add).
///
/// An accept in another table never helps: every base chain on a hook sees
/// the packet and any drop is final. Legacy (non-nft) iptables rules are
/// invisible here; readiness still refuses a guest without a network.
pub fn host_firewall_blocks(items: &[Value]) -> Vec<String> {
    let mut chains: Vec<(String, String, String)> = Vec::new();
    let mut policy_drop: BTreeSet<(String, String, String)> = BTreeSet::new();
    let mut last_rule: BTreeMap<(String, String, String), Value> = BTreeMap::new();
    let mut admitted: BTreeSet<(String, String)> = BTreeSet::new();
    for item in items {
        let Some((kind, body)) = item.as_object().and_then(|m| m.iter().next()) else {
            continue;
        };
        let family = body.get("family").and_then(Value::as_str).unwrap_or("");
        let table = body.get("table").and_then(Value::as_str).unwrap_or("");
        if !matches!(family, "ip" | "inet")
            || (family == "inet" && matches!(table, "incus" | TABLE))
        {
            continue;
        }
        match kind.as_str() {
            "chain" => {
                let hook = body.get("hook").and_then(Value::as_str);
                if !matches!(hook, Some("input" | "forward"))
                    || body.get("type").and_then(Value::as_str) != Some("filter")
                {
                    continue;
                }
                let name = body.get("name").and_then(Value::as_str).unwrap_or("?");
                let key = (family.to_string(), table.to_string(), name.to_string());
                if body.get("policy").and_then(Value::as_str) == Some("drop") {
                    policy_drop.insert(key.clone());
                }
                chains.push(key);
            }
            "rule" => {
                let chain = body.get("chain").and_then(Value::as_str).unwrap_or("");
                let expr = body.get("expr").and_then(Value::as_array);
                let exprs = expr.map(Vec::as_slice).unwrap_or(&[]);
                let verdict = exprs.iter().any(|e| {
                    e.get("accept").is_some() || e.get("jump").is_some() || e.get("goto").is_some()
                });
                if verdict && exprs.iter().any(matches_sandbox_iifname) {
                    admitted.insert((family.to_string(), table.to_string()));
                }
                last_rule.insert(
                    (family.to_string(), table.to_string(), chain.to_string()),
                    body.get("expr").cloned().unwrap_or(Value::Null),
                );
            }
            _ => {}
        }
    }
    let mut blocking = BTreeSet::new();
    for key in chains {
        if admitted.contains(&(key.0.clone(), key.1.clone())) {
            continue;
        }
        let final_drop = last_rule
            .get(&key)
            .and_then(Value::as_array)
            .is_some_and(|exprs| {
                !exprs.is_empty()
                    && exprs
                        .iter()
                        .any(|e| e.get("drop").is_some() || e.get("reject").is_some())
                    && exprs.iter().all(|e| {
                        e.as_object().is_some_and(|m| {
                            m.keys().all(|k| UNCONDITIONAL_KEYS.contains(&k.as_str()))
                        })
                    })
            });
        if policy_drop.contains(&key) || final_drop {
            blocking.insert(format!("{}/{}/{}", key.0, key.1, key.2));
        }
    }
    blocking.into_iter().collect()
}

type Ipv4ByInterface = BTreeMap<String, Vec<(Ipv4Addr, u8)>>;

fn ipv4_by_interface(addresses: &[Value]) -> Result<Ipv4ByInterface, String> {
    let mut v4: Ipv4ByInterface = BTreeMap::new();
    for entry in addresses {
        let name = str_field(entry, "ifname")?.to_string();
        for info in entry
            .get("addr_info")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if info.get("family").and_then(Value::as_str) != Some("inet") {
                continue;
            }
            let local: Ipv4Addr = str_field(info, "local")?
                .parse()
                .map_err(|_| format!("bad IPv4 address on `{name}`"))?;
            let prefix = info
                .get("prefixlen")
                .and_then(Value::as_u64)
                .and_then(|p| u8::try_from(p).ok())
                .filter(|p| *p <= 32)
                .ok_or_else(|| format!("bad prefix on `{name}`"))?;
            v4.entry(name.clone()).or_default().push((local, prefix));
        }
    }
    Ok(v4)
}

fn subnets_of(v4: &Ipv4ByInterface) -> Vec<Ipv4Net> {
    super::net::normalize(
        v4.iter()
            .filter(|(name, _)| is_sandbox_bridge(name))
            .flat_map(|(_, addrs)| addrs.iter())
            .filter_map(|(ip, prefix)| Ipv4Net::containing(*ip, *prefix)),
    )
}

/// Every IPv4 network on any `wsn-*` interface (`ip -j -4 addr show`): the
/// conntrack cleanup scope. Independent of the rest of the classification,
/// so a quarantine whose snapshot failed can still clean up.
pub fn sandbox_subnets(addresses: &Value) -> Result<Vec<Ipv4Net>, String> {
    let addresses = addresses
        .as_array()
        .ok_or("address listing is not an array")?;
    Ok(subnets_of(&ipv4_by_interface(addresses)?))
}

/// One sandbox link the quarantine fence takes down: a `wsn-*` interface or
/// a port whose master is one. `ifindex` pins the identity, so a restore
/// never brings up a different link that reused the name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxLink {
    pub name: String,
    pub ifindex: u64,
    /// A `wsn-*` interface itself (restored before its ports).
    pub bridge: bool,
    /// Administratively up (`UP` in `flags`).
    pub up: bool,
}

/// The fence targets in `ip -j -d link show`: every `wsn-*` interface and
/// every port enslaved to one. Ports are listed before bridges.
pub fn sandbox_links(links: &Value) -> Result<Vec<SandboxLink>, String> {
    let links = links.as_array().ok_or("link listing is not an array")?;
    let mut out = Vec::new();
    for link in links {
        let name = str_field(link, "ifname")?;
        let bridge = is_sandbox_bridge(name);
        let port = link
            .get("master")
            .and_then(Value::as_str)
            .is_some_and(is_sandbox_bridge);
        if !bridge && !port {
            continue;
        }
        if !valid_ifname(name) {
            return Err(format!("unsupported sandbox link name `{name}`"));
        }
        let ifindex = link
            .get("ifindex")
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("link `{name}` has no ifindex"))?;
        let flags = link
            .get("flags")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("link `{name}` has no flags"))?;
        out.push(SandboxLink {
            name: name.to_string(),
            ifindex,
            bridge,
            up: flags.iter().any(|f| f.as_str() == Some("UP")),
        });
    }
    out.sort_by(|a, b| (a.bridge, &a.name).cmp(&(b.bridge, &b.name)));
    Ok(out)
}

#[cfg(test)]
#[path = "path_tests.rs"]
mod tests;
