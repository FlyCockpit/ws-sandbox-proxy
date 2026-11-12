//! Security-critical: guard ruleset compiler, readback and packet model.

use std::net::Ipv4Addr;

use serde_json::Value;

use super::*;
use crate::guard::net::protected4;

const PROVEN: &str = include_str!("fixtures/guard-test.nft");
const READBACK: &str = include_str!("fixtures/readback-healthy.json");

fn net(text: &str) -> Ipv4Net {
    Ipv4Net::parse_cidr(text).unwrap()
}

fn pair(bridge: &str, gateway: [u8; 4]) -> GatewayPair {
    GatewayPair {
        bridge: bridge.into(),
        gateway: Ipv4Addr::from(gateway),
    }
}

/// The values hand-filled into the qualified ruleset (`fixtures/guard-test.nft`).
fn sample_host_inputs() -> GuardInputs {
    GuardInputs {
        protected4: protected4().unwrap().to_vec(),
        scope4: [
            "10.71.136.0/24",
            "10.250.77.0/24",
            "10.250.78.0/24",
            "100.64.0.0/16",
            "192.0.2.0/24",
        ]
        .into_iter()
        .map(net)
        .collect(),
        deny4: Vec::new(),
        uplinks: vec!["wlan0".into()],
        gateways: vec![
            pair("wsn-gq0", [10, 250, 77, 1]),
            pair("wsn-gq1", [10, 250, 78, 1]),
        ],
        live_bridges: vec!["wsn-gq0".into(), "wsn-gq1".into()],
    }
}

/// The inputs `fixtures/readback-healthy.json` was listed from (compiled by
/// this compiler, loaded by real nft 1.0.9 in a private netns; identifiers
/// since replaced with documentation ranges).
fn readback_inputs() -> GuardInputs {
    GuardInputs {
        deny4: vec![net("1.1.1.1/32"), net("9.9.9.0/24"), net("9.9.9.128/25")],
        ..sample_host_inputs()
    }
}

fn tokens(text: &str) -> Vec<String> {
    text.lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
        .replace(['{', '}', ',', ';'], " $0 ")
        .replace("$0", "")
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

fn split_live(compiled: &str) -> (String, Option<String>) {
    let mut body = Vec::new();
    let mut live = None;
    for line in compiled.lines() {
        if line.starts_with("add element") {
            live = Some(line.to_string());
        } else {
            body.push(line);
        }
    }
    (body.join("\n"), live)
}

#[test]
fn golden_equals_the_qualified_ruleset() {
    let compiled = compile(&sample_host_inputs(), 30).unwrap();
    let (body, live) = split_live(&compiled);
    // The qualified file loads live_bridges without timeouts inside the set;
    // production adds them in the same transaction with `timeout 30s`.
    let proven: String = PROVEN
        .lines()
        .filter(|line| line.trim() != r#"elements = { "wsn-gq0", "wsn-gq1" }"#)
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(tokens(&body), tokens(&proven));
    assert_eq!(
        live.as_deref(),
        Some(
            r#"add element inet wssp_guard live_bridges { "wsn-gq0" timeout 30s, "wsn-gq1" timeout 30s }"#
        )
    );
}

#[test]
fn quarantine_is_the_same_table_with_no_live_bridges() {
    let inputs = sample_host_inputs();
    let healthy = compile(&inputs, 30).unwrap();
    let quarantined = compile(&inputs.quarantined(), 30).unwrap();
    let (body, live) = split_live(&quarantined);
    assert_eq!(live, None);
    assert_eq!(body, split_live(&healthy).0);
}

#[test]
fn protected4_is_the_shared_fixture() {
    let compiled = compile(&sample_host_inputs(), 30).unwrap();
    let line = compiled
        .lines()
        .skip_while(|l| !l.contains("set protected4"))
        .find(|l| l.contains("elements"))
        .unwrap();
    for net in protected4().unwrap() {
        assert!(line.contains(&format!(" {net}")), "{net} missing");
    }
}

#[test]
fn no_accept_verdict_and_no_ct_expression_anywhere() {
    let mut inputs = sample_host_inputs();
    inputs.deny4 = vec![net("1.1.1.1/32")];
    for text in [
        compile(&inputs, 30).unwrap(),
        compile(&inputs.quarantined(), 30).unwrap(),
    ] {
        let toks: Vec<&str> = text
            .split(|c: char| c.is_whitespace() || matches!(c, ';' | '{' | '}' | ','))
            .filter(|t| !t.is_empty())
            .collect();
        for (index, token) in toks.iter().enumerate() {
            assert_ne!(*token, "ct", "ct expression in the guard");
            if *token == "accept" {
                assert_eq!(toks[index - 1], "policy", "accept verdict in the guard");
            }
            for forbidden in ["masquerade", "snat", "dnat", "redirect", "notrack", "flow"] {
                assert_ne!(*token, forbidden);
            }
        }
    }
    for (_, text, sig) in RULES {
        assert!(!text.contains("accept") && !sig.contains("accept"));
    }
}

#[test]
fn priorities_precede_conntrack_and_every_nat() {
    const CONNTRACK: i32 = -200;
    const DSTNAT: i32 = -100;
    const IPTABLES_RAW: i32 = -300;
    const { assert!(PRE_PRIORITY < CONNTRACK && PRE_PRIORITY < DSTNAT && PRE_PRIORITY < IPTABLES_RAW) };
    const { assert!(INPUT_PRIORITY < DSTNAT && FORWARD_PRIORITY < DSTNAT) };
    let compiled = compile(&sample_host_inputs(), 30).unwrap();
    assert!(compiled.contains("hook prerouting priority raw - 10; policy accept;"));
    assert!(compiled.contains("hook input priority filter - 300; policy accept;"));
    assert!(compiled.contains("hook forward priority filter - 300; policy accept;"));
}

#[test]
fn compiler_normalizes_overlaps_and_refuses_unsafe_names() {
    let mut inputs = sample_host_inputs();
    inputs.scope4.push(net("10.0.0.0/8"));
    inputs.scope4.push(net("10.250.77.0/24"));
    let text = compile(&inputs, 30).unwrap();
    assert!(text.contains("elements = { 10.0.0.0/8, 100.64.0.0/16, 192.0.2.0/24 }"));

    for (field, name) in [
        ("uplink", "eth0\"; flush ruleset; \""),
        ("uplink", "wsn-0123456789"),
        ("live", "eth0"),
        ("live", "wsn-x y"),
        ("gateway", "docker0"),
    ] {
        let mut bad = sample_host_inputs();
        match field {
            "uplink" => bad.uplinks.push(name.into()),
            "live" => bad.live_bridges.push(name.into()),
            _ => bad.gateways.push(pair(name, [10, 0, 0, 1])),
        }
        assert!(compile(&bad, 30).is_err(), "{field} {name}");
    }
    let mut zero = sample_host_inputs();
    zero.scope4.push(net("0.0.0.0/0"));
    assert!(compile(&zero, 30).is_err());
    let mut empty = sample_host_inputs();
    empty.protected4.clear();
    assert!(compile(&empty, 30).is_err());
    assert!(compile(&sample_host_inputs(), 0).is_err());
}

#[test]
fn readback_of_real_nft_listing_matches() {
    let listing: Value = serde_json::from_str(READBACK).unwrap();
    verify_readback(&readback_inputs(), &listing).unwrap();
}

#[test]
fn readback_detects_every_kind_of_drift() {
    let listing: Value = serde_json::from_str(READBACK).unwrap();
    let inputs = readback_inputs();

    // Different expected contents.
    for edit in [
        (|i: &mut GuardInputs| i.deny4.push(Ipv4Net::parse_cidr("8.8.8.8/32").unwrap()))
            as fn(&mut GuardInputs),
        |i| i.scope4.pop().map(drop).unwrap_or(()),
        |i| i.uplinks.push("eth9".into()),
        |i| i.live_bridges.clear(),
        |i| i.gateways.pop().map(drop).unwrap_or(()),
    ] {
        let mut changed = inputs.clone();
        edit(&mut changed);
        assert!(verify_readback(&changed, &listing).is_err());
    }

    // Mutated listings.
    let mutate = |f: &dyn Fn(&mut Vec<Value>)| {
        let mut copy = listing.clone();
        f(copy["nftables"].as_array_mut().unwrap());
        verify_readback(&inputs, &copy)
    };
    let is_rule = |v: &Value, chain: &str| v["rule"]["chain"] == chain;
    // An accept verdict replacing a drop.
    assert!(
        mutate(&|items| {
            let rule = items
                .iter_mut()
                .find(|v| is_rule(v, "from_sandbox"))
                .unwrap();
            let expr = rule["rule"]["expr"].as_array_mut().unwrap();
            *expr.last_mut().unwrap() = serde_json::json!({"accept": null});
        })
        .is_err()
    );
    // A rule removed.
    assert!(
        mutate(&|items| {
            let index = items.iter().position(|v| is_rule(v, "to_sandbox")).unwrap();
            items.remove(index);
        })
        .is_err()
    );
    // A priority moved after Incus's NAT.
    assert!(
        mutate(&|items| {
            let chain = items
                .iter_mut()
                .find(|v| v["chain"]["name"] == "pre")
                .unwrap();
            chain["chain"]["prio"] = serde_json::json!(-90);
        })
        .is_err()
    );
    // A foreign object inside the table.
    assert!(
        mutate(&|items| {
            items.push(serde_json::json!({"flowtable": {"family":"inet","table":"wssp_guard","name":"ft"}}));
        })
        .is_err()
    );
    // A ct expression sneaked in front of a drop.
    assert!(
        mutate(&|items| {
            let rule = items.iter_mut().find(|v| is_rule(v, "pre") && v["rule"]["comment"] == "pre: deny4").unwrap();
            rule["rule"]["expr"].as_array_mut().unwrap().insert(0, serde_json::json!({"match":{"op":"==","left":{"ct":{"key":"state"}},"right":"new"}}));
        })
        .is_err()
    );
    // Table gone (flush ruleset).
    assert!(
        verify_readback(
            &inputs,
            &serde_json::json!({"nftables": [{"metainfo": {}}]})
        )
        .is_err()
    );
}

// ---------------------------------------------------------------------------
// Packet model: mirrors the chains, evaluated at `pre` with the ORIGINAL
// destination and at `input`/`forward` with the TRANSLATED one.
// ---------------------------------------------------------------------------

struct Node {
    /// fib `local`/`broadcast`/`anycast` addresses of this node.
    local: Vec<Ipv4Addr>,
    broadcast: Vec<Ipv4Addr>,
}

struct Packet<'a> {
    iif: &'a str,
    /// `None` = delivered locally after routing.
    oif: Option<&'a str>,
    saddr: Ipv4Addr,
    daddr: Ipv4Addr,
    /// After DNAT at −100 (equals `daddr` when nothing translates).
    daddr_nat: Ipv4Addr,
    ipv6: bool,
    udp: Option<(u16, u16)>,
}

fn ip(text: &str) -> Ipv4Addr {
    text.parse().unwrap()
}

fn in_set(set: &[Ipv4Net], addr: Ipv4Addr) -> bool {
    set.iter().any(|n| n.contains(addr))
}

fn is_dhcp_discover(p: &Packet<'_>, daddr: Ipv4Addr) -> bool {
    daddr == Ipv4Addr::BROADCAST && p.udp == Some((68, 67))
}

fn own_gateway(g: &GuardInputs, iif: &str, daddr: Ipv4Addr) -> bool {
    g.gateways
        .iter()
        .any(|p| p.bridge == iif && p.gateway == daddr)
}

/// `Some(chain-reason)` when the guard drops the packet.
fn guard_drops(g: &GuardInputs, node: &Node, p: &Packet<'_>) -> Option<&'static str> {
    let from_sandbox = p.iif.starts_with("wsn-");
    let live = |name: &str| g.live_bridges.iter().any(|b| b == name);
    // pre (original destination)
    if from_sandbox {
        if p.ipv6 {
            return Some("pre: ipv6");
        }
        let passed = own_gateway(g, p.iif, p.daddr) || is_dhcp_discover(p, p.daddr);
        if !passed {
            let fib = node.local.contains(&p.daddr)
                || node.broadcast.contains(&p.daddr)
                || p.daddr.is_multicast()
                || p.daddr == Ipv4Addr::BROADCAST;
            if fib {
                return Some("pre: node address");
            }
            if in_set(&g.protected4, p.daddr) {
                return Some("pre: protected4");
            }
            if in_set(&g.scope4, p.daddr) {
                return Some("pre: scope4");
            }
            if in_set(&g.deny4, p.daddr) {
                return Some("pre: deny4");
            }
            if !live(p.iif) {
                return Some("pre: not live");
            }
        }
    }
    match p.oif {
        None => {
            // input (translated destination)
            if from_sandbox {
                if p.ipv6 {
                    return Some("input: ipv6");
                }
                if own_gateway(g, p.iif, p.daddr_nat) || is_dhcp_discover(p, p.daddr_nat) {
                    return None;
                }
                return Some("input: other node address");
            }
            None
        }
        Some(oif) => {
            if from_sandbox {
                if !live(p.iif) {
                    return Some("fwd-out: not live");
                }
                if p.ipv6 {
                    return Some("fwd-out: ipv6");
                }
                for (set, why) in [
                    (&g.protected4, "fwd-out: protected4"),
                    (&g.scope4, "fwd-out: scope4"),
                    (&g.deny4, "fwd-out: deny4"),
                ] {
                    if in_set(set, p.daddr_nat) {
                        return Some(why);
                    }
                }
                if !g.uplinks.iter().any(|u| u == oif) {
                    return Some("fwd-out: not via uplink");
                }
                return None;
            }
            if oif.starts_with("wsn-") {
                if !live(oif) {
                    return Some("fwd-in: not live");
                }
                if p.ipv6 {
                    return Some("fwd-in: ipv6");
                }
                for (set, why) in [
                    (&g.protected4, "fwd-in: protected4"),
                    (&g.scope4, "fwd-in: scope4"),
                    (&g.deny4, "fwd-in: deny4"),
                ] {
                    if in_set(set, p.saddr) {
                        return Some(why);
                    }
                }
                if !g.uplinks.iter().any(|u| u == p.iif) {
                    return Some("fwd-in: not via uplink");
                }
            }
            None
        }
    }
}

fn model() -> (GuardInputs, Node) {
    let mut inputs = sample_host_inputs();
    inputs.deny4 = vec![net("172.66.0.218/32")];
    inputs.scope4.push(net("44.0.0.0/6")); // public-numbered subnet route via tailscale0
    let node = Node {
        local: [
            "192.0.2.88",
            "100.64.0.10",
            "10.71.136.1",
            "10.250.77.1",
            "10.250.78.1",
            "10.250.77.250",
            "203.0.113.9",
        ]
        .into_iter()
        .map(ip)
        .collect(),
        broadcast: ["10.250.77.255", "192.0.2.255"]
            .into_iter()
            .map(ip)
            .collect(),
    };
    (inputs, node)
}

fn guest<'a>(daddr: &str, oif: Option<&'a str>) -> Packet<'a> {
    Packet {
        iif: "wsn-gq0",
        oif,
        saddr: ip("10.250.77.2"),
        daddr: ip(daddr),
        daddr_nat: ip(daddr),
        ipv6: false,
        udp: None,
    }
}

#[test]
fn packet_model_cases() {
    let (g, node) = model();
    let drops = |p: &Packet<'_>| guard_drops(&g, &node, p);

    // Own gateway, any port: not the guard's business (the ACL's).
    assert_eq!(drops(&guest("10.250.77.1", None)), None);
    // Own bridge broadcast and a second alias on it (m14).
    assert_eq!(
        drops(&guest("10.250.77.255", None)),
        Some("pre: node address")
    );
    assert_eq!(
        drops(&guest("10.250.77.250", None)),
        Some("pre: node address")
    );
    // Another bridge's gateway on 53/67.
    let mut other = guest("10.250.78.1", None);
    other.udp = Some((5353, 53));
    assert_eq!(drops(&other), Some("pre: node address"));
    // Node LAN / tailnet / docker addresses.
    for addr in ["192.0.2.88", "100.64.0.10", "10.71.136.1"] {
        assert_eq!(
            drops(&guest(addr, None)),
            Some("pre: node address"),
            "{addr}"
        );
    }
    // A node public address that a DNAT would forward to a public host: dropped at pre.
    let mut forwarded = guest("203.0.113.9", Some("wlan0"));
    forwarded.daddr_nat = ip("93.184.216.34");
    assert_eq!(drops(&forwarded), Some("pre: node address"));
    // A public address DNAT-translated to a protected one: dropped at forward.
    let mut inward = guest("93.184.216.34", Some("wlan0"));
    inward.daddr_nat = ip("192.0.2.254");
    assert_eq!(drops(&inward), Some("fwd-out: protected4"));
    // A public address DNAT-translated to the node itself: dropped at input.
    let mut to_node = guest("93.184.216.34", None);
    to_node.daddr_nat = ip("192.0.2.88");
    assert_eq!(drops(&to_node), Some("input: other node address"));
    // DHCP discover only.
    let mut discover = guest("255.255.255.255", None);
    discover.udp = Some((68, 67));
    assert_eq!(drops(&discover), None);
    let mut other_bcast = guest("255.255.255.255", None);
    other_bcast.udp = Some((1234, 67));
    assert_eq!(drops(&other_bcast), Some("pre: node address"));
    assert_eq!(
        drops(&guest("224.0.0.251", None)),
        Some("pre: node address")
    );
    // Public via uplink.
    assert_eq!(drops(&guest("93.184.216.34", Some("wlan0"))), None);
    // Public via a tunnel (subnet route) or another bridge.
    assert_eq!(
        drops(&guest("93.184.216.34", Some("tailscale0"))),
        Some("fwd-out: not via uplink")
    );
    assert_eq!(
        drops(&guest("45.1.2.3", Some("tailscale0"))),
        Some("pre: scope4")
    );
    // Protected / scope / deny.
    assert_eq!(
        drops(&guest("169.254.169.254", Some("wlan0"))),
        Some("pre: protected4")
    );
    assert_eq!(
        drops(&guest("168.63.129.16", Some("wlan0"))),
        Some("pre: protected4")
    );
    assert_eq!(
        drops(&guest("172.66.0.218", Some("wlan0"))),
        Some("pre: deny4")
    );
    // IPv6.
    let mut v6 = guest("93.184.216.34", Some("wlan0"));
    v6.ipv6 = true;
    assert_eq!(drops(&v6), Some("pre: ipv6"));
    // Inbound from deny / scope.
    let inbound = |saddr: &str| Packet {
        iif: "wlan0",
        oif: Some("wsn-gq0"),
        saddr: ip(saddr),
        daddr: ip("10.250.77.2"),
        daddr_nat: ip("10.250.77.2"),
        ipv6: false,
        udp: None,
    };
    assert_eq!(drops(&inbound("172.66.0.218")), Some("fwd-in: deny4"));
    assert_eq!(drops(&inbound("45.1.2.3")), Some("fwd-in: scope4"));
    assert_eq!(drops(&inbound("93.184.216.34")), None);
    let mut via_tunnel = inbound("93.184.216.34");
    via_tunnel.iif = "tailscale0";
    assert_eq!(drops(&via_tunnel), Some("fwd-in: not via uplink"));
}

#[test]
fn packet_model_dead_man_and_quarantine() {
    let (g, node) = model();
    let q = g.quarantined();
    let drops = |p: &Packet<'_>| guard_drops(&q, &node, p);
    // Everything forwarded stops, both directions.
    assert_eq!(
        drops(&guest("93.184.216.34", Some("wlan0"))),
        Some("pre: not live")
    );
    let inbound = Packet {
        iif: "wlan0",
        oif: Some("wsn-gq0"),
        saddr: ip("93.184.216.34"),
        daddr: ip("10.250.77.2"),
        daddr_nat: ip("10.250.77.2"),
        ipv6: false,
        udp: None,
    };
    assert_eq!(drops(&inbound), Some("fwd-in: not live"));
    // Own gateway DNS and DHCP keep working.
    assert_eq!(drops(&guest("10.250.77.1", None)), None);
    let mut discover = guest("255.255.255.255", None);
    discover.udp = Some((68, 67));
    assert_eq!(drops(&discover), None);
    // An unknown bridge (not yet seen by the guard) has neither forwarding
    // nor a gateway pair.
    let mut unknown = guest("93.184.216.34", Some("wlan0"));
    unknown.iif = "wsn-new0000000";
    assert_eq!(guard_drops(&g, &node, &unknown), Some("pre: not live"));
    let mut unknown_gw = guest("10.250.79.1", None);
    unknown_gw.iif = "wsn-new0000000";
    let node2 = Node {
        local: vec![ip("10.250.79.1")],
        broadcast: vec![],
    };
    assert_eq!(
        guard_drops(&g, &node2, &unknown_gw),
        Some("pre: node address")
    );
}
