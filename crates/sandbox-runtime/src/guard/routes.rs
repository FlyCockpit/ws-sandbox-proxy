//! Route classifier over `ip -j -4 route show table all`.
//!
//! - `scope4` = every prefix in every routing table, of ANY length, except
//!   default-like routes and the `local`/`broadcast`/`anycast` types (node
//!   addresses, handled by the `pre`/`input` chains).
//! - Default-like = exactly `0.0.0.0/0`, or the exact pair `0.0.0.0/1` +
//!   `128.0.0.0/1` on the same device(s) in the same table. A lone `/1` or a
//!   pair split across devices is an ordinary prefix and lands in `scope4`.
//! - `uplinks` = interfaces carrying a default-like unicast route in any
//!   table. Forwarded guest traffic may leave only through them.
//!
//! - `node4` = the destinations of those `local`/`broadcast`/`anycast`
//!   routes: the node's own addresses, which the `fib daddr type` rule
//!   drops for guest packets and the egress ceiling refuses for host
//!   sockets opened on a sandbox's behalf (credential proxy).
//!
//! Malformed input is an error; the daemon keeps the previous sets and
//! quarantines (never "empty means nothing to block").

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use serde_json::Value;

use super::net::{Ipv4Net, normalize};
use super::ruleset::{is_sandbox_bridge, valid_ifname};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteSets {
    pub scope4: Vec<Ipv4Net>,
    pub uplinks: Vec<String>,
    pub node4: Vec<Ipv4Net>,
}

fn parse_dst(dst: &str) -> Option<Ipv4Net> {
    if dst == "default" {
        return Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0);
    }
    let (address, prefix) = match dst.split_once('/') {
        Some((address, prefix)) => (address, prefix.parse::<u8>().ok()?),
        None => (dst, 32),
    };
    Ipv4Net::containing(address.parse().ok()?, prefix)
}

fn route_devices(route: &Value) -> Result<BTreeSet<String>, String> {
    let mut devices = BTreeSet::new();
    if let Some(dev) = route.get("dev") {
        devices.insert(
            dev.as_str()
                .ok_or("route `dev` is not a string")?
                .to_string(),
        );
    }
    if let Some(hops) = route.get("nexthops") {
        for hop in hops.as_array().ok_or("route `nexthops` is not an array")? {
            if let Some(dev) = hop.get("dev") {
                devices.insert(
                    dev.as_str()
                        .ok_or("nexthop `dev` is not a string")?
                        .to_string(),
                );
            }
        }
    }
    Ok(devices)
}

fn table_of(route: &Value) -> String {
    match route.get("table") {
        Some(Value::String(name)) => name.clone(),
        Some(Value::Number(id)) => id.to_string(),
        _ => "main".to_string(),
    }
}

/// Classify one `ip -j -4 route show table all` listing.
pub fn classify(listing: &Value) -> Result<RouteSets, String> {
    let routes = listing
        .as_array()
        .ok_or("route listing is not a JSON array")?;
    let mut scope = Vec::new();
    let mut node = Vec::new();
    let mut uplinks = BTreeSet::new();
    // (table, devices) -> which /1 halves are present (low, high).
    let mut halves: BTreeMap<(String, BTreeSet<String>), [bool; 2]> = BTreeMap::new();
    for route in routes {
        if !route.is_object() {
            return Err("route entry is not an object".into());
        }
        let kind = match route.get("type") {
            None => "unicast",
            Some(value) => value.as_str().ok_or("route `type` is not a string")?,
        };
        let dst = route
            .get("dst")
            .and_then(Value::as_str)
            .ok_or("route has no `dst`")?;
        let net = parse_dst(dst).ok_or_else(|| format!("route `dst` `{dst}` is malformed"))?;
        if matches!(kind, "local" | "broadcast" | "anycast") {
            node.push(net);
            continue;
        }
        let devices = route_devices(route)?;
        let unicast = kind == "unicast";
        match net.prefix() {
            0 => {
                // Unreachable/blackhole/prohibit/throw defaults carry no
                // egress path and cannot be scoped (that would drop all).
                if unicast {
                    uplinks.extend(devices);
                }
            }
            1 if unicast && !devices.is_empty() => {
                let high = net.address() != Ipv4Addr::UNSPECIFIED;
                let entry = halves.entry((table_of(route), devices)).or_default();
                entry[usize::from(high)] = true;
            }
            _ => scope.push(net),
        }
    }
    for ((_, devices), present) in &halves {
        if present[0] && present[1] {
            uplinks.extend(devices.iter().cloned());
            continue;
        }
        // A /1 that is not part of a same-table, same-device pair is an
        // ordinary prefix.
        for (high, here) in present.iter().enumerate() {
            let base = if high == 0 {
                Ipv4Addr::UNSPECIFIED
            } else {
                Ipv4Addr::new(128, 0, 0, 0)
            };
            if *here {
                scope.extend(Ipv4Net::new(base, 1));
            }
        }
    }
    for name in &uplinks {
        if !valid_ifname(name) {
            return Err(format!("uplink interface name `{name}` is not supported"));
        }
        if is_sandbox_bridge(name) {
            return Err(format!("default route through sandbox bridge `{name}`"));
        }
    }
    Ok(RouteSets {
        scope4: normalize(scope),
        uplinks: uplinks.into_iter().collect(),
        node4: normalize(node),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scope(sets: &RouteSets) -> Vec<String> {
        sets.scope4.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn sample_host_main_only_lan() {
        let sets = classify(&json!([
            {"dst":"default","gateway":"192.0.2.254","dev":"wlan0","protocol":"dhcp","metric":600,"flags":[]},
            {"dst":"10.71.136.0/24","dev":"incusbr0","protocol":"kernel","scope":"link","flags":[]},
            {"dst":"100.64.0.0/16","dev":"wt0","protocol":"kernel","scope":"link","flags":[]},
            {"dst":"192.0.2.0/24","dev":"wlan0","protocol":"kernel","scope":"link","flags":[]},
            {"type":"local","dst":"10.71.136.1","dev":"incusbr0","table":"local","flags":[]},
            {"type":"broadcast","dst":"10.71.136.255","dev":"incusbr0","table":"local","flags":[]}
        ]))
        .unwrap();
        assert_eq!(sets.uplinks, ["wlan0"]);
        // Node addresses (local/broadcast routes) are the ceiling's node4.
        let node: Vec<String> = sets.node4.iter().map(ToString::to_string).collect();
        assert_eq!(node, ["10.71.136.1/32", "10.71.136.255/32"]);
        // netbird wt0 is scope, never an uplink; docker/incus bridges too.
        assert_eq!(
            scope(&sets),
            ["10.71.136.0/24", "100.64.0.0/16", "192.0.2.0/24"]
        );
    }

    #[test]
    fn tailscale_table_52_public_subnet_route_and_exit_node() {
        let sets = classify(&json!([
            {"dst":"default","dev":"eth0","flags":[]},
            {"dst":"100.64.0.0/10","dev":"tailscale0","table":"52","flags":[]},
            {"dst":"203.0.114.0/24","dev":"tailscale0","table":"52","flags":[]},
            {"type":"throw","dst":"127.0.0.0/8","table":"52","flags":[]},
            {"dst":"default","dev":"tailscale0","table":"52","flags":[]}
        ]))
        .unwrap();
        assert_eq!(sets.uplinks, ["eth0", "tailscale0"]);
        assert_eq!(
            scope(&sets),
            ["100.64.0.0/10", "127.0.0.0/8", "203.0.114.0/24"]
        );
    }

    #[test]
    fn full_tunnel_pair_is_uplink_lone_or_split_half_is_scope() {
        let pair = classify(&json!([
            {"dst":"0.0.0.0/1","dev":"wg0","flags":[]},
            {"dst":"128.0.0.0/1","dev":"wg0","flags":[]},
            {"dst":"default","dev":"eth0","flags":[]}
        ]))
        .unwrap();
        assert_eq!(pair.uplinks, ["eth0", "wg0"]);
        assert!(pair.scope4.is_empty());

        let lone = classify(&json!([{"dst":"0.0.0.0/1","dev":"wg0","flags":[]}])).unwrap();
        assert!(lone.uplinks.is_empty());
        assert_eq!(scope(&lone), ["0.0.0.0/1"]);

        let split = classify(&json!([
            {"dst":"0.0.0.0/1","dev":"wg0","flags":[]},
            {"dst":"128.0.0.0/1","dev":"wg1","flags":[]}
        ]))
        .unwrap();
        assert!(split.uplinks.is_empty());
        assert_eq!(scope(&split), ["0.0.0.0/1", "128.0.0.0/1"]);
    }

    #[test]
    fn public_slash_6_via_uplink_is_scope_m15() {
        let sets = classify(&json!([
            {"dst":"default","dev":"eth0","flags":[]},
            {"dst":"44.0.0.0/6","dev":"eth0","flags":[]}
        ]))
        .unwrap();
        assert_eq!(scope(&sets), ["44.0.0.0/6"]);
        assert_eq!(sets.uplinks, ["eth0"]);
    }

    #[test]
    fn multi_wan_and_multipath_defaults() {
        let sets = classify(&json!([
            {"dst":"default","dev":"wan0","metric":100,"flags":[]},
            {"dst":"default","dev":"wan1","metric":200,"flags":[]},
            {"dst":"default","table":"7","nexthops":[{"dev":"wan2"},{"dev":"wan3"}],"flags":[]}
        ]))
        .unwrap();
        assert_eq!(sets.uplinks, ["wan0", "wan1", "wan2", "wan3"]);
    }

    #[test]
    fn no_default_route_is_empty_uplinks_and_ok() {
        let sets = classify(&json!([{"dst":"192.0.2.0/24","dev":"eth0","flags":[]}])).unwrap();
        assert!(sets.uplinks.is_empty());
        assert_eq!(scope(&sets), ["192.0.2.0/24"]);
    }

    #[test]
    fn unreachable_default_is_neither_uplink_nor_scope() {
        let sets = classify(&json!([
            {"type":"unreachable","dst":"default","table":"9","flags":[]},
            {"type":"blackhole","dst":"198.51.100.0/24","flags":[]}
        ]))
        .unwrap();
        assert!(sets.uplinks.is_empty());
        assert_eq!(scope(&sets), ["198.51.100.0/24"]);
    }

    #[test]
    fn docker_and_sandbox_bridges_are_scope_not_uplinks() {
        let sets = classify(&json!([
            {"dst":"default","dev":"eth0","flags":[]},
            {"dst":"172.17.0.0/16","dev":"docker0","flags":["linkdown"]},
            {"dst":"10.66.111.0/24","dev":"wsn-e71b4e4512","flags":["linkdown"]}
        ]))
        .unwrap();
        assert_eq!(sets.uplinks, ["eth0"]);
        assert_eq!(scope(&sets), ["10.66.111.0/24", "172.17.0.0/16"]);
    }

    #[test]
    fn default_through_a_sandbox_bridge_is_refused() {
        assert!(classify(&json!([{"dst":"default","dev":"wsn-0123456789","flags":[]}])).is_err());
    }

    #[test]
    fn malformed_listings_are_errors() {
        for bad in [
            json!({"dst":"default"}),
            json!([{"dev":"eth0"}]),
            json!([{"dst":"10.0.0.0/40","dev":"eth0"}]),
            json!([{"dst":"nope","dev":"eth0"}]),
            json!([{"dst":"default","dev":7}]),
            json!(["x"]),
            json!([{"dst":"default","dev":"bad name"}]),
        ] {
            assert!(classify(&bad).is_err(), "{bad}");
        }
    }
}
