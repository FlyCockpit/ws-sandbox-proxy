//! Security-critical: supported packet path checker (M14).

use serde_json::{Value, json};

use super::*;

/// A reference host's ruleset (Incus, iptables-nft, netbird, two test
/// bridges), taken before the guard was loaded; identifiers replaced with
/// documentation ranges.
const SAMPLE_HOST_RULESET: &str = include_str!("fixtures/ruleset-before.json");

fn sample_host_ruleset() -> Value {
    serde_json::from_str(SAMPLE_HOST_RULESET).unwrap()
}

fn links() -> Value {
    json!([
        {"ifname":"lo"},
        {"ifname":"wlan0"},
        {"ifname":"wt0","linkinfo":{"info_kind":"wireguard"}},
        {"ifname":"incusbr0","linkinfo":{"info_kind":"bridge"}},
        {"ifname":"veth3ca695be","master":"incusbr0","linkinfo":{"info_kind":"veth"}},
        {"ifname":"wsn-gq0","linkinfo":{"info_kind":"bridge"}},
        {"ifname":"tap517db40c","master":"wsn-gq0","linkinfo":{"info_kind":"tun"}},
        {"ifname":"wsn-gq1","linkinfo":{"info_kind":"bridge"}}
    ])
}

fn addrs() -> Value {
    json!([
        {"ifname":"lo","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8}]},
        {"ifname":"wlan0","addr_info":[{"family":"inet","local":"192.0.2.88","prefixlen":24}]},
        {"ifname":"wt0","addr_info":[{"family":"inet","local":"100.64.0.10","prefixlen":16}]},
        {"ifname":"incusbr0","addr_info":[{"family":"inet","local":"10.71.136.1","prefixlen":24}]},
        {"ifname":"wsn-gq0","addr_info":[{"family":"inet","local":"10.250.77.1","prefixlen":24}]},
        {"ifname":"wsn-gq1","addr_info":[{"family":"inet","local":"10.250.78.1","prefixlen":24}]}
    ])
}

fn qdiscs() -> Value {
    json!([
        {"kind":"noqueue","handle":"0:","dev":"lo","root":true},
        {"kind":"fq_codel","handle":"0:","dev":"wlan0","root":true},
        {"kind":"noqueue","handle":"0:","dev":"wsn-gq0","root":true}
    ])
}

fn uplinks() -> Vec<String> {
    vec!["wlan0".into()]
}

fn run(ruleset: &Value, links: &Value, addrs: &Value, qdiscs: &Value) -> PathReport {
    check(&PathInputs {
        ruleset,
        links,
        addresses: addrs,
        qdiscs,
        uplinks: &uplinks(),
    })
    .unwrap()
}

fn with_items(extra: Vec<Value>) -> Value {
    let mut ruleset = sample_host_ruleset();
    ruleset["nftables"].as_array_mut().unwrap().extend(extra);
    ruleset
}

fn healthy() -> PathReport {
    run(&sample_host_ruleset(), &links(), &addrs(), &qdiscs())
}

#[test]
fn sample_host_shape_is_healthy() {
    let report = healthy();
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert!(report.excluded.is_empty());
    assert_eq!(
        report.bridges,
        [
            GatewayPair {
                bridge: "wsn-gq0".into(),
                gateway: "10.250.77.1".parse().unwrap()
            },
            GatewayPair {
                bridge: "wsn-gq1".into(),
                gateway: "10.250.78.1".parse().unwrap()
            }
        ]
    );
    let subnets: Vec<String> = report
        .sandbox_subnets
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(subnets, ["10.250.77.0/24", "10.250.78.0/24"]);
}

#[test]
fn our_own_chains_never_count_as_early() {
    let report = run(
        &with_items(vec![
            json!({"chain":{"family":"inet","table":"wssp_guard","name":"pre","hook":"prerouting","prio":-310,"type":"filter","policy":"accept"}}),
            json!({"chain":{"family":"inet","table":"wssp_guard","name":"input","hook":"input","prio":-300,"type":"filter","policy":"accept"}}),
        ]),
        &links(),
        &addrs(),
        &qdiscs(),
    );
    assert!(report.findings.is_empty(), "{:?}", report.findings);
}

#[test]
fn each_unsupported_path_is_a_finding() {
    let cases: Vec<(Value, &str)> = vec![
        (
            json!({"flowtable":{"family":"inet","table":"qual","name":"ft","hook":"ingress","prio":0,"dev":"lo"}}),
            "flowtable:inet/qual/ft",
        ),
        (
            json!({"flowtable":{"family":"ip","table":"x","name":"hw","flags":["offload"]}}),
            "flowtable:ip/x/hw",
        ),
        (
            json!({"rule":{"family":"inet","table":"fw","chain":"fwd","expr":[{"flow":{"op":"add","flowtable":"@ft"}}]}}),
            "flow_offload:inet/fw/fwd",
        ),
        (
            json!({"chain":{"family":"ip","table":"raw","name":"PREROUTING","hook":"prerouting","prio":-310,"type":"filter"}}),
            "early_chain:ip/raw/PREROUTING@-310",
        ),
        (
            json!({"chain":{"family":"inet","table":"x","name":"early","hook":"forward","prio":-400,"type":"filter"}}),
            "early_chain:inet/x/early@-400",
        ),
        (
            json!({"chain":{"family":"inet","table":"x","name":"nat","hook":"input","prio":-300,"type":"nat"}}),
            "early_chain:inet/x/nat@-300",
        ),
        (
            json!({"chain":{"family":"netdev","table":"n","name":"in","hook":"ingress","prio":0,"dev":"wsn-gq0"}}),
            "netdev_chain:n/in/ingress",
        ),
        (
            json!({"chain":{"family":"netdev","table":"n","name":"port","hook":"egress","prio":0,"dev":["eth9","tap517db40c"]}}),
            "netdev_chain:n/port/egress",
        ),
        (
            json!({"chain":{"family":"netdev","table":"n","name":"up","hook":"ingress","prio":0,"dev":"wlan0"}}),
            "netdev_chain:n/up/ingress",
        ),
        (
            json!({"chain":{"family":"inet","table":"n","name":"ing","hook":"ingress","prio":0,"dev":"wsn-gq1"}}),
            "inet_chain:n/ing/ingress",
        ),
        (
            json!({"table":{"family":"bridge","name":"docker"}}),
            "bridge_table:docker",
        ),
    ];
    for (item, want) in cases {
        let report = run(
            &with_items(vec![item.clone()]),
            &links(),
            &addrs(),
            &qdiscs(),
        );
        assert_eq!(report.findings, [want.to_string()], "{item}");
    }
}

#[test]
fn chains_strictly_after_the_guard_or_off_path_are_fine() {
    let report = run(
        &with_items(vec![
            json!({"chain":{"family":"ip","table":"raw","name":"PREROUTING","hook":"prerouting","prio":-300,"type":"filter"}}),
            json!({"chain":{"family":"inet","table":"x","name":"out","hook":"output","prio":-500,"type":"filter"}}),
            json!({"chain":{"family":"ip6","table":"x","name":"pre","hook":"prerouting","prio":-500,"type":"filter"}}),
            json!({"chain":{"family":"netdev","table":"n","name":"other","hook":"ingress","prio":0,"dev":"enp193s0"}}),
            json!({"table":{"family":"bridge","name":"incus"}}),
        ]),
        &links(),
        &addrs(),
        &qdiscs(),
    );
    assert!(report.findings.is_empty(), "{:?}", report.findings);
}

#[test]
fn xdp_and_tc_ingress_on_the_sandbox_path() {
    let mut l = links();
    l.as_array_mut().unwrap()[1]["xdp"] = json!({"mode":1,"prog":{"id":7}});
    let report = run(&sample_host_ruleset(), &l, &addrs(), &qdiscs());
    assert_eq!(report.findings, ["xdp:wlan0"]);

    let mut q = qdiscs();
    q.as_array_mut()
        .unwrap()
        .push(json!({"kind":"clsact","handle":"ffff:","dev":"tap517db40c","parent":"ffff:fff1"}));
    let report = run(&sample_host_ruleset(), &links(), &addrs(), &q);
    assert_eq!(report.findings, ["tc_clsact:tap517db40c"]);

    let mut q = qdiscs();
    q.as_array_mut()
        .unwrap()
        .push(json!({"kind":"ingress","handle":"ffff:","dev":"wsn-gq1"}));
    assert_eq!(
        run(&sample_host_ruleset(), &links(), &addrs(), &q).findings,
        ["tc_ingress:wsn-gq1"]
    );

    // Off-path devices are not the guard's concern.
    let mut q = qdiscs();
    q.as_array_mut()
        .unwrap()
        .push(json!({"kind":"clsact","handle":"ffff:","dev":"docker0"}));
    assert!(
        run(&sample_host_ruleset(), &links(), &addrs(), &q)
            .findings
            .is_empty()
    );
}

fn excluded_reason(links: &Value, addrs: &Value) -> Vec<(String, String)> {
    let report = run(&sample_host_ruleset(), links, addrs, &qdiscs());
    assert!(report.findings.is_empty());
    // wsn-gq1 is untouched in every case: one bad bridge never affects another.
    assert!(report.bridges.iter().any(|p| p.bridge == "wsn-gq1"));
    report
        .excluded
        .into_iter()
        .map(|e| (e.bridge, e.reason))
        .collect()
}

#[test]
fn malformed_bridges_are_excluded_alone() {
    let gq0 = |reason: &str| vec![("wsn-gq0".to_string(), reason.to_string())];

    let mut a = addrs();
    a[4]["addr_info"]
        .as_array_mut()
        .unwrap()
        .push(json!({"family":"inet","local":"10.250.77.250","prefixlen":24}));
    assert_eq!(
        excluded_reason(&links(), &a),
        gq0("multiple_ipv4_addresses")
    );

    let mut a = addrs();
    a[4]["addr_info"][0]["prefixlen"] = json!(23);
    assert_eq!(excluded_reason(&links(), &a), gq0("prefix_not_24"));

    let mut a = addrs();
    a[4]["addr_info"][0]["local"] = json!("10.250.77.2");
    assert_eq!(excluded_reason(&links(), &a), gq0("gateway_not_dot1"));

    let mut a = addrs();
    a.as_array_mut().unwrap().remove(4);
    assert_eq!(excluded_reason(&links(), &a), gq0("no_ipv4_address"));

    let mut l = links();
    l.as_array_mut()
        .unwrap()
        .push(json!({"ifname":"veth9","master":"wsn-gq0","linkinfo":{"info_kind":"veth"}}));
    assert_eq!(excluded_reason(&l, &addrs()), gq0("foreign_port:veth9"));

    let mut l = links();
    l[5]["linkinfo"]["info_kind"] = json!("dummy");
    assert_eq!(excluded_reason(&l, &addrs()), gq0("not_a_bridge"));
}

#[test]
fn malformed_listings_are_errors() {
    let bad_inputs = [
        (json!({}), links(), addrs(), qdiscs()),
        (sample_host_ruleset(), json!({}), addrs(), qdiscs()),
        (
            sample_host_ruleset(),
            links(),
            json!([{"addr_info":[]}]),
            qdiscs(),
        ),
        (
            sample_host_ruleset(),
            links(),
            addrs(),
            json!([{"dev":"x"}]),
        ),
        (
            with_items(vec![
                json!({"chain":{"family":"ip","table":"t","name":"c","hook":"input"}}),
            ]),
            links(),
            addrs(),
            qdiscs(),
        ),
        (
            sample_host_ruleset(),
            links(),
            json!([{"ifname":"wsn-gq0","addr_info":[{"family":"inet","local":"nope","prefixlen":24}]}]),
            qdiscs(),
        ),
    ];
    for (ruleset, links, addrs, qdiscs) in bad_inputs {
        assert!(
            check(&PathInputs {
                ruleset: &ruleset,
                links: &links,
                addresses: &addrs,
                qdiscs: &qdiscs,
                uplinks: &uplinks(),
            })
            .is_err()
        );
    }
}

/// Review P1-1: a tc `mirred` redirect on the UPLINK transmits straight into
/// a sandbox port, past every netfilter hook; it is a finding like one on
/// the bridge or its ports.
#[test]
fn tc_ingress_or_clsact_on_an_uplink_is_a_finding() {
    for kind in ["ingress", "clsact"] {
        let mut q = qdiscs();
        q.as_array_mut()
            .unwrap()
            .push(json!({"kind":kind,"handle":"ffff:","dev":"wlan0"}));
        assert_eq!(
            run(&sample_host_ruleset(), &links(), &addrs(), &q).findings,
            [format!("tc_{kind}:wlan0")]
        );
    }
}

#[test]
fn fence_targets_are_sandbox_bridges_and_their_ports() {
    let listing = json!([
        {"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP"]},
        {"ifindex":2,"ifname":"wlan0","flags":["UP"]},
        {"ifindex":5,"ifname":"incusbr0","flags":["UP"]},
        {"ifindex":6,"ifname":"veth3ca695be","master":"incusbr0","flags":["UP"]},
        {"ifindex":9,"ifname":"wsn-gq0","flags":["BROADCAST","UP","LOWER_UP"]},
        {"ifindex":10,"ifname":"tap517db40c","master":"wsn-gq0","flags":["UP"]},
        {"ifindex":11,"ifname":"wsn-gq1","flags":["BROADCAST"]}
    ]);
    let targets = sandbox_links(&listing).unwrap();
    let names: Vec<(&str, u64, bool, bool)> = targets
        .iter()
        .map(|l| (l.name.as_str(), l.ifindex, l.bridge, l.up))
        .collect();
    assert_eq!(
        names,
        [
            ("tap517db40c", 10, false, true),
            ("wsn-gq0", 9, true, true),
            ("wsn-gq1", 11, true, false),
        ]
    );
    // A target without identity or flags is an error, never skipped.
    assert!(sandbox_links(&json!([{"ifname":"wsn-x","flags":["UP"]}])).is_err());
    assert!(sandbox_links(&json!([{"ifindex":3,"ifname":"wsn-x"}])).is_err());
    assert!(sandbox_links(&json!({})).is_err());
}

#[test]
fn sandbox_subnets_come_from_the_address_listing_alone() {
    let subnets: Vec<String> = sandbox_subnets(&addrs())
        .unwrap()
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(subnets, ["10.250.77.0/24", "10.250.78.0/24"]);
    assert!(sandbox_subnets(&json!({})).is_err());
}

fn base_chain(family: &str, table: &str, name: &str, hook: &str, policy: &str) -> Value {
    json!({"chain":{"family":family,"table":table,"name":name,"hook":hook,"prio":0,"type":"filter","policy":policy}})
}

fn rule(family: &str, table: &str, chain: &str, expr: Value) -> Value {
    json!({"rule":{"family":family,"table":table,"chain":chain,"expr":expr}})
}

fn ufw_allow_wsn(chain: &str) -> Value {
    rule(
        "ip",
        "filter",
        chain,
        json!([
            {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"wsn*"}},
            {"counter":{"packets":0,"bytes":0}},
            {"accept":null}
        ]),
    )
}

/// E1-A-01: a host's ufw (`DEFAULT_INPUT_POLICY="DROP"`) dropped every
/// sandbox's DHCP while the guard reported healthy.
#[test]
fn a_drop_policy_host_firewall_without_a_wsn_allow_blocks_sandboxes() {
    // The sample host (ufw disabled, policies accept): nothing to report.
    assert!(healthy().host_firewall.is_empty());

    let ufw = vec![
        base_chain("ip", "filter", "ufw-input", "input", "drop"),
        base_chain("ip", "filter", "ufw-forward", "forward", "drop"),
        rule(
            "ip",
            "filter",
            "ufw-input",
            json!([{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"lo"}},{"accept":null}]),
        ),
    ];
    let report = run(&with_items(ufw.clone()), &links(), &addrs(), &qdiscs());
    assert_eq!(
        report.host_firewall,
        ["ip/filter/ufw-forward", "ip/filter/ufw-input"]
    );
    // Never a packet-path finding: it cannot let a packet skip the guard.
    assert!(report.findings.is_empty(), "{:?}", report.findings);

    // `ufw allow in on wsn+` (+ route rules) admits the bridges.
    let mut fixed = ufw.clone();
    fixed.push(ufw_allow_wsn("ufw-user-input"));
    let report = run(&with_items(fixed), &links(), &addrs(), &qdiscs());
    assert!(
        report.host_firewall.is_empty(),
        "{:?}",
        report.host_firewall
    );

    // An accept in another table does not help (every base chain sees it).
    let mut other_table = ufw.clone();
    other_table.push(rule(
        "inet",
        "mine",
        "x",
        json!([{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"wsn*"}},{"accept":null}]),
    ));
    let report = run(&with_items(other_table), &links(), &addrs(), &qdiscs());
    assert_eq!(report.host_firewall.len(), 2);

    // A negated match is not an allow.
    let mut negated = ufw;
    negated.push(rule(
        "ip",
        "filter",
        "ufw-input",
        json!([{"match":{"op":"!=","left":{"meta":{"key":"iifname"}},"right":"wsn*"}},{"accept":null}]),
    ));
    let report = run(&with_items(negated), &links(), &addrs(), &qdiscs());
    assert_eq!(report.host_firewall.len(), 2);
}

#[test]
fn a_firewalld_style_final_reject_counts_and_a_trusted_zone_goto_admits() {
    let firewalld = vec![
        base_chain("inet", "firewalld", "filter_INPUT", "input", "accept"),
        rule(
            "inet",
            "firewalld",
            "filter_INPUT",
            json!([{"jump":{"target":"filter_INPUT_ZONES"}}]),
        ),
        rule(
            "inet",
            "firewalld",
            "filter_INPUT",
            json!([{"reject":{"type":"icmpx","expr":"admin-prohibited"}}]),
        ),
    ];
    let report = run(
        &with_items(firewalld.clone()),
        &links(),
        &addrs(),
        &qdiscs(),
    );
    assert_eq!(report.host_firewall, ["inet/firewalld/filter_INPUT"]);

    let mut trusted = firewalld;
    trusted.push(rule(
        "inet",
        "firewalld",
        "filter_INPUT_ZONES",
        json!([{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":{"set":["wsn*"]}}},{"goto":{"target":"filter_IN_trusted"}}]),
    ));
    let report = run(&with_items(trusted), &links(), &addrs(), &qdiscs());
    assert!(
        report.host_firewall.is_empty(),
        "{:?}",
        report.host_firewall
    );
}

#[test]
fn incus_and_guard_tables_and_non_filter_hooks_are_never_host_firewalls() {
    let report = run(
        &with_items(vec![
            base_chain("inet", "incus", "aclin.wsn-gq0", "input", "drop"),
            base_chain("inet", "wssp_guard", "input", "input", "drop"),
            base_chain("ip", "filter", "OUTPUT", "output", "drop"),
            base_chain("ip6", "filter", "INPUT", "input", "drop"),
            // A conditional final drop is not a default drop.
            base_chain("ip", "filter", "INPUT2", "input", "accept"),
            rule(
                "ip",
                "filter",
                "INPUT2",
                json!([{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":23}},{"drop":null}]),
            ),
        ]),
        &links(),
        &addrs(),
        &qdiscs(),
    );
    assert!(
        report.host_firewall.is_empty(),
        "{:?}",
        report.host_firewall
    );
}
