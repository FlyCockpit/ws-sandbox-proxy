//! Guard ruleset compiler and readback verifier.
//!
//! A pure function of [`GuardInputs`]. The output is the exact shape that
//! passed live qualification on a reference host (`tests/fixtures/guard-test.nft`):
//! one `inet wssp_guard` table, priorities −310 (prerouting) and −300
//! (input, forward), only `return`/`drop` verdicts, no `ct` expression.
//! The whole table is replaced in one `nft -f -` transaction; the dead-man
//! elements of `live_bridges` are added in the same transaction with a
//! timeout, exactly as qualified (`add element … { "wsn-x" timeout 30s }`).

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::net::Ipv4Addr;

use serde_json::Value;

use super::net::{Ipv4Net, interval_union, normalize};
use super::{BRIDGE_PREFIX, FORWARD_PRIORITY, INPUT_PRIORITY, PRE_PRIORITY, TABLE};

/// One `(wsn bridge, its single .1 address)` pair (m14).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayPair {
    pub bridge: String,
    pub gateway: Ipv4Addr,
}

/// Everything the table is compiled from. `live_bridges` empty means
/// quarantine: no sandbox forwarding, no pre-routing path except the own
/// gateway and the DHCP discover.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardInputs {
    pub protected4: Vec<Ipv4Net>,
    pub scope4: Vec<Ipv4Net>,
    pub deny4: Vec<Ipv4Net>,
    pub uplinks: Vec<String>,
    pub gateways: Vec<GatewayPair>,
    pub live_bridges: Vec<String>,
}

impl GuardInputs {
    /// Canonical form: prefix sets normalized (no overlaps), name sets
    /// sorted and deduplicated. Two equal canonical inputs compile to the
    /// same text.
    pub fn canonical(mut self) -> Self {
        self.protected4 = normalize(self.protected4);
        self.scope4 = normalize(self.scope4);
        self.deny4 = normalize(self.deny4);
        for names in [&mut self.uplinks, &mut self.live_bridges] {
            names.sort();
            names.dedup();
        }
        self.gateways.sort();
        self.gateways.dedup();
        self
    }

    /// The destination drop sets, in table order. The single source for the
    /// compiled `protected4`/`scope4`/`deny4` sets, their readback, and the
    /// host-socket [`super::ceiling::EgressCeiling`] (credential proxy), so
    /// the guard and the proxy can never disagree on what a sandbox may reach.
    pub fn drop_sets(&self) -> [(&'static str, &[Ipv4Net]); 3] {
        [
            (PREFIX_SETS[0], &self.protected4),
            (PREFIX_SETS[1], &self.scope4),
            (PREFIX_SETS[2], &self.deny4),
        ]
    }

    /// The same table with the dead-man set empty (§2.0.3 quarantine).
    pub fn quarantined(&self) -> Self {
        Self {
            live_bridges: Vec::new(),
            ..self.clone()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulesetError(pub String);

impl std::fmt::Display for RulesetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RulesetError {}

/// Linux interface names: 1..=15 bytes. The guard only ever quotes names
/// from this alphabet into nft text, so no name can inject syntax.
pub fn valid_ifname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

pub fn is_sandbox_bridge(name: &str) -> bool {
    name.starts_with(BRIDGE_PREFIX)
}

/// The static rule body: `(chain, nft text, readback signature)`. The text is
/// the qualified shape; the signature is what `nft -j list table` reads
/// back for that rule (see [`rule_signature`]). One table drives both the
/// compiler and the readback check.
const RULES: &[(&str, &str, &str)] = &[
    // ORIGINAL destination, before conntrack (−200) and every DNAT (−100).
    (
        "pre",
        r#"iifname != "wsn-*" return"#,
        "meta:iifname != wsn-*; return",
    ),
    (
        "pre",
        r#"meta nfproto ipv6 counter drop comment "pre: ipv6""#,
        "meta:nfproto == ipv6; counter; drop # pre: ipv6",
    ),
    (
        "pre",
        "iifname . ip daddr @gateways return",
        "concat(meta:iifname,ip.daddr) == @gateways; return",
    ),
    (
        "pre",
        "ip daddr 255.255.255.255 udp sport 68 udp dport 67 return",
        "ip.daddr == 255.255.255.255; udp.sport == 68; udp.dport == 67; return",
    ),
    (
        "pre",
        r#"fib daddr type { local, broadcast, multicast, anycast } counter drop comment "pre: node address (pre-NAT)""#,
        "fib:type:daddr == {anycast,broadcast,local,multicast}; counter; drop # pre: node address (pre-NAT)",
    ),
    (
        "pre",
        r#"ip daddr @protected4 counter drop comment "pre: protected4""#,
        "ip.daddr == @protected4; counter; drop # pre: protected4",
    ),
    (
        "pre",
        r#"ip daddr @scope4 counter drop comment "pre: scope4""#,
        "ip.daddr == @scope4; counter; drop # pre: scope4",
    ),
    (
        "pre",
        r#"ip daddr @deny4 counter drop comment "pre: deny4""#,
        "ip.daddr == @deny4; counter; drop # pre: deny4",
    ),
    (
        "pre",
        r#"iifname != @live_bridges counter drop comment "pre: not live (dead-man)""#,
        "meta:iifname != @live_bridges; counter; drop # pre: not live (dead-man)",
    ),
    // TRANSLATED destination that ends on this node.
    (
        "input",
        r#"iifname != "wsn-*" return"#,
        "meta:iifname != wsn-*; return",
    ),
    (
        "input",
        r#"meta nfproto ipv6 counter drop comment "input: ipv6""#,
        "meta:nfproto == ipv6; counter; drop # input: ipv6",
    ),
    (
        "input",
        "iifname . ip daddr @gateways return",
        "concat(meta:iifname,ip.daddr) == @gateways; return",
    ),
    (
        "input",
        "ip daddr 255.255.255.255 udp sport 68 udp dport 67 return",
        "ip.daddr == 255.255.255.255; udp.sport == 68; udp.dport == 67; return",
    ),
    (
        "input",
        r#"counter drop comment "input: other node address (post-NAT)""#,
        "counter; drop # input: other node address (post-NAT)",
    ),
    // TRANSLATED destination that leaves the node.
    (
        "forward",
        r#"iifname "wsn-*" jump from_sandbox"#,
        "meta:iifname == wsn-*; jump from_sandbox",
    ),
    (
        "forward",
        r#"oifname "wsn-*" jump to_sandbox"#,
        "meta:oifname == wsn-*; jump to_sandbox",
    ),
    (
        "from_sandbox",
        r#"iifname != @live_bridges counter drop comment "fwd-out: not live (dead-man)""#,
        "meta:iifname != @live_bridges; counter; drop # fwd-out: not live (dead-man)",
    ),
    (
        "from_sandbox",
        r#"meta nfproto ipv6 counter drop comment "fwd-out: ipv6""#,
        "meta:nfproto == ipv6; counter; drop # fwd-out: ipv6",
    ),
    (
        "from_sandbox",
        r#"ip daddr @protected4 counter drop comment "fwd-out: protected4""#,
        "ip.daddr == @protected4; counter; drop # fwd-out: protected4",
    ),
    (
        "from_sandbox",
        r#"ip daddr @scope4 counter drop comment "fwd-out: scope4""#,
        "ip.daddr == @scope4; counter; drop # fwd-out: scope4",
    ),
    (
        "from_sandbox",
        r#"ip daddr @deny4 counter drop comment "fwd-out: deny4""#,
        "ip.daddr == @deny4; counter; drop # fwd-out: deny4",
    ),
    (
        "from_sandbox",
        r#"oifname != @uplinks counter drop comment "fwd-out: not via uplink""#,
        "meta:oifname != @uplinks; counter; drop # fwd-out: not via uplink",
    ),
    (
        "to_sandbox",
        r#"oifname != @live_bridges counter drop comment "fwd-in: not live (dead-man)""#,
        "meta:oifname != @live_bridges; counter; drop # fwd-in: not live (dead-man)",
    ),
    (
        "to_sandbox",
        r#"meta nfproto ipv6 counter drop comment "fwd-in: ipv6""#,
        "meta:nfproto == ipv6; counter; drop # fwd-in: ipv6",
    ),
    (
        "to_sandbox",
        r#"ip saddr @protected4 counter drop comment "fwd-in: protected4""#,
        "ip.saddr == @protected4; counter; drop # fwd-in: protected4",
    ),
    (
        "to_sandbox",
        r#"ip saddr @scope4 counter drop comment "fwd-in: scope4""#,
        "ip.saddr == @scope4; counter; drop # fwd-in: scope4",
    ),
    (
        "to_sandbox",
        r#"ip saddr @deny4 counter drop comment "fwd-in: deny4""#,
        "ip.saddr == @deny4; counter; drop # fwd-in: deny4",
    ),
    (
        "to_sandbox",
        r#"iifname != @uplinks counter drop comment "fwd-in: not via uplink""#,
        "meta:iifname != @uplinks; counter; drop # fwd-in: not via uplink",
    ),
];

/// `(name, base-chain header)`; `None` for regular chains.
/// `(hook, priority text, priority)` of a base chain.
type BaseChain = (&'static str, &'static str, i32);

const CHAINS: &[(&str, Option<BaseChain>)] = &[
    ("pre", Some(("prerouting", "raw - 10", PRE_PRIORITY))),
    ("input", Some(("input", "filter - 300", INPUT_PRIORITY))),
    (
        "forward",
        Some(("forward", "filter - 300", FORWARD_PRIORITY)),
    ),
    ("from_sandbox", None),
    ("to_sandbox", None),
];

const PREFIX_SETS: [&str; 3] = ["protected4", "scope4", "deny4"];

fn validate(inputs: &GuardInputs) -> Result<(), RulesetError> {
    if inputs.protected4.is_empty() {
        return Err(RulesetError("guard protected set is empty".into()));
    }
    for name in &inputs.uplinks {
        if !valid_ifname(name) || is_sandbox_bridge(name) {
            return Err(RulesetError(format!("invalid uplink interface `{name}`")));
        }
    }
    for name in inputs
        .live_bridges
        .iter()
        .chain(inputs.gateways.iter().map(|pair| &pair.bridge))
    {
        if !valid_ifname(name) || !is_sandbox_bridge(name) {
            return Err(RulesetError(format!("invalid sandbox bridge `{name}`")));
        }
    }
    // A /0 in a drop set would cut every destination; the route classifier
    // never emits one for scope4 (default-like routes are uplinks), so its
    // presence there is a classification bug, not operator intent.
    if inputs.scope4.iter().any(|net| net.prefix() == 0) {
        return Err(RulesetError("scope4 holds 0.0.0.0/0".into()));
    }
    Ok(())
}

fn write_prefix_set(out: &mut String, name: &str, nets: &[Ipv4Net]) {
    let _ = writeln!(
        out,
        "\tset {name} {{\n\t\ttype ipv4_addr\n\t\tflags interval"
    );
    if !nets.is_empty() {
        let items: Vec<String> = nets.iter().map(ToString::to_string).collect();
        let _ = writeln!(out, "\t\telements = {{ {} }}", items.join(", "));
    }
    out.push_str("\t}\n\n");
}

fn write_name_set(out: &mut String, name: &str, flags: Option<&str>, names: &[String]) {
    let _ = writeln!(out, "\tset {name} {{\n\t\ttype ifname");
    if let Some(flags) = flags {
        let _ = writeln!(out, "\t\tflags {flags}");
    }
    if !names.is_empty() {
        let items: Vec<String> = names.iter().map(|n| format!("\"{n}\"")).collect();
        let _ = writeln!(out, "\t\telements = {{ {} }}", items.join(", "));
    }
    out.push_str("\t}\n\n");
}

/// Compile the whole-table transaction. `live_timeout_secs` arms the
/// dead-man (30 s in production; less when re-arming a persisted table so
/// a restart never extends forwarding past the last verified resync).
pub fn compile(inputs: &GuardInputs, live_timeout_secs: u64) -> Result<String, RulesetError> {
    let inputs = inputs.clone().canonical();
    validate(&inputs)?;
    if !(1..=3600).contains(&live_timeout_secs) {
        return Err(RulesetError("live_bridges timeout out of range".into()));
    }
    let mut out = String::new();
    out.push_str("# wssp egress guard: generated, do not edit (plan 2.0.2)\n");
    let _ = writeln!(out, "table inet {TABLE}\ndelete table inet {TABLE}\n");
    let _ = writeln!(out, "table inet {TABLE} {{");
    for (name, nets) in inputs.drop_sets() {
        write_prefix_set(&mut out, name, nets);
    }
    write_name_set(&mut out, "uplinks", None, &inputs.uplinks);
    out.push_str("\tset gateways {\n\t\ttype ifname . ipv4_addr\n");
    if !inputs.gateways.is_empty() {
        let items: Vec<String> = inputs
            .gateways
            .iter()
            .map(|pair| format!("\"{}\" . {}", pair.bridge, pair.gateway))
            .collect();
        let _ = writeln!(out, "\t\telements = {{ {} }}", items.join(", "));
    }
    out.push_str("\t}\n\n");
    // Elements are added below, with their timeout (qualified syntax).
    write_name_set(&mut out, "live_bridges", Some("timeout"), &[]);
    for (index, (chain, base)) in CHAINS.iter().enumerate() {
        let _ = writeln!(out, "\tchain {chain} {{");
        if let Some((hook, priority_text, _)) = base {
            let _ = writeln!(
                out,
                "\t\ttype filter hook {hook} priority {priority_text}; policy accept;"
            );
        }
        for (_, text, _) in RULES.iter().filter(|(c, _, _)| c == chain) {
            let _ = writeln!(out, "\t\t{text}");
        }
        out.push_str("\t}\n");
        if index + 1 < CHAINS.len() {
            out.push('\n');
        }
    }
    out.push_str("}\n");
    if !inputs.live_bridges.is_empty() {
        let items: Vec<String> = inputs
            .live_bridges
            .iter()
            .map(|n| format!("\"{n}\" timeout {live_timeout_secs}s"))
            .collect();
        let _ = writeln!(
            out,
            "add element inet {TABLE} live_bridges {{ {} }}",
            items.join(", ")
        );
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Readback (`nft -j list table inet wssp_guard`), compared semantically.
// ---------------------------------------------------------------------------

fn expr_operand(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        Value::Object(map) => {
            if let Some(meta) = map.get("meta") {
                return format!("meta:{}", meta["key"].as_str().unwrap_or("?"));
            }
            if let Some(payload) = map.get("payload") {
                return format!(
                    "{}.{}",
                    payload["protocol"].as_str().unwrap_or("?"),
                    payload["field"].as_str().unwrap_or("?")
                );
            }
            if let Some(fib) = map.get("fib") {
                let flags: Vec<&str> = fib["flags"]
                    .as_array()
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                return format!(
                    "fib:{}:{}",
                    fib["result"].as_str().unwrap_or("?"),
                    flags.join("+")
                );
            }
            if let Some(Value::Array(parts)) = map.get("concat") {
                let parts: Vec<String> = parts.iter().map(expr_operand).collect();
                return format!("concat({})", parts.join(","));
            }
            if let Some(Value::Array(items)) = map.get("set") {
                let mut items: Vec<String> = items.iter().map(expr_operand).collect();
                items.sort();
                return format!("{{{}}}", items.join(","));
            }
            if let Some(prefix) = map.get("prefix") {
                return format!(
                    "{}/{}",
                    prefix["addr"].as_str().unwrap_or("?"),
                    prefix["len"]
                );
            }
            format!("?{}", map.keys().cloned().collect::<Vec<_>>().join("+"))
        }
        other => format!("?{other}"),
    }
}

/// Canonical signature of one rule from `nft -j` output. Counter values,
/// handles and positions are ignored; every expression kind the guard does
/// not emit renders as `!kind`, so it can never match an expected rule.
pub fn rule_signature(rule: &Value) -> String {
    let mut parts = Vec::new();
    for expr in rule["expr"].as_array().into_iter().flatten() {
        let Some(map) = expr.as_object() else {
            parts.push("!expr".to_string());
            continue;
        };
        for (key, body) in map {
            parts.push(match key.as_str() {
                "match" => format!(
                    "{} {} {}",
                    expr_operand(&body["left"]),
                    body["op"].as_str().unwrap_or("?"),
                    expr_operand(&body["right"])
                ),
                "counter" => "counter".into(),
                "drop" => "drop".into(),
                "return" => "return".into(),
                "jump" => format!("jump {}", body["target"].as_str().unwrap_or("?")),
                other => format!("!{other}"),
            });
        }
    }
    let mut sig = parts.join("; ");
    if let Some(comment) = rule["comment"].as_str() {
        let _ = write!(sig, " # {comment}");
    }
    sig
}

fn ipv4_value(value: &Value) -> Option<u64> {
    value
        .as_str()?
        .parse::<Ipv4Addr>()
        .ok()
        .map(|ip| u64::from(u32::from(ip)))
}

fn interval_of(element: &Value) -> Option<(u64, u64)> {
    match element {
        Value::String(_) => ipv4_value(element).map(|start| (start, start + 1)),
        Value::Object(map) => {
            if let Some(inner) = map.get("elem") {
                return interval_of(&inner["val"]);
            }
            if let Some(prefix) = map.get("prefix") {
                let addr: Ipv4Addr = prefix["addr"].as_str()?.parse().ok()?;
                let len = u8::try_from(prefix["len"].as_u64()?).ok()?;
                return Ipv4Net::new(addr, len).map(Ipv4Net::interval);
            }
            if let Some(Value::Array(bounds)) = map.get("range") {
                let start = ipv4_value(bounds.first()?)?;
                let end = ipv4_value(bounds.get(1)?)?;
                return (start <= end).then_some((start, end + 1));
            }
            None
        }
        _ => None,
    }
}

fn name_of(element: &Value) -> Option<String> {
    match element {
        Value::String(name) => Some(name.clone()),
        Value::Object(map) => map.get("elem").and_then(|inner| name_of(&inner["val"])),
        _ => None,
    }
}

fn pair_of(element: &Value) -> Option<GatewayPair> {
    match element {
        Value::Object(map) => {
            if let Some(inner) = map.get("elem") {
                return pair_of(&inner["val"]);
            }
            let parts = map.get("concat")?.as_array()?;
            Some(GatewayPair {
                bridge: parts.first()?.as_str()?.to_string(),
                gateway: parts.get(1)?.as_str()?.parse().ok()?,
            })
        }
        _ => None,
    }
}

fn elements(set: &Value) -> &[Value] {
    set["elem"].as_array().map(Vec::as_slice).unwrap_or(&[])
}

fn flags(set: &Value) -> BTreeSet<String> {
    match &set["flags"] {
        Value::Array(items) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        Value::String(flag) => BTreeSet::from([flag.clone()]),
        _ => BTreeSet::new(),
    }
}

/// Verify a `nft -j list table inet wssp_guard` listing against the inputs
/// it was compiled from. Any difference (missing or extra object, a chain
/// header, a rule, a set's addresses or names) is an error, which the
/// daemon turns into quarantine.
pub fn verify_readback(expected: &GuardInputs, listing: &Value) -> Result<(), RulesetError> {
    let expected = expected.clone().canonical();
    let fail = |message: String| Err(RulesetError(format!("readback mismatch: {message}")));
    let Some(items) = listing["nftables"].as_array() else {
        return fail("listing has no `nftables` array".into());
    };
    let mut tables = 0usize;
    let mut sets = std::collections::BTreeMap::new();
    let mut chains = std::collections::BTreeMap::new();
    let mut rules: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for item in items {
        let Some((kind, body)) = item.as_object().and_then(|m| m.iter().next()) else {
            return fail("listing item is not an object".into());
        };
        if kind == "metainfo" {
            continue;
        }
        if body["family"] != "inet" || (kind != "table" && body["table"] != TABLE) {
            return fail(format!("foreign {kind} in the guard listing"));
        }
        match kind.as_str() {
            "table" if body["name"] == TABLE => tables += 1,
            "set" => {
                let name = body["name"].as_str().unwrap_or_default().to_string();
                if sets.insert(name.clone(), body.clone()).is_some() {
                    return fail(format!("duplicate set `{name}`"));
                }
            }
            "chain" => {
                let name = body["name"].as_str().unwrap_or_default().to_string();
                if chains.insert(name.clone(), body.clone()).is_some() {
                    return fail(format!("duplicate chain `{name}`"));
                }
            }
            "rule" => rules
                .entry(body["chain"].as_str().unwrap_or_default().to_string())
                .or_default()
                .push(rule_signature(body)),
            other => return fail(format!("unexpected `{other}` object")),
        }
    }
    if tables != 1 {
        return fail(format!("{tables} guard tables"));
    }
    // Sets: exact names, types, flags and contents.
    let expected_sets: BTreeSet<&str> = PREFIX_SETS
        .into_iter()
        .chain(["uplinks", "gateways", "live_bridges"])
        .collect();
    let actual_sets: BTreeSet<&str> = sets.keys().map(String::as_str).collect();
    if actual_sets != expected_sets {
        return fail(format!("sets {actual_sets:?}"));
    }
    for (name, nets) in expected.drop_sets() {
        let set = &sets[name];
        if set["type"] != "ipv4_addr" || flags(set) != BTreeSet::from(["interval".to_string()]) {
            return fail(format!("set `{name}` type or flags"));
        }
        let mut actual = Vec::new();
        for element in elements(set) {
            match interval_of(element) {
                Some(interval) => actual.push(interval),
                None => return fail(format!("set `{name}` has an unreadable element")),
            }
        }
        if interval_union(actual) != interval_union(nets.iter().map(|n| n.interval())) {
            return fail(format!("set `{name}` contents"));
        }
    }
    for (name, want_flags, names) in [
        ("uplinks", BTreeSet::new(), &expected.uplinks),
        (
            "live_bridges",
            BTreeSet::from(["timeout".to_string()]),
            &expected.live_bridges,
        ),
    ] {
        let set = &sets[name];
        if set["type"] != "ifname" || flags(set) != want_flags {
            return fail(format!("set `{name}` type or flags"));
        }
        let actual: Option<BTreeSet<String>> = elements(set).iter().map(name_of).collect();
        let want: BTreeSet<String> = names.iter().cloned().collect();
        if actual.as_ref() != Some(&want) {
            return fail(format!("set `{name}` contents"));
        }
    }
    let gateways = &sets["gateways"];
    if gateways["type"] != serde_json::json!(["ifname", "ipv4_addr"]) || !flags(gateways).is_empty()
    {
        return fail("set `gateways` type or flags".into());
    }
    let actual: Option<BTreeSet<GatewayPair>> = elements(gateways).iter().map(pair_of).collect();
    let want: BTreeSet<GatewayPair> = expected.gateways.iter().cloned().collect();
    if actual.as_ref() != Some(&want) {
        return fail("set `gateways` contents".into());
    }
    // Chains: exact names and base headers.
    let actual_chains: BTreeSet<&str> = chains.keys().map(String::as_str).collect();
    let want_chains: BTreeSet<&str> = CHAINS.iter().map(|(name, _)| *name).collect();
    if actual_chains != want_chains {
        return fail(format!("chains {actual_chains:?}"));
    }
    for (name, base) in CHAINS {
        let chain = &chains[*name];
        match base {
            Some((hook, _, priority)) => {
                if chain["type"] != "filter"
                    || chain["hook"] != *hook
                    || chain["prio"].as_i64() != Some(i64::from(*priority))
                    || chain["policy"] != "accept"
                {
                    return fail(format!("chain `{name}` header"));
                }
            }
            None => {
                if chain.get("hook").is_some() {
                    return fail(format!("chain `{name}` became a base chain"));
                }
            }
        }
        let want: Vec<&str> = RULES
            .iter()
            .filter(|(c, _, _)| c == name)
            .map(|(_, _, sig)| *sig)
            .collect();
        let actual: Vec<&str> = rules
            .get(*name)
            .map(|r| r.iter().map(String::as_str).collect())
            .unwrap_or_default();
        if actual != want {
            return fail(format!("chain `{name}` rules"));
        }
    }
    if rules.keys().any(|chain| !chains.contains_key(chain)) {
        return fail("rule in an unknown chain".into());
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/ruleset.rs"]
mod tests;
