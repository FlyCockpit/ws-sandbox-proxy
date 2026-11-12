//! IPv4 prefix arithmetic for the guard.
//!
//! Self-contained on purpose: the guard compiles only from its own inputs and
//! the shared contract fixture. Interval sets in nftables reject overlapping
//! elements, so every set the compiler emits goes through [`normalize`].

use std::fmt;
use std::net::Ipv4Addr;
use std::sync::OnceLock;

/// The shared contract fixture (`sandboxProtectedV4`), embedded at compile
/// time so the guard's static set can never drift from the control plane.
const EGRESS_POLICY_CASES_JSON: &str =
    include_str!("../../../sandbox-protocol/fixtures/egress_policy_cases.json");

/// One IPv4 network, base canonical (host bits zero).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ipv4Net {
    base: u32,
    prefix: u8,
}

fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    }
}

impl Ipv4Net {
    /// A network from an address and prefix; `None` when the prefix exceeds
    /// 32 or host bits are set.
    pub fn new(address: Ipv4Addr, prefix: u8) -> Option<Self> {
        if prefix > 32 {
            return None;
        }
        let base = u32::from(address);
        (base & mask(prefix) == base).then_some(Self { base, prefix })
    }

    /// The network that contains `address` at `prefix` (host bits cleared).
    pub fn containing(address: Ipv4Addr, prefix: u8) -> Option<Self> {
        (prefix <= 32).then(|| Self {
            base: u32::from(address) & mask(prefix),
            prefix,
        })
    }

    pub fn host(address: Ipv4Addr) -> Self {
        Self {
            base: u32::from(address),
            prefix: 32,
        }
    }

    /// Strict canonical `a.b.c.d/p` (decimal prefix without leading zeros).
    pub fn parse_cidr(text: &str) -> Option<Self> {
        let (address, prefix) = text.split_once('/')?;
        if prefix.is_empty()
            || (prefix.len() > 1 && prefix.starts_with('0'))
            || !prefix.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        let prefix: u8 = prefix.parse().ok()?;
        let address: Ipv4Addr = address.parse().ok()?;
        Self::new(address, prefix)
    }

    pub fn address(self) -> Ipv4Addr {
        Ipv4Addr::from(self.base)
    }

    pub fn prefix(self) -> u8 {
        self.prefix
    }

    pub fn contains(self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & mask(self.prefix) == self.base
    }

    /// `self` lies entirely inside `outer`.
    pub fn within(self, outer: Self) -> bool {
        self.prefix >= outer.prefix && self.base & mask(outer.prefix) == outer.base
    }

    /// Half-open interval `[start, end)` as u64.
    pub fn interval(self) -> (u64, u64) {
        let start = u64::from(self.base);
        (start, start + (1u64 << (32 - u32::from(self.prefix))))
    }
}

impl fmt::Display for Ipv4Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address(), self.prefix)
    }
}

impl serde::Serialize for Ipv4Net {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Ipv4Net {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse_cidr(&text)
            .ok_or_else(|| serde::de::Error::custom(format!("invalid IPv4 CIDR `{text}`")))
    }
}

/// Sorted, deduplicated, with every network that lies inside another one
/// removed. CIDRs either nest or are disjoint, so the result has no overlaps
/// (nftables interval sets refuse overlapping elements).
pub fn normalize(nets: impl IntoIterator<Item = Ipv4Net>) -> Vec<Ipv4Net> {
    let mut all: Vec<Ipv4Net> = nets.into_iter().collect();
    // Shorter prefixes first at the same base, so a cover precedes its parts.
    all.sort_unstable_by_key(|net| (net.base, net.prefix));
    all.dedup();
    let mut out: Vec<Ipv4Net> = Vec::with_capacity(all.len());
    for net in all {
        if out.last().is_some_and(|cover| net.within(*cover)) {
            continue;
        }
        out.push(net);
    }
    out
}

/// Union of the networks as merged half-open intervals (adjacent intervals
/// joined). Two lists cover the same addresses iff their unions are equal.
pub fn interval_union(intervals: impl IntoIterator<Item = (u64, u64)>) -> Vec<(u64, u64)> {
    let mut all: Vec<(u64, u64)> = intervals.into_iter().filter(|(s, e)| s < e).collect();
    all.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(all.len());
    for (start, end) in all {
        match out.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => out.push((start, end)),
        }
    }
    out
}

#[derive(serde::Deserialize)]
struct ProtectedFixture {
    #[serde(rename = "sandboxProtectedV4")]
    sandbox_protected_v4: Vec<String>,
}

fn load_protected() -> Result<Vec<Ipv4Net>, String> {
    let fixture: ProtectedFixture = serde_json::from_str(EGRESS_POLICY_CASES_JSON)
        .map_err(|err| format!("egress contract fixture is invalid: {err}"))?;
    let mut nets = Vec::with_capacity(fixture.sandbox_protected_v4.len());
    for text in &fixture.sandbox_protected_v4 {
        nets.push(
            Ipv4Net::parse_cidr(text)
                .ok_or_else(|| format!("egress contract fixture has a bad CIDR `{text}`"))?,
        );
    }
    if nets.is_empty() {
        return Err("egress contract fixture has an empty protected set".into());
    }
    Ok(normalize(nets))
}

/// `SANDBOX_PROTECTED_V4` from the shared fixture (static guard set).
pub fn protected4() -> Result<&'static [Ipv4Net], String> {
    static PROTECTED: OnceLock<Result<Vec<Ipv4Net>, String>> = OnceLock::new();
    PROTECTED
        .get_or_init(load_protected)
        .as_ref()
        .map(Vec::as_slice)
        .map_err(Clone::clone)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(text: &str) -> Ipv4Net {
        Ipv4Net::parse_cidr(text).unwrap()
    }

    #[test]
    fn parse_is_strict_and_canonical() {
        assert_eq!(net("10.0.0.0/8").to_string(), "10.0.0.0/8");
        for bad in [
            "10.0.0.1/8",
            "10.0.0.0/08",
            "10.0.0.0/33",
            "10.0.0.0",
            "10.0.0.0/",
            "::/0",
        ] {
            assert!(Ipv4Net::parse_cidr(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn normalize_drops_nested_and_duplicates() {
        let out = normalize([
            net("10.250.77.0/24"),
            net("10.0.0.0/8"),
            net("10.0.0.0/8"),
            net("192.0.2.0/24"),
            net("192.0.2.128/25"),
            net("100.64.0.0/16"),
        ]);
        assert_eq!(
            out.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["10.0.0.0/8", "100.64.0.0/16", "192.0.2.0/24"]
        );
    }

    #[test]
    fn interval_union_merges_adjacent() {
        let a = interval_union([
            net("10.0.0.0/25").interval(),
            net("10.0.0.128/25").interval(),
        ]);
        assert_eq!(a, vec![net("10.0.0.0/24").interval()]);
    }

    #[test]
    fn protected_set_is_the_shared_fixture() {
        let set = protected4().unwrap();
        let text: Vec<String> = set.iter().map(ToString::to_string).collect();
        assert!(text.contains(&"168.63.129.16/32".to_string()));
        assert!(text.contains(&"100.64.0.0/10".to_string()));
        assert!(text.contains(&"10.0.0.0/8".to_string()));
        assert_eq!(set.len(), 16);
    }
}
