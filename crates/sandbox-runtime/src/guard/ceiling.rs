//! The node's egress ceiling: every destination the guard drops for a
//! sandbox, as one predicate for host sockets opened on a sandbox's behalf.
//!
//! The guard's table cuts guest packets on the sandbox bridges; a socket the
//! daemon opens itself (the CLI-logins credential proxy) never
//! crosses those chains. That socket must still obey the same ceiling, so
//! the guard publishes it (`{"op":"ceiling"}`) from the exact inputs it
//! compiled and verified, and the daemon refuses any destination it covers:
//!
//! - the drop sets the compiler writes ([`GuardInputs::drop_sets`]):
//!   `protected4`, `scope4` (every non-default route prefix, any table) and
//!   `deny4` (operator root list plus deployment push);
//! - the `fib daddr type { local, broadcast, multicast, anycast }` rule:
//!   the node's own addresses ([`super::routes::RouteSets::node4`]), the
//!   limited broadcast address and multicast.
//!
//! The guard serves it only while healthy; the daemon fails closed when it is
//! unavailable (no ceiling, no proxied connection).

use std::net::Ipv4Addr;

use super::net::{Ipv4Net, normalize};
use super::ruleset::GuardInputs;

/// `224.0.0.0/4` and `255.255.255.255`: what `fib daddr type
/// { multicast, broadcast }` matches whatever the node's routes say.
fn fib_special(ip: Ipv4Addr) -> bool {
    ip.is_multicast() || ip.is_broadcast() || ip.is_unspecified()
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressCeiling {
    pub protected4: Vec<Ipv4Net>,
    pub scope4: Vec<Ipv4Net>,
    pub deny4: Vec<Ipv4Net>,
    /// The node's own addresses (local, broadcast and anycast routes).
    pub node4: Vec<Ipv4Net>,
}

impl EgressCeiling {
    /// The ceiling of a compiled table: its drop sets (shared with the
    /// compiler) plus the node's addresses.
    pub fn new(inputs: &GuardInputs, node4: Vec<Ipv4Net>) -> Self {
        let [(_, protected4), (_, scope4), (_, deny4)] = inputs.drop_sets();
        Self {
            protected4: normalize(protected4.iter().copied()),
            scope4: normalize(scope4.iter().copied()),
            deny4: normalize(deny4.iter().copied()),
            node4: normalize(node4),
        }
    }

    /// Whether a sandbox may not reach `ip`. An empty `protected4` is not a
    /// ceiling (the compiler refuses one too): everything is refused.
    pub fn refuses(&self, ip: Ipv4Addr) -> bool {
        self.protected4.is_empty()
            || fib_special(ip)
            || [&self.protected4, &self.scope4, &self.deny4, &self.node4]
                .into_iter()
                .flatten()
                .any(|net| net.contains(ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(text: &str) -> Ipv4Net {
        Ipv4Net::parse_cidr(text).unwrap()
    }

    #[test]
    fn refuses_every_drop_set_node_addresses_and_fib_specials() {
        let inputs = GuardInputs {
            protected4: vec![net("10.0.0.0/8")],
            scope4: vec![net("203.0.114.0/24")],
            deny4: vec![net("198.51.100.0/24")],
            ..GuardInputs::default()
        };
        let ceiling = EgressCeiling::new(&inputs, vec![net("192.0.2.10/32")]);
        for refused in [
            "10.1.2.3",
            "203.0.114.9",
            "198.51.100.77",
            "192.0.2.10",
            "224.0.0.251",
            "255.255.255.255",
            "0.0.0.0",
        ] {
            assert!(ceiling.refuses(refused.parse().unwrap()), "{refused}");
        }
        assert!(!ceiling.refuses("1.1.1.1".parse().unwrap()));
        assert!(!ceiling.refuses("192.0.2.11".parse().unwrap()));
        // No protected set: not a ceiling, nothing is allowed.
        let empty = EgressCeiling::new(&GuardInputs::default(), vec![]);
        assert!(empty.refuses("1.1.1.1".parse().unwrap()));
    }
}
