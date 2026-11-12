//! B12 blocked-name hints: which queried names count as refusals.
//!
//! The per-sandbox bridge `dnsmasq` (`incus/dns.rs`, C36) runs with
//! `no-resolv` and exact `host-record` answers, so every name outside the
//! sandbox's domain grants is refused. For TEMPLATE_BUILD sandboxes in
//! allowlist mode it forwards those names to the daemon's in-memory DNS stub
//! (`incus/dns_stub.rs`), which turns each queried name outside the granted
//! set into a refusal with `refused_query_name` and hands the pairs out
//! through `SandboxRuntime::drain_refused_dns_names`. The daemon validates,
//! deduplicates, bounds and rate-limits them before any frame.

use std::collections::BTreeSet;

/// A queried DNS name in hint form: lowercased, without a trailing dot, and
/// only when it is a valid hint DNS name.
pub fn hint_query_name(name: &str) -> Option<String> {
    let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    sandbox_protocol::valid_hint_dns_name(&name).then_some(name)
}

/// The build bridge's own DNS domain (Incus `dns.domain`, default `incus`).
/// The guest resolver appends it as a search suffix, so every lookup also
/// queries `<name>.incus`; the server drops those names too
/// (`packages/api/src/template-builds/hints.ts`, `internalDnsName`).
const BRIDGE_DNS_DOMAIN: &str = "incus";

fn bridge_domain_name(name: &str) -> bool {
    name == BRIDGE_DNS_DOMAIN
        || name
            .strip_suffix(BRIDGE_DNS_DOMAIN)
            .is_some_and(|rest| rest.ends_with('.'))
}

/// A name no egress grant can name: the grant grammar has no `_`, so service
/// lookups such as apt's `_http._tcp.archive.ubuntu.com` SRV query are never
/// something to "add to egress" (E3-A-05). The plain name's own lookup is.
fn ungrantable_name(name: &str) -> bool {
    name.contains('_')
}

/// A refusal: the queried name in hint form when it is not one of `granted`
/// (the sandbox policy's exact domain grants, lowercase), not a search-suffix
/// expansion under the bridge's own domain (E2-A-02), and grantable at all.
pub fn refused_query_name(name: &str, granted: &BTreeSet<String>) -> Option<String> {
    hint_query_name(name).filter(|name| {
        !granted.contains(name) && !bridge_domain_name(name) && !ungrantable_name(name)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_queried_names() {
        assert_eq!(hint_query_name("PyPI.org.").as_deref(), Some("pypi.org"));
        assert_eq!(
            hint_query_name("files.pythonhosted.org").as_deref(),
            Some("files.pythonhosted.org")
        );
        for name in ["", ".", "bad\u{7}name", "sp ace.example", "-x.example"] {
            assert_eq!(hint_query_name(name), None, "{name:?}");
        }
    }

    #[test]
    fn service_lookups_are_not_refusals() {
        let granted = BTreeSet::from(["archive.ubuntu.com".to_string()]);
        for name in [
            "_http._tcp.archive.ubuntu.com",
            "_https._tcp.esm.ubuntu.com",
            "_dmarc.example.org",
            "a_b.example",
        ] {
            assert_eq!(refused_query_name(name, &granted), None, "{name:?}");
        }
        assert_eq!(
            refused_query_name("esm.ubuntu.com", &granted).as_deref(),
            Some("esm.ubuntu.com")
        );
    }

    #[test]
    fn granted_names_are_not_refusals() {
        let granted = BTreeSet::from(["pypi.org".to_string()]);
        assert_eq!(refused_query_name("PyPI.org", &granted), None);
        assert_eq!(
            refused_query_name("evil.example", &granted).as_deref(),
            Some("evil.example")
        );
    }

    /// E2-A-02 at the source: the guest resolver's `.incus` search-suffix
    /// expansions reach the stub (the bridge dnsmasq forwards every name it
    /// does not answer), but they are never a name to grant, so they never
    /// take a slot in the bounded pending set or a report.
    #[test]
    fn bridge_domain_expansions_are_not_refusals() {
        let granted = BTreeSet::from(["archive.ubuntu.com".to_string()]);
        for name in ["archive.ubuntu.com.incus", "Evil.Example.INCUS.", "incus"] {
            assert_eq!(refused_query_name(name, &granted), None, "{name:?}");
        }
        assert_eq!(
            refused_query_name("incus.example", &granted).as_deref(),
            Some("incus.example")
        );
        assert_eq!(
            refused_query_name("notincus", &granted).as_deref(),
            Some("notincus")
        );
    }
}
