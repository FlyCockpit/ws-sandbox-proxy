//! Protected IPv4 destinations, shared by the Incus DNS grant filter and the
//! daemon's CLI-logins credential proxy (upstream addresses are
//! resolved and checked with the same rules before any connect).

use std::net::Ipv4Addr;

/// A destination a guest must never reach through a DNS answer, even when an
/// allowlisted name is rebound to it, and that the credential proxy never
/// connects to: the sandbox protected set read from the shared contract
/// fixture (`sandboxProtectedV4`, via `crate::egress`), so a granted domain
/// answering the Azure wireserver or a tailnet address is filtered too.
/// Fails closed (protected) if the table is unavailable.
pub fn is_protected_guest_address(ip: Ipv4Addr) -> bool {
    crate::egress::is_protected_v4(ip)
}
