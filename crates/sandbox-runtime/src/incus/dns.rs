//! DNS-aware egress (C36): allowlisted domain grants are resolved through the
//! HOST resolver with full A/AAAA/CNAME validation, and guests receive answers
//! only for allowlisted names. The mechanism is the per-bridge `dnsmasq` that
//! Incus runs for every managed bridge network (verified against the running
//! daemon on the development host: no `--no-resolv`, so an unmanaged bridge
//! forwards arbitrary guest queries to the host's upstreams): the sandbox
//! bridge carries `raw.dnsmasq` with `no-resolv` plus exact-name `host-record`
//! lines for the validated addresses, so unlisted names are REFUSED and no
//! wildcard resolution exists. Direct external DNS/DoT from the guest stays
//! denied by the C35 ACL (only the bridge gateway's port 53 is reachable)
//! unless the policy separately grants that destination.
//!
//! Refresh ordering is fail-closed: the ACL destination set is REPLACED
//! (stale rules removed, then new rules added, then read back) BEFORE the new
//! answers are published to dnsmasq, so an answer never becomes usable before
//! its destination rule exists. Resolver failures keep only unexpired prior
//! grants (bounded staleness); empty answers (NXDOMAIN/NODATA) and rebound
//! protected addresses deny immediately. The published state is persisted
//! crash-durably (same journal conventions as C35) and drives reconnect
//! readback verification.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sandbox_protocol::{EgressPolicy, SandboxErrorCode};

use super::client::{IncusClient, host_cli_error};
use super::network::{
    AclRule, CompileLimits, MAX_GRANT_DESTINATIONS, MAX_GRANT_RECORDS, NETWORK_SANDBOX_TAG,
    SandboxNetworkPlan, parse_policy_cidr, sandbox_network_names, validate_policy_domain,
    verify_policy_presence_and_hash,
};
use crate::RuntimeError;

/// Refresh lifetime clamps (issue #17): answer-dependent grants live at least
/// 30s (churn floor) and at most 300s (staleness ceiling) regardless of the
/// upstream TTL.
pub(crate) const MIN_REFRESH_TTL_SECS: u32 = 30;
pub(crate) const MAX_REFRESH_TTL_SECS: u32 = 300;

pub(crate) fn clamp_ttl(ttl: u32) -> u32 {
    ttl.clamp(MIN_REFRESH_TTL_SECS, MAX_REFRESH_TTL_SECS)
}

/// The dnsmasq config every sandbox bridge is created with: no upstream
/// resolvers, so unlisted names are REFUSED from first boot. Identical to
/// rendering zero answers.
pub(crate) fn base_dnsmasq_config() -> String {
    render_dnsmasq_config(&[], MAX_REFRESH_TTL_SECS)
}

/// Render the per-bridge `raw.dnsmasq` content. Names and addresses are
/// validated upstream (`validate_policy_domain`, `Ipv4Addr` formatting), so
/// no config-directive injection is possible. `host-record` is exact-name
/// (unlike `address=`, it does NOT wildcard subdomains). Bounded by the
/// policy/destination bounds of the caller; refuse absurd sizes anyway.
///
/// A published name is also local to dnsmasq for that exact name only
/// (`local=/<name>/` plus `server=/*.<name>/#`), so its other record types
/// (AAAA on this IPv4-only bridge, HTTPS/SVCB, TXT, MX, ...) get NODATA
/// instead of REFUSED: with `no-resolv` dnsmasq refuses any query it cannot
/// answer locally, and musl `getaddrinfo` fails the whole lookup on a
/// refused AAAA. `#` sends subdomains to the default servers exactly like an
/// unlisted name (none: REFUSED; a build VM: the DNS stub), and a more
/// specific blocked `local=` still wins (NXDOMAIN). Only host-published
/// A records are ever served. Names inside Incus's own local bridge domain
/// (`--local=/incus/`) already answer NODATA and NXDOMAIN, so they get no
/// pair. DS is the one type outside this: dnsmasq routes a DS query by its
/// parent name, so a published name's DS stays REFUSED and the DS of its
/// direct child is a local NXDOMAIN; either way nothing is forwarded.
pub(crate) fn render_dnsmasq_config(
    answers: &[(String, Vec<Ipv4Addr>)],
    _lease_ttl: u32,
) -> String {
    let mut out = String::from(
        "# wssp managed sandbox DNS policy (C36): no upstream resolvers;\n\
         # only the exact host-published answers below are served.\n\
         no-resolv\n",
    );
    // Rotations withdraw old IPs at half-life. A cached answer must never
    // survive that withdrawal; serve policy records without a guest cache TTL.
    out.push_str("local-ttl=0\n");
    for (name, addresses) in answers {
        // The installed dnsmasq manual documents one IPv4 (and one IPv6)
        // address per host-record directive; multiple A addresses for a name
        // require REPEATED host-record directives, one per name/address pair.
        for addr in addresses {
            out.push_str("host-record=");
            out.push_str(name);
            out.push(',');
            out.push_str(&addr.to_string());
            out.push('\n');
        }
        if !addresses.is_empty() && !in_incus_bridge_domain(name) {
            out.push_str("local=/");
            out.push_str(name);
            out.push_str("/\nserver=/*.");
            out.push_str(name);
            out.push_str("/#\n");
        }
    }
    out
}

/// Incus's default `dns.domain`, which sandbox bridges keep: Incus starts
/// their dnsmasq with `--local=/incus/`.
const INCUS_BRIDGE_DNS_DOMAIN: &str = "incus";

fn in_incus_bridge_domain(name: &str) -> bool {
    name.strip_suffix(INCUS_BRIDGE_DNS_DOMAIN)
        .is_some_and(|rest| rest.is_empty() || rest.ends_with('.'))
}

pub(crate) use crate::protected::is_protected_guest_address;

/// `local=/<d>/` for every operator-blocked domain (§2.2, M19): dnsmasq
/// answers NXDOMAIN for the name and every subdomain without consulting any
/// upstream. Names are validated (`EgressSettings::validate`), so no
/// directive injection is possible.
fn push_blocked_locals(out: &mut String, settings: &crate::egress::EgressSettings) {
    for name in &settings.domain_blocklist.names {
        out.push_str("local=/");
        out.push_str(name);
        out.push_str("/\n");
    }
}

/// B12 (build VMs in allowlist mode only): forward every name the resolver
/// does not answer itself (no `host-record`, no blocked `local=`) to the
/// daemon's in-memory DNS stub on loopback (`incus/dns_stub.rs`). No `log-*`
/// option is ever rendered.
fn push_refused_stub(out: &mut String, settings: &crate::egress::EgressSettings) {
    if let Some(port) = settings.refused_dns_stub_port {
        out.push_str(&refused_stub_line(port));
    }
}

/// The resolver line forwarding to the DNS stub on `port`.
pub(crate) fn refused_stub_line(port: u16) -> String {
    format!("server=127.0.0.1#{port}\n")
}

pub(crate) fn check_dnsmasq_body(body: String) -> Result<String, RuntimeError> {
    if body.len() > crate::egress::MAX_DNSMASQ_BODY_BYTES {
        return Err(protocol_error(format!(
            "the rendered sandbox resolver config is {} bytes, above the {}-byte bound",
            body.len(),
            crate::egress::MAX_DNSMASQ_BODY_BYTES
        )));
    }
    Ok(body)
}

/// The open-mode guest resolver (§2.2). Without upstreams there is no
/// `no-resolv`, so the bridge dnsmasq forwards to the host's resolv.conf;
/// with them, it uses only the listed upstreams (m6, m13). Private answers
/// are dropped (`stop-dns-rebind`, `bogus-priv`). Never truncates: an
/// over-bound body is an error (the guard rejects such a blocklist first).
pub(crate) fn render_open_dnsmasq_config(
    settings: &crate::egress::EgressSettings,
) -> Result<String, RuntimeError> {
    settings.validate()?;
    let mut out = String::from(
        "# wssp managed sandbox DNS (open egress)\n\
         stop-dns-rebind\n\
         bogus-priv\n\
         domain-needed\n\
         no-hosts\n\
         dns-forward-max=64\n",
    );
    if !settings.dns_upstreams.is_empty() {
        out.push_str("no-resolv\n");
        for upstream in &settings.dns_upstreams {
            out.push_str("server=");
            out.push_str(&upstream.to_string());
            out.push('\n');
        }
    }
    push_blocked_locals(&mut out, settings);
    check_dnsmasq_body(out)
}

/// The allowlist-mode bridge resolver before any publication: the deny-all
/// base plus `local=/<d>/` per blocked domain (M19). Byte-identical to
/// `base_dnsmasq_config()` when nothing is blocked. `dns_upstreams` never
/// applies in allowlist mode (m13).
pub(crate) fn allowlist_dnsmasq_base(
    settings: &crate::egress::EgressSettings,
) -> Result<String, RuntimeError> {
    settings.validate()?;
    let mut out = base_dnsmasq_config();
    push_blocked_locals(&mut out, settings);
    push_refused_stub(&mut out, settings);
    check_dnsmasq_body(out)
}

/// The publication boundary for allowlist answers (§2.1, M19): renders the
/// host-records plus the recorded blocklist's `local=` lines, and refuses
/// (defence in depth) to publish any name the recorded settings deny.
/// Legacy records without settings render exactly as before.
pub(crate) fn render_published_dnsmasq_config(
    answers: &[(String, Vec<Ipv4Addr>)],
    lease_ttl: u32,
    settings: Option<&crate::egress::EgressSettings>,
) -> Result<String, RuntimeError> {
    let mut out = render_dnsmasq_config(answers, lease_ttl);
    if let Some(settings) = settings {
        if let Some((name, _)) = answers
            .iter()
            .find(|(name, _)| crate::egress::domain_denied(name, settings))
        {
            return Err(internal_error(format!(
                "refusing to publish `{name}`: the node's domain blocklist denies it"
            )));
        }
        push_blocked_locals(&mut out, settings);
        push_refused_stub(&mut out, settings);
    }
    check_dnsmasq_body(out)
}

fn error(code: SandboxErrorCode, message: impl Into<String>) -> RuntimeError {
    RuntimeError::new(code, message)
}

fn protocol_error(message: impl Into<String>) -> RuntimeError {
    error(SandboxErrorCode::ProtocolError, message)
}

fn internal_error(message: impl Into<String>) -> RuntimeError {
    error(SandboxErrorCode::Internal, message)
}

// ---------------------------------------------------------------------------
// Minimal DNS wire codec (no new dependencies). Strictly bounded and
// fail-closed: truncation, compression loops, id/question mismatches and
// malformed records are all hard errors, never partial answers.
// ---------------------------------------------------------------------------

const QTYPE_A: u16 = 1;
const QTYPE_CNAME: u16 = 5;
const QTYPE_AAAA: u16 = 28;
const QCLASS_IN: u16 = 1;
const MAX_MESSAGE_LEN: usize = 4096;
const MAX_ANSWERS: usize = 64;
const MAX_CNAME_CHAIN: usize = 8;
/// Compression pointers may only point backwards; this caps the walk.
const MAX_POINTER_JUMPS: usize = 16;

/// Build one standard (RD) query for `name`/`qtype`. The name is re-validated
/// here so a non-conforming name can never reach the wire.
pub(crate) fn build_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>, RuntimeError> {
    validate_policy_domain(name).map_err(|err| {
        protocol_error(format!(
            "egress DNS query name is not an exact DNS name: {err}"
        ))
    })?;
    let mut out = Vec::with_capacity(12 + name.len() + 6);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&QCLASS_IN.to_be_bytes());
    Ok(out)
}

/// Decode a (possibly compressed) DNS name at `pos`. Pointers must point
/// strictly backwards — a forward or self pointer is a loop and fails.
fn decode_name(buf: &[u8], pos: usize) -> Result<(String, usize), RuntimeError> {
    let malformed = || protocol_error("egress DNS answer carries a malformed name");
    let mut labels: Vec<String> = Vec::new();
    let mut offset = pos;
    let mut end: Option<usize> = None;
    let mut jumps = 0;
    loop {
        if offset >= buf.len() {
            return Err(malformed());
        }
        let len = buf[offset];
        if len & 0xc0 == 0xc0 {
            if offset + 1 >= buf.len() {
                return Err(malformed());
            }
            let target = (usize::from(len & 0x3f) << 8) | usize::from(buf[offset + 1]);
            if target >= offset {
                return Err(malformed());
            }
            if end.is_none() {
                end = Some(offset + 2);
            }
            offset = target;
            jumps += 1;
            if jumps > MAX_POINTER_JUMPS {
                return Err(malformed());
            }
            continue;
        }
        if len & 0xc0 != 0 {
            return Err(malformed());
        }
        offset += 1;
        if len == 0 {
            break;
        }
        let finish = offset + usize::from(len);
        if finish > buf.len() {
            return Err(malformed());
        }
        if !buf[offset..finish].iter().all(|b| b.is_ascii_graphic()) {
            return Err(malformed());
        }
        labels.push(
            std::str::from_utf8(&buf[offset..finish])
                .map_err(|_| malformed())?
                .to_ascii_lowercase(),
        );
        offset = finish;
        let total: usize = labels.iter().map(|l| l.len() + 1).sum();
        if total > 254 {
            return Err(malformed());
        }
    }
    Ok((labels.join("."), end.unwrap_or(offset)))
}

/// One parsed answer-section record. Owner names are lowercased.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DnsRecord {
    A {
        owner: String,
        addr: Ipv4Addr,
        ttl: u32,
    },
    Aaaa {
        #[allow(dead_code)] // parsed and validated, never installed (v4-only bridge)
        addr: Ipv6Addr,
        owner: String,
        ttl: u32,
    },
    Cname {
        owner: String,
        target: String,
        ttl: u32,
    },
}

#[derive(Debug)]
pub(crate) struct ParsedMessage {
    pub rcode: u8,
    pub answers: Vec<DnsRecord>,
}

/// Parse a response, requiring it to answer THIS query: transaction id,
/// single question with the expected qname/qtype, no truncation. Bailiwick:
/// records for unrelated owners are never acted on by the resolver walk
/// (the walk only consumes records owned by the queried name).
pub(crate) fn parse_response(
    buf: &[u8],
    expected_id: u16,
    expect_name: &str,
    expect_qtype: u16,
) -> Result<ParsedMessage, RuntimeError> {
    let malformed = || protocol_error("egress DNS answer is malformed");
    if buf.len() < 12 || buf.len() > MAX_MESSAGE_LEN {
        return Err(malformed());
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    if id != expected_id {
        return Err(protocol_error(
            "egress DNS answer does not match the query transaction id",
        ));
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags & 0x8000 == 0 || flags & 0x7800 != 0 {
        return Err(malformed());
    }
    if flags & 0x0200 != 0 {
        // Truncated answers are never acted on: fail closed.
        return Err(protocol_error("egress DNS answer is truncated"));
    }
    let rcode = (flags & 0x000f) as u8;
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    if qdcount != 1 || ancount > MAX_ANSWERS as u16 {
        return Err(malformed());
    }
    let mut offset = 12;
    let (qname, after) = decode_name(buf, offset)?;
    if !qname.eq_ignore_ascii_case(expect_name) {
        return Err(protocol_error(
            "egress DNS answer does not echo the queried name",
        ));
    }
    offset = after;
    if offset + 4 > buf.len() {
        return Err(malformed());
    }
    let qtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
    let qclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
    offset += 4;
    if qtype != expect_qtype || qclass != QCLASS_IN {
        return Err(protocol_error(
            "egress DNS answer does not echo the queried record type",
        ));
    }
    let mut answers = Vec::new();
    for _ in 0..ancount {
        let (owner, after) = decode_name(buf, offset)?;
        offset = after;
        if offset + 10 > buf.len() {
            return Err(malformed());
        }
        let rtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let rclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
        let ttl = u32::from_be_bytes([
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ]);
        let rdlen = usize::from(u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]));
        offset += 10;
        if offset + rdlen > buf.len() {
            return Err(malformed());
        }
        if rclass != QCLASS_IN {
            return Err(malformed());
        }
        let rdata = &buf[offset..offset + rdlen];
        match rtype {
            QTYPE_A => {
                if rdlen != 4 {
                    return Err(malformed());
                }
                answers.push(DnsRecord::A {
                    owner,
                    addr: Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]),
                    ttl,
                });
            }
            QTYPE_AAAA => {
                if rdlen != 16 {
                    return Err(malformed());
                }
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(rdata);
                answers.push(DnsRecord::Aaaa {
                    owner,
                    addr: Ipv6Addr::from(bytes),
                    ttl,
                });
            }
            QTYPE_CNAME => {
                let (target, end) = decode_name(buf, offset)?;
                // The encoded target must occupy exactly RDLENGTH bytes (a
                // compression pointer consumes its 2 bytes at `offset`), so
                // a short RDLENGTH can never bleed the next record's owner
                // into this target, nor an oversized one hide trailing junk.
                if end != offset + rdlen {
                    return Err(malformed());
                }
                answers.push(DnsRecord::Cname { owner, target, ttl });
            }
            _ => {}
        }
        offset += rdlen;
    }
    Ok(ParsedMessage { rcode, answers })
}

// ---------------------------------------------------------------------------
// Transport. Production sends one bounded UDP datagram per query to the
// host's own resolvers (read from /etc/resolv.conf); tests inject fakes.
// ---------------------------------------------------------------------------

/// One DNS round-trip to one server. Implementations must bound their wait.
pub trait DnsTransport: Send + Sync {
    fn query(&self, server: Ipv4Addr, message: &[u8]) -> std::io::Result<Vec<u8>>;
}

/// UDP transport to port 53 with a hard per-query timeout.
pub struct UdpDnsTransport {
    timeout: Duration,
}

impl UdpDnsTransport {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(3),
        }
    }
}

impl Default for UdpDnsTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsTransport for UdpDnsTransport {
    fn query(&self, server: Ipv4Addr, message: &[u8]) -> std::io::Result<Vec<u8>> {
        let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        socket.set_read_timeout(Some(self.timeout))?;
        socket.set_write_timeout(Some(self.timeout))?;
        socket.connect((server, 53))?;
        socket.send(message)?;
        let mut buf = [0u8; MAX_MESSAGE_LEN];
        let read = socket.recv(&mut buf)?;
        Ok(buf[..read].to_vec())
    }
}

/// Parse `nameserver` lines: IPv4 servers only (sandbox egress is v4-only),
/// capped at 3, junk lines skipped. An empty result is the caller's error —
/// never silently "no servers".
pub(crate) fn resolv_conf_servers(text: &str) -> Vec<Ipv4Addr> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            if fields.next() != Some("nameserver") {
                return None;
            }
            fields.next()?.parse::<Ipv4Addr>().ok()
        })
        .take(3)
        .collect()
}

/// The host's configured DNS servers (read-only /etc/resolv.conf).
pub fn host_dns_servers() -> Result<Vec<Ipv4Addr>, RuntimeError> {
    let text = std::fs::read_to_string("/etc/resolv.conf").map_err(|err| {
        internal_error(format!(
            "cannot read the host resolver configuration: {err}"
        ))
    })?;
    let servers = resolv_conf_servers(&text);
    if servers.is_empty() {
        return Err(internal_error(
            "the host resolver configuration names no IPv4 servers",
        ));
    }
    Ok(servers)
}

/// Why a name was denied: `Empty` (NXDOMAIN/NODATA, malformed or rebound
/// answers) denies immediately, even against a live prior grant;
/// `Transient` (transport/server failure) keeps only an UNEXPIRED prior
/// grant (bounded staleness), so expired grants are removed on resolver
/// failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DenyKind {
    Empty,
    Transient,
}

#[derive(Debug)]
pub(crate) struct ResolveDeny {
    pub kind: DenyKind,
    pub error: RuntimeError,
}

impl ResolveDeny {
    /// M19: a grant name the RECORDED domain blocklist denies is never
    /// resolved; it is denied exactly like an empty answer (no retention).
    fn blocked(domain: &str) -> Self {
        Self::empty(error(
            SandboxErrorCode::EgressResolutionFailed,
            format!("egress domain `{domain}` is blocked by this node's policy"),
        ))
    }
    fn empty(error: RuntimeError) -> Self {
        Self {
            kind: DenyKind::Empty,
            error,
        }
    }
    pub(crate) fn transient(error: RuntimeError) -> Self {
        Self {
            kind: DenyKind::Transient,
            error,
        }
    }
}

/// One validated resolution of an allowlisted name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DomainGrant {
    pub name: String,
    /// Validated public IPv4 answers, sorted and deduplicated.
    pub addresses: Vec<Ipv4Addr>,
    /// Clamped refresh lifetime (30..=300s).
    pub ttl: u32,
    /// UNIX seconds after which this grant must no longer be served: the
    /// minimum over every contributing answer (each CNAME hop and address
    /// record) of ANSWER-RECEIPT time + its clamped TTL — never
    /// planning-time `now + ttl`, which would hand the earliest answers the
    /// wall-clock budget consumed by later lookups (CNAME hops, AAAA
    /// parity, other domains).
    pub expires_at: u64,
}

fn query_servers(
    transport: &dyn DnsTransport,
    servers: &[Ipv4Addr],
    name: &str,
    qtype: u16,
    limits: &CompileLimits<'_>,
) -> Result<ParsedMessage, ResolveDeny> {
    let mut last = ResolveDeny::transient(internal_error(format!(
        "egress domain `{name}`: no DNS server answered"
    )));
    for server in servers.iter().take(3) {
        limits.check().map_err(ResolveDeny::transient)?;
        let id = {
            use ring::rand::SecureRandom;
            let mut bytes = [0u8; 2];
            ring::rand::SystemRandom::new()
                .fill(&mut bytes)
                .map_err(|_| {
                    ResolveDeny::transient(internal_error("cannot draw a DNS transaction id"))
                })?;
            u16::from_be_bytes(bytes)
        };
        let message = build_query(id, name, qtype).map_err(ResolveDeny::transient)?;
        match transport.query(*server, &message) {
            Ok(bytes) => match parse_response(&bytes, id, name, qtype) {
                Ok(parsed) => return Ok(parsed),
                // A malformed/mismatched answer is never retried on another
                // server: fail closed (immediate deny).
                Err(err) => return Err(ResolveDeny::empty(err)),
            },
            Err(err) => {
                last = ResolveDeny::transient(internal_error(format!(
                    "egress domain `{name}`: DNS server {server} did not answer: {err}"
                )));
            }
        }
    }
    Err(last)
}

/// Resolve one allowlisted name through the host resolver with full
/// A/AAAA/CNAME validation. CNAME chains are followed iteratively (≤ 8, cycle
/// detection); every CNAME target must itself be an exact DNS name, and every
/// A answer must be a public, installable address — a single rebound
/// protected address denies the whole name. AAAA answers are parsed and
/// validated (malformed records deny) but never installed: sandbox bridges
/// are IPv4-only. The returned TTL is the clamped minimum over the chain.
pub(crate) fn resolve_policy_name(
    transport: &dyn DnsTransport,
    servers: &[Ipv4Addr],
    name: &str,
    limits: &CompileLimits<'_>,
    clock: &dyn DnsClock,
) -> Result<DomainGrant, ResolveDeny> {
    let mut current = name.to_string();
    let mut visited: BTreeSet<String> = BTreeSet::new();
    let mut min_ttl = u32::MAX;
    // Answer-time expiry: every contributing record expires at ITS receipt
    // time + its clamped TTL, so time spent on later lookups (chain hops,
    // AAAA parity, other domains) never extends an early answer's grant.
    let mut min_expiry = u64::MAX;
    // True when the inline-hop walk already recorded `current` in `visited`
    // (the query loop must not insert it twice).
    let mut chain_recorded = false;
    let addresses = loop {
        if !std::mem::take(&mut chain_recorded)
            && (!visited.insert(current.clone()) || visited.len() > MAX_CNAME_CHAIN)
        {
            return Err(ResolveDeny::empty(protocol_error(format!(
                "egress domain `{name}` has a CNAME cycle or an overlong chain"
            ))));
        }
        let parsed = query_servers(transport, servers, &current, QTYPE_A, limits)?;
        let answered_at = clock.unix_now().map_err(ResolveDeny::transient)?;
        match parsed.rcode {
            0 => {}
            // NXDOMAIN: authoritative non-existence denies immediately.
            3 => {
                return Err(ResolveDeny::empty(internal_error(format!(
                    "egress domain `{name}` does not exist (NXDOMAIN at `{current}`)"
                ))));
            }
            other => {
                return Err(ResolveDeny::transient(internal_error(format!(
                    "egress domain `{name}` lookup failed with rcode {other}"
                ))));
            }
        }
        for record in &parsed.answers {
            if let DnsRecord::Cname { target, .. } = record {
                // Every CNAME target in the answer must be a well-formed
                // exact name, even ones the walk does not follow.
                validate_policy_domain(target).map_err(|_| {
                    ResolveDeny::empty(protocol_error(format!(
                        "egress domain `{name}` chains to a malformed CNAME target"
                    )))
                })?;
            }
        }
        // Follow EVERY reachable inline CNAME hop within this response
        // before re-querying: a response can carry a→b→c plus address
        // records owned by c, and every hop's addresses belong to the
        // reachable chain — stopping at the first target and re-querying
        // would let a public second answer launder a protected address
        // already observed here. Cycle, depth, address and TTL checks apply
        // at every hop.
        loop {
            // DISTINCT CNAME targets for one owner are conflicting data
            // (C36 r34 F3): selecting either branch would leave the other
            // branch's record set unvalidated — `a CNAME pub` beside
            // `a CNAME priv` beside `priv A 10.0.0.5` must not sail
            // through on the public branch. Identical duplicates are one
            // RRset and collapse (the tighter TTL wins).
            let mut cname: Option<(String, u32)> = None;
            for record in &parsed.answers {
                if let DnsRecord::Cname { owner, target, ttl } = record
                    && owner.eq_ignore_ascii_case(&current)
                {
                    match &mut cname {
                        None => cname = Some((target.clone(), *ttl)),
                        Some((first, seen)) if first.eq_ignore_ascii_case(target) => {
                            *seen = (*seen).min(*ttl);
                        }
                        Some(_) => {
                            return Err(ResolveDeny::empty(protocol_error(format!(
                                "egress domain `{name}` answers `{current}` with conflicting CNAME targets"
                            ))));
                        }
                    }
                }
            }
            let Some((target, ttl)) = cname else { break };
            // The CURRENT owner's complete record set is validated before
            // advancing (C36 r33 F3): an owner carrying BOTH a CNAME and
            // address records is conflicting data. The walk follows the
            // CNAME, so address records owned by the current hop would
            // otherwise never be examined — `a A 10.0.0.5` beside
            // `a CNAME b` would let a public answer for `b` launder the
            // protected address the answer already carried.
            if parsed.answers.iter().any(|record| {
                matches!(record, DnsRecord::A { owner, .. } if owner.eq_ignore_ascii_case(&current))
            }) {
                return Err(ResolveDeny::empty(protocol_error(format!(
                    "egress domain `{name}` answers `{current}` with both a CNAME and address records"
                ))));
            }
            min_ttl = min_ttl.min(ttl);
            min_expiry = min_expiry.min(answered_at + u64::from(clamp_ttl(ttl)));
            // Address records ALREADY PRESENT for the hop target belong to
            // the reachable answer chain: a protected inline address denies
            // the whole name immediately.
            for record in &parsed.answers {
                if let DnsRecord::A { owner, addr, .. } = record
                    && owner.eq_ignore_ascii_case(&target)
                    && is_protected_guest_address(*addr)
                {
                    return Err(ResolveDeny::empty(protocol_error(format!(
                        "egress domain `{name}` resolves to a protected address {addr}"
                    ))));
                }
            }
            if !visited.insert(target.clone()) || visited.len() > MAX_CNAME_CHAIN {
                return Err(ResolveDeny::empty(protocol_error(format!(
                    "egress domain `{name}` has a CNAME cycle or an overlong chain"
                ))));
            }
            current = target;
            chain_recorded = true;
        }
        if chain_recorded {
            continue;
        }
        let owned: Vec<(Ipv4Addr, u32)> = parsed
            .answers
            .iter()
            .filter_map(|record| match record {
                DnsRecord::A { owner, addr, ttl } if owner.eq_ignore_ascii_case(&current) => {
                    Some((*addr, *ttl))
                }
                _ => None,
            })
            .collect();
        if owned.is_empty() {
            // NODATA: the name exists but has no A answer.
            return Err(ResolveDeny::empty(internal_error(format!(
                "egress domain `{name}` has no IPv4 answer"
            ))));
        }
        let mut addrs = Vec::with_capacity(owned.len());
        for (addr, ttl) in owned {
            if is_protected_guest_address(addr) {
                return Err(ResolveDeny::empty(protocol_error(format!(
                    "egress domain `{name}` resolves to a protected address {addr}"
                ))));
            }
            min_ttl = min_ttl.min(ttl);
            min_expiry = min_expiry.min(answered_at + u64::from(clamp_ttl(ttl)));
            addrs.push(addr);
        }
        addrs.sort();
        addrs.dedup();
        break addrs;
    };
    // AAAA parity with the A walk: the v6 view of the terminal name is
    // validated with the SAME strictness. NODATA/NXDOMAIN are fine (a v4-only
    // name); malformed, mismatched or truncated AAAA responses deny exactly
    // like malformed A responses (no silent install of the A half); actual
    // AAAA DATA denies as UNSUPPORTED_CAPABILITY rather than silently
    // narrowing the grant to the v4 addresses.
    // A malformed/mismatched/truncated AAAA response propagates its denial
    // exactly like a malformed A response (no silent install of the A half).
    // The AAAA view is walked with the same bounded, cycle-detecting CNAME
    // following as the A walk: a chain endpoint carrying IPv6 DATA denies
    // the grant (UNSUPPORTED_CAPABILITY), not silently installs the v4 half.
    let mut v6_current = current.clone();
    let mut v6_visited: BTreeSet<String> = BTreeSet::new();
    // Same inline-hop recording as the A walk.
    let mut v6_chain_recorded = false;
    loop {
        if !std::mem::take(&mut v6_chain_recorded)
            && (!v6_visited.insert(v6_current.clone()) || v6_visited.len() > MAX_CNAME_CHAIN)
        {
            return Err(ResolveDeny::empty(protocol_error(format!(
                "egress domain `{name}` has a CNAME cycle or an overlong chain (AAAA view)"
            ))));
        }
        let parsed = query_servers(transport, servers, &v6_current, QTYPE_AAAA, limits)?;
        match parsed.rcode {
            0 => {}
            // NXDOMAIN: authoritative non-existence of the v6 view, fine.
            3 => break,
            other => {
                return Err(ResolveDeny::transient(internal_error(format!(
                    "egress domain `{name}` AAAA lookup failed with rcode {other}"
                ))));
            }
        }
        for record in &parsed.answers {
            if let DnsRecord::Cname { target, .. } = record {
                validate_policy_domain(target).map_err(|_| {
                    ResolveDeny::empty(protocol_error(format!(
                        "egress domain `{name}` chains (AAAA) to a malformed CNAME target"
                    )))
                })?;
            }
        }
        // Same chain rule as the A walk: EVERY reachable inline CNAME hop is
        // followed within this response, and inline AAAA answers for every
        // hop target are validated, before the chain is re-queried.
        loop {
            // The same distinct-target rejection as the A walk (C36 r34
            // F3), independently of query type.
            let mut cname: Option<String> = None;
            for record in &parsed.answers {
                if let DnsRecord::Cname { owner, target, .. } = record
                    && owner.eq_ignore_ascii_case(&v6_current)
                {
                    match &cname {
                        None => cname = Some(target.clone()),
                        Some(first) if first.eq_ignore_ascii_case(target) => {}
                        Some(_) => {
                            return Err(ResolveDeny::empty(protocol_error(format!(
                                "egress domain `{name}` answers `{v6_current}` with conflicting CNAME targets (AAAA view)"
                            ))));
                        }
                    }
                }
            }
            let Some(target) = cname else { break };
            // The same current-owner conflict check as the A walk (C36
            // r33 F3): a hop owner carrying BOTH a CNAME and AAAA records
            // is conflicting data — the walk follows the CNAME and the
            // current owner's IPv6 data would otherwise go unexamined.
            if parsed.answers.iter().any(|record| {
                matches!(record, DnsRecord::Aaaa { owner, .. } if owner.eq_ignore_ascii_case(&v6_current))
            }) {
                return Err(ResolveDeny::empty(protocol_error(format!(
                    "egress domain `{name}` answers `{v6_current}` with both a CNAME and IPv6 records"
                ))));
            }
            if parsed.answers.iter().any(|record| {
                matches!(
                    record,
                    DnsRecord::Aaaa { owner, .. } if owner.eq_ignore_ascii_case(&target)
                )
            }) {
                return Err(ResolveDeny::empty(error(
                    SandboxErrorCode::UnsupportedCapability,
                    format!(
                        "egress domain `{name}` resolves with IPv6 answers; sandbox egress is IPv4-only"
                    ),
                )));
            }
            if !v6_visited.insert(target.clone()) || v6_visited.len() > MAX_CNAME_CHAIN {
                return Err(ResolveDeny::empty(protocol_error(format!(
                    "egress domain `{name}` has a CNAME cycle or an overlong chain (AAAA view)"
                ))));
            }
            v6_current = target;
            v6_chain_recorded = true;
        }
        if v6_chain_recorded {
            continue;
        }
        if parsed.answers.iter().any(|record| {
            matches!(
                record,
                DnsRecord::Aaaa { owner, .. } if owner.eq_ignore_ascii_case(&v6_current)
            )
        }) {
            return Err(ResolveDeny::empty(error(
                SandboxErrorCode::UnsupportedCapability,
                format!(
                    "egress domain `{name}` resolves with IPv6 answers; sandbox egress is IPv4-only"
                ),
            )));
        }
        // NODATA at the chain end: a v4-only name.
        break;
    }
    Ok(DomainGrant {
        name: name.to_string(),
        addresses,
        ttl: clamp_ttl(min_ttl),
        expires_at: min_expiry,
    })
}

/// Resolve one allowlisted name for the PRODUCTION refresh scheduler through
/// the SAME host system resolver (the bounded `getaddrinfo` pool) and the SAME
/// acceptance rules as create/cold-boot compilation (`compile_network_plan`):
/// IPv6 answers contribute nothing (the bridge is IPv4-only), a name with no
/// IPv4 answer or with ANY protected address denies immediately (`Empty`).
/// A lookup that fails or times out is `Transient`: planning keeps only an
/// unexpired prior grant with at least the churn floor left, and NEVER
/// extends it. `getaddrinfo` carries no TTL, so a fresh answer is granted for
/// the upper clamp from its answer time, exactly like the initial publish.
pub(crate) fn resolve_policy_name_system(
    client: &IncusClient,
    sandbox_id: &str,
    name: &str,
    limits: &CompileLimits<'_>,
) -> Result<DomainGrant, ResolveDeny> {
    limits.check().map_err(ResolveDeny::transient)?;
    let wait = super::network::PER_LOOKUP_BUDGET
        .min(limits.deadline.saturating_duration_since(Instant::now()));
    let resolved = client
        .resolve_domain(sandbox_id, name, wait)
        .map_err(ResolveDeny::transient)?;
    limits.check().map_err(ResolveDeny::transient)?;
    let answered_at = client
        .dns_clock
        .unix_now()
        .map_err(ResolveDeny::transient)?;
    let mut addresses: Vec<Ipv4Addr> = resolved
        .iter()
        .filter_map(|ip| match ip {
            std::net::IpAddr::V4(addr) => Some(*addr),
            std::net::IpAddr::V6(_) => None,
        })
        .collect();
    addresses.sort();
    addresses.dedup();
    if addresses.is_empty() {
        return Err(ResolveDeny::empty(error(
            SandboxErrorCode::UnsupportedCapability,
            format!("egress domain `{name}` resolves without any enforceable IPv4 address"),
        )));
    }
    if let Some(addr) = addresses
        .iter()
        .find(|addr| is_protected_guest_address(**addr))
    {
        return Err(ResolveDeny::empty(protocol_error(format!(
            "egress domain `{name}` resolves to a protected address {addr}"
        ))));
    }
    Ok(DomainGrant {
        name: name.to_string(),
        addresses,
        ttl: MAX_REFRESH_TTL_SECS,
        expires_at: answered_at + u64::from(MAX_REFRESH_TTL_SECS),
    })
}

// ---------------------------------------------------------------------------
// Refresh planning (pure) and persisted per-sandbox state.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct DnsGrantEntry {
    pub name: String,
    pub addresses: Vec<String>,
    /// Clamped refresh lifetime. The churn floor applies only to grants
    /// that ever HAD a window beyond it (`ttl > MIN`): floor-clamped short
    /// TTLs stay installable until their absolute expiry — otherwise every
    /// TTL <= 30s answer would be denied at its first rule addition (C36
    /// r14). A zero lifetime provides no safe publication window.
    pub ttl: u32,
    /// UNIX seconds after which this grant must no longer be served.
    pub expires_at: u64,
    /// Allow-rule generation (C36 r16): a re-grant after ANY revocation
    /// advances it, so the rule tag identifies THIS grant's mutation
    /// request-specifically — a stale daemon-side apply of an earlier
    /// uncertain mutation carries the OLD generation and can never pass
    /// for the current grant's rule. Zero identifies the initial compiled rule.
    pub generation: u64,
}

/// Private per-sandbox policy state, persisted crash-durably under the host
/// state dir. `published` is the exact `raw.dnsmasq` body last written, so
/// reconnect readback compares against what the host ACTUALLY published.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct SandboxDnsState {
    pub sandbox_id: String,
    pub policy_hash: String,
    pub grants: Vec<DnsGrantEntry>,
    pub published: String,
    /// Last allow-rule generation used per name (C36 r16): monotonic even
    /// across revocations, so a re-grant never reuses a generation an
    /// earlier uncertain mutation may still be carrying daemon-side.
    pub generations: std::collections::BTreeMap<String, u64>,
}

/// Durable revocation marker, written BEFORE a refresh mutates anything:
/// the policy names that refresh DENIED. If publication or persistence then
/// fails, the OLD dns-policy state survives, and without this marker a later
/// TRANSIENT lookup failure would retain — and reinstall — a just-denied
/// grant without any new successful resolution, undoing the denial. Cleared
/// once the refreshed state is durably persisted.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DnsRevocationRecord {
    sandbox_id: String,
    policy_hash: String,
    /// The owning project (C36 r32 F2): durable DNS records live under a
    /// state root that multiple project-scoped daemons may share, so the
    /// marker carries its project and every read refuses a foreign one
    /// (fail closed) rather than letting one project's daemon mutate
    /// another's revocation truth. A persisted record requires a project.
    #[serde(deserialize_with = "required_dns_project")]
    project: Option<String>,
    revoked: Vec<String>,
    /// The generations each revoked name denies (C36 r31 F2, r32 F1):
    /// EVERY request identity outstanding when the denial was journaled
    /// — the committed generation AND any armed-but-uncommitted identity
    /// (a re-grant that installed and published, then failed before its
    /// commit, leaving the durable state one generation behind). A
    /// generation NOT in the set was issued AFTER the denial and is
    /// never enforced against by the autonomous boundary — it belongs
    /// to the committing refresh. A name absent from the map remains
    /// denied regardless of generation: fail closed.
    revoked_generations: std::collections::BTreeMap<String, BTreeSet<u64>>,
    /// Broadening mutations whose daemon-side application cannot be ruled
    /// out (C36 r14, r17): fenced until a LATER refresh reconciles on
    /// definitive evidence.
    pending: Vec<PendingMutation>,
    /// Durable monotonic request counter (C36 r17 F1/F4): every broadening
    /// mutation's identity — an allow rule's generation or a fence's epoch —
    /// is allocated from HERE and persisted BEFORE the mutation is issued,
    /// so a retry after an interruption can never reuse an identity an
    /// in-flight request may still be carrying daemon-side. Once the marker
    /// clears, allocations are floored by the committed state's generation
    /// history and the observed rules' identities.
    next_request: u64,
    /// Destinations under a STANDING fence obligation (C36 r22 F2, r23
    /// F2): an unresolved allow mutation whose ACL incarnation is gone
    /// can never be reconciled by observation — the request may still be
    /// applied daemon-side against a FUTURE same-named ACL. The
    /// destination stays fenced by every plan until the policy
    /// authorizes it again (the fence release is journaled like any
    /// other), so a late deferred apply can only ever land behind the
    /// fence. The marker itself survives teardown and ACL name reuse
    /// precisely to carry these. Authorization SUPPRESSES the fence; it
    /// never retires the obligation (C36 r23 F2): the original request
    /// identity is preserved, and the obligation retires only on
    /// positive withdrawal evidence for THAT identity — so when a
    /// temporary reauthorization expires, the destination is fenced
    /// again and the long-deferred apply still lands behind the fence.
    standing_fences: Vec<StandingFence>,
    /// A managed DNS refresh began mutating live enforcement and has not
    /// committed (C58 NEW-1). Set durably BEFORE the refresh's first
    /// mutation, cleared only by its commit. While set, the live ACL and
    /// publication may legitimately differ from the persisted plan in the
    /// directions the refresh's own journaled work explains (withdrawn or
    /// fenced grants, lease-armed issuances). That is a refresh OWED, never
    /// drift: readiness refuses it as inconclusive and a later refresh
    /// retries the commit.
    refresh_owed: bool,
    /// SHA-256 digests (hex) of the `raw.dnsmasq` bodies an uncommitted
    /// refresh attempted to publish, recorded BEFORE each PATCH (C58
    /// NEW-1): a publication that landed before its commit failed reads
    /// back as one of these, never as unexplained drift. Bounded; cleared
    /// with `refresh_owed`.
    published_attempts: Vec<String>,
}

/// Bound on the recorded uncommitted publication digests (C58 NEW-1). The
/// newest attempt is always retained; older ones roll off.
const MAX_DNS_PUBLICATION_ATTEMPTS: usize = 16;

/// One standing fence obligation with its exact mutation identity.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
enum StandingFence {
    Full {
        destination: String,
        description: String,
    },
}

impl StandingFence {
    fn destination(&self) -> &str {
        match self {
            StandingFence::Full { destination, .. } => destination,
        }
    }
    fn description(&self) -> &str {
        match self {
            StandingFence::Full { description, .. } => description,
        }
    }
}

fn required_dns_project<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    let project = <String as serde::Deserialize>::deserialize(deserializer)?;
    if project.is_empty() {
        return Err(serde::de::Error::custom("DNS record project is required"));
    }
    Ok(Some(project))
}

/// Which broadening mutation a pending journal entry tracks (C36 r17 F4:
/// mutations are classified by their PERMISSION EFFECT, not add-vs-remove).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
enum PendingKind {
    /// An allow rule ADD whose daemon-side application is unproven.
    #[default]
    Allow,
    /// A fence (destination-wide reject) REMOVAL whose daemon-side
    /// application is unproven: the targeted fence is unreliable — a
    /// still-needed fence is re-issued under a FRESH epoch — and the entry
    /// retires only once the rule is observed absent (a deferred re-removal
    /// of an absent rule is a no-op).
    FenceRelease,
}

/// The outcome of one journaled fence-release attempt through the shared
/// safety boundary (C36 r32 F3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FenceReleaseAttempt {
    /// The old fence was positively withdrawn (retire-eligible once
    /// re-observed absent).
    Withdrawn,
    /// Proven absence: the fence is already gone — the goal state.
    Absent,
    /// Not releasable now: unauthorized with a failed or unverified
    /// replacement fence, an unproven removal, or an exhausted deadline.
    /// The old fence stays installed; the entry stays journaled.
    Pending,
}

/// The release boundary's full result (C36 r34 F1): the attempt outcome
/// AND the verified replacement fence installed before it, if any. The
/// commit-time drain must fold BOTH directions into the commit's
/// expected snapshot — a released identity vanishes, an installed
/// replacement appears, and the persisted plan is wrong without each.
struct FenceReleaseOutcome {
    attempt: FenceReleaseAttempt,
    replacement: Option<super::network::AclRule>,
}

impl FenceReleaseOutcome {
    fn pending() -> Self {
        Self {
            attempt: FenceReleaseAttempt::Pending,
            replacement: None,
        }
    }
}

/// The commit-time drain's explicit result (C36 r33 F2, C36 r34 F1):
/// `released` names the journaled fence releases PROVEN this drain
/// (withdrawn or proven-absent) and `added` the verified replacement
/// fences the boundary INSTALLED for unauthorized releases — those
/// rules legitimately vanished / appeared between the pass's
/// post-replacement observation and the commit's live re-read, so the
/// commit folds both directions into its expected snapshot instead of
/// rejecting the disappearance as unexplained rule loss or persisting
/// a plan that omits a live fence — and `drained` reports whether
/// NOTHING stays journaled (only then may the revocation marker clear).
#[derive(Debug, Default)]
pub(crate) struct DrainOutcome {
    pub(crate) drained: bool,
    // Module-private: only the refresh commit path (same module) folds
    // the proven releases and verified additions into its expected
    // snapshot.
    released: Vec<PendingMutation>,
    added: Vec<AclRule>,
}

/// An uncertain broadening mutation awaiting reconciliation. The daemon may
/// apply it after the CLI died; `destination` is the rule destination
/// (`<addr>/32`) and `description` its request-specific dynamic rule tag.
/// For `Allow` entries `name` is the policy domain; for `FenceRelease`
/// entries it is the fenced address (validation is kind-aware).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct PendingMutation {
    name: String,
    destination: String,
    description: String,
    kind: PendingKind,
}

/// What one enforcement pass installed and fenced: the complete rule set
/// AS INSTALLED (observed order), the domains revoked mid-pass, and the
/// uncertain allow mutations pending reconciliation.
struct ReplacementOutcome {
    installed: Vec<AclRule>,
    revoked: Vec<String>,
    uncertain: Vec<PendingMutation>,
    /// Names whose planned allow is a NEW issuance (absent at observation
    /// or withdrawn by the reject-repair pre-pass) carrying an identity
    /// that history or withdrawal evidence has already seen (C36 r20 F2):
    /// the caller allocates fresh generations and re-plans. Nothing else
    /// in the outcome is meaningful when this is non-empty.
    reissue: Vec<String>,
}

/// Everything the refresh loop and its failure-path cleanup need to
/// re-enforce or withdraw the planned rule set.
struct EnforcementContext<'a> {
    sandbox_id: &'a str,
    acl_name: &'a str,
    hash: &'a str,
    static_texts: &'a BTreeSet<String>,
    static_grants: &'a [super::network::GrantCidr],
    recorded_rules: Option<&'a [AclRule]>,
}

/// What an OWED DNS refresh or settlement (C58 NEW-1, SEED-1) durably
/// explains about the live enforcement state: the readback classifies a
/// divergence it fully accounts for as owed work (inconclusive), and
/// anything else as drift.
#[derive(Debug)]
pub(crate) struct DnsOwedEvidence {
    /// `(allow tag, destination)` identities armed in the durable expiry
    /// ledger. The ledger is persisted BEFORE any allow is issued
    /// (`replace_dns_acl_rules` arms first), so every allow this host
    /// issued — committed or not — is recorded here until it settles.
    pub(crate) armed: BTreeSet<(String, String)>,
    /// The uncommitted denials (G1-R1-2): per revoked name, its 32-bit
    /// rule-tag hash and the denied generations (`None` = every
    /// generation, a marker written before generations were recorded).
    /// Same identity precision as `revoked_due_dns_lease_pairs`.
    pub(crate) denied: Vec<(String, Option<BTreeSet<u64>>)>,
    /// Digests of uncommitted `raw.dnsmasq` publication attempts.
    pub(crate) published_attempts: BTreeSet<String>,
    /// A COMMIT is owed (`refresh_owed` or uncommitted revocations, or an
    /// unresolved fence release): the sandbox is owed regardless of what
    /// the live ACL shows. When false, the evidence exists only because
    /// of journaled uncertain ALLOW requests (C58 G1-R3-2), and the
    /// sandbox is owed only while one of them is LIVE.
    pub(crate) commit_owed: bool,
    /// `(description, destination)` of journaled uncertain ALLOW requests
    /// (pending journal). Host-issued, so explained when live; live ones
    /// make the sandbox owed until a refresh withdraws them.
    pub(crate) pending_allows: BTreeSet<(String, String)>,
    /// The inconclusive refusal's message.
    pub(crate) reason: String,
}

impl DnsOwedEvidence {
    /// Whether a DNS allow tag names an identity an uncommitted refresh
    /// DENIED (G1-R1-2). A generation issued after the denial is a fresh
    /// re-grant the committing refresh owns, never the denied identity.
    pub(crate) fn is_denied_identity(&self, allow_tag: &str) -> bool {
        let Some(rest) = allow_tag.strip_prefix("wssp-dns-") else {
            return false;
        };
        let hex = rest
            .strip_prefix('g')
            .and_then(|tail| tail.split_once('-'))
            .map(|(_, hex)| hex)
            .unwrap_or(rest);
        let generation = super::network::dns_tag_request_id(allow_tag);
        self.denied.iter().any(|(name_hex, generations)| {
            name_hex == hex
                && generations.as_ref().is_none_or(|denied| {
                    generation.is_none_or(|generation| denied.contains(&generation))
                })
        })
    }
}

/// What the revocation marker says for this refresh.
enum DnsRevocations {
    /// No marker file.
    None,
    /// These names were revoked; never retain their old grants.
    Set(BTreeSet<String>),
    /// Undecodable or mismatched marker: retain NOTHING (fail closed).
    Malformed,
}

/// The outcome of planning one refresh: the full desired destination set and
/// the exact answers/state to publish.
pub(crate) struct RefreshPlan {
    /// Static policy CIDRs plus every live resolved /32, sorted and deduped.
    pub destinations: Vec<String>,
    /// Live allowlist answers (name → addresses), sorted by name.
    pub answers: Vec<(String, Vec<Ipv4Addr>)>,
    /// Names denied this refresh, with the reason (operator diagnostics).
    pub denied: Vec<(String, String)>,
    /// Seconds until the next host refresh; guest records always have TTL zero.
    pub refresh_after: u32,
    pub state: SandboxDnsState,
}

/// Plan one refresh. Fail-closed rules:
/// - `Empty` outcomes (NXDOMAIN/NODATA/malformed/rebound) deny immediately,
///   dropping even an unexpired prior grant.
/// - `Transient` outcomes keep a prior grant only while it has at least
///   MIN_REFRESH_TTL_SECS left; expired (or expiring within the churn floor)
///   grants are removed.
/// - The destination set is bounded; exceeding it fails the whole refresh
///   (nothing is applied) rather than truncating the policy.
pub(crate) fn plan_refresh(
    sandbox_id: &str,
    policy: &EgressPolicy,
    hash: &str,
    prior: Option<&SandboxDnsState>,
    outcomes: Vec<Result<DomainGrant, ResolveDeny>>,
    now_unix: u64,
) -> Result<RefreshPlan, RuntimeError> {
    let mut destinations: Vec<String> = Vec::new();
    for raw in &policy.cidrs {
        destinations.push(parse_policy_cidr(raw)?.text);
    }
    let mut entries: Vec<DnsGrantEntry> = Vec::new();
    let mut denied: Vec<(String, String)> = Vec::new();
    for (domain, outcome) in policy.domains.iter().zip(outcomes) {
        match outcome {
            Ok(grant) => {
                let addresses: Vec<String> =
                    grant.addresses.iter().map(Ipv4Addr::to_string).collect();
                let prior_entry =
                    prior.and_then(|state| state.grants.iter().find(|entry| &entry.name == domain));
                let generation = match prior_entry {
                    // Unchanged grant: keep the generation (no rule churn).
                    Some(entry) if entry.addresses == addresses => entry.generation,
                    // Fresh or changed grant: identity placeholder — the
                    // refresh loop allocates a durable, request-unique
                    // generation BEFORE issuance (C36 r17 F1) for EVERY
                    // such name, brand-new ones included (C36 r26 F1).
                    _ => 0,
                };
                entries.push(DnsGrantEntry {
                    name: domain.clone(),
                    addresses,
                    ttl: grant.ttl,
                    // ANSWER-TIME expiry: never now + ttl, which would
                    // re-extend the earliest answers by the resolution
                    // budget later lookups consumed.
                    expires_at: grant.expires_at,
                    generation,
                });
            }
            Err(deny) => {
                let kept = match deny.kind {
                    DenyKind::Empty => None,
                    DenyKind::Transient => prior.and_then(|state| {
                        state
                            .grants
                            .iter()
                            .find(|entry| &entry.name == domain)
                            .filter(|entry| {
                                entry.expires_at >= now_unix + u64::from(MIN_REFRESH_TTL_SECS)
                            })
                            .cloned()
                    }),
                };
                match kept {
                    Some(entry) => entries.push(entry),
                    None => denied.push((domain.clone(), deny.error.to_string())),
                }
            }
        }
    }
    let mut answers: Vec<(String, Vec<Ipv4Addr>)> = Vec::new();
    for entry in &entries {
        let mut addrs = Vec::with_capacity(entry.addresses.len());
        for text in &entry.addresses {
            let addr: Ipv4Addr = text
                .parse()
                .map_err(|_| internal_error("planned DNS grant is not an IPv4 address"))?;
            addrs.push(addr);
            destinations.push(format!("{addr}/32"));
        }
        answers.push((entry.name.clone(), addrs));
    }
    destinations.sort();
    destinations.dedup();
    let records: usize = entries.iter().map(|entry| entry.addresses.len()).sum();
    if destinations.len() > MAX_GRANT_DESTINATIONS || records > MAX_GRANT_RECORDS {
        // Over-bound resolution must never abort with the previous ACL left
        // installed: a co-occurring NXDOMAIN/rebound/expiry would be stranded
        // forever. Plan a bounded fail-closed state instead: EVERY dynamic
        // grant revoked (deny-all beyond the static CIDRs), every name
        // reported denied, retry at the churn floor. Static CIDRs alone can
        // never exceed the bounds (policy validation caps them). The records
        // bound matches persisted-state loading exactly, so a committed state
        // is never discarded as invalid on the next transient failure.
        return revoke_all_plan(
            sandbox_id,
            policy,
            hash,
            prior
                .map(|state| state.generations.clone())
                .unwrap_or_default(),
        );
    }
    answers.sort_by(|a, b| a.0.cmp(&b.0));
    // Every entry kept above has >= MIN lifetime, so the minimum remaining
    // lifetime is already inside the clamp window; absent answers refresh at
    // the floor (retry soon, deny in the meantime).
    let refresh_after = entries
        .iter()
        .map(|entry| entry.expires_at.saturating_sub(now_unix))
        .min()
        .unwrap_or(u64::from(MIN_REFRESH_TTL_SECS))
        .clamp(
            u64::from(MIN_REFRESH_TTL_SECS),
            u64::from(MAX_REFRESH_TTL_SECS),
        ) as u32;
    let published = render_dnsmasq_config(&answers, refresh_after);
    // Generations accumulate monotonically, surviving revocations.
    let mut generations = prior
        .map(|state| state.generations.clone())
        .unwrap_or_default();
    for entry in &entries {
        generations
            .entry(entry.name.clone())
            .and_modify(|last| *last = (*last).max(entry.generation))
            .or_insert(entry.generation);
    }
    Ok(RefreshPlan {
        destinations,
        answers,
        denied,
        refresh_after,
        state: SandboxDnsState {
            sandbox_id: sandbox_id.to_string(),
            policy_hash: hash.to_string(),
            grants: entries,
            published,
            generations,
        },
    })
}

/// The bounded fail-closed plan for an over-bound resolution: EVERY dynamic
/// grant revoked (deny-all beyond the static CIDRs), every allowlisted name
/// reported denied, retry at the churn floor.
fn revoke_all_plan(
    sandbox_id: &str,
    policy: &EgressPolicy,
    hash: &str,
    generations: std::collections::BTreeMap<String, u64>,
) -> Result<RefreshPlan, RuntimeError> {
    let mut revoked: Vec<String> = Vec::new();
    for raw in &policy.cidrs {
        revoked.push(parse_policy_cidr(raw)?.text);
    }
    let denied_all = policy
        .domains
        .iter()
        .map(|domain| {
            (
                domain.clone(),
                "resolution exceeds the host destination bound; all DNS grants revoked".to_string(),
            )
        })
        .collect();
    let published = render_dnsmasq_config(&[], MIN_REFRESH_TTL_SECS);
    Ok(RefreshPlan {
        destinations: revoked,
        answers: Vec::new(),
        denied: denied_all,
        refresh_after: MIN_REFRESH_TTL_SECS,
        state: SandboxDnsState {
            sandbox_id: sandbox_id.to_string(),
            policy_hash: hash.to_string(),
            grants: Vec::new(),
            published,
            generations,
        },
    })
}

// ---------------------------------------------------------------------------
// Host-side state and the Incus-driving refresh.
// ---------------------------------------------------------------------------

impl IncusClient {
    pub(crate) fn dns_state_dir(&self) -> PathBuf {
        self.state_root().join("dns-policy")
    }

    pub(crate) fn dns_state_path(&self, sandbox_id: &str) -> PathBuf {
        self.dns_state_dir().join(format!("{sandbox_id}.json"))
    }

    /// Whether a DNS publication state exists (it then owns `raw.dnsmasq`).
    /// An unstatable path is unavailable evidence, never "absent".
    pub(crate) fn dns_state_exists(&self, sandbox_id: &str) -> Result<bool, RuntimeError> {
        match std::fs::symlink_metadata(self.dns_state_path(sandbox_id)) {
            Ok(_) => Ok(true),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(internal_error(format!(
                "cannot stat the DNS publication state for `{sandbox_id}`: {err}"
            ))),
        }
    }

    /// THE refresh-side half of the serialized lifecycle commit boundary
    /// (C36 r20 F3): DNS state and the recorded plan are written together
    /// under the per-sandbox commit lock (shared with the lease-settlement
    /// rewrite), merged against the CURRENT durable record — generation
    /// history is monotone and per-sandbox (max-merged from whatever is
    /// durably committed, regardless of policy hash), and every committed
    /// issuance is recorded in the history so it can never be re-issued
    /// (C36 r20 F2). A settlement that committed first is therefore never
    /// clobbered, and a refresh that commits first is re-derived over by
    /// the settlement under the same lock.
    fn commit_refresh_dns_records(
        &self,
        sandbox_id: &str,
        hash: &str,
        plan: &RefreshPlan,
        installed: &[AclRule],
        drain_released: &[PendingMutation],
        drain_added: &[AclRule],
    ) -> Result<(), RuntimeError> {
        // Test hook (C36 r21 F6): hold the refresh commit BEFORE the
        // commit lock is taken, so a settlement can complete end-to-end
        // while this refresh is parked — the refresh then commits its
        // stale snapshot as the LAST writer, and only the live-ACL
        // revalidation below keeps the settled grant from resurrecting.
        #[cfg(test)]
        if let Some(barrier) = &self.dns_commit_pre_lock_barrier {
            barrier.wait();
            barrier.wait();
        }
        let owner = self.dns_lease_owner(sandbox_id);
        let _commit = loop {
            self.check_dns_refresh_cancelled()?;
            match owner.commit.try_lock() {
                Ok(guard) => break guard,
                Err(std::sync::TryLockError::Poisoned(err)) => break err.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        };
        let mut state = plan.state.clone();
        if let Ok(body) = std::fs::read_to_string(self.dns_state_path(sandbox_id))
            && let Ok(current) = serde_json::from_str::<SandboxDnsState>(&body)
            && current.sandbox_id == sandbox_id
        {
            for (name, generation) in current.generations {
                state
                    .generations
                    .entry(name)
                    .and_modify(|floor| *floor = (*floor).max(generation))
                    .or_insert(generation);
            }
        }
        // Record every committed issuance — first grants included (C36 r20
        // F2): an identity that was never durably issued can never be
        // revived by stale withdrawal evidence, so history must name
        // everything that was.
        for grant in &state.grants {
            state
                .generations
                .entry(grant.name.clone())
                .and_modify(|floor| *floor = (*floor).max(grant.generation))
                .or_insert(grant.generation);
        }
        // Re-validate the snapshot against the LIVE ACL under the commit
        // lock before persisting (C36 r21 F6). The lock serializes this
        // commit against the settlement's rewrite, but a settlement's ACL
        // mutations run under the owner lock FIRST: a grant that expired
        // while this refresh was in flight has already been withdrawn
        // from the live ACL (its record rewrite is what queues behind
        // this lock). Persisting the refresh's earlier snapshot would
        // resurrect the settled grant in the durable records while the
        // live ACL no longer contains it — readiness would then compare
        // against a stale plan. The fresh read here is authoritative:
        // rules no longer live were settled (or never verifiably
        // installed) and are dropped from BOTH durable records; a grant
        // whose addresses are all static-CIDR-covered has no rules to
        // check and stays.
        let acl_name = sandbox_network_names(sandbox_id).1;
        let observed = self
            .read_sandbox_acl(&acl_name)?
            .ok_or_else(|| error(SandboxErrorCode::SandboxNotFound, "sandbox ACL is absent"))?;
        // Both directions, direction-AWARE identities (C36 r22 F4): an
        // ingress rule must never compare equal to a same-tuple egress
        // rule, and the observed STATE participates (a disabled or
        // re-directed drifted rule is not the recorded rule).
        #[allow(clippy::type_complexity)]
        let dir_planned_id = |rule: &AclRule| -> (String, AclRuleId) {
            (rule.direction.as_str().to_string(), acl_rule_id_tuple(rule))
        };
        #[allow(clippy::type_complexity)]
        let live: BTreeSet<(String, AclRuleId)> = observed
            .egress
            .iter()
            .map(|rule| ("egress".to_string(), observed_rule_id(rule)))
            .chain(
                observed
                    .ingress
                    .iter()
                    .map(|rule| ("ingress".to_string(), observed_rule_id(rule))),
            )
            .collect();
        // A rule the live ACL no longer carries is only EXPLAINED by
        // affirmative settlement evidence (C36 r23 F7 tightens C36 r22
        // F4): a proven lifecycle settlement durably recorded the
        // withdrawal of THAT identity (or, for a lease fence, of the
        // destination's settled grant) BEFORE it rewrote the durable
        // plan — the locks serialize those writers against this commit.
        // Membership in the PREVIOUS durable plan is necessary but never
        // sufficient: a rule installed by THIS pass (a first issuance or
        // a rotated generation) is absent from that plan, so its loss is
        // nobody's settlement — and silently filtering it would persist
        // an incomplete plan (an allow without its reject companions)
        // that later readiness would accept. Any unexplained absence
        // refuses the commit entirely. Nothing below has persisted yet,
        // the marker survives, and the next pass reconciles against the
        // still-trusted records instead of collapsing the trusted rule
        // set onto the corrupted one.
        // The commit's expected set is the COMPLETE derived multiset
        // (C36 r34 F1): the post-replacement observation PLUS every
        // verified replacement fence the drain installed this pass
        // (those entered the live ACL after the observation), MINUS the
        // drain's proven releases (explained below). Persisting the raw
        // observation would omit a live fence and fail every later
        // reconnect readback.
        let expected: Vec<AclRule> = installed
            .iter()
            .cloned()
            .chain(drain_added.iter().cloned())
            .collect();
        {
            let missing: Vec<&AclRule> = expected
                .iter()
                .filter(|rule| !live.contains(&dir_planned_id(rule)))
                .collect();
            if !missing.is_empty() {
                let withdrawal_evidence = self.read_dns_lease_withdrawals(sandbox_id);
                let explained = |rule: &AclRule| -> bool {
                    let description = rule.description.as_str();
                    let destination = rule.destination.as_deref().unwrap_or_default();
                    // A fence the commit-time drain PROVABLY released THIS
                    // pass (C36 r33 F2): the drain ran between the
                    // post-replacement observation and this commit's live
                    // re-read, so the rule's disappearance is the pass's
                    // own journaled work — journaled fence withdrawals
                    // produce no allow-withdrawal evidence, and without
                    // this the commit would reject its own drain. Only
                    // the exact drained identity+destination explains
                    // the loss; every other absence still needs
                    // settlement evidence.
                    if drain_released.iter().any(|pending| {
                        pending.description == description && pending.destination == destination
                    }) {
                        return true;
                    }
                    if super::network::is_dns_lease_fence_tag(description) {
                        // A lease fence is removed only by a settlement of
                        // THIS destination; the settlement's positive
                        // withdrawal evidence for the destination's grant
                        // is the affirmative proof.
                        return withdrawal_evidence
                            .iter()
                            .any(|(_, dest)| dest == destination);
                    }
                    // An allow or a reject companion is explained only by
                    // positive withdrawal evidence for ITS OWN group
                    // identity (a companion maps back to its allow tag).
                    let allow_tag = description.replacen("wssp-dns-reject-", "wssp-dns-", 1);
                    withdrawal_evidence.contains(&(allow_tag, destination.to_string()))
                };
                if missing.iter().any(|rule| !explained(rule)) {
                    return Err(internal_error(
                        "the live ACL lost rules no proven settlement explains; refusing to commit an unverified snapshot",
                    ));
                }
            }
        }
        let installed: Vec<AclRule> = expected
            .iter()
            .filter(|rule| live.contains(&dir_planned_id(rule)))
            .cloned()
            .collect();
        let dynamic_dests: BTreeSet<String> = plan
            .answers
            .iter()
            .flat_map(|(_, addresses)| addresses.iter().map(|addr| format!("{addr}/32")))
            .collect();
        let static_grants: Vec<super::network::GrantCidr> = plan
            .destinations
            .iter()
            .filter(|dest| !dynamic_dests.contains(*dest))
            .map(|text| parse_policy_cidr(text))
            .collect::<Result<_, _>>()?;
        state.grants.retain(|grant| {
            let allow_tag = super::network::dns_rule_tag(&grant.name, grant.generation);
            let has_live_allow = observed
                .egress
                .iter()
                .any(|rule| rule.action == "allow" && rule.description == allow_tag);
            has_live_allow
                || grant.addresses.iter().all(|address| {
                    address.parse::<Ipv4Addr>().ok().is_some_and(|ip| {
                        static_grants
                            .iter()
                            .any(|static_grant| static_grant.contains(ip))
                    })
                })
        });
        // Test hook (C36 r20 F3): hold the refresh commit — under the
        // commit lock, post-read, pre-persistence — so a test can run a
        // lease settlement against it and prove the two writers
        // serialize instead of interleaving into a lost update.
        #[cfg(test)]
        if let Some(barrier) = &self.dns_commit_barrier {
            barrier.wait();
            barrier.wait();
        }
        self.check_dns_refresh_cancelled()?;
        self.persist_dns_state(&state)?;
        self.check_dns_refresh_cancelled()?;
        // The recorded plan tracks the refreshed ACL verbatim (observed
        // install order): the reconnect readback compares positionally.
        self.update_persisted_plan_rules(sandbox_id, hash, &installed)
    }

    // Admission closure is graceful: an already admitted refresh may finish
    // its durable commit. Explicit revocation and the existing deadline still
    // preempt it, including while it waits for the commit lock.
    fn check_dns_refresh_cancelled(&self) -> Result<(), RuntimeError> {
        if self.io_cancelled() {
            return Err(error(
                SandboxErrorCode::UnknownOutcome,
                "runtime work preempted",
            ));
        }
        Ok(())
    }

    pub(crate) fn persist_dns_state(&self, state: &SandboxDnsState) -> Result<(), RuntimeError> {
        crate::validate_managed_instance_name(&crate::default_incus_instance_name(
            &state.sandbox_id,
        ))?;
        let body = serde_json::to_string(state)
            .map_err(|err| internal_error(format!("cannot encode the DNS policy state: {err}")))?;
        self.write_durable_record(
            &self.dns_state_dir(),
            &format!("{}.json", state.sandbox_id),
            &body,
        )
    }

    /// Persisted DNS policy state for this sandbox and policy hash, with
    /// every grant re-validated (parse + protected-address check): a corrupt
    /// or rebound record is never trusted. Absent/foreign/malformed → `None`
    /// (fail closed).
    pub(crate) fn load_dns_state(&self, sandbox_id: &str, hash: &str) -> Option<SandboxDnsState> {
        let body = std::fs::read_to_string(self.dns_state_path(sandbox_id)).ok()?;
        let state: SandboxDnsState = serde_json::from_str(&body).ok()?;
        if state.sandbox_id != sandbox_id || state.policy_hash != hash {
            return None;
        }
        if state.grants.len() > super::network::MAX_POLICY_DOMAINS {
            return None;
        }
        // The SAME bounds refresh planning enforces: unique DESTINATIONS
        // (names may share addresses) within the destination bound, and total
        // per-domain address RECORDS within the emitted-record bound. A state
        // planning legitimately commits must load — otherwise the next
        // transient failure would discard still-unexpired grants.
        let mut destinations: BTreeSet<Ipv4Addr> = BTreeSet::new();
        let mut total = 0usize;
        for entry in &state.grants {
            if validate_policy_domain(&entry.name).is_err() {
                return None;
            }
            total += entry.addresses.len();
            for text in &entry.addresses {
                let addr: Ipv4Addr = text.parse().ok()?;
                if is_protected_guest_address(addr) {
                    return None;
                }
                destinations.insert(addr);
            }
        }
        if destinations.len() > MAX_GRANT_DESTINATIONS || total > MAX_GRANT_RECORDS {
            return None;
        }
        Some(state)
    }

    pub(crate) fn dns_revocations_dir(&self) -> PathBuf {
        self.state_root().join("dns-revocations")
    }

    fn dns_revocations_path(&self, sandbox_id: &str) -> PathBuf {
        self.dns_revocations_dir()
            .join(format!("{sandbox_id}.json"))
    }

    /// Persist the revocation marker. Survives a crash between mutation
    /// and state persistence; cleared once the new state commits AND no
    /// uncertain mutation awaits reconciliation. THE marker-write
    /// boundary (C36 r29 F2): the consumed-identity high-water mark NEVER
    /// decreases here. A caller persisting an OLDER in-memory snapshot —
    /// reconciliation's record predates its replacement-fence allocation,
    /// which durably advanced `next_request` — would otherwise roll the
    /// counter backward, letting a crash/retry reissue an allocated fence
    /// epoch whose deferred removal may still be in flight. Every marker
    /// write funnels through this fn, so the clamp is enforced once: max
    /// of the caller's value, the on-disk record's, and the tombstone's
    /// high-water (the marker may have been legitimately CLEARED, its
    /// consumption folded into the tombstone — a fresh record must not
    /// restart the sequence). An undecodable existing marker or
    /// tombstone fails the write closed rather than risking a rollback.
    fn persist_dns_revocation_record(
        &self,
        record: &DnsRevocationRecord,
    ) -> Result<(), RuntimeError> {
        crate::validate_managed_instance_name(&crate::default_incus_instance_name(
            &record.sandbox_id,
        ))?;
        let mut record = record.clone();
        // Every persisted marker belongs to the writer's project.
        record.project = Some(self.project.clone());
        let path = self.dns_revocations_path(&record.sandbox_id);
        match std::fs::read_to_string(&path) {
            Ok(body) => {
                let existing: DnsRevocationRecord =
                    serde_json::from_str(&body).map_err(|err| {
                        internal_error(format!(
                            "cannot decode the existing DNS revocation marker; refusing to overwrite it: {err}"
                        ))
                    })?;
                record.next_request = record.next_request.max(existing.next_request);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(internal_error(format!(
                    "cannot read the existing DNS revocation marker; refusing to overwrite it: {err}"
                )));
            }
        }
        let tombstone = self.dns_identity_tombstone(&record.sandbox_id)?;
        record.next_request = record
            .next_request
            .max(tombstone.request_floor)
            .max(tombstone.generations.values().copied().max().unwrap_or(0));
        let body = serde_json::to_string(&record).map_err(|err| {
            internal_error(format!("cannot encode the DNS revocation marker: {err}"))
        })?;
        self.write_durable_record(
            &self.dns_revocations_dir(),
            &format!("{}.json", record.sandbox_id),
            &body,
        )
    }

    /// Read the full marker record. Only ABSENCE is `Ok(None)`; any other
    /// read failure, undecodable body, mismatch, or implausible content is
    /// fail-closed evidence (`Err`) — never silently treat it as absent.
    fn read_dns_revocation_record(
        &self,
        sandbox_id: &str,
        hash: &str,
    ) -> Result<Option<DnsRevocationRecord>, RuntimeError> {
        self.read_dns_revocation_record_checked(sandbox_id, Some(hash))
    }

    /// Structural validation shared by the hash-bound marker read and the
    /// lease/recovery hash-agnostic read. `hash = None` skips only the
    /// policy-generation binding (the journal is sandbox-scoped truth
    /// whichever policy generation last wrote it).
    fn read_dns_revocation_record_checked(
        &self,
        sandbox_id: &str,
        hash: Option<&str>,
    ) -> Result<Option<DnsRevocationRecord>, RuntimeError> {
        let body = match std::fs::read_to_string(self.dns_revocations_path(sandbox_id)) {
            Ok(body) => body,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(internal_error(format!(
                    "cannot read the DNS revocation marker: {err}"
                )));
            }
        };
        let record = serde_json::from_str::<DnsRevocationRecord>(&body).map_err(|err| {
            internal_error(format!("cannot decode the DNS revocation marker: {err}"))
        })?;
        let pending_valid = record.pending.len() <= 8 * super::network::MAX_GRANT_DESTINATIONS
            && record.pending.iter().all(|pending| {
                let name_ok = match pending.kind {
                    PendingKind::Allow => validate_policy_domain(&pending.name).is_ok(),
                    PendingKind::FenceRelease => pending.name.parse::<Ipv4Addr>().is_ok(),
                };
                name_ok
                    && super::network::is_dns_dynamic_tag(&pending.description)
                    && pending
                        .destination
                        .strip_suffix("/32")
                        .is_some_and(|ip| ip.parse::<Ipv4Addr>().is_ok())
            });
        if record.sandbox_id != sandbox_id
            || hash.is_some_and(|hash| record.policy_hash != hash)
            || record.revoked.len() > super::network::MAX_POLICY_DOMAINS
            || record.revoked_generations.len() > super::network::MAX_POLICY_DOMAINS
            || record
                .revoked_generations
                .keys()
                .any(|name| validate_policy_domain(name).is_err())
            || record
                .revoked_generations
                .values()
                .any(|generations| generations.len() > MAX_DNS_LEASE_OBLIGATIONS + 1)
            || !record
                .project
                .as_deref()
                .map(|project| project == self.project)
                .unwrap_or(false)
            || record
                .revoked
                .iter()
                .any(|name| validate_policy_domain(name).is_err())
            || !pending_valid
            || record.published_attempts.len() > MAX_DNS_PUBLICATION_ATTEMPTS
            || record
                .published_attempts
                .iter()
                .any(|digest| digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(internal_error(
                "sandbox's DNS revocation marker is undecodable; refusing to mutate before it resolves",
            ));
        }
        Ok(Some(record))
    }

    /// Allocate `count` request identities, durably, BEFORE issuance (C36
    /// r17 F1): the counter lives in the crash-durable marker, so an
    /// interrupted refresh's allocations survive — a retry can never reuse
    /// an identity an in-flight request may still be carrying daemon-side.
    /// `floor` covers identities recorded elsewhere (committed generations,
    /// observed or pending rule tags). The identity TOMBSTONE'S high-water
    /// mark applies here, at the shared allocator, so EVERY caller —
    /// fence-only allocations included — is floored by the consumption a
    /// retired marker once recorded (C36 r28 F1): after an uncertain fence
    /// release is retried and the marker clears, a revocation-only pass
    /// (refused withdrawal → replacement fence) can never reissue the
    /// retired fence's epoch for the deferred removal to strike. An
    /// unreadable tombstone fails closed. Returns the first identity.
    fn allocate_dns_requests(
        &self,
        sandbox_id: &str,
        hash: &str,
        floor: u64,
        count: u64,
    ) -> Result<u64, RuntimeError> {
        let tombstone = self.dns_identity_tombstone(sandbox_id)?;
        let floor = floor
            .max(tombstone.request_floor)
            .max(tombstone.generations.values().copied().max().unwrap_or(0));
        let mut record = self
            .read_dns_revocation_record(sandbox_id, hash)?
            .unwrap_or_else(|| DnsRevocationRecord {
                sandbox_id: sandbox_id.to_string(),
                policy_hash: hash.to_string(),
                project: None,
                revoked: Vec::new(),
                revoked_generations: Default::default(),
                pending: Vec::new(),
                next_request: 0,
                standing_fences: Vec::new(),
                refresh_owed: false,
                published_attempts: Vec::new(),
            });
        let base = record.next_request.max(floor);
        record.next_request = base + count;
        self.persist_dns_revocation_record(&record)?;
        Ok(base + 1)
    }

    /// Record denials WITHOUT dropping still-pending ones: each refresh's
    /// marker is the UNION of its own denials and every earlier denial that
    /// never committed — otherwise a second interrupted refresh (denying
    /// nothing itself) would erase a pending revocation, and a later
    /// transient failure would retain and reinstall the denied grant from
    /// the stale dns-policy state. An undecodable marker refuses the
    /// refresh BEFORE any mutation (fail closed). Unreconciled uncertain
    /// mutations already recorded are preserved.
    fn extend_dns_revocations(
        &self,
        sandbox_id: &str,
        hash: &str,
        denied: &[String],
        generations: &std::collections::BTreeMap<String, u64>,
    ) -> Result<(), RuntimeError> {
        let mut record = self
            .read_dns_revocation_record(sandbox_id, hash)?
            .unwrap_or_else(|| DnsRevocationRecord {
                sandbox_id: sandbox_id.to_string(),
                policy_hash: hash.to_string(),
                project: None,
                revoked: Vec::new(),
                revoked_generations: Default::default(),
                pending: Vec::new(),
                next_request: 0,
                standing_fences: Vec::new(),
                refresh_owed: false,
                published_attempts: Vec::new(),
            });
        let mut names: BTreeSet<String> = record.revoked.into_iter().collect();
        names.extend(denied.iter().cloned());
        record.revoked = names.into_iter().collect();
        // The denied identities are EVERY generation outstanding when the
        // denial is journaled (C36 r32 F1): the committed generation AND
        // any armed-but-uncommitted identity from the durable lease
        // ledger — a re-grant that installed and published its fresh
        // generation and then failed BEFORE committing leaves the state
        // one generation behind, and the armed ledger is the only
        // durable record of the uncommitted identity. Recording only the
        // committed generation would let the autonomous boundary skip
        // the live uncommitted one, leaving the denied destination
        // effective until its TTL. A generation issued AFTER this denial
        // is absent from the set and stays exempt — it belongs to the
        // committing refresh. An unreadable ledger fails closed (the
        // denial must not be journaled with an incomplete identity set).
        // Union semantics: earlier denials' recorded generations are
        // preserved.
        let armed = self.read_dns_lease_obligations(sandbox_id)?;
        for name in denied {
            let set = record.revoked_generations.entry(name.clone()).or_default();
            if let Some(generation) = generations.get(name) {
                set.insert(*generation);
            }
            for entry in armed.iter().filter(|entry| entry.name == *name) {
                if let Some(generation) = super::network::dns_tag_request_id(&entry.allow_tag) {
                    set.insert(generation);
                }
            }
        }
        // This is already the durable pre-mutation write for the refresh.
        // Stamp OWED in the same record instead of issuing a second write
        // (and two more fsyncs) immediately after this one.
        record.refresh_owed = true;
        self.persist_dns_revocation_record(&record)
    }

    /// Record the digest of a `raw.dnsmasq` body BEFORE publishing it
    /// (C58 NEW-1): the readback of an owed refresh accepts exactly the
    /// committed publication or one of these attempts. The marker is
    /// already owed (marked before the first mutation).
    fn record_dns_publication_attempt(
        &self,
        sandbox_id: &str,
        hash: &str,
        content: &str,
    ) -> Result<(), RuntimeError> {
        let mut record = self
            .read_dns_revocation_record(sandbox_id, hash)?
            .ok_or_else(|| internal_error("DNS refresh marker vanished before publication"))?;
        let digest = dns_publication_digest(content);
        record.published_attempts.retain(|known| known != &digest);
        record.published_attempts.push(digest);
        let excess = record
            .published_attempts
            .len()
            .saturating_sub(MAX_DNS_PUBLICATION_ATTEMPTS);
        record.published_attempts.drain(..excess);
        record.refresh_owed = true;
        self.persist_dns_revocation_record(&record)
    }

    /// Record uncertain allow mutations durably (unioned) BEFORE the pass
    /// that follows their fencing: the marker — and its readiness fence —
    /// outlives the commit until a later refresh reconciles absence.
    fn extend_dns_pending(
        &self,
        sandbox_id: &str,
        hash: &str,
        uncertain: &[PendingMutation],
    ) -> Result<(), RuntimeError> {
        if uncertain.is_empty() {
            return Ok(());
        }
        let mut record = self
            .read_dns_revocation_record(sandbox_id, hash)?
            .unwrap_or_else(|| DnsRevocationRecord {
                sandbox_id: sandbox_id.to_string(),
                policy_hash: hash.to_string(),
                project: None,
                revoked: Vec::new(),
                revoked_generations: Default::default(),
                pending: Vec::new(),
                next_request: 0,
                standing_fences: Vec::new(),
                refresh_owed: false,
                published_attempts: Vec::new(),
            });
        for entry in uncertain {
            if !record.pending.contains(entry) {
                record.pending.push(entry.clone());
            }
        }
        self.persist_dns_revocation_record(&record)
    }

    /// THE ownership gate every fence-mutating boundary shares (C36 r34
    /// F2): the sandbox tag AND the project tag must both match before a
    /// rule is added to or removed from this ACL — an inherited or
    /// same-named foreign ACL is never mutated by lease recovery, blind
    /// pre-fencing, or the journaled release boundary.
    fn require_owned_dns_acl(
        &self,
        observed: &super::acl::ObservedAcl,
        sandbox_id: &str,
        acl_name: &str,
    ) -> Result<(), RuntimeError> {
        let managed = observed
            .project_tag
            .as_deref()
            .map(|project| project == self.project)
            .unwrap_or(false);
        if observed.sandbox_tag.as_deref() != Some(sandbox_id) || !managed {
            return Err(super::acl::foreign_object("network acl", acl_name));
        }
        Ok(())
    }

    /// The destination-wide CURRENT-authorization check every
    /// fence-release path shares (C36 r28 F3): a covering static policy
    /// grant, or a complete observed group (allow + DNS/DoT reject
    /// companions) belonging to an UNEXPIRED, non-revoked armed grant.
    /// Lease-obligation state fails closed (unreadable → not authorized →
    /// the release path must fence instead). `exclude_allow_tag` removes
    /// ONE identity from consideration (C36 r32 F4): a withdrawal path
    /// must never let the identity being withdrawn authorize its own
    /// destination. Pass "" when no identity is excluded.
    #[allow(clippy::too_many_arguments)]
    fn dns_destination_authorized(
        &self,
        sandbox_id: &str,
        present: &BTreeSet<AclRuleId>,
        dest: &str,
        static_grants: &[super::network::GrantCidr],
        revoked: &[String],
        revoked_generations: &BTreeMap<String, BTreeSet<u64>>,
        exclude_allow_tag: &str,
    ) -> Result<bool, RuntimeError> {
        if dest
            .strip_suffix("/32")
            .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
            .is_some_and(|ip| static_grants.iter().any(|grant| grant.contains(ip)))
        {
            return Ok(true);
        }
        let now = self.dns_clock.unix_now()?;
        let obligations = self.read_dns_lease_obligations(sandbox_id)?;
        Ok(obligations.iter().any(|entry| {
            // Denials are GENERATION-EXACT (C36 r34 F1, the same identity
            // precision the autonomous boundary has had since r32 F1):
            // the marker denies the generations outstanding when the
            // denial was journaled, so a re-grant's FRESH generation —
            // issued after the denial and committed by THIS refresh —
            // still authorizes; a revoked name with no recorded
            // generation set denies every generation
            // — fail closed.
            let denied = revoked.iter().any(|name| name == &entry.name)
                && revoked_generations.get(&entry.name).is_none_or(|denied| {
                    super::network::dns_tag_request_id(&entry.allow_tag)
                        .is_none_or(|generation| denied.contains(&generation))
                });
            entry.expires_at > now
                && !denied
                && entry.allow_tag != exclude_allow_tag
                && entry.destinations.contains(dest)
                && present
                    .iter()
                    .find(|id| {
                        id.0 == entry.allow_tag
                            && id.1 == "allow"
                            && id.2 == "enabled"
                            && id.7 == dest
                    })
                    .is_some_and(|allow| {
                        dns_reject_companion_ids(allow)
                            .iter()
                            .all(|companion| present.contains(companion))
                    })
        }))
    }

    /// THE shared journaled fence-release safety boundary (C36 r32 F3):
    /// EVERY retry of a journaled `FenceRelease` — reconciliation AND the
    /// commit-time drain — routes through here. Release requires CURRENT
    /// authorization (the shared destination-wide check against a fresh,
    /// deadline-bounded observation); an UNAUTHORIZED release installs a
    /// RELIABLE replacement fence (fresh epoch, read back) BEFORE the old
    /// identity is touched, and a failed replacement keeps the old fence
    /// installed and the entry pending — over-denial only, never
    /// exposure. The check-and-release runs under the lease owner's state
    /// lock so a concurrent expiry settlement cannot interleave between
    /// the authorization read and the removal, and ONE absolute deadline
    /// — the earlier of the caller's and the earliest armed lease expiry
    /// (C36 r33 F1) — bounds every observation: an exhausted deadline
    /// yields the lock (so an expiring grant's watcher can fence on
    /// time) and leaves the release pending rather than releasing on an
    /// authorization whose own lifetime ran out mid-drain.
    #[allow(clippy::too_many_arguments)]
    fn release_journaled_fence(
        &self,
        sandbox_id: &str,
        hash: &str,
        acl_name: &str,
        pending: &PendingMutation,
        id: &AclRuleId,
        static_grants: &[super::network::GrantCidr],
        revoked: &[String],
        revoked_generations: &BTreeMap<String, BTreeSet<u64>>,
        deadline: Option<Instant>,
    ) -> Result<FenceReleaseOutcome, RuntimeError> {
        // ONE absolute deadline bounds the whole check-and-release (C36
        // r33 F1): the caller's deadline AND the earliest ARMED lease
        // expiry. The owner state lock below is held across the ACL
        // reads, the replacement install, and the removal — an unbounded
        // caller (reconciliation passes None) would otherwise hold that
        // lock through a stalled operation while an UNRELATED grant
        // expires, and that grant's watcher needs the same lock to
        // install the expiry fence: the destination would stay reachable
        // past its lifetime. An unreadable ledger fails closed — the
        // release simply does not happen this pass.
        let deadline = {
            let now = self.dns_clock.unix_now()?;
            let armed = self.read_dns_lease_obligations(sandbox_id)?;
            let earliest = armed
                .iter()
                .map(|entry| entry.expires_at.saturating_sub(now))
                .min();
            match (deadline, earliest) {
                (Some(d), Some(left)) => Some(d.min(Instant::now() + Duration::from_secs(left))),
                (Some(d), None) => Some(d),
                (None, Some(left)) => Some(Instant::now() + Duration::from_secs(left)),
                (None, None) => None,
            }
        };
        let owner = self.dns_lease_owner(sandbox_id);
        let _guard = owner.state.lock().unwrap_or_else(|err| err.into_inner());
        let remaining = || -> Option<Duration> {
            deadline.map(|d| d.saturating_duration_since(Instant::now()))
        };
        if remaining().is_some_and(|left| left.is_zero()) {
            return Ok(FenceReleaseOutcome::pending());
        }
        let dest = pending.destination.clone();
        let current = self
            .read_sandbox_acl_within(acl_name, remaining())?
            .ok_or_else(|| error(SandboxErrorCode::SandboxNotFound, "sandbox ACL is absent"))?;
        // Ownership BEFORE any mutation (C36 r34 F2): this boundary adds
        // replacement fences and removes rules — a same-named ACL that
        // was replaced or retagged foreign must receive NEITHER. The
        // check rides the read the boundary already performs.
        self.require_owned_dns_acl(&current, sandbox_id, acl_name)?;
        let present: BTreeSet<AclRuleId> = current.egress.iter().map(observed_rule_id).collect();
        let authorized = self.dns_destination_authorized(
            sandbox_id,
            &present,
            &dest,
            static_grants,
            revoked,
            revoked_generations,
            "",
        )?;
        let mut replacement = None;
        if !authorized {
            let Some(addr) = dest
                .strip_suffix("/32")
                .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
            else {
                return Ok(FenceReleaseOutcome::pending());
            };
            let epoch = self.allocate_dns_requests(sandbox_id, hash, 0, 1)?;
            let fence = super::network::domain_fence_rule(addr, epoch);
            let mut args = vec![
                "network".to_string(),
                "acl".to_string(),
                "rule".to_string(),
                "add".to_string(),
                acl_name.to_string(),
                "egress".to_string(),
            ];
            args.extend(fence.cli_args());
            let argv = args.iter().map(String::as_str).collect::<Vec<_>>();
            // Reliable means READ BACK: the replacement must be observed
            // before the old identity is touched.
            let out = match remaining() {
                Some(left) if !left.is_zero() => self.run_bounded(&argv, false, left).ok(),
                Some(_) => None,
                None => self.run(&argv, false).ok(),
            };
            let installed = out.is_some_and(|out| out.exit_code == 0)
                && self
                    .read_sandbox_acl_within(acl_name, remaining())
                    .ok()
                    .flatten()
                    .is_some_and(|after| {
                        after.egress.iter().any(|rule| {
                            rule.description == fence.description && rule.destination == dest
                        })
                    });
            if !installed {
                return Ok(FenceReleaseOutcome::pending());
            }
            // The verified replacement is reported to the caller (C36
            // r34 F1): a drain between the pass's observation and the
            // commit must fold this ADDITION into the committed
            // snapshot, or the persisted plan lacks a live fence and
            // reconnect verification refuses the sandbox forever.
            replacement = Some(fence);
        }
        // The shared enforced withdrawal primitive (C36 r18 F3):
        // duplicate-match refusals get a --force retry; only a clean exit
        // or a PROVEN-ABSENCE daemon reply counts.
        let attempt = match self.withdraw_rule_proven(acl_name, id, remaining()) {
            Ok(WithdrawalProof::PositivelyWithdrawn) => FenceReleaseAttempt::Withdrawn,
            Ok(WithdrawalProof::ProvenAbsent) => FenceReleaseAttempt::Absent,
            Ok(WithdrawalProof::Unproven) | Err(_) => FenceReleaseAttempt::Pending,
        };
        Ok(FenceReleaseOutcome {
            attempt,
            replacement,
        })
    }

    /// Reconcile unresolved broadening mutations at refresh START (C36
    /// r14–r17). An ALLOW entry retires ONLY on definitive evidence about
    /// ITS OWN request-specific rule (generation-scoped): the rule is
    /// observed PRESENT and a fresh withdrawal removes it (re-observed
    /// absent afterwards). Observing ABSENCE alone proves nothing: the
    /// daemon may apply an accepted mutation AFTER this check, so an absent
    /// allow entry stays pending — and its destination stays fenced — until
    /// definitive evidence. A RE-GRANT is not evidence either: the fresh
    /// grant's allow carries a NEW durable identity (r17 F1), so the stale
    /// request's late apply can never pass for it. A FENCE-RELEASE entry
    /// (r17 F4) retires once its rule is observed ABSENT (the removal's
    /// goal state; a deferred re-removal of an absent rule is a no-op);
    /// while the rule is present the removal is retried THROUGH THE SHARED
    /// RELEASE BOUNDARY (C36 r32 F3), and any still-needed fence for the
    /// destination is re-issued under a fresh epoch by the enforcement
    /// pass. An allow rule that is present and will not withdraw fails the
    /// refresh BEFORE any mutation (fail closed, marker retained); a stuck
    /// fence release only over-denies, so it never blocks the refresh.
    fn reconcile_pending_mutations(
        &self,
        sandbox_id: &str,
        hash: &str,
        acl_name: &str,
        acl_reborn: bool,
        static_grants: &[super::network::GrantCidr],
    ) -> Result<(), RuntimeError> {
        let Some(mut record) = self.read_dns_revocation_record(sandbox_id, hash)? else {
            return Ok(());
        };
        if record.pending.is_empty() {
            return Ok(());
        }
        let present_id =
            |pending: &PendingMutation, egress: &[super::acl::ObservedRule]| -> Option<AclRuleId> {
                egress
                    .iter()
                    .find(|rule| {
                        rule.description == pending.description
                            && rule.destination == pending.destination
                            && match pending.kind {
                                PendingKind::Allow => rule.action == "allow",
                                PendingKind::FenceRelease => true,
                            }
                    })
                    .map(observed_rule_id)
            };
        let observed = self
            .read_sandbox_acl(acl_name)?
            .ok_or_else(|| error(SandboxErrorCode::SandboxNotFound, "sandbox ACL is absent"))?;
        // Durable positive-withdrawal evidence from the expiry lease (C36
        // r17 follow-through): the lease OBSERVED the exact
        // request-specific rule and removed it (clean exit), which proves
        // the uncertain request COMPLETED — a request completes at most
        // once — so the entry can never observe the rule again and retires
        // even though absence alone would prove nothing.
        let lease_withdrawn = self.read_dns_lease_withdrawals(sandbox_id);
        let mut still_pending: Vec<PendingMutation> = Vec::new();
        let mut withdrawn: Vec<PendingMutation> = Vec::new();
        let mut failed = false;
        let mut standing_changed = false;
        for pending in &record.pending {
            match present_id(pending, &observed.egress) {
                None => {
                    // Allow: absence is NOT proof (C36 r15) — keep fenced
                    // unless the lease positively withdrew this identity.
                    // FenceRelease: absence IS the goal state — retire.
                    if pending.kind == PendingKind::Allow
                        && !lease_withdrawn
                            .contains(&(pending.description.clone(), pending.destination.clone()))
                    {
                        if acl_reborn {
                            // The ACL this entry targeted is GONE — a
                            // fresh incarnation under the same name (C36
                            // r22 F2). The uncertain request can never be
                            // observed against its original ACL again, yet
                            // the daemon may still apply it against the
                            // NEW one at any time: convert the entry into
                            // a STANDING fence obligation — PRESERVING
                            // the request identity (C36 r23 F2) — and
                            // retire the journal entry. This same pass
                            // plans and installs the fence BEFORE
                            // anything broadens, so the deferred apply
                            // can only ever land behind it. Authorization
                            // later SUPPRESSES the fence; only positive
                            // withdrawal evidence for this exact identity
                            // retires the obligation.
                            let standing = StandingFence::Full {
                                destination: pending.destination.clone(),
                                description: pending.description.clone(),
                            };
                            if !record.standing_fences.contains(&standing) {
                                record.standing_fences.push(standing);
                                standing_changed = true;
                            }
                            continue;
                        }
                        still_pending.push(pending.clone());
                    }
                }
                Some(id) => {
                    if pending.kind == PendingKind::Allow {
                        // THE shared destination-withdrawal boundary (C36
                        // r19 F3): proven withdrawal only — and an
                        // unproven withdrawal FENCES the destination
                        // (the entry is an unresolved broadening
                        // mutation; readiness stays marker-blocked, and
                        // now traffic is fenced too) before the error
                        // returns — UNLESS the destination is still
                        // covered by a verified CURRENT authorization
                        // that excludes the identity being withdrawn
                        // (C36 r32 F4): a stale pending allow landing on
                        // a destination a complete live sibling group
                        // still authorizes must not take the sibling
                        // down behind a destination-wide fence. The
                        // coverage derives through the shared
                        // current-authorization predicate. Reconcile's
                        // fences come from the marker-counter family
                        // like the rest of the refresh machinery.
                        let dest = pending.destination.clone();
                        let covered = {
                            let present: BTreeSet<AclRuleId> =
                                observed.egress.iter().map(observed_rule_id).collect();
                            self.dns_destination_authorized(
                                sandbox_id,
                                &present,
                                &dest,
                                static_grants,
                                &record.revoked,
                                &record.revoked_generations,
                                &pending.description,
                            )?
                        };
                        let mut fence_alloc =
                            |dest: &str| -> Result<super::network::AclRule, RuntimeError> {
                                let addr = dest
                                    .strip_suffix("/32")
                                    .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
                                    .ok_or_else(|| {
                                        internal_error(
                                            "pending DNS fence destination is not an IPv4 /32",
                                        )
                                    })?;
                                let epoch = self.allocate_dns_requests(sandbox_id, hash, 0, 1)?;
                                Ok(super::network::domain_fence_rule(addr, epoch))
                            };
                        self.enforce_destination_withdrawal(
                            sandbox_id,
                            acl_name,
                            &dest,
                            std::slice::from_ref(&pending.description),
                            &[],
                            false,
                            covered,
                            None,
                            None,
                            false,
                            &mut fence_alloc,
                        )?;
                        // Definitive ONLY once re-observed absent below.
                        withdrawn.push(pending.clone());
                        continue;
                    }
                    // FenceRelease: the retry goes through the SAME
                    // destination-wide release boundary as every other
                    // release path (C36 r28 F3, shared with the
                    // commit-time drain since r32 F3): release only
                    // behind CURRENT authorization; otherwise a RELIABLE
                    // replacement fence (fresh epoch, read back) lands
                    // BEFORE the old identity is removed, under the
                    // owner lock, inside the caller's deadline. A failed
                    // replacement keeps the old fence installed and the
                    // entry pending — over-denial only, never exposure.
                    let outcome = self.release_journaled_fence(
                        sandbox_id,
                        hash,
                        acl_name,
                        pending,
                        &id,
                        static_grants,
                        &record.revoked,
                        &record.revoked_generations,
                        None,
                    )?;
                    match outcome.attempt {
                        FenceReleaseAttempt::Withdrawn => {
                            // Definitive ONLY once re-observed absent below.
                            withdrawn.push(pending.clone());
                        }
                        FenceReleaseAttempt::Absent => {
                            // Proven absence: nothing matched — the fence
                            // is gone (goal state).
                        }
                        FenceReleaseAttempt::Pending => {
                            still_pending.push(pending.clone());
                        }
                    }
                }
            }
        }
        // Withdrawal is only proven by re-observation.
        let after = self
            .read_sandbox_acl(acl_name)?
            .ok_or_else(|| error(SandboxErrorCode::SandboxNotFound, "sandbox ACL is absent"))?;
        for pending in &withdrawn {
            if present_id(pending, &after.egress).is_some() {
                still_pending.push(pending.clone());
                if pending.kind == PendingKind::Allow {
                    failed = true;
                }
            }
        }
        if failed {
            return Err(internal_error(
                "an uncertain DNS allow mutation is still present and would not withdraw",
            ));
        }
        if still_pending.len() != record.pending.len() || standing_changed {
            record.pending = still_pending;
            self.persist_dns_revocation_record(&record)?;
        }
        Ok(())
    }

    /// Retire pending entries on DEFINITIVE evidence (C36 r15/r16): a
    /// clean exit 0 from the daemon (the rule applied), or a PROVEN
    /// rejection (`cli_daemon_rejected`). Timeout/UnknownOutcome, transport
    /// failures and unprovable nonzero exits keep the entry — the request
    /// may still be applied daemon-side.
    fn retire_dns_pending(
        &self,
        sandbox_id: &str,
        hash: &str,
        retired: &[PendingMutation],
    ) -> Result<(), RuntimeError> {
        if retired.is_empty() {
            return Ok(());
        }
        let Some(mut record) = self.read_dns_revocation_record(sandbox_id, hash)? else {
            return Ok(());
        };
        let before = record.pending.len();
        record.pending.retain(|entry| !retired.contains(entry));
        if record.pending.len() != before {
            self.persist_dns_revocation_record(&record)?;
        }
        Ok(())
    }

    /// Commit-time drain (C36 r14): attempt to withdraw pending uncertain
    /// FENCE-RELEASE rules that already landed. ALLOW-kind entries are
    /// deliberately left installed for the next refresh's reconcile
    /// (C36 r17): reconcile is the SINGLE proof point that withdraws and
    /// retires an uncertain allow — with one exception: an entry carrying
    /// durable POSITIVE-withdrawal evidence from the expiry lease retires
    /// here, since the lease's clean removal already proved the request
    /// completed. If the drain withdrew a landed allow while keeping its
    /// entry, no later refresh could ever observe it present again — and
    /// absence is not proof — so the entry (and its readiness fence)
    /// would never retire. The journaled fence covers the window either
    /// way. Returns whether nothing is pending; only then may the
    /// revocation marker clear.
    ///
    /// FenceRelease entries are retried through THE shared release
    /// boundary (C36 r32 F3) — the drain used to remove an observed fence
    /// on sight, with neither a current-authorization check nor a
    /// verified replacement: a pending release reaching the drain while
    /// an older allow stayed unresolved could strip the destination's
    /// remaining protection the moment a temporary authorizer expired
    /// mid-drain. `deadline` bounds every observation the boundary
    /// makes; the caller propagates the authorizing grants' own
    /// lifetimes so the drain never releases on an authorization that
    /// expired while it was looking.
    ///
    /// Successful fence releases are RETIRED here and returned in the
    /// outcome (C36 r33 F2): the drain used to ignore the result, so the
    /// entry stayed journaled (the marker could never clear) and the
    /// commit's live re-read saw the fence's disappearance as
    /// unexplained rule loss — journaled fence withdrawals produce none
    /// of the allow-withdrawal evidence the commit checks.
    pub(crate) fn drain_pending_mutations(
        &self,
        sandbox_id: &str,
        hash: &str,
        acl_name: &str,
        deadline: Option<Instant>,
    ) -> Result<DrainOutcome, RuntimeError> {
        let Some(record) = self.read_dns_revocation_record(sandbox_id, hash)? else {
            return Ok(DrainOutcome {
                drained: true,
                released: Vec::new(),
                added: Vec::new(),
            });
        };
        if record.pending.is_empty() {
            return Ok(DrainOutcome {
                drained: true,
                released: Vec::new(),
                added: Vec::new(),
            });
        }
        let observed = self
            .read_sandbox_acl(acl_name)?
            .ok_or_else(|| error(SandboxErrorCode::SandboxNotFound, "sandbox ACL is absent"))?;
        // An ALLOW entry the expiry lease has POSITIVELY withdrawn
        // (durable evidence) retires here too: the lease's positive
        // removal proves the uncertain request completed, so reconcile —
        // the single Allow proof point — could never observe the rule
        // again, and the entry must not outlive this commit. The entry may
        // have been (re-)journaled AFTER the lease fired: the uncertain
        // path's own withdrawal attempt can lose the race to the lease
        // (the killed CLI's deadline IS the grant's expiry) and then
        // conservatively re-journals on unproven absence.
        let lease_withdrawn = self.read_dns_lease_withdrawals(sandbox_id);
        let proven: Vec<PendingMutation> = record
            .pending
            .iter()
            .filter(|pending| {
                pending.kind == PendingKind::Allow
                    && lease_withdrawn
                        .contains(&(pending.description.clone(), pending.destination.clone()))
            })
            .cloned()
            .collect();
        let mut remaining = record.pending.len() - proven.len();
        self.retire_dns_pending(sandbox_id, hash, &proven)?;
        // Static coverage for the release gate comes from the RECORDED
        // policy's CIDRs (C36 r31 F3), never the resolved expansion.
        let static_grants = self.recorded_static_grant_cidrs(sandbox_id);
        let mut released: Vec<PendingMutation> = Vec::new();
        let mut added: Vec<AclRule> = Vec::new();
        for pending in &record.pending {
            if pending.kind != PendingKind::FenceRelease {
                continue;
            }
            if let Some(id) = observed
                .egress
                .iter()
                .find(|rule| {
                    rule.description == pending.description
                        && rule.destination == pending.destination
                })
                .map(observed_rule_id)
            {
                // THE shared release boundary (C36 r32 F3): current
                // authorization or a verified replacement before any
                // removal, owner-synchronized, deadline-bounded. The
                // drain is best-effort — a pending entry is retried by
                // the next refresh's reconcile — so an unsuccessful
                // attempt simply leaves the entry journaled. A PROVEN
                // release retires here and is reported to the caller so
                // the commit can explain the rule's disappearance (C36
                // r33 F2) — and a VERIFIED REPLACEMENT fence the
                // boundary installed is reported too, so the commit
                // folds the addition into the persisted plan instead of
                // leaving a live fence no durable record names (C36 r34
                // F1).
                if let Ok(outcome) = self.release_journaled_fence(
                    sandbox_id,
                    hash,
                    acl_name,
                    pending,
                    &id,
                    &static_grants,
                    &record.revoked,
                    &record.revoked_generations,
                    deadline,
                ) {
                    if let Some(fence) = outcome.replacement {
                        added.push(fence);
                    }
                    if matches!(
                        outcome.attempt,
                        FenceReleaseAttempt::Withdrawn | FenceReleaseAttempt::Absent
                    ) {
                        released.push(pending.clone());
                    }
                }
            }
        }
        if !released.is_empty() {
            self.retire_dns_pending(sandbox_id, hash, &released)?;
            remaining -= released.len();
        }
        Ok(DrainOutcome {
            drained: remaining == 0,
            released,
            added,
        })
    }

    /// Settle STANDING fence obligations at commit time (C36 r22 F2, r23
    /// F2). Authorization SUPPRESSES an obligation's fence — it never
    /// retires the obligation: the original request may still be applied
    /// daemon-side at any time, including AFTER a temporary
    /// reauthorization expires, so the obligation (and its preserved
    /// request identity) must survive to fence the destination again.
    /// An obligation retires ONLY on positive withdrawal evidence for
    /// its exact preserved identity (C36 r23 F8 records it the moment
    /// any pass proves the rule out; a request completes at most once,
    /// so the identity can never be observed again). Legacy
    /// identity-less obligations never retire (fail closed). Returns
    /// whether the marker is FULLY spent — no pending mutations and no
    /// standing obligations — the only state in which it may clear.
    fn settle_standing_fences(&self, sandbox_id: &str, hash: &str) -> Result<bool, RuntimeError> {
        let Some(mut record) = self.read_dns_revocation_record(sandbox_id, hash)? else {
            return Ok(true);
        };
        let withdrawn = self.read_dns_lease_withdrawals(sandbox_id);
        let before = record.standing_fences.len();
        record.standing_fences.retain(|standing| {
            !withdrawn.contains(&(
                standing.description().to_string(),
                standing.destination().to_string(),
            ))
        });
        if record.standing_fences.len() != before {
            self.persist_dns_revocation_record(&record)?;
        }
        Ok(record.pending.is_empty() && record.standing_fences.is_empty())
    }

    /// Failure-path expiry cleanup: grants whose safe publication window
    /// lapsed during a FAILED enforcement/publication attempt must not stay
    /// installed unrecorded. A bounded REVOKE-ONLY loop: each round records
    /// the revocations durably FIRST (the pending marker fences readiness
    /// and transient retention), then a withdrawal pass removes the lapsed
    /// rules — adding NO grant rules — and the survivors are rechecked, so
    /// a grant expiring DURING a slow withdrawal is revoked and withdrawn
    /// in turn. Bounded by the entry count (each round revokes at least
    /// one). Withdrawal runs through an INDEPENDENTLY bounded cleanup
    /// client (C36 r14): when the failure that brought us here is the
    /// CANCELLED issuing permit, commands through the issuing client are
    /// rejected outright. Fences are computed INSIDE the enforcement
    /// boundary from the marker and the surviving answers (C36 r17 F5):
    /// the cleanup installs fences that are still needed and releases —
    /// journaled — those that are not, exactly like the live path.
    fn revoke_lapsed_before_returning(
        &self,
        ctx: &EnforcementContext<'_>,
        plan: &mut RefreshPlan,
    ) -> Result<(), RuntimeError> {
        let mut cleanup_client = self.clone();
        cleanup_client.cancelled = None;
        while revoke_lapsed_entries(plan, self.dns_clock.unix_now()?) {
            let denied_names: Vec<String> =
                plan.denied.iter().map(|(name, _)| name.clone()).collect();
            self.extend_dns_revocations(
                ctx.sandbox_id,
                ctx.hash,
                &denied_names,
                &plan.state.generations,
            )?;
            let mut dynamic_rules: Vec<AclRule> = Vec::new();
            let generations: std::collections::BTreeMap<&str, u64> = plan
                .state
                .grants
                .iter()
                .map(|entry| (entry.name.as_str(), entry.generation))
                .collect();
            for (name, addresses) in &plan.answers {
                for addr in addresses {
                    dynamic_rules.extend(super::network::domain_grant_rules(
                        name,
                        *addr,
                        ctx.static_grants,
                        generations.get(name.as_str()).copied().unwrap_or(0),
                    ));
                }
            }
            let authorized_dests: BTreeSet<String> = plan
                .answers
                .iter()
                .flat_map(|(_, addresses)| addresses.iter().map(|addr| format!("{addr}/32")))
                .collect();
            cleanup_client.replace_dns_acl_rules(
                ctx.sandbox_id,
                ctx.acl_name,
                ctx.static_texts,
                ctx.static_grants,
                &dynamic_rules,
                &authorized_dests,
                &grant_expiries(&plan.state.grants),
                true,
                ctx.recorded_rules,
                ctx.hash,
            )?;
        }
        Ok(())
    }

    /// Clear the marker once the refreshed state is durably persisted.
    fn clear_dns_revocations(&self, sandbox_id: &str) -> Result<(), RuntimeError> {
        // The request-identity high-water mark OUTLIVES the marker (C36
        // r27 F1): `next_request` counts every allocation — fence epochs
        // as well as allow generations — but the committed generation
        // history records only allow generations, so deleting the marker
        // would drop the fence-epoch consumption. A later allocation
        // could then reissue a fence epoch whose DEFERRED daemon-side
        // removal (an earlier uncertain release, since retried and
        // retired) is still in flight — and that removal names its rule
        // by the exact identity string, striking the NEW fence around an
        // unresolved broadening mutation. Fold the counter (and any
        // surviving pending identities) into the monotone identity
        // tombstone BEFORE the marker is removed.
        self.preserve_dns_request_floor(sandbox_id)?;
        match std::fs::remove_file(self.dns_revocations_path(sandbox_id)) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(internal_error(format!(
                    "cannot clear the DNS revocation marker: {err}"
                )));
            }
        }
        // The lease-withdrawal evidence is spent with the marker: it only
        // ever retires entries OF that marker.
        match std::fs::remove_file(self.dns_lease_withdrawals_path(sandbox_id)) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(internal_error(format!(
                    "cannot clear the DNS lease-withdrawal evidence: {err}"
                )));
            }
        }
        // The append-only request-completion log (C36 r23 F8) retires with
        // the same marker: its proofs only ever retire entries OF it. A
        // late append after the clear can only name a request identity
        // that already completed (identities are never reused), never a
        // future one.
        match std::fs::remove_file(self.dns_withdrawal_evidence_log_path(sandbox_id)) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(internal_error(format!(
                "cannot clear the DNS withdrawal evidence log: {err}"
            ))),
        }
    }

    /// Preserve the request-identity high-water mark across marker
    /// retirement (C36 r27 F1): merge the marker's durable `next_request`
    /// counter and any still-pending mutation identities into the identity
    /// tombstone. The tombstone is MONOTONE — this only ever raises the
    /// floor, and it never touches the per-name generation history or the
    /// lease-fence floor — so a clear-then-allocate sequence can never
    /// reissue an identity a deferred daemon-side mutation still names.
    /// No marker (or nothing ever allocated) is a no-op.
    fn preserve_dns_request_floor(&self, sandbox_id: &str) -> Result<(), RuntimeError> {
        crate::validate_managed_instance_name(&crate::default_incus_instance_name(sandbox_id))?;
        let allocated = self
            .read_dns_revocation_record_unscoped(sandbox_id)?
            .map(|record| {
                record
                    .pending
                    .iter()
                    .filter_map(|pending| super::network::dns_tag_request_id(&pending.description))
                    .chain(std::iter::once(record.next_request))
                    .max()
                    .unwrap_or(0)
            })
            .unwrap_or(0);
        if allocated == 0 {
            return Ok(());
        }
        let mut history = self.dns_identity_tombstone(sandbox_id)?;
        if allocated <= history.request_floor {
            return Ok(());
        }
        history.request_floor = allocated;
        let body = serde_json::to_string(&serde_json::json!({
            "sandbox_id": sandbox_id,
            "generations": history.generations,
            "request_floor": history.request_floor,
            "lease_fence_floor": history.lease_fence_floor,
        }))
        .map_err(|err| {
            internal_error(format!("cannot encode the DNS identity tombstone: {err}"))
        })?;
        self.write_durable_record(
            &self.dns_revocations_dir(),
            &format!("{sandbox_id}.lease-history"),
            &body,
        )
    }

    /// Path of the durable lease-withdrawal evidence log for a sandbox
    /// (C36 r17 follow-through): one `<allow-tag> <destination>` line per
    /// POSITIVE expiry-lease withdrawal of a request-specific identity.
    /// Separate from the marker file (append-only, sole writer is the
    /// lease watcher) so the watcher never enters the refresh's marker
    /// read-modify-write; cleared together with the marker.
    fn dns_lease_withdrawals_path(&self, sandbox_id: &str) -> PathBuf {
        self.dns_revocations_dir()
            .join(format!("{sandbox_id}.lease-withdrawals"))
    }

    /// Path of the APPEND-ONLY request-completion evidence log (C36 r23
    /// F8). The lease-withdrawals file is whole-file-rewritten under the
    /// owner lock (sole writer: the lease), but the shared withdrawal
    /// boundary also produces positive proofs for callers that do NOT
    /// hold that lock (refresh, reconcile) — a read-modify-write from
    /// them could lose a concurrent lease write, and taking the owner
    /// lock would deadlock the settle that holds it. Single-line
    /// O_APPEND writes are atomic without any lock, so every caller of
    /// the boundary can durably record a proof the instant it exists —
    /// before any later fallible operation (a re-observation read, the
    /// commit) can discard it, and across a crash before the next
    /// scheduled flush.
    fn dns_withdrawal_evidence_log_path(&self, sandbox_id: &str) -> PathBuf {
        self.dns_revocations_dir()
            .join(format!("{sandbox_id}.withdrawal-evidence"))
    }

    /// Durably append ONE positive-withdrawal proof (`<tag> <destination>`
    /// line + fsync of file and directory). Called by the shared
    /// withdrawal boundary IMMEDIATELY when a proof is produced — a later
    /// error in the same pass can never discard it, and on retry the
    /// rule's absence is explained by THIS evidence even though no new
    /// proof can be produced for an already-absent rule.
    fn record_withdrawal_evidence(
        &self,
        sandbox_id: &str,
        tag: &str,
        destination: &str,
    ) -> Result<(), RuntimeError> {
        crate::validate_managed_instance_name(&crate::default_incus_instance_name(sandbox_id))?;
        let dir = self.dns_revocations_dir();
        let path = dir.join(format!("{sandbox_id}.withdrawal-evidence"));
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            // E-16: owner-only, like every other host-state record.
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path).map_err(|err| {
            internal_error(format!("cannot open the withdrawal evidence log: {err}"))
        })?;
        use std::io::Write as _;
        file.write_all(format!("{tag} {destination}\n").as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|err| {
                internal_error(format!("cannot append the withdrawal evidence log: {err}"))
            })?;
        Self::fsync_dir(&dir);
        Ok(())
    }

    /// The (allow-tag, destination) pairs POSITIVELY withdrawn — by the
    /// expiry lease (whole-file log) or by any caller of the shared
    /// withdrawal boundary (append-only log, C36 r23 F8). Unreadable/absent
    /// evidence degrades to the empty set — fail closed (affected entries
    /// simply stay pending and fenced).
    fn read_dns_lease_withdrawals(&self, sandbox_id: &str) -> BTreeSet<(String, String)> {
        let parse = |body: String| {
            body.lines()
                .filter_map(|line| {
                    let (tag, destination) = line.split_once(' ')?;
                    Some((tag.to_string(), destination.to_string()))
                })
                .collect::<BTreeSet<_>>()
        };
        let mut all: BTreeSet<(String, String)> =
            std::fs::read_to_string(self.dns_lease_withdrawals_path(sandbox_id))
                .map(parse)
                .unwrap_or_default();
        if let Ok(body) = std::fs::read_to_string(self.dns_withdrawal_evidence_log_path(sandbox_id))
        {
            all.extend(parse(body));
        }
        all
    }

    /// Persist the positive-withdrawal evidence log atomically with fsync
    /// (file AND directory, via the durable-record writer — C36 r18
    /// honesty): the proof that retires a journaled uncertain-allow entry
    /// must survive the crash window it protects against. The sole writer
    /// is the lease owner (watcher or restart recovery), under the owner
    /// lock, so a whole-file rewrite cannot lose a concurrent append. A
    /// POSITIVE withdrawal of a request-specific identity proves the
    /// uncertain request that installed it completed (a request completes
    /// at most once): absence alone would prove nothing — a still-deferred
    /// apply could land later — but a positive removal proves completion,
    /// so the journaled pending entry for that exact identity can never
    /// observe the rule again and must retire. A persist failure keeps the
    /// obligation armed (fail closed), never the reverse.
    fn persist_dns_lease_withdrawals(
        &self,
        sandbox_id: &str,
        evidence: &BTreeSet<(String, String)>,
    ) -> Result<(), RuntimeError> {
        crate::validate_managed_instance_name(&crate::default_incus_instance_name(sandbox_id))?;
        // Union with what is already durable: the in-memory owed set holds
        // only UNPERSISTED evidence, but earlier evidence must live until
        // the marker clears.
        let mut all = self.read_dns_lease_withdrawals(sandbox_id);
        all.extend(evidence.iter().cloned());
        let mut body = String::new();
        for (tag, destination) in &all {
            body.push_str(tag);
            body.push(' ');
            body.push_str(destination);
            body.push('\n');
        }
        self.write_durable_record(
            &self.dns_revocations_dir(),
            &format!("{sandbox_id}.lease-withdrawals"),
            &body,
        )
    }

    /// Read the marker for this sandbox/policy hash: a decodable marker
    /// excludes exactly its names from transient retention; an undecodable
    /// or mismatched marker retains NOTHING (fail closed).
    fn read_dns_revocations(&self, sandbox_id: &str, hash: &str) -> DnsRevocations {
        match self.read_dns_revocation_record(sandbox_id, hash) {
            Ok(None) => DnsRevocations::None,
            Ok(Some(record)) => DnsRevocations::Set(record.revoked.into_iter().collect()),
            Err(_) => DnsRevocations::Malformed,
        }
    }

    /// The `raw.dnsmasq` content the network readback must show: what the
    /// last refresh/initial publish durably recorded, else the deny-all
    /// base. Test-only convenience — production callers needing the
    /// distinction use the fallible variant (C37 R5).
    #[cfg(test)]
    pub(crate) fn expected_dnsmasq_config(&self, sandbox_id: &str) -> String {
        self.expected_dnsmasq_config_checked(sandbox_id)
            .unwrap_or_else(|_| base_dnsmasq_config())
    }

    /// Fallible variant for the observation boundary (C37 R5): a state file
    /// that exists but cannot be read or parsed is unavailable EVIDENCE —
    /// substituting the base config would manufacture a comparison mismatch
    /// (drift) out of a local read failure. A cleanly ABSENT state file
    /// means the deny-all base was published, legitimately.
    pub(crate) fn expected_dnsmasq_config_checked(
        &self,
        sandbox_id: &str,
    ) -> Result<String, RuntimeError> {
        let path = self.dns_state_path(sandbox_id);
        let body = match std::fs::read_to_string(&path) {
            Ok(body) => body,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                // §2.2/§2.6: with no publication state the bridge must carry
                // the RECORDED resolver base (open-mode resolver, or the
                // allowlist base plus blocked `local=` lines); a legacy or
                // absent record means the deny-all base. An unreadable
                // record is unavailable evidence (C37 R5).
                return Ok(self
                    .persisted_enforcement_plan_checked(sandbox_id)?
                    .map(|recorded| recorded.dnsmasq_base)
                    .unwrap_or_else(base_dnsmasq_config));
            }
            Err(err) => {
                return Err(RuntimeError::new(
                    SandboxErrorCode::Internal,
                    format!("cannot read the DNS publication state for `{sandbox_id}`: {err}"),
                ));
            }
        };
        let parsed = serde_json::from_str::<SandboxDnsState>(&body)
            .ok()
            .filter(|state| state.sandbox_id == sandbox_id)
            .ok_or_else(|| {
                RuntimeError::new(
                    SandboxErrorCode::Internal,
                    format!("cannot parse the DNS publication state for `{sandbox_id}`"),
                )
            })?;
        Ok(parsed.published)
    }

    /// Replace the ACL's DNS-grant rule set with the planned one. Every ACL
    /// mutation of a refresh flows through this ONE boundary (C36 r17): the
    /// expiry lease is (re)armed, deny-direction fences are installed FIRST,
    /// then removals, then additions (reject companions BEFORE their allow),
    /// then fence releases, and a final readback proves the dynamic MULTISET
    /// is exactly what the pass provably produced. Mutations are classified
    /// by PERMISSION EFFECT: broadening mutations (allow adds; fence
    /// removals) carry durable request-specific identities and are journaled
    /// pre-issuance; narrowing mutations (reject/fence adds, allow removals)
    /// are bounded and readback-verified but need no journal — a deferred
    /// narrowing apply only delays or over-applies a denial, and
    /// generation-scoped companion tags make a deferred companion removal
    /// unable to hit a newer companion.
    ///
    /// Fences are PREVENTIVE (C36 r17 F2): before any broadening allow is
    /// issued for a destination that is not otherwise effectively
    /// authorized, a destination-wide deny fence is installed and confirmed
    /// — a crashed daemon or a failed fence install can never leave an
    /// unconfirmed allow unfenced, because the allow is never issued. Fence
    /// necessity derives from the COMPLETE effective authorization (C36
    /// r17 F5): a destination authorized by ANY live planned grant (any
    /// name) or a covering static CIDR is not fenced; the fence returns
    /// before the final authorization disappears because deny adds run
    /// before removals. Fence releases are journaled broadening removals
    /// with fresh-epoch re-issue (C36 r17 F4): a deferred removal can never
    /// remove a newer fence.
    ///
    /// Every operation is deadline-bounded (C36 r17 F3): additions carry the
    /// grant-lifetime and earliest-deadline budgets; removals, fencing and
    /// releases are bounded by the earliest working grant's deadline.
    /// In `revoke_only` mode (failure cleanup) no grant rules are added;
    /// fences are still installed when needed and removed when unneeded.
    #[allow(clippy::too_many_arguments)]
    fn replace_dns_acl_rules(
        &self,
        sandbox_id: &str,
        acl_name: &str,
        static_texts: &BTreeSet<String>,
        static_grants: &[super::network::GrantCidr],
        dynamic_rules: &[AclRule],
        authorized_dests: &BTreeSet<String>,
        expiries: &BTreeMap<String, (String, u64, u64)>,
        revoke_only: bool,
        recorded_rules: Option<&[AclRule]>,
        hash: &str,
    ) -> Result<ReplacementOutcome, RuntimeError> {
        // Arm the enforcement-level expiry lease (C36 r17 F3) with the
        // identities THIS pass enforces, so it fires at absolute expiry even
        // if this refresh never commits. The arm MERGES (C36 r18 F6):
        // identities this pass no longer carries stay armed until their
        // expiry, and the fsync'd obligations drive restart recovery.
        let static_covered = |dest: &str| -> bool {
            dest.strip_suffix("/32")
                .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
                .is_some_and(|ip| static_grants.iter().any(|grant| grant.contains(ip)))
        };
        let mut seen_domains: BTreeSet<&str> = BTreeSet::new();
        let lease_entries: Vec<DnsLeaseEntry> = expiries
            .values()
            .filter(|(domain, _, _)| seen_domains.insert(domain.as_str()))
            .map(|(domain, expires_at, generation)| {
                let allow_tag = super::network::dns_rule_tag(domain, *generation);
                let destinations: BTreeSet<String> = dynamic_rules
                    .iter()
                    .filter(|rule| rule.description == allow_tag)
                    .filter_map(|rule| rule.destination.clone())
                    .collect();
                dns_lease_entry(
                    domain,
                    *expires_at,
                    *generation,
                    destinations,
                    static_grants,
                )
            })
            .collect();
        self.arm_dns_expiry_lease(sandbox_id, lease_entries)?;
        let observed = self
            .read_sandbox_acl(acl_name)?
            .ok_or_else(|| error(SandboxErrorCode::SandboxNotFound, "sandbox ACL is absent"))?;
        let managed = observed
            .project_tag
            .as_deref()
            .map(|project| project == self.project)
            .unwrap_or(false);
        if observed.sandbox_tag.as_deref() != Some(sandbox_id) || !managed {
            return Err(super::acl::foreign_object("network acl", acl_name));
        }
        let is_dynamic = |rule: &super::acl::ObservedRule| {
            super::network::is_dns_dynamic_tag(&rule.description)
                || (rule.description == "wssp-grant"
                    && !rule.destination.is_empty()
                    && !static_texts.contains(&rule.destination))
        };
        if let Some(recorded) = recorded_rules {
            let is_dynamic_planned = |rule: &AclRule| {
                super::network::is_dns_dynamic_tag(&rule.description)
                    || (rule.description == "wssp-grant"
                        && rule.destination.as_deref().is_some_and(|destination| {
                            !destination.is_empty() && !static_texts.contains(destination)
                        }))
            };
            let mut recorded_static: Vec<String> = recorded
                .iter()
                .filter(|rule| !is_dynamic_planned(rule))
                .map(|rule| {
                    format!(
                        "{}|{}|enabled|{}|{}|{}|{}|{}",
                        rule.direction.as_str(),
                        rule.action.as_str(),
                        rule.protocol.as_deref().unwrap_or_default(),
                        rule.source.as_deref().unwrap_or_default(),
                        rule.destination.as_deref().unwrap_or_default(),
                        rule.source_port.as_deref().unwrap_or_default(),
                        rule.destination_port.as_deref().unwrap_or_default(),
                    )
                })
                .collect();
            recorded_static.sort();
            let mut observed_static: Vec<String> = observed
                .ingress
                .iter()
                .map(|rule| ("ingress", rule))
                .chain(observed.egress.iter().map(|rule| ("egress", rule)))
                .filter(|(_, rule)| !is_dynamic(rule))
                .map(|(direction, rule)| {
                    format!(
                        "{direction}|{}|{}|{}|{}|{}|{}|{}",
                        rule.action,
                        rule.state,
                        rule.protocol,
                        rule.source,
                        rule.destination,
                        rule.source_port,
                        rule.destination_port
                    )
                })
                .collect();
            observed_static.sort();
            if observed_static != recorded_static {
                return Err(internal_error(
                    "incus sandbox ACL static rules drifted from the recorded plan",
                ));
            }
        }
        if observed.ingress.iter().any(&is_dynamic) {
            return Err(internal_error(
                "incus sandbox ACL holds unexpected DNS grant ingress rules",
            ));
        }
        type RuleId = AclRuleId;
        let observed_id = observed_rule_id;
        let planned_id = |rule: &AclRule| -> RuleId {
            (
                rule.description.clone(),
                rule.action.as_str().to_string(),
                "enabled".to_string(),
                rule.protocol.clone().unwrap_or_default(),
                rule.source.clone().unwrap_or_default(),
                rule.source_port.clone().unwrap_or_default(),
                rule.destination_port.clone().unwrap_or_default(),
                rule.destination.clone().unwrap_or_default(),
            )
        };
        let mut current_list: Vec<RuleId> = observed
            .egress
            .iter()
            .filter(|rule| is_dynamic(rule))
            .map(observed_id)
            .collect();
        current_list.sort();
        let current_dynamic: BTreeSet<RuleId> = current_list.into_iter().collect();
        // Every ADDED allow is a NEW issuance carrying a request-unique
        // identity (C36 r20 F2): a planned allow that is NOT installed
        // right now must never carry an identity that generation history
        // or withdrawal evidence has already seen — durable positive-
        // withdrawal evidence is keyed by the exact tag, so re-issuing a
        // seen identity would let its stale evidence retire the new
        // request's journaled pending entry before the request lands. A
        // rule verified still installed is a RENEWAL (identity kept);
        // anything re-added is a new issuance. The check runs on THIS
        // pass's own fresh observation: a renewal racing the expiry lease
        // (which can withdraw the old identity after planning observed it
        // present) reissues instead of reusing.
        if !revoke_only {
            let history = self.load_dns_state(sandbox_id, hash);
            let tombstone = self.dns_identity_tombstone(sandbox_id)?;
            let evidence = self.read_dns_lease_withdrawals(sandbox_id);
            let mut reissue: Vec<String> = Vec::new();
            let mut checked: BTreeSet<&str> = BTreeSet::new();
            for (tag, (name, _, generation)) in expiries {
                // The expiry map keys BOTH the allow and the reject-
                // companion tags to the same entry; identity is decided on
                // the allow (the broadening rule) only.
                if *tag != super::network::dns_rule_tag(name, *generation)
                    || !checked.insert(name.as_str())
                {
                    continue;
                }
                let allow_installed = dynamic_rules
                    .iter()
                    .filter(|rule| rule.description == *tag && rule.action.as_str() == "allow")
                    .all(|rule| current_dynamic.contains(&planned_id(rule)));
                if allow_installed {
                    continue;
                }
                let identity_known = history
                    .as_ref()
                    .is_some_and(|state| state.generations.get(name).copied() == Some(*generation))
                    // The tombstone records the torn-down incarnation's
                    // HIGH-WATER generation: identities AT OR BELOW it were
                    // possibly issued (and may carry still-deferred
                    // requests or evidence) and must never be re-added;
                    // anything above is a fresh, never-issued identity.
                    || tombstone
                        .generations
                        .get(name)
                        .is_some_and(|floor| *generation <= *floor)
                    || evidence.iter().any(|(evidence_tag, _)| evidence_tag == tag);
                if identity_known {
                    reissue.push(name.clone());
                }
            }
            if !reissue.is_empty() {
                return Ok(ReplacementOutcome {
                    installed: Vec::new(),
                    revoked: Vec::new(),
                    uncertain: Vec::new(),
                    reissue,
                });
            }
        }
        // Ordinary publication replaces the complete ruleset in one atomic
        // request. Recovery of uncertain legacy mutations still uses the proven
        // identity-specific fence/withdrawal boundary below: those obligations
        // must settle before a clean whole-policy replacement is safe.
        let marker = self.read_dns_revocation_record(sandbox_id, hash)?;
        let clean = self.supports_atomic_acl_updates()
            && !revoke_only
            && marker.as_ref().is_none_or(|record| {
                record.pending.is_empty() && record.standing_fences.is_empty()
            })
            && self.read_dns_lease_releases(sandbox_id)?.is_empty()
            && !observed
                .egress
                .iter()
                .any(|rule| super::network::is_dns_fence_tag(&rule.description));
        #[cfg(test)]
        let clean = clean && !self.force_legacy_dns_recovery;
        if clean {
            'atomic: {
                let now = self.dns_clock.unix_now()?;
                // The whole-policy write also withdraws superseded identities.
                // Serialize with expiry until that withdrawal is durably retired.
                let lease_owner = self.dns_lease_owner(sandbox_id);
                let mut lease_state = self.lock_runtime(&lease_owner.state)?;
                let obligations = lease_state.armed.clone();
                let lifetime = expiries
                    .values()
                    .map(|(_, expires_at, _)| *expires_at)
                    .chain(obligations.iter().map(|entry| entry.expires_at))
                    .map(|expiry| expiry.saturating_sub(now))
                    .min();
                if lifetime.is_none_or(|remaining| remaining > 0) {
                    let mut identities = BTreeSet::new();
                    if observed
                        .egress
                        .iter()
                        .filter(|rule| is_dynamic(rule))
                        .any(|rule| !identities.insert(observed_id(rule)))
                    {
                        return Err(internal_error(
                            "duplicate dynamic ACL rule; refusing to ratify drift",
                        ));
                    }
                    let intents: Vec<PendingMutation> = dynamic_rules
                        .iter()
                        .filter(|rule| rule.action.as_str() == "allow")
                        .filter_map(|rule| {
                            expiries
                                .get(&rule.description)
                                .map(|(domain, _, _)| PendingMutation {
                                    name: domain.clone(),
                                    destination: rule.destination.clone().unwrap_or_default(),
                                    description: rule.description.clone(),
                                    kind: PendingKind::Allow,
                                })
                        })
                        .collect();
                    // Journal every allow carried by the snapshot, including
                    // renewals. A timed-out PUT may still land at the daemon.
                    self.extend_dns_pending(sandbox_id, hash, &intents)?;
                    let now = self.dns_clock.unix_now()?;
                    let lifetime = expiries
                        .values()
                        .map(|(_, expiry, _)| *expiry)
                        .chain(obligations.iter().map(|entry| entry.expires_at))
                        .map(|expiry| expiry.saturating_sub(now))
                        .min();
                    let budget = lifetime
                        .map(Duration::from_secs)
                        .unwrap_or(self.agent_timeout)
                        .min(self.agent_timeout);
                    let deadline = Instant::now() + budget;
                    let updated = self.update_acl(acl_name, budget, |metadata| {
                    if expiries.values().any(|(_, expiry, _)| {
                        *expiry <= self.dns_clock.unix_now().unwrap_or(u64::MAX)
                    }) {
                        return Err(internal_error("DNS grant expired before atomic ACL update"));
                    }
                    if metadata["config"][super::network::NETWORK_SANDBOX_TAG].as_str()
                        != observed.sandbox_tag.as_deref()
                        || metadata["config"][super::network::NETWORK_PROJECT_TAG].as_str()
                            != observed.project_tag.as_deref()
                    {
                        return Err(super::acl::foreign_object("network acl", acl_name));
                    }
                    for (key, expected) in
                        [("ingress", &observed.ingress), ("egress", &observed.egress)]
                    {
                        let current = metadata
                            .get(key)
                            .and_then(serde_json::Value::as_array)
                            .ok_or_else(|| internal_error("missing ACL rule list"))?;
                        let current: Vec<_> = current
                            .iter()
                            .map(super::acl::ObservedRule::from_json)
                            .collect::<Result<_, _>>()?;
                        if &current != expected {
                            return Err(internal_error(
                                "ACL changed before atomic policy update; retry after settlement",
                            ));
                        }
                    }
                    metadata["egress"] = observed
                        .egress
                        .iter()
                        .filter(|rule| !is_dynamic(rule))
                        .map(|rule| rule.as_acl_rule(super::network::AclDirection::Egress))
                        .collect::<Result<Vec<_>, _>>()?
                        .iter()
                        .chain(dynamic_rules)
                        .map(super::acl::api_rule)
                        .collect::<Vec<_>>()
                        .into();
                    Ok(())
                });
                    if let Err(error) = updated {
                        if self.supports_atomic_acl_updates() {
                            return Err(error);
                        }
                        // A parser refusal proves no request was sent. No atomic
                        // uncertainty remains; use the older CLI's proven writer.
                        self.retire_dns_pending(sandbox_id, hash, &intents)?;
                        break 'atomic;
                    }
                    let after = self
                        .read_sandbox_acl_within(
                            acl_name,
                            Some(deadline.saturating_duration_since(Instant::now())),
                        )?
                        .ok_or_else(|| {
                            internal_error("sandbox ACL vanished after atomic update")
                        })?;
                    let desired: Vec<AclRule> = observed
                        .egress
                        .iter()
                        .filter(|rule| !is_dynamic(rule))
                        .map(|rule| rule.as_acl_rule(super::network::AclDirection::Egress))
                        .collect::<Result<Vec<_>, _>>()?
                        .into_iter()
                        .chain(dynamic_rules.iter().cloned())
                        .collect();
                    if after.sandbox_tag != observed.sandbox_tag
                        || after.project_tag != observed.project_tag
                        || after.ingress != observed.ingress
                        || after.egress.len() != desired.len()
                        || !after
                            .egress
                            .iter()
                            .zip(&desired)
                            .all(|(actual, wanted)| actual.matches_plan(wanted))
                    {
                        return Err(internal_error(
                            "atomic ACL update differs from the refreshed plan",
                        ));
                    }
                    if expiries.values().any(|(_, expiry, _)| {
                        *expiry <= self.dns_clock.unix_now().unwrap_or(u64::MAX)
                    }) {
                        return Err(internal_error("DNS grant expired during atomic ACL update"));
                    }
                    self.retire_dns_pending(sandbox_id, hash, &intents)?;
                    // No unresolved legacy write entered this path. The
                    // successful conditional PUT and exact readback prove all
                    // omitted identities absent; the revision fences late PUTs.
                    // Keeping their leases would trigger redundant per-rule
                    // expiry work on every subsequent rotation and restart.
                    let current_tags: BTreeSet<&str> =
                        expiries.keys().map(String::as_str).collect();
                    let retired: BTreeSet<(String, String)> = lease_state
                        .armed
                        .iter()
                        .filter(|entry| !current_tags.contains(entry.allow_tag.as_str()))
                        .flat_map(|entry| {
                            entry
                                .destinations
                                .iter()
                                .map(|dest| (entry.allow_tag.clone(), dest.clone()))
                        })
                        .collect();
                    self.persist_dns_lease_withdrawals(sandbox_id, &retired)?;
                    let survivors: Vec<_> = lease_state
                        .armed
                        .iter()
                        .filter(|entry| current_tags.contains(entry.allow_tag.as_str()))
                        .cloned()
                        .collect();
                    self.persist_dns_lease_obligations(sandbox_id, &survivors)?;
                    lease_state.armed = survivors;
                    lease_owner.wake.notify_all();
                    drop(lease_state);
                    let installed = after
                        .ingress
                        .iter()
                        .map(|rule| rule.as_acl_rule(super::network::AclDirection::Ingress))
                        .chain(
                            after
                                .egress
                                .iter()
                                .map(|rule| rule.as_acl_rule(super::network::AclDirection::Egress)),
                        )
                        .collect::<Result<Vec<_>, _>>()?;
                    return Ok(ReplacementOutcome {
                        installed,
                        revoked: Vec::new(),
                        uncertain: Vec::new(),
                        reissue: Vec::new(),
                    });
                }
            }
        }
        // Fencing commands run through an INDEPENDENTLY bounded, permit-free
        // client (C36 r16 F1): a cancelled issuing permit may be exactly WHY
        // enforcement is fencing.
        let fence_client = {
            let mut client = self.clone();
            client.cancelled = None;
            client
        };
        // ---------------- preventive fences (C36 r17) ----------------
        let marker = self.read_dns_revocation_record(sandbox_id, hash)?;
        let pending_releases: BTreeSet<String> = marker
            .iter()
            .flat_map(|record| record.pending.iter())
            .filter(|pending| pending.kind == PendingKind::FenceRelease)
            .map(|pending| pending.description.clone())
            .collect();
        // The LEASE's own release journal is equally disqualifying at
        // every adoption site (C36 r24 F1): a lease fence whose removal
        // the lease issued but could not prove may still complete
        // daemon-side at any time, so adopting it as THIS pass's fence
        // (and removing the newer refresh fence around the same
        // destination) could leave the destination unfenced behind an
        // uncertain allow. Refresh and lease fences share the canonical
        // shape, so both journals exclude.
        // An UNREADABLE journal (C36 r25 F4) means the release-uncertain
        // set is UNKNOWN: no adoption gate may treat any existing fence
        // as reliable — `None` excludes every candidate below so the
        // pass installs fresh identities instead of adopting.
        let lease_releases: Option<BTreeSet<String>> =
            self.read_dns_lease_releases(sandbox_id).ok();
        let mut needed_fence_dests: BTreeSet<String> = BTreeSet::new();
        let lease_withdrawn = self.read_dns_lease_withdrawals(sandbox_id);
        for pending in marker
            .iter()
            .flat_map(|record| record.pending.iter())
            .filter(|pending| pending.kind == PendingKind::Allow)
        {
            // A positively lease-withdrawn mutation is RESOLVED (the lease
            // observed and removed its exact rule, proving the request
            // completed): it needs no fence. The entry may still be
            // journaled here — the uncertain path re-journals on unproven
            // absence when the lease wins the withdrawal race (the killed
            // CLI's deadline IS the grant's expiry); the drain retires it
            // at commit.
            if lease_withdrawn.contains(&(pending.description.clone(), pending.destination.clone()))
            {
                continue;
            }
            // Necessity from the COMPLETE effective authorization (C36 r17
            // F5): any live planned grant or covering static CIDR.
            if !authorized_dests.contains(&pending.destination)
                && !static_covered(&pending.destination)
            {
                needed_fence_dests.insert(pending.destination.clone());
            }
        }
        // Standing fence obligations (C36 r22 F2, r23 F2): unresolved
        // allow mutations whose ACL incarnation is gone. The deferred
        // apply may land on ANY future same-named ACL, so every plan
        // fences the destination until the policy authorizes it again;
        // the release then runs through the ordinary journaled
        // fence-release path. Authorization SUPPRESSES the fence — the
        // obligation itself survives, so expiry of a temporary
        // reauthorization re-fences the destination (C36 r23 F2).
        for standing in marker
            .iter()
            .flat_map(|record| record.standing_fences.iter())
        {
            let dest = standing.destination();
            if !authorized_dests.contains(dest) && !static_covered(dest) {
                needed_fence_dests.insert(dest.to_string());
            }
        }
        let identity_floor = expiries
            .values()
            .map(|(_, _, generation)| *generation)
            .chain(
                observed
                    .egress
                    .iter()
                    .filter_map(|rule| super::network::dns_tag_request_id(&rule.description)),
            )
            .chain(marker.iter().flat_map(|record| {
                record
                    .pending
                    .iter()
                    .filter_map(|pending| super::network::dns_tag_request_id(&pending.description))
            }))
            .max()
            .unwrap_or(0);
        let parse_fence_addr = |dest: &str| -> Result<Ipv4Addr, RuntimeError> {
            dest.strip_suffix("/32")
                .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
                .ok_or_else(|| internal_error("pending DNS fence destination is not an IPv4 /32"))
        };
        let mut desired_fences: Vec<AclRule> = Vec::new();
        let mut fences_added: Vec<RuleId> = Vec::new();
        let mut fenced_dests: BTreeSet<String> = BTreeSet::new();
        for dest in &needed_fence_dests {
            // A fence is RELIABLE only with the COMPLETE canonical identity
            // (C36 r18 F8) and no unresolved release targeting it (C36 r17
            // F4); a narrowed, disabled, or release-pending fence is never
            // trusted — a fresh one is issued and the drift is removed by
            // the diff below.
            if let Some(rule) = observed.egress.iter().find(|rule| {
                is_canonical_dns_fence(rule, dest)
                    && !pending_releases.contains(&rule.description)
                    && lease_releases
                        .as_ref()
                        .is_some_and(|releases| !releases.contains(&rule.description))
            }) {
                desired_fences.push(rule.as_acl_rule(super::network::AclDirection::Egress)?);
                fenced_dests.insert(dest.clone());
                continue;
            }
            let epoch = self.allocate_dns_requests(sandbox_id, hash, identity_floor, 1)?;
            let fence = super::network::domain_fence_rule(parse_fence_addr(dest)?, epoch);
            let mut qargs = vec![
                "network".to_string(),
                "acl".to_string(),
                "rule".to_string(),
                "add".to_string(),
                acl_name.to_string(),
                "egress".to_string(),
            ];
            qargs.extend(fence.cli_args());
            let out =
                fence_client.run(&qargs.iter().map(String::as_str).collect::<Vec<_>>(), false)?;
            if out.exit_code != 0 {
                // Deny-direction install failed BEFORE any broadening: fail
                // closed; the journaled pending entries keep readiness
                // fenced and the next pass retries.
                return Err(host_cli_error("network acl rule add", &out));
            }
            fenced_dests.insert(dest.clone());
            fences_added.push(planned_id(&fence));
            desired_fences.push(fence);
        }
        let desired: BTreeSet<RuleId> = dynamic_rules
            .iter()
            .chain(&desired_fences)
            .map(planned_id)
            .collect();
        let removal_args = |id: &RuleId| acl_rule_removal_args(acl_name, id);
        let removals: Vec<RuleId> = current_dynamic.difference(&desired).cloned().collect();
        // Coverage means a SURVIVING, VERIFIED authorization OUTSIDE the
        // identity being retired or repaired (C36 r22 F3): an installed
        // allow for this destination whose ENTIRE canonical group — the
        // allow plus its three DNS/DoT reject companions — is observed
        // on the ACL NOW and is NOT scheduled for removal this pass.
        // Desired-answer membership proves nothing about the DNS
        // restriction the coverage claim relies on: withdrawals run
        // BEFORE additions, so the repaired identity's fresh companions
        // are not installed yet, and its stale ones are being removed —
        // treating it as coverage would withdraw the surviving allow
        // into an ACL with an unrestricted resolver path.
        let removal_id_set: BTreeSet<&RuleId> = removals.iter().collect();
        let verified_cover = |dest: &str| -> bool {
            // THE shared effective-authorization predicate (C36 r25 F3):
            // a complete, ENABLED group, exactly as settlement requires.
            current_dynamic.iter().any(|allow| {
                dns_allow_id_is_effective_cover(allow, dest, "")
                    && !removal_id_set.contains(allow)
                    && dns_reject_companion_ids(allow).iter().all(|companion| {
                        current_dynamic.contains(companion) && !removal_id_set.contains(companion)
                    })
            })
        };
        // NARROWING (deny-direction) withdrawals are bounded by the
        // earliest working grant's deadline measured at pass start (C36
        // r17 F3): the expiry lease enforces the absolute deadline
        // independently, so an overrunning withdrawal is safe, and a
        // per-call shrinking budget would only guarantee a deadline kill
        // — an UNCERTAIN removal — on slow passes (C36 r18 F7: the
        // at-issuance recheck matters where the operation BROADENS).
        let removal_budget: Option<Duration> = {
            let now = self.dns_clock.unix_now()?;
            expiries
                .values()
                .map(|(_, expires_at, _)| expires_at.saturating_sub(now))
                .filter(|remaining| *remaining > 0)
                .min()
                .map(Duration::from_secs)
        };
        // BROADENING operations (allow issuance, fence release) are bounded
        // by the remaining lifetime measured AT THE CALL (C36 r18 F7).
        let live_budget = || -> Result<Option<Duration>, RuntimeError> {
            let now = self.dns_clock.unix_now()?;
            Ok(expiries
                .values()
                .map(|(_, expires_at, _)| expires_at.saturating_sub(now))
                .filter(|remaining| *remaining > 0)
                .min()
                .map(Duration::from_secs))
        };
        // Reject-repair safety (fence tags excluded: a fence release never
        // justifies tearing down the allow it covered — the destination is
        // authorized exactly when the fence is released). The overlapping-
        // allow withdrawal triggers ONLY when a DESIRED reject is missing
        // (C36 r20 F2): merely STALE rejects — leftovers of an older
        // generation — are pure narrowing removals the destination phase
        // sequences behind the withdrawal boundary; withdrawing the live
        // allow for them would force a fresh issuance, whose own rejects
        // are then the stale ones — a loop that never converges on a
        // destination shared with another grant.
        let reject_dests: BTreeSet<&str> = desired
            .iter()
            .filter(|id| {
                id.1 != "allow"
                    && !super::network::is_dns_fence_tag(&id.0)
                    && !current_dynamic.contains(*id)
                    // ... whose ALLOW is installed (the exposure case): a
                    // missing reject of an identity whose allow is not
                    // installed yet is just a fresh issuance — the add
                    // phase installs rejects before allows, and withdrawing
                    // a nonexistent allow here (then reissuing) would churn
                    // generations forever on shared destinations.
                    && id.0
                        .strip_prefix("wssp-dns-reject-")
                        .map(|rest| format!("wssp-dns-{rest}"))
                        .is_some_and(|allow_tag| {
                            current_dynamic
                                .iter()
                                .any(|a| a.1 == "allow" && a.0 == allow_tag && a.7 == id.7)
                        })
            })
            .map(|id| id.7.as_str())
            .collect();
        let mut removed_allows: BTreeSet<RuleId> = BTreeSet::new();
        let mut reissue_names: Vec<String> = Vec::new();
        // Refresh-side fences come from the marker-counter family — the
        // expiry lease never enters this read-modify-write and vice
        // versa (C36 r18 F1).
        let mut pass_fence_alloc = |dest: &str| -> Result<super::network::AclRule, RuntimeError> {
            let epoch = self.allocate_dns_requests(sandbox_id, hash, identity_floor, 1)?;
            Ok(super::network::domain_fence_rule(
                parse_fence_addr(dest)?,
                epoch,
            ))
        };
        if !reject_dests.is_empty() {
            for id in &current_dynamic {
                if id.1 == "allow" && reject_dests.contains(id.7.as_str()) {
                    // THE shared destination-withdrawal boundary (C36
                    // r19 F3): proven withdrawal only, and an unproven
                    // one fences the destination (unless it is otherwise
                    // covered) BEFORE the pass fails — companions of the
                    // destination are never touched while an overlapping
                    // allow might still be installed.
                    let covered = verified_cover(&id.7) || static_covered(&id.7);
                    self.enforce_destination_withdrawal(
                        sandbox_id,
                        acl_name,
                        &id.7,
                        std::slice::from_ref(&id.0),
                        &[],
                        false,
                        covered,
                        removal_budget,
                        None,
                        false,
                        &mut pass_fence_alloc,
                    )?;
                    removed_allows.insert(id.clone());
                    if desired.contains(id) {
                        // A restore is a NEW issuance, never a re-use of
                        // the withdrawn identity (C36 r20 F2): a still-
                        // deferred earlier request may be carrying it, and
                        // its durable withdrawal evidence would retire the
                        // new request's pending entry. The removal above
                        // already made the destination safe; the caller
                        // allocates a fresh generation and re-plans, and
                        // the next pass re-adds under the new identity.
                        if let Some((name, _, _)) = expiries.get(id.0.as_str()) {
                            reissue_names.push(name.clone());
                        }
                    }
                }
            }
        }
        if !reissue_names.is_empty() {
            return Ok(ReplacementOutcome {
                installed: Vec::new(),
                revoked: Vec::new(),
                uncertain: Vec::new(),
                reissue: reissue_names,
            });
        }
        let mut fence_diff_kept: Vec<RuleId> = Vec::new();
        // Destination-level withdrawal through THE shared boundary (C36
        // r18 F2/F3, C36 r19 F3): per destination, EVERY allow is proven
        // absent — clean exit, proven-absence daemon reply, or a --force
        // retry of a duplicate-match refusal — and only then are that
        // destination's companions removed. An unproven allow fences
        // its destination (unless otherwise covered) and fails the pass
        // with every companion still installed; a rejected removal is
        // never mistaken for a successful one.
        let mut dest_groups: BTreeMap<String, (Vec<String>, Vec<String>)> = BTreeMap::new();
        for id in removals
            .iter()
            .filter(|id| !super::network::is_dns_fence_tag(&id.0))
        {
            let group = dest_groups.entry(id.7.clone()).or_default();
            if id.1 == "allow" {
                if !removed_allows.contains(id) {
                    group.0.push(id.0.clone());
                }
            } else {
                group.1.push(id.0.clone());
            }
        }
        // Stale LEASE fences (C36 r20 F1): a destination losing ALL
        // authorization this pass has its lease fence withdrawn WITH the
        // destination's other rules — companion position, after the allow
        // is proven gone, so the fence never comes down early. A
        // destination that KEEPS a live authorization (a renewal racing
        // the fence's install at expiry) releases the fence only post-add,
        // linearized against the lease, in the release phase below.
        let mut stale_lease_fences: Vec<RuleId> = Vec::new();
        // Lease fences withdrawn as COMPANIONS of a losing destination
        // are journaled in the lease's own release journal exactly like
        // the lease's Phase C removals (C36 r24 F1): a companion removal
        // that proves UNCERTAIN would otherwise leave no record, and a
        // later adoption site could then trust a fence whose deferred
        // daemon-side removal may still complete. The journal write
        // serializes against the lease through the OWNER lock (the
        // lease is otherwise the journal's sole writer), and it lands
        // BEFORE the destination-withdrawal loop issues any removal.
        let mut companion_lease_fences: Vec<RuleId> = Vec::new();
        for id in removals
            .iter()
            .filter(|id| super::network::is_dns_lease_fence_tag(&id.0))
        {
            if !authorized_dests.contains(&id.7) && !static_covered(&id.7) {
                companion_lease_fences.push(id.clone());
                dest_groups
                    .entry(id.7.clone())
                    .or_default()
                    .1
                    .push(id.0.clone());
            } else {
                stale_lease_fences.push(id.clone());
            }
        }
        if !companion_lease_fences.is_empty() {
            let owner = self.dns_lease_owner(sandbox_id);
            let _lease_guard = owner.state.lock().unwrap_or_else(|err| err.into_inner());
            let mut releases = self.read_dns_lease_releases(sandbox_id)?;
            releases.extend(companion_lease_fences.iter().map(|id| id.0.clone()));
            self.persist_dns_lease_releases(sandbox_id, &releases)?;
        }
        // Refresh-family fences leaving the desired set on destinations
        // that KEEP an authorization (C36 r23 F3): NEVER released up
        // front, before the replacement rules exist — the fence may be
        // the only thing standing between an older unresolved allow and
        // open DNS/DoT egress, and a stalled or failed companion
        // installation would then leave that allow effective. Their
        // release defers to the post-add phase, behind verified
        // replacement authorization and the lease-owner synchronization.
        // Planned answers are NOT release evidence. (Fences on
        // destinations losing ALL authorization are withdrawn right
        // after the destination-withdrawal loop below, as before.)
        let mut deferred_fence_releases: Vec<RuleId> = Vec::new();
        for id in removals.iter().filter(|id| {
            id.1 != "allow"
                && super::network::is_dns_fence_tag(&id.0)
                && !super::network::is_dns_lease_fence_tag(&id.0)
                && (authorized_dests.contains(&id.7) || static_covered(&id.7))
        }) {
            deferred_fence_releases.push(id.clone());
        }
        for (dest, (allow_tags, companion_tags)) in &dest_groups {
            let covered = verified_cover(dest) || static_covered(dest);
            let outcome = self.enforce_destination_withdrawal(
                sandbox_id,
                acl_name,
                dest,
                allow_tags,
                companion_tags,
                false,
                covered,
                removal_budget,
                None,
                false,
                &mut pass_fence_alloc,
            )?;
            if !outcome.companion_failures.is_empty() {
                return Err(internal_error("a DNS reject companion would not withdraw"));
            }
            // Companions proven withdrawn retire their release-journal
            // entries (C36 r24 F1); a fence whose removal was uncertain
            // stays journaled — but the failure above already failed the
            // pass, so only proven removals reach here.
            let retired: Vec<String> = companion_lease_fences
                .iter()
                .filter(|id| id.7 == *dest)
                .filter(|id| !outcome.companion_failures.contains(*id))
                .map(|id| id.0.clone())
                .collect();
            if !retired.is_empty() {
                let owner = self.dns_lease_owner(sandbox_id);
                let _lease_guard = owner.state.lock().unwrap_or_else(|err| err.into_inner());
                let mut releases = self.read_dns_lease_releases(sandbox_id)?;
                for tag in &retired {
                    releases.remove(tag);
                }
                self.persist_dns_lease_releases(sandbox_id, &releases)?;
            }
        }
        // Companion removals ran inside the destination-withdrawal
        // boundary above (per-destination, after that destination's
        // allows were proven — C36 r19 F3). So do the fences of
        // destinations losing ALL authorization (C36 r23 F3): only
        // releases BEHIND a verified replacement defer to the post-add
        // phase.
        for id in removals.iter().filter(|id| {
            id.1 != "allow"
                && super::network::is_dns_fence_tag(&id.0)
                && !super::network::is_dns_lease_fence_tag(&id.0)
                && !deferred_fence_releases.contains(id)
        }) {
            // Broadening removal (C36 r17 F4): journaled pre-issuance;
            // the entry retires only on definitive evidence.
            let entry = PendingMutation {
                name: id.7.trim_end_matches("/32").to_string(),
                destination: id.7.clone(),
                description: id.0.clone(),
                kind: PendingKind::FenceRelease,
            };
            self.extend_dns_pending(sandbox_id, hash, std::slice::from_ref(&entry))?;
            match self.withdraw_rule_proven(acl_name, id, live_budget()?) {
                Err(err) => return Err(err),
                Ok(WithdrawalProof::Unproven) => {
                    // Unproven: the rule stays EXPECTED below; the entry
                    // stays journaled and a still-needed fence is
                    // re-issued under a fresh epoch on the next pass.
                    fence_diff_kept.push(id.clone());
                }
                Ok(WithdrawalProof::PositivelyWithdrawn | WithdrawalProof::ProvenAbsent) => {
                    self.retire_dns_pending(sandbox_id, hash, std::slice::from_ref(&entry))?;
                }
            }
        }
        enum AddOutcome {
            Applied,
            Uncertain,
            Rejected(super::client::IncusCommandOutput),
        }
        let add_rule =
            |rule: &AclRule, budget: Option<Duration>| -> Result<AddOutcome, RuntimeError> {
                let mut args = vec![
                    "network".to_string(),
                    "acl".to_string(),
                    "rule".to_string(),
                    "add".to_string(),
                    acl_name.to_string(),
                    "egress".to_string(),
                ];
                args.extend(rule.cli_args());
                let result = match budget {
                    Some(budget) => self.run_bounded(&args, false, budget),
                    None => self.run(&args, false),
                };
                let out = match result {
                    Ok(out) => out,
                    Err(err)
                        if budget.is_some()
                            && matches!(
                                err.code,
                                SandboxErrorCode::Timeout | SandboxErrorCode::UnknownOutcome
                            ) =>
                    {
                        return Ok(AddOutcome::Uncertain);
                    }
                    Err(err) => return Err(err),
                };
                if out.exit_code != 0 {
                    return Ok(AddOutcome::Rejected(out));
                }
                Ok(AddOutcome::Applied)
            };
        let mut revoked_domains: BTreeSet<String> = BTreeSet::new();
        let mut revoked_tags: BTreeSet<String> = BTreeSet::new();
        let mut added_ids: Vec<RuleId> = Vec::new();
        let mut pending_mutations: Vec<PendingMutation> = Vec::new();
        let mut confirmed_dests: BTreeSet<String> = current_dynamic
            .intersection(&desired)
            .filter(|id| id.1 == "allow")
            .map(|id| id.7.clone())
            .collect();
        // The grant (absolute expiry) authorizing each confirmed
        // destination: the fence-release phase re-verifies the grant is
        // STILL LIVE before releasing the fence (C36 r18 F7).
        let mut confirmed_grants: BTreeMap<String, (u64, String, u64)> = current_dynamic
            .intersection(&desired)
            .filter(|id| id.1 == "allow")
            .filter_map(|id| {
                expiries
                    .get(id.0.as_str())
                    .map(|(domain, expires_at, generation)| {
                        (id.7.clone(), (*expires_at, domain.clone(), *generation))
                    })
            })
            .collect();
        for id in &removed_allows {
            // Every withdrawn allow de-authorizes its destination for the
            // rest of this pass: a still-desired one comes back under a
            // FRESH identity via the reissue re-plan above (C36 r20 F2),
            // never as an in-pass restore of the withdrawn identity. But a
            // destination SURVIVING on another grant's allow — still
            // desired and never touched — stays authorized (C36 r17 F5):
            // de-authorizing it would fence a legitimately granted
            // destination mid-pass.
            let surviving = desired.iter().any(|other| {
                other.1 == "allow" && other.7 == id.7 && !removed_allows.contains(other)
            });
            if !surviving {
                confirmed_dests.remove(&id.7);
                confirmed_grants.remove(&id.7);
            }
        }
        // Fences ensured this pass for broadening requests, for the release
        // phase below: (destination, rule id).
        let mut ensured_fences: Vec<(String, RuleId)> = Vec::new();
        let fence_revoked = |revoked_domains: &mut BTreeSet<String>,
                             revoked_tags: &mut BTreeSet<String>,
                             domain: &str,
                             generation: u64| {
            revoked_domains.insert(domain.to_string());
            revoked_tags.insert(super::network::dns_rule_tag(domain, generation));
            revoked_tags.insert(super::network::dns_rule_reject_tag(domain, generation));
        };
        let mut add_live_rule = |rule: &AclRule| -> Result<(), RuntimeError> {
            // Cheap early-out only; the binding lifetime check runs
            // IMMEDIATELY BEFORE issuance below (C36 r18 F7).
            if let Some((domain, expires_at, generation)) = expiries.get(rule.description.as_str())
            {
                let now = self.dns_clock.unix_now()?;
                if expires_at.saturating_sub(now) == 0 {
                    fence_revoked(&mut revoked_domains, &mut revoked_tags, domain, *generation);
                }
            }
            if revoked_tags.contains(rule.description.as_str()) {
                return Ok(());
            }
            // Preventive fence BEFORE any broadening issuance (C36 r17 F2):
            // a destination not otherwise effectively authorized — no
            // covering static CIDR and no confirmed live allow — is fenced
            // FIRST, and the fence install failing means the allow is never
            // issued. A daemon crash after issuance leaves the fence in
            // place; a deferred daemon-side allow lands behind it.
            //
            // A fence installed by THIS invocation is tracked: if the
            // at-issuance recheck below revokes the grant, the mutation
            // provably never issued and the fence defends against nothing
            // (an earlier pass's fence for a pending marker is never
            // touched here — `fenced_dests` already skipped it).
            let mut installed_fence_here = false;
            if rule.action.as_str() == "allow" {
                let dest = rule.destination.clone().unwrap_or_default();
                // Current coverage at the ISSUANCE boundary (C36 r30
                // F2, sharpened C36 r31 F1): the authorization is a
                // complete rule group that SURVIVES this pass, checked
                // against the request identity's own armed grant. The
                // effective rule set is the pass-start observation
                // MINUS every rule this pass retires — a partial
                // rotation {X,Y}→{X,Z} withdraws the old generation's
                // group before additions, so that group must not
                // authorize the replacement allow for X — PLUS every
                // rule this pass has installed and confirmed, so a
                // same-pass sibling authorizes only through its own
                // unexpired, non-revoked armed entry (the destination-
                // only `issued_this_pass` shortcut is gone: a grant
                // that expired or was revoked mid-pass no longer
                // legitimizes later issuances on its destinations).
                // Obligations are re-read from disk at issuance (fail
                // closed on an unreadable ledger), revocations come
                // from the durable marker plus this pass's own. Expiry
                // is clock-based and revocation is journaled before any
                // mutation, so the fresh read is synchronized with
                // settlement: the watcher withdraws an identity only at
                // its expiry, which the gate excludes by the clock even
                // while the settlement's commit still waits on this
                // pass's lock. A genuinely LIVE overlapping grant still
                // passes (the inverse).
                let authorized_now = static_covered(&dest) || {
                    let (mut revoked_now, revoked_generations_now) =
                        match self.read_dns_revocation_record_unscoped(sandbox_id) {
                            Ok(Some(record)) => (record.revoked, record.revoked_generations),
                            Ok(None) => (Vec::new(), BTreeMap::new()),
                            Err(err) => return Err(err),
                        };
                    revoked_now.extend(revoked_domains.iter().cloned());
                    let mut effective: BTreeSet<RuleId> = current_dynamic
                        .iter()
                        .filter(|id| !removal_id_set.contains(*id))
                        .cloned()
                        .collect();
                    effective.extend(added_ids.iter().cloned());
                    self.dns_destination_authorized(
                        sandbox_id,
                        &effective,
                        &dest,
                        static_grants,
                        &revoked_now,
                        &revoked_generations_now,
                        "",
                    )?
                };
                if !authorized_now && !fenced_dests.contains(&dest) {
                    // Same canonical-identity requirement as the preventive
                    // phase (C36 r18 F8): a narrowed/disabled fence is
                    // drift, not protection.
                    let reliable = current_dynamic
                        .iter()
                        .find(|id| {
                            is_canonical_dns_fence_id(id, &dest)
                                && !removal_id_set.contains(*id)
                                && !pending_releases.contains(&id.0)
                                && lease_releases
                                    .as_ref()
                                    .is_some_and(|releases| !releases.contains(&id.0))
                        })
                        .cloned();
                    let fence_id = match reliable {
                        Some(id) => id,
                        None => {
                            let epoch =
                                self.allocate_dns_requests(sandbox_id, hash, identity_floor, 1)?;
                            let fence =
                                super::network::domain_fence_rule(parse_fence_addr(&dest)?, epoch);
                            let mut qargs = vec![
                                "network".to_string(),
                                "acl".to_string(),
                                "rule".to_string(),
                                "add".to_string(),
                                acl_name.to_string(),
                                "egress".to_string(),
                            ];
                            qargs.extend(fence.cli_args());
                            let out = fence_client.run(
                                &qargs.iter().map(String::as_str).collect::<Vec<_>>(),
                                false,
                            )?;
                            if out.exit_code != 0 {
                                return Err(host_cli_error("network acl rule add", &out));
                            }
                            let id = planned_id(&fence);
                            fences_added.push(id.clone());
                            installed_fence_here = true;
                            id
                        }
                    };
                    fenced_dests.insert(dest.clone());
                    ensured_fences.push((dest.clone(), fence_id));
                }
            }
            // Journal the broadening mutation BEFORE issuance (C36 r15/r17):
            // the entry retires on definitive evidence only.
            let intent = if rule.action.as_str() == "allow" {
                expiries
                    .get(rule.description.as_str())
                    .map(|(domain, _, _)| PendingMutation {
                        name: domain.clone(),
                        destination: rule.destination.clone().unwrap_or_default(),
                        description: rule.description.clone(),
                        kind: PendingKind::Allow,
                    })
            } else {
                None
            };
            if let Some(intent) = &intent {
                self.extend_dns_pending(sandbox_id, hash, std::slice::from_ref(intent))?;
            }
            // The binding lifetime check (C36 r18 F7): fence installation
            // and the durable journal write above consume wall clock
            // against the grant's ABSOLUTE deadline, so the budget is
            // derived NOW — an authorization that expired under the fencing
            // work is revoked here and its allow is never issued, and a
            // live grant is issued with its ACTUAL remaining budget.
            let mut budget: Option<Duration> = None;
            if let Some((domain, expires_at, generation)) = expiries.get(rule.description.as_str())
            {
                let now = self.dns_clock.unix_now()?;
                let remaining = expires_at.saturating_sub(now);
                if remaining == 0 {
                    fence_revoked(&mut revoked_domains, &mut revoked_tags, domain, *generation);
                    // The journaled mutation provably NEVER issued (we hold
                    // the decision): retire the intent immediately rather
                    // than leave the destination fenced forever.
                    if let Some(intent) = &intent {
                        self.retire_dns_pending(sandbox_id, hash, std::slice::from_ref(intent))?;
                    }
                    // Nothing was issued, so the preventive fence this
                    // invocation just installed guards no uncertain state;
                    // remove it again (best effort — a leftover only
                    // over-denies a destination that has no grant at all,
                    // and default-deny still covers it).
                    if installed_fence_here {
                        let dest = rule.destination.clone().unwrap_or_default();
                        if let Some(position) = ensured_fences.iter().position(|(d, _)| *d == dest)
                        {
                            let (_, fence_id) = ensured_fences.remove(position);
                            let args = removal_args(&fence_id);
                            let removed = fence_client
                                .run(&args.iter().map(String::as_str).collect::<Vec<_>>(), false)
                                .map(|out| out.exit_code == 0)
                                .unwrap_or(false);
                            if removed {
                                fences_added.retain(|id| *id != fence_id);
                                fenced_dests.remove(&dest);
                            }
                        }
                    }
                    return Ok(());
                }
                let earliest_other = expiries
                    .values()
                    .filter(|(other, _, _)| !revoked_domains.contains(other))
                    .map(|(_, other_expiry, _)| other_expiry.saturating_sub(now))
                    .min()
                    .unwrap_or(remaining);
                budget = Some(Duration::from_secs(remaining.min(earliest_other)));
            }
            match add_rule(rule, budget)? {
                AddOutcome::Applied => {
                    if let Some(intent) = &intent {
                        self.retire_dns_pending(sandbox_id, hash, std::slice::from_ref(intent))?;
                    }
                    if rule.action.as_str() == "allow" {
                        let dest = rule.destination.clone().unwrap_or_default();
                        confirmed_dests.insert(dest.clone());
                        if let Some((domain, expires_at, generation)) =
                            expiries.get(rule.description.as_str())
                        {
                            confirmed_grants
                                .insert(dest, (*expires_at, domain.clone(), *generation));
                        }
                    }
                    added_ids.push(planned_id(rule));
                }
                AddOutcome::Rejected(out) if cli_daemon_rejected(&out) => {
                    if let Some(intent) = &intent {
                        self.retire_dns_pending(sandbox_id, hash, std::slice::from_ref(intent))?;
                    }
                    return Err(host_cli_error("network acl rule add", &out));
                }
                // Uncertain, OR a nonzero exit WITHOUT positive rejection
                // evidence (C36 r16 F4).
                _ => {
                    // The destination is already fenced (preventive fence
                    // above) whenever it is not otherwise authorized: the
                    // journaled pending entry keeps the marker (and its
                    // readiness fence) alive past the commit until
                    // definitive reconciliation.
                    if let Some((domain, _, generation)) = expiries.get(rule.description.as_str()) {
                        fence_revoked(&mut revoked_domains, &mut revoked_tags, domain, *generation);
                    }
                    let now = self.dns_clock.unix_now()?;
                    for (domain, expires_at, generation) in expiries.values() {
                        if *expires_at <= now {
                            fence_revoked(
                                &mut revoked_domains,
                                &mut revoked_tags,
                                domain,
                                *generation,
                            );
                        }
                    }
                    // Best-effort withdrawal through the fence client too:
                    // the issuing permit may be revoked.
                    let args = removal_args(&planned_id(rule));
                    let withdrawn = fence_client
                        .run(&args.iter().map(String::as_str).collect::<Vec<_>>(), false)
                        .map(|out| out.exit_code == 0)
                        .unwrap_or(false);
                    if withdrawn {
                        // Proven withdrawal (C36 r17): a clean exit means the
                        // daemon positively matched and removed the rule —
                        // the uncertain request had ALREADY completed
                        // daemon-side (that is why the removal matched) and
                        // a request completes at most once. This is the same
                        // evidence reconcile retires on; keeping the journal
                        // entry would fence readiness forever, because
                        // reconcile could never observe the rule again and
                        // absence alone is not proof. The mutation is
                        // RESOLVED, not pending: it must not enter the
                        // pass's unresolved-uncertain list either — the
                        // caller would re-journal it.
                        if let Some(intent) = &intent {
                            self.retire_dns_pending(
                                sandbox_id,
                                hash,
                                std::slice::from_ref(intent),
                            )?;
                        }
                    } else if let Some(intent) = &intent {
                        pending_mutations.push(intent.clone());
                    }
                }
            }
            Ok(())
        };
        if !revoke_only {
            for rule in dynamic_rules
                .iter()
                .filter(|rule| !current_dynamic.contains(&planned_id(rule)))
            {
                add_live_rule(rule)?;
            }
        }
        // Withdraw companions that landed before their domain lapsed —
        // allow before companions, proven classification, same as the main
        // removal phase (C36 r18 F2/F3).
        // Lapsed-grant sweep, again through THE shared boundary per
        // destination (C36 r19 F3): an unproven allow fences its
        // destination before the pass fails.
        let swept: Vec<RuleId> = added_ids
            .iter()
            .filter(|id| revoked_tags.contains(id.0.as_str()))
            .cloned()
            .collect();
        let mut swept_groups: BTreeMap<String, (Vec<String>, Vec<String>)> = BTreeMap::new();
        for id in &swept {
            let group = swept_groups.entry(id.7.clone()).or_default();
            if id.1 == "allow" {
                group.0.push(id.0.clone());
            } else {
                group.1.push(id.0.clone());
            }
        }
        for (dest, (allow_tags, companion_tags)) in &swept_groups {
            let covered = verified_cover(dest) || static_covered(dest);
            let outcome = self.enforce_destination_withdrawal(
                sandbox_id,
                acl_name,
                dest,
                allow_tags,
                companion_tags,
                false,
                covered,
                removal_budget,
                None,
                false,
                &mut pass_fence_alloc,
            )?;
            if !outcome.companion_failures.is_empty() {
                return Err(internal_error(
                    "a lapsed DNS grant's rule is not proven withdrawn",
                ));
            }
        }
        // Fence release (C36 r17 F2/F4/F5): a fence ensured this pass for a
        // request that COMPLETED — its allow is confirmed applied, so the
        // destination is authorized — is released. The release is itself a
        // broadening removal: journaled pre-issuance, retired only on
        // definitive evidence; an unproven outcome keeps the entry and the
        // fence stays expected below (over-denial only, retried later).
        //
        // ALL fence release is linearized against the expiry lease under
        // the owner lock (C36 r20 F1): the lease holds that lock across its
        // fence-then-withdraw, so a release here can never open a window
        // between the lease's fence check and its withdrawal — and a
        // destination with a DUE armed obligation is never released at
        // all, because its settle is imminent and fences it first.
        let owner = self.dns_lease_owner(sandbox_id);
        let lease_state = owner.state.lock().unwrap_or_else(|err| err.into_inner());
        // ONE absolute deadline carries across the ENTIRE owner-locked
        // release phase (C36 r24 F2): the earliest future expiry among
        // this pass's grants AND the lease's armed obligations. A
        // per-call recomputed `live_budget` DROPS deadlines that expired
        // mid-phase, so a stalled release would hand the NEXT release a
        // fresh, longer budget while the watcher — blocked on this very
        // lock — cannot settle the grant whose deadline just lapsed.
        // Past the deadline the phase yields: remaining releases keep
        // their fences (fail closed) and the commit proceeds, returning
        // the lock to settlement.
        let release_deadline: Option<Instant> = {
            let now = self.dns_clock.unix_now()?;
            expiries
                .values()
                .map(|(_, expires_at, _)| *expires_at)
                .chain(lease_state.armed.iter().map(|entry| entry.expires_at))
                .filter(|expires_at| *expires_at > now)
                .min()
                .map(|expires_at| Instant::now() + Duration::from_secs(expires_at - now))
        };
        let release_budget = |deadline: Option<Instant>| -> Option<Duration> {
            deadline.map(|at| at.saturating_duration_since(Instant::now()))
        };
        let release_expired =
            |deadline: Option<Instant>| -> bool { deadline.is_some_and(|at| Instant::now() >= at) };
        let due_fence_dests: BTreeSet<&str> = {
            let now = self.dns_clock.unix_now()?;
            lease_state
                .armed
                .iter()
                .filter(|entry| entry.expires_at <= now)
                .flat_map(|entry| entry.destinations.iter().map(String::as_str))
                .collect()
        };
        let mut fences_released: Vec<RuleId> = Vec::new();
        let mut fence_release_kept: Vec<RuleId> = Vec::new();
        let mut ensured_iter = ensured_fences.iter().peekable();
        while let Some((dest, fence_id)) = ensured_iter.next() {
            // Past the phase deadline, yield to settlement: every
            // remaining fence stays (C36 r24 F2).
            if release_expired(release_deadline) {
                fence_release_kept.push(fence_id.clone());
                fence_release_kept.extend(ensured_iter.map(|(_, id)| id.clone()));
                break;
            }
            if !confirmed_dests.contains(dest) || due_fence_dests.contains(dest.as_str()) {
                continue;
            }
            // Re-verify the authorizing grant is STILL LIVE at release time
            // (C36 r18 F7): fencing and slow mutations may have consumed its
            // remaining lifetime since the allow was confirmed — releasing
            // now would expose an already-expired destination. A lapsed
            // grant is revoked (the caller re-enforces a clean state); the
            // fence stays.
            //
            // …and STILL AUTHORITATIVE (C36 r27 F2): the cached
            // confirmation is invalidated when the grant is REVOKED later
            // in this same pass (a second address's uncertain issuance
            // revokes the whole domain, and the lapsed-grant sweep above
            // has already removed its installed group — the cache is
            // stale). Releasing on it would drop the fence around another
            // grant's still-unresolved uncertain allow for the same
            // destination. The gate is the shared one: unexpired AND not
            // revoked in this pass (revocation is the only same-pass
            // invalidation of a confirmed grant — the sweep touches only
            // revoked or lapsed identities, so a non-revoked
            // confirmation's group is still installed).
            let release_now = self.dns_clock.unix_now()?;
            match confirmed_grants.get(dest) {
                Some((expires_at, domain, _))
                    if *expires_at > release_now && !revoked_domains.contains(domain.as_str()) => {}
                Some((_, domain, generation)) => {
                    let (domain, generation) = (domain.clone(), *generation);
                    fence_revoked(&mut revoked_domains, &mut revoked_tags, &domain, generation);
                    continue;
                }
                // No live-grant evidence for the destination: keep the
                // fence (fail closed).
                None => continue,
            }
            let entry = PendingMutation {
                name: dest.trim_end_matches("/32").to_string(),
                destination: dest.clone(),
                description: fence_id.0.clone(),
                kind: PendingKind::FenceRelease,
            };
            self.extend_dns_pending(sandbox_id, hash, std::slice::from_ref(&entry))?;
            match self.withdraw_rule_proven(acl_name, fence_id, release_budget(release_deadline)) {
                Err(err) => return Err(err),
                Ok(WithdrawalProof::Unproven) => {
                    fence_release_kept.push(fence_id.clone());
                }
                Ok(WithdrawalProof::PositivelyWithdrawn | WithdrawalProof::ProvenAbsent) => {
                    self.retire_dns_pending(sandbox_id, hash, std::slice::from_ref(&entry))?;
                    fences_released.push(fence_id.clone());
                }
            }
        }
        // Deferred REFRESH-family fence releases (C36 r23 F3): the fence
        // comes down only BEHIND a verified replacement authorization —
        // the destination's renewed allow AND its complete DNS/DoT
        // reject-companion group re-observed installed NOW under the
        // owner lock, with the authorizing grant still live and no due
        // settlement pending — never on the strength of the planned
        // answers. Anything less keeps the fence (kept-expected at the
        // readback below): an older unresolved allow the fence protects
        // against can then only ever land behind it.
        if !deferred_fence_releases.is_empty() && release_expired(release_deadline) {
            // Past the phase deadline: keep every deferred fence and
            // yield the owner lock to settlement (C36 r24 F2).
            fence_diff_kept.extend(deferred_fence_releases.iter().cloned());
        } else if !deferred_fence_releases.is_empty() {
            let release_now = self.dns_clock.unix_now()?;
            let read_budget = Some(
                release_budget(release_deadline)
                    .unwrap_or(Duration::from_secs(LEASE_WITHDRAWAL_BUDGET_SECS)),
            );
            let observed_now = self
                .read_sandbox_acl_within(acl_name, read_budget)?
                .ok_or_else(|| error(SandboxErrorCode::SandboxNotFound, "sandbox ACL is absent"))?;
            let present: BTreeSet<RuleId> = observed_now.egress.iter().map(observed_id).collect();
            let replacement_installed = |dest: &str| -> bool {
                !due_fence_dests.contains(dest)
                    && desired.iter().any(|desired_id| {
                        desired_id.1 == "allow"
                            && desired_id.7 == dest
                            && present.contains(desired_id)
                            && matches!(
                                expiries.get(desired_id.0.as_str()),
                                Some((_, expires_at, _)) if *expires_at > release_now
                            )
                            && dns_reject_companion_ids(desired_id)
                                .iter()
                                .all(|companion| present.contains(companion))
                    })
            };
            let mut deferred_iter = deferred_fence_releases.iter().peekable();
            while let Some(id) = deferred_iter.next() {
                if release_expired(release_deadline) {
                    fence_diff_kept.push(id.clone());
                    fence_diff_kept.extend(deferred_iter.cloned());
                    break;
                }
                let dest = &id.7;
                if !replacement_installed(dest) {
                    fence_diff_kept.push(id.clone());
                    continue;
                }
                let entry = PendingMutation {
                    name: dest.trim_end_matches("/32").to_string(),
                    destination: dest.clone(),
                    description: id.0.clone(),
                    kind: PendingKind::FenceRelease,
                };
                self.extend_dns_pending(sandbox_id, hash, std::slice::from_ref(&entry))?;
                match self.withdraw_rule_proven(acl_name, id, release_budget(release_deadline)) {
                    Err(err) => return Err(err),
                    Ok(WithdrawalProof::Unproven) => {
                        fence_diff_kept.push(id.clone());
                    }
                    Ok(WithdrawalProof::PositivelyWithdrawn | WithdrawalProof::ProvenAbsent) => {
                        self.retire_dns_pending(sandbox_id, hash, std::slice::from_ref(&entry))?;
                    }
                }
            }
        }
        // Stale LEASE fences on destinations that KEEP a live
        // authorization (C36 r20 F1): released only when the destination's
        // renewed allow is installed NOW — re-observed under the owner
        // lock, because the lease may have withdrawn the identity this
        // pass observed at its start (a renewal racing the expiry) — and
        // the grant authorizing it is still live. Otherwise the fence
        // stays (kept-expected at the readback below): fail closed.
        if !stale_lease_fences.is_empty() && release_expired(release_deadline) {
            // Past the phase deadline: keep every stale lease fence and
            // yield the owner lock to settlement (C36 r24 F2).
            fence_diff_kept.extend(stale_lease_fences.iter().cloned());
        } else if !stale_lease_fences.is_empty() {
            let release_now = self.dns_clock.unix_now()?;
            // The re-observation is deadline-bounded like every other
            // operation on this path (C36 r22 F1): the refresh holds the
            // OWNER lock here, so an unbounded read would delay the
            // lease's settlement of a destination expiring during the
            // stall. A killed read fails the pass CLOSED — nothing was
            // broadened, the released fences were journaled, and the
            // armed obligations retry.
            let read_budget = Some(
                release_budget(release_deadline)
                    .unwrap_or(Duration::from_secs(LEASE_WITHDRAWAL_BUDGET_SECS)),
            );
            let observed_now = self
                .read_sandbox_acl_within(acl_name, read_budget)?
                .ok_or_else(|| error(SandboxErrorCode::SandboxNotFound, "sandbox ACL is absent"))?;
            let present: BTreeSet<RuleId> = observed_now.egress.iter().map(observed_id).collect();
            let mut stale_iter = stale_lease_fences.iter().peekable();
            while let Some(id) = stale_iter.next() {
                if release_expired(release_deadline) {
                    fence_diff_kept.push(id.clone());
                    fence_diff_kept.extend(stale_iter.cloned());
                    break;
                }
                let dest = &id.7;
                let live_installed = !due_fence_dests.contains(dest.as_str())
                    && desired.iter().any(|desired_id| {
                        desired_id.1 == "allow"
                            && &desired_id.7 == dest
                            && present.contains(desired_id)
                            && matches!(
                                expiries.get(desired_id.0.as_str()),
                                Some((_, expires_at, _)) if *expires_at > release_now
                            )
                    });
                if !live_installed {
                    fence_diff_kept.push(id.clone());
                    continue;
                }
                let entry = PendingMutation {
                    name: dest.trim_end_matches("/32").to_string(),
                    destination: dest.clone(),
                    description: id.0.clone(),
                    kind: PendingKind::FenceRelease,
                };
                self.extend_dns_pending(sandbox_id, hash, std::slice::from_ref(&entry))?;
                match self.withdraw_rule_proven(acl_name, id, release_budget(release_deadline)) {
                    Err(err) => return Err(err),
                    Ok(WithdrawalProof::Unproven) => {
                        fence_diff_kept.push(id.clone());
                    }
                    Ok(WithdrawalProof::PositivelyWithdrawn | WithdrawalProof::ProvenAbsent) => {
                        self.retire_dns_pending(sandbox_id, hash, std::slice::from_ref(&entry))?;
                        // A proof from EITHER side retires the lease's
                        // own journal entry too (C36 r24 F1): the fence
                        // is provably gone, whoever removed it. The
                        // owner lock is already held.
                        let mut releases = self.read_dns_lease_releases(sandbox_id)?;
                        if releases.remove(&id.0) {
                            self.persist_dns_lease_releases(sandbox_id, &releases)?;
                        }
                    }
                }
            }
        }
        drop(lease_state);
        // Readback: the dynamic multiset is exactly what the pass provably
        // produced, and no static or infrastructure rule moved.
        let after = self
            .read_sandbox_acl(acl_name)?
            .ok_or_else(|| error(SandboxErrorCode::SandboxNotFound, "sandbox ACL is absent"))?;
        let mut after_list: Vec<RuleId> = after
            .egress
            .iter()
            .filter(|rule| is_dynamic(rule))
            .map(observed_id)
            .collect();
        after_list.sort();
        let withdrawn: BTreeSet<&RuleId> = removals
            .iter()
            .filter(|id| !fence_diff_kept.contains(*id))
            .chain(&removed_allows)
            .chain(&swept)
            .collect();
        let mut desired_list: Vec<RuleId> = current_dynamic
            .iter()
            .filter(|id| !withdrawn.contains(id))
            .cloned()
            .chain(added_ids.iter().filter(|id| !swept.contains(*id)).cloned())
            .chain(
                fences_added
                    .iter()
                    .filter(|id| !fences_released.contains(*id))
                    .cloned(),
            )
            .collect();
        desired_list.sort();
        if after_list != desired_list {
            // A rule the pass model expected to RETAIN can be absent from
            // the readback when the expiry lease withdrew it mid-pass at
            // its absolute expiry (C36 r17 F3): the lease races the pass
            // deliberately. A divergence FULLY explained by grants that
            // have lapsed by now is a mid-pass lapse, not a violation:
            // report those domains as revoked so the caller records the
            // revocations durably and re-enforces a clean state. Any extra
            // rule, or a missing rule whose grant is still live, is a
            // genuine mismatch.
            let now = self.dns_clock.unix_now()?;
            let lapsed = |id: &RuleId| matches!(expiries.get(id.0.as_str()), Some((_, expires_at, _)) if *expires_at <= now);
            let missing: Vec<&RuleId> = desired_list
                .iter()
                .filter(|id| !after_list.contains(*id))
                .collect();
            // Extras are a MULTISET difference (C36 r18): a duplicate of a
            // desired rule is corruption the membership test would hide.
            let mut desired_counts: BTreeMap<&RuleId, usize> = BTreeMap::new();
            for id in &desired_list {
                *desired_counts.entry(id).or_insert(0) += 1;
            }
            let mut extra: Vec<&RuleId> = Vec::new();
            for id in &after_list {
                match desired_counts.get_mut(id) {
                    Some(count) if *count > 0 => *count -= 1,
                    _ => extra.push(id),
                }
            }
            // An extra is tolerated only when it is a canonical
            // destination-wide fence the EXPIRY LEASE installed mid-pass
            // (C36 r18 F1/F5): the lease fences an expiring final
            // authorization around an unresolved mutation without waiting
            // for this pass. Deny-direction only; the next pass adopts the
            // fence when it is still needed and releases it (journaled)
            // when it is not. Any other extra is a genuine mismatch.
            extra.retain(|id| {
                !(super::network::is_dns_lease_fence_tag(&id.0)
                    && is_canonical_dns_fence_id(id, id.7.as_str()))
            });
            if !extra.is_empty() || !missing.iter().all(|id| lapsed(id)) {
                return Err(internal_error(format!(
                    "incus sandbox ACL DNS grants differ from the refreshed plan: missing={missing:?} extra={extra:?}"
                )));
            }
            for id in &missing {
                if let Some((domain, _, generation)) = expiries.get(id.0.as_str()) {
                    fence_revoked(&mut revoked_domains, &mut revoked_tags, domain, *generation);
                }
            }
        }
        if after.ingress.iter().any(&is_dynamic) {
            return Err(internal_error(
                "incus sandbox ACL holds unexpected DNS grant ingress rules",
            ));
        }
        let nondynamic = |acl: &super::acl::ObservedAcl| {
            let mut rules: Vec<String> = acl
                .ingress
                .iter()
                .map(|rule| ("ingress", rule))
                .chain(acl.egress.iter().map(|rule| ("egress", rule)))
                .filter(|(_, rule)| !is_dynamic(rule))
                .map(|(direction, rule)| {
                    format!(
                        "{direction}|{}|{}|{}|{}|{}|{}|{}",
                        rule.action,
                        rule.state,
                        rule.protocol,
                        rule.source,
                        rule.destination,
                        rule.source_port,
                        rule.destination_port
                    )
                })
                .collect::<Vec<_>>();
            rules.sort();
            rules
        };
        if nondynamic(&after) != nondynamic(&observed) {
            return Err(internal_error(
                "incus sandbox ACL static rules changed during a DNS refresh",
            ));
        }
        let mut installed = Vec::with_capacity(after.ingress.len() + after.egress.len());
        for rule in after.ingress.iter() {
            installed.push(rule.as_acl_rule(super::network::AclDirection::Ingress)?);
        }
        for rule in after.egress.iter() {
            installed.push(rule.as_acl_rule(super::network::AclDirection::Egress)?);
        }
        Ok(ReplacementOutcome {
            installed,
            revoked: revoked_domains.into_iter().collect(),
            uncertain: pending_mutations,
            reissue: Vec::new(),
        })
    }

    /// Allocate fresh, request-unique generations for the named grants
    /// (C36 r20 F2): the generation comes from the crash-durable marker
    /// counter, floored above every generation history and pending-
    /// mutation identity ever recorded, so the new identity collides with
    /// no earlier request's — including requests from a torn-down
    /// incarnation (the tombstone is merged into `plan.state.generations`
    /// at planning time).
    fn allocate_fresh_generations(
        &self,
        sandbox_id: &str,
        hash: &str,
        plan: &mut RefreshPlan,
        names: &[String],
    ) -> Result<(), RuntimeError> {
        let mut names = names.to_vec();
        names.sort();
        names.dedup();
        if names.is_empty() {
            return Ok(());
        }
        let record = self.read_dns_revocation_record(sandbox_id, hash)?;
        let floor = plan
            .state
            .generations
            .values()
            .copied()
            .max()
            .unwrap_or(0)
            // The durable `next_request` counter dies with the sandbox's
            // marker at teardown; the tombstoned floor carries it across
            // the incarnation boundary (C36 r20 F4).
            .max(self.dns_identity_tombstone(sandbox_id)?.request_floor)
            .max(
                record
                    .as_ref()
                    .map(|record| record.next_request)
                    .unwrap_or(0),
            )
            .max(
                record
                    .iter()
                    .flat_map(|record| record.pending.iter())
                    .filter_map(|pending| super::network::dns_tag_request_id(&pending.description))
                    .max()
                    .unwrap_or(0),
            );
        let first = self.allocate_dns_requests(sandbox_id, hash, floor, names.len() as u64)?;
        for (offset, name) in names.iter().enumerate() {
            let generation = first + offset as u64;
            for entry in &mut plan.state.grants {
                if &entry.name == name {
                    entry.generation = generation;
                }
            }
            plan.state.generations.insert(name.clone(), generation);
        }
        Ok(())
    }

    /// Publish the rendered dnsmasq policy onto the sandbox bridge and prove
    /// the readback. The daemon regenerates and restarts dnsmasq on a network
    /// update, so this is when answers become usable (or unusable). The body
    /// travels on stdin (`incus query -X PATCH --data-file -`, Incus 7.4+;
    /// see `query_patch_timed` for the bounded inline fallback on older
    /// CLIs): a permitted policy at the record bound renders past Linux's
    /// per-argument limit (MAX_ARG_STRLEN, 128 KiB on 4 KiB-page hosts),
    /// which `network set <net> raw.dnsmasq <value>` would blow through.
    /// PATCH merges config keys, so only `raw.dnsmasq` is touched.
    /// Publication with an optional caller deadline (C36 r17 F3): the PATCH
    /// is bounded by the earliest working grant's remaining lifetime when
    /// the caller supplies one.
    pub(crate) fn publish_dnsmasq_config_within(
        &self,
        network_name: &str,
        content: &str,
        budget: Option<Duration>,
    ) -> Result<(), RuntimeError> {
        let body = serde_json::json!({
            "config": { "raw.dnsmasq": content }
        })
        .to_string();
        match budget {
            Some(budget) => self.query_patch_timed(
                &super::acl::network_url(network_name, &self.project),
                &body,
                budget,
            )?,
            None => {
                self.query_patch(&super::acl::network_url(network_name, &self.project), &body)?
            }
        };
        let config = self.read_network_config(network_name)?.ok_or_else(|| {
            error(
                SandboxErrorCode::SandboxNotFound,
                "sandbox network is absent",
            )
        })?;
        if config
            .get("raw.dnsmasq")
            .and_then(serde_json::Value::as_str)
            != Some(content)
        {
            return Err(internal_error(
                "incus sandbox network DNS policy does not read back as published",
            ));
        }
        Ok(())
    }

    /// One DNS-policy refresh for one sandbox: re-resolve every allowlisted
    /// domain through the host resolver (validated A/AAAA/CNAME), replace the
    /// ACL destination set (shrink-then-grow with readback), THEN publish the
    /// answers, and persist the new state durably. Per-sandbox serialized
    /// (`sandbox_lock`) and fenced by ownership tags, so a refresh can never
    /// broaden another sandbox's policy. Any failure aborts before publishing
    /// and surfaces; expired grants are dropped by planning.
    pub fn refresh_sandbox_dns_policy(
        &self,
        sandbox_id: &str,
        policy: &EgressPolicy,
        hash: &str,
        transport: &dyn DnsTransport,
        servers: &[Ipv4Addr],
    ) -> Result<DnsRefreshOutcome, RuntimeError> {
        self.refresh_sandbox_dns_policy_with_budget(
            sandbox_id,
            policy,
            hash,
            transport,
            servers,
            super::network::COMPILE_BUDGET,
        )
    }

    /// The refresh with an explicit resolution budget (tests drive the
    /// budget-exhaustion path without real 30s timeouts).
    pub(crate) fn refresh_sandbox_dns_policy_with_budget(
        &self,
        sandbox_id: &str,
        policy: &EgressPolicy,
        hash: &str,
        transport: &dyn DnsTransport,
        servers: &[Ipv4Addr],
        budget: Duration,
    ) -> Result<DnsRefreshOutcome, RuntimeError> {
        verify_policy_presence_and_hash(Some(policy), Some(hash))?;
        if servers.is_empty() {
            return Err(internal_error(
                "egress DNS refresh requires at least one host resolver",
            ));
        }
        crate::validate_managed_instance_name(&crate::default_incus_instance_name(sandbox_id))?;
        let sandbox_lock = self.sandbox_lock(sandbox_id);
        let _guard = sandbox_lock.lock().unwrap_or_else(|err| err.into_inner());
        self.refresh_dns_policy_locked(sandbox_id, policy, hash, budget, &|domain, limits| {
            resolve_policy_name(transport, servers, domain, limits, self.dns_clock.as_ref())
        })
    }

    /// The refresh body shared by the wire refresh above and the production
    /// scheduler (`dns_refresh`): the CALLER holds `sandbox_lock(sandbox_id)`
    /// for the whole call. `resolve` produces one validated outcome per
    /// allowlisted name; everything after resolution (recorded-policy fence,
    /// revocation marker, planning, the journaled enforce-and-commit
    /// boundary, lease re-arm) is identical whichever resolver ran.
    pub(crate) fn refresh_dns_policy_locked(
        &self,
        sandbox_id: &str,
        policy: &EgressPolicy,
        hash: &str,
        budget: Duration,
        resolve: &dyn Fn(&str, &CompileLimits<'_>) -> Result<DomainGrant, ResolveDeny>,
    ) -> Result<DnsRefreshOutcome, RuntimeError> {
        verify_policy_presence_and_hash(Some(policy), Some(hash))?;
        crate::validate_managed_instance_name(&crate::default_incus_instance_name(sandbox_id))?;
        let (network_name, _acl_name) = sandbox_network_names(sandbox_id);
        // Preview tunnels: the commit below copies the live ACL (ingress
        // too) into the record, so an unconfirmed runtime port change is
        // rolled back first (skipping the refresh if it cannot be).
        self.resolve_tunnel_pending_locked(sandbox_id)?;
        // C37 R3: a refresh mutates live DNS rules before its plan commit —
        // a marked transition so a concurrent enforcement verification
        // retries for a coherent snapshot instead of convicting it.
        let _transition = self.begin_dns_transition(sandbox_id);
        let config = self.read_network_config(&network_name)?.ok_or_else(|| {
            error(
                SandboxErrorCode::SandboxNotFound,
                "sandbox network is absent",
            )
        })?;
        let tag = config
            .get(NETWORK_SANDBOX_TAG)
            .and_then(serde_json::Value::as_str);
        if tag != Some(sandbox_id) || !self.manages(&config) {
            return Err(super::acl::foreign_object("network", &network_name));
        }
        // Fence the supplied policy against the sandbox's RECORDED policy
        // hash (network-plans/<id>.json), under the sandbox lock, BEFORE any
        // resolution or mutation: a refresh carrying a DIFFERENT policy (say
        // one with a covering CIDR) would otherwise remove the recorded
        // policy's DNS/DoT reject companions while its allow rules remain,
        // opening arbitrary external DNS — and the later persisted-plan
        // update would silently skip the mismatched hash AFTER enforcement
        // changed. No recorded plan means the sandbox never completed a
        // policy create: refuse (fail closed), there is nothing to refresh.
        // The recorded rule set must also be SUCCESSFULLY DECODED: an absent
        // or undecodable `rules` field would otherwise silently disable the
        // recorded-static comparison below, letting injected static rules be
        // ratified into the persisted plan.
        let recorded_rules = match self.recorded_policy_hash(sandbox_id) {
            Some(recorded) if recorded.as_deref() == Some(hash) => {
                Some(self.persisted_plan_rules(sandbox_id, hash).ok_or_else(|| {
                    error(
                        SandboxErrorCode::Internal,
                        "sandbox's recorded network plan rules are missing or undecodable",
                    )
                })?)
            }
            _ => {
                return Err(error(
                    SandboxErrorCode::IdempotencyConflict,
                    "egress DNS refresh does not match the sandbox's recorded policy",
                ));
            }
        };
        let limits = CompileLimits {
            deadline: Instant::now() + budget,
            cancelled: self.cancelled.as_deref(),
        };
        // M19: refresh reads the RECORDED settings (fixed at
        // materialization), so a blocked name is never re-resolved and a
        // refresh can never resurrect it. Missing settings refuse refresh.
        let recorded_settings = self
            .persisted_enforcement_plan_checked(sandbox_id)?
            .and_then(|recorded| recorded.settings)
            .ok_or_else(|| internal_error("recorded egress settings are required"))?;
        let mut outcomes = Vec::with_capacity(policy.domains.len());
        for domain in &policy.domains {
            validate_policy_domain(domain)?;
            if crate::egress::domain_denied(domain, &recorded_settings) {
                outcomes.push(Err(ResolveDeny::blocked(domain)));
                continue;
            }
            // An exhausted resolver budget degrades to a TRANSIENT outcome
            // for the remaining names — expiry cleanup below still runs —
            // instead of aborting the refresh with expired grants left
            // installed in the ACL.
            let outcome = match limits.check() {
                Ok(()) => resolve(domain, &limits),
                Err(err) => Err(ResolveDeny::transient(err)),
            };
            outcomes.push(outcome);
        }
        // Expiry decisions use the time AFTER resolution: a grant that
        // expired while lookups ran is not retained.
        let now_unix = self.dns_clock.unix_now()?;
        let mut prior = self.load_dns_state(sandbox_id, hash);
        // Revoked grants are never retained on a transient failure: the
        // marker (written by the refresh that denied them, BEFORE it
        // mutated anything) proves the denial happened even though the old
        // dns-policy state may still list the grant.
        match self.read_dns_revocations(sandbox_id, hash) {
            DnsRevocations::None => {}
            DnsRevocations::Set(revoked) => {
                if let Some(state) = prior.as_mut() {
                    state.grants.retain(|entry| !revoked.contains(&entry.name));
                }
            }
            DnsRevocations::Malformed => prior = None,
        }
        let plan = plan_refresh(sandbox_id, policy, hash, prior.as_ref(), outcomes, now_unix)?;
        // Byte budget (coordinator ruling on m12): a refresh whose
        // recompiled ACL would exceed 64 KiB publishes NOTHING — no ACL
        // mutation, no resolver PATCH, no state commit. The last-good rules
        // stay (fails narrow: grants still lapse at their armed expiry) and
        // the caller records the typed `egress_refresh_over_budget` warning.
        if let Some(recorded) = recorded_rules.as_deref() {
            super::network::check_refresh_budget(super::network::refresh_acl_body_bytes(
                sandbox_id,
                recorded,
                &policy.cidrs,
                &plan.answers,
            ))?;
        }
        let result = self.enforce_and_commit_refresh_plan(
            sandbox_id,
            hash,
            policy,
            plan,
            prior.as_ref(),
            recorded_rules,
            now_unix,
            false,
        );
        if result.is_err() {
            // Fence first (C58 NEW-1): a refresh that journaled a denial
            // and failed before its replacement pass withdrew the denied
            // grant leaves that allow live. Settle the journaled
            // revocations NOW through the autonomous expiry boundary (the
            // same settle readiness runs, under the lock order sandbox →
            // lease owner) instead of waiting for the next observation or
            // watcher tick. Best effort: the watcher and every later
            // observation retry, and the refresh's own error is returned.
            // A CANCELLED caller (daemon shutdown, exhausted pass budget)
            // skips it (G1-R1-5): recovery deliberately ignores the permit,
            // so running it here would delay shutdown by a whole settle;
            // the journaled revocations are settled by the watcher or by
            // startup recovery, which enforce recorded denials first.
            let cancelled = self
                .cancelled
                .as_deref()
                .is_some_and(crate::RuntimePermit::is_cancelled);
            if !cancelled {
                let _ = self.recover_dns_expiry_obligations(sandbox_id);
            }
        }
        result
    }

    /// THE shared enforce-and-commit tail (C36 r21 F4): the wire refresh
    /// AND the initial create-time publication finish through this one
    /// boundary — tombstone-merged identity floors, collision rejection,
    /// revocation journaling, request-unique identity allocation, the
    /// fenced/journaled enforcement loop, expiry-bounded publication, and
    /// the serialized, re-validated commit. The initial path used to
    /// install domain allows through the raw provisioning rule loop (no
    /// pending-allow journal, no preventive fence, fixed generation 0):
    /// a deferred daemon-side apply of an interrupted initial allow could
    /// land after rollback with no DNS journal or lease obligation
    /// protecting the retried incarnation from it.
    #[allow(clippy::too_many_arguments)]
    fn enforce_and_commit_refresh_plan(
        &self,
        sandbox_id: &str,
        hash: &str,
        policy: &EgressPolicy,
        plan: RefreshPlan,
        prior: Option<&SandboxDnsState>,
        recorded_rules: Option<Vec<AclRule>>,
        now_unix: u64,
        acl_reborn: bool,
    ) -> Result<DnsRefreshOutcome, RuntimeError> {
        let (network_name, acl_name) = sandbox_network_names(sandbox_id);
        debug_assert!(plan.destinations.len() <= MAX_GRANT_DESTINATIONS);
        let mut plan = plan;
        // Publication requires the settings recorded during materialization.
        let publish_settings = self
            .persisted_enforcement_plan_checked(sandbox_id)?
            .and_then(|recorded| recorded.settings)
            .ok_or_else(|| internal_error("recorded egress settings are required"))?;
        // Identity floors from torn-down incarnations (C36 r20 F4): a
        // re-grant after teardown+recreate must never reuse a request
        // identity a late daemon-side mutation of the old incarnation
        // could still be carrying. The tombstone is monotone history —
        // merged here, it flows into the identity floor, the history
        // checks below, and the commit's persisted generations.
        let tombstone_generations = self.dns_identity_tombstone(sandbox_id)?.generations;
        for (name, generation) in &tombstone_generations {
            plan.state
                .generations
                .entry(name.clone())
                .and_modify(|floor| *floor = (*floor).max(*generation))
                .or_insert(*generation);
        }
        // A reborn incarnation under a NEW policy generation inherits the
        // preserved obligations (C36 r36 F1): the marker is sandbox-scoped
        // truth, but it was written under the TORN-DOWN policy's hash and
        // every hash-bound read below would refuse to mutate. Re-scope it
        // before the first one: the old generation's uncommitted
        // REVOCATIONS die with their ACL (every name re-resolves fresh
        // under the new policy, re-denying anything still deniable),
        // while the pending journal, the standing fences, and the
        // request-identity counter MUST survive — a deferred daemon-side
        // apply of an old identity can still land on this incarnation.
        // Only a REBORN boundary migrates: the wire refresh keeps
        // refusing a foreign policy hash (fail closed).
        if acl_reborn
            && let Some(mut record) = self.read_dns_revocation_record_unscoped(sandbox_id)?
            && record.policy_hash != hash
        {
            record.policy_hash = hash.to_string();
            record.revoked.clear();
            record.revoked_generations.clear();
            self.persist_dns_revocation_record(&record)?;
        }
        // Domain-rule identities truncate the name hash to 32 bits (the
        // legacy tag shape): two names in this sandbox sharing the
        // truncated hash share every generation-scoped identity — they
        // would overwrite each other in the expiry map and confuse
        // withdrawal evidence (C36 r20 F2). Reject the collision BEFORE
        // any mutation: the policy is undeliverable as written (one
        // domain must be renamed).
        {
            let mut seen_hex: BTreeMap<String, &str> = BTreeMap::new();
            let mut collision: Option<(String, String)> = None;
            for name in plan
                .state
                .grants
                .iter()
                .map(|entry| entry.name.as_str())
                .chain(plan.state.generations.keys().map(String::as_str))
            {
                let hex = super::network::dns_tag_hex(name);
                match seen_hex.insert(hex, name) {
                    Some(other) if other != name => {
                        collision = Some((other.to_string(), name.to_string()));
                        break;
                    }
                    _ => {}
                }
            }
            if let Some((first, second)) = collision {
                return Err(internal_error(format!(
                    "DNS policy names `{first}` and `{second}` collide in the 32-bit rule-identity hash; refusing to enforce an ambiguous policy"
                )));
            }
        }
        // Answer-time expiries may ALREADY be past the safe publication
        // window (later lookups consumed the budget): revoke those grants
        // BEFORE the first enforcement pass, so an expired destination
        // never receives an allow-add — withholding DNS publication does
        // not stop a guest connecting by IP.
        revoke_lapsed_entries(&mut plan, now_unix);
        // Durable revocation marker BEFORE any mutation: if publication or
        // persistence below fails, the OLD dns-policy state survives — this
        // marker keeps a later transient lookup failure from retaining (and
        // reinstalling) a grant this refresh just denied.
        let denied_names: Vec<String> = plan.denied.iter().map(|(name, _)| name.clone()).collect();
        self.extend_dns_revocations(sandbox_id, hash, &denied_names, &plan.state.generations)?;
        // The revocation write also marks the refresh OWED until its commit
        // (C58 NEW-1). Every live mutation below — pending reconciliation,
        // withdrawal, fence,
        // issuance, publication — runs ahead of the durable commit, and a
        // failure anywhere leaves the live state diverged from the persisted
        // plan by exactly this refresh's journaled work. The durable mark is
        // what lets readiness tell that apart from drift.
        let static_grants: Vec<super::network::GrantCidr> = policy
            .cidrs
            .iter()
            .map(|raw| parse_policy_cidr(raw))
            .collect::<Result<_, _>>()?;
        // Uncertain allow mutations from an EARLIER refresh (CLI killed at
        // its deadline, daemon-side application possible) must reconcile
        // BEFORE this one mutates: withdraw anything that landed late and
        // confirm absence — a rule that will not withdraw fails closed
        // here with the marker retained.
        self.reconcile_pending_mutations(sandbox_id, hash, &acl_name, acl_reborn, &static_grants)?;
        let static_texts: BTreeSet<String> = static_grants
            .iter()
            .map(|grant| grant.text.clone())
            .collect();
        // Durable request identities BEFORE enforcement (C36 r17 F1): any
        // grant whose allow this refresh may (re)issue — changed addresses,
        // a re-grant with generation history, or a name with an unresolved
        // pending mutation (a retry must never reuse an in-flight request's
        // identity, and a RESTORE of an absent rule must not reuse a
        // possibly-still-deferred one) — gets a fresh generation from the
        // crash-durable marker counter. As of C36 r26 F1 that is EVERY new
        // issuance, brand-new names included: an interrupted FIRST grant
        // must leave its identity recorded so no later retry can reuse it.
        // Unchanged, uncontested grants keep theirs (no rule churn).
        {
            let record = self.read_dns_revocation_record(sandbox_id, hash)?;
            let pending_names: BTreeSet<String> = record
                .iter()
                .flat_map(|record| record.pending.iter())
                .filter(|pending| pending.kind == PendingKind::Allow)
                .map(|pending| pending.name.clone())
                .collect();
            // (The identity floor — generation history, the durable
            // request counter, and pending-mutation identities — is
            // computed inside `allocate_fresh_generations`.)
            // A committed rule that is daemon-side ABSENT will be restored
            // by the pass; the restore must not reuse the identity a
            // still-deferred earlier request may be carrying (C36 r17 F1,
            // interrupted-restore direction).
            let missing_names: BTreeSet<String> = if prior.is_some() {
                match self.read_sandbox_acl(&acl_name)? {
                    Some(observed) => {
                        // Full rule identity, not (description, destination):
                        // the reject companions share that pair and differ
                        // only in protocol/port, so a pair-level check would
                        // mask a drained companion behind its survivors.
                        let present: BTreeSet<AclRuleId> =
                            observed.egress.iter().map(observed_rule_id).collect();
                        plan.state
                            .grants
                            .iter()
                            .filter(|entry| {
                                entry.addresses.iter().any(|address| {
                                    let Ok(addr) = address.parse::<Ipv4Addr>() else {
                                        return true;
                                    };
                                    super::network::domain_grant_rules(
                                        &entry.name,
                                        addr,
                                        &static_grants,
                                        entry.generation,
                                    )
                                    .iter()
                                    .any(|rule| {
                                        !present.contains(&(
                                            rule.description.clone(),
                                            rule.action.as_str().to_string(),
                                            "enabled".to_string(),
                                            rule.protocol.clone().unwrap_or_default(),
                                            rule.source.clone().unwrap_or_default(),
                                            rule.source_port.clone().unwrap_or_default(),
                                            rule.destination_port.clone().unwrap_or_default(),
                                            rule.destination.clone().unwrap_or_default(),
                                        ))
                                    })
                                })
                            })
                            .map(|entry| entry.name.clone())
                            .collect()
                    }
                    // A missing ACL fails closed in the replacement pass.
                    None => BTreeSet::new(),
                }
            } else {
                BTreeSet::new()
            };
            let mut needs: Vec<String> = Vec::new();
            for entry in &plan.state.grants {
                let contested =
                    pending_names.contains(&entry.name) || missing_names.contains(&entry.name);
                let unchanged = prior
                    .as_ref()
                    .and_then(|state| state.grants.iter().find(|e| e.name == entry.name))
                    .is_some_and(|e| e.addresses == entry.addresses);
                if unchanged && !contested {
                    continue;
                }
                // EVERY new issuance gets a fresh, crash-durable identity
                // (C36 r26 F1) — brand-new names included. The allocation
                // bumps the durable request counter BEFORE issuance, so an
                // interrupted first grant leaves its identity recorded in
                // the surviving journal; a later retry can never reuse it
                // and have its withdrawal evidence mistaken for the
                // still-deferred original's. Only a verified,
                // still-installed renewal (unchanged AND uncontested)
                // keeps its identity.
                needs.push(entry.name.clone());
            }
            self.allocate_fresh_generations(sandbox_id, hash, &mut plan, &needs)?;
        }
        // The desired dynamic rule set (allow + DNS/DoT reject companions,
        // static-CIDR-covered addresses exempt) is shared verbatim by the
        // live replacement and the persisted-plan update below.
        // Rules are replaced BEFORE answers become usable: a guest can never
        // receive an address the ACL does not yet (or no longer) allow. The
        // plan's lifetimes were captured BEFORE potentially thousands of
        // sequential Incus calls, so lifetimes are rechecked after EVERY
        // enforcement pass AND after every publication: an entry without a
        // safe publication window (the churn floor) is revoked — the marker
        // extended BEFORE its removal pass — and the loop re-enforces and
        // republishes until everything committed has a safe lifetime at
        // commit time. Each iteration revokes at least one entry, so the
        // loop is bounded by the entry count.
        let ctx = EnforcementContext {
            sandbox_id,
            acl_name: &acl_name,
            hash,
            static_texts: &static_texts,
            static_grants: &static_grants,
            recorded_rules: recorded_rules.as_deref(),
        };
        let mut installed;
        loop {
            let mut dynamic_rules: Vec<AclRule> = Vec::new();
            let generations: std::collections::BTreeMap<&str, u64> = plan
                .state
                .grants
                .iter()
                .map(|entry| (entry.name.as_str(), entry.generation))
                .collect();
            for (name, addresses) in &plan.answers {
                for addr in addresses {
                    dynamic_rules.extend(super::network::domain_grant_rules(
                        name,
                        *addr,
                        &static_grants,
                        generations.get(name.as_str()).copied().unwrap_or(0),
                    ));
                }
            }
            // Fence rules are computed INSIDE the enforcement boundary from
            // the durable marker and the complete effective authorization
            // (C36 r17 F5); the loop passes the destinations the current
            // plan authorizes.
            let authorized_dests: BTreeSet<String> = plan
                .answers
                .iter()
                .flat_map(|(_, addresses)| addresses.iter().map(|addr| format!("{addr}/32")))
                .collect();
            let expiries = grant_expiries(&plan.state.grants);
            installed = match self.replace_dns_acl_rules(
                sandbox_id,
                &acl_name,
                &static_texts,
                &static_grants,
                &dynamic_rules,
                &authorized_dests,
                &expiries,
                false,
                recorded_rules.as_deref(),
                hash,
            ) {
                Ok(pass) => {
                    if !pass.reissue.is_empty() {
                        // A planned allow the pass would have to RE-ADD is
                        // not a renewal: issue it under a fresh, request-
                        // unique identity (C36 r20 F2) and re-plan.
                        self.allocate_fresh_generations(
                            sandbox_id,
                            hash,
                            &mut plan,
                            &pass.reissue,
                        )?;
                        continue;
                    }
                    let revoked = pass.revoked;
                    let uncertain = pass.uncertain;
                    if !revoked.is_empty() || !uncertain.is_empty() {
                        // A grant lapsed MID-PASS or a mutation's outcome
                        // is uncertain past its deadline: record the
                        // revocations AND the pending mutations durably
                        // BEFORE the next pass — that pass withdraws any
                        // companions that landed before the lapse and
                        // rechecks survivors; the pending entries keep the
                        // marker (and its readiness fence) alive past the
                        // commit until a later refresh reconciles absence.
                        revoke_entries_by_name(
                            &mut plan,
                            &revoked,
                            "grant expired during enforcement; revoked before its allow was installed",
                        );
                        let denied_names: Vec<String> =
                            plan.denied.iter().map(|(name, _)| name.clone()).collect();
                        self.extend_dns_revocations(
                            sandbox_id,
                            hash,
                            &denied_names,
                            &plan.state.generations,
                        )?;
                        self.extend_dns_pending(sandbox_id, hash, &uncertain)?;
                        continue;
                    }
                    pass.installed
                }
                Err(err) => {
                    // Failed enforcement leaves the plan's clock stale too:
                    // durably revoke and withdraw anything that lapsed
                    // during the attempt before returning.
                    self.revoke_lapsed_before_returning(&ctx, &mut plan)?;
                    return Err(err);
                }
            };
            if revoke_lapsed_entries(&mut plan, self.dns_clock.unix_now()?) {
                let denied_names: Vec<String> =
                    plan.denied.iter().map(|(name, _)| name.clone()).collect();
                self.extend_dns_revocations(
                    sandbox_id,
                    hash,
                    &denied_names,
                    &plan.state.generations,
                )?;
                continue;
            }
            // Publication TTL reflects lifetimes at enforcement completion.
            plan.refresh_after =
                completion_refresh_after(&plan.state.grants, self.dns_clock.unix_now()?);
            // The publication boundary (M19): the recorded blocklist's
            // `local=` lines ride along and a denied name is refused.
            plan.state.published = match render_published_dnsmasq_config(
                &plan.answers,
                plan.refresh_after,
                Some(&publish_settings),
            ) {
                Ok(body) => body,
                Err(err) => {
                    self.revoke_lapsed_before_returning(&ctx, &mut plan)?;
                    return Err(err);
                }
            };
            // Publication joins the expiry-aware boundary (C36 r17 F3): the
            // PATCH is bounded by the earliest surviving grant's remaining
            // lifetime, and the lease watcher withdraws anything that lapses
            // while a publication stalls.
            let publish_budget = {
                let now = self.dns_clock.unix_now()?;
                plan.state
                    .grants
                    .iter()
                    .map(|entry| entry.expires_at.saturating_sub(now))
                    .min()
                    .filter(|remaining| *remaining > 0)
                    .map(Duration::from_secs)
            };
            // The attempted body is journaled BEFORE the PATCH (C58
            // NEW-1): a publication that lands and then fails its
            // readback or commit is this refresh's own work, not drift.
            self.record_dns_publication_attempt(sandbox_id, hash, &plan.state.published)?;
            if let Err(err) = self.publish_dnsmasq_config_within(
                &network_name,
                &plan.state.published,
                publish_budget,
            ) {
                // A failed (or unverifiable) publication must not strand a
                // grant that lapsed during the slow PATCH: durably revoke
                // and withdraw it through bounded cleanup before returning.
                self.revoke_lapsed_before_returning(&ctx, &mut plan)?;
                return Err(err);
            }
            // Publication itself consumed wall time: an entry that lapsed
            // past the safe window during the PATCH is revoked and
            // republished rather than committed past its expiry.
            if revoke_lapsed_entries(&mut plan, self.dns_clock.unix_now()?) {
                let denied_names: Vec<String> =
                    plan.denied.iter().map(|(name, _)| name.clone()).collect();
                self.extend_dns_revocations(
                    sandbox_id,
                    hash,
                    &denied_names,
                    &plan.state.generations,
                )?;
                continue;
            }
            break;
        }
        // Revocation retirement is POST-COMMIT ONLY (C36 r25 F5): a
        // committed grant supersedes its earlier revocation, but pruning
        // the marker BEFORE the durable commit leaves a crash window in
        // which the revocation evidence is gone while the OLD dns-policy
        // state (which still lists the denied grant) survives — a later
        // transient retry would then retain and reinstall the denied
        // grant with no fresh answer. A re-grant stays plannable without
        // any pruning: revocation filters only RETAINED prior state,
        // never a fresh resolution, and the post-commit clear below
        // retires the stale denial once the new truth is durable.
        // Reconcile the journal BEFORE the commit so the persisted plan
        // reflects it; the marker is only SPENT after the commit is durable
        // — uncertain allow mutations stay FENCED past the commit (C36
        // r17), and the commit itself is THE serialized lifecycle boundary
        // shared with lease settlement (C36 r20 F3).
        let drain = {
            // The drain's observations are bounded by the authorizing
            // grants' own lifetimes (C36 r32 F3): it must never release a
            // fence on an authorization that expired while it looked.
            let now = self.dns_clock.unix_now()?;
            let drain_deadline = plan
                .state
                .grants
                .iter()
                .map(|grant| grant.expires_at.saturating_sub(now))
                .min()
                .map(|left| Instant::now() + Duration::from_secs(left.max(1)));
            self.drain_pending_mutations(sandbox_id, hash, &acl_name, drain_deadline)?
        };
        // The drain's PROVEN fence releases AND its verified replacement
        // additions are carried into the commit (C36 r33 F2, C36 r34 F1):
        // their rules vanished / appeared between the post-replacement
        // observation and the commit's live re-read by the pass's own
        // journaled work — explained in BOTH directions.
        self.commit_refresh_dns_records(
            sandbox_id,
            hash,
            &plan,
            &installed,
            &drain.released,
            &drain.added,
        )?;
        // The revocations this marker carried are COMMITTED (C36 r23 F1):
        // the durable state, plan, and publication now ARE the post-denial
        // truth, so the denial no longer needs the marker to survive a
        // transient retry. Clear them ONLY here — a refresh that recorded
        // a denial and crashed or failed before this point leaves
        // `revoked` intact, and readiness refuses the not-yet-committed
        // denial rather than accepting the stale, mutually consistent old
        // records.
        // The owed mark and its publication attempts retire in the SAME
        // write (C58 NEW-1): the committed records are the new truth.
        if let Some(mut record) =
            self.read_dns_revocation_record(sandbox_id, hash)?
                .filter(|record| {
                    !record.revoked.is_empty()
                        || record.refresh_owed
                        || !record.published_attempts.is_empty()
                })
        {
            record.revoked.clear();
            record.revoked_generations.clear();
            record.refresh_owed = false;
            record.published_attempts.clear();
            self.persist_dns_revocation_record(&record)?;
        }
        // Standing fence obligations (C36 r23 F2) persist ACROSS the
        // commit that authorizes their destination — the fence is merely
        // suppressed while authorized; only positive withdrawal evidence
        // for an obligation's exact preserved identity retires it here.
        // The marker clears ONLY when fully spent: no pending mutations
        // and no standing obligations.
        let spent = drain.drained && self.settle_standing_fences(sandbox_id, hash)?;
        if spent {
            self.clear_dns_revocations(sandbox_id)?;
        }
        // The returned delay is measured at ACTUAL completion — publication
        // and persistence consumed wall time since the plan's TTLs were
        // captured — and never exceeds the shortest remaining lifetime.
        Ok(DnsRefreshOutcome {
            published_names: plan.answers.len(),
            denied_names: plan.denied.iter().map(|(name, _)| name.clone()).collect(),
            refresh_after: Duration::from_secs(u64::from(completion_refresh_after(
                &plan.state.grants,
                self.dns_clock.unix_now()?,
            ))),
        })
    }
}

/// Does this marker owe a COMMIT (C58 G1-R3-2)? Journaled uncertain
/// allows alone do not.
fn record_commit_owed(record: &DnsRevocationRecord) -> bool {
    record.refresh_owed
        || !record.revoked.is_empty()
        || record
            .pending
            .iter()
            .any(|pending| pending.kind == PendingKind::FenceRelease)
}

/// SHA-256 (hex) of a `raw.dnsmasq` body: the identity an uncommitted
/// publication attempt is recorded under (C58 NEW-1).
pub(crate) fn dns_publication_digest(content: &str) -> String {
    ring::digest::digest(&ring::digest::SHA256, content.as_bytes())
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// DNS lifetime clock. Persisted expiries use UNIX seconds so they survive
/// daemon restarts; resolution/command deadlines retain `Instant` and are not
/// virtualized. All answer timestamps, TTL decisions and lease watchers for
/// one client (including its clones) share this source.
pub(crate) trait DnsClock: std::fmt::Debug + Send + Sync {
    fn unix_now(&self) -> Result<u64, RuntimeError>;
}

#[derive(Debug)]
pub(crate) struct RealDnsClock;

impl DnsClock for RealDnsClock {
    fn unix_now(&self) -> Result<u64, RuntimeError> {
        unix_now()
    }
}

/// Current wall clock as seconds since the epoch (host clock sanity-checked).
pub(crate) fn unix_now() -> Result<u64, RuntimeError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| internal_error(format!("host clock is before the epoch: {err}")))?
        .as_secs())
}

// ---------------------------------------------------------------------------
// Enforcement-level expiry lease (C36 r17 F3; synchronized per-sandbox owner
// since C36 r18 F5; restart-durable obligations since C36 r18 F6). Expiry
// enforcement must never wait behind sequential operations (resolution,
// removals, fencing, publication, readback, commit). ONE owner per (state
// root, sandbox) holds the armed obligations; ONE watcher thread per owner
// fires them. Renewal (arm) and withdrawal are LINEARIZED on the owner
// lock: the entire settle-and-withdraw section runs under it, so a
// superseded obligation can never mutate — an epoch re-check outside the
// critical section would leave a check-to-mutation race. Obligations are
// fsync'd to `dns-revocations/<id>.lease.json` on every arm, and restart
// recovery (`recover_dns_expiry_obligations`) settles the expired ones
// through the same enforced withdrawal boundary and rearms the survivors
// BEFORE reconnect/readiness acceptance.
//
// Planning is independently self-enforcing (an expired grant is never
// retained, and every refresh lapse path records the revocation marker), so
// the lease never writes the marker — which keeps it clear of the refresh's
// marker read-modify-write. Its durable records are the obligations file
// and the lease-withdrawal evidence log (both fsync'd, sole writer under
// the owner lock; the evidence is cleared with the marker): a POSITIVE
// withdrawal of a request-specific allow identity proves that request
// completed (a request completes at most once), so the journaled
// uncertain-allow entry for that exact identity retires instead of fencing
// readiness forever — the rule can never be observed again and absence
// alone is not proof.
// ---------------------------------------------------------------------------

/// One grant identity the expiry lease withdraws at its absolute expiry.
/// Tags are request-specific, so the withdrawal can never strike a newer
/// request's rule. `fence_on_expiry` carries the destinations that were
/// NOT covered by a static CIDR grant at arm time: only those may need a
/// fence restored when the final live authorization expires while a
/// broadening mutation for the destination is still unresolved
/// (C36 r18 F1).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub(crate) struct DnsLeaseEntry {
    pub(crate) expires_at: u64,
    pub(crate) allow_tag: String,
    pub(crate) reject_tag: String,
    /// The policy domain this identity was armed for; required on disk.
    pub(crate) name: String,
    pub(crate) destinations: BTreeSet<String>,
    pub(crate) fence_on_expiry: BTreeSet<String>,
}

/// THE one lease-entry construction (C36 r21 F1): initial publication and
/// refresh both arm through this, and `fence_on_expiry` means "not covered
/// by a STATIC policy CIDR" — a resolved domain /32 is an EXPIRING
/// authorization, never static cover for itself. Computing coverage from
/// a set that includes resolved domain destinations (as the pre-r21
/// initial publish did) leaves every initial domain destination
/// "covered", so an unwithdrawable initial allow would skip fencing and
/// the expired destination would stay reachable by IP.
fn dns_lease_entry(
    domain: &str,
    expires_at: u64,
    generation: u64,
    destinations: BTreeSet<String>,
    static_grants: &[super::network::GrantCidr],
) -> DnsLeaseEntry {
    let fence_on_expiry = destinations
        .iter()
        .filter(|dest| {
            dest.strip_suffix("/32")
                .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
                .is_some_and(|ip| !static_grants.iter().any(|grant| grant.contains(ip)))
        })
        .cloned()
        .collect();
    DnsLeaseEntry {
        expires_at,
        allow_tag: super::network::dns_rule_tag(domain, generation),
        reject_tag: super::network::dns_rule_reject_tag(domain, generation),
        name: domain.to_string(),
        destinations,
        fence_on_expiry,
    }
}

/// THE ONE effective-authorization predicate (C36 r25 F3): an allow
/// identity counts as destination coverage ONLY as an ENABLED,
/// allow-direction DNS grant rule — never a fence tag (a fence DENIES),
/// never a disabled rule, never the identity being withdrawn. Refresh
/// planning (`verified_cover`) and lease settlement (`observed_cover`)
/// both validate groups through this, so neither side can count an
/// identity the other would reject.
fn dns_allow_id_is_effective_cover(allow: &AclRuleId, dest: &str, exclude_allow_tag: &str) -> bool {
    allow.1 == "allow"
        && allow.2 == "enabled"
        && allow.0.starts_with("wssp-dns-")
        && !super::network::is_dns_fence_tag(&allow.0)
        && allow.0 != exclude_allow_tag
        && allow.7 == dest
}

/// The three deny-direction companions of a DNS allow identity: the
/// group is complete only when ALL of them are present.
fn dns_reject_companion_ids(allow: &AclRuleId) -> [AclRuleId; 3] {
    let tag = allow.0.replacen("wssp-dns-", "wssp-dns-reject-", 1);
    [("udp", "53"), ("tcp", "53"), ("tcp", "853")].map(|(protocol, port)| {
        (
            tag.clone(),
            "reject".to_string(),
            "enabled".to_string(),
            protocol.to_string(),
            String::new(),
            String::new(),
            port.to_string(),
            allow.7.clone(),
        )
    })
}

/// Restart-durable expiry obligations (C36 r18 F6), fsync'd on every arm.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DnsLeaseObligations {
    sandbox_id: String,
    /// The owning project (C36 r32 F2): the state root may be shared by
    /// project-scoped daemons, so the ledger carries its project and a
    /// reader whose project differs must never activate, settle, or
    /// purge it. A persisted record requires a project.
    #[serde(deserialize_with = "required_dns_project")]
    project: Option<String>,
    entries: Vec<DnsLeaseEntry>,
}

/// Tombstoned identity history of torn-down incarnations (C36 r20 F4).
#[derive(Debug, Default)]
struct DnsIdentityTombstone {
    generations: BTreeMap<String, u64>,
    request_floor: u64,
    /// High-water mark of LEASE fence epochs (C36 r23 F5): a deferred
    /// daemon-side removal of an old incarnation's fence names its exact
    /// epoch, so a recreated sandbox's allocator must never reissue an
    /// epoch whose removal may still be in flight.
    lease_fence_floor: u64,
}

/// Obligation bound shared EXACTLY by the writer (arm) and the reader
/// (recovery) (C36 r19 F6): up to one live identity per policy domain
/// plus the same number of historical identities whose settlement is not
/// yet proven (an overdue obligation survives a re-arm until it settles —
/// expiry makes it DUE, not settled). A policy at the domain bound
/// rotating every identity at once therefore still fits. The writer
/// REFUSES beyond the bound (fail closed) rather than persisting a file
/// the reader would reject.
const MAX_DNS_LEASE_OBLIGATIONS: usize = 2 * super::network::MAX_POLICY_DOMAINS;

/// Cap on ONE lease withdrawal command (C36 r20 F1): deadline enforcement
/// (fencing an expired destination) is separated from the potentially slow
/// cleanup (the withdrawal itself), and the withdrawal is additionally
/// bounded by the NEXT live armed expiry, so a stalled removal can neither
/// leave the expired destination reachable nor delay another grant's
/// deadline enforcement behind the default host-call timeout. A killed
/// removal is `Unproven`: the destination is already fenced, the
/// obligation stays armed, and the next tick retries.
const LEASE_WITHDRAWAL_BUDGET_SECS: u64 = 20;

/// Per-sandbox lease owner state (C36 r18 F5). Renewal (arm) replaces
/// `armed` and every withdrawal runs under the same lock, so the two
/// linearize.
struct DnsLeaseOwnerState {
    /// Obligations of the CURRENT lease (replaced wholesale on rearm).
    armed: Vec<DnsLeaseEntry>,
    /// Positive withdrawals not yet fsync'd to the evidence log: the
    /// obligation stays armed until the evidence is durable — a crash in
    /// the gap must never lose the proof that retires a journaled
    /// uncertain-allow entry.
    owed_evidence: BTreeSet<(String, String)>,
    /// (allow tag, destination, EXPIRY) triples already BLIND-pre-fenced
    /// by the deadline pass (C36 r23 F10): the pre-fence runs BEFORE any
    /// preliminary observation, so a stalled read can never leave an
    /// expired destination allowed while the settle computes. The armed
    /// EXPIRY participates in the key (C36 r25 F2): a same-identity
    /// RENEWAL always re-arms with a later deadline (and the renewal is
    /// what releases the old fence), so a stale cache entry keyed to the
    /// superseded expiry can never suppress the blind fence the NEXT
    /// expiry needs. Entries for an identity being withdrawn are
    /// guarded by `owed_evidence` until retirement instead — the
    /// release-then-retire path must never re-fence mid-settle.
    prefenced: BTreeSet<(String, String, u64)>,
    /// Process-liveness flag (dropped on teardown/test restart): the
    /// watcher exits promptly instead of leaking its sleep.
    alive: bool,
    watcher_running: bool,
}

struct DnsLeaseOwner {
    /// Census requests the next settlement turn before activating watchers.
    /// Watchers keep deadline fencing active, but yield cleanup to recovery.
    recovery_waiters: std::sync::atomic::AtomicUsize,
    state: std::sync::Mutex<DnsLeaseOwnerState>,
    wake: std::sync::Condvar,
    /// THE serialization point for DNS lifecycle record commits (C36 r20
    /// F3): the refresh commit and the lease-settlement rewrite both take
    /// this lock across their read-validate-persist, so the two writers
    /// can never interleave into a lost update. Lock ordering:
    /// `state` → `commit` (the settle holds `state`; nobody takes `state`
    /// while holding `commit`).
    commit: std::sync::Mutex<()>,
}

struct DnsRecoveryTurn(std::sync::Arc<DnsLeaseOwner>);
impl DnsRecoveryTurn {
    fn new(owner: std::sync::Arc<DnsLeaseOwner>) -> Self {
        owner
            .recovery_waiters
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        owner.wake.notify_all();
        Self(owner)
    }
}
impl Drop for DnsRecoveryTurn {
    fn drop(&mut self) {
        self.0
            .recovery_waiters
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        self.0.wake.notify_all();
    }
}

/// (state root, PROJECT, sandbox) → the synchronized lease owner. The
/// project participates (C36 r32 F2): daemons of different projects may
/// share the state root, and an owner keyed by sandbox alone would let
/// one project's daemon adopt, settle, and purge another project's
/// obligations.
type DnsLeaseOwnerMap = BTreeMap<(PathBuf, String, String), std::sync::Arc<DnsLeaseOwner>>;

static DNS_LEASE_OWNERS: std::sync::OnceLock<std::sync::Mutex<DnsLeaseOwnerMap>> =
    std::sync::OnceLock::new();

fn dns_lease_owners() -> &'static std::sync::Mutex<DnsLeaseOwnerMap> {
    DNS_LEASE_OWNERS.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
}

/// C37 R3: a seqlock over MANAGED DNS transitions (expiry fencing/removal
/// and refresh rule mutation) that rewrite the live ACL before the persisted
/// plan commit lands. Enforcement verification reads the persisted plan and
/// the live ACL as two separate observations; an unmanaged read pair that
/// straddles a transition compares the NEW live ACL against the OLD plan and
/// convicts a healthy, correctly narrowed sandbox of drift — and post-R2
/// that false drift triggers deletion of the VM. The transition epoch makes
/// the overlap detectable: verification retries until it observes a coherent
/// snapshot. The transition side never waits (deadline enforcement is
/// untouched); only the verifier retries.
///
/// Per sandbox: `(epoch, depth)`. `epoch` bumps on every begin AND end, so
/// `e0 == e1` proves no transition began or finished between two reads;
/// `depth == 0` proves none is in flight (guards nest).
type DnsTransitionMap = BTreeMap<(PathBuf, String, String), (u64, u64)>;

static DNS_TRANSITIONS: std::sync::OnceLock<std::sync::Mutex<DnsTransitionMap>> =
    std::sync::OnceLock::new();

fn dns_transitions() -> &'static std::sync::Mutex<DnsTransitionMap> {
    DNS_TRANSITIONS.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
}

/// RAII marker: a managed DNS transition for this sandbox is in flight
/// (drop ends it). Panic-safe: the epoch always reaches the idle state.
pub(crate) struct DnsTransitionGuard {
    key: (PathBuf, String, String),
}

impl Drop for DnsTransitionGuard {
    fn drop(&mut self) {
        let mut transitions = dns_transitions()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let entry = transitions.entry(self.key.clone()).or_insert((0, 0));
        entry.0 = entry.0.saturating_add(1);
        entry.1 = entry.1.saturating_sub(1);
    }
}

impl IncusClient {
    /// Mark a managed DNS transition (expiry settle, recovery, refresh) as
    /// in flight until the returned guard drops. Guard the WHOLE window —
    /// from the first live-ACL mutation through the persisted plan commit.
    pub(crate) fn begin_dns_transition(&self, sandbox_id: &str) -> DnsTransitionGuard {
        let key = (
            self.state_root(),
            self.project.clone(),
            sandbox_id.to_string(),
        );
        {
            let mut transitions = dns_transitions()
                .lock()
                .unwrap_or_else(|err| err.into_inner());
            let entry = transitions.entry(key.clone()).or_insert((0, 0));
            entry.0 = entry.0.saturating_add(1);
            entry.1 = entry.1.saturating_add(1);
        }
        DnsTransitionGuard { key }
    }

    /// The transition observation for verification: `(epoch, in_flight)`.
    /// A coherent enforcement snapshot requires the SAME epoch before and
    /// after the read pair with nothing in flight.
    pub(crate) fn dns_transition_observation(&self, sandbox_id: &str) -> (u64, bool) {
        let key = (
            self.state_root(),
            self.project.clone(),
            sandbox_id.to_string(),
        );
        let transitions = dns_transitions()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        transitions
            .get(&key)
            .map(|&(epoch, depth)| (epoch, depth > 0))
            .unwrap_or((0, false))
    }
}

impl IncusClient {
    /// Run `body` holding the sandbox's DNS lifecycle commit lock (the
    /// refresh commit and the lease settlement's record rewrite take it):
    /// preview tunnels' runtime port changes rewrite the same recorded rules.
    /// Acquired like the refresh commit: a cancellable try-lock loop, never
    /// the owner's `state` lock (deadline fencing must never wait for it).
    pub(crate) fn hold_dns_commit<T>(
        &self,
        sandbox_id: &str,
        body: impl FnOnce() -> Result<T, RuntimeError>,
    ) -> Result<T, RuntimeError> {
        let owner = self.dns_lease_owner(sandbox_id);
        let _commit = loop {
            self.check_dns_refresh_cancelled()?;
            match owner.commit.try_lock() {
                Ok(guard) => break guard,
                Err(std::sync::TryLockError::Poisoned(err)) => break err.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        };
        body()
    }

    /// The per-sandbox lease owner, created on first use.
    fn dns_lease_owner(&self, sandbox_id: &str) -> std::sync::Arc<DnsLeaseOwner> {
        let key = (
            self.state_root(),
            self.project.clone(),
            sandbox_id.to_string(),
        );
        let mut owners = dns_lease_owners()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        owners
            .entry(key)
            .or_insert_with(|| {
                std::sync::Arc::new(DnsLeaseOwner {
                    recovery_waiters: Default::default(),
                    state: std::sync::Mutex::new(DnsLeaseOwnerState {
                        armed: Vec::new(),
                        owed_evidence: BTreeSet::new(),
                        prefenced: BTreeSet::new(),
                        alive: true,
                        watcher_running: false,
                    }),
                    wake: std::sync::Condvar::new(),
                    commit: std::sync::Mutex::new(()),
                })
            })
            .clone()
    }

    /// Hold the real serialization lock; cancellation is observed only by
    /// the production commit-lock loop, never by this test helper.
    #[cfg(test)]
    pub(crate) fn debug_hold_dns_commit(&self, sandbox_id: &str) {
        let owner = self.dns_lease_owner(sandbox_id);
        let _guard = owner.commit.lock().unwrap();
        let hold = self.dns_commit_hold.as_ref().expect("hold configured");
        hold.entered
            .store(true, std::sync::atomic::Ordering::Release);
        std::thread::sleep(hold.duration);
    }

    /// Path of the restart-durable expiry obligations for a sandbox.
    fn dns_lease_obligations_path(&self, sandbox_id: &str) -> PathBuf {
        self.dns_revocations_dir()
            .join(format!("{sandbox_id}.lease.json"))
    }

    /// Persist the armed obligations atomically with fsync (file AND
    /// directory) — they must survive a daemon crash between the refresh
    /// that armed them and the expiry (C36 r18 F6). An empty set removes
    /// the file: absence means no obligations.
    fn persist_dns_lease_obligations(
        &self,
        sandbox_id: &str,
        armed: &[DnsLeaseEntry],
    ) -> Result<(), RuntimeError> {
        crate::validate_managed_instance_name(&crate::default_incus_instance_name(sandbox_id))?;
        if armed.is_empty() {
            match std::fs::remove_file(self.dns_lease_obligations_path(sandbox_id)) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(internal_error(format!(
                        "cannot clear the DNS lease obligations: {err}"
                    )));
                }
            }
            return Ok(());
        }
        let body = serde_json::to_string(&DnsLeaseObligations {
            sandbox_id: sandbox_id.to_string(),
            project: Some(self.project.clone()),
            entries: armed.to_vec(),
        })
        .map_err(|err| internal_error(format!("cannot encode the DNS lease obligations: {err}")))?;
        self.write_durable_record(
            &self.dns_revocations_dir(),
            &format!("{sandbox_id}.lease.json"),
            &body,
        )
    }

    /// Read the persisted obligations. Absence is `Ok(vec![])`; an
    /// undecodable or implausible file is fail-closed evidence (`Err`) —
    /// recovery refuses readiness rather than dropping obligations. A
    /// ledger owned by a DIFFERENT project is fail-closed evidence too
    /// (C36 r32 F2): the state root may be shared, and activating,
    /// settling, or purging a foreign project's obligations would leave
    /// the owning project's running guest without its expiry watcher.
    fn read_dns_lease_obligations(
        &self,
        sandbox_id: &str,
    ) -> Result<Vec<DnsLeaseEntry>, RuntimeError> {
        let obligations = self.read_dns_lease_ledger(sandbox_id)?;
        let owned = obligations
            .project
            .as_deref()
            .map(|project| project == self.project)
            .unwrap_or(false);
        if !owned {
            return Err(internal_error(
                "sandbox's DNS lease obligations belong to a different project; refusing to proceed",
            ));
        }
        Ok(obligations.entries)
    }

    /// The project carried by a persisted ledger (C36 r32 F2): the
    /// startup enumerator's filter — a foreign project's ledger is left
    /// EXACTLY as found (never adopted, never purged). Undecodable
    /// content propagates so the fan-out still reports it.
    fn dns_lease_ledger_project(&self, sandbox_id: &str) -> Result<Option<String>, RuntimeError> {
        Ok(self.read_dns_lease_ledger(sandbox_id)?.project)
    }

    /// Parse and structurally validate the obligations ledger WITHOUT the
    /// project check — project filtering is layered on by the callers
    /// (refusal for per-sandbox reads, silent skip for the startup
    /// enumeration, which must not error on a sibling project's records).
    fn read_dns_lease_ledger(&self, sandbox_id: &str) -> Result<DnsLeaseObligations, RuntimeError> {
        let body = match std::fs::read_to_string(self.dns_lease_obligations_path(sandbox_id)) {
            Ok(body) => body,
            // Absence is an empty OWNED ledger (any project): nothing to
            // recover or refuse.
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(DnsLeaseObligations {
                    sandbox_id: sandbox_id.to_string(),
                    project: Some(self.project.clone()),
                    entries: Vec::new(),
                });
            }
            Err(err) => {
                return Err(internal_error(format!(
                    "cannot read the DNS lease obligations: {err}"
                )));
            }
        };
        let obligations = serde_json::from_str::<DnsLeaseObligations>(&body).map_err(|err| {
            internal_error(format!("cannot decode the DNS lease obligations: {err}"))
        })?;
        let valid_ip = |dest: &str| {
            dest.strip_suffix("/32")
                .is_some_and(|ip| ip.parse::<Ipv4Addr>().is_ok())
        };
        let valid = obligations.sandbox_id == sandbox_id
            && obligations.entries.len() <= MAX_DNS_LEASE_OBLIGATIONS
            && obligations.entries.iter().all(|entry| {
                !entry.destinations.is_empty()
                    && entry.destinations.len() <= MAX_GRANT_DESTINATIONS
                    && entry.destinations.iter().all(|dest| valid_ip(dest))
                    && entry
                        .fence_on_expiry
                        .iter()
                        .all(|dest| entry.destinations.contains(dest))
                    && super::network::is_dns_dynamic_tag(&entry.allow_tag)
                    && super::network::is_dns_dynamic_tag(&entry.reject_tag)
            });
        if !valid {
            return Err(internal_error(
                "sandbox's DNS lease obligations are undecodable; refusing to proceed before they resolve",
            ));
        }
        Ok(obligations)
    }

    /// Arm (or re-arm) the expiry lease for `sandbox_id` with the
    /// identities of the working grants THIS pass is enforcing. Arming
    /// MERGES into the durable obligation ledger under the owner lock —
    /// linearized against any in-flight withdrawal (C36 r18 F5) — and is
    /// fsync'd BEFORE the watcher may act on it, so the obligations
    /// survive a daemon crash (C36 r18 F6). The merge is authoritative
    /// only for the identities it carries (same tag = renewed expiry
    /// supersedes the old deadline); every OTHER obligation stays armed
    /// until it SETTLES — expiry makes an obligation due, not settled,
    /// so an overdue obligation that survived a failed observation or
    /// withdrawal is never silently discarded by a re-arm (C36 r19 F2).
    /// A fresh owner loads the persisted ledger before the first merge
    /// so it cannot overwrite obligations it never saw.
    pub(crate) fn arm_dns_expiry_lease(
        &self,
        sandbox_id: &str,
        armed: Vec<DnsLeaseEntry>,
    ) -> Result<(), RuntimeError> {
        crate::validate_managed_instance_name(&crate::default_incus_instance_name(sandbox_id))?;
        let owner = self.dns_lease_owner(sandbox_id);
        let mut client = self.clone();
        // The lease must fire even when the refresh that armed it is
        // cancelled: it carries no permit.
        client.cancelled = None;
        client.inspection_permit = None;
        let acl_name = sandbox_network_names(sandbox_id).1;
        let mut state = owner.state.lock().unwrap_or_else(|err| err.into_inner());
        // Merge into a CANDIDATE, validate, persist — and only then publish
        // to the owner (C36 r21 F5): a refused arm (over the bound) or a
        // failed persistence leaves the owner's previous state untouched,
        // so the in-memory set can never diverge from the durable ledger
        // (an unpublished oversized set would otherwise block later arms
        // and poison the next settlement's persistence).
        let mut candidate = if state.armed.is_empty() {
            // Fresh owner (process start / owner recreated): adopt the
            // durable ledger before merging (C36 r19 F2). An undecodable
            // file fails the arm closed — obligations are never dropped.
            self.read_dns_lease_obligations(sandbox_id)?
        } else {
            state.armed.clone()
        };
        // Supersede ONLY the identities this pass re-arms (renewal with a
        // fresh deadline); retain everything else, due or not — an
        // overdue entry is settled by the watcher, which runs as long as
        // any obligation remains (C36 r19 F2).
        let new_tags: BTreeSet<&str> = armed.iter().map(|entry| entry.allow_tag.as_str()).collect();
        candidate.retain(|entry| !new_tags.contains(entry.allow_tag.as_str()));
        candidate.extend(armed);
        if candidate.len() > MAX_DNS_LEASE_OBLIGATIONS {
            return Err(internal_error(
                "DNS lease obligations exceed the bound; refusing to arm before settlement catches up",
            ));
        }
        self.persist_dns_lease_obligations(sandbox_id, &candidate)?;
        // Persisted: publish to the owner.
        state.alive = true;
        state.armed = candidate;
        if !state.armed.is_empty() && !state.watcher_running {
            state.watcher_running = true;
            let watcher_owner = owner.clone();
            let watch_id = sandbox_id.to_string();
            std::thread::Builder::new()
                .name(format!("wssp-dns-lease-{sandbox_id}"))
                .spawn(move || client.dns_expiry_lease_watch(watcher_owner, watch_id, acl_name))
                .map_err(|err| {
                    internal_error(format!("cannot spawn the DNS expiry lease watcher: {err}"))
                })?;
        }
        owner.wake.notify_all();
        Ok(())
    }

    /// The STARTUP boundary owns obligation recovery (C36 r29 F1):
    /// recover and rearm every sandbox's durable DNS expiry obligations
    /// from the persisted ledgers, enumerated from DISK — no daemon
    /// round-trip is needed to learn which sandboxes have armed
    /// obligations, so this runs BEFORE any daemon observation the
    /// caller is about to perform (instance listing, network/ACL reads)
    /// that could stall with an expired allow still effective on a
    /// running VM. A missing ledger directory means nothing was ever
    /// armed; an unreadable one fails closed. Per-sandbox recovery then
    /// owns settlement; the other entry points (verify, apply,
    /// reconnect) delegate to it.
    pub(crate) fn recover_all_dns_expiry_obligations(&self) -> Result<(), RuntimeError> {
        let entries = match std::fs::read_dir(self.dns_revocations_dir()) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => {
                return Err(internal_error(format!(
                    "cannot enumerate the DNS lease obligations; failing closed: {err}"
                )));
            }
        };
        let sandbox_ids: Vec<String> = entries
            .flatten()
            .filter_map(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .and_then(|name| name.strip_suffix(".lease.json"))
                    .map(str::to_owned)
            })
            .collect();
        // PROJECT SCOPING (C36 r32 F2): the state root may be shared by
        // project-scoped daemons whose network views are isolated. This
        // daemon must never activate a FOREIGN project's ledger: its ACL
        // probe would observe nothing in its own project and purge the
        // foreign obligations as "gone", leaving the owning daemon's
        // running guest without its expiry watcher. Filter BEFORE any
        // owner activation or watcher spawn; the foreign ledger is left
        // exactly as found. A ledger whose project cannot be determined
        // (undecodable) is NOT skipped — it is reported as a failure so
        // the operator's own records are never silently stranded.
        let mut prepared: Vec<String> = Vec::new();
        let mut failures: Vec<String> = Vec::new();
        let mut own: Vec<String> = Vec::new();
        for sandbox_id in &sandbox_ids {
            match self.dns_lease_ledger_project(sandbox_id) {
                Ok(project) => {
                    let owned = project
                        .as_deref()
                        .map(|project| project == self.project)
                        .unwrap_or(false);
                    if owned {
                        own.push(sandbox_id.clone());
                    }
                }
                Err(err) => failures.push(format!("{sandbox_id}: {err}")),
            }
        }
        // Fan-out (C36 r30 F1): phase 1 ACTIVATES every recoverable owner
        // — ledger read, adoption, watcher spawn — before ANY fallible
        // daemon settlement, and phase 2 settles each prepared sandbox
        // with its failure isolated. A malformed ledger or a stalled
        // settlement for sandbox A must never prevent sandbox B's owner
        // and watcher from starting: once phase 1 has run, every valid
        // sandbox enforces its own deadlines autonomously even if a
        // sibling's settlement hangs or fails. Errors aggregate and are
        // reported AFTER the whole fan-out. Only THIS project's ledgers
        // (C36 r32 F2).
        let _turns: Vec<_> = own
            .iter()
            .map(|id| DnsRecoveryTurn::new(self.dns_lease_owner(id)))
            .collect();
        for sandbox_id in &own {
            match self.prepare_dns_expiry_recovery_for(sandbox_id, true) {
                Ok(true) => prepared.push(sandbox_id.clone()),
                Ok(false) => {}
                Err(err) => failures.push(format!("{sandbox_id}: {err}")),
            }
        }
        for sandbox_id in &prepared {
            self.check_dns_refresh_cancelled()?;
            if let Err(err) = self.settle_dns_expiry_recovery_for(sandbox_id, true) {
                failures.push(format!("{sandbox_id}: {err}"));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(internal_error(format!(
                "DNS startup recovery failed closed: {}",
                failures.join("; ")
            )))
        }
    }

    /// Recovery phase 1 (C36 r30 F1): read the durable ledger, adopt the
    /// obligations, mark the owner alive, and spawn the expiry watcher —
    /// everything needed for this sandbox to enforce its own deadlines
    /// AUTONOMOUSLY — without any fallible daemon settlement. From here
    /// the watcher owns retries no matter what phase 2 (or a sibling
    /// sandbox) does. Returns Ok(false) when nothing is armed.
    fn prepare_dns_expiry_recovery(&self, sandbox_id: &str) -> Result<bool, RuntimeError> {
        self.prepare_dns_expiry_recovery_for(sandbox_id, false)
    }

    fn recovery_state<'a>(
        &self,
        owner: &'a DnsLeaseOwner,
        handover: bool,
    ) -> Result<std::sync::MutexGuard<'a, DnsLeaseOwnerState>, RuntimeError> {
        if !handover {
            return self.lock_runtime(&owner.state);
        }
        // A requested handover owns the next cleanup turn. Waiting for the
        // current bounded mutation is not a new settlement attempt; its IO
        // budget starts after ownership arrives. Shutdown still interrupts.
        loop {
            if self.io_cancelled() {
                return Err(internal_error("DNS recovery handover cancelled"));
            }
            match owner.state.try_lock() {
                Ok(state) => return Ok(state),
                Err(std::sync::TryLockError::Poisoned(err)) => return Ok(err.into_inner()),
                Err(std::sync::TryLockError::WouldBlock) => {
                    std::thread::sleep(Duration::from_millis(5))
                }
            }
        }
    }

    fn prepare_dns_expiry_recovery_for(
        &self,
        sandbox_id: &str,
        handover: bool,
    ) -> Result<bool, RuntimeError> {
        let obligations = self.read_dns_lease_obligations(sandbox_id)?;
        if obligations.is_empty() {
            return Ok(false);
        }
        let acl_name = sandbox_network_names(sandbox_id).1;
        let owner = self.dns_lease_owner(sandbox_id);
        let mut client = self.clone();
        // Recovery must complete even when the reconnecting permit is
        // revoked mid-verify.
        client.cancelled = None;
        client.inspection_permit = None;
        let mut state = self.recovery_state(&owner, handover)?;
        state.alive = true;
        // A live owner's in-memory set is never STALER than the file (it
        // persists on every change), so adopt the file only when the
        // in-memory set is empty (fresh process / owner recreated).
        if state.armed.is_empty() {
            // A prior watcher may have retired the ledger while we waited
            // for handover. Adopt the current durable truth under ownership.
            state.armed = self.read_dns_lease_obligations(sandbox_id)?;
        }
        // The watcher spawns in phase 1 — BEFORE the fallible settlement
        // (C36 r30 F1): autonomous enforcement of this sandbox's
        // deadlines never waits on another sandbox's ledger or daemon
        // calls. It blocks on the owner lock until the settlement below
        // (if any) releases it.
        if !state.armed.is_empty() && !state.watcher_running {
            state.watcher_running = true;
            let watcher_owner = owner.clone();
            let watch_id = sandbox_id.to_string();
            std::thread::Builder::new()
                .name(format!("wssp-dns-lease-{sandbox_id}"))
                .spawn(move || client.dns_expiry_lease_watch(watcher_owner, watch_id, acl_name))
                .map_err(|err| {
                    internal_error(format!("cannot spawn the DNS expiry lease watcher: {err}"))
                })?;
        }
        owner.wake.notify_all();
        Ok(true)
    }

    /// Recover persisted expiry obligations BEFORE reconnect/readiness
    /// acceptance (C36 r18 F6): settle every obligation whose grant expired
    /// while the daemon was down — through the SAME enforced withdrawal
    /// boundary — then rearm the in-memory lease for the survivors. Any
    /// settlement failure fails CLOSED (readiness refused); the
    /// obligations stay persisted for the next attempt.
    pub(crate) fn recover_dns_expiry_obligations(
        &self,
        sandbox_id: &str,
    ) -> Result<(), RuntimeError> {
        if self.prepare_dns_expiry_recovery(sandbox_id)? {
            self.settle_dns_expiry_recovery(sandbox_id)?;
        }
        Ok(())
    }

    /// Recovery phase 2: the fallible daemon settlement. Runs with the
    /// owner already live and the watcher already spawned (phase 1), so
    /// an error here never strands the obligations without autonomous
    /// enforcement.
    fn settle_dns_expiry_recovery(&self, sandbox_id: &str) -> Result<(), RuntimeError> {
        self.settle_dns_expiry_recovery_for(sandbox_id, false)
    }

    fn settle_dns_expiry_recovery_for(
        &self,
        sandbox_id: &str,
        handover: bool,
    ) -> Result<(), RuntimeError> {
        let acl_name = sandbox_network_names(sandbox_id).1;
        // Adopt the durable obligations and enter the deadline boundary
        // BEFORE the first ACL probe (C36 r27 F3): recovery used to read
        // the ACL with the ordinary host-call timeout (120s default)
        // before activating the owner or fencing anything, so after a
        // process restart a STALLED probe left expired allows effective
        // for the whole stall — refusing readiness does not stop an
        // already-running VM, and the watcher did not exist yet. The
        // owner goes live and the permit-independent pre-fence fires
        // FIRST; the absence probe below is bounded by the same
        // deadline the watcher would use.
        let owner = self.dns_lease_owner(sandbox_id);
        let mut state = self.recovery_state(&owner, handover)?;
        let mut client = self.clone();
        // Settlement has its own cumulative deadline, and explicit shutdown
        // revocation still interrupts it. Autonomous watchers use a separate
        // permit-free client and continue enforcing the durable obligations.
        let budget = Duration::from_secs(LEASE_WITHDRAWAL_BUDGET_SECS);
        client.cancelled = Some(std::sync::Arc::new(match &self.cancelled {
            Some(parent) => crate::RuntimePermit::child(parent.clone(), budget),
            None => crate::RuntimePermit::with_timeout(budget),
        }));
        client.agent_timeout = client.agent_timeout.min(budget);
        state.alive = true;
        if state.armed.is_empty() {
            return Ok(());
        }
        // C37 R6: transition marking lives at the shared MUTATION boundary
        // — acquired LAZILY, immediately before the first actual mutation,
        // and retained through the settle's commit — never predicted from
        // entry state. The R3 predicted marking (will-settle within a +2s
        // skew) missed a grant whose expiry landed DURING the probe below:
        // the pass deadline deliberately runs the probe right up to the
        // earliest future expiry (up to 20s out), so the settle that then
        // fenced and committed that grant ran UNMARKED, and a concurrent
        // verifier whose own recovery had already finished compared the
        // old plan to the narrowed ACL and convicted a healthy expiry of
        // drift. A genuinely no-op pass still never marks: the pre-fence
        // fills this cell only on its way into a real fence add, and the
        // settle below is guarded by the exact post-probe condition.
        let pass_now = self.dns_clock.unix_now()?;
        let mut transition: Option<DnsTransitionGuard> = None;
        // ONE absolute deadline carries across the recovery pre-fence AND
        // the probe (C36 r28 F2 — the watcher's r26 F2 discipline, applied
        // here): captured BEFORE pre-fencing from the earliest FUTURE
        // armed expiry. Recovery holds the owner lock and no watcher
        // exists yet, so a pre-fence pass that stalls until that expiry
        // must not re-arm the probe with a fresh 20s budget that excludes
        // the newly-due destination.
        let pass_deadline = {
            let now = pass_now;
            let next_gap = state
                .armed
                .iter()
                .filter(|entry| entry.expires_at > now)
                .map(|entry| entry.expires_at - now)
                .min();
            Instant::now()
                + Duration::from_secs(
                    next_gap
                        .unwrap_or(LEASE_WITHDRAWAL_BUDGET_SECS)
                        .clamp(1, LEASE_WITHDRAWAL_BUDGET_SECS),
                )
        };
        self.prefence_due_dns_dests(sandbox_id, &acl_name, &mut state, &mut transition);
        // The sandbox's ACL is GONE (torn down): every obligation is moot
        // (C36 r20 F4) — the watcher treats the same observation as
        // settle-and-stop. Records from a pre-r20 teardown must never
        // block a recreate behind settlement errors against a
        // nonexistent ACL. A FAILED observation is not a gone ACL (C36
        // r23 F9): proceed to the settlement attempt and the watcher —
        // obligations are purged only on a proven absence. The probe is
        // deadline-bounded like the watcher's preliminary read (C36 r26
        // F2): a stalled probe is just an observation failure — the
        // pre-fence above already protects the overdue destinations and
        // the watcher retries. The budget is what REMAINS of the pass
        // deadline — never a recomputed gap that would exclude an expiry
        // the pre-fence just consumed (C36 r28 F2). An exhausted deadline
        // re-discovers and fences the newly-due destinations and skips
        // the read outright: the settlement below and the watcher retry.
        if Instant::now() >= pass_deadline {
            self.prefence_due_dns_dests(sandbox_id, &acl_name, &mut state, &mut transition);
        }
        let probe_budget = pass_deadline.saturating_duration_since(Instant::now());
        let probe = if probe_budget.is_zero() {
            None
        } else {
            Some(client.read_sandbox_acl_within(&acl_name, Some(probe_budget)))
        };
        if matches!(probe, Some(Ok(None))) {
            state.armed.clear();
            state.owed_evidence.clear();
            self.persist_dns_lease_obligations(sandbox_id, &[])?;
            return Ok(());
        }
        let now = self.dns_clock.unix_now()?;
        let settled_expired = state.armed.iter().any(|entry| entry.expires_at <= now);
        // Recorded REVOCATIONS settle through the SAME boundary (C36
        // r31 F2/F3): a refresh that journaled an NXDOMAIN and crashed
        // before its first ACL mutation leaves the denied allow
        // effective, and the recovery probe above may already have
        // consumed the whole pass deadline — so the settle boundary
        // itself treats a durably revoked identity as immediately due,
        // with the watcher's autonomous retries guaranteeing
        // enforcement even when THIS pass has no budget left (C36 r31
        // F2). The withdrawal is coverage-aware (C36 r31 F3): the
        // quarantine installs only when no verified surviving group and
        // no static grant authorizes the destination. The marker and
        // the obligations stay persisted: denial evidence is preserved
        // until a refresh COMMITS the denial (C36 r30 F3).
        let revoked_due = self.revoked_due_dns_lease_pairs(sandbox_id, &state);
        // Settlement commits the lifecycle transition itself (C36 r19
        // F5): the persisted DNS state and plan are rewritten to the
        // post-settlement truth — derived and drift-validated (C36
        // r19 F4) — inside the settle, before obligations retire. The
        // error is CAPTURED, not propagated yet (C36 r23 F9): a failed
        // initial settlement must not strand the retained obligations
        // without autonomous enforcement — refusing readiness does not
        // stop an already-running VM, and without the watcher a
        // still-live grant would expire unwithdrawn until the next API
        // call happens to retry recovery.
        // C37 R6: mark the transition from the EXACT post-probe settle
        // condition (a fresh `now`), never from an entry-time prediction —
        // a grant that expired DURING the probe above settles here MARKED,
        // and the guard is retained through the settle's plan commit (the
        // guard drops at the end of this function, after the settle).
        let settle_needed =
            settled_expired || !state.owed_evidence.is_empty() || !revoked_due.is_empty();
        if settle_needed && transition.is_none() {
            transition = Some(self.begin_dns_transition(sandbox_id));
        }
        client.check_dns_refresh_cancelled()?;
        let settle_err = if settle_needed {
            client
                .settle_due_dns_lease(sandbox_id, &acl_name, &mut state, &[])
                .err()
        } else {
            None
        };
        // The settle has returned: its commit is complete. Drop the
        // lazily-acquired transition mark NOW (an explicit drop — the
        // guard's whole value is held through the commit, then released).
        drop(transition);
        owner.wake.notify_all();
        // The watcher is running (spawned in phase 1): autonomous
        // retries are guaranteed no matter what the initial settlement
        // did. Only NOW does its error fail readiness (the obligations
        // stay persisted and armed either way).
        if let Some(err) = settle_err {
            return Err(err);
        }
        Ok(())
    }

    /// Withdraw every DUE armed obligation through the enforced
    /// destination-withdrawal boundary and settle it only when nothing was
    /// observed AND its positive evidence is durable. The CALLER holds the
    /// owner lock for the whole run — that is what linearizes renewal
    /// against withdrawal (C36 r18 F5). An obligation that will not settle
    /// stays armed and is retried; a failed observation read is NOT
    /// settlement (C36 r18 F4).
    fn settle_due_dns_lease(
        &self,
        sandbox_id: &str,
        acl_name: &str,
        state: &mut DnsLeaseOwnerState,
        blind_fenced: &[super::network::AclRule],
    ) -> Result<(), RuntimeError> {
        // Unresolved broadening mutations by destination, from the durable
        // journal. Marker ABSENT (the common clean case) means no pending
        // mutation and NO fence on expiry; marker UNREADABLE is
        // fail-CLOSED: treat every fence-on-expiry destination as possibly
        // pending and keep the obligation armed for retry.
        let (pending_allow_dests, marker_failed): (Option<BTreeSet<String>>, bool) =
            match self.read_dns_revocation_record_unscoped(sandbox_id) {
                Ok(record) => (
                    Some(
                        record
                            .iter()
                            .flat_map(|record| record.pending.iter())
                            .filter(|pending| pending.kind == PendingKind::Allow)
                            .map(|pending| pending.destination.clone())
                            .chain(record.iter().flat_map(|record| {
                                // Standing fence obligations (C36 r23
                                // F2): a temporary authorization
                                // SUPPRESSED the fence while it lived;
                                // when the final authorization EXPIRES
                                // the suppression ends and the
                                // destination must stay denied — the
                                // settle keeps its deadline fence around
                                // the unresolved identity until a
                                // reconcile re-plans the standing fence.
                                record
                                    .standing_fences
                                    .iter()
                                    .map(|standing| standing.destination().to_string())
                            }))
                            .collect(),
                    ),
                    false,
                ),
                Err(_) => (None, true),
            };
        let mut failed = marker_failed;
        // C37 R6: lazily-acquired transition mark for THIS settle's fence
        // mutations. Every caller already holds a guard spanning the whole
        // settle (the watcher wraps its pass; recovery marks from the
        // exact post-probe condition), so this cell is a safety net — a
        // future caller that reaches a fence add unmarked still marks.
        let mut settle_transition: Option<DnsTransitionGuard> = None;
        let mut lease_fence_alloc = |dest: &str| -> Result<super::network::AclRule, RuntimeError> {
            let epoch = self.allocate_lease_fence_epoch(sandbox_id)?;
            let addr = dest
                .strip_suffix("/32")
                .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
                .ok_or_else(|| internal_error("DNS fence destination is not an IPv4 /32"))?;
            Ok(super::network::domain_lease_fence_rule(addr, epoch))
        };
        let mut settled: Vec<DnsLeaseEntry> = Vec::new();
        let mut fences_added: Vec<super::network::AclRule> = Vec::new();
        // Blind pre-fences installed on the way in (by the caller's
        // pre-observation pass and by every round below): tracked so a
        // fence whose pair went QUIET mid-settle can be swept (see the
        // release below) instead of orphaned.
        let mut blind_installed: Vec<super::network::AclRule> = blind_fenced.to_vec();
        // Deadline enforcement is separated from the potentially slow
        // cleanup (C36 r20 F1). EVERY round first fences every due,
        // otherwise-uncovered destination (so a destination whose expiry
        // lands MID-SETTLE is denied at its own deadline — never behind a
        // stalled removal), then performs ONE bounded withdrawal whose
        // budget is derived from the next live armed expiry: a stalled
        // removal is abandoned no later than the next deadline it would
        // otherwise delay (and capped), the obligation stays armed, and
        // the next round enforces that deadline immediately. `now` is
        // re-read every round: a long settle never makes liveness
        // decisions on a clock captured before a stall.
        let mut phase_fences: BTreeMap<String, super::network::AclRule> = BTreeMap::new();
        let mut fenced_dests: BTreeSet<String> = BTreeSet::new();
        // Destinations the per-entry phases actually PROCESS this call:
        // a blind pre-fence for one of these is adopted, reconciled, or
        // released inline, so the orphan sweep below skips it outright
        // (no extra observation or journal work in the common case).
        let mut handled_dests: BTreeSet<String> = BTreeSet::new();
        let mut attempted: BTreeSet<(String, String)> = BTreeSet::new();
        let mut failed_tags: BTreeSet<String> = BTreeSet::new();
        // Recorded revocations are immediately-due obligations in this
        // SAME boundary (C36 r31 F2): a denial journaled by a refresh
        // that crashed before its first ACL mutation is withdrawn and
        // fenced here with the same retries and pre-observation fencing
        // as an elapsed TTL — not by a one-shot recovery pass whose
        // deadline the probe may already have consumed. The pair set is
        // computed once per call; durable withdrawal evidence keeps an
        // enforced pair from re-entering, so a fully withdrawn revoked
        // identity goes quiet here (its obligation still retires only
        // through the expiry path below — the marker and the persisted
        // grant stay until the committing refresh or the expiry settle
        // owns them, C36 r30 F3).
        let revoked_due = self.revoked_due_dns_lease_pairs(sandbox_id, state);
        let revoked_due_tags: BTreeSet<String> =
            revoked_due.iter().map(|(tag, _)| tag.clone()).collect();
        // The recorded STATIC policy authorizes its destinations at this
        // boundary too (C36 r31 F3): an obligation armed BEFORE a static
        // grant covered its destination still carries the destination in
        // `fence_on_expiry`, and a refused withdrawal must not quarantine
        // traffic the committed static policy allows. An unreadable plan
        // yields no static coverage — fail closed (fence).
        let recorded_statics = self.recorded_static_grant_cidrs(sandbox_id);
        let static_covers = |dest: &str| {
            dest.strip_suffix("/32")
                .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
                .is_some_and(|ip| recorded_statics.iter().any(|grant| grant.contains(ip)))
        };
        loop {
            // A census requests handover between bounded mutation rounds.
            // Keep all obligations armed; recovery owns their durable settlement.
            if self.cancelled.is_none()
                && self
                    .dns_lease_owner(sandbox_id)
                    .recovery_waiters
                    .load(std::sync::atomic::Ordering::Acquire)
                    > 0
            {
                return Err(internal_error(
                    "DNS settlement handed over to startup recovery",
                ));
            }
            // Owed withdrawal evidence is retried on EVERY round, ahead
            // of any new withdrawal (C36 r22 F5): a destination whose
            // withdrawal proved out but whose evidence write failed is
            // skipped by BOTH phases below, and when it is the only due
            // destination the trailing flush is never reached — without
            // this flush the obligation would stay armed forever even
            // after storage recovers, and an uncertain request's journal
            // entry would never gain the proof it needs to retire.
            // Retirement stays conditional on durable proof: only a
            // successful fsync clears the debt.
            if !state.owed_evidence.is_empty()
                && self
                    .persist_dns_lease_withdrawals(sandbox_id, &state.owed_evidence)
                    .is_ok()
            {
                state.owed_evidence.clear();
            }
            // The round deadline (C36 r21 F2): EVERY blocking operation
            // this round — fencing, ACL readbacks, the allow withdrawal,
            // companion removals, and the clean-expiry fence withdrawal —
            // is bounded by the next live armed expiry (capped), recomputed
            // fresh every round. A stalled cleanup step is abandoned no
            // later than the next deadline it would otherwise delay; the
            // obligation stays armed and the next round enforces that
            // deadline immediately. Deadline enforcement never waits on
            // cleanup, and cleanup never outlives a deadline.
            let now = self.dns_clock.unix_now()?;
            let round_deadline = {
                let next_gap = state
                    .armed
                    .iter()
                    .filter(|entry| entry.expires_at > now)
                    .map(|entry| entry.expires_at - now)
                    .min();
                Instant::now()
                    + Duration::from_secs(
                        next_gap
                            .unwrap_or(LEASE_WITHDRAWAL_BUDGET_SECS)
                            .clamp(1, LEASE_WITHDRAWAL_BUDGET_SECS),
                    )
            };
            // Deadline fencing comes FIRST, before ANY observation this
            // round (C36 r23 F10): the blind pre-fence denies every due
            // destination that needs it, so the coverage read below can
            // never delay enforcement. The reliable adopt-or-install in
            // Phase A supersedes these fences.
            blind_installed.extend(self.prefence_due_dns_dests(
                sandbox_id,
                acl_name,
                state,
                &mut settle_transition,
            ));
            // Authorization coverage is an OBSERVED, COMPLETE, SURVIVING
            // rule group — never an unexpired armed obligation (C36 r23
            // F6): obligations are armed before installation and stay
            // armed after failed or revoked issuances, so an armed entry
            // proves nothing about a surviving authorization, and an
            // unconfirmed overlapping grant must never suppress the
            // quarantine of an expired allow that refuses withdrawal.
            // The read is bounded by the round deadline like every other
            // operation; a failed observation is NO coverage (fail
            // closed — the destination is fenced).
            let coverage_ids: BTreeSet<AclRuleId> = match self.read_sandbox_acl_within(
                acl_name,
                Some(round_deadline.saturating_duration_since(Instant::now())),
            ) {
                Ok(Some(snapshot)) => snapshot.egress.iter().map(observed_rule_id).collect(),
                _ => BTreeSet::new(),
            };
            // A REVOKED name is not an authorization (C36 r25 F3): a
            // revocation is recorded in the durable marker BEFORE any
            // mutation, and the withdrawal that would remove the revoked
            // grant's rules may still be failing — the complete observed
            // group then survives with NO effective authorization behind
            // it. Re-read each round (a concurrent refresh may revoke
            // mid-settle); an UNREADABLE marker is fail closed — no
            // coverage is provable at all.
            let revoked_names: Option<BTreeSet<String>> =
                match self.read_dns_revocation_record_unscoped(sandbox_id) {
                    Ok(Some(record)) => Some(record.revoked.into_iter().collect()),
                    Ok(None) => Some(BTreeSet::new()),
                    Err(_) => None,
                };
            let observed_cover = |dest: &str, exclude_allow_tag: &str| -> bool {
                // The covering group must belong to an UNEXPIRED grant
                // (C36 r24 F3): a complete observed group whose
                // authorization already lapsed is itself awaiting
                // settlement — two expired groups sharing a destination
                // must never suppress each other's quarantine. The
                // lifetime is re-read at EVERY check, so a grant that
                // expired while earlier blocking work ran this round
                // stops counting. An allow with no armed obligation at
                // all (an orphan the records cannot confirm) is no
                // coverage either — fail closed. And the armed entry's
                // NAME must not be revoked (C36 r25 F3): the marker is
                // the durable record of the denial, so a surviving group
                // whose withdrawal keeps failing never stands in as
                // coverage for a sibling expiry.
                let Ok(checked_at) = self.dns_clock.unix_now() else {
                    return false;
                };
                let Some(revoked) = revoked_names.as_ref() else {
                    return false;
                };
                coverage_ids.iter().any(|allow| {
                    dns_allow_id_is_effective_cover(allow, dest, exclude_allow_tag)
                        && state.armed.iter().any(|covering| {
                            covering.allow_tag == allow.0
                                && covering.expires_at > checked_at
                                && !revoked.contains(&covering.name)
                        })
                        && dns_reject_companion_ids(allow)
                            .iter()
                            .all(|companion| coverage_ids.contains(companion))
                })
            };
            // Phase A — fence every due, otherwise-uncovered destination
            // not already fenced this settle. The fence goes through THE
            // shared withdrawal boundary (empty tag sets withdraw
            // nothing), so adoption, canonical-identity checks and
            // readback proof are identical to every other fence.
            for entry in state.armed.iter().filter(|entry| {
                entry.expires_at <= now || revoked_due_tags.contains(&entry.allow_tag)
            }) {
                for dest in &entry.destinations {
                    if entry.expires_at > now
                        && !revoked_due.contains(&(entry.allow_tag.clone(), dest.clone()))
                    {
                        continue;
                    }
                    if fenced_dests.contains(dest)
                        || state
                            .owed_evidence
                            .contains(&(entry.allow_tag.clone(), dest.clone()))
                    {
                        continue;
                    }
                    handled_dests.insert(dest.clone());
                    // Coverage is checked — and blind fences reconciled —
                    // EVERY round for every due pair (C36 r24 F4), never
                    // gated on the withdrawal attempt set: an unproven
                    // release retries here even while the identity's own
                    // withdrawal keeps failing.
                    let survivors_cover =
                        observed_cover(dest, &entry.allow_tag) || static_covers(dest);
                    if survivors_cover {
                        // C36 r24 F4: a VERIFIED, unexpired surviving
                        // authorization makes every lease fence on this
                        // destination pure over-denial — including the
                        // blind pre-fence installed at this round's top,
                        // which knew nothing of the coverage. Reconcile
                        // NOW, independently of the expiring identity's
                        // withdrawal (Phase B may fail and retry for
                        // minutes; the covering grant's traffic must
                        // flow meanwhile). The release runs through the
                        // lease's journaled, deadline-bounded path —
                        // identical to Phase C — and NEVER touches a
                        // refresh-family fence. An unproven release
                        // keeps the fence journaled and the obligation
                        // armed so the next round retries.
                        let covered_fences: Vec<AclRuleId> = coverage_ids
                            .iter()
                            .filter(|id| {
                                super::network::is_dns_lease_fence_tag(&id.0)
                                    && id.1 == "reject"
                                    && id.2 == "enabled"
                                    && id.7 == *dest
                            })
                            .cloned()
                            .collect();
                        let mut releases = self.read_dns_lease_releases(sandbox_id);
                        for fence_id in covered_fences {
                            // Journal unreadable (C36 r25 F4): NEVER
                            // release a fence whose removal cannot be
                            // journaled — the fence stays and the round
                            // is marked failed for retry.
                            let releases = match releases.as_mut() {
                                Ok(releases) => releases,
                                Err(_) => {
                                    failed_tags.insert(entry.allow_tag.clone());
                                    failed = true;
                                    continue;
                                }
                            };
                            releases.insert(fence_id.0.clone());
                            if self
                                .persist_dns_lease_releases(sandbox_id, releases)
                                .is_err()
                            {
                                failed_tags.insert(entry.allow_tag.clone());
                                failed = true;
                                continue;
                            }
                            let remaining =
                                round_deadline.saturating_duration_since(Instant::now());
                            match self.withdraw_rule_proven(acl_name, &fence_id, Some(remaining)) {
                                Ok(WithdrawalProof::PositivelyWithdrawn)
                                | Ok(WithdrawalProof::ProvenAbsent) => {
                                    releases.remove(&fence_id.0);
                                    if self
                                        .persist_dns_lease_releases(sandbox_id, releases)
                                        .is_err()
                                    {
                                        failed_tags.insert(entry.allow_tag.clone());
                                        failed = true;
                                    }
                                }
                                _ => {
                                    failed_tags.insert(entry.allow_tag.clone());
                                    failed = true;
                                }
                            }
                        }
                        continue;
                    }
                    if attempted.contains(&(entry.allow_tag.clone(), dest.clone()))
                        || !entry.fence_on_expiry.contains(dest)
                    {
                        continue;
                    }
                    match self.enforce_destination_withdrawal(
                        sandbox_id,
                        acl_name,
                        dest,
                        &[],
                        &[],
                        true,
                        false,
                        None,
                        Some(round_deadline),
                        true,
                        &mut lease_fence_alloc,
                    ) {
                        Ok(outcome) => {
                            fenced_dests.insert(dest.clone());
                            if let Some(fence) = outcome.fence_added {
                                phase_fences.insert(dest.clone(), fence);
                            }
                        }
                        // The fence would not install: fail closed — the
                        // obligation stays armed and the next tick retries.
                        Err(_) => {
                            failed_tags.insert(entry.allow_tag.clone());
                            failed = true;
                        }
                    }
                }
            }
            // Phase B — ONE bounded withdrawal per round. A revoked pair
            // is withdrawn through the same coverage gate as an expiry
            // (C36 r31 F3): `survivors_cover` is the observed, complete,
            // non-revoked surviving group and a destination outside
            // `fence_on_expiry` is statically covered — a refused
            // withdrawal installs the quarantine ONLY when neither
            // holds, so a recorded denial never suppresses the traffic a
            // legitimate sibling grant or the static policy still
            // authorizes.
            let now = self.dns_clock.unix_now()?;
            let Some((entry, dest)) = state
                .armed
                .iter()
                .filter(|entry| {
                    entry.expires_at <= now || revoked_due_tags.contains(&entry.allow_tag)
                })
                .find_map(|entry| {
                    entry
                        .destinations
                        .iter()
                        .find(|dest| {
                            (entry.expires_at <= now
                                || revoked_due
                                    .contains(&(entry.allow_tag.clone(), (*dest).clone())))
                                && !attempted.contains(&(entry.allow_tag.clone(), (*dest).clone()))
                                && !state
                                    .owed_evidence
                                    .contains(&(entry.allow_tag.clone(), (*dest).clone()))
                        })
                        .map(|dest| (entry.clone(), dest.clone()))
                })
            else {
                break;
            };
            attempted.insert((entry.allow_tag.clone(), dest.clone()));
            // Coverage is the OBSERVED, COMPLETE surviving group (C36
            // r23 F6) — the same requirement the refresh's
            // `verified_cover` applies — never the mere existence of an
            // unexpired overlapping obligation.
            let survivors_cover = observed_cover(&dest, &entry.allow_tag) || static_covers(&dest);
            let uncovered = !survivors_cover && entry.fence_on_expiry.contains(&dest);
            // The final live authorization for this destination is
            // expiring while a broadening mutation for it is unresolved:
            // the fence STAYS after the withdrawal (C36 r18 F1). On a
            // clean expiry it is withdrawn again below, after the allow
            // is proven gone.
            //
            // The release gate is DESTINATION-WIDE (C36 r26 F3): proving
            // the EXPIRING identity withdrawn is never enough while any
            // OTHER enabled allow for the destination survives observed.
            // `uncovered` already establishes that nothing observed is an
            // EFFECTIVE authorization, so any surviving allow here is an
            // unauthorized one — e.g. a REVOKED sibling grant whose own
            // withdrawal keeps failing (C36 r25 F3): its traffic must
            // stay fenced until its withdrawal proves out (a later round
            // re-evaluates and releases), never released as a side effect
            // of THIS identity's clean withdrawal. A genuinely verified
            // survivor takes the covered branch instead and the fence is
            // reconciled away there (C36 r24 F4) — usability preserved.
            let unauthorized_survivor = uncovered
                && coverage_ids
                    .iter()
                    .any(|allow| dns_allow_id_is_effective_cover(allow, &dest, &entry.allow_tag));
            let keep_fence = uncovered
                && (pending_allow_dests
                    .as_ref()
                    .is_none_or(|dests| dests.contains(&dest))
                    || unauthorized_survivor);
            let covered = survivors_cover || !entry.fence_on_expiry.contains(&dest);
            // The withdrawal budget is the time REMAINING to the round
            // deadline (C36 r21 F2): Phase A's fencing and readbacks
            // already consumed wall clock against the same next-expiry
            // deadline, so the withdrawal gets what is actually left.
            let withdraw_budget = Some(round_deadline.saturating_duration_since(Instant::now()));
            match self.enforce_destination_withdrawal(
                sandbox_id,
                acl_name,
                &dest,
                std::slice::from_ref(&entry.allow_tag),
                std::slice::from_ref(&entry.reject_tag),
                uncovered,
                covered,
                withdraw_budget,
                Some(round_deadline),
                true,
                &mut lease_fence_alloc,
            ) {
                Ok(outcome) => {
                    if let Some(fence) = outcome.fence_added {
                        phase_fences.entry(dest.clone()).or_insert(fence);
                    }
                    for proof in outcome.positive {
                        state.owed_evidence.insert(proof);
                    }
                    // A stalled companion removal must not retire the
                    // obligation (C36 r21 F2): the leftover denies are
                    // safe, but retirement ends the retries that would
                    // clean them up — the destination stays fenced and
                    // the obligation armed until the withdrawal proves
                    // out, exactly like the refresh pass treats an
                    // unproven companion removal as fatal to the pass.
                    let companions_failed = !outcome.companion_failures.is_empty();
                    // Phase C — a clean expiry leaves no rule behind: with
                    // the allow proven withdrawn and no pending broadening
                    // mutation to defend against, the deadline fence is
                    // withdrawn again (deny-direction, best-effort — an
                    // unproven removal merely leaves over-denial the
                    // derivation carries). The fences removed are every
                    // canonical LEASE-family fence on the destination —
                    // the one THIS settle installed, one adopted from an
                    // interrupted earlier attempt, AND any whose earlier
                    // removal is still unresolved (C36 r23 F4) — never a
                    // refresh-family fence, which defends the refresh's
                    // own pending mutations.
                    //
                    // EVERY removal is journaled in the lease's own
                    // release journal BEFORE issuance (C36 r23 F4): an
                    // unproven removal leaves the identity listed, and no
                    // later round (or later ISSUANCE relying on a fence
                    // for this destination) may adopt that exact fence —
                    // its deferred daemon-side removal could still
                    // complete — so a fresh epoch is allocated instead.
                    let mut deadline_fences: Vec<super::network::AclRule> = Vec::new();
                    if let Some(fence) = phase_fences
                        .remove(&dest)
                        .filter(|fence| super::network::is_dns_lease_fence_tag(&fence.description))
                    {
                        deadline_fences.push(fence);
                    }
                    for fence in outcome.lease_fences_present {
                        if !deadline_fences
                            .iter()
                            .any(|known| known.description == fence.description)
                        {
                            deadline_fences.push(fence);
                        }
                    }
                    if !deadline_fences.is_empty() {
                        if keep_fence || companions_failed {
                            fences_added.extend(deadline_fences);
                        } else {
                            let mut releases = self.read_dns_lease_releases(sandbox_id);
                            for fence in deadline_fences {
                                // Journal unreadable (C36 r25 F4): NEVER
                                // release a fence whose removal cannot be
                                // journaled — the fence stays and the
                                // round is marked failed for retry.
                                let releases = match releases.as_mut() {
                                    Ok(releases) => releases,
                                    Err(_) => {
                                        fences_added.push(fence);
                                        failed_tags.insert(entry.allow_tag.clone());
                                        failed = true;
                                        continue;
                                    }
                                };
                                let fence_id = acl_rule_id_tuple(&fence);
                                releases.insert(fence_id.0.clone());
                                // Journal FIRST: a removal issued without
                                // its intent durable could complete
                                // daemon-side after a crash with nobody
                                // left to distrust the fence.
                                if let Err(err) =
                                    self.persist_dns_lease_releases(sandbox_id, releases)
                                {
                                    fences_added.push(fence);
                                    failed_tags.insert(entry.allow_tag.clone());
                                    failed = true;
                                    let _ = err;
                                    continue;
                                }
                                // Deadline-bounded like every other
                                // operation this round (C36 r21 F2): a
                                // stalled fence withdrawal must not delay
                                // the next expiry — and must not retire
                                // the obligation either: an unproven fence
                                // withdrawal keeps the destination fenced
                                // and the obligation armed for retry, so a
                                // released stall still ends in a clean
                                // retirement.
                                let remaining =
                                    round_deadline.saturating_duration_since(Instant::now());
                                match self.withdraw_rule_proven(
                                    acl_name,
                                    &fence_id,
                                    Some(remaining),
                                ) {
                                    Ok(WithdrawalProof::PositivelyWithdrawn)
                                    | Ok(WithdrawalProof::ProvenAbsent) => {
                                        releases.remove(&fence_id.0);
                                        if self
                                            .persist_dns_lease_releases(sandbox_id, releases)
                                            .is_err()
                                        {
                                            failed_tags.insert(entry.allow_tag.clone());
                                            failed = true;
                                        }
                                    }
                                    _ => {
                                        fences_added.push(fence);
                                        failed_tags.insert(entry.allow_tag.clone());
                                        failed = true;
                                    }
                                }
                            }
                        }
                    }
                    if companions_failed {
                        failed_tags.insert(entry.allow_tag.clone());
                        failed = true;
                    }
                }
                // Withdrawal failed — the boundary already fenced the
                // destination if exposure was possible. Keep the
                // obligation armed and retry.
                Err(_) => {
                    failed_tags.insert(entry.allow_tag.clone());
                    failed = true;
                }
            }
            // Positive-withdrawal evidence is durable BEFORE the
            // obligation settles: a crash between the withdrawal and the
            // fsync must never lose the proof.
            if !state.owed_evidence.is_empty()
                && self
                    .persist_dns_lease_withdrawals(sandbox_id, &state.owed_evidence)
                    .is_ok()
            {
                state.owed_evidence.clear();
            }
        }
        // Sweep blind pre-fences whose pair went QUIET mid-settle (C36
        // r34 F2 follow-up): the due check that installed the fence and
        // this settle's own due computation bracket concurrent progress
        // — a refresh's withdrawal may have made the proof durable in
        // between, so the per-entry phases above never touch the
        // destination and the fence would be ORPHANED (a deny-all rule
        // with no obligation behind it, kept forever because nothing is
        // due to trigger another settle). Release those fences through
        // the same journaled, ownership-checked path as a clean expiry.
        // A destination that is still due, has an unresolved broadening
        // mutation, was deliberately KEPT by Phase C, or shows ANY
        // surviving allow keeps its fence; a failed observation or an
        // unreadable marker skips the sweep outright — over-denial, and
        // the armed obligation that re-triggers a settle retries it.
        let mut sweep_unfinished = false;
        if !blind_installed.is_empty() {
            // Cheap pre-filter (C36 r35 F1): a blind pre-fence whose
            // destination the per-entry phases PROCESSED this call was
            // adopted, reconciled, or deliberately kept inline — the
            // sweep owns only fences nobody touched, so when every blind
            // fence was handled it must not spend an ACL read finding
            // out (the read holds the owner lock).
            let mut orphans: BTreeMap<String, super::network::AclRule> = BTreeMap::new();
            for fence in &blind_installed {
                let Some(dest) = fence.destination.clone() else {
                    continue;
                };
                if !handled_dests.contains(&dest) {
                    orphans
                        .entry(fence.description.clone())
                        .or_insert_with(|| fence.clone());
                }
            }
            // ONE absolute deadline for the whole sweep (C36 r35 F1),
            // derived exactly like the round deadline from the earliest
            // FUTURE armed expiry: the sweep runs under the owner lock,
            // so a stalled observation — or a stalled removal per fence,
            // each with a FRESH 5s budget — would otherwise delay the
            // fencing of a grant expiring mid-sweep by seconds, and
            // repeatedly so across several orphan removals. Cleanup
            // never outranks enforcement: at the deadline the sweep
            // stops and the caller's next round fences what expired; the
            // unreleased orphans stay journaled (over-denial) and a
            // later settle retries them.
            let sweep_deadline = {
                let now = self.dns_clock.unix_now().unwrap_or(0);
                let next_gap = state
                    .armed
                    .iter()
                    .filter(|entry| entry.expires_at > now)
                    .map(|entry| entry.expires_at - now)
                    .min();
                Instant::now()
                    + Duration::from_secs(
                        next_gap
                            .unwrap_or(LEASE_WITHDRAWAL_BUDGET_SECS)
                            .clamp(1, LEASE_WITHDRAWAL_BUDGET_SECS),
                    )
            };
            let sweep_budget = sweep_deadline.saturating_duration_since(Instant::now());
            // Nothing to sweep, or a deadline already arrived:
            // enforcement resumes without another observation.
            if !orphans.is_empty() && sweep_budget.is_zero() {
                sweep_unfinished = true;
            }
            if !orphans.is_empty() && !sweep_budget.is_zero() {
                sweep_unfinished = true;
                let marker_now = self.read_dns_revocation_record_unscoped(sandbox_id);
                let observed_now = self.read_sandbox_acl_within(acl_name, Some(sweep_budget));
                if let (Ok(marker_now), Ok(Some(observed_now))) = (marker_now, observed_now)
                    && self
                        .require_owned_dns_acl(&observed_now, sandbox_id, acl_name)
                        .is_ok()
                {
                    let pend_now: BTreeSet<String> = marker_now
                        .iter()
                        .flat_map(|record| record.pending.iter())
                        .filter(|pending| pending.kind == PendingKind::Allow)
                        .map(|pending| pending.destination.clone())
                        .chain(marker_now.iter().flat_map(|record| {
                            record
                                .standing_fences
                                .iter()
                                .map(|standing| standing.destination().to_string())
                        }))
                        .collect();
                    let revoked_now = self.revoked_due_dns_lease_pairs(sandbox_id, state);
                    let quiet_at = self.dns_clock.unix_now().unwrap_or(0);
                    let mut releases = self.read_dns_lease_releases(sandbox_id);
                    let mut finished = true;
                    for fence in orphans.values() {
                        let Some(dest) = fence.destination.clone() else {
                            continue;
                        };
                        // The deadline is checked per fence (C36 r35 F1): a
                        // stalled removal consumed the rest of the budget, so
                        // further cleanup waits for a later settle — the next
                        // round fences whatever expired in the meantime.
                        let removal_budget =
                            sweep_deadline.saturating_duration_since(Instant::now());
                        if removal_budget.is_zero() {
                            finished = false;
                            break;
                        }
                        let still_due = state.armed.iter().any(|entry| {
                            entry.destinations.contains(&dest)
                                && (entry.expires_at <= quiet_at
                                    || revoked_now
                                        .contains(&(entry.allow_tag.clone(), dest.clone())))
                        });
                        let any_allow_survives = observed_now
                            .egress
                            .iter()
                            .any(|rule| rule.action == "allow" && rule.destination == dest);
                        if still_due || pend_now.contains(&dest) || any_allow_survives {
                            continue;
                        }
                        let releases = match releases.as_mut() {
                            Ok(releases) => releases,
                            Err(_) => {
                                finished = false;
                                break;
                            }
                        };
                        let fence_id = acl_rule_id_tuple(fence);
                        releases.insert(fence_id.0.clone());
                        if self
                            .persist_dns_lease_releases(sandbox_id, releases)
                            .is_err()
                        {
                            finished = false;
                            break;
                        }
                        match self.withdraw_rule_proven(acl_name, &fence_id, Some(removal_budget)) {
                            Ok(WithdrawalProof::PositivelyWithdrawn)
                            | Ok(WithdrawalProof::ProvenAbsent) => {
                                releases.remove(&fence_id.0);
                                if self
                                    .persist_dns_lease_releases(sandbox_id, releases)
                                    .is_err()
                                {
                                    finished = false;
                                    break;
                                }
                            }
                            // Unproven: the fence stays listed in the
                            // release journal and in place; a later
                            // settle reconciles it.
                            _ => {}
                        }
                    }
                    sweep_unfinished = !finished;
                }
            }
        }
        // Cleanup cut short resumes as ENFORCEMENT before any
        // retirement (C36 r35 F1): a grant that expired while an
        // unfinished sweep held the lock — killed at the deadline, or
        // failed mid-release — is fenced NOW, in this same boundary, not
        // one watcher tick later. Only an UNFINISHED sweep pays for the
        // pass: a completed (or never-needed) sweep proves no expiry was
        // awaited, so the common settle path is byte-identical to r34.
        if sweep_unfinished {
            let _ =
                self.prefence_due_dns_dests(sandbox_id, acl_name, state, &mut settle_transition);
        }
        // An obligation settles once every destination's withdrawal is
        // proven AND its evidence is durable. A deferred re-apply of the
        // withdrawn identity is covered by the pending-mutation journal
        // (every issuance is journaled before it is issued), not by
        // keeping the obligation armed (C36 r19 F5: retirement is what
        // commits the lifecycle transition).
        let now = self.dns_clock.unix_now()?;
        // Durable withdrawal evidence is read ONCE here, after the
        // trailing flush: a destination whose withdrawal the flush just
        // made durable was never ATTEMPTED this settle (Phase B skips
        // re-attempting durable pairs), and it never becomes due again —
        // gating retirement on the attempt alone would strand such an
        // entry armed forever with the watcher asleep (the
        // restarted-owner retirement flake). Attempted OR durable are
        // both complete settlements; the r35 bug case (expired
        // mid-sweep, never withdrawn) has neither and stays armed.
        let durable_withdrawals = self.read_dns_lease_withdrawals(sandbox_id);
        for entry in state.armed.iter().filter(|entry| entry.expires_at <= now) {
            let evidence_pending = entry.destinations.iter().any(|dest| {
                state
                    .owed_evidence
                    .contains(&(entry.allow_tag.clone(), dest.clone()))
            });
            // The clock is re-read HERE, after every round AND the sweep
            // (C36 r35 F1): an entry that crossed its expiry after the
            // last round's selection — during a stalled withdrawal or a
            // deadline-capped sweep — was never fenced or withdrawn by
            // this settle. Retiring it would strand its allow effective
            // AND disarm the watcher's fencing: the worst possible
            // outcome, hidden by the armed ledger going quiet. Only an
            // entry whose every destination was actually attempted this
            // settle — or already carries durable withdrawal evidence —
            // may retire; anything else stays armed and the next tick
            // fences and withdraws it.
            let withdrawal_attempted = entry.destinations.iter().all(|dest| {
                let pair = (entry.allow_tag.clone(), dest.clone());
                attempted.contains(&pair) || durable_withdrawals.contains(&pair)
            });
            // An unreadable marker means the settlement cannot be
            // accounted for (a pending mutation for this identity cannot
            // be ruled out): the obligation stays armed even when the
            // withdrawal itself proved out (C36 r18 F4).
            if !failed_tags.contains(&entry.allow_tag)
                && !evidence_pending
                && !marker_failed
                && withdrawal_attempted
            {
                settled.push(entry.clone());
            }
        }
        // A fence still installed for a destination whose withdrawal
        // failed (or was never reached) stays: record it so the
        // settlement derivation expects it (C36 r20 F1).
        fences_added.extend(std::mem::take(&mut phase_fences).into_values());
        if !settled.is_empty() {
            // Commit the expiry as a lifecycle state transition (C36 r19
            // F5): the persisted DNS state and network plan are rewritten
            // to the post-settlement truth BEFORE the obligations retire,
            // so readiness and reconnect compare the live ACL against the
            // settled reality — never against a stale pre-expiry plan.
            // The rewrite VALIDATES the live ACL against the derivation
            // (C36 r19 F4): unrelated drift refuses the settlement and
            // keeps the obligations armed instead of being ratified.
            let settled_tags: BTreeSet<String> = settled
                .iter()
                .flat_map(|entry| [entry.allow_tag.clone(), entry.reject_tag.clone()])
                .collect();
            let fence_dests: BTreeSet<String> = state
                .armed
                .iter()
                .flat_map(|entry| entry.destinations.iter().cloned())
                .collect();
            // The commit is bounded by the NEXT LIVE armed expiry
            // measured NOW (C36 r22 F1): withdrawing destinations no
            // longer gate timing (their quarantine fences are already in
            // place), but an unbounded commit wait behind a stalled
            // refresh — or a slow ACL read — would delay fencing the
            // next due destination.
            let commit_deadline = {
                let gap = state
                    .armed
                    .iter()
                    .filter(|entry| entry.expires_at > now)
                    .map(|entry| entry.expires_at - now)
                    .min();
                Some(
                    Instant::now()
                        + Duration::from_secs(
                            gap.unwrap_or(LEASE_WITHDRAWAL_BUDGET_SECS)
                                .clamp(1, LEASE_WITHDRAWAL_BUDGET_SECS),
                        ),
                )
            };
            self.rewrite_persisted_state_after_lease_settlement(
                sandbox_id,
                acl_name,
                now,
                &settled_tags,
                &fence_dests,
                &fences_added,
                commit_deadline,
            )?;
            state.armed.retain(|armed| {
                !settled
                    .iter()
                    .any(|entry| entry.allow_tag == armed.allow_tag)
            });
        }
        // The retained obligation set is restart-durable.
        self.persist_dns_lease_obligations(sandbox_id, &state.armed)?;
        if failed {
            return Err(internal_error(
                "a DNS expiry obligation would not settle; it stays armed for retry",
            ));
        }
        Ok(())
    }

    /// Armed lease obligations whose revocation is durably recorded are
    /// IMMEDIATELY DUE in the autonomous enforcement boundary (C36 r31
    /// F2): the marker is journaled BEFORE any mutation, so a refresh
    /// that journaled an NXDOMAIN and then crashed — or whose recovery
    /// probe consumed the whole pass deadline — leaves the denied
    /// identity's allow effective until the old TTL unless the settle
    /// and the watcher treat it like an elapsed expiry. Returns the
    /// (allow tag, destination) pairs still needing enforcement: a pair
    /// whose withdrawal proof is already durable (or owed) is done.
    ///
    /// Identity precision: the marker records EVERY generation
    /// outstanding when the denial was journaled (committed AND
    /// armed-but-uncommitted — C36 r32 F1), so an entry carrying a
    /// generation in the denied set is enforced against, while an entry
    /// carrying a FRESH generation is skipped — it is a re-grant the
    /// committing refresh owns (the commit clears the marker), never the
    /// denied identity. A name
    /// without a recorded generation (a marker written before the field
    /// existed) stays enforced regardless: fail closed. An absent marker
    /// means nothing is due HERE; an UNREADABLE marker also means
    /// nothing due here — the withdrawal boundary itself fails closed on
    /// the same read, and enforcing "maybe-revoked" against LIVE grants
    /// on a storage error would deny legitimate committed traffic (the
    /// readiness gate already refuses on that error, C36 r29 F1).
    fn revoked_due_dns_lease_pairs(
        &self,
        sandbox_id: &str,
        state: &DnsLeaseOwnerState,
    ) -> BTreeSet<(String, String)> {
        let mut due = BTreeSet::new();
        let (revoked, denied_generations) =
            match self.read_dns_revocation_record_unscoped(sandbox_id) {
                Ok(Some(record)) => (
                    record.revoked.into_iter().collect::<BTreeSet<String>>(),
                    record.revoked_generations,
                ),
                _ => return due,
            };
        if revoked.is_empty() {
            return due;
        }
        let proven = self.read_dns_lease_withdrawals(sandbox_id);
        for entry in &state.armed {
            if !revoked.contains(&entry.name) {
                continue;
            }
            if let Some(denied) = denied_generations.get(&entry.name)
                && super::network::dns_tag_request_id(&entry.allow_tag)
                    .is_some_and(|generation| !denied.contains(&generation))
            {
                continue;
            }
            for dest in &entry.destinations {
                let pair = (entry.allow_tag.clone(), dest.clone());
                if !proven.contains(&pair) && !state.owed_evidence.contains(&pair) {
                    due.insert(pair);
                }
            }
        }
        due
    }

    /// The RECORDED policy's static CIDR grants (C36 r31 F3): the
    /// persisted plan's `policy_cidrs` — NEVER the resolved grant
    /// expansion (`grants`), whose DNS answers are expiring
    /// authorizations, not static coverage (crediting them would suppress
    /// every expiry fence over a granted destination). An absent or
    /// malformed record yields NO static coverage — fail closed (fence).
    /// An entry that fails to parse is simply not covering: the fence is
    /// the safe direction.
    fn recorded_static_grant_cidrs(&self, sandbox_id: &str) -> Vec<super::network::GrantCidr> {
        self.persisted_enforcement_plan(sandbox_id)
            .map(|plan| {
                plan.policy_cidrs
                    .iter()
                    .filter_map(|raw| parse_policy_cidr(raw).ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Blind deadline fencing (C36 r23 F10): install a lease fence for
    /// every DUE destination still needing one, WITHOUT any preliminary
    /// observation. Deadline enforcement is separated from observation
    /// and cleanup: retaining an obligation is not equivalent to denying
    /// expired traffic, so a stalled read must never leave an expired
    /// destination allowed while the settle computes. The fence add is
    /// deny-direction (over-denial only if the destination turns out
    /// covered — the settle's Phase C releases it through the journaled
    /// path), carries a FRESH epoch (identity uniqueness needs no
    /// observation), and runs through a permit-free, tightly bounded
    /// client. Failures simply retry next tick; the reliable
    /// adopt-or-install inside the settlement supersedes these fences.
    /// `transition` is the caller's lazily-acquired transition-guard cell
    /// (C37 R6): it is filled — once — only when this pass genuinely
    /// installs a fence, so marking tracks ACTUAL mutations (a grant that
    /// expires mid-probe is still marked) and a no-op pass never churns
    /// the epoch. The caller retains the guard through the pass's commit.
    fn prefence_due_dns_dests(
        &self,
        sandbox_id: &str,
        acl_name: &str,
        state: &mut DnsLeaseOwnerState,
        transition: &mut Option<DnsTransitionGuard>,
    ) -> Vec<super::network::AclRule> {
        let mut installed_rules: Vec<super::network::AclRule> = Vec::new();
        let Ok(now) = self.dns_clock.unix_now() else {
            return installed_rules;
        };
        // Prune the pre-fence cache to CURRENTLY ARMED (identity,
        // destination, expiry) triples (C36 r34 F4): a settled identity
        // or a superseded expiry is dropped here, so a long-lived
        // sandbox's cache is bounded by the armed ledger — never by
        // lifetime traffic. An identity mid-settlement stays armed until
        // retirement (guarded by `owed_evidence`), so the
        // release-then-retire path still never re-fences mid-settle.
        {
            let armed: BTreeSet<(String, String, u64)> = state
                .armed
                .iter()
                .flat_map(|entry| {
                    entry
                        .destinations
                        .iter()
                        .map(|dest| (entry.allow_tag.clone(), dest.clone(), entry.expires_at))
                })
                .collect();
            state.prefenced.retain(|triple| armed.contains(triple));
        }
        // ONE absolute deadline for the whole pass (C36 r25 F1), derived
        // from the earliest FUTURE expiry: a grant that lapses while an
        // earlier destination's fence add stalls must still be
        // discovered and fenced. The watcher re-invokes this boundary
        // whenever observation fails, so stopping AT the deadline —
        // never overrunning it — keeps every expiry enforced; with no
        // future expiry the 20s default caps one pass's damage to the
        // next detection.
        let deadline = {
            let gap = state
                .armed
                .iter()
                .filter(|entry| entry.expires_at > now)
                .map(|entry| entry.expires_at - now)
                .min()
                .unwrap_or(20)
                .clamp(1, 20);
            Instant::now() + Duration::from_secs(gap)
        };
        // Destination-DEDUPLICATED (C36 r25 F1): N expiring identities
        // over one destination need ONE fence, not N serialized adds;
        // the per-identity cache entries are recorded together on
        // success.
        let mut due: BTreeMap<String, Vec<(String, u64)>> = BTreeMap::new();
        // Recorded revocations are due IMMEDIATELY (C36 r31 F2): the
        // denied destination gets its blind fence before any observation,
        // exactly like an elapsed TTL — only the coverage-aware settle
        // reconciles it away when a surviving authorization is verified.
        let revoked_due = self.revoked_due_dns_lease_pairs(sandbox_id, state);
        // The recorded static policy's destinations are authorized
        // outright (C36 r31 F3): never blind-fence them.
        let recorded_statics = self.recorded_static_grant_cidrs(sandbox_id);
        let static_covers = |dest: &str| {
            dest.strip_suffix("/32")
                .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
                .is_some_and(|ip| recorded_statics.iter().any(|grant| grant.contains(ip)))
        };
        for entry in state.armed.iter() {
            let expired = entry.expires_at <= now;
            for dest in entry
                .destinations
                .iter()
                .filter(|dest| entry.fence_on_expiry.contains(*dest) && !static_covers(dest))
            {
                if expired || revoked_due.contains(&(entry.allow_tag.clone(), dest.clone())) {
                    due.entry(dest.clone())
                        .or_default()
                        .push((entry.allow_tag.clone(), entry.expires_at));
                }
            }
        }
        if due.is_empty() {
            return installed_rules;
        }
        // Most-RECENTLY-expired identities first: a destination whose
        // obligation just lapsed has had no settle time at all, while
        // older expiries had every tick since theirs — and a destination
        // that became due mid-pass (the deadline break above re-enters
        // this boundary on the next tick) is fenced before stale retries
        // consume the fresh deadline (C36 r25 F1).
        let mut due: Vec<(String, Vec<(String, u64)>)> = due.into_iter().collect();
        due.sort_by(|left, right| {
            let newest = |pairs: &[(String, u64)]| pairs.iter().map(|pair| pair.1).max();
            newest(&right.1)
                .cmp(&newest(&left.1))
                .then_with(|| left.0.cmp(&right.0))
        });
        let mut client = self.clone();
        client.cancelled = None;
        // Ownership BEFORE the blind add (C36 r34 F2): a daemon restarting
        // with an overdue owned ledger must never add a fence to a
        // same-named ACL that was REPLACED or RETAGGED foreign meanwhile.
        // The read is tightly bounded and best-effort in the safe
        // direction only: a SUCCESSFUL read proving foreign tags vetoes
        // the whole pass (zero mutations), while a STALLED or failed read
        // falls back to the blind add — the pre-fence's whole purpose
        // (r23 F10) is that a stalled read must never delay enforcement,
        // and every LATER mutation boundary (settle, release) re-checks
        // ownership from its own successful read before touching a rule.
        let ownership_budget = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(5));
        if !ownership_budget.is_zero()
            && let Ok(Some(observed)) =
                client.read_sandbox_acl_within(acl_name, Some(ownership_budget))
            && self
                .require_owned_dns_acl(&observed, sandbox_id, acl_name)
                .is_err()
        {
            return installed_rules;
        }
        // C37 R6: acquire the transition mark HERE, at the shared mutation
        // boundary — lazily, once a fence add is genuinely required (due
        // is non-empty and ownership passed), immediately before the first
        // actual mutation. Prediction at pass entry cannot see a grant
        // that expires mid-probe; this can. A pass with nothing due
        // returned above and never marks. (A pass whose fences all turn
        // out already-installed may mark without a mutation — rare, and
        // conservative: a concurrent verifier retries once and reads a
        // coherent snapshot.)
        if transition.is_none() {
            *transition = Some(self.begin_dns_transition(sandbox_id));
        }
        for (dest, pairs) in due {
            if pairs.iter().all(|(tag, expiry)| {
                state
                    .prefenced
                    .contains(&(tag.clone(), dest.clone(), *expiry))
                    || state.owed_evidence.contains(&(tag.clone(), dest.clone()))
            }) {
                continue;
            }
            // Stop AT the deadline (never overrun): the next loop tick
            // re-detects anything still unfenced — including grants that
            // became due while this pass ran.
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let Ok(epoch) = self.allocate_lease_fence_epoch(sandbox_id) else {
                continue;
            };
            let Some(addr) = dest
                .strip_suffix("/32")
                .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
            else {
                continue;
            };
            let fence = super::network::domain_lease_fence_rule(addr, epoch);
            let mut args = vec![
                "network".to_string(),
                "acl".to_string(),
                "rule".to_string(),
                "add".to_string(),
                acl_name.to_string(),
                "egress".to_string(),
            ];
            args.extend(fence.cli_args());
            let argv = args.iter().map(String::as_str).collect::<Vec<_>>();
            // Tightly bounded AND deadline-capped: the pre-fence exists
            // so a STALLED observation cannot delay enforcement; it must
            // not become the stall itself.
            let installed = client
                .run_bounded(&argv, false, remaining.min(Duration::from_secs(5)))
                .map(|out| out.exit_code == 0)
                .unwrap_or(false);
            if installed {
                for (tag, expiry) in pairs {
                    state.prefenced.insert((tag, dest.clone(), expiry));
                }
                installed_rules.push(fence);
                #[cfg(test)]
                if let Some(hook) = &self.dns_prefence_hook {
                    (hook.0)(state.prefenced.len());
                }
            } else {
                // One attempt per destination per pass, and the pass
                // STOPS at the first failure (C36 r25 F1): a stalled or
                // refused add must not serialize the remaining
                // destinations behind it — the settle's reliable
                // adopt-or-install covers them THIS round, and the next
                // tick retries the blind fence.
                break;
            }
        }
        installed_rules
    }

    fn dns_expiry_lease_watch(
        &self,
        owner: std::sync::Arc<DnsLeaseOwner>,
        sandbox_id: String,
        acl_name: String,
    ) {
        loop {
            let mut state = owner.state.lock().unwrap_or_else(|err| err.into_inner());
            if !state.alive || self.host_children.is_closed() {
                state.watcher_running = false;
                return;
            }
            let has_due = match self.dns_clock.unix_now() {
                Ok(now) => {
                    state.armed.iter().any(|entry| entry.expires_at <= now)
                        // A durably recorded REVOCATION is immediately
                        // due (C36 r31 F2): the watcher is the autonomous
                        // enforcement boundary that retries the denied
                        // identity's withdrawal until it proves out — no
                        // API call required, no dependence on a recovery
                        // pass deadline another sandbox's settlement may
                        // have stalled past.
                        || !self
                            .revoked_due_dns_lease_pairs(&sandbox_id, &state)
                            .is_empty()
                }
                Err(_) => {
                    state.watcher_running = false;
                    return;
                }
            };
            if has_due {
                // C37 R3: the whole settle pass — pre-fence, bounded read,
                // withdrawal, plan commit — is ONE marked transition so a
                // concurrent enforcement verification never convicts the
                // mid-transition (fenced, not yet committed) state of drift.
                let _transition = self.begin_dns_transition(&sandbox_id);
                // Deadline fencing comes FIRST (C36 r23 F10): an expired
                // destination is fenced before ANY preliminary
                // observation, so a stalled read can never leave it
                // allowed while the settlement computes. Fencing is
                // enforcement; observation and cleanup are not — a
                // retained obligation never denied any traffic by
                // itself.
                //
                // ONE absolute deadline carries across the pre-fence AND
                // the observation (C36 r26 F2): it is captured BEFORE the
                // pre-fence pass from the earliest FUTURE armed expiry, so
                // a pre-fence pass that stalls until that expiry cannot
                // re-arm the preliminary read with a fresh 20s budget that
                // excludes the newly-due destination. When the deadline
                // has arrived, the newly-due destinations are re-discovered
                // and fenced BEFORE any further observation work starts.
                let pass_deadline = {
                    let now = self.dns_clock.unix_now().unwrap_or(0);
                    let next_gap = state
                        .armed
                        .iter()
                        .filter(|entry| entry.expires_at > now)
                        .map(|entry| entry.expires_at - now)
                        .min();
                    Instant::now()
                        + Duration::from_secs(
                            next_gap
                                .unwrap_or(LEASE_WITHDRAWAL_BUDGET_SECS)
                                .clamp(1, LEASE_WITHDRAWAL_BUDGET_SECS),
                        )
                };
                let blind =
                    self.prefence_due_dns_dests(&sandbox_id, &acl_name, &mut state, &mut None);
                // The preliminary read is deadline-bounded like every
                // other operation on this path (C36 r22 F1): it runs
                // UNDER the owner lock, so an unbounded read (the host
                // timeout is 120s) would delay the fencing of a
                // destination expiring DURING the stall. The budget is
                // what REMAINS of the pass deadline — never a recomputed
                // gap that would exclude an expiry the pre-fence just
                // consumed (C36 r26 F2). An exhausted deadline skips the
                // read outright: the kill/miss is just an observation
                // failure — obligations stay armed, the pre-fence below
                // protects the newly due, and the short tick retries.
                if owner
                    .recovery_waiters
                    .load(std::sync::atomic::Ordering::Acquire)
                    > 0
                {
                    let (guard, _) = owner
                        .wake
                        .wait_timeout(state, Duration::from_millis(10))
                        .unwrap_or_else(|err| err.into_inner());
                    drop(guard);
                    continue;
                }
                let read_budget = pass_deadline.saturating_duration_since(Instant::now());
                let read = if read_budget.is_zero() {
                    None
                } else {
                    Some(self.read_sandbox_acl_within(&acl_name, Some(read_budget)))
                };
                match read {
                    // The sandbox (and its ACL) is GONE: every obligation
                    // is moot — settle all of them and stop.
                    Some(Ok(None)) => {
                        state.armed.clear();
                        state.owed_evidence.clear();
                        let _ = self.persist_dns_lease_obligations(&sandbox_id, &[]);
                        state.watcher_running = false;
                        return;
                    }
                    // Withdraw the lapsed identities NOW, whatever the
                    // refresh loop is doing — the whole settle runs under
                    // the owner lock (C36 r18 F5). Failures keep the
                    // obligation armed and are retried below (C36 r18 F4).
                    Some(Ok(Some(_))) => {
                        let _ =
                            self.settle_due_dns_lease(&sandbox_id, &acl_name, &mut state, &blind);
                    }
                    // A failed observation NEVER settles obligations
                    // (C36 r18 F4): retry on the short tick. The
                    // pre-fence runs AGAIN here (C36 r23 F10): the
                    // stalled read may have spanned another deadline —
                    // destinations that expired DURING it are fenced now,
                    // at their own deadline, not after another tick. The
                    // deadline-exhausted skip (C36 r26 F2) lands here too:
                    // newly-due destinations are fenced BEFORE the next
                    // observation is attempted.
                    _ => {
                        self.prefence_due_dns_dests(&sandbox_id, &acl_name, &mut state, &mut None);
                    }
                }
            } else if !state.owed_evidence.is_empty() {
                // Same C37 R3 transition marking for the evidence sweep.
                let _transition = self.begin_dns_transition(&sandbox_id);
                let _ = self.settle_due_dns_lease(&sandbox_id, &acl_name, &mut state, &[]);
            }
            let Ok(now) = self.dns_clock.unix_now() else {
                state.watcher_running = false;
                return;
            };
            if state.armed.is_empty() && state.owed_evidence.is_empty() {
                state.watcher_running = false;
                return;
            }
            // Next wake: the earliest pending expiry; 5s while a due
            // obligation is still settling or evidence is owed (this also
            // sweeps a deferred daemon-side re-apply of a withdrawn
            // identity); capped so liveness loss is noticed promptly.
            let mut wake_at = now + 60;
            if let Some(expiry) = state.armed.iter().map(|entry| entry.expires_at).min() {
                wake_at = wake_at.min(expiry);
            }
            let unsettled_due = state.armed.iter().any(|entry| entry.expires_at <= now)
                // A recorded revocation that has not enforced out yet
                // retries on the short tick too (C36 r31 F2); once every
                // revoked pair's withdrawal proof is durable the entry
                // quiesces until its own expiry.
                || !self.revoked_due_dns_lease_pairs(&sandbox_id, &state).is_empty();
            if unsettled_due || !state.owed_evidence.is_empty() {
                wake_at = wake_at.min(now + 5);
            }
            let wait = Duration::from_secs(wake_at.saturating_sub(now).max(1));
            let (guard, _) = owner
                .wake
                .wait_timeout(state, wait)
                .unwrap_or_else(|err| err.into_inner());
            drop(guard);
        }
    }

    /// Commit a proven lease settlement into the persisted lifecycle
    /// state (C36 r19 F5): drop the expired grants from the persisted
    /// DNS state (the same rule refresh planning applies) and rewrite
    /// the persisted plan rules to the post-settlement truth — DERIVED,
    /// not copied from the live ACL (C36 r19 F4): the recorded plan
    /// minus the settled identities' rules, plus the fences this
    /// settlement installed, plus any canonical fence still observed on
    /// an armed obligation's destination (installed by an earlier,
    /// failed attempt and not yet released). The live ACL must match
    /// that derivation EXACTLY — static, infrastructure, and unaffected
    /// dynamic rules included — or the settlement refuses and nothing
    /// is persisted: recovery never ratifies unrelated drift. The
    /// published dnsmasq config is left untouched: the stale ANSWER is
    /// inert without its (withdrawn) allow, and the next refresh
    /// republishes; `expected_dnsmasq_config` must keep matching the
    /// live bridge config meanwhile.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn rewrite_persisted_state_after_lease_settlement(
        &self,
        sandbox_id: &str,
        acl_name: &str,
        now: u64,
        settled_tags: &BTreeSet<String>,
        fence_dests: &BTreeSet<String>,
        fences_added: &[super::network::AclRule],
        deadline: Option<Instant>,
    ) -> Result<(), RuntimeError> {
        // THE serialized commit boundary for DNS lifecycle records (C36
        // r20 F3): the whole read-validate-persist below runs under the
        // per-sandbox commit lock shared with the refresh commit, so the
        // two writers can never interleave into a lost update; the
        // derivation re-reads the CURRENT durable record under the lock
        // (a merge against the current generation), and NOTHING is
        // persisted unless the live ACL validates against the derivation
        // first — a failed validation commits nothing.
        //
        // The commit itself is deadline-bounded (C36 r22 F1): the
        // settlement runs under the OWNER lock, so waiting on the commit
        // lock behind a stalled refresh commit — or on a slow ACL read —
        // would delay the fencing of a destination expiring meanwhile.
        // The wait and the read get what remains to the next live armed
        // expiry; on expiry the settlement fails CLOSED (nothing was
        // persisted) and the armed obligations retry.
        let owner = self.dns_lease_owner(sandbox_id);
        let _commit = loop {
            self.check_dns_refresh_cancelled()?;
            match owner.commit.try_lock() {
                Ok(guard) => break guard,
                Err(std::sync::TryLockError::Poisoned(err)) => break err.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => {
                    if deadline.is_some_and(|d| Instant::now() >= d) {
                        return Err(internal_error(
                            "the lifecycle commit lock wait exceeded the lease deadline; the settlement stays armed for retry",
                        ));
                    }
                    // Bounded, non-spinning wait; the deadline is the
                    // backstop, so a stalled holder cannot block the next
                    // expiry's enforcement.
                    std::thread::sleep(Duration::from_millis(25));
                }
            }
        };
        let now = self.dns_clock.unix_now()?.max(now);
        let body = match std::fs::read_to_string(self.dns_state_path(sandbox_id)) {
            Ok(body) => body,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => {
                return Err(internal_error(format!(
                    "cannot read the persisted DNS state during lease recovery: {err}"
                )));
            }
        };
        let mut state = serde_json::from_str::<SandboxDnsState>(&body).map_err(|err| {
            internal_error(format!(
                "cannot decode the persisted DNS state during lease recovery: {err}"
            ))
        })?;
        if state.sandbox_id != sandbox_id {
            return Err(internal_error(
                "persisted DNS state belongs to a different sandbox; refusing recovery",
            ));
        }
        state.grants.retain(|entry| entry.expires_at > now);
        // Generation history is NEVER pruned (C36 r19 F1): a request
        // identity (`name`, `generation`) must stay unique for the
        // sandbox's whole life — durable positive-withdrawal evidence is
        // keyed by the exact tag, and reusing generation zero for a
        // re-grant would let stale evidence "prove" a NEW issuance.
        // Nothing is persisted yet: the derivation below must VALIDATE
        // against the live ACL before any record moves (C36 r20 F3).
        // The read is bounded by the same deadline (C36 r22 F1): it runs
        // under the owner lock, so it must never stall the next expiry.
        let read_budget = deadline.map(|d| d.saturating_duration_since(Instant::now()));
        if read_budget == Some(Duration::ZERO) {
            return Err(internal_error(
                "the lease deadline expired before the settlement read; the settlement stays armed for retry",
            ));
        }
        let Some(observed) = self.read_sandbox_acl_within(acl_name, read_budget)? else {
            // The ACL is gone; readiness verification fails on its own.
            return Ok(());
        };
        let Some(recorded) = self.persisted_plan_rules(sandbox_id, &state.policy_hash) else {
            return Err(internal_error(
                "the recorded plan is unavailable for the lease settlement derivation; refusing to ratify the live ACL",
            ));
        };
        // Identity tuples include the direction and the observed STATE:
        // a disabled or re-directed drifted rule must never compare
        // equal to the recorded rule (C36 r19 F4).
        #[allow(clippy::type_complexity)]
        let planned_id = |rule: &super::network::AclRule| -> (String, AclRuleId) {
            (
                rule.direction.as_str().to_string(),
                (
                    rule.description.clone(),
                    rule.action.as_str().to_string(),
                    "enabled".to_string(),
                    rule.protocol.clone().unwrap_or_default(),
                    rule.source.clone().unwrap_or_default(),
                    rule.source_port.clone().unwrap_or_default(),
                    rule.destination_port.clone().unwrap_or_default(),
                    rule.destination.clone().unwrap_or_default(),
                ),
            )
        };
        let observed_id = |rule: &super::acl::ObservedRule, direction: &str| {
            (direction.to_string(), observed_rule_id(rule))
        };
        let mut observed_ids: Vec<(String, AclRuleId)> =
            Vec::with_capacity(observed.ingress.len() + observed.egress.len());
        for rule in &observed.ingress {
            observed_ids.push(observed_id(rule, "ingress"));
        }
        for rule in &observed.egress {
            observed_ids.push(observed_id(rule, "egress"));
        }
        // Derive: recorded rules minus the settled identities'
        // withdrawn rules (a companion that would not withdraw yet is
        // carried while still observed — deny-direction only, swept by
        // the next refresh), plus this settlement's fences, plus
        // canonical fences still observed on armed-obligation
        // destinations (leftovers of earlier failed attempts).
        let mut expected: Vec<super::network::AclRule> = Vec::with_capacity(recorded.len());
        for rule in &recorded {
            let id = planned_id(rule);
            if settled_tags.contains(&rule.description) && !observed_ids.contains(&id) {
                continue;
            }
            // A recorded LEASE fence on an armed obligation's destination
            // is re-derived from the live truth below (this settlement's
            // `fences_added`, then the carried-observation loop): a clean
            // expiry withdraws the fence BEFORE this rewrite, so the
            // stale record of an earlier partial settlement must not
            // force it back into the expectation (C36 r20 F1).
            if super::network::dns_lease_fence_epoch(&rule.description).is_some()
                && fence_dests.contains(rule.destination.as_deref().unwrap_or_default())
            {
                continue;
            }
            expected.push(rule.clone());
        }
        for fence in fences_added {
            let id = planned_id(fence);
            if !expected.iter().any(|rule| planned_id(rule) == id) {
                expected.push(fence.clone());
            }
        }
        // Canonical LEASE fences are carried while their epoch is within
        // the durable lease counter (i.e., provably allocated by this
        // host's lease), on ANY destination (C36 r20 F1): expiry now
        // fences unconditionally, and a fence whose removal is unproven
        // can outlive the obligation that installed it. Anything else —
        // including a fence-tagged rule past the counter — is drift.
        let lease_counter = self.read_dns_lease_fence_counter(sandbox_id)?;
        for rule in &observed.egress {
            let carried_lease_fence = super::network::dns_lease_fence_epoch(&rule.description)
                .is_some_and(|epoch| epoch <= lease_counter);
            if (fence_dests.contains(&rule.destination) || carried_lease_fence)
                && is_canonical_dns_fence(rule, &rule.destination.clone())
            {
                let carried = rule.as_acl_rule(super::network::AclDirection::Egress)?;
                let id = planned_id(&carried);
                if !expected.iter().any(|existing| planned_id(existing) == id) {
                    expected.push(carried);
                }
            }
        }
        let mut expected_ids: Vec<(String, AclRuleId)> = expected.iter().map(planned_id).collect();
        // Preview tunnels: while a runtime port change is unconfirmed, the
        // live tunnel rule may be either variant (and nothing else); it is
        // compared on its own, and the record keeps its committed rule.
        if let Some(plan) = self.persisted_enforcement_plan(sandbox_id)
            && let Some(pending) = plan
                .settings
                .as_ref()
                .and_then(|settings| settings.tunnel_pending.as_ref())
        {
            if !super::tunnel_ports::tunnel_rule_is_known_variant(
                &observed.ingress,
                plan.gateway,
                plan.tunnel_ports(),
                &pending.ports,
            ) {
                return Err(internal_error(
                    "the live tunnel rule is neither the recorded nor the pending variant; refusing to ratify the drift",
                ));
            }
            let tunnel =
                |(_, id): &(String, AclRuleId)| id.0 != super::network::TUNNEL_INGRESS_RULE_TAG;
            expected_ids.retain(tunnel);
            observed_ids.retain(tunnel);
        }
        expected_ids.sort();
        observed_ids.sort();
        if expected_ids != observed_ids {
            return Err(internal_error(
                "the live ACL differs from the recorded plan beyond the proven lease settlement; refusing to ratify the drift",
            ));
        }
        // Validated: commit the state transition and the derived plan
        // together, still under the commit lock.
        self.persist_dns_state(&state)?;
        self.update_persisted_plan_rules(sandbox_id, &state.policy_hash, &expected)
    }

    /// Retire the expiry lease WITH its sandbox (C36 r20 F4): called from
    /// network teardown AFTER the ownership-fenced resource deletions, so
    /// a stale teardown refused by those fences never reaches here and can
    /// never stop a newer incarnation's lease. Stops and unmaps the owner
    /// (production previously leaked one entry per sandbox forever), then
    /// durably retires the obligations, the withdrawal evidence, and the
    /// fence-epoch counter — none of them may cross the incarnation
    /// boundary. The GENERATION history is tombstoned first: a recreated
    /// sandbox must never reuse a request identity a late daemon-side
    /// mutation of the old incarnation could still be carrying.
    pub(crate) fn retire_dns_expiry_lease(&self, sandbox_id: &str) -> Result<(), RuntimeError> {
        crate::validate_managed_instance_name(&crate::default_incus_instance_name(sandbox_id))?;
        // Tombstone the identity history BEFORE retiring anything, merged
        // over any earlier tombstone (history is monotone).
        let mut history = self.dns_identity_tombstone(sandbox_id)?;
        if let Ok(body) = std::fs::read_to_string(self.dns_state_path(sandbox_id))
            && let Ok(state) = serde_json::from_str::<SandboxDnsState>(&body)
            && state.sandbox_id == sandbox_id
        {
            for (name, generation) in state.generations {
                history
                    .generations
                    .entry(name)
                    .and_modify(|floor| *floor = (*floor).max(generation))
                    .or_insert(generation);
            }
        }
        // The global request floor: every identity source that dies with
        // the sandbox's records — the generation history, the durable
        // `next_request` counter, pending-mutation identities, and the
        // still-armed obligations' tags — folds into the tombstone so no
        // identity can recur in a later incarnation.
        history.request_floor = history
            .request_floor
            .max(history.generations.values().copied().max().unwrap_or(0))
            .max(
                self.read_dns_lease_obligations(sandbox_id)?
                    .iter()
                    .flat_map(|entry| [&entry.allow_tag, &entry.reject_tag])
                    .filter_map(|tag| super::network::dns_tag_request_id(tag))
                    .max()
                    .unwrap_or(0),
            )
            .max(
                self.read_dns_revocation_record_unscoped(sandbox_id)?
                    .iter()
                    .flat_map(|record| {
                        record
                            .pending
                            .iter()
                            .filter_map(|pending| {
                                super::network::dns_tag_request_id(&pending.description)
                            })
                            .chain(std::iter::once(record.next_request))
                            .collect::<Vec<_>>()
                    })
                    .max()
                    .unwrap_or(0),
            );
        // The lease fence-epoch high-water mark folds into the tombstone
        // too (C36 r23 F5): the counter FILE is preserved below, but a
        // record written by an older build may already have lost it — and
        // a deferred daemon-side removal names an exact epoch, so the
        // recreate's allocator must start above every epoch the old
        // incarnation ever issued.
        history.lease_fence_floor = history
            .lease_fence_floor
            .max(self.read_dns_lease_fence_counter(sandbox_id).unwrap_or(0));
        if !history.generations.is_empty()
            || history.request_floor > 0
            || history.lease_fence_floor > 0
        {
            let body = serde_json::to_string(&serde_json::json!({
                "sandbox_id": sandbox_id,
                "generations": history.generations,
                "request_floor": history.request_floor,
                "lease_fence_floor": history.lease_fence_floor,
            }))
            .map_err(|err| {
                internal_error(format!("cannot encode the DNS identity tombstone: {err}"))
            })?;
            self.write_durable_record(
                &self.dns_revocations_dir(),
                &format!("{sandbox_id}.lease-history"),
                &body,
            )?;
        }
        // Stop the watcher and unmap the owner: the watcher exits on
        // `alive = false`; nothing may settle for a torn-down sandbox.
        let key = (
            self.state_root(),
            self.project.clone(),
            sandbox_id.to_string(),
        );
        let owner = dns_lease_owners()
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .remove(&key);
        if let Some(owner) = owner {
            {
                let mut state = owner.state.lock().unwrap_or_else(|err| err.into_inner());
                state.alive = false;
                state.watcher_running = false;
                state.armed.clear();
                state.owed_evidence.clear();
            }
            owner.wake.notify_all();
        }
        // Retire ONLY the obligations (C36 r23 F5/F2): the fence-epoch
        // counter, the withdrawal evidence, and the unresolved-release
        // journal all SURVIVE teardown — a deferred daemon-side removal
        // of an old incarnation's fence names its exact epoch (the
        // counter must never restart at zero), and a standing fence
        // obligation of a recreated incarnation retires on the preserved
        // positive-withdrawal evidence for its exact identity. A removal
        // failure fails the teardown closed: a leftover obligations file
        // would otherwise break the recreate.
        let lease_record = self
            .dns_revocations_dir()
            .join(format!("{sandbox_id}.lease.json"));
        match std::fs::remove_file(&lease_record) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(internal_error(format!(
                    "cannot retire the DNS lease record {}: {err}",
                    lease_record.display()
                )));
            }
        }
        Self::fsync_dir(&self.dns_revocations_dir());
        Ok(())
    }

    /// The tombstoned identity history from torn-down incarnations
    /// (C36 r20 F4): per-name generation floors plus a global request
    /// floor (the durable `next_request` counter and any armed
    /// obligation identities die with the sandbox's other records, so
    /// the floor is what keeps a recreated sandbox's request identities
    /// unique against late daemon-side mutations of the old
    /// incarnation). Absent → empty; an undecodable or foreign
    /// tombstone FAILS CLOSED (identity uniqueness is at stake).
    fn dns_identity_tombstone(
        &self,
        sandbox_id: &str,
    ) -> Result<DnsIdentityTombstone, RuntimeError> {
        crate::validate_managed_instance_name(&crate::default_incus_instance_name(sandbox_id))?;
        let path = self
            .dns_revocations_dir()
            .join(format!("{sandbox_id}.lease-history"));
        let body = match std::fs::read_to_string(&path) {
            Ok(body) => body,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(DnsIdentityTombstone::default());
            }
            Err(err) => {
                return Err(internal_error(format!(
                    "cannot read the DNS identity tombstone: {err}"
                )));
            }
        };
        let parsed: serde_json::Value = serde_json::from_str(&body).map_err(|err| {
            internal_error(format!("cannot decode the DNS identity tombstone: {err}"))
        })?;
        if parsed.get("sandbox_id").and_then(|v| v.as_str()) != Some(sandbox_id) {
            return Err(internal_error(
                "the DNS identity tombstone belongs to a different sandbox",
            ));
        }
        let mut floors = BTreeMap::new();
        let Some(map) = parsed.get("generations").and_then(|v| v.as_object()) else {
            return Err(internal_error(
                "the DNS identity tombstone has no generation history",
            ));
        };
        for (name, generation) in map {
            let generation = generation.as_u64().ok_or_else(|| {
                internal_error("the DNS identity tombstone carries an invalid generation")
            })?;
            floors.insert(name.clone(), generation);
        }
        let request_floor = parsed
            .get("request_floor")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| internal_error("the DNS identity tombstone carries no request floor"))?;
        // Absent in pre-r23 tombstones: zero — the preserved counter file
        // is the primary high-water mark (C36 r23 F5).
        let lease_fence_floor = parsed
            .get("lease_fence_floor")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        Ok(DnsIdentityTombstone {
            generations: floors,
            request_floor,
            lease_fence_floor,
        })
    }

    /// Test-only observability (C36 r34 F4): the pre-fence cache size, so
    /// the bounded-cache regression can assert the prune keeps it at the
    /// armed ledger's size rather than lifetime traffic.
    #[cfg(test)]
    pub(crate) fn debug_prefenced_cache_len(&self, sandbox_id: &str) -> usize {
        let owner = self.dns_lease_owner(sandbox_id);
        owner
            .state
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .prefenced
            .len()
    }

    /// Advance a test clock under the waiter's condition lock, then wake
    /// it. This prevents a notification between its clock check and wait
    /// from being lost; no polling or repeated notifications are needed.
    #[cfg(test)]
    pub(crate) fn debug_advance_dns_lease_clock(&self, sandbox_id: &str, advance: impl FnOnce()) {
        let owner = self.dns_lease_owner(sandbox_id);
        let _state = owner.state.lock().unwrap_or_else(|err| err.into_inner());
        advance();
        owner.wake.notify_all();
    }

    /// Wake the existing lease loop after a test advances its DNS clock.
    /// Tests poll their ordering condition and notify again, so a wake
    /// racing the loop's wait cannot strand a logical-time assertion.
    #[cfg(test)]
    pub(crate) fn debug_wake_dns_lease_owner(&self, sandbox_id: &str) {
        self.dns_lease_owner(sandbox_id).wake.notify_all();
    }

    /// Test-only process-restart hook: drop the in-memory lease owner and
    /// stop its watcher. The PERSISTED obligations survive, exactly like a
    /// process exit (C36 r18 F6).
    #[cfg(test)]
    pub(crate) fn debug_reset_dns_lease_owner(&self, sandbox_id: &str) {
        let key = (
            self.state_root(),
            self.project.clone(),
            sandbox_id.to_string(),
        );
        let owner = dns_lease_owners()
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .remove(&key);
        if let Some(owner) = owner {
            {
                let mut state = owner.state.lock().unwrap_or_else(|err| err.into_inner());
                state.alive = false;
                state.watcher_running = false;
            }
            owner.wake.notify_all();
        }
    }

    /// Test-only (C36 r35 F1): install blind pre-fences for `dests`
    /// exactly as the watcher's pre-observation pass installs them
    /// (fresh epoch, the same tightly bounded rule add), then run the
    /// REAL settle with them as the caller-installed blind set. This is
    /// the deterministic shape of a blind pre-fence whose pair went
    /// quiet mid-settle — the production interleaving (a refresh's
    /// withdrawal evidence landing between the tick's due check and the
    /// settle's own recompute) is a sub-millisecond race no test can
    /// stage reliably. Everything past the install is the production
    /// path under the production owner lock.
    #[cfg(test)]
    pub(crate) fn debug_settle_dns_lease_with_blind_fences(
        &self,
        sandbox_id: &str,
        dests: &[&str],
    ) -> Result<(), RuntimeError> {
        let acl_name = sandbox_network_names(sandbox_id).1;
        let owner = self.dns_lease_owner(sandbox_id);
        let mut state = owner.state.lock().unwrap_or_else(|err| err.into_inner());
        let mut blind = Vec::new();
        for dest in dests {
            let epoch = self.allocate_lease_fence_epoch(sandbox_id)?;
            let addr = dest
                .strip_suffix("/32")
                .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
                .ok_or_else(|| internal_error("DNS fence destination is not an IPv4 /32"))?;
            let fence = super::network::domain_lease_fence_rule(addr, epoch);
            let mut args = vec![
                "network".to_string(),
                "acl".to_string(),
                "rule".to_string(),
                "add".to_string(),
                acl_name.clone(),
                "egress".to_string(),
            ];
            args.extend(fence.cli_args());
            let argv = args.iter().map(String::as_str).collect::<Vec<_>>();
            self.run_bounded(&argv, false, Duration::from_secs(5))?;
            blind.push(fence);
        }
        self.settle_due_dns_lease(sandbox_id, &acl_name, &mut state, &blind)
    }
}

/// Drop the named grants from the plan (retained grants and answers) and
/// record their denial with `reason`.
fn revoke_entries_by_name(plan: &mut RefreshPlan, names: &[String], reason: &str) {
    plan.state
        .grants
        .retain(|entry| !names.contains(&entry.name));
    plan.answers
        .retain(|(name, _)| !names.iter().any(|revoked| revoked == name));
    for name in names {
        plan.denied.push((name.clone(), reason.to_string()));
    }
}

/// Rule identity is the EFFECTIVE rule: description, action, state, and
/// every match constraint (protocol, source, ports, destination).
#[allow(clippy::type_complexity)]
type AclRuleId = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
);

/// `incus network acl rule remove` arguments matching a rule's identity:
/// description+destination pin the rule group; protocol/port and a
/// non-default action disambiguate the reject companions that share them.
fn acl_rule_removal_args(acl_name: &str, id: &AclRuleId) -> Vec<String> {
    let (description, action, _, protocol, _, _, destination_port, destination) = id;
    let mut args = vec![
        "network".to_string(),
        "acl".to_string(),
        "rule".to_string(),
        "remove".to_string(),
        acl_name.to_string(),
        "egress".to_string(),
        format!("description={description}"),
        format!("destination={destination}"),
    ];
    if !protocol.is_empty() {
        args.push(format!("protocol={protocol}"));
    }
    if !destination_port.is_empty() {
        args.push(format!("destination_port={destination_port}"));
    }
    if action != "allow" {
        args.push(format!("action={action}"));
    }
    args
}

/// A planned rule's canonical identity tuple (the `AclRuleId` shape the
/// withdrawal boundary and the readback compare against).
fn acl_rule_id_tuple(rule: &super::network::AclRule) -> AclRuleId {
    (
        rule.description.clone(),
        rule.action.as_str().to_string(),
        "enabled".to_string(),
        rule.protocol.clone().unwrap_or_default(),
        rule.source.clone().unwrap_or_default(),
        rule.source_port.clone().unwrap_or_default(),
        rule.destination_port.clone().unwrap_or_default(),
        rule.destination.clone().unwrap_or_default(),
    )
}

/// The observed-rule counterpart of a planned rule's identity.
fn observed_rule_id(rule: &super::acl::ObservedRule) -> AclRuleId {
    (
        rule.description.clone(),
        rule.action.clone(),
        rule.state.clone(),
        rule.protocol.clone(),
        rule.source.clone(),
        rule.source_port.clone(),
        rule.destination_port.clone(),
        rule.destination.clone(),
    )
}

/// The COMPLETE canonical identity of a destination-wide quarantine fence
/// (C36 r18 F8): enabled, egress, reject, the exact destination, and NO
/// protocol/source/port restriction. A fence-tagged rule that fails any
/// conjunct is NOT a fence — a narrowed rule silently under-protects the
/// destination, and a disabled one is pure drift — so it is never adopted
/// or trusted: the enforced boundary repairs (fresh fence) or refuses.
pub(crate) fn is_canonical_dns_fence(rule: &super::acl::ObservedRule, dest: &str) -> bool {
    super::network::is_dns_fence_tag(&rule.description)
        && rule.state == "enabled"
        && rule.action == "reject"
        && rule.protocol.is_empty()
        && rule.source.is_empty()
        && rule.source_port.is_empty()
        && rule.destination_port.is_empty()
        && rule.destination == dest
}

/// The rule-identity-tuple counterpart of `is_canonical_dns_fence`.
fn is_canonical_dns_fence_id(id: &AclRuleId, dest: &str) -> bool {
    super::network::is_dns_fence_tag(&id.0)
        && id.1 == "reject"
        && id.2 == "enabled"
        && id.3.is_empty()
        && id.4.is_empty()
        && id.5.is_empty()
        && id.6.is_empty()
        && id.7 == dest
}

/// How a single-rule withdrawal through the enforced boundary ended
/// (C36 r18 F3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WithdrawalProof {
    /// Clean exit after the rule was observed present: the daemon matched
    /// and removed it, so the request that installed it COMPLETED (a
    /// request completes at most once) and the rule is gone.
    PositivelyWithdrawn,
    /// The daemon positively reported the target ABSENT (the expiry lease
    /// or a concurrent reconcile withdrew it first): goal reached.
    ProvenAbsent,
    /// No proof either way: deadline kill, uncertain outcome, transport
    /// failure, or a refusal that is neither proven absence nor a
    /// duplicate-match refusal. The rule may still be installed.
    Unproven,
}

impl IncusClient {
    /// Marker read WITHOUT the policy-hash binding (C36 r18): the expiry
    /// lease and restart recovery must consult the pending-mutation journal
    /// no matter which policy generation last wrote it. Structural
    /// validation is unchanged and every failure mode stays fail-closed.
    fn read_dns_revocation_record_unscoped(
        &self,
        sandbox_id: &str,
    ) -> Result<Option<DnsRevocationRecord>, RuntimeError> {
        self.read_dns_revocation_record_checked(sandbox_id, None)
    }

    /// Whether a managed DNS refresh is OWED for this sandbox (C58 NEW-1,
    /// superseding the C36 r22/r23 readiness gate): the durable marker
    /// records an uncommitted refresh (`refresh_owed`), UNCOMMITTED
    /// revocations, or UNRESOLVED pending mutations. All three are the
    /// host's own journaled work ahead of a commit — the old ACL,
    /// publication and plan may still agree (a refresh that journaled a
    /// denial and died before mutating), or the live state may already be
    /// narrowed past the plan (a refresh that withdrew and then failed to
    /// publish or commit). Readiness never accepts either as Ready, but
    /// neither is drift: it is refused INCONCLUSIVE and the refresh
    /// scheduler retries the commit. Unreadable or malformed records are
    /// an `Err` (fail closed, inconclusive). Returns the evidence the
    /// owed-mode readback needs, or `None` when nothing is owed.
    pub(crate) fn dns_owed_evidence(
        &self,
        sandbox_id: &str,
    ) -> Result<Option<DnsOwedEvidence>, RuntimeError> {
        let Some(record) = self.read_dns_revocation_record_unscoped(sandbox_id)? else {
            return Ok(None);
        };
        if !record.refresh_owed && record.revoked.is_empty() && record.pending.is_empty() {
            return Ok(None);
        }
        // C58 G1-R3-2: an uncertain ALLOW whose request never lands has no
        // observable exit (absence is not proof, C36 r15), so its journal
        // entry is NOT by itself an owed commit: it keeps its preventive
        // fence in every plan and is reconciled by every refresh, but it
        // blocks readiness only while its identity is LIVE (the caller
        // decides after reading the ACL). See `commit_owed`.
        let reason = format!(
            "pending DNS revocations or an uncommitted DNS refresh must commit before the sandbox network can verify (refresh owed: revoked={:?}, pending={}, uncommitted={})",
            record.revoked,
            record.pending.len(),
            record.refresh_owed
        );
        self.owed_evidence_from(sandbox_id, Some(&record), reason)
            .map(Some)
    }

    /// The owed-mode evidence for an observation whose DNS expiry
    /// RECOVERY failed (C58 SEED-1): the settlement itself is owed — the
    /// blind pre-fence and the autonomous watcher keep enforcing — so the
    /// readback may still convict unexplained drift but never verify.
    /// Unreadable records are an `Err` (inconclusive).
    pub(crate) fn dns_settlement_owed_evidence(
        &self,
        sandbox_id: &str,
        recovery: &RuntimeError,
    ) -> Result<DnsOwedEvidence, RuntimeError> {
        let record = self.read_dns_revocation_record_unscoped(sandbox_id)?;
        let mut evidence = self.owed_evidence_from(
            sandbox_id,
            record.as_ref(),
            format!(
                "sandbox `{sandbox_id}` DNS expiry obligations are not verifiably settled: {recovery}"
            ),
        )?;
        // The settlement itself is owed: never downgraded by the ACL.
        evidence.commit_owed = true;
        Ok(evidence)
    }

    /// Is a COMMIT owed (readable marker only, C58 G1-R3-1/2): an
    /// uncommitted refresh, uncommitted revocations, or an unresolved fence
    /// release. Journaled uncertain allows alone are not — see
    /// `dns_owed_evidence`. Drives refresh scheduling (including for a
    /// stopped VM) and the create-retry guard.
    pub(crate) fn dns_commit_owed(&self, sandbox_id: &str) -> bool {
        matches!(
            self.read_dns_revocation_record_unscoped(sandbox_id),
            Ok(Some(record)) if record_commit_owed(&record)
        )
    }

    /// Cheap scheduler probe: is a refresh owed (readable marker only)?
    pub(crate) fn dns_refresh_owed(&self, sandbox_id: &str) -> bool {
        matches!(
            self.read_dns_revocation_record_unscoped(sandbox_id),
            Ok(Some(record))
                if record.refresh_owed || !record.revoked.is_empty() || !record.pending.is_empty()
        )
    }

    fn owed_evidence_from(
        &self,
        sandbox_id: &str,
        record: Option<&DnsRevocationRecord>,
        reason: String,
    ) -> Result<DnsOwedEvidence, RuntimeError> {
        let armed = self
            .read_dns_lease_obligations(sandbox_id)?
            .iter()
            .flat_map(|entry| {
                entry
                    .destinations
                    .iter()
                    .map(|dest| (entry.allow_tag.clone(), dest.clone()))
            })
            .collect();
        let denied = record
            .map(|record| {
                record
                    .revoked
                    .iter()
                    .map(|name| {
                        (
                            super::network::dns_tag_hex(name),
                            record.revoked_generations.get(name).cloned(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        let pending_allows: BTreeSet<(String, String)> = record
            .iter()
            .flat_map(|record| record.pending.iter())
            .filter(|pending| pending.kind == PendingKind::Allow)
            .map(|pending| (pending.description.clone(), pending.destination.clone()))
            .collect();
        Ok(DnsOwedEvidence {
            armed,
            denied,
            published_attempts: record
                .map(|record| record.published_attempts.iter().cloned().collect())
                .unwrap_or_default(),
            // A missing record here only happens on the recovery-failed
            // path, where the settlement itself is owed.
            commit_owed: record.is_none_or(record_commit_owed),
            pending_allows,
            reason,
        })
    }

    /// Clear the owed-refresh claims when the network they describe is
    /// torn down (C58 NEW-1): `refresh_owed`, the publication attempts
    /// and the uncommitted revocations all describe THIS incarnation's
    /// live objects and DNS state, which are gone (the DNS state and
    /// expiry ledger retire in the same teardown). The pending journal,
    /// standing fences and request counter are preserved untouched —
    /// they protect a future same-named ACL from deferred applies.
    pub(crate) fn retire_dns_refresh_owed(&self, sandbox_id: &str) -> Result<(), RuntimeError> {
        let Some(mut record) = self.read_dns_revocation_record_unscoped(sandbox_id)? else {
            return Ok(());
        };
        if !record.refresh_owed
            && record.published_attempts.is_empty()
            && record.revoked.is_empty()
            && record.revoked_generations.is_empty()
        {
            return Ok(());
        }
        record.refresh_owed = false;
        record.published_attempts.clear();
        record.revoked.clear();
        record.revoked_generations.clear();
        self.persist_dns_revocation_record(&record)
    }

    /// Withdraw ONE observed rule identity through the shared enforced
    /// withdrawal primitive (C36 r18 F2/F3): plain removal, a single
    /// `--force` retry on a positive duplicate-match refusal (the matches
    /// are still installed — never read as withdrawn), and proven-absence
    /// classification. Every other failure is UNPROVEN; only transport
    /// deadline/uncertainty errors downgrade to `Unproven`, anything else
    /// propagates.
    fn withdraw_rule_proven(
        &self,
        acl_name: &str,
        id: &AclRuleId,
        budget: Option<Duration>,
    ) -> Result<WithdrawalProof, RuntimeError> {
        #[cfg(test)]
        if let Some(budgets) = &self.dns_withdrawal_budgets {
            budgets
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .push((id.7.clone(), budget));
        }
        // The budget is ONE absolute deadline for the whole primitive
        // (C36 r22 F1): the plain removal and a duplicate-match `--force`
        // retry must never each spend the full remaining budget — their
        // combined duration would overrun the caller's round deadline.
        // The remainder is recomputed before EVERY subprocess attempt,
        // and an exhausted deadline is simply Unproven (the caller keeps
        // the destination fenced and retries next round).
        let deadline = budget.map(|budget| Instant::now() + budget);
        let run = |args: &[String],
                   force: bool|
         -> Result<Option<super::client::IncusCommandOutput>, RuntimeError> {
            let mut args = args.to_vec();
            if force {
                args.push("--force".to_string());
            }
            let attempt_started = Instant::now();
            let remaining =
                deadline.map(|deadline| deadline.saturating_duration_since(attempt_started));
            #[cfg(test)]
            if let Some(attempts) = &self.dns_withdrawal_attempts {
                attempts
                    .lock()
                    .unwrap_or_else(|err| err.into_inner())
                    .push((
                        id.0.clone(),
                        force,
                        remaining.map(|budget| attempt_started + budget),
                    ));
            }
            if remaining == Some(Duration::ZERO) {
                return Ok(None);
            }
            let result = match remaining {
                Some(remaining) => self.run_bounded(&args, false, remaining),
                None => self.run(&args.iter().map(String::as_str).collect::<Vec<_>>(), false),
            };
            match result {
                Ok(out) => Ok(Some(out)),
                Err(err)
                    if matches!(
                        err.code,
                        SandboxErrorCode::Timeout | SandboxErrorCode::UnknownOutcome
                    ) =>
                {
                    Ok(None)
                }
                Err(err) => Err(err),
            }
        };
        let args = acl_rule_removal_args(acl_name, id);
        for force in [false, true] {
            let Some(out) = run(&args, force)? else {
                return Ok(WithdrawalProof::Unproven);
            };
            if out.exit_code == 0 {
                return Ok(WithdrawalProof::PositivelyWithdrawn);
            }
            if cli_daemon_proven_absent(&out) {
                return Ok(WithdrawalProof::ProvenAbsent);
            }
            // A duplicate-match refusal means every match is STILL
            // INSTALLED: retry once with --force, never record a removal.
            if cli_daemon_needs_force(&out) && !force {
                continue;
            }
            return Ok(WithdrawalProof::Unproven);
        }
        Ok(WithdrawalProof::Unproven)
    }
}

/// The outcome of one enforced destination withdrawal (C36 r18 F2).
pub(crate) struct DestinationWithdrawal {
    /// Every targeted allow is proven absent.
    allows_gone: bool,
    /// (allow tag, destination) positively withdrawn THIS call —
    /// request-completion evidence for the pending-mutation journal.
    positive: Vec<(String, String)>,
    /// A canonical destination-wide fence was confirmed installed.
    fenced: bool,
    /// Companion removals that failed without proven absence (leftover
    /// deny-direction rules; the caller decides whether that fails the
    /// surrounding operation — the boundary already made the destination
    /// safe).
    companion_failures: Vec<AclRuleId>,
    /// The fence rule THIS call installed (None when a pre-existing
    /// canonical fence was adopted or none was needed): settlement
    /// bookkeeping derives the post-settlement plan from the recorded plan
    /// plus exactly these additions (C36 r19 F4).
    pub(crate) fence_added: Option<super::network::AclRule>,
    /// EVERY canonical lease-family fence observed on the destination at
    /// the end of the call (C36 r23 F4), reliable AND release-unresolved:
    /// Phase C retires the reliable one and RETRIES the unresolved
    /// removals (their deferred daemon-side completion can never strike
    /// a fence any later round relies on — those are adopted only when
    /// not in this set... and fresh identities are always allocated when
    /// one is).
    lease_fences_present: Vec<super::network::AclRule>,
    /// The canonical fence present on the destination at the end of the
    /// call — installed by this call OR adopted (C36 r20 F1): a clean
    /// expiry withdraws it again no matter which settle installed it,
    /// otherwise a fence adopted from an interrupted earlier attempt
    /// would linger forever. `pub(crate)` for the shim regression that
    /// distinguishes adoption from fresh issuance (C36 r28 F4).
    pub(crate) fence_present: Option<super::network::AclRule>,
}

impl IncusClient {
    /// THE enforced destination-withdrawal boundary (C36 r18 F1/F2/F3,
    /// C36 r19 F3) — the ONLY destination-level withdrawal: the expiry
    /// lease, restart recovery, the refresh pass's removal and
    /// lapsed-sweep phases, reconcile, and the failure-path cleanup all
    /// enter here:
    ///
    /// 1. FENCE TIMING: with `fence_first` (the expiry lease settling the
    ///    FINAL live authorization around an unresolved mutation) a
    ///    canonical destination-wide fence is restored or confirmed, and
    ///    PROVEN by re-observation, BEFORE the first withdrawal; if it
    ///    cannot be confirmed, nothing is withdrawn. Without
    ///    `fence_first` (refresh/reconcile: the destination is still
    ///    protected by the marker fencing readiness, and the rule itself
    ///    is present) the fence is installed — and readback-proven — only
    ///    when a withdrawal proves UNPROVABLE, before the error returns:
    ///    an unwithdrawable allow never leaves its destination reachable,
    ///    and a clean withdrawal never leaves a fence behind.
    /// 2. Every targeted allow is withdrawn and proven absent (clean exit
    ///    re-observed, or a proven-absence daemon reply; duplicate matches
    ///    get a `--force` retry). An allow that will not withdraw installs
    ///    or confirms the fence (when `require_fence`, or fail-closed when
    ///    the marker is unreadable) and FAILS — companions are never
    ///    touched while an overlapping allow might still be installed.
    /// 3. Only then are the reject companions removed.
    ///
    /// `require_fence` gates the fence-FIRST step (the lease settling the
    /// final authorization around an unresolved mutation). `covered` is
    /// the caller's effective-authorization verdict for the unproven
    /// case: the destination still has a surviving grant or covering
    /// static CIDR. An unwithdrawable allow is fenced unless `covered`
    /// (a covered destination is not blocked; fail-closed when the
    /// marker is unreadable). Fences come from `fence_alloc`, so each
    /// caller stays in its own counter domain: the lease passes the
    /// LEASE-fence family (its caller holds the lease owner lock, the
    /// sole writer of that counter), the refresh pass and reconcile pass
    /// the marker-counter fence family (the lease never enters the
    /// refresh's marker read-modify-write).
    /// `deadline` bounds EVERY blocking operation in the boundary — fence
    /// installation, ACL readbacks, companion removals — not just the
    /// allow withdrawal (C36 r21 F2): the lease settlement passes the next
    /// live expiry so a stalled cleanup step can never delay a later
    /// deadline while the sole watcher holds the owner lock.
    ///
    /// Every operation runs on a PERMIT-INDEPENDENT client (C36 r21 F3):
    /// deny enforcement outlives the issuing request — a revoked refresh
    /// permit (relay disconnect, lease expiry) must never veto a fallback
    /// fence for a grant whose withdrawal just proved unprovable.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn enforce_destination_withdrawal(
        &self,
        sandbox_id: &str,
        acl_name: &str,
        dest: &str,
        allow_tags: &[String],
        companion_tags: &[String],
        require_fence: bool,
        covered: bool,
        budget: Option<Duration>,
        deadline: Option<Instant>,
        fence_first: bool,
        fence_alloc: &mut dyn FnMut(&str) -> Result<super::network::AclRule, RuntimeError>,
    ) -> Result<DestinationWithdrawal, RuntimeError> {
        // The enforcement client carries no cancellation permit (C36 r21
        // F3); per-operation budgets come from the caller's deadline
        // (C36 r21 F2).
        let mut enforcement = self.clone();
        enforcement.cancelled = None;
        let remaining = move || deadline.map(|d| d.saturating_duration_since(Instant::now()));
        let capped = move |budget: Option<Duration>| -> Option<Duration> {
            match (budget, remaining()) {
                (Some(budget), Some(remaining)) => Some(budget.min(remaining)),
                (Some(budget), None) => Some(budget),
                (None, remaining) => remaining,
            }
        };
        let read_acl = || -> Result<super::acl::ObservedAcl, RuntimeError> {
            let observed = enforcement
                .read_sandbox_acl_within(acl_name, capped(None))?
                .ok_or_else(|| error(SandboxErrorCode::SandboxNotFound, "sandbox ACL is absent"))?;
            // Ownership gate at the mutation boundary (C36 r32 F2, the
            // shared gate since r34 F2): the sandbox tag AND the project
            // tag must both match — an inherited or same-named foreign
            // ACL is never mutated by this boundary (the lease/recovery
            // paths reach here without the refresh apply path's own
            // ownership checks).
            enforcement.require_owned_dns_acl(&observed, sandbox_id, acl_name)?;
            Ok(observed)
        };
        // The pending-release set comes from the revocation marker. An
        // UNREADABLE marker must not stall the withdrawal (an expired
        // authorization would linger unfenced): degrade fail-closed —
        // every destination is treated as needing a fence, and NO
        // refresh-family fence is adoptable (C36 r28 F4): the
        // release-pending set is then UNKNOWN, so any observed refresh
        // fence could be one whose deferred removal is still in flight —
        // adopting it could leave the destination fenceless the moment
        // that removal lands while an expired allow is still effective.
        // A fresh lease-family fence is installed instead; LEASE fences
        // stay adoptable on their own journal's say-so below (their
        // deferred removals are journaled lease-side, so an unreadable
        // REFRESH journal says nothing about them — refusing them would
        // livelock the fail-closed withdrawal into re-installing a fresh
        // fence every round and never withdrawing).
        let (pending_releases, marker_ok): (BTreeSet<String>, bool) =
            match self.read_dns_revocation_record_unscoped(sandbox_id) {
                Ok(record) => (
                    record
                        .iter()
                        .flat_map(|record| record.pending.iter())
                        .filter(|pending| pending.kind == PendingKind::FenceRelease)
                        .map(|pending| pending.description.clone())
                        .collect(),
                    true,
                ),
                Err(_) => (BTreeSet::new(), false),
            };
        // The LEASE's own unresolved-release journal gates adoption the
        // same way (C36 r23 F4): a lease fence whose removal was issued
        // but never proven may still be deleted daemon-side at any
        // moment, so no later round may RELY on that exact fence — a
        // fresh epoch is issued instead. The marker's pending releases
        // exclude refresh-family fences; this excludes lease-family ones.
        // An UNREADABLE journal (C36 r25 F4) means the release-uncertain
        // set is UNKNOWN: NO observed fence is adoptable — a fresh epoch
        // is issued instead of relying on a possibly-uncertain identity.
        let lease_releases: Option<BTreeSet<String>> =
            self.read_dns_lease_releases(sandbox_id).ok();
        let canonical_fence_present = |observed: &super::acl::ObservedAcl| {
            observed.egress.iter().any(|rule| {
                is_canonical_dns_fence(rule, dest)
                    && (marker_ok || super::network::is_dns_lease_fence_tag(&rule.description))
                    && !pending_releases.contains(&rule.description)
                    && lease_releases
                        .as_ref()
                        .is_some_and(|releases| !releases.contains(&rule.description))
            })
        };
        let require_fence = require_fence || !marker_ok;
        let mut outcome = DestinationWithdrawal {
            allows_gone: false,
            positive: Vec::new(),
            fenced: false,
            companion_failures: Vec::new(),
            fence_added: None,
            lease_fences_present: Vec::new(),
            fence_present: None,
        };
        let mut install_fence = |outcome: &mut DestinationWithdrawal| -> Result<(), RuntimeError> {
            let fence = fence_alloc(dest)?;
            let mut args = vec![
                "network".to_string(),
                "acl".to_string(),
                "rule".to_string(),
                "add".to_string(),
                acl_name.to_string(),
                "egress".to_string(),
            ];
            args.extend(fence.cli_args());
            let argv = args.iter().map(String::as_str).collect::<Vec<_>>();
            // Permit-independent and deadline-bounded (C36 r21 F2/F3).
            let out = match capped(None) {
                Some(remaining) => enforcement.run_bounded(&argv, false, remaining)?,
                None => enforcement.run(&argv, false)?,
            };
            if out.exit_code != 0 {
                return Err(host_cli_error("network acl rule add", &out));
            }
            outcome.fence_added = Some(fence);
            Ok(())
        };
        let mut observed = read_acl()?;
        // Step 1: fence BEFORE withdrawing the final authorization (lease
        // settlement ordering; refresh/reconcile fence on unproven below).
        if fence_first && require_fence && !canonical_fence_present(&observed) {
            install_fence(&mut outcome)?;
            observed = read_acl()?;
            if !canonical_fence_present(&observed) {
                return Err(internal_error(
                    "a restored DNS fence did not read back; refusing to withdraw the final authorization",
                ));
            }
            outcome.fenced = true;
        }
        // Step 2: withdraw and PROVE the allows absent.
        let mut unproven = false;
        for _ in 0..3 {
            let targets: Vec<AclRuleId> = observed
                .egress
                .iter()
                .filter(|rule| {
                    rule.action == "allow"
                        && rule.destination == dest
                        && allow_tags.contains(&rule.description)
                })
                .map(observed_rule_id)
                .collect();
            if targets.is_empty() {
                outcome.allows_gone = true;
                break;
            }
            for id in &targets {
                match enforcement.withdraw_rule_proven(acl_name, id, capped(budget))? {
                    WithdrawalProof::PositivelyWithdrawn => {
                        // Request-completion evidence is DURABLE THE
                        // MOMENT the proof exists (C36 r23 F8): any later
                        // fallible step of this boundary — the
                        // re-observation read below, the caller's commit —
                        // can discard the in-memory proof, and a crash
                        // before the caller's scheduled evidence flush
                        // would lose it outright. On retry the rule is
                        // already absent, so no new proof could ever be
                        // produced: this append is what lets the journaled
                        // entry for the identity retire. A failed append
                        // degrades to the caller's own owed-evidence
                        // mechanism (the settle's durable retry loop); a
                        // caller without one simply keeps the journal
                        // entry pending — fail closed, never lost-while-
                        // reported-success.
                        let _ = enforcement.record_withdrawal_evidence(sandbox_id, &id.0, dest);
                        outcome.positive.push((id.0.clone(), dest.to_string()));
                    }
                    WithdrawalProof::ProvenAbsent => {}
                    WithdrawalProof::Unproven => {
                        unproven = true;
                        break;
                    }
                }
            }
            if unproven {
                break;
            }
            observed = read_acl()?;
        }
        if !outcome.allows_gone {
            // An unwithdrawable allow whose authorization is being
            // withdrawn must not stay reachable: confirm (or restore) the
            // fence, then fail — companions stay. A destination with a
            // SURVIVING authorization (another live grant or a covering
            // static CIDR) is not fenced: it stays allowed regardless.
            // Fail-closed: an unreadable marker fences regardless.
            if (!covered || !marker_ok) && !canonical_fence_present(&observed) {
                install_fence(&mut outcome)?;
                observed = read_acl()?;
                if !canonical_fence_present(&observed) {
                    return Err(internal_error(
                        "a DNS fence for an unwithdrawable allow did not read back",
                    ));
                }
            }
            return Err(internal_error(
                "a DNS grant's allow would not withdraw; the destination stays fenced",
            ));
        }
        // Step 3: companions — deny-direction leftovers never expose, so a
        // failed companion removal is reported, not fatal.
        let latest = read_acl()?;
        outcome.fenced = outcome.fenced || canonical_fence_present(&latest);
        outcome.fence_present = latest
            .egress
            .iter()
            .find(|rule| {
                is_canonical_dns_fence(rule, dest)
                    && (marker_ok || super::network::is_dns_lease_fence_tag(&rule.description))
                    && !pending_releases.contains(&rule.description)
                    && lease_releases
                        .as_ref()
                        .is_some_and(|releases| !releases.contains(&rule.description))
            })
            .map(|rule| rule.as_acl_rule(super::network::AclDirection::Egress))
            .transpose()?;
        outcome.lease_fences_present = latest
            .egress
            .iter()
            .filter(|rule| {
                is_canonical_dns_fence(rule, dest)
                    && super::network::is_dns_lease_fence_tag(&rule.description)
            })
            .map(|rule| rule.as_acl_rule(super::network::AclDirection::Egress))
            .collect::<Result<Vec<_>, _>>()?;
        let companions: Vec<AclRuleId> = latest
            .egress
            .iter()
            .filter(|rule| {
                rule.action != "allow"
                    && rule.destination == dest
                    && companion_tags.contains(&rule.description)
            })
            .map(observed_rule_id)
            .collect();
        for id in &companions {
            match enforcement.withdraw_rule_proven(acl_name, id, capped(None))? {
                WithdrawalProof::PositivelyWithdrawn | WithdrawalProof::ProvenAbsent => {}
                WithdrawalProof::Unproven => outcome.companion_failures.push(id.clone()),
            }
        }
        Ok(outcome)
    }

    /// Allocate one fence epoch from the LEASE-scoped durable counter.
    /// The caller holds the lease owner lock (sole writer), which is what
    /// makes the increment crash-safe; the tag family keeps the namespace
    /// disjoint from the refresh's marker-counter epochs (C36 r18 F1).
    /// The durable lease fence counter's current value (0 when absent):
    /// the high-water mark of lease-allocated fence epochs.
    fn read_dns_lease_fence_counter(&self, sandbox_id: &str) -> Result<u64, RuntimeError> {
        crate::validate_managed_instance_name(&crate::default_incus_instance_name(sandbox_id))?;
        let path = self
            .dns_revocations_dir()
            .join(format!("{sandbox_id}.lease-counter"));
        match std::fs::read_to_string(&path) {
            Ok(body) => body.trim().parse::<u64>().map_err(|err| {
                internal_error(format!("cannot decode the DNS lease fence counter: {err}"))
            }),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(err) => Err(internal_error(format!(
                "cannot read the DNS lease fence counter: {err}"
            ))),
        }
    }

    /// Path of the LEASE's own fence-release journal (C36 r23 F4): fence
    /// descriptions whose removal the lease issued but could not prove
    /// (timeout/uncertainty — the daemon may complete the removal at any
    /// time). The lease never writes the refresh's marker (sole-writer
    /// read-modify-write), so its release intents live here; every fence
    /// ADOPTION site excludes these identities, because a fence whose
    /// removal is still in flight is not protection anyone may rely on.
    fn dns_lease_releases_path(&self, sandbox_id: &str) -> PathBuf {
        self.dns_revocations_dir()
            .join(format!("{sandbox_id}.lease-releases"))
    }

    /// Fence identities with an UNRESOLVED lease-side removal. Fail
    /// CLOSED (C36 r25 F4): a MISSING journal is an empty set, but an
    /// unreadable or invalid-UTF-8 journal is an ERROR — the set of
    /// release-uncertain fences is then unknown, and every adoption gate
    /// treats unknown as "nothing is adoptable" instead of silently
    /// degrading to "everything is adoptable" (which would let a
    /// release-uncertain fence stand in as the deadline fence).
    fn read_dns_lease_releases(&self, sandbox_id: &str) -> Result<BTreeSet<String>, RuntimeError> {
        let body = match std::fs::read_to_string(self.dns_lease_releases_path(sandbox_id)) {
            Ok(body) => body,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(BTreeSet::new());
            }
            Err(err) => {
                return Err(internal_error(format!(
                    "lease release journal for {sandbox_id} is unreadable: {err}"
                )));
            }
        };
        Ok(body
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect())
    }

    /// Persist the unresolved-release set atomically (fsync file AND
    /// directory via the durable-record writer). Sole writer: the lease
    /// owner, under the owner lock.
    fn persist_dns_lease_releases(
        &self,
        sandbox_id: &str,
        releases: &BTreeSet<String>,
    ) -> Result<(), RuntimeError> {
        crate::validate_managed_instance_name(&crate::default_incus_instance_name(sandbox_id))?;
        let mut body = String::new();
        for description in releases {
            body.push_str(description);
            body.push('\n');
        }
        if releases.is_empty() {
            // An empty journal is indistinguishable from an absent one;
            // remove the file so teardown/recreate bookkeeping stays
            // exact.
            match std::fs::remove_file(self.dns_lease_releases_path(sandbox_id)) {
                Ok(()) => {
                    Self::fsync_dir(&self.dns_revocations_dir());
                    return Ok(());
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(err) => {
                    return Err(internal_error(format!(
                        "cannot clear the DNS lease release journal: {err}"
                    )));
                }
            }
        }
        self.write_durable_record(
            &self.dns_revocations_dir(),
            &format!("{sandbox_id}.lease-releases"),
            &body,
        )
    }

    pub(crate) fn allocate_lease_fence_epoch(&self, sandbox_id: &str) -> Result<u64, RuntimeError> {
        crate::validate_managed_instance_name(&crate::default_incus_instance_name(sandbox_id))?;
        let name = format!("{sandbox_id}.lease-counter");
        let path = self.dns_revocations_dir().join(&name);
        let current = match std::fs::read_to_string(&path) {
            Ok(body) => body.trim().parse::<u64>().map_err(|err| {
                internal_error(format!("cannot decode the DNS lease fence counter: {err}"))
            })?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => 0,
            Err(err) => {
                return Err(internal_error(format!(
                    "cannot read the DNS lease fence counter: {err}"
                )));
            }
        };
        // Floor at the tombstoned high-water mark (C36 r23 F5): epochs
        // are unique across ACL incarnations even if the counter file was
        // lost by a pre-r23 teardown, so a deferred daemon-side removal
        // of an old incarnation's fence can never match a fence of the
        // new one.
        let current = current.max(self.dns_identity_tombstone(sandbox_id)?.lease_fence_floor);
        let next = current
            .checked_add(1)
            .ok_or_else(|| internal_error("the DNS lease fence counter overflowed"))?;
        self.write_durable_record(&self.dns_revocations_dir(), &name, &next.to_string())?;
        Ok(next)
    }
}

/// Is this grant lapsed at `now_unix`? Absolute lapse revokes ANY grant;
/// the safe-publication-window lapse (churn floor) applies only to grants
/// that ever had a window beyond the floor — floor-clamped short TTLs
/// remain installable until their absolute expiry (C36 r14).
fn grant_lapsed(entry: &DnsGrantEntry, now_unix: u64) -> bool {
    entry.expires_at <= now_unix
        || (entry.ttl > MIN_REFRESH_TTL_SECS
            && entry.expires_at < now_unix + u64::from(MIN_REFRESH_TTL_SECS))
}

/// Revoke entries lapsed at `now_unix` (absolute expiry, or the safe
/// publication window for grants that ever had one): drop them from the
/// retained grants and answers, deny them, and report whether anything
/// was revoked (the caller extends the marker BEFORE removing the rules).
fn revoke_lapsed_entries(plan: &mut RefreshPlan, now_unix: u64) -> bool {
    let lapsed: Vec<String> = plan
        .state
        .grants
        .iter()
        .filter(|entry| grant_lapsed(entry, now_unix))
        .map(|entry| entry.name.clone())
        .collect();
    if lapsed.is_empty() {
        return false;
    }
    revoke_entries_by_name(
        plan,
        &lapsed,
        "grant expired during enforcement; revoked before publication",
    );
    true
}

/// Rule tag (allow AND reject companion) → (domain, answer-time expiry),
/// for the per-addition lifetime gate in replace_dns_acl_rules.
fn grant_expiries(grants: &[DnsGrantEntry]) -> BTreeMap<String, (String, u64, u64)> {
    let mut map = BTreeMap::new();
    for entry in grants {
        let tag = super::network::dns_rule_tag(&entry.name, entry.generation);
        map.insert(
            tag,
            (entry.name.clone(), entry.expires_at, entry.generation),
        );
        let tag = super::network::dns_rule_reject_tag(&entry.name, entry.generation);
        map.insert(
            tag,
            (entry.name.clone(), entry.expires_at, entry.generation),
        );
    }
    map
}

/// The CLI output carries a transport-failure signature: the request may
/// never have reached the daemon, or the reply was lost after acceptance.
fn cli_transport_failure(text: &str) -> bool {
    const TRANSPORT_MARKERS: [&str; 7] = [
        "connection",
        "dial ",
        "EOF",
        "timeout",
        "no such host",
        "tls",
        "TLS",
    ];
    TRANSPORT_MARKERS.iter().any(|marker| text.contains(marker))
}

/// Positive evidence that the daemon REFUSED a mutation (C36 r16 F4): the
/// CLI printed a daemon-side `Error:` diagnostic with no transport-failure
/// signature. A connection failure after the request was accepted — or an
/// externally signalled CLI — also exits nonzero; that outcome is
/// UNCERTAIN, never definitive cancellation.
fn cli_daemon_rejected(out: &super::client::IncusCommandOutput) -> bool {
    let text = format!(
        "{}
{}",
        out.stdout, out.stderr
    );
    if !text.contains("Error:") {
        return false;
    }
    !cli_transport_failure(&text)
}

/// Positive evidence a REMOVAL found nothing: the daemon's explicit
/// no-match reply with no transport-failure signature (C36 r18 F3). ONLY
/// this classifies a nonzero removal as goal-reached — any other rejection
/// (a duplicate-match refusal, a policy error) leaves the rule INSTALLED
/// and must never be read as a successful withdrawal.
fn cli_daemon_proven_absent(out: &super::client::IncusCommandOutput) -> bool {
    let text = format!(
        "{}
{}",
        out.stdout, out.stderr
    );
    text.contains("No matching rule(s) found") && !cli_transport_failure(&text)
}

/// Positive evidence the removal matched MORE THAN ONE rule and the daemon
/// refused without `--force`: every match is STILL INSTALLED. The correct
/// continuation is a `--force` retry, never "treat as withdrawn".
fn cli_daemon_needs_force(out: &super::client::IncusCommandOutput) -> bool {
    let text = format!(
        "{}
{}",
        out.stdout, out.stderr
    );
    text.contains("More than one matching rule") && !cli_transport_failure(&text)
}

/// Refresh delay for the surviving grants measured at `now_unix`: the
/// shortest remaining lifetime, clamped to the refresh TTL bounds.
fn completion_refresh_after(grants: &[DnsGrantEntry], now_unix: u64) -> u32 {
    // The delay is capped by the grant's REMAINING lifetime (C36 r15
    // finding 4): a floor-clamped TTL-30 grant that spent 10s on resolution
    // and enforcement has ~20s left — returning the 30s churn floor would
    // leave the old address allowed past expiry for a caller honoring the
    // delay. The floor applies only to the EMPTY set (scheduling default);
    // with grants, any remaining lifetime below the floor is returned as-is
    // (the ACL is the enforcement; a 0s-capable grant is already revoked by
    // the surrounding rechecks).
    let Some(min_remaining) = grants
        .iter()
        .map(|entry| entry.expires_at.saturating_sub(now_unix))
        .min()
    else {
        return MIN_REFRESH_TTL_SECS;
    };
    min_remaining.clamp(1, u64::from(MAX_REFRESH_TTL_SECS)) as u32
}

/// Publish the create-time answers captured during plan compilation.
/// `getaddrinfo` carries no TTL, so the initial publish uses the upper clamp;
/// the production refresh scheduler (`dns_refresh`) re-resolves through the
/// same system resolver at half-life and renews it. On the immutable
/// reconnect path (`resolved_domains` empty) the previously published state
/// persists and readback verification already proved it — nothing to redo.
pub(crate) fn publish_initial_answers(
    client: &IncusClient,
    plan: &SandboxNetworkPlan,
) -> Result<(), RuntimeError> {
    // Preserved obligations are enforced at THIS boundary whether or not
    // any DNS answer needs publication (C36 r36 F1): a standing fence
    // obligation (or an unresolved pending allow) survives the teardown
    // of a prior same-named incarnation — the ACL and expiry ledger are
    // gone, but the deferred daemon-side apply can still land on THIS
    // ACL at any time. A domain-free recreation that skipped enforcement
    // would let that late allow land EFFECTIVE against a policy that
    // denies the destination, with no expiry watcher armed to withdraw
    // it — and readiness would still pass, because a marker reduced to
    // standing-only obligations no longer gates it. The read is
    // unscoped: the obligation predates this policy generation. An
    // unreadable marker fails the create closed, exactly like the
    // readiness readback.
    let obligations_pending = client
        .read_dns_revocation_record_unscoped(&plan.sandbox_id)?
        .is_some_and(|record| !record.pending.is_empty() || !record.standing_fences.is_empty());
    if plan.policy_domains.is_empty() {
        if !obligations_pending {
            return Ok(());
        }
        // Domain-free recreation WITH preserved obligations: fall
        // through to the shared enforce-and-commit boundary with an
        // empty grant set — the standing/pending fences are planned,
        // installed, and committed into the recorded plan (which the
        // final verification overlays and readback-verifies), while the
        // static CIDR policy still suppresses any fence it authorizes.
        // A clean domain-free creation (no marker) keeps the cheap
        // return above.
    } else if plan.resolved_domains.is_empty() {
        return Ok(());
    }
    let hash = plan.policy_hash.clone().ok_or_else(|| {
        internal_error("a fresh egress plan has no recorded policy hash to publish under")
    })?;
    // `getaddrinfo` carries no TTL, so the initial grants use the upper
    // clamp, renewed by the scheduled refresh (`dns_refresh`). The
    // create-time resolutions become refresh-equivalent grants...
    let now_unix = client.dns_clock.unix_now()?;
    let policy = EgressPolicy {
        mode: sandbox_protocol::EgressMode::Allowlist,
        domains: plan.policy_domains.clone(),
        cidrs: plan.policy_cidrs.clone(),
    };
    let mut outcomes: Vec<Result<DomainGrant, ResolveDeny>> = Vec::new();
    for domain in &policy.domains {
        // M19: a grant the compile denied has no resolution and is denied
        // here exactly like an empty answer — never published.
        if plan
            .settings
            .as_ref()
            .is_some_and(|settings| crate::egress::domain_denied(domain, settings))
        {
            outcomes.push(Err(ResolveDeny::blocked(domain)));
            continue;
        }
        let Some(resolved) = plan
            .resolved_domains
            .iter()
            .find(|resolved| &resolved.name == domain)
        else {
            return Err(internal_error(
                "the compiled plan is missing a policy domain's resolution",
            ));
        };
        outcomes.push(Ok(DomainGrant {
            name: domain.clone(),
            addresses: resolved.addresses.clone(),
            ttl: MAX_REFRESH_TTL_SECS,
            expires_at: now_unix + u64::from(MAX_REFRESH_TTL_SECS),
        }));
    }
    // ...and issuance goes through THE SAME journaled, fenced,
    // tombstone-aware mutation boundary as a refresh (C36 r21 F4): the
    // base network and its static rules are already applied, so an
    // interrupted initial allow leaves a journaled pending mutation and
    // a tombstoned identity — never an unaccounted broadening request a
    // retry (potentially resolving a different address) could meet
    // unprotected. The boundary publishes the answers, persists the DNS
    // state, updates the recorded plan rules, and arms the expiry lease.
    let refresh_plan = plan_refresh(&plan.sandbox_id, &policy, &hash, None, outcomes, now_unix)?;
    let recorded_rules = client.persisted_plan_rules(&plan.sandbox_id, &hash);
    client.enforce_and_commit_refresh_plan(
        &plan.sandbox_id,
        &hash,
        &policy,
        refresh_plan,
        None,
        recorded_rules,
        now_unix,
        // The initial publication creates the ACL's current incarnation
        // (C36 r22 F2): unresolved allow mutations against a prior
        // same-named incarnation convert to standing fence obligations
        // instead of blocking readiness forever.
        true,
    )?;
    Ok(())
}

/// What one refresh established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRefreshOutcome {
    /// Allowlisted names with published answers.
    pub published_names: usize,
    /// Allowlisted names currently denied (failed, empty or rebound).
    pub denied_names: Vec<String>,
    /// When the next refresh is due, capped by the shortest remaining
    /// grant lifetime; an empty grant set uses the 30s scheduling floor.
    pub refresh_after: Duration,
}

// ---------------------------------------------------------------------------
// Fake transport for runtime/node-daemon tests: scripted per-name outcomes,
// default NXDOMAIN (fail closed), every query recorded.
// ---------------------------------------------------------------------------

/// One scripted answer record for `FakeDnsTransport`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakeDnsRecord {
    A(Ipv4Addr, u32),
    Aaaa(Ipv6Addr, u32),
    Cname(String, u32),
    /// Address record attributed to a name OTHER than the queried one — an
    /// inline chain record, e.g. the CNAME target answered in the same
    /// message (real resolvers do this).
    AFor(String, Ipv4Addr, u32),
    /// IPv6 counterpart of `AFor`.
    AaaaFor(String, Ipv6Addr, u32),
    /// CNAME record OWNED by a name other than the queried one: a later
    /// inline chain hop (b→c inside the answer for a).
    CnameFor(String, String, u32),
}

/// A scripted outcome for one query for a scripted name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakeDnsOutcome {
    /// NOERROR answer with these records (owner = the queried name).
    Answer(Vec<FakeDnsRecord>),
    /// Non-NOERROR response code (3 = NXDOMAIN).
    Rcode(u8),
    /// Transport failure (timeout/refused): the refresh treats it as
    /// transient and falls through to the next server.
    TransportError,
    /// Answer only after `secs` of wall-clock delay: proves expiries are
    /// anchored at ANSWER time, not at planning time after every lookup.
    Delayed(u64, Box<FakeDnsOutcome>),
}

/// Scriptable in-memory DNS transport. Unscripted names answer NXDOMAIN, so
/// tests must enumerate everything a resolution may ask for — an unexpected
/// query can never produce an answer.
pub struct FakeDnsTransport {
    inner: std::sync::Mutex<FakeDnsInner>,
}

#[derive(Default)]
struct FakeDnsInner {
    scripts: std::collections::HashMap<String, std::collections::VecDeque<FakeDnsOutcome>>,
    queries: Vec<(Ipv4Addr, String, u16)>,
    /// Consumed per query before answering; lets tests fail specific calls.
    barrier: Option<std::sync::Arc<std::sync::Barrier>>,
}

impl FakeDnsTransport {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(FakeDnsInner::default()),
        }
    }

    /// Replace the scripted outcome queue for one exact name (lowercase).
    pub fn script(&self, name: &str, outcomes: impl IntoIterator<Item = FakeDnsOutcome>) {
        self.inner
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .scripts
            .insert(name.to_ascii_lowercase(), outcomes.into_iter().collect());
    }

    /// A barrier every query waits on first: two refreshes holding a clone of
    /// this transport provably interleave inside the resolution phase.
    pub fn set_barrier(&self, barrier: std::sync::Arc<std::sync::Barrier>) {
        self.inner
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .barrier = Some(barrier);
    }

    /// Every query issued, as (server, qname, qtype).
    pub fn queries(&self) -> Vec<(Ipv4Addr, String, u16)> {
        self.inner
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .queries
            .clone()
    }
}

impl Default for FakeDnsTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsTransport for FakeDnsTransport {
    fn query(&self, server: Ipv4Addr, message: &[u8]) -> std::io::Result<Vec<u8>> {
        let (_, qname, qtype) = parse_question(message)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string()))?;
        let (outcome, barrier) = {
            let mut inner = self.inner.lock().unwrap_or_else(|err| err.into_inner());
            inner.queries.push((server, qname.clone(), qtype));
            let outcome = inner
                .scripts
                .get_mut(&qname)
                .and_then(std::collections::VecDeque::pop_front)
                .unwrap_or(FakeDnsOutcome::Rcode(3));
            (outcome, inner.barrier.clone())
        };
        if let Some(barrier) = barrier {
            barrier.wait();
        }
        fn respond(message: &[u8], outcome: FakeDnsOutcome) -> std::io::Result<Vec<u8>> {
            match outcome {
                FakeDnsOutcome::TransportError => Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "fake transport timed out",
                )),
                FakeDnsOutcome::Rcode(rcode) => encode_response(message, rcode, &[]),
                FakeDnsOutcome::Answer(records) => encode_response(message, 0, &records),
                FakeDnsOutcome::Delayed(secs, then) => {
                    std::thread::sleep(std::time::Duration::from_secs(secs));
                    respond(message, *then)
                }
            }
        }
        respond(message, outcome)
    }
}

/// Extract (id, qname, qtype) from a query built by `build_query`.
fn parse_question(message: &[u8]) -> Result<(u16, String, u16), RuntimeError> {
    if message.len() < 13 {
        return Err(protocol_error("DNS query is too short"));
    }
    let id = u16::from_be_bytes([message[0], message[1]]);
    let (name, after) = decode_name(message, 12)?;
    if after + 4 > message.len() {
        return Err(protocol_error("DNS question is truncated"));
    }
    let qtype = u16::from_be_bytes([message[after], message[after + 1]]);
    Ok((id, name, qtype))
}

/// Build a response echoing the query's id/question. Owners are the queried
/// name (compression pointer to the question); CNAME targets are encoded
/// literally.
fn encode_response(query: &[u8], rcode: u8, records: &[FakeDnsRecord]) -> std::io::Result<Vec<u8>> {
    let invalid = || std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid DNS query");
    let (_, qname, qtype) = parse_question(query).map_err(|_| invalid())?;
    let mut out = Vec::with_capacity(query.len() + 64 * records.len());
    out.extend_from_slice(&query[0..2]); // id
    let flags: u16 = 0x8180 | u16::from(rcode); // QR|RD|RA + rcode
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&(records.len() as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    // Echo the question.
    let (_, after) = decode_name(query, 12).map_err(|_| invalid())?;
    out.extend_from_slice(&query[12..after + 4]);
    let encode_name = |out: &mut Vec<u8>, name: &str| -> std::io::Result<()> {
        for label in name.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(invalid());
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        Ok(())
    };
    let _ = qname;
    let _ = qtype;
    for record in records {
        let (rtype, ttl, rdata): (u16, u32, Vec<u8>) = match record {
            FakeDnsRecord::A(addr, ttl) | FakeDnsRecord::AFor(_, addr, ttl) => {
                (QTYPE_A, *ttl, addr.octets().to_vec())
            }
            FakeDnsRecord::Aaaa(addr, ttl) | FakeDnsRecord::AaaaFor(_, addr, ttl) => {
                (QTYPE_AAAA, *ttl, addr.octets().to_vec())
            }
            FakeDnsRecord::Cname(target, ttl) | FakeDnsRecord::CnameFor(_, target, ttl) => {
                let mut rdata = Vec::new();
                encode_name(&mut rdata, target)?;
                (QTYPE_CNAME, *ttl, rdata)
            }
        };
        match record {
            // Owner: an explicit name for inline chain records, else a
            // pointer to the question name at offset 12.
            FakeDnsRecord::AFor(owner, _, _)
            | FakeDnsRecord::AaaaFor(owner, _, _)
            | FakeDnsRecord::CnameFor(owner, _, _) => {
                encode_name(&mut out, owner)?;
            }
            _ => out.extend_from_slice(&[0xc0, 0x0c]),
        }
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&QCLASS_IN.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&rdata);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_recovery_requests_handover_before_activating_watchers() {
        for cancel in [false, true] {
            let (mut client, _log) = super::super::shim_tests::client_for_with_log("running");
            client.agent_timeout = Duration::from_secs(5);
            let permit = std::sync::Arc::new(crate::RuntimePermit::default());
            client.cancelled = Some(permit.clone());
            let entry = DnsLeaseEntry {
                expires_at: u64::MAX,
                allow_tag: super::super::network::dns_rule_tag("a.example.com", 1),
                reject_tag: super::super::network::dns_rule_reject_tag("a.example.com", 1),
                name: "a.example.com".into(),
                destinations: BTreeSet::from(["128.66.0.7/32".into()]),
                fence_on_expiry: BTreeSet::new(),
            };
            client
                .persist_dns_lease_obligations("sbx-1", &[entry])
                .unwrap();
            let owner = client.dns_lease_owner("sbx-1");
            let held = owner.state.lock().unwrap();
            let recovering = client.clone();
            let worker =
                std::thread::spawn(move || recovering.recover_all_dns_expiry_obligations());
            let deadline = Instant::now() + Duration::from_secs(5);
            while owner
                .recovery_waiters
                .load(std::sync::atomic::Ordering::Acquire)
                == 0
            {
                assert!(
                    Instant::now() < deadline,
                    "census did not request settlement handover"
                );
                std::thread::yield_now();
            }
            // Ownership is requested while the previous operation still owns
            // state; the startup IO budget must not be spent on this wait.
            if cancel {
                permit.revoke();
                assert!(worker.join().unwrap().is_err());
                drop(held);
            } else {
                drop(held);
                worker
                    .join()
                    .unwrap()
                    .expect("the first census succeeds after handover");
            }
            assert_eq!(
                owner
                    .recovery_waiters
                    .load(std::sync::atomic::Ordering::Acquire),
                0
            );
            client.debug_reset_dns_lease_owner("sbx-1");
        }
    }

    const SERVER: Ipv4Addr = Ipv4Addr::new(128, 66, 2, 53);

    fn servers() -> Vec<Ipv4Addr> {
        vec![SERVER]
    }

    fn limits() -> CompileLimits<'static> {
        CompileLimits {
            deadline: Instant::now() + super::super::network::COMPILE_BUDGET,
            cancelled: None,
        }
    }

    fn resolve(transport: &dyn DnsTransport, name: &str) -> Result<DomainGrant, ResolveDeny> {
        resolve_policy_name(transport, &servers(), name, &limits(), &RealDnsClock)
    }

    fn policy(domains: &[&str], cidrs: &[&str]) -> (EgressPolicy, String) {
        let policy = EgressPolicy {
            mode: sandbox_protocol::EgressMode::Allowlist,
            domains: domains.iter().map(|d| d.to_string()).collect(),
            cidrs: cidrs.iter().map(|c| c.to_string()).collect(),
        };
        let hash = super::super::network::policy_hash_hex(&policy);
        (policy, hash)
    }

    #[test]
    fn the_expiry_lease_withdraws_armed_identities_without_a_refresh() {
        // C36 r17 F3 (mechanism): the enforcement-level lease withdraws the
        // armed, request-specific identities at their absolute expiry with
        // no refresh running at all — enforcement is independent of
        // operation completion.
        let (client, _log) = super::super::shim_tests::client_for_with_log("running");
        client
            .apply_sandbox_network(&super::super::network::test_plan("sbx-1"))
            .expect("apply");
        let (_network, acl) = super::super::network::sandbox_network_names("sbx-1");
        let rules = super::super::network::domain_grant_rules(
            "leased.example.com",
            Ipv4Addr::new(128, 66, 0, 7),
            &[],
            7,
        );
        for rule in &rules {
            let mut args = vec![
                "network".to_string(),
                "acl".to_string(),
                "rule".to_string(),
                "add".to_string(),
                acl.clone(),
                "egress".to_string(),
            ];
            args.extend(rule.cli_args());
            let out = client
                .run(&args.iter().map(String::as_str).collect::<Vec<_>>(), false)
                .expect("rule add runs");
            assert_eq!(out.exit_code, 0, "rule add applied");
        }
        let expiry = unix_now().expect("clock") + 2;
        client
            .arm_dns_expiry_lease(
                "sbx-1",
                vec![DnsLeaseEntry {
                    expires_at: expiry,
                    allow_tag: super::super::network::dns_rule_tag("leased.example.com", 7),
                    reject_tag: super::super::network::dns_rule_reject_tag("leased.example.com", 7),
                    name: "leased.example.com".to_string(),
                    destinations: ["128.66.0.7/32".to_string()].into_iter().collect(),
                    fence_on_expiry: BTreeSet::new(),
                }],
            )
            .expect("lease armed");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            let observed = client
                .read_sandbox_acl(&acl)
                .expect("read")
                .expect("acl present");
            if !observed
                .egress
                .iter()
                .any(|rule| rule.destination == "128.66.0.7/32")
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the lease withdrew the armed identities at their absolute expiry"
            );
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }

    #[test]
    fn ttl_is_clamped_to_the_30_300_window() {
        assert_eq!(clamp_ttl(0), 30);
        assert_eq!(clamp_ttl(5), 30);
        assert_eq!(clamp_ttl(30), 30);
        assert_eq!(clamp_ttl(120), 120);
        assert_eq!(clamp_ttl(300), 300);
        assert_eq!(clamp_ttl(86_400), 300);
        assert_eq!(clamp_ttl(u32::MAX), 300);
    }

    #[test]
    fn aaaa_parity_data_denies_nodata_and_nxdomain_are_fine() {
        // NODATA (NOERROR, no records) on the AAAA view: the v4 grant
        // installs.
        let transport = FakeDnsTransport::new();
        transport.script(
            "v4only.example.com",
            [
                FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 7), 60)]),
                FakeDnsOutcome::Answer(vec![]),
            ],
        );
        resolve(&transport, "v4only.example.com").expect("AAAA NODATA is fine");

        // NXDOMAIN on the AAAA view is equally fine.
        let transport = FakeDnsTransport::new();
        transport.script(
            "v4only.example.com",
            [
                FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 7), 60)]),
                FakeDnsOutcome::Rcode(3),
            ],
        );
        resolve(&transport, "v4only.example.com").expect("AAAA NXDOMAIN is fine");

        // AAAA DATA: the grant is DENIED (unsupported), never narrowed to v4.
        let transport = FakeDnsTransport::new();
        transport.script(
            "dual.example.com",
            [
                FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 7), 60)]),
                FakeDnsOutcome::Answer(vec![FakeDnsRecord::Aaaa(
                    "2001:db8::1".parse().unwrap(),
                    60,
                )]),
            ],
        );
        let deny = resolve(&transport, "dual.example.com").expect_err("AAAA data denies");
        assert_eq!(deny.kind, DenyKind::Empty);
        assert_eq!(deny.error.code, SandboxErrorCode::UnsupportedCapability);

        // An AAAA transport failure is transient (parity with A): the name
        // is not treated as v4-only on a flaky resolver.
        let transport = FakeDnsTransport::new();
        transport.script(
            "flaky.example.com",
            [
                FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 7), 60)]),
                FakeDnsOutcome::TransportError,
            ],
        );
        let deny = resolve(&transport, "flaky.example.com").expect_err("transient");
        assert_eq!(deny.kind, DenyKind::Transient);
    }

    #[test]
    fn inline_protected_address_at_the_cname_target_denies_before_following() {
        // The answer carries the CNAME AND the target's address inline: the
        // inline address belongs to the reachable chain and must be
        // validated BEFORE the chain is followed — a protected inline
        // address denies immediately, even when a re-query of the target
        // would return a public address.
        let transport = FakeDnsTransport::new();
        transport.script(
            "grants.example.com",
            [FakeDnsOutcome::Answer(vec![
                FakeDnsRecord::Cname("cdn.example.com".into(), 60),
                FakeDnsRecord::AFor("cdn.example.com".into(), Ipv4Addr::new(10, 0, 0, 5), 60),
            ])],
        );
        transport.script(
            "cdn.example.com",
            [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
                Ipv4Addr::new(128, 66, 0, 9),
                60,
            )])],
        );
        let deny = resolve(&transport, "grants.example.com")
            .expect_err("inline protected address denies the whole name");
        assert_eq!(deny.kind, DenyKind::Empty);
        assert_eq!(deny.error.code, SandboxErrorCode::ProtocolError);
        assert!(
            transport
                .queries()
                .iter()
                .all(|(_, qname, _)| qname != "cdn.example.com"),
            "the target is never re-queried: {:?}",
            transport.queries()
        );
    }

    #[test]
    fn inline_aaaa_at_the_cname_target_denies_before_following() {
        // AAAA parity: an inline AAAA record for the chain target is IPv6
        // data on the chain — deny (IPv4-only), never skip to a re-query.
        let transport = FakeDnsTransport::new();
        transport.script(
            "grants.example.com",
            [
                FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 7), 60)]),
                FakeDnsOutcome::Answer(vec![
                    FakeDnsRecord::Cname("cdn.example.com".into(), 60),
                    FakeDnsRecord::AaaaFor(
                        "cdn.example.com".into(),
                        "2001:db8::1".parse().unwrap(),
                        60,
                    ),
                ]),
            ],
        );
        let deny = resolve(&transport, "grants.example.com")
            .expect_err("inline AAAA at the target denies");
        assert_eq!(deny.kind, DenyKind::Empty);
        assert_eq!(deny.error.code, SandboxErrorCode::UnsupportedCapability);
        assert!(
            transport
                .queries()
                .iter()
                .all(|(_, qname, _)| qname != "cdn.example.com"),
            "the target is never re-queried: {:?}",
            transport.queries()
        );
    }

    #[test]
    fn multi_hop_inline_cname_chain_validates_every_hop() {
        // a→b→c carried in ONE response, with a protected address owned by
        // the SECOND hop target: examining only the first target (b) misses
        // it, and a public re-query answer would launder it. Every inline
        // hop is walked first; neither b nor c is ever queried.
        let transport = FakeDnsTransport::new();
        transport.script(
            "grants.example.com",
            [FakeDnsOutcome::Answer(vec![
                FakeDnsRecord::Cname("b.example.com".into(), 60),
                FakeDnsRecord::CnameFor("b.example.com".into(), "c.example.com".into(), 60),
                FakeDnsRecord::AFor("c.example.com".into(), Ipv4Addr::new(10, 0, 0, 5), 60),
            ])],
        );
        transport.script(
            "b.example.com",
            [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
                Ipv4Addr::new(128, 66, 0, 9),
                60,
            )])],
        );
        transport.script(
            "c.example.com",
            [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
                Ipv4Addr::new(128, 66, 0, 9),
                60,
            )])],
        );
        let deny = resolve(&transport, "grants.example.com")
            .expect_err("protected address at the second inline hop denies");
        assert_eq!(deny.kind, DenyKind::Empty);
        assert_eq!(deny.error.code, SandboxErrorCode::ProtocolError);
        assert!(
            transport
                .queries()
                .iter()
                .all(|(_, qname, _)| qname != "b.example.com" && qname != "c.example.com"),
            "no re-query launders the observed chain: {:?}",
            transport.queries()
        );

        // Public variant: the whole inline chain is walkable, only the FINAL
        // hop is re-queried, and the grant installs.
        let transport = FakeDnsTransport::new();
        transport.script(
            "grants.example.com",
            [FakeDnsOutcome::Answer(vec![
                FakeDnsRecord::Cname("b.example.com".into(), 60),
                FakeDnsRecord::CnameFor("b.example.com".into(), "c.example.com".into(), 60),
                FakeDnsRecord::AFor("c.example.com".into(), Ipv4Addr::new(128, 66, 0, 9), 60),
            ])],
        );
        transport.script(
            "c.example.com",
            [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
                Ipv4Addr::new(128, 66, 0, 9),
                60,
            )])],
        );
        let grant = resolve(&transport, "grants.example.com").expect("public chain installs");
        assert_eq!(grant.addresses, vec![Ipv4Addr::new(128, 66, 0, 9)]);
        let queries = transport.queries();
        let queried: Vec<&str> = queries.iter().map(|(_, qname, _)| qname.as_str()).collect();
        assert!(
            !queried.contains(&"b.example.com"),
            "intermediate hops are not re-queried: {queried:?}"
        );
        assert!(
            queried.contains(&"c.example.com"),
            "the chain end is re-queried: {queried:?}"
        );
    }

    #[test]
    fn multi_hop_inline_cname_chain_validates_every_hop_aaaa() {
        // AAAA parity: a→b→c inline in the AAAA answer with inline AAAA data
        // owned by c denies; a NODATA re-query of b must never launder it.
        let transport = FakeDnsTransport::new();
        transport.script(
            "grants.example.com",
            [
                FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 7), 60)]),
                FakeDnsOutcome::Answer(vec![
                    FakeDnsRecord::Cname("b.example.com".into(), 60),
                    FakeDnsRecord::CnameFor("b.example.com".into(), "c.example.com".into(), 60),
                    FakeDnsRecord::AaaaFor(
                        "c.example.com".into(),
                        "2001:db8::1".parse().unwrap(),
                        60,
                    ),
                ]),
            ],
        );
        transport.script("b.example.com", [FakeDnsOutcome::Answer(vec![])]);
        let deny = resolve(&transport, "grants.example.com")
            .expect_err("inline AAAA at the second hop denies");
        assert_eq!(deny.kind, DenyKind::Empty);
        assert_eq!(deny.error.code, SandboxErrorCode::UnsupportedCapability);
        assert!(
            transport
                .queries()
                .iter()
                .all(|(_, qname, _)| qname != "b.example.com" && qname != "c.example.com"),
            "no re-query launders the observed chain: {:?}",
            transport.queries()
        );
    }

    #[test]
    fn mixed_cname_and_address_data_for_the_current_hop_denies() {
        // C36 r33 F3: `grants A 10.0.0.5` beside `grants CNAME cdn` is
        // conflicting data. The pre-fix walk selected the CNAME and
        // validated only the TARGET's addresses, so a public answer for
        // `cdn` laundered the protected address the original answer
        // already carried into an accepted grant. The walk now rejects
        // the conflict BEFORE advancing the hop.
        let transport = FakeDnsTransport::new();
        transport.script(
            "grants.example.com",
            [FakeDnsOutcome::Answer(vec![
                FakeDnsRecord::A(Ipv4Addr::new(10, 0, 0, 5), 60),
                FakeDnsRecord::Cname("cdn.example.com".into(), 60),
            ])],
        );
        transport.script(
            "cdn.example.com",
            [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
                Ipv4Addr::new(128, 66, 0, 9),
                60,
            )])],
        );
        let deny = resolve(&transport, "grants.example.com")
            .expect_err("conflicting CNAME/address data denies");
        assert_eq!(deny.kind, DenyKind::Empty);
        assert_eq!(deny.error.code, SandboxErrorCode::ProtocolError);
        assert!(
            transport
                .queries()
                .iter()
                .all(|(_, qname, _)| qname != "cdn.example.com"),
            "the conflict is rejected before the hop is even followed: {:?}",
            transport.queries()
        );
    }

    #[test]
    fn mixed_cname_and_address_data_denies_even_with_public_addresses() {
        // C36 r33 F3: the conflict is malformed data in its own right —
        // the denial does not depend on the stray address being
        // protected. `a A 128.66.0.7` beside `a CNAME b` still denies.
        let transport = FakeDnsTransport::new();
        transport.script(
            "grants.example.com",
            [FakeDnsOutcome::Answer(vec![
                FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 7), 60),
                FakeDnsRecord::Cname("b.example.com".into(), 60),
            ])],
        );
        transport.script(
            "b.example.com",
            [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
                Ipv4Addr::new(128, 66, 0, 8),
                60,
            )])],
        );
        let deny = resolve(&transport, "grants.example.com")
            .expect_err("conflicting CNAME/address data denies regardless of the address");
        assert_eq!(deny.kind, DenyKind::Empty);
        assert_eq!(deny.error.code, SandboxErrorCode::ProtocolError);
    }

    #[test]
    fn mixed_cname_and_aaaa_data_for_the_current_hop_denies() {
        // C36 r33 F3 (AAAA parity): `grants CNAME v6` beside
        // `grants AAAA 2001:db8::1` — pre-fix the AAAA walk followed the
        // CNAME, never examined the current owner's IPv6 record, and the
        // grant was accepted.
        let transport = FakeDnsTransport::new();
        transport.script(
            "grants.example.com",
            [
                FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 7), 60)]),
                FakeDnsOutcome::Answer(vec![
                    FakeDnsRecord::Cname("v6.example.com".into(), 60),
                    FakeDnsRecord::AaaaFor(
                        "grants.example.com".into(),
                        "2001:db8::1".parse().unwrap(),
                        60,
                    ),
                ]),
            ],
        );
        transport.script("v6.example.com", [FakeDnsOutcome::Answer(vec![])]);
        let deny = resolve(&transport, "grants.example.com")
            .expect_err("conflicting CNAME/IPv6 data denies");
        assert_eq!(deny.kind, DenyKind::Empty);
        assert_eq!(deny.error.code, SandboxErrorCode::ProtocolError);
        assert!(
            transport
                .queries()
                .iter()
                .all(|(_, qname, _)| qname != "v6.example.com"),
            "the conflict is rejected before the AAAA hop is followed: {:?}",
            transport.queries()
        );
    }

    #[test]
    fn conflicting_cname_targets_deny_regardless_of_branch_order() {
        // C36 r34 F3: `a CNAME public` + `a CNAME private` +
        // `private A 10.0.0.5` — pre-fix the walk silently selected the
        // FIRST CNAME, so the public-first ordering was accepted while
        // the private branch's protected address escaped validation.
        // Distinct targets for one reachable owner are conflicting data
        // and deny in EITHER order.
        for (first, second) in [
            ("public.example.com", "private.example.com"),
            ("private.example.com", "public.example.com"),
        ] {
            let transport = FakeDnsTransport::new();
            transport.script(
                "grants.example.com",
                [FakeDnsOutcome::Answer(vec![
                    FakeDnsRecord::Cname(first.into(), 60),
                    FakeDnsRecord::Cname(second.into(), 60),
                    FakeDnsRecord::AFor(
                        "private.example.com".into(),
                        Ipv4Addr::new(10, 0, 0, 5),
                        60,
                    ),
                ])],
            );
            transport.script(
                "public.example.com",
                [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
                    Ipv4Addr::new(128, 66, 0, 9),
                    60,
                )])],
            );
            transport.script(
                "private.example.com",
                [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
                    Ipv4Addr::new(10, 0, 0, 5),
                    60,
                )])],
            );
            let deny = resolve(&transport, "grants.example.com")
                .expect_err("conflicting CNAME targets deny in either order");
            assert_eq!(deny.kind, DenyKind::Empty);
            assert_eq!(deny.error.code, SandboxErrorCode::ProtocolError);
            assert!(
                transport
                    .queries()
                    .iter()
                    .all(|(_, qname, _)| qname == "grants.example.com"),
                "the conflict is rejected before any branch is followed: {:?}",
                transport.queries()
            );
        }
    }

    #[test]
    fn conflicting_cname_targets_deny_in_the_aaaa_walk() {
        // C36 r34 F3 (AAAA parity, independently of query type): the
        // AAAA answer carries two distinct CNAME targets for the queried
        // name plus inline IPv6 data for the private branch.
        let transport = FakeDnsTransport::new();
        transport.script(
            "grants.example.com",
            [
                FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 7), 60)]),
                FakeDnsOutcome::Answer(vec![
                    FakeDnsRecord::Cname("public.example.com".into(), 60),
                    FakeDnsRecord::Cname("private.example.com".into(), 60),
                    FakeDnsRecord::AaaaFor(
                        "private.example.com".into(),
                        "2001:db8::1".parse().unwrap(),
                        60,
                    ),
                ]),
            ],
        );
        transport.script("public.example.com", [FakeDnsOutcome::Answer(vec![])]);
        transport.script("private.example.com", [FakeDnsOutcome::Answer(vec![])]);
        let deny = resolve(&transport, "grants.example.com")
            .expect_err("conflicting CNAME targets deny in the AAAA walk");
        assert_eq!(deny.kind, DenyKind::Empty);
        assert_eq!(deny.error.code, SandboxErrorCode::ProtocolError);
    }

    #[test]
    fn duplicate_identical_cnames_collapse_to_one_hop() {
        // C36 r34 F3 inverse: the SAME CNAME target repeated is one
        // RRset, not a conflict — the chain still resolves.
        let transport = FakeDnsTransport::new();
        transport.script(
            "grants.example.com",
            [FakeDnsOutcome::Answer(vec![
                FakeDnsRecord::Cname("cdn.example.com".into(), 120),
                FakeDnsRecord::Cname("cdn.example.com".into(), 60),
            ])],
        );
        transport.script(
            "cdn.example.com",
            [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
                Ipv4Addr::new(128, 66, 0, 9),
                60,
            )])],
        );
        let grant = resolve(&transport, "grants.example.com")
            .expect("duplicate identical CNAMEs are one hop");
        assert_eq!(grant.addresses, vec![Ipv4Addr::new(128, 66, 0, 9)]);
    }

    #[test]
    fn aaaa_cname_chain_to_ipv6_data_denies() {
        // The AAAA view follows CNAME chains: IPv6 data at the CHAIN END
        // denies the whole grant (UNSUPPORTED_CAPABILITY), not silently
        // installs the v4 half.
        let transport = FakeDnsTransport::new();
        transport.script(
            "grants.example.com",
            [
                FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 7), 60)]),
                FakeDnsOutcome::Answer(vec![FakeDnsRecord::Cname("v6.example.com".into(), 60)]),
            ],
        );
        transport.script(
            "v6.example.com",
            [FakeDnsOutcome::Answer(vec![FakeDnsRecord::Aaaa(
                "2001:db8::1".parse().unwrap(),
                60,
            )])],
        );
        let deny = resolve(&transport, "grants.example.com").expect_err("v6 data at chain end");
        assert_eq!(deny.kind, DenyKind::Empty);
        assert_eq!(deny.error.code, SandboxErrorCode::UnsupportedCapability);

        // NODATA at the chain end is fine (a v4-only alias target).
        let transport = FakeDnsTransport::new();
        transport.script(
            "grants.example.com",
            [
                FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 7), 60)]),
                FakeDnsOutcome::Answer(vec![FakeDnsRecord::Cname("v6.example.com".into(), 60)]),
            ],
        );
        transport.script("v6.example.com", [FakeDnsOutcome::Answer(vec![])]);
        resolve(&transport, "grants.example.com").expect("v6 NODATA at chain end is fine");
    }

    #[test]
    fn aaaa_cname_cycles_deny() {
        let transport = FakeDnsTransport::new();
        transport.script(
            "grants.example.com",
            [
                FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 7), 60)]),
                FakeDnsOutcome::Answer(vec![FakeDnsRecord::Cname("loop1.example.com".into(), 60)]),
            ],
        );
        transport.script(
            "loop1.example.com",
            [FakeDnsOutcome::Answer(vec![FakeDnsRecord::Cname(
                "loop2.example.com".into(),
                60,
            )])],
        );
        transport.script(
            "loop2.example.com",
            [FakeDnsOutcome::Answer(vec![FakeDnsRecord::Cname(
                "loop1.example.com".into(),
                60,
            )])],
        );
        let deny = resolve(&transport, "grants.example.com").expect_err("AAAA cycle denies");
        assert_eq!(deny.kind, DenyKind::Empty);
    }

    #[test]
    fn overlapping_grants_survive_persistence_and_transient_failures() {
        // 17 names sharing 32 addresses: 32 unique destinations (within the
        // destination bound) but 544 emitted records. Planning commits this
        // state, so LOADING must accept it — otherwise the next transient
        // failure would discard still-unexpired grants.
        let names: Vec<String> = (0..17).map(|i| format!("d{i}.example.com")).collect();
        let addrs: Vec<Ipv4Addr> = (0..32).map(|i| Ipv4Addr::new(128, 66, 1, i)).collect();
        let policy = EgressPolicy {
            mode: sandbox_protocol::EgressMode::Allowlist,
            domains: names.clone(),
            cidrs: Vec::new(),
        };
        let outcomes = names
            .iter()
            .map(|name| {
                Ok(DomainGrant {
                    name: name.clone(),
                    addresses: addrs.clone(),
                    ttl: 300,
                    expires_at: 1_300,
                })
            })
            .collect();
        let plan = plan_refresh("sbx-1", &policy, "h", None, outcomes, 1_000)
            .expect("544 records over 32 destinations is within bounds");
        assert_eq!(plan.destinations.len(), 32);
        assert_eq!(
            plan.state
                .grants
                .iter()
                .map(|grant| grant.addresses.len())
                .sum::<usize>(),
            544
        );
        // Persist + reload: the state planning committed is valid at load.
        let dir = std::env::temp_dir().join(format!("wssp-c36-load-{}", std::process::id()));
        let mut client = IncusClient::new("true".to_string(), "default".to_string());
        client.state_dir = Some(dir.clone());
        client
            .persist_dns_state(&plan.state)
            .expect("persist the committed state");
        let loaded = client
            .load_dns_state("sbx-1", "h")
            .expect("a committed overlapping state loads");
        let _ = std::fs::remove_dir_all(&dir);
        // A transient failure on every name keeps the unexpired grants.
        let outcomes = names
            .iter()
            .map(|_| Err(ResolveDeny::transient(internal_error("resolver down"))))
            .collect();
        let retained = plan_refresh("sbx-1", &policy, "h", Some(&loaded), outcomes, 1_100)
            .expect("retention planning");
        assert_eq!(retained.state.grants.len(), 17, "unexpired grants kept");
        assert_eq!(retained.answers.len(), 17);
        assert!(retained.denied.is_empty());
    }

    #[test]
    fn overbound_records_revoke_fail_closed() {
        // The emitted-record bound (distinct from unique destinations):
        // 128 names x 33 addresses = 4224 records over 33 destinations.
        let names: Vec<String> = (0..128).map(|i| format!("d{i}.example.com")).collect();
        let addrs: Vec<Ipv4Addr> = (0..33).map(|i| Ipv4Addr::new(128, 66, 0, i)).collect();
        let policy = EgressPolicy {
            mode: sandbox_protocol::EgressMode::Allowlist,
            domains: names.clone(),
            cidrs: Vec::new(),
        };
        let outcomes = names
            .iter()
            .map(|name| {
                Ok(DomainGrant {
                    name: name.clone(),
                    addresses: addrs.clone(),
                    ttl: 300,
                    expires_at: 1_300,
                })
            })
            .collect();
        let plan = plan_refresh("sbx-1", &policy, "h", None, outcomes, 1_000)
            .expect("over-bound records plan a bounded revocation");
        assert!(plan.state.grants.is_empty());
        assert!(plan.answers.is_empty());
        assert_eq!(plan.denied.len(), 128);
        assert!(plan.destinations.is_empty());
    }

    #[test]
    fn overbound_resolution_revokes_every_dynamic_grant_fail_closed() {
        // Prior: a live grant for a.example.com. Now a.example.com NXDOMAINs
        // while b.example.com expands past the destination bound. The plan
        // must revoke EVERYTHING dynamic (bounded, fail closed) — never
        // abort with the stale grant left installed past expiry.
        let (policy, hash) = policy(&["a.example.com", "b.example.com"], &["128.66.0.0/24"]);
        let prior = SandboxDnsState {
            sandbox_id: "sbx-1".into(),
            policy_hash: hash.clone(),
            grants: vec![DnsGrantEntry {
                name: "a.example.com".into(),
                addresses: vec!["128.66.1.7".into()],
                ttl: 120,
                expires_at: 2_000,
                generation: 0,
            }],
            published: String::new(),
            generations: std::collections::BTreeMap::new(),
        };
        let mut many = Vec::new();
        for third in [2u8, 3] {
            for fourth in 0..=255u8 {
                many.push(Ipv4Addr::new(128, 66, third, fourth));
            }
        }
        let grant = DomainGrant {
            name: "b.example.com".into(),
            addresses: many,
            ttl: 60,
            expires_at: 1_060,
        };
        let plan = plan_refresh(
            "sbx-1",
            &policy,
            &hash,
            Some(&prior),
            vec![
                Err(ResolveDeny::empty(internal_error("NXDOMAIN"))),
                Ok(grant),
            ],
            1_000,
        )
        .expect("over-bound resolution plans a bounded revocation, not an abort");
        assert!(plan.answers.is_empty(), "no answers published");
        assert!(
            plan.state.grants.is_empty(),
            "the negatively-resolved prior grant is revoked too"
        );
        assert_eq!(plan.destinations, vec!["128.66.0.0/24".to_string()]);
        assert_eq!(plan.denied.len(), 2, "both names reported denied");
        assert_eq!(plan.refresh_after, MIN_REFRESH_TTL_SECS, "retry soon");
        assert!(
            !plan.state.published.contains("host-record="),
            "deny-all publication"
        );
    }

    #[test]
    fn malformed_aaaa_responses_deny_like_malformed_a() {
        // A valid A answer followed by a malformed AAAA response must NOT
        // install the grant.
        struct BadAaaa;
        impl DnsTransport for BadAaaa {
            fn query(&self, _server: Ipv4Addr, message: &[u8]) -> std::io::Result<Vec<u8>> {
                let (_, _, qtype) = parse_question(message).map_err(|err| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string())
                })?;
                if qtype == QTYPE_AAAA {
                    // Well-formed-ish header, garbage body.
                    return Ok(vec![0x81, 0x80, 1, 2, 3]);
                }
                encode_response(
                    message,
                    0,
                    &[FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 7), 60)],
                )
            }
        }
        let deny = resolve(&BadAaaa, "grants.example.com").expect_err("malformed AAAA denies");
        assert_eq!(deny.kind, DenyKind::Empty);
    }

    #[test]
    fn cname_rdata_must_occupy_exactly_its_rdlen() {
        let query = build_query(0x4242, "grants.example.com", QTYPE_A).unwrap();
        let frame_with = |rdata: &[u8], rdlen: u16| {
            let mut frame = query.clone();
            frame[2] = 0x81;
            frame[3] = 0x80;
            frame[7] = 1; // ANCOUNT
            frame.extend_from_slice(&[0xc0, 0x0c]); // owner: the question name
            frame.extend_from_slice(&QTYPE_CNAME.to_be_bytes());
            frame.extend_from_slice(&QCLASS_IN.to_be_bytes());
            frame.extend_from_slice(&60u32.to_be_bytes());
            frame.extend_from_slice(&rdlen.to_be_bytes());
            frame.extend_from_slice(rdata);
            frame
        };
        // Legitimate: a literal target filling RDLENGTH exactly.
        let ok = frame_with(&[1, b'a', 0], 3);
        parse_response(&ok, 0x4242, "grants.example.com", QTYPE_A).expect("literal target");
        // Legitimate compression: a pointer consumes exactly 2 bytes.
        let ok = frame_with(&[0xc0, 0x0c], 2);
        parse_response(&ok, 0x4242, "grants.example.com", QTYPE_A).expect("pointer target");
        // SHORT RDLENGTH: the encoded name (3 bytes) must not bleed past a
        // 2-byte RDLENGTH (a following record's bytes are not the target).
        let short = frame_with(&[1, b'a', 0], 2);
        parse_response(&short, 0x4242, "grants.example.com", QTYPE_A)
            .expect_err("short rdlen is malformed");
        // Zero RDLENGTH: nothing may be decoded as the target.
        let zero = frame_with(&[1, b'a', 0], 0);
        parse_response(&zero, 0x4242, "grants.example.com", QTYPE_A)
            .expect_err("zero rdlen is malformed");
        // OVERSIZED RDLENGTH: trailing junk inside RDATA is not ignored.
        let mut big = frame_with(&[1, b'a', 0, 9, 9, 9, 9], 7);
        // (7 bytes of rdata, name ends at 3: trailing bytes must deny.)
        parse_response(&big, 0x4242, "grants.example.com", QTYPE_A)
            .expect_err("oversized rdlen is malformed");
        big.truncate(big.len() - 1);
        parse_response(&big, 0x4242, "grants.example.com", QTYPE_A)
            .expect_err("truncated rdata is malformed");
    }

    #[test]
    fn special_purpose_guest_address_boundaries_are_protected() {
        for (address, protected) in [
            ("191.255.255.255", false),
            ("192.0.0.0", true),
            ("192.0.0.9", true),
            ("192.0.0.255", true),
            ("192.0.1.0", false),
            ("192.0.2.0", true),
            ("192.0.2.255", true),
            ("192.0.3.0", false),
            ("198.51.99.255", false),
            ("198.51.100.0", true),
            ("198.51.100.255", true),
            ("198.51.101.0", false),
            ("203.0.112.255", false),
            ("203.0.113.0", true),
            ("203.0.113.255", true),
            ("203.0.114.0", false),
            ("192.88.98.255", false),
            ("192.88.99.0", true),
            ("192.88.99.255", true),
            ("192.88.100.0", false),
        ] {
            assert_eq!(
                is_protected_guest_address(address.parse().unwrap()),
                protected,
                "{address}"
            );
        }
    }

    #[test]
    fn protected_guest_addresses_cover_local_and_metadata_space() {
        for text in [
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.1",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.100.100.200",
            "100.127.255.254",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "198.18.0.1",
            "240.0.0.1",
        ] {
            let ip: Ipv4Addr = text.parse().unwrap();
            assert!(is_protected_guest_address(ip), "{text} must be protected");
        }
        for text in ["128.66.0.7", "128.66.1.9", "128.66.2.1", "8.8.8.8"] {
            let ip: Ipv4Addr = text.parse().unwrap();
            assert!(!is_protected_guest_address(ip), "{text} is a public answer");
        }
    }

    #[test]
    fn simple_a_resolution_returns_sorted_addresses_and_clamped_ttl() {
        let transport = FakeDnsTransport::new();
        transport.script(
            "grants.example.com",
            [FakeDnsOutcome::Answer(vec![
                FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 9), 12),
                FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 7), 12),
                FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 7), 12),
            ])],
        );
        let grant = resolve(&transport, "grants.example.com").expect("resolves");
        assert_eq!(
            grant.addresses,
            vec![Ipv4Addr::new(128, 66, 0, 7), Ipv4Addr::new(128, 66, 0, 9)]
        );
        // TTL 12 clamps up to the 30s floor.
        assert_eq!(grant.ttl, MIN_REFRESH_TTL_SECS);
        let queries = transport.queries();
        assert!(
            queries
                .iter()
                .any(|(_, name, qtype)| name == "grants.example.com" && *qtype == QTYPE_A),
            "queries: {queries:?}"
        );
        // The AAAA view is validated too (default NXDOMAIN is fine).
        assert!(
            queries
                .iter()
                .any(|(_, name, qtype)| name == "grants.example.com" && *qtype == QTYPE_AAAA),
            "queries: {queries:?}"
        );
    }

    #[test]
    fn ttl_uses_the_chain_minimum_clamped_to_300() {
        let transport = FakeDnsTransport::new();
        transport.script(
            "grants.example.com",
            [FakeDnsOutcome::Answer(vec![FakeDnsRecord::Cname(
                "cdn.example.net".to_string(),
                1000,
            )])],
        );
        transport.script(
            "cdn.example.net",
            [
                FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 7), 600)]),
                FakeDnsOutcome::Answer(vec![]),
            ],
        );
        let grant = resolve(&transport, "grants.example.com").expect("resolves");
        assert_eq!(grant.addresses, vec![Ipv4Addr::new(128, 66, 0, 7)]);
        assert_eq!(grant.ttl, MAX_REFRESH_TTL_SECS);
    }

    #[test]
    fn cname_cycles_and_overlong_chains_deny() {
        let transport = FakeDnsTransport::new();
        transport.script(
            "a.example.com",
            [FakeDnsOutcome::Answer(vec![FakeDnsRecord::Cname(
                "b.example.com".to_string(),
                60,
            )])],
        );
        transport.script(
            "b.example.com",
            [FakeDnsOutcome::Answer(vec![FakeDnsRecord::Cname(
                "a.example.com".to_string(),
                60,
            )])],
        );
        let deny = resolve(&transport, "a.example.com").expect_err("cycle denies");
        assert_eq!(deny.kind, DenyKind::Empty);

        // A chain longer than MAX_CNAME_CHAIN denies even without a cycle,
        // even when the terminal hop would resolve cleanly.
        let transport = FakeDnsTransport::new();
        for i in 0..=MAX_CNAME_CHAIN {
            transport.script(
                &format!("hop{i}.example.com"),
                [FakeDnsOutcome::Answer(vec![FakeDnsRecord::Cname(
                    format!("hop{}.example.com", i + 1),
                    60,
                )])],
            );
        }
        transport.script(
            &format!("hop{}.example.com", MAX_CNAME_CHAIN + 1),
            [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
                Ipv4Addr::new(128, 66, 0, 7),
                60,
            )])],
        );
        let deny = resolve(&transport, "hop0.example.com").expect_err("overlong chain denies");
        assert_eq!(deny.kind, DenyKind::Empty);
    }

    #[test]
    fn answers_for_unrelated_owners_are_never_installed() {
        // Bailiwick: an A record owned by a name the walk did not ask about
        // must not count as the queried name's answer.
        let query = build_query(0x4242, "grants.example.com", QTYPE_A).unwrap();
        // A response to `message` (its real transaction id/question) whose A
        // record is owned by a DIFFERENT name than the question.
        fn misowned_response(message: &[u8]) -> std::io::Result<Vec<u8>> {
            let mut frame = message.to_vec();
            frame[2] = 0x81;
            frame[3] = 0x80;
            frame[7] = 1; // ANCOUNT
            // Owner encoded literally: "other.example.com" (NOT the question).
            for label in ["other", "example", "com"] {
                frame.push(label.len() as u8);
                frame.extend_from_slice(label.as_bytes());
            }
            frame.push(0);
            frame.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 128, 66, 0, 7]);
            Ok(frame)
        }
        let frame = misowned_response(&query).unwrap();
        let parsed = parse_response(&frame, 0x4242, "grants.example.com", QTYPE_A)
            .expect("well-formed frame");
        assert_eq!(parsed.answers.len(), 1, "the record parses");
        // ...but the resolver walk owns nothing for the queried name:
        // NODATA, denied.
        struct Misowned;
        impl DnsTransport for Misowned {
            fn query(&self, _server: Ipv4Addr, message: &[u8]) -> std::io::Result<Vec<u8>> {
                let (_, qname, qtype) = parse_question(message).unwrap();
                if qname == "grants.example.com" && qtype == QTYPE_A {
                    return misowned_response(message);
                }
                encode_response(message, 3, &[])
            }
        }
        let deny = resolve_policy_name(
            &Misowned,
            &servers(),
            "grants.example.com",
            &limits(),
            &RealDnsClock,
        )
        .expect_err("foreign-owner answer denies");
        assert_eq!(deny.kind, DenyKind::Empty);
    }

    #[test]
    fn mixed_public_private_answers_deny_the_whole_name() {
        for rebound in [
            "10.0.0.5",
            "127.0.0.1",
            "169.254.169.254",
            "100.64.1.1",
            "192.0.2.7",
            "198.51.100.9",
            "203.0.113.1",
        ] {
            let transport = FakeDnsTransport::new();
            transport.script(
                "grants.example.com",
                [FakeDnsOutcome::Answer(vec![
                    FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 7), 60),
                    FakeDnsRecord::A(rebound.parse().unwrap(), 60),
                ])],
            );
            let deny = resolve(&transport, "grants.example.com")
                .expect_err("a rebound protected address denies");
            assert_eq!(deny.kind, DenyKind::Empty, "{rebound}");
        }
    }

    #[test]
    fn cname_chain_endpoint_addresses_are_validated() {
        // The rebound address arrives at the END of a CNAME chain.
        let transport = FakeDnsTransport::new();
        transport.script(
            "grants.example.com",
            [FakeDnsOutcome::Answer(vec![FakeDnsRecord::Cname(
                "rebind.attacker.example".to_string(),
                60,
            )])],
        );
        transport.script(
            "rebind.attacker.example",
            [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
                Ipv4Addr::new(192, 168, 1, 1),
                60,
            )])],
        );
        let deny = resolve(&transport, "grants.example.com").expect_err("rebound chain denies");
        assert_eq!(deny.kind, DenyKind::Empty);
    }

    #[test]
    fn nxdomain_and_nodata_are_empty_denials() {
        let transport = FakeDnsTransport::new();
        // Unscripted: default NXDOMAIN.
        let deny = resolve(&transport, "absent.example.com").expect_err("nxdomain");
        assert_eq!(deny.kind, DenyKind::Empty);

        let transport = FakeDnsTransport::new();
        transport.script("empty.example.com", [FakeDnsOutcome::Answer(vec![])]);
        let deny = resolve(&transport, "empty.example.com").expect_err("nodata");
        assert_eq!(deny.kind, DenyKind::Empty);
    }

    #[test]
    fn transport_failure_is_transient_and_falls_through_servers() {
        let transport = FakeDnsTransport::new();
        transport.script("grants.example.com", [FakeDnsOutcome::TransportError]);
        let deny = resolve(&transport, "grants.example.com").expect_err("all servers down");
        assert_eq!(deny.kind, DenyKind::Transient);
    }

    #[test]
    fn malformed_answers_are_immediate_denials() {
        // Answer for a DIFFERENT question (qname mismatch) than requested.
        let transport = FakeDnsTransport::new();
        transport.script(
            "grants.example.com",
            [FakeDnsOutcome::Answer(vec![FakeDnsRecord::Cname(
                "not a dns name!!".to_string(),
                60,
            )])],
        );
        let deny = resolve(&transport, "grants.example.com").expect_err("bad cname target");
        assert_eq!(deny.kind, DenyKind::Empty);
    }

    #[test]
    fn response_validation_rejects_spoofed_frames() {
        let transport = FakeDnsTransport::new();
        transport.script(
            "grants.example.com",
            [FakeDnsOutcome::Answer(vec![FakeDnsRecord::A(
                Ipv4Addr::new(128, 66, 0, 7),
                60,
            )])],
        );
        // Capture the query, corrupt the frame, reparse.
        let query = build_query(0x1234, "grants.example.com", QTYPE_A).unwrap();
        let response = encode_response(
            &query,
            0,
            &[FakeDnsRecord::A(Ipv4Addr::new(128, 66, 0, 7), 60)],
        )
        .unwrap();
        parse_response(&response, 0x1234, "grants.example.com", QTYPE_A).expect("roundtrip");
        // Wrong transaction id.
        parse_response(&response, 0x9999, "grants.example.com", QTYPE_A).expect_err("id mismatch");
        // Wrong expected question.
        parse_response(&response, 0x1234, "other.example.com", QTYPE_A)
            .expect_err("qname mismatch");
        parse_response(&response, 0x1234, "grants.example.com", QTYPE_AAAA)
            .expect_err("qtype mismatch");
        // Truncated flag set.
        let mut truncated = response.clone();
        truncated[2] |= 0x02;
        parse_response(&truncated, 0x1234, "grants.example.com", QTYPE_A).expect_err("truncated");
        // Compression loop: a frame whose answer owner pointer targets
        // itself (pointers may only point strictly backwards).
        let mut frame = query.clone();
        frame[2] = 0x81;
        frame[3] = 0x80;
        frame[7] = 1; // ANCOUNT
        let ptr_at = frame.len();
        frame.extend_from_slice(&[0xc0, (ptr_at & 0xff) as u8]); // pointer to itself
        frame.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 128, 66, 0, 7]);
        parse_response(&frame, 0x1234, "grants.example.com", QTYPE_A).expect_err("pointer loop");
    }

    #[test]
    fn resolv_conf_parsing_keeps_only_bounded_ipv4_servers() {
        let text = "# comment\nnameserver 128.66.2.1\nnameserver fd00::1\nnameserver 10.0.0.1 extra\nsearch example.com\nnameserver 128.66.1.1\nnameserver 128.66.0.1\nnameserver 128.66.0.2\n";
        let servers = resolv_conf_servers(text);
        assert_eq!(
            servers,
            vec![
                Ipv4Addr::new(128, 66, 2, 1),
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(128, 66, 1, 1),
            ],
            "v6 skipped, capped at 3"
        );
        assert!(resolv_conf_servers("").is_empty());
    }

    fn grant(name: &str, addr: &str, ttl: u32) -> DomainGrant {
        // Matches the now=1_000 planning clock used by the callers.
        DomainGrant {
            name: name.to_string(),
            addresses: vec![addr.parse().unwrap()],
            ttl: clamp_ttl(ttl),
            expires_at: 1_000 + u64::from(clamp_ttl(ttl)),
        }
    }

    #[test]
    fn refresh_planning_denies_empty_and_failed_without_prior() {
        let (policy, hash) = policy(&["a.example.com", "b.example.com"], &["128.66.0.0/24"]);
        let plan = plan_refresh(
            "sbx-1",
            &policy,
            &hash,
            None,
            vec![
                Err(ResolveDeny::empty(internal_error("nxdomain"))),
                Err(ResolveDeny::transient(internal_error("servfail"))),
            ],
            1_000,
        )
        .expect("plan");
        // Only the static CIDR remains; both domains are denied.
        assert_eq!(plan.destinations, vec!["128.66.0.0/24".to_string()]);
        assert!(plan.answers.is_empty());
        assert_eq!(plan.denied.len(), 2);
        assert_eq!(plan.state.published, render_dnsmasq_config(&[], 30));
        assert_eq!(plan.refresh_after, MIN_REFRESH_TTL_SECS);
    }

    #[test]
    fn transient_failure_keeps_only_unexpired_prior_grants() {
        let (policy, hash) = policy(&["a.example.com", "b.example.com"], &[]);
        let prior = SandboxDnsState {
            sandbox_id: "sbx-1".to_string(),
            policy_hash: hash.clone(),
            grants: vec![
                DnsGrantEntry {
                    name: "a.example.com".to_string(),
                    addresses: vec!["128.66.0.7".to_string()],
                    ttl: 120,
                    expires_at: 1_000 + 120, // 120s left: kept
                    generation: 0,
                },
                DnsGrantEntry {
                    name: "b.example.com".to_string(),
                    addresses: vec!["128.66.0.8".to_string()],
                    ttl: 40,
                    expires_at: 1_000 + 10, // inside the churn floor: dropped
                    generation: 0,
                },
            ],
            published: String::new(),
            generations: std::collections::BTreeMap::new(),
        };
        let plan = plan_refresh(
            "sbx-1",
            &policy,
            &hash,
            Some(&prior),
            vec![
                Err(ResolveDeny::transient(internal_error("servfail"))),
                Err(ResolveDeny::transient(internal_error("servfail"))),
            ],
            1_000,
        )
        .expect("plan");
        assert_eq!(
            plan.answers,
            vec![(
                "a.example.com".to_string(),
                vec![Ipv4Addr::new(128, 66, 0, 7)]
            )]
        );
        assert_eq!(plan.destinations, vec!["128.66.0.7/32".to_string()]);
        assert_eq!(
            plan.denied,
            vec![(
                "b.example.com".to_string(),
                "internal: servfail".to_string()
            )]
        );
    }

    #[test]
    fn empty_answers_deny_even_with_an_unexpired_prior_grant() {
        let (policy, hash) = policy(&["a.example.com"], &[]);
        let prior = SandboxDnsState {
            sandbox_id: "sbx-1".to_string(),
            policy_hash: hash.clone(),
            grants: vec![DnsGrantEntry {
                name: "a.example.com".to_string(),
                addresses: vec!["128.66.0.7".to_string()],
                ttl: 300,
                expires_at: 1_000 + 300,
                generation: 0,
            }],
            published: String::new(),
            generations: std::collections::BTreeMap::new(),
        };
        let plan = plan_refresh(
            "sbx-1",
            &policy,
            &hash,
            Some(&prior),
            vec![Err(ResolveDeny::empty(internal_error("nxdomain")))],
            1_000,
        )
        .expect("plan");
        assert!(plan.answers.is_empty(), "NXDOMAIN removes live grants now");
        assert!(plan.destinations.is_empty());
        assert_eq!(plan.denied.len(), 1);
    }

    #[test]
    fn refresh_after_tracks_the_soonest_expiry_within_the_clamp() {
        let (policy, hash) = policy(&["a.example.com", "b.example.com"], &[]);
        let plan = plan_refresh(
            "sbx-1",
            &policy,
            &hash,
            None,
            vec![
                Ok(grant("a.example.com", "128.66.0.7", 45)),
                Ok(grant("b.example.com", "128.66.1.9", 240)),
            ],
            1_000,
        )
        .expect("plan");
        assert_eq!(plan.refresh_after, 45);
        assert_eq!(plan.destinations.len(), 2);
        assert!(
            plan.state
                .published
                .contains("host-record=a.example.com,128.66.0.7")
        );
        assert!(plan.state.published.contains("local-ttl=0"));
    }

    #[test]
    fn render_publishes_only_exact_allowlisted_names() {
        let rendered = render_dnsmasq_config(
            &[(
                "grants.example.com".to_string(),
                vec![Ipv4Addr::new(128, 66, 0, 7), Ipv4Addr::new(128, 66, 0, 8)],
            )],
            120,
        );
        assert!(rendered.contains("no-resolv\n"), "{rendered}");
        assert!(rendered.contains("local-ttl=0\n"));
        // One directive per name/address pair: the installed dnsmasq manual
        // documents a single IPv4 address per host-record; repeated
        // directives carry the rest.
        assert_eq!(
            rendered.matches("host-record=").count(),
            2,
            "one exact-name record per address: {rendered}"
        );
        assert!(rendered.contains("host-record=grants.example.com,128.66.0.7\n"));
        assert!(rendered.contains("host-record=grants.example.com,128.66.0.8\n"));
        assert!(!rendered.contains("address="), "no wildcard directive");
        // The published name is local for itself only (other types NODATA,
        // not REFUSED); its subdomains fall through like any unlisted name.
        assert!(
            rendered.ends_with("local=/grants.example.com/\nserver=/*.grants.example.com/#\n"),
            "{rendered}"
        );
        assert_eq!(rendered.matches("local=").count(), 1, "{rendered}");
        assert!(
            rendered
                .lines()
                .filter(|line| line.starts_with("server="))
                .all(|line| line == "server=/*.grants.example.com/#"),
            "no upstream resolver: {rendered}"
        );
        // Incus's own local domain already answers NODATA/NXDOMAIN.
        let incus = render_dnsmasq_config(
            &[("api.incus".to_string(), vec![Ipv4Addr::new(128, 66, 0, 7)])],
            120,
        );
        assert!(!incus.contains("local="), "{incus}");
        assert!(!incus.contains("server="), "{incus}");
        let lookalike = render_dnsmasq_config(
            &[(
                "api.notincus".to_string(),
                vec![Ipv4Addr::new(128, 66, 0, 7)],
            )],
            120,
        );
        assert!(lookalike.contains("local=/api.notincus/\n"), "{lookalike}");
        // A name without published addresses stays unlisted.
        let empty = render_dnsmasq_config(&[("gone.example.com".to_string(), Vec::new())], 120);
        assert_eq!(empty, base_dnsmasq_config());
        // The base (deny-all) config is the empty render.
        assert_eq!(
            base_dnsmasq_config(),
            render_dnsmasq_config(&[], MAX_REFRESH_TTL_SECS)
        );
        assert!(base_dnsmasq_config().contains("no-resolv"));
    }

    fn state_client() -> (IncusClient, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "wssp-dns-state-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let mut client = IncusClient::new("true", "default");
        client.state_dir = Some(dir.clone());
        (client, dir)
    }

    /// E-16 (G8-R3): the append-only withdrawal-evidence log is created
    /// owner-only (0600) like every other host-state record, even under a
    /// permissive umask (002, Ubuntu's default), and later appends keep it
    /// so. The umask is process-wide, so the check runs in a child test
    /// process started under `umask 002`.
    #[cfg(unix)]
    #[test]
    fn withdrawal_evidence_log_is_created_owner_only_under_umask_002() {
        use std::os::unix::fs::PermissionsExt;
        const CHILD: &str = "WSSP_E16_EVIDENCE_LOG_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let (client, dir) = state_client();
            std::fs::create_dir_all(client.dns_revocations_dir()).unwrap();
            client
                .record_withdrawal_evidence("sbx-1", "wssp-dns-allow-1", "128.66.0.7/32")
                .expect("first proof");
            client
                .record_withdrawal_evidence("sbx-1", "wssp-dns-allow-2", "128.66.0.8/32")
                .expect("appended proof");
            let path = client.dns_withdrawal_evidence_log_path("sbx-1");
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
            let body = std::fs::read_to_string(&path).unwrap();
            let _ = std::fs::remove_dir_all(&dir);
            assert_eq!(mode, 0o600, "withdrawal evidence log {}", path.display());
            assert_eq!(
                body,
                "wssp-dns-allow-1 128.66.0.7/32\nwssp-dns-allow-2 128.66.0.8/32\n"
            );
            return;
        }
        let output = std::process::Command::new("/bin/sh")
            .args(["-c", "umask 002 && exec \"$@\"", "sh"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "incus::dns::tests::withdrawal_evidence_log_is_created_owner_only_under_umask_002",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "child failed: {:?}\nstdout:\n{stdout}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn dns_state_roundtrips_and_rejects_foreign_or_tampered_records() {
        let (client, dir) = state_client();
        let (_policy, hash) = policy(&["a.example.com"], &[]);
        let state = SandboxDnsState {
            sandbox_id: "sbx-1".to_string(),
            policy_hash: hash.clone(),
            grants: vec![DnsGrantEntry {
                name: "a.example.com".to_string(),
                addresses: vec!["128.66.0.7".to_string()],
                ttl: 300,
                expires_at: 999_999,
                generation: 0,
            }],
            published: "no-resolv\n".to_string(),
            generations: std::collections::BTreeMap::new(),
        };
        client.persist_dns_state(&state).expect("persist");
        let loaded = client.load_dns_state("sbx-1", &hash).expect("load");
        assert_eq!(loaded.grants.len(), 1);
        // Hash mismatch (a different policy) never reuses.
        assert!(client.load_dns_state("sbx-1", "00").is_none());
        // Foreign sandbox id never loads.
        assert!(client.load_dns_state("sbx-2", &hash).is_none());
        // A rebound address in the record is never trusted.
        let mut tampered = state.clone();
        tampered.grants[0].addresses = vec!["169.254.169.254".to_string()];
        client
            .persist_dns_state(&tampered)
            .expect("persist tampered");
        assert!(client.load_dns_state("sbx-1", &hash).is_none());
        // Corrupt JSON fails closed.
        std::fs::write(client.dns_state_path("sbx-1"), "{nope").unwrap();
        assert!(client.load_dns_state("sbx-1", &hash).is_none());
        // Expected config falls back to the deny-all base without state.
        assert_eq!(
            client.expected_dnsmasq_config("sbx-1"),
            base_dnsmasq_config()
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}

#[cfg(test)]
mod persisted_dns_shape_tests {
    use super::*;

    #[test]
    fn incomplete_dns_records_and_identity_free_fences_are_rejected() {
        let grant = serde_json::json!({"name":"example.com","addresses":["203.0.113.1"],"ttl":60,"expires_at":1000,"generation":1});
        for field in ["ttl", "generation"] {
            let mut missing = grant.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<DnsGrantEntry>(missing).is_err());
        }
        let state = serde_json::json!({"sandbox_id":"sbx","policy_hash":"hash","grants":[],"published":"","generations":{}});
        let mut missing = state.clone();
        missing.as_object_mut().unwrap().remove("generations");
        assert!(serde_json::from_value::<SandboxDnsState>(missing).is_err());
        assert!(
            serde_json::from_value::<StandingFence>(serde_json::json!("203.0.113.1/32")).is_err()
        );
        let record = serde_json::json!({"sandbox_id":"sbx","policy_hash":"hash","project":"default","revoked":[],"revoked_generations":{},"pending":[],"next_request":1,"standing_fences":[],"refresh_owed":false,"published_attempts":[]});
        assert!(serde_json::from_value::<DnsRevocationRecord>(record.clone()).is_ok());
        for field in [
            "project",
            "revoked_generations",
            "pending",
            "next_request",
            "standing_fences",
            "refresh_owed",
            "published_attempts",
        ] {
            let mut missing = record.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<DnsRevocationRecord>(missing).is_err(),
                "{field}"
            );
        }
        for project in [serde_json::Value::Null, serde_json::json!("")] {
            let mut invalid = record.clone();
            invalid["project"] = project;
            assert!(serde_json::from_value::<DnsRevocationRecord>(invalid).is_err());
        }
        let obligations = serde_json::json!({"sandbox_id":"sbx","entries":[]});
        assert!(serde_json::from_value::<DnsLeaseObligations>(obligations).is_err());
    }
}
