//! Per-sandbox bridge network + ACL plan compiled from the recorded egress
//! policy (M5, C35). The host re-validates the server-normalized policy and
//! fails closed: IPv6 grants, malformed CIDRs, protected destinations or a
//! policy/hash mismatch all refuse the launch instead of degrading to an
//! unenforced VM. Bridge ACLs are stateful on Incus >= 6.0, so allowed
//! outbound connections receive their established replies while both default
//! actions stay `drop`.

use std::net::{IpAddr, Ipv4Addr};

use sandbox_protocol::{EgressMode, EgressPolicy, SandboxErrorCode};

use crate::RuntimeError;
use crate::egress::{EgressRefusal, EgressSettings};

/// Bridge names are Linux interface names, so they must fit IFNAMSIZ (15
/// characters): `wsn-` plus 10 hex chars of the sandbox-id digest = 14.
pub(crate) const NETWORK_NAME_PREFIX: &str = "wsn-";
/// ACL names are Incus objects, not interfaces; they share the digest suffix.
pub(crate) const ACL_NAME_PREFIX: &str = "wssp-acl-";
/// Linux IFNAMSIZ leaves 15 usable characters for an interface name.
pub(crate) const MAX_INTERFACE_NAME: usize = 15;
/// Ownership tag on the managed network and ACL; verified before every
/// mutation so one sandbox's plan can never address another sandbox's rules.
pub(crate) const NETWORK_SANDBOX_TAG: &str = "user.wssp.sandbox_id";
/// Per-apply incarnation marker stamped on the network and ACL config. A
/// durable cleanup record is fenced by this marker: a drain only tears down
/// the exact attempt that incurred the obligation, never a network a later
/// create retry rebuilt.
pub(crate) const NETWORK_ATTEMPT_TAG: &str = "user.wssp.attempt";
/// Owning-project tag on the managed network and ACL. Dedicated projects
/// without network isolation inherit the default project's networks, so the
/// sandbox tag alone cannot prove this daemon's project owns the object:
/// discovery, recovery and cleanup only consider resources stamped with the
/// client's project. A missing project tag never proves ownership.
pub(crate) const NETWORK_PROJECT_TAG: &str = "user.wssp.project";

// Mirrors `packages/sandbox-contracts/src/egress.ts` bounds.
pub(crate) const MAX_POLICY_DOMAINS: usize = 128;
const MAX_POLICY_CIDRS: usize = 128;
/// Bound on total grant destinations after domain resolution.
pub(crate) const MAX_GRANT_DESTINATIONS: usize = 512;
/// Bound on emitted (name, address) grant RECORDS — distinct from the
/// destination bound because ACL rules and dnsmasq `host-record` lines scale
/// with name/address pairs, not unique addresses (many names may share
/// addresses). Planning, compile and persisted-state loading all enforce
/// THIS bound so a state refresh commits is never rejected at load time.
pub(crate) const MAX_GRANT_RECORDS: usize = 4096;

fn error(code: SandboxErrorCode, message: impl Into<String>) -> RuntimeError {
    RuntimeError::new(code, message)
}

fn protocol_error(message: impl Into<String>) -> RuntimeError {
    error(SandboxErrorCode::ProtocolError, message)
}

/// Deterministic per-sandbox network/ACL object names: the raw sandbox id is
/// never trusted as an Incus object name (charset), so both derive from its
/// SHA-256. Two sandboxes cannot collide on, or name, each other's objects.
/// The bridge name stays within Linux's 15-character interface limit.
pub fn sandbox_network_names(sandbox_id: &str) -> (String, String) {
    let digest = ring::digest::digest(&ring::digest::SHA256, sandbox_id.as_bytes());
    let hex: String = digest.as_ref()[..5]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let network = format!("{NETWORK_NAME_PREFIX}{hex}");
    debug_assert!(network.len() <= MAX_INTERFACE_NAME);
    (network, format!("{ACL_NAME_PREFIX}{hex}"))
}

/// One IPv4 CIDR grant destination, canonicalized (network base address).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GrantCidr {
    base: u32,
    prefix: u8,
    pub text: String,
}

impl GrantCidr {
    pub(crate) fn contains(&self, ip: Ipv4Addr) -> bool {
        let shift = 32 - u32::from(self.prefix);
        let mask = if shift == 32 { 0 } else { u32::MAX << shift };
        (u32::from(ip) & mask) == (self.base & mask)
    }
}

const fn u32_from(octets: [u8; 4]) -> u32 {
    u32::from_be_bytes(octets)
}

fn intersects(base: u32, prefix: u8, other_base: u32, other_prefix: u8) -> bool {
    let p = prefix.min(other_prefix);
    let shift = 32 - u32::from(p);
    let mask = if shift == 32 { 0 } else { u32::MAX << shift };
    (base & mask) == (other_base & mask)
}

pub(crate) fn parse_policy_cidr(raw: &str) -> Result<GrantCidr, RuntimeError> {
    if raw.is_empty()
        || raw.len() > 64
        || raw
            .bytes()
            .any(|b| b.is_ascii_control() || b == b' ' || b == b'%')
    {
        return Err(protocol_error("egress CIDR contains control characters"));
    }
    let (address, prefix_text) = raw
        .split_once('/')
        .filter(|(a, p)| !a.contains('/') && !p.contains('/'))
        .ok_or_else(|| protocol_error("egress CIDR must be address/prefix"))?;
    if prefix_text.is_empty()
        || (prefix_text.len() > 1 && prefix_text.starts_with('0'))
        || !prefix_text.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(protocol_error("egress CIDR prefix is not canonical"));
    }
    let prefix: u8 = prefix_text
        .parse()
        .map_err(|_| protocol_error("egress CIDR prefix is not canonical"))?;
    if address.contains(':') {
        // Sandbox bridges run IPv4-only (`ipv6.address=none` plus
        // `security.ipv6_filtering=true`); an IPv6 grant cannot be enforced,
        // so the launch fails closed instead of silently dropping the grant.
        return Err(error(
            SandboxErrorCode::UnsupportedCapability,
            "IPv6 egress grants are not enforceable on sandbox bridges",
        ));
    }
    let addr: Ipv4Addr = address
        .parse()
        .map_err(|_| protocol_error("egress CIDR address is not canonical IPv4"))?;
    if prefix > 32 {
        return Err(protocol_error("IPv4 CIDR prefix exceeds 32"));
    }
    let shift = 32 - u32::from(prefix);
    let mask = if shift == 32 { 0 } else { u32::MAX << shift };
    let base = u32::from(addr) & mask;
    if base != u32::from(addr) {
        return Err(protocol_error(
            "egress CIDR is not the network base address",
        ));
    }
    // The sandbox protected set is read from the shared contract fixture
    // (`sandboxProtectedV4`): the same table the control plane refuses
    // grants against. An unavailable table refuses every grant.
    for &(protected_base, protected_prefix) in crate::egress::sandbox_protected_v4()? {
        if intersects(base, prefix, protected_base, protected_prefix) {
            return Err(protocol_error(
                "egress CIDR intersects a protected destination range",
            ));
        }
    }
    Ok(GrantCidr {
        base,
        prefix,
        text: format!("{addr}/{prefix}"),
    })
}

/// Host-side re-validation of a normalized domain grant (exact ASCII DNS name,
/// no wildcards, no IP literals). Mirrors `normalizeDomain` post-conditions.
pub(crate) fn validate_policy_domain(domain: &str) -> Result<(), RuntimeError> {
    let valid = crate::egress::valid_domain_name(domain);
    if !valid {
        return Err(protocol_error("egress domain is not an exact DNS name"));
    }
    Ok(())
}

/// Canonical JSON text identical to `canonicalEgressPolicyJson`: one
/// implementation, `EgressPolicy::canonical_json()` (mode written only when
/// open, so allowlist hashes stay byte-identical).
fn canonical_policy_json(policy: &EgressPolicy) -> String {
    policy.canonical_json()
}

/// SHA-256 hex of the canonical policy JSON — the same digest the control
/// plane records as `egressPolicyHash`.
pub(crate) fn policy_hash_hex(policy: &EgressPolicy) -> String {
    let digest = ring::digest::digest(
        &ring::digest::SHA256,
        canonical_policy_json(policy).as_bytes(),
    );
    digest.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

fn verify_policy_hash(policy: &EgressPolicy, expected: &str) -> Result<(), RuntimeError> {
    let actual = policy_hash_hex(policy);
    if actual != expected {
        return Err(protocol_error(
            "egress policy hash does not match the recorded policy",
        ));
    }
    Ok(())
}

/// Bounds for policy compilation: an overall deadline and the worker's
/// cancellation permit. Compilation is CPU-trivial except for DNS, so the
/// deadline effectively bounds total resolution time; the permit is checked
/// before every lookup so a revoked worker resolves nothing further.
pub(crate) struct CompileLimits<'a> {
    pub deadline: std::time::Instant,
    pub cancelled: Option<&'a crate::RuntimePermit>,
}

impl CompileLimits<'_> {
    pub(crate) fn check(&self) -> Result<(), RuntimeError> {
        if let Some(permit) = self.cancelled {
            // Drop the guard immediately: no lock is held across IO.
            let _admitted = permit.admit()?;
        }
        if std::time::Instant::now() >= self.deadline {
            return Err(error(
                SandboxErrorCode::Timeout,
                "egress policy compilation exceeded its deadline",
            ));
        }
        Ok(())
    }
}

/// Overall budget for compiling one policy, dominated by DNS.
pub(crate) const COMPILE_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);
/// Per-lookup bound: `ToSocketAddrs` is blocking, so the lookup runs on a
/// helper thread and the worker stops waiting after this budget.
pub(crate) const PER_LOOKUP_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

/// Run one blocking name lookup with a hard wait bound. The lookup thread may
/// outlive the wait inside libc; it is detached and its answer is discarded,
/// so the worker never blocks past `budget`.
pub(crate) fn bounded_lookup(
    sandbox: &str,
    domain: &str,
    budget: std::time::Duration,
) -> Result<Vec<IpAddr>, RuntimeError> {
    resolver_pool()?.lookup(sandbox, domain, budget)
}

/// Bounded resolver executor. `getaddrinfo` cannot be cancelled, so a
/// caller-side timeout alone would leak one detached thread per stalled
/// lookup until thread creation itself panics. Instead lookups run on a
/// fixed set of worker threads fed by a bounded queue: a slot is retained
/// until the lookup ACTUALLY finishes, and once every slot is occupied by
/// stalled work, further lookups fail fast instead of growing without
/// bound. Thread-creation failure surfaces as an error, never a panic.
const RESOLVER_SLOTS: usize = 4;

type ResolveReply = std::sync::mpsc::Sender<Result<Vec<IpAddr>, std::io::Error>>;
type ResolveJob = (String, ResolveReply, ResolverSlot);

/// Retained by queued/running work, never by the caller's wait. A timed-out
/// libc lookup therefore still consumes this sandbox's sole in-flight slot.
#[derive(Debug)]
struct ResolverSlot {
    sandbox: String,
    owners: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
}

impl Drop for ResolverSlot {
    fn drop(&mut self) {
        self.owners
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .remove(&self.sandbox);
    }
}

#[derive(Debug)]
pub(crate) struct ResolverPool {
    tx: std::sync::mpsc::SyncSender<ResolveJob>,
    owners: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
}

type ResolveImpl = std::sync::Arc<dyn Fn(&str) -> std::io::Result<Vec<IpAddr>> + Send + Sync>;

impl ResolverPool {
    pub(crate) fn new(slots: usize) -> std::io::Result<Self> {
        Self::with_resolver(
            slots,
            std::sync::Arc::new(|name| {
                use std::net::ToSocketAddrs;
                (name, 443)
                    .to_socket_addrs()
                    .map(|addrs| addrs.map(|addr| addr.ip()).collect::<Vec<_>>())
            }),
        )
    }

    pub(super) fn with_resolver(slots: usize, resolve: ResolveImpl) -> std::io::Result<Self> {
        let (tx, rx) = std::sync::mpsc::sync_channel::<ResolveJob>(slots);
        let rx = std::sync::Arc::new(std::sync::Mutex::new(rx));
        for _ in 0..slots {
            let worker_rx = rx.clone();
            let resolve = resolve.clone();
            std::thread::Builder::new()
                .name("wssp-dns-resolver".to_string())
                .spawn(move || {
                    loop {
                        let job = worker_rx
                            .lock()
                            .unwrap_or_else(|err| err.into_inner())
                            .recv();
                        let Ok((name, reply, slot)) = job else {
                            return;
                        };
                        let result = resolve(&name);
                        drop(slot);
                        let _ = reply.send(result);
                    }
                })?;
        }
        Ok(Self {
            tx,
            owners: Default::default(),
        })
    }

    pub(crate) fn lookup(
        &self,
        sandbox: &str,
        domain: &str,
        budget: std::time::Duration,
    ) -> Result<Vec<IpAddr>, RuntimeError> {
        let (tx, rx) = std::sync::mpsc::channel();
        self.submit(sandbox, domain, tx)?;
        match rx.recv_timeout(budget) {
            Ok(Ok(addrs)) => Ok(addrs),
            Ok(Err(err)) => Err(error(
                SandboxErrorCode::Internal,
                format!("egress domain `{domain}` did not resolve: {err}"),
            )),
            Err(_) => Err(error(
                SandboxErrorCode::Timeout,
                format!("egress domain `{domain}` did not resolve within {budget:?}"),
            )),
        }
    }

    /// Queue one lookup. Fails fast (Timeout) when every worker and queue
    /// slot is occupied by still-running lookups: the caller's wait budget
    /// never implies the work is gone.
    fn submit(&self, sandbox: &str, domain: &str, reply: ResolveReply) -> Result<(), RuntimeError> {
        if !self
            .owners
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .insert(sandbox.to_owned())
        {
            return Err(error(
                SandboxErrorCode::Timeout,
                format!("sandbox `{sandbox}` already has an in-flight DNS lookup"),
            ));
        }
        let slot = ResolverSlot {
            sandbox: sandbox.to_owned(),
            owners: self.owners.clone(),
        };
        self.tx
            .try_send((domain.to_string(), reply, slot))
            .map_err(|_| {
                error(
                    SandboxErrorCode::Timeout,
                    format!(
                        "egress domain `{domain}` cannot be scheduled: the resolver is saturated with stalled lookups"
                    ),
                )
            })
    }
}

fn resolver_pool() -> Result<&'static ResolverPool, RuntimeError> {
    static POOL: std::sync::OnceLock<Result<ResolverPool, String>> = std::sync::OnceLock::new();
    POOL.get_or_init(|| {
        ResolverPool::new(RESOLVER_SLOTS)
            .map_err(|err| format!("cannot spawn resolver workers: {err}"))
    })
    .as_ref()
    .map_err(|err| error(SandboxErrorCode::Internal, err.clone()))
}

/// Incus ACL directions are relative to the instance NIC, NOT the network:
/// `ingress` is traffic towards the instance, `egress` is traffic leaving it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum AclDirection {
    /// Towards the instance NIC (replies and infrastructure answers).
    Ingress,
    /// Leaving the instance NIC (guest-initiated requests).
    Egress,
}

impl AclDirection {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Ingress => "ingress",
            Self::Egress => "egress",
        }
    }
}

/// Rule action. Plans are allow-based plus narrow `reject` companions: deny
/// in the large is never a rule but the network's default action for both
/// directions, so a plan can never express an unrestricted fallback. Incus
/// orders rules drop > reject > allow regardless of list order (installed
/// howto/network_acls.md), so a reject companion narrows an allow without
/// any ordering constraint.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum AclAction {
    #[default]
    Allow,
    Reject,
}

impl AclAction {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Reject => "reject",
        }
    }
}

/// One ACL rule. `action` defaults to `allow` so pre-C36 persisted plans
/// decode unchanged.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct AclRule {
    #[serde(default)]
    pub action: AclAction,
    pub direction: AclDirection,
    pub protocol: Option<String>,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub source_port: Option<String>,
    pub destination_port: Option<String>,
    pub description: String,
}

impl AclRule {
    /// `incus network acl rule add <acl> <direction> key=value ...` tail.
    pub(crate) fn cli_args(&self) -> Vec<String> {
        let mut args = vec![format!("action={}", self.action.as_str())];
        if let Some(protocol) = &self.protocol {
            args.push(format!("protocol={protocol}"));
        }
        if let Some(source) = &self.source {
            args.push(format!("source={source}"));
        }
        if let Some(destination) = &self.destination {
            args.push(format!("destination={destination}"));
        }
        if let Some(port) = &self.source_port {
            args.push(format!("source_port={port}"));
        }
        if let Some(port) = &self.destination_port {
            args.push(format!("destination_port={port}"));
        }
        args.push(format!("description={}", self.description));
        args
    }
}

/// The full instance binding (`bind_instance` tuple) expected of the VM a
/// plan provisions: persisted with the provisioning intent so restart
/// recovery applies the SAME authorization (template fingerprint, base
/// image, create key) before repairing or adopting an existing VM — the
/// normal create path rejects such VMs, and recovery must too.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct PlanBinding {
    pub template_fingerprint: String,
    pub create_key: Option<String>,
}

/// One domain grant resolved during compilation: the name and its validated
/// public IPv4 answers. Carried on the plan so the apply can publish the
/// initial guest-facing DNS answers (C36); empty on the immutable
/// persisted-expansion reuse path (the previously published answers persist).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedDomain {
    pub name: String,
    pub addresses: Vec<Ipv4Addr>,
}

/// Deterministic ACL rule description tag for one domain's DNS-managed grant
/// rules: refresh diffs dynamic rules by it, and two sandboxes' tags can
/// never collide on one ACL because the ACL itself is per-sandbox.
pub(crate) fn dns_rule_tag(domain: &str, generation: u64) -> String {
    let hex = dns_tag_hex(domain);
    // Every generation, including the compile-time generation zero, has an
    // explicit request identity. A stale apply cannot become a newer grant.
    format!("wssp-dns-g{generation}-{hex}")
}

/// The 32-bit truncated name hash shared by every tag for one domain
/// (C36): two domain names colliding here share every generation-scoped
/// identity too, so planning rejects the collision before any mutation
/// (C36 r20 F2). `pub(crate)` so tests can search for colliding names.
pub(crate) fn dns_tag_hex(seed: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, seed.as_bytes());
    digest.as_ref()[..4]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The request identity carried by a generation-scoped tag, if any
/// (`wssp-dns-g<N>-…`, `wssp-dns-reject-g<N>-…`, `wssp-dns-quarantine-g<N>-…`).
pub(crate) fn dns_tag_request_id(description: &str) -> Option<u64> {
    let rest = description.strip_prefix("wssp-dns-")?;
    let rest = rest
        .strip_prefix("reject-")
        .or_else(|| rest.strip_prefix("quarantine-"))
        .unwrap_or(rest);
    let tail = rest.strip_prefix('g')?;
    let (generation, _) = tail.split_once('-')?;
    generation.parse().ok()
}

/// DNS/DoT reject companions carry their allow's generation, so a deferred
/// removal of a superseded companion cannot remove the current companion.
pub(crate) fn dns_rule_reject_tag(domain: &str, generation: u64) -> String {
    format!("wssp-dns-reject-g{generation}-{}", dns_tag_hex(domain))
}

/// Fence (quarantine) tag for a DESTINATION under an unresolved broadening
/// mutation (C36 r17): destination-scoped — one fence covers the address
/// whichever domain's request it protects — and request-unique: the epoch
/// is allocated from the durable marker counter, so a deferred daemon-side
/// removal of a superseded fence can never remove a newer one (C36 r17 F4).
/// Epochs start at 1 and every fence includes its explicit epoch.
pub(crate) fn dns_fence_tag(destination: &str, epoch: u64) -> String {
    format!("wssp-dns-quarantine-g{epoch}-{}", dns_tag_hex(destination))
}

/// Fence tag family for fences the EXPIRY LEASE installs (C36 r18 F1):
/// the lease cannot take the sandbox lock (it must fire while a refresh
/// stalls holding it) and therefore cannot allocate epochs from the
/// refresh's marker-counter read-modify-write. Its epochs come from a
/// separate durable lease counter under the lease owner lock; the distinct
/// family keeps the two epoch namespaces collision-free, so a deferred
/// daemon-side removal journaled against a refresh-installed fence can
/// never strike a lease-installed one (and vice versa).
pub(crate) fn dns_lease_fence_tag(destination: &str, epoch: u64) -> String {
    format!(
        "wssp-dns-lease-quarantine-g{epoch}-{}",
        dns_tag_hex(destination)
    )
}

/// True only for LEASE-installed fence tags (C36 r18): the readback
/// tolerance treats a lease-installed fence appearing mid-pass as the
/// lease's own deny-direction work, while an unexpected refresh-family
/// fence remains a hard mismatch.
pub(crate) fn is_dns_lease_fence_tag(description: &str) -> bool {
    description
        .strip_prefix("wssp-dns-lease-quarantine-")
        .and_then(|rest| rest.strip_prefix('g'))
        .and_then(|tail| tail.split_once('-'))
        .is_some_and(|(epoch, tag)| {
            !epoch.is_empty()
                && epoch.bytes().all(|b| b.is_ascii_digit())
                && tag.len() == 8
                && tag
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

/// The epoch carried by a LEASE-installed fence tag
/// (`wssp-dns-lease-quarantine-g<N>-<hex(destination)>), if any. The
/// durable lease counter is the high-water mark of allocated epochs, so a
/// canonical lease fence whose epoch exceeds it was never allocated by
/// this host's lease — drift the settlement derivation must not carry
/// (C36 r20 F1).
pub(crate) fn dns_lease_fence_epoch(description: &str) -> Option<u64> {
    description
        .strip_prefix("wssp-dns-lease-quarantine-")?
        .strip_prefix('g')?
        .split_once('-')?
        .0
        .parse()
        .ok()
}

/// True for fence (destination-wide quarantine) tags, any epoch and either
/// family (refresh-installed and lease-installed).
pub(crate) fn is_dns_fence_tag(description: &str) -> bool {
    let rest = if let Some(rest) = description.strip_prefix("wssp-dns-quarantine-") {
        rest
    } else if let Some(rest) = description.strip_prefix("wssp-dns-lease-quarantine-") {
        rest
    } else {
        return false;
    };
    let hex8 = |tag: &str| {
        tag.len() == 8
            && tag
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    rest.strip_prefix('g')
        .and_then(|tail| tail.split_once('-'))
        .is_some_and(|(epoch, tag)| {
            !epoch.is_empty() && epoch.bytes().all(|b| b.is_ascii_digit()) && hex8(tag)
        })
}

/// True only for generation-qualified DNS-managed grant, reject and fence
/// descriptions, each ending in an eight-character lowercase hex hash.
/// The bridge DNS infrastructure rules `wssp-dns-udp`/`wssp-dns-tcp`
/// are NOT dynamic — a prefix match would misclassify (and a refresh would
/// delete) them.
pub(crate) fn is_dns_dynamic_tag(description: &str) -> bool {
    fn hex8(rest: &str) -> bool {
        rest.len() == 8
            && rest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
    let Some(rest) = description.strip_prefix("wssp-dns-") else {
        return false;
    };
    let generation_rule = |tag: &str| {
        tag.strip_prefix('g')
            .and_then(|tail| tail.split_once('-'))
            .is_some_and(|(generation, tag)| {
                !generation.is_empty()
                    && generation.bytes().all(|b| b.is_ascii_digit())
                    && hex8(tag)
            })
    };
    generation_rule(rest)
        || rest.strip_prefix("reject-").is_some_and(generation_rule)
        || rest
            .strip_prefix("quarantine-")
            .is_some_and(generation_rule)
        || rest
            .strip_prefix("lease-quarantine-")
            .is_some_and(generation_rule)
}

/// The egress rules one resolved domain address contributes: one `allow`
/// (any protocol/port) plus — unless an explicit static CIDR grant already
/// covers the address (which preserves direct DNS/DoT as granted) — `reject`
/// companions for DNS and DoT (udp/53, tcp/53, tcp/853). Reject outranks
/// allow in Incus, so the narrow rules close the resolver hole while every
/// other port stays allowed. The rejects come FIRST: rule application runs
/// in this order, and an interrupted install must never leave the
/// unrestricted allow in place without its companions.
pub(crate) fn domain_grant_rules(
    domain: &str,
    addr: Ipv4Addr,
    static_grants: &[GrantCidr],
    generation: u64,
) -> Vec<AclRule> {
    let destination = format!("{addr}/32");
    let mut rules = Vec::new();
    if !static_grants.iter().any(|grant| grant.contains(addr)) {
        let reject_tag = dns_rule_reject_tag(domain, generation);
        for (protocol, port) in [("udp", "53"), ("tcp", "53"), ("tcp", "853")] {
            rules.push(AclRule {
                action: AclAction::Reject,
                direction: AclDirection::Egress,
                protocol: Some(protocol.to_string()),
                source: None,
                destination: Some(destination.clone()),
                source_port: None,
                destination_port: Some(port.to_string()),
                description: reject_tag.clone(),
            });
        }
    }
    rules.push(AclRule {
        action: AclAction::Allow,
        direction: AclDirection::Egress,
        protocol: None,
        source: None,
        destination: Some(destination),
        source_port: None,
        destination_port: None,
        description: dns_rule_tag(domain, generation),
    });
    rules
}

/// The fence rule covering a destination under an unresolved broadening
/// mutation (C36 r15, destination-scoped and epoch-tagged since r17): a
/// DESTINATION-WIDE reject (every protocol/port). The DNS/DoT companion
/// rejects close only the resolver hole; a delayed daemon-side allow would
/// otherwise open TCP/443 and every other port past expiry. Reject outranks
/// allow in Incus, so the fenced destination stays denied until the pending
/// mutation is definitively reconciled.
pub(crate) fn domain_fence_rule(addr: Ipv4Addr, epoch: u64) -> AclRule {
    let destination = format!("{addr}/32");
    AclRule {
        action: AclAction::Reject,
        direction: AclDirection::Egress,
        protocol: None,
        source: None,
        destination: Some(destination.clone()),
        source_port: None,
        destination_port: None,
        description: dns_fence_tag(&destination, epoch),
    }
}

/// The lease-installed counterpart of `domain_fence_rule` (C36 r18 F1):
/// identical shape, lease tag family (see `dns_lease_fence_tag`).
pub(crate) fn domain_lease_fence_rule(addr: Ipv4Addr, epoch: u64) -> AclRule {
    let destination = format!("{addr}/32");
    AclRule {
        action: AclAction::Reject,
        direction: AclDirection::Egress,
        protocol: None,
        source: None,
        destination: Some(destination.clone()),
        source_port: None,
        destination_port: None,
        description: dns_lease_fence_tag(&destination, epoch),
    }
}

/// Everything the host applies for one sandbox's network enforcement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SandboxNetworkPlan {
    pub sandbox_id: String,
    pub binding: Option<PlanBinding>,
    pub network_name: String,
    pub acl_name: String,
    /// Bridge gateway address; the sandbox's DHCP/DNS service point.
    pub gateway: Ipv4Addr,
    pub grants: Vec<GrantCidr>,
    pub rules: Vec<AclRule>,
    /// Recorded policy hash this plan was compiled for. Persisted with the
    /// resolved expansion so reconnects reuse it immutably (DNS answers may
    /// legitimately rotate under an unchanged policy).
    pub policy_hash: Option<String>,
    /// Domains of the recorded policy (for expansion persistence).
    pub policy_domains: Vec<String>,
    /// CIDRs of the recorded policy (for expansion persistence).
    pub policy_cidrs: Vec<String>,
    /// Per-domain resolutions captured at compile time (C36 initial publish).
    pub resolved_domains: Vec<ResolvedDomain>,
    /// Effective egress mode the plan was compiled for (§2.1). Recorded.
    pub mode: EgressMode,
    /// Node settings captured during materialization. Pure compile-time plans
    /// may omit them; a persisted enforcement plan requires them.
    pub settings: Option<EgressSettings>,
    /// The `raw.dnsmasq` body this sandbox's bridge must carry while no DNS
    /// publication state exists (§2.2): the open-mode resolver, or the
    /// allowlist base plus `local=/<blocked>/` lines. Recorded.
    pub dnsmasq_base: String,
    /// Allowlist grant names refused by the node's domain blocklist (M19):
    /// never resolved, never allowed, never published. Recorded.
    pub denied_grants: Vec<String>,
}

/// Which rule set a verifier compares the live ACL against (§2.6, M3).
impl SandboxNetworkPlan {
    /// Rebind only bridge infrastructure after collision checking under the
    /// daemon allocation lock. User grants and resolved DNS identities stay intact.
    pub(crate) fn set_gateway(&mut self, gateway: Ipv4Addr) {
        self.gateway = gateway;
        for rule in &mut self.rules {
            match rule.description.as_str() {
                "wssp-dns-udp" | "wssp-dns-tcp" | CREDENTIAL_PROXY_RULE_TAG => {
                    rule.destination = Some(format!("{gateway}/32"));
                }
                "wssp-dhcp-reply" | "wssp-dns-udp-reply" | "wssp-dns-tcp-reply" => {
                    rule.source = Some(format!("{gateway}/32"));
                }
                _ => {}
            }
        }
    }

    /// Ordered `key=value` config for `incus network create`. Dedicated bridge,
    /// IPv4 NAT, IPv6 fully disabled, ACL attached, both defaults `drop`.
    pub(crate) fn network_config(&self) -> Vec<(String, String)> {
        vec![
            ("ipv4.address".into(), format!("{}/24", self.gateway)),
            ("ipv4.nat".into(), "true".into()),
            // Advertise only this bridge's policy resolver over DHCP, regardless
            // of daemon defaults or the image's prior network lease.
            ("dns.nameservers".into(), self.gateway.to_string()),
            ("ipv6.address".into(), "none".into()),
            ("security.acls".into(), self.acl_name.clone()),
            ("security.acls.default.ingress.action".into(), "drop".into()),
            ("security.acls.default.egress.action".into(), "drop".into()),
            // C36: the bridge resolver serves ONLY host-published answers for
            // allowlisted names (no upstream resolvers) from first boot; the
            // refresh loop rewrites this with host-record lines.
            ("raw.dnsmasq".into(), super::dns::base_dnsmasq_config()),
            (NETWORK_SANDBOX_TAG.into(), self.sandbox_id.clone()),
        ]
    }

    /// The pinned NIC as `key=value` arguments, installed post-init as a
    /// COMPLETE local device (`config device add`) and used by repair.
    /// Only options supported by BRIDGED NICs are set: per the installed
    /// Incus 6.0.0 documentation (devices_nic.md, "nictype: bridged"),
    /// `security.acls*` are OVN-NIC-only options and a supported host REJECTS
    /// them on a bridged NIC — the deny-default ACL actions live on the
    /// bridge network itself (network_config), where they are supported.
    pub(crate) fn nic_device_args(&self) -> Vec<String> {
        [
            format!("network={}", self.network_name),
            "security.mac_filtering=true".to_string(),
            "security.ipv4_filtering=true".to_string(),
            "security.ipv6_filtering=true".to_string(),
            "security.port_isolation=true".to_string(),
        ]
        .into_iter()
        .collect()
    }
}

/// The enforcement identity expected of any VM recovered for this sandbox:
/// the dedicated bridge/ACL names are deterministic in the sandbox id, so
/// restart recovery can verify networking without the recorded policy. Only
/// the device identity (bridge + pinned NIC) is compared; the gateway and
/// rules are irrelevant placeholders here.
pub(crate) fn enforcement_identity_plan(sandbox_id: &str) -> SandboxNetworkPlan {
    let (network_name, acl_name) = sandbox_network_names(sandbox_id);
    SandboxNetworkPlan {
        sandbox_id: sandbox_id.to_string(),
        binding: None,
        network_name,
        acl_name,
        gateway: Ipv4Addr::UNSPECIFIED,
        grants: Vec::new(),
        rules: Vec::new(),
        policy_hash: None,
        policy_domains: Vec::new(),
        policy_cidrs: Vec::new(),
        resolved_domains: Vec::new(),
        mode: EgressMode::Allowlist,
        settings: None,
        dnsmasq_base: super::dns::base_dnsmasq_config(),
        denied_grants: Vec::new(),
    }
}

/// Cheap fail-closed check that must run before any host IO: policy/hash
/// co-presence and the recorded hash. Full validation still happens in
/// `compile_network_plan`; this ordering keeps a forged policy from ever
/// reaching the daemon.
pub(crate) fn verify_policy_presence_and_hash(
    policy: Option<&EgressPolicy>,
    hash: Option<&str>,
) -> Result<(), RuntimeError> {
    match (policy, hash) {
        (Some(policy), Some(hash)) => {
            // The RECORDED policy's input bounds are validated here, before
            // any host IO. Compiled expansions are bounded separately (see
            // compile_network_plan): the persisted reuse path legitimately
            // merges recorded CIDRs with their domain expansion, so the
            // merged set is validated after dedup against the compiled
            // destination bound, not the input bound.
            if policy.domains.len() > MAX_POLICY_DOMAINS || policy.cidrs.len() > MAX_POLICY_CIDRS {
                return Err(protocol_error("egress policy exceeds host bounds"));
            }
            verify_policy_hash(policy, hash)
        }
        (None, None) => Ok(()),
        _ => Err(protocol_error(
            "VM launch requires the egress policy and its hash together",
        )),
    }
}

/// Injected domain resolver: the domain plus the wait budget clamped to the
/// remaining compilation deadline. Tests never perform DNS.
pub(crate) type DomainResolver<'a> =
    &'a dyn Fn(&str, std::time::Duration) -> Result<Vec<IpAddr>, RuntimeError>;

/// Compile the recorded egress policy into a host network plan. `None`/`None`
/// means deny-all (the server's no-policy default); exactly one of policy/hash
/// present is a producer bug and fails closed. `resolve` is injected so tests
/// never perform DNS. `gateway` is the collision-checked bridge address chosen
/// by the caller (see `allocate_gateway`); `limits` bounds DNS resolution.
/// Compiled with the production-default `EgressSettings`.
#[cfg(test)]
pub(crate) fn compile_network_plan(
    sandbox_id: &str,
    policy: Option<&EgressPolicy>,
    hash: Option<&str>,
    resolve: DomainResolver,
    gateway: Ipv4Addr,
    limits: &CompileLimits<'_>,
) -> Result<SandboxNetworkPlan, RuntimeError> {
    compile_network_plan_with(
        sandbox_id,
        policy,
        hash,
        &EgressSettings::default(),
        resolve,
        gateway,
        limits,
    )
}

#[cfg(test)]
pub(crate) fn compile_network_plan_with(
    sandbox_id: &str,
    policy: Option<&EgressPolicy>,
    hash: Option<&str>,
    settings: &EgressSettings,
    resolve: DomainResolver,
    gateway: Ipv4Addr,
    limits: &CompileLimits<'_>,
) -> Result<SandboxNetworkPlan, RuntimeError> {
    compile_network_plan_allocating(
        sandbox_id,
        policy,
        hash,
        settings,
        resolve,
        || Ok(gateway),
        limits,
    )
}

/// ACL rule description tags of the per-sandbox policy families (§2.1).
/// None sits in the `wssp-dns-` namespace the DNS refresh machinery owns.
pub(crate) const OPEN_RULE_TAG: &str = "wssp-open";
pub(crate) const SMTP_REJECT_TAG: &str = "wssp-smtp-reject";
pub(crate) const EXTERNAL_DNS_REJECT_TAG: &str = "wssp-extdns-reject";
/// CLI-logins proxy mode: guest → gateway:port TCP, a gateway
/// infrastructure allow. Like DNS it targets the gateway, so no `reject`
/// ever covers it (every reject is confined to `PUBLIC_V4`).
pub(crate) const CREDENTIAL_PROXY_RULE_TAG: &str = "wssp-credential-proxy";

/// G0 qualification switch (§2.1 "Shim check", risk 1): `true` emits each
/// `PUBLIC_V4` family as ONE rule with a comma-separated `destination` (and
/// `destination_port`), the plan default. If the live daemon normalizes the
/// lists, flip this to emit one rule per prefix from the same function.
const PUBLIC_V4_AS_COMMA_LIST: bool = true;

/// One `PUBLIC_V4` rule family: every rule in it carries a destination that
/// is a subset of `PUBLIC_V4`, hence disjoint from the protected set, the
/// bridge /24 and the gateway (the invariant `public_v4_invariant` checks).
fn public_v4_rules(
    action: AclAction,
    protocol: Option<&str>,
    port: Option<&str>,
    description: &str,
) -> Result<Vec<AclRule>, RuntimeError> {
    let rule = |destination: String| AclRule {
        action,
        direction: AclDirection::Egress,
        protocol: protocol.map(str::to_string),
        source: None,
        destination: Some(destination),
        source_port: None,
        destination_port: port.map(str::to_string),
        description: description.to_string(),
    };
    if PUBLIC_V4_AS_COMMA_LIST {
        Ok(vec![rule(
            crate::egress::sandbox_public_v4_text()?.to_string(),
        )])
    } else {
        Ok(crate::egress::sandbox_public_v4()?
            .iter()
            .map(|net| rule(crate::egress::format_ipv4_net(*net)))
            .collect())
    }
}

/// The node-setting reject families (§2.1 rows 2c and 2d), both modes.
/// Incus orders reject before allow, so they beat `wssp-open` and every
/// `wssp-grant` / domain allow, including a grant to a mail server.
fn setting_reject_rules(settings: &EgressSettings) -> Result<Vec<AclRule>, RuntimeError> {
    let mut rules = Vec::new();
    if settings.block_external_dns {
        for protocol in ["tcp", "udp"] {
            rules.extend(public_v4_rules(
                AclAction::Reject,
                Some(protocol),
                Some("53,853"),
                EXTERNAL_DNS_REJECT_TAG,
            )?);
        }
    }
    if settings.block_smtp {
        rules.extend(public_v4_rules(
            AclAction::Reject,
            Some("tcp"),
            Some("25"),
            SMTP_REJECT_TAG,
        )?);
    }
    Ok(rules)
}

/// Every CIDR in an ACL rule's destination list (comma-separated or single).
fn rule_destinations(rule: &AclRule) -> Option<Vec<crate::egress::Ipv4Net>> {
    rule.destination
        .as_deref()?
        .split(',')
        .map(crate::egress::parse_ipv4_net)
        .collect()
}

/// §2.1 invariant: every `reject` destination in a compiled plan is a subset
/// of `PUBLIC_V4`, hence disjoint from `SANDBOX_PROTECTED_V4`, the bridge /24
/// and the gateway: a reject can never override the gateway service allows
/// (Incus applies reject before allow). Checked on every compile.
pub(crate) fn public_v4_invariant(rules: &[AclRule]) -> Result<(), RuntimeError> {
    let public = crate::egress::sandbox_public_v4()?;
    for rule in rules.iter().filter(|rule| rule.action == AclAction::Reject) {
        let within = rule_destinations(rule).is_some_and(|destinations| {
            destinations.iter().all(|destination| {
                public
                    .iter()
                    .any(|outer| crate::egress::net_within(*destination, *outer))
            })
        });
        if !within {
            return Err(error(
                SandboxErrorCode::Internal,
                format!(
                    "compiled reject rule `{}` is not confined to public destinations",
                    rule.description
                ),
            ));
        }
    }
    Ok(())
}

/// Worst-case placeholder for each config value the `update_acl` PUT carries
/// besides the sandbox id (attempt token, project, revision).
const ACL_CONFIG_PLACEHOLDER: &str =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
/// A published generation can have 20 decimal digits, versus one for the
/// compile-time generation-zero tag.
const DNS_TAG_GENERATION_SLACK: usize = 19;

/// The exact size of the whole-ACL `update_acl` PUT body (`acl.rs`) for this
/// rule set, with every non-rule config value at its worst-case length and
/// every DNS-managed tag at its worst-case generation.
pub(crate) fn acl_put_body_bytes(sandbox_id: &str, rules: &[AclRule]) -> usize {
    let side = |direction: AclDirection| {
        rules
            .iter()
            .filter(|rule| rule.direction == direction)
            .map(super::acl::api_rule)
            .collect::<Vec<_>>()
    };
    let body = serde_json::json!({
        "description": "",
        "config": {
            NETWORK_SANDBOX_TAG: sandbox_id,
            NETWORK_ATTEMPT_TAG: ACL_CONFIG_PLACEHOLDER,
            NETWORK_PROJECT_TAG: ACL_CONFIG_PLACEHOLDER,
            "user.wssp.acl-revision": ACL_CONFIG_PLACEHOLDER,
        },
        "ingress": side(AclDirection::Ingress),
        "egress": side(AclDirection::Egress),
    });
    let slack = rules
        .iter()
        .filter(|rule| is_dns_dynamic_tag(&rule.description))
        .count()
        * DNS_TAG_GENERATION_SLACK;
    body.to_string().len() + slack
}

/// m12: the compiler never emits an ACL whose PUT body exceeds the bound; it
/// refuses (`egress_policy_too_large`) instead of truncating.
pub(crate) fn check_acl_body_bound(
    sandbox_id: &str,
    rules: &[AclRule],
) -> Result<(), RuntimeError> {
    let bytes = acl_put_body_bytes(sandbox_id, rules);
    if bytes > crate::egress::MAX_ACL_BODY_BYTES {
        return Err(EgressRefusal::PolicyTooLarge.error(format!(
            "the compiled egress policy needs a {bytes}-byte ACL, above the {}-byte bound",
            crate::egress::MAX_ACL_BODY_BYTES
        )));
    }
    Ok(())
}

/// The ACL a DNS refresh would leave installed for these answers: every
/// recorded non-DNS rule plus the allow and DNS/DoT companions per
/// (name, address), measured exactly like the create-time body (worst-case
/// generation tags). Transient fences are deny-direction and excluded.
pub(crate) fn refresh_acl_body_bytes(
    sandbox_id: &str,
    recorded_rules: &[AclRule],
    static_cidrs: &[String],
    answers: &[(String, Vec<Ipv4Addr>)],
) -> usize {
    let static_grants: Vec<GrantCidr> = static_cidrs
        .iter()
        .filter_map(|raw| parse_policy_cidr(raw).ok())
        .collect();
    let mut rules: Vec<AclRule> = recorded_rules
        .iter()
        .filter(|rule| !is_dns_dynamic_tag(&rule.description))
        .cloned()
        .collect();
    for (name, addresses) in answers {
        for addr in addresses {
            rules.extend(domain_grant_rules(name, *addr, &static_grants, 0));
        }
    }
    acl_put_body_bytes(sandbox_id, &rules)
}

/// The refresh byte budget (coordinator ruling): a refresh whose recompiled
/// body exceeds `MAX_ACL_BODY_BYTES` must not publish. Growth never relies
/// on the 96 KiB inline fallback.
pub(crate) fn check_refresh_budget(bytes: usize) -> Result<(), RuntimeError> {
    if bytes > crate::egress::MAX_ACL_BODY_BYTES {
        return Err(EgressRefusal::RefreshOverBudget.error(format!(
            "the refreshed egress grants need a {bytes}-byte ACL, above the {}-byte budget; \
             the last published rules stay",
            crate::egress::MAX_ACL_BODY_BYTES
        )));
    }
    Ok(())
}

/// The single grant-failure shape (§2.2): NXDOMAIN, an answer with no IPv4,
/// and an answer inside the protected set all read the same, so a grant
/// failure never reveals whether an internal name exists.
fn grant_unresolvable(domain: &str) -> RuntimeError {
    error(
        SandboxErrorCode::EgressResolutionFailed,
        format!("egress domain `{domain}` did not resolve to a usable public IPv4 address"),
    )
}

/// Resolve and validate every domain before choosing a subnet. The allocator
/// may retain its cross-process lock through the caller's subsequent apply.
pub(crate) fn compile_network_plan_allocating(
    sandbox_id: &str,
    policy: Option<&EgressPolicy>,
    hash: Option<&str>,
    settings: &EgressSettings,
    resolve: DomainResolver,
    allocate: impl FnOnce() -> Result<Ipv4Addr, RuntimeError>,
    limits: &CompileLimits<'_>,
) -> Result<SandboxNetworkPlan, RuntimeError> {
    crate::validate_managed_instance_name(&crate::default_incus_instance_name(sandbox_id))?;
    settings.validate()?;
    let empty = EgressPolicy {
        mode: EgressMode::Allowlist,
        domains: Vec::new(),
        cidrs: Vec::new(),
    };
    let policy = match (policy, hash) {
        (Some(policy), Some(hash)) => {
            verify_policy_hash(policy, hash)?;
            policy
        }
        (None, None) => &empty,
        _ => {
            return Err(protocol_error(
                "VM launch requires the egress policy and its hash together",
            ));
        }
    };
    // The effective open policy the control plane dispatches carries no
    // grants (fallback grants become the allowlist only when a node forces
    // allowlist mode, which the server resolves before dispatch).
    if policy.mode == EgressMode::Open && (!policy.domains.is_empty() || !policy.cidrs.is_empty()) {
        return Err(protocol_error(
            "an open egress policy must not carry grants",
        ));
    }
    // Domain count bounds resolution work. The CIDR input bound lives in
    // `verify_policy_presence_and_hash` on the recorded policy; this policy
    // may be a persisted expansion merging recorded CIDRs with previously
    // resolved destinations, so it is bounded after dedup by the compiled
    // destination limit below.
    if policy.domains.len() > MAX_POLICY_DOMAINS {
        return Err(protocol_error("egress policy exceeds host bounds"));
    }

    let mut grants: Vec<GrantCidr> = Vec::new();
    let mut static_grants: Vec<GrantCidr> = Vec::new();
    for raw in &policy.cidrs {
        let cidr = parse_policy_cidr(raw)?;
        static_grants.push(cidr.clone());
        grants.push(cidr);
    }
    let mut resolved_domains: Vec<ResolvedDomain> = Vec::new();
    let mut denied_grants: Vec<String> = Vec::new();
    for domain in &policy.domains {
        validate_policy_domain(domain)?;
        // M19: a grant the node's domain blocklist denies is never resolved,
        // gets no ACL allow and no host-record, and is reported.
        if crate::egress::domain_denied(domain, settings) {
            denied_grants.push(domain.clone());
            continue;
        }
        // A revoked permit or an expired deadline stops compilation before
        // another blocking lookup is issued.
        limits.check()?;
        // The lookup's wait is clamped to the REMAINING compilation budget:
        // a final lookup starting just before the deadline can never finish
        // after it, and the limits are rechecked once it returns.
        let wait = PER_LOOKUP_BUDGET.min(
            limits
                .deadline
                .saturating_duration_since(std::time::Instant::now()),
        );
        let resolved = resolve(domain, wait).map_err(|err| {
            if matches!(
                err.code,
                SandboxErrorCode::Internal | SandboxErrorCode::Timeout
            ) {
                grant_unresolvable(domain)
            } else {
                err
            }
        })?;
        limits.check()?;

        let mut v4: Vec<Ipv4Addr> = resolved
            .iter()
            .filter_map(|ip| match ip {
                IpAddr::V4(addr) => Some(*addr),
                // The bridge has no IPv6 path; a v6 answer contributes nothing.
                IpAddr::V6(_) => None,
            })
            .collect();
        v4.sort();
        v4.dedup();
        // C36: a rebound protected/private address is never installed, even
        // for an allowlisted name (DNS rebinding fails closed) — and it fails
        // exactly like NXDOMAIN (§2.2).
        if v4.is_empty()
            || v4
                .iter()
                .any(|addr| super::dns::is_protected_guest_address(*addr))
        {
            return Err(grant_unresolvable(domain));
        }
        for addr in &v4 {
            let cidr = parse_policy_cidr(&format!("{addr}/32"))?;
            grants.push(cidr);
        }
        resolved_domains.push(ResolvedDomain {
            name: domain.clone(),
            addresses: v4,
        });
    }
    grants.sort_by(|a, b| a.text.cmp(&b.text));
    grants.dedup_by(|a, b| a.text == b.text);
    if grants.len() > MAX_GRANT_DESTINATIONS {
        return Err(protocol_error("egress policy resolves beyond host bounds"));
    }
    // Emitted-record bound (rules/host-records scale with name×address
    // pairs): the SAME bound refresh planning and persisted-state loading
    // enforce, so compile/refresh/load can never disagree on validity.
    let records: usize = resolved_domains
        .iter()
        .map(|domain| domain.addresses.len())
        .sum();
    if records > MAX_GRANT_RECORDS {
        return Err(protocol_error("egress policy resolves beyond host bounds"));
    }
    // B12: only an allowlist resolver (build VMs) ever forwards to the
    // daemon's DNS stub; an open-mode resolver never does.
    if policy.mode == EgressMode::Open && settings.refused_dns_stub_port.is_some() {
        return Err(protocol_error(
            "an open-mode resolver never forwards to the DNS stub",
        ));
    }
    let dnsmasq_base = match policy.mode {
        EgressMode::Open => super::dns::render_open_dnsmasq_config(settings)?,
        EgressMode::Allowlist => super::dns::allowlist_dnsmasq_base(settings)?,
    };
    let setting_rejects = setting_reject_rules(settings)?;
    let open_rules = match policy.mode {
        EgressMode::Open => public_v4_rules(AclAction::Allow, None, None, OPEN_RULE_TAG)?,
        EgressMode::Allowlist => Vec::new(),
    };

    limits.check()?;
    let gateway = allocate()?;
    let (network_name, acl_name) = sandbox_network_names(sandbox_id);
    let gateway_cidr = format!("{gateway}/32");

    // Incus ACL directions are relative to the instance NIC: guest-initiated
    // requests are EGRESS rules, the bridge's replies are INGRESS rules.
    let mut rules = vec![
        // Narrowly needed infrastructure: DHCP (pre-IP client broadcast) and
        // DNS to the bridge resolver only.
        AclRule {
            action: AclAction::Allow,
            direction: AclDirection::Egress,
            protocol: Some("udp".to_string()),
            source: None,
            destination: Some("255.255.255.255/32".to_string()),
            source_port: Some("68".to_string()),
            destination_port: Some("67".to_string()),
            description: "wssp-dhcp".to_string(),
        },
        AclRule {
            action: AclAction::Allow,
            direction: AclDirection::Egress,
            protocol: Some("udp".to_string()),
            source: None,
            destination: Some(gateway_cidr.clone()),
            source_port: None,
            destination_port: Some("53".to_string()),
            description: "wssp-dns-udp".to_string(),
        },
        AclRule {
            action: AclAction::Allow,
            direction: AclDirection::Egress,
            protocol: Some("tcp".to_string()),
            source: None,
            destination: Some(gateway_cidr.clone()),
            source_port: None,
            destination_port: Some("53".to_string()),
            description: "wssp-dns-tcp".to_string(),
        },
    ];
    // CLI-logins proxy mode: one gateway allow on
    // the recorded proxy port, both modes. Other gateway ports stay dropped
    // by the bridge default. Replies ride the stateful ACL.
    if let Some(port) = settings.credential_proxy_port {
        rules.push(AclRule {
            action: AclAction::Allow,
            direction: AclDirection::Egress,
            protocol: Some("tcp".to_string()),
            source: None,
            destination: Some(gateway_cidr.clone()),
            source_port: None,
            destination_port: Some(port.to_string()),
            description: CREDENTIAL_PROXY_RULE_TAG.to_string(),
        });
    }
    // Static CIDR grants keep the `wssp-grant` description; domain-resolved
    // grants are tagged per name and generation (`wssp-dns-g<N>-<digest>`) so the C36 refresh
    // loop can diff its managed rules without ever touching static ones.
    let mut grant_rules = static_grants.iter().map(|grant| AclRule {
        action: AclAction::Allow,
        direction: AclDirection::Egress,
        protocol: None,
        source: None,
        destination: Some(grant.text.clone()),
        source_port: None,
        destination_port: None,
        description: "wssp-grant".to_string(),
    });
    rules.extend(&mut grant_rules);
    // §2.1 2b: open mode allows the complement of the protected set; the
    // bridge default `drop` keeps handling private space (a protected range
    // is never written as a reject: it would beat the gateway allows).
    rules.extend(open_rules);
    // §2.1 2c/2d: node-setting rejects, both modes.
    rules.extend(setting_rejects);
    for domain in &resolved_domains {
        for addr in &domain.addresses {
            // Create-time rules are generation 0 and are NOT installed by
            // the raw provisioning loop: they are issued through the
            // journaled, fenced DNS mutation boundary at publish time
            // (C36 r21 F4), which commits the observed rule set — a
            // tombstone-floored recreate may carry a higher generation,
            // and verifiers compare against the boundary's committed
            // record (see `acl_matches_effective`).
            rules.extend(domain_grant_rules(&domain.name, *addr, &static_grants, 0));
        }
    }
    // Ingress allows are belt-and-braces for the stateful default: DHCP offers
    // and DNS replies from the bridge. Established replies to allowed outbound
    // connections are permitted by the stateful ACL engine itself.
    rules.extend([
        AclRule {
            action: AclAction::Allow,
            direction: AclDirection::Ingress,
            protocol: Some("udp".to_string()),
            source: Some(gateway_cidr.clone()),
            destination: None,
            source_port: Some("67".to_string()),
            destination_port: Some("68".to_string()),
            description: "wssp-dhcp-reply".to_string(),
        },
        AclRule {
            action: AclAction::Allow,
            direction: AclDirection::Ingress,
            protocol: Some("udp".to_string()),
            source: Some(gateway_cidr.clone()),
            destination: None,
            source_port: Some("53".to_string()),
            destination_port: None,
            description: "wssp-dns-udp-reply".to_string(),
        },
        AclRule {
            action: AclAction::Allow,
            direction: AclDirection::Ingress,
            protocol: Some("tcp".to_string()),
            source: Some(gateway_cidr.clone()),
            destination: None,
            source_port: Some("53".to_string()),
            destination_port: None,
            description: "wssp-dns-tcp-reply".to_string(),
        },
    ]);
    public_v4_invariant(&rules)?;
    check_acl_body_bound(sandbox_id, &rules)?;

    Ok(SandboxNetworkPlan {
        sandbox_id: sandbox_id.to_string(),
        binding: None,
        network_name,
        acl_name,
        gateway,
        grants,
        rules,
        policy_hash: hash.map(str::to_owned),
        policy_domains: policy.domains.clone(),
        policy_cidrs: policy.cidrs.clone(),
        resolved_domains,
        mode: policy.mode,
        settings: Some(settings.clone()),
        dnsmasq_base,
        denied_grants,
    })
}

/// Upper bound on collision probes when allocating a bridge subnet; the
/// sandbox space is 10.0.0.0/8 (65536 /24s), so this fails long before the
/// address space itself is exhausted.
const MAX_SUBNET_PROBES: u32 = 4096;

/// Choose a non-overlapping /24 gateway for one sandbox bridge. The starting
/// candidate derives from the sandbox-id digest (stable per sandbox); probes
/// then walk the 10.0.0.0/8 space until the subnet avoids every `taken`
/// network (other managed bridges and host routes). Fail closed on exhaustion.
pub(crate) fn allocate_gateway(
    sandbox_id: &str,
    taken: &[(u32, u8)],
) -> Result<Ipv4Addr, RuntimeError> {
    let digest = ring::digest::digest(&ring::digest::SHA256, sandbox_id.as_bytes());
    let start = (u32::from(digest.as_ref()[6]) << 8) | u32::from(digest.as_ref()[7]);
    for probe in 0..MAX_SUBNET_PROBES {
        let index = (start + probe) % 65536;
        let base = u32_from([10, (index >> 8) as u8, (index & 0xff) as u8, 0]);
        if taken
            .iter()
            .any(|&(other_base, other_prefix)| intersects(base, 24, other_base, other_prefix))
        {
            continue;
        }
        return Ok(Ipv4Addr::from(base | 1));
    }
    Err(error(
        SandboxErrorCode::HostCapacity,
        "no non-overlapping subnet remains for a sandbox bridge",
    ))
}

/// Parse the kernel IPv4 route table (`/proc/net/route`) into (base, prefix)
/// networks. Malformed lines are skipped; an unreadable table is the caller's
/// error, never silently "no routes".
pub(crate) fn parse_route_table(text: &str) -> Vec<(u32, u8)> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let _iface = fields.next()?;
            let destination = u32::from_str_radix(fields.next()?, 16).ok()?;
            let mask = u32::from_str_radix(fields.nth(5)?, 16).ok()?;
            if mask == 0 {
                // The default route covers every address but carries no
                // on-link subnet; only on-link subnets collide with a bridge.
                return None;
            }
            // /proc/net/route is little-endian hex.
            let base = destination.swap_bytes() & mask.swap_bytes();
            let prefix = mask.swap_bytes().count_ones() as u8;
            Some((base, prefix))
        })
        .collect()
}

/// Host IPv4 routes the sandbox bridge must never overlay. Read-only.
#[cfg(target_os = "linux")]
pub(crate) fn host_route_networks() -> Result<Vec<(u32, u8)>, RuntimeError> {
    let text = std::fs::read_to_string("/proc/net/route").map_err(|err| {
        error(
            SandboxErrorCode::Internal,
            format!("cannot read the host route table: {err}"),
        )
    })?;
    Ok(parse_route_table(&text))
}

/// The exact effective device set a sandbox VM may run with: the audited
/// profile's root disk plus the single override NIC on the sandbox bridge.
/// Anything else — extra NICs, proxy devices, host mounts, missing anti-spoof
/// pinning — refuses the launch. Pure data so tests never need a daemon.
pub(crate) fn devices_match_plan(
    devices: &serde_json::Value,
    plan: &SandboxNetworkPlan,
) -> Result<(), RuntimeError> {
    let mismatch = || {
        error(
            SandboxErrorCode::IdempotencyConflict,
            "instance devices differ from the audited sandbox launch devices",
        )
    };
    let object = devices.as_object().ok_or_else(mismatch)?;
    if object.len() != 2 {
        return Err(mismatch());
    }
    // The audited root disk is identified by its PROPERTIES (a disk
    // mounted at /), not by its NAME: host init and launch preflight accept
    // a root disk under any name (e.g. "rootfs"), so a name-keyed check
    // would reject what preflight accepted — after networking was already
    // provisioned — and recovery could not repair the mismatch.
    let roots: Vec<&serde_json::Value> = object
        .values()
        .filter(|device| {
            device.get("type").and_then(|t| t.as_str()) == Some("disk")
                && device.get("path").and_then(|p| p.as_str()) == Some("/")
        })
        .collect();
    if roots.len() != 1 {
        return Err(mismatch());
    }
    super::storage::validate_root_keys(roots[0]).map_err(|_| mismatch())?;
    let eth0 = object.get("eth0").ok_or_else(mismatch)?;
    if eth0.get("type").and_then(|t| t.as_str()) != Some("nic") {
        return Err(mismatch());
    }
    let expected = [
        ("network", plan.network_name.as_str()),
        ("security.mac_filtering", "true"),
        ("security.ipv4_filtering", "true"),
        ("security.ipv6_filtering", "true"),
        ("security.port_isolation", "true"),
    ];
    for (key, want) in expected {
        if eth0.get(key).and_then(|v| v.as_str()) != Some(want) {
            return Err(mismatch());
        }
    }
    // Reject every OTHER security-relevant NIC property: a device-level
    // `security.acls` list, permissive default actions, routes or VLAN
    // membership would widen (or reroute around) the deny-default policy
    // while the five pinning checks above still pass. Benign daemon-filled
    // properties (nictype, mtu, hwaddr, host_name, queues, ...) stay allowed.
    let expected_keys: std::collections::BTreeSet<&str> =
        expected.iter().map(|(key, _)| *key).collect();
    let benign_prefixes = [
        "type",
        "name",
        "nictype",
        "mtu",
        "hwaddr",
        "host_name",
        "queues",
    ];
    if let Some(properties) = eth0.as_object() {
        for key in properties.keys() {
            let key = key.as_str();
            if expected_keys.contains(key) || benign_prefixes.iter().any(|p| key.starts_with(p)) {
                continue;
            }
            return Err(mismatch());
        }
    }
    Ok(())
}

/// Packet-level model of the compiled plan for adversarial tests. Not the
/// enforcement mechanism (Incus/nftables is); it exists so tests can assert
/// the intent against crafted packets.
#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct Packet {
    /// True: guest → network (Incus ACL egress, leaving the instance NIC).
    /// False: network → guest (Incus ACL ingress).
    pub from_guest: bool,
    /// True when the packet belongs to a connection the guest initiated and
    /// the plan already allowed (stateful bridge ACLs pass these regardless of
    /// the egress default drop).
    pub established_reply: bool,
    pub protocol: Option<&'static str>,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
}

#[cfg(test)]
fn rule_matches(rule: &AclRule, packet: &Packet) -> bool {
    if let Some(protocol) = &rule.protocol
        && packet.protocol != Some(protocol.as_str())
    {
        return false;
    }
    // Egress rules see packets leaving the NIC (guest → network): their
    // destination is the remote side. Ingress rules see packets arriving at
    // the NIC (network → guest): their source is the remote side.
    let (rule_cidr, packet_ip) = match rule.direction {
        AclDirection::Egress if packet.from_guest => {
            (rule.destination.as_deref(), packet.destination)
        }
        AclDirection::Ingress if !packet.from_guest => (rule.source.as_deref(), packet.source),
        _ => return false,
    };
    if let Some(cidrs) = rule_cidr {
        let IpAddr::V4(ip) = packet_ip else {
            return false;
        };
        // Incus subject lists are comma-separated (`wssp-open`, the
        // `PUBLIC_V4` reject families); a malformed entry matches nothing.
        let Some(nets) = cidrs
            .split(',')
            .map(crate::egress::parse_ipv4_net)
            .collect::<Option<Vec<_>>>()
        else {
            return false;
        };
        if !nets.iter().any(|net| crate::egress::net_contains(*net, ip)) {
            return false;
        }
    }
    // Every port the rule pins must match the packet's corresponding port —
    // source-port constraints (e.g. DHCP client sport 68) and destination-port
    // constraints on replies (e.g. DHCP offer dport 68) both bind. A port list
    // (`53,853`) matches any of its entries.
    for (rule_port, packet_port) in [
        (rule.source_port.as_deref(), packet.source_port),
        (rule.destination_port.as_deref(), packet.destination_port),
    ] {
        if let Some(ports) = rule_port {
            let matched = packet_port.is_some_and(|port| {
                ports
                    .split(',')
                    .any(|entry| entry.parse::<u16>().ok() == Some(port))
            });
            if !matched {
                return false;
            }
        }
    }
    true
}

/// Evaluate the plan against one packet. IPv6 never passes (the bridge has no
/// IPv6 address and the NIC drops it); anything unmatched falls to the
/// deny-by-default actions — there is no unrestricted fallback to model away.
#[cfg(test)]
pub(crate) fn plan_allows(plan: &SandboxNetworkPlan, packet: &Packet) -> bool {
    if packet.source.is_ipv6() || packet.destination.is_ipv6() {
        return false;
    }
    if !packet.from_guest && packet.established_reply {
        return true;
    }
    // Incus action precedence (drop > reject > allow): a matching reject
    // companion narrows a matching allow (C36 DNS/DoT rejection).
    let rejected = plan
        .rules
        .iter()
        .any(|rule| rule.action == AclAction::Reject && rule_matches(rule, packet));
    if rejected {
        return false;
    }
    plan.rules
        .iter()
        .any(|rule| rule.action == AclAction::Allow && rule_matches(rule, packet))
}

#[cfg(test)]
pub(crate) fn test_plan(sandbox_id: &str) -> SandboxNetworkPlan {
    let mut plan = compile_network_plan(
        sandbox_id,
        None,
        None,
        &|_, _| panic!("deny-all test plan must not resolve domains"),
        Ipv4Addr::new(10, 9, 9, 1),
        &CompileLimits {
            deadline: std::time::Instant::now() + COMPILE_BUDGET,
            cancelled: None,
        },
    )
    .expect("test plan");
    // The binding the shim fixtures seed on their instance metadata.
    plan.binding = Some(PlanBinding {
        template_fingerprint:
            "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string(),
        create_key: Some("create-1".to_string()),
    });
    plan
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn dns_tags_require_explicit_generations_including_zero() {
        for generation in [0, 1, u64::MAX] {
            for tag in [
                dns_rule_tag("example.com", generation),
                dns_rule_reject_tag("example.com", generation),
            ] {
                assert!(is_dns_dynamic_tag(&tag), "{tag}");
                assert_eq!(dns_tag_request_id(&tag), Some(generation));
            }
            for tag in [
                dns_fence_tag("128.66.0.7/32", generation),
                dns_lease_fence_tag("128.66.0.7/32", generation),
            ] {
                assert!(is_dns_dynamic_tag(&tag) && is_dns_fence_tag(&tag), "{tag}");
            }
        }
        for tag in [
            "wssp-dns-deadbeef",
            "wssp-dns-reject-deadbeef",
            "wssp-dns-quarantine-deadbeef",
            "wssp-dns-lease-quarantine-deadbeef",
            "wssp-dns-udp",
            "wssp-dns-tcp",
        ] {
            assert!(!is_dns_dynamic_tag(tag), "{tag}");
            assert!(!is_dns_fence_tag(tag), "{tag}");
        }
    }

    #[test]
    fn gateway_reallocation_rebinds_infrastructure_and_preserves_user_grants() {
        let mut plan = super::test_plan("reallocated");
        let mut grant = plan.rules[1].clone();
        grant.description = "wssp-grant".into();
        grant.destination = Some(format!("{}/32", plan.gateway));
        plan.rules.push(grant.clone());
        let gateway = Ipv4Addr::new(10, 250, 1, 1);
        plan.set_gateway(gateway);
        assert_eq!(plan.gateway, gateway);
        assert!(
            plan.network_config()
                .contains(&("ipv4.address".into(), "10.250.1.1/24".into()))
        );
        assert_eq!(plan.rules.last(), Some(&grant));
        for rule in &plan.rules {
            match rule.description.as_str() {
                "wssp-dns-udp" | "wssp-dns-tcp" => {
                    assert_eq!(rule.destination.as_deref(), Some("10.250.1.1/32"))
                }
                "wssp-dhcp-reply" | "wssp-dns-udp-reply" | "wssp-dns-tcp-reply" => {
                    assert_eq!(rule.source.as_deref(), Some("10.250.1.1/32"))
                }
                _ => {}
            }
        }
    }

    fn test_gateway() -> Ipv4Addr {
        Ipv4Addr::new(10, 9, 9, 1)
    }

    fn test_limits() -> CompileLimits<'static> {
        CompileLimits {
            deadline: Instant::now() + COMPILE_BUDGET,
            cancelled: None,
        }
    }

    fn compile(
        sandbox_id: &str,
        policy: Option<&EgressPolicy>,
        hash: Option<&str>,
        resolve: DomainResolver,
    ) -> Result<SandboxNetworkPlan, RuntimeError> {
        compile_network_plan(
            sandbox_id,
            policy,
            hash,
            resolve,
            test_gateway(),
            &test_limits(),
        )
    }

    fn deny_all() -> SandboxNetworkPlan {
        compile("sbx-1", None, None, &|_, _| {
            panic!("deny-all must not resolve domains")
        })
        .expect("deny-all plan")
    }

    #[test]
    fn compile_bounds_emitted_records_not_only_destinations() {
        // 128 names x 33 shared addresses: 33 unique destinations (within
        // the destination bound) but 4224 emitted records — rules and
        // host-record lines scale with records, so compile refuses, matching
        // the bound refresh planning and persisted-state loading enforce.
        let names: Vec<String> = (0..128).map(|i| format!("d{i}.example.com")).collect();
        let policy = EgressPolicy {
            mode: sandbox_protocol::EgressMode::Allowlist,
            domains: names,
            cidrs: Vec::new(),
        };
        let hash = policy_hash_hex(&policy);
        let err = compile("sbx-1", Some(&policy), Some(&hash), &|_domain, _wait| {
            Ok((0..33)
                .map(|i| std::net::IpAddr::V4(Ipv4Addr::new(128, 66, 0, i)))
                .collect())
        })
        .expect_err("over-bound records refuse");
        assert_eq!(err.code, SandboxErrorCode::ProtocolError);
    }

    #[test]
    fn network_names_are_deterministic_and_per_sandbox() {
        let (net_a, acl_a) = sandbox_network_names("sbx-1");
        let (net_b, acl_b) = sandbox_network_names("sbx-2");
        assert_eq!(
            sandbox_network_names("sbx-1"),
            (net_a.clone(), acl_a.clone())
        );
        assert_ne!(net_a, net_b);
        assert_ne!(acl_a, acl_b);
        assert!(net_a.starts_with(NETWORK_NAME_PREFIX));
        assert!(acl_a.starts_with(ACL_NAME_PREFIX));
        for name in [&net_a, &acl_a, &net_b, &acl_b] {
            assert!(
                name.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            );
        }
        // The bridge name is a Linux interface name: IFNAMSIZ allows 15.
        for name in [&net_a, &net_b] {
            assert!(name.len() <= MAX_INTERFACE_NAME, "{name}");
        }
    }

    #[test]
    fn deny_all_has_no_grant_rules_and_both_defaults_drop() {
        let plan = deny_all();
        assert!(plan.grants.is_empty());
        assert!(
            plan.rules
                .iter()
                .all(|rule| rule.description != "wssp-grant")
        );
        let config = plan.network_config();
        let get = |key: &str| {
            config
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(get("security.acls.default.ingress.action"), Some("drop"));
        assert_eq!(get("security.acls.default.egress.action"), Some("drop"));
        assert_eq!(get("ipv6.address"), Some("none"));
        assert_eq!(get("security.acls"), Some(plan.acl_name.as_str()));
        assert_eq!(get(NETWORK_SANDBOX_TAG), Some("sbx-1"));
    }

    #[test]
    fn no_rule_is_an_unrestricted_fallback() {
        let policy = EgressPolicy {
            mode: sandbox_protocol::EgressMode::Allowlist,
            domains: vec![],
            cidrs: vec!["128.66.0.0/24".into()],
        };
        let hash = {
            let digest = ring::digest::digest(
                &ring::digest::SHA256,
                canonical_policy_json(&policy).as_bytes(),
            );
            digest
                .as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        let plan = compile("sbx-1", Some(&policy), Some(&hash), &|_, _| Ok(vec![])).expect("plan");
        for rule in &plan.rules {
            assert!(rule.destination.is_some() || rule.source.is_some());
            assert_ne!(rule.destination.as_deref(), Some("0.0.0.0/0"));
            assert_ne!(rule.source.as_deref(), Some("0.0.0.0/0"));
        }
    }

    #[test]
    fn canonical_json_matches_control_plane_shape() {
        let policy = EgressPolicy {
            mode: sandbox_protocol::EgressMode::Allowlist,
            domains: vec!["b.example.com".into(), "a.example.com".into()],
            cidrs: vec!["128.66.0.0/24".into()],
        };
        assert_eq!(
            canonical_policy_json(&policy),
            r#"{"cidrs":["128.66.0.0/24"],"domains":["a.example.com","b.example.com"]}"#
        );
    }

    #[test]
    fn hash_mismatch_fails_closed() {
        let policy = EgressPolicy {
            mode: sandbox_protocol::EgressMode::Allowlist,
            domains: vec![],
            cidrs: vec![],
        };
        let err = compile("sbx-1", Some(&policy), Some(&"a".repeat(64)), &|_, _| {
            Ok(vec![])
        })
        .expect_err("mismatched hash");
        assert_eq!(err.code, SandboxErrorCode::ProtocolError);
    }

    #[test]
    fn policy_without_hash_or_hash_without_policy_fails_closed() {
        let policy = EgressPolicy {
            mode: sandbox_protocol::EgressMode::Allowlist,
            domains: vec![],
            cidrs: vec![],
        };
        for (p, h) in [(Some(&policy), None), (None, Some(&"a".repeat(64)[..]))] {
            let err =
                compile("sbx-1", p, h, &|_, _| Ok(vec![])).expect_err("half-specified policy");
            assert_eq!(err.code, SandboxErrorCode::ProtocolError);
        }
    }

    #[test]
    fn ipv6_cidr_grant_fails_closed() {
        let policy = EgressPolicy {
            mode: sandbox_protocol::EgressMode::Allowlist,
            domains: vec![],
            cidrs: vec!["2001:db8::/32".into()],
        };
        let err = compile("sbx-1", Some(&policy), None, &|_, _| Ok(vec![]));
        // mixed presence is ProtocolError; use the deny path instead
        assert!(err.is_err());
        let policy_hash = {
            let digest = ring::digest::digest(
                &ring::digest::SHA256,
                canonical_policy_json(&policy).as_bytes(),
            );
            digest
                .as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        let err = compile("sbx-1", Some(&policy), Some(&policy_hash), &|_, _| {
            Ok(vec![])
        })
        .expect_err("ipv6 grant");
        assert_eq!(err.code, SandboxErrorCode::UnsupportedCapability);
    }

    #[test]
    fn protected_cidrs_fail_closed() {
        for cidr in ["169.254.169.254/32", "169.254.0.0/16", "100.100.100.200/32"] {
            let policy = EgressPolicy {
                mode: sandbox_protocol::EgressMode::Allowlist,
                domains: vec![],
                cidrs: vec![cidr.into()],
            };
            let hash = {
                let digest = ring::digest::digest(
                    &ring::digest::SHA256,
                    canonical_policy_json(&policy).as_bytes(),
                );
                digest
                    .as_ref()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            };
            let err =
                compile("sbx-1", Some(&policy), Some(&hash), &|_, _| Ok(vec![])).expect_err(cidr);
            assert_eq!(err.code, SandboxErrorCode::ProtocolError, "{cidr}");
        }
    }

    #[test]
    fn non_canonical_cidr_fails_closed() {
        for cidr in [
            "128.66.0.5/24",
            "128.66.0.0/024",
            "128.66.0.0/33",
            "1.2.3.4",
        ] {
            let policy = EgressPolicy {
                mode: sandbox_protocol::EgressMode::Allowlist,
                domains: vec![],
                cidrs: vec![cidr.into()],
            };
            let hash = {
                let digest = ring::digest::digest(
                    &ring::digest::SHA256,
                    canonical_policy_json(&policy).as_bytes(),
                );
                digest
                    .as_ref()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            };
            assert!(
                compile("sbx-1", Some(&policy), Some(&hash), &|_, _| Ok(vec![])).is_err(),
                "{cidr}"
            );
        }
    }

    #[test]
    fn domain_grants_resolve_to_v4_hosts_and_fail_closed_without_v4() {
        let policy = EgressPolicy {
            mode: sandbox_protocol::EgressMode::Allowlist,
            domains: vec!["example.com".into()],
            cidrs: vec![],
        };
        let hash = {
            let digest = ring::digest::digest(
                &ring::digest::SHA256,
                canonical_policy_json(&policy).as_bytes(),
            );
            digest
                .as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        let plan = compile("sbx-1", Some(&policy), Some(&hash), &|_, _| {
            Ok(vec![
                "128.66.0.7".parse().unwrap(),
                "2001:db8::1".parse().unwrap(),
                "128.66.0.7".parse().unwrap(),
            ])
        })
        .expect("plan");
        assert_eq!(plan.grants.len(), 1);
        assert_eq!(plan.grants[0].text, "128.66.0.7/32");

        let err = compile("sbx-1", Some(&policy), Some(&hash), &|_, _| {
            Ok(vec!["2001:db8::1".parse().unwrap()])
        })
        .expect_err("v6-only domain");
        assert_eq!(err.code, SandboxErrorCode::EgressResolutionFailed);
    }

    #[test]
    fn unresolved_domains_are_typed_refusals_before_allocation() {
        let policy = EgressPolicy {
            mode: sandbox_protocol::EgressMode::Allowlist,
            domains: vec!["unresolved.example".into()],
            cidrs: vec![],
        };
        let hash = policy_hash_hex(&policy);
        for code in [SandboxErrorCode::Internal, SandboxErrorCode::Timeout] {
            let err = compile_network_plan_allocating(
                "sbx-1",
                Some(&policy),
                Some(&hash),
                &EgressSettings::default(),
                &|_, _| Err(error(code, "Name or service not known")),
                || panic!("DNS refusal must precede network allocation"),
                &CompileLimits {
                    deadline: Instant::now() + Duration::from_secs(1),
                    cancelled: None,
                },
            )
            .unwrap_err();
            assert_eq!(err.code, SandboxErrorCode::EgressResolutionFailed);
        }
    }

    #[test]
    fn domain_grants_rebinding_to_protected_addresses_fail_closed() {
        // C36: even an allowlisted name may not install a private, loopback,
        // link-local or shared-address-space destination.
        for rebound in [
            "10.0.0.9",
            "127.0.0.1",
            "169.254.169.254",
            "100.64.3.4",
            "192.0.2.7",
            "198.51.100.9",
            "203.0.113.1",
        ] {
            let policy = EgressPolicy {
                mode: sandbox_protocol::EgressMode::Allowlist,
                domains: vec!["example.com".into()],
                cidrs: vec![],
            };
            let hash = policy_hash_hex(&policy);
            let addr: IpAddr = rebound.parse().unwrap();
            let err = compile("sbx-1", Some(&policy), Some(&hash), &move |_, _| {
                Ok(vec![addr, "128.66.0.7".parse().unwrap()])
            })
            .expect_err("rebound address must fail the launch");
            // §2.2: a protected answer fails exactly like NXDOMAIN.
            assert_eq!(
                err.code,
                SandboxErrorCode::EgressResolutionFailed,
                "{rebound}"
            );
        }
    }

    #[test]
    fn domain_grants_never_open_external_dns_or_dot() {
        // C36 r1: a domain grant is a content grant, never a resolver grant.
        // `dns.google` resolving to 8.8.8.8 must NOT let the guest query
        // arbitrary names directly (udp/tcp 53, tcp 853); every other port
        // stays allowed. An explicit CIDR grant preserves direct DNS/DoT.
        let resolver_grant = |cidrs: Vec<String>| {
            let policy = EgressPolicy {
                mode: sandbox_protocol::EgressMode::Allowlist,
                domains: vec!["dns.google".into()],
                cidrs,
            };
            let hash = policy_hash_hex(&policy);
            compile("sbx-1", Some(&policy), Some(&hash), &|_, _| {
                Ok(vec!["8.8.8.8".parse().unwrap()])
            })
            .expect("plan")
        };
        let plan = resolver_grant(Vec::new());
        for (protocol, port) in [("udp", 53), ("tcp", 53), ("tcp", 853)] {
            assert!(
                !plan_allows(
                    &plan,
                    &packet(
                        true,
                        false,
                        Some(protocol),
                        "10.9.9.2",
                        "8.8.8.8",
                        Some(53000),
                        Some(port),
                    )
                ),
                "domain grant must not open external {protocol}/{port}"
            );
        }
        assert!(
            plan_allows(
                &plan,
                &packet(
                    true,
                    false,
                    Some("tcp"),
                    "10.9.9.2",
                    "8.8.8.8",
                    Some(53000),
                    Some(443),
                )
            ),
            "ordinary egress to the resolved address stays allowed"
        );
        // An unrelated public resolver stays fully denied.
        for port in [53u16, 853] {
            assert!(!plan_allows(
                &plan,
                &packet(
                    true,
                    false,
                    Some("udp"),
                    "10.9.9.2",
                    "1.1.1.1",
                    Some(53000),
                    Some(port),
                )
            ));
        }
        // Explicit CIDR grant over the same address preserves DNS/DoT.
        let plan = resolver_grant(vec!["8.8.8.8/32".into()]);
        for (protocol, port) in [("udp", 53), ("tcp", 53), ("tcp", 853)] {
            assert!(
                plan_allows(
                    &plan,
                    &packet(
                        true,
                        false,
                        Some(protocol),
                        "10.9.9.2",
                        "8.8.8.8",
                        Some(53000),
                        Some(port),
                    )
                ),
                "explicit CIDR grant preserves {protocol}/{port}"
            );
        }
    }

    #[test]
    fn invalid_domains_fail_closed() {
        for domain in [
            "*.example.com",
            "exa mple.com",
            "1.2.3.4",
            "example.com:443",
            "-bad.example.com",
        ] {
            let policy = EgressPolicy {
                mode: sandbox_protocol::EgressMode::Allowlist,
                domains: vec![domain.into()],
                cidrs: vec![],
            };
            let hash = {
                let digest = ring::digest::digest(
                    &ring::digest::SHA256,
                    canonical_policy_json(&policy).as_bytes(),
                );
                digest
                    .as_ref()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            };
            assert!(
                compile("sbx-1", Some(&policy), Some(&hash), &|_, _| Ok(vec![
                    "128.66.0.1".parse().unwrap()
                ]))
                .is_err(),
                "{domain}"
            );
        }
    }

    fn packet(
        from_guest: bool,
        established: bool,
        protocol: Option<&'static str>,
        source: &str,
        destination: &str,
        source_port: Option<u16>,
        destination_port: Option<u16>,
    ) -> Packet {
        Packet {
            from_guest,
            established_reply: established,
            protocol,
            source: source.parse().unwrap(),
            destination: destination.parse().unwrap(),
            source_port,
            destination_port,
        }
    }

    fn plan_with_grant() -> SandboxNetworkPlan {
        let policy = EgressPolicy {
            mode: sandbox_protocol::EgressMode::Allowlist,
            domains: vec![],
            cidrs: vec!["128.66.0.0/24".into()],
        };
        let hash = {
            let digest = ring::digest::digest(
                &ring::digest::SHA256,
                canonical_policy_json(&policy).as_bytes(),
            );
            digest
                .as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        compile("sbx-1", Some(&policy), Some(&hash), &|_, _| Ok(vec![])).expect("plan")
    }

    #[test]
    fn model_allows_granted_destination_and_established_reply() {
        let plan = plan_with_grant();
        assert!(plan_allows(
            &plan,
            &packet(
                true,
                false,
                Some("tcp"),
                "10.0.0.2",
                "128.66.0.9",
                None,
                Some(443)
            )
        ));
        // New inbound from the granted range is still denied...
        assert!(!plan_allows(
            &plan,
            &packet(
                false,
                false,
                Some("tcp"),
                "128.66.0.9",
                "10.0.0.2",
                Some(443),
                None
            )
        ));
        // ...but its established reply passes (stateful bridge ACLs).
        assert!(plan_allows(
            &plan,
            &packet(
                false,
                true,
                Some("tcp"),
                "128.66.0.9",
                "10.0.0.2",
                Some(443),
                Some(51000)
            )
        ));
    }

    #[test]
    fn model_denies_protected_host_services_and_lateral_traffic() {
        let plan = plan_with_grant();
        // Cloud metadata / host link-local.
        assert!(!plan_allows(
            &plan,
            &packet(
                true,
                false,
                Some("tcp"),
                "10.0.0.2",
                "169.254.169.254",
                None,
                Some(80)
            )
        ));
        // Lateral: another sandbox bridge's guest address.
        let other = compile("sbx-2", None, None, &|_, _| Ok(vec![])).expect("other");
        let other_guest =
            Ipv4Addr::new(10, other.gateway.octets()[1], other.gateway.octets()[2], 2);
        let dest = other_guest.to_string();
        assert!(!plan_allows(
            &plan,
            &packet(true, false, Some("tcp"), "10.0.0.2", &dest, None, Some(22))
        ));
        // The bridge gateway itself beyond DNS/DHCP.
        assert!(!plan_allows(
            &plan,
            &packet(
                true,
                false,
                Some("tcp"),
                "10.0.0.2",
                &plan.gateway.to_string(),
                None,
                Some(22)
            )
        ));
    }

    #[test]
    fn model_denies_ipv6_alternate_path() {
        let plan = plan_with_grant();
        assert!(!plan_allows(
            &plan,
            &Packet {
                from_guest: true,
                established_reply: false,
                protocol: Some("tcp"),
                source: "fe80::1".parse().unwrap(),
                destination: "2001:db8::1".parse().unwrap(),
                source_port: None,
                destination_port: Some(443),
            }
        ));
        assert!(!plan_allows(
            &plan,
            &Packet {
                from_guest: false,
                established_reply: true,
                protocol: Some("tcp"),
                source: "2001:db8::1".parse().unwrap(),
                destination: "fe80::1".parse().unwrap(),
                source_port: Some(443),
                destination_port: Some(51000),
            }
        ));
    }

    #[test]
    fn model_allows_dns_and_dhcp_but_not_other_gateway_ports() {
        let plan = deny_all();
        let gw = plan.gateway.to_string();
        assert!(plan_allows(
            &plan,
            &packet(true, false, Some("udp"), "10.0.0.2", &gw, None, Some(53))
        ));
        assert!(plan_allows(
            &plan,
            &packet(
                true,
                false,
                Some("udp"),
                "0.0.0.0",
                "255.255.255.255",
                Some(68),
                Some(67)
            )
        ));
        assert!(plan_allows(
            &plan,
            &packet(
                false,
                false,
                Some("udp"),
                &gw,
                "10.0.0.2",
                Some(67),
                Some(68)
            )
        ));
        assert!(!plan_allows(
            &plan,
            &packet(true, false, Some("tcp"), "10.0.0.2", &gw, None, Some(80))
        ));
        // C36: guests may only resolve through the bridge resolver. Direct
        // external DNS (udp/tcp 53) and DoT (853) to any other destination
        // are denied — there is no path around the DNS policy layer.
        for (protocol, port) in [("udp", 53), ("tcp", 53), ("tcp", 853)] {
            assert!(
                !plan_allows(
                    &plan,
                    &packet(
                        true,
                        false,
                        Some(protocol),
                        "10.0.0.2",
                        "8.8.8.8",
                        None,
                        Some(port)
                    )
                ),
                "external DNS {protocol}/{port} must be denied under deny-all"
            );
        }
        // ...unless the policy separately grants that destination as a
        // destination like any other (explicitly allowed external resolver).
        let policy = EgressPolicy {
            mode: sandbox_protocol::EgressMode::Allowlist,
            domains: vec![],
            cidrs: vec!["8.8.8.8/32".into()],
        };
        let hash = policy_hash_hex(&policy);
        let granted =
            compile("sbx-1", Some(&policy), Some(&hash), &|_, _| Ok(vec![])).expect("granted plan");
        assert!(plan_allows(
            &granted,
            &packet(
                true,
                false,
                Some("udp"),
                "10.0.0.2",
                "8.8.8.8",
                None,
                Some(53)
            )
        ));
        assert!(plan_allows(
            &granted,
            &packet(
                true,
                false,
                Some("tcp"),
                "10.0.0.2",
                "8.8.8.8",
                None,
                Some(853)
            )
        ));
        // Another resolver remains denied even under that grant.
        assert!(!plan_allows(
            &granted,
            &packet(
                true,
                false,
                Some("udp"),
                "10.0.0.2",
                "1.1.1.1",
                None,
                Some(53)
            )
        ));
        // Deny-all: no outbound destination passes.
        assert!(!plan_allows(
            &plan,
            &packet(
                true,
                false,
                Some("tcp"),
                "10.0.0.2",
                "128.66.0.9",
                None,
                Some(443)
            )
        ));
    }

    #[test]
    fn nic_device_args_pin_antispoof() {
        let plan = deny_all();
        let args = plan.nic_device_args();
        assert!(args.contains(&format!("network={}", plan.network_name)));
        for option in [
            "security.mac_filtering=true",
            "security.ipv4_filtering=true",
            "security.ipv6_filtering=true",
            "security.port_isolation=true",
        ] {
            assert!(args.iter().any(|arg| arg == option), "{option}");
        }
    }

    #[test]
    fn guest_requests_are_egress_rules_and_replies_are_ingress() {
        // Incus ACL directions are relative to the instance NIC.
        let plan = plan_with_grant();
        for rule in &plan.rules {
            match rule.description.as_str() {
                "wssp-dhcp"
                | "wssp-dns-udp"
                | "wssp-dns-tcp"
                | "wssp-grant"
                | OPEN_RULE_TAG
                | SMTP_REJECT_TAG
                | EXTERNAL_DNS_REJECT_TAG => {
                    assert_eq!(rule.direction, AclDirection::Egress, "{}", rule.description)
                }
                "wssp-dhcp-reply" | "wssp-dns-udp-reply" | "wssp-dns-tcp-reply" => {
                    assert_eq!(
                        rule.direction,
                        AclDirection::Ingress,
                        "{}",
                        rule.description
                    )
                }
                other => panic!("unexpected rule {other}"),
            }
        }
    }

    #[test]
    fn rule_port_constraints_bind_both_ports() {
        let plan = deny_all();
        let gw = plan.gateway.to_string();
        // DHCP request needs sport 68 AND dport 67; a source-port mismatch denies.
        assert!(!plan_allows(
            &plan,
            &packet(
                true,
                false,
                Some("udp"),
                "0.0.0.0",
                "255.255.255.255",
                Some(67),
                Some(67)
            )
        ));
        // DHCP offer with the wrong destination port: the dhcp-reply rule
        // pins dport 68, and the DNS replies pin sport 53, so nothing matches.
        assert!(!plan_allows(
            &plan,
            &packet(
                false,
                false,
                Some("udp"),
                &gw,
                "10.0.0.2",
                Some(67),
                Some(53)
            )
        ));
        assert!(!plan_allows(
            &plan,
            &packet(
                false,
                false,
                Some("udp"),
                &gw,
                "10.0.0.2",
                Some(67),
                Some(1234)
            )
        ));
        // A DNS answer (sport 53) deliberately leaves the destination port
        // unpinned; it reaches the guest's ephemeral port.
        assert!(plan_allows(
            &plan,
            &packet(
                false,
                false,
                Some("udp"),
                &gw,
                "10.0.0.2",
                Some(53),
                Some(53533)
            )
        ));
    }

    #[test]
    fn allocate_gateway_skips_collisions_and_fails_on_exhaustion() {
        // The hash-derived starting subnet is taken: the next free one is used.
        let start = allocate_gateway("sbx-1", &[]).expect("first choice");
        let base = u32::from(start) & !0xff;
        let taken = [(base, 24)];
        let second = allocate_gateway("sbx-1", &taken).expect("collision avoided");
        assert_ne!(second, start);
        assert_eq!(second.octets()[3], 1);
        // An overlapping host route (a /16 containing the candidate) is avoided.
        let wide = allocate_gateway("sbx-1", &[(base, 16)]).expect("route avoided");
        assert_ne!(u32::from(wide) & !0xff, base);
        // Every /24 in 10.0.0.0/8 taken: fail closed, deterministically.
        let full: Vec<(u32, u8)> = (0..65536)
            .map(|i| (u32_from([10, (i >> 8) as u8, (i & 0xff) as u8, 0]), 24))
            .collect();
        let err = allocate_gateway("sbx-1", &full).expect_err("exhausted");
        assert_eq!(err.code, SandboxErrorCode::HostCapacity);
    }

    #[test]
    fn parse_route_table_decodes_kernel_hex() {
        // iface dest gateway flags refcnt use metric mask mtu window irtt
        // (destination and mask are little-endian hex).
        let table = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
br0\t0000FEA9\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0
";
        let routes = parse_route_table(table);
        assert!(routes.contains(&(u32_from([192, 168, 1, 0]), 24)));
        assert!(routes.contains(&(u32_from([169, 254, 0, 0]), 16)));
        assert!(
            !routes.iter().any(|&(_, p)| p == 0),
            "default routes carry no on-link subnet"
        );
    }

    #[test]
    fn compilation_respects_deadline_and_revocation() {
        let policy = EgressPolicy {
            mode: sandbox_protocol::EgressMode::Allowlist,
            domains: vec!["a.example.com".into(), "b.example.com".into()],
            cidrs: vec![],
        };
        let hash = {
            let digest = ring::digest::digest(
                &ring::digest::SHA256,
                canonical_policy_json(&policy).as_bytes(),
            );
            digest
                .as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        // Already-expired deadline: not even the first lookup runs.
        let expired = CompileLimits {
            deadline: Instant::now() - Duration::from_millis(1),
            cancelled: None,
        };
        let err = compile_network_plan(
            "sbx-1",
            Some(&policy),
            Some(&hash),
            &|_, _| panic!("no lookup past the deadline"),
            test_gateway(),
            &expired,
        )
        .expect_err("expired deadline");
        assert_eq!(err.code, SandboxErrorCode::Timeout);
        // Permit revoked by the first lookup: the second domain never resolves.
        let permit = crate::RuntimePermit::default();
        let limits = CompileLimits {
            deadline: Instant::now() + COMPILE_BUDGET,
            cancelled: Some(&permit),
        };
        let lookups = std::sync::atomic::AtomicUsize::new(0);
        let err = compile_network_plan(
            "sbx-1",
            Some(&policy),
            Some(&hash),
            &|_, _| {
                lookups.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                permit.revoke();
                Ok(vec!["128.66.0.1".parse().unwrap()])
            },
            test_gateway(),
            &limits,
        )
        .expect_err("revoked permit");
        assert_eq!(err.code, SandboxErrorCode::UnknownOutcome);
        assert_eq!(
            lookups.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "no further lookups after revocation"
        );
    }

    /// R6-F3: the FINAL lookup cannot finish after the overall deadline and
    /// still produce an accepted plan: its wait is clamped to the remaining
    /// budget, and the limits are rechecked once it returns.
    #[test]
    fn final_lookup_is_clamped_to_the_remaining_deadline() {
        let policy = EgressPolicy {
            mode: sandbox_protocol::EgressMode::Allowlist,
            domains: vec!["a.example.com".into(), "b.example.com".into()],
            cidrs: vec![],
        };
        let hash = {
            let digest = ring::digest::digest(
                &ring::digest::SHA256,
                canonical_policy_json(&policy).as_bytes(),
            );
            digest
                .as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        let deadline = Instant::now() + Duration::from_millis(50);
        let limits = CompileLimits {
            deadline,
            cancelled: None,
        };
        let waits = std::sync::Mutex::new(Vec::new());
        let err = compile_network_plan(
            "sbx-1",
            Some(&policy),
            Some(&hash),
            &|_domain, wait| {
                waits.lock().unwrap().push(wait);
                // The final lookup finishes AFTER the overall deadline.
                std::thread::sleep(Duration::from_millis(120));
                Ok(vec!["128.66.0.1".parse().unwrap()])
            },
            test_gateway(),
            &limits,
        )
        .expect_err("a lookup finishing past the deadline never yields a plan");
        assert_eq!(err.code, SandboxErrorCode::Timeout);
        let waits = waits.lock().unwrap();
        assert_eq!(waits.len(), 1, "one lookup ran");
        assert!(
            waits[0] <= Duration::from_millis(50),
            "the lookup's wait is clamped to the remaining budget, not the full per-lookup bound: {:?}",
            waits[0]
        );
    }

    #[test]
    fn special_purpose_cidr_grants_cannot_bypass_guest_address_protection() {
        for cidr in [
            "192.0.2.0/24",
            "192.0.2.255/32",
            "198.51.100.0/24",
            "198.51.100.7/32",
            "203.0.113.0/24",
            "203.0.113.255/32",
            "203.0.112.0/23",
            "192.0.0.0/24",
            "192.0.0.9/32",
            "192.0.0.0/23",
            "192.88.99.0/24",
            "192.88.99.255/32",
            "192.88.98.0/23",
        ] {
            assert!(parse_policy_cidr(cidr).is_err(), "{cidr}");
        }
        for cidr in ["192.0.1.0/24", "192.88.98.0/24", "192.88.100.0/24"] {
            assert!(parse_policy_cidr(cidr).is_ok(), "{cidr}");
        }
    }

    /// R7-F3: a stalled NSS resolver can never accumulate uncapped detached
    /// threads. The pool's slots stay occupied until a lookup ACTUALLY
    /// finishes; once saturated, further submissions fail fast, and caller
    /// side timeouts do not free capacity. Finished work returns capacity.
    #[test]
    fn stalled_lookups_never_exceed_the_resolver_capacity() {
        let gate = std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let entered = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let stalled = {
            let gate = gate.clone();
            let entered = entered.clone();
            std::sync::Arc::new(move |_name: &str| {
                entered.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let (lock, cvar) = &*gate;
                let mut open = lock.lock().unwrap_or_else(|err| err.into_inner());
                while !*open {
                    open = cvar.wait(open).unwrap_or_else(|err| err.into_inner());
                }
                Ok(vec![])
            }) as ResolveImpl
        };
        let pool = ResolverPool::with_resolver(2, stalled).expect("pool");
        let mut replies = Vec::new();
        // Two running + two queued: every slot occupied by stalled work.
        // Wait for both workers to be inside a lookup so the queue depth is
        // deterministic.
        for i in 0..2 {
            let (tx, rx) = std::sync::mpsc::channel();
            pool.submit(&format!("sbx-{i}"), &format!("stalled-{i}.example.com"), tx)
                .expect("capacity for the first slots");
            replies.push(rx);
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while entered.load(std::sync::atomic::Ordering::SeqCst) < 2 {
            assert!(Instant::now() < deadline, "both workers start");
            std::thread::sleep(Duration::from_millis(5));
        }
        for i in 2..4 {
            let (tx, rx) = std::sync::mpsc::channel();
            pool.submit(&format!("sbx-{i}"), &format!("stalled-{i}.example.com"), tx)
                .expect("capacity for the first slots");
            replies.push(rx);
        }
        let (tx, _rx) = std::sync::mpsc::channel();
        let err = pool
            .submit("overflow", "overflow.example.com", tx)
            .expect_err("a saturated resolver fails fast");
        assert_eq!(err.code, SandboxErrorCode::Timeout);
        // Caller-side timeouts do NOT free the slots: the lookups are still
        // running, so the pool stays saturated.
        for rx in &replies {
            let _ = rx.recv_timeout(Duration::from_millis(5));
        }
        let (tx, _rx) = std::sync::mpsc::channel();
        pool.submit("still-overflow", "still-overflow.example.com", tx)
            .expect_err("timed-out callers do not free stalled slots");
        // When the stalled lookups actually finish, capacity returns.
        *gate.0.lock().unwrap_or_else(|err| err.into_inner()) = true;
        gate.1.notify_all();
        for rx in replies {
            let _ = rx
                .recv_timeout(Duration::from_secs(5))
                .expect("released lookups answer");
        }
        let (tx, rx) = std::sync::mpsc::channel();
        pool.submit("after", "after.example.com", tx)
            .expect("capacity returns once the lookups finish");
        let _ = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the freed pool resolves again");
    }

    #[test]
    fn bounded_lookup_times_out_instead_of_parking_the_worker() {
        let start = Instant::now();
        let err = bounded_lookup(
            "sbx-zero-budget",
            "nonexistent.invalid.",
            Duration::from_millis(0),
        )
        .expect_err("zero budget must time out");
        assert_eq!(err.code, SandboxErrorCode::Timeout);
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn devices_match_plan_accepts_only_the_audited_set() {
        let plan = deny_all();
        let good = serde_json::json!({
            "root": {"type": "disk", "path": "/", "pool": "default"},
            "eth0": {
                "type": "nic",
                "network": plan.network_name,
                "security.mac_filtering": "true",
                "security.ipv4_filtering": "true",
                "security.ipv6_filtering": "true",
                "security.port_isolation": "true",
            }
        });
        devices_match_plan(&good, &plan).expect("audited devices");
        for bad in [
            // Pre-C35 NIC on the shared bridge.
            serde_json::json!({
                "root": {"type": "disk", "path": "/", "pool": "default"},
                "eth0": {"type": "nic", "network": "incusbr0"}
            }),
            // Extra NIC alongside the pinned one.
            serde_json::json!({
                "root": {"type": "disk", "path": "/", "pool": "default"},
                "eth0": {
                    "type": "nic",
                    "network": plan.network_name,
                    "security.mac_filtering": "true",
                    "security.ipv4_filtering": "true",
                    "security.ipv6_filtering": "true",
                    "security.port_isolation": "true",
                },
                "eth1": {"type": "nic", "network": "incusbr0"}
            }),
            // Anti-spoof pinning dropped.
            serde_json::json!({
                "root": {"type": "disk", "path": "/", "pool": "default"},
                "eth0": {"type": "nic", "network": plan.network_name}
            }),
            // Host mount instead of the override NIC.
            serde_json::json!({
                "root": {"type": "disk", "path": "/", "pool": "default"},
                "hostdata": {"type": "disk", "path": "/srv", "source": "/srv"},
            }),
            // NIC-level permissive ACL list widening the deny-default policy.
            serde_json::json!({
                "root": {"type": "disk", "path": "/", "pool": "default"},
                "eth0": {
                    "type": "nic",
                    "network": plan.network_name,
                    "security.mac_filtering": "true",
                    "security.ipv4_filtering": "true",
                    "security.ipv6_filtering": "true",
                    "security.port_isolation": "true",
                    "security.acls.default.ingress.action": "drop",
                    "security.acls.default.egress.action": "drop",
                    "security.acls": "permissive-acl",
                }
            }),
            // NIC-level permissive default action overriding the network's drop.
            serde_json::json!({
                "root": {"type": "disk", "path": "/", "pool": "default"},
                "eth0": {
                    "type": "nic",
                    "network": plan.network_name,
                    "security.mac_filtering": "true",
                    "security.ipv4_filtering": "true",
                    "security.ipv6_filtering": "true",
                    "security.port_isolation": "true",
                    "security.acls.default.ingress.action": "drop",
                    "security.acls.default.egress.action": "allow",
                }
            }),
            // Any other unexpected security-relevant property.
            serde_json::json!({
                "root": {"type": "disk", "path": "/", "pool": "default"},
                "eth0": {
                    "type": "nic",
                    "network": plan.network_name,
                    "security.mac_filtering": "true",
                    "security.ipv4_filtering": "true",
                    "security.ipv6_filtering": "true",
                    "security.port_isolation": "true",
                    "security.acls.default.ingress.action": "drop",
                    "security.acls.default.egress.action": "drop",
                    "ipv4.routes": "0.0.0.0/0",
                }
            }),
        ] {
            let err = devices_match_plan(&bad, &plan).expect_err("unsafe devices");
            assert_eq!(err.code, SandboxErrorCode::IdempotencyConflict);
        }
    }

    #[test]
    fn devices_match_plan_identifies_the_root_disk_by_properties() {
        let plan = deny_all();
        let nic = serde_json::json!({
            "type": "nic",
            "network": plan.network_name,
            "security.mac_filtering": "true",
            "security.ipv4_filtering": "true",
            "security.ipv6_filtering": "true",
            "security.port_isolation": "true",
        });
        // A valid profile may name its root disk "rootfs" (or anything):
        // preflight accepts it, so verification must too.
        let renamed = serde_json::json!({
            "rootfs": {"type": "disk", "path": "/", "pool": "default"},
            "eth0": nic,
        });
        devices_match_plan(&renamed, &plan)
            .expect("a root disk named rootfs is still the audited root disk");
        // No root disk at all: the second device is a data mount.
        let absent = serde_json::json!({
            "eth0": nic,
            "data": {"type": "disk", "path": "/data", "pool": "default"},
        });
        let err = devices_match_plan(&absent, &plan).expect_err("missing root disk");
        assert_eq!(err.code, SandboxErrorCode::IdempotencyConflict);
    }
}
