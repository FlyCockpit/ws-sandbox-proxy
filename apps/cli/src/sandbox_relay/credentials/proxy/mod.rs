//! CLI-logins proxy mode: the secret stays on the host.
//!
//! A proxied login's values never enter the guest. Each proxied env entry
//! gets its own **handle** (128 random bits), bound to an immutable mapping
//! `{leaseId, bindingId, entryIndex, upstream authority, basepath, header,
//! format}`; the guest sees only `baseUrlEnv = http://<gw>:<port>/c/<handle>`
//! (and an optional placeholder). The proxy listens on the sandbox's bridge
//! gateway, parses each request strictly ([`http`]), checks the method
//! allowlist first, binds the guest connection and its single
//! upstream socket to the first handle it names, and injects the
//! header as a [`ValidatedHeaderValue`] built immediately before
//! serialization, only on a TLS connection to the definition's upstream.
//!
//! Revocation (free, `credential.revoke`, stop, kill, expiry, teardown)
//! removes the handles, zeroes the values and shuts down every guest
//! connection bound to them **and its upstream socket**. Every install,
//! restore or env insert carries an [`Authority`] taken before its bundle
//! wait and lands only if the lease was not revoked since
//! ([`LeaseRevocations`], shared with the service's env), atomically with
//! respect to the revocation. Every request serializes the credential header under the
//! mapping's value lock after re-checking revocation, so no credentialed
//! request is written upstream once a revocation has returned. After a
//! daemon restart the journaled handles answer 503 until the `proxy` restore
//! bundle arrives; a restore only completes handles still registered.
//!
//! Logs carry counts, status classes and entry indexes only: never a value,
//! a handle, a path, a header or a host.

#[path = "conn.rs"]
mod conn;
pub mod http;
pub mod upstream;

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use login_definition::ValidatedHeaderValue;
use login_definition::net::{format_problem, header_name_problem, parse_upstream};
use sandbox_protocol::{CredentialDelivery, SpecLeaseV11};

use super::SecretBytes;
use upstream::Watch;
pub use upstream::{CeilingFn, Connector, TlsConnector};

/// Guest connections per sandbox.
pub const SANDBOX_CONNECTIONS_MAX: usize = 16;
/// Guest connections per daemon.
pub const DAEMON_CONNECTIONS_MAX: usize = 256;
/// Requests per sandbox per minute.
pub const REQUESTS_PER_MINUTE: usize = 600;
/// One request (head, body, response) at most this long.
pub const REQUEST_MAX: Duration = Duration::from_secs(30 * 60);
/// Idle limit between bytes and between requests.
pub const IDLE_MAX: Duration = Duration::from_secs(120);
/// Revoked leases remembered (oldest forgotten first).
pub const TOMBSTONES_MAX: usize = 65_536;
/// Proxied entries per lease.
pub const ENTRIES_MAX: usize = 16;
/// The value a `placeholderEnv` holds in the guest.
pub const PLACEHOLDER_VALUE: &str = "wssp-credential-proxy";

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The sandbox's recorded proxy endpoint lookup (the runtime's): its bridge
/// gateway and the port its create opened there.
pub type EndpointFn = Arc<dyn Fn(&str) -> Option<SocketAddrV4> + Send + Sync>;
/// Whether a guest connection from a peer to a gateway is accepted.
pub type PeerFn = Arc<dyn Fn(Ipv4Addr, IpAddr) -> bool + Send + Sync>;

/// How the hub reaches the network. Production: [`ProxySettings::production`].
#[derive(Clone)]
pub struct ProxySettings {
    /// The proxy port a new create opens on its gateway ACL (the daemon's
    /// configuration). A listener binds on the sandbox's *recorded*
    /// endpoint instead ([`Self::endpoint`]), so a sandbox keeps its port
    /// across daemon restarts even when this setting changes.
    pub port: u16,
    pub connector: Arc<dyn Connector>,
    /// The sandbox's recorded proxy endpoint (the listen address; port 0 =
    /// ephemeral, tests only).
    pub endpoint: EndpointFn,
    /// Whether a guest connection from `peer` to `gateway` is accepted.
    pub peer_allowed: PeerFn,
    /// One request (head, body, response) at most this long.
    pub request_max: Duration,
}

impl fmt::Debug for ProxySettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxySettings")
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

impl ProxySettings {
    /// The daemon's settings: TLS with its trust, the bounded system
    /// resolver, the node's egress ceiling (from the runtime's guard), the
    /// runtime's recorded endpoint, and peers only from the gateway's own /24 (the
    /// sandbox bridge), never the gateway address itself (host processes).
    /// `None` when the resolver pool cannot start.
    pub fn production(
        port: u16,
        tls: &rustls::ClientConfig,
        endpoint: EndpointFn,
        ceiling: CeilingFn,
    ) -> Option<Self> {
        let resolver = upstream::system_resolver().ok()?;
        Some(Self {
            port,
            connector: Arc::new(TlsConnector::new(tls, resolver, ceiling)),
            endpoint,
            peer_allowed: Arc::new(bridge_peer),
            request_max: REQUEST_MAX,
        })
    }
}

/// A guest on the gateway's bridge: same /24, not the gateway itself.
pub fn bridge_peer(gateway: Ipv4Addr, peer: IpAddr) -> bool {
    let IpAddr::V4(peer) = peer else {
        return false;
    };
    peer != gateway && peer.octets()[..3] == gateway.octets()[..3] && peer.octets()[3] != 0
}

/// Lease revocations, shared by the proxy hub and the service's env.
///
/// Work that may grant authority to a lease (an install, a restore, an env
/// insert) first takes an [`Authority`] for it, before it waits for the
/// bundle; it lands only inside [`LeaseRevocations::while_valid`], which
/// refuses, atomically with respect to [`LeaseRevocations::revoke`], when
/// the lease was revoked after that authority was taken. A later grant of
/// the same lease (a RECOVER binding, a retried attach) takes a fresh
/// authority and is not affected by the earlier revocation.
#[derive(Debug, Default)]
pub struct LeaseRevocations {
    inner: Mutex<Revoked>,
}

#[derive(Debug, Default)]
struct Revoked {
    /// Sequence of every authority and revocation.
    next: u64,
    /// The latest revocation of each lease.
    last: HashMap<String, u64>,
    order: VecDeque<(String, u64)>,
    /// Revocations forgotten (bounded memory): an authority older than
    /// this is refused, whatever its lease.
    floor: u64,
}

/// The right to grant a lease's authority, as of when it was taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authority {
    lease_id: String,
    seq: u64,
}

impl Revoked {
    fn valid(&self, authority: &Authority) -> bool {
        authority.seq > self.floor
            && self
                .last
                .get(&authority.lease_id)
                .is_none_or(|revoked| *revoked < authority.seq)
    }
}

impl LeaseRevocations {
    /// An authority for `lease_id`, valid until its next revocation.
    pub fn authority(&self, lease_id: &str) -> Authority {
        let mut r = lock(&self.inner);
        r.next += 1;
        Authority {
            lease_id: lease_id.to_owned(),
            seq: r.next,
        }
    }

    /// Revokes `lease_id`: every authority taken before now is refused.
    pub fn revoke(&self, lease_id: &str) {
        let mut r = lock(&self.inner);
        r.next += 1;
        let seq = r.next;
        r.last.insert(lease_id.to_owned(), seq);
        r.order.push_back((lease_id.to_owned(), seq));
        while r.order.len() > TOMBSTONES_MAX {
            let Some((old, at)) = r.order.pop_front() else {
                break;
            };
            if r.last.get(&old) == Some(&at) {
                r.last.remove(&old);
            }
            r.floor = r.floor.max(at);
        }
    }

    pub fn is_valid(&self, authority: &Authority) -> bool {
        lock(&self.inner).valid(authority)
    }

    /// Runs `f` unless the lease was revoked after `authority` was taken; a
    /// concurrent revocation waits for `f` (and then removes what it
    /// installed).
    pub fn while_valid<T>(&self, authority: &Authority, f: impl FnOnce() -> T) -> Option<T> {
        let r = lock(&self.inner);
        if !r.valid(authority) {
            return None;
        }
        let out = f();
        drop(r);
        Some(out)
    }
}

/// The values an install brings.
#[derive(Clone, Copy)]
pub enum InstallValues<'a> {
    /// Handles registered without values (503 until restored).
    Pending,
    /// A fresh install with the bundle's values.
    Fresh(&'a [(String, SecretBytes)]),
    /// Completes still-registered pending handles after a daemon restart.
    Restore(&'a [(String, SecretBytes)]),
}

impl<'a> InstallValues<'a> {
    fn values(self) -> Option<&'a [(String, SecretBytes)]> {
        match self {
            Self::Pending => None,
            Self::Fresh(v) | Self::Restore(v) => Some(v),
        }
    }
}

/// Why a request may not use a mapping right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unready {
    Revoked,
    /// No value yet (daemon restart, restore pending).
    Pending,
    /// The stored value no longer builds a valid header value.
    Invalid,
}

/// One proxied env entry's immutable mapping. The value is the only secret;
/// it is taken out (and wiped) at revocation.
pub struct Mapping {
    pub lease_id: String,
    pub binding_id: String,
    pub entry_index: usize,
    host: String,
    port: u16,
    /// `host` or `host:port` (the `Host` header).
    authority: String,
    basepath: String,
    header: String,
    format: String,
    value: Mutex<Option<SecretBytes>>,
    revoked: AtomicBool,
}

impl fmt::Debug for Mapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mapping")
            .field("lease_id", &self.lease_id)
            .field("binding_id", &self.binding_id)
            .field("entry_index", &self.entry_index)
            .field("revoked", &self.revoked.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl Mapping {
    /// Step 1 of a revocation: no request starts or continues from here on.
    fn mark_revoked(&self) {
        self.revoked.store(true, Ordering::SeqCst);
    }

    /// Step 3 (after the connections are shut down): wipes the value. Waits
    /// for a header write in flight, which the shutdown has already failed.
    fn wipe(&self) {
        // Dropping the SecretBytes wipes it.
        lock(&self.value).take();
    }

    fn revoke(&self) {
        self.mark_revoked();
        self.wipe();
    }

    fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::SeqCst)
    }

    /// Whether a request can use the mapping now (no value is copied).
    fn ready(&self) -> Result<(), Unready> {
        let value = lock(&self.value);
        if self.is_revoked() {
            return Err(Unready::Revoked);
        }
        match value.as_ref() {
            None => Err(Unready::Pending),
            Some(_) => Ok(()),
        }
    }

    /// The fence on credential serialization: under the value lock, re-checks
    /// revocation, builds the header value and lets `write` put the whole
    /// request head on the upstream. A revocation sets the flag before it
    /// shuts the sockets down and takes this lock after, so once it returns
    /// no credentialed head is being or will be written. Returns the header
    /// value (response scrubbing).
    fn with_header<T>(
        &self,
        write: impl FnOnce(&ValidatedHeaderValue) -> T,
    ) -> Result<(ValidatedHeaderValue, T), Unready> {
        let value = lock(&self.value);
        if self.is_revoked() {
            return Err(Unready::Revoked);
        }
        let Some(raw) = value.as_ref() else {
            return Err(Unready::Pending);
        };
        let header =
            ValidatedHeaderValue::new(&self.format, raw.expose()).map_err(|_| Unready::Invalid)?;
        let out = write(&header);
        drop(value);
        Ok((header, out))
    }
}

/// A guest connection and the watch over its upstream socket (the live
/// upstream registry: peer address, deadline, binding), for shutdown at
/// revocation, at the deadline and on an egress ceiling change.
struct ConnEntry {
    stream: TcpStream,
    watch: Option<Arc<Watch>>,
    lease_id: Option<String>,
}

/// One proxy-enabled sandbox: its listener, handles and live connections.
pub(crate) struct SandboxProxy {
    gateway: Ipv4Addr,
    port: u16,
    handles: Mutex<HashMap<String, Arc<Mapping>>>,
    conns: Mutex<HashMap<u64, ConnEntry>>,
    next_conn: AtomicU64,
    stop: AtomicBool,
    rate: Mutex<VecDeque<Instant>>,
}

impl SandboxProxy {
    fn lookup(&self, handle: &str) -> Option<Arc<Mapping>> {
        lock(&self.handles).get(handle).cloned()
    }

    /// 600 requests per rolling minute.
    fn admit_request(&self) -> bool {
        let now = Instant::now();
        let mut rate = lock(&self.rate);
        while rate
            .front()
            .is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(60))
        {
            rate.pop_front();
        }
        if rate.len() >= REQUESTS_PER_MINUTE {
            return false;
        }
        rate.push_back(now);
        true
    }

    fn bind_conn(&self, conn_id: u64, lease_id: &str) {
        if let Some(entry) = lock(&self.conns).get_mut(&conn_id) {
            entry.lease_id = Some(lease_id.to_owned());
        }
    }

    /// Registers the watch over a guest connection's upstream socket
    /// before it connects (revocation shuts it down with the guest side;
    /// the hub's watchdog and egress enforcer see it). A connection already
    /// shut down by a revocation gets a closed watch.
    fn attach_watch(&self, conn_id: u64, watch: Arc<Watch>) {
        match lock(&self.conns).get_mut(&conn_id) {
            Some(entry) => entry.watch = Some(watch),
            None => watch.shutdown(),
        }
    }

    fn shutdown_conns(&self, lease: Option<&str>) {
        for entry in lock(&self.conns).values() {
            if lease.is_none() || entry.lease_id.as_deref() == lease {
                let _ = entry.stream.shutdown(std::net::Shutdown::Both);
                if let Some(watch) = &entry.watch {
                    watch.shutdown();
                }
            }
        }
    }

    fn watches(&self) -> Vec<Arc<Watch>> {
        lock(&self.conns)
            .values()
            .filter_map(|entry| entry.watch.clone())
            .collect()
    }

    fn stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }
}

/// Why a proxied install was refused. Fixed classes; never a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyInstallError {
    /// The lease is not a well-formed proxied lease (spec re-check).
    Spec,
    /// A constructed header value is not a valid field value.
    ValueInvalid,
    /// The runtime has no gateway for this sandbox.
    NoGateway,
    /// The listener could not be bound.
    Listen,
    /// The lease was revoked (or its pending handles are gone): a revoked
    /// binding never regains proxy authority.
    Revoked,
}

impl ProxyInstallError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Spec => "proxied lease spec invalid",
            Self::ValueInvalid => "credential.value_invalid",
            Self::NoGateway => "no proxy gateway for the sandbox",
            Self::Listen => "credential proxy could not listen",
            Self::Revoked => "credential proxy lease revoked",
        }
    }
}

/// A new handle: 128 bits from the system CSPRNG, lowercase hex.
pub fn new_handle() -> Option<String> {
    let mut bytes = [0u8; 16];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes).ok()?;
    Some(super::seal::hex(&bytes))
}

/// `n` fresh handles (one per proxied entry).
pub fn new_handles(n: usize) -> Option<Vec<String>> {
    (0..n).map(|_| new_handle()).collect()
}

fn valid_handle(handle: &str) -> bool {
    handle.len() == http::HANDLE_HEX_LEN
        && handle
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The process-wide proxy: one listener per proxy-enabled sandbox.
pub struct ProxyHub {
    settings: ProxySettings,
    sandboxes: Arc<Mutex<HashMap<String, Arc<SandboxProxy>>>>,
    /// The watchdog and egress enforcer threads run (started with the
    /// first listener; they end with the hub).
    enforcing: AtomicBool,
    daemon_conns: Arc<AtomicUsize>,
    revocations: Arc<LeaseRevocations>,
}

impl fmt::Debug for ProxyHub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyHub")
            .field("sandboxes", &lock(&self.sandboxes).len())
            .finish_non_exhaustive()
    }
}

/// The mappings of one lease, validated from its spec entry.
fn lease_mappings(
    lease: &SpecLeaseV11,
    binding_id: &str,
    handles: &[String],
) -> Result<Vec<Mapping>, ProxyInstallError> {
    if lease.delivery != CredentialDelivery::Proxy
        || lease.proxy.is_empty()
        || lease.proxy.len() > ENTRIES_MAX
        || lease.proxy.len() != handles.len()
        || !handles.iter().all(|h| valid_handle(h))
    {
        return Err(ProxyInstallError::Spec);
    }
    let mut out = Vec::with_capacity(handles.len());
    for (index, entry) in lease.proxy.iter().enumerate() {
        let upstream = parse_upstream(&entry.upstream).map_err(|_| ProxyInstallError::Spec)?;
        if header_name_problem(&entry.header).is_some() || format_problem(&entry.format).is_some() {
            return Err(ProxyInstallError::Spec);
        }
        let port = upstream.port.unwrap_or(443);
        let authority = match upstream.port {
            Some(p) if p != 443 => format!("{}:{p}", upstream.host),
            _ => upstream.host.clone(),
        };
        out.push(Mapping {
            lease_id: lease.lease_id.clone(),
            binding_id: binding_id.to_owned(),
            entry_index: index,
            host: upstream.host,
            port,
            authority,
            basepath: upstream.basepath,
            header: entry.header.clone(),
            format: entry.format.clone(),
            value: Mutex::new(None),
            revoked: AtomicBool::new(false),
        });
    }
    Ok(out)
}

impl ProxyHub {
    /// The proxy port a new create opens on its gateway (an existing
    /// sandbox's listener binds on its recorded port).
    pub fn port(&self) -> u16 {
        self.settings.port
    }

    pub fn new(settings: ProxySettings) -> Self {
        Self::with_revocations(settings, Arc::default())
    }

    /// A hub whose tombstones are shared with the caller (the service's env).
    pub fn with_revocations(settings: ProxySettings, revocations: Arc<LeaseRevocations>) -> Self {
        Self {
            settings,
            sandboxes: Arc::new(Mutex::new(HashMap::new())),
            enforcing: AtomicBool::new(false),
            daemon_conns: Arc::new(AtomicUsize::new(0)),
            revocations,
        }
    }

    /// An authority for `lease_id` (take it before waiting for the bundle).
    pub fn authority(&self, lease_id: &str) -> Authority {
        self.revocations.authority(lease_id)
    }

    /// Installs a proxied lease with fresh handles, authorized as of now.
    /// `values = None` registers the handles as pending (503; journaled
    /// handles after a daemon restart). Returns the guest env: `baseUrlEnv`
    /// (and `placeholderEnv`) per entry with a value. Entries the bundle
    /// carries no value for get no handle.
    pub fn install(
        &self,
        sandbox_id: &str,
        lease: &SpecLeaseV11,
        binding_id: &str,
        handles: &[String],
        values: Option<&[(String, SecretBytes)]>,
    ) -> Result<Vec<(String, String)>, ProxyInstallError> {
        let authority = self.authority(&lease.lease_id);
        let values = values.map_or(InstallValues::Pending, InstallValues::Fresh);
        self.install_authorized(&authority, sandbox_id, lease, binding_id, handles, values)
    }

    /// Installs (or, with [`InstallValues::Restore`], completes) a proxied
    /// lease under `authority`: refused when the lease was revoked after
    /// the authority was taken. A restore completes only handles still
    /// registered (not revoked, sandbox not removed): it never re-creates
    /// authority.
    pub fn install_authorized(
        &self,
        authority: &Authority,
        sandbox_id: &str,
        lease: &SpecLeaseV11,
        binding_id: &str,
        handles: &[String],
        mode: InstallValues<'_>,
    ) -> Result<Vec<(String, String)>, ProxyInstallError> {
        if authority.lease_id != lease.lease_id {
            return Err(ProxyInstallError::Spec);
        }
        let restore = matches!(mode, InstallValues::Restore(_));
        let values = mode.values();
        let mappings = lease_mappings(lease, binding_id, handles)?;
        // Every value is checked before anything is installed.
        let mut chosen: Vec<Option<SecretBytes>> = Vec::with_capacity(mappings.len());
        for (entry, mapping) in lease.proxy.iter().zip(&mappings) {
            let value = match values {
                None => None,
                Some(values) => {
                    let mut found = values.iter().filter(|(name, _)| *name == entry.name);
                    let first = found.next();
                    if found.next().is_some() {
                        return Err(ProxyInstallError::Spec);
                    }
                    match first {
                        None => None,
                        Some((_, v)) => {
                            if ValidatedHeaderValue::new(&mapping.format, v.expose()).is_err() {
                                tracing::warn!(
                                    entry = mapping.entry_index,
                                    "credential.value_invalid: proxied header value refused"
                                );
                                return Err(ProxyInstallError::ValueInvalid);
                            }
                            Some(SecretBytes::copy_from(v.expose()))
                        }
                    }
                }
            };
            chosen.push(value);
        }
        self.revocations
            .while_valid(authority, || {
                let (proxy, created) = if restore {
                    // A removed sandbox (stop, kill, teardown) is never
                    // brought back by a restore.
                    let proxy = lock(&self.sandboxes)
                        .get(sandbox_id)
                        .cloned()
                        .ok_or(ProxyInstallError::Revoked)?;
                    (proxy, false)
                } else {
                    self.sandbox(sandbox_id)?
                };
                let chosen = values.map(|_| chosen);
                let installed =
                    Self::install_live(&proxy, lease, handles, mappings, chosen, restore);
                // A listener this call opened for nothing is closed again;
                // one that already served the sandbox stays.
                if created && lock(&proxy.handles).is_empty() {
                    self.remove_sandbox(sandbox_id);
                }
                installed
            })
            .unwrap_or(Err(ProxyInstallError::Revoked))
    }

    /// The install proper, inside [`LeaseRevocations::while_valid`]. `chosen`
    /// is `None` overall for a pending install (no values at all).
    fn install_live(
        proxy: &SandboxProxy,
        lease: &SpecLeaseV11,
        handles: &[String],
        mappings: Vec<Mapping>,
        chosen: Option<Vec<Option<SecretBytes>>>,
        restore: bool,
    ) -> Result<Vec<(String, String)>, ProxyInstallError> {
        let mut env = Vec::new();
        let mut table = lock(&proxy.handles);
        // A restore completes exactly this lease's registered, unrevoked
        // entries; a fresh install never reuses a handle.
        for (handle, mapping) in handles.iter().zip(&mappings) {
            match table.get(handle) {
                Some(existing)
                    if existing.lease_id != mapping.lease_id
                        || existing.binding_id != mapping.binding_id
                        || existing.entry_index != mapping.entry_index =>
                {
                    return Err(ProxyInstallError::Spec);
                }
                Some(_) if !restore => return Err(ProxyInstallError::Spec),
                Some(existing) if existing.is_revoked() => {
                    return Err(ProxyInstallError::Revoked);
                }
                None if restore => return Err(ProxyInstallError::Revoked),
                _ => {}
            }
        }
        let with_values = chosen.is_some();
        let chosen = chosen.unwrap_or_else(|| (0..mappings.len()).map(|_| None).collect());
        for ((handle, mapping), value) in handles.iter().zip(mappings).zip(chosen) {
            let entry = &lease.proxy[mapping.entry_index];
            if with_values && value.is_none() {
                // No value for this entry: no handle, nothing in the guest.
                if let Some(old) = table.remove(handle) {
                    old.revoke();
                }
                continue;
            }
            let has_value = value.is_some();
            match table.get(handle) {
                Some(existing) => *lock(&existing.value) = value,
                None => {
                    *lock(&mapping.value) = value;
                    table.insert(handle.clone(), Arc::new(mapping));
                }
            }
            if has_value {
                env.push((
                    entry.base_url_env.clone(),
                    format!("http://{}:{}/c/{handle}", proxy.gateway, proxy.port),
                ));
                if let Some(name) = &entry.placeholder_env {
                    env.push((name.clone(), PLACEHOLDER_VALUE.to_owned()));
                }
            }
        }
        drop(table);
        Ok(env)
    }

    /// Removes every handle of `lease_id`, wipes its values and closes the
    /// guest connections bound to it. The sandbox's listener stays up even
    /// when its last handle goes: a proxy-enabled sandbox answers
    /// 403 for an unknown handle and a later attach reuses the listener.
    /// Only [`Self::remove_sandbox`] (stop, kill, expiry, teardown) closes it.
    ///
    /// The lease is tombstoned first (no install or restore lands after
    /// this), every request on it is stopped (flag), its guest and upstream
    /// sockets are shut down, and only then are the values wiped.
    pub fn revoke_lease(&self, lease_id: &str) {
        self.revocations.revoke(lease_id);
        let sandboxes: Vec<(String, Arc<SandboxProxy>)> = lock(&self.sandboxes)
            .iter()
            .map(|(id, p)| (id.clone(), p.clone()))
            .collect();
        for (_, proxy) in sandboxes {
            let mut removed = Vec::new();
            let mut table = lock(&proxy.handles);
            table.retain(|_, mapping| {
                if mapping.lease_id == lease_id {
                    mapping.mark_revoked();
                    removed.push(mapping.clone());
                    false
                } else {
                    true
                }
            });
            drop(table);
            // Connections bound to the lease (also ones whose mapping a
            // restore already dropped) close with their upstream sockets.
            proxy.shutdown_conns(Some(lease_id));
            for mapping in removed.iter() {
                mapping.wipe();
            }
        }
    }

    /// Stops the sandbox's listener, revokes every handle and closes every
    /// guest connection (stop, kill, expiry, teardown).
    pub fn remove_sandbox(&self, sandbox_id: &str) {
        let Some(proxy) = lock(&self.sandboxes).remove(sandbox_id) else {
            return;
        };
        proxy.stop.store(true, Ordering::SeqCst);
        let removed: Vec<Arc<Mapping>> = lock(&proxy.handles).drain().map(|(_, m)| m).collect();
        for mapping in &removed {
            mapping.mark_revoked();
        }
        proxy.shutdown_conns(None);
        for mapping in &removed {
            mapping.wipe();
        }
    }

    /// Handles installed for `sandbox_id` (tests, census of live state).
    pub fn handle_count(&self, sandbox_id: &str) -> usize {
        lock(&self.sandboxes)
            .get(sandbox_id)
            .map(|p| lock(&p.handles).len())
            .unwrap_or(0)
    }

    /// The listen address of `sandbox_id`'s proxy, when it listens.
    pub fn listen_addr(&self, sandbox_id: &str) -> Option<SocketAddr> {
        lock(&self.sandboxes)
            .get(sandbox_id)
            .map(|p| SocketAddr::new(IpAddr::V4(p.gateway), p.port))
    }

    /// Starts the hub's lifetime enforcement once: a watchdog that shuts
    /// every upstream socket down at its request's absolute deadline
    /// (handshake included), and an egress enforcer that re-validates every
    /// live upstream socket against the current ceiling each
    /// [`upstream::ENFORCE_INTERVAL`], shutting violators down, and every
    /// socket while the ceiling is unavailable. Separate threads, so a slow
    /// guard probe never delays the watchdog. No enforcement, no listener.
    fn start_enforcement(&self) -> Result<(), ProxyInstallError> {
        if self.enforcing.load(Ordering::SeqCst) {
            return Ok(());
        }
        let watchdog = Enforcer {
            sandboxes: Arc::downgrade(&self.sandboxes),
            connector: self.settings.connector.clone(),
        };
        let enforcer = Enforcer {
            sandboxes: Arc::downgrade(&self.sandboxes),
            connector: self.settings.connector.clone(),
        };
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        let second = dispatch.clone();
        std::thread::Builder::new()
            .name("wssp-credential-proxy-watchdog".into())
            .spawn(move || {
                tracing::dispatcher::with_default(&dispatch, || {
                    watchdog.run(WATCHDOG_TICK, Enforcer::deadlines);
                });
            })
            .map_err(|_| ProxyInstallError::Listen)?;
        std::thread::Builder::new()
            .name("wssp-credential-proxy-egress".into())
            .spawn(move || {
                tracing::dispatcher::with_default(&second, || {
                    enforcer.run(upstream::ENFORCE_INTERVAL, Enforcer::egress);
                });
            })
            .map_err(|_| ProxyInstallError::Listen)?;
        self.enforcing.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// The sandbox's proxy, binding its listener on first use (`true`:
    /// this call opened it).
    fn sandbox(&self, sandbox_id: &str) -> Result<(Arc<SandboxProxy>, bool), ProxyInstallError> {
        let mut sandboxes = lock(&self.sandboxes);
        if let Some(existing) = sandboxes.get(sandbox_id) {
            return Ok((existing.clone(), false));
        }
        self.start_enforcement()?;
        // The sandbox's recorded endpoint, never the configured port: the
        // guest's base URLs and gateway ACL name exactly this address.
        let endpoint = (self.settings.endpoint)(sandbox_id).ok_or(ProxyInstallError::NoGateway)?;
        let gateway = *endpoint.ip();
        if gateway.is_unspecified() || gateway.is_broadcast() || gateway.is_multicast() {
            return Err(ProxyInstallError::NoGateway);
        }
        let listener = TcpListener::bind(endpoint).map_err(|_| ProxyInstallError::Listen)?;
        let port = listener
            .local_addr()
            .map_err(|_| ProxyInstallError::Listen)?
            .port();
        listener
            .set_nonblocking(true)
            .map_err(|_| ProxyInstallError::Listen)?;
        let proxy = Arc::new(SandboxProxy {
            gateway,
            port,
            handles: Mutex::new(HashMap::new()),
            conns: Mutex::new(HashMap::new()),
            next_conn: AtomicU64::new(1),
            stop: AtomicBool::new(false),
            rate: Mutex::new(VecDeque::new()),
        });
        let accept = AcceptLoop {
            listener,
            proxy: proxy.clone(),
            connector: self.settings.connector.clone(),
            peer_allowed: self.settings.peer_allowed.clone(),
            request_max: self.settings.request_max,
            daemon_conns: self.daemon_conns.clone(),
            dispatch: tracing::dispatcher::get_default(Clone::clone),
        };
        std::thread::Builder::new()
            .name("wssp-credential-proxy".into())
            .spawn(move || accept.run())
            .map_err(|_| ProxyInstallError::Listen)?;
        sandboxes.insert(sandbox_id.to_owned(), proxy.clone());
        Ok((proxy, true))
    }
}

impl Drop for ProxyHub {
    fn drop(&mut self) {
        let ids: Vec<String> = lock(&self.sandboxes).keys().cloned().collect();
        for id in ids {
            self.remove_sandbox(&id);
        }
    }
}

const ACCEPT_POLL: Duration = Duration::from_millis(50);
/// The deadline watchdog's period.
const WATCHDOG_TICK: Duration = Duration::from_millis(100);

/// The hub's lifetime enforcement over every registered upstream socket.
struct Enforcer {
    sandboxes: std::sync::Weak<Mutex<HashMap<String, Arc<SandboxProxy>>>>,
    connector: Arc<dyn Connector>,
}

impl Enforcer {
    /// Every `tick` until the hub is gone.
    fn run(self, tick: Duration, pass: fn(&Self, Vec<Arc<Watch>>)) {
        loop {
            std::thread::sleep(tick);
            let Some(sandboxes) = self.sandboxes.upgrade() else {
                return;
            };
            let proxies: Vec<Arc<SandboxProxy>> = lock(&sandboxes).values().cloned().collect();
            drop(sandboxes);
            let watches = proxies.iter().flat_map(|p| p.watches()).collect();
            pass(&self, watches);
        }
    }

    /// The absolute deadline, beneath any operation still in progress: the
    /// upstream socket at the deadline, the guest socket
    /// [`upstream::GUEST_GRACE`] later (after the worker's own 504), so a
    /// worker blocked on either side releases its connection.
    fn deadlines(&self, watches: Vec<Arc<Watch>>) {
        for watch in watches {
            if watch.expired() && !watch.is_closed() {
                tracing::debug!("credential proxy upstream shut down at its request deadline");
                watch.shutdown();
            }
            if watch.overdue(upstream::GUEST_GRACE) && watch.shutdown_guest() {
                tracing::debug!("credential proxy guest shut down past its request deadline");
            }
        }
    }

    /// The current egress ceiling over every live upstream socket.
    fn egress(&self, watches: Vec<Arc<Watch>>) {
        let live: Vec<Arc<Watch>> = watches
            .into_iter()
            .filter(|w| w.has_socket() && !w.is_closed())
            .collect();
        if live.is_empty() {
            return;
        }
        let policy = self.connector.policy();
        let mut cut = 0usize;
        for watch in &live {
            if watch.enforce(policy.as_ref()).is_err() {
                cut += 1;
            }
        }
        if cut > 0 {
            tracing::warn!(
                sockets = cut,
                ceiling = policy.is_some(),
                "credential proxy: upstream sockets shut down by the egress ceiling"
            );
        }
    }
}

struct AcceptLoop {
    listener: TcpListener,
    proxy: Arc<SandboxProxy>,
    connector: Arc<dyn Connector>,
    peer_allowed: PeerFn,
    request_max: Duration,
    daemon_conns: Arc<AtomicUsize>,
    dispatch: tracing::Dispatch,
}

/// Releases a connection slot on every exit path.
struct Slot {
    proxy: Arc<SandboxProxy>,
    daemon_conns: Arc<AtomicUsize>,
    conn_id: u64,
}

impl Drop for Slot {
    fn drop(&mut self) {
        lock(&self.proxy.conns).remove(&self.conn_id);
        self.daemon_conns.fetch_sub(1, Ordering::SeqCst);
    }
}

impl AcceptLoop {
    fn run(self) {
        let dispatch = self.dispatch.clone();
        tracing::dispatcher::with_default(&dispatch, || self.accept_until_stopped());
    }

    fn accept_until_stopped(self) {
        while !self.proxy.stopped() {
            let (stream, peer) = match self.listener.accept() {
                Ok(pair) => pair,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(ACCEPT_POLL);
                    continue;
                }
                Err(_) => {
                    std::thread::sleep(ACCEPT_POLL);
                    continue;
                }
            };
            if !(self.peer_allowed)(self.proxy.gateway, peer.ip()) {
                tracing::debug!("credential proxy refused a connection from outside the bridge");
                continue;
            }
            let _ = stream.set_nonblocking(false);
            self.admit(stream);
        }
    }

    fn admit(&self, stream: TcpStream) {
        let refuse = |mut stream: TcpStream| {
            use std::io::Write;
            let _ = stream.write_all(&http::Status::Unavailable.response());
            let _ = stream.shutdown(std::net::Shutdown::Both);
        };
        let Ok(clone) = stream.try_clone() else {
            return;
        };
        let conn_id = self.proxy.next_conn.fetch_add(1, Ordering::SeqCst);
        {
            let mut conns = lock(&self.proxy.conns);
            if conns.len() >= SANDBOX_CONNECTIONS_MAX {
                drop(conns);
                tracing::debug!("credential proxy connection limit (sandbox)");
                refuse(stream);
                return;
            }
            if self.daemon_conns.fetch_add(1, Ordering::SeqCst) >= DAEMON_CONNECTIONS_MAX {
                self.daemon_conns.fetch_sub(1, Ordering::SeqCst);
                drop(conns);
                tracing::debug!("credential proxy connection limit (daemon)");
                refuse(stream);
                return;
            }
            conns.insert(
                conn_id,
                ConnEntry {
                    stream: clone,
                    watch: None,
                    lease_id: None,
                },
            );
        }
        let slot = Slot {
            proxy: self.proxy.clone(),
            daemon_conns: self.daemon_conns.clone(),
            conn_id,
        };
        let proxy = self.proxy.clone();
        let connector = self.connector.clone();
        let dispatch = self.dispatch.clone();
        let request_max = self.request_max;
        let spawned = std::thread::Builder::new()
            .name("wssp-credential-proxy-conn".into())
            .spawn(move || {
                tracing::dispatcher::with_default(&dispatch, || {
                    conn::serve(stream, &proxy, connector.as_ref(), conn_id, request_max);
                });
                drop(slot);
            });
        if spawned.is_err() {
            tracing::warn!("credential proxy could not start a connection thread");
        }
    }
}

#[cfg(test)]
#[path = "testing.rs"]
pub(crate) mod testing;
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
