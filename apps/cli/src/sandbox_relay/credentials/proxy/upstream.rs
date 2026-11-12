//! Upstream sockets for the credential proxy.
//!
//! One socket per guest connection, owned by exactly one mapping. The
//! production connector resolves the definition's hostname on a bounded
//! resolver pool (IPv4 only, AAAA ignored), refuses the whole answer when
//! any address is outside the node's **egress ceiling** (the guard's
//! published drop sets and node addresses, plus the static protected
//! table), re-checks each address against a current ceiling immediately
//! before connecting to it, and speaks TLS with the definition's hostname as
//! SNI and verification name. No ceiling (guard unreachable or unhealthy),
//! no connection. No environment proxy variables, no pool, no redirect
//! following, no fallback to plaintext.
//!
//! **Lifetime enforcement.** Every upstream socket is registered in its
//! connection's [`Watch`] before the TLS handshake. The hub re-validates
//! every registered socket's peer against the current ceiling
//! ([`Connector::policy`]) every [`ENFORCE_INTERVAL`], the connection does
//! so before each keep-alive reuse and periodically while relaying, and any
//! socket whose peer the ceiling now refuses is shut down; when the ceiling
//! is unavailable, every socket is. A watchdog shuts a socket down at its
//! request's absolute deadline, handshake included.
//!
//! **Both endpoints.** The watch also owns the guest side of its
//! connection: every guest write of a request goes through a
//! [`WatchedSocket`] on the same watch (deadline and cancellation checked
//! before every raw write, so a slow-reading guest cannot stretch a
//! partially written response past the deadline), and the watchdog shuts
//! the guest socket down [`GUEST_GRACE`] after the deadline, whatever the
//! connection's worker is blocked in, so no request holds connection
//! capacity past its deadline.
//!
//! **Deadlines beneath TLS.** Rustls never sees the raw socket: it reads
//! and writes through a [`WatchedSocket`], which checks the deadline and
//! cancellation before every raw operation and caps the socket timeout by
//! the time left, so an upstream trickling partial TLS records cannot hold a
//! request past its deadline.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use sandbox_runtime::guard::ceiling::EgressCeiling;
use sandbox_runtime::guard_probe::GuardProbe;

use super::IDLE_MAX;

/// Per-address connect budget, and the whole TLS handshake's (both bounded
/// by the request deadline).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Name resolution budget.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);
/// Resolver threads of the production pool.
pub const RESOLVER_WORKERS: usize = 8;
/// Lookups waiting for a resolver thread, at most.
pub const RESOLVER_QUEUE: usize = 24;
/// A guard ceiling answer is reused for at most this long (the guard
/// itself resyncs every 5 s; its lease is 15 s).
const CEILING_TTL: Duration = Duration::from_secs(1);
/// Live upstream sockets are re-validated against the current ceiling at
/// least this often (by the hub's enforcer, and by a relaying connection).
pub const ENFORCE_INTERVAL: Duration = Duration::from_secs(1);
/// Past its request deadline, a connection's guest socket is shut down by
/// the watchdog after this long: time for the worker to answer its own 504
/// (the upstream socket is cut at the deadline itself).
pub const GUEST_GRACE: Duration = Duration::from_secs(1);

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub trait UpstreamStream: Read + Write + Send {
    /// A second handle on the underlying TCP socket: revocation shuts it
    /// down and the request clock narrows its timeouts.
    fn socket(&self) -> io::Result<TcpStream>;
}

impl UpstreamStream for TcpStream {
    fn socket(&self) -> io::Result<TcpStream> {
        self.try_clone()
    }
}

impl UpstreamStream for rustls::StreamOwned<rustls::ClientConnection, WatchedSocket> {
    fn socket(&self) -> io::Result<TcpStream> {
        self.sock.sock.try_clone()
    }
}

/// The node's egress policy for established sockets at one instant:
/// `true` = the ceiling refuses this destination.
pub type Policy = Arc<dyn Fn(Ipv4Addr) -> bool + Send + Sync>;

/// Request-scoped liveness of one guest connection's upstream socket: the
/// armed absolute deadline, cancellation (revocation, proxy stop), and the
/// registered socket with its peer, so the hub can shut it down at the
/// deadline (watchdog) or when the egress ceiling no longer admits its peer.
pub struct Watch {
    deadline: Mutex<Option<Instant>>,
    cancel: Box<dyn Fn() -> bool + Send + Sync>,
    socket: Mutex<Option<(TcpStream, SocketAddr)>>,
    /// The guest side of the connection (a second handle on its socket).
    guest: Mutex<Option<TcpStream>>,
    closed: AtomicBool,
}

impl Watch {
    /// `cancel` answers whether the connection's work is no longer wanted.
    pub fn new(cancel: Box<dyn Fn() -> bool + Send + Sync>) -> Arc<Self> {
        Arc::new(Self {
            deadline: Mutex::new(None),
            cancel,
            socket: Mutex::new(None),
            guest: Mutex::new(None),
            closed: AtomicBool::new(false),
        })
    }

    /// Takes ownership of the connection's guest side: the watchdog shuts
    /// it down [`GUEST_GRACE`] past an armed deadline.
    pub fn own_guest(&self, guest: TcpStream) {
        *lock(&self.guest) = Some(guest);
    }

    /// The armed deadline passed more than `grace` ago.
    pub fn overdue(&self, grace: Duration) -> bool {
        self.deadline().is_some_and(|d| Instant::now() >= d + grace)
    }

    /// Shuts the guest side down (the worker's every guest read and write
    /// fails from here on); `true` the first time.
    pub fn shutdown_guest(&self) -> bool {
        let Some(guest) = lock(&self.guest).take() else {
            return false;
        };
        let _ = guest.shutdown(std::net::Shutdown::Both);
        true
    }

    /// Starts a request: its absolute deadline.
    pub fn arm(&self, deadline: Instant) {
        *lock(&self.deadline) = Some(deadline);
    }

    /// Between requests (keep-alive idle): no deadline runs.
    pub fn disarm(&self) {
        *lock(&self.deadline) = None;
    }

    pub fn deadline(&self) -> Option<Instant> {
        *lock(&self.deadline)
    }

    /// The armed deadline has passed.
    pub fn expired(&self) -> bool {
        self.deadline().is_some_and(|d| Instant::now() >= d)
    }

    /// Revoked, stopped, or already shut down.
    pub fn cancelled(&self) -> bool {
        self.closed.load(Ordering::SeqCst) || (self.cancel)()
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Registers the upstream socket (before any byte is exchanged). A
    /// watch already shut down shuts the new socket down at once.
    pub fn attach(&self, sock: &TcpStream) -> io::Result<()> {
        let peer = sock.peer_addr()?;
        let clone = sock.try_clone()?;
        let mut slot = lock(&self.socket);
        if self.closed.load(Ordering::SeqCst) {
            let _ = clone.shutdown(std::net::Shutdown::Both);
            return Err(io::ErrorKind::ConnectionAborted.into());
        }
        *slot = Some((clone, peer));
        Ok(())
    }

    pub fn has_socket(&self) -> bool {
        lock(&self.socket).is_some()
    }

    /// Shuts the upstream socket down for good (any later attach too).
    pub fn shutdown(&self) {
        let slot = lock(&self.socket);
        self.closed.store(true, Ordering::SeqCst);
        if let Some((sock, _)) = slot.as_ref() {
            let _ = sock.shutdown(std::net::Shutdown::Both);
        }
    }

    /// Re-validates the registered socket against `policy` (`None` = the
    /// ceiling is unavailable): a socket whose peer is refused, or any
    /// socket without a ceiling, is shut down. No socket, nothing to check.
    pub fn enforce(&self, policy: Option<&Policy>) -> Result<(), UpstreamError> {
        let peer = match lock(&self.socket).as_ref() {
            Some((_, peer)) => *peer,
            None => return Ok(()),
        };
        let verdict = match (policy, peer) {
            (None, _) => Err(UpstreamError::Ceiling),
            (Some(refuses), SocketAddr::V4(v4)) if !refuses(*v4.ip()) => Ok(()),
            (Some(_), _) => Err(UpstreamError::Protected),
        };
        if verdict.is_err() {
            self.shutdown();
        }
        verdict
    }

    /// Time a raw operation may take now: `ConnectionAborted` once
    /// cancelled or shut down, `TimedOut` once the deadline passed.
    fn remaining(&self) -> io::Result<Duration> {
        if self.cancelled() {
            return Err(io::ErrorKind::ConnectionAborted.into());
        }
        let Some(deadline) = self.deadline() else {
            return Ok(IDLE_MAX);
        };
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        Ok(left.min(IDLE_MAX))
    }
}

/// The transport beneath rustls: every raw read and write first checks the
/// watch (cancellation, absolute deadline) and an optional tighter limit
/// (the handshake budget), then caps the socket timeout by the time left.
pub struct WatchedSocket {
    sock: TcpStream,
    watch: Arc<Watch>,
    limit: Option<Instant>,
}

impl WatchedSocket {
    pub fn new(sock: TcpStream, watch: Arc<Watch>) -> Self {
        Self {
            sock,
            watch,
            limit: None,
        }
    }

    fn budget(&self) -> io::Result<Duration> {
        let mut left = self.watch.remaining()?;
        if let Some(limit) = self.limit {
            let until = limit.saturating_duration_since(Instant::now());
            if until.is_zero() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            left = left.min(until);
        }
        Ok(left.max(Duration::from_millis(1)))
    }
}

impl Read for WatchedSocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.budget()?;
        self.sock.set_read_timeout(Some(left))?;
        self.sock.read(buf)
    }
}

impl Write for WatchedSocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let left = self.budget()?;
        self.sock.set_write_timeout(Some(left))?;
        self.sock.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sock.flush()
    }
}

/// Why an upstream could not be reached. Fixed classes; never a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamError {
    /// The name did not resolve to a usable IPv4 address in time (or the
    /// resolver pool is saturated).
    Resolve,
    /// The answer contained an address outside the egress ceiling
    /// (refused as a whole).
    Protected,
    /// The node's egress ceiling is unavailable (guard unreachable or not
    /// healthy): fail closed.
    Ceiling,
    /// The mapping was revoked (or the proxy stopped) while connecting.
    Cancelled,
    Connect,
    Tls,
    Timeout,
}

impl UpstreamError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Resolve => "upstream did not resolve",
            Self::Protected => "upstream resolved to a protected address",
            Self::Ceiling => "egress ceiling unavailable",
            Self::Cancelled => "upstream connect cancelled",
            Self::Connect => "upstream connect failed",
            Self::Tls => "upstream tls failed",
            Self::Timeout => "upstream timed out",
        }
    }
}

/// Opens the one upstream socket of a guest connection and answers the
/// node's current egress policy for established sockets.
pub trait Connector: Send + Sync {
    /// Connects by the watch's armed deadline; the watch's cancellation is
    /// polled between steps (revocation, proxy stop). A connector registers
    /// its socket in the watch ([`Watch::attach`]) before any handshake.
    fn connect(
        &self,
        host: &str,
        port: u16,
        watch: &Arc<Watch>,
    ) -> Result<Box<dyn UpstreamStream>, UpstreamError>;

    /// The current egress policy for established upstream sockets; `None`
    /// when it is unavailable (every socket must close).
    fn policy(&self) -> Option<Policy>;
}

/// Resolves a host to socket addresses by a deadline (injected so tests
/// never do DNS).
pub type Resolver = Arc<dyn Fn(&str, u16, Instant) -> io::Result<Vec<SocketAddr>> + Send + Sync>;

/// One blocking lookup (the pool's work function).
pub type Lookup = Arc<dyn Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync>;

/// Releases one unit of resolver capacity when the work it charges ends.
struct Charge(Arc<AtomicUsize>);

impl Drop for Charge {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

struct Job {
    host: String,
    port: u16,
    reply: mpsc::Sender<io::Result<Vec<SocketAddr>>>,
    /// The caller stopped waiting: a queued job is skipped, never run.
    abandoned: Arc<AtomicBool>,
    /// Held until the job is dropped by a worker (done or skipped).
    _charge: Charge,
}

/// A fixed set of resolver threads with a bounded queue. Every lookup is
/// charged against `workers + queue` from submission until a worker drops
/// it, so a caller that times out does not release capacity while its
/// lookup still runs: slow lookups can never accumulate threads.
pub struct ResolverPool {
    jobs: Mutex<mpsc::SyncSender<Job>>,
    outstanding: Arc<AtomicUsize>,
    capacity: usize,
}

impl ResolverPool {
    pub fn new(workers: usize, queue: usize, lookup: Lookup) -> io::Result<Arc<Self>> {
        let workers = workers.max(1);
        let (tx, rx) = mpsc::sync_channel::<Job>(queue + workers);
        let rx = Arc::new(Mutex::new(rx));
        for _ in 0..workers {
            let rx = rx.clone();
            let lookup = lookup.clone();
            std::thread::Builder::new()
                .name("wssp-proxy-resolve".into())
                .spawn(move || {
                    loop {
                        // Exits once the pool (the sender) is dropped.
                        let next = rx.lock().map(|rx| rx.recv());
                        let Ok(Ok(job)) = next else {
                            return;
                        };
                        if job.abandoned.load(Ordering::SeqCst) {
                            continue;
                        }
                        let _ = job.reply.send(lookup(&job.host, job.port));
                    }
                })?;
        }
        Ok(Arc::new(Self {
            jobs: Mutex::new(tx),
            outstanding: Arc::new(AtomicUsize::new(0)),
            capacity: workers + queue,
        }))
    }

    /// Lookups submitted and not yet finished or skipped by a worker.
    pub fn outstanding(&self) -> usize {
        self.outstanding.load(Ordering::SeqCst)
    }

    /// Resolves within `min(deadline, RESOLVE_TIMEOUT)`. A saturated pool
    /// refuses at once (`WouldBlock`).
    pub fn resolve(&self, host: &str, port: u16, deadline: Instant) -> io::Result<Vec<SocketAddr>> {
        if self.outstanding.fetch_add(1, Ordering::SeqCst) >= self.capacity {
            self.outstanding.fetch_sub(1, Ordering::SeqCst);
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let charge = Charge(self.outstanding.clone());
        let (reply, answer) = mpsc::channel();
        let abandoned = Arc::new(AtomicBool::new(false));
        let job = Job {
            host: host.to_owned(),
            port,
            reply,
            abandoned: abandoned.clone(),
            _charge: charge,
        };
        self.jobs
            .lock()
            .map_err(|_| io::Error::other("resolver pool poisoned"))?
            .try_send(job)
            .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
        let wait = deadline
            .saturating_duration_since(Instant::now())
            .min(RESOLVE_TIMEOUT);
        match answer.recv_timeout(wait) {
            Ok(result) => result,
            Err(_) => {
                abandoned.store(true, Ordering::SeqCst);
                Err(io::ErrorKind::TimedOut.into())
            }
        }
    }
}

/// The system resolver (getaddrinfo) on a bounded pool; no environment
/// proxy variables are consulted.
pub fn system_resolver() -> io::Result<Resolver> {
    let pool = ResolverPool::new(
        RESOLVER_WORKERS,
        RESOLVER_QUEUE,
        Arc::new(|host: &str, port: u16| (host, port).to_socket_addrs().map(Iterator::collect)),
    )?;
    Ok(Arc::new(move |host: &str, port: u16, deadline: Instant| {
        pool.resolve(host, port, deadline)
    }))
}

/// The node's current egress ceiling; `None` = unavailable (fail closed).
pub type CeilingFn = Arc<dyn Fn() -> Option<Arc<EgressCeiling>> + Send + Sync>;

/// The ceiling from the egress guard (`{"op":"ceiling"}` through the
/// runtime's probe, so the daemon's pushed deployment digest is expected).
/// An answer is reused for at most [`CEILING_TTL`]; any failure clears it
/// and refuses. No probe, no ceiling.
pub fn guard_ceiling(probe: Option<Arc<dyn GuardProbe>>) -> CeilingFn {
    let cache: Mutex<Option<(Instant, Arc<EgressCeiling>)>> = Mutex::new(None);
    Arc::new(move || {
        let probe = probe.as_ref()?;
        let mut cache = cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((at, ceiling)) = cache.as_ref()
            && at.elapsed() < CEILING_TTL
        {
            return Some(ceiling.clone());
        }
        *cache = None;
        match probe.egress_ceiling() {
            Ok(ceiling) => {
                let ceiling = Arc::new(ceiling);
                *cache = Some((Instant::now(), ceiling.clone()));
                Some(ceiling)
            }
            Err(_) => {
                tracing::warn!("credential proxy: egress ceiling unavailable; refusing upstreams");
                None
            }
        }
    })
}

/// Whether the proxy may not open a socket to `ip`: the guard's ceiling
/// or the static protected table (same as the Incus DNS grant filter).
pub fn refused(ceiling: &EgressCeiling, ip: Ipv4Addr) -> bool {
    sandbox_runtime::is_protected_guest_address(ip) || ceiling.refuses(ip)
}

/// Validated IPv4 addresses of an answer, in order. AAAA answers are
/// ignored; any refused IPv4 address refuses the whole answer.
pub fn validated_addresses(
    answer: &[SocketAddr],
    refuse: &dyn Fn(Ipv4Addr) -> bool,
) -> Result<Vec<SocketAddrV4>, UpstreamError> {
    let mut out = Vec::new();
    for addr in answer {
        if let SocketAddr::V4(v4) = addr {
            if refuse(*v4.ip()) {
                return Err(UpstreamError::Protected);
            }
            if !out.contains(v4) {
                out.push(*v4);
            }
        }
    }
    if out.is_empty() {
        return Err(UpstreamError::Resolve);
    }
    Ok(out)
}

/// The production connector: resolve → ceiling → (re-check, TCP) → TLS
/// (handshake completed before any request byte is written).
pub struct TlsConnector {
    tls: Arc<rustls::ClientConfig>,
    resolve: Resolver,
    ceiling: CeilingFn,
    refuse: fn(&EgressCeiling, Ipv4Addr) -> bool,
}

impl TlsConnector {
    /// `base` is the daemon's TLS trust (webpki roots plus `ca_file`); ALPN is
    /// pinned to `http/1.1` so the upstream never negotiates another protocol.
    pub fn new(base: &rustls::ClientConfig, resolve: Resolver, ceiling: CeilingFn) -> Self {
        let mut tls = base.clone();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        tls.enable_sni = true;
        Self {
            tls: Arc::new(tls),
            resolve,
            ceiling,
            refuse: refused,
        }
    }

    /// Tests only: the ceiling alone decides (loopback test servers sit in
    /// the static protected table).
    #[cfg(test)]
    pub(crate) fn ceiling_only(
        base: &rustls::ClientConfig,
        resolve: Resolver,
        ceiling: CeilingFn,
    ) -> Self {
        Self {
            refuse: |ceiling, ip| ceiling.refuses(ip),
            ..Self::new(base, resolve, ceiling)
        }
    }

    fn ceiling(&self) -> Result<Arc<EgressCeiling>, UpstreamError> {
        (self.ceiling)().ok_or(UpstreamError::Ceiling)
    }
}

/// The daemon's default upstream trust: the webpki roots only.
pub fn webpki_client_config() -> Option<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .ok()
        .map(|b| b.with_root_certificates(roots).with_no_client_auth())
}

fn remaining(deadline: Instant) -> Result<Duration, UpstreamError> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        Err(UpstreamError::Timeout)
    } else {
        Ok(left)
    }
}

/// A handshake failure as a fixed class.
fn handshake_error(watch: &Watch, limit: Instant, error: &io::Error) -> UpstreamError {
    if (watch.cancel)() {
        return UpstreamError::Cancelled;
    }
    if matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ) || watch.expired()
        || Instant::now() >= limit
    {
        return UpstreamError::Timeout;
    }
    if watch.is_closed() {
        return UpstreamError::Cancelled;
    }
    UpstreamError::Tls
}

impl Connector for TlsConnector {
    fn connect(
        &self,
        host: &str,
        port: u16,
        watch: &Arc<Watch>,
    ) -> Result<Box<dyn UpstreamStream>, UpstreamError> {
        let deadline = watch.deadline().ok_or(UpstreamError::Timeout)?;
        let cancelled = || watch.cancelled();
        let name = rustls::pki_types::ServerName::try_from(host.to_owned())
            .map_err(|_| UpstreamError::Tls)?;
        if !matches!(name, rustls::pki_types::ServerName::DnsName(_)) {
            return Err(UpstreamError::Tls);
        }
        // No ceiling, no lookup either.
        self.ceiling()?;
        let answer = (self.resolve)(host, port, deadline).map_err(|_| UpstreamError::Resolve)?;
        if cancelled() {
            return Err(UpstreamError::Cancelled);
        }
        let ceiling = self.ceiling()?;
        let addresses = validated_addresses(&answer, &|ip| (self.refuse)(&ceiling, ip))?;
        let mut sock = None;
        for addr in addresses {
            if cancelled() {
                return Err(UpstreamError::Cancelled);
            }
            // The ceiling can change while earlier addresses time out:
            // re-check this address against a current one right before
            // connecting to exactly it.
            let current = self.ceiling()?;
            if (self.refuse)(&current, *addr.ip()) {
                return Err(UpstreamError::Protected);
            }
            let budget = remaining(deadline)?.min(CONNECT_TIMEOUT);
            if let Ok(s) = TcpStream::connect_timeout(&SocketAddr::V4(addr), budget) {
                if s.peer_addr().ok() != Some(SocketAddr::V4(addr)) {
                    return Err(UpstreamError::Connect);
                }
                sock = Some(s);
                break;
            }
        }
        let sock = sock.ok_or(UpstreamError::Connect)?;
        let _ = sock.set_nodelay(true);
        // Registered before the handshake: the watchdog cuts it at the
        // deadline, revocation and the egress enforcer at any time.
        watch.attach(&sock).map_err(|_| {
            if watch.expired() {
                UpstreamError::Timeout
            } else {
                UpstreamError::Cancelled
            }
        })?;
        let mut conn = rustls::ClientConnection::new(self.tls.clone(), name)
            .map_err(|_| UpstreamError::Tls)?;
        // The whole handshake within CONNECT_TIMEOUT (and the deadline),
        // checked beneath rustls on every raw read and write.
        let limit = Instant::now() + remaining(deadline)?.min(CONNECT_TIMEOUT);
        let mut io = WatchedSocket::new(sock, watch.clone());
        io.limit = Some(limit);
        while conn.is_handshaking() {
            conn.complete_io(&mut io)
                .map_err(|e| handshake_error(watch, limit, &e))?;
        }
        io.limit = None;
        Ok(Box::new(rustls::StreamOwned::new(conn, io)))
    }

    fn policy(&self) -> Option<Policy> {
        let ceiling = (self.ceiling)()?;
        let refuse = self.refuse;
        Some(Arc::new(move |ip| refuse(&ceiling, ip)))
    }
}
