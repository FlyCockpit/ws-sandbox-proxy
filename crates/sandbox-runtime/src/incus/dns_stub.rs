//! B12 blocked-name hints on real hosts (coordinator ruling (c)): a
//! daemon-run, in-memory DNS stub for TEMPLATE_BUILD sandboxes in allowlist
//! mode.
//!
//! No sandbox's resolver logs queries: dnsmasq's `log-queries` sink can fall
//! back to syslog for good, or stall DNS on a full pipe, so the bridge
//! dnsmasq carries no `log-*` option at all. Instead a build VM's allowlist
//! resolver forwards every name it does not answer itself to a loopback stub
//! owned by the daemon (`server=127.0.0.1#<port>`, `incus/dns.rs`). Granted
//! names keep resolving from their `host-record` answers and operator-blocked
//! names from their `local=/<d>/` NXDOMAIN; neither is ever forwarded. The
//! stub answers every query at once, in a form dnsmasq relays (`reply`):
//! NXDOMAIN for a name outside the grants, NODATA for a granted name's other
//! record types (its AAAA). It records the queried name in memory when it is
//! outside the build's grants (bounded, deduplicated), and never writes
//! anything to disk. (It used to answer REFUSED, which dnsmasq does not
//! relay: the guest timed out instead, E3-A-02.)
//!
//! One stub per build sandbox, bound to `127.0.0.1` only, so the source of a
//! query identifies the sandbox. A query records a hint only when its source
//! socket belongs to the build bridge's dnsmasq (`dns_stub_peer.rs`), so
//! other local processes cannot inject hints (E3-A-04). The port is chosen by the kernel at the
//! first bind and recorded in the network plan's settings; a daemon restart
//! re-binds the same port from the recorded plan (`recover`), so the resolver
//! config never changes. While the daemon is down (or before it re-binds),
//! those lookups get no answer and time out in the guest: acceptable for
//! build VMs, whose granted names never depend on the stub.
//!
//! Only `before_issue::network_plan` asks for a stub, only for a build in
//! allowlist mode; the network compiler refuses a stub port in open mode.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use sandbox_protocol::SandboxErrorCode;

use super::dns_stub_peer::{PeerRoots, ResolverPeer};
use crate::error::RuntimeError;

/// Refusals waiting for the daemon's next drain; older ones are dropped.
const PENDING_MAX: usize = 256;
/// Largest query considered (dnsmasq forwards at most an EDNS-sized one).
const QUERY_MAX: usize = 4096;
/// How often a stub's thread re-checks its stop flag while idle.
const IDLE_POLL: Duration = Duration::from_millis(100);
/// Delay between restart-recovery attempts while some stub fails to bind.
const RECOVERY_RETRY: Duration = Duration::from_secs(30);
/// DNS RCODEs the stub answers with.
const RCODE_NOERROR: u8 = 0;
const RCODE_FORMERR: u8 = 1;
const RCODE_NXDOMAIN: u8 = 3;
const RCODE_NOTIMP: u8 = 4;
/// The standard query opcode.
const OPCODE_QUERY: u8 = 0;
/// The UDP payload size the stub advertises in its OPT record.
const EDNS_UDP_SIZE: u16 = 1232;

fn error(message: impl Into<String>) -> RuntimeError {
    RuntimeError::new(SandboxErrorCode::Internal, message)
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|err| err.into_inner())
}

#[derive(Default)]
struct Pending {
    order: VecDeque<(String, String)>,
    seen: HashSet<(String, String)>,
}

impl Pending {
    fn push(&mut self, sandbox_id: &str, name: String) {
        let pair = (sandbox_id.to_string(), name);
        if self.seen.contains(&pair) {
            return;
        }
        if self.order.len() >= PENDING_MAX
            && let Some(old) = self.order.pop_front()
        {
            self.seen.remove(&old);
        }
        self.seen.insert(pair.clone());
        self.order.push_back(pair);
    }
}

/// The stub's answer to one query, and the queried name (raw presentation
/// form) when it is a hint candidate. `None` for anything that is not a
/// query (a response, or shorter than a header).
///
/// dnsmasq treats an upstream REFUSED or SERVFAIL as a server failure: it
/// does not relay it, so the guest waited out its own timeout (E3-A-02).
/// The stub therefore answers like an authority for the build's view of
/// DNS, which dnsmasq relays as-is:
/// - a granted name, or an ancestor of one (an empty non-terminal), gets
///   NOERROR with no answers (NODATA): dnsmasq forwards a granted name only
///   for a type its `host-record` lacks (AAAA, MX, …), and NODATA says just
///   that, without denying the name's A records to any resolver;
/// - every other name gets NXDOMAIN.
///
/// No SOA rides in the authority section, so no resolver negative-caches
/// either answer (Incus also runs dnsmasq with `no-negcache`): every lookup
/// reaches the stub. A query carrying EDNS gets an OPT back (BADVERS for an
/// unknown version); anything malformed gets FORMERR and an opcode other
/// than QUERY gets NOTIMP, neither with a hint.
fn reply(query: &[u8], granted: &BTreeSet<String>) -> Option<(Vec<u8>, Option<String>)> {
    if query.len() < 12 || query[2] & 0x80 != 0 {
        return None;
    }
    let opcode = (query[2] >> 3) & 0x0f;
    let count = |at: usize| u16::from_be_bytes([query[at], query[at + 1]]);
    let question = (count(4) == 1).then(|| parse_question(query)).flatten();
    let edns = question
        .as_ref()
        .and_then(|(_, end)| query_edns_version(query, *end));
    let (rcode, name) = match (&question, opcode) {
        (_, opcode) if opcode != OPCODE_QUERY => (RCODE_NOTIMP, None),
        (None, _) => (RCODE_FORMERR, None),
        (Some(_), _) if edns.is_some_and(|version| version != 0) => (RCODE_NOERROR, None),
        (Some((name, _)), _) => {
            let lower = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
            let exists = granted.contains(&lower)
                || granted.iter().any(|granted| {
                    granted
                        .strip_suffix(lower.as_str())
                        .is_some_and(|rest| rest.ends_with('.'))
                });
            let rcode = if exists {
                RCODE_NOERROR
            } else {
                RCODE_NXDOMAIN
            };
            (rcode, Some(name.clone()))
        }
    };
    let badvers = edns.is_some_and(|version| version != 0);
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&query[..2]);
    // QR, the query's opcode, AA and its RD; TC clear.
    out.push(0x80 | (query[2] & 0x79) | 0x04);
    // RA; Z/AD/CD clear.
    out.push(0x80 | rcode);
    let echoed = question.as_ref().filter(|_| opcode == OPCODE_QUERY);
    out.extend_from_slice(&[0, u8::from(echoed.is_some()), 0, 0, 0, 0]);
    out.extend_from_slice(&[0, u8::from(edns.is_some())]);
    if let Some((_, end)) = echoed {
        out.extend_from_slice(&query[12..*end]);
    }
    if edns.is_some() {
        // OPT: root owner, our UDP size, extended RCODE (BADVERS is 16:
        // upper bits 1, header RCODE 0), version 0, DO clear, no options.
        out.extend_from_slice(&[0, 0, 41]);
        out.extend_from_slice(&EDNS_UDP_SIZE.to_be_bytes());
        out.extend_from_slice(&[u8::from(badvers), 0, 0, 0, 0, 0]);
    }
    Some((out, name))
}

/// The EDNS version of the query's OPT record, when its additional section
/// (starting at `at`, after the single question) carries one. A query has
/// no answer or authority records; one that does is treated as non-EDNS.
fn query_edns_version(query: &[u8], mut at: usize) -> Option<u8> {
    let count = |at: usize| u16::from_be_bytes([query[at], query[at + 1]]);
    if count(6) != 0 || count(8) != 0 {
        return None;
    }
    for _ in 0..count(10) {
        at = skip_name(query, at)?;
        let fixed = query.get(at..at + 10)?;
        let rtype = u16::from_be_bytes([fixed[0], fixed[1]]);
        let rdlen = usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
        if rtype == 41 {
            return Some(fixed[5]);
        }
        at += 10 + rdlen;
    }
    None
}

/// The offset just past the (possibly compressed) name at `at`.
fn skip_name(message: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let len = *message.get(at)?;
        match len {
            0 => return Some(at + 1),
            len if len & 0xc0 == 0xc0 => return Some(at + 2),
            len if len <= 63 => at += 1 + usize::from(len),
            _ => return None,
        }
    }
}

/// The single question's name and the offset just past it. Uncompressed
/// labels only (a query has nothing to point back to).
fn parse_question(query: &[u8]) -> Option<(String, usize)> {
    let mut at = 12;
    let mut name = String::new();
    loop {
        let len = usize::from(*query.get(at)?);
        at += 1;
        if len == 0 {
            break;
        }
        if len > 63 || name.len() + len + 1 > 255 {
            return None;
        }
        let label = std::str::from_utf8(query.get(at..at + len)?).ok()?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(label);
        at += len;
    }
    let end = at + 4;
    (query.len() >= end).then_some((name, end))
}

fn serve(
    socket: UdpSocket,
    sandbox_id: String,
    granted: BTreeSet<String>,
    stop: Arc<AtomicBool>,
    pending: Arc<Mutex<Pending>>,
    mut peer: ResolverPeer,
) {
    let mut buf = [0u8; QUERY_MAX];
    while !stop.load(Ordering::Acquire) {
        let (read, from) = match socket.recv_from(&mut buf) {
            Ok(received) => received,
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                        // An earlier answer's ICMP port-unreachable.
                        | std::io::ErrorKind::ConnectionRefused
                ) =>
            {
                continue;
            }
            Err(_) => break,
        };
        if !from.ip().is_loopback() {
            continue;
        }
        let Some((answer, name)) = reply(&buf[..read], &granted) else {
            continue;
        };
        // Only the build bridge's dnsmasq may add hints (E3-A-04); anyone
        // else on the node still gets the answer.
        if let Some(name) = name.and_then(|name| crate::refused_query_name(&name, &granted))
            && peer.may_hint(from)
        {
            lock(&pending).push(&sandbox_id, name);
        }
        let _ = socket.send_to(&answer, from);
    }
}

struct Stub {
    port: u16,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Stub {
    fn halt(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            // Bounded: the thread re-checks its flag every `IDLE_POLL`.
            let _ = handle.join();
        }
    }
}

#[derive(Default)]
struct Recovery {
    done: bool,
    next_at: Option<Instant>,
    failures: Vec<(String, String)>,
}

/// One recorded build stub to re-bind after a restart.
pub(crate) struct RecordedStub {
    pub(crate) sandbox_id: String,
    pub(crate) port: u16,
    pub(crate) granted: BTreeSet<String>,
}

/// Per-runtime set of DNS stubs and their pending refusals.
pub(crate) struct DnsStubs {
    stubs: Mutex<HashMap<String, Stub>>,
    pending: Arc<Mutex<Pending>>,
    recovery: Mutex<Recovery>,
    retry: Duration,
    /// Where the source check reads the resolver's identity and socket owners.
    peer_roots: PeerRoots,
    /// Test hook: the maintenance worker's read of the recorded stubs.
    #[cfg(test)]
    pub(crate) slow_recorded: SlowRecorded,
}

/// Test hook: makes the maintenance worker's `recorded_dns_stubs` read slow
/// (cancellable through the worker's permit) and reports its progress.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct SlowRecorded {
    pub(crate) delay: Mutex<Option<Duration>>,
    pub(crate) entered: AtomicBool,
    pub(crate) cancelled: AtomicBool,
}

impl Default for DnsStubs {
    fn default() -> Self {
        Self::with_peer_roots(PeerRoots::default())
    }
}

impl DnsStubs {
    fn with_peer_roots(peer_roots: PeerRoots) -> Self {
        Self {
            stubs: Mutex::default(),
            pending: Arc::default(),
            recovery: Mutex::default(),
            retry: RECOVERY_RETRY,
            peer_roots,
            #[cfg(test)]
            slow_recorded: SlowRecorded::default(),
        }
    }
}

impl std::fmt::Debug for DnsStubs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsStubs")
            .field("stubs", &lock(&self.stubs).len())
            .finish_non_exhaustive()
    }
}

impl DnsStubs {
    /// Start (or reuse) the stub of `sandbox_id` with the sandbox's granted
    /// names, bound to `127.0.0.1:port` (`None`: a kernel-chosen port).
    /// Returns the bound port for the resolver's `server=` line. Idempotent:
    /// a retried create reuses the running stub.
    pub(crate) fn prepare(
        &self,
        sandbox_id: &str,
        granted: BTreeSet<String>,
        port: Option<u16>,
    ) -> Result<u16, RuntimeError> {
        crate::validate_managed_instance_name(&crate::default_incus_instance_name(sandbox_id))?;
        let mut stubs = lock(&self.stubs);
        if let Some(stub) = stubs.get(sandbox_id) {
            return match port {
                Some(port) if port != stub.port => Err(error(format!(
                    "the DNS stub of sandbox {sandbox_id} runs on another port"
                ))),
                _ => Ok(stub.port),
            };
        }
        let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port.unwrap_or(0)))
            .map_err(|err| error(format!("cannot bind the DNS stub: {err}")))?;
        socket
            .set_read_timeout(Some(IDLE_POLL))
            .map_err(|err| error(format!("cannot configure the DNS stub: {err}")))?;
        let bound = match socket.local_addr() {
            Ok(SocketAddr::V4(addr)) if addr.port() != 0 => addr.port(),
            _ => return Err(error("the DNS stub has no loopback port")),
        };
        let stop = Arc::new(AtomicBool::new(false));
        let handle = {
            let (sandbox, stop, pending) =
                (sandbox_id.to_string(), stop.clone(), self.pending.clone());
            let peer = ResolverPeer::new(self.peer_roots.clone(), sandbox_id);
            std::thread::Builder::new()
                .name("wssp-dns-stub".into())
                .spawn(move || serve(socket, sandbox, granted, stop, pending, peer))
                .map_err(|err| error(format!("cannot start the DNS stub: {err}")))?
        };
        stubs.insert(
            sandbox_id.to_string(),
            Stub {
                port: bound,
                stop,
                handle: Some(handle),
            },
        );
        Ok(bound)
    }

    /// The running stub's port.
    #[cfg(test)]
    pub(crate) fn port(&self, sandbox_id: &str) -> Option<u16> {
        lock(&self.stubs).get(sandbox_id).map(|stub| stub.port)
    }

    /// Stop the stub of `sandbox_id` (its network is gone or going).
    pub(crate) fn release(&self, sandbox_id: &str) {
        let stub = lock(&self.stubs).remove(sandbox_id);
        if let Some(mut stub) = stub {
            stub.halt();
        }
        lock(&self.recovery)
            .failures
            .retain(|(id, _)| id != sandbox_id);
    }

    /// Restart recovery: re-bind every recorded build stub on its recorded
    /// port, so the unchanged resolver config reaches it again. Failures
    /// (the port is taken) are reported and retried every `retry` until all
    /// recorded stubs run.
    pub(crate) fn recover(&self, recorded: &dyn Fn() -> Vec<RecordedStub>) {
        {
            let recovery = lock(&self.recovery);
            if recovery.done || recovery.next_at.is_some_and(|at| Instant::now() < at) {
                return;
            }
        }
        let mut failures = Vec::new();
        for stub in recorded() {
            if let Err(err) = self.prepare(&stub.sandbox_id, stub.granted, Some(stub.port)) {
                eprintln!(
                    "wssp: DNS stub recovery for sandbox {} failed (retrying): {}",
                    stub.sandbox_id, err.message
                );
                failures.push((stub.sandbox_id, err.message));
            }
        }
        let mut recovery = lock(&self.recovery);
        recovery.done = failures.is_empty();
        recovery.next_at = Some(Instant::now() + self.retry);
        recovery.failures = failures;
    }

    /// Every recorded stub was re-bound (restart recovery is over).
    pub(crate) fn recovered(&self) -> bool {
        lock(&self.recovery).done
    }

    /// Sandboxes whose stub the last recovery attempt could not re-bind.
    #[cfg(test)]
    pub(crate) fn recovery_failures(&self) -> Vec<(String, String)> {
        lock(&self.recovery).failures.clone()
    }

    /// Every refusal observed since the last call (in memory only).
    pub(crate) fn drain(&self) -> Vec<(String, String)> {
        let mut pending = lock(&self.pending);
        pending.seen.clear();
        pending.order.drain(..).collect()
    }
}

impl Drop for DnsStubs {
    fn drop(&mut self) {
        let stubs: Vec<Stub> = lock(&self.stubs).drain().map(|(_, stub)| stub).collect();
        for mut stub in stubs {
            stub.halt();
        }
    }
}

/// How often the maintenance worker re-checks its rate-limited work.
#[cfg(not(test))]
const MAINTENANCE_TICK: Duration = Duration::from_secs(1);
#[cfg(test)]
const MAINTENANCE_TICK: Duration = Duration::from_millis(10);

/// The daemon's one background worker for B12 restart maintenance: the DNS
/// stubs' restart recovery, retried on its own schedule until done, then the
/// worker ends. The socket thread only starts it (once, never waiting) and
/// drains the stubs' in-memory queue: control frames such as
/// `egress.blocklist` are never read behind Incus calls. Bounded (one
/// thread) and cancellable: dropping the last owner stops the worker
/// between steps, revokes its permit (an in-flight Incus call is preempted)
/// and joins it.
#[derive(Default)]
pub(crate) struct HintMaintenance {
    shared: Arc<WorkerShared>,
    permit: Arc<crate::RuntimePermit>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

#[derive(Default)]
struct WorkerShared {
    stop: Mutex<bool>,
    wake: std::sync::Condvar,
}

impl WorkerShared {
    fn stopped(&self) -> bool {
        *lock(&self.stop)
    }
}

impl HintMaintenance {
    /// Start the worker on `client` unless it already ran or is running.
    /// Never waits for it.
    pub(crate) fn start(&self, client: &super::client::IncusClient) {
        let mut handle = lock(&self.handle);
        if handle.is_some() || self.shared.stopped() {
            return;
        }
        let mut client = client.clone();
        client.cancelled = Some(self.permit.clone());
        let shared = self.shared.clone();
        match std::thread::Builder::new()
            .name("wssp-dns-maintenance".into())
            .spawn(move || maintain(&client, &shared))
        {
            Ok(spawned) => *handle = Some(spawned),
            // Retried by the next drain.
            Err(err) => eprintln!("wssp: cannot start the DNS hint maintenance: {err}"),
        }
    }

    /// Test hook: wait until the worker has ended (all work done).
    #[cfg(test)]
    pub(crate) fn wait_finished(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if lock(&self.handle)
                .as_ref()
                .is_some_and(JoinHandle::is_finished)
            {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }
}

impl Drop for HintMaintenance {
    fn drop(&mut self) {
        *lock(&self.shared.stop) = true;
        self.shared.wake.notify_all();
        self.permit.revoke();
        let handle = lock(&self.handle).take();
        if let Some(handle) = handle {
            let _ = handle.join();
        }
    }
}

fn maintain(client: &super::client::IncusClient, shared: &WorkerShared) {
    loop {
        if shared.stopped() {
            return;
        }
        client.dns_stubs.recover(&|| recorded_stubs(client));
        if client.dns_stubs.recovered() {
            return;
        }
        let guard = lock(&shared.stop);
        if *guard {
            return;
        }
        drop(shared.wake.wait_timeout(guard, MAINTENANCE_TICK));
    }
}

fn recorded_stubs(client: &super::client::IncusClient) -> Vec<RecordedStub> {
    #[cfg(test)]
    {
        let hook = &client.dns_stubs.slow_recorded;
        let delay = *lock(&hook.delay);
        if let Some(delay) = delay {
            hook.entered.store(true, Ordering::SeqCst);
            let until = Instant::now() + delay;
            while Instant::now() < until {
                if client.io_cancelled() {
                    hook.cancelled.store(true, Ordering::SeqCst);
                    return Vec::new();
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
    client.recorded_dns_stubs()
}

#[cfg(test)]
mod tests {
    use super::super::dns_stub_peer::fake_proc::{FakeProc, loopback_hex, test_uid};
    use super::*;

    fn granted(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|name| name.to_string()).collect()
    }

    /// A dnsmasq-shaped forwarded query: id, RD, one question, an EDNS OPT.
    fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut out = id.to_be_bytes().to_vec();
        out.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1]);
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
        out
    }

    fn ask(port: u16, id: u16, name: &str) -> Vec<u8> {
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client
            .send_to(&query(id, name, 1), (Ipv4Addr::LOCALHOST, port))
            .unwrap();
        let mut buf = [0u8; 512];
        let (read, _) = client
            .recv_from(&mut buf)
            .expect("the stub answers at once");
        buf[..read].to_vec()
    }

    /// Stubs that trust this test's own sockets as the bridge resolver of
    /// `sandbox_id`: a fake Incus pid file names a fake dnsmasq running as
    /// the test's uid, over the host's real socket tables.
    fn trusting(tag: &str, sandbox_id: &str) -> (FakeProc, DnsStubs) {
        let proc = FakeProc::with_real_sockets(tag);
        proc.resolver(12, sandbox_id, test_uid());
        let stubs = DnsStubs::with_peer_roots(proc.roots());
        (proc, stubs)
    }

    #[test]
    fn the_stub_answers_at_once_and_records_only_non_granted_names() {
        let (_proc, stubs) = trusting("answers", "sbx-1");
        let port = stubs
            .prepare("sbx-1", granted(&["pypi.org"]), None)
            .unwrap();
        assert_ne!(port, 0);
        let answer = ask(port, 0x1234, "Evil.Example");
        assert_eq!(&answer[..2], &[0x12, 0x34]);
        assert_eq!(answer[2] & 0x80, 0x80, "a response");
        assert_eq!(answer[3] & 0x0f, RCODE_NXDOMAIN);
        assert_eq!(&answer[4..12], &[0, 1, 0, 0, 0, 0, 0, 1]);
        let q = query(0x1234, "Evil.Example", 1);
        assert_eq!(
            &answer[12..q.len() - 11],
            &q[12..q.len() - 11],
            "the question is echoed"
        );
        ask(port, 2, "pypi.org");
        assert_eq!(
            stubs.drain(),
            vec![("sbx-1".to_string(), "evil.example".to_string())]
        );
        assert!(stubs.drain().is_empty(), "drained once");
        // Idempotent prepare reuses the running stub.
        assert_eq!(
            stubs
                .prepare("sbx-1", granted(&["pypi.org"]), None)
                .unwrap(),
            port
        );
        stubs.release("sbx-1");
        assert_eq!(stubs.port("sbx-1"), None);
    }

    #[test]
    fn non_queries_are_ignored_and_malformed_questions_get_formerr() {
        let none = granted(&[]);
        assert!(reply(&[0; 4], &none).is_none());
        let mut response = query(1, "a.example", 1);
        response[2] |= 0x80;
        assert!(reply(&response, &none).is_none());
        let mut truncated = query(1, "a.example", 1);
        truncated.truncate(16);
        let (answer, name) = reply(&truncated, &none).unwrap();
        assert_eq!(name, None, "no hint");
        assert_eq!(
            answer,
            [0, 1, 0x85, 0x80 | RCODE_FORMERR, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        // A NOTIFY (opcode 4) is not a lookup: NOTIMP, no hint.
        let mut notify = query(2, "a.example", 6);
        notify[2] = 4 << 3;
        let (answer, name) = reply(&notify, &none).unwrap();
        assert_eq!(name, None);
        assert_eq!(&answer[2..4], &[0x80 | 4 << 3 | 0x04, 0x80 | RCODE_NOTIMP]);
        assert_eq!(&answer[4..6], &[0, 0], "no question echoed");
    }

    /// The exact reply bytes, independent of any resolver: what dnsmasq
    /// (and anything else) relays to the guest.
    #[test]
    fn the_reply_bytes_are_exact() {
        let grants = granted(&["archive.ubuntu.com"]);
        let question = |name: &str, qtype: u16| {
            let q = query(0, name, qtype);
            q[12..q.len() - 11].to_vec()
        };
        // ID, QR|AA|RD (RD copied), RA + RCODE, QD 1, AN 0, NS 0, AR 1.
        let header = |rcode: u8| vec![0xbe, 0xef, 0x85, 0x80 | rcode, 0, 1, 0, 0, 0, 0, 0, 1];
        // OPT: root, type 41, UDP 1232, ext-rcode 0, version 0, flags 0, rdlen 0.
        let opt = [0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0];
        let expect = |rcode: u8, name: &str, qtype: u16| {
            [header(rcode), question(name, qtype), opt.to_vec()].concat()
        };

        // A non-granted name: NXDOMAIN and a hint.
        let (answer, name) = reply(&query(0xbeef, "Blocked.Example", 1), &grants).unwrap();
        assert_eq!(answer, expect(RCODE_NXDOMAIN, "Blocked.Example", 1));
        assert_eq!(name.as_deref(), Some("Blocked.Example"));
        // A granted name's AAAA: NODATA and no hint.
        let (answer, name) = reply(&query(0xbeef, "Archive.Ubuntu.com", 28), &grants).unwrap();
        assert_eq!(answer, expect(RCODE_NOERROR, "Archive.Ubuntu.com", 28));
        assert_eq!(
            name.and_then(|name| crate::refused_query_name(&name, &grants)),
            None
        );
        // An ancestor of a grant exists (an empty non-terminal): NODATA, so
        // no resolver may infer the grant away from an NXDOMAIN below it
        // (RFC 8020); it is still a name outside the grants.
        let (answer, name) = reply(&query(0xbeef, "ubuntu.com", 1), &grants).unwrap();
        assert_eq!(answer, expect(RCODE_NOERROR, "ubuntu.com", 1));
        assert_eq!(
            name.and_then(|name| crate::refused_query_name(&name, &grants))
                .as_deref(),
            Some("ubuntu.com")
        );
        // A suffix that is not a label boundary is a different name.
        let (answer, _) = reply(&query(0xbeef, "buntu.com", 1), &grants).unwrap();
        assert_eq!(answer[3] & 0x0f, RCODE_NXDOMAIN);

        // No OPT in, no OPT out; RD clear stays clear.
        let mut plain = query(0xbeef, "blocked.example", 1);
        plain.truncate(plain.len() - 11);
        plain[2] = 0;
        plain[11] = 0;
        let (answer, _) = reply(&plain, &grants).unwrap();
        let mut head = header(RCODE_NXDOMAIN);
        head[2] = 0x84;
        head[11] = 0;
        assert_eq!(answer, [head, question("blocked.example", 1)].concat());

        // An unknown EDNS version: BADVERS (extended RCODE 1, header 0), no hint.
        let mut v1 = query(0xbeef, "blocked.example", 1);
        let version_at = v1.len() - 5;
        v1[version_at] = 1;
        let (answer, name) = reply(&v1, &grants).unwrap();
        assert_eq!(name, None);
        let mut badvers = opt;
        badvers[5] = 1;
        assert_eq!(
            answer,
            [
                header(RCODE_NOERROR),
                question("blocked.example", 1),
                badvers.to_vec()
            ]
            .concat()
        );
    }

    #[test]
    fn pending_refusals_are_deduplicated_and_bounded() {
        let mut pending = Pending::default();
        pending.push("sbx-1", "a.example".into());
        pending.push("sbx-1", "a.example".into());
        pending.push("sbx-2", "a.example".into());
        assert_eq!(pending.order.len(), 2);
        for i in 0..PENDING_MAX + 10 {
            pending.push("sbx-1", format!("n{i}.example"));
        }
        assert_eq!(pending.order.len(), PENDING_MAX);
        assert_eq!(pending.seen.len(), PENDING_MAX);
        assert_eq!(
            pending.order.back().unwrap().1,
            format!("n{}.example", PENDING_MAX + 9)
        );
    }

    /// The `dnsmasq` binary, when this host has one (it lives in `sbin`,
    /// which an unprivileged `PATH` often lacks).
    fn dnsmasq_binary() -> Option<std::path::PathBuf> {
        let path = std::env::var_os("PATH").unwrap_or_default();
        std::env::split_paths(&path)
            .chain(["/usr/sbin", "/sbin", "/usr/local/sbin"].map(Into::into))
            .map(|dir| dir.join("dnsmasq"))
            .find(|candidate| candidate.is_file())
    }

    /// A free loopback UDP port (racy by nature; the caller retries).
    fn free_udp_port() -> u16 {
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    struct Dnsmasq(std::process::Child);

    impl Drop for Dnsmasq {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// One query to `port` and its answer, with how long it took (`None`:
    /// no answer within 3 s).
    fn timed_ask(port: u16, id: u16, name: &str, qtype: u16) -> (Option<Vec<u8>>, Duration) {
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let started = Instant::now();
        client
            .send_to(&query(id, name, qtype), (Ipv4Addr::LOCALHOST, port))
            .unwrap();
        let mut buf = [0u8; 1024];
        let answer = client
            .recv_from(&mut buf)
            .ok()
            .map(|(read, _)| buf[..read].to_vec());
        (answer, started.elapsed())
    }

    /// E3-A-02: what the guest sees goes through the bridge's dnsmasq, not
    /// the stub directly. Runs the real binary unprivileged on a high
    /// loopback port with the build resolver's shape (`no-resolv`,
    /// `host-record`, `server=` to the stub, Incus's `strict-order` and
    /// `no-negcache`): a non-granted name fails at once with NXDOMAIN and a
    /// granted name's AAAA (no host-record of that type) gets NODATA at
    /// once, never a timeout.
    #[test]
    fn through_real_dnsmasq_refused_names_and_granted_aaaa_answer_at_once() {
        let Some(binary) = dnsmasq_binary() else {
            eprintln!(
                "SKIPPED through_real_dnsmasq_refused_names_and_granted_aaaa_answer_at_once: \
                 no dnsmasq binary on this host (install dnsmasq to run it); \
                 the_reply_bytes_are_exact covers the protocol"
            );
            return;
        };
        // F6: the hint path authenticates this very dnsmasq through an
        // Incus-shaped pid file (pid + kernel start time) and the real
        // `/proc`; only the "root" owner of the fake Incus dir is the test's.
        let incus = FakeProc::new("dnsmasq-incus");
        let stubs = DnsStubs::with_peer_roots(PeerRoots {
            proc_root: std::path::PathBuf::from("/proc"),
            incus_dir: incus.incus_dir(),
            trusted_owner: test_uid(),
        });
        let stub_port = stubs
            .prepare("sbx-dnsmasq", granted(&["granted.example"]), None)
            .unwrap();
        let bridge = crate::incus::network::sandbox_network_names("sbx-dnsmasq").0;
        let (_dnsmasq, port) = (0..20)
            .find_map(|_| {
                let port = free_udp_port();
                let child = std::process::Command::new(&binary)
                    .args([
                        "--keep-in-foreground",
                        "--conf-file=/dev/null",
                        "--pid-file=",
                        "--no-hosts",
                        "--no-resolv",
                        "--strict-order",
                        "--no-negcache",
                        "--local-ttl=0",
                        // Incus binds the (here absent) bridge with
                        // `--bind-interfaces`; `--bind-dynamic` tolerates
                        // its absence and still listens on loopback.
                        "--bind-dynamic",
                        "--listen-address=127.0.0.1",
                        "--host-record=granted.example,192.0.2.7",
                    ])
                    .arg(format!("--interface={bridge}"))
                    .arg(format!("--port={port}"))
                    .arg(format!("--server=127.0.0.1#{stub_port}"))
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .unwrap();
                let pid = child.id();
                let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
                let start_time: u64 = stat
                    .rsplit_once(')')
                    .unwrap()
                    .1
                    .split_whitespace()
                    .nth(19)
                    .unwrap()
                    .parse()
                    .unwrap();
                incus.pid_file("sbx-dnsmasq", pid, start_time);
                let dnsmasq = Dnsmasq(child);
                // Ready once the local A answer comes back.
                let deadline = Instant::now() + Duration::from_secs(5);
                while Instant::now() < deadline {
                    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
                    client
                        .set_read_timeout(Some(Duration::from_millis(100)))
                        .unwrap();
                    let _ = client
                        .send_to(&query(1, "granted.example", 1), (Ipv4Addr::LOCALHOST, port));
                    let mut buf = [0u8; 512];
                    if client.recv_from(&mut buf).is_ok() {
                        return Some((dnsmasq, port));
                    }
                }
                None
            })
            .expect("dnsmasq starts on a free loopback port");
        let (answer, took) = timed_ask(port, 0x0a0a, "granted.example", 1);
        let answer = answer.expect("the granted A answers");
        assert_eq!(answer[3] & 0x0f, 0, "NOERROR");
        assert_eq!(&answer[6..8], &[0, 1], "the host-record answer");
        let cases = [
            (
                "blocked.example",
                1,
                RCODE_NXDOMAIN,
                "an A of a non-granted name",
            ),
            (
                "granted.example",
                28,
                RCODE_NOERROR,
                "an AAAA of a granted name",
            ),
        ];
        for (name, qtype, rcode, what) in cases {
            let (answer, took) = timed_ask(port, 0x0b0b, name, qtype);
            let answer = answer.unwrap_or_else(|| panic!("{what}: dnsmasq answers ({took:?})"));
            assert!(took < Duration::from_millis(100), "{what}: took {took:?}");
            assert_eq!(&answer[..2], &[0x0b, 0x0b], "{what}");
            assert_eq!(answer[3] & 0x0f, rcode, "{what}: rcode");
            assert_eq!(&answer[6..8], &[0, 0], "{what}: no answers");
        }
        assert!(took < Duration::from_secs(1));
        assert_eq!(
            stubs.drain(),
            vec![("sbx-dnsmasq".to_string(), "blocked.example".to_string())],
            "only the non-granted name is a hint"
        );
    }

    /// E3-A-04: a local process that is not the build bridge's dnsmasq
    /// gets its answer but adds no hint.
    #[test]
    fn only_the_bridge_resolver_adds_hints() {
        let proc = FakeProc::new("stub");
        let stubs = DnsStubs::with_peer_roots(proc.roots());
        let port = stubs.prepare("sbx-1", granted(&[]), None).unwrap();
        // The resolver runs as another uid than this test's client socket.
        proc.resolver(12, "sbx-1", 4_000_000);
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let source = client.local_addr().unwrap().port();
        let ask_from = |owner: u32, name: &str| {
            proc.sockets(&[("udp", &loopback_hex(), source, owner)]);
            client
                .send_to(&query(9, name, 1), (Ipv4Addr::LOCALHOST, port))
                .unwrap();
            let mut buf = [0u8; 512];
            let (read, _) = client.recv_from(&mut buf).expect("answered at once");
            assert_eq!(buf[3] & 0x0f, RCODE_NXDOMAIN);
            assert!(read > 12);
        };
        ask_from(1000, "injected.example");
        assert!(
            stubs.drain().is_empty(),
            "a local user's query adds no hint"
        );
        ask_from(4_000_000, "real.example");
        assert_eq!(
            stubs.drain(),
            vec![("sbx-1".to_string(), "real.example".to_string())]
        );
    }

    /// Daemon restart: a new runtime re-binds the recorded port, so the
    /// recorded resolver config (`server=127.0.0.1#<port>`) reaches it again;
    /// a taken port is reported and retried.
    #[test]
    fn a_restarted_daemon_rebinds_the_recorded_port() {
        // A parallel test's kernel-chosen bind may take the freed port
        // first; then start over on another one.
        let (port, blocker) = (0..50)
            .find_map(|_| {
                let first = DnsStubs::default();
                let port = first.prepare("sbx-1", granted(&[]), None).unwrap();
                drop(first);
                let blocker = UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).ok()?;
                Some((port, blocker))
            })
            .expect("a freed stub port can be re-bound");
        let (_proc, mut second) = trusting("restart", "sbx-1");
        second.retry = Duration::ZERO;
        let recorded = || {
            vec![RecordedStub {
                sandbox_id: "sbx-1".into(),
                port,
                granted: BTreeSet::new(),
            }]
        };
        second.recover(&recorded);
        assert_eq!(second.recovery_failures().len(), 1);
        drop(blocker);
        // A parallel test's kernel-chosen bind may briefly take the freed
        // port; recovery keeps retrying until the port is free again.
        let deadline = Instant::now() + Duration::from_secs(10);
        second.recover(&recorded);
        while !second.recovery_failures().is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
            second.recover(&recorded);
        }
        assert!(second.recovery_failures().is_empty());
        assert_eq!(second.port("sbx-1"), Some(port));
        ask(port, 7, "after.restart.example");
        assert_eq!(
            second.drain(),
            vec![("sbx-1".to_string(), "after.restart.example".to_string())]
        );
        // Recovered once: later drains do not re-scan.
        second.recover(&|| panic!("recovery is done"));
    }
}
