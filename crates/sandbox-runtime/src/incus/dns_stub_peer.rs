//! E3-A-04 / F6: which loopback queries to the DNS stub may become hints.
//!
//! The stub listens on `127.0.0.1`, which every local process can reach, so
//! any local user could inject "blocked" lines into a running build's step
//! log. Only the build bridge's own dnsmasq may add hints, and it is
//! identified by evidence no unprivileged local process can forge:
//!
//! 1. Incus records the pid and kernel start time of every bridge's
//!    dnsmasq in `<incus dir>/networks/<bridge>/dnsmasq.pid`, a root-owned
//!    file in a root-owned directory (default `/var/lib/incus`, or the
//!    daemon's `INCUS_DIR`). Every directory from `/` down, as written and
//!    as resolved, must be root-owned and not replaceable by anyone else;
//!    the file is read through one non-symlink descriptor that is checked
//!    itself, and a file without a start time is not evidence.
//! 2. `/proc/<pid>/stat`'s start time must equal the recorded one (a reused
//!    pid is not the resolver), and `/proc/<pid>/cmdline` must still be a
//!    `dnsmasq` serving `--interface=<bridge>` (a consistency check only;
//!    argv is never the evidence).
//! 3. That process's effective uid (`/proc/<pid>/status`) must own every UDP
//!    socket bound to the query's source port on a loopback or wildcard
//!    address. Incus runs dnsmasq as its own system user (`-u incus`); a
//!    local user who is not that uid (or root) cannot own such a socket. The
//!    owners come from the kernel's `sock_diag` UDP dump filtered by that
//!    port: every socket on one port sits in one hash slot, dumped under that
//!    slot's lock, so the answer is consistent. `/proc/net/udp{,6}` is not:
//!    it is read a page at a time and resumes by position, so sockets created
//!    or closed elsewhere meanwhile can drop a row (seen on a busy host: the
//!    resolver's own socket missing, or, in principle, another uid's sharing
//!    its port). The tables are read only where the kernel has no UDP diag.
//!
//! The identity is re-read at most once a second, so a dnsmasq restart
//! (new pid, new start time) is picked up. It FAILS CLOSED: when the
//! identity cannot be established (no pid file, `hidepid`, a mismatch) the
//! query still gets its normal answer but records no hint, and the stub
//! logs that once (then at most every `WARN_EVERY`).
//!
//! Residual: a local process that queries the bridge's own address goes
//! through dnsmasq like the guest does, which no check at the stub can tell
//! apart.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// How often the resolver identity is established again.
const RESCAN_EVERY: Duration = Duration::from_secs(1);
/// How often an unestablished identity is reported again.
const WARN_EVERY: Duration = Duration::from_secs(60);

/// Where the source check reads its evidence.
#[derive(Clone, Debug)]
pub(crate) struct PeerRoots {
    /// The procfs root (`/proc`).
    pub(crate) proc_root: PathBuf,
    /// The Incus server's var dir (`/var/lib/incus`).
    pub(crate) incus_dir: PathBuf,
    /// The uid that must own the pid file and its directory (root).
    pub(crate) trusted_owner: u32,
    /// Where the owners of a port's UDP sockets are read.
    pub(crate) sockets: SocketTable,
    /// Where the trusted chain starts: this directory and every one below
    /// it on the way to the pid file must be trusted. `/` in production
    /// (the whole chain). A test's fake Incus dir starts at its own private
    /// directory: the host's directories above it (`TMPDIR` under a
    /// group-writable home on a `umask 002` host) are not the fake's to vouch
    /// for, and the product correctly distrusts them.
    pub(crate) chain_root: PathBuf,
}

impl Default for PeerRoots {
    fn default() -> Self {
        Self {
            proc_root: PathBuf::from("/proc"),
            incus_dir: std::env::var_os("INCUS_DIR")
                .filter(|dir| !dir.is_empty())
                .map_or_else(|| PathBuf::from("/var/lib/incus"), PathBuf::from),
            trusted_owner: 0,
            sockets: SocketTable::Kernel(kernel_socket_owners),
            chain_root: PathBuf::from("/"),
        }
    }
}

/// Where the owners of a port's UDP sockets are read.
#[derive(Clone, Copy, Debug)]
pub(crate) enum SocketTable {
    /// The kernel's `sock_diag` UDP dump through this lookup
    /// (`kernel_socket_owners`; a test may stand in for the kernel), and
    /// `<proc_root>/net/udp{,6}` only when the kernel has no UDP diag.
    Kernel(fn(u16) -> Result<Vec<u32>, DiagError>),
    /// `<proc_root>/net/udp{,6}` (the tests' fake tables).
    #[cfg(test)]
    Proc,
}

/// Per-stub source check: the build bridge's resolver uid, established
/// lazily (the stub starts before the bridge and its dnsmasq exist) and
/// refreshed after `RESCAN_EVERY`.
pub(crate) struct ResolverPeer {
    roots: PeerRoots,
    bridge: String,
    uid: Option<u32>,
    scanned_at: Option<Instant>,
    warned_at: Option<Instant>,
    /// The kernel has no UDP diag (reported once).
    diag_warned: bool,
    /// A kernel lookup failed (reported at most every `WARN_EVERY`).
    diag_failed_at: Option<Instant>,
}

impl ResolverPeer {
    pub(crate) fn new(roots: PeerRoots, sandbox_id: &str) -> Self {
        Self {
            roots,
            bridge: super::network::sandbox_network_names(sandbox_id).0,
            uid: None,
            scanned_at: None,
            warned_at: None,
            diag_warned: false,
            diag_failed_at: None,
        }
    }

    /// Whether a query from `from` may record a hint.
    pub(crate) fn may_hint(&mut self, from: SocketAddr) -> bool {
        if self
            .scanned_at
            .is_none_or(|at| at.elapsed() >= RESCAN_EVERY)
        {
            self.scanned_at = Some(Instant::now());
            self.uid = resolver_uid(&self.roots, &self.bridge);
        }
        let Some(uid) = self.uid else {
            // Fail closed: answered, never recorded.
            if self.warned_at.is_none_or(|at| at.elapsed() >= WARN_EVERY) {
                self.warned_at = Some(Instant::now());
                eprintln!(
                    "wssp: blocked-name hints for bridge {} are off: its dnsmasq cannot be \
                     verified from the Incus pid file (queries are still answered)",
                    self.bridge
                );
            }
            return false;
        };
        let owners = match self.roots.sockets {
            #[cfg(test)]
            SocketTable::Proc => socket_owners(&self.roots.proc_root, from.port()),
            SocketTable::Kernel(lookup) => match lookup(from.port()) {
                Ok(owners) => owners,
                // Only a kernel without UDP diag falls back to the tables.
                Err(DiagError::Unsupported(error)) => {
                    if !self.diag_warned {
                        self.diag_warned = true;
                        eprintln!(
                            "wssp: the kernel's UDP socket diag is unavailable ({error}); \
                             blocked-name hints for bridge {} read /proc/net/udp, which can \
                             miss a socket on a busy host",
                            self.bridge
                        );
                    }
                    socket_owners(&self.roots.proc_root, from.port())
                }
                // Any other failure is no evidence: answered, never recorded.
                Err(DiagError::Failed(error)) => {
                    if self
                        .diag_failed_at
                        .is_none_or(|at| at.elapsed() >= WARN_EVERY)
                    {
                        self.diag_failed_at = Some(Instant::now());
                        eprintln!(
                            "wssp: a blocked-name hint for bridge {} was dropped: the kernel's \
                             UDP socket lookup failed ({error})",
                            self.bridge
                        );
                    }
                    Vec::new()
                }
            },
        };
        !owners.is_empty() && owners.iter().all(|owner| *owner == uid)
    }
}

/// A datagram from `ip` can come over loopback: a loopback or wildcard bind.
fn loopback_source(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback() || ip.is_unspecified(),
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.to_ipv4_mapped().is_some_and(|ip| ip.is_loopback())
        }
    }
}

/// `SOCK_DIAG_BY_FAMILY` (linux/sock_diag.h).
const SOCK_DIAG_BY_FAMILY: u16 = 20;
/// `struct nlmsghdr`.
const NLMSG_HEADER: usize = 16;
/// `struct inet_diag_req_v2`.
const INET_DIAG_REQ: usize = 56;
/// `struct inet_diag_msg`: family, state, timer, retrans, the 48-byte
/// `inet_diag_sockid`, expires, rqueue, wqueue, uid, inode.
const INET_DIAG_MSG: usize = 72;

/// One `SOCK_DIAG_BY_FAMILY` dump request: every UDP socket of `family`
/// whose local port is `port`, in any state.
fn diag_request(family: u8, port: u16, seq: u32) -> Vec<u8> {
    let mut request = Vec::with_capacity(NLMSG_HEADER + INET_DIAG_REQ);
    let flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
    request.extend_from_slice(&((NLMSG_HEADER + INET_DIAG_REQ) as u32).to_ne_bytes());
    request.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    request.extend_from_slice(&flags.to_ne_bytes());
    request.extend_from_slice(&seq.to_ne_bytes());
    request.extend_from_slice(&0u32.to_ne_bytes());
    // sdiag_family, sdiag_protocol, idiag_ext, pad, idiag_states (all).
    request.extend_from_slice(&[family, libc::IPPROTO_UDP as u8, 0, 0]);
    request.extend_from_slice(&u32::MAX.to_ne_bytes());
    // inet_diag_sockid: the source port (network order) filters the dump
    // in the kernel; destination, addresses, interface and cookie are 0.
    request.extend_from_slice(&port.to_be_bytes());
    request.resize(NLMSG_HEADER + INET_DIAG_REQ, 0);
    request
}

/// Why the kernel's lookup gave no answer.
#[derive(Debug)]
pub(crate) enum DiagError {
    /// This kernel has no UDP sock_diag (no netlink family or UDP handler).
    Unsupported(std::io::Error),
    /// Anything else (a timeout, a split or interrupted dump, a malformed
    /// reply): no evidence either way.
    Failed(std::io::Error),
}

impl DiagError {
    fn from_errno(error: std::io::Error) -> Self {
        match error.raw_os_error() {
            Some(libc::ENOENT | libc::EOPNOTSUPP | libc::EPROTONOSUPPORT | libc::EAFNOSUPPORT) => {
                Self::Unsupported(error)
            }
            _ => Self::Failed(error),
        }
    }
}

fn diag_invalid(what: &str) -> DiagError {
    DiagError::Failed(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        what.to_string(),
    ))
}

/// What one received datagram of a dump held.
#[derive(Debug, PartialEq, Eq)]
struct DiagBatch {
    /// Socket messages for this request.
    sockets: usize,
    /// The dump's `NLMSG_DONE` arrived (successfully).
    done: bool,
}

/// Appends the `(local address, uid)` of each socket in one datagram of a
/// dump's replies to `out`. A failed or interrupted dump is an error: its
/// `NLMSG_DONE` carries a negative errno, `NLM_F_DUMP_INTR` marks a dump the
/// kernel knows to be inconsistent.
fn diag_replies(
    replies: &[u8],
    family: u8,
    port: u16,
    seq: u32,
    out: &mut Vec<(IpAddr, u32)>,
) -> Result<DiagBatch, DiagError> {
    let u32_at = |at: usize| -> u32 {
        u32::from_ne_bytes(replies[at..at + 4].try_into().unwrap_or_default())
    };
    let status = |body: &[u8]| -> Result<i32, DiagError> {
        body.get(..4)
            .map(|code| i32::from_ne_bytes(code.try_into().unwrap_or_default()))
            .ok_or_else(|| diag_invalid("a truncated sock_diag status"))
    };
    let mut batch = DiagBatch {
        sockets: 0,
        done: false,
    };
    let mut at = 0;
    while at + NLMSG_HEADER <= replies.len() {
        let len = u32_at(at) as usize;
        if len < NLMSG_HEADER || at + len > replies.len() {
            return Err(diag_invalid("a truncated sock_diag reply"));
        }
        let kind = u16::from_ne_bytes([replies[at + 4], replies[at + 5]]);
        let flags = u16::from_ne_bytes([replies[at + 6], replies[at + 7]]);
        let body = &replies[at + NLMSG_HEADER..at + len];
        if u32_at(at + 8) == seq {
            if flags & libc::NLM_F_DUMP_INTR as u16 != 0 {
                return Err(diag_invalid("an interrupted sock_diag dump"));
            }
            match kind {
                kind if kind == libc::NLMSG_DONE as u16 => {
                    let code = status(body)?;
                    if code < 0 {
                        return Err(DiagError::from_errno(std::io::Error::from_raw_os_error(
                            -code,
                        )));
                    }
                    batch.done = true;
                    return Ok(batch);
                }
                kind if kind == libc::NLMSG_ERROR as u16 => {
                    let code = status(body)?;
                    return Err(DiagError::from_errno(std::io::Error::from_raw_os_error(
                        -code,
                    )));
                }
                SOCK_DIAG_BY_FAMILY => {
                    if body.len() < INET_DIAG_MSG || body[0] != family {
                        return Err(diag_invalid("an unexpected sock_diag message"));
                    }
                    // id: sport, dport (network order), src[16], dst[16], ...
                    let sport = u16::from_be_bytes([body[4], body[5]]);
                    let src = &body[8..24];
                    let ip = if family == libc::AF_INET as u8 {
                        IpAddr::V4(Ipv4Addr::new(src[0], src[1], src[2], src[3]))
                    } else {
                        let bytes: [u8; 16] = src.try_into().unwrap_or_default();
                        IpAddr::V6(Ipv6Addr::from(bytes))
                    };
                    let uid = u32::from_ne_bytes(body[64..68].try_into().unwrap_or_default());
                    batch.sockets += 1;
                    if sport == port {
                        out.push((ip, uid));
                    }
                }
                _ => {}
            }
        }
        at += (len + 3) & !3;
    }
    Ok(batch)
}

/// The longest datagram of socket messages accepted as a whole hash slot.
/// The kernel stops walking a slot (and later resumes it by position, which
/// can drop a row) only when its reply buffer cannot take the next message;
/// that buffer is at least `NLMSG_GOODSIZE` (about 3.7 KiB with 4 KiB pages),
/// and one UDP message with every attribute is a few hundred bytes. A reply
/// of at most 2 KiB therefore left room for another message: the walk
/// finished. A longer one may have stopped for space and is refused.
const DIAG_WHOLE_SLOT_BYTES: usize = 2048;

/// One dump's datagrams from `receive` (which fills the buffer and returns
/// the length) until its `NLMSG_DONE`, appended to `out`. The port's sockets
/// must arrive in one datagram short enough to prove the kernel walked their
/// hash slot in one go (`DIAG_WHOLE_SLOT_BYTES`).
fn collect_dump(
    family: u8,
    port: u16,
    seq: u32,
    out: &mut Vec<(IpAddr, u32)>,
    mut receive: impl FnMut(&mut [u8]) -> Result<usize, DiagError>,
) -> Result<(), DiagError> {
    let mut buf = vec![0u8; 32 * 1024];
    let mut batches_with_sockets = 0;
    loop {
        let read = receive(&mut buf)?;
        let datagram = &buf[..read.min(buf.len())];
        let batch = diag_replies(datagram, family, port, seq, out)?;
        if batch.sockets > 0 {
            batches_with_sockets += 1;
            if datagram.len() > DIAG_WHOLE_SLOT_BYTES {
                return Err(diag_invalid(
                    "the port's sockets may not have fit one sock_diag reply",
                ));
            }
        }
        if batches_with_sockets > 1 {
            return Err(diag_invalid(
                "the port's sockets did not fit one sock_diag reply",
            ));
        }
        if batch.done {
            return Ok(());
        }
    }
}

/// The owners of every UDP socket bound to `port` on an address a loopback
/// datagram can come from, from the kernel's `sock_diag` dump (IPv4, then
/// IPv6). The kernel filters by port, and every socket on one port sits in
/// one hash slot that it walks under that slot's lock, so an answer that
/// arrives whole in one reply is a consistent snapshot. Only when the port's
/// sockets overflow a reply does the kernel unlock and resume the slot by
/// position, which can drop a row: an answer that may have been split is
/// refused (`collect_dump`).
fn kernel_socket_owners(port: u16) -> Result<Vec<u32>, DiagError> {
    use rustix::io::Errno;
    use rustix::net::{
        AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType, netlink, recv, sendto,
        socket_with, sockopt,
    };
    let fd = socket_with(
        AddressFamily::NETLINK,
        SocketType::DGRAM,
        SocketFlags::CLOEXEC,
        Some(netlink::SOCK_DIAG),
    )
    .map_err(|errno| DiagError::from_errno(errno.into()))?;
    sockopt::set_socket_timeout(&fd, sockopt::Timeout::Recv, Some(Duration::from_secs(2)))
        .map_err(|errno| DiagError::Failed(errno.into()))?;
    let kernel = netlink::SocketAddrNetlink::new(0, 0);
    let mut sockets = Vec::new();
    for (seq, family) in [(1, libc::AF_INET as u8), (2, libc::AF_INET6 as u8)] {
        let request = diag_request(family, port, seq);
        loop {
            match sendto(&fd, &request, SendFlags::empty(), &kernel) {
                Err(Errno::INTR) => continue,
                result => {
                    result.map_err(|errno| DiagError::Failed(errno.into()))?;
                    break;
                }
            }
        }
        collect_dump(family, port, seq, &mut sockets, |buf| {
            loop {
                match recv(&fd, &mut *buf, RecvFlags::empty()) {
                    Err(Errno::INTR) => continue,
                    result => {
                        break result
                            .map(|(read, _)| read)
                            .map_err(|errno| DiagError::Failed(errno.into()));
                    }
                }
            }
        })?;
    }
    Ok(sockets
        .into_iter()
        .filter(|(ip, _)| loopback_source(*ip))
        .map(|(_, uid)| uid)
        .collect())
}

/// Owned by root or `owner`, and no one else can replace its entries:
/// writable by no one else, or sticky (`/tmp`), where only an entry's owner
/// can rename it and the next component is checked in turn.
fn trusted_dir(meta: &std::fs::Metadata, owner: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    meta.is_dir()
        && (meta.uid() == 0 || meta.uid() == owner)
        && (meta.mode() & 0o022 == 0 || meta.mode() & 0o1000 != 0)
}

/// `path` and its ancestors up to and including `root`; every ancestor
/// when `root` is not one of them (`/` for a relative path).
fn ancestors_to<'a>(path: &'a Path, root: &'a Path) -> impl Iterator<Item = &'a Path> {
    let mut reached = false;
    path.ancestors().take_while(move |ancestor| {
        let take = !reached;
        reached = *ancestor == root;
        take
    })
}

/// F6 review: every directory from `root` (`/` in production) down to
/// `dir`, both as written and as resolved, is trusted, so nothing
/// unprivileged can swap a component (or the pid file) between this check
/// and the read that follows. A `dir` that does not resolve below `root` is
/// not trusted.
fn trusted_chain(dir: &Path, root: &Path, owner: u32) -> bool {
    let (Ok(resolved), Ok(resolved_root)) =
        (std::fs::canonicalize(dir), std::fs::canonicalize(root))
    else {
        return false;
    };
    if !resolved.starts_with(&resolved_root) {
        return false;
    }
    let lexical_ok = ancestors_to(dir, root).all(|path| {
        path.as_os_str().is_empty()
            || std::fs::symlink_metadata(path).is_ok_and(|meta| {
                use std::os::unix::fs::MetadataExt;
                if meta.file_type().is_symlink() {
                    meta.uid() == 0 || meta.uid() == owner
                } else {
                    trusted_dir(&meta, owner)
                }
            })
    });
    lexical_ok
        && ancestors_to(&resolved, &resolved_root)
            .all(|path| std::fs::symlink_metadata(path).is_ok_and(|meta| trusted_dir(&meta, owner)))
}

/// `(pid, start_time)` from Incus's YAML pid file (`pid: N`,
/// `start_time: N`). Both are required: without the start time a reused pid
/// cannot be told from the resolver (F6 review), so the file is not trusted.
fn parse_pid_file(text: &str) -> Option<(u32, u64)> {
    let field = |key: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(key))
            .map(str::trim)
    };
    let pid = field("pid:")?.parse().ok().filter(|pid| *pid > 0)?;
    let start_time = field("start_time:")?.parse().ok()?;
    Some((pid, start_time))
}

/// Reads the pid file through one descriptor that is not a symlink, and
/// checks that same opened file: a regular file owned by `owner`, writable
/// by no one else.
fn read_pid_file(path: &Path, owner: u32) -> Option<String> {
    use std::io::Read as _;
    use std::os::unix::fs::MetadataExt;
    if std::fs::symlink_metadata(path)
        .ok()?
        .file_type()
        .is_symlink()
    {
        return None;
    }
    let file = std::fs::File::open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.uid() != owner || meta.mode() & 0o022 != 0 {
        return None;
    }
    let mut text = String::new();
    file.take(64 * 1024).read_to_string(&mut text).ok()?;
    Some(text)
}

/// The kernel start time (clock ticks after boot) of `/proc/<pid>/stat`.
fn proc_start_time(stat: &str) -> Option<u64> {
    // Field 2 (comm) may hold spaces and parentheses: count after the last ')'.
    let (_, rest) = stat.rsplit_once(')')?;
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// The effective uid of the dnsmasq Incus runs for `bridge`, established
/// from the root-owned pid file (never from a process's own argv).
fn resolver_uid(roots: &PeerRoots, bridge: &str) -> Option<u32> {
    let dir = roots.incus_dir.join("networks").join(bridge);
    if !trusted_chain(&dir, &roots.chain_root, roots.trusted_owner) {
        return None;
    }
    let (pid, start_time) = parse_pid_file(&read_pid_file(
        &dir.join("dnsmasq.pid"),
        roots.trusted_owner,
    )?)?;
    let process = roots.proc_root.join(pid.to_string());
    let stat = std::fs::read_to_string(process.join("stat")).ok()?;
    if proc_start_time(&stat) != Some(start_time) {
        return None;
    }
    let cmdline = std::fs::read(process.join("cmdline")).ok()?;
    let mut args = cmdline.split(|b| *b == 0);
    let program = args.next()?;
    let interface = format!("--interface={bridge}");
    if program.rsplit(|b| *b == b'/').next() != Some(b"dnsmasq".as_slice())
        || !args.any(|arg| arg == interface.as_bytes())
    {
        return None;
    }
    let status = std::fs::read_to_string(process.join("status")).ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// The owners of every UDP socket bound to `port` on an address a loopback
/// datagram can come from (loopback or wildcard, IPv4 or IPv6).
fn socket_owners(proc_root: &Path, port: u16) -> Vec<u32> {
    let mut owners = Vec::new();
    for table in ["net/udp", "net/udp6"] {
        let Ok(text) = std::fs::read_to_string(proc_root.join(table)) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (Some(local), Some(uid)) = (fields.get(1), fields.get(7)) else {
                continue;
            };
            let Some((address, local_port)) = local.split_once(':') else {
                continue;
            };
            if u16::from_str_radix(local_port, 16).ok() != Some(port) {
                continue;
            }
            if proc_address(address).is_some_and(loopback_source)
                && let Ok(uid) = uid.parse()
            {
                owners.push(uid);
            }
        }
    }
    owners
}

/// A `/proc/net/udp{,6}` address: the kernel prints each 32-bit word of the
/// network-order address as a host-order hex number.
fn proc_address(hex: &str) -> Option<IpAddr> {
    let word = |at: usize| -> Option<[u8; 4]> {
        Some(
            u32::from_str_radix(hex.get(at..at + 8)?, 16)
                .ok()?
                .to_ne_bytes(),
        )
    };
    match hex.len() {
        8 => Some(IpAddr::V4(Ipv4Addr::from(word(0)?))),
        32 => {
            let words = [word(0)?, word(8)?, word(16)?, word(24)?];
            let bytes: [u8; 16] = words.concat().try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

/// A fake `/proc` and Incus var dir for the stub's tests. The "root" that
/// must own the pid file is the test's own uid.
#[cfg(test)]
pub(crate) mod fake_proc {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    use super::*;

    pub(crate) struct FakeProc(pub(crate) PathBuf);

    impl FakeProc {
        pub(crate) fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "wssp-fake-proc-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(dir.join("net")).unwrap();
            std::fs::create_dir_all(dir.join("incus").join("networks")).unwrap();
            // Like `/var/lib/incus`: not replaceable by others, whatever the umask.
            for path in [
                dir.clone(),
                dir.join("incus"),
                dir.join("incus").join("networks"),
            ] {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            Self(dir)
        }

        pub(crate) fn path(&self) -> &Path {
            &self.0
        }

        /// The fake Incus var dir.
        pub(crate) fn incus_dir(&self) -> PathBuf {
            self.0.join("incus")
        }

        /// Roots reading this fake `/proc` and Incus dir.
        pub(crate) fn roots(&self) -> PeerRoots {
            PeerRoots {
                proc_root: self.0.clone(),
                incus_dir: self.incus_dir(),
                trusted_owner: test_uid(),
                sockets: SocketTable::Proc,
                // The fake's own 0755 directory: the chain the fake builds.
                chain_root: self.0.clone(),
            }
        }

        /// Roots reading this fake `/proc` and Incus dir, with the owners of
        /// real sockets from the kernel (as in production).
        pub(crate) fn kernel_roots(&self) -> PeerRoots {
            PeerRoots {
                sockets: SocketTable::Kernel(kernel_socket_owners),
                ..self.roots()
            }
        }

        /// A process `pid` running `args` as `uid`, started at tick `pid`.
        pub(crate) fn process(&self, pid: u32, args: &[&str], uid: u32) {
            let dir = self.0.join(pid.to_string());
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("cmdline"), args.join("\0") + "\0").unwrap();
            std::fs::write(
                dir.join("status"),
                format!("Name:\tx\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"),
            )
            .unwrap();
            let mut stat = format!("{pid} (a (b) c) S 1");
            for field in 5..=22 {
                stat.push_str(&format!(" {}", if field == 22 { pid } else { 0 }));
            }
            std::fs::write(dir.join("stat"), stat + " 0 0\n").unwrap();
        }

        /// Incus's pid file for the bridge of `sandbox_id`.
        pub(crate) fn pid_file(&self, sandbox_id: &str, pid: u32, start_time: u64) {
            let bridge = crate::incus::network::sandbox_network_names(sandbox_id).0;
            let dir = self.incus_dir().join("networks").join(bridge);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o711)).unwrap();
            let file = dir.join("dnsmasq.pid");
            std::fs::write(
                &file,
                format!("name: dnsmasq\nargs: [--keep-in-foreground]\npid: {pid}\nstart_time: {start_time}\nuid: 0\n"),
            )
            .unwrap();
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        }

        /// The bridge dnsmasq of `sandbox_id`, as Incus starts and records it.
        pub(crate) fn resolver(&self, pid: u32, sandbox_id: &str, uid: u32) {
            let bridge = crate::incus::network::sandbox_network_names(sandbox_id).0;
            self.process(
                pid,
                &[
                    "dnsmasq",
                    "--keep-in-foreground",
                    &format!("--interface={bridge}"),
                    "-u",
                    "incus",
                ],
                uid,
            );
            self.pid_file(sandbox_id, pid, u64::from(pid));
        }

        /// `(table, local address hex, port, uid)` rows.
        pub(crate) fn sockets(&self, rows: &[(&str, &str, u16, u32)]) {
            for table in ["udp", "udp6"] {
                let mut text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n".to_string();
                for (i, (_, address, port, uid)) in
                    rows.iter().filter(|row| row.0 == table).enumerate()
                {
                    let remote = "0".repeat(address.len());
                    text.push_str(&format!(
                        "{i:5}: {address}:{port:04X} {remote}:0000 07 00000000:00000000 00:00000000 00000000 {uid:5} 0 {i} 2 0000000000000000 0\n"
                    ));
                }
                std::fs::write(self.0.join("net").join(table), text).unwrap();
            }
        }
    }

    impl Drop for FakeProc {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The uid this test runs as.
    pub(crate) fn test_uid() -> u32 {
        let probe = std::env::temp_dir().join(format!(
            "wssp-uid-probe-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&probe, b"").unwrap();
        let uid = std::fs::metadata(&probe).unwrap().uid();
        let _ = std::fs::remove_file(&probe);
        uid
    }

    /// Fails with a clear message unless this kernel answers the UDP socket
    /// diag: the tests that exercise the real kernel lookup need it (the
    /// Halo `cargo test --workspace` and Ubuntu CI have `udp_diag`).
    pub(crate) fn needs_kernel_udp_diag() {
        let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = socket.local_addr().unwrap().port();
        match kernel_socket_owners(port) {
            Ok(owners) if owners == [test_uid()] => {}
            other => panic!(
                "needs the kernel's UDP sock_diag (netlink NETLINK_SOCK_DIAG with the udp_diag \
                 module) to report this test's own socket; got {other:?}"
            ),
        }
    }

    /// `127.0.0.1` as `/proc/net/udp` prints it on this host.
    pub(crate) fn loopback_hex() -> String {
        format!("{:08X}", u32::from_ne_bytes(Ipv4Addr::LOCALHOST.octets()))
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::fake_proc::{FakeProc, loopback_hex};
    use super::*;

    fn from(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, port))
    }

    #[test]
    fn proc_addresses_parse_in_host_order() {
        assert_eq!(
            proc_address(&loopback_hex()),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(
            proc_address("00000000"),
            Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        );
        let v6_loopback = format!("{}{}", "0".repeat(24), {
            format!("{:08X}", u32::from_ne_bytes([0, 0, 0, 1]))
        });
        assert_eq!(
            proc_address(&v6_loopback),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
        assert_eq!(proc_address("zz"), None);
    }

    #[test]
    fn pid_files_and_stat_start_times_parse() {
        assert_eq!(
            parse_pid_file("name: dnsmasq\npid: 3666466\nstart_time: 113779042\n"),
            Some((3_666_466, 113_779_042))
        );
        // F6 review: a pid file without a start time is not evidence.
        assert_eq!(parse_pid_file("pid: 7\n"), None);
        assert_eq!(parse_pid_file("pid: 0\n"), None);
        assert_eq!(parse_pid_file("pid: 7\nstart_time: x\n"), None);
        assert_eq!(parse_pid_file("name: dnsmasq\n"), None);
        let stat = "42 (dns) masq) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 777 19 20";
        assert_eq!(proc_start_time(stat), Some(777));
    }

    #[test]
    fn only_the_bridge_resolvers_sockets_may_hint() {
        let proc = FakeProc::new("peer");
        proc.process(10, &["/usr/bin/dig", "--interface=x"], 1000);
        proc.resolver(11, "sbx-other", 997);
        proc.resolver(12, "sbx-1", 998);
        let lo = loopback_hex();
        proc.sockets(&[
            ("udp", &lo, 40001, 998),
            ("udp", "00000000", 40002, 998),
            ("udp", &lo, 40003, 1000),
            // A second socket on the resolver's port, owned by another user.
            ("udp", &lo, 40004, 998),
            ("udp", "00000000", 40004, 1000),
            // Bound elsewhere: cannot have sent a loopback datagram.
            ("udp", "0102000A", 40005, 1000),
            ("udp", &lo, 40005, 998),
            ("udp6", &"0".repeat(32), 40006, 998),
        ]);
        let mut peer = ResolverPeer::new(proc.roots(), "sbx-1");
        assert!(peer.may_hint(from(40001)), "the resolver's socket");
        assert_eq!(peer.uid, Some(998), "not another bridge's resolver");
        assert!(peer.may_hint(from(40002)), "the resolver on the wildcard");
        assert!(!peer.may_hint(from(40003)), "a local user's dig");
        assert!(!peer.may_hint(from(40004)), "a shared port is not proof");
        assert!(peer.may_hint(from(40005)), "a non-loopback bind is ignored");
        assert!(peer.may_hint(from(40006)), "an IPv6 wildcard socket");
        assert!(!peer.may_hint(from(40007)), "no socket at all");
    }

    /// F6: without verifiable evidence of the bridge's resolver, no query
    /// records a hint (it used to count every loopback query).
    #[test]
    fn an_unknown_resolver_fails_closed() {
        let proc = FakeProc::new("hidden");
        proc.sockets(&[("udp", &loopback_hex(), 40001, 1000)]);
        let mut peer = ResolverPeer::new(proc.roots(), "sbx-1");
        assert!(!peer.may_hint(from(40001)), "no pid file: no hint");
        assert_eq!(peer.uid, None);
        // Learned once Incus records the resolver (after the rescan interval).
        proc.resolver(12, "sbx-1", 1000);
        peer.scanned_at = None;
        assert!(peer.may_hint(from(40001)));
        assert_eq!(peer.uid, Some(1000));
        // `hidepid`: the recorded process cannot be read.
        std::fs::remove_dir_all(proc.path().join("12")).unwrap();
        peer.scanned_at = None;
        assert!(
            !peer.may_hint(from(40001)),
            "an unreadable process: no hint"
        );
    }

    /// F6: a local process that calls itself the bridge's dnsmasq (argv[0]
    /// and `--interface` are its own to choose) is never the resolver.
    #[test]
    fn a_spoofed_dnsmasq_argv_is_not_the_resolver() {
        let proc = FakeProc::new("spoof");
        let bridge = crate::incus::network::sandbox_network_names("sbx-1").0;
        let spoof = [
            "/tmp/dnsmasq",
            "--keep-in-foreground",
            &format!("--interface={bridge}"),
        ];
        proc.process(5, &spoof, 1000);
        proc.sockets(&[("udp", &loopback_hex(), 40001, 1000)]);
        let mut peer = ResolverPeer::new(proc.roots(), "sbx-1");
        assert!(!peer.may_hint(from(40001)), "argv alone proves nothing");
        assert_eq!(peer.uid, None);
        // The real resolver, recorded by Incus, runs as another uid.
        proc.resolver(12, "sbx-1", 998);
        peer.scanned_at = None;
        assert!(!peer.may_hint(from(40001)), "the spoof's socket");
        assert_eq!(peer.uid, Some(998));
        // A pid file anyone may rewrite is no evidence.
        proc.pid_file("sbx-1", 5, 5);
        let file = proc
            .incus_dir()
            .join("networks")
            .join(&bridge)
            .join("dnsmasq.pid");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
        peer.scanned_at = None;
        assert!(!peer.may_hint(from(40001)), "a writable pid file");
        assert_eq!(peer.uid, None);
        // A recorded pid now reused by another process (start time differs).
        proc.pid_file("sbx-1", 5, 4);
        peer.scanned_at = None;
        assert!(!peer.may_hint(from(40001)), "a reused pid");
        assert_eq!(peer.uid, None);
    }

    /// F6 review: a pid file without a start time, a symlinked pid file, and
    /// a replaceable directory above it are no evidence.
    #[test]
    fn incomplete_or_replaceable_pid_files_are_not_evidence() {
        let proc = FakeProc::new("chain");
        proc.resolver(12, "sbx-1", 1000);
        proc.sockets(&[("udp", &loopback_hex(), 40001, 1000)]);
        let mut peer = ResolverPeer::new(proc.roots(), "sbx-1");
        assert!(peer.may_hint(from(40001)), "the complete, trusted record");
        let bridge = crate::incus::network::sandbox_network_names("sbx-1").0;
        let dir = proc.incus_dir().join("networks").join(&bridge);
        let file = dir.join("dnsmasq.pid");

        // A stale pid-only record, now naming a process with the right argv.
        std::fs::write(&file, "pid: 12\n").unwrap();
        peer.scanned_at = None;
        assert!(!peer.may_hint(from(40001)), "no start time");
        assert_eq!(peer.uid, None);

        // A symlink to a well-formed record elsewhere.
        let elsewhere = proc.path().join("elsewhere.pid");
        std::fs::write(&elsewhere, "pid: 12\nstart_time: 12\n").unwrap();
        std::fs::remove_file(&file).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &file).unwrap();
        peer.scanned_at = None;
        assert!(!peer.may_hint(from(40001)), "a symlinked pid file");

        // A well-formed record under a directory anyone may write to.
        std::fs::remove_file(&file).unwrap();
        proc.resolver(12, "sbx-1", 1000);
        let networks = proc.incus_dir().join("networks");
        std::fs::set_permissions(&networks, std::fs::Permissions::from_mode(0o777)).unwrap();
        peer.scanned_at = None;
        assert!(!peer.may_hint(from(40001)), "a replaceable ancestor");
        std::fs::set_permissions(&networks, std::fs::Permissions::from_mode(0o755)).unwrap();
        peer.scanned_at = None;
        assert!(peer.may_hint(from(40001)), "trusted again");
    }

    /// The chain is checked from `chain_root` down, the root included, and
    /// only for a directory that resolves below it; production starts at
    /// `/`. Hermetic: every mode that matters is set here, whatever the
    /// host's own `TMPDIR` chain or umask.
    #[test]
    fn the_chain_is_checked_from_its_root_down() {
        assert_eq!(PeerRoots::default().chain_root, PathBuf::from("/"));
        let proc = FakeProc::new("root");
        let uid = super::fake_proc::test_uid();
        let mode = |path: &Path, mode: u32| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        // outer (writable by anyone) / root / networks / bridge.
        let outer = proc.path().join("outer");
        let root = outer.join("root");
        let bridge = root.join("networks").join("wssp-br");
        std::fs::create_dir_all(&bridge).unwrap();
        for dir in [&root, &root.join("networks"), &bridge] {
            mode(dir, 0o755);
        }
        mode(&outer, 0o777);
        assert!(
            trusted_chain(&bridge, &root, uid),
            "trusted from its root down"
        );
        assert!(
            !trusted_chain(&bridge, &outer, uid),
            "the root itself is checked"
        );
        assert!(
            !trusted_chain(&bridge, Path::new("/"), uid),
            "from `/`, the replaceable ancestor is found"
        );
        let elsewhere = proc.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        mode(&elsewhere, 0o755);
        assert!(
            !trusted_chain(&bridge, &elsewhere, uid),
            "a directory outside the root"
        );
        // A replaceable directory below the root is still found.
        mode(&root.join("networks"), 0o775);
        assert!(
            !trusted_chain(&bridge, &root, uid),
            "group-writable below the root"
        );
        mode(&root.join("networks"), 0o1777);
        assert!(trusted_chain(&bridge, &root, uid), "sticky, like /tmp");
        // A symlink below the root that someone else could own is checked
        // as written, and the target as resolved.
        let link = root.join("link");
        std::os::unix::fs::symlink(&outer, &link).unwrap();
        std::fs::create_dir(outer.join("networks")).unwrap();
        assert!(
            !trusted_chain(&link.join("networks"), &root, uid),
            "resolves outside the root"
        );
        mode(&outer, 0o755);
    }

    /// One `SOCK_DIAG_BY_FAMILY` reply as the kernel frames it.
    fn diag_msg(seq: u32, family: u8, port: u16, src: &[u8], uid: u32) -> Vec<u8> {
        let mut body = vec![family, 7, 0, 0];
        body.extend_from_slice(&port.to_be_bytes());
        body.extend_from_slice(&[0, 0]);
        let mut address = src.to_vec();
        address.resize(16, 0);
        body.extend_from_slice(&address);
        body.resize(64, 0);
        body.extend_from_slice(&uid.to_ne_bytes());
        body.extend_from_slice(&77u32.to_ne_bytes());
        nl(SOCK_DIAG_BY_FAMILY, seq, &body)
    }

    fn nl(kind: u16, seq: u32, body: &[u8]) -> Vec<u8> {
        nl_flags(kind, libc::NLM_F_MULTI as u16, seq, body)
    }

    fn nl_flags(kind: u16, flags: u16, seq: u32, body: &[u8]) -> Vec<u8> {
        let mut out = ((NLMSG_HEADER + body.len()) as u32).to_ne_bytes().to_vec();
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(&flags.to_ne_bytes());
        out.extend_from_slice(&seq.to_ne_bytes());
        out.extend_from_slice(&0u32.to_ne_bytes());
        out.extend_from_slice(body);
        out
    }

    fn done(seq: u32, status: i32) -> Vec<u8> {
        nl(libc::NLMSG_DONE as u16, seq, &status.to_ne_bytes())
    }

    fn errno_of(error: &DiagError) -> (bool, Option<i32>) {
        match error {
            DiagError::Unsupported(error) => (true, error.raw_os_error()),
            DiagError::Failed(error) => (false, error.raw_os_error()),
        }
    }

    #[test]
    fn sock_diag_requests_and_replies_have_the_kernel_layout() {
        let request = diag_request(libc::AF_INET as u8, 0x1234, 9);
        assert_eq!(request.len(), 72);
        assert_eq!(&request[0..4], &72u32.to_ne_bytes());
        assert_eq!(&request[4..6], &20u16.to_ne_bytes());
        assert_eq!(&request[6..8], &0x301u16.to_ne_bytes(), "REQUEST | DUMP");
        assert_eq!(&request[8..12], &9u32.to_ne_bytes());
        assert_eq!(&request[16..20], &[libc::AF_INET as u8, 17, 0, 0]);
        assert_eq!(&request[20..24], &[0xff; 4], "every state");
        assert_eq!(&request[24..26], &[0x12, 0x34], "sport, network order");
        assert!(request[26..].iter().all(|byte| *byte == 0));

        let v4 = libc::AF_INET as u8;
        let mut replies = diag_msg(1, v4, 5353, &[127, 0, 0, 1], 998);
        replies.extend(diag_msg(1, v4, 5353, &[0, 0, 0, 0], 999));
        // Another request's reply, and a socket on another port: ignored.
        replies.extend(diag_msg(7, v4, 5353, &[127, 0, 0, 1], 1));
        replies.extend(diag_msg(1, v4, 5354, &[127, 0, 0, 1], 2));
        let mut out = Vec::new();
        assert_eq!(
            diag_replies(&replies, v4, 5353, 1, &mut out).unwrap(),
            DiagBatch {
                sockets: 3,
                done: false
            }
        );
        assert_eq!(
            diag_replies(&done(1, 0), v4, 5353, 1, &mut out).unwrap(),
            DiagBatch {
                sockets: 0,
                done: true
            }
        );
        assert_eq!(
            out,
            vec![
                (IpAddr::V4(Ipv4Addr::LOCALHOST), 998),
                (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 999)
            ]
        );

        let v6 = libc::AF_INET6 as u8;
        let mut out = Vec::new();
        let loopback = Ipv6Addr::LOCALHOST.octets();
        diag_replies(&diag_msg(2, v6, 53, &loopback, 5), v6, 53, 2, &mut out).unwrap();
        assert_eq!(out, vec![(IpAddr::V6(Ipv6Addr::LOCALHOST), 5)]);

        // No UDP handler: NLMSG_ERROR, or a DONE carrying the errno.
        let error = nl(libc::NLMSG_ERROR as u16, 2, &(-libc::ENOENT).to_ne_bytes());
        let error = diag_replies(&error, v6, 53, 2, &mut out).unwrap_err();
        assert_eq!(errno_of(&error), (true, Some(libc::ENOENT)));
        let error = diag_replies(&done(2, -libc::ENOENT), v6, 53, 2, &mut out).unwrap_err();
        assert_eq!(
            errno_of(&error),
            (true, Some(libc::ENOENT)),
            "a failed DONE"
        );
        // Any other failure is no evidence, never a fallback.
        let error = diag_replies(&done(2, -libc::ENOBUFS), v6, 53, 2, &mut out).unwrap_err();
        assert_eq!(errno_of(&error), (false, Some(libc::ENOBUFS)));
        let error = nl(libc::NLMSG_ERROR as u16, 2, &(-libc::EPERM).to_ne_bytes());
        let error = diag_replies(&error, v6, 53, 2, &mut out).unwrap_err();
        assert_eq!(errno_of(&error), (false, Some(libc::EPERM)));
        // An interrupted dump, a DONE without its status, a truncated
        // reply, a wrong family, a short socket message.
        let interrupted = nl_flags(
            SOCK_DIAG_BY_FAMILY,
            (libc::NLM_F_MULTI | libc::NLM_F_DUMP_INTR) as u16,
            2,
            &diag_msg(2, v6, 53, &loopback, 5)[NLMSG_HEADER..],
        );
        let error = diag_replies(&interrupted, v6, 53, 2, &mut out).unwrap_err();
        assert_eq!(errno_of(&error), (false, None));
        let bare_done = nl(libc::NLMSG_DONE as u16, 2, &[]);
        assert!(matches!(
            diag_replies(&bare_done, v6, 53, 2, &mut out),
            Err(DiagError::Failed(_))
        ));
        let whole = diag_msg(2, v6, 53, &loopback, 5);
        assert!(diag_replies(&whole[..whole.len() - 1], v6, 53, 2, &mut out).is_err());
        let v4_reply = diag_msg(2, v4, 53, &[127, 0, 0, 1], 5);
        assert!(diag_replies(&v4_reply, v6, 53, 2, &mut out).is_err());
        let mut short = nl(SOCK_DIAG_BY_FAMILY, 2, &[v6; 8]);
        assert!(diag_replies(&short, v6, 53, 2, &mut out).is_err());
        short.truncate(10);
        assert_eq!(
            diag_replies(&short, v6, 53, 2, &mut out).unwrap(),
            DiagBatch {
                sockets: 0,
                done: false
            }
        );
    }

    /// The port's sockets in one datagram are one locked snapshot of their
    /// hash slot; spread over two, the kernel resumed the slot by position
    /// (it can drop a row then), so the answer is refused.
    #[test]
    fn a_dump_split_across_datagrams_is_no_evidence() {
        let v4 = libc::AF_INET as u8;
        let run = |datagrams: Vec<Vec<u8>>| {
            let mut datagrams = datagrams.into_iter();
            let mut out = Vec::new();
            let result = collect_dump(v4, 53, 1, &mut out, |buf| {
                let datagram = datagrams.next().expect("the dump ended without DONE");
                buf[..datagram.len()].copy_from_slice(&datagram);
                Ok(datagram.len())
            });
            result.map(|()| out)
        };
        let row = |uid| diag_msg(1, v4, 53, &[127, 0, 0, 1], uid);
        let together = [row(998), row(999)].concat();
        assert_eq!(run(vec![together.clone(), done(1, 0)]).unwrap().len(), 2);
        assert_eq!(
            run(vec![[together.clone(), done(1, 0)].concat()])
                .unwrap()
                .len(),
            2,
            "DONE in the same datagram"
        );
        assert!(run(vec![done(1, 0)]).unwrap().is_empty(), "no socket");
        assert!(matches!(
            run(vec![row(998), row(999), done(1, 0)]),
            Err(DiagError::Failed(_))
        ));
        // Another request's datagram in between does not count.
        let other = diag_msg(9, v4, 53, &[127, 0, 0, 1], 1);
        assert_eq!(run(vec![other, together, done(1, 0)]).unwrap().len(), 2);
        // A reply long enough that the kernel may have stopped the slot walk
        // for space, followed by DONE alone (the walk resumed by position and
        // may have skipped a row): refused, though no second datagram held
        // a socket.
        let rows = row(998).len();
        let fits = DIAG_WHOLE_SLOT_BYTES / rows;
        let whole = (0..fits).map(|_| row(998)).collect::<Vec<_>>().concat();
        assert_eq!(run(vec![whole.clone(), done(1, 0)]).unwrap().len(), fits);
        let saturated = [whole, row(998)].concat();
        assert!(saturated.len() > DIAG_WHOLE_SLOT_BYTES);
        assert!(matches!(
            run(vec![saturated, done(1, 0)]),
            Err(DiagError::Failed(_))
        ));
    }

    /// Through `ResolverPeer`: the kernel's answer is the evidence; a kernel
    /// without UDP diag falls back to the socket tables; any other failure
    /// records no hint, whatever the tables say.
    #[test]
    fn only_a_kernel_without_udp_diag_falls_back_to_the_tables() {
        let proc = FakeProc::new("fallback");
        proc.resolver(12, "sbx-1", 998);
        proc.sockets(&[
            ("udp", &loopback_hex(), 40001, 998),
            ("udp", &loopback_hex(), 40002, 1000),
        ]);
        let peer = |lookup: fn(u16) -> Result<Vec<u32>, DiagError>| {
            ResolverPeer::new(
                PeerRoots {
                    sockets: SocketTable::Kernel(lookup),
                    ..proc.roots()
                },
                "sbx-1",
            )
        };
        // The kernel's answer, not the tables', decides.
        let mut kernel = peer(|port| Ok(if port == 40002 { vec![998] } else { vec![1000] }));
        assert!(kernel.may_hint(from(40002)), "the kernel says the resolver");
        assert!(!kernel.may_hint(from(40001)), "the kernel says another uid");
        let mut unsupported = peer(|_| {
            Err(DiagError::Unsupported(std::io::Error::from_raw_os_error(
                libc::ENOENT,
            )))
        });
        assert!(
            unsupported.may_hint(from(40001)),
            "the tables: the resolver"
        );
        assert!(
            !unsupported.may_hint(from(40002)),
            "the tables: another uid"
        );
        assert!(unsupported.diag_warned, "reported");
        let mut failed = peer(|_| {
            Err(DiagError::Failed(std::io::Error::from_raw_os_error(
                libc::ETIMEDOUT,
            )))
        });
        assert!(!failed.may_hint(from(40001)), "no evidence, no hint");
        assert!(failed.diag_failed_at.is_some(), "reported");
    }

    /// The kernel names this test's own sockets, on loopback and on the
    /// wildcard, with this uid.
    #[test]
    fn the_kernel_reports_who_owns_a_ports_sockets() {
        super::fake_proc::needs_kernel_udp_diag();
        let uid = super::fake_proc::test_uid();
        for bind in [Ipv4Addr::LOCALHOST, Ipv4Addr::UNSPECIFIED] {
            let socket = std::net::UdpSocket::bind((bind, 0)).unwrap();
            let port = socket.local_addr().unwrap().port();
            assert_eq!(
                kernel_socket_owners(port)
                    .expect("needs the kernel's UDP sock_diag (the udp_diag module)"),
                vec![uid],
                "{bind}"
            );
        }
    }

    /// Threads binding and closing UDP sockets on 127.0.0.1 until dropped
    /// (also when the test panics).
    struct Churn {
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        threads: Vec<std::thread::JoinHandle<()>>,
    }

    impl Drop for Churn {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
            for thread in self.threads.drain(..) {
                let _ = thread.join();
            }
        }
    }

    /// 2048 unprivileged ports outside `ip_local_port_range`, so binding
    /// them never takes a port a parallel test freed and binds again (with
    /// port 0, the kernel hands out only ports inside the range).
    fn non_ephemeral_band() -> u16 {
        let range = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
            .expect("needs /proc/sys/net/ipv4/ip_local_port_range");
        let mut bounds = range.split_whitespace().map(|bound| bound.parse::<u32>());
        let (Some(Ok(low)), Some(Ok(high))) = (bounds.next(), bounds.next()) else {
            panic!("unreadable ip_local_port_range: {range:?}");
        };
        if low >= 1024 + 2048 {
            return (low - 2048) as u16;
        }
        if high + 2048 <= 65535 {
            return (high + 1) as u16;
        }
        panic!(
            "needs 2048 unprivileged ports outside ip_local_port_range ({low}-{high}) to churn \
             sockets without taking ephemeral ports"
        );
    }

    /// Forced race: other threads create and close UDP sockets without
    /// pause (as the parallel stub tests and a busy host do) while one bound
    /// socket's owners are looked up. `/proc/net/udp`, read a page at a time,
    /// drops that row here; the kernel's dump of the port's slot never does.
    /// The churn binds explicit ports outside the ephemeral range.
    #[test]
    fn the_kernel_lookup_holds_under_socket_churn() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        super::fake_proc::needs_kernel_udp_diag();
        let uid = super::fake_proc::test_uid();
        let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = socket.local_addr().unwrap().port();
        let band = non_ephemeral_band();
        let binds = std::sync::Arc::new(AtomicUsize::new(0));
        let started = std::sync::Arc::new(std::sync::Barrier::new(5));
        let mut churn = Churn {
            stop: std::sync::Arc::new(AtomicBool::new(false)),
            threads: Vec::new(),
        };
        for thread in 0..4u16 {
            let (stop, binds, started) = (churn.stop.clone(), binds.clone(), started.clone());
            let band = band + thread * 512;
            churn.threads.push(std::thread::spawn(move || {
                started.wait();
                let mut ring = std::collections::VecDeque::new();
                let mut next = 0;
                while !stop.load(Ordering::Relaxed) {
                    next = (next + 1) % 512;
                    if let Ok(socket) =
                        std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, band + next))
                    {
                        ring.push_back(socket);
                        binds.fetch_add(1, Ordering::Relaxed);
                    }
                    if ring.len() > 64 {
                        ring.pop_front();
                    }
                }
            }));
        }
        started.wait();
        let missed = (0..2000)
            .filter(|_| kernel_socket_owners(port).expect("the kernel's UDP sock_diag") != [uid])
            .count();
        let churned = binds.load(Ordering::Relaxed);
        drop(churn);
        assert_eq!(missed, 0, "lookups that missed the bound socket");
        // The race was exercised: sockets came and went throughout.
        assert!(churned >= 1000, "only {churned} sockets churned");
    }

    /// F6: a dnsmasq restart (new pid, new uid) is picked up at the next
    /// rescan.
    #[test]
    fn a_restarted_resolver_is_picked_up() {
        let proc = FakeProc::new("restart");
        proc.resolver(12, "sbx-1", 998);
        proc.sockets(&[
            ("udp", &loopback_hex(), 40001, 998),
            ("udp", &loopback_hex(), 40002, 999),
        ]);
        let mut peer = ResolverPeer::new(proc.roots(), "sbx-1");
        assert!(peer.may_hint(from(40001)));
        std::fs::remove_dir_all(proc.path().join("12")).unwrap();
        proc.resolver(13, "sbx-1", 999);
        peer.scanned_at = None;
        assert!(peer.may_hint(from(40002)));
        assert!(!peer.may_hint(from(40001)), "the old resolver's uid");
    }
}
