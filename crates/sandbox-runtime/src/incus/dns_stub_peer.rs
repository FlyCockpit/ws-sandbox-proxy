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
//!    address (`/proc/net/udp{,6}`, world-readable). Incus runs dnsmasq as
//!    its own system user (`-u incus`); a local user who is not that uid (or
//!    root) cannot own such a socket.
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
}

impl Default for PeerRoots {
    fn default() -> Self {
        Self {
            proc_root: PathBuf::from("/proc"),
            incus_dir: std::env::var_os("INCUS_DIR")
                .filter(|dir| !dir.is_empty())
                .map_or_else(|| PathBuf::from("/var/lib/incus"), PathBuf::from),
            trusted_owner: 0,
        }
    }
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
}

impl ResolverPeer {
    pub(crate) fn new(roots: PeerRoots, sandbox_id: &str) -> Self {
        Self {
            roots,
            bridge: super::network::sandbox_network_names(sandbox_id).0,
            uid: None,
            scanned_at: None,
            warned_at: None,
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
        let owners = socket_owners(&self.roots.proc_root, from.port());
        !owners.is_empty() && owners.iter().all(|owner| *owner == uid)
    }
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

/// F6 review: every directory from `/` down to `dir`, both as written and
/// as resolved, is trusted, so nothing unprivileged can swap a component
/// (or the pid file) between this check and the read that follows.
fn trusted_chain(dir: &Path, owner: u32) -> bool {
    let Ok(resolved) = std::fs::canonicalize(dir) else {
        return false;
    };
    let lexical_ok = dir.ancestors().all(|path| {
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
        && resolved
            .ancestors()
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
    if !trusted_chain(&dir, roots.trusted_owner) {
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
            let loopback_source = proc_address(address).is_some_and(|ip| match ip {
                IpAddr::V4(ip) => ip.is_loopback() || ip.is_unspecified(),
                IpAddr::V6(ip) => {
                    ip.is_loopback()
                        || ip.is_unspecified()
                        || ip.to_ipv4_mapped().is_some_and(|ip| ip.is_loopback())
                }
            });
            if loopback_source && let Ok(uid) = uid.parse() {
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

        /// A fake `/proc` whose socket tables are this host's real ones.
        pub(crate) fn with_real_sockets(tag: &str) -> Self {
            let proc = Self::new(tag);
            std::fs::remove_dir_all(proc.0.join("net")).unwrap();
            std::os::unix::fs::symlink("/proc/net", proc.0.join("net")).unwrap();
            proc
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
