//! Per-command Linux subreapers. Each per-command supervisor has one known direct
//! child, so adopted orphans can be killed/reaped without stealing runtime or
//! PTY exit statuses from other daemon threads. No command data is logged.
use std::collections::HashMap;
use std::io;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

pub const ENTRY: &str = "__wssp-host-child";

pub(crate) struct Report {
    pub pid: u32,
    pub status: Option<i32>,
    pub clean: bool,
}
impl Report {
    pub fn read(path: &Path) -> Option<Self> {
        use std::io::Read;
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .ok()?
            .take(15)
            .read_to_end(&mut bytes)
            .ok()?;
        if bytes.len() != 14 || &bytes[..4] != b"WHP1" || bytes[12] > 1 || bytes[13] > 1 {
            return None;
        }
        let raw_status = i32::from_le_bytes(bytes[8..12].try_into().ok()?);
        Some(Self {
            pid: u32::from_le_bytes(bytes[4..8].try_into().ok()?),
            status: (bytes[12] == 1).then_some(raw_status),
            clean: bytes[13] == 1,
        })
    }
    fn write(&self, path: &Path) -> io::Result<()> {
        // Fixed local metadata, not a relay frame; never serialize command data.
        let mut bytes = Vec::from(*b"WHP1");
        bytes.extend_from_slice(&self.pid.to_le_bytes());
        bytes.extend_from_slice(&self.status.unwrap_or_default().to_le_bytes());
        bytes.push(u8::from(self.status.is_some()));
        bytes.push(u8::from(self.clean));
        std::fs::write(path, bytes)
    }
}

/// Entered before clap, logging, config or any credential handling. This is a
/// plain unprivileged process, with the host-command environment and no daemon
/// credentials, state access or authorization of its own.
#[doc(hidden)]
pub fn run() -> i32 {
    supervise().unwrap_or(125)
}
fn supervise() -> io::Result<i32> {
    nix::sys::prctl::set_child_subreaper(true).map_err(io::Error::from)?;
    let stopped = Arc::new(AtomicBool::new(false));
    for signal in [
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGHUP,
    ] {
        signal_hook::flag::register(signal, stopped.clone())?;
    }
    let mut args = std::env::args_os().skip(2);
    let report_path = args
        .next()
        .ok_or_else(|| io::Error::other("missing host report"))?;
    let program = args
        .next()
        .ok_or_else(|| io::Error::other("missing host program"))?;
    let mut child = sandbox_runtime::host_agent_command(program)
        .args(args)
        .process_group(0)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    let path = Path::new(&report_path);
    let mut tree = Tree::new(child.id(), true);
    if (Report {
        pid: child.id(),
        status: None,
        clean: false,
    })
    .write(path)
    .is_err()
    {
        tree.kill();
        let _ = child.wait();
        tree.root_reaped();
        let _ = tree.finish();
        return Err(io::Error::other("host report unavailable"));
    }
    let status = loop {
        if tree.refresh().is_err() {
            tree.kill();
            let _ = child.wait();
            tree.root_reaped();
            let _ = tree.finish();
            return Err(io::Error::other("host process ancestry unreadable"));
        }
        if stopped.load(Ordering::Acquire) {
            tree.signal(rustix::process::Signal::TERM);
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                tree.kill();
                let _ = child.wait();
                tree.root_reaped();
                let _ = tree.finish();
                return Err(error);
            }
        }
        if stopped.load(Ordering::Acquire) {
            // The supervisor must finish cleanup before its parent escalates
            // to SIGKILL. Untrusted descendants get no unbounded grace period.
            tree.kill();
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    tree.root_reaped = true;
    let clean = tree.finish();
    Report {
        pid: child.id(),
        status: Some(status.into_raw()),
        clean,
    }
    .write(path)?;
    Ok(if clean { 0 } else { 125 })
}

#[derive(Clone, Copy)]
struct Process {
    pid: u32,
    parent: u32,
    group: u32,
    session: u32,
    start: u64,
    zombie: bool,
}
fn processes() -> io::Result<HashMap<u32, Process>> {
    processes_in(Path::new("/proc"), |path| std::fs::read_to_string(path))
}
fn processes_in(
    root: &Path,
    mut read_stat: impl FnMut(&Path) -> io::Result<String>,
) -> io::Result<HashMap<u32, Process>> {
    let mut all = HashMap::new();
    for dir in std::fs::read_dir(root)? {
        let dir = dir?;
        let Some(pid) = dir.file_name().to_str().and_then(|s| s.parse().ok()) else {
            continue;
        };
        let stat = match read_stat(&dir.path().join("stat")) {
            Ok(v) => v,
            Err(e)
                if e.kind() == io::ErrorKind::NotFound
                    || e.raw_os_error() == Some(nix::libc::ESRCH) =>
            {
                continue;
            }
            Err(e) => return Err(e),
        };
        let Some((_, tail)) = stat.rsplit_once(')') else {
            return Err(io::Error::other("invalid process stat"));
        };
        let fields: Vec<_> = tail.split_whitespace().collect();
        let parse = |index: usize| fields.get(index).and_then(|s| s.parse::<u32>().ok());
        let Some((parent, group, session, start)) = parse(1)
            .zip(parse(2))
            .zip(parse(3))
            .zip(fields.get(19).and_then(|s| s.parse::<u64>().ok()))
            .map(|(((a, b), c), d)| (a, b, c, d))
        else {
            return Err(io::Error::other("invalid process stat fields"));
        };
        all.insert(
            pid,
            Process {
                pid,
                parent,
                group,
                session,
                start,
                zombie: fields.first() == Some(&"Z"),
            },
        );
    }
    Ok(all)
}

pub(crate) struct Tree {
    root: u32,
    root_start: Option<u64>,
    root_reaped: bool,
    adopt_unknown: bool,
    known: HashMap<u32, Process>,
}
impl Tree {
    pub fn new(root: u32, adopt_unknown: bool) -> Self {
        Self {
            root,
            root_start: crate::sandbox_relay::quiesce::process_start_time(root),
            root_reaped: false,
            adopt_unknown,
            known: HashMap::new(),
        }
    }
    pub fn refresh(&mut self) -> io::Result<()> {
        let all = processes()?;
        self.known
            .retain(|pid, old| all.get(pid).is_some_and(|p| p.start == old.start));
        if !self.root_reaped
            && let Some(root) = all.get(&self.root)
            && Some(root.start) == self.root_start
        {
            self.known.entry(self.root).or_insert(*root);
        }
        // Iterate to a fixed point, including sessions and groups whose leader
        // belongs to this command. Never adopt the daemon's shared session.
        loop {
            let before = self.known.len();
            for p in all.values() {
                if p.pid == self.root && Some(p.start) != self.root_start {
                    continue;
                }
                if self.known.contains_key(&p.parent)
                    || self.known.contains_key(&p.group)
                    || self.known.contains_key(&p.session)
                    || (self.adopt_unknown && p.parent == std::process::id())
                {
                    self.known.insert(p.pid, *p);
                }
            }
            if before == self.known.len() {
                break;
            }
        }
        // Only this command's adopted orphans are reaped. The root's Child
        // remains the sole waiter for its exit status.
        for p in self.known.values_mut() {
            if p.pid != self.root && p.parent == std::process::id() && p.zombie {
                let _ = nix::sys::wait::waitpid(
                    nix::unistd::Pid::from_raw(p.pid as i32),
                    Some(nix::sys::wait::WaitPidFlag::WNOHANG),
                );
            }
        }
        Ok(())
    }
    pub fn signal(&self, signal: rustix::process::Signal) {
        for p in self.known.values() {
            let Some(pid) = i32::try_from(p.pid)
                .ok()
                .and_then(rustix::process::Pid::from_raw)
            else {
                continue;
            };
            // Pin before rechecking start time, so pid reuse never signals an
            // unrelated child. Failure is reflected by the final live scan.
            if let Ok(fd) = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())
                && crate::sandbox_relay::quiesce::process_start_time(p.pid) == Some(p.start)
            {
                let _ = rustix::process::pidfd_send_signal(&fd, signal);
            }
        }
    }
    pub fn kill(&mut self) {
        let _ = self.refresh();
        self.signal(rustix::process::Signal::KILL);
        if !self.root_reaped
            && self.known.contains_key(&self.root)
            && let Ok(pid) = i32::try_from(self.root)
        {
            let _ = nix::sys::signal::killpg(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
    }
    pub fn finish(&mut self) -> bool {
        let until = Instant::now() + Duration::from_millis(750);
        loop {
            if self.refresh().is_err() {
                return false;
            }
            if self
                .known
                .values()
                .all(|p| p.zombie || (p.pid == self.root && self.root_reaped))
            {
                // One more refresh removes the orphans just reaped above.
                return self.refresh().is_ok()
                    && self
                        .known
                        .values()
                        .all(|p| p.pid == self.root && self.root_reaped);
            }
            self.kill();
            if Instant::now() >= until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    pub fn root_reaped(&mut self) {
        self.root_reaped = true;
    }
}

pub(crate) fn command(report: &Path, argv: &[String]) -> io::Result<Command> {
    #[cfg(not(test))]
    let exe = Path::new("/proc/self/exe");
    #[cfg(test)]
    let exe = test_wssp_binary()?;
    let mut cmd = sandbox_runtime::host_agent_command(exe);
    cmd.arg(ENTRY).arg(report).args(argv);
    Ok(cmd)
}

/// The `wssp` binary for lib unit tests, which get no `CARGO_BIN_EXE_wssp`.
/// Nextest names it; under `cargo test` the package's integration tests make
/// Cargo build it into the artifact dir (`<target-dir>/<profile>/wssp`). That
/// dir is an ancestor of the test binary in every build-dir layout (Cargo
/// before 1.100: `<profile>/deps/`; 1.100: `<profile>/build/wssp/<hash>/out/`),
/// so search the ancestors instead of assuming either layout's depth, but
/// never above the target dir (the one Cargo marks with `CACHEDIR.TAG`).
#[cfg(test)]
fn test_wssp_binary() -> io::Result<std::path::PathBuf> {
    if let Some(exe) = std::env::var_os("NEXTEST_BIN_EXE_wssp") {
        return Ok(exe.into());
    }
    let test_binary = std::env::current_exe()?;
    for dir in test_binary.ancestors().skip(1) {
        let candidate = dir.join("wssp");
        if candidate.is_file() {
            return Ok(candidate);
        }
        if dir.join("CACHEDIR.TAG").is_file() {
            break;
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "no `wssp` binary in the target dir above `{}`: build it (`cargo build -p wssp`) or run the package's tests",
            test_binary.display()
        ),
    ))
}

pub(crate) fn exit_status(report: &Path) -> Option<ExitStatus> {
    let report = Report::read(report)?;
    report.clean.then_some(ExitStatus::from_raw(report.status?))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn process_scan_skips_disappeared_processes_but_refuses_other_errors() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("42")).unwrap();
        std::fs::create_dir(dir.path().join("43")).unwrap();
        for errno in [nix::libc::ESRCH, nix::libc::ENOENT] {
            let found = processes_in(dir.path(), |path| {
                if path.parent().unwrap().ends_with("42") {
                    Err(io::Error::from_raw_os_error(errno))
                } else {
                    Ok(format!("43 (child) S 1 43 43 {} 99", "0 ".repeat(15)))
                }
            })
            .unwrap();
            assert_eq!(found.len(), 1);
            assert!(found.contains_key(&43));
        }
        assert!(
            processes_in(dir.path(), |_| Err(io::Error::from_raw_os_error(
                nix::libc::EACCES
            )))
            .is_err()
        );
    }
}
